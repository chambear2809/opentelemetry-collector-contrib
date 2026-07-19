// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/extension/xextension/storage"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/fmc"
)

const (
	checkpointFormatVersion         = 1
	checkpointManifestFormatVersion = 2
	checkpointSlottedLayout         = 1
	checkpointShardSlots            = 2
	checkpointKeyPrefix             = "cisco_os/checkpoints/v1/"
	checkpointShardCount            = (defaultLogDedupMaxEntries + checkpointShardEntries - 1) / checkpointShardEntries
	checkpointShardEntries          = 64
	maxCheckpointShardBytes         = 64 * 1024
	maxCheckpointMetaBytes          = 64 * 1024
	checkpointFlushTimeout          = 5 * time.Second
	checkpointFutureSkew            = 5 * time.Minute

	checkpointSignalMetrics = "metrics"
	checkpointSignalLogs    = "logs"

	checkpointStateCounters  = "delta_counters"
	checkpointStateLogDedup  = "log_dedup"
	checkpointStateFMCResume = "fmc_resume"
)

const unassignedCheckpointShard = ^uint16(0)

func checkpointClockAnchor(anchor, candidate time.Time) time.Time {
	if candidate.After(anchor) {
		return candidate.UTC()
	}
	return anchor.UTC()
}

func checkpointLatestValidTime(now, anchor time.Time) time.Time {
	return checkpointClockAnchor(now, anchor).Add(checkpointFutureSkew)
}

func checkpointFlushContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, checkpointFlushTimeout)
}

func checkpointRollbackContext(parent context.Context) (context.Context, context.CancelFunc) {
	timeout := checkpointFlushTimeout
	if deadline, ok := parent.Deadline(); ok {
		timeout = min(timeout, time.Until(deadline))
	}
	if timeout < 0 {
		timeout = 0
	}
	return context.WithTimeout(context.WithoutCancel(parent), timeout)
}

// checkpointIdentity is deliberately encoded as one structured digest rather
// than concatenated path segments. Receiver names and controller targets are
// operator-controlled strings, so hashing a fixed-field representation avoids
// delimiter collisions and unbounded storage keys.
type checkpointIdentity struct {
	Receiver string `json:"receiver"`
	Provider string `json:"provider"`
	Target   string `json:"target"`
	Signal   string `json:"signal"`
	State    string `json:"state"`
}

func (id checkpointIdentity) key() string {
	encoded, err := json.Marshal(id)
	if err != nil {
		// All fields are strings, so encoding cannot fail. Keep a deterministic
		// fallback in case the representation changes in the future.
		encoded = []byte(fmt.Sprintf("%q\x00%q\x00%q\x00%q\x00%q", id.Receiver, id.Provider, id.Target, id.Signal, id.State))
	}
	digest := sha256.Sum256(encoded)
	return checkpointKeyPrefix + hex.EncodeToString(digest[:])
}

func checkpointTargetFingerprint(target any) string {
	encoded, err := json.Marshal(target)
	if err != nil {
		encoded = []byte(fmt.Sprintf("unsupported:%T", target))
	} else {
		var value any
		if unmarshalErr := json.Unmarshal(encoded, &value); unmarshalErr == nil {
			encoded, err = json.Marshal(canonicalCheckpointValue(value))
			if err != nil {
				encoded = []byte(fmt.Sprintf("unsupported:%T", target))
			}
		}
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func canonicalCheckpointValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			typed[key] = canonicalCheckpointValue(item)
		}
		return typed
	case []any:
		for i, item := range typed {
			typed[i] = canonicalCheckpointValue(item)
		}
		sort.Slice(typed, func(i, j int) bool {
			left, _ := json.Marshal(typed[i])
			right, _ := json.Marshal(typed[j])
			return string(left) < string(right)
		})
		return typed
	default:
		return value
	}
}

func canonicalCheckpointHTTPEndpoint(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return strings.TrimSpace(raw)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	host := canonicalCheckpointHost(parsed.Hostname())
	port := parsed.Port()
	if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
		port = ""
	}
	switch {
	case port != "":
		parsed.Host = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"):
		parsed.Host = "[" + host + "]"
	default:
		parsed.Host = host
	}
	parsed.User = nil
	parsed.Fragment = ""
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = strings.TrimRight(parsed.RawPath, "/")
	parsed.RawQuery = parsed.Query().Encode()
	return parsed.String()
}

func canonicalCheckpointHost(raw string) string {
	host := strings.ToLower(strings.TrimSpace(raw))
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Unmap().String()
	}
	return strings.TrimSuffix(host, ".")
}

func canonicalCheckpointEStreamerEndpoint(raw string) string {
	endpoint, _, err := canonicalHostPort(raw, "8302")
	if err == nil {
		host, port, splitErr := net.SplitHostPort(endpoint)
		if splitErr == nil {
			return net.JoinHostPort(canonicalCheckpointHost(host), port)
		}
		return endpoint
	}
	host, port, splitErr := net.SplitHostPort(strings.TrimSpace(raw))
	if splitErr == nil {
		return net.JoinHostPort(canonicalCheckpointHost(host), port)
	}
	return canonicalCheckpointHost(raw)
}

func checkpointFMCResumeTarget(name, address string) string {
	return checkpointFMCResumeTargetWithScope(name, address, nil)
}

func checkpointFMCResumeTargetWithScope(name, address string, eventTypes []string) string {
	canonicalAddress := canonicalCheckpointEStreamerEndpoint(address)
	effectiveName := strings.TrimSpace(name)
	if canonicalCheckpointEStreamerEndpoint(effectiveName) == canonicalAddress {
		effectiveName = canonicalAddress
	}
	return checkpointTargetFingerprint(struct {
		Name       string
		Address    string
		EventTypes []string
	}{
		Name:       effectiveName,
		Address:    canonicalAddress,
		EventTypes: fmc.NormalizeEStreamerEventTypes(eventTypes),
	})
}

func canonicalCheckpointHTTPControllerName(name, endpoint string) string {
	canonicalEndpoint := canonicalCheckpointHTTPEndpoint(endpoint)
	parsed, err := url.Parse(canonicalEndpoint)
	if err != nil || parsed.Host == "" {
		return strings.TrimSpace(name)
	}
	effectiveHost := parsed.Host
	name = strings.TrimSpace(name)
	if name == "" {
		return effectiveHost
	}
	nameURL, err := url.Parse(parsed.Scheme + "://" + name)
	hostOnlyName := err == nil &&
		nameURL.Host != "" &&
		nameURL.User == nil &&
		nameURL.Path == "" &&
		nameURL.RawPath == "" &&
		nameURL.RawQuery == "" &&
		!nameURL.ForceQuery &&
		nameURL.Fragment == ""
	if hostOnlyName {
		canonicalNameURL, canonicalErr := url.Parse(canonicalCheckpointHTTPEndpoint(nameURL.String()))
		if canonicalErr == nil && canonicalNameURL.Host == effectiveHost {
			return effectiveHost
		}
	}
	return name
}

func canonicalCheckpointHTTPControllerIdentity(name, endpoint string) (string, string) {
	return canonicalCheckpointHTTPControllerName(name, endpoint), canonicalCheckpointHTTPEndpoint(endpoint)
}

type checkpointDeviceSelection struct {
	Include checkpointDeviceSelectionMatch
	Exclude checkpointDeviceSelectionMatch
}

type checkpointDeviceSelectionMatch struct {
	HostNames []string
	HostIDs   []string
	HostIPs   []string
	Serials   []string
	DeviceIDs []string
}

func canonicalCheckpointDeviceSelection(selection DeviceSelectionConfig) checkpointDeviceSelection {
	canonicalMatch := func(match DeviceSelectionMatchConfig) checkpointDeviceSelectionMatch {
		return checkpointDeviceSelectionMatch{
			HostNames: canonicalCheckpointStrings(match.HostNames, normalizeSelectorText),
			HostIDs:   canonicalCheckpointStrings(match.HostIDs, normalizeSelectorText),
			HostIPs:   canonicalCheckpointStrings(match.HostIPs, normalizeSelectorIP),
			Serials:   canonicalCheckpointStrings(match.Serials, normalizeSelectorText),
			DeviceIDs: canonicalCheckpointStrings(match.DeviceIDs, normalizeSelectorText),
		}
	}
	return checkpointDeviceSelection{Include: canonicalMatch(selection.Include), Exclude: canonicalMatch(selection.Exclude)}
}

func canonicalCheckpointStrings(values []string, normalize func(string) string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = normalize(value); value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func canonicalCheckpointScope(groups map[string][]string, normalize func(string) string) map[string][]string {
	result := make(map[string][]string, len(groups))
	for name, values := range groups {
		result[name] = canonicalCheckpointStrings(values, normalize)
	}
	return result
}

func canonicalCheckpointMAC(raw string) string {
	value := strings.TrimSpace(raw)
	if address, err := net.ParseMAC(value); err == nil {
		return strings.ToLower(address.String())
	}
	return strings.ToLower(value)
}

func checkpointProviderTarget(conf *Config, provider string) string {
	if conf == nil {
		return checkpointTargetFingerprint(nil)
	}
	withSelection := func(target any) string {
		return checkpointTargetFingerprint(struct {
			Target          any
			DeviceSelection checkpointDeviceSelection
		}{Target: target, DeviceSelection: canonicalCheckpointDeviceSelection(conf.DeviceSelection)})
	}
	switch provider {
	case "meraki":
		organizations := make([]map[string]any, 0, len(conf.Meraki.Organizations))
		for i := range conf.Meraki.Organizations {
			organization := &conf.Meraki.Organizations[i]
			organizations = append(organizations, map[string]any{
				"organization_id":  strings.TrimSpace(organization.OrganizationID),
				"network_ids":      canonicalCheckpointStrings(organization.NetworkIDs, strings.TrimSpace),
				"serials":          canonicalCheckpointStrings(organization.Serials, strings.TrimSpace),
				"product_types":    canonicalCheckpointStrings(organization.ProductTypes, strings.TrimSpace),
				"tags":             canonicalCheckpointStrings(organization.Tags, strings.TrimSpace),
				"tags_filter_type": strings.TrimSpace(organization.TagsFilterType),
			})
		}
		devices := make([]map[string]string, 0, len(conf.Meraki.Devices))
		for _, device := range conf.Meraki.Devices {
			devices = append(devices, map[string]string{
				"organization_id": strings.TrimSpace(device.OrganizationID),
				"serial":          strings.TrimSpace(device.Serial),
			})
		}
		return withSelection(map[string]any{
			"base_url":      canonicalCheckpointHTTPEndpoint(conf.Meraki.BaseURL),
			"organizations": organizations,
			"devices":       devices,
		})
	case "intersight":
		return withSelection(map[string]any{
			"endpoint": canonicalCheckpointHTTPEndpoint(conf.Intersight.Endpoint),
			"targets": canonicalCheckpointScope(map[string][]string{
				"serials": conf.Intersight.Targets.Serials,
				"moids":   conf.Intersight.Targets.MoIDs,
			}, normalizeSelectorText),
		})
	case "catalyst_center":
		details := make([]map[string]string, 0, len(conf.CatalystCenter.Targets.DeviceDetails))
		for _, detail := range conf.CatalystCenter.Targets.DeviceDetails {
			identifier := canonicalCatalystCenterDeviceIdentifier(detail.Identifier)
			searchBy := strings.TrimSpace(detail.SearchBy)
			if identifier == "macAddress" {
				searchBy = canonicalCheckpointMAC(searchBy)
			}
			details = append(details, map[string]string{"identifier": identifier, "search_by": searchBy})
		}
		return withSelection(map[string]any{
			"endpoint":       canonicalCheckpointHTTPEndpoint(conf.CatalystCenter.Endpoint),
			"device_details": details,
			"client_macs":    canonicalCheckpointStrings(conf.CatalystCenter.Targets.ClientMACs, canonicalCheckpointMAC),
		})
	case "sdwan":
		targets := canonicalCheckpointScope(map[string][]string{
			"site_ids":             conf.SDWAN.Targets.SiteIDs,
			"uuids":                conf.SDWAN.Targets.UUIDs,
			"serials":              conf.SDWAN.Targets.Serials,
			"device_types":         conf.SDWAN.Targets.DeviceTypes,
			"personalities":        conf.SDWAN.Targets.Personalities,
			"colors":               conf.SDWAN.Targets.Colors,
			"interface_names":      conf.SDWAN.Targets.InterfaceNames,
			"vpn_ids":              conf.SDWAN.Targets.VPNIDs,
			"applications":         conf.SDWAN.Targets.Applications,
			"application_families": conf.SDWAN.Targets.ApplicationFamilies,
			"cloud_providers":      conf.SDWAN.Targets.CloudProviders,
			"service_types":        conf.SDWAN.Targets.ServiceTypes,
		}, normalizeSelectorText)
		targets["system_ips"] = canonicalCheckpointStrings(conf.SDWAN.Targets.SystemIPs, normalizeSelectorIP)
		return withSelection(map[string]any{
			"endpoint": canonicalCheckpointHTTPEndpoint(conf.SDWAN.Endpoint),
			"targets":  targets,
		})
	case "nexus_dashboard":
		return withSelection(map[string]any{
			"endpoint":    canonicalCheckpointHTTPEndpoint(conf.NexusDashboard.Endpoint),
			"api_profile": normalizeNexusDashboardAPIProfile(conf.NexusDashboard.APIProfile),
			"targets": canonicalCheckpointScope(map[string][]string{
				"sites":           conf.NexusDashboard.Targets.Sites,
				"fabrics":         conf.NexusDashboard.Targets.Fabrics,
				"switch_serials":  conf.NexusDashboard.Targets.SwitchSerials,
				"switch_ids":      conf.NexusDashboard.Targets.SwitchIDs,
				"interface_names": conf.NexusDashboard.Targets.InterfaceNames,
				"service_names":   conf.NexusDashboard.Targets.ServiceNames,
			}, normalizeSelectorText),
		})
	case "aci":
		controllers := make([]map[string]string, 0, len(conf.ACI.Controllers))
		for _, controller := range conf.ACI.Controllers {
			name, endpoint := canonicalCheckpointHTTPControllerIdentity(controller.Name, controller.Endpoint)
			controllers = append(controllers, map[string]string{
				"name": name, "endpoint": endpoint,
			})
		}
		targets := map[string][]string{
			"sites":           canonicalCheckpointStrings(conf.ACI.Targets.Sites, normalizeACITargetName),
			"fabrics":         canonicalCheckpointStrings(conf.ACI.Targets.Fabrics, normalizeACITargetName),
			"node_ids":        canonicalCheckpointStrings(conf.ACI.Targets.NodeIDs, normalizeACINodeID),
			"serials":         canonicalCheckpointStrings(conf.ACI.Targets.Serials, normalizeACITargetName),
			"tenants":         canonicalCheckpointStrings(conf.ACI.Targets.Tenants, normalizeACITargetName),
			"vrfs":            canonicalCheckpointStrings(conf.ACI.Targets.VRFs, normalizeACITargetName),
			"bridge_domains":  canonicalCheckpointStrings(conf.ACI.Targets.BridgeDomains, normalizeACITargetName),
			"epgs":            canonicalCheckpointStrings(conf.ACI.Targets.EPGs, normalizeACITargetName),
			"interface_names": canonicalCheckpointStrings(conf.ACI.Targets.InterfaceNames, normalizeACIInterfaceName),
		}
		return withSelection(map[string]any{"controllers": controllers, "targets": targets})
	case "fmc":
		controllers := make([]map[string]string, 0, len(conf.FMC.Controllers))
		for _, controller := range conf.FMC.Controllers {
			name, endpoint := canonicalCheckpointHTTPControllerIdentity(controller.Name, controller.Endpoint)
			controllers = append(controllers, map[string]string{
				"name":        name,
				"endpoint":    endpoint,
				"domain_uuid": normalizeSelectorText(controller.DomainUUID),
			})
		}
		targets := canonicalCheckpointScope(map[string][]string{
			"device_ids":      conf.FMC.Targets.DeviceIDs,
			"serials":         conf.FMC.Targets.Serials,
			"names":           conf.FMC.Targets.Names,
			"policy_ids":      conf.FMC.Targets.PolicyIDs,
			"policy_names":    conf.FMC.Targets.PolicyNames,
			"interface_names": conf.FMC.Targets.InterfaceNames,
		}, normalizeSelectorText)
		targets["management_ips"] = canonicalCheckpointStrings(conf.FMC.Targets.ManagementIPs, normalizeSelectorIP)
		return withSelection(map[string]any{"controllers": controllers, "targets": targets})
	case "ise":
		ise := conf.ISE.withDefaults()
		pxGridEndpoint := ise.PxGrid.Endpoint
		if ise.PxGrid.hasTarget() && pxGridEndpoint == "" {
			pxGridEndpoint = defaultISEPxGridEndpoint(ise.Endpoint)
		}
		targets := canonicalCheckpointScope(map[string][]string{
			"node_names":           ise.Targets.NodeNames,
			"network_device_names": ise.Targets.NetworkDeviceNames,
			"usernames":            ise.Targets.Usernames,
			"policy_names":         ise.Targets.PolicyNames,
			"security_group_names": ise.Targets.SecurityGroupNames,
			"pxgrid_services":      ise.Targets.PxGridServices,
		}, normalizeSelectorText)
		targets["network_device_ips"] = canonicalCheckpointStrings(ise.Targets.NetworkDeviceIPs, normalizeSelectorIP)
		targets["endpoint_macs"] = canonicalCheckpointStrings(ise.Targets.EndpointMACs, canonicalCheckpointMAC)
		return withSelection(map[string]any{
			"endpoint":        canonicalCheckpointHTTPEndpoint(ise.Endpoint),
			"pxgrid_endpoint": canonicalCheckpointHTTPEndpoint(pxGridEndpoint),
			"data_connect": map[string]any{
				"host": canonicalCheckpointHost(ise.DataConnect.Host), "port": ise.DataConnect.Port, "service": strings.TrimSpace(ise.DataConnect.ServiceName),
			},
			"targets": targets,
		})
	default:
		return withSelection(provider)
	}
}

type checkpointRegistry struct {
	storageID  component.ID
	receiverID component.ID
	signal     string
	logger     *zap.Logger

	startMu       sync.Mutex
	stateMu       sync.Mutex
	operationGate chan struct{}
	client        storage.Client
	started       bool
	closed        bool
	closeDone     chan struct{}
	closeWarned   atomic.Bool

	restorersMu sync.Mutex
	restorers   []func(context.Context)
	flushers    []func(context.Context)
}

type checkpointManifest struct {
	Version     int             `json:"version"`
	Layout      int             `json:"layout,omitempty"`
	Active      []uint16        `json:"active,omitempty"`
	Slots       []uint8         `json:"slots,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	ClockAnchor time.Time       `json:"clock_anchor,omitzero"`
}

type logCheckpointRetention struct {
	ttl        time.Duration
	maxEntries int
}

func checkpointLogRetention(conf *Config, provider string) logCheckpointRetention {
	policy := logCheckpointRetention{maxEntries: defaultLogDedupMaxEntries}
	if conf == nil {
		return policy
	}
	switch provider {
	case "intersight":
		policy.ttl = conf.Intersight.EventLookback
		if policy.ttl <= 0 {
			policy.ttl = defaultIntersightConfig().EventLookback
		}
		policy.ttl *= 2
	case "sdwan":
		policy.ttl = conf.SDWAN.EventLookback * 2
		if policy.ttl <= 0 {
			policy.ttl = 48 * time.Hour
		}
	case "nexus_dashboard":
		policy.ttl = conf.NexusDashboard.EventLookback
		if policy.ttl <= 0 {
			policy.ttl = defaultNexusDashboardConfig().EventLookback
		}
		policy.ttl *= 2
	case "aci":
		policy.ttl = conf.ACI.EventLookback
		if policy.ttl <= 0 {
			policy.ttl = defaultACIConfig().EventLookback
		}
		policy.ttl *= 2
		policy.maxEntries = aciSeenMaxEntries
	case "fmc":
		policy.ttl = conf.FMC.EventLookback
		if policy.ttl <= 0 {
			policy.ttl = defaultFMCConfig().EventLookback
		}
		policy.ttl *= 2
	case "ise":
		policy.ttl = conf.ISE.withDefaults().EventLookback
		policy.maxEntries = iseSeenMaxEntries
	}
	return policy
}

type loadedCheckpoint struct {
	active      []uint16
	slots       map[uint16]uint8
	legacy      bool
	manifest    []byte
	metadata    json.RawMessage
	shards      map[uint16][]byte
	clockAnchor time.Time
}

func newCheckpointRegistry(storageID, receiverID component.ID, signal string, logger *zap.Logger) *checkpointRegistry {
	if logger == nil {
		logger = zap.NewNop()
	}
	registry := &checkpointRegistry{
		storageID:     storageID,
		receiverID:    receiverID,
		signal:        signal,
		logger:        logger,
		operationGate: make(chan struct{}, 1),
	}
	registry.operationGate <- struct{}{}
	return registry
}

func (r *checkpointRegistry) bind(provider, target, state string, restore func(context.Context)) *checkpointBinding {
	binding := &checkpointBinding{
		registry:          r,
		replaceGeneration: true,
		identity: checkpointIdentity{
			Receiver: r.receiverID.String(),
			Provider: provider,
			Target:   target,
			Signal:   r.signal,
			State:    state,
		},
	}
	r.restorersMu.Lock()
	r.restorers = append(r.restorers, restore)
	r.restorersMu.Unlock()
	return binding
}

func (r *checkpointRegistry) enableCounter(provider, target string, state *counterStore, next consumer.Metrics) consumer.Metrics {
	binding := r.bind(provider, target, checkpointStateCounters, state.restoreCheckpoint)
	state.enableCheckpoint(binding)
	r.addShutdownFlusher(state.flushAcceptedCheckpoint)
	return &counterCheckpointingConsumer{next: next, state: state}
}

func (r *checkpointRegistry) enableLogDedup(provider, target string, state *logDeduplicator, retention logCheckpointRetention) {
	binding := r.bind(provider, target, checkpointStateLogDedup, state.restoreCheckpoint)
	retainAcceptedSnapshot := provider != "ise"
	state.enableCheckpoint(binding, retention, retainAcceptedSnapshot)
	if retainAcceptedSnapshot {
		r.addShutdownFlusher(state.flushAcceptedCheckpoint)
	}
}

func (r *checkpointRegistry) enableFMCResume(target string, state *fmcEStreamerResumeState) {
	binding := r.bind("fmc_estreamer", target, checkpointStateFMCResume, state.restoreCheckpoint)
	state.enableCheckpoint(binding)
}

func (r *checkpointRegistry) addShutdownFlusher(flush func(context.Context)) {
	r.restorersMu.Lock()
	r.flushers = append(r.flushers, flush)
	r.restorersMu.Unlock()
}

func (r *checkpointRegistry) flushAccepted(ctx context.Context) {
	if r == nil {
		return
	}
	r.restorersMu.Lock()
	flushers := append([]func(context.Context){}, r.flushers...)
	r.restorersMu.Unlock()
	for _, flush := range flushers {
		flush(ctx)
	}
}

// Start preserves normal Collector dependency semantics: when storage was
// explicitly configured, the extension and client must be available before
// collection starts. Data-operation failures after acquisition are fail-open.
func (r *checkpointRegistry) Start(ctx context.Context, host component.Host) error {
	if r == nil {
		return nil
	}
	r.startMu.Lock()
	defer r.startMu.Unlock()
	r.stateMu.Lock()
	if r.started {
		r.stateMu.Unlock()
		return nil
	}
	if r.closed {
		r.stateMu.Unlock()
		return errors.New("Cisco OS checkpoint registry is already closed")
	}
	r.stateMu.Unlock()

	if host == nil {
		return errors.New("Cisco OS checkpoint storage requires a Collector host")
	}
	extensionComponent, ok := host.GetExtensions()[r.storageID]
	if !ok {
		return fmt.Errorf("storage extension %q was not found", r.storageID)
	}
	extension, ok := extensionComponent.(storage.Extension)
	if !ok {
		return fmt.Errorf("extension %q does not implement the storage interface", r.storageID)
	}
	client, err := extension.GetClient(ctx, component.KindReceiver, r.receiverID, "cisco_os_checkpoints_"+r.signal)
	if err != nil {
		return fmt.Errorf("create checkpoint storage client from extension %q: %w", r.storageID, err)
	}
	if client == nil {
		return fmt.Errorf("storage extension %q returned a nil client", r.storageID)
	}
	r.stateMu.Lock()
	if r.closed {
		r.stateMu.Unlock()
		r.closeUnregisteredClient(ctx, client)
		return errors.New("Cisco OS checkpoint registry was closed while storage started")
	}
	r.client = client
	r.started = true
	r.stateMu.Unlock()

	r.restorersMu.Lock()
	restorers := append([]func(context.Context){}, r.restorers...)
	r.restorersMu.Unlock()
	for _, restore := range restorers {
		restore(ctx)
	}
	return nil
}

func (r *checkpointRegistry) Close(ctx context.Context) {
	if r == nil {
		return
	}
	waitCtx, waitCancel := checkpointFlushContext(ctx)
	defer waitCancel()
	r.stateMu.Lock()
	done := r.closeDone
	if done == nil {
		r.closed = true
		client := r.client
		r.client = nil
		done = make(chan struct{})
		r.closeDone = done
		// The caller's context bounds only how long Close waits. The drain
		// creates a fresh bounded context after any in-flight operation exits,
		// so a caller deadline cannot cancel the eventual resource release.
		go r.drainAndClose(context.WithoutCancel(ctx), client, done)
	}
	r.stateMu.Unlock()
	select {
	case <-done:
	case <-waitCtx.Done():
		if r.closeWarned.CompareAndSwap(false, true) {
			r.logger.Warn("Timed out waiting for Cisco OS checkpoint storage to close; shutdown will continue",
				zap.String("receiver", r.receiverID.String()),
				zap.String("signal", r.signal),
				zap.Error(waitCtx.Err()))
		}
	}
}

func (r *checkpointRegistry) closeUnregisteredClient(ctx context.Context, client storage.Client) {
	waitCtx, waitCancel := checkpointRollbackContext(ctx)
	defer waitCancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Client acquisition may finish after Start and Close contexts expire.
		// Give that otherwise-unregistered client an independent close attempt.
		closeCtx, closeCancel := checkpointFlushContext(context.WithoutCancel(ctx))
		defer closeCancel()
		if err := client.Close(closeCtx); err != nil {
			r.warnCloseFailure(err)
		}
	}()
	select {
	case <-done:
	case <-waitCtx.Done():
		r.logger.Warn("Timed out waiting for an unregistered Cisco OS checkpoint storage client to close; cleanup will continue asynchronously",
			zap.String("receiver", r.receiverID.String()),
			zap.String("signal", r.signal),
			zap.Error(waitCtx.Err()))
	}
}

func (r *checkpointRegistry) drainAndClose(closeParent context.Context, client storage.Client, done chan<- struct{}) {
	defer close(done)
	if client == nil {
		return
	}
	<-r.operationGate
	closeCtx, closeCancel := checkpointFlushContext(closeParent)
	defer closeCancel()
	if err := client.Close(closeCtx); err != nil {
		r.warnCloseFailure(err)
	}
}

func (r *checkpointRegistry) warnCloseFailure(err error) {
	r.logger.Warn("Failed to close Cisco OS checkpoint storage; shutdown will continue",
		zap.String("receiver", r.receiverID.String()),
		zap.String("signal", r.signal),
		zap.Error(err))
}

func (r *checkpointRegistry) beginOperation(ctx context.Context) (storage.Client, bool, error) {
	r.stateMu.Lock()
	available := !r.closed && r.client != nil
	r.stateMu.Unlock()
	if !available {
		return nil, false, nil
	}
	select {
	case <-r.operationGate:
	case <-ctx.Done():
		return nil, true, ctx.Err()
	}
	r.stateMu.Lock()
	client := r.client
	available = !r.closed && client != nil
	r.stateMu.Unlock()
	if !available {
		r.operationGate <- struct{}{}
		return nil, false, nil
	}
	return client, true, nil
}

func (r *checkpointRegistry) endOperation() {
	r.operationGate <- struct{}{}
}

func (r *checkpointRegistry) get(ctx context.Context, key string) ([]byte, bool, error) {
	client, available, err := r.beginOperation(ctx)
	if !available || err != nil {
		return nil, available, err
	}
	defer r.endOperation()
	value, err := client.Get(ctx, key)
	return value, true, err
}

func (r *checkpointRegistry) batch(ctx context.Context, operations ...*storage.Operation) (bool, error) {
	client, available, err := r.beginOperation(ctx)
	if !available || err != nil {
		return available, err
	}
	defer r.endOperation()
	return true, client.Batch(ctx, operations...)
}

func (r *checkpointRegistry) set(ctx context.Context, key string, value []byte) (bool, error) {
	client, available, err := r.beginOperation(ctx)
	if !available || err != nil {
		return available, err
	}
	defer r.endOperation()
	return true, client.Set(ctx, key, value)
}

type checkpointPublication struct {
	manifest         []byte
	previousManifest []byte
	active           map[uint16]struct{}
	slots            map[uint16]uint8
	clockAnchor      time.Time
}

type checkpointBinding struct {
	registry *checkpointRegistry
	identity checkpointIdentity

	loadFailed atomic.Bool
	saveFailed atomic.Bool
	corrupt    atomic.Bool

	persistMu      sync.Mutex
	active         map[uint16]struct{}
	slots          map[uint16]uint8
	legacy         bool
	manifest       []byte
	legacyShards   map[uint16][]byte
	legacyMetadata json.RawMessage
	uncertain      *checkpointPublication
	fenceKnown     bool
	// replaceGeneration means restoration did not populate the in-memory
	// domain. active/slots still fence the durable generation for safe slot
	// selection, but none of its logical shards may be carried forward.
	replaceGeneration bool
	// clockAnchor is the greatest wall-clock observation included in any
	// committed manifest. Keeping it monotonic lets a later restore distinguish
	// a legitimate host-clock rollback from an isolated future timestamp.
	clockAnchor time.Time
}

func (b *checkpointBinding) load(ctx context.Context) (loadedCheckpoint, bool) {
	if b == nil || b.registry == nil {
		return loadedCheckpoint{}, false
	}
	value, available, err := b.registry.get(ctx, b.manifestKey())
	if !available {
		return loadedCheckpoint{}, false
	}
	if err != nil {
		b.invalidateWriteFence()
		if b.loadFailed.CompareAndSwap(false, true) {
			b.warn("Failed to restore Cisco OS checkpoint; collection will continue with empty in-memory state", err)
		}
		return loadedCheckpoint{}, false
	}
	b.loadFailed.Store(false)
	if len(value) == 0 {
		b.installEmptyWriteFence()
		return loadedCheckpoint{}, false
	}
	if len(value) > maxCheckpointMetaBytes {
		b.invalidateWriteFence()
		b.warnCorrupt(fmt.Errorf("checkpoint manifest is %d bytes; maximum is %d", len(value), maxCheckpointMetaBytes))
		return loadedCheckpoint{}, false
	}
	var manifest checkpointManifest
	if decodeErr := json.Unmarshal(value, &manifest); decodeErr != nil {
		b.invalidateWriteFence()
		b.warnCorrupt(fmt.Errorf("decode checkpoint manifest: %w", decodeErr))
		return loadedCheckpoint{}, false
	}
	if validationErr := validateCheckpointManifest(manifest); validationErr != nil {
		b.invalidateWriteFence()
		b.warnCorrupt(validationErr)
		return loadedCheckpoint{}, false
	}
	// Install the exact manifest fence before reading any shard. Even if a
	// shard is missing, a batch read fails, or domain validation later rejects
	// the payload, subsequent writes must select slots opposite these durable
	// references and replace (not retain) this logical generation.
	b.installManifestWriteFence(manifest, value)
	legacy := manifest.Version == checkpointFormatVersion
	slots := make(map[uint16]uint8, len(manifest.Active))
	operations := make([]*storage.Operation, 0, len(manifest.Active))
	for i, shard := range manifest.Active {
		key := b.shardKey(shard)
		if !legacy {
			slots[shard] = manifest.Slots[i]
			key = b.slottedShardKey(shard, manifest.Slots[i])
		}
		operations = append(operations, storage.GetOperation(key))
	}
	if len(operations) > 0 {
		available, err = b.registry.batch(ctx, operations...)
		if !available {
			return loadedCheckpoint{}, false
		}
		if err != nil {
			if b.loadFailed.CompareAndSwap(false, true) {
				b.warn("Failed to restore Cisco OS checkpoint shards; collection will continue with empty in-memory state", err)
			}
			return loadedCheckpoint{}, false
		}
	}
	shards := make(map[uint16][]byte, len(operations))
	for i, operation := range operations {
		if len(operation.Value) == 0 {
			b.warnCorrupt(fmt.Errorf("checkpoint manifest references missing shard %d", manifest.Active[i]))
			return loadedCheckpoint{}, false
		}
		if len(operation.Value) > maxCheckpointShardBytes {
			b.warnCorrupt(fmt.Errorf("checkpoint shard %d is %d bytes; maximum is %d", manifest.Active[i], len(operation.Value), maxCheckpointShardBytes))
			return loadedCheckpoint{}, false
		}
		shards[manifest.Active[i]] = operation.Value
	}
	return loadedCheckpoint{
		active:      manifest.Active,
		slots:       slots,
		legacy:      legacy,
		manifest:    append([]byte(nil), value...),
		metadata:    manifest.Metadata,
		shards:      shards,
		clockAnchor: manifest.ClockAnchor,
	}, true
}

// persist stages changed shards in the slot not referenced by the committed
// manifest, then publishes the manifest with a separate single-key write. A
// failed storage Batch may apply any prefix, so no live shard is ever part of
// the stage-one operation set.
func (b *checkpointBinding) persist(ctx context.Context, shards map[uint16][]byte, activeUpdates map[uint16]bool, metadata json.RawMessage, clockAnchor time.Time) bool {
	if b == nil || b.registry == nil {
		return false
	}
	if len(shards) > checkpointShardCount || len(activeUpdates) > checkpointShardCount || len(metadata) > maxCheckpointMetaBytes {
		b.warnPersistFailure(errors.New("checkpoint update exceeds the bounded shard or metadata limit"))
		return false
	}
	b.persistMu.Lock()
	defer b.persistMu.Unlock()
	return b.persistLocked(ctx, shards, activeUpdates, metadata, clockAnchor)
}

func (b *checkpointBinding) persistLocked(ctx context.Context, shards map[uint16][]byte, activeUpdates map[uint16]bool, metadata json.RawMessage, clockAnchor time.Time) bool {
	if !b.ensureWriteFenceLocked(ctx) {
		return false
	}
	if b.uncertain != nil {
		resolved, _ := b.resolvePublicationLocked(ctx, true)
		if !resolved {
			return false
		}
	}
	// The clock anchor belongs to the structurally valid committed manifest,
	// not to any one domain entry. Preserve it even when replacement mode drops
	// a semantically rejected payload so host-clock rollback handling remains
	// monotonic without carrying any rejected metadata or shard contents.
	if b.clockAnchor.After(clockAnchor) {
		clockAnchor = b.clockAnchor
	}
	if b.active == nil {
		b.active = map[uint16]struct{}{}
	}
	if b.slots == nil {
		b.slots = map[uint16]uint8{}
	}
	effectiveShards := make(map[uint16][]byte, len(shards)+len(b.legacyShards))
	maps.Copy(effectiveShards, shards)
	effectiveUpdates := make(map[uint16]bool, len(activeUpdates)+len(b.legacyShards))
	maps.Copy(effectiveUpdates, activeUpdates)
	// A legacy manifest references unslotted keys. Its complete validated
	// generation must be copied before the first slotted manifest is published,
	// including shards that the domain snapshot did not otherwise dirty.
	if b.legacy && !b.replaceGeneration {
		for shard := range b.active {
			if _, updated := effectiveUpdates[shard]; updated {
				continue
			}
			effectiveShards[shard] = b.legacyShards[shard]
			effectiveUpdates[shard] = true
		}
	}
	if len(effectiveShards) > checkpointShardCount || len(effectiveUpdates) > checkpointShardCount {
		b.warnPersistFailure(errors.New("checkpoint update exceeds the bounded shard limit after legacy migration"))
		return false
	}
	nextActive := make(map[uint16]struct{}, len(b.active)+len(activeUpdates))
	nextSlots := make(map[uint16]uint8, len(b.slots)+len(effectiveUpdates))
	if !b.replaceGeneration {
		for shard := range b.active {
			nextActive[shard] = struct{}{}
		}
		maps.Copy(nextSlots, b.slots)
	}
	indexSet := make(map[uint16]struct{}, len(effectiveShards)+len(effectiveUpdates))
	for shard, value := range effectiveShards {
		if shard >= checkpointShardCount {
			b.warnPersistFailure(fmt.Errorf("checkpoint shard index %d is out of range", shard))
			return false
		}
		if len(value) > maxCheckpointShardBytes {
			b.warnPersistFailure(fmt.Errorf("checkpoint shard %d is %d bytes; maximum is %d", shard, len(value), maxCheckpointShardBytes))
			return false
		}
		indexSet[shard] = struct{}{}
	}
	for shard := range effectiveUpdates {
		if shard >= checkpointShardCount {
			b.warnPersistFailure(fmt.Errorf("checkpoint shard index %d is out of range", shard))
			return false
		}
		indexSet[shard] = struct{}{}
	}
	if b.replaceGeneration {
		for shard := range b.active {
			indexSet[shard] = struct{}{}
		}
	}
	indices := make([]int, 0, len(indexSet))
	for shard := range indexSet {
		indices = append(indices, int(shard))
	}
	sort.Ints(indices)
	stageOperations := make([]*storage.Operation, 0, len(indices))
	for _, index := range indices {
		shard := uint16(index)
		if effectiveUpdates[shard] {
			value := effectiveShards[shard]
			if len(value) == 0 {
				b.warnPersistFailure(fmt.Errorf("active checkpoint shard %d is empty", shard))
				return false
			}
			slot := uint8(0)
			if _, active := b.active[shard]; active && !b.legacy {
				slot = (b.slots[shard] + 1) % checkpointShardSlots
			}
			key := b.slottedShardKey(shard, slot)
			stageOperations = append(stageOperations, storage.SetOperation(key, value))
			nextActive[shard] = struct{}{}
			nextSlots[shard] = slot
		} else {
			delete(nextActive, shard)
			delete(nextSlots, shard)
		}
	}
	active := make([]uint16, 0, len(nextActive))
	for shard := range nextActive {
		active = append(active, shard)
	}
	slices.Sort(active)
	slots := make([]uint8, 0, len(active))
	for _, shard := range active {
		slots = append(slots, nextSlots[shard])
	}
	manifest, err := json.Marshal(checkpointManifest{
		Version:     checkpointManifestFormatVersion,
		Layout:      checkpointSlottedLayout,
		Active:      active,
		Slots:       slots,
		Metadata:    metadata,
		ClockAnchor: clockAnchor.UTC(),
	})
	if err != nil {
		b.warnPersistFailure(fmt.Errorf("encode checkpoint manifest: %w", err))
		return false
	}
	if len(manifest) > maxCheckpointMetaBytes {
		b.warnPersistFailure(fmt.Errorf("checkpoint manifest is %d bytes; maximum is %d", len(manifest), maxCheckpointMetaBytes))
		return false
	}
	publication := &checkpointPublication{
		manifest:         manifest,
		previousManifest: append([]byte(nil), b.manifest...),
		active:           nextActive,
		slots:            nextSlots,
		clockAnchor:      clockAnchor.UTC(),
	}
	if len(stageOperations) > 0 {
		available, stageErr := b.registry.batch(ctx, stageOperations...)
		if !available || stageErr != nil {
			if stageErr != nil {
				b.warnPersistFailure(stageErr)
			}
			return false
		}
	}
	available, err := b.registry.set(ctx, b.manifestKey(), manifest)
	if !available {
		return false
	}
	if err != nil {
		// Set may have applied before returning an error. Until a read proves
		// whether the old or candidate manifest is live, neither slot view is
		// safe to overwrite.
		b.uncertain = publication
		resolved, candidateCommitted := b.resolvePublicationLocked(ctx, false)
		if resolved && candidateCommitted {
			return true
		}
		b.warnPersistFailure(err)
		return false
	}
	b.commitPublicationLocked(publication)
	return true
}

// maintain retries uncertain publication reconciliation or a validated legacy
// migration even when the domain has no dirty state of its own (for example,
// an empty polling delivery immediately after restore).
func (b *checkpointBinding) maintain(ctx context.Context) bool {
	if b == nil || b.registry == nil {
		return false
	}
	b.persistMu.Lock()
	defer b.persistMu.Unlock()
	if !b.ensureWriteFenceLocked(ctx) {
		return false
	}
	if b.uncertain != nil {
		resolved, _ := b.resolvePublicationLocked(ctx, true)
		if !resolved {
			return false
		}
	}
	if b.replaceGeneration {
		// The binding does not own a domain snapshot or its metadata. The
		// domain's replacement-dirty path must call persist with the complete
		// fresh generation before this fence can advance.
		return false
	}
	if b.legacy {
		return b.persistLocked(ctx, nil, nil, b.legacyMetadata, b.clockAnchor)
	}
	return true
}

func (b *checkpointBinding) acceptLoaded(loaded loadedCheckpoint) {
	if b == nil {
		return
	}
	b.persistMu.Lock()
	b.active = make(map[uint16]struct{}, len(loaded.active))
	for _, shard := range loaded.active {
		b.active[shard] = struct{}{}
	}
	b.slots = make(map[uint16]uint8, len(loaded.slots))
	maps.Copy(b.slots, loaded.slots)
	b.legacy = loaded.legacy
	b.manifest = append([]byte(nil), loaded.manifest...)
	b.clockAnchor = loaded.clockAnchor.UTC()
	b.fenceKnown = true
	b.replaceGeneration = false
	b.legacyShards = nil
	b.legacyMetadata = nil
	if loaded.legacy {
		b.legacyShards = make(map[uint16][]byte, len(loaded.shards))
		for shard, value := range loaded.shards {
			b.legacyShards[shard] = append([]byte(nil), value...)
		}
		b.legacyMetadata = append(json.RawMessage(nil), loaded.metadata...)
	}
	b.persistMu.Unlock()
}

func (b *checkpointBinding) invalidateWriteFence() {
	if b == nil {
		return
	}
	b.persistMu.Lock()
	b.invalidateWriteFenceLocked()
	b.persistMu.Unlock()
}

func (b *checkpointBinding) invalidateWriteFenceLocked() {
	b.fenceKnown = false
	b.replaceGeneration = true
	b.active = nil
	b.slots = nil
	b.legacy = false
	b.manifest = nil
	b.clockAnchor = time.Time{}
	b.legacyShards = nil
	b.legacyMetadata = nil
}

func (b *checkpointBinding) installEmptyWriteFence() {
	if b == nil {
		return
	}
	b.persistMu.Lock()
	b.installEmptyWriteFenceLocked()
	b.persistMu.Unlock()
}

func (b *checkpointBinding) installEmptyWriteFenceLocked() {
	b.fenceKnown = true
	b.replaceGeneration = false
	b.active = map[uint16]struct{}{}
	b.slots = map[uint16]uint8{}
	b.legacy = false
	b.manifest = nil
	b.clockAnchor = time.Time{}
	b.legacyShards = nil
	b.legacyMetadata = nil
}

func (b *checkpointBinding) installManifestWriteFence(manifest checkpointManifest, encoded []byte) {
	if b == nil {
		return
	}
	b.persistMu.Lock()
	b.installManifestWriteFenceLocked(manifest, encoded)
	b.persistMu.Unlock()
}

func (b *checkpointBinding) installManifestWriteFenceLocked(manifest checkpointManifest, encoded []byte) {
	b.fenceKnown = true
	b.replaceGeneration = true
	b.active = make(map[uint16]struct{}, len(manifest.Active))
	b.slots = make(map[uint16]uint8, len(manifest.Active))
	for i, shard := range manifest.Active {
		b.active[shard] = struct{}{}
		if manifest.Version == checkpointManifestFormatVersion {
			b.slots[shard] = manifest.Slots[i]
		}
	}
	b.legacy = manifest.Version == checkpointFormatVersion
	b.manifest = append([]byte(nil), encoded...)
	b.clockAnchor = manifest.ClockAnchor.UTC()
	b.legacyShards = nil
	b.legacyMetadata = nil
}

func (b *checkpointBinding) ensureWriteFenceLocked(ctx context.Context) bool {
	if b.fenceKnown {
		return true
	}
	value, available, err := b.registry.get(ctx, b.manifestKey())
	if !available || err != nil {
		if err != nil {
			b.warnPersistFailure(fmt.Errorf("establish checkpoint write fence: %w", err))
		}
		return false
	}
	if len(value) == 0 {
		b.installEmptyWriteFenceLocked()
		return true
	}
	if len(value) > maxCheckpointMetaBytes {
		b.warnPersistFailure(fmt.Errorf("establish checkpoint write fence: manifest is %d bytes; maximum is %d", len(value), maxCheckpointMetaBytes))
		return false
	}
	var manifest checkpointManifest
	if decodeErr := json.Unmarshal(value, &manifest); decodeErr != nil {
		b.warnPersistFailure(fmt.Errorf("establish checkpoint write fence: decode manifest: %w", decodeErr))
		return false
	}
	if validationErr := validateCheckpointManifest(manifest); validationErr != nil {
		b.warnPersistFailure(fmt.Errorf("establish checkpoint write fence: %w", validationErr))
		return false
	}
	b.installManifestWriteFenceLocked(manifest, value)
	return true
}

func (b *checkpointBinding) replacementRequired() bool {
	if b == nil {
		return false
	}
	b.persistMu.Lock()
	defer b.persistMu.Unlock()
	return b.replaceGeneration
}

func (b *checkpointBinding) resolvePublicationLocked(ctx context.Context, retryCandidate bool) (resolved, candidateCommitted bool) {
	publication := b.uncertain
	if publication == nil {
		return true, false
	}
	value, available, err := b.registry.get(ctx, b.manifestKey())
	if !available || err != nil {
		if err != nil {
			b.warnPersistFailure(fmt.Errorf("reconcile uncertain checkpoint manifest publication: %w", err))
		}
		return false, false
	}
	if len(value) > 0 {
		if len(value) > maxCheckpointMetaBytes {
			b.warnPersistFailure(fmt.Errorf("reconcile uncertain checkpoint manifest publication: manifest is %d bytes; maximum is %d", len(value), maxCheckpointMetaBytes))
			return false, false
		}
		var manifest checkpointManifest
		if decodeErr := json.Unmarshal(value, &manifest); decodeErr != nil {
			b.warnPersistFailure(fmt.Errorf("reconcile uncertain checkpoint manifest publication: %w", decodeErr))
			return false, false
		}
		if validationErr := validateCheckpointManifest(manifest); validationErr != nil {
			b.warnPersistFailure(fmt.Errorf("reconcile uncertain checkpoint manifest publication: %w", validationErr))
			return false, false
		}
	}
	switch {
	case bytes.Equal(value, publication.manifest):
		b.uncertain = nil
		b.commitPublicationLocked(publication)
		return true, true
	case bytes.Equal(value, publication.previousManifest):
		// A stale read cannot prove that an errored Set will never become
		// visible, so never reject the candidate or reuse its slots based on this
		// observation. A later persist or maintain call may retry the exact same
		// manifest once; publishing identical bytes is safe whether the first Set
		// was unapplied or was accepted while this read still observed stale data.
		// The storage contract requires the earlier invocation to remain ordered
		// before a successful retry, so it cannot later overwrite a newer manifest.
		if !retryCandidate {
			return false, false
		}
		available, setErr := b.registry.set(ctx, b.manifestKey(), publication.manifest)
		if !available || setErr != nil {
			if setErr != nil {
				b.warnPersistFailure(fmt.Errorf("retry uncertain checkpoint manifest publication: %w", setErr))
			}
			return false, false
		}
		b.uncertain = nil
		b.commitPublicationLocked(publication)
		return true, true
	default:
		b.warnPersistFailure(errors.New("reconcile uncertain checkpoint manifest publication: stored manifest is neither the previous nor candidate generation"))
		return false, false
	}
}

func (b *checkpointBinding) commitPublicationLocked(publication *checkpointPublication) {
	b.active = publication.active
	b.slots = publication.slots
	b.legacy = false
	b.manifest = append([]byte(nil), publication.manifest...)
	b.clockAnchor = publication.clockAnchor
	b.fenceKnown = true
	b.replaceGeneration = false
	b.legacyShards = nil
	b.legacyMetadata = nil
	b.loadFailed.Store(false)
	b.corrupt.Store(false)
	b.saveFailed.Store(false)
}

func (b *checkpointBinding) warnPersistFailure(err error) {
	if b.saveFailed.CompareAndSwap(false, true) {
		b.warn("Failed to persist Cisco OS checkpoint; collection will continue with in-memory state", err)
	}
}

func (b *checkpointBinding) manifestKey() string {
	return b.identity.key() + "/manifest"
}

func (b *checkpointBinding) shardKey(shard uint16) string {
	return fmt.Sprintf("%s/shards/%04d", b.identity.key(), shard)
}

func (b *checkpointBinding) slottedShardKey(shard uint16, slot uint8) string {
	return fmt.Sprintf("%s/slots/%d/shards/%04d", b.identity.key(), slot, shard)
}

func (b *checkpointBinding) warnCorrupt(err error) {
	if b != nil && b.corrupt.CompareAndSwap(false, true) {
		b.warn("Corrupt Cisco OS checkpoint was ignored; collection will continue with empty in-memory state", err)
	}
}

func (b *checkpointBinding) markValid() {
	if b != nil {
		b.corrupt.Store(false)
	}
}

func (b *checkpointBinding) warn(message string, err error) {
	b.registry.logger.Warn(message,
		zap.String("receiver", b.identity.Receiver),
		zap.String("provider", b.identity.Provider),
		zap.String("target", b.identity.Target),
		zap.String("signal", b.identity.Signal),
		zap.String("state", b.identity.State),
		zap.Error(err))
}

func validateCheckpointManifest(manifest checkpointManifest) error {
	switch manifest.Version {
	case checkpointFormatVersion:
		if manifest.Layout != 0 || len(manifest.Slots) != 0 {
			return errors.New("legacy checkpoint manifest contains slotted-layout fields")
		}
	case checkpointManifestFormatVersion:
		if manifest.Layout != checkpointSlottedLayout {
			return fmt.Errorf("checkpoint manifest version %d requires layout %d", manifest.Version, checkpointSlottedLayout)
		}
		if len(manifest.Slots) != len(manifest.Active) {
			return fmt.Errorf("checkpoint manifest contains %d active shards but %d slot references", len(manifest.Active), len(manifest.Slots))
		}
		for i, slot := range manifest.Slots {
			if slot >= checkpointShardSlots {
				return fmt.Errorf("checkpoint manifest shard %d references invalid slot %d", manifest.Active[i], slot)
			}
		}
	default:
		return fmt.Errorf("unsupported checkpoint manifest version %d", manifest.Version)
	}
	if len(manifest.Active) > checkpointShardCount {
		return fmt.Errorf("checkpoint manifest contains %d shards; maximum is %d", len(manifest.Active), checkpointShardCount)
	}
	seen := make(map[uint16]struct{}, len(manifest.Active))
	for _, shard := range manifest.Active {
		if shard >= checkpointShardCount {
			return fmt.Errorf("checkpoint manifest shard %d is out of range", shard)
		}
		if _, duplicate := seen[shard]; duplicate {
			return fmt.Errorf("checkpoint manifest contains duplicate shard %d", shard)
		}
		seen[shard] = struct{}{}
	}
	return nil
}

func checkpointShardWithRoom(shards map[uint16]*list.List, next *uint16) (uint16, bool) {
	for offset := range checkpointShardCount {
		candidate := (int(*next) + offset) % checkpointShardCount
		shardLRU := shards[uint16(candidate)]
		if shardLRU == nil || shardLRU.Len() < checkpointShardEntries {
			// Fill one page before advancing so a delivery touching adjacent new
			// entries usually rewrites one small page rather than many sparse pages.
			*next = uint16(candidate)
			return uint16(candidate), true
		}
	}
	return unassignedCheckpointShard, false
}

type counterCheckpointingConsumer struct {
	next  consumer.Metrics
	state *counterStore
}

func (c *counterCheckpointingConsumer) Capabilities() consumer.Capabilities {
	return c.next.Capabilities()
}

func (c *counterCheckpointingConsumer) ConsumeMetrics(ctx context.Context, md pmetric.Metrics) error {
	if err := c.next.ConsumeMetrics(ctx, md); err != nil {
		return err
	}
	c.state.persistCheckpoint(ctx)
	return nil
}

type checkpointedMetricsReceiver struct {
	next        receiver.Metrics
	checkpoints *checkpointRegistry
	shutdown    checkpointedReceiverShutdown
}

func (r *checkpointedMetricsReceiver) Start(ctx context.Context, host component.Host) error {
	if err := r.checkpoints.Start(ctx, host); err != nil {
		return err
	}
	if err := r.next.Start(ctx, host); err != nil {
		rollbackCtx, rollbackCancel := checkpointRollbackContext(ctx)
		defer rollbackCancel()
		r.checkpoints.Close(rollbackCtx)
		return err
	}
	return nil
}

func (r *checkpointedMetricsReceiver) Shutdown(ctx context.Context) error {
	return r.shutdown.shutdown(ctx, r.next.Shutdown, r.checkpoints)
}

type checkpointedLogsReceiver struct {
	next        receiver.Logs
	checkpoints *checkpointRegistry
	shutdown    checkpointedReceiverShutdown
}

func (r *checkpointedLogsReceiver) Start(ctx context.Context, host component.Host) error {
	if err := r.checkpoints.Start(ctx, host); err != nil {
		return err
	}
	if err := r.next.Start(ctx, host); err != nil {
		rollbackCtx, rollbackCancel := checkpointRollbackContext(ctx)
		defer rollbackCancel()
		r.checkpoints.Close(rollbackCtx)
		return err
	}
	return nil
}

func (r *checkpointedLogsReceiver) Shutdown(ctx context.Context) error {
	return r.shutdown.shutdown(ctx, r.next.Shutdown, r.checkpoints)
}

type checkpointedReceiverShutdown struct {
	once sync.Once
	done chan struct{}
	err  error
}

// shutdown detaches the single child shutdown from caller cancellation so the
// registry remains usable through the last in-flight delivery. Each caller
// still bounds only its own wait; accepted-state flush and Close run in order
// after the child lifecycle has actually terminated.
func (s *checkpointedReceiverShutdown) shutdown(ctx context.Context, shutdownNext func(context.Context) error, checkpoints *checkpointRegistry) error {
	s.once.Do(func() {
		s.done = make(chan struct{})
		go s.run(context.WithoutCancel(ctx), shutdownNext, checkpoints)
	})
	select {
	case <-s.done:
		return s.err
	case <-ctx.Done():
		select {
		case <-s.done:
			return s.err
		default:
			return ctx.Err()
		}
	}
}

func (s *checkpointedReceiverShutdown) run(ctx context.Context, shutdownNext func(context.Context) error, checkpoints *checkpointRegistry) {
	defer close(s.done)
	s.err = shutdownNext(ctx)
	flushCtx, flushCancel := checkpointFlushContext(ctx)
	checkpoints.flushAccepted(flushCtx)
	flushCancel()
	checkpoints.Close(ctx)
}
