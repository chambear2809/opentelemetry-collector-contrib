// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"fmt"
	"maps"
	"math"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/meraki"
)

const merakiScopeName = "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/meraki"

type merakiMetricsReceiver struct {
	settings receiver.Settings
	config   *Config
	consumer consumer.Metrics
	client   *meraki.Client
	targets  []merakiTarget
	counters *counterStore
	obs      *receiverhelper.ObsReport

	startMu sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}

	statsMu sync.Mutex
	stats   []meraki.RequestStat

	successMu             sync.Mutex
	successByOrganization map[string]*scrapeSuccessState
}

type merakiTarget struct {
	OrganizationID string
	NetworkIDs     []string
	Serials        []string
	ProductTypes   []string
	Tags           []string
	TagsFilterType string

	filters                []merakiTargetFilter
	explicitSerials        []string
	selectAll              bool
	unionRequiresInventory bool
}

type merakiTargetFilter struct {
	NetworkIDs     []string
	Serials        []string
	ProductTypes   []string
	Tags           []string
	TagsFilterType string
}

func newMerakiMetricsReceiver(set receiver.Settings, conf *Config, consumer consumer.Metrics) (*merakiMetricsReceiver, error) {
	client, err := meraki.NewClient(meraki.Config{
		APIKey:             string(conf.Meraki.Auth.APIKey),
		BaseURL:            conf.Meraki.BaseURL,
		UserAgent:          conf.Meraki.UserAgent,
		Timeout:            conf.Timeout,
		MaxRetries:         conf.Meraki.MaxRetries,
		InsecureSkipVerify: conf.Meraki.InsecureSkipVerify,
	})
	if err != nil {
		return nil, err
	}
	r := &merakiMetricsReceiver{
		settings:              set,
		config:                conf,
		consumer:              consumer,
		client:                client,
		targets:               normalizeMerakiTargets(conf.Meraki),
		counters:              newCounterStore(),
		obs:                   newPlatformObsReport(set, "http"),
		done:                  make(chan struct{}),
		successByOrganization: make(map[string]*scrapeSuccessState),
	}
	client.OnRequest = r.recordRequest
	return r, nil
}

func normalizeMerakiTargets(cfg MerakiConfig) []merakiTarget {
	byOrganization := make(map[string]merakiTarget, len(cfg.Organizations)+len(cfg.Devices))
	for i := range cfg.Organizations {
		org := &cfg.Organizations[i]
		organizationID := strings.TrimSpace(org.OrganizationID)
		target := byOrganization[organizationID]
		target.OrganizationID = organizationID
		target.filters = append(target.filters, merakiTargetFilter{
			NetworkIDs:     uniqueStrings(org.NetworkIDs),
			Serials:        uniqueStrings(org.Serials),
			ProductTypes:   uniqueStrings(org.ProductTypes),
			Tags:           uniqueStrings(org.Tags),
			TagsFilterType: org.TagsFilterType,
		})
		byOrganization[organizationID] = target
	}

	for _, device := range cfg.Devices {
		organizationID := strings.TrimSpace(device.OrganizationID)
		target := byOrganization[organizationID]
		target.OrganizationID = organizationID
		target.explicitSerials = uniqueStrings(append(target.explicitSerials, device.Serial))
		byOrganization[organizationID] = target
	}
	orgs := make([]string, 0, len(byOrganization))
	for orgID := range byOrganization {
		orgs = append(orgs, orgID)
	}
	sort.Strings(orgs)
	targets := make([]merakiTarget, 0, len(orgs))
	for _, orgID := range orgs {
		target := byOrganization[orgID]
		target.configureQueryScope()
		targets = append(targets, target)
	}
	return targets
}

func (t *merakiTarget) configureQueryScope() {
	for _, filter := range t.filters {
		if filter.empty() {
			t.selectAll = true
			return
		}
	}

	allSerialOnly := len(t.filters) > 0
	for _, filter := range t.filters {
		if !filter.serialOnly() {
			allSerialOnly = false
			break
		}
	}
	if allSerialOnly {
		serials := append([]string(nil), t.explicitSerials...)
		for _, filter := range t.filters {
			serials = append(serials, filter.Serials...)
		}
		t.Serials = uniqueStrings(serials)
		return
	}

	if len(t.filters) == 1 && len(t.explicitSerials) == 0 {
		filter := t.filters[0]
		t.NetworkIDs = filter.NetworkIDs
		t.Serials = filter.Serials
		t.ProductTypes = filter.ProductTypes
		t.Tags = filter.Tags
		t.TagsFilterType = filter.TagsFilterType
		return
	}

	if len(t.filters) == 0 {
		t.Serials = append([]string(nil), t.explicitSerials...)
		return
	}

	// A union of filtered organization targets and/or explicit device targets
	// cannot be represented as one Dashboard query because query fields are
	// intersected. Fetch inventory broadly, resolve the union locally, then use
	// its serial allowlist for every downstream endpoint.
	t.unionRequiresInventory = true
}

func (f merakiTargetFilter) empty() bool {
	return len(f.NetworkIDs) == 0 && len(f.Serials) == 0 && len(f.ProductTypes) == 0 && len(f.Tags) == 0
}

func (f merakiTargetFilter) serialOnly() bool {
	return len(f.Serials) > 0 && len(f.NetworkIDs) == 0 && len(f.ProductTypes) == 0 && len(f.Tags) == 0
}

func (r *merakiMetricsReceiver) Start(_ context.Context, _ component.Host) error {
	r.startMu.Lock()
	defer r.startMu.Unlock()
	if r.cancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go r.run(ctx)
	return nil
}

func (r *merakiMetricsReceiver) Shutdown(ctx context.Context) error {
	r.startMu.Lock()
	cancel := r.cancel
	r.startMu.Unlock()
	if cancel == nil {
		r.client.CloseIdleConnections()
		return nil
	}
	cancel()
	defer r.client.CloseIdleConnections()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *merakiMetricsReceiver) run(ctx context.Context) {
	defer close(r.done)
	r.collect(ctx)
	ticker := time.NewTicker(r.config.CollectionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.collect(ctx)
		}
	}
}

func (r *merakiMetricsReceiver) collect(ctx context.Context) {
	scrapeCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()

	obsCtx := startMetricsOp(ctx, r.obs)
	md, scrapeErr := r.scrape(scrapeCtx)
	if scrapeErr != nil {
		r.settings.Logger.Error("Meraki scrape failed", zap.Error(scrapeErr))
	}
	metricCount, consumeErr := consumeMetricsIfPresent(ctx, r.consumer, md)
	if consumeErr != nil {
		r.settings.Logger.Error("Meraki metrics consumer failed", zap.Error(consumeErr))
	}
	endMetricsOp(obsCtx, r.obs, metricCount, combineSignalErrors(scrapeErr, consumeErr))
}

func (r *merakiMetricsReceiver) scrape(ctx context.Context) (pmetric.Metrics, error) {
	r.resetRequestStats()
	now := time.Now()
	builder := newMerakiMetricsBuilder(now, r.counters)
	partialByOrganization := make(map[string]bool, len(r.targets))
	var scrapeErr error

	for i := range r.targets {
		target := &r.targets[i]
		targetPartial, err := r.scrapeTarget(ctx, builder, *target)
		partialByOrganization[target.OrganizationID] = targetPartial || err != nil
		if err != nil {
			scrapeErr = err
			// The shared scrape context is no longer usable. Mark targets that
			// could not be attempted as partial instead of silently reporting
			// them as successful.
			for j := i + 1; j < len(r.targets); j++ {
				remaining := &r.targets[j]
				partialByOrganization[remaining.OrganizationID] = true
			}
			break
		}
	}

	return r.finishScrape(builder, partialByOrganization), scrapeErr
}

func (r *merakiMetricsReceiver) finishScrape(builder *merakiMetricsBuilder, partialByOrganization map[string]bool) pmetric.Metrics {
	r.recordAPIRequestMetrics(builder)
	stats := r.requestStats()
	for i := range r.targets {
		target := &r.targets[i]
		rb := builder.orgResource(target.OrganizationID)
		partial := partialByOrganization[target.OrganizationID]
		rb.recordInt("cisco.scrape.partial_success", "Whether one or more Meraki endpoint families failed during the scrape.", "1", boolToInt(partial), nil)
		outcome := merakiOrganizationOutcome(stats, target.OrganizationID)
		if availability, ok := outcome.availability(); ok {
			rb.recordInt("meraki.controller.up", "Meraki Dashboard API availability for this organization and scrape.", "1", availability, nil)
		}
		if lastSuccess, ok := r.successState(target.OrganizationID).observe(time.Now(), !partial && outcome.succeeded); ok {
			rb.recordInt("meraki.scrape.last_success", "Unix timestamp of the most recent fully successful Meraki scrape for this organization.", "s", lastSuccess.Unix(), nil)
		}
	}
	return builder.emit()
}

func merakiOrganizationOutcome(stats []meraki.RequestStat, organizationID string) apiOutcomeSummary {
	summary := apiOutcomeSummary{}
	for _, stat := range stats {
		if stat.OrganizationID != organizationID {
			continue
		}
		summary.attempted = true
		if stat.Outcome == "success" {
			summary.succeeded = true
		}
	}
	return summary
}

func (r *merakiMetricsReceiver) successState(organizationID string) *scrapeSuccessState {
	r.successMu.Lock()
	defer r.successMu.Unlock()
	if r.successByOrganization == nil {
		r.successByOrganization = make(map[string]*scrapeSuccessState)
	}
	state := r.successByOrganization[organizationID]
	if state == nil {
		state = &scrapeSuccessState{}
		r.successByOrganization[organizationID] = state
	}
	return state
}

func (r *merakiMetricsReceiver) scrapeTarget(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget) (bool, error) {
	partial := false
	selector := newDeviceSelectionMatcher(r.config.DeviceSelection)
	allowedSerials := target.serialSet()
	devices, err := meraki.GetPaginatedJSON[meraki.Device](ctx, r.client, target.OrganizationID, "devices", meraki.OrganizationPath(target.OrganizationID, "/devices"), target.deviceInventoryQuery())
	inventorySucceeded := err == nil
	if err != nil {
		if ctx.Err() != nil {
			return partial, ctx.Err()
		}
		partial = true
		r.settings.Logger.Warn("Meraki device inventory endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
	}
	inventorySerials := make(map[string]struct{}, len(devices))
	for i := range devices {
		device := &devices[i]
		if device.Serial == "" || !allowsSerial(allowedSerials, device.Serial) || !target.allowsInventoryMetadata(*device) {
			continue
		}
		resource := deviceResourceFromInventory(*device)
		// Device status contributes public IP identity, so defer shared selector
		// evaluation until inventory and status resources have been merged.
		builder.deviceResource(resource)
		inventorySerials[device.Serial] = struct{}{}
	}
	if inventorySucceeded {
		// Inventory is the authoritative intersection for network, product,
		// tag, serial, and shared device selectors. Replacing the allowlist even
		// when it is empty prevents a configured serial from reappearing through
		// an endpoint that lacks one of those filters or identity fields.
		allowedSerials = inventorySerials
	} else if target.requiresInventoryResolution(selector) {
		// A serial-only target can still be enforced exactly when inventory is
		// unavailable. Every other target scope needs inventory to translate its
		// filters into a serial allowlist for organization-wide endpoints. Keep
		// safely selected results from any pages returned before a later page
		// failed, but never broaden beyond that partial allowlist.
		allowedSerials = inventorySerials
		if selector.empty() {
			maps.Copy(allowedSerials, target.fallbackSerialSet())
		}
		if len(allowedSerials) == 0 {
			return partial, nil
		}
	}
	serialScoped := target.scoped(selector)
	if serialScoped {
		if len(allowedSerials) == 0 {
			// Dynamic selectors are resolved through inventory. With no selected
			// devices, querying organization-wide endpoints would only add load
			// and risks collecting data outside the configured scope.
			return partial, nil
		}
	}

	statuses, statusErr := meraki.GetPaginatedJSON[meraki.DeviceStatus](ctx, r.client, target.OrganizationID, "device_statuses", meraki.OrganizationPath(target.OrganizationID, "/devices/statuses"), target.deviceStatusQuery())
	if statusErr != nil {
		partial = true
		r.settings.Logger.Warn("Meraki device status endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(statusErr))
	}
	statusSerials := make(map[string]struct{}, len(statuses))
	for i := range statuses {
		status := &statuses[i]
		if status.Serial == "" || !allowsSerial(allowedSerials, status.Serial) {
			continue
		}
		builder.deviceResource(deviceResourceFromStatus(*status))
		statusSerials[status.Serial] = struct{}{}
	}
	uplinkStatuses, uplinkStatusErr := meraki.GetPaginatedJSON[meraki.UplinkStatus](ctx, r.client, target.OrganizationID, "uplink_statuses", meraki.OrganizationPath(target.OrganizationID, "/uplinks/statuses"), target.uplinkStatusQuery())
	if uplinkStatusErr != nil {
		partial = true
		r.settings.Logger.Warn("Meraki uplink status endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(uplinkStatusErr))
	}
	uplinkStatusSerials := make(map[string]struct{}, len(uplinkStatuses))
	for i := range uplinkStatuses {
		status := &uplinkStatuses[i]
		if status.Serial == "" || !allowsSerial(allowedSerials, status.Serial) {
			continue
		}
		builder.deviceResource(deviceResourceFromUplinkStatus(*status))
		uplinkStatusSerials[status.Serial] = struct{}{}
	}

	if !selector.empty() {
		completeIPIdentityRequired := len(selector.exclude.hostIPs) > 0
		selectedSerials := make(map[string]struct{}, len(allowedSerials))
		incompleteIPIdentity := false
		for serial := range allowedSerials {
			device, ok := builder.devices[serial]
			if !ok {
				continue
			}
			if completeIPIdentityRequired {
				if _, ok := statusSerials[serial]; !ok {
					// A missing status could hide a public-IP exclusion. Keep
					// only devices whose complete IP identity was observed.
					incompleteIPIdentity = true
					continue
				}
				if merakiDeviceUsesUplinkStatus(device) {
					if _, ok := uplinkStatusSerials[serial]; !ok {
						// The uplink-status endpoint is the authoritative source
						// for MX, vMX, MG, and Z uplink IP identities.
						incompleteIPIdentity = true
						continue
					}
				}
			}
			if !selector.allows(merakiDeviceIdentity(device)) {
				continue
			}
			selectedSerials[serial] = struct{}{}
		}
		if incompleteIPIdentity {
			partial = true
			r.settings.Logger.Warn("Meraki IP selector identity was incomplete; affected devices were excluded", zap.String("organization_id", target.OrganizationID))
		}
		allowedSerials = selectedSerials
		if len(allowedSerials) == 0 {
			if ctx.Err() != nil {
				return true, ctx.Err()
			}
			return partial, nil
		}
	}

	recordMerakiDeviceStatuses(builder, statuses, allowedSerials)
	recordMerakiUplinkStatuses(builder, uplinkStatuses, allowedSerials, selector)
	if ctx.Err() != nil {
		return true, ctx.Err()
	}

	if statusErr != nil {
		partial = true
	}
	if r.scrapeMemoryUsage(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}
	if r.scrapeSwitchPorts(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}
	if r.scrapeUplinkLossLatency(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}
	if r.scrapeWireless(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}
	if r.scrapeVPN(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}
	if r.scrapePowerModules(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}
	if r.scrapeTopology(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}
	if r.scrapeTransceivers(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}
	if r.scrapeAppliancePerformance(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}

	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	return partial, nil
}

func recordMerakiDeviceStatuses(builder *merakiMetricsBuilder, statuses []meraki.DeviceStatus, allowedSerials map[string]struct{}) {
	for i := range statuses {
		status := &statuses[i]
		if !allowsSerial(allowedSerials, status.Serial) {
			continue
		}
		resource := deviceResourceFromStatus(*status)
		rb := builder.deviceResource(resource)
		if up, ok := merakiDeviceUp(status.Status); ok {
			rb.recordInt("cisco.device.up", "Device availability (1 = up, 0 = down).", "1", up, nil)
		}
		if code, ok := merakiStatusCode(status.Status); ok {
			rb.recordInt("meraki.device.status", "Meraki Dashboard device status.", "1", code, map[string]string{
				"meraki.device.status":       status.Status,
				"meraki.device.product_type": status.ProductType,
			})
		}
	}
}

func merakiDeviceUsesUplinkStatus(device deviceResource) bool {
	productType := strings.ToLower(strings.TrimSpace(device.ProductType))
	if productType == "appliance" || productType == "cellulargateway" {
		return true
	}
	model := strings.ToUpper(strings.TrimSpace(device.Model))
	return strings.HasPrefix(model, "MX") || strings.HasPrefix(model, "VMX") || strings.HasPrefix(model, "MG") || strings.HasPrefix(model, "Z")
}

func (r *merakiMetricsReceiver) scrapeMemoryUsage(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	usages, err := meraki.GetPaginatedItemsJSON[meraki.DeviceMemoryUsage](ctx, r.client, target.OrganizationID, "device_memory", meraki.OrganizationPath(target.OrganizationID, "/devices/system/memory/usage/history/byInterval"), target.memoryQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki memory usage endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		if ctx.Err() != nil {
			return true
		}
	}
	for i := range usages {
		usage := &usages[i]
		if !allowsSerial(allowedSerials, usage.Serial) {
			continue
		}
		resource := deviceResourceFromMemory(*usage)
		rb, selected := builder.selectedDeviceResource(resource, selector)
		if !selected {
			continue
		}
		if value, observedAt, ok := memoryUtilization(*usage); ok {
			rb.recordDoubleAt("system.memory.utilization", "Memory utilization as a ratio from 0 to 1.", "1", value, map[string]string{"system.memory.state": "used"}, observedAt)
		}
	}
	return err != nil
}

func (r *merakiMetricsReceiver) scrapeSwitchPorts(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	partial := false
	statuses, err := meraki.GetPaginatedItemsJSON[meraki.SwitchPortsStatus](ctx, r.client, target.OrganizationID, "switch_ports_status", meraki.OrganizationPath(target.OrganizationID, "/switch/ports/statuses/bySwitch"), target.switchStatusQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki switch port status endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		partial = true
		if ctx.Err() != nil {
			return true
		}
	}
	for i := range statuses {
		sw := &statuses[i]
		if !allowsSerial(allowedSerials, sw.Serial) {
			continue
		}
		resource := deviceResourceFromSwitch(*sw)
		rb, selected := builder.selectedDeviceResource(resource, selector)
		if !selected {
			continue
		}
		for j := range sw.Ports {
			port := &sw.Ports[j]
			speedBits, speedString := parseMerakiSpeed(port.Speed)
			if speedBits > 0 {
				builder.setPortSpeed(sw.Serial, port.PortID, speedBits)
				rb.recordInt("cisco.interface.speed", "Interface line speed.", "bit/s", speedBits, interfaceAttrs(port.PortID, sw.MAC, "", speedString))
			}
			if connected, ok := connectedStatus(port.Status); ok {
				rb.recordInt("system.network.interface.status", "Interface operational status (1 = up, 0 = down).", "1", connected, interfaceAttrs(port.PortID, sw.MAC, "", speedString))
			}
			rb.recordInt("cisco.interface.admin.status", "Interface administrative status (1 = enabled, 0 = disabled).", "1", boolToInt(port.Enabled), interfaceAttrs(port.PortID, sw.MAC, "", speedString))
			rb.recordInt("meraki.switch.port.poe.allocated", "Whether Meraki reports PoE as allocated on the switch port.", "1", boolToInt(port.PoE.IsAllocated), interfaceAttrs(port.PortID, sw.MAC, "", speedString))
			for _, reason := range port.Errors {
				attrs := interfaceAttrs(port.PortID, sw.MAC, "", speedString)
				attrs["meraki.switch.port.alert.severity"] = "error"
				attrs["meraki.switch.port.alert.reason"] = reason
				rb.recordInt("meraki.switch.port.alert.active", "Current Meraki switch port error or warning.", "1", 1, attrs)
			}
			for _, reason := range port.Warnings {
				attrs := interfaceAttrs(port.PortID, sw.MAC, "", speedString)
				attrs["meraki.switch.port.alert.severity"] = "warning"
				attrs["meraki.switch.port.alert.reason"] = reason
				rb.recordInt("meraki.switch.port.alert.active", "Current Meraki switch port error or warning.", "1", 1, attrs)
			}
		}
	}

	usages, err := meraki.GetPaginatedItemsJSON[meraki.SwitchPortsUsage](ctx, r.client, target.OrganizationID, "switch_ports_usage", meraki.OrganizationPath(target.OrganizationID, "/switch/ports/usage/history/byDevice/byInterval"), target.switchUsageQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki switch port usage endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		partial = true
		if ctx.Err() != nil {
			return true
		}
	}
	for i := range usages {
		sw := &usages[i]
		if !allowsSerial(allowedSerials, sw.Serial) {
			continue
		}
		resource := deviceResourceFromSwitchUsage(*sw)
		rb, selected := builder.selectedDeviceResource(resource, selector)
		if !selected {
			continue
		}
		for j := range sw.Ports {
			port := &sw.Ports[j]
			if len(port.Intervals) == 0 {
				continue
			}
			intervalIndex, observedAt := latestTimestampedIndex(len(port.Intervals), len(port.Intervals)-1, func(index int) string {
				return firstValidTimestamp(port.Intervals[index].EndTS, port.Intervals[index].StartTS)
			})
			interval := port.Intervals[intervalIndex]
			speedBits := builder.portSpeed(sw.Serial, port.PortID)
			speedString := ""
			if speedBits > 0 {
				speedString = strconv.FormatInt(speedBits, 10)
			}
			attrsRx := interfaceAttrs(port.PortID, sw.MAC, "", speedString)
			attrsRx["network.io.direction"] = "receive"
			attrsTx := interfaceAttrs(port.PortID, sw.MAC, "", speedString)
			attrsTx["network.io.direction"] = "transmit"
			rxBits, rxRateOK := merakiKilobitsToBits(interval.Bandwidth.Usage.Downstream)
			txBits, txRateOK := merakiKilobitsToBits(interval.Bandwidth.Usage.Upstream)
			if rxRateOK {
				rb.recordDoubleAt("cisco.interface.io.rate", "Interface traffic rate.", "bit/s", float64(rxBits), attrsRx, observedAt)
			}
			if txRateOK {
				rb.recordDoubleAt("cisco.interface.io.rate", "Interface traffic rate.", "bit/s", float64(txBits), attrsTx, observedAt)
			}
			if validNonnegativeFloat(interval.Data.Usage.Downstream) {
				rb.recordDoubleAt("meraki.switch.port.usage", "Windowed switch port usage reported by Meraki.", "kBy", interval.Data.Usage.Downstream, attrsRx, observedAt)
			}
			if validNonnegativeFloat(interval.Data.Usage.Upstream) {
				rb.recordDoubleAt("meraki.switch.port.usage", "Windowed switch port usage reported by Meraki.", "kBy", interval.Data.Usage.Upstream, attrsTx, observedAt)
			}
			if utilization, ok := merakiInterfaceUtilization(rxBits, speedBits, rxRateOK); ok {
				rb.recordDoubleAt("cisco.interface.utilization", "Interface traffic utilization as a ratio from 0 to 1.", "1", utilization, attrsRx, observedAt)
			}
			if utilization, ok := merakiInterfaceUtilization(txBits, speedBits, txRateOK); ok {
				rb.recordDoubleAt("cisco.interface.utilization", "Interface traffic utilization as a ratio from 0 to 1.", "1", utilization, attrsTx, observedAt)
			}
		}
	}

	return partial
}

func recordMerakiUplinkStatuses(builder *merakiMetricsBuilder, statuses []meraki.UplinkStatus, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) {
	for i := range statuses {
		device := &statuses[i]
		if !allowsSerial(allowedSerials, device.Serial) {
			continue
		}
		resource := deviceResourceFromUplinkStatus(*device)
		rb, selected := builder.selectedDeviceResource(resource, selector)
		if !selected {
			continue
		}
		for j := range device.Uplinks {
			uplink := &device.Uplinks[j]
			attrs := map[string]string{
				"meraki.uplink.interface":       uplink.Interface,
				"meraki.uplink.status":          uplink.Status,
				"meraki.uplink.provider":        uplink.Provider,
				"meraki.uplink.connection_type": uplink.ConnectionType,
			}
			if active, ok := activeStatus(uplink.Status); ok {
				rb.recordInt("meraki.uplink.status", "Meraki uplink status.", "1", active, attrs)
			}
			if rsrp, ok := parseFloatString(uplink.SignalStat.RSRP); ok {
				rb.recordDouble("meraki.uplink.cellular.signal.rsrp", "Cellular uplink RSRP.", "dBm", rsrp, attrs)
			}
			if rsrq, ok := parseFloatString(uplink.SignalStat.RSRQ); ok {
				rb.recordDouble("meraki.uplink.cellular.signal.rsrq", "Cellular uplink RSRQ.", "dB", rsrq, attrs)
			}
		}
	}
}

func (r *merakiMetricsReceiver) scrapeUplinkLossLatency(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	lossLatency, err := meraki.GetJSON[[]meraki.UplinkLossLatency](ctx, r.client, target.OrganizationID, "uplink_loss_latency", meraki.OrganizationPath(target.OrganizationID, "/devices/uplinksLossAndLatency"), nil)
	if err != nil {
		r.settings.Logger.Warn("Meraki uplink loss and latency endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		return true
	}
	for _, uplink := range lossLatency {
		if !allowsSerial(allowedSerials, uplink.Serial) || len(uplink.TimeSeries) == 0 {
			continue
		}
		sampleIndex, observedAt := latestTimestampedIndex(len(uplink.TimeSeries), len(uplink.TimeSeries)-1, func(index int) string {
			return uplink.TimeSeries[index].TS
		})
		sample := uplink.TimeSeries[sampleIndex]
		// The loss/latency IP is the monitored target, not another stable
		// device identity. Uplink device IPs come from /uplinks/statuses.
		resource := deviceResource{Serial: uplink.Serial, NetworkID: uplink.NetworkID, OSName: "Meraki"}
		rb, selected := builder.selectedDeviceResource(resource, selector)
		if !selected {
			continue
		}
		attrs := map[string]string{"meraki.uplink.interface": uplink.Uplink}
		rb.recordDoubleAt("meraki.uplink.loss", "Meraki uplink packet loss percentage.", "%", sample.LossPercent, attrs, observedAt)
		rb.recordDoubleAt("meraki.uplink.latency", "Meraki uplink latency.", "ms", sample.LatencyMS, attrs, observedAt)
	}
	return false
}

func (r *merakiMetricsReceiver) scrapeWireless(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	partial := false
	clients, err := meraki.GetPaginatedItemsJSON[meraki.WirelessClientsOverview](ctx, r.client, target.OrganizationID, "wireless_clients", meraki.OrganizationPath(target.OrganizationID, "/wireless/clients/overview/byDevice"), target.wirelessClientsQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki wireless clients endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		partial = true
		if ctx.Err() != nil {
			return true
		}
	}
	for _, device := range clients {
		if !allowsSerial(allowedSerials, device.Serial) {
			continue
		}
		resource := deviceResource{Serial: device.Serial, NetworkID: device.Network.ID, OSName: "Meraki"}
		rb, selected := builder.selectedDeviceResource(resource, selector)
		if !selected {
			continue
		}
		for status, count := range device.Counts.ByStatus {
			rb.recordInt("meraki.wireless.client.count", "Wireless client count by status.", "{client}", count, map[string]string{"meraki.wireless.client.status": status})
		}
	}

	channels, err := meraki.GetPaginatedJSON[meraki.WirelessChannelUtilization](ctx, r.client, target.OrganizationID, "wireless_channel_utilization", meraki.OrganizationPath(target.OrganizationID, "/wireless/devices/channelUtilization/byDevice"), target.wirelessChannelQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki wireless channel utilization endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		partial = true
		if ctx.Err() != nil {
			return true
		}
	}
	for _, device := range channels {
		if !allowsSerial(allowedSerials, device.Serial) {
			continue
		}
		resource := deviceResource{Serial: device.Serial, MAC: device.MAC, NetworkID: device.Network.ID, OSName: "Meraki"}
		rb, selected := builder.selectedDeviceResource(resource, selector)
		if !selected {
			continue
		}
		for _, band := range device.ByBand {
			attrs := map[string]string{"meraki.wireless.band": band.Band}
			rb.recordDouble("meraki.wireless.channel_utilization", "Wireless channel utilization percentage.", "%", band.Total.Percentage, withAttr(attrs, "meraki.wireless.utilization.type", "total"))
			rb.recordDouble("meraki.wireless.channel_utilization", "Wireless channel utilization percentage.", "%", band.WiFi.Percentage, withAttr(attrs, "meraki.wireless.utilization.type", "wifi"))
			rb.recordDouble("meraki.wireless.channel_utilization", "Wireless channel utilization percentage.", "%", band.NonWiFi.Percentage, withAttr(attrs, "meraki.wireless.utilization.type", "non_wifi"))
		}
	}

	packetLoss, err := meraki.GetPaginatedJSON[meraki.WirelessPacketLoss](ctx, r.client, target.OrganizationID, "wireless_packet_loss", meraki.OrganizationPath(target.OrganizationID, "/wireless/devices/packetLoss/byDevice"), target.wirelessPacketLossQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki wireless packet loss endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		partial = true
		if ctx.Err() != nil {
			return true
		}
	}
	for i := range packetLoss {
		device := &packetLoss[i]
		if !allowsSerial(allowedSerials, device.Device.Serial) {
			continue
		}
		resource := deviceResource{Serial: device.Device.Serial, Name: device.Device.Name, MAC: device.Device.MAC, NetworkID: device.Network.ID, OSName: "Meraki"}
		rb, selected := builder.selectedDeviceResource(resource, selector)
		if !selected {
			continue
		}
		recordWirelessPacketLoss(rb, "receive", device.Downstream)
		recordWirelessPacketLoss(rb, "transmit", device.Upstream)
	}

	ssids, err := meraki.GetPaginatedItemsJSON[meraki.WirelessSSIDStatus](ctx, r.client, target.OrganizationID, "wireless_ssids", meraki.OrganizationPath(target.OrganizationID, "/wireless/ssids/statuses/byDevice"), target.wirelessSSIDQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki wireless SSID status endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		partial = true
		if ctx.Err() != nil {
			return true
		}
	}
	for _, device := range ssids {
		if !allowsSerial(allowedSerials, device.Serial) {
			continue
		}
		resource := deviceResource{Serial: device.Serial, Name: device.Name, NetworkID: device.Network.ID, OSName: "Meraki"}
		rb, selected := builder.selectedDeviceResource(resource, selector)
		if !selected {
			continue
		}
		for _, bss := range device.BasicServiceSets {
			attrs := map[string]string{
				"meraki.wireless.ssid.name":   bss.SSID.Name,
				"meraki.wireless.ssid.number": strconv.FormatInt(bss.SSID.Number, 10),
				"meraki.wireless.bssid":       bss.BSSID,
				"meraki.wireless.band":        bss.Radio.Band,
				"meraki.wireless.radio.index": bss.Radio.Index,
			}
			rb.recordInt("meraki.wireless.ssid.status", "Wireless SSID enabled, advertised, and broadcasting status.", "1", boolToInt(bss.SSID.Enabled && bss.SSID.Advertised && bss.Radio.IsBroadcasting), attrs)
		}
	}

	return partial
}

func (r *merakiMetricsReceiver) scrapeVPN(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	partial := false
	deviceScoped := target.unionRequiresInventory || len(target.explicitSerials) > 0 || len(target.Serials) > 0 || len(target.ProductTypes) > 0 || len(target.Tags) > 0 || !selector.empty()
	networkScoped := len(target.NetworkIDs) > 0
	filterNetworks := target.scoped(selector)
	allowedNetworks := make(map[string]struct{}, len(target.NetworkIDs))
	if networkScoped && !deviceScoped {
		for _, networkID := range target.NetworkIDs {
			allowedNetworks[networkID] = struct{}{}
		}
	}
	statuses, err := meraki.GetPaginatedJSON[meraki.VPNStatus](ctx, r.client, target.OrganizationID, "vpn_statuses", meraki.OrganizationPath(target.OrganizationID, "/appliance/vpn/statuses"), target.vpnStatusQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki VPN status endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		partial = true
		if ctx.Err() != nil {
			return true
		}
	}
	for i := range statuses {
		status := &statuses[i]
		if !allowsSerial(allowedSerials, status.DeviceSerial) {
			continue
		}
		resource := deviceResource{Serial: status.DeviceSerial, NetworkID: status.NetworkID, OSName: "Meraki"}
		rb, selected := builder.selectedDeviceResource(resource, selector)
		if !selected {
			continue
		}
		if status.NetworkID != "" {
			allowedNetworks[status.NetworkID] = struct{}{}
		}
		for j := range status.MerakiVPNPeers {
			peer := &status.MerakiVPNPeers[j]
			if reachable, ok := reachableStatus(peer.Reachability); ok {
				rb.recordInt("meraki.vpn.peer.status", "Meraki VPN peer reachability.", "1", reachable, map[string]string{
					"meraki.vpn.peer.type":         "meraki",
					"meraki.vpn.peer.network_id":   peer.NetworkID,
					"meraki.vpn.peer.name":         peer.NetworkName,
					"meraki.vpn.peer.reachability": peer.Reachability,
				})
			}
		}
		for _, peer := range status.ThirdPartyVPNPeers {
			if reachable, ok := reachableStatus(peer.Reachability); ok {
				rb.recordInt("meraki.vpn.peer.status", "Meraki VPN peer reachability.", "1", reachable, map[string]string{
					"meraki.vpn.peer.type":         "third_party",
					"meraki.vpn.peer.name":         peer.Name,
					"meraki.vpn.peer.public_ip":    peer.PublicIP,
					"meraki.vpn.peer.reachability": peer.Reachability,
				})
			}
		}
	}
	if filterNetworks && len(allowedNetworks) == 0 {
		return partial
	}

	stats, err := meraki.GetPaginatedJSON[meraki.VPNStats](ctx, r.client, target.OrganizationID, "vpn_stats", meraki.OrganizationPath(target.OrganizationID, "/appliance/vpn/stats"), target.vpnStatsQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki VPN stats endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		partial = true
		if ctx.Err() != nil {
			return true
		}
	}
	for _, stat := range stats {
		if stat.NetworkID == "" {
			continue
		}
		if filterNetworks {
			if _, ok := allowedNetworks[stat.NetworkID]; !ok {
				continue
			}
		}
		rb := builder.networkResource(stat.NetworkID, stat.NetworkName, target.OrganizationID)
		for i := range stat.MerakiVPNPeers {
			peer := &stat.MerakiVPNPeers[i]
			peerAttrs := map[string]string{
				"meraki.vpn.peer.network_id": peer.NetworkID,
				"meraki.vpn.peer.name":       peer.NetworkName,
			}
			rb.recordInt("meraki.vpn.peer.usage", "Windowed Meraki VPN peer usage.", "kBy", int64(peer.UsageSummary.ReceivedInKilobytes), withAttr(peerAttrs, "network.io.direction", "receive"))
			rb.recordInt("meraki.vpn.peer.usage", "Windowed Meraki VPN peer usage.", "kBy", int64(peer.UsageSummary.SentInKilobytes), withAttr(peerAttrs, "network.io.direction", "transmit"))
			for _, latency := range peer.LatencySummaries {
				rb.recordDouble("meraki.vpn.peer.latency", "Meraki VPN peer latency.", "ms", latency.AvgLatencyMS, withVPNUplinks(peerAttrs, latency.SenderUplink, latency.ReceiverUplink))
			}
			for _, loss := range peer.LossPercentageSummaries {
				rb.recordDouble("meraki.vpn.peer.loss", "Meraki VPN peer packet loss percentage.", "%", loss.AvgLossPercentage, withVPNUplinks(peerAttrs, loss.SenderUplink, loss.ReceiverUplink))
			}
			for _, jitter := range peer.JitterSummaries {
				rb.recordDouble("meraki.vpn.peer.jitter", "Meraki VPN peer jitter.", "ms", jitter.AvgJitter, withVPNUplinks(peerAttrs, jitter.SenderUplink, jitter.ReceiverUplink))
			}
			for _, mos := range peer.MOSSummaries {
				rb.recordDouble("meraki.vpn.peer.mos", "Meraki VPN peer MOS score.", "1", mos.AvgMOS, withVPNUplinks(peerAttrs, mos.SenderUplink, mos.ReceiverUplink))
			}
		}
	}
	return partial
}

func (r *merakiMetricsReceiver) scrapePowerModules(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	statuses, err := meraki.GetPaginatedJSON[meraki.PowerModuleStatus](ctx, r.client, target.OrganizationID, "power_modules", meraki.OrganizationPath(target.OrganizationID, "/devices/powerModules/statuses/byDevice"), target.powerModulesQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki power module endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		if ctx.Err() != nil {
			return true
		}
	}
	for i := range statuses {
		device := &statuses[i]
		if !allowsSerial(allowedSerials, device.Serial) {
			continue
		}
		resource := deviceResource{Serial: device.Serial, Name: device.Name, MAC: device.MAC, ProductType: device.ProductType, NetworkID: device.Network.ID, OSName: "Meraki"}
		rb, selected := builder.selectedDeviceResource(resource, selector)
		if !selected {
			continue
		}
		for _, slot := range device.Slots {
			if code, ok := powerModuleStatus(slot.Status); ok {
				rb.recordInt("meraki.power.module.status", "Meraki power module status.", "1", code, map[string]string{
					"meraki.power.slot":          strconv.FormatInt(slot.Number, 10),
					"meraki.power.module.serial": slot.Serial,
					"meraki.power.module.model":  slot.Model,
					"meraki.power.module.status": slot.Status,
				})
			}
		}
	}
	return err != nil
}

func (r *merakiMetricsReceiver) scrapeTopology(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	devices, err := meraki.GetPaginatedItemsJSON[meraki.TopologyDiscovery](ctx, r.client, target.OrganizationID, "switch_topology", meraki.OrganizationPath(target.OrganizationID, "/switch/ports/topology/discovery/byDevice"), target.topologyQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki topology discovery endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		if ctx.Err() != nil {
			return true
		}
	}
	for i := range devices {
		device := &devices[i]
		if !allowsSerial(allowedSerials, device.Serial) {
			continue
		}
		resource := deviceResourceFromTopology(*device)
		rb, selected := builder.selectedDeviceResource(resource, selector)
		if !selected {
			continue
		}
		for _, port := range device.Ports {
			recordTopologyProtocol(rb, "cdp", port.PortID, port.CDP)
			recordTopologyProtocol(rb, "lldp", port.PortID, port.LLDP)
		}
	}
	return err != nil
}

func (r *merakiMetricsReceiver) scrapeTransceivers(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	partial := false
	type transceiverRequest struct {
		operation string
		path      string
		query     url.Values
		product   string
	}
	requests := []transceiverRequest{
		{
			operation: "appliance_transceivers",
			path:      "/appliance/devices/ports/transceivers/readings/history/byDevice",
			query:     target.applianceTransceiverQuery(),
			product:   "appliance",
		},
	}
	if r.config.Meraki.SwitchTransceivers.Enabled {
		requests = append(requests, transceiverRequest{
			operation: "switch_transceivers",
			path:      "/switch/ports/transceivers/readings/history/bySwitch",
			query:     target.switchTransceiverQuery(),
			product:   "switch",
		})
	}
	for _, request := range requests {
		devices, err := meraki.GetPaginatedItemsJSON[meraki.TransceiverReadings](ctx, r.client, target.OrganizationID, request.operation, meraki.OrganizationPath(target.OrganizationID, request.path), request.query)
		if err != nil {
			r.settings.Logger.Warn("Meraki transceiver endpoint failed", zap.String("organization_id", target.OrganizationID), zap.String("product", request.product), zap.Error(err))
			partial = true
			if ctx.Err() != nil {
				return true
			}
		}
		recordMerakiTransceivers(builder, devices, allowedSerials, selector)
	}
	return partial
}

func recordMerakiTransceivers(builder *merakiMetricsBuilder, devices []meraki.TransceiverReadings, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) {
	for i := range devices {
		device := &devices[i]
		if !allowsSerial(allowedSerials, device.Serial) {
			continue
		}
		resource := deviceResource{Serial: device.Serial, NetworkID: device.Network.ID, OSName: "Meraki"}
		rb, selected := builder.selectedDeviceResource(resource, selector)
		if !selected {
			continue
		}
		for j := range device.Ports {
			port := &device.Ports[j]
			if len(port.Readings) == 0 {
				continue
			}
			// Emit only the newest completed DOM snapshot. Timestamp comparison
			// keeps this correct even if an API version changes array order.
			readingIndex, observedAt := latestTimestampedIndex(len(port.Readings), 0, func(index int) string {
				return firstValidTimestamp(port.Readings[index].EndTS, port.Readings[index].StartTS)
			})
			reading := &port.Readings[readingIndex]
			attrs := interfaceAttrs(firstNonEmpty(port.InterfaceName, port.PortID), "", "", "")
			attrs["meraki.transceiver.sfp_product_id"] = reading.SFPProductID
			recordTransceiverValueAt(rb, attrs, "tx_power", "dBm", reading.ByMetric.Power.Transmit, observedAt)
			recordTransceiverValueAt(rb, attrs, "rx_power", "dBm", reading.ByMetric.Power.Receive, observedAt)
			recordTransceiverValueAt(rb, attrs, "temperature", "Cel", reading.ByMetric.Temperature.Celsius, observedAt)
			recordTransceiverValueAt(rb, attrs, "voltage", "V", reading.ByMetric.SupplyVoltage.Level, observedAt)
			recordTransceiverValueAt(rb, attrs, "current", "mA", reading.ByMetric.LaserBiasCurrent.Draw, observedAt)
		}
	}
}

func (r *merakiMetricsReceiver) scrapeAppliancePerformance(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	partial := false
	devices := builder.applianceDevices(allowedSerials)
	for i := range devices {
		device := &devices[i]
		if !selector.allows(merakiDeviceIdentity(*device)) {
			continue
		}
		path := "/devices/" + url.PathEscape(device.Serial) + "/appliance/performance"
		perf, hasData, err := meraki.GetOptionalJSON[meraki.AppliancePerformance](ctx, r.client, target.OrganizationID, "appliance_performance", path, nil)
		if err != nil {
			r.settings.Logger.Warn("Meraki appliance performance endpoint failed", zap.String("organization_id", target.OrganizationID), zap.String("serial", device.Serial), zap.Error(err))
			partial = true
			continue
		}
		if !hasData {
			continue
		}
		builder.deviceResource(*device).recordDouble("meraki.appliance.performance.score", "Meraki appliance performance score.", "1", perf.PerfScore, nil)
	}
	return partial
}

func (r *merakiMetricsReceiver) recordRequest(stat meraki.RequestStat) {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats = append(r.stats, stat)
}

func (r *merakiMetricsReceiver) resetRequestStats() {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats = nil
}

func (r *merakiMetricsReceiver) requestStats() []meraki.RequestStat {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	return append([]meraki.RequestStat(nil), r.stats...)
}

func (r *merakiMetricsReceiver) recordAPIRequestMetrics(builder *merakiMetricsBuilder) {
	stats := r.requestStats()
	observations := make([]apiRequestObservation, 0, len(stats))
	for _, stat := range stats {
		attrs := map[string]string{
			"meraki.api.operation":   stat.Operation,
			"meraki.api.method":      stat.Method,
			"meraki.api.path":        stat.Path,
			"meraki.api.outcome":     stat.Outcome,
			"meraki.organization.id": stat.OrganizationID,
		}
		if stat.StatusCode > 0 {
			attrs["http.response.status_code"] = strconv.Itoa(stat.StatusCode)
		}
		observations = append(observations, apiRequestObservation{resource: stat.OrganizationID, attrs: attrs, durationSeconds: stat.Duration.Seconds(), failed: stat.Err != nil, rateLimited: stat.RateLimited})
	}
	for _, aggregate := range aggregateAPIRequestObservations(observations) {
		rb := builder.orgResource(aggregate.resource)
		rb.recordDouble("meraki.api.request.duration", "Average Meraki API request duration for attempts in this scrape.", "s", aggregate.averageDurationSeconds, aggregate.attrs)
		if aggregate.errors > 0 {
			rb.recordSum("meraki.api.request.errors", "Meraki API request errors.", "{error}", aggregate.errors, aggregate.attrs)
		}
		if aggregate.rateLimited > 0 {
			rb.recordSum("meraki.api.request.rate_limited", "Meraki API requests that received HTTP 429.", "{request}", aggregate.rateLimited, aggregate.attrs)
		}
	}
}

func (t merakiTarget) deviceFilterQuery(perPage string) url.Values {
	return meraki.Query(map[string][]string{
		"networkIds":   t.NetworkIDs,
		"productTypes": t.ProductTypes,
		"serials":      t.Serials,
		"tags":         t.Tags,
	}, map[string]string{
		"perPage":        perPage,
		"tagsFilterType": t.TagsFilterType,
	})
}

func (t merakiTarget) deviceInventoryQuery() url.Values {
	return t.deviceFilterQuery("5000")
}

func (t merakiTarget) deviceStatusQuery() url.Values {
	return t.deviceFilterQuery("1000")
}

func (t merakiTarget) memoryQuery() url.Values {
	query := meraki.Query(map[string][]string{
		"networkIds":   t.NetworkIDs,
		"productTypes": t.ProductTypes,
		"serials":      t.Serials,
	}, map[string]string{"perPage": "20"})
	query.Set("timespan", "300")
	query.Set("interval", "300")
	return query
}

func (t merakiTarget) networkSerialQuery(perPage string) url.Values {
	return meraki.Query(map[string][]string{
		"networkIds": t.NetworkIDs,
		"serials":    t.Serials,
	}, map[string]string{"perPage": perPage})
}

func (t merakiTarget) networkQuery(perPage string) url.Values {
	return meraki.Query(map[string][]string{"networkIds": t.NetworkIDs}, map[string]string{"perPage": perPage})
}

func (t merakiTarget) switchStatusQuery() url.Values {
	return t.networkSerialQuery("20")
}

func (t merakiTarget) switchUsageQuery() url.Values {
	query := t.networkSerialQuery("50")
	// The API returns only completed intervals. A single five-minute
	// lookback frequently straddles the active bucket and yields no ports.
	query.Set("timespan", "1200")
	query.Set("interval", "300")
	return query
}

func (t merakiTarget) uplinkStatusQuery() url.Values {
	return t.networkSerialQuery("1000")
}

func (t merakiTarget) wirelessClientsQuery() url.Values {
	return t.networkSerialQuery("1000")
}

func (t merakiTarget) wirelessChannelQuery() url.Values {
	query := t.networkSerialQuery("1000")
	query.Set("timespan", "300")
	query.Set("interval", "300")
	return query
}

func (t merakiTarget) wirelessPacketLossQuery() url.Values {
	query := t.networkSerialQuery("1000")
	query.Set("timespan", "300")
	return query
}

func (t merakiTarget) wirelessSSIDQuery() url.Values {
	return t.networkSerialQuery("500")
}

func (t merakiTarget) vpnStatusQuery() url.Values {
	return t.networkQuery("300")
}

func (t merakiTarget) vpnStatsQuery() url.Values {
	query := t.networkQuery("300")
	query.Set("timespan", "300")
	return query
}

func (t merakiTarget) powerModulesQuery() url.Values {
	return t.deviceFilterQuery("1000")
}

func (t merakiTarget) topologyQuery() url.Values {
	return t.networkSerialQuery("20")
}

func (t merakiTarget) applianceTransceiverQuery() url.Values {
	return t.transceiverQuery("10")
}

func (t merakiTarget) switchTransceiverQuery() url.Values {
	return t.transceiverQuery("100")
}

func (t merakiTarget) transceiverQuery(perPage string) url.Values {
	query := t.networkSerialQuery(perPage)
	query.Set("timespan", "1200")
	query.Set("interval", "300")
	return query
}

func (t merakiTarget) scoped(selector deviceSelectionMatcher) bool {
	if t.selectAll {
		return !selector.empty()
	}
	return len(t.filters) > 0 || len(t.explicitSerials) > 0 || len(t.NetworkIDs) > 0 || len(t.Serials) > 0 || len(t.ProductTypes) > 0 || len(t.Tags) > 0 || !selector.empty()
}

func (t merakiTarget) requiresInventoryResolution(selector deviceSelectionMatcher) bool {
	return t.unionRequiresInventory || len(t.NetworkIDs) > 0 || len(t.ProductTypes) > 0 || len(t.Tags) > 0 || !selector.empty()
}

func (t merakiTarget) allowsInventoryMetadata(device meraki.Device) bool {
	if t.selectAll {
		return true
	}
	if stringSliceContains(t.explicitSerials, device.Serial) {
		return true
	}
	for _, filter := range t.filters {
		if filter.allows(device) {
			return true
		}
	}
	if len(t.filters) > 0 || len(t.explicitSerials) > 0 {
		return false
	}
	return merakiTargetFilter{
		NetworkIDs:     t.NetworkIDs,
		Serials:        t.Serials,
		ProductTypes:   t.ProductTypes,
		Tags:           t.Tags,
		TagsFilterType: t.TagsFilterType,
	}.allows(device)
}

func (f merakiTargetFilter) allows(device meraki.Device) bool {
	if len(f.NetworkIDs) > 0 && !stringSliceContains(f.NetworkIDs, device.NetworkID) {
		return false
	}
	if len(f.Serials) > 0 && !stringSliceContains(f.Serials, device.Serial) {
		return false
	}
	if len(f.ProductTypes) > 0 && !stringSliceContains(f.ProductTypes, device.ProductType) {
		return false
	}
	if len(f.Tags) == 0 {
		return true
	}

	if f.TagsFilterType == "withAllTags" {
		for _, tag := range f.Tags {
			if !stringSliceContains(device.Tags, tag) {
				return false
			}
		}
		return true
	}
	for _, tag := range f.Tags {
		if stringSliceContains(device.Tags, tag) {
			return true
		}
	}
	return false
}

func (t merakiTarget) fallbackSerialSet() map[string]struct{} {
	out := make(map[string]struct{}, len(t.explicitSerials))
	for _, serial := range t.explicitSerials {
		if serial != "" {
			out[serial] = struct{}{}
		}
	}
	for _, filter := range t.filters {
		if !filter.serialOnly() {
			continue
		}
		for _, serial := range filter.Serials {
			if serial != "" {
				out[serial] = struct{}{}
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (t merakiTarget) serialSet() map[string]struct{} {
	if len(t.Serials) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(t.Serials))
	for _, serial := range t.Serials {
		if serial != "" {
			out[serial] = struct{}{}
		}
	}
	return out
}

func stringSliceContains(values []string, expected string) bool {
	return slices.Contains(values, expected)
}

type merakiMetricsBuilder struct {
	metrics    pmetric.Metrics
	now        pcommon.Timestamp
	start      pcommon.Timestamp
	resources  map[string]*resourceMetricsBuilder
	devices    map[string]deviceResource
	portSpeeds map[string]int64
	counters   *counterStore
}

type deviceResource struct {
	Serial               string
	Name                 string
	LANIP                string
	PublicIP             string
	AdditionalIPs        []string
	MAC                  string
	Model                string
	Firmware             string
	ProductType          string
	NetworkID            string
	OSName               string
	HighAvailabilityRole string
}

type resourceMetricsBuilder struct {
	resource         pcommon.Resource
	scope            pmetric.ScopeMetrics
	metrics          map[string]pmetric.Metric
	now              pcommon.Timestamp
	start            pcommon.Timestamp
	counterNamespace string
	counters         *counterStore
}

func newMerakiMetricsBuilder(now time.Time, counters *counterStore) *merakiMetricsBuilder {
	if counters == nil {
		counters = newCounterStore()
	}
	ts := pcommon.NewTimestampFromTime(now)
	return &merakiMetricsBuilder{
		metrics:    pmetric.NewMetrics(),
		now:        ts,
		start:      pcommon.NewTimestampFromTime(counters.StartTime()),
		resources:  map[string]*resourceMetricsBuilder{},
		devices:    map[string]deviceResource{},
		portSpeeds: map[string]int64{},
		counters:   counters,
	}
}

func (b *merakiMetricsBuilder) emit() pmetric.Metrics {
	b.metrics.ResourceMetrics().RemoveIf(func(rm pmetric.ResourceMetrics) bool {
		rm.ScopeMetrics().RemoveIf(func(sm pmetric.ScopeMetrics) bool {
			return sm.Metrics().Len() == 0
		})
		return rm.ScopeMetrics().Len() == 0
	})
	return b.metrics
}

func (b *merakiMetricsBuilder) selectedDeviceResource(device deviceResource, selector deviceSelectionMatcher) (*resourceMetricsBuilder, bool) {
	if device.Serial != "" {
		if existing, ok := b.devices[device.Serial]; ok {
			device = mergeDeviceResource(existing, device)
		}
	}
	if !selector.allows(merakiDeviceIdentity(device)) {
		return nil, false
	}
	return b.deviceResource(device), true
}

func (b *merakiMetricsBuilder) deviceResource(device deviceResource) *resourceMetricsBuilder {
	if device.Serial == "" {
		device.Serial = firstNonEmpty(device.NetworkID, "unknown")
	}
	device.OSName = firstNonEmpty(device.OSName, "Meraki")
	if existing, ok := b.devices[device.Serial]; ok {
		device = mergeDeviceResource(existing, device)
	}
	b.devices[device.Serial] = device

	key := "device:" + device.Serial
	rb := b.resource(key)
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", device.Serial)
	hostIPs := append([]string{device.LANIP, device.PublicIP}, device.AdditionalIPs...)
	putIPAttrs(attrs, "host.ip", hostIPs...)
	putStr(attrs, "host.name", device.Name)
	putStr(attrs, "host.type", firstNonEmpty(device.Model, device.ProductType))
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", device.OSName)
	putStr(attrs, "os.version", device.Firmware)
	putStr(attrs, "meraki.device.serial", device.Serial)
	putStr(attrs, "meraki.device.product_type", device.ProductType)
	putStr(attrs, "meraki.network.id", device.NetworkID)
	return rb
}

func (b *merakiMetricsBuilder) networkResource(networkID, networkName, organizationID string) *resourceMetricsBuilder {
	rb := b.resource("network:" + networkID)
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", "meraki:network:"+networkID)
	putStr(attrs, "host.name", firstNonEmpty(networkName, networkID))
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Meraki")
	putStr(attrs, "meraki.network.id", networkID)
	putStr(attrs, "meraki.organization.id", organizationID)
	return rb
}

func (b *merakiMetricsBuilder) orgResource(organizationID string) *resourceMetricsBuilder {
	rb := b.resource("org:" + organizationID)
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", "meraki:org:"+organizationID)
	putStr(attrs, "host.name", "Meraki organization "+organizationID)
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Meraki")
	putStr(attrs, "meraki.organization.id", organizationID)
	return rb
}

func (b *merakiMetricsBuilder) resource(key string) *resourceMetricsBuilder {
	if rb := b.resources[key]; rb != nil {
		return rb
	}
	rm := b.metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName(merakiScopeName)
	rb := &resourceMetricsBuilder{
		resource:         rm.Resource(),
		scope:            sm,
		metrics:          map[string]pmetric.Metric{},
		now:              b.now,
		start:            b.start,
		counterNamespace: key,
		counters:         b.counters,
	}
	b.resources[key] = rb
	return rb
}

func (b *merakiMetricsBuilder) setPortSpeed(serial, portID string, speed int64) {
	if serial == "" || portID == "" || speed <= 0 {
		return
	}
	b.portSpeeds[serial+"/"+portID] = speed
}

func (b *merakiMetricsBuilder) portSpeed(serial, portID string) int64 {
	return b.portSpeeds[serial+"/"+portID]
}

func (b *merakiMetricsBuilder) applianceDevices(allowedSerials map[string]struct{}) []deviceResource {
	devices := make([]deviceResource, 0)
	for _, device := range b.devices { //nolint:gocritic // Map iteration necessarily copies values.
		if !allowsSerial(allowedSerials, device.Serial) {
			continue
		}
		if isMerakiMXModel(device.Model) && !strings.EqualFold(device.HighAvailabilityRole, "spare") {
			devices = append(devices, device)
		}
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].Serial < devices[j].Serial })
	return devices
}

func (rb *resourceMetricsBuilder) recordInt(name, description, unit string, value int64, attrs map[string]string) {
	rb.recordIntAt(name, description, unit, value, attrs, time.Time{})
}

func (rb *resourceMetricsBuilder) recordIntAt(name, description, unit string, value int64, attrs map[string]string, observedAt time.Time) {
	dp := rb.gaugeMetric(name, description, unit).Gauge().DataPoints().AppendEmpty()
	dp.SetTimestamp(metricTimestamp(observedAt, rb.now))
	dp.SetIntValue(value)
	putAttrs(dp.Attributes(), attrs)
}

func (rb *resourceMetricsBuilder) recordDouble(name, description, unit string, value float64, attrs map[string]string) {
	rb.recordDoubleAt(name, description, unit, value, attrs, time.Time{})
}

func (rb *resourceMetricsBuilder) recordDoubleAt(name, description, unit string, value float64, attrs map[string]string, observedAt time.Time) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return
	}
	dp := rb.gaugeMetric(name, description, unit).Gauge().DataPoints().AppendEmpty()
	dp.SetTimestamp(metricTimestamp(observedAt, rb.now))
	dp.SetDoubleValue(value)
	putAttrs(dp.Attributes(), attrs)
}

func metricTimestamp(observedAt time.Time, fallback pcommon.Timestamp) pcommon.Timestamp {
	if observedAt.IsZero() {
		return fallback
	}
	return pcommon.NewTimestampFromTime(observedAt)
}

// recordSum accumulates delta into the receiver-scoped counter store and emits
// the running cumulative total as a monotonic Sum metric. Use this for
// counter-style observations (errors, rate-limit hits, packet counts) so
// SignalFlow rate()/sum_over_time() compute correctly.
func (rb *resourceMetricsBuilder) recordSum(name, description, unit string, delta int64, attrs map[string]string) {
	total, seriesStart := rb.counters.AddInt(rb.counterNamespace, name, attrs, delta)
	dp := rb.sumMetric(name, description, unit).Sum().DataPoints().AppendEmpty()
	dp.SetTimestamp(counterSeriesDatapointTimestamp(seriesStart, rb.now))
	dp.SetStartTimestamp(counterSeriesStartTimestamp(seriesStart, rb.start))
	dp.SetIntValue(total)
	putAttrs(dp.Attributes(), attrs)
}

func (rb *resourceMetricsBuilder) recordSumDouble(name, description, unit string, delta float64, attrs map[string]string) {
	if math.IsNaN(delta) || math.IsInf(delta, 0) {
		return
	}
	total, seriesStart := rb.counters.AddDouble(rb.counterNamespace, name, attrs, delta)
	dp := rb.sumMetric(name, description, unit).Sum().DataPoints().AppendEmpty()
	dp.SetTimestamp(counterSeriesDatapointTimestamp(seriesStart, rb.now))
	dp.SetStartTimestamp(counterSeriesStartTimestamp(seriesStart, rb.start))
	dp.SetDoubleValue(total)
	putAttrs(dp.Attributes(), attrs)
}

func counterSeriesStartTimestamp(seriesStart time.Time, fallback pcommon.Timestamp) pcommon.Timestamp {
	if seriesStart.IsZero() {
		return fallback
	}
	return pcommon.NewTimestampFromTime(seriesStart)
}

func counterSeriesDatapointTimestamp(seriesStart time.Time, observedAt pcommon.Timestamp) pcommon.Timestamp {
	if !seriesStart.IsZero() && seriesStart.After(observedAt.AsTime()) {
		return pcommon.NewTimestampFromTime(seriesStart)
	}
	return observedAt
}

func (rb *resourceMetricsBuilder) recordAbsoluteSumDouble(name, description, unit string, value float64, attrs map[string]string) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return
	}
	dp := rb.sumMetric(name, description, unit).Sum().DataPoints().AppendEmpty()
	dp.SetTimestamp(rb.now)
	dp.SetStartTimestamp(rb.start)
	dp.SetDoubleValue(value)
	putAttrs(dp.Attributes(), attrs)
}

func (rb *resourceMetricsBuilder) gaugeMetric(name, description, unit string) pmetric.Metric {
	if metric, ok := rb.metrics[name]; ok {
		return metric
	}
	metric := rb.scope.Metrics().AppendEmpty()
	metric.SetName(name)
	metric.SetDescription(description)
	metric.SetUnit(unit)
	metric.SetEmptyGauge()
	rb.metrics[name] = metric
	return metric
}

func (rb *resourceMetricsBuilder) sumMetric(name, description, unit string) pmetric.Metric {
	if metric, ok := rb.metrics[name]; ok {
		return metric
	}
	metric := rb.scope.Metrics().AppendEmpty()
	metric.SetName(name)
	metric.SetDescription(description)
	metric.SetUnit(unit)
	sum := metric.SetEmptySum()
	sum.SetIsMonotonic(true)
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	rb.metrics[name] = metric
	return metric
}

func deviceResourceFromInventory(device meraki.Device) deviceResource {
	return deviceResource{
		Serial:      device.Serial,
		Name:        device.Name,
		LANIP:       device.LANIP,
		MAC:         device.MAC,
		Model:       device.Model,
		Firmware:    device.Firmware,
		ProductType: device.ProductType,
		NetworkID:   device.NetworkID,
		OSName:      "Meraki",
	}
}

func deviceResourceFromStatus(status meraki.DeviceStatus) deviceResource {
	return deviceResource{
		Serial:      status.Serial,
		Name:        status.Name,
		LANIP:       status.LANIP,
		PublicIP:    status.PublicIP,
		MAC:         status.MAC,
		Model:       status.Model,
		ProductType: status.ProductType,
		NetworkID:   status.NetworkID,
		OSName:      "Meraki",
	}
}

func deviceResourceFromMemory(usage meraki.DeviceMemoryUsage) deviceResource {
	return deviceResource{
		Serial:    usage.Serial,
		Name:      usage.Name,
		MAC:       usage.MAC,
		Model:     usage.Model,
		NetworkID: usage.Network.ID,
		OSName:    "Meraki",
	}
}

func deviceResourceFromSwitch(sw meraki.SwitchPortsStatus) deviceResource {
	return deviceResource{Serial: sw.Serial, Name: sw.Name, MAC: sw.MAC, Model: sw.Model, NetworkID: sw.Network.ID, ProductType: "switch", OSName: "Meraki"}
}

func deviceResourceFromSwitchUsage(sw meraki.SwitchPortsUsage) deviceResource {
	return deviceResource{Serial: sw.Serial, Name: sw.Name, MAC: sw.MAC, Model: sw.Model, NetworkID: sw.Network.ID, ProductType: "switch", OSName: "Meraki"}
}

func deviceResourceFromUplinkStatus(status meraki.UplinkStatus) deviceResource {
	return deviceResource{
		Serial:               status.Serial,
		LANIP:                firstUplinkIP(status),
		PublicIP:             firstUplinkPublicIP(status),
		AdditionalIPs:        merakiUplinkIPs(status),
		Model:                status.Model,
		NetworkID:            status.NetworkID,
		OSName:               "Meraki",
		HighAvailabilityRole: status.HighAvailability.Role,
	}
}

func deviceResourceFromTopology(device meraki.TopologyDiscovery) deviceResource {
	return deviceResource{Serial: device.Serial, Name: device.Name, MAC: device.MAC, Model: device.Model, NetworkID: device.Network.ID, ProductType: "switch", OSName: "Meraki"}
}

func mergeDeviceResource(existing, update deviceResource) deviceResource {
	additionalIPs := append([]string(nil), existing.AdditionalIPs...)
	additionalIPs = append(additionalIPs, update.AdditionalIPs...)
	additionalIPs = append(additionalIPs, existing.LANIP, existing.PublicIP, update.LANIP, update.PublicIP)
	return deviceResource{
		Serial:               firstNonEmpty(update.Serial, existing.Serial),
		Name:                 firstNonEmpty(update.Name, existing.Name),
		LANIP:                firstNonEmpty(update.LANIP, existing.LANIP),
		PublicIP:             firstNonEmpty(update.PublicIP, existing.PublicIP),
		AdditionalIPs:        uniqueStrings(additionalIPs),
		MAC:                  firstNonEmpty(update.MAC, existing.MAC),
		Model:                firstNonEmpty(update.Model, existing.Model),
		Firmware:             firstNonEmpty(update.Firmware, existing.Firmware),
		ProductType:          firstNonEmpty(update.ProductType, existing.ProductType),
		NetworkID:            firstNonEmpty(update.NetworkID, existing.NetworkID),
		OSName:               firstNonEmpty(update.OSName, existing.OSName),
		HighAvailabilityRole: firstNonEmpty(update.HighAvailabilityRole, existing.HighAvailabilityRole),
	}
}

func isMerakiMXModel(model string) bool {
	model = strings.ToUpper(strings.TrimSpace(model))
	return strings.HasPrefix(model, "MX") || strings.HasPrefix(model, "VMX")
}

func memoryUtilization(usage meraki.DeviceMemoryUsage) (float64, time.Time, bool) {
	if len(usage.Intervals) > 0 {
		latestIndex, observedAt := latestTimestampedIndex(len(usage.Intervals), 0, func(index int) string {
			return firstValidTimestamp(usage.Intervals[index].EndTS, usage.Intervals[index].StartTS)
		})
		latest := usage.Intervals[latestIndex]
		if invalidNonnegativeValue(latest.Memory.Used.Median) || invalidNonnegativeValue(latest.Memory.Free.Median) {
			return 0, observedAt, false
		}
		if latest.Memory.Used.Percentages.Median != nil {
			ratio, ok := merakiPercentageRatio(*latest.Memory.Used.Percentages.Median)
			return ratio, observedAt, ok
		}
		if latest.Memory.Used.Percentages.Maximum != nil {
			ratio, ok := merakiPercentageRatio(*latest.Memory.Used.Percentages.Maximum)
			return ratio, observedAt, ok
		}
		if used, usedOK := merakiNonnegativeValue(latest.Memory.Used.Median); usedOK {
			if free, freeOK := merakiNonnegativeValue(latest.Memory.Free.Median); freeOK && used+free > 0 && !math.IsInf(used+free, 0) {
				return used / (used + free), observedAt, true
			}
		}
	}
	if invalidNonnegativeValue(usage.Used.Median) || invalidNonnegativeValue(usage.Free.Median) || invalidNonnegativeValue(usage.Provisioned) {
		return 0, time.Time{}, false
	}
	used, usedOK := merakiNonnegativeValue(usage.Used.Median)
	free, freeOK := merakiNonnegativeValue(usage.Free.Median)
	if usedOK && freeOK && used+free > 0 && !math.IsInf(used+free, 0) {
		return used / (used + free), time.Time{}, true
	}
	provisioned, provisionedOK := merakiNonnegativeValue(usage.Provisioned)
	if usedOK && provisionedOK && provisioned > 0 && used <= provisioned {
		return used / provisioned, time.Time{}, true
	}
	return 0, time.Time{}, false
}

func merakiPercentageRatio(value float64) (float64, bool) {
	if !validNonnegativeFloat(value) || value > 100 {
		return 0, false
	}
	return value / 100, true
}

func merakiNonnegativeValue(value *float64) (float64, bool) {
	if value == nil || !validNonnegativeFloat(*value) {
		return 0, false
	}
	return *value, true
}

func invalidNonnegativeValue(value *float64) bool {
	return value != nil && !validNonnegativeFloat(*value)
}

func validNonnegativeFloat(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}

func merakiKilobitsToBits(value float64) (int64, bool) {
	if !validNonnegativeFloat(value) {
		return 0, false
	}
	scaled := value * 1000
	// float64(math.MaxInt64) rounds to 2^63, which is the exact exclusive
	// upper bound for conversion to int64.
	if math.IsInf(scaled, 0) || scaled >= float64(math.MaxInt64) {
		return 0, false
	}
	return int64(scaled), true
}

func merakiInterfaceUtilization(rateBits, speedBits int64, validRate bool) (float64, bool) {
	if !validRate || rateBits < 0 || speedBits <= 0 || rateBits > speedBits {
		return 0, false
	}
	return float64(rateBits) / float64(speedBits), true
}

func recordWirelessPacketLoss(rb *resourceMetricsBuilder, direction string, loss meraki.PacketLossDirection) {
	attrs := map[string]string{"network.io.direction": direction}
	// The Dashboard API returns totals for a rolling query window, not
	// monotonic device counters. Exporting them as cumulative sums would add
	// the overlapping window again on every scrape.
	rb.recordInt("meraki.wireless.packet.count", "Wireless packets observed in the Meraki reporting window.", "{packet}", loss.Total, attrs)
	rb.recordInt("meraki.wireless.packet.loss", "Wireless packets lost in the Meraki reporting window.", "{packet}", loss.Lost, attrs)
	rb.recordDouble("meraki.wireless.packet.loss_percentage", "Wireless packet loss percentage.", "%", loss.LossPercentage, attrs)
}

func recordTopologyProtocol(rb *resourceMetricsBuilder, protocol, portID string, values []meraki.NameValue) {
	if len(values) == 0 {
		return
	}
	attrs := map[string]string{
		"cisco.topology.protocol":           protocol,
		"network.interface.name":            portID,
		"cisco.topology.neighbor.name":      topologyValue(values, "System name", "Device ID", "Chassis ID"),
		"cisco.topology.neighbor.interface": topologyValue(values, "Port ID", "Port description"),
		"cisco.topology.neighbor.platform":  topologyValue(values, "Platform", "System description"),
		"cisco.topology.neighbor.address":   topologyValue(values, "Management address", "Management Address"),
	}
	rb.recordInt("cisco.topology.neighbor.info", "Topology neighbor information.", "1", 1, attrs)
}

func recordTransceiverValue(rb *resourceMetricsBuilder, base map[string]string, sensor, unit string, value meraki.SummaryValue) {
	recordTransceiverValueAt(rb, base, sensor, unit, value, time.Time{})
}

func recordTransceiverValueAt(rb *resourceMetricsBuilder, base map[string]string, sensor, unit string, value meraki.SummaryValue, observedAt time.Time) {
	median, ok := value.MedianValue()
	if !ok {
		return
	}
	attrs := cloneStringMap(base)
	attrs["cisco.transceiver.sensor"] = sensor
	attrs["cisco.transceiver.sensor.unit"] = unit
	// One OTLP metric descriptor cannot change unit between datapoints. The
	// physical unit remains explicit on each sensor datapoint.
	rb.recordDoubleAt("cisco.transceiver.sensor", "Transceiver DOM sensor value; physical unit is in cisco.transceiver.sensor.unit.", "1", median, attrs, observedAt)
}

func latestTimestampedIndex(length, fallback int, timestampAt func(int) string) (int, time.Time) {
	if length <= 0 {
		return -1, time.Time{}
	}
	if fallback < 0 || fallback >= length {
		fallback = 0
	}
	latestIndex := fallback
	var latest time.Time
	for i := range length {
		parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(timestampAt(i)))
		if err != nil {
			continue
		}
		if latest.IsZero() || parsed.After(latest) {
			latest = parsed
			latestIndex = i
		}
	}
	return latestIndex, latest
}

func firstValidTimestamp(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if _, err := time.Parse(time.RFC3339Nano, value); err == nil {
			return value
		}
	}
	return ""
}

func topologyValue(values []meraki.NameValue, names ...string) string {
	for _, name := range names {
		for _, value := range values {
			if strings.EqualFold(value.Name, name) {
				return value.Value
			}
		}
	}
	return ""
}

func interfaceAttrs(name, mac, description, speed string) map[string]string {
	return map[string]string{
		"network.interface.name":        name,
		"network.interface.mac":         mac,
		"network.interface.description": description,
		"network.interface.speed":       speed,
	}
}

func withAttr(attrs map[string]string, key, value string) map[string]string {
	out := cloneStringMap(attrs)
	out[key] = value
	return out
}

func withVPNUplinks(attrs map[string]string, sender, receiver string) map[string]string {
	out := cloneStringMap(attrs)
	out["meraki.vpn.sender.uplink"] = sender
	out["meraki.vpn.receiver.uplink"] = receiver
	return out
}

func cloneStringMap(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs))
	maps.Copy(out, attrs)
	return out
}

func putAttrs(target pcommon.Map, attrs map[string]string) {
	for key, value := range attrs {
		if key == "http.response.status_code" {
			if status, err := strconv.ParseInt(value, 10, 64); err == nil {
				target.PutInt(key, status)
				continue
			}
		}
		putStr(target, key, value)
	}
}

func putStr(attrs pcommon.Map, key, value string) {
	if key != "" && value != "" {
		attrs.PutStr(key, value)
	}
}

func allowsSerial(allowed map[string]struct{}, serial string) bool {
	if allowed == nil {
		return true
	}
	_, ok := allowed[serial]
	return ok
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstUplinkIP(status meraki.UplinkStatus) string {
	for i := range status.Uplinks {
		uplink := &status.Uplinks[i]
		if uplink.IP != "" {
			return uplink.IP
		}
	}
	return ""
}

func firstUplinkPublicIP(status meraki.UplinkStatus) string {
	for i := range status.Uplinks {
		uplink := &status.Uplinks[i]
		if uplink.PublicIP != "" {
			return uplink.PublicIP
		}
	}
	return ""
}

func merakiUplinkIPs(status meraki.UplinkStatus) []string {
	values := make([]string, 0, len(status.Uplinks)*2)
	for i := range status.Uplinks {
		values = append(values, status.Uplinks[i].IP, status.Uplinks[i].PublicIP)
	}
	return uniqueStrings(values)
}

func boolToInt(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func merakiDeviceUp(status string) (int64, bool) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "online", "alerting":
		return 1, true
	case "offline", "dormant":
		return 0, true
	default:
		return 0, false
	}
}

func merakiStatusCode(status string) (int64, bool) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "online":
		return 1, true
	case "alerting":
		return 2, true
	case "dormant":
		return 3, true
	case "offline":
		return 4, true
	default:
		return 0, false
	}
}

func connectedStatus(status string) (int64, bool) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "connected", "up", "active", "ready":
		return 1, true
	case "disconnected", "down", "inactive", "disabled", "offline", "not connected":
		return 0, true
	default:
		return 0, false
	}
}

func activeStatus(status string) (int64, bool) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "active", "ready", "online":
		return 1, true
	case "connecting", "failed", "not connected", "inactive", "offline", "down", "disabled":
		return 0, true
	default:
		return 0, false
	}
}

func reachableStatus(status string) (int64, bool) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "reachable":
		return 1, true
	case "unreachable", "not reachable", "not-reachable":
		return 0, true
	default:
		return 0, false
	}
}

func powerModuleStatus(status string) (int64, bool) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "connected", "powering", "ok", "present":
		return 1, true
	case "not connected", "disconnected", "failed", "fault", "absent", "not present":
		return 0, true
	default:
		return 0, false
	}
}

func parseMerakiSpeed(speed string) (int64, string) {
	speed = strings.TrimSpace(speed)
	if speed == "" {
		return 0, ""
	}
	fields := strings.Fields(speed)
	if len(fields) < 2 {
		return 0, speed
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, speed
	}
	unit := strings.ToLower(fields[1])
	var multiplier float64
	switch {
	case strings.HasPrefix(unit, "tb"):
		multiplier = 1_000_000_000_000
	case strings.HasPrefix(unit, "gb"):
		multiplier = 1_000_000_000
	case strings.HasPrefix(unit, "mb"):
		multiplier = 1_000_000
	case strings.HasPrefix(unit, "kb"):
		multiplier = 1_000
	default:
		return 0, speed
	}
	return int64(value * multiplier), speed
}

func parseFloatString(value string) (float64, bool) {
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	return parsed, err == nil
}

func (d deviceResource) String() string {
	return fmt.Sprintf("%s/%s", d.Serial, d.Name)
}
