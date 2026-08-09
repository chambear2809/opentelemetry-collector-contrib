// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/multierr"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/aci"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/catalystcenter"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/fmc"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/intersight"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/nexusdashboard"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/sdwan"
)

// DeviceSelectionConfig defines shared device include/exclude filters across Cisco providers.
type DeviceSelectionConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Include DeviceSelectionMatchConfig `mapstructure:"include"`
	Exclude DeviceSelectionMatchConfig `mapstructure:"exclude"`
}

// DeviceSelectionMatchConfig defines one side of the shared device selector.
type DeviceSelectionMatchConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	HostNames []string `mapstructure:"host_names"`
	HostIDs   []string `mapstructure:"host_ids"`
	HostIPs   []string `mapstructure:"host_ips"`
	Serials   []string `mapstructure:"serials"`
	DeviceIDs []string `mapstructure:"device_ids"`
}

// Validate prevents an apparently active include selector from becoming empty
// after normalization and unintentionally broadening collection to all devices.
func (cfg DeviceSelectionConfig) Validate() error {
	var err error
	err = multierr.Append(err, validateDeviceSelectionMatch("include", cfg.Include))
	err = multierr.Append(err, validateDeviceSelectionMatch("exclude", cfg.Exclude))
	return err
}

func validateDeviceSelectionMatch(prefix string, cfg DeviceSelectionMatchConfig) error {
	var err error
	for name, values := range map[string][]string{
		"host_names": cfg.HostNames,
		"host_ids":   cfg.HostIDs,
		"serials":    cfg.Serials,
		"device_ids": cfg.DeviceIDs,
	} {
		for i, value := range values {
			if strings.TrimSpace(value) == "" {
				err = multierr.Append(err, fmt.Errorf("%s.%s[%d] cannot be empty", prefix, name, i))
			}
		}
	}
	for i, value := range cfg.HostIPs {
		value = strings.TrimSpace(value)
		if value == "" {
			err = multierr.Append(err, fmt.Errorf("%s.host_ips[%d] cannot be empty", prefix, i))
			continue
		}
		if _, parseErr := netip.ParseAddr(value); parseErr != nil {
			err = multierr.Append(err, fmt.Errorf("%s.host_ips[%d] must be a valid IP address", prefix, i))
		}
	}
	return err
}

type deviceSelectionMatcher struct {
	include deviceSelectionMatch
	exclude deviceSelectionMatch
}

type deviceSelectionMatch struct {
	hostNames map[string]struct{}
	hostIDs   map[string]struct{}
	hostIPs   map[string]struct{}
	serials   map[string]struct{}
	deviceIDs map[string]struct{}
}

type deviceIdentity struct {
	hostNames []string
	hostIDs   []string
	hostIPs   []string
	serials   []string
	deviceIDs []string
}

func newDeviceSelectionMatcher(cfg DeviceSelectionConfig) deviceSelectionMatcher {
	return deviceSelectionMatcher{
		include: newDeviceSelectionMatch(cfg.Include),
		exclude: newDeviceSelectionMatch(cfg.Exclude),
	}
}

func newDeviceSelectionMatch(cfg DeviceSelectionMatchConfig) deviceSelectionMatch {
	return deviceSelectionMatch{
		hostNames: normalizedSet(cfg.HostNames, normalizeSelectorText),
		hostIDs:   normalizedSet(cfg.HostIDs, normalizeSelectorText),
		hostIPs:   normalizedSet(cfg.HostIPs, normalizeSelectorIP),
		serials:   normalizedSet(cfg.Serials, normalizeSelectorText),
		deviceIDs: normalizedSet(cfg.DeviceIDs, normalizeSelectorText),
	}
}

func normalizedSet(values []string, normalize func(string) string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := normalize(value)
		if normalized == "" {
			continue
		}
		out[normalized] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (m deviceSelectionMatcher) empty() bool {
	return m.include.empty() && m.exclude.empty()
}

func (m deviceSelectionMatcher) allows(id deviceIdentity) bool {
	if m.exclude.matches(id) {
		return false
	}
	if m.include.empty() {
		return true
	}
	return m.include.matches(id)
}

func (m deviceSelectionMatcher) allowsResource(attrs pcommon.Map) bool {
	return m.allows(deviceIdentityFromResourceAttrs(attrs))
}

// allowsSSHConfiguration determines whether a configured SSH target may need
// to be connected before device selection can be decided. The configured IP
// is authoritative, but host name and stable IDs can be discovered only after
// show version succeeds.
func (m deviceSelectionMatcher) allowsSSHConfiguration(id deviceIdentity) bool {
	if m.exclude.matches(id) {
		return false
	}
	if m.include.empty() || m.include.matches(id) {
		return true
	}
	return len(m.include.hostNames) > 0 ||
		len(m.include.hostIDs) > 0 ||
		len(m.include.serials) > 0
}

func (m deviceSelectionMatch) empty() bool {
	return len(m.hostNames) == 0 && len(m.hostIDs) == 0 && len(m.hostIPs) == 0 && len(m.serials) == 0 && len(m.deviceIDs) == 0
}

func (m deviceSelectionMatch) matches(id deviceIdentity) bool {
	return matchAny(m.hostNames, id.hostNames, normalizeSelectorText) ||
		matchAny(m.hostIDs, id.hostIDs, normalizeSelectorText) ||
		matchAny(m.hostIPs, id.hostIPs, normalizeSelectorIP) ||
		matchAny(m.serials, id.serials, normalizeSelectorText) ||
		matchAny(m.deviceIDs, id.deviceIDs, normalizeSelectorText)
}

func matchAny(set map[string]struct{}, values []string, normalize func(string) string) bool {
	if len(set) == 0 || len(values) == 0 {
		return false
	}
	for _, value := range values {
		if _, ok := set[normalize(value)]; ok {
			return true
		}
	}
	return false
}

func normalizeSelectorText(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeSelectorIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.Unmap().String()
	}
	return strings.ToLower(value)
}

func sshDeviceIdentity(device DeviceConfig) deviceIdentity {
	return deviceIdentity{
		hostNames: []string{device.Name},
		hostIDs:   []string{device.Name, device.Host},
		hostIPs:   []string{device.Host},
		deviceIDs: []string{device.Name, device.Host},
	}
}

type sshDeviceSelectionConsumer struct {
	next                    consumer.Metrics
	selector                deviceSelectionMatcher
	configured              deviceIdentity
	configuredHostFallbacks []string
	metadataStore           *connection.DeviceMetadataStore
}

func newSSHDeviceSelectionConsumer(
	next consumer.Metrics,
	selector deviceSelectionMatcher,
	device DeviceConfig,
	metadataStore *connection.DeviceMetadataStore,
) consumer.Metrics {
	if selector.empty() {
		return next
	}
	configured := sshDeviceIdentity(device)
	return &sshDeviceSelectionConsumer{
		next:                    next,
		selector:                selector,
		configured:              configured,
		configuredHostFallbacks: append(append([]string(nil), configured.hostNames...), device.Host),
		metadataStore:           metadataStore,
	}
}

func (*sshDeviceSelectionConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

func (c *sshDeviceSelectionConsumer) ConsumeMetrics(ctx context.Context, md pmetric.Metrics) error {
	md.ResourceMetrics().RemoveIf(func(rm pmetric.ResourceMetrics) bool {
		resourceAttrs := rm.Resource().Attributes()
		metadata, metadataAvailable := c.metadataStore.Load()
		if c.unresolvedSSHExclusionIdentity(metadata, metadataAvailable) {
			// Exclusions always win, so an initial connection failure cannot be
			// safely emitted until show version resolves every field needed to
			// prove that the target is not excluded.
			return true
		}
		if metadataAvailable {
			c.enrichSSHResourceIdentity(resourceAttrs, metadata)
		}
		identity := deviceIdentityFromResourceAttrs(resourceAttrs)
		if metadataAvailable {
			// Prefer discovered identity carried by this batch. Fill dimensions that
			// contain no discovered value from the last verified target metadata so a
			// later failure cannot lose an established include/exclude decision.
			if hasOnlyConfiguredDeviceSelectionValues(identity.hostNames, c.configuredHostFallbacks) {
				identity.hostNames = append(identity.hostNames, metadata.HostName)
			}
			if hasOnlyConfiguredDeviceSelectionValues(identity.hostIDs, c.configured.hostIDs) {
				identity.hostIDs = append(identity.hostIDs, metadata.HostID, metadata.Serial)
			}
			if !hasDeviceSelectionValue(identity.serials) {
				identity.serials = append(identity.serials, metadata.Serial)
			}
		}
		// Retain configured target identity alongside the hostname and serial
		// discovered by the SSH scrapers.
		identity.hostNames = append(identity.hostNames, c.configured.hostNames...)
		identity.hostIDs = append(identity.hostIDs, c.configured.hostIDs...)
		identity.hostIPs = append(identity.hostIPs, c.configured.hostIPs...)
		identity.deviceIDs = append(identity.deviceIDs, c.configured.deviceIDs...)
		return !c.selector.allows(identity)
	})
	if md.MetricCount() == 0 {
		return nil
	}
	return c.next.ConsumeMetrics(ctx, md)
}

func (c *sshDeviceSelectionConsumer) enrichSSHResourceIdentity(attrs pcommon.Map, metadata connection.DeviceMetadata) {
	if serial := strings.TrimSpace(metadata.Serial); serial != "" && strings.TrimSpace(attrString(attrs, "cisco.switch.serial")) == "" {
		attrs.PutStr("cisco.switch.serial", serial)
	}
	if hostName := strings.TrimSpace(metadata.HostName); hostName != "" {
		if current := attrString(attrs, "host.name"); current != "" && hasOnlyConfiguredDeviceSelectionValues([]string{current}, c.configuredHostFallbacks) {
			// Replace only an emitted configured fallback. Absence can mean that
			// the user disabled this resource attribute and must be preserved.
			attrs.PutStr("host.name", hostName)
		}
	}
	if hostID := strings.TrimSpace(firstNonEmpty(metadata.HostID, metadata.Serial)); hostID != "" {
		if current := attrString(attrs, "host.id"); current != "" && hasOnlyConfiguredDeviceSelectionValues([]string{current}, c.configured.hostIDs) {
			attrs.PutStr("host.id", hostID)
		}
	}
}

func hasDeviceSelectionValue(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func hasOnlyConfiguredDeviceSelectionValues(values, configured []string) bool {
	configuredSet := normalizedSet(configured, normalizeSelectorText)
	for _, value := range values {
		normalized := normalizeSelectorText(value)
		if normalized == "" {
			continue
		}
		if _, ok := configuredSet[normalized]; !ok {
			return false
		}
	}
	return true
}

func (m deviceSelectionMatch) requiresSSHDiscovery() bool {
	return len(m.hostNames) > 0 || len(m.hostIDs) > 0 || len(m.serials) > 0
}

func (c *sshDeviceSelectionConsumer) unresolvedSSHExclusionIdentity(metadata connection.DeviceMetadata, available bool) bool {
	exclude := c.selector.exclude
	if !exclude.requiresSSHDiscovery() {
		return false
	}
	if !available {
		return true
	}
	if len(exclude.hostNames) > 0 && strings.TrimSpace(metadata.HostName) == "" {
		return true
	}
	stableID := firstNonEmpty(metadata.HostID, metadata.Serial)
	if len(exclude.hostIDs) > 0 && stableID == "" {
		return true
	}
	return len(exclude.serials) > 0 && strings.TrimSpace(metadata.Serial) == ""
}

func merakiDeviceIdentity(device deviceResource) deviceIdentity {
	hostIPs := append([]string{device.LANIP, device.PublicIP}, device.AdditionalIPs...)
	return deviceIdentity{
		hostNames: []string{device.Name},
		hostIDs:   []string{device.Serial},
		hostIPs:   hostIPs,
		serials:   []string{device.Serial},
		deviceIDs: []string{device.Serial, device.MAC, device.NetworkID},
	}
}

func intersightObjectIdentity(obj intersight.Object) deviceIdentity {
	serial := firstNonEmpty(intersight.String(obj, "Serial", "SerialNumber"), firstString(intersight.StringSlice(obj, "Serial")))
	moid := intersight.String(obj, "Moid")
	registeredDevice := intersight.RelationshipMoid(obj, "RegisteredDevice")
	affectedMoid := firstNonEmpty(intersight.String(obj, "AffectedMoId", "AffectedObjectMoid"), intersight.RelationshipMoid(obj, "AffectedObject"))
	deviceMoid := firstNonEmpty(intersight.String(obj, "DeviceMoId"), registeredDevice, affectedMoid)
	hostName := firstNonEmpty(
		intersight.String(obj, "Name", "HostName", "DeviceHostname", "AffectedMoDisplayName"),
		firstString(intersight.StringSlice(obj, "DeviceHostname")),
	)
	return deviceIdentity{
		hostNames: []string{hostName},
		hostIDs:   []string{serial, moid, deviceMoid},
		hostIPs: []string{
			intersight.String(obj, "MgmtIpAddress", "Ipv4Address", "OutOfBandIpAddress", "InbandIpAddress"),
			firstString(intersight.StringSlice(obj, "DeviceIpAddress")),
		},
		serials:   []string{serial},
		deviceIDs: []string{moid, deviceMoid, registeredDevice, affectedMoid, intersight.String(obj, "InstId"), intersight.String(obj, "ClusterUuid", "NodeUuid")},
	}
}

func intersightTelemetryIdentity(event map[string]any) deviceIdentity {
	hostName := firstNonEmpty(anyString(event["host.name"]), anyString(event["hostName"]), anyString(event["hostname"]), anyString(event["name"]))
	serial := firstNonEmpty(anyString(event["serial"]), anyString(event["Serial"]), anyString(event["serialNumber"]), anyString(event["SerialNumber"]))
	deviceID := firstNonEmpty(anyString(event["deviceId"]), anyString(event["DeviceId"]), anyString(event["deviceID"]), anyString(event["Moid"]), anyString(event["moid"]))
	hostIP := firstNonEmpty(anyString(event["host.ip"]), anyString(event["ip"]), anyString(event["ipAddress"]), anyString(event["mgmtIpAddress"]))
	return deviceIdentity{
		hostNames: []string{hostName},
		hostIDs:   []string{firstNonEmpty(serial, deviceID, hostName), deviceID},
		hostIPs:   []string{hostIP},
		serials:   []string{serial},
		deviceIDs: []string{deviceID, anyString(event["deviceName"])},
	}
}

func catalystDeviceIdentity(device catalystcenter.Device) deviceIdentity {
	return deviceIdentity{
		hostNames: []string{device.Hostname},
		hostIDs:   []string{firstNonEmpty(device.SerialNumber, device.ID, device.InstanceUUID, device.MacAddress)},
		hostIPs:   []string{device.ManagementIPAddress, device.DNSResolvedManagementAddr, device.APManagerInterfaceIP, device.AssociatedWlcIP},
		serials:   []string{device.SerialNumber},
		deviceIDs: []string{device.ID, device.InstanceUUID, device.MacAddress},
	}
}

func catalystInterfaceIdentity(iface catalystcenter.Interface, device catalystcenter.Device) deviceIdentity {
	id := deviceIdentity{
		hostNames: []string{device.Hostname},
		hostIDs:   []string{firstNonEmpty(iface.SerialNo, device.SerialNumber, iface.DeviceID, device.ID, device.InstanceUUID, iface.MacAddress)},
		hostIPs:   []string{iface.IPv4Address, device.ManagementIPAddress},
		serials:   []string{firstNonEmpty(iface.SerialNo, device.SerialNumber)},
		deviceIDs: []string{iface.DeviceID, iface.InstanceUUID, iface.ID, iface.MacAddress, device.ID, device.InstanceUUID},
	}
	if device == (catalystcenter.Device{}) {
		id.hostNames = nil
	}
	return id
}

func catalystTopologyNodeIdentity(node catalystcenter.TopologyNode, device catalystcenter.Device) deviceIdentity {
	id := catalystDeviceIdentity(device)
	id.hostNames = append(id.hostNames, node.Label)
	id.hostIDs = append(id.hostIDs, node.ID)
	id.deviceIDs = append(id.deviceIDs, node.ID)
	return id
}

func catalystIssueIdentity(issue catalystcenter.Issue, device catalystcenter.Device) deviceIdentity {
	id := catalystDeviceIdentity(device)
	id.hostNames = append(id.hostNames, issue.Name, issue.SiteName)
	id.hostIDs = append(id.hostIDs, issue.EntityID)
	id.deviceIDs = append(id.deviceIDs, issue.EntityID)
	return id
}

func catalystClientDetailIdentity(mac string, detail catalystcenter.Object) deviceIdentity {
	hostID := firstNonEmpty(mac, catalystObjectString(detail, "hostMac", "macAddress", "id"))
	return deviceIdentity{
		hostNames: []string{catalystObjectString(detail, "hostName", "userId", "id")},
		hostIDs:   []string{hostID},
		hostIPs:   []string{catalystObjectString(detail, "hostIpV4"), catalystObjectString(detail, "hostIpV6")},
		deviceIDs: []string{hostID, catalystObjectString(detail, "connectedNetworkDeviceId", "deviceId", "nwDeviceId")},
	}
}

func sdwanObjectIdentity(obj sdwan.Object) deviceIdentity {
	serial := sdwanSerial(obj)
	systemIP := sdwanSystemIP(obj)
	uuid := sdwan.String(obj, "uuid", "deviceId")
	siteID := sdwanSiteID(obj)
	return deviceIdentity{
		hostNames: []string{sdwanHostName(obj)},
		hostIDs:   []string{firstNonEmpty(serial, uuid, systemIP, siteID)},
		hostIPs:   []string{systemIP, sdwan.String(obj, "managementIp", "mgmt-ip", "local-system-ip")},
		serials:   []string{serial},
		deviceIDs: []string{uuid, systemIP},
	}
}

func nexusDashboardObjectIdentity(obj nexusdashboard.Object) deviceIdentity {
	serial := nexusdashboard.String(obj, "serialNumber", "serialNo", "serial", "switchSerialNo", "switchSerial")
	switchID := nexusdashboard.String(obj, "switchDbId", "switchId", "nodeId", "id", "uuid")
	hostName := nexusdashboard.String(obj, "switchName", "hostName", "hostname", "name")
	return deviceIdentity{
		hostNames: []string{hostName},
		hostIDs:   []string{firstNonEmpty(serial, switchID)},
		hostIPs:   []string{nexusdashboard.String(obj, "ipAddress", "mgmtIpAddress", "managementIp", "hostIp", "ip")},
		serials:   []string{serial},
		deviceIDs: []string{switchID},
	}
}

func aciObjectIdentity(obj aci.Object) deviceIdentity {
	serial := aci.String(obj, "serial")
	nodeID := firstNonEmpty(nodeIDFromACIDN(aci.String(obj, "dn", "rn")), aci.String(obj, "nodeId", "id"))
	name := aci.String(obj, "name", "descr")
	return deviceIdentity{
		hostNames: []string{name},
		hostIDs:   []string{firstNonEmpty(serial, nodeID, aci.String(obj, "dn"))},
		hostIPs:   []string{aci.String(obj, "ip", "addr")},
		serials:   []string{serial},
		deviceIDs: []string{nodeID, aci.String(obj, "dn"), aci.String(obj, "fabricName", "siteName")},
	}
}

func fmcObjectIdentity(obj fmc.Object) deviceIdentity {
	serial := firstNonEmpty(fmc.String(obj, "serialNumber", "serial"), fmc.String(obj, "parent.device.serial"))
	deviceID := firstNonEmpty(fmc.StableID(obj), fmc.String(obj, "deviceId", "deviceUUID", "parent.device.id"))
	name := firstNonEmpty(fmc.String(obj, "name", "hostName", "displayName"), fmc.String(obj, "parent.device.name"))
	return deviceIdentity{
		hostNames: []string{name},
		hostIDs:   []string{firstNonEmpty(serial, deviceID, name)},
		hostIPs:   []string{fmc.String(obj, "managementIpAddress", "managementIP", "mgmtIp", "ipAddress", "ip", "parent.device.ip")},
		serials:   []string{serial},
		deviceIDs: []string{deviceID},
	}
}

func deviceIdentityFromResourceAttrs(attrs pcommon.Map) deviceIdentity {
	return deviceIdentity{
		hostNames: []string{attrString(attrs, "host.name")},
		hostIDs:   []string{attrString(attrs, "host.id")},
		hostIPs:   attrStrings(attrs, "host.ip"),
		serials: []string{
			attrString(attrs, "meraki.device.serial"),
			attrString(attrs, "intersight.serial"),
			attrString(attrs, "catalyst_center.device.serial"),
			attrString(attrs, "sdwan.chassis_serial"),
			attrString(attrs, "sdwan.board_serial"),
			attrString(attrs, "cisco.switch.serial"),
		},
		deviceIDs: []string{
			attrString(attrs, "meraki.network.id"),
			attrString(attrs, "intersight.moid"),
			attrString(attrs, "intersight.device.registration_moid"),
			attrString(attrs, "catalyst_center.device.id"),
			attrString(attrs, "catalyst_center.device.instance_uuid"),
			attrString(attrs, "sdwan.system_ip"),
			attrString(attrs, "sdwan.uuid"),
			attrString(attrs, "ndfc.switch.id"),
			attrString(attrs, "aci.node.id"),
			attrString(attrs, "aci.dn"),
		},
	}
}

func attrString(attrs pcommon.Map, key string) string {
	value, ok := attrs.Get(key)
	if !ok {
		return ""
	}
	return value.AsString()
}

func attrStrings(attrs pcommon.Map, key string) []string {
	value, ok := attrs.Get(key)
	if !ok {
		return nil
	}
	if value.Type() != pcommon.ValueTypeSlice {
		return []string{value.AsString()}
	}
	values := value.Slice()
	result := make([]string, 0, values.Len())
	for i := 0; i < values.Len(); i++ {
		item := values.At(i)
		if item.Type() == pcommon.ValueTypeStr && item.Str() != "" {
			result = append(result, item.Str())
		}
	}
	return result
}

func anyString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}
