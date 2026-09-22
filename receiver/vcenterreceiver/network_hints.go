// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package vcenterreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/vcenterreceiver"

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/scraper/scrapererror"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/vcenterreceiver/internal/metadata"
)

const networkHintEventName = "vcenter.network_hint.snapshot"

type networkHintSnapshot struct {
	supportsNetworkHints bool
	state                string
	requestedDevices     []string
	hints                []types.PhysicalNicHintInfo
	errorCategory        string
}

// scrapeNetworkHints collects one source-faithful network-hint snapshot per host.
// It is intentionally a logs signal: CDP/LLDP fields are structured event data,
// not metric dimensions.
func (v *vcenterMetricScraper) scrapeNetworkHints(ctx context.Context) (plog.Logs, error) {
	logs := plog.NewLogs()
	if v.client == nil {
		v.client = newVcenterClient(v.logger, v.config)
	}
	if err := v.client.EnsureConnection(ctx); err != nil {
		return logs, fmt.Errorf("unable to connect to vSphere SDK: %w", err)
	}

	datacenters, err := v.client.Datacenters(ctx)
	if err != nil {
		return logs, err
	}

	var errs scrapererror.ScrapeErrors
	for i := range datacenters {
		hosts, hostErr := v.client.HostSystems(ctx, datacenters[i].Reference())
		if hostErr != nil {
			errs.AddPartial(1, fmt.Errorf("retrieve hosts for datacenter %q: %w", datacenters[i].Name, hostErr))
			continue
		}
		for j := range hosts {
			snapshot, queryErr := v.client.queryNetworkHints(ctx, &hosts[j])
			if err := appendNetworkHintLog(logs, datacenters[i].Name, &hosts[j], snapshot, queryErr); err != nil {
				errs.Add(err)
			}
			if queryErr != nil {
				errs.AddPartial(1, fmt.Errorf("query network hints for host %q: %w", hosts[j].Name, queryErr))
			}
		}
	}

	return logs, errs.Combine()
}

// queryNetworkHints reads host network capabilities and invokes QueryNetworkHint
// only with an explicit, non-empty pNIC device list. An empty list has a special
// vSphere meaning (“all pNICs”), so zero-pNIC hosts are complete without a call.
func (vc *vcenterClient) queryNetworkHints(ctx context.Context, host *mo.HostSystem) (networkHintSnapshot, error) {
	snapshot := networkHintSnapshot{state: "failed"}
	hostObject := object.NewHostSystem(vc.vimDriver, host.Reference())
	networkSystem, err := hostObject.ConfigManager().NetworkSystem(ctx)
	if err != nil {
		snapshot.errorCategory = "network_system_unavailable"
		return snapshot, err
	}

	var networkInfo mo.HostNetworkSystem
	// Request the supported parent property paths. Some vSphere versions reject
	// the equivalent nested leaf paths (for example, networkInfo.pnic.device)
	// with InvalidProperty even though the parent objects are available.
	if err := networkSystem.Properties(ctx, networkSystem.Reference(), []string{
		"capabilities",
		"networkInfo.pnic",
	}, &networkInfo); err != nil {
		snapshot.errorCategory = "network_info_unavailable"
		return snapshot, err
	}

	if networkInfo.Capabilities == nil || !networkInfo.Capabilities.SupportsNetworkHints {
		snapshot.state = "unsupported"
		return snapshot, nil
	}
	snapshot.supportsNetworkHints = true

	devices := make([]string, 0)
	seen := make(map[string]struct{})
	if networkInfo.NetworkInfo != nil {
		for _, pnic := range networkInfo.NetworkInfo.Pnic {
			if pnic.Device == "" {
				continue
			}
			if _, ok := seen[pnic.Device]; ok {
				snapshot.errorCategory = "duplicate_pnic_device"
				return snapshot, fmt.Errorf("host %q returned duplicate pNIC device %q", host.Name, pnic.Device)
			}
			seen[pnic.Device] = struct{}{}
			devices = append(devices, pnic.Device)
		}
	}
	if len(devices) == 0 {
		snapshot.state = "complete"
		return snapshot, nil
	}
	snapshot.requestedDevices = devices

	hints, err := networkSystem.QueryNetworkHint(ctx, devices)
	snapshot.hints = hints
	if err != nil {
		snapshot.errorCategory = "query_network_hint"
		return snapshot, err
	}
	if mismatch := networkHintResponseMismatch(devices, hints); mismatch != "" {
		snapshot.state = "partial"
		snapshot.errorCategory = "response_mismatch"
		return snapshot, fmt.Errorf("QueryNetworkHint response mismatch: %s", mismatch)
	}
	snapshot.state = "complete"
	return snapshot, nil
}

func networkHintResponseMismatch(requested []string, hints []types.PhysicalNicHintInfo) string {
	if len(requested) != len(hints) {
		return fmt.Sprintf("requested %d pNICs, returned %d hints", len(requested), len(hints))
	}
	requestedSet := make(map[string]struct{}, len(requested))
	for _, device := range requested {
		requestedSet[device] = struct{}{}
	}
	returnedSet := make(map[string]struct{}, len(hints))
	for _, hint := range hints {
		if _, duplicate := returnedSet[hint.Device]; duplicate {
			return fmt.Sprintf("duplicate returned pNIC device %q", hint.Device)
		}
		returnedSet[hint.Device] = struct{}{}
	}
	for device := range requestedSet {
		if _, ok := returnedSet[device]; !ok {
			return fmt.Sprintf("missing requested pNIC device %q", device)
		}
	}
	for device := range returnedSet {
		if _, ok := requestedSet[device]; !ok {
			return fmt.Sprintf("unexpected returned pNIC device %q", device)
		}
	}
	return ""
}

func appendNetworkHintLog(
	logs plog.Logs,
	datacenterName string,
	host *mo.HostSystem,
	snapshot networkHintSnapshot,
	queryErr error,
) error {
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	resourceLogs.Resource().Attributes().PutStr("vcenter.datacenter.name", datacenterName)
	resourceLogs.Resource().Attributes().PutStr("vcenter.host.name", host.Name)
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	scopeLogs.Scope().SetName(metadata.ScopeName)
	record := scopeLogs.LogRecords().AppendEmpty()
	now := time.Now()
	record.SetTimestamp(pcommon.NewTimestampFromTime(now))
	record.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	record.SetEventName(networkHintEventName)
	record.SetSeverityNumber(networkHintSeverity(snapshot.state))
	record.SetSeverityText(strings.ToUpper(snapshot.state))

	returnedDevices := make([]string, 0, len(snapshot.hints))
	physicalNics := make([]any, 0, len(snapshot.hints))
	for _, hint := range snapshot.hints {
		returnedDevices = append(returnedDevices, hint.Device)
		physicalNics = append(physicalNics, physicalNicHintRaw(hint))
	}
	requestedDeviceValues := make([]any, 0, len(snapshot.requestedDevices))
	for _, device := range snapshot.requestedDevices {
		requestedDeviceValues = append(requestedDeviceValues, device)
	}
	returnedDeviceValues := make([]any, 0, len(returnedDevices))
	for _, device := range returnedDevices {
		returnedDeviceValues = append(returnedDeviceValues, device)
	}
	body := map[string]any{
		"event_type":             networkHintEventName,
		"snapshot_state":         snapshot.state,
		"supports_network_hints": snapshot.supportsNetworkHints,
		"requested_pnic_devices": requestedDeviceValues,
		"returned_pnic_devices":  returnedDeviceValues,
		"returned_hint_count":    int64(len(snapshot.hints)),
		"physical_nics":          physicalNics,
	}
	if snapshot.errorCategory != "" {
		body["error_category"] = snapshot.errorCategory
	}
	if queryErr != nil {
		body["error_present"] = true
	}
	if err := record.Body().SetEmptyMap().FromRaw(body); err != nil {
		return fmt.Errorf("build network-hint log body: %w", err)
	}
	return nil
}

func networkHintSeverity(state string) plog.SeverityNumber {
	switch state {
	case "failed":
		return plog.SeverityNumberError
	case "partial":
		return plog.SeverityNumberWarn
	default:
		return plog.SeverityNumberInfo
	}
}

func physicalNicHintRaw(hint types.PhysicalNicHintInfo) map[string]any {
	raw := map[string]any{"device": hint.Device}
	if len(hint.Network) > 0 {
		networks := make([]any, 0, len(hint.Network))
		for _, network := range hint.Network {
			networks = append(networks, map[string]any{"name": network.Network, "vlan_id": int64(network.VlanId)})
		}
		raw["network_names"] = networks
	}
	if len(hint.Subnet) > 0 {
		subnets := make([]any, 0, len(hint.Subnet))
		for _, subnet := range hint.Subnet {
			subnets = append(subnets, map[string]any{"ip_subnet": subnet.IpSubnet, "vlan_id": int64(subnet.VlanId)})
		}
		raw["subnets"] = subnets
	}
	if hint.ConnectedSwitchPort != nil {
		cdp := hint.ConnectedSwitchPort
		raw["cdp"] = map[string]any{
			"cdp_version":        int64(cdp.CdpVersion),
			"timeout_seconds":    int64(cdp.Timeout),
			"ttl_seconds":        int64(cdp.Ttl),
			"samples":            int64(cdp.Samples),
			"device_id":          cdp.DevId,
			"advertised_address": cdp.Address,
			"port_id":            cdp.PortId,
			"software_version":   cdp.SoftwareVersion,
			"hardware_platform":  cdp.HardwarePlatform,
			"ip_prefix":          cdp.IpPrefix,
			"ip_prefix_length":   int64(cdp.IpPrefixLen),
			"native_vlan":        int64(cdp.Vlan),
			"mtu":                int64(cdp.Mtu),
			"system_name":        cdp.SystemName,
			"system_oid":         cdp.SystemOID,
			"management_address": cdp.MgmtAddr,
			"location":           cdp.Location,
		}
		if cdp.FullDuplex != nil {
			raw["cdp"].(map[string]any)["full_duplex"] = *cdp.FullDuplex
		}
		if cdp.DeviceCapability != nil {
			raw["cdp"].(map[string]any)["device_capability"] = map[string]any{
				"router":              cdp.DeviceCapability.Router,
				"transparent_bridge":  cdp.DeviceCapability.TransparentBridge,
				"source_route_bridge": cdp.DeviceCapability.SourceRouteBridge,
				"network_switch":      cdp.DeviceCapability.NetworkSwitch,
				"host":                cdp.DeviceCapability.Host,
				"igmp_enabled":        cdp.DeviceCapability.IgmpEnabled,
				"repeater":            cdp.DeviceCapability.Repeater,
			}
		}
	}
	if hint.LldpInfo != nil {
		lldp := hint.LldpInfo
		parameters := make([]any, 0, len(lldp.Parameter))
		for position, parameter := range lldp.Parameter {
			parameters = append(parameters, map[string]any{
				"position": int64(position),
				"key":      parameter.Key,
				"value":    typedNetworkHintValue(parameter.Value),
			})
		}
		raw["lldp"] = map[string]any{
			"chassis_id":                 lldp.ChassisId,
			"port_id":                    lldp.PortId,
			"ttl_seconds":                int64(lldp.TimeToLive),
			"ttl_zero_withdrawal_signal": lldp.TimeToLive == 0,
			"parameters":                 parameters,
		}
	}
	return raw
}

func typedNetworkHintValue(value any) map[string]any {
	valueType, encoded := encodeNetworkHintValue(value)
	vmomiType := "<nil>"
	if value != nil {
		vmomiType = reflect.TypeOf(value).String()
	}
	result := map[string]any{
		"value_type":    valueType,
		"vmomi_type":    vmomiType,
		"encoded_value": encoded,
	}
	return result
}

func encodeNetworkHintValue(value any) (string, string) {
	switch v := value.(type) {
	case nil:
		return "null", "null"
	case string:
		return "string", v
	case bool:
		if v {
			return "boolean", "true"
		}
		return "boolean", "false"
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return "integer", fmt.Sprint(v)
	case float32, float64:
		return "number", fmt.Sprint(v)
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return "unknown", fmt.Sprint(v)
		}
		return "unknown", string(encoded)
	}
}
