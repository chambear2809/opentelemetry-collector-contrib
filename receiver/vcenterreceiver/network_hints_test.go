// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package vcenterreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/vcenterreceiver"

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestNetworkHintResponseMismatch(t *testing.T) {
	testCases := []struct {
		name      string
		requested []string
		hints     []types.PhysicalNicHintInfo
		wantErr   bool
	}{
		{
			name:      "exact set",
			requested: []string{"vmnic0", "vmnic1"},
			hints: []types.PhysicalNicHintInfo{
				{Device: "vmnic1"},
				{Device: "vmnic0"},
			},
		},
		{
			name:      "short response",
			requested: []string{"vmnic0", "vmnic1"},
			hints:     []types.PhysicalNicHintInfo{{Device: "vmnic0"}},
			wantErr:   true,
		},
		{
			name:      "extra response",
			requested: []string{"vmnic0"},
			hints:     []types.PhysicalNicHintInfo{{Device: "vmnic0"}, {Device: "vmnic1"}},
			wantErr:   true,
		},
		{
			name:      "duplicate response",
			requested: []string{"vmnic0", "vmnic1"},
			hints:     []types.PhysicalNicHintInfo{{Device: "vmnic0"}, {Device: "vmnic0"}},
			wantErr:   true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mismatch := networkHintResponseMismatch(testCase.requested, testCase.hints)
			if testCase.wantErr {
				require.NotEmpty(t, mismatch)
			} else {
				require.Empty(t, mismatch)
			}
		})
	}
}

func TestPhysicalNicHintRaw(t *testing.T) {
	fullDuplex := true
	raw := physicalNicHintRaw(types.PhysicalNicHintInfo{
		Device:  "vmnic0",
		Network: []types.PhysicalNicNameHint{{Network: "prod", PhysicalNicHint: types.PhysicalNicHint{VlanId: 100}}},
		Subnet:  []types.PhysicalNicIpHint{{IpSubnet: "10.0.0.0/24", PhysicalNicHint: types.PhysicalNicHint{VlanId: 100}}},
		ConnectedSwitchPort: &types.PhysicalNicCdpInfo{
			CdpVersion: 1,
			Address:    "192.0.2.1",
			MgmtAddr:   "192.0.2.2",
			PortId:     "Gi1/0/1",
			FullDuplex: &fullDuplex,
			DeviceCapability: &types.PhysicalNicCdpDeviceCapability{
				NetworkSwitch: true,
			},
		},
		LldpInfo: &types.LinkLayerDiscoveryProtocolInfo{
			ChassisId:  "chassis-1",
			PortId:     "Ethernet1/1",
			TimeToLive: 0,
			Parameter: []types.KeyAnyValue{
				{Key: "system-name", Value: "switch-a"},
				{Key: "vlan", Value: int32(100)},
			},
		},
	})

	require.Equal(t, "vmnic0", raw["device"])
	require.Equal(t, []any{map[string]any{"name": "prod", "vlan_id": int64(100)}}, raw["network_names"])
	require.Equal(t, []any{map[string]any{"ip_subnet": "10.0.0.0/24", "vlan_id": int64(100)}}, raw["subnets"])

	cdp, ok := raw["cdp"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "192.0.2.1", cdp["advertised_address"])
	require.Equal(t, "192.0.2.2", cdp["management_address"])
	require.Equal(t, true, cdp["full_duplex"])
	require.Equal(t, map[string]any{
		"router":              false,
		"transparent_bridge":  false,
		"source_route_bridge": false,
		"network_switch":      true,
		"host":                false,
		"igmp_enabled":        false,
		"repeater":            false,
	}, cdp["device_capability"])

	lldp, ok := raw["lldp"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, true, lldp["ttl_zero_withdrawal_signal"])
	parameters, ok := lldp["parameters"].([]any)
	require.True(t, ok)
	require.Len(t, parameters, 2)
	require.Equal(t, "system-name", parameters[0].(map[string]any)["key"])
	require.Equal(t, "string", parameters[0].(map[string]any)["value"].(map[string]any)["value_type"])
	require.Equal(t, "vlan", parameters[1].(map[string]any)["key"])
	require.Equal(t, "100", parameters[1].(map[string]any)["value"].(map[string]any)["encoded_value"])
}

func TestTypedNetworkHintValueNil(t *testing.T) {
	require.Equal(t, map[string]any{
		"value_type":    "null",
		"vmomi_type":    "<nil>",
		"encoded_value": "null",
	}, typedNetworkHintValue(nil))
}

func TestAppendNetworkHintLog(t *testing.T) {
	logs := plog.NewLogs()
	host := &mo.HostSystem{}
	host.Name = "esx-01"
	fullDuplex := true
	err := appendNetworkHintLog(logs, "dc-01", host, networkHintSnapshot{
		supportsNetworkHints: true,
		state:                "complete",
		requestedDevices:     []string{"vmnic0"},
		hints: []types.PhysicalNicHintInfo{{
			Device:  "vmnic0",
			Network: []types.PhysicalNicNameHint{{Network: "prod", PhysicalNicHint: types.PhysicalNicHint{VlanId: 100}}},
			ConnectedSwitchPort: &types.PhysicalNicCdpInfo{
				CdpVersion: 1,
				FullDuplex: &fullDuplex,
			},
			LldpInfo: &types.LinkLayerDiscoveryProtocolInfo{
				TimeToLive: 120,
				Parameter:  []types.KeyAnyValue{{Key: "system-name", Value: "switch-a"}},
			},
		}},
	}, nil)
	require.NoError(t, err)
	require.Equal(t, 1, logs.ResourceLogs().Len())
	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	require.Equal(t, networkHintEventName, record.EventName())
	datacenter, ok := logs.ResourceLogs().At(0).Resource().Attributes().Get("vcenter.datacenter.name")
	require.True(t, ok)
	require.Equal(t, "dc-01", datacenter.AsString())
	hostName, ok := logs.ResourceLogs().At(0).Resource().Attributes().Get("vcenter.host.name")
	require.True(t, ok)
	require.Equal(t, "esx-01", hostName.AsString())
	body := record.Body().Map().AsRaw()
	require.Equal(t, "complete", body["snapshot_state"])
	require.Equal(t, int64(1), body["returned_hint_count"])
}
