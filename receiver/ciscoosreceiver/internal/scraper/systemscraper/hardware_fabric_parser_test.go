// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package systemscraper

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHardwareHealth(t *testing.T) {
	output := `Fan 1 OK
Power Supply 1 failed
Temperature Sensor 1 42 C OK`

	statuses, temperatures := parseHardwareHealth(output, "hardware_environment")

	require.GreaterOrEqual(t, len(statuses), 3)
	assert.Contains(t, statuses, hardwareStatus{Component: "fan", Name: "Fan 1", Slot: "1", State: "ok", Value: 1})
	assert.Contains(t, statuses, hardwareStatus{Component: "power_supply", Name: "Power Supply 1", Slot: "1", State: "failed", Value: 0})
	require.Len(t, temperatures, 1)
	assert.Equal(t, "Temperature Sensor 1", temperatures[0].Name)
	assert.Equal(t, 42.0, temperatures[0].Value)
	assert.Equal(t, "ok", temperatures[0].State)
}

func TestParseRoutingNeighbors(t *testing.T) {
	bgp := `Neighbor        V    AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd
10.0.0.2       4 65001      10      12      0   0    0 1d02h 42
10.0.0.3       4 65002       0       0      0   0    0 never Idle`

	neighbors := parseRoutingNeighbors(bgp, "bgp", "default")

	require.Len(t, neighbors, 2)
	assert.True(t, neighbors[0].Up)
	assert.Equal(t, int64(42), neighbors[0].Prefixes)
	assert.True(t, neighbors[0].HasPrefixes)
	assert.False(t, neighbors[1].Up)
	assert.Equal(t, "idle", neighbors[1].State)
}

func TestParseOSPFNeighborsIncludesNonFullStates(t *testing.T) {
	ospf := `Neighbor ID     Pri   State           Dead Time   Address         Interface
10.0.0.2          1   FULL/DR         00:00:32    10.0.0.2        Gi1/0/1
10.0.0.3          1   2WAY/DROTHER    00:00:31    10.0.0.3        Gi1/0/2
10.0.0.4          1   EXSTART/BDR     00:00:30    10.0.0.4        Gi1/0/3`

	neighbors := parseRoutingNeighbors(ospf, "ospf", "default")

	require.Len(t, neighbors, 3)
	assert.True(t, neighbors[0].Up)
	assert.Equal(t, "full", neighbors[0].State)
	assert.False(t, neighbors[1].Up)
	assert.Equal(t, "2way", neighbors[1].State)
	assert.False(t, neighbors[2].Up)
	assert.Equal(t, "exstart", neighbors[2].State)
}

func TestParseFabricState(t *testing.T) {
	peers := parseNVEPeers(`Peer-IP          State LearnType Uptime
10.1.1.1         Up    CP        1d
10.1.1.2         Down  CP        0d`)
	vnis := parseNVEVNIs(`VNI       Type State
10010     L2   Up
50000     L3   Down`)
	routes := parseEVPNRoutes(`Route-Type 2: 14
Route Type-5: 8`)

	require.Len(t, peers, 2)
	assert.True(t, peers[0].Up)
	assert.False(t, peers[1].Up)
	require.Len(t, vnis, 2)
	assert.Equal(t, "10010", vnis[0].VNI)
	assert.True(t, vnis[0].Up)
	require.Len(t, routes, 2)
	assert.Contains(t, routes, evpnRouteCounter{VRF: "default", RouteType: "route_type_2", Value: 14})
}
