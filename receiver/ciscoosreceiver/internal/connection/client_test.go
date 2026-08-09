// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestRPCClient_GetOSType(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name     string
		osType   string
		expected string
	}{
		{
			name:     "Returns configured OS type",
			osType:   "NX-OS",
			expected: "NX-OS",
		},
		{
			name:     "Returns unknown when empty",
			osType:   "",
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &RPCClient{
				OSType: tt.osType,
				Logger: logger,
			}
			assert.Equal(t, tt.expected, client.GetOSType())
		})
	}
}

func TestRPCClient_GetCommand(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name     string
		osType   string
		feature  string
		expected string
	}{
		{
			name:     "Version command",
			osType:   "IOS XE",
			feature:  "version",
			expected: "show version",
		},
		{
			name:     "CPU command for NX-OS",
			osType:   "NX-OS",
			feature:  "cpu",
			expected: "show system resources",
		},
		{
			name:     "CPU command for IOS XE",
			osType:   "IOS XE",
			feature:  "cpu",
			expected: "show process cpu",
		},
		{
			name:     "Memory command for NX-OS",
			osType:   "NX-OS",
			feature:  "memory",
			expected: "show system resources",
		},
		{
			name:     "Memory command for IOS XE",
			osType:   "IOS XE",
			feature:  "memory",
			expected: "show process memory",
		},
		{
			name:     "Interfaces command for NX-OS",
			osType:   "NX-OS",
			feature:  "interfaces",
			expected: "show interface",
		},
		{
			name:     "Interfaces command for IOS XE",
			osType:   "IOS XE",
			feature:  "interfaces",
			expected: "show interface",
		},
		{
			name:     "VLANs command for IOS XE returns empty (feature removed)",
			osType:   "IOS XE",
			feature:  "vlans",
			expected: "",
		},
		{
			name:     "VLANs command for NX-OS returns empty",
			osType:   "NX-OS",
			feature:  "vlans",
			expected: "",
		},
		{
			name:     "VLANs command for IOS returns empty",
			osType:   "IOS",
			feature:  "vlans",
			expected: "",
		},
		{
			name:     "Unknown feature returns empty",
			osType:   "IOS XE",
			feature:  "unknown",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &RPCClient{
				OSType: tt.osType,
				Logger: logger,
			}
			assert.Equal(t, tt.expected, client.GetCommand(tt.feature))
		})
	}
}

func TestRPCClient_GetInterfaceCommands(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name                           string
		osType                         string
		expectedInterfaces             string
		expectedInterfaceCounters      string
		expectedInterfaceErrorCounters string
		expectedIPTraffic              string
		expectedVLANs                  string
	}{
		{
			name:                           "NX-OS interface commands",
			osType:                         "NX-OS",
			expectedInterfaces:             "show interface",
			expectedInterfaceCounters:      "show interface counters",
			expectedInterfaceErrorCounters: "show interface counters errors",
			expectedIPTraffic:              "show ip traffic",
			expectedVLANs:                  "",
		},
		{
			name:                           "IOS XE interface commands (vlans feature removed)",
			osType:                         "IOS XE",
			expectedInterfaces:             "show interface",
			expectedInterfaceCounters:      "show interfaces counters",
			expectedInterfaceErrorCounters: "show interfaces counters errors",
			expectedIPTraffic:              "show ip traffic",
			expectedVLANs:                  "",
		},
		{
			name:                           "IOS interface commands",
			osType:                         "IOS",
			expectedInterfaces:             "show interface",
			expectedInterfaceCounters:      "show interfaces counters",
			expectedInterfaceErrorCounters: "show interfaces counters errors",
			expectedIPTraffic:              "show ip traffic",
			expectedVLANs:                  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &RPCClient{
				OSType: tt.osType,
				Logger: logger,
			}
			assert.Equal(t, tt.expectedInterfaces, client.GetCommand("interfaces"))
			assert.Equal(t, tt.expectedInterfaceCounters, client.GetCommand("interface_counters"))
			assert.Equal(t, tt.expectedInterfaceErrorCounters, client.GetCommand("interface_error_counters"))
			assert.Equal(t, tt.expectedIPTraffic, client.GetCommand("ip_traffic"))
			assert.Equal(t, tt.expectedVLANs, client.GetCommand("vlans"))
		})
	}
}

func TestRPCClient_GetAIInterfaceCounterCommands(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name     string
		osType   string
		feature  string
		expected []string
	}{
		{
			name:     "NX-OS PFC commands",
			osType:   "NX-OS",
			feature:  "interface_priority_flow_control",
			expected: []string{"show interface priority-flow-control detail", "show interface priority-flow-control"},
		},
		{
			name:     "NX-OS queueing command",
			osType:   "NX-OS",
			feature:  "interface_queueing",
			expected: []string{"show queuing interface", "show queuing"},
		},
		{
			name:     "IOS XE flow-control commands",
			osType:   "IOS XE",
			feature:  "interface_flowcontrol",
			expected: []string{"show interfaces flowcontrol", "show flowcontrol"},
		},
		{
			name:     "IOS XE platform queue stats commands",
			osType:   "IOS XE",
			feature:  "interface_platform_queue_stats",
			expected: []string{"show platform hardware fed active qos queue stats interface", "show platform hardware fed switch active qos queue stats interface"},
		},
		{
			name:     "IOS XE has no PFC command",
			osType:   "IOS XE",
			feature:  "interface_priority_flow_control",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &RPCClient{
				OSType: tt.osType,
				Logger: logger,
			}
			assert.Equal(t, tt.expected, client.GetCommands(tt.feature))
		})
	}
}

func TestRPCClient_GetTroubleshootingCommands(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name     string
		osType   string
		feature  string
		expected []string
	}{
		{
			name:     "IOS XE control-plane CPU process commands",
			osType:   "IOS XE",
			feature:  "control_cpu_processes",
			expected: []string{"show processes cpu sorted 5sec", "show process cpu sorted 5sec", "show processes cpu platform sorted"},
		},
		{
			name:     "NX-OS control-plane CoPP commands",
			osType:   "NX-OS",
			feature:  "control_copp",
			expected: []string{"show policy-map interface control-plane", "show copp status", "show hardware rate-limiter"},
		},
		{
			name:     "NX-OS control-plane CPU process commands",
			osType:   "NX-OS",
			feature:  "control_cpu_processes",
			expected: []string{"show process cpu sort", "show processes cpu sort", "show process cpu", "show processes cpu"},
		},
		{
			name:     "NX-OS has no punt rate command",
			osType:   "NX-OS",
			feature:  "control_punt_rates",
			expected: nil,
		},
		{
			name:    "IOS XE punt rate commands",
			osType:  "IOS XE",
			feature: "control_punt_rates",
			expected: []string{
				"show platform software fed active punt rates interfaces",
				"show platform software fed switch active punt rates interfaces",
			},
		},
		{
			name:     "IOS route summary commands",
			osType:   "IOS",
			feature:  "routing_route_summary",
			expected: []string{"show ip route summary", "show ip route vrf %s summary"},
		},
		{
			name:     "NX-OS ARP summary commands",
			osType:   "NX-OS",
			feature:  "routing_arp",
			expected: []string{"show ip arp summary vrf %s", "show ip arp statistics vrf %s"},
		},
		{
			name:     "IOS LACP command",
			osType:   "IOS",
			feature:  "l2_lacp",
			expected: []string{"show lacp counters"},
		},
		{
			name:     "NX-OS vPC commands",
			osType:   "NX-OS",
			feature:  "l2_vpc",
			expected: []string{"show vpc", "show vpc consistency-parameters global"},
		},
		{
			name:     "IOS has no vPC commands",
			osType:   "IOS",
			feature:  "l2_vpc",
			expected: nil,
		},
		{
			name:     "IOS transceiver commands",
			osType:   "IOS",
			feature:  "transceiver",
			expected: []string{"show interfaces transceiver details", "show interfaces transceiver detail"},
		},
		{
			name:     "NX-OS hardware environment command",
			osType:   "NX-OS",
			feature:  "hardware_environment",
			expected: []string{"show environment"},
		},
		{
			name:     "IOS XE BGP neighbor commands",
			osType:   "IOS XE",
			feature:  "routing_bgp_neighbors",
			expected: []string{"show ip bgp summary", "show bgp ipv4 unicast summary", "show ip bgp vpnv4 vrf %s summary"},
		},
		{
			name:     "NX-OS NVE peer command",
			osType:   "NX-OS",
			feature:  "fabric_nve_peers",
			expected: []string{"show nve peers"},
		},
		{
			name:     "IOS XE has no NVE peer command",
			osType:   "IOS XE",
			feature:  "fabric_nve_peers",
			expected: nil,
		},
		{
			name:     "LLDP topology command",
			osType:   "NX-OS",
			feature:  "l2_lldp",
			expected: []string{"show lldp neighbors detail"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &RPCClient{
				OSType: tt.osType,
				Logger: logger,
			}
			assert.Equal(t, tt.expected, client.GetCommands(tt.feature))
		})
	}
}
