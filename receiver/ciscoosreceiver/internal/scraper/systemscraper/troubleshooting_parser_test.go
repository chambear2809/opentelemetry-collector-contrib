// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package systemscraper

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseControlPlaneCPUProcesses(t *testing.T) {
	output := `PID Runtime(ms) Invoked uSecs 5Sec 1Min 5Min TTY Process
  10      12345    1000  12345  12.34%  3.00%  1.00%   0 IOSD ipc task
  20       2345     500   4690   2.00%  1.00%  0.50%   0 Check heaps
  30       1000     400   2500   8.00%  4.00%  2.00%   0 ARP Input`

	processes := parseControlPlaneCPUProcesses(output, 2)
	require.Len(t, processes, 2)
	assert.Equal(t, "10", processes[0].PID)
	assert.Equal(t, "IOSD ipc task", processes[0].Name)
	assert.Equal(t, "5s", processes[0].Window)
	assert.InDelta(t, 0.1234, processes[0].Utilization, 0.0001)
	assert.Equal(t, "30", processes[1].PID)

	nxOutput := `PID Runtime(ms) Invoked uSecs 5Sec 1Min 5Min TTY Process 1Sec
 123      10000      100   100  3.00%  2.00%  1.00%   - netstack process 4.00%
 124       5000      100    50  1.00%  0.50%  0.20%   - sysmgr 1.50%`
	processes = parseControlPlaneCPUProcesses(nxOutput, 10)
	require.Len(t, processes, 2)
	assert.Equal(t, "netstack process", processes[0].Name)
	assert.Equal(t, "5s", processes[0].Window)
	assert.InDelta(t, 0.03, processes[0].Utilization, 0.0001)
}

func TestParseControlPlanePolicy(t *testing.T) {
	output := `Class-map: routing (match-any)
  100 packets, 6400 bytes
  Match: access-group name copp-routing
  police:
    5 minute offered rate 1000 bps, drop rate 99 bps
    rate 17000 pps, burst 4150 packets
    conformed 80 packets, exceeded 20 packets; actions: transmit drop
    20 packets dropped
Class-map: class-default
  5 packets, 300 bytes`

	packets, drops := parseControlPlanePolicy(output, "show policy-map control-plane")
	require.Len(t, packets, 2)
	require.Len(t, drops, 1)
	assert.Equal(t, int64(100), packets[0].Value)
	assert.Equal(t, "routing", packets[0].Class)
	assert.Equal(t, int64(5), packets[1].Value)
	assert.Equal(t, "class_default", packets[1].Class)
	assert.Equal(t, int64(20), drops[0].Value)
	assert.Equal(t, "routing", drops[0].Class)
	assert.Equal(t, "police_drop", drops[0].Reason)

	nxOutput := `class-map copp-system-class-igmp (match-any)
  police cir 1024 kbps, bc 65535 bytes
  conformed 12 packets; action: transmit
  violated 3 packets; action: drop`
	packets, drops = parseControlPlanePolicy(nxOutput, "show policy-map interface control-plane")
	require.Len(t, packets, 1)
	require.Len(t, drops, 1)
	assert.Equal(t, "copp_system_class_igmp", packets[0].Class)
	assert.Equal(t, int64(12), packets[0].Value)
	assert.Equal(t, int64(3), drops[0].Value)

	multiDropOutput := `Class-map: routing (match-any)
  queue drops 7
  no-buffer drops 4
  queue drops 9`
	_, drops = parseControlPlanePolicy(multiDropOutput, "show policy-map control-plane")
	assert.ElementsMatch(t, []controlPlaneDropCounter{
		{Source: "show policy-map control-plane", Class: "routing", Reason: "queue_drops", Value: 7},
		{Source: "show policy-map control-plane", Class: "routing", Reason: "no_buffer_drops", Value: 4},
	}, drops)
}

func TestParseControlPlanePuntRates(t *testing.T) {
	output := `Queue                         Rate
For-us data                      12 pps
Packets per second averaged over 10 seconds, 1 min and 5 mins
GigabitEthernet1/0/1              7 pps
TenGigabitEthernet1/0/2 0x0000002f 5 5 5 0 0 0
0  CPU_Q_DOT1X_AUTH               11        3        9        0
7  ARP request or response        142962    0`

	rates := parseControlPlanePuntRates(output)
	require.Len(t, rates, 4)
	assert.Equal(t, "for_us_data", rates[0].Queue)
	assert.Equal(t, int64(12), rates[0].Value)
	assert.Equal(t, "interface", rates[1].Queue)
	assert.Equal(t, "gigabitethernet1_0_1", rates[1].Interface)
	assert.Equal(t, "tengigabitethernet1_0_2", rates[2].Interface)
	assert.Equal(t, int64(5), rates[2].Value)
	assert.Equal(t, "cpu_q_dot1x_auth", rates[3].Queue)
	assert.Equal(t, int64(3), rates[3].Value)
}

func TestParseRoutingForwardingSummaries(t *testing.T) {
	routes := parseRouteSummary(`Route Source    Networks    Subnets
connected       0           3
eigrp 109       747         12
internal        3
Total           750         18
Total number of routes: 768
ospf-50 : 9`, "default")
	require.Len(t, routes, 5)
	assert.Equal(t, "connected", routes[0].Source)
	assert.Equal(t, int64(3), routes[0].Value)
	assert.Equal(t, "eigrp_109", routes[1].Source)
	assert.Equal(t, int64(759), routes[1].Value)
	assert.Equal(t, "total", routes[3].Source)
	assert.Equal(t, int64(768), routes[3].Value)
	assert.Equal(t, "ospf_50", routes[4].Source)

	ambiguousRoutes := parseRouteSummary(`Maximum path: 16
Router ID: 192.0.2.1
database version: 4`, "default")
	require.Empty(t, ambiguousRoutes)

	arp := parseARPSummary(`Total ARP entries: 42`, "default")
	require.Len(t, arp, 1)
	assert.Equal(t, int64(42), arp[0].Value)
	assert.Empty(t, parseARPSummary(`Incomplete ARP entries: 2`, "default"))

	fib := parseFIBSummary(`21 routes, 0 reresolve, 0 unresolved (0 old, 0 new), peak 2
22 prefixes (22/0 fwd/non-fwd)`, "default")
	require.Len(t, fib, 1)
	assert.Equal(t, int64(21), fib[0].Value)
	assert.Empty(t, parseFIBSummary(`nonrecursive prefixes: 2`, "default"))

	adj := parseAdjacencySummary(`6 complete adjacencies
incomplete adjacencies: 2
Dynamic : 22
Static : 1
Total : 31`, "default")
	require.Len(t, adj, 5)
	assert.Equal(t, "complete", adj[0].State)
	assert.Equal(t, int64(6), adj[0].Value)
	assert.Equal(t, "dynamic", adj[2].State)
	assert.Empty(t, parseAdjacencySummary(`cache adjacency entries: 2`, "default"))

	drops := parseForwardingDrops(`No route drop: 3
unsupported drops 4
drop rate 99 bps
drop bytes 1024`, "default")
	require.Len(t, drops, 2)
	assert.Equal(t, int64(3), drops[0].Value)
}

func TestParseQFPDatapathUtilization(t *testing.T) {
	output := `CPP 0: Subdev 0 5 secs 1 min 5 min 60 min
Input:  Priority (pps)            0            1            2            3
                 (bps)           96           32           32           32
    Non-Priority (pps)       327503       526605       552898       594269
                 (bps)   1225600520   2664222472   2867573720   2960588728
           Total (pps)       327503       526606       552900       594272
                 (bps)   1225600616   2664222504   2867573752   2960588760
Output: Total (pps)            61           71           75           73
                 (bps)       391904       514648       573408       560424
Processing: Load (pct)            7            8            8            8
Crypto/IO
Crypto: Load (pct)                0            1            2            3
RX: Load (pct)                    0            0            0            0
TX: Load (pct)                   10            9            9            9
Idle (pct)                       90           90           90           90`

	rates, utilizations := parseQFPDatapathUtilization(output)
	require.Len(t, rates, 16)
	require.Len(t, utilizations, 20)

	assert.Contains(t, rates, qfpDatapathRate{
		Direction:        protocolDirectionReceive,
		TrafficClass:     "non_priority",
		Window:           "1m",
		PacketsPerSecond: 526605,
		BitsPerSecond:    2664222472,
	})
	assert.Contains(t, rates, qfpDatapathRate{
		Direction:        protocolDirectionTransmit,
		TrafficClass:     "total",
		Window:           "5s",
		PacketsPerSecond: 61,
		BitsPerSecond:    391904,
	})
	assert.Contains(t, utilizations, qfpDatapathUtilization{LoadType: "processing", Window: "5s", Value: 0.07})
	assert.Contains(t, utilizations, qfpDatapathUtilization{LoadType: "crypto", Window: "60m", Value: 0.03})
	assert.Contains(t, utilizations, qfpDatapathUtilization{LoadType: "tx", Window: "1m", Value: 0.09})
}

func TestParseQFPDrops(t *testing.T) {
	output := `Router# show drops qfp
------------------ show platform hardware qfp active statistics drop detail ------------------
Last clearing of QFP drops statistics : Fri Feb 18 08:02:37 2022
--------------------------------------------------------------------------------
ID Global Drop Stats Packets Octets
--------------------------------------------------------------------------------
319 BFDoffload 9 1350
61 Icmp 84 3780
23 TailDrop 26,713,208 10,952,799,454
------------------ show platform hardware qfp active interface all statistics drop_summary ------------------
Drop Stats Summary:
Interface Rx Pkts Tx Pkts
GigabitEthernet1 60547 0
GigabitEthernet2 60782 27769658
Tunnel14095001 0 1990214`

	drops, interfaceDrops := parseQFPDrops(output, "qfp")
	require.Len(t, drops, 3)
	require.Len(t, interfaceDrops, 6)

	assert.Equal(t, qfpDropCounter{Source: "qfp", Reason: "bfdoffload", Packets: 9, Octets: 1350}, drops[0])
	assert.Equal(t, qfpDropCounter{Source: "qfp", Reason: "taildrop", Packets: 26713208, Octets: 10952799454}, drops[2])
	assert.Contains(t, interfaceDrops, qfpInterfaceDropCounter{
		Interface: "Tunnel14095001",
		Direction: protocolDirectionTransmit,
		Packets:   1990214,
	})
}
