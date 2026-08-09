// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package interfacesscraper

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestParseInterfaces_IOSXE(t *testing.T) {
	output := `
GigabitEthernet0/0 is up, line protocol is up
  Hardware is iGbE, address is aabb.ccdd.ee01 (bia aabb.ccdd.ee01)
  Description: Uplink to Core
  Internet address is 10.1.1.1/24
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive set (10 sec)
  Full-duplex, 1000 Mb/s, media type is RJ45
  output flow-control is unsupported, input flow-control is unsupported
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input 00:00:00, output 00:00:00, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 5
  Queueing strategy: fifo
  Output queue: 0/40 (size/max)
  5 minute input rate 1000 bits/sec, 2 packets/sec
  5 minute output rate 2000 bits/sec, 3 packets/sec
     12345 packets input, 9876543 bytes, 0 no buffer
     Received 150 broadcasts (25 IP multicasts)
     0 runts, 0 giants, 0 throttles
     10 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 watchdog, 75 multicast, 0 pause input
     20 packets output, 1234567 bytes, 0 underruns
     5 output errors, 0 collisions, 1 interface resets
     0 unknown protocol drops
     0 babbles, 0 late collision, 0 deferred
     0 lost carrier, 0 no carrier, 0 pause output
     0 output buffer failures, 0 output buffers swapped out

TenGigabitEthernet1/0/1 is down, line protocol is down (notconnect)
  Hardware is Ten Gigabit Ethernet, address is 1122.3344.5566 (bia 1122.3344.5566)
  MTU 1500 bytes, BW 10000000 Kbit/sec, DLY 10 usec,
  Encapsulation ARPA, loopback not set
  Input queue: 0/75/2/0 (size/max/drops/flushes); Total output drops: 10
  100 packets input, 5000 bytes
  5 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
  50 packets output, 3000 bytes
  3 output errors, 0 collisions, 0 interface resets
`

	logger := zaptest.NewLogger(t)
	interfaces := parseInterfaces(output, logger)

	require.Len(t, interfaces, 2, "should parse 2 interfaces")

	// Verify GigabitEthernet0/0
	gig0 := interfaces[0]
	assert.Equal(t, "GigabitEthernet0/0", gig0.Name)
	assert.Equal(t, "aabb.ccdd.ee01", gig0.MACAddress)
	assert.Equal(t, "Uplink to Core", gig0.Description)
	assert.Equal(t, StatusUp, gig0.AdminStatus)
	assert.Equal(t, StatusUp, gig0.OperStatus)
	assert.Equal(t, int64(9876543), gig0.InputBytes)
	assert.Equal(t, int64(1234567), gig0.OutputBytes)
	assert.Equal(t, int64(10), gig0.InputErrors)
	assert.Equal(t, int64(5), gig0.OutputErrors)
	assert.Equal(t, int64(0), gig0.InputDrops)
	assert.Equal(t, int64(5), gig0.OutputDrops)
	assert.Equal(t, int64(150), gig0.InputBroadcastMulticast)
	assert.Equal(t, int64(75), gig0.InputBroadcast)
	assert.Equal(t, int64(25), gig0.InputIPMulticast)
	assert.Equal(t, int64(75), gig0.InputTotalMulticast)
	assert.Equal(t, int64(75), gig0.InputMulticast)
	assert.Equal(t, int64(12345), gig0.InputPackets)
	assert.Equal(t, int64(20), gig0.OutputPackets)
	assert.Equal(t, int64(1000), gig0.InputRateBits)
	assert.Equal(t, int64(2), gig0.InputRatePackets)
	assert.Equal(t, int64(2000), gig0.OutputRateBits)
	assert.Equal(t, int64(3), gig0.OutputRatePackets)
	assert.Equal(t, "1000 Mb/s", gig0.SpeedString)
	assert.Equal(t, int64(1), gig0.Counters["interface_resets"])
	assert.Equal(t, int64(0), gig0.Counters["crc"])

	// Verify TenGigabitEthernet1/0/1
	ten1 := interfaces[1]
	assert.Equal(t, "TenGigabitEthernet1/0/1", ten1.Name)
	assert.Equal(t, "1122.3344.5566", ten1.MACAddress)
	assert.Equal(t, StatusUp, ten1.AdminStatus)
	assert.Equal(t, StatusDown, ten1.OperStatus)
	assert.Equal(t, int64(5000), ten1.InputBytes)
	assert.Equal(t, int64(3000), ten1.OutputBytes)
	assert.Equal(t, int64(5), ten1.InputErrors)
	assert.Equal(t, int64(3), ten1.OutputErrors)
	assert.Equal(t, int64(2), ten1.InputDrops)
	assert.Equal(t, int64(10), ten1.OutputDrops)
}

func TestParseInterfaces_IOSXEReceiveMulticastPrecedence(t *testing.T) {
	tests := []struct {
		name               string
		output             string
		wantIPMulticast    int64
		wantTotalMulticast int64
	}{
		{
			name: "explicit zero IP multicast",
			output: `GigabitEthernet1/0/1 is up, line protocol is up
  100 packets input, 10000 bytes
  Received 50 broadcasts (0 IP multicasts)
  0 watchdog, 30 multicast, 0 pause input`,
			wantIPMulticast:    0,
			wantTotalMulticast: 30,
		},
		{
			name: "divergent counters in reverse order",
			output: `GigabitEthernet1/0/1 is up, line protocol is up
  100 packets input, 10000 bytes
  0 watchdog, 30 multicast, 0 pause input
  Received 50 broadcasts (20 IP multicasts)`,
			wantIPMulticast:    20,
			wantTotalMulticast: 30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interfaces := parseInterfaces(tt.output, zaptest.NewLogger(t))

			require.Len(t, interfaces, 1)
			intf := interfaces[0]
			assert.Equal(t, int64(50), intf.InputBroadcastMulticast)
			assert.Equal(t, int64(20), intf.InputBroadcast)
			assert.Equal(t, tt.wantIPMulticast, intf.InputIPMulticast)
			assert.Equal(t, tt.wantTotalMulticast, intf.InputTotalMulticast)
			assert.Equal(t, tt.wantTotalMulticast, intf.InputMulticast)
			assert.Equal(t, invalidCounterValue, intf.InputUnicast)
		})
	}
}

func TestParseInterfaces_NXOS(t *testing.T) {
	output := `
Ethernet1/1 is up
admin state is up, Dedicated Interface
  Hardware: 1000/10000 Ethernet, address: 2233.4455.6677 (bia 2233.4455.6677)
  Description: Server Connection
  MTU 1500 bytes, BW 10000000 Kbit, DLY 10 usec
  reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, medium is broadcast
  full-duplex, 10 Gb/s, media type is 10G
  Beacon is turned off
  Auto-Negotiation is turned on
  Input flow-control is off, output flow-control is off
  Auto-mdix is turned off
  Switchport monitor is off
  EtherType is 0x8100
  Last link flapped 5week(s) 2day(s)
  Last clearing of "show interface" counters never
  1 interface resets
  30 seconds input rate 16 bits/sec, 0 packets/sec
  30 seconds output rate 24 bits/sec, 0 packets/sec
  Load-Interval #2: 5 minute (300 seconds)
    input rate 8 bps, 0 pps; output rate 16 bps, 0 pps
  RX
    54321 unicast packets  9999 multicast packets  7777 broadcast packets
    72097 input packets  987654321 bytes
    0 jumbo packets  0 storm suppression bytes
    0 runts  0 giants  0 CRC  0 no buffer
    0 input error  0 short frame  0 overrun   0 underrun  0 ignored
    0 watchdog  0 bad etype drop  0 bad proto drop  0 if down drop
    0 input with dribble  0 input discard
    25 Rx pause
  TX
    12345 unicast packets  5555 multicast packets  3333 broadcast packets
    21233 output packets  123456789 bytes
    0 jumbo packets
    0 output error  0 collision  0 deferred  0 late collision
    0 lost carrier  0 no carrier  0 babble  0 output discard
    0 Tx pause

mgmt0 is up
admin state is up,
  Hardware: GigabitEthernet, address: aabb.ccdd.eeff (bia aabb.ccdd.eeff)
  Internet Address is 192.168.1.10/24
  MTU 1500 bytes, BW 1000000 Kbit, DLY 10 usec
  RX
    1000 unicast packets  500 multicast packets  200 broadcast packets
    1700 input packets  850000 bytes
  TX
    800 unicast packets  100 multicast packets  50 broadcast packets
    950 output packets  475000 bytes
`

	logger := zaptest.NewLogger(t)
	interfaces := parseInterfaces(output, logger)

	require.Len(t, interfaces, 2, "should parse 2 interfaces")

	// Verify Ethernet1/1
	eth1 := interfaces[0]
	assert.Equal(t, "Ethernet1/1", eth1.Name)
	assert.Equal(t, "2233.4455.6677", eth1.MACAddress)
	assert.Equal(t, "Server Connection", eth1.Description)
	assert.Equal(t, StatusUp, eth1.AdminStatus)
	assert.Equal(t, StatusUp, eth1.OperStatus)
	assert.Equal(t, int64(987654321), eth1.InputBytes)
	assert.Equal(t, int64(123456789), eth1.OutputBytes)
	assert.Equal(t, int64(9999), eth1.InputMulticast)
	assert.Equal(t, int64(7777), eth1.InputBroadcast)
	assert.Equal(t, int64(54321), eth1.InputUnicast)
	assert.Equal(t, int64(5555), eth1.OutputMulticast)
	assert.Equal(t, int64(3333), eth1.OutputBroadcast)
	assert.Equal(t, int64(16), eth1.InputRateBits)
	assert.Equal(t, int64(24), eth1.OutputRateBits)
	assert.Equal(t, int64(1), eth1.Counters["interface_resets"])

	// Verify mgmt0
	mgmt := interfaces[1]
	assert.Equal(t, "mgmt0", mgmt.Name)
	assert.Equal(t, "aabb.ccdd.eeff", mgmt.MACAddress)
	assert.Equal(t, StatusUp, mgmt.AdminStatus)
	assert.Equal(t, StatusUp, mgmt.OperStatus)
	assert.Equal(t, int64(850000), mgmt.InputBytes)
	assert.Equal(t, int64(475000), mgmt.OutputBytes)
	assert.Equal(t, int64(500), mgmt.InputMulticast)
	assert.Equal(t, int64(200), mgmt.InputBroadcast)
	assert.Equal(t, int64(800), mgmt.OutputUnicast)
	assert.Equal(t, int64(100), mgmt.OutputMulticast)
	assert.Equal(t, int64(50), mgmt.OutputBroadcast)
}

func TestParseInterfaceCounterTablesAndMerge(t *testing.T) {
	output := `
Port            InOctets    InUcastPkts    InMcastPkts    InBcastPkts
Gi1/0/1              520              2              3              4

Port           OutOctets   OutUcastPkts   OutMcastPkts   OutBcastPkts
Gi1/0/1             1040              5              6              7

Port        Align-Err    FCS-Err   Xmit-Err    Rcv-Err UnderSize OutDiscards
Gi1/0/1             1          2          3          4         5           6

Port         Single-Col  Multi-Col   Late-Col  Exces-Col  Carri-Sen       Runts
Gi1/0/1               7          8          9         10         11          12

Port          Giants SQETest-Err Deferred-Tx IntMacTx-Er IntMacRx-Er Symbol-Err
Gi1/0/1           13          14          15          16          17         18

Port         InDiscards
Gi1/0/1              19

Port         Stomped-CRC
Gi1/0/1              20
`

	logger := zaptest.NewLogger(t)
	counters := parseInterfaceCounterTables(output, logger)
	interfaces := mergeInterfaceCounterTables([]*Interface{NewInterface("GigabitEthernet1/0/1")}, counters)

	require.Len(t, interfaces, 1)
	intf := interfaces[0]
	assert.Equal(t, int64(520), intf.InputBytes)
	assert.Equal(t, int64(1040), intf.OutputBytes)
	assert.Equal(t, int64(2), intf.InputUnicast)
	assert.Equal(t, int64(3), intf.InputMulticast)
	assert.Equal(t, int64(4), intf.InputBroadcast)
	assert.Equal(t, int64(5), intf.OutputUnicast)
	assert.Equal(t, int64(6), intf.OutputMulticast)
	assert.Equal(t, int64(7), intf.OutputBroadcast)
	assert.Equal(t, int64(2), intf.Counters["fcs_errors"])
	assert.Equal(t, int64(3), intf.OutputErrors)
	assert.Equal(t, int64(4), intf.InputErrors)
	assert.Equal(t, int64(6), intf.OutputDrops)
	assert.Equal(t, int64(10), intf.Counters["excess_collisions"])
	assert.Equal(t, int64(12), intf.Counters["runts"])
	assert.Equal(t, int64(13), intf.Counters["giants"])
	assert.Equal(t, int64(16), intf.Counters["internal_mac_transmit_errors"])
	assert.Equal(t, int64(17), intf.Counters["internal_mac_receive_errors"])
	assert.Equal(t, int64(18), intf.Counters["symbol_errors"])
	assert.Equal(t, int64(19), intf.InputDrops)
	assert.Equal(t, int64(20), intf.Counters["stomped_crc"])
	assert.True(t, intf.HasInputPacketTypes)
	assert.True(t, intf.HasOutputPacketTypes)
}

func TestParseInterfaces_NXOSWrappedPhysicalCounters(t *testing.T) {
	output := `
Ethernet1/1 is up
admin state is up, Dedicated Interface
  Hardware: 100/1000/10000/25000 Ethernet, address: 00d7.8f86.2bbe (bia 00d7.8f86.2bbe)
  MTU 1500 bytes, BW 10000000 Kbit, DLY 10 usec
  full-duplex, 10 Gb/s, media type is 10G
  0 interface resets
  RX
    3 unicast packets  3087 multicast packets  0 broadcast packets
    3097 input packets  244636 bytes
    7 jumbo packets  0 storm suppression bytes
    0 runts  7 giants
    7 CRC
    0 no buffer
    7 input error
    0 short frame  1 overrun   2 underrun  3 ignored
    0 watchdog  4 bad etype drop  5 bad proto drop  6 if down drop
    8 input with dribble  9 input discard
    10 Rx pause
    11 Stomped CRC
  TX
    908 unicast packets  323 multicast packets  3 broadcast packets
    1234 output packets  113342 bytes
    12 jumbo packets
    13 output error  14 collision  15 deferred  16 late collision
    17 lost carrier  18 no carrier  19 babble  20 output discard
    21 Tx pause
`

	logger := zaptest.NewLogger(t)
	interfaces := parseInterfaces(output, logger)

	require.Len(t, interfaces, 1)
	intf := interfaces[0]
	assert.Equal(t, int64(7), intf.Counters["crc"])
	assert.Equal(t, int64(7), intf.InputErrors)
	assert.Equal(t, int64(7), intf.Counters["giants"])
	assert.Equal(t, int64(9), intf.InputDrops)
	assert.Equal(t, int64(10), intf.Counters["pause_input"])
	assert.Equal(t, int64(11), intf.Counters["stomped_crc"])
	assert.Equal(t, int64(13), intf.OutputErrors)
	assert.Equal(t, int64(20), intf.OutputDrops)
	assert.Equal(t, int64(21), intf.Counters["pause_output"])
}

func TestParseInterfaces_NXOSCompactRxTxCounters(t *testing.T) {
	output := `
Ethernet2/5 is up
admin state is up, Dedicated Interface
  Hardware: 10/100/1000 Ethernet, address: 0018.bad8.3ffd (bia 0019.076c.4db0)
  MTU 1500 bytes, BW 1000000 Kbit, DLY 10 usec,
  auto-duplex, auto-speed
  1 minute input rate 64 bits/sec, 4 packets/sec
  1 minute output rate 32 bits/sec, 2 packets/sec
  Rx
    78681 input packets 15607 unicast packets 20178 multicast packets
    42896 broadcast packets 7 jumbo packets 8 storm suppression packets
    24189392 bytes
  Tx
    20647 output packets 246 multicast packets
    24 broadcast packets 7370904 bytes
    2 input error 3 short frame 4 watchdog
    5 no buffer 6 runt 7 CRC 8 ecc
    9 overrun  10 underrun 11 ignored 12 bad etype drop
    13 bad proto drop 14 if down drop 15 input with dribble
    16 input discard
    17 output error 18 collision 19 deferred
    20 late collision 21 lost carrier 22 no carrier
    23 babble
    24 Rx pause 25 Tx pause
  26 interface resets
`

	logger := zaptest.NewLogger(t)
	interfaces := parseInterfaces(output, logger)

	require.Len(t, interfaces, 1)
	intf := interfaces[0]
	assert.Equal(t, "Ethernet2/5", intf.Name)
	assert.Equal(t, StatusUp, intf.OperStatus)
	assert.Equal(t, int64(78681), intf.InputPackets)
	assert.Equal(t, int64(15607), intf.InputUnicast)
	assert.Equal(t, int64(20178), intf.InputMulticast)
	assert.Equal(t, int64(42896), intf.InputBroadcast)
	assert.Equal(t, int64(24189392), intf.InputBytes)
	assert.Equal(t, int64(20647), intf.OutputPackets)
	assert.Equal(t, int64(246), intf.OutputMulticast)
	assert.Equal(t, int64(24), intf.OutputBroadcast)
	assert.Equal(t, int64(7370904), intf.OutputBytes)
	assert.Equal(t, int64(64), intf.InputRateBits)
	assert.Equal(t, int64(4), intf.InputRatePackets)
	assert.Equal(t, int64(32), intf.OutputRateBits)
	assert.Equal(t, int64(2), intf.OutputRatePackets)
	assert.Equal(t, int64(7), intf.Counters["input_jumbo_packets"])
	assert.Equal(t, int64(8), intf.Counters["input_storm_suppression_packets"])
	assert.Equal(t, invalidCounterValue, intf.OutputUnicast)
	assert.Equal(t, int64(2), intf.InputErrors)
	assert.Equal(t, int64(16), intf.InputDrops)
	assert.Equal(t, int64(17), intf.OutputErrors)
	assert.Equal(t, int64(6), intf.Counters["runts"])
	assert.Equal(t, int64(7), intf.Counters["crc"])
	assert.Equal(t, int64(8), intf.Counters["ecc"])
	assert.Equal(t, int64(12), intf.Counters["bad_etype_drops"])
	assert.Equal(t, int64(13), intf.Counters["bad_proto_drops"])
	assert.Equal(t, int64(14), intf.Counters["if_down_drops"])
	assert.Equal(t, int64(15), intf.Counters["input_dribble"])
	assert.Equal(t, int64(20), intf.Counters["late_collision"])
	assert.Equal(t, int64(23), intf.Counters["babbles"])
	assert.Equal(t, int64(24), intf.Counters["pause_input"])
	assert.Equal(t, int64(25), intf.Counters["pause_output"])
	assert.Equal(t, int64(26), intf.Counters["interface_resets"])
}

func TestParseInterfaces_VirtualInterfaces(t *testing.T) {
	output := `
Loopback0 is up, line protocol is up
  Hardware is Loopback
  Internet address is 1.1.1.1/32
  MTU 1514 bytes, BW 8000000 Kbit/sec, DLY 5000 usec,
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0
  100 packets input, 10000 bytes
  0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
  100 packets output, 10000 bytes
  0 output errors, 0 collisions, 0 interface resets

Vlan100 is up, line protocol is up
  Hardware is Ethernet SVI, address is 0011.2233.4455 (bia 0011.2233.4455)
  Description: Management VLAN
  Internet address is 10.0.100.1/24
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
  Input queue: 0/75/1/0 (size/max/drops/flushes); Total output drops: 2
  500 packets input, 50000 bytes
  Received 30 broadcasts (15 IP multicasts)
  2 input errors, 0 CRC, 0 frame
  400 packets output, 40000 bytes
  1 output errors, 0 collisions, 0 interface resets
`

	logger := zaptest.NewLogger(t)
	interfaces := parseInterfaces(output, logger)

	require.Len(t, interfaces, 2, "should parse 2 interfaces")

	// Verify Loopback0 (no MAC address)
	loopback := interfaces[0]
	assert.Equal(t, "Loopback0", loopback.Name)
	assert.Empty(t, loopback.MACAddress, "loopback should have no MAC")
	assert.Equal(t, StatusUp, loopback.OperStatus)
	assert.Equal(t, int64(10000), loopback.InputBytes)
	assert.Equal(t, int64(10000), loopback.OutputBytes)

	// Verify Vlan100
	vlan := interfaces[1]
	assert.Equal(t, "Vlan100", vlan.Name)
	assert.Equal(t, "0011.2233.4455", vlan.MACAddress)
	assert.Equal(t, "Management VLAN", vlan.Description)
	assert.Equal(t, StatusUp, vlan.OperStatus)
	assert.Equal(t, int64(50000), vlan.InputBytes)
	assert.Equal(t, int64(40000), vlan.OutputBytes)
	assert.Equal(t, int64(2), vlan.InputErrors)
	assert.Equal(t, int64(1), vlan.OutputErrors)
	assert.Equal(t, int64(1), vlan.InputDrops)
	assert.Equal(t, int64(2), vlan.OutputDrops)
	assert.Equal(t, int64(30), vlan.InputBroadcastMulticast)
	assert.Equal(t, invalidCounterValue, vlan.InputBroadcast)
	assert.Equal(t, int64(15), vlan.InputIPMulticast)
	assert.Equal(t, invalidCounterValue, vlan.InputTotalMulticast)
	assert.Equal(t, invalidCounterValue, vlan.InputMulticast)
}

func TestParseInterfaces_AdminDown(t *testing.T) {
	output := `
GigabitEthernet0/1 is administratively down, line protocol is down
  Hardware is iGbE, address is 1111.2222.3333 (bia 1111.2222.3333)
  MTU 1500 bytes, BW 1000000 Kbit/sec
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0
  0 packets input, 0 bytes
  0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
  0 packets output, 0 bytes
  0 output errors, 0 collisions, 0 interface resets
`

	logger := zaptest.NewLogger(t)
	interfaces := parseInterfaces(output, logger)

	require.Len(t, interfaces, 1, "should parse 1 interface")

	iface := interfaces[0]
	assert.Equal(t, "GigabitEthernet0/1", iface.Name)
	assert.Equal(t, "1111.2222.3333", iface.MACAddress)
	assert.Equal(t, StatusDown, iface.AdminStatus)
	assert.Equal(t, StatusDown, iface.OperStatus)
	assert.Equal(t, int64(0), iface.InputBytes)
	assert.Equal(t, int64(0), iface.OutputBytes)
}

func TestParseInterfaces_AdminUpOperDown(t *testing.T) {
	output := `
GigabitEthernet0/2 is up, line protocol is down (notconnect)
  Hardware is iGbE, address is 1111.2222.4444 (bia 1111.2222.4444)
  MTU 1500 bytes, BW 1000000 Kbit/sec
  0 packets input, 0 bytes
  0 packets output, 0 bytes
`

	logger := zaptest.NewLogger(t)
	interfaces := parseInterfaces(output, logger)

	require.Len(t, interfaces, 1, "should parse 1 interface")

	iface := interfaces[0]
	assert.Equal(t, "GigabitEthernet0/2", iface.Name)
	assert.Equal(t, StatusUp, iface.AdminStatus)
	assert.Equal(t, StatusDown, iface.OperStatus)
}

func TestParseSimpleInterfaces(t *testing.T) {
	output := `
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0     10.1.1.1        YES NVRAM  up                    up
GigabitEthernet0/1     unassigned      YES NVRAM  administratively down down
TenGigabitEthernet1/1  10.2.2.1        YES NVRAM  up                    up
Loopback0              1.1.1.1         YES NVRAM  up                    up
`

	logger := zaptest.NewLogger(t)
	interfaces := parseSimpleInterfaces(output, logger)

	require.Len(t, interfaces, 4, "should parse 4 interfaces")

	assert.Equal(t, "GigabitEthernet0/0", interfaces[0].Name)
	assert.Equal(t, StatusUp, interfaces[0].OperStatus)

	assert.Equal(t, "GigabitEthernet0/1", interfaces[1].Name)
	assert.Equal(t, StatusDown, interfaces[1].OperStatus)

	assert.Equal(t, "TenGigabitEthernet1/1", interfaces[2].Name)
	assert.Equal(t, StatusUp, interfaces[2].OperStatus)

	assert.Equal(t, "Loopback0", interfaces[3].Name)
	assert.Equal(t, StatusUp, interfaces[3].OperStatus)
}

func TestParseSimpleInterfacesNXOSBrief(t *testing.T) {
	output := `
--------------------------------------------------------------------------------
Port   VRF          Status IP Address                              Speed    MTU
--------------------------------------------------------------------------------
mgmt0  --           up     10.250.15.51                            1000    1500
--------------------------------------------------------------------------------
Ethernet        VLAN    Type Mode   Status  Reason                 Speed     Port
Interface                                                                    Ch #
--------------------------------------------------------------------------------
Eth1/1          1       eth  access down    XCVR not inserted        auto(D) --
Eth1/15         --      eth  routed up      none                     400G(D) --

--------------------------------------------------------------------------------
Interface     Status     Description
--------------------------------------------------------------------------------
Lo0           up         --
Lo1           up         --

-------------------------------------------------------------------------------
Interface Secondary VLAN(Type)                    Status Reason
-------------------------------------------------------------------------------
Vlan1     --                                      down   Administratively down`

	logger := zaptest.NewLogger(t)
	interfaces := parseSimpleInterfaces(output, logger)

	require.Len(t, interfaces, 6)
	assert.Equal(t, "mgmt0", interfaces[0].Name)
	assert.Equal(t, StatusUp, interfaces[0].OperStatus)
	assert.Equal(t, "Eth1/1", interfaces[1].Name)
	assert.Equal(t, StatusDown, interfaces[1].OperStatus)
	assert.Equal(t, "Eth1/15", interfaces[2].Name)
	assert.Equal(t, StatusUp, interfaces[2].OperStatus)
	assert.Equal(t, "Lo0", interfaces[3].Name)
	assert.Equal(t, StatusUp, interfaces[3].OperStatus)
	assert.Equal(t, "Lo1", interfaces[4].Name)
	assert.Equal(t, StatusUp, interfaces[4].OperStatus)
	assert.Equal(t, "Vlan1", interfaces[5].Name)
	assert.Equal(t, StatusDown, interfaces[5].OperStatus)
}

func TestParseStatus(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"up", StatusUp},
		{"UP", StatusUp},
		{"Up", StatusUp},
		{"1", StatusUp},
		{"down", StatusDown},
		{"DOWN", StatusDown},
		{"Down", StatusDown},
		{"0", StatusDown},
		{"unknown", StatusDown},
		{"", StatusDown},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseStatus(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatSpeed(t *testing.T) {
	tests := []struct {
		name     string
		input    int64
		expected string
	}{
		{"zero", 0, ""},
		{"negative", -100, ""},
		{"1 Kbps", 1000, "1 Kb/s"},
		{"100 Kbps", 100000, "100 Kb/s"},
		{"1 Mbps", 1000000, "1 Mb/s"},
		{"100 Mbps", 100000000, "100 Mb/s"},
		{"1 Gbps", 1000000000, "1 Gb/s"},
		{"10 Gbps", 10000000000, "10 Gb/s"},
		{"100 Gbps", 100000000000, "100 Gb/s"},
		{"500 bps", 500, "500 b/s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatSpeed(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseLineSpeed(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		unit     string
		expected int64
	}{
		{name: "ten gig", value: "10", unit: "Gb/s", expected: 10_000_000_000},
		{name: "twenty five gig decimal", value: "25", unit: "Gb/s", expected: 25_000_000_000},
		{name: "megabit", value: "1000", unit: "Mb/s", expected: 1_000_000_000},
		{name: "unknown", value: "auto", unit: "Gb/s", expected: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseLineSpeed(tt.value, tt.unit))
		})
	}
}

func TestParseInterfacesSkipsUnavailableRates(t *testing.T) {
	output := `GigabitEthernet0/0 is up, line protocol is up
  Hardware is iGbE, address is aabb.ccdd.ee01
  Full-duplex, 1000 Mb/s, media type is RJ45
  5 minute input rate - bits/sec, - packets/sec
  5 minute output rate - bits/sec, - packets/sec
     1 packets input, 100 bytes
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     2 packets output, 200 bytes
     0 output errors, 0 collisions, 0 interface resets`

	interfaces := parseInterfaces(output, zaptest.NewLogger(t))

	require.Len(t, interfaces, 1)
	assert.False(t, interfaces[0].HasInputRate)
	assert.False(t, interfaces[0].HasOutputRate)
}

func TestParseInterfacesSkipsUnavailableNXOSCombinedRates(t *testing.T) {
	output := `Ethernet1/1 is up
admin state is up, Dedicated Interface
  full-duplex, 10 Gb/s, media type is 10G
  Load-Interval #2: 5 minute (300 seconds)
    input rate - bps, - pps; output rate - bps, - pps`

	interfaces := parseInterfaces(output, zaptest.NewLogger(t))

	require.Len(t, interfaces, 1)
	assert.False(t, interfaces[0].HasInputRate)
	assert.False(t, interfaces[0].HasOutputRate)
	assert.Equal(t, invalidCounterValue, interfaces[0].InputRateBits)
	assert.Equal(t, invalidCounterValue, interfaces[0].OutputRateBits)
}

func TestStr2Float64(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
	}{
		{"valid integer", "123", 123.0},
		{"valid float", "123.45", 123.45},
		{"dash", "-", 0.0},
		{"empty", "", 0.0},
		{"invalid", "abc", 0.0},
		{"zero", "0", 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := str2float64(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestStr2Int64PreservesLargeCounters(t *testing.T) {
	assert.Equal(t, int64(9007199254740993), str2int64("9,007,199,254,740,993"))
	assert.Equal(t, invalidCounterValue, str2int64("18,446,744,073,709,551,615"))
	assert.Equal(t, invalidCounterValue, str2int64("-"))
	assert.Equal(t, invalidCounterValue, str2int64("-1"))
	assert.Equal(t, invalidCounterValue, str2int64("not-a-counter"))
}

func TestInterface_GetOperStatusInt(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected int64
	}{
		{"up", StatusUp, 1},
		{"down", StatusDown, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iface := &Interface{OperStatus: tt.status}
			result := iface.GetOperStatusInt()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInterface_GetAdminStatusInt(t *testing.T) {
	assert.Equal(t, int64(1), (&Interface{AdminStatus: StatusUp}).GetAdminStatusInt())
	assert.Equal(t, int64(0), (&Interface{AdminStatus: StatusDown}).GetAdminStatusInt())
}

func TestInterface_Validate(t *testing.T) {
	tests := []struct {
		name     string
		iface    *Interface
		expected bool
	}{
		{
			name:     "valid interface",
			iface:    &Interface{Name: "eth0", OperStatus: StatusUp},
			expected: true,
		},
		{
			name:     "empty name",
			iface:    &Interface{Name: "", OperStatus: StatusUp},
			expected: false,
		},
		{
			name:     "invalid status gets normalized",
			iface:    &Interface{Name: "eth0", OperStatus: "invalid"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.iface.Validate()
			assert.Equal(t, tt.expected, result)
			if tt.name == "invalid status gets normalized" {
				assert.Equal(t, StatusDown, tt.iface.OperStatus)
			}
			if tt.expected {
				assert.NotEmpty(t, tt.iface.AdminStatus)
			}
		})
	}
}
