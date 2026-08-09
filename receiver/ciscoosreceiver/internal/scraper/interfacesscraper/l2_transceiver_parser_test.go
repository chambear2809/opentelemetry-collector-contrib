// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package interfacesscraper

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSTPStats(t *testing.T) {
	output := `Switch is in rapid-pvst mode
1 vlan
1 blocking
4 forwarding
Root bridge for: VLAN0001
Extended system ID is enabled
Portfast Default is disabled
PortFast BPDU Guard Default is disabled
Portfast BPDU Filter Default is disabled
Loopguard Default is disabled
EtherChannel misconfig guard is enabled
UplinkFast is disabled
BackboneFast is disabled
Configured Pathcost method used is short
Name                   Blocking Listening Learning Forwarding STP Active
---------------------- -------- --------- -------- ---------- ----------
VLAN0001                     1         0        0          4          5
Total                        1         0        0          4          5

VLAN0001
  Number of topology changes 7 last change occurred 00:01:12 ago
          from Gi1/0/1

Name                 Blocked Interfaces List
-------------------- ------------------------------------
VLAN0001             Gi1/0/24,Gi1/0/25

VLAN0002
  Number of topology changes 3 last change occurred 00:00:12 ago`

	stats := parseSTPStats(output)
	require.NotEmpty(t, stats.Instances)
	require.Len(t, stats.TopologyChanges, 2)
	require.Len(t, stats.BlockedPorts, 2)
	assert.Contains(t, stats.Instances, stpInstanceCounter{State: "active", Value: 5})
	assert.Equal(t, int64(7), stats.TopologyChanges[0].Value)
	assert.Equal(t, "Gi1/0/1", stats.TopologyChanges[0].Interface)
	assert.Empty(t, stats.TopologyChanges[1].Interface)
	assert.Equal(t, "1", stats.BlockedPorts[0].VLAN)
	assert.Equal(t, "Gi1/0/24", stats.BlockedPorts[0].Interface)
	assert.Equal(t, "Gi1/0/25", stats.BlockedPorts[1].Interface)
}

func TestParsePortChannelSummary(t *testing.T) {
	output := `Group  Port-channel  Protocol    Ports
------+-------------+-----------+-----------------------------------------------
1      Po1(SU)         LACP      Gi1/0/1(P) Gi1/0/2(s)
                         Gi1/0/4(P)
2      Po2(SD)         LACP      Gi1/0/3(D)`

	channels, members := parsePortChannelSummary(output)
	require.Len(t, channels, 2)
	require.Len(t, members, 4)
	assert.Equal(t, "Port-channel1", channels[0].Name)
	assert.True(t, channels[0].Up)
	assert.False(t, channels[1].Up)
	assert.True(t, members[0].Up)
	assert.False(t, members[1].Up)
	assert.Equal(t, "Port-channel1", members[2].PortChannel)
}

func TestParseLACPCounters(t *testing.T) {
	output := `Gi1/0/9     99          99

Port        LACPDUs Rx  Marker Rx  Marker Resp Rx  LACPDUs Tx
Gi1/0/1     10          0          0               12
Gi1/0/2     3           1          0               4

Port        LACPDUs Sent Recv Marker Sent Marker Recv Marker Response Sent Marker Response Recv Pkts Err
Gi1/0/3     20           18   0           0           0                    0                    2`

	packets, errors := parseLACPCounters(output)
	require.Len(t, packets, 6)
	require.Len(t, errors, 1)
	assert.Equal(t, "Gi1/0/1", packets[0].Interface)
	assert.Equal(t, int64(10), packets[0].Value)
	assert.Equal(t, "receive", packets[0].Direction)
	assert.Equal(t, "Gi1/0/3", packets[4].Interface)
	assert.Equal(t, "transmit", packets[4].Direction)
	assert.Equal(t, int64(20), packets[4].Value)
	assert.Equal(t, "receive", packets[5].Direction)
	assert.Equal(t, int64(18), packets[5].Value)
	assert.Equal(t, int64(2), errors[0].Value)
}

func TestParseLACPCountersRxTxWithPacketErrorColumn(t *testing.T) {
	packets, errors := parseLACPCounters(`Port LACPDUs Rx LACPDUs Tx Pkts Err
Gi1/0/1 10 12 2`)

	require.Len(t, packets, 2)
	assert.Equal(t, "receive", packets[0].Direction)
	assert.Equal(t, int64(10), packets[0].Value)
	assert.Equal(t, "transmit", packets[1].Direction)
	assert.Equal(t, int64(12), packets[1].Value)
	require.Len(t, errors, 1)
	assert.Equal(t, int64(2), errors[0].Value)
}

func TestParseErrDisabledInterfaces(t *testing.T) {
	output := `Port      Name               Status       Reason
This interface is errdisabled because of a test
Gi1/0/2                      err-disabled link-flap
Eth1/3                       errdisabled  udld
Gi1/0/4  uplink-to-core      err-disabled gbic-invalid
Eth114/1/27 --               down         BPDUGuard errDisable`

	interfaces := parseErrDisabledInterfaces(output)
	require.Len(t, interfaces, 4)
	assert.Equal(t, "Gi1/0/2", interfaces[0].Interface)
	assert.Equal(t, "link_flap", interfaces[0].Reason)
	assert.Equal(t, "Gi1/0/4", interfaces[2].Interface)
	assert.Equal(t, "gbic_invalid", interfaces[2].Reason)
	assert.Equal(t, "Eth114/1/27", interfaces[3].Interface)
	assert.Equal(t, "bpduguard_errdisable", interfaces[3].Reason)
}

func TestParseVPC(t *testing.T) {
	output := `vPC domain id                     : 10
peer status                       : peer adjacency formed ok
vPC keep-alive status             : peer is alive
Type-2 consistency status         : failed
Configuration consistency status  : inconsistent

vPC status
id  Port        Status Consistency Reason
1   Po1         up     success     success

vPC status
id                        : 101
Port                      : Po101
Status                    : up
Consistency               : success`

	statuses, failures := parseVPC(output)
	require.Len(t, statuses, 6)
	require.Len(t, failures, 2)
	assert.Equal(t, "10", statuses[0].Domain)
	assert.True(t, statuses[0].Up)
	assert.Equal(t, "type_2_consistency_status", failures[0].Check)
	assert.True(t, statuses[5].Up)
	assert.Equal(t, "101_Po101", statuses[5].Peer)
}

func TestParseTransceiverSensors(t *testing.T) {
	output := `Ethernet1/1
    Temperature  32.50 C
    Voltage       3.29 V
    Tx Power     -1.20 dBm
Lane 1
    Rx Power     -2.10 dBm

Gi1/0/1 transceiver is present
    Temperature  29.00 C
    Temperature Threshold  80.00 C

Temperature
Port       Current  High Alarm  High Warn  Low Warn  Low Alarm  Unit
Gi2/0/3    41.5     88.7        80.7       0.0       -5.0       C

Tx Power
Port       Current  High Alarm  High Warn  Low Warn  Low Alarm  Unit
Gi2/0/3    -1.7     1.0         0.0        -9.9      -13.0      dBm

                            High Alarm  High Warn  Low Warn   Low Alarm
        Voltage             Threshold   Threshold  Threshold  Threshold
Port     (Volts)            (Volts)     (Volts)    (Volts)    (Volts)
Gi2/0/4   3.20               4.00        3.70       3.00       2.95
Gi2/0/5   N/A                4.00        3.70       3.00       2.95`

	sensors := parseTransceiverSensors(output)
	require.Len(t, sensors, 8)
	assert.Equal(t, "Ethernet1/1", sensors[0].Interface)
	assert.Equal(t, "temperature", sensors[0].Sensor)
	assert.InDelta(t, 32.5, sensors[0].Value, 0.01)
	assert.Equal(t, "1", sensors[3].Lane)
	assert.Equal(t, "Gi1/0/1", sensors[4].Interface)
	assert.Equal(t, "Gi2/0/3", sensors[5].Interface)
	assert.Equal(t, "temperature", sensors[5].Sensor)
	assert.InDelta(t, 41.5, sensors[5].Value, 0.01)
	assert.Equal(t, "tx_power", sensors[6].Sensor)
	assert.Equal(t, "Gi2/0/4", sensors[7].Interface)
	assert.Equal(t, "voltage", sensors[7].Sensor)
	assert.Equal(t, "V", sensors[7].Unit)
}
