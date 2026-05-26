// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package interfacesscraper

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestParseFlowControlCounters(t *testing.T) {
	output := `
Port  Send    FlowControl Receive FlowControl RxPause TxPause
      admin   oper        admin   oper
----- -------- ----------- ------- ----------- ------- -------
Gi1/1 desired off         on      on          123     456
Eth1/2 off     off         off     off         7       8
`

	counters := parseFlowControlCounters(output, zaptest.NewLogger(t))

	require.Len(t, counters, 2)
	assert.Equal(t, int64(123), counters["Gi1/1"]["flowcontrol_rx_pause_frames"])
	assert.Equal(t, int64(456), counters["Gi1/1"]["flowcontrol_tx_pause_frames"])
	assert.Equal(t, int64(7), counters["Eth1/2"]["flowcontrol_rx_pause_frames"])
	assert.Equal(t, int64(8), counters["Eth1/2"]["flowcontrol_tx_pause_frames"])
}

func TestParsePriorityFlowControlCounters(t *testing.T) {
	output := `
============================================================
Port               Mode Oper(VL bmap)  RxPPP      TxPPP
============================================================
Ethernet1/2        Auto On   (9)       4088353    1890
Ethernet1/5        On   On   (0)       0          12
`

	counters := parsePriorityFlowControlCounters(output, zaptest.NewLogger(t))

	require.Len(t, counters, 2)
	assert.Equal(t, int64(4088353), counters["Ethernet1/2"]["pfc_rx_pause_frames"])
	assert.Equal(t, int64(1890), counters["Ethernet1/2"]["pfc_tx_pause_frames"])
	assert.Equal(t, int64(12), counters["Ethernet1/5"]["pfc_tx_pause_frames"])
}

func TestParseQueueingCounters(t *testing.T) {
	output := `
Egress Queuing for Ethernet2/1 [System]
+-------------------------------------------------------------------+
|                              QOS GROUP 0                          |
+-------------------------------------------------------------------+
|                |  Unicast       | OOBFC Unicast  |  Multicast     |
+-------------------------------------------------------------------+
|        Tx Pkts |              12|              22|              34|
|        Tx Byts |            1200|            2200|            3400|
|   Dropped Pkts |               1|               0|               2|
+-------------------------------------------------------------------+
|                              QOS GROUP 3                          |
+-------------------------------------------------------------------+
|        Tx Pkts |              50|   Dropped Pkts |               6|
+-------------------------------------------------------------------+
Port Egress Statistics
--------------------------------------------------------
WRED Drop Pkts                              9
Ingress Queuing for Ethernet2/1
Port Ingress Statistics
--------------------------------------------------------
Ingress MMU Drop Pkts 10
Ingress MMU Drop Bytes 1024
PFC Statistics
----------------------------------------------------------------------------
TxPPP:                    11, RxPPP:                    12
----------------------------------------------------------------------------
COS QOS Group        PG   TxPause   TxCount         RxPause         RxCount
   0         -         -  Inactive         0        Inactive               0
   3         3         3  Active           7        Active                 8
----------------------------------------------------------------------------
`

	counters := parseQueueingCounters(output, zaptest.NewLogger(t))

	require.Len(t, counters, 1)
	intfCounters := counters["Ethernet2/1"]
	assert.Equal(t, int64(12), intfCounters["qos_group_0_unicast_transmit_packets"])
	assert.Equal(t, int64(22), intfCounters["qos_group_0_oobfc_unicast_transmit_packets"])
	assert.Equal(t, int64(3400), intfCounters["qos_group_0_multicast_transmit_bytes"])
	assert.Equal(t, int64(2), intfCounters["qos_group_0_multicast_dropped_packets"])
	assert.Equal(t, int64(50), intfCounters["qos_group_3_transmit_packets"])
	assert.Equal(t, int64(6), intfCounters["qos_group_3_dropped_packets"])
	assert.Equal(t, int64(9), intfCounters["qos_wred_dropped_packets"])
	assert.Equal(t, int64(10), intfCounters["qos_ingress_mmu_dropped_packets"])
	assert.Equal(t, int64(1024), intfCounters["qos_ingress_mmu_dropped_bytes"])
	assert.Equal(t, int64(11), intfCounters["pfc_tx_pause_frames"])
	assert.Equal(t, int64(12), intfCounters["pfc_rx_pause_frames"])
	assert.Equal(t, int64(7), intfCounters["pfc_cos_3_transmit_pause_frames"])
	assert.Equal(t, int64(8), intfCounters["pfc_cos_3_receive_pause_frames"])
}

func TestParseQueueingCountersLegacyNXOS(t *testing.T) {
	output := `
Ethernet1/2 queuing information:
TX Queuing
qos-group sched-type oper-bandwidth
0 WRR 73
RX Queuing
qos-group 1
q-size: 76800, HW MTU: 2240 (2158 configured)
drop-type: no-drop, xon: 128, xoff: 240
Statistics:
Pkts received over the port : 101
Ucast pkts sent to the cross-bar : 102
Mcast pkts sent to the cross-bar : 103
Ucast pkts received from the cross-bar : 104
Pkts sent to the port : 105
Pkts discarded on ingress : 106
Per-priority-pause status : Rx (Inactive), Tx (Inactive)
`

	counters := parseQueueingCounters(output, zaptest.NewLogger(t))

	require.Len(t, counters, 1)
	intfCounters := counters["Ethernet1/2"]
	assert.Equal(t, int64(101), intfCounters["qos_group_1_packets_received_over_the_port"])
	assert.Equal(t, int64(102), intfCounters["qos_group_1_ucast_packets_sent_to_the_cross_bar"])
	assert.Equal(t, int64(106), intfCounters["qos_group_1_packets_discarded_on_ingress"])
}

func TestParsePFCWatchdogCounters(t *testing.T) {
	output := `
Ethernet1/23 Interface PFC watchdog: [Enabled]
Disable-action                     : No
PFC watch-dog interface-multiplier : 0
+----------------------------------------------------+
| QOS GROUP 3 [Shutdown] PFC [YES] PFC-COS [3]
+----------------------------------------------------+
|                               |  Stats             |
+----------------------------------------------------+
|                       Shutdown|                   1|
|                       Restored|                   2|
|             Total pkts drained|                   3|
|             Total pkts dropped|                   4|
|   Total pkts drained + dropped|                   5|
|         Aggregate pkts dropped|                   6|
|     Total Ingress pkts dropped|                1924|
| Aggregate Ingress pkts dropped|                1925|
+----------------------------------------------------+
`

	counters := parsePFCWatchdogCounters(output, zaptest.NewLogger(t))

	require.Len(t, counters, 1)
	intfCounters := counters["Ethernet1/23"]
	assert.Equal(t, int64(1), intfCounters["pfc_watchdog_qos_group_3_shutdown_events"])
	assert.Equal(t, int64(2), intfCounters["pfc_watchdog_qos_group_3_restored_events"])
	assert.Equal(t, int64(3), intfCounters["pfc_watchdog_qos_group_3_total_packets_drained"])
	assert.Equal(t, int64(4), intfCounters["pfc_watchdog_qos_group_3_total_packets_dropped"])
	assert.Equal(t, int64(5), intfCounters["pfc_watchdog_qos_group_3_total_packets_drained_dropped"])
	assert.Equal(t, int64(6), intfCounters["pfc_watchdog_qos_group_3_aggregate_packets_dropped"])
	assert.Equal(t, int64(1924), intfCounters["pfc_watchdog_qos_group_3_total_ingress_packets_dropped"])
	assert.Equal(t, int64(1925), intfCounters["pfc_watchdog_qos_group_3_aggregate_ingress_packets_dropped"])
}

func TestParsePolicyMapInterfaceCounters(t *testing.T) {
	output := `
Serial4/1
 Service-policy output:policy_ecn
       Class-map:prec1 (match-all)
         1000 packets, 125000 bytes
         (pkts matched/bytes matched) 989/123625
         (depth/total drops/no-buffer drops) 0/455/9
          class   Transmitted  Random drop  Tail drop   Minimum     Maximum     Mark
                  pkts/bytes   pkts/bytes    pkts/bytes threshold   threshold   probability
            1     545/68125      2/250        3/375        22          40        1/10
          class   ECN Mark
                 pkts/bytes
            1    43/5375

GigabitEthernet1/0/1
  Service-policy output: SHAPE
    Class-map: dscp2 (match-all)
      0 packets, 0 bytes
      Queueing
      (total drops) 10554
      (bytes output) 2443152000
      (pkts output) 4910606
      AFD WRED STATS BEGIN
      Total Drops(Bytes)   : 123
      Total Drops (Packets) : 4
      AFD WRED STATS END
`

	counters := parsePolicyMapInterfaceCounters(output, zaptest.NewLogger(t))

	require.Len(t, counters, 2)
	serialCounters := counters["Serial4/1"]
	assert.Equal(t, int64(1000), serialCounters["qos_policy_class_prec1_matched_packets"])
	assert.Equal(t, int64(123625), serialCounters["qos_policy_class_prec1_queue_matched_bytes"])
	assert.Equal(t, int64(455), serialCounters["qos_policy_class_prec1_total_drops"])
	assert.Equal(t, int64(9), serialCounters["qos_policy_class_prec1_no_buffer_drops"])
	assert.Equal(t, int64(545), serialCounters["qos_policy_class_prec1_wred_class_1_transmitted_packets"])
	assert.Equal(t, int64(250), serialCounters["qos_policy_class_prec1_wred_class_1_random_drop_bytes"])
	assert.Equal(t, int64(3), serialCounters["qos_policy_class_prec1_wred_class_1_tail_drop_packets"])
	assert.Equal(t, int64(43), serialCounters["qos_policy_class_prec1_wred_class_1_ecn_mark_packets"])
	assert.Equal(t, int64(5375), serialCounters["qos_policy_class_prec1_wred_class_1_ecn_mark_bytes"])

	gigCounters := counters["GigabitEthernet1/0/1"]
	assert.Equal(t, int64(10554), gigCounters["qos_policy_class_dscp2_total_drops"])
	assert.Equal(t, int64(2443152000), gigCounters["qos_policy_class_dscp2_output_bytes"])
	assert.Equal(t, int64(4910606), gigCounters["qos_policy_class_dscp2_output_packets"])
	assert.Equal(t, int64(123), gigCounters["qos_policy_class_dscp2_wred_total_drop_bytes"])
	assert.Equal(t, int64(4), gigCounters["qos_policy_class_dscp2_wred_total_drop_packets"])
}

func TestParsePlatformQueueStatsCounters(t *testing.T) {
	output := `
DATA Port:16 Enqueue Counters
------------------------------------------------------------------------------
Q Buffers        Enqueue-TH0  Enqueue-TH1  Enqueue-TH2  Qpolicer
    (Count)      (Bytes)      (Bytes)      (Bytes)      (Bytes)
--- ----         ----         ------       -----        -----
  0    0                10           20          30          40
  1    0                50           60          70          80

DATA Port:16 Drop Counters
------------------------------------------------------------------------------
Q     Drop-TH0    Drop-TH1    Drop-TH2    SBufDrop    QebDrop   QpolicerDrop
      (Bytes)     (Bytes)     (Bytes)     (Bytes)     (Bytes)   (Bytes)
--    -----       -------     ------      ------      -----     -------
  0       1            2           3           4           5               6
  1       7            8           9          10          11              12
`

	counters := parsePlatformQueueStatsCounters(output, zaptest.NewLogger(t))

	assert.Equal(t, int64(10), counters["hardware_queue_0_enqueue_threshold_0_bytes"])
	assert.Equal(t, int64(80), counters["hardware_queue_1_policer_enqueue_bytes"])
	assert.Equal(t, int64(3), counters["hardware_queue_0_drop_threshold_2_bytes"])
	assert.Equal(t, int64(10), counters["hardware_queue_1_shared_buffer_drop_bytes"])
	assert.Equal(t, int64(12), counters["hardware_queue_1_policer_drop_bytes"])
}
