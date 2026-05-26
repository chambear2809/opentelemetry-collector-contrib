// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package interfacesscraper

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/scraper/scrapertest"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/interfacesscraper/internal/metadata"
)

func TestRecordStructuredInterfaceCounters(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	s := &interfacesScraper{
		logger: zap.NewNop(),
		config: cfg,
		mb:     metadata.NewMetricsBuilder(cfg.MetricsBuilderConfig, scrapertest.NewNopSettings(metadata.Type)),
	}
	intf := &Interface{
		Name: "Ethernet1/1",
		Counters: map[string]int64{
			"flowcontrol_rx_pause_frames":                          3,
			"pfc_cos_3_transmit_pause_frames":                      4,
			"qos_group_0_unicast_transmit_packets":                 10,
			"qos_group_0_multicast_dropped_bytes":                  20,
			"qos_group_control_0_unicast_transmit_packets":         30,
			"qos_policy_class_prec1_wred_class_1_ecn_mark_packets": 5,
			"qos_policy_class_prec1_wred_total_drop_bytes":         6,
			"hardware_queue_1_shared_buffer_drop_bytes":            8,
		},
	}

	s.recordStructuredInterfaceCounters(pcommon.NewTimestampFromTime(time.Now()), intf)
	counts := interfaceMetricDataPointCounts(s.mb.Emit())

	assert.Equal(t, 2, counts["cisco.interface.pause.frames"])
	assert.Equal(t, 1, counts["cisco.interface.qos.policy.packets"])
	assert.Equal(t, 2, counts["cisco.interface.qos.queue.packets"])
	assert.Equal(t, 1, counts["cisco.interface.qos.policy.bytes"])
	assert.Equal(t, 2, counts["cisco.interface.qos.queue.bytes"])
}

func TestSplitQOSGroupCounter(t *testing.T) {
	group, detail, ok := splitQOSGroupCounter("control_0_unicast_transmit_packets")

	assert.True(t, ok)
	assert.Equal(t, "control_0", group)
	assert.Equal(t, "unicast_transmit_packets", detail)
}

func TestParseTopologyNeighbors(t *testing.T) {
	lldp := `Chassis id: 0011.2233.4455
System Name: leaf-02
Local Intf: Eth1/1
Port id: Eth1/49
Management Address: 10.10.10.2`
	cdp := `Device ID: core-01
Interface: GigabitEthernet1/0/1, Port ID (outgoing port): TenGigabitEthernet1/1
Platform: cisco C9500
IP address: 10.20.20.1`

	lldpNeighbors := parseTopologyNeighbors(lldp, "lldp")
	cdpNeighbors := parseTopologyNeighbors(cdp, "cdp")

	assert.Equal(t, []topologyNeighbor{{
		Protocol:          "lldp",
		LocalInterface:    "Eth1/1",
		NeighborName:      "leaf-02",
		NeighborInterface: "Eth1/49",
		NeighborAddress:   "10.10.10.2",
	}}, lldpNeighbors)
	assert.Equal(t, "core-01", cdpNeighbors[0].NeighborName)
	assert.Equal(t, "GigabitEthernet1/0/1", cdpNeighbors[0].LocalInterface)
	assert.Equal(t, "TenGigabitEthernet1/1", cdpNeighbors[0].NeighborInterface)
	assert.Equal(t, "cisco C9500", cdpNeighbors[0].NeighborPlatform)
}
