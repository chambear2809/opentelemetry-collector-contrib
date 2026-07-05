// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestCatalyst9800GNMIDecoderWirelessAliasesAndRawMetrics(t *testing.T) {
	decoder := catalyst9800GNMIUpdateDecoder{
		target: Catalyst9800TargetConfig{
			ClientConfig:   mustCatalyst9800ClientConfig("192.0.2.20:57400"),
			Name:           "wlc-9800-1",
			PlatformFamily: "catalyst_9800",
		},
		health: &catalyst9800Health{},
	}

	md := pmetric.NewMetrics()
	for _, notification := range []*gnmi.Notification{
		catalyst9800JSONNotification(t, "wireless-ap-global-oper:ap-global-oper-data/ap-join-stats[wtp-mac=AA:BB:CC:DD:EE:FF]", "ap-join-info", `{
			"ap-name": "AP-01",
			"ap-ip": "192.0.2.21",
			"is-joined": true,
			"last-join-failure-type": "max-retries",
			"disconnects": 2
		}`),
		catalyst9800JSONNotification(t, "wireless-access-point-oper:access-point-oper-data/capwap-data[wtp-mac=AA:BB:CC:DD:EE:FF]", "state", `{
			"ap-operation-state": "registered"
		}`),
		catalyst9800JSONNotification(t, "wireless-rrm-oper:rrm-oper-data/rrm-measurement[wtp-mac=AA:BB:CC:DD:EE:FF][radio-slot-id=0]", "measurement", `{
			"cca-util-percentage": 62,
			"noise": -92,
			"stations": 17,
			"chan-changes": 3
		}`),
		catalyst9800JSONNotification(t, "wireless-access-point-oper:access-point-oper-data/ssid-counters[wtp-mac=AA:BB:CC:DD:EE:FF][slot-id=0][wlan-id=42]", "counters", `{
			"vap-ssid": "Corp",
			"num-assoc-clients": 12,
			"bss-chan-util": 55,
			"tx-bytes-data": 1000,
			"rx-bytes-data": 2000,
			"tx-retries-data": 7,
			"noise-floor": -90
		}`),
		catalyst9800JSONNotification(t, "wireless-client-oper:client-oper-data/common-oper-data[client-mac=00:11:22:33:44:55]", "state", `{
			"co-state": "run"
		}`),
		catalyst9800JSONNotification(t, "wireless-client-oper:client-oper-data/dot11-oper-data[ms-mac-address=00:11:22:33:44:55]", "roam", `{
			"vap-ssid": "Corp",
			"dot11-roam-type": "l3",
			"roam-failure-count": 1
		}`),
		catalyst9800JSONNotification(t, "wireless-client-oper:client-oper-data/traffic-stats[ms-mac-address=00:11:22:33:44:55]", "stats", `{
			"most-recent-rssi": -51,
			"most-recent-snr": 38,
			"bytes-rx": 1234,
			"pkts-tx": 10
		}`),
		catalyst9800JSONNotification(t, "wireless-client-oper:client-oper-data/exclusion-data[client-mac=00:11:22:33:44:55]", "auth", `{
			"exclude-reason": "aaa-timeout"
		}`),
		catalyst9800JSONNotification(t, "wireless-mobility-oper:mobility-oper-data/mobility-node-data[node-ip=198.51.100.10]", "peer", `{
			"peer-status": "up",
			"l2-roam-cnt": 8,
			"l3-roam-cnt": 4,
			"handoff-sent-ok": 3,
			"handoff-sent-fail": 1
		}`),
		catalyst9800JSONNotification(t, "ha-ios-xe-oper:ha-oper-data/ha-infra", "state", `{
			"ha-state": "active",
			"ha-enabled": true,
			"switchover-count": 2,
			"standby-failure-count": 1
		}`),
		catalyst9800JSONNotification(t, "aaa-ios-xe-oper:aaa-data/aaa-radius-global-stats", "radius", `{
			"access-accepts": 50,
			"access-rejects": 5,
			"authen-timeouts": 2,
			"authen-avg-response-delay": 12,
			"authen-max-response-delay": 55,
			"authen-bad-authenticators": 1
		}`),
		catalyst9800JSONNotification(t, "process-cpu-ios-xe-oper:cpu-usage/cpu-utilization", "cpu", `{
			"five-seconds": 22
		}`),
	} {
		decoder.decodeNotification(notification, catalyst9800TelemetryTransportDialIn).ResourceMetrics().MoveAndAppendTo(md.ResourceMetrics())
	}

	assertMetricExists(t, md, "cisco.catalyst9800.yang.wireless_ap_global_oper.ap_global_oper_data.ap_join_stats.ap_join_info.is_joined")
	for _, name := range []string{
		"cisco.wlc.ap.join.status",
		"cisco.wlc.ap.join.failure.reason.info",
		"cisco.wlc.ap.disconnect",
		"cisco.wlc.ap.capwap.state",
		"cisco.wlc.rf.channel.utilization",
		"cisco.wlc.rf.noise_floor",
		"cisco.wlc.rf.client.count",
		"cisco.wlc.rf.channel.change.count",
		"cisco.wlc.ssid.client.count",
		"cisco.wlc.ssid.channel.utilization",
		"cisco.wlc.ssid.network.io",
		"cisco.wlc.ssid.retry.count",
		"cisco.wlc.client.connection.state",
		"cisco.wlc.client.auth.failure.reason.info",
		"cisco.wlc.client.roam.count",
		"cisco.wlc.client.roam.failure.count",
		"cisco.wlc.client.wireless.rssi",
		"cisco.wlc.client.wireless.snr",
		"cisco.wlc.client.network.io",
		"cisco.wlc.client.network.packets",
		"cisco.wlc.mobility.peer.status",
		"cisco.wlc.mobility.roam.count",
		"cisco.wlc.mobility.handoff.count",
		"cisco.wlc.mobility.handoff.failure.count",
		"cisco.wlc.ha.state",
		"cisco.wlc.ha.enabled",
		"cisco.wlc.ha.switchover.count",
		"cisco.wlc.ha.standby.failure.count",
		"cisco.wlc.auth.radius.access.accept.count",
		"cisco.wlc.auth.radius.access.reject.count",
		"cisco.wlc.auth.radius.timeout.count",
		"cisco.wlc.auth.radius.response_delay.avg",
		"cisco.wlc.auth.radius.response_delay.max",
		"cisco.wlc.auth.radius.bad_authenticator.count",
		"cisco.wlc.controller.cpu.utilization",
	} {
		assertMetricExists(t, md, name)
	}

	join := mustFindIOSXRMetric(t, md, "cisco.wlc.ap.join.status")
	require.Equal(t, pmetric.MetricTypeGauge, join.Type())
	dp := join.Gauge().DataPoints().At(0)
	assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
	assert.Equal(t, int64(1), dp.IntValue())
	assert.Equal(t, "AA:BB:CC:DD:EE:FF", attrValue(t, dp.Attributes(), "cisco.wlc.ap.mac"))
	assert.Equal(t, []string{"192.0.2.21"}, stringSliceAttrValue(t, dp.Attributes()))

	rfUtilization := mustFindIOSXRMetric(t, md, "cisco.wlc.rf.channel.utilization")
	require.Equal(t, pmetric.MetricTypeGauge, rfUtilization.Type())
	assert.Equal(t, "1", rfUtilization.Unit())
	require.Equal(t, 1, rfUtilization.Gauge().DataPoints().Len())
	assert.InDelta(t, 0.62, rfUtilization.Gauge().DataPoints().At(0).DoubleValue(), 0.0001)

	ssidUtilization := mustFindIOSXRMetric(t, md, "cisco.wlc.ssid.channel.utilization")
	require.Equal(t, pmetric.MetricTypeGauge, ssidUtilization.Type())
	assert.Equal(t, "1", ssidUtilization.Unit())
	require.Equal(t, 1, ssidUtilization.Gauge().DataPoints().Len())
	assert.InDelta(t, 0.55, ssidUtilization.Gauge().DataPoints().At(0).DoubleValue(), 0.0001)

	cpuUtilization := mustFindIOSXRMetric(t, md, "cisco.wlc.controller.cpu.utilization")
	require.Equal(t, pmetric.MetricTypeGauge, cpuUtilization.Type())
	assert.Equal(t, "1", cpuUtilization.Unit())
	require.Equal(t, 1, cpuUtilization.Gauge().DataPoints().Len())
	assert.InDelta(t, 0.22, cpuUtilization.Gauge().DataPoints().At(0).DoubleValue(), 0.0001)

	clientBytes := mustFindIOSXRMetric(t, md, "cisco.wlc.client.network.io")
	require.Equal(t, pmetric.MetricTypeSum, clientBytes.Type())
	assert.Equal(t, "By", clientBytes.Unit())
	require.Equal(t, 1, clientBytes.Sum().DataPoints().Len())
	bytesDP := clientBytes.Sum().DataPoints().At(0)
	assert.Equal(t, int64(1234), bytesDP.IntValue())
	assert.Equal(t, "rx", attrValue(t, bytesDP.Attributes(), "direction"))
	_, hasUnitAttr := bytesDP.Attributes().Get("unit")
	assert.False(t, hasUnitAttr)

	clientPackets := mustFindIOSXRMetric(t, md, "cisco.wlc.client.network.packets")
	require.Equal(t, pmetric.MetricTypeSum, clientPackets.Type())
	assert.Equal(t, "{packet}", clientPackets.Unit())
	require.Equal(t, 1, clientPackets.Sum().DataPoints().Len())
	packetsDP := clientPackets.Sum().DataPoints().At(0)
	assert.Equal(t, int64(10), packetsDP.IntValue())
	assert.Equal(t, "tx", attrValue(t, packetsDP.Attributes(), "direction"))
	_, hasUnitAttr = packetsDP.Attributes().Get("unit")
	assert.False(t, hasUnitAttr)

	resourceAttrs := md.ResourceMetrics().At(0).Resource().Attributes()
	assert.Equal(t, "wlc-9800-1", attrValue(t, resourceAttrs, "host.name"))
	assert.Equal(t, []string{"192.0.2.20"}, stringSliceAttrValue(t, resourceAttrs))
	assert.Equal(t, "ios_xe", attrValue(t, resourceAttrs, "cisco.os.name"))
	assert.Equal(t, "catalyst_9800", attrValue(t, resourceAttrs, "cisco.platform.family"))
	assert.Equal(t, "gnmi_dial_in", attrValue(t, resourceAttrs, "cisco.telemetry.transport"))
}

func TestCatalyst9800GNMIDecoderCoalescesMetricStreamsAndPreservesUint64(t *testing.T) {
	decoder := catalyst9800GNMIUpdateDecoder{
		target: Catalyst9800TargetConfig{Name: "wlc-1"},
		health: &catalyst9800Health{},
	}

	md := decoder.decodeNotification(&gnmi.Notification{
		Timestamp: time.Unix(1700000000, 0).UnixNano(),
		Prefix:    mustParseIOSXRPath(t, "wireless-access-point-oper:access-point-oper-data"),
		Update: []*gnmi.Update{
			{
				Path: catalyst9800SSIDCounterPath("AA:BB:CC:DD:EE:01", "tx-bytes-data"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_UintVal{UintVal: math.MaxInt64}},
			},
			{
				Path: catalyst9800SSIDCounterPath("AA:BB:CC:DD:EE:02", "tx-bytes-data"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_UintVal{UintVal: 42}},
			},
			{
				Path: catalyst9800SSIDCounterPath("AA:BB:CC:DD:EE:03", "rx-bytes-data"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_UintVal{UintVal: ^uint64(0)}},
			},
		},
	}, catalyst9800TelemetryTransportDialIn)

	const txBytes = "cisco.catalyst9800.yang.wireless_access_point_oper.access_point_oper_data.ssid_counters.tx_bytes_data"
	assert.Equal(t, 1, metricCountNamed(md, txBytes))
	assertCatalyst9800IntDatapointsByAP(t, mustFindIOSXRMetric(t, md, txBytes), map[string]int64{
		"AA:BB:CC:DD:EE:01": math.MaxInt64,
		"AA:BB:CC:DD:EE:02": 42,
	})

	const networkIO = "cisco.wlc.ssid.network.io"
	assert.Equal(t, 1, metricCountNamed(md, networkIO))
	assertCatalyst9800IntDatapointsByAP(t, mustFindIOSXRMetric(t, md, networkIO), map[string]int64{
		"AA:BB:CC:DD:EE:01": math.MaxInt64,
		"AA:BB:CC:DD:EE:02": 42,
	})

	const rxBytesInfo = "cisco.catalyst9800.yang.wireless_access_point_oper.access_point_oper_data.ssid_counters.rx_bytes_data_info"
	assert.Equal(t, 1, metricCountNamed(md, rxBytesInfo))
	overflow := mustFindIOSXRMetric(t, md, rxBytesInfo)
	require.Equal(t, pmetric.MetricTypeGauge, overflow.Type())
	require.Equal(t, 1, overflow.Gauge().DataPoints().Len())
	overflowDP := overflow.Gauge().DataPoints().At(0)
	assert.Equal(t, "18446744073709551615", attrValue(t, overflowDP.Attributes(), "value"))
	assert.Equal(t, "uint64", attrValue(t, overflowDP.Attributes(), "cisco.value.type"))
	assert.Equal(t, "true", attrValue(t, overflowDP.Attributes(), "cisco.value.out_of_range"))
	assert.Equal(t, "AA:BB:CC:DD:EE:03", attrValue(t, overflowDP.Attributes(), "cisco.wlc.ap.mac"))
}

//nolint:staticcheck // Cisco devices still emit deprecated gNMI Decimal64 values, including malformed boundary cases.
func TestCatalyst9800GNMIDecoderTypedValueBranches(t *testing.T) {
	health := &catalyst9800Health{}
	decoder := catalyst9800GNMIUpdateDecoder{target: Catalyst9800TargetConfig{Name: "wlc-1"}, health: health}
	md := decoder.decodeNotification(&gnmi.Notification{
		Prefix: mustParseIOSXRPath(t, "wireless-access-point-oper:access-point-oper-data"),
		Update: []*gnmi.Update{
			{Path: mustParseIOSXRPath(t, "ascii-value"), Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_AsciiVal{AsciiVal: "legacy"}}},
			{Path: mustParseIOSXRPath(t, "signed-value"), Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_IntVal{IntVal: -7}}},
			{Path: mustParseIOSXRPath(t, "disabled"), Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_BoolVal{BoolVal: false}}},
			{Path: mustParseIOSXRPath(t, "float-value"), Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_FloatVal{FloatVal: 1.5}}},
			{Path: mustParseIOSXRPath(t, "double-value"), Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_DoubleVal{DoubleVal: 2.25}}},
			{Path: mustParseIOSXRPath(t, "decimal-value"), Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_DecimalVal{DecimalVal: &gnmi.Decimal64{Digits: 12345, Precision: 2}}}},
			{
				Path: mustParseIOSXRPath(t, "mixed-leaf-list"),
				Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_LeaflistVal{LeaflistVal: &gnmi.ScalarArray{Element: []*gnmi.TypedValue{
					{Value: &gnmi.TypedValue_StringVal{StringVal: "text"}},
					{Value: &gnmi.TypedValue_AsciiVal{AsciiVal: "ascii"}},
					{Value: &gnmi.TypedValue_IntVal{IntVal: -1}},
					{Value: &gnmi.TypedValue_UintVal{UintVal: 2}},
					{Value: &gnmi.TypedValue_BoolVal{BoolVal: false}},
					{Value: &gnmi.TypedValue_FloatVal{FloatVal: 1.5}},
					{Value: &gnmi.TypedValue_DoubleVal{DoubleVal: 2.25}},
				}}}},
			},
			{Path: mustParseIOSXRPath(t, "legacy-json"), Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonVal{JsonVal: []byte(`{"count":3}`)}}},
			{Path: mustParseIOSXRPath(t, "opaque"), Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_BytesVal{BytesVal: []byte{0xde, 0xad}}}},
			{Path: mustParseIOSXRPath(t, "compact"), Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_ProtoBytes{ProtoBytes: []byte{0x01, 0x02}}}},
			{Path: mustParseIOSXRPath(t, "envelope"), Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_AnyVal{AnyVal: &anypb.Any{TypeUrl: "type.googleapis.com/example.Telemetry", Value: []byte{0x01}}}}},
		},
	}, catalyst9800TelemetryTransportDialIn)

	const prefix = "cisco.catalyst9800.yang.wireless_access_point_oper.access_point_oper_data."
	assertInfoMetricValue(t, md, prefix+"ascii_value_info", "legacy")
	assertGaugeIntMetricValue(t, md, prefix+"signed_value", -7)
	assertGaugeIntMetricValue(t, md, prefix+"disabled", 0)
	assertGaugeDoubleMetricValue(t, md, prefix+"float_value", 1.5)
	assertGaugeDoubleMetricValue(t, md, prefix+"double_value", 2.25)
	assertGaugeDoubleMetricValue(t, md, prefix+"decimal_value", 123.45)
	assertInfoMetricValue(t, md, prefix+"mixed_leaf_list_info", "text,ascii,-1,2,false,1.5,2.25")
	assertMetricExists(t, md, prefix+"legacy_json.count")
	assertInfoMetricValue(t, md, prefix+"opaque.bytes_info", "dead")
	envelope := mustFindIOSXRMetric(t, md, prefix+"envelope.any_info")
	envelopeValue := attrValue(t, envelope.Gauge().DataPoints().At(0).Attributes(), "value")
	assert.Contains(t, envelopeValue, "type.googleapis.com/example.Telemetry")
	assertMetricExists(t, md, "cisco.catalyst9800.receiver.compact_gpb_payloads")
	assert.Equal(t, int64(1), health.snapshot().compactGPBPayloads)
	assert.Zero(t, health.snapshot().decodeErrors)
	assert.Zero(t, health.snapshot().droppedDatapoints)
}

//nolint:staticcheck // Cisco devices still emit deprecated gNMI Decimal64 values, including malformed boundary cases.
func TestCatalyst9800GNMIDecoderRejectsMalformedTypedValues(t *testing.T) {
	tests := []struct {
		name  string
		value *gnmi.TypedValue
	}{
		{name: "missing typed value"},
		{name: "empty typed value", value: &gnmi.TypedValue{}},
		{name: "nil Decimal64", value: &gnmi.TypedValue{Value: &gnmi.TypedValue_DecimalVal{}}},
		{name: "Decimal64 precision 309", value: &gnmi.TypedValue{Value: &gnmi.TypedValue_DecimalVal{DecimalVal: &gnmi.Decimal64{Digits: 1, Precision: 309}}}},
		{name: "nil leaf list", value: &gnmi.TypedValue{Value: &gnmi.TypedValue_LeaflistVal{}}},
		{name: "nil Any", value: &gnmi.TypedValue{Value: &gnmi.TypedValue_AnyVal{}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			health := &catalyst9800Health{}
			decoder := catalyst9800GNMIUpdateDecoder{target: Catalyst9800TargetConfig{Name: "wlc-1"}, health: health}
			md := decoder.decodeNotification(&gnmi.Notification{
				Prefix: mustParseIOSXRPath(t, "wireless-access-point-oper:access-point-oper-data"),
				Update: []*gnmi.Update{{
					Path: mustParseIOSXRPath(t, "invalid-value"),
					Val:  tt.value,
				}},
			}, catalyst9800TelemetryTransportDialIn)

			assert.Zero(t, metricCountNamed(md, "cisco.catalyst9800.yang.wireless_access_point_oper.access_point_oper_data.invalid_value"))
			assert.Equal(t, int64(1), health.snapshot().decodeErrors)
			assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
			assertMetricExists(t, md, "cisco.catalyst9800.receiver.decode_errors")
			assertMetricExists(t, md, "cisco.catalyst9800.receiver.dropped_datapoints")
		})
	}
}

func TestCatalyst9800GNMIDecoderInvalidJSONCountsDecodeErrors(t *testing.T) {
	health := &catalyst9800Health{}
	decoder := catalyst9800GNMIUpdateDecoder{target: Catalyst9800TargetConfig{Name: "wlc-1"}, health: health}
	md := decoder.decodeNotification(&gnmi.Notification{
		Prefix: mustParseIOSXRPath(t, "wireless-access-point-oper:access-point-oper-data/ssid-counters"),
		Update: []*gnmi.Update{{
			Path: mustParseIOSXRPath(t, "bad-json"),
			Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{"unterminated"`)}},
		}},
	}, catalyst9800TelemetryTransportDialIn)

	assert.Equal(t, int64(1), health.snapshot().decodeErrors)
	assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
	assertMetricExists(t, md, "cisco.catalyst9800.receiver.decode_errors")
	assertMetricExists(t, md, "cisco.catalyst9800.receiver.dropped_datapoints")
}

func TestCatalyst9800GNMIDecoderBoundsAdversarialJSON(t *testing.T) {
	t.Run("many leaves stop at datapoint budget", func(t *testing.T) {
		health := &catalyst9800Health{}
		decoder := catalyst9800GNMIUpdateDecoder{
			target:        Catalyst9800TargetConfig{Name: "wlc-1"},
			health:        health,
			maxDatapoints: 5,
		}
		md := decoder.decodeNotification(&gnmi.Notification{
			Prefix: mustParseIOSXRPath(t, "wireless-access-point-oper:access-point-oper-data"),
			Update: []*gnmi.Update{{
				Path: mustParseIOSXRPath(t, "wide"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: manyLeafJSON(t, 1_000)}},
			}},
		}, catalyst9800TelemetryTransportDialIn)

		assert.Equal(t, 5, directTelemetryDataPointCount(md))
		assert.Positive(t, health.snapshot().droppedDatapoints)
		assert.Zero(t, health.snapshot().decodeErrors)
		assertMetricExists(t, md, "cisco.catalyst9800.receiver.dropped_datapoints")
	})

	t.Run("excessive depth is dropped before append", func(t *testing.T) {
		health := &catalyst9800Health{}
		decoder := catalyst9800GNMIUpdateDecoder{
			target: Catalyst9800TargetConfig{Name: "wlc-1"},
			health: health,
			limits: directGNMIDecodeLimits{maxDepth: 4},
		}
		md := decoder.decodeNotification(&gnmi.Notification{
			Prefix: mustParseIOSXRPath(t, "wireless-access-point-oper:access-point-oper-data"),
			Update: []*gnmi.Update{{
				Path: mustParseIOSXRPath(t, "deep"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: deeplyNestedJSON(t, 32)}},
			}},
		}, catalyst9800TelemetryTransportDialIn)

		assert.Zero(t, directTelemetryDataPointCount(md))
		assert.Positive(t, health.snapshot().droppedDatapoints)
		assert.Zero(t, health.snapshot().decodeErrors)
	})

	t.Run("oversized object key is rejected before nested identity hashing", func(t *testing.T) {
		hugeKey := strings.Repeat("x", directGNMIHardMaxMetricNameBytes+1)
		raw, err := json.Marshal(map[string]any{
			"name":  "outer",
			hugeKey: map[string]any{"name": "inner", "value": 1},
		})
		require.NoError(t, err)
		health := &catalyst9800Health{}
		decoder := catalyst9800GNMIUpdateDecoder{target: Catalyst9800TargetConfig{Name: "wlc-1"}, health: health}
		md := decoder.decodeNotification(&gnmi.Notification{
			Prefix: mustParseIOSXRPath(t, "wireless-access-point-oper:access-point-oper-data"),
			Update: []*gnmi.Update{{
				Path: mustParseIOSXRPath(t, "json"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: raw}},
			}},
		}, catalyst9800TelemetryTransportDialIn)

		assert.Equal(t, 1, directTelemetryDataPointCount(md), "only the bounded sibling may be emitted")
		assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
	})
}

func TestCatalyst9800JSONIdentityUsesExplicitDeterministicPrecedence(t *testing.T) {
	value := map[string]any{
		"wtp-mac":        "preferred-ap",
		"ap-mac":         "fallback-ap",
		"ap-name":        "AP-01",
		"slot-id":        "preferred-slot",
		"radio-slot-id":  "fallback-slot",
		"wlan-id":        "42",
		"ssid":           "preferred-ssid",
		"vap-ssid":       "fallback-ssid",
		"client-mac":     "preferred-client",
		"ms-mac-address": "fallback-client",
		"node-ip":        "192.0.2.10",
		"ap-ip":          "192.0.2.11",
		"ip-addr":        "192.0.2.12",
		"serial-num":     "preferred-serial",
		"serial-number":  "fallback-serial",
	}
	wantSemantic := map[string]string{
		"cisco.wlc.ap.mac":           "preferred-ap",
		"cisco.wlc.ap.name":          "AP-01",
		"cisco.wlc.radio.slot":       "preferred-slot",
		"cisco.wlc.wlan.id":          "42",
		"cisco.wlc.ssid":             "preferred-ssid",
		"cisco.wlc.client.mac":       "preferred-client",
		"cisco.wlc.mobility.node_ip": "192.0.2.10",
		"host.ip":                    "192.0.2.11",
		"hw.serial_number":           "preferred-serial",
	}

	var baseline map[string]string
	for iteration := range 100 {
		attrs := map[string]string{}
		budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
		require.True(t, extractCatalyst9800JSONIdentityAttrs(value, attrs, budget, nil))
		for key, expected := range wantSemantic {
			assert.Equal(t, expected, attrs[key])
		}
		for key, raw := range value {
			assert.Equal(t, raw, attrs["cisco.yang.key."+sanitizeMetricSegment(key)])
		}
		if iteration == 0 {
			baseline = attrs
		} else {
			assert.Equal(t, baseline, attrs)
		}
		assert.Zero(t, budget.dropped)
	}

	t.Run("present empty canonical identity wins over fallback", func(t *testing.T) {
		attrs := map[string]string{}
		budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
		require.True(t, extractCatalyst9800JSONIdentityAttrs(map[string]any{
			"wtp-mac": "",
			"ap-mac":  "fallback-must-not-win",
		}, attrs, budget, nil))
		for _, key := range []string{"cisco.yang.key.wtp_mac", "cisco.wlc.ap.mac"} {
			value, present := attrs[key]
			assert.True(t, present)
			assert.Empty(t, value)
		}
		assert.Equal(t, "fallback-must-not-win", attrs["cisco.yang.key.ap_mac"])
	})
}

func TestCatalyst9800GNMIPathNormalizationPreservesRawSourceIdentity(t *testing.T) {
	health := &catalyst9800Health{}
	decoder := catalyst9800GNMIUpdateDecoder{target: Catalyst9800TargetConfig{Name: "wlc-1"}, health: health}
	md := decoder.decodeNotification(&gnmi.Notification{
		Prefix: mustParseIOSXRPath(t, "wireless-rrm-oper:rrm-oper-data/state"),
		Update: []*gnmi.Update{
			{Path: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "foo-bar"}}}, Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_IntVal{IntVal: 1}}},
			{Path: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "foo_bar"}}}, Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_IntVal{IntVal: 2}}},
		},
	}, catalyst9800TelemetryTransportDialIn)

	metric := mustFindIOSXRMetric(t, md, "cisco.catalyst9800.yang.wireless_rrm_oper.rrm_oper_data.state.foo_bar")
	dps := metric.Gauge().DataPoints()
	require.Equal(t, 2, dps.Len())
	paths := map[string]struct{}{}
	for index := 0; index < dps.Len(); index++ {
		paths[attrValue(t, dps.At(index).Attributes(), "cisco.yang.path")] = struct{}{}
	}
	assert.Equal(t, map[string]struct{}{
		"wireless-rrm-oper:rrm-oper-data/state/foo-bar": {},
		"wireless-rrm-oper:rrm-oper-data/state/foo_bar": {},
	}, paths)
	assert.Zero(t, health.snapshot().droppedDatapoints)
}

func TestCatalyst9800GNMIJSONRejectsAmbiguousUnrecognizedListIdentity(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
	}{
		{
			name: "two unrecognized entries",
			raw:  `{"items":[{"tenant-code":"blue","value":1},{"tenant-code":"red","value":2}]}`,
		},
		{
			name: "recognized and unrecognized entries",
			raw:  `{"items":[{"name":"known","value":1},{"tenant-code":"anonymous","value":2}]}`,
		},
		{
			name: "duplicate recognized identities",
			raw:  `{"items":[{"name":"duplicate","value":1},{"name":"duplicate","value":2}]}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			health := &catalyst9800Health{}
			decoder := catalyst9800GNMIUpdateDecoder{target: Catalyst9800TargetConfig{Name: "wlc-1"}, health: health}
			md := decoder.decodeNotification(&gnmi.Notification{
				Prefix: mustParseIOSXRPath(t, "wireless-rrm-oper:rrm-oper-data/state"),
				Update: []*gnmi.Update{{
					Path: mustParseIOSXRPath(t, "json"),
					Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(test.raw)}},
				}},
			}, catalyst9800TelemetryTransportDialIn)

			assert.Zero(t, directTelemetryDataPointCount(md))
			assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
		})
	}
}

func TestCatalyst9800GNMIDecoderRejectsPathElementWithoutMetricIdentity(t *testing.T) {
	health := &catalyst9800Health{}
	decoder := catalyst9800GNMIUpdateDecoder{target: Catalyst9800TargetConfig{Name: "wlc-1"}, health: health}
	md := decoder.decodeNotification(&gnmi.Notification{
		Prefix: mustParseIOSXRPath(t, "wireless-rrm-oper:rrm-oper-data/state"),
		Update: []*gnmi.Update{{
			Path: &gnmi.Path{Elem: []*gnmi.PathElem{
				{Name: "---", Key: map[string]string{"name": "must-not-disappear"}},
				{Name: "value"},
			}},
			Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_IntVal{IntVal: 1}},
		}},
	}, catalyst9800TelemetryTransportDialIn)
	assert.Zero(t, directTelemetryDataPointCount(md))
	assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
}

func TestCatalyst9800JSONIdentityAttributeCountBoundary(t *testing.T) {
	value := map[string]any{"wtp-mac": "AA:BB:CC:DD:EE:FF"}
	atLimit := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributes: 2}, 10)
	attrs := map[string]string{}
	require.True(t, extractCatalyst9800JSONIdentityAttrs(value, attrs, atLimit, nil))
	assert.Equal(t, map[string]string{
		"cisco.yang.key.wtp_mac": "AA:BB:CC:DD:EE:FF",
		"cisco.wlc.ap.mac":       "AA:BB:CC:DD:EE:FF",
	}, attrs)

	overLimit := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributes: 1}, 10)
	assert.False(t, extractCatalyst9800JSONIdentityAttrs(value, map[string]string{}, overLimit, nil))
	assert.Equal(t, int64(1), overLimit.dropped)
}

func TestCatalyst9800GNMINestedJSONPreservesOuterAndInnerIdentity(t *testing.T) {
	decoder := catalyst9800GNMIUpdateDecoder{target: Catalyst9800TargetConfig{Name: "wlc-1"}, health: &catalyst9800Health{}}
	md := decoder.decodeNotification(&gnmi.Notification{
		Prefix: mustParseIOSXRPath(t, "wireless-access-point-oper:access-point-oper-data"),
		Update: []*gnmi.Update{{
			Path: mustParseIOSXRPath(t, "json"),
			Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{
				"aps": [
					{"wtp-mac":"AA:AA:AA:AA:AA:AA","radios":[{"wtp-mac":"CC:CC:CC:CC:CC:CC","load":1}]},
					{"wtp-mac":"BB:BB:BB:BB:BB:BB","radios":[{"wtp-mac":"CC:CC:CC:CC:CC:CC","load":1}]}
				]
			}`)}},
		}},
	}, catalyst9800TelemetryTransportDialIn)

	metric := mustFindIOSXRMetric(t, md, "cisco.catalyst9800.yang.wireless_access_point_oper.access_point_oper_data.json.aps.radios.load")
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	dps := metric.Gauge().DataPoints()
	require.Equal(t, 2, dps.Len())
	const nestedRaw = "cisco.yang.key.json.access_point_oper_data.json.aps.radios.cisco_yang_key_wtp_mac"
	const nestedSemantic = "cisco.yang.key.json.access_point_oper_data.json.aps.radios.cisco_wlc_ap_mac"
	outerMACs := map[string]struct{}{}
	for index := 0; index < dps.Len(); index++ {
		attrs := dps.At(index).Attributes()
		outerMAC := attrValue(t, attrs, "cisco.yang.key.wtp_mac")
		outerMACs[outerMAC] = struct{}{}
		assert.Equal(t, outerMAC, attrValue(t, attrs, "cisco.wlc.ap.mac"))
		assert.Equal(t, "CC:CC:CC:CC:CC:CC", attrValue(t, attrs, nestedRaw))
		assert.Equal(t, "CC:CC:CC:CC:CC:CC", attrValue(t, attrs, nestedSemantic))
	}
	assert.Equal(t, map[string]struct{}{
		"AA:AA:AA:AA:AA:AA": {},
		"BB:BB:BB:BB:BB:BB": {},
	}, outerMACs)
}

func TestCatalyst9800GNMIDecoderRecreationDoesNotAdvanceCounterEpoch(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	tracked := newAbsoluteCounterTrackingConsumer(sink)
	times := []time.Time{time.Unix(100, 0), time.Unix(200, 0)}
	values := []uint64{100, 150}

	for i := range times {
		// recvLoop constructs a new decoder after every reconnect. Counter epoch
		// state belongs to the receiver-level tracking consumer, not this decoder.
		decoder := catalyst9800GNMIUpdateDecoder{
			target: Catalyst9800TargetConfig{Name: "wlc-1"},
			health: &catalyst9800Health{},
		}
		md := decoder.decodeNotification(&gnmi.Notification{
			Timestamp: times[i].UnixNano(),
			Prefix:    mustParseIOSXRPath(t, "wireless-access-point-oper:access-point-oper-data"),
			Update: []*gnmi.Update{{
				Path: catalyst9800SSIDCounterPath("AA:BB:CC:DD:EE:FF", "tx-bytes-data"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_UintVal{UintVal: values[i]}},
			}},
		}, catalyst9800TelemetryTransportDialIn)
		require.NoError(t, tracked.ConsumeMetrics(t.Context(), md))
	}

	require.Len(t, sink.AllMetrics(), 2)
	const metricName = "cisco.catalyst9800.yang.wireless_access_point_oper.access_point_oper_data.ssid_counters.tx_bytes_data"
	for _, md := range sink.AllMetrics() {
		dp := mustFindIOSXRMetric(t, md, metricName).Sum().DataPoints().At(0)
		assert.True(t, times[0].Equal(dp.StartTimestamp().AsTime()))
	}
}

func catalyst9800JSONNotification(t *testing.T, prefix, updatePath, body string) *gnmi.Notification {
	t.Helper()
	return &gnmi.Notification{
		Timestamp: time.Unix(1700000000, 0).UnixNano(),
		Prefix:    mustParseIOSXRPath(t, prefix),
		Update: []*gnmi.Update{{
			Path: mustParseIOSXRPath(t, updatePath),
			Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(body)}},
		}},
	}
}

func catalyst9800SSIDCounterPath(apMAC, leaf string) *gnmi.Path {
	return &gnmi.Path{Elem: []*gnmi.PathElem{
		{
			Name: "ssid-counters",
			Key: map[string]string{
				"wtp-mac": apMAC,
				"slot-id": "0",
				"wlan-id": "42",
			},
		},
		{Name: leaf},
	}}
}

func assertCatalyst9800IntDatapointsByAP(t *testing.T, metric pmetric.Metric, expected map[string]int64) {
	t.Helper()
	require.Equal(t, pmetric.MetricTypeSum, metric.Type())
	dps := metric.Sum().DataPoints()
	require.Equal(t, len(expected), dps.Len())
	actual := make(map[string]int64, dps.Len())
	for i := 0; i < dps.Len(); i++ {
		dp := dps.At(i)
		assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
		actual[attrValue(t, dp.Attributes(), "cisco.wlc.ap.mac")] = dp.IntValue()
	}
	assert.Equal(t, expected, actual)
}

func mustCatalyst9800ClientConfig(endpoint string) configgrpc.ClientConfig {
	cfg := configgrpc.NewDefaultClientConfig()
	cfg.Endpoint = endpoint
	cfg.TLS.Insecure = true
	return cfg
}
