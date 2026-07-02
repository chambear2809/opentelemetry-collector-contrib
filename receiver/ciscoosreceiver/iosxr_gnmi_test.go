// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"encoding/json"
	"fmt"
	"math"
	"testing"
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

func TestIOSXRGNMIDecoderScalarsJSONLeaflistsAndDeletes(t *testing.T) {
	prefix := mustParseIOSXRPath(t, "openconfig-interfaces:interfaces/interface[name=HundredGigE0/0/0/0]/state")
	health := &iosXRHealth{}
	decoder := iosXRGNMIUpdateDecoder{
		target: IOSXRTargetConfig{
			ClientConfig:   mustIOSXRClientConfig("192.0.2.10:57400"),
			Name:           "core-asr9k-1",
			PlatformFamily: "ASR 9000",
		},
		health: health,
	}

	md := decoder.decodeNotification(&gnmi.Notification{
		Timestamp: time.Unix(1700000000, 0).UnixNano(),
		Prefix:    prefix,
		Delete: []*gnmi.Path{
			mustParseIOSXRPath(t, "oper-status"),
		},
		Update: []*gnmi.Update{
			{
				Path: mustParseIOSXRPath(t, "counters/in-octets"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_UintVal{UintVal: 42}},
			},
			{
				Path: mustParseIOSXRPath(t, "admin-status"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_StringVal{StringVal: "UP"}},
			},
			{
				Path: mustParseIOSXRPath(t, "enabled"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_BoolVal{BoolVal: true}},
			},
			{
				Path: mustParseIOSXRPath(t, "labels"),
				Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_LeaflistVal{LeaflistVal: &gnmi.ScalarArray{Element: []*gnmi.TypedValue{
					{Value: &gnmi.TypedValue_StringVal{StringVal: "core"}},
					{Value: &gnmi.TypedValue_StringVal{StringVal: "wan"}},
				}}}},
			},
			{
				Path: mustParseIOSXRPath(t, "json"),
				Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{
					"openconfig-interfaces:description": "uplink",
					"mtu": 9216,
					"counters": {"out-octets": 84},
					"openconfig-if-ip:ipv4": {"addresses": {"address": [{"ip": "192.0.2.1"}]}}
				}`)}},
			},
			{
				Path: mustParseIOSXRPath(t, "compact"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_ProtoBytes{ProtoBytes: []byte{0x01, 0x02}}},
			},
		},
	})

	assertMetricExists(t, md, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.counters.in_octets")
	assertMetricExists(t, md, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.enabled")
	assertInfoMetricValue(t, md, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.admin_status_info", "UP")
	assertInfoMetricValue(t, md, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.labels_info", "core,wan")
	assertInfoMetricValue(t, md, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.oper_status_info", "deleted")
	assertInfoMetricValue(t, md, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.json.description_info", "uplink")
	assertMetricExists(t, md, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.json.mtu")
	assertMetricExists(t, md, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.json.counters.out_octets")
	assertInfoMetricValue(t, md, "cisco.iosxr.yang.openconfig_if_ip.interfaces.interface.state.json.ipv4.addresses.address.ip_info", "192.0.2.1")
	assertMetricExists(t, md, "cisco.iosxr.receiver.compact_gpb_payloads")

	metric := mustFindIOSXRMetric(t, md, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.counters.in_octets")
	require.Equal(t, pmetric.MetricTypeSum, metric.Type())
	dp := metric.Sum().DataPoints().At(0)
	assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
	assert.Equal(t, int64(42), dp.IntValue())
	iface, ok := dp.Attributes().Get("network.interface.name")
	require.True(t, ok)
	assert.Equal(t, "HundredGigE0/0/0/0", iface.AsString())

	resourceAttrs := md.ResourceMetrics().At(0).Resource().Attributes()
	assert.Equal(t, "core-asr9k-1", attrValue(t, resourceAttrs, "host.name"))
	assert.Equal(t, []string{"192.0.2.10"}, stringSliceAttrValue(t, resourceAttrs))
	assert.Equal(t, "ios_xr", attrValue(t, resourceAttrs, "cisco.os.name"))
	assert.Equal(t, "gnmi_dial_in", attrValue(t, resourceAttrs, "cisco.telemetry.transport"))
	_, hasResourceModule := resourceAttrs.Get("cisco.yang.module")
	assert.False(t, hasResourceModule)
	assert.Equal(t, "openconfig-interfaces", attrValue(t, dp.Attributes(), "cisco.yang.module"))
	assert.Equal(t, int64(1), health.snapshot().compactGPBPayloads)
}

func TestIOSXRGNMIDecoderCoalescesMetricStreamsAndPreservesUint64(t *testing.T) {
	decoder := iosXRGNMIUpdateDecoder{
		target: IOSXRTargetConfig{Name: "xr-1"},
		health: &iosXRHealth{},
	}

	md := decoder.decodeNotification(&gnmi.Notification{
		Timestamp: time.Unix(1700000000, 0).UnixNano(),
		Prefix:    mustParseIOSXRPath(t, "openconfig-interfaces:interfaces"),
		Update: []*gnmi.Update{
			{
				Path: mustParseIOSXRPath(t, "interface[name=GigabitEthernet0/0]/state/counters/in-octets"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_UintVal{UintVal: math.MaxInt64}},
			},
			{
				Path: mustParseIOSXRPath(t, "interface[name=GigabitEthernet0/1]/state/counters/in-octets"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_UintVal{UintVal: 42}},
			},
			{
				Path: mustParseIOSXRPath(t, "interface[name=GigabitEthernet0/2]/state/counters/out-octets"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_UintVal{UintVal: ^uint64(0)}},
			},
		},
	})

	const inOctets = "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.counters.in_octets"
	assert.Equal(t, 1, metricCountNamed(md, inOctets))
	metric := mustFindIOSXRMetric(t, md, inOctets)
	require.Equal(t, pmetric.MetricTypeSum, metric.Type())
	dps := metric.Sum().DataPoints()
	require.Equal(t, 2, dps.Len())

	values := map[string]int64{}
	for i := 0; i < dps.Len(); i++ {
		dp := dps.At(i)
		assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
		values[attrValue(t, dp.Attributes(), "network.interface.name")] = dp.IntValue()
	}
	assert.Equal(t, int64(math.MaxInt64), values["GigabitEthernet0/0"])
	assert.Equal(t, int64(42), values["GigabitEthernet0/1"])

	const outOctetsInfo = "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.counters.out_octets_info"
	assert.Equal(t, 1, metricCountNamed(md, outOctetsInfo))
	overflow := mustFindIOSXRMetric(t, md, outOctetsInfo)
	require.Equal(t, pmetric.MetricTypeGauge, overflow.Type())
	require.Equal(t, 1, overflow.Gauge().DataPoints().Len())
	overflowDP := overflow.Gauge().DataPoints().At(0)
	assert.Equal(t, "18446744073709551615", attrValue(t, overflowDP.Attributes(), "value"))
	assert.Equal(t, "uint64", attrValue(t, overflowDP.Attributes(), "cisco.value.type"))
	assert.Equal(t, "true", attrValue(t, overflowDP.Attributes(), "cisco.value.out_of_range"))
	assert.Equal(t, "GigabitEthernet0/2", attrValue(t, overflowDP.Attributes(), "network.interface.name"))
}

func TestIOSXRGNMIDecoderInvalidJSONCountsDecodeErrors(t *testing.T) {
	health := &iosXRHealth{}
	decoder := iosXRGNMIUpdateDecoder{target: IOSXRTargetConfig{Name: "xr-1"}, health: health}
	md := decoder.decodeNotification(&gnmi.Notification{
		Prefix: mustParseIOSXRPath(t, "openconfig-system:system/state"),
		Update: []*gnmi.Update{{
			Path: mustParseIOSXRPath(t, "bad-json"),
			Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{"unterminated"`)}},
		}},
	})

	assert.Equal(t, int64(1), health.snapshot().decodeErrors)
	assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
	assertMetricExists(t, md, "cisco.iosxr.receiver.decode_errors")
	assertMetricExists(t, md, "cisco.iosxr.receiver.dropped_datapoints")
}

func TestIOSXRGNMIDecoderBoundsAdversarialJSON(t *testing.T) {
	t.Run("many leaves stop at datapoint budget", func(t *testing.T) {
		health := &iosXRHealth{}
		decoder := iosXRGNMIUpdateDecoder{
			target:        IOSXRTargetConfig{Name: "xr-1"},
			health:        health,
			maxDatapoints: 5,
		}
		md := decoder.decodeNotification(&gnmi.Notification{
			Prefix: mustParseIOSXRPath(t, "openconfig-system:system/state"),
			Update: []*gnmi.Update{{
				Path: mustParseIOSXRPath(t, "wide"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: manyLeafJSON(t, 1_000)}},
			}},
		})

		assert.Equal(t, 5, directTelemetryDataPointCount(md))
		assert.Positive(t, health.snapshot().droppedDatapoints)
		assert.Zero(t, health.snapshot().decodeErrors)
		assertMetricExists(t, md, "cisco.iosxr.receiver.dropped_datapoints")
	})

	t.Run("excessive depth is dropped before append", func(t *testing.T) {
		health := &iosXRHealth{}
		decoder := iosXRGNMIUpdateDecoder{
			target: IOSXRTargetConfig{Name: "xr-1"},
			health: health,
			limits: directGNMIDecodeLimits{maxDepth: 4},
		}
		md := decoder.decodeNotification(&gnmi.Notification{
			Prefix: mustParseIOSXRPath(t, "openconfig-system:system/state"),
			Update: []*gnmi.Update{{
				Path: mustParseIOSXRPath(t, "deep"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: deeplyNestedJSON(t, 32)}},
			}},
		})

		assert.Zero(t, directTelemetryDataPointCount(md))
		assert.Positive(t, health.snapshot().droppedDatapoints)
		assert.Zero(t, health.snapshot().decodeErrors)
	})
}

func TestIOSXRGNMIDecoderRecreationDoesNotAdvanceCounterEpoch(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	tracked := newAbsoluteCounterTrackingConsumer(sink)
	times := []time.Time{time.Unix(100, 0), time.Unix(200, 0)}
	values := []uint64{100, 150}

	for i := range times {
		// recvLoop constructs a new decoder after every reconnect. Counter epoch
		// state belongs to the receiver-level tracking consumer, not this decoder.
		decoder := iosXRGNMIUpdateDecoder{
			target: IOSXRTargetConfig{Name: "xr-1"},
			health: &iosXRHealth{},
		}
		md := decoder.decodeNotification(&gnmi.Notification{
			Timestamp: times[i].UnixNano(),
			Prefix:    mustParseIOSXRPath(t, "openconfig-interfaces:interfaces/interface[name=GigabitEthernet0/0]/state"),
			Update: []*gnmi.Update{{
				Path: mustParseIOSXRPath(t, "counters/in-octets"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_UintVal{UintVal: values[i]}},
			}},
		})
		require.NoError(t, tracked.ConsumeMetrics(t.Context(), md))
	}

	require.Len(t, sink.AllMetrics(), 2)
	const metricName = "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.counters.in_octets"
	for _, md := range sink.AllMetrics() {
		dp := mustFindIOSXRMetric(t, md, metricName).Sum().DataPoints().At(0)
		assert.True(t, times[0].Equal(dp.StartTimestamp().AsTime()))
	}
}

func mustParseIOSXRPath(t *testing.T, raw string) *gnmi.Path {
	t.Helper()
	path, err := parseGNMIPath(raw)
	require.NoError(t, err)
	return path
}

func assertMetricExists(t *testing.T, md pmetric.Metrics, name string) {
	t.Helper()
	_ = mustFindIOSXRMetric(t, md, name)
}

func assertInfoMetricValue(t *testing.T, md pmetric.Metrics, name, value string) {
	t.Helper()
	metric := mustFindIOSXRMetric(t, md, name)
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	require.Equal(t, 1, metric.Gauge().DataPoints().Len())
	got, ok := metric.Gauge().DataPoints().At(0).Attributes().Get("value")
	require.True(t, ok)
	assert.Equal(t, value, got.AsString())
}

func mustFindIOSXRMetric(t *testing.T, md pmetric.Metrics, name string) pmetric.Metric {
	t.Helper()
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		sms := md.ResourceMetrics().At(i).ScopeMetrics()
		for j := 0; j < sms.Len(); j++ {
			metrics := sms.At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				if metrics.At(k).Name() == name {
					return metrics.At(k)
				}
			}
		}
	}
	require.FailNowf(t, "metric not found", "missing metric %s", name)
	return pmetric.Metric{}
}

func metricCountNamed(md pmetric.Metrics, name string) int {
	count := 0
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		sms := md.ResourceMetrics().At(i).ScopeMetrics()
		for j := 0; j < sms.Len(); j++ {
			metrics := sms.At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				if metrics.At(k).Name() == name {
					count++
				}
			}
		}
	}
	return count
}

func directTelemetryDataPointCount(md pmetric.Metrics) int {
	if md.ResourceMetrics().Len() == 0 {
		return 0
	}
	count := 0
	sms := md.ResourceMetrics().At(0).ScopeMetrics()
	for i := 0; i < sms.Len(); i++ {
		metrics := sms.At(i).Metrics()
		for j := 0; j < metrics.Len(); j++ {
			switch metrics.At(j).Type() {
			case pmetric.MetricTypeGauge:
				count += metrics.At(j).Gauge().DataPoints().Len()
			case pmetric.MetricTypeSum:
				count += metrics.At(j).Sum().DataPoints().Len()
			}
		}
	}
	return count
}

func manyLeafJSON(t *testing.T, count int) []byte {
	t.Helper()
	value := make(map[string]any, count)
	for i := range count {
		value[fmt.Sprintf("field-%06d", i)] = i
	}
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	return raw
}

func deeplyNestedJSON(t *testing.T, depth int) []byte {
	t.Helper()
	var value any = 1
	for range depth {
		value = map[string]any{"level": value}
	}
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	return raw
}

func attrValue(t *testing.T, attrs pcommon.Map, key string) string {
	t.Helper()
	value, ok := attrs.Get(key)
	require.True(t, ok, "missing attribute %s", key)
	return value.AsString()
}

func stringSliceAttrValue(t *testing.T, attrs pcommon.Map) []string {
	t.Helper()
	value, ok := attrs.Get("host.ip")
	require.True(t, ok, "missing attribute host.ip")
	require.Equal(t, pcommon.ValueTypeSlice, value.Type())
	values := value.Slice()
	result := make([]string, 0, values.Len())
	for i := 0; i < values.Len(); i++ {
		require.Equal(t, pcommon.ValueTypeStr, values.At(i).Type())
		result = append(result, values.At(i).Str())
	}
	return result
}

func mustIOSXRClientConfig(endpoint string) configgrpc.ClientConfig {
	cfg := configgrpc.NewDefaultClientConfig()
	cfg.Endpoint = endpoint
	cfg.TLS.Insecure = true
	return cfg
}
