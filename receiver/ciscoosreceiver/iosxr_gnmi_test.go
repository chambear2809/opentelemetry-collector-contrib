// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"google.golang.org/protobuf/types/known/anypb"
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
	}, iosXRTelemetryTransportDialIn)

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
	}, iosXRTelemetryTransportDialIn)

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

//nolint:staticcheck // Cisco devices still emit deprecated gNMI Decimal64 values, including malformed boundary cases.
func TestIOSXRGNMIDecoderTypedValueBranches(t *testing.T) {
	health := &iosXRHealth{}
	decoder := iosXRGNMIUpdateDecoder{target: IOSXRTargetConfig{Name: "xr-1"}, health: health}
	md := decoder.decodeNotification(&gnmi.Notification{
		Prefix: mustParseIOSXRPath(t, "openconfig-system:system/state"),
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
			{Path: mustParseIOSXRPath(t, "envelope"), Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_AnyVal{AnyVal: &anypb.Any{TypeUrl: "type.googleapis.com/example.Telemetry", Value: []byte{0x01}}}}},
		},
	}, iosXRTelemetryTransportDialIn)

	const prefix = "cisco.iosxr.yang.openconfig_system.system.state."
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
	assert.Zero(t, health.snapshot().decodeErrors)
	assert.Zero(t, health.snapshot().droppedDatapoints)
}

//nolint:staticcheck // Cisco devices still emit deprecated gNMI Decimal64 values, including malformed boundary cases.
func TestIOSXRGNMIDecoderRejectsMalformedTypedValues(t *testing.T) {
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
			health := &iosXRHealth{}
			decoder := iosXRGNMIUpdateDecoder{target: IOSXRTargetConfig{Name: "xr-1"}, health: health}
			md := decoder.decodeNotification(&gnmi.Notification{
				Prefix: mustParseIOSXRPath(t, "openconfig-system:system/state"),
				Update: []*gnmi.Update{{
					Path: mustParseIOSXRPath(t, "invalid-value"),
					Val:  tt.value,
				}},
			}, iosXRTelemetryTransportDialIn)

			assert.Zero(t, metricCountNamed(md, "cisco.iosxr.yang.openconfig_system.system.state.invalid_value"))
			assert.Equal(t, int64(1), health.snapshot().decodeErrors)
			assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
			assertMetricExists(t, md, "cisco.iosxr.receiver.decode_errors")
			assertMetricExists(t, md, "cisco.iosxr.receiver.dropped_datapoints")
		})
	}
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
	}, iosXRTelemetryTransportDialIn)

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
		}, iosXRTelemetryTransportDialIn)

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
		}, iosXRTelemetryTransportDialIn)

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
		health := &iosXRHealth{}
		decoder := iosXRGNMIUpdateDecoder{target: IOSXRTargetConfig{Name: "xr-1"}, health: health}
		md := decoder.decodeNotification(&gnmi.Notification{
			Prefix: mustParseIOSXRPath(t, "openconfig-system:system/state"),
			Update: []*gnmi.Update{{
				Path: mustParseIOSXRPath(t, "json"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: raw}},
			}},
		}, iosXRTelemetryTransportDialIn)

		assert.Equal(t, 1, directTelemetryDataPointCount(md), "only the bounded sibling may be emitted")
		assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
	})
}

func TestDirectGNMIPathIdentityIsDeterministicAndCollisionSafe(t *testing.T) {
	prefix := &gnmi.Path{Elem: []*gnmi.PathElem{{
		Name: "list",
		Key: map[string]string{
			"2.foo-bar":        "numbered-base",
			"empty-key":        "",
			"foo-bar":          "hyphen",
			"foo_bar":          "underscore",
			"interface":        "GigabitEthernet-fallback",
			"interface-name":   "TenGigE-preferred",
			"neighbor":         "192.0.2.2",
			"neighbor-address": "192.0.2.1",
			"vrf":              "fallback-vrf",
			"vrf-name":         "preferred-vrf",
		},
	}}}
	update := &gnmi.Path{Elem: []*gnmi.PathElem{
		{Name: "list", Key: map[string]string{"empty-key": "", "foo-bar": "hyphen-middle", "interface-name": "HundredGigE-middle"}},
		{Name: "list", Key: map[string]string{"empty-key": "", "foo-bar": "hyphen-inner", "interface-name": "FortyGigE-inner"}},
	}}
	want := map[string]string{
		"cisco.yang.key.2_foo_bar":                                  "numbered-base",
		"cisco.yang.key.empty_key":                                  "",
		"cisco.yang.key.foo_bar":                                    "hyphen",
		"cisco.yang.key.2.foo_bar":                                  "underscore",
		"cisco.yang.key.interface":                                  "GigabitEthernet-fallback",
		"cisco.yang.key.interface_name":                             "TenGigE-preferred",
		"cisco.yang.key.neighbor":                                   "192.0.2.2",
		"cisco.yang.key.neighbor_address":                           "192.0.2.1",
		"cisco.yang.key.vrf":                                        "fallback-vrf",
		"cisco.yang.key.vrf_name":                                   "preferred-vrf",
		"network.interface.name":                                    "TenGigE-preferred",
		"network.peer.address":                                      "192.0.2.1",
		"network.vrf.name":                                          "preferred-vrf",
		"cisco.yang.key.path.list.list.network_interface_name":      "HundredGigE-middle",
		"cisco.yang.key.path.list.list.list.network_interface_name": "FortyGigE-inner",
	}
	for _, scoped := range []struct {
		key, value string
		path       []string
	}{
		{key: "empty-key", value: "", path: []string{"list", "list"}},
		{key: "foo-bar", value: "hyphen-middle", path: []string{"list", "list"}},
		{key: "interface-name", value: "HundredGigE-middle", path: []string{"list", "list"}},
		{key: "empty-key", value: "", path: []string{"list", "list", "list"}},
		{key: "foo-bar", value: "hyphen-inner", path: []string{"list", "list", "list"}},
		{key: "interface-name", value: "FortyGigE-inner", path: []string{"list", "list", "list"}},
	} {
		attribute, ok := directGNMIPathKeyIdentityAttributeName(scoped.key, sanitizeMetricSegment(scoped.key), scoped.path, 1, directGNMIHardMaxAttributeKeyBytes)
		require.True(t, ok)
		want[attribute] = scoped.value
	}

	for range 100 {
		budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
		parts, attrs, ok := pathPartsAndAttrs(prefix, update, budget)
		require.True(t, ok)
		assert.Equal(t, []string{"list", "list", "list"}, parts)
		assert.Equal(t, want, attrs)
		assert.Zero(t, budget.dropped)
	}
}

func TestDirectGNMIPathIdentityCollisionBoundaries(t *testing.T) {
	path := func(values map[string]string) *gnmi.Path {
		return &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "list", Key: values}}}
	}

	t.Run("attribute count", func(t *testing.T) {
		values := map[string]string{"foo-bar": "one", "foo_bar": "two"}
		atLimit := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributes: 2}, 10)
		_, attrs, ok := pathPartsAndAttrs(path(values), nil, atLimit)
		require.True(t, ok)
		assert.Len(t, attrs, 2)

		overLimit := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributes: 1}, 10)
		_, _, ok = pathPartsAndAttrs(path(values), nil, overLimit)
		assert.False(t, ok)
		assert.Equal(t, int64(1), overLimit.dropped)
	})

	t.Run("escaped key length", func(t *testing.T) {
		maxKeyBytes := len("cisco.yang.key.foo_bar")
		budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributeKeyBytes: maxKeyBytes}, 10)
		_, attrs, ok := pathPartsAndAttrs(path(map[string]string{"foo-bar": "one", "foo_bar": "two"}), nil, budget)
		require.True(t, ok, "a compact numbered fallback must preserve the collision when the full numbered name does not fit")
		assert.Equal(t, "one", attrs["cisco.yang.key.foo_bar"])
		assert.Equal(t, "two", attrs["cisco.yang.key.2"])
		assert.Zero(t, budget.dropped)
	})

	t.Run("value length", func(t *testing.T) {
		atLimit := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributeValueBytes: 4}, 10)
		_, attrs, ok := pathPartsAndAttrs(path(map[string]string{"key": "1234"}), nil, atLimit)
		require.True(t, ok)
		assert.Equal(t, "1234", attrs["cisco.yang.key.key"])

		overLimit := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributeValueBytes: 4}, 10)
		_, _, ok = pathPartsAndAttrs(path(map[string]string{"key": "12345"}), nil, overLimit)
		assert.False(t, ok)
		assert.Equal(t, int64(1), overLimit.dropped)
	})

	t.Run("deep repeated key uses compact deterministic escape", func(t *testing.T) {
		elements := make([]*gnmi.PathElem, directGNMIHardMaxDepth)
		elementPath := make([]string, directGNMIHardMaxDepth)
		for index := range elements {
			elements[index] = &gnmi.PathElem{Name: "x"}
			elementPath[index] = "x"
		}
		elements[0].Key = map[string]string{"name": "outer"}
		elements[len(elements)-1].Key = map[string]string{"name": "inner"}
		expected, ok := directGNMIPathKeyIdentityAttributeName("name", "name", elementPath, 1, directGNMIHardMaxAttributeKeyBytes)
		require.True(t, ok)
		require.LessOrEqual(t, len(expected), directGNMIHardMaxAttributeKeyBytes)

		budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
		_, attrs, ok := pathPartsAndAttrs(&gnmi.Path{Elem: elements}, nil, budget)
		require.True(t, ok)
		assert.Equal(t, "outer", attrs["cisco.yang.key.name"])
		assert.Equal(t, "inner", attrs[expected])
		assert.Len(t, attrs, 2)
	})

	t.Run("wide key maps reject before sort", func(t *testing.T) {
		keys := make(map[string]string, 100_000)
		for index := range 100_000 {
			keys[fmt.Sprintf("key-%06d", index)] = ""
		}
		path := &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "list", Key: keys}}}
		formatBudget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
		_, ok := gnmiPathToString(path, formatBudget)
		assert.False(t, ok)
		assert.Zero(t, formatBudget.fields, "prefix rendering must not charge path fields a second time")
		assert.Equal(t, int64(1), formatBudget.dropped)

		budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
		_, _, ok = pathPartsAndAttrs(path, nil, budget)
		assert.False(t, ok)
		assert.Equal(t, 1, budget.fields)
		assert.Equal(t, int64(1), budget.dropped)
	})

	t.Run("oversized path name rejects before key scan", func(t *testing.T) {
		keys := map[string]string{"name": "value"}
		budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
		_, _, ok := pathPartsAndAttrs(&gnmi.Path{Elem: []*gnmi.PathElem{{
			Name: strings.Repeat("x", directGNMIHardMaxMetricNameBytes+1),
			Key:  keys,
		}}}, nil, budget)
		assert.False(t, ok)
		assert.Equal(t, 1, budget.fields)
		assert.Equal(t, int64(1), budget.dropped)
	})

	t.Run("structured elements take precedence over deprecated elements", func(t *testing.T) {
		path := &gnmi.Path{
			Elem:    []*gnmi.PathElem{{Name: "structured", Key: map[string]string{"name": "Ethernet1"}}},
			Element: []string{"deprecated", "must-not-appear"},
		}
		formatBudget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
		formatted, ok := gnmiPathToString(path, formatBudget)
		require.True(t, ok)
		assert.Equal(t, "structured[name=Ethernet1]", formatted)

		budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
		parts, attrs, ok := pathPartsAndAttrs(path, nil, budget)
		require.True(t, ok)
		assert.Equal(t, []string{"structured"}, parts)
		assert.Equal(t, "Ethernet1", attrs["cisco.yang.key.name"])
		assert.Equal(t, 1, budget.fields)
	})

	t.Run("names without a metric identity are rejected", func(t *testing.T) {
		for _, name := range []string{"", " ", "---", "..."} {
			t.Run(fmt.Sprintf("structured-%q", name), func(t *testing.T) {
				path := &gnmi.Path{Elem: []*gnmi.PathElem{
					{Name: "list"},
					{Name: name, Key: map[string]string{"name": "identity-must-not-disappear"}},
					{Name: "value"},
				}}
				formatBudget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
				_, ok := gnmiPathToString(path, formatBudget)
				assert.False(t, ok)
				assert.Equal(t, int64(1), formatBudget.dropped)

				budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
				_, _, ok = pathPartsAndAttrs(path, nil, budget)
				assert.False(t, ok)
				assert.Equal(t, int64(1), budget.dropped)
			})
		}

		legacy := &gnmi.Path{Element: []string{"list", "", "value"}}
		formatBudget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
		_, ok := gnmiPathToString(legacy, formatBudget)
		assert.False(t, ok)
		budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
		_, _, ok = pathPartsAndAttrs(legacy, nil, budget)
		assert.False(t, ok)
	})

	t.Run("normalized collisions at a deep repeated scope hash raw keys once", func(t *testing.T) {
		const collisionCount = 24
		elements := make([]*gnmi.PathElem, 100)
		elementPath := make([]string, len(elements))
		outerKeys := make(map[string]string, collisionCount)
		innerKeys := make(map[string]string, collisionCount)
		for index := range collisionCount {
			key := "foo" + strings.Repeat("!", index+1) + "bar"
			require.Equal(t, "foo_bar", sanitizeMetricSegment(key))
			outerKeys[key] = fmt.Sprintf("outer-%02d", index)
			innerKeys[key] = fmt.Sprintf("inner-%02d", index)
		}
		for index := range elements {
			elements[index] = &gnmi.PathElem{Name: "x"}
			elementPath[index] = "x"
		}
		elements[0].Key = outerKeys
		elements[len(elements)-1].Key = innerKeys

		budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
		_, attrs, ok := pathPartsAndAttrs(&gnmi.Path{Elem: elements}, nil, budget)
		require.True(t, ok)
		assert.Len(t, attrs, collisionCount*2)
		for index := range collisionCount {
			key := "foo" + strings.Repeat("!", index+1) + "bar"
			expected, nameOK := directGNMIPathKeyIdentityAttributeName(key, "foo_bar", elementPath, 1, directGNMIHardMaxAttributeKeyBytes)
			require.True(t, nameOK)
			assert.Equal(t, fmt.Sprintf("inner-%02d", index), attrs[expected])
		}
	})
}

func TestIOSXRGNMIPathPreservesRepeatedListKeyIdentity(t *testing.T) {
	decoder := iosXRGNMIUpdateDecoder{target: IOSXRTargetConfig{Name: "xr-1"}, health: &iosXRHealth{}}
	md := decoder.decodeNotification(&gnmi.Notification{
		Prefix: mustParseIOSXRPath(t, "openconfig-network-instance:network-instances"),
		Update: []*gnmi.Update{
			{
				Path: mustParseIOSXRPath(t, "network-instance[name=blue]/protocols/protocol[name=bgp]/state/enabled"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_BoolVal{BoolVal: true}},
			},
			{
				Path: mustParseIOSXRPath(t, "network-instance[name=red]/protocols/protocol[name=bgp]/state/enabled"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_BoolVal{BoolVal: true}},
			},
		},
	}, iosXRTelemetryTransportDialIn)

	metric := mustFindIOSXRMetric(t, md, "cisco.iosxr.yang.openconfig_network_instance.network_instances.network_instance.protocols.protocol.state.enabled")
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	dps := metric.Gauge().DataPoints()
	require.Equal(t, 2, dps.Len())
	protocolPath := []string{"network-instances", "network-instance", "protocols", "protocol"}
	protocolName, ok := directGNMIPathKeyIdentityAttributeName("name", "name", protocolPath, 1, directGNMIHardMaxAttributeKeyBytes)
	require.True(t, ok)
	outerNames := map[string]struct{}{}
	for index := 0; index < dps.Len(); index++ {
		attrs := dps.At(index).Attributes()
		outerNames[attrValue(t, attrs, "cisco.yang.key.name")] = struct{}{}
		assert.Equal(t, "bgp", attrValue(t, attrs, protocolName))
	}
	assert.Equal(t, map[string]struct{}{"blue": {}, "red": {}}, outerNames)
}

func TestIOSXRGNMIPathNormalizationPreservesRawSourceIdentity(t *testing.T) {
	health := &iosXRHealth{}
	decoder := iosXRGNMIUpdateDecoder{target: IOSXRTargetConfig{Name: "xr-1"}, health: health}
	md := decoder.decodeNotification(&gnmi.Notification{
		Prefix: mustParseIOSXRPath(t, "openconfig-system:system/state"),
		Update: []*gnmi.Update{
			{Path: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "foo-bar"}}}, Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_IntVal{IntVal: 1}}},
			{Path: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "foo_bar"}}}, Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_IntVal{IntVal: 2}}},
		},
	}, iosXRTelemetryTransportDialIn)

	metric := mustFindIOSXRMetric(t, md, "cisco.iosxr.yang.openconfig_system.system.state.foo_bar")
	dps := metric.Gauge().DataPoints()
	require.Equal(t, 2, dps.Len())
	paths := map[string]struct{}{}
	for index := 0; index < dps.Len(); index++ {
		paths[attrValue(t, dps.At(index).Attributes(), "cisco.yang.path")] = struct{}{}
	}
	assert.Equal(t, map[string]struct{}{
		"openconfig-system:system/state/foo-bar": {},
		"openconfig-system:system/state/foo_bar": {},
	}, paths)
	assert.Zero(t, health.snapshot().droppedDatapoints)
}

func TestIOSXRGNMIPathRenderingEscapesStructuralDelimiterCollisions(t *testing.T) {
	for _, test := range []struct {
		name  string
		left  *gnmi.Path
		right *gnmi.Path
	}{
		{
			name:  "structured element boundary",
			left:  &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "a/b"}, {Name: "c", Key: map[string]string{"k": "v"}}}},
			right: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "a"}, {Name: "b"}, {Name: "c", Key: map[string]string{"k": "v"}}}},
		},
		{
			name:  "legacy element boundary",
			left:  &gnmi.Path{Element: []string{"a/b", "c"}},
			right: &gnmi.Path{Element: []string{"a", "b", "c"}},
		},
		{
			name:  "key syntax",
			left:  &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "list", Key: map[string]string{"a": "x][b=y"}}}},
			right: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "list", Key: map[string]string{"a": "x", "b": "y"}}}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			leftBudget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
			left, ok := gnmiPathToString(test.left, leftBudget)
			require.True(t, ok)
			rightBudget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
			right, ok := gnmiPathToString(test.right, rightBudget)
			require.True(t, ok)
			assert.NotEqual(t, left, right)
			assert.Contains(t, left, "%")
		})
	}

	health := &iosXRHealth{}
	decoder := iosXRGNMIUpdateDecoder{target: IOSXRTargetConfig{Name: "xr-1"}, health: health}
	md := decoder.decodeNotification(&gnmi.Notification{
		Prefix: mustParseIOSXRPath(t, "openconfig-system:system/state"),
		Update: []*gnmi.Update{
			{Path: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "a/b"}}}, Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_IntVal{IntVal: 1}}},
			{Path: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "a"}, {Name: "b"}}}, Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_IntVal{IntVal: 2}}},
		},
	}, iosXRTelemetryTransportDialIn)
	paths := map[string]struct{}{}
	for _, name := range []string{
		"cisco.iosxr.yang.openconfig_system.system.state.a_b",
		"cisco.iosxr.yang.openconfig_system.system.state.a.b",
	} {
		metric := mustFindIOSXRMetric(t, md, name)
		dps := metric.Gauge().DataPoints()
		require.Equal(t, 1, dps.Len())
		paths[attrValue(t, dps.At(0).Attributes(), "cisco.yang.path")] = struct{}{}
	}
	assert.Equal(t, map[string]struct{}{
		"openconfig-system:system/state/a%2Fb": {},
		"openconfig-system:system/state/a/b":   {},
	}, paths)
	assert.Zero(t, health.snapshot().droppedDatapoints)
}

func TestIOSXRGNMIDecoderRejectsPathElementWithoutMetricIdentity(t *testing.T) {
	health := &iosXRHealth{}
	decoder := iosXRGNMIUpdateDecoder{target: IOSXRTargetConfig{Name: "xr-1"}, health: health}
	md := decoder.decodeNotification(&gnmi.Notification{
		Prefix: mustParseIOSXRPath(t, "openconfig-system:system/state"),
		Update: []*gnmi.Update{{
			Path: &gnmi.Path{Elem: []*gnmi.PathElem{
				{Name: "---", Key: map[string]string{"name": "must-not-disappear"}},
				{Name: "value"},
			}},
			Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_IntVal{IntVal: 1}},
		}},
	}, iosXRTelemetryTransportDialIn)
	assert.Zero(t, directTelemetryDataPointCount(md))
	assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
}

func TestDirectGNMIJSONIdentityUsesExplicitDeterministicPrecedence(t *testing.T) {
	value := map[string]any{
		"name":             "GigabitEthernet-name",
		"interface":        "GigabitEthernet-fallback",
		"interface-name":   "TenGigE-preferred",
		"vrf":              "fallback-vrf",
		"vrf-name":         "preferred-vrf",
		"neighbor":         "192.0.2.2",
		"neighbor-address": "192.0.2.1",
		"node":             "fallback-node",
		"node-name":        "preferred-node",
	}
	want := map[string]string{
		"name":                   "GigabitEthernet-name",
		"network.interface.name": "TenGigE-preferred",
		"network.vrf.name":       "preferred-vrf",
		"network.peer.address":   "192.0.2.1",
		"cisco.node.name":        "preferred-node",
	}

	for range 100 {
		attrs := map[string]string{}
		budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
		require.True(t, extractJSONIdentityAttrs(value, attrs, budget, nil))
		assert.Equal(t, want, attrs)
		assert.Zero(t, budget.dropped)
	}

	t.Run("lower-priority synonym remains bounded", func(t *testing.T) {
		attrs := map[string]string{}
		budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributeValueBytes: 4}, 10)
		assert.False(t, extractJSONIdentityAttrs(map[string]any{
			"vrf-name": "good",
			"vrf":      "oversized",
		}, attrs, budget, nil))
		assert.Equal(t, int64(1), budget.dropped)
	})

	t.Run("present empty canonical identity wins over fallback", func(t *testing.T) {
		attrs := map[string]string{}
		budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
		require.True(t, extractJSONIdentityAttrs(map[string]any{
			"interface-name": "",
			"interface":      "fallback-must-not-win",
		}, attrs, budget, nil))
		value, present := attrs["network.interface.name"]
		assert.True(t, present)
		assert.Empty(t, value)
	})
}

func TestIOSXRGNMIJSONPreservesEmptyIdentityInEmittedDatapoints(t *testing.T) {
	decoder := iosXRGNMIUpdateDecoder{target: IOSXRTargetConfig{Name: "xr-1"}, health: &iosXRHealth{}}
	md := decoder.decodeNotification(&gnmi.Notification{
		Prefix: mustParseIOSXRPath(t, "openconfig-system:system/state"),
		Update: []*gnmi.Update{{
			Path: mustParseIOSXRPath(t, "json"),
			Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{
				"items": [
					{"name":"","value":1},
					{"id":"other","value":2}
				]
			}`)}},
		}},
	}, iosXRTelemetryTransportDialIn)

	metric := mustFindIOSXRMetric(t, md, "cisco.iosxr.yang.openconfig_system.system.state.json.items.value")
	dps := metric.Gauge().DataPoints()
	require.Equal(t, 2, dps.Len())
	presentEmpty := 0
	missing := 0
	for index := 0; index < dps.Len(); index++ {
		value, present := dps.At(index).Attributes().Get("name")
		if present {
			assert.Empty(t, value.Str())
			presentEmpty++
		} else {
			missing++
		}
	}
	assert.Equal(t, 1, presentEmpty)
	assert.Equal(t, 1, missing)
}

func TestIOSXRGNMIJSONRejectsAmbiguousUnrecognizedListIdentity(t *testing.T) {
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
			health := &iosXRHealth{}
			decoder := iosXRGNMIUpdateDecoder{target: IOSXRTargetConfig{Name: "xr-1"}, health: health}
			md := decoder.decodeNotification(&gnmi.Notification{
				Prefix: mustParseIOSXRPath(t, "openconfig-system:system/state"),
				Update: []*gnmi.Update{{
					Path: mustParseIOSXRPath(t, "json"),
					Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(test.raw)}},
				}},
			}, iosXRTelemetryTransportDialIn)

			assert.Zero(t, directTelemetryDataPointCount(md))
			assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
		})
	}
}

func TestIOSXRGNMINestedJSONPreservesOuterAndInnerIdentity(t *testing.T) {
	decoder := iosXRGNMIUpdateDecoder{target: IOSXRTargetConfig{Name: "xr-1"}, health: &iosXRHealth{}}
	md := decoder.decodeNotification(&gnmi.Notification{
		Prefix: mustParseIOSXRPath(t, "openconfig-network-instance:network-instances"),
		Update: []*gnmi.Update{{
			Path: mustParseIOSXRPath(t, "json"),
			Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{
				"vrfs": [
					{"name":"blue","protocols":[{"name":"bgp","state":1}]},
					{"name":"red","protocols":[{"name":"bgp","state":1}]}
				]
			}`)}},
		}},
	}, iosXRTelemetryTransportDialIn)

	metric := mustFindIOSXRMetric(t, md, "cisco.iosxr.yang.openconfig_network_instance.network_instances.json.vrfs.protocols.state")
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	dps := metric.Gauge().DataPoints()
	require.Equal(t, 2, dps.Len())
	const nestedName = "cisco.yang.key.json.network_instances.json.vrfs.protocols.name"
	outerNames := map[string]struct{}{}
	for index := 0; index < dps.Len(); index++ {
		attrs := dps.At(index).Attributes()
		outerNames[attrValue(t, attrs, "name")] = struct{}{}
		assert.Equal(t, "bgp", attrValue(t, attrs, nestedName))
	}
	assert.Equal(t, map[string]struct{}{"blue": {}, "red": {}}, outerNames)
}

func TestDirectGNMINestedJSONIdentityCollisionBoundaries(t *testing.T) {
	const escaped = "cisco.yang.key.json.parent.child.name"
	for range 100 {
		attrs := map[string]string{"name": "outer"}
		budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributes: 2, maxAttributeKeyBytes: len(escaped)}, 10)
		require.True(t, extractJSONIdentityAttrs(map[string]any{"name": "inner"}, attrs, budget, []string{"parent", "child"}))
		assert.Equal(t, map[string]string{"name": "outer", escaped: "inner"}, attrs)
	}

	fallbackLimit := len(escaped) - 1
	fallback, ok := directGNMIScopedIdentityAttributeName("json", "name", []string{"parent", "child"}, 1, fallbackLimit)
	require.True(t, ok)
	require.LessOrEqual(t, len(fallback), fallbackLimit)
	fallbackAttrs := map[string]string{"name": "outer"}
	fallbackBudget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributeKeyBytes: fallbackLimit}, 10)
	require.True(t, extractJSONIdentityAttrs(map[string]any{"name": "inner"}, fallbackAttrs, fallbackBudget, []string{"parent", "child"}))
	assert.Equal(t, "inner", fallbackAttrs[fallback])

	longPath := make([]string, directGNMIHardMaxDepth)
	for index := range longPath {
		longPath[index] = fmt.Sprintf("repeated-element-%03d", index)
	}
	longFallback, ok := directGNMIScopedIdentityAttributeName("json", "name", longPath, 1, directGNMIHardMaxAttributeKeyBytes)
	require.True(t, ok)
	require.LessOrEqual(t, len(longFallback), directGNMIHardMaxAttributeKeyBytes)
	longAttrs := map[string]string{"name": "outer"}
	longBudget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
	require.True(t, extractJSONIdentityAttrs(map[string]any{"name": "inner"}, longAttrs, longBudget, longPath))
	assert.Equal(t, "inner", longAttrs[longFallback])

	keyBudget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributeKeyBytes: len(directGNMIPathKeyAttributePrefix)}, 10)
	assert.False(t, extractJSONIdentityAttrs(
		map[string]any{"name": "inner"},
		map[string]string{"name": "outer"},
		keyBudget,
		[]string{"parent", "child"},
	))
	assert.Equal(t, int64(1), keyBudget.dropped)

	countBudget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributes: 1}, 10)
	assert.False(t, extractJSONIdentityAttrs(
		map[string]any{"name": "inner"},
		map[string]string{"name": "outer"},
		countBudget,
		[]string{"parent", "child"},
	))
	assert.Equal(t, int64(1), countBudget.dropped)
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
		}, iosXRTelemetryTransportDialIn)
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

func assertGaugeIntMetricValue(t *testing.T, md pmetric.Metrics, name string, value int64) {
	t.Helper()
	metric := mustFindIOSXRMetric(t, md, name)
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	require.Equal(t, 1, metric.Gauge().DataPoints().Len())
	dp := metric.Gauge().DataPoints().At(0)
	require.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
	assert.Equal(t, value, dp.IntValue())
}

func assertGaugeDoubleMetricValue(t *testing.T, md pmetric.Metrics, name string, value float64) {
	t.Helper()
	metric := mustFindIOSXRMetric(t, md, name)
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	require.Equal(t, 1, metric.Gauge().DataPoints().Len())
	dp := metric.Gauge().DataPoints().At(0)
	require.Equal(t, pmetric.NumberDataPointValueTypeDouble, dp.ValueType())
	assert.InDelta(t, value, dp.DoubleValue(), 1e-9)
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
	require.True(t, ok, "missing attribute %s", "host.ip")
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
