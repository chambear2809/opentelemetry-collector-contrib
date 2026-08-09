// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestDecodeNotificationDuplicatePathUsesFinalUpdate(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	path := protoPath("counter")
	decoded, stats, err := DecodeNotification("switch-1", &gnmipb.Notification{
		Timestamp: receipt.UnixNano(),
		Prefix:    protoPath("system", "state"),
		Update: []*gnmipb.Update{
			{Path: path, Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{"invalid":`)}}},
			{Path: path, Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: 2}}},
		},
	}, receipt)
	require.NoError(t, err, "a superseded value must not be decoded")
	assert.Zero(t, stats.UnmappedValues)
	require.Len(t, decoded.Touched, 1)
	require.Len(t, decoded.Updates, 1)
	assert.Equal(t, int64(2), decoded.Updates[0].Value.Int)
}

//nolint:staticcheck // The test verifies required decoding of the deprecated gNMI decimal wire variant.
func TestDecodeNotificationScalarsJSONAndUnsupportedValues(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	prefix := &gnmipb.Path{
		Origin: "openconfig",
		Elem: []*gnmipb.PathElem{
			{Name: "interfaces"},
			{Name: "interface", Key: map[string]string{"name": "Ethernet1"}},
			{Name: "state"},
		},
	}
	notification := &gnmipb.Notification{
		Timestamp: receipt.Add(-time.Minute).UnixMilli(),
		Prefix:    prefix,
		Update: []*gnmipb.Update{
			{Path: protoPath("signed"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: -2}}},
			{Path: protoPath("unsigned"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{UintVal: 3}}},
			{Path: protoPath("float"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_FloatVal{FloatVal: 2.5}}},
			{Path: protoPath("double"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_DoubleVal{DoubleVal: 3.5}}},
			{Path: protoPath("ratio"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_DecimalVal{DecimalVal: &gnmipb.Decimal64{Digits: 125, Precision: 2}}}},
			{Path: protoPath("enabled"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{BoolVal: true}}},
			{Path: protoPath("description"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "uplink"}}},
			{Path: protoPath("ascii"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_AsciiVal{AsciiVal: "legacy"}}},
			{Path: protoPath("subtree"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{"temperature":42.5,"label":"hot"}`)}}},
			{Path: protoPath("unsupported"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_ProtoBytes{ProtoBytes: []byte{1, 2}}}},
		},
		Delete: []*gnmipb.Path{protoPath("old")},
	}

	decoded, stats, err := DecodeNotification("switch-1", notification, receipt)
	require.NoError(t, err)
	assert.Len(t, decoded.Updates, 10)
	require.Len(t, decoded.Touched, 10, "every wire update path must survive even when its value is unsupported")
	assert.Equal(t, "unsupported", decoded.Touched[9].Elements[len(decoded.Touched[9].Elements)-1].Name)
	assert.Equal(t, 1, stats.UnmappedValues)
	assert.Equal(t, map[UnsupportedValueKind]int{UnsupportedValueProtoBytes: 1}, stats.UnsupportedValueKinds)
	assert.Zero(t, stats.InvalidTimestamps)
	assert.Equal(t, "switch-1", decoded.Prefix.Target)
	require.Len(t, decoded.Deletes, 1)
	assert.Equal(t, "old", decoded.Deletes[0].Elements[len(decoded.Deletes[0].Elements)-1].Name)

	byLeaf := map[string]Point{}
	for _, point := range decoded.Updates {
		byLeaf[point.Series.Leaf] = point
	}
	assert.Equal(t, int64(-2), byLeaf["signed"].Value.Int)
	assert.Equal(t, uint64(3), byLeaf["unsigned"].Value.Uint)
	assert.Equal(t, 2.5, byLeaf["float"].Value.Double)
	assert.Equal(t, 3.5, byLeaf["double"].Value.Double)
	assert.Equal(t, 1.25, byLeaf["ratio"].Value.Double)
	assert.True(t, byLeaf["enabled"].Value.Bool)
	assert.Equal(t, "uplink", byLeaf["description"].Value.String)
	assert.Equal(t, "legacy", byLeaf["ascii"].Value.String)
	assert.Equal(t, 42.5, byLeaf["temperature"].Value.Double)
	assert.Equal(t, "hot", byLeaf["label"].Value.String)
}

func TestDecodeNotificationClassifiesBoundedUnsupportedTypedValues(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	decoded, stats, err := DecodeNotification("switch-1", &gnmipb.Notification{
		Timestamp: receipt.UnixNano(),
		Prefix:    protoPath("system", "state"),
		Update: []*gnmipb.Update{
			{Path: protoPath("bytes"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BytesVal{BytesVal: []byte{1}}}},
			{Path: protoPath("leaf-list"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_LeaflistVal{LeaflistVal: &gnmipb.ScalarArray{Element: []*gnmipb.TypedValue{
				{Value: &gnmipb.TypedValue_StringVal{StringVal: "one"}},
				{Value: &gnmipb.TypedValue_UintVal{UintVal: 2}},
			}}}}},
			{Path: protoPath("any"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_AnyVal{AnyVal: &anypb.Any{TypeUrl: "example.test/Value", Value: []byte{2}}}}},
			{Path: protoPath("proto"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_ProtoBytes{ProtoBytes: []byte{3}}}},
		},
	}, receipt)
	require.NoError(t, err)
	assert.Empty(t, decoded.Updates)
	assert.Len(t, decoded.Touched, 4)
	assert.Equal(t, 4, stats.UnmappedValues)
	assert.Equal(t, map[UnsupportedValueKind]int{
		UnsupportedValueBytes:      1,
		UnsupportedValueLeafList:   1,
		UnsupportedValueAny:        1,
		UnsupportedValueProtoBytes: 1,
	}, stats.UnsupportedValueKinds)
	require.Len(t, decoded.Undecodable, 4)
	for index := range decoded.Undecodable {
		assert.Equal(t, decoded.Touched[index].Key(), decoded.Undecodable[index].Key())
	}
}

//nolint:staticcheck // The test covers invalid deprecated decimal wire variants.
func TestDecodeNotificationRetainsUndecodableScalarPaths(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name        string
		value       *gnmipb.TypedValue
		unsupported map[UnsupportedValueKind]int
	}{
		{name: "nil TypedValue"},
		{name: "empty TypedValue", value: &gnmipb.TypedValue{}},
		{name: "non-finite float", value: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_FloatVal{FloatVal: float32(math.NaN())}}},
		{name: "non-finite double", value: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_DoubleVal{DoubleVal: math.Inf(1)}}},
		{name: "nil decimal", value: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_DecimalVal{}}},
		{name: "invalid decimal precision", value: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_DecimalVal{
			DecimalVal: &gnmipb.Decimal64{Digits: 1, Precision: 309},
		}}},
		{
			name:        "unsupported bytes",
			value:       &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BytesVal{BytesVal: []byte{1}}},
			unsupported: map[UnsupportedValueKind]int{UnsupportedValueBytes: 1},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoded, stats, err := DecodeNotification("switch-1", &gnmipb.Notification{
				Timestamp: receipt.UnixNano(),
				Prefix:    protoPath("system", "state"),
				Update: []*gnmipb.Update{{
					Path: protoPath("value"),
					Val:  test.value,
				}},
			}, receipt)
			require.NoError(t, err)
			assert.Empty(t, decoded.Updates)
			require.Len(t, decoded.Touched, 1)
			require.Len(t, decoded.Undecodable, 1)
			assert.Equal(t, decoded.Touched[0].Key(), decoded.Undecodable[0].Key())
			assert.Equal(t, 1, stats.UnmappedValues)
			assert.Equal(t, test.unsupported, stats.UnsupportedValueKinds)
		})
	}
}

func TestDecodeNotificationRejectsOversizedUnsupportedTypedValues(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	oversized := make([]byte, maxUnsupportedTypedValueBytes+1)
	tests := []struct {
		name  string
		value *gnmipb.TypedValue
	}{
		{name: "bytes", value: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BytesVal{BytesVal: oversized}}},
		{name: "leaf-list", value: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_LeaflistVal{LeaflistVal: &gnmipb.ScalarArray{Element: []*gnmipb.TypedValue{{Value: &gnmipb.TypedValue_BytesVal{BytesVal: oversized}}}}}}},
		{name: "Any", value: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_AnyVal{AnyVal: &anypb.Any{TypeUrl: "example.test/Value", Value: oversized}}}},
		{name: "proto_bytes", value: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_ProtoBytes{ProtoBytes: oversized}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, stats, err := DecodeNotification("switch-1", &gnmipb.Notification{
				Timestamp: receipt.UnixNano(), Prefix: protoPath("system"),
				Update: []*gnmipb.Update{{Path: protoPath("value"), Val: tt.value}},
			}, receipt)
			require.ErrorContains(t, err, "payload exceeds")
			assert.Zero(t, stats.UnmappedValues)
			assert.Empty(t, stats.UnsupportedValueKinds)
		})
	}
}

func TestDecodeNotificationRejectsDeepUnsupportedLeafList(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	value := &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{UintVal: 1}}
	for range maxUnsupportedTypedValueDepth {
		value = &gnmipb.TypedValue{Value: &gnmipb.TypedValue_LeaflistVal{LeaflistVal: &gnmipb.ScalarArray{Element: []*gnmipb.TypedValue{value}}}}
	}
	_, stats, err := DecodeNotification("switch-1", &gnmipb.Notification{
		Timestamp: receipt.UnixNano(), Prefix: protoPath("system"),
		Update: []*gnmipb.Update{{Path: protoPath("value"), Val: value}},
	}, receipt)
	require.ErrorContains(t, err, "nesting exceeds")
	assert.Zero(t, stats.UnmappedValues)
	assert.Empty(t, stats.UnsupportedValueKinds)
}

func TestDecodeNotificationInvalidTimestampFallsBackAndCounts(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	decoded, stats, err := DecodeNotification("switch-1", &gnmipb.Notification{
		Timestamp: 1,
		Prefix:    protoPath("system"),
		Update: []*gnmipb.Update{{
			Path: protoPath("up"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{BoolVal: true}},
		}},
	}, receipt)
	require.NoError(t, err)
	assert.Equal(t, 1, stats.InvalidTimestamps)
	assert.Equal(t, receipt, decoded.Timestamp)
	require.Len(t, decoded.Updates, 1)
	assert.Equal(t, receipt, decoded.Updates[0].Timestamp)
}

func TestDecodeNotificationKeepsWirePathTargetSeparateFromConfiguredIdentity(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	notification := &gnmipb.Notification{
		Timestamp: receipt.UnixNano(),
		Prefix:    &gnmipb.Path{Target: "device-wire-id", Origin: "openconfig", Elem: []*gnmipb.PathElem{{Name: "system"}}},
		Update: []*gnmipb.Update{{
			Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "state"}, {Name: "up"}}},
			Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{BoolVal: true}},
		}},
		Delete: []*gnmipb.Path{{Elem: []*gnmipb.PathElem{{Name: "old"}}}},
	}

	decoded, _, err := DecodeNotification("nexus-shard-01", notification, receipt)
	require.NoError(t, err)
	assert.Equal(t, "nexus-shard-01", decoded.Prefix.Target)
	assert.Equal(t, "device-wire-id", decoded.Prefix.PathTarget)
	require.Len(t, decoded.Updates, 1)
	assert.Equal(t, "nexus-shard-01", decoded.Updates[0].Series.Target)
	assert.Equal(t, "device-wire-id", decoded.Updates[0].Series.PathTarget)
	require.Len(t, decoded.Deletes, 1)
	assert.Equal(t, "nexus-shard-01", decoded.Deletes[0].Target)
	assert.Equal(t, "device-wire-id", decoded.Deletes[0].PathTarget)
}

func TestDecodeNotificationRejectsConflictingWirePathTargets(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	_, _, err := DecodeNotification("nexus-shard-01", &gnmipb.Notification{
		Timestamp: receipt.UnixNano(),
		Prefix:    &gnmipb.Path{Target: "OC-YANG", Elem: []*gnmipb.PathElem{{Name: "system"}}},
		Update: []*gnmipb.Update{{
			Path: &gnmipb.Path{Target: "OTHERS", Elem: []*gnmipb.PathElem{{Name: "state"}, {Name: "up"}}},
			Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{BoolVal: true}},
		}},
	}, receipt)
	require.ErrorContains(t, err, "conflicting gNMI path targets")
}

func TestDecodeNotificationRejectsMalformedJSON(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	_, stats, err := DecodeNotification("switch-1", &gnmipb.Notification{
		Timestamp: receipt.UnixNano(), Prefix: protoPath("system"),
		Update: []*gnmipb.Update{{
			Path: protoPath("state"),
			Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{"unterminated":`)}},
		}},
	}, receipt)
	require.ErrorContains(t, err, "decode JSON value")
	assert.Zero(t, stats.UnmappedValues)
}

func TestDecodeNotificationRejectsUnsafeJSONBeforeMaterializing(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		raw  []byte
		err  string
	}{
		{name: "oversized payload", raw: []byte(`"` + strings.Repeat("x", maxJSONTypedValueBytes) + `"`), err: "payload exceeds hard limit"},
		{name: "excessive depth", raw: []byte(strings.Repeat("[", 129) + "0" + strings.Repeat("]", 129)), err: "depth limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := DecodeNotification("switch-1", &gnmipb.Notification{
				Timestamp: receipt.UnixNano(),
				Prefix:    protoPath("system"),
				Update: []*gnmipb.Update{{
					Path: protoPath("state"),
					Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: tt.raw}},
				}},
			}, receipt)
			require.ErrorContains(t, err, tt.err)
		})
	}
}

func TestDecodeJSONArrayObjectsUsesExactDeclaredContextAndQualifiedKeys(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	schema, err := NewJSONListKeySchema(JSONListKeySpec{
		Elements: []string{"root", "interfaces", "openconfig-interfaces:interface"},
		Keys:     []string{"name"},
	})
	require.NoError(t, err)
	notification := &gnmipb.Notification{
		Timestamp: receipt.UnixNano(),
		Prefix:    protoPath("root"),
		Update: []*gnmipb.Update{{
			Path: protoPath("interfaces"),
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonVal{JsonVal: []byte(`{
				"openconfig-interfaces:interface": [
					{"openconfig-interfaces:name":"Ethernet1","state":{"counter":10}},
					{"openconfig-interfaces:name":"Ethernet2","state":{"counter":20}}
				]
			}`)}},
		}},
	}

	decoded, stats, err := DecodeNotificationWithSchema("switch-1", notification, receipt, schema)
	require.NoError(t, err)
	assert.Zero(t, stats.UnmappedValues)
	var counters []Point
	for _, point := range decoded.Updates {
		if point.Series.Leaf == "counter" {
			counters = append(counters, point)
		}
	}
	require.Len(t, counters, 2)
	assert.NotEqual(t, counters[0].Series.Key(), counters[1].Series.Key())
	assert.Equal(t, "Ethernet1", counters[0].Series.Elements[2].Keys["name"])
	assert.Equal(t, "Ethernet2", counters[1].Series.Elements[2].Keys["name"])
}

func TestDecodeJSONAggregateRetainsExactUndecodableMappedDescendant(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	key := []KeyAttribute{{Element: "interface", Key: "name", Attribute: "network.interface.name"}}
	registry, err := NewRegistry(
		Mapping{
			Source: SourcePath{
				Origin: "openconfig", Elements: []string{"interfaces", "interface", "state"}, Leaf: "oper-status",
			},
			Metric:        MetricMetadata{Name: "interface.status", Description: "Interface status.", Unit: "1"},
			Scale:         1,
			GaugeType:     GaugeInt,
			KeyAttributes: key,
		},
		Mapping{
			Source: SourcePath{
				Origin: "openconfig", Elements: []string{"interfaces", "interface", "state", "counters"}, Leaf: "in-octets",
			},
			Metric:        MetricMetadata{Name: "interface.io", Description: "Interface bytes.", Unit: "By"},
			Scale:         1,
			GaugeType:     GaugeInt,
			KeyAttributes: key,
		},
	)
	require.NoError(t, err)

	decoded, stats, err := DecodeNotificationWithRegistry("switch-1", &gnmipb.Notification{
		Timestamp: receipt.UnixNano(),
		Prefix:    &gnmipb.Path{Origin: "openconfig"},
		Update: []*gnmipb.Update{{
			Path: protoPath("interfaces", "interface"),
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`[
				{"name":"Ethernet1","state":{"oper-status":null,"counters":{"in-octets":5}}},
				{"name":"Ethernet2","state":{"oper-status":1,"counters":{"in-octets":7}}}
			]`)}},
		}},
	}, receipt, registry)
	require.NoError(t, err)
	assert.Equal(t, 1, stats.UnmappedValues)
	require.Len(t, decoded.Undecodable, 1)
	invalid := decoded.Undecodable[0]
	assert.Equal(t, "interfaces/interface[name=Ethernet1]/state/oper-status", invalid.String())
	assert.Equal(t, "Ethernet1", invalid.Elements[1].Keys["name"])
	assert.NotEqual(t, decoded.Touched[0].Key(), invalid.Key(),
		"an aggregate list container must not become the precise invalidation")

	var counters []Point
	for _, point := range decoded.Updates {
		if point.Series.Leaf == "in-octets" {
			counters = append(counters, point)
		}
	}
	require.Len(t, counters, 2)
	assert.Equal(t, int64(5), counters[0].Value.Int)
	assert.Equal(t, int64(7), counters[1].Value.Int)

	transaction, _ := registry.MapNotification(decoded)
	require.Len(t, transaction.Invalidates, 1)
	require.Len(t, transaction.Updates, 3,
		"both counters and the valid sibling status must remain independently mappable")
	assert.Equal(t, invalid.Key(), transaction.Invalidates[0].Key())
}

func TestDecodeJSONScalarLeafListDeduplicatesUndecodablePath(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	decoded, stats, err := DecodeNotification("switch-1", &gnmipb.Notification{
		Timestamp: receipt.UnixNano(),
		Prefix:    protoPath("system", "state"),
		Update: []*gnmipb.Update{{
			Path: protoPath("value"),
			Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`[null,1,2]`)}},
		}},
	}, receipt)
	require.NoError(t, err)
	assert.Empty(t, decoded.Updates)
	assert.Equal(t, 3, stats.UnmappedValues)
	require.Len(t, decoded.Undecodable, 1,
		"one scalar leaf-list wire path must consume one invalid-path cardinality slot")
	assert.Equal(t, decoded.Touched[0].Key(), decoded.Undecodable[0].Key())
}

func TestDecodeJSONEmptyContainerRetainsExactPathWithoutUnmappedCount(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	for _, raw := range []string{`[]`, `{}`} {
		t.Run(raw, func(t *testing.T) {
			decoded, stats, err := DecodeNotification("switch-1", &gnmipb.Notification{
				Timestamp: receipt.UnixNano(),
				Prefix:    protoPath("system", "state"),
				Update: []*gnmipb.Update{{
					Path: protoPath("value"),
					Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{
						JsonIetfVal: []byte(raw),
					}},
				}},
			}, receipt)
			require.NoError(t, err)
			assert.Empty(t, decoded.Updates)
			assert.Zero(t, stats.UnmappedValues,
				"an empty container has no scalar values to count as unmapped")
			require.Len(t, decoded.Undecodable, 1)
			assert.Equal(t, decoded.Touched[0].Key(), decoded.Undecodable[0].Key())
		})
	}
}

func TestDecodeJSONEmptyAggregateDescendantsDoNotInvalidateUnmatchedMapping(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	registry, err := NewRegistry(Mapping{
		Source:    SourcePath{Origin: "openconfig", Elements: []string{"system", "state"}, Leaf: "value"},
		Metric:    MetricMetadata{Name: "system.value", Description: "System value.", Unit: "1"},
		Scale:     1,
		GaugeType: GaugeInt,
	})
	require.NoError(t, err)
	decoded, stats, err := DecodeNotificationWithRegistry("switch-1", &gnmipb.Notification{
		Timestamp: receipt.UnixNano(),
		Prefix:    &gnmipb.Path{Origin: "openconfig", Elem: []*gnmipb.PathElem{{Name: "interfaces"}}},
		Update: []*gnmipb.Update{{
			Path: protoPath("state"),
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{
				JsonIetfVal: []byte(`{"empty-list":[],"empty-object":{}}`),
			}},
		}},
	}, receipt, registry)
	require.NoError(t, err)
	assert.Zero(t, stats.UnmappedValues)
	require.Len(t, decoded.Undecodable, 2)
	assert.Equal(t, "interfaces/state/empty-list", decoded.Undecodable[0].String())
	assert.Equal(t, "interfaces/state/empty-object", decoded.Undecodable[1].String())
	for _, path := range decoded.Undecodable {
		assert.NotEqual(t, decoded.Touched[0].Key(), path.Key(),
			"an empty descendant must not turn its aggregate parent into an invalidation")
	}
	transaction, mappingStats := registry.MapNotification(decoded)
	assert.Empty(t, transaction.Invalidates)
	assert.Equal(t, MappingStats{}, mappingStats)
}

func TestDecodeJSONNonemptyContainerAtExactMappedScalarIsUndecodable(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	registry, err := NewRegistry(Mapping{
		Source:    SourcePath{Origin: "openconfig", Elements: []string{"system", "state"}, Leaf: "value"},
		Metric:    MetricMetadata{Name: "system.value", Description: "System value.", Unit: "1"},
		Scale:     1,
		GaugeType: GaugeInt,
	})
	require.NoError(t, err)
	for _, raw := range []string{`{"child":1}`, `[{"child":1}]`} {
		t.Run(raw, func(t *testing.T) {
			decoded, stats, err := DecodeNotificationWithRegistry("switch-1", &gnmipb.Notification{
				Timestamp: receipt.UnixNano(),
				Prefix:    &gnmipb.Path{Origin: "openconfig", Elem: []*gnmipb.PathElem{{Name: "system"}, {Name: "state"}}},
				Update: []*gnmipb.Update{{
					Path: protoPath("value"),
					Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{
						JsonIetfVal: []byte(raw),
					}},
				}},
			}, receipt, registry)
			require.NoError(t, err)
			assert.Zero(t, stats.UnmappedValues)
			require.Len(t, decoded.Updates, 1)
			assert.Equal(t, "child", decoded.Updates[0].Series.Leaf)
			require.Len(t, decoded.Undecodable, 1)
			assert.Equal(t, decoded.Touched[0].Key(), decoded.Undecodable[0].Key())

			transaction, _ := registry.MapNotification(decoded)
			assert.Empty(t, transaction.Updates)
			require.Len(t, transaction.Invalidates, 1)
			assert.Equal(t, decoded.Touched[0].Key(), transaction.Invalidates[0].Key())
		})
	}
}

func TestDecodeJSONMappedDescendantDoesNotInvalidateUnmatchedAggregateRoot(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	registry, err := NewRegistry(Mapping{
		Source:    SourcePath{Origin: "openconfig", Elements: []string{"system", "state", "value"}, Leaf: "child"},
		Metric:    MetricMetadata{Name: "system.value.child", Description: "System child value.", Unit: "1"},
		Scale:     1,
		GaugeType: GaugeInt,
	})
	require.NoError(t, err)
	decoded, stats, err := DecodeNotificationWithRegistry("switch-1", &gnmipb.Notification{
		Timestamp: receipt.UnixNano(),
		Prefix:    &gnmipb.Path{Origin: "openconfig", Elem: []*gnmipb.PathElem{{Name: "system"}, {Name: "state"}}},
		Update: []*gnmipb.Update{{
			Path: protoPath("value"),
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{
				JsonIetfVal: []byte(`{"child":1}`),
			}},
		}},
	}, receipt, registry)
	require.NoError(t, err)
	assert.Zero(t, stats.UnmappedValues)
	assert.Empty(t, decoded.Undecodable)
	transaction, mappingStats := registry.MapNotification(decoded)
	require.Len(t, transaction.Updates, 1)
	assert.Empty(t, transaction.Invalidates)
	assert.Equal(t, MappingStats{Mapped: 1}, mappingStats)
}

func TestDecodeJSONArrayObjectsPreservesIOSXEInstallLocationKeys(t *testing.T) {
	receipt := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	notification := &gnmipb.Notification{
		Timestamp: receipt.UnixNano(),
		Prefix:    protoPath("install-oper-data"),
		Update: []*gnmipb.Update{{
			Path: protoPath("install-location-information"),
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`[
				{"fru":"rp","slot":0,"bay":0,"chassis":1,"install-version-info":[{"version":"17.18.01.0.1186","version-extension":"build-a","current":0}]},
				{"fru":"rp","slot":0,"bay":0,"chassis":2,"install-version-info":[{"version":"17.18.01.0.1186","version-extension":"build-a","current":0}]}
			]`)}},
		}},
	}

	decoded, stats, err := DecodeNotification("controller", notification, receipt)
	require.NoError(t, err)
	assert.Zero(t, stats.UnmappedValues)
	var current []Point
	for _, point := range decoded.Updates {
		if point.Series.Leaf == "current" {
			current = append(current, point)
		}
	}
	require.Len(t, current, 2)
	assert.NotEqual(t, current[0].Series.Key(), current[1].Series.Key())
	for index, point := range current {
		require.GreaterOrEqual(t, len(point.Series.Elements), 2)
		keys := point.Series.Elements[1].Keys
		assert.Equal(t, "rp", keys["fru"])
		assert.Equal(t, "0", keys["slot"])
		assert.Equal(t, "0", keys["bay"])
		assert.Equal(t, strconv.Itoa(index+1), keys["chassis"])
	}
}

func TestDecodeJSONArrayObjectPreservesEmptyListKey(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	schema, err := NewJSONListKeySchema(JSONListKeySpec{
		Elements: []string{"root", "interfaces", "interface"},
		Keys:     []string{"name"},
	})
	require.NoError(t, err)
	notification := &gnmipb.Notification{
		Timestamp: receipt.UnixNano(),
		Prefix:    protoPath("root"),
		Update: []*gnmipb.Update{{
			Path: protoPath("interfaces"),
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{
				"interface": [
						{"name":"","state":{"counter":10}}
					]
				}`)}},
		}},
	}

	decoded, stats, err := DecodeNotificationWithSchema("switch-1", notification, receipt, schema)
	require.NoError(t, err)
	assert.Zero(t, stats.UnmappedValues)
	var counters []Point
	for _, point := range decoded.Updates {
		if point.Series.Leaf == "counter" {
			counters = append(counters, point)
		}
	}
	require.Len(t, counters, 1)
	value, present := counters[0].Series.Elements[2].Keys["name"]
	assert.True(t, present)
	assert.Empty(t, value)
}

func TestDecodeJSONArrayObjectRejectsMissingKeyWithoutPartialSuccess(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	schema, err := NewJSONListKeySchema(JSONListKeySpec{
		Elements: []string{"root", "interfaces", "interface"},
		Keys:     []string{"name", "index"},
	})
	require.NoError(t, err)
	decoded, _, err := DecodeNotificationWithSchema("switch-1", &gnmipb.Notification{
		Timestamp: receipt.UnixNano(),
		Prefix:    protoPath("root"),
		Update: []*gnmipb.Update{{
			Path: protoPath("interfaces"),
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{
					"interface": [
						{"name":"Ethernet1","index":1,"state":{"counter":10}},
						{"name":"Ethernet2","state":{"counter":20}}
					]
				}`)}},
		}},
	}, receipt, schema)
	require.ErrorContains(t, err, `required list key "index" is missing`)
	assert.Empty(t, decoded.Updates)
	assert.Empty(t, decoded.Touched)
}

func TestDecodeJSONArrayObjectRejectsConflictingDeclaredKeyRepresentations(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	schema, err := NewJSONListKeySchema(JSONListKeySpec{
		Elements: []string{"root", "interfaces", "interface"},
		Keys:     []string{"name"},
	})
	require.NoError(t, err)
	decoded, _, err := DecodeNotificationWithSchema("switch-1", &gnmipb.Notification{
		Timestamp: receipt.UnixNano(),
		Prefix:    protoPath("root"),
		Update: []*gnmipb.Update{{
			Path: protoPath("interfaces"),
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{
					"interface": [
						{"name":"Ethernet1","openconfig-interfaces:name":"Ethernet2","state":{"counter":10}}
					]
				}`)}},
		}},
	}, receipt, schema)
	require.ErrorContains(t, err, `conflicting values for list key "name"`)
	assert.Empty(t, decoded.Updates)
}

func TestDecodeJSONArrayObjectsUsesRegistryRequiredCustomListKeys(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	registry, err := NewRegistry(Mapping{
		Source: SourcePath{Origin: "custom", Elements: []string{"neighbors", "neighbor", "state"}, Leaf: "value"},
		Metric: MetricMetadata{Name: "custom.neighbor.value", Description: "Custom neighbor value.", Unit: "1"},
		Scale:  1, GaugeType: GaugeInt,
		KeyAttributes: []KeyAttribute{{Element: "neighbor", Key: "routing_instance", Attribute: "network.vrf.name"}},
	})
	require.NoError(t, err)
	notification := &gnmipb.Notification{
		Timestamp: receipt.UnixNano(),
		Prefix:    &gnmipb.Path{Origin: "custom"},
		Update: []*gnmipb.Update{{
			Path: protoPath("neighbors", "neighbor"),
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`[
				{"routing_instance":"red","state":{"value":10}},
				{"routing_instance":"blue","state":{"value":20}}
			]`)}},
		}},
	}

	decoded, stats, err := DecodeNotificationWithRegistry("switch-1", notification, receipt, registry)
	require.NoError(t, err)
	assert.Zero(t, stats.UnmappedValues)
	var mapped []MappedPoint
	for _, point := range decoded.Updates {
		if point.Series.Leaf != "value" {
			continue
		}
		value, present := point.Series.Elements[1].Keys["routing_instance"]
		assert.True(t, present)
		assert.NotContains(t, point.Series.Elements[1].Keys, "routing-instance")
		metric, ok := registry.Map(point)
		require.True(t, ok)
		assert.Equal(t, value, metric.Attributes["network.vrf.name"])
		mapped = append(mapped, metric)
	}
	require.Len(t, mapped, 2)
	assert.NotEqual(t, mapped[0].Source.Key(), mapped[1].Source.Key())
}

//nolint:staticcheck // This test verifies compatibility with the deprecated gNMI Value field.
func TestDecodeNotificationSupportsDeprecatedUpdateValue(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	legacyNotification := func(encoding gnmipb.Encoding, raw []byte, path *gnmipb.Path) *gnmipb.Notification {
		return &gnmipb.Notification{
			Timestamp: receipt.UnixNano(), Prefix: protoPath("system"),
			Update: []*gnmipb.Update{{Path: path, Value: &gnmipb.Value{Type: encoding, Value: raw}}},
		}
	}

	for _, encoding := range []gnmipb.Encoding{gnmipb.Encoding_JSON, gnmipb.Encoding_JSON_IETF} {
		decoded, stats, err := DecodeNotification("switch-1", legacyNotification(encoding, []byte(`{"value":7}`), protoPath("state")), receipt)
		require.NoError(t, err)
		assert.Zero(t, stats.UnmappedValues)
		require.Len(t, decoded.Updates, 1)
		assert.Equal(t, IntValue(7), decoded.Updates[0].Value)
	}

	decoded, stats, err := DecodeNotification("switch-1", legacyNotification(gnmipb.Encoding_ASCII, []byte("42"), protoPath("value")), receipt)
	require.NoError(t, err)
	assert.Zero(t, stats.UnmappedValues)
	require.Len(t, decoded.Updates, 1)
	assert.Equal(t, StringValue("42"), decoded.Updates[0].Value)

	for _, test := range []struct {
		encoding gnmipb.Encoding
		kind     UnsupportedValueKind
	}{
		{encoding: gnmipb.Encoding_BYTES, kind: UnsupportedValueBytes},
		{encoding: gnmipb.Encoding_PROTO, kind: UnsupportedValueProtoBytes},
	} {
		decoded, stats, err = DecodeNotification("switch-1", legacyNotification(test.encoding, []byte{1, 2, 3}, protoPath("value")), receipt)
		require.NoError(t, err)
		assert.Empty(t, decoded.Updates)
		assert.Equal(t, 1, stats.UnmappedValues)
		assert.Equal(t, map[UnsupportedValueKind]int{test.kind: 1}, stats.UnsupportedValueKinds)
	}

	unknown := legacyNotification(gnmipb.Encoding(99), []byte("value"), protoPath("value"))
	_, _, err = DecodeNotification("switch-1", unknown, receipt)
	require.ErrorContains(t, err, "legacy value has unknown encoding 99")

	precedence := legacyNotification(gnmipb.Encoding(99), []byte("ignored"), protoPath("value"))
	precedence.Update[0].Val = &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: 9}}
	decoded, _, err = DecodeNotification("switch-1", precedence, receipt)
	require.NoError(t, err)
	require.Len(t, decoded.Updates, 1)
	assert.Equal(t, IntValue(9), decoded.Updates[0].Value)
}

func TestMappingRegistryRequiresExplicitNumericContract(t *testing.T) {
	mapping := Mapping{
		Source:    SourcePath{Origin: "openconfig", Elements: []string{"interfaces", "interface", "state"}, Leaf: "temperature"},
		Metric:    MetricMetadata{Name: "cisco.optics.temperature", Description: "Module temperature.", Unit: "Cel"},
		Scale:     0.001,
		GaugeType: GaugeDouble,
		KeyAttributes: []KeyAttribute{{
			Element: "interface", Key: "name", Attribute: "network.interface.name",
		}},
	}
	registry, err := NewRegistry(mapping)
	require.NoError(t, err)
	point := Point{
		Series: Series{
			Target: "switch-1", Origin: "openconfig",
			Elements: []PathElem{{Name: "interfaces"}, {Name: "interface", Keys: map[string]string{"name": "Ethernet1"}}, {Name: "state"}},
			Leaf:     "temperature",
		},
		Value: IntValue(42_500), Timestamp: time.Unix(100, 0),
	}
	mapped, ok := registry.Map(point)
	require.True(t, ok)
	assert.Equal(t, "cisco.optics.temperature", mapped.Metric.Name)
	assert.Equal(t, "Cel", mapped.Metric.Unit)
	assert.Equal(t, 42.5, mapped.DoubleValue)
	assert.Equal(t, "Ethernet1", mapped.Attributes["network.interface.name"])

	ambiguousMapping := mapping
	ambiguousMapping.Source.Elements = []string{"interfaces", "interface", "interface", "state"}
	ambiguousRegistry, err := NewRegistry(ambiguousMapping)
	require.NoError(t, err)
	ambiguousPoint := point
	ambiguousPoint.Series.Elements = append(
		append([]PathElem(nil), point.Series.Elements[:2]...),
		PathElem{Name: "interface", Keys: map[string]string{"name": "Ethernet2"}},
		point.Series.Elements[2],
	)
	_, ok = ambiguousRegistry.Map(ambiguousPoint)
	assert.False(t, ok, "same-named elements carrying the same mapped key must not collapse to the first value")

	point.Series.Leaf = "unknown"
	_, ok = registry.Map(point)
	assert.False(t, ok)
	point.Series.Leaf = "temperature"
	point.Value = StringValue("42500")
	mapped, ok = registry.Map(point)
	require.True(t, ok, "explicit numeric mappings must accept RFC7951 string-encoded 64-bit and decimal values")
	assert.Equal(t, 42.5, mapped.DoubleValue)
	point.Value = StringValue("not-a-number")
	_, ok = registry.Map(point)
	assert.False(t, ok, "ordinary JSON strings must not be promoted")

	_, err = NewRegistry(Mapping{Source: mapping.Source, Metric: mapping.Metric, Scale: 1, GaugeType: "sum"})
	require.ErrorContains(t, err, "gauge type")
	_, err = NewRegistry(Mapping{Source: mapping.Source, Metric: MetricMetadata{Name: "bad", Unit: "1"}, Scale: 1, GaugeType: GaugeInt})
	require.ErrorContains(t, err, "description")
}

func TestMappingRegistryEnforcesSourceBoundsAndInvalidatesRejectedValue(t *testing.T) {
	registry, err := NewRegistry(Mapping{
		Source:       SourcePath{Origin: "rfc7951", Elements: []string{"system", "state"}, Leaf: "used-percent"},
		Metric:       MetricMetadata{Name: "system.memory.utilization", Description: "Memory utilization.", Unit: "1"},
		Scale:        .01,
		SourceBounds: &NumericBounds{Min: 0, Max: 100},
		GaugeType:    GaugeDouble,
	})
	require.NoError(t, err)
	series := Series{
		Target: "switch-1", Origin: "rfc7951",
		Elements: []PathElem{{Name: "system"}, {Name: "state"}},
		Leaf:     "used-percent",
	}
	for _, test := range []struct {
		name  string
		value Value
		want  float64
	}{
		{name: "minimum", value: UintValue(0), want: 0},
		{name: "maximum", value: UintValue(100), want: 1},
		{name: "RFC7951 uint64 string", value: StringValue("50"), want: .5},
	} {
		t.Run(test.name, func(t *testing.T) {
			mapped, status := registry.MapWithStatus(Point{Series: series, Value: test.value, Timestamp: time.Unix(1, 0)})
			require.Equal(t, MappingMapped, status)
			assert.Equal(t, test.want, mapped.DoubleValue)
		})
	}

	for _, test := range []struct {
		name  string
		value Value
	}{
		{name: "below minimum", value: IntValue(-1)},
		{name: "above maximum", value: UintValue(101)},
		{name: "boolean false is not a numeric zero", value: BoolValue(false)},
		{name: "boolean true is not a numeric one", value: BoolValue(true)},
		{name: "malformed string", value: StringValue("not-a-percent")},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, status := registry.MapWithStatus(Point{Series: series, Value: test.value, Timestamp: time.Unix(2, 0)})
			assert.Equal(t, MappingInvalidValue, status)
		})
	}

	cache, err := NewCache(4)
	require.NoError(t, err)
	good := DecodedNotification{Timestamp: time.Unix(1, 0), Updates: []Point{{
		Series: series, Value: UintValue(50), Timestamp: time.Unix(1, 0),
	}}}
	goodTransaction, stats := registry.MapNotification(good)
	require.Equal(t, MappingStats{Mapped: 1}, stats)
	_, err = cache.Apply(goodTransaction)
	require.NoError(t, err)
	require.Len(t, cache.Snapshot(), 1)

	rejected := DecodedNotification{Timestamp: time.Unix(2, 0), Updates: []Point{{
		Series: series, Value: UintValue(255), Timestamp: time.Unix(2, 0),
	}}}
	rejectedTransaction, stats := registry.MapNotification(rejected)
	require.Equal(t, MappingStats{Unmapped: 1}, stats)
	assert.Empty(t, rejectedTransaction.Updates)
	require.Len(t, rejectedTransaction.Invalidates, 1)
	_, err = cache.Apply(rejectedTransaction)
	require.NoError(t, err)
	assert.Empty(t, cache.Snapshot(), "an invalid newer utilization value must withdraw stale cached state")
	assert.Equal(t, 1, cache.Usage().InvalidationWatermarks)
}

func TestMappingRegistryMonotonicSumRejectsInvalidCounterValuesAndAllowsCorrection(t *testing.T) {
	mapping := Mapping{
		Source:     SourcePath{Origin: "rfc7951", Elements: []string{"interfaces", "interface", "state", "counters"}, Leaf: "in-octets"},
		Metric:     MetricMetadata{Name: "system.network.io", Description: "Interface bytes.", Unit: "By"},
		Scale:      1,
		GaugeType:  GaugeInt,
		MetricType: MetricSum,
		Monotonic:  true,
		KeyAttributes: []KeyAttribute{{
			Element: "interface", Key: "name", Attribute: "network.interface.name",
		}},
	}
	registry, err := NewRegistry(mapping)
	require.NoError(t, err)
	series := Series{
		Target: "switch-1", Origin: "rfc7951",
		Elements: []PathElem{
			{Name: "interfaces"},
			{Name: "interface", Keys: map[string]string{"name": "Ethernet1"}},
			{Name: "state"},
			{Name: "counters"},
		},
		Leaf: "in-octets",
	}

	for _, test := range []struct {
		name  string
		value Value
		want  int64
	}{
		{name: "zero signed", value: IntValue(0), want: 0},
		{name: "positive signed", value: IntValue(5), want: 5},
		{name: "positive unsigned", value: UintValue(6), want: 6},
		{name: "integral double", value: DoubleValue(7), want: 7},
		{name: "canonical RFC7951 uint64 string", value: StringValue("9007199254740993"), want: 9_007_199_254_740_993},
		{name: "RFC7951 positive-sign string", value: StringValue("+8"), want: 8},
		{name: "RFC7951 leading-zero string", value: StringValue("009"), want: 9},
	} {
		t.Run("accepts "+test.name, func(t *testing.T) {
			mapped, status := registry.MapWithStatus(Point{Series: series, Value: test.value})
			require.Equal(t, MappingMapped, status)
			assert.Equal(t, test.want, mapped.IntValue)
			assert.True(t, mapped.Monotonic)
			assert.Equal(t, MetricSum, mapped.MetricType)
		})
	}

	for _, test := range []struct {
		name  string
		value Value
	}{
		{name: "negative signed", value: IntValue(-1)},
		{name: "negative double", value: DoubleValue(-1)},
		{name: "negative string", value: StringValue("-1")},
		{name: "boolean false", value: BoolValue(false)},
		{name: "boolean true", value: BoolValue(true)},
		{name: "fractional double", value: DoubleValue(1.5)},
		{name: "fractional string", value: StringValue("1.0")},
		{name: "exponent string", value: StringValue("1e3")},
		{name: "negative zero string", value: StringValue("-0")},
		{name: "whitespace string", value: StringValue(" 1")},
		{name: "uint64 beyond OTLP int64 output", value: StringValue("18446744073709551615")},
		{name: "rounded int64 upper boundary", value: DoubleValue(float64(math.MaxInt64))},
	} {
		t.Run("rejects "+test.name, func(t *testing.T) {
			mapped, status := registry.MapWithStatus(Point{Series: series, Value: test.value})
			assert.Equal(t, MappingInvalidValue, status)
			assert.Equal(t, MappedPoint{}, mapped)
		})
	}

	t1 := time.Unix(100, 0)
	t2 := t1.Add(time.Second)
	cache, err := NewCache(4)
	require.NoError(t, err)
	seed, stats := registry.MapNotification(DecodedNotification{
		Timestamp: t1,
		Updates:   []Point{{Series: series, Value: UintValue(5), Timestamp: t1}},
	})
	require.Equal(t, MappingStats{Mapped: 1}, stats)
	_, err = cache.Apply(seed)
	require.NoError(t, err)
	require.Len(t, cache.Snapshot(), 1)

	withdrawal, stats := registry.MapNotification(DecodedNotification{
		Timestamp: t2,
		Updates:   []Point{{Series: series, Value: IntValue(-1), Timestamp: t2}},
	})
	require.Equal(t, MappingStats{Unmapped: 1}, stats)
	assert.Empty(t, withdrawal.Updates)
	require.Len(t, withdrawal.Invalidates, 1)
	assert.Equal(t, series.Path().Key(), withdrawal.Invalidates[0].Key())
	result, err := cache.Apply(withdrawal)
	require.NoError(t, err)
	require.Len(t, result.Removed, 1)
	assert.Empty(t, cache.Snapshot(), "a negative counter must withdraw the exact stale series")
	assert.Equal(t, 1, cache.Usage().InvalidationWatermarks)
	assert.False(t, cache.IsStale(series.Path(), t2),
		"the semantic watermark must admit a valid same-timestamp correction")

	correction, stats := registry.MapNotification(DecodedNotification{
		Timestamp: t2,
		Updates:   []Point{{Series: series, Value: UintValue(6), Timestamp: t2}},
	})
	require.Equal(t, MappingStats{Mapped: 1}, stats)
	result, err = cache.Apply(correction)
	require.NoError(t, err)
	require.Len(t, result.Applied, 1)
	snapshot := cache.Snapshot()
	require.Len(t, snapshot, 1)
	assert.Equal(t, int64(6), snapshot[0].IntValue)
	assert.Zero(t, cache.Usage().InvalidationWatermarks)
}

func TestMappingRegistryMonotonicSumRequiresPositiveScale(t *testing.T) {
	mapping := Mapping{
		Source:     SourcePath{Origin: "openconfig", Elements: []string{"system", "state"}, Leaf: "counter"},
		Metric:     MetricMetadata{Name: "example.counter", Description: "Example counter.", Unit: "{count}"},
		Scale:      -1,
		GaugeType:  GaugeInt,
		MetricType: MetricSum,
		Monotonic:  true,
	}
	_, err := NewRegistry(mapping)
	require.ErrorContains(t, err, "monotonic sum mapping scale must be positive")

	mapping.MetricType = MetricGauge
	mapping.Monotonic = false
	registry, err := NewRegistry(mapping)
	require.NoError(t, err, "negative scaling remains valid for a custom gauge contract")
	mapped, status := registry.MapWithStatus(Point{
		Series: Series{
			Target: "switch-1", Origin: "openconfig",
			Elements: []PathElem{{Name: "system"}, {Name: "state"}},
			Leaf:     "counter",
		},
		Value: IntValue(2),
	})
	require.Equal(t, MappingMapped, status)
	assert.Equal(t, int64(-2), mapped.IntValue)
}

func TestMappingRegistryInvalidatesUndecodableMappedSourceWithCorrectableWatermark(t *testing.T) {
	registry, err := NewRegistry(Mapping{
		Source:    SourcePath{Origin: "openconfig", Elements: []string{"system", "state"}, Leaf: "value"},
		Metric:    MetricMetadata{Name: "system.value", Description: "System value.", Unit: "1"},
		Scale:     1,
		GaugeType: GaugeDouble,
	})
	require.NoError(t, err)
	series := Series{
		Target: "switch-1", Origin: "openconfig",
		Elements: []PathElem{{Name: "system"}, {Name: "state"}},
		Leaf:     "value",
	}
	path := series.Path()
	t1 := time.Unix(100, 0)
	t2 := t1.Add(time.Second)

	cache, err := NewCache(4)
	require.NoError(t, err)
	seed, stats := registry.MapNotification(DecodedNotification{
		Timestamp: t1,
		Updates:   []Point{{Series: series, Value: UintValue(1), Timestamp: t1}},
	})
	require.Equal(t, MappingStats{Mapped: 1}, stats)
	_, err = cache.Apply(seed)
	require.NoError(t, err)
	require.Len(t, cache.Snapshot(), 1)

	withdrawal, stats := registry.MapNotification(DecodedNotification{
		Timestamp:   t2,
		Undecodable: []Path{path},
	})
	require.Equal(t, MappingStats{Unmapped: 1}, stats)
	require.Len(t, withdrawal.Invalidates, 1)
	result, err := cache.Apply(withdrawal)
	require.NoError(t, err)
	require.Len(t, result.Removed, 1)
	assert.Empty(t, cache.Snapshot())
	assert.Equal(t, 1, cache.Usage().InvalidationWatermarks)
	assert.True(t, cache.IsStale(path, t1))
	assert.False(t, cache.IsStale(path, t2))

	correction, stats := registry.MapNotification(DecodedNotification{
		Timestamp: t2,
		Updates:   []Point{{Series: series, Value: UintValue(2), Timestamp: t2}},
	})
	require.Equal(t, MappingStats{Mapped: 1}, stats)
	result, err = cache.Apply(correction)
	require.NoError(t, err)
	require.Len(t, result.Applied, 1)
	require.Len(t, cache.Snapshot(), 1)
	assert.Equal(t, 2.0, cache.Snapshot()[0].DoubleValue)
	assert.Zero(t, cache.Usage().InvalidationWatermarks)

	atomicBarrier, stats := registry.MapNotification(DecodedNotification{
		Prefix:      Path{Target: "switch-1", Origin: "openconfig", Elements: []PathElem{{Name: "system"}}},
		Timestamp:   t2.Add(time.Second),
		Atomic:      true,
		Undecodable: []Path{path},
	})
	require.Equal(t, MappingStats{Unmapped: 1}, stats)
	assert.False(t, atomicBarrier.Atomic)
	assert.Empty(t, atomicBarrier.Updates)
	require.Len(t, atomicBarrier.Invalidates, 1)
	assert.Equal(t, "system", atomicBarrier.Invalidates[0].Elements[0].Name)
}

func TestMappingRegistryRejectsInvalidSourceBounds(t *testing.T) {
	base := Mapping{
		Source:    SourcePath{Origin: "rfc7951", Elements: []string{"system", "state"}, Leaf: "value"},
		Metric:    MetricMetadata{Name: "example.value", Description: "Example value.", Unit: "1"},
		Scale:     1,
		GaugeType: GaugeDouble,
	}
	for _, bounds := range []*NumericBounds{
		{Min: math.NaN(), Max: 100},
		{Min: 0, Max: math.Inf(1)},
		{Min: 101, Max: 100},
	} {
		mapping := base
		mapping.SourceBounds = bounds
		_, err := NewRegistry(mapping)
		require.Error(t, err)
	}
}

func TestMappingRegistryRejectsMappingsThatCannotEnterTheBoundedCache(t *testing.T) {
	base := Mapping{
		Source:    SourcePath{Origin: "openconfig", Elements: []string{"system", "state"}, Leaf: "value"},
		Metric:    MetricMetadata{Name: "example.value", Description: "Example value.", Unit: "1"},
		Scale:     1,
		GaugeType: GaugeDouble,
	}

	exact := base
	exact.Metric = MetricMetadata{
		Name:        strings.Repeat("a", maxCachedMetricNameBytes),
		Description: strings.Repeat("d", maxCachedMetricDescriptionBytes),
		Unit:        strings.Repeat("u", maxCachedMetricUnitBytes),
	}
	exact.KeyAttributes = make([]KeyAttribute, maxCachedPointAttributes)
	for index := range exact.KeyAttributes {
		exact.KeyAttributes[index] = KeyAttribute{
			Element: "state", Key: fmt.Sprintf("key%d", index), Attribute: fmt.Sprintf("example.attribute.%d", index),
		}
	}
	_, err := NewRegistry(exact)
	require.NoError(t, err, "the exact cache payload boundaries must remain registrable")

	tests := []struct {
		name   string
		mutate func(*Mapping)
		want   string
	}{
		{name: "source element", mutate: func(mapping *Mapping) {
			mapping.Source.Elements[0] = strings.Repeat("e", maxPathNameBytes+1)
		}, want: "path element name exceeds 256 bytes"},
		{name: "source leaf", mutate: func(mapping *Mapping) {
			mapping.Source.Leaf = strings.Repeat("l", maxPathNameBytes+1)
		}, want: "path element name exceeds 256 bytes"},
		{name: "metric name", mutate: func(mapping *Mapping) {
			mapping.Metric.Name = strings.Repeat("n", maxCachedMetricNameBytes+1)
		}, want: "metric name exceeds 256 bytes"},
		{name: "description", mutate: func(mapping *Mapping) {
			mapping.Metric.Description = strings.Repeat("d", maxCachedMetricDescriptionBytes+1)
		}, want: "metric description exceeds 4096 bytes"},
		{name: "unit", mutate: func(mapping *Mapping) {
			mapping.Metric.Unit = strings.Repeat("u", maxCachedMetricUnitBytes+1)
		}, want: "metric unit exceeds 256 bytes"},
		{name: "attribute count", mutate: func(mapping *Mapping) {
			mapping.KeyAttributes = make([]KeyAttribute, maxCachedPointAttributes+1)
			for index := range mapping.KeyAttributes {
				mapping.KeyAttributes[index] = KeyAttribute{
					Element: "state", Key: fmt.Sprintf("key%d", index), Attribute: fmt.Sprintf("example.attribute.%d", index),
				}
			}
		}, want: "mapping exceeds 64 metric attributes"},
		{name: "attribute key", mutate: func(mapping *Mapping) {
			mapping.KeyAttributes = []KeyAttribute{{Element: "state", Key: strings.Repeat("k", maxPathNameBytes+1), Attribute: "example.name"}}
		}, want: "key attribute key exceeds 256 bytes"},
		{name: "attribute name", mutate: func(mapping *Mapping) {
			mapping.KeyAttributes = []KeyAttribute{{Element: "state", Key: "name", Attribute: strings.Repeat("a", maxPathNameBytes+1)}}
		}, want: "metric attribute name exceeds 256 bytes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mapping := base
			mapping.Source.Elements = append([]string(nil), base.Source.Elements...)
			test.mutate(&mapping)
			_, err := NewRegistry(mapping)
			require.ErrorContains(t, err, test.want)
		})
	}
}

func TestMappingRegistryPreservesRFC7951IntegerStringPrecision(t *testing.T) {
	registry, err := NewRegistry(Mapping{
		Source: SourcePath{Origin: "rfc7951", Elements: []string{"system", "state"}, Leaf: "counter"},
		Metric: MetricMetadata{Name: "example.counter", Description: "Example counter.", Unit: "{count}"},
		Scale:  1, GaugeType: GaugeInt,
	})
	require.NoError(t, err)
	point := Point{
		Series: Series{Target: "switch-1", Origin: "rfc7951", Elements: []PathElem{{Name: "system"}, {Name: "state"}}, Leaf: "counter"},
		Value:  StringValue("9007199254740993"), Timestamp: time.Unix(100, 0),
	}
	mapped, ok := registry.Map(point)
	require.True(t, ok)
	assert.Equal(t, int64(9_007_199_254_740_993), mapped.IntValue)
}

func TestScaledIntValueRejectsRoundedUpperBoundary(t *testing.T) {
	value, ok := scaledIntValue(DoubleValue(float64(math.MaxInt64)), 1)
	assert.False(t, ok)
	assert.Zero(t, value)

	value, ok = scaledIntValue(IntValue(math.MaxInt64), 1)
	require.True(t, ok, "an exact int64 input must retain the valid maximum")
	assert.Equal(t, int64(math.MaxInt64), value)
}

func TestMappingRegistryIntegerGaugeAndNotificationStats(t *testing.T) {
	mapping := Mapping{
		Source:    SourcePath{Origin: "openconfig", Elements: []string{"components", "component", "state"}, Leaf: "present"},
		Metric:    MetricMetadata{Name: "cisco.optics.present", Description: "Optic presence.", Unit: "1"},
		Scale:     1,
		GaugeType: GaugeInt,
		KeyAttributes: []KeyAttribute{{
			Element: "component", Key: "name", Attribute: "hw.name",
		}},
	}
	registry, err := NewRegistry(mapping)
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)
	present := Point{
		Series: Series{Target: "switch-1", Origin: "openconfig", Elements: []PathElem{
			{Name: "components"}, {Name: "component", Keys: map[string]string{"name": "Ethernet1"}}, {Name: "state"},
		}, Leaf: "present"},
		Value: BoolValue(true), Timestamp: timestamp,
	}
	unmapped := present
	unmapped.Series.Leaf = "description"
	unmapped.Value = StringValue("optic")
	prefix, err := ParsePath("switch-1", "openconfig", "components")
	require.NoError(t, err)
	touched := present.Series.Path()
	transaction, stats := registry.MapNotification(DecodedNotification{
		Prefix: prefix, Timestamp: timestamp, Touched: []Path{touched}, Updates: []Point{present, unmapped}, Deletes: []Path{prefix},
	})
	assert.Equal(t, MappingStats{Mapped: 1, Unmapped: 1}, stats)
	require.Len(t, transaction.Updates, 1)
	assert.Equal(t, int64(1), transaction.Updates[0].IntValue)
	assert.Equal(t, "Ethernet1", transaction.Updates[0].Attributes["hw.name"])
	require.Len(t, transaction.Deletes, 1)
	require.Len(t, transaction.Touched, 1)
	assert.Equal(t, touched.Key(), transaction.Touched[0].Key())
}

func TestUnsupportedWireTouchInvalidatesOverlappingAtomicBaseline(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	baselineTimestamp := receipt.Add(-2 * time.Minute)
	updateTimestamp := receipt.Add(-time.Minute)
	baseline, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]/state")
	require.NoError(t, err)
	cache, err := NewCache(10)
	require.NoError(t, err)
	_, err = cache.Apply(CacheNotification{Prefix: baseline, Timestamp: baselineTimestamp, Atomic: true})
	require.NoError(t, err)

	decoded, stats, err := DecodeNotification("switch-1", unsupportedInterfaceNotification("Ethernet1", updateTimestamp), receipt)
	require.NoError(t, err)
	assert.Equal(t, 1, stats.UnmappedValues)
	assert.Empty(t, decoded.Updates)
	require.Len(t, decoded.Touched, 1)
	assert.True(t, decoded.Touched[0].HasPrefix(baseline))

	registry, err := NewRegistry()
	require.NoError(t, err)
	transaction, mappingStats := registry.MapNotification(decoded)
	assert.Equal(t, MappingStats{}, mappingStats)
	result, err := cache.Apply(transaction)
	require.NoError(t, err)
	assert.Equal(t, 1, result.AtomicBaselinesInvalidated)
	_, exists := cache.AtomicBaseline(baseline)
	assert.False(t, exists, "an unsupported wire value still touches and invalidates its overlapping atomic baseline")
}

func TestUnsupportedWireTouchDoesNotInvalidateKeyedSiblingAtomicBaseline(t *testing.T) {
	receipt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	baselineTimestamp := receipt.Add(-2 * time.Minute)
	updateTimestamp := receipt.Add(-time.Minute)
	baseline, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]/state")
	require.NoError(t, err)
	cache, err := NewCache(10)
	require.NoError(t, err)
	_, err = cache.Apply(CacheNotification{Prefix: baseline, Timestamp: baselineTimestamp, Atomic: true})
	require.NoError(t, err)

	decoded, stats, err := DecodeNotification("switch-1", unsupportedInterfaceNotification("Ethernet2", updateTimestamp), receipt)
	require.NoError(t, err)
	assert.Equal(t, 1, stats.UnmappedValues)
	assert.Empty(t, decoded.Updates)
	require.Len(t, decoded.Touched, 1)
	assert.False(t, pathsOverlap(decoded.Touched[0], baseline))

	registry, err := NewRegistry()
	require.NoError(t, err)
	transaction, mappingStats := registry.MapNotification(decoded)
	assert.Equal(t, MappingStats{}, mappingStats)
	result, err := cache.Apply(transaction)
	require.NoError(t, err)
	assert.Zero(t, result.AtomicBaselinesInvalidated)
	timestamp, exists := cache.AtomicBaseline(baseline)
	require.True(t, exists, "an unsupported keyed sibling must not invalidate the baseline")
	assert.Equal(t, baselineTimestamp, timestamp)
}

func unsupportedInterfaceNotification(name string, timestamp time.Time) *gnmipb.Notification {
	return &gnmipb.Notification{
		Timestamp: timestamp.UnixNano(),
		Prefix: &gnmipb.Path{Origin: "openconfig", Elem: []*gnmipb.PathElem{
			{Name: "interfaces"},
		}},
		Update: []*gnmipb.Update{{
			Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{
				{Name: "interface", Key: map[string]string{"name": name}},
				{Name: "state"},
				{Name: "vendor-binary"},
			}},
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_ProtoBytes{ProtoBytes: []byte{1, 2, 3}}},
		}},
	}
}

func protoPath(names ...string) *gnmipb.Path {
	path := &gnmipb.Path{}
	for _, name := range names {
		path.Elem = append(path.Elem, &gnmipb.PathElem{Name: name})
	}
	return path
}
