// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi

import (
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeJSONListSchemaIsExactToOriginAndElementPath(t *testing.T) {
	receipt := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	schema, err := NewJSONListKeySchema(JSONListKeySpec{
		Origin:   "openconfig",
		Elements: []string{"root", "payload", "interfaces", "interface"},
		Keys:     []string{"name"},
	})
	require.NoError(t, err)
	notification := &gnmipb.Notification{
		Timestamp: receipt.UnixNano(),
		Prefix: &gnmipb.Path{
			Origin: "openconfig",
			Elem:   []*gnmipb.PathElem{{Name: "root"}},
		},
		Update: []*gnmipb.Update{{
			Path: protoPath("payload"),
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{
				"interfaces":{"interface":[{"name":"Ethernet1","state":{"counter":10}}]}
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
	assert.Equal(t, int64(10), counters[0].Value.Int)
	assert.Equal(t, "Ethernet1", counters[0].Series.Elements[3].Keys["name"])

	notification.Prefix.Origin = "vendor-origin"
	_, _, err = DecodeNotificationWithSchema("switch-1", notification, receipt, schema)
	require.ErrorContains(t, err, "list identity is absent from the catalog schema",
		"an identical element path under another origin must not use the declaration")
}

func TestDecodeJSONArrayWithoutSchemaRemainsUnmapped(t *testing.T) {
	receipt := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	decoded, stats, err := DecodeNotification("switch-1", &gnmipb.Notification{
		Timestamp: receipt.UnixNano(),
		Prefix:    protoPath("root"),
		Update: []*gnmipb.Update{{
			Path: protoPath("interfaces"),
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonVal{JsonVal: []byte(`{
				"interface":[
					{"name":"Ethernet1","state":{"counter":10}},
					{"name":"Ethernet2","state":{"counter":20}}
				]
			}`)}},
		}},
	}, receipt)
	require.NoError(t, err)
	assert.Empty(t, decoded.Updates, "unidentified list objects must not collapse onto an unkeyed series")
	require.Len(t, decoded.Touched, 1, "the unsupported JSON array still touched its wire update path")
	assert.Equal(t, 4, stats.UnmappedValues)
}

func TestDecodeJSONListSchemaRejectsNonScalarKeyWithoutPartialSuccess(t *testing.T) {
	receipt := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
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
				"interface":[{"name":{"unexpected":"object"},"state":{"counter":10}}]
			}`)}},
		}},
	}, receipt, schema)
	require.ErrorContains(t, err, `list key "name" has a non-scalar value`)
	assert.Empty(t, decoded.Updates)
	assert.Empty(t, decoded.Touched)
}

func TestJSONListKeySchemaCopiesCallerOwnedDefinitions(t *testing.T) {
	receipt := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	spec := JSONListKeySpec{
		Elements: []string{"root", "interface"},
		Keys:     []string{"name"},
	}
	schema, err := NewJSONListKeySchema(spec)
	require.NoError(t, err)
	spec.Elements[0] = "mutated"
	spec.Keys[0] = "mutated"

	decoded, _, err := DecodeNotificationWithSchema("switch-1", &gnmipb.Notification{
		Timestamp: receipt.UnixNano(),
		Prefix:    protoPath("root"),
		Update: []*gnmipb.Update{{
			Path: &gnmipb.Path{},
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{
				"interface":[{"name":"Ethernet1","counter":10}]
			}`)}},
		}},
	}, receipt, schema)
	require.NoError(t, err)
	var counter Point
	for _, point := range decoded.Updates {
		if point.Series.Leaf == "counter" {
			counter = point
		}
	}
	assert.Equal(t, "Ethernet1", counter.Series.Elements[1].Keys["name"])
}

func TestNewJSONListKeySchemaValidatesDefinitions(t *testing.T) {
	_, err := NewJSONListKeySchema(JSONListKeySpec{})
	require.ErrorContains(t, err, "empty element path")

	_, err = NewJSONListKeySchema(JSONListKeySpec{Elements: []string{"root", "item"}})
	require.ErrorContains(t, err, "has no keys")

	_, err = NewJSONListKeySchema(JSONListKeySpec{Elements: []string{"root", "item"}, Keys: []string{"id", "id"}})
	require.ErrorContains(t, err, `duplicates key "id"`)

	_, err = NewJSONListKeySchema(
		JSONListKeySpec{Origin: "openconfig", Elements: []string{"root", "item"}, Keys: []string{"id"}},
		JSONListKeySpec{Origin: "openconfig", Elements: []string{"root", "item"}, Keys: []string{"name"}},
	)
	require.ErrorContains(t, err, "duplicates origin and element path")
}

func TestDecodeNotificationWithSchemaRejectsUndeclaredJSONList(t *testing.T) {
	schema, err := NewJSONListKeySchema()
	require.NoError(t, err)
	notification := &gnmipb.Notification{
		Prefix: &gnmipb.Path{Origin: "openconfig-interfaces", Elem: []*gnmipb.PathElem{{Name: "interfaces"}}},
		Update: []*gnmipb.Update{{
			Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "interface"}}},
			Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`[{"name":"Ethernet1"}]`)}},
		}},
	}
	_, _, err = DecodeNotificationWithSchema("switch-1", notification, time.Now(), schema)
	require.ErrorContains(t, err, "list identity is absent from the catalog schema")

	_, stats, err := DecodeNotification("switch-1", notification, time.Now())
	require.NoError(t, err)
	assert.Equal(t, 1, stats.UnmappedValues, "schema-neutral callers continue to account for unsupported lists")
}

func TestDecodeNotificationWithSchemaRejectsOpaqueTypedValue(t *testing.T) {
	schema, err := NewJSONListKeySchema()
	require.NoError(t, err)
	notification := &gnmipb.Notification{Update: []*gnmipb.Update{{
		Path: &gnmipb.Path{Origin: "vendor", Elem: []*gnmipb.PathElem{{Name: "opaque"}}},
		Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_ProtoBytes{ProtoBytes: []byte{1, 2, 3}}},
	}}}
	_, _, err = DecodeNotificationWithSchema("switch-1", notification, time.Now(), schema)
	require.ErrorContains(t, err, "has no declared decoder")
}

func TestDecodeNotificationRejectsDuplicateJSONObjectMembers(t *testing.T) {
	schema, err := NewJSONListKeySchema(JSONListKeySpec{
		Elements: []string{"root", "interface"}, Keys: []string{"name"},
	})
	require.NoError(t, err)
	for name, payload := range map[string]string{
		"object leaf": `{"state":{"counter":1,"counter":2}}`,
		"list key":    `{"interface":[{"name":"Ethernet1","name":"Ethernet2","counter":1}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			notification := &gnmipb.Notification{
				Prefix: protoPath("root"),
				Update: []*gnmipb.Update{{
					Path: &gnmipb.Path{},
					Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(payload)}},
				}},
			}
			decoded, _, err := DecodeNotificationWithSchema("switch-1", notification, time.Now(), schema)
			require.ErrorContains(t, err, "duplicate JSON object member")
			assert.Empty(t, decoded.Updates)
			assert.Empty(t, decoded.Touched)
		})
	}
}
