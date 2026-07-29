// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

func TestNormalizeGNMIStateValuesUsesLeafSpecificEnums(t *testing.T) {
	tests := []struct {
		name, leaf, raw string
		want            bool
	}{
		{name: "oper up", leaf: "oper-status", raw: "UP", want: true},
		{name: "oper down", leaf: "oper_status", raw: "DOWN"},
		{name: "oper testing", leaf: "oper-status", raw: "TESTING"},
		{name: "oper unknown", leaf: "oper-status", raw: "UNKNOWN"},
		{name: "oper dormant", leaf: "oper-status", raw: "DORMANT"},
		{name: "oper not present", leaf: "oper-status", raw: "NOT_PRESENT"},
		{name: "oper lower layer down", leaf: "oper-status", raw: "LOWER_LAYER_DOWN"},
		{name: "oper qualified mixed case", leaf: "oper-status", raw: " openconfig-interfaces:up ", want: true},
		{name: "oper qualified hyphenated", leaf: "oper-status", raw: "openconfig-interfaces:lower-layer-down"},
		{name: "admin up", leaf: "admin-status", raw: "UP", want: true},
		{name: "admin down", leaf: "admin-status", raw: "DOWN"},
		{name: "admin testing", leaf: "admin_status", raw: "TESTING"},
		{name: "present compatibility", leaf: "present", raw: "present", want: true},
		{name: "absent compatibility", leaf: "present", raw: "not-present"},
		{name: "joined compatibility", leaf: "is-joined", raw: "joined", want: true},
		{name: "not joined compatibility", leaf: "is_joined", raw: "not joined"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			notification := internalgnmi.DecodedNotification{Updates: []internalgnmi.Point{{
				Series: testGNMIStateSeries(test.leaf),
				Value:  internalgnmi.StringValue(test.raw),
			}}}
			normalizeGNMIStateValues(&notification)
			require.Len(t, notification.Updates, 1)
			assert.Equal(t, internalgnmi.BoolValue(test.want), notification.Updates[0].Value)
		})
	}
}

func TestNormalizeGNMIStateValuesInvalidatesUnknownAndNonStringInterfaceStatus(t *testing.T) {
	values := []internalgnmi.Value{
		internalgnmi.StringValue("FUTURE_STATE"),
		internalgnmi.StringValue("1"),
		internalgnmi.StringValue("evil:UP"),
		internalgnmi.StringValue("evil::UP"),
		internalgnmi.StringValue("openconfig-interfaces::UP"),
		internalgnmi.IntValue(1),
		internalgnmi.UintValue(1),
		internalgnmi.DoubleValue(1),
		internalgnmi.BoolValue(true),
	}
	for _, value := range values {
		t.Run(stateValueName(value), func(t *testing.T) {
			notification := internalgnmi.DecodedNotification{Updates: []internalgnmi.Point{{
				Series: testGNMIStateSeries("oper-status"),
				Value:  value,
			}}}
			invalidated := normalizeGNMIStateValues(&notification)
			assert.Equal(t, internalgnmi.Value{}, notification.Updates[0].Value)
			assert.Empty(t, notification.Deletes,
				"local semantic rejection must not claim an authoritative device deletion")
			require.Len(t, invalidated, 1)
			assert.Equal(t, notification.Updates[0].Series.Path().Key(), invalidated[0].Key())
		})
	}
}

func TestNormalizeGNMIStateValuesPreservesNativeNonInterfaceScalars(t *testing.T) {
	for _, value := range []internalgnmi.Value{internalgnmi.BoolValue(true), internalgnmi.IntValue(1)} {
		notification := internalgnmi.DecodedNotification{Updates: []internalgnmi.Point{{
			Series: internalgnmi.Series{Leaf: "present"},
			Value:  value,
		}}}
		normalizeGNMIStateValues(&notification)
		assert.Equal(t, value, notification.Updates[0].Value)
		assert.Empty(t, notification.Deletes)
	}
}

func TestNormalizeGNMIStateValuesPreservesCustomStatusScalars(t *testing.T) {
	for _, value := range []internalgnmi.Value{
		internalgnmi.IntValue(7),
		internalgnmi.UintValue(8),
		internalgnmi.StringValue("UP"),
	} {
		notification := internalgnmi.DecodedNotification{Updates: []internalgnmi.Point{{
			Series: internalgnmi.Series{
				Target: "switch",
				Origin: builtinGNMIOriginRFC7951,
				Elements: []internalgnmi.PathElem{
					{Name: "example-custom:interfaces"},
					{Name: "interface", Keys: map[string]string{"name": "custom-1"}},
					{Name: "state"},
				},
				Leaf: "oper-status",
			},
			Value: value,
		}}}
		invalidated := normalizeGNMIStateValues(&notification)
		assert.Equal(t, value, notification.Updates[0].Value,
			"a proprietary same-named leaf is outside the curated interface metric contract")
		assert.Empty(t, invalidated)
		assert.Empty(t, notification.Deletes)
	}
}

func TestNormalizeGNMIStateValuesRejectsUnaddressableInterfaceStatus(t *testing.T) {
	for _, test := range []struct {
		name string
		keys map[string]string
	}{
		{name: "missing key"},
		{name: "empty name", keys: map[string]string{"name": ""}},
	} {
		t.Run(test.name, func(t *testing.T) {
			notification := interfaceOperStateNotification("UP", time.Unix(1, 0))
			notification.Updates[0].Series.Elements[1].Keys = test.keys
			notification.Updates[0].Value = internalgnmi.IntValue(6)
			invalidated, malformed := normalizeGNMIStateValuesChecked(&notification)
			assert.True(t, malformed)
			assert.Equal(t, internalgnmi.Value{}, notification.Updates[0].Value)
			assert.Empty(t, invalidated,
				"an unaddressable list path must never become a wildcard cache invalidation")
		})
	}
}

func TestNormalizeGNMIStateValuesCanonicalizesMalformedStatusSelector(t *testing.T) {
	notification := interfaceOperStateNotification("UP", time.Unix(2, 0))
	notification.Updates[0].Series.Elements[0].Keys = map[string]string{"unexpected": "root"}
	notification.Updates[0].Series.Elements[1].Keys["index"] = "1"
	notification.Updates[0].Series.Elements[2].Keys = map[string]string{"unexpected": "state"}
	notification.Updates[0].Value = internalgnmi.IntValue(6)

	invalidated, malformed := normalizeGNMIStateValuesChecked(&notification)
	assert.False(t, malformed)
	require.Len(t, invalidated, 1)
	assert.Equal(t, internalgnmi.Path{
		Target: "switch",
		Origin: builtinGNMIOriginRFC7951,
		Elements: []internalgnmi.PathElem{
			{Name: "openconfig-interfaces:interfaces"},
			{Name: "interface", Keys: map[string]string{"name": "GigabitEthernet1/0/1"}},
			{Name: "state"},
			{Name: "oper-status"},
		},
	}, invalidated[0])
}

func TestNormalizeGNMIStateValuesUnaddressableMalformedPathCannotEvictInterfaceSiblings(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9300, "17.18.1")
	require.NoError(t, err)
	profile, ok := builtinGNMIProfile(contract, builtinGNMIProfileInterfaces)
	require.True(t, ok)
	mappings := make([]internalgnmi.Mapping, 0, len(profile.Paths[0].Mappings))
	for _, catalogMapping := range profile.Paths[0].Mappings {
		mappings = append(mappings, catalogMapping.Mapping)
	}
	registry, err := internalgnmi.NewRegistry(mappings...)
	require.NoError(t, err)
	cache, err := internalgnmi.NewCache(4)
	require.NoError(t, err)

	for index, name := range []string{"GigabitEthernet1/0/1", "GigabitEthernet1/0/2"} {
		notification := interfaceOperStateNotification("UP", time.Unix(1, int64(index)))
		notification.Updates[0].Series.Elements[1].Keys["name"] = name
		assert.Empty(t, normalizeGNMIStateValues(&notification))
		mapped, stats := registry.MapNotification(notification)
		assert.Equal(t, internalgnmi.MappingStats{Mapped: 1}, stats)
		_, err = cache.Apply(mapped)
		require.NoError(t, err)
	}
	require.Len(t, cache.Snapshot(), 2)

	for _, keys := range []map[string]string{nil, {"name": ""}} {
		malformed := interfaceOperStateNotification("UP", time.Unix(2, 0))
		malformed.Updates[0].Series.Elements[1].Keys = keys
		malformed.Updates[0].Value = internalgnmi.IntValue(6)
		invalidated, malformedPath := normalizeGNMIStateValuesChecked(&malformed)
		assert.True(t, malformedPath)
		assert.Empty(t, invalidated)
		mapped, stats := registry.MapNotification(malformed)
		assert.Equal(t, internalgnmi.MappingStats{Unmapped: 1}, stats)
		_, err = cache.Apply(mapped)
		require.NoError(t, err)
		assert.Len(t, cache.Snapshot(), 2,
			"an unaddressable list path must not act as a wildcard selector over cached interface siblings")
	}
}

func TestNormalizeGNMIStateValuesClearsCachedUpForEveryDefinedNonUpOperState(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9300, "17.18.1")
	require.NoError(t, err)
	profile, ok := builtinGNMIProfile(contract, builtinGNMIProfileInterfaces)
	require.True(t, ok)
	require.Len(t, profile.Paths, 1)
	mappings := make([]internalgnmi.Mapping, 0, len(profile.Paths[0].Mappings))
	for _, catalogMapping := range profile.Paths[0].Mappings {
		mappings = append(mappings, catalogMapping.Mapping)
	}
	registry, err := internalgnmi.NewRegistry(mappings...)
	require.NoError(t, err)

	for _, state := range []string{"DOWN", "TESTING", "UNKNOWN", "DORMANT", "NOT_PRESENT", "LOWER_LAYER_DOWN"} {
		t.Run(state, func(t *testing.T) {
			cache, cacheErr := internalgnmi.NewCache(4)
			require.NoError(t, cacheErr)
			first := interfaceOperStateNotification("UP", time.Unix(1, 0))
			normalizeGNMIStateValues(&first)
			firstMapped, stats := registry.MapNotification(first)
			assert.Equal(t, internalgnmi.MappingStats{Mapped: 1}, stats)
			firstResult, applyErr := cache.Apply(firstMapped)
			require.NoError(t, applyErr)
			require.Len(t, firstResult.Applied, 1)
			assert.Equal(t, int64(1), firstResult.Applied[0].IntValue)

			second := interfaceOperStateNotification(state, time.Unix(2, 0))
			normalizeGNMIStateValues(&second)
			secondMapped, stats := registry.MapNotification(second)
			assert.Equal(t, internalgnmi.MappingStats{Mapped: 1}, stats)
			secondResult, applyErr := cache.Apply(secondMapped)
			require.NoError(t, applyErr)
			require.Len(t, secondResult.Applied, 1)
			assert.Equal(t, int64(0), secondResult.Applied[0].IntValue)
			require.Len(t, cache.Snapshot(), 1)
			assert.Equal(t, int64(0), cache.Snapshot()[0].IntValue)
		})
	}
}

func TestNormalizeGNMIStateValuesWithdrawsCachedStatusForMalformedRepresentation(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9300, "17.18.1")
	require.NoError(t, err)
	profile, ok := builtinGNMIProfile(contract, builtinGNMIProfileInterfaces)
	require.True(t, ok)
	mappings := make([]internalgnmi.Mapping, 0, len(profile.Paths[0].Mappings))
	for _, catalogMapping := range profile.Paths[0].Mappings {
		mappings = append(mappings, catalogMapping.Mapping)
	}
	registry, err := internalgnmi.NewRegistry(mappings...)
	require.NoError(t, err)

	for _, value := range []internalgnmi.Value{internalgnmi.IntValue(6), internalgnmi.StringValue("FUTURE_STATE")} {
		t.Run(stateValueName(value), func(t *testing.T) {
			cache, cacheErr := internalgnmi.NewCache(4)
			require.NoError(t, cacheErr)
			first := interfaceOperStateNotification("UP", time.Unix(1, 0))
			normalizeGNMIStateValues(&first)
			firstMapped, stats := registry.MapNotification(first)
			assert.Equal(t, internalgnmi.MappingStats{Mapped: 1}, stats)
			_, applyErr := cache.Apply(firstMapped)
			require.NoError(t, applyErr)
			require.Len(t, cache.Snapshot(), 1)

			second := interfaceOperStateNotification("UP", time.Unix(2, 0))
			second.Updates[0].Value = value
			invalidated := normalizeGNMIStateValues(&second)
			secondMapped, stats := registry.MapNotification(second)
			assert.Equal(t, internalgnmi.MappingStats{Unmapped: 1}, stats)
			assert.Empty(t, secondMapped.Updates, "malformed status must never emit a non-binary datapoint")
			require.Len(t, invalidated, 1)
			secondMapped.Invalidates = invalidated
			_, applyErr = cache.Apply(secondMapped)
			require.NoError(t, applyErr)
			assert.Empty(t, cache.Snapshot(), "malformed status must withdraw a previously cached UP value")
			assert.Zero(t, cache.Usage().Tombstones,
				"semantic withdrawal must not block a valid same-timestamp correction")
			assert.Equal(t, 1, cache.Usage().InvalidationWatermarks)

			correction := interfaceOperStateNotification("UP", time.Unix(2, 0))
			assert.Empty(t, normalizeGNMIStateValues(&correction))
			correctionMapped, stats := registry.MapNotification(correction)
			assert.Equal(t, internalgnmi.MappingStats{Mapped: 1}, stats)
			correctionResult, applyErr := cache.Apply(correctionMapped)
			require.NoError(t, applyErr)
			require.Len(t, correctionResult.Applied, 1)
			assert.Zero(t, correctionResult.Duplicates)
			assert.Zero(t, correctionResult.OutOfOrder)
			require.Len(t, cache.Snapshot(), 1)
			assert.Equal(t, int64(1), cache.Snapshot()[0].IntValue)
			assert.Zero(t, cache.Usage().InvalidationWatermarks)
		})
	}
}

func TestNormalizeGNMIStateValuesExtraKeysCannotBypassMalformedStatusWithdrawal(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9300, "17.18.1")
	require.NoError(t, err)
	profile, ok := builtinGNMIProfile(contract, builtinGNMIProfileInterfaces)
	require.True(t, ok)
	mappings := make([]internalgnmi.Mapping, 0, len(profile.Paths[0].Mappings))
	for _, catalogMapping := range profile.Paths[0].Mappings {
		mappings = append(mappings, catalogMapping.Mapping)
	}
	registry, err := internalgnmi.NewRegistry(mappings...)
	require.NoError(t, err)
	cache, err := internalgnmi.NewCache(4)
	require.NoError(t, err)

	valid := interfaceOperStateNotification("UP", time.Unix(1, 0))
	normalizeGNMIStateValues(&valid)
	mapped, stats := registry.MapNotification(valid)
	require.Equal(t, internalgnmi.MappingStats{Mapped: 1}, stats)
	_, err = cache.Apply(mapped)
	require.NoError(t, err)

	malformed := interfaceOperStateNotification("UP", time.Unix(2, 0))
	malformed.Updates[0].Series.Elements[0].Keys = map[string]string{"unexpected": "root"}
	malformed.Updates[0].Series.Elements[1].Keys["index"] = "1"
	malformed.Updates[0].Series.Elements[2].Keys = map[string]string{"unexpected": "state"}
	malformed.Updates[0].Value = internalgnmi.UintValue(6)
	invalidated, malformedPath := normalizeGNMIStateValuesChecked(&malformed)
	assert.False(t, malformedPath)
	require.Len(t, invalidated, 1)
	mapped, stats = registry.MapNotification(malformed)
	assert.Equal(t, internalgnmi.MappingStats{Unmapped: 1}, stats)
	mapped.Invalidates = invalidated
	_, err = cache.Apply(mapped)
	require.NoError(t, err)
	assert.Empty(t, cache.Snapshot(),
		"unexpected keys must neither emit a numeric status nor prevent canonical stale-state withdrawal")
	assert.Equal(t, 1, cache.Usage().InvalidationWatermarks)
}

func testGNMIStateSeries(leaf string) internalgnmi.Series {
	series := interfaceOperStateNotification("UP", time.Unix(1, 0)).Updates[0].Series
	series.Leaf = leaf
	return series
}

func interfaceOperStateNotification(value string, timestamp time.Time) internalgnmi.DecodedNotification {
	point := internalgnmi.Point{
		Series: internalgnmi.Series{
			Target: "switch",
			Origin: builtinGNMIOriginRFC7951,
			Elements: []internalgnmi.PathElem{
				{Name: "openconfig-interfaces:interfaces"},
				{Name: "interface", Keys: map[string]string{"name": "GigabitEthernet1/0/1"}},
				{Name: "state"},
			},
			Leaf: "oper-status",
		},
		Value:     internalgnmi.StringValue(value),
		Timestamp: timestamp,
	}
	return internalgnmi.DecodedNotification{
		Prefix:    internalgnmi.Path{Target: "switch", Origin: builtinGNMIOriginRFC7951},
		Timestamp: timestamp,
		Touched:   []internalgnmi.Path{point.Series.Path()},
		Updates:   []internalgnmi.Point{point},
	}
}

func stateValueName(value internalgnmi.Value) string {
	switch value.Kind {
	case internalgnmi.ValueInt:
		return "int"
	case internalgnmi.ValueUint:
		return "uint"
	case internalgnmi.ValueDouble:
		return "double"
	case internalgnmi.ValueBool:
		return "bool"
	case internalgnmi.ValueString:
		return "string_" + value.String
	default:
		return "invalid"
	}
}
