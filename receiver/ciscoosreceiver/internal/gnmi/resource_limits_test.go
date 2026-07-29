// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi

import (
	"fmt"
	"strings"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeNotificationRejectsUnsafeWirePaths(t *testing.T) {
	timestamp := time.Unix(100, 0)
	scalar := &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: 1}}
	pathWithElements := func(count int) *gnmipb.Path {
		path := &gnmipb.Path{}
		for index := range count {
			path.Elem = append(path.Elem, &gnmipb.PathElem{Name: fmt.Sprintf("element-%d", index)})
		}
		return path
	}
	pathWithKeys := func(count int, value string) *gnmipb.Path {
		keys := make(map[string]string, count)
		for index := range count {
			keys[fmt.Sprintf("key-%02d", index)] = value
		}
		return &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "list", Key: keys}, {Name: "value"}}}
	}

	tests := []struct {
		name          string
		prefix        *gnmipb.Path
		update        *gnmipb.Path
		errorContains string
	}{
		{name: "depth", update: pathWithElements(maxPathDepth + 1), errorContains: "exceeds 128 elements"},
		{name: "joined depth", prefix: pathWithElements(maxPathDepth), update: protoPath("value"), errorContains: "exceeds 128 elements"},
		{name: "element name", update: protoPath(strings.Repeat("n", maxPathNameBytes+1)), errorContains: "element name exceeds 256 bytes"},
		{name: "key name", update: &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "list", Key: map[string]string{strings.Repeat("k", maxPathNameBytes+1): "v"}}, {Name: "value"}}}, errorContains: "key name exceeds 256 bytes"},
		{name: "key count", update: pathWithKeys(maxPathKeysPerElement+1, "v"), errorContains: "exceeds 64 keys"},
		{name: "key value", update: pathWithKeys(1, strings.Repeat("v", maxPathKeyValueBytes+1)), errorContains: "value exceeds 4096 bytes"},
		{name: "canonical bytes", update: func() *gnmipb.Path {
			path := &gnmipb.Path{}
			for index := range 20 {
				keys := make(map[string]string, maxPathKeysPerElement)
				for keyIndex := range maxPathKeysPerElement {
					keys[fmt.Sprintf("key-%02d", keyIndex)] = strings.Repeat("v", 64)
				}
				path.Elem = append(path.Elem, &gnmipb.PathElem{Name: fmt.Sprintf("list-%d", index), Key: keys})
			}
			return path
		}(), errorContains: "exceeds 65536 canonical bytes"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prefix := test.prefix
			if prefix == nil {
				prefix = protoPath("root")
			}
			_, _, err := DecodeNotification("switch-1", &gnmipb.Notification{
				Timestamp: timestamp.UnixNano(),
				Prefix:    prefix,
				Update:    []*gnmipb.Update{{Path: test.update, Val: scalar}},
			}, timestamp)
			require.ErrorContains(t, err, test.errorContains)
		})
	}
}

func TestDecodeNotificationEnforcesAggregateLimits(t *testing.T) {
	timestamp := time.Unix(100, 0)
	base := defaultNotificationDecodeLimits()

	t.Run("wire operations", func(t *testing.T) {
		limits := base
		limits.maxWireOperations = 2
		_, _, err := decodeNotificationWithLimits("switch-1", &gnmipb.Notification{
			Prefix: protoPath("root"),
			Update: []*gnmipb.Update{
				{Path: protoPath("one")},
				{Path: protoPath("two")},
			},
			Delete: []*gnmipb.Path{protoPath("old")},
		}, timestamp, limits)
		require.ErrorContains(t, err, "exceeds 2 wire operations")
	})

	t.Run("decoded points", func(t *testing.T) {
		limits := base
		limits.maxPoints = 2
		_, _, err := decodeNotificationWithLimits("switch-1", &gnmipb.Notification{
			Prefix: protoPath("root"),
			Update: []*gnmipb.Update{{
				Path: protoPath("state"),
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{"one":1,"two":2,"three":3}`)}},
			}},
		}, timestamp, limits)
		require.ErrorContains(t, err, "exceeds 2 points")
	})

	t.Run("decoded and undecodable points share one limit", func(t *testing.T) {
		limits := base
		limits.maxPoints = 1
		_, _, err := decodeNotificationWithLimits("switch-1", &gnmipb.Notification{
			Prefix: protoPath("root"),
			Update: []*gnmipb.Update{{
				Path: protoPath("state"),
				Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(
					`{"invalid":null,"valid":1}`,
				)}},
			}},
		}, timestamp, limits)
		require.ErrorContains(t, err, "exceeds 1 points")
	})

	t.Run("empty JSON descendants consume invalid path cardinality", func(t *testing.T) {
		limits := base
		limits.maxPoints = 1
		_, _, err := decodeNotificationWithLimits("switch-1", &gnmipb.Notification{
			Prefix: protoPath("root"),
			Update: []*gnmipb.Update{{
				Path: protoPath("state"),
				Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(
					`{"empty-list":[],"empty-object":{}}`,
				)}},
			}},
		}, timestamp, limits)
		require.ErrorContains(t, err, "exceeds 1 points")
	})

	t.Run("exact mapped container mismatch shares the point limit", func(t *testing.T) {
		limits := base
		limits.maxPoints = 1
		registry, err := NewRegistry(Mapping{
			Source:    SourcePath{Origin: "openconfig", Elements: []string{"root"}, Leaf: "value"},
			Metric:    MetricMetadata{Name: "root.value", Description: "Root value.", Unit: "1"},
			Scale:     1,
			GaugeType: GaugeInt,
		})
		require.NoError(t, err)
		_, _, err = decodeNotificationWithOptions("switch-1", &gnmipb.Notification{
			Prefix: &gnmipb.Path{Origin: "openconfig", Elem: []*gnmipb.PathElem{{Name: "root"}}},
			Update: []*gnmipb.Update{{
				Path: protoPath("value"),
				Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{
					JsonIetfVal: []byte(`{"child":1}`),
				}},
			}},
		}, timestamp, limits, registry.jsonListKeys, registry)
		require.ErrorContains(t, err, "exceeds 1 points")
	})

	t.Run("path and string bytes", func(t *testing.T) {
		limits := base
		limits.maxPathStringBytes = 512
		_, _, err := decodeNotificationWithLimits("switch-1", &gnmipb.Notification{
			Prefix: protoPath("root"),
			Update: []*gnmipb.Update{{
				Path: protoPath("description"),
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: strings.Repeat("v", 512)}},
			}},
		}, timestamp, limits)
		require.ErrorContains(t, err, "aggregate path/string bytes")
	})

	t.Run("JSON nodes across values including leaf lists", func(t *testing.T) {
		limits := base
		limits.maxJSONNodes = 7
		jsonValue := &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`[null,1,"two"]`)}}
		_, _, err := decodeNotificationWithLimits("switch-1", &gnmipb.Notification{
			Prefix: protoPath("root"),
			Update: []*gnmipb.Update{
				{Path: protoPath("first"), Val: jsonValue},
				{Path: protoPath("second"), Val: jsonValue},
			},
		}, timestamp, limits)
		require.ErrorContains(t, err, "exceeds 7 JSON nodes")
	})
}

func TestDecodeNotificationRejectsProductionWireOperationOverflow(t *testing.T) {
	updates := make([]*gnmipb.Update, maxNotificationWireOperations+1)
	_, _, err := DecodeNotification("switch-1", &gnmipb.Notification{Update: updates}, time.Unix(100, 0))
	require.ErrorContains(t, err, "exceeds 100000 wire operations")
}

func TestCacheRetainedByteLimitIsTransactional(t *testing.T) {
	timestamp := time.Unix(100, 0)
	first := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, timestamp)
	firstBytes := estimateCacheEntryRetainedBytes(first.Key(), first)
	cache, err := NewCacheWithLimits(10, firstBytes)
	require.NoError(t, err)

	_, err = cache.Apply(CacheNotification{Timestamp: timestamp, Updates: []MappedPoint{first}})
	require.NoError(t, err)
	assert.Equal(t, firstBytes, cache.RetainedBytes())

	second := testMappedPoint("switch-1", "Ethernet2", "temperature", 42, timestamp.Add(time.Second))
	_, err = cache.Apply(CacheNotification{Timestamp: second.Timestamp, Updates: []MappedPoint{second}})
	var capacity *CapacityError
	require.ErrorAs(t, err, &capacity)
	assert.Equal(t, firstBytes, capacity.RetainedByteLimit)
	assert.Equal(t, firstBytes, capacity.CurrentRetainedBytes)
	assert.Greater(t, capacity.RequestedRetainedBytes, capacity.RetainedByteLimit)
	assert.Equal(t, firstBytes, cache.RetainedBytes())
	snapshot := cache.Snapshot()
	require.Len(t, snapshot, 1)
	assert.Equal(t, "Ethernet1", snapshot[0].Attributes["network.interface.name"])
}

func TestCacheRejectsUnsafeUpdatePayloadBeforeMutation(t *testing.T) {
	timestamp := time.Unix(100, 0)
	cache, err := NewCache(10)
	require.NoError(t, err)
	first := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, timestamp)
	_, err = cache.Apply(CacheNotification{Timestamp: timestamp, Updates: []MappedPoint{first}})
	require.NoError(t, err)
	beforeBytes := cache.RetainedBytes()

	invalid := testMappedPoint("switch-1", "Ethernet2", "temperature", 42, timestamp.Add(time.Second))
	invalid.Attributes["oversized"] = strings.Repeat("v", maxPathKeyValueBytes+1)
	_, err = cache.Apply(CacheNotification{
		Timestamp: invalid.Timestamp,
		Updates: []MappedPoint{
			testMappedPoint("switch-1", "Ethernet3", "temperature", 43, invalid.Timestamp),
			invalid,
		},
	})
	require.ErrorContains(t, err, "attribute \"oversized\" value exceeds 4096 bytes")
	assert.Equal(t, beforeBytes, cache.RetainedBytes())
	snapshot := cache.Snapshot()
	require.Len(t, snapshot, 1)
	assert.Equal(t, "Ethernet1", snapshot[0].Attributes["network.interface.name"])
}

func TestCacheRejectsInvalidPathBeforeMutation(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	invalid := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, time.Unix(100, 0))
	invalid.Source.Elements[1].Keys["name"] = strings.Repeat("x", maxPathKeyValueBytes+1)
	_, err = cache.Apply(CacheNotification{Timestamp: invalid.Timestamp, Updates: []MappedPoint{invalid}})
	require.ErrorContains(t, err, "value exceeds 4096 bytes")
	assert.Zero(t, cache.StateLen())
	assert.Zero(t, cache.RetainedBytes())
}

func TestCacheRetainedByteAccountingTracksEveryStateKind(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	prefix := testInterfacePrefix()
	timestamp := time.Unix(100, 0)
	first := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, timestamp)

	_, err = cache.Apply(CacheNotification{
		Prefix: prefix, Timestamp: timestamp, Atomic: true, Updates: []MappedPoint{first},
	})
	require.NoError(t, err)
	assertCacheRetainedByteInvariant(t, cache)

	secondTimestamp := timestamp.Add(time.Second)
	second := testMappedPoint("switch-1", "Ethernet2", "temperature", 42, secondTimestamp)
	_, err = cache.Apply(CacheNotification{
		Prefix: prefix, Timestamp: secondTimestamp, Atomic: true, Updates: []MappedPoint{second},
	})
	require.NoError(t, err)
	assertCacheRetainedByteInvariant(t, cache)

	deleteTimestamp := secondTimestamp.Add(time.Second)
	_, err = cache.Apply(CacheNotification{Timestamp: deleteTimestamp, Deletes: []Path{second.Source.Path()}})
	require.NoError(t, err)
	assertCacheRetainedByteInvariant(t, cache)

	second.Timestamp = deleteTimestamp.Add(time.Second)
	_, err = cache.Apply(CacheNotification{Timestamp: second.Timestamp, Updates: []MappedPoint{second}})
	require.NoError(t, err)
	assertCacheRetainedByteInvariant(t, cache)
}

func assertCacheRetainedByteInvariant(t *testing.T, cache *Cache) {
	t.Helper()
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	var expected int64
	for key := range cache.entries {
		expected += cache.entries[key].retainedBytes
	}
	for key := range cache.atomic {
		expected += cache.atomic[key].retainedBytes
	}
	for key := range cache.tombstone {
		expected += cache.tombstone[key].retainedBytes
	}
	expected += cache.ownerIndexRetainedBytesLocked()
	assert.Equal(t, expected, cache.retainedBytes)
}

func TestCacheFullActiveSeriesCapacityRejectsNewDeleteAndInvalidationState(t *testing.T) {
	timestamp := time.Unix(100, 0)
	point := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, timestamp)
	unmatchedDelete, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet2]/state/enabled")
	require.NoError(t, err)
	unmatchedInvalidation, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet3]/state/oper-status")
	require.NoError(t, err)

	for _, test := range []struct {
		name         string
		notification CacheNotification
	}{
		{
			name: "authoritative delete tombstone",
			notification: CacheNotification{
				OwnerID: "owner-a", Timestamp: timestamp.Add(time.Second), Deletes: []Path{unmatchedDelete},
			},
		},
		{
			name: "semantic invalidation watermark",
			notification: CacheNotification{
				OwnerID: "owner-a", Timestamp: timestamp.Add(time.Second), Invalidates: []Path{unmatchedInvalidation},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache, cacheErr := NewCache(1)
			require.NoError(t, cacheErr)
			_, cacheErr = cache.Apply(CacheNotification{
				OwnerID: "owner-a", Timestamp: timestamp, Updates: []MappedPoint{point},
			})
			require.NoError(t, cacheErr)
			beforeBytes := cache.RetainedBytes()

			_, cacheErr = cache.Apply(test.notification)
			var capacity *CapacityError
			require.ErrorAs(t, cacheErr, &capacity)
			assert.Equal(t, 1, capacity.Limit)
			assert.Equal(t, 2, capacity.Requested)
			assert.Equal(t, CacheUsage{Entries: 1, Total: 1, Limit: 1}, cache.Usage())
			assert.Equal(t, beforeBytes, cache.RetainedBytes())
			assertCacheRetainedByteInvariant(t, cache)
		})
	}
}
