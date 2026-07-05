// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheSelectorPlanCollapsesDuplicatesAndDescendants(t *testing.T) {
	broad, err := ParsePath("switch-1", "openconfig", "interfaces/interface")
	require.NoError(t, err)
	narrow, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]/state")
	require.NoError(t, err)
	unrelated, err := ParsePath("switch-1", "openconfig", "system/state")
	require.NoError(t, err)
	plan, err := buildCacheSelectorPlan([]Path{narrow, broad, narrow, broad, unrelated})
	require.NoError(t, err)

	require.Len(t, plan.selectors, 2)
	assert.True(t, plan.index.selects(narrow))
	assert.True(t, plan.index.selects(unrelated))
	assert.False(t, plan.index.selects(Path{Target: "switch-2", Origin: "openconfig", Elements: narrow.Elements}))
	assert.True(t, plan.index.overlaps(broad))
}

func TestCacheSelectorPlanBoundsAdversarialKeySubsetTraversal(t *testing.T) {
	const (
		subsetSelectors = 2_500
		fullSelectors   = 2_500
		keyCount        = 12
	)
	paths := make([]Path, 0, subsetSelectors+fullSelectors)
	path := func(keys map[string]string, suffix string) Path {
		return Path{
			Target: "switch-1", Origin: "openconfig",
			Elements: []PathElem{
				{Name: "interface", Keys: keys},
				{Name: suffix},
			},
		}
	}
	for mask := range subsetSelectors {
		keys := make(map[string]string, keyCount)
		for keyIndex := range keyCount {
			if mask&(1<<keyIndex) != 0 {
				keys[fmt.Sprintf("k%02d", keyIndex)] = "v"
			}
		}
		paths = append(paths, path(keys, fmt.Sprintf("seed-%d", mask)))
	}
	fullKeys := make(map[string]string, keyCount)
	for keyIndex := range keyCount {
		fullKeys[fmt.Sprintf("k%02d", keyIndex)] = "v"
	}
	for index := range fullSelectors {
		paths = append(paths, path(fullKeys, fmt.Sprintf("query-%d", index)))
	}

	plan, err := buildCacheSelectorPlan(paths)
	require.ErrorContains(t, err, "cache selector planning work exceeds 5000000 comparisons")
	assert.Empty(t, plan.selectors)
}

func TestCacheDuplicateDeletesMatchSingleDeleteSemantics(t *testing.T) {
	t1 := time.Unix(100, 0)
	t2 := t1.Add(time.Second)
	prefix, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]")
	require.NoError(t, err)
	point := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	newPopulatedCache := func() *Cache {
		cache, cacheErr := NewCache(20)
		require.NoError(t, cacheErr)
		_, cacheErr = cache.Apply(CacheNotification{
			Prefix: prefix, Timestamp: t1, Atomic: true, Updates: []MappedPoint{point},
		})
		require.NoError(t, cacheErr)
		return cache
	}

	single := newPopulatedCache()
	singleResult, err := single.Apply(CacheNotification{Timestamp: t2, Deletes: []Path{prefix}})
	require.NoError(t, err)

	duplicates := newPopulatedCache()
	duplicateResult, err := duplicates.Apply(CacheNotification{
		Timestamp: t2,
		Deletes:   []Path{prefix, prefix.Clone(), prefix.Clone(), prefix.Clone()},
	})
	require.NoError(t, err)

	assert.Equal(t, singleResult, duplicateResult)
	assert.Equal(t, single.Usage(), duplicates.Usage())
	assert.Equal(t, single.RetainedBytes(), duplicates.RetainedBytes())
	assert.Equal(t, single.Snapshot(), duplicates.Snapshot())
	assert.Equal(t, 1, duplicateResult.AtomicBaselinesInvalidated)
}

func TestCacheAdversarialDuplicateDeletePlanScansRetainedStateOnce(t *testing.T) {
	const (
		entries   = 2_500
		deleteOps = 20_000
	)
	t1 := time.Unix(100, 0)
	t2 := t1.Add(time.Second)
	cache, err := NewCache(entries + 10)
	require.NoError(t, err)
	points := make([]MappedPoint, 0, entries)
	for index := range entries {
		points = append(points, testMappedPoint(
			"switch-1", fmt.Sprintf("Ethernet%d", index), "temperature", float64(index), t1,
		))
	}
	_, err = cache.Apply(CacheNotification{Timestamp: t1, Updates: points})
	require.NoError(t, err)
	broad, err := ParsePath("switch-1", "openconfig", "interfaces")
	require.NoError(t, err)
	narrow, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]")
	require.NoError(t, err)
	deletes := make([]Path, 0, deleteOps)
	for index := range deleteOps {
		if index%2 == 0 {
			deletes = append(deletes, narrow)
		} else {
			deletes = append(deletes, broad)
		}
	}

	result, err := cache.Apply(CacheNotification{Timestamp: t2, Deletes: deletes})
	require.NoError(t, err)
	assert.Len(t, result.Removed, entries)
	assert.Zero(t, result.OutOfOrder)
	assert.Zero(t, cache.Len())
	assert.Equal(t, 1, cache.Usage().Tombstones)
}

func TestCacheRemovalPathsUseStagedSelectorWithoutRetainedCrossProduct(t *testing.T) {
	const retained = 2_500
	assert.Greater(t, retained*retained, maxCachePlanningComparisons,
		"the fixture must exceed the work ceiling if removals query every retained tombstone")
	t1 := time.Unix(100, 0)
	t2 := t1.Add(time.Second)
	cache, err := NewCache(2*retained + 10)
	require.NoError(t, err)
	for index := range retained {
		path := Path{
			Target: "switch-1", Origin: "openconfig",
			Elements: []PathElem{{Name: "interfaces"}, {Name: "deleted", Keys: map[string]string{"id": fmt.Sprintf("%d", index)}}},
		}
		key := path.Key()
		tombstone := stateTombstone{path: path, timestamp: t1, retainedBytes: estimateTombstoneRetainedBytes(key, path)}
		cache.putTombstone(tombstone)
		cache.retainedBytes = saturatingRetainedByteAdd(cache.retainedBytes, tombstone.retainedBytes)
	}
	for index := range retained {
		point := testMappedPoint("switch-1", fmt.Sprintf("Ethernet%d", index), "temperature", float64(index), t1)
		key := point.Key()
		entry := cacheEntry{point: point, retainedBytes: estimateCacheEntryRetainedBytes(key, point)}
		cache.entries[key] = entry
		cache.retainedBytes = saturatingRetainedByteAdd(cache.retainedBytes, entry.retainedBytes)
	}
	selector, err := ParsePath("switch-1", "openconfig", "interfaces")
	require.NoError(t, err)

	result, err := cache.Apply(CacheNotification{Timestamp: t2, Deletes: []Path{selector}})
	require.NoError(t, err)
	assert.Len(t, result.Removed, retained)
	assert.Equal(t, CacheUsage{Tombstones: 1, Total: 1, Limit: 2*retained + 10}, cache.Usage())
}

func TestCacheNotificationOperationLimitRejectsBeforeMutation(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)
	point := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, timestamp)
	_, err = cache.Apply(CacheNotification{Timestamp: timestamp, Updates: []MappedPoint{point}})
	require.NoError(t, err)
	before := cache.Snapshot()

	_, err = cache.Apply(CacheNotification{
		Timestamp: timestamp.Add(time.Second),
		Deletes:   make([]Path, maxNotificationWireOperations+1),
	})
	require.ErrorContains(t, err, "exceeds 100000 touched/delete operations")
	assert.Equal(t, before, cache.Snapshot())
}

func TestCacheNotificationStagedByteLimitRejectsBeforeMutation(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)
	committed := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, timestamp)
	_, err = cache.Apply(CacheNotification{Timestamp: timestamp, Updates: []MappedPoint{committed}})
	require.NoError(t, err)
	before := cache.Snapshot()

	large := testMappedPoint("switch-1", "Ethernet2", "temperature", 42, timestamp.Add(time.Second))
	large.Attributes["payload"] = strings.Repeat("v", maxPathKeyValueBytes)
	updates := make([]MappedPoint, 8_200)
	for index := range updates {
		updates[index] = large
	}
	_, err = cache.Apply(CacheNotification{Timestamp: large.Timestamp, Updates: updates})
	require.ErrorContains(t, err, "exceeds 33554432 staged bytes")
	assert.Equal(t, before, cache.Snapshot())
}

func TestCachePlanningWorkLimitRejectsKeyedSelectorCrossProduct(t *testing.T) {
	const (
		baselines = 1_000
		selectors = maxCachePlanningComparisons/baselines + 1
	)
	cache, err := NewCache(baselines + 10)
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)
	for index := range baselines {
		path := Path{
			Target: "switch-1", Origin: "openconfig",
			Elements: []PathElem{{Name: "interfaces"}, {Name: "interface", Keys: map[string]string{"z": fmt.Sprintf("%d", index)}}},
		}
		cache.atomic[path.Key()] = atomicBaseline{prefix: path, timestamp: timestamp}
	}
	touched := make([]Path, selectors)
	for index := range touched {
		touched[index] = Path{
			Target: "switch-1", Origin: "openconfig",
			Elements: []PathElem{{Name: "interfaces"}, {Name: "interface", Keys: map[string]string{"a": fmt.Sprintf("%d", index)}}},
		}
	}

	transaction, err := cache.Prepare(CacheNotification{Timestamp: timestamp.Add(time.Second), Touched: touched})
	require.Nil(t, transaction)
	require.ErrorContains(t, err, "planning work exceeds 5000000 comparisons")
	assert.Equal(t, baselines, cache.Usage().AtomicBaselines)
}

func TestCacheStructuralPlanningBoundsKeySubsetTrieWork(t *testing.T) {
	const (
		keyCount        = 6
		keysPerSelector = 3
		entries         = 200
		structuralLimit = 20_000
	)
	allKeys := make(map[string]string, keyCount)
	keyNames := make([]string, keyCount)
	for keyIndex := range keyCount {
		keyNames[keyIndex] = fmt.Sprintf("k%02d", keyIndex)
		allKeys[keyNames[keyIndex]] = "v"
	}
	var selectors []Path
	var appendCombinations func(start int, selected []string)
	appendCombinations = func(start int, selected []string) {
		if len(selected) == keysPerSelector {
			keys := make(map[string]string, len(selected))
			for _, key := range selected {
				keys[key] = "v"
			}
			selectors = append(selectors, Path{
				Target: "switch-1", Origin: "openconfig",
				Elements: []PathElem{
					{Name: "list", Keys: keys},
					{Name: fmt.Sprintf("selector-%03d", len(selectors))},
				},
			})
			return
		}
		for index := start; index <= len(keyNames)-(keysPerSelector-len(selected)); index++ {
			appendCombinations(index+1, append(selected, keyNames[index]))
		}
	}
	appendCombinations(0, nil)
	require.Len(t, selectors, 20)
	plan, err := buildCacheSelectorPlan(selectors)
	require.NoError(t, err)
	require.Len(t, plan.selectors, len(selectors), "the keyed selectors form an antichain")

	// Selector staging alone remains below the small test ceiling. Retained
	// entries use every key but a different suffix, forcing each lookup to walk
	// every matching key-subset branch before it can report no match.
	empty, err := NewCache(100)
	require.NoError(t, err)
	transaction, err := empty.prepare(CacheNotification{
		Timestamp: time.Unix(200, 0), Deletes: selectors,
	}, structuralLimit)
	require.NoError(t, err)
	transaction.Rollback()

	cache, err := NewCache(entries + 100)
	require.NoError(t, err)
	querySource := Series{
		Target: "switch-1", Origin: "openconfig",
		Elements: []PathElem{{Name: "list", Keys: allKeys}},
		Leaf:     "retained",
	}
	for entryIndex := range entries {
		point := MappedPoint{
			Source: querySource,
			Metric: MetricMetadata{
				Name:        fmt.Sprintf("adversarial.metric.%d", entryIndex),
				Description: "Adversarial structural planning fixture.",
				Unit:        "1",
			},
			GaugeType: GaugeInt,
			Timestamp: time.Unix(100, 0),
		}
		key := point.Key()
		entry := cacheEntry{point: point, retainedBytes: estimateCacheEntryRetainedBytes(key, point)}
		cache.entries[key] = entry
		cache.retainedBytes = saturatingRetainedByteAdd(cache.retainedBytes, entry.retainedBytes)
	}
	beforeSnapshot := cache.Snapshot()
	beforeUsage := cache.Usage()
	beforeBytes := cache.RetainedBytes()

	transaction, err = cache.prepare(CacheNotification{
		Timestamp: time.Unix(200, 0), Deletes: selectors,
	}, structuralLimit)
	require.Nil(t, transaction)
	require.ErrorContains(t, err, "cache structural planning work exceeds 20000 operations")
	assert.Equal(t, beforeSnapshot, cache.Snapshot())
	assert.Equal(t, beforeUsage, cache.Usage())
	assert.Equal(t, beforeBytes, cache.RetainedBytes())
}

func TestCacheStructuralPlanningChargesRetainedSeriesPathMaterialization(t *testing.T) {
	const (
		entries         = 10
		elementsPerPath = maxPathDepth - 1
		keysPerElement  = 8
		structuralLimit = 5_000
	)
	timestamp := time.Unix(100, 0)
	selector := Path{
		Target: "switch-1", Origin: "openconfig",
		Elements: []PathElem{{Name: "does-not-match"}},
	}
	notification := CacheNotification{
		Timestamp: timestamp.Add(time.Second),
		Deletes:   []Path{selector},
	}

	empty, err := NewCache(100)
	require.NoError(t, err)
	transaction, err := empty.prepare(notification, structuralLimit)
	require.NoError(t, err, "selector staging itself must fit under the test budget")
	transaction.Rollback()

	cache, err := NewCache(entries + 100)
	require.NoError(t, err)
	keys := make(map[string]string, keysPerElement)
	for keyIndex := range keysPerElement {
		keys[fmt.Sprintf("key-%d", keyIndex)] = "value"
	}
	elements := make([]PathElem, elementsPerPath)
	for elementIndex := range elements {
		elements[elementIndex] = PathElem{
			Name: fmt.Sprintf("deep-%03d", elementIndex),
			Keys: keys,
		}
	}
	for entryIndex := range entries {
		point := MappedPoint{
			Source: Series{
				Target: "switch-1", Origin: "openconfig", Elements: elements, Leaf: "value",
			},
			Metric: MetricMetadata{
				Name: fmt.Sprintf("deep.metric.%d", entryIndex), Description: "Deep retained path.", Unit: "1",
			},
			GaugeType: GaugeInt,
			Timestamp: timestamp,
		}
		key := point.Key()
		entry := cacheEntry{point: point, retainedBytes: estimateCacheEntryRetainedBytes(key, point)}
		cache.entries[key] = entry
		cache.retainedBytes = saturatingRetainedByteAdd(cache.retainedBytes, entry.retainedBytes)
	}
	beforeSnapshot := cache.Snapshot()
	beforeUsage := cache.Usage()
	beforeBytes := cache.RetainedBytes()

	transaction, err = cache.prepare(notification, structuralLimit)
	require.Nil(t, transaction)
	require.ErrorContains(t, err, "cache structural planning work exceeds 5000 operations")
	assert.Equal(t, beforeSnapshot, cache.Snapshot())
	assert.Equal(t, beforeUsage, cache.Usage())
	assert.Equal(t, beforeBytes, cache.RetainedBytes())
}

func TestCacheRetainedEstimatorsChargeSparseBucketsAndKeyedTombstoneTrie(t *testing.T) {
	oneEntryMapBytes := estimateStringMapRetainedBytes(map[string]string{"k": "v"})
	assert.GreaterOrEqual(t, oneEntryMapBytes, int64(370),
		"one string-map entry must include a complete 64-bit runtime bucket")

	unkeyed, err := ParsePath("switch-1", "openconfig", "interfaces/interface")
	require.NoError(t, err)
	keyed, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]")
	require.NoError(t, err)
	unkeyedBytes := estimateTombstoneRetainedBytes(unkeyed.Key(), unkeyed)
	keyedBytes := estimateTombstoneRetainedBytes(keyed.Key(), keyed)
	assert.GreaterOrEqual(t, keyedBytes, int64(3_000),
		"a keyed tombstone must include path storage and its structural trie maps/nodes")
	assert.GreaterOrEqual(t, keyedBytes-unkeyedBytes, int64(1_100),
		"one key constraint must include its path map bucket and both trie maps plus node")

	cache, err := NewCacheWithLimits(10, keyedBytes-1)
	require.NoError(t, err)
	_, err = cache.Apply(CacheNotification{Timestamp: time.Unix(100, 0), Deletes: []Path{keyed}})
	var capacity *CapacityError
	require.ErrorAs(t, err, &capacity)
	assert.Equal(t, keyedBytes, capacity.RequestedRetainedBytes)
}

func TestTombstoneRetainedEstimatorChargesCompositeScopeKey(t *testing.T) {
	path := Path{
		Target:     "configured-target",
		PathTarget: "wire-path-target",
		Origin:     "openconfig",
		Elements:   []PathElem{{Name: "system"}},
	}
	scopeKey := tombstoneScopeKey(path.Target, path.PathTarget)
	assert.Equal(t, retainedStringBytes(scopeKey), estimateTombstoneScopeKeyRetainedBytes(path))

	key := path.Key()
	withoutScopeKey := retainedCacheMapEntryBytes + retainedStringBytes(key)
	withoutScopeKey = saturatingRetainedByteAdd(withoutScopeKey, estimatePathRetainedBytes(path))
	withoutScopeKey = saturatingRetainedByteAdd(
		withoutScopeKey,
		retainedTombstoneRootIndexBytes+retainedTombstonePathElementBytes,
	)
	assert.Equal(
		t,
		saturatingRetainedByteAdd(withoutScopeKey, retainedStringBytes(scopeKey)),
		estimateTombstoneRetainedBytes(key, path),
	)
}
