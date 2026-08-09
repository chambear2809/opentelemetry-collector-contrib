// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCachePreparedReplacementRollbackAllowsEqualTimestampRedelivery(t *testing.T) {
	cache, err := NewCache(20)
	require.NoError(t, err)
	t1 := time.Unix(100, 0)
	t2 := t1.Add(time.Second)
	prefix := testInterfacePrefix()
	one := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	two := testMappedPoint("switch-1", "Ethernet2", "temperature", 42, t1)
	_, err = cache.Apply(CacheNotification{Prefix: prefix, Timestamp: t1, Updates: []MappedPoint{one, two}})
	require.NoError(t, err)
	beforeSnapshot := cache.Snapshot()
	beforeUsage := cache.Usage()
	beforeBytes := cache.RetainedBytes()

	replacement := testMappedPoint("switch-1", "Ethernet3", "temperature", 43, t2)
	notification := CacheNotification{
		Prefix: prefix, Timestamp: t2, Atomic: true, Updates: []MappedPoint{replacement},
	}
	transaction, err := cache.Prepare(notification)
	require.NoError(t, err)
	prepared := transaction.Result()
	require.Len(t, prepared.Applied, 1)
	require.Len(t, prepared.Removed, 2)
	assert.False(t, prepared.Rejected)
	transaction.Rollback()
	transaction.Rollback()
	transaction.Commit()

	assert.Equal(t, beforeSnapshot, cache.Snapshot())
	assert.Equal(t, beforeUsage, cache.Usage())
	assert.Equal(t, beforeBytes, cache.RetainedBytes())
	_, exists := cache.AtomicBaseline(prefix)
	assert.False(t, exists)

	redelivery, err := cache.Prepare(notification)
	require.NoError(t, err)
	assert.False(t, redelivery.Result().Rejected, "rollback must not turn equal-timestamp redelivery into a duplicate")
	redelivery.Commit()

	snapshot := cache.Snapshot()
	require.Len(t, snapshot, 1)
	assert.Equal(t, "Ethernet3", snapshot[0].Attributes["network.interface.name"])
	baseline, exists := cache.AtomicBaseline(prefix)
	require.True(t, exists)
	assert.Equal(t, t2, baseline)
}

func TestCacheIsStaleBatchReturnsConsistentTimestampedResults(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)
	selector, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]")
	require.NoError(t, err)
	_, err = cache.Apply(CacheNotification{Timestamp: timestamp, Deletes: []Path{selector}})
	require.NoError(t, err)
	child, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]/state/temperature")
	require.NoError(t, err)
	sibling, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet2]/state/temperature")
	require.NoError(t, err)

	results, err := cache.IsStaleBatch([]StaleQuery{
		{Path: child, Timestamp: timestamp.Add(-time.Second)},
		{Path: child, Timestamp: timestamp},
		{Path: child, Timestamp: timestamp.Add(time.Second)},
		{Path: sibling, Timestamp: timestamp},
	})
	require.NoError(t, err)
	assert.Equal(t, []bool{true, true, false, false}, results)
}

func TestCacheIsStaleBatchStructuralFailureReturnsNoPartialResults(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)
	selector, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]")
	require.NoError(t, err)
	_, err = cache.Apply(CacheNotification{Timestamp: timestamp, Deletes: []Path{selector}})
	require.NoError(t, err)
	child, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]/state/temperature")
	require.NoError(t, err)
	queries := []StaleQuery{
		{Path: child, Timestamp: timestamp},
		{Path: child, Timestamp: timestamp},
	}
	beforeUsage := cache.Usage()
	beforeBytes := cache.RetainedBytes()

	results, err := cache.isStaleBatch(queries, 1)
	assert.Nil(t, results, "a bounded batch must never expose a partially filled result")
	require.ErrorContains(t, err, "cache structural planning work exceeds 1 operations")
	assert.Equal(t, beforeUsage, cache.Usage())
	assert.Equal(t, beforeBytes, cache.RetainedBytes())

	oneQueryLimit := 1
	for ; oneQueryLimit < 1_000; oneQueryLimit++ {
		results, err = cache.isStaleBatch(queries[:1], oneQueryLimit)
		if err == nil {
			break
		}
	}
	require.Less(t, oneQueryLimit, 1_000)
	assert.Equal(t, []bool{true}, results)
	results, err = cache.isStaleBatch(queries, oneQueryLimit)
	assert.Nil(t, results, "two queries must share one cumulative structural budget")
	require.ErrorContains(t, err, fmt.Sprintf("cache structural planning work exceeds %d operations", oneQueryLimit))

	results, err = cache.IsStaleBatch(queries)
	require.NoError(t, err, "one exhausted batch must not retain budget state")
	assert.Equal(t, []bool{true, true}, results)
}
