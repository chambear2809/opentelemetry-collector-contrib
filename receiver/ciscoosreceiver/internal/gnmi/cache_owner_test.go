// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheOwnerResetTransactionConcurrentCommitAndRollbackIsSafe(t *testing.T) {
	for range 100 {
		cache, err := NewCache(10)
		require.NoError(t, err)
		point := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, time.Unix(100, 0))
		_, err = cache.Apply(CacheNotification{OwnerID: "owner-a", Timestamp: point.Timestamp, Updates: []MappedPoint{point}})
		require.NoError(t, err)
		transaction, err := cache.PrepareResetOwner("owner-a")
		require.NoError(t, err)

		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			transaction.Commit()
		}()
		go func() {
			defer wait.Done()
			<-start
			transaction.Rollback()
		}()
		close(start)
		wait.Wait()

		assert.LessOrEqual(t, cache.Len(), 1)
		assertCacheRetainedByteInvariant(t, cache)
		transaction.Commit()
		transaction.Rollback()
	}
}

func TestCacheResetOwnerRemovesOnlyAttributedState(t *testing.T) {
	cache, err := NewCache(20)
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)
	ownedPrefix := testInterfacePrefix()
	deleted, err := ParsePath("switch-1", "openconfig", "system/obsolete")
	require.NoError(t, err)
	owned := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, timestamp)
	retained := testMappedPoint("switch-1", "system", "temperature", 9, timestamp)
	retained.Source.Elements = []PathElem{{Name: "system"}}
	retained.Source.Leaf = "temperature"
	retained.Metric = MetricMetadata{Name: "example.system.temperature", Description: "System temperature.", Unit: "Cel"}
	retained.Attributes = nil

	_, err = cache.Apply(CacheNotification{
		OwnerID: "owner-a", Prefix: ownedPrefix, Timestamp: timestamp, Atomic: true,
		Updates: []MappedPoint{owned}, Deletes: []Path{deleted},
	})
	require.NoError(t, err)
	_, err = cache.Apply(CacheNotification{OwnerID: "owner-b", Timestamp: timestamp, Updates: []MappedPoint{retained}})
	require.NoError(t, err)
	assert.True(t, cache.IsStaleForOwner("owner-a", deleted, timestamp))
	assert.False(t, cache.IsStaleForOwner("owner-b", deleted, timestamp))
	beforeBytes := cache.RetainedBytes()
	assertCacheRetainedByteInvariant(t, cache)

	result, err := cache.ResetOwnerForReconciliation("owner-a")
	require.NoError(t, err)
	assert.Equal(t, "owner-a", result.OwnerID)
	assert.Equal(t, 1, result.Entries)
	assert.Equal(t, 1, result.AtomicBaselines)
	assert.Equal(t, 2, result.Tombstones)
	require.Len(t, result.Removed, 1)
	assert.Equal(t, owned.Key(), result.Removed[0].Key())
	assert.Equal(t, beforeBytes-result.RetainedBytes, cache.RetainedBytes())
	assert.False(t, cache.IsStaleForOwner("owner-a", deleted, timestamp), "owner reset must remove the tombstone trie entry")
	_, exists := cache.AtomicBaselineForOwner("owner-a", ownedPrefix)
	assert.False(t, exists)
	require.Len(t, cache.Snapshot(), 1)
	assert.Equal(t, retained.Key(), cache.Snapshot()[0].Key())
	assertCacheRetainedByteInvariant(t, cache)

	empty, err := cache.ResetOwner("owner-a")
	require.NoError(t, err)
	assert.Zero(t, empty.Entries)
	assert.Zero(t, empty.RetainedBytes)
}

func TestCacheOwnerAttributionTransfersOnReplacementAndIsolatesDelete(t *testing.T) {
	cache, err := NewCache(20)
	require.NoError(t, err)
	t1 := time.Unix(100, 0)
	point := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	_, err = cache.Apply(CacheNotification{OwnerID: "owner-a", Timestamp: t1, Updates: []MappedPoint{point}})
	require.NoError(t, err)

	point.Timestamp = t1.Add(time.Second)
	point.DoubleValue = 42
	_, err = cache.Apply(CacheNotification{OwnerID: "owner-b", Timestamp: point.Timestamp, Updates: []MappedPoint{point}})
	require.NoError(t, err)
	resetA, err := cache.ResetOwner("owner-a")
	require.NoError(t, err)
	assert.Zero(t, resetA.Entries)
	require.Len(t, cache.Snapshot(), 1)
	assert.Equal(t, 42.0, cache.Snapshot()[0].DoubleValue)

	deletedAt := point.Timestamp.Add(time.Second)
	_, err = cache.Apply(CacheNotification{OwnerID: "owner-c", Timestamp: deletedAt, Deletes: []Path{point.Source.Path()}})
	require.NoError(t, err)
	require.Len(t, cache.Snapshot(), 1)
	assert.Equal(t, 42.0, cache.Snapshot()[0].DoubleValue)
	resetB, err := cache.ResetOwner("owner-b")
	require.NoError(t, err)
	assert.Equal(t, 1, resetB.Entries, "a cross-owner delete must preserve the prior owner's membership")
	assert.Empty(t, cache.Snapshot())
	assert.False(t, cache.IsStaleForOwner("owner-b", point.Source.Path(), deletedAt))
	assert.True(t, cache.IsStaleForOwner("owner-c", point.Source.Path(), deletedAt))
	resetC, err := cache.ResetOwner("owner-c")
	require.NoError(t, err)
	assert.Equal(t, 1, resetC.Tombstones)
	assert.False(t, cache.IsStaleForOwner("owner-c", point.Source.Path(), deletedAt))
	assertCacheRetainedByteInvariant(t, cache)
}

func TestCacheOwnerAttributionKeepsAtomicAndDominatingTombstonesIsolated(t *testing.T) {
	cache, err := NewCache(20)
	require.NoError(t, err)
	t1 := time.Unix(100, 0)
	prefix := testInterfacePrefix()
	point := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	_, err = cache.Apply(CacheNotification{
		OwnerID: "owner-a", Prefix: prefix, Timestamp: t1, Atomic: true, Updates: []MappedPoint{point},
	})
	require.NoError(t, err)

	point.DoubleValue = 42
	_, err = cache.Apply(CacheNotification{
		OwnerID: "owner-b", Prefix: prefix, Timestamp: t1.Add(time.Second), Atomic: true, Updates: []MappedPoint{point},
	})
	require.NoError(t, err)
	resetA, err := cache.ResetOwner("owner-a")
	require.NoError(t, err)
	assert.Zero(t, resetA.Entries)
	assert.Equal(t, 1, resetA.AtomicBaselines)
	assert.Equal(t, 1, resetA.Tombstones)
	resetB, err := cache.ResetOwner("owner-b")
	require.NoError(t, err)
	assert.Equal(t, 1, resetB.Entries)
	assert.Equal(t, 1, resetB.AtomicBaselines)
	assert.Equal(t, 1, resetB.Tombstones)
	assert.Empty(t, resetB.Removed)

	parent, err := ParsePath("switch-1", "openconfig", "system")
	require.NoError(t, err)
	first, err := ParsePath("switch-1", "openconfig", "system/first")
	require.NoError(t, err)
	second, err := ParsePath("switch-1", "openconfig", "system/second")
	require.NoError(t, err)
	_, err = cache.Apply(CacheNotification{OwnerID: "owner-a", Timestamp: t1, Deletes: []Path{first, second}})
	require.NoError(t, err)
	_, err = cache.Apply(CacheNotification{OwnerID: "owner-b", Timestamp: t1.Add(time.Second), Deletes: []Path{parent}})
	require.NoError(t, err)
	resetA, err = cache.ResetOwner("owner-a")
	require.NoError(t, err)
	assert.Equal(t, 2, resetA.Tombstones, "another owner's dominating tombstone must preserve this owner's descendants")
	resetB, err = cache.ResetOwner("owner-b")
	require.NoError(t, err)
	assert.Equal(t, 1, resetB.Tombstones)
	assert.False(t, cache.IsStaleForOwner("owner-a", first, t1))
	assert.False(t, cache.IsStaleForOwner("owner-b", first, t1))
	assertCacheRetainedByteInvariant(t, cache)
}

func TestCacheAtomicPartialSubscriptionStateIsOwnerScoped(t *testing.T) {
	cache, err := NewCache(20)
	require.NoError(t, err)
	t1 := time.Unix(100, 0)
	prefix := testInterfacePrefix()
	first := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	second := testMappedPoint("switch-1", "Ethernet2", "temperature", 42, t1)

	_, err = cache.Apply(CacheNotification{
		OwnerID: "owner-a", Prefix: prefix, Timestamp: t1, Atomic: true, Updates: []MappedPoint{first},
	})
	require.NoError(t, err)
	_, err = cache.Apply(CacheNotification{
		OwnerID: "owner-b", Prefix: prefix, Timestamp: t1, Atomic: true, Updates: []MappedPoint{second},
	})
	require.NoError(t, err)
	assert.Len(t, cache.Snapshot(), 2, "same-prefix atomic snapshots from separate subscriptions must coexist")
	assert.Equal(t, 2, cache.Usage().AtomicBaselines)
	assert.Equal(t, 2, cache.Usage().Tombstones)

	t2 := t1.Add(time.Second)
	_, err = cache.Apply(CacheNotification{OwnerID: "owner-a", Prefix: prefix, Timestamp: t2, Atomic: true})
	require.NoError(t, err)
	snapshot := cache.Snapshot()
	require.Len(t, snapshot, 1)
	assert.Equal(t, second.Key(), snapshot[0].Key(), "owner-a replacement must preserve owner-b data")
	assert.True(t, cache.IsStaleForOwner("owner-a", second.Source.Path(), t2))
	assert.False(t, cache.IsStaleForOwner("owner-b", second.Source.Path(), t2))
	stale, err := cache.IsStaleBatchForOwner("owner-b", []StaleQuery{{Path: second.Source.Path(), Timestamp: t2}})
	require.NoError(t, err)
	assert.Equal(t, []bool{false}, stale)

	resetA, err := cache.ResetOwner("owner-a")
	require.NoError(t, err)
	assert.Equal(t, 1, resetA.AtomicBaselines)
	assert.Equal(t, 1, resetA.Tombstones)
	assert.Len(t, cache.Snapshot(), 1)
	assert.Equal(t, 1, cache.Usage().AtomicBaselines)
	assert.Equal(t, 1, cache.Usage().Tombstones)
	_, exists := cache.AtomicBaselineForOwner("owner-b", prefix)
	assert.True(t, exists)

	t3 := t2.Add(time.Second)
	_, err = cache.Apply(CacheNotification{OwnerID: "owner-b", Timestamp: t3, Deletes: []Path{prefix}})
	require.NoError(t, err)
	assert.Empty(t, cache.Snapshot(), "an owner must still be able to delete its own retained state")
	_, exists = cache.AtomicBaselineForOwner("owner-b", prefix)
	assert.False(t, exists)
	assert.True(t, cache.IsStaleForOwner("owner-b", second.Source.Path(), t3))
	resetB, err := cache.ResetOwner("owner-b")
	require.NoError(t, err)
	assert.Equal(t, 1, resetB.Tombstones)
	assert.Zero(t, cache.Usage().Total)
	assertCacheRetainedByteInvariant(t, cache)
}

func TestCacheOwnerAttributionCanTransferToOwnerlessState(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)
	point := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, timestamp)
	_, err = cache.Apply(CacheNotification{OwnerID: "owner-a", Timestamp: timestamp, Updates: []MappedPoint{point}})
	require.NoError(t, err)

	point.DoubleValue = 42
	_, err = cache.Apply(CacheNotification{Timestamp: timestamp.Add(time.Second), Updates: []MappedPoint{point}})
	require.NoError(t, err)
	reset, err := cache.ResetOwner("owner-a")
	require.NoError(t, err)
	assert.Zero(t, reset.Entries)
	snapshot := cache.Snapshot()
	require.Len(t, snapshot, 1)
	assert.Equal(t, 42.0, snapshot[0].DoubleValue)
	assertCacheRetainedByteInvariant(t, cache)
}

func TestCachePrepareResetOwnerRollbackIsTransactional(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)
	point := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, timestamp)
	_, err = cache.Apply(CacheNotification{OwnerID: "owner-a", Timestamp: timestamp, Updates: []MappedPoint{point}})
	require.NoError(t, err)
	before := cache.RetainedBytes()

	transaction, err := cache.PrepareResetOwner("owner-a")
	require.NoError(t, err)
	prepared := transaction.Result()
	assert.Equal(t, 1, prepared.Entries)
	assert.Empty(t, prepared.Removed, "counts-only reset must not materialize retained points")
	transaction.Rollback()
	transaction.Commit()
	require.Len(t, cache.Snapshot(), 1)
	assert.Equal(t, before, cache.RetainedBytes())
	assertCacheRetainedByteInvariant(t, cache)

	transaction, err = cache.PrepareResetOwner("owner-a")
	require.NoError(t, err)
	transaction.Commit()
	transaction.Rollback()
	assert.Empty(t, cache.Snapshot())
	assert.Zero(t, cache.RetainedBytes())
	assert.Empty(t, cache.owners)
}

func TestCachePrepareResetOwnerForReconciliationMaterializesStablePoints(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)
	point := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, timestamp)
	_, err = cache.Apply(CacheNotification{OwnerID: "owner-a", Timestamp: timestamp, Updates: []MappedPoint{point}})
	require.NoError(t, err)

	transaction, err := cache.PrepareResetOwnerForReconciliation("owner-a")
	require.NoError(t, err)
	result := transaction.Result()
	require.Len(t, result.Removed, 1)
	result.Removed[0].Source.Elements[0].Name = "mutated"
	result.Removed[0].Attributes["network.interface.name"] = "mutated"
	transaction.Rollback()

	snapshot := cache.Snapshot()
	require.Len(t, snapshot, 1)
	assert.NotEqual(t, "mutated", snapshot[0].Source.Elements[0].Name)
	assert.Equal(t, "Ethernet1", snapshot[0].Attributes["network.interface.name"])
}

func TestCacheOwnerIndexRetainedBytesChargesEveryItemKey(t *testing.T) {
	ownerID := "owner-a"
	items := map[string]cacheOwnerItemKind{
		"short":                         cacheOwnerEntry,
		"a-distinct-longer-backing-key": cacheOwnerAtomicBaseline | cacheOwnerTombstone,
	}
	expected := estimateCacheOwnerIndexBaseRetainedBytes(ownerID)
	for key := range items {
		expected = saturatingRetainedByteAdd(expected, retainedCacheOwnerIndexItemBytes)
		expected = saturatingRetainedByteAdd(expected, retainedStringBytes(key))
	}
	assert.Equal(t, expected, estimateCacheOwnerIndexRetainedBytes(ownerID, items))

	withoutLongKey := map[string]cacheOwnerItemKind{"short": cacheOwnerEntry}
	assert.Equal(
		t,
		estimateCacheOwnerIndexItemRetainedBytes("a-distinct-longer-backing-key"),
		estimateCacheOwnerIndexRetainedBytes(ownerID, items)-
			estimateCacheOwnerIndexRetainedBytes(ownerID, withoutLongKey),
	)
}

func TestCacheOwnerIndexParticipatesInRetainedByteCapacity(t *testing.T) {
	timestamp := time.Unix(100, 0)
	point := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, timestamp)
	unowned, err := NewCache(10)
	require.NoError(t, err)
	_, err = unowned.Apply(CacheNotification{Timestamp: timestamp, Updates: []MappedPoint{point}})
	require.NoError(t, err)
	unownedBytes := unowned.RetainedBytes()

	owned, err := NewCacheWithLimits(10, unownedBytes)
	require.NoError(t, err)
	_, err = owned.Apply(CacheNotification{OwnerID: "owner-a", Timestamp: timestamp, Updates: []MappedPoint{point}})
	var capacity *CapacityError
	require.ErrorAs(t, err, &capacity)
	assert.Zero(t, owned.StateLen())
	assert.Zero(t, owned.RetainedBytes())
	assert.Empty(t, owned.owners)

	_, err = owned.ResetOwner("")
	require.ErrorContains(t, err, "cannot be empty")
	_, err = owned.Apply(CacheNotification{OwnerID: strings.Repeat("x", maxCacheOwnerIDBytes+1), Timestamp: timestamp, Updates: []MappedPoint{point}})
	require.ErrorContains(t, err, "owner ID exceeds")
}
