// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

func TestCacheIgnoresDuplicatesAndOutOfOrderAndIsTransactionalAtCapacity(t *testing.T) {
	cache, err := NewCache(2)
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)
	one := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, timestamp)
	result, err := cache.Apply(CacheNotification{Prefix: testInterfacePrefix(), Timestamp: timestamp, Updates: []MappedPoint{one}})
	require.NoError(t, err)
	require.Len(t, result.Applied, 1)

	duplicate := one
	duplicate.DoubleValue = 99
	result, err = cache.Apply(CacheNotification{Prefix: testInterfacePrefix(), Timestamp: timestamp, Updates: []MappedPoint{duplicate}})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Duplicates)
	assert.Equal(t, 41.0, cache.Snapshot()[0].DoubleValue)

	older := one
	older.Timestamp = timestamp.Add(-time.Second)
	result, err = cache.Apply(CacheNotification{Prefix: testInterfacePrefix(), Timestamp: older.Timestamp, Updates: []MappedPoint{older}})
	require.NoError(t, err)
	assert.Equal(t, 1, result.OutOfOrder)

	two := testMappedPoint("switch-1", "Ethernet2", "temperature", 42, timestamp.Add(time.Second))
	three := testMappedPoint("switch-1", "Ethernet3", "temperature", 43, timestamp.Add(time.Second))
	_, err = cache.Apply(CacheNotification{Prefix: testInterfacePrefix(), Timestamp: timestamp.Add(time.Second), Updates: []MappedPoint{two, three}})
	var capacity *CapacityError
	require.ErrorAs(t, err, &capacity)
	assert.Equal(t, 2, capacity.Limit)
	assert.Equal(t, 1, cache.Len(), "capacity failure must not partially mutate state")
}

func TestCacheAtomicReplacementReportsOnlyOmittedSeriesAndTracksBaseline(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	prefix := testInterfacePrefix()
	t1 := time.Unix(100, 0)
	t2 := t1.Add(time.Second)
	t3 := t2.Add(time.Second)
	temperature := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	voltage := testMappedPoint("switch-1", "Ethernet1", "voltage", 3.3, t1)
	outside := testMappedPoint("switch-1", "system", "temperature", 1, t1)
	outside.Source.Elements = []PathElem{{Name: "system"}}
	outside.Source.Leaf = "up"
	outside.Metric = MetricMetadata{Name: "cisco.device.up", Description: "Device availability.", Unit: "1"}
	outside.Attributes = nil
	_, err = cache.Apply(CacheNotification{Prefix: prefix, Timestamp: t1, Updates: []MappedPoint{temperature, voltage, outside}})
	require.NoError(t, err)

	temperature.DoubleValue = 42
	temperature.Timestamp = t2
	result, err := cache.Apply(CacheNotification{Prefix: prefix, Timestamp: t2, Atomic: true, Updates: []MappedPoint{temperature}})
	require.NoError(t, err)
	require.Len(t, result.Applied, 1)
	require.Len(t, result.Removed, 1, "the retained temperature series is a replacement, not a removal")
	assert.Equal(t, "cisco.optics.voltage", result.Removed[0].Metric.Name)
	assert.Equal(t, 2, cache.Len(), "exact-prefix replacement must preserve state outside the prefix")
	baseline, ok := cache.AtomicBaseline(prefix)
	require.True(t, ok)
	assert.Equal(t, t2, baseline)

	temperature.Timestamp = t3
	result, err = cache.Apply(CacheNotification{Prefix: prefix, Timestamp: t3, Updates: []MappedPoint{temperature}})
	require.NoError(t, err)
	assert.Equal(t, 1, result.AtomicBaselinesInvalidated)
	_, ok = cache.AtomicBaseline(prefix)
	assert.False(t, ok)
}

func TestCacheAtomicBaselinePreventsStaleBranchResurrection(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	parent := testInterfacePrefix()
	child, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]")
	require.NoError(t, err)
	t1 := time.Unix(100, 0)
	t2 := t1.Add(time.Second)
	stale := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)

	_, err = cache.Apply(CacheNotification{Prefix: child, Timestamp: t1, Updates: []MappedPoint{stale}})
	require.NoError(t, err)
	result, err := cache.Apply(CacheNotification{Prefix: parent, Timestamp: t2, Atomic: true})
	require.NoError(t, err)
	require.Len(t, result.Removed, 1)
	assert.Zero(t, cache.Len())

	result, err = cache.Apply(CacheNotification{Prefix: child, Timestamp: t1, Updates: []MappedPoint{stale}})
	require.NoError(t, err)
	assert.Equal(t, 1, result.OutOfOrder)
	assert.Empty(t, result.Applied)
	assert.Zero(t, cache.Len(), "a late non-atomic child update must not resurrect state removed by a parent atomic snapshot")

	result, err = cache.Apply(CacheNotification{Prefix: child, Timestamp: t1, Atomic: true, Updates: []MappedPoint{stale}})
	require.NoError(t, err)
	assert.Equal(t, 1, result.OutOfOrder)
	assert.Empty(t, result.Applied)
	assert.Zero(t, cache.Len(), "a late child atomic snapshot must not resurrect state removed by a newer parent snapshot")
}

func TestCacheNewerSiblingAtomicBaselineDoesNotRejectBroadPrefixUpdate(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	t1 := time.Unix(100, 0)
	t2 := t1.Add(time.Second)
	interfaceA, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]")
	require.NoError(t, err)
	pointA := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t2)
	_, err = cache.Apply(CacheNotification{Prefix: interfaceA, Timestamp: t2, Atomic: true, Updates: []MappedPoint{pointA}})
	require.NoError(t, err)

	pointB := testMappedPoint("switch-1", "Ethernet2", "temperature", 42, t1)
	result, err := cache.Apply(CacheNotification{Prefix: testInterfacePrefix(), Timestamp: t1, Updates: []MappedPoint{pointB}})
	require.NoError(t, err)
	require.Len(t, result.Applied, 1)
	assert.Equal(t, "Ethernet2", result.Applied[0].Attributes["network.interface.name"])
	assert.Equal(t, 2, cache.Len(), "a broad notification prefix must not make an unrelated sibling update stale")
}

func TestCacheBoundsAtomicBaselineState(t *testing.T) {
	cache, err := NewCache(2)
	require.NoError(t, err)
	first, err := ParsePath("switch-1", "openconfig", "interfaces")
	require.NoError(t, err)
	second, err := ParsePath("switch-1", "openconfig", "system")
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)

	_, err = cache.Apply(CacheNotification{Prefix: first, Timestamp: timestamp, Atomic: true})
	require.NoError(t, err)
	_, err = cache.Apply(CacheNotification{Prefix: second, Timestamp: timestamp.Add(time.Second), Atomic: true})
	var capacity *CapacityError
	require.ErrorAs(t, err, &capacity)
	_, ok := cache.AtomicBaseline(first)
	assert.True(t, ok)
	_, ok = cache.AtomicBaseline(second)
	assert.False(t, ok, "baseline capacity failure must be transactional")
}

func TestCacheInvalidationOnlyWithdrawsOverlappingAtomicBaselineTransactionally(t *testing.T) {
	cache, err := NewCache(4)
	require.NoError(t, err)
	t1 := time.Unix(100, 0)
	t2 := t1.Add(time.Second)
	prefix := testInterfacePrefix()
	point := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	_, err = cache.Apply(CacheNotification{
		OwnerID: "owner-a", Prefix: prefix, Timestamp: t1, Atomic: true, Updates: []MappedPoint{point},
	})
	require.NoError(t, err)

	prepared, err := cache.Prepare(CacheNotification{
		OwnerID: "owner-a", Timestamp: t2, Invalidates: []Path{point.Source.Path()},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, prepared.Result().AtomicBaselinesInvalidated)
	require.Len(t, prepared.Result().Removed, 1)
	prepared.Rollback()
	_, hasBaseline := cache.AtomicBaselineForOwner("owner-a", prefix)
	assert.True(t, hasBaseline)
	require.Len(t, cache.Snapshot(), 1)

	result, err := cache.Apply(CacheNotification{
		OwnerID: "owner-a", Timestamp: t2, Invalidates: []Path{point.Source.Path()},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.AtomicBaselinesInvalidated)
	require.Len(t, result.Removed, 1)
	_, hasBaseline = cache.AtomicBaselineForOwner("owner-a", prefix)
	assert.False(t, hasBaseline)
	assert.Empty(t, cache.Snapshot())
	assert.Equal(t, 1, cache.Usage().InvalidationWatermarks)
}

func TestCacheInvalidationCapacityFailurePreservesAtomicBaselineAndEntry(t *testing.T) {
	cache, err := NewCache(3)
	require.NoError(t, err)
	t1 := time.Unix(100, 0)
	t2 := t1.Add(time.Second)
	prefix := testInterfacePrefix()
	point := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	_, err = cache.Apply(CacheNotification{
		OwnerID: "owner-a", Prefix: prefix, Timestamp: t1, Atomic: true, Updates: []MappedPoint{point},
	})
	require.NoError(t, err)
	require.Equal(t, 3, cache.StateLen())

	first := testMappedPoint("switch-1", "Ethernet2", "temperature", 42, t2)
	second := testMappedPoint("switch-1", "Ethernet3", "temperature", 43, t2)
	_, err = cache.Apply(CacheNotification{
		OwnerID: "owner-a", Timestamp: t2, Invalidates: []Path{point.Source.Path()},
		Updates: []MappedPoint{first, second},
	})
	var capacity *CapacityError
	require.ErrorAs(t, err, &capacity)
	_, hasBaseline := cache.AtomicBaselineForOwner("owner-a", prefix)
	assert.True(t, hasBaseline)
	require.Len(t, cache.Snapshot(), 1)
	assert.Equal(t, point.Key(), cache.Snapshot()[0].Key())
	assert.Equal(t, 1, cache.Usage().Tombstones)
	assert.Zero(t, cache.Usage().InvalidationWatermarks)
}

func TestCacheExplicitBranchDeleteReturnsRemovedMappedPoints(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	t1 := time.Unix(100, 0)
	t2 := t1.Add(time.Second)
	one := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	two := testMappedPoint("switch-1", "Ethernet2", "temperature", 42, t1)
	_, err = cache.Apply(CacheNotification{Prefix: testInterfacePrefix(), Timestamp: t1, Updates: []MappedPoint{one, two}})
	require.NoError(t, err)

	deleteOne, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]")
	require.NoError(t, err)
	result, err := cache.Apply(CacheNotification{Prefix: testInterfacePrefix(), Timestamp: t2, Deletes: []Path{deleteOne}})
	require.NoError(t, err)
	require.Len(t, result.Removed, 1)
	assert.Equal(t, "Ethernet1", result.Removed[0].Attributes["network.interface.name"])
	assert.Equal(t, 1, cache.Len())
}

func TestCacheDeleteOnlyAtomicFlagDoesNotReplacePrefix(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	t1 := time.Unix(100, 0)
	t2 := t1.Add(time.Second)
	one := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	two := testMappedPoint("switch-1", "Ethernet2", "temperature", 42, t1)
	prefix := testInterfacePrefix()
	_, err = cache.Apply(CacheNotification{Prefix: prefix, Timestamp: t1, Updates: []MappedPoint{one, two}})
	require.NoError(t, err)

	deleteOne, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]")
	require.NoError(t, err)
	result, err := cache.Apply(CacheNotification{Prefix: prefix, Timestamp: t2, Atomic: true, Deletes: []Path{deleteOne}})
	require.NoError(t, err)
	require.Len(t, result.Removed, 1)
	assert.Equal(t, "Ethernet1", result.Removed[0].Attributes["network.interface.name"])
	require.Len(t, cache.Snapshot(), 1, "the atomic bit has no snapshot meaning on a delete-only notification")
	assert.Equal(t, "Ethernet2", cache.Snapshot()[0].Attributes["network.interface.name"])
	_, ok := cache.AtomicBaseline(prefix)
	assert.False(t, ok)
}

func TestCacheDeleteThenUpdateRedeliveryIsIdempotent(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)
	point := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, timestamp)
	notification := CacheNotification{
		OwnerID:   "owner-a",
		Timestamp: timestamp,
		Deletes:   []Path{point.Source.Path()},
		Updates:   []MappedPoint{point},
	}

	first, err := cache.Apply(notification)
	require.NoError(t, err)
	require.Len(t, first.Applied, 1)
	require.Len(t, cache.Snapshot(), 1, "the update is the final state after the delete")

	redelivery, err := cache.Apply(notification)
	require.NoError(t, err)
	assert.Equal(t, 1, redelivery.Duplicates)
	assert.Empty(t, redelivery.Removed)
	require.Len(t, cache.Snapshot(), 1, "equal-timestamp redelivery must not erase the final update")
	assert.Equal(t, point.DoubleValue, cache.Snapshot()[0].DoubleValue)
	assertCacheRetainedByteInvariant(t, cache)

	reset, err := cache.ResetOwner("owner-a")
	require.NoError(t, err)
	assert.Equal(t, 1, reset.Entries)
	assert.Equal(t, 1, reset.Tombstones)
	assert.Zero(t, cache.StateLen())
}

func TestCacheInvalidationWatermarkPreservesFreshnessAndAllowsSameTimestampCorrection(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	t1 := time.Unix(100, 0)
	t2 := t1.Add(time.Second)
	t3 := t2.Add(time.Second)
	point := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	path := point.Source.Path()

	first, err := cache.Apply(CacheNotification{
		OwnerID:   "owner-a",
		Timestamp: t1,
		Updates:   []MappedPoint{point},
	})
	require.NoError(t, err)
	require.Len(t, first.Applied, 1)

	prepared, err := cache.Prepare(CacheNotification{
		OwnerID:     "owner-a",
		Timestamp:   t3,
		Invalidates: []Path{path},
	})
	require.NoError(t, err)
	require.Len(t, prepared.Result().Removed, 1)
	prepared.Rollback()
	require.Len(t, cache.Snapshot(), 1,
		"rolling back an unpublished invalidation must retain the original entry")
	assert.Zero(t, cache.Usage().InvalidationWatermarks)

	withdrawal, err := cache.Apply(CacheNotification{
		OwnerID:     "owner-a",
		Timestamp:   t3,
		Invalidates: []Path{path},
	})
	require.NoError(t, err)
	require.Len(t, withdrawal.Removed, 1)
	assert.Empty(t, cache.Snapshot())
	assert.Zero(t, cache.Usage().Tombstones,
		"a local semantic invalidation must not claim an authoritative source delete")
	assert.Equal(t, 1, cache.Usage().InvalidationWatermarks)
	assert.True(t, cache.IsStaleForOwner("owner-a", path, t2),
		"the semantic watermark must reject delayed state older than the malformed value")
	assert.False(t, cache.IsStaleForOwner("owner-a", path, t3),
		"the semantic watermark must admit a correction at the same source timestamp")
	assertCacheRetainedByteInvariant(t, cache)

	point.Timestamp = t2
	point.DoubleValue = 42
	delayed, err := cache.Apply(CacheNotification{
		OwnerID:   "owner-a",
		Timestamp: t2,
		Updates:   []MappedPoint{point},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, delayed.OutOfOrder)
	assert.Empty(t, delayed.Applied)
	assert.Empty(t, cache.Snapshot())

	point.Timestamp = t3
	correction, err := cache.Apply(CacheNotification{
		OwnerID:   "owner-a",
		Timestamp: t3,
		Updates:   []MappedPoint{point},
	})
	require.NoError(t, err)
	require.Len(t, correction.Applied, 1)
	assert.Zero(t, correction.OutOfOrder)
	assert.Zero(t, correction.Duplicates)
	require.Len(t, cache.Snapshot(), 1)
	assert.Equal(t, 42.0, cache.Snapshot()[0].DoubleValue)
	assert.Zero(t, cache.Usage().Tombstones)
	assert.Zero(t, cache.Usage().InvalidationWatermarks)

	sameTimestampInvalidation, err := cache.Apply(CacheNotification{
		OwnerID:     "owner-a",
		Timestamp:   t3,
		Invalidates: []Path{path},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, sameTimestampInvalidation.Duplicates)
	assert.Empty(t, sameTimestampInvalidation.Removed)
	require.Len(t, cache.Snapshot(), 1,
		"a valid value at the same timestamp must win over a local semantic invalidation")
	assert.Zero(t, cache.Usage().InvalidationWatermarks,
		"an equal-timestamp valid entry already supplies the freshness boundary")

	_, err = cache.Apply(CacheNotification{
		OwnerID:     "owner-a",
		Timestamp:   t3.Add(time.Second),
		Invalidates: []Path{path},
	})
	require.NoError(t, err)
	reset, err := cache.ResetOwner("owner-a")
	require.NoError(t, err)
	assert.Equal(t, 1, reset.InvalidationWatermarks)
	assert.Zero(t, reset.Tombstones)
	assert.Zero(t, cache.StateLen())
	assertCacheRetainedByteInvariant(t, cache)
}

func TestCacheRejectsMultipleOutputSeriesForOneOwnerSource(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	t1 := time.Unix(100, 0)
	older := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	fresh := older
	fresh.Metric = MetricMetadata{Name: "cisco.optics.voltage", Description: "Voltage.", Unit: "V"}
	fresh.Timestamp = t1.Add(time.Second)
	fresh.DoubleValue = 3.3
	require.NotEqual(t, older.Key(), fresh.Key())
	require.Equal(t, older.Source.Key(), fresh.Source.Key())

	_, err = cache.Apply(CacheNotification{OwnerID: "owner-a", Timestamp: t1, Updates: []MappedPoint{older}})
	require.NoError(t, err)
	_, err = cache.Apply(CacheNotification{
		OwnerID: "owner-a", Timestamp: fresh.Timestamp, Updates: []MappedPoint{fresh},
	})
	require.ErrorContains(t, err, "one source path to multiple output series")
	require.Len(t, cache.Snapshot(), 1)
	assert.Equal(t, older.Key(), cache.Snapshot()[0].Key())
	assertCacheRetainedByteInvariant(t, cache)

	_, err = cache.Apply(CacheNotification{
		OwnerID: "owner-b", Timestamp: fresh.Timestamp, Updates: []MappedPoint{fresh},
	})
	require.NoError(t, err)
	require.Len(t, cache.Snapshot(), 2,
		"source-to-output uniqueness is isolated by configured stream owner")

	empty, err := NewCache(10)
	require.NoError(t, err)
	_, err = empty.Apply(CacheNotification{
		OwnerID: "owner-a", Timestamp: fresh.Timestamp, Updates: []MappedPoint{older, fresh},
	})
	require.ErrorContains(t, err, "one source path to multiple output series")
	assert.Empty(t, empty.Snapshot(), "a same-notification conflict must be transactional")
	assert.Zero(t, empty.StateLen())
}

func TestCacheSourceUniquenessIsIndependentOfDeleteRedeliveryUpdateOrder(t *testing.T) {
	timestamp := time.Unix(100, 0)
	original := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, timestamp)
	other := original
	other.Metric = MetricMetadata{Name: "cisco.optics.voltage", Description: "Voltage.", Unit: "V"}
	other.DoubleValue = 3.3

	for _, test := range []struct {
		name    string
		updates []MappedPoint
	}{
		{name: "new output before redelivered original", updates: []MappedPoint{other, original}},
		{name: "redelivered original before new output", updates: []MappedPoint{original, other}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache, err := NewCache(10)
			require.NoError(t, err)
			_, err = cache.Apply(CacheNotification{
				OwnerID: "owner-a", Timestamp: timestamp, Updates: []MappedPoint{original},
			})
			require.NoError(t, err)

			_, err = cache.Apply(CacheNotification{
				OwnerID: "owner-a", Timestamp: timestamp,
				Deletes: []Path{original.Source.Path()}, Updates: test.updates,
			})
			require.ErrorContains(t, err, "one source path to multiple output series")
			require.Len(t, cache.Snapshot(), 1)
			assert.Equal(t, original.Key(), cache.Snapshot()[0].Key())
			assertCacheRetainedByteInvariant(t, cache)

			reset, err := cache.ResetOwner("owner-a")
			require.NoError(t, err)
			assert.Equal(t, 1, reset.Entries)
			assert.Zero(t, cache.StateLen())
			assert.Empty(t, cache.sources)
		})
	}
}

func TestCacheSourceRebindingUsesCompleteNotificationPlan(t *testing.T) {
	t1 := time.Unix(100, 0)
	t2 := t1.Add(time.Second)
	outputAP := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	outputBQ := testMappedPoint("switch-1", "Ethernet1", "voltage", 3.3, t1)
	require.NotEqual(t, outputAP.Key(), outputBQ.Key())
	require.NotEqual(t, outputAP.Source.Key(), outputBQ.Source.Key())

	outputAQ := outputAP
	outputAQ.Source = outputBQ.Source
	outputAQ.Timestamp = t2
	outputAQ.DoubleValue = 42
	outputBP := outputBQ
	outputBP.Source = outputAP.Source
	outputBP.Timestamp = t2
	outputBP.DoubleValue = 3.4
	require.Equal(t, outputAP.Key(), outputAQ.Key())
	require.Equal(t, outputBQ.Key(), outputBP.Key())

	for _, test := range []struct {
		name    string
		updates []MappedPoint
	}{
		{name: "release retained source before reuse", updates: []MappedPoint{outputAQ, outputBP}},
		{name: "reuse retained source before release", updates: []MappedPoint{outputBP, outputAQ}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache, err := NewCache(10)
			require.NoError(t, err)
			_, err = cache.Apply(CacheNotification{
				OwnerID: "owner-a", Timestamp: t1, Updates: []MappedPoint{outputAP},
			})
			require.NoError(t, err)
			beforeBytes := cache.RetainedBytes()

			result, err := cache.Apply(CacheNotification{
				OwnerID: "owner-a", Timestamp: t2, Updates: test.updates,
			})
			require.NoError(t, err)
			require.Len(t, result.Applied, 2)
			require.Len(t, cache.Snapshot(), 2)
			assert.Greater(t, cache.RetainedBytes(), beforeBytes)
			assertCacheSourceBindings(t, cache, map[string]string{
				cacheOwnerPathKey("owner-a", outputAQ.Source.Path()): outputAQ.Key(),
				cacheOwnerPathKey("owner-a", outputBP.Source.Path()): outputBP.Key(),
			})
			assertCacheRetainedByteInvariant(t, cache)
		})
	}
}

func TestCacheSourceBindingsCanSwapTransactionally(t *testing.T) {
	t1 := time.Unix(100, 0)
	t2 := t1.Add(time.Second)
	outputAP := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	outputBQ := testMappedPoint("switch-1", "Ethernet1", "voltage", 3.3, t1)
	outputAQ := outputAP
	outputAQ.Source = outputBQ.Source
	outputAQ.Timestamp = t2
	outputBP := outputBQ
	outputBP.Source = outputAP.Source
	outputBP.Timestamp = t2

	for _, updates := range [][]MappedPoint{{outputAQ, outputBP}, {outputBP, outputAQ}} {
		cache, err := NewCache(10)
		require.NoError(t, err)
		_, err = cache.Apply(CacheNotification{
			OwnerID: "owner-a", Timestamp: t1, Updates: []MappedPoint{outputAP, outputBQ},
		})
		require.NoError(t, err)
		beforeBytes := cache.RetainedBytes()

		result, err := cache.Apply(CacheNotification{
			OwnerID: "owner-a", Timestamp: t2, Updates: updates,
		})
		require.NoError(t, err)
		require.Len(t, result.Applied, 2)
		require.Len(t, cache.Snapshot(), 2)
		assert.Equal(t, beforeBytes, cache.RetainedBytes())
		assertCacheSourceBindings(t, cache, map[string]string{
			cacheOwnerPathKey("owner-a", outputAQ.Source.Path()): outputAQ.Key(),
			cacheOwnerPathKey("owner-a", outputBP.Source.Path()): outputBP.Key(),
		})
		assertCacheRetainedByteInvariant(t, cache)
	}
}

func assertCacheSourceBindings(t *testing.T, cache *Cache, expected map[string]string) {
	t.Helper()
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	require.Len(t, cache.sources, len(expected))
	for sourceKey, outputKey := range expected {
		assert.Equal(t, outputKey, cache.sources[sourceKey])
	}
}

func TestCacheRejectsAtomicNotificationWithLocalInvalidationTransactionally(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	t1 := time.Unix(100, 0)
	point := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	_, err = cache.Apply(CacheNotification{Timestamp: t1, Updates: []MappedPoint{point}})
	require.NoError(t, err)

	_, err = cache.Apply(CacheNotification{
		Prefix:      testInterfacePrefix(),
		Timestamp:   t1.Add(time.Second),
		Atomic:      true,
		Invalidates: []Path{point.Source.Path()},
	})
	require.ErrorContains(t, err, "atomic cache notification contains a locally invalidated value")
	require.Len(t, cache.Snapshot(), 1)
	assert.Zero(t, cache.Usage().Tombstones)
	assert.Zero(t, cache.Usage().InvalidationWatermarks)
	_, hasBaseline := cache.AtomicBaseline(testInterfacePrefix())
	assert.False(t, hasBaseline)
	assertCacheRetainedByteInvariant(t, cache)
}

func TestCacheAuthoritativeDeleteDominatesEqualTimestampInvalidationWatermark(t *testing.T) {
	path := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, time.Time{}).Source.Path()
	parent := path.Clone()
	parent.Elements = parent.Elements[:len(parent.Elements)-1]
	timestamp := time.Unix(100, 0)

	for _, test := range []struct {
		name          string
		notifications []CacheNotification
	}{
		{
			name: "watermark then delete",
			notifications: []CacheNotification{
				{OwnerID: "owner-a", Timestamp: timestamp, Invalidates: []Path{path}},
				{OwnerID: "owner-a", Timestamp: timestamp, Deletes: []Path{path}},
			},
		},
		{
			name: "delete then watermark",
			notifications: []CacheNotification{
				{OwnerID: "owner-a", Timestamp: timestamp, Deletes: []Path{path}},
				{OwnerID: "owner-a", Timestamp: timestamp, Invalidates: []Path{path}},
			},
		},
		{
			name: "same notification",
			notifications: []CacheNotification{{
				OwnerID: "owner-a", Timestamp: timestamp,
				Deletes: []Path{path}, Invalidates: []Path{path},
			}},
		},
		{
			name: "ancestor delete dominates descendant invalidation",
			notifications: []CacheNotification{{
				OwnerID: "owner-a", Timestamp: timestamp,
				Deletes: []Path{parent}, Invalidates: []Path{path},
			}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache, err := NewCache(10)
			require.NoError(t, err)
			seed := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, timestamp.Add(-time.Second))
			_, err = cache.Apply(CacheNotification{
				OwnerID: "owner-a", Timestamp: seed.Timestamp, Updates: []MappedPoint{seed},
			})
			require.NoError(t, err)
			for _, notification := range test.notifications {
				_, err = cache.Apply(notification)
				require.NoError(t, err)
			}
			assert.Equal(t, 1, cache.Usage().Tombstones)
			assert.Zero(t, cache.Usage().InvalidationWatermarks)
			assert.True(t, cache.IsStaleForOwner("owner-a", path, timestamp),
				"an authoritative delete must reject equal-timestamp resurrection")

			point := testMappedPoint("switch-1", "Ethernet1", "temperature", 42, timestamp)
			result, err := cache.Apply(CacheNotification{
				OwnerID: "owner-a", Timestamp: timestamp, Updates: []MappedPoint{point},
			})
			require.NoError(t, err)
			assert.Equal(t, 1, result.OutOfOrder)
			assert.Empty(t, result.Applied)
			assertCacheRetainedByteInvariant(t, cache)
		})
	}
}

func TestCacheEqualTimestampAncestorWatermarkCoversSoftDescendantsOnly(t *testing.T) {
	cache, err := NewCache(32)
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)
	parent, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]")
	require.NoError(t, err)
	_, err = cache.Apply(CacheNotification{
		OwnerID: "owner-a", Timestamp: timestamp, Invalidates: []Path{parent},
	})
	require.NoError(t, err)

	var firstChild Path
	for index := range 16 {
		child := parent.Clone()
		child.Elements = append(child.Elements,
			PathElem{Name: "state"},
			PathElem{Name: fmt.Sprintf("leaf-%d", index)},
		)
		if index == 0 {
			firstChild = child
		}
		_, err = cache.Apply(CacheNotification{
			OwnerID: "owner-a", Timestamp: timestamp, Invalidates: []Path{child},
		})
		require.NoError(t, err)
	}
	assert.Equal(t, 1, cache.Usage().InvalidationWatermarks,
		"equal-time soft descendants add no freshness coverage beyond their soft ancestor")

	_, err = cache.Apply(CacheNotification{
		OwnerID: "owner-b", Timestamp: timestamp, Invalidates: []Path{firstChild},
	})
	require.NoError(t, err)
	assert.Equal(t, 2, cache.Usage().InvalidationWatermarks,
		"another owner's watermark must not be covered")

	_, err = cache.Apply(CacheNotification{
		OwnerID: "owner-a", Timestamp: timestamp, Deletes: []Path{firstChild},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, cache.Usage().Tombstones)
	assert.Equal(t, 2, cache.Usage().InvalidationWatermarks)
	assert.True(t, cache.IsStaleForOwner("owner-a", firstChild, timestamp),
		"an equal-time authoritative child delete is stronger than a soft ancestor")
	assert.False(t, cache.IsStaleForOwner("owner-a", parent, timestamp),
		"the soft ancestor must continue to admit an equal-time correction outside the hard child")
}

func TestCacheDeleteTombstonePreventsStaleResurrection(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	t1 := time.Unix(100, 0)
	t2 := t1.Add(time.Second)
	t3 := t2.Add(time.Second)
	t4 := t3.Add(time.Second)
	point := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	_, err = cache.Apply(CacheNotification{Prefix: testInterfacePrefix(), Timestamp: t1, Updates: []MappedPoint{point}})
	require.NoError(t, err)
	deleted, err := ParsePath("switch-1", "openconfig", "interfaces/interface")
	require.NoError(t, err)
	_, err = cache.Apply(CacheNotification{Prefix: testInterfacePrefix(), Timestamp: t3, Deletes: []Path{deleted}})
	require.NoError(t, err)
	assert.Zero(t, cache.Len())

	point.Timestamp = t2
	result, err := cache.Apply(CacheNotification{Prefix: testInterfacePrefix(), Timestamp: t2, Updates: []MappedPoint{point}})
	require.NoError(t, err)
	assert.Equal(t, 1, result.OutOfOrder)
	assert.Empty(t, result.Applied)
	assert.Zero(t, cache.Len(), "a delayed pre-delete update must not resurrect removed state")

	point.Timestamp = t4
	result, err = cache.Apply(CacheNotification{Prefix: testInterfacePrefix(), Timestamp: t4, Updates: []MappedPoint{point}})
	require.NoError(t, err)
	require.Len(t, result.Applied, 1)
	assert.Equal(t, 1, cache.Len(), "a genuinely newer update remains valid")
}

func TestCacheBoundsDeleteTombstonesTransactionally(t *testing.T) {
	cache, err := NewCache(1)
	require.NoError(t, err)
	first, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]")
	require.NoError(t, err)
	second, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet2]")
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)
	_, err = cache.Apply(CacheNotification{Prefix: testInterfacePrefix(), Timestamp: timestamp, Deletes: []Path{first}})
	require.NoError(t, err)
	_, err = cache.Apply(CacheNotification{Prefix: testInterfacePrefix(), Timestamp: timestamp.Add(time.Second), Deletes: []Path{second}})
	var capacity *CapacityError
	require.ErrorAs(t, err, &capacity)
	assert.True(t, cache.IsStale(first, timestamp))
	assert.False(t, cache.IsStale(second, timestamp.Add(time.Second)), "capacity failure must not partially publish a tombstone")
}

func TestCachePrunesRedundantDeleteTombstonesInEitherOrder(t *testing.T) {
	parent, err := ParsePath("switch-1", "openconfig", "interfaces")
	require.NoError(t, err)
	child, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]")
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)
	for _, deletes := range [][]Path{{child, parent}, {parent, child}} {
		cache, cacheErr := NewCache(1)
		require.NoError(t, cacheErr)
		_, cacheErr = cache.Apply(CacheNotification{Prefix: parent, Timestamp: timestamp, Deletes: deletes})
		require.NoError(t, cacheErr)
		assert.Equal(t, 1, cache.tombCount)
		assert.True(t, cache.IsStale(child, timestamp))
	}

	cache, err := NewCache(1)
	require.NoError(t, err)
	_, err = cache.Apply(CacheNotification{Prefix: parent, Timestamp: timestamp, Deletes: []Path{child}})
	require.NoError(t, err)
	_, err = cache.Apply(CacheNotification{Prefix: parent, Timestamp: timestamp.Add(time.Second), Deletes: []Path{parent}})
	require.NoError(t, err, "a newer ancestor tombstone must replace a redundant descendant at capacity")
	assert.Equal(t, 1, cache.tombCount)
}

func TestCacheReportsSourceReplacementForAuxiliaryStateCleanup(t *testing.T) {
	cache, err := NewCache(10)
	require.NoError(t, err)
	t1 := time.Unix(100, 0)
	first := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	_, err = cache.Apply(CacheNotification{Prefix: testInterfacePrefix(), Timestamp: t1, Updates: []MappedPoint{first}})
	require.NoError(t, err)

	second := first
	second.Source.Origin = "DME"
	second.Timestamp = t1.Add(time.Second)
	second.DoubleValue = 42
	result, err := cache.Apply(CacheNotification{Prefix: testInterfacePrefix(), Timestamp: second.Timestamp, Updates: []MappedPoint{second}})
	require.NoError(t, err)
	require.Len(t, result.Applied, 1)
	assert.Empty(t, result.Removed, "the output metric series remains present")
	require.Len(t, result.Replaced, 1)
	assert.Equal(t, first.Source.Key(), result.Replaced[0].Source.Key())
	assert.Equal(t, second.Source.Key(), cache.Snapshot()[0].Source.Key())
}

func TestBuildMetricChunksIsLosslessAndPreservesMetricContract(t *testing.T) {
	timestamp := time.Unix(100, 0)
	points := []MappedPoint{
		testMappedPoint("switch-1", "Ethernet1", "temperature", 41, timestamp),
		testMappedPoint("switch-1", "Ethernet2", "temperature", 42, timestamp),
		testMappedPoint("switch-1", "Ethernet3", "temperature", 43, timestamp),
		testMappedPoint("switch-2", "Ethernet1", "temperature", 44, timestamp),
		testMappedPoint("switch-2", "Ethernet2", "temperature", 45, timestamp),
	}
	chunks, err := BuildMetricChunks(points, 2)
	require.NoError(t, err)
	require.Len(t, chunks, 3)
	assert.Equal(t, []int{2, 2, 1}, []int{chunks[0].DataPointCount(), chunks[1].DataPointCount(), chunks[2].DataPointCount()})

	count := 0
	for _, chunk := range chunks {
		for i := 0; i < chunk.ResourceMetrics().Len(); i++ {
			scopes := chunk.ResourceMetrics().At(i).ScopeMetrics()
			for j := 0; j < scopes.Len(); j++ {
				metrics := scopes.At(j).Metrics()
				for k := 0; k < metrics.Len(); k++ {
					metric := metrics.At(k)
					assert.Equal(t, "cisco.optics.temperature", metric.Name())
					assert.Equal(t, "Module temperature.", metric.Description())
					assert.Equal(t, "Cel", metric.Unit())
					require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
					count += metric.Gauge().DataPoints().Len()
				}
			}
		}
	}
	assert.Equal(t, len(points), count)
}

func TestBuildMetricChunksPreservesCumulativeSumAndTypedOpticsAttribute(t *testing.T) {
	point := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, time.Unix(100, 0))
	point.Metric = MetricMetadata{Name: "system.network.io", Description: "The number of bytes transmitted and received", Unit: "By"}
	point.GaugeType = GaugeInt
	point.MetricType = MetricSum
	point.Monotonic = true
	point.IntValue = 123
	point.Attributes["cisco.optics.experimental"] = "true"

	chunks, err := BuildMetricChunks([]MappedPoint{point}, 10)
	require.NoError(t, err)
	metric := chunks[0].ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0)
	require.Equal(t, pmetric.MetricTypeSum, metric.Type())
	assert.True(t, metric.Sum().IsMonotonic())
	assert.Equal(t, pmetric.AggregationTemporalityCumulative, metric.Sum().AggregationTemporality())
	datapoint := metric.Sum().DataPoints().At(0)
	assert.Equal(t, int64(123), datapoint.IntValue())
	experimental, ok := datapoint.Attributes().Get("cisco.optics.experimental")
	require.True(t, ok)
	assert.True(t, experimental.Bool())
}

func testInterfacePrefix() Path {
	path, err := ParsePath("switch-1", "openconfig", "interfaces")
	if err != nil {
		panic(err)
	}
	return path
}

func testMappedPoint(target, iface, sensor string, value float64, timestamp time.Time) MappedPoint {
	unit := "Cel"
	if sensor == "voltage" {
		unit = "V"
	}
	return MappedPoint{
		Source: Series{
			Target: target,
			Origin: "openconfig",
			Elements: []PathElem{
				{Name: "interfaces"},
				{Name: "interface", Keys: map[string]string{"name": iface}},
				{Name: "optics"},
			},
			Leaf: sensor,
		},
		Metric: MetricMetadata{
			Name: "cisco.optics." + sensor, Description: "Module " + sensor + ".", Unit: unit,
		},
		GaugeType:   GaugeDouble,
		DoubleValue: value,
		Attributes:  map[string]string{"network.interface.name": iface},
		Timestamp:   timestamp,
	}
}
