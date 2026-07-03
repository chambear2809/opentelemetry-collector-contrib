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

func TestCacheCapacityPreflightAccountsForRemovals(t *testing.T) {
	cache, err := NewCache(2)
	require.NoError(t, err)
	t1 := time.Unix(100, 0)
	one := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	two := testMappedPoint("switch-1", "Ethernet2", "temperature", 42, t1)
	_, err = cache.Apply(CacheNotification{Timestamp: t1, Updates: []MappedPoint{one, two}})
	require.NoError(t, err)

	deleteOne, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]")
	require.NoError(t, err)
	three := testMappedPoint("switch-1", "Ethernet3", "temperature", 43, t1.Add(time.Second))
	result, err := cache.Apply(CacheNotification{
		Timestamp: t1.Add(time.Second),
		Deletes:   []Path{deleteOne},
		Updates:   []MappedPoint{three},
	})
	require.NoError(t, err)
	assert.Len(t, result.Applied, 1)
	assert.Len(t, result.Removed, 1)
	assert.Equal(t, 2, cache.Len())
}

func TestCacheCapacityFailurePreservesPlannedBaselineAndEntryChanges(t *testing.T) {
	cache, err := NewCache(2)
	require.NoError(t, err)
	prefix := testInterfacePrefix()
	t1 := time.Unix(100, 0)
	one := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	_, err = cache.Apply(CacheNotification{Prefix: prefix, Timestamp: t1, Atomic: true, Updates: []MappedPoint{one}})
	require.NoError(t, err)

	t2 := t1.Add(time.Second)
	one.DoubleValue = 99
	two := testMappedPoint("switch-1", "Ethernet2", "temperature", 42, t2)
	three := testMappedPoint("switch-1", "Ethernet3", "temperature", 43, t2)
	_, err = cache.Apply(CacheNotification{Prefix: prefix, Timestamp: t2, Updates: []MappedPoint{one, two, three}})
	var capacity *CapacityError
	require.ErrorAs(t, err, &capacity)

	baseline, ok := cache.AtomicBaseline(prefix)
	require.True(t, ok, "capacity failure must not commit baseline invalidation")
	assert.Equal(t, t1, baseline)
	snapshot := cache.Snapshot()
	require.Len(t, snapshot, 1)
	assert.Equal(t, 41.0, snapshot[0].DoubleValue, "capacity failure must not commit point replacement")
}

func TestCacheNonAtomicOverlappingPrefixInvalidatesBaselineWithoutMappedUpdates(t *testing.T) {
	cache, err := NewCache(2)
	require.NoError(t, err)
	prefix := testInterfacePrefix()
	t1 := time.Unix(100, 0)
	point := testMappedPoint("switch-1", "Ethernet1", "temperature", 41, t1)
	_, err = cache.Apply(CacheNotification{Prefix: prefix, Timestamp: t1, Atomic: true, Updates: []MappedPoint{point}})
	require.NoError(t, err)

	unrelated, err := ParsePath("switch-1", "openconfig", "system")
	require.NoError(t, err)
	result, err := cache.Apply(CacheNotification{Prefix: unrelated, Timestamp: t1.Add(time.Second)})
	require.NoError(t, err)
	assert.Zero(t, result.AtomicBaselinesInvalidated)
	_, ok := cache.AtomicBaseline(prefix)
	assert.True(t, ok, "an unrelated notification must retain the baseline")

	overlapping, err := ParsePath("switch-1", "openconfig", "interfaces/interface[name=Ethernet1]")
	require.NoError(t, err)
	result, err = cache.Apply(CacheNotification{
		Prefix: overlapping, Timestamp: t1.Add(2 * time.Second), Touched: []Path{overlapping},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.AtomicBaselinesInvalidated)
	_, ok = cache.AtomicBaseline(prefix)
	assert.False(t, ok, "an overlapping notification invalidates the baseline even when every value is unmapped")
}

func TestCacheSinglePointApplyAllocationsDoNotScaleWithCacheSize(t *testing.T) {
	if testing.Short() {
		t.Skip("allocation scale regression populates a large cache")
	}
	small := singlePointApplyAllocs(t, 128)
	large := singlePointApplyAllocs(t, 20_000)
	assert.LessOrEqual(t, large, small+20,
		"one-point Apply allocations must be independent of total cache size (small=%f large=%f)", small, large)
}

func singlePointApplyAllocs(tb testing.TB, size int) float64 {
	tb.Helper()
	cache, point, timestamp := populatedCache(tb, size)
	iteration := int64(0)
	return testing.AllocsPerRun(50, func() {
		iteration++
		point.DoubleValue = float64(iteration)
		_, err := cache.Apply(CacheNotification{
			Timestamp: timestamp.Add(time.Duration(iteration) * time.Nanosecond),
			Updates:   []MappedPoint{point},
		})
		if err != nil {
			tb.Fatalf("single point Apply failed: %v", err)
		}
	})
}

func populatedCache(tb testing.TB, size int) (*Cache, MappedPoint, time.Time) {
	tb.Helper()
	cache, err := NewCache(size)
	if err != nil {
		tb.Fatalf("NewCache failed: %v", err)
	}
	timestamp := time.Unix(100, 0)
	points := make([]MappedPoint, size)
	for i := range points {
		points[i] = testMappedPoint("switch-1", fmt.Sprintf("Ethernet%d", i), "temperature", float64(i), timestamp)
	}
	if _, err := cache.Apply(CacheNotification{Timestamp: timestamp, Updates: points}); err != nil {
		tb.Fatalf("cache population failed: %v", err)
	}
	return cache, points[size/2], timestamp
}

func BenchmarkCacheApplySinglePointLargeCache(b *testing.B) {
	cache, point, timestamp := populatedCache(b, 100_000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		point.DoubleValue = float64(i)
		if _, err := cache.Apply(CacheNotification{
			Timestamp: timestamp.Add(time.Duration(i+1) * time.Nanosecond),
			Updates:   []MappedPoint{point},
		}); err != nil {
			b.Fatal(err)
		}
	}
}
