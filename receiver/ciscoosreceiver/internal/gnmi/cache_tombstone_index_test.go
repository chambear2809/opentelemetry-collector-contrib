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

func TestTombstonePrefixIndexMatchesSubsetKeysAndWildcardOrigin(t *testing.T) {
	index := newTombstonePrefixIndex()
	timestamp := time.Unix(100, 0)
	wildcard := mustTombstonePath(t, "switch-1", "", "interfaces/interface")
	keyed := mustTombstonePath(t, "switch-1", "openconfig", "interfaces/interface[name=Ethernet1]/state")
	wildcardTarget := mustTombstonePath(t, "", "openconfig", "system/state")
	index.upsert(wildcard.Key(), stateTombstone{path: wildcard, timestamp: timestamp})
	index.upsert(keyed.Key(), stateTombstone{path: keyed, timestamp: timestamp.Add(time.Second)})
	index.upsert(wildcardTarget.Key(), stateTombstone{path: wildcardTarget, timestamp: timestamp})

	withExtraKey := mustTombstonePath(t, "switch-1", "openconfig", "interfaces/interface[name=Ethernet1][slot=1]/state/counters/in-octets")
	assert.True(t, index.isStale(withExtraKey, timestamp), "an empty origin and unkeyed element must retain wildcard semantics")
	assert.True(t, index.isStale(withExtraKey, timestamp.Add(time.Second)), "a keyed selector must match a concrete element with extra keys")
	assert.False(t, index.isStale(withExtraKey, timestamp.Add(2*time.Second)))

	otherInterface := mustTombstonePath(t, "switch-1", "openconfig", "interfaces/interface[name=Ethernet2]/state/counters/in-octets")
	assert.True(t, index.isStale(otherInterface, timestamp))
	assert.False(t, index.isStale(otherInterface, timestamp.Add(time.Second)), "the keyed Ethernet1 tombstone must not match a sibling key value")
	otherTargetSystem := mustTombstonePath(t, "switch-9", "openconfig", "system/state/uptime")
	assert.True(t, index.isStale(otherTargetSystem, timestamp), "an empty target retains Path.HasPrefix wildcard semantics during lookup")
}

func TestTombstonePrefixIndexDominanceIsStructurallyScoped(t *testing.T) {
	index := newTombstonePrefixIndex()
	timestamp := time.Unix(100, 0)
	paths := []Path{
		mustTombstonePath(t, "switch-1", "openconfig", "interfaces/interface[index=1][name=Ethernet1]/state/temperature"),
		mustTombstonePath(t, "switch-1", "openconfig", "interfaces/interface[name=Ethernet2]/state/temperature"),
		mustTombstonePath(t, "switch-1", "", "interfaces/interface[name=Ethernet3]/state/temperature"),
		mustTombstonePath(t, "switch-2", "openconfig", "interfaces/interface[name=Ethernet1]/state/temperature"),
		mustTombstonePath(t, "switch-1", "openconfig", "system/state/uptime"),
	}
	for _, path := range paths {
		index.upsert(path.Key(), stateTombstone{path: path, timestamp: timestamp})
	}

	keyedSelector := mustTombstonePath(t, "switch-1", "openconfig", "interfaces/interface[name=Ethernet1]")
	assert.Equal(t, map[string]struct{}{paths[0].Key(): {}}, index.dominated(keyedSelector, timestamp))

	originSelector := mustTombstonePath(t, "switch-1", "openconfig", "interfaces/interface")
	assert.Equal(t, map[string]struct{}{paths[0].Key(): {}, paths[1].Key(): {}}, index.dominated(originSelector, timestamp))

	wildcardOrigin := mustTombstonePath(t, "switch-1", "", "interfaces/interface")
	assert.Equal(t, map[string]struct{}{paths[0].Key(): {}, paths[1].Key(): {}, paths[2].Key(): {}}, index.dominated(wildcardOrigin, timestamp))
}

func TestCacheAncestorTombstonePruningIsTransactionalAtCapacity(t *testing.T) {
	cache, err := NewCache(2)
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)
	first := mustTombstonePath(t, "switch-1", "openconfig", "interfaces/interface[name=Ethernet1]")
	second := mustTombstonePath(t, "switch-1", "openconfig", "interfaces/interface[name=Ethernet2]")
	parent := mustTombstonePath(t, "switch-1", "openconfig", "interfaces/interface")

	_, err = cache.Apply(CacheNotification{Prefix: first, Timestamp: timestamp, Deletes: []Path{first}})
	require.NoError(t, err)
	_, err = cache.Apply(CacheNotification{Prefix: second, Timestamp: timestamp, Deletes: []Path{second}})
	require.NoError(t, err)
	require.Equal(t, 2, cache.tombCount)

	_, err = cache.Apply(CacheNotification{Prefix: parent, Timestamp: timestamp.Add(time.Second), Deletes: []Path{parent}})
	require.NoError(t, err, "one ancestor must replace its dominated descendants before the cap check")
	assert.Equal(t, 1, cache.tombCount)
	assert.Len(t, cache.tombIndex.dominated(parent, timestamp.Add(time.Second)), 1,
		"dominance pruning must remove descendant index nodes as well as map entries")
	assert.True(t, cache.IsStale(first, timestamp.Add(time.Second)))
	assert.True(t, cache.IsStale(second, timestamp.Add(time.Second)))

	unrelated := mustTombstonePath(t, "switch-1", "openconfig", "system")
	_, err = cache.Apply(CacheNotification{Prefix: unrelated, Timestamp: timestamp.Add(2 * time.Second), Deletes: []Path{unrelated}})
	require.NoError(t, err)
	overflow := mustTombstonePath(t, "switch-1", "openconfig", "components")
	_, err = cache.Apply(CacheNotification{Prefix: overflow, Timestamp: timestamp.Add(3 * time.Second), Deletes: []Path{overflow}})
	var capacity *CapacityError
	require.ErrorAs(t, err, &capacity)
	assert.Equal(t, 2, cache.tombCount)
	assert.False(t, cache.IsStale(overflow, timestamp.Add(3*time.Second)), "a failed transaction must not publish its index entry")
}

func TestCacheAncestorTouchInvalidatesAtomicDescendantBaseline(t *testing.T) {
	cache, err := NewCache(4)
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)
	ancestor := mustTombstonePath(t, "switch-1", "openconfig", "interfaces")
	descendant := mustTombstonePath(t, "switch-1", "openconfig", "interfaces/interface[name=Ethernet1]")

	_, err = cache.Apply(CacheNotification{Prefix: descendant, Timestamp: timestamp, Atomic: true})
	require.NoError(t, err)
	_, ok := cache.AtomicBaseline(descendant)
	require.True(t, ok)

	result, err := cache.Apply(CacheNotification{
		Prefix: ancestor, Timestamp: timestamp.Add(time.Second), Touched: []Path{ancestor},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.AtomicBaselinesInvalidated)
	_, ok = cache.AtomicBaseline(descendant)
	assert.False(t, ok, "an ancestor subtree update must invalidate an overlapping atomic baseline")
}

func BenchmarkTombstonePrefixIndexIsStale100K(b *testing.B) {
	index := newTombstonePrefixIndex()
	timestamp := time.Unix(100, 0)
	for target := range 100 {
		for port := range 1_000 {
			path := Path{
				Target: fmt.Sprintf("switch-%d", target), Origin: "openconfig",
				Elements: []PathElem{{Name: "interfaces"}, {Name: "interface", Keys: map[string]string{"name": fmt.Sprintf("Ethernet%d", port)}}},
			}
			index.upsert(path.Key(), stateTombstone{path: path, timestamp: timestamp})
		}
	}
	query := Path{
		Target: "switch-50", Origin: "openconfig",
		Elements: []PathElem{{Name: "interfaces"}, {Name: "interface", Keys: map[string]string{"name": "Ethernet500"}}, {Name: "state"}, {Name: "temperature"}},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if !index.isStale(query, timestamp) {
			b.Fatal("indexed tombstone did not match")
		}
	}
}

func mustTombstonePath(tb testing.TB, target, origin, path string) Path {
	tb.Helper()
	parsed, err := ParsePath(target, origin, path)
	require.NoError(tb, err)
	return parsed
}
