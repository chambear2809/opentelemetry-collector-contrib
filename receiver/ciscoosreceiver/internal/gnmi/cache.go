// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi

import (
	"errors"
	"fmt"
	"maps"
	"sort"
	"sync"
	"time"
)

// CapacityError reports a hard cache-state limit. Active series, atomic
// baselines, and removal tombstones are bounded independently by the configured
// limit. Mutation is transactional when this error is returned.
type CapacityError struct {
	Limit     int
	Current   int
	Requested int
}

func (e *CapacityError) Error() string {
	return fmt.Sprintf("gNMI state cache capacity exceeded: limit=%d current=%d requested=%d", e.Limit, e.Current, e.Requested)
}

// CacheNotification applies mapped updates and canonical branch deletes from
// one wire notification.
type CacheNotification struct {
	Prefix    Path
	Timestamp time.Time
	Atomic    bool
	Touched   []Path
	Updates   []MappedPoint
	Deletes   []Path
}

// CacheResult describes accepted and removed output points. Removed contains
// the previous mapped points, allowing callers to emit explicit presence=0
// signals without relying on OTLP no-recorded-value flags.
type CacheResult struct {
	Applied                    []MappedPoint
	Removed                    []MappedPoint
	Replaced                   []MappedPoint
	Duplicates                 int
	OutOfOrder                 int
	AtomicBaselinesInvalidated int
	Rejected                   bool
}

type cacheEntry struct {
	point MappedPoint
}

type atomicBaseline struct {
	prefix    Path
	timestamp time.Time
}

type stateTombstone struct {
	path      Path
	timestamp time.Time
}

// Cache is a bounded, concurrency-safe mapped-series state cache.
type Cache struct {
	mu        sync.RWMutex
	maxSeries int
	entries   map[string]cacheEntry
	atomic    map[string]atomicBaseline
	tombstone map[string]stateTombstone
	tombIndex *tombstonePrefixIndex
	tombCount int
}

// NewCache constructs a cache with a mandatory positive hard limit.
func NewCache(maxSeries int) (*Cache, error) {
	if maxSeries <= 0 {
		return nil, errors.New("max cached series must be positive")
	}
	return &Cache{
		maxSeries: maxSeries,
		entries:   make(map[string]cacheEntry),
		atomic:    make(map[string]atomicBaseline),
		tombstone: make(map[string]stateTombstone),
		tombIndex: newTombstonePrefixIndex(),
	}, nil
}

// Len returns the active mapped-series count.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Capacity returns the configured hard active-series limit.
func (c *Cache) Capacity() int {
	if c == nil {
		return 0
	}
	return c.maxSeries
}

// AtomicBaseline returns the timestamp of an exact-prefix atomic baseline.
func (c *Cache) AtomicBaseline(prefix Path) (time.Time, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	baseline, ok := c.atomic[prefix.Key()]
	return baseline.timestamp, ok
}

// IsStale reports whether path is at or below a branch removed by an atomic
// replacement or explicit delete at the same or a later timestamp.
func (c *Cache) IsStale(path Path, timestamp time.Time) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isStale(path, timestamp)
}

// Snapshot returns stable copies of all current mapped points.
func (c *Cache) Snapshot() []MappedPoint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	keys := make([]string, 0, len(c.entries))
	for key := range c.entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]MappedPoint, 0, len(keys))
	for _, key := range keys {
		out = append(out, cloneMappedPoint(c.entries[key].point))
	}
	return out
}

// Apply transactionally applies one notification. Older updates and deletes
// cannot roll state back; equal-timestamp updates are counted as duplicates.
func (c *Cache) Apply(notification CacheNotification) (CacheResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	result := CacheResult{}
	entryRemovals := map[string]cacheEntry{}
	entryUpdates := map[string]cacheEntry{}
	var entryReplacements map[string]cacheEntry
	baselineRemovals := map[string]struct{}{}
	tombstoneUpdates := map[string]stateTombstone{}
	tombstoneRemovals := map[string]stateTombstone{}
	plannedTombstones := newTombstonePrefixIndex()
	applied := make([]MappedPoint, 0, len(notification.Updates))
	planRemoval := func(key string, entry cacheEntry) {
		if _, planned := entryRemovals[key]; !planned {
			entryRemovals[key] = entry
		}
	}
	planTombstone := func(path Path) {
		if c.isStale(path, notification.Timestamp) || plannedTombstones.isStale(path, notification.Timestamp) {
			return
		}
		key := path.Key()
		if existing, ok := c.tombstoneFor(path); ok && !notification.Timestamp.After(existing.timestamp) {
			return
		}
		if existing, ok := tombstoneUpdates[key]; ok && !notification.Timestamp.After(existing.timestamp) {
			return
		}
		for stagedKey := range plannedTombstones.dominated(path, notification.Timestamp) {
			if stagedKey == key {
				continue
			}
			staged := tombstoneUpdates[stagedKey]
			delete(tombstoneUpdates, stagedKey)
			plannedTombstones.remove(stagedKey, staged.path)
		}
		for existingKey := range c.tombIndex.dominated(path, notification.Timestamp) {
			if existingKey != key {
				tombstoneRemovals[existingKey] = c.tombstone[existingKey]
			}
		}
		tombstoneUpdates[key] = stateTombstone{path: path.Clone(), timestamp: notification.Timestamp}
		plannedTombstones.upsert(key, tombstoneUpdates[key])
	}
	if notification.Atomic && c.isStale(notification.Prefix, notification.Timestamp) {
		result.OutOfOrder = max(1, len(notification.Updates)+len(notification.Deletes))
		result.Rejected = true
		return result, nil
	}
	for _, baseline := range c.atomic {
		if !notificationOverlapsBaseline(notification, baseline.prefix) {
			continue
		}
		count := len(notification.Updates) + len(notification.Deletes)
		if count == 0 {
			count = 1
		}
		if notification.Timestamp.Before(baseline.timestamp) {
			result.OutOfOrder += count
			result.Rejected = true
			return result, nil
		}
		if !notification.Atomic && notification.Timestamp.Equal(baseline.timestamp) {
			result.Duplicates += count
			result.Rejected = true
			return result, nil
		}
	}

	if notification.Atomic {
		planTombstone(notification.Prefix)
		if previous, ok := c.atomic[notification.Prefix.Key()]; ok && !notification.Timestamp.After(previous.timestamp) {
			if notification.Timestamp.Equal(previous.timestamp) {
				result.Duplicates += len(notification.Updates)
			} else {
				result.OutOfOrder += len(notification.Updates)
			}
			result.Rejected = true
			return result, nil
		}
		// cacheEntry is an immutable transaction snapshot; pointers would add an
		// allocation for every cached series.
		//nolint:gocritic // Copying the snapshot is intentional while the cache lock is held.
		for key, entry := range c.entries {
			if !entry.point.Source.Path().HasPrefix(notification.Prefix) {
				continue
			}
			if entry.point.Timestamp.After(notification.Timestamp) {
				result.OutOfOrder++
				continue
			}
			planRemoval(key, entry)
		}
		for key, baseline := range c.atomic {
			if baseline.prefix.HasPrefix(notification.Prefix) && !baseline.timestamp.After(notification.Timestamp) {
				baselineRemovals[key] = struct{}{}
			}
		}
	} else {
		for key, baseline := range c.atomic {
			if !notification.Timestamp.After(baseline.timestamp) {
				continue
			}
			if pathsOverlapAny(notification.Touched, baseline.prefix) || updatesOverlap(notification.Updates, baseline.prefix) {
				baselineRemovals[key] = struct{}{}
				result.AtomicBaselinesInvalidated++
			}
		}
	}

	for _, deleted := range notification.Deletes {
		planTombstone(deleted)
		// cacheEntry is an immutable transaction snapshot; pointers would add an
		// allocation for every cached series.
		//nolint:gocritic // Copying the snapshot is intentional while the cache lock is held.
		for key, entry := range c.entries {
			if _, removed := entryRemovals[key]; removed {
				continue
			}
			if !entry.point.Source.Path().HasPrefix(deleted) {
				continue
			}
			if entry.point.Timestamp.After(notification.Timestamp) {
				result.OutOfOrder++
				continue
			}
			planRemoval(key, entry)
		}
		for key, baseline := range c.atomic {
			if _, removed := baselineRemovals[key]; removed {
				continue
			}
			if pathsOverlap(deleted, baseline.prefix) && !notification.Timestamp.Before(baseline.timestamp) {
				baselineRemovals[key] = struct{}{}
				result.AtomicBaselinesInvalidated++
			}
		}
	}
	//nolint:gocritic // Removal values are immutable snapshots captured earlier in this transaction.
	for _, removed := range entryRemovals {
		planTombstone(removed.point.Source.Path())
	}

	for i := range notification.Updates {
		point := cloneMappedPoint(notification.Updates[i])
		point.Timestamp = notification.Timestamp
		if c.isStale(point.Source.Path(), point.Timestamp) {
			result.OutOfOrder++
			continue
		}
		key := point.Key()
		current, exists := entryUpdates[key]
		if !exists {
			if _, removed := entryRemovals[key]; !removed {
				current, exists = c.entries[key]
			}
		}
		if exists {
			switch {
			case point.Timestamp.Before(current.point.Timestamp):
				result.OutOfOrder++
				continue
			case point.Timestamp.Equal(current.point.Timestamp):
				result.Duplicates++
				continue
			}
			if point.Source.Key() != current.point.Source.Key() {
				if entryReplacements == nil {
					entryReplacements = map[string]cacheEntry{}
				}
				entryReplacements[key] = current
			}
		}
		entryUpdates[key] = cacheEntry{point: point}
		applied = append(applied, point)
	}

	finalSize := len(c.entries) - len(entryRemovals)
	for key := range entryUpdates {
		if _, existed := c.entries[key]; !existed {
			finalSize++
			continue
		}
		if _, removed := entryRemovals[key]; removed {
			finalSize++
		}
	}
	if finalSize > c.maxSeries {
		return CacheResult{}, &CapacityError{Limit: c.maxSeries, Current: len(c.entries), Requested: finalSize}
	}
	finalBaselines := len(c.atomic) - len(baselineRemovals)
	if notification.Atomic {
		if _, exists := c.atomic[notification.Prefix.Key()]; !exists {
			finalBaselines++
		} else if _, removed := baselineRemovals[notification.Prefix.Key()]; removed {
			finalBaselines++
		}
	}
	if finalBaselines > c.maxSeries {
		return CacheResult{}, &CapacityError{Limit: c.maxSeries, Current: len(c.atomic), Requested: finalBaselines}
	}
	newTombstones := 0
	for key, tombstone := range tombstoneUpdates {
		_, removed := tombstoneRemovals[key]
		if _, exists := c.tombstoneFor(tombstone.path); !exists || removed {
			newTombstones++
		}
	}
	if finalTombstones := c.tombCount - len(tombstoneRemovals) + newTombstones; finalTombstones > c.maxSeries {
		return CacheResult{}, &CapacityError{Limit: c.maxSeries, Current: c.tombCount, Requested: finalTombstones}
	}

	for key := range entryRemovals {
		delete(c.entries, key)
	}
	maps.Copy(c.entries, entryUpdates)
	for key := range baselineRemovals {
		delete(c.atomic, key)
	}
	for _, tombstone := range tombstoneRemovals {
		c.removeTombstone(tombstone)
	}
	for _, tombstone := range tombstoneUpdates {
		c.putTombstone(tombstone)
	}
	if notification.Atomic {
		c.atomic[notification.Prefix.Key()] = atomicBaseline{prefix: notification.Prefix.Clone(), timestamp: notification.Timestamp}
	}

	result.Applied = make([]MappedPoint, len(applied))
	for i := range applied {
		result.Applied[i] = cloneMappedPoint(applied[i])
	}
	// A delete followed by an update of the same output series is a
	// replacement, not a removal signal. Atomic replacement therefore reports
	// only leaves omitted from the new snapshot.
	//nolint:gocritic // Removal values are immutable snapshots needed to build the result.
	for key, removed := range entryRemovals {
		replacement, replaced := c.entries[key]
		if !replaced || replacement.point.Source.Key() != removed.point.Source.Key() {
			result.Removed = append(result.Removed, cloneMappedPoint(removed.point))
		}
	}
	sort.Slice(result.Removed, func(i, j int) bool {
		left, right := result.Removed[i], result.Removed[j]
		if left.Key() == right.Key() {
			return left.Source.Key() < right.Source.Key()
		}
		return left.Key() < right.Key()
	})
	result.Replaced = make([]MappedPoint, 0, len(entryReplacements))
	//nolint:gocritic // Replacement values are immutable snapshots needed to build the result.
	for _, replaced := range entryReplacements {
		result.Replaced = append(result.Replaced, cloneMappedPoint(replaced.point))
	}
	sort.Slice(result.Replaced, func(i, j int) bool {
		left, right := result.Replaced[i], result.Replaced[j]
		if left.Key() == right.Key() {
			return left.Source.Key() < right.Source.Key()
		}
		return left.Key() < right.Key()
	})
	return result, nil
}

func cloneMappedPoint(point MappedPoint) MappedPoint {
	elements := make([]PathElem, len(point.Source.Elements))
	for i, elem := range point.Source.Elements {
		elements[i] = PathElem{Name: elem.Name, Keys: cloneStrings(elem.Keys)}
	}
	point.Source.Elements = elements
	point.Attributes = cloneStrings(point.Attributes)
	return point
}

func pathsOverlap(left, right Path) bool {
	return left.HasPrefix(right) || right.HasPrefix(left)
}

func updatesOverlap(updates []MappedPoint, prefix Path) bool {
	for i := range updates {
		if updates[i].Source.Path().HasPrefix(prefix) {
			return true
		}
	}
	return false
}

func pathsOverlapAny(paths []Path, prefix Path) bool {
	for i := range paths {
		if pathsOverlap(paths[i], prefix) {
			return true
		}
	}
	return false
}

func notificationOverlapsBaseline(notification CacheNotification, prefix Path) bool {
	if notification.Atomic && pathsOverlap(notification.Prefix, prefix) {
		return true
	}
	if pathsOverlapAny(notification.Touched, prefix) {
		return true
	}
	if updatesOverlap(notification.Updates, prefix) {
		return true
	}
	for _, deleted := range notification.Deletes {
		if pathsOverlap(deleted, prefix) {
			return true
		}
	}
	return false
}

func (c *Cache) isStale(path Path, timestamp time.Time) bool {
	return c.tombIndex.isStale(path, timestamp)
}

func (c *Cache) tombstoneFor(path Path) (stateTombstone, bool) {
	tombstone, ok := c.tombstone[path.Key()]
	return tombstone, ok
}

func (c *Cache) putTombstone(tombstone stateTombstone) {
	key := tombstone.path.Key()
	if _, exists := c.tombstone[key]; !exists {
		c.tombCount++
	}
	c.tombstone[key] = tombstone
	c.tombIndex.upsert(key, tombstone)
}

func (c *Cache) removeTombstone(tombstone stateTombstone) {
	key := tombstone.path.Key()
	if _, exists := c.tombstone[key]; !exists {
		return
	}
	delete(c.tombstone, key)
	c.tombIndex.remove(key, tombstone.path)
	c.tombCount--
}
