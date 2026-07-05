// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"

import (
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CapacityError reports a hard retained-state limit. Active series, atomic
// baselines, and removal tombstones share the configured limit. Mutation is
// transactional when this error is returned.
type CapacityError struct {
	Limit                  int
	Current                int
	Requested              int
	RetainedByteLimit      int64
	CurrentRetainedBytes   int64
	RequestedRetainedBytes int64
}

func (e *CapacityError) Error() string {
	if e.RetainedByteLimit > 0 && e.RequestedRetainedBytes > e.RetainedByteLimit {
		return fmt.Sprintf(
			"gNMI state cache retained-byte capacity exceeded: limit=%d current=%d requested=%d",
			e.RetainedByteLimit,
			e.CurrentRetainedBytes,
			e.RequestedRetainedBytes,
		)
	}
	return fmt.Sprintf("gNMI state cache capacity exceeded: limit=%d current=%d requested=%d", e.Limit, e.Current, e.Requested)
}

// CacheNotification applies mapped updates and canonical branch deletes from
// one wire notification.
type CacheNotification struct {
	// OwnerID is a stable configured-stream identity. Entries may transfer when
	// two streams intentionally produce one output identity, but destructive
	// selectors, atomic baselines, tombstones, and stale checks remain isolated
	// to this owner. Empty preserves the ownerless namespace used by legacy
	// internal callers.
	OwnerID   string
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

// CacheTransaction owns the cache write lock from Prepare until Commit or
// Rollback. Result is an immutable delivery snapshot; committing publishes the
// sparse mutation plan, while rolling back leaves every cache index unchanged.
type CacheTransaction struct {
	cache      *Cache
	result     CacheResult
	commitPlan func()
	done       atomic.Bool
}

// Result returns the prepared notification result. Its mapped points do not
// alias cache entries and remain valid after Commit or Rollback.
func (tx *CacheTransaction) Result() CacheResult {
	if tx == nil {
		return CacheResult{}
	}
	return tx.result
}

// Commit atomically publishes the prepared cache mutation and releases the
// cache lock. It is safe to call more than once.
func (tx *CacheTransaction) Commit() {
	if tx == nil || !tx.done.CompareAndSwap(false, true) {
		return
	}
	defer tx.cache.mu.Unlock()
	if tx.commitPlan != nil {
		tx.commitPlan()
	}
}

// Rollback discards the prepared cache mutation and releases the cache lock.
// It is safe to call more than once.
func (tx *CacheTransaction) Rollback() {
	if tx == nil || !tx.done.CompareAndSwap(false, true) {
		return
	}
	tx.cache.mu.Unlock()
}

type cacheEntry struct {
	point         MappedPoint
	ownerID       string
	retainedBytes int64
}

type atomicBaseline struct {
	prefix        Path
	timestamp     time.Time
	ownerID       string
	retainedBytes int64
}

type stateTombstone struct {
	path          Path
	timestamp     time.Time
	ownerID       string
	retainedBytes int64
}

const (
	// DefaultMaxCacheRetainedBytes is the receiver-wide retained-memory ceiling
	// partitioned across configured targets by the shared gNMI receiver. The
	// 1.25 GiB limit leaves bounded headroom above the qualified 500,000-series
	// workload, whose conservative retained-state estimate is about 1.03 GiB.
	DefaultMaxCacheRetainedBytes    int64 = 1280 * 1024 * 1024
	maxCachedPointAttributes              = 64
	maxCachedAttributeBytes               = 64 * 1024
	maxCachedMetricNameBytes              = 256
	maxCachedMetricDescriptionBytes       = 4 * 1024
	maxCachedMetricUnitBytes              = 256
	maxCachedMetricMetadataBytes          = 4*1024 + 2*256
	retainedStringHeaderBytes       int64 = 16
	retainedMapHeaderBytes          int64 = 48
	// A map[string]string bucket contains eight string keys, eight string
	// values, tophashes, and an overflow pointer. Round above the current
	// 64-bit runtime size so even a one-entry map pays for a full first bucket.
	retainedStringMapBucketBytes   int64 = 288
	retainedSliceHeaderBytes       int64 = 24
	retainedPathBaseBytes          int64 = 64
	retainedPathElementBytes       int64 = 64
	retainedMappedPointBytes       int64 = 192
	retainedCacheMapEntryBytes     int64 = 32
	retainedTombstonePathNodeBytes int64 = 64
	retainedTombstoneKeyNodeBytes  int64 = 64
	retainedSparseStringMapBytes         = retainedMapHeaderBytes + retainedStringMapBucketBytes
	// A root is reached through target and origin maps. Every path element adds
	// a child map, element index, and path node. Every key constraint adds both
	// key->value-map and value->node sparse maps plus its trie node.
	retainedTombstoneRootIndexBytes      = 2*retainedSparseStringMapBytes + retainedTombstonePathNodeBytes
	retainedTombstonePathElementBytes    = retainedSparseStringMapBytes + 2*retainedTombstonePathNodeBytes
	retainedTombstoneKeyConstraintBytes  = 2*retainedSparseStringMapBytes + retainedTombstoneKeyNodeBytes
	maxCacheNotificationOperations       = maxNotificationWireOperations + maxDecodedNotificationPoints
	maxCacheNotificationStagedBytes      = 32 * 1024 * 1024
	maxCachePlanningComparisons          = 5_000_000
	maxCacheStructuralPlanningOperations = 25_000_000
)

// CacheUsage reports the cache's retained-state usage. Total is the sum of
// Entries, AtomicBaselines, and Tombstones.
type CacheUsage struct {
	Entries         int
	AtomicBaselines int
	Tombstones      int
	Total           int
	Limit           int
}

// Cache is a bounded, concurrency-safe mapped-series state cache. Active
// mapped series, atomic baselines, and removal tombstones share one hard limit.
type Cache struct {
	mu               sync.RWMutex
	maxSeries        int
	maxRetainedBytes int64
	retainedBytes    int64
	entries          map[string]cacheEntry
	atomic           map[string]atomicBaseline
	tombstone        map[string]stateTombstone
	tombIndex        *tombstonePrefixIndex
	tombCount        int
	owners           map[string]*cacheOwnerState
}

// NewCache constructs a cache with a mandatory positive retained-state limit.
func NewCache(maxSeries int) (*Cache, error) {
	return NewCacheWithLimits(maxSeries, DefaultMaxCacheRetainedBytes)
}

// NewCacheWithLimits constructs a cache with independent count and retained-
// byte ceilings. It is exposed so scale qualification and adversarial tests can
// use small deterministic budgets without weakening production defaults.
func NewCacheWithLimits(maxSeries int, maxRetainedBytes int64) (*Cache, error) {
	if maxSeries <= 0 {
		return nil, errors.New("max cached series must be positive")
	}
	if maxRetainedBytes <= 0 {
		return nil, errors.New("max retained bytes must be positive")
	}
	return &Cache{
		maxSeries:        maxSeries,
		maxRetainedBytes: maxRetainedBytes,
		entries:          make(map[string]cacheEntry),
		atomic:           make(map[string]atomicBaseline),
		tombstone:        make(map[string]stateTombstone),
		tombIndex:        newTombstonePrefixIndex(),
		owners:           make(map[string]*cacheOwnerState),
	}, nil
}

// Len returns the active mapped-series count.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// StateLen returns the total retained-state count, including active entries,
// atomic baselines, and removal tombstones.
func (c *Cache) StateLen() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stateLenLocked()
}

// Usage returns a consistent snapshot of retained-state usage.
func (c *Cache) Usage() CacheUsage {
	if c == nil {
		return CacheUsage{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return CacheUsage{
		Entries:         len(c.entries),
		AtomicBaselines: len(c.atomic),
		Tombstones:      c.tombCount,
		Total:           c.stateLenLocked(),
		Limit:           c.maxSeries,
	}
}

// Capacity returns the configured hard retained-state limit.
func (c *Cache) Capacity() int {
	if c == nil {
		return 0
	}
	return c.maxSeries
}

// RetainedBytes returns the cache's conservative retained-memory estimate.
func (c *Cache) RetainedBytes() int64 {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.retainedBytes
}

// RetainedByteCapacity returns the hard retained-byte ceiling.
func (c *Cache) RetainedByteCapacity() int64 {
	if c == nil {
		return 0
	}
	return c.maxRetainedBytes
}

// AtomicBaseline returns the timestamp of an exact-prefix atomic baseline.
func (c *Cache) AtomicBaseline(prefix Path) (time.Time, bool) {
	return c.AtomicBaselineForOwner("", prefix)
}

// AtomicBaselineForOwner returns the timestamp of an exact-prefix atomic
// baseline retained for one configured subscription owner.
func (c *Cache) AtomicBaselineForOwner(ownerID string, prefix Path) (time.Time, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	baseline, ok := c.atomic[cacheOwnerPathKey(ownerID, prefix)]
	return baseline.timestamp, ok
}

// IsStale reports whether path is at or below a branch removed by an atomic
// replacement or explicit delete at the same or a later timestamp.
func (c *Cache) IsStale(path Path, timestamp time.Time) bool {
	return c.IsStaleForOwner("", path, timestamp)
}

// IsStaleForOwner reports whether a path is stale within one configured
// subscription owner's independently versioned view of the target tree.
func (c *Cache) IsStaleForOwner(ownerID string, path Path, timestamp time.Time) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isStaleForOwner(ownerID, path, timestamp)
}

// StaleQuery is one timestamped path checked by IsStaleBatch.
type StaleQuery struct {
	Path      Path
	Timestamp time.Time
}

// IsStaleBatch returns a consistent stale-state snapshot for a bounded set of
// queries. One structural-work budget is shared by the complete batch, so many
// individually valid paths cannot repeatedly traverse an adversarial retained
// tombstone trie without bound. An error returns no partial results.
func (c *Cache) IsStaleBatch(queries []StaleQuery) ([]bool, error) {
	return c.IsStaleBatchForOwner("", queries)
}

// IsStaleBatchForOwner applies IsStaleForOwner to a bounded query batch under
// one cache read lock and one structural-work budget.
func (c *Cache) IsStaleBatchForOwner(ownerID string, queries []StaleQuery) ([]bool, error) {
	return c.isStaleBatchForOwner(ownerID, queries, maxCacheStructuralPlanningOperations)
}

func (c *Cache) isStaleBatch(queries []StaleQuery, maximumStructuralOperations int) ([]bool, error) {
	return c.isStaleBatchForOwner("", queries, maximumStructuralOperations)
}

func (c *Cache) isStaleBatchForOwner(ownerID string, queries []StaleQuery, maximumStructuralOperations int) ([]bool, error) {
	if c == nil {
		return nil, errors.New("gNMI state cache cannot be nil")
	}
	if err := validateCacheOwnerID(ownerID, false); err != nil {
		return nil, err
	}
	if maximumStructuralOperations <= 0 {
		return nil, errors.New("cache structural planning operation limit must be positive")
	}
	if len(queries) > maxDecodedNotificationPoints {
		return nil, fmt.Errorf("cache stale batch exceeds %d queries", maxDecodedNotificationPoints)
	}
	validatedBytes := 0
	for index := range queries {
		pathBytes, err := validatePath(queries[index].Path)
		if err != nil {
			return nil, fmt.Errorf("cache stale query %d: %w", index, err)
		}
		if pathBytes > maxCacheNotificationStagedBytes-validatedBytes {
			return nil, fmt.Errorf("cache stale batch exceeds %d path bytes", maxCacheNotificationStagedBytes)
		}
		validatedBytes += pathBytes
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	budget := &cacheStructuralPlanningBudget{maximum: maximumStructuralOperations}
	results := make([]bool, len(queries))
	for index := range queries {
		if !budget.consume() {
			return nil, fmt.Errorf(
				"cache structural planning work exceeds %d operations",
				maximumStructuralOperations,
			)
		}
		stale, complete := c.tombIndex.isStaleForOwnerForStructuralPlan(
			ownerID,
			queries[index].Path,
			queries[index].Timestamp,
			budget,
		)
		if !complete {
			return nil, fmt.Errorf(
				"cache structural planning work exceeds %d operations",
				maximumStructuralOperations,
			)
		}
		results[index] = stale
	}
	return results, nil
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

// Apply prepares and immediately commits one notification. Call Prepare when
// publication must wait for downstream delivery.
func (c *Cache) Apply(notification CacheNotification) (CacheResult, error) {
	transaction, err := c.Prepare(notification)
	if err != nil {
		return CacheResult{}, err
	}
	defer transaction.Rollback()
	result := transaction.Result()
	transaction.Commit()
	return result, nil
}

// Prepare validates and stages one notification without publishing state.
// Older updates and deletes cannot roll state back; equal-timestamp updates are
// counted as duplicates. The caller must always call Commit or Rollback.
func (c *Cache) Prepare(notification CacheNotification) (*CacheTransaction, error) {
	return c.prepare(notification, maxCacheStructuralPlanningOperations)
}

func (c *Cache) prepare(notification CacheNotification, maximumStructuralOperations int) (*CacheTransaction, error) {
	if maximumStructuralOperations <= 0 {
		return nil, errors.New("cache structural planning operation limit must be positive")
	}
	if err := validateCacheNotificationPaths(notification); err != nil {
		return nil, err
	}
	deletePlan, deletePlanErr := buildCacheSelectorPlan(notification.Deletes)
	if deletePlanErr != nil {
		return nil, deletePlanErr
	}
	touchedIndex := buildCachePathIndex(notification.Touched)
	updateIndex := buildCacheUpdateIndex(notification.Updates)
	// The gNMI atomic bit describes an update transaction. On a notification
	// carrying only deletes it has no snapshot-replacement semantics; treating
	// it as a snapshot would incorrectly erase the entire notification prefix.
	atomicSnapshot := notification.Atomic && (len(notification.Updates) > 0 || len(notification.Touched) > 0 || len(notification.Deletes) == 0)
	c.mu.Lock()
	handedOff := false
	defer func() {
		if !handedOff {
			c.mu.Unlock()
		}
	}()
	if err := c.validatePlanningWorkLocked(notification, atomicSnapshot, len(deletePlan.selectors)); err != nil {
		return nil, err
	}
	structuralBudget := &cacheStructuralPlanningBudget{maximum: maximumStructuralOperations}
	structuralPlanningError := func() error {
		return fmt.Errorf(
			"cache structural planning work exceeds %d operations",
			maximumStructuralOperations,
		)
	}
	preparedResult := func(result CacheResult) *CacheTransaction {
		handedOff = true
		return &CacheTransaction{cache: c, result: result}
	}

	result := CacheResult{}
	entryRemovals := map[string]cacheEntry{}
	entryRemovalPaths := map[string]Path{}
	entryUpdates := map[string]cacheEntry{}
	var entryReplacements map[string]cacheEntry
	baselineRemovals := map[string]struct{}{}
	tombstoneUpdates := map[string]stateTombstone{}
	tombstoneRemovals := map[string]stateTombstone{}
	plannedTombstones := newTombstonePrefixIndex()
	plannedTombstonePaths := map[string]Path{}
	applied := make([]MappedPoint, 0, len(notification.Updates))
	planRemoval := func(key string, entry cacheEntry, path Path) {
		if _, planned := entryRemovals[key]; !planned {
			entryRemovals[key] = entry
			entryRemovalPaths[key] = path
		}
	}
	stagePlannedTombstone := func(path Path, timestamp time.Time) error {
		if !structuralBudget.consumePath(path) {
			return structuralPlanningError()
		}
		key := path.Key()
		plannedTombstonePaths[key] = path
		plannedTombstones.upsert(key, stateTombstone{path: path, timestamp: timestamp})
		return nil
	}
	planTombstone := func(path Path) error {
		// Delete/atomic selectors are staged before retained entries are scanned.
		// Check that sparse transaction trie first so each removal-generated path
		// short-circuits on its staged ancestor instead of re-traversing the full
		// retained tombstone trie once per removed entry.
		stale, complete := plannedTombstones.isStaleForStructuralPlan(path, notification.Timestamp, structuralBudget)
		if !complete {
			return structuralPlanningError()
		}
		if stale {
			return nil
		}
		stale, complete = c.tombIndex.isStaleForOwnerForStructuralPlan(
			notification.OwnerID,
			path,
			notification.Timestamp,
			structuralBudget,
		)
		if !complete {
			return structuralPlanningError()
		}
		if stale {
			// The retained ancestor already supplies the durable stale-state
			// boundary, but this notification's selector must still participate in
			// the sparse removal plan. This is especially important for idempotent
			// redelivery of a delete followed by an update at one timestamp.
			return stagePlannedTombstone(path, notification.Timestamp)
		}
		key := cacheOwnerPathKey(notification.OwnerID, path)
		if existing, ok := c.tombstoneForOwner(notification.OwnerID, path); ok && !notification.Timestamp.After(existing.timestamp) {
			return nil
		}
		if existing, ok := tombstoneUpdates[key]; ok && !notification.Timestamp.After(existing.timestamp) {
			return nil
		}
		stagedDominated, complete := plannedTombstones.dominatedForStructuralPlan(path, notification.Timestamp, structuralBudget)
		if !complete {
			return structuralPlanningError()
		}
		for stagedKey := range stagedDominated {
			if stagedKey == key {
				continue
			}
			stagedPath := plannedTombstonePaths[stagedKey]
			if !structuralBudget.consumePath(stagedPath) {
				return structuralPlanningError()
			}
			delete(tombstoneUpdates, stagedKey)
			delete(plannedTombstonePaths, stagedKey)
			plannedTombstones.remove(stagedKey, stagedPath)
		}
		existingDominated, complete := c.tombIndex.dominatedForOwnerForStructuralPlan(
			notification.OwnerID,
			path,
			notification.Timestamp,
			structuralBudget,
		)
		if !complete {
			return structuralPlanningError()
		}
		for existingKey := range existingDominated {
			if existingKey != key {
				tombstoneRemovals[existingKey] = c.tombstone[existingKey]
			}
		}
		clonedPath := path.Clone()
		tombstoneUpdates[key] = stateTombstone{
			path:      clonedPath,
			timestamp: notification.Timestamp,
			ownerID:   notification.OwnerID,
			retainedBytes: saturatingRetainedByteAdd(
				estimateTombstoneRetainedBytes(key, clonedPath, notification.OwnerID),
				estimateCacheOwnerReferenceRetainedBytes(notification.OwnerID),
			),
		}
		return stagePlannedTombstone(tombstoneUpdates[key].path, notification.Timestamp)
	}
	if atomicSnapshot {
		stale, complete := c.tombIndex.isStaleForOwnerForStructuralPlan(
			notification.OwnerID,
			notification.Prefix,
			notification.Timestamp,
			structuralBudget,
		)
		if !complete {
			return nil, structuralPlanningError()
		}
		if stale {
			result.OutOfOrder = max(1, len(notification.Updates)+len(deletePlan.selectors))
			result.Rejected = true
			return preparedResult(result), nil
		}
	}
	operationCount := len(notification.Updates) + len(deletePlan.selectors)
	if operationCount == 0 {
		operationCount = 1
	}
	for key, baseline := range c.atomic {
		if !structuralBudget.consume() {
			return nil, structuralPlanningError()
		}
		if baseline.ownerID != notification.OwnerID {
			continue
		}
		atomicOverlap := false
		baselineSelectedByAtomic := false
		if atomicSnapshot {
			var complete bool
			baselineSelectedByAtomic, complete = pathHasPrefixForStructuralPlan(
				baseline.prefix,
				notification.Prefix,
				structuralBudget,
			)
			if !complete {
				return nil, structuralPlanningError()
			}
			atomicOverlap = baselineSelectedByAtomic
			if !atomicOverlap {
				atomicOverlap, complete = pathHasPrefixForStructuralPlan(
					notification.Prefix,
					baseline.prefix,
					structuralBudget,
				)
				if !complete {
					return nil, structuralPlanningError()
				}
			}
		}
		touchedOverlap, complete := touchedIndex.overlapsForStructuralPlan(baseline.prefix, structuralBudget)
		if !complete {
			return nil, structuralPlanningError()
		}
		updateOverlap, complete := updateIndex.hasSelectedPathForStructuralPlan(baseline.prefix, structuralBudget)
		if !complete {
			return nil, structuralPlanningError()
		}
		deleteOverlap, complete := deletePlan.index.overlapsForStructuralPlan(baseline.prefix, structuralBudget)
		if !complete {
			return nil, structuralPlanningError()
		}
		if !atomicOverlap && !touchedOverlap && !updateOverlap && !deleteOverlap {
			continue
		}
		if notification.Timestamp.Before(baseline.timestamp) {
			result.AtomicBaselinesInvalidated = 0
			result.OutOfOrder += operationCount
			result.Rejected = true
			return preparedResult(result), nil
		}
		if !atomicSnapshot && notification.Timestamp.Equal(baseline.timestamp) {
			result.AtomicBaselinesInvalidated = 0
			result.Duplicates += operationCount
			result.Rejected = true
			return preparedResult(result), nil
		}
		_, removed := baselineRemovals[key]
		if atomicSnapshot && baselineSelectedByAtomic && !baseline.timestamp.After(notification.Timestamp) {
			baselineRemovals[key] = struct{}{}
			removed = true
		}
		if !removed && !atomicSnapshot && notification.Timestamp.After(baseline.timestamp) && (touchedOverlap || updateOverlap) {
			baselineRemovals[key] = struct{}{}
			result.AtomicBaselinesInvalidated++
			removed = true
		}
		if !removed && deleteOverlap && !notification.Timestamp.Before(baseline.timestamp) {
			baselineRemovals[key] = struct{}{}
			result.AtomicBaselinesInvalidated++
		}
	}

	if atomicSnapshot {
		prefixKey := cacheOwnerPathKey(notification.OwnerID, notification.Prefix)
		if previous, ok := c.atomic[prefixKey]; ok && !notification.Timestamp.After(previous.timestamp) {
			result.AtomicBaselinesInvalidated = 0
			if notification.Timestamp.Equal(previous.timestamp) {
				result.Duplicates += len(notification.Updates)
			} else {
				result.OutOfOrder += len(notification.Updates)
			}
			result.Rejected = true
			return preparedResult(result), nil
		}
		if err := planTombstone(notification.Prefix); err != nil {
			return nil, err
		}
	}
	for _, deleted := range deletePlan.selectors {
		if err := planTombstone(deleted); err != nil {
			return nil, err
		}
	}
	if atomicSnapshot || len(deletePlan.selectors) > 0 {
		// cacheEntry is an immutable transaction snapshot; pointers would add an
		// allocation for every cached series.
		//nolint:gocritic // Copying the snapshot is intentional while the cache lock is held.
		for key, entry := range c.entries {
			if !structuralBudget.consume() {
				return nil, structuralPlanningError()
			}
			if entry.ownerID != notification.OwnerID {
				continue
			}
			path, complete := seriesPathForStructuralPlan(entry.point.Source, structuralBudget)
			if !complete {
				return nil, structuralPlanningError()
			}
			selectedByAtomic := false
			if atomicSnapshot {
				selectedByAtomic, complete = pathHasPrefixForStructuralPlan(path, notification.Prefix, structuralBudget)
				if !complete {
					return nil, structuralPlanningError()
				}
			}
			selectedByDelete := false
			if !selectedByAtomic {
				var complete bool
				selectedByDelete, complete = deletePlan.index.selectsForStructuralPlan(path, structuralBudget)
				if !complete {
					return nil, structuralPlanningError()
				}
			}
			if !selectedByAtomic && !selectedByDelete {
				continue
			}
			if entry.point.Timestamp.After(notification.Timestamp) {
				result.OutOfOrder++
				continue
			}
			planRemoval(key, entry, path)
		}
	}
	// Every removal is selected by an atomic prefix or collapsed delete that was
	// staged before the single entry scan. Enforce that invariant explicitly:
	// removal-generated exact tombstones would be redundant, and consulting the
	// retained trie here would recreate a tombCount×entryRemovals cross-product.
	for key := range entryRemovals {
		if !structuralBudget.consume() {
			return nil, structuralPlanningError()
		}
		selected, complete := plannedTombstones.isStaleForStructuralPlan(
			entryRemovalPaths[key],
			notification.Timestamp,
			structuralBudget,
		)
		if !complete {
			return nil, structuralPlanningError()
		}
		if !selected {
			return nil, errors.New("cache removal escaped its staged tombstone selector")
		}
	}

	for i := range notification.Updates {
		if !structuralBudget.consume() {
			return nil, structuralPlanningError()
		}
		if !structuralBudget.consumeSeriesPath(notification.Updates[i].Source) {
			return nil, structuralPlanningError()
		}
		point := cloneMappedPoint(notification.Updates[i])
		point.Timestamp = notification.Timestamp
		pointPath, complete := seriesPathForStructuralPlan(point.Source, structuralBudget)
		if !complete {
			return nil, structuralPlanningError()
		}
		key := point.Key()
		current, exists := entryUpdates[key]
		currentFromRemoval := false
		if !exists {
			if removed, planned := entryRemovals[key]; planned && point.Source.Key() == removed.point.Source.Key() {
				current, exists = removed, true
				currentFromRemoval = true
			} else if !planned {
				current, exists = c.entries[key]
			}
		}
		if currentFromRemoval && point.Timestamp.Equal(current.point.Timestamp) {
			result.Duplicates++
			// A delete followed by the same update is already represented by
			// the retained point. Keep it on equal-timestamp redelivery while
			// the tombstone continues to protect against older resurrection.
			delete(entryRemovals, key)
			delete(entryRemovalPaths, key)
			continue
		}
		stale, complete := c.tombIndex.isStaleForOwnerForStructuralPlan(
			notification.OwnerID,
			pointPath,
			point.Timestamp,
			structuralBudget,
		)
		if !complete {
			return nil, structuralPlanningError()
		}
		if stale {
			result.OutOfOrder++
			continue
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
		// A strictly newer update of the exact deleted source path supersedes
		// that tombstone. Retaining it would consume correctness-state capacity
		// forever and could prevent a valid series from returning at the limit.
		// Ancestor tombstones remain: they still protect deleted siblings.
		if tombstone, ok := c.tombstoneForOwner(notification.OwnerID, pointPath); ok && point.Timestamp.After(tombstone.timestamp) {
			tombstoneRemovals[cacheOwnerPathKey(notification.OwnerID, pointPath)] = tombstone
		}
		entryUpdates[key] = cacheEntry{
			point:   point,
			ownerID: notification.OwnerID,
			retainedBytes: saturatingRetainedByteAdd(
				estimateCacheEntryRetainedBytes(key, point),
				estimateCacheOwnerReferenceRetainedBytes(notification.OwnerID),
			),
		}
		applied = append(applied, point)
	}

	var baselineKey string
	var baselineUpdate atomicBaseline
	if atomicSnapshot {
		baselineKey = cacheOwnerPathKey(notification.OwnerID, notification.Prefix)
		baselinePrefix := notification.Prefix.Clone()
		baselineUpdate = atomicBaseline{
			prefix:    baselinePrefix,
			timestamp: notification.Timestamp,
			ownerID:   notification.OwnerID,
			retainedBytes: saturatingRetainedByteAdd(
				estimateBaselineRetainedBytes(baselineKey, baselinePrefix),
				estimateCacheOwnerReferenceRetainedBytes(notification.OwnerID),
			),
		}
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
	finalBaselines := len(c.atomic) - len(baselineRemovals)
	if atomicSnapshot {
		if _, exists := c.atomic[baselineKey]; !exists {
			finalBaselines++
		} else if _, removed := baselineRemovals[baselineKey]; removed {
			finalBaselines++
		}
	}
	newTombstones := 0
	for key, tombstone := range tombstoneUpdates {
		_, removed := tombstoneRemovals[key]
		if _, exists := c.tombstoneForOwner(tombstone.ownerID, tombstone.path); !exists || removed {
			newTombstones++
		}
	}
	finalTombstones := c.tombCount - len(tombstoneRemovals) + newTombstones
	finalState := finalSize + finalBaselines + finalTombstones
	if finalState > c.maxSeries {
		return nil, &CapacityError{Limit: c.maxSeries, Current: c.stateLenLocked(), Requested: finalState}
	}

	finalRetainedBytes := c.retainedBytes
	for key := range entryRemovals {
		removed := entryRemovals[key]
		finalRetainedBytes -= removed.retainedBytes
	}
	for key := range entryUpdates {
		update := entryUpdates[key]
		if existing, exists := c.entries[key]; exists {
			if _, removed := entryRemovals[key]; !removed {
				finalRetainedBytes -= existing.retainedBytes
			}
		}
		finalRetainedBytes = saturatingRetainedByteAdd(finalRetainedBytes, update.retainedBytes)
	}
	for key := range baselineRemovals {
		if existing, exists := c.atomic[key]; exists {
			finalRetainedBytes -= existing.retainedBytes
		}
	}
	if atomicSnapshot {
		if existing, exists := c.atomic[baselineKey]; exists {
			if _, removed := baselineRemovals[baselineKey]; !removed {
				finalRetainedBytes -= existing.retainedBytes
			}
		}
		finalRetainedBytes = saturatingRetainedByteAdd(finalRetainedBytes, baselineUpdate.retainedBytes)
	}
	for key := range tombstoneRemovals {
		if existing, exists := c.tombstone[key]; exists {
			finalRetainedBytes -= existing.retainedBytes
		}
	}
	for key, update := range tombstoneUpdates {
		if existing, exists := c.tombstone[key]; exists {
			if _, removed := tombstoneRemovals[key]; !removed {
				finalRetainedBytes -= existing.retainedBytes
			}
		}
		finalRetainedBytes = saturatingRetainedByteAdd(finalRetainedBytes, update.retainedBytes)
	}

	ownerPlan := newCacheOwnerIndexPlan(c)
	for key := range entryRemovals {
		if err := ownerPlan.remove(entryRemovals[key].ownerID, key, cacheOwnerEntry); err != nil {
			return nil, err
		}
	}
	for key := range entryUpdates {
		if existing, exists := c.entries[key]; exists {
			if _, removed := entryRemovals[key]; !removed {
				if err := ownerPlan.remove(existing.ownerID, key, cacheOwnerEntry); err != nil {
					return nil, err
				}
			}
		}
		if err := ownerPlan.add(entryUpdates[key].ownerID, key, cacheOwnerEntry); err != nil {
			return nil, err
		}
	}
	for key := range baselineRemovals {
		if existing, exists := c.atomic[key]; exists {
			if err := ownerPlan.remove(existing.ownerID, key, cacheOwnerAtomicBaseline); err != nil {
				return nil, err
			}
		}
	}
	if atomicSnapshot {
		if existing, exists := c.atomic[baselineKey]; exists {
			if _, removed := baselineRemovals[baselineKey]; !removed {
				if err := ownerPlan.remove(existing.ownerID, baselineKey, cacheOwnerAtomicBaseline); err != nil {
					return nil, err
				}
			}
		}
		if err := ownerPlan.add(baselineUpdate.ownerID, baselineKey, cacheOwnerAtomicBaseline); err != nil {
			return nil, err
		}
	}
	for key, existing := range tombstoneRemovals {
		if err := ownerPlan.remove(existing.ownerID, key, cacheOwnerTombstone); err != nil {
			return nil, err
		}
	}
	for key, update := range tombstoneUpdates {
		if existing, exists := c.tombstone[key]; exists {
			if _, removed := tombstoneRemovals[key]; !removed {
				if err := ownerPlan.remove(existing.ownerID, key, cacheOwnerTombstone); err != nil {
					return nil, err
				}
			}
		}
		if err := ownerPlan.add(update.ownerID, key, cacheOwnerTombstone); err != nil {
			return nil, err
		}
	}
	ownerRetainedBytesDelta, err := ownerPlan.retainedBytesDelta()
	if err != nil {
		return nil, err
	}
	if ownerRetainedBytesDelta < 0 {
		if finalRetainedBytes < -ownerRetainedBytesDelta {
			return nil, errors.New("gNMI state cache retained-byte accounting underflow")
		}
		finalRetainedBytes += ownerRetainedBytesDelta
	} else {
		finalRetainedBytes = saturatingRetainedByteAdd(finalRetainedBytes, ownerRetainedBytesDelta)
	}
	if finalRetainedBytes < 0 {
		return nil, errors.New("gNMI state cache retained-byte accounting underflow")
	}
	if finalRetainedBytes > c.maxRetainedBytes {
		return nil, &CapacityError{
			Limit:                  c.maxSeries,
			Current:                c.stateLenLocked(),
			Requested:              finalState,
			RetainedByteLimit:      c.maxRetainedBytes,
			CurrentRetainedBytes:   c.retainedBytes,
			RequestedRetainedBytes: finalRetainedBytes,
		}
	}

	result.Applied = make([]MappedPoint, len(applied))
	for i := range applied {
		result.Applied[i] = cloneMappedPoint(applied[i])
	}
	// A delete followed by an update of the same output series is a
	// replacement, not a removal signal. Atomic replacement therefore reports
	// only leaves omitted from the new snapshot. The map is already keyed by
	// each point's unique output-series key, so sorting those retained keys once
	// avoids repeated JSON/path key construction inside a sort comparator.
	removedKeys := make([]string, 0, len(entryRemovals))
	for key := range entryRemovals {
		removed := entryRemovals[key]
		replacement, replaced := entryUpdates[key]
		if !replaced || replacement.point.Source.Key() != removed.point.Source.Key() {
			removedKeys = append(removedKeys, key)
		}
	}
	sort.Strings(removedKeys)
	result.Removed = make([]MappedPoint, 0, len(removedKeys))
	for _, key := range removedKeys {
		result.Removed = append(result.Removed, cloneMappedPoint(entryRemovals[key].point))
	}
	result.Replaced = make([]MappedPoint, 0, len(entryReplacements))
	replacedKeys := make([]string, 0, len(entryReplacements))
	for key := range entryReplacements {
		replacedKeys = append(replacedKeys, key)
	}
	sort.Strings(replacedKeys)
	for _, key := range replacedKeys {
		result.Replaced = append(result.Replaced, cloneMappedPoint(entryReplacements[key].point))
	}
	transaction := &CacheTransaction{cache: c, result: result}
	transaction.commitPlan = func() {
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
		if atomicSnapshot {
			c.atomic[baselineKey] = baselineUpdate
		}
		ownerPlan.apply()
		c.retainedBytes = finalRetainedBytes
	}
	handedOff = true
	return transaction, nil
}

// validatePlanningWorkLocked rejects adversarial selector/state cross-products
// before traversing retained baselines or tombstone indexes. Structural entry
// selection is charged as one scan; baseline overlap is conservatively charged
// against every notification selector because keyed-superset trie walks can
// visit most selector branches in the worst case.
func (c *Cache) validatePlanningWorkLocked(notification CacheNotification, atomicSnapshot bool, deletes int) error {
	entryScan := 0
	if atomicSnapshot || deletes > 0 {
		entryScan = len(c.entries)
	}
	if entryScan > maxCachePlanningComparisons {
		return fmt.Errorf("cache notification planning work exceeds %d comparisons", maxCachePlanningComparisons)
	}
	work := entryScan
	baselineSelectors := deletes + len(notification.Touched) + len(notification.Updates)
	tombstoneSelectors := deletes + len(notification.Updates)
	if atomicSnapshot {
		baselineSelectors++
		tombstoneSelectors++
	}
	addProduct := func(items, selectors int) bool {
		if items == 0 || selectors == 0 {
			return true
		}
		remaining := maxCachePlanningComparisons - work
		if selectors > remaining/items {
			return false
		}
		work += items * selectors
		return true
	}
	if !addProduct(len(c.atomic), baselineSelectors) || !addProduct(c.tombCount, tombstoneSelectors) {
		return fmt.Errorf("cache notification planning work exceeds %d comparisons", maxCachePlanningComparisons)
	}
	return nil
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

func (c *Cache) isStaleForOwner(ownerID string, path Path, timestamp time.Time) bool {
	return c.tombIndex.isStaleForOwner(ownerID, path, timestamp)
}

// stateLenLocked returns total retained state. The caller must hold c.mu for
// reading or writing.
func (c *Cache) stateLenLocked() int {
	return len(c.entries) + len(c.atomic) + c.tombCount
}

func cacheOwnerPathKey(ownerID string, path Path) string {
	pathKey := path.Key()
	if ownerID == "" {
		return pathKey
	}
	var key strings.Builder
	appendKeyPart(&key, ownerID)
	appendKeyPart(&key, pathKey)
	return key.String()
}

func (c *Cache) tombstoneForOwner(ownerID string, path Path) (stateTombstone, bool) {
	tombstone, ok := c.tombstone[cacheOwnerPathKey(ownerID, path)]
	return tombstone, ok
}

func (c *Cache) putTombstone(tombstone stateTombstone) {
	key := cacheOwnerPathKey(tombstone.ownerID, tombstone.path)
	if _, exists := c.tombstone[key]; !exists {
		c.tombCount++
	}
	c.tombstone[key] = tombstone
	c.tombIndex.upsert(key, tombstone)
}

func (c *Cache) removeTombstone(tombstone stateTombstone) {
	key := cacheOwnerPathKey(tombstone.ownerID, tombstone.path)
	if _, exists := c.tombstone[key]; !exists {
		return
	}
	delete(c.tombstone, key)
	c.tombIndex.removeForOwner(tombstone.ownerID, key, tombstone.path)
	c.tombCount--
}

func validateCacheNotificationPaths(notification CacheNotification) error {
	if err := validateCacheOwnerID(notification.OwnerID, false); err != nil {
		return err
	}
	if err := validateCacheNotificationOperationCount(notification); err != nil {
		return err
	}
	stagedBytes := 0
	reserveBytes := func(bytes int) error {
		if bytes > maxCacheNotificationStagedBytes-stagedBytes {
			return fmt.Errorf("cache notification exceeds %d staged bytes", maxCacheNotificationStagedBytes)
		}
		stagedBytes += bytes
		return nil
	}
	prefixBytes, err := validatePath(notification.Prefix)
	if err != nil {
		return fmt.Errorf("cache notification prefix: %w", err)
	}
	if err := reserveBytes(prefixBytes); err != nil {
		return err
	}
	for index := range notification.Touched {
		pathBytes, err := validatePath(notification.Touched[index])
		if err != nil {
			return fmt.Errorf("cache notification touched path %d: %w", index, err)
		}
		if err := reserveBytes(pathBytes); err != nil {
			return err
		}
	}
	for index := range notification.Deletes {
		pathBytes, err := validatePath(notification.Deletes[index])
		if err != nil {
			return fmt.Errorf("cache notification delete path %d: %w", index, err)
		}
		if err := reserveBytes(pathBytes); err != nil {
			return err
		}
	}
	for index := range notification.Updates {
		pathBytes, err := validateSeries(notification.Updates[index].Source)
		if err != nil {
			return fmt.Errorf("cache notification update path %d: %w", index, err)
		}
		payloadBytes, err := validateMappedPointPayload(notification.Updates[index])
		if err != nil {
			return fmt.Errorf("cache notification update %d: %w", index, err)
		}
		if err := reserveBytes(pathBytes + payloadBytes); err != nil {
			return err
		}
	}
	return nil
}

func validateCacheNotificationOperationCount(notification CacheNotification) error {
	operations := len(notification.Touched)
	if len(notification.Deletes) > maxCacheNotificationOperations-operations {
		return fmt.Errorf("cache notification exceeds %d operations", maxCacheNotificationOperations)
	}
	operations += len(notification.Deletes)
	if len(notification.Updates) > maxCacheNotificationOperations-operations {
		return fmt.Errorf("cache notification exceeds %d operations", maxCacheNotificationOperations)
	}
	if len(notification.Updates) > maxDecodedNotificationPoints {
		return fmt.Errorf("cache notification exceeds %d mapped updates", maxDecodedNotificationPoints)
	}
	if len(notification.Touched) > maxNotificationWireOperations || len(notification.Deletes) > maxNotificationWireOperations-len(notification.Touched) {
		return fmt.Errorf("cache notification exceeds %d touched/delete operations", maxNotificationWireOperations)
	}
	return nil
}

func validateMappedPointPayload(point MappedPoint) (int, error) {
	if len(point.Attributes) > maxCachedPointAttributes {
		return 0, fmt.Errorf("mapped point exceeds %d attributes", maxCachedPointAttributes)
	}
	attributeBytes := 0
	for key, value := range point.Attributes {
		if key == "" {
			return 0, errors.New("mapped point contains an empty attribute key")
		}
		if len(key) > maxPathNameBytes {
			return 0, fmt.Errorf("mapped point attribute key exceeds %d bytes", maxPathNameBytes)
		}
		if len(value) > maxPathKeyValueBytes {
			return 0, fmt.Errorf("mapped point attribute %q value exceeds %d bytes", key, maxPathKeyValueBytes)
		}
		attributeBytes += len(key) + len(value)
		if attributeBytes > maxCachedAttributeBytes {
			return 0, fmt.Errorf("mapped point exceeds %d aggregate attribute bytes", maxCachedAttributeBytes)
		}
	}
	if point.Metric.Name == "" {
		return 0, errors.New("mapped point metric name cannot be empty")
	}
	if len(point.Metric.Name) > maxCachedMetricNameBytes {
		return 0, fmt.Errorf("mapped point metric name exceeds %d bytes", maxCachedMetricNameBytes)
	}
	if len(point.Metric.Description) > maxCachedMetricDescriptionBytes {
		return 0, fmt.Errorf("mapped point metric description exceeds %d bytes", maxCachedMetricDescriptionBytes)
	}
	if len(point.Metric.Unit) > maxCachedMetricUnitBytes {
		return 0, fmt.Errorf("mapped point metric unit exceeds %d bytes", maxCachedMetricUnitBytes)
	}
	metadataBytes := len(point.Metric.Name) + len(point.Metric.Description) + len(point.Metric.Unit)
	if metadataBytes > maxCachedMetricMetadataBytes {
		return 0, fmt.Errorf("mapped point metric metadata exceeds %d bytes", maxCachedMetricMetadataBytes)
	}
	return attributeBytes + metadataBytes, nil
}

func estimateCacheEntryRetainedBytes(key string, point MappedPoint) int64 {
	bytes := retainedMappedPointBytes + retainedCacheMapEntryBytes + retainedStringBytes(key)
	bytes = saturatingRetainedByteAdd(bytes, estimateSeriesRetainedBytes(point.Source))
	bytes = saturatingRetainedByteAdd(bytes, retainedStringBytes(point.Metric.Name))
	bytes = saturatingRetainedByteAdd(bytes, retainedStringBytes(point.Metric.Description))
	bytes = saturatingRetainedByteAdd(bytes, retainedStringBytes(point.Metric.Unit))
	return saturatingRetainedByteAdd(bytes, estimateStringMapRetainedBytes(point.Attributes))
}

func estimateBaselineRetainedBytes(key string, prefix Path) int64 {
	bytes := retainedCacheMapEntryBytes + retainedStringBytes(key)
	return saturatingRetainedByteAdd(bytes, estimatePathRetainedBytes(prefix))
}

func estimateTombstoneRetainedBytes(key string, path Path, owners ...string) int64 {
	ownerID := ""
	if len(owners) > 0 {
		ownerID = owners[0]
	}
	bytes := retainedCacheMapEntryBytes + retainedStringBytes(key)
	bytes = saturatingRetainedByteAdd(bytes, estimatePathRetainedBytes(path))
	// tombstonePrefixIndex retains a separately allocated, length-prefixed
	// composite scope key for (subscription owner, configured target, gNMI
	// Path.target). The path strings themselves can share the tombstone's backing
	// storage, but this builder-produced map key cannot.
	bytes = saturatingRetainedByteAdd(bytes, estimateTombstoneScopeKeyRetainedBytes(path, ownerID))
	indexBytes := retainedTombstoneRootIndexBytes
	for _, elem := range path.Elements {
		indexBytes = saturatingRetainedByteAdd(indexBytes, retainedTombstonePathElementBytes)
		indexBytes = saturatingRetainedByteAdd(
			indexBytes,
			saturatingRetainedByteMultiply(int64(len(elem.Keys)), retainedTombstoneKeyConstraintBytes),
		)
	}
	return saturatingRetainedByteAdd(bytes, indexBytes)
}

func estimateTombstoneScopeKeyRetainedBytes(path Path, owners ...string) int64 {
	ownerID := ""
	if len(owners) > 0 {
		ownerID = owners[0]
	}
	keyBytes := canonicalKeyPartBytes(path.Target) + canonicalKeyPartBytes(path.PathTarget)
	if ownerID != "" {
		keyBytes += canonicalKeyPartBytes(ownerID)
	}
	return saturatingRetainedByteAdd(retainedStringHeaderBytes, int64(keyBytes))
}

func estimateSeriesRetainedBytes(series Series) int64 {
	bytes := retainedPathBaseBytes + retainedSliceHeaderBytes
	bytes = saturatingRetainedByteAdd(bytes, retainedStringBytes(series.Target))
	bytes = saturatingRetainedByteAdd(bytes, retainedStringBytes(series.PathTarget))
	bytes = saturatingRetainedByteAdd(bytes, retainedStringBytes(series.Origin))
	bytes = saturatingRetainedByteAdd(bytes, retainedStringBytes(series.Leaf))
	for _, elem := range series.Elements {
		bytes = saturatingRetainedByteAdd(bytes, estimatePathElementRetainedBytes(elem))
	}
	return bytes
}

func estimatePathRetainedBytes(path Path) int64 {
	bytes := retainedPathBaseBytes + retainedSliceHeaderBytes
	bytes = saturatingRetainedByteAdd(bytes, retainedStringBytes(path.Target))
	bytes = saturatingRetainedByteAdd(bytes, retainedStringBytes(path.PathTarget))
	bytes = saturatingRetainedByteAdd(bytes, retainedStringBytes(path.Origin))
	for _, elem := range path.Elements {
		bytes = saturatingRetainedByteAdd(bytes, estimatePathElementRetainedBytes(elem))
	}
	return bytes
}

func estimatePathElementRetainedBytes(elem PathElem) int64 {
	bytes := retainedPathElementBytes + retainedStringBytes(elem.Name)
	return saturatingRetainedByteAdd(bytes, estimateStringMapRetainedBytes(elem.Keys))
}

func estimateStringMapRetainedBytes(values map[string]string) int64 {
	if len(values) == 0 {
		return 0
	}
	bytes := retainedMapHeaderBytes
	buckets := int64(1)
	// Keep the modeled load at or below 6.5 entries per bucket. Rounding the
	// bucket count to powers of two mirrors Go maps and intentionally errs high
	// for sparse maps near a growth boundary.
	for int64(len(values))*2 > buckets*13 {
		buckets = saturatingRetainedByteMultiply(buckets, 2)
	}
	bytes = saturatingRetainedByteAdd(bytes, saturatingRetainedByteMultiply(buckets, retainedStringMapBucketBytes))
	for key, value := range values {
		bytes = saturatingRetainedByteAdd(bytes, retainedStringBytes(key))
		bytes = saturatingRetainedByteAdd(bytes, retainedStringBytes(value))
	}
	return bytes
}

func retainedStringBytes(value string) int64 {
	return saturatingRetainedByteAdd(retainedStringHeaderBytes, int64(len(value)))
}

func saturatingRetainedByteMultiply(left, right int64) int64 {
	const maximum = int64(^uint64(0) >> 1)
	if left <= 0 || right <= 0 {
		return 0
	}
	if left > maximum/right {
		return maximum
	}
	return left * right
}

func saturatingRetainedByteAdd(left, right int64) int64 {
	const maximum = int64(^uint64(0) >> 1)
	if right > 0 && left > maximum-right {
		return maximum
	}
	return left + right
}
