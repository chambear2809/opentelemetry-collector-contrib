// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultCounterStoreMaxEntries = 100_000
	defaultCounterStoreIdleTTL    = 24 * time.Hour
)

type counterStoreConfig struct {
	maxEntries int
	idleTTL    time.Duration
	now        func() time.Time
}

type counterValueType uint8

const (
	counterValueTypeInt counterValueType = iota
	counterValueTypeDouble
)

type counterSeriesRef struct {
	key       string
	valueType counterValueType
}

type intCounterSeries struct {
	value         int64
	startedAt     time.Time
	lastSeen      time.Time
	lru           *list.Element
	checkpointLRU *list.Element
	shard         uint16
}

type doubleCounterSeries struct {
	value         float64
	startedAt     time.Time
	lastSeen      time.Time
	lru           *list.Element
	checkpointLRU *list.Element
	shard         uint16
}

// counterStore tracks cumulative values for Sum metrics across scrapes within a
// single receiver instance. SignalFlow rate()/sum_over_time() expect monotonic
// cumulative counters, so per-scrape delta observations are accumulated here
// and emitted as a running total.
type counterStore struct {
	mu            sync.Mutex
	persistMu     sync.Mutex
	intValues     map[string]*intCounterSeries
	doubleValues  map[string]*doubleCounterSeries
	lru           *list.List
	startedAt     time.Time
	maxEntries    int
	idleTTL       time.Duration
	now           func() time.Time
	checkpoint    *checkpointBinding
	shards        map[uint16]*list.List
	nextShard     uint16
	generation    map[uint16]uint64
	persisted     map[uint16]uint64
	metadataDirty bool
}

type counterCheckpointMetadata struct {
	StartedAt time.Time `json:"started_at"`
}

type counterCheckpointShard struct {
	Version  int                       `json:"version"`
	Shard    uint16                    `json:"shard"`
	Integers []intCounterCheckpoint    `json:"integers,omitempty"`
	Doubles  []doubleCounterCheckpoint `json:"doubles,omitempty"`
}

type intCounterCheckpoint struct {
	Key       string    `json:"key"`
	Value     int64     `json:"value"`
	StartedAt time.Time `json:"started_at"`
	LastSeen  time.Time `json:"last_seen"`
}

type doubleCounterCheckpoint struct {
	Key       string    `json:"key"`
	Value     float64   `json:"value"`
	StartedAt time.Time `json:"started_at"`
	LastSeen  time.Time `json:"last_seen"`
}

func newCounterStore() *counterStore {
	startedAt := time.Now()
	return newCounterStoreWithConfig(startedAt, counterStoreConfig{})
}

func newCounterStoreAt(startedAt time.Time) *counterStore {
	return newCounterStoreWithConfig(startedAt, counterStoreConfig{now: func() time.Time { return startedAt }})
}

func newCounterStoreWithConfig(startedAt time.Time, cfg counterStoreConfig) *counterStore {
	maxEntries := cfg.maxEntries
	if maxEntries <= 0 {
		maxEntries = defaultCounterStoreMaxEntries
	}
	idleTTL := cfg.idleTTL
	if idleTTL <= 0 {
		idleTTL = defaultCounterStoreIdleTTL
	}
	now := cfg.now
	if now == nil {
		now = time.Now
	}
	return &counterStore{
		intValues:    map[string]*intCounterSeries{},
		doubleValues: map[string]*doubleCounterSeries{},
		lru:          list.New(),
		startedAt:    startedAt,
		maxEntries:   maxEntries,
		idleTTL:      idleTTL,
		now:          now,
		generation:   map[uint16]uint64{},
		persisted:    map[uint16]uint64{},
	}
}

// AddDouble increments a floating-point counter and returns its cumulative
// total and per-series start time. The resource namespace is required because
// OpenTelemetry resource attributes are part of a time series identity even
// though they are not repeated on each datapoint.
func (s *counterStore) AddDouble(resource, name string, attrs map[string]string, delta float64) (float64, time.Time) {
	if s == nil {
		return delta, time.Time{}
	}
	key := counterKey(resource, name, attrs)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.evictExpiredLocked(now)
	if series := s.doubleValues[key]; series != nil {
		if series.lastSeen.After(now) {
			now = series.lastSeen
		}
		series.value += delta
		series.lastSeen = now
		s.lru.MoveToBack(series.lru)
		s.touchCheckpointSeriesLocked(series.shard, series.checkpointLRU)
		return series.value, series.startedAt
	}
	shard := s.checkpointShardLocked()
	s.makeCheckpointShardRoomLocked(shard)
	s.makeRoomLocked()
	series := &doubleCounterSeries{value: delta, startedAt: now, lastSeen: now, shard: shard}
	series.lru = s.lru.PushBack(counterSeriesRef{key: key, valueType: counterValueTypeDouble})
	series.checkpointLRU = s.addCheckpointSeriesLocked(shard, counterSeriesRef{key: key, valueType: counterValueTypeDouble})
	s.doubleValues[key] = series
	s.markCheckpointShardDirtyLocked(shard)
	return series.value, series.startedAt
}

// AddInt is the integer-preserving counterpart to AddDouble. Counter values often
// exceed float64's exact integer range on busy network devices, so integer
// deltas must never pass through float64 on their way to an OTLP int datapoint.
func (s *counterStore) AddInt(resource, name string, attrs map[string]string, delta int64) (int64, time.Time) {
	if s == nil {
		return delta, time.Time{}
	}
	key := counterKey(resource, name, attrs)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.evictExpiredLocked(now)
	if series := s.intValues[key]; series != nil {
		if series.lastSeen.After(now) {
			now = series.lastSeen
		}
		if delta > 0 && series.value > math.MaxInt64-delta || delta < 0 && series.value < math.MinInt64-delta {
			// OTLP integer datapoints are signed int64. Start a new cumulative
			// epoch instead of wrapping through zero and fabricating a negative
			// monotonic counter when the in-process accumulator is exhausted.
			series.value = delta
			series.startedAt = now
		} else {
			series.value += delta
		}
		series.lastSeen = now
		s.lru.MoveToBack(series.lru)
		s.touchCheckpointSeriesLocked(series.shard, series.checkpointLRU)
		return series.value, series.startedAt
	}
	shard := s.checkpointShardLocked()
	s.makeCheckpointShardRoomLocked(shard)
	s.makeRoomLocked()
	series := &intCounterSeries{value: delta, startedAt: now, lastSeen: now, shard: shard}
	series.lru = s.lru.PushBack(counterSeriesRef{key: key, valueType: counterValueTypeInt})
	series.checkpointLRU = s.addCheckpointSeriesLocked(shard, counterSeriesRef{key: key, valueType: counterValueTypeInt})
	s.intValues[key] = series
	s.markCheckpointShardDirtyLocked(shard)
	return series.value, series.startedAt
}

func (s *counterStore) evictExpiredLocked(now time.Time) {
	if s.idleTTL <= 0 {
		return
	}
	cutoff := now.Add(-s.idleTTL)
	for oldest := s.lru.Front(); oldest != nil; oldest = s.lru.Front() {
		ref := oldest.Value.(counterSeriesRef)
		lastSeen := s.seriesLastSeenLocked(ref)
		if lastSeen.After(cutoff) {
			return
		}
		s.removeSeriesLocked(oldest, ref)
	}
}

func (s *counterStore) makeRoomLocked() {
	for s.lru.Len() >= s.maxEntries {
		oldest := s.lru.Front()
		if oldest == nil {
			return
		}
		s.removeSeriesLocked(oldest, oldest.Value.(counterSeriesRef))
	}
}

func (s *counterStore) seriesLastSeenLocked(ref counterSeriesRef) time.Time {
	if ref.valueType == counterValueTypeInt {
		if series := s.intValues[ref.key]; series != nil {
			return series.lastSeen
		}
		return time.Time{}
	}
	if series := s.doubleValues[ref.key]; series != nil {
		return series.lastSeen
	}
	return time.Time{}
}

func (s *counterStore) removeSeriesLocked(element *list.Element, ref counterSeriesRef) {
	if ref.valueType == counterValueTypeInt {
		series := s.intValues[ref.key]
		if series != nil {
			s.removeCheckpointSeriesLocked(series.shard, series.checkpointLRU)
		}
		delete(s.intValues, ref.key)
	} else {
		series := s.doubleValues[ref.key]
		if series != nil {
			s.removeCheckpointSeriesLocked(series.shard, series.checkpointLRU)
		}
		delete(s.doubleValues, ref.key)
	}
	s.lru.Remove(element)
}

func (s *counterStore) checkpointShardLocked() uint16 {
	if s.checkpoint == nil {
		return 0
	}
	shard, ok := checkpointShardWithRoom(s.shards, &s.nextShard)
	if !ok {
		return unassignedCheckpointShard
	}
	return shard
}

func (s *counterStore) addCheckpointSeriesLocked(shard uint16, ref counterSeriesRef) *list.Element {
	if s.checkpoint == nil {
		return nil
	}
	if shard == unassignedCheckpointShard {
		return nil
	}
	shardLRU := s.shards[shard]
	if shardLRU == nil {
		shardLRU = list.New()
		s.shards[shard] = shardLRU
	}
	return shardLRU.PushBack(ref)
}

func (s *counterStore) touchCheckpointSeriesLocked(shard uint16, element *list.Element) {
	if s.checkpoint == nil {
		return
	}
	if shardLRU := s.shards[shard]; shardLRU != nil && element != nil {
		shardLRU.MoveToBack(element)
	}
	s.markCheckpointShardDirtyLocked(shard)
}

func (s *counterStore) removeCheckpointSeriesLocked(shard uint16, element *list.Element) {
	if s.checkpoint == nil {
		return
	}
	if shardLRU := s.shards[shard]; shardLRU != nil && element != nil {
		shardLRU.Remove(element)
		if shardLRU.Len() == 0 {
			delete(s.shards, shard)
		}
	}
	s.markCheckpointShardDirtyLocked(shard)
}

func (s *counterStore) markCheckpointShardDirtyLocked(shard uint16) {
	if s.checkpoint != nil {
		if shard == unassignedCheckpointShard {
			return
		}
		s.generation[shard]++
	}
}

func (s *counterStore) makeCheckpointShardRoomLocked(shard uint16) {
	if s.checkpoint == nil {
		return
	}
	if shard == unassignedCheckpointShard {
		return
	}
	for shardLRU := s.shards[shard]; shardLRU != nil && shardLRU.Len() > checkpointShardEntries; shardLRU = s.shards[shard] {
		oldest := shardLRU.Front()
		if oldest == nil {
			return
		}
		ref := oldest.Value.(counterSeriesRef)
		if ref.valueType == counterValueTypeInt {
			series := s.intValues[ref.key]
			if series == nil {
				shardLRU.Remove(oldest)
				continue
			}
			s.removeSeriesLocked(series.lru, ref)
		} else {
			series := s.doubleValues[ref.key]
			if series == nil {
				shardLRU.Remove(oldest)
				continue
			}
			s.removeSeriesLocked(series.lru, ref)
		}
	}
}

func (s *counterStore) StartTime() time.Time {
	if s == nil {
		return time.Time{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startedAt
}

func (s *counterStore) enableCheckpoint(binding *checkpointBinding) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.checkpoint = binding
	s.shards = map[uint16]*list.List{}
	s.nextShard = 0
	for element := s.lru.Front(); element != nil; element = element.Next() {
		ref := element.Value.(counterSeriesRef)
		shard := s.checkpointShardLocked()
		if ref.valueType == counterValueTypeInt {
			series := s.intValues[ref.key]
			series.shard = shard
			series.checkpointLRU = s.addCheckpointSeriesLocked(shard, ref)
		} else {
			series := s.doubleValues[ref.key]
			series.shard = shard
			series.checkpointLRU = s.addCheckpointSeriesLocked(shard, ref)
		}
		s.markCheckpointShardDirtyLocked(shard)
	}
	for shard := range s.shards {
		s.makeCheckpointShardRoomLocked(shard)
	}
	s.mu.Unlock()
}

func (s *counterStore) restoreCheckpoint(ctx context.Context) {
	if s == nil {
		return
	}
	s.mu.Lock()
	binding := s.checkpoint
	s.mu.Unlock()
	loaded, ok := binding.load(ctx)
	if !ok {
		return
	}
	if err := s.applyCheckpoint(loaded); err != nil {
		binding.warnCorrupt(err)
		return
	}
	binding.acceptLoaded(loaded.active, loaded.clockAnchor)
	binding.markValid()
	s.persistCheckpoint(ctx)
}

func (s *counterStore) applyCheckpoint(loaded loadedCheckpoint) error {
	now := s.now()
	latestValidTime := checkpointLatestValidTime(now, loaded.clockAnchor)
	var metadata counterCheckpointMetadata
	if err := json.Unmarshal(loaded.metadata, &metadata); err != nil {
		return fmt.Errorf("decode delta counter checkpoint metadata: %w", err)
	}
	if metadata.StartedAt.IsZero() {
		return errors.New("delta counter checkpoint has an empty receiver start time")
	}
	if metadata.StartedAt.After(latestValidTime) {
		return errors.New("delta counter checkpoint receiver start time exceeds the allowed future skew")
	}
	metadataDirty := metadata.StartedAt.After(now)
	if metadataDirty {
		metadata.StartedAt = now
	}

	type restoredSeries struct {
		key       string
		valueType counterValueType
		intValue  int64
		double    float64
		startedAt time.Time
		lastSeen  time.Time
		shard     uint16
	}
	restored := make([]restoredSeries, 0, len(loaded.shards)*checkpointShardEntries)
	logicalKeys := map[string]struct{}{}
	normalizedShards := map[uint16]struct{}{}
	for shard, encoded := range loaded.shards {
		var checkpoint counterCheckpointShard
		if err := json.Unmarshal(encoded, &checkpoint); err != nil {
			return fmt.Errorf("decode delta counter checkpoint shard %d: %w", shard, err)
		}
		if checkpoint.Version != checkpointFormatVersion || checkpoint.Shard != shard {
			return fmt.Errorf("delta counter checkpoint shard %d has incompatible version or identity", shard)
		}
		if len(checkpoint.Integers)+len(checkpoint.Doubles) > checkpointShardEntries {
			return fmt.Errorf("delta counter checkpoint shard %d contains %d series; maximum is %d", shard, len(checkpoint.Integers)+len(checkpoint.Doubles), checkpointShardEntries)
		}
		for _, entry := range checkpoint.Integers {
			key, err := decodeCounterCheckpointKey(entry.Key)
			if err != nil {
				return errors.New("delta counter checkpoint contains an invalid integer series key")
			}
			if _, duplicate := logicalKeys[key]; duplicate {
				return errors.New("delta counter checkpoint contains a duplicate logical series")
			}
			if entry.StartedAt.IsZero() || entry.LastSeen.IsZero() || entry.LastSeen.Before(entry.StartedAt) {
				return errors.New("delta counter checkpoint contains invalid integer timestamps")
			}
			if entry.StartedAt.After(latestValidTime) || entry.LastSeen.After(latestValidTime) {
				return errors.New("delta counter checkpoint contains integer timestamps beyond the allowed future skew")
			}
			// The raw pair is ordered above. Capping both values to the same
			// restore time preserves LastSeen >= StartedAt.
			if entry.StartedAt.After(now) {
				entry.StartedAt = now
				normalizedShards[shard] = struct{}{}
			}
			if entry.LastSeen.After(now) {
				entry.LastSeen = now
				normalizedShards[shard] = struct{}{}
			}
			logicalKeys[key] = struct{}{}
			restored = append(restored, restoredSeries{key: key, valueType: counterValueTypeInt, intValue: entry.Value, startedAt: entry.StartedAt, lastSeen: entry.LastSeen, shard: shard})
		}
		for _, entry := range checkpoint.Doubles {
			key, err := decodeCounterCheckpointKey(entry.Key)
			if err != nil {
				return errors.New("delta counter checkpoint contains an invalid double series key")
			}
			if _, duplicate := logicalKeys[key]; duplicate {
				return errors.New("delta counter checkpoint contains a duplicate logical series")
			}
			if math.IsNaN(entry.Value) || math.IsInf(entry.Value, 0) {
				return errors.New("delta counter checkpoint contains a non-finite double")
			}
			if entry.StartedAt.IsZero() || entry.LastSeen.IsZero() || entry.LastSeen.Before(entry.StartedAt) {
				return errors.New("delta counter checkpoint contains invalid double timestamps")
			}
			if entry.StartedAt.After(latestValidTime) || entry.LastSeen.After(latestValidTime) {
				return errors.New("delta counter checkpoint contains double timestamps beyond the allowed future skew")
			}
			// Use the same cap for both fields to preserve their validated order.
			if entry.StartedAt.After(now) {
				entry.StartedAt = now
				normalizedShards[shard] = struct{}{}
			}
			if entry.LastSeen.After(now) {
				entry.LastSeen = now
				normalizedShards[shard] = struct{}{}
			}
			logicalKeys[key] = struct{}{}
			restored = append(restored, restoredSeries{key: key, valueType: counterValueTypeDouble, double: entry.Value, startedAt: entry.StartedAt, lastSeen: entry.LastSeen, shard: shard})
		}
	}
	if len(restored) > s.maxEntries {
		return fmt.Errorf("delta counter checkpoint contains %d series; maximum is %d", len(restored), s.maxEntries)
	}
	sort.Slice(restored, func(i, j int) bool {
		if restored[i].lastSeen.Equal(restored[j].lastSeen) {
			if restored[i].valueType == restored[j].valueType {
				return restored[i].key < restored[j].key
			}
			return restored[i].valueType < restored[j].valueType
		}
		return restored[i].lastSeen.Before(restored[j].lastSeen)
	})

	s.mu.Lock()
	defer s.mu.Unlock()
	s.intValues = map[string]*intCounterSeries{}
	s.doubleValues = map[string]*doubleCounterSeries{}
	s.lru.Init()
	s.shards = map[uint16]*list.List{}
	s.nextShard = 0
	s.startedAt = metadata.StartedAt
	s.metadataDirty = metadataDirty
	cutoff := now.Add(-s.idleTTL)
	prunedShards := map[uint16]struct{}{}
	for _, entry := range restored {
		if !entry.lastSeen.After(cutoff) {
			prunedShards[entry.shard] = struct{}{}
			continue
		}
		ref := counterSeriesRef{key: entry.key, valueType: entry.valueType}
		element := s.lru.PushBack(ref)
		shardElement := s.addCheckpointSeriesLocked(entry.shard, ref)
		if entry.valueType == counterValueTypeInt {
			s.intValues[entry.key] = &intCounterSeries{value: entry.intValue, startedAt: entry.startedAt, lastSeen: entry.lastSeen, lru: element, checkpointLRU: shardElement, shard: entry.shard}
		} else {
			s.doubleValues[entry.key] = &doubleCounterSeries{value: entry.double, startedAt: entry.startedAt, lastSeen: entry.lastSeen, lru: element, checkpointLRU: shardElement, shard: entry.shard}
		}
	}
	s.generation = map[uint16]uint64{}
	s.persisted = map[uint16]uint64{}
	for shard := range normalizedShards {
		s.generation[shard] = 1
	}
	for shard := range prunedShards {
		s.generation[shard]++
	}
	return nil
}

func (s *counterStore) persistCheckpoint(ctx context.Context) {
	if s == nil {
		return
	}
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	s.mu.Lock()
	binding := s.checkpoint
	s.mu.Unlock()
	if binding == nil {
		return
	}
	shards, active, generations, metadata, clockAnchor, dirty, err := s.checkpointSnapshot()
	if !dirty {
		return
	}
	if err != nil {
		binding.warn("Failed to encode Cisco OS delta counter checkpoint; collection will continue with in-memory state", err)
		return
	}
	if binding.persist(ctx, shards, active, metadata, clockAnchor) {
		s.mu.Lock()
		for shard, generation := range generations {
			if generation > s.persisted[shard] {
				s.persisted[shard] = generation
			}
		}
		s.metadataDirty = false
		s.mu.Unlock()
	}
}

func (s *counterStore) checkpointSnapshot() (map[uint16][]byte, map[uint16]bool, map[uint16]uint64, json.RawMessage, time.Time, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dirtyShards := make([]int, 0, len(s.generation))
	for shard, generation := range s.generation {
		if generation != s.persisted[shard] {
			dirtyShards = append(dirtyShards, int(shard))
		}
	}
	if len(dirtyShards) == 0 && !s.metadataDirty {
		return nil, nil, nil, nil, time.Time{}, false, nil
	}
	sort.Ints(dirtyShards)
	shards := make(map[uint16][]byte, len(dirtyShards))
	active := make(map[uint16]bool, len(dirtyShards))
	generations := make(map[uint16]uint64, len(dirtyShards))
	clockAnchor := checkpointClockAnchor(s.now(), s.startedAt)
	for _, index := range dirtyShards {
		shard := uint16(index)
		checkpoint := counterCheckpointShard{Version: checkpointFormatVersion, Shard: shard}
		var first *list.Element
		if shardLRU := s.shards[shard]; shardLRU != nil {
			first = shardLRU.Front()
		}
		for element := first; element != nil; element = element.Next() {
			ref := element.Value.(counterSeriesRef)
			encodedKey := base64.RawURLEncoding.EncodeToString([]byte(ref.key))
			if ref.valueType == counterValueTypeInt {
				series := s.intValues[ref.key]
				clockAnchor = checkpointClockAnchor(clockAnchor, series.startedAt)
				clockAnchor = checkpointClockAnchor(clockAnchor, series.lastSeen)
				checkpoint.Integers = append(checkpoint.Integers, intCounterCheckpoint{Key: encodedKey, Value: series.value, StartedAt: series.startedAt, LastSeen: series.lastSeen})
			} else {
				series := s.doubleValues[ref.key]
				clockAnchor = checkpointClockAnchor(clockAnchor, series.startedAt)
				clockAnchor = checkpointClockAnchor(clockAnchor, series.lastSeen)
				checkpoint.Doubles = append(checkpoint.Doubles, doubleCounterCheckpoint{Key: encodedKey, Value: series.value, StartedAt: series.startedAt, LastSeen: series.lastSeen})
			}
		}
		encoded, err := json.Marshal(checkpoint)
		if err != nil {
			return nil, nil, nil, nil, time.Time{}, false, err
		}
		shards[shard] = encoded
		active[shard] = len(checkpoint.Integers)+len(checkpoint.Doubles) > 0
		generations[shard] = s.generation[shard]
	}
	metadata, err := json.Marshal(counterCheckpointMetadata{StartedAt: s.startedAt})
	return shards, active, generations, metadata, clockAnchor, true, err
}

func decodeCounterCheckpointKey(encoded string) (string, error) {
	key, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(key) != sha256.Size {
		return "", errors.New("delta counter checkpoint contains an invalid series key")
	}
	return string(key), nil
}

func counterKey(resource, name string, attrs map[string]string) string {
	var b strings.Builder
	b.Grow(len(resource) + len(name) + 17*len(attrs))
	b.WriteString(strconv.Quote(resource))
	b.WriteByte('|')
	b.WriteString(name)
	if len(attrs) > 0 {
		keys := make([]string, 0, len(attrs))
		for k := range attrs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteByte('|')
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(strconv.Quote(attrs[k]))
		}
	}
	digest := sha256.Sum256([]byte(b.String()))
	return string(digest[:])
}
