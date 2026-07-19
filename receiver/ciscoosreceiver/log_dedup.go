// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
)

const (
	defaultLogDedupMaxEntries  = 100_000
	logCheckpointFlushEvents   = 256
	logCheckpointFlushInterval = 5 * time.Second
)

// logDeduplicator provides transactional deduplication for polled event APIs.
// Keys discovered by a scrape are committed only after the resulting batch is
// accepted by the next consumer.
type logDeduplicator struct {
	mu            sync.Mutex
	persistMu     sync.Mutex
	seen          map[string]*logDedupEntry
	pending       map[string]struct{}
	streamPending map[string]struct{}
	checkpoint    *checkpointBinding
	shards        map[uint16]*list.List
	nextShard     uint16
	generation    map[uint16]uint64
	persisted     map[uint16]uint64
	accepted      uint64
	flushed       uint64
	lastAttempt   time.Time
	retryAfter    time.Time
	now           func() time.Time
	retention     logCheckpointRetention
}

type logDedupEntry struct {
	seenAt        time.Time
	shard         uint16
	checkpointLRU *list.Element
}

type logDedupCheckpointShard struct {
	Version int                       `json:"version"`
	Shard   uint16                    `json:"shard"`
	Entries []logDedupCheckpointEntry `json:"entries,omitempty"`
}

type logDedupCheckpointEntry struct {
	Key    string    `json:"key"`
	SeenAt time.Time `json:"seen_at"`
}

func consumeDeduplicatedLogs(ctx context.Context, next consumer.Logs, dedup *logDeduplicator, logs plog.Logs) (int, error) {
	count := logs.LogRecordCount()
	if count == 0 {
		dedup.RollbackBatch()
		return count, nil
	}
	if err := next.ConsumeLogs(ctx, logs); err != nil {
		dedup.RollbackBatch()
		return count, err
	}
	dedup.CommitBatch()
	dedup.persistCheckpoint(ctx, true)
	return count, nil
}

func combineSignalErrors(scrapeErr, consumeErr error) error {
	return errors.Join(scrapeErr, consumeErr)
}

func newLogDeduplicator() *logDeduplicator {
	return &logDeduplicator{
		seen:       map[string]*logDedupEntry{},
		generation: map[uint16]uint64{},
		persisted:  map[uint16]uint64{},
		now:        time.Now,
	}
}

func (d *logDeduplicator) BeginBatch() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for key := range d.pending {
		d.removeSeenLocked(key)
	}
	d.pending = map[string]struct{}{}
}

// MarkPending returns true only when key has not been observed before.
func (d *logDeduplicator) MarkPending(key string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	key = logDedupStateKey(key)
	if _, exists := d.seen[key]; exists {
		return false
	}
	d.addSeenLocked(key, now)
	if d.pending != nil {
		d.pending[key] = struct{}{}
	}
	return true
}

// MarkCommitted records a key delivered outside the polling transaction, such
// as an ISE pxGrid streaming message.
func (d *logDeduplicator) MarkCommitted(key string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	key = logDedupStateKey(key)
	if _, exists := d.seen[key]; exists {
		return false
	}
	d.addSeenLocked(key, now)
	if d.checkpoint != nil {
		if d.streamPending == nil {
			d.streamPending = map[string]struct{}{}
		}
		d.streamPending[key] = struct{}{}
	}
	return true
}

func (d *logDeduplicator) CommitBatch() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.checkpoint != nil {
		for key := range d.pending {
			if entry := d.seen[key]; entry != nil && entry.shard != unassignedCheckpointShard {
				d.generation[entry.shard]++
			}
			d.accepted++
		}
	}
	d.pending = nil
}

// ConfirmCommitted makes one streaming entry eligible for persistence. It must
// be called only after the next logs consumer accepts that entry.
func (d *logDeduplicator) ConfirmCommitted(key string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	key = logDedupStateKey(key)
	if _, pending := d.streamPending[key]; !pending {
		return
	}
	delete(d.streamPending, key)
	if entry := d.seen[key]; entry != nil && entry.shard != unassignedCheckpointShard {
		d.generation[entry.shard]++
	}
	d.accepted++
}

func (d *logDeduplicator) RollbackBatch() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for key := range d.pending {
		d.removeSeenLocked(key)
	}
	d.pending = nil
}

func (d *logDeduplicator) Forget(key string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	key = logDedupStateKey(key)
	d.removeSeenLocked(key)
	delete(d.pending, key)
	delete(d.streamPending, key)
}

func (d *logDeduplicator) Expire(cutoff time.Time, maxEntries int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if maxEntries <= 0 {
		maxEntries = defaultLogDedupMaxEntries
	}
	d.expireLocked(cutoff, maxEntries)
}

func (d *logDeduplicator) addSeenLocked(key string, seenAt time.Time) {
	entry := &logDedupEntry{seenAt: seenAt}
	if d.checkpoint != nil {
		entry.shard, _ = checkpointShardWithRoom(d.shards, &d.nextShard)
		d.addSeenToCheckpointShardLocked(key, entry)
	}
	d.seen[key] = entry
}

func (d *logDeduplicator) addSeenToCheckpointShardLocked(key string, entry *logDedupEntry) {
	if entry.shard == unassignedCheckpointShard {
		return
	}
	shardLRU := d.shards[entry.shard]
	if shardLRU == nil {
		shardLRU = list.New()
		d.shards[entry.shard] = shardLRU
	}
	entry.checkpointLRU = shardLRU.PushBack(key)
	d.generation[entry.shard]++
}

func (d *logDeduplicator) removeSeenLocked(key string) {
	entry := d.seen[key]
	if entry == nil {
		return
	}
	if d.checkpoint != nil {
		if entry.shard == unassignedCheckpointShard {
			delete(d.seen, key)
			return
		}
		if shardLRU := d.shards[entry.shard]; shardLRU != nil && entry.checkpointLRU != nil {
			shardLRU.Remove(entry.checkpointLRU)
			if shardLRU.Len() == 0 {
				delete(d.shards, entry.shard)
			}
		}
		d.generation[entry.shard]++
	}
	delete(d.seen, key)
}

func (d *logDeduplicator) enableCheckpoint(binding *checkpointBinding, retention logCheckpointRetention) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.checkpoint = binding
	d.retention = retention
	if d.retention.maxEntries <= 0 {
		d.retention.maxEntries = defaultLogDedupMaxEntries
	}
	if d.now == nil {
		d.now = time.Now
	}
	d.lastAttempt = d.now()
	d.shards = map[uint16]*list.List{}
	d.nextShard = 0
	for key, entry := range d.seen {
		entry.shard, _ = checkpointShardWithRoom(d.shards, &d.nextShard)
		d.addSeenToCheckpointShardLocked(key, entry)
	}
	d.mu.Unlock()
}

func (d *logDeduplicator) checkpointEnabled() bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.checkpoint != nil
}

func (d *logDeduplicator) restoreCheckpoint(ctx context.Context) {
	if d == nil {
		return
	}
	d.mu.Lock()
	binding := d.checkpoint
	d.mu.Unlock()
	loaded, ok := binding.load(ctx)
	if !ok {
		return
	}
	type restoredEntry struct {
		key    string
		seenAt time.Time
		shard  uint16
	}
	restored := make([]restoredEntry, 0, len(loaded.shards)*checkpointShardEntries)
	seen := map[string]struct{}{}
	for shard, encoded := range loaded.shards {
		var checkpoint logDedupCheckpointShard
		if err := json.Unmarshal(encoded, &checkpoint); err != nil {
			binding.warnCorrupt(fmt.Errorf("decode log dedup checkpoint shard %d: %w", shard, err))
			return
		}
		if checkpoint.Version != checkpointFormatVersion || checkpoint.Shard != shard {
			binding.warnCorrupt(fmt.Errorf("log dedup checkpoint shard %d has incompatible version or identity", shard))
			return
		}
		if len(checkpoint.Entries) > checkpointShardEntries {
			binding.warnCorrupt(fmt.Errorf("log dedup checkpoint shard %d contains %d entries; maximum is %d", shard, len(checkpoint.Entries), checkpointShardEntries))
			return
		}
		for _, entry := range checkpoint.Entries {
			if entry.Key == "" || entry.SeenAt.IsZero() {
				binding.warnCorrupt(fmt.Errorf("log dedup checkpoint shard %d contains an invalid entry", shard))
				return
			}
			if _, duplicate := seen[entry.Key]; duplicate {
				binding.warnCorrupt(errors.New("log dedup checkpoint contains a duplicate entry"))
				return
			}
			seen[entry.Key] = struct{}{}
			restored = append(restored, restoredEntry{key: entry.Key, seenAt: entry.SeenAt, shard: shard})
		}
	}
	if len(restored) > defaultLogDedupMaxEntries {
		binding.warnCorrupt(fmt.Errorf("log dedup checkpoint contains %d entries; maximum is %d", len(restored), defaultLogDedupMaxEntries))
		return
	}
	d.mu.Lock()
	d.seen = make(map[string]*logDedupEntry, len(restored))
	d.pending = nil
	d.streamPending = nil
	d.shards = map[uint16]*list.List{}
	d.nextShard = 0
	sort.Slice(restored, func(i, j int) bool {
		if restored[i].seenAt.Equal(restored[j].seenAt) {
			return restored[i].key < restored[j].key
		}
		return restored[i].seenAt.Before(restored[j].seenAt)
	})
	for _, item := range restored {
		entry := &logDedupEntry{seenAt: item.seenAt, shard: item.shard}
		d.addSeenToCheckpointShardLocked(item.key, entry)
		d.seen[item.key] = entry
	}
	d.generation = map[uint16]uint64{}
	d.persisted = map[uint16]uint64{}
	cutoff := time.Time{}
	if d.retention.ttl > 0 {
		cutoff = d.now().Add(-d.retention.ttl)
	}
	d.expireLocked(cutoff, d.retention.maxEntries)
	d.accepted = 0
	d.flushed = 0
	d.lastAttempt = d.now()
	d.retryAfter = time.Time{}
	d.mu.Unlock()
	binding.acceptLoaded(loaded.active)
	binding.markValid()
	d.persistCheckpoint(ctx, true)
}

func (d *logDeduplicator) persistCheckpoint(ctx context.Context, force bool) {
	if d == nil {
		return
	}
	d.persistMu.Lock()
	defer d.persistMu.Unlock()
	d.mu.Lock()
	binding := d.checkpoint
	if binding == nil {
		d.mu.Unlock()
		return
	}
	now := d.now()
	pendingAccepted := d.accepted - d.flushed
	if !force {
		if pendingAccepted == 0 || now.Before(d.retryAfter) || (pendingAccepted < logCheckpointFlushEvents && now.Sub(d.lastAttempt) < logCheckpointFlushInterval) {
			d.mu.Unlock()
			return
		}
	}
	d.enforceCheckpointBoundsLocked()
	dirty := make([]int, 0, len(d.generation))
	for shard, generation := range d.generation {
		if generation != d.persisted[shard] {
			dirty = append(dirty, int(shard))
		}
	}
	sort.Ints(dirty)
	shards := make(map[uint16][]byte, len(dirty))
	active := make(map[uint16]bool, len(dirty))
	generations := make(map[uint16]uint64, len(dirty))
	for _, index := range dirty {
		shard := uint16(index)
		checkpoint := logDedupCheckpointShard{Version: checkpointFormatVersion, Shard: shard}
		if shardLRU := d.shards[shard]; shardLRU != nil {
			for element := shardLRU.Front(); element != nil; element = element.Next() {
				key := element.Value.(string)
				if _, pending := d.pending[key]; pending {
					continue
				}
				if _, pending := d.streamPending[key]; pending {
					continue
				}
				checkpoint.Entries = append(checkpoint.Entries, logDedupCheckpointEntry{Key: key, SeenAt: d.seen[key].seenAt})
			}
		}
		encoded, err := json.Marshal(checkpoint)
		if err != nil {
			d.mu.Unlock()
			binding.warn("Failed to encode Cisco OS log dedup checkpoint; collection will continue with in-memory state", err)
			return
		}
		shards[shard] = encoded
		active[shard] = len(checkpoint.Entries) > 0
		generations[shard] = d.generation[shard]
	}
	accepted := d.accepted
	d.mu.Unlock()
	if len(dirty) == 0 {
		return
	}
	persisted := binding.persist(ctx, shards, active, nil)
	d.mu.Lock()
	d.lastAttempt = now
	if persisted {
		for shard, generation := range generations {
			if generation > d.persisted[shard] {
				d.persisted[shard] = generation
			}
		}
		if accepted > d.flushed {
			d.flushed = accepted
		}
		d.retryAfter = time.Time{}
	} else {
		d.retryAfter = now.Add(logCheckpointFlushInterval)
	}
	d.mu.Unlock()
}

func (d *logDeduplicator) enforceCheckpointBoundsLocked() {
	if len(d.seen) > defaultLogDedupMaxEntries {
		d.expireLocked(time.Time{}, defaultLogDedupMaxEntries)
	}
	for key, entry := range d.seen {
		if entry.checkpointLRU != nil {
			continue
		}
		entry.shard, _ = checkpointShardWithRoom(d.shards, &d.nextShard)
		d.addSeenToCheckpointShardLocked(key, entry)
	}
}

func (d *logDeduplicator) expireLocked(cutoff time.Time, maxEntries int) {
	if !cutoff.IsZero() {
		for key, entry := range d.seen {
			if entry.seenAt.Before(cutoff) && !d.deliveryPendingLocked(key) {
				d.removeSeenLocked(key)
			}
		}
	}
	if len(d.seen) <= maxEntries {
		return
	}
	entries := make([]logDedupCheckpointEntry, 0, len(d.seen))
	for key, entry := range d.seen {
		if d.deliveryPendingLocked(key) {
			continue
		}
		entries = append(entries, logDedupCheckpointEntry{Key: key, SeenAt: entry.seenAt})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].SeenAt.Before(entries[j].SeenAt) })
	removeCount := min(len(entries), len(d.seen)-maxEntries)
	for _, entry := range entries[:removeCount] {
		d.removeSeenLocked(entry.Key)
	}
}

func (d *logDeduplicator) deliveryPendingLocked(key string) bool {
	if _, pending := d.pending[key]; pending {
		return true
	}
	_, pending := d.streamPending[key]
	return pending
}

func logDedupStateKey(key string) string {
	digest := sha256.Sum256([]byte(key))
	return hex.EncodeToString(digest[:])
}

// logDedupKey returns a fixed-size key even when a controller supplies a very
// large identifier or event body. Both the stable identifier and canonical
// object content are included: exact replays are suppressed while a fault,
// alarm, session, or workflow that keeps its ID but changes state is emitted.
// The namespace remains part of the digest so identical vendor identifiers
// from different endpoints cannot collide.
func logDedupKey(namespace, stableID string, fallback any) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(namespace))
	_, _ = hash.Write([]byte{0})
	if stableID != "" {
		_, _ = hash.Write([]byte("id:"))
		_, _ = hash.Write([]byte(stableID))
		_, _ = hash.Write([]byte{0})
	}
	if fallback != nil {
		_, _ = hash.Write([]byte("object:"))
		encoded, err := json.Marshal(fallback)
		if err != nil {
			encoded = []byte(fmt.Sprintf("%T:%v", fallback, fallback))
		}
		_, _ = hash.Write(encoded)
	}
	return hex.EncodeToString(hash.Sum(nil))
}
