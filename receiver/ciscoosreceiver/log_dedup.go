// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
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

const defaultLogDedupMaxEntries = 100_000

// logDeduplicator provides transactional deduplication for polled event APIs.
// Keys discovered by a scrape are committed only after the resulting batch is
// accepted by the next consumer.
type logDeduplicator struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	pending map[string]struct{}
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
	return count, nil
}

func combineSignalErrors(scrapeErr, consumeErr error) error {
	return errors.Join(scrapeErr, consumeErr)
}

func newLogDeduplicator() *logDeduplicator {
	return &logDeduplicator{seen: map[string]time.Time{}}
}

func (d *logDeduplicator) BeginBatch() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for key := range d.pending {
		delete(d.seen, key)
	}
	d.pending = map[string]struct{}{}
}

// MarkPending returns true only when key has not been observed before.
func (d *logDeduplicator) MarkPending(key string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.seen[key]; exists {
		return false
	}
	d.seen[key] = now
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
	if _, exists := d.seen[key]; exists {
		return false
	}
	d.seen[key] = now
	return true
}

func (d *logDeduplicator) CommitBatch() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pending = nil
}

func (d *logDeduplicator) RollbackBatch() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for key := range d.pending {
		delete(d.seen, key)
	}
	d.pending = nil
}

func (d *logDeduplicator) Forget(key string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.seen, key)
	delete(d.pending, key)
}

func (d *logDeduplicator) Expire(cutoff time.Time, maxEntries int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for key, ts := range d.seen {
		if ts.Before(cutoff) {
			delete(d.seen, key)
			delete(d.pending, key)
		}
	}
	if maxEntries <= 0 {
		maxEntries = defaultLogDedupMaxEntries
	}
	if len(d.seen) <= maxEntries {
		return
	}
	type entry struct {
		key string
		ts  time.Time
	}
	entries := make([]entry, 0, len(d.seen))
	for key, ts := range d.seen {
		entries = append(entries, entry{key: key, ts: ts})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ts.Before(entries[j].ts) })
	for _, item := range entries[:len(entries)-maxEntries] {
		delete(d.seen, item.key)
		delete(d.pending, item.key)
	}
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
