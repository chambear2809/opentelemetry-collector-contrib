// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLogDeduplicatorRollsBackUnconsumedBatch(t *testing.T) {
	dedup := newLogDeduplicator()
	now := time.Unix(100, 0)

	dedup.BeginBatch()
	assert.True(t, dedup.MarkPending("event-1", now))
	assert.False(t, dedup.MarkPending("event-1", now))
	dedup.RollbackBatch()

	dedup.BeginBatch()
	assert.True(t, dedup.MarkPending("event-1", now))
	dedup.CommitBatch()

	dedup.BeginBatch()
	assert.False(t, dedup.MarkPending("event-1", now))
	dedup.CommitBatch()
}

func TestLogDeduplicatorPendingKeyRemainsEligibleAfterConcurrentStreamDuplicate(t *testing.T) {
	dedup := newLogDeduplicator()
	now := time.Unix(100, 0)

	dedup.BeginBatch()
	assert.True(t, dedup.MarkPending("event-1", now))
	assert.False(t, dedup.MarkCommitted("event-1", now))
	dedup.RollbackBatch()

	assert.True(t, dedup.MarkCommitted("event-1", now))
}

func TestLogDeduplicatorUsesDefaultEntryCap(t *testing.T) {
	dedup := newLogDeduplicator()
	now := time.Unix(100, 0)
	for i := range defaultLogDedupMaxEntries + 10 {
		assert.True(t, dedup.MarkCommitted(logDedupKey("events", fmt.Sprintf("event-%d", i), nil), now))
	}

	dedup.Expire(now.Add(-time.Hour), 0)
	assert.Len(t, dedup.seen, defaultLogDedupMaxEntries)
}

func TestLogDedupKeyIsFixedSizeAndSeparatesEventBodies(t *testing.T) {
	first := logDedupKey("events", strings.Repeat("x", 1_000_000), nil)
	second := logDedupKey("events", "", map[string]any{"serial": "same", "id": "event-1"})
	third := logDedupKey("events", "", map[string]any{"serial": "same", "id": "event-2"})

	assert.Len(t, first, sha256.Size*2)
	assert.NotEqual(t, second, third)
}

func TestLogDedupKeyIncludesMutableContentWithStableID(t *testing.T) {
	first := logDedupKey("faults", "fault-1", map[string]any{"severity": "minor", "state": "raised"})
	replay := logDedupKey("faults", "fault-1", map[string]any{"state": "raised", "severity": "minor"})
	transition := logDedupKey("faults", "fault-1", map[string]any{"severity": "critical", "state": "raised"})
	otherID := logDedupKey("faults", "fault-2", map[string]any{"severity": "minor", "state": "raised"})

	assert.Equal(t, first, replay, "canonical JSON must suppress exact replays")
	assert.NotEqual(t, first, transition, "state changes under a stable ID must be emitted")
	assert.NotEqual(t, first, otherID, "stable identifiers must remain part of the key")
}
