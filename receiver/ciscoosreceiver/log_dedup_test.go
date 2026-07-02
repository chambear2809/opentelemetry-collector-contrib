// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
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
