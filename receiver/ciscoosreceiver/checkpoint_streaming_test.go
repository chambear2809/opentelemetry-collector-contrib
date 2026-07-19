// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/fmc"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/ise"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func putFMCResumeTestCheckpoint(
	t *testing.T,
	backend *checkpointTestBackend,
	binding *checkpointBinding,
	cursor time.Time,
	shards ...fmcResumeCheckpointShard,
) []byte {
	t.Helper()
	active := make([]uint16, 0, len(shards))
	for _, shard := range shards {
		page, err := json.Marshal(shard)
		require.NoError(t, err)
		active = append(active, shard.Shard)
		backend.put(binding.shardKey(shard.Shard), page)
	}
	metadata, err := json.Marshal(fmcResumeCheckpointMetadata{Cursor: cursor})
	require.NoError(t, err)
	manifest, err := json.Marshal(checkpointManifest{Version: checkpointFormatVersion, Active: active, Metadata: metadata})
	require.NoError(t, err)
	backend.put(binding.manifestKey(), manifest)
	return manifest
}

func TestFMCEStreamerCheckpointResumesAndPrunesAcrossRestarts(t *testing.T) {
	backend := newCheckpointTestBackend()
	initial := time.Unix(1_900_000_000, 0).UTC()
	oldEventTime := initial.Add(time.Minute)
	newEventTime := oldEventTime.Add(10 * time.Second)
	first := newFMCEStreamerResumeState(initial)
	first.now = func() time.Time { return newEventTime }
	firstRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	firstRegistry.enableFMCResume("fmc-target", first)
	require.NoError(t, firstRegistry.Start(t.Context(), checkpointHost(backend)))
	first.commit("old-event", oldEventTime, oldEventTime)
	first.commit("new-event", newEventTime, newEventTime)
	first.persistCheckpoint(t.Context(), true)
	firstRegistry.Close(t.Context())

	restarted := newFMCEStreamerResumeState(initial)
	restarted.now = func() time.Time { return newEventTime.Add(time.Minute) }
	restartedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	restartedRegistry.enableFMCResume("fmc-target", restarted)
	require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.Equal(t, newEventTime, restarted.cursor)
	assert.Equal(t, newEventTime.Truncate(time.Second).Add(-fmcEStreamerResumeOverlap), restarted.requestStart())
	assert.True(t, restarted.seenBefore("new-event"))
	assert.False(t, restarted.seenBefore("old-event"), "events older than the restored resume overlap must be pruned")
	restartedRegistry.Close(t.Context())

	third := newFMCEStreamerResumeState(initial)
	third.now = func() time.Time { return newEventTime.Add(2 * time.Minute) }
	thirdRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	thirdRegistry.enableFMCResume("fmc-target", third)
	require.NoError(t, thirdRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.True(t, third.seenBefore("new-event"))
	assert.False(t, third.seenBefore("old-event"), "restore pruning must be persisted instead of repeated forever")
}

func TestFMCEStreamerCheckpointRestoredCursorPrecedesAdvancedColdStartLookback(t *testing.T) {
	backend := newCheckpointTestBackend()
	firstNow := time.Date(2090, time.January, 2, 3, 4, 5, 0, time.UTC)
	firstInitial := firstNow.Add(-10 * time.Minute)
	cursor := firstNow.Add(-time.Minute)
	first := newFMCEStreamerResumeState(firstInitial)
	first.now = func() time.Time { return firstNow }
	firstRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	firstRegistry.enableFMCResume("advanced-lookback-target", first)
	require.NoError(t, firstRegistry.Start(t.Context(), checkpointHost(backend)))
	first.commit("persisted-event", cursor, cursor)
	first.persistCheckpoint(t.Context(), true)
	firstRegistry.Close(t.Context())

	restartNow := firstNow.Add(2 * time.Hour)
	restartInitial := restartNow.Add(-10 * time.Minute)
	require.True(t, restartInitial.After(cursor), "the new cold-start lookback must advance beyond the persisted cursor")
	restarted := newFMCEStreamerResumeState(restartInitial)
	restarted.now = func() time.Time { return restartNow }
	restartedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	restartedRegistry.enableFMCResume("advanced-lookback-target", restarted)
	require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))

	assert.Equal(t, cursor, restarted.cursor)
	assert.Equal(t, fmcEStreamerRetentionStart(cursor), restarted.requestStart(), "a valid durable cursor must take precedence over the newly computed cold-start lookback")
	assert.True(t, restarted.seenBefore("persisted-event"))
}

func TestFMCEStreamerCheckpointNormalizesAnyFutureControllerTimeAcrossRestart(t *testing.T) {
	backend := newCheckpointTestBackend()
	observedAt := time.Date(2090, time.January, 2, 3, 4, 5, 0, time.UTC)
	controllerTime := observedAt.Add(fmcCheckpointFutureSkew - time.Minute)
	initial := observedAt.Add(-time.Hour)
	client, err := fmc.NewEStreamerClient(fmc.EStreamerConfig{
		Address: "fmc.example.test:8302", Name: "fmc", InitialTime: initial,
	})
	require.NoError(t, err)
	state := newFMCEStreamerResumeState(initial)
	state.now = func() time.Time { return observedAt }
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	registry.enableFMCResume("future-controller-target", state)
	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	sink := &consumertest.LogsSink{}
	receiver := &fmcEStreamerLogsReceiver{
		settings: receivertest.NewNopSettings(metadata.Type),
		config:   &Config{FMC: FMCConfig{}},
		consumer: sink,
	}
	event := fmc.EStreamerEvent{
		EventType: "connection", RecordType: 1, Timestamp: controllerTime, Body: fmc.Object{"eventId": "future-controller-event"},
	}

	require.NoError(t, receiver.consumeEStreamerEvent(t.Context(), client, state, event))
	require.Len(t, sink.AllLogs(), 1)
	record := sink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	assert.Equal(t, controllerTime, record.Timestamp().AsTime(), "the accepted log must retain its raw controller timestamp")
	assert.Equal(t, observedAt, state.cursor, "only resume state should be clamped to the local observation time")
	assert.Equal(t, observedAt, state.seen[fmcEStreamerEventKey(event)].eventTime)
	state.persistCheckpoint(t.Context(), true)
	registry.Close(t.Context())

	restartAt := observedAt.Add(time.Second)
	restartInitial := restartAt.Add(-500 * time.Millisecond)
	restarted := newFMCEStreamerResumeState(restartInitial)
	restarted.now = func() time.Time { return restartAt }
	restartedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	restartedRegistry.enableFMCResume("future-controller-target", restarted)
	require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))

	assert.False(t, restarted.checkpoint.corrupt.Load(), "live-persisted resume state must pass its own restore validation")
	assert.Equal(t, observedAt, restarted.cursor)
	assert.Equal(t, observedAt.Add(-fmcEStreamerResumeOverlap), restarted.requestStart(), "restart must resume behind the observation time instead of the bad future controller clock")
	assert.True(t, restarted.seenBefore(fmcEStreamerEventKey(event)))
}

func TestFMCEStreamerCheckpointSurvivesWallClockRollback(t *testing.T) {
	backend := newCheckpointTestBackend()
	firstObservation := time.Date(2090, time.January, 2, 3, 4, 5, 0, time.UTC)
	initial := firstObservation.Add(-time.Hour)
	first := newFMCEStreamerResumeState(initial)
	first.now = func() time.Time { return firstObservation }
	firstRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	firstRegistry.enableFMCResume("clock-rollback-target", first)
	require.NoError(t, firstRegistry.Start(t.Context(), checkpointHost(backend)))
	first.commit("event-before-clock-rollback", firstObservation.Add(-time.Second), firstObservation)
	first.persistCheckpoint(t.Context(), true)
	firstRegistry.Close(t.Context())

	restartAt := firstObservation.Add(-10 * time.Minute)
	restarted := newFMCEStreamerResumeState(initial)
	restarted.now = func() time.Time { return restartAt }
	restartedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	restartedRegistry.enableFMCResume("clock-rollback-target", restarted)
	require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.False(t, restarted.checkpoint.corrupt.Load())
	assert.Equal(t, restartAt, restarted.cursor)
	assert.Equal(t, restartAt.Add(-fmcEStreamerResumeOverlap), restarted.requestStart(), "rollback normalization must never resume ahead of the current clock")
	assert.True(t, restarted.seenBefore("event-before-clock-rollback"))
	restartedRegistry.Close(t.Context())
}

func TestFMCEStreamerRequestStartNeverStaysAheadAfterLiveClockRollback(t *testing.T) {
	firstObservation := time.Date(2090, time.January, 2, 3, 4, 5, 0, time.UTC)
	current := firstObservation
	state := newFMCEStreamerResumeState(firstObservation.Add(-time.Hour))
	state.now = func() time.Time { return current }
	state.commit("event-before-clock-rollback", firstObservation.Add(-time.Second), firstObservation)

	current = firstObservation.Add(-10 * time.Minute)
	assert.Equal(t, current.Add(-fmcEStreamerResumeOverlap), state.requestStart(), "a live host-clock rollback must not leave reconnect ahead of the current observation clock")
}

func TestFMCEStreamerCheckpointCommitSubstitutesZeroObservationTime(t *testing.T) {
	backend := newCheckpointTestBackend()
	now := time.Date(2090, time.January, 2, 3, 4, 5, 0, time.UTC)
	eventTime := now.Add(-time.Second)
	state := newFMCEStreamerResumeState(now.Add(-time.Hour))
	state.now = func() time.Time { return now }
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	registry.enableFMCResume("zero-observation-target", state)
	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))

	state.commit("zero-observation-event", eventTime, time.Time{})
	assert.Equal(t, now, state.seen["zero-observation-event"].seenAt)
	state.persistCheckpoint(t.Context(), true)
	registry.Close(t.Context())

	restarted := newFMCEStreamerResumeState(now.Add(-time.Hour))
	restarted.now = func() time.Time { return now.Add(time.Second) }
	restartedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	restartedRegistry.enableFMCResume("zero-observation-target", restarted)
	require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))

	assert.False(t, restarted.checkpoint.corrupt.Load())
	assert.Equal(t, eventTime, restarted.cursor)
	assert.True(t, restarted.seenBefore("zero-observation-event"))
}

func TestFMCEStreamerCheckpointAcceptsInjectedYear2090Envelope(t *testing.T) {
	backend := newCheckpointTestBackend()
	now := time.Date(2090, time.January, 2, 3, 4, 5, 0, time.UTC)
	initial := now.Add(-10 * time.Minute)
	eventTime := now.Add(-time.Second)
	first := newFMCEStreamerResumeState(initial)
	first.now = func() time.Time { return now }
	firstRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	firstRegistry.enableFMCResume("future-clock-target", first)
	require.NoError(t, firstRegistry.Start(t.Context(), checkpointHost(backend)))
	first.commit("year-2090-event", eventTime, now)
	first.persistCheckpoint(t.Context(), true)
	firstRegistry.Close(t.Context())

	restarted := newFMCEStreamerResumeState(initial)
	restarted.now = func() time.Time { return now.Add(time.Minute) }
	restartedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	restartedRegistry.enableFMCResume("future-clock-target", restarted)
	require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.Equal(t, eventTime, restarted.cursor)
	assert.Equal(t, eventTime.Truncate(time.Second).Add(-fmcEStreamerResumeOverlap), restarted.requestStart())
	assert.True(t, restarted.seenBefore("year-2090-event"))
}

func TestFMCEStreamerCheckpointRejectsInconsistentEnvelopeWithoutPruning(t *testing.T) {
	backend := newCheckpointTestBackend()
	now := time.Date(2090, time.January, 2, 3, 4, 5, 0, time.UTC)
	initial := now.Add(-10 * time.Minute)
	state := newFMCEStreamerResumeState(initial)
	state.now = func() time.Time { return now }
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	registry.enableFMCResume("inconsistent-target", state)
	binding := state.checkpoint
	eventTime := now.Add(-time.Second)
	page, err := json.Marshal(fmcResumeCheckpointShard{
		Version: checkpointFormatVersion,
		Shard:   0,
		Entries: []fmcResumeCheckpointEntry{{Key: "newer-than-cursor", EventTime: eventTime, SeenAt: now}},
	})
	require.NoError(t, err)
	metadataBytes, err := json.Marshal(fmcResumeCheckpointMetadata{Cursor: eventTime.Add(-time.Second)})
	require.NoError(t, err)
	manifest, err := json.Marshal(checkpointManifest{Version: checkpointFormatVersion, Active: []uint16{0}, Metadata: metadataBytes})
	require.NoError(t, err)
	backend.put(binding.shardKey(0), page)
	backend.put(binding.manifestKey(), manifest)

	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	assert.True(t, state.cursor.IsZero())
	assert.Equal(t, initial, state.requestStart(), "invalid durable state must retain the configured initial lookback")
	assert.False(t, state.seenBefore("newer-than-cursor"))
	assert.Equal(t, page, backend.value(binding.shardKey(0)), "invalid state must not be destructively pruned")
	assert.Equal(t, manifest, backend.value(binding.manifestKey()))
	batches, _, _, _ := backend.writeStats()
	assert.Zero(t, batches, "invalid state must not trigger a cleanup write")
}

func TestFMCEStreamerCheckpointRejectsCursorAheadOfRetainedEvidenceWithoutPruning(t *testing.T) {
	backend := newCheckpointTestBackend()
	now := time.Date(2090, time.January, 2, 3, 4, 5, 0, time.UTC)
	initial := now.Add(-24 * time.Hour)
	state := newFMCEStreamerResumeState(initial)
	state.now = func() time.Time { return now }
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	registry.enableFMCResume("cursor-ahead-target", state)
	binding := state.checkpoint
	evidenceTime := initial.Add(time.Minute)
	cursor := now
	page, err := json.Marshal(fmcResumeCheckpointShard{
		Version: checkpointFormatVersion,
		Shard:   0,
		Entries: []fmcResumeCheckpointEntry{{Key: "stale-evidence", EventTime: evidenceTime, SeenAt: evidenceTime}},
	})
	require.NoError(t, err)
	metadataBytes, err := json.Marshal(fmcResumeCheckpointMetadata{Cursor: cursor})
	require.NoError(t, err)
	manifest, err := json.Marshal(checkpointManifest{Version: checkpointFormatVersion, Active: []uint16{0}, Metadata: metadataBytes})
	require.NoError(t, err)
	backend.put(binding.shardKey(0), page)
	backend.put(binding.manifestKey(), manifest)

	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	assert.True(t, state.cursor.IsZero())
	assert.Equal(t, initial, state.requestStart(), "an unanchored cursor must not replace the configured lookback")
	assert.False(t, state.seenBefore("stale-evidence"))
	assert.Equal(t, page, backend.value(binding.shardKey(0)), "invalid state must not be destructively pruned")
	assert.Equal(t, manifest, backend.value(binding.manifestKey()))
	batches, _, _, _ := backend.writeStats()
	assert.Zero(t, batches, "invalid state must not trigger a cleanup write")
}

func TestFMCEStreamerCheckpointAcceptsShardedSizePrunedEvidence(t *testing.T) {
	backend := newCheckpointTestBackend()
	now := time.Date(2090, time.January, 2, 3, 4, 5, 0, time.UTC)
	initial := now.Add(-time.Hour)
	cursor := now.Add(-2 * time.Minute).Truncate(time.Second)
	state := newFMCEStreamerResumeState(initial)
	state.now = func() time.Time { return now }
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	registry.enableFMCResume("sharded-pruned-target", state)
	putFMCResumeTestCheckpoint(t, backend, state.checkpoint, cursor,
		fmcResumeCheckpointShard{
			Version: checkpointFormatVersion,
			Shard:   0,
			Entries: []fmcResumeCheckpointEntry{{Key: "old-entry", EventTime: cursor.Add(-10 * time.Minute), SeenAt: cursor.Add(-9 * time.Minute)}},
		},
		fmcResumeCheckpointShard{
			Version: checkpointFormatVersion,
			Shard:   7,
			Entries: []fmcResumeCheckpointEntry{{Key: "later-seen-evidence", EventTime: cursor.Add(-5 * time.Minute), SeenAt: cursor.Add(time.Minute)}},
		},
	)

	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	assert.False(t, state.checkpoint.corrupt.Load())
	assert.Equal(t, cursor, state.cursor)
	assert.False(t, state.seenBefore("old-entry"), "ordinary stale entries should still be pruned")
	assert.True(t, state.seenBefore("later-seen-evidence"), "later observation evidence must retain a size-pruned cursor anchor")
	assert.Nil(t, backend.value(state.checkpoint.shardKey(0)))
	registry.Close(t.Context())

	restarted := newFMCEStreamerResumeState(initial)
	restarted.now = func() time.Time { return now.Add(time.Minute) }
	restartedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	restartedRegistry.enableFMCResume("sharded-pruned-target", restarted)
	require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.False(t, restarted.checkpoint.corrupt.Load(), "a cleanup-persisted pruned checkpoint must remain valid")
	assert.Equal(t, cursor, restarted.cursor)
	assert.True(t, restarted.seenBefore("later-seen-evidence"))
}

func TestFMCEStreamerCheckpointRetainsOldCursorEvidenceAndDefinesEmptyState(t *testing.T) {
	backend := newCheckpointTestBackend()
	now := time.Date(2090, time.January, 2, 3, 4, 5, 0, time.UTC)
	initial := now.Add(-10 * time.Minute)
	oldCursor := now.Add(-2 * time.Hour)
	old := newFMCEStreamerResumeState(initial)
	old.now = func() time.Time { return now }
	oldRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	oldRegistry.enableFMCResume("old-anchor-target", old)
	putFMCResumeTestCheckpoint(t, backend, old.checkpoint, oldCursor, fmcResumeCheckpointShard{
		Version: checkpointFormatVersion,
		Shard:   0,
		Entries: []fmcResumeCheckpointEntry{{Key: "old-cursor-anchor", EventTime: oldCursor, SeenAt: oldCursor}},
	})
	require.NoError(t, oldRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.False(t, old.checkpoint.corrupt.Load())
	assert.Equal(t, fmcEStreamerRetentionStart(oldCursor), old.requestStart(), "the valid restored cursor must control the request even when the cold-start lookback is newer")
	assert.True(t, old.seenBefore("old-cursor-anchor"), "persistence must retain evidence for every nonzero cursor")
	var retainedManifest checkpointManifest
	require.NoError(t, json.Unmarshal(backend.value(old.checkpoint.manifestKey()), &retainedManifest))
	assert.Equal(t, []uint16{0}, retainedManifest.Active, "old cursor evidence must remain durable after restore pruning")
	oldRegistry.Close(t.Context())

	emptyZero := newFMCEStreamerResumeState(initial)
	emptyZero.now = func() time.Time { return now }
	emptyZeroRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	emptyZeroRegistry.enableFMCResume("empty-zero-target", emptyZero)
	putFMCResumeTestCheckpoint(t, backend, emptyZero.checkpoint, time.Time{})
	require.NoError(t, emptyZeroRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.False(t, emptyZero.checkpoint.corrupt.Load(), "an empty zero-cursor checkpoint is equivalent to absent state")
	assert.Equal(t, initial, emptyZero.requestStart())
	emptyZeroRegistry.Close(t.Context())

	emptyCursor := now.Add(-time.Minute)
	emptyNonzero := newFMCEStreamerResumeState(initial)
	emptyNonzero.now = func() time.Time { return now }
	emptyNonzeroRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	emptyNonzeroRegistry.enableFMCResume("empty-nonzero-target", emptyNonzero)
	manifest := putFMCResumeTestCheckpoint(t, backend, emptyNonzero.checkpoint, emptyCursor)
	require.NoError(t, emptyNonzeroRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.True(t, emptyNonzero.checkpoint.corrupt.Load())
	assert.True(t, emptyNonzero.cursor.IsZero())
	assert.Equal(t, initial, emptyNonzero.requestStart())
	assert.Equal(t, manifest, backend.value(emptyNonzero.checkpoint.manifestKey()), "invalid empty state must not be rewritten")
}

func TestFMCEStreamerCheckpointRejectsFutureEnvelope(t *testing.T) {
	backend := newCheckpointTestBackend()
	now := time.Date(2090, time.January, 2, 3, 4, 5, 0, time.UTC)
	initial := now.Add(-10 * time.Minute)
	state := newFMCEStreamerResumeState(initial)
	state.now = func() time.Time { return now }
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	registry.enableFMCResume("future-envelope-target", state)
	binding := state.checkpoint
	future := now.Add(fmcCheckpointFutureSkew + time.Second)
	page, err := json.Marshal(fmcResumeCheckpointShard{
		Version: checkpointFormatVersion,
		Shard:   0,
		Entries: []fmcResumeCheckpointEntry{{Key: "future-event", EventTime: future, SeenAt: now}},
	})
	require.NoError(t, err)
	metadataBytes, err := json.Marshal(fmcResumeCheckpointMetadata{Cursor: future})
	require.NoError(t, err)
	manifest, err := json.Marshal(checkpointManifest{Version: checkpointFormatVersion, Active: []uint16{0}, Metadata: metadataBytes})
	require.NoError(t, err)
	backend.put(binding.shardKey(0), page)
	backend.put(binding.manifestKey(), manifest)

	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	assert.True(t, state.cursor.IsZero())
	assert.Equal(t, initial, state.requestStart())
	assert.False(t, state.seenBefore("future-event"))
	assert.Equal(t, page, backend.value(binding.shardKey(0)))
	assert.Equal(t, manifest, backend.value(binding.manifestKey()))
	batches, _, _, _ := backend.writeStats()
	assert.Zero(t, batches, "future state must not trigger a cleanup write")
}

func TestFMCEStreamerHighRateCheckpointWritesAreBounded(t *testing.T) {
	backend := newCheckpointTestBackend()
	now := time.Unix(1_900_000_000, 0).UTC()
	state := newFMCEStreamerResumeState(now.Add(-time.Hour))
	state.now = func() time.Time { return now }
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	registry.enableFMCResume("high-rate-target", state)
	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))

	const eventCount = 4096
	for i := range eventCount {
		eventTime := now.Add(time.Duration(i) * time.Nanosecond)
		state.commit(fmt.Sprintf("event-%d", i), eventTime, eventTime)
		state.persistCheckpoint(t.Context(), false)
	}

	batches, operations, maxOperations, maxValueSize := backend.writeStats()
	assert.Equal(t, eventCount/fmcCheckpointFlushEvents, batches)
	assert.Less(t, batches, eventCount/100, "high-rate input must not cause one storage write per event")
	assert.LessOrEqual(t, maxOperations, fmcCheckpointFlushEvents/checkpointShardEntries+2, "one flush may touch only bounded pages plus the manifest")
	assert.LessOrEqual(t, operations, batches*(fmcCheckpointFlushEvents/checkpointShardEntries+2))
	assert.LessOrEqual(t, maxValueSize, maxCheckpointShardBytes)

	state.commit("interval-event", now.Add(time.Second), now.Add(time.Second))
	state.persistCheckpoint(t.Context(), false)
	batchesBeforeInterval, _, _, _ := backend.writeStats()
	assert.Equal(t, batches, batchesBeforeInterval)
	now = now.Add(fmcCheckpointFlushInterval)
	state.persistCheckpoint(t.Context(), false)
	batchesAfterInterval, _, _, _ := backend.writeStats()
	assert.Equal(t, batches+1, batchesAfterInterval, "an accepted partial batch must flush at the interval bound")
	for i := range fmcCheckpointFlushEvents {
		eventTime := now.Add(time.Duration(i+1) * time.Nanosecond)
		state.commit(fmt.Sprintf("post-interval-event-%d", i), eventTime, eventTime)
		state.persistCheckpoint(t.Context(), false)
	}
	batchesAfterPartialPage, _, maxOperations, _ := backend.writeStats()
	assert.Equal(t, batchesAfterInterval+1, batchesAfterPartialPage)
	assert.Equal(t, fmcCheckpointFlushEvents/checkpointShardEntries+2, maxOperations, "a partial page plus 256 events must still have a fixed write bound")
}

func TestFMCEStreamerShutdownPersistsOnlyAcceptedEvents(t *testing.T) {
	backend := newCheckpointTestBackend()
	initial := time.Unix(1_900_000_000, 0).UTC()
	client, err := fmc.NewEStreamerClient(fmc.EStreamerConfig{
		Address: "fmc.example.test:8302", Name: "fmc", InitialTime: initial,
	})
	require.NoError(t, err)
	state := newFMCEStreamerResumeState(initial)
	state.now = func() time.Time { return initial }
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	registry.enableFMCResume("shutdown-target", state)
	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	receiver := &fmcEStreamerLogsReceiver{
		settings: receivertest.NewNopSettings(metadata.Type),
		config:   &Config{FMC: FMCConfig{}},
		consumer: consumertest.NewErr(errors.New("downstream rejected event")),
		resumes:  map[*fmc.EStreamerClient]*fmcEStreamerResumeState{client: state},
	}
	rejected := fmc.EStreamerEvent{
		EventType: "connection", RecordType: 1, Timestamp: initial.Add(time.Second), Body: fmc.Object{"eventId": "rejected"},
	}
	require.Error(t, receiver.consumeEStreamerEvent(t.Context(), client, state, rejected))
	receiver.consumer = consumertest.NewErr(context.Canceled)
	canceled := fmc.EStreamerEvent{
		EventType: "connection", RecordType: 1, Timestamp: initial.Add(2 * time.Second), Body: fmc.Object{"eventId": "canceled"},
	}
	require.ErrorIs(t, receiver.consumeEStreamerEvent(t.Context(), client, state, canceled), context.Canceled)
	receiver.consumer = consumertest.NewNop()
	accepted := fmc.EStreamerEvent{
		EventType: "connection", RecordType: 1, Timestamp: initial.Add(3 * time.Second), Body: fmc.Object{"eventId": "accepted"},
	}
	require.NoError(t, receiver.consumeEStreamerEvent(t.Context(), client, state, accepted))
	batches, _, _, _ := backend.writeStats()
	assert.Zero(t, batches, "a partial accepted batch must remain debounced before shutdown")

	require.NoError(t, receiver.Shutdown(t.Context()))
	batches, _, _, _ = backend.writeStats()
	assert.Equal(t, 1, batches, "shutdown must best-effort flush the accepted partial batch")
	registry.Close(t.Context())

	restored := newFMCEStreamerResumeState(initial)
	restored.now = func() time.Time { return initial.Add(4 * time.Second) }
	restoredRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	restoredRegistry.enableFMCResume("shutdown-target", restored)
	require.NoError(t, restoredRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.True(t, restored.seenBefore(fmcEStreamerEventKey(accepted)))
	assert.False(t, restored.seenBefore(fmcEStreamerEventKey(rejected)))
	assert.False(t, restored.seenBefore(fmcEStreamerEventKey(canceled)), "failed or canceled delivery must never advance the checkpoint")
}

func TestISEPxGridHighRateCheckpointWritesAreBoundedAndFlushOnIntervalAndShutdown(t *testing.T) {
	backend := newCheckpointTestBackend()
	now := time.Unix(1_900_000_000, 0).UTC()
	seen := newLogDeduplicator()
	seen.now = func() time.Time { return now }
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	registry.enableLogDedup("ise", "pxgrid-target", seen, logCheckpointRetention{})
	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	receiver := &iseLogsReceiver{
		settings:  receivertest.NewNopSettings(metadata.Type),
		config:    &Config{},
		iseConfig: ISEConfig{Endpoint: "https://ise.example.test"},
		consumer:  consumertest.NewNop(),
		seen:      seen,
	}

	const eventCount = 4096
	for i := range eventCount {
		require.NoError(t, receiver.consumePxGridMessage(t.Context(), ise.StompMessage{
			Topic: "com.cisco.ise.session", MessageID: fmt.Sprintf("message-%d", i),
		}))
	}

	batches, operations, maxOperations, maxValueSize := backend.writeStats()
	assert.Equal(t, eventCount/logCheckpointFlushEvents, batches)
	assert.Less(t, batches, eventCount/100, "ISE streaming must not cause one storage write per message")
	assert.LessOrEqual(t, maxOperations, logCheckpointFlushEvents/checkpointShardEntries+2)
	assert.LessOrEqual(t, operations, batches*(logCheckpointFlushEvents/checkpointShardEntries+2))
	assert.LessOrEqual(t, maxValueSize, maxCheckpointShardBytes)

	require.NoError(t, receiver.consumePxGridMessage(t.Context(), ise.StompMessage{
		Topic: "com.cisco.ise.session", MessageID: "interval-message",
	}))
	now = now.Add(logCheckpointFlushInterval)
	seen.persistCheckpoint(t.Context(), false)
	batchesAfterInterval, _, _, _ := backend.writeStats()
	assert.Equal(t, batches+1, batchesAfterInterval, "an accepted partial batch must flush at the interval bound")
	for i := range logCheckpointFlushEvents {
		require.NoError(t, receiver.consumePxGridMessage(t.Context(), ise.StompMessage{
			Topic: "com.cisco.ise.session", MessageID: fmt.Sprintf("post-interval-message-%d", i),
		}))
	}
	batchesAfterPartialPage, _, maxOperations, _ := backend.writeStats()
	assert.Equal(t, batchesAfterInterval+1, batchesAfterPartialPage)
	assert.Equal(t, logCheckpointFlushEvents/checkpointShardEntries+2, maxOperations, "a partial page plus 256 messages must still have a fixed write bound")

	require.NoError(t, receiver.consumePxGridMessage(t.Context(), ise.StompMessage{
		Topic: "com.cisco.ise.session", MessageID: "shutdown-message",
	}))
	require.NoError(t, receiver.Shutdown(t.Context()))
	batchesAfterShutdown, _, _, _ := backend.writeStats()
	assert.Equal(t, batchesAfterPartialPage+1, batchesAfterShutdown, "shutdown must flush the accepted partial batch")
}

func TestISEPxGridShutdownPersistsOnlyAcceptedEvents(t *testing.T) {
	backend := newCheckpointTestBackend()
	now := time.Unix(1_900_000_000, 0).UTC()
	seen := newLogDeduplicator()
	seen.now = func() time.Time { return now }
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	registry.enableLogDedup("ise", "shutdown-target", seen, logCheckpointRetention{})
	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	receiver := &iseLogsReceiver{
		settings:  receivertest.NewNopSettings(metadata.Type),
		config:    &Config{},
		iseConfig: ISEConfig{Endpoint: "https://ise.example.test"},
		consumer:  consumertest.NewErr(errors.New("downstream rejected event")),
		seen:      seen,
	}
	rejected := ise.StompMessage{Topic: "com.cisco.ise.session", MessageID: "rejected"}
	require.Error(t, receiver.consumePxGridMessage(t.Context(), rejected))
	receiver.consumer = consumertest.NewErr(context.Canceled)
	canceled := ise.StompMessage{Topic: "com.cisco.ise.session", MessageID: "canceled"}
	require.ErrorIs(t, receiver.consumePxGridMessage(t.Context(), canceled), context.Canceled)
	receiver.consumer = consumertest.NewNop()
	accepted := ise.StompMessage{Topic: "com.cisco.ise.session", MessageID: "accepted"}
	require.NoError(t, receiver.consumePxGridMessage(t.Context(), accepted))

	require.NoError(t, receiver.Shutdown(t.Context()))
	registry.Close(t.Context())
	restored := newLogDeduplicator()
	restoredRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	restoredRegistry.enableLogDedup("ise", "shutdown-target", restored, logCheckpointRetention{})
	require.NoError(t, restoredRegistry.Start(t.Context(), checkpointHost(backend)))
	spec := iseEndpointSpec{group: "pxgrid", operation: "pxgrid.subscription", objectType: "pxgrid_message"}
	messageKey := func(message ise.StompMessage) string {
		return iseSeenKey(spec, ise.Object{"topic": message.Topic, "message_id": message.MessageID})
	}
	restored.BeginBatch()
	assert.False(t, restored.MarkPending(messageKey(accepted), now), "accepted delivery must be restored")
	assert.True(t, restored.MarkPending(messageKey(rejected), now), "rejected delivery must remain replayable")
	assert.True(t, restored.MarkPending(messageKey(canceled), now), "canceled delivery must remain replayable")
	restored.RollbackBatch()
}

func TestISEPxGridShutdownFlushesBeforeBlockedDataConnectClose(t *testing.T) {
	backend := newCheckpointTestBackend()
	now := time.Unix(1_900_000_000, 0).UTC()
	seen := newLogDeduplicator()
	seen.now = func() time.Time { return now }
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	registry.enableLogDedup("ise", "blocked-close-target", seen, logCheckpointRetention{})
	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	blocker := &blockingISEDataConnect{started: make(chan struct{}), release: make(chan struct{})}
	receiver := &iseLogsReceiver{
		settings:    receivertest.NewNopSettings(metadata.Type),
		config:      &Config{},
		iseConfig:   ISEConfig{Endpoint: "https://ise.example.test"},
		consumer:    consumertest.NewNop(),
		seen:        seen,
		dataConnect: blocker,
		closeDone:   make(chan struct{}),
	}
	accepted := ise.StompMessage{Topic: "com.cisco.ise.session", MessageID: "accepted-before-blocked-close"}
	require.NoError(t, receiver.consumePxGridMessage(t.Context(), accepted))
	batches, _, _, _ := backend.writeStats()
	assert.Zero(t, batches)

	shutdownCtx, shutdownCancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	startedAt := time.Now()
	err := receiver.Shutdown(shutdownCtx)
	shutdownCancel()
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(startedAt), time.Second)
	batches, _, _, _ = backend.writeStats()
	assert.Equal(t, 1, batches, "accepted pxGrid state must flush before waiting for Data Connect Close")
	select {
	case <-blocker.started:
	default:
		t.Fatal("Data Connect close did not start")
	}
	close(blocker.release)
	select {
	case <-receiver.closeDone:
	case <-time.After(time.Second):
		t.Fatal("Data Connect close did not finish after release")
	}
	registry.Close(t.Context())

	restored := newLogDeduplicator()
	restoredRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	restoredRegistry.enableLogDedup("ise", "blocked-close-target", restored, logCheckpointRetention{})
	require.NoError(t, restoredRegistry.Start(t.Context(), checkpointHost(backend)))
	spec := iseEndpointSpec{group: "pxgrid", operation: "pxgrid.subscription", objectType: "pxgrid_message"}
	key := iseSeenKey(spec, ise.Object{"topic": accepted.Topic, "message_id": accepted.MessageID})
	restored.BeginBatch()
	assert.False(t, restored.MarkPending(key, now), "accepted state must survive the close timeout and restart")
	restored.RollbackBatch()
}
