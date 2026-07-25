// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"
)

type checkpointPollingTestReceiver struct {
	mu     sync.Mutex
	run    func(context.Context)
	cancel context.CancelFunc
	done   chan struct{}
}

type checkpointBlockingShutdownReceiver struct {
	mu       sync.Mutex
	calls    int
	detached bool
	childErr error

	enteredOnce sync.Once
	releaseOnce sync.Once
	entered     chan struct{}
	release     chan struct{}
}

func newCheckpointBlockingShutdownReceiver(childErr error) *checkpointBlockingShutdownReceiver {
	return &checkpointBlockingShutdownReceiver{
		childErr: childErr,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
}

func (*checkpointBlockingShutdownReceiver) Start(context.Context, component.Host) error {
	return nil
}

func (r *checkpointBlockingShutdownReceiver) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	r.calls++
	_, hasDeadline := ctx.Deadline()
	r.detached = ctx.Done() == nil && !hasDeadline
	r.mu.Unlock()
	r.enteredOnce.Do(func() { close(r.entered) })
	<-r.release
	return r.childErr
}

func (r *checkpointBlockingShutdownReceiver) shutdownState() (int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls, r.detached
}

func (r *checkpointBlockingShutdownReceiver) unblock() {
	r.releaseOnce.Do(func() { close(r.release) })
}

func newCheckpointPollingTestReceiver(run func(context.Context)) *checkpointPollingTestReceiver {
	return &checkpointPollingTestReceiver{run: run, done: make(chan struct{})}
}

func (r *checkpointPollingTestReceiver) Start(context.Context, component.Host) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() {
		defer close(r.done)
		r.run(ctx)
	}()
	return nil
}

func (r *checkpointPollingTestReceiver) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	cancel := r.cancel
	r.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type checkpointBlockingConsumer struct {
	err error

	enteredOnce  sync.Once
	canceledOnce sync.Once
	releaseOnce  sync.Once
	entered      chan struct{}
	canceled     chan struct{}
	release      chan struct{}
}

func newCheckpointBlockingConsumer(err error) *checkpointBlockingConsumer {
	return &checkpointBlockingConsumer{
		err:      err,
		entered:  make(chan struct{}),
		canceled: make(chan struct{}),
		release:  make(chan struct{}),
	}
}

func (*checkpointBlockingConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{}
}

func (c *checkpointBlockingConsumer) ConsumeMetrics(ctx context.Context, _ pmetric.Metrics) error {
	return c.consume(ctx)
}

func (c *checkpointBlockingConsumer) ConsumeLogs(ctx context.Context, _ plog.Logs) error {
	return c.consume(ctx)
}

func (c *checkpointBlockingConsumer) consume(ctx context.Context) error {
	c.enteredOnce.Do(func() { close(c.entered) })
	select {
	case <-ctx.Done():
		c.canceledOnce.Do(func() { close(c.canceled) })
		<-c.release
	case <-c.release:
	}
	return c.err
}

func (c *checkpointBlockingConsumer) unblock() {
	c.releaseOnce.Do(func() { close(c.release) })
}

func checkpointShutdownRaceBackend(t *testing.T) (*checkpointTestBackend, func()) {
	t.Helper()
	backend := newCheckpointTestBackend()
	backend.writesNeedLiveContext = true
	backend.closeEntered = make(chan struct{}, 1)
	closeRelease := make(chan struct{})
	backend.closeRelease = closeRelease
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(closeRelease) }) }
	t.Cleanup(release)
	return backend, release
}

func requireCheckpointSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}

func checkpointRaceMetrics(value int64) pmetric.Metrics {
	md := pmetric.NewMetrics()
	metric := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	metric.SetName("test.counter")
	metric.SetEmptySum().DataPoints().AppendEmpty().SetIntValue(value)
	return md
}

func TestPollingMetricsShutdownFlushesAcceptedCheckpointAfterCallerCancellation(t *testing.T) {
	backend, releaseClose := checkpointShutdownRaceBackend(t)
	now := time.Unix(1_900_000_000, 0).UTC()
	state := newCounterStoreWithConfig(now, counterStoreConfig{now: func() time.Time { return now }})
	registry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
	downstream := newCheckpointBlockingConsumer(nil)
	t.Cleanup(downstream.unblock)
	checkpointConsumer := registry.enableCounter("fmc", "shutdown-race-metrics", state, downstream)
	workerResult := make(chan error, 1)
	next := newCheckpointPollingTestReceiver(func(ctx context.Context) {
		value, _ := state.AddInt("resource", "requests", nil, 7)
		workerResult <- checkpointConsumer.ConsumeMetrics(ctx, checkpointRaceMetrics(value))
	})
	receiver := &checkpointedMetricsReceiver{next: next, checkpoints: registry}
	require.NoError(t, receiver.Start(t.Context(), checkpointHost(backend)))
	requireCheckpointSignal(t, downstream.entered, "polling metrics did not reach the downstream consumer")

	shutdownCtx, cancelShutdown := context.WithCancel(t.Context())
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- receiver.Shutdown(shutdownCtx) }()
	requireCheckpointSignal(t, downstream.canceled, "polling metrics did not observe worker cancellation")
	cancelShutdown()
	require.ErrorIs(t, <-shutdownDone, context.Canceled)

	registry.stateMu.Lock()
	assert.False(t, registry.closed, "storage must remain open while the accepted delivery is still running")
	registry.stateMu.Unlock()
	backend.mu.Lock()
	assert.Zero(t, backend.closeCalls)
	backend.mu.Unlock()

	downstream.unblock()
	requireCheckpointSignal(t, backend.closeEntered, "checkpoint storage did not close after the worker exited")
	require.NoError(t, <-workerResult)
	batches, operations, _, _ := backend.writeStats()
	assert.Equal(t, 2, batches, "the canceled worker write must fail and the live shutdown flush must publish once")
	assert.Equal(t, 2, operations)
	var checkpoint counterCheckpointShard
	require.NoError(t, json.Unmarshal(checkpointTestReferencedShard(t, backend, state.checkpoint, 0), &checkpoint))
	require.Len(t, checkpoint.Integers, 1)
	assert.Equal(t, int64(7), checkpoint.Integers[0].Value)

	releaseClose()
	require.NoError(t, receiver.Shutdown(t.Context()), "a later shutdown call must join the same cleanup")
	afterBatches, afterOperations, _, _ := backend.writeStats()
	assert.Equal(t, batches, afterBatches, "idempotent shutdown must not republish accepted state")
	assert.Equal(t, operations, afterOperations)
	backend.mu.Lock()
	assert.Equal(t, 1, backend.closeCalls)
	assert.True(t, backend.closeSucceeded)
	backend.mu.Unlock()

	restored := newCounterStoreWithConfig(now.Add(time.Second), counterStoreConfig{now: func() time.Time { return now.Add(time.Second) }})
	restoredRegistry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
	restoredRegistry.enableCounter("fmc", "shutdown-race-metrics", restored, consumertest.NewNop())
	require.NoError(t, restoredRegistry.Start(t.Context(), checkpointHost(backend)))
	restoredSeries := restored.intValues[counterKey("resource", "requests", nil)]
	require.NotNil(t, restoredSeries)
	assert.Equal(t, int64(7), restoredSeries.value)
	restoredRegistry.Close(t.Context())
}

func TestPollingLogsShutdownFlushesAcceptedCheckpointBeforeClose(t *testing.T) {
	backend, releaseClose := checkpointShutdownRaceBackend(t)
	now := time.Unix(1_900_000_000, 0).UTC()
	state := newLogDeduplicator()
	state.now = func() time.Time { return now }
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	registry.enableLogDedup("fmc", "shutdown-race-logs", state, logCheckpointRetention{})
	downstream := newCheckpointBlockingConsumer(nil)
	t.Cleanup(downstream.unblock)
	const eventKey = "accepted-during-shutdown"
	workerResult := make(chan error, 1)
	next := newCheckpointPollingTestReceiver(func(ctx context.Context) {
		state.BeginBatch()
		if !state.MarkPending(eventKey, now) {
			workerResult <- errors.New("polling-log test event was already present")
			return
		}
		_, err := consumeDeduplicatedLogs(ctx, downstream, state, oneLogRecord())
		workerResult <- err
	})
	receiver := &checkpointedLogsReceiver{next: next, checkpoints: registry}
	require.NoError(t, receiver.Start(t.Context(), checkpointHost(backend)))
	requireCheckpointSignal(t, downstream.entered, "polling logs did not reach the downstream consumer")

	shutdownDone := make(chan error, 1)
	shutdownCtx := t.Context()
	go func() { shutdownDone <- receiver.Shutdown(shutdownCtx) }()
	requireCheckpointSignal(t, downstream.canceled, "polling logs did not observe worker cancellation")
	downstream.unblock()
	requireCheckpointSignal(t, backend.closeEntered, "checkpoint storage closed before the polling-log flush completed")
	require.NoError(t, <-workerResult)
	batches, operations, _, _ := backend.writeStats()
	assert.Equal(t, 2, batches)
	assert.Equal(t, 2, operations)
	var checkpoint logDedupCheckpointShard
	require.NoError(t, json.Unmarshal(checkpointTestReferencedShard(t, backend, state.checkpoint, 0), &checkpoint))
	require.Len(t, checkpoint.Entries, 1)
	assert.Equal(t, logDedupStateKey(eventKey), checkpoint.Entries[0].Key)

	releaseClose()
	require.NoError(t, <-shutdownDone)
	require.NoError(t, receiver.Shutdown(t.Context()))
	afterBatches, afterOperations, _, _ := backend.writeStats()
	assert.Equal(t, batches, afterBatches)
	assert.Equal(t, operations, afterOperations)

	restored := newLogDeduplicator()
	restored.now = func() time.Time { return now.Add(time.Second) }
	restoredRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	restoredRegistry.enableLogDedup("fmc", "shutdown-race-logs", restored, logCheckpointRetention{})
	require.NoError(t, restoredRegistry.Start(t.Context(), checkpointHost(backend)))
	restored.BeginBatch()
	assert.False(t, restored.MarkPending(eventKey, now), "the accepted log must remain suppressed after restart")
	restored.RollbackBatch()
	restoredRegistry.Close(t.Context())
}

func TestPollingLogSafePersistSupersedesFailedAcceptedSnapshotBeforeShutdown(t *testing.T) {
	backend := newCheckpointTestBackend()
	current := time.Unix(1_900_000_000, 0).UTC()
	state := newLogDeduplicator()
	state.now = func() time.Time { return current }
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	registry.enableLogDedup("fmc", "superseded-shutdown-log", state, logCheckpointRetention{})
	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))

	const eventKey = "accepted-before-expiration"
	backend.batchWriteErr = errors.New("temporary checkpoint failure")
	state.BeginBatch()
	require.True(t, state.MarkPending(eventKey, current))
	_, err := consumeDeduplicatedLogs(t.Context(), consumertest.NewNop(), state, oneLogRecord())
	require.NoError(t, err)
	require.NotNil(t, state.acceptedSnapshot)
	assert.Empty(t, backend.value(state.checkpoint.manifestKey()))

	backend.batchWriteErr = nil
	current = current.Add(logCheckpointFlushInterval)
	state.Expire(current, 0)
	state.BeginBatch()
	count, err := consumeDeduplicatedLogs(t.Context(), consumertest.NewErr(errors.New("empty batch must not reach downstream")), state, plog.NewLogs())
	require.NoError(t, err)
	assert.Zero(t, count)
	assert.Nil(t, state.acceptedSnapshot, "the newer successful empty snapshot must retire the failed accepted snapshot")
	assert.Empty(t, checkpointTestManifest(t, backend, state.checkpoint).Active)

	batches, operations, _, _ := backend.writeStats()
	receiver := &checkpointedLogsReceiver{next: &checkpointTestLogsReceiver{}, checkpoints: registry}
	require.NoError(t, receiver.Shutdown(t.Context()))
	afterBatches, afterOperations, _, _ := backend.writeStats()
	assert.Equal(t, batches, afterBatches, "shutdown must not republish the superseded accepted snapshot")
	assert.Equal(t, operations, afterOperations)

	restored := newLogDeduplicator()
	restored.now = func() time.Time { return current.Add(time.Second) }
	restoredRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	restoredRegistry.enableLogDedup("fmc", "superseded-shutdown-log", restored, logCheckpointRetention{})
	require.NoError(t, restoredRegistry.Start(t.Context(), checkpointHost(backend)))
	restored.BeginBatch()
	assert.True(t, restored.MarkPending(eventKey, current), "the expired entry must not be resurrected by shutdown")
	restored.RollbackBatch()
	restoredRegistry.Close(t.Context())
}

func TestCheckpointShutdownUsesOneDetachedChildCallAndIsConcurrentSafe(t *testing.T) {
	backend, releaseClose := checkpointShutdownRaceBackend(t)
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	childErr := errors.New("one-shot child shutdown failure")
	next := newCheckpointBlockingShutdownReceiver(childErr)
	t.Cleanup(next.unblock)
	receiver := &checkpointedLogsReceiver{
		next:        next,
		checkpoints: registry,
	}

	callerCtx, cancelCaller := context.WithCancel(t.Context())
	firstResult := make(chan error, 1)
	go func() { firstResult <- receiver.Shutdown(callerCtx) }()
	requireCheckpointSignal(t, next.entered, "the detached child shutdown did not start")
	cancelCaller()
	require.ErrorIs(t, <-firstResult, context.Canceled)
	calls, detached := next.shutdownState()
	assert.Equal(t, 1, calls)
	assert.True(t, detached, "the shared child shutdown context must have no cancellation or deadline")
	registry.stateMu.Lock()
	assert.False(t, registry.closed, "storage must remain open while the child shutdown is blocked")
	registry.stateMu.Unlock()

	const callers = 8
	results := make(chan error, callers)
	shutdownCtx := t.Context()
	for range callers {
		go func() { results <- receiver.Shutdown(shutdownCtx) }()
	}
	calls, _ = next.shutdownState()
	assert.Equal(t, 1, calls, "all callers must share one child shutdown call")
	next.unblock()
	requireCheckpointSignal(t, backend.closeEntered, "checkpoint storage did not close after the child shutdown returned")
	select {
	case err := <-results:
		t.Fatalf("shutdown returned before ordered checkpoint cleanup completed: %v", err)
	default:
	}
	cleanupCtx, cancelCleanupCaller := context.WithCancel(t.Context())
	cleanupResult := make(chan error, 1)
	go func() { cleanupResult <- receiver.Shutdown(cleanupCtx) }()
	cancelCleanupCaller()
	require.ErrorIs(t, <-cleanupResult, context.Canceled, "caller cancellation during checkpoint cleanup must not report child completion")
	releaseClose()
	for range callers {
		err := <-results
		require.ErrorIs(t, err, childErr)
		assert.Equal(t, childErr, err)
	}
	require.ErrorIs(t, receiver.Shutdown(t.Context()), childErr)
	calls, _ = next.shutdownState()
	assert.Equal(t, 1, calls)
	backend.mu.Lock()
	assert.Equal(t, 1, backend.closeCalls)
	assert.True(t, backend.closeSucceeded)
	backend.mu.Unlock()
}

func TestPollingShutdownDoesNotPersistRejectedBatchMutations(t *testing.T) {
	deliveryErr := errors.New("downstream rejected batch")
	now := time.Unix(1_900_000_000, 0).UTC()

	t.Run("metrics", func(t *testing.T) {
		backend, releaseClose := checkpointShutdownRaceBackend(t)
		state := newCounterStoreWithConfig(now, counterStoreConfig{now: func() time.Time { return now }})
		registry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
		downstream := newCheckpointBlockingConsumer(deliveryErr)
		t.Cleanup(downstream.unblock)
		checkpointConsumer := registry.enableCounter("fmc", "rejected-shutdown-metrics", state, downstream)
		require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
		state.AddInt("resource", "requests", nil, 3)
		state.persistCheckpoint(t.Context())
		initialBatches, initialOperations, _, _ := backend.writeStats()

		workerResult := make(chan error, 1)
		next := newCheckpointPollingTestReceiver(func(ctx context.Context) {
			value, _ := state.AddInt("resource", "requests", nil, 5)
			workerResult <- checkpointConsumer.ConsumeMetrics(ctx, checkpointRaceMetrics(value))
		})
		receiver := &checkpointedMetricsReceiver{next: next, checkpoints: registry}
		require.NoError(t, receiver.Start(t.Context(), checkpointHost(backend)))
		requireCheckpointSignal(t, downstream.entered, "rejected polling metrics did not reach downstream")
		shutdownDone := make(chan error, 1)
		shutdownCtx := t.Context()
		go func() { shutdownDone <- receiver.Shutdown(shutdownCtx) }()
		requireCheckpointSignal(t, downstream.canceled, "rejected polling metrics did not observe cancellation")
		downstream.unblock()
		requireCheckpointSignal(t, backend.closeEntered, "metrics checkpoint storage did not close")
		require.ErrorIs(t, <-workerResult, deliveryErr)
		batches, operations, _, _ := backend.writeStats()
		assert.Equal(t, initialBatches, batches)
		assert.Equal(t, initialOperations, operations)
		var checkpoint counterCheckpointShard
		require.NoError(t, json.Unmarshal(checkpointTestReferencedShard(t, backend, state.checkpoint, 0), &checkpoint))
		require.Len(t, checkpoint.Integers, 1)
		assert.Equal(t, int64(3), checkpoint.Integers[0].Value)
		releaseClose()
		require.NoError(t, <-shutdownDone)
	})

	t.Run("logs", func(t *testing.T) {
		backend, releaseClose := checkpointShutdownRaceBackend(t)
		state := newLogDeduplicator()
		state.now = func() time.Time { return now }
		registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
		registry.enableLogDedup("fmc", "rejected-shutdown-logs", state, logCheckpointRetention{})
		require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
		state.BeginBatch()
		require.True(t, state.MarkPending("previously-accepted", now))
		_, err := consumeDeduplicatedLogs(t.Context(), consumertest.NewNop(), state, oneLogRecord())
		require.NoError(t, err)
		initialBatches, initialOperations, _, _ := backend.writeStats()

		downstream := newCheckpointBlockingConsumer(deliveryErr)
		t.Cleanup(downstream.unblock)
		workerResult := make(chan error, 1)
		next := newCheckpointPollingTestReceiver(func(ctx context.Context) {
			state.BeginBatch()
			if !state.MarkPending("rejected-during-shutdown", now) {
				workerResult <- errors.New("rejected polling-log test event was already present")
				return
			}
			_, err := consumeDeduplicatedLogs(ctx, downstream, state, oneLogRecord())
			workerResult <- err
		})
		receiver := &checkpointedLogsReceiver{next: next, checkpoints: registry}
		require.NoError(t, receiver.Start(t.Context(), checkpointHost(backend)))
		requireCheckpointSignal(t, downstream.entered, "rejected polling logs did not reach downstream")
		shutdownDone := make(chan error, 1)
		shutdownCtx := t.Context()
		go func() { shutdownDone <- receiver.Shutdown(shutdownCtx) }()
		requireCheckpointSignal(t, downstream.canceled, "rejected polling logs did not observe cancellation")
		downstream.unblock()
		requireCheckpointSignal(t, backend.closeEntered, "logs checkpoint storage did not close")
		require.ErrorIs(t, <-workerResult, deliveryErr)
		batches, operations, _, _ := backend.writeStats()
		assert.Equal(t, initialBatches, batches)
		assert.Equal(t, initialOperations, operations)
		var checkpoint logDedupCheckpointShard
		require.NoError(t, json.Unmarshal(checkpointTestReferencedShard(t, backend, state.checkpoint, 0), &checkpoint))
		require.Len(t, checkpoint.Entries, 1)
		assert.Equal(t, logDedupStateKey("previously-accepted"), checkpoint.Entries[0].Key)
		releaseClose()
		require.NoError(t, <-shutdownDone)
	})
}
