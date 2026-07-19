// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/extension/xextension/storage"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	aciinternal "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/aci"
	fmcinternal "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/fmc"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

var checkpointTestStorageID = component.MustNewIDWithName("file_storage", "checkpoints")

type checkpointTestBackend struct {
	mu sync.Mutex

	values map[string][]byte

	getErr                error
	batchReadErr          error
	batchWriteErr         error
	deleteErr             error
	closeErr              error
	batchEntered          chan struct{}
	batchRelease          <-chan struct{}
	closeEntered          chan struct{}
	closeRelease          <-chan struct{}
	closeNeedsLiveContext bool

	writeBatches   int
	writeOps       int
	maxWriteOps    int
	maxValueSize   int
	closeCalls     int
	closeSucceeded bool
}

func newCheckpointTestBackend() *checkpointTestBackend {
	return &checkpointTestBackend{values: map[string][]byte{}}
}

func (b *checkpointTestBackend) put(key string, value []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.values[key] = append([]byte(nil), value...)
}

func (b *checkpointTestBackend) value(key string) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.values[key]...)
}

func (b *checkpointTestBackend) writeStats() (batches, operations, maxOperations, maxValueSize int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.writeBatches, b.writeOps, b.maxWriteOps, b.maxValueSize
}

type checkpointTestClient struct {
	backend *checkpointTestBackend
}

func (c *checkpointTestClient) Get(_ context.Context, key string) ([]byte, error) {
	c.backend.mu.Lock()
	defer c.backend.mu.Unlock()
	if c.backend.getErr != nil {
		return nil, c.backend.getErr
	}
	return append([]byte(nil), c.backend.values[key]...), nil
}

func (c *checkpointTestClient) Set(_ context.Context, key string, value []byte) error {
	c.backend.mu.Lock()
	defer c.backend.mu.Unlock()
	if c.backend.batchWriteErr != nil {
		return c.backend.batchWriteErr
	}
	c.backend.values[key] = append([]byte(nil), value...)
	return nil
}

func (c *checkpointTestClient) Delete(_ context.Context, key string) error {
	c.backend.mu.Lock()
	defer c.backend.mu.Unlock()
	if c.backend.deleteErr != nil {
		return c.backend.deleteErr
	}
	delete(c.backend.values, key)
	return nil
}

func (c *checkpointTestClient) Batch(_ context.Context, operations ...*storage.Operation) error {
	if c.backend.batchEntered != nil {
		select {
		case c.backend.batchEntered <- struct{}{}:
		default:
		}
	}
	if c.backend.batchRelease != nil {
		<-c.backend.batchRelease
	}
	c.backend.mu.Lock()
	defer c.backend.mu.Unlock()
	hasRead := false
	hasWrite := false
	hasDelete := false
	writeOperations := 0
	for _, operation := range operations {
		switch operation.Type {
		case storage.Get:
			hasRead = true
		case storage.Set:
			hasWrite = true
			writeOperations++
		case storage.Delete:
			hasWrite = true
			hasDelete = true
			writeOperations++
		}
	}
	if hasWrite {
		c.backend.writeBatches++
		c.backend.writeOps += writeOperations
		c.backend.maxWriteOps = max(c.backend.maxWriteOps, writeOperations)
	}
	if hasRead && c.backend.batchReadErr != nil {
		return c.backend.batchReadErr
	}
	if hasDelete && c.backend.deleteErr != nil {
		return c.backend.deleteErr
	}
	if hasWrite && c.backend.batchWriteErr != nil {
		return c.backend.batchWriteErr
	}
	for _, operation := range operations {
		switch operation.Type {
		case storage.Get:
			operation.Value = append([]byte(nil), c.backend.values[operation.Key]...)
		case storage.Set:
			c.backend.maxValueSize = max(c.backend.maxValueSize, len(operation.Value))
			c.backend.values[operation.Key] = append([]byte(nil), operation.Value...)
		case storage.Delete:
			delete(c.backend.values, operation.Key)
		}
	}
	return nil
}

func (c *checkpointTestClient) Close(ctx context.Context) error {
	c.backend.mu.Lock()
	c.backend.closeCalls++
	err := c.backend.closeErr
	needsLiveContext := c.backend.closeNeedsLiveContext
	c.backend.mu.Unlock()
	if c.backend.closeEntered != nil {
		select {
		case c.backend.closeEntered <- struct{}{}:
		default:
		}
	}
	if c.backend.closeRelease != nil {
		<-c.backend.closeRelease
	}
	if err == nil && needsLiveContext {
		err = ctx.Err()
	}
	c.backend.mu.Lock()
	if err == nil {
		c.backend.closeSucceeded = true
	}
	c.backend.mu.Unlock()
	return err
}

type checkpointTestExtension struct {
	backend        *checkpointTestBackend
	acquireErr     error
	nilClient      bool
	acquireEntered chan struct{}
	acquireRelease <-chan struct{}
}

var _ storage.Extension = (*checkpointTestExtension)(nil)

func (*checkpointTestExtension) Start(context.Context, component.Host) error { return nil }
func (*checkpointTestExtension) Shutdown(context.Context) error              { return nil }

func (e *checkpointTestExtension) GetClient(context.Context, component.Kind, component.ID, string) (storage.Client, error) {
	if e.acquireEntered != nil {
		select {
		case e.acquireEntered <- struct{}{}:
		default:
		}
	}
	if e.acquireRelease != nil {
		<-e.acquireRelease
	}
	if e.acquireErr != nil {
		return nil, e.acquireErr
	}
	if e.nilClient {
		return nil, nil
	}
	return &checkpointTestClient{backend: e.backend}, nil
}

type checkpointTestNonStorageExtension struct{}

func (*checkpointTestNonStorageExtension) Start(context.Context, component.Host) error { return nil }
func (*checkpointTestNonStorageExtension) Shutdown(context.Context) error              { return nil }

type checkpointTestHost struct {
	extensions map[component.ID]component.Component
}

func (h checkpointTestHost) GetExtensions() map[component.ID]component.Component {
	return h.extensions
}

func checkpointHost(backend *checkpointTestBackend) checkpointTestHost {
	return checkpointTestHost{extensions: map[component.ID]component.Component{
		checkpointTestStorageID: &checkpointTestExtension{backend: backend},
	}}
}

type checkpointTestLogsReceiver struct {
	startCalls int
	startErr   error
}

func (r *checkpointTestLogsReceiver) Start(context.Context, component.Host) error {
	r.startCalls++
	return r.startErr
}

func (*checkpointTestLogsReceiver) Shutdown(context.Context) error { return nil }

func newCheckpointTestRegistry(signal string, logger *zap.Logger) *checkpointRegistry {
	return newCheckpointRegistry(
		checkpointTestStorageID,
		component.NewIDWithName(metadata.Type, "checkpoint-test"),
		signal,
		logger,
	)
}

func TestCheckpointConfiguredStorageAcquisitionFailureStopsStart(t *testing.T) {
	acquireErr := errors.New("storage unavailable")
	tests := []struct {
		name    string
		host    component.Host
		wantErr string
	}{
		{name: "nil host", wantErr: "requires a Collector host"},
		{name: "missing extension", host: checkpointTestHost{extensions: map[component.ID]component.Component{}}, wantErr: "was not found"},
		{
			name: "wrong extension type",
			host: checkpointTestHost{extensions: map[component.ID]component.Component{
				checkpointTestStorageID: &checkpointTestNonStorageExtension{},
			}},
			wantErr: "does not implement the storage interface",
		},
		{
			name: "client acquisition error",
			host: checkpointTestHost{extensions: map[component.ID]component.Component{
				checkpointTestStorageID: &checkpointTestExtension{backend: newCheckpointTestBackend(), acquireErr: acquireErr},
			}},
			wantErr: acquireErr.Error(),
		},
		{
			name: "nil client",
			host: checkpointTestHost{extensions: map[component.ID]component.Component{
				checkpointTestStorageID: &checkpointTestExtension{backend: newCheckpointTestBackend(), nilClient: true},
			}},
			wantErr: "returned a nil client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := &checkpointTestLogsReceiver{}
			wrapped := &checkpointedLogsReceiver{
				next:        next,
				checkpoints: newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop()),
			}
			err := wrapped.Start(t.Context(), tt.host)
			require.ErrorContains(t, err, tt.wantErr)
			assert.Zero(t, next.startCalls, "collection must not start without the configured storage client")
		})
	}
}

func TestCheckpointShutdownDeadlineDoesNotWaitForBlockedBatch(t *testing.T) {
	backend := newCheckpointTestBackend()
	backend.batchEntered = make(chan struct{}, 1)
	batchRelease := make(chan struct{})
	backend.batchRelease = batchRelease
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	batchDone := make(chan error, 1)
	go func() {
		available, err := registry.batch(t.Context(), storage.SetOperation("blocked", []byte("value")))
		if !available && err == nil {
			err = errors.New("checkpoint storage became unavailable before the blocked batch started")
		}
		batchDone <- err
	}()
	select {
	case <-backend.batchEntered:
	case <-time.After(time.Second):
		t.Fatal("checkpoint batch did not enter storage")
	}

	wrapper := &checkpointedLogsReceiver{next: &checkpointTestLogsReceiver{}, checkpoints: registry}
	shutdownCtx, shutdownCancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	startedAt := time.Now()
	require.NoError(t, wrapper.Shutdown(shutdownCtx))
	shutdownCancel()
	assert.Less(t, time.Since(startedAt), time.Second)
	available, err := registry.batch(t.Context(), storage.SetOperation("late", []byte("value")))
	require.NoError(t, err)
	assert.False(t, available, "checkpoint operations must not start after close begins")
	backend.mu.Lock()
	assert.Zero(t, backend.closeCalls, "Client.Close must not race the in-flight batch")
	backend.mu.Unlock()

	close(batchRelease)
	require.NoError(t, <-batchDone)
	registry.Close(t.Context())
	backend.mu.Lock()
	assert.Equal(t, 1, backend.closeCalls)
	backend.mu.Unlock()
}

func TestCheckpointCloseEventuallyUsesLiveContextAfterCallerDeadline(t *testing.T) {
	backend := newCheckpointTestBackend()
	backend.batchEntered = make(chan struct{}, 1)
	batchRelease := make(chan struct{})
	backend.batchRelease = batchRelease
	backend.closeNeedsLiveContext = true
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	batchDone := make(chan error, 1)
	go func() {
		_, err := registry.batch(t.Context(), storage.SetOperation("blocked-past-close-deadline", []byte("value")))
		batchDone <- err
	}()
	select {
	case <-backend.batchEntered:
	case <-time.After(time.Second):
		t.Fatal("checkpoint batch did not enter storage")
	}

	wrapper := &checkpointedLogsReceiver{next: &checkpointTestLogsReceiver{}, checkpoints: registry}
	shutdownCtx, shutdownCancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	require.NoError(t, wrapper.Shutdown(shutdownCtx))
	shutdownCancel()
	backend.mu.Lock()
	assert.Zero(t, backend.closeCalls, "Client.Close must wait for the in-flight batch")
	backend.mu.Unlock()

	close(batchRelease)
	require.NoError(t, <-batchDone)
	registry.Close(t.Context())
	backend.mu.Lock()
	assert.Equal(t, 1, backend.closeCalls)
	assert.True(t, backend.closeSucceeded, "eventual Client.Close must receive a live context after the caller deadline")
	backend.mu.Unlock()
}

func TestCheckpointStartCloseRaceEventuallyClosesUnregisteredClientWithLiveContext(t *testing.T) {
	backend := newCheckpointTestBackend()
	backend.closeNeedsLiveContext = true
	acquireEntered := make(chan struct{}, 1)
	acquireRelease := make(chan struct{})
	extension := &checkpointTestExtension{
		backend:        backend,
		acquireEntered: acquireEntered,
		acquireRelease: acquireRelease,
	}
	host := checkpointTestHost{extensions: map[component.ID]component.Component{checkpointTestStorageID: extension}}
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	startCtx, startCancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer startCancel()
	startDone := make(chan error, 1)
	go func() { startDone <- registry.Start(startCtx, host) }()
	select {
	case <-acquireEntered:
	case <-time.After(time.Second):
		t.Fatal("storage client acquisition did not start")
	}

	registry.Close(t.Context())
	<-startCtx.Done()
	close(acquireRelease)
	require.ErrorContains(t, <-startDone, "closed while storage started")
	require.Eventually(t, func() bool {
		backend.mu.Lock()
		defer backend.mu.Unlock()
		return backend.closeCalls == 1 && backend.closeSucceeded
	}, time.Second, time.Millisecond, "the unregistered client must receive a live asynchronous close context")
}

func TestCheckpointShutdownCooperativelyDrainsBeforeClose(t *testing.T) {
	backend := newCheckpointTestBackend()
	backend.batchEntered = make(chan struct{}, 1)
	batchRelease := make(chan struct{})
	backend.batchRelease = batchRelease
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	batchDone := make(chan error, 1)
	go func() {
		_, err := registry.batch(t.Context(), storage.SetOperation("drained", []byte("value")))
		batchDone <- err
	}()
	select {
	case <-backend.batchEntered:
	case <-time.After(time.Second):
		t.Fatal("checkpoint batch did not enter storage")
	}

	wrapper := &checkpointedLogsReceiver{next: &checkpointTestLogsReceiver{}, checkpoints: registry}
	shutdownCtx, shutdownCancel := context.WithTimeout(t.Context(), time.Second)
	defer shutdownCancel()
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- wrapper.Shutdown(shutdownCtx) }()
	require.Eventually(t, func() bool {
		registry.stateMu.Lock()
		defer registry.stateMu.Unlock()
		return registry.closed
	}, time.Second, time.Millisecond)
	close(batchRelease)
	require.NoError(t, <-batchDone)
	require.NoError(t, <-shutdownDone)
	assert.Equal(t, []byte("value"), backend.value("drained"))
	backend.mu.Lock()
	assert.Equal(t, 1, backend.closeCalls)
	backend.mu.Unlock()
}

func TestCheckpointShutdownDeadlineDoesNotWaitForBlockedClientClose(t *testing.T) {
	backend := newCheckpointTestBackend()
	backend.closeEntered = make(chan struct{}, 1)
	closeRelease := make(chan struct{})
	backend.closeRelease = closeRelease
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	wrapper := &checkpointedLogsReceiver{next: &checkpointTestLogsReceiver{}, checkpoints: registry}

	shutdownCtx, shutdownCancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	startedAt := time.Now()
	require.NoError(t, wrapper.Shutdown(shutdownCtx))
	shutdownCancel()
	assert.Less(t, time.Since(startedAt), time.Second)
	select {
	case <-backend.closeEntered:
	default:
		t.Fatal("checkpoint Client.Close was not attempted during shutdown")
	}
	available, err := registry.batch(t.Context(), storage.SetOperation("late", []byte("value")))
	require.NoError(t, err)
	assert.False(t, available, "checkpoint operations must not start while Client.Close is blocked")

	close(closeRelease)
	registry.Close(t.Context())
	backend.mu.Lock()
	assert.Equal(t, 1, backend.closeCalls)
	backend.mu.Unlock()
}

func TestCheckpointStartRollbackDeadlineDoesNotWaitForBlockedClientClose(t *testing.T) {
	backend := newCheckpointTestBackend()
	backend.closeEntered = make(chan struct{}, 1)
	closeRelease := make(chan struct{})
	backend.closeRelease = closeRelease
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	startErr := errors.New("receiver start failed")
	wrapper := &checkpointedLogsReceiver{
		next:        &checkpointTestLogsReceiver{startErr: startErr},
		checkpoints: registry,
	}
	startCtx, startCancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	startedAt := time.Now()
	err := wrapper.Start(startCtx, checkpointHost(backend))
	startCancel()
	require.ErrorIs(t, err, startErr)
	assert.Less(t, time.Since(startedAt), time.Second)
	select {
	case <-backend.closeEntered:
	default:
		t.Fatal("checkpoint Client.Close was not attempted during rollback")
	}

	close(closeRelease)
	registry.Close(t.Context())
	backend.mu.Lock()
	assert.Equal(t, 1, backend.closeCalls)
	backend.mu.Unlock()
}

func TestCheckpointDisabledPreservesMemoryOnlyFactoryBehavior(t *testing.T) {
	config := createDefaultConfig().(*Config)
	require.Nil(t, config.StorageID)

	rcvr, err := createLogsReceiver(
		t.Context(),
		receivertest.NewNopSettings(metadata.Type),
		config,
		consumertest.NewNop(),
	)
	require.NoError(t, err)
	assert.IsType(t, &nopLogsReceiver{}, rcvr)

	dedup := newLogDeduplicator()
	dedup.BeginBatch()
	require.True(t, dedup.MarkPending("memory-only", time.Now()))
	_, err = consumeDeduplicatedLogs(t.Context(), consumertest.NewNop(), dedup, oneLogRecord())
	require.NoError(t, err)
	assert.Nil(t, dedup.checkpoint)
}

func TestLogDedupCheckpointSuppressesReplayAfterRestartAndIsolatesTargets(t *testing.T) {
	backend := newCheckpointTestBackend()
	now := time.Unix(1_900_000_000, 0).UTC()
	const eventKey = "accepted-event"

	firstRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	first := newLogDeduplicator()
	first.now = func() time.Time { return now }
	firstRegistry.enableLogDedup("ise", "target-a", first, logCheckpointRetention{})
	require.NoError(t, firstRegistry.Start(t.Context(), checkpointHost(backend)))
	first.BeginBatch()
	require.True(t, first.MarkPending(eventKey, now))
	_, err := consumeDeduplicatedLogs(t.Context(), consumertest.NewNop(), first, oneLogRecord())
	require.NoError(t, err)
	firstRegistry.Close(t.Context())

	restartedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	restarted := newLogDeduplicator()
	restarted.now = func() time.Time { return now.Add(time.Second) }
	restartedRegistry.enableLogDedup("ise", "target-a", restarted, logCheckpointRetention{})
	require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
	restarted.BeginBatch()
	assert.False(t, restarted.MarkPending(eventKey, now), "accepted event must be suppressed after restart")
	restarted.RollbackBatch()

	isolatedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	isolated := newLogDeduplicator()
	isolated.now = func() time.Time { return now.Add(time.Second) }
	isolatedRegistry.enableLogDedup("ise", "target-b", isolated, logCheckpointRetention{})
	require.NoError(t, isolatedRegistry.Start(t.Context(), checkpointHost(backend)))
	isolated.BeginBatch()
	assert.True(t, isolated.MarkPending(eventKey, now), "different targets must not share dedup state")
	isolated.RollbackBatch()
}

func TestCounterCheckpointContinuesValueAndEpochAfterRestart(t *testing.T) {
	backend := newCheckpointTestBackend()
	startedAt := time.Unix(1_900_000_000, 0).UTC()
	firstNow := startedAt.Add(time.Minute)
	first := newCounterStoreWithConfig(startedAt, counterStoreConfig{now: func() time.Time { return firstNow }})
	firstRegistry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
	consumer := firstRegistry.enableCounter("fmc", "target-a", first, consumertest.NewNop())
	require.NoError(t, firstRegistry.Start(t.Context(), checkpointHost(backend)))

	value, epoch := first.AddInt("device-a", "packets", map[string]string{"interface": "Gi0/1"}, 7)
	assert.Equal(t, int64(7), value)
	assert.Equal(t, firstNow, epoch)
	require.NoError(t, consumer.ConsumeMetrics(t.Context(), pmetric.NewMetrics()))
	firstRegistry.Close(t.Context())

	secondNow := firstNow.Add(time.Minute)
	second := newCounterStoreWithConfig(secondNow, counterStoreConfig{now: func() time.Time { return secondNow }})
	secondRegistry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
	secondRegistry.enableCounter("fmc", "target-a", second, consumertest.NewNop())
	require.NoError(t, secondRegistry.Start(t.Context(), checkpointHost(backend)))

	value, epoch = second.AddInt("device-a", "packets", map[string]string{"interface": "Gi0/1"}, 5)
	assert.Equal(t, int64(12), value)
	assert.Equal(t, firstNow, epoch, "the cumulative series epoch must survive restart")
	assert.Equal(t, startedAt, second.StartTime(), "the receiver counter epoch must survive restart")
}

func TestCounterCheckpointDoesNotPersistRejectedDelivery(t *testing.T) {
	backend := newCheckpointTestBackend()
	now := time.Unix(1_900_000_000, 0).UTC()
	state := newCounterStoreWithConfig(now, counterStoreConfig{now: func() time.Time { return now }})
	registry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
	deliveryErr := errors.New("downstream rejected metrics")
	consumer := registry.enableCounter("ise", "target-a", state, consumertest.NewErr(deliveryErr))
	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	state.AddInt("resource", "requests", nil, 1)

	require.ErrorIs(t, consumer.ConsumeMetrics(t.Context(), pmetric.NewMetrics()), deliveryErr)
	batches, _, _, _ := backend.writeStats()
	assert.Zero(t, batches, "checkpoint must not advance before downstream acceptance")
}

func TestCounterRestoreDeletesTTLExpiredCheckpointEntries(t *testing.T) {
	backend := newCheckpointTestBackend()
	lastSeen := time.Unix(1_900_000_000, 0).UTC()
	idleTTL := time.Hour
	first := newCounterStoreWithConfig(lastSeen.Add(-time.Minute), counterStoreConfig{
		idleTTL: idleTTL,
		now:     func() time.Time { return lastSeen },
	})
	firstRegistry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
	consumer := firstRegistry.enableCounter("ise", "ttl-target", first, consumertest.NewNop())
	require.NoError(t, firstRegistry.Start(t.Context(), checkpointHost(backend)))
	first.AddInt("resource", "expired", nil, 1)
	require.NoError(t, consumer.ConsumeMetrics(t.Context(), pmetric.NewMetrics()))
	manifestKey := first.checkpoint.manifestKey()
	shardKey := first.checkpoint.shardKey(0)
	require.NotEmpty(t, backend.value(shardKey))
	firstRegistry.Close(t.Context())

	restartNow := lastSeen.Add(2 * idleTTL)
	restarted := newCounterStoreWithConfig(restartNow, counterStoreConfig{
		idleTTL: idleTTL,
		now:     func() time.Time { return restartNow },
	})
	restartedRegistry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
	restartedRegistry.enableCounter("ise", "ttl-target", restarted, consumertest.NewNop())
	require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.Empty(t, restarted.intValues)
	assert.Empty(t, backend.value(shardKey), "a page containing only expired series must be deleted during restore")
	var manifest checkpointManifest
	require.NoError(t, json.Unmarshal(backend.value(manifestKey), &manifest))
	assert.Empty(t, manifest.Active)
	restartedRegistry.Close(t.Context())

	third := newCounterStoreWithConfig(restartNow, counterStoreConfig{
		idleTTL: idleTTL,
		now:     func() time.Time { return restartNow },
	})
	thirdRegistry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
	thirdRegistry.enableCounter("ise", "ttl-target", third, consumertest.NewNop())
	require.NoError(t, thirdRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.Empty(t, third.intValues, "expired series must not be reloaded on subsequent restarts")
}

func TestLogDedupRestoreDeletesTTLExpiredCheckpointEntries(t *testing.T) {
	backend := newCheckpointTestBackend()
	seenAt := time.Unix(1_900_000_000, 0).UTC()
	retention := logCheckpointRetention{ttl: time.Hour, maxEntries: defaultLogDedupMaxEntries}
	first := newLogDeduplicator()
	first.now = func() time.Time { return seenAt }
	firstRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	firstRegistry.enableLogDedup("ise", "ttl-target", first, retention)
	require.NoError(t, firstRegistry.Start(t.Context(), checkpointHost(backend)))
	first.BeginBatch()
	require.True(t, first.MarkPending("expired-event", seenAt))
	_, err := consumeDeduplicatedLogs(t.Context(), consumertest.NewNop(), first, oneLogRecord())
	require.NoError(t, err)
	manifestKey := first.checkpoint.manifestKey()
	shardKey := first.checkpoint.shardKey(0)
	require.NotEmpty(t, backend.value(shardKey))
	firstRegistry.Close(t.Context())

	restartNow := seenAt.Add(2 * retention.ttl)
	restarted := newLogDeduplicator()
	restarted.now = func() time.Time { return restartNow }
	restartedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	restartedRegistry.enableLogDedup("ise", "ttl-target", restarted, retention)
	require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.Empty(t, restarted.seen)
	assert.Empty(t, backend.value(shardKey), "a page containing only expired dedup entries must be deleted during restore")
	var manifest checkpointManifest
	require.NoError(t, json.Unmarshal(backend.value(manifestKey), &manifest))
	assert.Empty(t, manifest.Active)
	restartedRegistry.Close(t.Context())

	third := newLogDeduplicator()
	third.now = func() time.Time { return restartNow }
	thirdRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	thirdRegistry.enableLogDedup("ise", "ttl-target", third, retention)
	require.NoError(t, thirdRegistry.Start(t.Context(), checkpointHost(backend)))
	third.BeginBatch()
	assert.True(t, third.MarkPending("expired-event", restartNow), "expired state must not reappear on a later restart")
	third.RollbackBatch()
}

func TestCounterRestoreRejectsDuplicateLogicalKeyAcrossValueTypes(t *testing.T) {
	backend := newCheckpointTestBackend()
	now := time.Unix(1_900_000_000, 0).UTC()
	state := newCounterStoreWithConfig(now, counterStoreConfig{now: func() time.Time { return now }})
	core, observed := observer.New(zap.WarnLevel)
	registry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.New(core))
	registry.enableCounter("ise", "duplicate-target", state, consumertest.NewNop())
	binding := state.checkpoint
	logicalKey := base64.RawURLEncoding.EncodeToString([]byte(counterKey("resource", "metric", nil)))
	page, err := json.Marshal(counterCheckpointShard{
		Version: checkpointFormatVersion,
		Shard:   0,
		Integers: []intCounterCheckpoint{{
			Key: logicalKey, Value: 1, StartedAt: now, LastSeen: now,
		}},
		Doubles: []doubleCounterCheckpoint{{
			Key: logicalKey, Value: 1.5, StartedAt: now, LastSeen: now,
		}},
	})
	require.NoError(t, err)
	metadataBytes, err := json.Marshal(counterCheckpointMetadata{StartedAt: now})
	require.NoError(t, err)
	manifest, err := json.Marshal(checkpointManifest{
		Version: checkpointFormatVersion, Active: []uint16{0}, Metadata: metadataBytes,
	})
	require.NoError(t, err)
	backend.put(binding.shardKey(0), page)
	backend.put(binding.manifestKey(), manifest)

	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	assert.Empty(t, state.intValues)
	assert.Empty(t, state.doubleValues)
	warnings := observed.FilterMessageSnippet("Corrupt Cisco OS checkpoint was ignored").All()
	require.NotEmpty(t, warnings)
	assert.Contains(t, fmt.Sprint(warnings[0].ContextMap()["error"]), "duplicate logical series")
}

func TestCheckpointCorruptAndTransientStorageFailuresFailOpenWithWarnings(t *testing.T) {
	t.Run("manifest read failure", func(t *testing.T) {
		backend := newCheckpointTestBackend()
		backend.getErr = errors.New("temporary read failure")
		core, observed := observer.New(zap.WarnLevel)
		registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.New(core))
		registry.enableLogDedup("ise", "target", newLogDeduplicator(), logCheckpointRetention{})

		require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
		require.NotEmpty(t, observed.FilterMessageSnippet("Failed to restore Cisco OS checkpoint").All())
	})

	t.Run("shard read failure", func(t *testing.T) {
		backend := newCheckpointTestBackend()
		core, observed := observer.New(zap.WarnLevel)
		registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.New(core))
		state := newLogDeduplicator()
		registry.enableLogDedup("ise", "target", state, logCheckpointRetention{})
		binding := state.checkpoint
		backend.put(binding.manifestKey(), []byte(`{"version":1,"active":[0]}`))
		backend.put(binding.shardKey(0), []byte(`{"version":1,"shard":0}`))
		backend.batchReadErr = errors.New("temporary batch read failure")

		require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
		require.NotEmpty(t, observed.FilterMessageSnippet("Failed to restore Cisco OS checkpoint shards").All())
	})

	t.Run("corrupt version", func(t *testing.T) {
		backend := newCheckpointTestBackend()
		core, observed := observer.New(zap.WarnLevel)
		registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.New(core))
		state := newLogDeduplicator()
		registry.enableLogDedup("ise", "target", state, logCheckpointRetention{})
		backend.put(state.checkpoint.manifestKey(), []byte(`{"version":99}`))

		require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
		assert.Empty(t, state.seen)
		require.NotEmpty(t, observed.FilterMessageSnippet("Corrupt Cisco OS checkpoint was ignored").All())
	})

	t.Run("write failure", func(t *testing.T) {
		backend := newCheckpointTestBackend()
		backend.batchWriteErr = errors.New("temporary write failure")
		core, observed := observer.New(zap.WarnLevel)
		registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.New(core))
		state := newLogDeduplicator()
		registry.enableLogDedup("ise", "target", state, logCheckpointRetention{})
		require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
		state.BeginBatch()
		require.True(t, state.MarkPending("event", time.Now()))

		_, err := consumeDeduplicatedLogs(t.Context(), consumertest.NewNop(), state, oneLogRecord())
		require.NoError(t, err, "storage write errors must not fail collection")
		state.BeginBatch()
		assert.False(t, state.MarkPending("event", time.Now()), "in-memory dedup must remain active after storage failure")
		state.RollbackBatch()
		require.NotEmpty(t, observed.FilterMessageSnippet("Failed to persist Cisco OS checkpoint").All())
	})

	t.Run("delete failure", func(t *testing.T) {
		backend := newCheckpointTestBackend()
		core, observed := observer.New(zap.WarnLevel)
		registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.New(core))
		state := newLogDeduplicator()
		registry.enableLogDedup("ise", "target", state, logCheckpointRetention{})
		require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
		now := time.Now()
		state.BeginBatch()
		require.True(t, state.MarkPending("event", now))
		_, err := consumeDeduplicatedLogs(t.Context(), consumertest.NewNop(), state, oneLogRecord())
		require.NoError(t, err)
		backend.deleteErr = errors.New("temporary delete failure")
		state.Expire(now.Add(time.Second), defaultLogDedupMaxEntries)

		state.persistCheckpoint(t.Context(), true)
		require.NotEmpty(t, observed.FilterMessageSnippet("Failed to persist Cisco OS checkpoint").All())
	})
}

func TestPollingLogDedupCanonicalControllerNamespaceSurvivesRestart(t *testing.T) {
	now := time.Date(2090, time.January, 2, 3, 4, 5, 0, time.UTC)
	const (
		firstEndpoint  = "HTTPS://HOST:443/"
		secondEndpoint = "https://host"
	)

	t.Run("ACI", func(t *testing.T) {
		backend := newCheckpointTestBackend()
		firstConfig := createDefaultConfig().(*Config)
		firstConfig.ACI.Controllers = []ACIControllerConfig{{Endpoint: firstEndpoint}}
		secondConfig := createDefaultConfig().(*Config)
		secondConfig.ACI.Controllers = []ACIControllerConfig{{Endpoint: secondEndpoint}}
		firstTarget := checkpointProviderTarget(firstConfig, "aci")
		secondTarget := checkpointProviderTarget(secondConfig, "aci")
		require.Equal(t, firstTarget, secondTarget, "equivalent URL spellings must bind the same ACI checkpoint")
		endpoint := aciEndpoint{group: "faults", operation: "faults.active", className: "faultInst"}
		object := aciinternal.Object{
			"dn": "topology/pod-1/node-101/sys/fault-F1234", "id": "1234", "severity": "major", "descr": "test fault",
		}

		first := &aciLogsReceiver{seen: newLogDeduplicator()}
		first.seen.now = func() time.Time { return now }
		firstRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
		firstRegistry.enableLogDedup("aci", firstTarget, first.seen, logCheckpointRetention{})
		require.NoError(t, firstRegistry.Start(t.Context(), checkpointHost(backend)))
		first.seen.BeginBatch()
		assert.False(t, first.seenBefore("HOST:443", firstEndpoint, endpoint, object, now))
		_, err := consumeDeduplicatedLogs(t.Context(), consumertest.NewNop(), first.seen, oneLogRecord())
		require.NoError(t, err)
		firstRegistry.Close(t.Context())

		restarted := &aciLogsReceiver{seen: newLogDeduplicator()}
		restarted.seen.now = func() time.Time { return now.Add(time.Second) }
		restartedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
		restartedRegistry.enableLogDedup("aci", secondTarget, restarted.seen, logCheckpointRetention{})
		require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
		restarted.seen.BeginBatch()
		assert.True(t, restarted.seenBefore("host", secondEndpoint, endpoint, object, now.Add(time.Second)), "the restored ACI replay key must match the canonical runtime namespace")
		restarted.seen.RollbackBatch()
		restartedRegistry.Close(t.Context())
	})

	t.Run("FMC", func(t *testing.T) {
		backend := newCheckpointTestBackend()
		firstConfig := createDefaultConfig().(*Config)
		firstConfig.FMC.Controllers = []FMCControllerConfig{{Endpoint: firstEndpoint, DomainUUID: "domain-1"}}
		secondConfig := createDefaultConfig().(*Config)
		secondConfig.FMC.Controllers = []FMCControllerConfig{{Endpoint: secondEndpoint, DomainUUID: "domain-1"}}
		firstTarget := checkpointProviderTarget(firstConfig, "fmc")
		secondTarget := checkpointProviderTarget(secondConfig, "fmc")
		require.Equal(t, firstTarget, secondTarget, "equivalent URL spellings must bind the same FMC checkpoint")
		endpoint := fmcEndpoint{group: "audit", operation: "audit.records", objectType: "fmc.audit"}
		object := fmcinternal.Object{"id": "event-1", "status": "success", "message": "test event"}

		first := &fmcLogsReceiver{seen: newLogDeduplicator()}
		first.seen.now = func() time.Time { return now }
		firstRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
		firstRegistry.enableLogDedup("fmc", firstTarget, first.seen, logCheckpointRetention{})
		require.NoError(t, firstRegistry.Start(t.Context(), checkpointHost(backend)))
		first.seen.BeginBatch()
		assert.False(t, first.seenBefore("HOST:443", firstEndpoint, endpoint, object, now))
		_, err := consumeDeduplicatedLogs(t.Context(), consumertest.NewNop(), first.seen, oneLogRecord())
		require.NoError(t, err)
		firstRegistry.Close(t.Context())

		restarted := &fmcLogsReceiver{seen: newLogDeduplicator()}
		restarted.seen.now = func() time.Time { return now.Add(time.Second) }
		restartedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
		restartedRegistry.enableLogDedup("fmc", secondTarget, restarted.seen, logCheckpointRetention{})
		require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
		restarted.seen.BeginBatch()
		assert.True(t, restarted.seenBefore("host", secondEndpoint, endpoint, object, now.Add(time.Second)), "the restored FMC replay key must match the canonical runtime namespace")
		restarted.seen.RollbackBatch()
		restartedRegistry.Close(t.Context())
	})
}

func TestCheckpointIdentityIsCollisionSafeAndCredentialStable(t *testing.T) {
	base := checkpointIdentity{
		Receiver: "cisco_os/primary",
		Provider: "ise",
		Target:   "endpoint-a",
		Signal:   checkpointSignalLogs,
		State:    checkpointStateLogDedup,
	}
	keys := map[string]struct{}{base.key(): {}}
	for _, identity := range []checkpointIdentity{
		{Receiver: "cisco_os/secondary", Provider: base.Provider, Target: base.Target, Signal: base.Signal, State: base.State},
		{Receiver: base.Receiver, Provider: "fmc", Target: base.Target, Signal: base.Signal, State: base.State},
		{Receiver: base.Receiver, Provider: base.Provider, Target: "endpoint-b", Signal: base.Signal, State: base.State},
		{Receiver: base.Receiver, Provider: base.Provider, Target: base.Target, Signal: checkpointSignalMetrics, State: base.State},
		{Receiver: base.Receiver, Provider: base.Provider, Target: base.Target, Signal: base.Signal, State: checkpointStateFMCResume},
	} {
		keys[identity.key()] = struct{}{}
	}
	assert.Len(t, keys, 6, "receiver, provider, target, signal, and state identities must be isolated")

	config := createDefaultConfig().(*Config)
	config.Intersight.Enabled = true
	config.Intersight.Endpoint = "HTTPS://INTERSIGHT.EXAMPLE.TEST:443/"
	config.Intersight.Auth = IntersightAuthConfig{
		KeyID: "old-key", KeyFile: "/old/key.pem", KeyPEM: configopaque.String("old pem"),
	}
	config.Intersight.Targets = IntersightTargetFilters{Serials: []string{"B", "A"}, MoIDs: []string{"2", "1"}}
	config.DeviceSelection = DeviceSelectionConfig{Include: DeviceSelectionMatchConfig{
		HostNames: []string{" EDGE-A ", "edge-a"},
		HostIPs:   []string{"2001:0db8:0:0::1"},
	}}
	original := checkpointProviderTarget(config, "intersight")

	rotated := *config
	rotated.Intersight.Auth = IntersightAuthConfig{
		KeyID: "new-key", KeyFile: "/new/key.pem", KeyPEM: configopaque.String("new pem"),
	}
	rotated.Intersight.MaxRetries = 99
	rotated.Intersight.EventLookback = 7 * 24 * time.Hour
	rotated.Intersight.Inventory.MaxResults = 42
	rotated.Intersight.Endpoint = "https://intersight.example.test"
	rotated.Intersight.Targets = IntersightTargetFilters{Serials: []string{" a ", "b"}, MoIDs: []string{"1", "2"}}
	rotated.DeviceSelection = DeviceSelectionConfig{Include: DeviceSelectionMatchConfig{
		HostNames: []string{"edge-a"},
		HostIPs:   []string{"2001:db8::1"},
	}}
	assert.Equal(t, original, checkpointProviderTarget(&rotated, "intersight"), "credential rotation, irrelevant tuning, endpoint spelling, and unordered filters must be stable")

	rotated.Intersight.Endpoint = "https://other.example.test"
	assert.NotEqual(t, original, checkpointProviderTarget(&rotated, "intersight"), "a distinct endpoint must use isolated state")

	iseConfig := createDefaultConfig().(*Config)
	iseConfig.ISE.Enabled = true
	iseConfig.ISE.Endpoint = "https://ise.example.test"
	iseConfig.ISE.Auth = ISEAuthConfig{Username: "old-user", Password: configopaque.String("old-password")}
	iseConfig.ISE.Targets = ISETargetFilters{
		NetworkDeviceIPs: []string{"2001:0db8:0:0:0:0:0:10"},
		EndpointMACs:     []string{"AA-BB-CC-DD-EE-FF"},
	}
	iseConfig.ISE.PxGrid = ISEPxGridConfig{
		Enabled: true, NodeName: "old-node", Password: configopaque.String("old-pxgrid-password"),
		CertFile: "/old/client.crt", KeyFile: "/old/client.key", KeyPassword: configopaque.String("old-key-password"), CAFile: "/old/ca.pem",
	}
	iseOriginal := checkpointProviderTarget(iseConfig, "ise")
	iseRotated := *iseConfig
	iseRotated.ISE.Auth = ISEAuthConfig{Username: "new-user", Password: configopaque.String("new-password")}
	iseRotated.ISE.PxGrid = iseConfig.ISE.PxGrid
	iseRotated.ISE.PxGrid.NodeName = "new-node"
	iseRotated.ISE.PxGrid.Password = configopaque.String("new-pxgrid-password")
	iseRotated.ISE.PxGrid.CertFile = "/new/client.crt"
	iseRotated.ISE.PxGrid.KeyFile = "/new/client.key"
	iseRotated.ISE.PxGrid.KeyPassword = configopaque.String("new-key-password")
	iseRotated.ISE.PxGrid.CAFile = "/new/ca.pem"
	iseRotated.ISE.Targets = ISETargetFilters{
		NetworkDeviceIPs: []string{"2001:db8::10"},
		EndpointMACs:     []string{"aa:bb:cc:dd:ee:ff"},
	}
	assert.Equal(t, iseOriginal, checkpointProviderTarget(&iseRotated, "ise"), "password, API client identity, certificate rotation, IPv6 spelling, and MAC spelling must not orphan state")

	fmcConfig := createDefaultConfig().(*Config)
	fmcConfig.FMC.Enabled = true
	fmcConfig.FMC.Auth = ControllerAuthConfig{Username: "old-user", Password: configopaque.String("old-password"), APIKey: configopaque.String("old-api-key")}
	fmcConfig.FMC.Controllers = []FMCControllerConfig{
		{Name: "primary", Endpoint: "HTTPS://FMC-A.EXAMPLE.TEST:443/", DomainUUID: " ABCD "},
		{Name: "secondary", Endpoint: "https://fmc-b.example.test", DomainUUID: "EF01"},
	}
	fmcConfig.FMC.Targets.ManagementIPs = []string{"2001:0db8:0:0:0:0:0:20"}
	fmcOriginal := checkpointProviderTarget(fmcConfig, "fmc")
	fmcRotated := *fmcConfig
	fmcRotated.FMC.Auth = ControllerAuthConfig{Username: "new-user", Password: configopaque.String("new-password"), APIKey: configopaque.String("new-api-key")}
	fmcRotated.FMC.Controllers = []FMCControllerConfig{
		{Name: "secondary", Endpoint: "https://FMC-B.EXAMPLE.TEST:443/", DomainUUID: "ef01"},
		{Name: "primary", Endpoint: "https://fmc-a.example.test", DomainUUID: "abcd"},
	}
	fmcRotated.FMC.Targets.ManagementIPs = []string{"2001:db8::20"}
	assert.Equal(t, fmcOriginal, checkpointProviderTarget(&fmcRotated, "fmc"), "API-key/password rotation, controller order, and IPv6 spelling must not orphan FMC state")

	aciOmittedName := createDefaultConfig().(*Config)
	aciOmittedName.ACI.Controllers = []ACIControllerConfig{{Endpoint: "HTTPS://APIC.EXAMPLE.TEST:443/"}}
	aciEffectiveName := *aciOmittedName
	aciEffectiveName.ACI.Controllers = []ACIControllerConfig{{Endpoint: "https://apic.example.test", Name: "APIC.EXAMPLE.TEST:443"}}
	assert.Equal(t,
		checkpointProviderTarget(aciOmittedName, "aci"),
		checkpointProviderTarget(&aciEffectiveName, "aci"),
		"an omitted ACI controller name must equal the endpoint-host name synthesized by the client",
	)
	aciEffectiveName.ACI.Controllers[0].Name = "different-apic"
	assert.NotEqual(t, checkpointProviderTarget(aciOmittedName, "aci"), checkpointProviderTarget(&aciEffectiveName, "aci"))
	for _, distinctName := range []string{"apic.example.test/blue", "ops@apic.example.test", "apic.example.test?scope=blue", "apic.example.test#blue"} {
		aciEffectiveName.ACI.Controllers[0].Name = distinctName
		assert.NotEqual(t,
			checkpointProviderTarget(aciOmittedName, "aci"),
			checkpointProviderTarget(&aciEffectiveName, "aci"),
			"runtime-distinct ACI controller name %q must retain isolated checkpoint state", distinctName,
		)
	}

	fmcOmittedName := createDefaultConfig().(*Config)
	fmcOmittedName.FMC.Controllers = []FMCControllerConfig{{Endpoint: "HTTPS://FMC.EXAMPLE.TEST:443/", DomainUUID: "domain-a"}}
	fmcEffectiveName := *fmcOmittedName
	fmcEffectiveName.FMC.Controllers = []FMCControllerConfig{{Endpoint: "https://fmc.example.test", Name: "FMC.EXAMPLE.TEST:443", DomainUUID: "domain-a"}}
	assert.Equal(t,
		checkpointProviderTarget(fmcOmittedName, "fmc"),
		checkpointProviderTarget(&fmcEffectiveName, "fmc"),
		"an omitted FMC controller name must equal the endpoint-host name synthesized by the client",
	)
	fmcEffectiveName.FMC.Controllers[0].Name = "different-fmc"
	assert.NotEqual(t, checkpointProviderTarget(fmcOmittedName, "fmc"), checkpointProviderTarget(&fmcEffectiveName, "fmc"))
	for _, distinctName := range []string{"fmc.example.test/blue", "ops@fmc.example.test", "fmc.example.test?scope=blue", "fmc.example.test#blue"} {
		fmcEffectiveName.FMC.Controllers[0].Name = distinctName
		assert.NotEqual(t,
			checkpointProviderTarget(fmcOmittedName, "fmc"),
			checkpointProviderTarget(&fmcEffectiveName, "fmc"),
			"runtime-distinct FMC controller name %q must retain isolated checkpoint state", distinctName,
		)
	}

	assert.Equal(t,
		checkpointFMCResumeTarget("FMC.EXAMPLE.TEST.:8302", "FMC.EXAMPLE.TEST.:8302"),
		checkpointFMCResumeTarget("fmc.example.test:8302", "fmc.example.test"),
		"default eStreamer controller and endpoint spellings must normalize to one target identity",
	)
	assert.NotEqual(t,
		checkpointFMCResumeTarget("fmc.example.test:8302", "fmc.example.test"),
		checkpointFMCResumeTarget("other.example.test:8302", "other.example.test"),
	)
	assert.Equal(t,
		checkpointFMCResumeTargetWithScope("fmc.example.test:8302", "fmc.example.test", []string{" Intrusion ", "CONNECTION"}),
		checkpointFMCResumeTargetWithScope("fmc.example.test:8302", "fmc.example.test", []string{"connection", "intrusion"}),
		"unordered eStreamer event scope must be canonical",
	)
	assert.Equal(t,
		checkpointFMCResumeTargetWithScope("fmc.example.test:8302", "fmc.example.test", nil),
		checkpointFMCResumeTargetWithScope("fmc.example.test:8302", "fmc.example.test", []string{"file", "connection", "intrusion_packet", "intrusion"}),
		"an empty eStreamer scope must equal the four runtime defaults",
	)
	assert.Equal(t,
		checkpointFMCResumeTargetWithScope("fmc.example.test:8302", "fmc.example.test", []string{"traffic", "intrusion_event", "IntrusionPacketEvent", "malware_event"}),
		checkpointFMCResumeTargetWithScope("fmc.example.test:8302", "fmc.example.test", []string{"connection", "intrusion", "intrusion_packet", "file"}),
		"runtime event aliases must share checkpoint identity with their canonical scope",
	)
	assert.NotEqual(t,
		checkpointFMCResumeTargetWithScope("fmc.example.test:8302", "fmc.example.test", []string{"connection"}),
		checkpointFMCResumeTargetWithScope("fmc.example.test:8302", "fmc.example.test", []string{"intrusion"}),
		"a changed eStreamer event scope must use isolated cursor state",
	)
}

func TestCheckpointShardsRetainFullDedupCeilingWithoutBucketOverflow(t *testing.T) {
	state := newLogDeduplicator()
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	registry.enableLogDedup("ise", "target", state, logCheckpointRetention{})
	now := time.Unix(1_900_000_000, 0).UTC()
	for i := range defaultLogDedupMaxEntries {
		require.True(t, state.MarkCommitted(fmt.Sprintf("event-%d", i), now))
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	assert.Len(t, state.seen, defaultLogDedupMaxEntries)
	assigned := 0
	for _, shard := range state.shards {
		assert.LessOrEqual(t, shard.Len(), checkpointShardEntries)
		assigned += shard.Len()
	}
	assert.Equal(t, defaultLogDedupMaxEntries, assigned, "page allocation must not evict entries because of hash-bucket collisions")
	for _, entry := range state.seen {
		assert.NotEqual(t, unassignedCheckpointShard, entry.shard)
	}
}

func TestLogDedupCheckpointFutureSkewValidation(t *testing.T) {
	now := time.Date(2090, time.January, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		name        string
		seenAt      time.Time
		wantCorrupt bool
	}{
		{name: "at skew boundary", seenAt: now.Add(checkpointFutureSkew)},
		{name: "beyond skew boundary", seenAt: now.Add(checkpointFutureSkew + time.Second), wantCorrupt: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := newCheckpointTestBackend()
			current := now
			state := newLogDeduplicator()
			state.now = func() time.Time { return current }
			registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
			registry.enableLogDedup("fmc", "future-log-target", state, logCheckpointRetention{})
			binding := state.checkpoint
			const eventKey = "future-log-event"
			page, err := json.Marshal(logDedupCheckpointShard{
				Version: checkpointFormatVersion,
				Shard:   0,
				Entries: []logDedupCheckpointEntry{{Key: logDedupStateKey(eventKey), SeenAt: tt.seenAt}},
			})
			require.NoError(t, err)
			manifest, err := json.Marshal(checkpointManifest{Version: checkpointFormatVersion, Active: []uint16{0}})
			require.NoError(t, err)
			backend.put(binding.shardKey(0), page)
			backend.put(binding.manifestKey(), manifest)

			require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)), "future checkpoint state must fail open without failing receiver startup")
			assert.Equal(t, tt.wantCorrupt, binding.corrupt.Load())
			state.BeginBatch()
			if tt.wantCorrupt {
				assert.True(t, state.MarkPending(eventKey, now), "an ignored future checkpoint must leave the event eligible")
				state.RollbackBatch()
				assert.Equal(t, page, backend.value(binding.shardKey(0)), "invalid state must not be rewritten")
				assert.Equal(t, manifest, backend.value(binding.manifestKey()))
				batches, _, _, _ := backend.writeStats()
				assert.Zero(t, batches)
				registry.Close(t.Context())
			} else {
				assert.False(t, state.MarkPending(eventKey, now), "the exact skew boundary must remain valid")
				assert.Equal(t, now, state.seen[logDedupStateKey(eventKey)].seenAt, "accepted future observations must be normalized before entering TTL/LRU state")
				batches, _, _, _ := backend.writeStats()
				assert.Equal(t, 1, batches, "restore must durably rewrite the normalized observation")

				const normalEventKey = "normal-log-event"
				current = now.Add(time.Second)
				require.True(t, state.MarkPending(normalEventKey, current))
				_, err = consumeDeduplicatedLogs(t.Context(), consumertest.NewNop(), state, oneLogRecord())
				require.NoError(t, err)
				registry.Close(t.Context())

				restarted := newLogDeduplicator()
				restarted.now = func() time.Time { return current.Add(time.Second) }
				restartedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
				restartedRegistry.enableLogDedup("fmc", "future-log-target", restarted, logCheckpointRetention{})
				require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
				assert.False(t, restarted.checkpoint.corrupt.Load(), "normalized state plus a normal update must remain restart-valid")
				restarted.BeginBatch()
				assert.False(t, restarted.MarkPending(eventKey, current.Add(time.Second)))
				assert.False(t, restarted.MarkPending(normalEventKey, current.Add(time.Second)))
				restarted.RollbackBatch()
				batches, _, _, _ = backend.writeStats()
				assert.Equal(t, 2, batches, "the second restart must not need another normalization write")
				restartedRegistry.Close(t.Context())
			}
		})
	}
}

func TestCounterCheckpointFutureSkewValidation(t *testing.T) {
	now := time.Date(2090, time.January, 2, 3, 4, 5, 0, time.UTC)
	latestValidTime := now.Add(checkpointFutureSkew)
	future := latestValidTime.Add(time.Second)
	tests := []struct {
		name        string
		configure   func(*counterCheckpointMetadata, *counterCheckpointShard)
		wantCorrupt bool
	}{
		{
			name: "at skew boundary",
			configure: func(metadata *counterCheckpointMetadata, shard *counterCheckpointShard) {
				metadata.StartedAt = latestValidTime
				shard.Integers[0].StartedAt, shard.Integers[0].LastSeen = latestValidTime, latestValidTime
				shard.Doubles[0].StartedAt, shard.Doubles[0].LastSeen = latestValidTime, latestValidTime
			},
		},
		{
			name: "future receiver metadata",
			configure: func(metadata *counterCheckpointMetadata, _ *counterCheckpointShard) {
				metadata.StartedAt = future
			},
			wantCorrupt: true,
		},
		{
			name: "future integer start",
			configure: func(_ *counterCheckpointMetadata, shard *counterCheckpointShard) {
				shard.Integers[0].StartedAt, shard.Integers[0].LastSeen = future, future
			},
			wantCorrupt: true,
		},
		{
			name: "future integer last seen",
			configure: func(_ *counterCheckpointMetadata, shard *counterCheckpointShard) {
				shard.Integers[0].LastSeen = future
			},
			wantCorrupt: true,
		},
		{
			name: "future double start",
			configure: func(_ *counterCheckpointMetadata, shard *counterCheckpointShard) {
				shard.Doubles[0].StartedAt, shard.Doubles[0].LastSeen = future, future
			},
			wantCorrupt: true,
		},
		{
			name: "future double last seen",
			configure: func(_ *counterCheckpointMetadata, shard *counterCheckpointShard) {
				shard.Doubles[0].LastSeen = future
			},
			wantCorrupt: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := newCheckpointTestBackend()
			current := now
			processStartedAt := now.Add(-2 * time.Hour)
			state := newCounterStoreWithConfig(processStartedAt, counterStoreConfig{now: func() time.Time { return current }})
			registry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
			consumer := registry.enableCounter("fmc", "future-counter-target", state, consumertest.NewNop())
			binding := state.checkpoint
			metadata := counterCheckpointMetadata{StartedAt: now.Add(-time.Hour)}
			shard := counterCheckpointShard{
				Version: checkpointFormatVersion,
				Shard:   0,
				Integers: []intCounterCheckpoint{{
					Key:       base64.RawURLEncoding.EncodeToString([]byte(counterKey("resource", "integer", nil))),
					Value:     7,
					StartedAt: now.Add(-time.Minute),
					LastSeen:  now,
				}},
				Doubles: []doubleCounterCheckpoint{{
					Key:       base64.RawURLEncoding.EncodeToString([]byte(counterKey("resource", "double", nil))),
					Value:     1.5,
					StartedAt: now.Add(-time.Minute),
					LastSeen:  now,
				}},
			}
			tt.configure(&metadata, &shard)
			page, err := json.Marshal(shard)
			require.NoError(t, err)
			metadataBytes, err := json.Marshal(metadata)
			require.NoError(t, err)
			manifest, err := json.Marshal(checkpointManifest{Version: checkpointFormatVersion, Active: []uint16{0}, Metadata: metadataBytes})
			require.NoError(t, err)
			backend.put(binding.shardKey(0), page)
			backend.put(binding.manifestKey(), manifest)

			require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)), "future checkpoint state must fail open without failing receiver startup")
			assert.Equal(t, tt.wantCorrupt, binding.corrupt.Load())
			if tt.wantCorrupt {
				assert.Equal(t, processStartedAt, state.StartTime(), "ignored metadata must not replace the current process epoch")
				assert.Empty(t, state.intValues)
				assert.Empty(t, state.doubleValues)
				value, epoch := state.AddInt("fail-open", "requests", nil, 1)
				assert.Equal(t, int64(1), value)
				assert.Equal(t, now, epoch, "collection must continue with fresh in-memory state")
				assert.Equal(t, page, backend.value(binding.shardKey(0)), "invalid state must not be rewritten")
				assert.Equal(t, manifest, backend.value(binding.manifestKey()))
				batches, _, _, _ := backend.writeStats()
				assert.Zero(t, batches)
				registry.Close(t.Context())
			} else {
				assert.Equal(t, now, state.StartTime(), "accepted future receiver metadata must be normalized")
				assert.Len(t, state.intValues, 1)
				assert.Len(t, state.doubleValues, 1)
				integerKey := counterKey("resource", "integer", nil)
				doubleKey := counterKey("resource", "double", nil)
				assert.Equal(t, now, state.intValues[integerKey].startedAt)
				assert.Equal(t, now, state.intValues[integerKey].lastSeen)
				assert.Equal(t, now, state.doubleValues[doubleKey].startedAt)
				assert.Equal(t, now, state.doubleValues[doubleKey].lastSeen)
				batches, _, _, _ := backend.writeStats()
				assert.Equal(t, 1, batches, "restore must durably rewrite normalized metadata and series")

				current = now.Add(time.Second)
				intValue, intEpoch := state.AddInt("resource", "integer", nil, 1)
				doubleValue, doubleEpoch := state.AddDouble("resource", "double", nil, 0.5)
				assert.Equal(t, int64(8), intValue)
				assert.Equal(t, 2.0, doubleValue)
				assert.Equal(t, now, intEpoch)
				assert.Equal(t, now, doubleEpoch)
				require.NoError(t, consumer.ConsumeMetrics(t.Context(), pmetric.NewMetrics()))
				registry.Close(t.Context())

				restartAt := current.Add(time.Second)
				restarted := newCounterStoreWithConfig(restartAt, counterStoreConfig{now: func() time.Time { return restartAt }})
				restartedRegistry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
				restartedRegistry.enableCounter("fmc", "future-counter-target", restarted, consumertest.NewNop())
				require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
				assert.False(t, restarted.checkpoint.corrupt.Load(), "normalized state plus a normal update must remain restart-valid")
				assert.Equal(t, now, restarted.StartTime())
				restartedIntValue, restartedIntEpoch := restarted.AddInt("resource", "integer", nil, 1)
				restartedDoubleValue, restartedDoubleEpoch := restarted.AddDouble("resource", "double", nil, 0.5)
				assert.Equal(t, int64(9), restartedIntValue)
				assert.Equal(t, 2.5, restartedDoubleValue)
				assert.Equal(t, now, restartedIntEpoch)
				assert.Equal(t, now, restartedDoubleEpoch)
				batches, _, _, _ = backend.writeStats()
				assert.Equal(t, 2, batches, "the second restart must not need another normalization write")
				restartedRegistry.Close(t.Context())
			}
		})
	}
}

func TestCounterCheckpointNormalizesFutureMetadataWithoutSeries(t *testing.T) {
	backend := newCheckpointTestBackend()
	now := time.Date(2090, time.January, 2, 3, 4, 5, 0, time.UTC)
	state := newCounterStoreWithConfig(now.Add(-time.Hour), counterStoreConfig{now: func() time.Time { return now }})
	registry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
	registry.enableCounter("fmc", "future-metadata-only-target", state, consumertest.NewNop())
	metadataBytes, err := json.Marshal(counterCheckpointMetadata{StartedAt: now.Add(checkpointFutureSkew)})
	require.NoError(t, err)
	manifest, err := json.Marshal(checkpointManifest{Version: checkpointFormatVersion, Metadata: metadataBytes})
	require.NoError(t, err)
	backend.put(state.checkpoint.manifestKey(), manifest)

	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	assert.False(t, state.checkpoint.corrupt.Load())
	assert.Equal(t, now, state.StartTime())
	batches, _, _, _ := backend.writeStats()
	assert.Equal(t, 1, batches, "metadata normalization must persist even without a dirty series shard")
	var normalizedManifest checkpointManifest
	require.NoError(t, json.Unmarshal(backend.value(state.checkpoint.manifestKey()), &normalizedManifest))
	var normalizedMetadata counterCheckpointMetadata
	require.NoError(t, json.Unmarshal(normalizedManifest.Metadata, &normalizedMetadata))
	assert.Equal(t, now, normalizedMetadata.StartedAt)
	registry.Close(t.Context())

	restarted := newCounterStoreWithConfig(now.Add(time.Second), counterStoreConfig{now: func() time.Time { return now.Add(time.Second) }})
	restartedRegistry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
	restartedRegistry.enableCounter("fmc", "future-metadata-only-target", restarted, consumertest.NewNop())
	require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.False(t, restarted.checkpoint.corrupt.Load())
	assert.Equal(t, now, restarted.StartTime())
	batches, _, _, _ = backend.writeStats()
	assert.Equal(t, 1, batches, "normalized metadata must not be rewritten again on restart")
	restartedRegistry.Close(t.Context())
}

func TestCheckpointDedupPruningPreservesInFlightStreamingDelivery(t *testing.T) {
	state := newLogDeduplicator()
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	registry.enableLogDedup("ise", "target", state, logCheckpointRetention{})
	now := time.Unix(1_900_000_000, 0).UTC()

	require.True(t, state.MarkCommitted("in-flight", now))
	state.Expire(now.Add(time.Hour), defaultLogDedupMaxEntries)
	assert.False(t, state.MarkCommitted("in-flight", now), "concurrent pruning must not release an event before downstream acceptance")

	state.ConfirmCommitted("in-flight")
	state.Expire(now.Add(time.Hour), defaultLogDedupMaxEntries)
	assert.True(t, state.MarkCommitted("in-flight", now), "an accepted entry may be pruned after its retention window")
}
