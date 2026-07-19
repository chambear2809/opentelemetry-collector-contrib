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
	"go.opentelemetry.io/collector/pdata/plog"
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
	staleGetOnceKey       string
	staleGetOnceValue     []byte
	batchReadErr          error
	batchMissingKey       string
	batchWriteErr         error
	batchWritePrefix      int
	setErr                error
	setApplyThenErr       bool
	setDeferApplyThenErr  bool
	deferredSetKey        string
	deferredSetValue      []byte
	deleteErr             error
	deleteEntered         chan struct{}
	deleteRelease         <-chan struct{}
	deleteUntilContext    bool
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
	setValues      [][]byte
	deferredSets   int
	deleteCalls    int
	closeCalls     int
	closeSucceeded bool
}

func newCheckpointTestBackend() *checkpointTestBackend {
	return &checkpointTestBackend{values: map[string][]byte{}, batchWritePrefix: -1}
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

func (b *checkpointTestBackend) deleteStats() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.deleteCalls
}

func (b *checkpointTestBackend) manifestSetValues() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	values := make([][]byte, len(b.setValues))
	for i, value := range b.setValues {
		values[i] = append([]byte(nil), value...)
	}
	return values
}

func (b *checkpointTestBackend) hasDeferredSet() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.deferredSetKey != ""
}

func (b *checkpointTestBackend) deferredSetStats() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.deferredSets
}

func (b *checkpointTestBackend) waitForDelete(ctx context.Context) error {
	b.mu.Lock()
	b.deleteCalls++
	entered := b.deleteEntered
	release := b.deleteRelease
	untilContext := b.deleteUntilContext
	b.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if untilContext {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func checkpointTestManifest(t *testing.T, backend *checkpointTestBackend, binding *checkpointBinding) checkpointManifest {
	t.Helper()
	var manifest checkpointManifest
	require.NoError(t, json.Unmarshal(backend.value(binding.manifestKey()), &manifest))
	return manifest
}

func removeCheckpointClockAnchor(t *testing.T, backend *checkpointTestBackend, binding *checkpointBinding) {
	t.Helper()
	manifest := checkpointTestManifest(t, backend, binding)
	require.False(t, manifest.ClockAnchor.IsZero())
	manifest.ClockAnchor = time.Time{}
	encoded, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "clock_anchor")
	backend.put(binding.manifestKey(), encoded)
}

func checkpointTestReferencedShardKey(t *testing.T, backend *checkpointTestBackend, binding *checkpointBinding, shard uint16) string {
	t.Helper()
	manifest := checkpointTestManifest(t, backend, binding)
	for i, active := range manifest.Active {
		if active != shard {
			continue
		}
		if manifest.Version == checkpointFormatVersion {
			return binding.shardKey(shard)
		}
		require.Equal(t, checkpointManifestFormatVersion, manifest.Version)
		require.Len(t, manifest.Slots, len(manifest.Active))
		return binding.slottedShardKey(shard, manifest.Slots[i])
	}
	t.Fatalf("checkpoint manifest does not reference shard %d", shard)
	return ""
}

func checkpointTestReferencedShard(t *testing.T, backend *checkpointTestBackend, binding *checkpointBinding, shard uint16) []byte {
	t.Helper()
	return backend.value(checkpointTestReferencedShardKey(t, backend, binding, shard))
}

func checkpointTestValues(backend *checkpointTestBackend) map[string][]byte {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	values := make(map[string][]byte, len(backend.values))
	for key, value := range backend.values {
		values[key] = append([]byte(nil), value...)
	}
	return values
}

func startCheckpointTestBinding(t *testing.T, backend *checkpointTestBackend, target string) (*checkpointRegistry, *checkpointBinding) {
	t.Helper()
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	binding := registry.bind("atomic-test", target, "generation", func(context.Context) {})
	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	return registry, binding
}

func checkpointTestGeneration(prefix string, count int) (map[uint16][]byte, map[uint16]bool) {
	shards := make(map[uint16][]byte, count)
	active := make(map[uint16]bool, count)
	for index := range count {
		shard := uint16(index)
		shards[shard] = []byte(fmt.Sprintf("%s-%d", prefix, index))
		active[shard] = true
	}
	return shards, active
}

func requireCheckpointTestGeneration(t *testing.T, binding *checkpointBinding, prefix string, count int) loadedCheckpoint {
	t.Helper()
	loaded, ok := binding.load(t.Context())
	require.True(t, ok)
	require.Len(t, loaded.shards, count)
	for index := range count {
		assert.Equal(t, fmt.Sprintf("%s-%d", prefix, index), string(loaded.shards[uint16(index)]))
	}
	return loaded
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
	if key == c.backend.staleGetOnceKey {
		value := append([]byte(nil), c.backend.staleGetOnceValue...)
		c.backend.staleGetOnceKey = ""
		c.backend.staleGetOnceValue = nil
		return value, nil
	}
	return append([]byte(nil), c.backend.values[key]...), nil
}

func (c *checkpointTestClient) Set(_ context.Context, key string, value []byte) error {
	c.backend.mu.Lock()
	defer c.backend.mu.Unlock()
	if key == c.backend.deferredSetKey {
		// Model the latest effect permitted by the checkpoint storage contract:
		// an errored Set may become visible only in invocation order, before a
		// later Set to the same key is applied.
		c.backend.values[key] = append([]byte(nil), c.backend.deferredSetValue...)
		c.backend.deferredSets++
		c.backend.deferredSetKey = ""
		c.backend.deferredSetValue = nil
	}
	c.backend.writeBatches++
	c.backend.writeOps++
	c.backend.maxWriteOps = max(c.backend.maxWriteOps, 1)
	c.backend.maxValueSize = max(c.backend.maxValueSize, len(value))
	c.backend.setValues = append(c.backend.setValues, append([]byte(nil), value...))
	err := c.backend.setErr
	if err == nil {
		err = c.backend.batchWriteErr
	}
	if err != nil {
		if c.backend.setApplyThenErr {
			c.backend.values[key] = append([]byte(nil), value...)
		} else if c.backend.setDeferApplyThenErr {
			c.backend.deferredSetKey = key
			c.backend.deferredSetValue = append([]byte(nil), value...)
		}
		return err
	}
	c.backend.values[key] = append([]byte(nil), value...)
	return nil
}

func (c *checkpointTestClient) Delete(ctx context.Context, key string) error {
	if err := c.backend.waitForDelete(ctx); err != nil {
		return err
	}
	c.backend.mu.Lock()
	defer c.backend.mu.Unlock()
	if c.backend.deleteErr != nil {
		return c.backend.deleteErr
	}
	delete(c.backend.values, key)
	return nil
}

func (c *checkpointTestClient) Batch(ctx context.Context, operations ...*storage.Operation) error {
	if c.backend.batchEntered != nil {
		select {
		case c.backend.batchEntered <- struct{}{}:
		default:
		}
	}
	if c.backend.batchRelease != nil {
		<-c.backend.batchRelease
	}
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
	if hasDelete {
		if err := c.backend.waitForDelete(ctx); err != nil {
			return err
		}
	}
	c.backend.mu.Lock()
	defer c.backend.mu.Unlock()
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
	if hasWrite && c.backend.batchWriteErr != nil && c.backend.batchWritePrefix < 0 {
		return c.backend.batchWriteErr
	}
	writesApplied := 0
	for _, operation := range operations {
		switch operation.Type {
		case storage.Get:
			if operation.Key == c.backend.batchMissingKey {
				operation.Value = nil
			} else {
				operation.Value = append([]byte(nil), c.backend.values[operation.Key]...)
			}
		case storage.Set:
			if c.backend.batchWriteErr != nil && c.backend.batchWritePrefix >= 0 && writesApplied >= c.backend.batchWritePrefix {
				return c.backend.batchWriteErr
			}
			c.backend.maxValueSize = max(c.backend.maxValueSize, len(operation.Value))
			c.backend.values[operation.Key] = append([]byte(nil), operation.Value...)
			writesApplied++
		case storage.Delete:
			if c.backend.batchWriteErr != nil && c.backend.batchWritePrefix >= 0 && writesApplied >= c.backend.batchWritePrefix {
				return c.backend.batchWriteErr
			}
			delete(c.backend.values, operation.Key)
			writesApplied++
		}
	}
	if hasWrite && c.backend.batchWriteErr != nil {
		return c.backend.batchWriteErr
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

func TestCheckpointShardStagePrefixFailuresPreserveCommittedGeneration(t *testing.T) {
	const shardCount = 3
	for prefix := 0; prefix <= shardCount; prefix++ {
		t.Run(fmt.Sprintf("after_%d_shards", prefix), func(t *testing.T) {
			backend := newCheckpointTestBackend()
			registry, binding := startCheckpointTestBinding(t, backend, fmt.Sprintf("stage-prefix-%d", prefix))
			oldShards, active := checkpointTestGeneration("old", shardCount)
			require.True(t, binding.persist(t.Context(), oldShards, active, json.RawMessage(`{"generation":"old"}`), time.Unix(100, 0)))
			oldManifest := backend.value(binding.manifestKey())
			oldReferenced := make(map[string][]byte, shardCount)
			for shard := range uint16(shardCount) {
				key := checkpointTestReferencedShardKey(t, backend, binding, shard)
				oldReferenced[key] = backend.value(key)
			}

			backend.batchWriteErr = errors.New("partial shard stage")
			backend.batchWritePrefix = prefix
			newShards, _ := checkpointTestGeneration("new", shardCount)
			assert.False(t, binding.persist(t.Context(), newShards, active, json.RawMessage(`{"generation":"new"}`), time.Unix(200, 0)))
			assert.Equal(t, oldManifest, backend.value(binding.manifestKey()))
			for key, value := range oldReferenced {
				assert.Equal(t, value, backend.value(key), "stage failure changed a shard referenced by the committed manifest")
			}

			restartRegistry, restartBinding := startCheckpointTestBinding(t, backend, fmt.Sprintf("stage-prefix-%d", prefix))
			requireCheckpointTestGeneration(t, restartBinding, "old", shardCount)
			restartRegistry.Close(t.Context())

			backend.batchWriteErr = nil
			backend.batchWritePrefix = -1
			require.True(t, binding.persist(t.Context(), newShards, active, json.RawMessage(`{"generation":"new"}`), time.Unix(200, 0)))
			finalRegistry, finalBinding := startCheckpointTestBinding(t, backend, fmt.Sprintf("stage-prefix-%d", prefix))
			requireCheckpointTestGeneration(t, finalBinding, "new", shardCount)
			finalRegistry.Close(t.Context())
			registry.Close(t.Context())
		})
	}
}

func TestCheckpointPreviousManifestReadRetriesExactCandidateOnce(t *testing.T) {
	backend := newCheckpointTestBackend()
	registry, binding := startCheckpointTestBinding(t, backend, "manifest-exact-retry")
	defer registry.Close(t.Context())
	oldShards, active := checkpointTestGeneration("old", 2)
	require.True(t, binding.persist(t.Context(), oldShards, active, nil, time.Unix(100, 0)))
	oldManifest := backend.value(binding.manifestKey())

	backend.setErr = errors.New("manifest outcome unknown")
	backend.setDeferApplyThenErr = true
	candidateShards, _ := checkpointTestGeneration("candidate", 2)
	assert.False(t, binding.persist(t.Context(), candidateShards, active, nil, time.Unix(200, 0)))
	require.NotNil(t, binding.uncertain)
	require.True(t, backend.hasDeferredSet(), "the test backend must hold the errored Set until the next same-key Set invocation")
	candidateManifest := append([]byte(nil), binding.uncertain.manifest...)
	assert.Equal(t, oldManifest, backend.value(binding.manifestKey()))
	var candidate checkpointManifest
	require.NoError(t, json.Unmarshal(candidateManifest, &candidate))
	candidateKeys := make(map[uint16]string, len(candidate.Active))
	for i, shard := range candidate.Active {
		candidateKeys[shard] = binding.slottedShardKey(shard, candidate.Slots[i])
		assert.Equal(t, fmt.Sprintf("candidate-%d", shard), string(backend.value(candidateKeys[shard])))
	}

	batchesBefore, _, _, _ := backend.writeStats()
	setValuesBefore := len(backend.manifestSetValues())
	backend.setErr = nil
	backend.setDeferApplyThenErr = false
	newerShards, _ := checkpointTestGeneration("newer", 2)
	require.True(t, binding.persist(t.Context(), newerShards, active, nil, time.Unix(300, 0)), "the pending caller snapshot must advance through the exact candidate retry")
	batchesAfter, _, _, _ := backend.writeStats()
	assert.Equal(t, batchesBefore+3, batchesAfter, "resolution must Set the candidate once, then stage and publish the pending snapshot")
	setValues := backend.manifestSetValues()
	require.Len(t, setValues, setValuesBefore+2)
	assert.Equal(t, candidateManifest, setValues[setValuesBefore], "uncertainty resolution must retry byte-identical candidate manifest data")
	assert.Nil(t, binding.uncertain)
	assert.False(t, backend.hasDeferredSet(), "the earlier errored Set must be ordered before the successful exact retry")
	assert.Equal(t, 1, backend.deferredSetStats(), "the storage model must apply the errored candidate before the later successful retry")
	finalManifest := checkpointTestManifest(t, backend, binding)
	for i, shard := range finalManifest.Active {
		assert.NotEqual(t, candidate.Slots[i], finalManifest.Slots[i], "the pending snapshot must stage opposite the committed candidate slot")
		assert.Equal(t, fmt.Sprintf("candidate-%d", shard), string(backend.value(candidateKeys[shard])), "publishing the pending snapshot must not overwrite the candidate slot")
	}
	finalRegistry, finalBinding := startCheckpointTestBinding(t, backend, "manifest-exact-retry")
	requireCheckpointTestGeneration(t, finalBinding, "newer", 2)
	finalRegistry.Close(t.Context())
}

func TestCheckpointStalePreviousObservationThenCandidateVisibilityCommitsWithoutSlotReuse(t *testing.T) {
	backend := newCheckpointTestBackend()
	registry, binding := startCheckpointTestBinding(t, backend, "manifest-late-candidate")
	defer registry.Close(t.Context())
	oldShards, active := checkpointTestGeneration("old", 2)
	require.True(t, binding.persist(t.Context(), oldShards, active, nil, time.Unix(100, 0)))
	oldManifest := backend.value(binding.manifestKey())

	backend.setErr = errors.New("manifest result ambiguous")
	backend.setApplyThenErr = true
	backend.staleGetOnceKey = binding.manifestKey()
	backend.staleGetOnceValue = oldManifest
	firstNew, _ := checkpointTestGeneration("new-one", 2)
	assert.False(t, binding.persist(t.Context(), firstNew, active, nil, time.Unix(200, 0)))
	require.NotNil(t, binding.uncertain)
	candidateManifest := append([]byte(nil), binding.uncertain.manifest...)
	assert.Equal(t, oldManifest, binding.uncertain.previousManifest)
	assert.Equal(t, candidateManifest, backend.value(binding.manifestKey()), "the errored Set may have been accepted even though reconciliation observed the stale previous value")

	backend.setApplyThenErr = false
	backend.staleGetOnceKey = binding.manifestKey()
	backend.staleGetOnceValue = oldManifest
	beforeRetry := checkpointTestValues(backend)
	secondNew, _ := checkpointTestGeneration("new-two", 2)
	assert.False(t, binding.persist(t.Context(), secondNew, active, nil, time.Unix(300, 0)))
	assert.Equal(t, beforeRetry, checkpointTestValues(backend), "another ambiguous exact retry must retain the candidate slots unchanged")
	require.NotNil(t, binding.uncertain)

	batchesBefore, _, _, _ := backend.writeStats()
	require.True(t, binding.maintain(t.Context()), "a fresh candidate observation must commit the already staged generation")
	batchesAfter, _, _, _ := backend.writeStats()
	assert.Equal(t, batchesBefore, batchesAfter, "observing the candidate must require no write")
	assert.Nil(t, binding.uncertain)
	newRestartRegistry, newRestartBinding := startCheckpointTestBinding(t, backend, "manifest-late-candidate")
	requireCheckpointTestGeneration(t, newRestartBinding, "new-one", 2)
	newRestartRegistry.Close(t.Context())
}

func TestCheckpointUnrelatedManifestKeepsAmbiguousCandidateFenced(t *testing.T) {
	backend := newCheckpointTestBackend()
	registry, binding := startCheckpointTestBinding(t, backend, "manifest-unrelated-fence")
	defer registry.Close(t.Context())
	oldShards, active := checkpointTestGeneration("old", 2)
	require.True(t, binding.persist(t.Context(), oldShards, active, nil, time.Unix(100, 0)))

	backend.setErr = errors.New("manifest outcome unknown")
	candidateShards, _ := checkpointTestGeneration("candidate", 2)
	assert.False(t, binding.persist(t.Context(), candidateShards, active, nil, time.Unix(200, 0)))
	require.NotNil(t, binding.uncertain)

	var unrelated checkpointManifest
	require.NoError(t, json.Unmarshal(binding.uncertain.previousManifest, &unrelated))
	unrelated.Metadata = json.RawMessage(`{"writer":"unrelated"}`)
	unrelatedManifest, err := json.Marshal(unrelated)
	require.NoError(t, err)
	backend.put(binding.manifestKey(), unrelatedManifest)
	before := checkpointTestValues(backend)

	assert.False(t, binding.maintain(t.Context()))
	assert.NotNil(t, binding.uncertain)
	nextShards, _ := checkpointTestGeneration("next", 2)
	assert.False(t, binding.persist(t.Context(), nextShards, active, nil, time.Unix(300, 0)))
	assert.Equal(t, before, checkpointTestValues(backend), "an unrelated manifest must permit no shard or manifest write")
}

func TestCheckpointAppliedManifestErrorImmediatelyReconcilesSuccess(t *testing.T) {
	backend := newCheckpointTestBackend()
	registry, binding := startCheckpointTestBinding(t, backend, "manifest-applied-immediate")
	defer registry.Close(t.Context())
	oldShards, active := checkpointTestGeneration("old", 2)
	require.True(t, binding.persist(t.Context(), oldShards, active, nil, time.Unix(100, 0)))

	backend.setErr = errors.New("manifest response lost after apply")
	backend.setApplyThenErr = true
	newShards, _ := checkpointTestGeneration("new", 2)
	require.True(t, binding.persist(t.Context(), newShards, active, nil, time.Unix(200, 0)), "read-after-error confirmation must count as a successful publication")
	assert.Nil(t, binding.uncertain)
	restartRegistry, restartBinding := startCheckpointTestBinding(t, backend, "manifest-applied-immediate")
	requireCheckpointTestGeneration(t, restartBinding, "new", 2)
	restartRegistry.Close(t.Context())
}

func TestCheckpointAppliedManifestErrorReconcilesBeforeSlotReuse(t *testing.T) {
	backend := newCheckpointTestBackend()
	registry, binding := startCheckpointTestBinding(t, backend, "manifest-applied-error")
	defer registry.Close(t.Context())
	oldShards, active := checkpointTestGeneration("old", 2)
	require.True(t, binding.persist(t.Context(), oldShards, active, nil, time.Unix(100, 0)))
	oldManifest := backend.value(binding.manifestKey())

	backend.setErr = errors.New("manifest applied before connection failure")
	backend.setApplyThenErr = true
	backend.getErr = errors.New("reconciliation temporarily unavailable")
	firstNew, _ := checkpointTestGeneration("new-one", 2)
	assert.False(t, binding.persist(t.Context(), firstNew, active, nil, time.Unix(200, 0)))
	require.NotNil(t, binding.uncertain)
	assert.Equal(t, oldManifest, binding.uncertain.previousManifest)

	beforeBlockedRetry := checkpointTestValues(backend)
	secondNew, _ := checkpointTestGeneration("new-two", 2)
	assert.False(t, binding.persist(t.Context(), secondNew, active, nil, time.Unix(300, 0)))
	assert.Equal(t, beforeBlockedRetry, checkpointTestValues(backend), "an unresolved publication must block every shard write")

	backend.getErr = nil
	firstRestartRegistry, firstRestartBinding := startCheckpointTestBinding(t, backend, "manifest-applied-error")
	requireCheckpointTestGeneration(t, firstRestartBinding, "new-one", 2)
	firstRestartRegistry.Close(t.Context())

	require.True(t, binding.persist(t.Context(), secondNew, active, nil, time.Unix(300, 0)))
	assert.Nil(t, binding.uncertain)
	secondRestartRegistry, secondRestartBinding := startCheckpointTestBinding(t, backend, "manifest-applied-error")
	requireCheckpointTestGeneration(t, secondRestartBinding, "new-two", 2)
	secondRestartRegistry.Close(t.Context())
}

func TestCheckpointChangedSubsetPreservesUnchangedShardReferences(t *testing.T) {
	backend := newCheckpointTestBackend()
	registry, binding := startCheckpointTestBinding(t, backend, "changed-subset")
	defer registry.Close(t.Context())
	oldShards, active := checkpointTestGeneration("old", 3)
	require.True(t, binding.persist(t.Context(), oldShards, active, nil, time.Unix(100, 0)))
	oldKeys := make(map[uint16]string, 3)
	oldValues := make(map[uint16][]byte, 3)
	for shard := range uint16(3) {
		oldKeys[shard] = checkpointTestReferencedShardKey(t, backend, binding, shard)
		oldValues[shard] = backend.value(oldKeys[shard])
	}
	batchesBefore, operationsBefore, _, _ := backend.writeStats()

	require.True(t, binding.persist(t.Context(), map[uint16][]byte{1: []byte("new-1")}, map[uint16]bool{1: true}, nil, time.Unix(200, 0)))
	batchesAfter, operationsAfter, _, _ := backend.writeStats()
	assert.Equal(t, batchesBefore+2, batchesAfter)
	assert.Equal(t, operationsBefore+2, operationsAfter, "one changed shard plus one manifest must be the complete write set")
	assert.Equal(t, oldKeys[0], checkpointTestReferencedShardKey(t, backend, binding, 0))
	assert.Equal(t, oldKeys[2], checkpointTestReferencedShardKey(t, backend, binding, 2))
	assert.NotEqual(t, oldKeys[1], checkpointTestReferencedShardKey(t, backend, binding, 1))
	assert.Equal(t, oldValues[0], checkpointTestReferencedShard(t, backend, binding, 0))
	assert.Equal(t, []byte("new-1"), checkpointTestReferencedShard(t, backend, binding, 1))
	assert.Equal(t, oldValues[2], checkpointTestReferencedShard(t, backend, binding, 2))

	restartRegistry, restartBinding := startCheckpointTestBinding(t, backend, "changed-subset")
	loaded, ok := restartBinding.load(t.Context())
	require.True(t, ok)
	assert.Equal(t, oldValues[0], loaded.shards[0])
	assert.Equal(t, []byte("new-1"), loaded.shards[1])
	assert.Equal(t, oldValues[2], loaded.shards[2])
	restartRegistry.Close(t.Context())
}

func TestCheckpointManifestReadFailureEstablishesFenceBeforeReplacementStage(t *testing.T) {
	backend := newCheckpointTestBackend()
	firstRegistry, firstBinding := startCheckpointTestBinding(t, backend, "manifest-read-fence")
	oldShards, oldActive := checkpointTestGeneration("old", 3)
	require.True(t, firstBinding.persist(t.Context(), oldShards, oldActive, nil, time.Unix(100, 0)))
	oldManifest := backend.value(firstBinding.manifestKey())
	oldReferenced := make(map[string][]byte, 3)
	for shard := range uint16(3) {
		key := checkpointTestReferencedShardKey(t, backend, firstBinding, shard)
		oldReferenced[key] = backend.value(key)
	}
	omittedKey := checkpointTestReferencedShardKey(t, backend, firstBinding, 2)
	firstRegistry.Close(t.Context())

	replacementRegistry, replacement := startCheckpointTestBinding(t, backend, "manifest-read-fence")
	defer replacementRegistry.Close(t.Context())
	backend.getErr = errors.New("temporary manifest read failure")
	_, ok := replacement.load(t.Context())
	assert.False(t, ok)
	assert.False(t, replacement.fenceKnown)
	assert.True(t, replacement.replacementRequired())

	backend.getErr = nil
	backend.batchWriteErr = errors.New("partial replacement stage")
	backend.batchWritePrefix = 1
	freshShards, freshActive := checkpointTestGeneration("fresh", 2)
	assert.False(t, replacement.persist(t.Context(), freshShards, freshActive, nil, time.Unix(200, 0)))
	assert.True(t, replacement.fenceKnown)
	assert.True(t, replacement.replaceGeneration)
	assert.Equal(t, oldManifest, replacement.manifest, "the recovered fence must retain the exact prior manifest bytes")
	assert.Equal(t, oldManifest, backend.value(replacement.manifestKey()))
	for key, value := range oldReferenced {
		assert.Equal(t, value, backend.value(key), "replacement staging changed a fenced shard")
	}
	restartRegistry, restartBinding := startCheckpointTestBinding(t, backend, "manifest-read-fence")
	requireCheckpointTestGeneration(t, restartBinding, "old", 3)
	restartRegistry.Close(t.Context())

	backend.batchWriteErr = nil
	backend.batchWritePrefix = -1
	require.True(t, replacement.persist(t.Context(), freshShards, freshActive, nil, time.Unix(200, 0)))
	assert.False(t, replacement.loadFailed.Load())
	finalRegistry, finalBinding := startCheckpointTestBinding(t, backend, "manifest-read-fence")
	requireCheckpointTestGeneration(t, finalBinding, "fresh", 2)
	assert.Equal(t, oldReferenced[omittedKey], backend.value(omittedKey), "an omitted shard may remain physically retained but must not be manifest-referenced")
	finalRegistry.Close(t.Context())
}

func TestCheckpointUnavailableLoadEstablishesFenceBeforeLaterReplacementStage(t *testing.T) {
	backend := newCheckpointTestBackend()
	firstRegistry, firstBinding := startCheckpointTestBinding(t, backend, "unavailable-load-fence")
	oldShards, active := checkpointTestGeneration("old", 2)
	require.True(t, firstBinding.persist(t.Context(), oldShards, active, nil, time.Unix(100, 0)))
	oldManifest := backend.value(firstBinding.manifestKey())
	oldKeys := []string{
		checkpointTestReferencedShardKey(t, backend, firstBinding, 0),
		checkpointTestReferencedShardKey(t, backend, firstBinding, 1),
	}
	oldValues := [][]byte{backend.value(oldKeys[0]), backend.value(oldKeys[1])}
	firstRegistry.Close(t.Context())

	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	binding := registry.bind("atomic-test", "unavailable-load-fence", "generation", func(context.Context) {})
	_, ok := binding.load(t.Context())
	assert.False(t, ok)
	assert.False(t, binding.fenceKnown)
	assert.True(t, binding.replacementRequired())
	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	defer registry.Close(t.Context())
	assert.False(t, binding.fenceKnown, "storage availability alone must not guess a durable generation")

	backend.batchWriteErr = errors.New("partial replacement stage")
	backend.batchWritePrefix = 1
	freshShards, freshActive := checkpointTestGeneration("fresh", 2)
	assert.False(t, binding.persist(t.Context(), freshShards, freshActive, nil, time.Unix(200, 0)))
	assert.True(t, binding.fenceKnown, "the first later write must establish a fence before staging")
	assert.True(t, binding.replacementRequired())
	assert.Equal(t, oldManifest, binding.manifest)
	assert.Equal(t, oldManifest, backend.value(binding.manifestKey()))
	assert.Equal(t, oldValues[0], backend.value(oldKeys[0]))
	assert.Equal(t, oldValues[1], backend.value(oldKeys[1]))
	restartRegistry, restartBinding := startCheckpointTestBinding(t, backend, "unavailable-load-fence")
	requireCheckpointTestGeneration(t, restartBinding, "old", 2)
	restartRegistry.Close(t.Context())

	backend.batchWriteErr = nil
	backend.batchWritePrefix = -1
	require.True(t, binding.persist(t.Context(), freshShards, freshActive, nil, time.Unix(200, 0)))
	finalRegistry, finalBinding := startCheckpointTestBinding(t, backend, "unavailable-load-fence")
	requireCheckpointTestGeneration(t, finalBinding, "fresh", 2)
	finalRegistry.Close(t.Context())
}

func TestCheckpointShardRestoreFailureKeepsManifestFence(t *testing.T) {
	tests := []struct {
		name string
		fail func(*checkpointTestBackend, string)
		fix  func(*checkpointTestBackend)
	}{
		{
			name: "batch read error",
			fail: func(backend *checkpointTestBackend, _ string) {
				backend.batchReadErr = errors.New("temporary shard read failure")
			},
			fix: func(backend *checkpointTestBackend) { backend.batchReadErr = nil },
		},
		{
			name: "reported missing shard",
			fail: func(backend *checkpointTestBackend, key string) { backend.batchMissingKey = key },
			fix:  func(backend *checkpointTestBackend) { backend.batchMissingKey = "" },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := newCheckpointTestBackend()
			firstRegistry, firstBinding := startCheckpointTestBinding(t, backend, "shard-restore-fence-"+tt.name)
			oldShards, active := checkpointTestGeneration("old", 2)
			require.True(t, firstBinding.persist(t.Context(), oldShards, active, nil, time.Unix(100, 0)))
			oldManifest := backend.value(firstBinding.manifestKey())
			oldKeys := []string{
				checkpointTestReferencedShardKey(t, backend, firstBinding, 0),
				checkpointTestReferencedShardKey(t, backend, firstBinding, 1),
			}
			oldValues := [][]byte{backend.value(oldKeys[0]), backend.value(oldKeys[1])}
			firstRegistry.Close(t.Context())

			replacementRegistry, replacement := startCheckpointTestBinding(t, backend, "shard-restore-fence-"+tt.name)
			defer replacementRegistry.Close(t.Context())
			tt.fail(backend, oldKeys[0])
			_, ok := replacement.load(t.Context())
			assert.False(t, ok)
			assert.True(t, replacement.fenceKnown)
			assert.True(t, replacement.replaceGeneration)
			assert.Equal(t, oldManifest, replacement.manifest)
			tt.fix(backend)

			backend.batchWriteErr = errors.New("partial replacement stage")
			backend.batchWritePrefix = 1
			freshShards, _ := checkpointTestGeneration("fresh", 2)
			assert.False(t, replacement.persist(t.Context(), freshShards, active, nil, time.Unix(200, 0)))
			assert.Equal(t, oldManifest, backend.value(replacement.manifestKey()))
			assert.Equal(t, oldValues[0], backend.value(oldKeys[0]))
			assert.Equal(t, oldValues[1], backend.value(oldKeys[1]))
			restartRegistry, restartBinding := startCheckpointTestBinding(t, backend, "shard-restore-fence-"+tt.name)
			requireCheckpointTestGeneration(t, restartBinding, "old", 2)
			restartRegistry.Close(t.Context())

			backend.batchWriteErr = nil
			backend.batchWritePrefix = -1
			require.True(t, replacement.persist(t.Context(), freshShards, active, nil, time.Unix(200, 0)))
			finalRegistry, finalBinding := startCheckpointTestBinding(t, backend, "shard-restore-fence-"+tt.name)
			requireCheckpointTestGeneration(t, finalBinding, "fresh", 2)
			finalRegistry.Close(t.Context())
		})
	}
}

func TestCheckpointInvalidManifestBlocksWritesUntilSafeFenceExists(t *testing.T) {
	tests := []struct {
		name     string
		manifest []byte
	}{
		{name: "malformed", manifest: []byte(`{"version":`)},
		{name: "unsupported", manifest: []byte(`{"version":99,"active":[0]}`)},
		{name: "invalid slots", manifest: []byte(`{"version":2,"layout":1,"active":[0]}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := newCheckpointTestBackend()
			registry, binding := startCheckpointTestBinding(t, backend, "invalid-fence-"+tt.name)
			defer registry.Close(t.Context())
			backend.put(binding.manifestKey(), tt.manifest)
			_, ok := binding.load(t.Context())
			assert.False(t, ok)
			assert.False(t, binding.fenceKnown)
			before := checkpointTestValues(backend)
			shards, active := checkpointTestGeneration("fresh", 1)
			assert.False(t, binding.persist(t.Context(), shards, active, nil, time.Unix(100, 0)))
			assert.Equal(t, before, checkpointTestValues(backend))
			batches, operations, _, _ := backend.writeStats()
			assert.Zero(t, batches, "an unsafe header must allow no Set or Delete operation")
			assert.Zero(t, operations)

			backend.put(binding.manifestKey(), nil)
			require.True(t, binding.persist(t.Context(), shards, active, nil, time.Unix(100, 0)))
			assert.False(t, binding.corrupt.Load())
			finalRegistry, finalBinding := startCheckpointTestBinding(t, backend, "invalid-fence-"+tt.name)
			requireCheckpointTestGeneration(t, finalBinding, "fresh", 1)
			finalRegistry.Close(t.Context())
		})
	}
}

func TestCheckpointAbsentManifestRemainsSafeForFirstPublication(t *testing.T) {
	backend := newCheckpointTestBackend()
	registry, binding := startCheckpointTestBinding(t, backend, "absent-manifest")
	defer registry.Close(t.Context())
	_, ok := binding.load(t.Context())
	assert.False(t, ok)
	assert.True(t, binding.fenceKnown)
	assert.False(t, binding.replacementRequired())
	shards, active := checkpointTestGeneration("first", 1)
	require.True(t, binding.persist(t.Context(), shards, active, nil, time.Unix(100, 0)))
	manifest := checkpointTestManifest(t, backend, binding)
	assert.Equal(t, checkpointManifestFormatVersion, manifest.Version)
	assert.Equal(t, []uint8{0}, manifest.Slots)
	requireCheckpointTestGeneration(t, binding, "first", 1)
}

func TestCheckpointRestoreFailurePublishesCompleteFreshDomainSnapshots(t *testing.T) {
	const freshEntries = checkpointShardEntries + 1
	baseTime := time.Unix(1_900_000_000, 0).UTC()

	t.Run("counter", func(t *testing.T) {
		backend := newCheckpointTestBackend()
		first := newCounterStoreWithConfig(baseTime, counterStoreConfig{now: func() time.Time { return baseTime }})
		firstRegistry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
		firstConsumer := firstRegistry.enableCounter("fmc", "caller-replacement-counter", first, consumertest.NewNop())
		require.NoError(t, firstRegistry.Start(t.Context(), checkpointHost(backend)))
		first.AddInt("old-resource", "old-counter", nil, 1)
		require.NoError(t, firstConsumer.ConsumeMetrics(t.Context(), pmetric.NewMetrics()))
		firstRegistry.Close(t.Context())

		fresh := newCounterStoreWithConfig(baseTime, counterStoreConfig{now: func() time.Time { return baseTime }})
		for index := range freshEntries {
			fresh.AddInt(fmt.Sprintf("fresh-resource-%d", index), "counter", nil, int64(index+1))
		}
		freshRegistry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
		freshRegistry.enableCounter("fmc", "caller-replacement-counter", fresh, consumertest.NewNop())
		backend.batchReadErr = errors.New("temporary counter shard restore failure")
		require.NoError(t, freshRegistry.Start(t.Context(), checkpointHost(backend)))
		assert.True(t, fresh.metadataDirty)
		for shard := range fresh.shards {
			assert.NotEqual(t, fresh.persisted[shard], fresh.generation[shard], "every fresh counter page must be replacement-dirty")
		}
		backend.batchReadErr = nil
		fresh.persistCheckpoint(t.Context())
		assert.False(t, fresh.checkpoint.loadFailed.Load())
		freshRegistry.Close(t.Context())

		restarted := newCounterStoreWithConfig(baseTime, counterStoreConfig{now: func() time.Time { return baseTime }})
		restartedRegistry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
		restartedRegistry.enableCounter("fmc", "caller-replacement-counter", restarted, consumertest.NewNop())
		require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
		assert.NotContains(t, restarted.intValues, counterKey("old-resource", "old-counter", nil))
		for index := range freshEntries {
			series := restarted.intValues[counterKey(fmt.Sprintf("fresh-resource-%d", index), "counter", nil)]
			require.NotNil(t, series)
			assert.Equal(t, int64(index+1), series.value)
		}
		restartedRegistry.Close(t.Context())
	})

	t.Run("log dedup", func(t *testing.T) {
		backend := newCheckpointTestBackend()
		first := newLogDeduplicator()
		first.now = func() time.Time { return baseTime }
		firstRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
		firstRegistry.enableLogDedup("ise", "caller-replacement-log", first, logCheckpointRetention{})
		require.NoError(t, firstRegistry.Start(t.Context(), checkpointHost(backend)))
		first.BeginBatch()
		require.True(t, first.MarkPending("old-log", baseTime))
		_, err := consumeDeduplicatedLogs(t.Context(), consumertest.NewNop(), first, oneLogRecord())
		require.NoError(t, err)
		firstRegistry.Close(t.Context())

		fresh := newLogDeduplicator()
		fresh.now = func() time.Time { return baseTime }
		for index := range freshEntries {
			require.True(t, fresh.MarkCommitted(fmt.Sprintf("fresh-log-%d", index), baseTime))
		}
		freshRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
		freshRegistry.enableLogDedup("ise", "caller-replacement-log", fresh, logCheckpointRetention{})
		backend.batchReadErr = errors.New("temporary log shard restore failure")
		require.NoError(t, freshRegistry.Start(t.Context(), checkpointHost(backend)))
		assert.True(t, fresh.manifestDirty)
		for shard := range fresh.shards {
			assert.NotEqual(t, fresh.persisted[shard], fresh.generation[shard], "every fresh log page must be replacement-dirty")
		}
		backend.batchReadErr = nil
		fresh.persistCheckpoint(t.Context(), true)
		assert.False(t, fresh.checkpoint.loadFailed.Load())
		freshRegistry.Close(t.Context())

		restarted := newLogDeduplicator()
		restarted.now = func() time.Time { return baseTime }
		restartedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
		restartedRegistry.enableLogDedup("ise", "caller-replacement-log", restarted, logCheckpointRetention{})
		require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
		assert.NotContains(t, restarted.seen, logDedupStateKey("old-log"))
		for index := range freshEntries {
			assert.Contains(t, restarted.seen, logDedupStateKey(fmt.Sprintf("fresh-log-%d", index)))
		}
		restartedRegistry.Close(t.Context())
	})

	t.Run("FMC", func(t *testing.T) {
		backend := newCheckpointTestBackend()
		now := baseTime.Add(time.Hour)
		first := newFMCEStreamerResumeState(baseTime.Add(-time.Hour))
		first.now = func() time.Time { return now }
		firstRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
		firstRegistry.enableFMCResume("caller-replacement-fmc", first)
		require.NoError(t, firstRegistry.Start(t.Context(), checkpointHost(backend)))
		first.commit("old-fmc", baseTime, baseTime)
		first.persistCheckpoint(t.Context(), true)
		firstRegistry.Close(t.Context())

		fresh := newFMCEStreamerResumeState(baseTime.Add(-time.Hour))
		fresh.now = func() time.Time { return now }
		for index := range freshEntries {
			observed := baseTime.Add(time.Duration(index) * time.Nanosecond)
			fresh.commit(fmt.Sprintf("fresh-fmc-%d", index), observed, observed)
		}
		freshRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
		freshRegistry.enableFMCResume("caller-replacement-fmc", fresh)
		backend.batchReadErr = errors.New("temporary FMC shard restore failure")
		require.NoError(t, freshRegistry.Start(t.Context(), checkpointHost(backend)))
		assert.True(t, fresh.metadataDirty)
		for shard := range fresh.shards {
			assert.NotEqual(t, fresh.persisted[shard], fresh.generation[shard], "every fresh FMC page must be replacement-dirty")
		}
		backend.batchReadErr = nil
		fresh.persistCheckpoint(t.Context(), true)
		assert.False(t, fresh.checkpoint.loadFailed.Load())
		freshRegistry.Close(t.Context())

		restarted := newFMCEStreamerResumeState(baseTime.Add(-time.Hour))
		restarted.now = func() time.Time { return now }
		restartedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
		restartedRegistry.enableFMCResume("caller-replacement-fmc", restarted)
		require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
		assert.False(t, restarted.seenBefore("old-fmc"))
		for index := range freshEntries {
			assert.True(t, restarted.seenBefore(fmt.Sprintf("fresh-fmc-%d", index)))
		}
		restartedRegistry.Close(t.Context())
	})
}

func TestCheckpointDomainPayloadRejectionPublishesOnlyFreshSnapshot(t *testing.T) {
	const freshEntries = checkpointShardEntries + 1
	durableAnchor := time.Unix(1_900_000_000, 0).UTC()
	replacementNow := durableAnchor.Add(-10 * time.Minute)
	backend := newCheckpointTestBackend()

	first := newLogDeduplicator()
	first.now = func() time.Time { return durableAnchor }
	require.True(t, first.MarkCommitted("old-seed", durableAnchor))
	firstRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	firstRegistry.enableLogDedup("ise", "domain-rejection-replacement", first, logCheckpointRetention{})
	require.NoError(t, firstRegistry.Start(t.Context(), checkpointHost(backend)))
	first.persistCheckpoint(t.Context(), true)
	binding := first.checkpoint
	committedManifest := backend.value(binding.manifestKey())
	manifest := checkpointTestManifest(t, backend, binding)
	require.Equal(t, checkpointManifestFormatVersion, manifest.Version)
	require.Equal(t, durableAnchor, manifest.ClockAnchor)

	rejectedKey := logDedupStateKey("rejected-durable-entry")
	rejectedPage, err := json.Marshal(logDedupCheckpointShard{
		Version: checkpointFormatVersion,
		Shard:   0,
		Entries: []logDedupCheckpointEntry{
			{Key: rejectedKey, SeenAt: durableAnchor},
			{Key: rejectedKey, SeenAt: durableAnchor},
		},
	})
	require.NoError(t, err)
	backend.put(checkpointTestReferencedShardKey(t, backend, binding, 0), rejectedPage)
	firstRegistry.Close(t.Context())

	fresh := newLogDeduplicator()
	fresh.now = func() time.Time { return replacementNow }
	for index := range freshEntries {
		require.True(t, fresh.MarkCommitted(fmt.Sprintf("fresh-domain-entry-%d", index), replacementNow))
	}
	freshRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	freshRegistry.enableLogDedup("ise", "domain-rejection-replacement", fresh, logCheckpointRetention{})
	batchesBefore, operationsBefore, _, _ := backend.writeStats()
	require.NoError(t, freshRegistry.Start(t.Context(), checkpointHost(backend)))
	batchesAfter, operationsAfter, _, _ := backend.writeStats()
	assert.Equal(t, batchesBefore, batchesAfter, "domain rejection must not mutate durable state during restore")
	assert.Equal(t, operationsBefore, operationsAfter)
	assert.True(t, fresh.checkpoint.corrupt.Load())
	assert.True(t, fresh.checkpoint.replacementRequired())
	assert.True(t, fresh.checkpoint.fenceKnown)
	assert.Equal(t, committedManifest, fresh.checkpoint.manifest)
	assert.Equal(t, durableAnchor, fresh.checkpoint.clockAnchor)
	assert.NotContains(t, fresh.seen, rejectedKey, "a valid-looking entry preceding the validation error must not leak into memory")
	for shard := range fresh.shards {
		assert.NotEqual(t, fresh.persisted[shard], fresh.generation[shard], "every fresh page must remain replacement-dirty")
	}

	fresh.persistCheckpoint(t.Context(), true)
	assert.False(t, fresh.checkpoint.corrupt.Load())
	assert.False(t, fresh.checkpoint.replacementRequired())
	assert.Equal(t, durableAnchor, checkpointTestManifest(t, backend, fresh.checkpoint).ClockAnchor,
		"replacement must retain the committed monotonic anchor across a host-clock rollback")
	freshRegistry.Close(t.Context())

	restarted := newLogDeduplicator()
	restarted.now = func() time.Time { return replacementNow }
	restartedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	restartedRegistry.enableLogDedup("ise", "domain-rejection-replacement", restarted, logCheckpointRetention{})
	require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.False(t, restarted.checkpoint.corrupt.Load())
	assert.NotContains(t, restarted.seen, rejectedKey)
	assert.Len(t, restarted.seen, freshEntries)
	for index := range freshEntries {
		assert.Contains(t, restarted.seen, logDedupStateKey(fmt.Sprintf("fresh-domain-entry-%d", index)))
	}
	restartedRegistry.Close(t.Context())
}

func TestCheckpointDeletionAndReactivationUseCompleteGenerations(t *testing.T) {
	backend := newCheckpointTestBackend()
	registry, binding := startCheckpointTestBinding(t, backend, "delete-reactivate")
	defer registry.Close(t.Context())
	require.True(t, binding.persist(t.Context(), map[uint16][]byte{0: []byte("old-0")}, map[uint16]bool{0: true}, nil, time.Unix(100, 0)))

	require.True(t, binding.persist(t.Context(), nil, map[uint16]bool{0: false}, nil, time.Unix(200, 0)))
	deletedManifest := checkpointTestManifest(t, backend, binding)
	assert.Empty(t, deletedManifest.Active)
	assert.Equal(t, []byte("old-0"), backend.value(binding.slottedShardKey(0, 0)), "logical deletion must not require physical cleanup")
	deletedRestartRegistry, deletedRestartBinding := startCheckpointTestBinding(t, backend, "delete-reactivate")
	deleted := requireCheckpointTestGeneration(t, deletedRestartBinding, "unused", 0)
	deletedRestartBinding.acceptLoaded(deleted)
	deletedRestartRegistry.Close(t.Context())

	require.True(t, binding.persist(t.Context(), map[uint16][]byte{0: []byte("reactivated-0")}, map[uint16]bool{0: true}, nil, time.Unix(300, 0)))
	reactivatedRestartRegistry, reactivatedRestartBinding := startCheckpointTestBinding(t, backend, "delete-reactivate")
	requireCheckpointTestGeneration(t, reactivatedRestartBinding, "reactivated", 1)
	reactivatedRestartRegistry.Close(t.Context())
}

func TestCheckpointStaleKeyDeletionCannotBlockPublicationOtherIdentitiesOrShutdown(t *testing.T) {
	tests := []struct {
		name              string
		blockUntilRelease bool
		blockUntilContext bool
	}{
		{name: "delete blocks until released", blockUntilRelease: true},
		{name: "delete exhausts its context", blockUntilContext: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := newCheckpointTestBackend()
			registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
			first := registry.bind("atomic-test", "delete-liveness-first", "generation", func(context.Context) {})
			second := registry.bind("atomic-test", "delete-liveness-second", "generation", func(context.Context) {})
			require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
			active := map[uint16]bool{0: true}
			require.True(t, first.persist(t.Context(), map[uint16][]byte{0: []byte("generation-0")}, active, nil, time.Unix(100, 0)))
			require.True(t, first.persist(t.Context(), map[uint16][]byte{0: []byte("generation-1")}, active, nil, time.Unix(200, 0)))

			deleteEntered := make(chan struct{}, 1)
			backend.deleteEntered = deleteEntered
			var releaseDelete chan struct{}
			if tt.blockUntilRelease {
				releaseDelete = make(chan struct{})
				backend.deleteRelease = releaseDelete
			}
			backend.deleteUntilContext = tt.blockUntilContext
			operationCtx, cancelOperations := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancelOperations()
			var releaseOnce sync.Once
			release := func() {
				releaseOnce.Do(func() {
					cancelOperations()
					if releaseDelete != nil {
						close(releaseDelete)
					}
				})
			}
			defer release()

			requireReturns := func(name string, call func() bool) {
				done := make(chan bool, 1)
				go func() { done <- call() }()
				select {
				case result := <-done:
					require.True(t, result, name)
				case <-time.After(time.Second):
					release()
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Errorf("%s did not stop after releasing the adversarial storage operation", name)
					}
					t.Fatalf("%s was delayed by stale-key deletion", name)
				}
			}

			requireReturns("subsequent generation publication", func() bool {
				return first.persist(operationCtx, map[uint16][]byte{0: []byte("generation-2")}, active, nil, time.Unix(300, 0))
			})
			requireReturns("unrelated identity publication", func() bool {
				return second.persist(operationCtx, map[uint16][]byte{0: []byte("unrelated")}, active, nil, time.Unix(300, 0))
			})
			loaded, ok := first.load(t.Context())
			require.True(t, ok)
			assert.Equal(t, []byte("generation-2"), loaded.shards[0])
			assert.Zero(t, backend.deleteStats(), "checkpoint persistence must never invoke stale-key deletion")
			select {
			case <-deleteEntered:
				t.Fatal("stale-key deletion entered storage")
			default:
			}

			shutdownCtx, cancelShutdown := context.WithTimeout(t.Context(), time.Second)
			defer cancelShutdown()
			shutdownDone := make(chan struct{})
			go func() {
				registry.Close(shutdownCtx)
				close(shutdownDone)
			}()
			select {
			case <-shutdownDone:
			case <-shutdownCtx.Done():
				release()
				<-shutdownDone
				t.Fatal("checkpoint shutdown was delayed by stale-key deletion")
			}
		})
	}
}

func TestCheckpointLegacyManifestMigratesAtomicallyToVersionTwo(t *testing.T) {
	backend := newCheckpointTestBackend()
	registry, binding := startCheckpointTestBinding(t, backend, "legacy-migration")
	defer registry.Close(t.Context())
	anchor := time.Unix(500, 0).UTC()
	metadata := json.RawMessage(`{"legacy":true}`)
	legacyManifest, err := json.Marshal(checkpointManifest{
		Version: checkpointFormatVersion, Active: []uint16{0, 1}, Metadata: metadata, ClockAnchor: anchor,
	})
	require.NoError(t, err)
	backend.put(binding.manifestKey(), legacyManifest)
	backend.put(binding.shardKey(0), []byte("legacy-0"))
	backend.put(binding.shardKey(1), []byte("legacy-1"))

	loaded, ok := binding.load(t.Context())
	require.True(t, ok)
	require.True(t, loaded.legacy)
	binding.acceptLoaded(loaded)
	require.True(t, binding.maintain(t.Context()))

	manifest := checkpointTestManifest(t, backend, binding)
	assert.Equal(t, checkpointManifestFormatVersion, manifest.Version)
	assert.Equal(t, checkpointSlottedLayout, manifest.Layout)
	assert.Equal(t, []uint16{0, 1}, manifest.Active)
	assert.Equal(t, []uint8{0, 0}, manifest.Slots)
	assert.Equal(t, metadata, manifest.Metadata)
	assert.Equal(t, anchor, manifest.ClockAnchor)
	assert.Equal(t, []byte("legacy-0"), backend.value(binding.shardKey(0)), "legacy keys remain as bounded stale storage")
	assert.Equal(t, []byte("legacy-1"), backend.value(binding.shardKey(1)), "legacy keys remain as bounded stale storage")
	requireCheckpointTestGeneration(t, binding, "legacy", 2)

	backend.put(binding.shardKey(0), []byte("stale-v1-0"))
	legacyShardReads := 0
	var legacyDecoder struct {
		Version int `json:"version"`
	}
	require.NoError(t, json.Unmarshal(backend.value(binding.manifestKey()), &legacyDecoder))
	legacyLoad := func() error {
		if legacyDecoder.Version != checkpointFormatVersion {
			return fmt.Errorf("unsupported checkpoint manifest version %d", legacyDecoder.Version)
		}
		legacyShardReads++
		return nil
	}
	assert.Error(t, legacyLoad(), "a v1-only receiver must reject a v2 manifest")
	assert.Zero(t, legacyShardReads, "rollback must reject v2 before reading stale unslotted shards")
}

func TestCheckpointLegacyMigrationStageFailureRetriesWithoutChangingVersionOne(t *testing.T) {
	backend := newCheckpointTestBackend()
	registry, binding := startCheckpointTestBinding(t, backend, "legacy-migration-retry")
	defer registry.Close(t.Context())
	legacyManifest, err := json.Marshal(checkpointManifest{Version: checkpointFormatVersion, Active: []uint16{0, 1}})
	require.NoError(t, err)
	backend.put(binding.manifestKey(), legacyManifest)
	backend.put(binding.shardKey(0), []byte("legacy-0"))
	backend.put(binding.shardKey(1), []byte("legacy-1"))
	loaded, ok := binding.load(t.Context())
	require.True(t, ok)
	binding.acceptLoaded(loaded)

	backend.batchWriteErr = errors.New("partial legacy migration stage")
	backend.batchWritePrefix = 1
	assert.False(t, binding.maintain(t.Context()))
	assert.Equal(t, legacyManifest, backend.value(binding.manifestKey()))
	assert.Equal(t, []byte("legacy-0"), backend.value(binding.shardKey(0)))
	assert.Equal(t, []byte("legacy-1"), backend.value(binding.shardKey(1)))
	restartRegistry, restartBinding := startCheckpointTestBinding(t, backend, "legacy-migration-retry")
	restarted := requireCheckpointTestGeneration(t, restartBinding, "legacy", 2)
	assert.True(t, restarted.legacy)
	restartRegistry.Close(t.Context())

	backend.batchWriteErr = nil
	backend.batchWritePrefix = -1
	require.True(t, binding.maintain(t.Context()))
	assert.Equal(t, checkpointManifestFormatVersion, checkpointTestManifest(t, backend, binding).Version)
	finalRegistry, finalBinding := startCheckpointTestBinding(t, backend, "legacy-migration-retry")
	final := requireCheckpointTestGeneration(t, finalBinding, "legacy", 2)
	assert.False(t, final.legacy)
	finalRegistry.Close(t.Context())
}

func TestCheckpointManifestVersionAndSlotValidation(t *testing.T) {
	tests := []checkpointManifest{
		{Version: checkpointFormatVersion, Layout: checkpointSlottedLayout},
		{Version: checkpointFormatVersion, Slots: []uint8{0}},
		{Version: checkpointManifestFormatVersion, Layout: checkpointSlottedLayout, Active: []uint16{0}},
		{Version: checkpointManifestFormatVersion, Layout: checkpointSlottedLayout, Active: []uint16{0}, Slots: []uint8{checkpointShardSlots}},
	}
	for _, manifest := range tests {
		assert.Error(t, validateCheckpointManifest(manifest))
	}
	assert.NoError(t, validateCheckpointManifest(checkpointManifest{
		Version: checkpointManifestFormatVersion,
		Layout:  checkpointSlottedLayout,
		Active:  []uint16{0, 1},
		Slots:   []uint8{1, 0},
	}))
}

func TestCheckpointRetainedStaleKeyspaceIsBounded(t *testing.T) {
	backend := newCheckpointTestBackend()
	registry, binding := startCheckpointTestBinding(t, backend, "bounded-stale-keys")
	defer registry.Close(t.Context())
	active := map[uint16]bool{0: true}
	require.True(t, binding.persist(t.Context(), map[uint16][]byte{0: []byte("generation-0")}, active, nil, time.Unix(100, 0)))
	for generation := 1; generation <= 8; generation++ {
		value := []byte(fmt.Sprintf("generation-%d", generation))
		require.True(t, binding.persist(t.Context(), map[uint16][]byte{0: value}, active, nil, time.Unix(int64(100+generation), 0)))
		loaded, ok := binding.load(t.Context())
		require.True(t, ok)
		assert.Equal(t, value, loaded.shards[0])
		binding.acceptLoaded(loaded)
	}
	values := checkpointTestValues(backend)
	assert.LessOrEqual(t, len(values), 1+checkpointShardSlots, "manifest plus two fixed slots bounds stale generations")

	require.True(t, binding.persist(t.Context(), nil, map[uint16]bool{0: false}, nil, time.Unix(200, 0)))
	loaded, ok := binding.load(t.Context())
	require.True(t, ok)
	assert.Empty(t, loaded.shards)
	binding.acceptLoaded(loaded)
	values = checkpointTestValues(backend)
	assert.LessOrEqual(t, len(values), 1+checkpointShardSlots, "retained stale data remains bounded by the fixed slot namespace")

	require.True(t, binding.maintain(t.Context()))
	assert.Equal(t, values, checkpointTestValues(backend), "maintenance must perform no stale-key I/O")
	assert.Zero(t, backend.deleteStats())
	loaded, ok = binding.load(t.Context())
	require.True(t, ok)
	assert.Empty(t, loaded.shards)
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

func TestCounterCheckpointSurvivesWallClockRollback(t *testing.T) {
	backend := newCheckpointTestBackend()
	firstObservation := time.Unix(1_900_000_000, 0).UTC()
	current := firstObservation
	first := newCounterStoreWithConfig(firstObservation.Add(-time.Hour), counterStoreConfig{now: func() time.Time { return current }})
	firstRegistry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
	consumer := firstRegistry.enableCounter("fmc", "clock-rollback-target", first, consumertest.NewNop())
	require.NoError(t, firstRegistry.Start(t.Context(), checkpointHost(backend)))

	_, _ = first.AddInt("device-a", "packets", nil, 7)
	current = firstObservation.Add(-time.Minute)
	value, _ := first.AddInt("device-a", "packets", nil, 5)
	assert.Equal(t, int64(12), value)
	series := first.intValues[counterKey("device-a", "packets", nil)]
	require.NotNil(t, series)
	assert.Equal(t, firstObservation, series.lastSeen, "a live clock rollback must not invert the persisted series interval")
	require.NoError(t, consumer.ConsumeMetrics(t.Context(), pmetric.NewMetrics()))
	firstRegistry.Close(t.Context())

	restartAt := firstObservation.Add(-10 * time.Minute)
	restarted := newCounterStoreWithConfig(restartAt, counterStoreConfig{now: func() time.Time { return restartAt }})
	restartedRegistry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
	restartedRegistry.enableCounter("fmc", "clock-rollback-target", restarted, consumertest.NewNop())
	require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.False(t, restarted.checkpoint.corrupt.Load())
	value, epoch := restarted.AddInt("device-a", "packets", nil, 1)
	assert.Equal(t, int64(13), value, "clock rollback must not reset the accumulated counter")
	assert.Equal(t, restartAt, epoch, "future wall times must be normalized to the restored clock")
	restartedRegistry.Close(t.Context())
}

func TestCounterCheckpointMigratesMissingClockAnchorAcrossRepeatedRollback(t *testing.T) {
	backend := newCheckpointTestBackend()
	firstObservation := time.Unix(1_900_000_000, 0).UTC()
	const target = "missing-anchor-counter-target"
	first := newCounterStoreWithConfig(firstObservation.Add(-time.Minute), counterStoreConfig{now: func() time.Time { return firstObservation }})
	firstRegistry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
	consumer := firstRegistry.enableCounter("fmc", target, first, consumertest.NewNop())
	require.NoError(t, firstRegistry.Start(t.Context(), checkpointHost(backend)))
	_, _ = first.AddInt("device-a", "packets", nil, 7)
	require.NoError(t, consumer.ConsumeMetrics(t.Context(), pmetric.NewMetrics()))
	binding := first.checkpoint
	shardKey := checkpointTestReferencedShardKey(t, backend, binding, 0)
	originalShard := backend.value(shardKey)
	removeCheckpointClockAnchor(t, backend, binding)
	firstRegistry.Close(t.Context())

	migrationTime := firstObservation.Add(-10 * time.Minute)
	migrated := newCounterStoreWithConfig(migrationTime, counterStoreConfig{now: func() time.Time { return migrationTime }})
	migratedRegistry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
	migratedRegistry.enableCounter("fmc", target, migrated, consumertest.NewNop())
	batchesBefore, operationsBefore, _, _ := backend.writeStats()
	require.NoError(t, migratedRegistry.Start(t.Context(), checkpointHost(backend)))
	batchesAfter, operationsAfter, _, _ := backend.writeStats()
	assert.Equal(t, batchesBefore+2, batchesAfter)
	assert.Equal(t, operationsBefore+2, operationsAfter, "rollback migration must stage the normalized shard before publishing the manifest")
	assert.Equal(t, originalShard, backend.value(shardKey), "copy-on-write must not mutate the previously referenced slot")
	assert.NotEqual(t, originalShard, checkpointTestReferencedShard(t, backend, migrated.checkpoint, 0))
	assert.Equal(t, migrationTime, checkpointTestManifest(t, backend, migrated.checkpoint).ClockAnchor)
	migratedSeries := migrated.intValues[counterKey("device-a", "packets", nil)]
	require.NotNil(t, migratedSeries)
	assert.Equal(t, int64(7), migratedSeries.value)
	assert.Equal(t, migrationTime, migrated.StartTime())
	assert.Equal(t, migrationTime, migratedSeries.startedAt)
	assert.Equal(t, migrationTime, migratedSeries.lastSeen)
	migratedRegistry.Close(t.Context())

	restartTime := migrationTime.Add(-10 * time.Minute)
	restarted := newCounterStoreWithConfig(restartTime, counterStoreConfig{now: func() time.Time { return restartTime }})
	restartedRegistry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
	restartedRegistry.enableCounter("fmc", target, restarted, consumertest.NewNop())
	require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.False(t, restarted.checkpoint.corrupt.Load(), "the migrated anchor must preserve a second rollback restart")
	series := restarted.intValues[counterKey("device-a", "packets", nil)]
	require.NotNil(t, series)
	assert.Equal(t, int64(7), series.value)
	assert.Equal(t, restartTime, restarted.StartTime())
	assert.Equal(t, restartTime, series.startedAt)
	assert.Equal(t, restartTime, series.lastSeen)
	assert.Equal(t, migrationTime, checkpointTestManifest(t, backend, restarted.checkpoint).ClockAnchor)
	restartedRegistry.Close(t.Context())
}

func TestLogDedupCheckpointSurvivesWallClockRollback(t *testing.T) {
	backend := newCheckpointTestBackend()
	firstObservation := time.Unix(1_900_000_000, 0).UTC()
	const eventKey = "accepted-before-clock-rollback"
	first := newLogDeduplicator()
	first.now = func() time.Time { return firstObservation }
	firstRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	firstRegistry.enableLogDedup("ise", "clock-rollback-target", first, logCheckpointRetention{})
	require.NoError(t, firstRegistry.Start(t.Context(), checkpointHost(backend)))
	first.BeginBatch()
	require.True(t, first.MarkPending(eventKey, firstObservation))
	_, err := consumeDeduplicatedLogs(t.Context(), consumertest.NewNop(), first, oneLogRecord())
	require.NoError(t, err)
	firstRegistry.Close(t.Context())

	restartAt := firstObservation.Add(-10 * time.Minute)
	restarted := newLogDeduplicator()
	restarted.now = func() time.Time { return restartAt }
	restartedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	restartedRegistry.enableLogDedup("ise", "clock-rollback-target", restarted, logCheckpointRetention{})
	require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.False(t, restarted.checkpoint.corrupt.Load())
	restarted.BeginBatch()
	assert.False(t, restarted.MarkPending(eventKey, restartAt), "clock rollback must not replay an already delivered event")
	restarted.RollbackBatch()
	restartedRegistry.Close(t.Context())
}

func TestLogDedupCheckpointMigratesMissingClockAnchorAcrossRepeatedRollback(t *testing.T) {
	backend := newCheckpointTestBackend()
	firstObservation := time.Unix(1_900_000_000, 0).UTC()
	const (
		target   = "missing-anchor-log-target"
		eventKey = "accepted-before-anchor-migration"
	)
	first := newLogDeduplicator()
	first.now = func() time.Time { return firstObservation }
	firstRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	firstRegistry.enableLogDedup("ise", target, first, logCheckpointRetention{})
	require.NoError(t, firstRegistry.Start(t.Context(), checkpointHost(backend)))
	first.BeginBatch()
	require.True(t, first.MarkPending(eventKey, firstObservation))
	_, err := consumeDeduplicatedLogs(t.Context(), consumertest.NewNop(), first, oneLogRecord())
	require.NoError(t, err)
	binding := first.checkpoint
	shardKey := checkpointTestReferencedShardKey(t, backend, binding, 0)
	originalShard := backend.value(shardKey)
	removeCheckpointClockAnchor(t, backend, binding)
	firstRegistry.Close(t.Context())

	migrationTime := firstObservation.Add(-10 * time.Minute)
	migrated := newLogDeduplicator()
	migrated.now = func() time.Time { return migrationTime }
	migratedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	migratedRegistry.enableLogDedup("ise", target, migrated, logCheckpointRetention{})
	batchesBefore, operationsBefore, _, _ := backend.writeStats()
	require.NoError(t, migratedRegistry.Start(t.Context(), checkpointHost(backend)))
	batchesAfter, operationsAfter, _, _ := backend.writeStats()
	assert.Equal(t, batchesBefore+2, batchesAfter)
	assert.Equal(t, operationsBefore+2, operationsAfter, "rollback migration must stage the normalized shard before publishing the manifest")
	assert.Equal(t, originalShard, backend.value(shardKey), "copy-on-write must not mutate the previously referenced slot")
	assert.NotEqual(t, originalShard, checkpointTestReferencedShard(t, backend, migrated.checkpoint, 0))
	assert.Equal(t, migrationTime, checkpointTestManifest(t, backend, migrated.checkpoint).ClockAnchor)
	assert.Equal(t, migrationTime, migrated.seen[logDedupStateKey(eventKey)].seenAt)
	migrated.BeginBatch()
	assert.False(t, migrated.MarkPending(eventKey, migrationTime))
	migrated.RollbackBatch()
	migratedRegistry.Close(t.Context())

	restartTime := migrationTime.Add(-10 * time.Minute)
	restarted := newLogDeduplicator()
	restarted.now = func() time.Time { return restartTime }
	restartedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	restartedRegistry.enableLogDedup("ise", target, restarted, logCheckpointRetention{})
	require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.False(t, restarted.checkpoint.corrupt.Load(), "the migrated anchor must preserve a second rollback restart")
	restarted.BeginBatch()
	assert.False(t, restarted.MarkPending(eventKey, restartTime))
	restarted.RollbackBatch()
	assert.Equal(t, restartTime, restarted.seen[logDedupStateKey(eventKey)].seenAt)
	assert.Equal(t, migrationTime, checkpointTestManifest(t, backend, restarted.checkpoint).ClockAnchor)
	restartedRegistry.Close(t.Context())
}

func TestCheckpointMissingClockAnchorManifestMigrationRetriesAfterFailure(t *testing.T) {
	migrationErr := errors.New("temporary manifest migration failure")
	writeManifest := func(t *testing.T, backend *checkpointTestBackend, binding *checkpointBinding, metadata json.RawMessage) {
		t.Helper()
		manifest, err := json.Marshal(checkpointManifest{Version: checkpointFormatVersion, Metadata: metadata})
		require.NoError(t, err)
		require.NotContains(t, string(manifest), "clock_anchor")
		backend.put(binding.manifestKey(), manifest)
		backend.batchWriteErr = migrationErr
	}

	t.Run("counter", func(t *testing.T) {
		backend := newCheckpointTestBackend()
		now := time.Unix(1_900_000_000, 0).UTC()
		state := newCounterStoreWithConfig(now, counterStoreConfig{now: func() time.Time { return now }})
		registry := newCheckpointTestRegistry(checkpointSignalMetrics, zap.NewNop())
		registry.enableCounter("fmc", "retry-counter-target", state, consumertest.NewNop())
		metadata, err := json.Marshal(counterCheckpointMetadata{StartedAt: now.Add(-time.Hour)})
		require.NoError(t, err)
		writeManifest(t, backend, state.checkpoint, metadata)

		require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
		assert.True(t, state.metadataDirty)
		assert.True(t, checkpointTestManifest(t, backend, state.checkpoint).ClockAnchor.IsZero())
		backend.batchWriteErr = nil
		state.persistCheckpoint(t.Context())
		assert.False(t, state.metadataDirty)
		assert.Equal(t, now, checkpointTestManifest(t, backend, state.checkpoint).ClockAnchor)
		registry.Close(t.Context())
	})

	t.Run("log dedup", func(t *testing.T) {
		backend := newCheckpointTestBackend()
		current := time.Unix(1_900_000_000, 0).UTC()
		state := newLogDeduplicator()
		state.now = func() time.Time { return current }
		registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
		registry.enableLogDedup("ise", "retry-log-target", state, logCheckpointRetention{})
		writeManifest(t, backend, state.checkpoint, nil)

		require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
		assert.True(t, state.manifestDirty)
		assert.True(t, checkpointTestManifest(t, backend, state.checkpoint).ClockAnchor.IsZero())
		state.BeginBatch()
		count, err := consumeDeduplicatedLogs(t.Context(), consumertest.NewErr(errors.New("empty poll must not call the consumer")), state, plog.NewLogs())
		require.NoError(t, err)
		assert.Zero(t, count)
		assert.True(t, state.manifestDirty, "the retry backoff must retain pending manifest work")
		backend.batchWriteErr = nil
		current = current.Add(logCheckpointFlushInterval)
		state.BeginBatch()
		count, err = consumeDeduplicatedLogs(t.Context(), consumertest.NewErr(errors.New("empty poll must not call the consumer")), state, plog.NewLogs())
		require.NoError(t, err)
		assert.Zero(t, count)
		assert.False(t, state.manifestDirty)
		assert.Equal(t, current, checkpointTestManifest(t, backend, state.checkpoint).ClockAnchor)
		registry.Close(t.Context())
	})

	t.Run("FMC", func(t *testing.T) {
		backend := newCheckpointTestBackend()
		current := time.Unix(1_900_000_000, 0).UTC()
		state := newFMCEStreamerResumeState(current.Add(-time.Hour))
		state.now = func() time.Time { return current }
		registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
		registry.enableFMCResume("retry-fmc-target", state)
		writeManifest(t, backend, state.checkpoint, nil)

		require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
		assert.True(t, state.metadataDirty)
		assert.True(t, checkpointTestManifest(t, backend, state.checkpoint).ClockAnchor.IsZero())
		backend.batchWriteErr = nil
		current = current.Add(fmcCheckpointFlushInterval)
		state.persistCheckpoint(t.Context(), false)
		assert.False(t, state.metadataDirty)
		assert.Equal(t, current, checkpointTestManifest(t, backend, state.checkpoint).ClockAnchor)
		registry.Close(t.Context())
	})
}

func TestEmptyPollingLogBatchRetriesFailedCheckpointNormalization(t *testing.T) {
	backend := newCheckpointTestBackend()
	current := time.Unix(1_900_000_000, 0).UTC()
	normalizedAt := current
	state := newLogDeduplicator()
	state.now = func() time.Time { return current }
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	registry.enableLogDedup("fmc", "retry-normalized-log-target", state, logCheckpointRetention{})
	binding := state.checkpoint
	const eventKey = "future-log-event"
	page, err := json.Marshal(logDedupCheckpointShard{
		Version: checkpointFormatVersion,
		Shard:   0,
		Entries: []logDedupCheckpointEntry{{Key: logDedupStateKey(eventKey), SeenAt: current.Add(time.Minute)}},
	})
	require.NoError(t, err)
	manifest, err := json.Marshal(checkpointManifest{Version: checkpointFormatVersion, Active: []uint16{0}, ClockAnchor: current})
	require.NoError(t, err)
	backend.put(binding.shardKey(0), page)
	backend.put(binding.manifestKey(), manifest)
	backend.batchWriteErr = errors.New("temporary normalization failure")

	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))
	assert.False(t, binding.corrupt.Load())
	assert.False(t, state.manifestDirty, "an anchored checkpoint needs only a shard normalization retry")
	assert.NotEqual(t, state.generation[0], state.persisted[0])
	assert.Equal(t, page, backend.value(binding.shardKey(0)))

	backend.batchWriteErr = nil
	current = current.Add(logCheckpointFlushInterval)
	state.BeginBatch()
	count, err := consumeDeduplicatedLogs(t.Context(), consumertest.NewErr(errors.New("empty poll must not call the consumer")), state, plog.NewLogs())
	require.NoError(t, err)
	assert.Zero(t, count)
	assert.Equal(t, state.generation[0], state.persisted[0])
	var normalized logDedupCheckpointShard
	require.NoError(t, json.Unmarshal(checkpointTestReferencedShard(t, backend, binding, 0), &normalized))
	require.Len(t, normalized.Entries, 1)
	assert.Equal(t, normalizedAt, normalized.Entries[0].SeenAt)
	registry.Close(t.Context())
}

func TestEmptyPollingLogBatchDoesNotWriteCleanCheckpoint(t *testing.T) {
	backend := newCheckpointTestBackend()
	current := time.Unix(1_900_000_000, 0).UTC()
	state := newLogDeduplicator()
	state.now = func() time.Time { return current }
	registry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	registry.enableLogDedup("fmc", "clean-empty-log-target", state, logCheckpointRetention{})
	require.NoError(t, registry.Start(t.Context(), checkpointHost(backend)))

	current = current.Add(logCheckpointFlushInterval)
	state.BeginBatch()
	count, err := consumeDeduplicatedLogs(t.Context(), consumertest.NewErr(errors.New("empty poll must not call the consumer")), state, plog.NewLogs())
	require.NoError(t, err)
	assert.Zero(t, count)
	batches, operations, _, _ := backend.writeStats()
	assert.Zero(t, batches)
	assert.Zero(t, operations)
	registry.Close(t.Context())
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

func TestCounterRestoreDropsTTLExpiredCheckpointEntries(t *testing.T) {
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
	shardKey := checkpointTestReferencedShardKey(t, backend, first.checkpoint, 0)
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
	assert.NotEmpty(t, backend.value(shardKey), "the expired page may remain physically retained in the bounded slot namespace")
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

func TestLogDedupRestoreDropsTTLExpiredCheckpointEntries(t *testing.T) {
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
	shardKey := checkpointTestReferencedShardKey(t, backend, first.checkpoint, 0)
	require.NotEmpty(t, backend.value(shardKey))
	firstRegistry.Close(t.Context())

	restartNow := seenAt.Add(2 * retention.ttl)
	restarted := newLogDeduplicator()
	restarted.now = func() time.Time { return restartNow }
	restartedRegistry := newCheckpointTestRegistry(checkpointSignalLogs, zap.NewNop())
	restartedRegistry.enableLogDedup("ise", "ttl-target", restarted, retention)
	require.NoError(t, restartedRegistry.Start(t.Context(), checkpointHost(backend)))
	assert.Empty(t, restarted.seen)
	assert.NotEmpty(t, backend.value(shardKey), "the expired page may remain physically retained in the bounded slot namespace")
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
			manifest, err := json.Marshal(checkpointManifest{Version: checkpointFormatVersion, Active: []uint16{0}, ClockAnchor: now})
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
				assert.Equal(t, 2, batches, "legacy restore must stage and publish the normalized observation")

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
				assert.Equal(t, 4, batches, "the second restart must not need another normalization write")
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
			manifest, err := json.Marshal(checkpointManifest{Version: checkpointFormatVersion, Active: []uint16{0}, Metadata: metadataBytes, ClockAnchor: now})
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
				assert.Equal(t, 2, batches, "legacy restore must stage and publish normalized metadata and series")

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
				assert.Equal(t, 4, batches, "the second restart must not need another normalization write")
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
