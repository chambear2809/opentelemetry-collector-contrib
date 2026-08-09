// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"sync"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestSharedGNMINegativeCacheBackoffAndFingerprintScope(t *testing.T) {
	runtime := runtimeTestNegativeTarget(t)
	clock := newRuntimeTestNegativeClock(time.Unix(1_700_000_000, 0))
	runtime.now = clock.Now
	runtime.sessionMu.Lock()
	runtime.fingerprint = "pid-a\x00version-a\x00models-a"
	runtime.sessionMu.Unlock()
	path := sharedGNMIPath{Origin: runtimeTestOrigin, Path: "bad/value"}

	for attempt, wantDelay := range []time.Duration{
		time.Minute,
		2 * time.Minute,
		4 * time.Minute,
		8 * time.Minute,
		15 * time.Minute,
		15 * time.Minute,
	} {
		runtime.isolatePath(path)
		assert.True(t, runtime.pathIsolated(path), "attempt %d", attempt+1)
		runtime.stateMu.RLock()
		entry := runtime.isolate[sharedGNMIPathKey(path)]
		runtime.stateMu.RUnlock()
		assert.Equal(t, attempt+1, entry.failures)
		assert.Equal(t, wantDelay, entry.retryAt.Sub(clock.Now()))
		clock.Advance(wantDelay - time.Nanosecond)
		assert.True(t, runtime.pathIsolated(path), "suppression must remain active before retry_at")
		clock.Advance(time.Nanosecond)
		assert.False(t, runtime.pathIsolated(path), "suppression must expire exactly at retry_at")
	}

	runtime.stopProfile("runtime-custom")
	assert.True(t, runtime.profileStopped("runtime-custom"))
	runtime.sessionMu.Lock()
	runtime.fingerprint = "pid-b\x00version-b\x00models-b"
	runtime.sessionMu.Unlock()
	assert.False(t, runtime.pathIsolated(path), "a fingerprint change must invalidate path suppression immediately")
	assert.False(t, runtime.profileStopped("runtime-custom"), "a fingerprint change must invalidate profile suppression immediately")
}

func TestSharedGNMINegativeCacheExpiryTriggersSessionRetry(t *testing.T) {
	runtime := runtimeTestNegativeTarget(t)
	clock := newRuntimeTestNegativeClock(time.Unix(1_700_000_000, 0))
	runtime.now = clock.Now
	runtime.after = clock.After
	runtime.sessionMu.Lock()
	runtime.fingerprint = "pid-a\x00version-a\x00models-a"
	runtime.sessionMu.Unlock()
	runtime.stopProfile("runtime-custom")

	receiver := &sharedGNMIReceiver{
		settings:          receivertest.NewNopSettings(componentmetadata.Type),
		consumer:          consumertest.NewNop(),
		maxDatapoints:     10,
		maxCachedSeries:   100,
		host:              componenttest.NewNopHost(),
		notificationSlots: make(chan struct{}, sharedGNMIMaxConcurrentDelivery),
		responseAdmission: newGNMIResponseAdmission(),
	}
	type result struct {
		terminal bool
		err      error
	}
	resultCh := make(chan result, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		terminal, err := receiver.serveTargetStreams(ctx, runtime, nil)
		resultCh <- result{terminal: terminal, err: err}
	}()

	select {
	case delay := <-clock.delays:
		assert.Equal(t, time.Minute, delay)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for negative-cache retry timer")
	}
	clock.Advance(time.Minute)
	clock.Fire()
	select {
	case got := <-resultCh:
		assert.False(t, got.terminal)
		var retryErr *sharedGNMINegativeRetryError
		require.ErrorAs(t, got.err, &retryErr)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for negative-cache session retry")
	}
	assert.False(t, runtime.profileStopped("runtime-custom"))
}

func TestSharedGNMIPathSetMetadataPreservesWireDedupeAndAtomicity(t *testing.T) {
	definition := builtinGNMIProfileDefinition{
		Name: "atomic-test",
		Paths: []builtinGNMIPathDefinition{
			{ID: "first", Origin: "vendor", Path: "same/path", PathSetID: "set-a", VariantID: "openconfig"},
			{ID: "second", Origin: "vendor", Path: "same/path", PathSetID: "set-b", VariantID: "native"},
			{ID: "third", Origin: "vendor", Path: "related/path", PathSetID: "set-b", VariantID: "native"},
			{ID: "fourth", Origin: "vendor", Path: "independent/path", PathSetID: "set-c", VariantID: "native"},
		},
	}
	streams, err := buildBuiltinProfileStreams(gnmiPlatformNXOS, definition, GNMIProfileConfig{})
	require.NoError(t, err)
	require.Len(t, streams, 1)
	assert.Len(t, streams[0].Paths, 3, "duplicate origin/path values must remain one wire subscription")

	var same sharedGNMIPath
	for _, path := range streams[0].Paths {
		if path.Path == "same/path" {
			same = path
			break
		}
	}
	assert.Equal(t, "set-a", same.PathSetID)
	assert.Equal(t, "openconfig", same.VariantID)
	assert.ElementsMatch(t, []sharedGNMIPathSetVariant{
		{PathSetID: "set-a", VariantID: "openconfig"},
		{PathSetID: "set-b", VariantID: "native"},
	}, same.PathSetVariants)

	pathSets := sharedGNMIAtomicPathSets(streams[0].Paths)
	require.Len(t, pathSets, 2)
	for _, pathSet := range pathSets {
		if len(pathSet) == 1 {
			assert.Equal(t, "independent/path", pathSet[0].Path)
			continue
		}
		assert.Len(t, pathSet, 2, "a deduplicated path must connect every non-empty generated path set it belongs to")
	}
}

func TestSharedGNMIAtomicPathSetsNeverSplitCommonPathSetVariant(t *testing.T) {
	paths := []sharedGNMIPath{
		{Origin: "vendor", Path: "a", PathSetID: "atomic", VariantID: "openconfig"},
		{Origin: "vendor", Path: "b", PathSetID: "atomic", VariantID: "openconfig"},
		{Origin: "vendor", Path: "c"},
		{Origin: "vendor", Path: "d", PathSetVariants: []sharedGNMIPathSetVariant{{PathSetID: "atomic", VariantID: "native"}}},
	}
	sets := sharedGNMIAtomicPathSets(paths)
	require.Len(t, sets, 3)
	assert.Equal(t, []string{"a", "b"}, []string{sets[0][0].Path, sets[0][1].Path})
	assert.Equal(t, "c", sets[1][0].Path)
	assert.Equal(t, "d", sets[2][0].Path, "a sibling variant must not be fused into another variant's atomic unit")
}

func TestSharedGNMIBisectionProbesPathSetsAtomically(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		paths := runtimeTestSubscribedPaths(request)
		if runtimeTestContains(paths, "atomic/bad") {
			return status.Error(codes.InvalidArgument, "atomic set rejected")
		}
		return stream.Send(&gnmipb.SubscribeResponse{
			Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
		})
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce,
		runtimeTestMapping("atomic/bad", "runtime.atomic.bad"),
		runtimeTestMapping("atomic/companion", "runtime.atomic.companion"),
		runtimeTestMapping("independent/good", "runtime.atomic.good"),
	).withDefaults()
	cache, err := internalgnmi.NewCache(100)
	require.NoError(t, err)
	runtime, err := newSharedGNMITargetRuntime(target, cache)
	require.NoError(t, err)
	require.Len(t, runtime.streams, 1)
	for index := range runtime.streams[0].Paths {
		path := &runtime.streams[0].Paths[index]
		if path.Path == "atomic/bad" || path.Path == "atomic/companion" {
			path.PathSetID = "atomic-set"
			path.VariantID = "native"
		}
	}
	receiver := &sharedGNMIReceiver{
		settings:          receivertest.NewNopSettings(componentmetadata.Type),
		consumer:          consumertest.NewNop(),
		maxDatapoints:     10,
		maxCachedSeries:   100,
		host:              componenttest.NewNopHost(),
		notificationSlots: make(chan struct{}, sharedGNMIMaxConcurrentDelivery),
		responseAdmission: newGNMIResponseAdmission(),
	}
	conn, err := receiver.dialTarget(t.Context(), target)
	require.NoError(t, err)
	defer conn.Close()

	valid, err := receiver.resolveUnsupportedGNMIPaths(
		t.Context(),
		runtime,
		gnmipb.NewGNMIClient(conn),
		runtime.streams[0],
		gnmipb.Encoding_JSON_IETF,
	)
	require.NoError(t, err)
	require.Len(t, valid, 1)
	require.Len(t, valid[0], 1)
	assert.Equal(t, "independent/good", valid[0][0].Path)
	assert.True(t, runtime.pathIsolated(sharedGNMIPath{Origin: runtimeTestOrigin, Path: "atomic/bad"}))
	assert.True(t, runtime.pathIsolated(sharedGNMIPath{Origin: runtimeTestOrigin, Path: "atomic/companion"}))
	for _, request := range fake.snapshot().requests {
		paths := runtimeTestSubscribedPaths(request)
		assert.Equal(t,
			runtimeTestContains(paths, "atomic/bad"),
			runtimeTestContains(paths, "atomic/companion"),
			"no bisection probe may split a non-empty PathSetID",
		)
	}
}

func runtimeTestNegativeTarget(t *testing.T) *sharedGNMITargetRuntime {
	t.Helper()
	cache, err := internalgnmi.NewCache(100)
	require.NoError(t, err)
	target := runtimeTestTarget("127.0.0.1:1", "unused-ca.pem", gnmiModeStream, runtimeTestMapping("bad/value", "runtime.negative.value"))
	target = target.withDefaults()
	runtime, err := newSharedGNMITargetRuntime(target, cache)
	require.NoError(t, err)
	return runtime
}

type runtimeTestNegativeClock struct {
	mu     sync.Mutex
	now    time.Time
	wake   chan time.Time
	delays chan time.Duration
}

func newRuntimeTestNegativeClock(now time.Time) *runtimeTestNegativeClock {
	return &runtimeTestNegativeClock{
		now:    now,
		wake:   make(chan time.Time, 1),
		delays: make(chan time.Duration, 1),
	}
}

func (clock *runtimeTestNegativeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *runtimeTestNegativeClock) Advance(delta time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(delta)
	clock.mu.Unlock()
}

func (clock *runtimeTestNegativeClock) After(delay time.Duration) <-chan time.Time {
	clock.delays <- delay
	return clock.wake
}

func (clock *runtimeTestNegativeClock) Fire() {
	clock.wake <- clock.Now()
}
