// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
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

func TestSharedGNMIRequiredUnsupportedSingletonWaitsForFingerprintRetry(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		return status.Error(codes.InvalidArgument, "required path is unsupported")
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	targetConfig := runtimeTestTarget(
		endpoint,
		material.caFile,
		gnmiModeStream,
		runtimeTestMapping("required/unsupported", "runtime.required.unsupported"),
	).withDefaults()
	cache, err := internalgnmi.NewCache(100)
	require.NoError(t, err)
	target, err := newSharedGNMITargetRuntime(targetConfig, cache)
	require.NoError(t, err)
	require.Len(t, target.streams, 1)
	target.streams[0].Required = true
	clock := newRuntimeTestNegativeClock(time.Unix(1_700_000_000, 0))
	target.now = clock.Now
	target.after = clock.After
	target.sessionMu.Lock()
	target.fingerprint = "pid-a\x00version-a\x00models-a"
	target.sessionMu.Unlock()

	receiver := &sharedGNMIReceiver{
		settings:          receivertest.NewNopSettings(componentmetadata.Type),
		consumer:          consumertest.NewNop(),
		maxDatapoints:     10,
		maxCachedSeries:   100,
		host:              componenttest.NewNopHost(),
		notificationSlots: make(chan struct{}, sharedGNMIMaxConcurrentDelivery),
		responseAdmission: newGNMIResponseAdmission(),
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	conn, err := receiver.dialTarget(ctx, target.config)
	require.NoError(t, err)
	defer conn.Close()
	type serveResult struct {
		terminal bool
		err      error
	}
	resultCh := make(chan serveResult, 1)
	go func() {
		terminal, serveErr := receiver.serveTargetStreams(ctx, target, gnmipb.NewGNMIClient(conn))
		resultCh <- serveResult{terminal: terminal, err: serveErr}
	}()

	select {
	case delay := <-clock.delays:
		assert.Equal(t, time.Minute, delay)
	case result := <-resultCh:
		t.Fatalf("required unsupported stream returned before its negative retry window: terminal=%v err=%v", result.terminal, result.err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for required-path negative retry timer")
	}
	path := target.streams[0].Paths[0]
	target.stateMu.RLock()
	entry, isolated := target.isolate[sharedGNMIPathKey(path)]
	target.stateMu.RUnlock()
	require.True(t, isolated)
	assert.Equal(t, "pid-a\x00version-a\x00models-a", entry.fingerprint)
	assert.Equal(t, 1, entry.failures)
	assert.Equal(t, clock.Now().Add(time.Minute), entry.retryAt)
	assert.False(t, target.sessionUp.Load(), "an unsupported required stream must not make the target available")
	assert.False(t, target.profileStopped(sharedGNMIStreamSuppressionKey(target.streams[0].sharedGNMIStream)))

	clock.Advance(time.Minute)
	clock.Fire()
	select {
	case result := <-resultCh:
		assert.False(t, result.terminal)
		var retryErr *sharedGNMINegativeRetryError
		require.ErrorAs(t, result.err, &retryErr)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for required-path negative retry")
	}
	assert.Equal(t, 1, fake.snapshot().subscribeCalls)
}

func TestSharedGNMIPreviouslyIsolatedRequiredPathWaitsForSameCircuitBreaker(t *testing.T) {
	target := runtimeTestNegativeTarget(t)
	require.Len(t, target.streams, 1)
	target.streams[0].Required = true
	clock := newRuntimeTestNegativeClock(time.Unix(1_700_000_000, 0))
	target.now = clock.Now
	target.after = clock.After
	target.sessionMu.Lock()
	target.fingerprint = "pid-a\x00version-a\x00models-a"
	target.sessionMu.Unlock()
	target.isolatePath(target.streams[0].Paths[0])

	receiver := &sharedGNMIReceiver{
		settings:          receivertest.NewNopSettings(componentmetadata.Type),
		consumer:          consumertest.NewNop(),
		maxDatapoints:     10,
		maxCachedSeries:   100,
		host:              componenttest.NewNopHost(),
		notificationSlots: make(chan struct{}, sharedGNMIMaxConcurrentDelivery),
		responseAdmission: newGNMIResponseAdmission(),
	}
	type serveResult struct {
		terminal bool
		err      error
	}
	resultCh := make(chan serveResult, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	go func() {
		terminal, serveErr := receiver.serveTargetStreams(ctx, target, nil)
		resultCh <- serveResult{terminal: terminal, err: serveErr}
	}()

	select {
	case delay := <-clock.delays:
		assert.Equal(t, time.Minute, delay)
	case result := <-resultCh:
		t.Fatalf("pre-isolated required stream bypassed its circuit breaker: terminal=%v err=%v", result.terminal, result.err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for pre-isolated required-path retry timer")
	}
	assert.False(t, target.sessionUp.Load())
	clock.Advance(time.Minute)
	clock.Fire()
	select {
	case result := <-resultCh:
		assert.False(t, result.terminal)
		var retryErr *sharedGNMINegativeRetryError
		require.ErrorAs(t, result.err, &retryErr)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for pre-isolated required-path retry")
	}
}

func TestSharedGNMIOnceProbeDeadlineIncludesCleanEOF(t *testing.T) {
	streamCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	watchdog, err := newSharedGNMISyncWatchdog("once-probe", 40*time.Millisecond, cancel)
	require.NoError(t, err)
	stream := &singleUpdateGNMIClientStream{
		ctx: streamCtx,
		response: &gnmipb.SubscribeResponse{
			Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
		},
	}

	err = receiveSharedGNMIProbeOnceWithWatchdog(stream, nil, watchdog)
	var timeoutErr *sharedGNMISyncTimeoutError
	require.ErrorAs(t, err, &timeoutErr)
	assert.Equal(t, "once-probe", timeoutErr.profile)
	assert.Equal(t, 40*time.Millisecond, timeoutErr.timeout)
	assert.ErrorIs(t, streamCtx.Err(), context.Canceled)
}

func TestSharedGNMIRuntimeOnceDeadlineIncludesCleanEOF(t *testing.T) {
	target := runtimeTestNegativeTarget(t)
	stream := target.streams[0]
	stream.Mode = gnmiModeOnce
	stream.Required = true
	stream.SyncTimeout = 40 * time.Millisecond
	streamCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	clientStream := &singleUpdateGNMIClientStream{
		ctx: streamCtx,
		response: &gnmipb.SubscribeResponse{
			Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
		},
	}
	receiver := &sharedGNMIReceiver{responseAdmission: newGNMIResponseAdmission()}

	err := receiver.receiveOnceToCompletion(streamCtx, target, stream, clientStream, cancel)
	var timeoutErr *sharedGNMISyncTimeoutError
	require.ErrorAs(t, err, &timeoutErr)
	assert.Equal(t, stream.Profile, timeoutErr.profile)
	assert.False(t, target.sessionUp.Load(), "sync without ONCE EOF must not satisfy required readiness")
}

func TestConfigureDiscoveredSessionReplacesFingerprintScopedRetainedState(t *testing.T) {
	cache, err := internalgnmi.NewCacheWithLimits(7, 1024*1024)
	require.NoError(t, err)
	budget := newSharedGNMIAuxiliaryBudgetWithLimits(13, 2*1024*1024)
	targetConfig := runtimeTestTarget(
		"127.0.0.1:57400",
		"unused-ca.pem",
		gnmiModeStream,
		runtimeTestMapping("system/value", "runtime.fingerprint.value"),
	).withDefaults()
	target, err := newSharedGNMITargetRuntimeWithBudget(targetConfig, cache, budget)
	require.NoError(t, err)

	oldTimestamp := time.Unix(1_700_000_100, 0)
	oldPoint := internalgnmi.MappedPoint{
		Source: internalgnmi.Series{
			Target:   target.config.Name,
			Origin:   runtimeTestOrigin,
			Elements: []internalgnmi.PathElem{{Name: "system"}},
			Leaf:     "value",
		},
		Metric:     internalgnmi.MetricMetadata{Name: "runtime.fingerprint.value", Description: "Fingerprint value.", Unit: "1"},
		GaugeType:  internalgnmi.GaugeInt,
		MetricType: internalgnmi.MetricGauge,
		IntValue:   1,
		Timestamp:  oldTimestamp,
	}
	_, err = cache.Apply(internalgnmi.CacheNotification{
		Prefix: oldPoint.Source.Path(), Timestamp: oldTimestamp, Updates: []internalgnmi.MappedPoint{oldPoint},
	})
	require.NoError(t, err)
	target.sessionMu.Lock()
	target.fingerprint = "old-device\x00old-release\x00old-capabilities"
	target.sessionMu.Unlock()
	target.stateMu.Lock()
	target.isolate["old-path"] = sharedGNMINegativeEntry{fingerprint: target.fingerprint, failures: 2, retryAt: time.Now().Add(time.Hour)}
	target.stopped["old-profile"] = sharedGNMINegativeEntry{fingerprint: target.fingerprint, failures: 2, retryAt: time.Now().Add(time.Hour)}
	target.stateMu.Unlock()
	target.nxMu.Lock()
	target.nxSensors = map[string]nxSensorState{"old-sensor": {description: "old"}}
	target.nxMu.Unlock()
	target.presenceMu.Lock()
	target.opticalSources = map[string]string{"old-source": "old-presence"}
	target.presenceCounts = map[string]int{"old-presence": 1}
	target.presenceAttrs = map[string]map[string]string{"old-presence": {"network.interface.name": "Ethernet1/1"}}
	target.presenceMu.Unlock()
	budget.mu.Lock()
	budget.used = 4
	budget.usedBytes = 4096
	budget.mu.Unlock()
	target.sessionUp.Store(true)

	identity := sharedGNMIDeviceIdentity{
		OSFamily: gnmiPlatformIOSXR, ModelIdentifier: "XRv9000", SoftwareVersion: "25.2.21",
	}
	product := gnmiCatalogProductDefinition{ID: "runtime-fingerprint-product"}
	family := gnmiCatalogProductFamilyDefinition{ID: "ios_xr", Platform: gnmiPlatformIOSXR, MaxStreams: 4}
	badCapabilities := &gnmipb.CapabilityResponse{}
	require.Error(t, target.configureDiscoveredSession(identity, product, family, badCapabilities))
	assert.Same(t, cache, target.cache, "failed session planning must preserve the complete old retained-state generation")
	assert.Len(t, target.cache.Snapshot(), 1)
	assert.Len(t, target.nxSensors, 1)
	assert.Len(t, target.opticalSources, 1)
	assert.Equal(t, sharedGNMIAuxiliaryUsage{count: 4, bytes: 4096}, auxiliaryTestBudgetUsage(target.nxBudget))

	capabilities := runtimeTestIOSXRCapabilities(gnmipb.Encoding_JSON_IETF)
	require.NoError(t, target.configureDiscoveredSession(identity, product, family, capabilities))
	replacementCache := target.cache
	replacementBudget := target.nxBudget
	assert.NotSame(t, cache, replacementCache)
	assert.Equal(t, cache.Capacity(), replacementCache.Capacity())
	assert.Equal(t, cache.RetainedByteCapacity(), replacementCache.RetainedByteCapacity())
	assert.Empty(t, replacementCache.Snapshot())
	assert.Len(t, cache.Snapshot(), 1, "publishing the new generation must not mutate an old cache still held by a completed session")
	assert.NotSame(t, budget, replacementBudget)
	assert.Equal(t, budget.maximum, replacementBudget.maximum)
	assert.Equal(t, budget.maximumBytes, replacementBudget.maximumBytes)
	assert.Equal(t, sharedGNMIAuxiliaryUsage{}, auxiliaryTestBudgetUsage(replacementBudget))
	assert.Empty(t, target.isolate)
	assert.Empty(t, target.stopped)
	assert.Empty(t, target.nxSensors)
	assert.Empty(t, target.opticalSources)
	assert.Empty(t, target.presenceCounts)
	assert.Empty(t, target.presenceAttrs)
	assert.False(t, target.sessionUp.Load())

	newPoint := oldPoint
	newPoint.IntValue = 2
	newPoint.Timestamp = oldTimestamp.Add(-time.Hour)
	result, err := replacementCache.Apply(internalgnmi.CacheNotification{
		Prefix: newPoint.Source.Path(), Timestamp: newPoint.Timestamp, Updates: []internalgnmi.MappedPoint{newPoint},
	})
	require.NoError(t, err)
	assert.Len(t, result.Applied, 1, "an old device timestamp must not reject the replacement device's lower timestamp")
	assert.Zero(t, result.OutOfOrder)

	require.NoError(t, target.configureDiscoveredSession(identity, product, family, capabilities))
	assert.Same(t, replacementCache, target.cache, "ordinary reconnects with the same fingerprint must retain cache continuity")
	assert.Same(t, replacementBudget, target.nxBudget)
	assert.Len(t, target.cache.Snapshot(), 1)
}
