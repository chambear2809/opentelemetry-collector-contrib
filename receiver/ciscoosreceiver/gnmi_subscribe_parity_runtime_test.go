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
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestSharedGNMIScalarJSONIETFUsesMandatoryIdentityGet(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.capabilities = func(context.Context) (*gnmipb.CapabilityResponse, error) {
		return &gnmipb.CapabilityResponse{
			SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON_IETF},
			SupportedModels:    runtimeTestASRRequiredModels(),
		}, nil
	}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		require.Equal(t, gnmipb.Encoding_JSON_IETF, request.GetSubscribe().GetEncoding())
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
			Timestamp: time.Now().UnixNano(), Prefix: &gnmipb.Path{Origin: runtimeTestOrigin},
			Update: []*gnmipb.Update{
				{Path: runtimeTestProtoPath(t, "system/state/count"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{UintVal: 9}}},
				{Path: runtimeTestProtoPath(t, "system/state/enabled"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{BoolVal: true}}},
				{Path: runtimeTestProtoPath(t, "system/state/oper-status"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: 1}}},
			},
		}}}); err != nil {
			return err
		}
		return stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}})
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(
		endpoint,
		material.caFile,
		gnmiModeOnce,
		runtimeTestMapping("system/state/count", "runtime.proto.count"),
		runtimeTestMapping("system/state/enabled", "runtime.proto.enabled"),
		runtimeTestMapping("system/state/oper-status", "runtime.proto.status"),
	)
	target.EncodingPreference = []string{"json_ietf"}
	sink := &consumertest.MetricsSink{}
	receiver := runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 10, sink)
	runtimeTestWaitDone(t, receiver)

	snapshot := fake.snapshot()
	assert.Equal(t, 1, snapshot.capabilitiesCalls)
	assert.Zero(t, snapshot.identitySubscribeCalls)
	assert.Equal(t, 1, snapshot.subscribeCalls)
	assert.Equal(t, 1, snapshot.getCalls)
	assert.Zero(t, snapshot.setCalls)
	assert.Equal(t, 1, runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.proto.count"))
	assert.Equal(t, 1, runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.proto.enabled"))
	assert.Equal(t, 1, runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.proto.status"))
}

func TestSharedGNMIOptionRejectionRunsOneBaselineAndStopsOnlyThatStream(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		paths := runtimeTestSubscribedPaths(request)
		if runtimeTestContains(paths, "options/value") {
			if request.GetSubscribe().GetUpdatesOnly() {
				return status.Error(codes.InvalidArgument, "updates_only is not supported")
			}
			// The diagnostic probe intentionally discards this update. A successful
			// baseline must stop the configured stream instead of downgrading it.
			if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
				Timestamp: time.Now().UnixNano(), Prefix: &gnmipb.Path{Origin: runtimeTestOrigin},
				Update: []*gnmipb.Update{{
					Path: runtimeTestProtoPath(t, "options/value"),
					Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: 99}},
				}},
			}}}); err != nil {
				return err
			}
			return stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}})
		}
		if !runtimeTestContains(paths, "sibling/value") {
			return status.Error(codes.Internal, "unexpected subscription path")
		}
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
			Timestamp: time.Now().UnixNano(), Prefix: &gnmipb.Path{Origin: runtimeTestOrigin},
			Update: []*gnmipb.Update{{
				Path: runtimeTestProtoPath(t, "sibling/value"),
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: 7}},
			}},
		}}}); err != nil {
			return err
		}
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}}); err != nil {
			return err
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}
	endpoint, listener := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeStream, runtimeTestMapping("options/value", "runtime.options.value"))
	target.MaxStreams = 2
	target.CustomSubscriptions[0].Name = "runtime-options"
	target.CustomSubscriptions[0].Required = true
	target.CustomSubscriptions[0].UpdatesOnly = true
	target.CustomSubscriptions = append(target.CustomSubscriptions, GNMICustomSubscriptionConfig{
		Name: "runtime-sibling", Origin: runtimeTestOrigin, Mode: gnmiModeStream,
		SampleInterval: 10 * time.Millisecond,
		Mappings:       []GNMIMetricMappingConfig{runtimeTestMapping("sibling/value", "runtime.sibling.value")},
	})
	sink := &consumertest.MetricsSink{}
	receiver := runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 10, sink)

	require.Eventually(t, func() bool {
		return receiver.targets[0].profileStopped("runtime-options") &&
			runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.sibling.value") == 1
	}, 5*time.Second, 10*time.Millisecond)
	assert.False(t, receiver.targets[0].profileStopped("runtime-sibling"))
	assert.Zero(t, runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.options.value"), "diagnostic data must be discarded")
	assert.Equal(t, int64(1), listener.accepts.Load(), "configured and diagnostic Subscribe RPCs reuse the verified connection")

	snapshot := fake.snapshot()
	assert.Equal(t, 3, snapshot.subscribeCalls, "configured rejection, one baseline diagnostic, and the sibling stream")
	assert.Zero(t, snapshot.identitySubscribeCalls)
	assert.Equal(t, 1, snapshot.getCalls)
	assert.Zero(t, snapshot.setCalls)
	configuredAttempts := 0
	baselineAttempts := 0
	for _, request := range snapshot.requests {
		if !runtimeTestContains(runtimeTestSubscribedPaths(request), "options/value") {
			continue
		}
		if request.GetSubscribe().GetUpdatesOnly() {
			configuredAttempts++
		} else {
			baselineAttempts++
		}
	}
	assert.Equal(t, 1, configuredAttempts, "the rejected request must never be silently retried with weaker options")
	assert.Equal(t, 1, baselineAttempts)
}

func TestSharedGNMIAggregatedJSONSubtreeUsesExplicitDescendantMapping(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		require.True(t, request.GetSubscribe().GetAllowAggregation())
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
			Timestamp: time.Now().UnixNano(), Prefix: &gnmipb.Path{Origin: runtimeTestOrigin},
			Update: []*gnmipb.Update{{
				Path: runtimeTestProtoPath(t, "neighbors/neighbor"),
				Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`[
					{"routing_instance":"red","state":{"value":17}},
					{"routing_instance":"blue","state":{"value":23}}
				]`)}},
			}},
		}}}); err != nil {
			return err
		}
		return stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}})
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	mapping := runtimeTestMapping("neighbors/neighbor/state/value", "runtime.aggregate.value")
	mapping.PathKeys = map[string]string{"neighbor.routing_instance": "network.vrf.name"}
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce, mapping)
	target.CustomSubscriptions[0].AllowAggregation = true
	target.CustomSubscriptions[0].Paths = []GNMISubscriptionPathConfig{{Path: "neighbors/neighbor"}}
	sink := &consumertest.MetricsSink{}
	receiver := runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 10, sink)
	runtimeTestWaitDone(t, receiver)

	assert.Equal(t, 2, runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.aggregate.value"))
	snapshot := fake.snapshot()
	assert.Zero(t, snapshot.identitySubscribeCalls)
	assert.Equal(t, 1, snapshot.getCalls)
	assert.Zero(t, snapshot.setCalls)
}

func TestSharedGNMIUpdatesOnlyOwnerResetIsSilentAndStreamScoped(t *testing.T) {
	targetConfig := runtimeTestTarget(
		"127.0.0.1:9339",
		"",
		gnmiModeStream,
		runtimeTestMapping("updates/value", "runtime.updates_only.value"),
	)
	targetConfig.MaxStreams = 2
	targetConfig.CustomSubscriptions[0].Name = "updates-only"
	targetConfig.CustomSubscriptions[0].UpdatesOnly = true
	targetConfig.CustomSubscriptions = append(targetConfig.CustomSubscriptions, GNMICustomSubscriptionConfig{
		Name: "retained", Origin: runtimeTestOrigin, Mode: gnmiModeStream,
		SampleInterval: 10 * time.Millisecond,
		Mappings:       []GNMIMetricMappingConfig{runtimeTestMapping("retained/value", "runtime.retained.value")},
	})
	config := createDefaultConfig().(*Config)
	config.GNMI = GNMIConfig{MaxDatapointsPerChunk: 10, MaxCachedSeries: 100, Targets: []GNMITargetConfig{targetConfig}}
	sink := &consumertest.MetricsSink{}
	created, err := newSharedGNMIReceiver(receivertest.NewNopSettings(componentmetadata.Type), config, sink)
	require.NoError(t, err)
	receiver := created.(*sharedGNMIReceiver)
	t.Cleanup(receiver.telemetry.shutdown)
	require.Len(t, receiver.targets, 1)
	target := receiver.targets[0]

	streams := make(map[string]sharedGNMIRuntimeStream, len(target.streams))
	for _, stream := range target.streams {
		streams[stream.Profile] = stream
	}
	updatesOnly, ok := streams["updates-only"]
	require.True(t, ok)
	retained, ok := streams["retained"]
	require.True(t, ok)
	require.NotEmpty(t, updatesOnly.OwnerID)
	require.NotEqual(t, updatesOnly.OwnerID, retained.OwnerID)

	notification := func(path string, value int64) *gnmipb.Notification {
		return &gnmipb.Notification{
			Timestamp: time.Now().UnixNano(),
			Prefix:    &gnmipb.Path{Origin: runtimeTestOrigin},
			Update: []*gnmipb.Update{{
				Path: runtimeTestProtoPath(t, path),
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: value}},
			}},
		}
	}
	splitUpdatesOnly := sharedGNMIBisectedRuntimeStream(updatesOnly, updatesOnly.Paths)
	target.registerPhysicalCacheOwner(splitUpdatesOnly)
	require.NotEqual(t, updatesOnly.OwnerID, sharedGNMICacheOwnerID(splitUpdatesOnly))
	require.NoError(t, receiver.processNotification(t.Context(), target, splitUpdatesOnly, notification("updates/value", 1)))
	require.NoError(t, receiver.processNotification(t.Context(), target, retained, notification("retained/value", 2)))
	require.Len(t, target.cache.Snapshot(), 2)
	batchesBeforeReset := len(sink.AllMetrics())

	require.NoError(t, receiver.resetUpdatesOnlyOwners(t.Context(), target))
	cacheSnapshot := target.cache.Snapshot()
	require.Len(t, cacheSnapshot, 1)
	assert.Equal(t, "runtime.retained.value", cacheSnapshot[0].Metric.Name)
	assert.Equal(t, []string{updatesOnly.OwnerID}, target.cacheOwnerIDsForLogicalStream(updatesOnly.OwnerID),
		"a completed reconnect reset must release remembered physical scopes")
	assert.Len(t, sink.AllMetrics(), batchesBeforeReset, "reconnect owner reset must not emit deletion or presence signals")
}

func TestSharedGNMICacheTopologyTransitionsRemoveObsoleteOwners(t *testing.T) {
	targetConfig := runtimeTestTarget(
		"127.0.0.1:9339",
		"",
		gnmiModeStream,
		runtimeTestMapping("topology/first/value", "runtime.topology.first"),
		runtimeTestMapping("topology/second/value", "runtime.topology.second"),
	)
	config := createDefaultConfig().(*Config)
	config.GNMI = GNMIConfig{MaxDatapointsPerChunk: 10, MaxCachedSeries: 100, Targets: []GNMITargetConfig{targetConfig}}
	created, err := newSharedGNMIReceiver(
		receivertest.NewNopSettings(componentmetadata.Type),
		config,
		consumertest.NewNop(),
	)
	require.NoError(t, err)
	receiver := created.(*sharedGNMIReceiver)
	t.Cleanup(receiver.telemetry.shutdown)
	require.Len(t, receiver.targets, 1)
	target := receiver.targets[0]
	require.Len(t, target.streams, 1)
	combined := target.streams[0]
	require.Len(t, combined.Paths, 2)

	timestamp := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	notification := func(paths []sharedGNMIPath, offset time.Duration) *gnmipb.Notification {
		updates := make([]*gnmipb.Update, 0, len(paths))
		for index, path := range paths {
			updates = append(updates, &gnmipb.Update{
				Path: runtimeTestProtoPath(t, path.Path),
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: int64(index + 1)}},
			})
		}
		return &gnmipb.Notification{
			Timestamp: timestamp.Add(offset).UnixNano(),
			Prefix:    &gnmipb.Path{Origin: runtimeTestOrigin},
			Atomic:    true,
			Update:    updates,
		}
	}
	metricNames := func() map[string]struct{} {
		names := map[string]struct{}{}
		for _, point := range target.cache.Snapshot() {
			names[point.Metric.Name] = struct{}{}
		}
		return names
	}

	// Session 1 accepts the configured combined subscription.
	require.NoError(t, receiver.processNotification(t.Context(), target, combined, notification(combined.Paths, 0)))
	require.NoError(t, receiver.reconcileCacheTopology(t.Context(), target, combined))
	assert.Equal(t, map[string]struct{}{
		"runtime.topology.first": {}, "runtime.topology.second": {},
	}, metricNames())

	// Session 2 rejects the combined request and accepts two physical groups.
	// The first group replaces its series, but the old logical owner is retained
	// until the sibling group also proves that the new topology is accepted.
	target.beginCacheTopologySession()
	children := sharedGNMIBisectedRuntimeStreams(combined, [][]sharedGNMIPath{{combined.Paths[0]}, {combined.Paths[1]}})
	for index := range children {
		children[index].responseSelectors, err = sharedGNMIResponseSelectors(target.config.Name, children[index].Paths)
		require.NoError(t, err)
	}
	require.NoError(t, receiver.processNotification(t.Context(), target, children[0], notification(children[0].Paths, time.Second)))
	require.NoError(t, receiver.reconcileCacheTopology(t.Context(), target, children[0]))
	assert.Len(t, target.cache.Snapshot(), 2, "an incomplete candidate topology must preserve the prior cache")
	require.NoError(t, receiver.reconcileCacheTopology(t.Context(), target, children[1]))
	assert.Equal(t, map[string]struct{}{metricNameForTopologyPath(children[0].Paths[0].Path): {}}, metricNames(),
		"combined-to-split transition must remove disappeared logical-owner state")
	assert.Equal(t, 1, target.cache.Usage().AtomicBaselines)
	assert.Equal(t, 1, target.cache.Usage().Tombstones)

	// Populate both accepted child owners, then let session 3 accept the original
	// combined request with only the first series present. Transitioning back must
	// remove the stale state retained under the other physical child.
	require.NoError(t, receiver.processNotification(t.Context(), target, children[1], notification(children[1].Paths, 2*time.Second)))
	require.NoError(t, receiver.reconcileCacheTopology(t.Context(), target, children[1]))
	require.Len(t, target.cache.Snapshot(), 2)
	target.beginCacheTopologySession()
	require.NoError(t, receiver.processNotification(t.Context(), target, combined, notification(children[0].Paths, 3*time.Second)))
	require.NoError(t, receiver.reconcileCacheTopology(t.Context(), target, combined))
	assert.Equal(t, map[string]struct{}{metricNameForTopologyPath(children[0].Paths[0].Path): {}}, metricNames(),
		"split-to-combined transition must remove disappeared physical-owner state")
	assert.Equal(t, 1, target.cache.Usage().AtomicBaselines)
	assert.Equal(t, 1, target.cache.Usage().Tombstones)

	// A resolution with one valid strict-subset group is also a topology change:
	// otherwise state belonging only to its rejected sibling remains under the
	// logical owner forever.
	combinedNonAtomic := notification(combined.Paths, 4*time.Second)
	combinedNonAtomic.Atomic = false
	require.NoError(t, receiver.processNotification(t.Context(), target, combined, combinedNonAtomic))
	require.NoError(t, receiver.reconcileCacheTopology(t.Context(), target, combined))
	require.Len(t, target.cache.Snapshot(), 2)
	target.beginCacheTopologySession()
	subset := sharedGNMIResolvedRuntimeStreams(combined, [][]sharedGNMIPath{{combined.Paths[0]}})
	require.Len(t, subset, 1)
	subset[0].responseSelectors, err = sharedGNMIResponseSelectors(target.config.Name, subset[0].Paths)
	require.NoError(t, err)
	subsetNonAtomic := notification(subset[0].Paths, 5*time.Second)
	subsetNonAtomic.Atomic = false
	require.NoError(t, receiver.processNotification(t.Context(), target, subset[0], subsetNonAtomic))
	require.NoError(t, receiver.reconcileCacheTopology(t.Context(), target, subset[0]))
	assert.Equal(t, map[string]struct{}{metricNameForTopologyPath(subset[0].Paths[0].Path): {}}, metricNames(),
		"single-subset transition must remove state from the rejected logical-owner path")
	assert.Zero(t, target.cache.Usage().AtomicBaselines)
	assert.Zero(t, target.cache.Usage().Tombstones)
}

func metricNameForTopologyPath(path string) string {
	if path == "topology/first/value" {
		return "runtime.topology.first"
	}
	return "runtime.topology.second"
}
