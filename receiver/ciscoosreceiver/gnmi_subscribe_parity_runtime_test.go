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
				{Path: runtimeTestProtoPath(t, "system/state/oper-status"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "UP"}}},
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
				Path: runtimeTestProtoPath(t, "system/state"),
				Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{
					"value": 17,
					"ignored": {"leaf": 2}
				}`)}},
			}},
		}}}); err != nil {
			return err
		}
		return stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}})
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce,
		runtimeTestMapping("system/state/value", "runtime.aggregate.value"),
	)
	target.CustomSubscriptions[0].AllowAggregation = true
	target.CustomSubscriptions[0].Paths = []GNMISubscriptionPathConfig{{Path: "system/state"}}
	sink := &consumertest.MetricsSink{}
	receiver := runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 10, sink)
	runtimeTestWaitDone(t, receiver)

	assert.Equal(t, 1, runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.aggregate.value"))
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
	require.NoError(t, receiver.processNotification(t.Context(), target, updatesOnly, notification("updates/value", 1)))
	require.NoError(t, receiver.processNotification(t.Context(), target, retained, notification("retained/value", 2)))
	require.Len(t, target.cache.Snapshot(), 2)
	batchesBeforeReset := len(sink.AllMetrics())

	require.NoError(t, receiver.resetUpdatesOnlyOwners(t.Context(), target))
	cacheSnapshot := target.cache.Snapshot()
	require.Len(t, cacheSnapshot, 1)
	assert.Equal(t, "runtime.retained.value", cacheSnapshot[0].Metric.Name)
	assert.Len(t, sink.AllMetrics(), batchesBeforeReset, "reconnect owner reset must not emit deletion or presence signals")
}
