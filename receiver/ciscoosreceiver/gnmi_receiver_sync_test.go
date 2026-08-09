// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"errors"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"google.golang.org/grpc"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestSharedGNMIRequiredStreamsGateAvailabilityUntilEverySync(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	updatesSent := make(chan string, 2)
	releaseA := make(chan struct{})
	releaseB := make(chan struct{})
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		paths := runtimeTestSubscribedPaths(request)
		if len(paths) != 1 {
			return errors.New("required-stream test expected one path per subscription")
		}
		path := paths[0]
		var release <-chan struct{}
		switch path {
		case "system/a":
			release = releaseA
		case "system/b":
			release = releaseB
		default:
			return errors.New("required-stream test received an unexpected path")
		}
		if err := runtimeTestSendScalarUpdate(stream, path, 1); err != nil {
			return err
		}
		updatesSent <- path
		select {
		case <-release:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}}); err != nil {
			return err
		}
		if err := runtimeTestSendScalarUpdate(stream, path, 2); err != nil {
			return err
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))

	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeStream, runtimeTestMapping("system/a", "runtime.required.a"))
	target.MaxStreams = 2
	target.SyncTimeout = 2 * time.Second
	target.CustomSubscriptions[0].Required = true
	target.CustomSubscriptions = append(target.CustomSubscriptions, GNMICustomSubscriptionConfig{
		Name:           "runtime-required-b",
		Origin:         runtimeTestOrigin,
		Mode:           gnmiModeStream,
		SampleInterval: 10 * time.Millisecond,
		PollInterval:   10 * time.Millisecond,
		Required:       true,
		Mappings:       []GNMIMetricMappingConfig{runtimeTestMapping("system/b", "runtime.required.b")},
	})
	sink := &consumertest.MetricsSink{}
	receiver := runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 10, sink)

	seen := map[string]bool{}
	for range 2 {
		select {
		case path := <-updatesSent:
			seen[path] = true
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for pre-sync updates")
		}
	}
	require.True(t, seen["system/a"])
	require.True(t, seen["system/b"])
	require.Eventually(t, func() bool {
		return runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.required.a") == 1 &&
			runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.required.b") == 1
	}, 3*time.Second, 10*time.Millisecond)
	assert.Zero(t, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.device.up"),
		"updates before sync_response must not report the target up")

	close(releaseA)
	require.Eventually(t, func() bool {
		return runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.required.a") == 2
	}, 3*time.Second, 10*time.Millisecond)
	assert.Zero(t, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.device.up"),
		"one required stream cannot make the target available while another remains unsynchronized")

	close(releaseB)
	require.Eventually(t, func() bool {
		values := runtimeTestIntGaugeValues(sink.AllMetrics(), "cisco.device.up")
		return runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.required.b") == 2 &&
			len(values) == 1 && values[0] == 1
	}, 3*time.Second, 10*time.Millisecond)
	assert.Equal(t, 2, fake.snapshot().subscribeCalls)
	require.NotNil(t, receiver)
}

func TestSharedGNMIRequiredSyncTimeoutRetriesWithoutStoppingProfile(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		<-stream.Context().Done()
		return stream.Context().Err()
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeStream, runtimeTestMapping("system/value", "runtime.timeout.value"))
	target.SyncTimeout = 2 * time.Second
	target.CustomSubscriptions[0].Required = true
	target = target.withDefaults()

	cache, err := internalgnmi.NewCache(100)
	require.NoError(t, err)
	runtime, err := newSharedGNMITargetRuntime(target, cache)
	require.NoError(t, err)
	require.Len(t, runtime.streams, 1)
	runtime.streams[0].SyncTimeout = 40 * time.Millisecond
	receiver := &sharedGNMIReceiver{
		settings:          receivertest.NewNopSettings(componentmetadata.Type),
		consumer:          consumertest.NewNop(),
		maxDatapoints:     10,
		maxCachedSeries:   100,
		host:              componenttest.NewNopHost(),
		notificationSlots: make(chan struct{}, sharedGNMIMaxConcurrentDelivery),
		responseAdmission: newGNMIResponseAdmission(),
	}

	for attempt := range 2 {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		conn, dialErr := receiver.dialTarget(ctx, runtime.config)
		require.NoError(t, dialErr)
		terminal, serveErr := receiver.serveTargetStreams(ctx, runtime, gnmipb.NewGNMIClient(conn))
		require.NoError(t, conn.Close())
		cancel()
		require.False(t, terminal)
		var timeoutErr *sharedGNMISyncTimeoutError
		require.ErrorAs(t, serveErr, &timeoutErr, "attempt %d", attempt+1)
		assert.False(t, runtime.profileStopped("runtime-custom"),
			"a required timeout must fail the session without permanently stopping its profile")
	}
	assert.Equal(t, 2, fake.snapshot().subscribeCalls,
		"the same required profile must be attempted again on the next session")
}

func TestSharedGNMIReadinessKeyIncludesPerStreamSyncTimeout(t *testing.T) {
	base := sharedGNMIRuntimeStream{sharedGNMIStream: sharedGNMIStream{
		Profile: "grouped", Mode: gnmiModeStream, StreamMode: gnmiStreamModeSample,
		Encoding: gnmiEncodingAuto, SampleInterval: time.Minute,
		Paths: []sharedGNMIPath{{Origin: "vendor", Path: "state/value"}},
	}}
	left, right := base, base
	left.SyncTimeout = time.Minute
	right.SyncTimeout = 2 * time.Minute
	assert.NotEqual(t, sharedGNMIReadinessStreamKey(left), sharedGNMIReadinessStreamKey(right))
}

func TestSharedGNMIStreamSyncWatchdogEndsAfterInitialSync(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}}); err != nil {
			return err
		}
		timer := time.NewTimer(150 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		if err := runtimeTestSendScalarUpdate(stream, "system/value", 42); err != nil {
			return err
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeStream, runtimeTestMapping("system/value", "runtime.after-sync.value"))
	target.SyncTimeout = 40 * time.Millisecond
	sink := &consumertest.MetricsSink{}
	receiver := runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 10, sink)

	require.Eventually(t, func() bool {
		return runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.after-sync.value") == 1
	}, 3*time.Second, 10*time.Millisecond)
	assert.Equal(t, 1, fake.snapshot().subscribeCalls,
		"a STREAM subscription must not retain its initial-sync deadline after sync_response")
	require.NotNil(t, receiver)
}

func runtimeTestSendScalarUpdate(
	stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse],
	path string,
	value int64,
) error {
	parsed, err := internalgnmi.ParsePath("", "", path)
	if err != nil {
		return err
	}
	return stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
		Timestamp: time.Now().UnixNano(),
		Prefix:    &gnmipb.Path{Origin: runtimeTestOrigin},
		Update: []*gnmipb.Update{{
			Path: parsed.ToProto(),
			Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: value}},
		}},
	}}})
}

func runtimeTestIntGaugeValues(metrics []pmetric.Metrics, name string) []int64 {
	var values []int64
	for _, batch := range metrics {
		for i := 0; i < batch.ResourceMetrics().Len(); i++ {
			scopes := batch.ResourceMetrics().At(i).ScopeMetrics()
			for j := 0; j < scopes.Len(); j++ {
				items := scopes.At(j).Metrics()
				for k := 0; k < items.Len(); k++ {
					metric := items.At(k)
					if metric.Name() != name || metric.Type() != pmetric.MetricTypeGauge {
						continue
					}
					points := metric.Gauge().DataPoints()
					for pointIndex := 0; pointIndex < points.Len(); pointIndex++ {
						point := points.At(pointIndex)
						if point.ValueType() == pmetric.NumberDataPointValueTypeInt {
							values = append(values, point.IntValue())
						}
					}
				}
			}
		}
	}
	return values
}
