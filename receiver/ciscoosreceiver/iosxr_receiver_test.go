// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcmetadata "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestIOSXRDialInReceiverSubscribesAndConsumesGNMI(t *testing.T) {
	fake := &fakeGNMIServer{
		caps: &gnmi.CapabilityResponse{
			SupportedModels:    []*gnmi.ModelData{{Name: "openconfig-interfaces"}},
			SupportedEncodings: []gnmi.Encoding{gnmi.Encoding_JSON_IETF, gnmi.Encoding_PROTO},
		},
	}
	endpoint := startFakeGNMIServer(t, fake)

	cfg := defaultIOSXRConfig()
	cfg.Enabled = true
	cfg.Paths.Include = []string{"openconfig-interfaces:interfaces/interface/state/counters"}
	sink := &consumertest.MetricsSink{}
	receiver := &iosXRDialInReceiver{
		settings: receivertest.NewNopSettings(componentmetadata.Type),
		config:   cfg,
		consumer: sink,
		health:   &iosXRHealth{},
		host:     componenttest.NewNopHost(),
	}
	target := IOSXRTargetConfig{
		ClientConfig: mustIOSXRClientConfig(endpoint),
		Name:         "xr-1",
		Credentials: IOSXRCredentialsConfig{
			Username: "admin",
			Password: configopaque.String("password"),
		},
		Subscription: IOSXRSubscriptionConfig{Mode: iosXRSubscribeModeOnce},
	}
	target = target.withDefaults(cfg)

	require.NoError(t, receiver.subscribeTarget(t.Context(), target))
	data := metricsBatchWithName(t, sink.AllMetrics(), "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.counters.in_octets")
	assertMetricExists(t, data, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.counters.in_octets")
	snapshot := receiver.health.snapshotForTarget("xr-1")
	assert.Equal(t, int64(0), snapshot.activeSubscriptions)
	assert.False(t, snapshot.targetActive)
	assert.Equal(t, int64(1), snapshot.updatesReceived)
	assert.Equal(t, int64(1), snapshot.targetUpdatesReceived)
	assert.True(t, metricGaugeValueExists(sink.AllMetrics(), "cisco.iosxr.receiver.target.subscription.active", 1))
	assert.True(t, metricGaugeValueExists(sink.AllMetrics(), "cisco.iosxr.receiver.target.subscription.active", 0))

	fake.mu.Lock()
	defer fake.mu.Unlock()
	require.Len(t, fake.requests, 1)
	subscribe := fake.requests[0].GetSubscribe()
	require.NotNil(t, subscribe)
	assert.Equal(t, gnmi.Encoding_JSON_IETF, subscribe.Encoding)
	assert.Equal(t, gnmi.SubscriptionList_ONCE, subscribe.Mode)
	require.Len(t, subscribe.Subscription, 1)
	assert.Equal(t, gnmi.SubscriptionMode_SAMPLE, subscribe.Subscription[0].Mode)
	assert.Equal(t, "admin", firstMetadataValue(fake.capabilitiesMD, "username"))
	assert.Equal(t, "password", firstMetadataValue(fake.subscribeMD, "password"))
}

func TestIOSXRDialInReceiverPollWaitsForInitialSync(t *testing.T) {
	fake := &fakeGNMIServer{
		caps: &gnmi.CapabilityResponse{
			SupportedModels:    []*gnmi.ModelData{{Name: "openconfig-interfaces"}},
			SupportedEncodings: []gnmi.Encoding{gnmi.Encoding_JSON_IETF},
		},
		waitForPoll: true,
		pollCycles:  2,
	}
	endpoint := startFakeGNMIServer(t, fake)

	cfg := defaultIOSXRConfig()
	cfg.Enabled = true
	cfg.Paths.Include = []string{"openconfig-interfaces:interfaces/interface/state/counters"}
	sink := &consumertest.MetricsSink{}
	receiver := &iosXRDialInReceiver{
		settings: receivertest.NewNopSettings(componentmetadata.Type),
		config:   cfg,
		consumer: sink,
		health:   &iosXRHealth{},
		host:     componenttest.NewNopHost(),
	}
	target := IOSXRTargetConfig{
		ClientConfig: mustIOSXRClientConfig(endpoint),
		Name:         "xr-1",
		Credentials: IOSXRCredentialsConfig{
			Username: "admin",
			Password: configopaque.String("password"),
		},
		Subscription: IOSXRSubscriptionConfig{
			Mode:         iosXRSubscribeModePoll,
			PollInterval: 10 * time.Millisecond,
		},
	}
	target = target.withDefaults(cfg)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, receiver.subscribeTarget(ctx, target))
	_ = metricsBatchWithName(t, sink.AllMetrics(), "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.counters.in_octets")
	assert.Equal(t, int64(0), receiver.health.snapshot().activeSubscriptions)

	fake.mu.Lock()
	defer fake.mu.Unlock()
	require.Len(t, fake.requests, 3)
	assert.NotNil(t, fake.requests[0].GetSubscribe())
	assert.NotNil(t, fake.requests[1].GetPoll())
	assert.NotNil(t, fake.requests[2].GetPoll())
	assert.False(t, fake.pollBeforeSync)
	assert.False(t, fake.pollBeforePollSync)
}

func TestIOSXRDialInReceiverOnceRequiresCleanEOF(t *testing.T) {
	const remoteStatusMessage = "device-echoed password=legacy-runtime-secret"
	fake := &fakeGNMIServer{
		caps: &gnmi.CapabilityResponse{
			SupportedModels:    []*gnmi.ModelData{{Name: "openconfig-interfaces"}},
			SupportedEncodings: []gnmi.Encoding{gnmi.Encoding_JSON_IETF},
		},
		afterSyncErr: status.Error(codes.PermissionDenied, remoteStatusMessage),
	}
	endpoint := startFakeGNMIServer(t, fake)

	cfg := defaultIOSXRConfig()
	cfg.Enabled = true
	cfg.Paths.Include = []string{"openconfig-interfaces:interfaces/interface/state/counters"}
	receiver := &iosXRDialInReceiver{
		settings: receivertest.NewNopSettings(componentmetadata.Type),
		config:   cfg,
		consumer: consumertest.NewNop(),
		health:   &iosXRHealth{},
		host:     componenttest.NewNopHost(),
	}
	target := IOSXRTargetConfig{
		ClientConfig: mustIOSXRClientConfig(endpoint),
		Name:         "xr-1",
		Credentials: IOSXRCredentialsConfig{
			Username: "admin",
			Password: configopaque.String("password"),
		},
		Subscription: IOSXRSubscriptionConfig{Mode: iosXRSubscribeModeOnce},
	}.withDefaults(cfg)

	err := receiver.subscribeTarget(t.Context(), target)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.ErrorContains(t, err, "code=PermissionDenied")
	assert.NotContains(t, err.Error(), "device-echoed")
	assert.NotContains(t, err.Error(), "legacy-runtime-secret")
}

func TestIOSXRDialInReceiverReturnsConsumerRefusal(t *testing.T) {
	fake := &fakeGNMIServer{
		caps: &gnmi.CapabilityResponse{
			SupportedModels:    []*gnmi.ModelData{{Name: "openconfig-interfaces"}},
			SupportedEncodings: []gnmi.Encoding{gnmi.Encoding_JSON_IETF},
		},
	}
	endpoint := startFakeGNMIServer(t, fake)

	cfg := defaultIOSXRConfig()
	cfg.Enabled = true
	cfg.Paths.Include = []string{"openconfig-interfaces:interfaces/interface/state/counters"}
	health := &iosXRHealth{}
	receiver := &iosXRDialInReceiver{
		settings: receivertest.NewNopSettings(componentmetadata.Type),
		config:   cfg,
		consumer: consumertest.NewErr(errors.New("refused")),
		health:   health,
		host:     componenttest.NewNopHost(),
	}
	target := IOSXRTargetConfig{
		ClientConfig: mustIOSXRClientConfig(endpoint),
		Name:         "xr-1",
		Credentials: IOSXRCredentialsConfig{
			Username: "admin",
			Password: configopaque.String("password"),
		},
		Subscription: IOSXRSubscriptionConfig{Mode: iosXRSubscribeModeOnce},
	}.withDefaults(cfg)

	err := receiver.subscribeTarget(t.Context(), target)
	require.ErrorContains(t, err, "refused")
	snapshot := health.snapshot()
	assert.Zero(t, snapshot.reconnects)
	assert.Positive(t, snapshot.droppedDatapoints)
	fake.mu.Lock()
	defer fake.mu.Unlock()
	assert.Len(t, fake.requests, 1)
}

func TestIOSXRDialInReceiverShutdownJoinsLegacySessionReader(t *testing.T) {
	fake := &fakeGNMIServer{
		caps: &gnmi.CapabilityResponse{
			SupportedModels:    []*gnmi.ModelData{{Name: "openconfig-interfaces"}},
			SupportedEncodings: []gnmi.Encoding{gnmi.Encoding_JSON_IETF},
		},
	}
	endpoint := startFakeGNMIServer(t, fake)

	cfg := defaultIOSXRConfig()
	cfg.Enabled = true
	cfg.Paths.Include = []string{"openconfig-interfaces:interfaces/interface/state/counters"}
	target := IOSXRTargetConfig{
		ClientConfig: mustIOSXRClientConfig(endpoint),
		Name:         "xr-1",
		Credentials: IOSXRCredentialsConfig{
			Username: "admin",
			Password: configopaque.String("password"),
		},
		Subscription: IOSXRSubscriptionConfig{Mode: iosXRSubscribeModeStream},
	}.withDefaults(cfg)
	next := &releaseBlockingMetricsConsumer{
		metricName: "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.counters.in_octets",
		started:    make(chan struct{}),
		release:    make(chan struct{}),
	}
	t.Cleanup(next.Release)
	receiver := &iosXRDialInReceiver{
		settings: receivertest.NewNopSettings(componentmetadata.Type),
		config:   cfg,
		targets:  []IOSXRTargetConfig{target},
		consumer: next,
		health:   &iosXRHealth{},
		done:     make(chan struct{}),
	}
	require.NoError(t, receiver.Start(t.Context(), componenttest.NewNopHost()))
	t.Cleanup(func() {
		next.Release()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		_ = receiver.Shutdown(ctx)
	})

	select {
	case <-next.started:
	case <-time.After(5 * time.Second):
		t.Fatal("legacy gNMI reader did not reach the downstream consumer")
	}

	shortCtx, shortCancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	err := receiver.Shutdown(shortCtx)
	shortCancel()
	require.ErrorIs(t, err, context.DeadlineExceeded)
	select {
	case <-receiver.done:
		t.Fatal("receiver shutdown completed while its response reader still owned receiver state")
	default:
	}

	next.Release()
	shutdownCtx, shutdownCancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer shutdownCancel()
	require.NoError(t, receiver.Shutdown(shutdownCtx))
}

func TestLegacyGNMIRetryDelaySlowsAuthenticationFailures(t *testing.T) {
	assert.Equal(t, legacyGNMIAuthenticationBackoff, legacyGNMIRetryDelay(status.Error(codes.Unauthenticated, "denied")))
	assert.Equal(t, legacyGNMIAuthenticationBackoff, legacyGNMIRetryDelay(status.Error(codes.PermissionDenied, "denied")))
	assert.Equal(t, legacyGNMIAuthenticationBackoff, legacyGNMIRetryDelay(fmt.Errorf("capabilities: %w", status.Error(codes.Unauthenticated, "denied"))))
	assert.Equal(t, legacyGNMIReconnectBackoff, legacyGNMIRetryDelay(status.Error(codes.Unavailable, "down")))
}

func TestIOSXRDialInReceiverPollJoinsReaderOnCancellation(t *testing.T) {
	streamCtx, cancelStream := context.WithCancel(t.Context())
	next := &releaseBlockingMetricsConsumer{started: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(next.Release)
	receiver := &iosXRDialInReceiver{
		settings: receivertest.NewNopSettings(componentmetadata.Type),
		config:   defaultIOSXRConfig(),
		consumer: next,
		health:   &iosXRHealth{},
	}
	target := IOSXRTargetConfig{
		Name: "xr-1",
		Subscription: IOSXRSubscriptionConfig{
			Mode:         iosXRSubscribeModePoll,
			PollInterval: time.Hour,
		},
	}
	stream := &singleUpdateGNMIClientStream{ctx: streamCtx, response: testDirectGNMIUpdate()}
	result := make(chan error, 1)
	go func() {
		var progressed atomic.Bool
		result <- receiver.recvPoll(streamCtx, cancelStream, target, stream, &progressed)
	}()

	select {
	case <-next.started:
	case <-time.After(5 * time.Second):
		t.Fatal("gNMI POLL reader did not reach the downstream consumer")
	}
	cancelStream()
	select {
	case err := <-result:
		t.Fatalf("recvPoll returned before its reader exited: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	next.Release()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("recvPoll did not join its reader after downstream returned")
	}
}

func TestIOSXRDialInReceiverPollPreservesSendError(t *testing.T) {
	streamCtx, cancelStream := context.WithCancel(t.Context())
	sendErr := errors.New("poll send failed")
	stream := &singleUpdateGNMIClientStream{ctx: streamCtx, sendErr: sendErr, sendErrAt: 2}
	target := IOSXRTargetConfig{Subscription: IOSXRSubscriptionConfig{Mode: iosXRSubscribeModePoll, PollInterval: time.Millisecond}}
	var progressed atomic.Bool

	err := (&iosXRDialInReceiver{}).recvPoll(streamCtx, cancelStream, target, stream, &progressed)
	require.ErrorIs(t, err, sendErr)
}

func TestIOSXRResolveTargetPathsHonorsUnsupportedAction(t *testing.T) {
	cfg := defaultIOSXRConfig()
	cfg.Enabled = true
	cfg.UnsupportedPathAction = iosXRUnsupportedError
	cfg.Paths.Include = []string{"Cisco-IOS-XR-ipv4-bgp-oper:bgp/instances/instance/instance-active/default-vrf/process-info"}
	receiver := &iosXRDialInReceiver{
		settings: receivertest.NewNopSettings(componentmetadata.Type),
		config:   cfg,
		health:   &iosXRHealth{},
	}

	paths, err := receiver.resolveTargetPaths(IOSXRTargetConfig{Name: "xr-1"}, &gnmi.CapabilityResponse{
		SupportedModels: []*gnmi.ModelData{{Name: "openconfig-interfaces"}},
	})
	require.Error(t, err)
	assert.Empty(t, paths)
	assert.Contains(t, err.Error(), "does not advertise models")
	assert.Equal(t, int64(1), receiver.health.snapshot().unsupportedPaths)
}

func TestIOSXREncodingNegotiation(t *testing.T) {
	encoding, err := negotiateIOSXREncoding([]string{"json_ietf", "proto"}, &gnmi.CapabilityResponse{
		SupportedEncodings: []gnmi.Encoding{gnmi.Encoding_PROTO},
	})
	require.NoError(t, err)
	assert.Equal(t, gnmi.Encoding_PROTO, encoding)

	_, err = negotiateIOSXREncoding([]string{"json_ietf", "json"}, &gnmi.CapabilityResponse{
		SupportedEncodings: []gnmi.Encoding{gnmi.Encoding_PROTO},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not support requested IOS XR encodings")
}

func TestBuildIOSXRSubscribeRequestModesAndGuardrails(t *testing.T) {
	req := buildIOSXRSubscribeRequest(IOSXRSubscriptionConfig{
		Mode:              iosXRSubscribeModePoll,
		StreamMode:        iosXRStreamModeTargetDefined,
		SampleInterval:    30 * time.Second,
		HeartbeatInterval: 10 * time.Second,
		SuppressRedundant: configoptional.Some(true),
		UpdatesOnly:       configoptional.Some(true),
		AllowAggregation:  configoptional.Some(true),
	}, []iosXRPathDefinition{
		{ID: "oc", Path: "openconfig-interfaces:interfaces/interface/state", MinSampleInterval: time.Minute},
		{ID: "native", Path: "Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/latest/generic-counters", MinSampleInterval: time.Minute},
	}, gnmi.Encoding_JSON)

	subscribe := req.GetSubscribe()
	require.NotNil(t, subscribe)
	assert.Equal(t, gnmi.SubscriptionList_POLL, subscribe.Mode)
	assert.Equal(t, gnmi.Encoding_JSON, subscribe.Encoding)
	assert.True(t, subscribe.UpdatesOnly)
	assert.True(t, subscribe.AllowAggregation)
	require.Len(t, subscribe.Subscription, 2)
	assert.Equal(t, gnmi.SubscriptionMode_TARGET_DEFINED, subscribe.Subscription[0].Mode)
	assert.Equal(t, gnmi.SubscriptionMode_SAMPLE, subscribe.Subscription[1].Mode)
	assert.Equal(t, uint64(time.Minute.Nanoseconds()), subscribe.Subscription[0].SampleInterval)
	assert.Equal(t, uint64((10 * time.Second).Nanoseconds()), subscribe.Subscription[0].HeartbeatInterval)
	assert.True(t, subscribe.Subscription[0].SuppressRedundant)
}

func TestBuildIOSXRSubscribeRequestPathDefaultStreamModeOverrides(t *testing.T) {
	req := buildIOSXRSubscribeRequest(IOSXRSubscriptionConfig{
		Mode:           iosXRSubscribeModeStream,
		StreamMode:     iosXRStreamModeSample,
		SampleInterval: 30 * time.Second,
	}, []iosXRPathDefinition{
		{ID: "alarms", Path: "Cisco-IOS-XR-alarmgr-server-oper:alarms", DefaultStreamMode: iosXRStreamModeOnChange},
		{ID: "counters", Path: "Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/latest/generic-counters"},
	}, gnmi.Encoding_JSON)

	subscribe := req.GetSubscribe()
	require.NotNil(t, subscribe)
	require.Len(t, subscribe.Subscription, 2)
	// Per-path catalog DefaultStreamMode wins over the global sample default.
	assert.Equal(t, gnmi.SubscriptionMode_ON_CHANGE, subscribe.Subscription[0].Mode)
	// Path with no catalog default falls back to the global stream_mode.
	assert.Equal(t, gnmi.SubscriptionMode_SAMPLE, subscribe.Subscription[1].Mode)
}

func TestDirectGNMIRetryDelayIsBoundedExponentialWithJitter(t *testing.T) {
	noJitter := func(time.Duration) time.Duration { return 0 }
	assert.Equal(t, 500*time.Millisecond, nextDirectGNMIRetryDelay(1, noJitter))
	assert.Equal(t, time.Second, nextDirectGNMIRetryDelay(2, noJitter))
	assert.Equal(t, 2*time.Second, nextDirectGNMIRetryDelay(3, noJitter))
	assert.Equal(t, 15*time.Second, nextDirectGNMIRetryDelay(100, noJitter))

	maxJitter := func(upperBound time.Duration) time.Duration { return upperBound - 1 }
	delay := nextDirectGNMIRetryDelay(100, maxJitter)
	assert.LessOrEqual(t, delay, directGNMIRetryMax)
	assert.GreaterOrEqual(t, delay, directGNMIRetryMax/2)
}

func TestIOSXRRunTargetTracksLifecycleAndResetsRetryBackoff(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	receiver := &iosXRDialInReceiver{
		settings: receivertest.NewNopSettings(componentmetadata.Type),
		config:   defaultIOSXRConfig(),
		consumer: sink,
		health:   &iosXRHealth{},
	}
	target := IOSXRTargetConfig{Name: "xr-1", Subscription: IOSXRSubscriptionConfig{Mode: iosXRSubscribeModeStream}}
	attempts := 0
	observedActive := int64(0)
	receiver.subscribeTargetFn = func(ctx context.Context, target IOSXRTargetConfig) (bool, error) {
		attempts++
		if attempts < 3 {
			return false, errors.New("dial failed")
		}
		receiver.setTargetSubscriptionActive(ctx, target, true)
		observedActive = receiver.health.snapshot().activeSubscriptions
		receiver.setTargetSubscriptionActive(ctx, target, false)
		return true, errors.New("stream disconnected")
	}
	receiver.retryJitterFn = func(time.Duration) time.Duration { return 0 }
	var delays []time.Duration
	receiver.retryWaitFn = func(_ context.Context, delay time.Duration) bool {
		delays = append(delays, delay)
		return len(delays) < 3
	}

	receiver.runTarget(t.Context(), target)

	assert.Equal(t, 3, attempts)
	assert.Equal(t, []time.Duration{500 * time.Millisecond, time.Second, 500 * time.Millisecond}, delays)
	assert.Equal(t, int64(1), observedActive)
	snapshot := receiver.health.snapshotForTarget(target.Name)
	assert.Equal(t, int64(0), snapshot.activeSubscriptions)
	assert.False(t, snapshot.targetActive)
	assert.Equal(t, int64(3), snapshot.reconnects)
	assert.Equal(t, int64(3), snapshot.targetReconnects)
	assert.True(t, metricGaugeValueExists(sink.AllMetrics(), "cisco.iosxr.receiver.active_subscriptions", 1))
	assert.True(t, metricGaugeValueExists(sink.AllMetrics(), "cisco.iosxr.receiver.active_subscriptions", 0))
	assert.True(t, metricGaugeValueExists(sink.AllMetrics(), "cisco.iosxr.receiver.target.subscription.active", 1))
	assert.True(t, metricGaugeValueExists(sink.AllMetrics(), "cisco.iosxr.receiver.target.subscription.active", 0))
}

func metricsBatchWithName(t *testing.T, batches []pmetric.Metrics, name string) pmetric.Metrics {
	t.Helper()
	for _, md := range batches {
		if metricCountNamed(md, name) > 0 {
			return md
		}
	}
	require.FailNowf(t, "metric batch not found", "missing metric %s", name)
	return pmetric.Metrics{}
}

func metricGaugeValueExists(batches []pmetric.Metrics, name string, expected float64) bool {
	for _, md := range batches {
		for i := 0; i < md.ResourceMetrics().Len(); i++ {
			sms := md.ResourceMetrics().At(i).ScopeMetrics()
			for j := 0; j < sms.Len(); j++ {
				metrics := sms.At(j).Metrics()
				for k := 0; k < metrics.Len(); k++ {
					metric := metrics.At(k)
					if metric.Name() != name || metric.Type() != pmetric.MetricTypeGauge {
						continue
					}
					dps := metric.Gauge().DataPoints()
					for l := 0; l < dps.Len(); l++ {
						if dps.At(l).DoubleValue() == expected {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

type fakeGNMIServer struct {
	gnmi.UnimplementedGNMIServer

	caps *gnmi.CapabilityResponse

	mu                 sync.Mutex
	capabilitiesMD     grpcmetadata.MD
	subscribeMD        grpcmetadata.MD
	requests           []*gnmi.SubscribeRequest
	waitForPoll        bool
	pollCycles         int
	pollBeforeSync     bool
	pollBeforePollSync bool
	afterSyncErr       error
	sendUpdate         func(grpc.BidiStreamingServer[gnmi.SubscribeRequest, gnmi.SubscribeResponse]) error
}

func (s *fakeGNMIServer) Capabilities(ctx context.Context, _ *gnmi.CapabilityRequest) (*gnmi.CapabilityResponse, error) {
	md, _ := grpcmetadata.FromIncomingContext(ctx)
	s.mu.Lock()
	s.capabilitiesMD = md.Copy()
	s.mu.Unlock()
	return s.caps, nil
}

func (s *fakeGNMIServer) Subscribe(stream grpc.BidiStreamingServer[gnmi.SubscribeRequest, gnmi.SubscribeResponse]) error {
	md, _ := grpcmetadata.FromIncomingContext(stream.Context())
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.subscribeMD = md.Copy()
	s.requests = append(s.requests, req)
	s.mu.Unlock()
	if s.waitForPoll {
		if err := s.sendFakeUpdate(stream); err != nil {
			return err
		}
		type pollResult struct {
			request *gnmi.SubscribeRequest
			err     error
		}
		receivePoll := func() <-chan pollResult {
			pollResults := make(chan pollResult, 1)
			go func() {
				pollReq, pollErr := stream.Recv()
				pollResults <- pollResult{request: pollReq, err: pollErr}
			}()
			return pollResults
		}
		pollResults := receivePoll()
		var result pollResult
		select {
		case result = <-pollResults:
			s.mu.Lock()
			s.pollBeforeSync = true
			s.mu.Unlock()
		case <-time.After(50 * time.Millisecond):
		}
		if err := sendFakeGNMISync(stream); err != nil {
			return err
		}
		if result.request == nil && result.err == nil {
			result = <-pollResults
		}
		if result.err != nil {
			return result.err
		}
		s.mu.Lock()
		s.requests = append(s.requests, result.request)
		s.mu.Unlock()
		if s.pollCycles > 1 {
			nextPollResults := receivePoll()
			var next pollResult
			select {
			case next = <-nextPollResults:
				s.mu.Lock()
				s.pollBeforePollSync = true
				s.mu.Unlock()
			case <-time.After(50 * time.Millisecond):
			}
			if err := sendFakeGNMISync(stream); err != nil {
				return err
			}
			if next.request == nil && next.err == nil {
				next = <-nextPollResults
			}
			if next.err != nil {
				return next.err
			}
			s.mu.Lock()
			s.requests = append(s.requests, next.request)
			s.mu.Unlock()
			if err := sendFakeGNMISync(stream); err != nil {
				return err
			}
			return s.afterSyncErr
		}
		if err := sendFakeGNMISync(stream); err != nil {
			return err
		}
		return s.afterSyncErr
	}

	if err := s.sendFakeUpdate(stream); err != nil {
		return err
	}
	if err := sendFakeGNMISync(stream); err != nil {
		return err
	}
	return s.afterSyncErr
}

func (s *fakeGNMIServer) sendFakeUpdate(stream grpc.BidiStreamingServer[gnmi.SubscribeRequest, gnmi.SubscribeResponse]) error {
	if s.sendUpdate != nil {
		return s.sendUpdate(stream)
	}
	return sendFakeIOSXRUpdateOnly(stream)
}

func sendFakeIOSXRUpdateOnly(stream grpc.BidiStreamingServer[gnmi.SubscribeRequest, gnmi.SubscribeResponse]) error {
	return stream.Send(&gnmi.SubscribeResponse{Response: &gnmi.SubscribeResponse_Update{Update: &gnmi.Notification{
		Timestamp: time.Unix(1700000000, 0).UnixNano(),
		Prefix:    mustParseIOSXRPathForServer("openconfig-interfaces:interfaces/interface[name=HundredGigE0/0/0/0]/state"),
		Update: []*gnmi.Update{{
			Path: mustParseIOSXRPathForServer("counters/in-octets"),
			Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_UintVal{UintVal: 123}},
		}},
	}}})
}

func sendFakeGNMISync(stream grpc.BidiStreamingServer[gnmi.SubscribeRequest, gnmi.SubscribeResponse]) error {
	return stream.Send(&gnmi.SubscribeResponse{Response: &gnmi.SubscribeResponse_SyncResponse{SyncResponse: true}})
}

func startFakeGNMIServer(t *testing.T, srv *fakeGNMIServer) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	grpcServer := grpc.NewServer()
	gnmi.RegisterGNMIServer(grpcServer, srv)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})
	return listener.Addr().String()
}

func firstMetadataValue(md grpcmetadata.MD, key string) string {
	values := md.Get(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func mustParseIOSXRPathForServer(raw string) *gnmi.Path {
	path, err := parseGNMIPath(raw)
	if err != nil {
		panic(err)
	}
	return path
}

type releaseBlockingMetricsConsumer struct {
	metricName  string
	started     chan struct{}
	release     chan struct{}
	once        sync.Once
	releaseOnce sync.Once
}

func (*releaseBlockingMetricsConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (c *releaseBlockingMetricsConsumer) ConsumeMetrics(_ context.Context, md pmetric.Metrics) error {
	if c.metricName != "" && metricCountNamed(md, c.metricName) == 0 {
		return nil
	}
	c.once.Do(func() { close(c.started) })
	<-c.release
	return nil
}

func (c *releaseBlockingMetricsConsumer) Release() {
	c.releaseOnce.Do(func() { close(c.release) })
}

type singleUpdateGNMIClientStream struct {
	ctx       context.Context
	response  *gnmi.SubscribeResponse
	mu        sync.Mutex
	sendErr   error
	sendErrAt int
	sendCalls int
}

func (s *singleUpdateGNMIClientStream) Send(*gnmi.SubscribeRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendCalls++
	if s.sendErrAt > 0 && s.sendCalls >= s.sendErrAt {
		return s.sendErr
	}
	return nil
}

func (s *singleUpdateGNMIClientStream) Recv() (*gnmi.SubscribeResponse, error) {
	s.mu.Lock()
	response := s.response
	s.response = nil
	s.mu.Unlock()
	if response != nil {
		return response, nil
	}
	<-s.ctx.Done()
	return nil, s.ctx.Err()
}

func (*singleUpdateGNMIClientStream) Header() (grpcmetadata.MD, error) { return nil, nil }
func (*singleUpdateGNMIClientStream) Trailer() grpcmetadata.MD         { return nil }
func (*singleUpdateGNMIClientStream) CloseSend() error                 { return nil }
func (s *singleUpdateGNMIClientStream) Context() context.Context       { return s.ctx }
func (*singleUpdateGNMIClientStream) SendMsg(any) error                { return nil }
func (s *singleUpdateGNMIClientStream) RecvMsg(value any) error {
	response, err := s.Recv()
	if err != nil {
		return err
	}
	output, ok := value.(*gnmi.SubscribeResponse)
	if !ok {
		return errors.New("unexpected receive message type")
	}
	proto.Merge(output, response)
	return nil
}

func testDirectGNMIUpdate() *gnmi.SubscribeResponse {
	return &gnmi.SubscribeResponse{Response: &gnmi.SubscribeResponse_Update{Update: &gnmi.Notification{
		Timestamp: time.Unix(1700000000, 0).UnixNano(),
		Prefix:    mustParseIOSXRPathForServer("openconfig-interfaces:interfaces/interface[name=HundredGigE0/0/0/0]/state"),
		Update: []*gnmi.Update{{
			Path: mustParseIOSXRPathForServer("counters/in-octets"),
			Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_UintVal{UintVal: 123}},
		}},
	}}}
}
