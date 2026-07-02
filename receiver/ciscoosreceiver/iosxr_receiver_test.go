// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"google.golang.org/grpc"
	grpcmetadata "google.golang.org/grpc/metadata"

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

func TestIOSXRDialInReceiverPollSendsInitialPoll(t *testing.T) {
	fake := &fakeGNMIServer{
		caps: &gnmi.CapabilityResponse{
			SupportedModels:    []*gnmi.ModelData{{Name: "openconfig-interfaces"}},
			SupportedEncodings: []gnmi.Encoding{gnmi.Encoding_JSON_IETF},
		},
		waitForPoll: true,
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
			PollInterval: time.Hour,
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
	require.Len(t, fake.requests, 2)
	assert.NotNil(t, fake.requests[0].GetSubscribe())
	assert.NotNil(t, fake.requests[1].GetPoll())
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
		SuppressRedundant: true,
	}, []iosXRPathDefinition{
		{ID: "oc", Path: "openconfig-interfaces:interfaces/interface/state", MinSampleInterval: time.Minute},
		{ID: "native", Path: "Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/latest/generic-counters", MinSampleInterval: time.Minute},
	}, gnmi.Encoding_JSON)

	subscribe := req.GetSubscribe()
	require.NotNil(t, subscribe)
	assert.Equal(t, gnmi.SubscriptionList_POLL, subscribe.Mode)
	assert.Equal(t, gnmi.Encoding_JSON, subscribe.Encoding)
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

	maxJitter := func(max time.Duration) time.Duration { return max - 1 }
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

	mu             sync.Mutex
	capabilitiesMD grpcmetadata.MD
	subscribeMD    grpcmetadata.MD
	requests       []*gnmi.SubscribeRequest
	waitForPoll    bool
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
		pollReq, err := stream.Recv()
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.requests = append(s.requests, pollReq)
		s.mu.Unlock()
	}

	return sendFakeIOSXRUpdate(stream)
}

func sendFakeIOSXRUpdate(stream grpc.BidiStreamingServer[gnmi.SubscribeRequest, gnmi.SubscribeResponse]) error {
	if err := stream.Send(&gnmi.SubscribeResponse{Response: &gnmi.SubscribeResponse_Update{Update: &gnmi.Notification{
		Timestamp: time.Unix(1700000000, 0).UnixNano(),
		Prefix:    mustParseIOSXRPathForServer("openconfig-interfaces:interfaces/interface[name=HundredGigE0/0/0/0]/state"),
		Update: []*gnmi.Update{{
			Path: mustParseIOSXRPathForServer("counters/in-octets"),
			Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_UintVal{UintVal: 123}},
		}},
	}}}); err != nil {
		return err
	}
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
