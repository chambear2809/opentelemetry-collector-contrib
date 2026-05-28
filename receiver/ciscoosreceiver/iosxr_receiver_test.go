// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
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
	require.Len(t, sink.AllMetrics(), 1)
	assertMetricExists(t, sink.AllMetrics()[0], "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.counters.in_octets")
	assert.Equal(t, int64(1), receiver.health.snapshot().updatesReceived)

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
	require.Len(t, sink.AllMetrics(), 1)

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
