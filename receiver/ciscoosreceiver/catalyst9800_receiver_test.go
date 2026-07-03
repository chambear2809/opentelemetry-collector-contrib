// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"google.golang.org/grpc"

	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestCatalyst9800DialInReceiverUsesLegacySharedSession(t *testing.T) {
	fake := &fakeGNMIServer{
		caps: &gnmi.CapabilityResponse{
			SupportedModels:    []*gnmi.ModelData{{Name: "Cisco-IOS-XE-wireless-ap-global-oper"}},
			SupportedEncodings: []gnmi.Encoding{gnmi.Encoding_JSON_IETF},
		},
		sendUpdate: func(stream grpc.BidiStreamingServer[gnmi.SubscribeRequest, gnmi.SubscribeResponse]) error {
			return stream.Send(&gnmi.SubscribeResponse{Response: &gnmi.SubscribeResponse_Update{Update: &gnmi.Notification{
				Timestamp: time.Unix(1700000000, 0).UnixNano(),
				Prefix:    mustParseIOSXRPathForServer("wireless-ap-global-oper:ap-global-oper-data/ap-join-stats[wtp-mac=AA:BB:CC:DD:EE:FF]"),
				Update: []*gnmi.Update{{
					Path: mustParseIOSXRPathForServer("ap-join-info"),
					Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{"is-joined":true}`)}},
				}},
			}}})
		},
	}
	endpoint := startFakeGNMIServer(t, fake)

	cfg := defaultCatalyst9800Config()
	cfg.Enabled = true
	for name := range cfg.PathGroups {
		cfg.PathGroups[name] = Catalyst9800PathGroupConfig{}
	}
	cfg.Paths.Include = []string{"wireless-ap-global-oper:ap-global-oper-data/ap-join-stats"}
	sink := &consumertest.MetricsSink{}
	receiver := &catalyst9800DialInReceiver{
		settings: receivertest.NewNopSettings(componentmetadata.Type),
		config:   cfg,
		consumer: sink,
		health:   &catalyst9800Health{},
		host:     componenttest.NewNopHost(),
	}
	target := Catalyst9800TargetConfig{
		ClientConfig: mustCatalyst9800ClientConfig(endpoint),
		Name:         "wlc-1",
		Credentials: Catalyst9800CredentialsConfig{
			Username: "admin",
			Password: configopaque.String("password"),
		},
		Subscription: Catalyst9800SubscriptionConfig{Mode: iosXRSubscribeModeOnce},
	}.withDefaults(cfg)

	require.NoError(t, receiver.subscribeTarget(t.Context(), target))
	data := metricsBatchWithName(t, sink.AllMetrics(), "cisco.catalyst9800.yang.wireless_ap_global_oper.ap_global_oper_data.ap_join_stats.ap_join_info.is_joined")
	assertMetricExists(t, data, "cisco.catalyst9800.yang.wireless_ap_global_oper.ap_global_oper_data.ap_join_stats.ap_join_info.is_joined")
	assertMetricExists(t, data, "cisco.wlc.ap.join.status")

	fake.mu.Lock()
	defer fake.mu.Unlock()
	assert.Equal(t, "admin", firstMetadataValue(fake.capabilitiesMD, "username"))
	assert.Equal(t, "password", firstMetadataValue(fake.subscribeMD, "password"))
}

func TestCatalyst9800ResolveTargetPathsAcceptsCiscoModuleAliases(t *testing.T) {
	cfg := defaultCatalyst9800Config()
	for name := range cfg.PathGroups {
		cfg.PathGroups[name] = Catalyst9800PathGroupConfig{}
	}
	cfg.Paths.Include = []string{"wireless-access-point-oper:access-point-oper-data/ssid-counters"}
	cfg.UnsupportedPathAction = iosXRUnsupportedError
	receiver := catalyst9800DialInReceiver{config: cfg, health: &catalyst9800Health{}}

	paths, err := receiver.resolveTargetPaths(Catalyst9800TargetConfig{Name: "wlc-1"}, &gnmi.CapabilityResponse{
		SupportedModels: []*gnmi.ModelData{{Name: "Cisco-IOS-XE-wireless-access-point-oper"}},
	})
	require.NoError(t, err)
	require.NotEmpty(t, paths)
}

func TestCatalyst9800EncodingNegotiation(t *testing.T) {
	encoding, err := negotiateCatalyst9800Encoding([]string{"json_ietf", "json"}, &gnmi.CapabilityResponse{
		SupportedEncodings: []gnmi.Encoding{gnmi.Encoding_JSON_IETF},
	})
	require.NoError(t, err)
	assert.Equal(t, gnmi.Encoding_JSON_IETF, encoding)

	_, err = negotiateCatalyst9800Encoding([]string{"json_ietf"}, &gnmi.CapabilityResponse{
		SupportedEncodings: []gnmi.Encoding{gnmi.Encoding_PROTO},
	})
	require.Error(t, err)
}

func TestBuildCatalyst9800SubscribeRequestModesAndGuardrails(t *testing.T) {
	req := buildCatalyst9800SubscribeRequest(Catalyst9800SubscriptionConfig{
		Mode:              iosXRSubscribeModeStream,
		StreamMode:        iosXRStreamModeTargetDefined,
		SampleInterval:    10 * time.Second,
		HeartbeatInterval: 30 * time.Second,
		SuppressRedundant: configoptional.Some(true),
		UpdatesOnly:       configoptional.Some(true),
		AllowAggregation:  configoptional.Some(true),
	}, []catalyst9800PathDefinition{
		{
			ID:                "capwap",
			Path:              "wireless-access-point-oper:access-point-oper-data/capwap-data",
			MinSampleInterval: 15 * time.Minute,
		},
		{
			ID:                "wildcard",
			Path:              "wireless-client-oper:client-oper-data/*",
			MinSampleInterval: time.Minute,
		},
	}, gnmi.Encoding_JSON_IETF)

	sub := req.GetSubscribe()
	require.NotNil(t, sub)
	require.Len(t, sub.Subscription, 1)
	assert.Equal(t, gnmi.Encoding_JSON_IETF, sub.Encoding)
	assert.True(t, sub.UpdatesOnly)
	assert.True(t, sub.AllowAggregation)
	assert.Equal(t, gnmi.SubscriptionMode_SAMPLE, sub.Subscription[0].Mode)
	assert.Equal(t, uint64((15 * time.Minute).Nanoseconds()), sub.Subscription[0].SampleInterval)
	assert.Equal(t, uint64((30 * time.Second).Nanoseconds()), sub.Subscription[0].HeartbeatInterval)
	assert.True(t, sub.Subscription[0].SuppressRedundant)
}

func TestBuildCatalyst9800SubscribeRequestHonorsPathDefaultStreamMode(t *testing.T) {
	req := buildCatalyst9800SubscribeRequest(Catalyst9800SubscriptionConfig{
		Mode:           iosXRSubscribeModeStream,
		StreamMode:     iosXRStreamModeSample,
		SampleInterval: time.Minute,
	}, []catalyst9800PathDefinition{
		{
			ID:                "ap.join",
			Path:              "wireless-ap-global-oper:ap-global-oper-data/ap-join-stats",
			DefaultStreamMode: iosXRStreamModeOnChange,
			MinSampleInterval: time.Minute,
		},
	}, gnmi.Encoding_JSON_IETF)

	sub := req.GetSubscribe()
	require.NotNil(t, sub)
	require.Len(t, sub.Subscription, 1)
	assert.Equal(t, gnmi.SubscriptionMode_ON_CHANGE, sub.Subscription[0].Mode)
	assert.Zero(t, sub.Subscription[0].SampleInterval)
}

func TestCatalyst9800RunTargetTracksLifecycleAndResetsRetryBackoff(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	receiver := &catalyst9800DialInReceiver{
		settings: receivertest.NewNopSettings(componentmetadata.Type),
		config:   defaultCatalyst9800Config(),
		consumer: sink,
		health:   &catalyst9800Health{},
	}
	target := Catalyst9800TargetConfig{Name: "wlc-1", Subscription: Catalyst9800SubscriptionConfig{Mode: iosXRSubscribeModeStream}}
	attempts := 0
	observedActive := int64(0)
	receiver.subscribeTargetFn = func(ctx context.Context, target Catalyst9800TargetConfig) (bool, error) {
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
	assert.True(t, metricGaugeValueExists(sink.AllMetrics(), "cisco.catalyst9800.receiver.active_subscriptions", 1))
	assert.True(t, metricGaugeValueExists(sink.AllMetrics(), "cisco.catalyst9800.receiver.active_subscriptions", 0))
	assert.True(t, metricGaugeValueExists(sink.AllMetrics(), "cisco.catalyst9800.receiver.target.subscription.active", 1))
	assert.True(t, metricGaugeValueExists(sink.AllMetrics(), "cisco.catalyst9800.receiver.target.subscription.active", 0))
}

func TestCatalyst9800DialInReceiverPollJoinsReaderOnCancellation(t *testing.T) {
	streamCtx, cancelStream := context.WithCancel(t.Context())
	next := &releaseBlockingMetricsConsumer{started: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(next.Release)
	receiver := &catalyst9800DialInReceiver{
		settings: receivertest.NewNopSettings(componentmetadata.Type),
		config:   defaultCatalyst9800Config(),
		consumer: next,
		health:   &catalyst9800Health{},
	}
	target := Catalyst9800TargetConfig{
		Name: "wlc-1",
		Subscription: Catalyst9800SubscriptionConfig{
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

func TestCatalyst9800DialInReceiverPollPreservesSendError(t *testing.T) {
	streamCtx, cancelStream := context.WithCancel(t.Context())
	sendErr := errors.New("poll send failed")
	stream := &singleUpdateGNMIClientStream{ctx: streamCtx, sendErr: sendErr, sendErrAt: 2}
	target := Catalyst9800TargetConfig{Subscription: Catalyst9800SubscriptionConfig{Mode: iosXRSubscribeModePoll, PollInterval: time.Millisecond}}
	var progressed atomic.Bool

	err := (&catalyst9800DialInReceiver{}).recvPoll(streamCtx, cancelStream, target, stream, &progressed)
	require.ErrorIs(t, err, sendErr)
}

func TestCatalyst9800DialInReceiverRecvLoopReturnsConsumerRefusal(t *testing.T) {
	streamCtx, cancelStream := context.WithCancel(t.Context())
	defer cancelStream()
	response := &gnmi.SubscribeResponse{Response: &gnmi.SubscribeResponse_Update{Update: &gnmi.Notification{
		Timestamp: time.Unix(1700000000, 0).UnixNano(),
		Prefix:    mustParseIOSXRPathForServer("wireless-ap-global-oper:ap-global-oper-data/ap-join-stats[wtp-mac=AA:BB:CC:DD:EE:FF]"),
		Update: []*gnmi.Update{{
			Path: mustParseIOSXRPathForServer("ap-join-info"),
			Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{"is-joined":true}`)}},
		}},
	}}}
	receiver := &catalyst9800DialInReceiver{
		settings: receivertest.NewNopSettings(componentmetadata.Type),
		config:   defaultCatalyst9800Config(),
		consumer: consumertest.NewErr(errors.New("refused")),
		health:   &catalyst9800Health{},
	}
	target := Catalyst9800TargetConfig{Name: "wlc-1"}
	var progressed atomic.Bool
	err := receiver.recvLoop(streamCtx, target, &singleUpdateGNMIClientStream{ctx: streamCtx, response: response}, &progressed)
	require.ErrorContains(t, err, "refused")
	assert.False(t, progressed.Load())
	assert.Positive(t, receiver.health.snapshot().droppedDatapoints)
}

func TestCatalyst9800NormalizingConsumerRenamesDialOutMetricsAndAddsAliases(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	normalizer := newCatalyst9800NormalizingConsumer(
		sink,
		defaultCatalyst9800Config(),
		newDeviceSelectionMatcher(DeviceSelectionConfig{}),
		catalyst9800TelemetryTransportDialOut,
		&catalyst9800Health{},
	)

	raw := rawCatalyst9800DialOutMetrics("cisco.rrm-oper-data.rrm-measurement.cca-util-percentage", 67, "wlc-1")
	raw.ResourceMetrics().At(0).Resource().Attributes().PutStr("host.ip", "192.0.2.40")
	err := normalizer.ConsumeMetrics(t.Context(), raw)
	require.NoError(t, err)
	require.Len(t, sink.AllMetrics(), 1)

	md := sink.AllMetrics()[0]
	assertMetricExists(t, md, "cisco.catalyst9800.yang.wireless_rrm_oper.rrm_oper_data.rrm_measurement.cca_util_percentage")
	assertMetricExists(t, md, "cisco.wlc.rf.channel.utilization")

	resourceAttrs := md.ResourceMetrics().At(0).Resource().Attributes()
	assert.Equal(t, "wlc-1", attrValue(t, resourceAttrs, "host.name"))
	assert.Equal(t, []string{"192.0.2.40"}, stringSliceAttrValue(t, resourceAttrs))
	assert.Equal(t, "ios_xe", attrValue(t, resourceAttrs, "cisco.os.name"))
	assert.Equal(t, "catalyst_9800", attrValue(t, resourceAttrs, "cisco.platform.family"))
	assert.Equal(t, "mdt_grpc_dial_out", attrValue(t, resourceAttrs, "cisco.telemetry.transport"))
	_, hasResourceModule := resourceAttrs.Get("cisco.yang.module")
	assert.False(t, hasResourceModule)
	metric := requireMetricByName(t, md, "cisco.catalyst9800.yang.wireless_rrm_oper.rrm_oper_data.rrm_measurement.cca_util_percentage")
	assert.Equal(t, "wireless-rrm-oper", attrValue(t, metric.Gauge().DataPoints().At(0).Attributes(), "cisco.yang.module"))
}

func TestCatalyst9800NormalizingConsumerAllowsRootMetricPatternFilteringAfterAliases(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	filter := newMetricFilteringConsumer(sink, &Config{Metrics: map[string]MetricConfig{
		"cisco.wlc.*": {Enabled: false},
	}})
	normalizer := newCatalyst9800NormalizingConsumer(
		filter,
		defaultCatalyst9800Config(),
		newDeviceSelectionMatcher(DeviceSelectionConfig{}),
		catalyst9800TelemetryTransportDialOut,
		&catalyst9800Health{},
	)

	err := normalizer.ConsumeMetrics(t.Context(), rawCatalyst9800DialOutMetrics("cisco.rrm-oper-data.rrm-measurement.cca-util-percentage", 67, "wlc-1"))
	require.NoError(t, err)
	require.Len(t, sink.AllMetrics(), 1)

	md := sink.AllMetrics()[0]
	assertMetricExists(t, md, "cisco.catalyst9800.yang.wireless_rrm_oper.rrm_oper_data.rrm_measurement.cca_util_percentage")
	assert.NotContains(t, metricNames(md), "cisco.wlc.rf.channel.utilization")
}

func rawCatalyst9800DialOutMetrics(metricName string, value float64, nodeID string) pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("cisco.node_id", nodeID)
	rm.Resource().Attributes().PutStr("cisco.encoding_path", "wireless-rrm-oper:rrm-oper-data/rrm-measurement")
	sm := rm.ScopeMetrics().AppendEmpty()
	metric := sm.Metrics().AppendEmpty()
	metric.SetName(metricName)
	dp := metric.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetDoubleValue(value)
	return md
}
