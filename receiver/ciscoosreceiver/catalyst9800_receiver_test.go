// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

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
		SuppressRedundant: true,
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

func TestCatalyst9800NormalizingConsumerRenamesDialOutMetricsAndAddsAliases(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	normalizer := newCatalyst9800NormalizingConsumer(
		sink,
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
	assertMetricExists(t, md, "cisco.wlc.rf.channel.utilization")

	resourceAttrs := md.ResourceMetrics().At(0).Resource().Attributes()
	assert.Equal(t, "wlc-1", attrValue(t, resourceAttrs, "host.name"))
	assert.Equal(t, "ios_xe", attrValue(t, resourceAttrs, "cisco.os.name"))
	assert.Equal(t, "catalyst_9800", attrValue(t, resourceAttrs, "cisco.platform.family"))
	assert.Equal(t, "mdt_grpc_dial_out", attrValue(t, resourceAttrs, "cisco.telemetry.transport"))
	assert.Equal(t, "wireless-rrm-oper", attrValue(t, resourceAttrs, "cisco.yang.module"))
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
