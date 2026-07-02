// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

func TestIOSXRNormalizingConsumerDeclaresMutation(t *testing.T) {
	normalizer := newIOSXRNormalizingConsumer(consumertest.NewNop(), defaultIOSXRConfig(), deviceSelectionMatcher{}, iosXRTelemetryTransportDialOut, nil)
	assert.True(t, normalizer.Capabilities().MutatesData)
}

func TestIOSXRHealthTracksOnlyRunningSubscriptions(t *testing.T) {
	health := &iosXRHealth{}
	assert.True(t, health.setTargetSubscriptionActive("xr-1", true))
	assert.False(t, health.setTargetSubscriptionActive("xr-1", true))
	assert.True(t, health.setTargetSubscriptionActive("xr-2", true))
	assert.Equal(t, int64(2), health.snapshot().activeSubscriptions)
	assert.True(t, health.snapshotForTarget("xr-1").targetActive)
	assert.True(t, health.setTargetSubscriptionActive("xr-1", false))
	assert.Equal(t, int64(1), health.snapshot().activeSubscriptions)
	assert.False(t, health.snapshotForTarget("xr-1").targetActive)
	assert.True(t, health.setTargetSubscriptionActive("xr-2", false))
	assert.Equal(t, int64(0), health.snapshot().activeSubscriptions)
}

func TestIOSXRNormalizingConsumerRenamesDialOutMetricsAndAttributes(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	health := &iosXRHealth{}
	normalizer := newIOSXRNormalizingConsumer(
		sink,
		defaultIOSXRConfig(),
		newDeviceSelectionMatcher(DeviceSelectionConfig{}),
		iosXRTelemetryTransportDialOut,
		health,
	)

	raw := rawIOSXRDialOutMetrics("cisco.interface.statistics.rx-pkts", 7)
	raw.ResourceMetrics().At(0).Resource().Attributes().PutStr("host.ip", "192.0.2.30")
	raw.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Gauge().DataPoints().At(0).Attributes().PutStr("interface", "HundredGigE0/0/0/0")
	raw.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Gauge().DataPoints().At(0).Attributes().PutStr("vrf", "default")
	raw.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Gauge().DataPoints().At(0).Attributes().PutStr("neighbor-address", "192.0.2.2")
	err := normalizer.ConsumeMetrics(t.Context(), raw)
	require.NoError(t, err)
	require.Len(t, sink.AllMetrics(), 1)

	md := sink.AllMetrics()[0]
	metric := mustFindIOSXRMetric(t, md, "cisco.iosxr.yang.cisco_ios_xr_infra_statsd_oper.interface.statistics.rx_pkts")
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	assert.Equal(t, 7.0, metric.Gauge().DataPoints().At(0).DoubleValue())

	resourceAttrs := md.ResourceMetrics().At(0).Resource().Attributes()
	assert.Equal(t, "xr-1", attrValue(t, resourceAttrs, "host.name"))
	assert.Equal(t, "xr-1", attrValue(t, resourceAttrs, "host.id"))
	assert.Equal(t, []string{"192.0.2.30"}, stringSliceAttrValue(t, resourceAttrs))
	assert.Equal(t, "network", attrValue(t, resourceAttrs, "hw.type"))
	assert.Equal(t, "ios_xr", attrValue(t, resourceAttrs, "cisco.os.name"))
	assert.Equal(t, "ios_xr", attrValue(t, resourceAttrs, "cisco.platform.family"))
	assert.Equal(t, "mdt_grpc_dial_out", attrValue(t, resourceAttrs, "cisco.telemetry.transport"))
	_, hasResourceModule := resourceAttrs.Get("cisco.yang.module")
	assert.False(t, hasResourceModule, "YANG paths belong on datapoints so one device is not fragmented into many resources")
	_, hasResourcePath := resourceAttrs.Get("cisco.yang.path")
	assert.False(t, hasResourcePath)
	assert.Equal(t, "xr-1", attrValue(t, resourceAttrs, "cisco.node.id"))

	dpAttrs := metric.Gauge().DataPoints().At(0).Attributes()
	assert.Equal(t, "mdt_grpc_dial_out", attrValue(t, dpAttrs, "cisco.telemetry.transport"))
	assert.Equal(t, "Cisco-IOS-XR-infra-statsd-oper", attrValue(t, dpAttrs, "cisco.yang.module"))
	assert.Equal(t, "HundredGigE0/0/0/0", attrValue(t, dpAttrs, "network.interface.name"))
	assert.Equal(t, "default", attrValue(t, dpAttrs, "network.vrf.name"))
	assert.Equal(t, "192.0.2.2", attrValue(t, dpAttrs, "network.peer.address"))
}

func TestIOSXRNormalizingConsumerCoalescesStreamsAndPreservesIntDatapoints(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	normalizer := newIOSXRNormalizingConsumer(
		sink,
		defaultIOSXRConfig(),
		newDeviceSelectionMatcher(DeviceSelectionConfig{}),
		iosXRTelemetryTransportDialOut,
		&iosXRHealth{},
	)

	raw := pmetric.NewMetrics()
	rm := raw.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("cisco.node_id", "xr-1")
	rm.Resource().Attributes().PutStr("cisco.encoding_path", "Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/latest/generic-counters")
	sm := rm.ScopeMetrics().AppendEmpty()
	for iface, value := range map[string]int64{
		"GigabitEthernet0/0": math.MaxInt64,
		"GigabitEthernet0/1": 42,
	} {
		metric := sm.Metrics().AppendEmpty()
		metric.SetName("cisco.interface.statistics.rx-pkts")
		dp := metric.SetEmptyGauge().DataPoints().AppendEmpty()
		dp.SetIntValue(value)
		dp.Attributes().PutStr("interface", iface)
	}

	require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
	require.Len(t, sink.AllMetrics(), 1)
	const name = "cisco.iosxr.yang.cisco_ios_xr_infra_statsd_oper.interface.statistics.rx_pkts"
	md := sink.AllMetrics()[0]
	assert.Equal(t, 1, metricCountNamed(md, name))
	metric := mustFindIOSXRMetric(t, md, name)
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	dps := metric.Gauge().DataPoints()
	require.Equal(t, 2, dps.Len())
	values := make(map[string]int64, dps.Len())
	for i := 0; i < dps.Len(); i++ {
		dp := dps.At(i)
		assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
		values[attrValue(t, dp.Attributes(), "network.interface.name")] = dp.IntValue()
	}
	assert.Equal(t, map[string]int64{
		"GigabitEthernet0/0": math.MaxInt64,
		"GigabitEthernet0/1": 42,
	}, values)
}

func TestIOSXRNormalizingConsumerAppliesDeviceSelection(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	selector := newDeviceSelectionMatcher(DeviceSelectionConfig{
		Include: DeviceSelectionMatchConfig{HostNames: []string{"xr-2"}},
	})
	normalizer := newIOSXRNormalizingConsumer(sink, defaultIOSXRConfig(), selector, iosXRTelemetryTransportDialOut, &iosXRHealth{})

	err := normalizer.ConsumeMetrics(t.Context(), rawIOSXRDialOutMetrics("cisco.interface.statistics.rx-pkts", 7))
	require.NoError(t, err)
	assert.Empty(t, sink.AllMetrics())
}

func TestIOSXRNormalizingConsumerAllowsRootMetricFilteringAfterRename(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	filter := newMetricFilteringConsumer(sink, &Config{Metrics: map[string]MetricConfig{
		"cisco.iosxr.yang.cisco_ios_xr_infra_statsd_oper.interface.statistics.rx_pkts": {Enabled: false},
	}})
	normalizer := newIOSXRNormalizingConsumer(filter, defaultIOSXRConfig(), newDeviceSelectionMatcher(DeviceSelectionConfig{}), iosXRTelemetryTransportDialOut, &iosXRHealth{})

	err := normalizer.ConsumeMetrics(t.Context(), rawIOSXRDialOutMetrics("cisco.interface.statistics.rx-pkts", 7))
	require.NoError(t, err)
	assert.Empty(t, sink.AllMetrics())
}

func TestIOSXRNormalizingConsumerRenamesCompactGPBDiagnostic(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	health := &iosXRHealth{}
	normalizer := newIOSXRNormalizingConsumer(sink, defaultIOSXRConfig(), newDeviceSelectionMatcher(DeviceSelectionConfig{}), iosXRTelemetryTransportDialOut, health)

	err := normalizer.ConsumeMetrics(t.Context(), rawIOSXRDialOutMetrics("cisco.yang_grpc.compact_gpb_payloads", 3))
	require.NoError(t, err)
	require.Len(t, sink.AllMetrics(), 1)

	metric := mustFindIOSXRMetric(t, sink.AllMetrics()[0], "cisco.iosxr.receiver.compact_gpb_payloads")
	assert.Equal(t, 3.0, metric.Gauge().DataPoints().At(0).DoubleValue())
	assert.Equal(t, int64(3), health.snapshot().compactGPBPayloads)
}

func TestIOSXRNormalizingConsumerEnforcesDatapointLimit(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	health := &iosXRHealth{}
	cfg := defaultIOSXRConfig()
	cfg.MaxDatapointsPerBatch = 2
	normalizer := newIOSXRNormalizingConsumer(sink, cfg, newDeviceSelectionMatcher(DeviceSelectionConfig{}), iosXRTelemetryTransportDialOut, health)

	err := normalizer.ConsumeMetrics(t.Context(), rawIOSXRDialOutMultiDatapointMetric())
	require.NoError(t, err)
	require.Len(t, sink.AllMetrics(), 1)

	metric := mustFindIOSXRMetric(t, sink.AllMetrics()[0], "cisco.iosxr.yang.cisco_ios_xr_infra_statsd_oper.interface.statistics.rx_pkts")
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	assert.Equal(t, 2, metric.Gauge().DataPoints().Len())
	assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
}

func rawIOSXRDialOutMetrics(metricName string, value float64) pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("cisco.node_id", "xr-1")
	rm.Resource().Attributes().PutStr("cisco.encoding_path", "Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/latest/generic-counters")
	sm := rm.ScopeMetrics().AppendEmpty()
	metric := sm.Metrics().AppendEmpty()
	metric.SetName(metricName)
	dp := metric.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetDoubleValue(value)
	return md
}

func rawIOSXRDialOutMultiDatapointMetric() pmetric.Metrics {
	md := rawIOSXRDialOutMetrics("cisco.interface.statistics.rx-pkts", 1)
	dps := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Gauge().DataPoints()
	for _, value := range []float64{2, 3} {
		dp := dps.AppendEmpty()
		dp.SetDoubleValue(value)
	}
	return md
}
