// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"math"
	"strings"
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

func TestIOSXRHealthCountersSaturateAndIgnoreNegativeValues(t *testing.T) {
	health := &iosXRHealth{}
	health.addTargetUpdates("xr-1", math.MaxInt64)
	health.addTargetUpdates("xr-1", 1)
	health.addTargetUpdates("xr-1", -1)
	health.addDecodeErrors(math.MaxInt64)
	health.addDecodeErrors(1)
	health.addUnsupportedPaths(math.MaxInt64)
	health.addUnsupportedPaths(1)
	health.addTargetReconnects("xr-1", math.MaxInt64)
	health.addTargetReconnects("xr-1", 1)
	health.addDroppedDatapoints(math.MaxInt64)
	health.addDroppedDatapoints(1)

	snapshot := health.snapshotForTarget("xr-1")
	assert.Equal(t, int64(math.MaxInt64), snapshot.updatesReceived)
	assert.Equal(t, int64(math.MaxInt64), snapshot.targetUpdatesReceived)
	assert.Equal(t, int64(math.MaxInt64), snapshot.decodeErrors)
	assert.Equal(t, int64(math.MaxInt64), snapshot.unsupportedPaths)
	assert.Equal(t, int64(math.MaxInt64), snapshot.reconnects)
	assert.Equal(t, int64(math.MaxInt64), snapshot.targetReconnects)
	assert.Equal(t, int64(math.MaxInt64), snapshot.droppedDatapoints)
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
	metricName := mustDialOutDynamicYANGName(t, "cisco.iosxr.yang", "Cisco-IOS-XR-infra-statsd-oper",
		"Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/generic-counters", "interface/statistics/rx-pkts", dynamicYANGMetricVariantNumber)
	metric := mustFindIOSXRMetric(t, md, metricName)
	require.Equal(t, pmetric.MetricTypeSum, metric.Type())
	assert.True(t, metric.Sum().IsMonotonic())
	assert.Equal(t, pmetric.AggregationTemporalityCumulative, metric.Sum().AggregationTemporality())
	assert.Equal(t, int64(7), metric.Sum().DataPoints().At(0).IntValue())

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

	dpAttrs := metric.Sum().DataPoints().At(0).Attributes()
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
	rm.Resource().Attributes().PutStr("cisco.encoding_path", "Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/generic-counters")
	sm := rm.ScopeMetrics().AppendEmpty()
	for iface, value := range map[string]int64{
		"GigabitEthernet0/0": math.MaxInt64,
		"GigabitEthernet0/1": 42,
		"Null0":              0,
		"srte_c_100_ep_1":    7,
	} {
		metric := sm.Metrics().AppendEmpty()
		metric.SetName("cisco.interface.statistics.rx-pkts")
		dp := metric.SetEmptyGauge().DataPoints().AppendEmpty()
		dp.SetIntValue(value)
		dp.Attributes().PutStr("interface-name", iface)
		dp.Attributes().PutStr("cisco.yang.source_path", "interface/statistics/rx-pkts")
	}

	require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
	require.Len(t, sink.AllMetrics(), 1)
	name := mustDialOutDynamicYANGName(t, "cisco.iosxr.yang", "Cisco-IOS-XR-infra-statsd-oper",
		"Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/generic-counters", "interface/statistics/rx-pkts", dynamicYANGMetricVariantNumber)
	md := sink.AllMetrics()[0]
	assert.Equal(t, 1, metricCountNamed(md, name))
	metric := mustFindIOSXRMetric(t, md, name)
	require.Equal(t, pmetric.MetricTypeSum, metric.Type())
	assert.True(t, metric.Sum().IsMonotonic())
	assert.Equal(t, pmetric.AggregationTemporalityCumulative, metric.Sum().AggregationTemporality())
	dps := metric.Sum().DataPoints()
	require.Equal(t, 4, dps.Len())
	values := make(map[string]int64, dps.Len())
	for i := 0; i < dps.Len(); i++ {
		dp := dps.At(i)
		assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
		values[attrValue(t, dp.Attributes(), "network.interface.name")] = dp.IntValue()
	}
	assert.Equal(t, map[string]int64{
		"GigabitEthernet0/0": math.MaxInt64,
		"GigabitEthernet0/1": 42,
		"Null0":              0,
		"srte_c_100_ep_1":    7,
	}, values)
}

func TestIOSXRNormalizingConsumerKeepsCounterContainerStateAsGauge(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	normalizer := newIOSXRNormalizingConsumer(
		sink,
		defaultIOSXRConfig(),
		newDeviceSelectionMatcher(DeviceSelectionConfig{}),
		iosXRTelemetryTransportDialOut,
		&iosXRHealth{},
	)
	raw := rawIOSXRDialOutMetrics("cisco.seconds-since-packet-received", 12)

	require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
	metricName := mustDialOutDynamicYANGName(t, "cisco.iosxr.yang", "Cisco-IOS-XR-infra-statsd-oper",
		"Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/generic-counters", "seconds-since-packet-received", dynamicYANGMetricVariantNumber)
	metric := mustFindIOSXRMetric(t, sink.AllMetrics()[0], metricName)
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	assert.Equal(t, 12.0, metric.Gauge().DataPoints().At(0).DoubleValue())
}

func TestIOSXRNormalizingConsumerPreservesEscapedDeviceKeysForOwnedAttributes(t *testing.T) {
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
	resAttrs := rm.Resource().Attributes()
	resAttrs.PutStr("cisco.node_id", "xr-1")
	resAttrs.PutStr("cisco.encoding_path", "openconfig-system:system/state")
	metric := rm.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	metric.SetName("cisco.state")
	dp := metric.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetIntValue(1)
	dp.Attributes().PutStr("cisco.yang.source_path", "state")
	dp.Attributes().PutStr("cisco.key.cisco.yang.path", "device-path")
	dp.Attributes().PutStr("cisco.key.cisco.yang.module", "device-module")
	dp.Attributes().PutStr("cisco.key.cisco.telemetry.transport", "device-transport")

	require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
	require.Len(t, sink.AllMetrics(), 1)
	metricName := mustDialOutDynamicYANGName(t, "cisco.iosxr.yang", "openconfig-system", "openconfig-system:system/state", "state", dynamicYANGMetricVariantNumber)
	attrs := mustFindIOSXRMetric(t, sink.AllMetrics()[0], metricName).Gauge().DataPoints().At(0).Attributes()
	assert.Equal(t, "device-path", attrValue(t, attrs, "cisco.key.cisco.yang.path"))
	assert.Equal(t, "device-module", attrValue(t, attrs, "cisco.key.cisco.yang.module"))
	assert.Equal(t, "device-transport", attrValue(t, attrs, "cisco.key.cisco.telemetry.transport"))
	assert.Equal(t, "openconfig-system:system/state", attrValue(t, attrs, "cisco.yang.path"))
	assert.Equal(t, "openconfig-system", attrValue(t, attrs, "cisco.yang.module"))
	assert.Equal(t, iosXRTelemetryTransportDialOut, attrValue(t, attrs, "cisco.telemetry.transport"))
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
	metricName := mustDialOutDynamicYANGName(t, "cisco.iosxr.yang", "Cisco-IOS-XR-infra-statsd-oper",
		"Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/generic-counters", "interface/statistics/rx-pkts", dynamicYANGMetricVariantNumber)
	filter := newMetricFilteringConsumer(sink, &Config{Metrics: map[string]MetricConfig{metricName: {Enabled: false}}})
	normalizer := newIOSXRNormalizingConsumer(filter, defaultIOSXRConfig(), newDeviceSelectionMatcher(DeviceSelectionConfig{}), iosXRTelemetryTransportDialOut, &iosXRHealth{})

	err := normalizer.ConsumeMetrics(t.Context(), rawIOSXRDialOutMetrics("cisco.interface.statistics.rx-pkts", 7))
	require.NoError(t, err)
	assert.Empty(t, sink.AllMetrics())
}

func TestIOSXRNormalizingConsumerPreservesPerMessageCompactGPBDiagnostic(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	health := &iosXRHealth{}
	normalizer := newIOSXRNormalizingConsumer(sink, defaultIOSXRConfig(), newDeviceSelectionMatcher(DeviceSelectionConfig{}), iosXRTelemetryTransportDialOut, health)

	for index, observation := range []struct {
		target string
		value  float64
	}{
		{target: "xr-a", value: 3},
		{target: "xr-b", value: 2},
		{target: "xr-a", value: 1},
		{target: "", value: 4},
	} {
		raw := rawCompactGPBDiagnostic(observation.target, "test-module:state", int64(observation.value))
		require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
		require.Len(t, sink.AllMetrics(), index+1)
		md := sink.AllMetrics()[index]
		resourceAttrs := md.ResourceMetrics().At(0).Resource().Attributes()
		if observation.target == "" {
			_, present := resourceAttrs.Get("host.name")
			assert.False(t, present)
		} else {
			assert.Equal(t, observation.target, attrValue(t, resourceAttrs, "host.name"))
		}
		assertSingleIntGaugeMetric(t, md, "cisco.iosxr.receiver.compact_gpb_payloads", int64(observation.value))
	}
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

	metricName := mustDialOutDynamicYANGName(t, "cisco.iosxr.yang", "Cisco-IOS-XR-infra-statsd-oper",
		"Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/generic-counters", "interface/statistics/rx-pkts", dynamicYANGMetricVariantNumber)
	metric := mustFindIOSXRMetric(t, sink.AllMetrics()[0], metricName)
	require.Equal(t, pmetric.MetricTypeSum, metric.Type())
	assert.Equal(t, 2, metric.Sum().DataPoints().Len())
	assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
}

func TestIOSXRNormalizingConsumerBudgetsLongPathBeforeDatapointCopy(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	health := &iosXRHealth{}
	cfg := defaultIOSXRConfig()
	cfg.MaxDatapointsPerBatch = 10
	path := "test-module:" + strings.Repeat("x", 512)
	transport := iosXRTelemetryTransportDialOut
	perDatapointBytes := len("cisco.yang.module") + len("test-module") +
		len("cisco.yang.path") + len(path) +
		len("cisco.telemetry.transport") + len(transport) +
		len("cisco.yang.source_path") + len("interface/statistics/rx-pkts")
	normalizer := newIOSXRNormalizingConsumer(
		sink,
		cfg,
		newDeviceSelectionMatcher(DeviceSelectionConfig{}),
		transport,
		health,
	).(*iosXRNormalizingConsumer)
	normalizer.budgetLimits = finalDatapointBudgetLimits{
		maxDatapoints:     10,
		maxAttributeBytes: perDatapointBytes,
	}
	raw := rawIOSXRDialOutMultiDatapointMetric()
	raw.ResourceMetrics().At(0).Resource().Attributes().PutStr("cisco.encoding_path", path)

	require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
	require.Len(t, sink.AllMetrics(), 1)
	metricName := mustDialOutDynamicYANGName(t, "cisco.iosxr.yang", "test-module", path, "interface/statistics/rx-pkts", dynamicYANGMetricVariantNumber)
	metric := mustFindIOSXRMetric(t, sink.AllMetrics()[0], metricName)
	require.Equal(t, 1, metric.Sum().DataPoints().Len())
	assert.Equal(t, path, attrValue(t, metric.Sum().DataPoints().At(0).Attributes(), "cisco.yang.path"))
	assert.Equal(t, int64(2), health.snapshot().droppedDatapoints)
}

func TestIOSXRNormalizingConsumerRejectsNonNumberDynamicDatapoints(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	health := &iosXRHealth{}
	cfg := defaultIOSXRConfig()
	cfg.MaxDatapointsPerBatch = 3
	normalizer := newIOSXRNormalizingConsumer(
		sink,
		cfg,
		newDeviceSelectionMatcher(DeviceSelectionConfig{}),
		iosXRTelemetryTransportDialOut,
		health,
	)

	require.NoError(t, normalizer.ConsumeMetrics(t.Context(), rawDialOutNonNumberMetrics("xr-1")))
	assert.Empty(t, sink.AllMetrics())
	assert.Equal(t, int64(3), health.snapshot().droppedDatapoints)

	limitedSink := &consumertest.MetricsSink{}
	limitedHealth := &iosXRHealth{}
	cfg.MaxDatapointsPerBatch = 2
	limited := newIOSXRNormalizingConsumer(
		limitedSink,
		cfg,
		newDeviceSelectionMatcher(DeviceSelectionConfig{}),
		iosXRTelemetryTransportDialOut,
		limitedHealth,
	)
	require.NoError(t, limited.ConsumeMetrics(t.Context(), rawDialOutNonNumberMetrics("xr-1")))
	assert.Empty(t, limitedSink.AllMetrics())
	assert.Equal(t, int64(3), limitedHealth.snapshot().droppedDatapoints)
}

func TestIOSXRNormalizingConsumerRejectsNestedIdentityAttributeBeforeStringConversion(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	health := &iosXRHealth{}
	normalizer := newIOSXRNormalizingConsumer(
		sink,
		defaultIOSXRConfig(),
		newDeviceSelectionMatcher(DeviceSelectionConfig{}),
		iosXRTelemetryTransportDialOut,
		health,
	).(*iosXRNormalizingConsumer)
	normalizer.budgetLimits = finalDatapointBudgetLimits{
		maxAttributeBytes: 1_000,
		maxAttributeDepth: 2,
		maxAttributeNodes: 10,
	}
	raw := rawIOSXRDialOutMetrics("cisco.interface.state", 1)
	attrs := raw.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Gauge().DataPoints().At(0).Attributes()
	level := attrs.PutEmptyMap("interface").PutEmptyMap("child")
	level.PutEmptySlice("grandchild")

	require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
	assert.Empty(t, sink.AllMetrics())
	assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
}

func TestIOSXRNormalizingConsumerEnforcesFinalAttributeShapeAfterAnnotations(t *testing.T) {
	for _, test := range []struct {
		name           string
		sourceAttrs    int
		wantDelivered  bool
		wantFinalAttrs int
		wantDropped    int64
	}{
		{name: "exactly 64 attributes", sourceAttrs: 60, wantDelivered: true, wantFinalAttrs: 64},
		{name: "annotation exceeds 64 attributes", sourceAttrs: 61, wantDropped: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			sink := &consumertest.MetricsSink{}
			health := &iosXRHealth{}
			normalizer := newIOSXRNormalizingConsumer(
				sink,
				defaultIOSXRConfig(),
				newDeviceSelectionMatcher(DeviceSelectionConfig{}),
				iosXRTelemetryTransportDialOut,
				health,
			)
			raw := rawIOSXRDialOutMetrics("cisco.interface.state", 1)
			attrs := raw.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Gauge().DataPoints().At(0).Attributes()
			applyStringAttrs(attrs, numberedStringAttrs(test.sourceAttrs))

			require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
			if test.wantDelivered {
				require.Len(t, sink.AllMetrics(), 1)
				metricName := mustDialOutDynamicYANGName(t, "cisco.iosxr.yang", "Cisco-IOS-XR-infra-statsd-oper",
					"Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/generic-counters", "interface/state", dynamicYANGMetricVariantNumber)
				metric := mustFindIOSXRMetric(t, sink.AllMetrics()[0], metricName)
				assert.Equal(t, test.wantFinalAttrs, metric.Sum().DataPoints().At(0).Attributes().Len())
			} else {
				assert.Empty(t, sink.AllMetrics())
			}
			assert.Equal(t, test.wantDropped, health.snapshot().droppedDatapoints)
		})
	}
}

func TestIOSXRNormalizingConsumerRejectsOversizedFinalPathAttribute(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	health := &iosXRHealth{}
	normalizer := newIOSXRNormalizingConsumer(
		sink,
		defaultIOSXRConfig(),
		newDeviceSelectionMatcher(DeviceSelectionConfig{}),
		iosXRTelemetryTransportDialOut,
		health,
	)
	raw := rawIOSXRDialOutMetrics("cisco.interface.state", 1)
	raw.ResourceMetrics().At(0).Resource().Attributes().PutStr(
		"cisco.encoding_path",
		"test-module:"+strings.Repeat("x", directGNMIHardMaxAttributeValueBytes),
	)

	require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
	assert.Empty(t, sink.AllMetrics())
	assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
}

func TestCoalesceMetricStreamsRequiresCompatibleDescriptors(t *testing.T) {
	md := pmetric.NewMetrics()
	sm := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	appendSum := func(temporality pmetric.AggregationTemporality) {
		metric := sm.Metrics().AppendEmpty()
		metric.SetName("test.sum")
		metric.SetDescription("counter")
		metric.SetUnit("By")
		sum := metric.SetEmptySum()
		sum.SetIsMonotonic(true)
		sum.SetAggregationTemporality(temporality)
		sum.DataPoints().AppendEmpty().SetIntValue(1)
	}
	appendSum(pmetric.AggregationTemporalityCumulative)
	appendSum(pmetric.AggregationTemporalityDelta)
	appendSum(pmetric.AggregationTemporalityDelta)

	for _, unit := range []string{"By", "{packet}"} {
		metric := sm.Metrics().AppendEmpty()
		metric.SetName("test.gauge")
		metric.SetUnit(unit)
		metric.SetEmptyGauge().DataPoints().AppendEmpty().SetIntValue(1)
	}

	coalesceMetricStreams(sm)
	require.Equal(t, 4, sm.Metrics().Len(), "incompatible sum aggregation and gauge units must remain separate streams")
	var cumulativePoints, deltaPoints int
	for i := 0; i < sm.Metrics().Len(); i++ {
		metric := sm.Metrics().At(i)
		if metric.Type() != pmetric.MetricTypeSum {
			continue
		}
		switch metric.Sum().AggregationTemporality() {
		case pmetric.AggregationTemporalityCumulative:
			cumulativePoints = metric.Sum().DataPoints().Len()
		case pmetric.AggregationTemporalityDelta:
			deltaPoints = metric.Sum().DataPoints().Len()
		}
	}
	assert.Equal(t, 1, cumulativePoints)
	assert.Equal(t, 2, deltaPoints, "compatible delta streams should still coalesce")
}

func rawIOSXRDialOutMetrics(metricName string, value float64) pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("cisco.node_id", "xr-1")
	rm.Resource().Attributes().PutStr("cisco.encoding_path", "Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/generic-counters")
	sm := rm.ScopeMetrics().AppendEmpty()
	metric := sm.Metrics().AppendEmpty()
	metric.SetName(metricName)
	dp := metric.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetDoubleValue(value)
	dp.Attributes().PutStr("cisco.yang.source_path", strings.ReplaceAll(strings.TrimPrefix(metricName, "cisco."), ".", "/"))
	return md
}

func rawIOSXRDialOutMultiDatapointMetric() pmetric.Metrics {
	md := rawIOSXRDialOutMetrics("cisco.interface.statistics.rx-pkts", 1)
	dps := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Gauge().DataPoints()
	for _, value := range []float64{2, 3} {
		dp := dps.AppendEmpty()
		dp.SetDoubleValue(value)
		dp.Attributes().PutStr("cisco.yang.source_path", "interface/statistics/rx-pkts")
	}
	return md
}

func rawDialOutNonNumberMetrics(nodeID string) pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("cisco.node_id", nodeID)
	rm.Resource().Attributes().PutStr("cisco.encoding_path", "test-module:state")
	metrics := rm.ScopeMetrics().AppendEmpty().Metrics()

	histogram := metrics.AppendEmpty()
	histogram.SetName("cisco.histogram")
	histogramAttrs := histogram.SetEmptyHistogram().DataPoints().AppendEmpty().Attributes()
	histogramAttrs.PutStr("source", "histogram")
	histogramAttrs.PutStr("cisco.yang.source_path", "histogram")

	exponential := metrics.AppendEmpty()
	exponential.SetName("cisco.exponential-histogram")
	exponentialAttrs := exponential.SetEmptyExponentialHistogram().DataPoints().AppendEmpty().Attributes()
	exponentialAttrs.PutStr("source", "exponential")
	exponentialAttrs.PutStr("cisco.yang.source_path", "exponential-histogram")

	summary := metrics.AppendEmpty()
	summary.SetName("cisco.summary")
	summaryAttrs := summary.SetEmptySummary().DataPoints().AppendEmpty().Attributes()
	summaryAttrs.PutStr("source", "summary")
	summaryAttrs.PutStr("cisco.yang.source_path", "summary")
	return md
}

func rawCompactGPBDiagnostic(nodeID, encodingPath string, value int64) pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("cisco.node_id", nodeID)
	rm.Resource().Attributes().PutStr("cisco.encoding_path", encodingPath)
	metric := rm.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	metric.SetName("cisco.yang_grpc.compact_gpb_payloads")
	dp := metric.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetIntValue(value)
	dp.Attributes().PutStr("node_id", nodeID)
	dp.Attributes().PutStr("encoding_path", encodingPath)
	return md
}
