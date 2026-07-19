// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

func TestCatalyst9800NormalizingConsumerDeclaresMutation(t *testing.T) {
	normalizer := newCatalyst9800NormalizingConsumer(consumertest.NewNop(), defaultCatalyst9800Config(), deviceSelectionMatcher{}, catalyst9800TelemetryTransportDialOut, nil)
	assert.True(t, normalizer.Capabilities().MutatesData)
}

func TestCatalyst9800NormalizingConsumerPreservesPerMessageCompactGPBDiagnostic(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	health := &catalyst9800Health{}
	normalizer := newCatalyst9800NormalizingConsumer(
		sink,
		defaultCatalyst9800Config(),
		newDeviceSelectionMatcher(DeviceSelectionConfig{}),
		catalyst9800TelemetryTransportDialOut,
		health,
	)

	for index, observation := range []struct {
		target string
		value  float64
	}{
		{target: "wlc-a", value: 3},
		{target: "wlc-b", value: 2},
		{target: "wlc-a", value: 1},
		{target: "", value: 4},
	} {
		require.NoError(t, normalizer.ConsumeMetrics(t.Context(), rawCompactGPBDiagnostic(
			observation.target,
			"test-module:state",
			int64(observation.value),
		)))
		require.Len(t, sink.AllMetrics(), index+1)
		md := sink.AllMetrics()[index]
		resourceAttrs := md.ResourceMetrics().At(0).Resource().Attributes()
		if observation.target == "" {
			_, present := resourceAttrs.Get("host.name")
			assert.False(t, present)
		} else {
			assert.Equal(t, observation.target, attrValue(t, resourceAttrs, "host.name"))
		}
		assertSingleIntGaugeMetric(t, md, "cisco.catalyst9800.receiver.compact_gpb_payloads", int64(observation.value))
	}
}

func TestCatalyst9800PercentageRatioIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value float64
		want  float64
		ok    bool
	}{
		{name: "zero", value: 0, ok: true},
		{name: "one percent", value: 1, want: 0.01, ok: true},
		{name: "one hundred percent", value: 100, want: 1, ok: true},
		{name: "negative", value: -1},
		{name: "over one hundred", value: 101},
		{name: "not a number", value: math.NaN()},
		{name: "infinite", value: math.Inf(1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := catalyst9800PercentageRatio(tc.value)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCatalyst9800AliasPreservesPresentEmptyIdentity(t *testing.T) {
	source := pmetric.NewMetrics()
	sourceMetric := source.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	sourceMetric.SetName("cisco.noise")
	dps := sourceMetric.SetEmptyGauge().DataPoints()
	withEmptyIdentity := dps.AppendEmpty()
	withEmptyIdentity.SetIntValue(-90)
	withEmptyIdentity.SetTimestamp(pcommon.Timestamp(1))
	withEmptyIdentity.Attributes().PutStr("cisco.yang.key.wtp_mac", "")
	withoutIdentity := dps.AppendEmpty()
	withoutIdentity.SetIntValue(-91)
	withoutIdentity.SetTimestamp(pcommon.Timestamp(1))

	aliases := pmetric.NewMetrics()
	aliasScope := aliases.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	appendCatalyst9800AliasesFromMetric(
		newIndexedMetricBuilder(aliasScope, nil),
		sourceMetric,
		"wireless-rrm-oper",
		[]string{"noise"},
		false,
		"wireless-rrm-oper:rrm-oper-data/noise",
		catalyst9800TelemetryTransportDialOut,
	)

	alias := mustFindIOSXRMetric(t, aliases, "cisco.wlc.rf.noise_floor")
	aliasDPs := alias.Gauge().DataPoints()
	require.Equal(t, 2, aliasDPs.Len())
	presentEmpty := 0
	missing := 0
	for index := 0; index < aliasDPs.Len(); index++ {
		value, present := aliasDPs.At(index).Attributes().Get("cisco.yang.key.wtp_mac")
		if present {
			assert.Empty(t, value.Str())
			presentEmpty++
		} else {
			missing++
		}
	}
	assert.Equal(t, 1, presentEmpty)
	assert.Equal(t, 1, missing)
}

func TestCatalyst9800NormalizerAliasPreservesArbitraryPresentEmptyYANGKey(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	normalizer := newCatalyst9800NormalizingConsumer(
		sink,
		defaultCatalyst9800Config(),
		newDeviceSelectionMatcher(DeviceSelectionConfig{}),
		catalyst9800TelemetryTransportDialOut,
		&catalyst9800Health{},
	)

	raw := pmetric.NewMetrics()
	rm := raw.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("cisco.node_id", "wlc-1")
	rm.Resource().Attributes().PutStr("cisco.encoding_path", "wireless-rrm-oper:rrm-oper-data/noise")
	metric := rm.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	metric.SetName("cisco.noise")
	dps := metric.SetEmptyGauge().DataPoints()
	withEmptyKey := dps.AppendEmpty()
	withEmptyKey.SetIntValue(-90)
	withEmptyKey.Attributes().PutStr("tenant-code", "")
	withEmptyKey.Attributes().PutStr("cisco.yang.source_path", "noise")
	withoutKey := dps.AppendEmpty()
	withoutKey.SetIntValue(-91)
	withoutKey.Attributes().PutStr("cisco.yang.source_path", "noise")

	require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
	require.Len(t, sink.AllMetrics(), 1)
	alias := mustFindIOSXRMetric(t, sink.AllMetrics()[0], "cisco.wlc.rf.noise_floor")
	aliasDPs := alias.Gauge().DataPoints()
	require.Equal(t, 2, aliasDPs.Len())
	presentEmpty := 0
	missing := 0
	for index := 0; index < aliasDPs.Len(); index++ {
		value, present := aliasDPs.At(index).Attributes().Get("tenant-code")
		if present {
			assert.Empty(t, value.Str())
			presentEmpty++
		} else {
			missing++
		}
	}
	assert.Equal(t, 1, presentEmpty)
	assert.Equal(t, 1, missing)
}

func TestCatalyst9800NormalizingConsumerCoalescesStreamsAndPreservesIntDatapoints(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	normalizer := newCatalyst9800NormalizingConsumer(
		sink,
		defaultCatalyst9800Config(),
		newDeviceSelectionMatcher(DeviceSelectionConfig{}),
		catalyst9800TelemetryTransportDialOut,
		&catalyst9800Health{},
	)

	raw := pmetric.NewMetrics()
	rm := raw.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("cisco.node_id", "wlc-1")
	rm.Resource().Attributes().PutStr("cisco.encoding_path", "wireless-access-point-oper:access-point-oper-data/ssid-counters")
	sm := rm.ScopeMetrics().AppendEmpty()
	for apMAC, value := range map[string]int64{
		"AA:BB:CC:DD:EE:01": math.MaxInt64,
		"AA:BB:CC:DD:EE:02": 1<<53 + 1,
		"AA:BB:CC:DD:EE:03": 42,
	} {
		metric := sm.Metrics().AppendEmpty()
		metric.SetName("cisco.access-point-oper-data.ssid-counters.tx-bytes-data")
		dp := metric.SetEmptyGauge().DataPoints().AppendEmpty()
		dp.SetIntValue(value)
		dp.Attributes().PutStr("wtp-mac", apMAC)
		dp.Attributes().PutStr("cisco.yang.source_path", "access-point-oper-data/ssid-counters/tx-bytes-data")
	}

	require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
	require.Len(t, sink.AllMetrics(), 1)
	md := sink.AllMetrics()[0]

	canonical := mustDialOutDynamicYANGName(t, "cisco.catalyst9800.yang", "wireless-access-point-oper",
		"wireless-access-point-oper:access-point-oper-data/ssid-counters", "access-point-oper-data/ssid-counters/tx-bytes-data", dynamicYANGMetricVariantNumber)
	assert.Equal(t, 1, metricCountNamed(md, canonical))
	canonicalMetric := mustFindIOSXRMetric(t, md, canonical)
	assertIntSumDatapointsByAttr(t, canonicalMetric, "wtp-mac", map[string]int64{
		"AA:BB:CC:DD:EE:01": math.MaxInt64,
		"AA:BB:CC:DD:EE:02": 1<<53 + 1,
		"AA:BB:CC:DD:EE:03": 42,
	})

	const alias = "cisco.wlc.ssid.network.io"
	assert.Equal(t, 1, metricCountNamed(md, alias))
	assertCatalyst9800IntDatapointsByAP(t, mustFindIOSXRMetric(t, md, alias), map[string]int64{
		"AA:BB:CC:DD:EE:01": math.MaxInt64,
		"AA:BB:CC:DD:EE:02": 1<<53 + 1,
		"AA:BB:CC:DD:EE:03": 42,
	})
}

func TestCatalyst9800NormalizingConsumerRejectsFractionalIntegerAlias(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	health := &catalyst9800Health{}
	normalizer := newCatalyst9800NormalizingConsumer(
		sink,
		defaultCatalyst9800Config(),
		newDeviceSelectionMatcher(DeviceSelectionConfig{}),
		catalyst9800TelemetryTransportDialOut,
		health,
	)
	raw := rawCatalyst9800DialOutMetrics("cisco.access-point-oper-data.ssid-counters.tx-bytes-data", 1.5, "wlc-1")

	require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
	assert.Empty(t, sink.AllMetrics(), "fractional values for path-classified counters must be dropped, not rounded")
	assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
}

func TestCatalyst9800NormalizingConsumerPreservesBuiltinNumFlapsSumAndRejectsConflicts(t *testing.T) {
	const encodingPath = "Cisco-IOS-XE-interfaces-oper:interfaces/interface/statistics"

	for _, test := range []struct {
		name        string
		leaf        string
		mutate      func(pmetric.Metric)
		wantMetric  bool
		wantDropped int64
	}{
		{
			name:       "built-in num-flaps cumulative sum",
			leaf:       "num-flaps",
			wantMetric: true,
		},
		{
			name:        "sum conflicts with built-in rate gauge",
			leaf:        "rx-pps",
			wantDropped: 1,
		},
		{
			name: "delta num-flaps sum",
			leaf: "num-flaps",
			mutate: func(metric pmetric.Metric) {
				metric.Sum().SetAggregationTemporality(pmetric.AggregationTemporalityDelta)
			},
			wantDropped: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sink := &consumertest.MetricsSink{}
			health := &catalyst9800Health{}
			normalizer := newCatalyst9800NormalizingConsumer(
				sink,
				defaultCatalyst9800Config(),
				newDeviceSelectionMatcher(DeviceSelectionConfig{}),
				catalyst9800TelemetryTransportDialOut,
				health,
			)
			sourcePath := "interface/statistics/" + test.leaf
			raw := rawDynamicYANGDialOutMetric(
				encodingPath,
				"",
				"cisco.interface.statistics."+test.leaf,
				sourcePath,
				pmetric.MetricTypeSum,
				intMetricNumber(7),
			)
			if test.mutate != nil {
				test.mutate(raw.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0))
			}

			require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
			if test.wantMetric {
				name := mustDialOutDynamicYANGName(
					t,
					"cisco.catalyst9800.yang",
					"Cisco-IOS-XE-interfaces-oper",
					encodingPath,
					sourcePath,
					dynamicYANGMetricVariantNumber,
				)
				metric := mustFindMetricExactInBatches(t, sink.AllMetrics(), name)
				require.Equal(t, pmetric.MetricTypeSum, metric.Type())
				assert.True(t, metric.Sum().IsMonotonic())
				assert.Equal(t, pmetric.AggregationTemporalityCumulative, metric.Sum().AggregationTemporality())
				assert.Equal(t, int64(7), metric.Sum().DataPoints().At(0).IntValue())
			} else {
				assert.Empty(t, sink.AllMetrics())
			}
			assert.Equal(t, test.wantDropped, health.snapshot().droppedDatapoints)
		})
	}
}

func TestCatalyst9800NormalizingConsumerPrioritizesCanonicalPointsBeforeAliases(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	health := &catalyst9800Health{}
	cfg := defaultCatalyst9800Config()
	cfg.MaxDatapointsPerBatch = 3
	normalizer := newCatalyst9800NormalizingConsumer(
		sink,
		cfg,
		newDeviceSelectionMatcher(DeviceSelectionConfig{}),
		catalyst9800TelemetryTransportDialOut,
		health,
	)

	raw := pmetric.NewMetrics()
	rm := raw.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("cisco.node_id", "wlc-1")
	rm.Resource().Attributes().PutStr("cisco.encoding_path", "wireless-access-point-oper:access-point-oper-data/ssid-counters")
	sm := rm.ScopeMetrics().AppendEmpty()
	for i, apMAC := range []string{"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"} {
		metric := sm.Metrics().AppendEmpty()
		metric.SetName("cisco.access-point-oper-data.ssid-counters.tx-bytes-data")
		dp := metric.SetEmptyGauge().DataPoints().AppendEmpty()
		dp.SetIntValue(int64(i + 1))
		dp.Attributes().PutStr("wtp-mac", apMAC)
		dp.Attributes().PutStr("cisco.yang.source_path", "access-point-oper-data/ssid-counters/tx-bytes-data")
	}

	require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
	require.Len(t, sink.AllMetrics(), 1)
	md := sink.AllMetrics()[0]
	canonical := mustDialOutDynamicYANGName(t, "cisco.catalyst9800.yang", "wireless-access-point-oper",
		"wireless-access-point-oper:access-point-oper-data/ssid-counters", "access-point-oper-data/ssid-counters/tx-bytes-data", dynamicYANGMetricVariantNumber)
	canonicalMetric := mustFindIOSXRMetric(t, md, canonical)
	require.Equal(t, 2, canonicalMetric.Sum().DataPoints().Len(), "canonical datapoints must consume the budget first")
	aliasMetric := mustFindIOSXRMetric(t, md, "cisco.wlc.ssid.network.io")
	require.Equal(t, 1, aliasMetric.Sum().DataPoints().Len(), "only the remaining budget may be used for aliases")
	assert.Equal(t, 3, md.DataPointCount())
	assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
}

func TestCatalyst9800NormalizingConsumerAccountsAliasAttributeBytes(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	health := &catalyst9800Health{}
	cfg := defaultCatalyst9800Config()
	cfg.MaxDatapointsPerBatch = 10
	path := "wireless-access-point-oper:access-point-oper-data/ssid-counters"
	module := "wireless-access-point-oper"
	transport := catalyst9800TelemetryTransportDialOut
	apMAC := "AA:BB:CC:DD:EE:01"
	canonicalAttributeBytes := len("wtp-mac") + len(apMAC) +
		len("cisco.yang.source_path") + len("access-point-oper-data/ssid-counters/tx-bytes-data") +
		len("cisco.yang.module") + len(module) +
		len("cisco.yang.path") + len(path) +
		len("cisco.telemetry.transport") + len(transport)
	normalizer := newCatalyst9800NormalizingConsumer(
		sink,
		cfg,
		newDeviceSelectionMatcher(DeviceSelectionConfig{}),
		transport,
		health,
	).(*catalyst9800NormalizingConsumer)
	normalizer.budgetLimits = finalDatapointBudgetLimits{
		maxDatapoints:     10,
		maxAttributeBytes: canonicalAttributeBytes,
	}

	raw := pmetric.NewMetrics()
	rm := raw.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("cisco.node_id", "wlc-1")
	rm.Resource().Attributes().PutStr("cisco.encoding_path", path)
	metric := rm.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	metric.SetName("cisco.access-point-oper-data.ssid-counters.tx-bytes-data")
	dp := metric.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetIntValue(1)
	dp.Attributes().PutStr("wtp-mac", apMAC)
	dp.Attributes().PutStr("cisco.yang.source_path", "access-point-oper-data/ssid-counters/tx-bytes-data")

	require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
	require.Len(t, sink.AllMetrics(), 1)
	md := sink.AllMetrics()[0]
	canonical := mustDialOutDynamicYANGName(t, "cisco.catalyst9800.yang", module, path, "access-point-oper-data/ssid-counters/tx-bytes-data", dynamicYANGMetricVariantNumber)
	require.Equal(t, 1, mustFindIOSXRMetric(t, md, canonical).Sum().DataPoints().Len())
	assert.Zero(t, metricCountNamed(md, "cisco.wlc.ssid.network.io"), "an alias must not be created after its attributes exceed the shared budget")
	assert.Equal(t, 1, md.DataPointCount())
	assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
}

func TestCatalyst9800NormalizingConsumerEnforcesFinalAliasAttributeCount(t *testing.T) {
	for _, test := range []struct {
		name          string
		sourceAttrs   int
		wantAlias     bool
		wantDropped   int64
		wantAliasAttr int
	}{
		{name: "alias exactly 64 attributes", sourceAttrs: 59, wantAlias: true, wantAliasAttr: 64},
		{name: "alias exceeds 64 attributes", sourceAttrs: 60, wantDropped: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			sink := &consumertest.MetricsSink{}
			health := &catalyst9800Health{}
			cfg := defaultCatalyst9800Config()
			cfg.MaxDatapointsPerBatch = 10
			normalizer := newCatalyst9800NormalizingConsumer(
				sink,
				cfg,
				newDeviceSelectionMatcher(DeviceSelectionConfig{}),
				catalyst9800TelemetryTransportDialOut,
				health,
			)

			raw := pmetric.NewMetrics()
			rm := raw.ResourceMetrics().AppendEmpty()
			rm.Resource().Attributes().PutStr("cisco.node_id", "wlc-1")
			rm.Resource().Attributes().PutStr("cisco.encoding_path", "wireless-access-point-oper:access-point-oper-data/ssid-counters")
			metric := rm.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
			metric.SetName("cisco.access-point-oper-data.ssid-counters.tx-bytes-data")
			dp := metric.SetEmptyGauge().DataPoints().AppendEmpty()
			dp.SetIntValue(1)
			applyStringAttrs(dp.Attributes(), numberedStringAttrs(test.sourceAttrs))
			dp.Attributes().PutStr("cisco.yang.source_path", "access-point-oper-data/ssid-counters/tx-bytes-data")

			require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
			require.Len(t, sink.AllMetrics(), 1)
			md := sink.AllMetrics()[0]
			canonical := mustDialOutDynamicYANGName(t, "cisco.catalyst9800.yang", "wireless-access-point-oper",
				"wireless-access-point-oper:access-point-oper-data/ssid-counters", "access-point-oper-data/ssid-counters/tx-bytes-data", dynamicYANGMetricVariantNumber)
			assert.Equal(t, test.sourceAttrs+4, mustFindIOSXRMetric(t, md, canonical).Sum().DataPoints().At(0).Attributes().Len())
			if test.wantAlias {
				alias := mustFindIOSXRMetric(t, md, "cisco.wlc.ssid.network.io")
				assert.Equal(t, test.wantAliasAttr, alias.Sum().DataPoints().At(0).Attributes().Len())
			} else {
				assert.Zero(t, metricCountNamed(md, "cisco.wlc.ssid.network.io"))
			}
			assert.Equal(t, test.wantDropped, health.snapshot().droppedDatapoints)
		})
	}
}

func TestCatalyst9800NormalizingConsumerRejectsNonNumberDynamicDatapoints(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	health := &catalyst9800Health{}
	cfg := defaultCatalyst9800Config()
	cfg.MaxDatapointsPerBatch = 3
	normalizer := newCatalyst9800NormalizingConsumer(
		sink,
		cfg,
		newDeviceSelectionMatcher(DeviceSelectionConfig{}),
		catalyst9800TelemetryTransportDialOut,
		health,
	)

	require.NoError(t, normalizer.ConsumeMetrics(t.Context(), rawDialOutNonNumberMetrics("wlc-1")))
	assert.Empty(t, sink.AllMetrics())
	assert.Equal(t, int64(3), health.snapshot().droppedDatapoints)

	limitedSink := &consumertest.MetricsSink{}
	limitedHealth := &catalyst9800Health{}
	cfg.MaxDatapointsPerBatch = 2
	limited := newCatalyst9800NormalizingConsumer(
		limitedSink,
		cfg,
		newDeviceSelectionMatcher(DeviceSelectionConfig{}),
		catalyst9800TelemetryTransportDialOut,
		limitedHealth,
	)
	require.NoError(t, limited.ConsumeMetrics(t.Context(), rawDialOutNonNumberMetrics("wlc-1")))
	assert.Empty(t, limitedSink.AllMetrics())
	assert.Equal(t, int64(3), limitedHealth.snapshot().droppedDatapoints)
}

func TestCatalyst9800ReasonAliasesRemainGaugeInfoForNumericEnums(t *testing.T) {
	md, sm := newCatalyst9800Metrics(catalyst9800MetricContext{targetName: "wlc-1"})
	ts := pcommon.NewTimestampFromTime(time.Unix(1, 0))
	path := []string{"ap-join-info", "last-join-failure-type"}
	appendCatalyst9800AliasesForValue(sm, "wireless-ap-global-oper", path, int64(7), ts, nil)
	appendCatalyst9800AliasesForValue(sm, "wireless-ap-global-oper", path, "certificate-error", ts, nil)

	metric := mustFindIOSXRMetric(t, md, "cisco.wlc.ap.join.failure.reason.info")
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	require.Equal(t, 2, metric.Gauge().DataPoints().Len())
	assert.Equal(t, "7", attrValue(t, metric.Gauge().DataPoints().At(0).Attributes(), "failure.reason"))
	assert.Equal(t, "certificate-error", attrValue(t, metric.Gauge().DataPoints().At(1).Attributes(), "failure.reason"))
	assert.False(t, isCatalyst9800CounterMetric(path))
}

func TestCatalyst9800CAPWAPStateAliasesEmitOneDatapoint(t *testing.T) {
	for _, leaf := range []string{"ap_operation_state", "capwap_state"} {
		t.Run(leaf, func(t *testing.T) {
			md, sm := newCatalyst9800Metrics(catalyst9800MetricContext{targetName: "wlc-1"})
			ts := pcommon.NewTimestampFromTime(time.Unix(1, 0))

			appendCatalyst9800AliasesForValue(
				sm,
				"wireless-access-point-oper",
				[]string{"capwap_data", leaf},
				"registered",
				ts,
				map[string]string{"wtp-mac": "AA:BB:CC:DD:EE:FF"},
			)

			metric := mustFindIOSXRMetric(t, md, "cisco.wlc.ap.capwap.state")
			require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
			require.Equal(t, 1, metric.Gauge().DataPoints().Len())
		})
	}
}

func TestCatalyst9800AliasAttrsPreserveCanonicalIdentity(t *testing.T) {
	attrs := catalyst9800AliasAttrs(map[string]string{
		"cisco.wlc.ap.mac": "canonical",
		"wtp-mac":          "legacy",
	})
	assert.Equal(t, "canonical", attrs["cisco.wlc.ap.mac"])

	empty := catalyst9800AliasAttrs(map[string]string{
		"cisco.wlc.ap.mac": "",
		"wtp-mac":          "fallback-must-not-win",
	})
	value, present := empty["cisco.wlc.ap.mac"]
	assert.True(t, present)
	assert.Empty(t, value)
}

func assertIntSumDatapointsByAttr(t *testing.T, metric pmetric.Metric, attr string, expected map[string]int64) {
	t.Helper()
	require.Equal(t, pmetric.MetricTypeSum, metric.Type())
	dps := metric.Sum().DataPoints()
	require.Equal(t, len(expected), dps.Len())
	actual := make(map[string]int64, dps.Len())
	for i := 0; i < dps.Len(); i++ {
		dp := dps.At(i)
		assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
		actual[attrValue(t, dp.Attributes(), attr)] = dp.IntValue()
	}
	assert.Equal(t, expected, actual)
}
