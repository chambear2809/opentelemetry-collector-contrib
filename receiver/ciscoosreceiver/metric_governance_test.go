// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

func TestGovernedFixedMetricMetadataRejectsRuntimeDescriptorDrift(t *testing.T) {
	const name = "cisco.iosxr.receiver.compact_gpb_payloads"
	require.Panics(t, func() {
		governedFixedMetricMetadata(name, pmetric.MetricTypeSum, fixedMetricValueTypeInt, "", "")
	})
	require.Panics(t, func() {
		governedFixedMetricMetadata(name, pmetric.MetricTypeGauge, fixedMetricValueTypeDouble, "", "")
	})
}

func TestGovernedFixedMetricMetadataLeavesCustomDescriptorsUnchanged(t *testing.T) {
	description, unit := governedFixedMetricMetadata(
		"example.custom.metric",
		pmetric.MetricTypeGauge,
		fixedMetricValueTypeDouble,
		"Configured description.",
		"ms",
	)
	require.Equal(t, "Configured description.", description)
	require.Equal(t, "ms", unit)
}

func TestReceiverHealthWireDescriptorsAreGovernedIntegers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		append  func(pmetric.Metrics)
		metrics []string
		compact string
	}{
		{
			name: "ios_xr",
			append: func(md pmetric.Metrics) {
				appendIOSXRHealthMetrics(md, &iosXRHealth{}, iosXRMetricContext{targetName: "xr-1"}, 0)
			},
			metrics: []string{
				"cisco.iosxr.receiver.active_subscriptions",
				"cisco.iosxr.receiver.updates",
				"cisco.iosxr.receiver.decode_errors",
				"cisco.iosxr.receiver.unsupported_paths",
				"cisco.iosxr.receiver.reconnects",
				"cisco.iosxr.receiver.dropped_datapoints",
				"cisco.iosxr.receiver.target.subscription.active",
				"cisco.iosxr.receiver.target.updates",
				"cisco.iosxr.receiver.target.reconnects",
			},
			compact: "cisco.iosxr.receiver.compact_gpb_payloads",
		},
		{
			name: "catalyst_9800",
			append: func(md pmetric.Metrics) {
				appendCatalyst9800HealthMetrics(md, &catalyst9800Health{}, catalyst9800MetricContext{targetName: "wlc-1"}, 0)
			},
			metrics: []string{
				"cisco.catalyst9800.receiver.active_subscriptions",
				"cisco.catalyst9800.receiver.updates",
				"cisco.catalyst9800.receiver.decode_errors",
				"cisco.catalyst9800.receiver.unsupported_paths",
				"cisco.catalyst9800.receiver.reconnects",
				"cisco.catalyst9800.receiver.dropped_datapoints",
				"cisco.wlc.controller.receiver.active_subscriptions",
				"cisco.wlc.controller.receiver.updates",
				"cisco.wlc.controller.receiver.decode_errors",
				"cisco.catalyst9800.receiver.target.subscription.active",
				"cisco.catalyst9800.receiver.target.updates",
				"cisco.catalyst9800.receiver.target.reconnects",
				"cisco.wlc.controller.receiver.subscription.active",
			},
			compact: "cisco.catalyst9800.receiver.compact_gpb_payloads",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			md := pmetric.NewMetrics()
			tc.append(md)
			actual := metricNames(md)
			expected := make(map[string]int, len(tc.metrics))
			for _, name := range tc.metrics {
				expected[name] = 1
				assertMetricMatchesFixedDescriptor(t, mustFindIOSXRMetric(t, md, name))
			}
			require.Equal(t, expected, actual)
			require.NotContains(t, actual, tc.compact, "compact GPB is emitted only from the per-notification diagnostic path")
		})
	}
}

func assertMetricMatchesFixedDescriptor(t *testing.T, metric pmetric.Metric) {
	t.Helper()
	descriptor, ok := fixedMetricDescriptors[metric.Name()]
	require.Truef(t, ok, "missing fixed descriptor for %s", metric.Name())
	require.Equal(t, descriptor.description, metric.Description(), metric.Name())
	require.Equal(t, descriptor.unit, metric.Unit(), metric.Name())

	assertValueType := func(dataPoints pmetric.NumberDataPointSlice) {
		for index := 0; index < dataPoints.Len(); index++ {
			actual := dataPoints.At(index).ValueType()
			if descriptor.valueType == fixedMetricValueTypeInt {
				require.Equal(t, pmetric.NumberDataPointValueTypeInt, actual, metric.Name())
			} else {
				require.Equal(t, pmetric.NumberDataPointValueTypeDouble, actual, metric.Name())
			}
		}
	}

	switch descriptor.instrument {
	case fixedMetricInstrumentGauge:
		require.Equal(t, pmetric.MetricTypeGauge, metric.Type(), metric.Name())
		assertValueType(metric.Gauge().DataPoints())
	case fixedMetricInstrumentSum:
		require.Equal(t, pmetric.MetricTypeSum, metric.Type(), metric.Name())
		require.Equal(t, descriptor.monotonic, metric.Sum().IsMonotonic(), metric.Name())
		require.Equal(t, pmetric.AggregationTemporalityCumulative, metric.Sum().AggregationTemporality(), metric.Name())
		assertValueType(metric.Sum().DataPoints())
	default:
		require.FailNow(t, "unsupported fixed metric instrument", metric.Name())
	}
}
