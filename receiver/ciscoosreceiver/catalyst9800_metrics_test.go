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
		"AA:BB:CC:DD:EE:02": 42,
	} {
		metric := sm.Metrics().AppendEmpty()
		metric.SetName("cisco.access-point-oper-data.ssid-counters.tx-bytes-data")
		dp := metric.SetEmptyGauge().DataPoints().AppendEmpty()
		dp.SetIntValue(value)
		dp.Attributes().PutStr("wtp-mac", apMAC)
	}

	require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
	require.Len(t, sink.AllMetrics(), 1)
	md := sink.AllMetrics()[0]

	const canonical = "cisco.catalyst9800.yang.wireless_access_point_oper.access_point_oper_data.ssid_counters.tx_bytes_data"
	assert.Equal(t, 1, metricCountNamed(md, canonical))
	canonicalMetric := mustFindIOSXRMetric(t, md, canonical)
	assertIntGaugeDatapointsByAttr(t, canonicalMetric, "wtp-mac", map[string]int64{
		"AA:BB:CC:DD:EE:01": math.MaxInt64,
		"AA:BB:CC:DD:EE:02": 42,
	})

	const alias = "cisco.wlc.ssid.network.io"
	assert.Equal(t, 1, metricCountNamed(md, alias))
	assertCatalyst9800IntDatapointsByAP(t, mustFindIOSXRMetric(t, md, alias), map[string]int64{
		"AA:BB:CC:DD:EE:01": math.MaxInt64,
		"AA:BB:CC:DD:EE:02": 42,
	})
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

func assertIntGaugeDatapointsByAttr(t *testing.T, metric pmetric.Metric, attr string, expected map[string]int64) {
	t.Helper()
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	dps := metric.Gauge().DataPoints()
	require.Equal(t, len(expected), dps.Len())
	actual := make(map[string]int64, dps.Len())
	for i := 0; i < dps.Len(); i++ {
		dp := dps.At(i)
		assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
		actual[attrValue(t, dp.Attributes(), attr)] = dp.IntValue()
	}
	assert.Equal(t, expected, actual)
}
