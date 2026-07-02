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
