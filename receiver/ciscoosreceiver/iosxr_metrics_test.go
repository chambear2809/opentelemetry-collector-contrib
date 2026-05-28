// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

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

	raw := rawIOSXRDialOutMetrics("cisco.interface.statistics.rx-pkts", 7, "xr-1")
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
	assert.Equal(t, "network", attrValue(t, resourceAttrs, "hw.type"))
	assert.Equal(t, "ios_xr", attrValue(t, resourceAttrs, "cisco.os.name"))
	assert.Equal(t, "ios_xr", attrValue(t, resourceAttrs, "cisco.platform.family"))
	assert.Equal(t, "mdt_grpc_dial_out", attrValue(t, resourceAttrs, "cisco.telemetry.transport"))
	assert.Equal(t, "Cisco-IOS-XR-infra-statsd-oper", attrValue(t, resourceAttrs, "cisco.yang.module"))
	assert.Equal(t, "xr-1", attrValue(t, resourceAttrs, "cisco.node.id"))

	dpAttrs := metric.Gauge().DataPoints().At(0).Attributes()
	assert.Equal(t, "mdt_grpc_dial_out", attrValue(t, dpAttrs, "cisco.telemetry.transport"))
	assert.Equal(t, "Cisco-IOS-XR-infra-statsd-oper", attrValue(t, dpAttrs, "cisco.yang.module"))
	assert.Equal(t, "HundredGigE0/0/0/0", attrValue(t, dpAttrs, "network.interface.name"))
	assert.Equal(t, "default", attrValue(t, dpAttrs, "network.vrf.name"))
	assert.Equal(t, "192.0.2.2", attrValue(t, dpAttrs, "network.peer.address"))
}

func TestIOSXRNormalizingConsumerAppliesDeviceSelection(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	selector := newDeviceSelectionMatcher(DeviceSelectionConfig{
		Include: DeviceSelectionMatchConfig{HostNames: []string{"xr-2"}},
	})
	normalizer := newIOSXRNormalizingConsumer(sink, defaultIOSXRConfig(), selector, iosXRTelemetryTransportDialOut, &iosXRHealth{})

	err := normalizer.ConsumeMetrics(t.Context(), rawIOSXRDialOutMetrics("cisco.interface.statistics.rx-pkts", 7, "xr-1"))
	require.NoError(t, err)
	assert.Empty(t, sink.AllMetrics())
}

func TestIOSXRNormalizingConsumerAllowsRootMetricFilteringAfterRename(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	filter := newMetricFilteringConsumer(sink, &Config{Metrics: map[string]MetricConfig{
		"cisco.iosxr.yang.cisco_ios_xr_infra_statsd_oper.interface.statistics.rx_pkts": {Enabled: false},
	}})
	normalizer := newIOSXRNormalizingConsumer(filter, defaultIOSXRConfig(), newDeviceSelectionMatcher(DeviceSelectionConfig{}), iosXRTelemetryTransportDialOut, &iosXRHealth{})

	err := normalizer.ConsumeMetrics(t.Context(), rawIOSXRDialOutMetrics("cisco.interface.statistics.rx-pkts", 7, "xr-1"))
	require.NoError(t, err)
	assert.Empty(t, sink.AllMetrics())
}

func TestIOSXRNormalizingConsumerRenamesCompactGPBDiagnostic(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	health := &iosXRHealth{}
	normalizer := newIOSXRNormalizingConsumer(sink, defaultIOSXRConfig(), newDeviceSelectionMatcher(DeviceSelectionConfig{}), iosXRTelemetryTransportDialOut, health)

	err := normalizer.ConsumeMetrics(t.Context(), rawIOSXRDialOutMetrics("cisco.yang_grpc.compact_gpb_payloads", 3, "xr-1"))
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

func rawIOSXRDialOutMetrics(metricName string, value float64, nodeID string) pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("cisco.node_id", nodeID)
	rm.Resource().Attributes().PutStr("cisco.encoding_path", "Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/latest/generic-counters")
	sm := rm.ScopeMetrics().AppendEmpty()
	metric := sm.Metrics().AppendEmpty()
	metric.SetName(metricName)
	dp := metric.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetDoubleValue(value)
	return md
}

func rawIOSXRDialOutMultiDatapointMetric() pmetric.Metrics {
	md := rawIOSXRDialOutMetrics("cisco.interface.statistics.rx-pkts", 1, "xr-1")
	dps := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Gauge().DataPoints()
	for _, value := range []float64{2, 3} {
		dp := dps.AppendEmpty()
		dp.SetDoubleValue(value)
	}
	return md
}
