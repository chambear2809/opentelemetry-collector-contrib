// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

func TestDirectGNMIRejectsNumericDynamicInfoSuffix(t *testing.T) {
	products := []struct {
		name       string
		prefix     string
		metricBase string
		decode     func(*iosXRHealth, *gnmi.Notification) pmetric.Metrics
	}{
		{
			name:       "ios_xr",
			prefix:     "openconfig-system:system/state",
			metricBase: "cisco.iosxr.yang.openconfig_system.system.state.payload.",
			decode: func(health *iosXRHealth, notification *gnmi.Notification) pmetric.Metrics {
				decoder := iosXRGNMIUpdateDecoder{target: IOSXRTargetConfig{Name: "xr-1"}, health: health}
				return decoder.decodeNotification(notification, iosXRTelemetryTransportDialIn)
			},
		},
		{
			name:       "catalyst_9800",
			prefix:     "wireless-rrm-oper:rrm-oper-data/state",
			metricBase: "cisco.catalyst9800.yang.wireless_rrm_oper.rrm_oper_data.state.payload.",
			decode: func(health *iosXRHealth, notification *gnmi.Notification) pmetric.Metrics {
				decoder := catalyst9800GNMIUpdateDecoder{target: Catalyst9800TargetConfig{Name: "wlc-1"}, health: health}
				return decoder.decodeNotification(notification, catalyst9800TelemetryTransportDialIn)
			},
		},
	}
	collisions := []struct {
		name        string
		textLeaf    string
		numericLeaf string
		metricLeaf  string
	}{
		{name: "gauge", textLeaf: "foo", numericLeaf: "foo_info", metricLeaf: "foo_info"},
		{name: "counter", textLeaf: "foo_packets", numericLeaf: "foo_packets_info", metricLeaf: "foo_packets_info"},
	}
	for _, product := range products {
		for _, collision := range collisions {
			for _, numericFirst := range []bool{false, true} {
				order := "text_first"
				if numericFirst {
					order = "numeric_first"
				}
				t.Run(product.name+"/"+collision.name+"/"+order, func(t *testing.T) {
					health := &iosXRHealth{}
					events := []bool{false, true}
					if numericFirst {
						events = []bool{true, false}
					}
					for _, numeric := range events {
						leaf := collision.textLeaf
						value := `"up"`
						if numeric {
							leaf = collision.numericLeaf
							value = "1"
						}
						notification := &gnmi.Notification{
							Prefix: mustParseIOSXRPath(t, product.prefix),
							Update: []*gnmi.Update{{
								Path: mustParseIOSXRPath(t, "payload"),
								Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(
									`{"` + leaf + `":` + value + `}`,
								)}},
							}},
						}
						md := product.decode(health, notification)
						name := product.metricBase + collision.metricLeaf
						if numeric {
							assert.Zero(t, metricCountNamed(md, name))
							continue
						}
						metric := mustFindIOSXRMetric(t, md, name)
						require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
						require.Equal(t, 1, metric.Gauge().DataPoints().Len())
						assert.Equal(t, "up", attrValue(t, metric.Gauge().DataPoints().At(0).Attributes(), "value"))
					}
					assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
				})
			}
		}
	}
}

func TestDialOutNormalizationRejectsNumericDynamicInfoSuffixAcrossBatches(t *testing.T) {
	products := []struct {
		name       string
		metricBase string
		normalizer func(consumer.Metrics, *iosXRHealth) consumer.Metrics
	}{
		{
			name:       "ios_xr",
			metricBase: "cisco.iosxr.yang.test_module.",
			normalizer: func(next consumer.Metrics, health *iosXRHealth) consumer.Metrics {
				return newIOSXRNormalizingConsumer(next, defaultIOSXRConfig(), newDeviceSelectionMatcher(DeviceSelectionConfig{}), iosXRTelemetryTransportDialOut, health)
			},
		},
		{
			name:       "catalyst_9800",
			metricBase: "cisco.catalyst9800.yang.test_module.",
			normalizer: func(next consumer.Metrics, health *iosXRHealth) consumer.Metrics {
				return newCatalyst9800NormalizingConsumer(next, defaultCatalyst9800Config(), newDeviceSelectionMatcher(DeviceSelectionConfig{}), catalyst9800TelemetryTransportDialOut, health)
			},
		},
	}
	collisions := []struct {
		name       string
		metricLeaf string
		counter    bool
	}{
		{name: "gauge", metricLeaf: "foo_info"},
		{name: "counter", metricLeaf: "foo_packets_info", counter: true},
	}
	for _, product := range products {
		for _, collision := range collisions {
			for _, numericFirst := range []bool{false, true} {
				order := "text_first"
				if numericFirst {
					order = "numeric_first"
				}
				t.Run(product.name+"/"+collision.name+"/"+order, func(t *testing.T) {
					sink := &consumertest.MetricsSink{}
					health := &iosXRHealth{}
					normalizer := product.normalizer(sink, health)
					events := []bool{false, true}
					if numericFirst {
						events = []bool{true, false}
					}
					for _, numeric := range events {
						raw := dynamicYANGVariantDialOutMetrics(collision.metricLeaf, numeric, collision.counter)
						require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
					}
					require.Len(t, sink.AllMetrics(), 1, "only the text info variant may reach the downstream consumer")
					metric := mustFindIOSXRMetric(t, sink.AllMetrics()[0], product.metricBase+collision.metricLeaf)
					require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
					require.Equal(t, 1, metric.Gauge().DataPoints().Len())
					dp := metric.Gauge().DataPoints().At(0)
					assert.Equal(t, pmetric.NumberDataPointValueTypeDouble, dp.ValueType())
					assert.Equal(t, 1.0, dp.DoubleValue())
					assert.Equal(t, "up", attrValue(t, dp.Attributes(), "value"))
					assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
				})
			}
		}
	}
}

func dynamicYANGVariantDialOutMetrics(metricLeaf string, numeric, counter bool) pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("cisco.node_id", "device-1")
	rm.Resource().Attributes().PutStr("cisco.encoding_path", "test-module:state")
	metric := rm.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	metric.SetName("cisco." + metricLeaf)
	if !numeric {
		dp := metric.SetEmptyGauge().DataPoints().AppendEmpty()
		dp.SetDoubleValue(1)
		dp.Attributes().PutStr("value", "up")
		return md
	}
	if counter {
		sum := metric.SetEmptySum()
		sum.SetIsMonotonic(true)
		sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
		sum.DataPoints().AppendEmpty().SetIntValue(1)
		return md
	}
	metric.SetEmptyGauge().DataPoints().AppendEmpty().SetIntValue(1)
	return md
}
