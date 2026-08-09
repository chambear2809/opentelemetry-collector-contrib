// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

type dynamicYANGTestProduct struct {
	name                 string
	prefix               string
	decode               func(*iosXRHealth, *gnmi.Notification, directGNMIDecodeLimits) pmetric.Metrics
	normalizer           func(consumer.Metrics, *iosXRHealth) consumer.Metrics
	directNormalizer     func(consumer.Metrics, *iosXRHealth) consumer.Metrics
	normalizerWithLimit  func(consumer.Metrics, *iosXRHealth, int) consumer.Metrics
	counterContainerPath bool
}

func dynamicYANGTestProducts() []dynamicYANGTestProduct {
	return []dynamicYANGTestProduct{
		{
			name:   "ios_xr",
			prefix: "cisco.iosxr.yang",
			decode: func(health *iosXRHealth, notification *gnmi.Notification, limits directGNMIDecodeLimits) pmetric.Metrics {
				decoder := iosXRGNMIUpdateDecoder{target: IOSXRTargetConfig{Name: "xr-1"}, health: health, limits: limits}
				return decoder.decodeNotification(notification, iosXRTelemetryTransportDialIn)
			},
			normalizer: func(next consumer.Metrics, health *iosXRHealth) consumer.Metrics {
				return newIOSXRNormalizingConsumer(next, defaultIOSXRConfig(), newDeviceSelectionMatcher(DeviceSelectionConfig{}), iosXRTelemetryTransportDialOut, health)
			},
			directNormalizer: func(next consumer.Metrics, health *iosXRHealth) consumer.Metrics {
				return newIOSXRNormalizingConsumer(next, defaultIOSXRConfig(), newDeviceSelectionMatcher(DeviceSelectionConfig{}), iosXRTelemetryTransportDialIn, health)
			},
			normalizerWithLimit: func(next consumer.Metrics, health *iosXRHealth, limit int) consumer.Metrics {
				normalizer := newIOSXRNormalizingConsumer(next, defaultIOSXRConfig(), newDeviceSelectionMatcher(DeviceSelectionConfig{}), iosXRTelemetryTransportDialOut, health).(*iosXRNormalizingConsumer)
				normalizer.budgetLimits.maxMetricNameBytes = limit
				return normalizer
			},
			counterContainerPath: true,
		},
		{
			name:   "catalyst_9800",
			prefix: "cisco.catalyst9800.yang",
			decode: func(health *iosXRHealth, notification *gnmi.Notification, limits directGNMIDecodeLimits) pmetric.Metrics {
				decoder := catalyst9800GNMIUpdateDecoder{target: Catalyst9800TargetConfig{Name: "wlc-1"}, health: health, limits: limits}
				return decoder.decodeNotification(notification, catalyst9800TelemetryTransportDialIn)
			},
			normalizer: func(next consumer.Metrics, health *iosXRHealth) consumer.Metrics {
				return newCatalyst9800NormalizingConsumer(next, defaultCatalyst9800Config(), newDeviceSelectionMatcher(DeviceSelectionConfig{}), catalyst9800TelemetryTransportDialOut, health)
			},
			directNormalizer: func(next consumer.Metrics, health *iosXRHealth) consumer.Metrics {
				return newCatalyst9800NormalizingConsumer(next, defaultCatalyst9800Config(), newDeviceSelectionMatcher(DeviceSelectionConfig{}), catalyst9800TelemetryTransportDialIn, health)
			},
			normalizerWithLimit: func(next consumer.Metrics, health *iosXRHealth, limit int) consumer.Metrics {
				normalizer := newCatalyst9800NormalizingConsumer(next, defaultCatalyst9800Config(), newDeviceSelectionMatcher(DeviceSelectionConfig{}), catalyst9800TelemetryTransportDialOut, health).(*catalyst9800NormalizingConsumer)
				normalizer.budgetLimits.maxMetricNameBytes = limit
				return normalizer
			},
		},
	}
}

func TestDirectDynamicYANGJSONNamesAreOrderIndependentAndInjective(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		t.Run(product.name, func(t *testing.T) {
			var priorNames []string
			for index, payload := range [][]byte{
				[]byte(`{"foo-bar":1,"foo_bar":1.5,"$":2}`),
				[]byte(`{"$":2,"foo_bar":1.5,"foo-bar":1}`),
			} {
				health := &iosXRHealth{}
				md := product.decode(health, &gnmi.Notification{
					Prefix: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "root-mod:root"}}},
					Update: []*gnmi.Update{{
						Path: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "payload"}}},
						Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: payload}},
					}},
				}, directGNMIDecodeLimits{})

				wantPaths := [][]string{
					{"root-mod:root", "payload", "foo-bar"},
					{"root-mod:root", "payload", "foo_bar"},
					{"root-mod:root", "payload", "$"},
				}
				names := make([]string, 0, len(wantPaths))
				for _, path := range wantPaths {
					name := mustDynamicYANGName(t, product.prefix, "root-mod", path, dynamicYANGMetricVariantNumber)
					metric := mustFindMetricExact(t, md, name)
					require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
					dp := metric.Gauge().DataPoints().At(0)
					assert.Equal(t, pmetric.NumberDataPointValueTypeDouble, dp.ValueType())
					assert.NotEmpty(t, attrValue(t, dp.Attributes(), "cisco.yang.source_path"))
					names = append(names, name)
				}
				require.NotEqual(t, names[0], names[1])
				require.NotEqual(t, names[0], names[2])
				slices.Sort(names)
				if index > 0 {
					assert.Equal(t, priorNames, names)
				}
				priorNames = names
				assert.Zero(t, health.snapshot().droppedDatapoints)
			}
		})
	}
}

func TestDirectDynamicYANGJSONEmptyStringAndQualifiedModuleStayConsistent(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		t.Run(product.name, func(t *testing.T) {
			health := &iosXRHealth{}
			md := product.decode(health, &gnmi.Notification{
				Prefix: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "module-A:root"}}},
				Update: []*gnmi.Update{{
					Path: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "payload"}}},
					Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{"module-B:leaf":"","null-leaf":null}`)}},
				}},
			}, directGNMIDecodeLimits{})

			name := mustDynamicYANGName(t, product.prefix, "module-B", []string{"module-A:root", "payload", "module-B:leaf"}, dynamicYANGMetricVariantInfo)
			metric := mustFindMetricExact(t, md, name)
			require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
			dp := metric.Gauge().DataPoints().At(0)
			value, ok := dp.Attributes().Get("value")
			require.True(t, ok, "an empty string is still a present YANG leaf value")
			assert.Empty(t, value.Str())
			assert.Equal(t, "module-B", attrValue(t, dp.Attributes(), "cisco.yang.module"))

			nullName := mustDynamicYANGName(t, product.prefix, "module-A", []string{"module-A:root", "payload", "null-leaf"}, dynamicYANGMetricVariantInfo)
			assert.Zero(t, metricCountExact(md, nullName), "JSON null must remain absent")
			assert.Zero(t, health.snapshot().droppedDatapoints)
		})
	}
}

func TestDirectDynamicYANGRetainsLaterModuleQualifiersAndDeleteIdentity(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		t.Run(product.name, func(t *testing.T) {
			health := &iosXRHealth{}
			md := product.decode(health, &gnmi.Notification{
				Prefix: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "root-mod:root"}}},
				Update: []*gnmi.Update{
					{Path: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "aug-A:state"}, {Name: "value"}}}, Val: intTypedValue(1)},
					{Path: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "aug-B:state"}, {Name: "value"}}}, Val: doubleTypedValue(1.5)},
				},
				Delete: []*gnmi.Path{
					{Elem: []*gnmi.PathElem{{Name: "aug-A:state"}, {Name: "stale"}}},
					{Elem: []*gnmi.PathElem{{Name: "aug-B:state"}, {Name: "stale"}}},
				},
			}, directGNMIDecodeLimits{})

			for _, qualifier := range []string{"aug-A:state", "aug-B:state"} {
				module, _ := strings.CutSuffix(qualifier, ":state")
				numericName := mustDynamicYANGName(t, product.prefix, module, []string{"root-mod:root", qualifier, "value"}, dynamicYANGMetricVariantNumber)
				metric := mustFindMetricExact(t, md, numericName)
				require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
				numericAttrs := metric.Gauge().DataPoints().At(0).Attributes()
				assert.Contains(t, attrValue(t, numericAttrs, "cisco.yang.source_path"), strings.ReplaceAll(qualifier, ":", "%3A"))
				assert.Equal(t, module, attrValue(t, numericAttrs, "cisco.yang.module"))

				deleteName := mustDynamicYANGName(t, product.prefix, module, []string{"root-mod:root", qualifier, "stale"}, dynamicYANGMetricVariantInfo)
				deleted := mustFindMetricExact(t, md, deleteName)
				deletedAttrs := deleted.Gauge().DataPoints().At(0).Attributes()
				assert.Equal(t, "deleted", attrValue(t, deletedAttrs, "value"))
				assert.Equal(t, module, attrValue(t, deletedAttrs, "cisco.yang.module"))
			}
			assert.Zero(t, health.snapshot().droppedDatapoints)
		})
	}
}

func TestDirectDynamicYANGFramesModuleAndPathSeparately(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		t.Run(product.name, func(t *testing.T) {
			health := &iosXRHealth{}
			md := product.decode(health, &gnmi.Notification{Update: []*gnmi.Update{
				{Path: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "counters:value"}}}, Val: intTypedValue(1)},
				{Path: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "counters"}, {Name: "value"}}}, Val: doubleTypedValue(2)},
			}}, directGNMIDecodeLimits{})

			moduleName := mustDynamicYANGName(t, product.prefix, "counters", []string{"counters:value"}, dynamicYANGMetricVariantNumber)
			pathName := mustDynamicYANGName(t, product.prefix, "", []string{"counters", "value"}, dynamicYANGMetricVariantNumber)
			require.NotEqual(t, moduleName, pathName)
			require.Equal(t, pmetric.MetricTypeGauge, mustFindMetricExact(t, md, moduleName).Type())
			pathMetric := mustFindMetricExact(t, md, pathName)
			if product.counterContainerPath {
				require.Equal(t, pmetric.MetricTypeSum, pathMetric.Type())
				assert.Equal(t, pmetric.NumberDataPointValueTypeInt, pathMetric.Sum().DataPoints().At(0).ValueType())
			} else {
				require.Equal(t, pmetric.MetricTypeGauge, pathMetric.Type())
				assert.Equal(t, pmetric.NumberDataPointValueTypeDouble, pathMetric.Gauge().DataPoints().At(0).ValueType())
			}
			assert.Zero(t, health.snapshot().droppedDatapoints)
		})
	}
}

func TestDirectDynamicYANGLegacyElementUsesRawIdentityAndLocalSemantics(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		for _, test := range []struct {
			name     string
			prefix   *gnmi.Path
			path     []string
			identity []string
			module   string
		}{
			{
				name: "qualified container",
				path: []string{"legacy-mod:counters", "packets"}, identity: []string{"legacy-mod:counters", "packets"}, module: "legacy-mod",
			},
			{
				name:   "unqualified MAC predicate inherits module",
				prefix: &gnmi.Path{Element: []string{"root-mod:root"}},
				path:   []string{"packets[client-mac=00:11:22]"}, identity: []string{"root-mod:root", "packets[client-mac=00:11:22]"}, module: "root-mod",
			},
			{
				name: "unqualified MAC predicate keeps absent module",
				path: []string{"packets[client-mac=00:11:22]"}, identity: []string{"packets[client-mac=00:11:22]"},
			},
			{
				name:   "qualified predicate selects only prefix",
				prefix: &gnmi.Path{Element: []string{"root-mod:root"}},
				path:   []string{"mod:packets[key=00:11]"}, identity: []string{"root-mod:root", "mod:packets[key=00:11]"}, module: "mod",
			},
		} {
			t.Run(product.name+"/"+test.name, func(t *testing.T) {
				health := &iosXRHealth{}
				md := product.decode(health, &gnmi.Notification{Prefix: test.prefix, Update: []*gnmi.Update{{
					Path: &gnmi.Path{Element: test.path},
					Val:  intTypedValue(7),
				}}}, directGNMIDecodeLimits{})
				name := mustDynamicYANGName(t, product.prefix, test.module, test.identity, dynamicYANGMetricVariantNumber)
				metric := mustFindMetricExact(t, md, name)
				require.Equal(t, pmetric.MetricTypeSum, metric.Type(), "predicate text must not hide the packets leaf semantics")
				dp := metric.Sum().DataPoints().At(0)
				assert.Equal(t, int64(7), dp.IntValue())
				module, present := dp.Attributes().Get("cisco.yang.module")
				if test.module == "" {
					assert.False(t, present)
				} else {
					require.True(t, present)
					assert.Equal(t, test.module, module.Str())
				}
				assert.Zero(t, health.snapshot().droppedDatapoints)
			})
		}
	}
}

func TestDirectDynamicYANGEffectiveOriginAndConflicts(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		t.Run(product.name+"/inherited_and_single_origin", func(t *testing.T) {
			health := &iosXRHealth{}
			inherited := product.decode(health, &gnmi.Notification{
				Prefix: &gnmi.Path{Origin: "prefix-origin", Elem: []*gnmi.PathElem{{Name: "root"}}},
				Update: []*gnmi.Update{{Path: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "state"}, {Name: "value"}}}, Val: intTypedValue(1)}},
				Delete: []*gnmi.Path{{Elem: []*gnmi.PathElem{{Name: "state"}, {Name: "stale"}}}},
			}, directGNMIDecodeLimits{})
			_ = mustFindMetricExact(t, inherited, mustDynamicYANGName(t, product.prefix, "prefix-origin", []string{"root", "state", "value"}, dynamicYANGMetricVariantNumber))
			_ = mustFindMetricExact(t, inherited, mustDynamicYANGName(t, product.prefix, "prefix-origin", []string{"root", "state", "stale"}, dynamicYANGMetricVariantInfo))

			single := product.decode(health, &gnmi.Notification{
				Update: []*gnmi.Update{{Path: &gnmi.Path{Origin: "update-origin", Elem: []*gnmi.PathElem{{Name: "root"}, {Name: "value"}}}, Val: intTypedValue(2)}},
				Delete: []*gnmi.Path{{Origin: "delete-origin", Elem: []*gnmi.PathElem{{Name: "root"}, {Name: "stale"}}}},
			}, directGNMIDecodeLimits{})
			_ = mustFindMetricExact(t, single, mustDynamicYANGName(t, product.prefix, "update-origin", []string{"root", "value"}, dynamicYANGMetricVariantNumber))
			_ = mustFindMetricExact(t, single, mustDynamicYANGName(t, product.prefix, "delete-origin", []string{"root", "stale"}, dynamicYANGMetricVariantInfo))
			assert.Zero(t, health.snapshot().decodeErrors)
			assert.Zero(t, health.snapshot().droppedDatapoints)
		})

		t.Run(product.name+"/conflicting_update_and_delete_origins", func(t *testing.T) {
			health := &iosXRHealth{}
			md := product.decode(health, &gnmi.Notification{
				Prefix: &gnmi.Path{Origin: "prefix-origin", Elem: []*gnmi.PathElem{{Name: "root"}}},
				Update: []*gnmi.Update{{Path: &gnmi.Path{Origin: "update-origin", Elem: []*gnmi.PathElem{{Name: "value"}}}, Val: intTypedValue(1)}},
				Delete: []*gnmi.Path{{Origin: "delete-origin", Elem: []*gnmi.PathElem{{Name: "stale"}}}},
			}, directGNMIDecodeLimits{})
			assert.Zero(t, metricCountExact(md, mustDynamicYANGName(t, product.prefix, "prefix-origin", []string{"root", "value"}, dynamicYANGMetricVariantNumber)))
			assert.Zero(t, metricCountExact(md, mustDynamicYANGName(t, product.prefix, "prefix-origin", []string{"root", "stale"}, dynamicYANGMetricVariantInfo)))
			assert.Equal(t, int64(2), health.snapshot().decodeErrors)
			assert.Equal(t, int64(2), health.snapshot().droppedDatapoints)
		})

		t.Run(product.name+"/relative_origins_override_qualified_prefix_module", func(t *testing.T) {
			health := &iosXRHealth{}
			md := product.decode(health, &gnmi.Notification{
				Prefix: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "base:root"}}},
				Update: []*gnmi.Update{
					{Path: &gnmi.Path{Origin: "origin-B", Elem: []*gnmi.PathElem{{Name: "x"}}}, Val: intTypedValue(1)},
					{Path: &gnmi.Path{Origin: "origin-C", Elem: []*gnmi.PathElem{{Name: "x"}}}, Val: intTypedValue(2)},
				},
				Delete: []*gnmi.Path{
					{Origin: "origin-B", Elem: []*gnmi.PathElem{{Name: "stale"}}},
					{Origin: "origin-C", Elem: []*gnmi.PathElem{{Name: "stale"}}},
				},
			}, directGNMIDecodeLimits{})
			for _, origin := range []string{"origin-B", "origin-C"} {
				_ = mustFindMetricExact(t, md, mustDynamicYANGName(t, product.prefix, origin, []string{"base:root", "x"}, dynamicYANGMetricVariantNumber))
				_ = mustFindMetricExact(t, md, mustDynamicYANGName(t, product.prefix, origin, []string{"base:root", "stale"}, dynamicYANGMetricVariantInfo))
			}
			assert.Zero(t, metricCountExact(md, mustDynamicYANGName(t, product.prefix, "base", []string{"base:root", "x"}, dynamicYANGMetricVariantNumber)))
			assert.Zero(t, health.snapshot().decodeErrors)
			assert.Zero(t, health.snapshot().droppedDatapoints)
		})
	}
}

func TestDirectDynamicYANGRejectsIncompatibleCounterRepresentationAcrossBatches(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		t.Run(product.name, func(t *testing.T) {
			health := &iosXRHealth{}
			path := &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "test:counters"}, {Name: "packets"}}}
			first := product.decode(health, &gnmi.Notification{Update: []*gnmi.Update{{Path: path, Val: intTypedValue(1)}}}, directGNMIDecodeLimits{})
			name := mustDynamicYANGName(t, product.prefix, "test", []string{"test:counters", "packets"}, dynamicYANGMetricVariantNumber)
			metric := mustFindMetricExact(t, first, name)
			require.Equal(t, pmetric.MetricTypeSum, metric.Type())
			assert.Equal(t, pmetric.NumberDataPointValueTypeInt, metric.Sum().DataPoints().At(0).ValueType())

			second := product.decode(health, &gnmi.Notification{Update: []*gnmi.Update{{Path: path, Val: doubleTypedValue(1.5)}}}, directGNMIDecodeLimits{})
			assert.Zero(t, metricCountExact(second, name))
			assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
		})
	}
}

func TestDirectDynamicYANGFinalNameLimitIsExact(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		t.Run(product.name, func(t *testing.T) {
			path := &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "test:root"}, {Name: "value"}}}
			name := mustDynamicYANGName(t, product.prefix, "test", []string{"test:root", "value"}, dynamicYANGMetricVariantNumber)

			acceptedHealth := &iosXRHealth{}
			accepted := product.decode(acceptedHealth, &gnmi.Notification{Update: []*gnmi.Update{{Path: path, Val: intTypedValue(1)}}}, directGNMIDecodeLimits{maxMetricNameBytes: len(name)})
			assert.Equal(t, 1, metricCountExact(accepted, name))
			assert.Zero(t, acceptedHealth.snapshot().droppedDatapoints)

			rejectedHealth := &iosXRHealth{}
			rejected := product.decode(rejectedHealth, &gnmi.Notification{Update: []*gnmi.Update{{Path: path, Val: intTypedValue(1)}}}, directGNMIDecodeLimits{maxMetricNameBytes: len(name) - 1})
			assert.Zero(t, metricCountExact(rejected, name))
			assert.Equal(t, int64(1), rejectedHealth.snapshot().droppedDatapoints)
		})
	}
}

func TestDialOutDynamicYANGNamesAreOrderIndependentAndInjective(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		for _, reverse := range []bool{false, true} {
			order := "forward"
			if reverse {
				order = "reverse"
			}
			t.Run(product.name+"/"+order, func(t *testing.T) {
				sink := &consumertest.MetricsSink{}
				health := &iosXRHealth{}
				normalizer := product.normalizer(sink, health)
				inputs := []pmetric.Metrics{
					rawDynamicYANGDialOutMetric("test-module:root", "", "cisco.foo-bar", "content/foo-bar", pmetric.MetricTypeGauge, intMetricNumber(1)),
					rawDynamicYANGDialOutMetric("test-module:root", "", "cisco.foo_bar", "content/foo_bar", pmetric.MetricTypeGauge, doubleMetricNumber(1.5)),
				}
				if reverse {
					slices.Reverse(inputs)
				}
				for _, input := range inputs {
					require.NoError(t, normalizer.ConsumeMetrics(t.Context(), input))
				}
				want := []string{
					mustDialOutDynamicYANGName(t, product.prefix, "test-module", "test-module:root", "content/foo-bar", dynamicYANGMetricVariantNumber),
					mustDialOutDynamicYANGName(t, product.prefix, "test-module", "test-module:root", "content/foo_bar", dynamicYANGMetricVariantNumber),
				}
				require.NotEqual(t, want[0], want[1])
				for _, name := range want {
					metric := mustFindMetricExactInBatches(t, sink.AllMetrics(), name)
					require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
					assert.Equal(t, pmetric.NumberDataPointValueTypeDouble, metric.Gauge().DataPoints().At(0).ValueType())
					assert.NotEmpty(t, attrValue(t, metric.Gauge().DataPoints().At(0).Attributes(), "cisco.yang.source_path"))
				}
				assert.Zero(t, health.snapshot().droppedDatapoints)
			})
		}
	}
}

func TestDialOutDynamicYANGRetainsEncodingContentAndConflictingModulePrefix(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		t.Run(product.name, func(t *testing.T) {
			sink := &consumertest.MetricsSink{}
			health := &iosXRHealth{}
			normalizer := product.normalizer(sink, health)
			for _, source := range []string{"content/foo", "foo"} {
				require.NoError(t, normalizer.ConsumeMetrics(t.Context(), rawDynamicYANGDialOutMetric(
					"encoding-module:state", "attribute-module", "cisco.foo", source, pmetric.MetricTypeGauge, intMetricNumber(1),
				)))
			}
			contentName := mustDialOutDynamicYANGName(t, product.prefix, "attribute-module", "encoding-module:state", "content/foo", dynamicYANGMetricVariantNumber)
			plainName := mustDialOutDynamicYANGName(t, product.prefix, "attribute-module", "encoding-module:state", "foo", dynamicYANGMetricVariantNumber)
			require.NotEqual(t, contentName, plainName)
			for _, name := range []string{contentName, plainName} {
				module, path, variant, ok := decodeDynamicYANGMetricNameForTest(name, product.prefix)
				require.True(t, ok)
				assert.Equal(t, "attribute-module", module)
				assert.Equal(t, "encoding-module:state", path[0], "the conflicting raw encoding qualifier must remain in identity")
				assert.Equal(t, dynamicYANGMetricVariantNumber, variant)
				_ = mustFindMetricExactInBatches(t, sink.AllMetrics(), name)
			}
			assert.Zero(t, health.snapshot().droppedDatapoints)
		})
	}
}

func TestDialOutDynamicYANGFramesEncodingAndSourceBoundaries(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		t.Run(product.name, func(t *testing.T) {
			tests := []struct {
				encoding string
				metric   string
				source   string
			}{
				{encoding: "a/counters", metric: "cisco.value", source: "content/value"},
				{encoding: "a", metric: "cisco.counters.content.value", source: "counters/content/value"},
				{encoding: "a/content", metric: "cisco.foo", source: "foo"},
				{encoding: "a", metric: "cisco.foo", source: "content/foo"},
			}
			names := make([]string, 0, len(tests))
			for _, test := range tests {
				sink := &consumertest.MetricsSink{}
				health := &iosXRHealth{}
				normalizer := product.normalizer(sink, health)
				require.NoError(t, normalizer.ConsumeMetrics(t.Context(), rawDynamicYANGDialOutMetric(
					test.encoding, "test-module", test.metric, test.source, pmetric.MetricTypeGauge, intMetricNumber(1),
				)))
				name := mustDialOutDynamicYANGName(t, product.prefix, "test-module", test.encoding, test.source, dynamicYANGMetricVariantNumber)
				_ = mustFindMetricExactInBatches(t, sink.AllMetrics(), name)
				names = append(names, name)
				assert.Zero(t, health.snapshot().droppedDatapoints)
			}
			require.NotEqual(t, names[0], names[1], "moving counters across the tuple boundary must change identity")
			require.NotEqual(t, names[2], names[3], "content in encoding_path must not equal transparent source content")
		})
	}
}

func TestDialOutDynamicYANGEmptyEncodingPathUsesExplicitAbsentFrame(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		for _, attributePresent := range []bool{false, true} {
			label := "attribute_absent"
			if attributePresent {
				label = "explicitly_empty"
			}
			t.Run(product.name+"/"+label, func(t *testing.T) {
				sink := &consumertest.MetricsSink{}
				health := &iosXRHealth{}
				normalizer := product.normalizer(sink, health)
				raw := rawDynamicYANGDialOutMetric("", "test-module", "cisco.value", "content/value", pmetric.MetricTypeGauge, intMetricNumber(1))
				if !attributePresent {
					raw.ResourceMetrics().At(0).Resource().Attributes().Remove("cisco.encoding_path")
				}
				require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
				name := mustDialOutDynamicYANGName(t, product.prefix, "test-module", "", "content/value", dynamicYANGMetricVariantNumber)
				assert.Contains(t, name, ".e0.p2.")
				_ = mustFindMetricExactInBatches(t, sink.AllMetrics(), name)
				assert.Zero(t, health.snapshot().droppedDatapoints)
			})
		}
	}
}

func TestDialOutDynamicYANGRejectsNoncanonicalEncodingPaths(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		for index, encodingPath := range []string{"/foo/", " foo ", "foo/"} {
			t.Run(fmt.Sprintf("%s/case_%d", product.name, index), func(t *testing.T) {
				sink := &consumertest.MetricsSink{}
				health := &iosXRHealth{}
				raw := rawDynamicYANGDialOutMetric(encodingPath, "test", "cisco.value", "content/value", pmetric.MetricTypeGauge, intMetricNumber(1))
				require.NoError(t, product.normalizer(sink, health).ConsumeMetrics(t.Context(), raw))
				assert.Empty(t, sink.AllMetrics())
				assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
			})
		}
	}
}

func TestDialOutDynamicYANGPredicateColonsDoNotForgeModules(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		for _, test := range []struct {
			name         string
			encodingPath string
			module       string
		}{
			{name: "unqualified MAC predicate", encodingPath: "common-oper-data[client-mac=00:11:22]/state"},
			{name: "qualified container with predicate", encodingPath: "mod:element[key=00:11]/state", module: "mod"},
		} {
			t.Run(product.name+"/"+test.name, func(t *testing.T) {
				sink := &consumertest.MetricsSink{}
				health := &iosXRHealth{}
				raw := rawDynamicYANGDialOutMetric(test.encodingPath, "", "cisco.value", "content/value", pmetric.MetricTypeGauge, intMetricNumber(1))
				require.NoError(t, product.normalizer(sink, health).ConsumeMetrics(t.Context(), raw))
				name := mustDialOutDynamicYANGName(t, product.prefix, test.module, test.encodingPath, "content/value", dynamicYANGMetricVariantNumber)
				metric := mustFindMetricExactInBatches(t, sink.AllMetrics(), name)
				dp := metric.Gauge().DataPoints().At(0)
				module, present := dp.Attributes().Get("cisco.yang.module")
				if test.module == "" {
					assert.False(t, present)
				} else {
					require.True(t, present)
					assert.Equal(t, test.module, module.Str())
				}
				assert.Zero(t, health.snapshot().droppedDatapoints)
			})
		}
	}
}

func TestDialOutDynamicYANGReservedRawPrefixesCannotBypassFraming(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		t.Run(product.name, func(t *testing.T) {
			productHealthName := "cisco.iosxr.receiver.updates"
			productHealthSource := "iosxr/receiver/updates"
			if product.name == "catalyst_9800" {
				productHealthName = "cisco.catalyst9800.receiver.updates"
				productHealthSource = "catalyst9800/receiver/updates"
			}
			for _, test := range []struct {
				name   string
				source string
			}{
				{name: productHealthName, source: productHealthSource},
				{name: "cisco.wlc.reserved-leaf", source: "wlc/reserved-leaf"},
				{name: "cisco.yang_grpc.compact_gpb_payloads", source: "yang_grpc/compact_gpb_payloads"},
			} {
				sink := &consumertest.MetricsSink{}
				health := &iosXRHealth{}
				normalizer := product.normalizer(sink, health)
				require.NoError(t, normalizer.ConsumeMetrics(t.Context(), rawDynamicYANGDialOutMetric(
					"test:root", "test", test.name, test.source, pmetric.MetricTypeGauge, intMetricNumber(1),
				)))
				require.Len(t, sink.AllMetrics(), 1)
				md := sink.AllMetrics()[0]
				expected := mustDialOutDynamicYANGName(t, product.prefix, "test", "test:root", test.source, dynamicYANGMetricVariantNumber)
				metric := mustFindMetricExact(t, md, expected)
				require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
				assert.Equal(t, pmetric.NumberDataPointValueTypeDouble, metric.Gauge().DataPoints().At(0).ValueType())
				assert.Zero(t, metricCountExact(md, test.name), "raw device names must not masquerade as normalized health metrics or aliases")
				assert.Zero(t, health.snapshot().droppedDatapoints)
			}
		})
	}
}

func TestDialOutDynamicYANGRejectsNonCiscoRawMetricBoundary(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		t.Run(product.name, func(t *testing.T) {
			sink := &consumertest.MetricsSink{}
			health := &iosXRHealth{}
			normalizer := product.normalizer(sink, health)
			require.NoError(t, normalizer.ConsumeMetrics(t.Context(), rawDynamicYANGDialOutMetric(
				"test:root", "test", "device.value", "device/value", pmetric.MetricTypeGauge, intMetricNumber(1),
			)))
			assert.Empty(t, sink.AllMetrics(), "yang_grpc emits only cisco.* names; out-of-contract input must fail closed")
			assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
		})
	}
}

func TestDialInDynamicYANGRejectsUngovernedFixedPrefixPassthrough(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		t.Run(product.name, func(t *testing.T) {
			sink := &consumertest.MetricsSink{}
			health := &iosXRHealth{}
			var normalizer consumer.Metrics
			var names []string
			if product.name == "ios_xr" {
				normalizer = newIOSXRNormalizingConsumer(sink, defaultIOSXRConfig(), newDeviceSelectionMatcher(DeviceSelectionConfig{}), iosXRTelemetryTransportDialIn, health)
				names = []string{"cisco.iosxr.receiver.not_governed"}
			} else {
				normalizer = newCatalyst9800NormalizingConsumer(sink, defaultCatalyst9800Config(), newDeviceSelectionMatcher(DeviceSelectionConfig{}), catalyst9800TelemetryTransportDialIn, health)
				names = []string{"cisco.catalyst9800.receiver.not_governed", "cisco.wlc.not_governed"}
			}
			md := pmetric.NewMetrics()
			metrics := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty().Metrics()
			for _, name := range names {
				metric := metrics.AppendEmpty()
				metric.SetName(name)
				metric.SetEmptyGauge().DataPoints().AppendEmpty().SetIntValue(1)
			}
			require.NoError(t, normalizer.ConsumeMetrics(t.Context(), md))
			assert.Empty(t, sink.AllMetrics())
			assert.Equal(t, int64(len(names)), health.snapshot().droppedDatapoints)
		})
	}
}

func TestIOSXRDialOutDynamicYANGEncodingPathsSeparateGaugeAndCounter(t *testing.T) {
	sink := &consumertest.MetricsSink{}
	health := &iosXRHealth{}
	normalizer := dynamicYANGTestProducts()[0].normalizer(sink, health)
	for _, encodingPath := range []string{"test-module:state", "test-module:counters"} {
		require.NoError(t, normalizer.ConsumeMetrics(t.Context(), rawDynamicYANGDialOutMetric(
			encodingPath, "", "cisco.value", "content/value", pmetric.MetricTypeGauge, intMetricNumber(7),
		)))
	}
	gaugeName := mustDialOutDynamicYANGName(t, "cisco.iosxr.yang", "test-module", "test-module:state", "content/value", dynamicYANGMetricVariantNumber)
	counterName := mustDialOutDynamicYANGName(t, "cisco.iosxr.yang", "test-module", "test-module:counters", "content/value", dynamicYANGMetricVariantNumber)
	require.NotEqual(t, gaugeName, counterName)
	require.Equal(t, pmetric.MetricTypeGauge, mustFindMetricExactInBatches(t, sink.AllMetrics(), gaugeName).Type())
	counter := mustFindMetricExactInBatches(t, sink.AllMetrics(), counterName)
	require.Equal(t, pmetric.MetricTypeSum, counter.Type())
	assert.True(t, counter.Sum().IsMonotonic())
	assert.Equal(t, pmetric.AggregationTemporalityCumulative, counter.Sum().AggregationTemporality())
	assert.Equal(t, pmetric.NumberDataPointValueTypeInt, counter.Sum().DataPoints().At(0).ValueType())
	assert.Zero(t, health.snapshot().droppedDatapoints)
}

func TestIOSXRQualifiedCounterContainerClassifiesConsistentlyDirectAndDialOut(t *testing.T) {
	product := dynamicYANGTestProducts()[0]
	directHealth := &iosXRHealth{}
	direct := product.decode(directHealth, &gnmi.Notification{Update: []*gnmi.Update{{
		Path: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "test:root"}, {Name: "aug:counters"}, {Name: "value"}}},
		Val:  intTypedValue(9),
	}}}, directGNMIDecodeLimits{})
	directName := mustDynamicYANGName(t, product.prefix, "aug", []string{"test:root", "aug:counters", "value"}, dynamicYANGMetricVariantNumber)
	directMetric := mustFindMetricExact(t, direct, directName)
	require.Equal(t, pmetric.MetricTypeSum, directMetric.Type())
	assert.Equal(t, "aug", attrValue(t, directMetric.Sum().DataPoints().At(0).Attributes(), "cisco.yang.module"))
	assert.Zero(t, directHealth.snapshot().droppedDatapoints)

	sink := &consumertest.MetricsSink{}
	dialOutHealth := &iosXRHealth{}
	normalizer := product.normalizer(sink, dialOutHealth)
	require.NoError(t, normalizer.ConsumeMetrics(t.Context(), rawDynamicYANGDialOutMetric(
		"test:root", "test", "cisco.aug:counters.value", "content/aug:counters/value", pmetric.MetricTypeGauge, intMetricNumber(9),
	)))
	dialOutName := mustDialOutDynamicYANGName(t, product.prefix, "test", "test:root", "content/aug:counters/value", dynamicYANGMetricVariantNumber)
	require.Equal(t, pmetric.MetricTypeSum, mustFindMetricExactInBatches(t, sink.AllMetrics(), dialOutName).Type())
	assert.Zero(t, dialOutHealth.snapshot().droppedDatapoints)
}

func TestDialOutDynamicYANGGaugeCarrierPromotionAndConflictingSums(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		t.Run(product.name+"/gauge_carrier_to_sum", func(t *testing.T) {
			sink := &consumertest.MetricsSink{}
			health := &iosXRHealth{}
			normalizer := product.normalizer(sink, health)
			require.NoError(t, normalizer.ConsumeMetrics(t.Context(), rawDynamicYANGDialOutMetric(
				"test-module:state", "", "cisco.packets", "content/packets", pmetric.MetricTypeGauge, doubleMetricNumber(7),
			)))
			name := mustDialOutDynamicYANGName(t, product.prefix, "test-module", "test-module:state", "content/packets", dynamicYANGMetricVariantNumber)
			metric := mustFindMetricExactInBatches(t, sink.AllMetrics(), name)
			require.Equal(t, pmetric.MetricTypeSum, metric.Type())
			assert.Equal(t, int64(7), metric.Sum().DataPoints().At(0).IntValue())
			assert.Zero(t, health.snapshot().droppedDatapoints)
		})

		t.Run(product.name+"/sum_conflicts_with_gauge", func(t *testing.T) {
			sink := &consumertest.MetricsSink{}
			health := &iosXRHealth{}
			normalizer := product.normalizer(sink, health)
			require.NoError(t, normalizer.ConsumeMetrics(t.Context(), rawDynamicYANGDialOutMetric(
				"test-module:state", "", "cisco.value", "content/value", pmetric.MetricTypeSum, intMetricNumber(1),
			)))
			assert.Empty(t, sink.AllMetrics())
			assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
		})

		t.Run(product.name+"/malformed_sum", func(t *testing.T) {
			sink := &consumertest.MetricsSink{}
			health := &iosXRHealth{}
			normalizer := product.normalizer(sink, health)
			raw := rawDynamicYANGDialOutMetric("test-module:state", "", "cisco.packets", "content/packets", pmetric.MetricTypeSum, intMetricNumber(1))
			raw.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Sum().SetAggregationTemporality(pmetric.AggregationTemporalityDelta)
			require.NoError(t, normalizer.ConsumeMetrics(t.Context(), raw))
			assert.Empty(t, sink.AllMetrics())
			assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
		})
	}
}

func TestDialOutDynamicYANGRejectsIncompatibleCounterRepresentationAcrossBatches(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		t.Run(product.name, func(t *testing.T) {
			sink := &consumertest.MetricsSink{}
			health := &iosXRHealth{}
			normalizer := product.normalizer(sink, health)
			for _, value := range []metricNumber{intMetricNumber(1), doubleMetricNumber(1.5)} {
				require.NoError(t, normalizer.ConsumeMetrics(t.Context(), rawDynamicYANGDialOutMetric(
					"test-module:state", "", "cisco.packets", "content/packets", pmetric.MetricTypeGauge, value,
				)))
			}
			require.Len(t, sink.AllMetrics(), 1)
			assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
		})
	}
}

func TestDynamicYANGUnsetNumberDatapointsFailClosed(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		for _, instrument := range []struct {
			name       string
			metricType pmetric.MetricType
			path       []string
			sourcePath string
		}{
			{name: "gauge", metricType: pmetric.MetricTypeGauge, path: []string{"test:root", "value"}, sourcePath: "content/value"},
			{name: "sum", metricType: pmetric.MetricTypeSum, path: []string{"test:root", "packets"}, sourcePath: "content/packets"},
		} {
			t.Run(product.name+"/direct/"+instrument.name, func(t *testing.T) {
				sink := &consumertest.MetricsSink{}
				health := &iosXRHealth{}
				name := mustDynamicYANGName(t, product.prefix, "test", instrument.path, dynamicYANGMetricVariantNumber)
				raw := unsetDynamicYANGNumberMetric(name, instrument.metricType, "")
				require.NoError(t, product.directNormalizer(sink, health).ConsumeMetrics(t.Context(), raw))
				assert.Empty(t, sink.AllMetrics(), "an unset direct datapoint must not become numeric zero")
				assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
			})
			t.Run(product.name+"/dial_out/"+instrument.name, func(t *testing.T) {
				sink := &consumertest.MetricsSink{}
				health := &iosXRHealth{}
				raw := unsetDynamicYANGNumberMetric("cisco."+instrument.path[len(instrument.path)-1], instrument.metricType, instrument.sourcePath)
				rm := raw.ResourceMetrics().At(0)
				rm.Resource().Attributes().PutStr("cisco.node_id", "device-1")
				rm.Resource().Attributes().PutStr("cisco.encoding_path", "test:root")
				require.NoError(t, product.normalizer(sink, health).ConsumeMetrics(t.Context(), raw))
				assert.Empty(t, sink.AllMetrics(), "an unset dial-out datapoint must not become numeric zero")
				assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
			})
		}
	}
}

func TestDialOutDynamicYANGFinalNameLimitDropsWholeMetricExactly(t *testing.T) {
	for _, product := range dynamicYANGTestProducts() {
		t.Run(product.name, func(t *testing.T) {
			name := mustDialOutDynamicYANGName(t, product.prefix, "test-module", "test-module:state", "content/value", dynamicYANGMetricVariantNumber)

			acceptedSink := &consumertest.MetricsSink{}
			acceptedHealth := &iosXRHealth{}
			accepted := product.normalizerWithLimit(acceptedSink, acceptedHealth, len(name))
			require.NoError(t, accepted.ConsumeMetrics(t.Context(), rawDynamicYANGDialOutMetric(
				"test-module:state", "", "cisco.value", "content/value", pmetric.MetricTypeGauge, intMetricNumber(1),
			)))
			_ = mustFindMetricExactInBatches(t, acceptedSink.AllMetrics(), name)
			assert.Zero(t, acceptedHealth.snapshot().droppedDatapoints)

			rejectedSink := &consumertest.MetricsSink{}
			rejectedHealth := &iosXRHealth{}
			rejected := product.normalizerWithLimit(rejectedSink, rejectedHealth, len(name)-1)
			raw := rawDynamicYANGDialOutMetric("test-module:state", "", "cisco.value", "content/value", pmetric.MetricTypeGauge, intMetricNumber(1))
			metric := raw.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0)
			second := metric.Gauge().DataPoints().AppendEmpty()
			second.SetIntValue(2)
			second.Attributes().PutStr("cisco.yang.source_path", "content/value")
			require.NoError(t, rejected.ConsumeMetrics(t.Context(), raw))
			assert.Empty(t, rejectedSink.AllMetrics(), "an overflowed dynamic metric must be removed before delivery")
			assert.Equal(t, int64(2), rejectedHealth.snapshot().droppedDatapoints)
		})
	}
}

func TestDynamicYANGMetricNameLimitUsesFinalBuilderBudget(t *testing.T) {
	budget := newFinalDatapointBudget(finalDatapointBudgetLimits{maxMetricNameBytes: 17}, 10)
	builder := newFinalIndexedMetricBuilder(pmetric.NewScopeMetrics(), budget)
	assert.Equal(t, 17, builder.dynamicYANGMetricNameLimit())
}

func rawDynamicYANGDialOutMetric(encodingPath, module, metricName, sourcePath string, metricType pmetric.MetricType, value metricNumber) pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("cisco.node_id", "device-1")
	rm.Resource().Attributes().PutStr("cisco.encoding_path", encodingPath)
	if module != "" {
		rm.Resource().Attributes().PutStr("cisco.yang.module", module)
	}
	metric := rm.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	metric.SetName(metricName)
	var dp pmetric.NumberDataPoint
	if metricType == pmetric.MetricTypeSum {
		sum := metric.SetEmptySum()
		sum.SetIsMonotonic(true)
		sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
		dp = sum.DataPoints().AppendEmpty()
	} else {
		dp = metric.SetEmptyGauge().DataPoints().AppendEmpty()
	}
	value.set(dp)
	dp.Attributes().PutStr("cisco.yang.source_path", sourcePath)
	return md
}

func unsetDynamicYANGNumberMetric(metricName string, metricType pmetric.MetricType, sourcePath string) pmetric.Metrics {
	md := pmetric.NewMetrics()
	metric := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	metric.SetName(metricName)
	var dp pmetric.NumberDataPoint
	if metricType == pmetric.MetricTypeSum {
		sum := metric.SetEmptySum()
		sum.SetIsMonotonic(true)
		sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
		dp = sum.DataPoints().AppendEmpty()
	} else {
		dp = metric.SetEmptyGauge().DataPoints().AppendEmpty()
	}
	if sourcePath != "" {
		dp.Attributes().PutStr("cisco.yang.source_path", sourcePath)
	}
	return md
}

func intTypedValue(value int64) *gnmi.TypedValue {
	return &gnmi.TypedValue{Value: &gnmi.TypedValue_IntVal{IntVal: value}}
}

func doubleTypedValue(value float64) *gnmi.TypedValue {
	return &gnmi.TypedValue{Value: &gnmi.TypedValue_DoubleVal{DoubleVal: value}}
}

func mustDynamicYANGName(t *testing.T, prefix, module string, path []string, variant dynamicYANGMetricVariant) string {
	t.Helper()
	name, ok := dynamicYANGMetricName(prefix, module, path, variant, directGNMIHardMaxMetricNameBytes)
	require.True(t, ok)
	return name
}

func mustFindMetricExact(t *testing.T, md pmetric.Metrics, name string) pmetric.Metric {
	t.Helper()
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		sms := md.ResourceMetrics().At(i).ScopeMetrics()
		for j := 0; j < sms.Len(); j++ {
			metrics := sms.At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				if metrics.At(k).Name() == name {
					return metrics.At(k)
				}
			}
		}
	}
	require.FailNowf(t, "metric not found", "missing exact metric %s", name)
	return pmetric.Metric{}
}

func mustFindMetricExactInBatches(t *testing.T, batches []pmetric.Metrics, name string) pmetric.Metric {
	t.Helper()
	for _, md := range batches {
		if metricCountExact(md, name) > 0 {
			return mustFindMetricExact(t, md, name)
		}
	}
	require.FailNowf(t, "metric not found", "missing exact metric %s", name)
	return pmetric.Metric{}
}

func metricCountExact(md pmetric.Metrics, name string) int {
	count := 0
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		sms := md.ResourceMetrics().At(i).ScopeMetrics()
		for j := 0; j < sms.Len(); j++ {
			metrics := sms.At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				if metrics.At(k).Name() == name {
					count++
				}
			}
		}
	}
	return count
}
