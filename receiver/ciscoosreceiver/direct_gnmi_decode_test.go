// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

func TestDirectGNMITimestampNormalizesCiscoMagnitudesAndBounds(t *testing.T) {
	receipt := time.Date(2026, time.July, 10, 12, 0, 0, 0, time.UTC)
	want := time.Date(2025, time.January, 2, 3, 4, 5, 678_901_000, time.UTC)

	for name, raw := range map[string]int64{
		"seconds":      want.Unix(),
		"milliseconds": want.UnixMilli(),
		"microseconds": want.UnixMicro(),
		"nanoseconds":  want.UnixNano(),
	} {
		t.Run(name, func(t *testing.T) {
			got := directGNMITimestamp(raw, receipt).AsTime()
			switch name {
			case "seconds":
				assert.Equal(t, want.Truncate(time.Second), got)
			case "milliseconds":
				assert.Equal(t, want.Truncate(time.Millisecond), got)
			case "microseconds":
				assert.Equal(t, want.Truncate(time.Microsecond), got)
			default:
				assert.Equal(t, want, got)
			}
		})
	}

	for name, raw := range map[string]int64{
		"zero":       0,
		"pre-2000":   time.Date(1999, time.December, 31, 23, 59, 59, 0, time.UTC).Unix(),
		"far-future": receipt.Add(25 * time.Hour).UnixNano(),
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, receipt, directGNMITimestamp(raw, receipt).AsTime())
		})
	}
}

func TestDeprecatedProductGNMIDecodersAcceptLegacyValueAndSecondsTimestamp(t *testing.T) {
	eventTime := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	notification := &gnmi.Notification{
		Timestamp: eventTime.Unix(),
		Prefix:    mustParseIOSXRPath(t, "test:root"),
		Update: []*gnmi.Update{{
			Path:  mustParseIOSXRPath(t, "value"),
			Value: &gnmi.Value{Type: gnmi.Encoding_JSON, Value: []byte("5")}, //nolint:staticcheck // Exercise compatibility with the deprecated wire field.
		}},
	}

	decoders := map[string]func() pmetric.Metrics{
		"ios-xr": func() pmetric.Metrics {
			decoder := iosXRGNMIUpdateDecoder{target: IOSXRTargetConfig{Name: "xr"}, health: &iosXRHealth{}}
			return decoder.decodeNotification(notification, iosXRTelemetryTransportDialIn)
		},
		"catalyst-9800": func() pmetric.Metrics {
			decoder := catalyst9800GNMIUpdateDecoder{target: Catalyst9800TargetConfig{Name: "wlc"}, health: &catalyst9800Health{}}
			return decoder.decodeNotification(notification, catalyst9800TelemetryTransportDialIn)
		},
	}

	for name, decode := range decoders {
		t.Run(name, func(t *testing.T) {
			md := decode()
			prefix := "cisco.catalyst9800.yang"
			if name == "ios-xr" {
				prefix = "cisco.iosxr.yang"
			}
			metricName := mustDynamicYANGName(t, prefix, "test", []string{"root", "value"}, dynamicYANGMetricVariantNumber)
			metric := mustFindIOSXRMetric(t, md, metricName)
			require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
			dp := metric.Gauge().DataPoints().At(0)
			assert.Equal(t, pmetric.NumberDataPointValueTypeDouble, dp.ValueType())
			assert.Equal(t, float64(5), dp.DoubleValue())
			assert.Equal(t, eventTime, dp.Timestamp().AsTime())
		})
	}
}

func TestDirectGNMIPathTargetsSeparateDynamicSourceIdentity(t *testing.T) {
	products := []struct {
		name       string
		metricBase string
		decode     func(*gnmi.Notification, *iosXRHealth) pmetric.Metrics
	}{
		{
			name:       "ios-xr",
			metricBase: "cisco.iosxr.yang",
			decode: func(notification *gnmi.Notification, health *iosXRHealth) pmetric.Metrics {
				decoder := iosXRGNMIUpdateDecoder{target: IOSXRTargetConfig{Name: "xr"}, health: health}
				return decoder.decodeNotification(notification, iosXRTelemetryTransportDialIn)
			},
		},
		{
			name:       "catalyst-9800",
			metricBase: "cisco.catalyst9800.yang",
			decode: func(notification *gnmi.Notification, health *iosXRHealth) pmetric.Metrics {
				decoder := catalyst9800GNMIUpdateDecoder{target: Catalyst9800TargetConfig{Name: "wlc"}, health: health}
				return decoder.decodeNotification(notification, catalyst9800TelemetryTransportDialIn)
			},
		},
	}

	for _, product := range products {
		t.Run(product.name, func(t *testing.T) {
			prefix := mustParseIOSXRPath(t, "test:root")
			pathForTarget := func(path, target string) *gnmi.Path {
				parsed := mustParseIOSXRPath(t, path)
				parsed.Target = target
				return parsed
			}
			health := &iosXRHealth{}
			md := product.decode(&gnmi.Notification{
				Prefix: prefix,
				Update: []*gnmi.Update{
					{Path: pathForTarget("value", "tenant-a"), Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_IntVal{IntVal: 1}}},
					{Path: pathForTarget("value", "tenant-b"), Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_IntVal{IntVal: 2}}},
				},
				Delete: []*gnmi.Path{
					pathForTarget("stale", "tenant-a"),
					pathForTarget("stale", "tenant-b"),
				},
			}, health)

			metricName := mustDynamicYANGName(t, product.metricBase, "test", []string{"root", "value"}, dynamicYANGMetricVariantNumber)
			metric := mustFindIOSXRMetric(t, md, metricName)
			require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
			points := metric.Gauge().DataPoints()
			require.Equal(t, 2, points.Len(), "otherwise identical path targets must remain separate datapoints")
			valuesBySource := make(map[string]float64, points.Len())
			for index := 0; index < points.Len(); index++ {
				point := points.At(index)
				assert.Equal(t, "test:root/value", attrValue(t, point.Attributes(), "cisco.yang.path"))
				valuesBySource[attrValue(t, point.Attributes(), "cisco.yang.source_path")] = point.DoubleValue()
			}
			assert.Equal(t, map[string]float64{
				"@target=tenant-a@/test:root/value": 1,
				"@target=tenant-b@/test:root/value": 2,
			}, valuesBySource)

			deleteName := mustDynamicYANGName(t, product.metricBase, "test", []string{"root", "stale"}, dynamicYANGMetricVariantInfo)
			deleted := mustFindIOSXRMetric(t, md, deleteName).Gauge().DataPoints()
			require.Equal(t, 2, deleted.Len(), "relative delete targets must participate in source identity")
			deleteSources := make(map[string]struct{}, deleted.Len())
			for index := 0; index < deleted.Len(); index++ {
				point := deleted.At(index)
				assert.Equal(t, "test:root/stale", attrValue(t, point.Attributes(), "cisco.yang.path"))
				assert.Equal(t, "deleted", attrValue(t, point.Attributes(), "value"))
				deleteSources[attrValue(t, point.Attributes(), "cisco.yang.source_path")] = struct{}{}
			}
			assert.Equal(t, map[string]struct{}{
				"@target=tenant-a@/test:root/stale": {},
				"@target=tenant-b@/test:root/stale": {},
			}, deleteSources)

			prefixTarget := mustParseIOSXRPath(t, "test:root")
			prefixTarget.Target = "tenant-prefix"
			prefixMD := product.decode(&gnmi.Notification{
				Prefix: prefixTarget,
				Update: []*gnmi.Update{{
					Path: mustParseIOSXRPath(t, "value"),
					Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_IntVal{IntVal: 3}},
				}},
				Delete: []*gnmi.Path{mustParseIOSXRPath(t, "stale")},
			}, health)
			prefixPoint := mustFindIOSXRMetric(t, prefixMD, metricName).Gauge().DataPoints().At(0)
			assert.Equal(t, "@target=tenant-prefix@/test:root/value", attrValue(t, prefixPoint.Attributes(), "cisco.yang.source_path"))
			prefixDelete := mustFindIOSXRMetric(t, prefixMD, deleteName).Gauge().DataPoints().At(0)
			assert.Equal(t, "@target=tenant-prefix@/test:root/stale", attrValue(t, prefixDelete.Attributes(), "cisco.yang.source_path"))
			assert.Zero(t, health.snapshot().decodeErrors)
			assert.Zero(t, health.snapshot().droppedDatapoints)
		})
	}
}

func TestDirectGNMISourcePathTargetFramingIsInjectiveAndBounded(t *testing.T) {
	const (
		pathText       = "test:root/value"
		target         = "tenant/a@b#c%"
		expectedSource = "@target=tenant%2Fa%40b%23c%25@/" + pathText
	)

	for _, test := range []struct {
		name     string
		prefix   *gnmi.Path
		relative *gnmi.Path
	}{
		{name: "prefix target", prefix: &gnmi.Path{Target: target}, relative: &gnmi.Path{}},
		{name: "relative update or delete target", prefix: &gnmi.Path{}, relative: &gnmi.Path{Target: target}},
		{name: "matching prefix and relative targets", prefix: &gnmi.Path{Target: target}, relative: &gnmi.Path{Target: target}},
	} {
		t.Run(test.name, func(t *testing.T) {
			attrs := map[string]string{}
			budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributeValueBytes: len(expectedSource)}, 10)
			require.True(t, setDirectGNMISourcePath(attrs, test.prefix, test.relative, "test:root", "value", budget))
			assert.Equal(t, pathText, attrs["cisco.yang.path"], "the user-facing path must not gain target framing")
			assert.Equal(t, expectedSource, attrs["cisco.yang.source_path"])
			assert.Zero(t, budget.decodeErrors)
			assert.Zero(t, budget.dropped)
		})
	}

	t.Run("target frame preserves JSON boundary", func(t *testing.T) {
		const expectedJSONSource = expectedSource + "#/child~1name"
		attrs := map[string]string{}
		budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributeValueBytes: len(expectedJSONSource)}, 10)
		require.True(t, setDirectGNMISourcePath(attrs, &gnmi.Path{}, &gnmi.Path{Target: target}, "test:root", "value", budget))
		require.True(t, extendDirectGNMISourcePath(attrs, "child/name", budget))
		assert.Equal(t, expectedJSONSource, attrs["cisco.yang.source_path"])
		assert.Equal(t, pathText+"/child~1name", attrs["cisco.yang.path"])
	})

	t.Run("one byte over value budget is rejected atomically", func(t *testing.T) {
		attrs := map[string]string{"existing": "value"}
		budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributeValueBytes: len(expectedSource) - 1}, 10)
		assert.False(t, setDirectGNMISourcePath(attrs, &gnmi.Path{Target: target}, nil, "test:root", "value", budget))
		assert.Equal(t, map[string]string{"existing": "value"}, attrs)
		assert.Zero(t, budget.decodeErrors)
		assert.Equal(t, int64(1), budget.dropped)
	})

	t.Run("conflicting targets are decode failures", func(t *testing.T) {
		attrs := map[string]string{}
		budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
		assert.False(t, setDirectGNMISourcePath(attrs, &gnmi.Path{Target: "tenant-a"}, &gnmi.Path{Target: "tenant-b"}, "test:root", "value", budget))
		assert.Empty(t, attrs)
		assert.Equal(t, int64(1), budget.decodeErrors)
		assert.Equal(t, int64(1), budget.dropped)
	})
}

func TestDirectGNMIDecodersRejectEmptyEffectiveUpdatePathsBeforeValueDecode(t *testing.T) {
	values := []struct {
		name  string
		value *gnmi.TypedValue
	}{
		{name: "scalar", value: &gnmi.TypedValue{Value: &gnmi.TypedValue_IntVal{IntVal: 1}}},
		{name: "JSON scalar", value: &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte("2")}}},
		{name: "JSON root object", value: &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{"child":3}`)}}},
	}
	products := []struct {
		name       string
		metricBase string
		decode     func(*gnmi.Notification, *iosXRHealth) pmetric.Metrics
	}{
		{
			name:       "ios-xr",
			metricBase: "cisco.iosxr.yang",
			decode: func(notification *gnmi.Notification, health *iosXRHealth) pmetric.Metrics {
				decoder := iosXRGNMIUpdateDecoder{target: IOSXRTargetConfig{Name: "xr"}, health: health}
				return decoder.decodeNotification(notification, iosXRTelemetryTransportDialIn)
			},
		},
		{
			name:       "catalyst-9800",
			metricBase: "cisco.catalyst9800.yang",
			decode: func(notification *gnmi.Notification, health *iosXRHealth) pmetric.Metrics {
				decoder := catalyst9800GNMIUpdateDecoder{target: Catalyst9800TargetConfig{Name: "wlc"}, health: health}
				return decoder.decodeNotification(notification, catalyst9800TelemetryTransportDialIn)
			},
		},
	}

	for _, product := range products {
		for _, value := range values {
			t.Run(product.name+"/"+value.name, func(t *testing.T) {
				health := &iosXRHealth{}
				md := product.decode(&gnmi.Notification{Update: []*gnmi.Update{{Val: value.value}}}, health)

				assert.Zero(t, metricCountNamed(md, product.metricBase), "a bare dynamic YANG metric must never be emitted")
				assert.Zero(t, metricCountNamed(md, product.metricBase+".child"), "a root JSON object must not manufacture a descendant metric")
				assert.Empty(t, directGNMIMetricNamesWithPrefix(md, product.metricBase+"."))
				assert.Equal(t, int64(1), health.snapshot().decodeErrors)
				assert.Equal(t, int64(1), health.snapshot().droppedDatapoints)
			})
		}
	}
}

func directGNMIMetricNamesWithPrefix(md pmetric.Metrics, prefix string) []string {
	names := []string{}
	for resourceIndex := 0; resourceIndex < md.ResourceMetrics().Len(); resourceIndex++ {
		scopes := md.ResourceMetrics().At(resourceIndex).ScopeMetrics()
		for scopeIndex := 0; scopeIndex < scopes.Len(); scopeIndex++ {
			metrics := scopes.At(scopeIndex).Metrics()
			for metricIndex := 0; metricIndex < metrics.Len(); metricIndex++ {
				if name := metrics.At(metricIndex).Name(); strings.HasPrefix(name, prefix) {
					names = append(names, name)
				}
			}
		}
	}
	return names
}

func TestIndexedMetricBuilderCoalescesStreams(t *testing.T) {
	md := pmetric.NewMetrics()
	sm := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	builder := newIndexedMetricBuilder(sm, newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10))

	require.True(t, builder.appendNumber("test.metric", pmetric.MetricTypeGauge, intMetricNumber(1), 0, nil))
	require.True(t, builder.appendNumber("test.metric", pmetric.MetricTypeGauge, intMetricNumber(2), 0, nil))

	require.Equal(t, 1, sm.Metrics().Len())
	assert.Equal(t, 2, sm.Metrics().At(0).Gauge().DataPoints().Len())
}

func TestDirectGNMIDecodeBudgetRejectsOversizedFieldsBeforeAppend(t *testing.T) {
	md := pmetric.NewMetrics()
	sm := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{
		maxDatapoints:          10,
		maxFields:              2,
		maxDepth:               2,
		maxMetricNameBytes:     8,
		maxAttributes:          1,
		maxAttributeKeyBytes:   4,
		maxAttributeValueBytes: 4,
		maxAttributeBytes:      8,
	}, 10)
	builder := newIndexedMetricBuilder(sm, budget)

	assert.False(t, builder.appendNumber("metric-name-too-long", pmetric.MetricTypeGauge, intMetricNumber(1), 0, nil))
	assert.False(t, builder.appendNumber("metric", pmetric.MetricTypeGauge, intMetricNumber(1), 0, map[string]string{"key": "value-too-long"}))
	assert.False(t, builder.appendNumber("metric", pmetric.MetricTypeGauge, intMetricNumber(1), 0, map[string]string{"one": "1", "two": "2"}))
	assert.Empty(t, sm.Metrics().Len())
	assert.Equal(t, int64(3), budget.dropped)

	assert.True(t, budget.visitField(2))
	assert.False(t, budget.visitField(3))
	assert.True(t, budget.exhausted)
	assert.Equal(t, int64(4), budget.dropped)

	fieldBudget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxFields: 1}, 10)
	assert.True(t, fieldBudget.visitField(1))
	assert.False(t, fieldBudget.visitField(1))
	assert.True(t, fieldBudget.exhausted)
}

func TestDirectGNMIDecodeBudgetCapsAggregateAttributeBytes(t *testing.T) {
	md := pmetric.NewMetrics()
	sm := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributeBytes: 8}, 10)
	builder := newIndexedMetricBuilder(sm, budget)

	require.True(t, builder.appendNumber("metric", pmetric.MetricTypeGauge, intMetricNumber(1), 0, map[string]string{"key": "1"}))
	require.True(t, builder.appendNumber("metric", pmetric.MetricTypeGauge, intMetricNumber(2), 0, map[string]string{"key": "2"}))
	assert.False(t, builder.appendNumber("metric", pmetric.MetricTypeGauge, intMetricNumber(3), 0, map[string]string{"key": "3"}))
	assert.Equal(t, 2, sm.Metrics().At(0).Gauge().DataPoints().Len())
	assert.True(t, budget.exhausted)
}

func TestDirectGNMIEmptyPathKeyIsEmittedAndExactlyAccounted(t *testing.T) {
	const pathKey = "cisco.yang.key.empty_key"
	attrs := map[string]string{
		pathKey:          "",
		"optional.empty": "",
	}

	md := pmetric.NewMetrics()
	sm := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	directBudget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributeBytes: len(pathKey)}, 10)
	require.True(t, newIndexedMetricBuilder(sm, directBudget).appendNumber("test.metric", pmetric.MetricTypeGauge, intMetricNumber(1), 0, attrs))
	directAttrs := sm.Metrics().At(0).Gauge().DataPoints().At(0).Attributes()
	value, exists := directAttrs.Get(pathKey)
	require.True(t, exists)
	assert.Empty(t, value.Str())
	_, optionalExists := directAttrs.Get("optional.empty")
	assert.False(t, optionalExists)
	assert.Equal(t, len(pathKey), directBudget.attributeBytes)

	overBudget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributeBytes: len(pathKey) - 1}, 10)
	overMD := pmetric.NewMetrics()
	overSM := overMD.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	assert.False(t, newIndexedMetricBuilder(overSM, overBudget).appendNumber("test.metric", pmetric.MetricTypeGauge, intMetricNumber(1), 0, attrs))
	assert.True(t, overBudget.exhausted)
	assert.Zero(t, overSM.Metrics().Len())

	finalMD := pmetric.NewMetrics()
	finalSM := finalMD.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	finalBytes := len(pathKey) + len("optional.empty")
	finalBudget := newFinalDatapointBudget(finalDatapointBudgetLimits{maxAttributeBytes: finalBytes}, 10)
	require.True(t, newFinalIndexedMetricBuilder(finalSM, finalBudget).appendNumber("test.metric", pmetric.MetricTypeGauge, intMetricNumber(1), 0, attrs))
	finalAttrs := finalSM.Metrics().At(0).Gauge().DataPoints().At(0).Attributes()
	value, exists = finalAttrs.Get(pathKey)
	require.True(t, exists)
	assert.Empty(t, value.Str())
	optional, optionalExists := finalAttrs.Get("optional.empty")
	require.True(t, optionalExists)
	assert.Empty(t, optional.Str())
	assert.Equal(t, finalBytes, finalBudget.attributeBytes)
	assert.Equal(t, 2, finalBudget.attributeNodes)
}

func TestDirectGNMIDecodeBudgetRejectsNonFiniteNumbers(t *testing.T) {
	md := pmetric.NewMetrics()
	sm := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	budget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{}, 10)
	builder := newIndexedMetricBuilder(sm, budget)

	assert.False(t, builder.appendNumber("metric", pmetric.MetricTypeGauge, doubleMetricNumber(math.NaN()), 0, nil))
	assert.Zero(t, sm.Metrics().Len())
	assert.Equal(t, int64(1), budget.decodeErrors)
	assert.Equal(t, int64(1), budget.dropped)
}

func TestIndexedMetricBuilderInfoValueHasDeterministicPrecedenceAndAccounting(t *testing.T) {
	attrs := map[string]string{"value": "path-key", "key": "context"}
	wantBytes := len("value") + len("decoded-leaf") +
		len("cisco.key.value") + len("path-key") +
		len("key") + len("context")

	md := pmetric.NewMetrics()
	sm := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	directBudget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxAttributeBytes: wantBytes}, 10)
	builder := newIndexedMetricBuilder(sm, directBudget)
	require.True(t, builder.appendInfo("test.info", "decoded-leaf", 0, attrs))

	dp := sm.Metrics().At(0).Gauge().DataPoints().At(0)
	assert.Equal(t, "decoded-leaf", attrValue(t, dp.Attributes(), "value"))
	assert.Equal(t, "path-key", attrValue(t, dp.Attributes(), "cisco.key.value"))
	assert.Equal(t, wantBytes, directBudget.attributeBytes)
	assert.False(t, directBudget.exhausted)

	finalMD := pmetric.NewMetrics()
	finalSM := finalMD.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	finalBudget := newFinalDatapointBudget(finalDatapointBudgetLimits{maxAttributeBytes: wantBytes}, 10)
	finalBuilder := newFinalIndexedMetricBuilder(finalSM, finalBudget)
	require.True(t, finalBuilder.appendInfo("test.info", "decoded-leaf", 0, attrs))
	finalAttrs := finalSM.Metrics().At(0).Gauge().DataPoints().At(0).Attributes()
	assert.Equal(t, "decoded-leaf", attrValue(t, finalAttrs, "value"))
	assert.Equal(t, "path-key", attrValue(t, finalAttrs, "cisco.key.value"))
	assert.Equal(t, wantBytes, finalBudget.attributeBytes)
}

func TestEscapeReservedInfoAttributeUsesDeterministicNumberedFallback(t *testing.T) {
	original := map[string]string{
		"value":             "path-key",
		"cisco.key.value":   "first",
		"cisco.key.2.value": "second",
	}
	escaped := escapeReservedInfoAttribute(original, "value")
	assert.Equal(t, "path-key", escaped["cisco.key.3.value"])
	assert.NotContains(t, escaped, "value")
	assert.Equal(t, "path-key", original["value"], "escaping must not mutate attributes shared by other derived metrics")
}

func TestFinalDatapointBudgetEnforcesPerPointAttributeShape(t *testing.T) {
	t.Run("attribute count boundary", func(t *testing.T) {
		atLimit := newFinalDatapointBudget(finalDatapointBudgetLimits{}, 10)
		assert.True(t, atLimit.reserveStringDatapoint(numberedStringAttrs(directGNMIHardMaxAttributesPerPoint)))

		overLimit := newFinalDatapointBudget(finalDatapointBudgetLimits{}, 10)
		assert.False(t, overLimit.reserveStringDatapoint(numberedStringAttrs(directGNMIHardMaxAttributesPerPoint+1)))
		assert.Equal(t, int64(1), overLimit.dropped)
		assert.Zero(t, overLimit.datapoints)
	})

	t.Run("key boundary", func(t *testing.T) {
		atLimit := newFinalDatapointBudget(finalDatapointBudgetLimits{}, 10)
		assert.True(t, atLimit.reserveStringDatapoint(map[string]string{strings.Repeat("k", directGNMIHardMaxAttributeKeyBytes): "v"}))

		overLimit := newFinalDatapointBudget(finalDatapointBudgetLimits{}, 10)
		assert.False(t, overLimit.reserveStringDatapoint(map[string]string{strings.Repeat("k", directGNMIHardMaxAttributeKeyBytes+1): "v"}))
		assert.Equal(t, int64(1), overLimit.dropped)
	})

	t.Run("value boundary", func(t *testing.T) {
		atLimit := newFinalDatapointBudget(finalDatapointBudgetLimits{}, 10)
		assert.True(t, atLimit.reserveStringDatapoint(map[string]string{"key": strings.Repeat("v", directGNMIHardMaxAttributeValueBytes)}))

		overLimit := newFinalDatapointBudget(finalDatapointBudgetLimits{}, 10)
		assert.False(t, overLimit.reserveStringDatapoint(map[string]string{"key": strings.Repeat("v", directGNMIHardMaxAttributeValueBytes+1)}))
		assert.Equal(t, int64(1), overLimit.dropped)
	})

	t.Run("nested value total", func(t *testing.T) {
		attrs := pcommon.NewMap()
		values := attrs.PutEmptySlice("nested")
		values.AppendEmpty().SetStr(strings.Repeat("a", directGNMIHardMaxAttributeValueBytes/2))
		values.AppendEmpty().SetStr(strings.Repeat("b", directGNMIHardMaxAttributeValueBytes/2+1))
		budget := newFinalDatapointBudget(finalDatapointBudgetLimits{}, 10)
		assert.False(t, budget.reservePcommonDatapoint(attrs, nil))
		assert.Equal(t, int64(1), budget.dropped)
	})
}

func TestFinalAliasBudgetPreservesAndExactlyAccountsEmptyCanonicalAttributes(t *testing.T) {
	const key = "tenant-code"
	md := pmetric.NewMetrics()
	sm := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	budget := newFinalDatapointBudget(finalDatapointBudgetLimits{
		maxAttributeBytes: len(key),
		maxAttributeNodes: 1,
	}, 1)

	require.True(t, newFinalIndexedMetricBuilder(sm, budget).appendNumber(
		"test.metric",
		pmetric.MetricTypeGauge,
		intMetricNumber(1),
		0,
		map[string]string{key: ""},
	))
	attrs := sm.Metrics().At(0).Gauge().DataPoints().At(0).Attributes()
	value, present := attrs.Get(key)
	require.True(t, present)
	assert.Empty(t, value.Str())
	assert.Equal(t, len(key), budget.attributeBytes)
	assert.Equal(t, 1, budget.attributeNodes)
}

func TestFinalStringBudgetAccountsEmptyDirectIdentity(t *testing.T) {
	budget := newFinalDatapointBudget(finalDatapointBudgetLimits{
		maxAttributeBytes: len("name"),
		maxAttributeNodes: 1,
	}, 1)
	require.True(t, budget.reserveStringDatapoint(map[string]string{"name": ""}))
	assert.Equal(t, len("name"), budget.attributeBytes)
	assert.Equal(t, 1, budget.attributeNodes)
}

func TestFinalIndexedMetricBuilderCountsEscapedInfoCollisionAtFinalLimit(t *testing.T) {
	build := func(rawAttributeCount int) (*finalDatapointBudget, pmetric.ScopeMetrics, bool) {
		attrs := numberedStringAttrs(rawAttributeCount - 1)
		attrs["value"] = "path-key"
		md := pmetric.NewMetrics()
		sm := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
		budget := newFinalDatapointBudget(finalDatapointBudgetLimits{}, 10)
		appended := newFinalIndexedMetricBuilder(sm, budget).appendInfo("test.info", "decoded", 0, attrs)
		return budget, sm, appended
	}

	atLimit, atLimitScope, appended := build(directGNMIHardMaxAttributesPerPoint - 1)
	require.True(t, appended)
	assert.Equal(t, directGNMIHardMaxAttributesPerPoint, atLimitScope.Metrics().At(0).Gauge().DataPoints().At(0).Attributes().Len())
	assert.Zero(t, atLimit.dropped)

	overLimit, overLimitScope, appended := build(directGNMIHardMaxAttributesPerPoint)
	assert.False(t, appended)
	assert.Zero(t, overLimitScope.Metrics().Len())
	assert.Equal(t, int64(1), overLimit.dropped)
}

func TestFinalDatapointBudgetBoundsNestedPdataDepthAndNodes(t *testing.T) {
	hostIPBudget := newFinalDatapointBudget(finalDatapointBudgetLimits{
		maxAttributeBytes: 100,
		maxAttributeDepth: 10,
		maxAttributeNodes: 1,
	}, 10)
	assert.False(t, hostIPBudget.reserveStringDatapoint(map[string]string{"host.ip": "192.0.2.1"}),
		"host.ip becomes a slice root plus one element")
	assert.Equal(t, int64(1), hostIPBudget.dropped)

	deepAttrs := pcommon.NewMap()
	level := deepAttrs.PutEmptySlice("nested").AppendEmpty()
	level = level.SetEmptySlice().AppendEmpty()
	level.SetEmptySlice()
	depthBudget := newFinalDatapointBudget(finalDatapointBudgetLimits{
		maxAttributeBytes: 100,
		maxAttributeDepth: 2,
		maxAttributeNodes: 10,
	}, 10)
	assert.False(t, depthBudget.reservePcommonDatapoint(deepAttrs, nil))
	assert.Equal(t, int64(1), depthBudget.dropped)
	assert.Zero(t, depthBudget.attributeNodes)

	wideAttrs := pcommon.NewMap()
	values := wideAttrs.PutEmptySlice("nested")
	for range 3 {
		values.AppendEmpty()
	}
	nodeBudget := newFinalDatapointBudget(finalDatapointBudgetLimits{
		maxAttributeBytes: 100,
		maxAttributeDepth: 10,
		maxAttributeNodes: 3,
	}, 10)
	assert.False(t, nodeBudget.reservePcommonDatapoint(wideAttrs, nil), "the container and its three empty children consume four nodes")
	assert.Equal(t, int64(1), nodeBudget.dropped)
	assert.Zero(t, nodeBudget.attributeNodes)
}

func TestFinalIndexedMetricBuilderDoesNotReuseIncompatibleStream(t *testing.T) {
	md := pmetric.NewMetrics()
	sm := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	existing := sm.Metrics().AppendEmpty()
	existing.SetName("test.counter")
	existing.SetUnit("By")
	delta := existing.SetEmptySum()
	delta.SetAggregationTemporality(pmetric.AggregationTemporalityDelta)
	delta.SetIsMonotonic(false)
	delta.DataPoints().AppendEmpty().SetIntValue(1)

	builder := newFinalIndexedMetricBuilder(sm, newFinalDatapointBudget(finalDatapointBudgetLimits{}, 10))
	require.True(t, builder.appendNumberWithUnit("test.counter", pmetric.MetricTypeSum, intMetricNumber(2), 0, nil, "By"))
	require.Equal(t, 2, sm.Metrics().Len())
	assert.Equal(t, pmetric.AggregationTemporalityDelta, sm.Metrics().At(0).Sum().AggregationTemporality())
	assert.False(t, sm.Metrics().At(0).Sum().IsMonotonic())
	assert.Equal(t, pmetric.AggregationTemporalityCumulative, sm.Metrics().At(1).Sum().AggregationTemporality())
	assert.True(t, sm.Metrics().At(1).Sum().IsMonotonic())
}

func numberedStringAttrs(count int) map[string]string {
	attrs := make(map[string]string, count)
	for i := range count {
		attrs["key."+strconv.Itoa(i)] = "value"
	}
	return attrs
}
