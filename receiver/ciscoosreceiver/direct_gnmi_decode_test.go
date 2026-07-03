// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

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

	nameBudget := newDirectGNMIDecodeBudget(directGNMIDecodeLimits{maxMetricNameBytes: 16}, 10)
	assert.False(t, nameBudget.allowMetricName("base", "module", []string{"oversized-path"}, ""))
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
