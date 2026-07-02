// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
