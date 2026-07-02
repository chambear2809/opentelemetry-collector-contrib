// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

func TestAbsoluteCounterTrackingConsumerDeclaresMutation(t *testing.T) {
	consumer := newAbsoluteCounterTrackingConsumer(consumertest.NewNop())
	assert.True(t, consumer.Capabilities().MutatesData)
	require.NoError(t, consumer.ConsumeMetrics(context.Background(), cumulativeTestMetric(time.Unix(100, 0), 1)))
}

func TestAbsoluteCounterTrackerDetectsReset(t *testing.T) {
	tracker := newAbsoluteCounterTracker()
	times := []time.Time{
		time.Unix(100, 0),
		time.Unix(200, 0),
		time.Unix(300, 0),
	}
	values := []int64{100, 150, 10}
	wantStarts := []time.Time{times[0], times[0], times[2]}
	for i, value := range values {
		md := cumulativeTestMetric(times[i], value)
		applyAbsoluteCounterStartTimestamps(md, tracker)
		dp := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Sum().DataPoints().At(0)
		assert.True(t, wantStarts[i].Equal(dp.StartTimestamp().AsTime()))
	}
}

func TestAbsoluteCounterTrackerKeepsSeriesIndependent(t *testing.T) {
	tracker := newAbsoluteCounterTracker()
	md := cumulativeTestMetric(time.Unix(100, 0), 5)
	dps := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Sum().DataPoints()
	second := dps.AppendEmpty()
	second.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(100, 0)))
	second.SetIntValue(9)
	second.Attributes().PutStr("network.interface.name", "eth2")
	applyAbsoluteCounterStartTimestamps(md, tracker)
	require.Equal(t, 2, dps.Len())
	assert.True(t, time.Unix(100, 0).Equal(dps.At(0).StartTimestamp().AsTime()))
	assert.True(t, time.Unix(100, 0).Equal(dps.At(1).StartTimestamp().AsTime()))
}

func TestAbsoluteCounterTrackerDoesNotTreatLateSampleAsReset(t *testing.T) {
	tracker := newAbsoluteCounterTracker()
	initial := cumulativeTestMetric(time.Unix(200, 0), 150)
	applyAbsoluteCounterStartTimestamps(initial, tracker)

	late := cumulativeTestMetric(time.Unix(100, 0), 10)
	applyAbsoluteCounterStartTimestamps(late, tracker)
	lateDP := late.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Sum().DataPoints().At(0)
	assert.False(t, lateDP.StartTimestamp().AsTime().After(lateDP.Timestamp().AsTime()))

	next := cumulativeTestMetric(time.Unix(300, 0), 175)
	applyAbsoluteCounterStartTimestamps(next, tracker)
	nextDP := next.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Sum().DataPoints().At(0)
	assert.True(t, time.Unix(200, 0).Equal(nextDP.StartTimestamp().AsTime()))
}

func TestAbsoluteCounterTrackerDoesNotResetDuplicateTimestamp(t *testing.T) {
	tracker := newAbsoluteCounterTracker()
	initial := cumulativeTestMetric(time.Unix(100, 0), 150)
	applyAbsoluteCounterStartTimestamps(initial, tracker)

	duplicate := cumulativeTestMetric(time.Unix(100, 0), 10)
	applyAbsoluteCounterStartTimestamps(duplicate, tracker)

	next := cumulativeTestMetric(time.Unix(200, 0), 175)
	applyAbsoluteCounterStartTimestamps(next, tracker)
	dp := next.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Sum().DataPoints().At(0)
	assert.True(t, time.Unix(100, 0).Equal(dp.StartTimestamp().AsTime()))
}

func TestAbsoluteCounterTrackerFillsMissingTimestamp(t *testing.T) {
	tracker := newAbsoluteCounterTracker()
	md := cumulativeTestMetric(time.Time{}, 5)
	applyAbsoluteCounterStartTimestamps(md, tracker)
	dp := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Sum().DataPoints().At(0)
	require.NotZero(t, dp.Timestamp())
	assert.Equal(t, dp.Timestamp(), dp.StartTimestamp())
}

func TestAbsoluteCounterValueComparisonPreservesLargeIntegerPrecision(t *testing.T) {
	const aboveFloatPrecision = int64(9_007_199_254_740_993)
	assert.True(t, absoluteCounterValue{f: float64(aboveFloatPrecision - 1)}.lessThan(absoluteCounterValue{isInt: true, i: aboveFloatPrecision}))
	assert.False(t, absoluteCounterValue{isInt: true, i: aboveFloatPrecision}.lessThan(absoluteCounterValue{f: float64(aboveFloatPrecision - 1)}))
}

func cumulativeTestMetric(ts time.Time, value int64) pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("host.id", "device-1")
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("test")
	metric := sm.Metrics().AppendEmpty()
	metric.SetName("system.network.packets")
	sum := metric.SetEmptySum()
	sum.SetIsMonotonic(true)
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	dp := sum.DataPoints().AppendEmpty()
	dp.SetTimestamp(pcommon.NewTimestampFromTime(ts))
	dp.SetIntValue(value)
	dp.Attributes().PutStr("network.interface.name", "eth1")
	return md
}
