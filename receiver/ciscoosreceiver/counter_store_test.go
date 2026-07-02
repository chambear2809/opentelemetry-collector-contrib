// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

func TestCounterStoreIsolatesResourcesAndCanonicalizesAttributes(t *testing.T) {
	start := time.Unix(100, 0)
	store := newCounterStoreAt(start)
	attrsAB := map[string]string{"a": "one", "b": "two"}
	attrsBA := map[string]string{"b": "two", "a": "one"}

	total, seriesStart := store.AddDouble("resource-a", "requests", attrsAB, 1)
	assert.Equal(t, float64(1), total)
	assert.Equal(t, start, seriesStart)
	total, seriesStart = store.AddDouble("resource-a", "requests", attrsBA, 2)
	assert.Equal(t, float64(3), total)
	assert.Equal(t, start, seriesStart)
	total, seriesStart = store.AddDouble("resource-b", "requests", attrsAB, 1)
	assert.Equal(t, float64(1), total)
	assert.Equal(t, start, seriesStart)
	total, seriesStart = store.AddDouble("resource-a", "requests", attrsAB, 1)
	assert.Equal(t, float64(4), total)
	assert.Equal(t, start, seriesStart)
}

func TestCounterKeyHasFixedSizeForUntrustedDimensions(t *testing.T) {
	key := counterKey(strings.Repeat("resource", 10_000), "requests", map[string]string{
		"controller.id": strings.Repeat("x", 10_000),
	})
	assert.Len(t, key, 32)
}

func TestCounterStorePreservesIntegersAboveFloatPrecision(t *testing.T) {
	start := time.Unix(100, 0)
	store := newCounterStoreAt(start)
	const aboveFloatPrecision = int64(1<<53 + 1)

	total, seriesStart := store.AddInt("resource-a", "packets", nil, aboveFloatPrecision)
	assert.Equal(t, aboveFloatPrecision, total)
	assert.Equal(t, start, seriesStart)
	total, seriesStart = store.AddInt("resource-a", "packets", nil, 2)
	assert.Equal(t, aboveFloatPrecision+2, total)
	assert.Equal(t, start, seriesStart)
}

func TestCounterStoreStartsNewEpochInsteadOfOverflowingInt64(t *testing.T) {
	now := time.Unix(100, 0)
	store := newCounterStoreWithConfig(now, counterStoreConfig{
		now: func() time.Time { return now },
	})

	total, seriesStart := store.AddInt("resource-a", "packets", nil, math.MaxInt64-1)
	assert.Equal(t, int64(math.MaxInt64-1), total)
	assert.Equal(t, time.Unix(100, 0), seriesStart)

	now = time.Unix(200, 0)
	total, seriesStart = store.AddInt("resource-a", "packets", nil, 2)
	assert.Equal(t, int64(2), total)
	assert.Equal(t, now, seriesStart)
}

func TestCounterStoreKeepsIntegerAndDoubleSeriesSeparate(t *testing.T) {
	store := newCounterStoreAt(time.Unix(100, 0))
	const aboveFloatPrecision = int64(1<<53 + 1)

	intTotal, _ := store.AddInt("resource-a", "requests", nil, aboveFloatPrecision)
	doubleTotal, _ := store.AddDouble("resource-a", "requests", nil, 0.5)
	intTotal, _ = store.AddInt("resource-a", "requests", nil, 2)
	doubleTotal, _ = store.AddDouble("resource-a", "requests", nil, 0.25)

	assert.Equal(t, aboveFloatPrecision+2, intTotal)
	assert.Equal(t, 0.75, doubleTotal)
	assert.Equal(t, 2, store.lru.Len())
}

func TestCounterStoreEvictsIdleSeriesAndRefreshesStart(t *testing.T) {
	now := time.Unix(100, 0)
	store := newCounterStoreWithConfig(now, counterStoreConfig{
		maxEntries: 10,
		idleTTL:    time.Hour,
		now:        func() time.Time { return now },
	})

	total, seriesStart := store.AddInt("resource-a", "requests", nil, 1)
	assert.Equal(t, int64(1), total)
	assert.Equal(t, time.Unix(100, 0), seriesStart)

	now = now.Add(30 * time.Minute)
	total, seriesStart = store.AddInt("resource-a", "requests", nil, 2)
	assert.Equal(t, int64(3), total)
	assert.Equal(t, time.Unix(100, 0), seriesStart)

	now = now.Add(time.Hour)
	total, seriesStart = store.AddInt("resource-a", "requests", nil, 4)
	assert.Equal(t, int64(4), total)
	assert.Equal(t, now, seriesStart)
	assert.Equal(t, 1, store.lru.Len())
}

func TestCounterStoreEvictsLeastRecentlyUsedAtCapacity(t *testing.T) {
	now := time.Unix(100, 0)
	store := newCounterStoreWithConfig(now, counterStoreConfig{
		maxEntries: 2,
		idleTTL:    24 * time.Hour,
		now:        func() time.Time { return now },
	})

	_, _ = store.AddInt("resource-a", "a", nil, 1)
	now = now.Add(time.Second)
	_, _ = store.AddInt("resource-a", "b", nil, 2)
	now = now.Add(time.Second)
	_, _ = store.AddInt("resource-a", "a", nil, 3)
	now = now.Add(time.Second)
	_, _ = store.AddDouble("resource-a", "c", nil, 0.5)

	assert.Equal(t, 2, store.lru.Len())
	assert.Contains(t, store.intValues, counterKey("resource-a", "a", nil))
	assert.NotContains(t, store.intValues, counterKey("resource-a", "b", nil))
	assert.Contains(t, store.doubleValues, counterKey("resource-a", "c", nil))

	now = now.Add(time.Second)
	total, seriesStart := store.AddInt("resource-a", "b", nil, 7)
	assert.Equal(t, int64(7), total)
	assert.Equal(t, now, seriesStart)
	assert.Equal(t, 2, store.lru.Len())
}

func TestResourceMetricsBuilderKeepsCumulativeStartTimeAcrossScrapes(t *testing.T) {
	start := time.Unix(100, 123)
	now := start
	store := newCounterStoreWithConfig(start, counterStoreConfig{
		maxEntries: 10,
		idleTTL:    time.Hour,
		now:        func() time.Time { return now },
	})

	first := newMerakiMetricsBuilder(time.Unix(200, 0), store).orgResource("org-a")
	first.recordSum("test.requests", "test", "{request}", 1, nil)
	firstDP := first.metrics["test.requests"].Sum().DataPoints().At(0)

	now = now.Add(time.Minute)
	second := newMerakiMetricsBuilder(time.Unix(300, 0), store).orgResource("org-a")
	second.recordSum("test.requests", "test", "{request}", 1, nil)
	secondDP := second.metrics["test.requests"].Sum().DataPoints().At(0)

	require.Equal(t, int64(1), firstDP.IntValue())
	require.Equal(t, int64(2), secondDP.IntValue())
	assert.Equal(t, pcommon.NewTimestampFromTime(start), firstDP.StartTimestamp())
	assert.Equal(t, firstDP.StartTimestamp(), secondDP.StartTimestamp())
}

func TestResourceMetricsBuilderUsesFreshStartAfterSeriesRecreation(t *testing.T) {
	now := time.Unix(100, 0)
	store := newCounterStoreWithConfig(now, counterStoreConfig{
		maxEntries: 1,
		idleTTL:    24 * time.Hour,
		now:        func() time.Time { return now },
	})

	first := newMerakiMetricsBuilder(time.Unix(200, 0), store).orgResource("org-a")
	first.recordSum("test.requests", "test", "{request}", 1, nil)
	firstDP := first.metrics["test.requests"].Sum().DataPoints().At(0)

	now = time.Unix(150, 0)
	_, _ = store.AddInt("other-resource", "other-counter", nil, 1)
	now = time.Unix(300, 0)
	second := newMerakiMetricsBuilder(time.Unix(400, 0), store).orgResource("org-a")
	second.recordSum("test.requests", "test", "{request}", 1, nil)
	secondDP := second.metrics["test.requests"].Sum().DataPoints().At(0)

	assert.Equal(t, int64(1), firstDP.IntValue())
	assert.Equal(t, int64(1), secondDP.IntValue())
	assert.Equal(t, pcommon.NewTimestampFromTime(time.Unix(100, 0)), firstDP.StartTimestamp())
	assert.Equal(t, pcommon.NewTimestampFromTime(time.Unix(300, 0)), secondDP.StartTimestamp())
}

func TestResourceMetricsBuilderPreservesLargeIntegerSum(t *testing.T) {
	start := time.Unix(100, 0)
	store := newCounterStoreAt(start)
	const aboveFloatPrecision = int64(1<<53 + 1)

	builder := newMerakiMetricsBuilder(time.Unix(200, 0), store).orgResource("org-a")
	builder.recordSum("test.packets", "test", "{packet}", aboveFloatPrecision, nil)
	builder.recordSum("test.packets", "test", "{packet}", 2, nil)
	dps := builder.metrics["test.packets"].Sum().DataPoints()

	require.Equal(t, 2, dps.Len())
	assert.Equal(t, aboveFloatPrecision, dps.At(0).IntValue())
	assert.Equal(t, aboveFloatPrecision+2, dps.At(1).IntValue())
}

func TestResourceMetricsBuilderDoesNotSetGaugeStartTime(t *testing.T) {
	store := newCounterStoreAt(time.Unix(100, 0))
	builder := newMerakiMetricsBuilder(time.Unix(200, 0), store).orgResource("org-a")
	builder.recordInt("test.gauge", "test", "1", 1, nil)

	dp := builder.metrics["test.gauge"].Gauge().DataPoints().At(0)
	assert.Equal(t, pcommon.Timestamp(0), dp.StartTimestamp())
}

func TestResourceMetricsBuilderDropsNonFiniteDoubleValues(t *testing.T) {
	builder := newMerakiMetricsBuilder(time.Unix(200, 0), newCounterStore()).orgResource("org-a")
	builder.recordDouble("test.nan", "test", "1", math.NaN(), nil)
	builder.recordSumDouble("test.inf_sum", "test", "1", math.Inf(1), nil)
	builder.recordAbsoluteSumDouble("test.inf_absolute", "test", "1", math.Inf(-1), nil)

	assert.NotContains(t, builder.metrics, "test.nan")
	assert.NotContains(t, builder.metrics, "test.inf_sum")
	assert.NotContains(t, builder.metrics, "test.inf_absolute")
}
