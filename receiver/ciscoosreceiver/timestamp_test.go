// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

func TestPdataTimestampFromTimeRejectsWrappedControllerTimes(t *testing.T) {
	valid := time.Unix(1_800_000_000, 123).UTC()
	timestamp, ok := pdataTimestampFromTime(valid)
	require.True(t, ok)
	assert.Equal(t, pcommon.NewTimestampFromTime(valid), timestamp)

	for _, invalid := range []time.Time{
		{},
		time.Unix(-1, 0),
		time.Date(9999, time.December, 31, 0, 0, 0, 0, time.UTC),
	} {
		_, ok = pdataTimestampFromTime(invalid)
		assert.False(t, ok, invalid.String())
	}
}

func TestMetricTimestampFallsBackForUnrepresentableControllerTime(t *testing.T) {
	fallback := pcommon.NewTimestampFromTime(time.Unix(1_800_000_000, 0))

	assert.Equal(t, fallback, metricTimestamp(time.Unix(-1, 0), fallback))
	assert.Equal(t, fallback, metricTimestamp(time.Date(9999, time.December, 31, 0, 0, 0, 0, time.UTC), fallback))
}

func TestLatestTimestampedIndexIgnoresUnrepresentableControllerTimes(t *testing.T) {
	timestamps := []string{
		"1969-12-31T23:59:59Z",
		"2026-01-01T00:00:00Z",
		"9999-12-31T23:59:59Z",
	}

	index, timestamp := latestTimestampedIndex(len(timestamps), 0, func(index int) string {
		return timestamps[index]
	})

	assert.Equal(t, 1, index)
	assert.Equal(t, time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC), timestamp)
	assert.Equal(t, timestamps[1], firstValidTimestamp(timestamps[0], timestamps[1]))
}
