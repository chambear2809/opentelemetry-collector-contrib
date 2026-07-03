// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi

import "time"

var earliestValidTimestamp = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

// NormalizeTimestamp accepts Cisco timestamps expressed as Unix seconds,
// milliseconds, microseconds, or nanoseconds. It returns receipt time and false
// when the magnitude is invalid or the result falls outside year 2000 through
// receipt time plus 24 hours.
func NormalizeTimestamp(raw int64, receipt time.Time) (time.Time, bool) {
	receipt = receipt.UTC()
	if raw <= 0 {
		return receipt, false
	}

	var seconds, nanoseconds int64
	switch {
	case raw < 100_000_000_000: // seconds (11 digits leaves room for future dates)
		seconds = raw
	case raw < 100_000_000_000_000: // milliseconds
		seconds = raw / 1_000
		nanoseconds = (raw % 1_000) * int64(time.Millisecond)
	case raw < 100_000_000_000_000_000: // microseconds
		seconds = raw / 1_000_000
		nanoseconds = (raw % 1_000_000) * int64(time.Microsecond)
	default: // nanoseconds
		seconds = raw / int64(time.Second)
		nanoseconds = raw % int64(time.Second)
	}

	normalized := time.Unix(seconds, nanoseconds).UTC()
	if normalized.Before(earliestValidTimestamp) || normalized.After(receipt.Add(24*time.Hour)) {
		return receipt, false
	}
	return normalized, true
}
