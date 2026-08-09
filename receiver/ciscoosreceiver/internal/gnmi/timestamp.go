// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"

import "time"

var (
	earliestValidTimestamp = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
	maximumFutureClockSkew = 5 * time.Second
)

// NormalizeTimestamp accepts Cisco timestamps expressed as Unix seconds,
// milliseconds, microseconds, or nanoseconds. It returns receipt time and false
// when the magnitude is invalid or the result is before year 2000 or more than
// five seconds in the future. A future timestamp within the bounded clock-skew
// allowance is clamped to receipt time so it cannot poison cache freshness.
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
	if normalized.Before(earliestValidTimestamp) {
		return receipt, false
	}
	if normalized.After(receipt) {
		if normalized.Sub(receipt) <= maximumFutureClockSkew {
			return receipt, true
		}
		return receipt, false
	}
	return normalized, true
}
