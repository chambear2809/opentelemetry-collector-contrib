// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

// pdataTimestampFromTime rejects controller timestamps that cannot be
// represented as positive Unix nanoseconds. pcommon.NewTimestampFromTime casts
// time.UnixNano directly to uint64, so out-of-range or pre-epoch values would
// otherwise wrap into plausible but incorrect telemetry timestamps.
func pdataTimestampFromTime(value time.Time) (pcommon.Timestamp, bool) {
	if value.IsZero() {
		return 0, false
	}
	nanoseconds := value.UnixNano()
	if nanoseconds <= 0 || !time.Unix(0, nanoseconds).Equal(value) {
		return 0, false
	}
	return pcommon.Timestamp(uint64(nanoseconds)), true
}
