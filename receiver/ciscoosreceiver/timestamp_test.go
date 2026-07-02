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
