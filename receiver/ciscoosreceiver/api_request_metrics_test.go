// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

func TestAggregateAPIRequestObservationsProducesUniqueStreams(t *testing.T) {
	attrs := map[string]string{"operation": "devices", "outcome": "error"}
	aggregates := aggregateAPIRequestObservations([]apiRequestObservation{
		{resource: "controller", attrs: attrs, durationSeconds: 1, failed: true, rateLimited: true},
		{resource: "controller", attrs: map[string]string{"outcome": "error", "operation": "devices"}, durationSeconds: 3, failed: true},
		{resource: "controller", attrs: map[string]string{"operation": "devices", "outcome": "success"}, durationSeconds: 2},
	})

	require.Len(t, aggregates, 2)
	var failed apiRequestAggregate
	for _, aggregate := range aggregates {
		if aggregate.attrs["outcome"] == "error" {
			failed = aggregate
		}
	}
	assert.Equal(t, float64(2), failed.averageDurationSeconds)
	assert.Equal(t, int64(2), failed.errors)
	assert.Equal(t, int64(1), failed.rateLimited)
}

func TestPutAttrsUsesIntegerHTTPStatusCode(t *testing.T) {
	attrs := pcommon.NewMap()
	putAttrs(attrs, map[string]string{"http.response.status_code": "503", "outcome": "error"})

	status, ok := attrs.Get("http.response.status_code")
	require.True(t, ok)
	assert.Equal(t, pcommon.ValueTypeInt, status.Type())
	assert.Equal(t, int64(503), status.Int())
}
