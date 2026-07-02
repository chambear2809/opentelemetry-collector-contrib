// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/intersight"
)

func TestScrapeSuccessStateRetainsLastFullSuccess(t *testing.T) {
	state := scrapeSuccessState{}
	first := time.Unix(1_800_000_000, 0)
	second := first.Add(time.Minute)

	_, ok := state.observe(first, false)
	assert.False(t, ok, "a failed initial scrape must not invent a success timestamp")

	got, ok := state.observe(first, true)
	require.True(t, ok)
	assert.Equal(t, first, got)

	got, ok = state.observe(second, false)
	require.True(t, ok)
	assert.Equal(t, first, got, "a partial scrape must retain the preceding full success")
}

func TestStatusMappingsOmitUnknownValues(t *testing.T) {
	for _, value := range []string{"", "unknown", "none", "future-controller-state"} {
		_, ok := statusCode(value)
		assert.False(t, ok, value)
		_, ok = upStatus(value)
		assert.False(t, ok, value)
	}

	code, ok := statusCode("healthy")
	require.True(t, ok)
	assert.Equal(t, int64(1), code)
	code, ok = statusCode("failed")
	require.True(t, ok)
	assert.Equal(t, int64(4), code)

	up, ok := upStatus("reachable")
	require.True(t, ok)
	assert.Equal(t, int64(1), up)
	up, ok = upStatus("down")
	require.True(t, ok)
	assert.Equal(t, int64(0), up)
	for _, transitional := range []string{"pending", "degraded", "warning", "present", "learned", "valid"} {
		_, ok = upStatus(transitional)
		assert.False(t, ok, transitional)
	}

	for _, mapping := range []func(string) (int64, bool){
		merakiDeviceUp,
		merakiStatusCode,
		connectedStatus,
		activeStatus,
		reachableStatus,
		powerModuleStatus,
	} {
		_, ok = mapping("future-controller-state")
		assert.False(t, ok)
	}

	for status, want := range map[string]int64{
		"active":        1,
		"ready":         1,
		"connecting":    0,
		"failed":        0,
		"not connected": 0,
	} {
		got, ok := activeStatus(status)
		require.True(t, ok, status)
		assert.Equal(t, want, got, status)
	}
	for status, want := range map[string]int64{
		"connected":     1,
		"powering":      1,
		"not connected": 0,
	} {
		got, ok := powerModuleStatus(status)
		require.True(t, ok, status)
		assert.Equal(t, want, got, status)
	}
}

func TestUnknownIntersightStatusKeepsInfoAndOmitsNumericState(t *testing.T) {
	builder := newIntersightMetricsBuilder(time.Unix(1_800_000_000, 0), "https://intersight.example.test", nil)
	builder.recordObject(intersightEndpoint{group: "inventory", operation: "inventory.devices", objectType: "compute.PhysicalSummary"}, intersight.Object{
		"Moid":       "device-1",
		"Serial":     "SERIAL-1",
		"Status":     "future-controller-state",
		"ObjectType": "compute.PhysicalSummary",
	})
	md := builder.emit()

	assert.True(t, metricNameExists(md, "intersight.resource.info"))
	assert.False(t, metricNameExists(md, "intersight.resource.status"))
	assert.False(t, metricNameExists(md, "cisco.device.up"))
}
