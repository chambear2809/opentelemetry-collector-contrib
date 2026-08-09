// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestYANGCounterClassificationIsConservative(t *testing.T) {
	for _, path := range [][]string{
		{"interfaces", "counters", "in-octets"},
		{"ssid-counters", "tx-bytes-data"},
		{"statistics", "crc-errors"},
		{"state", "dropped-packets"},
	} {
		assert.True(t, isUnambiguousYANGCounter(path), path)
	}

	for _, path := range [][]string{
		{"radio", "transmit-power"},
		{"radio", "received-power"},
		{"clients", "client-count"},
		{"interfaces", "packet-rate"},
		{"system", "process-count"},
		{"authentication", "failure-reason"},
		{"environment", "current"},
	} {
		assert.False(t, isUnambiguousYANGCounter(path), path)
		assert.False(t, isCatalyst9800CounterMetric(path), path)
		assert.False(t, isIOSXRCounterMetric(path), path)
	}
}
