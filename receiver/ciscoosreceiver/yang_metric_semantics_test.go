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
		{"statistics", "seconds-since-packet-received"},
		{"system", "process-count"},
		{"authentication", "failure-reason"},
		{"environment", "current"},
	} {
		assert.False(t, isUnambiguousYANGCounter(path), path)
		assert.False(t, isCatalyst9800CounterMetric(path), path)
		assert.False(t, isIOSXRCounterMetric(path), path)
	}
}

func TestCatalyst9800CounterClassificationIncludesBuiltinInterfaceStatisticsExceptions(t *testing.T) {
	for _, leaf := range []string{
		"num-flaps",
		"in-unknown-protos",
		"in-unknown-protos-64",
	} {
		path := []string{"interfaces", "interface", "statistics", leaf}
		assert.False(t, isUnambiguousYANGCounter(path), "the shared heuristic must remain conservative for %q", leaf)
		assert.True(t, isCatalyst9800CounterMetric(path), "the exact IOS XE schema counter %q must be cumulative", leaf)
	}

	for _, leaf := range []string{
		"num-flaps-per-second",
		"num_flaps",
		"in-unknown-protos-rate",
		"in_unknown_protos",
		"in-unknown-protos-640",
		"unknown-protos",
	} {
		assert.False(t, isCatalyst9800CounterMetric([]string{"interfaces", "interface", "statistics", leaf}),
			"near-match %q must not inherit cumulative semantics", leaf)
	}
}

func TestIOSXRCounterClassificationUsesContainerSemantics(t *testing.T) {
	for _, path := range [][]string{
		{"infra-statistics", "interfaces", "interface", "generic-counters", "applique"},
		{"infra-statistics", "interfaces", "interface", "generic-counters", "carrier-transitions"},
		{"infra-statistics", "interfaces", "interface", "generic-counters", "input-aborts"},
		{"infra-statistics", "interfaces", "interface", "generic-counters", "input-overruns"},
		{"infra-statistics", "interfaces", "interface", "generic-counters", "output-buffer-failures"},
		{"infra-statistics", "interfaces", "interface", "generic-counters", "output-buffers-swapped-out"},
		{"infra-statistics", "interfaces", "interface", "generic-counters", "output-underruns"},
		{"infra-statistics", "interfaces", "interface", "generic-counters", "resets"},
		{"interfaces", "interface", "state", "counters", "carrier-transitions"},
		{"interfaces", "interface", "state", "counters", "in-unknown-protos"},
	} {
		assert.True(t, isIOSXRCounterMetric(path), path)
	}

	for _, path := range [][]string{
		{"infra-statistics", "interfaces", "interface", "generic-counters", "availability-flag"},
		{"infra-statistics", "interfaces", "interface", "generic-counters", "hardware-timestamp"},
		{"infra-statistics", "interfaces", "interface", "generic-counters", "last-data-time"},
		{"infra-statistics", "interfaces", "interface", "generic-counters", "last-discontinuity-time"},
		{"infra-statistics", "interfaces", "interface", "generic-counters", "seconds-since-last-clear-counters"},
		{"infra-statistics", "interfaces", "interface", "generic-counters", "seconds-since-packet-received"},
		{"infra-statistics", "interfaces", "interface", "generic-counters", "seconds-since-packet-sent"},
		{"interfaces", "interface", "state", "counters", "last-clear"},
		{"interfaces", "interface", "state", "counters", "cisco", "last-read-time"},
	} {
		assert.False(t, isIOSXRCounterMetric(path), path)
	}
}
