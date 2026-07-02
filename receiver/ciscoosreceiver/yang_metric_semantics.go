// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import "strings"

// isUnambiguousYANGCounter deliberately recognizes only leaf names whose
// semantics are cumulative across Cisco and OpenConfig models. Unknown numeric
// leaves remain gauges: treating a population, rate, or optical level as a
// monotonic sum creates invalid resets and rate calculations downstream.
func isUnambiguousYANGCounter(pathParts []string) bool {
	if len(pathParts) == 0 {
		return false
	}
	leaf := sanitizeMetricSegment(pathParts[len(pathParts)-1])
	for _, gaugeHint := range []string{
		"rate", "per_second", "utilization", "percentage", "percent", "ratio",
		"temperature", "voltage", "current", "power", "rssi", "snr", "noise",
		"state", "status", "reason", "type", "enum", "delay", "latency",
	} {
		if containsMetricWord(leaf, gaugeHint) || strings.Contains(gaugeHint, "_") && strings.Contains(leaf, gaugeHint) {
			return false
		}
	}

	for _, counterWord := range []string{
		"octet", "octets", "byte", "bytes", "packet", "packets", "pkt", "pkts",
		"error", "errors", "drop", "drops", "discard", "discards", "retry", "retries",
		"timeout", "timeouts", "crc", "interrupt", "interrupts",
	} {
		if containsMetricWord(leaf, counterWord) {
			return true
		}
	}
	return false
}

func containsMetricWord(value, word string) bool {
	if value == word {
		return true
	}
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == '_' || r == '.' }) {
		if part == word {
			return true
		}
	}
	return false
}
