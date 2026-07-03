// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package aci // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/aci"

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Object is a generic APIC managed object with flattened attributes.
type Object map[string]any

// String returns the first non-empty string-like value for the provided keys.
func String(obj Object, keys ...string) string {
	for _, key := range keys {
		value, ok := obj[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if typed != "" {
				return typed
			}
		case fmt.Stringer:
			if typed.String() != "" {
				return typed.String()
			}
		default:
			s := fmt.Sprint(typed)
			if s != "" && s != "<nil>" {
				return s
			}
		}
	}
	return ""
}

// Int64 returns an integer-like value for a key.
func Int64(obj Object, key string) (int64, bool) {
	value, ok := obj[key]
	if !ok || value == nil {
		return 0, false
	}
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case json.Number:
		i, err := typed.Int64()
		return i, err == nil
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || math.Trunc(typed) != typed || typed < float64(math.MinInt64) || typed >= float64(math.MaxInt64) {
			return 0, false
		}
		return int64(typed), true
	case string:
		i, err := strconv.ParseInt(typed, 10, 64)
		return i, err == nil
	default:
		return 0, false
	}
}

// Float64 returns a floating-point value for a key.
func Float64(obj Object, key string) (float64, bool) {
	value, ok := obj[key]
	if !ok || value == nil {
		return 0, false
	}
	switch typed := value.(type) {
	case float64:
		return typed, !math.IsNaN(typed) && !math.IsInf(typed, 0)
	case float32:
		value := float64(typed)
		return value, !math.IsNaN(value) && !math.IsInf(value, 0)
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case json.Number:
		f, err := typed.Float64()
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	case string:
		f, err := strconv.ParseFloat(typed, 64)
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	default:
		return 0, false
	}
}

// Time returns a timestamp value for a key.
func Time(obj Object, key string) (time.Time, bool) {
	value := String(obj, key)
	if value == "" {
		return time.Time{}, false
	}
	ts, err := time.Parse(time.RFC3339Nano, value)
	if err == nil {
		return ts, true
	}
	ts, err = time.Parse(time.RFC3339, value)
	return ts, err == nil
}

// StableID returns a stable identifier for an APIC managed object.
func StableID(obj Object) string {
	return firstNonEmpty(
		String(obj, "serial", "nodeId", "id", "dn", "name", "mac", "ip"),
	)
}

// FallbackKey returns a deterministic key=value;key=value... representation of
// an APIC object for use when StableID cannot find an identifier. Go map
// iteration order is randomized, so fmt.Sprint on a map produces a different
// string per call and breaks dedup across scrapes.
func FallbackKey(obj Object) string {
	if len(obj) == 0 {
		return ""
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+fmt.Sprint(obj[k]))
	}
	return strings.Join(parts, ";")
}

// SearchText returns a lower-case concatenation of common identity fields.
func SearchText(obj Object) string {
	parts := []string{
		String(obj, "dn", "rn"),
		String(obj, "fabricName", "siteName"),
		String(obj, "serial"),
		String(obj, "nodeId", "id"),
		String(obj, "name", "descr"),
		String(obj, "tenant", "tnFvTenantName"),
		String(obj, "vrf", "ctxDn"),
		String(obj, "bd", "bdDn"),
		String(obj, "epg", "epgDn"),
		String(obj, "mac", "ip"),
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
