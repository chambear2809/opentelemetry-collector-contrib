// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nexusdashboard

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Object is a generic Nexus Dashboard service object.
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
		case []any:
			for _, item := range typed {
				if s, ok := item.(string); ok && s != "" {
					return s
				}
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

// StringSlice returns a string slice value for a key.
func StringSlice(obj Object, key string) []string {
	value, ok := obj[key]
	if !ok || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s := fmt.Sprint(item); s != "" && s != "<nil>" {
				out = append(out, s)
			}
		}
		return out
	default:
		if s := fmt.Sprint(typed); s != "" && s != "<nil>" {
			return []string{s}
		}
	}
	return nil
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
	case float64:
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
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case string:
		f, err := strconv.ParseFloat(typed, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// Bool returns a boolean-like value for a key.
func Bool(obj Object, key string) (bool, bool) {
	value, ok := obj[key]
	if !ok || value == nil {
		return false, false
	}
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		b, err := strconv.ParseBool(typed)
		return b, err == nil
	default:
		return false, false
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

// StableID returns a stable identifier for a Nexus Dashboard object.
func StableID(obj Object) string {
	return firstNonEmpty(
		String(obj, "serialNumber", "serialNo", "serial", "switchSerialNo", "switchSerial"),
		String(obj, "switchDbId", "switchId", "nodeId", "id", "uuid", "name", "fabricName", "siteName"),
	)
}

// SearchText returns a lower-case concatenation of common identity fields.
func SearchText(obj Object) string {
	parts := []string{
		String(obj, "siteName", "site"),
		String(obj, "fabricName", "fabric"),
		String(obj, "serialNumber", "serialNo", "serial", "switchSerialNo", "switchSerial"),
		String(obj, "switchDbId", "switchId", "nodeId", "id"),
		String(obj, "switchName", "hostName", "hostname", "name"),
		String(obj, "serviceName", "appName", "featureName"),
		String(obj, "ifName", "interfaceName", "portName"),
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
