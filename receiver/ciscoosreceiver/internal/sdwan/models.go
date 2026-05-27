// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sdwan

import (
	"fmt"
	"strconv"
	"strings"
)

// Object is a generic Catalyst SD-WAN Manager API object.
type Object map[string]any

// String returns the first non-empty string value for the supplied keys.
func String(obj Object, keys ...string) string {
	for _, key := range keys {
		value, ok := obj[key]
		if !ok || value == nil {
			continue
		}
		if str := StringValue(value); str != "" && str != "<nil>" {
			return str
		}
	}
	return ""
}

// StringValue converts common JSON values to strings.
func StringValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return fmt.Sprint(typed)
	}
}

// Number returns the first numeric value for the supplied keys.
func Number(obj Object, keys ...string) (float64, bool) {
	for _, key := range keys {
		value, ok := numberValue(obj[key])
		if ok {
			return value, true
		}
	}
	return 0, false
}

// Int returns the first integer-like value for the supplied keys.
func Int(obj Object, keys ...string) (int64, bool) {
	value, ok := Number(obj, keys...)
	if !ok {
		return 0, false
	}
	return int64(value), true
}

func numberValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case nil:
		return 0, false
	case float64:
		return typed, true
	case int64:
		return float64(typed), true
	case int:
		return float64(typed), true
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return 0, false
		}
		parsed, err := strconv.ParseFloat(trimmed, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}
