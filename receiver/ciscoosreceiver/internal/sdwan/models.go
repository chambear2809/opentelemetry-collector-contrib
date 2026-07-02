// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sdwan

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
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
	for _, key := range keys {
		if value, ok := integerValue(obj[key]); ok {
			return value, true
		}
	}
	return 0, false
}

func numberValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case nil:
		return 0, false
	case json.Number:
		parsed, err := typed.Float64()
		return parsed, err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0)
	case float64:
		return typed, !math.IsNaN(typed) && !math.IsInf(typed, 0)
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
		return parsed, err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0)
	default:
		return 0, false
	}
}

func integerValue(value any) (int64, bool) {
	switch typed := value.(type) {
	case nil:
		return 0, false
	case json.Number:
		return exactInt64FromString(typed.String())
	case int:
		return int64(typed), true
	case int8:
		return int64(typed), true
	case int16:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case int64:
		return typed, true
	case uint:
		if uint64(typed) <= math.MaxInt64 {
			return int64(typed), true
		}
	case uint8:
		return int64(typed), true
	case uint16:
		return int64(typed), true
	case uint32:
		return int64(typed), true
	case uint64:
		if typed <= math.MaxInt64 {
			return int64(typed), true
		}
	case float32:
		return exactInt64FromFloat(float64(typed), true)
	case float64:
		return exactInt64FromFloat(typed, true)
	case string:
		return exactInt64FromString(typed)
	}
	return 0, false
}

func exactInt64FromString(value string) (int64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
		return parsed, true
	}
	rational, ok := new(big.Rat).SetString(value)
	if !ok || !rational.IsInt() || !rational.Num().IsInt64() {
		return 0, false
	}
	return rational.Num().Int64(), true
}

func exactInt64FromFloat(value float64, parsed bool) (int64, bool) {
	const maxInt64Exclusive = float64(uint64(1) << 63)
	if !parsed || math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || value < math.MinInt64 || value >= maxInt64Exclusive {
		return 0, false
	}
	return int64(value), true
}
