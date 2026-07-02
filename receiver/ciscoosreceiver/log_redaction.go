// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"reflect"
	"strings"
)

const redactedLogValue = "[REDACTED]"

const (
	maxLogRedactionDepth = 128
	truncatedLogValue    = "[TRUNCATED]"
)

// isSensitiveLogKey deliberately favors preventing credential disclosure over
// retaining fields whose names are ambiguous. Controller event payloads are
// vendor-defined and may add credential fields without a receiver release.
func isSensitiveLogKey(key string) bool {
	var normalized strings.Builder
	normalized.Grow(len(key))
	for _, r := range strings.ToLower(key) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			normalized.WriteRune(r)
		}
	}
	value := normalized.String()
	for _, marker := range []string{
		"password",
		"passwd",
		"passphrase",
		"secret",
		"token",
		"apikey",
		"authorization",
		"privatekey",
		"accesskey",
		"sharedkey",
		"encryptionkey",
		"signingkey",
		"keymaterial",
		"credential",
		"bearer",
		"cookie",
		"sessionid",
	} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return value == "pwd" || strings.HasPrefix(value, "pwd") || strings.HasSuffix(value, "pwd")
}

func redactLogValue(value any) any {
	return redactLogValueAtDepth(value, 0)
}

func redactLogValueAtDepth(value any, depth int) any {
	if depth >= maxLogRedactionDepth {
		return truncatedLogValue
	}
	switch typed := value.(type) {
	case map[string]any:
		redacted := make(map[string]any, len(typed))
		for key, nested := range typed {
			if isSensitiveLogKey(key) {
				redacted[key] = redactedLogValue
			} else {
				redacted[key] = redactLogValueAtDepth(nested, depth+1)
			}
		}
		return redacted
	case map[string]string:
		redacted := make(map[string]string, len(typed))
		for key, nested := range typed {
			if isSensitiveLogKey(key) {
				redacted[key] = redactedLogValue
			} else {
				redacted[key] = nested
			}
		}
		return redacted
	case []any:
		redacted := make([]any, len(typed))
		for i, nested := range typed {
			redacted[i] = redactLogValueAtDepth(nested, depth+1)
		}
		return redacted
	case []map[string]any:
		redacted := make([]any, len(typed))
		for i, nested := range typed {
			redacted[i] = redactLogValueAtDepth(nested, depth+1)
		}
		return redacted
	}

	// Vendor SDKs commonly define aliases such as type Object map[string]any.
	// Reflection keeps those aliases on the same recursive redaction path
	// instead of falling through to fmt.Sprint with their secrets intact.
	reflected := reflect.ValueOf(value)
	for reflected.IsValid() && (reflected.Kind() == reflect.Interface || reflected.Kind() == reflect.Pointer) {
		depth++
		if depth >= maxLogRedactionDepth {
			return truncatedLogValue
		}
		if reflected.IsNil() {
			return nil
		}
		reflected = reflected.Elem()
	}
	if !reflected.IsValid() {
		return nil
	}
	switch reflected.Kind() {
	case reflect.Map:
		if reflected.Type().Key().Kind() != reflect.String {
			return value
		}
		redacted := make(map[string]any, reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			key := iterator.Key().String()
			if isSensitiveLogKey(key) {
				redacted[key] = redactedLogValue
			} else {
				redacted[key] = redactLogValueAtDepth(iterator.Value().Interface(), depth+1)
			}
		}
		return redacted
	case reflect.Slice, reflect.Array:
		redacted := make([]any, reflected.Len())
		for i := 0; i < reflected.Len(); i++ {
			redacted[i] = redactLogValueAtDepth(reflected.Index(i).Interface(), depth+1)
		}
		return redacted
	default:
		return value
	}
}
