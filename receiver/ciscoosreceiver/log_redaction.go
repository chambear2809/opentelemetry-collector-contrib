// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import "strings"

const redactedLogValue = "[REDACTED]"

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
	switch typed := value.(type) {
	case map[string]any:
		redacted := make(map[string]any, len(typed))
		for key, nested := range typed {
			if isSensitiveLogKey(key) {
				redacted[key] = redactedLogValue
			} else {
				redacted[key] = redactLogValue(nested)
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
			redacted[i] = redactLogValue(nested)
		}
		return redacted
	case []map[string]any:
		redacted := make([]any, len(typed))
		for i, nested := range typed {
			redacted[i] = redactLogValue(nested)
		}
		return redacted
	default:
		return value
	}
}
