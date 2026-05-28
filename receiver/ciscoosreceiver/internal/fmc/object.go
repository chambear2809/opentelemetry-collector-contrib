// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package fmc

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Object is a normalized FMC REST object.
type Object map[string]any

// String returns the first non-empty string-like field from obj.
func String(obj Object, keys ...string) string {
	for _, key := range keys {
		value, ok := obj[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return typed
			}
		case fmt.Stringer:
			if text := strings.TrimSpace(typed.String()); text != "" {
				return text
			}
		case json.Number:
			return typed.String()
		case float64:
			if typed == float64(int64(typed)) {
				return strconv.FormatInt(int64(typed), 10)
			}
			return strconv.FormatFloat(typed, 'f', -1, 64)
		case int:
			return strconv.Itoa(typed)
		case int64:
			return strconv.FormatInt(typed, 10)
		case bool:
			return strconv.FormatBool(typed)
		case map[string]any:
			if nested := String(typed, "name", "id", "uuid"); nested != "" {
				return nested
			}
		}
	}
	return ""
}

// Float64 returns a numeric field from obj.
func Float64(obj Object, keys ...string) (float64, bool) {
	for _, key := range keys {
		value, ok := obj[key]
		if !ok || value == nil {
			continue
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
		case json.Number:
			if parsed, err := typed.Float64(); err == nil {
				return parsed, true
			}
		case string:
			if parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64); err == nil {
				return parsed, true
			}
		}
	}
	return 0, false
}

// Bool returns a boolean field from obj.
func Bool(obj Object, keys ...string) (bool, bool) {
	for _, key := range keys {
		value, ok := obj[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case bool:
			return typed, true
		case string:
			switch strings.ToLower(strings.TrimSpace(typed)) {
			case "true", "yes", "up", "online", "enabled", "healthy":
				return true, true
			case "false", "no", "down", "offline", "disabled", "unhealthy":
				return false, true
			}
		}
	}
	return false, false
}

// Time returns a timestamp field from obj.
func Time(obj Object, keys ...string) (time.Time, bool) {
	for _, key := range keys {
		value, ok := obj[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case time.Time:
			return typed, true
		case string:
			if ts, ok := parseTime(typed); ok {
				return ts, true
			}
		case float64:
			if ts, ok := unixTime(typed); ok {
				return ts, true
			}
		case json.Number:
			if parsed, err := typed.Float64(); err == nil {
				if ts, ok := unixTime(parsed); ok {
					return ts, true
				}
			}
		}
	}
	return time.Time{}, false
}

// StableID returns a best-effort stable identifier for deduplicating FMC objects.
func StableID(obj Object) string {
	if id := String(obj, "id", "uuid", "UUID", "objectId", "containerUUID", "containerUuid", "jobId", "taskId", "eventId"); id != "" {
		return id
	}
	if links, ok := obj["links"].(map[string]any); ok {
		if self := String(links, "self"); self != "" {
			return self
		}
	}
	return ""
}

// SearchText returns a lower-case string containing searchable values from obj.
func SearchText(obj Object) string {
	var parts []string
	appendSearch(parts[:0], obj, &parts)
	return strings.ToLower(strings.Join(parts, " "))
}

func appendSearch(_ []string, value any, parts *[]string) {
	switch typed := value.(type) {
	case string:
		*parts = append(*parts, typed)
	case map[string]any:
		for _, nested := range typed {
			appendSearch(nil, nested, parts)
		}
	case []any:
		for _, nested := range typed {
			appendSearch(nil, nested, parts)
		}
	case json.Number:
		*parts = append(*parts, typed.String())
	case float64:
		*parts = append(*parts, strconv.FormatFloat(typed, 'f', -1, 64))
	case bool:
		*parts = append(*parts, strconv.FormatBool(typed))
	}
}

func parseTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, value); err == nil {
			return ts, true
		}
	}
	if parsed, err := strconv.ParseFloat(value, 64); err == nil {
		return unixTime(parsed)
	}
	return time.Time{}, false
}

func unixTime(value float64) (time.Time, bool) {
	if value <= 0 {
		return time.Time{}, false
	}
	if value > 1_000_000_000_000 {
		return time.UnixMilli(int64(value)).UTC(), true
	}
	return time.Unix(int64(value), 0).UTC(), true
}
