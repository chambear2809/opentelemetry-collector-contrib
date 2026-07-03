// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

// Object is a normalized Cisco ISE API, pxGrid, or Data Connect object.
type Object map[string]any

// String returns the first non-empty string-like field from obj.
func String(obj Object, keys ...string) string {
	for _, key := range keys {
		value, ok := valueForKey(obj, key)
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return typed
			}
		case json.Number:
			return typed.String()
		case fmt.Stringer:
			if text := strings.TrimSpace(typed.String()); text != "" {
				return text
			}
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
		case Object:
			if nested := String(typed, "name", "id", "uuid", "hostname", "ipaddress", "ipAddress", "href", "rel"); nested != "" {
				return nested
			}
		case map[string]any:
			if nested := String(Object(typed), "name", "id", "uuid", "hostname", "ipaddress", "ipAddress", "href", "rel"); nested != "" {
				return nested
			}
		}
	}
	return ""
}

// Float64 returns a numeric field from obj.
func Float64(obj Object, keys ...string) (float64, bool) {
	for _, key := range keys {
		value, ok := valueForKey(obj, key)
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
		case int32:
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

// Time returns a timestamp field from obj.
func Time(obj Object, keys ...string) (time.Time, bool) {
	for _, key := range keys {
		value, ok := valueForKey(obj, key)
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
		case int:
			if ts, ok := unixTime(float64(typed)); ok {
				return ts, true
			}
		case int32:
			if ts, ok := unixTime(float64(typed)); ok {
				return ts, true
			}
		case int64:
			if ts, ok := unixTime(float64(typed)); ok {
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

// StableID returns a best-effort stable identifier for deduplicating ISE evidence.
func StableID(obj Object) string {
	if id := String(obj,
		"id", "uuid", "UUID", "eventId", "event_id", "eventID", "deliveryId", "delivery_id",
		"taskId", "task_id", "message_id", "messageId", "message-id", "audit_session_id", "auditSessionId",
		"audit-session-id", "session_id", "sessionId", "idRef", "link",
	); id != "" {
		return id
	}
	if link, ok := obj["link"].(Object); ok {
		if href := String(link, "href", "rel"); href != "" {
			return href
		}
	}
	if link, ok := obj["link"].(map[string]any); ok {
		if href := String(Object(link), "href", "rel"); href != "" {
			return href
		}
	}
	return ""
}

// SearchText returns a lower-case string containing searchable values from obj.
func SearchText(obj Object) string {
	var parts []string
	appendSearch(obj, &parts)
	return strings.ToLower(strings.Join(parts, " "))
}

func appendSearch(value any, parts *[]string) {
	switch typed := value.(type) {
	case string:
		*parts = append(*parts, typed)
	case Object:
		for _, nested := range typed {
			appendSearch(nested, parts)
		}
	case map[string]any:
		for _, nested := range typed {
			appendSearch(nested, parts)
		}
	case []any:
		for _, nested := range typed {
			appendSearch(nested, parts)
		}
	case json.Number:
		*parts = append(*parts, typed.String())
	case float64:
		*parts = append(*parts, strconv.FormatFloat(typed, 'f', -1, 64))
	case bool:
		*parts = append(*parts, strconv.FormatBool(typed))
	}
}

func valueForKey(obj Object, key string) (any, bool) {
	if value, ok := obj[key]; ok {
		return value, true
	}
	lower := strings.ToLower(key)
	for candidate, value := range obj {
		if strings.EqualFold(candidate, lower) {
			return value, true
		}
	}
	return nil, false
}

func decodeObject(body []byte) (Object, error) {
	var obj Object
	jsonErr := httpclient.DecodeJSON(body, &obj)
	if jsonErr == nil {
		return obj, nil
	}
	var limitErr *httpclient.JSONComplexityLimitError
	if errors.As(jsonErr, &limitErr) {
		return nil, jsonErr
	}
	xmlObj, err := decodeXMLObject(body)
	if err != nil {
		return nil, err
	}
	return flattenSingleRoot(xmlObj), nil
}

func decodeObjects(body []byte) ([]Object, int, error) {
	var raw any
	jsonErr := httpclient.DecodeJSON(body, &raw)
	if jsonErr == nil {
		normalized := normalizeJSON(raw)
		return extractObjects(normalized), extractTotal(normalized), nil
	}
	var limitErr *httpclient.JSONComplexityLimitError
	if errors.As(jsonErr, &limitErr) {
		return nil, -1, jsonErr
	}
	xmlObj, err := decodeXMLObject(body)
	if err != nil {
		return nil, -1, err
	}
	return extractObjects(xmlObj), extractTotal(xmlObj), nil
}

func normalizeJSON(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		obj := Object{}
		for key, nested := range typed {
			obj[key] = normalizeJSON(nested)
		}
		return obj
	case []any:
		values := make([]any, 0, len(typed))
		for _, nested := range typed {
			values = append(values, normalizeJSON(nested))
		}
		return values
	default:
		return typed
	}
}

func extractObjects(value any) []Object {
	switch typed := value.(type) {
	case []any:
		return objectSlice(typed)
	case []Object:
		return typed
	case Object:
		for _, key := range []string{"response", "Response", "data", "Data", "items", "Items", "content", "Content", "results", "Results", "records", "Records", "entries", "Entries", "resources", "Resources", "resource", "Resource"} {
			if nested, ok := typed[key]; ok {
				return extractObjects(nested)
			}
		}
		for _, key := range []string{"activeSession", "authSession", "authStatusElements", "acctStatusElements", "sessionParameters"} {
			if nested, ok := typed[key]; ok {
				return extractObjects(nested)
			}
		}
		for _, key := range []string{"SearchResult", "searchResult", "ERSResponse", "ersResponse", "OperationResult"} {
			if nested, ok := typed[key]; ok {
				return extractObjects(nested)
			}
		}
		for _, key := range []string{"sessionCount", "activeSessionList", "authSessionList", "authStatusOutputList", "authStatusList", "acctStatusOutputList", "acctStatusList"} {
			if nested, ok := typed[key]; ok {
				return extractObjects(nested)
			}
		}
		if len(typed) == 1 {
			for _, nested := range typed {
				if objects := extractObjects(nested); len(objects) > 0 {
					return objects
				}
			}
		}
		return []Object{typed}
	case map[string]any:
		return extractObjects(Object(typed))
	default:
		return nil
	}
}

func objectSlice(values []any) []Object {
	objects := make([]Object, 0, len(values))
	for _, value := range values {
		switch typed := value.(type) {
		case Object:
			objects = append(objects, typed)
		case map[string]any:
			objects = append(objects, Object(typed))
		}
	}
	return objects
}

func extractTotal(value any) int {
	switch typed := value.(type) {
	case Object:
		for _, key := range []string{"total", "@total", "totalCount", "total_count", "@noOfActiveSession", "@noOfAuthSession"} {
			if total, ok := numberValue(typed[key]); ok {
				return int(total)
			}
		}
		for _, key := range []string{"SearchResult", "searchResult", "activeSessionList", "authSessionList"} {
			if nested, ok := typed[key]; ok {
				if total := extractTotal(nested); total >= 0 {
					return total
				}
			}
		}
	case map[string]any:
		return extractTotal(Object(typed))
	}
	return -1
}

func flattenSingleRoot(obj Object) Object {
	if len(obj) != 1 {
		return obj
	}
	for _, value := range obj {
		switch typed := value.(type) {
		case Object:
			return typed
		case map[string]any:
			return Object(typed)
		}
	}
	return obj
}

func numberValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case json.Number:
		parsed, err := typed.Float64()
		return parsed, err == nil
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

type xmlElement struct {
	XMLName xml.Name
	Attrs   []xml.Attr   `xml:",any,attr"`
	Text    string       `xml:",chardata"`
	Nodes   []xmlElement `xml:",any"`
}

const (
	hardMaxXMLDepth      = 128
	hardMaxXMLTokens     = 450_000
	hardMaxXMLElements   = 200_000
	hardMaxXMLAttributes = 250_000
)

type xmlComplexityLimitError struct {
	kind    string
	maximum int
}

type xmlComplexityLimits struct {
	depth      int
	tokens     int
	elements   int
	attributes int
}

func (e *xmlComplexityLimitError) Error() string {
	return fmt.Sprintf("XML response exceeds hard %s limit of %d", e.kind, e.maximum)
}

// validateXMLComplexity performs a streaming pass before xml.Unmarshal builds
// the recursive element tree. Cisco ISE REST bodies are byte-bounded by the
// HTTP client, but a small adversarial document can still contain unsafe depth
// or hundreds of thousands of tiny nodes and attributes.
func validateXMLComplexity(body []byte) error {
	return validateXMLComplexityWithLimits(body, xmlComplexityLimits{
		depth:      hardMaxXMLDepth,
		tokens:     hardMaxXMLTokens,
		elements:   hardMaxXMLElements,
		attributes: hardMaxXMLAttributes,
	})
}

func validateXMLComplexityWithLimits(body []byte, limits xmlComplexityLimits) error {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	depth := 0
	tokens := 0
	elements := 0
	attributes := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		tokens++
		if tokens > limits.tokens {
			return &xmlComplexityLimitError{kind: "token", maximum: limits.tokens}
		}
		switch typed := token.(type) {
		case xml.StartElement:
			depth++
			elements++
			attributes += len(typed.Attr)
			if depth > limits.depth {
				return &xmlComplexityLimitError{kind: "depth", maximum: limits.depth}
			}
			if elements > limits.elements {
				return &xmlComplexityLimitError{kind: "element", maximum: limits.elements}
			}
			if attributes > limits.attributes {
				return &xmlComplexityLimitError{kind: "attribute", maximum: limits.attributes}
			}
		case xml.EndElement:
			depth--
		}
	}
}

func decodeXMLObject(body []byte) (Object, error) {
	if err := validateXMLComplexity(body); err != nil {
		return nil, fmt.Errorf("decode ise response: %w", err)
	}
	var root xmlElement
	if err := xml.Unmarshal(body, &root); err != nil {
		return nil, fmt.Errorf("decode ise response: %w", err)
	}
	return Object{root.XMLName.Local: root.toValue()}, nil
}

func (e xmlElement) toValue() any {
	obj := Object{}
	for _, attr := range e.Attrs {
		obj["@"+attr.Name.Local] = attr.Value
	}
	children := map[string][]any{}
	for _, child := range e.Nodes {
		children[child.XMLName.Local] = append(children[child.XMLName.Local], child.toValue())
	}
	for name, values := range children {
		if len(values) == 1 {
			obj[name] = values[0]
		} else {
			obj[name] = values
		}
	}
	if text := strings.TrimSpace(e.Text); text != "" {
		if len(obj) == 0 {
			return text
		}
		obj["value"] = text
	}
	return obj
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
		"2006-01-02T15:04:05Z",
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
