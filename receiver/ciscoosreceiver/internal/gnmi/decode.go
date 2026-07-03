// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

const maxJSONTypedValueBytes = 4 * 1024 * 1024

// DecodeNotification decodes one wire notification to canonical leaves. It is
// intentionally schema-neutral: unsupported wire values are counted and
// omitted, never converted into dynamically named metrics.
func DecodeNotification(target string, notification *gnmipb.Notification, receipt time.Time) (DecodedNotification, DecodeStats, error) {
	var stats DecodeStats
	if notification == nil {
		return DecodedNotification{}, stats, errors.New("notification cannot be nil")
	}

	prefix := PathFromProto(notification.GetPrefix())
	if target != "" {
		prefix.Target = target
	}
	if prefix.Target == "" {
		return DecodedNotification{}, stats, errors.New("notification target cannot be empty")
	}

	timestamp, valid := NormalizeTimestamp(notification.GetTimestamp(), receipt)
	if !valid {
		stats.InvalidTimestamps++
	}
	out := DecodedNotification{Prefix: prefix.Clone(), Timestamp: timestamp, Atomic: notification.GetAtomic()}

	for _, deleted := range notification.GetDelete() {
		relative := PathFromProto(deleted)
		if target != "" {
			relative.Target = target
		}
		full, err := JoinPaths(prefix, relative)
		if err != nil {
			return DecodedNotification{}, stats, fmt.Errorf("decode delete: %w", err)
		}
		out.Deletes = append(out.Deletes, full)
	}

	// gNMI requires the final update to win when a notification contains the
	// same fully-resolved path more than once. Resolve in reverse so superseded
	// values are never decoded or counted as touched state, then restore wire
	// order for the surviving updates.
	type resolvedUpdate struct {
		path   Path
		update *gnmipb.Update
	}
	updates := notification.GetUpdate()
	resolved := make([]resolvedUpdate, 0, len(updates))
	seen := make(map[string]struct{}, len(updates))
	for _, update := range slices.Backward(updates) {
		if update == nil {
			stats.UnmappedValues++
			continue
		}
		relative := PathFromProto(update.GetPath())
		if target != "" {
			relative.Target = target
		}
		full, err := JoinPaths(prefix, relative)
		if err != nil {
			return DecodedNotification{}, stats, fmt.Errorf("decode update: %w", err)
		}
		if _, duplicate := seen[full.Key()]; duplicate {
			continue
		}
		seen[full.Key()] = struct{}{}
		resolved = append(resolved, resolvedUpdate{path: full, update: update})
	}
	for _, item := range slices.Backward(resolved) {
		full := item.path
		update := item.update
		out.Touched = append(out.Touched, full.Clone())
		points, unmapped, err := decodeValue(full, update.GetVal(), timestamp)
		stats.UnmappedValues += unmapped
		if err != nil {
			return DecodedNotification{}, stats, err
		}
		out.Updates = append(out.Updates, points...)
	}
	return out, stats, nil
}

//nolint:staticcheck // gNMI still defines deprecated float and decimal wire variants that must be decoded.
func decodeValue(path Path, typed *gnmipb.TypedValue, timestamp time.Time) ([]Point, int, error) {
	if typed == nil {
		return nil, 1, nil
	}
	appendScalar := func(value Value) ([]Point, int, error) {
		series, err := path.SplitLeaf()
		if err != nil {
			return nil, 1, nil
		}
		return []Point{{Series: series, Value: value, Timestamp: timestamp}}, 0, nil
	}

	switch value := typed.GetValue().(type) {
	case *gnmipb.TypedValue_IntVal:
		return appendScalar(IntValue(value.IntVal))
	case *gnmipb.TypedValue_UintVal:
		return appendScalar(UintValue(value.UintVal))
	case *gnmipb.TypedValue_FloatVal:
		if math.IsNaN(float64(value.FloatVal)) || math.IsInf(float64(value.FloatVal), 0) {
			return nil, 1, nil
		}
		return appendScalar(DoubleValue(float64(value.FloatVal)))
	case *gnmipb.TypedValue_DoubleVal:
		if math.IsNaN(value.DoubleVal) || math.IsInf(value.DoubleVal, 0) {
			return nil, 1, nil
		}
		return appendScalar(DoubleValue(value.DoubleVal))
	case *gnmipb.TypedValue_DecimalVal:
		if value.DecimalVal == nil || value.DecimalVal.Precision > 308 {
			return nil, 1, nil
		}
		decoded := float64(value.DecimalVal.Digits) / math.Pow10(int(value.DecimalVal.Precision))
		if math.IsNaN(decoded) || math.IsInf(decoded, 0) {
			return nil, 1, nil
		}
		return appendScalar(DoubleValue(decoded))
	case *gnmipb.TypedValue_BoolVal:
		return appendScalar(BoolValue(value.BoolVal))
	case *gnmipb.TypedValue_StringVal:
		return appendScalar(StringValue(value.StringVal))
	case *gnmipb.TypedValue_AsciiVal:
		return appendScalar(StringValue(value.AsciiVal))
	case *gnmipb.TypedValue_JsonVal:
		return decodeJSON(path, value.JsonVal, timestamp)
	case *gnmipb.TypedValue_JsonIetfVal:
		return decodeJSON(path, value.JsonIetfVal, timestamp)
	default:
		// bytes, proto_bytes, leaf-lists, Any, and future value kinds require
		// an explicit decoder and are never promoted to ad-hoc metrics.
		return nil, 1, nil
	}
}

func decodeJSON(path Path, raw []byte, timestamp time.Time) ([]Point, int, error) {
	if len(raw) > maxJSONTypedValueBytes {
		return nil, 0, fmt.Errorf("decode JSON value: payload exceeds hard limit of %d bytes", maxJSONTypedValueBytes)
	}
	var value any
	// Validate nesting and node complexity with a streaming token pass before
	// materializing arbitrary device JSON. The enclosing gRPC message limit can
	// be much larger than a safe per-value decode budget.
	if err := httpclient.DecodeJSON(raw, &value); err != nil {
		return nil, 0, fmt.Errorf("decode JSON value: %w", err)
	}
	var points []Point
	unmapped := walkJSON(path, value, timestamp, &points)
	return points, unmapped, nil
}

func walkJSON(path Path, value any, timestamp time.Time, points *[]Point) int {
	switch value := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		unmapped := 0
		for _, key := range keys {
			// Keep RFC7951 module qualification in the element name. Origin
			// remains the independent Path.Origin field.
			unmapped += walkJSON(path.AppendElements(key), value[key], timestamp, points)
		}
		return unmapped
	case []any:
		unmapped := 0
		for _, item := range value {
			switch item := item.(type) {
			case map[string]any:
				unmapped += walkJSON(withJSONListKeys(path, item), item, timestamp, points)
			case []any:
				unmapped += walkJSON(path, item, timestamp, points)
			default:
				// A scalar JSON array is a leaf-list, not a scalar leaf.
				unmapped++
			}
		}
		return unmapped
	case nil:
		return 1
	default:
		canonical, ok := canonicalJSONScalar(value)
		if !ok {
			return 1
		}
		series, err := path.SplitLeaf()
		if err != nil {
			return 1
		}
		*points = append(*points, Point{Series: series, Value: canonical, Timestamp: timestamp})
		return 0
	}
}

var jsonListKeyNames = map[string]struct{}{
	"name": {}, "id": {}, "index": {}, "interface": {}, "interface-name": {},
	"port": {}, "port-id": {}, "lane": {}, "lane-id": {}, "slot": {},
	"slot-id": {}, "lane-index": {}, "radio-slot-id": {}, "wlan-id": {}, "wtp-mac": {},
	"sensor": {}, "sensor-id": {}, "channel": {}, "channel-id": {},
	"component": {}, "component-name": {}, "node": {}, "node-id": {},
	"neighbor": {}, "neighbor-address": {}, "address": {}, "serial": {},
}

// withJSONListKeys derives stable list identity from common direct key leaves.
// RFC7951-qualified key names are matched by their suffix and stored without
// the module qualifier, matching their PathElem key representation.
func withJSONListKeys(path Path, object map[string]any) Path {
	if len(path.Elements) == 0 {
		return path
	}
	keys := map[string]string{}
	names := make([]string, 0, len(object))
	for name := range object {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, qualified := range names {
		name := qualified
		for i := len(qualified) - 1; i >= 0; i-- {
			if qualified[i] == ':' {
				name = qualified[i+1:]
				break
			}
		}
		name = strings.ToLower(strings.ReplaceAll(name, "_", "-"))
		if _, recognized := jsonListKeyNames[name]; !recognized {
			continue
		}
		if value, ok := jsonKeyString(object[qualified]); ok {
			if _, duplicate := keys[name]; !duplicate {
				keys[name] = value
			}
		}
	}
	if len(keys) == 0 {
		return path
	}
	out := path.Clone()
	last := &out.Elements[len(out.Elements)-1]
	if last.Keys == nil {
		last.Keys = map[string]string{}
	}
	maps.Copy(last.Keys, keys)
	return out
}

func jsonKeyString(value any) (string, bool) {
	switch value := value.(type) {
	case string:
		return value, value != ""
	case json.Number:
		return value.String(), value.String() != ""
	case bool:
		return strconv.FormatBool(value), true
	default:
		return "", false
	}
}

func canonicalJSONScalar(value any) (Value, bool) {
	switch value := value.(type) {
	case string:
		return StringValue(value), true
	case bool:
		return BoolValue(value), true
	case json.Number:
		if integer, err := value.Int64(); err == nil {
			return IntValue(integer), true
		}
		if unsigned, err := strconv.ParseUint(value.String(), 10, 64); err == nil {
			return UintValue(unsigned), true
		}
		double, err := value.Float64()
		if err != nil || math.IsNaN(double) || math.IsInf(double, 0) {
			return Value{}, false
		}
		return DoubleValue(double), true
	default:
		return Value{}, false
	}
}
