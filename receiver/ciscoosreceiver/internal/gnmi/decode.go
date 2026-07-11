// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

const (
	maxJSONTypedValueBytes          = 4 * 1024 * 1024
	maxUnsupportedTypedValueBytes   = maxJSONTypedValueBytes
	maxUnsupportedTypedValueNodes   = 100_000
	maxUnsupportedTypedValueDepth   = 128
	maxNotificationWireOperations   = 100_000
	maxDecodedNotificationPoints    = 50_000
	maxDecodedNotificationJSONNodes = 100_000
	maxDecodedNotificationBytes     = 16 * 1024 * 1024
)

type notificationDecodeLimits struct {
	maxWireOperations  int
	maxPoints          int
	maxJSONNodes       int
	maxPathStringBytes int
}

func defaultNotificationDecodeLimits() notificationDecodeLimits {
	return notificationDecodeLimits{
		maxWireOperations:  maxNotificationWireOperations,
		maxPoints:          maxDecodedNotificationPoints,
		maxJSONNodes:       maxDecodedNotificationJSONNodes,
		maxPathStringBytes: maxDecodedNotificationBytes,
	}
}

type notificationDecodeBudget struct {
	limits          notificationDecodeLimits
	points          int
	jsonNodes       int
	pathStringBytes int
}

func (b *notificationDecodeBudget) reservePathStringBytes(amount int) error {
	if amount < 0 || amount > b.limits.maxPathStringBytes-b.pathStringBytes {
		return fmt.Errorf("decoded notification exceeds %d aggregate path/string bytes", b.limits.maxPathStringBytes)
	}
	b.pathStringBytes += amount
	return nil
}

func (b *notificationDecodeBudget) reservePoint(path Path, value Value) error {
	if b.points >= b.limits.maxPoints {
		return fmt.Errorf("decoded notification exceeds %d points", b.limits.maxPoints)
	}
	pathBytes, err := validatePath(path)
	if err != nil {
		return err
	}
	valueBytes := 0
	if value.Kind == ValueString {
		valueBytes = len(value.String)
	}
	if err := b.reservePathStringBytes(pathBytes + valueBytes); err != nil {
		return err
	}
	b.points++
	return nil
}

func (b *notificationDecodeBudget) visitJSONNode() error {
	if b.jsonNodes >= b.limits.maxJSONNodes {
		return fmt.Errorf("decoded notification exceeds %d JSON nodes", b.limits.maxJSONNodes)
	}
	b.jsonNodes++
	return nil
}

// DecodeNotification decodes one wire notification to canonical leaves. It is
// intentionally schema-neutral: unsupported wire values are counted and
// omitted, never converted into dynamically named metrics.
func DecodeNotification(target string, notification *gnmipb.Notification, receipt time.Time) (DecodedNotification, DecodeStats, error) {
	return decodeNotificationWithLimits(target, notification, receipt, defaultNotificationDecodeLimits())
}

// DecodeNotificationWithRegistry uses the registry's explicit path-key
// requirements to recover list identity from aggregated JSON objects. Metric
// selection remains a separate, exact Registry.Map operation.
func DecodeNotificationWithRegistry(
	target string,
	notification *gnmipb.Notification,
	receipt time.Time,
	registry *Registry,
) (DecodedNotification, DecodeStats, error) {
	var listKeys jsonListKeySchema
	if registry != nil {
		listKeys = registry.jsonListKeys
	}
	return decodeNotificationWithOptions(target, notification, receipt, defaultNotificationDecodeLimits(), listKeys)
}

func decodeNotificationWithLimits(
	target string,
	notification *gnmipb.Notification,
	receipt time.Time,
	limits notificationDecodeLimits,
) (DecodedNotification, DecodeStats, error) {
	return decodeNotificationWithOptions(target, notification, receipt, limits, nil)
}

func decodeNotificationWithOptions(
	target string,
	notification *gnmipb.Notification,
	receipt time.Time,
	limits notificationDecodeLimits,
	listKeys jsonListKeySchema,
) (DecodedNotification, DecodeStats, error) {
	var stats DecodeStats
	if notification == nil {
		return DecodedNotification{}, stats, errors.New("notification cannot be nil")
	}
	if limits.maxWireOperations <= 0 || limits.maxPoints <= 0 || limits.maxJSONNodes <= 0 || limits.maxPathStringBytes <= 0 {
		return DecodedNotification{}, stats, errors.New("notification decode limits must be positive")
	}
	if len(notification.GetUpdate()) > limits.maxWireOperations || len(notification.GetDelete()) > limits.maxWireOperations-len(notification.GetUpdate()) {
		return DecodedNotification{}, stats, fmt.Errorf("notification exceeds %d wire operations", limits.maxWireOperations)
	}
	budget := &notificationDecodeBudget{limits: limits}

	prefix, prefixWireBytes, err := validatedPathFromProto(notification.GetPrefix())
	if err != nil {
		return DecodedNotification{}, stats, fmt.Errorf("decode prefix: %w", err)
	}
	if budgetErr := budget.reservePathStringBytes(prefixWireBytes); budgetErr != nil {
		return DecodedNotification{}, stats, budgetErr
	}
	if target != "" {
		prefix.Target = target
	}
	if prefix.Target == "" {
		return DecodedNotification{}, stats, errors.New("notification target cannot be empty")
	}
	prefixBytes, err := validatePath(prefix)
	if err != nil {
		return DecodedNotification{}, stats, fmt.Errorf("decode prefix: %w", err)
	}
	if err := budget.reservePathStringBytes(prefixBytes); err != nil {
		return DecodedNotification{}, stats, err
	}

	timestamp, valid := NormalizeTimestamp(notification.GetTimestamp(), receipt)
	if !valid {
		stats.InvalidTimestamps++
	}
	out := DecodedNotification{Prefix: prefix.Clone(), Timestamp: timestamp, Atomic: notification.GetAtomic()}

	for _, deleted := range notification.GetDelete() {
		relative, relativeBytes, pathErr := validatedPathFromProto(deleted)
		if pathErr != nil {
			return DecodedNotification{}, stats, fmt.Errorf("decode delete: %w", pathErr)
		}
		if err := budget.reservePathStringBytes(relativeBytes); err != nil {
			return DecodedNotification{}, stats, err
		}
		if target != "" {
			relative.Target = target
		}
		fullBytes, pathErr := validateJoinedPath(prefix, relative)
		if pathErr != nil {
			return DecodedNotification{}, stats, fmt.Errorf("decode delete: %w", pathErr)
		}
		if err := budget.reservePathStringBytes(fullBytes); err != nil {
			return DecodedNotification{}, stats, err
		}
		full, pathErr := JoinPaths(prefix, relative)
		if pathErr != nil {
			return DecodedNotification{}, stats, fmt.Errorf("decode delete: %w", pathErr)
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
		relative, relativeBytes, pathErr := validatedPathFromProto(update.GetPath())
		if pathErr != nil {
			return DecodedNotification{}, stats, fmt.Errorf("decode update: %w", pathErr)
		}
		if err := budget.reservePathStringBytes(relativeBytes); err != nil {
			return DecodedNotification{}, stats, err
		}
		if target != "" {
			relative.Target = target
		}
		fullBytes, pathErr := validateJoinedPath(prefix, relative)
		if pathErr != nil {
			return DecodedNotification{}, stats, fmt.Errorf("decode update: %w", pathErr)
		}
		// Reserve both the joined Path and the canonical key before allocating
		// either. The exact key length is the value returned by validation.
		if err := budget.reservePathStringBytes(fullBytes * 2); err != nil {
			return DecodedNotification{}, stats, err
		}
		full, pathErr := JoinPaths(prefix, relative)
		if pathErr != nil {
			return DecodedNotification{}, stats, fmt.Errorf("decode update: %w", pathErr)
		}
		key := full.Key()
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		resolved = append(resolved, resolvedUpdate{path: full, update: update})
	}
	for _, item := range slices.Backward(resolved) {
		full := item.path
		update := item.update
		fullBytes, pathErr := validatePath(full)
		if pathErr != nil {
			return DecodedNotification{}, stats, fmt.Errorf("decode update: %w", pathErr)
		}
		if err := budget.reservePathStringBytes(fullBytes); err != nil {
			return DecodedNotification{}, stats, err
		}
		out.Touched = append(out.Touched, full.Clone())
		typed, valueErr := ResolveUpdateValue(update)
		if valueErr != nil {
			return DecodedNotification{}, stats, fmt.Errorf("decode update value: %w", valueErr)
		}
		points, unmapped, err := decodeValue(full, typed, timestamp, budget, &stats, listKeys)
		stats.UnmappedValues += unmapped
		if err != nil {
			return DecodedNotification{}, stats, err
		}
		out.Updates = append(out.Updates, points...)
	}
	return out, stats, nil
}

// ResolveUpdateValue returns the current TypedValue representation of an
// update. When both fields are present, val takes precedence as required by the
// field's replacement semantics. Deprecated Value encodings are translated
// explicitly so legacy senders are never accepted and then silently dropped.
//
//nolint:staticcheck // Supporting the deprecated field is the purpose of this compatibility boundary.
func ResolveUpdateValue(update *gnmipb.Update) (*gnmipb.TypedValue, error) {
	if update == nil {
		return nil, nil
	}
	if typed := update.GetVal(); typed != nil {
		return typed, nil
	}
	legacy := update.GetValue()
	if legacy == nil {
		return nil, nil
	}
	raw := legacy.GetValue()
	switch legacy.GetType() {
	case gnmipb.Encoding_JSON:
		return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonVal{JsonVal: raw}}, nil
	case gnmipb.Encoding_JSON_IETF:
		return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: raw}}, nil
	case gnmipb.Encoding_ASCII:
		return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_AsciiVal{AsciiVal: string(raw)}}, nil
	case gnmipb.Encoding_BYTES:
		return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BytesVal{BytesVal: raw}}, nil
	case gnmipb.Encoding_PROTO:
		return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_ProtoBytes{ProtoBytes: raw}}, nil
	default:
		return nil, fmt.Errorf("legacy value has unknown encoding %d", legacy.GetType())
	}
}

//nolint:staticcheck // gNMI still defines deprecated float and decimal wire variants that must be decoded.
func decodeValue(
	path Path,
	typed *gnmipb.TypedValue,
	timestamp time.Time,
	budget *notificationDecodeBudget,
	stats *DecodeStats,
	listKeys jsonListKeySchema,
) ([]Point, int, error) {
	if typed == nil {
		return nil, 1, nil
	}
	appendScalar := func(value Value) ([]Point, int, error) {
		if err := budget.reservePoint(path, value); err != nil {
			return nil, 0, err
		}
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
		return decodeJSON(path, value.JsonVal, timestamp, budget, listKeys)
	case *gnmipb.TypedValue_JsonIetfVal:
		return decodeJSON(path, value.JsonIetfVal, timestamp, budget, listKeys)
	case *gnmipb.TypedValue_BytesVal:
		if err := validateUnsupportedTypedValue(typed); err != nil {
			return nil, 0, fmt.Errorf("decode unsupported bytes value: %w", err)
		}
		stats.recordUnsupportedValue(UnsupportedValueBytes)
		return nil, 1, nil
	case *gnmipb.TypedValue_LeaflistVal:
		if err := validateUnsupportedTypedValue(typed); err != nil {
			return nil, 0, fmt.Errorf("decode unsupported leaf-list value: %w", err)
		}
		stats.recordUnsupportedValue(UnsupportedValueLeafList)
		return nil, 1, nil
	case *gnmipb.TypedValue_AnyVal:
		if err := validateUnsupportedTypedValue(typed); err != nil {
			return nil, 0, fmt.Errorf("decode unsupported Any value: %w", err)
		}
		stats.recordUnsupportedValue(UnsupportedValueAny)
		return nil, 1, nil
	case *gnmipb.TypedValue_ProtoBytes:
		if err := validateUnsupportedTypedValue(typed); err != nil {
			return nil, 0, fmt.Errorf("decode unsupported proto_bytes value: %w", err)
		}
		stats.recordUnsupportedValue(UnsupportedValueProtoBytes)
		return nil, 1, nil
	default:
		// Future value kinds require an explicit decoder and are never promoted
		// to ad-hoc metrics.
		return nil, 1, nil
	}
}

type unsupportedTypedValueBudget struct {
	nodes int
	bytes int
}

func validateUnsupportedTypedValue(typed *gnmipb.TypedValue) error {
	budget := &unsupportedTypedValueBudget{}
	return budget.visit(typed, 1)
}

func (b *unsupportedTypedValueBudget) visit(typed *gnmipb.TypedValue, depth int) error {
	if depth > maxUnsupportedTypedValueDepth {
		return fmt.Errorf("nesting exceeds %d", maxUnsupportedTypedValueDepth)
	}
	if typed == nil {
		return nil
	}
	if b.nodes >= maxUnsupportedTypedValueNodes {
		return fmt.Errorf("value count exceeds %d", maxUnsupportedTypedValueNodes)
	}
	b.nodes++
	reserveBytes := func(amount int) error {
		if amount < 0 || amount > maxUnsupportedTypedValueBytes-b.bytes {
			return fmt.Errorf("payload exceeds %d bytes", maxUnsupportedTypedValueBytes)
		}
		b.bytes += amount
		return nil
	}

	switch value := typed.GetValue().(type) {
	case *gnmipb.TypedValue_StringVal:
		return reserveBytes(len(value.StringVal))
	case *gnmipb.TypedValue_AsciiVal:
		return reserveBytes(len(value.AsciiVal))
	case *gnmipb.TypedValue_BytesVal:
		return reserveBytes(len(value.BytesVal))
	case *gnmipb.TypedValue_JsonVal:
		return reserveBytes(len(value.JsonVal))
	case *gnmipb.TypedValue_JsonIetfVal:
		return reserveBytes(len(value.JsonIetfVal))
	case *gnmipb.TypedValue_ProtoBytes:
		return reserveBytes(len(value.ProtoBytes))
	case *gnmipb.TypedValue_AnyVal:
		if value.AnyVal == nil {
			return nil
		}
		if err := reserveBytes(len(value.AnyVal.GetTypeUrl())); err != nil {
			return err
		}
		return reserveBytes(len(value.AnyVal.GetValue()))
	case *gnmipb.TypedValue_LeaflistVal:
		if value.LeaflistVal == nil {
			return nil
		}
		for _, element := range value.LeaflistVal.GetElement() {
			if err := b.visit(element, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func decodeJSON(
	path Path,
	raw []byte,
	timestamp time.Time,
	budget *notificationDecodeBudget,
	listKeys jsonListKeySchema,
) ([]Point, int, error) {
	if len(raw) > maxJSONTypedValueBytes {
		return nil, 0, fmt.Errorf("decode JSON value: payload exceeds hard limit of %d bytes", maxJSONTypedValueBytes)
	}
	if err := validateJSONNodeCount(raw, budget.jsonNodes, budget.limits.maxJSONNodes); err != nil {
		return nil, 0, fmt.Errorf("decode JSON value: %w", err)
	}
	var value any
	// Validate nesting and node complexity with a streaming token pass before
	// materializing arbitrary device JSON. The enclosing gRPC message limit can
	// be much larger than a safe per-value decode budget.
	if err := httpclient.DecodeJSON(raw, &value); err != nil {
		return nil, 0, fmt.Errorf("decode JSON value: %w", err)
	}
	var points []Point
	unmapped, err := walkJSON(path, value, timestamp, &points, budget, listKeys)
	return points, unmapped, err
}

func validateJSONNodeCount(raw []byte, current, maximum int) error {
	if maximum <= current {
		return fmt.Errorf("decoded notification exceeds %d JSON nodes", maximum)
	}
	type container struct {
		object    bool
		expectKey bool
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	containers := make([]container, 0, 8)
	nodes := 0
	completeValue := func() {
		if len(containers) > 0 && containers[len(containers)-1].object {
			containers[len(containers)-1].expectKey = true
		}
	}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			// DecodeJSON below owns the detailed syntax diagnostic.
			return nil
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				nodes++
				containers = append(containers, container{object: true, expectKey: true})
			case '[':
				nodes++
				containers = append(containers, container{})
			case '}', ']':
				if len(containers) > 0 {
					containers = containers[:len(containers)-1]
				}
				completeValue()
			}
		default:
			if len(containers) > 0 {
				current := &containers[len(containers)-1]
				if current.object && current.expectKey {
					current.expectKey = false
					continue
				}
			}
			nodes++
			completeValue()
		}
		if nodes > maximum-current {
			return fmt.Errorf("decoded notification exceeds %d JSON nodes", maximum)
		}
	}
}

func walkJSON(
	path Path,
	value any,
	timestamp time.Time,
	points *[]Point,
	budget *notificationDecodeBudget,
	listKeys jsonListKeySchema,
) (int, error) {
	if err := budget.visitJSONNode(); err != nil {
		return 0, err
	}
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
			appendedBytes, err := validateAppendedPathElement(path, key, nil)
			if err != nil {
				return 0, fmt.Errorf("decode JSON path: %w", err)
			}
			if budgetErr := budget.reservePathStringBytes(appendedBytes); budgetErr != nil {
				return 0, budgetErr
			}
			childUnmapped, err := walkJSON(path.AppendElements(key), value[key], timestamp, points, budget, listKeys)
			if err != nil {
				return 0, err
			}
			unmapped += childUnmapped
		}
		return unmapped, nil
	case []any:
		unmapped := 0
		var objectPaths map[string]struct{}
		var requiredListKeys map[string]string
		if len(listKeys) > 0 {
			requiredListKeys = listKeys[jsonListSchemaPathKeyForPath(path)]
		}
		for _, item := range value {
			switch item := item.(type) {
			case map[string]any:
				keyed, keyedBytes, err := withJSONListKeys(path, item, requiredListKeys)
				if err != nil {
					return 0, err
				}
				if objectPaths == nil {
					objectPaths = make(map[string]struct{}, len(value))
				}
				key := keyed.Key()
				if _, duplicate := objectPaths[key]; duplicate {
					return 0, errors.New("decode JSON path: array contains duplicate canonical list identity")
				}
				objectPaths[key] = struct{}{}
				if keyedBytes > 0 {
					if budgetErr := budget.reservePathStringBytes(keyedBytes); budgetErr != nil {
						return 0, budgetErr
					}
				}
				itemUnmapped, err := walkJSON(keyed, item, timestamp, points, budget, listKeys)
				if err != nil {
					return 0, err
				}
				unmapped += itemUnmapped
			case []any:
				itemUnmapped, err := walkJSON(path, item, timestamp, points, budget, listKeys)
				if err != nil {
					return 0, err
				}
				unmapped += itemUnmapped
			default:
				// A scalar JSON array is a leaf-list, not a scalar leaf.
				if err := budget.visitJSONNode(); err != nil {
					return 0, err
				}
				unmapped++
			}
		}
		return unmapped, nil
	case nil:
		return 1, nil
	default:
		canonical, ok := canonicalJSONScalar(value)
		if !ok {
			return 1, nil
		}
		if err := budget.reservePoint(path, canonical); err != nil {
			return 0, err
		}
		series, err := path.SplitLeaf()
		if err != nil {
			return 1, nil
		}
		*points = append(*points, Point{Series: series, Value: canonical, Timestamp: timestamp})
		return 0, nil
	}
}

var jsonListKeyNames = map[string]struct{}{
	"name": {}, "id": {}, "index": {}, "interface": {}, "interface-name": {},
	"port": {}, "port-id": {}, "lane": {}, "lane-id": {}, "slot": {},
	"slot-id": {}, "lane-index": {}, "radio-slot-id": {}, "wlan-id": {}, "wtp-mac": {},
	"sensor": {}, "sensor-id": {}, "channel": {}, "channel-id": {},
	"component": {}, "component-name": {}, "node": {}, "node-id": {},
	"neighbor": {}, "neighbor-address": {}, "address": {}, "serial": {},
	// Product qualification reads bounded Cisco inventory/install lists. These
	// fields are schema keys in those identity responses and must remain on the
	// list element so sibling chassis/version entries cannot collapse together.
	"hw-type": {}, "hw-dev-index": {}, "version": {}, "version-extension": {},
	"fru": {}, "bay": {}, "chassis": {},
}

// jsonListKeySchema maps an exact modeled list path to normalized JSON member
// names and the canonical configured PathElem key each member satisfies.
type jsonListKeySchema map[string]map[string]string

func jsonListSchemaPathKey(pathTarget, origin string, elements []string) string {
	return (SourcePath{PathTarget: pathTarget, Origin: origin, Elements: elements}).Key()
}

func jsonListSchemaPathKeyForPath(path Path) string {
	elements := make([]string, len(path.Elements))
	for index := range path.Elements {
		elements[index] = path.Elements[index].Name
	}
	return jsonListSchemaPathKey(path.PathTarget, path.Origin, elements)
}

func normalizeJSONListKeyName(qualified string) string {
	name := qualified
	for index := len(qualified) - 1; index >= 0; index-- {
		if qualified[index] == ':' {
			name = qualified[index+1:]
			break
		}
	}
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}

// withJSONListKeys derives stable list identity from common direct key leaves
// and all keys explicitly required by mappings for this exact modeled list.
// RFC7951-qualified key names are matched by their suffix.
func withJSONListKeys(path Path, object map[string]any, required map[string]string) (Path, int, error) {
	if len(path.Elements) == 0 {
		return path, 0, nil
	}
	keys := map[string]string{}
	names := make([]string, 0, len(object))
	for name := range object {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, qualified := range names {
		normalized := normalizeJSONListKeyName(qualified)
		name, recognized := required[normalized]
		if !recognized && len(required) == 0 {
			if _, recognized = jsonListKeyNames[normalized]; !recognized {
				continue
			}
			name = normalized
		}
		if !recognized {
			continue
		}
		if value, ok := jsonKeyString(object[qualified]); ok {
			if previous, duplicate := keys[name]; duplicate {
				if previous != value {
					return Path{}, 0, fmt.Errorf("decode JSON path: conflicting values for normalized list key %q", name)
				}
				continue
			}
			if len(value) > maxPathKeyValueBytes {
				return Path{}, 0, fmt.Errorf("decode JSON path: key %q value exceeds %d bytes", name, maxPathKeyValueBytes)
			}
			keys[name] = value
		}
	}
	if len(keys) == 0 {
		return path, 0, nil
	}
	mergedKeys := make(map[string]string, len(path.Elements[len(path.Elements)-1].Keys)+len(keys))
	maps.Copy(mergedKeys, path.Elements[len(path.Elements)-1].Keys)
	for name, value := range keys {
		if previous, exists := mergedKeys[name]; exists && previous != value {
			return Path{}, 0, fmt.Errorf("decode JSON path: conflicting values for existing list key %q", name)
		}
		mergedKeys[name] = value
	}
	if len(mergedKeys) > maxPathKeysPerElement {
		return Path{}, 0, fmt.Errorf("decode JSON path: element exceeds %d keys", maxPathKeysPerElement)
	}
	pathBytes, err := validateReplacedLastPathElement(path, mergedKeys)
	if err != nil {
		return Path{}, 0, fmt.Errorf("decode JSON path: %w", err)
	}
	out := path.Clone()
	last := &out.Elements[len(out.Elements)-1]
	last.Keys = mergedKeys
	return out, pathBytes, nil
}

func jsonKeyString(value any) (string, bool) {
	switch value := value.(type) {
	case string:
		return value, true
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
