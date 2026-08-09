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
	maxJSONListKeySchemaEntries     = 4_096
)

// JSONListKeySpec declares the complete key set for one JSON-encoded YANG list.
// Origin and Elements identify the list by its exact canonical path after the
// notification prefix and update path have been joined. Keys are canonical YANG
// key names. An unqualified key also accepts an RFC7951 module-qualified JSON
// member with the same local name.
type JSONListKeySpec struct {
	Origin   string
	Elements []string
	Keys     []string
}

// JSONListKeySchema is an immutable, validated set of JSON list identities.
// Its contents can only be constructed through NewJSONListKeySchema, which
// copies all caller-owned slices.
type JSONListKeySchema struct {
	keysByPath map[string][]string
}

// NewJSONListKeySchema validates and copies exact JSON list-key declarations.
func NewJSONListKeySchema(specs ...JSONListKeySpec) (*JSONListKeySchema, error) {
	if len(specs) > maxJSONListKeySchemaEntries {
		return nil, fmt.Errorf("JSON list-key schema exceeds %d entries", maxJSONListKeySchemaEntries)
	}
	schema := &JSONListKeySchema{keysByPath: make(map[string][]string, len(specs))}
	for index := range specs {
		spec := &specs[index]
		if len(spec.Elements) == 0 {
			return nil, fmt.Errorf("JSON list-key schema entry %d has an empty element path", index)
		}
		path := Path{Origin: spec.Origin, Elements: make([]PathElem, len(spec.Elements))}
		for elementIndex, element := range spec.Elements {
			path.Elements[elementIndex] = PathElem{Name: element}
		}
		if _, err := validatePath(path); err != nil {
			return nil, fmt.Errorf("JSON list-key schema entry %d path: %w", index, err)
		}
		if len(spec.Keys) == 0 {
			return nil, fmt.Errorf("JSON list-key schema entry %d has no keys", index)
		}
		if len(spec.Keys) > maxPathKeysPerElement {
			return nil, fmt.Errorf("JSON list-key schema entry %d exceeds %d keys", index, maxPathKeysPerElement)
		}
		keys := make([]string, len(spec.Keys))
		seen := make(map[string]struct{}, len(spec.Keys))
		for keyIndex, key := range spec.Keys {
			if key == "" {
				return nil, fmt.Errorf("JSON list-key schema entry %d contains an empty key", index)
			}
			if len(key) > maxPathNameBytes {
				return nil, fmt.Errorf("JSON list-key schema entry %d key %q exceeds %d bytes", index, key, maxPathNameBytes)
			}
			if _, duplicate := seen[key]; duplicate {
				return nil, fmt.Errorf("JSON list-key schema entry %d duplicates key %q", index, key)
			}
			seen[key] = struct{}{}
			keys[keyIndex] = key
		}
		pathKey := jsonListKeySchemaPathKey(path.Origin, path.Elements)
		if _, duplicate := schema.keysByPath[pathKey]; duplicate {
			return nil, fmt.Errorf("JSON list-key schema entry %d duplicates origin and element path", index)
		}
		schema.keysByPath[pathKey] = keys
	}
	return schema, nil
}

func (s *JSONListKeySchema) keysFor(path Path) ([]string, bool) {
	if s == nil {
		return nil, false
	}
	keys, ok := s.keysByPath[jsonListKeySchemaPathKey(path.Origin, path.Elements)]
	return keys, ok
}

func jsonListKeySchemaPathKey(origin string, elements []PathElem) string {
	var key strings.Builder
	appendKeyPart(&key, origin)
	for index := range elements {
		appendKeyPart(&key, elements[index].Name)
	}
	return key.String()
}

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

// undecodablePathCollector retains each exact invalid scalar path once. Its
// paths share the decoded notification's point and path/string budgets, while
// the additional canonical keys used for deduplication are charged explicitly.
// Aggregate object and list-container paths are never added merely because a
// descendant is invalid.
type undecodablePathCollector struct {
	budget *notificationDecodeBudget
	seen   map[string]struct{}
	paths  []Path
}

func (c *undecodablePathCollector) add(path Path) error {
	if c == nil || c.budget == nil {
		return errors.New("undecodable path collector is not initialized")
	}
	pathBytes, err := validatePath(path)
	if err != nil {
		return err
	}
	key := path.Key()
	if _, exists := c.seen[key]; exists {
		return nil
	}
	if err := c.budget.reservePathStringBytes(pathBytes); err != nil {
		return err
	}
	if err := c.budget.reservePoint(path, Value{}); err != nil {
		return err
	}
	if c.seen == nil {
		c.seen = make(map[string]struct{})
	}
	c.seen[key] = struct{}{}
	c.paths = append(c.paths, path)
	return nil
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
// omitted, never converted into dynamically named metrics. JSON arrays are not
// assigned inferred identities; use DecodeNotificationWithSchema when a
// catalog declares their exact list keys.
func DecodeNotification(target string, notification *gnmipb.Notification, receipt time.Time) (DecodedNotification, DecodeStats, error) {
	return decodeNotificationWithLimits(target, notification, receipt, defaultNotificationDecodeLimits())
}

// DecodeNotificationWithSchema decodes one wire notification using only the
// exact JSON list identities declared by schema. A malformed list identity
// rejects the complete notification; no partially decoded result is returned.
func DecodeNotificationWithSchema(
	target string,
	notification *gnmipb.Notification,
	receipt time.Time,
	schema *JSONListKeySchema,
) (DecodedNotification, DecodeStats, error) {
	return decodeNotificationWithSchemaAndLimits(target, notification, receipt, schema, defaultNotificationDecodeLimits())
}

func decodeNotificationWithLimits(
	target string,
	notification *gnmipb.Notification,
	receipt time.Time,
	limits notificationDecodeLimits,
) (DecodedNotification, DecodeStats, error) {
	return decodeNotificationWithSchemaAndLimits(target, notification, receipt, nil, limits)
}

func decodeNotificationWithSchemaAndLimits(
	target string,
	notification *gnmipb.Notification,
	receipt time.Time,
	schema *JSONListKeySchema,
	limits notificationDecodeLimits,
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
	undecodable := &undecodablePathCollector{budget: budget}
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
		points, unmapped, err := decodeValue(full, update.GetVal(), timestamp, budget, schema)
		stats.UnmappedValues += unmapped
		if err != nil {
			return DecodedNotification{}, stats, err
		}
		if exactMappedScalarMissing(registry, full, points) {
			if err := undecodable.add(full); err != nil {
				return DecodedNotification{}, stats, err
			}
		}
		out.Updates = append(out.Updates, points...)
	}
	out.Undecodable = undecodable.paths
	return out, stats, nil
}

// exactMappedScalarMissing reports only a fully keyed exact source contract
// whose wire update produced no scalar at that same path. Descendant points do
// not satisfy a scalar contract at their aggregate parent, while an unmatched
// aggregate root remains benign.
func exactMappedScalarMissing(registry *Registry, path Path, points []Point) bool {
	if registry == nil {
		return false
	}
	for index := range points {
		if seriesMatchesExactPath(points[index].Series, path) {
			return false
		}
	}
	series, err := path.SplitLeaf()
	if err != nil {
		return false
	}
	_, status := registry.MapWithStatus(Point{Series: series})
	return status == MappingInvalidValue
}

func seriesMatchesExactPath(series Series, path Path) bool {
	if series.Target != path.Target ||
		series.PathTarget != path.PathTarget ||
		series.Origin != path.Origin ||
		len(path.Elements) != len(series.Elements)+1 {
		return false
	}
	for index := range series.Elements {
		if series.Elements[index].Name != path.Elements[index].Name ||
			!maps.Equal(series.Elements[index].Keys, path.Elements[index].Keys) {
			return false
		}
	}
	leaf := path.Elements[len(path.Elements)-1]
	return leaf.Name == series.Leaf && len(leaf.Keys) == 0
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
	schema *JSONListKeySchema,
) ([]Point, int, error) {
	if typed == nil {
		return nil, 1, nil
	}
	if typed == nil {
		return rejectScalar()
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
			return rejectScalar()
		}
		return appendScalar(DoubleValue(float64(value.FloatVal)))
	case *gnmipb.TypedValue_DoubleVal:
		if math.IsNaN(value.DoubleVal) || math.IsInf(value.DoubleVal, 0) {
			return rejectScalar()
		}
		return appendScalar(DoubleValue(value.DoubleVal))
	case *gnmipb.TypedValue_DecimalVal:
		if value.DecimalVal == nil || value.DecimalVal.Precision > 308 {
			return rejectScalar()
		}
		decoded := float64(value.DecimalVal.Digits) / math.Pow10(int(value.DecimalVal.Precision))
		if math.IsNaN(decoded) || math.IsInf(decoded, 0) {
			return rejectScalar()
		}
		return appendScalar(DoubleValue(decoded))
	case *gnmipb.TypedValue_BoolVal:
		return appendScalar(BoolValue(value.BoolVal))
	case *gnmipb.TypedValue_StringVal:
		return appendScalar(StringValue(value.StringVal))
	case *gnmipb.TypedValue_AsciiVal:
		return appendScalar(StringValue(value.AsciiVal))
	case *gnmipb.TypedValue_JsonVal:
		return decodeJSON(path, value.JsonVal, timestamp, budget, schema)
	case *gnmipb.TypedValue_JsonIetfVal:
		return decodeJSON(path, value.JsonIetfVal, timestamp, budget, schema)
	default:
		// bytes, proto_bytes, leaf-lists, Any, and future value kinds require
		// an explicit decoder and are never promoted to ad-hoc metrics.
		if schema != nil {
			return nil, 0, fmt.Errorf("decode catalog path %q: unsupported typed value %T has no declared decoder", pathString(path), value)
		}
		return nil, 1, nil
	}
}

func decodeJSON(
	path Path,
	raw []byte,
	timestamp time.Time,
	budget *notificationDecodeBudget,
	schema *JSONListKeySchema,
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
	unmapped, err := walkJSON(path, value, timestamp, &points, budget, schema)
	return points, unmapped, err
}

func validateJSONNodeCount(raw []byte, current, maximum int) error {
	if maximum <= current {
		return fmt.Errorf("decoded notification exceeds %d JSON nodes", maximum)
	}
	type container struct {
		object    bool
		expectKey bool
		keys      map[string]struct{}
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
				containers = append(containers, container{object: true, expectKey: true, keys: map[string]struct{}{}})
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
					key, ok := value.(string)
					if !ok {
						return errors.New("JSON object member name is not a string")
					}
					if _, duplicate := current.keys[key]; duplicate {
						return fmt.Errorf("duplicate JSON object member %q", key)
					}
					current.keys[key] = struct{}{}
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
	schema *JSONListKeySchema,
) (int, error) {
	if err := budget.visitJSONNode(); err != nil {
		return 0, err
	}
	switch value := value.(type) {
	case map[string]any:
		if len(value) == 0 {
			if err := undecodable.add(path); err != nil {
				return 0, err
			}
			return 0, nil
		}
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
			childUnmapped, err := walkJSON(path.AppendElements(key), value[key], timestamp, points, budget, schema)
			if err != nil {
				return 0, err
			}
			unmapped += childUnmapped
		}
		return unmapped, nil
	case []any:
		declaredKeys, declared := schema.keysFor(path)
		if !declared {
			if schema != nil {
				return 0, fmt.Errorf("decode JSON list path %q: list identity is absent from the catalog schema", pathString(path))
			}
			unmapped := 0
			for _, item := range value {
				itemUnmapped, err := visitUnmappedJSONValue(item, budget)
				if err != nil {
					return 0, err
				}
				unmapped += itemUnmapped
			}
			return unmapped, nil
		}
		unmapped := 0
		for itemIndex, item := range value {
			object, ok := item.(map[string]any)
			if !ok {
				return 0, fmt.Errorf("decode JSON list path %q: item %d is not an object", pathString(path), itemIndex)
			}
			keyed, keyedBytes, err := withDeclaredJSONListKeys(path, object, declaredKeys)
			if err != nil {
				return 0, err
			}
			if budgetErr := budget.reservePathStringBytes(keyedBytes); budgetErr != nil {
				return 0, budgetErr
			}
			itemUnmapped, err := walkJSON(keyed, object, timestamp, points, budget, schema)
			if err != nil {
				return 0, err
			}
			unmapped += itemUnmapped
		}
		return unmapped, nil
	case nil:
		if err := undecodable.add(path); err != nil {
			return 0, err
		}
		return 1, nil
	default:
		canonical, ok := canonicalJSONScalar(value)
		if !ok {
			if err := undecodable.add(path); err != nil {
				return 0, err
			}
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

// visitUnmappedJSONValue charges the full decoded-node budget while refusing to
// materialize an array whose list identity is not catalog-declared. Scalar
// leaves are counted as unmapped; no canonical series is produced.
func visitUnmappedJSONValue(value any, budget *notificationDecodeBudget) (int, error) {
	if err := budget.visitJSONNode(); err != nil {
		return 0, err
	}
	switch value := value.(type) {
	case map[string]any:
		unmapped := 0
		for _, child := range value {
			childUnmapped, err := visitUnmappedJSONValue(child, budget)
			if err != nil {
				return 0, err
			}
			unmapped += childUnmapped
		}
		return unmapped, nil
	case []any:
		unmapped := 0
		for _, child := range value {
			childUnmapped, err := visitUnmappedJSONValue(child, budget)
			if err != nil {
				return 0, err
			}
			unmapped += childUnmapped
		}
		return unmapped, nil
	default:
		return 1, nil
	}
}

func withDeclaredJSONListKeys(path Path, object map[string]any, declaredKeys []string) (Path, int, error) {
	if len(path.Elements) == 0 {
		return Path{}, 0, errors.New("decode JSON list path has no element")
	}
	keys := make(map[string]string, len(declaredKeys))
	names := make([]string, 0, len(object))
	for name := range object {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, declaredKey := range declaredKeys {
		found := false
		for _, memberName := range names {
			if !jsonMemberMatchesDeclaredKey(memberName, declaredKey) {
				continue
			}
			value, scalar := jsonKeyString(object[memberName])
			if !scalar {
				return Path{}, 0, fmt.Errorf("decode JSON path: list key %q has a non-scalar value", declaredKey)
			}
			if previous, duplicate := keys[declaredKey]; duplicate {
				if previous != value {
					return Path{}, 0, fmt.Errorf("decode JSON path: conflicting values for list key %q", declaredKey)
				}
				continue
			}
			if len(value) > maxPathKeyValueBytes {
				return Path{}, 0, fmt.Errorf("decode JSON path: key %q value exceeds %d bytes", declaredKey, maxPathKeyValueBytes)
			}
			keys[declaredKey] = value
			found = true
		}
		if !found {
			return Path{}, 0, fmt.Errorf("decode JSON path: required list key %q is missing", declaredKey)
		}
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

func jsonMemberMatchesDeclaredKey(memberName, declaredKey string) bool {
	if memberName == declaredKey {
		return true
	}
	if strings.Contains(declaredKey, ":") {
		return false
	}
	separator := strings.IndexByte(memberName, ':')
	return separator > 0 && memberName[separator+1:] == declaredKey
}

func pathString(path Path) string {
	elements := make([]string, len(path.Elements))
	for index := range path.Elements {
		elements[index] = path.Elements[index].Name
	}
	joined := strings.Join(elements, "/")
	if path.Origin == "" {
		return joined
	}
	return path.Origin + ":" + joined
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
