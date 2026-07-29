// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var metricNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*$`)

// GaugeValueType is the explicit OTLP gauge number representation.
type GaugeValueType string

const (
	GaugeInt    GaugeValueType = "int"
	GaugeDouble GaugeValueType = "double"
)

// MetricType distinguishes instantaneous gauges from device-reported
// cumulative counters. Custom mappings remain gauges; curated profiles may
// select sums when reusing an existing cumulative metric contract.
type MetricType uint8

const (
	MetricGauge MetricType = iota
	MetricSum
)

// SourcePath is an exact scalar source path. List key values are intentionally
// omitted because mappings apply to every instance of a modeled list.
type SourcePath struct {
	PathTarget string
	Origin     string
	Elements   []string
	Leaf       string
}

// MetricMetadata is the required metric contract for one mapping.
type MetricMetadata struct {
	Name        string
	Description string
	Unit        string
}

// KeyAttribute maps one modeled PathElem key to one bounded metric attribute.
type KeyAttribute struct {
	Element   string
	Key       string
	Attribute string
}

// NumericBounds constrains the decoded source value before scaling. Bounds are
// inclusive and are intended for modeled numeric leaves whose OTLP contract is
// narrower than the wire integer type.
type NumericBounds struct {
	Min float64
	Max float64
}

// Mapping explicitly maps one numeric source leaf to one gauge metric.
type Mapping struct {
	Source        SourcePath
	Metric        MetricMetadata
	Scale         float64
	SourceBounds  *NumericBounds
	GaugeType     GaugeValueType
	MetricType    MetricType
	Monotonic     bool
	KeyAttributes []KeyAttribute
}

// MappingStatus distinguishes an unregistered source, malformed key identity,
// malformed/out-of-contract source value, and a successful mapping. Callers
// can invalidate only the precise cached series for MappingInvalidValue while
// preserving the existing bool-only Map API.
type MappingStatus uint8

const (
	MappingUnmatched MappingStatus = iota
	MappingInvalidIdentity
	MappingInvalidValue
	MappingMapped
)

// Registry contains only validated, explicit source mappings.
type Registry struct {
	mappings     map[string]Mapping
	metrics      map[string]metricContract
	jsonListKeys jsonListKeySchema
}

type metricContract struct {
	metadata   MetricMetadata
	gaugeType  GaugeValueType
	metricType MetricType
	monotonic  bool
}

// NewRegistry validates and registers all mappings.
func NewRegistry(mappings ...Mapping) (*Registry, error) {
	registry := &Registry{
		mappings:     make(map[string]Mapping, len(mappings)),
		metrics:      make(map[string]metricContract),
		jsonListKeys: jsonListKeySchema{},
	}
	for i := range mappings {
		if err := registry.Register(mappings[i]); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

// Register adds one mapping and rejects ambiguous duplicates.
func (r *Registry) Register(mapping Mapping) error {
	if r == nil {
		return errors.New("mapping registry cannot be nil")
	}
	if err := validateMapping(mapping); err != nil {
		return err
	}
	if r.mappings == nil {
		r.mappings = map[string]Mapping{}
	}
	if r.metrics == nil {
		r.metrics = map[string]metricContract{}
	}
	if r.jsonListKeys == nil {
		r.jsonListKeys = jsonListKeySchema{}
	}
	key := sourcePathKey(mapping.Source)
	if _, exists := r.mappings[key]; exists {
		return fmt.Errorf("duplicate mapping for %s", mapping.Source.String())
	}
	contract := metricContract{
		metadata: mapping.Metric, gaugeType: mapping.GaugeType,
		metricType: mapping.MetricType, monotonic: mapping.Monotonic,
	}
	if existing, exists := r.metrics[mapping.Metric.Name]; exists && existing != contract {
		return fmt.Errorf("conflicting contract for metric %q", mapping.Metric.Name)
	}
	listKeyRequirements, err := r.validateJSONListKeyRequirements(mapping)
	if err != nil {
		return err
	}
	mapping.Source.Elements = append([]string(nil), mapping.Source.Elements...)
	mapping.KeyAttributes = append([]KeyAttribute(nil), mapping.KeyAttributes...)
	if mapping.SourceBounds != nil {
		bounds := *mapping.SourceBounds
		mapping.SourceBounds = &bounds
	}
	r.mappings[key] = mapping
	r.metrics[mapping.Metric.Name] = contract
	for _, requirement := range listKeyRequirements {
		keys := r.jsonListKeys[requirement.path]
		if keys == nil {
			keys = map[string]string{}
			r.jsonListKeys[requirement.path] = keys
		}
		keys[requirement.normalized] = requirement.canonical
	}
	return nil
}

type jsonListKeyRequirement struct {
	path       string
	normalized string
	canonical  string
}

func (r *Registry) validateJSONListKeyRequirements(mapping Mapping) ([]jsonListKeyRequirement, error) {
	requirements := make([]jsonListKeyRequirement, 0, len(mapping.KeyAttributes))
	staged := map[string]map[string]string{}
	for _, attribute := range mapping.KeyAttributes {
		for index, element := range mapping.Source.Elements {
			if element != attribute.Element {
				continue
			}
			path := jsonListSchemaPathKey(mapping.Source.PathTarget, mapping.Source.Origin, mapping.Source.Elements[:index+1])
			normalized := normalizeJSONListKeyName(attribute.Key)
			if existing, ok := r.jsonListKeys[path][normalized]; ok && existing != attribute.Key {
				return nil, fmt.Errorf(
					"mapping source %s has JSON list keys %q and %q with the same normalized identity",
					mapping.Source.String(), existing, attribute.Key,
				)
			}
			keys := staged[path]
			if keys == nil {
				keys = map[string]string{}
				staged[path] = keys
			}
			if existing, ok := keys[normalized]; ok {
				if existing != attribute.Key {
					return nil, fmt.Errorf(
						"mapping source %s has JSON list keys %q and %q with the same normalized identity",
						mapping.Source.String(), existing, attribute.Key,
					)
				}
				continue
			}
			if _, exists := r.jsonListKeys[path][normalized]; !exists && len(r.jsonListKeys[path])+len(keys) >= maxPathKeysPerElement {
				return nil, fmt.Errorf("mapping source %s requires more than %d JSON list keys on one element", mapping.Source.String(), maxPathKeysPerElement)
			}
			keys[normalized] = attribute.Key
			requirements = append(requirements, jsonListKeyRequirement{path: path, normalized: normalized, canonical: attribute.Key})
		}
	}
	return requirements, nil
}

// Len returns the number of explicit mappings.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.mappings)
}

// Map emits a point only when its exact source path is registered, all mapped
// keys are present, and its scalar value can satisfy the configured gauge type.
func (r *Registry) Map(point Point) (MappedPoint, bool) {
	mapped, status := r.MapWithStatus(point)
	return mapped, status == MappingMapped
}

// MapWithStatus maps one point and classifies why it was not emitted. An
// invalid value is returned only after exact source and key identity have been
// established, so its Series path is safe to use as a precise invalidation.
func (r *Registry) MapWithStatus(point Point) (MappedPoint, MappingStatus) {
	if r == nil {
		return MappedPoint{}, MappingUnmatched
	}
	source := SourcePath{PathTarget: point.Series.PathTarget, Origin: point.Series.Origin, Leaf: point.Series.Leaf, Elements: make([]string, len(point.Series.Elements))}
	for i, elem := range point.Series.Elements {
		source.Elements[i] = elem.Name
	}
	mapping, ok := r.mappings[sourcePathKey(source)]
	if !ok {
		return MappedPoint{}, MappingUnmatched
	}

	attributes := make(map[string]string, len(mapping.KeyAttributes))
	for _, attr := range mapping.KeyAttributes {
		found := false
		var value string
		for _, elem := range point.Series.Elements {
			if elem.Name != attr.Element {
				continue
			}
			candidate, exists := elem.Keys[attr.Key]
			if !exists {
				continue
			}
			if found {
				// Element names are not positional selectors. Refuse a point if
				// more than one same-named element carries the requested key;
				// choosing the first would collapse distinct source series.
				return MappedPoint{}, MappingInvalidIdentity
			}
			value = candidate
			found = true
		}
		if !found {
			return MappedPoint{}, MappingInvalidIdentity
		}
		attributes[attr.Attribute] = value
	}

	monotonicSum := mapping.MetricType == MetricSum && mapping.Monotonic
	if monotonicSum && !validMonotonicSumSource(point.Value) {
		return MappedPoint{}, MappingInvalidValue
	}
	// SourceBounds are attached only to modeled numeric leaves. Although gauges
	// can deliberately map boolean state to 0/1, accepting a boolean for a
	// bounded numeric leaf would silently turn a schema-invalid CPU or memory
	// sample into plausible telemetry.
	if mapping.SourceBounds != nil && point.Value.Kind == ValueBool {
		return MappedPoint{}, MappingInvalidValue
	}
	numeric, numericOK := numericValue(point.Value)
	if !numericOK {
		return MappedPoint{}, MappingInvalidValue
	}
	if mapping.SourceBounds != nil && (numeric < mapping.SourceBounds.Min || numeric > mapping.SourceBounds.Max) {
		return MappedPoint{}, MappingInvalidValue
	}

	mapped := MappedPoint{
		Source:     point.Series,
		Metric:     mapping.Metric,
		GaugeType:  mapping.GaugeType,
		MetricType: mapping.MetricType,
		Monotonic:  mapping.Monotonic,
		Attributes: attributes,
		Timestamp:  point.Timestamp,
	}
	switch mapping.GaugeType {
	case GaugeInt:
		scaled, ok := scaledIntValue(point.Value, mapping.Scale)
		if !ok || (monotonicSum && scaled < 0) {
			return MappedPoint{}, MappingInvalidValue
		}
		mapped.IntValue = scaled
	case GaugeDouble:
		scaled := numeric * mapping.Scale
		if math.IsNaN(scaled) || math.IsInf(scaled, 0) || (monotonicSum && scaled < 0) {
			return MappedPoint{}, MappingInvalidValue
		}
		mapped.DoubleValue = scaled
	default:
		return MappedPoint{}, MappingInvalidValue
	}
	return mapped, MappingMapped
}

// MappingStats summarizes explicit registry matching for one notification.
type MappingStats struct {
	Mapped   int
	Unmapped int
}

// MapNotification maps all eligible decoded leaves and prepares one atomic
// cache transaction while preserving canonical deletes and prefix semantics.
func (r *Registry) MapNotification(notification DecodedNotification) (CacheNotification, MappingStats) {
	out := CacheNotification{
		Prefix:    notification.Prefix.Clone(),
		Timestamp: notification.Timestamp,
		Atomic:    notification.Atomic,
		Touched:   make([]Path, len(notification.Touched)),
		Deletes:   make([]Path, len(notification.Deletes)),
	}
	for i, touched := range notification.Touched {
		out.Touched[i] = touched.Clone()
	}
	for i, deleted := range notification.Deletes {
		out.Deletes[i] = deleted.Clone()
	}
	stats := MappingStats{}
	semanticInvalid := false
	for i := range notification.Undecodable {
		series, err := notification.Undecodable[i].SplitLeaf()
		if err != nil {
			continue
		}
		_, status := r.MapWithStatus(Point{Series: series})
		if status != MappingUnmatched {
			stats.Unmapped++
		}
		switch status {
		case MappingInvalidValue:
			out.Invalidates = append(out.Invalidates, notification.Undecodable[i].Clone())
			semanticInvalid = true
		case MappingInvalidIdentity:
			semanticInvalid = true
		}
	}
	for i := range notification.Updates {
		mapped, status := r.MapWithStatus(notification.Updates[i])
		if status != MappingMapped {
			stats.Unmapped++
			if status == MappingInvalidValue {
				out.Invalidates = append(out.Invalidates, notification.Updates[i].Series.Path())
			}
			if status == MappingInvalidValue || status == MappingInvalidIdentity {
				semanticInvalid = true
			}
			continue
		}
		out.Updates = append(out.Updates, mapped)
		stats.Mapped++
	}
	if notification.Atomic && semanticInvalid {
		out = CacheNotification{
			Timestamp:   notification.Timestamp,
			Invalidates: []Path{notification.Prefix.Clone()},
		}
	}
	return out, stats
}

// MappedPoint is one fully specified OTLP gauge datapoint.
type MappedPoint struct {
	Source      Series
	Metric      MetricMetadata
	GaugeType   GaugeValueType
	MetricType  MetricType
	Monotonic   bool
	IntValue    int64
	DoubleValue float64
	Attributes  map[string]string
	Timestamp   time.Time
}

// Key returns the target metric-series identity used by the bounded cache.
func (p MappedPoint) Key() string {
	return p.Source.Target + "\x00" + p.Metric.Name + "\x00" + stableAttributesKey(p.Attributes)
}

// EqualValue reports whether two mapped values are identical.
func (p MappedPoint) EqualValue(other MappedPoint) bool {
	if p.GaugeType != other.GaugeType {
		return false
	}
	if p.GaugeType == GaugeInt {
		return p.IntValue == other.IntValue
	}
	return !math.IsNaN(p.DoubleValue) && p.DoubleValue == other.DoubleValue
}

func validateMapping(mapping Mapping) error {
	if len(mapping.Source.Elements) == 0 || strings.TrimSpace(mapping.Source.Leaf) == "" {
		return errors.New("mapping source must contain elements and a leaf")
	}
	if len(mapping.Source.Elements)+1 > maxPathDepth {
		return fmt.Errorf("mapping source exceeds %d path elements", maxPathDepth)
	}
	series := Series{
		PathTarget: mapping.Source.PathTarget,
		Origin:     mapping.Source.Origin,
		Elements:   make([]PathElem, len(mapping.Source.Elements)),
		Leaf:       mapping.Source.Leaf,
	}
	for _, elem := range mapping.Source.Elements {
		if strings.TrimSpace(elem) == "" {
			return errors.New("mapping source elements cannot be empty")
		}
	}
	for index, elem := range mapping.Source.Elements {
		series.Elements[index].Name = elem
	}
	if err := ValidateSeries(series); err != nil {
		return fmt.Errorf("mapping source is invalid: %w", err)
	}
	if !metricNamePattern.MatchString(mapping.Metric.Name) {
		return fmt.Errorf("invalid metric name %q", mapping.Metric.Name)
	}
	if len(mapping.Metric.Name) > maxCachedMetricNameBytes {
		return fmt.Errorf("metric name exceeds %d bytes", maxCachedMetricNameBytes)
	}
	if strings.TrimSpace(mapping.Metric.Description) == "" {
		return errors.New("metric description cannot be empty")
	}
	if len(mapping.Metric.Description) > maxCachedMetricDescriptionBytes {
		return fmt.Errorf("metric description exceeds %d bytes", maxCachedMetricDescriptionBytes)
	}
	if strings.TrimSpace(mapping.Metric.Unit) == "" {
		return errors.New("metric UCUM unit cannot be empty")
	}
	if len(mapping.Metric.Unit) > maxCachedMetricUnitBytes {
		return fmt.Errorf("metric unit exceeds %d bytes", maxCachedMetricUnitBytes)
	}
	metadataBytes := len(mapping.Metric.Name) + len(mapping.Metric.Description) + len(mapping.Metric.Unit)
	if metadataBytes > maxCachedMetricMetadataBytes {
		return fmt.Errorf("metric metadata exceeds %d bytes", maxCachedMetricMetadataBytes)
	}
	if mapping.Scale == 0 || math.IsNaN(mapping.Scale) || math.IsInf(mapping.Scale, 0) {
		return errors.New("mapping scale must be finite and non-zero")
	}
	if mapping.SourceBounds != nil {
		if math.IsNaN(mapping.SourceBounds.Min) || math.IsInf(mapping.SourceBounds.Min, 0) ||
			math.IsNaN(mapping.SourceBounds.Max) || math.IsInf(mapping.SourceBounds.Max, 0) {
			return errors.New("mapping source bounds must be finite")
		}
		if mapping.SourceBounds.Min > mapping.SourceBounds.Max {
			return errors.New("mapping source minimum cannot exceed maximum")
		}
	}
	if mapping.GaugeType != GaugeInt && mapping.GaugeType != GaugeDouble {
		return fmt.Errorf("gauge type must be %q or %q", GaugeInt, GaugeDouble)
	}
	if mapping.MetricType != MetricGauge && mapping.MetricType != MetricSum {
		return errors.New("metric type must be gauge or sum")
	}
	if mapping.MetricType == MetricGauge && mapping.Monotonic {
		return errors.New("gauge mappings cannot be monotonic")
	}
	if mapping.MetricType == MetricSum && mapping.Monotonic && mapping.Scale < 0 {
		return errors.New("monotonic sum mapping scale must be positive")
	}
	elements := make(map[string]struct{}, len(mapping.Source.Elements))
	for _, elem := range mapping.Source.Elements {
		elements[elem] = struct{}{}
	}
	attributes := map[string]struct{}{}
	if len(mapping.KeyAttributes) > maxCachedPointAttributes {
		return fmt.Errorf("mapping exceeds %d metric attributes", maxCachedPointAttributes)
	}
	for _, attr := range mapping.KeyAttributes {
		if _, ok := elements[attr.Element]; !ok {
			return fmt.Errorf("key attribute element %q is not in the source path", attr.Element)
		}
		if attr.Key == "" || attr.Attribute == "" {
			return errors.New("key attribute key and attribute cannot be empty")
		}
		if len(attr.Key) > maxPathNameBytes {
			return fmt.Errorf("key attribute key exceeds %d bytes", maxPathNameBytes)
		}
		if len(attr.Attribute) > maxPathNameBytes {
			return fmt.Errorf("metric attribute name exceeds %d bytes", maxPathNameBytes)
		}
		if _, duplicate := attributes[attr.Attribute]; duplicate {
			return fmt.Errorf("duplicate metric attribute %q", attr.Attribute)
		}
		attributes[attr.Attribute] = struct{}{}
	}
	return nil
}

// Key returns an unambiguous identity for an exact scalar source path. Every
// component is length-prefixed because protobuf strings may legally contain a
// NUL byte; delimiter concatenation could otherwise make a shorter,
// device-controlled path collide with a configured mapping.
func (p SourcePath) Key() string {
	var key strings.Builder
	appendKeyPart(&key, p.PathTarget)
	appendKeyPart(&key, p.Origin)
	for _, element := range p.Elements {
		appendKeyPart(&key, element)
	}
	appendKeyPart(&key, p.Leaf)
	return key.String()
}

func sourcePathKey(path SourcePath) string { return path.Key() }

func (p SourcePath) String() string {
	path := strings.Join(append(append([]string(nil), p.Elements...), p.Leaf), "/")
	if p.PathTarget == "" && p.Origin == "" {
		return path
	}
	return "target=" + p.PathTarget + " origin=" + p.Origin + " " + path
}

func numericValue(value Value) (float64, bool) {
	switch value.Kind {
	case ValueInt:
		return float64(value.Int), true
	case ValueUint:
		return float64(value.Uint), true
	case ValueDouble:
		return value.Double, !math.IsNaN(value.Double) && !math.IsInf(value.Double, 0)
	case ValueBool:
		if value.Bool {
			return 1, true
		}
		return 0, true
	case ValueString:
		text := strings.TrimSpace(value.String)
		if text == "" || text != value.String {
			return 0, false
		}
		if signed, err := strconv.ParseInt(text, 10, 64); err == nil {
			return float64(signed), true
		}
		if unsigned, err := strconv.ParseUint(text, 10, 64); err == nil {
			return float64(unsigned), true
		}
		double, err := strconv.ParseFloat(text, 64)
		if err != nil || math.IsNaN(double) || math.IsInf(double, 0) {
			return 0, false
		}
		return double, true
	default:
		return 0, false
	}
}

func validMonotonicSumSource(value Value) bool {
	switch value.Kind {
	case ValueInt:
		return value.Int >= 0
	case ValueUint:
		return true
	case ValueDouble:
		return !math.IsNaN(value.Double) && !math.IsInf(value.Double, 0) && value.Double >= 0
	case ValueString:
		// RFC 7951 represents uint64/counter64 leaves as strings. Require the
		// YANG unsigned-integer lexical form: an optional positive sign followed
		// by decimal digits. Leading zeroes are valid in an instance encoding;
		// float, exponent, negative-sign, and whitespace spellings are not.
		text := strings.TrimPrefix(value.String, "+")
		if text == "" {
			return false
		}
		for index := range len(text) {
			if text[index] < '0' || text[index] > '9' {
				return false
			}
		}
		_, err := strconv.ParseUint(text, 10, 64)
		return err == nil
	default:
		// In particular, boolean presence/state leaves are not counter samples.
		return false
	}
}

func scaledIntValue(value Value, scale float64) (int64, bool) {
	if scale == 1 {
		switch value.Kind {
		case ValueInt:
			return value.Int, true
		case ValueUint:
			if value.Uint <= math.MaxInt64 {
				return int64(value.Uint), true
			}
			return 0, false
		case ValueBool:
			if value.Bool {
				return 1, true
			}
			return 0, true
		case ValueString:
			if value.String != strings.TrimSpace(value.String) || value.String == "" {
				return 0, false
			}
			if signed, err := strconv.ParseInt(value.String, 10, 64); err == nil {
				return signed, true
			}
			if unsigned, err := strconv.ParseUint(value.String, 10, 64); err == nil && unsigned <= math.MaxInt64 {
				return int64(unsigned), true
			}
		}
	}
	numeric, ok := numericValue(value)
	if !ok {
		return 0, false
	}
	scaled := numeric * scale
	// float64 cannot represent MaxInt64: float64(MaxInt64) rounds to 2^63.
	// Reject that upper boundary before conversion, which would otherwise wrap
	// to MinInt64. Exact integral inputs at scale 1 use the fast path above.
	if math.IsNaN(scaled) || math.IsInf(scaled, 0) || scaled < math.MinInt64 || scaled >= float64(math.MaxInt64) || scaled != math.Trunc(scaled) {
		return 0, false
	}
	return int64(scaled), true
}
