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
	Origin   string
	Elements []string
	Leaf     string
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

// Mapping explicitly maps one numeric source leaf to one gauge metric.
type Mapping struct {
	Source        SourcePath
	Metric        MetricMetadata
	Scale         float64
	GaugeType     GaugeValueType
	MetricType    MetricType
	Monotonic     bool
	KeyAttributes []KeyAttribute
}

// Registry contains only validated, explicit source mappings.
type Registry struct {
	mappings map[string]Mapping
	metrics  map[string]metricContract
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
		mappings: make(map[string]Mapping, len(mappings)),
		metrics:  make(map[string]metricContract),
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
	mapping.Source.Elements = append([]string(nil), mapping.Source.Elements...)
	mapping.KeyAttributes = append([]KeyAttribute(nil), mapping.KeyAttributes...)
	r.mappings[key] = mapping
	r.metrics[mapping.Metric.Name] = contract
	return nil
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
	if r == nil {
		return MappedPoint{}, false
	}
	source := SourcePath{Origin: point.Series.Origin, Leaf: point.Series.Leaf, Elements: make([]string, len(point.Series.Elements))}
	for i, elem := range point.Series.Elements {
		source.Elements[i] = elem.Name
	}
	mapping, ok := r.mappings[sourcePathKey(source)]
	if !ok {
		return MappedPoint{}, false
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
				return MappedPoint{}, false
			}
			value = candidate
			found = true
		}
		if !found {
			return MappedPoint{}, false
		}
		attributes[attr.Attribute] = value
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
		if !ok {
			return MappedPoint{}, false
		}
		mapped.IntValue = scaled
	case GaugeDouble:
		numeric, ok := numericValue(point.Value)
		if !ok {
			return MappedPoint{}, false
		}
		scaled := numeric * mapping.Scale
		if math.IsNaN(scaled) || math.IsInf(scaled, 0) {
			return MappedPoint{}, false
		}
		mapped.DoubleValue = scaled
	default:
		return MappedPoint{}, false
	}
	return mapped, true
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
	for i := range notification.Updates {
		mapped, ok := r.Map(notification.Updates[i])
		if !ok {
			stats.Unmapped++
			continue
		}
		out.Updates = append(out.Updates, mapped)
		stats.Mapped++
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
	for _, elem := range mapping.Source.Elements {
		if strings.TrimSpace(elem) == "" {
			return errors.New("mapping source elements cannot be empty")
		}
	}
	if !metricNamePattern.MatchString(mapping.Metric.Name) {
		return fmt.Errorf("invalid metric name %q", mapping.Metric.Name)
	}
	if strings.TrimSpace(mapping.Metric.Description) == "" {
		return errors.New("metric description cannot be empty")
	}
	if strings.TrimSpace(mapping.Metric.Unit) == "" {
		return errors.New("metric UCUM unit cannot be empty")
	}
	if mapping.Scale == 0 || math.IsNaN(mapping.Scale) || math.IsInf(mapping.Scale, 0) {
		return errors.New("mapping scale must be finite and non-zero")
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
	elements := make(map[string]struct{}, len(mapping.Source.Elements))
	for _, elem := range mapping.Source.Elements {
		elements[elem] = struct{}{}
	}
	attributes := map[string]struct{}{}
	for _, attr := range mapping.KeyAttributes {
		if _, ok := elements[attr.Element]; !ok {
			return fmt.Errorf("key attribute element %q is not in the source path", attr.Element)
		}
		if attr.Key == "" || attr.Attribute == "" {
			return errors.New("key attribute key and attribute cannot be empty")
		}
		if _, duplicate := attributes[attr.Attribute]; duplicate {
			return fmt.Errorf("duplicate metric attribute %q", attr.Attribute)
		}
		attributes[attr.Attribute] = struct{}{}
	}
	return nil
}

func sourcePathKey(path SourcePath) string {
	return path.Origin + "\x00" + strings.Join(path.Elements, "\x00") + "\x00" + path.Leaf
}

func (p SourcePath) String() string {
	path := strings.Join(append(append([]string(nil), p.Elements...), p.Leaf), "/")
	if p.Origin == "" {
		return path
	}
	return p.Origin + " " + path
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
