// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"math"
	"strconv"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

type dynamicYANGMetricVariant uint8

const (
	dynamicYANGMetricVariantUnknown dynamicYANGMetricVariant = iota
	dynamicYANGMetricVariantNumber
	dynamicYANGMetricVariantInfo
)

// dynamicYANGPath keeps schema identity separate from the normalized path used
// for counter classification and Catalyst aliases. identity contains the raw,
// ordered schema segments and is the only path representation encoded into a
// dynamic metric name. normalized deliberately retains the receiver's legacy
// semantic projection and must never be used as metric identity.
type dynamicYANGPath struct {
	identity   []string
	normalized []string
}

type dialOutDynamicYANGPath struct {
	encodingIdentity []string
	sourceIdentity   []string
	normalized       []string
	aliases          []string
}

func (p dynamicYANGPath) child(identity, normalized string) dynamicYANGPath {
	return dynamicYANGPath{
		identity:   append(append([]string(nil), p.identity...), identity),
		normalized: append(append([]string(nil), p.normalized...), normalized),
	}
}

// dynamicYANGMetricName encodes the schema tuple, never list-key or target
// identity. The suffix after the product namespace has this grammar:
//
//	__v1 (m0 | m1 <segment>) p<count> <segment>... (n | i)
//
// Each token is dot-delimited. A segment is s<raw-byte-count>_<escaped-raw>,
// where ASCII letters and digits are literal and every other byte is _HH.
// Since literal underscores and dots are escaped, the representation is
// reversible and its module/path boundaries are unambiguous. The explicit
// module-presence and variant frames prevent the module/path and numeric/info
// collisions that a joined sanitized name cannot prevent.
func dynamicYANGMetricName(prefix, module string, pathParts []string, variant dynamicYANGMetricVariant, maximum int) (string, bool) {
	if maximum <= 0 || len(pathParts) == 0 || (variant != dynamicYANGMetricVariantNumber && variant != dynamicYANGMetricVariantInfo) {
		return "", false
	}
	builder := boundedMetricNameBuilder{maximum: maximum}
	if !writeDynamicYANGNameHeader(&builder, prefix, module) || !writeDynamicYANGSegmentFrame(&builder, "p", pathParts) || !writeDynamicYANGVariant(&builder, variant) {
		return "", false
	}
	return builder.String(), true
}

// dynamicYANGDialOutMetricName additionally frames raw encoding-path presence
// and the boundary between encoding-path containers and GPB-KV source-path
// segments. Its grammar after the common module frame is:
//
//	(e0 | e1 e<count> <segment>...) p<count> <segment>... (n | i)
//
// e0 represents an absent or explicitly empty encoding path. e1 represents a
// present nonempty path. Separate counts make the two raw segment sequences an
// injective tuple rather than an ambiguous concatenation.
func dynamicYANGDialOutMetricName(prefix, module string, encodingParts, sourceParts []string, variant dynamicYANGMetricVariant, maximum int) (string, bool) {
	if maximum <= 0 || len(sourceParts) == 0 || (variant != dynamicYANGMetricVariantNumber && variant != dynamicYANGMetricVariantInfo) {
		return "", false
	}
	builder := boundedMetricNameBuilder{maximum: maximum}
	if !writeDynamicYANGNameHeader(&builder, prefix, module) {
		return "", false
	}
	if len(encodingParts) == 0 {
		if !builder.write(".e0") {
			return "", false
		}
	} else if !builder.write(".e1") || !writeDynamicYANGSegmentFrame(&builder, "e", encodingParts) {
		return "", false
	}
	if !writeDynamicYANGSegmentFrame(&builder, "p", sourceParts) || !writeDynamicYANGVariant(&builder, variant) {
		return "", false
	}
	return builder.String(), true
}

func writeDynamicYANGNameHeader(builder *boundedMetricNameBuilder, prefix, module string) bool {
	if !builder.write(prefix) || !builder.write(".__v1") {
		return false
	}
	if module == "" {
		if !builder.write(".m0") {
			return false
		}
	} else {
		if !builder.write(".m1") || !builder.writeDynamicYANGSegment(module) {
			return false
		}
	}
	return true
}

func writeDynamicYANGSegmentFrame(builder *boundedMetricNameBuilder, marker string, parts []string) bool {
	if len(parts) == 0 || !builder.write(".") || !builder.write(marker) || !builder.write(strconv.Itoa(len(parts))) {
		return false
	}
	for _, part := range parts {
		if part == "" || !builder.writeDynamicYANGSegment(part) {
			return false
		}
	}
	return true
}

func writeDynamicYANGVariant(builder *boundedMetricNameBuilder, variant dynamicYANGMetricVariant) bool {
	if variant == dynamicYANGMetricVariantInfo {
		if !builder.write(".i") {
			return false
		}
	} else if !builder.write(".n") {
		return false
	}
	return true
}

func (b *indexedMetricBuilder) dynamicYANGMetricNameLimit() int {
	if b.budget != nil {
		return b.budget.limits.maxMetricNameBytes
	}
	if b.finalBudget != nil {
		return b.finalBudget.limits.maxMetricNameBytes
	}
	return directGNMIHardMaxMetricNameBytes
}

type boundedMetricNameBuilder struct {
	strings.Builder
	maximum int
}

func (b *boundedMetricNameBuilder) write(value string) bool {
	if len(value) > b.maximum-b.Len() {
		return false
	}
	b.WriteString(value)
	return true
}

func (b *boundedMetricNameBuilder) writeDynamicYANGSegment(value string) bool {
	if !b.write(".s") || !b.write(strconv.Itoa(len(value))) || !b.write("_") {
		return false
	}
	const hex = "0123456789ABCDEF"
	for index := 0; index < len(value); index++ {
		current := value[index]
		if current >= 'A' && current <= 'Z' || current >= 'a' && current <= 'z' || current >= '0' && current <= '9' {
			if b.Len() >= b.maximum {
				return false
			}
			b.WriteByte(current)
			continue
		}
		if b.maximum-b.Len() < 3 {
			return false
		}
		b.WriteByte('_')
		b.WriteByte(hex[current>>4])
		b.WriteByte(hex[current&0x0f])
	}
	return true
}

// canonicalDynamicYANGNumber makes the output representation a pure function
// of the instrument contract. Gauges use doubles and cumulative sums use
// int64. Exact cross-representation values are accepted; fractional counters
// and integers that cannot be represented exactly as float64 are rejected.
func canonicalDynamicYANGNumber(metricType pmetric.MetricType, value metricNumber) (metricNumber, bool) {
	switch metricType {
	case pmetric.MetricTypeGauge:
		if !value.isInt {
			if math.IsNaN(value.doubleValue) || math.IsInf(value.doubleValue, 0) {
				return metricNumber{}, false
			}
			return value, true
		}
		converted := float64(value.intValue)
		// Converting a positive float64 at 2^63 back to int64 is out of
		// range. Guard that edge explicitly before using the round trip to
		// accept every exactly representable int64 (not only the contiguous
		// exact range through 2^53).
		if (value.intValue > 0 && converted >= math.Ldexp(1, 63)) || int64(converted) != value.intValue {
			return metricNumber{}, false
		}
		return doubleMetricNumber(converted), true
	case pmetric.MetricTypeSum:
		if value.isInt {
			return value, true
		}
		candidate := value.doubleValue
		if math.IsNaN(candidate) || math.IsInf(candidate, 0) || math.Trunc(candidate) != candidate ||
			candidate < float64(math.MinInt64) || candidate >= -float64(math.MinInt64) {
			return metricNumber{}, false
		}
		integer := int64(candidate)
		if float64(integer) != candidate {
			return metricNumber{}, false
		}
		return intMetricNumber(integer), true
	default:
		return metricNumber{}, false
	}
}

func enforceDynamicYANGNumberContract(metric pmetric.Metric, expected pmetric.MetricType, budget *finalDatapointBudget) bool {
	if expected == pmetric.MetricTypeSum && metric.Type() == pmetric.MetricTypeGauge {
		// The generic yang_grpc receiver has no schema type when no YANG parser
		// is configured and emits numeric leaves as Gauge carriers. Preserve
		// that established parser-less path by promoting the raw points only
		// after deterministic path classification identifies a counter.
		points := pmetric.NewNumberDataPointSlice()
		metric.Gauge().DataPoints().MoveAndAppendTo(points)
		sum := metric.SetEmptySum()
		sum.SetIsMonotonic(true)
		sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
		points.MoveAndAppendTo(sum.DataPoints())
	}
	if metric.Type() != expected || expected == pmetric.MetricTypeSum &&
		(!metric.Sum().IsMonotonic() || metric.Sum().AggregationTemporality() != pmetric.AggregationTemporalityCumulative) {
		dropDynamicYANGMetric(metric, budget)
		return false
	}
	metric.SetDescription("")
	metric.SetUnit("")
	var points pmetric.NumberDataPointSlice
	if expected == pmetric.MetricTypeSum {
		points = metric.Sum().DataPoints()
	} else {
		points = metric.Gauge().DataPoints()
	}
	points.RemoveIf(func(point pmetric.NumberDataPoint) bool {
		var value metricNumber
		switch point.ValueType() {
		case pmetric.NumberDataPointValueTypeInt:
			value = intMetricNumber(point.IntValue())
		case pmetric.NumberDataPointValueTypeDouble:
			value = doubleMetricNumber(point.DoubleValue())
		default:
			budget.dropped++
			return true
		}
		canonical, ok := canonicalDynamicYANGNumber(expected, value)
		if !ok {
			budget.dropped++
			return true
		}
		canonical.set(point)
		return false
	})
	return points.Len() > 0
}

func enforceDynamicYANGInfoContract(metric pmetric.Metric, budget *finalDatapointBudget) bool {
	if !dynamicYANGMetricIsInfoVariant(metric) {
		dropDynamicYANGMetric(metric, budget)
		return false
	}
	metric.SetDescription("")
	metric.SetUnit("")
	return true
}

// enforceDialInDynamicYANGContract validates the canonical representation
// produced by the direct decoder before the normalizer treats the versioned
// namespace as trusted. The terminal variant frame is authoritative; direct
// numeric streams retain their decoder-selected Gauge or Sum instrument, but
// must still satisfy its deterministic representation and Sum semantics.
func enforceDialInDynamicYANGContract(metric pmetric.Metric, budget *finalDatapointBudget) bool {
	switch {
	case strings.HasSuffix(metric.Name(), ".i"):
		return enforceDynamicYANGInfoContract(metric, budget)
	case !strings.HasSuffix(metric.Name(), ".n"):
		dropDynamicYANGMetric(metric, budget)
		return false
	}
	switch metric.Type() {
	case pmetric.MetricTypeGauge, pmetric.MetricTypeSum:
		return enforceDynamicYANGNumberContract(metric, metric.Type(), budget)
	default:
		dropDynamicYANGMetric(metric, budget)
		return false
	}
}

func dropDynamicYANGMetric(metric pmetric.Metric, budget *finalDatapointBudget) {
	budget.dropped += int64(metricDatapointCount(metric))
	metric.SetEmptyGauge()
}

func dialOutDynamicYANGPathParts(metric pmetric.Metric, originalName, encodingPath string, info bool) (dialOutDynamicYANGPath, bool) {
	sourcePath, ok := oneDynamicYANGSourcePath(metric)
	if !ok {
		return dialOutDynamicYANGPath{}, false
	}
	sourceParts, ok := decodeDynamicYANGSourcePath(sourcePath)
	if !ok {
		return dialOutDynamicYANGPath{}, false
	}
	encodingIdentity, encodingNormalized, ok := dynamicYANGEncodingPathParts(encodingPath)
	if !ok {
		return dialOutDynamicYANGPath{}, false
	}
	flattened := strings.TrimPrefix(originalName, "cisco.")
	if info {
		var found bool
		flattened, found = strings.CutSuffix(flattened, "_info")
		if !found {
			return dialOutDynamicYANGPath{}, false
		}
	}
	legacySourceParts := sourceParts
	legacyMatches := strings.Join(legacySourceParts, ".") == flattened
	if !legacyMatches && len(sourceParts) > 1 && sourceParts[0] == "content" {
		legacySourceParts = sourceParts[1:]
		legacyMatches = strings.Join(legacySourceParts, ".") == flattened
	}
	if !legacyMatches {
		return dialOutDynamicYANGPath{}, false
	}
	// The generic YANG receiver treats a root GPB-KV content wrapper as
	// transparent only in its legacy flattened metric name. Keep that segment,
	// every raw encoding-path container, and any encoding-path module prefix in
	// the reversible schema identity. In particular, a separately supplied
	// cisco.yang.module value cannot make two conflicting qualified encoding
	// paths converge because the raw qualifier is still in the separately
	// framed encoding-path identity.
	normalizedSource := make([]string, 0, len(legacySourceParts))
	for _, raw := range legacySourceParts {
		_, local := splitYANGQualifiedName("", raw)
		if local == "" {
			return dialOutDynamicYANGPath{}, false
		}
		normalizedSource = append(normalizedSource, local)
	}
	normalized := make([]string, 0, len(encodingNormalized)+len(normalizedSource))
	normalized = append(normalized, encodingNormalized...)
	normalized = append(normalized, normalizedSource...)
	// Aliases retain their historical relative, transparent-content projection;
	// they are fixed governed streams and are not dynamic schema identity.
	return dialOutDynamicYANGPath{
		encodingIdentity: encodingIdentity,
		sourceIdentity:   sourceParts,
		normalized:       normalized,
		aliases:          normalizedSource,
	}, true
}

func dynamicYANGEncodingPathParts(value string) ([]string, []string, bool) {
	trimmed := strings.TrimSpace(value)
	if strings.Trim(trimmed, "/") == "" {
		return nil, nil, true
	}
	// Nonempty encoding paths use a canonical slash-delimited form. Reject
	// surrounding whitespace or slashes instead of silently erasing schema
	// identity bytes. Empty/absent path spellings remain the deliberate e0
	// equivalence class.
	if value != trimmed || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return nil, nil, false
	}
	identity := strings.Split(value, "/")
	normalized := make([]string, 0, len(identity))
	for _, part := range identity {
		if part == "" {
			return nil, nil, false
		}
		_, local := splitYANGQualifiedName("", part)
		if local == "" {
			return nil, nil, false
		}
		normalized = append(normalized, local)
	}
	return identity, normalized, true
}

func oneDynamicYANGSourcePath(metric pmetric.Metric) (string, bool) {
	value := ""
	found := false
	valid := true
	visit := func(attrs pcommon.Map) {
		if !valid {
			return
		}
		attribute, ok := attrs.Get("cisco.yang.source_path")
		if !ok || attribute.Type() != pcommon.ValueTypeStr || attribute.Str() == "" {
			valid = false
			return
		}
		if !found {
			value = attribute.Str()
			found = true
			return
		}
		valid = value == attribute.Str()
	}
	switch metric.Type() {
	case pmetric.MetricTypeGauge:
		points := metric.Gauge().DataPoints()
		for index := 0; index < points.Len(); index++ {
			visit(points.At(index).Attributes())
		}
	case pmetric.MetricTypeSum:
		points := metric.Sum().DataPoints()
		for index := 0; index < points.Len(); index++ {
			visit(points.At(index).Attributes())
		}
	case pmetric.MetricTypeHistogram:
		points := metric.Histogram().DataPoints()
		for index := 0; index < points.Len(); index++ {
			visit(points.At(index).Attributes())
		}
	case pmetric.MetricTypeExponentialHistogram:
		points := metric.ExponentialHistogram().DataPoints()
		for index := 0; index < points.Len(); index++ {
			visit(points.At(index).Attributes())
		}
	case pmetric.MetricTypeSummary:
		points := metric.Summary().DataPoints()
		for index := 0; index < points.Len(); index++ {
			visit(points.At(index).Attributes())
		}
	default:
		return "", false
	}
	return value, found && valid
}

func decodeDynamicYANGSourcePath(value string) ([]string, bool) {
	rawParts := strings.Split(value, "/")
	parts := make([]string, 0, len(rawParts))
	for _, raw := range rawParts {
		if raw == "" {
			return nil, false
		}
		var part strings.Builder
		part.Grow(len(raw))
		for index := 0; index < len(raw); index++ {
			if raw[index] != '~' {
				part.WriteByte(raw[index])
				continue
			}
			if index+1 >= len(raw) {
				return nil, false
			}
			index++
			switch raw[index] {
			case '0':
				part.WriteByte('~')
			case '1':
				part.WriteByte('/')
			default:
				return nil, false
			}
		}
		parts = append(parts, part.String())
	}
	return parts, len(parts) > 0
}
