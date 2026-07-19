// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"math"
	"strconv"
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

const (
	directGNMIDefaultMaxDatapoints       = 50_000
	directGNMIHardMaxDatapoints          = 100_000
	directGNMIHardMaxFields              = 200_000
	directGNMIHardMaxDepth               = 128
	directGNMIHardMaxMetricNameBytes     = 1024
	directGNMIHardMaxAttributesPerPoint  = 64
	directGNMIHardMaxAttributeKeyBytes   = 256
	directGNMIHardMaxAttributeValueBytes = 4 * 1024
	directGNMIHardMaxAttributeBytes      = 32 * 1024 * 1024
	directGNMIHardMaxPayloadBytes        = 4 * 1024 * 1024
)

func directGNMITimestamp(raw int64, receipt time.Time) pcommon.Timestamp {
	normalized, _ := internalgnmi.NormalizeTimestamp(raw, receipt)
	return pcommon.NewTimestampFromTime(normalized)
}

func resolveDirectGNMIUpdateValue(update *gnmi.Update, budget *directGNMIDecodeBudget) (*gnmi.TypedValue, bool) {
	value, err := internalgnmi.ResolveUpdateValue(update)
	if err == nil {
		return value, true
	}
	budget.addDecodeError()
	budget.drop(false)
	return nil, false
}

// directGNMIDecodeLimits are non-configurable production ceilings. Tests may
// lower an individual value to exercise rejection without constructing a huge
// notification. A configured datapoint limit is still honored when it is
// lower than the hard ceiling.
type directGNMIDecodeLimits struct {
	maxDatapoints          int
	maxFields              int
	maxDepth               int
	maxMetricNameBytes     int
	maxAttributes          int
	maxAttributeKeyBytes   int
	maxAttributeValueBytes int
	maxAttributeBytes      int
}

func (l directGNMIDecodeLimits) withDefaults(configuredMaxDatapoints int) directGNMIDecodeLimits {
	if configuredMaxDatapoints <= 0 {
		configuredMaxDatapoints = directGNMIDefaultMaxDatapoints
	}
	if configuredMaxDatapoints > directGNMIHardMaxDatapoints {
		configuredMaxDatapoints = directGNMIHardMaxDatapoints
	}
	if l.maxDatapoints <= 0 || l.maxDatapoints > configuredMaxDatapoints {
		l.maxDatapoints = configuredMaxDatapoints
	}
	if l.maxFields <= 0 {
		l.maxFields = directGNMIHardMaxFields
	}
	if l.maxDepth <= 0 {
		l.maxDepth = directGNMIHardMaxDepth
	}
	if l.maxMetricNameBytes <= 0 {
		l.maxMetricNameBytes = directGNMIHardMaxMetricNameBytes
	}
	if l.maxAttributes <= 0 {
		l.maxAttributes = directGNMIHardMaxAttributesPerPoint
	}
	if l.maxAttributeKeyBytes <= 0 {
		l.maxAttributeKeyBytes = directGNMIHardMaxAttributeKeyBytes
	}
	if l.maxAttributeValueBytes <= 0 {
		l.maxAttributeValueBytes = directGNMIHardMaxAttributeValueBytes
	}
	if l.maxAttributeBytes <= 0 {
		l.maxAttributeBytes = directGNMIHardMaxAttributeBytes
	}
	return l
}

type directGNMIDecodeBudget struct {
	limits         directGNMIDecodeLimits
	fields         int
	datapoints     int
	attributeBytes int
	dropped        int64
	decodeErrors   int64
	exhausted      bool
}

func newDirectGNMIDecodeBudget(limits directGNMIDecodeLimits, configuredMaxDatapoints int) *directGNMIDecodeBudget {
	return &directGNMIDecodeBudget{limits: limits.withDefaults(configuredMaxDatapoints)}
}

func (b *directGNMIDecodeBudget) visitField(depth int) bool {
	if b.exhausted {
		return false
	}
	if depth > b.limits.maxDepth {
		b.drop(true)
		return false
	}
	b.fields++
	if b.fields > b.limits.maxFields {
		b.drop(true)
		return false
	}
	return true
}

func (b *directGNMIDecodeBudget) ensureChildFieldCapacity(count, depth int) bool {
	if b.exhausted {
		return false
	}
	if count == 0 {
		return true
	}
	if depth > b.limits.maxDepth || count > b.limits.maxFields-b.fields {
		b.drop(true)
		return false
	}
	return true
}

func (b *directGNMIDecodeBudget) consumeChildFields(count, depth int) bool {
	if !b.ensureChildFieldCapacity(count, depth) {
		return false
	}
	b.fields += count
	return true
}

func (b *directGNMIDecodeBudget) addDecodeError() {
	b.decodeErrors++
}

func (b *directGNMIDecodeBudget) drop(exhaust bool) {
	b.dropped++
	if exhaust {
		b.exhausted = true
	}
}

func (b *directGNMIDecodeBudget) reserveDatapoint(name string, attrs map[string]string, extraKey, extraValue string) bool {
	if b.exhausted {
		return false
	}
	if b.datapoints >= b.limits.maxDatapoints {
		b.drop(true)
		return false
	}
	if name == "" || len(name) > b.limits.maxMetricNameBytes {
		b.drop(false)
		return false
	}

	attributeCount := 0
	attributeBytes := 0
	for key, value := range attrs {
		if (value == "" && !isDirectGNMIIdentityAttribute(key)) || (extraKey != "" && key == extraKey) {
			continue
		}
		if !b.validAttribute(key, value) {
			b.drop(false)
			return false
		}
		attributeCount++
		attributeBytes += len(key) + len(value)
	}
	if extraKey != "" {
		if !b.validAttribute(extraKey, extraValue) {
			b.drop(false)
			return false
		}
		attributeCount++
		attributeBytes += len(extraKey) + len(extraValue)
	}
	if attributeCount > b.limits.maxAttributes {
		b.drop(false)
		return false
	}
	if attributeBytes > b.limits.maxAttributeBytes-b.attributeBytes {
		b.drop(true)
		return false
	}

	b.datapoints++
	b.attributeBytes += attributeBytes
	return true
}

func (b *directGNMIDecodeBudget) allowMetricName(base, module string, parts []string, suffix string) bool {
	if b.exhausted {
		return false
	}
	remaining := b.limits.maxMetricNameBytes - len(base) - len(suffix)
	consume := func(value string) bool {
		if value == "" {
			return true
		}
		needed := len(value) + 1 // separator
		if needed > remaining {
			b.drop(false)
			return false
		}
		remaining -= needed
		return true
	}
	if remaining < 0 {
		b.drop(false)
		return false
	}
	if !consume(module) {
		return false
	}
	for _, part := range parts {
		if !consume(part) {
			return false
		}
	}
	return true
}

func (b *directGNMIDecodeBudget) validAttribute(key, value string) bool {
	return key != "" && len(key) <= b.limits.maxAttributeKeyBytes && len(value) <= b.limits.maxAttributeValueBytes
}

func (b *directGNMIDecodeBudget) validInfoValue(value string) bool {
	if len(value) > b.limits.maxAttributeValueBytes {
		b.drop(false)
		return false
	}
	return true
}

func (b *directGNMIDecodeBudget) validNumber(value metricNumber) bool {
	if value.isInt {
		return true
	}
	if math.IsNaN(value.doubleValue) || math.IsInf(value.doubleValue, 0) {
		b.addDecodeError()
		b.drop(false)
		return false
	}
	return true
}

type indexedMetricBuilder struct {
	scope       pmetric.ScopeMetrics
	streams     map[metricStreamIdentity]pmetric.Metric
	budget      *directGNMIDecodeBudget
	finalBudget *finalDatapointBudget
}

func newIndexedMetricBuilder(scope pmetric.ScopeMetrics, budget *directGNMIDecodeBudget) *indexedMetricBuilder {
	streams := make(map[metricStreamIdentity]pmetric.Metric, scope.Metrics().Len())
	metrics := scope.Metrics()
	for i := 0; i < metrics.Len(); i++ {
		metric := metrics.At(i)
		identity := metricStreamIdentityFromMetric(metric)
		if _, exists := streams[identity]; !exists {
			streams[identity] = metric
		}
	}
	return &indexedMetricBuilder{scope: scope, streams: streams, budget: budget}
}

func newFinalIndexedMetricBuilder(scope pmetric.ScopeMetrics, budget *finalDatapointBudget) *indexedMetricBuilder {
	builder := newIndexedMetricBuilder(scope, nil)
	builder.finalBudget = budget
	return builder
}

func (b *indexedMetricBuilder) getOrCreateWithMetadata(name string, metricType pmetric.MetricType, unit, description string) pmetric.Metric {
	identity := metricStreamIdentity{name: name, metricType: metricType, unit: unit, description: description}
	if metricType == pmetric.MetricTypeSum {
		identity.aggregationTemporality = pmetric.AggregationTemporalityCumulative
		identity.monotonic = true
	}
	if metric, ok := b.streams[identity]; ok {
		return metric
	}
	metric := b.scope.Metrics().AppendEmpty()
	metric.SetName(name)
	metric.SetUnit(unit)
	metric.SetDescription(description)
	switch metricType {
	case pmetric.MetricTypeGauge:
		metric.SetEmptyGauge()
	case pmetric.MetricTypeSum:
		sum := metric.SetEmptySum()
		sum.SetIsMonotonic(true)
		sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	}
	b.streams[identity] = metric
	return metric
}

func (b *indexedMetricBuilder) appendNumber(name string, metricType pmetric.MetricType, value metricNumber, ts pcommon.Timestamp, attrs map[string]string) bool {
	return b.appendNumberWithUnit(name, metricType, value, ts, attrs, "")
}

func (b *indexedMetricBuilder) appendNumberWithUnit(name string, metricType pmetric.MetricType, value metricNumber, ts pcommon.Timestamp, attrs map[string]string, unit string) bool {
	if b.budget != nil {
		if !b.budget.validNumber(value) || !b.budget.reserveDatapoint(name, attrs, "", "") {
			return false
		}
	}
	if b.finalBudget != nil && !b.finalBudget.reserveAliasStringDatapoint(attrs, "", "") {
		return false
	}
	valueType := fixedMetricValueTypeDouble
	if value.isInt {
		valueType = fixedMetricValueTypeInt
	}
	description, unit := governedFixedMetricMetadata(name, metricType, valueType, "", unit)
	metric := b.getOrCreateWithMetadata(name, metricType, unit, description)
	var dp pmetric.NumberDataPoint
	if metricType == pmetric.MetricTypeSum {
		dp = metric.Sum().DataPoints().AppendEmpty()
	} else {
		dp = metric.Gauge().DataPoints().AppendEmpty()
	}
	value.set(dp)
	dp.SetTimestamp(ts)
	applyStringAttrsWithEmpty(dp.Attributes(), attrs, b.finalBudget != nil)
	return true
}

func (b *indexedMetricBuilder) appendInfo(name, value string, ts pcommon.Timestamp, attrs map[string]string) bool {
	attrs = escapeReservedInfoAttribute(attrs, "value")
	if b.budget != nil {
		if !b.budget.validInfoValue(value) || !b.budget.reserveDatapoint(name, attrs, "value", value) {
			return false
		}
	}
	if b.finalBudget != nil {
		if !b.finalBudget.reserveAliasStringDatapoint(attrs, "value", value) {
			return false
		}
	}
	description, unit := governedFixedMetricMetadata(name, pmetric.MetricTypeGauge, fixedMetricValueTypeDouble, "", "")
	metric := b.getOrCreateWithMetadata(name, pmetric.MetricTypeGauge, unit, description)
	dp := metric.Gauge().DataPoints().AppendEmpty()
	dp.SetDoubleValue(1)
	dp.SetTimestamp(ts)
	applyStringAttrsWithEmpty(dp.Attributes(), attrs, b.finalBudget != nil)
	// The decoded leaf value is the semantic value of an info metric. A path
	// key named "value" is contextual input and must not overwrite it.
	dp.Attributes().PutStr("value", value)
	return true
}

func escapeReservedInfoAttribute(attrs map[string]string, reservedKey string) map[string]string {
	contextValue, exists := attrs[reservedKey]
	if !exists || contextValue == "" {
		return attrs
	}
	escaped := cloneAttrs(attrs)
	delete(escaped, reservedKey)
	for index := 1; index <= len(attrs)+1; index++ {
		candidate := "cisco.key." + reservedKey
		if index > 1 {
			candidate = "cisco.key." + strconv.Itoa(index) + "." + reservedKey
		}
		if existing, candidateExists := escaped[candidate]; candidateExists {
			if existing == contextValue {
				return escaped
			}
			continue
		}
		escaped[candidate] = contextValue
		return escaped
	}
	return escaped
}
