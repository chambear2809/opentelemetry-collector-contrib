// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

const (
	iosXRTelemetryTransportDialIn  = "gnmi_dial_in"
	iosXRTelemetryTransportDialOut = "mdt_grpc_dial_out"
)

var metricNameCleaner = regexp.MustCompile(`[^A-Za-z0-9_]+`)

type iosXRHealth struct {
	mu sync.Mutex

	activeSubscriptions int64
	updatesReceived     int64
	decodeErrors        int64
	unsupportedPaths    int64
	reconnects          int64
	droppedDatapoints   int64
	compactGPBPayloads  int64
	lastSuccess         time.Time
	targets             map[string]iosXRTargetHealth
}

type iosXRTargetHealth struct {
	active          bool
	updatesReceived int64
	reconnects      int64
	lastSuccess     time.Time
}

func (h *iosXRHealth) setTargetSubscriptionActive(target string, active bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.targets == nil {
		h.targets = make(map[string]iosXRTargetHealth)
	}
	state := h.targets[target]
	if state.active == active {
		h.targets[target] = state
		return false
	}
	state.active = active
	h.targets[target] = state
	if active {
		h.activeSubscriptions = saturatingAddNonNegative(h.activeSubscriptions, 1)
	} else if h.activeSubscriptions > 0 {
		h.activeSubscriptions--
	}
	return true
}

func (h *iosXRHealth) addTargetUpdates(target string, value int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.updatesReceived = saturatingAddNonNegative(h.updatesReceived, value)
	now := time.Now()
	h.lastSuccess = now
	if target != "" {
		if h.targets == nil {
			h.targets = make(map[string]iosXRTargetHealth)
		}
		state := h.targets[target]
		state.updatesReceived = saturatingAddNonNegative(state.updatesReceived, value)
		state.lastSuccess = now
		h.targets[target] = state
	}
}

func (h *iosXRHealth) addDecodeErrors(value int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.decodeErrors = saturatingAddNonNegative(h.decodeErrors, value)
}

func (h *iosXRHealth) addUnsupportedPaths(value int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.unsupportedPaths = saturatingAddNonNegative(h.unsupportedPaths, value)
}

func (h *iosXRHealth) addTargetReconnects(target string, value int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reconnects = saturatingAddNonNegative(h.reconnects, value)
	if target != "" {
		if h.targets == nil {
			h.targets = make(map[string]iosXRTargetHealth)
		}
		state := h.targets[target]
		state.reconnects = saturatingAddNonNegative(state.reconnects, value)
		h.targets[target] = state
	}
}

func (h *iosXRHealth) addDroppedDatapoints(value int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.droppedDatapoints = saturatingAddNonNegative(h.droppedDatapoints, value)
}

func (h *iosXRHealth) addCompactGPBPayloads(value int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.compactGPBPayloads = saturatingAddNonNegative(h.compactGPBPayloads, value)
}

func saturatingAddNonNegative(current, value int64) int64 {
	if current < 0 {
		current = 0
	}
	if value <= 0 {
		return current
	}
	if current > math.MaxInt64-value {
		return math.MaxInt64
	}
	return current + value
}

func (h *iosXRHealth) snapshot() iosXRHealthSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.snapshotLocked("")
}

func (h *iosXRHealth) snapshotForTarget(target string) iosXRHealthSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.snapshotLocked(target)
}

func (h *iosXRHealth) snapshotLocked(target string) iosXRHealthSnapshot {
	snapshot := iosXRHealthSnapshot{
		activeSubscriptions: h.activeSubscriptions,
		updatesReceived:     h.updatesReceived,
		decodeErrors:        h.decodeErrors,
		unsupportedPaths:    h.unsupportedPaths,
		reconnects:          h.reconnects,
		droppedDatapoints:   h.droppedDatapoints,
		compactGPBPayloads:  h.compactGPBPayloads,
		lastSuccess:         h.lastSuccess,
	}
	if target != "" {
		state := h.targets[target]
		snapshot.targetActive = state.active
		snapshot.targetUpdatesReceived = state.updatesReceived
		snapshot.targetReconnects = state.reconnects
		snapshot.targetLastSuccess = state.lastSuccess
	}
	return snapshot
}

type iosXRHealthSnapshot struct {
	activeSubscriptions   int64
	updatesReceived       int64
	decodeErrors          int64
	unsupportedPaths      int64
	reconnects            int64
	droppedDatapoints     int64
	compactGPBPayloads    int64
	lastSuccess           time.Time
	targetActive          bool
	targetUpdatesReceived int64
	targetReconnects      int64
	targetLastSuccess     time.Time
}

type iosXRMetricContext struct {
	targetName     string
	endpoint       string
	platformFamily string
	transport      string
	yangPath       string
	yangModule     string
}

func newIOSXRMetrics(ctx iosXRMetricContext) (pmetric.Metrics, pmetric.ScopeMetrics) {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	attrs := rm.Resource().Attributes()
	if ctx.targetName != "" {
		attrs.PutStr("host.name", ctx.targetName)
		attrs.PutStr("host.id", ctx.targetName)
	}
	if ctx.endpoint != "" {
		if host, _, err := net.SplitHostPort(ctx.endpoint); err == nil {
			if _, exists := attrs.Get("host.name"); !exists {
				attrs.PutStr("host.name", host)
			}
			putIPAttr(attrs, "host.ip", host)
		}
	}
	attrs.PutStr("hw.type", "network")
	attrs.PutStr("cisco.os.name", "ios_xr")
	if ctx.platformFamily != "" {
		attrs.PutStr("cisco.platform.family", ctx.platformFamily)
	}
	if ctx.transport != "" {
		attrs.PutStr("cisco.telemetry.transport", ctx.transport)
	}
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/iosxr")
	return md, sm
}

func appendIOSXRHealthMetrics(md pmetric.Metrics, health *iosXRHealth, ctx iosXRMetricContext, ts pcommon.Timestamp) {
	if health == nil {
		return
	}
	rm := md.ResourceMetrics().AppendEmpty()
	attrs := rm.Resource().Attributes()
	if ctx.targetName != "" {
		attrs.PutStr("host.name", ctx.targetName)
		attrs.PutStr("host.id", ctx.targetName)
	}
	if ctx.endpoint != "" {
		if host, _, err := net.SplitHostPort(ctx.endpoint); err == nil {
			putIPAttr(attrs, "host.ip", host)
		}
	}
	attrs.PutStr("hw.type", "network")
	attrs.PutStr("cisco.os.name", "ios_xr")
	if ctx.platformFamily != "" {
		attrs.PutStr("cisco.platform.family", ctx.platformFamily)
	}
	if ctx.transport != "" {
		attrs.PutStr("cisco.telemetry.transport", ctx.transport)
	}
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/iosxr")
	snap := health.snapshotForTarget(ctx.targetName)
	appendGaugeMetric(sm, "cisco.iosxr.receiver.active_subscriptions", float64(snap.activeSubscriptions), ts, nil)
	appendSumMetric(sm, "cisco.iosxr.receiver.updates", float64(snap.updatesReceived), ts, nil)
	appendSumMetric(sm, "cisco.iosxr.receiver.decode_errors", float64(snap.decodeErrors), ts, nil)
	appendSumMetric(sm, "cisco.iosxr.receiver.unsupported_paths", float64(snap.unsupportedPaths), ts, nil)
	appendSumMetric(sm, "cisco.iosxr.receiver.reconnects", float64(snap.reconnects), ts, nil)
	appendSumMetric(sm, "cisco.iosxr.receiver.dropped_datapoints", float64(snap.droppedDatapoints), ts, nil)
	appendSumMetric(sm, "cisco.iosxr.receiver.compact_gpb_payloads", float64(snap.compactGPBPayloads), ts, nil)
	if !snap.lastSuccess.IsZero() {
		appendGaugeMetric(sm, "cisco.iosxr.receiver.last_success_timestamp", float64(snap.lastSuccess.Unix()), ts, nil)
	}
	if ctx.targetName != "" {
		appendGaugeMetric(sm, "cisco.iosxr.receiver.target.subscription.active", float64(boolToInt(snap.targetActive)), ts, nil)
		appendSumMetric(sm, "cisco.iosxr.receiver.target.updates", float64(snap.targetUpdatesReceived), ts, nil)
		appendSumMetric(sm, "cisco.iosxr.receiver.target.reconnects", float64(snap.targetReconnects), ts, nil)
		if !snap.targetLastSuccess.IsZero() {
			appendGaugeMetric(sm, "cisco.iosxr.receiver.target.last_success_timestamp", float64(snap.targetLastSuccess.Unix()), ts, nil)
		}
	}
}

func appendIOSXRMetricNumberIndexed(builder *indexedMetricBuilder, module string, pathParts []string, value metricNumber, ts pcommon.Timestamp, attrs map[string]string) {
	if builder.budget != nil && !builder.budget.allowMetricName("cisco.iosxr.yang", module, pathParts, "") {
		return
	}
	name := iosXRMetricName(module, pathParts)
	if isIOSXRCounterMetric(pathParts) {
		builder.appendNumber(name, pmetric.MetricTypeSum, value, ts, attrs)
		return
	}
	builder.appendNumber(name, pmetric.MetricTypeGauge, value, ts, attrs)
}

func appendIOSXRInfoMetricIndexed(builder *indexedMetricBuilder, module string, pathParts []string, value string, ts pcommon.Timestamp, attrs map[string]string) {
	if builder.budget != nil && !builder.budget.allowMetricName("cisco.iosxr.yang", module, pathParts, "_info") {
		return
	}
	name := iosXRMetricName(module, pathParts) + "_info"
	builder.appendInfo(name, value, ts, attrs)
}

func appendGaugeMetric(sm pmetric.ScopeMetrics, name string, value float64, ts pcommon.Timestamp, attrs map[string]string) { //nolint:unparam // Attribute support is shared infrastructure for future receiver-health dimensions.
	appendMetricNumberGauge(sm, name, doubleMetricNumber(value), ts, attrs)
}

func appendMetricNumberGauge(sm pmetric.ScopeMetrics, name string, value metricNumber, ts pcommon.Timestamp, attrs map[string]string) {
	metric := getOrCreateMetric(sm, name, pmetric.MetricTypeGauge)
	dp := metric.Gauge().DataPoints().AppendEmpty()
	value.set(dp)
	dp.SetTimestamp(ts)
	applyStringAttrs(dp.Attributes(), attrs)
}

func appendSumMetric(sm pmetric.ScopeMetrics, name string, value float64, ts pcommon.Timestamp, attrs map[string]string) { //nolint:unparam // Attribute support is shared infrastructure for future receiver-health dimensions.
	appendMetricNumberSum(sm, name, doubleMetricNumber(value), ts, attrs)
}

func appendMetricNumberSum(sm pmetric.ScopeMetrics, name string, value metricNumber, ts pcommon.Timestamp, attrs map[string]string) {
	metric := getOrCreateMetric(sm, name, pmetric.MetricTypeSum)
	sum := metric.Sum()
	dp := sum.DataPoints().AppendEmpty()
	value.set(dp)
	dp.SetTimestamp(ts)
	applyStringAttrs(dp.Attributes(), attrs)
}

func getOrCreateMetric(sm pmetric.ScopeMetrics, name string, metricType pmetric.MetricType) pmetric.Metric {
	metrics := sm.Metrics()
	for i := 0; i < metrics.Len(); i++ {
		metric := metrics.At(i)
		if metric.Name() == name && metric.Type() == metricType {
			return metric
		}
	}
	metric := metrics.AppendEmpty()
	metric.SetName(name)
	switch metricType {
	case pmetric.MetricTypeGauge:
		metric.SetEmptyGauge()
	case pmetric.MetricTypeSum:
		sum := metric.SetEmptySum()
		sum.SetIsMonotonic(true)
		sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	}
	return metric
}

func iosXRMetricName(module string, pathParts []string) string {
	parts := []string{"cisco", "iosxr", "yang"}
	if module != "" {
		parts = append(parts, sanitizeMetricSegment(module))
	}
	for _, part := range pathParts {
		if cleaned := sanitizeMetricSegment(part); cleaned != "" {
			parts = append(parts, cleaned)
		}
	}
	return strings.Join(parts, ".")
}

func sanitizeMetricSegment(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, "/")
	value = strings.ReplaceAll(value, ":", ".")
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, "/", ".")
	value = metricNameCleaner.ReplaceAllString(value, "_")
	value = strings.Trim(value, "._")
	if value == "" {
		return ""
	}
	return strings.ToLower(value)
}

func isIOSXRCounterMetric(pathParts []string) bool {
	return isUnambiguousYANGCounter(pathParts)
}

func applyStringAttrs(attrs pcommon.Map, values map[string]string) {
	applyStringAttrsWithEmpty(attrs, values, false)
}

func applyStringAttrsWithEmpty(attrs pcommon.Map, values map[string]string, preserveEmpty bool) {
	if len(values) == 0 {
		return
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if values[key] == "" && !preserveEmpty && !isDirectGNMIIdentityAttribute(key) {
			continue
		}
		if key == "host.ip" && values[key] != "" {
			putIPAttr(attrs, key, values[key])
			continue
		}
		attrs.PutStr(key, values[key])
	}
}

type metricNumber struct {
	intValue    int64
	doubleValue float64
	isInt       bool
}

func (n metricNumber) String() string {
	if n.isInt {
		return strconv.FormatInt(n.intValue, 10)
	}
	return strconv.FormatFloat(n.doubleValue, 'g', -1, 64)
}

func intMetricNumber(value int64) metricNumber {
	return metricNumber{intValue: value, isInt: true}
}

func doubleMetricNumber(value float64) metricNumber {
	return metricNumber{doubleValue: value}
}

func (n metricNumber) set(dp pmetric.NumberDataPoint) {
	if n.isInt {
		dp.SetIntValue(n.intValue)
		return
	}
	dp.SetDoubleValue(n.doubleValue)
}

func typedNumericValue(value any) (metricNumber, bool) {
	switch v := value.(type) {
	case metricNumber:
		return v, true
	case int:
		return intMetricNumber(int64(v)), true
	case int8:
		return intMetricNumber(int64(v)), true
	case int16:
		return intMetricNumber(int64(v)), true
	case int32:
		return intMetricNumber(int64(v)), true
	case int64:
		return intMetricNumber(v), true
	case uint:
		return unsignedMetricNumber(uint64(v))
	case uint8:
		return intMetricNumber(int64(v)), true
	case uint16:
		return intMetricNumber(int64(v)), true
	case uint32:
		return intMetricNumber(int64(v)), true
	case uint64:
		return unsignedMetricNumber(v)
	case float32:
		value := float64(v)
		return doubleMetricNumber(value), !math.IsNaN(value) && !math.IsInf(value, 0)
	case float64:
		return doubleMetricNumber(v), !math.IsNaN(v) && !math.IsInf(v, 0)
	case json.Number:
		return numericStringValue(v.String())
	case bool:
		if v {
			return intMetricNumber(1), true
		}
		return intMetricNumber(0), true
	case string:
		return numericStringValue(v)
	}
	return metricNumber{}, false
}

func unsignedMetricNumber(value uint64) (metricNumber, bool) {
	if value > math.MaxInt64 {
		return metricNumber{}, false
	}
	return intMetricNumber(int64(value)), true
}

func numericStringValue(value string) (metricNumber, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return metricNumber{}, false
	}
	if !strings.ContainsAny(value, ".eE") {
		if signed, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intMetricNumber(signed), true
		}
		if unsigned, err := strconv.ParseUint(value, 10, 64); err == nil {
			return unsignedMetricNumber(unsigned)
		}
		return metricNumber{}, false
	}
	f, err := strconv.ParseFloat(value, 64)
	return doubleMetricNumber(f), err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
}

func valueToInfoString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		return string(b)
	}
}

type iosXRNormalizingConsumer struct {
	next         consumer.Metrics
	config       IOSXRConfig
	selector     deviceSelectionMatcher
	transport    string
	health       *iosXRHealth
	budgetLimits finalDatapointBudgetLimits
}

func newIOSXRNormalizingConsumer(next consumer.Metrics, config IOSXRConfig, selector deviceSelectionMatcher, transport string, health *iosXRHealth) consumer.Metrics { //nolint:unparam // Transport remains explicit because the normalizer owns transport attribution.
	return &iosXRNormalizingConsumer{next: next, config: config, selector: selector, transport: transport, health: health}
}

func (*iosXRNormalizingConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

func (c *iosXRNormalizingConsumer) ConsumeMetrics(ctx context.Context, md pmetric.Metrics) error {
	budget := newFinalDatapointBudget(c.budgetLimits, c.config.MaxDatapointsPerBatch)
	c.normalize(md, budget)
	if budget.dropped > 0 && c.health != nil {
		c.health.addDroppedDatapoints(budget.dropped)
	}
	if md.MetricCount() == 0 {
		return nil
	}
	return c.next.ConsumeMetrics(ctx, md)
}

func (c *iosXRNormalizingConsumer) normalize(md pmetric.Metrics, budget *finalDatapointBudget) {
	rms := md.ResourceMetrics()
	rms.RemoveIf(func(rm pmetric.ResourceMetrics) bool {
		resAttrs := rm.Resource().Attributes()
		normalizeHostIPAttr(resAttrs)
		resAttrs.PutStr("hw.type", "network")
		resAttrs.PutStr("cisco.os.name", "ios_xr")
		resAttrs.PutStr("cisco.platform.family", "ios_xr")
		resAttrs.PutStr("cisco.telemetry.transport", c.transport)
		if v, ok := resAttrs.Get("cisco.node_id"); ok && v.AsString() != "" {
			if _, exists := resAttrs.Get("host.name"); !exists {
				resAttrs.PutStr("host.name", v.AsString())
			}
			if _, exists := resAttrs.Get("host.id"); !exists {
				resAttrs.PutStr("host.id", v.AsString())
			}
			resAttrs.PutStr("cisco.node.id", v.AsString())
		}
		if !c.selector.empty() && !c.selector.allowsResource(resAttrs) {
			return true
		}
		encodingPath := ""
		if v, ok := resAttrs.Get("cisco.encoding_path"); ok {
			encodingPath = v.AsString()
		}
		module := ""
		if v, ok := resAttrs.Get("cisco.yang.module"); ok {
			module = v.AsString()
		}
		if module == "" {
			module = moduleFromYANGPath(encodingPath)
		}
		resAttrs.Remove("cisco.encoding_path")
		resAttrs.Remove("cisco.yang.path")
		resAttrs.Remove("cisco.yang.module")
		rm.ScopeMetrics().RemoveIf(func(sm pmetric.ScopeMetrics) bool {
			metrics := sm.Metrics()
			for k := 0; k < metrics.Len(); k++ {
				metric := metrics.At(k)
				switch metric.Name() {
				case "cisco.yang_grpc.compact_gpb_payloads":
					metric.SetName("cisco.iosxr.receiver.compact_gpb_payloads")
					if c.health != nil {
						c.health.addCompactGPBPayloads(metricNumericTotal(metric))
					}
				default:
					if strings.HasPrefix(metric.Name(), "cisco.") && !strings.HasPrefix(metric.Name(), "cisco.iosxr.") {
						name := strings.TrimPrefix(metric.Name(), "cisco.")
						metric.SetName(iosXRMetricName(module, strings.Split(name, ".")))
					}
				}
				annotateMetricDatapoints(metric, module, encodingPath, c.transport, budget)
			}
			coalesceMetricStreams(sm)
			metrics.RemoveIf(func(metric pmetric.Metric) bool { return metricDatapointCount(metric) == 0 })
			return metrics.Len() == 0
		})
		return rm.ScopeMetrics().Len() == 0
	})
}

func metricNumericTotal(metric pmetric.Metric) int64 {
	var total int64
	add := func(dp pmetric.NumberDataPoint) {
		value, ok := numberDatapointInt64(dp)
		if !ok || value <= 0 {
			return
		}
		total = saturatingAddNonNegative(total, value)
	}
	switch metric.Type() {
	case pmetric.MetricTypeGauge:
		dps := metric.Gauge().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			add(dps.At(i))
		}
	case pmetric.MetricTypeSum:
		dps := metric.Sum().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			add(dps.At(i))
		}
	}
	return total
}

func numberDatapointInt64(dp pmetric.NumberDataPoint) (int64, bool) {
	if dp.ValueType() == pmetric.NumberDataPointValueTypeInt {
		return dp.IntValue(), true
	}
	value := dp.DoubleValue()
	const maxExactFloat64Integer = float64(1 << 53)
	if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || value < -maxExactFloat64Integer || value > maxExactFloat64Integer {
		return 0, false
	}
	return int64(value), true
}

type metricStreamIdentity struct {
	name                   string
	metricType             pmetric.MetricType
	unit                   string
	description            string
	aggregationTemporality pmetric.AggregationTemporality
	monotonic              bool
}

func metricStreamIdentityFromMetric(metric pmetric.Metric) metricStreamIdentity {
	identity := metricStreamIdentity{
		name: metric.Name(), metricType: metric.Type(), unit: metric.Unit(), description: metric.Description(),
	}
	switch metric.Type() {
	case pmetric.MetricTypeSum:
		identity.aggregationTemporality = metric.Sum().AggregationTemporality()
		identity.monotonic = metric.Sum().IsMonotonic()
	case pmetric.MetricTypeHistogram:
		identity.aggregationTemporality = metric.Histogram().AggregationTemporality()
	case pmetric.MetricTypeExponentialHistogram:
		identity.aggregationTemporality = metric.ExponentialHistogram().AggregationTemporality()
	}
	return identity
}

func coalesceMetricStreams(sm pmetric.ScopeMetrics) {
	seen := map[metricStreamIdentity]pmetric.Metric{}
	sm.Metrics().RemoveIf(func(metric pmetric.Metric) bool {
		identity := metricStreamIdentityFromMetric(metric)
		existing, found := seen[identity]
		if !found {
			seen[identity] = metric
			return false
		}
		switch metric.Type() {
		case pmetric.MetricTypeGauge:
			metric.Gauge().DataPoints().MoveAndAppendTo(existing.Gauge().DataPoints())
		case pmetric.MetricTypeSum:
			metric.Sum().DataPoints().MoveAndAppendTo(existing.Sum().DataPoints())
		case pmetric.MetricTypeHistogram:
			metric.Histogram().DataPoints().MoveAndAppendTo(existing.Histogram().DataPoints())
		case pmetric.MetricTypeExponentialHistogram:
			metric.ExponentialHistogram().DataPoints().MoveAndAppendTo(existing.ExponentialHistogram().DataPoints())
		case pmetric.MetricTypeSummary:
			metric.Summary().DataPoints().MoveAndAppendTo(existing.Summary().DataPoints())
		default:
			return false
		}
		return true
	})
}

func annotateMetricDatapoints(metric pmetric.Metric, module, yangPath, transport string, budget *finalDatapointBudget) {
	keep := func(attrs pcommon.Map) bool {
		additions := iosXRDatapointAttributeAdditions(attrs, module, yangPath, transport)
		if !budget.reservePcommonDatapoint(attrs, additions) {
			return false
		}
		applyStringAttrs(attrs, additions)
		return true
	}
	switch metric.Type() {
	case pmetric.MetricTypeGauge:
		dps := metric.Gauge().DataPoints()
		dps.RemoveIf(func(dp pmetric.NumberDataPoint) bool { return !keep(dp.Attributes()) })
	case pmetric.MetricTypeSum:
		dps := metric.Sum().DataPoints()
		dps.RemoveIf(func(dp pmetric.NumberDataPoint) bool { return !keep(dp.Attributes()) })
	case pmetric.MetricTypeHistogram:
		dps := metric.Histogram().DataPoints()
		dps.RemoveIf(func(dp pmetric.HistogramDataPoint) bool { return !keep(dp.Attributes()) })
	case pmetric.MetricTypeExponentialHistogram:
		dps := metric.ExponentialHistogram().DataPoints()
		dps.RemoveIf(func(dp pmetric.ExponentialHistogramDataPoint) bool { return !keep(dp.Attributes()) })
	case pmetric.MetricTypeSummary:
		dps := metric.Summary().DataPoints()
		dps.RemoveIf(func(dp pmetric.SummaryDataPoint) bool { return !keep(dp.Attributes()) })
	}
}

func moduleFromYANGPath(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, "/")
	if idx := strings.Index(value, ":"); idx > 0 {
		return value[:idx]
	}
	return ""
}

func putIPAttr(attrs pcommon.Map, key, value string) {
	putIPAttrs(attrs, key, value)
}

func putIPAttrs(attrs pcommon.Map, key string, candidates ...string) {
	valid := uniqueStrings(candidates)
	if len(valid) == 0 {
		return
	}
	values := make([]string, 0, len(valid))
	for _, value := range valid {
		if net.ParseIP(value) != nil {
			values = append(values, value)
		}
	}
	if len(values) == 0 {
		return
	}
	target := attrs.PutEmptySlice(key)
	for _, value := range values {
		target.AppendEmpty().SetStr(value)
	}
}

func normalizeHostIPAttr(attrs pcommon.Map) {
	value, ok := attrs.Get("host.ip")
	if !ok || value.Type() == pcommon.ValueTypeSlice {
		return
	}
	hostIP := value.AsString()
	attrs.Remove("host.ip")
	putIPAttr(attrs, "host.ip", hostIP)
}

func iosXRDatapointAttributeAdditions(attrs pcommon.Map, module, yangPath, transport string) map[string]string {
	additions := make(map[string]string, 8)
	if module != "" {
		additions["cisco.yang.module"] = module
	}
	if yangPath != "" {
		additions["cisco.yang.path"] = yangPath
	}
	if transport != "" {
		additions["cisco.telemetry.transport"] = transport
	}
	iface := firstIOSXRAttr(attrs, "interface", "interface-name", "if-name", "name")
	if iface != "" && looksLikeInterfaceName(iface) {
		planAttrIfMissing(attrs, additions, "network.interface.name", iface)
	}
	if vrf := firstIOSXRAttr(attrs, "vrf", "vrf-name", "vrf-name-xr"); vrf != "" {
		planAttrIfMissing(attrs, additions, "network.vrf.name", vrf)
	}
	if peer := firstIOSXRAttr(attrs, "neighbor", "neighbor-address", "peer-address", "neighbor-id"); peer != "" {
		planAttrIfMissing(attrs, additions, "network.peer.address", peer)
	}
	if node := firstIOSXRAttr(attrs, "node_id", "node-id", "node-name", "node"); node != "" {
		planAttrIfMissing(attrs, additions, "cisco.node.id", node)
	}
	if location := firstIOSXRAttr(attrs, "location", "rack", "slot"); location != "" {
		planAttrIfMissing(attrs, additions, "cisco.location", location)
	}
	return additions
}

func firstIOSXRAttr(attrs pcommon.Map, keys ...string) string {
	for _, key := range keys {
		if value, ok := attrs.Get(key); ok {
			switch value.Type() {
			case pcommon.ValueTypeStr, pcommon.ValueTypeInt, pcommon.ValueTypeDouble, pcommon.ValueTypeBool:
				if text := value.AsString(); text != "" {
					return text
				}
			}
		}
	}
	return ""
}

func planAttrIfMissing(attrs pcommon.Map, additions map[string]string, key, value string) {
	if _, exists := attrs.Get(key); !exists && value != "" {
		additions[key] = value
	}
}
