// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package yanggrpcreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver"

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver/internal"
	pb "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver/internal/proto/generated/proto"
)

// grpcService handles Cisco gRPC Dial-out telemetry streams.
type grpcService struct {
	pb.UnimplementedGRPCMdtDialoutServer
	receiver   *yangReceiver
	yangParser *internal.YANGParser
	limits     telemetryConversionLimits
}

const (
	defaultMaxTelemetryMetrics        = 50_000
	defaultMaxTelemetryFields         = 100_000
	defaultMaxTelemetryAttributes     = 250_000
	defaultMaxTelemetryAttributeBytes = 16 * 1024 * 1024
	defaultMaxAttributesPerMetric     = 64
	defaultMaxTelemetryDepth          = 128
	defaultMaxAttributeKeyBytes       = 256
	defaultMaxAttributeValueBytes     = 4 * 1024
	defaultMaxMetricNameBytes         = 1024
	maxTelemetryTimestampMillis       = ^uint64(0) / uint64(time.Millisecond)
)

// telemetryConversionLimits are hard safety ceilings, not tuning knobs. They
// prevent a small GPB-KV message from expanding into an unbounded OTLP batch.
// Tests may lower individual limits to exercise the rejection paths.
type telemetryConversionLimits struct {
	MaxMetrics         int
	MaxFields          int
	MaxAttributes      int
	MaxAttributeBytes  int
	MaxAttrsPerMetric  int
	MaxDepth           int
	MaxAttrKeyBytes    int
	MaxAttrValueBytes  int
	MaxMetricNameBytes int
}

func (l telemetryConversionLimits) withDefaults() telemetryConversionLimits {
	if l.MaxMetrics <= 0 {
		l.MaxMetrics = defaultMaxTelemetryMetrics
	}
	if l.MaxFields <= 0 {
		l.MaxFields = defaultMaxTelemetryFields
	}
	if l.MaxAttributes <= 0 {
		l.MaxAttributes = defaultMaxTelemetryAttributes
	}
	if l.MaxAttributeBytes <= 0 {
		l.MaxAttributeBytes = defaultMaxTelemetryAttributeBytes
	}
	if l.MaxAttrsPerMetric <= 0 {
		l.MaxAttrsPerMetric = defaultMaxAttributesPerMetric
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = defaultMaxTelemetryDepth
	}
	if l.MaxAttrKeyBytes <= 0 {
		l.MaxAttrKeyBytes = defaultMaxAttributeKeyBytes
	}
	if l.MaxAttrValueBytes <= 0 {
		l.MaxAttrValueBytes = defaultMaxAttributeValueBytes
	}
	if l.MaxMetricNameBytes <= 0 {
		l.MaxMetricNameBytes = defaultMaxMetricNameBytes
	}
	return l
}

type telemetryConversionBudget struct {
	limits         telemetryConversionLimits
	fields         int
	metrics        int
	attributes     int
	attributeBytes int
}

// MdtDialout processes the bidirectional gRPC stream.
func (s *grpcService) MdtDialout(stream pb.GRPCMdtDialout_MdtDialoutServer) error {
	s.receiver.settings.Logger.Info("New Cisco telemetry session established")
	reader := newTelemetryStreamReader(
		stream.Context(),
		stream,
		effectiveStreamIdleTimeout(s.receiver.config.StreamIdleTimeout),
	)
	s.receiver.wg.Go(reader.read)
	defer reader.stop()
	for {
		req, releaseFrame, err := reader.receive()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		processErr := func() error {
			defer releaseFrame()
			return s.processTelemetryData(stream.Context(), req)
		}()
		if processErr != nil {
			s.receiver.settings.Logger.Error("Failed to process telemetry data", zap.Error(processErr))
			return processErr
		}
	}
}

// processTelemetryData unmarshals the GPBKV payload and triggers OTLP conversion.
func (s *grpcService) processTelemetryData(ctx context.Context, req *pb.MdtDialoutArgs) error {
	release, err := s.receiver.acquireProcessingSlot(ctx)
	if err != nil {
		return err
	}
	defer release()
	if preflightErr := preflightTelemetryPayload(req.Data, s.limits); preflightErr != nil {
		return preflightErr
	}

	telemetryMsg := &pb.Telemetry{}
	if unmarshalErr := proto.Unmarshal(req.Data, telemetryMsg); unmarshalErr != nil {
		return status.Errorf(codes.InvalidArgument, "invalid telemetry payload: %v", unmarshalErr)
	}

	metrics, err := s.convertToOTELMetrics(telemetryMsg, time.Now())
	if err != nil {
		return err
	}
	if err := s.receiver.consumer.ConsumeMetrics(ctx, metrics); err != nil {
		return fmt.Errorf("consume converted telemetry: %w", err)
	}
	return nil
}

// convertToOTELMetrics maps Cisco KV-GPB data to OTLP using a Telegraf-inspired
// approach: extract identifiers (tags) first, then emit measurements.
func (s *grpcService) convertToOTELMetrics(telemetry *pb.Telemetry, receivedAt time.Time) (pmetric.Metrics, error) {
	limits := s.limits.withDefaults()
	budget := &telemetryConversionBudget{limits: limits}
	timestamp, err := telemetryTimestamp(telemetry.MsgTimestamp, receivedAt)
	if err != nil {
		return pmetric.Metrics{}, err
	}
	if err := budget.validateAttribute("cisco.node_id", telemetry.GetNodeIdStr()); err != nil {
		return pmetric.Metrics{}, err
	}
	if err := budget.validateAttribute("cisco.encoding_path", telemetry.EncodingPath); err != nil {
		return pmetric.Metrics{}, err
	}
	if err := budget.reserveAttributes(2, len("cisco.node_id")+len(telemetry.GetNodeIdStr())+len("cisco.encoding_path")+len(telemetry.EncodingPath)); err != nil {
		return pmetric.Metrics{}, err
	}

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()

	resAttrs := rm.Resource().Attributes()
	resAttrs.PutStr("cisco.node_id", telemetry.GetNodeIdStr())
	resAttrs.PutStr("cisco.encoding_path", telemetry.EncodingPath)

	sm := rm.ScopeMetrics().AppendEmpty()

	if rows := telemetry.GetDataGpb().GetRow(); len(rows) > 0 {
		attrs := map[string]string{
			"node_id":       telemetry.GetNodeIdStr(),
			"encoding_path": telemetry.GetEncodingPath(),
		}
		if err := budget.reserveMetric(attrs, "", ""); err != nil {
			return pmetric.Metrics{}, err
		}
		m := sm.Metrics().AppendEmpty()
		createNumericMetric(m, "yang_grpc.compact_gpb_payloads", telemetryNumber{isInt: true, intValue: int64(len(rows))}, timestamp, nil, attrs)
	}

	// Process each entry in DataGpbkv as a distinct row/object.
	for _, field := range telemetry.DataGpbkv {
		if field == nil {
			continue
		}
		// Initialize the inherited context with trusted, stable metadata. List
		// keys are added lexically by emitMetrics for the object that owns each
		// explicit `keys` subtree; arbitrary string leaves must not become labels
		// on sibling cumulative counters.
		ctxBag := map[string]string{
			"node_id": telemetry.GetNodeIdStr(),
		}
		if err := s.emitMetrics(sm, field, "", "", telemetry.EncodingPath, timestamp, ctxBag, false, 1, budget); err != nil {
			return pmetric.Metrics{}, err
		}
	}

	return metrics, nil
}

type telemetryKeyAttribute struct {
	name  string
	value string
}

// extractKeyAttributes copies scalar leaves from an explicit GPB-KV `keys`
// subtree into the context for its owning list instance. It intentionally does
// not treat arbitrary string leaves (status, description, reason, and so on)
// as identity attributes. Key leaves are sorted before publication because
// protobuf repeated-field order is not part of list identity; reordering an
// equivalent key set must not change collision escape names or series keys.
func extractKeyAttributes(field *pb.TelemetryField, ctxBag map[string]string, depth int, budget *telemetryConversionBudget) error {
	attributes := make([]telemetryKeyAttribute, 0)
	if err := collectKeyAttributes(field, depth, budget, &attributes); err != nil {
		return err
	}
	slices.SortFunc(attributes, func(left, right telemetryKeyAttribute) int {
		if byName := strings.Compare(left.name, right.name); byName != 0 {
			return byName
		}
		return strings.Compare(left.value, right.value)
	})
	for _, attribute := range attributes {
		if err := budget.addKeyContextAttribute(ctxBag, attribute.name, attribute.value); err != nil {
			return err
		}

		// Common Cisco naming normalization.
		lowName := strings.ToLower(attribute.name)
		if attribute.value != "" && (lowName == "name" || lowName == "interface-name") {
			if err := budget.addKeyContextAttribute(ctxBag, "interface", attribute.value); err != nil {
				return err
			}
		}
	}
	return nil
}

func collectKeyAttributes(
	field *pb.TelemetryField,
	depth int,
	budget *telemetryConversionBudget,
	attributes *[]telemetryKeyAttribute,
) error {
	if field == nil {
		return nil
	}
	if depth > budget.limits.MaxDepth {
		return status.Errorf(codes.ResourceExhausted, "telemetry field nesting exceeds %d levels", budget.limits.MaxDepth)
	}
	if len(field.Name) > budget.limits.MaxAttrKeyBytes {
		return status.Errorf(codes.ResourceExhausted, "telemetry field name exceeds %d bytes", budget.limits.MaxAttrKeyBytes)
	}
	value, present, err := telemetryKeyAttributeValue(field, budget.limits.MaxAttrValueBytes)
	if err != nil {
		return err
	}
	if present {
		*attributes = append(*attributes, telemetryKeyAttribute{name: field.Name, value: value})
	}
	for _, child := range field.Fields {
		if err := collectKeyAttributes(child, depth+1, budget, attributes); err != nil {
			return err
		}
	}
	return nil
}

func telemetryKeyAttributeValue(field *pb.TelemetryField, maximum int) (string, bool, error) {
	switch value := field.ValueByType.(type) {
	case *pb.TelemetryField_StringValue:
		return value.StringValue, true, nil
	case *pb.TelemetryField_BytesValue:
		if base64.StdEncoding.EncodedLen(len(value.BytesValue)) > maximum {
			return "", false, status.Errorf(codes.ResourceExhausted, "telemetry key value exceeds %d bytes", maximum)
		}
		return base64.StdEncoding.EncodeToString(value.BytesValue), true, nil
	case *pb.TelemetryField_BoolValue:
		return strconv.FormatBool(value.BoolValue), true, nil
	case *pb.TelemetryField_Uint32Value:
		return strconv.FormatUint(uint64(value.Uint32Value), 10), true, nil
	case *pb.TelemetryField_Uint64Value:
		return strconv.FormatUint(value.Uint64Value, 10), true, nil
	case *pb.TelemetryField_Sint32Value:
		return strconv.FormatInt(int64(value.Sint32Value), 10), true, nil
	case *pb.TelemetryField_Sint64Value:
		return strconv.FormatInt(value.Sint64Value, 10), true, nil
	case *pb.TelemetryField_DoubleValue:
		if math.IsNaN(value.DoubleValue) || math.IsInf(value.DoubleValue, 0) {
			return "", false, status.Error(codes.InvalidArgument, "telemetry key contains a non-finite double value")
		}
		return strconv.FormatFloat(value.DoubleValue, 'g', -1, 64), true, nil
	case *pb.TelemetryField_FloatValue:
		converted := float64(value.FloatValue)
		if math.IsNaN(converted) || math.IsInf(converted, 0) {
			return "", false, status.Error(codes.InvalidArgument, "telemetry key contains a non-finite float value")
		}
		return strconv.FormatFloat(converted, 'g', -1, 32), true, nil
	default:
		return "", false, nil
	}
}

// emitMetrics processes leaf values and emits OTLP metrics with the stable key
// context of the enclosing GPB-KV list instance.
func (s *grpcService) emitMetrics(sm pmetric.ScopeMetrics, field *pb.TelemetryField, pathPrefix, sourcePathPrefix, encodingPath string, timestamp pcommon.Timestamp, ctxBag map[string]string, inKeys bool, depth int, budget *telemetryConversionBudget) error {
	if field == nil {
		return nil
	}
	if err := budget.visitField(field.Name, depth); err != nil {
		return err
	}
	effectiveTimestamp := timestamp
	if field.Timestamp != 0 {
		var err error
		effectiveTimestamp, err = telemetryFieldTimestamp(field.Timestamp)
		if err != nil {
			return err
		}
	}
	currentPath := pathPrefix
	if currentPath != "" {
		currentPath += "."
	}
	currentPath += field.Name
	if len(currentPath) > budget.limits.MaxMetricNameBytes {
		return status.Errorf(codes.ResourceExhausted, "telemetry metric path exceeds %d bytes", budget.limits.MaxMetricNameBytes)
	}
	currentSourcePath, err := extendTelemetrySourcePath(sourcePathPrefix, field.Name, budget.limits.MaxAttrValueBytes)
	if err != nil {
		return err
	}

	localCtx := ctxBag
	contextCloned := false
	if !inKeys {
		for _, child := range field.Fields {
			if child == nil || !strings.EqualFold(child.Name, "keys") {
				continue
			}
			if !contextCloned {
				localCtx = maps.Clone(ctxBag)
				contextCloned = true
			}
			if err := extractKeyAttributes(child, localCtx, depth+1, budget); err != nil {
				return err
			}
		}
	}

	// Key leaves define identity but are not measurements themselves.
	if field.ValueByType != nil && len(field.Fields) == 0 && !inKeys {
		cleanName := strings.TrimPrefix(currentPath, "content.")
		metricCtx := maps.Clone(localCtx)
		if err := budget.addContextAttribute(metricCtx, "cisco.yang.source_path", currentSourcePath); err != nil {
			return err
		}

		if strVal, ok := field.ValueByType.(*pb.TelemetryField_StringValue); ok {
			if err := budget.validateAttribute("value", strVal.StringValue); err != nil {
				return err
			}
			if err := budget.reserveMetric(metricCtx, "value", strVal.StringValue); err != nil {
				return err
			}
			m := sm.Metrics().AppendEmpty()
			// Step/Info metrics for string states (e.g., Up/Down).
			createStepMetric(m, cleanName, strVal.StringValue, effectiveTimestamp, metricCtx)
		} else if uintVal, ok := field.ValueByType.(*pb.TelemetryField_Uint64Value); ok && uintVal.Uint64Value > math.MaxInt64 {
			// OTLP numeric datapoints do not have an unsigned integer type. Match
			// the direct gNMI receivers by preserving out-of-range uint64 values
			// exactly in an info metric rather than rounding them through float64.
			value := strconv.FormatUint(uintVal.Uint64Value, 10)
			overflowCtx := make(map[string]string, len(metricCtx)+1)
			maps.Copy(overflowCtx, metricCtx)
			if err := budget.addContextAttribute(overflowCtx, "cisco.value.type", "uint64"); err != nil {
				return err
			}
			if err := budget.reserveMetric(overflowCtx, "value", value); err != nil {
				return err
			}
			m := sm.Metrics().AppendEmpty()
			createStepMetric(m, cleanName, value, effectiveTimestamp, overflowCtx)
		} else {
			numericValue, ok, err := getNumericValue(field)
			if err != nil {
				return err
			}
			if ok {
				if err := budget.reserveMetric(metricCtx, "", ""); err != nil {
					return err
				}
				m := sm.Metrics().AppendEmpty()
				// Numeric metrics for counters and gauges.
				var yangType *internal.YANGDataType
				if s.yangParser != nil {
					yangType = s.yangParser.GetDataTypeForEncodingPath(encodingPath, field.Name)
				}
				createNumericMetric(m, cleanName, numericValue, effectiveTimestamp, yangType, metricCtx)
			}
		}
	}

	for _, child := range field.Fields {
		childInKeys := inKeys || (child != nil && strings.EqualFold(child.Name, "keys"))
		if err := s.emitMetrics(sm, child, currentPath, currentSourcePath, encodingPath, effectiveTimestamp, localCtx, childInKeys, depth+1, budget); err != nil {
			return err
		}
	}
	return nil
}

func extendTelemetrySourcePath(prefix, name string, maximum int) (string, error) {
	// JSON Pointer escaping makes the segmentation injective even when a device
	// sends punctuation that is also used by the metric-name path.
	escaped := strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1")
	if prefix != "" {
		prefix += "/"
	}
	if len(escaped) > maximum-len(prefix) {
		return "", status.Errorf(codes.ResourceExhausted, "telemetry source path exceeds %d bytes", maximum)
	}
	return prefix + escaped, nil
}

// createNumericMetric populates a NumberDataPoint.
func createNumericMetric(m pmetric.Metric, name string, value telemetryNumber, ts pcommon.Timestamp, yType *internal.YANGDataType, ctx map[string]string) {
	m.SetName("cisco." + name)
	if yType != nil {
		m.SetDescription(yType.Description)
		m.SetUnit(yType.Units)
	}
	if yType != nil && yType.IsCounterType() {
		sum := m.SetEmptySum()
		sum.SetIsMonotonic(true)
		sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
		dp := sum.DataPoints().AppendEmpty()
		setTelemetryNumber(dp, value)
		dp.SetTimestamp(ts)
		applyCtxBag(dp.Attributes(), ctx)
	} else {
		dp := m.SetEmptyGauge().DataPoints().AppendEmpty()
		setTelemetryNumber(dp, value)
		dp.SetTimestamp(ts)
		applyCtxBag(dp.Attributes(), ctx)
	}
}

type telemetryNumber struct {
	isInt       bool
	intValue    int64
	doubleValue float64
}

func setTelemetryNumber(dp pmetric.NumberDataPoint, value telemetryNumber) {
	if value.isInt {
		dp.SetIntValue(value.intValue)
		return
	}
	dp.SetDoubleValue(value.doubleValue)
}

// createStepMetric creates an "Info" metric where the actual value is an attribute.
func createStepMetric(m pmetric.Metric, name, val string, ts pcommon.Timestamp, ctx map[string]string) {
	m.SetName("cisco." + name + "_info")
	dp := m.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetDoubleValue(1.0)
	dp.SetTimestamp(ts)
	applyCtxBag(dp.Attributes(), ctx)
	// `value` is receiver-owned for info metrics. Apply it last so a future
	// context-construction regression cannot corrupt the reported state.
	dp.Attributes().PutStr("value", val)
}

// getNumericValue extracts float64 from numeric and boolean protobuf types.
// Byte values are intentionally not converted to a fabricated numeric zero.
func getNumericValue(f *pb.TelemetryField) (telemetryNumber, bool, error) {
	switch v := f.ValueByType.(type) {
	case *pb.TelemetryField_Uint32Value:
		return telemetryNumber{isInt: true, intValue: int64(v.Uint32Value)}, true, nil
	case *pb.TelemetryField_Uint64Value:
		if v.Uint64Value <= math.MaxInt64 {
			return telemetryNumber{isInt: true, intValue: int64(v.Uint64Value)}, true, nil
		}
		return telemetryNumber{}, false, status.Errorf(codes.InvalidArgument, "telemetry uint64 value %d cannot be represented as an OTLP integer", v.Uint64Value)
	case *pb.TelemetryField_Sint32Value:
		return telemetryNumber{isInt: true, intValue: int64(v.Sint32Value)}, true, nil
	case *pb.TelemetryField_Sint64Value:
		return telemetryNumber{isInt: true, intValue: v.Sint64Value}, true, nil
	case *pb.TelemetryField_DoubleValue:
		if math.IsNaN(v.DoubleValue) || math.IsInf(v.DoubleValue, 0) {
			return telemetryNumber{}, false, status.Error(codes.InvalidArgument, "telemetry contains a non-finite double value")
		}
		return telemetryNumber{doubleValue: v.DoubleValue}, true, nil
	case *pb.TelemetryField_FloatValue:
		value := float64(v.FloatValue)
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return telemetryNumber{}, false, status.Error(codes.InvalidArgument, "telemetry contains a non-finite float value")
		}
		return telemetryNumber{doubleValue: value}, true, nil
	case *pb.TelemetryField_BoolValue:
		if v.BoolValue {
			return telemetryNumber{isInt: true, intValue: 1}, true, nil
		}
		return telemetryNumber{isInt: true}, true, nil
	}
	return telemetryNumber{}, false, nil
}

func telemetryTimestamp(milliseconds uint64, receivedAt time.Time) (pcommon.Timestamp, error) {
	if milliseconds == 0 {
		if receivedAt.IsZero() {
			receivedAt = time.Now()
		}
		return pcommon.NewTimestampFromTime(receivedAt), nil
	}
	if milliseconds > maxTelemetryTimestampMillis {
		return 0, status.Error(codes.InvalidArgument, "telemetry msg_timestamp overflows nanoseconds")
	}
	return pcommon.Timestamp(milliseconds * uint64(time.Millisecond)), nil
}

func telemetryFieldTimestamp(milliseconds uint64) (pcommon.Timestamp, error) {
	if milliseconds > maxTelemetryTimestampMillis {
		return 0, status.Error(codes.InvalidArgument, "telemetry field timestamp overflows nanoseconds")
	}
	return pcommon.Timestamp(milliseconds * uint64(time.Millisecond)), nil
}

func (b *telemetryConversionBudget) visitField(name string, depth int) error {
	if depth > b.limits.MaxDepth {
		return status.Errorf(codes.ResourceExhausted, "telemetry field nesting exceeds %d levels", b.limits.MaxDepth)
	}
	if strings.TrimSpace(name) == "" {
		return status.Error(codes.InvalidArgument, "telemetry field name cannot be empty")
	}
	b.fields++
	if b.fields > b.limits.MaxFields {
		return status.Errorf(codes.ResourceExhausted, "telemetry payload exceeds %d fields", b.limits.MaxFields)
	}
	if len(name) > b.limits.MaxAttrKeyBytes {
		return status.Errorf(codes.ResourceExhausted, "telemetry field name exceeds %d bytes", b.limits.MaxAttrKeyBytes)
	}
	return nil
}

func (b *telemetryConversionBudget) validateAttribute(key, value string) error {
	if strings.TrimSpace(key) == "" {
		return status.Error(codes.InvalidArgument, "telemetry attribute key cannot be empty")
	}
	if len(key) > b.limits.MaxAttrKeyBytes {
		return status.Errorf(codes.ResourceExhausted, "telemetry attribute key exceeds %d bytes", b.limits.MaxAttrKeyBytes)
	}
	if len(value) > b.limits.MaxAttrValueBytes {
		return status.Errorf(codes.ResourceExhausted, "telemetry attribute value exceeds %d bytes", b.limits.MaxAttrValueBytes)
	}
	return nil
}

func (b *telemetryConversionBudget) addContextAttribute(ctx map[string]string, key, value string) error {
	if err := b.validateAttribute(key, value); err != nil {
		return err
	}
	if _, exists := ctx[key]; !exists {
		// Reserve one slot for the `value` attribute added by string info
		// metrics, so every emitted datapoint remains within the same ceiling.
		maxContextAttributes := b.limits.MaxAttrsPerMetric - 1
		if len(ctx) >= maxContextAttributes {
			return status.Errorf(codes.ResourceExhausted, "telemetry context exceeds %d attributes", maxContextAttributes)
		}
	}
	ctx[key] = value
	return nil
}

// addKeyContextAttribute preserves list-key identity without allowing
// device-controlled key names to overwrite receiver-owned attributes or an
// inherited list key. The common case retains its historical attribute name;
// only ambiguous names are escaped under cisco.key.*.
func (b *telemetryConversionBudget) addKeyContextAttribute(ctx map[string]string, key, value string) error {
	if err := b.validateAttribute(key, value); err != nil {
		return err
	}

	if existing, exists := ctx[key]; !isReservedMetricAttribute(key) && (!exists || existing == value) {
		if exists {
			return nil
		}
		return b.addContextAttribute(ctx, key, value)
	}

	for index := 1; index <= len(ctx)+1; index++ {
		candidate := "cisco.key." + key
		if index > 1 {
			candidate = "cisco.key." + strconv.Itoa(index) + "." + key
		}
		if len(candidate) > b.limits.MaxAttrKeyBytes {
			return status.Errorf(codes.ResourceExhausted, "escaped telemetry key attribute exceeds %d bytes", b.limits.MaxAttrKeyBytes)
		}
		if existing, exists := ctx[candidate]; exists {
			if existing == value {
				return nil
			}
			continue
		}
		return b.addContextAttribute(ctx, candidate, value)
	}

	return status.Errorf(codes.ResourceExhausted, "telemetry context exceeds %d attributes", b.limits.MaxAttrsPerMetric-1)
}

func isReservedMetricAttribute(key string) bool {
	if strings.HasPrefix(key, "cisco.key.") {
		return true
	}
	switch key {
	case "node_id", "value", "cisco.value.type", "cisco.yang.source_path",
		"cisco.yang.path", "cisco.yang.module", "cisco.telemetry.transport":
		return true
	default:
		return false
	}
}

func (b *telemetryConversionBudget) reserveMetric(ctx map[string]string, extraKey, extraValue string) error {
	if b.metrics >= b.limits.MaxMetrics {
		return status.Errorf(codes.ResourceExhausted, "telemetry payload exceeds %d metrics", b.limits.MaxMetrics)
	}
	attributeCount := len(ctx)
	attributeBytes := 0
	for key, value := range ctx {
		if err := b.validateAttribute(key, value); err != nil {
			return err
		}
		attributeBytes += len(key) + len(value)
	}
	if extraKey != "" {
		if _, exists := ctx[extraKey]; exists {
			return status.Errorf(codes.InvalidArgument, "telemetry context conflicts with reserved metric attribute %q", extraKey)
		}
		if err := b.validateAttribute(extraKey, extraValue); err != nil {
			return err
		}
		attributeCount++
		attributeBytes += len(extraKey) + len(extraValue)
	}
	if attributeCount > b.limits.MaxAttrsPerMetric {
		return status.Errorf(codes.ResourceExhausted, "telemetry metric exceeds %d attributes", b.limits.MaxAttrsPerMetric)
	}
	if err := b.reserveAttributes(attributeCount, attributeBytes); err != nil {
		return err
	}
	b.metrics++
	return nil
}

func (b *telemetryConversionBudget) reserveAttributes(count, byteCount int) error {
	if count > b.limits.MaxAttributes-b.attributes {
		return status.Errorf(codes.ResourceExhausted, "telemetry payload exceeds %d attributes", b.limits.MaxAttributes)
	}
	if byteCount > b.limits.MaxAttributeBytes-b.attributeBytes {
		return status.Errorf(codes.ResourceExhausted, "telemetry payload exceeds %d attribute bytes", b.limits.MaxAttributeBytes)
	}
	b.attributes += count
	b.attributeBytes += byteCount
	return nil
}

func applyCtxBag(attrs pcommon.Map, ctx map[string]string) {
	for k, v := range ctx {
		// Empty strings are valid YANG list-key values and still participate in
		// series identity. reserveMetric already accounts every context entry, so
		// publish the exact context shape it validated.
		attrs.PutStr(k, v)
	}
}
