// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package yanggrpcreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
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
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		if err := s.processTelemetryData(stream.Context(), req); err != nil {
			s.receiver.settings.Logger.Error("Failed to process telemetry data", zap.Error(err))
			return err
		}
	}
}

// processTelemetryData unmarshals the GPBKV payload and triggers OTLP conversion.
func (s *grpcService) processTelemetryData(ctx context.Context, req *pb.MdtDialoutArgs) error {
	telemetryMsg := &pb.Telemetry{}
	if err := proto.Unmarshal(req.Data, telemetryMsg); err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid telemetry payload: %v", err)
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
		// Step 1: Initialize context bag with global metadata.
		ctxBag := map[string]string{
			"node_id": telemetry.GetNodeIdStr(),
		}

		// Step 2: Pre-scan the entire tree for keys/identifiers (Telegraf logic).
		// This ensures sibling branches like 'admin-status' can access 'interface-name'.
		if err := s.extractKeys(field, ctxBag, 1, budget); err != nil {
			return pmetric.Metrics{}, err
		}

		// Step 3: Walk the tree again to emit actual metrics using the enriched context.
		if err := s.emitMetrics(sm, field, "", telemetry.EncodingPath, timestamp, ctxBag, 1, budget); err != nil {
			return pmetric.Metrics{}, err
		}
	}

	return metrics, nil
}

// extractKeys recursively scans for string values that serve as identifiers.
func (s *grpcService) extractKeys(field *pb.TelemetryField, ctxBag map[string]string, depth int, budget *telemetryConversionBudget) error {
	if field == nil {
		return nil
	}
	if err := budget.visitField(field.Name, depth); err != nil {
		return err
	}
	if value, ok := field.ValueByType.(*pb.TelemetryField_StringValue); ok && value.StringValue != "" {
		if err := budget.addContextAttribute(ctxBag, field.Name, value.StringValue); err != nil {
			return err
		}

		// Common Cisco naming normalization.
		lowName := strings.ToLower(field.Name)
		if lowName == "name" || lowName == "interface-name" {
			if err := budget.addContextAttribute(ctxBag, "interface", value.StringValue); err != nil {
				return err
			}
		}
	}
	for _, child := range field.Fields {
		if err := s.extractKeys(child, ctxBag, depth+1, budget); err != nil {
			return err
		}
	}
	return nil
}

// emitMetrics processes numerical values and emits OTLP metrics with the full context bag.
func (s *grpcService) emitMetrics(sm pmetric.ScopeMetrics, field *pb.TelemetryField, pathPrefix, encodingPath string, timestamp pcommon.Timestamp, ctxBag map[string]string, depth int, budget *telemetryConversionBudget) error {
	if field == nil {
		return nil
	}
	if depth > budget.limits.MaxDepth {
		return status.Errorf(codes.ResourceExhausted, "telemetry field nesting exceeds %d levels", budget.limits.MaxDepth)
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

	// Only emit metrics for leaf nodes (values) that are NOT in the 'keys' branch.
	if field.ValueByType != nil && len(field.Fields) == 0 && !strings.HasPrefix(currentPath, "keys") {
		cleanName := strings.TrimPrefix(currentPath, "content.")

		if strVal, ok := field.ValueByType.(*pb.TelemetryField_StringValue); ok {
			if err := budget.validateAttribute("value", strVal.StringValue); err != nil {
				return err
			}
			if err := budget.reserveMetric(ctxBag, "value", strVal.StringValue); err != nil {
				return err
			}
			m := sm.Metrics().AppendEmpty()
			// Step/Info metrics for string states (e.g., Up/Down).
			createStepMetric(m, cleanName, strVal.StringValue, effectiveTimestamp, ctxBag)
		} else if uintVal, ok := field.ValueByType.(*pb.TelemetryField_Uint64Value); ok && uintVal.Uint64Value > math.MaxInt64 {
			// OTLP numeric datapoints do not have an unsigned integer type. Match
			// the direct gNMI receivers by preserving out-of-range uint64 values
			// exactly in an info metric rather than rounding them through float64.
			value := strconv.FormatUint(uintVal.Uint64Value, 10)
			overflowCtx := make(map[string]string, len(ctxBag)+1)
			for key, contextValue := range ctxBag {
				overflowCtx[key] = contextValue
			}
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
				if err := budget.reserveMetric(ctxBag, "", ""); err != nil {
					return err
				}
				m := sm.Metrics().AppendEmpty()
				// Numeric metrics for counters and gauges.
				var yangType *internal.YANGDataType
				if s.yangParser != nil {
					yangType = s.yangParser.GetDataTypeForEncodingPath(encodingPath, field.Name)
				}
				createNumericMetric(m, cleanName, numericValue, effectiveTimestamp, yangType, ctxBag)
			}
		}
	}

	for _, child := range field.Fields {
		if err := s.emitMetrics(sm, child, currentPath, encodingPath, effectiveTimestamp, ctxBag, depth+1, budget); err != nil {
			return err
		}
	}
	return nil
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
	dp.Attributes().PutStr("value", val)
	applyCtxBag(dp.Attributes(), ctx)
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
		if v != "" {
			attrs.PutStr(k, v)
		}
	}
}
