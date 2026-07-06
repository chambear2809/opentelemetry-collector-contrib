// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package yanggrpcreceiver

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver/internal"
	pb "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver/internal/proto/generated/proto"
)

func TestTelemetryTimestamp(t *testing.T) {
	receivedAt := time.Unix(123, 456)
	timestamp, err := telemetryTimestamp(0, receivedAt)
	require.NoError(t, err)
	assert.True(t, receivedAt.Equal(timestamp.AsTime()))

	timestamp, err = telemetryTimestamp(1234, receivedAt)
	require.NoError(t, err)
	assert.Equal(t, uint64(1_234_000_000), uint64(timestamp))

	_, err = telemetryTimestamp(maxTelemetryTimestampMillis+1, receivedAt)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = telemetryFieldTimestamp(maxTelemetryTimestampMillis + 1)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestConversionUsesNestedFieldTimestamps(t *testing.T) {
	service := newLimitsTestService(t)
	telemetry := &pb.Telemetry{
		NodeId:       &pb.Telemetry_NodeIdStr{NodeIdStr: "router-1"},
		MsgTimestamp: 1_000,
		DataGpbkv: []*pb.TelemetryField{
			{Name: "global-inherited", ValueByType: &pb.TelemetryField_Uint64Value{Uint64Value: 1}},
			{
				Name:      "root",
				Timestamp: 2_000,
				Fields: []*pb.TelemetryField{
					{Name: "parent-inherited", ValueByType: &pb.TelemetryField_Uint64Value{Uint64Value: 2}},
					{
						Name:      "nested",
						Timestamp: 3_000,
						Fields: []*pb.TelemetryField{
							{Name: "nested-inherited", ValueByType: &pb.TelemetryField_Uint64Value{Uint64Value: 3}},
							{Name: "leaf-override", Timestamp: 4_000, ValueByType: &pb.TelemetryField_Uint64Value{Uint64Value: 4}},
						},
					},
				},
			},
		},
	}

	metrics, err := service.convertToOTELMetrics(telemetry, time.Unix(1, 0))
	require.NoError(t, err)
	metricSlice := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	require.Equal(t, 4, metricSlice.Len())
	timestamps := make(map[string]uint64, metricSlice.Len())
	for i := 0; i < metricSlice.Len(); i++ {
		metric := metricSlice.At(i)
		timestamps[metric.Name()] = uint64(metric.Gauge().DataPoints().At(0).Timestamp())
	}
	assert.Equal(t, uint64(1_000_000_000), timestamps["cisco.global-inherited"])
	assert.Equal(t, uint64(2_000_000_000), timestamps["cisco.root.parent-inherited"])
	assert.Equal(t, uint64(3_000_000_000), timestamps["cisco.root.nested.nested-inherited"])
	assert.Equal(t, uint64(4_000_000_000), timestamps["cisco.root.nested.leaf-override"])

	telemetry.DataGpbkv[1].Fields[1].Timestamp = maxTelemetryTimestampMillis + 1
	_, err = service.convertToOTELMetrics(telemetry, time.Unix(1, 0))
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "field timestamp overflows")
}

func TestConversionRejectsMetricAmplification(t *testing.T) {
	service := newLimitsTestService(t)
	service.limits.MaxMetrics = 2
	telemetry := &pb.Telemetry{
		NodeId:       &pb.Telemetry_NodeIdStr{NodeIdStr: "router-1"},
		MsgTimestamp: 1,
		DataGpbkv: []*pb.TelemetryField{
			numericTelemetryField("one"),
			numericTelemetryField("two"),
			numericTelemetryField("three"),
		},
	}

	_, err := service.convertToOTELMetrics(telemetry, time.Unix(1, 0))
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.Contains(t, err.Error(), "exceeds 2 metrics")
}

func TestConversionRejectsAttributeAmplification(t *testing.T) {
	service := newLimitsTestService(t)
	service.limits.MaxAttrsPerMetric = 2
	telemetry := &pb.Telemetry{
		NodeId:       &pb.Telemetry_NodeIdStr{NodeIdStr: "router-1"},
		MsgTimestamp: 1,
		DataGpbkv: []*pb.TelemetryField{{
			Name: "row",
			Fields: []*pb.TelemetryField{
				{
					Name:   "keys",
					Fields: []*pb.TelemetryField{{Name: "tenant", ValueByType: &pb.TelemetryField_StringValue{StringValue: "blue"}}},
				},
				numericTelemetryField("packets"),
			},
		}},
	}

	_, err := service.convertToOTELMetrics(telemetry, time.Unix(1, 0))
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.Contains(t, err.Error(), "context exceeds")
}

func TestConversionRejectsEmptyFieldAndKeyNames(t *testing.T) {
	service := newLimitsTestService(t)
	tests := map[string]*pb.Telemetry{
		"metric field": {
			NodeId:    &pb.Telemetry_NodeIdStr{NodeIdStr: "router-1"},
			DataGpbkv: []*pb.TelemetryField{numericTelemetryField("")},
		},
		"whitespace metric field": {
			NodeId:    &pb.Telemetry_NodeIdStr{NodeIdStr: "router-1"},
			DataGpbkv: []*pb.TelemetryField{numericTelemetryField(" ")},
		},
		"list key": {
			NodeId: &pb.Telemetry_NodeIdStr{NodeIdStr: "router-1"},
			DataGpbkv: []*pb.TelemetryField{{
				Name: "row",
				Fields: []*pb.TelemetryField{
					{Name: "keys", Fields: []*pb.TelemetryField{{
						Name: "", ValueByType: &pb.TelemetryField_StringValue{StringValue: "blue"},
					}}},
					numericTelemetryField("packets"),
				},
			}},
		},
		"anonymous row missing keys": {
			NodeId: &pb.Telemetry_NodeIdStr{NodeIdStr: "router-1"},
			DataGpbkv: []*pb.TelemetryField{{
				Fields: []*pb.TelemetryField{
					{Name: "content", Fields: []*pb.TelemetryField{numericTelemetryField("packets")}},
				},
			}},
		},
		"anonymous row duplicate content": {
			NodeId: &pb.Telemetry_NodeIdStr{NodeIdStr: "router-1"},
			DataGpbkv: []*pb.TelemetryField{{
				Fields: []*pb.TelemetryField{
					{Name: "content", Fields: []*pb.TelemetryField{numericTelemetryField("packets")}},
					{Name: "content", Fields: []*pb.TelemetryField{numericTelemetryField("errors")}},
				},
			}},
		},
		"nested anonymous row": {
			NodeId: &pb.Telemetry_NodeIdStr{NodeIdStr: "router-1"},
			DataGpbkv: []*pb.TelemetryField{{
				Name: "root",
				Fields: []*pb.TelemetryField{{
					Fields: []*pb.TelemetryField{
						{Name: "keys"},
						{Name: "content", Fields: []*pb.TelemetryField{numericTelemetryField("packets")}},
					},
				}},
			}},
		},
	}
	for name, telemetry := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := service.convertToOTELMetrics(telemetry, time.Unix(1, 0))
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.ErrorContains(t, err, "cannot be empty")
		})
	}
}

func TestConversionAcceptsAnonymousTopLevelGPBKVRow(t *testing.T) {
	service := newLimitsTestService(t)
	telemetry := &pb.Telemetry{
		NodeId:       &pb.Telemetry_NodeIdStr{NodeIdStr: "xrd-1"},
		EncodingPath: "Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/generic-counters",
		MsgTimestamp: 1_000,
		DataGpbkv: []*pb.TelemetryField{{
			Timestamp: 2_000,
			Fields: []*pb.TelemetryField{
				{
					Name: "keys",
					Fields: []*pb.TelemetryField{{
						Name:        "interface-name",
						ValueByType: &pb.TelemetryField_StringValue{StringValue: "GigabitEthernet0/0/0/0"},
					}},
				},
				{
					Name:   "content",
					Fields: []*pb.TelemetryField{numericTelemetryField("bytes-received")},
				},
			},
		}},
	}

	metrics, err := service.convertToOTELMetrics(telemetry, time.Unix(1, 0))
	require.NoError(t, err)
	metricSlice := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	require.Equal(t, 1, metricSlice.Len())
	metric := metricSlice.At(0)
	assert.Equal(t, "cisco.bytes-received", metric.Name())
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	dp := metric.Gauge().DataPoints().At(0)
	assert.Equal(t, uint64(2_000_000_000), uint64(dp.Timestamp()))
	interfaceName, ok := dp.Attributes().Get("interface-name")
	require.True(t, ok)
	assert.Equal(t, "GigabitEthernet0/0/0/0", interfaceName.Str())
	interfaceAlias, ok := dp.Attributes().Get("interface")
	require.True(t, ok)
	assert.Equal(t, "GigabitEthernet0/0/0/0", interfaceAlias.Str())
	sourcePath, ok := dp.Attributes().Get("cisco.yang.source_path")
	require.True(t, ok)
	assert.Equal(t, "content/bytes-received", sourcePath.Str())
}

func TestConversionUsesYANGTypeAndSafeCounterTimestamp(t *testing.T) {
	service := newLimitsTestService(t)
	telemetry := &pb.Telemetry{
		NodeId:       &pb.Telemetry_NodeIdStr{NodeIdStr: "router-1"},
		EncodingPath: "Cisco-IOS-XE-interfaces-oper:interfaces/interface/statistics",
		MsgTimestamp: 1234,
		DataGpbkv:    []*pb.TelemetryField{numericTelemetryField("in-octets")},
	}

	metrics, err := service.convertToOTELMetrics(telemetry, time.Unix(1, 0))
	require.NoError(t, err)
	metric := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0)
	require.Equal(t, pmetric.MetricTypeSum, metric.Type())
	assert.Equal(t, "bytes", metric.Unit())
	dp := metric.Sum().DataPoints().At(0)
	assert.Equal(t, uint64(1_234_000_000), uint64(dp.Timestamp()))
	assert.LessOrEqual(t, uint64(dp.StartTimestamp()), uint64(dp.Timestamp()))
}

func TestConversionPreservesInt64AndRejectsNonFiniteValues(t *testing.T) {
	service := newLimitsTestService(t)
	telemetry := &pb.Telemetry{
		NodeId:       &pb.Telemetry_NodeIdStr{NodeIdStr: "router-1"},
		MsgTimestamp: 1,
		DataGpbkv: []*pb.TelemetryField{{
			Name:        "large-counter",
			ValueByType: &pb.TelemetryField_Sint64Value{Sint64Value: math.MaxInt64},
		}},
	}

	metrics, err := service.convertToOTELMetrics(telemetry, time.Unix(1, 0))
	require.NoError(t, err)
	dp := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Gauge().DataPoints().At(0)
	require.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
	assert.Equal(t, int64(math.MaxInt64), dp.IntValue())

	telemetry.DataGpbkv[0] = &pb.TelemetryField{
		Name:        "unsigned-out-of-range",
		ValueByType: &pb.TelemetryField_Uint64Value{Uint64Value: uint64(math.MaxInt64) + 1},
	}
	metrics, err = service.convertToOTELMetrics(telemetry, time.Unix(1, 0))
	require.NoError(t, err)
	overflowMetric := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0)
	assert.Equal(t, "cisco.unsigned-out-of-range_info", overflowMetric.Name())
	dp = overflowMetric.Gauge().DataPoints().At(0)
	assert.Equal(t, pmetric.NumberDataPointValueTypeDouble, dp.ValueType())
	value, ok := dp.Attributes().Get("value")
	require.True(t, ok)
	assert.Equal(t, "9223372036854775808", value.Str())
	valueType, ok := dp.Attributes().Get("cisco.value.type")
	require.True(t, ok)
	assert.Equal(t, "uint64", valueType.Str())

	telemetry.DataGpbkv[0] = &pb.TelemetryField{
		Name:        "invalid",
		ValueByType: &pb.TelemetryField_DoubleValue{DoubleValue: math.Inf(1)},
	}
	_, err = service.convertToOTELMetrics(telemetry, time.Unix(1, 0))
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestProcessTelemetryDataPropagatesStreamContext(t *testing.T) {
	const contextValue = "stream-context"
	consumer := &capturingMetricsConsumer{}
	receiver := createMetricsReceiver(t.Context(), createTestSettings(), createValidTestConfig(), consumer).(*yangReceiver)
	service := &grpcService{receiver: receiver, yangParser: internal.NewYANGParser()}
	payload, err := proto.Marshal(&pb.Telemetry{MsgTimestamp: 1})
	require.NoError(t, err)
	ctx := context.WithValue(t.Context(), contextCaptureKey{}, contextValue)

	require.NoError(t, service.processTelemetryData(ctx, &pb.MdtDialoutArgs{Data: payload}))
	assert.Equal(t, contextValue, consumer.contextValue)

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	err = service.processTelemetryData(canceled, &pb.MdtDialoutArgs{Data: payload})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func newLimitsTestService(t *testing.T) *grpcService {
	t.Helper()
	receiver := createMetricsReceiver(t.Context(), createTestSettings(), createValidTestConfig(), &capturingMetricsConsumer{}).(*yangReceiver)
	parser := internal.NewYANGParser()
	parser.LoadBuiltinModules()
	return &grpcService{receiver: receiver, yangParser: parser}
}

func numericTelemetryField(name string) *pb.TelemetryField {
	return &pb.TelemetryField{Name: name, ValueByType: &pb.TelemetryField_Uint64Value{Uint64Value: 1}}
}

func testNumberDataPointValue(dp pmetric.NumberDataPoint) float64 {
	if dp.ValueType() == pmetric.NumberDataPointValueTypeInt {
		return float64(dp.IntValue())
	}
	return dp.DoubleValue()
}

type contextCaptureKey struct{}

type capturingMetricsConsumer struct {
	contextValue any
}

func (*capturingMetricsConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (c *capturingMetricsConsumer) ConsumeMetrics(ctx context.Context, _ pmetric.Metrics) error {
	c.contextValue = ctx.Value(contextCaptureKey{})
	return ctx.Err()
}
