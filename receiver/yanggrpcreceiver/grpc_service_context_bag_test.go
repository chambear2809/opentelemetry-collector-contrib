// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package yanggrpcreceiver

import (
	"maps"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"google.golang.org/protobuf/proto"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver/internal"
	pb "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver/internal/proto/generated/proto"
)

func TestGrpcService_ProcessTelemetryData_ContextBagAttributes(t *testing.T) {
	tests := []struct {
		name               string
		telemetry          *pb.Telemetry
		expectedDatapoints map[string]map[string]string
	}{
		{
			name: "copies only explicit list keys onto step and numeric metrics",
			telemetry: &pb.Telemetry{
				NodeId:       &pb.Telemetry_NodeIdStr{NodeIdStr: "test-node-1"},
				EncodingPath: "Cisco-IOS-XE-interfaces-oper:interfaces/interface/statistics",
				MsgTimestamp: uint64(time.Date(2026, time.May, 28, 12, 0, 0, 0, time.UTC).UnixMilli()),
				DataGpbkv: []*pb.TelemetryField{
					{
						Name: "interface",
						Fields: []*pb.TelemetryField{
							{
								Name: "keys",
								Fields: []*pb.TelemetryField{
									{
										Name: "interface-name",
										ValueByType: &pb.TelemetryField_StringValue{
											StringValue: "GigabitEthernet0/0/1",
										},
									},
									{
										Name: "name",
										ValueByType: &pb.TelemetryField_StringValue{
											StringValue: "GigabitEthernet0/0/1",
										},
									},
								},
							},
							{
								Name: "content",
								Fields: []*pb.TelemetryField{
									{
										Name: "admin-status",
										ValueByType: &pb.TelemetryField_StringValue{
											StringValue: "up",
										},
									},
									{
										Name: "rx-pkts",
										ValueByType: &pb.TelemetryField_Uint64Value{
											Uint64Value: 1234567,
										},
									},
								},
							},
						},
					},
				},
			},
			expectedDatapoints: map[string]map[string]string{
				"cisco.interface.content.admin-status_info": {
					"node_id":                "test-node-1",
					"interface-name":         "GigabitEthernet0/0/1",
					"interface":              "GigabitEthernet0/0/1",
					"name":                   "GigabitEthernet0/0/1",
					"cisco.yang.source_path": "interface/content/admin-status",
					"value":                  "up",
				},
				"cisco.interface.content.rx-pkts": {
					"node_id":                "test-node-1",
					"interface-name":         "GigabitEthernet0/0/1",
					"interface":              "GigabitEthernet0/0/1",
					"name":                   "GigabitEthernet0/0/1",
					"cisco.yang.source_path": "interface/content/rx-pkts",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createValidTestConfig()
			consumer := &consumertest.MetricsSink{}
			settings := createTestSettings()
			receiver := createMetricsReceiver(t.Context(), settings, config, consumer)

			yangParser := internal.NewYANGParser()
			yangParser.LoadBuiltinModules()
			service := &grpcService{
				receiver:   receiver.(*yangReceiver),
				yangParser: yangParser,
			}

			data, err := proto.Marshal(tt.telemetry)
			require.NoError(t, err)

			req := &pb.MdtDialoutArgs{ReqId: 1, Data: data}
			require.NoError(t, service.processTelemetryData(t.Context(), req))

			emitted := consumer.AllMetrics()
			require.Len(t, emitted, 1)

			resourceMetrics := emitted[0].ResourceMetrics()
			require.Equal(t, 1, resourceMetrics.Len())

			scopeMetrics := resourceMetrics.At(0).ScopeMetrics()
			require.Equal(t, 1, scopeMetrics.Len())

			metrics := scopeMetrics.At(0).Metrics()
			require.Equal(t, len(tt.expectedDatapoints), metrics.Len())

			seen := make(map[string]struct{}, metrics.Len())
			for i := 0; i < metrics.Len(); i++ {
				metric := metrics.At(i)
				expectedAttrs, ok := tt.expectedDatapoints[metric.Name()]
				require.Truef(t, ok, "unexpected metric emitted: %s", metric.Name())

				seen[metric.Name()] = struct{}{}
				assertMetricDatapointsHaveAttributes(t, metric, expectedAttrs)
			}

			require.Len(t, seen, len(tt.expectedDatapoints))
		})
	}
}

func TestGrpcService_ConvertToOTELMetrics_ScopesKeysToRepeatedListInstance(t *testing.T) {
	listEntry := func(name string, packets uint64) *pb.TelemetryField {
		return &pb.TelemetryField{
			Name: "interface",
			Fields: []*pb.TelemetryField{
				{
					Name: "keys",
					Fields: []*pb.TelemetryField{{
						Name:        "interface-name",
						ValueByType: &pb.TelemetryField_StringValue{StringValue: name},
					}},
				},
				{
					Name: "content",
					Fields: []*pb.TelemetryField{{
						Name:        "rx-pkts",
						ValueByType: &pb.TelemetryField_Uint64Value{Uint64Value: packets},
					}},
				},
			},
		}
	}
	telemetry := &pb.Telemetry{
		NodeId:       &pb.Telemetry_NodeIdStr{NodeIdStr: "test-node-1"},
		EncodingPath: "Cisco-IOS-XE-interfaces-oper:interfaces/interface/statistics",
		DataGpbkv: []*pb.TelemetryField{{
			Name:   "interfaces",
			Fields: []*pb.TelemetryField{listEntry("GigabitEthernet0/0/1", 1), listEntry("GigabitEthernet0/0/2", 2)},
		}},
	}

	metrics, err := (&grpcService{}).convertToOTELMetrics(telemetry, time.Now())
	require.NoError(t, err)
	scopeMetrics := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	require.Equal(t, 2, scopeMetrics.Len())

	seen := map[string]int64{}
	for i := 0; i < scopeMetrics.Len(); i++ {
		metric := scopeMetrics.At(i)
		require.Equal(t, "cisco.interfaces.interface.content.rx-pkts", metric.Name())
		dp := metric.Gauge().DataPoints().At(0)
		name, ok := dp.Attributes().Get("interface-name")
		require.True(t, ok)
		seen[name.Str()] = dp.IntValue()
	}
	require.Equal(t, map[string]int64{
		"GigabitEthernet0/0/1": 1,
		"GigabitEthernet0/0/2": 2,
	}, seen)
}

func TestGrpcService_ConvertToOTELMetrics_PreservesNumericListKeys(t *testing.T) {
	listEntry := func(index uint32, packets uint64) *pb.TelemetryField {
		return &pb.TelemetryField{
			Name: "queue",
			Fields: []*pb.TelemetryField{
				{
					Name: "keys",
					Fields: []*pb.TelemetryField{{
						Name:        "index",
						ValueByType: &pb.TelemetryField_Uint32Value{Uint32Value: index},
					}},
				},
				{
					Name: "content",
					Fields: []*pb.TelemetryField{{
						Name:        "packets",
						ValueByType: &pb.TelemetryField_Uint64Value{Uint64Value: packets},
					}},
				},
			},
		}
	}
	telemetry := &pb.Telemetry{
		NodeId:       &pb.Telemetry_NodeIdStr{NodeIdStr: "test-node-1"},
		EncodingPath: "Cisco-IOS-XR-qos-ma-oper:qos/nodes/node/policy-map/interface-table/interface/input/service-policy-names/service-policy-instance/statistics/class-stats/class-stat/queue-stats",
		DataGpbkv: []*pb.TelemetryField{{
			Name:   "queues",
			Fields: []*pb.TelemetryField{listEntry(0, 10), listEntry(1, 20)},
		}},
	}

	metrics, err := (&grpcService{}).convertToOTELMetrics(telemetry, time.Now())
	require.NoError(t, err)
	items := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	require.Equal(t, 2, items.Len())

	seen := map[string]int64{}
	for i := 0; i < items.Len(); i++ {
		metric := items.At(i)
		require.Equal(t, "cisco.queues.queue.content.packets", metric.Name())
		datapoint := metric.Gauge().DataPoints().At(0)
		index, ok := datapoint.Attributes().Get("index")
		require.True(t, ok)
		seen[index.Str()] = datapoint.IntValue()
	}
	require.Equal(t, map[string]int64{"0": 10, "1": 20}, seen)
}

func TestGrpcService_ConvertToOTELMetrics_PreservesReservedAndNestedListKeys(t *testing.T) {
	telemetry := &pb.Telemetry{
		NodeId: &pb.Telemetry_NodeIdStr{NodeIdStr: "trusted-node"},
		DataGpbkv: []*pb.TelemetryField{{
			Name: "outer",
			Fields: []*pb.TelemetryField{
				{
					Name: "keys",
					Fields: []*pb.TelemetryField{
						{Name: "node_id", ValueByType: &pb.TelemetryField_StringValue{StringValue: "list-node"}},
						{Name: "value", ValueByType: &pb.TelemetryField_StringValue{StringValue: "list-value"}},
						{Name: "cisco.value.type", ValueByType: &pb.TelemetryField_StringValue{StringValue: "list-type"}},
						{Name: "name", ValueByType: &pb.TelemetryField_StringValue{StringValue: "outer-name"}},
					},
				},
				{
					Name: "inner",
					Fields: []*pb.TelemetryField{
						{
							Name: "keys",
							Fields: []*pb.TelemetryField{{
								Name:        "name",
								ValueByType: &pb.TelemetryField_StringValue{StringValue: "inner-name"},
							}},
						},
						{
							Name: "content",
							Fields: []*pb.TelemetryField{
								{Name: "state", ValueByType: &pb.TelemetryField_StringValue{StringValue: "up"}},
								{Name: "sequence", ValueByType: &pb.TelemetryField_Uint64Value{Uint64Value: math.MaxInt64 + 1}},
							},
						},
					},
				},
			},
		}},
	}

	service := &grpcService{limits: telemetryConversionLimits{MaxAttrsPerMetric: 11}}
	metrics, err := service.convertToOTELMetrics(telemetry, time.Now())
	require.NoError(t, err)
	items := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	require.Equal(t, 2, items.Len())

	wantListKeys := map[string]string{
		"node_id":                    "trusted-node",
		"cisco.key.node_id":          "list-node",
		"cisco.key.value":            "list-value",
		"cisco.key.cisco.value.type": "list-type",
		"name":                       "outer-name",
		"interface":                  "outer-name",
		"cisco.key.name":             "inner-name",
		"cisco.key.interface":        "inner-name",
	}

	for i := 0; i < items.Len(); i++ {
		metric := items.At(i)
		switch metric.Name() {
		case "cisco.outer.inner.content.state_info":
			want := make(map[string]string, len(wantListKeys)+1)
			maps.Copy(want, wantListKeys)
			want["cisco.yang.source_path"] = "outer/inner/content/state"
			want["value"] = "up"
			assertMetricDatapointsHaveAttributes(t, metric, want)
		case "cisco.outer.inner.content.sequence_info":
			want := make(map[string]string, len(wantListKeys)+2)
			maps.Copy(want, wantListKeys)
			want["cisco.yang.source_path"] = "outer/inner/content/sequence"
			want["value"] = "9223372036854775808"
			want["cisco.value.type"] = "uint64"
			assertMetricDatapointsHaveAttributes(t, metric, want)
		default:
			require.Failf(t, "unexpected metric", "metric %q was not expected", metric.Name())
		}
	}
}

func TestGrpcService_ConvertToOTELMetricsPreservesInjectiveSourcePaths(t *testing.T) {
	telemetry := &pb.Telemetry{
		NodeId: &pb.Telemetry_NodeIdStr{NodeIdStr: "router-1"},
		DataGpbkv: []*pb.TelemetryField{
			{Name: "foo-bar", ValueByType: &pb.TelemetryField_Uint64Value{Uint64Value: 1}},
			{Name: "foo_bar", ValueByType: &pb.TelemetryField_Uint64Value{Uint64Value: 2}},
			{Name: "nested", Fields: []*pb.TelemetryField{{Name: "leaf", ValueByType: &pb.TelemetryField_Uint64Value{Uint64Value: 3}}}},
			{Name: "nested.leaf", ValueByType: &pb.TelemetryField_Uint64Value{Uint64Value: 4}},
		},
	}

	metrics, err := (&grpcService{}).convertToOTELMetrics(telemetry, time.Now())
	require.NoError(t, err)
	items := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	require.Equal(t, 4, items.Len())
	seen := map[string]map[string]struct{}{}
	for index := 0; index < items.Len(); index++ {
		metric := items.At(index)
		dp := metric.Gauge().DataPoints().At(0)
		path, ok := dp.Attributes().Get("cisco.yang.source_path")
		require.True(t, ok)
		if seen[metric.Name()] == nil {
			seen[metric.Name()] = map[string]struct{}{}
		}
		seen[metric.Name()][path.Str()] = struct{}{}
	}
	require.Equal(t, map[string]map[string]struct{}{
		"cisco.foo-bar": {"foo-bar": {}},
		"cisco.foo_bar": {"foo_bar": {}},
		"cisco.nested.leaf": {
			"nested/leaf": {},
			"nested.leaf": {},
		},
	}, seen)
}

func TestExtractKeyAttributesIsOrderIndependentAndReservesEscapeNamespace(t *testing.T) {
	fields := []*pb.TelemetryField{
		{Name: "node_id", ValueByType: &pb.TelemetryField_StringValue{StringValue: "list-node"}},
		{Name: "cisco.key.node_id", ValueByType: &pb.TelemetryField_StringValue{StringValue: "literal-prefixed-key"}},
		{Name: "empty", ValueByType: &pb.TelemetryField_StringValue{}},
		{Name: "name", ValueByType: &pb.TelemetryField_StringValue{StringValue: "zebra"}},
		{Name: "name", ValueByType: &pb.TelemetryField_StringValue{StringValue: "alpha"}},
		{Name: "cisco.yang.source_path", ValueByType: &pb.TelemetryField_StringValue{StringValue: "device-controlled"}},
		{Name: "cisco.yang.path", ValueByType: &pb.TelemetryField_StringValue{StringValue: "device-path"}},
		{Name: "cisco.yang.module", ValueByType: &pb.TelemetryField_StringValue{StringValue: "device-module"}},
		{Name: "cisco.telemetry.transport", ValueByType: &pb.TelemetryField_StringValue{StringValue: "device-transport"}},
	}
	convert := func(fields []*pb.TelemetryField) map[string]string {
		ctx := map[string]string{"node_id": "trusted-node"}
		limits := (telemetryConversionLimits{MaxAttrsPerMetric: 16}).withDefaults()
		budget := &telemetryConversionBudget{limits: limits}
		require.NoError(t, extractKeyAttributes(&pb.TelemetryField{Name: "keys", Fields: fields}, ctx, 1, budget))
		return ctx
	}

	forward := convert(fields)
	reversed := convert([]*pb.TelemetryField{fields[8], fields[7], fields[6], fields[5], fields[4], fields[3], fields[2], fields[1], fields[0]})
	require.Equal(t, forward, reversed)
	require.Equal(t, map[string]string{
		"node_id":                             "trusted-node",
		"cisco.key.node_id":                   "list-node",
		"cisco.key.cisco.key.node_id":         "literal-prefixed-key",
		"empty":                               "",
		"name":                                "alpha",
		"cisco.key.name":                      "zebra",
		"interface":                           "alpha",
		"cisco.key.interface":                 "zebra",
		"cisco.key.cisco.yang.source_path":    "device-controlled",
		"cisco.key.cisco.yang.path":           "device-path",
		"cisco.key.cisco.yang.module":         "device-module",
		"cisco.key.cisco.telemetry.transport": "device-transport",
	}, forward)
	attrs := pcommon.NewMap()
	applyCtxBag(attrs, forward)
	empty, ok := attrs.Get("empty")
	require.True(t, ok)
	require.Empty(t, empty.Str())
}

func assertMetricDatapointsHaveAttributes(t *testing.T, metric pmetric.Metric, expectedAttrs map[string]string) {
	t.Helper()

	var datapoints pmetric.NumberDataPointSlice
	switch metric.Type() {
	case pmetric.MetricTypeGauge:
		datapoints = metric.Gauge().DataPoints()
	case pmetric.MetricTypeSum:
		datapoints = metric.Sum().DataPoints()
	default:
		require.Failf(t, "unexpected metric type", "metric %q has type %v", metric.Name(), metric.Type())
	}

	require.Positive(t, datapoints.Len(), "expected datapoints for metric %q", metric.Name())
	for i := 0; i < datapoints.Len(); i++ {
		attrs := datapoints.At(i).Attributes()
		require.Equal(t, len(expectedAttrs), attrs.Len(), "unexpected attribute set for metric %q", metric.Name())

		for key, want := range expectedAttrs {
			got, ok := attrs.Get(key)
			require.Truef(t, ok, "missing attribute %q on metric %q", key, metric.Name())

			if got.Type() == pcommon.ValueTypeStr {
				require.Equalf(t, want, got.Str(), "unexpected value for attribute %q on metric %q", key, metric.Name())
				continue
			}

			require.Equalf(t, want, got.AsString(), "unexpected value for attribute %q on metric %q", key, metric.Name())
		}
	}
}
