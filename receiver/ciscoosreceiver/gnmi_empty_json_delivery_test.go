// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.opentelemetry.io/otel/sdk/metric"

	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestProcessNotificationJSONContainerAtMappedScalarWithdrawsAndStaysDegraded(t *testing.T) {
	tests := []struct {
		name         string
		raw          string
		wantUnmapped int64
	}{
		{name: "empty array", raw: `[]`},
		{name: "empty object", raw: `{}`},
		{name: "nonempty object", raw: `{"child":1}`, wantUnmapped: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := metric.NewManualReader()
			provider := metric.NewMeterProvider(metric.WithReader(reader))
			t.Cleanup(func() { require.NoError(t, provider.Shutdown(context.WithoutCancel(t.Context()))) })
			settings := receivertest.NewNopSettings(componentmetadata.Type)
			settings.MeterProvider = provider
			targetConfig := GNMITargetConfig{
				Name: "empty-json-mapped", Product: gnmiProductCatalyst9300, SoftwareVersion: "17.18.1",
				AllowUnqualified: true, MaxStreams: 1, Profiles: subscriptionProfilesOnly(builtinGNMIProfileSystem),
			}
			sink := &consumertest.MetricsSink{}
			receiver, target, stream := newDeliveryTestReceiverWithSettings(t, settings, targetConfig, 10, sink)
			t1 := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
			t2 := t1.Add(time.Second)

			require.NoError(t, receiver.processNotification(
				t.Context(),
				target,
				stream,
				deliveryTestSwitchCPUValueNotification(
					t,
					t1,
					false,
					&gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{UintVal: 70}},
				),
			))
			require.Len(t, target.cache.Snapshot(), 1)
			receiver.telemetry.success(t.Context(), target.config.Name, stream.Profile, time.Unix(123, 0))

			synced, err := receiver.handleSubscribeResponse(t.Context(), target, stream, &gnmipb.SubscribeResponse{
				Response: &gnmipb.SubscribeResponse_Update{Update: deliveryTestSwitchCPUValueNotification(
					t,
					t2,
					false,
					&gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(test.raw)}},
				)},
			})
			require.NoError(t, err)
			assert.False(t, synced)
			assert.Empty(t, target.cache.Snapshot())
			assert.Equal(t, 1, target.cache.Usage().InvalidationWatermarks)
			target.qualificationMu.Lock()
			assert.False(t, target.anyProgress)
			assert.Contains(t, target.degradedQualification, stream.Profile)
			target.qualificationMu.Unlock()
			assert.False(t, target.sessionUp.Load())
			assert.Zero(t, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.device.up"))
			assert.Equal(t, int64(123), runtimeTestTelemetryIntGauge(
				t, reader, "otelcol_ciscoosreceiver_gnmi_last_success_unixtime",
			))
			assert.Equal(t, int64(1), runtimeTestTelemetryIntSum(
				t, reader, "otelcol_ciscoosreceiver_gnmi_decode_errors",
			))
			assert.Equal(t, test.wantUnmapped, runtimeTestTelemetryIntSum(
				t, reader, "otelcol_ciscoosreceiver_gnmi_unmapped_values",
			))

			synced, err = receiver.handleSubscribeResponse(t.Context(), target, stream, &gnmipb.SubscribeResponse{
				Response: &gnmipb.SubscribeResponse_Update{Update: deliveryTestSwitchCPUValueNotification(
					t,
					t2,
					false,
					&gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{UintVal: 80}},
				)},
			})
			require.NoError(t, err)
			assert.False(t, synced)
			snapshot := target.cache.Snapshot()
			require.Len(t, snapshot, 1)
			assert.InDelta(t, .8, snapshot[0].DoubleValue, 0.0001)
			assert.Zero(t, target.cache.Usage().InvalidationWatermarks)
			target.qualificationMu.Lock()
			assert.True(t, target.anyProgress)
			assert.Contains(t, target.degradedQualification, stream.Profile)
			target.qualificationMu.Unlock()
			assert.False(t, target.sessionUp.Load())
			assert.Zero(t, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.device.up"))
		})
	}
}

func TestProcessNotificationJSONUnmatchedAggregateIsBenign(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(context.WithoutCancel(t.Context()))) })
	settings := receivertest.NewNopSettings(componentmetadata.Type)
	settings.MeterProvider = provider
	targetConfig := GNMITargetConfig{
		Name: "empty-json-unmatched", Product: gnmiProductCatalyst9300, SoftwareVersion: "17.18.1",
		AllowUnqualified: true, MaxStreams: 1, Profiles: subscriptionProfilesOnly(builtinGNMIProfileInterfaces),
	}
	sink := &consumertest.MetricsSink{}
	receiver, target, stream := newDeliveryTestReceiverWithSettings(t, settings, targetConfig, 10, sink)

	synced, err := receiver.handleSubscribeResponse(t.Context(), target, stream, &gnmipb.SubscribeResponse{
		Response: &gnmipb.SubscribeResponse_Update{
			Update: emptyJSONInterfaceAggregateNotification(t, time.Now().Add(-time.Minute)),
		},
	})
	require.NoError(t, err)
	assert.False(t, synced)
	snapshot := target.cache.Snapshot()
	require.Len(t, snapshot, 1)
	assert.Equal(t, "system.network.io", snapshot[0].Metric.Name)
	assert.Equal(t, int64(5), snapshot[0].IntValue)
	assert.Zero(t, target.cache.Usage().InvalidationWatermarks)
	target.qualificationMu.Lock()
	assert.True(t, target.anyProgress)
	assert.NotContains(t, target.degradedQualification, stream.Profile)
	target.qualificationMu.Unlock()
	assert.True(t, target.sessionUp.Load())
	assert.Equal(t, 1, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.device.up"))
	assert.Zero(t, runtimeTestTelemetryIntSum(
		t, reader, "otelcol_ciscoosreceiver_gnmi_decode_errors",
	))
	assert.Zero(t, runtimeTestTelemetryIntSum(
		t, reader, "otelcol_ciscoosreceiver_gnmi_unmapped_values",
	))
	assert.Positive(t, runtimeTestTelemetryIntGauge(
		t, reader, "otelcol_ciscoosreceiver_gnmi_last_success_unixtime",
	))
	assert.Zero(t, runtimeTestTelemetryIntGauge(
		t, reader, "otelcol_ciscoosreceiver_gnmi_profile_degraded",
	))
}

func emptyJSONInterfaceAggregateNotification(t *testing.T, timestamp time.Time) *gnmipb.Notification {
	t.Helper()
	return &gnmipb.Notification{
		Timestamp: timestamp.UnixNano(),
		Prefix: &gnmipb.Path{
			Origin: builtinGNMIOriginRFC7951,
			Elem:   []*gnmipb.PathElem{{Name: "openconfig-interfaces:interfaces"}},
		},
		Update: []*gnmipb.Update{{
			Path: runtimeTestProtoPath(t, "interface[name=GigabitEthernet1/0/1]/state"),
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{
				JsonIetfVal: []byte(`{"counters":{"in-octets":5},"empty-list":[],"empty-object":{}}`),
			}},
		}},
	}
}
