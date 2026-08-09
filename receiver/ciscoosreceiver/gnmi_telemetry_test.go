// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestBoundedStateUtilizationUsesMostConstrainedBudget(t *testing.T) {
	assert.InDelta(t, 0.8, boundedStateUtilization(8, 10, 5, 10), 0.0001)
	assert.InDelta(t, 0.9, boundedStateUtilization(1, 10, 9, 10), 0.0001)
	assert.InDelta(t, 1.0, boundedStateUtilization(11, 10, 1, 10), 0.0001)
	assert.InDelta(t, 0.0, boundedStateUtilization(-1, 10, -1, 10), 0.0001)
	assert.InDelta(t, 0.0, boundedStateUtilization(1, 0, 1, 0), 0.0001)
}

func TestGNMITelemetryStreamKeyRejectsNULBoundaryCollision(t *testing.T) {
	assert.NotEqual(t,
		sharedGNMITelemetryStreamKey("target\x00profile", "one"),
		sharedGNMITelemetryStreamKey("target", "profile\x00one"),
	)
}

func TestGNMIStateUtilizationIsTargetLabeledAndByteAware(t *testing.T) {
	telemetry := componenttest.NewTelemetry()
	builder, err := componentmetadata.NewTelemetryBuilder(telemetry.NewTelemetrySettings())
	require.NoError(t, err)
	t.Cleanup(func() {
		builder.Shutdown()
		require.NoError(t, telemetry.Shutdown(context.WithoutCancel(t.Context())))
	})

	tel := &gnmiTelemetry{builder: builder}
	tel.cacheUtilization(t.Context(), "target-a", 2, 10, 8, 10)
	tel.cacheUtilization(t.Context(), "target-b", 5, 10, 1, 10)
	tel.auxiliaryStateUtilization(t.Context(), "target-a", 3, 4, 1, 10)
	tel.auxiliaryCapacityUtilization(t.Context(), "rejected-aux", &internalgnmi.CapacityError{
		Current: 2, Requested: 100, Limit: 10,
		CurrentRetainedBytes: 1, RequestedRetainedBytes: 100, RetainedByteLimit: 10,
	})

	assert.Equal(t, map[string]float64{"target-a": 0.8, "target-b": 0.5},
		telemetryGaugeByTarget(t, telemetry, "otelcol_ciscoosreceiver_gnmi_cache_utilization"))
	assert.Equal(t, map[string]float64{"rejected-aux": 0.2, "target-a": 0.75},
		telemetryGaugeByTarget(t, telemetry, "otelcol_ciscoosreceiver_gnmi_auxiliary_state_utilization"))
}

func TestClearTargetNXSensorStateRecordsReleasedAuxiliaryCapacity(t *testing.T) {
	telemetry := componenttest.NewTelemetry()
	builder, err := componentmetadata.NewTelemetryBuilder(telemetry.NewTelemetrySettings())
	require.NoError(t, err)
	t.Cleanup(func() {
		builder.Shutdown()
		require.NoError(t, telemetry.Shutdown(context.WithoutCancel(t.Context())))
	})

	state := nxSensorState{description: "temperature", unit: "celsius"}
	states := map[string]nxSensorState{"sensor-1": state}
	usage := estimateSharedGNMINXSensorUsage(states)
	budget := newSharedGNMIAuxiliaryBudgetWithLimits(10, usage.bytes*2)
	budget.used = usage.count
	budget.usedBytes = usage.bytes
	target := &sharedGNMITargetRuntime{
		config:    GNMITargetConfig{Name: "nx-cleanup"},
		nxSensors: states,
		nxBudget:  budget,
	}
	receiver := &sharedGNMIReceiver{telemetry: &gnmiTelemetry{builder: builder}}

	receiver.clearTargetNXSensorState(t.Context(), target)

	assert.Empty(t, target.nxSensors)
	assert.Zero(t, target.nxBudget.used)
	assert.Equal(t, map[string]float64{"nx-cleanup": 0},
		telemetryGaugeByTarget(t, telemetry, "otelcol_ciscoosreceiver_gnmi_auxiliary_state_utilization"))
}

func TestGNMISubscribeParityTelemetryUsesBoundedAttributes(t *testing.T) {
	telemetry := componenttest.NewTelemetry()
	builder, err := componentmetadata.NewTelemetryBuilder(telemetry.NewTelemetrySettings())
	require.NoError(t, err)
	t.Cleanup(func() {
		builder.Shutdown()
		require.NoError(t, telemetry.Shutdown(context.WithoutCancel(t.Context())))
	})

	tel := &gnmiTelemetry{builder: builder}
	tel.unsupportedValueKind(t.Context(), "target-a", "interfaces", "bytes", 2)
	tel.unsupportedValueKind(t.Context(), "target-a", "interfaces", "device-controlled-kind", 100)
	tel.cacheOwnerReset(t.Context(), "target-a", "interfaces")

	unsupported, err := telemetry.GetMetric("otelcol_ciscoosreceiver_gnmi_unsupported_value_kinds")
	require.NoError(t, err)
	unsupportedSum, ok := unsupported.Data.(metricdata.Sum[int64])
	require.True(t, ok)
	require.Len(t, unsupportedSum.DataPoints, 1)
	assert.Equal(t, int64(2), unsupportedSum.DataPoints[0].Value)
	kind, exists := unsupportedSum.DataPoints[0].Attributes.Value(attribute.Key("cisco.gnmi.value_kind"))
	require.True(t, exists)
	assert.Equal(t, "bytes", kind.AsString())

	resets, err := telemetry.GetMetric("otelcol_ciscoosreceiver_gnmi_cache_owner_resets")
	require.NoError(t, err)
	resetSum, ok := resets.Data.(metricdata.Sum[int64])
	require.True(t, ok)
	require.Len(t, resetSum.DataPoints, 1)
	assert.Equal(t, int64(1), resetSum.DataPoints[0].Value)
}

func telemetryGaugeByTarget(
	t *testing.T,
	telemetry *componenttest.Telemetry,
	name string,
) map[string]float64 {
	t.Helper()
	metric, err := telemetry.GetMetric(name)
	require.NoError(t, err)
	gauge, ok := metric.Data.(metricdata.Gauge[float64])
	require.True(t, ok)
	values := make(map[string]float64, len(gauge.DataPoints))
	for _, point := range gauge.DataPoints {
		target, exists := point.Attributes.Value(attribute.Key("cisco.gnmi.target"))
		require.True(t, exists)
		values[target.AsString()] = point.Value
	}
	return values
}
