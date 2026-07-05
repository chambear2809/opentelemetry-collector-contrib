// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

type gnmiTelemetry struct {
	builder *componentmetadata.TelemetryBuilder
	stop    sync.Once
	mu      sync.Mutex
	streams map[string]int64
}

func (t *gnmiTelemetry) shutdown() {
	if t != nil && t.builder != nil {
		t.stop.Do(t.builder.Shutdown)
	}
}

func gnmiTargetAttributes(target string) []attribute.KeyValue {
	return []attribute.KeyValue{attribute.String("cisco.gnmi.target", target)}
}

func gnmiProfileAttributes(target, profile string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("cisco.gnmi.target", target),
		attribute.String("cisco.gnmi.profile", profile),
	}
}

func (t *gnmiTelemetry) connection(ctx context.Context, target string, connected bool) {
	if t == nil || t.builder == nil {
		return
	}
	value := int64(0)
	if connected {
		value = 1
	}
	t.builder.CiscoosreceiverGnmiConnections.Record(ctx, value, metric.WithAttributes(gnmiTargetAttributes(target)...))
}

func (t *gnmiTelemetry) subscription(ctx context.Context, target, profile string, active bool) {
	if t == nil || t.builder == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.streams == nil {
		t.streams = map[string]int64{}
	}
	key := sharedGNMITelemetryStreamKey(target, profile)
	if active {
		t.streams[key]++
	} else if t.streams[key] > 0 {
		t.streams[key]--
	}
	t.builder.CiscoosreceiverGnmiSubscriptions.Record(ctx, t.streams[key], metric.WithAttributes(gnmiProfileAttributes(target, profile)...))
}

func sharedGNMITelemetryStreamKey(target, profile string) string {
	var key strings.Builder
	appendSharedGNMIKeyPart(&key, target)
	appendSharedGNMIKeyPart(&key, profile)
	return key.String()
}

func (t *gnmiTelemetry) updates(ctx context.Context, target, profile string, count int) {
	if t != nil && t.builder != nil && count > 0 {
		t.builder.CiscoosreceiverGnmiUpdates.Add(ctx, int64(count), metric.WithAttributes(gnmiProfileAttributes(target, profile)...))
	}
}

func (t *gnmiTelemetry) duplicates(ctx context.Context, target, profile string, count int) {
	if t != nil && t.builder != nil && count > 0 {
		t.builder.CiscoosreceiverGnmiDuplicateUpdates.Add(ctx, int64(count), metric.WithAttributes(gnmiProfileAttributes(target, profile)...))
	}
}

func (t *gnmiTelemetry) decodeErrors(ctx context.Context, target, profile string, count int) {
	if t != nil && t.builder != nil && count > 0 {
		t.builder.CiscoosreceiverGnmiDecodeErrors.Add(ctx, int64(count), metric.WithAttributes(gnmiProfileAttributes(target, profile)...))
	}
}

func (t *gnmiTelemetry) unmapped(ctx context.Context, target, profile string, count int) {
	if t != nil && t.builder != nil && count > 0 {
		t.builder.CiscoosreceiverGnmiUnmappedValues.Add(ctx, int64(count), metric.WithAttributes(gnmiProfileAttributes(target, profile)...))
	}
}

func (t *gnmiTelemetry) unsupportedValueKind(ctx context.Context, target, profile, kind string, count int) {
	if t == nil || t.builder == nil || count <= 0 || !validGNMIUnsupportedValueKind(kind) {
		return
	}
	t.builder.CiscoosreceiverGnmiUnsupportedValueKinds.Add(ctx, int64(count), metric.WithAttributes(
		attribute.String("cisco.gnmi.target", target),
		attribute.String("cisco.gnmi.profile", profile),
		attribute.String("cisco.gnmi.value_kind", kind),
	))
}

func validGNMIUnsupportedValueKind(kind string) bool {
	switch kind {
	case "any", "bytes", "leaflist", "proto_bytes":
		return true
	default:
		return false
	}
}

func (t *gnmiTelemetry) cacheOwnerReset(ctx context.Context, target, profile string) {
	if t != nil && t.builder != nil {
		t.builder.CiscoosreceiverGnmiCacheOwnerResets.Add(ctx, 1, metric.WithAttributes(gnmiProfileAttributes(target, profile)...))
	}
}

func (t *gnmiTelemetry) invalidTimestamps(ctx context.Context, target, profile string, count int) {
	if t != nil && t.builder != nil && count > 0 {
		t.builder.CiscoosreceiverGnmiInvalidTimestamps.Add(ctx, int64(count), metric.WithAttributes(gnmiProfileAttributes(target, profile)...))
	}
}

func (t *gnmiTelemetry) deletes(ctx context.Context, target, profile string, count int) {
	if t != nil && t.builder != nil && count > 0 {
		t.builder.CiscoosreceiverGnmiDeletes.Add(ctx, int64(count), metric.WithAttributes(gnmiProfileAttributes(target, profile)...))
	}
}

func boundedStateUtilization(currentCount, maximumCount int, currentBytes, maximumBytes int64) float64 {
	utilization := 0.0
	if maximumCount > 0 {
		utilization = float64(currentCount) / float64(maximumCount)
	}
	if maximumBytes > 0 {
		utilization = max(utilization, float64(currentBytes)/float64(maximumBytes))
	}
	return min(max(utilization, 0), 1)
}

func (t *gnmiTelemetry) cacheUtilization(
	ctx context.Context,
	target string,
	currentCount, maximumCount int,
	currentBytes, maximumBytes int64,
) {
	if t == nil || t.builder == nil || (maximumCount <= 0 && maximumBytes <= 0) {
		return
	}
	t.builder.CiscoosreceiverGnmiCacheUtilization.Record(
		ctx,
		boundedStateUtilization(currentCount, maximumCount, currentBytes, maximumBytes),
		metric.WithAttributes(gnmiTargetAttributes(target)...),
	)
}

func (t *gnmiTelemetry) auxiliaryStateUtilization(
	ctx context.Context,
	target string,
	currentCount, maximumCount int,
	currentBytes, maximumBytes int64,
) {
	if t == nil || t.builder == nil || (maximumCount <= 0 && maximumBytes <= 0) {
		return
	}
	t.builder.CiscoosreceiverGnmiAuxiliaryStateUtilization.Record(
		ctx,
		boundedStateUtilization(currentCount, maximumCount, currentBytes, maximumBytes),
		metric.WithAttributes(gnmiTargetAttributes(target)...),
	)
}

func (t *gnmiTelemetry) auxiliaryCapacityUtilization(ctx context.Context, target string, capacity *internalgnmi.CapacityError) {
	if capacity == nil {
		return
	}
	t.auxiliaryStateUtilization(
		ctx,
		target,
		capacity.Current,
		capacity.Limit,
		capacity.CurrentRetainedBytes,
		capacity.RetainedByteLimit,
	)
}

func (t *gnmiTelemetry) consumerRefusal(ctx context.Context, target, profile string) {
	if t != nil && t.builder != nil {
		t.builder.CiscoosreceiverGnmiConsumerRefusals.Add(ctx, 1, metric.WithAttributes(gnmiProfileAttributes(target, profile)...))
	}
}

func (t *gnmiTelemetry) reconnect(ctx context.Context, target string) {
	if t != nil && t.builder != nil {
		t.builder.CiscoosreceiverGnmiReconnects.Add(ctx, 1, metric.WithAttributes(gnmiTargetAttributes(target)...))
	}
}

func (t *gnmiTelemetry) authenticationFailure(ctx context.Context, target string) {
	if t != nil && t.builder != nil {
		t.builder.CiscoosreceiverGnmiAuthenticationFailures.Add(ctx, 1, metric.WithAttributes(gnmiTargetAttributes(target)...))
	}
}

func (t *gnmiTelemetry) productVerified(ctx context.Context, target string, verified bool) {
	if t == nil || t.builder == nil {
		return
	}
	value := int64(0)
	if verified {
		value = 1
	}
	t.builder.CiscoosreceiverGnmiProductVerified.Record(ctx, value, metric.WithAttributes(gnmiTargetAttributes(target)...))
}

func (t *gnmiTelemetry) preflightFailure(ctx context.Context, target, reason string) {
	if t == nil || t.builder == nil || !validGNMIPreflightFailureReason(reason) {
		return
	}
	t.builder.CiscoosreceiverGnmiPreflightFailures.Add(ctx, 1, metric.WithAttributes(
		attribute.String("cisco.gnmi.target", target),
		attribute.String("cisco.gnmi.reason", reason),
	))
}

func (t *gnmiTelemetry) success(ctx context.Context, target, profile string, when time.Time) {
	if t != nil && t.builder != nil {
		t.builder.CiscoosreceiverGnmiLastSuccessUnixtime.Record(ctx, when.Unix(), metric.WithAttributes(gnmiProfileAttributes(target, profile)...))
	}
}

func (t *gnmiTelemetry) degraded(ctx context.Context, target, profile, reason string, degraded bool) {
	if t == nil || t.builder == nil {
		return
	}
	value := int64(0)
	if degraded {
		value = 1
	}
	t.builder.CiscoosreceiverGnmiProfileDegraded.Record(ctx, value, metric.WithAttributes(
		attribute.String("cisco.gnmi.target", target),
		attribute.String("cisco.gnmi.profile", profile),
		attribute.String("cisco.gnmi.reason", reason),
	))
}
