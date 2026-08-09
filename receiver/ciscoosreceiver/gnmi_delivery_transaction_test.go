// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestProcessNotificationSecondChunkRefusalRollsBackAndRedeliversAllChunks(t *testing.T) {
	mapping := runtimeTestMapping("interfaces/interface/state/value", "delivery.value")
	mapping.PathKeys = map[string]string{"interface.name": "network.interface.name"}
	targetConfig := runtimeTestTarget("127.0.0.1:57400", "", gnmiModeStream, mapping)
	consumer := &deliveryTestScriptedConsumer{failCalls: map[int]struct{}{2: {}}}
	receiver, target, stream := newDeliveryTestReceiver(t, targetConfig, 1, consumer)
	timestamp := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	notification := deliveryTestInterfaceNotification(t, timestamp, false, "", "Ethernet1", "Ethernet2")

	err := receiver.processNotification(t.Context(), target, stream, notification)
	require.ErrorContains(t, err, "chunk 2 of 2")
	assert.Empty(t, target.cache.Snapshot(), "a later chunk refusal must abort the whole cache transaction")

	require.NoError(t, receiver.processNotification(t.Context(), target, stream, notification))
	assert.Len(t, target.cache.Snapshot(), 2)
	seen, accepted := consumer.snapshot()
	assert.Equal(t, []string{"Ethernet1", "Ethernet2", "Ethernet1", "Ethernet2"}, seen)
	assert.Equal(t, []string{"Ethernet1", "Ethernet1", "Ethernet2"}, accepted,
		"a chunk accepted before a later refusal is delivered at least once again on retry")
}

func TestProcessNotificationAtomicReplacementRefusalPreservesPriorState(t *testing.T) {
	mapping := runtimeTestMapping("interfaces/interface/state/value", "delivery.replacement")
	mapping.PathKeys = map[string]string{"interface.name": "network.interface.name"}
	targetConfig := runtimeTestTarget("127.0.0.1:57400", "", gnmiModeStream, mapping)
	consumer := &deliveryTestScriptedConsumer{failCalls: map[int]struct{}{2: {}}}
	receiver, target, stream := newDeliveryTestReceiver(t, targetConfig, 10, consumer)
	t1 := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	t2 := t1.Add(time.Second)

	require.NoError(t, receiver.processNotification(
		t.Context(), target, stream,
		deliveryTestInterfaceNotification(t, t1, false, "", "Ethernet1", "Ethernet2"),
	))
	err := receiver.processNotification(
		t.Context(), target, stream,
		deliveryTestInterfaceNotification(t, t2, true, "interfaces", "Ethernet3"),
	)
	require.Error(t, err)
	assert.Equal(t, []string{"Ethernet1", "Ethernet2"}, deliveryTestSnapshotInterfaces(target.cache.Snapshot()),
		"refused delete/replacement must preserve the committed snapshot")

	require.NoError(t, receiver.processNotification(
		t.Context(), target, stream,
		deliveryTestInterfaceNotification(t, t2, true, "interfaces", "Ethernet3"),
	))
	assert.Equal(t, []string{"Ethernet3"}, deliveryTestSnapshotInterfaces(target.cache.Snapshot()))
}

func TestProcessNXOpticsRefusalRollsBackCacheSensorAndPresenceState(t *testing.T) {
	consumer := &deliveryTestScriptedConsumer{failCalls: map[int]struct{}{1: {}}}
	targetConfig := GNMITargetConfig{
		Name: "nx-delivery", Platform: gnmiPlatformNXOS, MaxStreams: 1,
		Profiles: subscriptionProfilesOnly(builtinGNMIProfileOptics),
	}
	receiver, target, stream := newDeliveryTestReceiver(t, targetConfig, 10, consumer)
	timestamp := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	notification := deliveryTestNXOpticsNotification(timestamp, "1")

	require.Error(t, receiver.processNotification(t.Context(), target, stream, notification))
	assert.Empty(t, target.cache.Snapshot())
	target.nxMu.Lock()
	assert.Empty(t, target.nxSensors)
	target.nxMu.Unlock()
	target.nxBudget.mu.Lock()
	assert.Zero(t, target.nxBudget.used)
	assert.Zero(t, target.nxBudget.usedBytes)
	target.nxBudget.mu.Unlock()
	target.presenceMu.Lock()
	assert.Empty(t, target.opticalSources)
	assert.Empty(t, target.presenceCounts)
	assert.Empty(t, target.presenceAttrs)
	target.presenceMu.Unlock()

	require.NoError(t, receiver.processNotification(t.Context(), target, stream, notification))
	assert.Len(t, target.cache.Snapshot(), 1)
	target.nxMu.Lock()
	assert.Len(t, target.nxSensors, 1)
	target.nxMu.Unlock()
	target.nxBudget.mu.Lock()
	assert.Equal(t, 4, target.nxBudget.used, "one NX sensor and three optical map entries are retained")
	assert.Positive(t, target.nxBudget.usedBytes)
	target.nxBudget.mu.Unlock()
	target.presenceMu.Lock()
	assert.Len(t, target.opticalSources, 1)
	assert.Len(t, target.presenceCounts, 1)
	assert.Len(t, target.presenceAttrs, 1)
	target.presenceMu.Unlock()
}

func TestProcessNXOpticsFitsAuxiliaryMultiplierAtOneCachedSeries(t *testing.T) {
	targetConfig := GNMITargetConfig{
		Name: "nx-minimum-budget", Platform: gnmiPlatformNXOS, MaxStreams: 1,
		Profiles: subscriptionProfilesOnly(builtinGNMIProfileOptics),
	}
	config := createDefaultConfig().(*Config)
	config.GNMI = GNMIConfig{
		MaxDatapointsPerChunk: 10,
		MaxCachedSeries:       1,
		Targets:               []GNMITargetConfig{targetConfig},
	}
	created, err := newSharedGNMIReceiver(
		receivertest.NewNopSettings(componentmetadata.Type),
		config,
		&consumertest.MetricsSink{},
	)
	require.NoError(t, err)
	receiver := created.(*sharedGNMIReceiver)
	t.Cleanup(func() { require.NoError(t, receiver.Shutdown(context.WithoutCancel(t.Context()))) })
	require.Len(t, receiver.targets, 1)
	target := receiver.targets[0]
	require.Len(t, target.streams, 1)

	require.NoError(t, receiver.processNotification(
		t.Context(),
		target,
		target.streams[0],
		deliveryTestNXOpticsNotification(time.Now().Add(-time.Minute), "1"),
	))
	assert.Len(t, target.cache.Snapshot(), 1)
	assert.Len(t, target.nxSensors, 1)
	assert.Len(t, target.opticalSources, 1)
	assert.Len(t, target.presenceCounts, 1)
	assert.Len(t, target.presenceAttrs, 1)
	target.nxBudget.mu.Lock()
	assert.Equal(t, sharedGNMIAuxiliaryEntriesPerCachedSeries, target.nxBudget.maximum)
	assert.Equal(t, sharedGNMIAuxiliaryEntriesPerCachedSeries, target.nxBudget.used)
	target.nxBudget.mu.Unlock()
}

func TestProcessNXOpticsCombinesCrossComponentReplacementDeltasAtCapacity(t *testing.T) {
	targetConfig := GNMITargetConfig{
		Name: "nx-combined-budget", Platform: gnmiPlatformNXOS, MaxStreams: 1,
		Profiles: subscriptionProfilesOnly(builtinGNMIProfileOptics),
	}
	receiver, target, stream := newDeliveryTestReceiver(t, targetConfig, 10, consumertest.NewNop())
	target.nxBudget = newSharedGNMIAuxiliaryBudgetWithLimits(
		sharedGNMIAuxiliaryEntriesPerCachedSeries,
		sharedGNMIAuxiliaryRetainedBytes,
	)
	baseTime := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	recognized := func(timestamp time.Time) *gnmipb.Notification {
		return deliveryTestNXAuxiliaryReplacementNotification(timestamp, true, "1")
	}
	unknown := func(timestamp time.Time) *gnmipb.Notification {
		return deliveryTestNXAuxiliaryReplacementNotification(timestamp, false, "2", "3", "4", "5")
	}

	require.NoError(t, receiver.processNotification(t.Context(), target, stream, recognized(baseTime)))
	recognizedUsage := auxiliaryTestBudgetUsage(target.nxBudget)
	require.Equal(t, sharedGNMIAuxiliaryEntriesPerCachedSeries, recognizedUsage.count)
	require.Len(t, target.nxSensors, 1)
	require.Len(t, target.opticalSources, 1)

	// First discover the larger endpoint under the normal byte ceiling. Count
	// capacity is already full, so this also exercises optical shrink funding
	// NX growth in one combined reservation.
	require.NoError(t, receiver.processNotification(t.Context(), target, stream, unknown(baseTime.Add(time.Second))))
	unknownUsage := auxiliaryTestBudgetUsage(target.nxBudget)
	require.Equal(t, sharedGNMIAuxiliaryEntriesPerCachedSeries, unknownUsage.count)
	require.Greater(t, unknownUsage.bytes, recognizedUsage.bytes)
	require.Len(t, target.nxSensors, 4)
	require.Empty(t, target.opticalSources)

	// Pin bytes to the larger final state. Starting exactly at that ceiling,
	// NX shrink must fund optical growth; the reverse replacement must then be
	// able to grow NX while optical state is released in the same reservation.
	target.nxBudget.mu.Lock()
	target.nxBudget.maximumBytes = unknownUsage.bytes
	target.nxBudget.mu.Unlock()
	require.NoError(t, receiver.processNotification(t.Context(), target, stream, recognized(baseTime.Add(2*time.Second))))
	assert.Equal(t, recognizedUsage, auxiliaryTestBudgetUsage(target.nxBudget))
	assert.Len(t, target.nxSensors, 1)
	assert.Len(t, target.opticalSources, 1)
	assert.Len(t, target.presenceCounts, 1)
	assert.Len(t, target.presenceAttrs, 1)

	require.NoError(t, receiver.processNotification(t.Context(), target, stream, unknown(baseTime.Add(3*time.Second))))
	assert.Equal(t, unknownUsage, auxiliaryTestBudgetUsage(target.nxBudget))
	assert.Len(t, target.nxSensors, 4)
	assert.Empty(t, target.opticalSources)
	assert.Empty(t, target.presenceCounts)
	assert.Empty(t, target.presenceAttrs)
}

func TestPendingNXTransactionsDoNotHoldGlobalBudgetLock(t *testing.T) {
	budget := newSharedGNMIAuxiliaryBudget(2)
	newTarget := func(name string) *sharedGNMITargetRuntime {
		cache, err := internalgnmi.NewCache(10)
		require.NoError(t, err)
		target, err := newSharedGNMITargetRuntimeWithBudget(GNMITargetConfig{
			Name: name, Platform: gnmiPlatformNXOS, MaxStreams: 1,
			Profiles: subscriptionProfilesOnly(builtinGNMIProfileOptics),
		}, cache, budget)
		require.NoError(t, err)
		return target
	}
	notification := func(name string) internalgnmi.DecodedNotification {
		timestamp := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
		elements := []internalgnmi.PathElem{
			{Name: "sys"},
			{Name: "intf"},
			{Name: "sensor", Keys: map[string]string{"id": name}},
		}
		return internalgnmi.DecodedNotification{
			Prefix: internalgnmi.Path{Target: name, Origin: builtinGNMIOriginDME, Elements: elements}, Timestamp: timestamp,
			Updates: []internalgnmi.Point{{
				Series: internalgnmi.Series{Target: name, Origin: builtinGNMIOriginDME, Elements: elements, Leaf: "description"},
				Value:  internalgnmi.StringValue("TDECQ"), Timestamp: timestamp,
			}},
		}
	}
	first := newTarget("nx-pending-one")
	second := newTarget("nx-pending-two")
	_, firstTransaction, err := first.prepareNXNotification(notification(first.config.Name))
	require.NoError(t, err)
	require.NotNil(t, firstTransaction)
	firstReservation, err := prepareSharedGNMIAuxiliaryReservation(budget, firstTransaction.budgetDelta)
	require.NoError(t, err)
	defer firstTransaction.rollback()
	defer firstReservation.rollback()

	type transactionResult struct {
		transaction *nxSensorTransaction
		reservation *sharedGNMIAuxiliaryReservation
		err         error
	}
	secondResult := make(chan transactionResult, 1)
	go func() {
		_, transaction, prepareErr := second.prepareNXNotification(notification(second.config.Name))
		if prepareErr != nil {
			secondResult <- transactionResult{err: prepareErr}
			return
		}
		reservation, reserveErr := prepareSharedGNMIAuxiliaryReservation(budget, transaction.budgetDelta)
		secondResult <- transactionResult{transaction: transaction, reservation: reservation, err: reserveErr}
	}()
	var secondTransaction *nxSensorTransaction
	var secondReservation *sharedGNMIAuxiliaryReservation
	select {
	case result := <-secondResult:
		require.NoError(t, result.err)
		secondTransaction = result.transaction
		secondReservation = result.reservation
	case <-time.After(time.Second):
		t.Fatal("a pending target transaction held the global NX budget lock")
	}
	require.NotNil(t, secondTransaction)
	require.NotNil(t, secondReservation)
	secondTransaction.rollback()
	secondReservation.rollback()
	firstTransaction.rollback()
	firstReservation.rollback()
	budget.mu.Lock()
	assert.Zero(t, budget.used)
	budget.mu.Unlock()
}

func TestProcessNotificationProfileStopDuringDeliveryAbortsState(t *testing.T) {
	mapping := runtimeTestMapping("interfaces/interface/state/value", "delivery.stop_race")
	mapping.PathKeys = map[string]string{"interface.name": "network.interface.name"}
	targetConfig := runtimeTestTarget("127.0.0.1:57400", "", gnmiModeStream, mapping)
	consumer := &deliveryTestBlockingConsumer{started: make(chan struct{}), release: make(chan struct{})}
	receiver, target, stream := newDeliveryTestReceiver(t, targetConfig, 10, consumer)
	notification := deliveryTestInterfaceNotification(
		t, time.Now().Add(-time.Minute).Truncate(time.Millisecond), false, "", "Ethernet1",
	)
	ctx := t.Context()
	result := make(chan error, 1)
	go func() {
		result <- receiver.processNotification(ctx, target, stream, notification)
	}()

	select {
	case <-consumer.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for staged downstream delivery")
	}
	target.stopProfile(stream.Profile)
	close(consumer.release)
	require.NoError(t, <-result)
	assert.Empty(t, target.cache.Snapshot(), "a stopped profile must not publish its staged cache state")
	require.NoError(t, receiver.processNotification(t.Context(), target, stream, notification))
	assert.Equal(t, int64(1), consumer.calls.Load(), "stopped profiles must not deliver later notifications")
}

func TestProcessNotificationSerializesTargetDeliveries(t *testing.T) {
	mapping := runtimeTestMapping("interfaces/interface/state/value", "delivery.serial")
	mapping.PathKeys = map[string]string{"interface.name": "network.interface.name"}
	targetConfig := runtimeTestTarget("127.0.0.1:57400", "", gnmiModeStream, mapping)
	consumer := &deliveryTestBlockingConsumer{started: make(chan struct{}), release: make(chan struct{})}
	receiver, target, stream := newDeliveryTestReceiver(t, targetConfig, 10, consumer)
	t1 := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	firstNotification := deliveryTestInterfaceNotification(t, t1, false, "", "Ethernet1")
	secondNotification := deliveryTestInterfaceNotification(t, t1.Add(time.Second), false, "", "Ethernet2")
	ctx := t.Context()
	results := make(chan error, 2)
	go func() {
		results <- receiver.processNotification(ctx, target, stream, firstNotification)
	}()
	select {
	case <-consumer.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first target delivery")
	}
	go func() {
		results <- receiver.processNotification(ctx, target, stream, secondNotification)
	}()
	assert.Never(t, func() bool { return consumer.calls.Load() > 1 }, 100*time.Millisecond, 5*time.Millisecond)
	close(consumer.release)
	require.NoError(t, <-results)
	require.NoError(t, <-results)
	assert.Equal(t, int64(2), consumer.calls.Load())
	assert.Len(t, target.cache.Snapshot(), 2)
}

func TestProcessNotificationReceiverWideGateBoundsConcurrencyAndHonorsCancellation(t *testing.T) {
	mapping := runtimeTestMapping("interfaces/interface/state/value", "delivery.concurrent")
	mapping.PathKeys = map[string]string{"interface.name": "network.interface.name"}
	targets := make([]GNMITargetConfig, sharedGNMIMaxConcurrentDelivery+1)
	for index := range targets {
		targets[index] = runtimeTestTarget(
			fmt.Sprintf("127.0.0.1:%d", 57400+index),
			"",
			gnmiModeStream,
			mapping,
		)
		targets[index].Name = fmt.Sprintf("concurrent-%d", index)
	}
	consumer := &deliveryTestConcurrencyConsumer{
		entered: make(chan struct{}, sharedGNMIMaxConcurrentDelivery),
		release: make(chan struct{}),
	}
	config := createDefaultConfig().(*Config)
	config.GNMI = GNMIConfig{
		MaxDatapointsPerChunk: 10,
		MaxCachedSeries:       900,
		Targets:               targets,
	}
	created, err := newSharedGNMIReceiver(
		receivertest.NewNopSettings(componentmetadata.Type),
		config,
		consumer,
	)
	require.NoError(t, err)
	receiver := created.(*sharedGNMIReceiver)
	t.Cleanup(func() { require.NoError(t, receiver.Shutdown(context.WithoutCancel(t.Context()))) })
	require.Len(t, receiver.targets, sharedGNMIMaxConcurrentDelivery+1)

	results := make(chan error, sharedGNMIMaxConcurrentDelivery)
	timestamp := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	preCanceled, cancelBeforeAdmission := context.WithCancel(t.Context())
	cancelBeforeAdmission()
	err = receiver.processNotification(
		preCanceled,
		receiver.targets[0],
		receiver.targets[0].streams[0],
		deliveryTestInterfaceNotification(t, timestamp, false, "", "Ethernet-pre-canceled"),
	)
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, consumer.calls.Load(), "a pre-canceled notification must not acquire an available slot")
	assert.Empty(t, receiver.targets[0].cache.Snapshot())

	for index := range sharedGNMIMaxConcurrentDelivery {
		target := receiver.targets[index]
		notification := deliveryTestInterfaceNotification(
			t,
			timestamp,
			false,
			"",
			fmt.Sprintf("Ethernet%d", index),
		)
		go func() {
			results <- receiver.processNotification(t.Context(), target, target.streams[0], notification)
		}()
	}
	for range sharedGNMIMaxConcurrentDelivery {
		select {
		case <-consumer.entered:
		case <-time.After(time.Second):
			t.Fatal("timed out filling the receiver-wide notification processing gate")
		}
	}
	assert.Equal(t, int64(sharedGNMIMaxConcurrentDelivery), consumer.maxActive.Load())

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	ninth := receiver.targets[sharedGNMIMaxConcurrentDelivery]
	err = receiver.processNotification(
		canceled,
		ninth,
		ninth.streams[0],
		deliveryTestInterfaceNotification(t, timestamp, false, "", "Ethernet-canceled"),
	)
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, int64(sharedGNMIMaxConcurrentDelivery), consumer.calls.Load(),
		"a canceled waiter must not decode or reach the consumer")

	close(consumer.release)
	for range sharedGNMIMaxConcurrentDelivery {
		require.NoError(t, <-results)
	}
	assert.Equal(t, int64(sharedGNMIMaxConcurrentDelivery), consumer.maxActive.Load())
}

func newDeliveryTestReceiver(
	t *testing.T,
	targetConfig GNMITargetConfig,
	maxDatapoints int,
	next consumer.Metrics,
) (*sharedGNMIReceiver, *sharedGNMITargetRuntime, sharedGNMIRuntimeStream) {
	t.Helper()
	config := createDefaultConfig().(*Config)
	config.GNMI = GNMIConfig{
		MaxDatapointsPerChunk: maxDatapoints,
		MaxCachedSeries:       100,
		Targets:               []GNMITargetConfig{targetConfig},
	}
	created, err := newSharedGNMIReceiver(receivertest.NewNopSettings(componentmetadata.Type), config, next)
	require.NoError(t, err)
	receiver := created.(*sharedGNMIReceiver)
	t.Cleanup(func() { require.NoError(t, receiver.Shutdown(context.WithoutCancel(t.Context()))) })
	require.Len(t, receiver.targets, 1)
	require.Len(t, receiver.targets[0].streams, 1)
	return receiver, receiver.targets[0], receiver.targets[0].streams[0]
}

func deliveryTestInterfaceNotification(
	t *testing.T,
	timestamp time.Time,
	atomicNotification bool,
	prefix string,
	interfaces ...string,
) *gnmipb.Notification {
	t.Helper()
	protoPrefix := &gnmipb.Path{Origin: runtimeTestOrigin}
	if prefix != "" {
		protoPrefix = runtimeTestProtoPath(t, prefix)
		protoPrefix.Origin = runtimeTestOrigin
	}
	updates := make([]*gnmipb.Update, 0, len(interfaces))
	for index, interfaceName := range interfaces {
		path := fmt.Sprintf("interfaces/interface[name=%s]/state/value", interfaceName)
		if prefix == "interfaces" {
			path = fmt.Sprintf("interface[name=%s]/state/value", interfaceName)
		}
		updates = append(updates, &gnmipb.Update{
			Path: runtimeTestProtoPath(t, path),
			Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: int64(index + 1)}},
		})
	}
	return &gnmipb.Notification{
		Timestamp: timestamp.UnixNano(), Prefix: protoPrefix, Atomic: atomicNotification, Update: updates,
	}
}

func deliveryTestNXOpticsNotification(timestamp time.Time, sensorID string) *gnmipb.Notification {
	base := fmt.Sprintf("sys/intf/phys-[Ethernet1/1]/phys/fcotdd/lane-0-sensor-%s", sensorID)
	path := func(leaf string) *gnmipb.Path {
		return &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: base}, {Name: leaf}}}
	}
	return &gnmipb.Notification{
		Timestamp: timestamp.UnixNano(), Prefix: &gnmipb.Path{Origin: builtinGNMIOriginDME},
		Update: []*gnmipb.Update{
			{Path: path("description"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "TDECQ"}}},
			{Path: path("unit"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "dB"}}},
			{Path: path("value"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_DoubleVal{DoubleVal: 2.5}}},
		},
	}
}

func deliveryTestNXAuxiliaryReplacementNotification(
	timestamp time.Time,
	recognized bool,
	sensorIDs ...string,
) *gnmipb.Notification {
	updates := make([]*gnmipb.Update, 0, len(sensorIDs)*3)
	for sensorIndex, sensorID := range sensorIDs {
		base := fmt.Sprintf("sys/intf/phys-[Ethernet1/1]/phys/fcotdd/lane-0-sensor-%s", sensorID)
		path := func(leaf string) *gnmipb.Path {
			return &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: base}, {Name: leaf}}}
		}
		description := strings.Repeat("unknown-optical-sensor-", 256)
		if recognized {
			description = "TDECQ"
		}
		updates = append(updates, &gnmipb.Update{
			Path: path("description"),
			Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: description}},
		})
		if !recognized {
			continue
		}
		updates = append(updates,
			&gnmipb.Update{Path: path("unit"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "dB"}}},
			&gnmipb.Update{Path: path("value"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_DoubleVal{DoubleVal: float64(sensorIndex + 1)}}},
		)
	}
	return &gnmipb.Notification{
		Timestamp: timestamp.UnixNano(),
		Atomic:    true,
		Prefix:    &gnmipb.Path{Origin: builtinGNMIOriginDME},
		Update:    updates,
	}
}

func deliveryTestSnapshotInterfaces(points []internalgnmi.MappedPoint) []string {
	interfaces := make([]string, 0, len(points))
	for pointIndex := range points {
		interfaces = append(interfaces, points[pointIndex].Attributes["network.interface.name"])
	}
	sort.Strings(interfaces)
	return interfaces
}

type deliveryTestScriptedConsumer struct {
	mu        sync.Mutex
	calls     int
	failCalls map[int]struct{}
	seen      []string
	accepted  []string
}

func (*deliveryTestScriptedConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (c *deliveryTestScriptedConsumer) ConsumeMetrics(_ context.Context, metrics pmetric.Metrics) error {
	interfaceName := deliveryTestFirstStringAttribute(metrics, "network.interface.name")
	c.mu.Lock()
	c.calls++
	call := c.calls
	c.seen = append(c.seen, interfaceName)
	_, fail := c.failCalls[call]
	if !fail {
		c.accepted = append(c.accepted, interfaceName)
	}
	c.mu.Unlock()
	if fail {
		return errors.New("intentional delivery transaction refusal")
	}
	return nil
}

func (c *deliveryTestScriptedConsumer) snapshot() (seen, accepted []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.seen...), append([]string(nil), c.accepted...)
}

type deliveryTestBlockingConsumer struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int64
}

type deliveryTestConcurrencyConsumer struct {
	entered   chan struct{}
	release   chan struct{}
	calls     atomic.Int64
	active    atomic.Int64
	maxActive atomic.Int64
}

func (*deliveryTestConcurrencyConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (c *deliveryTestConcurrencyConsumer) ConsumeMetrics(context.Context, pmetric.Metrics) error {
	c.calls.Add(1)
	active := c.active.Add(1)
	for {
		maximum := c.maxActive.Load()
		if active <= maximum || c.maxActive.CompareAndSwap(maximum, active) {
			break
		}
	}
	c.entered <- struct{}{}
	<-c.release
	c.active.Add(-1)
	return nil
}

func (*deliveryTestBlockingConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (c *deliveryTestBlockingConsumer) ConsumeMetrics(context.Context, pmetric.Metrics) error {
	call := c.calls.Add(1)
	if call == 1 {
		c.once.Do(func() { close(c.started) })
		<-c.release
	}
	return nil
}

func deliveryTestFirstStringAttribute(metrics pmetric.Metrics, key string) string {
	for resourceIndex := 0; resourceIndex < metrics.ResourceMetrics().Len(); resourceIndex++ {
		scopes := metrics.ResourceMetrics().At(resourceIndex).ScopeMetrics()
		for scopeIndex := 0; scopeIndex < scopes.Len(); scopeIndex++ {
			items := scopes.At(scopeIndex).Metrics()
			for metricIndex := 0; metricIndex < items.Len(); metricIndex++ {
				metric := items.At(metricIndex)
				if metric.Type() != pmetric.MetricTypeGauge || metric.Gauge().DataPoints().Len() == 0 {
					continue
				}
				value, ok := metric.Gauge().DataPoints().At(0).Attributes().Get(key)
				if ok {
					return value.Str()
				}
			}
		}
	}
	return ""
}
