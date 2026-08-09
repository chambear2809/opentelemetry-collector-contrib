// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"fmt"
	"strings"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

func TestNXAuxiliaryByteBudgetRejectsUniqueOversizedMetadata(t *testing.T) {
	target := newAuxiliaryTestNXTarget(t, "nx-byte-limit", 10, sharedGNMIAuxiliaryRetainedBytes)
	timestamp := time.Date(2026, time.July, 3, 12, 0, 0, 0, time.UTC)

	_, err := target.normalizeNXNotification(auxiliaryTestNXSensorNotification(
		target.config.Name,
		"1",
		"TDECQ",
		timestamp,
	))
	require.NoError(t, err)
	committed := auxiliaryTestBudgetUsage(target.nxBudget)
	require.Equal(t, 1, committed.count)
	require.Positive(t, committed.bytes)

	target.nxBudget.mu.Lock()
	target.nxBudget.maximumBytes = committed.bytes
	target.nxBudget.mu.Unlock()
	_, err = target.normalizeNXNotification(auxiliaryTestNXSensorNotification(
		target.config.Name,
		"2",
		strings.Repeat("adversarial-metadata-", 1024),
		timestamp.Add(time.Second),
	))
	var capacity *internalgnmi.CapacityError
	require.ErrorAs(t, err, &capacity)
	assert.LessOrEqual(t, capacity.Requested, capacity.Limit, "the count limit must not be the rejecting dimension")
	assert.Greater(t, capacity.RequestedRetainedBytes, capacity.RetainedByteLimit)
	assert.Len(t, target.nxSensors, 1)
	assert.Equal(t, committed, auxiliaryTestBudgetUsage(target.nxBudget),
		"a rejected metadata reservation must preserve the committed sensor and byte accounting")
}

func TestNXMetadataUsesBoundedBatchStaleSnapshot(t *testing.T) {
	target := newAuxiliaryTestNXTarget(t, "nx-stale-batch", 10, sharedGNMIAuxiliaryRetainedBytes)
	deleteTimestamp := time.Date(2026, time.July, 3, 12, 0, 0, 0, time.UTC)
	stale := auxiliaryTestNXSensorNotification(
		target.config.Name,
		"1",
		"TDECQ",
		deleteTimestamp.Add(-time.Second),
	)
	_, err := target.cache.Apply(internalgnmi.CacheNotification{
		Timestamp: deleteTimestamp,
		Deletes:   []internalgnmi.Path{stale.Prefix.Clone()},
	})
	require.NoError(t, err)

	_, err = target.normalizeNXNotification(stale)
	require.NoError(t, err)
	assert.Empty(t, target.nxSensors, "metadata older than a retained delete must not repopulate NX identity")
	assert.Equal(t, sharedGNMIAuxiliaryUsage{}, auxiliaryTestBudgetUsage(target.nxBudget))

	newer := auxiliaryTestNXSensorNotification(
		target.config.Name,
		"1",
		"TDECQ",
		deleteTimestamp.Add(time.Second),
	)
	_, err = target.normalizeNXNotification(newer)
	require.NoError(t, err)
	require.Len(t, target.nxSensors, 1, "metadata newer than the retained delete must remain admissible")
}

func TestOpticalAuxiliaryByteBudgetRejectsUniqueOversizedAttributes(t *testing.T) {
	target := newAuxiliaryTestOpticalTarget(t, "optical-byte-limit", 100)
	timestamp := time.Date(2026, time.July, 3, 12, 0, 0, 0, time.UTC)
	first := auxiliaryTestOpticalPoint(target.config.Name, "Ethernet1/1", "qualified")

	_, err := target.updateOpticalPresence(
		internalgnmi.CacheResult{Applied: []internalgnmi.MappedPoint{first}},
		timestamp,
	)
	require.NoError(t, err)
	committed := auxiliaryTestBudgetUsage(target.nxBudget)
	require.Equal(t, 3, committed.count, "source, presence count, and attributes are each bounded")
	require.Positive(t, committed.bytes)

	target.nxBudget.mu.Lock()
	target.nxBudget.maximumBytes = committed.bytes
	target.nxBudget.mu.Unlock()
	second := auxiliaryTestOpticalPoint(
		target.config.Name,
		"Ethernet1/2",
		strings.Repeat("untrusted-cardinality-", 1024),
	)
	_, err = target.updateOpticalPresence(
		internalgnmi.CacheResult{Applied: []internalgnmi.MappedPoint{second}},
		timestamp.Add(time.Second),
	)
	var capacity *internalgnmi.CapacityError
	require.ErrorAs(t, err, &capacity)
	assert.LessOrEqual(t, capacity.Requested, capacity.Limit, "the count limit must not be the rejecting dimension")
	assert.Greater(t, capacity.RequestedRetainedBytes, capacity.RetainedByteLimit)
	assert.Len(t, target.opticalSources, 1)
	assert.Len(t, target.presenceCounts, 1)
	assert.Len(t, target.presenceAttrs, 1)
	assert.Equal(t, committed, auxiliaryTestBudgetUsage(target.nxBudget),
		"a rejected optical reservation must not strand count or byte capacity")
}

func TestOpticalAuxiliaryReservationsRollbackAndReleaseOnlyAtCommit(t *testing.T) {
	target := newAuxiliaryTestOpticalTarget(t, "optical-transactions", 10)
	timestamp := time.Date(2026, time.July, 3, 12, 0, 0, 0, time.UTC)
	point := auxiliaryTestOpticalPoint(target.config.Name, "Ethernet1/1", "qualified")
	result := internalgnmi.CacheResult{Applied: []internalgnmi.MappedPoint{point}}

	transaction := target.prepareOpticalPresence(result, timestamp)
	reservation, err := prepareSharedGNMIAuxiliaryReservation(target.nxBudget, transaction.budgetDelta)
	require.NoError(t, err)
	reserved := auxiliaryTestBudgetUsage(target.nxBudget)
	assert.Equal(t, 3, reserved.count)
	assert.Positive(t, reserved.bytes)
	assert.Empty(t, target.opticalSources, "preparation must not publish optical state")
	transaction.rollback()
	reservation.rollback()
	assert.Equal(t, sharedGNMIAuxiliaryUsage{}, auxiliaryTestBudgetUsage(target.nxBudget))
	assert.Empty(t, target.opticalSources)

	transaction = target.prepareOpticalPresence(result, timestamp)
	reservation, err = prepareSharedGNMIAuxiliaryReservation(target.nxBudget, transaction.budgetDelta)
	require.NoError(t, err)
	transaction.commit()
	reservation.commit()
	committed := auxiliaryTestBudgetUsage(target.nxBudget)
	require.Equal(t, reserved, committed)
	require.Len(t, target.opticalSources, 1)

	removal := internalgnmi.CacheResult{Removed: []internalgnmi.MappedPoint{point}}
	transaction = target.prepareOpticalPresence(removal, timestamp.Add(time.Second))
	reservation, err = prepareSharedGNMIAuxiliaryReservation(target.nxBudget, transaction.budgetDelta)
	require.NoError(t, err)
	assert.Equal(t, committed, auxiliaryTestBudgetUsage(target.nxBudget),
		"negative deltas must not release reusable capacity during preparation")
	transaction.rollback()
	reservation.rollback()
	assert.Equal(t, committed, auxiliaryTestBudgetUsage(target.nxBudget))
	assert.Len(t, target.opticalSources, 1)

	transaction = target.prepareOpticalPresence(removal, timestamp.Add(2*time.Second))
	reservation, err = prepareSharedGNMIAuxiliaryReservation(target.nxBudget, transaction.budgetDelta)
	require.NoError(t, err)
	assert.Equal(t, committed, auxiliaryTestBudgetUsage(target.nxBudget))
	transaction.commit()
	reservation.commit()
	assert.Equal(t, sharedGNMIAuxiliaryUsage{}, auxiliaryTestBudgetUsage(target.nxBudget))
	assert.Empty(t, target.opticalSources)
	assert.Empty(t, target.presenceCounts)
	assert.Empty(t, target.presenceAttrs)
}

func TestNXDeletePlanningDeduplicatesSelectorsAndStopsBoundedCrossProducts(t *testing.T) {
	targetConfig := GNMITargetConfig{
		Name: "nx-planning", Platform: gnmiPlatformNXOS, MaxStreams: 1,
		Profiles: subscriptionProfilesOnly(builtinGNMIProfileOptics),
	}
	receiver, target, stream := newDeliveryTestReceiver(t, targetConfig, 10, consumertest.NewNop())
	target.nxBudget = newSharedGNMIAuxiliaryBudget(2_000)
	target.nxSensors = make(map[string]nxSensorState, 1_000)
	timestamp := time.Date(2026, time.July, 3, 12, 0, 0, 0, time.UTC)
	for sensorID := range 1_000 {
		path := internalgnmi.Path{
			Target: target.config.Name,
			Origin: builtinGNMIOriginDME,
			Elements: []internalgnmi.PathElem{
				{Name: "sys"},
				{Name: "sensor", Keys: map[string]string{"id": fmt.Sprintf("%d", sensorID)}},
			},
		}
		target.nxSensors[path.Key()] = nxSensorState{
			description: "TDECQ", unit: "dB", path: path,
			descriptionTimestamp: timestamp, unitTimestamp: timestamp,
		}
	}
	usage := estimateSharedGNMINXSensorUsage(target.nxSensors)
	target.nxBudget.mu.Lock()
	target.nxBudget.used = usage.count
	target.nxBudget.usedBytes = usage.bytes
	target.nxBudget.mu.Unlock()

	duplicate := internalgnmi.Path{
		Target:   target.config.Name,
		Origin:   builtinGNMIOriginDME,
		Elements: []internalgnmi.PathElem{{Name: "does-not-match", Keys: map[string]string{"id": "duplicate"}}},
	}
	duplicateDeletes := make([]internalgnmi.Path, 2_501)
	for index := range duplicateDeletes {
		duplicateDeletes[index] = duplicate.Clone()
	}
	_, transaction, err := target.prepareNXNotification(internalgnmi.DecodedNotification{
		Prefix: duplicate.Clone(), Timestamp: timestamp.Add(time.Second), Atomic: true, Deletes: duplicateDeletes,
	})
	require.NoError(t, err, "exact duplicate deletes and the identical atomic selector must be planned once")
	require.NotNil(t, transaction)
	transaction.rollback()
	assert.Equal(t, usage, auxiliaryTestBudgetUsage(target.nxBudget))

	deletes := make([]*gnmipb.Path, 2_500)
	for index := range deletes {
		deletes[index] = &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: fmt.Sprintf("selector-%d", index)}}}
	}
	err = receiver.processNotification(t.Context(), target, stream, &gnmipb.Notification{
		Timestamp: timestamp.Add(2 * time.Second).UnixNano(),
		Atomic:    true,
		Prefix: &gnmipb.Path{
			Origin: builtinGNMIOriginDME,
			Elem:   []*gnmipb.PathElem{{Name: "atomic-selector"}},
		},
		Delete: deletes,
	})
	var stopped *sharedGNMIProfileStopError
	require.ErrorAs(t, err, &stopped)
	require.ErrorContains(t, err, "NX auxiliary-state planning work exceeds 25000000 comparisons")
	assert.Equal(t, usage, auxiliaryTestBudgetUsage(target.nxBudget))
	assert.Len(t, target.nxSensors, 1_000)
}

func TestNXDeleteOnlyAtomicNotificationPreservesSiblingAuxiliaryState(t *testing.T) {
	targetConfig := GNMITargetConfig{
		Name: "nx-delete-only", Platform: gnmiPlatformNXOS, MaxStreams: 1,
		Profiles: subscriptionProfilesOnly(builtinGNMIProfileOptics),
	}
	_, target, _ := newDeliveryTestReceiver(t, targetConfig, 10, consumertest.NewNop())
	timestamp := time.Date(2026, time.July, 3, 12, 0, 0, 0, time.UTC)
	prefix := internalgnmi.Path{
		Target: target.config.Name,
		Origin: builtinGNMIOriginDME,
		Elements: []internalgnmi.PathElem{
			{Name: "sys"},
		},
	}
	sensorPath := func(id string) internalgnmi.Path {
		path := prefix.Clone()
		path.Elements = append(path.Elements, internalgnmi.PathElem{Name: "sensor", Keys: map[string]string{"id": id}})
		return path
	}
	deleted := sensorPath("one")
	sibling := sensorPath("two")
	target.nxSensors = map[string]nxSensorState{
		deleted.Key(): {description: "TDECQ", unit: "dB", path: deleted, descriptionTimestamp: timestamp, unitTimestamp: timestamp},
		sibling.Key(): {description: "TDECQ", unit: "dB", path: sibling, descriptionTimestamp: timestamp, unitTimestamp: timestamp},
	}
	usage := estimateSharedGNMINXSensorUsage(target.nxSensors)
	target.nxBudget.mu.Lock()
	target.nxBudget.used = usage.count
	target.nxBudget.usedBytes = usage.bytes
	target.nxBudget.mu.Unlock()

	_, transaction, err := target.prepareNXNotification(internalgnmi.DecodedNotification{
		Prefix: prefix, Timestamp: timestamp.Add(time.Second), Atomic: true, Deletes: []internalgnmi.Path{deleted},
	})
	require.NoError(t, err)
	reservation, err := prepareSharedGNMIAuxiliaryReservation(target.nxBudget, transaction.budgetDelta)
	require.NoError(t, err)
	transaction.commit()
	reservation.commit()

	assert.NotContains(t, target.nxSensors, deleted.Key())
	assert.Contains(t, target.nxSensors, sibling.Key(), "delete-only atomic notifications must not replace the whole prefix")
	assert.Equal(t, estimateSharedGNMINXSensorUsage(target.nxSensors), auxiliaryTestBudgetUsage(target.nxBudget))
}

func TestNXDMESlashPackedExpansionIsRejectedBeforeNormalization(t *testing.T) {
	targetConfig := GNMITargetConfig{
		Name: "nx-packed-path", Platform: gnmiPlatformNXOS, MaxStreams: 1,
		Profiles: subscriptionProfilesOnly(builtinGNMIProfileOptics),
	}
	receiver, target, stream := newDeliveryTestReceiver(t, targetConfig, 10, consumertest.NewNop())
	packed := strings.Repeat("a/", 127) + "a"
	require.Len(t, packed, 255)
	require.Equal(t, sharedGNMIMaxPathElements, countNormalizedNXDMEElement(packed))
	packedElements := make([]*gnmipb.PathElem, sharedGNMIMaxPathElements)
	for index := range packedElements {
		packedElements[index] = &gnmipb.PathElem{Name: packed}
	}

	err := receiver.processNotification(t.Context(), target, stream, &gnmipb.Notification{
		Timestamp: time.Now().Add(-time.Minute).UnixNano(),
		Atomic:    true,
		Prefix:    &gnmipb.Path{Origin: builtinGNMIOriginDME, Elem: packedElements},
	})
	var stopped *sharedGNMIProfileStopError
	require.ErrorAs(t, err, &stopped)
	require.ErrorContains(t, err, "path exceeds 128 elements after slash-packed expansion")
	assert.Empty(t, target.nxSensors)
	assert.Equal(t, sharedGNMIAuxiliaryUsage{}, auxiliaryTestBudgetUsage(target.nxBudget))

	_, transaction, err := target.prepareNXNotification(internalgnmi.DecodedNotification{
		Prefix: internalgnmi.Path{
			Target: target.config.Name, Origin: builtinGNMIOriginDME,
			Elements: []internalgnmi.PathElem{{Name: "sys"}},
		},
		Updates: []internalgnmi.Point{{
			Series: internalgnmi.Series{
				Target: target.config.Name, Origin: builtinGNMIOriginDME,
				Elements: []internalgnmi.PathElem{{Name: packed}}, Leaf: "description",
			},
			Value: internalgnmi.StringValue("TDECQ"), Timestamp: time.Now().Add(-time.Minute),
		}},
	})
	require.Nil(t, transaction)
	require.ErrorContains(t, err, "path exceeds 127 elements after slash-packed expansion")
	assert.Equal(t, 3, countNormalizedNXDMEElement("phys-[Ethernet1/1]/lane-0-sensor-1"),
		"slashes inside bracketed identifiers must not count as delimiters")
}

func TestOpticalAuthoritativeAbsenceClearsMultipleIdentitiesInOneSourceScan(t *testing.T) {
	target := newAuxiliaryTestOpticalTarget(t, "optical-absence", 100)
	timestamp := time.Date(2026, time.July, 3, 12, 0, 0, 0, time.UTC)
	points := []internalgnmi.MappedPoint{
		auxiliaryTestOpticalPoint(target.config.Name, "Ethernet1/1", "qualified"),
		auxiliaryTestOpticalPoint(target.config.Name, "Ethernet1/2", "qualified"),
		auxiliaryTestOpticalPoint(target.config.Name, "Ethernet1/3", "qualified"),
	}
	_, err := target.updateOpticalPresence(internalgnmi.CacheResult{Applied: points}, timestamp)
	require.NoError(t, err)
	require.Equal(t, 9, auxiliaryTestBudgetUsage(target.nxBudget).count)

	absent := make([]internalgnmi.MappedPoint, 2)
	for index := range absent {
		absent[index] = points[index]
		absent[index].Metric.Name = "cisco.optics.present"
		absent[index].GaugeType = internalgnmi.GaugeInt
		absent[index].IntValue = 0
	}
	_, err = target.updateOpticalPresence(
		internalgnmi.CacheResult{Applied: absent},
		timestamp.Add(time.Second),
	)
	require.NoError(t, err)
	thirdKey, _ := opticalPresenceIdentity(points[2].Attributes)
	assert.Equal(t, map[string]int{thirdKey: 1}, target.presenceCounts)
	assert.Len(t, target.opticalSources, 1)
	assert.Contains(t, target.presenceAttrs, thirdKey)
	assert.Equal(t, 3, auxiliaryTestBudgetUsage(target.nxBudget).count)
}

func TestOpticalSourceIdentityMoveEmitsAbsenceAndReleasesOldAttributes(t *testing.T) {
	target := newAuxiliaryTestOpticalTarget(t, "optical-move", 100)
	timestamp := time.Date(2026, time.July, 3, 12, 0, 0, 0, time.UTC)
	original := auxiliaryTestOpticalPoint(
		target.config.Name,
		"Ethernet-old",
		strings.Repeat("large-retained-attribute", 256),
	)
	_, err := target.updateOpticalPresence(
		internalgnmi.CacheResult{Applied: []internalgnmi.MappedPoint{original}},
		timestamp,
	)
	require.NoError(t, err)
	before := auxiliaryTestBudgetUsage(target.nxBudget)
	require.Equal(t, 3, before.count)

	moved := original
	moved.Attributes = map[string]string{"network.interface.name": "Ethernet-new"}
	transaction := target.prepareOpticalPresence(
		internalgnmi.CacheResult{Applied: []internalgnmi.MappedPoint{moved}},
		timestamp.Add(time.Second),
	)
	reservation, err := prepareSharedGNMIAuxiliaryReservation(target.nxBudget, transaction.budgetDelta)
	require.NoError(t, err)
	presenceValues := make(map[string]int64, len(transaction.points))
	for _, point := range transaction.points {
		presenceKey, _ := opticalPresenceIdentity(point.Attributes)
		presenceValues[presenceKey] = point.IntValue
	}
	oldKey, _ := opticalPresenceIdentity(original.Attributes)
	newKey, _ := opticalPresenceIdentity(moved.Attributes)
	assert.Equal(t, map[string]int64{oldKey: 0, newKey: 1}, presenceValues)
	assert.Equal(t, before, auxiliaryTestBudgetUsage(target.nxBudget),
		"the old attribute bytes must remain reserved until the move commits")

	transaction.commit()
	reservation.commit()
	after := auxiliaryTestBudgetUsage(target.nxBudget)
	assert.Equal(t, 3, after.count)
	assert.Less(t, after.bytes, before.bytes)
	assert.Equal(t, map[string]int{newKey: 1}, target.presenceCounts)
	assert.NotContains(t, target.presenceAttrs, oldKey)
	assert.Contains(t, target.presenceAttrs, newKey)
	assert.Equal(t, map[string]string{moved.Source.Key(): newKey}, target.opticalSources)
}

func TestOpticalSourceIdentityMoveFromAtomicCacheResultKeepsNewSource(t *testing.T) {
	target := newAuxiliaryTestOpticalTarget(t, "optical-cache-move", 100)
	cache, err := internalgnmi.NewCache(10)
	require.NoError(t, err)
	timestamp := time.Date(2026, time.July, 3, 13, 0, 0, 0, time.UTC)
	original := auxiliaryTestOpticalPoint(target.config.Name, "Ethernet-old", "false")
	// Keep the canonical source path fixed while changing the mapped presence
	// identity, matching a mapping/metadata replacement for one sensor leaf.
	original.Source.Elements[1].Keys = map[string]string{"name": "sensor-1"}
	moved := original
	moved.Attributes = map[string]string{
		"network.interface.name":    "Ethernet-new",
		"cisco.optics.experimental": "false",
	}

	initialResult, err := cache.Apply(internalgnmi.CacheNotification{
		Timestamp: timestamp,
		Updates:   []internalgnmi.MappedPoint{original},
	})
	require.NoError(t, err)
	_, err = target.updateOpticalPresence(initialResult, timestamp)
	require.NoError(t, err)

	replacementResult, err := cache.Apply(internalgnmi.CacheNotification{
		Prefix:    original.Source.Path(),
		Timestamp: timestamp.Add(time.Second),
		Atomic:    true,
		Updates:   []internalgnmi.MappedPoint{moved},
	})
	require.NoError(t, err)
	require.Len(t, replacementResult.Applied, 1)
	require.Len(t, replacementResult.Removed, 1)
	assert.Equal(t, original.Source.Key(), replacementResult.Applied[0].Source.Key())
	assert.Equal(t, original.Source.Key(), replacementResult.Removed[0].Source.Key())

	presence, err := target.updateOpticalPresence(replacementResult, timestamp.Add(time.Second))
	require.NoError(t, err)
	values := make(map[string]int64, len(presence))
	for _, point := range presence {
		key, _ := opticalPresenceIdentity(point.Attributes)
		values[key] = point.IntValue
	}
	oldKey, _ := opticalPresenceIdentity(original.Attributes)
	newKey, _ := opticalPresenceIdentity(moved.Attributes)
	assert.Equal(t, map[string]int64{oldKey: 0, newKey: 1}, values)
	assert.Equal(t, map[string]string{moved.Source.Key(): newKey}, target.opticalSources)
	assert.Equal(t, map[string]int{newKey: 1}, target.presenceCounts)
	assert.NotContains(t, target.presenceAttrs, oldKey)
	assert.Contains(t, target.presenceAttrs, newKey)
}

func newAuxiliaryTestNXTarget(
	t *testing.T,
	name string,
	maximum int,
	maximumBytes int64,
) *sharedGNMITargetRuntime {
	t.Helper()
	cache, err := internalgnmi.NewCache(100)
	require.NoError(t, err)
	target, err := newSharedGNMITargetRuntimeWithBudget(GNMITargetConfig{
		Name: name, Platform: gnmiPlatformNXOS, MaxStreams: 1,
		Profiles: subscriptionProfilesOnly(builtinGNMIProfileOptics),
	}, cache, newSharedGNMIAuxiliaryBudgetWithLimits(maximum, maximumBytes))
	require.NoError(t, err)
	return target
}

func newAuxiliaryTestOpticalTarget(
	t *testing.T,
	name string,
	maximum int,
) *sharedGNMITargetRuntime {
	t.Helper()
	return &sharedGNMITargetRuntime{
		config:   GNMITargetConfig{Name: name},
		nxBudget: newSharedGNMIAuxiliaryBudgetWithLimits(maximum, sharedGNMIAuxiliaryRetainedBytes),
	}
}

func auxiliaryTestNXSensorNotification(
	targetName string,
	sensorID string,
	description string,
	timestamp time.Time,
) internalgnmi.DecodedNotification {
	elements := []internalgnmi.PathElem{
		{Name: "sys"},
		{Name: "intf"},
		{Name: "phys", Keys: map[string]string{"id": "Ethernet1/1"}},
		{Name: "phys"},
		{Name: "fcotdd"},
		{Name: "lane", Keys: map[string]string{"id": "0"}},
		{Name: "sensor", Keys: map[string]string{"id": sensorID}},
	}
	path := internalgnmi.Path{Target: targetName, Origin: builtinGNMIOriginDME, Elements: elements}
	return internalgnmi.DecodedNotification{
		Prefix: path.Clone(), Timestamp: timestamp,
		Updates: []internalgnmi.Point{
			{
				Series: internalgnmi.Series{Target: targetName, Origin: builtinGNMIOriginDME, Elements: elements, Leaf: "description"},
				Value:  internalgnmi.StringValue(description), Timestamp: timestamp,
			},
			{
				Series: internalgnmi.Series{Target: targetName, Origin: builtinGNMIOriginDME, Elements: elements, Leaf: "unit"},
				Value:  internalgnmi.StringValue("dB"), Timestamp: timestamp,
			},
		},
	}
}

func auxiliaryTestOpticalPoint(targetName, interfaceName, experimental string) internalgnmi.MappedPoint {
	return internalgnmi.MappedPoint{
		Source: internalgnmi.Series{
			Target: targetName,
			Origin: "openconfig",
			Elements: []internalgnmi.PathElem{
				{Name: "interfaces"},
				{Name: "interface", Keys: map[string]string{"name": interfaceName}},
				{Name: "state"},
			},
			Leaf: "temperature",
		},
		Metric: internalgnmi.MetricMetadata{Name: "cisco.optics.temperature"},
		Attributes: map[string]string{
			"network.interface.name":    interfaceName,
			"cisco.optics.experimental": experimental,
		},
	}
}

func auxiliaryTestBudgetUsage(budget *sharedGNMIAuxiliaryBudget) sharedGNMIAuxiliaryUsage {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return sharedGNMIAuxiliaryUsage{count: budget.used, bytes: budget.usedBytes}
}
