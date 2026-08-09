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
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"google.golang.org/grpc"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

func TestProcessNotificationEntityLimitOverflowRollsBackAndDeleteFreesCapacity(t *testing.T) {
	profiles := subscriptionProfilesOnly(builtinGNMIProfileCatalyst9800Wireless)
	profiles.Catalyst9800Wireless.Groups = map[string]GNMIGroupConfig{
		"ap_capwap": {MaxEntities: 1},
		"rf_rrm":    {Enabled: subscriptionBoolPtr(false)},
		"wlan_ssid": {Enabled: subscriptionBoolPtr(false)},
	}
	targetConfig := GNMITargetConfig{
		Name: "wireless-entity-limit", Platform: gnmiPlatformIOSXE, MaxStreams: 1, Profiles: profiles,
	}
	sink := &consumertest.MetricsSink{}
	receiver, target, stream := newDeliveryTestReceiver(t, targetConfig, 10, sink)
	require.Len(t, stream.EntityLimits, 1)
	assert.Equal(t, 1, stream.EntityLimits[0].MaxEntities)

	baseTime := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	firstMAC := "00:11:22:33:44:55"
	secondMAC := "66:77:88:99:aa:bb"
	require.NoError(t, receiver.processNotification(
		t.Context(), target, stream, entityLimitTestAPNotification(baseTime, false, firstMAC),
	))
	assert.Equal(t, 1, entityLimitTestManagerCount(target))
	assert.Equal(t, 1, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.wlc.ap.join.status"))
	require.Len(t, target.cache.Snapshot(), 1)

	err := receiver.processNotification(
		t.Context(), target, stream, entityLimitTestAPNotification(baseTime.Add(time.Second), false, secondMAC),
	)
	var stopped *sharedGNMIProfileStopError
	require.ErrorAs(t, err, &stopped)
	assert.Equal(t, "entity_limit", stopped.reason)
	var capacity *sharedGNMIEntityCapacityError
	require.ErrorAs(t, err, &capacity)
	assert.Equal(t, 1, capacity.Limit)
	assert.Equal(t, 2, capacity.Requested)
	assert.Equal(t, 1, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.wlc.ap.join.status"),
		"overflow must be rejected before OTLP delivery")
	snapshot := target.cache.Snapshot()
	require.Len(t, snapshot, 1, "overflow must roll back the prepared cache transaction")
	assert.Equal(t, firstMAC, snapshot[0].Attributes["cisco.wlc.ap.mac"])
	assert.Equal(t, 1, entityLimitTestManagerCount(target))

	require.NoError(t, receiver.processNotification(
		t.Context(), target, stream, entityLimitTestAPDelete(baseTime.Add(2*time.Second), firstMAC),
	))
	assert.Zero(t, entityLimitTestManagerCount(target))
	assert.Empty(t, target.cache.Snapshot())

	require.NoError(t, receiver.processNotification(
		t.Context(), target, stream, entityLimitTestAPNotification(baseTime.Add(3*time.Second), false, secondMAC),
	))
	assert.Equal(t, 1, entityLimitTestManagerCount(target))
	assert.Equal(t, 2, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.wlc.ap.join.status"))
}

func TestProcessNotificationEntityLimitAllowsAtomicEntityReplacement(t *testing.T) {
	profiles := subscriptionProfilesOnly(builtinGNMIProfileCatalyst9800Wireless)
	profiles.Catalyst9800Wireless.Groups = map[string]GNMIGroupConfig{
		"ap_capwap": {MaxEntities: 1},
		"rf_rrm":    {Enabled: subscriptionBoolPtr(false)},
		"wlan_ssid": {Enabled: subscriptionBoolPtr(false)},
	}
	targetConfig := GNMITargetConfig{
		Name: "wireless-entity-atomic", Platform: gnmiPlatformIOSXE, MaxStreams: 1, Profiles: profiles,
	}
	receiver, target, stream := newDeliveryTestReceiver(t, targetConfig, 10, consumertest.NewNop())
	baseTime := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	require.NoError(t, receiver.processNotification(
		t.Context(), target, stream, entityLimitTestAPNotification(baseTime, false, "00:11:22:33:44:55"),
	))
	require.NoError(t, receiver.processNotification(
		t.Context(), target, stream, entityLimitTestAPNotification(baseTime.Add(time.Second), true, "66:77:88:99:aa:bb"),
	))
	assert.Equal(t, 1, entityLimitTestManagerCount(target))
	snapshot := target.cache.Snapshot()
	require.Len(t, snapshot, 1)
	assert.Equal(t, "66:77:88:99:aa:bb", snapshot[0].Attributes["cisco.wlc.ap.mac"])
}

func TestProcessNotificationEntityLimitRollsBackOnConsumerRefusal(t *testing.T) {
	profiles := subscriptionProfilesOnly(builtinGNMIProfileCatalyst9800Wireless)
	profiles.Catalyst9800Wireless.Groups = map[string]GNMIGroupConfig{
		"ap_capwap": {MaxEntities: 1},
		"rf_rrm":    {Enabled: subscriptionBoolPtr(false)},
		"wlan_ssid": {Enabled: subscriptionBoolPtr(false)},
	}
	targetConfig := GNMITargetConfig{
		Name: "wireless-entity-refusal", Platform: gnmiPlatformIOSXE, MaxStreams: 1, Profiles: profiles,
	}
	consumer := &deliveryTestScriptedConsumer{failCalls: map[int]struct{}{1: {}}}
	receiver, target, stream := newDeliveryTestReceiver(t, targetConfig, 10, consumer)
	notification := entityLimitTestAPNotification(
		time.Now().Add(-time.Minute).Truncate(time.Millisecond), false, "00:11:22:33:44:55",
	)
	require.Error(t, receiver.processNotification(t.Context(), target, stream, notification))
	assert.Empty(t, target.cache.Snapshot())
	assert.Zero(t, entityLimitTestManagerCount(target))

	require.NoError(t, receiver.processNotification(t.Context(), target, stream, notification))
	assert.Len(t, target.cache.Snapshot(), 1)
	assert.Equal(t, 1, entityLimitTestManagerCount(target))
}

func TestEntityLimitManagerCountsEntitiesAcrossMetricLeavesAndReplans(t *testing.T) {
	point := func(mac, leaf, metric string) internalgnmi.MappedPoint {
		return internalgnmi.MappedPoint{
			Source: internalgnmi.Series{
				Target: "wireless", Origin: builtinGNMIOriginRFC7951,
				Elements: []internalgnmi.PathElem{
					{Name: "root"},
					{Name: "ap", Keys: map[string]string{"mac": mac}},
				},
				Leaf: leaf,
			},
			Metric:     internalgnmi.MetricMetadata{Name: metric, Description: metric, Unit: "1"},
			GaugeType:  internalgnmi.GaugeInt,
			Attributes: map[string]string{"cisco.wlc.ap.mac": mac},
		}
	}
	firstStatus := point("aa", "status", "status")
	firstClients := point("aa", "clients", "clients")
	secondStatus := point("bb", "status", "status")
	stream := sharedGNMIRuntimeStream{sharedGNMIStream: sharedGNMIStream{
		Profile: "wireless",
		EntityLimits: []sharedGNMIEntityLimit{{
			Group: "clients", MaxEntities: 1,
			Sources: map[string][]string{
				sharedGNMISeriesSourceKey(firstStatus.Source):  {"cisco.wlc.ap.mac"},
				sharedGNMISeriesSourceKey(firstClients.Source): {"cisco.wlc.ap.mac"},
			},
		}},
	}}
	manager, err := newSharedGNMIEntityLimitManager([]sharedGNMIRuntimeStream{stream}, nil)
	require.NoError(t, err)
	transaction, err := manager.prepare(internalgnmi.CacheResult{Applied: []internalgnmi.MappedPoint{firstStatus, firstClients}})
	require.NoError(t, err)
	transaction.commit()
	assert.Len(t, manager.groups[sharedGNMIEntityGroupKey("wireless", "clients")].entities, 1,
		"two metric leaves for one entity consume one slot")

	_, err = manager.prepare(internalgnmi.CacheResult{Applied: []internalgnmi.MappedPoint{secondStatus}})
	var capacity *sharedGNMIEntityCapacityError
	require.ErrorAs(t, err, &capacity)

	replanned, err := newSharedGNMIEntityLimitManager(
		[]sharedGNMIRuntimeStream{stream}, []internalgnmi.MappedPoint{firstStatus, firstClients},
	)
	require.NoError(t, err)
	assert.Len(t, replanned.groups[sharedGNMIEntityGroupKey("wireless", "clients")].entities, 1,
		"session replanning must rebuild distinct entities from committed cache state")
	transaction, err = replanned.prepare(internalgnmi.CacheResult{Removed: []internalgnmi.MappedPoint{firstStatus}})
	require.NoError(t, err)
	transaction.commit()
	assert.Len(t, replanned.groups[sharedGNMIEntityGroupKey("wireless", "clients")].entities, 1,
		"one remaining metric source keeps the entity present")
	transaction, err = replanned.prepare(internalgnmi.CacheResult{Removed: []internalgnmi.MappedPoint{firstClients}})
	require.NoError(t, err)
	transaction.commit()
	assert.Empty(t, replanned.groups[sharedGNMIEntityGroupKey("wireless", "clients")].entities)

	_, err = newSharedGNMIEntityLimitManager(
		[]sharedGNMIRuntimeStream{stream}, []internalgnmi.MappedPoint{firstStatus, secondStatus},
	)
	require.ErrorAs(t, err, &capacity, "session replanning must reject cache state already beyond the configured limit")
	assert.Equal(t, 2, capacity.Requested)
}

func TestEntityLimitManagerHandlesVariantSourceReplacement(t *testing.T) {
	primary := internalgnmi.MappedPoint{
		Source: internalgnmi.Series{
			Target: "router", Origin: "openconfig-wireless",
			Elements: []internalgnmi.PathElem{{Name: "aps"}, {Name: "ap", Keys: map[string]string{"name": "aa"}}},
			Leaf:     "status",
		},
		Metric:     internalgnmi.MetricMetadata{Name: "ap.status", Description: "AP status", Unit: "1"},
		GaugeType:  internalgnmi.GaugeInt,
		Attributes: map[string]string{"cisco.wlc.ap.mac": "aa"},
	}
	native := primary
	native.Source.Origin = "cisco-wireless"
	limitFor := func(point internalgnmi.MappedPoint) []sharedGNMIEntityLimit {
		return []sharedGNMIEntityLimit{{
			Group: "aps", MaxEntities: 1,
			Sources: map[string][]string{sharedGNMISeriesSourceKey(point.Source): {"cisco.wlc.ap.mac"}},
		}}
	}
	stream := sharedGNMIRuntimeStream{sharedGNMIStream: sharedGNMIStream{
		Profile: "wireless", EntityLimits: limitFor(primary),
	}}
	stream.variantFallbacks = []sharedGNMIRuntimeVariant{{
		stream: sharedGNMIRuntimeStream{sharedGNMIStream: sharedGNMIStream{
			Profile: "wireless", EntityLimits: limitFor(native),
		}},
	}}
	manager, err := newSharedGNMIEntityLimitManager([]sharedGNMIRuntimeStream{stream}, nil)
	require.NoError(t, err)
	transaction, err := manager.prepare(internalgnmi.CacheResult{Applied: []internalgnmi.MappedPoint{primary}})
	require.NoError(t, err)
	transaction.commit()

	transaction, err = manager.prepare(internalgnmi.CacheResult{
		Replaced: []internalgnmi.MappedPoint{primary}, Applied: []internalgnmi.MappedPoint{native},
	})
	require.NoError(t, err)
	transaction.commit()
	assert.Len(t, manager.groups[sharedGNMIEntityGroupKey("wireless", "aps")].entities, 1)
	assert.Len(t, manager.sourceEntities, 1, "one output cache entry must transfer between qualified source variants")

	transaction, err = manager.prepare(internalgnmi.CacheResult{Removed: []internalgnmi.MappedPoint{native}})
	require.NoError(t, err)
	transaction.commit()
	assert.Empty(t, manager.groups[sharedGNMIEntityGroupKey("wireless", "aps")].entities)
}

func TestFilterPackedRuntimeStreamRemovesOnlyOverflowGroup(t *testing.T) {
	profiles := subscriptionProfilesOnly(builtinGNMIProfileCatalyst9800Wireless)
	profiles.Catalyst9800Wireless.Groups = map[string]GNMIGroupConfig{
		"ap_capwap": {MaxEntities: 1},
		"rf_rrm":    {MaxEntities: 1},
		"wlan_ssid": {MaxEntities: 1},
	}
	streams, err := buildSharedGNMIRuntimeStreams(GNMITargetConfig{
		Name: "packed-wireless", Platform: gnmiPlatformIOSXE, MaxStreams: 4, Profiles: profiles,
	})
	require.NoError(t, err)
	require.Len(t, streams, 1, "compatible bounded groups must share one stream within the IOS ceiling")
	require.ElementsMatch(t, []string{"ap_capwap", "rf_rrm", "wlan_ssid"}, streams[0].Groups)

	filtered, removed, available, err := filterSharedGNMIRuntimeGroups(streams[0], "ap_capwap")
	require.NoError(t, err)
	require.True(t, available)
	assert.Equal(t, []string{"ap_capwap"}, removed)
	assert.ElementsMatch(t, []string{"rf_rrm", "wlan_ssid"}, filtered.Groups)
	assert.Len(t, filtered.Paths, 2)
	assert.Len(t, filtered.Mappings, 2)
	assert.Len(t, filtered.EntityLimits, 2)
	assert.Len(t, filtered.JSONListKeySpecs, 2)
	require.NotNil(t, filtered.JSONListKeys)
	for _, path := range filtered.Paths {
		assert.NotContains(t, path.Groups, "ap_capwap")
	}
	for _, spec := range filtered.JSONListKeySpecs {
		assert.NotContains(t, spec.Elements[0], "wireless-ap-global-oper")
	}
	for _, mapping := range filtered.Mappings {
		assert.NotContains(t, mapping.Groups, "ap_capwap")
		assert.NotEqual(t, "cisco.wlc.ap.join.status", mapping.Mapping.Metric.Name)
	}
	apPoint := internalgnmi.Point{
		Series: internalgnmi.Series{Origin: builtinGNMIOriginRFC7951, Elements: []internalgnmi.PathElem{
			{Name: "Cisco-IOS-XE-wireless-ap-global-oper:ap-global-oper-data"},
			{Name: "ap-join-stats", Keys: map[string]string{"wtp-mac": "aa"}},
		}, Leaf: "is-joined"},
		Value: internalgnmi.BoolValue(true),
	}
	_, mapped := filtered.registry.Map(apPoint)
	assert.False(t, mapped, "removed group source must be absent from the rebuilt registry")
	rfPoint := internalgnmi.Point{
		Series: internalgnmi.Series{Origin: builtinGNMIOriginRFC7951, Elements: []internalgnmi.PathElem{
			{Name: "Cisco-IOS-XE-wireless-rrm-oper:rrm-oper-data"},
			{Name: "rrm-measurement", Keys: map[string]string{"wtp-mac": "aa", "radio-slot-id": "0"}},
		}, Leaf: "cca-util-percentage"},
		Value: internalgnmi.IntValue(10),
	}
	_, mapped = filtered.registry.Map(rfPoint)
	assert.True(t, mapped, "retained group source must remain in the rebuilt registry")
}

func TestFilterPackedRuntimeStreamPreservesAtomicGroupClosure(t *testing.T) {
	stream := sharedGNMIRuntimeStream{sharedGNMIStream: sharedGNMIStream{
		Profile: "atomic", Groups: []string{"group_a", "group_b"},
		AtomicGroupSets: [][]string{{"group_a", "group_b"}},
		Paths: []sharedGNMIPath{
			{Origin: "vendor", Path: "state/a", PathSetID: "atomic-set", Groups: []string{"group_a", "group_b"}},
			{Origin: "vendor", Path: "state/b", PathSetID: "atomic-set", Groups: []string{"group_a", "group_b"}},
		},
	}}
	_, removed, available, err := filterSharedGNMIRuntimeGroups(stream, "group_a")
	require.NoError(t, err)
	assert.False(t, available)
	assert.Equal(t, []string{"group_a", "group_b"}, removed,
		"an indivisible path set cannot leave its partner group running")
}

func TestCompleteRuntimeStreamSyncDoesNotClearSuppressedPackedGroup(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	target := &sharedGNMITargetRuntime{
		fingerprint: "pid-a\x00version-a\x00models-a",
		isolate:     map[string]sharedGNMINegativeEntry{},
		stopped:     map[string]sharedGNMINegativeEntry{},
		now:         func() time.Time { return now },
	}
	stream := sharedGNMIRuntimeStream{sharedGNMIStream: sharedGNMIStream{
		Profile: "wireless", Groups: []string{"ap_capwap", "rf_rrm"},
		Paths: []sharedGNMIPath{{Origin: "vendor", Path: "wireless/state"}},
	}}
	require.NoError(t, target.beginSessionReadiness([]sharedGNMIRuntimeStream{stream}))
	defer target.endSessionReadiness()
	target.stopProfile(sharedGNMIGroupSuppressionKey(stream.Profile, "ap_capwap"))

	receiver := &sharedGNMIReceiver{}
	require.NoError(t, receiver.completeRuntimeStreamSync(t.Context(), target, stream))
	assert.True(t, target.profileStopped(sharedGNMIGroupSuppressionKey(stream.Profile, "ap_capwap")))
	target.readinessMu.Lock()
	assert.False(t, target.readiness.anySynced, "a canceled sibling must not satisfy session readiness")
	target.readinessMu.Unlock()
	assert.False(t, target.sessionUp.Load())
}

func TestEntityLimitOverflowRelaunchesPackedStreamWithoutAffectedGroup(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	requests := make(chan []string, 2)
	fake := &runtimeTestGNMIServer{}
	baseTime := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		paths := runtimeTestSubscribedPaths(request)
		requests <- paths
		if len(paths) == 3 {
			for _, notification := range []*gnmipb.Notification{
				entityLimitTestAPNotification(baseTime, false, "00:11:22:33:44:55"),
				entityLimitTestAPNotification(baseTime.Add(time.Second), false, "66:77:88:99:aa:bb"),
			} {
				if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: notification}}); err != nil {
					return err
				}
				if notification.Timestamp == baseTime.UnixNano() {
					if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}}); err != nil {
						return err
					}
				}
			}
		} else {
			if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}}); err != nil {
				return err
			}
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	profiles := subscriptionProfilesOnly(builtinGNMIProfileCatalyst9800Wireless)
	profiles.Catalyst9800Wireless.Groups = map[string]GNMIGroupConfig{
		"ap_capwap": {MaxEntities: 1},
		"rf_rrm":    {MaxEntities: 1},
		"wlan_ssid": {MaxEntities: 1},
	}
	targetConfig := runtimeTestTarget(endpoint, material.caFile, gnmiModeStream)
	targetConfig.Name = "wireless-packed-runtime"
	targetConfig.Platform = gnmiPlatformIOSXE
	targetConfig.MaxStreams = 4
	targetConfig.Profiles = profiles
	targetConfig.CustomSubscriptions = nil
	sink := &consumertest.MetricsSink{}
	receiver, target, _ := newDeliveryTestReceiver(t, targetConfig, 10, sink)
	receiver.host = componenttest.NewNopHost()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, err := receiver.dialTarget(ctx, target.config)
	require.NoError(t, err)
	defer conn.Close()
	result := make(chan error, 1)
	go func() {
		_, serveErr := receiver.serveTargetStreams(ctx, target, gnmipb.NewGNMIClient(conn))
		result <- serveErr
	}()

	var first, second []string
	select {
	case first = <-requests:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for packed wireless request")
	}
	select {
	case second = <-requests:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for filtered wireless relaunch")
	}
	require.Len(t, first, 3)
	require.Len(t, second, 2)
	for _, path := range second {
		assert.NotContains(t, path, "wireless-ap-global-oper")
	}
	assert.True(t, target.profileStopped(sharedGNMIGroupSuppressionKey(
		builtinGNMIProfileCatalyst9800Wireless, "ap_capwap",
	)))
	assert.False(t, target.profileStopped(sharedGNMIGroupSuppressionKey(
		builtinGNMIProfileCatalyst9800Wireless, "rf_rrm",
	)))
	assert.Equal(t, 1, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.wlc.ap.join.status"))
	require.Len(t, target.cache.Snapshot(), 1, "overflowing entity must not enter committed cache state")

	cancel()
	select {
	case serveErr := <-result:
		require.ErrorIs(t, serveErr, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out stopping packed group replan test")
	}
}

func entityLimitTestAPNotification(timestamp time.Time, atomic bool, mac string) *gnmipb.Notification {
	return &gnmipb.Notification{
		Timestamp: timestamp.UnixNano(), Atomic: atomic,
		Prefix: &gnmipb.Path{Origin: builtinGNMIOriginRFC7951, Elem: []*gnmipb.PathElem{{
			Name: "Cisco-IOS-XE-wireless-ap-global-oper:ap-global-oper-data",
		}}},
		Update: []*gnmipb.Update{{
			Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{
				{Name: "ap-join-stats", Key: map[string]string{"wtp-mac": mac}},
				{Name: "is-joined"},
			}},
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{BoolVal: true}},
		}},
	}
}

func entityLimitTestAPDelete(timestamp time.Time, mac string) *gnmipb.Notification {
	return &gnmipb.Notification{
		Timestamp: timestamp.UnixNano(),
		Prefix: &gnmipb.Path{Origin: builtinGNMIOriginRFC7951, Elem: []*gnmipb.PathElem{{
			Name: "Cisco-IOS-XE-wireless-ap-global-oper:ap-global-oper-data",
		}}},
		Delete: []*gnmipb.Path{{Elem: []*gnmipb.PathElem{{
			Name: "ap-join-stats", Key: map[string]string{"wtp-mac": mac},
		}}}},
	}
}

func entityLimitTestManagerCount(target *sharedGNMITargetRuntime) int {
	manager := target.sessionEntityLimits()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return len(manager.groups[sharedGNMIEntityGroupKey(builtinGNMIProfileCatalyst9800Wireless, "ap_capwap")].entities)
}
