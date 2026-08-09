// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	grpcmetadata "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

const (
	runtimeTestOrigin     = "runtime-test-origin"
	runtimeTestUsername   = "runtime-user"
	runtimeTestPassword   = "runtime-password"
	runtimeTestServerName = "gnmi.runtime.test"
)

func TestSharedGNMIConcurrentSubscriptionsReuseVerifiedConnection(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	var peersMu sync.Mutex
	subscribePeers := map[string]struct{}{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		peerInfo, ok := peer.FromContext(stream.Context())
		if !ok || peerInfo.Addr == nil {
			return status.Error(codes.Internal, "missing Subscribe peer")
		}
		peerAddress := peerInfo.Addr.String()
		peersMu.Lock()
		subscribePeers[peerAddress] = struct{}{}
		peersMu.Unlock()

		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		subscriptions := request.GetSubscribe().GetSubscription()
		if len(subscriptions) != 1 {
			return status.Error(codes.InvalidArgument, "expected one test subscription")
		}
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
			Timestamp: time.Now().UnixNano(),
			Prefix:    &gnmipb.Path{Origin: runtimeTestOrigin},
			Update: []*gnmipb.Update{{
				Path: subscriptions[0].GetPath(),
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: 1}},
			}},
		}}}); err != nil {
			return err
		}
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}}); err != nil {
			return err
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}
	endpoint, listener := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeStream, runtimeTestMapping("first/value", "runtime.connection.first"))
	target.MaxStreams = 2
	target.CustomSubscriptions = append(target.CustomSubscriptions, GNMICustomSubscriptionConfig{
		Name: "runtime-second", Origin: runtimeTestOrigin, Mode: gnmiModeStream, SampleInterval: time.Second,
		Mappings: []GNMIMetricMappingConfig{runtimeTestMapping("second/value", "runtime.connection.second")},
	})
	sink := &consumertest.MetricsSink{}
	runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 10, sink)
	require.Eventually(t, func() bool {
		return runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.connection.first") == 1 &&
			runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.connection.second") == 1
	}, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, int64(1), listener.accepts.Load(), "Capabilities, identity Get, and concurrent Subscribe RPCs must share one verified connection")
	peersMu.Lock()
	assert.Len(t, subscribePeers, 1)
	peersMu.Unlock()
}

func TestSharedGNMIRuntimeTLSMetadataOnceAndLosslessChunks(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		updates := make([]*gnmipb.Update, 0, 5)
		for i := range 5 {
			updates = append(updates, &gnmipb.Update{
				Path: runtimeTestProtoPath(t, fmt.Sprintf("interfaces/interface[name=Ethernet%d]/state/value", i+1)),
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: int64(i + 1)}},
			})
		}
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
			Timestamp: time.Now().UnixNano(),
			Prefix:    &gnmipb.Path{Origin: runtimeTestOrigin},
			Update:    updates,
		}}}); err != nil {
			return err
		}
		return stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}})
	}
	endpoint, listener := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))

	mapping := runtimeTestMapping("interfaces/interface/state/value", "runtime.once.value")
	mapping.PathKeys = map[string]string{"interface.name": "network.interface.name"}
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce, mapping)
	sink := &consumertest.MetricsSink{}
	receiver := runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 2, sink)
	runtimeTestWaitDone(t, receiver)

	fakeSnapshot := fake.snapshot()
	assert.Equal(t, int64(1), listener.accepts.Load(), "Capabilities, identity Get, and Subscribe share one verified connection")
	assert.Equal(t, 1, fakeSnapshot.capabilitiesCalls)
	assert.Equal(t, 1, fakeSnapshot.subscribeCalls)
	assert.Equal(t, 1, fakeSnapshot.getCalls)
	assert.Zero(t, fakeSnapshot.identitySubscribeCalls)
	assert.Zero(t, fakeSnapshot.setCalls)
	assert.Equal(t, runtimeTestUsername, runtimeTestMetadataValue(fakeSnapshot.capabilitiesMetadata, "username"))
	assert.Equal(t, runtimeTestPassword, runtimeTestMetadataValue(fakeSnapshot.capabilitiesMetadata, "password"))
	require.Len(t, fakeSnapshot.subscribeMetadata, 1)
	assert.Equal(t, runtimeTestUsername, runtimeTestMetadataValue(fakeSnapshot.subscribeMetadata[0], "username"))
	assert.Equal(t, runtimeTestPassword, runtimeTestMetadataValue(fakeSnapshot.subscribeMetadata[0], "password"))
	require.Len(t, fakeSnapshot.requests, 1)
	assert.Equal(t, gnmipb.SubscriptionList_ONCE, fakeSnapshot.requests[0].GetSubscribe().GetMode())

	batches := runtimeTestMetricBatches(sink.AllMetrics(), "runtime.once.value")
	require.Len(t, batches, 3)
	resourceAttributes := batches[0].ResourceMetrics().At(0).Resource().Attributes()
	assert.Equal(t, "network", attrValue(t, resourceAttributes, "hw.type"))
	assert.Equal(t, "ios_xr", attrValue(t, resourceAttributes, "cisco.os.name"))
	assert.Equal(t, "Cisco IOS XR", attrValue(t, resourceAttributes, "os.name"))
	assert.Equal(t, "gnmi_dial_in", attrValue(t, resourceAttributes, "cisco.telemetry.transport"))
	total := 0
	for _, batch := range batches {
		count := runtimeTestMetricPointCount(batch, "runtime.once.value")
		assert.LessOrEqual(t, count, 2)
		total += count
	}
	assert.Equal(t, 5, total)
}

func TestSharedGNMIAvailabilityStartsAfterSubscriptionProgress(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	subscribed := make(chan struct{})
	releaseSync := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseSync) }) })
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		close(subscribed)
		<-releaseSync
		return stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}})
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce, runtimeTestMapping("system/value", "runtime.availability.value"))
	sink := &consumertest.MetricsSink{}
	receiver := runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 10, sink)

	select {
	case <-subscribed:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for subscription request")
	}
	assert.Zero(t, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.device.up"),
		"Capabilities and a sent request alone must not report the target up")

	releaseOnce.Do(func() { close(releaseSync) })
	runtimeTestWaitDone(t, receiver)
	assert.Equal(t, 1, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.device.up"),
		"a non-health-only target must report up after its first sync")
}

func TestSharedGNMIAvailabilityRefusalReleasesGateAndRetries(t *testing.T) {
	cfg := validGNMITestConfig()
	rejecting := &runtimeTestRejectingConsumer{metricName: "cisco.device.up", maxRefusals: 1}
	created, err := newSharedGNMIReceiver(
		receivertest.NewNopSettings(componentmetadata.Type),
		cfg,
		rejecting,
	)
	require.NoError(t, err)
	receiver, ok := created.(*sharedGNMIReceiver)
	require.True(t, ok)
	t.Cleanup(receiver.telemetry.shutdown)
	require.Len(t, receiver.targets, 1)
	target := receiver.targets[0]
	target.setVerifiedIdentity(verifiedGNMIIdentity{
		Product: gnmiProductASR9000, OSFamily: gnmiPlatformIOSXR,
		ModelIdentifier: "ASR-9904", SoftwareVersion: "24.4.1",
	})
	for _, stream := range target.streams {
		target.recordStreamProgress(stream)
	}

	receiver.emitTargetAvailable(t.Context(), target)
	assert.False(t, target.sessionUp.Load(), "a refused up signal must remain eligible for retry")
	assert.Empty(t, receiver.notificationSlots)

	receiver.emitTargetAvailable(t.Context(), target)
	assert.True(t, target.sessionUp.Load())
	assert.Equal(t, int64(2), rejecting.calls.Load())
	assert.Equal(t, int64(1), rejecting.accepted.Load())
	assert.Empty(t, receiver.notificationSlots)
}

func TestSharedGNMICuratedQualificationTracksBisectionGroups(t *testing.T) {
	original := sharedGNMIRuntimeStream{sharedGNMIStream: sharedGNMIStream{
		Profile: builtinGNMIProfileSystem,
		Paths: []sharedGNMIPath{
			{Origin: "openconfig-system", Path: "system/state/hostname"},
			{Origin: "openconfig-system", Path: "system/state/current-datetime"},
		},
	}}
	target := &sharedGNMITargetRuntime{
		streams:               []sharedGNMIRuntimeStream{original},
		degradedQualification: map[string]struct{}{},
	}
	target.resetSessionQualification()
	require.Len(t, target.pendingQualification, 1)

	groups := [][]sharedGNMIPath{{original.Paths[0]}, {original.Paths[1]}}
	target.replacePendingQualificationStream(original, groups)
	require.Len(t, target.pendingQualification, 2)

	first := original
	first.Paths = groups[0]
	target.recordStreamProgress(first)
	assert.False(t, target.sessionQualifiedForAvailability(), "one accepted split group is still pending")

	second := original
	second.Paths = groups[1]
	target.recordStreamProgress(second)
	assert.True(t, target.sessionQualifiedForAvailability(), "all accepted split groups reached progress")
}

func TestSharedGNMIRequiredCustomStreamIsQualificationObligation(t *testing.T) {
	requiredCustom := sharedGNMIRuntimeStream{sharedGNMIStream: sharedGNMIStream{
		Profile: "required-custom", Required: true,
		Paths: []sharedGNMIPath{{Origin: "openconfig-system", Path: "system/state"}},
	}}
	target := &sharedGNMITargetRuntime{
		streams:               []sharedGNMIRuntimeStream{requiredCustom},
		degradedQualification: map[string]struct{}{},
	}
	target.resetSessionQualification()
	require.Len(t, target.pendingQualification, 1)
	assert.False(t, target.sessionQualifiedForAvailability())

	target.recordStreamProgress(requiredCustom)
	assert.True(t, target.sessionQualifiedForAvailability())
	target.markQualificationDegraded(requiredCustom)
	assert.False(t, target.sessionQualifiedForAvailability())
}

func TestSharedGNMIMalformedUpdateDoesNotSatisfyQualification(t *testing.T) {
	cfg := validGNMITestConfig()
	sink := &consumertest.MetricsSink{}
	created, err := newSharedGNMIReceiver(
		receivertest.NewNopSettings(componentmetadata.Type),
		cfg,
		sink,
	)
	require.NoError(t, err)
	receiver := created.(*sharedGNMIReceiver)
	t.Cleanup(receiver.telemetry.shutdown)
	require.Len(t, receiver.targets, 1)
	target := receiver.targets[0]
	require.NotEmpty(t, target.streams)
	stream := target.streams[0]
	target.resetSessionQualification()
	require.NotEmpty(t, target.pendingQualification)

	response := &gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
		Timestamp: time.Now().UnixNano(),
		Update: []*gnmipb.Update{{
			Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "state"}}},
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{
				JsonIetfVal: []byte(`{"unterminated":`),
			}},
		}},
	}}}
	synced, err := receiver.handleSubscribeResponse(t.Context(), target, stream, response)
	require.NoError(t, err)
	assert.False(t, synced)
	assert.NotEmpty(t, target.pendingQualification)
	assert.Contains(t, target.degradedQualification, stream.Profile)
	assert.False(t, target.sessionQualifiedForAvailability())
	assert.Zero(t, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.device.up"))

	synced, err = receiver.handleSubscribeResponse(t.Context(), target, stream, &gnmipb.SubscribeResponse{
		Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
	})
	require.NoError(t, err)
	assert.True(t, synced)
	assert.False(t, target.sessionQualifiedForAvailability(), "a later sync cannot repair a malformed enabled-profile update")
	assert.Zero(t, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.device.up"))
}

func TestSharedGNMILateQualificationDegradationEmitsDownOnce(t *testing.T) {
	cfg := validGNMITestConfig()
	sink := &consumertest.MetricsSink{}
	created, err := newSharedGNMIReceiver(
		receivertest.NewNopSettings(componentmetadata.Type),
		cfg,
		sink,
	)
	require.NoError(t, err)
	receiver := created.(*sharedGNMIReceiver)
	t.Cleanup(receiver.telemetry.shutdown)
	require.Len(t, receiver.targets, 1)
	target := receiver.targets[0]
	target.setVerifiedIdentity(verifiedGNMIIdentity{
		Product: gnmiProductASR9000, OSFamily: gnmiPlatformIOSXR,
		ModelIdentifier: "ASR-9904", SoftwareVersion: "24.4.1",
	})
	for _, stream := range target.streams {
		target.recordStreamProgress(stream)
	}
	receiver.emitTargetAvailable(t.Context(), target)
	require.True(t, target.sessionUp.Load())
	require.Equal(t, []int64{1}, runtimeTestDeviceUpValuesAll(sink.AllMetrics()))

	target.markQualificationDegraded(target.streams[0])
	receiver.emitTargetUnavailable(t.Context(), target)
	assert.False(t, target.sessionUp.Load())
	assert.False(t, target.sessionQualifiedForAvailability())
	assert.Equal(t, []int64{1, 0}, runtimeTestDeviceUpValuesAll(sink.AllMetrics()))

	receiver.emitTargetUnavailable(t.Context(), target)
	assert.Equal(t, []int64{1, 0}, runtimeTestDeviceUpValuesAll(sink.AllMetrics()),
		"repeated degradation must not duplicate the down transition")
}

func TestSharedGNMILateQualificationDownRefusalRemainsRetryable(t *testing.T) {
	cfg := validGNMITestConfig()
	consumer := &runtimeTestRejectingDownConsumer{}
	created, err := newSharedGNMIReceiver(
		receivertest.NewNopSettings(componentmetadata.Type),
		cfg,
		consumer,
	)
	require.NoError(t, err)
	receiver := created.(*sharedGNMIReceiver)
	t.Cleanup(receiver.telemetry.shutdown)
	target := receiver.targets[0]
	target.setVerifiedIdentity(verifiedGNMIIdentity{
		Product: gnmiProductASR9000, OSFamily: gnmiPlatformIOSXR,
		ModelIdentifier: "ASR-9904", SoftwareVersion: "24.4.1",
	})
	for _, stream := range target.streams {
		target.recordStreamProgress(stream)
	}
	receiver.emitTargetAvailable(t.Context(), target)
	require.True(t, target.sessionUp.Load())

	target.markQualificationDegraded(target.streams[0])
	receiver.emitTargetUnavailable(t.Context(), target)
	assert.True(t, target.sessionUp.Load(), "a refused down transition must remain eligible for retry")
	assert.True(t, consumer.rejected.Load())
	assert.Equal(t, []int64{1}, runtimeTestDeviceUpValuesAll(consumer.sink.AllMetrics()))

	receiver.emitTargetAvailable(t.Context(), target)
	assert.False(t, target.sessionUp.Load())
	assert.Equal(t, []int64{1, 0}, runtimeTestDeviceUpValuesAll(consumer.sink.AllMetrics()))
}

func TestSharedGNMIStreamAndPathKeysRejectNULBoundaryCollisions(t *testing.T) {
	first := sharedGNMIPath{PathTarget: "a\x00b", Origin: "c", Path: "d"}
	second := sharedGNMIPath{PathTarget: "a", Origin: "b\x00c", Path: "d"}
	assert.NotEqual(t, sharedGNMIPathKey(first), sharedGNMIPathKey(second))
	assert.NotEqual(t,
		sharedGNMIQualificationStreamKey(sharedGNMIStream{Profile: "profile", Paths: []sharedGNMIPath{first}}),
		sharedGNMIQualificationStreamKey(sharedGNMIStream{Profile: "profile", Paths: []sharedGNMIPath{second}}),
	)
}

func TestOpticalPresenceIdentityRejectsNULBoundaryCollision(t *testing.T) {
	first, firstAttrs := opticalPresenceIdentity(map[string]string{
		"network.interface.name": "Ethernet1",
		"cisco.optics.lane":      "1\x00dom",
		"cisco.optics.profile":   "lane",
	})
	second, secondAttrs := opticalPresenceIdentity(map[string]string{
		"network.interface.name": "Ethernet1",
		"cisco.optics.lane":      "1",
		"cisco.optics.profile":   "dom\x00lane",
	})
	require.NotEmpty(t, first)
	require.NotEmpty(t, second)
	assert.NotEqual(t, first, second)
	assert.Equal(t, "1\x00dom", firstAttrs["cisco.optics.lane"])
	assert.Equal(t, "dom\x00lane", secondAttrs["cisco.optics.profile"])
}

func TestSharedGNMIRuntimePollWaitsForSyncAndSerializesPolls(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	sequenceDone := make(chan struct{})
	var sequenceErr atomic.Value
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		requests := make(chan *gnmipb.SubscribeRequest, 4)
		receiveErrors := make(chan error, 1)
		go func() {
			for {
				request, err := stream.Recv()
				if err != nil {
					receiveErrors <- err
					return
				}
				fake.recordRequest(request)
				requests <- request
			}
		}()

		select {
		case request := <-requests:
			if request.GetSubscribe() == nil {
				sequenceErr.Store(errors.New("first request was not the subscription"))
				close(sequenceDone)
				return nil
			}
		case err := <-receiveErrors:
			return err
		case <-time.After(time.Second):
			return errors.New("timed out waiting for subscription request")
		}

		select {
		case request := <-requests:
			sequenceErr.Store(fmt.Errorf("request %T arrived before initial sync", request.GetRequest()))
			close(sequenceDone)
			return nil
		case <-time.After(100 * time.Millisecond):
		}
		if sendErr := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}}); sendErr != nil {
			return sendErr
		}

		select {
		case request := <-requests:
			if request.GetPoll() == nil {
				sequenceErr.Store(errors.New("first post-sync request was not a poll"))
				close(sequenceDone)
				return nil
			}
		case err := <-receiveErrors:
			return err
		case <-time.After(time.Second):
			return errors.New("timed out waiting for first poll")
		}

		select {
		case request := <-requests:
			sequenceErr.Store(fmt.Errorf("second request %T arrived with a poll outstanding", request.GetRequest()))
		case <-time.After(100 * time.Millisecond):
		}
		if sendErr := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}}); sendErr != nil {
			return sendErr
		}
		close(sequenceDone)
		<-stream.Context().Done()
		return stream.Context().Err()
	}
	endpoint, listener := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModePoll, runtimeTestMapping("system/value", "runtime.poll.value"))
	target.CustomSubscriptions[0].PollInterval = time.Second
	receiver := runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 10, consumertest.NewNop())

	select {
	case <-sequenceDone:
	case <-time.After(3 * time.Second):
		require.FailNow(t, "timed out waiting for POLL sequence")
	}
	if errValue := sequenceErr.Load(); errValue != nil {
		require.NoError(t, errValue.(error))
	}
	assert.Equal(t, int64(1), listener.accepts.Load())
	require.GreaterOrEqual(t, len(fake.snapshot().requests), 2)

	shutdownCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, receiver.Shutdown(shutdownCtx))
}

func TestSharedGNMIRuntimePollBisectionValidatesPollStageAndDiscardsProbes(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		paths := runtimeTestSubscribedPaths(request)
		if sendErr := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}}); sendErr != nil {
			return sendErr
		}
		poll, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(poll)
		if poll.GetPoll() == nil {
			return status.Error(codes.InvalidArgument, "expected poll")
		}
		if runtimeTestContains(paths, "bad/value") {
			return status.Error(codes.InvalidArgument, "path rejected during poll")
		}
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
			Timestamp: time.Now().UnixNano(), Prefix: &gnmipb.Path{Origin: runtimeTestOrigin},
			Update: []*gnmipb.Update{{Path: runtimeTestProtoPath(t, "good/value"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: 17}}}},
		}}}); err != nil {
			return err
		}
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}}); err != nil {
			return err
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}
	endpoint, listener := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModePoll,
		runtimeTestMapping("bad/value", "runtime.poll.bad"),
		runtimeTestMapping("good/value", "runtime.poll.good"),
	)
	target.CustomSubscriptions[0].PollInterval = time.Hour
	sink := &consumertest.MetricsSink{}
	receiver := runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 10, sink)

	require.Eventually(t, func() bool {
		return fake.snapshot().subscribeCalls == 4 && runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.poll.good") == 1
	}, 5*time.Second, 20*time.Millisecond)
	assert.Equal(t, int64(1), listener.accepts.Load())
	assert.True(t, receiver.targets[0].pathIsolated(sharedGNMIPath{Origin: runtimeTestOrigin, Path: "bad/value"}))

	shutdownCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, receiver.Shutdown(shutdownCtx))
}

func TestSharedGNMIRuntimeBisectionIsolatesBadPathOnOneConnection(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		paths := runtimeTestSubscribedPaths(request)
		if runtimeTestContains(paths, "bad/value") {
			return status.Error(codes.InvalidArgument, "unsupported test path")
		}
		if !runtimeTestContains(paths, "good/value") {
			return status.Error(codes.Internal, "missing good path")
		}
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
			Timestamp: time.Now().UnixNano(),
			Prefix:    &gnmipb.Path{Origin: runtimeTestOrigin},
			Update: []*gnmipb.Update{{
				Path: runtimeTestProtoPath(t, "good/value"),
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: 7}},
			}},
		}}}); err != nil {
			return err
		}
		return stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}})
	}
	endpoint, listener := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce,
		runtimeTestMapping("bad/value", "runtime.bad.value"),
		runtimeTestMapping("good/value", "runtime.good.value"),
	)
	sink := &consumertest.MetricsSink{}
	receiver := runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 10, sink)
	runtimeTestWaitDone(t, receiver)

	assert.Equal(t, int64(1), listener.accepts.Load(), "configured Subscribe and bisection probes reuse the verified connection")
	snapshot := fake.snapshot()
	assert.Equal(t, 4, snapshot.subscribeCalls, "combined rejection, two discard-only probes, and one final good subscription")
	assert.Equal(t, 1, snapshot.getCalls)
	assert.Zero(t, snapshot.identitySubscribeCalls)
	assert.Zero(t, snapshot.setCalls)
	for _, metadata := range snapshot.subscribeMetadata {
		assert.Equal(t, runtimeTestUsername, runtimeTestMetadataValue(metadata, "username"))
		assert.Equal(t, runtimeTestPassword, runtimeTestMetadataValue(metadata, "password"))
	}
	assert.Equal(t, 1, runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.good.value"))
	assert.Zero(t, runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.bad.value"))
	assert.True(t, receiver.targets[0].pathIsolated(sharedGNMIPath{Origin: runtimeTestOrigin, Path: "bad/value"}))
}

func TestSharedGNMIRuntimeBisectionSilentProbeIsTimeBounded(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		paths := runtimeTestSubscribedPaths(request)
		if len(paths) > 1 || runtimeTestContains(paths, "bad/value") {
			return status.Error(codes.InvalidArgument, "unsupported test path")
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeStream,
		runtimeTestMapping("bad/value", "runtime.bad.value"),
		runtimeTestMapping("good/value", "runtime.good.value"),
	)

	started := time.Now()
	err := runtimeTestServeTarget(t, target)
	require.Error(t, err)
	assert.Equal(t, codes.DeadlineExceeded, status.Code(err))
	assert.Less(t, time.Since(started), time.Second)
	assert.Equal(t, 3, fake.snapshot().subscribeCalls, "combined rejection and two bounded half probes")
	var compatibility *sharedGNMICompatibilityError
	assert.NotErrorAs(t, err, &compatibility, "a silent diagnostic probe is a retryable session failure")
}

func TestSharedGNMIRuntimeBisectionAtStreamLimitDoesNotDeadlock(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		paths := runtimeTestSubscribedPaths(request)
		for _, path := range paths {
			if strings.HasPrefix(path, "bad") {
				return status.Error(codes.InvalidArgument, "unsupported test path")
			}
		}
		if runtimeTestContains(paths, "good-1/value") {
			if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
				Timestamp: time.Now().UnixNano(),
				Prefix:    &gnmipb.Path{Origin: runtimeTestOrigin},
				Update: []*gnmipb.Update{{
					Path: runtimeTestProtoPath(t, "good-1/value"),
					Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: 11}},
				}},
			}}}); err != nil {
				return err
			}
		}
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}}); err != nil {
			return err
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}
	endpoint, listener := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeStream,
		runtimeTestMapping("bad-1/value", "runtime.bad.one"),
		runtimeTestMapping("bad-2/value", "runtime.bad.two"),
		runtimeTestMapping("good-1/value", "runtime.good.one"),
		runtimeTestMapping("good-2/value", "runtime.good.two"),
	)
	target.MaxStreams = 2
	target.CustomSubscriptions = append(target.CustomSubscriptions, GNMICustomSubscriptionConfig{
		Name: "runtime-keepalive", Origin: runtimeTestOrigin, Mode: gnmiModeStream,
		SampleInterval: time.Second,
		Mappings:       []GNMIMetricMappingConfig{runtimeTestMapping("keepalive/value", "runtime.keepalive")},
	})
	sink := &consumertest.MetricsSink{}
	receiver := runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 10, sink)

	require.Eventually(t, func() bool {
		return fake.snapshot().subscribeCalls >= 7 && runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.good.one") > 0
	}, 5*time.Second, 20*time.Millisecond)
	assert.Equal(t, int64(1), listener.accepts.Load(), "configured streams and bisection probes reuse the verified connection")
	for _, path := range []string{"bad-1/value", "bad-2/value"} {
		assert.True(t, receiver.targets[0].pathIsolated(sharedGNMIPath{Origin: runtimeTestOrigin, Path: path}), path)
	}

	shutdownCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, receiver.Shutdown(shutdownCtx))
}

func TestSharedGNMIRuntimeCombinationRejectionStopsProfileWhenGroupsExceedStreamLimit(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		if len(runtimeTestSubscribedPaths(request)) > 2 {
			return status.Error(codes.InvalidArgument, "device accepts at most two paths per stream")
		}
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}}); err != nil {
			return err
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}
	endpoint, listener := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeStream,
		runtimeTestMapping("path-a/value", "runtime.combo.a"),
		runtimeTestMapping("path-b/value", "runtime.combo.b"),
		runtimeTestMapping("path-c/value", "runtime.combo.c"),
		runtimeTestMapping("path-d/value", "runtime.combo.d"),
	)
	target.MaxStreams = 2
	target.CustomSubscriptions = append(target.CustomSubscriptions, GNMICustomSubscriptionConfig{
		Name: "runtime-keepalive", Origin: runtimeTestOrigin, Mode: gnmiModeStream, SampleInterval: time.Second,
		Mappings: []GNMIMetricMappingConfig{runtimeTestMapping("keepalive/value", "runtime.combo.keepalive")},
	})
	receiver := runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 10, consumertest.NewNop())

	require.Eventually(t, func() bool {
		return receiver.targets[0].profileStopped("runtime-custom") && fake.snapshot().subscribeCalls == 5
	}, 5*time.Second, 20*time.Millisecond)
	assert.False(t, receiver.targets[0].profileStopped("runtime-keepalive"))
	assert.Equal(t, int64(1), listener.accepts.Load())
	assert.Never(t, func() bool { return fake.snapshot().subscribeCalls > 5 }, 300*time.Millisecond, 20*time.Millisecond,
		"a deterministic group-level rejection must not restart bisection indefinitely")

	shutdownCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, receiver.Shutdown(shutdownCtx))
}

func TestSharedGNMIRuntimeCombinationRejectionContinuesGroupsWithinStreamLimit(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		paths := runtimeTestSubscribedPaths(request)
		if len(paths) > 2 {
			return status.Error(codes.InvalidArgument, "device accepts at most two paths per stream")
		}
		updates := make([]*gnmipb.Update, 0, len(paths))
		for index, path := range paths {
			updates = append(updates, &gnmipb.Update{
				Path: runtimeTestProtoPath(t, path),
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: int64(index + 1)}},
			})
		}
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
			Timestamp: time.Now().UnixNano(),
			Prefix:    &gnmipb.Path{Origin: runtimeTestOrigin},
			Atomic:    true,
			Update:    updates,
		}}}); err != nil {
			return err
		}
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}}); err != nil {
			return err
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}
	endpoint, listener := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeStream,
		runtimeTestMapping("path-a/value", "runtime.split.a"),
		runtimeTestMapping("path-b/value", "runtime.split.b"),
		runtimeTestMapping("path-c/value", "runtime.split.c"),
		runtimeTestMapping("path-d/value", "runtime.split.d"),
	)
	target.MaxStreams = 2
	sink := &consumertest.MetricsSink{}
	receiver := runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 10, sink)

	require.Eventually(t, func() bool {
		return fake.snapshot().subscribeCalls >= 6 &&
			runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.split.a") > 0 &&
			runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.split.d") > 0 &&
			len(receiver.targets[0].cache.Snapshot()) == 4
	}, 5*time.Second, 20*time.Millisecond)
	assert.False(t, receiver.targets[0].profileStopped("runtime-custom"))
	assert.Equal(t, int64(1), listener.accepts.Load())
	assert.Len(t, receiver.targets[0].cache.Snapshot(), 4,
		"atomic snapshots from separately bisected subscriptions must preserve sibling state")

	shutdownCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, receiver.Shutdown(shutdownCtx))
}

func TestSharedGNMIBisectedStreamsSeparateCacheScopeFromLogicalRuntimeKey(t *testing.T) {
	original := sharedGNMIRuntimeStream{sharedGNMIStream: sharedGNMIStream{
		OwnerID: "logical-owner",
		Paths: []sharedGNMIPath{
			{Origin: "openconfig", Path: "system/first"},
			{Origin: "openconfig", Path: "system/second"},
		},
	}}
	first := sharedGNMIBisectedRuntimeStream(original, original.Paths[:1])
	second := sharedGNMIBisectedRuntimeStream(original, original.Paths[1:])

	assert.Equal(t, sharedGNMIRuntimeStreamKey(original), sharedGNMIRuntimeStreamKey(first))
	assert.Equal(t, sharedGNMIRuntimeStreamKey(first), sharedGNMIRuntimeStreamKey(second))
	assert.NotEqual(t, sharedGNMICacheOwnerID(first), sharedGNMICacheOwnerID(second))
	assert.NotEqual(t, original.OwnerID, sharedGNMICacheOwnerID(first))
	assert.Equal(t, sharedGNMICacheOwnerID(first), sharedGNMICacheOwnerID(sharedGNMIBisectedRuntimeStream(original, original.Paths[:1])))
	reordered := sharedGNMIBisectedRuntimeStream(original, []sharedGNMIPath{original.Paths[1], original.Paths[0]})
	assert.Equal(t, sharedGNMICacheOwnerID(reordered), sharedGNMICacheOwnerID(sharedGNMIBisectedRuntimeStream(original, original.Paths)),
		"physical ownership must depend on the subscription set, not path order")
	resolvedSubset := sharedGNMIResolvedRuntimeStreams(original, [][]sharedGNMIPath{original.Paths[:1]})
	require.Len(t, resolvedSubset, 1)
	assert.NotEqual(t, original.OwnerID, sharedGNMICacheOwnerID(resolvedSubset[0]),
		"a single strict-subset resolution is still a physical topology change")
	resolvedReordered := sharedGNMIResolvedRuntimeStreams(original, [][]sharedGNMIPath{{original.Paths[1], original.Paths[0]}})
	require.Len(t, resolvedReordered, 1)
	assert.Equal(t, original.OwnerID, sharedGNMICacheOwnerID(resolvedReordered[0]),
		"an identical selector set does not require a cache-owner transition")
	target := &sharedGNMITargetRuntime{stopped: map[string]struct{}{}}
	target.stopStream(first)
	assert.True(t, target.streamStopped(second), "stopping one physical group must stop its logical siblings")
}

func TestSharedGNMICacheTopologyKeepsNestedSplitCandidateWhenSiblingProgresses(t *testing.T) {
	cache, err := internalgnmi.NewCache(20)
	require.NoError(t, err)
	receiver := &sharedGNMIReceiver{}
	original := sharedGNMIRuntimeStream{sharedGNMIStream: sharedGNMIStream{
		OwnerID: "logical-owner",
		Paths: []sharedGNMIPath{
			{Origin: "openconfig", Path: "system/first"},
			{Origin: "openconfig", Path: "system/second"},
			{Origin: "openconfig", Path: "system/third"},
		},
	}}
	target := &sharedGNMITargetRuntime{
		cache:           cache,
		stopped:         map[string]struct{}{},
		cacheTopologies: map[string]*sharedGNMICacheTopology{original.OwnerID: {current: []string{original.OwnerID}}},
	}
	firstSplit := sharedGNMIBisectedRuntimeStreams(original, [][]sharedGNMIPath{original.Paths[:2], original.Paths[2:]})
	require.NoError(t, receiver.reconcileCacheTopology(t.Context(), target, firstSplit[0]))
	require.NoError(t, receiver.reconcileCacheTopology(t.Context(), target, firstSplit[1]))
	assert.Equal(t, sharedGNMICacheTopologyOwners(firstSplit[0]), target.cacheTopologies[original.OwnerID].current)

	nested := sharedGNMIBisectedRuntimeStreams(firstSplit[0], [][]sharedGNMIPath{firstSplit[0].Paths[:1], firstSplit[0].Paths[1:]})
	require.NoError(t, receiver.reconcileCacheTopology(t.Context(), target, nested[0]))
	require.NoError(t, receiver.reconcileCacheTopology(t.Context(), target, firstSplit[1]))
	assert.NotEmpty(t, target.cacheTopologies[original.OwnerID].candidate,
		"progress from an unchanged sibling must not abandon the nested split candidate")
	require.NoError(t, receiver.reconcileCacheTopology(t.Context(), target, nested[1]))
	assert.Equal(t, sharedGNMICacheTopologyOwners(nested[0]), target.cacheTopologies[original.OwnerID].current)
}

func TestSharedGNMIRuntimeConsumerRefusalReconnectsAndRedeliversEqualTimestamp(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	timestamp := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		updates := make([]*gnmipb.Update, 0, 2)
		for i := range 2 {
			updates = append(updates, &gnmipb.Update{
				Path: runtimeTestProtoPath(t, fmt.Sprintf("interfaces/interface[name=Ethernet%d]/state/value", i+1)),
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: int64(i + 1)}},
			})
		}
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
			Timestamp: timestamp.UnixNano(), Prefix: &gnmipb.Path{Origin: runtimeTestOrigin}, Update: updates,
		}}}); err != nil {
			return err
		}
		return stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}})
	}
	endpoint, listener := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	mapping := runtimeTestMapping("interfaces/interface/state/value", "runtime.refused.value")
	mapping.PathKeys = map[string]string{"interface.name": "network.interface.name"}
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce, mapping)
	rejecting := &runtimeTestRejectingConsumer{metricName: "runtime.refused.value", maxRefusals: 1}
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })
	settings := receivertest.NewNopSettings(componentmetadata.Type)
	settings.MeterProvider = provider
	receiver := runtimeTestStartReceiver(t, settings, target, 1, rejecting)
	select {
	case <-receiver.done:
	case <-time.After(8 * time.Second):
		require.FailNow(t, "timed out waiting for refusal reconnect and redelivery")
	}

	assert.Equal(t, int64(2), listener.accepts.Load(), "each retry creates one new verified session connection")
	assert.Equal(t, int64(1), rejecting.refusals.Load())
	assert.Equal(t, int64(2), rejecting.accepted.Load())
	assert.Equal(t, 2, fake.snapshot().subscribeCalls)
	assert.Equal(t, int64(1), runtimeTestTelemetryIntSum(t, reader, "otelcol_ciscoosreceiver_gnmi_consumer_refusals"))
	assert.Len(t, receiver.targets[0].cache.Snapshot(), 2,
		"the refused attempt must not make equal-timestamp redelivery look duplicate")
}

func TestSharedGNMIRuntimeRejectsWrongCAAndSAN(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))

	t.Run("wrong CA", func(t *testing.T) {
		wrong := runtimeTestTLSMaterial(t)
		target := runtimeTestTarget(endpoint, wrong.caFile, gnmiModeOnce, runtimeTestMapping("system/value", "runtime.tls.value"))
		target.ConnectTimeout = 100 * time.Millisecond
		err := runtimeTestServeTarget(t, target)
		require.Error(t, err)
		assert.Contains(t, strings.ToLower(err.Error()), "connection did not become ready")
	})

	t.Run("SAN mismatch", func(t *testing.T) {
		target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce, runtimeTestMapping("system/value", "runtime.tls.value"))
		target.TLS.ServerNameOverride = "wrong.runtime.test"
		target.ConnectTimeout = 100 * time.Millisecond
		err := runtimeTestServeTarget(t, target)
		require.Error(t, err)
		assert.Contains(t, strings.ToLower(err.Error()), "connection did not become ready")
	})
}

func TestSharedGNMIRuntimeSelfSignedTLSRequiresExplicitOptIn(t *testing.T) {
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		return stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}})
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, runtimeTestSelfSignedServerTLS(t))

	t.Run("default deny", func(t *testing.T) {
		target := runtimeTestTarget(endpoint, "", gnmiModeOnce, runtimeTestMapping("system/value", "runtime.self_signed.value"))
		target.ConnectTimeout = 100 * time.Millisecond
		err := runtimeTestServeTarget(t, target)
		require.Error(t, err)
		assert.ErrorContains(t, err, "tls.ca_file")
		assert.ErrorContains(t, err, "tls.insecure_skip_verify: true")
	})

	t.Run("explicit lab opt-in", func(t *testing.T) {
		target := runtimeTestTarget(endpoint, "", gnmiModeOnce, runtimeTestMapping("system/value", "runtime.self_signed.value"))
		target.TLS.InsecureSkipVerify = true
		require.NoError(t, runtimeTestServeTarget(t, target))
	})

	snapshot := fake.snapshot()
	assert.Equal(t, 1, snapshot.capabilitiesCalls)
	assert.Equal(t, 1, snapshot.subscribeCalls)
}

func TestSharedGNMIRuntimeMutualTLSWithoutPasswordMetadata(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		return stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}})
	}
	endpoint, listener := runtimeTestStartGNMIServer(t, fake, material.serverTLS(true))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce, runtimeTestMapping("system/value", "runtime.mtls.value"))
	target.Credentials = GNMICredentialsConfig{Mode: gnmiCredentialMTLS}
	target.TLS.CertFile = material.clientCertFile
	target.TLS.KeyFile = material.clientKeyFile
	receiver := runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 10, consumertest.NewNop())
	runtimeTestWaitDone(t, receiver)

	snapshot := fake.snapshot()
	assert.Equal(t, int64(1), listener.accepts.Load())
	assert.Equal(t, 1, snapshot.capabilitiesCalls)
	assert.Equal(t, 1, snapshot.subscribeCalls)
	assert.Empty(t, runtimeTestMetadataValue(snapshot.capabilitiesMetadata, "username"))
	require.Len(t, snapshot.subscribeMetadata, 1)
	assert.Empty(t, runtimeTestMetadataValue(snapshot.subscribeMetadata[0], "password"))
	assert.Equal(t, 1, snapshot.getCalls)
	assert.Zero(t, snapshot.identitySubscribeCalls)
	assert.Zero(t, snapshot.setCalls)
}

func TestSharedGNMIRuntimeOnceRequiresCleanCompletionAfterSync(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}}); err != nil {
			return err
		}
		return status.Error(codes.Internal, "post-sync failure")
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce, runtimeTestMapping("system/value", "runtime.once.completion"))
	err := runtimeTestServeTarget(t, target)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.NotContains(t, err.Error(), "post-sync failure")
	assert.Contains(t, err.Error(), "code=Internal")
}

func TestSharedGNMIRuntimeAuthenticationFailureUsesSlowBackoff(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{capabilities: func(context.Context) (*gnmipb.CapabilityResponse, error) {
		return nil, status.Error(codes.Unauthenticated, "credentials denied")
	}}
	endpoint, listener := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce, runtimeTestMapping("system/value", "runtime.auth.value"))
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })
	settings := receivertest.NewNopSettings(componentmetadata.Type)
	settings.MeterProvider = provider
	receiver := runtimeTestStartReceiver(t, settings, target, 10, consumertest.NewNop())

	require.Eventually(t, func() bool { return fake.snapshot().capabilitiesCalls == 1 }, 2*time.Second, 10*time.Millisecond)
	assert.Never(t, func() bool { return fake.snapshot().capabilitiesCalls > 1 }, 300*time.Millisecond, 20*time.Millisecond,
		"authentication failures must not create an AAA retry storm")
	snapshot := fake.snapshot()
	assert.Zero(t, snapshot.subscribeCalls)
	assert.Equal(t, int64(1), listener.accepts.Load())
	assert.Equal(t, runtimeTestUsername, runtimeTestMetadataValue(snapshot.capabilitiesMetadata, "username"))
	assert.Equal(t, int64(1), runtimeTestTelemetryIntSum(t, reader, "otelcol_ciscoosreceiver_gnmi_authentication_failures"))

	shutdownCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, receiver.Shutdown(shutdownCtx))
}

func TestSharedGNMIInBandErrorsAreSanitizedAndKeepClassification(t *testing.T) {
	receiver := &sharedGNMIReceiver{}
	response := func(code codes.Code) *gnmipb.SubscribeResponse {
		protocolErr := &gnmipb.Error{Code: uint32(code), Message: "device-controlled secret"} //nolint:staticcheck // Exercise deprecated in-band error handling.
		return &gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Error{Error: protocolErr}}
	}

	_, authErr := receiver.handleSubscribeResponse(t.Context(), nil, sharedGNMIRuntimeStream{}, response(codes.PermissionDenied))
	require.Error(t, authErr)
	assert.Equal(t, codes.PermissionDenied, status.Code(authErr))
	assert.True(t, isSharedGNMIAuthenticationError(authErr))
	assert.NotContains(t, authErr.Error(), "device-controlled")
	assert.NotContains(t, authErr.Error(), "secret")

	_, unsupportedErr := receiver.handleSubscribeResponse(t.Context(), nil, sharedGNMIRuntimeStream{}, response(codes.InvalidArgument))
	require.Error(t, unsupportedErr)
	var unsupported *sharedGNMIUnsupportedError
	require.ErrorAs(t, unsupportedErr, &unsupported)
	assert.Equal(t, codes.InvalidArgument, status.Code(unsupportedErr))
	assert.NotContains(t, unsupportedErr.Error(), "device-controlled")

	for name, receive := range map[string]func(
		grpc.BidiStreamingClient[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse],
		*gnmiResponseAdmission,
		*sharedGNMITargetRuntime,
		sharedGNMIRuntimeStream,
	) error{
		"until sync": receiveSharedGNMIProbeUntilSync,
		"once":       receiveSharedGNMIProbeOnce,
	} {
		t.Run(name, func(t *testing.T) {
			probeCtx, cancel := context.WithCancel(t.Context())
			defer cancel()
			stream := &singleUpdateGNMIClientStream{ctx: probeCtx, response: response(codes.InvalidArgument)}
			err := receive(stream, nil, nil, sharedGNMIRuntimeStream{})
			require.Error(t, err)
			var probeUnsupported *sharedGNMIUnsupportedError
			require.ErrorAs(t, err, &probeUnsupported)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.NotContains(t, err.Error(), "device-controlled")
			assert.NotContains(t, err.Error(), "secret")
		})
	}
}

func TestSharedGNMIRuntimeCacheLimitStopsOnlyAffectedProfileWithoutReconnect(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		paths := runtimeTestSubscribedPaths(request)
		now := time.Now()
		if runtimeTestContains(paths, "interfaces/interface/state/value") {
			updates := []*gnmipb.Update{}
			for i := 1; i <= 2; i++ {
				updates = append(updates, &gnmipb.Update{
					Path: runtimeTestProtoPath(t, fmt.Sprintf("interfaces/interface[name=Ethernet%d]/state/value", i)),
					Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: int64(i)}},
				})
			}
			if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
				Timestamp: now.UnixNano(), Prefix: &gnmipb.Path{Origin: runtimeTestOrigin}, Update: updates,
			}}}); err != nil {
				return err
			}
			<-stream.Context().Done()
			return stream.Context().Err()
		}
		for i := range 2 {
			if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
				Timestamp: now.Add(time.Duration(i) * time.Second).UnixNano(), Prefix: &gnmipb.Path{Origin: runtimeTestOrigin},
				Update: []*gnmipb.Update{{Path: runtimeTestProtoPath(t, "health/value"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: int64(i + 1)}}}},
			}}}); err != nil {
				return err
			}
		}
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}}); err != nil {
			return err
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}
	endpoint, listener := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	limitedMapping := runtimeTestMapping("interfaces/interface/state/value", "runtime.cache.limited")
	limitedMapping.PathKeys = map[string]string{"interface.name": "network.interface.name"}
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeStream, limitedMapping)
	target.MaxStreams = 2
	target.CustomSubscriptions = append(target.CustomSubscriptions, GNMICustomSubscriptionConfig{
		Name: "runtime-healthy", Origin: runtimeTestOrigin, Mode: gnmiModeStream, SampleInterval: time.Second,
		Mappings: []GNMIMetricMappingConfig{runtimeTestMapping("health/value", "runtime.cache.healthy")},
	})
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })
	settings := receivertest.NewNopSettings(componentmetadata.Type)
	settings.MeterProvider = provider
	sink := &consumertest.MetricsSink{}
	config := createDefaultConfig().(*Config)
	config.GNMI = GNMIConfig{MaxDatapointsPerChunk: 10, MaxCachedSeries: 1, Targets: []GNMITargetConfig{target}}
	created, err := newSharedGNMIReceiver(settings, config, sink)
	require.NoError(t, err)
	receiver := created.(*sharedGNMIReceiver)
	require.NoError(t, receiver.Start(t.Context(), componenttest.NewNopHost()))

	require.Eventually(t, func() bool {
		return receiver.targets[0].profileStopped("runtime-custom") && runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.cache.healthy") == 2
	}, 5*time.Second, 20*time.Millisecond)
	assert.False(t, receiver.targets[0].profileStopped("runtime-healthy"))
	assert.Zero(t, runtimeTestMetricPointCountAll(sink.AllMetrics(), "runtime.cache.limited"))
	assert.Equal(t, int64(1), listener.accepts.Load())
	assert.Equal(t, int64(1), runtimeTestTelemetryIntGauge(t, reader, "otelcol_ciscoosreceiver_gnmi_profile_degraded"))
	assert.Never(t, func() bool { return listener.accepts.Load() > 1 }, 300*time.Millisecond, 20*time.Millisecond)

	shutdownCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, receiver.Shutdown(shutdownCtx))
}

func TestSharedGNMINXReconnectRequiresFreshSensorIdentity(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	firstTimestamp := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	secondValueSent := make(chan struct{})
	releaseFreshIdentity := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseFreshIdentity) }) })

	notification := func(timestamp time.Time, description string, includeIdentity bool, value float64) *gnmipb.SubscribeResponse {
		base := "sys/intf/phys-[Ethernet1/1]/phys/fcotdd/lane-0-sensor-27"
		path := func(leaf string) *gnmipb.Path {
			return &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: base}, {Name: leaf}}}
		}
		updates := make([]*gnmipb.Update, 0, 3)
		if includeIdentity {
			updates = append(updates,
				&gnmipb.Update{Path: path("description"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: description}}},
				&gnmipb.Update{Path: path("unit"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "dB"}}},
			)
		}
		updates = append(updates, &gnmipb.Update{Path: path("value"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_DoubleVal{DoubleVal: value}}})
		return &gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
			Timestamp: timestamp.UnixNano(), Prefix: &gnmipb.Path{Origin: builtinGNMIOriginDME}, Update: updates,
		}}}
	}

	var session atomic.Int64
	fake := &runtimeTestGNMIServer{}
	fake.capabilities = func(context.Context) (*gnmipb.CapabilityResponse, error) {
		return &gnmipb.CapabilityResponse{
			SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON},
			SupportedModels: []*gnmipb.ModelData{
				{Name: "openconfig-platform"},
				{Name: builtinGNMIOriginDME},
			},
		}, nil
	}
	fake.get = func(context.Context, *gnmipb.GetRequest) (*gnmipb.GetResponse, error) {
		return runtimeTestNXIdentityResponse("N9K-C93180YC-FX3", "10.6(1)"), nil
	}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		switch session.Add(1) {
		case 1:
			if err := stream.Send(notification(firstTimestamp, "TDECQ", true, 1)); err != nil {
				return err
			}
			return status.Error(codes.Unavailable, "force reconnect")
		case 2:
			if err := stream.Send(notification(firstTimestamp.Add(time.Second), "", false, 2)); err != nil {
				return err
			}
			close(secondValueSent)
			<-releaseFreshIdentity
			if err := stream.Send(notification(firstTimestamp.Add(2*time.Second), "ESNR", true, 3)); err != nil {
				return err
			}
			return status.Error(codes.Unavailable, "end second session")
		default:
			return status.Error(codes.Unavailable, "unexpected session")
		}
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))

	enabled := true
	profiles := runtimeTestDisabledProfiles()
	profiles.Optics.Enabled = &enabled
	targetConfig := GNMITargetConfig{
		Name: "nx-reconnect", Endpoint: endpoint, Product: gnmiProductNexus9000, SoftwareVersion: "10.6(1)", MaxStreams: 1,
		Credentials: GNMICredentialsConfig{
			Mode: gnmiCredentialUsernamePassword, Username: runtimeTestUsername, Password: configopaque.String(runtimeTestPassword),
		},
		TLS:      GNMITLSConfig{CAFile: material.caFile, MinVersion: "1.2", ServerNameOverride: runtimeTestServerName},
		Profiles: profiles,
	}
	config := createDefaultConfig().(*Config)
	config.GNMI = GNMIConfig{MaxDatapointsPerChunk: 10, MaxCachedSeries: 100, Targets: []GNMITargetConfig{targetConfig}}
	sink := &consumertest.MetricsSink{}
	created, err := newSharedGNMIReceiver(receivertest.NewNopSettings(componentmetadata.Type), config, sink)
	require.NoError(t, err)
	receiver := created.(*sharedGNMIReceiver)
	receiver.host = componenttest.NewNopHost()
	require.Len(t, receiver.targets, 1)
	target := receiver.targets[0]
	cachedMetricCount := func(name string) int {
		count := 0
		for _, point := range target.cache.Snapshot() {
			if point.Metric.Name == name {
				count++
			}
		}
		return count
	}

	firstCtx, firstCancel := context.WithTimeout(t.Context(), 3*time.Second)
	_, _, firstErr := receiver.serveTarget(firstCtx, target)
	firstCancel()
	require.Error(t, firstErr)
	assert.Equal(t, 1, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.optics.tdecq"))
	target.nxMu.Lock()
	assert.Empty(t, target.nxSensors, "session exit must release auxiliary sensor identity")
	target.nxMu.Unlock()
	target.nxBudget.mu.Lock()
	assert.Equal(t, 3, target.nxBudget.used,
		"session exit releases NX identity but preserves the cached optic's source, count, and attributes")
	assert.Positive(t, target.nxBudget.usedBytes)
	target.nxBudget.mu.Unlock()
	assert.Equal(t, 1, cachedMetricCount("cisco.optics.tdecq"), "session cleanup must preserve mapped cache state")

	type targetResult struct{ err error }
	secondResult := make(chan targetResult, 1)
	secondCtx, secondCancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer secondCancel()
	go func() {
		_, _, serveErr := receiver.serveTarget(secondCtx, target)
		secondResult <- targetResult{err: serveErr}
	}()

	select {
	case <-secondValueSent:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for value-only reconnect update")
	}
	assert.Never(t, func() bool {
		return runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.optics.tdecq") > 1
	}, 250*time.Millisecond, 10*time.Millisecond, "value-only reconnect update reused stale TDECQ identity")
	assert.Equal(t, 1, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.optics.tdecq"),
		"mapped cache survives the auxiliary reset without being re-emitted")
	assert.Equal(t, 1, cachedMetricCount("cisco.optics.tdecq"))

	releaseOnce.Do(func() { close(releaseFreshIdentity) })
	select {
	case result := <-secondResult:
		require.Error(t, result.err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for refreshed sensor identity")
	}
	assert.Equal(t, 1, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.optics.tdecq"))
	assert.Equal(t, 1, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.optics.esnr"))
	target.nxMu.Lock()
	assert.Empty(t, target.nxSensors)
	target.nxMu.Unlock()
	target.nxBudget.mu.Lock()
	assert.Equal(t, 4, target.nxBudget.used,
		"both cached optical series retain sources while sharing one presence count and attribute entry")
	assert.Positive(t, target.nxBudget.usedBytes)
	target.nxBudget.mu.Unlock()
}

func TestNormalizeNXNotificationBoundsAndInvalidatesSensorState(t *testing.T) {
	cache, err := internalgnmi.NewCache(1)
	require.NoError(t, err)
	target, err := newSharedGNMITargetRuntime(GNMITargetConfig{
		Name: "nx-state", Product: gnmiProductNexus9000, SoftwareVersion: "10.6(1)", MaxStreams: 1,
		Profiles: subscriptionProfilesOnly(builtinGNMIProfileOptics),
	}, cache)
	require.NoError(t, err)
	baseTime := time.Date(2026, time.July, 2, 12, 0, 0, 0, time.UTC)
	sensorPath := func(id string) internalgnmi.Path {
		return internalgnmi.Path{Target: "nx-state", Origin: builtinGNMIOriginDME, Elements: []internalgnmi.PathElem{
			{Name: "sys"},
			{Name: "intf"},
			{Name: "phys", Keys: map[string]string{"id": "Ethernet1/1"}},
			{Name: "phys"},
			{Name: "fcotdd"},
			{Name: "lane", Keys: map[string]string{"id": "0"}},
			{Name: "sensor", Keys: map[string]string{"id": id}},
		}}
	}
	sensorNotification := func(id, description string, timestamp time.Time) internalgnmi.DecodedNotification {
		path := sensorPath(id)
		return internalgnmi.DecodedNotification{Prefix: path.Clone(), Timestamp: timestamp, Updates: []internalgnmi.Point{
			{Series: internalgnmi.Series{Target: path.Target, Origin: path.Origin, Elements: path.Elements, Leaf: "description"}, Value: internalgnmi.StringValue(description), Timestamp: timestamp},
			{Series: internalgnmi.Series{Target: path.Target, Origin: path.Origin, Elements: path.Elements, Leaf: "unit"}, Value: internalgnmi.StringValue("dB"), Timestamp: timestamp},
		}}
	}

	_, err = target.normalizeNXNotification(sensorNotification("1", "TDECQ", baseTime))
	require.NoError(t, err)
	require.Len(t, target.nxSensors, 1)
	_, err = target.normalizeNXNotification(sensorNotification("2", "ESNR", baseTime.Add(time.Second)))
	var capacity *internalgnmi.CapacityError
	require.ErrorAs(t, err, &capacity)
	assert.Len(t, target.nxSensors, 1, "auxiliary DME state must be bounded by the mapped-series cap")
	assert.Equal(t, 1, target.nxBudget.used, "a failed reservation must not strand auxiliary capacity")

	_, err = target.normalizeNXNotification(internalgnmi.DecodedNotification{
		Prefix: sensorPath("1"), Timestamp: baseTime.Add(2 * time.Second), Deletes: []internalgnmi.Path{sensorPath("1")},
	})
	require.NoError(t, err)
	assert.Empty(t, target.nxSensors)
	_, err = target.normalizeNXNotification(sensorNotification("2", "ESNR", baseTime.Add(3*time.Second)))
	require.NoError(t, err)
	require.Len(t, target.nxSensors, 1)
	state := target.nxSensors[sharedGNMIPathFromCanonical(sensorPath("2"))]
	assert.Equal(t, "ESNR", state.description)

	_, err = target.normalizeNXNotification(sensorNotification("2", "TDECQ", baseTime.Add(time.Second)))
	require.NoError(t, err)
	state = target.nxSensors[sharedGNMIPathFromCanonical(sensorPath("2"))]
	assert.Equal(t, "ESNR", state.description, "older metadata must not roll sensor identity back")

	descriptionDelete := sensorPath("2")
	descriptionDelete.Elements = append(descriptionDelete.Elements, internalgnmi.PathElem{Name: "description"})
	_, err = target.normalizeNXNotification(internalgnmi.DecodedNotification{
		Prefix: sensorPath("2"), Timestamp: baseTime.Add(4 * time.Second), Deletes: []internalgnmi.Path{descriptionDelete},
	})
	require.NoError(t, err)
	state = target.nxSensors[sharedGNMIPathFromCanonical(sensorPath("2"))]
	assert.Empty(t, state.description, "a leaf delete must invalidate allowlist metadata")
	assert.Equal(t, "dB", state.unit)

	// A replacement at the hard limit can stage one removal and one addition.
	replacementPrefix := sensorPath("2")
	replacementPrefix.Elements = replacementPrefix.Elements[:len(replacementPrefix.Elements)-1]
	replacement := sensorNotification("3", "TDECQ", baseTime.Add(5*time.Second))
	replacement.Prefix = replacementPrefix
	replacement.Atomic = true
	_, err = target.normalizeNXNotification(replacement)
	require.NoError(t, err)
	require.Len(t, target.nxSensors, 1)
	_, oldExists := target.nxSensors[sharedGNMIPathFromCanonical(sensorPath("2"))]
	assert.False(t, oldExists)
	state = target.nxSensors[sharedGNMIPathFromCanonical(sensorPath("3"))]
	assert.Equal(t, "TDECQ", state.description)
	assert.Equal(t, 1, target.nxBudget.used)

	// Description and unit clocks are independent. A description newer than
	// the prior description is accepted even when the unit arrived later, but
	// a reading cannot use metadata from its future.
	unitOnly := sensorPath("3")
	unitOnlyTimestamp := baseTime.Add(7 * time.Second)
	_, err = target.normalizeNXNotification(internalgnmi.DecodedNotification{
		Prefix: unitOnly, Timestamp: unitOnlyTimestamp, Updates: []internalgnmi.Point{{
			Series: internalgnmi.Series{Target: unitOnly.Target, Origin: unitOnly.Origin, Elements: unitOnly.Elements, Leaf: "unit"},
			Value:  internalgnmi.StringValue("dB"), Timestamp: unitOnlyTimestamp,
		}},
	})
	require.NoError(t, err)
	descriptionTimestamp := baseTime.Add(6 * time.Second)
	_, err = target.normalizeNXNotification(internalgnmi.DecodedNotification{
		Prefix: unitOnly, Timestamp: descriptionTimestamp, Updates: []internalgnmi.Point{{
			Series: internalgnmi.Series{Target: unitOnly.Target, Origin: unitOnly.Origin, Elements: unitOnly.Elements, Leaf: "description"},
			Value:  internalgnmi.StringValue("ESNR"), Timestamp: descriptionTimestamp,
		}},
	})
	require.NoError(t, err)
	state = target.nxSensors[sharedGNMIPathFromCanonical(sensorPath("3"))]
	assert.Equal(t, "ESNR", state.description)
	assert.Equal(t, unitOnlyTimestamp, state.unitTimestamp)

	reading := func(timestamp time.Time) internalgnmi.DecodedNotification {
		return internalgnmi.DecodedNotification{
			Prefix: unitOnly, Timestamp: timestamp, Updates: []internalgnmi.Point{{
				Series: internalgnmi.Series{Target: unitOnly.Target, Origin: unitOnly.Origin, Elements: unitOnly.Elements, Leaf: "value"},
				Value:  internalgnmi.DoubleValue(20), Timestamp: timestamp,
			}},
		}
	}
	beforeUnit, err := target.normalizeNXNotification(reading(baseTime.Add(6500 * time.Millisecond)))
	require.NoError(t, err)
	assert.Equal(t, "value", beforeUnit.Updates[0].Series.Leaf, "a reading must not consume metadata newer than itself")
	afterUnit, err := target.normalizeNXNotification(reading(baseTime.Add(8 * time.Second)))
	require.NoError(t, err)
	assert.Equal(t, "esnr", afterUnit.Updates[0].Series.Leaf)

	target.clearNXSensorState()
	assert.Empty(t, target.nxSensors)
	assert.Zero(t, target.nxBudget.used, "profile cleanup must release the global auxiliary-state budget")
}

func TestNormalizeNXNotificationAuxiliaryBudgetsAreIsolatedByTarget(t *testing.T) {
	newTarget := func(name string) *sharedGNMITargetRuntime {
		cache, err := internalgnmi.NewCache(10)
		require.NoError(t, err)
		target, buildErr := newSharedGNMITargetRuntimeWithBudget(GNMITargetConfig{
			Name: name, Product: gnmiProductNexus9000, SoftwareVersion: "10.6(1)", MaxStreams: 1,
			Profiles: subscriptionProfilesOnly(builtinGNMIProfileOptics),
		}, cache, newSharedGNMIAuxiliaryBudget(1))
		require.NoError(t, buildErr)
		return target
	}
	notification := func(name, sensorID string) internalgnmi.DecodedNotification {
		elements := []internalgnmi.PathElem{
			{Name: "sys"},
			{Name: "intf"},
			{Name: "phys", Keys: map[string]string{"id": "Ethernet1/1"}},
			{Name: "phys"},
			{Name: "fcotdd"},
			{Name: "lane", Keys: map[string]string{"id": "0"}},
			{Name: "sensor", Keys: map[string]string{"id": sensorID}},
		}
		timestamp := time.Date(2026, time.July, 2, 12, 0, 0, 0, time.UTC)
		return internalgnmi.DecodedNotification{
			Prefix: internalgnmi.Path{Target: name, Origin: builtinGNMIOriginDME, Elements: elements}, Timestamp: timestamp,
			Updates: []internalgnmi.Point{{
				Series: internalgnmi.Series{Target: name, Origin: builtinGNMIOriginDME, Elements: elements, Leaf: "description"},
				Value:  internalgnmi.StringValue("TDECQ"), Timestamp: timestamp,
			}},
		}
	}
	first := newTarget("nx-one")
	second := newTarget("nx-two")
	_, err := first.normalizeNXNotification(notification("nx-one", "1"))
	require.NoError(t, err)
	_, err = first.normalizeNXNotification(notification("nx-one", "2"))
	var capacity *internalgnmi.CapacityError
	require.ErrorAs(t, err, &capacity)
	_, err = second.normalizeNXNotification(notification("nx-two", "1"))
	require.NoError(t, err)
	assert.Len(t, first.nxSensors, 1)
	assert.Len(t, second.nxSensors, 1, "one target exhausting its partition must not affect another target")
	assert.NotSame(t, first.nxBudget, second.nxBudget)
	assert.Equal(t, 1, first.nxBudget.used)
	assert.Equal(t, 1, second.nxBudget.used)
}

func TestNXSensorTransactionRollsBackAfterMappedCacheCapacityFailure(t *testing.T) {
	cache, err := internalgnmi.NewCache(1)
	require.NoError(t, err)
	timestamp := time.Date(2026, time.July, 2, 12, 0, 0, 0, time.UTC)
	existing := internalgnmi.MappedPoint{
		Source:    internalgnmi.Series{Target: "existing", Origin: "openconfig", Elements: []internalgnmi.PathElem{{Name: "system"}}, Leaf: "up"},
		Metric:    internalgnmi.MetricMetadata{Name: "existing.metric", Description: "Existing metric", Unit: "1"},
		GaugeType: internalgnmi.GaugeInt, MetricType: internalgnmi.MetricGauge, IntValue: 1, Timestamp: timestamp,
	}
	_, err = cache.Apply(internalgnmi.CacheNotification{Prefix: existing.Source.Path(), Timestamp: timestamp, Updates: []internalgnmi.MappedPoint{existing}})
	require.NoError(t, err)

	budget := newSharedGNMIAuxiliaryBudget(1)
	target, err := newSharedGNMITargetRuntimeWithBudget(GNMITargetConfig{
		Name: "nx-rollback", Product: gnmiProductNexus9000, SoftwareVersion: "10.6(1)", MaxStreams: 1,
		Profiles: subscriptionProfilesOnly(builtinGNMIProfileOptics),
	}, cache, budget)
	require.NoError(t, err)
	elements := []internalgnmi.PathElem{
		{Name: "sys"},
		{Name: "intf"},
		{Name: "phys", Keys: map[string]string{"id": "Ethernet1/1"}},
		{Name: "phys"},
		{Name: "fcotdd"},
		{Name: "lane", Keys: map[string]string{"id": "0"}},
		{Name: "sensor", Keys: map[string]string{"id": "1"}},
	}
	decoded, transaction, err := target.prepareNXNotification(internalgnmi.DecodedNotification{
		Prefix: internalgnmi.Path{Target: "nx-rollback", Origin: builtinGNMIOriginDME, Elements: elements}, Timestamp: timestamp.Add(time.Second),
		Updates: []internalgnmi.Point{
			{Series: internalgnmi.Series{Target: "nx-rollback", Origin: builtinGNMIOriginDME, Elements: elements, Leaf: "description"}, Value: internalgnmi.StringValue("TDECQ"), Timestamp: timestamp.Add(time.Second)},
			{Series: internalgnmi.Series{Target: "nx-rollback", Origin: builtinGNMIOriginDME, Elements: elements, Leaf: "unit"}, Value: internalgnmi.StringValue("dB"), Timestamp: timestamp.Add(time.Second)},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, transaction)
	assert.Empty(t, target.nxSensors, "preparation must not publish auxiliary state")
	reservation, err := prepareSharedGNMIAuxiliaryReservation(target.nxBudget, transaction.budgetDelta)
	require.NoError(t, err)
	assert.Equal(t, 1, budget.used, "the pending transaction reserves capacity")

	rejected := existing
	rejected.Source.Target = "nx-rollback"
	rejected.Source.Elements = decoded.Prefix.Elements
	rejected.Source.Leaf = "tdecq"
	rejected.Metric.Name = "cisco.optics.tdecq"
	rejected.Timestamp = timestamp.Add(time.Second)
	_, err = cache.Apply(internalgnmi.CacheNotification{Prefix: decoded.Prefix, Timestamp: rejected.Timestamp, Updates: []internalgnmi.MappedPoint{rejected}})
	var capacity *internalgnmi.CapacityError
	require.ErrorAs(t, err, &capacity)
	transaction.rollback()
	reservation.rollback()
	assert.Empty(t, target.nxSensors)
	assert.Zero(t, budget.used, "rollback must return the shared auxiliary reservation")
}

func TestProcessNXNotificationAtomicallyReplacesCacheAndAuxiliaryStateAtCapacity(t *testing.T) {
	settings := receivertest.NewNopSettings(componentmetadata.Type)
	config := createDefaultConfig().(*Config)
	config.GNMI = GNMIConfig{
		MaxDatapointsPerChunk: 10,
		MaxCachedSeries:       3,
		Targets: []GNMITargetConfig{{
			Name: "nx-integrated", Product: gnmiProductNexus9000, SoftwareVersion: "10.6(1)", MaxStreams: 1,
			Profiles: subscriptionProfilesOnly(builtinGNMIProfileOptics),
		}},
	}
	created, err := newSharedGNMIReceiver(settings, config, &consumertest.MetricsSink{})
	require.NoError(t, err)
	receiver := created.(*sharedGNMIReceiver)
	t.Cleanup(func() { require.NoError(t, receiver.Shutdown(context.WithoutCancel(t.Context()))) })
	require.Len(t, receiver.targets, 1)
	target := receiver.targets[0]
	// Exercise a one-sensor auxiliary budget independently from the combined
	// cache budget, which needs three slots for one atomic mapped point.
	target.nxBudget = newSharedGNMIAuxiliaryBudget(4)
	require.Len(t, target.streams, 1)
	stream := target.streams[0]
	require.Equal(t, builtinGNMIProfileOptics, stream.Profile)

	notification := func(timestamp time.Time, atomicNotification bool, sensorIDs ...string) *gnmipb.Notification {
		updates := make([]*gnmipb.Update, 0, len(sensorIDs)*3)
		for index, sensorID := range sensorIDs {
			base := fmt.Sprintf("sys/intf/phys-[Ethernet1/1]/phys/fcotdd/lane-0-sensor-%s", sensorID)
			path := func(leaf string) *gnmipb.Path {
				return &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: base}, {Name: leaf}}}
			}
			updates = append(updates,
				&gnmipb.Update{Path: path("description"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "TDECQ"}}},
				&gnmipb.Update{Path: path("unit"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "dB"}}},
				&gnmipb.Update{Path: path("value"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_DoubleVal{DoubleVal: float64(index + 1)}}},
			)
		}
		return &gnmipb.Notification{
			Timestamp: timestamp.UnixNano(), Atomic: atomicNotification,
			Prefix: &gnmipb.Path{Origin: builtinGNMIOriginDME}, Update: updates,
		}
	}
	sensorID := func(elements []internalgnmi.PathElem) string {
		for _, element := range elements {
			if element.Name == "sensor" {
				return element.Keys["id"]
			}
		}
		return ""
	}
	assertState := func(wantSensor string) {
		t.Helper()
		require.Len(t, target.nxSensors, 1)
		for _, state := range target.nxSensors {
			assert.Equal(t, wantSensor, sensorID(state.path.Elements))
		}
		assert.Equal(t, 4, target.nxBudget.used, "one NX sensor and three optical map entries are retained")
		snapshot := target.cache.Snapshot()
		require.Len(t, snapshot, 1)
		assert.Equal(t, wantSensor, sensorID(snapshot[0].Source.Elements))
	}

	baseTime := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	require.NoError(t, receiver.processNotification(t.Context(), target, stream, notification(baseTime, false, "1")))
	assertState("1")

	// One mapped point plus its atomic baseline and prefix tombstone consume the
	// three retained-state slots, while the auxiliary sensor map stays bounded.
	require.NoError(t, receiver.processNotification(t.Context(), target, stream, notification(baseTime.Add(time.Second), true, "2")))
	assertState("2")

	// A notification which exceeds a retained-state limit must not partially
	// replace the already committed cache or auxiliary state.
	err = receiver.processNotification(t.Context(), target, stream, notification(baseTime.Add(2*time.Second), true, "3", "4"))
	var stopped *sharedGNMIProfileStopError
	require.ErrorAs(t, err, &stopped)
	var capacity *internalgnmi.CapacityError
	require.ErrorAs(t, err, &capacity)
	assert.Greater(t, capacity.Requested, capacity.Limit)
	assertState("2")
}

func TestNormalizeNXDMEElementsAcceptsWholeDistinguishedNameElement(t *testing.T) {
	got := normalizeNXDMEElements([]internalgnmi.PathElem{{
		Name: "sys/intf/phys-[Ethernet1/49]/phys/fcotdd/lane-0-sensor-27/value",
	}})
	require.Len(t, got, 8)
	assert.Equal(t, []string{"sys", "intf", "phys", "phys", "fcotdd", "lane", "sensor", "value"}, func() []string {
		names := make([]string, len(got))
		for i := range got {
			names[i] = got[i].Name
		}
		return names
	}())
	assert.Equal(t, "Ethernet1/49", got[2].Keys["id"])
	assert.Equal(t, "0", got[5].Keys["id"])
	assert.Equal(t, "27", got[6].Keys["id"])
}

func TestOpticalPresenceTracksDeletesExplicitAbsenceAndSourceReplacement(t *testing.T) {
	target := &sharedGNMITargetRuntime{
		config: GNMITargetConfig{Name: "optics-target"}, opticalSources: map[string]string{},
		presenceCounts: map[string]int{}, presenceAttrs: map[string]map[string]string{},
		nxBudget: newSharedGNMIAuxiliaryBudget(100),
	}
	timestamp := time.Date(2026, time.July, 2, 12, 0, 0, 0, time.UTC)
	attributes := map[string]string{
		"network.interface.name":    "Ethernet1/1",
		"cisco.optics.lane":         "0",
		"cisco.optics.profile":      "dom",
		"cisco.optics.experimental": "false",
	}
	point := func(origin, leaf, metric string, value int64) internalgnmi.MappedPoint {
		return internalgnmi.MappedPoint{
			Source: internalgnmi.Series{Target: "optics-target", Origin: origin, Elements: []internalgnmi.PathElem{{Name: "optic"}}, Leaf: leaf},
			Metric: builtinGNMIMetricMetadata[metric], GaugeType: internalgnmi.GaugeInt,
			MetricType: internalgnmi.MetricGauge, IntValue: value, Attributes: cloneGNMIAttributes(attributes), Timestamp: timestamp,
		}
	}
	temperature := point("device", "temperature", "cisco.optics.temperature", 40)
	presence, err := target.updateOpticalPresence(internalgnmi.CacheResult{Applied: []internalgnmi.MappedPoint{temperature}}, timestamp)
	require.NoError(t, err)
	require.Len(t, presence, 1)
	assert.Equal(t, int64(1), presence[0].IntValue)

	replacement := point("DME", "temperature", "cisco.optics.temperature", 41)
	presence, err = target.updateOpticalPresence(internalgnmi.CacheResult{
		Applied: []internalgnmi.MappedPoint{replacement}, Replaced: []internalgnmi.MappedPoint{temperature},
	}, timestamp.Add(time.Second))
	require.NoError(t, err)
	require.Len(t, presence, 1)
	assert.Equal(t, int64(1), presence[0].IntValue)
	assert.NotContains(t, target.opticalSources, temperature.Source.Key())
	assert.Contains(t, target.opticalSources, replacement.Source.Key())

	presence, err = target.updateOpticalPresence(internalgnmi.CacheResult{Removed: []internalgnmi.MappedPoint{replacement}}, timestamp.Add(2*time.Second))
	require.NoError(t, err)
	require.Len(t, presence, 1)
	assert.Equal(t, int64(0), presence[0].IntValue)

	explicitPresent := point("device", "present", "cisco.optics.present", 1)
	presence, err = target.updateOpticalPresence(internalgnmi.CacheResult{Applied: []internalgnmi.MappedPoint{explicitPresent}}, timestamp.Add(3*time.Second))
	require.NoError(t, err)
	assert.Empty(t, presence, "the explicitly mapped present=1 datapoint is already in the output batch")
	presence, err = target.updateOpticalPresence(internalgnmi.CacheResult{Removed: []internalgnmi.MappedPoint{explicitPresent}}, timestamp.Add(4*time.Second))
	require.NoError(t, err)
	require.Len(t, presence, 1)
	assert.Equal(t, int64(0), presence[0].IntValue, "deleting an explicit presence leaf must signal absence")

	_, err = target.updateOpticalPresence(internalgnmi.CacheResult{Applied: []internalgnmi.MappedPoint{temperature}}, timestamp.Add(5*time.Second))
	require.NoError(t, err)
	explicitAbsent := point("device", "present", "cisco.optics.present", 0)
	presence, err = target.updateOpticalPresence(internalgnmi.CacheResult{Applied: []internalgnmi.MappedPoint{explicitAbsent}}, timestamp.Add(6*time.Second))
	require.NoError(t, err)
	assert.Empty(t, presence, "the explicitly mapped present=0 datapoint is already in the output batch")
	assert.Empty(t, target.opticalSources)
	assert.Empty(t, target.presenceCounts)
	assert.Empty(t, target.presenceAttrs)
}

func sharedGNMIPathFromCanonical(path internalgnmi.Path) string {
	return path.Key()
}

type runtimeTestGNMIServer struct {
	gnmipb.UnimplementedGNMIServer

	mu                        sync.Mutex
	capabilitiesCalls         int
	subscribeCalls            int
	identitySubscribeCalls    int
	getCalls                  int
	setCalls                  int
	capabilitiesMetadata      grpcmetadata.MD
	getMetadata               []grpcmetadata.MD
	subscribeMetadata         []grpcmetadata.MD
	identitySubscribeMetadata []grpcmetadata.MD
	getRequests               []*gnmipb.GetRequest
	requests                  []*gnmipb.SubscribeRequest
	rpcOrder                  []string
	capabilities              func(context.Context) (*gnmipb.CapabilityResponse, error)
	get                       func(context.Context, *gnmipb.GetRequest) (*gnmipb.GetResponse, error)
	subscribe                 func(grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error
}

type runtimeTestGNMISnapshot struct {
	capabilitiesCalls         int
	subscribeCalls            int
	identitySubscribeCalls    int
	getCalls                  int
	setCalls                  int
	capabilitiesMetadata      grpcmetadata.MD
	getMetadata               []grpcmetadata.MD
	subscribeMetadata         []grpcmetadata.MD
	identitySubscribeMetadata []grpcmetadata.MD
	getRequests               []*gnmipb.GetRequest
	requests                  []*gnmipb.SubscribeRequest
	rpcOrder                  []string
}

type runtimeTestPrefetchedSubscribeStream struct {
	grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]
	first     *gnmipb.SubscribeRequest
	delivered bool
}

func (s *runtimeTestPrefetchedSubscribeStream) Recv() (*gnmipb.SubscribeRequest, error) {
	if !s.delivered {
		s.delivered = true
		return s.first, nil
	}
	return s.BidiStreamingServer.Recv()
}

func runtimeTestIsIdentitySubscribeRequest(request *gnmipb.SubscribeRequest) bool {
	for _, path := range runtimeTestSubscribedPaths(request) {
		switch {
		case strings.Contains(path, "device-hardware-data/device-hardware/device-inventory"),
			strings.Contains(path, "install-oper-data/install-location-information/install-version-info"),
			path == "install/version",
			path == "components/component/state":
			return true
		}
	}
	return false
}

func (s *runtimeTestGNMIServer) Capabilities(ctx context.Context, _ *gnmipb.CapabilityRequest) (*gnmipb.CapabilityResponse, error) {
	metadata, _ := grpcmetadata.FromIncomingContext(ctx)
	s.mu.Lock()
	s.capabilitiesCalls++
	s.rpcOrder = append(s.rpcOrder, "Capabilities")
	s.capabilitiesMetadata = metadata.Copy()
	fn := s.capabilities
	s.mu.Unlock()
	if fn != nil {
		return fn(ctx)
	}
	return &gnmipb.CapabilityResponse{
		SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON_IETF},
		SupportedModels: []*gnmipb.ModelData{
			{Name: "Cisco-IOS-XR-install-oper"},
			{Name: runtimeTestOrigin},
		},
	}, nil
}

func (s *runtimeTestGNMIServer) Subscribe(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
	metadata, _ := grpcmetadata.FromIncomingContext(stream.Context())
	request, err := stream.Recv()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.rpcOrder = append(s.rpcOrder, "Subscribe")
	s.mu.Unlock()
	if runtimeTestIsIdentitySubscribeRequest(request) {
		s.mu.Lock()
		s.identitySubscribeCalls++
		s.identitySubscribeMetadata = append(s.identitySubscribeMetadata, metadata.Copy())
		s.mu.Unlock()
		return status.Error(codes.InvalidArgument, "identity preflight must use a bounded STATE Get RPC")
	}
	s.mu.Lock()
	s.subscribeCalls++
	s.subscribeMetadata = append(s.subscribeMetadata, metadata.Copy())
	fn := s.subscribe
	s.mu.Unlock()
	if fn == nil {
		return status.Error(codes.Unimplemented, "test Subscribe behavior not configured")
	}
	return fn(&runtimeTestPrefetchedSubscribeStream{BidiStreamingServer: stream, first: request})
}

func (s *runtimeTestGNMIServer) Get(ctx context.Context, request *gnmipb.GetRequest) (*gnmipb.GetResponse, error) {
	metadata, _ := grpcmetadata.FromIncomingContext(ctx)
	s.mu.Lock()
	s.getCalls++
	s.rpcOrder = append(s.rpcOrder, "Get")
	s.getMetadata = append(s.getMetadata, metadata.Copy())
	s.getRequests = append(s.getRequests, request)
	fn := s.get
	s.mu.Unlock()
	if fn != nil {
		return fn(ctx, request)
	}
	return runtimeTestXRIdentityResponse("ASR-9904", "24.4.1"), nil
}

func (s *runtimeTestGNMIServer) Set(context.Context, *gnmipb.SetRequest) (*gnmipb.SetResponse, error) {
	s.mu.Lock()
	s.setCalls++
	s.mu.Unlock()
	return nil, status.Error(codes.PermissionDenied, "Set forbidden in runtime test")
}

func (s *runtimeTestGNMIServer) recordRequest(request *gnmipb.SubscribeRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, request)
}

func (s *runtimeTestGNMIServer) snapshot() runtimeTestGNMISnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return runtimeTestGNMISnapshot{
		capabilitiesCalls:         s.capabilitiesCalls,
		subscribeCalls:            s.subscribeCalls,
		identitySubscribeCalls:    s.identitySubscribeCalls,
		getCalls:                  s.getCalls,
		setCalls:                  s.setCalls,
		capabilitiesMetadata:      s.capabilitiesMetadata.Copy(),
		getMetadata:               append([]grpcmetadata.MD(nil), s.getMetadata...),
		subscribeMetadata:         append([]grpcmetadata.MD(nil), s.subscribeMetadata...),
		identitySubscribeMetadata: append([]grpcmetadata.MD(nil), s.identitySubscribeMetadata...),
		getRequests:               append([]*gnmipb.GetRequest(nil), s.getRequests...),
		requests:                  append([]*gnmipb.SubscribeRequest(nil), s.requests...),
		rpcOrder:                  append([]string(nil), s.rpcOrder...),
	}
}

type runtimeTestCountingListener struct {
	net.Listener
	accepts atomic.Int64
}

func (l *runtimeTestCountingListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err == nil {
		l.accepts.Add(1)
	}
	return connection, err
}

type runtimeTestTLSFiles struct {
	caFile         string
	serverCert     tls.Certificate
	clientCertFile string
	clientKeyFile  string
	caPool         *x509.CertPool
}

func (m runtimeTestTLSFiles) serverTLS(requireClientCertificate bool) *tls.Config {
	config := &tls.Config{Certificates: []tls.Certificate{m.serverCert}, MinVersion: tls.VersionTLS12}
	if requireClientCertificate {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = m.caPool
	}
	return config
}

func runtimeTestTLSMaterial(t *testing.T) runtimeTestTLSFiles {
	t.Helper()
	directory := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          runtimeTestSerial(t),
		Subject:               pkix.Name{CommonName: "runtime test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(cryptorand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCertificate, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caFile := filepath.Join(directory, "ca.pem")
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o600))
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caPEM))

	serverCertificate, _, _ := runtimeTestSignedCertificate(t, directory, "server", caCertificate, caKey, []string{runtimeTestServerName}, x509.ExtKeyUsageServerAuth)
	_, clientCertFile, clientKeyFile := runtimeTestSignedCertificate(t, directory, "client", caCertificate, caKey, nil, x509.ExtKeyUsageClientAuth)
	return runtimeTestTLSFiles{
		caFile:         caFile,
		serverCert:     serverCertificate,
		clientCertFile: clientCertFile,
		clientKeyFile:  clientKeyFile,
		caPool:         caPool,
	}
}

func runtimeTestSelfSignedServerTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: runtimeTestSerial(t),
		Subject:      pkix.Name{CommonName: runtimeTestServerName},
		DNSNames:     []string{runtimeTestServerName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(cryptorand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certificateDER}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}
}

func runtimeTestSignedCertificate(
	t *testing.T,
	directory, name string,
	ca *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	dnsNames []string,
	usage x509.ExtKeyUsage,
) (tls.Certificate, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: runtimeTestSerial(t),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	certificateDER, err := x509.CreateCertificate(cryptorand.Reader, template, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	certificateFile := filepath.Join(directory, name+".pem")
	keyFile := filepath.Join(directory, name+"-key.pem")
	require.NoError(t, os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	certificate, err := tls.LoadX509KeyPair(certificateFile, keyFile)
	require.NoError(t, err)
	return certificate, certificateFile, keyFile
}

func runtimeTestSerial(t *testing.T) *big.Int {
	t.Helper()
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := cryptorand.Int(cryptorand.Reader, limit)
	require.NoError(t, err)
	return serial
}

func runtimeTestStartGNMIServer(t *testing.T, fake *runtimeTestGNMIServer, tlsConfig *tls.Config) (string, *runtimeTestCountingListener) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	counting := &runtimeTestCountingListener{Listener: listener}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	gnmipb.RegisterGNMIServer(server, fake)
	go func() { _ = server.Serve(counting) }()
	t.Cleanup(func() {
		server.Stop()
		_ = counting.Close()
	})
	return counting.Addr().String(), counting
}

func runtimeTestTarget(endpoint, caFile, mode string, mappings ...GNMIMetricMappingConfig) GNMITargetConfig {
	return GNMITargetConfig{
		Name:            "runtime-target",
		Endpoint:        endpoint,
		Product:         gnmiProductASR9000,
		SoftwareVersion: "24.4.1",
		MaxStreams:      1,
		Credentials: GNMICredentialsConfig{
			Mode: gnmiCredentialUsernamePassword, Username: runtimeTestUsername, Password: configopaque.String(runtimeTestPassword),
		},
		TLS:      GNMITLSConfig{CAFile: caFile, MinVersion: "1.2", ServerNameOverride: runtimeTestServerName},
		Profiles: runtimeTestDisabledProfiles(),
		CustomSubscriptions: []GNMICustomSubscriptionConfig{{
			Name: "runtime-custom", Origin: runtimeTestOrigin, Mode: mode,
			SampleInterval: 10 * time.Millisecond, PollInterval: 10 * time.Millisecond, Mappings: mappings,
		}},
	}
}

func runtimeTestXRIdentityResponse(model, version string) *gnmipb.GetResponse {
	return &gnmipb.GetResponse{Notification: []*gnmipb.Notification{{
		Timestamp: time.Now().UnixNano(),
		Prefix:    &gnmipb.Path{Origin: "Cisco-IOS-XR-install-oper"},
		Update: []*gnmipb.Update{
			{
				Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "install"}, {Name: "version"}, {Name: "chassis-pid"}}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: model}},
			},
			{
				Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "install"}, {Name: "version"}, {Name: "label"}}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: version}},
			},
		},
	}}}
}

func runtimeTestNXIdentityResponse(model, version string) *gnmipb.GetResponse {
	component := []*gnmipb.PathElem{
		{Name: "components"},
		{Name: "component", Key: map[string]string{"name": "Chassis"}},
		{Name: "state"},
	}
	path := func(leaf string) *gnmipb.Path {
		elements := append([]*gnmipb.PathElem(nil), component...)
		elements = append(elements, &gnmipb.PathElem{Name: leaf})
		return &gnmipb.Path{Elem: elements}
	}
	return &gnmipb.GetResponse{Notification: []*gnmipb.Notification{{
		Timestamp: time.Now().UnixNano(),
		Prefix:    &gnmipb.Path{Origin: "openconfig"},
		Update: []*gnmipb.Update{
			{Path: path("type"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "openconfig-platform-types:CHASSIS"}}},
			{Path: path("model-name"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: model}}},
			{Path: path("software-version"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: version}}},
		},
	}}}
}

func runtimeTestMapping(path, metricName string) GNMIMetricMappingConfig {
	scale := 1.0
	return GNMIMetricMappingConfig{
		Path: path, MetricName: metricName, Description: "Runtime test metric.", Unit: "1", Scale: &scale, GaugeType: "int",
	}
}

func runtimeTestDisabledProfiles() GNMIProfilesConfig {
	disabled := false
	return GNMIProfilesConfig{
		Identity:             GNMIProfileConfig{Enabled: &disabled},
		System:               GNMIProfileConfig{Enabled: &disabled},
		Interfaces:           GNMIProfileConfig{Enabled: &disabled},
		Optics:               GNMIProfileConfig{Enabled: &disabled},
		Catalyst9800Wireless: GNMIProfileConfig{Enabled: &disabled},
	}
}

func runtimeTestStartReceiver(
	t *testing.T,
	settings receiver.Settings,
	target GNMITargetConfig,
	maxDatapoints int,
	next consumer.Metrics,
) *sharedGNMIReceiver {
	t.Helper()
	config := createDefaultConfig().(*Config)
	config.GNMI = GNMIConfig{MaxDatapointsPerChunk: maxDatapoints, MaxCachedSeries: 100, Targets: []GNMITargetConfig{target}}
	created, err := newSharedGNMIReceiver(settings, config, next)
	require.NoError(t, err)
	receiver := created.(*sharedGNMIReceiver)
	require.NoError(t, receiver.Start(t.Context(), componenttest.NewNopHost()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		_ = receiver.Shutdown(ctx)
	})
	return receiver
}

func runtimeTestServeTarget(t *testing.T, target GNMITargetConfig) error {
	t.Helper()
	target = target.withDefaults()
	target.CapabilitiesTimeout = 500 * time.Millisecond
	cache, err := internalgnmi.NewCache(100)
	require.NoError(t, err)
	runtime, err := newSharedGNMITargetRuntime(target, cache)
	require.NoError(t, err)
	receiver := &sharedGNMIReceiver{
		settings:          receivertest.NewNopSettings(componentmetadata.Type),
		consumer:          consumertest.NewNop(),
		maxDatapoints:     10,
		maxCachedSeries:   100,
		host:              componenttest.NewNopHost(),
		notificationSlots: make(chan struct{}, sharedGNMIMaxConcurrentDelivery),
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, _, err = receiver.serveTarget(ctx, runtime)
	return err
}

func runtimeTestWaitDone(t *testing.T, receiver *sharedGNMIReceiver) {
	t.Helper()
	select {
	case <-receiver.done:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "timed out waiting for shared gNMI receiver")
	}
}

func runtimeTestProtoPath(t *testing.T, path string) *gnmipb.Path {
	t.Helper()
	parsed, err := internalgnmi.ParsePath("", "", path)
	require.NoError(t, err)
	return parsed.ToProto()
}

func runtimeTestMetadataValue(metadata grpcmetadata.MD, key string) string {
	values := metadata.Get(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func runtimeTestSubscribedPaths(request *gnmipb.SubscribeRequest) []string {
	var paths []string
	for _, subscription := range request.GetSubscribe().GetSubscription() {
		parts := make([]string, 0, len(subscription.GetPath().GetElem()))
		for _, element := range subscription.GetPath().GetElem() {
			parts = append(parts, element.GetName())
		}
		paths = append(paths, strings.Join(parts, "/"))
	}
	return paths
}

func runtimeTestContains(values []string, wanted string) bool {
	return slices.Contains(values, wanted)
}

func runtimeTestMetricBatches(metrics []pmetric.Metrics, name string) []pmetric.Metrics {
	var batches []pmetric.Metrics
	for _, metric := range metrics {
		if runtimeTestMetricPointCount(metric, name) > 0 {
			batches = append(batches, metric)
		}
	}
	return batches
}

func runtimeTestMetricPointCountAll(metrics []pmetric.Metrics, name string) int {
	total := 0
	for _, metric := range metrics {
		total += runtimeTestMetricPointCount(metric, name)
	}
	return total
}

func runtimeTestDeviceUpValuesAll(metrics []pmetric.Metrics) []int64 {
	var values []int64
	for _, batch := range metrics {
		for i := 0; i < batch.ResourceMetrics().Len(); i++ {
			scopes := batch.ResourceMetrics().At(i).ScopeMetrics()
			for j := 0; j < scopes.Len(); j++ {
				items := scopes.At(j).Metrics()
				for k := 0; k < items.Len(); k++ {
					item := items.At(k)
					if item.Name() != "cisco.device.up" || item.Type() != pmetric.MetricTypeGauge {
						continue
					}
					points := item.Gauge().DataPoints()
					for pointIndex := 0; pointIndex < points.Len(); pointIndex++ {
						values = append(values, points.At(pointIndex).IntValue())
					}
				}
			}
		}
	}
	return values
}

func runtimeTestMetricPointCount(metrics pmetric.Metrics, name string) int {
	total := 0
	for i := 0; i < metrics.ResourceMetrics().Len(); i++ {
		scopes := metrics.ResourceMetrics().At(i).ScopeMetrics()
		for j := 0; j < scopes.Len(); j++ {
			items := scopes.At(j).Metrics()
			for k := 0; k < items.Len(); k++ {
				item := items.At(k)
				if item.Name() != name {
					continue
				}
				switch item.Type() {
				case pmetric.MetricTypeGauge:
					total += item.Gauge().DataPoints().Len()
				case pmetric.MetricTypeSum:
					total += item.Sum().DataPoints().Len()
				}
			}
		}
	}
	return total
}

type runtimeTestRejectingConsumer struct {
	metricName  string
	maxRefusals int64
	calls       atomic.Int64
	refusals    atomic.Int64
	accepted    atomic.Int64
}

type runtimeTestRejectingDownConsumer struct {
	sink     consumertest.MetricsSink
	rejected atomic.Bool
}

func (*runtimeTestRejectingDownConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (c *runtimeTestRejectingDownConsumer) ConsumeMetrics(ctx context.Context, metrics pmetric.Metrics) error {
	if slices.Contains(runtimeTestDeviceUpValuesAll([]pmetric.Metrics{metrics}), int64(0)) &&
		c.rejected.CompareAndSwap(false, true) {
		return errors.New("intentional down-transition refusal")
	}
	return c.sink.ConsumeMetrics(ctx, metrics)
}

func (*runtimeTestRejectingConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (c *runtimeTestRejectingConsumer) ConsumeMetrics(_ context.Context, metrics pmetric.Metrics) error {
	points := runtimeTestMetricPointCount(metrics, c.metricName)
	if points == 0 {
		return nil
	}
	call := c.calls.Add(1)
	if call <= c.maxRefusals {
		c.refusals.Add(1)
		return errors.New("intentional runtime test refusal")
	}
	c.accepted.Add(int64(points))
	return nil
}

func runtimeTestTelemetryIntSum(t *testing.T, reader *metric.ManualReader, name string) int64 {
	t.Helper()
	var resourceMetrics metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &resourceMetrics))
	var total int64
	for _, scope := range resourceMetrics.ScopeMetrics {
		for _, instrument := range scope.Metrics {
			if instrument.Name != name {
				continue
			}
			sum, ok := instrument.Data.(metricdata.Sum[int64])
			require.True(t, ok)
			for _, point := range sum.DataPoints {
				total += point.Value
			}
		}
	}
	return total
}

func runtimeTestTelemetryIntGauge(t *testing.T, reader *metric.ManualReader, name string) int64 {
	t.Helper()
	var resourceMetrics metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &resourceMetrics))
	var total int64
	for _, scope := range resourceMetrics.ScopeMetrics {
		for _, instrument := range scope.Metrics {
			if instrument.Name != name {
				continue
			}
			gauge, ok := instrument.Data.(metricdata.Gauge[int64])
			require.True(t, ok)
			for _, point := range gauge.DataPoints {
				total += point.Value
			}
		}
	}
	return total
}
