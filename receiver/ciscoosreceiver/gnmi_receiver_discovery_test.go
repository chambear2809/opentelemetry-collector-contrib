// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestSharedGNMIAutomaticDiscoverySelectsCatalogAndPopulatesResources(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{
		capabilities: func(context.Context) (*gnmipb.CapabilityResponse, error) {
			return runtimeTestIOSXRCapabilities(gnmipb.Encoding_JSON_IETF), nil
		},
	}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		if err := runtimeTestSendScalarUpdate(stream, "system/value", 42); err != nil {
			return err
		}
		return stream.Send(&gnmipb.SubscribeResponse{
			Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
		})
	}
	endpoint, listener := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce, runtimeTestMapping("system/value", "runtime.discovery.value"))
	target.Platform = ""
	target.ProductFamily = ""
	sink := &consumertest.MetricsSink{}
	receiver := runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 10, sink)
	runtimeTestWaitDone(t, receiver)

	snapshot := fake.snapshot()
	assert.Equal(t, int64(1), listener.accepts.Load(), "capabilities, identity, and operational subscriptions must share one connection")
	assert.Equal(t, 1, snapshot.capabilitiesCalls)
	assert.Equal(t, 1, snapshot.identityCalls)
	assert.Equal(t, 1, snapshot.subscribeCalls)
	assert.Zero(t, snapshot.getCalls)
	assert.Zero(t, snapshot.setCalls)
	require.Len(t, snapshot.identityRequests, 1)
	assert.True(t, runtimeTestIsIOSXRIdentityRequest(snapshot.identityRequests[0]))
	require.Len(t, snapshot.identityMetadata, 1)
	assert.Equal(t, runtimeTestUsername, runtimeTestMetadataValue(snapshot.identityMetadata[0], "username"))
	assert.Equal(t, runtimeTestPassword, runtimeTestMetadataValue(snapshot.identityMetadata[0], "password"))

	effective, identity := receiver.targets[0].sessionResourceIdentity()
	assert.Equal(t, gnmiPlatformIOSXR, effective.Platform)
	assert.Equal(t, "ios_xr", effective.ProductFamily)
	assert.Equal(t, "ios_xr", identity.ProductFamily)
	assert.Equal(t, "XRv9000", identity.ModelIdentifier)
	assert.Equal(t, "25.2.21", identity.SoftwareVersion)
	assert.Equal(t, "XR-SERIAL-1", identity.SerialNumber)
	require.Len(t, receiver.targets[0].streams, 1)
	assert.Equal(t, gnmipb.Encoding_JSON_IETF, receiver.targets[0].streams[0].wireEncoding)

	batches := runtimeTestMetricBatches(sink.AllMetrics(), "runtime.discovery.value")
	require.Len(t, batches, 1)
	attributes := batches[0].ResourceMetrics().At(0).Resource().Attributes()
	assert.Equal(t, "ios_xr", attrValue(t, attributes, "cisco.os.name"))
	assert.Equal(t, "ios_xr", attrValue(t, attributes, "cisco.platform.family"))
	assert.Equal(t, "Cisco", attrValue(t, attributes, "device.manufacturer"))
	assert.Equal(t, "XRv9000", attrValue(t, attributes, "device.model.identifier"))
	assert.Equal(t, "25.2.21", attrValue(t, attributes, "os.version"))
	assert.Equal(t, "XR-SERIAL-1", attrValue(t, attributes, "host.id"))
	assert.Equal(t, "XR-SERIAL-1", attrValue(t, attributes, "hw.serial_number"))
	assert.Equal(t, "xrv9k-lab", attrValue(t, attributes, "host.name"))
	assert.Equal(t, "XR Virtual Router", attrValue(t, attributes, "host.type"))
}

func TestSharedGNMIDiscoveryReleasesCapabilitiesBeforeSingleSlotIdentity(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{
		capabilities: func(context.Context) (*gnmipb.CapabilityResponse, error) {
			return runtimeTestIOSXRCapabilities(gnmipb.Encoding_JSON_IETF), nil
		},
	}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		return stream.Send(&gnmipb.SubscribeResponse{
			Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
		})
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce, runtimeTestMapping("system/value", "runtime.single-slot.value"))
	target.Platform = ""
	target.SyncTimeout = 500 * time.Millisecond
	config := createDefaultConfig().(*Config)
	config.GNMI = GNMIConfig{MaxDatapointsPerChunk: 10, MaxCachedSeries: 100, Targets: []GNMITargetConfig{target}}
	admission := newGNMIResponseAdmissionWithLimit(1)
	created, err := newSharedGNMIReceiver(
		receivertest.NewNopSettings(componentmetadata.Type),
		config,
		consumertest.NewNop(),
		admission,
	)
	require.NoError(t, err)
	receiver := created.(*sharedGNMIReceiver)
	require.NoError(t, receiver.Start(t.Context(), componenttest.NewNopHost()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		_ = receiver.Shutdown(ctx)
	})
	runtimeTestWaitDone(t, receiver)

	snapshot := fake.snapshot()
	assert.Equal(t, 1, snapshot.capabilitiesCalls)
	assert.Equal(t, 1, snapshot.identityCalls)
	assert.Equal(t, 1, snapshot.subscribeCalls)
	assert.Empty(t, admission.slots, "capabilities and stream response leases must both be released")
}

func TestSharedGNMIDiscoveryRejectsExpectedFamilyMismatchAndCatalogCeiling(t *testing.T) {
	material := runtimeTestTLSMaterial(t)

	t.Run("platform mismatch", func(t *testing.T) {
		fake := &runtimeTestGNMIServer{
			capabilities: func(context.Context) (*gnmipb.CapabilityResponse, error) {
				return runtimeTestIOSXRCapabilities(gnmipb.Encoding_JSON_IETF), nil
			},
			identity: func(request *gnmipb.SubscribeRequest) (*gnmipb.Notification, error) {
				if runtimeTestIsNXOSIdentityRequest(request) {
					return nil, status.Error(codes.Unimplemented, "NX identity path is not available on the IOS XR target")
				}
				return runtimeTestIOSXRIdentityNotification("XRv9000", "25.2.21"), nil
			},
		}
		endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
		target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce, runtimeTestMapping("system/value", "runtime.platform-mismatch.value"))
		target.Platform = gnmiPlatformNXOS

		err := runtimeTestServeTarget(t, target)
		require.ErrorContains(t, err, `configured platform "nx_os" does not match subscribed OS family "ios_xr"`)
		snapshot := fake.snapshot()
		assert.Equal(t, 2, snapshot.identityCalls, "the configured probe is attempted before the capability-advertised family")
		assert.Zero(t, snapshot.subscribeCalls)
		assert.Zero(t, snapshot.getCalls)
		assert.Zero(t, snapshot.setCalls)
	})

	t.Run("product family mismatch", func(t *testing.T) {
		fake := &runtimeTestGNMIServer{
			capabilities: func(context.Context) (*gnmipb.CapabilityResponse, error) {
				return runtimeTestIOSXRCapabilities(gnmipb.Encoding_JSON_IETF), nil
			},
		}
		endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
		target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce, runtimeTestMapping("system/value", "runtime.mismatch.value"))
		target.Platform = ""
		target.ProductFamily = "nx_os"

		err := runtimeTestServeTarget(t, target)
		require.ErrorContains(t, err, `configured product_family "nx_os" belongs to platform "nx_os"`)
		snapshot := fake.snapshot()
		assert.Equal(t, 1, snapshot.identityCalls)
		assert.Zero(t, snapshot.subscribeCalls)
		assert.Zero(t, snapshot.getCalls)
		assert.Zero(t, snapshot.setCalls)
	})

	t.Run("catalog stream ceiling", func(t *testing.T) {
		fake := &runtimeTestGNMIServer{
			capabilities: func(context.Context) (*gnmipb.CapabilityResponse, error) {
				return runtimeTestIOSXRCapabilities(gnmipb.Encoding_JSON_IETF), nil
			},
		}
		endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
		target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce, runtimeTestMapping("system/value", "runtime.ceiling.value"))
		target.MaxStreams = 5
		target.ProductFamily = "ios_xr"

		err := runtimeTestServeTarget(t, target)
		require.ErrorContains(t, err, `configured max_streams 5 exceeds selected catalog family "ios_xr" ceiling 4`)
		snapshot := fake.snapshot()
		assert.Equal(t, 1, snapshot.identityCalls)
		assert.Zero(t, snapshot.subscribeCalls)
		assert.Zero(t, snapshot.getCalls)
		assert.Zero(t, snapshot.setCalls)
	})
}

func TestSharedGNMISessionUsesPerStreamEncodings(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{
		capabilities: func(context.Context) (*gnmipb.CapabilityResponse, error) {
			return runtimeTestIOSXRCapabilities(gnmipb.Encoding_JSON_IETF, gnmipb.Encoding_JSON), nil
		},
	}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		return stream.Send(&gnmipb.SubscribeResponse{
			Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
		})
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce, runtimeTestMapping("system/json", "runtime.encoding.json"))
	target.Platform = ""
	target.MaxStreams = 2
	target.CustomSubscriptions[0].Encoding = gnmiEncodingJSON
	target.CustomSubscriptions = append(target.CustomSubscriptions, GNMICustomSubscriptionConfig{
		Name:           "runtime-json-ietf",
		Origin:         runtimeTestOrigin,
		Mode:           gnmiModeOnce,
		Encoding:       gnmiEncodingJSONIETF,
		SampleInterval: 10 * time.Millisecond,
		PollInterval:   10 * time.Millisecond,
		Mappings:       []GNMIMetricMappingConfig{runtimeTestMapping("system/json-ietf", "runtime.encoding.json_ietf")},
	})
	receiver := runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 10, consumertest.NewNop())
	runtimeTestWaitDone(t, receiver)

	snapshot := fake.snapshot()
	assert.Equal(t, 1, snapshot.identityCalls)
	require.Len(t, snapshot.requests, 2)
	encodings := map[gnmipb.Encoding]bool{}
	for _, request := range snapshot.requests {
		encodings[request.GetSubscribe().GetEncoding()] = true
	}
	assert.Equal(t, map[gnmipb.Encoding]bool{
		gnmipb.Encoding_JSON:      true,
		gnmipb.Encoding_JSON_IETF: true,
	}, encodings)
}

func TestSharedGNMIReconnectRediscoversAndReselectsIdentity(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	var identityAttempt atomic.Int64
	var operationalAttempt atomic.Int64
	fake := &runtimeTestGNMIServer{
		capabilities: func(context.Context) (*gnmipb.CapabilityResponse, error) {
			return runtimeTestIOSXRCapabilities(gnmipb.Encoding_JSON_IETF), nil
		},
		identity: func(*gnmipb.SubscribeRequest) (*gnmipb.Notification, error) {
			switch identityAttempt.Add(1) {
			case 1:
				return runtimeTestIOSXRIdentityNotification("XRv9000", "25.2.21"), nil
			case 2:
				return runtimeTestIOSXRIdentityNotification("NCS-5501", "25.2.21"), nil
			default:
				return runtimeTestIOSXRIdentityNotification("NCS-5501", "25.2.22"), nil
			}
		},
	}
	fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		fake.recordRequest(request)
		value := operationalAttempt.Add(1)
		if err := runtimeTestSendScalarUpdate(stream, "system/value", value); err != nil {
			return err
		}
		return stream.Send(&gnmipb.SubscribeResponse{
			Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
		})
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce, runtimeTestMapping("system/value", "runtime.reselection.value"))
	target.Platform = ""
	target = target.withDefaults()
	cache, err := internalgnmi.NewCache(100)
	require.NoError(t, err)
	runtime, err := newSharedGNMITargetRuntime(target, cache)
	require.NoError(t, err)
	assert.Empty(t, runtime.streams, "empty-platform construction must defer stream compilation")
	sink := &consumertest.MetricsSink{}
	receiver := &sharedGNMIReceiver{
		settings:          receivertest.NewNopSettings(componentmetadata.Type),
		consumer:          sink,
		maxDatapoints:     10,
		maxCachedSeries:   100,
		host:              componenttest.NewNopHost(),
		notificationSlots: make(chan struct{}, sharedGNMIMaxConcurrentDelivery),
		responseAdmission: newGNMIResponseAdmission(),
	}

	terminal, _, err := receiver.serveTarget(t.Context(), runtime)
	require.NoError(t, err)
	require.True(t, terminal)
	_, identity := runtime.sessionResourceIdentity()
	assert.Equal(t, "XRv9000", identity.ModelIdentifier)
	require.Len(t, runtime.streams, 1)
	firstRegistry := runtime.streams[0].registry

	terminal, _, err = receiver.serveTarget(t.Context(), runtime)
	require.NoError(t, err)
	require.True(t, terminal)
	_, identity = runtime.sessionResourceIdentity()
	assert.Equal(t, "NCS-5501", identity.ModelIdentifier)
	require.Len(t, runtime.streams, 1)
	assert.NotSame(t, firstRegistry, runtime.streams[0].registry, "each session must rebuild its discovered runtime streams")

	terminal, _, err = receiver.serveTarget(t.Context(), runtime)
	require.ErrorContains(t, err, `software version "25.2.22"`)
	assert.False(t, terminal)
	_, identity = runtime.sessionResourceIdentity()
	assert.Equal(t, sharedGNMIDeviceIdentity{}, identity, "a failed new release selection must not retain stale session identity")

	snapshot := fake.snapshot()
	assert.Equal(t, 3, snapshot.capabilitiesCalls)
	assert.Equal(t, 3, snapshot.identityCalls)
	assert.Equal(t, 2, snapshot.subscribeCalls)
	assert.Zero(t, snapshot.getCalls)
	assert.Zero(t, snapshot.setCalls)
	batches := runtimeTestMetricBatches(sink.AllMetrics(), "runtime.reselection.value")
	require.Len(t, batches, 2)
	secondAttributes := batches[1].ResourceMetrics().At(0).Resource().Attributes()
	assert.Equal(t, "NCS-5501", attrValue(t, secondAttributes, "device.model.identifier"))
}

func runtimeTestIOSXRCapabilities(encodings ...gnmipb.Encoding) *gnmipb.CapabilityResponse {
	return &gnmipb.CapabilityResponse{
		SupportedEncodings: encodings,
		SupportedModels: []*gnmipb.ModelData{{
			Name: "Cisco-IOS-XR-install-oper",
		}},
	}
}
