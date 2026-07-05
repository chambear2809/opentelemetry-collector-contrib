// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestSharedGNMIProductContractsPreflightBeforeSubscribe(t *testing.T) {
	tests := []struct {
		name, product, version, model, osFamily string
		metric, updateOrigin, updatePath        string
		encoding                                gnmipb.Encoding
		requiredModels                          []string
	}{
		{
			name: "catalyst 9800", product: gnmiProductCatalyst9800, version: "17.18.1a", model: "C9800-40-K9", osFamily: gnmiPlatformIOSXE,
			encoding: gnmipb.Encoding_JSON_IETF, metric: "cisco.wlc.ap.join.status", updateOrigin: builtinGNMIOriginRFC7951,
			updatePath: "Cisco-IOS-XE-wireless-ap-global-oper:ap-global-oper-data/ap-join-stats[wtp-mac=ap-1]/is-joined",
			requiredModels: []string{
				"Cisco-IOS-XE-device-hardware-oper", "Cisco-IOS-XE-install-oper",
				"Cisco-IOS-XE-wireless-access-point-oper", "Cisco-IOS-XE-wireless-ap-global-oper", "Cisco-IOS-XE-wireless-rrm-oper",
			},
		},
		{
			name: "asr 9000", product: gnmiProductASR9000, version: "24.4.1", model: "ASR-9904", osFamily: gnmiPlatformIOSXR,
			encoding: gnmipb.Encoding_JSON_IETF, metric: "system.network.interface.status", updateOrigin: "openconfig-interfaces",
			updatePath:     "interfaces/interface[name=Ethernet1]/state/oper-status",
			requiredModels: []string{"Cisco-IOS-XR-install-oper", "openconfig-interfaces"},
		},
		{
			name: "ncs 5500", product: gnmiProductNCS5500, version: "24.4.2", model: "NCS-5501-SE", osFamily: gnmiPlatformIOSXR,
			encoding: gnmipb.Encoding_JSON_IETF, metric: "system.network.interface.status", updateOrigin: "openconfig-interfaces",
			updatePath:     "interfaces/interface[name=Ethernet1]/state/oper-status",
			requiredModels: []string{"Cisco-IOS-XR-install-oper", "openconfig-interfaces"},
		},
		{
			name: "nexus 9000", product: gnmiProductNexus9000, version: "10.6(1)F", model: "N9K-C93180YC-FX3", osFamily: gnmiPlatformNXOS,
			encoding: gnmipb.Encoding_JSON, metric: "system.network.interface.status", updateOrigin: "openconfig",
			updatePath:     "interfaces/interface[name=Ethernet1]/state/oper-status",
			requiredModels: []string{"openconfig-platform", "openconfig-interfaces"},
		},
		{
			name: "nexus 3500", product: gnmiProductNexus3500, version: "10.5(3)M", model: "N3K-C3548P-10GX", osFamily: gnmiPlatformNXOS,
			encoding: gnmipb.Encoding_JSON, metric: "system.network.interface.status", updateOrigin: "openconfig",
			updatePath:     "interfaces/interface[name=Ethernet1]/state/oper-status",
			requiredModels: []string{"openconfig-platform", "openconfig-interfaces"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			material := runtimeTestTLSMaterial(t)
			fake := &runtimeTestGNMIServer{}
			models := make([]*gnmipb.ModelData, 0, len(test.requiredModels))
			for _, name := range test.requiredModels {
				models = append(models, &gnmipb.ModelData{Name: name})
			}
			fake.capabilities = func(context.Context) (*gnmipb.CapabilityResponse, error) {
				return &gnmipb.CapabilityResponse{
					SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_PROTO, test.encoding},
					SupportedModels:    models,
					GNMIVersion:        "0.7.0",
				}, nil
			}
			var identityProbeCalls atomic.Int64
			fake.get = func(context.Context, *gnmipb.GetRequest) (*gnmipb.GetResponse, error) {
				call := identityProbeCalls.Add(1)
				switch test.osFamily {
				case gnmiPlatformIOSXE:
					if call == 1 {
						return runtimeTestXEHardwareIdentityResponse(test.model), nil
					}
					// IOS XE exposes an internal install-version key and a
					// separate opaque version-extension, not the public release
					// string used by configuration and os.version.
					return runtimeTestXEVersionIdentityResponseWithExtension("17.18.01a.0.1186", "1750000000"), nil
				case gnmiPlatformIOSXR:
					return runtimeTestXRIdentityResponse(test.model, test.version), nil
				default:
					return runtimeTestNXIdentityResponse(test.model, test.version), nil
				}
			}
			fake.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
				request, err := stream.Recv()
				if err != nil {
					return err
				}
				fake.recordRequest(request)
				if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
					Timestamp: time.Now().UnixNano(),
					Prefix:    &gnmipb.Path{Origin: test.updateOrigin},
					Update: []*gnmipb.Update{{
						Path: runtimeTestProtoPath(t, test.updatePath),
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

			target := runtimeTestTarget(endpoint, material.caFile, gnmiModeStream, runtimeTestMapping("unused/value", "runtime.unused"))
			target.Product = test.product
			target.SoftwareVersion = test.version
			target.CustomSubscriptions = nil
			target.Profiles = runtimeTestDisabledProfiles()
			enabled := true
			if test.product == gnmiProductCatalyst9800 {
				target.Profiles.Catalyst9800Wireless = GNMIProfileConfig{Enabled: &enabled, Required: true, SampleInterval: time.Second}
			} else {
				target.Profiles.Interfaces = GNMIProfileConfig{Enabled: &enabled, Required: true, SampleInterval: time.Second}
			}
			sink := &consumertest.MetricsSink{}
			reader := metric.NewManualReader()
			provider := metric.NewMeterProvider(metric.WithReader(reader))
			t.Cleanup(func() { require.NoError(t, provider.Shutdown(context.WithoutCancel(t.Context()))) })
			settings := receivertest.NewNopSettings(componentmetadata.Type)
			settings.MeterProvider = provider
			runtimeTestStartReceiver(t, settings, target, 10, sink)

			require.Eventually(t, func() bool {
				return runtimeTestMetricPointCountAll(sink.AllMetrics(), test.metric) == 1 &&
					runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.device.up") == 1
			}, 5*time.Second, 10*time.Millisecond)

			snapshot := fake.snapshot()
			contract, canonical, err := resolveGNMIProductContract(test.product, test.version)
			require.NoError(t, err)
			plannedStreams, err := buildSharedGNMIStreams(target)
			require.NoError(t, err)
			requiredModels := requiredGNMIModels(contract, plannedStreams)
			assert.ElementsMatch(t, test.requiredModels, requiredModels)
			assert.NotContains(t, requiredModels, "openconfig", "the NX-OS wire origin is not a Capabilities model name")
			assert.Equal(t, int64(1), listener.accepts.Load(), "Capabilities, identity Get, and Subscribe must share the verified connection")
			assert.Equal(t, 1, snapshot.capabilitiesCalls)
			assert.Equal(t, len(contract.IdentityProbes), snapshot.getCalls)
			assert.Zero(t, snapshot.identitySubscribeCalls)
			assert.Equal(t, 1, snapshot.subscribeCalls)
			expectedRPCOrder := []string{"Capabilities"}
			for range contract.IdentityProbes {
				expectedRPCOrder = append(expectedRPCOrder, "Get")
			}
			expectedRPCOrder = append(expectedRPCOrder, "Subscribe")
			assert.Equal(t, expectedRPCOrder, snapshot.rpcOrder)
			require.Len(t, snapshot.getRequests, len(contract.IdentityProbes))
			require.Len(t, snapshot.getMetadata, len(contract.IdentityProbes))
			for index, getRequest := range snapshot.getRequests {
				assert.Equal(t, gnmipb.GetRequest_STATE, getRequest.GetType())
				assert.Equal(t, test.encoding, getRequest.GetEncoding())
				require.Len(t, getRequest.GetPath(), 1)
				assert.Equal(t, runtimeTestUsername, runtimeTestMetadataValue(snapshot.getMetadata[index], "username"))
				assert.Equal(t, runtimeTestPassword, runtimeTestMetadataValue(snapshot.getMetadata[index], "password"))
			}
			require.Len(t, snapshot.requests, 1)
			request := snapshot.requests[0].GetSubscribe()
			require.NotNil(t, request)
			require.NotEmpty(t, request.GetSubscription())
			assert.Equal(t, test.encoding, request.GetEncoding())
			if test.osFamily == gnmiPlatformNXOS {
				assert.Nil(t, request.GetPrefix())
				assert.Equal(t, test.updateOrigin, request.GetSubscription()[0].GetPath().GetOrigin())
				assert.Equal(t, gnmipb.SubscriptionList_STREAM, request.GetMode())
				assert.Equal(t, gnmipb.SubscriptionMode_SAMPLE, request.GetSubscription()[0].GetMode())
				assert.NotContains(t, request.GetSubscription()[0].GetPath().String(), "*")
				assert.False(t, request.GetUpdatesOnly())
				assert.False(t, request.GetAllowAggregation())
				assert.Nil(t, request.GetQos())
				assert.Empty(t, snapshot.requests[0].GetExtension())
			} else {
				assert.Equal(t, test.updateOrigin, request.GetPrefix().GetOrigin())
			}

			batches := runtimeTestMetricBatches(sink.AllMetrics(), test.metric)
			require.NotEmpty(t, batches)
			attrs := batches[0].ResourceMetrics().At(0).Resource().Attributes()
			assert.Equal(t, test.product, attrValue(t, attrs, "cisco.product.family"))
			assert.Equal(t, test.osFamily, attrValue(t, attrs, "cisco.platform.family"))
			assert.Equal(t, test.osFamily, attrValue(t, attrs, "cisco.os.name"))
			assert.Equal(t, "Cisco", attrValue(t, attrs, "device.manufacturer"))
			assert.Equal(t, test.model, attrValue(t, attrs, "device.model.identifier"))
			assert.Equal(t, contract.OSFamily, test.osFamily)
			assert.Equal(t, canonical.Canonical, attrValue(t, attrs, "os.version"))
			assert.Equal(t, int64(1), runtimeTestTelemetryIntGauge(t, reader, "otelcol_ciscoosreceiver_gnmi_product_verified"))
		})
	}
}

func TestSharedGNMICompatibilityFailuresQuarantineOnceWithoutSubscribe(t *testing.T) {
	tests := []struct {
		name            string
		reason          string
		capabilities    *gnmipb.CapabilityResponse
		capabilitiesErr error
		get             func(context.Context, *gnmipb.GetRequest) (*gnmipb.GetResponse, error)
		wantGetCalls    int
	}{
		{
			reason: gnmiPreflightUnsupportedEncoding,
			capabilities: &gnmipb.CapabilityResponse{
				SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_PROTO},
				SupportedModels:    runtimeTestASRRequiredModels(),
			},
		},
		{
			name:            "unimplemented Capabilities is terminal",
			reason:          gnmiPreflightUnsupportedEncoding,
			capabilitiesErr: status.Error(codes.Unimplemented, "Capabilities unavailable"),
		},
		{
			reason: gnmiPreflightMissingModel,
			capabilities: &gnmipb.CapabilityResponse{
				SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON_IETF},
				SupportedModels:    []*gnmipb.ModelData{{Name: "Cisco-IOS-XR-install-oper"}},
			},
		},
		{
			reason:       gnmiPreflightIdentityMissing,
			wantGetCalls: 1,
			get: func(context.Context, *gnmipb.GetRequest) (*gnmipb.GetResponse, error) {
				return &gnmipb.GetResponse{}, nil
			},
		},
		{
			reason:       gnmiPreflightIdentityAmbiguous,
			wantGetCalls: 1,
			get: func(context.Context, *gnmipb.GetRequest) (*gnmipb.GetResponse, error) {
				response := runtimeTestXRIdentityResponse("ASR-9904", "24.4.1")
				other := runtimeTestXRIdentityResponse("ASR-9912", "24.4.1")
				response.Notification = append(response.Notification, other.Notification...)
				return response, nil
			},
		},
		{
			reason:       gnmiPreflightProductMismatch,
			wantGetCalls: 1,
			get: func(context.Context, *gnmipb.GetRequest) (*gnmipb.GetResponse, error) {
				return runtimeTestXRIdentityResponse("NCS-5501-SE", "24.4.1"), nil
			},
		},
		{
			reason:       gnmiPreflightReleaseMismatch,
			wantGetCalls: 1,
			get: func(context.Context, *gnmipb.GetRequest) (*gnmipb.GetResponse, error) {
				return runtimeTestXRIdentityResponse("ASR-9904", "24.4.2"), nil
			},
		},
		{
			reason:       gnmiPreflightMalformedIdentity,
			wantGetCalls: 1,
			get: func(context.Context, *gnmipb.GetRequest) (*gnmipb.GetResponse, error) {
				return runtimeTestXRIdentityResponse("ASR-9904", "not-a-release"), nil
			},
		},
		{
			reason:       gnmiPreflightMalformedIdentity,
			wantGetCalls: 1,
			get: func(context.Context, *gnmipb.GetRequest) (*gnmipb.GetResponse, error) {
				return &gnmipb.GetResponse{Notification: make([]*gnmipb.Notification, gnmiMaximumIdentityNotifications+1)}, nil
			},
		},
		{
			name:         "not found identity subtree is terminal",
			reason:       gnmiPreflightMalformedIdentity,
			wantGetCalls: 1,
			get: func(context.Context, *gnmipb.GetRequest) (*gnmipb.GetResponse, error) {
				return nil, status.Error(codes.NotFound, "identity subtree is unavailable")
			},
		},
	}

	for _, test := range tests {
		name := test.name
		if name == "" {
			name = test.reason
		}
		t.Run(name, func(t *testing.T) {
			material := runtimeTestTLSMaterial(t)
			fake := &runtimeTestGNMIServer{}
			capabilities := test.capabilities
			if capabilities == nil {
				capabilities = &gnmipb.CapabilityResponse{
					SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON_IETF},
					SupportedModels:    runtimeTestASRRequiredModels(),
				}
			}
			fake.capabilities = func(context.Context) (*gnmipb.CapabilityResponse, error) {
				return capabilities, test.capabilitiesErr
			}
			fake.get = test.get
			endpoint, listener := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
			target := runtimeTestTarget(endpoint, material.caFile, gnmiModeStream, runtimeTestMapping("system/value", "runtime.quarantine.value"))

			reader := metric.NewManualReader()
			provider := metric.NewMeterProvider(metric.WithReader(reader))
			t.Cleanup(func() { require.NoError(t, provider.Shutdown(context.WithoutCancel(t.Context()))) })
			settings := receivertest.NewNopSettings(componentmetadata.Type)
			settings.MeterProvider = provider
			sink := &consumertest.MetricsSink{}
			receiver := runtimeTestStartReceiver(t, settings, target, 10, sink)
			runtimeTestWaitDone(t, receiver)

			snapshot := fake.snapshot()
			assert.Equal(t, int64(1), listener.accepts.Load())
			assert.Equal(t, 1, snapshot.capabilitiesCalls)
			assert.Equal(t, test.wantGetCalls, snapshot.getCalls)
			assert.Zero(t, snapshot.identitySubscribeCalls)
			assert.Zero(t, snapshot.subscribeCalls)
			expectedRPCOrder := []string{"Capabilities"}
			for range test.wantGetCalls {
				expectedRPCOrder = append(expectedRPCOrder, "Get")
			}
			assert.Equal(t, expectedRPCOrder, snapshot.rpcOrder)
			assert.Equal(t, 1, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.device.up"))
			assert.Equal(t, int64(1), runtimeTestTelemetryIntSum(t, reader, "otelcol_ciscoosreceiver_gnmi_preflight_failures"))
			assert.Equal(t, int64(0), runtimeTestTelemetryIntGauge(t, reader, "otelcol_ciscoosreceiver_gnmi_product_verified"))
			assert.Equal(t, int64(1), runtimeTestTelemetryPreflightReason(t, reader, test.reason))
		})
	}
}

func TestSharedGNMIOversizedIdentityGetQuarantinesWithoutReconnect(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.capabilities = func(context.Context) (*gnmipb.CapabilityResponse, error) {
		return &gnmipb.CapabilityResponse{
			SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON_IETF},
			SupportedModels:    runtimeTestASRRequiredModels(),
		}, nil
	}
	fake.get = func(context.Context, *gnmipb.GetRequest) (*gnmipb.GetResponse, error) {
		oversizedJSON := `"` + strings.Repeat("x", 2*1024*1024) + `"`
		return &gnmipb.GetResponse{Notification: []*gnmipb.Notification{{
			Prefix: &gnmipb.Path{Origin: "Cisco-IOS-XR-install-oper"},
			Update: []*gnmipb.Update{{
				Path: runtimeTestProtoPath(t, "install/version/label"),
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(oversizedJSON)}},
			}},
		}}}, nil
	}
	endpoint, listener := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeStream, runtimeTestMapping("system/value", "runtime.oversized.value"))
	target.MaxRecvMsgSizeMiB = 1

	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(context.WithoutCancel(t.Context()))) })
	settings := receivertest.NewNopSettings(componentmetadata.Type)
	settings.MeterProvider = provider
	sink := &consumertest.MetricsSink{}
	receiver := runtimeTestStartReceiver(t, settings, target, 10, sink)
	runtimeTestWaitDone(t, receiver)

	snapshot := fake.snapshot()
	assert.Equal(t, int64(1), listener.accepts.Load())
	assert.Equal(t, 1, snapshot.capabilitiesCalls)
	assert.Equal(t, 1, snapshot.getCalls)
	assert.Zero(t, snapshot.subscribeCalls)
	assert.Equal(t, int64(1), runtimeTestTelemetryPreflightReason(t, reader, gnmiPreflightMalformedIdentity))
	assert.Equal(t, 1, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.device.up"))
}

func TestSharedGNMIEnabledCuratedProfileMissingModelQuarantines(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.capabilities = func(context.Context) (*gnmipb.CapabilityResponse, error) {
		return &gnmipb.CapabilityResponse{
			SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON_IETF},
			SupportedModels:    []*gnmipb.ModelData{{Name: "Cisco-IOS-XR-install-oper"}},
		}, nil
	}
	endpoint, listener := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeStream, runtimeTestMapping("unused/value", "runtime.unused"))
	target.CustomSubscriptions = nil
	target.MaxStreams = 3
	enabled := true
	target.Profiles.System.Enabled = &enabled

	sink := &consumertest.MetricsSink{}
	receiver := runtimeTestStartReceiver(t, receivertest.NewNopSettings(componentmetadata.Type), target, 10, sink)
	runtimeTestWaitDone(t, receiver)

	snapshot := fake.snapshot()
	assert.Equal(t, int64(1), listener.accepts.Load())
	assert.Equal(t, 1, snapshot.capabilitiesCalls)
	assert.Zero(t, snapshot.getCalls)
	assert.Zero(t, snapshot.identitySubscribeCalls)
	assert.Zero(t, snapshot.subscribeCalls)
	assert.Equal(t, 1, runtimeTestMetricPointCountAll(sink.AllMetrics(), "cisco.device.up"))
}

func TestSharedGNMITransientIdentityRPCFailureRemainsRetryable(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	fake := &runtimeTestGNMIServer{}
	fake.capabilities = func(context.Context) (*gnmipb.CapabilityResponse, error) {
		return &gnmipb.CapabilityResponse{
			SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON_IETF},
			SupportedModels:    runtimeTestASRRequiredModels(),
		}, nil
	}
	fake.get = func(context.Context, *gnmipb.GetRequest) (*gnmipb.GetResponse, error) {
		// The endpoint controls status descriptions. It must not be able to
		// spoof the local codec marker and turn a retryable outage into quarantine.
		return nil, status.Error(codes.Unavailable, "gNMI response preflight: temporary identity backend failure")
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
	target := runtimeTestTarget(endpoint, material.caFile, gnmiModeStream, runtimeTestMapping("system/value", "runtime.retryable.value"))
	err := runtimeTestServeTarget(t, target)
	require.Error(t, err)
	var compatibility *sharedGNMICompatibilityError
	assert.NotErrorAs(t, err, &compatibility, "temporary identity Get failure must enter reconnect backoff, not quarantine")
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Equal(t, 1, fake.snapshot().getCalls)
	assert.Zero(t, fake.snapshot().identitySubscribeCalls)
	assert.Zero(t, fake.snapshot().subscribeCalls)
}

func TestSharedGNMIInvalidArgumentAuthenticationFailuresRemainRetryable(t *testing.T) {
	material := runtimeTestTLSMaterial(t)

	for _, test := range []struct {
		name      string
		configure func(*runtimeTestGNMIServer)
	}{
		{
			name: "Capabilities",
			configure: func(fake *runtimeTestGNMIServer) {
				fake.capabilities = func(context.Context) (*gnmipb.CapabilityResponse, error) {
					return nil, status.Error(codes.InvalidArgument, "authentication failed: runtime-secret")
				}
			},
		},
		{
			name: "identity Get",
			configure: func(fake *runtimeTestGNMIServer) {
				fake.get = func(context.Context, *gnmipb.GetRequest) (*gnmipb.GetResponse, error) {
					return nil, status.Error(codes.InvalidArgument, "authentication failed: runtime-secret")
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &runtimeTestGNMIServer{}
			test.configure(fake)
			endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
			target := runtimeTestTarget(endpoint, material.caFile, gnmiModeStream, runtimeTestMapping("system/value", "runtime.auth.value"))

			err := runtimeTestServeTarget(t, target)
			require.Error(t, err)
			var compatibility *sharedGNMICompatibilityError
			assert.NotErrorAs(t, err, &compatibility, "authentication failure must retry instead of quarantining the target")
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.True(t, isSharedGNMIAuthenticationError(err))
			assert.NotContains(t, sanitizedGNMIRPCError(err).Error(), "runtime-secret")
			assert.Zero(t, fake.snapshot().subscribeCalls)
		})
	}
}

func runtimeTestASRRequiredModels() []*gnmipb.ModelData {
	return []*gnmipb.ModelData{{Name: "Cisco-IOS-XR-install-oper"}, {Name: runtimeTestOrigin}}
}

func runtimeTestTelemetryPreflightReason(t *testing.T, reader *metric.ManualReader, reason string) int64 {
	t.Helper()
	var resourceMetrics metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &resourceMetrics))
	var total int64
	for _, scope := range resourceMetrics.ScopeMetrics {
		for _, instrument := range scope.Metrics {
			if instrument.Name != "otelcol_ciscoosreceiver_gnmi_preflight_failures" {
				continue
			}
			sum, ok := instrument.Data.(metricdata.Sum[int64])
			require.True(t, ok)
			for _, point := range sum.DataPoints {
				value, ok := point.Attributes.Value(attribute.Key("cisco.gnmi.reason"))
				if ok && value.AsString() == reason {
					total += point.Value
				}
			}
		}
	}
	return total
}

func runtimeTestXEHardwareIdentityResponse(model string) *gnmipb.GetResponse {
	return &gnmipb.GetResponse{Notification: []*gnmipb.Notification{{
		Timestamp: time.Now().UnixNano(),
		Prefix:    &gnmipb.Path{Origin: builtinGNMIOriginRFC7951},
		Update: []*gnmipb.Update{{
			Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{
				{Name: "Cisco-IOS-XE-device-hardware-oper:device-hardware-data"},
				{Name: "device-hardware"},
				{Name: "device-inventory", Key: map[string]string{"hw-type": "hw-type-chassis", "hw-dev-index": "0"}},
				{Name: "part-number"},
			}},
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: model}},
		}},
	}}}
}

func runtimeTestXEVersionIdentityResponse(version string) *gnmipb.GetResponse {
	return runtimeTestXEVersionIdentityResponseWithExtension(version, "0")
}

func runtimeTestXEVersionIdentityResponseWithExtension(version, extension string) *gnmipb.GetResponse {
	return &gnmipb.GetResponse{Notification: []*gnmipb.Notification{{
		Timestamp: time.Now().UnixNano(),
		Prefix:    &gnmipb.Path{Origin: builtinGNMIOriginRFC7951},
		Update: []*gnmipb.Update{{
			Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{
				{Name: "Cisco-IOS-XE-install-oper:install-oper-data"},
				{Name: "install-location-information", Key: map[string]string{
					"fru": "fru-rp", "slot": "0", "bay": "0", "chassis": "0",
				}},
				{Name: "install-version-info", Key: map[string]string{"version": version, "version-extension": extension}},
				{Name: "current"},
			}},
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "install-version-state-provisioned-committed"}},
		}},
	}}}
}
