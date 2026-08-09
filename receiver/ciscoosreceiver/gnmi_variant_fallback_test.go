// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"fmt"
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

func TestSharedGNMIVariantFallbackRejectsOpenConfigThenSelectsNative(t *testing.T) {
	harness := newRuntimeTestVariantHarness(t, true, 1, func(paths []string) error {
		if runtimeTestContains(paths, "openconfig/component/state/value") {
			return status.Error(codes.InvalidArgument, "OpenConfig path unsupported")
		}
		return nil
	})

	selected, err := harness.receiver.selectSharedGNMIStreamVariants(
		t.Context(), harness.runtime, harness.client, harness.streams,
	)
	require.NoError(t, err)
	require.Len(t, selected, 1)
	assert.Empty(t, selected[0].variantFallbacks)
	assert.Equal(t, []string{"native/component/state/value"}, runtimeTestSharedPathStrings(selected[0].Paths))
	require.Len(t, selected[0].Mappings, 1)
	assert.Equal(t, "native", selected[0].Mappings[0].Mapping.Source.Origin)
	require.Len(t, selected[0].JSONListKeySpecs, 1)
	assert.Equal(t, "native", selected[0].JSONListKeySpecs[0].Origin)
	assert.Equal(t, 1, selected[0].registry.Len())

	requests := harness.server.snapshot().requests
	require.Len(t, requests, 2)
	assert.Equal(t, []string{"openconfig/component/state/value"}, runtimeTestSubscribedPaths(requests[0]))
	assert.Equal(t, []string{"native/component/state/value"}, runtimeTestSubscribedPaths(requests[1]))
	assert.True(t, harness.runtime.variantIsolated("variant-test", "state.values", "openconfig"))
}

func TestSharedGNMIVariantFallbackStopsAfterOpenConfigSuccess(t *testing.T) {
	harness := newRuntimeTestVariantHarness(t, true, 1, func([]string) error { return nil })
	harness.runtime.isolateVariant("variant-test", "state.values", "native")
	require.True(t, harness.runtime.variantIsolated("variant-test", "state.values", "native"))

	selected, err := harness.receiver.selectSharedGNMIStreamVariants(
		t.Context(), harness.runtime, harness.client, harness.streams,
	)
	require.NoError(t, err)
	require.Len(t, selected, 1)
	assert.Equal(t, []string{"openconfig/component/state/value"}, runtimeTestSharedPathStrings(selected[0].Paths))
	require.Len(t, selected[0].Mappings, 1)
	assert.Equal(t, "openconfig", selected[0].Mappings[0].Mapping.Source.Origin)
	assert.False(t, harness.runtime.variantIsolated("variant-test", "state.values", "native"),
		"a stale lower-priority failure must not force a reconnect while the preferred variant is active")

	requests := harness.server.snapshot().requests
	require.Len(t, requests, 1, "a successful preferred variant must prevent probing the native fallback")
	assert.Equal(t, []string{"openconfig/component/state/value"}, runtimeTestSubscribedPaths(requests[0]))
}

func TestSharedGNMIVariantFallbackExhaustionRespectsRequiredAndOptional(t *testing.T) {
	for _, required := range []bool{true, false} {
		t.Run(fmt.Sprintf("required=%t", required), func(t *testing.T) {
			harness := newRuntimeTestVariantHarness(t, required, 1, func([]string) error {
				return status.Error(codes.Unimplemented, "variant unsupported")
			})

			selected, err := harness.receiver.selectSharedGNMIStreamVariants(
				t.Context(), harness.runtime, harness.client, harness.streams,
			)
			require.NoError(t, err)
			if required {
				require.Len(t, selected, 1)
				assert.True(t, selected[0].Required)
				assert.NotEmpty(t, selected[0].variantFallbacks, "required exhaustion remains a dormant readiness entry")
				assert.Nil(t, selected[0].registry, "a dormant plan must not own an active decoder")
			} else {
				assert.Empty(t, selected, "optional exhaustion degrades only the affected path set")
			}
			assert.True(t, harness.runtime.variantIsolated("variant-test", "state.values", "openconfig"))
			assert.True(t, harness.runtime.variantIsolated("variant-test", "state.values", "native"))
			require.Len(t, harness.server.snapshot().requests, 2)

			selected, err = harness.receiver.selectSharedGNMIStreamVariants(
				t.Context(), harness.runtime, harness.client, harness.streams,
			)
			require.NoError(t, err)
			if required {
				require.Len(t, selected, 1)
			} else {
				assert.Empty(t, selected)
			}
			assert.Len(t, harness.server.snapshot().requests, 2, "the negative cache must suppress repeated probes")
		})
	}
}

func TestSharedGNMIVariantFallbackKeepsMultiPathVariantsIndivisible(t *testing.T) {
	harness := newRuntimeTestVariantHarness(t, true, 2, func(paths []string) error {
		if runtimeTestContains(paths, "openconfig/component/state/value") {
			return status.Error(codes.InvalidArgument, "OpenConfig path set unsupported")
		}
		return nil
	})

	selected, err := harness.receiver.selectSharedGNMIStreamVariants(
		t.Context(), harness.runtime, harness.client, harness.streams,
	)
	require.NoError(t, err)
	require.Len(t, selected, 1)
	assert.Equal(t, []string{
		"native/component/state/companion",
		"native/component/state/value",
	}, runtimeTestSharedPathStrings(selected[0].Paths))

	requests := harness.server.snapshot().requests
	require.Len(t, requests, 2)
	for _, request := range requests {
		assert.Len(t, runtimeTestSubscribedPaths(request), 2, "no probe may split an indivisible path-set variant")
	}
	assert.Equal(t, []string{
		"openconfig/component/state/companion",
		"openconfig/component/state/value",
	}, runtimeTestSubscribedPaths(requests[0]))
	assert.Equal(t, []string{
		"native/component/state/companion",
		"native/component/state/value",
	}, runtimeTestSubscribedPaths(requests[1]))
}

type runtimeTestVariantHarness struct {
	receiver *sharedGNMIReceiver
	runtime  *sharedGNMITargetRuntime
	client   gnmipb.GNMIClient
	streams  []sharedGNMIRuntimeStream
	server   *runtimeTestGNMIServer
}

func newRuntimeTestVariantHarness(
	t *testing.T,
	required bool,
	pathCount int,
	result func([]string) error,
) runtimeTestVariantHarness {
	t.Helper()
	material := runtimeTestTLSMaterial(t)
	server := &runtimeTestGNMIServer{}
	server.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		server.recordRequest(request)
		if err := result(runtimeTestSubscribedPaths(request)); err != nil {
			return err
		}
		return stream.Send(&gnmipb.SubscribeResponse{
			Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
		})
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, server, material.serverTLS(false))
	target := runtimeTestTarget(
		endpoint,
		material.caFile,
		gnmiModeStream,
		runtimeTestMapping("placeholder/value", "runtime.variant.placeholder"),
	).withDefaults()
	target.Platform = gnmiPlatformNXOS
	cache, err := internalgnmi.NewCache(100)
	require.NoError(t, err)
	runtime, err := newSharedGNMITargetRuntime(target, cache)
	require.NoError(t, err)
	runtime.sessionMu.Lock()
	runtime.fingerprint = "variant-pid\x00variant-version\x00variant-models"
	runtime.sessionMu.Unlock()

	definition := runtimeTestVariantProfile(pathCount)
	planned, err := buildBuiltinProfileStreams(gnmiPlatformNXOS, definition, GNMIProfileConfig{
		Required: required, SampleInterval: time.Second, StreamMode: gnmiStreamModeSample,
	})
	require.NoError(t, err)
	require.Len(t, planned, 1)
	require.Len(t, planned[0].VariantFallbacks, 2)
	runtimeStream, err := buildSharedGNMIRuntimeStream(planned[0])
	require.NoError(t, err)
	require.Len(t, runtimeStream.variantFallbacks, 2)
	capabilities := &gnmipb.CapabilityResponse{SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON_IETF}}
	require.NoError(t, negotiateSharedGNMIRuntimeStreamEncodings(target, capabilities, &runtimeStream))

	receiver := &sharedGNMIReceiver{
		settings:          receivertest.NewNopSettings(componentmetadata.Type),
		consumer:          consumertest.NewNop(),
		maxDatapoints:     10,
		maxCachedSeries:   100,
		host:              componenttest.NewNopHost(),
		notificationSlots: make(chan struct{}, sharedGNMIMaxConcurrentDelivery),
		responseAdmission: newGNMIResponseAdmission(),
	}
	conn, err := receiver.dialTarget(t.Context(), target)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	return runtimeTestVariantHarness{
		receiver: receiver,
		runtime:  runtime,
		client:   gnmipb.NewGNMIClient(conn),
		streams:  []sharedGNMIRuntimeStream{runtimeStream},
		server:   server,
	}
}

func runtimeTestVariantProfile(pathCount int) builtinGNMIProfileDefinition {
	definition := builtinGNMIProfileDefinition{Name: "variant-test"}
	for _, variant := range []struct {
		id, preference, origin string
		order                  int
	}{
		{id: "native", preference: "native", origin: "native", order: 2},
		{id: "openconfig", preference: "openconfig", origin: "openconfig", order: 1},
	} {
		leaves := []string{"value"}
		if pathCount > 1 {
			leaves = append(leaves, "companion")
		}
		for _, leaf := range leaves {
			definition.Paths = append(definition.Paths, builtinGNMIPathDefinition{
				ID:               variant.id + "." + leaf,
				Group:            "state",
				PathSetID:        "state.values",
				VariantID:        variant.id,
				VariantOrder:     variant.order,
				SourcePreference: variant.preference,
				Origin:           variant.origin,
				Path:             variant.origin + "/component/state/" + leaf,
				Encodings:        []string{gnmiEncodingJSONIETF},
				StreamModes:      []string{gnmiStreamModeSample},
				JSONListKeys: []internalgnmi.JSONListKeySpec{{
					Origin: variant.origin, Elements: []string{variant.origin, "component"}, Keys: []string{"name"},
				}},
				Mappings: []builtinGNMIMapping{{Mapping: internalgnmi.Mapping{
					Source: internalgnmi.SourcePath{
						Origin: variant.origin, Elements: []string{variant.origin, "component", "state"}, Leaf: leaf,
					},
					Metric: internalgnmi.MetricMetadata{
						Name: "runtime.variant." + leaf, Description: "Runtime variant test metric.", Unit: "1",
					},
					Scale: 1, GaugeType: internalgnmi.GaugeInt,
					KeyAttributes: []internalgnmi.KeyAttribute{{
						Element: "component", Key: "name", Attribute: "component",
					}},
				}}},
			})
		}
	}
	return definition
}

func runtimeTestSharedPathStrings(paths []sharedGNMIPath) []string {
	out := make([]string, len(paths))
	for index := range paths {
		out[index] = paths[index].Path
	}
	return out
}
