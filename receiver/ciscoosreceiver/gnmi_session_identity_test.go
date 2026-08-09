// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"math"
	"net"
	"sync/atomic"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

func TestSharedGNMICapabilityFingerprintIgnoresWireOrder(t *testing.T) {
	left := &gnmipb.CapabilityResponse{
		GNMIVersion:        "0.10.0",
		SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON, gnmipb.Encoding_JSON_IETF},
		SupportedModels: []*gnmipb.ModelData{
			{Name: "openconfig-platform", Organization: "OpenConfig", Version: "2024-05-13"},
			{Name: "Cisco-IOS-XR-install-oper", Organization: "Cisco", Version: "2025-01-01"},
		},
	}
	right := &gnmipb.CapabilityResponse{
		GNMIVersion:        "0.10.0",
		SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON_IETF, gnmipb.Encoding_JSON},
		SupportedModels: []*gnmipb.ModelData{
			{Name: "Cisco-IOS-XR-install-oper", Organization: "Cisco", Version: "2025-01-01"},
			{Name: "openconfig-platform", Organization: "OpenConfig", Version: "2024-05-13"},
		},
	}

	assert.Equal(t, sharedGNMICapabilityFingerprint(left), sharedGNMICapabilityFingerprint(right))
	right.SupportedModels[0].Version = "2026-01-01"
	assert.NotEqual(t, sharedGNMICapabilityFingerprint(left), sharedGNMICapabilityFingerprint(right))
}

func TestSharedGNMIEligiblePlatformsUsesModelsOnlyAsFilter(t *testing.T) {
	capabilities := &gnmipb.CapabilityResponse{SupportedModels: []*gnmipb.ModelData{{Name: "Cisco-IOS-XE-install-oper"}}}
	platforms, err := sharedGNMIEligiblePlatforms("", capabilities)
	require.NoError(t, err)
	assert.Equal(t, []string{gnmiPlatformIOSXE}, platforms)

	platforms, err = sharedGNMIEligiblePlatforms(gnmiPlatformNXOS, capabilities)
	require.NoError(t, err)
	assert.Equal(t, []string{gnmiPlatformNXOS, gnmiPlatformIOSXE}, platforms,
		"SupportedModels must not suppress the configured probe; subscribed identity proves the mismatch")

	platforms, err = sharedGNMIEligiblePlatforms("", &gnmipb.CapabilityResponse{
		SupportedModels: []*gnmipb.ModelData{{Name: "openconfig-platform"}},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{gnmiPlatformIOSXE, gnmiPlatformIOSXR, gnmiPlatformNXOS}, platforms,
		"an OpenConfig-only model list must not be treated as product or OS proof")
}

func TestSharedGNMIIdentityProbesUsePublishedIOSXEListKeys(t *testing.T) {
	probes := sharedGNMIIdentityProbes(gnmiPlatformIOSXE)
	require.Len(t, probes, 1)
	assert.Equal(t, []internalgnmi.JSONListKeySpec{
		{Origin: builtinGNMIOriginRFC7951, Elements: []string{"Cisco-IOS-XE-device-hardware-oper:device-hardware-data", "device-hardware", "device-inventory"}, Keys: []string{"hw-type", "hw-dev-index"}},
		{Origin: builtinGNMIOriginRFC7951, Elements: []string{"Cisco-IOS-XE-install-oper:install-oper-data", "install-location-information"}, Keys: []string{"fru", "slot", "bay", "chassis"}},
		{Origin: builtinGNMIOriginRFC7951, Elements: []string{"Cisco-IOS-XE-install-oper:install-oper-data", "install-location-information", "install-version-info"}, Keys: []string{"version", "version-extension"}},
	}, probes[0].ListSchema)
}

func TestExecuteSharedGNMIIdentityProbeSubscribeOnce(t *testing.T) {
	requests := make(chan *gnmipb.SubscribeRequest, 1)
	server := &identityProbeTestServer{}
	server.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		requests <- request
		if err := stream.Send(identityProbeUpdateResponse(identityProbeIOSXRNotification(true))); err != nil {
			return err
		}
		return stream.Send(&gnmipb.SubscribeResponse{
			Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
		})
	}
	client := startIdentityProbeTestServer(t, server)
	admission := newGNMIResponseAdmission()
	probe := sharedGNMIIdentityProbes(gnmiPlatformIOSXR)[0]

	identity, err := executeSharedGNMIIdentityProbe(
		t.Context(), identityProbeTarget(time.Second), client, probe, gnmipb.Encoding_JSON_IETF, admission,
	)
	require.NoError(t, err)
	assert.Equal(t, "NCS-5501-SE", identity.ModelIdentifier)
	assert.Equal(t, "25.2.21", identity.SoftwareVersion)
	assert.Equal(t, "FOC1234", identity.SerialNumber)
	assert.Equal(t, gnmiPlatformIOSXR, identity.OSFamily)

	request := <-requests
	require.NotNil(t, request.GetSubscribe())
	assert.Equal(t, gnmipb.SubscriptionList_ONCE, request.GetSubscribe().GetMode())
	assert.Equal(t, gnmipb.Encoding_JSON_IETF, request.GetSubscribe().GetEncoding())
	assert.Equal(t, "Cisco-IOS-XR-install-oper", request.GetSubscribe().GetPrefix().GetOrigin())
	assert.Equal(t, int64(1), server.subscribeCalls.Load())
	assert.Zero(t, server.capabilitiesCalls.Load())
	assert.Zero(t, server.getCalls.Load(), "identity bootstrap must never call Get")
	assert.Zero(t, server.setCalls.Load(), "identity bootstrap must never call Set")
	assert.Empty(t, admission.slots)
}

func TestExecuteSharedGNMIIdentityProbeWaitsForEOFAndTimesOut(t *testing.T) {
	server := &identityProbeTestServer{}
	server.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(identityProbeUpdateResponse(identityProbeIOSXRNotification(true))); err != nil {
			return err
		}
		if err := stream.Send(&gnmipb.SubscribeResponse{
			Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
		}); err != nil {
			return err
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}
	client := startIdentityProbeTestServer(t, server)
	admission := newGNMIResponseAdmission()
	target := identityProbeTarget(25 * time.Millisecond)

	identity, err := executeSharedGNMIIdentityProbe(
		t.Context(), target, client, sharedGNMIIdentityProbes(gnmiPlatformIOSXR)[0], gnmipb.Encoding_JSON_IETF, admission,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, sharedGNMIDeviceIdentity{}, identity, "a synchronized but unclosed ONCE stream must not publish partial identity")
	assert.Zero(t, server.getCalls.Load())
	assert.Zero(t, server.setCalls.Load())
	assert.Empty(t, admission.slots)
}

func TestExecuteSharedGNMIIdentityProbeRejectsMalformedSchemaWithoutPartialResult(t *testing.T) {
	server := &identityProbeTestServer{}
	server.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(identityProbeUpdateResponse(identityProbeNXChassisNotification())); err != nil {
			return err
		}
		return stream.Send(identityProbeUpdateResponse(&gnmipb.Notification{
			Prefix: &gnmipb.Path{Origin: "openconfig-platform"},
			Update: []*gnmipb.Update{{
				Path: &gnmipb.Path{},
				Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{
					"components":{"component":[{"state":{"type":"CHASSIS","model-name":"N9K-BAD","software-version":"10.6(2)F"}}]}
				}`)}},
			}},
		}))
	}
	client := startIdentityProbeTestServer(t, server)
	admission := newGNMIResponseAdmission()

	identity, err := executeSharedGNMIIdentityProbe(
		t.Context(), identityProbeTarget(time.Second), client, sharedGNMIIdentityProbes(gnmiPlatformNXOS)[0], gnmipb.Encoding_JSON_IETF, admission,
	)
	require.ErrorContains(t, err, `required list key "name" is missing`)
	assert.Equal(t, sharedGNMIDeviceIdentity{}, identity)
	assert.Zero(t, server.getCalls.Load())
	assert.Zero(t, server.setCalls.Load())
	assert.Empty(t, admission.slots)
}

func TestExecuteSharedGNMIIdentityProbeRejectsMissingIdentity(t *testing.T) {
	server := &identityProbeTestServer{}
	server.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(identityProbeUpdateResponse(identityProbeIOSXRNotification(false))); err != nil {
			return err
		}
		return stream.Send(&gnmipb.SubscribeResponse{
			Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
		})
	}
	client := startIdentityProbeTestServer(t, server)
	admission := newGNMIResponseAdmission()

	identity, err := executeSharedGNMIIdentityProbe(
		t.Context(), identityProbeTarget(time.Second), client, sharedGNMIIdentityProbes(gnmiPlatformIOSXR)[0], gnmipb.Encoding_JSON, admission,
	)
	require.ErrorContains(t, err, "missing software version")
	assert.Equal(t, sharedGNMIDeviceIdentity{}, identity)
	assert.Zero(t, server.getCalls.Load())
	assert.Zero(t, server.setCalls.Load())
	assert.Empty(t, admission.slots)
}

func TestExecuteSharedGNMIIdentityProbeRejectsOffPathIdentityInjection(t *testing.T) {
	server := &identityProbeTestServer{}
	server.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		notification := identityProbeIOSXRNotification(true)
		notification.Update = append(notification.Update,
			identityProbeStringUpdate([]string{"unrequested", "label"}, "99.9.9"))
		if err := stream.Send(identityProbeUpdateResponse(notification)); err != nil {
			return err
		}
		return stream.Send(&gnmipb.SubscribeResponse{
			Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
		})
	}
	client := startIdentityProbeTestServer(t, server)
	identity, err := executeSharedGNMIIdentityProbe(
		t.Context(), identityProbeTarget(time.Second), client,
		sharedGNMIIdentityProbes(gnmiPlatformIOSXR)[0], gnmipb.Encoding_JSON, newGNMIResponseAdmission(),
	)
	require.ErrorContains(t, err, "outside every requested probe path")
	assert.Equal(t, sharedGNMIDeviceIdentity{}, identity)
}

func TestExecuteSharedGNMIIdentityProbeRejectsOffPathUnmappedUpdate(t *testing.T) {
	server := &identityProbeTestServer{}
	server.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		notification := identityProbeIOSXRNotification(true)
		notification.Update = append(notification.Update, &gnmipb.Update{
			Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "unrequested"}, {Name: "value"}}},
			Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_DoubleVal{DoubleVal: math.NaN()}},
		})
		return stream.Send(identityProbeUpdateResponse(notification))
	}
	client := startIdentityProbeTestServer(t, server)
	identity, err := executeSharedGNMIIdentityProbe(
		t.Context(), identityProbeTarget(time.Second), client,
		sharedGNMIIdentityProbes(gnmiPlatformIOSXR)[0], gnmipb.Encoding_JSON, newGNMIResponseAdmission(),
	)
	require.ErrorContains(t, err, "outside every requested probe path")
	assert.Equal(t, sharedGNMIDeviceIdentity{}, identity)
}

func TestExecuteSharedGNMIIdentityProbeRejectsUnsupportedInScopeValue(t *testing.T) {
	server := &identityProbeTestServer{}
	server.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		notification := identityProbeIOSXRNotification(true)
		notification.Update = append(notification.Update, &gnmipb.Update{
			Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "install"}, {Name: "version"}, {Name: "unsupported"}}},
			Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_DoubleVal{DoubleVal: math.Inf(1)}},
		})
		return stream.Send(identityProbeUpdateResponse(notification))
	}
	client := startIdentityProbeTestServer(t, server)
	identity, err := executeSharedGNMIIdentityProbe(
		t.Context(), identityProbeTarget(time.Second), client,
		sharedGNMIIdentityProbes(gnmiPlatformIOSXR)[0], gnmipb.Encoding_JSON, newGNMIResponseAdmission(),
	)
	require.ErrorContains(t, err, "unsupported or non-scalar values")
	assert.Equal(t, sharedGNMIDeviceIdentity{}, identity)
}

func TestExecuteSharedGNMIIdentityProbeRejectsAncestorDelete(t *testing.T) {
	server := &identityProbeTestServer{}
	server.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		return stream.Send(identityProbeUpdateResponse(&gnmipb.Notification{
			Prefix: &gnmipb.Path{Origin: "Cisco-IOS-XR-install-oper"},
			Delete: []*gnmipb.Path{{Elem: []*gnmipb.PathElem{{Name: "install"}}}},
		}))
	}
	client := startIdentityProbeTestServer(t, server)
	_, err := executeSharedGNMIIdentityProbe(
		t.Context(), identityProbeTarget(time.Second), client,
		sharedGNMIIdentityProbes(gnmiPlatformIOSXR)[0], gnmipb.Encoding_JSON, newGNMIResponseAdmission(),
	)
	require.ErrorContains(t, err, "delete")
	require.ErrorContains(t, err, "outside every requested probe path")
}

func TestExecuteSharedGNMIIdentityProbeRejectsDataAfterSync(t *testing.T) {
	server := &identityProbeTestServer{}
	server.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(identityProbeUpdateResponse(identityProbeIOSXRNotification(true))); err != nil {
			return err
		}
		if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}}); err != nil {
			return err
		}
		return stream.Send(identityProbeUpdateResponse(identityProbeIOSXRNotification(true)))
	}
	client := startIdentityProbeTestServer(t, server)
	identity, err := executeSharedGNMIIdentityProbe(
		t.Context(), identityProbeTarget(time.Second), client,
		sharedGNMIIdentityProbes(gnmiPlatformIOSXR)[0], gnmipb.Encoding_JSON, newGNMIResponseAdmission(),
	)
	require.ErrorContains(t, err, "data after sync_response=true")
	assert.Equal(t, sharedGNMIDeviceIdentity{}, identity)
}

func TestExecuteSharedGNMIIdentityProbeAppliesUpdatesAndDeletesBeforeSync(t *testing.T) {
	tests := []struct {
		name      string
		second    *gnmipb.Notification
		wantModel string
		wantError string
	}{
		{
			name: "last update wins",
			second: &gnmipb.Notification{
				Timestamp: time.Now().Add(time.Second).UnixNano(),
				Prefix:    &gnmipb.Path{Origin: "Cisco-IOS-XR-install-oper"},
				Update:    []*gnmipb.Update{identityProbeStringUpdate([]string{"install", "version", "chassis-pid"}, "NCS-5502")},
			},
			wantModel: "NCS-5502",
		},
		{
			name: "delete removes staged version",
			second: &gnmipb.Notification{
				Timestamp: time.Now().Add(time.Second).UnixNano(),
				Prefix:    &gnmipb.Path{Origin: "Cisco-IOS-XR-install-oper"},
				Delete:    []*gnmipb.Path{{Elem: []*gnmipb.PathElem{{Name: "install"}, {Name: "version"}, {Name: "label"}}}},
			},
			wantError: "missing software version",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := &identityProbeTestServer{}
			server.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
				if _, err := stream.Recv(); err != nil {
					return err
				}
				first := identityProbeIOSXRNotification(true)
				first.Timestamp = time.Now().UnixNano()
				if err := stream.Send(identityProbeUpdateResponse(first)); err != nil {
					return err
				}
				if err := stream.Send(identityProbeUpdateResponse(test.second)); err != nil {
					return err
				}
				return stream.Send(&gnmipb.SubscribeResponse{
					Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
				})
			}
			client := startIdentityProbeTestServer(t, server)
			identity, err := executeSharedGNMIIdentityProbe(
				t.Context(), identityProbeTarget(time.Second), client,
				sharedGNMIIdentityProbes(gnmiPlatformIOSXR)[0], gnmipb.Encoding_JSON, newGNMIResponseAdmission(),
			)
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
				assert.Equal(t, sharedGNMIDeviceIdentity{}, identity)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.wantModel, identity.ModelIdentifier)
		})
	}
}

func TestExtractSharedGNMIDeviceIdentityIOSXESelectsChassisAndActiveVersion(t *testing.T) {
	inventory := func(hardwareType, index string) []internalgnmi.PathElem {
		return []internalgnmi.PathElem{
			{Name: "Cisco-IOS-XE-device-hardware-oper:device-hardware-data"},
			{Name: "device-hardware"},
			{Name: "device-inventory", Keys: map[string]string{"hw-type": hardwareType, "hw-dev-index": index}},
		}
	}
	version := func(value, extension string) []internalgnmi.PathElem {
		return []internalgnmi.PathElem{
			{Name: "Cisco-IOS-XE-install-oper:install-oper-data"},
			{Name: "install-location-information", Keys: map[string]string{"fru": "fru-rp", "slot": "0", "bay": "0", "chassis": "0"}},
			{Name: "install-version-info", Keys: map[string]string{"version": value, "version-extension": extension}},
		}
	}
	points := []internalgnmi.Point{
		identityTestPoint(builtinGNMIOriginRFC7951, inventory("hw-type-chassis", "0"), "part-number", internalgnmi.StringValue("C9300-48UXM")),
		identityTestPoint(builtinGNMIOriginRFC7951, inventory("hw-type-chassis", "0"), "serial-number", internalgnmi.StringValue("FCW1234")),
		identityTestPoint(builtinGNMIOriginRFC7951, inventory("hw-type-pim", "1"), "part-number", internalgnmi.StringValue("C9300-NM-8X")),
		identityTestPoint(builtinGNMIOriginRFC7951, inventory("hw-type-pim", "1"), "serial-number", internalgnmi.StringValue("MODULE1")),
		identityTestPoint(builtinGNMIOriginRFC7951, version("17.12.4", "100"), "version", internalgnmi.StringValue("17.12.4")),
		identityTestPoint(builtinGNMIOriginRFC7951, version("17.15.5", "200"), "version", internalgnmi.StringValue("17.15.5")),
		identityTestPoint(builtinGNMIOriginRFC7951, version("17.15.5", "200"), "current", internalgnmi.StringValue("install-version-state-provisioned-committed")),
	}
	identity, err := extractSharedGNMIDeviceIdentity(gnmiPlatformIOSXE, points)
	require.NoError(t, err)
	assert.Equal(t, "C9300-48UXM", identity.ModelIdentifier)
	assert.Equal(t, "17.15.5", identity.SoftwareVersion)
	assert.Equal(t, "FCW1234", identity.SerialNumber)

	points = points[:len(points)-1]
	_, err = extractSharedGNMIDeviceIdentity(gnmiPlatformIOSXE, points)
	require.ErrorContains(t, err, "ambiguous software version without an active marker")
}

func TestExtractSharedGNMIDeviceIdentityIOSXERejectsInferredChassisAndConflictingSerial(t *testing.T) {
	versionElements := []internalgnmi.PathElem{
		{Name: "Cisco-IOS-XE-install-oper:install-oper-data"},
		{Name: "install-location-information", Keys: map[string]string{"fru": "fru-rp", "slot": "0", "bay": "0", "chassis": "0"}},
		{Name: "install-version-info", Keys: map[string]string{"version": "17.15.5", "version-extension": "200"}},
	}
	inventory := func(hardwareType string) []internalgnmi.PathElem {
		return []internalgnmi.PathElem{
			{Name: "Cisco-IOS-XE-device-hardware-oper:device-hardware-data"},
			{Name: "device-hardware"},
			{Name: "device-inventory", Keys: map[string]string{"hw-type": hardwareType, "hw-dev-index": "0"}},
		}
	}
	baseVersion := []internalgnmi.Point{
		identityTestPoint(builtinGNMIOriginRFC7951, versionElements, "version", internalgnmi.StringValue("17.15.5")),
		identityTestPoint(builtinGNMIOriginRFC7951, versionElements, "current", internalgnmi.StringValue("install-version-state-provisioned-committed")),
	}

	points := append([]internalgnmi.Point{
		identityTestPoint(builtinGNMIOriginRFC7951, inventory("hw-type-pim"), "part-number", internalgnmi.StringValue("CHASSIS-IN-DESCRIPTION")),
		identityTestPoint(builtinGNMIOriginRFC7951, inventory("hw-type-pim"), "hw-description", internalgnmi.StringValue("chassis-like module")),
	}, baseVersion...)
	_, err := extractSharedGNMIDeviceIdentity(gnmiPlatformIOSXE, points)
	require.ErrorContains(t, err, "exactly one explicitly identified chassis")

	points = append([]internalgnmi.Point{
		identityTestPoint(builtinGNMIOriginRFC7951, inventory("hw-type-chassis"), "part-number", internalgnmi.StringValue("C9300-48UXM")),
		identityTestPoint(builtinGNMIOriginRFC7951, inventory("hw-type-chassis"), "serial-number", internalgnmi.StringValue("SERIAL-A")),
		identityTestPoint(builtinGNMIOriginRFC7951, inventory("hw-type-chassis"), "serial-number", internalgnmi.StringValue("SERIAL-B")),
	}, baseVersion...)
	_, err = extractSharedGNMIDeviceIdentity(gnmiPlatformIOSXE, points)
	require.ErrorContains(t, err, "ambiguous serial identity")
}

func TestCompactSharedGNMIIdentityTombstones(t *testing.T) {
	root, err := internalgnmi.ParsePath("target", "origin", "install/version")
	require.NoError(t, err)
	leaf, err := internalgnmi.ParsePath("target", "origin", "install/version/label")
	require.NoError(t, err)
	now := time.Now()

	tombstones := compactSharedGNMIIdentityTombstones(nil, sharedGNMIIdentityTombstone{selector: leaf, timestamp: now})
	tombstones = compactSharedGNMIIdentityTombstones(tombstones, sharedGNMIIdentityTombstone{selector: root, timestamp: now.Add(time.Second)})
	require.Len(t, tombstones, 1)
	assert.Equal(t, root.Key(), tombstones[0].selector.Key())

	tombstones = compactSharedGNMIIdentityTombstones(tombstones, sharedGNMIIdentityTombstone{selector: leaf, timestamp: now})
	require.Len(t, tombstones, 1, "an older descendant is dominated by the newer ancestor")
}

func TestExtractSharedGNMIDeviceIdentityIOSXR(t *testing.T) {
	points := []internalgnmi.Point{
		identityTestPoint("Cisco-IOS-XR-install-oper", []internalgnmi.PathElem{{Name: "install"}, {Name: "version"}}, "chassis-pid", internalgnmi.StringValue("NCS-5501-SE")),
		identityTestPoint("Cisco-IOS-XR-install-oper", []internalgnmi.PathElem{{Name: "install"}, {Name: "version"}}, "label", internalgnmi.StringValue("25.2.21")),
		identityTestPoint("Cisco-IOS-XR-install-oper", []internalgnmi.PathElem{{Name: "install"}, {Name: "version"}}, "serial-number", internalgnmi.StringValue("FOC1234")),
	}

	identity, err := extractSharedGNMIDeviceIdentity(gnmiPlatformIOSXR, points)
	require.NoError(t, err)
	assert.True(t, identity.validForCatalogSelection())
	assert.Equal(t, "NCS-5501-SE", identity.ModelIdentifier)
	assert.Equal(t, "25.2.21", identity.SoftwareVersion)
	assert.Equal(t, "FOC1234", identity.SerialNumber)
	assert.Equal(t, "Cisco", identity.Manufacturer)
}

func TestExtractSharedGNMIDeviceIdentityNXOSRequiresOneChassis(t *testing.T) {
	component := []internalgnmi.PathElem{
		{Name: "components"},
		{Name: "component", Keys: map[string]string{"name": "Chassis"}},
		{Name: "state"},
	}
	points := []internalgnmi.Point{
		identityTestPoint("openconfig-platform", component, "type", internalgnmi.StringValue("openconfig-platform-types:CHASSIS")),
		identityTestPoint("openconfig-platform", component, "model-name", internalgnmi.StringValue("N9K-C93180YC-FX3")),
		identityTestPoint("openconfig-platform", component, "software-version", internalgnmi.StringValue("10.6(2)F")),
		identityTestPoint("openconfig-platform", component, "serial-no", internalgnmi.StringValue("SAL1234")),
	}

	identity, err := extractSharedGNMIDeviceIdentity(gnmiPlatformNXOS, points)
	require.NoError(t, err)
	assert.Equal(t, "N9K-C93180YC-FX3", identity.ModelIdentifier)
	assert.Equal(t, "10.6(2)F", identity.SoftwareVersion)
	assert.Equal(t, "SAL1234", identity.SerialNumber)

	duplicate := make([]internalgnmi.Point, len(points))
	copy(duplicate, points)
	for index := range duplicate {
		duplicate[index].Series.Elements = append([]internalgnmi.PathElem(nil), duplicate[index].Series.Elements...)
		duplicate[index].Series.Elements[1] = internalgnmi.PathElem{Name: "component", Keys: map[string]string{"name": "Chassis-2"}}
	}
	_, err = extractSharedGNMIDeviceIdentity(gnmiPlatformNXOS, append(points, duplicate...))
	require.ErrorContains(t, err, "exactly one complete chassis")
}

func TestExtractSharedGNMIDeviceIdentityRejectsAmbiguousRequiredLeaves(t *testing.T) {
	points := []internalgnmi.Point{
		identityTestPoint("Cisco-IOS-XR-install-oper", []internalgnmi.PathElem{{Name: "install"}}, "chassis-pid", internalgnmi.StringValue("NCS-5501-SE")),
		identityTestPoint("Cisco-IOS-XR-install-oper", []internalgnmi.PathElem{{Name: "install"}}, "label", internalgnmi.StringValue("25.2.21")),
		identityTestPoint("Cisco-IOS-XR-install-oper", []internalgnmi.PathElem{{Name: "install"}}, "label", internalgnmi.StringValue("25.2.2")),
	}
	_, err := extractSharedGNMIDeviceIdentity(gnmiPlatformIOSXR, points)
	require.ErrorContains(t, err, "ambiguous software version")
}

func identityTestPoint(origin string, elements []internalgnmi.PathElem, leaf string, value internalgnmi.Value) internalgnmi.Point {
	return internalgnmi.Point{Series: internalgnmi.Series{Target: "identity-test", Origin: origin, Elements: elements, Leaf: leaf}, Value: value}
}

type identityProbeTestServer struct {
	gnmipb.UnimplementedGNMIServer

	capabilitiesCalls atomic.Int64
	subscribeCalls    atomic.Int64
	getCalls          atomic.Int64
	setCalls          atomic.Int64
	subscribe         func(grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error
}

func (s *identityProbeTestServer) Capabilities(context.Context, *gnmipb.CapabilityRequest) (*gnmipb.CapabilityResponse, error) {
	s.capabilitiesCalls.Add(1)
	return nil, status.Error(codes.Unimplemented, "Capabilities forbidden in identity probe test")
}

func (s *identityProbeTestServer) Subscribe(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
	s.subscribeCalls.Add(1)
	if s.subscribe == nil {
		return status.Error(codes.Unimplemented, "Subscribe behavior not configured")
	}
	return s.subscribe(stream)
}

func (s *identityProbeTestServer) Get(context.Context, *gnmipb.GetRequest) (*gnmipb.GetResponse, error) {
	s.getCalls.Add(1)
	return nil, status.Error(codes.Unimplemented, "Get forbidden in identity probe test")
}

func (s *identityProbeTestServer) Set(context.Context, *gnmipb.SetRequest) (*gnmipb.SetResponse, error) {
	s.setCalls.Add(1)
	return nil, status.Error(codes.PermissionDenied, "Set forbidden in identity probe test")
}

func startIdentityProbeTestServer(t *testing.T, server *identityProbeTestServer) gnmipb.GNMIClient {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	gnmipb.RegisterGNMIServer(grpcServer, server)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})

	connection, err := grpc.NewClient(
		"passthrough:///identity-probe-test",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, connection.Close()) })
	return gnmipb.NewGNMIClient(connection)
}

func identityProbeTarget(syncTimeout time.Duration) GNMITargetConfig {
	return GNMITargetConfig{
		Name:               "identity-probe-target",
		Platform:           gnmiPlatformIOSXR,
		MaxRecvMsgSizeMiB:  1,
		SyncTimeout:        syncTimeout,
		EncodingPreference: []string{gnmiEncodingJSONIETF, gnmiEncodingJSON},
	}
}

func identityProbeUpdateResponse(notification *gnmipb.Notification) *gnmipb.SubscribeResponse {
	return &gnmipb.SubscribeResponse{
		Response: &gnmipb.SubscribeResponse_Update{Update: notification},
	}
}

func identityProbeIOSXRNotification(includeVersion bool) *gnmipb.Notification {
	updates := []*gnmipb.Update{
		identityProbeStringUpdate([]string{"install", "version", "chassis-pid"}, "NCS-5501-SE"),
		identityProbeStringUpdate([]string{"install", "version", "serial-number"}, "FOC1234"),
	}
	if includeVersion {
		updates = append(updates, identityProbeStringUpdate([]string{"install", "version", "label"}, "25.2.21"))
	}
	return &gnmipb.Notification{
		Timestamp: time.Now().UnixNano(),
		Prefix:    &gnmipb.Path{Origin: "Cisco-IOS-XR-install-oper"},
		Update:    updates,
	}
}

func identityProbeNXChassisNotification() *gnmipb.Notification {
	path := func(leaf string) *gnmipb.Path {
		return &gnmipb.Path{Elem: []*gnmipb.PathElem{
			{Name: "components"},
			{Name: "component", Key: map[string]string{"name": "Chassis"}},
			{Name: "state"},
			{Name: leaf},
		}}
	}
	return &gnmipb.Notification{
		Timestamp: time.Now().UnixNano(),
		Prefix:    &gnmipb.Path{Origin: "openconfig-platform"},
		Update: []*gnmipb.Update{
			{Path: path("type"), Val: identityProbeStringValue("openconfig-platform-types:CHASSIS")},
			{Path: path("model-name"), Val: identityProbeStringValue("N9K-C93180YC-FX3")},
			{Path: path("software-version"), Val: identityProbeStringValue("10.6(2)F")},
		},
	}
}

func identityProbeStringUpdate(elements []string, value string) *gnmipb.Update {
	path := &gnmipb.Path{Elem: make([]*gnmipb.PathElem, len(elements))}
	for index, element := range elements {
		path.Elem[index] = &gnmipb.PathElem{Name: element}
	}
	return &gnmipb.Update{Path: path, Val: identityProbeStringValue(value)}
}

func identityProbeStringValue(value string) *gnmipb.TypedValue {
	return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: value}}
}
