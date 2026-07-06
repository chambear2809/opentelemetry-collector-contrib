// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

func TestBuildGNMIIdentityGetRequestUsesBoundedStateShape(t *testing.T) {
	tests := []struct {
		product, version, prefixOrigin, pathOrigin string
		paths                                      []string
		encoding                                   gnmipb.Encoding
	}{
		{
			product: gnmiProductCatalyst9800, version: "17.18.1a", prefixOrigin: builtinGNMIOriginRFC7951,
			paths: []string{
				"Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware/device-inventory",
				"Cisco-IOS-XE-install-oper:install-oper-data/install-location-information/install-version-info",
			},
			encoding: gnmipb.Encoding_JSON_IETF,
		},
		{
			product: gnmiProductASR9000, version: "24.4.1", prefixOrigin: "Cisco-IOS-XR-install-oper",
			paths: []string{"install/version"}, encoding: gnmipb.Encoding_JSON_IETF,
		},
		{
			product: gnmiProductNexus9000, version: "10.6(1)", pathOrigin: "openconfig",
			paths: []string{"components/component/state"}, encoding: gnmipb.Encoding_JSON,
		},
	}

	for _, test := range tests {
		t.Run(test.product, func(t *testing.T) {
			contract, _, err := resolveGNMIProductContract(test.product, test.version)
			require.NoError(t, err)
			require.Len(t, contract.IdentityProbes, len(test.paths))
			for i, probe := range contract.IdentityProbes {
				request, requestErr := buildGNMIIdentityGetRequest(probe, test.encoding)
				require.NoError(t, requestErr)
				assert.Equal(t, gnmipb.GetRequest_STATE, request.GetType())
				assert.Equal(t, test.encoding, request.GetEncoding())
				assert.Equal(t, test.prefixOrigin, request.GetPrefix().GetOrigin())
				require.Len(t, request.GetPath(), 1)
				assert.Equal(t, test.pathOrigin, request.GetPath()[0].GetOrigin())
				assert.Equal(t, test.paths[i], internalgnmi.PathFromProto(request.GetPath()[0]).String())
			}
		})
	}
}

func TestValidateGNMIIdentityProbePointsRejectsOutsideAndCrossProbeData(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9800, "17.18.1a")
	require.NoError(t, err)
	require.Len(t, contract.IdentityProbes, 2)

	hardwarePoints, err := decodeGNMIIdentityGetResponse("xe", runtimeTestXEHardwareIdentityResponse("C9800-40-K9"))
	require.NoError(t, err)
	versionPoints, err := decodeGNMIIdentityGetResponse("xe", runtimeTestXEVersionIdentityResponse("17.18.1a"))
	require.NoError(t, err)
	require.NotEmpty(t, versionPoints)

	require.NoError(t, validateGNMIIdentityProbePoints(contract.IdentityProbes[0], hardwarePoints))
	require.NoError(t, validateGNMIIdentityProbePoints(contract.IdentityProbes[1], versionPoints))
	require.ErrorContains(t, validateGNMIIdentityProbePoints(contract.IdentityProbes[0], versionPoints), "does not match a configured probe path")
	require.ErrorContains(t, validateGNMIIdentityProbePoints(contract.IdentityProbes[1], hardwarePoints), "does not match a configured probe path")

	outside := versionPoints[0]
	outside.Series.Elements = []internalgnmi.PathElem{{Name: "Cisco-IOS-XE-install-oper:install-oper-data"}, {Name: "unrequested-state"}}
	outside.Series.Leaf = "version"
	require.ErrorContains(t, validateGNMIIdentityProbePoints(contract.IdentityProbes[1], []internalgnmi.Point{outside}), "does not match a configured probe path")

	wrongTarget := versionPoints[0]
	wrongTarget.Series.PathTarget = "unexpected-proxy-target"
	require.ErrorContains(t, validateGNMIIdentityProbePoints(contract.IdentityProbes[1], []internalgnmi.Point{wrongTarget}), "does not match a configured probe path")

	wrongOrigin := versionPoints[0]
	wrongOrigin.Series.Origin = "unexpected-origin"
	require.ErrorContains(t, validateGNMIIdentityProbePoints(contract.IdentityProbes[1], []internalgnmi.Point{wrongOrigin}), "does not match a configured probe path")
}

func TestDecodeGNMIIdentityGetResponseRejectsDeleteOperations(t *testing.T) {
	response := runtimeTestXRIdentityResponse("ASR-9904", "24.4.1")
	require.NotEmpty(t, response.Notification)
	response.Notification[0].Delete = []*gnmipb.Path{{Elem: []*gnmipb.PathElem{{Name: "peer-controlled"}}}}

	_, err := decodeGNMIIdentityGetResponse("xr", response)
	require.ErrorContains(t, err, "contains delete operations")
}

func TestExtractIOSXEGNMIIdentityRequiresOneChassisEntry(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9800, "17.18.1a")
	require.NoError(t, err)

	tests := []struct {
		name       string
		hardware   []*gnmipb.GetResponse
		versions   []*gnmipb.GetResponse
		wantModel  string
		wantBuild  string
		wantReason string
	}{
		{
			name: "one chassis", hardware: []*gnmipb.GetResponse{runtimeTestXEHardwareIdentityResponse("C9800-40-K9")},
			versions:  []*gnmipb.GetResponse{runtimeTestXEVersionIdentityResponse("17.18.1a")},
			wantModel: "C9800-40-K9", wantBuild: "17.18.1a",
		},
		{
			name: "documented internal install version", hardware: []*gnmipb.GetResponse{runtimeTestXEHardwareIdentityResponse("C9800-40-K9")},
			versions:  []*gnmipb.GetResponse{runtimeTestXEVersionIdentityResponseWithExtension("17.18.01.0.1186", "1750000000")},
			wantModel: "C9800-40-K9", wantBuild: "17.18.1",
		},
		{
			name:       "matching PID on valid non-chassis inventory is missing",
			hardware:   []*gnmipb.GetResponse{runtimeTestXEHardwareIdentityResponseWithType("C9800-40-K9", "hw-type-fantray")},
			versions:   []*gnmipb.GetResponse{runtimeTestXEVersionIdentityResponse("17.18.1a")},
			wantReason: gnmiPreflightIdentityMissing,
		},
		{
			name: "two chassis models are ambiguous",
			hardware: []*gnmipb.GetResponse{
				runtimeTestXEHardwareIdentityResponse("C9800-40-K9"),
				runtimeTestXEHardwareIdentityResponse("C9800-80-K9"),
			},
			versions:   []*gnmipb.GetResponse{runtimeTestXEVersionIdentityResponse("17.18.1a")},
			wantReason: gnmiPreflightIdentityAmbiguous,
		},
		{
			name: "duplicate chassis entries with the same model are ambiguous",
			hardware: func() []*gnmipb.GetResponse {
				first := runtimeTestXEHardwareIdentityResponse("C9800-40-K9")
				second := runtimeTestXEHardwareIdentityResponse("C9800-40-K9")
				second.Notification[0].Update[0].Path.Elem[2].Key["hw-dev-index"] = "1"
				return []*gnmipb.GetResponse{first, second}
			}(),
			versions:   []*gnmipb.GetResponse{runtimeTestXEVersionIdentityResponse("17.18.1a")},
			wantReason: gnmiPreflightIdentityAmbiguous,
		},
		{
			name: "matching and wrong-family chassis models are ambiguous",
			hardware: []*gnmipb.GetResponse{
				runtimeTestXEHardwareIdentityResponse("C9800-40-K9"),
				runtimeTestXEHardwareIdentityResponse("C9300-48P"),
			},
			versions:   []*gnmipb.GetResponse{runtimeTestXEVersionIdentityResponse("17.18.1a")},
			wantReason: gnmiPreflightIdentityAmbiguous,
		},
		{
			name:       "wrong chassis family is a product mismatch",
			hardware:   []*gnmipb.GetResponse{runtimeTestXEHardwareIdentityResponse("C9300-48P")},
			versions:   []*gnmipb.GetResponse{runtimeTestXEVersionIdentityResponse("17.18.1a")},
			wantReason: gnmiPreflightProductMismatch,
		},
		{
			name:     "mixed valid and malformed current builds are ambiguous",
			hardware: []*gnmipb.GetResponse{runtimeTestXEHardwareIdentityResponse("C9800-40-K9")},
			versions: []*gnmipb.GetResponse{
				runtimeTestXEVersionIdentityResponse("17.18.1a"),
				runtimeTestXEVersionIdentityResponse("BROKEN"),
			},
			wantReason: gnmiPreflightIdentityAmbiguous,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decodeResponses := func(responses []*gnmipb.GetResponse) []internalgnmi.Point {
				points := make([]internalgnmi.Point, 0)
				for _, response := range responses {
					decoded, decodeErr := decodeGNMIIdentityGetResponse("xe", response)
					require.NoError(t, decodeErr)
					points = append(points, decoded...)
				}
				return points
			}
			hardwarePoints := decodeResponses(test.hardware)
			versionPoints := decodeResponses(test.versions)
			model, build, extractErr := extractIOSXEGNMIIdentity(contract, hardwarePoints, versionPoints)
			if test.wantReason == "" {
				require.NoError(t, extractErr)
				assert.Equal(t, test.wantModel, model)
				assert.Equal(t, test.wantBuild, build)
				return
			}
			assertGNMICompatibilityReason(t, extractErr, test.wantReason)
		})
	}
}

func TestIOSXEIdentityAcceptsDocumentedNumericEnums(t *testing.T) {
	for _, value := range []internalgnmi.Value{internalgnmi.IntValue(1), internalgnmi.UintValue(1), internalgnmi.StringValue("1")} {
		code, present, err := strictIdentityEnumValues([]internalgnmi.Value{value}, iosXEHardwareTypeCodes, 0, 12)
		require.NoError(t, err)
		assert.True(t, present)
		assert.Equal(t, int64(1), code)
	}
	for _, current := range []internalgnmi.Value{
		internalgnmi.IntValue(0),
		internalgnmi.IntValue(1),
		internalgnmi.UintValue(0),
		internalgnmi.UintValue(1),
	} {
		code, present, err := strictIdentityEnumValues([]internalgnmi.Value{current}, iosXEInstallVersionStateCodes, 0, 6)
		require.NoError(t, err)
		assert.True(t, present)
		assert.Contains(t, []int64{0, 1}, code)
	}
	_, _, err := strictIdentityEnumValues([]internalgnmi.Value{internalgnmi.BoolValue(true)}, iosXEInstallVersionStateCodes, 0, 6)
	require.Error(t, err)
}

func TestIOSXEIdentitySchemaViolationsAreMalformed(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9800, "17.18.1")
	require.NoError(t, err)

	tests := []struct {
		name   string
		mutate func(*gnmipb.GetResponse, *gnmipb.GetResponse)
	}{
		{
			name: "boolean current",
			mutate: func(_, version *gnmipb.GetResponse) {
				version.Notification[0].Update[0].Val = &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{BoolVal: true}}
			},
		},
		{
			name: "invented string current",
			mutate: func(_, version *gnmipb.GetResponse) {
				version.Notification[0].Update[0].Val = &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "true"}}
			},
		},
		{
			name: "missing hardware index key",
			mutate: func(hardware, _ *gnmipb.GetResponse) {
				delete(hardware.Notification[0].Update[0].Path.Elem[2].Key, "hw-dev-index")
			},
		},
		{
			name: "missing version extension key",
			mutate: func(_, version *gnmipb.GetResponse) {
				delete(version.Notification[0].Update[0].Path.Elem[2].Key, "version-extension")
			},
		},
		{
			name: "hardware key conflicts with leaf",
			mutate: func(hardware, _ *gnmipb.GetResponse) {
				path := proto.Clone(hardware.Notification[0].Update[0].Path).(*gnmipb.Path)
				path.Elem[len(path.Elem)-1].Name = "hw-type"
				hardware.Notification[0].Update = append(hardware.Notification[0].Update, &gnmipb.Update{
					Path: path,
					Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "hw-type-fantray"}},
				})
			},
		},
		{
			name: "non-string part number",
			mutate: func(hardware, _ *gnmipb.GetResponse) {
				hardware.Notification[0].Update[0].Val = &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: 9800}}
			},
		},
		{
			name: "hardware index out of range",
			mutate: func(hardware, _ *gnmipb.GetResponse) {
				hardware.Notification[0].Update[0].Path.Elem[2].Key["hw-dev-index"] = "4294967296"
			},
		},
		{
			name: "location out of range",
			mutate: func(_, version *gnmipb.GetResponse) {
				version.Notification[0].Update[0].Path.Elem[1].Key["slot"] = "32768"
			},
		},
		{
			name: "conflicting current states",
			mutate: func(_, version *gnmipb.GetResponse) {
				conflict := proto.Clone(version.Notification[0]).(*gnmipb.Notification)
				conflict.Update[0].Val = &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "install-version-state-provisioned-uncommitted"}}
				version.Notification = append(version.Notification, conflict)
			},
		},
	}

	decode := func(t *testing.T, response *gnmipb.GetResponse) []internalgnmi.Point {
		points, decodeErr := decodeGNMIIdentityGetResponse("xe", response)
		require.NoError(t, decodeErr)
		return points
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hardware := runtimeTestXEHardwareIdentityResponse("C9800-40-K9")
			version := runtimeTestXEVersionIdentityResponseWithExtension("17.18.01.0.1186", "opaque-build")
			test.mutate(hardware, version)
			_, _, extractErr := extractIOSXEGNMIIdentity(contract, decode(t, hardware), decode(t, version))
			assertGNMICompatibilityReason(t, extractErr, gnmiPreflightMalformedIdentity)
		})
	}
}

func TestIOSXEIdentityAllowsEmptyOpaqueVersionExtension(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9800, "17.18.1")
	require.NoError(t, err)
	hardware, err := decodeGNMIIdentityGetResponse("xe", runtimeTestXEHardwareIdentityResponse("C9800-40-K9"))
	require.NoError(t, err)
	version, err := decodeGNMIIdentityGetResponse("xe", runtimeTestXEVersionIdentityResponseWithExtension("17.18.01.0.1186", ""))
	require.NoError(t, err)

	model, build, err := extractIOSXEGNMIIdentity(contract, hardware, version)
	require.NoError(t, err)
	assert.Equal(t, "C9800-40-K9", model)
	assert.Equal(t, "17.18.1", build)
}

func TestGroupGNMIIdentityPointsRejectsNULKeyBoundaryCollision(t *testing.T) {
	point := func(keys map[string]string, leaf string) internalgnmi.Point {
		return internalgnmi.Point{Series: internalgnmi.Series{
			Target: "target", Origin: "openconfig",
			Elements: []internalgnmi.PathElem{{Name: "components"}, {Name: "component", Keys: keys}, {Name: "state"}},
			Leaf:     leaf,
		}, Value: internalgnmi.StringValue("value")}
	}
	points := []internalgnmi.Point{
		point(map[string]string{"a": "x\x00b=y"}, "model-name"),
		point(map[string]string{"a": "x", "b": "y"}, "software-version"),
	}
	assert.Len(t, groupGNMIIdentityPoints(points, "component", []string{"state"}, nil), 2)
}

func TestValidateGNMIIdentityProbePointsDoesNotReflectPeerPath(t *testing.T) {
	probe := gnmiIdentityProbe{
		Name:         "xr",
		Model:        "Cisco-IOS-XR-install-oper",
		PrefixOrigin: "Cisco-IOS-XR-install-oper",
		Paths:        []sharedGNMIPath{{Path: "install/version"}},
	}
	points := []internalgnmi.Point{{Series: internalgnmi.Series{
		Target: "target", Origin: "Cisco-IOS-XR-install-oper",
		Elements: []internalgnmi.PathElem{{Name: "outside", Keys: map[string]string{"echo": "username:password"}}},
		Leaf:     "label",
	}}}
	err := validateGNMIIdentityProbePoints(probe, points)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "username:password")
	assert.NotContains(t, err.Error(), "outside")
}

func TestValidateGNMIIdentityProbePointsRejectsForeignQualifiedNames(t *testing.T) {
	probe := gnmiIdentityProbe{
		Name:         "xr",
		Model:        "Cisco-IOS-XR-install-oper",
		PrefixOrigin: "Cisco-IOS-XR-install-oper",
		Paths:        []sharedGNMIPath{{Path: "install/version"}},
	}
	point := internalgnmi.Point{Series: internalgnmi.Series{
		Target: "target", Origin: "Cisco-IOS-XR-install-oper",
		Elements: []internalgnmi.PathElem{{Name: "install"}, {Name: "version"}},
		Leaf:     "Cisco-IOS-XR-install-oper:label",
	}}
	require.NoError(t, validateGNMIIdentityProbePoints(probe, []internalgnmi.Point{point}))

	for _, mutate := range []func(*internalgnmi.Point){
		func(point *internalgnmi.Point) { point.Series.Leaf = "peer-secret:label" },
		func(point *internalgnmi.Point) {
			point.Series.Elements[1].Keys = map[string]string{"peer-secret:slot": "value"}
		},
	} {
		malformed := point
		malformed.Series.Elements = append([]internalgnmi.PathElem(nil), point.Series.Elements...)
		mutate(&malformed)
		err := validateGNMIIdentityProbePoints(probe, []internalgnmi.Point{malformed})
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "peer-secret")
	}
}

func TestValidateGNMIIdentityProbePointsAllowsNXOSOmittedOpenConfigOrigin(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductNexus9000, "10.6(1)")
	require.NoError(t, err)
	probe := contract.IdentityProbes[0]
	point := internalgnmi.Point{Series: internalgnmi.Series{
		Target: "target",
		Elements: []internalgnmi.PathElem{
			{Name: "components"},
			{Name: "component", Keys: map[string]string{"name": "Chassis"}},
			{Name: "state"},
		},
		Leaf: "model-name",
	}}
	require.NoError(t, validateGNMIIdentityProbePoints(probe, []internalgnmi.Point{point}))

	for _, origin := range []string{"openconfig-platform", "OpenConfig", "peer-origin"} {
		malformed := point
		malformed.Series.Origin = origin
		err := validateGNMIIdentityProbePoints(probe, []internalgnmi.Point{malformed})
		require.ErrorContains(t, err, "does not match a configured probe path")
	}

	wrongTarget := point
	wrongTarget.Series.PathTarget = "peer-target"
	require.ErrorContains(t, validateGNMIIdentityProbePoints(probe, []internalgnmi.Point{wrongTarget}), "does not match a configured probe path")

	for _, mutate := range []func(*gnmiIdentityProbe){
		func(probe *gnmiIdentityProbe) { probe.Name += "-other" },
		func(probe *gnmiIdentityProbe) { probe.Model += "-other" },
	} {
		nearMiss := probe
		mutate(&nearMiss)
		require.ErrorContains(t, validateGNMIIdentityProbePoints(nearMiss, []internalgnmi.Point{point}), "does not match a configured probe path")
	}
}

func TestValidateGNMIIdentityProbePointsDoesNotGenerallyAllowOmittedOrigin(t *testing.T) {
	probe := gnmiIdentityProbe{
		Name:         "xr",
		Model:        "Cisco-IOS-XR-install-oper",
		PrefixOrigin: "Cisco-IOS-XR-install-oper",
		Paths:        []sharedGNMIPath{{Path: "install/version"}},
	}
	point := internalgnmi.Point{Series: internalgnmi.Series{
		Target:   "target",
		Elements: []internalgnmi.PathElem{{Name: "install"}, {Name: "version"}},
		Leaf:     "label",
	}}
	err := validateGNMIIdentityProbePoints(probe, []internalgnmi.Point{point})
	require.ErrorContains(t, err, "does not match a configured probe path")
}

func TestRunGNMIIdentityPreflightDoesNotReflectMalformedPeerData(t *testing.T) {
	contract, configured, err := resolveGNMIProductContract(gnmiProductASR9000, "24.4.1")
	require.NoError(t, err)
	keys := make(map[string]string, 65)
	for index := range 65 {
		keys["key-"+strconv.Itoa(index)] = "value"
	}
	conn := &identityGetTestConn{response: &gnmipb.GetResponse{Notification: []*gnmipb.Notification{{
		Prefix: &gnmipb.Path{Origin: "Cisco-IOS-XR-install-oper", Elem: []*gnmipb.PathElem{{Name: "peer-secret", Key: keys}}},
	}}}}

	_, err = runGNMIIdentityPreflight(
		t.Context(), conn, newGNMIResponseAdmission(),
		GNMITargetConfig{Name: "target", CapabilitiesTimeout: time.Second},
		contract, configured, gnmipb.Encoding_JSON_IETF,
	)
	assertGNMICompatibilityReason(t, err, gnmiPreflightMalformedIdentity)
	assert.NotContains(t, err.Error(), "peer-secret")
}

func TestRunGNMIIdentityPreflightKeepsInBandInvalidArgumentAuthenticationRetryable(t *testing.T) {
	contract, configured, err := resolveGNMIProductContract(gnmiProductASR9000, "24.4.1")
	require.NoError(t, err)
	conn := &identityGetTestConn{response: &gnmipb.GetResponse{
		Error: &gnmipb.Error{ //nolint:staticcheck // Exercise the legacy in-band Get error contract.
			Code: uint32(codes.InvalidArgument), Message: "authentication failed: runtime-secret",
		},
	}}

	_, err = runGNMIIdentityPreflight(
		t.Context(), conn, newGNMIResponseAdmission(),
		GNMITargetConfig{Name: "target", CapabilitiesTimeout: time.Second},
		contract, configured, gnmipb.Encoding_JSON_IETF,
	)
	require.Error(t, err)
	var compatibility *sharedGNMICompatibilityError
	assert.NotErrorAs(t, err, &compatibility)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.True(t, isSharedGNMIAuthenticationError(err))
	assert.NotContains(t, err.Error(), "runtime-secret")
}

func TestIdentityExtractionRejectsExpectedLeafNamesAtUnexpectedDescendants(t *testing.T) {
	point := func(elements []string, leaf, value string) internalgnmi.Point {
		path := make([]internalgnmi.PathElem, len(elements))
		for index, element := range elements {
			path[index] = internalgnmi.PathElem{Name: element}
		}
		return internalgnmi.Point{Series: internalgnmi.Series{Elements: path, Leaf: leaf}, Value: internalgnmi.StringValue(value)}
	}

	t.Run("IOS XR", func(t *testing.T) {
		points := []internalgnmi.Point{
			point([]string{"install", "version", "unexpected"}, "chassis-pid", "ASR-9904"),
			point([]string{"install", "version", "unexpected"}, "label", "24.4.1"),
		}
		_, _, err := extractIOSXRGNMIIdentity(points)
		assertGNMICompatibilityReason(t, err, gnmiPreflightIdentityMissing)
	})

	t.Run("IOS XE", func(t *testing.T) {
		contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9800, "17.18.1")
		require.NoError(t, err)
		hardware := []internalgnmi.Point{
			point([]string{"device-hardware-data", "device-hardware", "device-inventory", "unexpected"}, "hw-type", "chassis"),
			point([]string{"device-hardware-data", "device-hardware", "device-inventory", "unexpected"}, "part-number", "C9800-40-K9"),
		}
		version := []internalgnmi.Point{
			point([]string{"install-oper-data", "install-location-information", "install-version-info"}, "current", "true"),
			point([]string{"install-oper-data", "install-location-information", "install-version-info"}, "version", "17.18.1"),
		}
		_, _, err = extractIOSXEGNMIIdentity(contract, hardware, version)
		assertGNMICompatibilityReason(t, err, gnmiPreflightIdentityMissing)
	})

	t.Run("NX-OS", func(t *testing.T) {
		points := []internalgnmi.Point{
			point([]string{"components", "component", "state", "unexpected"}, "type", "CHASSIS"),
			point([]string{"components", "component", "state", "unexpected"}, "model-name", "N9K-C93180YC-FX3"),
			point([]string{"components", "component", "state", "unexpected"}, "software-version", "10.6(1)F"),
		}
		_, _, err := extractNXOSGNMIIdentity(points)
		assertGNMICompatibilityReason(t, err, gnmiPreflightIdentityMissing)
	})

	t.Run("NX-OS list keys cannot impersonate state leaves", func(t *testing.T) {
		points := []internalgnmi.Point{{
			Series: internalgnmi.Series{
				Elements: []internalgnmi.PathElem{
					{Name: "components"},
					{Name: "component", Keys: map[string]string{
						"name": "Chassis", "type": "CHASSIS",
						"model-name": "N9K-C93180YC-FX3", "software-version": "10.6(1)F",
					}},
					{Name: "state"},
				},
				Leaf: "dummy",
			},
			Value: internalgnmi.StringValue("ignored"),
		}}
		_, _, err := extractNXOSGNMIIdentity(points)
		assertGNMICompatibilityReason(t, err, gnmiPreflightIdentityMissing)
	})
}

func TestProductIdentityExtractionFromSubtreeJSON(t *testing.T) {
	t.Run("IOS XE inventory and install JSON-IETF", func(t *testing.T) {
		contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9800, "17.18.1a")
		require.NoError(t, err)
		hardware := decodeIdentityJSONResponse(t, "xe", builtinGNMIOriginRFC7951,
			"Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware",
			`{"device-inventory":[{"hw-type":"hw-type-chassis","hw-dev-index":0,"part-number":"C9800-40-K9"}]}`, true)
		version := decodeIdentityJSONResponse(t, "xe", builtinGNMIOriginRFC7951,
			"Cisco-IOS-XE-install-oper:install-oper-data/install-location-information[fru=fru-rp][slot=0][bay=0][chassis=0]",
			`{"install-version-info":[{"version":"17.18.01a.0.1186","version-extension":"opaque-build","current":"install-version-state-provisioned-committed"}]}`, true)
		require.NoError(t, validateGNMIIdentityProbePoints(contract.IdentityProbes[0], hardware))
		require.NoError(t, validateGNMIIdentityProbePoints(contract.IdentityProbes[1], version))
		model, build, err := extractIOSXEGNMIIdentity(contract, hardware, version)
		require.NoError(t, err)
		assert.Equal(t, "C9800-40-K9", model)
		assert.Equal(t, "17.18.1a", build)
	})

	t.Run("IOS XR install version JSON-IETF", func(t *testing.T) {
		contract, _, err := resolveGNMIProductContract(gnmiProductASR9000, "24.4.1")
		require.NoError(t, err)
		points := decodeIdentityJSONResponse(t, "xr", "Cisco-IOS-XR-install-oper", "install/version",
			`{"chassis-pid":"ASR-9904","label":"24.4.1"}`, true)
		require.NoError(t, validateGNMIIdentityProbePoints(contract.IdentityProbes[0], points))
		model, build, err := extractIOSXRGNMIIdentity(points)
		require.NoError(t, err)
		assert.Equal(t, "ASR-9904", model)
		assert.Equal(t, "24.4.1", build)
	})

	t.Run("NX-OS OpenConfig platform JSON", func(t *testing.T) {
		contract, _, err := resolveGNMIProductContract(gnmiProductNexus9000, "10.6(1)F")
		require.NoError(t, err)
		for _, test := range []struct {
			name   string
			origin string
		}{
			{name: "requested origin retained", origin: "openconfig"},
			{name: "requested origin omitted", origin: ""},
		} {
			t.Run(test.name, func(t *testing.T) {
				points := decodeIdentityJSONResponse(t, "nx", test.origin, "components/component[name=Chassis]/state",
					`{"type":"openconfig-platform-types:CHASSIS","model-name":"N9K-C93180YC-FX3","software-version":"10.6(1)F"}`, false)
				require.NoError(t, validateGNMIIdentityProbePoints(contract.IdentityProbes[0], points))
				model, build, err := extractNXOSGNMIIdentity(points)
				require.NoError(t, err)
				assert.Equal(t, "N9K-C93180YC-FX3", model)
				assert.Equal(t, "10.6(1)F", build)
			})
		}
	})
}

func decodeIdentityJSONResponse(t *testing.T, target, origin, path, raw string, ietf bool) []internalgnmi.Point {
	t.Helper()
	protoPath, err := sharedGNMIPathToProto("", "", path)
	require.NoError(t, err)
	typed := &gnmipb.TypedValue{}
	if ietf {
		typed.Value = &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(raw)}
	} else {
		typed.Value = &gnmipb.TypedValue_JsonVal{JsonVal: []byte(raw)}
	}
	points, err := decodeGNMIIdentityGetResponse(target, &gnmipb.GetResponse{Notification: []*gnmipb.Notification{{
		Prefix: &gnmipb.Path{Origin: origin},
		Update: []*gnmipb.Update{{Path: protoPath, Val: typed}},
	}}})
	require.NoError(t, err)
	return points
}

func TestDecodeGNMIIdentityGetResponseBounds(t *testing.T) {
	_, err := decodeGNMIIdentityGetResponse("target", nil)
	require.ErrorContains(t, err, "empty Get response")

	tooManyNotifications := &gnmipb.GetResponse{Notification: make([]*gnmipb.Notification, gnmiMaximumIdentityNotifications+1)}
	_, err = decodeGNMIIdentityGetResponse("target", tooManyNotifications)
	require.ErrorContains(t, err, "exceeds 64 notifications")

	tooManyLeaves := &gnmipb.GetResponse{Notification: []*gnmipb.Notification{{
		Update: make([]*gnmipb.Update, gnmiMaximumIdentityDecodedUpdates+1),
	}}}
	for i := range tooManyLeaves.Notification[0].Update {
		tooManyLeaves.Notification[0].Update[i] = &gnmipb.Update{
			Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "state"}, {Name: "value-" + strconv.Itoa(i)}}},
			Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "x"}},
		}
	}
	_, err = decodeGNMIIdentityGetResponse("target", tooManyLeaves)
	require.ErrorContains(t, err, "exceeds 10000 decoded identity leaves")
}

func TestClientGNMIResponseTooLargeClassificationIsNarrow(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "wire frame", err: status.Error(codes.ResourceExhausted, "grpc: received message larger than max (1048577 vs. 1048576)"), want: true},
		{name: "decompressed frame", err: status.Error(codes.ResourceExhausted, "grpc: received message after decompression larger than max 1048576"), want: true},
		{name: "server capacity", err: status.Error(codes.ResourceExhausted, "device is temporarily overloaded")},
		{name: "malformed size", err: status.Error(codes.ResourceExhausted, "grpc: received message larger than max (1 vs. 2)")},
		{name: "trailing peer text", err: status.Error(codes.ResourceExhausted, fmt.Sprintf("grpc: received message larger than max (%d vs. %d) peer", 2, 1))},
		{name: "different code", err: status.Error(codes.Unavailable, "grpc: received message larger than max (2 vs. 1)")},
	} {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, clientGNMIResponseTooLarge(test.err))
		})
	}
}

func TestDeterministicGNMIIdentityRPCErrorDoesNotTrustPeerText(t *testing.T) {
	peerError := status.Error(codes.Unavailable, "gNMI response preflight: message exceeds 1 bytes")
	assert.False(t, deterministicGNMIIdentityRPCError(peerError))

	localError := &gnmiLocalResponsePreflightError{err: status.Error(codes.Internal, "decode rejected")}
	assert.True(t, deterministicGNMIIdentityRPCError(localError))
}

func runtimeTestXEHardwareIdentityResponseWithType(model, hardwareType string) *gnmipb.GetResponse {
	response := runtimeTestXEHardwareIdentityResponse(model)
	response.GetNotification()[0].GetUpdate()[0].GetPath().GetElem()[2].Key["hw-type"] = hardwareType
	return response
}

type identityGetTestConn struct {
	response *gnmipb.GetResponse
}

func (c *identityGetTestConn) Invoke(
	_ context.Context,
	method string,
	_, reply any,
	_ ...grpc.CallOption,
) error {
	if method != gnmipb.GNMI_Get_FullMethodName {
		return fmt.Errorf("unexpected RPC method %q", method)
	}
	response, ok := reply.(*gnmipb.GetResponse)
	if !ok {
		return fmt.Errorf("unexpected RPC response type %T", reply)
	}
	if c.response == nil {
		return nil
	}
	proto.Merge(response, c.response)
	return nil
}

func (*identityGetTestConn) NewStream(
	context.Context,
	*grpc.StreamDesc,
	string,
	...grpc.CallOption,
) (grpc.ClientStream, error) {
	return nil, errors.New("unexpected streaming RPC")
}

func assertGNMICompatibilityReason(t *testing.T, err error, reason string) {
	t.Helper()
	var compatibility *sharedGNMICompatibilityError
	require.Error(t, err)
	require.ErrorAs(t, err, &compatibility)
	assert.Equal(t, reason, compatibility.reason)
}
