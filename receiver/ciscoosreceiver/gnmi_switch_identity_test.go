// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

func TestExtractCatalystSwitchGNMIIdentity(t *testing.T) {
	tests := []struct {
		product, model string
	}{
		{product: gnmiProductCatalyst9300, model: "C9300-48UXM"},
		{product: gnmiProductCatalyst9500, model: "C9500-48Y4C"},
	}
	for _, test := range tests {
		t.Run(test.product, func(t *testing.T) {
			contract, _, err := resolveGNMIProductContract(test.product, "17.18.1")
			require.NoError(t, err)
			hardware, err := decodeGNMIIdentityGetResponse("switch", runtimeTestXEHardwareIdentityResponse(test.model))
			require.NoError(t, err)
			version, err := decodeGNMIIdentityGetResponse("switch", runtimeTestXEVersionIdentityResponse("17.18.01.0.1186"))
			require.NoError(t, err)
			model, build, err := extractIOSXEGNMIIdentity(contract, hardware, version)
			require.NoError(t, err)
			assert.Equal(t, test.model, model)
			assert.Equal(t, "17.18.1", build)
		})
	}
}

func TestExtractCatalystSwitchGNMIIdentityRejectsCrossProductAndMultipleChassis(t *testing.T) {
	version, err := decodeGNMIIdentityGetResponse("switch", runtimeTestXEVersionIdentityResponse("17.18.01.0.1186"))
	require.NoError(t, err)
	for _, test := range []struct {
		product, validModel, foreignModel string
	}{
		{product: gnmiProductCatalyst9300, validModel: "C9300-48UXM", foreignModel: "C9500-48Y4C"},
		{product: gnmiProductCatalyst9500, validModel: "C9500-48Y4C", foreignModel: "C9300-48UXM"},
	} {
		t.Run(test.product, func(t *testing.T) {
			contract, _, contractErr := resolveGNMIProductContract(test.product, "17.18.1")
			require.NoError(t, contractErr)
			foreign, decodeErr := decodeGNMIIdentityGetResponse("switch", runtimeTestXEHardwareIdentityResponse(test.foreignModel))
			require.NoError(t, decodeErr)
			_, _, extractErr := extractIOSXEGNMIIdentity(contract, foreign, version)
			assertGNMICompatibilityReason(t, extractErr, gnmiPreflightProductMismatch)

			first, decodeErr := decodeGNMIIdentityGetResponse("switch", runtimeTestXEHardwareIdentityResponse(test.validModel))
			require.NoError(t, decodeErr)
			secondResponse := runtimeTestXEHardwareIdentityResponse(test.validModel)
			secondResponse.GetNotification()[0].GetUpdate()[0].GetPath().GetElem()[2].Key["hw-dev-index"] = "1"
			second, decodeErr := decodeGNMIIdentityGetResponse("switch", secondResponse)
			require.NoError(t, decodeErr)
			multiple := append(append([]internalgnmi.Point(nil), first...), second...)
			_, _, extractErr = extractIOSXEGNMIIdentity(contract, multiple, version)
			assertGNMICompatibilityReason(t, extractErr, gnmiPreflightIdentityAmbiguous)
			assert.ErrorContains(t, extractErr, "multiple chassis")
		})
	}
}

func TestExtractCatalystSwitchGNMIIdentityRequiresOneExactCurrentImage(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9300, "17.18.1")
	require.NoError(t, err)
	hardware, err := decodeGNMIIdentityGetResponse("switch", runtimeTestXEHardwareIdentityResponse("C9300-48UXM"))
	require.NoError(t, err)
	decodeVersion := func(response *gnmipb.GetResponse) []internalgnmi.Point {
		points, decodeErr := decodeGNMIIdentityGetResponse("switch", response)
		require.NoError(t, decodeErr)
		return points
	}

	for _, test := range []struct {
		name       string
		second     *gnmipb.GetResponse
		wantReason string
	}{
		{
			name:       "different internal build at same location",
			second:     runtimeTestXEVersionIdentityResponseWithExtension("17.18.01.0.2222", "ext-b"),
			wantReason: gnmiPreflightIdentityAmbiguous,
		},
		{
			name:       "different extension at same location",
			second:     runtimeTestXEVersionIdentityResponseWithExtension("17.18.01.0.1186", "ext-b"),
			wantReason: gnmiPreflightIdentityAmbiguous,
		},
		{
			name: "same exact image at another current location",
			second: func() *gnmipb.GetResponse {
				response := runtimeTestXEVersionIdentityResponseWithExtension("17.18.01.0.1186", "ext-a")
				response.GetNotification()[0].GetUpdate()[0].GetPath().GetElem()[1].Key["slot"] = "1"
				return response
			}(),
		},
		{
			name:       "different exact image at another current location",
			wantReason: gnmiPreflightIdentityAmbiguous,
			second: func() *gnmipb.GetResponse {
				response := runtimeTestXEVersionIdentityResponseWithExtension("17.18.01.0.2222", "ext-b")
				response.GetNotification()[0].GetUpdate()[0].GetPath().GetElem()[1].Key["slot"] = "1"
				return response
			}(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			first := decodeVersion(runtimeTestXEVersionIdentityResponseWithExtension("17.18.01.0.1186", "ext-a"))
			first = append(first, decodeVersion(test.second)...)
			model, version, extractErr := extractIOSXEGNMIIdentity(contract, hardware, first)
			if test.wantReason != "" {
				assertGNMICompatibilityReason(t, extractErr, test.wantReason)
				return
			}
			require.NoError(t, extractErr)
			assert.Equal(t, "C9300-48UXM", model)
			assert.Equal(t, "17.18.1", version)
		})
	}
}

func TestCatalystSwitchBootModePreflightIsLocationCorrelatedAndFailClosed(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9300, "17.18.1")
	require.NoError(t, err)

	stringValue := func(value string) *gnmipb.TypedValue {
		return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: value}}
	}
	appendLocation := func(response *gnmipb.GetResponse, slot string, mode *gnmipb.TypedValue, includeVersion bool) {
		notification := response.GetNotification()[0]
		if includeVersion {
			version := proto.Clone(notification.GetUpdate()[0]).(*gnmipb.Update)
			version.GetPath().GetElem()[1].Key["slot"] = slot
			notification.Update = append(notification.Update, version)
		}
		boot := proto.Clone(notification.GetUpdate()[1]).(*gnmipb.Update)
		boot.GetPath().GetElem()[1].Key["slot"] = slot
		boot.Val = mode
		notification.Update = append(notification.Update, boot)
	}

	tests := []struct {
		name       string
		mutate     func(*gnmipb.GetResponse)
		wantMode   string
		wantReason string
	}{
		{name: "install enum string", wantMode: gnmiIOSXEBootModeInstall},
		{
			name: "install numeric integer",
			mutate: func(response *gnmipb.GetResponse) {
				response.GetNotification()[0].GetUpdate()[1].Val = &gnmipb.TypedValue{
					Value: &gnmipb.TypedValue_IntVal{IntVal: 1},
				}
			},
			wantMode: gnmiIOSXEBootModeInstall,
		},
		{
			name: "install numeric unsigned integer",
			mutate: func(response *gnmipb.GetResponse) {
				response.GetNotification()[0].GetUpdate()[1].Val = &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{UintVal: 1}}
			},
			wantMode: gnmiIOSXEBootModeInstall,
		},
		{
			name: "install numeric string",
			mutate: func(response *gnmipb.GetResponse) {
				response.GetNotification()[0].GetUpdate()[1].Val = stringValue("1")
			},
			wantMode: gnmiIOSXEBootModeInstall,
		},
		{
			name: "multiple current install locations",
			mutate: func(response *gnmipb.GetResponse) {
				appendLocation(response, "1", stringValue("install-boot-mode-install"), true)
			},
			wantMode: gnmiIOSXEBootModeInstall,
		},
		{
			name: "extra install-only location",
			mutate: func(response *gnmipb.GetResponse) {
				appendLocation(response, "1", stringValue("install-boot-mode-install"), false)
			},
			wantMode: gnmiIOSXEBootModeInstall,
		},
		{
			name: "semantically equivalent numeric location keys",
			mutate: func(response *gnmipb.GetResponse) {
				versionLocation := response.GetNotification()[0].GetUpdate()[0].GetPath().GetElem()[1]
				versionLocation.Key["fru"] = "0"
				versionLocation.Key["slot"] = "00"
			},
			wantMode: gnmiIOSXEBootModeInstall,
		},
		{
			name: "missing boot mode",
			mutate: func(response *gnmipb.GetResponse) {
				response.GetNotification()[0].Update = response.GetNotification()[0].GetUpdate()[:1]
			},
			wantReason: gnmiPreflightIdentityMissing,
		},
		{
			name: "uncorrelated boot location",
			mutate: func(response *gnmipb.GetResponse) {
				response.GetNotification()[0].GetUpdate()[1].GetPath().GetElem()[1].Key["slot"] = "1"
			},
			wantReason: gnmiPreflightIdentityMissing,
		},
		{
			name: "bundle mode",
			mutate: func(response *gnmipb.GetResponse) {
				response.GetNotification()[0].GetUpdate()[1].Val = stringValue("install-boot-mode-bundle")
			},
			wantReason: gnmiPreflightUnsupportedBootMode,
		},
		{
			name: "unknown mode",
			mutate: func(response *gnmipb.GetResponse) {
				response.GetNotification()[0].GetUpdate()[1].Val = stringValue("install-boot-mode-unknown")
			},
			wantReason: gnmiPreflightUnsupportedBootMode,
		},
		{
			name: "extra bundle location",
			mutate: func(response *gnmipb.GetResponse) {
				appendLocation(response, "1", stringValue("install-boot-mode-bundle"), false)
			},
			wantReason: gnmiPreflightUnsupportedBootMode,
		},
		{
			name: "boolean mode",
			mutate: func(response *gnmipb.GetResponse) {
				response.GetNotification()[0].GetUpdate()[1].Val = &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{BoolVal: true}}
			},
			wantReason: gnmiPreflightMalformedIdentity,
		},
		{
			name: "idempotent duplicate wire update",
			mutate: func(response *gnmipb.GetResponse) {
				duplicate := proto.Clone(response.GetNotification()[0].GetUpdate()[1]).(*gnmipb.Update)
				response.GetNotification()[0].Update = append(response.GetNotification()[0].Update, duplicate)
			},
			wantMode: gnmiIOSXEBootModeInstall,
		},
		{
			name: "semantically duplicate location",
			mutate: func(response *gnmipb.GetResponse) {
				duplicate := proto.Clone(response.GetNotification()[0].GetUpdate()[1]).(*gnmipb.Update)
				location := duplicate.GetPath().GetElem()[1]
				location.Key["fru"] = "0"
				location.Key["slot"] = "00"
				response.GetNotification()[0].Update = append(response.GetNotification()[0].Update, duplicate)
			},
			wantReason: gnmiPreflightMalformedIdentity,
		},
		{
			name: "missing location key",
			mutate: func(response *gnmipb.GetResponse) {
				delete(response.GetNotification()[0].GetUpdate()[1].GetPath().GetElem()[1].Key, "chassis")
			},
			wantReason: gnmiPreflightMalformedIdentity,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := runtimeTestXEVersionIdentityResponseWithExtension("17.18.01.0.1186", "opaque")
			runtimeTestAppendXEInstallBootMode(response, "install-boot-mode-install")
			if test.mutate != nil {
				test.mutate(response)
			}
			points, decodeErr := decodeGNMIIdentityGetResponse("switch", response)
			require.NoError(t, decodeErr)
			mode, validateErr := validateRequiredIOSXEBootMode(contract, points)
			if test.wantReason != "" {
				assertGNMICompatibilityReason(t, validateErr, test.wantReason)
				assert.Empty(t, mode)
				return
			}
			require.NoError(t, validateErr)
			assert.Equal(t, test.wantMode, mode)
		})
	}
}

func TestCatalystSwitchBootModeRequirementIsContractScoped(t *testing.T) {
	for _, product := range []string{gnmiProductCatalyst9300, gnmiProductCatalyst9500} {
		contract, _, err := resolveGNMIProductContract(product, "17.18.1")
		require.NoError(t, err)
		assert.Equal(t, gnmiIOSXEBootModeInstall, contract.RequiredIOSXEBootMode)
		require.Len(t, contract.IdentityProbes, 2)
		require.Len(t, contract.IdentityProbes[1].Paths, 2)
		assert.Equal(t,
			"Cisco-IOS-XE-install-oper:install-oper-data/install-location-information/oper-state/boot-mode",
			contract.IdentityProbes[1].Paths[1].Path,
		)
	}

	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9800, "17.18.3")
	require.NoError(t, err)
	assert.Empty(t, contract.RequiredIOSXEBootMode)
	require.Len(t, contract.IdentityProbes[1].Paths, 1)
}

func TestCatalystSwitchIdentityPreflightRejectsUndecodableCorrelatedListKeyLeaves(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9300, "17.18.1")
	require.NoError(t, err)

	values := []struct {
		name  string
		value func() *gnmipb.TypedValue
	}{
		{
			name: "JSON null",
			value: func() *gnmipb.TypedValue {
				return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte("null")}}
			},
		},
		{
			name: "leaf-list",
			value: func() *gnmipb.TypedValue {
				return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_LeaflistVal{
					LeaflistVal: &gnmipb.ScalarArray{Element: []*gnmipb.TypedValue{{
						Value: &gnmipb.TypedValue_StringVal{StringVal: "invalid"},
					}}},
				}}
			},
		},
		{
			name: "unsupported bytes",
			value: func() *gnmipb.TypedValue {
				return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BytesVal{BytesVal: []byte{1}}}
			},
		},
	}

	appendSibling := func(response *gnmipb.GetResponse, leaf string, value *gnmipb.TypedValue) {
		t.Helper()
		seed := response.GetNotification()[0].GetUpdate()[0]
		path := proto.Clone(seed.GetPath()).(*gnmipb.Path)
		path.Elem[len(path.GetElem())-1].Name = leaf
		response.Notification[0].Update = append(response.Notification[0].Update, &gnmipb.Update{
			Path: path,
			Val:  value,
		})
	}

	for _, test := range values {
		t.Run("hardware "+test.name, func(t *testing.T) {
			response := runtimeTestXEHardwareIdentityResponse("C9300-48UXM")
			appendSibling(response, "hw-type", test.value())
			_, decodeErr := decodeGNMIIdentityGetResponseForProbe(
				"switch",
				response,
				contract.IdentityProbes[0],
			)
			require.ErrorContains(t, decodeErr, "undecodable correlated list-key leaf")
		})

		t.Run("install "+test.name, func(t *testing.T) {
			response := runtimeTestXEVersionIdentityResponse("17.18.01.0.1186")
			appendSibling(response, "version", test.value())
			_, decodeErr := decodeGNMIIdentityGetResponseForProbe(
				"switch",
				response,
				contract.IdentityProbes[1],
			)
			require.ErrorContains(t, decodeErr, "undecodable correlated list-key leaf")
		})
	}
}

func TestCatalystSwitchIdentityPreflightRejectsUndecodablePathsOutsideProbeScopeOrModel(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9300, "17.18.1")
	require.NoError(t, err)
	probe := contract.IdentityProbes[0]
	unsupported := func(path *gnmipb.Path) *gnmipb.Update {
		return &gnmipb.Update{
			Path: path,
			Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BytesVal{BytesVal: []byte{1}}},
		}
	}

	tests := []struct {
		name   string
		update *gnmipb.Update
	}{
		{
			name: "outside requested root",
			update: unsupported(&gnmipb.Path{Elem: []*gnmipb.PathElem{
				{Name: "Cisco-IOS-XE-device-hardware-oper:device-hardware-data"},
				{Name: "device-hardware"},
				{Name: "device-location"},
				{Name: "opaque-state"},
			}}),
		},
		{
			name: "foreign qualified leaf",
			update: unsupported(&gnmipb.Path{Elem: []*gnmipb.PathElem{
				{Name: "Cisco-IOS-XE-device-hardware-oper:device-hardware-data"},
				{Name: "device-hardware"},
				{Name: "device-inventory", Key: map[string]string{
					"hw-type": "hw-type-chassis", "hw-dev-index": "0",
				}},
				{Name: "peer-secret:reload-history-support"},
			}}),
		},
		{
			name:   "empty path",
			update: unsupported(&gnmipb.Path{}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := runtimeTestXEHardwareIdentityResponse("C9300-48UXM")
			response.Notification[0].Update = append(response.Notification[0].Update, test.update)
			_, decodeErr := decodeGNMIIdentityGetResponseForProbe("switch", response, probe)
			require.ErrorContains(t, decodeErr, "undecodable identity path")
			assert.NotContains(t, decodeErr.Error(), "peer-secret")
			assert.NotContains(t, decodeErr.Error(), "device-location")
		})
	}
}

func TestCatalystSwitchIdentityPreflightPreservesBenignUndecodableInventoryLeaves(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9300, "17.18.1")
	require.NoError(t, err)

	appendUnsupportedSibling := func(response *gnmipb.GetResponse, leaf string) {
		t.Helper()
		seed := response.GetNotification()[0].GetUpdate()[0]
		path := proto.Clone(seed.GetPath()).(*gnmipb.Path)
		path.Elem[len(path.GetElem())-1].Name = leaf
		response.Notification[0].Update = append(response.Notification[0].Update, &gnmipb.Update{
			Path: path,
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_LeaflistVal{
				LeaflistVal: &gnmipb.ScalarArray{Element: []*gnmipb.TypedValue{{
					Value: &gnmipb.TypedValue_StringVal{StringVal: "inventory-metadata"},
				}}},
			}},
		})
	}

	hardwareResponse := runtimeTestXEHardwareIdentityResponse("C9300-48UXM")
	appendUnsupportedSibling(hardwareResponse, "reload-history-support")
	hardware, err := decodeGNMIIdentityGetResponseForProbe(
		"switch",
		hardwareResponse,
		contract.IdentityProbes[0],
	)
	require.NoError(t, err)

	versionResponse := runtimeTestXEVersionIdentityResponse("17.18.01.0.1186")
	appendUnsupportedSibling(versionResponse, "smu-fixes-list")
	version, err := decodeGNMIIdentityGetResponseForProbe(
		"switch",
		versionResponse,
		contract.IdentityProbes[1],
	)
	require.NoError(t, err)

	model, release, err := extractIOSXEGNMIIdentity(contract, hardware, version)
	require.NoError(t, err)
	assert.Equal(t, "C9300-48UXM", model)
	assert.Equal(t, "17.18.1", release)
}
