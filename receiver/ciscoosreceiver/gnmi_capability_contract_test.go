// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"testing"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateGNMIProtocolVersionPinsCatalystSwitchContracts(t *testing.T) {
	for _, product := range []string{gnmiProductCatalyst9300, gnmiProductCatalyst9500} {
		t.Run(product, func(t *testing.T) {
			contract, _, err := resolveGNMIProductContract(product, "17.18.1")
			require.NoError(t, err)
			require.Equal(t, []string{"0.4.0"}, contract.ApprovedGNMIVersions)
			require.True(t, contract.CanonicalizeJSONIETFPathKeys)
			require.NoError(t, validateGNMIProtocolVersion(contract, &gnmipb.CapabilityResponse{GNMIVersion: "0.4.0"}))

			for _, version := range []string{"", "0.4", "0.4.0 ", "0.7.0"} {
				err = validateGNMIProtocolVersion(contract, &gnmipb.CapabilityResponse{GNMIVersion: version})
				assertGNMICompatibilityReason(t, err, gnmiPreflightUnsupportedVersion)
			}
			assertGNMICompatibilityReason(t, validateGNMIProtocolVersion(contract, nil), gnmiPreflightUnsupportedVersion)
		})
	}

	legacy, _, err := resolveGNMIProductContract(gnmiProductCatalyst9800, "17.18.3")
	require.NoError(t, err)
	assert.Empty(t, legacy.ApprovedGNMIVersions)
	assert.False(t, legacy.CanonicalizeJSONIETFPathKeys,
		"the new IOS XE quoted-key policy is limited to the switch contracts until C9800 capture qualification")
	assert.NoError(t, validateGNMIProtocolVersion(legacy, &gnmipb.CapabilityResponse{}))
}

func TestCatalystSwitchUnsupportedGNMIVersionQuarantinesBeforeGet(t *testing.T) {
	for _, version := range []string{"", "0.7.0"} {
		t.Run("version_"+version, func(t *testing.T) {
			material := runtimeTestTLSMaterial(t)
			fake := &runtimeTestGNMIServer{}
			fake.capabilities = func(context.Context) (*gnmipb.CapabilityResponse, error) {
				return &gnmipb.CapabilityResponse{
					GNMIVersion:        version,
					SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON_IETF},
				}, nil
			}
			endpoint, _ := runtimeTestStartGNMIServer(t, fake, material.serverTLS(false))
			target := runtimeTestTarget(endpoint, material.caFile, gnmiModeStream)
			target.Product = gnmiProductCatalyst9300
			target.SoftwareVersion = "17.18.1"
			target.CustomSubscriptions = nil
			target.MaxStreams = 1
			enabled := true
			target.Profiles.Interfaces = GNMIProfileConfig{Enabled: &enabled, Required: true}

			err := runtimeTestServeTarget(t, target)
			assertGNMICompatibilityReason(t, err, gnmiPreflightUnsupportedVersion)
			snapshot := fake.snapshot()
			assert.Equal(t, 1, snapshot.capabilitiesCalls)
			assert.Zero(t, snapshot.getCalls)
			assert.Zero(t, snapshot.subscribeCalls)
		})
	}
}

func TestValidateGNMIRequiredModelsPinsCatalystSwitchCatalogTuples(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9300, "17.18.1")
	require.NoError(t, err)

	revisionDates := runtimeTestCatalystSwitchModelData(
		"Cisco-IOS-XE-device-hardware-oper",
		"Cisco-IOS-XE-install-oper",
	)
	semanticVersions := []*gnmipb.ModelData{
		{Name: "Cisco-IOS-XE-device-hardware-oper", Organization: "Cisco Systems, Inc.", Version: "1.12.0"},
		{Name: "Cisco-IOS-XE-install-oper", Organization: "Cisco Systems, Inc.", Version: "2.1.0"},
	}
	require.NoError(t, validateGNMIRequiredModels(contract, nil, &gnmipb.CapabilityResponse{SupportedModels: revisionDates}))
	require.NoError(t, validateGNMIRequiredModels(contract, nil, &gnmipb.CapabilityResponse{SupportedModels: semanticVersions}))

	tests := []struct {
		name   string
		models []*gnmipb.ModelData
	}{
		{
			name: "version omitted",
			models: []*gnmipb.ModelData{
				{Name: "Cisco-IOS-XE-device-hardware-oper", Organization: "Cisco Systems, Inc."},
				revisionDates[1],
			},
		},
		{
			name: "organization mismatch",
			models: []*gnmipb.ModelData{
				{Name: "Cisco-IOS-XE-device-hardware-oper", Organization: "Not Cisco", Version: "2025-03-01"},
				revisionDates[1],
			},
		},
		{
			name: "unreviewed version",
			models: []*gnmipb.ModelData{
				{Name: "Cisco-IOS-XE-device-hardware-oper", Organization: "Cisco Systems, Inc.", Version: "2099-01-01"},
				revisionDates[1],
			},
		},
		{
			name: "conflicting same-name entries",
			models: append(append([]*gnmipb.ModelData(nil), revisionDates...), &gnmipb.ModelData{
				Name: "Cisco-IOS-XE-device-hardware-oper", Organization: "Cisco Systems, Inc.", Version: "1.12.0",
			}),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertGNMICompatibilityReason(
				t,
				validateGNMIRequiredModels(contract, nil, &gnmipb.CapabilityResponse{SupportedModels: test.models}),
				gnmiPreflightUnsupportedModel,
			)
		})
	}
}

func TestValidateGNMIRequiredModelsRejectsUnpinnedCatalystSwitchCustomModel(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9300, "17.18.1")
	require.NoError(t, err)
	streams := []sharedGNMIStream{{RequiredModels: []string{"example-custom-model"}}}
	capabilities := &gnmipb.CapabilityResponse{SupportedModels: append(
		runtimeTestCatalystSwitchModelData(
			"Cisco-IOS-XE-device-hardware-oper",
			"Cisco-IOS-XE-install-oper",
		),
		&gnmipb.ModelData{Name: "example-custom-model", Organization: "Example", Version: "1.0.0"},
	)}

	assertGNMICompatibilityReason(
		t,
		validateGNMIRequiredModels(contract, streams, capabilities),
		gnmiPreflightUnsupportedModel,
	)
}

func TestValidateGNMIRequiredModelsRejectsMalformedAdvertisedNames(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9300, "17.18.1")
	require.NoError(t, err)

	for _, name := range []string{
		" Cisco-IOS-XE-device-hardware-oper",
		"Cisco-IOS-XE-device-hardware-oper ",
		"Cisco-IOS-XE-device-hardware-oper/control",
		"",
	} {
		t.Run(name, func(t *testing.T) {
			capabilities := &gnmipb.CapabilityResponse{SupportedModels: []*gnmipb.ModelData{
				{Name: name},
				runtimeTestCatalystSwitchModelData("Cisco-IOS-XE-install-oper")[0],
			}}
			assertGNMICompatibilityReason(
				t,
				validateGNMIRequiredModels(contract, nil, capabilities),
				gnmiPreflightMissingModel,
			)
		})
	}
}
