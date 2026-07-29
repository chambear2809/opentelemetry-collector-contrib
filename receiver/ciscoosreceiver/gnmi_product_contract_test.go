// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

func TestResolveGNMIProductContract(t *testing.T) {
	tests := []struct {
		product, version, osFamily, train, canonical string
		encoding                                     gnmipb.Encoding
	}{
		{gnmiProductCatalyst9300, "17.18.01", gnmiPlatformIOSXE, gnmiReleaseTrainIOSXE1718, "17.18.1", gnmipb.Encoding_JSON_IETF},
		{gnmiProductCatalyst9500, "017.018.001", gnmiPlatformIOSXE, gnmiReleaseTrainIOSXE1718, "17.18.1", gnmipb.Encoding_JSON_IETF},
		{gnmiProductCatalyst9800, "17.18.01a", gnmiPlatformIOSXE, gnmiReleaseTrainIOSXE1718, "17.18.1a", gnmipb.Encoding_JSON_IETF},
		{gnmiProductASR9000, "24.4.2", gnmiPlatformIOSXR, gnmiReleaseTrainIOSXR244, "24.4.2", gnmipb.Encoding_JSON_IETF},
		{gnmiProductNCS5500, "24.04.002", gnmiPlatformIOSXR, gnmiReleaseTrainIOSXR244, "24.4.2", gnmipb.Encoding_JSON_IETF},
		{gnmiProductNexus9000, "10.6(1)f", gnmiPlatformNXOS, gnmiReleaseTrainNXOS106, "10.6(1)F", gnmipb.Encoding_JSON},
		{gnmiProductNexus3500, "10.05(03)M", gnmiPlatformNXOS, gnmiReleaseTrainNXOS105, "10.5(3)M", gnmipb.Encoding_JSON},
	}
	for _, test := range tests {
		t.Run(test.product, func(t *testing.T) {
			contract, parsed, err := resolveGNMIProductContract(test.product, test.version)
			require.NoError(t, err)
			assert.Equal(t, test.product, contract.Product)
			assert.Equal(t, test.osFamily, contract.OSFamily)
			assert.Equal(t, test.train, contract.ReleaseTrain)
			assert.Equal(t, test.canonical, parsed.Canonical)
			assert.Equal(t, test.train, parsed.Train)
			require.NotEmpty(t, contract.ApprovedEncodings)
			assert.Equal(t, test.encoding, contract.ApprovedEncodings[0])
			require.NotEmpty(t, contract.IdentityProbes)
		})
	}
}

func TestGNMIProductContractRegistryIsInternallyConsistent(t *testing.T) {
	supported := make(map[string]struct{}, len(supportedGNMIProducts))
	for _, product := range supportedGNMIProducts {
		require.NotEmpty(t, product)
		_, duplicate := supported[product]
		require.False(t, duplicate, "duplicate supported product %q", product)
		supported[product] = struct{}{}
		definition, ok := gnmiProductDefinition(product)
		require.True(t, ok, "supported product %q has no definition", product)
		require.NotEmpty(t, definition.releaseTrain)
		require.NotNil(t, definition.parser)
	}

	contractProducts := make(map[string]struct{}, len(gnmiProductContracts))
	for key, contract := range gnmiProductContracts {
		require.NotNil(t, contract)
		require.Equal(t, key.Product, contract.Product)
		require.Equal(t, key.ReleaseTrain, contract.ReleaseTrain)
		_, supportedProduct := supported[key.Product]
		require.True(t, supportedProduct, "contract product %q is absent from supportedGNMIProducts", key.Product)
		definition, ok := gnmiProductDefinition(key.Product)
		require.True(t, ok)
		require.Equal(t, definition.releaseTrain, key.ReleaseTrain)
		require.NotEmpty(t, contract.OSFamily)
		require.NotNil(t, contract.ChassisPattern)
		require.NotNil(t, contract.versionParser)
		require.NotEmpty(t, contract.profiles)
		require.NotEmpty(t, contract.ApprovedEncodings)
		require.NotEmpty(t, contract.IdentityProbes)
		contractProducts[key.Product] = struct{}{}

		encodings := make(map[gnmipb.Encoding]struct{}, len(contract.ApprovedEncodings))
		for _, encoding := range contract.ApprovedEncodings {
			_, duplicate := encodings[encoding]
			require.False(t, duplicate, "%s has duplicate encoding %s", key.Product, encoding)
			encodings[encoding] = struct{}{}
		}
		versions := make(map[string]struct{}, len(contract.ApprovedGNMIVersions))
		for _, version := range contract.ApprovedGNMIVersions {
			require.NotEmpty(t, version)
			_, duplicate := versions[version]
			require.False(t, duplicate, "%s has duplicate gNMI protocol version %q", key.Product, version)
			versions[version] = struct{}{}
		}
		if key.Product == gnmiProductCatalyst9300 || key.Product == gnmiProductCatalyst9500 {
			require.Equal(t, []string{"0.4.0"}, contract.ApprovedGNMIVersions)
			require.Equal(t, []string{gnmiReviewedIOSXESwitchRelease17181}, contract.ApprovedSoftwareVersions)
			require.Len(t, contract.RequiredModelData, 7)
			for name, model := range contract.RequiredModelData {
				require.True(t, gnmiYANGIdentifierPattern.MatchString(name))
				require.NotEmpty(t, model.Organization)
				require.NotEmpty(t, model.Versions)
				versions := make(map[string]struct{}, len(model.Versions))
				for _, version := range model.Versions {
					require.NotEmpty(t, version)
					_, duplicate := versions[version]
					require.False(t, duplicate, "%s has duplicate ModelData version %q for %s", key.Product, version, name)
					versions[version] = struct{}{}
				}
			}
		} else {
			require.Empty(t, contract.RequiredModelData)
		}

		probeNames := make(map[string]struct{}, len(contract.IdentityProbes))
		for _, probe := range contract.IdentityProbes {
			require.NotEmpty(t, probe.Name)
			require.NotEmpty(t, probe.Model)
			require.NotEmpty(t, probe.Paths)
			_, duplicate := probeNames[probe.Name]
			require.False(t, duplicate, "%s has duplicate identity probe %q", key.Product, probe.Name)
			probeNames[probe.Name] = struct{}{}
		}
		for name, profile := range contract.profiles {
			require.Equal(t, name, profile.Name)
		}
	}
	assert.Equal(t, supported, contractProducts)
}

func TestGNMIContractVersionParserDistinguishesMalformedAndWrongTrain(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductASR9000, "24.4.2")
	require.NoError(t, err)

	parsed, err := contract.ParseSoftwareVersion("25.1.3")
	require.NoError(t, err)
	assert.Equal(t, "25.1", parsed.Train)
	assert.Equal(t, "25.1.3", parsed.Canonical)

	_, _, err = resolveGNMIProductContract(gnmiProductASR9000, "25.1.3")
	require.ErrorContains(t, err, "requires release train 24.4")
	_, err = contract.ParseSoftwareVersion("IOS XR 24.4.2")
	require.ErrorContains(t, err, "must use major.minor.maintenance")
}

func TestGNMIProductContractAcceptedVersionSyntaxes(t *testing.T) {
	tests := []struct {
		product, version, canonical string
	}{
		{gnmiProductCatalyst9300, "17.18.1", "17.18.1"},
		{gnmiProductCatalyst9500, "017.018.001", "17.18.1"},
		{gnmiProductCatalyst9800, "17.18.0", "17.18.0"},
		{gnmiProductCatalyst9800, "017.018.001A", "17.18.1a"},
		{gnmiProductASR9000, "24.4.0", "24.4.0"},
		{gnmiProductNCS5500, "024.004.002", "24.4.2"},
		{gnmiProductNexus9000, "10.6(1)", "10.6(1)"},
		{gnmiProductNexus9000, "010.006(001)f", "10.6(1)F"},
		{gnmiProductNexus9000, "10.6(2n)F", "10.6(2n)F"},
		{gnmiProductNexus9000, "010.006(001S)f", "10.6(1s)F"},
		{gnmiProductNexus3500, "10.5(3)M", "10.5(3)M"},
		{gnmiProductNexus3500, "010.005(003)f", "10.5(3)F"},
	}
	for _, test := range tests {
		t.Run(test.product+"/"+test.version, func(t *testing.T) {
			_, parsed, err := resolveGNMIProductContract(test.product, test.version)
			require.NoError(t, err)
			assert.Equal(t, test.canonical, parsed.Canonical)
		})
	}
}

func TestGNMICatalystSwitchContractsRejectUnreviewedReleaseWithinTrain(t *testing.T) {
	for _, product := range []string{gnmiProductCatalyst9300, gnmiProductCatalyst9500} {
		for _, version := range []string{"17.18.0", "17.18.1a", "17.18.2", "17.18.99"} {
			t.Run(product+"/"+version, func(t *testing.T) {
				contract, parsed, err := resolveGNMIProductContract(product, version)
				require.ErrorContains(t, err, "permits only reviewed release(s): 17.18.1")
				assert.Nil(t, contract)
				assert.Equal(t, version, parsed.Canonical)
			})
		}
	}
}

func TestGNMIProductContractRejectsWrongTrainForEveryProduct(t *testing.T) {
	tests := []struct {
		product, version, train string
	}{
		{gnmiProductCatalyst9300, "17.17.1", gnmiReleaseTrainIOSXE1718},
		{gnmiProductCatalyst9500, "17.19.1", gnmiReleaseTrainIOSXE1718},
		{gnmiProductCatalyst9800, "17.17.1", gnmiReleaseTrainIOSXE1718},
		{gnmiProductASR9000, "24.5.1", gnmiReleaseTrainIOSXR244},
		{gnmiProductNCS5500, "25.1.1", gnmiReleaseTrainIOSXR244},
		{gnmiProductNexus9000, "10.5(1)", gnmiReleaseTrainNXOS106},
		{gnmiProductNexus3500, "10.6(1)", gnmiReleaseTrainNXOS105},
	}
	for _, test := range tests {
		t.Run(test.product, func(t *testing.T) {
			_, _, err := resolveGNMIProductContract(test.product, test.version)
			require.ErrorContains(t, err, "requires release train "+test.train)
		})
	}
}

func TestGNMIProductContractRejectsMalformedOrUnsupportedConfiguration(t *testing.T) {
	tests := []struct {
		name, product, version, want string
	}{
		{name: "missing product", version: "24.4.1", want: "product must be one of"},
		{name: "noncanonical product spelling", product: "ASR_9000", version: "24.4.1", want: "product must be one of"},
		{name: "SONiC is unsupported", product: "sonic", version: "SONiC.202411.1", want: "SONiC"},
		{name: "Cisco SONiC alias is unsupported", product: "cisco_sonic", version: "SONiC.202411.1", want: "SONiC"},
		{name: "missing version", product: gnmiProductASR9000, want: "software_version is required"},
		{name: "xe wrong shape", product: gnmiProductCatalyst9800, version: "17.18(1)", want: "invalid"},
		{name: "xe internal install form is observation-only", product: gnmiProductCatalyst9800, version: "17.18.01.0.1186", want: "invalid"},
		{name: "xr suffix", product: gnmiProductASR9000, version: "24.4.1a", want: "invalid"},
		{name: "nx wrong shape", product: gnmiProductNexus9000, version: "10.6.1", want: "invalid"},
		{name: "nx trailing suffix separator", product: gnmiProductNexus9000, version: "10.6(1)F-", want: "invalid"},
		{name: "nx repeated suffix separator", product: gnmiProductNexus9000, version: "10.6(1)F..1", want: "invalid"},
		{name: "nx multi-character image suffix", product: gnmiProductNexus9000, version: "10.6(1)F1", want: "invalid"},
		{name: "nx multi-character maintenance suffix", product: gnmiProductNexus9000, version: "10.6(1ab)F", want: "invalid"},
		{name: "surrounding whitespace", product: gnmiProductNexus9000, version: " 10.6(1)", want: "without surrounding whitespace"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := resolveGNMIProductContract(test.product, test.version)
			require.ErrorContains(t, err, test.want)
		})
	}
}

func TestParseIOSXEInstallSoftwareVersion(t *testing.T) {
	for _, test := range []struct {
		version   string
		canonical string
	}{
		{version: "17.18.1", canonical: "17.18.1"},
		{version: "17.18.01a", canonical: "17.18.1a"},
		{version: "17.18.01.0", canonical: "17.18.1"},
		{version: "17.18.01.0.1186", canonical: "17.18.1"},
		{version: "017.018.001A.0.0001186", canonical: "17.18.1a"},
	} {
		parsed, err := parseIOSXEInstallSoftwareVersion(test.version)
		require.NoError(t, err)
		assert.Equal(t, test.canonical, parsed.Canonical)
		assert.Equal(t, gnmiReleaseTrainIOSXE1718, parsed.Train)
	}

	for _, version := range []string{"17.18.1.1.1186", "17.18.1.0.12345678901", "17.18.1.0.1.extra"} {
		_, err := parseIOSXEInstallSoftwareVersion(version)
		require.Error(t, err, version)
	}
}

func TestGNMIProductContractChassisFamiliesAreAnchored(t *testing.T) {
	tests := []struct {
		product, version   string
		accepted, rejected []string
	}{
		{
			gnmiProductCatalyst9300,
			"17.18.1",
			[]string{"C9300-48P", "c9300l-48p-4x", "C9300L-48UXG-2Q", "C9300X-24Y"},
			[]string{"C9300", "XC9300-48P", "C9300LM-48UX-4Y", "C9300XL-24Y", "C9300-NM-8X", "C9300-0", "C9300-48P-E", "C9500-16X"},
		},
		{
			gnmiProductCatalyst9500,
			"17.18.1",
			[]string{"C9500-12Q", "C9500-40X", "C9500-16X", "c9500-24y4c", "C9500-32QC", "C9500X-28C8D", "C9500X-60L4D"},
			[]string{"C9500", "XC9500-16X", "C9500H-24Y4C", "C9500-NM-8X", "C9500-0", "C9500-48X", "C9500-16X-A", "C9300-48P"},
		},
		{gnmiProductCatalyst9800, "17.18.1", []string{"C9800-40-K9", "cat9800-cl"}, []string{"C9800", "X-C9800-40-K9", "C9300-48P"}},
		{gnmiProductASR9000, "24.4.1", []string{"ASR-9904", "asr-9001"}, []string{"ASR-1000", "XASR-9904"}},
		{gnmiProductNCS5500, "24.4.1", []string{"NCS-5501-SE", "ncs-55a2-mod-se"}, []string{"NCS-540", "XNCS-5501"}},
		{gnmiProductNexus9000, "10.6(1)", []string{"N9K-C93180YC-FX3"}, []string{"N3K-C3548P", "XN9K-C93180"}},
		{gnmiProductNexus3500, "10.5(1)", []string{"N3K-C3548P-10GX"}, []string{"N3K-C3064PQ", "XN3K-C3548P"}},
	}
	for _, test := range tests {
		t.Run(test.product, func(t *testing.T) {
			contract, _, err := resolveGNMIProductContract(test.product, test.version)
			require.NoError(t, err)
			for _, chassis := range test.accepted {
				assert.True(t, contract.MatchesChassis(chassis), chassis)
			}
			for _, chassis := range test.rejected {
				assert.False(t, contract.MatchesChassis(chassis), chassis)
			}
		})
	}
}

func TestRequiredGNMIModelsIncludesIdentityProfilesAndCustomOrigins(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9800, "17.18.1")
	require.NoError(t, err)
	streams, err := buildSharedGNMIStreams(GNMITargetConfig{
		Product:         gnmiProductCatalyst9800,
		SoftwareVersion: "17.18.1",
		MaxStreams:      5,
		CustomSubscriptions: []GNMICustomSubscriptionConfig{{
			Name: "custom", Origin: "example-custom-model", Mode: gnmiModeStream,
			SampleInterval: 1, Mappings: []GNMIMetricMappingConfig{{
				Path: "state/value", MetricName: "example.value", Description: "Example value", Unit: "1",
				Scale: floatPtr(1), GaugeType: "int", PathKeys: map[string]string{"state.name": "example.name"},
			}},
		}},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"Cisco-IOS-XE-device-hardware-oper",
		"Cisco-IOS-XE-install-oper",
		"Cisco-IOS-XE-platform-software-oper",
		"Cisco-IOS-XE-process-cpu-oper",
		"example-custom-model",
		"openconfig-interfaces",
		"openconfig-system",
	}, requiredGNMIModels(contract, streams))
}

func TestRequiredGNMIModelsIncludesQualifiedRFC7951CustomPath(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9800, "17.18.1")
	require.NoError(t, err)
	models := requiredGNMIModels(contract, []sharedGNMIStream{{Paths: []sharedGNMIPath{{
		Origin: builtinGNMIOriginRFC7951,
		Path:   "example-custom-model:state/value",
	}}}})
	assert.Contains(t, models, "example-custom-model")
}

func TestRequiredGNMIModelsDoesNotTreatIPv6ListKeyAsModuleQualifier(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductASR9000, "24.4.1")
	require.NoError(t, err)
	models := requiredGNMIModels(contract, []sharedGNMIStream{{Paths: []sharedGNMIPath{{
		Origin: "openconfig-bgp",
		Path:   "neighbor[address=2001:db8::1]/state/session-state",
	}}}})
	assert.Contains(t, models, "Cisco-IOS-XR-install-oper")
	assert.Contains(t, models, "openconfig-bgp")
	for _, model := range models {
		assert.NotContains(t, model, "neighbor[address=2001")
	}
}

func TestRequiredGNMIModelsIncludesEveryQualifiedSelectorAndMappingModule(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9800, "17.18.1")
	require.NoError(t, err)
	stream := sharedGNMIStream{
		Paths: []sharedGNMIPath{{
			Origin: builtinGNMIOriginRFC7951,
			Path:   "openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state",
		}},
		Mappings: []builtinGNMIMapping{{Mapping: internalgnmi.Mapping{Source: internalgnmi.SourcePath{
			Origin: builtinGNMIOriginRFC7951,
			Elements: []string{
				"openconfig-interfaces:interfaces", "interface", "openconfig-if-aggregate:aggregation",
			},
			Leaf: "openconfig-if-ethernet:port-speed",
		}}}},
	}
	models := requiredGNMIModels(contract, []sharedGNMIStream{stream})
	for _, model := range []string{"openconfig-interfaces", "openconfig-if-ethernet", "openconfig-if-aggregate"} {
		assert.Contains(t, models, model)
	}
}

func TestRequiredGNMIModelsPreservesCaseDistinctModuleNames(t *testing.T) {
	models := requiredGNMIModels(nil, []sharedGNMIStream{{Paths: []sharedGNMIPath{
		{Origin: builtinGNMIOriginRFC7951, Path: "Foo:state/value"},
		{Origin: builtinGNMIOriginRFC7951, Path: "foo:state/value"},
	}}})
	assert.Equal(t, []string{"Foo", "foo"}, models)
}

func TestRequiredGNMIModelsCoversEveryEnabledProductProfile(t *testing.T) {
	tests := []struct {
		product, version string
		models           []string
	}{
		{
			product: gnmiProductCatalyst9300, version: "17.18.1",
			models: []string{
				"Cisco-IOS-XE-device-hardware-oper", "Cisco-IOS-XE-install-oper", "Cisco-IOS-XE-platform-software-oper",
				"Cisco-IOS-XE-process-cpu-oper", "Cisco-IOS-XE-transceiver-oper",
				"openconfig-interfaces", "openconfig-system",
			},
		},
		{
			product: gnmiProductCatalyst9500, version: "17.18.1",
			models: []string{
				"Cisco-IOS-XE-device-hardware-oper", "Cisco-IOS-XE-install-oper", "Cisco-IOS-XE-platform-software-oper",
				"Cisco-IOS-XE-process-cpu-oper", "Cisco-IOS-XE-transceiver-oper",
				"openconfig-interfaces", "openconfig-system",
			},
		},
		{
			product: gnmiProductCatalyst9800, version: "17.18.1",
			models: []string{
				"Cisco-IOS-XE-device-hardware-oper", "Cisco-IOS-XE-install-oper", "Cisco-IOS-XE-platform-software-oper",
				"Cisco-IOS-XE-process-cpu-oper", "Cisco-IOS-XE-transceiver-oper",
				"Cisco-IOS-XE-wireless-access-point-oper", "Cisco-IOS-XE-wireless-ap-global-oper", "Cisco-IOS-XE-wireless-rrm-oper",
				"openconfig-interfaces", "openconfig-system",
			},
		},
		{
			product: gnmiProductASR9000, version: "24.4.1",
			models: []string{
				"Cisco-IOS-XR-controller-optics-oper", "Cisco-IOS-XR-install-oper",
				"Cisco-IOS-XR-wdsysmon-fd-oper", "openconfig-interfaces",
			},
		},
		{
			product: gnmiProductNCS5500, version: "24.4.1",
			models: []string{
				"Cisco-IOS-XR-controller-optics-oper", "Cisco-IOS-XR-install-oper",
				"Cisco-IOS-XR-wdsysmon-fd-oper", "openconfig-interfaces",
			},
		},
		{
			product: gnmiProductNexus9000, version: "10.6(1)",
			models: []string{"DME", "openconfig-interfaces", "openconfig-platform", "openconfig-system"},
		},
		{
			product: gnmiProductNexus3500, version: "10.5(1)",
			models: []string{"DME", "openconfig-interfaces", "openconfig-platform", "openconfig-system"},
		},
	}

	for _, test := range tests {
		t.Run(test.product, func(t *testing.T) {
			target := subscriptionTestTarget(test.product, 8)
			target.SoftwareVersion = test.version
			enabled := true
			target.Profiles.Identity.Enabled = &enabled
			if test.product != gnmiProductNexus9000 && test.product != gnmiProductNexus3500 {
				target.Profiles.System.Enabled = &enabled
			}
			target.Profiles.Interfaces.Enabled = &enabled
			target.Profiles.Optics.Enabled = &enabled
			if test.product == gnmiProductCatalyst9800 {
				target.Profiles.Catalyst9800Wireless.Enabled = &enabled
			}
			contract, _, err := resolveGNMIProductContract(test.product, test.version)
			require.NoError(t, err)
			streams, err := buildSharedGNMIStreams(target)
			require.NoError(t, err)
			assert.Len(t, streams, estimateGNMIStreamsForContract(target, contract))
			models := requiredGNMIModels(contract, streams)
			assert.Equal(t, test.models, models)
			assert.NotContains(t, models, "openconfig", "wire origins must not be treated as Capabilities model names")
			if test.product == gnmiProductCatalyst9300 || test.product == gnmiProductCatalyst9500 {
				for _, model := range models {
					assert.Contains(t, contract.RequiredModelData, model,
						"every built-in switch model must have an exact Capabilities catalog contract")
				}
			}
		})
	}
}

func floatPtr(value float64) *float64 { return &value }
