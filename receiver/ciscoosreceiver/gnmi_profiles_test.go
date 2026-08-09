// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

func TestBuiltinGNMIProfileCoverageAndDefaults(t *testing.T) {
	expected := map[string][]string{
		builtinGNMIPlatformIOSXE: {builtinGNMIProfileIdentity, builtinGNMIProfileSystem, builtinGNMIProfileInterfaces, builtinGNMIProfileOptics, builtinGNMIProfileCatalyst9800Wireless},
		builtinGNMIPlatformIOSXR: {builtinGNMIProfileIdentity, builtinGNMIProfileSystem, builtinGNMIProfileInterfaces, builtinGNMIProfileOptics},
		builtinGNMIPlatformNXOS:  {builtinGNMIProfileIdentity, builtinGNMIProfileSystem, builtinGNMIProfileInterfaces, builtinGNMIProfileOptics},
	}

	for platform, expectedNames := range expected {
		t.Run(platform, func(t *testing.T) {
			profiles := builtinGNMIProfiles(platform)
			names := make([]string, 0, len(profiles))
			for _, profile := range profiles {
				names = append(names, profile.Name)
				switch profile.Name {
				case builtinGNMIProfileIdentity:
					assert.True(t, profile.DefaultEnabled)
					assert.Equal(t, 5*time.Minute, profile.DefaultInterval)
				case builtinGNMIProfileSystem, builtinGNMIProfileInterfaces:
					assert.True(t, profile.DefaultEnabled)
					assert.Equal(t, time.Minute, profile.DefaultInterval)
				case builtinGNMIProfileOptics:
					assert.False(t, profile.DefaultEnabled)
					assert.Equal(t, 30*time.Second, profile.DefaultInterval)
				}
			}
			assert.ElementsMatch(t, expectedNames, names)
		})
	}

	assert.Empty(t, builtinGNMIProfiles("sonic"))
}

func TestBuiltinGNMIPlatformOriginsAndOpticalSources(t *testing.T) {
	for _, profile := range builtinGNMIProfiles(builtinGNMIPlatformIOSXE) {
		for _, path := range profile.Paths {
			assert.Equal(t, builtinGNMIOriginRFC7951, path.Origin, path.ID)
			first := strings.Split(path.Path, "/")[0]
			assert.Contains(t, first, ":", path.ID)
		}
	}

	xrOptics, ok := builtinGNMIProfile(builtinGNMIPlatformIOSXR, builtinGNMIProfileOptics)
	require.True(t, ok)
	xrPaths := pathsByID(xrOptics)
	assertPathDefinition(t, xrPaths["optics.controllers"], "Cisco-IOS-XR-controller-optics-oper", "optics-oper/optics-ports/optics-port/optics-info", false)
	assertPathDefinition(t, xrPaths["optics.lanes"], "Cisco-IOS-XR-controller-optics-oper", "optics-oper/optics-ports/optics-port/optics-lane-info", false)
	assertPathDefinition(t, xrPaths["optics.coherent"], "Cisco-IOS-XR-controller-optics-oper", "optics-oper/optics-ports/optics-port/optics-info", true)
	assertPathDefinition(t, xrPaths["optics.otu"], "Cisco-IOS-XR-controller-otu-oper", "otu/controllers/controller/info", true)

	nxOptics, ok := builtinGNMIProfile(builtinGNMIPlatformNXOS, builtinGNMIProfileOptics)
	require.True(t, ok)
	nxPaths := pathsByID(nxOptics)
	dmePath := nxPaths["optics.dme.sensors"]
	assertPathDefinition(t, dmePath, builtinGNMIOriginDME, "sys/intf", true)
	assert.NotContains(t, dmePath.Path, "Cisco-NX-OS-device:System")
	assert.NotContains(t, nxPaths, "optics.device.dom", "DME distinguished names must not be confused with the device-YANG representation")

	nxOrigins := map[string]bool{}
	for _, profile := range builtinGNMIProfiles(builtinGNMIPlatformNXOS) {
		for _, path := range profile.Paths {
			nxOrigins[path.Origin] = true
		}
	}
	assert.True(t, nxOrigins[builtinGNMIOriginDME])
	assert.True(t, nxOrigins[builtinGNMIOriginNXDevice])
	assert.True(t, nxOrigins["openconfig-system"])
	assert.True(t, nxOrigins["openconfig-interfaces"])
}

func TestBuiltinGNMIMappingsValidateAndReuseBaselineContract(t *testing.T) {
	baseline := []string{
		"cisco.device.up",
		"system.cpu.utilization",
		"system.memory.utilization",
		"system.uptime",
		"system.network.interface.status",
		"system.network.io",
		"system.network.errors",
		"system.network.packet.count",
		"system.network.packet.dropped",
		"cisco.interface.admin.status",
		"cisco.interface.speed",
		"cisco.interface.io.rate",
		"cisco.interface.packet.rate",
		"cisco.interface.utilization",
	}

	for _, platform := range []string{builtinGNMIPlatformIOSXE, builtinGNMIPlatformIOSXR, builtinGNMIPlatformNXOS} {
		t.Run(platform, func(t *testing.T) {
			catalogMappings := mappingsForPlatform(platform)
			sharedMappings := make([]internalgnmi.Mapping, 0, len(catalogMappings))
			names := map[string]bool{}
			for _, catalogMapping := range catalogMappings {
				sharedMappings = append(sharedMappings, catalogMapping.Mapping)
				names[catalogMapping.Mapping.Metric.Name] = true
			}
			registry, err := internalgnmi.NewRegistry(sharedMappings...)
			require.NoError(t, err)
			assert.Len(t, sharedMappings, registry.Len())
			for _, name := range baseline {
				assert.True(t, names[name], "missing %s on %s", name, platform)
				assert.Equal(t, builtinGNMIMetricMetadata[name], metricForName(t, catalogMappings, name))
			}
		})
	}
}

func TestBuiltinGNMIOpticsMetricUnitsAndExperimentalState(t *testing.T) {
	expected := map[string]string{
		"cisco.optics.temperature":          "Cel",
		"cisco.optics.voltage":              "V",
		"cisco.optics.laser_bias_current":   "mA",
		"cisco.optics.rx_power":             "dB[mW]",
		"cisco.optics.tx_power":             "dB[mW]",
		"cisco.optics.present":              "1",
		"cisco.optics.esnr":                 "dB",
		"cisco.optics.tdecq":                "dB",
		"cisco.optics.pre_fec_ber":          "1",
		"cisco.optics.tec_current":          "mA",
		"cisco.optics.tec_utilization":      "1",
		"cisco.optics.q_factor":             "dB",
		"cisco.optics.q_margin":             "dB",
		"cisco.optics.osnr":                 "dB",
		"cisco.optics.dgd":                  "ps",
		"cisco.optics.chromatic_dispersion": "ps/nm",
	}

	got := map[string]string{}
	for _, platform := range []string{builtinGNMIPlatformIOSXE, builtinGNMIPlatformIOSXR, builtinGNMIPlatformNXOS} {
		profile, ok := builtinGNMIProfile(platform, builtinGNMIProfileOptics)
		require.True(t, ok)
		for _, path := range profile.Paths {
			for _, catalogMapping := range path.Mappings {
				metric := catalogMapping.Mapping.Metric
				if strings.HasPrefix(metric.Name, "cisco.optics.") {
					got[metric.Name] = metric.Unit
				}
			}
		}
	}
	assert.Equal(t, expected, got)

	nx, _ := builtinGNMIProfile(builtinGNMIPlatformNXOS, builtinGNMIProfileOptics)
	for _, mapping := range pathsByID(nx)["optics.dme.sensors"].Mappings {
		if mapping.StaticAttributes["cisco.optics.profile"] == "vdm" {
			assert.Equal(t, "true", mapping.StaticAttributes["cisco.optics.experimental"])
		} else {
			assert.Equal(t, "dom", mapping.StaticAttributes["cisco.optics.profile"])
			assert.Equal(t, "false", mapping.StaticAttributes["cisco.optics.experimental"])
		}
	}
	xr, _ := builtinGNMIProfile(builtinGNMIPlatformIOSXR, builtinGNMIProfileOptics)
	for _, id := range []string{"optics.coherent", "optics.otu"} {
		for _, mapping := range pathsByID(xr)[id].Mappings {
			assert.Equal(t, "true", mapping.StaticAttributes["cisco.optics.experimental"])
			assert.Equal(t, "coherent", mapping.StaticAttributes["cisco.optics.profile"])
		}
	}
}

func TestNormalizeNXOpticsSensorStrictAllowlist(t *testing.T) {
	tests := []struct {
		name, description, sourceUnit, metric, outputUnit, profile string
		ok                                                         bool
	}{
		{name: "temperature", description: "Temperature", sourceUnit: "Cel", metric: "cisco.optics.temperature", outputUnit: "Cel", profile: "dom", ok: true},
		{name: "power converts UCUM spelling", description: "RX Power", sourceUnit: "dBm", metric: "cisco.optics.rx_power", outputUnit: "dB[mW]", profile: "dom", ok: true},
		{name: "TDECQ exact description", description: "  TdEcQ  ", sourceUnit: "dB", metric: "cisco.optics.tdecq", outputUnit: "dB", profile: "vdm", ok: true},
		{name: "TEC current", description: "TEC Current", sourceUnit: "mA", metric: "cisco.optics.tec_current", outputUnit: "mA", profile: "vdm", ok: true},
		{name: "TEC utilization", description: "TEC Utilization", sourceUnit: "1", metric: "cisco.optics.tec_utilization", outputUnit: "1", profile: "vdm", ok: true},
		{name: "TEC percentage scales to ratio", description: "TEC Utilization", sourceUnit: "%", metric: "cisco.optics.tec_utilization", outputUnit: "1", profile: "vdm", ok: true},
		{name: "PAM4 transition is not TDECQ", description: "PAM4 level transition parameter", sourceUnit: "dB", ok: false},
		{name: "TDECQ wrong unit", description: "TDECQ", sourceUnit: "1", ok: false},
		{name: "TDECQ heuristic suffix rejected", description: "TDECQ estimate", sourceUnit: "dB", ok: false},
		{name: "TEC unit mismatch", description: "TEC Current", sourceUnit: "1", ok: false},
		{name: "unknown numeric sensor", description: "sensor-42", sourceUnit: "dB", ok: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			definition, ok := normalizeNXOpticsSensor(test.description, test.sourceUnit)
			assert.Equal(t, test.ok, ok)
			if !test.ok {
				assert.Empty(t, definition.Metric.Name)
				return
			}
			assert.Equal(t, test.metric, definition.Metric.Name)
			assert.Equal(t, test.outputUnit, definition.Metric.Unit)
			assert.Equal(t, test.profile, definition.Profile)
			if test.sourceUnit == "%" {
				assert.Equal(t, 0.01, definition.Scale)
			} else {
				assert.Equal(t, 1.0, definition.Scale)
			}
		})
	}
}

func pathsByID(profile builtinGNMIProfileDefinition) map[string]builtinGNMIPathDefinition {
	out := make(map[string]builtinGNMIPathDefinition, len(profile.Paths))
	for pathIndex := range profile.Paths {
		path := profile.Paths[pathIndex]
		out[path.ID] = path
	}
	return out
}

func assertPathDefinition(t *testing.T, got builtinGNMIPathDefinition, origin, path string, experimental bool) {
	t.Helper()
	assert.Equal(t, origin, got.Origin)
	assert.Equal(t, path, got.Path)
	assert.Equal(t, experimental, got.Experimental)
}

func mappingsForPlatform(platform string) []builtinGNMIMapping {
	var out []builtinGNMIMapping
	for _, profile := range builtinGNMIProfiles(platform) {
		out = append(out, profile.SyntheticMappings...)
		for pathIndex := range profile.Paths {
			path := profile.Paths[pathIndex]
			out = append(out, path.Mappings...)
		}
	}
	return out
}

func metricForName(t *testing.T, mappings []builtinGNMIMapping, name string) internalgnmi.MetricMetadata {
	t.Helper()
	for i := range mappings {
		if mappings[i].Mapping.Metric.Name == name {
			return mappings[i].Mapping.Metric
		}
	}
	require.FailNow(t, "metric not found", name)
	return internalgnmi.MetricMetadata{}
}
