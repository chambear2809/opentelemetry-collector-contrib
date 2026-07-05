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
		gnmiProductCatalyst9800: {builtinGNMIProfileIdentity, builtinGNMIProfileSystem, builtinGNMIProfileInterfaces, builtinGNMIProfileOptics, builtinGNMIProfileCatalyst9800Wireless},
		gnmiProductASR9000:      {builtinGNMIProfileIdentity, builtinGNMIProfileSystem, builtinGNMIProfileInterfaces, builtinGNMIProfileOptics},
		gnmiProductNCS5500:      {builtinGNMIProfileIdentity, builtinGNMIProfileSystem, builtinGNMIProfileInterfaces, builtinGNMIProfileOptics},
		gnmiProductNexus9000:    {builtinGNMIProfileIdentity, builtinGNMIProfileInterfaces, builtinGNMIProfileOptics},
		gnmiProductNexus3500:    {builtinGNMIProfileIdentity, builtinGNMIProfileInterfaces, builtinGNMIProfileOptics},
	}

	for product, expectedNames := range expected {
		t.Run(product, func(t *testing.T) {
			profiles := builtinGNMIProfiles(profileTestContract(t, product))
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

	assert.Empty(t, builtinGNMIProfiles(nil))
}

func TestBuiltinGNMIPlatformOriginsAndOpticalSources(t *testing.T) {
	for _, profile := range builtinGNMIProfiles(profileTestContract(t, gnmiProductCatalyst9800)) {
		for _, path := range profile.Paths {
			assert.Equal(t, builtinGNMIOriginRFC7951, path.Origin, path.ID)
			first := strings.Split(path.Path, "/")[0]
			assert.Contains(t, first, ":", path.ID)
		}
	}

	xrContract := profileTestContract(t, gnmiProductASR9000)
	xrOptics, ok := builtinGNMIProfile(xrContract, builtinGNMIProfileOptics)
	require.True(t, ok)
	xrPaths := pathsByID(xrOptics)
	assertPathDefinition(t, xrPaths["optics.controllers"], "Cisco-IOS-XR-controller-optics-oper", "optics-oper/optics-ports/optics-port/optics-info", true)
	assertPathDefinition(t, xrPaths["optics.lanes"], "Cisco-IOS-XR-controller-optics-oper", "optics-oper/optics-ports/optics-port/optics-lanes/optics-lane", true)
	assert.NotContains(t, xrPaths, "optics.coherent")
	assert.NotContains(t, xrPaths, "optics.otu", "the scalar mapper cannot safely derive XR 24.4 OTU string and split-mantissa values")

	nxContract := profileTestContract(t, gnmiProductNexus9000)
	nxOptics, ok := builtinGNMIProfile(nxContract, builtinGNMIProfileOptics)
	require.True(t, ok)
	nxPaths := pathsByID(nxOptics)
	dmePath := nxPaths["optics.dme.sensors"]
	assertPathDefinition(t, dmePath, builtinGNMIOriginDME, "sys/intf", true)
	assert.NotContains(t, dmePath.Path, "Cisco-NX-OS-device:System")
	assert.NotContains(t, nxPaths, "optics.device.dom", "DME distinguished names must not be confused with the device-YANG representation")

	nxOrigins := map[string]bool{}
	for _, profile := range builtinGNMIProfiles(nxContract) {
		for _, path := range profile.Paths {
			nxOrigins[path.Origin] = true
		}
	}
	assert.True(t, nxOrigins[builtinGNMIOriginDME])
	assert.False(t, nxOrigins[builtinGNMIOriginNXDevice], "unverified device-YANG system paths must not be requested")
	assert.True(t, nxOrigins["openconfig"])
	assert.False(t, nxOrigins["openconfig-system"], "Capabilities module names are not NX-OS wire origins")
	assert.False(t, nxOrigins["openconfig-interfaces"], "Capabilities module names are not NX-OS wire origins")
	_, ok = builtinGNMIProfile(nxContract, builtinGNMIProfileSystem)
	assert.False(t, ok, "NX system metrics have no conservative common 10.5/10.6 source")
}

func TestBuiltinGNMIMappingsValidateAndReuseBaselineContract(t *testing.T) {
	interfaceMetrics := []string{
		"system.network.interface.status", "system.network.io", "system.network.errors",
		"system.network.packet.count", "system.network.packet.dropped", "cisco.interface.admin.status",
	}
	expected := map[string][]string{
		gnmiProductCatalyst9800: append([]string{"cisco.device.up", "system.cpu.utilization", "system.memory.utilization"}, interfaceMetrics...),
		gnmiProductASR9000:      append([]string{"cisco.device.up", "system.cpu.utilization"}, interfaceMetrics...),
		gnmiProductNexus9000:    append([]string{"cisco.device.up"}, interfaceMetrics...),
	}

	for product, expectedNames := range expected {
		t.Run(product, func(t *testing.T) {
			catalogMappings := mappingsForContract(profileTestContract(t, product))
			sharedMappings := make([]internalgnmi.Mapping, 0, len(catalogMappings))
			names := map[string]bool{}
			for _, catalogMapping := range catalogMappings {
				sharedMappings = append(sharedMappings, catalogMapping.Mapping)
				names[catalogMapping.Mapping.Metric.Name] = true
			}
			registry, err := internalgnmi.NewRegistry(sharedMappings...)
			require.NoError(t, err)
			assert.Len(t, sharedMappings, registry.Len())
			for _, name := range expectedNames {
				assert.True(t, names[name], "missing %s on %s", name, product)
				assert.Equal(t, builtinGNMIMetricMetadata[name], metricForName(t, catalogMappings, name))
			}
			assert.False(t, names["system.uptime"], "exact packaged trains expose boot time, not uptime")
			for _, unsupported := range []string{"cisco.interface.speed", "cisco.interface.io.rate", "cisco.interface.packet.rate", "cisco.interface.utilization"} {
				assert.False(t, names[unsupported], "OpenConfig interface state has no %s source", unsupported)
			}
		})
	}
}

func TestBuiltinGNMIOpticsMetricUnitsAndExperimentalState(t *testing.T) {
	expected := map[string]string{
		"cisco.optics.temperature":        "Cel",
		"cisco.optics.voltage":            "V",
		"cisco.optics.laser_bias_current": "mA",
		"cisco.optics.rx_power":           "dB[mW]",
		"cisco.optics.tx_power":           "dB[mW]",
		"cisco.optics.present":            "1",
		"cisco.optics.esnr":               "dB",
		"cisco.optics.tdecq":              "dB",
		"cisco.optics.pre_fec_ber":        "1",
		"cisco.optics.tec_current":        "mA",
		"cisco.optics.tec_utilization":    "1",
	}

	got := map[string]string{}
	for _, product := range []string{gnmiProductCatalyst9800, gnmiProductASR9000, gnmiProductNexus9000} {
		profile, ok := builtinGNMIProfile(profileTestContract(t, product), builtinGNMIProfileOptics)
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

	nx, _ := builtinGNMIProfile(profileTestContract(t, gnmiProductNexus9000), builtinGNMIProfileOptics)
	for _, mapping := range pathsByID(nx)["optics.dme.sensors"].Mappings {
		assert.Equal(t, "true", mapping.StaticAttributes["cisco.optics.experimental"])
	}
	xr, _ := builtinGNMIProfile(profileTestContract(t, gnmiProductASR9000), builtinGNMIProfileOptics)
	for _, id := range []string{"optics.controllers", "optics.lanes"} {
		for _, mapping := range pathsByID(xr)[id].Mappings {
			assert.Equal(t, "true", mapping.StaticAttributes["cisco.optics.experimental"])
			assert.Equal(t, "dom", mapping.StaticAttributes["cisco.optics.profile"])
		}
	}
	xe, _ := builtinGNMIProfile(profileTestContract(t, gnmiProductCatalyst9800), builtinGNMIProfileOptics)
	for _, mapping := range pathsByID(xe)["optics.dom"].Mappings {
		assert.Equal(t, "true", mapping.StaticAttributes["cisco.optics.experimental"])
	}
}

func TestBuiltinGNMIExactTrainSystemSources(t *testing.T) {
	xe, ok := builtinGNMIProfile(profileTestContract(t, gnmiProductCatalyst9800), builtinGNMIProfileSystem)
	require.True(t, ok)
	require.Len(t, xe.Paths, 2)
	xePaths := pathsByID(xe)
	assert.ElementsMatch(t, []string{"system.cpu", "system.memory"}, []string{xe.Paths[0].ID, xe.Paths[1].ID})
	assert.NotContains(t, xePaths, "system.uptime")
	assertPathDefinition(t, xePaths["system.memory"], builtinGNMIOriginRFC7951, "Cisco-IOS-XE-platform-software-oper:cisco-platform-software/control-processes/control-process/memory-stats", false)
	require.Len(t, xePaths["system.memory"].Mappings, 1)
	xeMemory := xePaths["system.memory"].Mappings[0].Mapping
	assert.Equal(t, []string{"Cisco-IOS-XE-platform-software-oper:cisco-platform-software", "control-processes", "control-process", "memory-stats"}, xeMemory.Source.Elements)
	assert.Equal(t, "used-percent", xeMemory.Source.Leaf)
	assert.Equal(t, .01, xeMemory.Scale)
	assert.Equal(t, []internalgnmi.KeyAttribute{
		{Element: "control-process", Key: "fru", Attribute: "cisco.location.fru"},
		{Element: "control-process", Key: "slot", Attribute: "cisco.location.slot"},
		{Element: "control-process", Key: "bay", Attribute: "cisco.location.bay"},
		{Element: "control-process", Key: "chassis", Attribute: "cisco.location.chassis"},
	}, xeMemory.KeyAttributes)

	xr, ok := builtinGNMIProfile(profileTestContract(t, gnmiProductASR9000), builtinGNMIProfileSystem)
	require.True(t, ok)
	require.Len(t, xr.Paths, 1, "XR memory is derived from two leaves and packaged OpenConfig has no uptime leaf")
	assert.Equal(t, "system.cpu", xr.Paths[0].ID)
	require.Len(t, xr.Paths[0].Mappings, 1)
	xrCPU := xr.Paths[0].Mappings[0].Mapping
	assert.Equal(t, "total-cpu-one-minute", xrCPU.Source.Leaf)
	assert.Equal(t, .01, xrCPU.Scale)
	assert.Equal(t, []internalgnmi.KeyAttribute{{Element: "cpu-utilization", Key: "node-name", Attribute: "cisco.node.name"}}, xrCPU.KeyAttributes)

	_, ok = builtinGNMIProfile(profileTestContract(t, gnmiProductNexus9000), builtinGNMIProfileSystem)
	assert.False(t, ok, "Cisco-NX-OS-device has no conservative common CPU/memory source in 10.5 and 10.6")
}

func TestBuiltinGNMIExactTrainOpenConfigInterfaceSources(t *testing.T) {
	expectedLeaves := []string{
		"oper-status", "admin-status", "in-octets", "out-octets", "in-errors", "out-errors",
		"in-discards", "out-discards", "in-unicast-pkts", "in-multicast-pkts", "in-broadcast-pkts",
		"out-unicast-pkts", "out-multicast-pkts", "out-broadcast-pkts",
	}
	for _, product := range []string{gnmiProductCatalyst9800, gnmiProductASR9000, gnmiProductNexus9000} {
		profile, ok := builtinGNMIProfile(profileTestContract(t, product), builtinGNMIProfileInterfaces)
		require.True(t, ok)
		require.Len(t, profile.Paths, 1)
		leaves := make([]string, 0, len(profile.Paths[0].Mappings))
		for _, catalogMapping := range profile.Paths[0].Mappings {
			mapping := catalogMapping.Mapping
			leaves = append(leaves, mapping.Source.Leaf)
			if mapping.Source.Leaf == "oper-status" || mapping.Source.Leaf == "admin-status" {
				assert.Equal(t, "state", mapping.Source.Elements[len(mapping.Source.Elements)-1])
			} else {
				assert.Equal(t, "counters", mapping.Source.Elements[len(mapping.Source.Elements)-1])
			}
		}
		assert.ElementsMatch(t, expectedLeaves, leaves, product)
	}
}

func TestBuiltinGNMIExactTrainOpticsSources(t *testing.T) {
	type sourceContract struct {
		metric string
		scale  float64
	}
	assertSources := func(t *testing.T, mappings []builtinGNMIMapping, expected map[string]sourceContract) {
		t.Helper()
		actual := make(map[string]sourceContract, len(mappings))
		for _, catalogMapping := range mappings {
			mapping := catalogMapping.Mapping
			parts := append(append([]string(nil), mapping.Source.Elements...), mapping.Source.Leaf)
			actual[strings.Join(parts, "/")] = sourceContract{metric: mapping.Metric.Name, scale: mapping.Scale}
			assert.Equal(t, "true", catalogMapping.StaticAttributes["cisco.optics.experimental"])
		}
		assert.Equal(t, expected, actual)
	}
	xeExpected := map[string]sourceContract{
		"Cisco-IOS-XE-transceiver-oper:transceiver-oper-data/transceiver/internal-temp":              {metric: "cisco.optics.temperature", scale: 1},
		"Cisco-IOS-XE-transceiver-oper:transceiver-oper-data/transceiver/voltage/instant":            {metric: "cisco.optics.voltage", scale: 1},
		"Cisco-IOS-XE-transceiver-oper:transceiver-oper-data/transceiver/laser-bias-current/instant": {metric: "cisco.optics.laser_bias_current", scale: 1},
		"Cisco-IOS-XE-transceiver-oper:transceiver-oper-data/transceiver/input-power/instant":        {metric: "cisco.optics.rx_power", scale: 1},
		"Cisco-IOS-XE-transceiver-oper:transceiver-oper-data/transceiver/output-power/instant":       {metric: "cisco.optics.tx_power", scale: 1},
		"Cisco-IOS-XE-transceiver-oper:transceiver-oper-data/transceiver/present":                    {metric: "cisco.optics.present", scale: 1},
	}
	xe, _ := builtinGNMIProfile(profileTestContract(t, gnmiProductCatalyst9800), builtinGNMIProfileOptics)
	assertSources(t, pathsByID(xe)["optics.dom"].Mappings, xeExpected)

	xrExpected := map[string]sourceContract{
		"optics-oper/optics-ports/optics-port/optics-info/temperature":                                {metric: "cisco.optics.temperature", scale: .01},
		"optics-oper/optics-ports/optics-port/optics-info/voltage":                                    {metric: "cisco.optics.voltage", scale: .01},
		"optics-oper/optics-ports/optics-port/optics-info/total-rx-power":                             {metric: "cisco.optics.rx_power", scale: .01},
		"optics-oper/optics-ports/optics-port/optics-info/total-tx-power":                             {metric: "cisco.optics.tx_power", scale: .01},
		"optics-oper/optics-ports/optics-port/optics-info/optics-present":                             {metric: "cisco.optics.present", scale: 1},
		"optics-oper/optics-ports/optics-port/optics-lanes/optics-lane/laser-bias-current-milli-amps": {metric: "cisco.optics.laser_bias_current", scale: .01},
		"optics-oper/optics-ports/optics-port/optics-lanes/optics-lane/receive-power":                 {metric: "cisco.optics.rx_power", scale: .01},
		"optics-oper/optics-ports/optics-port/optics-lanes/optics-lane/transmit-power":                {metric: "cisco.optics.tx_power", scale: .01},
	}
	xr, _ := builtinGNMIProfile(profileTestContract(t, gnmiProductASR9000), builtinGNMIProfileOptics)
	xrMappings := append([]builtinGNMIMapping(nil), pathsByID(xr)["optics.controllers"].Mappings...)
	xrMappings = append(xrMappings, pathsByID(xr)["optics.lanes"].Mappings...)
	assertSources(t, xrMappings, xrExpected)
	laneKeys := pathsByID(xr)["optics.lanes"].Mappings[0].Mapping.KeyAttributes
	assert.Equal(t, []internalgnmi.KeyAttribute{
		{Element: "optics-port", Key: "name", Attribute: "network.interface.name"},
		{Element: "optics-lane", Key: "number", Attribute: "cisco.optics.lane"},
	}, laneKeys)

	nx, _ := builtinGNMIProfile(profileTestContract(t, gnmiProductNexus9000), builtinGNMIProfileOptics)
	nxMappings := pathsByID(nx)["optics.dme.sensors"].Mappings
	require.Len(t, nxMappings, 20)
	families := map[string]int{}
	for _, catalogMapping := range nxMappings {
		families[catalogMapping.Mapping.Source.Elements[4]]++
		assert.Equal(t, "true", catalogMapping.StaticAttributes["cisco.optics.experimental"])
	}
	assert.Equal(t, map[string]int{"fcot": 10, "fcotdd": 10}, families)
}

func TestBuiltinGNMIWirelessSSIDUsesCompleteSchemaKey(t *testing.T) {
	profile, ok := builtinGNMIProfile(profileTestContract(t, gnmiProductCatalyst9800), builtinGNMIProfileCatalyst9800Wireless)
	require.True(t, ok)
	mappings := pathsByID(profile)["wireless.ssid"].Mappings
	require.Len(t, mappings, 1)
	assert.Equal(t, []internalgnmi.KeyAttribute{
		{Element: "ssid-counters", Key: "wtp-mac", Attribute: "cisco.wlc.ap.mac"},
		{Element: "ssid-counters", Key: "slot-id", Attribute: "cisco.wlc.radio.slot"},
		{Element: "ssid-counters", Key: "wlan-id", Attribute: "cisco.wlc.wlan.id"},
	}, mappings[0].Mapping.KeyAttributes)
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
	for _, path := range profile.Paths {
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

func mappingsForContract(contract *gnmiProductContract) []builtinGNMIMapping {
	var out []builtinGNMIMapping
	for _, profile := range builtinGNMIProfiles(contract) {
		out = append(out, profile.SyntheticMappings...)
		for _, path := range profile.Paths {
			out = append(out, path.Mappings...)
		}
	}
	return out
}

func profileTestContract(t *testing.T, product string) *gnmiProductContract {
	t.Helper()
	version := map[string]string{
		gnmiProductCatalyst9800: "17.18.1",
		gnmiProductASR9000:      "24.4.1",
		gnmiProductNCS5500:      "24.4.1",
		gnmiProductNexus9000:    "10.6(1)",
		gnmiProductNexus3500:    "10.5(1)",
	}[product]
	contract, _, err := resolveGNMIProductContract(product, version)
	require.NoError(t, err)
	return contract
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
