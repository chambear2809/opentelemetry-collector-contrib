// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"sort"
	"strings"
	"time"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

const (
	builtinGNMIPlatformIOSXE = "ios_xe"
	builtinGNMIPlatformIOSXR = "ios_xr"
	builtinGNMIPlatformNXOS  = "nx_os"

	builtinGNMIProfileIdentity             = "identity"
	builtinGNMIProfileSystem               = "system"
	builtinGNMIProfileInterfaces           = "interfaces"
	builtinGNMIProfileOptics               = "optics"
	builtinGNMIProfileCatalyst9800Wireless = "catalyst_9800_wireless"
	builtinGNMIOriginRFC7951               = "rfc7951"
	builtinGNMIOriginDME                   = "DME"
	builtinGNMIOriginNXDevice              = "Cisco-NX-OS-device"
	builtinGNMISyntheticReceiverOrigin     = "cisco_os"
)

// builtinGNMIMapping adds bounded, catalog-owned attributes to the shared
// explicit mapping contract. Dynamic attributes may only come from modeled
// PathElem keys declared by Mapping.KeyAttributes.
type builtinGNMIMapping struct {
	Mapping          internalgnmi.Mapping
	StaticAttributes map[string]string
}

// builtinGNMIPathDefinition is one subscription path. Origin and Path remain
// separate so request builders cannot accidentally encode "origin:path".
type builtinGNMIPathDefinition struct {
	ID           string
	Origin       string
	Path         string
	Experimental bool
	Mappings     []builtinGNMIMapping
}

type builtinGNMIProfileDefinition struct {
	Name              string
	DefaultEnabled    bool
	DefaultInterval   time.Duration
	SyntheticMappings []builtinGNMIMapping
	Paths             []builtinGNMIPathDefinition
}

// builtinGNMIProfiles returns profiles in stable name order. Catalog values are
// treated as immutable by receiver code.
func builtinGNMIProfiles(platform string) []builtinGNMIProfileDefinition {
	profiles := builtinGNMIProfileCatalog[platform]
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]builtinGNMIProfileDefinition, 0, len(names))
	for _, name := range names {
		out = append(out, profiles[name])
	}
	return out
}

func builtinGNMIProfile(platform, profile string) (builtinGNMIProfileDefinition, bool) {
	definition, ok := builtinGNMIProfileCatalog[platform][profile]
	return definition, ok
}

var builtinGNMIMetricMetadata = map[string]internalgnmi.MetricMetadata{
	"cisco.device.up":                 {Name: "cisco.device.up", Description: "Device availability (1 = up, 0 = down)", Unit: "1"},
	"system.cpu.utilization":          {Name: "system.cpu.utilization", Description: "Percentage of CPU time in use.", Unit: "1"},
	"system.memory.utilization":       {Name: "system.memory.utilization", Description: "Percentage of memory bytes in use.", Unit: "1"},
	"system.uptime":                   {Name: "system.uptime", Description: "The time the Cisco device has been running", Unit: "s"},
	"system.network.interface.status": {Name: "system.network.interface.status", Description: "Interface operational status (1 = up, 0 = down)", Unit: "1"},
	"system.network.io":               {Name: "system.network.io", Description: "The number of bytes transmitted and received", Unit: "By"},
	"system.network.errors":           {Name: "system.network.errors", Description: "The number of errors encountered", Unit: "{error}"},
	"system.network.packet.count":     {Name: "system.network.packet.count", Description: "The number of packets transmitted or received, categorized by type", Unit: "{packet}"},
	"system.network.packet.dropped":   {Name: "system.network.packet.dropped", Description: "The number of packets dropped", Unit: "{packet}"},
	"cisco.interface.admin.status":    {Name: "cisco.interface.admin.status", Description: "Cisco interface administrative status (1 = administratively enabled, 0 = administratively disabled)", Unit: "1"},
	"cisco.interface.speed":           {Name: "cisco.interface.speed", Description: "The numeric line speed of a Cisco interface", Unit: "bit/s"},
	"cisco.interface.io.rate":         {Name: "cisco.interface.io.rate", Description: "The device-reported interface traffic rate", Unit: "bit/s"},
	"cisco.interface.packet.rate":     {Name: "cisco.interface.packet.rate", Description: "The device-reported interface packet rate", Unit: "{packet}/s"},
	"cisco.interface.utilization":     {Name: "cisco.interface.utilization", Description: "Cisco interface traffic utilization as a ratio of line speed", Unit: "1"},

	"cisco.optics.temperature":          {Name: "cisco.optics.temperature", Description: "Optical module temperature", Unit: "Cel"},
	"cisco.optics.voltage":              {Name: "cisco.optics.voltage", Description: "Optical module supply voltage", Unit: "V"},
	"cisco.optics.laser_bias_current":   {Name: "cisco.optics.laser_bias_current", Description: "Optical transmitter laser bias current", Unit: "mA"},
	"cisco.optics.rx_power":             {Name: "cisco.optics.rx_power", Description: "Received optical power", Unit: "dB[mW]"},
	"cisco.optics.tx_power":             {Name: "cisco.optics.tx_power", Description: "Transmitted optical power", Unit: "dB[mW]"},
	"cisco.optics.present":              {Name: "cisco.optics.present", Description: "Optical module or lane presence (1 = present, 0 = absent)", Unit: "1"},
	"cisco.optics.esnr":                 {Name: "cisco.optics.esnr", Description: "Effective signal-to-noise ratio reported by a qualified VDM sensor", Unit: "dB"},
	"cisco.optics.tdecq":                {Name: "cisco.optics.tdecq", Description: "Transmitter and dispersion eye closure for PAM4 reported by a sensor explicitly identified as TDECQ in dB", Unit: "dB"},
	"cisco.optics.pre_fec_ber":          {Name: "cisco.optics.pre_fec_ber", Description: "Pre-forward-error-correction bit error ratio", Unit: "1"},
	"cisco.optics.tec_current":          {Name: "cisco.optics.tec_current", Description: "Thermoelectric cooler current when the device reports the sensor in milliamperes", Unit: "mA"},
	"cisco.optics.tec_utilization":      {Name: "cisco.optics.tec_utilization", Description: "Thermoelectric cooler utilization normalized to a unitless ratio", Unit: "1"},
	"cisco.optics.q_factor":             {Name: "cisco.optics.q_factor", Description: "Coherent optical Q-factor", Unit: "dB"},
	"cisco.optics.q_margin":             {Name: "cisco.optics.q_margin", Description: "Coherent optical Q-margin", Unit: "dB"},
	"cisco.optics.osnr":                 {Name: "cisco.optics.osnr", Description: "Coherent optical signal-to-noise ratio", Unit: "dB"},
	"cisco.optics.dgd":                  {Name: "cisco.optics.dgd", Description: "Coherent optical differential group delay", Unit: "ps"},
	"cisco.optics.chromatic_dispersion": {Name: "cisco.optics.chromatic_dispersion", Description: "Coherent optical chromatic dispersion", Unit: "ps/nm"},

	"cisco.wlc.ap.join.status":         {Name: "cisco.wlc.ap.join.status", Description: "Catalyst 9800 access point join status", Unit: "1"},
	"cisco.wlc.rf.channel.utilization": {Name: "cisco.wlc.rf.channel.utilization", Description: "Catalyst 9800 RF channel utilization ratio", Unit: "1"},
	"cisco.wlc.ssid.client.count":      {Name: "cisco.wlc.ssid.client.count", Description: "Catalyst 9800 associated client count", Unit: "{client}"},
}

var builtinGNMIProfileCatalog = map[string]map[string]builtinGNMIProfileDefinition{
	builtinGNMIPlatformIOSXE: iosXEBuiltinGNMIProfiles(),
	builtinGNMIPlatformIOSXR: iosXRBuiltinGNMIProfiles(),
	builtinGNMIPlatformNXOS:  nxOSBuiltinGNMIProfiles(),
}

func iosXEBuiltinGNMIProfiles() map[string]builtinGNMIProfileDefinition {
	return map[string]builtinGNMIProfileDefinition{
		builtinGNMIProfileIdentity: profileDefinition(builtinGNMIProfileIdentity, true, 5*time.Minute,
			[]builtinGNMIMapping{availabilityMapping(builtinGNMIPlatformIOSXE)},
			builtinGNMIPathDefinition{ID: "identity.system", Origin: builtinGNMIOriginRFC7951, Path: "openconfig-system:system/state"}),
		builtinGNMIProfileSystem: profileDefinition(builtinGNMIProfileSystem, true, time.Minute, nil,
			builtinGNMIPathDefinition{ID: "system.cpu", Origin: builtinGNMIOriginRFC7951, Path: "Cisco-IOS-XE-process-cpu-oper:cpu-usage/cpu-utilization", Mappings: []builtinGNMIMapping{mapping(builtinGNMIOriginRFC7951, []string{"Cisco-IOS-XE-process-cpu-oper:cpu-usage", "cpu-utilization"}, "five-seconds", "system.cpu.utilization", .01, internalgnmi.GaugeDouble, nil, nil)}},
			builtinGNMIPathDefinition{ID: "system.memory", Origin: builtinGNMIOriginRFC7951, Path: "Cisco-IOS-XE-memory-oper:memory-statistics/memory-statistic", Mappings: []builtinGNMIMapping{mapping(builtinGNMIOriginRFC7951, []string{"Cisco-IOS-XE-memory-oper:memory-statistics", "memory-statistic"}, "used-memory-percent", "system.memory.utilization", .01, internalgnmi.GaugeDouble, nil, nil)}},
			builtinGNMIPathDefinition{ID: "system.uptime", Origin: builtinGNMIOriginRFC7951, Path: "Cisco-IOS-XE-platform-software-oper:cisco-platform-software/control-processes/control-process", Mappings: []builtinGNMIMapping{mapping(builtinGNMIOriginRFC7951, []string{"Cisco-IOS-XE-platform-software-oper:cisco-platform-software", "control-processes", "control-process"}, "uptime", "system.uptime", 1, internalgnmi.GaugeInt, nil, nil)}}),
		builtinGNMIProfileInterfaces: profileDefinition(builtinGNMIProfileInterfaces, true, time.Minute, nil,
			builtinGNMIPathDefinition{ID: "interfaces.openconfig", Origin: builtinGNMIOriginRFC7951, Path: "openconfig-interfaces:interfaces/interface/state", Mappings: interfaceMappings(builtinGNMIOriginRFC7951, []string{"openconfig-interfaces:interfaces", "interface"})}),
		builtinGNMIProfileOptics: profileDefinition(builtinGNMIProfileOptics, false, 30*time.Second, nil,
			builtinGNMIPathDefinition{ID: "optics.dom", Origin: builtinGNMIOriginRFC7951, Path: "Cisco-IOS-XE-transceiver-oper:transceiver-oper-data/transceiver", Mappings: domMappings(builtinGNMIOriginRFC7951, []string{"Cisco-IOS-XE-transceiver-oper:transceiver-oper-data", "transceiver"}, "transceiver", "name", "", "", false)}),
		builtinGNMIProfileCatalyst9800Wireless: profileDefinition(builtinGNMIProfileCatalyst9800Wireless, false, time.Minute, nil,
			builtinGNMIPathDefinition{ID: "wireless.ap.join", Origin: builtinGNMIOriginRFC7951, Path: "Cisco-IOS-XE-wireless-ap-global-oper:ap-global-oper-data/ap-join-stats", Mappings: []builtinGNMIMapping{mapping(builtinGNMIOriginRFC7951, []string{"Cisco-IOS-XE-wireless-ap-global-oper:ap-global-oper-data", "ap-join-stats"}, "is-joined", "cisco.wlc.ap.join.status", 1, internalgnmi.GaugeInt, []internalgnmi.KeyAttribute{{Element: "ap-join-stats", Key: "wtp-mac", Attribute: "cisco.wlc.ap.mac"}}, nil)}},
			builtinGNMIPathDefinition{ID: "wireless.rf", Origin: builtinGNMIOriginRFC7951, Path: "Cisco-IOS-XE-wireless-rrm-oper:rrm-oper-data/rrm-measurement", Mappings: []builtinGNMIMapping{mapping(builtinGNMIOriginRFC7951, []string{"Cisco-IOS-XE-wireless-rrm-oper:rrm-oper-data", "rrm-measurement"}, "cca-util-percentage", "cisco.wlc.rf.channel.utilization", .01, internalgnmi.GaugeDouble, []internalgnmi.KeyAttribute{{Element: "rrm-measurement", Key: "wtp-mac", Attribute: "cisco.wlc.ap.mac"}, {Element: "rrm-measurement", Key: "radio-slot-id", Attribute: "cisco.wlc.radio.slot"}}, nil)}},
			builtinGNMIPathDefinition{ID: "wireless.ssid", Origin: builtinGNMIOriginRFC7951, Path: "Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data/ssid-counters", Mappings: []builtinGNMIMapping{mapping(builtinGNMIOriginRFC7951, []string{"Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data", "ssid-counters"}, "num-assoc-clients", "cisco.wlc.ssid.client.count", 1, internalgnmi.GaugeInt, []internalgnmi.KeyAttribute{{Element: "ssid-counters", Key: "wtp-mac", Attribute: "cisco.wlc.ap.mac"}, {Element: "ssid-counters", Key: "wlan-id", Attribute: "cisco.wlc.wlan.id"}}, nil)}}),
	}
}

func iosXRBuiltinGNMIProfiles() map[string]builtinGNMIProfileDefinition {
	const (
		opticsOrigin = "Cisco-IOS-XR-controller-optics-oper"
		otuOrigin    = "Cisco-IOS-XR-controller-otu-oper"
		miscOrigin   = "Cisco-IOS-XR-n" + "to-misc-oper"
	)
	return map[string]builtinGNMIProfileDefinition{
		builtinGNMIProfileIdentity: profileDefinition(builtinGNMIProfileIdentity, true, 5*time.Minute,
			[]builtinGNMIMapping{availabilityMapping(builtinGNMIPlatformIOSXR)}),
		builtinGNMIProfileSystem: profileDefinition(builtinGNMIProfileSystem, true, time.Minute, nil,
			builtinGNMIPathDefinition{ID: "system.cpu", Origin: "Cisco-IOS-XR-wdsysmon-fd-oper", Path: "system-monitoring/cpu-utilization", Mappings: []builtinGNMIMapping{mapping("Cisco-IOS-XR-wdsysmon-fd-oper", []string{"system-monitoring", "cpu-utilization"}, "total-cpu-one-minute", "system.cpu.utilization", .01, internalgnmi.GaugeDouble, nil, nil)}},
			builtinGNMIPathDefinition{ID: "system.memory", Origin: miscOrigin, Path: "memory-summary/nodes/node/summary", Mappings: []builtinGNMIMapping{mapping(miscOrigin, []string{"memory-summary", "nodes", "node", "summary"}, "memory-utilization", "system.memory.utilization", .01, internalgnmi.GaugeDouble, nil, nil)}},
			builtinGNMIPathDefinition{ID: "system.uptime", Origin: "openconfig-system", Path: "system/state", Mappings: []builtinGNMIMapping{mapping("openconfig-system", []string{"system", "state"}, "uptime", "system.uptime", 1, internalgnmi.GaugeInt, nil, nil)}}),
		builtinGNMIProfileInterfaces: profileDefinition(builtinGNMIProfileInterfaces, true, time.Minute, nil,
			builtinGNMIPathDefinition{ID: "interfaces.openconfig", Origin: "openconfig-interfaces", Path: "interfaces/interface/state", Mappings: interfaceMappings("openconfig-interfaces", []string{"interfaces", "interface"})}),
		builtinGNMIProfileOptics: profileDefinition(builtinGNMIProfileOptics, false, 30*time.Second, nil,
			builtinGNMIPathDefinition{ID: "optics.controllers", Origin: opticsOrigin, Path: "optics-oper/optics-ports/optics-port/optics-info", Mappings: domMappings(opticsOrigin, []string{"optics-oper", "optics-ports", "optics-port", "optics-info"}, "optics-port", "name", "", "", false)},
			builtinGNMIPathDefinition{ID: "optics.lanes", Origin: opticsOrigin, Path: "optics-oper/optics-ports/optics-port/optics-lane-info", Mappings: domMappings(opticsOrigin, []string{"optics-oper", "optics-ports", "optics-port", "optics-lane-info"}, "optics-port", "name", "optics-lane-info", "lane-index", false)},
			builtinGNMIPathDefinition{ID: "optics.coherent", Origin: opticsOrigin, Path: "optics-oper/optics-ports/optics-port/optics-info", Experimental: true, Mappings: coherentOpticsMappings(opticsOrigin, []string{"optics-oper", "optics-ports", "optics-port", "optics-info"}, "optics-port", "name")},
			builtinGNMIPathDefinition{ID: "optics.otu", Origin: otuOrigin, Path: "otu/controllers/controller/info", Experimental: true, Mappings: otuMappings(otuOrigin, []string{"otu", "controllers", "controller", "info"})}),
	}
}

func nxOSBuiltinGNMIProfiles() map[string]builtinGNMIProfileDefinition {
	return map[string]builtinGNMIProfileDefinition{
		builtinGNMIProfileIdentity: profileDefinition(builtinGNMIProfileIdentity, true, 5*time.Minute,
			[]builtinGNMIMapping{availabilityMapping(builtinGNMIPlatformNXOS)},
			builtinGNMIPathDefinition{ID: "identity.system", Origin: "openconfig-system", Path: "system/state"}),
		builtinGNMIProfileSystem: profileDefinition(builtinGNMIProfileSystem, true, time.Minute, nil,
			builtinGNMIPathDefinition{ID: "system.device", Origin: builtinGNMIOriginNXDevice, Path: "System/systemTable/sysEntry", Mappings: systemMappings(builtinGNMIOriginNXDevice, []string{"System", "systemTable", "sysEntry"}, "cpu-utilization", "memory-utilization", "uptime", .01, .01)}),
		builtinGNMIProfileInterfaces: profileDefinition(builtinGNMIProfileInterfaces, true, time.Minute, nil,
			builtinGNMIPathDefinition{ID: "interfaces.openconfig", Origin: "openconfig-interfaces", Path: "interfaces/interface/state", Mappings: interfaceMappings("openconfig-interfaces", []string{"interfaces", "interface"})}),
		builtinGNMIProfileOptics: profileDefinition(builtinGNMIProfileOptics, false, 30*time.Second, nil,
			// NX DME publishes a distinguished-name family, not the device YANG tree.
			// Subscribe at the nearest static ancestor; the explicit mapper accepts
			// only the sys/intf/phys-[...]/phys/fcotdd/lane-...-sensor-... family.
			builtinGNMIPathDefinition{ID: "optics.dme.sensors", Origin: builtinGNMIOriginDME, Path: "sys/intf", Experimental: true, Mappings: nxDMESensorMappings()}),
	}
}

func profileDefinition(name string, enabled bool, interval time.Duration, synthetic []builtinGNMIMapping, paths ...builtinGNMIPathDefinition) builtinGNMIProfileDefinition {
	return builtinGNMIProfileDefinition{Name: name, DefaultEnabled: enabled, DefaultInterval: interval, SyntheticMappings: synthetic, Paths: paths}
}

func availabilityMapping(platform string) builtinGNMIMapping {
	return mapping(builtinGNMISyntheticReceiverOrigin, []string{"target", platform}, "up", "cisco.device.up", 1, internalgnmi.GaugeInt, nil, nil)
}

func systemMappings(origin string, elements []string, cpuLeaf, memoryLeaf, uptimeLeaf string, cpuScale, memoryScale float64) []builtinGNMIMapping {
	return []builtinGNMIMapping{
		mapping(origin, elements, cpuLeaf, "system.cpu.utilization", cpuScale, internalgnmi.GaugeDouble, nil, nil),
		mapping(origin, elements, memoryLeaf, "system.memory.utilization", memoryScale, internalgnmi.GaugeDouble, nil, nil),
		mapping(origin, elements, uptimeLeaf, "system.uptime", 1, internalgnmi.GaugeInt, nil, nil),
	}
}

func interfaceMappings(origin string, root []string) []builtinGNMIMapping {
	state := appendElements(root, "state")
	counters := appendElements(state, "counters")
	key := []internalgnmi.KeyAttribute{{Element: "interface", Key: "name", Attribute: "network.interface.name"}}
	withDirection := func(direction string) map[string]string { return map[string]string{"network.io.direction": direction} }
	withPacket := func(direction, packetType string) map[string]string {
		return map[string]string{"network.io.direction": direction, "network.packet.type": packetType}
	}
	return []builtinGNMIMapping{
		mapping(origin, state, "oper-status", "system.network.interface.status", 1, internalgnmi.GaugeInt, key, nil),
		mapping(origin, state, "admin-status", "cisco.interface.admin.status", 1, internalgnmi.GaugeInt, key, nil),
		mapping(origin, state, "speed", "cisco.interface.speed", 1, internalgnmi.GaugeInt, key, nil),
		mapping(origin, state, "in-bps", "cisco.interface.io.rate", 1, internalgnmi.GaugeInt, key, withDirection("receive")),
		mapping(origin, state, "out-bps", "cisco.interface.io.rate", 1, internalgnmi.GaugeInt, key, withDirection("transmit")),
		mapping(origin, state, "in-pps", "cisco.interface.packet.rate", 1, internalgnmi.GaugeInt, key, withDirection("receive")),
		mapping(origin, state, "out-pps", "cisco.interface.packet.rate", 1, internalgnmi.GaugeInt, key, withDirection("transmit")),
		mapping(origin, state, "in-utilization", "cisco.interface.utilization", .01, internalgnmi.GaugeDouble, key, withDirection("receive")),
		mapping(origin, state, "out-utilization", "cisco.interface.utilization", .01, internalgnmi.GaugeDouble, key, withDirection("transmit")),
		sumMapping(origin, counters, "in-octets", "system.network.io", key, withDirection("receive")),
		sumMapping(origin, counters, "out-octets", "system.network.io", key, withDirection("transmit")),
		sumMapping(origin, counters, "in-errors", "system.network.errors", key, withDirection("receive")),
		sumMapping(origin, counters, "out-errors", "system.network.errors", key, withDirection("transmit")),
		sumMapping(origin, counters, "in-discards", "system.network.packet.dropped", key, withDirection("receive")),
		sumMapping(origin, counters, "out-discards", "system.network.packet.dropped", key, withDirection("transmit")),
		sumMapping(origin, counters, "in-unicast-pkts", "system.network.packet.count", key, withPacket("receive", "unicast")),
		sumMapping(origin, counters, "in-multicast-pkts", "system.network.packet.count", key, withPacket("receive", "multicast")),
		sumMapping(origin, counters, "in-broadcast-pkts", "system.network.packet.count", key, withPacket("receive", "broadcast")),
		sumMapping(origin, counters, "out-unicast-pkts", "system.network.packet.count", key, withPacket("transmit", "unicast")),
		sumMapping(origin, counters, "out-multicast-pkts", "system.network.packet.count", key, withPacket("transmit", "multicast")),
		sumMapping(origin, counters, "out-broadcast-pkts", "system.network.packet.count", key, withPacket("transmit", "broadcast")),
	}
}

func domMappings(origin string, elements []string, portElement, portKey, laneElement, laneKey string, experimental bool) []builtinGNMIMapping {
	keys := []internalgnmi.KeyAttribute{{Element: portElement, Key: portKey, Attribute: "network.interface.name"}}
	if laneElement != "" {
		keys = append(keys, internalgnmi.KeyAttribute{Element: laneElement, Key: laneKey, Attribute: "cisco.optics.lane"})
	}
	definitions := []struct {
		leaf, metric, sensor string
		gauge                internalgnmi.GaugeValueType
	}{
		{"temperature", "cisco.optics.temperature", "temperature", internalgnmi.GaugeDouble},
		{"voltage", "cisco.optics.voltage", "voltage", internalgnmi.GaugeDouble},
		{"laser-bias-current", "cisco.optics.laser_bias_current", "laser_bias_current", internalgnmi.GaugeDouble},
		{"rx-power", "cisco.optics.rx_power", "rx_power", internalgnmi.GaugeDouble},
		{"tx-power", "cisco.optics.tx_power", "tx_power", internalgnmi.GaugeDouble},
		{"present", "cisco.optics.present", "presence", internalgnmi.GaugeInt},
	}
	out := make([]builtinGNMIMapping, 0, len(definitions))
	for _, definition := range definitions {
		attrs := opticsAttributes("dom", definition.sensor, experimental)
		if definition.metric == "cisco.optics.present" {
			delete(attrs, "cisco.optics.sensor")
		}
		out = append(out, mapping(origin, elements, definition.leaf, definition.metric, 1, definition.gauge, keys, attrs))
	}
	return out
}

func coherentOpticsMappings(origin string, elements []string, portElement, portKey string) []builtinGNMIMapping {
	keys := []internalgnmi.KeyAttribute{{Element: portElement, Key: portKey, Attribute: "network.interface.name"}}
	definitions := []struct{ leaf, metric string }{
		{"q-margin", "cisco.optics.q_margin"},
		{"osnr", "cisco.optics.osnr"},
		{"dgd", "cisco.optics.dgd"},
		{"chromatic-dispersion", "cisco.optics.chromatic_dispersion"},
	}
	out := make([]builtinGNMIMapping, 0, len(definitions))
	for _, definition := range definitions {
		out = append(out, mapping(origin, elements, definition.leaf, definition.metric, 1, internalgnmi.GaugeDouble, keys, opticsAttributes("coherent", definition.leaf, true)))
	}
	return out
}

func otuMappings(origin string, elements []string) []builtinGNMIMapping {
	keys := []internalgnmi.KeyAttribute{{Element: "controller", Key: "name", Attribute: "network.interface.name"}}
	return []builtinGNMIMapping{
		mapping(origin, elements, "q-factor", "cisco.optics.q_factor", 1, internalgnmi.GaugeDouble, keys, opticsAttributes("coherent", "q_factor", true)),
		mapping(origin, elements, "pre-fec-ber", "cisco.optics.pre_fec_ber", 1, internalgnmi.GaugeDouble, keys, opticsAttributes("coherent", "pre_fec_ber", true)),
	}
}

func nxDMESensorMappings() []builtinGNMIMapping {
	origin := builtinGNMIOriginDME
	elements := []string{"sys", "intf", "phys", "phys", "fcotdd", "lane", "sensor"}
	keys := []internalgnmi.KeyAttribute{{Element: "phys", Key: "id", Attribute: "network.interface.name"}, {Element: "lane", Key: "id", Attribute: "cisco.optics.lane"}}
	definitions := []struct {
		leaf, metric, profile string
		experimental          bool
	}{
		{"temperature", "cisco.optics.temperature", "dom", false},
		{"voltage", "cisco.optics.voltage", "dom", false},
		{"laser-bias-current", "cisco.optics.laser_bias_current", "dom", false},
		{"rx-power", "cisco.optics.rx_power", "dom", false},
		{"tx-power", "cisco.optics.tx_power", "dom", false},
		{"esnr", "cisco.optics.esnr", "vdm", true},
		{"tdecq", "cisco.optics.tdecq", "vdm", true},
		{"pre-fec-ber", "cisco.optics.pre_fec_ber", "vdm", true},
		{"tec-current", "cisco.optics.tec_current", "vdm", true},
		{"tec-utilization", "cisco.optics.tec_utilization", "vdm", true},
	}
	out := make([]builtinGNMIMapping, 0, len(definitions))
	for _, definition := range definitions {
		out = append(out, mapping(origin, elements, definition.leaf, definition.metric, 1, internalgnmi.GaugeDouble, keys, opticsAttributes(definition.profile, definition.leaf, definition.experimental)))
	}
	return out
}

func mapping(origin string, elements []string, leaf, metricName string, scale float64, gauge internalgnmi.GaugeValueType, keys []internalgnmi.KeyAttribute, attrs map[string]string) builtinGNMIMapping {
	return builtinGNMIMapping{
		Mapping: internalgnmi.Mapping{
			Source:        internalgnmi.SourcePath{Origin: origin, Elements: append([]string(nil), elements...), Leaf: leaf},
			Metric:        builtinGNMIMetricMetadata[metricName],
			Scale:         scale,
			GaugeType:     gauge,
			KeyAttributes: append([]internalgnmi.KeyAttribute(nil), keys...),
		},
		StaticAttributes: attrs,
	}
}

func sumMapping(origin string, elements []string, leaf, metricName string, keys []internalgnmi.KeyAttribute, attrs map[string]string) builtinGNMIMapping {
	mapped := mapping(origin, elements, leaf, metricName, 1, internalgnmi.GaugeInt, keys, attrs)
	mapped.Mapping.MetricType = internalgnmi.MetricSum
	mapped.Mapping.Monotonic = true
	return mapped
}

func opticsAttributes(profile, sensor string, experimental bool) map[string]string {
	return map[string]string{
		"cisco.optics.profile":      profile,
		"cisco.optics.sensor":       strings.ReplaceAll(sensor, "-", "_"),
		"cisco.optics.experimental": strings.ToLower(strings.TrimSpace(boolString(experimental))),
	}
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func appendElements(base []string, elements ...string) []string {
	out := append([]string(nil), base...)
	return append(out, elements...)
}

type nxOpticsSensorDefinition struct {
	Metric  internalgnmi.MetricMetadata
	Profile string
	Scale   float64
}

// normalizeNXOpticsSensor applies the strict description-and-source-unit
// allowlist used for NX DME sensors. It intentionally contains no heuristic or
// numeric sensor-ID fallback. Benign case and repeated-space differences are
// normalized, but words and punctuation must otherwise match an entry.
func normalizeNXOpticsSensor(description, unit string) (nxOpticsSensorDefinition, bool) {
	key := normalizeNXSensorToken(description) + "\x00" + strings.TrimSpace(unit)
	definition, ok := nxOpticsSensorAllowlist[key]
	return definition, ok
}

func normalizeNXSensorToken(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

var nxOpticsSensorAllowlist = map[string]nxOpticsSensorDefinition{
	"temperature\x00Cel":       {Metric: builtinGNMIMetricMetadata["cisco.optics.temperature"], Profile: "dom", Scale: 1},
	"voltage\x00V":             {Metric: builtinGNMIMetricMetadata["cisco.optics.voltage"], Profile: "dom", Scale: 1},
	"laser bias current\x00mA": {Metric: builtinGNMIMetricMetadata["cisco.optics.laser_bias_current"], Profile: "dom", Scale: 1},
	"rx power\x00dBm":          {Metric: builtinGNMIMetricMetadata["cisco.optics.rx_power"], Profile: "dom", Scale: 1},
	"tx power\x00dBm":          {Metric: builtinGNMIMetricMetadata["cisco.optics.tx_power"], Profile: "dom", Scale: 1},
	"esnr\x00dB":               {Metric: builtinGNMIMetricMetadata["cisco.optics.esnr"], Profile: "vdm", Scale: 1},
	"tdecq\x00dB":              {Metric: builtinGNMIMetricMetadata["cisco.optics.tdecq"], Profile: "vdm", Scale: 1},
	"pre-fec ber\x001":         {Metric: builtinGNMIMetricMetadata["cisco.optics.pre_fec_ber"], Profile: "vdm", Scale: 1},
	"tec current\x00mA":        {Metric: builtinGNMIMetricMetadata["cisco.optics.tec_current"], Profile: "vdm", Scale: 1},
	"tec utilization\x001":     {Metric: builtinGNMIMetricMetadata["cisco.optics.tec_utilization"], Profile: "vdm", Scale: 1},
	"tec utilization\x00%":     {Metric: builtinGNMIMetricMetadata["cisco.optics.tec_utilization"], Profile: "vdm", Scale: .01},
}
