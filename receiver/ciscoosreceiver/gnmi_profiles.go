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
	builtinGNMIOriginOpenConfig            = "openconfig"
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
	ID         string
	PathTarget string
	Origin     string
	// Model is the Capabilities ModelData name when the wire origin does not
	// identify one model, as with NX-OS's generic "openconfig" origin.
	Model        string
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

// builtinGNMIProfiles returns a product contract's profiles in stable name
// order. Catalog values are treated as immutable by receiver code.
func builtinGNMIProfiles(contract *gnmiProductContract) []builtinGNMIProfileDefinition {
	if contract == nil {
		return nil
	}
	profiles := contract.profiles
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

func builtinGNMIProfile(contract *gnmiProductContract, profile string) (builtinGNMIProfileDefinition, bool) {
	if contract == nil {
		return builtinGNMIProfileDefinition{}, false
	}
	definition, ok := contract.profiles[profile]
	return definition, ok
}

func defaultBuiltinGNMIProfile(profile string) (builtinGNMIProfileDefinition, bool) {
	for _, catalog := range []map[string]builtinGNMIProfileDefinition{
		iosXEBuiltinGNMIProfileCatalog,
		iosXRBuiltinGNMIProfileCatalog,
		nxOSBuiltinGNMIProfileCatalog,
	} {
		if definition, ok := catalog[profile]; ok {
			return definition, true
		}
	}
	return builtinGNMIProfileDefinition{}, false
}

var builtinGNMIMetricMetadata = map[string]internalgnmi.MetricMetadata{
	"cisco.device.up":                 {Name: "cisco.device.up", Description: "Device availability (1 = up, 0 = down)", Unit: "1"},
	"system.cpu.utilization":          {Name: "system.cpu.utilization", Description: "Ratio of CPU time in use, from 0 to 1.", Unit: "1"},
	"system.memory.utilization":       {Name: "system.memory.utilization", Description: "Ratio of memory bytes in use, from 0 to 1.", Unit: "1"},
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

	"cisco.optics.temperature":        {Name: "cisco.optics.temperature", Description: "Optical module temperature", Unit: "Cel"},
	"cisco.optics.voltage":            {Name: "cisco.optics.voltage", Description: "Optical module supply voltage", Unit: "V"},
	"cisco.optics.laser_bias_current": {Name: "cisco.optics.laser_bias_current", Description: "Optical transmitter laser bias current", Unit: "mA"},
	"cisco.optics.rx_power":           {Name: "cisco.optics.rx_power", Description: "Received optical power", Unit: "dB[mW]"},
	"cisco.optics.tx_power":           {Name: "cisco.optics.tx_power", Description: "Transmitted optical power", Unit: "dB[mW]"},
	"cisco.optics.present":            {Name: "cisco.optics.present", Description: "Optical module or lane presence (1 = present, 0 = absent)", Unit: "1"},
	"cisco.optics.esnr":               {Name: "cisco.optics.esnr", Description: "Effective signal-to-noise ratio reported by an allowlisted device VDM sensor", Unit: "dB"},
	"cisco.optics.tdecq":              {Name: "cisco.optics.tdecq", Description: "Transmitter and dispersion eye closure for PAM4 reported by a sensor explicitly identified as TDECQ in dB", Unit: "dB"},
	"cisco.optics.pre_fec_ber":        {Name: "cisco.optics.pre_fec_ber", Description: "Pre-forward-error-correction bit error ratio", Unit: "1"},
	"cisco.optics.tec_current":        {Name: "cisco.optics.tec_current", Description: "Thermoelectric cooler current when the device reports the sensor in milliamperes", Unit: "mA"},
	"cisco.optics.tec_utilization":    {Name: "cisco.optics.tec_utilization", Description: "Thermoelectric cooler utilization normalized to a unitless ratio", Unit: "1"},

	"cisco.wlc.ap.join.status":         {Name: "cisco.wlc.ap.join.status", Description: "Catalyst 9800 access point join status", Unit: "1"},
	"cisco.wlc.rf.channel.utilization": {Name: "cisco.wlc.rf.channel.utilization", Description: "Catalyst 9800 RF channel utilization ratio", Unit: "1"},
	"cisco.wlc.ssid.client.count":      {Name: "cisco.wlc.ssid.client.count", Description: "Catalyst 9800 associated client count", Unit: "{client}"},
}

var (
	iosXEBuiltinGNMIProfileCatalog = iosXEBuiltinGNMIProfiles()
	iosXRBuiltinGNMIProfileCatalog = iosXRBuiltinGNMIProfiles()
	nxOSBuiltinGNMIProfileCatalog  = nxOSBuiltinGNMIProfiles()
)

func iosXEBuiltinGNMIProfiles() map[string]builtinGNMIProfileDefinition {
	return map[string]builtinGNMIProfileDefinition{
		builtinGNMIProfileIdentity: profileDefinition(builtinGNMIProfileIdentity, true, 5*time.Minute,
			[]builtinGNMIMapping{availabilityMapping(builtinGNMIPlatformIOSXE)},
			builtinGNMIPathDefinition{ID: "identity.system", Origin: builtinGNMIOriginRFC7951, Path: "openconfig-system:system/state"}),
		builtinGNMIProfileSystem: profileDefinition(builtinGNMIProfileSystem, true, time.Minute, nil,
			builtinGNMIPathDefinition{ID: "system.cpu", Origin: builtinGNMIOriginRFC7951, Path: "Cisco-IOS-XE-process-cpu-oper:cpu-usage/cpu-utilization", Mappings: []builtinGNMIMapping{mapping(builtinGNMIOriginRFC7951, []string{"Cisco-IOS-XE-process-cpu-oper:cpu-usage", "cpu-utilization"}, "five-seconds", "system.cpu.utilization", .01, internalgnmi.GaugeDouble, nil, nil)}},
			builtinGNMIPathDefinition{
				ID:     "system.memory",
				Origin: builtinGNMIOriginRFC7951,
				Path:   "Cisco-IOS-XE-platform-software-oper:cisco-platform-software/control-processes/control-process/memory-stats",
				Mappings: []builtinGNMIMapping{mapping(
					builtinGNMIOriginRFC7951,
					[]string{"Cisco-IOS-XE-platform-software-oper:cisco-platform-software", "control-processes", "control-process", "memory-stats"},
					"used-percent",
					"system.memory.utilization",
					.01,
					internalgnmi.GaugeDouble,
					[]internalgnmi.KeyAttribute{
						{Element: "control-process", Key: "fru", Attribute: "cisco.location.fru"},
						{Element: "control-process", Key: "slot", Attribute: "cisco.location.slot"},
						{Element: "control-process", Key: "bay", Attribute: "cisco.location.bay"},
						{Element: "control-process", Key: "chassis", Attribute: "cisco.location.chassis"},
					},
					nil,
				)},
			}),
		builtinGNMIProfileInterfaces: profileDefinition(builtinGNMIProfileInterfaces, true, time.Minute, nil,
			builtinGNMIPathDefinition{ID: "interfaces.openconfig", Origin: builtinGNMIOriginRFC7951, Path: "openconfig-interfaces:interfaces/interface/state", Mappings: interfaceMappings(builtinGNMIOriginRFC7951, []string{"openconfig-interfaces:interfaces", "interface"})}),
		builtinGNMIProfileOptics: profileDefinition(builtinGNMIProfileOptics, false, 30*time.Second, nil,
			builtinGNMIPathDefinition{ID: "optics.dom", Origin: builtinGNMIOriginRFC7951, Path: "Cisco-IOS-XE-transceiver-oper:transceiver-oper-data/transceiver", Experimental: true, Mappings: iosXEDOMMappings()}),
		builtinGNMIProfileCatalyst9800Wireless: profileDefinition(builtinGNMIProfileCatalyst9800Wireless, false, time.Minute, nil,
			builtinGNMIPathDefinition{ID: "wireless.ap.join", Origin: builtinGNMIOriginRFC7951, Path: "Cisco-IOS-XE-wireless-ap-global-oper:ap-global-oper-data/ap-join-stats", Mappings: []builtinGNMIMapping{mapping(builtinGNMIOriginRFC7951, []string{"Cisco-IOS-XE-wireless-ap-global-oper:ap-global-oper-data", "ap-join-stats"}, "is-joined", "cisco.wlc.ap.join.status", 1, internalgnmi.GaugeInt, []internalgnmi.KeyAttribute{{Element: "ap-join-stats", Key: "wtp-mac", Attribute: "cisco.wlc.ap.mac"}}, nil)}},
			builtinGNMIPathDefinition{ID: "wireless.rf", Origin: builtinGNMIOriginRFC7951, Path: "Cisco-IOS-XE-wireless-rrm-oper:rrm-oper-data/rrm-measurement", Mappings: []builtinGNMIMapping{mapping(builtinGNMIOriginRFC7951, []string{"Cisco-IOS-XE-wireless-rrm-oper:rrm-oper-data", "rrm-measurement"}, "cca-util-percentage", "cisco.wlc.rf.channel.utilization", .01, internalgnmi.GaugeDouble, []internalgnmi.KeyAttribute{{Element: "rrm-measurement", Key: "wtp-mac", Attribute: "cisco.wlc.ap.mac"}, {Element: "rrm-measurement", Key: "radio-slot-id", Attribute: "cisco.wlc.radio.slot"}}, nil)}},
			builtinGNMIPathDefinition{ID: "wireless.ssid", Origin: builtinGNMIOriginRFC7951, Path: "Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data/ssid-counters", Mappings: []builtinGNMIMapping{mapping(builtinGNMIOriginRFC7951, []string{"Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data", "ssid-counters"}, "num-assoc-clients", "cisco.wlc.ssid.client.count", 1, internalgnmi.GaugeInt, []internalgnmi.KeyAttribute{{Element: "ssid-counters", Key: "wtp-mac", Attribute: "cisco.wlc.ap.mac"}, {Element: "ssid-counters", Key: "slot-id", Attribute: "cisco.wlc.radio.slot"}, {Element: "ssid-counters", Key: "wlan-id", Attribute: "cisco.wlc.wlan.id"}}, nil)}}),
	}
}

func iosXRBuiltinGNMIProfiles() map[string]builtinGNMIProfileDefinition {
	const opticsOrigin = "Cisco-IOS-XR-controller-optics-oper"
	return map[string]builtinGNMIProfileDefinition{
		builtinGNMIProfileIdentity: profileDefinition(builtinGNMIProfileIdentity, true, 5*time.Minute,
			[]builtinGNMIMapping{availabilityMapping(builtinGNMIPlatformIOSXR)}),
		builtinGNMIProfileSystem: profileDefinition(builtinGNMIProfileSystem, true, time.Minute, nil,
			builtinGNMIPathDefinition{ID: "system.cpu", Origin: "Cisco-IOS-XR-wdsysmon-fd-oper", Path: "system-monitoring/cpu-utilization", Mappings: []builtinGNMIMapping{mapping("Cisco-IOS-XR-wdsysmon-fd-oper", []string{"system-monitoring", "cpu-utilization"}, "total-cpu-one-minute", "system.cpu.utilization", .01, internalgnmi.GaugeDouble, []internalgnmi.KeyAttribute{{Element: "cpu-utilization", Key: "node-name", Attribute: "cisco.node.name"}}, nil)}}),
		builtinGNMIProfileInterfaces: profileDefinition(builtinGNMIProfileInterfaces, true, time.Minute, nil,
			builtinGNMIPathDefinition{ID: "interfaces.openconfig", Origin: "openconfig-interfaces", Path: "interfaces/interface/state", Mappings: interfaceMappings("openconfig-interfaces", []string{"interfaces", "interface"})}),
		builtinGNMIProfileOptics: profileDefinition(builtinGNMIProfileOptics, false, 30*time.Second, nil,
			builtinGNMIPathDefinition{ID: "optics.controllers", Origin: opticsOrigin, Path: "optics-oper/optics-ports/optics-port/optics-info", Experimental: true, Mappings: iosXRControllerDOMMappings(opticsOrigin)},
			builtinGNMIPathDefinition{ID: "optics.lanes", Origin: opticsOrigin, Path: "optics-oper/optics-ports/optics-port/optics-lanes/optics-lane", Experimental: true, Mappings: iosXRLaneDOMMappings(opticsOrigin)}),
	}
}

func nxOSBuiltinGNMIProfiles() map[string]builtinGNMIProfileDefinition {
	return map[string]builtinGNMIProfileDefinition{
		builtinGNMIProfileIdentity: profileDefinition(builtinGNMIProfileIdentity, true, 5*time.Minute,
			[]builtinGNMIMapping{availabilityMapping(builtinGNMIPlatformNXOS)},
			builtinGNMIPathDefinition{ID: "identity.system", Origin: builtinGNMIOriginOpenConfig, Model: "openconfig-system", Path: "system/state"}),
		builtinGNMIProfileInterfaces: profileDefinition(builtinGNMIProfileInterfaces, true, time.Minute, nil,
			builtinGNMIPathDefinition{ID: "interfaces.openconfig", Origin: builtinGNMIOriginOpenConfig, Model: "openconfig-interfaces", Path: "interfaces/interface/state", Mappings: interfaceMappings(builtinGNMIOriginOpenConfig, []string{"interfaces", "interface"})}),
		builtinGNMIProfileOptics: profileDefinition(builtinGNMIProfileOptics, false, 30*time.Second, nil,
			// NX DME publishes a distinguished-name family, not the device YANG tree.
			// Subscribe at the nearest static ancestor; the explicit mapper accepts
			// only the documented sys/intf/phys-[...]/phys/fcot{,dd}/lane-...-sensor-... families.
			builtinGNMIPathDefinition{ID: "optics.dme.sensors", Origin: builtinGNMIOriginDME, Path: "sys/intf", Experimental: true, Mappings: nxDMESensorMappings()}),
	}
}

func profileDefinition(name string, enabled bool, interval time.Duration, synthetic []builtinGNMIMapping, paths ...builtinGNMIPathDefinition) builtinGNMIProfileDefinition {
	return builtinGNMIProfileDefinition{Name: name, DefaultEnabled: enabled, DefaultInterval: interval, SyntheticMappings: synthetic, Paths: paths}
}

func availabilityMapping(platform string) builtinGNMIMapping {
	return mapping(builtinGNMISyntheticReceiverOrigin, []string{"target", platform}, "up", "cisco.device.up", 1, internalgnmi.GaugeInt, nil, nil)
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

func iosXEDOMMappings() []builtinGNMIMapping {
	const origin = builtinGNMIOriginRFC7951
	root := []string{"Cisco-IOS-XE-transceiver-oper:transceiver-oper-data", "transceiver"}
	keys := []internalgnmi.KeyAttribute{{Element: "transceiver", Key: "name", Attribute: "network.interface.name"}}
	return []builtinGNMIMapping{
		opticsMapping(origin, root, "internal-temp", "cisco.optics.temperature", 1, internalgnmi.GaugeDouble, keys, "temperature"),
		opticsMapping(origin, appendElements(root, "voltage"), "instant", "cisco.optics.voltage", 1, internalgnmi.GaugeDouble, keys, "voltage"),
		opticsMapping(origin, appendElements(root, "laser-bias-current"), "instant", "cisco.optics.laser_bias_current", 1, internalgnmi.GaugeDouble, keys, "laser_bias_current"),
		opticsMapping(origin, appendElements(root, "input-power"), "instant", "cisco.optics.rx_power", 1, internalgnmi.GaugeDouble, keys, "rx_power"),
		opticsMapping(origin, appendElements(root, "output-power"), "instant", "cisco.optics.tx_power", 1, internalgnmi.GaugeDouble, keys, "tx_power"),
		opticsMapping(origin, root, "present", "cisco.optics.present", 1, internalgnmi.GaugeInt, keys, ""),
	}
}

func iosXRControllerDOMMappings(origin string) []builtinGNMIMapping {
	root := []string{"optics-oper", "optics-ports", "optics-port", "optics-info"}
	keys := []internalgnmi.KeyAttribute{{Element: "optics-port", Key: "name", Attribute: "network.interface.name"}}
	return []builtinGNMIMapping{
		opticsMapping(origin, root, "temperature", "cisco.optics.temperature", .01, internalgnmi.GaugeDouble, keys, "temperature"),
		opticsMapping(origin, root, "voltage", "cisco.optics.voltage", .01, internalgnmi.GaugeDouble, keys, "voltage"),
		opticsMapping(origin, root, "total-rx-power", "cisco.optics.rx_power", .01, internalgnmi.GaugeDouble, keys, "rx_power"),
		opticsMapping(origin, root, "total-tx-power", "cisco.optics.tx_power", .01, internalgnmi.GaugeDouble, keys, "tx_power"),
		opticsMapping(origin, root, "optics-present", "cisco.optics.present", 1, internalgnmi.GaugeInt, keys, ""),
	}
}

func iosXRLaneDOMMappings(origin string) []builtinGNMIMapping {
	root := []string{"optics-oper", "optics-ports", "optics-port", "optics-lanes", "optics-lane"}
	keys := []internalgnmi.KeyAttribute{
		{Element: "optics-port", Key: "name", Attribute: "network.interface.name"},
		{Element: "optics-lane", Key: "number", Attribute: "cisco.optics.lane"},
	}
	return []builtinGNMIMapping{
		opticsMapping(origin, root, "laser-bias-current-milli-amps", "cisco.optics.laser_bias_current", .01, internalgnmi.GaugeDouble, keys, "laser_bias_current"),
		opticsMapping(origin, root, "receive-power", "cisco.optics.rx_power", .01, internalgnmi.GaugeDouble, keys, "rx_power"),
		opticsMapping(origin, root, "transmit-power", "cisco.optics.tx_power", .01, internalgnmi.GaugeDouble, keys, "tx_power"),
	}
}

func opticsMapping(origin string, elements []string, leaf, metricName string, scale float64, gauge internalgnmi.GaugeValueType, keys []internalgnmi.KeyAttribute, sensor string) builtinGNMIMapping {
	attrs := opticsAttributes("dom", sensor, true)
	if sensor == "" {
		delete(attrs, "cisco.optics.sensor")
	}
	return mapping(origin, elements, leaf, metricName, scale, gauge, keys, attrs)
}

func nxDMESensorMappings() []builtinGNMIMapping {
	origin := builtinGNMIOriginDME
	keys := []internalgnmi.KeyAttribute{{Element: "phys", Key: "id", Attribute: "network.interface.name"}, {Element: "lane", Key: "id", Attribute: "cisco.optics.lane"}}
	definitions := []struct {
		leaf, metric, profile string
	}{
		{"temperature", "cisco.optics.temperature", "dom"},
		{"voltage", "cisco.optics.voltage", "dom"},
		{"laser-bias-current", "cisco.optics.laser_bias_current", "dom"},
		{"rx-power", "cisco.optics.rx_power", "dom"},
		{"tx-power", "cisco.optics.tx_power", "dom"},
		{"esnr", "cisco.optics.esnr", "vdm"},
		{"tdecq", "cisco.optics.tdecq", "vdm"},
		{"pre-fec-ber", "cisco.optics.pre_fec_ber", "vdm"},
		{"tec-current", "cisco.optics.tec_current", "vdm"},
		{"tec-utilization", "cisco.optics.tec_utilization", "vdm"},
	}
	out := make([]builtinGNMIMapping, 0, 2*len(definitions))
	for _, family := range []string{"fcot", "fcotdd"} {
		elements := []string{"sys", "intf", "phys", "phys", family, "lane", "sensor"}
		for _, definition := range definitions {
			out = append(out, mapping(origin, elements, definition.leaf, definition.metric, 1, internalgnmi.GaugeDouble, keys, opticsAttributes(definition.profile, definition.leaf, true)))
		}
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
