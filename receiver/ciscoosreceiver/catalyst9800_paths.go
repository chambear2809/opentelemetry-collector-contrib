// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"path"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	catalyst9800PathGroupAP               = "ap"
	catalyst9800PathGroupRF               = "rf"
	catalyst9800PathGroupSSID             = "ssid"
	catalyst9800PathGroupMobility         = "mobility"
	catalyst9800PathGroupHA               = "ha"
	catalyst9800PathGroupAuthSummary      = "auth_summary"
	catalyst9800PathGroupControllerSystem = "controller_system"
	catalyst9800PathGroupClientDetail     = "client_detail"
	catalyst9800PathGroupCAPWAPPackets    = "capwap_packets" //nolint:gosec // Telemetry path-group identifier, not a credential.
	catalyst9800PathGroupNeighbors        = "neighbors"
)

type catalyst9800PathDefinition struct {
	ID                string
	Group             string
	Path              string
	Description       string
	Source            string
	ReleaseHint       string
	DefaultStreamMode string
	MinSampleInterval time.Duration
	HighVolume        bool
	Platforms         []string
}

func init() {
	for i := range catalyst9800PathCatalog {
		if len(catalyst9800PathCatalog[i].Platforms) == 0 {
			catalyst9800PathCatalog[i].Platforms = []string{"CAT9100-EWC", "CAT9800-CL", "CAT9800-L", "CAT9800-40", "CAT9800-80"}
		}
		if catalyst9800PathCatalog[i].ReleaseHint == "" {
			catalyst9800PathCatalog[i].ReleaseHint = "IOS XE 17.6 or later; verify advertised YANG model support with gNMI Capabilities for the target Catalyst 9800 release"
		}
		if catalyst9800PathCatalog[i].Source == "" {
			catalyst9800PathCatalog[i].Source = "Cisco Catalyst 9800 streaming telemetry and IOS XE 17.18 YANG model"
		}
	}
}

// The catalog uses concrete gather-point paths. Catalyst 9800 gNMI does not
// support wildcard subscription paths, and several wireless tables can become
// large at controller scale, so client, neighbor, and CAPWAP packet paths stay
// opt-in.
var catalyst9800PathCatalog = []catalyst9800PathDefinition{
	{ID: "ap.join", Group: catalyst9800PathGroupAP, Path: "wireless-ap-global-oper:ap-global-oper-data/ap-join-stats", Description: "AP join state, join failure, and disconnect counters", DefaultStreamMode: iosXRStreamModeOnChange, MinSampleInterval: time.Minute},
	{ID: "ap.capwap", Group: catalyst9800PathGroupAP, Path: "wireless-access-point-oper:access-point-oper-data/capwap-data", Description: "CAPWAP control/data tunnel state per AP", MinSampleInterval: 15 * time.Minute},
	{ID: "ap.oper", Group: catalyst9800PathGroupAP, Path: "wireless-access-point-oper:access-point-oper-data/oper-data", Description: "AP operational identity and state", MinSampleInterval: 3 * time.Minute},
	{ID: "ap.mac_map", Group: catalyst9800PathGroupAP, Path: "wireless-access-point-oper:access-point-oper-data/ethernet-mac-wtp-mac-map", Description: "AP Ethernet MAC to WTP MAC mapping", MinSampleInterval: 15 * time.Minute},

	{ID: "rf.radio_stats", Group: catalyst9800PathGroupRF, Path: "wireless-access-point-oper:access-point-oper-data/radio-oper-stats", Description: "Radio client counts, channel, utilization, noise, and load statistics", MinSampleInterval: time.Minute},
	{ID: "rf.radio_data", Group: catalyst9800PathGroupRF, Path: "wireless-access-point-oper:access-point-oper-data/radio-oper-data", Description: "Radio operating channel, DCA, and administrative state", MinSampleInterval: 3 * time.Minute},
	{ID: "rf.radio_band_info", Group: catalyst9800PathGroupRF, Path: "wireless-access-point-oper:access-point-oper-data/radio-oper-data/radio-band-info", Description: "Radio band details under radio operational data", MinSampleInterval: 3 * time.Minute},
	{ID: "rf.rrm_measurement", Group: catalyst9800PathGroupRF, Path: "wireless-rrm-oper:rrm-oper-data/rrm-measurement", Description: "RRM channel utilization, station counts, noise, and channel changes", MinSampleInterval: 3 * time.Minute},

	{ID: "ssid.counters", Group: catalyst9800PathGroupSSID, Path: "wireless-access-point-oper:access-point-oper-data/ssid-counters", Description: "SSID/BSSID client, utilization, byte, and retry counters", MinSampleInterval: 3 * time.Minute},

	{ID: "mobility.nodes", Group: catalyst9800PathGroupMobility, Path: "wireless-mobility-oper:mobility-oper-data/mobility-node-data", Description: "Mobility peer/link state and L2/L3 handoff counters", MinSampleInterval: time.Minute},

	{ID: "ha.infra", Group: catalyst9800PathGroupHA, Path: "ha-ios-xe-oper:ha-oper-data/ha-infra", Description: "Local/peer HA state, HA enabled, switchover, and standby failure counters", MinSampleInterval: time.Minute},

	{ID: "auth.radius_global", Group: catalyst9800PathGroupAuthSummary, Path: "aaa-ios-xe-oper:aaa-data/aaa-radius-global-stats", Description: "RADIUS accepts, rejects, timeouts, delay, and authenticator counters", MinSampleInterval: time.Minute},

	{ID: "controller.cpu", Group: catalyst9800PathGroupControllerSystem, Path: "process-cpu-ios-xe-oper:cpu-usage/cpu-utilization", Description: "IOS XE process and control-plane CPU utilization", MinSampleInterval: time.Minute},
	{ID: "controller.platform_software", Group: catalyst9800PathGroupControllerSystem, Path: "platform-sw-ios-xe-oper:cisco-platform-software/control-processes", Description: "IOS XE platform software control-process health", MinSampleInterval: time.Minute},
	{ID: "controller.platform", Group: catalyst9800PathGroupControllerSystem, Path: "platform-ios-xe-oper:components/component", Description: "Platform component inventory and operational state", MinSampleInterval: time.Minute},
	{ID: "controller.hardware", Group: catalyst9800PathGroupControllerSystem, Path: "device-hardware-xe-oper:device-hardware-data/device-hardware", Description: "Device hardware inventory and state", MinSampleInterval: 15 * time.Minute},
	{ID: "controller.environment", Group: catalyst9800PathGroupControllerSystem, Path: "environment-ios-xe-oper:environment-sensors/environment-sensor", Description: "IOS XE environmental sensor state and readings", MinSampleInterval: time.Minute},
	{ID: "controller.interfaces", Group: catalyst9800PathGroupControllerSystem, Path: "interfaces-ios-xe-oper:interfaces/interface", Description: "IOS XE interface operational counters and state", MinSampleInterval: time.Minute, HighVolume: true},
	{ID: "controller.lldp_state", Group: catalyst9800PathGroupControllerSystem, Path: "lldp-ios-xe-oper:lldp-entries/lldp-state-details", Description: "LLDP state details", DefaultStreamMode: iosXRStreamModeOnChange, MinSampleInterval: time.Minute, HighVolume: true},
	{ID: "controller.lldp_interfaces", Group: catalyst9800PathGroupControllerSystem, Path: "lldp-ios-xe-oper:lldp-entries/lldp-intf-details", Description: "LLDP interface details", DefaultStreamMode: iosXRStreamModeOnChange, MinSampleInterval: time.Minute, HighVolume: true},
	{ID: "controller.mdt", Group: catalyst9800PathGroupControllerSystem, Path: "mdt-oper-v2:mdt-oper-v2-data", Description: "Model-driven telemetry subscription self-health", MinSampleInterval: time.Minute},

	{ID: "client.common", Group: catalyst9800PathGroupClientDetail, Path: "wireless-client-oper:client-oper-data/common-oper-data", Description: "Client connection state, WLAN, username, and policy state", MinSampleInterval: 15 * time.Minute, HighVolume: true},
	{ID: "client.dot11", Group: catalyst9800PathGroupClientDetail, Path: "wireless-client-oper:client-oper-data/dot11-oper-data", Description: "Client SSID, radio, and roam detail", MinSampleInterval: 3 * time.Minute, HighVolume: true},
	{ID: "client.policy", Group: catalyst9800PathGroupClientDetail, Path: "wireless-client-oper:client-oper-data/policy-data", Description: "Client policy state and authorization detail", MinSampleInterval: time.Minute, HighVolume: true},
	{ID: "client.traffic", Group: catalyst9800PathGroupClientDetail, Path: "wireless-client-oper:client-oper-data/traffic-stats", Description: "Client bytes, packets, RSSI, and SNR", MinSampleInterval: 3 * time.Minute, HighVolume: true},
	{ID: "client.exclusion", Group: catalyst9800PathGroupClientDetail, Path: "wireless-client-oper:client-oper-data/exclusion-data", Description: "Client exclusion/auth failure reason", MinSampleInterval: 15 * time.Minute, HighVolume: true},
	{ID: "client.ipv4_binding", Group: catalyst9800PathGroupClientDetail, Path: "wireless-client-oper:client-oper-data/sisf-db-mac/ipv4-binding/ip-key/ip-addr", Description: "Client IPv4 binding detail", MinSampleInterval: 15 * time.Minute, HighVolume: true},

	{ID: "capwap.packets", Group: catalyst9800PathGroupCAPWAPPackets, Path: "wireless-access-point-oper:access-point-oper-data/capwap-pkts", Description: "CAPWAP packet and error counters per AP", MinSampleInterval: 15 * time.Minute, HighVolume: true},

	{ID: "neighbors.rrm", Group: catalyst9800PathGroupNeighbors, Path: "wireless-rrm-oper:rrm-oper-data/rrm-neighbor", Description: "RRM/AP neighbor records", MinSampleInterval: 15 * time.Minute, HighVolume: true},
	{ID: "neighbors.cdp_cache", Group: catalyst9800PathGroupNeighbors, Path: "wireless-access-point-oper:access-point-oper-data/cdp-cache-data", Description: "AP CDP cache neighbor records", MinSampleInterval: 15 * time.Minute, HighVolume: true},
}

var catalyst9800SafeDefaultPathGroups = map[string]struct{}{
	catalyst9800PathGroupAP:               {},
	catalyst9800PathGroupRF:               {},
	catalyst9800PathGroupSSID:             {},
	catalyst9800PathGroupMobility:         {},
	catalyst9800PathGroupHA:               {},
	catalyst9800PathGroupAuthSummary:      {},
	catalyst9800PathGroupControllerSystem: {},
}

func catalyst9800PathGroupNames() []string {
	seen := map[string]struct{}{}
	for i := range catalyst9800PathCatalog {
		seen[catalyst9800PathCatalog[i].Group] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func isKnownCatalyst9800PathGroup(name string) bool {
	return slices.Contains(catalyst9800PathGroupNames(), name)
}

func resolveCatalyst9800PathSelection(globalGroups map[string]Catalyst9800PathGroupConfig, globalPaths Catalyst9800PathOverrideConfig, target *Catalyst9800TargetConfig) []catalyst9800PathDefinition {
	groups := globalGroups
	paths := globalPaths
	if target != nil {
		if target.PathGroups != nil {
			groups = target.PathGroups
		}
		if len(target.Paths.Include) > 0 || len(target.Paths.Exclude) > 0 {
			paths = target.Paths
		}
	}

	selected := make([]catalyst9800PathDefinition, 0, len(catalyst9800PathCatalog)+len(paths.Include))
	seen := map[string]struct{}{}
	for i := range catalyst9800PathCatalog {
		def := catalyst9800PathCatalog[i]
		if groups[def.Group].Enabled && !catalyst9800PathExcluded(def, paths.Exclude) {
			if _, ok := seen[def.Path]; !ok {
				selected = append(selected, def)
				seen[def.Path] = struct{}{}
			}
		}
	}
	for _, custom := range paths.Include {
		custom = strings.TrimSpace(custom)
		if custom == "" {
			continue
		}
		def := catalyst9800PathDefinition{
			ID:                "custom." + sanitizeMetricSegment(custom),
			Group:             "custom",
			Path:              custom,
			Description:       "Custom Catalyst 9800 telemetry path",
			DefaultStreamMode: iosXRStreamModeSample,
			MinSampleInterval: time.Minute,
		}
		if catalyst9800PathExcluded(def, paths.Exclude) {
			continue
		}
		if _, ok := seen[def.Path]; !ok {
			selected = append(selected, def)
			seen[def.Path] = struct{}{}
		}
	}
	return selected
}

func catalyst9800PathExcluded(def catalyst9800PathDefinition, excludes []string) bool {
	for _, exclude := range excludes {
		exclude = strings.TrimSpace(exclude)
		if exclude == "" {
			continue
		}
		if exclude == def.ID || exclude == def.Group || exclude == def.Path {
			return true
		}
		if ok, _ := path.Match(exclude, def.ID); ok {
			return true
		}
		if ok, _ := path.Match(exclude, def.Path); ok {
			return true
		}
		if strings.Contains(exclude, "*") && simpleWildcardMatch(exclude, def.Path) {
			return true
		}
	}
	return false
}

var catalyst9800YANGModuleAliases = map[string][]string{
	"wireless-ap-global-oper":    {"Cisco-IOS-XE-wireless-ap-global-oper"},
	"wireless-access-point-oper": {"Cisco-IOS-XE-wireless-access-point-oper"},
	"wireless-rrm-oper":          {"Cisco-IOS-XE-wireless-rrm-oper"},
	"wireless-client-oper":       {"Cisco-IOS-XE-wireless-client-oper"},
	"wireless-mobility-oper":     {"Cisco-IOS-XE-wireless-mobility-oper"},
	"ha-ios-xe-oper":             {"Cisco-IOS-XE-ha-oper"},
	"aaa-ios-xe-oper":            {"Cisco-IOS-XE-aaa-oper"},
	"process-cpu-ios-xe-oper":    {"Cisco-IOS-XE-process-cpu-oper"},
	"platform-sw-ios-xe-oper":    {"Cisco-IOS-XE-platform-software-oper"},
	"platform-ios-xe-oper":       {"Cisco-IOS-XE-platform-oper"},
	"device-hardware-xe-oper":    {"Cisco-IOS-XE-device-hardware-oper"},
	"environment-ios-xe-oper":    {"Cisco-IOS-XE-environment-oper"},
	"interfaces-ios-xe-oper":     {"Cisco-IOS-XE-interfaces-oper"},
	"lldp-ios-xe-oper":           {"Cisco-IOS-XE-lldp-oper"},
	"mdt-oper-v2":                {"Cisco-IOS-XE-mdt-oper-v2"},
	"mdt-ios-xe-oper":            {"Cisco-IOS-XE-mdt-oper"},
}

func catalyst9800ModuleCandidates(yangPath string) []string {
	module := moduleFromYANGPath(yangPath)
	if module == "" {
		return nil
	}
	out := []string{module}
	out = append(out, catalyst9800YANGModuleAliases[module]...)
	return out
}
