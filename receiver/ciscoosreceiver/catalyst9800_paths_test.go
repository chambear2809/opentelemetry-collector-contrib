// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCatalyst9800PathCatalogCoverage(t *testing.T) {
	expectedGroups := map[string]struct{}{
		"ap": {}, "rf": {}, "ssid": {}, "mobility": {}, "ha": {}, "auth_summary": {},
		"controller_system": {}, "client_detail": {}, "capwap_packets": {}, "neighbors": {},
	}
	actualGroups := map[string]struct{}{}
	ids := map[string]struct{}{}
	paths := map[string]struct{}{}

	for _, def := range catalyst9800PathCatalog {
		require.NotEmpty(t, def.ID)
		require.NotEmpty(t, def.Group)
		require.NotEmpty(t, def.Path)
		require.NotEmpty(t, def.Description)
		require.NotEmpty(t, def.Source, def.ID)
		require.NotEmpty(t, def.ReleaseHint, def.ID)
		require.NotEmpty(t, def.Platforms, def.ID)
		require.GreaterOrEqual(t, def.MinSampleInterval, time.Minute, def.ID)
		assert.NotContains(t, def.Path, "*", def.ID)

		_, duplicateID := ids[def.ID]
		assert.False(t, duplicateID, "duplicate Catalyst 9800 path id %s", def.ID)
		ids[def.ID] = struct{}{}
		_, duplicatePath := paths[def.Path]
		assert.False(t, duplicatePath, "duplicate Catalyst 9800 path %s", def.Path)
		paths[def.Path] = struct{}{}
		actualGroups[def.Group] = struct{}{}

		parsed, err := parseGNMIPath(def.Path)
		require.NoError(t, err, def.ID)
		assert.NotEmpty(t, parsed.GetElem(), def.ID)
		assert.NotEmpty(t, moduleFromYANGPath(def.Path), def.ID)
	}

	assert.Equal(t, expectedGroups, actualGroups)
	expectedIntervals := map[string]time.Duration{
		"ap.capwap":                    15 * time.Minute,
		"ap.oper":                      3 * time.Minute,
		"rf.radio_stats":               time.Minute,
		"rf.radio_data":                3 * time.Minute,
		"rf.radio_band_info":           3 * time.Minute,
		"rf.rrm_measurement":           3 * time.Minute,
		"client.common":                15 * time.Minute,
		"client.dot11":                 3 * time.Minute,
		"client.policy":                time.Minute,
		"client.traffic":               3 * time.Minute,
		"client.ipv4_binding":          15 * time.Minute,
		"controller.platform":          time.Minute,
		"controller.platform_software": time.Minute,
		"controller.hardware":          15 * time.Minute,
		"controller.environment":       time.Minute,
		"controller.lldp_state":        time.Minute,
		"controller.lldp_interfaces":   time.Minute,
		"controller.mdt":               time.Minute,
		"neighbors.cdp_cache":          15 * time.Minute,
	}
	for id, interval := range expectedIntervals {
		require.Contains(t, ids, id)
		for _, def := range catalyst9800PathCatalog {
			if def.ID == id {
				assert.Equal(t, interval, def.MinSampleInterval, id)
				break
			}
		}
	}
	assert.Contains(t, paths, "wireless-access-point-oper:access-point-oper-data/ethernet-mac-wtp-mac-map")
	assert.Contains(t, paths, "wireless-access-point-oper:access-point-oper-data/radio-oper-data/radio-band-info")
	assert.Contains(t, paths, "platform-sw-ios-xe-oper:cisco-platform-software/control-processes")
	assert.Contains(t, paths, "device-hardware-xe-oper:device-hardware-data/device-hardware")
	assert.Contains(t, paths, "environment-ios-xe-oper:environment-sensors/environment-sensor")
	assert.Contains(t, paths, "lldp-ios-xe-oper:lldp-entries/lldp-state-details")
	assert.Contains(t, paths, "lldp-ios-xe-oper:lldp-entries/lldp-intf-details")
	assert.Contains(t, paths, "mdt-oper-v2:mdt-oper-v2-data")
	assert.Contains(t, paths, "wireless-client-oper:client-oper-data/policy-data")
	assert.Contains(t, paths, "wireless-client-oper:client-oper-data/sisf-db-mac/ipv4-binding/ip-key/ip-addr")
	assert.Contains(t, paths, "wireless-access-point-oper:access-point-oper-data/cdp-cache-data")
	assert.NotContains(t, paths, "device-hardware-ios-xe-oper:device-hardware-data/device-hardware")
	assert.NotContains(t, paths, "mdt-ios-xe-oper:mdt-oper-data/mdt-subscriptions")
	assert.NotContains(t, paths, "lldp-ios-xe-oper:lldp-entries/lldp-entry")
}

func TestResolveCatalyst9800PathSelectionDefaultsAndOptIn(t *testing.T) {
	groups := defaultCatalyst9800PathGroups()
	selected := resolveCatalyst9800PathSelection(groups, Catalyst9800PathOverrideConfig{}, nil)
	ids := map[string]struct{}{}
	for _, def := range selected {
		ids[def.ID] = struct{}{}
		assert.NotEqual(t, "client_detail", def.Group)
		assert.NotEqual(t, "neighbors", def.Group)
		assert.NotEqual(t, "capwap_packets", def.Group)
	}

	assert.Contains(t, ids, "ap.join")
	assert.Contains(t, ids, "rf.radio_stats")
	assert.Contains(t, ids, "ssid.counters")
	assert.Contains(t, ids, "ha.infra")
	assert.NotContains(t, ids, "client.common")

	groups["client_detail"] = Catalyst9800PathGroupConfig{Enabled: true}
	selected = resolveCatalyst9800PathSelection(groups, Catalyst9800PathOverrideConfig{}, nil)
	ids = map[string]struct{}{}
	for _, def := range selected {
		ids[def.ID] = struct{}{}
	}
	assert.Contains(t, ids, "client.common")
	assert.Contains(t, ids, "client.traffic")
}

func TestResolveCatalyst9800PathSelectionDeduplicatesAndExcludes(t *testing.T) {
	groups := defaultCatalyst9800PathGroups()
	paths := Catalyst9800PathOverrideConfig{
		Include: []string{
			"wireless-client-oper:client-oper-data/common-oper-data",
			"wireless-client-oper:client-oper-data/common-oper-data",
		},
		Exclude: []string{"rf.radio_data", "*lldp*"},
	}

	selected := resolveCatalyst9800PathSelection(groups, paths, nil)
	ids := map[string]struct{}{}
	for _, def := range selected {
		assert.NotEqual(t, "rf.radio_data", def.ID)
		assert.NotContains(t, def.ID, "lldp")
		ids[def.ID] = struct{}{}
	}

	assert.Contains(t, ids, "custom.wireless_client_oper_client_oper_data_common_oper_data")
	assert.Len(t, selected, len(ids), "selected Catalyst 9800 paths should be deduplicated")
}

func TestCatalyst9800ModuleCandidatesIncludeCiscoModuleNames(t *testing.T) {
	candidates := catalyst9800ModuleCandidates("wireless-access-point-oper:access-point-oper-data/ssid-counters")
	assert.Contains(t, candidates, "wireless-access-point-oper")
	assert.Contains(t, candidates, "Cisco-IOS-XE-wireless-access-point-oper")

	candidates = catalyst9800ModuleCandidates("device-hardware-xe-oper:device-hardware-data/device-hardware")
	assert.Contains(t, candidates, "Cisco-IOS-XE-device-hardware-oper")

	candidates = catalyst9800ModuleCandidates("mdt-oper-v2:mdt-oper-v2-data")
	assert.Contains(t, candidates, "Cisco-IOS-XE-mdt-oper-v2")
}
