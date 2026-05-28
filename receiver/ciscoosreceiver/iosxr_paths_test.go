// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIOSXRPathCatalogCoverage(t *testing.T) {
	expectedGroups := map[string]struct{}{
		"system": {}, "platform": {}, "environment": {}, "interfaces": {}, "optics": {},
		"routing": {}, "fib": {}, "bgp": {}, "isis": {}, "mpls": {}, "segment_routing": {},
		"qos": {}, "security_policy": {}, "bfd": {}, "topology": {}, "time_sync": {},
		"asic": {}, "telemetry_self": {},
	}
	actualGroups := map[string]struct{}{}
	ids := map[string]struct{}{}
	paths := map[string]struct{}{}

	for _, def := range iosXRPathCatalog {
		require.NotEmpty(t, def.ID)
		require.NotEmpty(t, def.Group)
		require.NotEmpty(t, def.Path)
		require.NotEmpty(t, def.Description)
		require.NotEmpty(t, def.Source, def.ID)
		require.NotEmpty(t, def.ReleaseHint, def.ID)
		require.NotEmpty(t, def.Platforms, def.ID)
		require.GreaterOrEqual(t, def.MinSampleInterval, time.Minute, def.ID)

		_, duplicateID := ids[def.ID]
		assert.False(t, duplicateID, "duplicate IOS XR path id %s", def.ID)
		ids[def.ID] = struct{}{}
		_, duplicatePath := paths[def.Path]
		assert.False(t, duplicatePath, "duplicate IOS XR path %s", def.Path)
		paths[def.Path] = struct{}{}
		actualGroups[def.Group] = struct{}{}

		parsed, err := parseGNMIPath(def.Path)
		require.NoError(t, err, def.ID)
		assert.NotEmpty(t, parsed.GetElem(), def.ID)
		assert.NotEmpty(t, moduleFromYANGPath(def.Path), def.ID)
	}

	assert.Equal(t, expectedGroups, actualGroups)
}

func TestResolveIOSXRPathSelectionDeduplicatesAndExcludes(t *testing.T) {
	groups := defaultIOSXRPathGroups()
	groups["interfaces"] = IOSXRPathGroupConfig{Enabled: true}
	paths := IOSXRPathOverrideConfig{
		Include: []string{
			"Cisco-IOS-XR-controller-optics-oper:optics-oper/optics-ports/optics-port/optics-info",
			"Cisco-IOS-XR-controller-optics-oper:optics-oper/optics-ports/optics-port/optics-info",
		},
		Exclude: []string{"interfaces.rates", "*ipv6*"},
	}

	selected := resolveIOSXRPathSelection(groups, paths, nil)
	ids := map[string]struct{}{}
	for _, def := range selected {
		assert.NotEqual(t, "interfaces.rates", def.ID)
		assert.NotContains(t, def.ID, "ipv6")
		ids[def.ID] = struct{}{}
	}

	assert.Contains(t, ids, "interfaces.oc")
	assert.Contains(t, ids, "interfaces.counters")
	assert.Contains(t, ids, "custom.cisco_ios_xr_controller_optics_oper_optics_oper_optics_ports_optics_port_optics_info")
	assert.Len(t, selected, len(ids), "selected IOS XR paths should be deduplicated")
}

func TestParseGNMIPathSupportsOriginAndKeys(t *testing.T) {
	parsed, err := parseGNMIPath("/openconfig-interfaces:interfaces/interface[name='HundredGigE0/0/0/0']/state/counters")
	require.NoError(t, err)

	assert.Equal(t, "openconfig-interfaces", parsed.Origin)
	require.Len(t, parsed.Elem, 4)
	assert.Equal(t, "interfaces", parsed.Elem[0].Name)
	assert.Equal(t, "HundredGigE0/0/0/0", parsed.Elem[1].Key["name"])
	assert.Equal(t, "counters", parsed.Elem[3].Name)
	assert.Equal(t, "openconfig-interfaces", moduleFromYANGPath("/openconfig-interfaces:interfaces/interface/state"))
}
