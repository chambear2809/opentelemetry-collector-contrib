// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/catalystcenter"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"
)

func TestDeviceSelectionEmptyAllowsExistingBehavior(t *testing.T) {
	selector := newDeviceSelectionMatcher(DeviceSelectionConfig{})

	assert.True(t, selector.allows(deviceIdentity{}))
	assert.True(t, selector.allows(deviceIdentity{hostNames: []string{"leaf-1"}}))
	assert.True(t, selector.empty())
}

func TestDeviceSelectionNormalizesAndMatchesIdentities(t *testing.T) {
	selector := newDeviceSelectionMatcher(DeviceSelectionConfig{
		Include: DeviceSelectionMatchConfig{
			HostNames: []string{" Leaf-1 "},
			HostIPs:   []string{"2001:0db8::1"},
			Serials:   []string{"FOC1234"},
		},
	})

	assert.True(t, selector.allows(deviceIdentity{hostNames: []string{"leaf-1"}}))
	assert.True(t, selector.allows(deviceIdentity{hostIPs: []string{"2001:db8::1"}}))
	assert.True(t, newDeviceSelectionMatcher(DeviceSelectionConfig{
		Include: DeviceSelectionMatchConfig{HostIPs: []string{"192.0.2.1"}},
	}).allows(deviceIdentity{hostIPs: []string{"::ffff:192.0.2.1"}}))
	assert.True(t, selector.allows(deviceIdentity{serials: []string{"foc1234"}}))
	assert.False(t, selector.allows(deviceIdentity{hostNames: []string{"leaf-2"}}))
}

func TestDeviceSelectionExcludeWins(t *testing.T) {
	selector := newDeviceSelectionMatcher(DeviceSelectionConfig{
		Include: DeviceSelectionMatchConfig{HostNames: []string{"leaf-1"}},
		Exclude: DeviceSelectionMatchConfig{Serials: []string{
			"FOC1234",
		}},
	})

	assert.False(t, selector.allows(deviceIdentity{
		hostNames: []string{"leaf-1"},
		serials:   []string{"FOC1234"},
	}))
}

func TestDeviceSelectionMatchesProviderResourceAttributes(t *testing.T) {
	attrs := pcommon.NewMap()
	attrs.PutStr("host.name", "edge-1")
	attrs.PutStr("host.id", "FOC1234")
	attrs.PutStr("host.ip", "10.0.0.10")
	attrs.PutStr("hw.type", "network")
	attrs.PutStr("catalyst_center.device.id", "device-1")
	attrs.PutStr("catalyst_center.device.serial", "FOC1234")

	selector := newDeviceSelectionMatcher(DeviceSelectionConfig{
		Include: DeviceSelectionMatchConfig{DeviceIDs: []string{"device-1"}},
	})

	assert.True(t, selector.allowsResource(attrs))
}

func TestDeviceSelectionMatchesSemanticConventionHostIPSlice(t *testing.T) {
	attrs := pcommon.NewMap()
	hostIPs := attrs.PutEmptySlice("host.ip")
	hostIPs.AppendEmpty().SetStr("192.0.2.10")
	hostIPs.AppendEmpty().SetStr("2001:db8::10")
	selector := newDeviceSelectionMatcher(DeviceSelectionConfig{
		Include: DeviceSelectionMatchConfig{HostIPs: []string{"2001:0db8::10"}},
	})

	assert.True(t, selector.allowsResource(attrs))
}

func TestDeviceSelectionProviderIdentities(t *testing.T) {
	selector := newDeviceSelectionMatcher(DeviceSelectionConfig{
		Include: DeviceSelectionMatchConfig{
			Serials:   []string{"Q234-ABCD-0001", "SERIAL-1", "ACI-SERIAL-1"},
			DeviceIDs: []string{"switch-101"},
		},
	})

	assert.True(t, selector.allows(merakiDeviceIdentity(deviceResource{Serial: "Q234-ABCD-0001"})))
	assert.True(t, selector.allows(intersightTelemetryIdentity(map[string]any{"serial": "SERIAL-1"})))
	assert.True(t, selector.allows(nexusDashboardObjectIdentity(map[string]any{"switchId": "switch-101"})))
	assert.True(t, selector.allows(aciObjectIdentity(map[string]any{"serial": "ACI-SERIAL-1"})))
	assert.False(t, selector.allows(merakiDeviceIdentity(deviceResource{Serial: "Q234-ABCD-9999"})))
}

func TestDeviceSelectionDeviceIDsDoNotMatchGroupingDimensions(t *testing.T) {
	tests := []struct {
		name           string
		stableID       string
		groupingValues []string
		identity       deviceIdentity
	}{
		{
			name:           "Catalyst Center device location",
			stableID:       "catalyst-device-1",
			groupingValues: []string{"building-1", "global/site-1/building-1"},
			identity: catalystDeviceIdentity(catalystcenter.Device{
				ID:           "catalyst-device-1",
				LocationName: "building-1",
				Location:     "global/site-1/building-1",
			}),
		},
		{
			name:           "Catalyst Center issue site",
			stableID:       "issue-entity-1",
			groupingValues: []string{"site-1", "site-hierarchy-1"},
			identity: catalystIssueIdentity(catalystcenter.Issue{
				EntityID:        "issue-entity-1",
				SiteID:          "site-1",
				SiteHierarchyID: "site-hierarchy-1",
			}, catalystcenter.Device{}),
		},
		{
			name:           "SD-WAN inventory grouping dimensions",
			stableID:       "sdwan-device-1",
			groupingValues: []string{"site-1", "C8000V", "vedge"},
			identity: sdwanObjectIdentity(map[string]any{
				"uuid":         "sdwan-device-1",
				"site-id":      "site-1",
				"device-model": "C8000V",
				"personality":  "vedge",
			}),
		},
		{
			name:           "SD-WAN event grouping dimensions",
			stableID:       "192.0.2.10",
			groupingValues: []string{"site-1", "C8000V", "vedge"},
			identity: sdwanEventIdentity(map[string]any{
				"system-ip":    "192.0.2.10",
				"site-id":      "site-1",
				"device-model": "C8000V",
				"personality":  "vedge",
			}),
		},
		{
			name:           "Nexus Dashboard fabric and site",
			stableID:       "switch-101",
			groupingValues: []string{"prod-fabric", "site-1"},
			identity: nexusDashboardObjectIdentity(map[string]any{
				"switchId":   "switch-101",
				"fabricName": "prod-fabric",
				"siteName":   "site-1",
			}),
		},
		{
			name:           "FMC policy",
			stableID:       "fmc-device-1",
			groupingValues: []string{"policy-1", "policy-id-1"},
			identity: fmcObjectIdentity(map[string]any{
				"id":         "fmc-device-1",
				"policyName": "policy-1",
				"policyId":   "policy-id-1",
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stableSelector := newDeviceSelectionMatcher(DeviceSelectionConfig{
				Include: DeviceSelectionMatchConfig{DeviceIDs: []string{tt.stableID}},
			})
			assert.True(t, stableSelector.allows(tt.identity), "stable device ID should match")

			for _, groupingValue := range tt.groupingValues {
				groupingSelector := newDeviceSelectionMatcher(DeviceSelectionConfig{
					Include: DeviceSelectionMatchConfig{DeviceIDs: []string{groupingValue}},
				})
				assert.Falsef(t, groupingSelector.allows(tt.identity), "grouping attribute %q must not act as a device ID", groupingValue)
			}
		})
	}
}

func TestDeviceSelectionResourceDeviceIDsExcludeSDWANSite(t *testing.T) {
	attrs := pcommon.NewMap()
	attrs.PutStr("sdwan.site.id", "site-1")
	attrs.PutStr("sdwan.system_ip", "192.0.2.10")

	stableSelector := newDeviceSelectionMatcher(DeviceSelectionConfig{
		Include: DeviceSelectionMatchConfig{DeviceIDs: []string{"192.0.2.10"}},
	})
	assert.True(t, stableSelector.allowsResource(attrs))

	siteSelector := newDeviceSelectionMatcher(DeviceSelectionConfig{
		Include: DeviceSelectionMatchConfig{DeviceIDs: []string{"site-1"}},
	})
	assert.False(t, siteSelector.allowsResource(attrs))
}

func TestDeviceSelectionConfigValidate(t *testing.T) {
	require.NoError(t, (DeviceSelectionConfig{
		Include: DeviceSelectionMatchConfig{
			HostNames: []string{" edge-1 "},
			HostIPs:   []string{"192.0.2.10", "2001:db8::10"},
		},
	}).Validate())

	tests := []struct {
		name    string
		config  DeviceSelectionConfig
		wantErr string
	}{
		{
			name:    "blank include",
			config:  DeviceSelectionConfig{Include: DeviceSelectionMatchConfig{Serials: []string{" "}}},
			wantErr: "include.serials[0] cannot be empty",
		},
		{
			name:    "blank exclude",
			config:  DeviceSelectionConfig{Exclude: DeviceSelectionMatchConfig{DeviceIDs: []string{"\t"}}},
			wantErr: "exclude.device_ids[0] cannot be empty",
		},
		{
			name:    "invalid include IP",
			config:  DeviceSelectionConfig{Include: DeviceSelectionMatchConfig{HostIPs: []string{"192.0.2.999"}}},
			wantErr: "include.host_ips[0] must be a valid IP address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorContains(t, tt.config.Validate(), tt.wantErr)
		})
	}
}

func TestSSHDeviceSelectionUsesDiscoveredAndConfiguredIdentity(t *testing.T) {
	tests := []struct {
		name     string
		config   DeviceSelectionConfig
		wantSent bool
	}{
		{
			name:     "include discovered serial",
			config:   DeviceSelectionConfig{Include: DeviceSelectionMatchConfig{Serials: []string{"SERIAL-1"}}},
			wantSent: true,
		},
		{
			name:     "exclude discovered serial",
			config:   DeviceSelectionConfig{Exclude: DeviceSelectionMatchConfig{Serials: []string{"SERIAL-1"}}},
			wantSent: false,
		},
		{
			name:     "include configured host name after discovery",
			config:   DeviceSelectionConfig{Include: DeviceSelectionMatchConfig{HostNames: []string{"configured-edge"}}},
			wantSent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink := &consumertest.MetricsSink{}
			store := &connection.DeviceMetadataStore{}
			store.Store(connection.DeviceMetadata{HostName: "discovered-edge", HostID: "SERIAL-1", Serial: "SERIAL-1", OSType: "IOS XE"})
			consumer := newSSHDeviceSelectionConsumer(sink, newDeviceSelectionMatcher(tt.config), DeviceConfig{
				Name: "configured-edge",
				Host: "192.0.2.10",
			}, store)
			md := pmetric.NewMetrics()
			rm := md.ResourceMetrics().AppendEmpty()
			rm.Resource().Attributes().PutStr("host.name", "discovered-edge")
			rm.Resource().Attributes().PutStr("cisco.switch.serial", "SERIAL-1")
			metric := rm.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
			metric.SetName("cisco.device.up")
			metric.SetEmptyGauge().DataPoints().AppendEmpty().SetIntValue(1)

			require.NoError(t, consumer.ConsumeMetrics(t.Context(), md))
			assert.Equal(t, tt.wantSent, len(sink.AllMetrics()) == 1)
		})
	}
}

func TestSSHDeviceSelectionFailsClosedBeforeExclusionIdentityDiscovery(t *testing.T) {
	for _, tt := range []struct {
		name     string
		metadata *connection.DeviceMetadata
	}{
		{name: "no verified metadata"},
		{name: "supported OS without required serial", metadata: &connection.DeviceMetadata{OSType: "IOS XE"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := &connection.DeviceMetadataStore{}
			if tt.metadata != nil {
				store.Store(*tt.metadata)
			}
			sink := &consumertest.MetricsSink{}
			consumer := newSSHDeviceSelectionConsumer(sink, newDeviceSelectionMatcher(DeviceSelectionConfig{
				Exclude: DeviceSelectionMatchConfig{Serials: []string{"LAB-DO-NOT-COLLECT"}},
			}), DeviceConfig{Name: "configured-edge", Host: "192.0.2.10"}, store)

			md := pmetric.NewMetrics()
			rm := md.ResourceMetrics().AppendEmpty()
			metric := rm.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
			metric.SetName("cisco.device.up")
			metric.SetEmptyGauge().DataPoints().AppendEmpty().SetIntValue(0)
			require.NoError(t, consumer.ConsumeMetrics(t.Context(), md))
			assert.Empty(t, sink.AllMetrics())
		})
	}
}

func TestSSHDeviceSelectionRetainsVerifiedIdentityAcrossConnectionFailure(t *testing.T) {
	newMetrics := func(hostName, hostID, serial string) pmetric.Metrics {
		md := pmetric.NewMetrics()
		rm := md.ResourceMetrics().AppendEmpty()
		if hostName != "" {
			rm.Resource().Attributes().PutStr("host.name", hostName)
		}
		if hostID != "" {
			rm.Resource().Attributes().PutStr("host.id", hostID)
		}
		if serial != "" {
			rm.Resource().Attributes().PutStr("cisco.switch.serial", serial)
		}
		metric := rm.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
		metric.SetName("cisco.device.up")
		metric.SetEmptyGauge().DataPoints().AppendEmpty().SetIntValue(1)
		return md
	}

	for _, tt := range []struct {
		name        string
		config      DeviceSelectionConfig
		wantBatches int
	}{
		{
			name:        "included serial keeps failure health",
			config:      DeviceSelectionConfig{Include: DeviceSelectionMatchConfig{Serials: []string{"SERIAL-1"}}},
			wantBatches: 2,
		},
		{
			name:        "excluded serial keeps failure health excluded",
			config:      DeviceSelectionConfig{Exclude: DeviceSelectionMatchConfig{Serials: []string{"SERIAL-1"}}},
			wantBatches: 0,
		},
		{
			name:        "included discovered host name keeps failure health",
			config:      DeviceSelectionConfig{Include: DeviceSelectionMatchConfig{HostNames: []string{"discovered-edge"}}},
			wantBatches: 2,
		},
		{
			name:        "excluded discovered host name keeps failure health excluded",
			config:      DeviceSelectionConfig{Exclude: DeviceSelectionMatchConfig{HostNames: []string{"discovered-edge"}}},
			wantBatches: 0,
		},
		{
			name:        "included discovered host ID keeps failure health",
			config:      DeviceSelectionConfig{Include: DeviceSelectionMatchConfig{HostIDs: []string{"SERIAL-1"}}},
			wantBatches: 2,
		},
		{
			name:        "excluded discovered host ID keeps failure health excluded",
			config:      DeviceSelectionConfig{Exclude: DeviceSelectionMatchConfig{HostIDs: []string{"SERIAL-1"}}},
			wantBatches: 0,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := &connection.DeviceMetadataStore{}
			store.Store(connection.DeviceMetadata{HostName: "discovered-edge", HostID: "SERIAL-1", Serial: "SERIAL-1", OSType: "IOS XE"})
			sink := &consumertest.MetricsSink{}
			consumer := newSSHDeviceSelectionConsumer(sink, newDeviceSelectionMatcher(tt.config), DeviceConfig{
				Name: "configured-edge",
				Host: "192.0.2.10",
			}, store)

			// The first batch carries live discovery metadata. The second models a
			// later connection-establishment failure and contains only the scraper's
			// configured fallback aliases.
			require.NoError(t, consumer.ConsumeMetrics(t.Context(), newMetrics("discovered-edge", "SERIAL-1", "SERIAL-1")))
			require.NoError(t, consumer.ConsumeMetrics(t.Context(), newMetrics("configured-edge", "192.0.2.10", "")))
			assert.Len(t, sink.AllMetrics(), tt.wantBatches)
			if tt.wantBatches == 2 {
				outageAttrs := sink.AllMetrics()[1].ResourceMetrics().At(0).Resource().Attributes()
				assert.Equal(t, "discovered-edge", attrString(outageAttrs, "host.name"))
				assert.Equal(t, "SERIAL-1", attrString(outageAttrs, "host.id"))
				assert.Equal(t, "SERIAL-1", attrString(outageAttrs, "cisco.switch.serial"))
			}
		})
	}
}

func TestSSHDeviceSelectionDoesNotTreatProviderDeviceIDAsDiscoverable(t *testing.T) {
	selector := newDeviceSelectionMatcher(DeviceSelectionConfig{
		Include: DeviceSelectionMatchConfig{DeviceIDs: []string{"provider-only-id"}},
	})
	assert.False(t, selector.allowsSSHConfiguration(sshDeviceIdentity(DeviceConfig{
		Name: "configured-edge",
		Host: "192.0.2.10",
	})))
}

func TestSSHDeviceSelectionRetainsDiscoveredHostnameForUnnamedTargetFailure(t *testing.T) {
	for _, tt := range []struct {
		name        string
		config      DeviceSelectionConfig
		wantBatches int
	}{
		{
			name:        "include",
			config:      DeviceSelectionConfig{Include: DeviceSelectionMatchConfig{HostNames: []string{"discovered-edge"}}},
			wantBatches: 1,
		},
		{
			name:        "exclude",
			config:      DeviceSelectionConfig{Exclude: DeviceSelectionMatchConfig{HostNames: []string{"discovered-edge"}}},
			wantBatches: 0,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := &connection.DeviceMetadataStore{}
			store.Store(connection.DeviceMetadata{HostName: "discovered-edge", OSType: "IOS XE"})
			sink := &consumertest.MetricsSink{}
			consumer := newSSHDeviceSelectionConsumer(sink, newDeviceSelectionMatcher(tt.config), DeviceConfig{
				Host: "192.0.2.10",
			}, store)
			md := pmetric.NewMetrics()
			rm := md.ResourceMetrics().AppendEmpty()
			rm.Resource().Attributes().PutStr("host.name", "192.0.2.10")
			rm.Resource().Attributes().PutStr("host.id", "192.0.2.10")
			metric := rm.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
			metric.SetName("cisco.device.up")
			metric.SetEmptyGauge().DataPoints().AppendEmpty().SetIntValue(0)

			require.NoError(t, consumer.ConsumeMetrics(t.Context(), md))
			assert.Len(t, sink.AllMetrics(), tt.wantBatches)
		})
	}
}
