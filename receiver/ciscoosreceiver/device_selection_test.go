// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"
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
