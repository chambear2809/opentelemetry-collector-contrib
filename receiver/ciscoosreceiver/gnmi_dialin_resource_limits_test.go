// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGNMIDialInCombinedFrameEnvelope(t *testing.T) {
	t.Run("legacy boundary", func(t *testing.T) {
		cfg := validIOSXRConfig()
		cfg.IOSXR.DialIn.Targets = legacyIOSXRTargets(128)
		require.NoError(t, cfg.Validate())

		cfg.IOSXR.DialIn.Targets = legacyIOSXRTargets(129)
		require.ErrorContains(t, cfg.Validate(), "516 MiB of stream-by-frame capacity")
	})

	t.Run("split legacy providers", func(t *testing.T) {
		cfg := NewFactory().CreateDefaultConfig().(*Config)
		cfg.IOSXR.DialIn.Targets = legacyIOSXRTargets(64)
		cfg.Catalyst9800.DialIn.Targets = legacyCatalyst9800Targets(64, 64)
		require.NoError(t, cfg.validateGNMI())

		cfg.Catalyst9800.DialIn.Targets = legacyCatalyst9800Targets(65, 64)
		require.ErrorContains(t, cfg.validateGNMI(), "516 MiB of stream-by-frame capacity")
	})

	t.Run("shared and legacy", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.IOSXR.DialIn.Targets = legacyIOSXRTargets(112)
		require.NoError(t, cfg.validateGNMI(), "one default shared target plus 112 legacy targets exactly fit")

		cfg.IOSXR.DialIn.Targets = legacyIOSXRTargets(113)
		require.ErrorContains(t, cfg.validateGNMI(), "516 MiB of stream-by-frame capacity")
	})

	t.Run("excluded targets do not charge runtime envelope", func(t *testing.T) {
		cfg := NewFactory().CreateDefaultConfig().(*Config)
		cfg.IOSXR.DialIn.Targets = legacyIOSXRTargets(129)
		cfg.DeviceSelection.Exclude.HostNames = []string{"legacy-iosxr-128"}
		require.NoError(t, cfg.validateGNMI())
	})

	t.Run("enabled dial-out servers share the receiver envelope", func(t *testing.T) {
		cfg := NewFactory().CreateDefaultConfig().(*Config)
		cfg.IOSXR.DialOut.Enabled = true
		cfg.Catalyst9800.DialOut.Enabled = true
		require.NoError(t, cfg.validateGNMI(), "two default 64-by-4 MiB dial-out servers exactly fit")

		cfg.IOSXR.DialIn.Targets = legacyIOSXRTargets(1)
		require.ErrorContains(t, cfg.validateGNMI(), "516 MiB of stream-by-frame capacity")
	})

	t.Run("programmatic dial-out defaults are charged", func(t *testing.T) {
		cfg := &Config{
			IOSXR:        IOSXRConfig{DialOut: IOSXRDialOutConfig{Enabled: true}},
			Catalyst9800: Catalyst9800Config{DialOut: Catalyst9800DialOutConfig{Enabled: true}},
		}
		require.NoError(t, cfg.validateGNMI())
		cfg.IOSXR.DialIn.Targets = legacyIOSXRTargets(1)
		require.ErrorContains(t, cfg.validateGNMI(), "516 MiB of stream-by-frame capacity")
	})
}

func TestGNMIDialInCombinedTargetDefinitionLimit(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.IOSXR.DialIn.Targets = legacyIOSXRTargets(128)
	cfg.Catalyst9800.DialIn.Targets = legacyCatalyst9800Targets(128, 128)
	cfg.DeviceSelection.Include.HostNames = []string{"legacy-iosxr-0"}
	require.NoError(t, cfg.validateGNMI(), "excluded definitions still fit the configuration ceiling")

	cfg.GNMI.Targets = []GNMITargetConfig{{Name: "excluded-shared", Endpoint: "excluded.example.test:57400"}}
	require.ErrorContains(t, cfg.validateGNMI(), "must contain at most 256 targets in total")
}

func TestLegacyTargetsDoNotConsumeSharedCacheSeriesMinimum(t *testing.T) {
	cfg := validGNMITestConfig()
	cfg.GNMI.MaxCachedSeries = 1
	cfg.IOSXR.DialIn.Targets = legacyIOSXRTargets(1)
	require.NoError(t, cfg.validateGNMI())

	second := cfg.GNMI.Targets[0]
	second.Name = "edge-2"
	second.Endpoint = "edge-2.example.test:57400"
	cfg.GNMI.Targets = append(cfg.GNMI.Targets, second)
	require.ErrorContains(t, cfg.validateGNMI(), "smaller than the selected target count 2")
}

func legacyIOSXRTargets(count int) []IOSXRTargetConfig {
	base := validIOSXRConfig().IOSXR.DialIn.Targets[0]
	targets := make([]IOSXRTargetConfig, 0, count)
	for index := range count {
		target := base
		target.Name = fmt.Sprintf("legacy-iosxr-%d", index)
		target.Endpoint = fmt.Sprintf("legacy-iosxr-%d.example.test:57400", index)
		targets = append(targets, target)
	}
	return targets
}

func legacyCatalyst9800Targets(count, offset int) []Catalyst9800TargetConfig {
	base := validCatalyst9800Config().Catalyst9800.DialIn.Targets[0]
	targets := make([]Catalyst9800TargetConfig, 0, count)
	for index := range count {
		target := base
		target.Name = fmt.Sprintf("legacy-catalyst-%d", index+offset)
		target.Endpoint = fmt.Sprintf("legacy-catalyst-%d.example.test:57400", index+offset)
		targets = append(targets, target)
	}
	return targets
}
