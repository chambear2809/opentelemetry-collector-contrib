// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
)

func TestGNMIDialOutOmittedPerClientCapPreservesLowerGlobalCapAfterUnmarshal(t *testing.T) {
	const globalCap = uint32(8)

	t.Run("Catalyst 9800", func(t *testing.T) {
		cfg := NewFactory().CreateDefaultConfig().(*Config)
		parser := confmap.NewFromStringMap(map[string]any{
			"catalyst_9800": map[string]any{
				"enabled": true,
				"dial_out": map[string]any{
					"enabled":                true,
					"max_concurrent_streams": globalCap,
				},
			},
		})

		require.NoError(t, parser.Unmarshal(cfg))
		assert.Zero(t, cfg.Catalyst9800.DialOut.MaxStreamsPerClient)
		require.NoError(t, cfg.Validate())
		assert.Equal(t, globalCap, cfg.Catalyst9800.withDefaults().DialOut.MaxStreamsPerClient)
	})

	t.Run("IOS XR", func(t *testing.T) {
		cfg := NewFactory().CreateDefaultConfig().(*Config)
		parser := confmap.NewFromStringMap(map[string]any{
			"ios_xr": map[string]any{
				"enabled": true,
				"dial_out": map[string]any{
					"enabled":                true,
					"max_concurrent_streams": globalCap,
				},
			},
		})

		require.NoError(t, parser.Unmarshal(cfg))
		assert.Zero(t, cfg.IOSXR.DialOut.MaxStreamsPerClient)
		require.NoError(t, cfg.Validate())
		assert.Equal(t, globalCap, cfg.IOSXR.withDefaults().DialOut.MaxStreamsPerClient)
	})
}
