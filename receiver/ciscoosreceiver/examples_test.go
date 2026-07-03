// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap/confmaptest"
)

func TestShippedCiscoOSReceiverExamplesUnmarshalAndValidate(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		resolve   func(*Config)
		assertion func(*testing.T, *Config)
	}{
		{
			name: "secure gNMI",
			path: filepath.Join("examples", "gnmi-secure.yaml"),
			assertion: func(t *testing.T, cfg *Config) {
				require.Len(t, cfg.GNMI.Targets, 1)
				assert.Equal(t, "nexus-shard-01", cfg.GNMI.Targets[0].Name)
			},
		},
		{
			name: "Catalyst Center and SD-WAN",
			path: filepath.Join("examples", "catalyst-sdwan-splunk-platform.yaml"),
			resolve: func(cfg *Config) {
				// Environment expansion normally happens before component decoding.
				// confmaptest deliberately loads the file without an env provider, so
				// substitute only the URL values whose syntax is validated here.
				cfg.CatalystCenter.Endpoint = "https://catalyst-center.example.test"
				cfg.SDWAN.Endpoint = "https://sdwan.example.test"
			},
			assertion: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.CatalystCenter.Enabled)
				assert.True(t, cfg.SDWAN.Enabled)
				assert.False(t, cfg.SDWAN.RealtimeDetails.Enabled)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf, err := confmaptest.LoadConf(tt.path)
			require.NoError(t, err)
			receiverConf, err := conf.Sub("receivers::cisco_os")
			require.NoError(t, err)

			cfg := NewFactory().CreateDefaultConfig().(*Config)
			require.NoError(t, cfg.Unmarshal(receiverConf))
			if tt.resolve != nil {
				tt.resolve(cfg)
			}
			require.NoError(t, cfg.Validate())
			tt.assertion(t, cfg)
		})
	}
}
