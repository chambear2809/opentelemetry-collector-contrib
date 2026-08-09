// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/confmaptest"
	"go.yaml.in/yaml/v3"
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
				target := cfg.GNMI.Targets[0].withDefaults()
				assert.Equal(t, "nexus-shard-01", target.Name)
				assert.Equal(t, "nx_os", target.ProductFamily)
				assert.Equal(t, 2*time.Minute, target.SyncTimeout)
				assert.Equal(t, []string{"json", "json_ietf"}, target.EncodingPreference)
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

func TestKubernetesGNMIShardEmbeddedConfigsValidate(t *testing.T) {
	file, err := os.Open(filepath.Join("examples", "kubernetes-gnmi-shard.yaml"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })

	decoder := yaml.NewDecoder(file)
	validated := 0
	for {
		var manifest struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
			Data map[string]string `yaml:"data"`
		}
		err = decoder.Decode(&manifest)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		collectorYAML, ok := manifest.Data["collector.yaml"]
		if manifest.Kind != "ConfigMap" || !ok {
			continue
		}

		t.Run(manifest.Metadata.Name, func(t *testing.T) {
			var raw map[string]any
			require.NoError(t, yaml.Unmarshal([]byte(collectorYAML), &raw))
			collectorConf := confmap.NewFromStringMap(raw)
			receiverConf, subErr := collectorConf.Sub("receivers::cisco_os")
			require.NoError(t, subErr)

			cfg := NewFactory().CreateDefaultConfig().(*Config)
			require.NoError(t, cfg.Unmarshal(receiverConf))
			require.NoError(t, cfg.Validate())
		})
		validated++
	}
	require.Equal(t, 2, validated, "every collector ConfigMap must be validated")
}
