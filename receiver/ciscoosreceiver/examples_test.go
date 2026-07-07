// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap/confmaptest"
	"gopkg.in/yaml.v3"
)

func TestShippedCiscoOSReceiverExamplesUnmarshalAndValidate(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		receiverKey string
		resolve     func(*Config)
		assertion   func(*testing.T, *Config)
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
		{
			name:        "ACI to Splunk Observability Cloud",
			path:        filepath.Join("examples", "aci-splunk-o11y.yaml"),
			receiverKey: "cisco_os/aci",
			resolve: func(cfg *Config) {
				cfg.ACI.Controllers[0].Endpoint = "https://apic.example.test"
				cfg.ACI.CAFile = "/etc/otelcol/apic-ca.pem"
				cfg.ACI.ServerName = "apic.example.test"
			},
			assertion: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.ACI.Enabled)
				require.Len(t, cfg.ACI.Controllers, 1)
				assert.Equal(t, "apic-primary", cfg.ACI.Controllers[0].Name)
				assert.Equal(t, "/etc/otelcol/apic-ca.pem", cfg.ACI.CAFile)
				assert.Equal(t, "apic.example.test", cfg.ACI.ServerName)
				assert.False(t, cfg.ACI.InsecureSkipVerify)
			},
		},
		{
			name:        "FMC to Splunk Observability Cloud",
			path:        filepath.Join("examples", "fmc-splunk-o11y.yaml"),
			receiverKey: "cisco_os/fmc",
			resolve: func(cfg *Config) {
				cfg.FMC.Controllers[0].Endpoint = "https://fmc.example.test"
			},
			assertion: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.FMC.Enabled)
				require.Len(t, cfg.FMC.Controllers, 1)
				assert.Equal(t, "fmc-primary", cfg.FMC.Controllers[0].Name)
				assert.False(t, cfg.FMC.InsecureSkipVerify)
				assert.True(t, cfg.FMC.Manager.Enabled)
				assert.True(t, cfg.FMC.Inventory.Enabled)
				assert.True(t, cfg.FMC.Interfaces.Enabled)
				assert.True(t, cfg.FMC.Health.Enabled)
				assert.True(t, cfg.FMC.VPN.Enabled)
				assert.True(t, cfg.FMC.HA.Enabled)
				assert.True(t, cfg.FMC.Policy.Enabled)
				assert.True(t, cfg.FMC.Deployments.Enabled)
				assert.False(t, cfg.FMC.Audit.Enabled)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf, err := confmaptest.LoadConf(tt.path)
			require.NoError(t, err)
			receiverKey := tt.receiverKey
			if receiverKey == "" {
				receiverKey = "cisco_os"
			}
			receiverConf, err := conf.Sub("receivers::" + receiverKey)
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

func TestKubernetesGNMIShardEmbeddedCollectorConfigsUnmarshalAndValidate(t *testing.T) {
	file, err := os.Open(filepath.Join("examples", "kubernetes-gnmi-shard.yaml"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })

	type manifest struct {
		Kind     string `yaml:"kind"`
		Metadata struct {
			Name string `yaml:"name"`
		} `yaml:"metadata"`
		Data map[string]string `yaml:"data"`
	}
	decoder := yaml.NewDecoder(file)
	validated := map[string]string{}
	for {
		var document manifest
		decodeErr := decoder.Decode(&document)
		if errors.Is(decodeErr, io.EOF) {
			break
		}
		require.NoError(t, decodeErr)
		if document.Kind != "ConfigMap" || document.Data["collector.yaml"] == "" {
			continue
		}
		t.Run(document.Metadata.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "collector.yaml")
			require.NoError(t, os.WriteFile(path, []byte(document.Data["collector.yaml"]), 0o600))
			conf, loadErr := confmaptest.LoadConf(path)
			require.NoError(t, loadErr)
			receiverConf, subErr := conf.Sub("receivers::cisco_os")
			require.NoError(t, subErr)
			cfg := NewFactory().CreateDefaultConfig().(*Config)
			require.NoError(t, cfg.Unmarshal(receiverConf))
			require.NoError(t, cfg.Validate())
			require.Len(t, cfg.GNMI.Targets, 1)
			target := cfg.GNMI.Targets[0]
			validated[document.Metadata.Name] = target.Product
			if target.Product == gnmiProductNexus9000 {
				require.NotNil(t, target.Profiles.System.Enabled)
				assert.False(t, *target.Profiles.System.Enabled, "Nexus example must explicitly disable the unavailable system profile")
			}
		})
	}
	assert.Equal(t, map[string]string{
		"cisco-gnmi-shard-01": gnmiProductNexus9000,
		"cisco-gnmi-shard-02": gnmiProductASR9000,
	}, validated)
}
