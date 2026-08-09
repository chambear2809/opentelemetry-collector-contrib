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
				target := cfg.GNMI.Targets[0].withDefaults()
				assert.Equal(t, "nexus-shard-01", target.Name)
				assert.Equal(t, "nx_os", target.ProductFamily)
				assert.Equal(t, 2*time.Minute, target.SyncTimeout)
				assert.Equal(t, []string{"json", "json_ietf"}, target.EncodingPreference)
			},
		},
		{
			name: "Catalyst switch gNMI",
			path: filepath.Join("examples", "gnmi-catalyst-switches.yaml"),
			assertion: func(t *testing.T, cfg *Config) {
				require.Len(t, cfg.GNMI.Targets, 2)
				assert.Equal(t, gnmiProductCatalyst9300, cfg.GNMI.Targets[0].Product)
				assert.Equal(t, gnmiReviewedIOSXESwitchRelease17181, cfg.GNMI.Targets[0].SoftwareVersion)
				assert.True(t, cfg.GNMI.Targets[0].AllowUnqualified)
				assert.Equal(t, gnmiProductCatalyst9500, cfg.GNMI.Targets[1].Product)
				assert.Equal(t, gnmiReviewedIOSXESwitchRelease17181, cfg.GNMI.Targets[1].SoftwareVersion)
				assert.True(t, cfg.GNMI.Targets[1].AllowUnqualified)
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
				assert.True(t, cfg.ACI.Logs.Faults.Enabled)
				assert.True(t, cfg.ACI.Logs.Audit.Enabled)
				assert.True(t, cfg.ACI.Logs.Events.Enabled)
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
