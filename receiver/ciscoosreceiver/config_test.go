// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/confmaptest"
	"go.opentelemetry.io/collector/confmap/xconfmap"
	"go.opentelemetry.io/collector/scraper/scraperhelper"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/interfacesscraper"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/systemscraper"
)

func newTestDeviceConfig(host string, port int, auth connection.AuthConfig) DeviceConfig {
	return DeviceConfig{
		Name: "test-device",
		Host: host,
		Port: port,
		Auth: auth,
	}
}

func validTestDevice() DeviceConfig {
	return newTestDeviceConfig("192.168.1.1", 22, connection.AuthConfig{
		Username:           "admin",
		Password:           configopaque.String("password"),
		InsecureSkipVerify: true,
	})
}

func TestDefaultACIConfigKeepsMetricsEnabledAndLogsDisabled(t *testing.T) {
	cfg := defaultACIConfig()

	assert.True(t, cfg.Faults.Enabled)
	assert.True(t, cfg.Audit.Enabled)
	assert.True(t, cfg.Events.Enabled)
	assert.False(t, cfg.Logs.Faults.Enabled)
	assert.False(t, cfg.Logs.Audit.Enabled)
	assert.False(t, cfg.Logs.Events.Enabled)
	assert.False(t, cfg.hasLogs())
}

func TestACILogOptInActivatesACIValidationWithAnotherValidProvider(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Meraki.Auth.APIKey = configopaque.String("meraki-key")
	cfg.Meraki.Organizations = []MerakiOrganizationConfig{{OrganizationID: "123456"}}

	assert.False(t, cfg.ACI.hasTarget())
	require.NoError(t, cfg.Validate(), "safe-default ACI logs must remain inert")

	cfg.ACI.Logs.Audit.Enabled = true
	assert.True(t, cfg.ACI.hasTarget(), "an explicit ACI log opt-in must express ACI configuration intent")
	err := cfg.Validate()
	require.ErrorContains(t, err, "aci.controllers must include at least one APIC endpoint")
	assert.ErrorContains(t, err, "aci.auth.username must be provided")
	assert.ErrorContains(t, err, "aci.auth.password must be provided")
}

func TestACILogOnlyIntentActivatesACIValidationWithoutAnotherProvider(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.ACI.Logs.Events.Enabled = true

	assert.True(t, cfg.ACI.hasTarget())
	err := cfg.Validate()
	require.ErrorContains(t, err, "aci.controllers must include at least one APIC endpoint")
	assert.ErrorContains(t, err, "aci.auth.username must be provided")
	assert.ErrorContains(t, err, "aci.auth.password must be provided")
}

func TestConfigUnmarshalACILogOptInAndLegacyCompatibility(t *testing.T) {
	tests := []struct {
		name             string
		aci              map[string]any
		wantMetricFaults bool
		wantLogs         ACILogsConfig
	}{
		{
			name:             "omitted log config stays disabled",
			aci:              map[string]any{},
			wantMetricFaults: true,
		},
		{
			name: "new signal settings opt in independently",
			aci: map[string]any{
				"logs": map[string]any{
					"faults": map[string]any{"enabled": true},
					"audit":  map[string]any{"enabled": false},
					"events": map[string]any{"enabled": true},
				},
			},
			wantMetricFaults: true,
			wantLogs: ACILogsConfig{
				Faults: ACILogSignalConfig{Enabled: true},
				Events: ACILogSignalConfig{Enabled: true},
			},
		},
		{
			name: "explicit legacy group opt in remains compatible",
			aci: map[string]any{
				"faults": map[string]any{"enabled": true},
				"audit":  map[string]any{"enabled": false},
			},
			wantMetricFaults: true,
			wantLogs: ACILogsConfig{
				Faults: ACILogSignalConfig{Enabled: true},
			},
		},
		{
			name: "new explicit setting overrides legacy opt in",
			aci: map[string]any{
				"faults": map[string]any{"enabled": true},
				"logs": map[string]any{
					"faults": map[string]any{"enabled": false},
				},
			},
			wantMetricFaults: true,
		},
		{
			name: "new empty signal block keeps safe default over legacy opt in",
			aci: map[string]any{
				"faults": map[string]any{"enabled": true},
				"logs": map[string]any{
					"faults": map[string]any{},
				},
			},
			wantMetricFaults: true,
		},
		{
			name: "log opt in does not reenable fault metrics",
			aci: map[string]any{
				"faults": map[string]any{"enabled": false},
				"logs": map[string]any{
					"faults": map[string]any{"enabled": true},
				},
			},
			wantMetricFaults: false,
			wantLogs: ACILogsConfig{
				Faults: ACILogSignalConfig{Enabled: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createDefaultConfig().(*Config)
			require.NoError(t, cfg.Unmarshal(confmap.NewFromStringMap(map[string]any{"aci": tt.aci})))

			assert.Equal(t, tt.wantMetricFaults, cfg.ACI.Faults.Enabled)
			assert.Equal(t, tt.wantLogs.Faults.Enabled, cfg.ACI.Logs.Faults.Enabled)
			assert.Equal(t, tt.wantLogs.Audit.Enabled, cfg.ACI.Logs.Audit.Enabled)
			assert.Equal(t, tt.wantLogs.Events.Enabled, cfg.ACI.Logs.Events.Enabled)
		})
	}
}

func TestConfigUnmarshalRejectsMalformedACILogSettings(t *testing.T) {
	type malformedShape struct {
		name    string
		value   any
		nullErr bool
	}
	shapes := []malformedShape{
		{name: "boolean", value: false},
		{name: "null", value: nil, nullErr: true},
		{name: "string", value: "enabled"},
		{name: "list", value: []any{"enabled"}},
	}
	type testCase struct {
		name    string
		aci     map[string]any
		wantErr string
	}

	tests := make([]testCase, 0, len(shapes)*4)
	for _, shape := range shapes {
		wantErr := "logs"
		if shape.nullErr {
			wantErr = "aci.logs must be a map and cannot be null"
		}
		tests = append(tests, testCase{
			name: "top-level logs/" + shape.name,
			aci: map[string]any{
				"faults": map[string]any{"enabled": true},
				"logs":   shape.value,
			},
			wantErr: wantErr,
		})

		for _, signal := range []string{"faults", "audit", "events"} {
			wantSignalErr := "logs"
			if shape.nullErr {
				wantSignalErr = fmt.Sprintf("aci.logs.%s must be a map and cannot be null", signal)
			}
			tests = append(tests, testCase{
				name: signal + " signal/" + shape.name,
				aci: map[string]any{
					signal: map[string]any{"enabled": true},
					"logs": map[string]any{signal: shape.value},
				},
				wantErr: wantSignalErr,
			})
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createDefaultConfig().(*Config)
			err := cfg.Unmarshal(confmap.NewFromStringMap(map[string]any{"aci": tt.aci}))
			require.Error(t, err)
			assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tt.wantErr))
			assert.False(t, cfg.ACI.hasLogs(), "malformed input must never enable ACI logs")
		})
	}
}

func TestConfigUnmarshalRejectsNullACILogSettingsFromYAML(t *testing.T) {
	type testCase struct {
		name    string
		yaml    string
		wantErr string
	}
	tests := []testCase{
		{
			name:    "top-level logs",
			yaml:    "aci:\n  logs: null\n",
			wantErr: "aci.logs must be a map and cannot be null",
		},
	}
	for _, signal := range []string{"faults", "audit", "events"} {
		tests = append(tests, testCase{
			name:    signal + " signal",
			yaml:    fmt.Sprintf("aci:\n  logs:\n    %s: null\n", signal),
			wantErr: fmt.Sprintf("aci.logs.%s must be a map and cannot be null", signal),
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(path, []byte(tt.yaml), 0o600))
			cm, err := confmaptest.LoadConf(path)
			require.NoError(t, err)

			cfg := createDefaultConfig().(*Config)
			err = cfg.Unmarshal(cm)
			require.ErrorContains(t, err, tt.wantErr)
			assert.False(t, cfg.ACI.hasLogs(), "YAML null must never enable ACI logs")
		})
	}
}

func TestConfigValidateRejectsUnsafeDeviceSelection(t *testing.T) {
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
			name:    "invalid IP",
			config:  DeviceSelectionConfig{Include: DeviceSelectionMatchConfig{HostIPs: []string{"192.0.2.999"}}},
			wantErr: "include.host_ips[0] must be a valid IP address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createDefaultConfig().(*Config)
			cfg.Devices = []DeviceConfig{validTestDevice()}
			cfg.Scrapers = map[component.Type]component.Config{component.MustNewType("system"): nil}
			cfg.DeviceSelection = tt.config
			require.ErrorContains(t, cfg.Validate(), tt.wantErr)
		})
	}
}

func TestControllerConfigRejectsDuplicateEffectiveIdentities(t *testing.T) {
	t.Run("SSH normalized endpoint", func(t *testing.T) {
		for _, tt := range []struct {
			name       string
			firstHost  string
			secondHost string
			endpoint   string
		}{
			{name: "DNS case and trailing dot", firstHost: "Router.EXAMPLE.test.", secondHost: "router.example.test", endpoint: "router.example.test:22"},
			{name: "canonical IPv6", firstHost: "2001:0db8:0:0:0:0:0:10", secondHost: "2001:db8::10", endpoint: "[2001:db8::10]:22"},
		} {
			t.Run(tt.name, func(t *testing.T) {
				first := validTestDevice()
				first.Host = tt.firstHost
				second := validTestDevice()
				second.Host = tt.secondHost
				cfg := createDefaultConfig().(*Config)
				cfg.Devices = []DeviceConfig{first, second}
				cfg.Scrapers = map[component.Type]component.Config{component.MustNewType("system"): nil}

				require.ErrorContains(t, cfg.Validate(), fmt.Sprintf("devices[1] endpoint %q duplicates devices[0] after host normalization", tt.endpoint))
			})
		}
	})

	t.Run("SSH same host different port", func(t *testing.T) {
		first := validTestDevice()
		second := validTestDevice()
		second.Host = "192.168.1.1"
		second.Port = 2222
		cfg := createDefaultConfig().(*Config)
		cfg.Devices = []DeviceConfig{first, second}
		cfg.Scrapers = map[component.Type]component.Config{component.MustNewType("system"): nil}

		require.NoError(t, cfg.Validate())
	})

	t.Run("ACI normalized endpoint", func(t *testing.T) {
		cfg := createDefaultConfig().(*Config)
		cfg.ACI.Enabled = true
		cfg.ACI.Controllers = []ACIControllerConfig{
			{Endpoint: "https://APIC.example.test", Name: "apic-a"},
			{Endpoint: "https://apic.example.test:443/", Name: "apic-b"},
		}
		cfg.ACI.Auth.Username = "admin"
		cfg.ACI.Auth.Password = configopaque.String("password")

		require.ErrorContains(t, cfg.validateACI(), "aci.controllers[1].endpoint duplicates aci.controllers[0].endpoint after URL normalization")
	})

	t.Run("FMC effective name", func(t *testing.T) {
		cfg := createDefaultConfig().(*Config)
		cfg.FMC.Enabled = true
		cfg.FMC.Controllers = []FMCControllerConfig{
			{Endpoint: "https://fmc-a.example.test", Name: "production-fmc"},
			{Endpoint: "https://fmc-b.example.test", Name: "PRODUCTION-FMC"},
		}
		cfg.FMC.Auth.Username = "admin"
		cfg.FMC.Auth.Password = configopaque.String("password")

		require.ErrorContains(t, cfg.validateFMC(), "fmc.controllers[1].name duplicates the effective name of fmc.controllers[0]")
	})

	t.Run("eStreamer default port", func(t *testing.T) {
		cfg := createDefaultConfig().(*Config)
		cfg.FMC.EStreamer.Enabled = true
		cfg.FMC.EStreamer.Targets = []FMCEStreamerTargetConfig{
			{Endpoint: "FMC.example.test", Name: "stream-a"},
			{Endpoint: "fmc.example.test:8302", Name: "stream-b"},
		}
		cfg.FMC.EStreamer.TLS.CertFile = "client.crt"
		cfg.FMC.EStreamer.TLS.KeyFile = "client.key"

		require.ErrorContains(t, cfg.validateFMCEStreamer(), "fmc.estreamer.targets[1].endpoint duplicates fmc.estreamer.targets[0].endpoint after address normalization")
	})
}

func TestValidateACITLSConfig(t *testing.T) {
	for _, tt := range []struct {
		name    string
		config  ACIConfig
		wantErr string
	}{
		{
			name: "private CA with DNS server name",
			config: ACIConfig{
				CAFile:     filepath.Join("certs", "apic-ca.pem"),
				ServerName: "apic.example.com",
			},
		},
		{
			name:   "IP server name",
			config: ACIConfig{ServerName: "192.0.2.10"},
		},
		{
			name:    "CA path surrounding whitespace",
			config:  ACIConfig{CAFile: " /etc/otelcol/apic-ca.pem"},
			wantErr: "aci.ca_file must not contain surrounding whitespace",
		},
		{
			name:    "CA path NUL",
			config:  ACIConfig{CAFile: "apic\x00.pem"},
			wantErr: "aci.ca_file must be a valid file path",
		},
		{
			name:    "server name surrounding whitespace",
			config:  ACIConfig{ServerName: " apic.example.com "},
			wantErr: "aci.server_name must not contain surrounding whitespace",
		},
		{
			name:    "server name URL",
			config:  ACIConfig{ServerName: "https://apic.example.com"},
			wantErr: "aci.server_name must be a valid hostname or IP address without a scheme or port",
		},
		{
			name:    "server name port",
			config:  ACIConfig{ServerName: "apic.example.com:443"},
			wantErr: "aci.server_name must be a valid hostname or IP address without a scheme or port",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateACITLSConfig(tt.config)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestACIConfigUnmarshalTLSSettings(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	require.NoError(t, cfg.Unmarshal(confmap.NewFromStringMap(map[string]any{
		"aci": map[string]any{
			"ca_file":     "/etc/otelcol/apic-ca.pem",
			"server_name": "apic.example.com",
		},
	})))
	assert.Equal(t, "/etc/otelcol/apic-ca.pem", cfg.ACI.CAFile)
	assert.Equal(t, "apic.example.com", cfg.ACI.ServerName)
}

func TestACIConfigTLSSettingsActivateValidation(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.ACI.ServerName = "https://apic.example.com"

	err := cfg.Validate()
	require.ErrorContains(t, err, "aci.server_name must be a valid hostname or IP address without a scheme or port")
	require.ErrorContains(t, err, "aci.controllers must include at least one APIC endpoint")
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectedErr string
	}{
		{
			name: "valid config with password auth",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Devices: []DeviceConfig{validTestDevice()},
				Scrapers: map[component.Type]component.Config{
					component.MustNewType("system"): nil,
				},
			},
			expectedErr: "",
		},
		{
			name: "valid config with key file auth",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Devices: []DeviceConfig{
					newTestDeviceConfig("192.168.1.1", 22, connection.AuthConfig{
						Username:           "admin",
						KeyFile:            "/path/to/key",
						InsecureSkipVerify: true,
					}),
				},
				Scrapers: map[component.Type]component.Config{
					component.MustNewType("system"): nil,
				},
			},
			expectedErr: "",
		},
		{
			name: "valid config with known_hosts_file",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Devices: []DeviceConfig{
					newTestDeviceConfig("192.168.1.1", 22, connection.AuthConfig{
						Username:       "admin",
						Password:       configopaque.String("password"),
						KnownHostsFile: "/etc/otelcol/known_hosts",
					}),
				},
				Scrapers: map[component.Type]component.Config{
					component.MustNewType("system"): nil,
				},
			},
			expectedErr: "",
		},
		{
			name: "missing host key verification",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Devices: []DeviceConfig{
					newTestDeviceConfig("192.168.1.1", 22, connection.AuthConfig{
						Username: "admin",
						Password: configopaque.String("password"),
						// neither KnownHostsFile nor InsecureSkipVerify set
					}),
				},
				Scrapers: map[component.Type]component.Config{
					component.MustNewType("system"): nil,
				},
			},
			expectedErr: "known_hosts_file or devices[0].auth.insecure_skip_verify must be set",
		},
		{
			name: "empty device host",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Devices: []DeviceConfig{
					newTestDeviceConfig("", 22, connection.AuthConfig{
						Username:           "admin",
						Password:           configopaque.String("password"),
						InsecureSkipVerify: true,
					}),
				},
				Scrapers: map[component.Type]component.Config{
					component.MustNewType("system"): nil,
				},
			},
			expectedErr: "devices[0].host cannot be empty",
		},
		{
			name: "zero port",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Devices: []DeviceConfig{
					newTestDeviceConfig("192.168.1.1", 0, connection.AuthConfig{
						Username:           "admin",
						Password:           configopaque.String("password"),
						InsecureSkipVerify: true,
					}),
				},
				Scrapers: map[component.Type]component.Config{
					component.MustNewType("system"): nil,
				},
			},
			expectedErr: "devices[0].port must be between 1 and 65535",
		},
		{
			name: "negative port",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Devices: []DeviceConfig{
					newTestDeviceConfig("192.168.1.1", -1, connection.AuthConfig{
						Username:           "admin",
						Password:           configopaque.String("password"),
						InsecureSkipVerify: true,
					}),
				},
				Scrapers: map[component.Type]component.Config{
					component.MustNewType("system"): nil,
				},
			},
			expectedErr: "devices[0].port must be between 1 and 65535",
		},
		{
			name: "port above maximum",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Devices: []DeviceConfig{
					newTestDeviceConfig("192.168.1.1", 65536, connection.AuthConfig{
						Username:           "admin",
						Password:           configopaque.String("password"),
						InsecureSkipVerify: true,
					}),
				},
				Scrapers: map[component.Type]component.Config{
					component.MustNewType("system"): nil,
				},
			},
			expectedErr: "devices[0].port must be between 1 and 65535",
		},
		{
			name: "missing username",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Devices: []DeviceConfig{
					newTestDeviceConfig("192.168.1.1", 22, connection.AuthConfig{
						Username:           "",
						Password:           configopaque.String("password"),
						InsecureSkipVerify: true,
					}),
				},
				Scrapers: map[component.Type]component.Config{
					component.MustNewType("system"): nil,
				},
			},
			expectedErr: "devices[0].auth.username cannot be empty",
		},
		{
			name: "missing password and key file",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Devices: []DeviceConfig{
					newTestDeviceConfig("192.168.1.1", 22, connection.AuthConfig{
						Username:           "admin",
						InsecureSkipVerify: true,
					}),
				},
				Scrapers: map[component.Type]component.Config{
					component.MustNewType("system"): nil,
				},
			},
			expectedErr: "devices[0].auth.password or devices[0].auth.key_file must be provided",
		},
		{
			name: "no devices configured",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Devices: []DeviceConfig{},
				Scrapers: map[component.Type]component.Config{
					component.MustNewType("system"): nil,
				},
			},
			expectedErr: "must specify at least one SSH device, Meraki target, Intersight target, Catalyst Center target, Catalyst 9800 target, SD-WAN target, Nexus Dashboard target, ACI target, FMC target, ISE target, or IOS XR target",
		},
		{
			name: "valid meraki organization target",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Meraki: MerakiConfig{
					Auth: MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
					Organizations: []MerakiOrganizationConfig{{
						OrganizationID: "123456",
						ProductTypes:   []string{"switch", "wireless"},
						Tags:           []string{"prod"},
						TagsFilterType: "withAnyTags",
					}},
				},
			},
			expectedErr: "",
		},
		{
			name: "valid meraki serial target",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Meraki: MerakiConfig{
					Auth:    MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
					BaseURL: "https://api.meraki.com/api/v1",
					Devices: []MerakiDeviceConfig{{
						OrganizationID: "123456",
						Serial:         "Q234-ABCD-5678",
					}},
				},
			},
			expectedErr: "",
		},
		{
			name: "valid mixed ssh and meraki",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Devices: []DeviceConfig{validTestDevice()},
				Meraki: MerakiConfig{
					Auth: MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
					Organizations: []MerakiOrganizationConfig{{
						OrganizationID: "123456",
					}},
				},
				Scrapers: map[component.Type]component.Config{
					component.MustNewType("system"): nil,
				},
			},
			expectedErr: "",
		},
		{
			name: "valid intersight target",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Intersight: IntersightConfig{
					Enabled: true,
					Auth: IntersightAuthConfig{
						KeyID:  "api-key-id",
						KeyPEM: configopaque.String("pem"),
					},
					Endpoint:          "https://intersight.com",
					PageSize:          100,
					MaxRetries:        3,
					EventLookback:     time.Hour,
					TelemetryLookback: 30 * time.Minute,
					Inventory:         defaultIntersightGroupConfig(10),
				},
			},
			expectedErr: "",
		},
		{
			name: "missing intersight key id",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Intersight: IntersightConfig{
					Enabled: true,
					Auth: IntersightAuthConfig{
						KeyPEM: configopaque.String("pem"),
					},
				},
			},
			expectedErr: "intersight.auth.key_id must be provided",
		},
		{
			name: "missing intersight private key",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Intersight: IntersightConfig{
					Enabled: true,
					Auth: IntersightAuthConfig{
						KeyID: "api-key-id",
					},
				},
			},
			expectedErr: "intersight.auth.key_file or intersight.auth.key_pem must be provided",
		},
		{
			name: "invalid intersight endpoint",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Intersight: IntersightConfig{
					Enabled: true,
					Auth: IntersightAuthConfig{
						KeyID:  "api-key-id",
						KeyPEM: configopaque.String("pem"),
					},
					Endpoint: "://bad",
				},
			},
			expectedErr: "intersight.endpoint must be a valid absolute URL",
		},
		{
			name: "invalid intersight group cap",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Intersight: IntersightConfig{
					Enabled: true,
					Auth: IntersightAuthConfig{
						KeyID:  "api-key-id",
						KeyPEM: configopaque.String("pem"),
					},
					Endpoint:  "https://intersight.com",
					Inventory: IntersightGroupConfig{Enabled: true, MaxResults: -1},
				},
			},
			expectedErr: "intersight.inventory.max_results must not be negative",
		},
		{
			name: "valid catalyst center target with basic auth",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				CatalystCenter: CatalystCenterConfig{
					Enabled:  true,
					Endpoint: "https://catalyst-center.example.com",
					Auth: CatalystCenterAuthConfig{
						Mode:     "basic",
						Username: "admin",
						Password: configopaque.String("password"),
					},
					PageSize:   500,
					MaxRetries: 3,
					Lookback:   time.Hour,
					Targets: CatalystCenterTargetFilters{
						DeviceDetails: []CatalystCenterDeviceDetailTarget{{Identifier: "MACADDRESS", SearchBy: "00:11:22:33:44:55"}},
					},
					Inventory: defaultCatalystCenterGroupConfig(10),
				},
			},
			expectedErr: "",
		},
		{
			name: "valid catalyst center target with aes credentials",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				CatalystCenter: CatalystCenterConfig{
					Enabled:  true,
					Endpoint: "https://catalyst-center.example.com",
					Auth: CatalystCenterAuthConfig{
						Mode:           "aes",
						AESCredentials: configopaque.String("opaque-ciphertext"),
					},
				},
			},
			expectedErr: "",
		},
		{
			name: "missing catalyst center endpoint",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				CatalystCenter: CatalystCenterConfig{
					Enabled: true,
					Auth: CatalystCenterAuthConfig{
						Username: "admin",
						Password: configopaque.String("password"),
					},
				},
			},
			expectedErr: "catalyst_center.endpoint must be provided",
		},
		{
			name: "missing catalyst center basic auth password",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				CatalystCenter: CatalystCenterConfig{
					Enabled:  true,
					Endpoint: "https://catalyst-center.example.com",
					Auth: CatalystCenterAuthConfig{
						Mode:     "basic",
						Username: "admin",
					},
				},
			},
			expectedErr: "catalyst_center.auth.password must be provided for basic auth",
		},
		{
			name: "invalid catalyst center page size",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				CatalystCenter: CatalystCenterConfig{
					Enabled:  true,
					Endpoint: "https://catalyst-center.example.com",
					Auth: CatalystCenterAuthConfig{
						Username: "admin",
						Password: configopaque.String("password"),
					},
					PageSize: 501,
				},
			},
			expectedErr: "catalyst_center.page_size must be between 1 and 500 when set",
		},
		{
			name: "invalid catalyst center device detail search key",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				CatalystCenter: CatalystCenterConfig{
					Enabled:  true,
					Endpoint: "https://catalyst-center.example.com",
					Auth: CatalystCenterAuthConfig{
						Username: "admin",
						Password: configopaque.String("password"),
					},
					Targets: CatalystCenterTargetFilters{
						DeviceDetails: []CatalystCenterDeviceDetailTarget{{Identifier: "hostname", SearchBy: "switch-1"}},
					},
				},
			},
			expectedErr: "identifier must be macAddress, nwDeviceName, or uuid",
		},
		{
			name: "valid sdwan target with jwt auth",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				SDWAN: SDWANConfig{
					Enabled:  true,
					Endpoint: "https://sdwan-manager.example.com",
					Auth: SDWANAuthConfig{
						Mode:     "jwt",
						Username: "admin",
						Password: configopaque.String("password"),
					},
					PageSize:      500,
					MaxRetries:    3,
					EventLookback: time.Hour,
					Inventory:     defaultSDWANGroupConfig(true, 10),
				},
			},
			expectedErr: "",
		},
		{
			name: "valid sdwan target with bearer auth",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				SDWAN: SDWANConfig{
					Enabled:  true,
					Endpoint: "https://sdwan-manager.example.com",
					Auth: SDWANAuthConfig{
						Mode:        "bearer",
						BearerToken: configopaque.String("token"),
					},
				},
			},
			expectedErr: "",
		},
		{
			name: "missing sdwan endpoint",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				SDWAN: SDWANConfig{
					Enabled: true,
					Auth: SDWANAuthConfig{
						Username: "admin",
						Password: configopaque.String("password"),
					},
				},
			},
			expectedErr: "sdwan.endpoint must be provided",
		},
		{
			name: "missing sdwan jwt password",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				SDWAN: SDWANConfig{
					Enabled:  true,
					Endpoint: "https://sdwan-manager.example.com",
					Auth: SDWANAuthConfig{
						Mode:     "jwt",
						Username: "admin",
					},
				},
			},
			expectedErr: "sdwan.auth.password must be provided for jwt auth",
		},
		{
			name: "sdwan realtime requires targets",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				SDWAN: SDWANConfig{
					Enabled:  true,
					Endpoint: "https://sdwan-manager.example.com",
					Auth: SDWANAuthConfig{
						Username: "admin",
						Password: configopaque.String("password"),
					},
					RealtimeDetails: SDWANGroupConfig{Enabled: true, MaxResults: 10},
				},
			},
			expectedErr: "sdwan.realtime_details requires at least one target filter",
		},
		{
			name: "invalid sdwan group cap",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				SDWAN: SDWANConfig{
					Enabled:  true,
					Endpoint: "https://sdwan-manager.example.com",
					Auth: SDWANAuthConfig{
						BearerToken: configopaque.String("token"),
					},
					BFD: SDWANGroupConfig{Enabled: true, MaxResults: -1},
				},
			},
			expectedErr: "sdwan.bfd.max_results must not be negative",
		},
		{
			name: "valid nexus dashboard api key target",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				NexusDashboard: NexusDashboardConfig{
					Enabled:  true,
					Endpoint: "https://nd.example.com",
					Auth: ControllerAuthConfig{
						Mode:     "api_key",
						Username: "admin",
						APIKey:   configopaque.String("nd-api-key"),
					},
					PageSize:      100,
					MaxRetries:    3,
					EventLookback: time.Hour,
					NDFC:          defaultNexusControllerGroupConfig(100),
				},
			},
			expectedErr: "",
		},
		{
			name: "invalid nexus dashboard api profile",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				NexusDashboard: NexusDashboardConfig{
					Enabled:    true,
					Endpoint:   "https://nd.example.com",
					APIProfile: "automatic",
					Auth: ControllerAuthConfig{
						Mode:     "api_key",
						Username: "admin",
						APIKey:   configopaque.String("nd-api-key"),
					},
				},
			},
			expectedErr: "nexus_dashboard.api_profile must be legacy or unified",
		},
		{
			name: "valid aci target",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				ACI: ACIConfig{
					Enabled: true,
					Controllers: []ACIControllerConfig{{
						Endpoint: "https://apic.example.com",
						Name:     "apic-1",
					}},
					Auth: ControllerAuthConfig{
						Username: "admin",
						Password: configopaque.String("password"),
					},
					PageSize:      100,
					MaxRetries:    3,
					EventLookback: time.Hour,
				},
			},
			expectedErr: "",
		},
		{
			name: "valid fmc target",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				FMC: FMCConfig{
					Enabled: true,
					Controllers: []FMCControllerConfig{{
						Endpoint:   "https://fmc.example.com",
						Name:       "fmc-1",
						DomainUUID: "domain-uuid-1",
					}},
					Auth: ControllerAuthConfig{
						Username: "admin",
						Password: configopaque.String("password"),
					},
					PageSize:      100,
					MaxRetries:    3,
					EventLookback: time.Hour,
				},
			},
			expectedErr: "",
		},
		{
			name: "valid fmc estreamer target",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				FMC: FMCConfig{
					EStreamer: FMCEStreamerConfig{
						Enabled: true,
						Targets: []FMCEStreamerTargetConfig{{
							Endpoint: "fmc.example.com:8302",
							Name:     "fmc-1",
						}},
						TLS: FMCEStreamerTLSConfig{
							CertFile: "/etc/otelcol/fmc-estreamer.crt",
							KeyFile:  "/etc/otelcol/fmc-estreamer.key",
						},
						EventTypes: []string{"connection", "intrusion", "intrusion_packet", "file", "malware", "security_intelligence"},
					},
				},
			},
			expectedErr: "",
		},
		{
			name: "fmc estreamer message limit exceeds hard maximum",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				FMC: FMCConfig{
					EStreamer: FMCEStreamerConfig{
						Enabled: true,
						Targets: []FMCEStreamerTargetConfig{{
							Endpoint: "fmc.example.com:8302",
						}},
						TLS: FMCEStreamerTLSConfig{
							CertFile: "/etc/otelcol/fmc-estreamer.crt",
							KeyFile:  "/etc/otelcol/fmc-estreamer.key",
						},
						MaxMessageBytes: maxFMCEStreamerMessageBytes + 1,
					},
				},
			},
			expectedErr: "fmc.estreamer.max_message_bytes must be between 1 and 16777216 when set",
		},
		{
			name: "missing fmc controller",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				FMC: FMCConfig{
					Enabled: true,
					Auth: ControllerAuthConfig{
						Username: "admin",
						Password: configopaque.String("password"),
					},
				},
			},
			expectedErr: "fmc.controllers must include at least one FMC endpoint",
		},
		{
			name: "missing fmc auth password",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				FMC: FMCConfig{
					Enabled: true,
					Controllers: []FMCControllerConfig{{
						Endpoint: "https://fmc.example.com",
					}},
					Auth: ControllerAuthConfig{Username: "admin"},
				},
			},
			expectedErr: "fmc.auth.password must be provided",
		},
		{
			name: "invalid fmc group cap",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				FMC: FMCConfig{
					Enabled: true,
					Controllers: []FMCControllerConfig{{
						Endpoint: "https://fmc.example.com",
					}},
					Auth: ControllerAuthConfig{
						Username: "admin",
						Password: configopaque.String("password"),
					},
					Health: FMCGroupConfig{Enabled: true, MaxResults: -1},
				},
			},
			expectedErr: "fmc.health.max_results must not be negative",
		},
		{
			name: "missing nexus dashboard api key username",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				NexusDashboard: NexusDashboardConfig{
					Enabled:  true,
					Endpoint: "https://nd.example.com",
					Auth: ControllerAuthConfig{
						Mode:   "api_key",
						APIKey: configopaque.String("nd-api-key"),
					},
				},
			},
			expectedErr: "nexus_dashboard.auth.username must be provided for api_key auth",
		},
		{
			name: "missing aci controller",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				ACI: ACIConfig{
					Enabled: true,
					Auth: ControllerAuthConfig{
						Username: "admin",
						Password: configopaque.String("password"),
					},
				},
			},
			expectedErr: "aci.controllers must include at least one APIC endpoint",
		},
		{
			name: "invalid aci group cap",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				ACI: ACIConfig{
					Enabled: true,
					Controllers: []ACIControllerConfig{{
						Endpoint: "https://apic.example.com",
					}},
					Auth: ControllerAuthConfig{
						Username: "admin",
						Password: configopaque.String("password"),
					},
					Faults: NexusControllerGroupConfig{Enabled: true, MaxResults: -1},
				},
			},
			expectedErr: "aci.faults.max_results must not be negative",
		},
		{
			name: "empty metric filter key",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Metrics: map[string]MetricConfig{
					"": {Enabled: false},
				},
				Meraki: MerakiConfig{
					Auth:          MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
					Organizations: []MerakiOrganizationConfig{{OrganizationID: "123456"}},
				},
			},
			expectedErr: "metrics keys cannot be empty",
		},
		{
			name: "invalid metric filter glob",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Metrics: map[string]MetricConfig{
					"cisco.iosxr.yang.[": {Enabled: false},
				},
				Meraki: MerakiConfig{
					Auth:          MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
					Organizations: []MerakiOrganizationConfig{{OrganizationID: "123456"}},
				},
			},
			expectedErr: "must be a valid metric name glob",
		},
		{
			name: "missing meraki api key",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Meraki: MerakiConfig{
					Organizations: []MerakiOrganizationConfig{{OrganizationID: "123456"}},
				},
			},
			expectedErr: "meraki.auth.api_key must be provided",
		},
		{
			name: "invalid meraki base url",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Meraki: MerakiConfig{
					Auth:          MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
					BaseURL:       "://not-a-url",
					Organizations: []MerakiOrganizationConfig{{OrganizationID: "123456"}},
				},
			},
			expectedErr: "meraki.base_url must be a valid absolute URL",
		},
		{
			name: "invalid meraki tags filter",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Meraki: MerakiConfig{
					Auth: MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
					Organizations: []MerakiOrganizationConfig{{
						OrganizationID: "123456",
						TagsFilterType: "all",
					}},
				},
			},
			expectedErr: "tags_filter_type must be withAnyTags or withAllTags",
		},
		{
			name: "no scrapers configured",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Devices:  []DeviceConfig{validTestDevice()},
				Scrapers: map[component.Type]component.Config{},
			},
			expectedErr: "must specify at least one scraper",
		},
		{
			name: "negative timeout",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            -1 * time.Second,
					CollectionInterval: 60 * time.Second,
				},
				Devices: []DeviceConfig{validTestDevice()},
				Scrapers: map[component.Type]component.Config{
					component.MustNewType("system"): nil,
				},
			},
			expectedErr: "timeout must be positive",
		},
		{
			name: "zero timeout",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            0,
					CollectionInterval: 60 * time.Second,
				},
				Devices: []DeviceConfig{validTestDevice()},
				Scrapers: map[component.Type]component.Config{
					component.MustNewType("system"): nil,
				},
			},
			expectedErr: "timeout must be positive",
		},
		{
			name: "zero collection interval",
			config: &Config{
				ControllerConfig: scraperhelper.ControllerConfig{
					Timeout:            30 * time.Second,
					CollectionInterval: 0,
				},
				Devices: []DeviceConfig{validTestDevice()},
				Scrapers: map[component.Type]component.Config{
					component.MustNewType("system"): nil,
				},
			},
			expectedErr: "collection_interval must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}

func TestValidateHostPortOrHost(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "hostname", value: "fmc.example.com"},
		{name: "hostname with trailing dot", value: "fmc.example.com."},
		{name: "hostname and port", value: "fmc.example.com:8302"},
		{name: "bare IPv4", value: "192.0.2.10"},
		{name: "IPv4 and port", value: "192.0.2.10:8302"},
		{name: "bare IPv6", value: "2001:db8::10"},
		{name: "bracketed IPv6 and port", value: "[2001:db8::10]:8302"},
		{name: "empty", value: "", wantErr: true},
		{name: "URL", value: "https://fmc.example.com:8302", wantErr: true},
		{name: "embedded whitespace", value: "fmc.example.com\t:8302", wantErr: true},
		{name: "missing host", value: ":8302", wantErr: true},
		{name: "missing port", value: "fmc.example.com:", wantErr: true},
		{name: "nonnumeric port", value: "fmc.example.com:not-a-port", wantErr: true},
		{name: "signed port", value: "fmc.example.com:+8302", wantErr: true},
		{name: "zero port", value: "fmc.example.com:0", wantErr: true},
		{name: "port too large", value: "fmc.example.com:65536", wantErr: true},
		{name: "unclosed IPv6 bracket", value: "[2001:db8::10:8302", wantErr: true},
		{name: "unopened IPv6 bracket", value: "2001:db8::10]:8302", wantErr: true},
		{name: "bracketed IPv6 without port", value: "[2001:db8::10]", wantErr: true},
		{name: "bracketed hostname", value: "[fmc.example.com]:8302", wantErr: true},
		{name: "malformed IPv6", value: "2001:db8::not-ip", wantErr: true},
		{name: "malformed IPv4", value: "192.0.2.999", wantErr: true},
		{name: "empty hostname label", value: "fmc..example.com", wantErr: true},
		{name: "invalid hostname character", value: "fmc/example.com", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHostPortOrHost("endpoint", tt.value)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateHTTPURLRequiresHTTPSAndSafeContents(t *testing.T) {
	require.NoError(t, validateHTTPURL("endpoint", "https://controller.example.com", false))
	require.ErrorContains(t, validateHTTPURL("endpoint", "http://controller.example.com", true), "must use https")
	require.ErrorContains(t, validateHTTPURL("endpoint", "http://controller.example.com", false), "must use https")
	require.Error(t, validateHTTPURL("endpoint", "ftp://controller.example.com", true))
	require.ErrorContains(t, validateHTTPURL("endpoint", "https://user:password@controller.example.com", false), "must not include user information")
	require.ErrorContains(t, validateHTTPURL("endpoint", "https://controller.example.com?token=secret", false), "must not include a query string")
	require.ErrorContains(t, validateHTTPURL("endpoint", "https://controller.example.com#token", false), "must not include a fragment")
}

func TestMerakiConfigRejectsPlaintextBaseURL(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.Meraki.Auth.APIKey = configopaque.String("secret")
	cfg.Meraki.BaseURL = "http://api.example.com"
	cfg.Meraki.Organizations = []MerakiOrganizationConfig{{OrganizationID: "org-1"}}

	require.ErrorContains(t, cfg.Validate(), "meraki.base_url must use https")
}

func TestMerakiConfigRejectsCredentialsInBaseURL(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.Meraki.Auth.APIKey = configopaque.String("secret")
	cfg.Meraki.BaseURL = "https://user:password@api.example.com/api/v1"
	cfg.Meraki.Organizations = []MerakiOrganizationConfig{{OrganizationID: "org-1"}}

	require.ErrorContains(t, cfg.Validate(), "meraki.base_url must not include user information")
}

func TestMerakiConfigRejectsUnknownProductType(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.Meraki.Auth.APIKey = configopaque.String("secret")
	cfg.Meraki.Organizations = []MerakiOrganizationConfig{{
		OrganizationID: "org-1",
		ProductTypes:   []string{"switch", "swich"},
	}}

	require.ErrorContains(t, cfg.Validate(), "meraki.organizations[0].product_types[1] must be one of")
}

func TestConfigRejectsBlankProviderTargetFilters(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Config)
		wantErr   string
	}{
		{
			name: "Meraki",
			configure: func(cfg *Config) {
				cfg.Meraki.Auth.APIKey = configopaque.String("secret")
				cfg.Meraki.Organizations = []MerakiOrganizationConfig{{OrganizationID: "org-1", Serials: []string{" "}}}
			},
			wantErr: "meraki.organizations[0].serials[0] cannot be empty",
		},
		{
			name: "Intersight",
			configure: func(cfg *Config) {
				cfg.Intersight.Enabled = true
				cfg.Intersight.Auth.KeyID = "key-id"
				cfg.Intersight.Auth.KeyPEM = configopaque.String("pem")
				cfg.Intersight.Targets.Serials = []string{" "}
			},
			wantErr: "intersight.targets.serials[0] cannot be empty",
		},
		{
			name: "Catalyst Center",
			configure: func(cfg *Config) {
				cfg.CatalystCenter.Enabled = true
				cfg.CatalystCenter.Endpoint = "https://catalyst-center.example.com"
				cfg.CatalystCenter.Auth.Username = "admin"
				cfg.CatalystCenter.Auth.Password = configopaque.String("secret")
				cfg.CatalystCenter.Targets.ClientMACs = []string{" "}
			},
			wantErr: "catalyst_center.targets.client_macs[0] cannot be empty",
		},
		{
			name: "Nexus Dashboard",
			configure: func(cfg *Config) {
				cfg.NexusDashboard.Enabled = true
				cfg.NexusDashboard.Endpoint = "https://nd.example.com"
				cfg.NexusDashboard.Auth.Username = "admin"
				cfg.NexusDashboard.Auth.Password = configopaque.String("secret")
				cfg.NexusDashboard.Targets.SwitchIDs = []string{" "}
			},
			wantErr: "nexus_dashboard.targets.switch_ids[0] cannot be empty",
		},
		{
			name: "ACI",
			configure: func(cfg *Config) {
				cfg.ACI.Enabled = true
				cfg.ACI.Controllers = []ACIControllerConfig{{Endpoint: "https://apic.example.com"}}
				cfg.ACI.Auth.Username = "admin"
				cfg.ACI.Auth.Password = configopaque.String("secret")
				cfg.ACI.Targets.NodeIDs = []string{" "}
			},
			wantErr: "aci.targets.node_ids[0] cannot be empty",
		},
		{
			name: "FMC",
			configure: func(cfg *Config) {
				cfg.FMC.Enabled = true
				cfg.FMC.Controllers = []FMCControllerConfig{{Endpoint: "https://fmc.example.com"}}
				cfg.FMC.Auth.Username = "admin"
				cfg.FMC.Auth.Password = configopaque.String("secret")
				cfg.FMC.Targets.Serials = []string{" "}
			},
			wantErr: "fmc.targets.serials[0] cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewFactory().CreateDefaultConfig().(*Config)
			tt.configure(cfg)
			require.ErrorContains(t, cfg.Validate(), tt.wantErr)
		})
	}
}

func TestConfigRejectsInvalidTargetAddresses(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Config)
		wantErr   string
	}{
		{
			name: "SD-WAN system IP",
			configure: func(cfg *Config) {
				cfg.SDWAN.Enabled = true
				cfg.SDWAN.Endpoint = "https://sdwan.example.com"
				cfg.SDWAN.Auth.BearerToken = configopaque.String("token")
				cfg.SDWAN.Targets.SystemIPs = []string{"10.0.0.999"}
			},
			wantErr: "sdwan.targets.system_ips[0] must be a valid IP address",
		},
		{
			name: "FMC management IP",
			configure: func(cfg *Config) {
				cfg.FMC.Enabled = true
				cfg.FMC.Controllers = []FMCControllerConfig{{Endpoint: "https://fmc.example.com"}}
				cfg.FMC.Auth.Username = "admin"
				cfg.FMC.Auth.Password = configopaque.String("secret")
				cfg.FMC.Targets.ManagementIPs = []string{"not-an-ip"}
			},
			wantErr: "fmc.targets.management_ips[0] must be a valid IP address",
		},
		{
			name: "Catalyst Center client MAC",
			configure: func(cfg *Config) {
				cfg.CatalystCenter.Enabled = true
				cfg.CatalystCenter.Endpoint = "https://catalyst-center.example.com"
				cfg.CatalystCenter.Auth.Username = "admin"
				cfg.CatalystCenter.Auth.Password = configopaque.String("secret")
				cfg.CatalystCenter.Targets.ClientMACs = []string{"not-a-mac"}
			},
			wantErr: "catalyst_center.targets.client_macs[0] must be a valid 48-bit MAC address",
		},
		{
			name: "Catalyst Center detail MAC",
			configure: func(cfg *Config) {
				cfg.CatalystCenter.Enabled = true
				cfg.CatalystCenter.Endpoint = "https://catalyst-center.example.com"
				cfg.CatalystCenter.Auth.Username = "admin"
				cfg.CatalystCenter.Auth.Password = configopaque.String("secret")
				cfg.CatalystCenter.Targets.DeviceDetails = []CatalystCenterDeviceDetailTarget{{Identifier: "macAddress", SearchBy: "not-a-mac"}}
			},
			wantErr: "catalyst_center.targets.device_details[0].search_by must be a valid 48-bit MAC address",
		},
		{
			name: "ISE network device IP",
			configure: func(cfg *Config) {
				cfg.ISE.Enabled = true
				cfg.ISE.Endpoint = "https://ise.example.com"
				cfg.ISE.Auth.Username = "admin"
				cfg.ISE.Auth.Password = configopaque.String("secret")
				cfg.ISE.Targets.NetworkDeviceIPs = []string{"not-an-ip"}
			},
			wantErr: "ise.targets.network_device_ips[0] must be a valid IP address",
		},
		{
			name: "ISE endpoint MAC",
			configure: func(cfg *Config) {
				cfg.ISE.Enabled = true
				cfg.ISE.Endpoint = "https://ise.example.com"
				cfg.ISE.Auth.Username = "admin"
				cfg.ISE.Auth.Password = configopaque.String("secret")
				cfg.ISE.Targets.EndpointMACs = []string{"not-a-mac"}
			},
			wantErr: "ise.targets.endpoint_macs[0] must be a valid 48-bit MAC address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewFactory().CreateDefaultConfig().(*Config)
			tt.configure(cfg)
			require.ErrorContains(t, cfg.Validate(), tt.wantErr)
		})
	}
}

func TestValidateMACAddressAcceptsCommonCiscoSpellings(t *testing.T) {
	for _, value := range []string{"00:11:22:33:44:55", "00-11-22-33-44-55", "0011.2233.4455"} {
		require.NoError(t, validateMACAddress("mac", value))
	}
	require.Error(t, validateMACAddress("mac", "00:11:22:33:44:55:66:77"))
}

func TestConfigUnmarshal(t *testing.T) {
	cm, err := confmaptest.LoadConf(filepath.Join("testdata", "config.yaml"))
	require.NoError(t, err)

	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)

	sub, err := cm.Sub("ciscoos")
	require.NoError(t, err)

	require.NoError(t, sub.Unmarshal(cfg))
	require.Len(t, cfg.Devices, 2)
	assert.Equal(t, "enable-password", string(cfg.Devices[0].Auth.EnablePassword))
	assert.Equal(t, []string{"device-1", "edge-1"}, cfg.DeviceSelection.Include.HostNames)
	assert.Equal(t, []string{"host-1"}, cfg.DeviceSelection.Include.HostIDs)
	assert.Equal(t, []string{"192.168.1.1"}, cfg.DeviceSelection.Include.HostIPs)
	assert.Equal(t, []string{"Q234-ABCD-0001", "SERIAL-1", "FOC1234", "ACI-SERIAL-1", "FMC-SERIAL-1"}, cfg.DeviceSelection.Include.Serials)
	assert.Equal(t, []string{"device-uuid-1", "101"}, cfg.DeviceSelection.Include.DeviceIDs)
	assert.Equal(t, []string{"lab-disabled"}, cfg.DeviceSelection.Exclude.HostNames)
	assert.Equal(t, []string{"host-disabled"}, cfg.DeviceSelection.Exclude.HostIDs)
	assert.Equal(t, []string{"192.168.1.254"}, cfg.DeviceSelection.Exclude.HostIPs)
	assert.Equal(t, []string{"Q234-ABCD-9999"}, cfg.DeviceSelection.Exclude.Serials)
	assert.Equal(t, []string{"device-disabled"}, cfg.DeviceSelection.Exclude.DeviceIDs)
	assert.False(t, cfg.Metrics["sdwan.app_route.loss"].Enabled)
	assert.False(t, cfg.Metrics["system.network.errors"].Enabled)
	assert.False(t, cfg.Metrics["cisco.wlc.client.*"].Enabled)
	assert.False(t, cfg.Metrics["cisco.iosxr.yang.cisco_ios_xr_ip_rib_ipv4_oper.*"].Enabled)
	assert.Equal(t, "https://api.meraki.com/api/v1", cfg.Meraki.BaseURL)
	assert.Equal(t, 3, cfg.Meraki.MaxRetries)
	assert.True(t, cfg.Meraki.InsecureSkipVerify)
	assert.True(t, cfg.Meraki.SwitchTransceivers.Enabled)
	assert.Equal(t, "meraki-key", string(cfg.Meraki.Auth.APIKey))
	require.Len(t, cfg.Meraki.Organizations, 1)
	assert.Equal(t, "123456", cfg.Meraki.Organizations[0].OrganizationID)
	assert.Equal(t, []string{"N_1"}, cfg.Meraki.Organizations[0].NetworkIDs)
	assert.Equal(t, []string{"Q234-ABCD-0001"}, cfg.Meraki.Organizations[0].Serials)
	assert.Equal(t, []string{"switch", "wireless"}, cfg.Meraki.Organizations[0].ProductTypes)
	assert.Equal(t, []string{"prod"}, cfg.Meraki.Organizations[0].Tags)
	assert.Equal(t, "withAnyTags", cfg.Meraki.Organizations[0].TagsFilterType)
	require.Len(t, cfg.Meraki.Devices, 1)
	assert.Equal(t, "Q234-ABCD-0002", cfg.Meraki.Devices[0].Serial)
	assert.True(t, cfg.Intersight.Enabled)
	assert.Equal(t, "intersight-key", cfg.Intersight.Auth.KeyID)
	assert.Equal(t, "/etc/otelcol/intersight.pem", cfg.Intersight.Auth.KeyFile)
	assert.Equal(t, "https://intersight.example.com", cfg.Intersight.Endpoint)
	assert.True(t, cfg.Intersight.InsecureSkipVerify)
	assert.Equal(t, "ciscoosreceiver-test", cfg.Intersight.UserAgent)
	assert.Equal(t, 50, cfg.Intersight.PageSize)
	assert.Equal(t, 2, cfg.Intersight.MaxRetries)
	assert.Equal(t, 12*time.Hour, cfg.Intersight.EventLookback)
	assert.Equal(t, 15*time.Minute, cfg.Intersight.TelemetryLookback)
	assert.Equal(t, []string{"SERIAL-1"}, cfg.Intersight.Targets.Serials)
	assert.Equal(t, []string{"moid-1"}, cfg.Intersight.Targets.MoIDs)
	assert.False(t, cfg.Intersight.Telemetry.Enabled)
	assert.Equal(t, 25, cfg.Intersight.Telemetry.MaxResults)
	assert.True(t, cfg.Intersight.Storage.Enabled)
	assert.Equal(t, 75, cfg.Intersight.Storage.MaxResults)
	assert.True(t, cfg.CatalystCenter.Enabled)
	assert.Equal(t, "https://catalyst-center.example.com", cfg.CatalystCenter.Endpoint)
	assert.True(t, cfg.CatalystCenter.InsecureSkipVerify)
	assert.Equal(t, "ciscoosreceiver-test", cfg.CatalystCenter.UserAgent)
	assert.Equal(t, 250, cfg.CatalystCenter.PageSize)
	assert.Equal(t, 2, cfg.CatalystCenter.MaxRetries)
	assert.Equal(t, 6*time.Hour, cfg.CatalystCenter.Lookback)
	assert.Equal(t, "basic", cfg.CatalystCenter.Auth.Mode)
	assert.Equal(t, "admin", cfg.CatalystCenter.Auth.Username)
	assert.Equal(t, "password", string(cfg.CatalystCenter.Auth.Password))
	require.Len(t, cfg.CatalystCenter.Targets.DeviceDetails, 1)
	assert.Equal(t, "uuid", cfg.CatalystCenter.Targets.DeviceDetails[0].Identifier)
	assert.Equal(t, "device-uuid-1", cfg.CatalystCenter.Targets.DeviceDetails[0].SearchBy)
	assert.Equal(t, []string{"00:11:22:33:44:55"}, cfg.CatalystCenter.Targets.ClientMACs)
	assert.True(t, cfg.CatalystCenter.Topology.Enabled)
	assert.Equal(t, 500, cfg.CatalystCenter.Topology.MaxResults)
	assert.True(t, cfg.CatalystCenter.Issues.Enabled)
	assert.Equal(t, 100, cfg.CatalystCenter.Issues.MaxResults)
	assert.True(t, cfg.SDWAN.Enabled)
	assert.Equal(t, "https://sdwan-manager.example.com", cfg.SDWAN.Endpoint)
	assert.True(t, cfg.SDWAN.InsecureSkipVerify)
	assert.Equal(t, "ciscoosreceiver-test", cfg.SDWAN.UserAgent)
	assert.Equal(t, 300, cfg.SDWAN.PageSize)
	assert.Equal(t, 2, cfg.SDWAN.MaxRetries)
	assert.Equal(t, 9*time.Hour, cfg.SDWAN.EventLookback)
	assert.Equal(t, "jwt", cfg.SDWAN.Auth.Mode)
	assert.Equal(t, "admin", cfg.SDWAN.Auth.Username)
	assert.Equal(t, "password", string(cfg.SDWAN.Auth.Password))
	assert.Equal(t, []string{"100"}, cfg.SDWAN.Targets.SiteIDs)
	assert.Equal(t, []string{"10.0.0.1"}, cfg.SDWAN.Targets.SystemIPs)
	assert.Equal(t, []string{"sdwan-device-uuid-1"}, cfg.SDWAN.Targets.UUIDs)
	assert.Equal(t, []string{"SDWAN-SERIAL-1"}, cfg.SDWAN.Targets.Serials)
	assert.Equal(t, []string{"vedge"}, cfg.SDWAN.Targets.DeviceTypes)
	assert.Equal(t, []string{"vedge"}, cfg.SDWAN.Targets.Personalities)
	assert.Equal(t, []string{"biz-internet"}, cfg.SDWAN.Targets.Colors)
	assert.Equal(t, []string{"ge0/0"}, cfg.SDWAN.Targets.InterfaceNames)
	assert.Equal(t, []string{"0"}, cfg.SDWAN.Targets.VPNIDs)
	assert.Equal(t, []string{"openai-api"}, cfg.SDWAN.Targets.Applications)
	assert.Equal(t, []string{"ai"}, cfg.SDWAN.Targets.ApplicationFamilies)
	assert.Equal(t, []string{"aws"}, cfg.SDWAN.Targets.CloudProviders)
	assert.Equal(t, []string{"saas"}, cfg.SDWAN.Targets.ServiceTypes)
	assert.True(t, cfg.SDWAN.ControlPlane.Enabled)
	assert.Equal(t, 100, cfg.SDWAN.ControlPlane.MaxResults)
	assert.True(t, cfg.SDWAN.BFD.Enabled)
	assert.Equal(t, 200, cfg.SDWAN.BFD.MaxResults)
	assert.True(t, cfg.SDWAN.RealtimeDetails.Enabled)
	assert.Equal(t, 50, cfg.SDWAN.RealtimeDetails.MaxResults)
	assert.True(t, cfg.SDWAN.CloudOnRamp.Enabled)
	assert.Equal(t, 75, cfg.SDWAN.CloudOnRamp.MaxResults)
	assert.True(t, cfg.NexusDashboard.Enabled)
	assert.Equal(t, "https://nexus-dashboard.example.com", cfg.NexusDashboard.Endpoint)
	assert.Equal(t, nexusDashboardAPIProfileUnified, cfg.NexusDashboard.APIProfile)
	assert.True(t, cfg.NexusDashboard.InsecureSkipVerify)
	assert.Equal(t, "api_key", cfg.NexusDashboard.Auth.Mode)
	assert.Equal(t, "admin", cfg.NexusDashboard.Auth.Username)
	assert.Equal(t, "nd-api-key", string(cfg.NexusDashboard.Auth.APIKey))
	assert.Equal(t, 75, cfg.NexusDashboard.PageSize)
	assert.Equal(t, 2, cfg.NexusDashboard.MaxRetries)
	assert.Equal(t, 8*time.Hour, cfg.NexusDashboard.EventLookback)
	assert.Equal(t, []string{"fabric-a"}, cfg.NexusDashboard.Targets.Fabrics)
	assert.Equal(t, []string{"N9K-SERIAL-1"}, cfg.NexusDashboard.Targets.SwitchSerials)
	assert.Equal(t, []string{"101"}, cfg.NexusDashboard.Targets.SwitchIDs)
	assert.Equal(t, 250, cfg.NexusDashboard.NDFC.MaxResults)
	assert.Equal(t, 150, cfg.NexusDashboard.Insights.MaxResults)
	assert.Equal(t, 200, cfg.NexusDashboard.Performance.MaxResults)
	assert.True(t, cfg.ACI.Enabled)
	require.Len(t, cfg.ACI.Controllers, 2)
	assert.Equal(t, "https://apic1.example.com", cfg.ACI.Controllers[0].Endpoint)
	assert.Equal(t, "apic-1", cfg.ACI.Controllers[0].Name)
	assert.Equal(t, "admin", cfg.ACI.Auth.Username)
	assert.Equal(t, "password", string(cfg.ACI.Auth.Password))
	assert.Equal(t, "local", cfg.ACI.Auth.Domain)
	assert.Equal(t, 80, cfg.ACI.PageSize)
	assert.Equal(t, 2, cfg.ACI.MaxRetries)
	assert.True(t, cfg.ACI.InsecureSkipVerify)
	assert.Equal(t, 10*time.Hour, cfg.ACI.EventLookback)
	assert.Equal(t, []string{"101"}, cfg.ACI.Targets.NodeIDs)
	assert.Equal(t, []string{"prod"}, cfg.ACI.Targets.Tenants)
	assert.Equal(t, 300, cfg.ACI.Faults.MaxResults)
	assert.True(t, cfg.ACI.Logs.Faults.Enabled)
	assert.True(t, cfg.ACI.Logs.Audit.Enabled)
	assert.False(t, cfg.ACI.Logs.Events.Enabled)
	assert.Equal(t, 400, cfg.ACI.Endpoints.MaxResults)
	assert.Equal(t, 500, cfg.ACI.Tenants.MaxResults)
	assert.True(t, cfg.FMC.Enabled)
	require.Len(t, cfg.FMC.Controllers, 1)
	assert.Equal(t, "https://fmc1.example.com", cfg.FMC.Controllers[0].Endpoint)
	assert.Equal(t, "fmc-1", cfg.FMC.Controllers[0].Name)
	assert.Equal(t, "domain-uuid-1", cfg.FMC.Controllers[0].DomainUUID)
	assert.Equal(t, "admin", cfg.FMC.Auth.Username)
	assert.Equal(t, "password", string(cfg.FMC.Auth.Password))
	assert.Equal(t, "ciscoosreceiver-test", cfg.FMC.UserAgent)
	assert.Equal(t, 90, cfg.FMC.PageSize)
	assert.Equal(t, 2, cfg.FMC.MaxRetries)
	assert.Equal(t, 11*time.Hour, cfg.FMC.EventLookback)
	assert.True(t, cfg.FMC.InsecureSkipVerify)
	assert.Equal(t, []string{"fmc-device-uuid-1"}, cfg.FMC.Targets.DeviceIDs)
	assert.Equal(t, []string{"FMC-SERIAL-1"}, cfg.FMC.Targets.Serials)
	assert.Equal(t, []string{"ftd-edge-1"}, cfg.FMC.Targets.Names)
	assert.Equal(t, []string{"192.0.2.40"}, cfg.FMC.Targets.ManagementIPs)
	assert.Equal(t, []string{"policy-uuid-1"}, cfg.FMC.Targets.PolicyIDs)
	assert.Equal(t, []string{"edge-access-policy"}, cfg.FMC.Targets.PolicyNames)
	assert.Equal(t, []string{"GigabitEthernet0/0"}, cfg.FMC.Targets.InterfaceNames)
	assert.Equal(t, 250, cfg.FMC.Inventory.MaxResults)
	assert.Equal(t, 500, cfg.FMC.Interfaces.MaxResults)
	assert.Equal(t, 150, cfg.FMC.Health.MaxResults)
	assert.Equal(t, 175, cfg.FMC.VPN.MaxResults)
	assert.Equal(t, 50, cfg.FMC.HA.MaxResults)
	assert.Equal(t, 300, cfg.FMC.Policy.MaxResults)
	assert.Equal(t, 125, cfg.FMC.Deployments.MaxResults)
	assert.Equal(t, 100, cfg.FMC.Audit.MaxResults)
	assert.True(t, cfg.FMC.EStreamer.Enabled)
	require.Len(t, cfg.FMC.EStreamer.Targets, 1)
	assert.Equal(t, "fmc1.example.com:8302", cfg.FMC.EStreamer.Targets[0].Endpoint)
	assert.Equal(t, "/etc/otelcol/fmc-estreamer.crt", cfg.FMC.EStreamer.TLS.CertFile)
	assert.True(t, cfg.FMC.EStreamer.TLS.InsecureSkipVerify)
	assert.Equal(t, []string{"connection", "intrusion", "intrusion_packet", "file"}, cfg.FMC.EStreamer.EventTypes)
	assert.Equal(t, 10*time.Minute, cfg.FMC.EStreamer.Lookback)
	assert.Equal(t, 20*time.Second, cfg.FMC.EStreamer.ReconnectInterval)
	assert.Equal(t, 1048576, cfg.FMC.EStreamer.MaxMessageBytes)
	assert.True(t, cfg.ISE.Enabled)
	assert.Equal(t, "https://ise.example.com", cfg.ISE.Endpoint)
	assert.Equal(t, "admin", cfg.ISE.Auth.Username)
	assert.Equal(t, "password", string(cfg.ISE.Auth.Password))
	assert.Equal(t, "ciscoosreceiver-test", cfg.ISE.UserAgent)
	assert.Equal(t, 100, cfg.ISE.PageSize)
	assert.Equal(t, 2, cfg.ISE.MaxRetries)
	assert.Equal(t, 7*time.Hour, cfg.ISE.EventLookback)
	assert.Equal(t, 10*time.Minute, cfg.ISE.SessionLookback)
	assert.Equal(t, 900, cfg.ISE.MaxResults)
	assert.Equal(t, "/etc/otelcol/ise-rest-ca.crt", cfg.ISE.CAFile)
	assert.Equal(t, "nyc-ise-01.ciscovalidated.com", cfg.ISE.ServerName)
	assert.False(t, cfg.ISE.InsecureSkipVerify)
	assert.Equal(t, []string{"ise-pan-1"}, cfg.ISE.Targets.NodeNames)
	assert.Equal(t, []string{"edge-switch-1"}, cfg.ISE.Targets.NetworkDeviceNames)
	assert.Equal(t, []string{"192.0.2.10"}, cfg.ISE.Targets.NetworkDeviceIPs)
	assert.Equal(t, []string{"00:11:22:33:44:55"}, cfg.ISE.Targets.EndpointMACs)
	assert.Equal(t, []string{"alice@example.com"}, cfg.ISE.Targets.Usernames)
	assert.Equal(t, []string{"wired-access"}, cfg.ISE.Targets.PolicyNames)
	assert.Equal(t, []string{"Employees"}, cfg.ISE.Targets.SecurityGroupNames)
	assert.Equal(t, []string{"com.cisco.ise.session"}, cfg.ISE.Targets.PxGridServices)
	assert.Equal(t, 750, cfg.ISE.Sessions.MaxResults)
	assert.True(t, cfg.ISE.SessionDetails.Enabled)
	assert.Equal(t, 125, cfg.ISE.SessionDetails.MaxResults)
	assert.Equal(t, 300, cfg.ISE.AuthFailures.MaxResults)
	assert.Equal(t, 200, cfg.ISE.TrustSec.MaxResults)
	assert.True(t, cfg.ISE.PxGrid.Enabled)
	assert.Equal(t, "otel-collector", cfg.ISE.PxGrid.NodeName)
	assert.Equal(t, "pxgrid-secret", string(cfg.ISE.PxGrid.Password))
	assert.Equal(t, "/etc/otelcol/pxgrid.crt", cfg.ISE.PxGrid.CertFile)
	assert.Equal(t, "/etc/otelcol/pxgrid.key", cfg.ISE.PxGrid.KeyFile)
	assert.Equal(t, "pxgrid-key-password", string(cfg.ISE.PxGrid.KeyPassword))
	assert.True(t, cfg.ISE.PxGrid.Streaming)
	assert.True(t, cfg.ISE.PxGrid.Subscriptions.RadiusFailures)
	assert.True(t, cfg.ISE.DataConnect.Enabled)
	assert.Equal(t, "ise.example.com", cfg.ISE.DataConnect.Host)
	assert.Equal(t, "cpm10", cfg.ISE.DataConnect.ServiceName)
	assert.Equal(t, "dataconnect", cfg.ISE.DataConnect.Username)
	assert.Equal(t, "db-secret", string(cfg.ISE.DataConnect.Password))
	assert.Equal(t, "/etc/otelcol/ise-wallet", cfg.ISE.DataConnect.WalletDir)
	assert.False(t, cfg.ISE.DataConnect.SSLVerify)
	assert.Equal(t, 12*time.Hour, cfg.ISE.DataConnect.Lookback)
	assert.Equal(t, 400, cfg.ISE.DataConnect.RowLimit)
	assert.Equal(t, 250, cfg.ISE.DataConnect.Views["RADIUS_AUTHENTICATIONS_WEEK"].MaxResults)
	assert.True(t, cfg.Catalyst9800.Enabled)
	assert.Equal(t, 10000, cfg.Catalyst9800.MaxDatapointsPerBatch)
	assert.True(t, cfg.Catalyst9800.PathGroups["client_detail"].Enabled)
	assert.False(t, cfg.Catalyst9800.PathGroups["neighbors"].Enabled)
	assert.False(t, cfg.Catalyst9800.PathGroups["capwap_packets"].Enabled)
	assert.Equal(t, "warn", cfg.Catalyst9800.UnsupportedPathAction)
	assert.Equal(t, []string{"json_ietf", "json"}, cfg.Catalyst9800.EncodingPreference)
	assert.Equal(t, time.Minute, cfg.Catalyst9800.Subscription.SampleInterval)
	require.Len(t, cfg.Catalyst9800.DialIn.Targets, 1)
	assert.Equal(t, "campus-wlc-1", cfg.Catalyst9800.DialIn.Targets[0].Name)
	assert.Equal(t, "10.0.0.20:57400", cfg.Catalyst9800.DialIn.Targets[0].Endpoint)
	assert.True(t, cfg.Catalyst9800.DialIn.Targets[0].TLS.InsecureSkipVerify)
	assert.Equal(t, "catalyst_9800", cfg.Catalyst9800.DialIn.Targets[0].PlatformFamily)
	assert.Equal(t, "admin", cfg.Catalyst9800.DialIn.Targets[0].Credentials.Username)
	assert.Equal(t, "password", string(cfg.Catalyst9800.DialIn.Targets[0].Credentials.Password))
	assert.Equal(t, []string{"wireless-client-oper:client-oper-data/common-oper-data"}, cfg.Catalyst9800.DialIn.Targets[0].Paths.Include)
	assert.True(t, cfg.Catalyst9800.DialOut.Enabled)
	assert.Equal(t, "0.0.0.0:57501", cfg.Catalyst9800.DialOut.NetAddr.Endpoint)
	assert.Equal(t, []string{"10.0.0.0/8"}, cfg.Catalyst9800.DialOut.AllowedClients)
	assert.Equal(t, gnmiDialOutIdentityRequired, cfg.Catalyst9800.DialOut.IdentityVerification)
	assert.Equal(t, []GNMIDialOutIdentityBindingConfig{{
		Sources: []string{"10.0.0.20"},
		NodeIDs: []string{"campus-wlc-1"},
	}}, cfg.Catalyst9800.DialOut.IdentityBindings)
	assert.Equal(t, uint32(16), cfg.Catalyst9800.DialOut.MaxStreamsPerClient)
	assert.True(t, cfg.IOSXR.Enabled)
	assert.Equal(t, 12000, cfg.IOSXR.MaxDatapointsPerBatch)
	assert.True(t, cfg.IOSXR.PathGroups["interfaces"].Enabled)
	assert.True(t, cfg.IOSXR.PathGroups["optics"].Enabled)
	assert.True(t, cfg.IOSXR.PathGroups["bgp"].Enabled)
	assert.Equal(t, "error", cfg.IOSXR.UnsupportedPathAction)
	assert.Equal(t, []string{"json_ietf", "proto"}, cfg.IOSXR.EncodingPreference)
	assert.Equal(t, time.Minute, cfg.IOSXR.Subscription.SampleInterval)
	require.Len(t, cfg.IOSXR.DialIn.Targets, 1)
	assert.Equal(t, "core-asr9k-1", cfg.IOSXR.DialIn.Targets[0].Name)
	assert.Equal(t, "10.0.0.10:57400", cfg.IOSXR.DialIn.Targets[0].Endpoint)
	assert.True(t, cfg.IOSXR.DialIn.Targets[0].TLS.InsecureSkipVerify)
	assert.Equal(t, "ASR 9000", cfg.IOSXR.DialIn.Targets[0].PlatformFamily)
	assert.Equal(t, "admin", cfg.IOSXR.DialIn.Targets[0].Credentials.Username)
	assert.Equal(t, "password", string(cfg.IOSXR.DialIn.Targets[0].Credentials.Password))
	assert.True(t, cfg.IOSXR.DialOut.Enabled)
	assert.Equal(t, "0.0.0.0:57500", cfg.IOSXR.DialOut.NetAddr.Endpoint)
	assert.Equal(t, []string{"10.0.0.0/8"}, cfg.IOSXR.DialOut.AllowedClients)
	assert.Equal(t, gnmiDialOutIdentityRequired, cfg.IOSXR.DialOut.IdentityVerification)
	assert.Equal(t, []GNMIDialOutIdentityBindingConfig{{
		Sources: []string{"10.0.0.10"},
		NodeIDs: []string{"core-asr9k-1"},
	}}, cfg.IOSXR.DialOut.IdentityBindings)
	assert.Equal(t, uint32(16), cfg.IOSXR.DialOut.MaxStreamsPerClient)
	assert.Len(t, cfg.Scrapers, 2)
	assert.Contains(t, cfg.Scrapers, component.MustNewType("system"))
	assert.Contains(t, cfg.Scrapers, component.MustNewType("interfaces"))

	systemCfg, ok := cfg.Scrapers[component.MustNewType("system")].(*systemscraper.Config)
	require.True(t, ok)
	assert.True(t, systemCfg.ProtocolTraffic.Enabled)
	assert.True(t, systemCfg.ControlPlane.Enabled)
	assert.Equal(t, 5, systemCfg.ControlPlane.ProcessTopN)
	assert.True(t, systemCfg.ControlPlane.Commands.PuntRates)
	assert.Equal(t, []string{"default", "Mgmt-vrf"}, systemCfg.RoutingForwarding.VRFs)
	assert.Equal(t, 2, systemCfg.RoutingForwarding.MaxVRFs)
	assert.True(t, systemCfg.RoutingForwarding.Commands.RouteSummary)
	assert.True(t, systemCfg.RoutingForwarding.Commands.ARP)
	assert.True(t, systemCfg.RouterDataplane.Commands.QFPUtilization)
	assert.True(t, systemCfg.RouterDataplane.Commands.QFPDrops)
	assert.True(t, systemCfg.RouterDataplane.Commands.QoSDrops)
	assert.True(t, systemCfg.RouterDataplane.Commands.CryptoDrops)
	assert.Equal(t, 64, systemCfg.HardwareHealth.MaxComponents)
	assert.True(t, systemCfg.HardwareHealth.Commands.Environment)
	assert.Equal(t, []string{"default"}, systemCfg.RoutingNeighbors.VRFs)
	assert.Equal(t, 128, systemCfg.RoutingNeighbors.MaxNeighbors)
	assert.True(t, systemCfg.RoutingNeighbors.Commands.BGP)
	assert.Equal(t, 128, systemCfg.Fabric.MaxPeers)
	assert.Equal(t, 512, systemCfg.Fabric.MaxVNIs)
	assert.True(t, systemCfg.Fabric.Commands.NVEPeers)
	assert.True(t, systemCfg.Fabric.Commands.NVEVNIs)
	assert.True(t, systemCfg.Fabric.Commands.EVPNRoutes)

	interfaceCfg, ok := cfg.Scrapers[component.MustNewType("interfaces")].(*interfacesscraper.Config)
	require.True(t, ok)
	assert.True(t, interfaceCfg.Rates.Enabled)
	assert.True(t, interfaceCfg.Counters.Enabled)
	assert.Equal(t, []string{"*error*", "*drop*", "pause_*"}, interfaceCfg.Counters.Include)
	assert.Equal(t, 25, interfaceCfg.Counters.MaxPerInterface)
	assert.True(t, interfaceCfg.Counters.Commands.FlowControl)
	assert.True(t, interfaceCfg.Counters.Commands.QoSPolicy)
	assert.True(t, interfaceCfg.L2Topology.Enabled)
	assert.Equal(t, []string{"Gi*", "Eth*"}, interfaceCfg.L2Topology.Include)
	assert.Equal(t, []string{"*0/48"}, interfaceCfg.L2Topology.Exclude)
	assert.Equal(t, 32, interfaceCfg.L2Topology.MaxInterfaces)
	assert.Equal(t, 64, interfaceCfg.L2Topology.MaxVLANs)
	assert.True(t, interfaceCfg.L2Topology.Commands.VPC)
	assert.True(t, interfaceCfg.L2Topology.Commands.LLDP)
	assert.True(t, interfaceCfg.L2Topology.Commands.CDP)
	assert.True(t, interfaceCfg.Transceiver.Enabled)
	assert.Equal(t, []string{"Te*", "Eth*"}, interfaceCfg.Transceiver.Include)
	assert.Equal(t, 16, interfaceCfg.Transceiver.MaxInterfaces)
}

func TestConfigUnmarshalDefaultsEmptyMetricEntryToEnabled(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	require.NoError(t, cfg.Unmarshal(confmap.NewFromStringMap(map[string]any{
		"metrics": map[string]any{
			"empty":          map[string]any{},
			"explicit_true":  map[string]any{"enabled": true},
			"explicit_false": map[string]any{"enabled": false},
		},
	})))

	assert.True(t, cfg.Metrics["empty"].Enabled)
	assert.True(t, cfg.Metrics["explicit_true"].Enabled)
	assert.False(t, cfg.Metrics["explicit_false"].Enabled)
	assert.True(t, cfg.metricEnabled("empty"))
	assert.False(t, cfg.metricEnabled("explicit_false"))
}

func TestNexusDashboardAPIProfileDefaultsToLegacy(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	assert.Equal(t, nexusDashboardAPIProfileLegacy, cfg.NexusDashboard.APIProfile)
	assert.Equal(t, nexusDashboardAPIProfileLegacy, normalizeNexusDashboardAPIProfile(""))
}

func TestConfigUnmarshalNil(t *testing.T) {
	cfg := &Config{}
	err := cfg.Unmarshal(nil)
	require.NoError(t, err)
}

func TestConfigValidationIncludesDynamicScrapers(t *testing.T) {
	tests := []struct {
		name    string
		scraper component.Config
		wantErr string
	}{
		{
			name: "system",
			scraper: func() component.Config {
				cfg := systemscraper.NewFactory().CreateDefaultConfig().(*systemscraper.Config)
				cfg.RoutingForwarding.VRFs = []string{"blue;show version"}
				return cfg
			}(),
			wantErr: "routing_forwarding.vrfs[0] must contain only",
		},
		{
			name: "interfaces",
			scraper: func() component.Config {
				cfg := interfacesscraper.NewFactory().CreateDefaultConfig().(*interfacesscraper.Config)
				cfg.Counters.MaxInterfaces = -1
				return cfg
			}(),
			wantErr: "counters.max_interfaces must not be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewFactory().CreateDefaultConfig().(*Config)
			cfg.Devices = []DeviceConfig{validTestDevice()}
			cfg.Scrapers = map[component.Type]component.Config{component.MustNewType(tt.name): tt.scraper}
			require.ErrorContains(t, xconfmap.Validate(cfg), tt.wantErr)
		})
	}
}

func TestConfigUnmarshalRejectsUnknownSettings(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]any
	}{
		{
			name: "unknown top-level setting",
			config: map[string]any{
				"unexpected_setting": "1m",
			},
		},
		{
			name: "unknown nested setting",
			config: map[string]any{
				"sdwan": map[string]any{
					"insecure_skip_verfy": true,
				},
			},
		},
		{
			name: "removed Nexus telemetry lookback",
			config: map[string]any{
				"nexus_dashboard": map[string]any{
					"telemetry_lookback": "30m",
				},
			},
		},
		{
			name: "removed Nexus service discovery switch",
			config: map[string]any{
				"nexus_dashboard": map[string]any{
					"service_discovery": true,
				},
			},
		},
		{
			name: "removed ACI stats lookback",
			config: map[string]any{
				"aci": map[string]any{
					"stats_lookback": "30m",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewFactory().CreateDefaultConfig().(*Config)
			err := cfg.Unmarshal(confmap.NewFromStringMap(tt.config))
			require.Error(t, err)
			assert.Contains(t, strings.ToLower(err.Error()), "invalid keys")
		})
	}
}

func TestConfigUnmarshalPreservesExplicitZeroRetries(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	require.NoError(t, cfg.Unmarshal(confmap.NewFromStringMap(map[string]any{
		"meraki": map[string]any{"max_retries": 0},
	})))
	assert.Zero(t, cfg.Meraki.MaxRetries)
}

func TestConfigSafetyCeilings(t *testing.T) {
	assert.EqualError(t, validatePageSize("provider.page_size", 100_001), "provider.page_size must not exceed 100000")
	assert.EqualError(t, validateMaxRetries("provider.max_retries", 11), "provider.max_retries must not exceed 10")
	assert.EqualError(t, validateMaxResults("provider.group.max_results", 100_001), "provider.group.max_results must not exceed the hard pagination limit of 100000")

	assert.NoError(t, validatePageSize("provider.page_size", 100_000))
	assert.NoError(t, validateMaxRetries("provider.max_retries", 10))
	assert.NoError(t, validateMaxResults("provider.group.max_results", 100_000))
}
