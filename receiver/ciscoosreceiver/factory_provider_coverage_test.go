// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestFactoryWiresControllerMetricsProviders(t *testing.T) {
	tests := []struct {
		name       string
		config     func(*testing.T) *Config
		assertType func(*testing.T, receiver.Metrics)
	}{
		{
			name:   "Catalyst 9800",
			config: factoryCatalyst9800Config,
			assertType: func(t *testing.T, rcvr receiver.Metrics) {
				require.IsType(t, &catalyst9800DialInReceiver{}, rcvr)
			},
		},
		{
			name:   "SD-WAN",
			config: factorySDWANConfig,
			assertType: func(t *testing.T, rcvr receiver.Metrics) {
				require.IsType(t, &sdwanMetricsReceiver{}, rcvr)
			},
		},
		{
			name:   "Nexus Dashboard",
			config: factoryNexusDashboardConfig,
			assertType: func(t *testing.T, rcvr receiver.Metrics) {
				require.IsType(t, &nexusDashboardMetricsReceiver{}, rcvr)
			},
		},
		{
			name:   "ACI",
			config: factoryACIConfig,
			assertType: func(t *testing.T, rcvr receiver.Metrics) {
				require.IsType(t, &aciMetricsReceiver{}, rcvr)
			},
		},
		{
			name:   "FMC REST",
			config: factoryFMCRESTConfig,
			assertType: func(t *testing.T, rcvr receiver.Metrics) {
				require.IsType(t, &fmcMetricsReceiver{}, rcvr)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.config(t)
			require.NoError(t, cfg.Validate())

			rcvr, err := NewFactory().CreateMetrics(
				t.Context(),
				receivertest.NewNopSettings(metadata.Type),
				cfg,
				consumertest.NewNop(),
			)
			require.NoError(t, err)
			require.NotNil(t, rcvr)
			t.Cleanup(func() { require.NoError(t, rcvr.Shutdown(context.WithoutCancel(t.Context()))) })
			tt.assertType(t, rcvr)
		})
	}
}

func TestFactoryWiresControllerLogsProviders(t *testing.T) {
	tests := []struct {
		name       string
		config     func(*testing.T) *Config
		assertType func(*testing.T, receiver.Logs)
	}{
		{
			name:   "SD-WAN",
			config: factorySDWANConfig,
			assertType: func(t *testing.T, rcvr receiver.Logs) {
				require.IsType(t, &sdwanLogsReceiver{}, rcvr)
			},
		},
		{
			name:   "Nexus Dashboard",
			config: factoryNexusDashboardConfig,
			assertType: func(t *testing.T, rcvr receiver.Logs) {
				require.IsType(t, &nexusDashboardLogsReceiver{}, rcvr)
			},
		},
		{
			name:   "ACI",
			config: factoryACIConfig,
			assertType: func(t *testing.T, rcvr receiver.Logs) {
				require.IsType(t, &aciLogsReceiver{}, rcvr)
			},
		},
		{
			name:   "FMC REST",
			config: factoryFMCRESTConfig,
			assertType: func(t *testing.T, rcvr receiver.Logs) {
				require.IsType(t, &fmcLogsReceiver{}, rcvr)
			},
		},
		{
			name:   "FMC eStreamer",
			config: factoryFMCEStreamerConfig,
			assertType: func(t *testing.T, rcvr receiver.Logs) {
				require.IsType(t, &fmcEStreamerLogsReceiver{}, rcvr)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.config(t)
			require.NoError(t, cfg.Validate())

			rcvr, err := NewFactory().CreateLogs(
				t.Context(),
				receivertest.NewNopSettings(metadata.Type),
				cfg,
				consumertest.NewNop(),
			)
			require.NoError(t, err)
			require.NotNil(t, rcvr)
			t.Cleanup(func() { require.NoError(t, rcvr.Shutdown(context.WithoutCancel(t.Context()))) })
			tt.assertType(t, rcvr)
		})
	}
}

func factoryCatalyst9800Config(*testing.T) *Config {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.Catalyst9800.Enabled = true
	cfg.Catalyst9800.DialIn.Targets = []Catalyst9800TargetConfig{{
		ClientConfig: configgrpc.ClientConfig{Endpoint: "wlc.example.test:57400"},
		Name:         "campus-wlc-1",
		Credentials: Catalyst9800CredentialsConfig{
			Username: "telemetry",
			Password: configopaque.String("secret"),
		},
	}}
	return cfg
}

func factorySDWANConfig(*testing.T) *Config {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.SDWAN.Enabled = true
	cfg.SDWAN.Endpoint = "https://sdwan.example.test"
	cfg.SDWAN.Auth.Mode = "bearer"
	cfg.SDWAN.Auth.BearerToken = configopaque.String("token")
	return cfg
}

func factoryNexusDashboardConfig(*testing.T) *Config {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.NexusDashboard.Enabled = true
	cfg.NexusDashboard.Endpoint = "https://nexus-dashboard.example.test"
	cfg.NexusDashboard.Auth.Mode = "api_key"
	cfg.NexusDashboard.Auth.Username = "automation"
	cfg.NexusDashboard.Auth.APIKey = configopaque.String("token")
	return cfg
}

func factoryACIConfig(*testing.T) *Config {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.ACI.Enabled = true
	cfg.ACI.Controllers = []ACIControllerConfig{{Endpoint: "https://apic.example.test", Name: "apic-1"}}
	cfg.ACI.Auth.Username = "automation"
	cfg.ACI.Auth.Password = configopaque.String("secret")
	return cfg
}

func factoryFMCRESTConfig(*testing.T) *Config {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.FMC.Enabled = true
	cfg.FMC.Controllers = []FMCControllerConfig{{Endpoint: "https://fmc.example.test", Name: "fmc-1"}}
	cfg.FMC.Auth.Username = "automation"
	cfg.FMC.Auth.Password = configopaque.String("secret")
	return cfg
}

func factoryFMCEStreamerConfig(t *testing.T) *Config {
	material := runtimeTestTLSMaterial(t)
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.FMC.EStreamer.Enabled = true
	cfg.FMC.EStreamer.Targets = []FMCEStreamerTargetConfig{{Endpoint: "fmc.example.test:8302", Name: "fmc-1"}}
	cfg.FMC.EStreamer.TLS = FMCEStreamerTLSConfig{
		CertFile:   material.clientCertFile,
		KeyFile:    material.clientKeyFile,
		CAFile:     material.caFile,
		ServerName: runtimeTestServerName,
	}
	return cfg
}
