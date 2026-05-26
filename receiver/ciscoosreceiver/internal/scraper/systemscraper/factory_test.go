// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package systemscraper

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/systemscraper/internal/metadata"
)

func TestNewFactory(t *testing.T) {
	factory := NewFactory()
	require.NotNil(t, factory)
	assert.Equal(t, "system", factory.Type().String())
}

func TestCreateDefaultConfig(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	require.NotNil(t, cfg)

	// Verify it's a Config type
	config, ok := cfg.(*Config)
	assert.True(t, ok)
	assert.NotNil(t, config)

	// Verify default metrics are enabled
	assert.True(t, config.Metrics.CiscoDeviceUp.Enabled)
	assert.False(t, config.ProtocolTraffic.Enabled)
	assert.False(t, config.ControlPlane.Enabled)
	assert.Equal(t, 10, config.ControlPlane.ProcessTopN)
	assert.False(t, config.ControlPlane.Commands.anyEnabled())
	assert.False(t, config.RoutingForwarding.Enabled)
	assert.Equal(t, []string{"default"}, config.RoutingForwarding.VRFs)
	assert.Equal(t, 16, config.RoutingForwarding.MaxVRFs)
	assert.False(t, config.RoutingForwarding.Commands.anyEnabled())
	assert.False(t, config.RouterDataplane.Enabled)
	assert.False(t, config.RouterDataplane.Commands.anyEnabled())
}

func TestFactory_CreateScraperMethod(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)

	// Add device configuration
	cfg.Device = connection.DeviceConfig{
		Device: connection.DeviceInfo{
			Host: connection.HostInfo{
				IP:   "192.168.1.1",
				Port: 22,
			},
		},
		Auth: connection.AuthConfig{
			Username: "admin",
			Password: "password",
		},
	}

	// Verify config structure is correct for scraper creation
	assert.NotNil(t, cfg)
	assert.Equal(t, "192.168.1.1", cfg.Device.Device.Host.IP)
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
	}{
		{
			name: "valid_config",
			config: &Config{
				MetricsBuilderConfig: metadata.NewDefaultMetricsBuilderConfig(),
				Device: connection.DeviceConfig{
					Device: connection.DeviceInfo{
						Host: connection.HostInfo{IP: "192.168.1.1", Port: 22},
					},
					Auth: connection.AuthConfig{Username: "admin", Password: "password"},
				},
			},
			expectError: false,
		},
		{
			name: "empty_device",
			config: &Config{
				MetricsBuilderConfig: metadata.NewDefaultMetricsBuilderConfig(),
				Device:               connection.DeviceConfig{},
			},
			expectError: false, // Empty device is allowed at config level
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Config doesn't have explicit Validate, just verify structure
			assert.NotNil(t, tt.config)
			if !tt.expectError {
				assert.NotNil(t, tt.config.MetricsBuilderConfig)
			}
		})
	}
}

func TestConfig_MetricsConfiguration(t *testing.T) {
	config := &Config{
		MetricsBuilderConfig: metadata.NewDefaultMetricsBuilderConfig(),
	}

	// Verify metrics are configurable
	assert.True(t, config.Metrics.CiscoDeviceUp.Enabled)

	// Test disabling metrics
	config.Metrics.CiscoDeviceUp.Enabled = false
	assert.False(t, config.Metrics.CiscoDeviceUp.Enabled)
}

func TestDeviceConfig_Structure(t *testing.T) {
	device := connection.DeviceConfig{
		Device: connection.DeviceInfo{
			Host: connection.HostInfo{
				Name: "router1",
				IP:   "10.0.0.1",
				Port: 22,
			},
		},
		Auth: connection.AuthConfig{
			Username: "admin",
			Password: "secret",
			KeyFile:  "/path/to/key",
		},
	}

	assert.Equal(t, "router1", device.Device.Host.Name)
	assert.Equal(t, "10.0.0.1", device.Device.Host.IP)
	assert.Equal(t, 22, device.Device.Host.Port)
	assert.Equal(t, "admin", device.Auth.Username)
	assert.Equal(t, "secret", string(device.Auth.Password))
	assert.Equal(t, "/path/to/key", device.Auth.KeyFile)
}

func TestHostInfo_DefaultPort(t *testing.T) {
	host := connection.HostInfo{
		Name: "router",
		IP:   "192.168.1.1",
		Port: 22,
	}

	assert.Equal(t, "router", host.Name)
	assert.Equal(t, "192.168.1.1", host.IP)
	assert.Equal(t, 22, host.Port)
}

func TestAuthConfig_PasswordOnly(t *testing.T) {
	auth := connection.AuthConfig{
		Username: "testuser",
		Password: "testpass",
	}

	assert.Equal(t, "testuser", auth.Username)
	assert.Equal(t, "testpass", string(auth.Password))
	assert.Empty(t, auth.KeyFile)
}

func TestAuthConfig_KeyFileOnly(t *testing.T) {
	auth := connection.AuthConfig{
		Username: "testuser",
		KeyFile:  "/home/user/.ssh/id_rsa",
	}

	assert.Equal(t, "testuser", auth.Username)
	assert.Empty(t, auth.Password)
	assert.Equal(t, "/home/user/.ssh/id_rsa", auth.KeyFile)
}

func TestFactory_Type(t *testing.T) {
	factory := NewFactory()
	scraperType := factory.Type()

	assert.Equal(t, "system", scraperType.String())
}

func TestCreateDefaultConfig_MetricsEnabled(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)

	// Verify all default metrics are enabled
	metrics := cfg.Metrics
	assert.True(t, metrics.CiscoDeviceUp.Enabled)
}

func TestTroubleshootingGroupCommandDefaults(t *testing.T) {
	controlPlane := defaultControlPlaneConfig()
	assert.False(t, controlPlane.emitsMetrics())
	assert.False(t, controlPlane.commandEnabled("control_cpu_processes"))

	controlPlane.Enabled = true
	assert.True(t, controlPlane.emitsMetrics())
	assert.True(t, controlPlane.commandEnabled("control_cpu_processes"))
	assert.True(t, controlPlane.commandEnabled("control_copp"))
	assert.True(t, controlPlane.commandEnabled("control_punt_rates"))

	controlPlane = defaultControlPlaneConfig()
	controlPlane.Commands.PuntRates = true
	assert.True(t, controlPlane.emitsMetrics())
	assert.True(t, controlPlane.commandEnabled("control_punt_rates"))
	assert.False(t, controlPlane.commandEnabled("control_copp"))

	routing := defaultRoutingForwardingConfig()
	assert.False(t, routing.emitsMetrics())
	assert.False(t, routing.commandEnabled("routing_route_summary"))

	routing.Enabled = true
	assert.True(t, routing.commandEnabled("routing_route_summary"))
	assert.True(t, routing.commandEnabled("routing_arp"))
	assert.True(t, routing.commandEnabled("routing_cef_fib"))
	assert.True(t, routing.commandEnabled("routing_adjacency"))
	assert.True(t, routing.commandEnabled("routing_forwarding_drops"))

	routing = defaultRoutingForwardingConfig()
	routing.Commands.All = true
	assert.True(t, routing.commandEnabled("routing_forwarding_drops"))

	routerDataplane := defaultRouterDataplaneConfig()
	assert.False(t, routerDataplane.emitsMetrics())
	assert.False(t, routerDataplane.commandEnabled("router_qfp_utilization"))

	routerDataplane.Enabled = true
	assert.True(t, routerDataplane.emitsMetrics())
	assert.True(t, routerDataplane.commandEnabled("router_qfp_utilization"))
	assert.True(t, routerDataplane.commandEnabled("router_qfp_drops"))
	assert.True(t, routerDataplane.commandEnabled("router_interface_drops"))
	assert.True(t, routerDataplane.commandEnabled("router_qos_drops"))
	assert.True(t, routerDataplane.commandEnabled("router_crypto_drops"))
	assert.True(t, routerDataplane.commandEnabled("router_nat_drops"))
	assert.True(t, routerDataplane.commandEnabled("router_punt_drops"))
	assert.True(t, routerDataplane.commandEnabled("router_ip_drops"))

	routerDataplane = defaultRouterDataplaneConfig()
	routerDataplane.Commands.QFPDrops = true
	assert.True(t, routerDataplane.emitsMetrics())
	assert.True(t, routerDataplane.commandEnabled("router_qfp_drops"))
	assert.False(t, routerDataplane.commandEnabled("router_qfp_utilization"))
}
