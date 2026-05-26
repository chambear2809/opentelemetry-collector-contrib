// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/interfacesscraper"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/systemscraper"
)

func newTestDevice(name, host string) DeviceConfig {
	return DeviceConfig{
		Name: name,
		Host: host,
		Port: 22,
		Auth: connection.AuthConfig{
			Username: "admin",
			Password: configopaque.String("password"),
		},
	}
}

func TestNewFactory(t *testing.T) {
	factory := NewFactory()
	require.NotNil(t, factory)
	assert.Equal(t, "cisco_os", factory.Type().String())
}

func TestCreateDefaultConfig(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	require.NotNil(t, cfg)

	config, ok := cfg.(*Config)
	require.True(t, ok)
	assert.Equal(t, 1*time.Minute, config.CollectionInterval)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Empty(t, config.Devices)
	assert.Empty(t, config.Scrapers)
	assert.Equal(t, "https://api.meraki.com/api/v1", config.Meraki.BaseURL)
	assert.Equal(t, "opentelemetry-collector-contrib-ciscoosreceiver", config.Meraki.UserAgent)
	assert.Equal(t, "https://intersight.com", config.Intersight.Endpoint)
	assert.Equal(t, 100, config.Intersight.PageSize)
	assert.Equal(t, 24*time.Hour, config.Intersight.EventLookback)
	assert.Equal(t, 30*time.Minute, config.Intersight.TelemetryLookback)
	assert.True(t, config.Intersight.Inventory.Enabled)
	assert.True(t, config.Intersight.Telemetry.Enabled)
	assert.Empty(t, config.CatalystCenter.Endpoint)
	assert.Equal(t, 500, config.CatalystCenter.PageSize)
	assert.Equal(t, 24*time.Hour, config.CatalystCenter.Lookback)
	assert.True(t, config.CatalystCenter.Inventory.Enabled)
	assert.True(t, config.CatalystCenter.Issues.Enabled)
}

func TestCreateMetricsReceiver(t *testing.T) {
	factory := NewFactory()
	config := factory.CreateDefaultConfig().(*Config)
	config.Devices = []DeviceConfig{newTestDevice("test-device", "192.168.1.1")}
	config.Scrapers = map[component.Type]component.Config{
		component.MustNewType("system"): systemscraper.NewFactory().CreateDefaultConfig(),
	}

	receiver, err := factory.CreateMetrics(t.Context(), receivertest.NewNopSettings(metadata.Type), config, consumertest.NewNop())
	assert.NotNil(t, receiver)
	assert.NoError(t, err)
}

func TestCreateMetricsReceiverWithMeraki(t *testing.T) {
	factory := NewFactory()
	config := factory.CreateDefaultConfig().(*Config)
	config.Meraki.Auth.APIKey = configopaque.String("meraki-key")
	config.Meraki.Organizations = []MerakiOrganizationConfig{{OrganizationID: "123456"}}

	receiver, err := factory.CreateMetrics(t.Context(), receivertest.NewNopSettings(metadata.Type), config, consumertest.NewNop())
	assert.NotNil(t, receiver)
	assert.NoError(t, err)

	_, ok := receiver.(*merakiMetricsReceiver)
	assert.True(t, ok, "expected merakiMetricsReceiver for Meraki-only config")
}

func TestCreateMetricsReceiverWithSSHAndMeraki(t *testing.T) {
	factory := NewFactory()
	config := factory.CreateDefaultConfig().(*Config)
	config.Devices = []DeviceConfig{newTestDevice("test-device", "192.168.1.1")}
	config.Scrapers = map[component.Type]component.Config{
		component.MustNewType("system"): systemscraper.NewFactory().CreateDefaultConfig(),
	}
	config.Meraki.Auth.APIKey = configopaque.String("meraki-key")
	config.Meraki.Devices = []MerakiDeviceConfig{{OrganizationID: "123456", Serial: "Q234-ABCD-5678"}}

	receiver, err := factory.CreateMetrics(t.Context(), receivertest.NewNopSettings(metadata.Type), config, consumertest.NewNop())
	assert.NotNil(t, receiver)
	assert.NoError(t, err)

	_, ok := receiver.(*multiMetricsReceiver)
	assert.True(t, ok, "expected multiMetricsReceiver for mixed SSH and Meraki config")
}

func TestCreateMetricsReceiverWithIntersight(t *testing.T) {
	factory := NewFactory()
	config := factory.CreateDefaultConfig().(*Config)
	config.Intersight.Enabled = true
	config.Intersight.Auth.KeyID = "test-key"
	config.Intersight.Auth.KeyPEM = configopaque.String(testIntersightPrivateKeyPEM(t))

	receiver, err := factory.CreateMetrics(t.Context(), receivertest.NewNopSettings(metadata.Type), config, consumertest.NewNop())
	assert.NotNil(t, receiver)
	assert.NoError(t, err)

	_, ok := receiver.(*intersightMetricsReceiver)
	assert.True(t, ok, "expected intersightMetricsReceiver for Intersight-only config")
}

func TestCreateMetricsReceiverWithCatalystCenter(t *testing.T) {
	factory := NewFactory()
	config := factory.CreateDefaultConfig().(*Config)
	config.CatalystCenter.Enabled = true
	config.CatalystCenter.Endpoint = "https://catalyst-center.example.com"
	config.CatalystCenter.Auth.Username = "admin"
	config.CatalystCenter.Auth.Password = configopaque.String("password")

	receiver, err := factory.CreateMetrics(t.Context(), receivertest.NewNopSettings(metadata.Type), config, consumertest.NewNop())
	assert.NotNil(t, receiver)
	assert.NoError(t, err)

	_, ok := receiver.(*catalystCenterMetricsReceiver)
	assert.True(t, ok, "expected catalystCenterMetricsReceiver for Catalyst Center-only config")
}

func TestCreateMetricsReceiverWithDisabledCatalystCenter(t *testing.T) {
	factory := NewFactory()
	config := factory.CreateDefaultConfig().(*Config)
	config.CatalystCenter.Endpoint = "https://catalyst-center.example.com"
	config.CatalystCenter.Auth.Username = "admin"
	config.CatalystCenter.Auth.Password = configopaque.String("password")

	receiver, err := factory.CreateMetrics(t.Context(), receivertest.NewNopSettings(metadata.Type), config, consumertest.NewNop())
	assert.NotNil(t, receiver)
	assert.NoError(t, err)

	_, ok := receiver.(*nopMetricsReceiver)
	assert.True(t, ok, "expected disabled Catalyst Center config not to create a receiver")
}

func TestCreateLogsReceiverWithIntersight(t *testing.T) {
	factory := NewFactory()
	config := factory.CreateDefaultConfig().(*Config)
	config.Intersight.Enabled = true
	config.Intersight.Auth.KeyID = "test-key"
	config.Intersight.Auth.KeyPEM = configopaque.String(testIntersightPrivateKeyPEM(t))

	receiver, err := factory.CreateLogs(t.Context(), receivertest.NewNopSettings(metadata.Type), config, &consumertest.LogsSink{})
	assert.NotNil(t, receiver)
	assert.NoError(t, err)

	_, ok := receiver.(*intersightLogsReceiver)
	assert.True(t, ok, "expected intersightLogsReceiver for Intersight config")
}

func TestCreateLogsReceiverWithoutIntersight(t *testing.T) {
	factory := NewFactory()
	config := factory.CreateDefaultConfig().(*Config)

	receiver, err := factory.CreateLogs(t.Context(), receivertest.NewNopSettings(metadata.Type), config, &consumertest.LogsSink{})
	assert.NotNil(t, receiver)
	assert.NoError(t, err)

	_, ok := receiver.(*nopLogsReceiver)
	assert.True(t, ok, "expected nopLogsReceiver when Intersight is not configured")
}

func TestFactoryCanBeUsed(t *testing.T) {
	factory := NewFactory()
	err := componenttest.CheckConfigStruct(factory.CreateDefaultConfig())
	require.NoError(t, err)
}

func TestCreateMetricsReceiverWithMultipleDevices(t *testing.T) {
	factory := NewFactory()
	config := factory.CreateDefaultConfig().(*Config)
	config.Devices = []DeviceConfig{
		newTestDevice("device-1", "192.168.1.1"),
		newTestDevice("device-2", "192.168.1.2"),
	}
	config.Scrapers = map[component.Type]component.Config{
		component.MustNewType("system"): systemscraper.NewFactory().CreateDefaultConfig(),
	}

	receiver, err := factory.CreateMetrics(t.Context(), receivertest.NewNopSettings(metadata.Type), config, consumertest.NewNop())
	assert.NotNil(t, receiver)
	assert.NoError(t, err)

	_, isMulti := receiver.(*multiMetricsReceiver)
	assert.True(t, isMulti, "expected multiMetricsReceiver for multiple devices")
}

func TestCreateMetricsReceiverFiltersSSHDevicesBeforeControllerCreation(t *testing.T) {
	factory := NewFactory()
	config := factory.CreateDefaultConfig().(*Config)
	config.Devices = []DeviceConfig{
		newTestDevice("device-1", "192.168.1.1"),
		newTestDevice("device-2", "192.168.1.2"),
	}
	config.DeviceSelection.Include.HostNames = []string{"device-1"}
	config.Scrapers = map[component.Type]component.Config{
		component.MustNewType("system"): systemscraper.NewFactory().CreateDefaultConfig(),
	}

	receiver, err := factory.CreateMetrics(t.Context(), receivertest.NewNopSettings(metadata.Type), config, consumertest.NewNop())
	require.NoError(t, err)
	assert.NotNil(t, receiver)
	_, isMulti := receiver.(*multiMetricsReceiver)
	assert.False(t, isMulti, "expected one SSH controller after device selection")
}

func TestCreateMetricsReceiverReturnsNopWhenSSHDevicesAreExcluded(t *testing.T) {
	factory := NewFactory()
	config := factory.CreateDefaultConfig().(*Config)
	config.Devices = []DeviceConfig{newTestDevice("device-1", "192.168.1.1")}
	config.DeviceSelection.Exclude.HostIPs = []string{"192.168.1.1"}
	config.Scrapers = map[component.Type]component.Config{
		component.MustNewType("system"): systemscraper.NewFactory().CreateDefaultConfig(),
	}

	receiver, err := factory.CreateMetrics(t.Context(), receivertest.NewNopSettings(metadata.Type), config, consumertest.NewNop())
	require.NoError(t, err)
	_, ok := receiver.(*nopMetricsReceiver)
	assert.True(t, ok, "expected no SSH controller when all devices are excluded")
}

func TestScraperFactoriesRegistered(t *testing.T) {
	assert.Contains(t, scraperFactories, component.MustNewType("system"))
	assert.Contains(t, scraperFactories, component.MustNewType("interfaces"))
	assert.Len(t, scraperFactories, 2)
}

func TestCloneSystemScraperConfigPreservesOptionalGroups(t *testing.T) {
	source := systemscraper.NewFactory().CreateDefaultConfig().(*systemscraper.Config)
	source.ProtocolTraffic.Enabled = true
	source.ControlPlane.Enabled = true
	source.RoutingForwarding.VRFs = []string{"default", "blue"}
	source.RouterDataplane.Commands.QFPDrops = true
	source.HardwareHealth.Enabled = true
	source.HardwareHealth.MaxComponents = 64
	source.HardwareHealth.Commands.Inventory = true
	source.RoutingNeighbors.Enabled = true
	source.RoutingNeighbors.VRFs = []string{"default", "Mgmt-vrf"}
	source.RoutingNeighbors.MaxNeighbors = 128
	source.RoutingNeighbors.Commands.BGP = true
	source.Fabric.Enabled = true
	source.Fabric.MaxPeers = 128
	source.Fabric.MaxVNIs = 512
	source.Fabric.Commands.NVEPeers = true

	device := connection.DeviceConfig{
		Device: connection.DeviceInfo{
			Host: connection.HostInfo{Name: "leaf-01", IP: "192.0.2.10", Port: 22},
		},
	}

	cloned := cloneSystemScraperConfig(systemscraper.NewFactory(), source, device, 45*time.Second)
	assert.True(t, cloned.ProtocolTraffic.Enabled)
	assert.True(t, cloned.ControlPlane.Enabled)
	assert.Equal(t, []string{"default", "blue"}, cloned.RoutingForwarding.VRFs)
	assert.True(t, cloned.RouterDataplane.Commands.QFPDrops)
	assert.True(t, cloned.HardwareHealth.Enabled)
	assert.Equal(t, 64, cloned.HardwareHealth.MaxComponents)
	assert.True(t, cloned.HardwareHealth.Commands.Inventory)
	assert.True(t, cloned.RoutingNeighbors.Enabled)
	assert.Equal(t, []string{"default", "Mgmt-vrf"}, cloned.RoutingNeighbors.VRFs)
	assert.Equal(t, 128, cloned.RoutingNeighbors.MaxNeighbors)
	assert.True(t, cloned.RoutingNeighbors.Commands.BGP)
	assert.True(t, cloned.Fabric.Enabled)
	assert.Equal(t, 128, cloned.Fabric.MaxPeers)
	assert.Equal(t, 512, cloned.Fabric.MaxVNIs)
	assert.True(t, cloned.Fabric.Commands.NVEPeers)
	assert.Equal(t, "192.0.2.10", cloned.Device.Device.Host.IP)
	assert.Equal(t, 45*time.Second, cloned.Timeout)
}

func TestCloneInterfacesScraperConfigPreservesOptionalGroups(t *testing.T) {
	source := interfacesscraper.NewFactory().CreateDefaultConfig().(*interfacesscraper.Config)
	source.Rates.Enabled = true
	source.Counters.Enabled = true
	source.Counters.MaxPerInterface = 25
	source.Counters.Commands.QoSPolicy = true
	source.L2Topology.Enabled = true
	source.L2Topology.Include = []string{"Eth*"}
	source.L2Topology.Commands.LLDP = true
	source.Transceiver.Enabled = true
	source.Transceiver.MaxInterfaces = 16

	device := connection.DeviceConfig{
		Device: connection.DeviceInfo{
			Host: connection.HostInfo{Name: "leaf-01", IP: "192.0.2.10", Port: 22},
		},
	}

	cloned := cloneInterfacesScraperConfig(interfacesscraper.NewFactory(), source, device, 45*time.Second)
	assert.True(t, cloned.Rates.Enabled)
	assert.True(t, cloned.Counters.Enabled)
	assert.Equal(t, 25, cloned.Counters.MaxPerInterface)
	assert.True(t, cloned.Counters.Commands.QoSPolicy)
	assert.True(t, cloned.L2Topology.Enabled)
	assert.Equal(t, []string{"Eth*"}, cloned.L2Topology.Include)
	assert.True(t, cloned.L2Topology.Commands.LLDP)
	assert.True(t, cloned.Transceiver.Enabled)
	assert.Equal(t, 16, cloned.Transceiver.MaxInterfaces)
	assert.Equal(t, "192.0.2.10", cloned.Device.Device.Host.IP)
	assert.Equal(t, 45*time.Second, cloned.Timeout)
}
