// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package systemscraper

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/systemscraper/internal/metadata"
)

func TestSystemScraper_Start(t *testing.T) {
	logger := zap.NewNop()

	config := &Config{
		Device: connection.DeviceConfig{
			Device: connection.DeviceInfo{
				Host: connection.HostInfo{
					Name: "test-device",
					IP:   "192.168.1.1",
					Port: 22,
				},
			},
			Auth: connection.AuthConfig{
				Username: "testuser",
				Password: "testpass",
			},
		},
	}
	config.MetricsBuilderConfig = metadata.NewDefaultMetricsBuilderConfig()

	scraper := &systemScraper{
		logger: logger,
		config: config,
	}

	err := scraper.Start(t.Context(), componenttest.NewNopHost())
	require.NoError(t, err)
	assert.NotNil(t, scraper.mb, "MetricsBuilder should be initialized")
	assert.Equal(t, "192.168.1.1", scraper.deviceTarget)
}

func TestSystemScraper_Start_EmptyIP(t *testing.T) {
	logger := zap.NewNop()

	config := &Config{
		Device: connection.DeviceConfig{
			Device: connection.DeviceInfo{
				Host: connection.HostInfo{
					Name: "test-device",
					IP:   "",
					Port: 22,
				},
			},
		},
	}
	config.MetricsBuilderConfig = metadata.NewDefaultMetricsBuilderConfig()

	scraper := &systemScraper{
		logger: logger,
		config: config,
	}

	err := scraper.Start(t.Context(), componenttest.NewNopHost())
	require.Error(t, err, "Should error with empty IP")
	assert.Contains(t, err.Error(), "no device configured")
}

func TestSystemScraper_HostIPResourceRequiresIPLiteral(t *testing.T) {
	scraper := newStartedTestSystemScraper(t, createDefaultConfig().(*Config))

	scraper.deviceTarget = "router.example.com"
	_, ok := scraper.newResourceBuilder().Emit().Attributes().Get("host.ip")
	assert.False(t, ok)

	scraper.deviceTarget = "2001:0db8:0:0:0:0:0:10"
	hostIP, ok := scraper.newResourceBuilder().Emit().Attributes().Get("host.ip")
	require.True(t, ok)
	assert.Equal(t, "2001:db8::10", hostIP.Str())
}

func TestSystemScraper_Shutdown(t *testing.T) {
	logger := zap.NewNop()

	scraper := &systemScraper{
		logger: logger,
	}

	err := scraper.Shutdown(t.Context())
	require.NoError(t, err)
}

func TestSystemScraper_TroubleshootingGroupsDisabled(t *testing.T) {
	scraper := newStartedTestSystemScraper(t, createDefaultConfig().(*Config))
	fakeClient := newFakeSystemCommandClient()
	scraper.rpcClient = fakeClient

	metrics, err := scraper.ScrapeMetrics(t.Context())
	require.NoError(t, err)

	names := systemMetricDataPointCounts(metrics)
	assert.Contains(t, names, "cisco.device.up")
	assert.NotContains(t, names, "cisco.control_plane.cpu.process.utilization")
	assert.NotContains(t, names, "cisco.routing.routes")
	assert.NotContains(t, fakeClient.calls, "show processes cpu sorted 5sec")
	assert.NotContains(t, fakeClient.calls, "show ip route summary")
	assert.NotContains(t, fakeClient.calls, "show environment all")
	assert.NotContains(t, fakeClient.calls, "show ip bgp summary")
	assert.NotContains(t, fakeClient.calls, "show nve peers")
}

func TestSystemScraper_TroubleshootingGroupsRecordWithCapsAndOptionalFailures(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.ControlPlane.Commands.CPUProcesses = true
	cfg.ControlPlane.ProcessTopN = 1
	cfg.RoutingForwarding.Commands.RouteSummary = true
	cfg.RoutingForwarding.VRFs = []string{"default", "blue", "red"}
	cfg.RoutingForwarding.MaxVRFs = 2

	scraper := newStartedTestSystemScraper(t, cfg)
	fakeClient := newFakeSystemCommandClient()
	fakeClient.errors["show processes cpu sorted 5sec"] = errors.New("unsupported")
	fakeClient.outputs["show process cpu sorted 5sec"] = `PID Runtime(ms) Invoked uSecs 5Sec 1Min 5Min TTY Process
  10 1 1 1 20.00% 1.00% 1.00% 0 IOSD
  20 1 1 1 10.00% 1.00% 1.00% 0 ARP Input`
	fakeClient.outputs["show ip route summary"] = `connected 2
Total number of routes: 2`
	fakeClient.outputs["show ip route vrf blue summary"] = `static 3
Total number of routes: 3`
	scraper.rpcClient = fakeClient

	metrics, err := scraper.ScrapeMetrics(t.Context())
	require.NoError(t, err)

	names := systemMetricDataPointCounts(metrics)
	assert.Equal(t, 1, names["cisco.control_plane.cpu.process.utilization"])
	assert.Equal(t, 4, names["cisco.routing.routes"])
	assert.Equal(t, 1, names["cisco.scrape.command.errors"])
	assert.Equal(t, 1, names["cisco.scrape.partial_success"])
	assert.Contains(t, fakeClient.calls, "show processes cpu sorted 5sec")
	assert.Contains(t, fakeClient.calls, "show process cpu sorted 5sec")
	assert.Contains(t, fakeClient.calls, "show ip route summary")
	assert.Contains(t, fakeClient.calls, "show ip route vrf blue summary")
	assert.NotContains(t, fakeClient.calls, "show ip route vrf red summary")
}

func TestSystemScraper_TroubleshootingFallbackCommandsStopAfterParseableOutput(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.ControlPlane.Commands.CoPP = true
	cfg.ControlPlane.Commands.PuntRates = true
	cfg.RoutingForwarding.Commands.ForwardingDrops = true

	scraper := newStartedTestSystemScraper(t, cfg)
	fakeClient := newFakeSystemCommandClient()
	fakeClient.outputs["show policy-map control-plane"] = `Class-map: routing
  10 packets, 640 bytes`
	fakeClient.outputs["show policy-map system-cpp-policy"] = `Class-map: duplicate
  20 packets, 1280 bytes`
	fakeClient.outputs["show platform software fed active punt rates interfaces"] = `GigabitEthernet1/0/1 0x00000001 5 5 5 0 0 0`
	fakeClient.outputs["show platform software fed switch active punt rates interfaces"] = `GigabitEthernet1/0/1 0x00000001 7 7 7 0 0 0`
	fakeClient.outputs["show cef drop"] = `No route drop: 3`
	fakeClient.outputs["show ip cef switching statistics"] = `No route drop: 4`
	scraper.rpcClient = fakeClient

	metrics, err := scraper.ScrapeMetrics(t.Context())
	require.NoError(t, err)

	names := systemMetricDataPointCounts(metrics)
	assert.Equal(t, 1, names["cisco.control_plane.packets"])
	assert.Equal(t, 1, names["cisco.control_plane.punt.rate"])
	assert.Equal(t, 1, names["cisco.forwarding.drops"])
	assert.Contains(t, fakeClient.calls, "show policy-map control-plane")
	assert.NotContains(t, fakeClient.calls, "show policy-map system-cpp-policy")
	assert.Contains(t, fakeClient.calls, "show platform software fed active punt rates interfaces")
	assert.NotContains(t, fakeClient.calls, "show platform software fed switch active punt rates interfaces")
	assert.Contains(t, fakeClient.calls, "show cef drop")
	assert.NotContains(t, fakeClient.calls, "show ip cef switching statistics")
}

func TestSystemScraper_CommandsAllStopsAfterFirstParseableAlias(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.RoutingForwarding.Commands.All = true

	scraper := newStartedTestSystemScraper(t, cfg)
	fakeClient := newFakeSystemCommandClient()
	scraper.rpcClient = fakeClient
	commands := scraper.commandsForVRF("routing_forwarding_drops", "default")
	require.Len(t, commands, 7)
	for _, command := range commands {
		fakeClient.outputs[command] = `No route drop: 3`
	}

	metrics, err := scraper.ScrapeMetrics(t.Context())
	require.NoError(t, err)

	assert.Equal(t, int64(3), systemMetricIntSum(metrics, "cisco.forwarding.drops"))
	assert.Contains(t, fakeClient.calls, commands[0])
	for _, command := range commands[1:] {
		assert.NotContains(t, fakeClient.calls, command)
	}
}

func TestSystemScraper_CommandErrorsAccumulateAcrossScrapes(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.RouterDataplane.Commands.QoSDrops = true

	scraper := newStartedTestSystemScraper(t, cfg)
	fakeClient := newFakeSystemCommandClient()
	fakeClient.errors["show drops qos"] = errors.New("unsupported")
	scraper.rpcClient = fakeClient

	first, err := scraper.ScrapeMetrics(t.Context())
	require.NoError(t, err)
	second, err := scraper.ScrapeMetrics(t.Context())
	require.NoError(t, err)

	assert.Equal(t, int64(1), systemMetricIntSum(first, "cisco.scrape.command.errors"))
	assert.Equal(t, int64(2), systemMetricIntSum(second, "cisco.scrape.command.errors"))
}

func TestSystemScraper_RecordsHardwareAndRoutingNeighbors(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.HardwareHealth.Commands.Environment = true
	cfg.RoutingNeighbors.Commands.BGP = true

	scraper := newStartedTestSystemScraper(t, cfg)
	fakeClient := newFakeSystemCommandClient()
	fakeClient.outputs["show environment all"] = `Fan 1 OK
Power Supply 1 OK
Temperature Sensor 1 42 C OK`
	fakeClient.outputs["show ip bgp summary"] = `Neighbor        V    AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd
10.0.0.2       4 65001      10      12      0   0    0 1d02h 42`
	scraper.rpcClient = fakeClient

	metrics, err := scraper.ScrapeMetrics(t.Context())
	require.NoError(t, err)

	names := systemMetricDataPointCounts(metrics)
	assert.GreaterOrEqual(t, names["cisco.hardware.status"], 3)
	assert.Equal(t, 1, names["cisco.hardware.temperature"])
	assert.Equal(t, 1, names["cisco.routing.neighbor.state"])
	assert.Equal(t, 1, names["cisco.routing.neighbor.prefixes"])
	assert.Contains(t, fakeClient.calls, "show environment all")
	assert.Contains(t, fakeClient.calls, "show ip bgp summary")
}

func TestSystemScraper_HardwareMaxComponentsCapsStatusAndTemperatureTogether(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.HardwareHealth.Commands.Environment = true
	cfg.HardwareHealth.MaxComponents = 3

	scraper := newStartedTestSystemScraper(t, cfg)
	fakeClient := newFakeSystemCommandClient()
	fakeClient.outputs["show environment all"] = `Fan 1 OK
Power Supply 1 OK
Temperature Sensor 1 42 C OK
Temperature Sensor 2 43 C OK`
	scraper.rpcClient = fakeClient

	metrics, err := scraper.ScrapeMetrics(t.Context())
	require.NoError(t, err)

	names := systemMetricDataPointCounts(metrics)
	assert.Equal(t, 3, names["cisco.hardware.status"])
	assert.Equal(t, 1, names["cisco.hardware.temperature"])
}

func TestSystemScraper_RouterDataplaneRecordsQFPMetrics(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.RouterDataplane.Commands.QFPUtilization = true
	cfg.RouterDataplane.Commands.QFPDrops = true
	cfg.RouterDataplane.Commands.QoSDrops = true

	scraper := newStartedTestSystemScraper(t, cfg)
	fakeClient := newFakeSystemCommandClient()
	fakeClient.outputs["show platform hardware qfp active datapath utilization"] = `CPP 0: 5 secs 1 min 5 min 60 min
Input: Total (pps) 62 71 75 73
       (bps) 399280 514352 572520 559440
Output: Total (pps) 61 71 75 73
        (bps) 391904 514648 573408 560424
Processing: Load (pct) 7 8 8 8
Crypto/IO
Crypto: Load (pct) 0 0 0 0
RX: Load (pct) 0 0 0 0
TX: Load (pct) 10 9 9 9
Idle (pct) 90 90 90 90`
	fakeClient.outputs["show drops qfp"] = `------------------ show platform hardware qfp active statistics drop detail ------------------
ID Global Drop Stats Packets Octets
319 BFDoffload 9 1350
23 TailDrop 26713208 10952799454
------------------ show platform hardware qfp active interface all statistics drop_summary ------------------
Drop Stats Summary:
Interface Rx Pkts Tx Pkts
GigabitEthernet1 60547 0
Tunnel14095001 0 1990214`
	fakeClient.outputs["show drops qos"] = `ID Global Drop Stats Packets Octets
23 TailDrop 11 2200`
	scraper.rpcClient = fakeClient

	metrics, err := scraper.ScrapeMetrics(t.Context())
	require.NoError(t, err)

	names := systemMetricDataPointCounts(metrics)
	assert.Equal(t, 20, names["cisco.qfp.datapath.utilization"])
	assert.Equal(t, 8, names["cisco.qfp.datapath.packet.rate"])
	assert.Equal(t, 8, names["cisco.qfp.datapath.io"])
	assert.Equal(t, 3, names["cisco.qfp.drops"])
	assert.Equal(t, 3, names["cisco.qfp.drop.bytes"])
	assert.Equal(t, 4, names["cisco.qfp.interface.drops"])
	assert.Contains(t, fakeClient.calls, "show platform hardware qfp active datapath utilization")
	assert.Contains(t, fakeClient.calls, "show drops qfp")
	assert.Contains(t, fakeClient.calls, "show drops qos")
}

func TestSystemScraper_OptionalRouterDataplaneDoesNotSuppressCoreMetrics(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Timeout = 10 * time.Millisecond
	cfg.RouterDataplane.Commands.QFPUtilization = true

	scraper := newStartedTestSystemScraper(t, cfg)
	fakeClient := newFakeSystemCommandClient()
	fakeClient.blockUntilContext["show platform hardware qfp active datapath utilization"] = true
	scraper.rpcClient = fakeClient

	metrics, err := scraper.ScrapeMetrics(t.Context())
	require.NoError(t, err)

	names := systemMetricDataPointCounts(metrics)
	assert.Equal(t, 1, names["cisco.device.up"])
	assert.Equal(t, 1, names["system.cpu.utilization"])
	assert.Equal(t, 1, names["system.memory.utilization"])
	assert.Zero(t, names["cisco.qfp.datapath.utilization"])
	assert.Contains(t, fakeClient.calls, "show platform hardware qfp active datapath utilization")
	assert.NotContains(t, fakeClient.calls, "show platform hardware qfp active datapath utilization summary")
}

func TestSystemScraper_UnparseableCoreOutputKeepsReachableDeviceUp(t *testing.T) {
	scraper := newStartedTestSystemScraper(t, createDefaultConfig().(*Config))
	fakeClient := newFakeSystemCommandClient()
	fakeClient.outputs["show process cpu"] = "new CPU format"
	fakeClient.outputs["show process memory"] = "new memory format"
	scraper.rpcClient = fakeClient

	metrics, err := scraper.ScrapeMetrics(t.Context())
	require.NoError(t, err)

	assert.Equal(t, int64(1), systemMetricIntSum(metrics, "cisco.device.up"))
	assert.Equal(t, int64(1), systemMetricIntSum(metrics, "cisco.scrape.partial_success"))
	assert.NotNil(t, scraper.rpcClient)
	assert.Zero(t, systemMetricDataPointCounts(metrics)["system.cpu.utilization"])
	assert.Zero(t, systemMetricDataPointCounts(metrics)["system.memory.utilization"])
}

func TestSystemScraper_CoreMetricsRetryAfterOSTypeChangesDuringCommand(t *testing.T) {
	t.Run("CPU", func(t *testing.T) {
		scraper := newStartedTestSystemScraper(t, createDefaultConfig().(*Config))
		fakeClient := newFakeSystemCommandClient()
		fakeClient.outputs["show process cpu"] = "CPU utilization for five seconds: 99%/0%; one minute: 99%; five minutes: 99%"
		fakeClient.outputs["show system resources"] = "CPU states : 10.00% user, 5.00% kernel, 85.00% idle"
		fakeClient.osTypeAfterCommand["show process cpu"] = "NX-OS"
		scraper.rpcClient = fakeClient

		utilization, err := scraper.collectCPUUtilization(t.Context())
		require.NoError(t, err)
		assert.InDelta(t, 0.15, utilization, 0.0001)
		assert.Equal(t, []string{"show process cpu", "show system resources"}, fakeClient.calls)
	})

	t.Run("memory", func(t *testing.T) {
		scraper := newStartedTestSystemScraper(t, createDefaultConfig().(*Config))
		fakeClient := newFakeSystemCommandClient()
		fakeClient.outputs["show process memory"] = "Processor Pool Total: 1000 Used: 900 Free: 100"
		fakeClient.outputs["show system resources"] = "Memory usage: 1000K total, 250K used, 750K free"
		fakeClient.osTypeAfterCommand["show process memory"] = "NX-OS"
		scraper.rpcClient = fakeClient

		utilization, err := scraper.collectMemoryUtilization(t.Context())
		require.NoError(t, err)
		assert.InDelta(t, 0.25, utilization, 0.0001)
		assert.Equal(t, []string{"show process memory", "show system resources"}, fakeClient.calls)
	})

	t.Run("refuses a second identity change", func(t *testing.T) {
		scraper := newStartedTestSystemScraper(t, createDefaultConfig().(*Config))
		fakeClient := newFakeSystemCommandClient()
		fakeClient.outputs["show system resources"] = "CPU states : 10.00% user, 5.00% kernel, 85.00% idle"
		fakeClient.osTypeAfterCommand["show process cpu"] = "NX-OS"
		fakeClient.osTypeAfterCommand["show system resources"] = "IOS XE"
		scraper.rpcClient = fakeClient

		_, err := scraper.collectCPUUtilization(t.Context())
		require.ErrorContains(t, err, "OS type changed again during cpu command retry")
		assert.Equal(t, []string{"show process cpu", "show system resources"}, fakeClient.calls)
	})
}

func TestSystemScraper_CoreCommandResponseErrorsKeepReachableDeviceUp(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
	}{
		{name: "CLI rejection", err: connection.ErrCiscoCLICommandRejected},
		{name: "output limit", err: connection.ErrSSHCommandOutputTooLarge},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scraper := newStartedTestSystemScraper(t, createDefaultConfig().(*Config))
			fakeClient := newFakeSystemCommandClient()
			fakeClient.errors["show process cpu"] = tt.err
			fakeClient.errors["show process memory"] = tt.err
			scraper.rpcClient = fakeClient

			metrics, err := scraper.ScrapeMetrics(t.Context())
			require.NoError(t, err)

			assert.Equal(t, int64(1), systemMetricIntSum(metrics, "cisco.device.up"))
			assert.Equal(t, int64(1), systemMetricIntSum(metrics, "cisco.scrape.partial_success"))
			assert.Equal(t, int64(2), systemMetricIntSum(metrics, "cisco.scrape.command.errors"))
			assert.NotNil(t, scraper.rpcClient)
		})
	}
}

func TestSystemScraper_CoreCommandExecutionFailuresMarkDeviceDown(t *testing.T) {
	scraper := newStartedTestSystemScraper(t, createDefaultConfig().(*Config))
	fakeClient := newFakeSystemCommandClient()
	fakeClient.deviceMetadata = connection.DeviceMetadata{Serial: "FTX1234", HostID: "FTX1234"}
	fakeClient.errors["show process cpu"] = errors.New("connection lost")
	fakeClient.errors["show process memory"] = errors.New("connection lost")
	scraper.rpcClient = fakeClient

	metrics, err := scraper.ScrapeMetrics(t.Context())
	require.NoError(t, err)

	assert.Equal(t, int64(0), systemMetricIntSum(metrics, "cisco.device.up"))
	assert.Equal(t, int64(1), systemMetricIntSum(metrics, "cisco.scrape.partial_success"))
	assert.Nil(t, scraper.rpcClient)
	serial, ok := metrics.ResourceMetrics().At(0).Resource().Attributes().Get("cisco.switch.serial")
	require.True(t, ok)
	assert.Equal(t, "FTX1234", serial.Str())
}

func TestSystemScraper_UnsupportedCoreCommandAndExecutionFailureMarkDeviceDown(t *testing.T) {
	scraper := newStartedTestSystemScraper(t, createDefaultConfig().(*Config))
	fakeClient := newFakeSystemCommandClient()
	fakeClient.commandOverrides["cpu"] = ""
	fakeClient.errors["show process memory"] = errors.New("connection lost")
	scraper.rpcClient = fakeClient

	metrics, err := scraper.ScrapeMetrics(t.Context())
	require.NoError(t, err)

	assert.Equal(t, int64(0), systemMetricIntSum(metrics, "cisco.device.up"))
	assert.Nil(t, scraper.rpcClient)
}

func TestScrapeMetrics_DeviceUp_IsOne_WhenConnected(t *testing.T) {
	scraper := newStartedTestSystemScraper(t, createDefaultConfig().(*Config))
	fakeClient := newFakeSystemCommandClient()
	fakeClient.deviceMetadata = connection.DeviceMetadata{
		HostName:  "device-hostname",
		HostID:    "FTX1234",
		Serial:    "FTX1234",
		HostType:  "C9300",
		OSType:    "IOS XE",
		OSVersion: "17.9.4",
	}
	scraper.rpcClient = fakeClient

	metrics, err := scraper.ScrapeMetrics(t.Context())
	require.NoError(t, err)

	names := systemMetricDataPointCounts(metrics)
	assert.Equal(t, 1, names["cisco.device.up"], "cisco.device.up should have exactly one data point")

	// Verify the value is 1 (device is up)
	for i := 0; i < metrics.ResourceMetrics().Len(); i++ {
		scopeMetrics := metrics.ResourceMetrics().At(i).ScopeMetrics()
		for j := 0; j < scopeMetrics.Len(); j++ {
			metricSlice := scopeMetrics.At(j).Metrics()
			for k := 0; k < metricSlice.Len(); k++ {
				m := metricSlice.At(k)
				if m.Name() == "cisco.device.up" {
					require.Equal(t, pmetric.MetricTypeGauge, m.Type())
					require.Equal(t, 1, m.Gauge().DataPoints().Len())
					assert.Equal(t, int64(1), m.Gauge().DataPoints().At(0).IntValue(),
						"cisco.device.up should be 1 when rpcClient is functional")
				}
			}
		}
	}

	attrs := metrics.ResourceMetrics().At(0).Resource().Attributes()
	hostName, ok := attrs.Get("host.name")
	require.True(t, ok)
	assert.Equal(t, "device-hostname", hostName.Str())
	hostID, ok := attrs.Get("host.id")
	require.True(t, ok)
	assert.Equal(t, "FTX1234", hostID.Str())
	serial, ok := attrs.Get("cisco.switch.serial")
	require.True(t, ok)
	assert.Equal(t, "FTX1234", serial.Str())
	hostType, ok := attrs.Get("host.type")
	require.True(t, ok)
	assert.Equal(t, "C9300", hostType.Str())
	osVersion, ok := attrs.Get("os.version")
	require.True(t, ok)
	assert.Equal(t, "17.9.4", osVersion.Str())
}

func TestSystemScraper_UsesLastVerifiedResourceIdentityWhenDisconnected(t *testing.T) {
	scraper := newStartedTestSystemScraper(t, createDefaultConfig().(*Config))
	store := &connection.DeviceMetadataStore{}
	store.Store(connection.DeviceMetadata{
		HostName:  "device-hostname",
		HostID:    "FTX1234",
		Serial:    "FTX1234",
		HostType:  "C9300",
		OSType:    "IOS XE",
		OSVersion: "17.9.4",
	})
	scraper.config.Device.MetadataStore = store
	scraper.rpcClient = nil
	scraper.mb.RecordCiscoDeviceUpDataPoint(pcommon.NewTimestampFromTime(time.Now()), 0)

	metrics := scraper.emitMetricsWithResource(scraper.newResourceBuilder())
	attrs := metrics.ResourceMetrics().At(0).Resource().Attributes()
	for key, expected := range map[string]string{
		"host.name":           "device-hostname",
		"host.id":             "FTX1234",
		"host.type":           "C9300",
		"os.name":             "IOS XE",
		"os.version":          "17.9.4",
		"cisco.switch.serial": "FTX1234",
	} {
		value, ok := attrs.Get(key)
		require.True(t, ok, key)
		assert.Equal(t, expected, value.Str(), key)
	}
}

func TestSystemScraper_NonPositiveTroubleshootingCapsUseDefaults(t *testing.T) {
	scraper := &systemScraper{
		config: &Config{
			ControlPlane:      ControlPlaneConfig{ProcessTopN: 0},
			RoutingForwarding: RoutingForwardingConfig{MaxVRFs: 0},
			HardwareHealth:    HardwareHealthConfig{MaxComponents: 0},
			RoutingNeighbors:  RoutingNeighborsConfig{MaxVRFs: 0, MaxNeighbors: 0},
			Fabric:            FabricConfig{MaxPeers: 0, MaxVNIs: 0},
		},
	}

	assert.Equal(t, 10, scraper.controlPlaneProcessTopN())
	assert.Equal(t, 16, scraper.routingForwardingMaxVRFs())
	assert.Equal(t, 256, scraper.hardwareMaxComponents())
	assert.Equal(t, 16, scraper.routingNeighborMaxVRFs())
	assert.Equal(t, 512, scraper.routingNeighborMaxNeighbors())
	assert.Equal(t, 512, scraper.fabricMaxPeers())
	assert.Equal(t, 2048, scraper.fabricMaxVNIs())
}

func newStartedTestSystemScraper(t *testing.T, cfg *Config) *systemScraper {
	t.Helper()
	cfg.Device = connection.DeviceConfig{
		Device: connection.DeviceInfo{Host: connection.HostInfo{Name: "test-device", IP: "192.168.1.1", Port: 22}},
		Auth:   connection.AuthConfig{Username: "testuser", Password: "testpass"},
	}
	scraper := &systemScraper{logger: zap.NewNop(), config: cfg}
	require.NoError(t, scraper.Start(t.Context(), componenttest.NewNopHost()))
	return scraper
}

type fakeSystemCommandClient struct {
	osType             string
	osTypeAfterCommand map[string]string
	deviceMetadata     connection.DeviceMetadata
	outputs            map[string]string
	errors             map[string]error
	commandOverrides   map[string]string
	blockUntilContext  map[string]bool
	calls              []string
}

func newFakeSystemCommandClient() *fakeSystemCommandClient {
	return &fakeSystemCommandClient{
		osType:             "IOS XE",
		osTypeAfterCommand: map[string]string{},
		outputs: map[string]string{
			"show process cpu":    "CPU utilization for five seconds: 5%/0%; one minute: 3%; five minutes: 2%",
			"show process memory": "Processor Pool Total: 1000 Used: 500 Free: 500",
		},
		errors:            map[string]error{},
		commandOverrides:  map[string]string{},
		blockUntilContext: map[string]bool{},
	}
}

func (f *fakeSystemCommandClient) GetOSType() string {
	return f.osType
}

func (f *fakeSystemCommandClient) GetDeviceMetadata() connection.DeviceMetadata {
	return f.deviceMetadata
}

func (f *fakeSystemCommandClient) GetCommand(feature string) string {
	if command, ok := f.commandOverrides[feature]; ok {
		return command
	}
	return (&connection.RPCClient{OSType: f.osType}).GetCommand(feature)
}

func (f *fakeSystemCommandClient) GetCommands(feature string) []string {
	return (&connection.RPCClient{OSType: f.osType}).GetCommands(feature)
}

func (f *fakeSystemCommandClient) ExecuteCommand(command string) (string, error) {
	f.calls = append(f.calls, command)
	f.applyOSTypeChangeAfterCommand(command)
	if err, ok := f.errors[command]; ok {
		return "", err
	}
	return f.outputs[command], nil
}

func (f *fakeSystemCommandClient) ExecuteCommandWithContext(ctx context.Context, command string) (string, error) {
	f.calls = append(f.calls, command)
	if f.blockUntilContext[command] {
		<-ctx.Done()
		return "", ctx.Err()
	}
	f.applyOSTypeChangeAfterCommand(command)
	if err, ok := f.errors[command]; ok {
		return "", err
	}
	return f.outputs[command], nil
}

func (f *fakeSystemCommandClient) applyOSTypeChangeAfterCommand(command string) {
	if osType, ok := f.osTypeAfterCommand[command]; ok {
		f.osType = osType
		delete(f.osTypeAfterCommand, command)
	}
}

func (*fakeSystemCommandClient) Close() error {
	return nil
}

func systemMetricDataPointCounts(metrics pmetric.Metrics) map[string]int {
	counts := map[string]int{}
	for i := 0; i < metrics.ResourceMetrics().Len(); i++ {
		scopeMetrics := metrics.ResourceMetrics().At(i).ScopeMetrics()
		for j := 0; j < scopeMetrics.Len(); j++ {
			metricSlice := scopeMetrics.At(j).Metrics()
			for k := 0; k < metricSlice.Len(); k++ {
				metric := metricSlice.At(k)
				counts[metric.Name()] += metricDataPointCount(metric)
			}
		}
	}
	return counts
}

func systemMetricIntSum(metrics pmetric.Metrics, metricName string) int64 {
	var total int64
	for i := 0; i < metrics.ResourceMetrics().Len(); i++ {
		scopeMetrics := metrics.ResourceMetrics().At(i).ScopeMetrics()
		for j := 0; j < scopeMetrics.Len(); j++ {
			metricSlice := scopeMetrics.At(j).Metrics()
			for k := 0; k < metricSlice.Len(); k++ {
				metric := metricSlice.At(k)
				if metric.Name() != metricName {
					continue
				}
				switch metric.Type() {
				case pmetric.MetricTypeGauge:
					for l := 0; l < metric.Gauge().DataPoints().Len(); l++ {
						total += metric.Gauge().DataPoints().At(l).IntValue()
					}
				case pmetric.MetricTypeSum:
					for l := 0; l < metric.Sum().DataPoints().Len(); l++ {
						total += metric.Sum().DataPoints().At(l).IntValue()
					}
				}
			}
		}
	}
	return total
}

func metricDataPointCount(metric pmetric.Metric) int {
	switch metric.Type() {
	case pmetric.MetricTypeGauge:
		return metric.Gauge().DataPoints().Len()
	case pmetric.MetricTypeSum:
		return metric.Sum().DataPoints().Len()
	default:
		return 0
	}
}
