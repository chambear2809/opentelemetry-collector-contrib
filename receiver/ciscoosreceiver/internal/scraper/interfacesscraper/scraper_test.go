// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package interfacesscraper

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
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/interfacesscraper/internal/metadata"
)

func TestInterfacesScraper_Start(t *testing.T) {
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

	scraper := &interfacesScraper{
		logger: logger,
		config: config,
	}

	err := scraper.Start(t.Context(), componenttest.NewNopHost())
	require.NoError(t, err)
	assert.NotNil(t, scraper.mb, "MetricsBuilder should be initialized")
	assert.Equal(t, "192.168.1.1", scraper.deviceTarget)
}

func TestInterfacesScraper_Start_EmptyIP(t *testing.T) {
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

	scraper := &interfacesScraper{
		logger: logger,
		config: config,
	}

	err := scraper.Start(t.Context(), componenttest.NewNopHost())
	require.Error(t, err, "Should error with empty IP")
	assert.Contains(t, err.Error(), "no device configured")
}

func TestInterfacesScraper_Shutdown(t *testing.T) {
	logger := zap.NewNop()

	scraper := &interfacesScraper{
		logger: logger,
	}

	err := scraper.Shutdown(t.Context())
	require.NoError(t, err)
}

func TestInterfacesScraper_TroubleshootingGroupsDisabled(t *testing.T) {
	scraper := newStartedTestInterfacesScraper(t, createDefaultConfig().(*Config))
	fakeClient := newFakeInterfacesCommandClient()
	scraper.rpcClient = fakeClient

	metrics, err := scraper.ScrapeMetrics(t.Context())
	require.NoError(t, err)

	names := interfaceMetricDataPointCounts(metrics)
	assert.Contains(t, names, "system.network.interface.status")
	assert.NotContains(t, names, "cisco.port_channel.member.status")
	assert.NotContains(t, names, "cisco.transceiver.sensor")
	assert.NotContains(t, fakeClient.calls, "show etherchannel summary")
	assert.NotContains(t, fakeClient.calls, "show interfaces transceiver detail")
	assert.NotContains(t, fakeClient.calls, "show lldp neighbors detail")
	assert.NotContains(t, fakeClient.calls, "show cdp neighbors detail")
}

func TestInterfacesScraper_ParseInterfaceDataFallsBackWhenPrimaryOutputUnparseable(t *testing.T) {
	scraper := newStartedTestInterfacesScraper(t, createDefaultConfig().(*Config))
	fakeClient := newFakeInterfacesCommandClient()
	fakeClient.outputs["show interface"] = "% Invalid input detected at '^' marker."
	fakeClient.outputs["show interface brief"] = `Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet1/0/1   unassigned      YES unset  up                    up`
	scraper.rpcClient = fakeClient

	interfaces, err := scraper.parseInterfaceData(t.Context())
	require.NoError(t, err)
	require.Len(t, interfaces, 1)
	assert.Equal(t, "GigabitEthernet1/0/1", interfaces[0].Name)
	assert.Equal(t, StatusUp, interfaces[0].OperStatus)
	assert.Equal(t, []string{"show interface", "show interface brief"}, fakeClient.calls)
}

func TestInterfacesScraper_RecordsSpeedUtilizationAndTopology(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.L2Topology.Commands.LLDP = true
	cfg.L2Topology.Commands.CDP = true

	scraper := newStartedTestInterfacesScraper(t, cfg)
	fakeClient := newFakeInterfacesCommandClient()
	fakeClient.outputs["show interface"] = `GigabitEthernet1/0/1 is up, line protocol is up
  Hardware is iGbE, address is aabb.ccdd.ee01
  Description: uplink
  full-duplex, 10 Gb/s, media type is 10G
  30 seconds input rate 1000 bits/sec, 1 packets/sec
  30 seconds output rate 2000 bits/sec, 2 packets/sec
     1 packets input, 100 bytes
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     2 packets output, 200 bytes
     0 output errors, 0 collisions, 0 interface resets`
	fakeClient.outputs["show lldp neighbors detail"] = `Chassis id: 0011.2233.4455
System Name: leaf-02
Local Intf: GigabitEthernet1/0/1
Port id: Ethernet1/49
Management Address: 10.10.10.2`
	fakeClient.outputs["show cdp neighbors detail"] = `Device ID: core-01
Interface: GigabitEthernet1/0/1, Port ID (outgoing port): TenGigabitEthernet1/1
Platform: cisco C9500
IP address: 10.20.20.1`
	scraper.rpcClient = fakeClient

	metrics, err := scraper.ScrapeMetrics(t.Context())
	require.NoError(t, err)

	names := interfaceMetricDataPointCounts(metrics)
	assert.Equal(t, 1, names["cisco.interface.speed"])
	assert.Equal(t, 2, names["cisco.interface.utilization"])
	assert.Equal(t, 2, names["cisco.topology.neighbor.info"])
	assert.Contains(t, fakeClient.calls, "show lldp neighbors detail")
	assert.Contains(t, fakeClient.calls, "show cdp neighbors detail")
}

func TestInterfacesScraper_TroubleshootingGroupsRecordWithCapsFiltersAndOptionalFailures(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.L2Topology.Commands.STP = true
	cfg.L2Topology.Commands.PortChannel = true
	cfg.L2Topology.Include = []string{"Gi1/0/1"}
	cfg.L2Topology.MaxInterfaces = 1
	cfg.Transceiver.Enabled = true
	cfg.Transceiver.Include = []string{"Gi1/0/1"}
	cfg.Transceiver.MaxInterfaces = 1

	scraper := newStartedTestInterfacesScraper(t, cfg)
	fakeClient := newFakeInterfacesCommandClient()
	fakeClient.errors["show spanning-tree summary"] = errors.New("unsupported")
	fakeClient.errors["show spanning-tree detail"] = errors.New("unsupported")
	fakeClient.errors["show spanning-tree blockedports"] = errors.New("unsupported")
	fakeClient.outputs["show etherchannel summary"] = `Group  Port-channel  Protocol    Ports
1      Po1(SU)         LACP      Gi1/0/1(P) Gi1/0/2(P)`
	fakeClient.outputs["show interfaces transceiver detail"] = `Gi1/0/1 transceiver is present
  Temperature 31.0 C
  Voltage 3.3 V
Gi1/0/2 transceiver is present
  Temperature 30.0 C`
	scraper.rpcClient = fakeClient

	metrics, err := scraper.ScrapeMetrics(t.Context())
	require.NoError(t, err)

	names := interfaceMetricDataPointCounts(metrics)
	assert.NotContains(t, names, "cisco.port_channel.status")
	assert.Equal(t, 1, names["cisco.port_channel.member.status"])
	assert.Equal(t, 2, names["cisco.transceiver.sensor"])
	// The generated metrics builder may aggregate failures with identical
	// attributes and timestamps into one data point. Validate the cumulative
	// error value below instead of depending on scheduler/clock granularity.
	assert.Positive(t, names["cisco.scrape.command.errors"])
	assert.Equal(t, int64(3), interfaceMetricIntSum(metrics, "cisco.scrape.command.errors"))
	assert.Equal(t, 1, names["cisco.scrape.partial_success"])
	assert.Contains(t, fakeClient.calls, "show spanning-tree summary")
	assert.Contains(t, fakeClient.calls, "show etherchannel summary")
	assert.Contains(t, fakeClient.calls, "show interfaces transceiver detail")
	assert.NotContains(t, fakeClient.calls, "show lldp neighbors detail")
	assert.NotContains(t, fakeClient.calls, "show cdp neighbors detail")
}

func TestInterfacesScraper_PrimaryFailureRecordsScrapeHealth(t *testing.T) {
	scraper := newStartedTestInterfacesScraper(t, createDefaultConfig().(*Config))
	fakeClient := newFakeInterfacesCommandClient()
	fakeClient.errors["show interface"] = errors.New("unsupported")
	fakeClient.errors["show interface brief"] = errors.New("unsupported")
	scraper.rpcClient = fakeClient

	metrics, err := scraper.ScrapeMetrics(t.Context())
	require.Error(t, err)

	names := interfaceMetricDataPointCounts(metrics)
	assert.Equal(t, 2, names["cisco.scrape.command.errors"])
	assert.Equal(t, 1, names["cisco.scrape.partial_success"])
}

func TestInterfacesScraper_OptionalCountersDoNotSuppressCoreInterfaceMetrics(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Timeout = time.Millisecond
	cfg.Counters.Commands.PlatformQueueStats = true

	scraper := newStartedTestInterfacesScraper(t, cfg)
	fakeClient := newFakeInterfacesCommandClient()
	fakeClient.blockUntilContext["show platform hardware fed active qos queue stats interface GigabitEthernet1/0/1"] = true
	scraper.rpcClient = fakeClient

	metrics, err := scraper.ScrapeMetrics(t.Context())
	require.NoError(t, err)

	names := interfaceMetricDataPointCounts(metrics)
	assert.Contains(t, names, "system.network.interface.status")
	assert.Contains(t, names, "system.network.io")
	assert.Contains(t, names, "system.network.errors")
	assert.Contains(t, names, "system.network.packet.dropped")
	assert.Contains(t, fakeClient.calls, "show platform hardware fed active qos queue stats interface GigabitEthernet1/0/1")
}

func TestRecordPacketCounts_InputUnicastUnderflowGuard(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	scraper := newStartedTestInterfacesScraper(t, cfg)
	ts := pcommon.NewTimestampFromTime(time.Now())

	// Case 1: multicast + broadcast exceeds total packets — InputUnicast must not go negative
	overflow := &Interface{
		Name:                "Gi1/0/1",
		HasInputPacketTypes: true,
		InputPackets:        100,
		InputMulticast:      60,
		InputBroadcast:      50, // sum 110 > 100
		InputUnicast:        0,
	}
	recordPacketCounts(scraper.mb, ts, overflow, "", "", "")
	// Emit to flush the builder state for the next sub-test
	scraper.mb.Emit()

	assert.Equal(t, int64(0), overflow.InputUnicast,
		"InputUnicast should remain 0 when multicast+broadcast exceeds total (underflow guard)")

	// Case 2: multicast + broadcast is within total — InputUnicast should be computed correctly
	valid := &Interface{
		Name:                "Gi1/0/2",
		HasInputPacketTypes: true,
		InputPackets:        100,
		InputMulticast:      30,
		InputBroadcast:      20, // sum 50, leaves 50 unicast
		InputUnicast:        0,
	}
	recordPacketCounts(scraper.mb, ts, valid, "", "", "")
	scraper.mb.Emit()

	assert.Equal(t, int64(50), valid.InputUnicast,
		"InputUnicast should be 50 when multicast+broadcast sums to 50 out of 100 total")
}

func TestInterfacesScraper_NonPositiveTroubleshootingCapsUseDefaults(t *testing.T) {
	scraper := &interfacesScraper{
		config: &Config{
			L2Topology:  L2TopologyConfig{MaxInterfaces: 0, MaxVLANs: 0},
			Transceiver: TransceiverConfig{MaxInterfaces: 0},
		},
	}

	assert.Equal(t, 256, scraper.l2MaxInterfaces())
	assert.Equal(t, 128, scraper.l2MaxVLANs())
	assert.Equal(t, 256, scraper.transceiverMaxInterfaces())
}

func newStartedTestInterfacesScraper(t *testing.T, cfg *Config) *interfacesScraper {
	t.Helper()
	cfg.Device = connection.DeviceConfig{
		Device: connection.DeviceInfo{Host: connection.HostInfo{Name: "test-device", IP: "192.168.1.1", Port: 22}},
		Auth:   connection.AuthConfig{Username: "testuser", Password: "testpass"},
	}
	scraper := &interfacesScraper{logger: zap.NewNop(), config: cfg}
	require.NoError(t, scraper.Start(t.Context(), componenttest.NewNopHost()))
	return scraper
}

type fakeInterfacesCommandClient struct {
	osType            string
	outputs           map[string]string
	errors            map[string]error
	blockUntilContext map[string]bool
	calls             []string
}

func newFakeInterfacesCommandClient() *fakeInterfacesCommandClient {
	return &fakeInterfacesCommandClient{
		osType: "IOS XE",
		outputs: map[string]string{
			"show interface": `GigabitEthernet1/0/1 is up, line protocol is up
  Hardware is iGbE, address is aabb.ccdd.ee01
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0
     1 packets input, 100 bytes
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     2 packets output, 200 bytes
     0 output errors, 0 collisions, 0 interface resets`,
		},
		errors:            map[string]error{},
		blockUntilContext: map[string]bool{},
	}
}

func (f *fakeInterfacesCommandClient) GetOSType() string {
	return f.osType
}

func (f *fakeInterfacesCommandClient) GetCommand(feature string) string {
	return (&connection.RPCClient{OSType: f.osType}).GetCommand(feature)
}

func (f *fakeInterfacesCommandClient) GetCommands(feature string) []string {
	return (&connection.RPCClient{OSType: f.osType}).GetCommands(feature)
}

func (f *fakeInterfacesCommandClient) ExecuteCommand(command string) (string, error) {
	return f.executeCommand(command)
}

func (f *fakeInterfacesCommandClient) ExecuteCommandWithContext(ctx context.Context, command string) (string, error) {
	if f.blockUntilContext[command] {
		f.calls = append(f.calls, command)
		<-ctx.Done()
		return "", ctx.Err()
	}
	return f.executeCommand(command)
}

func (f *fakeInterfacesCommandClient) executeCommand(command string) (string, error) {
	f.calls = append(f.calls, command)
	if err, ok := f.errors[command]; ok {
		return "", err
	}
	return f.outputs[command], nil
}

func (*fakeInterfacesCommandClient) Close() error {
	return nil
}

func interfaceMetricDataPointCounts(metrics pmetric.Metrics) map[string]int {
	counts := map[string]int{}
	for i := 0; i < metrics.ResourceMetrics().Len(); i++ {
		scopeMetrics := metrics.ResourceMetrics().At(i).ScopeMetrics()
		for j := 0; j < scopeMetrics.Len(); j++ {
			metricSlice := scopeMetrics.At(j).Metrics()
			for k := 0; k < metricSlice.Len(); k++ {
				metric := metricSlice.At(k)
				counts[metric.Name()] += interfaceMetricDataPointCount(metric)
			}
		}
	}
	return counts
}

func interfaceMetricDataPointCount(metric pmetric.Metric) int {
	switch metric.Type() {
	case pmetric.MetricTypeGauge:
		return metric.Gauge().DataPoints().Len()
	case pmetric.MetricTypeSum:
		return metric.Sum().DataPoints().Len()
	default:
		return 0
	}
}

func interfaceMetricIntSum(metrics pmetric.Metrics, metricName string) int64 {
	var total int64
	for i := 0; i < metrics.ResourceMetrics().Len(); i++ {
		scopeMetrics := metrics.ResourceMetrics().At(i).ScopeMetrics()
		for j := 0; j < scopeMetrics.Len(); j++ {
			metricSlice := scopeMetrics.At(j).Metrics()
			for k := 0; k < metricSlice.Len(); k++ {
				metric := metricSlice.At(k)
				if metric.Name() != metricName || metric.Type() != pmetric.MetricTypeSum {
					continue
				}
				dataPoints := metric.Sum().DataPoints()
				for l := 0; l < dataPoints.Len(); l++ {
					total += dataPoints.At(l).IntValue()
				}
			}
		}
	}
	return total
}
