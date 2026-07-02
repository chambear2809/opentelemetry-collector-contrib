// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package ciscoosreceiver

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/interfacesscraper"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/systemscraper"
)

const (
	ciscoOSE2EHostEnv             = "CISCOOS_E2E_HOST"
	ciscoOSE2EPortEnv             = "CISCOOS_E2E_PORT"
	ciscoOSE2EUsernameEnv         = "CISCOOS_E2E_USERNAME"
	ciscoOSE2EPasswordEnv         = "CISCOOS_E2E_PASSWORD"
	ciscoOSE2EEnablePasswordEnv   = "CISCOOS_E2E_ENABLE_PASSWORD"
	ciscoOSE2EKeyFileEnv          = "CISCOOS_E2E_KEY_FILE"
	ciscoOSE2EKnownHostsEnv       = "CISCOOS_E2E_KNOWN_HOSTS_FILE"
	ciscoOSE2EInsecureSkipEnv     = "CISCOOS_E2E_INSECURE_SKIP_VERIFY"
	ciscoOSE2EExpectedOSEnv       = "CISCOOS_E2E_EXPECT_OS"
	ciscoOSE2EExpectedMetricsEnv  = "CISCOOS_E2E_EXPECT_METRICS"
	ciscoOSE2EExpectedIntfsEnv    = "CISCOOS_E2E_EXPECT_INTERFACES"
	ciscoOSE2EMinInterfacesEnv    = "CISCOOS_E2E_MIN_INTERFACES"
	ciscoOSE2ECollectionIntEnv    = "CISCOOS_E2E_COLLECTION_INTERVAL"
	ciscoOSE2ETimeoutEnv          = "CISCOOS_E2E_TIMEOUT"
	ciscoOSE2EWaitTimeoutEnv      = "CISCOOS_E2E_WAIT_TIMEOUT"
	ciscoOSE2EOptionalCommandsEnv = "CISCOOS_E2E_ENABLE_OPTIONAL_COMMANDS"
	ciscoOSE2ERouterDataplaneEnv  = "CISCOOS_E2E_ENABLE_ROUTER_DATAPLANE_COMMANDS"
	ciscoOSE2EVRFsEnv             = "CISCOOS_E2E_VRFS"
	ciscoOSE2EIOSXREndpointEnv    = "CISCOOS_E2E_IOSXR_ENDPOINT"
	ciscoOSE2EIOSXRUsernameEnv    = "CISCOOS_E2E_IOSXR_USERNAME"
	ciscoOSE2EIOSXRPasswordEnv    = "CISCOOS_E2E_IOSXR_PASSWORD"
	ciscoOSE2EIOSXRInsecureEnv    = "CISCOOS_E2E_IOSXR_TLS_INSECURE"
	ciscoOSE2EIOSXRGroupsEnv      = "CISCOOS_E2E_IOSXR_PATH_GROUPS"
	ciscoOSE2EIOSXRMetricsEnv     = "CISCOOS_E2E_IOSXR_EXPECT_METRICS"
	ciscoOSE2EIOSXRDialOutEnv     = "CISCOOS_E2E_IOSXR_DIALOUT_ENDPOINT"
)

var defaultCiscoOSE2EMetrics = []string{
	"cisco.device.up",
	"system.cpu.utilization",
	"system.memory.utilization",
	"system.network.errors",
	"system.network.interface.status",
	"system.network.io",
	"system.network.packet.count",
	"system.network.packet.dropped",
}

// TestE2ELiveSwitch exercises the receiver against a real Cisco switch over SSH.
//
// Required environment:
//
//	CISCOOS_E2E_HOST
//	CISCOOS_E2E_USERNAME
//	CISCOOS_E2E_PASSWORD or CISCOOS_E2E_KEY_FILE
//	CISCOOS_E2E_KNOWN_HOSTS_FILE or CISCOOS_E2E_INSECURE_SKIP_VERIFY=true
//
// Useful NX-OS lab example:
//
//	CISCOOS_E2E_HOST=10.0.0.10
//	CISCOOS_E2E_USERNAME=automation
//	CISCOOS_E2E_KNOWN_HOSTS_FILE=../../local/ciscoos_known_hosts
//	CISCOOS_E2E_EXPECT_OS=NX-OS
//	CISCOOS_E2E_MIN_INTERFACES=20
//	CISCOOS_E2E_EXPECT_INTERFACES=mgmt0,Eth1/1,Eth1/15,Eth1/16,Lo0,Lo1,Vlan1
//	go test -tags=e2e -run TestE2ELiveSwitch -count=1 -timeout=3m ./receiver/ciscoosreceiver
func TestE2ELiveSwitch(t *testing.T) {
	cfg := newCiscoOSE2EConfig(t)
	sink := new(consumertest.MetricsSink)

	rcvr, err := NewFactory().CreateMetrics(
		t.Context(),
		receivertest.NewNopSettings(metadata.Type),
		cfg,
		sink,
	)
	require.NoError(t, err)
	require.NoError(t, rcvr.Start(t.Context(), componenttest.NewNopHost()))
	t.Cleanup(func() {
		assert.NoError(t, rcvr.Shutdown(context.Background()))
	})

	expectedMetrics := append([]string{}, defaultCiscoOSE2EMetrics...)
	if boolEnv(t, ciscoOSE2ERouterDataplaneEnv, false) {
		expectedMetrics = append(expectedMetrics, "cisco.qfp.datapath.utilization")
	}
	expectedMetrics = append(expectedMetrics, csvEnv(ciscoOSE2EExpectedMetricsEnv)...)
	waitTimeout := durationEnv(t, ciscoOSE2EWaitTimeoutEnv, 2*time.Minute)

	require.EventuallyWithT(t, func(tt *assert.CollectT) {
		summary := summarizeCiscoOSE2EMetrics(sink.AllMetrics())
		assert.Positive(tt, sink.DataPointCount())
		assert.Contains(tt, summary.hostIPs, cfg.Devices[0].Host)
		assert.True(tt, summary.deviceUp, "expected cisco.device.up datapoint with value 1")
		for _, metricName := range expectedMetrics {
			assert.Contains(tt, summary.metricNames, metricName)
		}
	}, waitTimeout, time.Second)

	summary := summarizeCiscoOSE2EMetrics(sink.AllMetrics())
	if expectedOS := os.Getenv(ciscoOSE2EExpectedOSEnv); expectedOS != "" {
		assert.Contains(t, summary.osNames, expectedOS)
	}

	minInterfaces := intEnv(t, ciscoOSE2EMinInterfacesEnv, 1)
	assert.GreaterOrEqual(t, len(summary.interfaceNames), minInterfaces)
	normalizedInterfaceNames := normalizeCiscoOSE2EInterfaceSet(summary.interfaceNames)
	for _, interfaceName := range csvEnv(ciscoOSE2EExpectedIntfsEnv) {
		assert.Contains(t, normalizedInterfaceNames, normalizeCiscoOSE2EInterfaceName(interfaceName))
	}
	for _, invalidInterfaceName := range []string{"Ethernet", "Port", "Interface"} {
		assert.NotContains(t, summary.interfaceNames, invalidInterfaceName)
	}

	t.Logf("collected %d metric batches, %d datapoints, %d metric names, %d interfaces, OS values: %v",
		len(sink.AllMetrics()), sink.DataPointCount(), len(summary.metricNames), len(summary.interfaceNames), setKeys(summary.osNames))
}

func TestE2EIOSXRGNMIDialIn(t *testing.T) {
	cfg := newIOSXRDialInE2EConfig(t)
	sink := new(consumertest.MetricsSink)

	rcvr, err := NewFactory().CreateMetrics(
		t.Context(),
		receivertest.NewNopSettings(metadata.Type),
		cfg,
		sink,
	)
	require.NoError(t, err)
	require.NoError(t, rcvr.Start(t.Context(), componenttest.NewNopHost()))
	t.Cleanup(func() {
		assert.NoError(t, rcvr.Shutdown(context.Background()))
	})

	expectedMetrics := append([]string{"cisco.iosxr.receiver.updates"}, csvEnv(ciscoOSE2EIOSXRMetricsEnv)...)
	waitTimeout := durationEnv(t, ciscoOSE2EWaitTimeoutEnv, 2*time.Minute)
	require.EventuallyWithT(t, func(tt *assert.CollectT) {
		summary := summarizeCiscoOSE2EMetrics(sink.AllMetrics())
		assert.Positive(tt, sink.DataPointCount())
		assert.True(tt, summaryHasMetricPrefix(summary, "cisco.iosxr."), "expected IOS XR metrics")
		for _, metricName := range expectedMetrics {
			assert.Contains(tt, summary.metricNames, metricName)
		}
	}, waitTimeout, time.Second)
}

func TestE2EIOSXRMDTDialOut(t *testing.T) {
	endpoint := os.Getenv(ciscoOSE2EIOSXRDialOutEnv)
	if endpoint == "" {
		t.Skipf("set %s to run IOS XR MDT dial-out e2e test", ciscoOSE2EIOSXRDialOutEnv)
	}

	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.IOSXR.Enabled = true
	cfg.IOSXR.DialOut.Enabled = true
	cfg.IOSXR.DialOut.ServerConfig.NetAddr.Endpoint = endpoint
	cfg.IOSXR.DialOut.ServerConfig.NetAddr.Transport = "tcp"
	require.NoError(t, cfg.Validate())

	sink := new(consumertest.MetricsSink)
	rcvr, err := NewFactory().CreateMetrics(
		t.Context(),
		receivertest.NewNopSettings(metadata.Type),
		cfg,
		sink,
	)
	require.NoError(t, err)
	require.NoError(t, rcvr.Start(t.Context(), componenttest.NewNopHost()))
	t.Cleanup(func() {
		assert.NoError(t, rcvr.Shutdown(context.Background()))
	})

	waitTimeout := durationEnv(t, ciscoOSE2EWaitTimeoutEnv, 2*time.Minute)
	require.EventuallyWithT(t, func(tt *assert.CollectT) {
		summary := summarizeCiscoOSE2EMetrics(sink.AllMetrics())
		assert.Positive(tt, sink.DataPointCount())
		assert.True(tt, summaryHasMetricPrefix(summary, "cisco.iosxr."), "expected IOS XR dial-out metrics")
	}, waitTimeout, time.Second)
}

func newCiscoOSE2EConfig(t *testing.T) *Config {
	host := requiredEnvOrSkip(t, ciscoOSE2EHostEnv)
	username := requiredEnvOrSkip(t, ciscoOSE2EUsernameEnv)
	password := os.Getenv(ciscoOSE2EPasswordEnv)
	enablePassword := os.Getenv(ciscoOSE2EEnablePasswordEnv)
	keyFile := os.Getenv(ciscoOSE2EKeyFileEnv)
	if password == "" && keyFile == "" {
		t.Skipf("set %s or %s to run Cisco OS live e2e test", ciscoOSE2EPasswordEnv, ciscoOSE2EKeyFileEnv)
	}

	knownHosts := os.Getenv(ciscoOSE2EKnownHostsEnv)
	insecureSkipVerify := boolEnv(t, ciscoOSE2EInsecureSkipEnv, false)
	if knownHosts == "" && !insecureSkipVerify {
		t.Skipf("set %s or %s=true to run Cisco OS live e2e test", ciscoOSE2EKnownHostsEnv, ciscoOSE2EInsecureSkipEnv)
	}

	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.CollectionInterval = durationEnv(t, ciscoOSE2ECollectionIntEnv, 10*time.Second)
	cfg.Timeout = durationEnv(t, ciscoOSE2ETimeoutEnv, 45*time.Second)
	cfg.Devices = []DeviceConfig{{
		Name: "ciscoos-e2e",
		Host: host,
		Port: intEnv(t, ciscoOSE2EPortEnv, 22),
		Auth: connection.AuthConfig{
			Username:           username,
			Password:           configopaque.String(password),
			EnablePassword:     configopaque.String(enablePassword),
			KeyFile:            keyFile,
			KnownHostsFile:     knownHosts,
			InsecureSkipVerify: insecureSkipVerify,
		},
	}}

	systemCfg := systemscraper.NewFactory().CreateDefaultConfig().(*systemscraper.Config)
	interfacesCfg := interfacesscraper.NewFactory().CreateDefaultConfig().(*interfacesscraper.Config)
	if boolEnv(t, ciscoOSE2EOptionalCommandsEnv, false) {
		enableCiscoOSE2EOptionalCommands(systemCfg, interfacesCfg)
	}
	if boolEnv(t, ciscoOSE2ERouterDataplaneEnv, false) {
		enableCiscoOSE2ERouterDataplaneCommands(systemCfg)
	}
	cfg.Scrapers = map[component.Type]component.Config{
		component.MustNewType("system"):     systemCfg,
		component.MustNewType("interfaces"): interfacesCfg,
	}
	require.NoError(t, cfg.Validate())
	return cfg
}

func newIOSXRDialInE2EConfig(t *testing.T) *Config {
	endpoint := requiredEnvOrSkip(t, ciscoOSE2EIOSXREndpointEnv)
	username := requiredEnvOrSkip(t, ciscoOSE2EIOSXRUsernameEnv)
	password := requiredEnvOrSkip(t, ciscoOSE2EIOSXRPasswordEnv)

	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.IOSXR.Enabled = true
	for _, group := range csvEnvWithDefault(ciscoOSE2EIOSXRGroupsEnv, []string{"interfaces"}) {
		if _, ok := cfg.IOSXR.PathGroups[group]; ok {
			cfg.IOSXR.PathGroups[group] = IOSXRPathGroupConfig{Enabled: true}
		}
	}
	clientCfg := configgrpc.NewDefaultClientConfig()
	clientCfg.Endpoint = endpoint
	clientCfg.TLS.Insecure = boolEnv(t, ciscoOSE2EIOSXRInsecureEnv, false)
	cfg.IOSXR.DialIn.Targets = []IOSXRTargetConfig{{
		ClientConfig: clientCfg,
		Name:         "iosxr-e2e",
		Credentials: IOSXRCredentialsConfig{
			Username: username,
			Password: configopaque.String(password),
		},
		Subscription: IOSXRSubscriptionConfig{
			Mode:              iosXRSubscribeModeOnce,
			StreamMode:        iosXRStreamModeSample,
			SampleInterval:    durationEnv(t, ciscoOSE2ECollectionIntEnv, time.Minute),
			HeartbeatInterval: durationEnv(t, ciscoOSE2ECollectionIntEnv, time.Minute),
			SuppressRedundant: configoptional.Some(true),
		},
	}}
	require.NoError(t, cfg.Validate())
	return cfg
}

func enableCiscoOSE2EOptionalCommands(systemCfg *systemscraper.Config, interfacesCfg *interfacesscraper.Config) {
	systemCfg.ProtocolTraffic.Enabled = true
	systemCfg.ControlPlane.Enabled = true
	systemCfg.ControlPlane.ProcessTopN = 5
	systemCfg.RoutingForwarding.Enabled = true
	systemCfg.RoutingForwarding.VRFs = []string{"default"}
	if vrfs := csvEnv(ciscoOSE2EVRFsEnv); len(vrfs) > 0 {
		systemCfg.RoutingForwarding.VRFs = vrfs
	}
	systemCfg.RoutingForwarding.MaxVRFs = len(systemCfg.RoutingForwarding.VRFs)

	interfacesCfg.Rates.Enabled = true
	interfacesCfg.Counters.Enabled = true
	interfacesCfg.Counters.Include = []string{"*error*", "*drop*", "pause_*"}
	interfacesCfg.Counters.MaxPerInterface = 25
	interfacesCfg.Counters.MaxInterfaces = 16
	interfacesCfg.Counters.Commands.All = true
	interfacesCfg.L2Topology.Enabled = true
	interfacesCfg.L2Topology.Include = []string{"Eth*", "Gi*", "mgmt*", "Lo*", "Vlan*"}
	interfacesCfg.L2Topology.MaxInterfaces = 32
	interfacesCfg.L2Topology.MaxVLANs = 64
	interfacesCfg.Transceiver.Enabled = true
	interfacesCfg.Transceiver.Include = []string{"Eth*", "Te*"}
	interfacesCfg.Transceiver.MaxInterfaces = 16
}

func enableCiscoOSE2ERouterDataplaneCommands(systemCfg *systemscraper.Config) {
	systemCfg.RouterDataplane.Enabled = true
}

type ciscoOSE2EMetricSummary struct {
	metricNames    map[string]struct{}
	hostIPs        map[string]struct{}
	osNames        map[string]struct{}
	interfaceNames map[string]struct{}
	deviceUp       bool
}

func summarizeCiscoOSE2EMetrics(metrics []pmetric.Metrics) ciscoOSE2EMetricSummary {
	summary := ciscoOSE2EMetricSummary{
		metricNames:    map[string]struct{}{},
		hostIPs:        map[string]struct{}{},
		osNames:        map[string]struct{}{},
		interfaceNames: map[string]struct{}{},
	}

	for _, md := range metrics {
		for i := 0; i < md.ResourceMetrics().Len(); i++ {
			rm := md.ResourceMetrics().At(i)
			recordResourceAttribute(summary.hostIPs, rm.Resource().Attributes(), "host.ip")
			recordResourceAttribute(summary.osNames, rm.Resource().Attributes(), "os.name")

			for j := 0; j < rm.ScopeMetrics().Len(); j++ {
				metricsSlice := rm.ScopeMetrics().At(j).Metrics()
				for k := 0; k < metricsSlice.Len(); k++ {
					metric := metricsSlice.At(k)
					summary.metricNames[metric.Name()] = struct{}{}
					visitNumberDataPoints(metric, func(dp pmetric.NumberDataPoint) {
						if interfaceName, ok := dp.Attributes().Get("network.interface.name"); ok {
							summary.interfaceNames[interfaceName.Str()] = struct{}{}
						}
						if metric.Name() == "cisco.device.up" && numberDataPointValue(dp) == 1 {
							summary.deviceUp = true
						}
					})
				}
			}
		}
	}

	return summary
}

func visitNumberDataPoints(metric pmetric.Metric, visit func(pmetric.NumberDataPoint)) {
	switch metric.Type() {
	case pmetric.MetricTypeGauge:
		dps := metric.Gauge().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			visit(dps.At(i))
		}
	case pmetric.MetricTypeSum:
		dps := metric.Sum().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			visit(dps.At(i))
		}
	}
}

func numberDataPointValue(dp pmetric.NumberDataPoint) float64 {
	switch dp.ValueType() {
	case pmetric.NumberDataPointValueTypeInt:
		return float64(dp.IntValue())
	case pmetric.NumberDataPointValueTypeDouble:
		return dp.DoubleValue()
	default:
		return 0
	}
}

func recordResourceAttribute(values map[string]struct{}, attrs pcommon.Map, name string) {
	value, ok := attrs.Get(name)
	if !ok {
		return
	}
	values[value.Str()] = struct{}{}
}

func normalizeCiscoOSE2EInterfaceSet(values map[string]struct{}) map[string]struct{} {
	normalized := make(map[string]struct{}, len(values))
	for value := range values {
		normalized[normalizeCiscoOSE2EInterfaceName(value)] = struct{}{}
	}
	return normalized
}

func normalizeCiscoOSE2EInterfaceName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, replacement := range []struct {
		prefix      string
		replacement string
	}{
		{prefix: "ethernet", replacement: "eth"},
		{prefix: "gigabitethernet", replacement: "gi"},
		{prefix: "tengigabitethernet", replacement: "te"},
		{prefix: "loopback", replacement: "lo"},
		{prefix: "port-channel", replacement: "po"},
	} {
		if strings.HasPrefix(name, replacement.prefix) {
			return replacement.replacement + strings.TrimPrefix(name, replacement.prefix)
		}
	}
	return name
}

func requiredEnvOrSkip(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Skipf("set %s to run Cisco OS live e2e test", name)
	}
	return value
}

func intEnv(t *testing.T, name string, fallback int) int {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	require.NoErrorf(t, err, "invalid integer in %s", name)
	return parsed
}

func boolEnv(t *testing.T, name string, fallback bool) bool {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	require.NoErrorf(t, err, "invalid boolean in %s", name)
	return parsed
}

func durationEnv(t *testing.T, name string, fallback time.Duration) time.Duration {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	require.NoErrorf(t, err, "invalid duration in %s", name)
	return parsed
}

func csvEnv(name string) []string {
	value := os.Getenv(name)
	if value == "" {
		return nil
	}
	fields := strings.Split(value, ",")
	values := make([]string, 0, len(fields))
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}

func csvEnvWithDefault(key string, defaults []string) []string {
	values := csvEnv(key)
	if len(values) == 0 {
		return defaults
	}
	return values
}

func summaryHasMetricPrefix(summary ciscoOSE2EMetricSummary, prefix string) bool {
	for metricName := range summary.metricNames {
		if strings.HasPrefix(metricName, prefix) {
			return true
		}
	}
	return false
}

func setKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	return keys
}
