// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package ciscoosreceiver

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/sdwan"
)

const (
	sdwanE2EEndpointEnv          = "CISCOOS_E2E_SDWAN_ENDPOINT"
	sdwanE2EUsernameEnv          = "CISCOOS_E2E_SDWAN_USERNAME"
	sdwanE2EPasswordEnv          = "CISCOOS_E2E_SDWAN_PASSWORD"
	sdwanE2ESystemIPsEnv         = "CISCOOS_E2E_SDWAN_SYSTEM_IPS"
	sdwanE2EInsecureSkipEnv      = "CISCOOS_E2E_SDWAN_INSECURE_SKIP_VERIFY"
	sdwanE2EOptInGroupsEnv       = "CISCOOS_E2E_SDWAN_OPT_IN_GROUPS"
	sdwanE2ETimeoutEnv           = "CISCOOS_E2E_SDWAN_TIMEOUT"
	sdwanE2EMaxResultsEnv        = "CISCOOS_E2E_SDWAN_MAX_RESULTS"
	sdwanE2EEventLookbackEnv     = "CISCOOS_E2E_SDWAN_EVENT_LOOKBACK"
	sdwanE2EDefaultTimeout       = 2 * time.Minute
	sdwanE2EMaxAllowedTimeout    = 10 * time.Minute
	sdwanE2EDefaultEventLookback = time.Hour
	sdwanE2EMaxEventLookback     = 24 * time.Hour
	sdwanE2EDefaultMaxResults    = 100
	sdwanE2EMaxAllowedMaxResults = 1000
)

// TestE2ELiveSDWAN performs exactly one bounded metrics scrape and one bounded
// logs scrape against a live Catalyst SD-WAN Manager. Core collection groups
// are enabled by default; potentially expensive or feature-dependent groups
// require explicit selection through CISCOOS_E2E_SDWAN_OPT_IN_GROUPS.
func TestE2ELiveSDWAN(t *testing.T) {
	cfg, enabledOptInGroups := newSDWANE2EConfig(t)

	metricsReceiver, err := newSDWANMetricsReceiver(
		receivertest.NewNopSettings(metadata.Type),
		cfg,
		consumertest.NewNop(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, metricsReceiver.Shutdown(context.Background())) })

	metricsCtx, cancelMetrics := context.WithTimeout(t.Context(), cfg.Timeout)
	md, metricsErr := metricsReceiver.scrape(metricsCtx)
	cancelMetrics()

	metricStats := metricsReceiver.requestStats()
	metricOperations := sdwanE2EExpectedMetricOperations(cfg.SDWAN)
	requireSDWANE2EOperationsSucceeded(t, "metrics", metricStats, metricOperations)
	require.NoError(t, metricsErr)
	require.True(t, intMetricValueExists(md, "sdwan.manager.up", 1), "every Manager health operation succeeded, but sdwan.manager.up=1 was not emitted")
	require.True(t, intMetricValueExists(md, "sdwan.scrape.partial_success", 0), "every configured SD-WAN endpoint family must complete without skips or failures")
	require.False(t, sdwanE2EHasMetric(md, "sdwan.api.request.errors"), "successful validation must not emit sdwan.api.request.errors")
	require.False(t, sdwanE2EHasMetric(md, "sdwan.service.unavailable"), "successful validation must not report unavailable services")
	require.False(t, sdwanE2EHasMetric(md, "sdwan.service.skipped"), "successful validation must not skip configured services")
	require.True(t, sdwanE2EHasPositiveNumber(md, "sdwan.inventory.device.count"), "targeted inventory must contain at least one device")
	require.True(t, sdwanE2EHasPositiveNumber(md, "sdwan.scrape.last_success"), "the one-shot full scrape must advance sdwan.scrape.last_success")

	durationOperations := sdwanE2EAPIDurationOperations(md)
	for _, operation := range metricOperations {
		require.NotZero(t, durationOperations[operation], "sdwan.api.request.duration must describe successful operation %s", operation)
	}
	for targetIndex, systemIP := range cfg.SDWAN.Targets.SystemIPs {
		require.Positive(t, sdwanE2ETargetDataPointCount(md, systemIP), "configured inventory target %d must contribute telemetry datapoints", targetIndex)
		require.True(t, sdwanE2ETargetHasMetric(md, systemIP, "sdwan.resource.info"), "configured inventory target %d must emit sdwan.resource.info", targetIndex)
	}

	metricInventory := sdwanE2EMetricInventory(md)
	t.Logf("SD-WAN enabled opt-in groups (%d): %s", len(enabledOptInGroups), sdwanE2EFormatList(enabledOptInGroups))
	t.Logf("SD-WAN metric inventory (%d families): %s", len(metricInventory), sdwanE2EFormatInventory(metricInventory))

	logsReceiver, err := newSDWANLogsReceiver(
		receivertest.NewNopSettings(metadata.Type),
		cfg,
		consumertest.NewNop(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, logsReceiver.Shutdown(context.Background())) })

	var (
		logStatsMu sync.Mutex
		logStats   []sdwan.RequestStat
	)
	logsReceiver.client.OnRequest = func(stat sdwan.RequestStat) {
		logStatsMu.Lock()
		logStats = append(logStats, stat)
		logStatsMu.Unlock()
	}
	logsCtx, cancelLogs := context.WithTimeout(t.Context(), cfg.Timeout)
	ld, logsErr := logsReceiver.scrape(logsCtx)
	cancelLogs()

	logStatsMu.Lock()
	logRequestStats := append([]sdwan.RequestStat(nil), logStats...)
	logStatsMu.Unlock()
	requireSDWANE2EOperationsSucceeded(t, "logs", logRequestStats, sdwanE2EExpectedLogOperations(cfg.SDWAN))
	require.NoError(t, logsErr)

	logInventory := sdwanE2ELogInventory(t, ld)
	t.Logf("SD-WAN log inventory (%d event families, %d records): %s", len(logInventory), ld.LogRecordCount(), sdwanE2EFormatInventory(logInventory))
}

func newSDWANE2EConfig(t *testing.T) (*Config, []string) {
	t.Helper()
	endpoint := strings.TrimSpace(requiredEnvOrSkip(t, sdwanE2EEndpointEnv))
	username := strings.TrimSpace(requiredEnvOrSkip(t, sdwanE2EUsernameEnv))
	password := requiredEnvOrSkip(t, sdwanE2EPasswordEnv)
	requiredEnvOrSkip(t, sdwanE2ESystemIPsEnv)
	systemIPs := sdwanE2EUniqueValues(csvEnv(sdwanE2ESystemIPsEnv))
	require.NotEmpty(t, endpoint, "%s cannot contain only whitespace", sdwanE2EEndpointEnv)
	require.NotEmpty(t, username, "%s cannot contain only whitespace", sdwanE2EUsernameEnv)
	require.NotEmpty(t, systemIPs, "%s must contain at least one system IP", sdwanE2ESystemIPsEnv)

	timeout := durationEnv(t, sdwanE2ETimeoutEnv, sdwanE2EDefaultTimeout)
	require.Positive(t, timeout, "%s must be positive", sdwanE2ETimeoutEnv)
	require.LessOrEqual(t, timeout, sdwanE2EMaxAllowedTimeout, "%s must be at most %s", sdwanE2ETimeoutEnv, sdwanE2EMaxAllowedTimeout)
	lookback := durationEnv(t, sdwanE2EEventLookbackEnv, sdwanE2EDefaultEventLookback)
	require.Positive(t, lookback, "%s must be positive", sdwanE2EEventLookbackEnv)
	require.LessOrEqual(t, lookback, sdwanE2EMaxEventLookback, "%s must be at most %s", sdwanE2EEventLookbackEnv, sdwanE2EMaxEventLookback)
	maxResults := intEnv(t, sdwanE2EMaxResultsEnv, sdwanE2EDefaultMaxResults)
	require.Positive(t, maxResults, "%s must be positive", sdwanE2EMaxResultsEnv)
	require.LessOrEqual(t, maxResults, sdwanE2EMaxAllowedMaxResults, "%s must be at most %d", sdwanE2EMaxResultsEnv, sdwanE2EMaxAllowedMaxResults)

	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.Timeout = timeout
	cfg.CollectionInterval = time.Hour
	cfg.SDWAN = defaultSDWANConfig()
	cfg.SDWAN.Enabled = true
	cfg.SDWAN.Endpoint = endpoint
	cfg.SDWAN.Auth.Mode = "auto"
	cfg.SDWAN.Auth.Username = username
	cfg.SDWAN.Auth.Password = configopaque.String(password)
	cfg.SDWAN.InsecureSkipVerify = boolEnv(t, sdwanE2EInsecureSkipEnv, false)
	cfg.SDWAN.PageSize = maxResults
	cfg.SDWAN.MaxRetries = 0
	cfg.SDWAN.EventLookback = lookback
	cfg.SDWAN.Targets.SystemIPs = systemIPs

	configureSDWANE2ECoreGroups(&cfg.SDWAN, maxResults)
	enabledOptInGroups := configureSDWANE2EOptInGroups(t, &cfg.SDWAN, maxResults)
	require.NoError(t, cfg.Validate())
	return cfg, enabledOptInGroups
}

func configureSDWANE2ECoreGroups(cfg *SDWANConfig, maxResults int) {
	group := defaultSDWANGroupConfig(true, maxResults)
	cfg.Manager = group
	cfg.Inventory = group
	cfg.ControlPlane = group
	cfg.BFD = group
	cfg.AppRoute = group
	cfg.Interfaces = group
	cfg.Alarms = group
	cfg.Events = group
	cfg.Audit = group
}

func configureSDWANE2EOptInGroups(t *testing.T, cfg *SDWANConfig, maxResults int) []string {
	t.Helper()
	available := make([]string, 0, len(sdwanOptInGroups(*cfg)))
	for _, group := range sdwanOptInGroups(*cfg) {
		available = append(available, group.name)
		require.True(t, setSDWANE2EOptInGroup(cfg, group.name, false, maxResults), "unhandled SD-WAN opt-in group %s", group.name)
	}
	sort.Strings(available)

	requested := make(map[string]struct{})
	all := false
	for _, rawName := range csvEnv(sdwanE2EOptInGroupsEnv) {
		name := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(rawName)), "-", "_")
		if name == "all" {
			all = true
			continue
		}
		if !setSDWANE2EOptInGroup(cfg, name, false, maxResults) {
			require.FailNowf(t, "unknown SD-WAN opt-in group", "%s contains %q; valid names are all,%s", sdwanE2EOptInGroupsEnv, rawName, strings.Join(available, ","))
		}
		requested[name] = struct{}{}
	}
	if all {
		for _, name := range available {
			requested[name] = struct{}{}
		}
	}

	enabled := make([]string, 0, len(requested))
	for name := range requested {
		require.True(t, setSDWANE2EOptInGroup(cfg, name, true, maxResults), "unhandled SD-WAN opt-in group %s", name)
		enabled = append(enabled, name)
	}
	sort.Strings(enabled)
	return enabled
}

func setSDWANE2EOptInGroup(cfg *SDWANConfig, name string, enabled bool, maxResults int) bool {
	group := defaultSDWANGroupConfig(enabled, maxResults)
	switch name {
	case "realtime_details":
		cfg.RealtimeDetails = group
	case "tunnels":
		cfg.Tunnels = group
	case "flows":
		cfg.Flows = group
	case "policy_qos":
		cfg.PolicyQoS = group
	case "security":
		cfg.Security = group
	case "appqoe":
		cfg.AppQoE = group
	case "cloud_onramp":
		cfg.CloudOnRamp = group
	case "nwpi":
		cfg.NWPI = group
	case "underlay":
		cfg.Underlay = group
	case "cellular":
		cfg.Cellular = group
	case "hardware_energy":
		cfg.HardwareEnergy = group
	case "routing_services":
		cfg.RoutingServices = group
	case "branch_services":
		cfg.BranchServices = group
	case "lifecycle_compliance":
		cfg.LifecycleCompliance = group
	case "thousandeyes":
		cfg.ThousandEyes = group
	case "management_security":
		cfg.ManagementSecurity = group
	default:
		return false
	}
	return true
}

func sdwanE2EExpectedMetricOperations(cfg SDWANConfig) []string {
	operations := make([]string, 0, 32)
	if cfg.Manager.Enabled {
		operations = append(operations, "manager.cluster_health", "manager.server_info", "manager.settings")
	}
	if cfg.Inventory.Enabled {
		operations = append(operations, "inventory.devices")
	}
	for _, group := range []struct {
		enabled bool
		specs   []sdwanEndpointSpec
	}{
		{cfg.ControlPlane.Enabled, sdwanControlPlaneSpecs()},
		{cfg.BFD.Enabled, sdwanBFDSpecs()},
		{cfg.AppRoute.Enabled, sdwanAppRouteSpecs()},
		{cfg.Interfaces.Enabled, sdwanInterfaceSpecs()},
	} {
		if !group.enabled {
			continue
		}
		for _, spec := range group.specs {
			operations = append(operations, spec.operation)
		}
	}
	if cfg.Alarms.Enabled {
		operations = append(operations, "events.alarms")
	}
	if cfg.Events.Enabled {
		operations = append(operations, "events.events")
	}
	if cfg.Audit.Enabled {
		operations = append(operations, "events.audit")
	}
	for _, group := range sdwanOptInGroups(cfg) {
		if !group.config.Enabled {
			continue
		}
		for _, spec := range group.specs {
			operations = append(operations, spec.operation)
		}
	}
	return sdwanE2EUniqueValues(operations)
}

func sdwanE2EExpectedLogOperations(cfg SDWANConfig) []string {
	operations := []string{"logs.filter_inventory"}
	if cfg.Alarms.Enabled {
		operations = append(operations, "logs.alarms")
	}
	if cfg.Events.Enabled {
		operations = append(operations, "logs.events")
	}
	if cfg.Audit.Enabled {
		operations = append(operations, "logs.audit")
	}
	return operations
}

func requireSDWANE2EOperationsSucceeded(t *testing.T, signal string, stats []sdwan.RequestStat, expected []string) {
	t.Helper()
	successes := make(map[string]int)
	failures := make(map[string]int)
	observed := make(map[string]struct{})
	for _, stat := range stats {
		observed[stat.Operation] = struct{}{}
		if stat.Outcome == "success" {
			successes[stat.Operation]++
			continue
		}
		status := "none"
		if stat.StatusCode > 0 {
			status = strconv.Itoa(stat.StatusCode)
		}
		key := strings.Join([]string{
			stat.Operation,
			strings.ToUpper(stat.Method),
			stat.Path,
			"outcome=" + firstNonEmpty(stat.Outcome, "unknown"),
			"status=" + status,
		}, " ")
		failures[key]++
	}

	expectedSet := make(map[string]struct{}, len(expected))
	for _, operation := range expected {
		expectedSet[operation] = struct{}{}
	}
	unexpected := make([]string, 0)
	for operation := range observed {
		if _, ok := expectedSet[operation]; !ok {
			unexpected = append(unexpected, operation)
		}
	}
	sort.Strings(unexpected)

	t.Logf("SD-WAN %s successful operation inventory (%d operations): %s", signal, len(successes), sdwanE2EFormatInventory(successes))
	if len(failures) > 0 {
		t.Logf("SD-WAN %s failed request inventory (%d request variants): %s", signal, len(failures), sdwanE2EFormatInventory(failures))
	}
	require.Empty(t, failures, "%s scrape contained failed endpoint requests; the inventory intentionally excludes credentials, query values, and response bodies", signal)
	require.Empty(t, unexpected, "%s scrape used unexpected fallback or unconfigured operations: %s", signal, strings.Join(unexpected, ", "))
	for _, operation := range expected {
		require.NotZero(t, successes[operation], "%s endpoint operation %s must succeed", signal, operation)
	}
}

func sdwanE2EMetricInventory(md pmetric.Metrics) map[string]int {
	counts := make(map[string]int)
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			metrics := rm.ScopeMetrics().At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				metric := metrics.At(k)
				counts[metric.Name()] += sdwanE2EMetricDataPointCount(metric)
			}
		}
	}
	return counts
}

func sdwanE2EMetricDataPointCount(metric pmetric.Metric) int {
	switch metric.Type() {
	case pmetric.MetricTypeGauge:
		return metric.Gauge().DataPoints().Len()
	case pmetric.MetricTypeSum:
		return metric.Sum().DataPoints().Len()
	case pmetric.MetricTypeHistogram:
		return metric.Histogram().DataPoints().Len()
	case pmetric.MetricTypeExponentialHistogram:
		return metric.ExponentialHistogram().DataPoints().Len()
	case pmetric.MetricTypeSummary:
		return metric.Summary().DataPoints().Len()
	case pmetric.MetricTypeEmpty:
		return 0
	}
	return 0
}

func sdwanE2EAPIDurationOperations(md pmetric.Metrics) map[string]int {
	operations := make(map[string]int)
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			metrics := rm.ScopeMetrics().At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				metric := metrics.At(k)
				if metric.Name() != "sdwan.api.request.duration" || metric.Type() != pmetric.MetricTypeGauge {
					continue
				}
				points := metric.Gauge().DataPoints()
				for l := 0; l < points.Len(); l++ {
					attrs := points.At(l).Attributes()
					operation, operationOK := attrs.Get("sdwan.api.operation")
					outcome, outcomeOK := attrs.Get("sdwan.api.outcome")
					if operationOK && outcomeOK && outcome.AsString() == "success" {
						operations[operation.AsString()]++
					}
				}
			}
		}
	}
	return operations
}

func sdwanE2ETargetDataPointCount(md pmetric.Metrics, systemIP string) int {
	count := 0
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		if !sdwanE2EAttributeEquals(rm.Resource().Attributes(), "sdwan.system_ip", systemIP) {
			continue
		}
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			metrics := rm.ScopeMetrics().At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				count += sdwanE2EMetricDataPointCount(metrics.At(k))
			}
		}
	}
	return count
}

func sdwanE2ETargetHasMetric(md pmetric.Metrics, systemIP, metricName string) bool {
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		if !sdwanE2EAttributeEquals(rm.Resource().Attributes(), "sdwan.system_ip", systemIP) {
			continue
		}
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			metrics := rm.ScopeMetrics().At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				metric := metrics.At(k)
				if metric.Name() == metricName && sdwanE2EMetricDataPointCount(metric) > 0 {
					return true
				}
			}
		}
	}
	return false
}

func sdwanE2ELogInventory(t *testing.T, ld plog.Logs) map[string]int {
	t.Helper()
	counts := make(map[string]int)
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		rl := ld.ResourceLogs().At(i)
		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			records := rl.ScopeLogs().At(j).LogRecords()
			for k := 0; k < records.Len(); k++ {
				record := records.At(k)
				require.True(t, sdwanE2EAttributeEquals(record.Attributes(), "event.domain", "sdwan"), "SD-WAN log records must set event.domain=sdwan")
				eventNameValue, ok := record.Attributes().Get("event.name")
				require.True(t, ok, "SD-WAN log records must set event.name")
				eventName := eventNameValue.AsString()
				require.Contains(t, []string{"alarms", "events", "audit"}, eventName, "unexpected SD-WAN log event family")
				require.Equal(t, pcommon.ValueTypeMap, record.Body().Type(), "SD-WAN log record bodies must preserve the source object as a map")
				require.Positive(t, record.Body().Map().Len(), "SD-WAN log record bodies must not be empty")
				counts[eventName]++
			}
		}
	}
	return counts
}

func sdwanE2EHasMetric(md pmetric.Metrics, name string) bool {
	return metricDataPointCount(md, name) > 0
}

func sdwanE2EHasPositiveNumber(md pmetric.Metrics, name string) bool {
	found := false
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			metrics := rm.ScopeMetrics().At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				metric := metrics.At(k)
				if metric.Name() != name {
					continue
				}
				visitNumberDataPoints(metric, func(point pmetric.NumberDataPoint) {
					if numberDataPointValue(point) > 0 {
						found = true
					}
				})
			}
		}
	}
	return found
}

func sdwanE2EAttributeEquals(attrs pcommon.Map, key, expected string) bool {
	value, ok := attrs.Get(key)
	return ok && value.AsString() == expected
}

func sdwanE2EUniqueValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	sort.Strings(unique)
	return unique
}

func sdwanE2EFormatInventory(counts map[string]int) string {
	entries := make([]string, 0, len(counts))
	for key, count := range counts {
		entries = append(entries, key+"="+strconv.Itoa(count))
	}
	sort.Strings(entries)
	if len(entries) == 0 {
		return "<empty>"
	}
	return strings.Join(entries, ", ")
}

func sdwanE2EFormatList(values []string) string {
	if len(values) == 0 {
		return "<none>"
	}
	return strings.Join(values, ", ")
}
