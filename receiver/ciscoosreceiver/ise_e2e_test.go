// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package ciscoosreceiver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
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
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/ise"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

const (
	iseE2EEndpointEnv          = "CISCOOS_E2E_ISE_ENDPOINT"
	iseE2EUsernameEnv          = "CISCOOS_E2E_ISE_USERNAME"
	iseE2EPasswordEnv          = "CISCOOS_E2E_ISE_PASSWORD" //nolint:gosec // Environment variable name, not a credential.
	iseE2EGroupsEnv            = "CISCOOS_E2E_ISE_GROUPS"
	iseE2ECAFileEnv            = "CISCOOS_E2E_ISE_CA_FILE"
	iseE2EServerNameEnv        = "CISCOOS_E2E_ISE_SERVER_NAME"
	iseE2EInsecureSkipEnv      = "CISCOOS_E2E_ISE_INSECURE_SKIP_VERIFY"
	iseE2ETimeoutEnv           = "CISCOOS_E2E_ISE_TIMEOUT"
	iseE2EOperationsEnv        = "CISCOOS_E2E_ISE_OPERATIONS"
	iseE2EPageSizeEnv          = "CISCOOS_E2E_ISE_PAGE_SIZE"
	iseE2EMaxResultsEnv        = "CISCOOS_E2E_ISE_MAX_RESULTS"
	iseE2ERequireNonEmptyEnv   = "CISCOOS_E2E_ISE_REQUIRE_NONEMPTY"
	iseE2ERequireCSRFEnv       = "CISCOOS_E2E_ISE_REQUIRE_CSRF"
	iseE2EEventLookbackEnv     = "CISCOOS_E2E_ISE_EVENT_LOOKBACK"
	iseE2ESessionLookbackEnv   = "CISCOOS_E2E_ISE_SESSION_LOOKBACK"
	iseE2EDefaultTimeout       = 2 * time.Minute
	iseE2EMaxAllowedTimeout    = 10 * time.Minute
	iseE2EDefaultMaxResults    = 100
	iseE2EMaxAllowedMaxResults = 5000
	iseE2EDefaultEventLookback = time.Hour
	iseE2EMaxEventLookback     = 24 * time.Hour
	iseE2EDefaultSessionWindow = 15 * time.Minute
	iseE2EMaxSessionWindow     = 24 * time.Hour
	iseE2EShutdownTimeout      = 5 * time.Second
)

type iseE2EOptions struct {
	operations      map[string]struct{}
	requireNonEmpty bool
	requireCSRF     bool
}

// TestE2ELiveISE performs exactly one bounded metrics scrape and one bounded
// logs scrape against a live Cisco ISE deployment. All REST groups start
// disabled and must be selected explicitly with CISCOOS_E2E_ISE_GROUPS.
// Credentials are read only from the environment. The test never logs request
// paths, query values, response bodies, credentials, or object attributes.
//
// pxGrid and Data Connect are intentionally outside this REST harness because
// each requires independent credentials and trust configuration.
func TestE2ELiveISE(t *testing.T) {
	cfg, selectedGroups, options := newISEE2EConfig(t)
	expectedMetricOperations := iseE2EExpectedMetricOperations(cfg.ISE, options.operations)
	dynamicOperations := iseE2EAllowedDynamicOperations(cfg.ISE, options.operations)

	metricsReceiver, err := newISEMetricsReceiver(
		receivertest.NewNopSettings(metadata.Type),
		cfg,
		consumertest.NewNop(),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), iseE2EShutdownTimeout)
		defer cancel()
		assert.NoError(t, metricsReceiver.Shutdown(shutdownCtx))
	})

	metricsReceiver.success.mu.Lock()
	previousLastSuccess := metricsReceiver.success.lastSuccess
	metricsReceiver.success.mu.Unlock()

	metricsCtx, cancelMetrics := context.WithTimeout(t.Context(), cfg.Timeout)
	md, metricResultCounts, metricsErr := scrapeISEE2EMetrics(metricsCtx, metricsReceiver, options.operations)
	cancelMetrics()

	metricsReceiver.statsMu.Lock()
	metricRequestStats := append([]ise.RequestStat(nil), metricsReceiver.stats...)
	metricsReceiver.statsMu.Unlock()
	if len(options.operations) > 0 {
		t.Logf("ISE metrics result inventory (%d operations): %s", len(metricResultCounts), iseE2EFormatInventory(metricResultCounts))
	}
	requireISEE2EOperationsSucceeded(
		t,
		"metrics",
		metricRequestStats,
		expectedMetricOperations,
		dynamicOperations,
	)
	if options.requireNonEmpty {
		requireISEE2ENonEmptyResults(t, metricResultCounts, expectedMetricOperations)
	}
	if options.requireCSRF {
		requireISEE2ECSRFProtected(t, "metrics", metricRequestStats, expectedMetricOperations)
	}
	if metricsErr != nil {
		require.FailNowf(t, "ISE metrics scrape failed", "scrape returned error type %T; request details are intentionally omitted", metricsErr)
	}

	metricsReceiver.success.mu.Lock()
	currentLastSuccess := metricsReceiver.success.lastSuccess
	metricsReceiver.success.mu.Unlock()
	require.True(t, currentLastSuccess.After(previousLastSuccess), "a fully successful one-shot scrape must advance ISE last-success state")

	requireISEE2EIntGaugeValue(t, md, "ise.controller.up", 1)
	requireISEE2EIntGaugeValue(t, md, "ise.scrape.partial_success", 0)
	requireISEE2EIntGaugeValue(t, md, "ise.scrape.last_success", currentLastSuccess.Unix())

	metricInventory := iseE2EMetricInventory(md)
	for _, name := range []string{
		"ise.api.endpoint.error",
		"ise.api.rate_limited",
		"ise.api.request.errors",
		"ise.dataconnect.query.errors",
		"ise.service.skipped",
		"ise.service.unavailable",
	} {
		require.Zero(t, metricInventory[name], "strict ISE validation must not emit %s", name)
	}
	t.Logf("ISE selected REST groups (%d): %s", len(selectedGroups), strings.Join(selectedGroups, ", "))
	if len(options.operations) > 0 {
		t.Logf("ISE selected operations (%d): %s", len(expectedMetricOperations), strings.Join(expectedMetricOperations, ", "))
	}
	t.Logf("ISE metric inventory (%d families): %s", len(metricInventory), iseE2EFormatInventory(metricInventory))

	logsReceiver, err := newISELogsReceiver(
		receivertest.NewNopSettings(metadata.Type),
		cfg,
		consumertest.NewNop(),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), iseE2EShutdownTimeout)
		defer cancel()
		assert.NoError(t, logsReceiver.Shutdown(shutdownCtx))
	})

	var (
		logStatsMu sync.Mutex
		logStats   []ise.RequestStat
	)
	logsReceiver.client.OnRequest = func(stat ise.RequestStat) {
		logStatsMu.Lock()
		logStats = append(logStats, stat)
		logStatsMu.Unlock()
	}

	logsCtx, cancelLogs := context.WithTimeout(t.Context(), cfg.Timeout)
	ld, logResultCounts, logsErr := scrapeISEE2ELogs(logsCtx, logsReceiver, options.operations)
	cancelLogs()

	logStatsMu.Lock()
	logRequestStats := append([]ise.RequestStat(nil), logStats...)
	logStatsMu.Unlock()
	expectedLogOperations := iseE2EExpectedLogOperations(cfg.ISE, options.operations)
	if len(options.operations) > 0 {
		t.Logf("ISE logs result inventory (%d operations): %s", len(logResultCounts), iseE2EFormatInventory(logResultCounts))
	}
	requireISEE2EOperationsSucceeded(t, "logs", logRequestStats, expectedLogOperations, dynamicOperations)
	if options.requireCSRF {
		requireISEE2ECSRFProtected(t, "logs", logRequestStats, expectedLogOperations)
	}
	if logsErr != nil {
		require.FailNowf(t, "ISE logs scrape failed", "scrape returned error type %T; request details are intentionally omitted", logsErr)
	}

	logInventory := iseE2ELogInventory(t, ld, expectedLogOperations, dynamicOperations)
	t.Logf("ISE log inventory (%d event families, %d records): %s", len(logInventory), ld.LogRecordCount(), iseE2EFormatInventory(logInventory))
}

func TestISEE2EGroupSelectionIsExplicit(t *testing.T) {
	t.Setenv(iseE2EGroupsEnv, "network-devices,session-details,sessions")
	cfg := defaultISEConfig()
	cfg.PxGrid.Enabled = true
	cfg.DataConnect.Enabled = true
	selected := configureISEE2EGroups(t, &cfg, 17)
	require.Equal(t, []string{"network_devices", "session_details", "sessions"}, selected)
	assert.False(t, cfg.PxGrid.Enabled, "the REST-only E2E selector must disable pxGrid")
	assert.False(t, cfg.DataConnect.Enabled, "the REST-only E2E selector must disable Data Connect")

	selectedSet := map[string]struct{}{
		"network_devices": {},
		"session_details": {},
		"sessions":        {},
	}
	for name, group := range cfg.groups() {
		_, expectedEnabled := selectedSet[name]
		assert.Equal(t, expectedEnabled, group.Enabled, "group %s has unexpected enabled state", name)
		assert.Equal(t, 17, group.MaxResults, "group %s must use the bounded E2E result limit", name)
	}
}

func TestISEE2EOperationSelectionIsExact(t *testing.T) {
	t.Setenv(iseE2EGroupsEnv, "network-devices,session-details")
	t.Setenv(iseE2EOperationsEnv, "ers.network_devices,mnt.session.active_list")
	t.Setenv(iseE2ERequireNonEmptyEnv, "true")
	t.Setenv(iseE2ERequireCSRFEnv, "true")
	cfg := defaultISEConfig()
	configureISEE2EGroups(t, &cfg, 17)
	options := newISEE2EOptions(t, cfg)

	require.Equal(t, map[string]struct{}{
		"ers.network_devices":     {},
		"mnt.session.active_list": {},
	}, options.operations)
	assert.True(t, options.requireNonEmpty)
	assert.True(t, options.requireCSRF)
	assert.Equal(t,
		[]string{"ers.network_devices", "mnt.session.active_list"},
		iseE2EExpectedMetricOperations(cfg, options.operations),
	)
	assert.Equal(t,
		[]string{"mnt.session.active_list"},
		iseE2EExpectedLogOperations(cfg, options.operations),
	)
	assert.Equal(t, map[string]struct{}{"ers.csrf_token": {}}, iseE2EAllowedDynamicOperations(cfg, options.operations))
}

func TestISEE2EPageSizeIsIndependentFromResultLimit(t *testing.T) {
	t.Setenv(iseE2EPageSizeEnv, "37")
	assert.Equal(t, 37, iseE2EPageSize(t, 17))
}

func TestISEE2EExactOperationScrapeIsFilteredAndCounted(t *testing.T) {
	var requestedPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.Path)
		if r.URL.Path != "/admin/API/mnt/Session/ActiveCount" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`<sessionCount><count>11</count></sessionCount>`))
	}))
	defer server.Close()

	cfg := createDefaultConfig().(*Config)
	cfg.ISE.Enabled = true
	cfg.ISE.Endpoint = server.URL
	cfg.ISE.Auth.Username = "admin"
	cfg.ISE.Auth.Password = configopaque.String("password")
	selected := map[string]struct{}{"mnt.session.active_count": {}}
	receiver, err := newISEMetricsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)

	md, counts, err := scrapeISEE2EMetrics(t.Context(), receiver, selected)
	require.NoError(t, err)
	assert.Equal(t, []string{"/admin/API/mnt/Session/ActiveCount"}, requestedPaths)
	assert.Equal(t, map[string]int{"mnt.session.active_count": 1}, counts)
	requireISEE2ENonEmptyResults(t, counts, []string{"mnt.session.active_count"})
	requireISEE2EOperationsSucceeded(
		t,
		"metrics",
		append([]ise.RequestStat(nil), receiver.stats...),
		[]string{"mnt.session.active_count"},
		nil,
	)
	requireISEE2EIntGaugeValue(t, md, "ise.controller.up", 1)
	requireISEE2EIntGaugeValue(t, md, "ise.scrape.partial_success", 0)
}

func TestISEE2ECSRFInventoryContainsOnlyOperationAndBooleanCounts(t *testing.T) {
	stats := []ise.RequestStat{
		{Operation: "ers.csrf_token", CSRFProtected: false},
		{Operation: "ers.network_devices", CSRFProtected: true},
		{Operation: "mnt.session.active_count", CSRFProtected: false},
	}
	requireISEE2ECSRFProtected(t, "metrics", stats, []string{"ers.network_devices"})
	assert.Equal(t, map[string]int{
		"ers.csrf_token csrf_protected=false":     1,
		"ers.network_devices csrf_protected=true": 1,
	}, iseE2ECSRFInventory(stats))
}

func newISEE2EConfig(t *testing.T) (*Config, []string, iseE2EOptions) {
	t.Helper()
	endpoint := strings.TrimSpace(requiredEnvOrSkip(t, iseE2EEndpointEnv))
	username := strings.TrimSpace(requiredEnvOrSkip(t, iseE2EUsernameEnv))
	password := requiredEnvOrSkip(t, iseE2EPasswordEnv)
	requiredEnvOrSkip(t, iseE2EGroupsEnv)
	require.NotEmpty(t, endpoint, "%s cannot contain only whitespace", iseE2EEndpointEnv)
	require.NotEmpty(t, username, "%s cannot contain only whitespace", iseE2EUsernameEnv)
	require.NotEmpty(t, password, "%s cannot be empty", iseE2EPasswordEnv)

	timeout := durationEnv(t, iseE2ETimeoutEnv, iseE2EDefaultTimeout)
	require.Positive(t, timeout, "%s must be positive", iseE2ETimeoutEnv)
	require.LessOrEqual(t, timeout, iseE2EMaxAllowedTimeout, "%s must be at most %s", iseE2ETimeoutEnv, iseE2EMaxAllowedTimeout)
	maxResults := intEnv(t, iseE2EMaxResultsEnv, iseE2EDefaultMaxResults)
	require.Positive(t, maxResults, "%s must be positive", iseE2EMaxResultsEnv)
	require.LessOrEqual(t, maxResults, iseE2EMaxAllowedMaxResults, "%s must be at most %d", iseE2EMaxResultsEnv, iseE2EMaxAllowedMaxResults)
	pageSize := iseE2EPageSize(t, maxResults)
	eventLookback := durationEnv(t, iseE2EEventLookbackEnv, iseE2EDefaultEventLookback)
	require.Positive(t, eventLookback, "%s must be positive", iseE2EEventLookbackEnv)
	require.LessOrEqual(t, eventLookback, iseE2EMaxEventLookback, "%s must be at most %s", iseE2EEventLookbackEnv, iseE2EMaxEventLookback)
	sessionLookback := durationEnv(t, iseE2ESessionLookbackEnv, iseE2EDefaultSessionWindow)
	require.Positive(t, sessionLookback, "%s must be positive", iseE2ESessionLookbackEnv)
	require.LessOrEqual(t, sessionLookback, iseE2EMaxSessionWindow, "%s must be at most %s", iseE2ESessionLookbackEnv, iseE2EMaxSessionWindow)

	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.Timeout = timeout
	cfg.CollectionInterval = time.Hour
	cfg.ISE = defaultISEConfig()
	cfg.ISE.Enabled = true
	cfg.ISE.Endpoint = endpoint
	cfg.ISE.Auth.Username = username
	cfg.ISE.Auth.Password = configopaque.String(password)
	cfg.ISE.CAFile = strings.TrimSpace(os.Getenv(iseE2ECAFileEnv))
	cfg.ISE.ServerName = strings.TrimSpace(os.Getenv(iseE2EServerNameEnv))
	cfg.ISE.InsecureSkipVerify = boolEnv(t, iseE2EInsecureSkipEnv, false)
	cfg.ISE.PageSize = pageSize
	cfg.ISE.MaxRetries = 0
	cfg.ISE.EventLookback = eventLookback
	cfg.ISE.SessionLookback = sessionLookback
	cfg.ISE.MaxResults = maxResults

	selectedGroups := configureISEE2EGroups(t, &cfg.ISE, maxResults)
	options := newISEE2EOptions(t, cfg.ISE)
	require.NoError(t, cfg.Validate())
	return cfg, selectedGroups, options
}

func iseE2EPageSize(t *testing.T, maxResults int) int {
	t.Helper()
	pageSize := intEnv(t, iseE2EPageSizeEnv, min(maxResults, maxISEERSPageSize))
	require.Positive(t, pageSize, "%s must be positive", iseE2EPageSizeEnv)
	require.LessOrEqual(t, pageSize, maxISEERSPageSize, "%s must be at most %d", iseE2EPageSizeEnv, maxISEERSPageSize)
	return pageSize
}

func newISEE2EOptions(t *testing.T, cfg ISEConfig) iseE2EOptions {
	t.Helper()
	options := iseE2EOptions{
		operations:      configureISEE2EOperations(t, cfg),
		requireNonEmpty: boolEnv(t, iseE2ERequireNonEmptyEnv, false),
		requireCSRF:     boolEnv(t, iseE2ERequireCSRFEnv, false),
	}
	if options.requireNonEmpty || options.requireCSRF {
		require.NotEmpty(t, options.operations, "%s and %s require an explicit %s allowlist", iseE2ERequireNonEmptyEnv, iseE2ERequireCSRFEnv, iseE2EOperationsEnv)
	}
	if options.requireCSRF {
		hasERSOperation := false
		for operation := range options.operations {
			if strings.HasPrefix(operation, "ers.") {
				hasERSOperation = true
				break
			}
		}
		require.True(t, hasERSOperation, "%s requires at least one selected ers.* operation", iseE2ERequireCSRFEnv)
	}
	return options
}

func configureISEE2EOperations(t *testing.T, cfg ISEConfig) map[string]struct{} {
	t.Helper()
	rawSelection := strings.TrimSpace(os.Getenv(iseE2EOperationsEnv))
	if rawSelection == "" {
		return nil
	}
	requestedNames := csvEnv(iseE2EOperationsEnv)
	require.NotEmpty(t, requestedNames, "%s must contain at least one exact operation when set", iseE2EOperationsEnv)

	available := make(map[string]struct{})
	for _, spec := range iseMetricEndpoints() {
		if iseGroupEnabled(cfg, spec.group) {
			available[spec.operation] = struct{}{}
		}
	}
	requested := make(map[string]struct{}, len(requestedNames))
	for _, operation := range requestedNames {
		if _, duplicate := requested[operation]; duplicate {
			require.FailNowf(t, "duplicate ISE E2E operation", "%s contains duplicate exact operation %q", iseE2EOperationsEnv, operation)
		}
		if _, ok := available[operation]; !ok {
			valid := make([]string, 0, len(available))
			for candidate := range available {
				valid = append(valid, candidate)
			}
			sort.Strings(valid)
			require.FailNowf(
				t,
				"unknown or disabled ISE E2E operation",
				"%s contains exact operation %q, which is not exposed by the selected groups; valid operations are %s",
				iseE2EOperationsEnv,
				operation,
				strings.Join(valid, ","),
			)
		}
		requested[operation] = struct{}{}
	}
	return requested
}

func configureISEE2EGroups(t *testing.T, cfg *ISEConfig, maxResults int) []string {
	t.Helper()
	cfg.PxGrid.Enabled = false
	cfg.DataConnect.Enabled = false
	available := make([]string, 0, len(cfg.groups()))
	disabled := ISEGroupConfig{Enabled: false, MaxResults: maxResults}
	for name := range cfg.groups() {
		require.True(t, setISEE2ERESTGroup(cfg, name, disabled), "unhandled ISE REST group %s", name)
		available = append(available, name)
	}
	sort.Strings(available)

	requested := make(map[string]struct{})
	selectAll := false
	for _, rawName := range csvEnv(iseE2EGroupsEnv) {
		name := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(rawName)), "-", "_")
		if name == "all" {
			selectAll = true
			continue
		}
		if !setISEE2ERESTGroup(cfg, name, disabled) {
			require.FailNowf(
				t,
				"unknown or unsupported ISE E2E group",
				"%s contains %q; this REST-only harness accepts all,%s",
				iseE2EGroupsEnv,
				rawName,
				strings.Join(available, ","),
			)
		}
		requested[name] = struct{}{}
	}
	if selectAll {
		for _, name := range available {
			requested[name] = struct{}{}
		}
	}
	require.NotEmpty(t, requested, "%s must select at least one REST group", iseE2EGroupsEnv)

	enabled := ISEGroupConfig{Enabled: true, MaxResults: maxResults}
	selected := make([]string, 0, len(requested))
	for name := range requested {
		require.True(t, setISEE2ERESTGroup(cfg, name, enabled), "unhandled ISE REST group %s", name)
		selected = append(selected, name)
	}
	sort.Strings(selected)
	return selected
}

func setISEE2ERESTGroup(cfg *ISEConfig, name string, group ISEGroupConfig) bool {
	switch name {
	case "deployment":
		cfg.Deployment = group
	case "network_devices":
		cfg.NetworkDevices = group
	case "endpoints":
		cfg.Endpoints = group
	case "sessions":
		cfg.Sessions = group
	case "session_details":
		cfg.SessionDetails = group
	case "auth_failures":
		cfg.AuthFailures = group
	case "accounting":
		cfg.Accounting = group
	case "policy":
		cfg.Policy = group
	case "posture":
		cfg.Posture = group
	case "profiler":
		cfg.Profiler = group
	case "trustsec":
		cfg.TrustSec = group
	case "alarms":
		cfg.Alarms = group
	case "certificates":
		cfg.Certificates = group
	case "licensing":
		cfg.Licensing = group
	case "webhooks":
		cfg.Webhooks = group
	default:
		return false
	}
	return true
}

func iseE2EExpectedMetricOperations(cfg ISEConfig, selections ...map[string]struct{}) []string {
	var selected map[string]struct{}
	if len(selections) > 0 {
		selected = selections[0]
	}
	operations := make([]string, 0)
	for _, spec := range iseMetricEndpoints() {
		if iseGroupEnabled(cfg, spec.group) && iseE2EOperationSelected(selected, spec.operation) {
			operations = append(operations, spec.operation)
		}
	}
	return iseE2EUniqueValues(operations)
}

func iseE2EExpectedLogOperations(cfg ISEConfig, selections ...map[string]struct{}) []string {
	var selected map[string]struct{}
	if len(selections) > 0 {
		selected = selections[0]
	}
	operations := make([]string, 0)
	for _, spec := range iseLogEndpoints() {
		if iseGroupEnabled(cfg, spec.group) && iseE2EOperationSelected(selected, spec.operation) {
			operations = append(operations, spec.operation)
		}
	}
	return iseE2EUniqueValues(operations)
}

func iseE2EOperationSelected(selected map[string]struct{}, operation string) bool {
	if len(selected) == 0 {
		return true
	}
	_, ok := selected[operation]
	return ok
}

func iseE2EAllowedDynamicOperations(cfg ISEConfig, selected map[string]struct{}) map[string]struct{} {
	allowed := make(map[string]struct{})
	if len(selected) == 0 && cfg.Webhooks.Enabled {
		allowed["openapi.webhook_deliveries"] = struct{}{}
	}
	for _, operation := range iseE2EExpectedMetricOperations(cfg, selected) {
		if strings.HasPrefix(operation, "ers.") {
			allowed["ers.csrf_token"] = struct{}{}
			break
		}
	}
	return allowed
}

func scrapeISEE2EMetrics(
	ctx context.Context,
	r *iseMetricsReceiver,
	selected map[string]struct{},
) (pmetric.Metrics, map[string]int, error) {
	if len(selected) == 0 {
		md, err := r.scrape(ctx)
		return md, nil, err
	}

	r.resetRequestStats()
	r.resetDataConnectQueries()
	now := time.Now()
	builder := newISEMetricsBuilder(now, r.iseConfig.Endpoint, r.counters)
	selector := newISEDeviceSelectionMatcher(r.config)
	targets := newISETargetMatcher(r.iseConfig.Targets)
	resultCounts := make(map[string]int, len(selected))
	partial := false
	for _, spec := range iseMetricEndpoints() {
		if !iseGroupEnabled(r.iseConfig, spec.group) || !iseE2EOperationSelected(selected, spec.operation) {
			continue
		}
		objects, err := r.fetchEndpoint(ctx, spec, now)
		resultCounts[spec.operation] += len(objects)
		if err != nil {
			partial = true
			builder.recordEndpointError(iseEndpointSpecWithPath(r.config, spec, now), err)
			if ctx.Err() != nil {
				return r.finishScrape(builder, now, partial, apiOutcomeSummary{}), resultCounts, ctx.Err()
			}
		}
		for _, obj := range objects {
			// Exact-operation mode deliberately does not expand webhook
			// definitions into unlisted delivery requests.
			if spec.operation == "openapi.webhooks" {
				continue
			}
			if iseObjectSelected(obj, targets, selector) {
				builder.recordObject(spec, obj)
			}
		}
	}
	return r.finishScrape(builder, now, partial, apiOutcomeSummary{}), resultCounts, nil
}

func scrapeISEE2ELogs(
	ctx context.Context,
	r *iseLogsReceiver,
	selected map[string]struct{},
) (plog.Logs, map[string]int, error) {
	if len(selected) == 0 {
		ld, err := r.scrape(ctx)
		return ld, nil, err
	}

	now := time.Now()
	builder := newISELogsBuilder(now, r.iseConfig.Endpoint)
	selector := newISEDeviceSelectionMatcher(r.config)
	targets := newISETargetMatcher(r.iseConfig.Targets)
	resultCounts := make(map[string]int)
	var endpointErrors []error
	r.pruneSeen(now)
	for _, spec := range iseLogEndpoints() {
		if !iseGroupEnabled(r.iseConfig, spec.group) || !iseE2EOperationSelected(selected, spec.operation) {
			continue
		}
		objects, err := r.fetchEndpoint(ctx, spec, now)
		resultCounts[spec.operation] += len(objects)
		if err != nil {
			if ctx.Err() != nil {
				return builder.emit(), resultCounts, ctx.Err()
			}
			endpointErrors = append(endpointErrors, err)
		}
		for _, obj := range objects {
			// Webhook definitions can contain delivery credentials and are
			// never logs. Exact-operation mode also prevents implicit delivery
			// lookups that were not named in the allowlist.
			if spec.operation == "openapi.webhooks" {
				continue
			}
			if iseObjectSelected(obj, targets, selector) && r.markSeen(spec, obj, now) {
				builder.recordObject(spec, obj)
			}
		}
	}
	return builder.emit(), resultCounts, errors.Join(endpointErrors...)
}

func requireISEE2ENonEmptyResults(t *testing.T, counts map[string]int, expected []string) {
	t.Helper()
	for _, operation := range expected {
		require.Positive(t, counts[operation], "operation %s must return at least one decoded result", operation)
	}
}

func requireISEE2ECSRFProtected(t *testing.T, signal string, stats []ise.RequestStat, expected []string) {
	t.Helper()
	expectedERS := make(map[string]struct{})
	for _, operation := range expected {
		if strings.HasPrefix(operation, "ers.") {
			expectedERS[operation] = struct{}{}
		}
	}
	observed := make(map[string]int, len(expectedERS))
	for _, stat := range stats {
		if _, ok := expectedERS[stat.Operation]; !ok {
			continue
		}
		observed[stat.Operation]++
		require.True(t, stat.CSRFProtected, "%s ERS operation %s must send a negotiated CSRF token", signal, stat.Operation)
	}
	for operation := range expectedERS {
		require.Positive(t, observed[operation], "%s ERS operation %s must be observed for CSRF validation", signal, operation)
	}
}

func iseE2ECSRFInventory(stats []ise.RequestStat) map[string]int {
	counts := make(map[string]int)
	for _, stat := range stats {
		if !strings.HasPrefix(stat.Operation, "ers.") {
			continue
		}
		key := stat.Operation + " csrf_protected=" + strconv.FormatBool(stat.CSRFProtected)
		counts[key]++
	}
	return counts
}

func requireISEE2EOperationsSucceeded(
	t *testing.T,
	signal string,
	stats []ise.RequestStat,
	expected []string,
	allowedDynamic map[string]struct{},
) {
	t.Helper()
	successesByOperation := make(map[string]int)
	successInventory := make(map[string]int)
	failureInventory := make(map[string]int)
	observed := make(map[string]struct{})
	for _, stat := range stats {
		observed[stat.Operation] = struct{}{}
		status := "none"
		if stat.StatusCode > 0 {
			status = strconv.Itoa(stat.StatusCode)
		}
		key := stat.Operation + " status=" + status
		if stat.Outcome == "success" {
			successesByOperation[stat.Operation]++
			successInventory[key]++
			continue
		}
		failureInventory[key]++
	}

	expectedSet := make(map[string]struct{}, len(expected))
	for _, operation := range expected {
		expectedSet[operation] = struct{}{}
	}
	unexpected := make([]string, 0)
	for operation := range observed {
		if _, ok := expectedSet[operation]; ok {
			continue
		}
		if _, ok := allowedDynamic[operation]; !ok {
			unexpected = append(unexpected, operation)
		}
	}
	sort.Strings(unexpected)

	t.Logf("ISE %s successful request inventory (%d operation/status pairs): %s", signal, len(successInventory), iseE2EFormatInventory(successInventory))
	t.Logf("ISE %s failed request inventory (%d operation/status pairs): %s", signal, len(failureInventory), iseE2EFormatInventory(failureInventory))
	csrfInventory := iseE2ECSRFInventory(stats)
	if len(csrfInventory) > 0 {
		t.Logf("ISE %s CSRF inventory (%d operation/boolean pairs): %s", signal, len(csrfInventory), iseE2EFormatInventory(csrfInventory))
	}
	require.Empty(t, failureInventory, "%s scrape contained failed requests; only operation, status, and count are reported", signal)
	require.Empty(t, unexpected, "%s scrape used unexpected operations: %s", signal, strings.Join(unexpected, ", "))
	for _, operation := range expected {
		require.Positive(t, successesByOperation[operation], "%s operation %s must succeed", signal, operation)
	}
}

func requireISEE2EIntGaugeValue(t *testing.T, md pmetric.Metrics, name string, expected int64) {
	t.Helper()
	values := make([]int64, 0, 1)
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			metrics := rm.ScopeMetrics().At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				metric := metrics.At(k)
				if metric.Name() != name {
					continue
				}
				require.Equal(t, pmetric.MetricTypeGauge, metric.Type(), "%s must be a gauge", name)
				points := metric.Gauge().DataPoints()
				for l := 0; l < points.Len(); l++ {
					point := points.At(l)
					require.Equal(t, pmetric.NumberDataPointValueTypeInt, point.ValueType(), "%s must have integer datapoints", name)
					values = append(values, point.IntValue())
				}
			}
		}
	}
	require.Equal(t, []int64{expected}, values, "%s must contain exactly one datapoint with the expected value", name)
}

func iseE2EMetricInventory(md pmetric.Metrics) map[string]int {
	counts := make(map[string]int)
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			metrics := rm.ScopeMetrics().At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				metric := metrics.At(k)
				counts[metric.Name()] += iseE2EMetricDataPointCount(metric)
			}
		}
	}
	return counts
}

func iseE2EMetricDataPointCount(metric pmetric.Metric) int {
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

func iseE2ELogInventory(
	t *testing.T,
	ld plog.Logs,
	expected []string,
	allowedDynamic map[string]struct{},
) map[string]int {
	t.Helper()
	allowed := make(map[string]struct{}, len(expected)+len(allowedDynamic))
	for _, operation := range expected {
		allowed[operation] = struct{}{}
	}
	for operation := range allowedDynamic {
		allowed[operation] = struct{}{}
	}

	counts := make(map[string]int)
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		rl := ld.ResourceLogs().At(i)
		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			records := rl.ScopeLogs().At(j).LogRecords()
			for k := 0; k < records.Len(); k++ {
				record := records.At(k)
				domain, domainOK := record.Attributes().Get("event.domain")
				require.True(t, domainOK && domain.AsString() == "ise", "ISE log records must set event.domain=ise")
				eventName, eventNameOK := record.Attributes().Get("event.name")
				require.True(t, eventNameOK, "ISE log records must set event.name")
				operation := eventName.AsString()
				_, operationAllowed := allowed[operation]
				require.True(t, operationAllowed, "ISE logs emitted an unconfigured operation %s", operation)
				counts[operation]++
			}
		}
	}
	return counts
}

func iseE2EUniqueValues(values []string) []string {
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

func iseE2EFormatInventory(counts map[string]int) string {
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
