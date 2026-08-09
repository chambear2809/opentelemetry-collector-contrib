// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package ciscoosreceiver

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/ise"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

const (
	iseE2EDataConnectHostEnv       = "CISCOOS_E2E_ISE_DATACONNECT_HOST"
	iseE2EDataConnectPortEnv       = "CISCOOS_E2E_ISE_DATACONNECT_PORT"
	iseE2EDataConnectServiceEnv    = "CISCOOS_E2E_ISE_DATACONNECT_SERVICE_NAME"
	iseE2EDataConnectUsernameEnv   = "CISCOOS_E2E_ISE_DATACONNECT_USERNAME"
	iseE2EDataConnectPasswordEnv   = "CISCOOS_E2E_ISE_DATACONNECT_PASSWORD" //nolint:gosec // Environment variable name, not a credential.
	iseE2EDataConnectCAFileEnv     = "CISCOOS_E2E_ISE_DATACONNECT_CA_FILE"
	iseE2EDataConnectServerNameEnv = "CISCOOS_E2E_ISE_DATACONNECT_SERVER_NAME"
	iseE2EDataConnectWalletDirEnv  = "CISCOOS_E2E_ISE_DATACONNECT_WALLET_DIR"
	iseE2EDataConnectVerifyEnv     = "CISCOOS_E2E_ISE_DATACONNECT_SSL_VERIFY"
	iseE2EDataConnectViewsEnv      = "CISCOOS_E2E_ISE_DATACONNECT_VIEWS"
	iseE2EDataConnectRowLimitEnv   = "CISCOOS_E2E_ISE_DATACONNECT_ROW_LIMIT"
	iseE2EDataConnectLogsEnv       = "CISCOOS_E2E_ISE_DATACONNECT_INCLUDE_LOGS"
	iseE2EDataConnectDefaultPort   = 2484
	iseE2EDataConnectDefaultRows   = 25
	iseE2EDataConnectMaxRows       = 100
)

// TestE2ELiveISEDataConnect performs one bounded, metrics-only Data Connect
// scrape. Views must be selected explicitly, or set to "none" to validate only
// REST status plus the database Ping. The test reports view names and row
// counts, never row content or credentials.
func TestE2ELiveISEDataConnect(t *testing.T) {
	cfg, selectedViews, rowLimit := newISEDataConnectE2EConfig(t)
	receiver, err := newISEMetricsReceiver(
		receivertest.NewNopSettings(metadata.Type),
		cfg,
		consumertest.NewNop(),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), iseE2EShutdownTimeout)
		defer cancel()
		assert.NoError(t, receiver.Shutdown(shutdownCtx))
	})

	receiver.success.mu.Lock()
	previousLastSuccess := receiver.success.lastSuccess
	receiver.success.mu.Unlock()

	scrapeCtx, cancel := context.WithTimeout(t.Context(), cfg.ControllerConfig.Timeout)
	md, scrapeErr := receiver.scrape(scrapeCtx)
	cancel()

	receiver.statsMu.Lock()
	requestStats := append([]ise.RequestStat(nil), receiver.stats...)
	receiver.statsMu.Unlock()
	requireISEE2EOperationsSucceeded(
		t,
		"Data Connect metrics",
		requestStats,
		iseE2EExpectedMetricOperations(cfg.ISE),
		nil,
	)
	if scrapeErr != nil {
		require.FailNowf(t, "ISE Data Connect scrape failed", "scrape returned error type %T; request and row details are intentionally omitted", scrapeErr)
	}

	receiver.success.mu.Lock()
	currentLastSuccess := receiver.success.lastSuccess
	receiver.success.mu.Unlock()
	require.True(t, currentLastSuccess.After(previousLastSuccess), "a fully successful Data Connect scrape must advance last-success state")
	requireISEE2EIntGaugeValue(t, md, "ise.controller.up", 1)
	requireISEE2EIntGaugeValue(t, md, "ise.scrape.partial_success", 0)

	receiver.queryMu.Lock()
	queryStats := append([]ise.DataConnectStat(nil), receiver.queries...)
	receiver.queryMu.Unlock()
	require.Len(t, queryStats, len(selectedViews), "each explicitly selected Data Connect view must execute exactly once")
	queryRows := make(map[string]int, len(queryStats))
	for _, stat := range queryStats {
		require.Equal(t, "success", stat.Outcome, "Data Connect view %s did not succeed; error details are intentionally omitted", stat.View)
		require.GreaterOrEqual(t, stat.Rows, 0)
		require.LessOrEqual(t, stat.Rows, rowLimit)
		queryRows[stat.View] = stat.Rows
	}
	for _, view := range selectedViews {
		rows, ok := queryRows[view]
		require.True(t, ok, "selected Data Connect view %s was not observed", view)
		t.Logf("ISE Data Connect view %s rows=%d", view, rows)
	}

	metricInventory := iseE2EMetricInventory(md)
	for _, name := range []string{
		"ise.api.endpoint.error",
		"ise.api.request.errors",
		"ise.dataconnect.query.errors",
		"ise.service.skipped",
		"ise.service.unavailable",
	} {
		require.Zero(t, metricInventory[name], "strict Data Connect validation must not emit %s", name)
	}
	if len(selectedViews) > 0 {
		require.Equal(t, len(selectedViews), metricInventory["ise.dataconnect.query.duration"])
		require.Equal(t, len(selectedViews), metricInventory["ise.dataconnect.query.rows"])
	}
	if boolEnv(t, iseE2EDataConnectLogsEnv, false) {
		requireISEDataConnectE2ELogs(t, cfg, selectedViews, rowLimit)
	}
}

func requireISEDataConnectE2ELogs(t *testing.T, cfg *Config, selectedViews []string, rowLimit int) {
	t.Helper()
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

	expected := make(map[string]struct{})
	for _, view := range selectedViews {
		if iseDataConnectLogViewAllowed(view) {
			expected["data_connect."+strings.ToLower(view)] = struct{}{}
		}
	}
	logsReceiver.seen.BeginBatch()
	scrapeCtx, cancel := context.WithTimeout(t.Context(), cfg.ControllerConfig.Timeout)
	ld, scrapeErr := logsReceiver.scrape(scrapeCtx)
	cancel()
	require.NoError(t, scrapeErr)
	counts := iseDataConnectE2ELogInventory(t, ld, expected, rowLimit)
	for operation, count := range counts {
		t.Logf("ISE Data Connect log operation %s records=%d", operation, count)
	}
	consumed, consumeErr := consumeDeduplicatedLogs(t.Context(), logsReceiver.consumer, logsReceiver.seen, ld)
	require.NoError(t, consumeErr)
	require.Equal(t, ld.LogRecordCount(), consumed)

	logsReceiver.seen.BeginBatch()
	secondCtx, cancelSecond := context.WithTimeout(t.Context(), cfg.ControllerConfig.Timeout)
	second, secondErr := logsReceiver.scrape(secondCtx)
	cancelSecond()
	require.NoError(t, secondErr)
	require.Zero(t, second.LogRecordCount(), "a second identical Data Connect log poll must be deduplicated")
}

func iseDataConnectE2ELogInventory(t *testing.T, ld plog.Logs, allowed map[string]struct{}, rowLimit int) map[string]int {
	t.Helper()
	counts := make(map[string]int)
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		rls := ld.ResourceLogs().At(i).ScopeLogs()
		for j := 0; j < rls.Len(); j++ {
			records := rls.At(j).LogRecords()
			for k := 0; k < records.Len(); k++ {
				record := records.At(k)
				domain, ok := record.Attributes().Get("event.domain")
				require.True(t, ok && domain.AsString() == "ise", "Data Connect logs must set event.domain=ise")
				eventName, ok := record.Attributes().Get("event.name")
				require.True(t, ok, "Data Connect logs must set event.name")
				operation := eventName.AsString()
				_, ok = allowed[operation]
				require.True(t, ok, "Data Connect emitted an unselected log operation %s", operation)
				counts[operation]++
				require.LessOrEqual(t, counts[operation], rowLimit, "Data Connect log operation %s exceeded the row cap", operation)
			}
		}
	}
	return counts
}

func newISEDataConnectE2EConfig(t *testing.T) (*Config, []string, int) {
	t.Helper()
	endpoint := strings.TrimSpace(requiredEnvOrSkip(t, iseE2EEndpointEnv))
	username := strings.TrimSpace(requiredEnvOrSkip(t, iseE2EUsernameEnv))
	password := requiredEnvOrSkip(t, iseE2EPasswordEnv)
	host := strings.TrimSpace(requiredEnvOrSkip(t, iseE2EDataConnectHostEnv))
	service := strings.TrimSpace(requiredEnvOrSkip(t, iseE2EDataConnectServiceEnv))
	dbUsername := strings.TrimSpace(requiredEnvOrSkip(t, iseE2EDataConnectUsernameEnv))
	dbPassword := requiredEnvOrSkip(t, iseE2EDataConnectPasswordEnv)
	requiredEnvOrSkip(t, iseE2EDataConnectViewsEnv)
	for name, value := range map[string]string{
		iseE2EEndpointEnv:            endpoint,
		iseE2EUsernameEnv:            username,
		iseE2EPasswordEnv:            password,
		iseE2EDataConnectHostEnv:     host,
		iseE2EDataConnectServiceEnv:  service,
		iseE2EDataConnectUsernameEnv: dbUsername,
		iseE2EDataConnectPasswordEnv: dbPassword,
	} {
		require.NotEmpty(t, value, "%s cannot contain only whitespace or be empty", name)
	}

	timeout := durationEnv(t, iseE2ETimeoutEnv, iseE2EDefaultTimeout)
	require.Positive(t, timeout)
	require.LessOrEqual(t, timeout, iseE2EMaxAllowedTimeout)
	port := intEnv(t, iseE2EDataConnectPortEnv, iseE2EDataConnectDefaultPort)
	require.GreaterOrEqual(t, port, 1)
	require.LessOrEqual(t, port, 65535)
	rowLimit := intEnv(t, iseE2EDataConnectRowLimitEnv, iseE2EDataConnectDefaultRows)
	require.Positive(t, rowLimit)
	require.LessOrEqual(t, rowLimit, iseE2EDataConnectMaxRows)

	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.ControllerConfig.Timeout = timeout
	cfg.ControllerConfig.CollectionInterval = time.Hour
	cfg.ISE = defaultISEConfig()
	cfg.ISE.Enabled = true
	cfg.ISE.Endpoint = endpoint
	cfg.ISE.Auth.Username = username
	cfg.ISE.Auth.Password = configopaque.String(password)
	cfg.ISE.CAFile = strings.TrimSpace(os.Getenv(iseE2ECAFileEnv))
	cfg.ISE.ServerName = strings.TrimSpace(os.Getenv(iseE2EServerNameEnv))
	cfg.ISE.InsecureSkipVerify = boolEnv(t, iseE2EInsecureSkipEnv, false)
	cfg.ISE.MaxRetries = 0
	disableISEGroups(&cfg.ISE)
	cfg.ISE.DataConnect.Enabled = true
	cfg.ISE.DataConnect.Host = host
	cfg.ISE.DataConnect.Port = port
	cfg.ISE.DataConnect.ServiceName = service
	cfg.ISE.DataConnect.Username = dbUsername
	cfg.ISE.DataConnect.Password = configopaque.String(dbPassword)
	cfg.ISE.DataConnect.CAFile = strings.TrimSpace(os.Getenv(iseE2EDataConnectCAFileEnv))
	cfg.ISE.DataConnect.ServerName = strings.TrimSpace(os.Getenv(iseE2EDataConnectServerNameEnv))
	cfg.ISE.DataConnect.WalletDir = strings.TrimSpace(os.Getenv(iseE2EDataConnectWalletDirEnv))
	cfg.ISE.DataConnect.SSL = true
	cfg.ISE.DataConnect.SSLVerify = boolEnv(t, iseE2EDataConnectVerifyEnv, true)
	cfg.ISE.DataConnect.Lookback = time.Hour
	cfg.ISE.DataConnect.RowLimit = rowLimit
	cfg.ISE.DataConnect.FullViews = false

	available := make(map[string]struct{}, len(cfg.ISE.DataConnect.Views))
	for name, group := range cfg.ISE.DataConnect.Views {
		available[name] = struct{}{}
		group.Enabled = false
		group.MaxResults = rowLimit
		cfg.ISE.DataConnect.Views[name] = group
	}
	requested := csvEnv(iseE2EDataConnectViewsEnv)
	require.NotEmpty(t, requested, "%s must select one or more views, or none", iseE2EDataConnectViewsEnv)
	selected := make([]string, 0, len(requested))
	for _, raw := range requested {
		name := strings.ToUpper(strings.TrimSpace(raw))
		if name == "NONE" {
			require.Len(t, requested, 1, "none cannot be combined with Data Connect view names")
			continue
		}
		_, ok := available[name]
		require.True(t, ok, "%s contains unsupported Data Connect view %q", iseE2EDataConnectViewsEnv, raw)
		group := cfg.ISE.DataConnect.Views[name]
		group.Enabled = true
		cfg.ISE.DataConnect.Views[name] = group
		selected = append(selected, name)
	}
	sort.Strings(selected)
	require.NoError(t, cfg.Validate())
	return cfg, selected, rowLimit
}
