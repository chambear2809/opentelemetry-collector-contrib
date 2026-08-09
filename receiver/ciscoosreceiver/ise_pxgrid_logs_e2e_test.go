// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package ciscoosreceiver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"sync/atomic"
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

// TestE2ELiveISEPxGridLogs performs two bounded polls using the exact same
// pxGrid request window. Only session and RADIUS failure operations are
// accepted. The first nonempty batch is committed through the production
// deduplication path. The second poll may emit genuinely new records, but it
// must not re-emit an exact record fingerprint from the first batch.
//
// Request instrumentation retains only operation, outcome, and status code.
// It never retains or reports request paths, discovered URLs, errors, bodies,
// headers, credentials, or object attributes.
func TestE2ELiveISEPxGridLogs(t *testing.T) {
	cfg, options := newISEPxGridE2EConfig(t)
	expected := requireISEPxGridE2ELogOperations(t, options.operations)
	require.True(t, options.requireNonEmpty, "%s=true is required for the live pxGrid logs qualification gate", iseE2EPxGridRequireNonEmptyEnv)
	require.False(t, cfg.ISE.PxGrid.Streaming, "%s must be false for the polling-only logs gate", iseE2EPxGridStreamingEnv)
	require.Empty(t, options.subscriptions, "the polling-only logs gate must not configure streaming subscriptions")

	receiver, err := newISELogsReceiver(
		receivertest.NewNopSettings(metadata.Type),
		cfg,
		consumertest.NewNop(),
	)
	if err != nil {
		require.FailNowf(t, "create ISE pxGrid logs receiver", "receiver construction failed with error type %T; configuration details are intentionally omitted", err)
	}
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), iseE2EShutdownTimeout)
		defer cancel()
		assert.NoError(t, receiver.Shutdown(shutdownCtx))
	})
	require.NotNil(t, receiver.pxGrid)

	recorder := &isePxGridE2ERequestRecorder{}
	receiver.pxGrid.SetOnRequest(recorder.record)
	allowedDynamic := isePxGridE2ELogDynamicOperations()
	pollTime := time.Now()

	receiver.seen.BeginBatch()
	firstCtx, cancelFirst := context.WithTimeout(t.Context(), cfg.ControllerConfig.Timeout)
	first := scrapeISEPxGridE2ELogsAt(firstCtx, receiver, options.operations, pollTime)
	cancelFirst()
	firstStats := recorder.take()
	requireISEE2EOperationsSucceeded(t, "pxGrid logs first poll", firstStats, expected, allowedDynamic)
	if first.err != nil {
		receiver.seen.RollbackBatch()
		require.FailNowf(t, "ISE pxGrid logs first poll failed", "poll returned error type %T; request and response details are intentionally omitted", first.err)
	}
	requireISEPxGridE2EBoundedLogResults(t, first.logs, first.resultCounts, expected, cfg.ISE.PxGrid.MaxResults)
	require.Equal(t, first.logs.LogRecordCount(), isePxGridE2EFingerprintCount(first.emittedFingerprints), "every emitted pxGrid log must have one fixed-size dedup fingerprint")
	firstInventory := iseE2ELogInventory(t, first.logs, expected, nil)
	for _, operation := range expected {
		require.Positive(t, first.resultCounts[operation], "pxGrid log operation %s must return at least one decoded result", operation)
		require.Positive(t, firstInventory[operation], "pxGrid log operation %s must emit at least one record", operation)
	}
	firstConsumed, firstConsumeErr := consumeDeduplicatedLogs(t.Context(), receiver.consumer, receiver.seen, first.logs)
	if firstConsumeErr != nil {
		require.FailNowf(t, "consume ISE pxGrid logs", "consumer returned error type %T; log details are intentionally omitted", firstConsumeErr)
	}
	require.Equal(t, first.logs.LogRecordCount(), firstConsumed)

	// Across polls retain only fixed-size hashes plus aggregate operation counts,
	// never first-poll records, bodies, raw IDs, or dedup keys.
	firstFingerprints := first.emittedFingerprints
	firstResultCounts := first.resultCounts
	firstLogCount := first.logs.LogRecordCount()
	first = isePxGridE2ELogScrapeResult{}

	// Reuse pollTime so both POST bodies contain the exact same startTimestamp.
	receiver.seen.BeginBatch()
	secondCtx, cancelSecond := context.WithTimeout(t.Context(), cfg.ControllerConfig.Timeout)
	second := scrapeISEPxGridE2ELogsAt(secondCtx, receiver, options.operations, pollTime)
	cancelSecond()
	secondStats := recorder.take()
	requireISEE2EOperationsSucceeded(t, "pxGrid logs second poll", secondStats, expected, allowedDynamic)
	if second.err != nil {
		receiver.seen.RollbackBatch()
		require.FailNowf(t, "ISE pxGrid logs second poll failed", "poll returned error type %T; request and response details are intentionally omitted", second.err)
	}
	requireISEPxGridE2EBoundedLogResults(t, second.logs, second.resultCounts, expected, cfg.ISE.PxGrid.MaxResults)
	require.Equal(t, second.logs.LogRecordCount(), isePxGridE2EFingerprintCount(second.emittedFingerprints), "every emitted pxGrid log must have one fixed-size dedup fingerprint")
	secondInventory := iseE2ELogInventory(t, second.logs, expected, nil)
	repeatInventory := make(map[string]int, len(expected))
	newInventory := make(map[string]int, len(expected))
	replayedFingerprints := 0
	for _, operation := range expected {
		repeatCandidates := isePxGridE2EFingerprintIntersectionCount(firstFingerprints[operation], second.observedFingerprints[operation])
		require.Positive(t, repeatCandidates, "pxGrid log operation %s must return at least one unchanged first-poll record on the second poll to exercise live deduplication", operation)
		repeatInventory[operation] = repeatCandidates
		replayed := isePxGridE2EFingerprintIntersectionCount(firstFingerprints[operation], second.emittedFingerprints[operation])
		require.Zero(t, replayed, "the second pxGrid poll re-emitted one or more exact first-poll records for operation %s", operation)
		replayedFingerprints += replayed
		newInventory[operation] = len(second.emittedFingerprints[operation])
	}
	secondConsumed, secondConsumeErr := consumeDeduplicatedLogs(t.Context(), receiver.consumer, receiver.seen, second.logs)
	if secondConsumeErr != nil {
		require.FailNowf(t, "consume second ISE pxGrid logs batch", "consumer returned error type %T; log details are intentionally omitted", secondConsumeErr)
	}
	require.Equal(t, second.logs.LogRecordCount(), secondConsumed)

	t.Logf("ISE pxGrid first-poll result inventory (%d operations): %s", len(firstResultCounts), iseE2EFormatInventory(firstResultCounts))
	t.Logf("ISE pxGrid first-poll log inventory (%d event families, %d records): %s", len(firstInventory), firstLogCount, iseE2EFormatInventory(firstInventory))
	t.Logf("ISE pxGrid second-poll result inventory (%d operations): %s", len(second.resultCounts), iseE2EFormatInventory(second.resultCounts))
	t.Logf("ISE pxGrid second-poll log inventory (%d event families, %d new records): %s", len(secondInventory), second.logs.LogRecordCount(), iseE2EFormatInventory(secondInventory))
	t.Logf("ISE pxGrid repeat-candidate inventory (%d operations): %s", len(repeatInventory), iseE2EFormatInventory(repeatInventory))
	t.Logf("ISE pxGrid new-record inventory (%d operations): %s", len(newInventory), iseE2EFormatInventory(newInventory))
	t.Logf("ISE pxGrid dedup summary: first_records=%d replayed_records=%d new_records=%d", isePxGridE2EFingerprintCount(firstFingerprints), replayedFingerprints, isePxGridE2EFingerprintCount(second.emittedFingerprints))
}

type isePxGridE2ELogFingerprint [sha256.Size]byte

type isePxGridE2ELogFingerprintSets map[string]map[isePxGridE2ELogFingerprint]struct{}

type isePxGridE2ELogScrapeResult struct {
	logs                 plog.Logs
	resultCounts         map[string]int
	observedFingerprints isePxGridE2ELogFingerprintSets
	emittedFingerprints  isePxGridE2ELogFingerprintSets
	err                  error
}

type isePxGridE2ERequestRecorder struct {
	mu    sync.Mutex
	stats []ise.RequestStat
}

func (r *isePxGridE2ERequestRecorder) record(stat ise.RequestStat) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stats = append(r.stats, ise.RequestStat{
		Operation:  stat.Operation,
		Outcome:    stat.Outcome,
		StatusCode: stat.StatusCode,
	})
}

func (r *isePxGridE2ERequestRecorder) take() []ise.RequestStat {
	r.mu.Lock()
	defer r.mu.Unlock()
	stats := append([]ise.RequestStat(nil), r.stats...)
	r.stats = nil
	return stats
}

func requireISEPxGridE2ELogOperations(t *testing.T, operations map[string]struct{}) []string {
	t.Helper()
	allowed := map[string]struct{}{
		"pxgrid.radius.get_failures":  {},
		"pxgrid.session.get_sessions": {},
	}
	require.NotEmpty(t, operations, "%s must select at least one pxGrid log operation", iseE2EPxGridOperationsEnv)
	selected := make([]string, 0, len(operations))
	for operation := range operations {
		_, ok := allowed[operation]
		require.True(t, ok, "%s operation %s is not a supported pxGrid log operation", iseE2EPxGridOperationsEnv, operation)
		selected = append(selected, operation)
	}
	sort.Strings(selected)
	return selected
}

func isePxGridE2ELogDynamicOperations() map[string]struct{} {
	return map[string]struct{}{
		"pxgrid.access_secret":  {},
		"pxgrid.service_lookup": {},
	}
}

func scrapeISEPxGridE2ELogsAt(
	ctx context.Context,
	receiver *iseLogsReceiver,
	selected map[string]struct{},
	pollTime time.Time,
) isePxGridE2ELogScrapeResult {
	builder := newISELogsBuilder(pollTime, receiver.iseConfig.Endpoint)
	selector := newISEDeviceSelectionMatcher(receiver.config)
	targets := newISETargetMatcher(receiver.iseConfig.Targets)
	resultCounts := make(map[string]int, len(selected))
	observedFingerprints := make(isePxGridE2ELogFingerprintSets)
	emittedFingerprints := make(isePxGridE2ELogFingerprintSets)
	var endpointErrors []error
	receiver.pruneSeen(pollTime)

	for _, query := range isePxGridLogQueries(receiver.iseConfig, pollTime) {
		if _, ok := selected[query.operation]; !ok {
			continue
		}
		objects, err := receiver.pxGrid.PostObjects(
			ctx,
			query.operation,
			query.service,
			query.path,
			query.payload,
			receiver.iseConfig.PxGrid.MaxResults,
		)
		resultCounts[query.operation] = len(objects)
		if err != nil {
			if ctx.Err() != nil {
				return isePxGridE2ELogScrapeResult{
					logs:                 builder.emit(),
					resultCounts:         resultCounts,
					observedFingerprints: observedFingerprints,
					emittedFingerprints:  emittedFingerprints,
					err:                  ctx.Err(),
				}
			}
			endpointErrors = append(endpointErrors, err)
		}
		spec := iseEndpointSpec{group: "pxgrid", operation: query.operation, objectType: query.objectType}
		for _, object := range objects {
			if !iseObjectSelected(object, targets, selector) {
				continue
			}
			dedupKey := iseSeenKey(spec, object)
			fingerprint := sha256.Sum256([]byte(dedupKey))
			isePxGridE2EAddFingerprint(observedFingerprints, query.operation, fingerprint)
			if receiver.seen.MarkPending(dedupKey, pollTime) {
				isePxGridE2EAddFingerprint(emittedFingerprints, query.operation, fingerprint)
				builder.recordObject(spec, object)
			}
		}
	}

	return isePxGridE2ELogScrapeResult{
		logs:                 builder.emit(),
		resultCounts:         resultCounts,
		observedFingerprints: observedFingerprints,
		emittedFingerprints:  emittedFingerprints,
		err:                  errors.Join(endpointErrors...),
	}
}

func isePxGridE2EAddFingerprint(sets isePxGridE2ELogFingerprintSets, operation string, fingerprint isePxGridE2ELogFingerprint) {
	set := sets[operation]
	if set == nil {
		set = make(map[isePxGridE2ELogFingerprint]struct{})
		sets[operation] = set
	}
	set[fingerprint] = struct{}{}
}

func isePxGridE2EFingerprintCount(sets isePxGridE2ELogFingerprintSets) int {
	count := 0
	for _, set := range sets {
		count += len(set)
	}
	return count
}

func isePxGridE2EFingerprintIntersectionCount(
	left map[isePxGridE2ELogFingerprint]struct{},
	right map[isePxGridE2ELogFingerprint]struct{},
) int {
	count := 0
	for fingerprint := range left {
		if _, ok := right[fingerprint]; ok {
			count++
		}
	}
	return count
}

func requireISEPxGridE2EBoundedLogResults(
	t *testing.T,
	logs plog.Logs,
	resultCounts map[string]int,
	expected []string,
	maxResults int,
) {
	t.Helper()
	require.Len(t, resultCounts, len(expected), "each selected pxGrid log operation must execute exactly once")
	for _, operation := range expected {
		count, ok := resultCounts[operation]
		require.True(t, ok, "selected pxGrid log operation %s was not executed", operation)
		require.GreaterOrEqual(t, count, 0)
		require.LessOrEqual(t, count, maxResults, "pxGrid log operation %s exceeded the result cap", operation)
	}
	require.LessOrEqual(t, logs.LogRecordCount(), maxResults*len(expected), "pxGrid logs exceeded the aggregate result cap")
}

func TestISEPxGridE2ELogOperationsAreNarrow(t *testing.T) {
	selected := requireISEPxGridE2ELogOperations(t, map[string]struct{}{
		"pxgrid.session.get_sessions": {},
		"pxgrid.radius.get_failures":  {},
	})
	assert.Equal(t, []string{"pxgrid.radius.get_failures", "pxgrid.session.get_sessions"}, selected)
	assert.Equal(t, map[string]struct{}{
		"pxgrid.access_secret":  {},
		"pxgrid.service_lookup": {},
	}, isePxGridE2ELogDynamicOperations())
}

func TestISEPxGridE2ERequestRecorderDropsRequestDetails(t *testing.T) {
	recorder := &isePxGridE2ERequestRecorder{}
	recorder.record(ise.RequestStat{
		Operation:  "pxgrid.session.get_sessions",
		Method:     http.MethodPost,
		Path:       "https://sensitive.invalid/path",
		Outcome:    "error",
		StatusCode: http.StatusUnauthorized,
		Err:        errors.New("sensitive request detail"),
	})

	stats := recorder.take()
	require.Len(t, stats, 1)
	assert.Equal(t, "pxgrid.session.get_sessions", stats[0].Operation)
	assert.Equal(t, "error", stats[0].Outcome)
	assert.Equal(t, http.StatusUnauthorized, stats[0].StatusCode)
	assert.Empty(t, stats[0].Method)
	assert.Empty(t, stats[0].Path)
	assert.NoError(t, stats[0].Err)
	assert.Empty(t, recorder.take())
}

func TestISEPxGridE2ELogsSuppressReplayAndAllowNewRecord(t *testing.T) {
	const (
		collectorNode = "collector"
		accountSecret = "account-password"
		serviceNode   = "ise-mnt"
		serviceSecret = "service-secret"
	)

	var serviceCalls atomic.Int32
	serviceServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/pxgrid/mnt/sd/getSessions", r.URL.Path)
		username, password, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, collectorNode, username)
		assert.Equal(t, serviceSecret, password)
		sessions := []map[string]string{{"id": "session-1", "timestamp": "2026-07-06T00:00:00Z"}}
		if serviceCalls.Add(1) > 1 {
			sessions = append(sessions, map[string]string{"id": "session-2", "timestamp": "2026-07-06T00:00:01Z"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sessions": sessions})
	}))
	defer serviceServer.Close()

	controlServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, collectorNode, username)
		assert.Equal(t, accountSecret, password)
		switch r.URL.Path {
		case "/pxgrid/control/ServiceLookup":
			var request struct {
				Name string `json:"name"`
			}
			if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&request)) {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			assert.Equal(t, "com.cisco.ise.session", request.Name)
			_ = json.NewEncoder(w).Encode(map[string]any{"services": []map[string]any{{
				"name":     "com.cisco.ise.session",
				"nodeName": serviceNode,
				"properties": map[string]string{
					"restBaseUrl": serviceServer.URL + "/pxgrid/mnt/sd",
				},
			}}})
		case "/pxgrid/control/AccessSecret":
			_ = json.NewEncoder(w).Encode(map[string]string{"secret": serviceSecret})
		default:
			http.NotFound(w, r)
		}
	}))
	defer controlServer.Close()

	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.ControllerConfig.Timeout = 5 * time.Second
	cfg.ControllerConfig.CollectionInterval = time.Hour
	cfg.ISE = defaultISEConfig()
	cfg.ISE.Enabled = true
	cfg.ISE.Endpoint = controlServer.URL
	cfg.ISE.Auth.Username = "unused"
	cfg.ISE.Auth.Password = configopaque.String("unused")
	cfg.ISE.InsecureSkipVerify = true
	for name := range cfg.ISE.groups() {
		require.True(t, setISEE2ERESTGroup(&cfg.ISE, name, ISEGroupConfig{MaxResults: 3}))
	}
	cfg.ISE.DataConnect.Enabled = false
	cfg.ISE.PxGrid.Enabled = true
	cfg.ISE.PxGrid.Endpoint = controlServer.URL + "/pxgrid"
	cfg.ISE.PxGrid.NodeName = collectorNode
	cfg.ISE.PxGrid.Password = configopaque.String(accountSecret)
	cfg.ISE.PxGrid.InsecureSkipVerify = true
	cfg.ISE.PxGrid.AllowedServiceOrigins = []string{serviceServer.URL}
	cfg.ISE.PxGrid.MaxResults = 3
	require.NoError(t, cfg.Validate())

	receiver, err := newISELogsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)
	recorder := &isePxGridE2ERequestRecorder{}
	receiver.pxGrid.SetOnRequest(recorder.record)
	selected := map[string]struct{}{"pxgrid.session.get_sessions": {}}
	pollTime := time.Date(2026, time.July, 6, 0, 0, 0, 0, time.UTC)

	receiver.seen.BeginBatch()
	first := scrapeISEPxGridE2ELogsAt(t.Context(), receiver, selected, pollTime)
	require.NoError(t, first.err)
	assert.Equal(t, map[string]int{"pxgrid.session.get_sessions": 1}, first.resultCounts)
	require.Equal(t, 1, first.logs.LogRecordCount())
	require.Len(t, first.emittedFingerprints["pxgrid.session.get_sessions"], 1)
	firstInventory := iseE2ELogInventory(t, first.logs, []string{"pxgrid.session.get_sessions"}, nil)
	assert.Equal(t, map[string]int{"pxgrid.session.get_sessions": 1}, firstInventory)
	consumed, err := consumeDeduplicatedLogs(t.Context(), receiver.consumer, receiver.seen, first.logs)
	require.NoError(t, err)
	require.Equal(t, 1, consumed)
	requireISEE2EOperationsSucceeded(t, "pxGrid logs self-test first poll", recorder.take(), []string{"pxgrid.session.get_sessions"}, isePxGridE2ELogDynamicOperations())
	firstFingerprints := first.emittedFingerprints
	first = isePxGridE2ELogScrapeResult{}

	receiver.seen.BeginBatch()
	second := scrapeISEPxGridE2ELogsAt(t.Context(), receiver, selected, pollTime)
	require.NoError(t, second.err)
	assert.Equal(t, map[string]int{"pxgrid.session.get_sessions": 2}, second.resultCounts)
	require.Equal(t, 1, second.logs.LogRecordCount(), "the replay must be suppressed while the new record is emitted")
	require.Len(t, second.observedFingerprints["pxgrid.session.get_sessions"], 2)
	require.Len(t, second.emittedFingerprints["pxgrid.session.get_sessions"], 1)
	require.Equal(t, 1, isePxGridE2EFingerprintIntersectionCount(firstFingerprints["pxgrid.session.get_sessions"], second.observedFingerprints["pxgrid.session.get_sessions"]))
	require.Zero(t, isePxGridE2EFingerprintIntersectionCount(firstFingerprints["pxgrid.session.get_sessions"], second.emittedFingerprints["pxgrid.session.get_sessions"]))
	secondInventory := iseE2ELogInventory(t, second.logs, []string{"pxgrid.session.get_sessions"}, nil)
	assert.Equal(t, map[string]int{"pxgrid.session.get_sessions": 1}, secondInventory)
	consumed, err = consumeDeduplicatedLogs(t.Context(), receiver.consumer, receiver.seen, second.logs)
	require.NoError(t, err)
	require.Equal(t, 1, consumed)
	secondStats := recorder.take()
	requireISEE2EOperationsSucceeded(t, "pxGrid logs self-test second poll", secondStats, []string{"pxgrid.session.get_sessions"}, isePxGridE2ELogDynamicOperations())
	for _, stat := range secondStats {
		assert.Empty(t, stat.Path)
		assert.Empty(t, stat.Method)
		assert.NoError(t, stat.Err)
	}
}
