// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package ciscoosreceiver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"golang.org/x/net/websocket"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/ise"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

const (
	iseE2EPxGridEndpointEnv             = "CISCOOS_E2E_ISE_PXGRID_ENDPOINT"
	iseE2EPxGridNodeNameEnv             = "CISCOOS_E2E_ISE_PXGRID_NODE_NAME"
	iseE2EPxGridPasswordEnv             = "CISCOOS_E2E_ISE_PXGRID_PASSWORD" //nolint:gosec // Environment variable name, not a credential.
	iseE2EPxGridCertFileEnv             = "CISCOOS_E2E_ISE_PXGRID_CERT_FILE"
	iseE2EPxGridKeyFileEnv              = "CISCOOS_E2E_ISE_PXGRID_KEY_FILE"
	iseE2EPxGridKeyPasswordEnv          = "CISCOOS_E2E_ISE_PXGRID_KEY_PASSWORD" //nolint:gosec // Environment variable name, not a credential.
	iseE2EPxGridCAFileEnv               = "CISCOOS_E2E_ISE_PXGRID_CA_FILE"
	iseE2EPxGridServerNameEnv           = "CISCOOS_E2E_ISE_PXGRID_SERVER_NAME"
	iseE2EPxGridInsecureSkipEnv         = "CISCOOS_E2E_ISE_PXGRID_INSECURE_SKIP_VERIFY"
	iseE2EPxGridAllowedOriginsEnv       = "CISCOOS_E2E_ISE_PXGRID_ALLOWED_SERVICE_ORIGINS"
	iseE2EPxGridOperationsEnv           = "CISCOOS_E2E_ISE_PXGRID_OPERATIONS"
	iseE2EPxGridServicesEnv             = "CISCOOS_E2E_ISE_PXGRID_SERVICES"
	iseE2EPxGridAutoActivateEnv         = "CISCOOS_E2E_ISE_PXGRID_AUTO_ACTIVATE"
	iseE2EPxGridMaxResultsEnv           = "CISCOOS_E2E_ISE_PXGRID_MAX_RESULTS"
	iseE2EPxGridRequireNonEmptyEnv      = "CISCOOS_E2E_ISE_PXGRID_REQUIRE_NONEMPTY"
	iseE2EPxGridStreamingEnv            = "CISCOOS_E2E_ISE_PXGRID_STREAMING"
	iseE2EPxGridSubscriptionsEnv        = "CISCOOS_E2E_ISE_PXGRID_SUBSCRIPTIONS"
	iseE2EPxGridStreamTimeoutEnv        = "CISCOOS_E2E_ISE_PXGRID_STREAM_TIMEOUT"
	iseE2EPxGridStreamRequireMessageEnv = "CISCOOS_E2E_ISE_PXGRID_STREAM_REQUIRE_MESSAGE"
	iseE2EPxGridDefaultMaxResults       = 100
	iseE2EPxGridMaxAllowedResults       = 5000
	iseE2EPxGridDefaultStreamTimeout    = 30 * time.Second
	iseE2EPxGridMaximumStreamTimeout    = 5 * time.Minute
)

type isePxGridE2EOptions struct {
	operations           map[string]struct{}
	services             []string
	requireNonEmpty      bool
	subscriptions        []ise.PxGridSubscription
	streamTimeout        time.Duration
	streamRequireMessage bool
}

type isePxGridE2EStreamResult struct {
	service string
	err     error
}

type isePxGridE2EStreamDependencyCounts struct {
	serviceLookup int
	accessSecret  int
}

type isePxGridE2EReadyTracker struct {
	mu          sync.Mutex
	expected    int
	seen        map[string]struct{}
	baseline    isePxGridE2EStreamDependencyCounts
	baselineSet bool
	snapshot    func() isePxGridE2EStreamDependencyCounts
}

type isePxGridE2EStreamFailure string

const (
	isePxGridE2EStreamFailureMissingTopic      isePxGridE2EStreamFailure = "missing_topic"
	isePxGridE2EStreamFailurePubSubUnavailable isePxGridE2EStreamFailure = "pubsub_unavailable"
	isePxGridE2EStreamFailureOriginNotAllowed  isePxGridE2EStreamFailure = "origin_not_allowed"
	isePxGridE2EStreamFailureAccessSecret      isePxGridE2EStreamFailure = "access_secret"
	isePxGridE2EStreamFailureWebSocketDial     isePxGridE2EStreamFailure = "websocket_dial"
	isePxGridE2EStreamFailureTLS               isePxGridE2EStreamFailure = "tls"
	isePxGridE2EStreamFailureSTOMPErrorFrame   isePxGridE2EStreamFailure = "stomp_error_frame"
	isePxGridE2EStreamFailureSTOMPHandshake    isePxGridE2EStreamFailure = "stomp_handshake"
	isePxGridE2EStreamFailureEOF               isePxGridE2EStreamFailure = "read_eof"
	isePxGridE2EStreamFailureTimeout           isePxGridE2EStreamFailure = "read_write_timeout"
	isePxGridE2EStreamFailureProtocol          isePxGridE2EStreamFailure = "protocol_error"
	isePxGridE2EStreamFailureConnectionReset   isePxGridE2EStreamFailure = "connection_reset"
	isePxGridE2EStreamFailureReadWrite         isePxGridE2EStreamFailure = "read_write"
	isePxGridE2EStreamFailureContext           isePxGridE2EStreamFailure = "context"
	isePxGridE2EStreamFailureServiceDiscovery  isePxGridE2EStreamFailure = "service_discovery"
	isePxGridE2EStreamFailureOther             isePxGridE2EStreamFailure = "other"
)

// TestE2ELiveISEPxGrid performs one bounded, exact-operation metrics scrape
// against pxGrid. Account activation and streaming are disabled unless their
// dedicated opt-in environment variables are true. The test reports only
// operation/service names, status codes, and counts; it never logs credentials,
// discovered URLs, request payloads, response bodies, or message bodies.
func TestE2ELiveISEPxGrid(t *testing.T) {
	cfg, options := newISEPxGridE2EConfig(t)
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

	scrapeCtx, cancel := context.WithTimeout(t.Context(), cfg.Timeout)
	md, resultCounts, lookupCounts, scrapeErr := scrapeISEPxGridE2EMetrics(scrapeCtx, receiver, options)
	cancel()

	receiver.statsMu.Lock()
	requestStats := append([]ise.RequestStat(nil), receiver.stats...)
	receiver.statsMu.Unlock()
	expected := isePxGridE2ESortedOperations(options.operations)
	requireISEE2EOperationsSucceeded(t, "pxGrid metrics", requestStats, expected, isePxGridE2EDynamicOperations(options.operations))
	if scrapeErr != nil {
		require.FailNowf(t, "ISE pxGrid scrape failed", "scrape returned error type %T; request and response details are intentionally omitted", scrapeErr)
	}

	for operation, count := range resultCounts {
		if operation == "pxgrid.service_lookup" {
			continue
		}
		require.LessOrEqual(t, count, cfg.ISE.PxGrid.MaxResults, "pxGrid operation %s exceeded the result cap", operation)
	}
	for service, count := range lookupCounts {
		require.LessOrEqual(t, count, cfg.ISE.PxGrid.MaxResults, "pxGrid service lookup %s exceeded the result cap", service)
	}
	if options.requireNonEmpty {
		for _, operation := range expected {
			require.Positive(t, resultCounts[operation], "pxGrid operation %s must return at least one decoded result", operation)
		}
		for service, count := range lookupCounts {
			require.Positive(t, count, "pxGrid service lookup %s must return at least one decoded result", service)
		}
	}

	receiver.success.mu.Lock()
	currentLastSuccess := receiver.success.lastSuccess
	receiver.success.mu.Unlock()
	require.True(t, currentLastSuccess.After(previousLastSuccess), "a fully successful one-shot pxGrid scrape must advance last-success state")
	requireISEE2EIntGaugeValue(t, md, "ise.controller.up", 1)
	requireISEE2EIntGaugeValue(t, md, "ise.scrape.partial_success", 0)
	requireISEE2EIntGaugeValue(t, md, "ise.scrape.last_success", currentLastSuccess.Unix())

	metricInventory := iseE2EMetricInventory(md)
	for _, name := range []string{
		"ise.api.endpoint.error",
		"ise.api.rate_limited",
		"ise.api.request.errors",
		"ise.service.skipped",
		"ise.service.unavailable",
	} {
		require.Zero(t, metricInventory[name], "strict pxGrid validation must not emit %s", name)
	}
	t.Logf("ISE pxGrid result inventory (%d operations): %s", len(resultCounts), iseE2EFormatInventory(resultCounts))
	if len(lookupCounts) > 0 {
		t.Logf("ISE pxGrid service inventory (%d services): %s", len(lookupCounts), iseE2EFormatInventory(lookupCounts))
	}
	t.Logf("ISE pxGrid metric inventory (%d families): %s", len(metricInventory), iseE2EFormatInventory(metricInventory))

	if cfg.ISE.PxGrid.Streaming {
		requireISEPxGridE2EStreaming(t, receiver, options)
	}
}

func newISEPxGridE2EConfig(t *testing.T) (*Config, isePxGridE2EOptions) {
	t.Helper()
	endpoint := strings.TrimSpace(requiredEnvOrSkip(t, iseE2EPxGridEndpointEnv))
	nodeName := strings.TrimSpace(requiredEnvOrSkip(t, iseE2EPxGridNodeNameEnv))
	requiredEnvOrSkip(t, iseE2EPxGridOperationsEnv)
	password := os.Getenv(iseE2EPxGridPasswordEnv)
	certFile := strings.TrimSpace(os.Getenv(iseE2EPxGridCertFileEnv))
	keyFile := strings.TrimSpace(os.Getenv(iseE2EPxGridKeyFileEnv))
	keyPassword := os.Getenv(iseE2EPxGridKeyPasswordEnv)
	require.NotEmpty(t, endpoint, "%s cannot contain only whitespace", iseE2EPxGridEndpointEnv)
	require.NotEmpty(t, nodeName, "%s cannot contain only whitespace", iseE2EPxGridNodeNameEnv)
	require.Equal(t, certFile == "", keyFile == "", "%s and %s must be provided together", iseE2EPxGridCertFileEnv, iseE2EPxGridKeyFileEnv)
	require.True(t, password != "" || certFile != "", "set %s or both %s and %s", iseE2EPxGridPasswordEnv, iseE2EPxGridCertFileEnv, iseE2EPxGridKeyFileEnv)
	require.True(t, keyPassword == "" || certFile != "", "%s requires both %s and %s", iseE2EPxGridKeyPasswordEnv, iseE2EPxGridCertFileEnv, iseE2EPxGridKeyFileEnv)

	timeout := durationEnv(t, iseE2ETimeoutEnv, iseE2EDefaultTimeout)
	require.Positive(t, timeout)
	require.LessOrEqual(t, timeout, iseE2EMaxAllowedTimeout)
	maxResults := intEnv(t, iseE2EPxGridMaxResultsEnv, iseE2EPxGridDefaultMaxResults)
	require.Positive(t, maxResults)
	require.LessOrEqual(t, maxResults, iseE2EPxGridMaxAllowedResults)
	eventLookback := durationEnv(t, iseE2EEventLookbackEnv, iseE2EDefaultEventLookback)
	require.Positive(t, eventLookback)
	require.LessOrEqual(t, eventLookback, iseE2EMaxEventLookback)
	streamTimeout := durationEnv(t, iseE2EPxGridStreamTimeoutEnv, iseE2EPxGridDefaultStreamTimeout)
	require.Positive(t, streamTimeout)
	require.LessOrEqual(t, streamTimeout, iseE2EPxGridMaximumStreamTimeout)

	autoActivate := boolEnv(t, iseE2EPxGridAutoActivateEnv, false)
	streaming := boolEnv(t, iseE2EPxGridStreamingEnv, false)
	operations := configureISEPxGridE2EOperations(t, autoActivate)
	services := configureISEPxGridE2EServices(t, operations)
	subscriptions := configureISEPxGridE2ESubscriptions(t, streaming)

	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.Timeout = timeout
	cfg.CollectionInterval = time.Hour
	cfg.ISE = defaultISEConfig()
	cfg.ISE.Enabled = true
	// The pxGrid-only receiver does not issue REST/MnT requests. These values
	// satisfy the shared ISE configuration contract without requiring a second
	// administrative credential.
	cfg.ISE.Endpoint = endpoint
	cfg.ISE.Auth.Username = nodeName
	cfg.ISE.Auth.Password = configopaque.String("unused-pxgrid-only-e2e")
	cfg.ISE.CAFile = strings.TrimSpace(os.Getenv(iseE2EPxGridCAFileEnv))
	cfg.ISE.ServerName = strings.TrimSpace(os.Getenv(iseE2EPxGridServerNameEnv))
	cfg.ISE.InsecureSkipVerify = boolEnv(t, iseE2EPxGridInsecureSkipEnv, false)
	cfg.ISE.MaxRetries = 0
	cfg.ISE.EventLookback = eventLookback
	for name := range cfg.ISE.groups() {
		require.True(t, setISEE2ERESTGroup(&cfg.ISE, name, ISEGroupConfig{MaxResults: maxResults}), "unhandled ISE group %s", name)
	}
	cfg.ISE.DataConnect.Enabled = false
	cfg.ISE.PxGrid.Enabled = true
	cfg.ISE.PxGrid.Endpoint = endpoint
	cfg.ISE.PxGrid.NodeName = nodeName
	cfg.ISE.PxGrid.Password = configopaque.String(password)
	cfg.ISE.PxGrid.CertFile = certFile
	cfg.ISE.PxGrid.KeyFile = keyFile
	cfg.ISE.PxGrid.KeyPassword = configopaque.String(keyPassword)
	cfg.ISE.PxGrid.CAFile = strings.TrimSpace(os.Getenv(iseE2EPxGridCAFileEnv))
	cfg.ISE.PxGrid.ServerName = strings.TrimSpace(os.Getenv(iseE2EPxGridServerNameEnv))
	cfg.ISE.PxGrid.InsecureSkipVerify = boolEnv(t, iseE2EPxGridInsecureSkipEnv, false)
	cfg.ISE.PxGrid.AllowedServiceOrigins = csvEnv(iseE2EPxGridAllowedOriginsEnv)
	cfg.ISE.PxGrid.AllowedServiceHosts = nil
	cfg.ISE.PxGrid.AutoActivate = autoActivate
	cfg.ISE.PxGrid.Streaming = streaming
	cfg.ISE.PxGrid.Subscriptions = isePxGridE2ESubscriptionConfig(subscriptions)
	cfg.ISE.PxGrid.MaxResults = maxResults
	require.NoError(t, cfg.Validate())

	return cfg, isePxGridE2EOptions{
		operations:           operations,
		services:             services,
		requireNonEmpty:      boolEnv(t, iseE2EPxGridRequireNonEmptyEnv, false),
		subscriptions:        subscriptions,
		streamTimeout:        streamTimeout,
		streamRequireMessage: isePxGridE2EStreamRequireMessage(t),
	}
}

func isePxGridE2EStreamRequireMessage(t *testing.T) bool {
	t.Helper()
	return boolEnv(t, iseE2EPxGridStreamRequireMessageEnv, true)
}

func configureISEPxGridE2EOperations(t *testing.T, autoActivate bool) map[string]struct{} {
	t.Helper()
	requested := csvEnv(iseE2EPxGridOperationsEnv)
	require.NotEmpty(t, requested, "%s must contain at least one exact operation", iseE2EPxGridOperationsEnv)
	known := isePxGridE2EKnownOperations()
	selected := make(map[string]struct{}, len(requested))
	for _, operation := range requested {
		_, duplicate := selected[operation]
		require.False(t, duplicate, "%s contains duplicate exact operation %q", iseE2EPxGridOperationsEnv, operation)
		_, ok := known[operation]
		require.True(t, ok, "%s contains unsupported exact operation %q", iseE2EPxGridOperationsEnv, operation)
		selected[operation] = struct{}{}
	}
	_, activationSelected := selected["pxgrid.account_activate"]
	require.Equal(t, autoActivate, activationSelected, "%s=true and exact operation pxgrid.account_activate must be selected together", iseE2EPxGridAutoActivateEnv)
	return selected
}

func configureISEPxGridE2EServices(t *testing.T, operations map[string]struct{}) []string {
	t.Helper()
	services := csvEnv(iseE2EPxGridServicesEnv)
	_, lookupSelected := operations["pxgrid.service_lookup"]
	if lookupSelected {
		require.NotEmpty(t, services, "%s must select at least one service when pxgrid.service_lookup is selected", iseE2EPxGridServicesEnv)
	} else {
		require.Empty(t, services, "%s requires exact operation pxgrid.service_lookup", iseE2EPxGridServicesEnv)
	}
	seen := make(map[string]struct{}, len(services))
	for _, service := range services {
		require.NotEmpty(t, strings.TrimSpace(service))
		_, duplicate := seen[service]
		require.False(t, duplicate, "%s contains duplicate service %q", iseE2EPxGridServicesEnv, service)
		seen[service] = struct{}{}
	}
	sort.Strings(services)
	return services
}

func configureISEPxGridE2ESubscriptions(t *testing.T, streaming bool) []ise.PxGridSubscription {
	t.Helper()
	names := csvEnv(iseE2EPxGridSubscriptionsEnv)
	if !streaming {
		require.Empty(t, names, "%s requires %s=true", iseE2EPxGridSubscriptionsEnv, iseE2EPxGridStreamingEnv)
		return nil
	}
	require.NotEmpty(t, names, "%s=true requires one or more exact %s values", iseE2EPxGridStreamingEnv, iseE2EPxGridSubscriptionsEnv)
	known := map[string]ise.PxGridSubscription{
		"session":         {Service: "com.cisco.ise.session", TopicProperty: "sessionTopic"},
		"radius_failures": {Service: "com.cisco.ise.radius", TopicProperty: "failureTopic"},
		"endpoint":        {Service: "com.cisco.ise.endpoint", TopicProperty: "topic"},
		"trustsec": {
			Service:                  "com.cisco.ise.config.trustsec",
			TopicProperty:            "securityGroupTopic",
			AlternateTopicProperties: []string{"securityGroupAclTopic", "securityGroupVnVlanTopic"},
		},
	}
	seen := make(map[string]struct{}, len(names))
	selected := make([]ise.PxGridSubscription, 0, len(names))
	for _, name := range names {
		_, duplicate := seen[name]
		require.False(t, duplicate, "%s contains duplicate subscription %q", iseE2EPxGridSubscriptionsEnv, name)
		subscription, ok := known[name]
		require.True(t, ok, "%s contains unsupported exact subscription %q", iseE2EPxGridSubscriptionsEnv, name)
		seen[name] = struct{}{}
		selected = append(selected, subscription)
	}
	return selected
}

func isePxGridE2ESubscriptionConfig(subscriptions []ise.PxGridSubscription) ISEPxGridSubscriptionConfig {
	configured := ISEPxGridSubscriptionConfig{}
	for _, subscription := range subscriptions {
		switch subscription.Service {
		case "com.cisco.ise.session":
			configured.Session = true
		case "com.cisco.ise.radius":
			configured.RadiusFailures = true
		case "com.cisco.ise.endpoint":
			configured.Endpoint = true
		case "com.cisco.ise.config.trustsec":
			configured.TrustSec = true
		}
	}
	return configured
}

func isePxGridE2EKnownOperations() map[string]struct{} {
	known := map[string]struct{}{
		"pxgrid.account_activate": {},
		"pxgrid.service_lookup":   {},
		"pxgrid.version":          {},
	}
	for _, query := range isePxGridRESTQueries(defaultISEConfig(), time.Time{}) {
		known[query.operation] = struct{}{}
	}
	return known
}

func isePxGridE2ESortedOperations(operations map[string]struct{}) []string {
	selected := make([]string, 0, len(operations))
	for operation := range operations {
		selected = append(selected, operation)
	}
	sort.Strings(selected)
	return selected
}

func isePxGridE2EDynamicOperations(operations map[string]struct{}) map[string]struct{} {
	allowed := make(map[string]struct{})
	knownQueries := isePxGridRESTQueries(defaultISEConfig(), time.Time{})
	for _, query := range knownQueries {
		if _, ok := operations[query.operation]; ok {
			allowed["pxgrid.service_lookup"] = struct{}{}
			allowed["pxgrid.access_secret"] = struct{}{}
		}
	}
	return allowed
}

func scrapeISEPxGridE2EMetrics(
	ctx context.Context,
	r *iseMetricsReceiver,
	options isePxGridE2EOptions,
) (pmetric.Metrics, map[string]int, map[string]int, error) {
	r.resetRequestStats()
	now := time.Now()
	builder := newISEMetricsBuilder(now, r.iseConfig.Endpoint, r.counters)
	resultCounts := make(map[string]int, len(options.operations))
	lookupCounts := make(map[string]int, len(options.services))
	outcome := apiOutcomeSummary{}
	partial := false
	var operationErrors []error
	recordError := func(operation string, err error) {
		partial = true
		builder.recordServiceUnavailable("pxgrid", operation, err)
		operationErrors = append(operationErrors, fmt.Errorf("pxGrid operation %s: %w", operation, err))
	}

	if _, ok := options.operations["pxgrid.account_activate"]; ok {
		outcome.attempted = true
		obj, err := r.pxGrid.AccountActivate(ctx)
		if err != nil {
			recordError("pxgrid.account_activate", err)
		} else {
			outcome.succeeded = true
			resultCounts["pxgrid.account_activate"] = 1
			builder.recordObject(iseEndpointSpec{group: "pxgrid", operation: "pxgrid.account_activate", objectType: "pxgrid_account", mode: iseEndpointGet}, obj)
		}
	}
	if _, ok := options.operations["pxgrid.version"]; ok {
		outcome.attempted = true
		obj, err := r.pxGrid.Version(ctx)
		if err != nil {
			recordError("pxgrid.version", err)
		} else {
			outcome.succeeded = true
			resultCounts["pxgrid.version"] = 1
			builder.recordObject(iseEndpointSpec{group: "pxgrid", operation: "pxgrid.version", objectType: "pxgrid_version", mode: iseEndpointGet}, obj)
		}
	}
	if _, ok := options.operations["pxgrid.service_lookup"]; ok {
		for _, service := range options.services {
			outcome.attempted = true
			objects, err := r.pxGrid.ServiceLookup(ctx, service)
			if err != nil {
				recordError("pxgrid.service_lookup", err)
				continue
			}
			outcome.succeeded = true
			lookupCounts[service] = len(objects)
			resultCounts["pxgrid.service_lookup"] += len(objects)
			for _, obj := range objects {
				builder.recordObject(iseEndpointSpec{group: "pxgrid", operation: "pxgrid.service_lookup", objectType: "pxgrid_service", mode: iseEndpointList}, obj)
			}
		}
	}
	for _, query := range isePxGridRESTQueries(r.iseConfig, now) {
		if _, ok := options.operations[query.operation]; !ok {
			continue
		}
		outcome.attempted = true
		objects, err := r.pxGrid.PostObjects(ctx, query.operation, query.service, query.path, query.payload, r.iseConfig.PxGrid.MaxResults)
		if err != nil {
			recordError(query.operation, err)
			continue
		}
		outcome.succeeded = true
		resultCounts[query.operation] = len(objects)
		for _, obj := range objects {
			builder.recordObject(iseEndpointSpec{group: "pxgrid", operation: query.operation, objectType: query.objectType, mode: iseEndpointList}, obj)
		}
	}
	for _, subscription := range options.subscriptions {
		builder.controllerResource().recordInt("ise.pxgrid.subscription.status", "Configured Cisco ISE pxGrid subscription status.", "1", 1, map[string]string{"ise.pxgrid.topic": isePxGridSubscriptionLabel(subscription)})
	}
	return r.finishScrape(builder, now, partial, outcome), resultCounts, lookupCounts, errors.Join(operationErrors...)
}

func requireISEPxGridE2EStreaming(t *testing.T, receiver *iseMetricsReceiver, options isePxGridE2EOptions) {
	t.Helper()
	receiver.resetRequestStats()
	var (
		streamCtx context.Context
		cancel    context.CancelFunc
	)
	if options.streamRequireMessage {
		streamCtx, cancel = context.WithTimeout(t.Context(), options.streamTimeout)
	} else {
		streamCtx, cancel = context.WithCancel(t.Context())
	}
	defer cancel()

	messages := make(chan string, len(options.subscriptions))
	acknowledged := make(chan string, len(options.subscriptions))
	ready := make(chan string, len(options.subscriptions))
	results := make(chan isePxGridE2EStreamResult, len(options.subscriptions))
	readyTracker := &isePxGridE2EReadyTracker{
		expected: len(options.subscriptions),
		seen:     make(map[string]struct{}, len(options.subscriptions)),
		snapshot: func() isePxGridE2EStreamDependencyCounts {
			return snapshotISEPxGridE2EStreamDependencies(receiver)
		},
	}
	for _, subscription := range options.subscriptions {
		subscription := subscription
		go func() {
			var messageOnce sync.Once
			var acknowledgedOnce sync.Once
			handler := func(_ ise.StompMessage) error {
				messageOnce.Do(func() { messages <- subscription.Service })
				return nil
			}
			var err error
			if options.streamRequireMessage {
				err = receiver.pxGrid.SubscribeWithLifecycle(
					streamCtx,
					subscription,
					ise.PxGridSubscriptionLifecycle{
						Ready: func() {},
						Acknowledged: func() {
							acknowledgedOnce.Do(func() { acknowledged <- subscription.Service })
						},
					},
					handler,
				)
			} else {
				err = receiver.pxGrid.SubscribeWithReady(
					streamCtx,
					subscription,
					func() { readyTracker.signal(streamCtx, ready, subscription.Service) },
					handler,
				)
			}
			results <- isePxGridE2EStreamResult{service: subscription.Service, err: err}
		}()
	}

	var received map[string]int
	if options.streamRequireMessage {
		received = requireISEPxGridE2EMessageDelivery(t, options, streamCtx, cancel, messages, acknowledged, results)
	} else {
		setupTimeout := isePxGridE2EStreamSetupTimeout(receiver.config.Timeout, options.streamTimeout)
		received = requireISEPxGridE2EIdleWindow(t, options, cancel, setupTimeout, readyTracker, ready, messages, results)
	}

	receiver.statsMu.Lock()
	requestStats := append([]ise.RequestStat(nil), receiver.stats...)
	receiver.statsMu.Unlock()
	requireISEE2EOperationsSucceeded(
		t,
		"pxGrid streaming dependencies",
		requestStats,
		[]string{"pxgrid.access_secret", "pxgrid.service_lookup"},
		nil,
	)
	if options.streamRequireMessage {
		t.Logf("ISE pxGrid streaming validated message delivery and a completed ACK write for %d selected services; bodies were not logged", len(received))
	} else {
		t.Logf("ISE pxGrid streaming remained open for the bounded idle window across %d selected services; observed messages=%d and bodies were not logged", len(options.subscriptions), len(received))
	}
}

func (tracker *isePxGridE2EReadyTracker) signal(ctx context.Context, ready chan<- string, service string) {
	tracker.mu.Lock()
	tracker.seen[service] = struct{}{}
	if !tracker.baselineSet && len(tracker.seen) == tracker.expected {
		tracker.baseline = tracker.snapshot()
		tracker.baselineSet = true
	}
	tracker.mu.Unlock()
	select {
	case ready <- service:
	case <-ctx.Done():
	}
}

func (tracker *isePxGridE2EReadyTracker) dependencyBaseline() (isePxGridE2EStreamDependencyCounts, bool) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.baseline, tracker.baselineSet
}

func requireISEPxGridE2EMessageDelivery(
	t *testing.T,
	options isePxGridE2EOptions,
	streamCtx context.Context,
	cancel context.CancelFunc,
	messages <-chan string,
	acknowledged <-chan string,
	results <-chan isePxGridE2EStreamResult,
) map[string]int {
	t.Helper()
	received := make(map[string]int, len(options.subscriptions))
	acked := make(map[string]struct{}, len(options.subscriptions))
	for len(received) < len(options.subscriptions) || len(acked) < len(options.subscriptions) {
		select {
		case service := <-messages:
			received[service]++
		case service := <-acknowledged:
			acked[service] = struct{}{}
		case result := <-results:
			requireISEPxGridE2ENoEarlyStreamResult(t, "before delivering and acknowledging a message", result)
		case <-streamCtx.Done():
			require.FailNowf(
				t,
				"ISE pxGrid stream validation timed out",
				"%d of %d selected services delivered a message and %d of %d completed an ACK write",
				len(received),
				len(options.subscriptions),
				len(acked),
				len(options.subscriptions),
			)
		}
	}
	cancel()
	completed := collectISEPxGridE2EStreamResults(t, results, nil, len(options.subscriptions))
	requireISEPxGridE2ECleanStreamShutdown(t, completed, "after message delivery")
	return received
}

func requireISEPxGridE2EIdleWindow(
	t *testing.T,
	options isePxGridE2EOptions,
	cancel context.CancelFunc,
	setupTimeout time.Duration,
	readyTracker *isePxGridE2EReadyTracker,
	ready <-chan string,
	messages <-chan string,
	results <-chan isePxGridE2EStreamResult,
) map[string]int {
	t.Helper()
	setupCtx, cancelSetup := context.WithTimeout(t.Context(), setupTimeout)
	readyServices, completed, early, duplicateReady := waitForISEPxGridE2EReady(setupCtx, ready, results, len(options.subscriptions))
	cancelSetup()
	if early != nil {
		requireISEPxGridE2ENoEarlyStreamResult(t, "before STOMP subscription readiness", *early)
	}
	if duplicateReady != "" {
		requireISEPxGridE2ENoReconnect(t, cancel, results, completed, len(options.subscriptions), duplicateReady, "during readiness")
	}
	if len(readyServices) != len(options.subscriptions) {
		cancel()
		completed = collectISEPxGridE2EStreamResults(t, results, completed, len(options.subscriptions))
		requireISEPxGridE2ECleanStreamShutdown(t, completed, "after the readiness deadline")
		require.FailNowf(
			t,
			"ISE pxGrid stream readiness timed out",
			"%d of %d selected streams reached STOMP CONNECTED and sent SUBSCRIBE",
			len(readyServices),
			len(options.subscriptions),
		)
	}
	baselineDependencies, baselineSet := readyTracker.dependencyBaseline()
	if !baselineSet {
		cancel()
		completed = collectISEPxGridE2EStreamResults(t, results, completed, len(options.subscriptions))
		requireISEPxGridE2ECleanStreamShutdown(t, completed, "after missing readiness snapshot")
		require.FailNow(t, "ISE pxGrid stream readiness did not capture its dependency baseline")
	}
	idleCtx, cancelIdle := context.WithTimeout(t.Context(), options.streamTimeout)
	received, completed, early, duplicateReady := waitForISEPxGridE2EIdleWindow(idleCtx, ready, messages, results)
	cancelIdle()
	if early != nil {
		requireISEPxGridE2ENoEarlyStreamResult(t, "before the idle qualification window elapsed", *early)
	}
	if duplicateReady != "" {
		requireISEPxGridE2ENoReconnect(t, cancel, results, completed, len(options.subscriptions), duplicateReady, "during the idle qualification window")
	}
	cancel()
	completed = collectISEPxGridE2EStreamResults(t, results, completed, len(options.subscriptions))
	requireISEPxGridE2ECleanStreamShutdown(t, completed, "after the idle qualification window")
	postReadyDependencies := readyTracker.snapshot()
	if isePxGridE2EStreamDependenciesGrew(baselineDependencies, postReadyDependencies) {
		require.FailNowf(
			t,
			"ISE pxGrid stream performed dependency requests after readiness",
			"service_lookup attempts %d->%d; access_secret attempts %d->%d",
			baselineDependencies.serviceLookup,
			postReadyDependencies.serviceLookup,
			baselineDependencies.accessSecret,
			postReadyDependencies.accessSecret,
		)
	}
	return received
}

func isePxGridE2EStreamSetupTimeout(requestTimeout, streamTimeout time.Duration) time.Duration {
	if requestTimeout > 0 && requestTimeout < streamTimeout {
		return requestTimeout
	}
	return streamTimeout
}

func snapshotISEPxGridE2EStreamDependencies(receiver *iseMetricsReceiver) isePxGridE2EStreamDependencyCounts {
	receiver.statsMu.Lock()
	defer receiver.statsMu.Unlock()
	counts := isePxGridE2EStreamDependencyCounts{}
	for _, stat := range receiver.stats {
		switch stat.Operation {
		case "pxgrid.service_lookup":
			counts.serviceLookup++
		case "pxgrid.access_secret":
			counts.accessSecret++
		}
	}
	return counts
}

func isePxGridE2EStreamDependenciesGrew(before, after isePxGridE2EStreamDependencyCounts) bool {
	return after.serviceLookup > before.serviceLookup || after.accessSecret > before.accessSecret
}

func waitForISEPxGridE2EReady(
	ctx context.Context,
	ready <-chan string,
	results <-chan isePxGridE2EStreamResult,
	expected int,
) (map[string]struct{}, []isePxGridE2EStreamResult, *isePxGridE2EStreamResult, string) {
	readyServices := make(map[string]struct{}, expected)
	for len(readyServices) < expected {
		select {
		case service := <-ready:
			if _, duplicate := readyServices[service]; duplicate {
				return readyServices, nil, nil, service
			}
			readyServices[service] = struct{}{}
		case result := <-results:
			if ctx.Err() == nil {
				return readyServices, nil, &result, ""
			}
			return readyServices, []isePxGridE2EStreamResult{result}, nil, ""
		case <-ctx.Done():
			return readyServices, nil, nil, ""
		}
	}
	return readyServices, nil, nil, ""
}

func waitForISEPxGridE2EIdleWindow(
	ctx context.Context,
	ready <-chan string,
	messages <-chan string,
	results <-chan isePxGridE2EStreamResult,
) (map[string]int, []isePxGridE2EStreamResult, *isePxGridE2EStreamResult, string) {
	received := make(map[string]int)
	for {
		select {
		case service := <-ready:
			return received, nil, nil, service
		case service := <-messages:
			received[service]++
		case result := <-results:
			if ctx.Err() == nil {
				return received, nil, &result, ""
			}
			return received, []isePxGridE2EStreamResult{result}, nil, ""
		case <-ctx.Done():
			return received, nil, nil, ""
		}
	}
}

func requireISEPxGridE2ENoReconnect(
	t *testing.T,
	cancel context.CancelFunc,
	results <-chan isePxGridE2EStreamResult,
	completed []isePxGridE2EStreamResult,
	expected int,
	service, phase string,
) {
	t.Helper()
	cancel()
	completed = collectISEPxGridE2EStreamResults(t, results, completed, expected)
	requireISEPxGridE2ECleanStreamShutdown(t, completed, "after duplicate readiness")
	require.FailNowf(
		t,
		"ISE pxGrid stream reconnected "+phase,
		"service %s emitted more than one readiness signal; continuous-connection qualification requires exactly one",
		service,
	)
}

func collectISEPxGridE2EStreamResults(
	t *testing.T,
	results <-chan isePxGridE2EStreamResult,
	completed []isePxGridE2EStreamResult,
	expected int,
) []isePxGridE2EStreamResult {
	t.Helper()
	timer := time.NewTimer(iseE2EShutdownTimeout)
	defer timer.Stop()
	for len(completed) < expected {
		select {
		case result := <-results:
			completed = append(completed, result)
		case <-timer.C:
			require.FailNowf(t, "ISE pxGrid streams did not stop after cancellation", "%d of %d selected streams stopped", len(completed), expected)
		}
	}
	return completed
}

func requireISEPxGridE2ENoEarlyStreamResult(t *testing.T, phase string, result isePxGridE2EStreamResult) {
	t.Helper()
	require.FailNowf(
		t,
		"ISE pxGrid stream ended "+phase,
		"service %s failed with cause=%s; message, endpoint, header, and credential details are intentionally omitted",
		result.service,
		classifyISEPxGridE2EStreamFailure(result.err),
	)
}

func requireISEPxGridE2ECleanStreamShutdown(t *testing.T, results []isePxGridE2EStreamResult, phase string) {
	t.Helper()
	for _, result := range results {
		if !isePxGridE2EStreamEndedByContext(result.err) {
			require.FailNowf(
				t,
				"ISE pxGrid stream ended unexpectedly "+phase,
				"service %s failed with cause=%s; message, endpoint, header, and credential details are intentionally omitted",
				result.service,
				classifyISEPxGridE2EStreamFailure(result.err),
			)
		}
	}
}

func isePxGridE2EStreamEndedByContext(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func classifyISEPxGridE2EStreamFailure(err error) isePxGridE2EStreamFailure {
	if err == nil {
		return isePxGridE2EStreamFailureOther
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return isePxGridE2EStreamFailureContext
	}
	if httpclient.IsCertificateVerificationError(err) {
		return isePxGridE2EStreamFailureTLS
	}
	var websocketDialError *websocket.DialError
	if errors.As(err, &websocketDialError) {
		return isePxGridE2EStreamFailureWebSocketDial
	}

	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "origin is not authorized") || strings.Contains(message, "allowed_service_origins"):
		return isePxGridE2EStreamFailureOriginNotAllowed
	case strings.Contains(message, "has no documented topic property") ||
		strings.Contains(message, "missing properties.wspubsubservice or topic property"):
		return isePxGridE2EStreamFailureMissingTopic
	case strings.Contains(message, "access secret") || strings.Contains(message, "accesssecret"):
		return isePxGridE2EStreamFailureAccessSecret
	case (strings.Contains(message, "subscription service") && strings.Contains(message, " is unavailable")) ||
		(strings.Contains(message, "pubsub service") &&
			(strings.Contains(message, " is unavailable") || strings.Contains(message, "is missing nodename") || strings.Contains(message, "discover pubsub service"))):
		return isePxGridE2EStreamFailurePubSubUnavailable
	case strings.Contains(message, "stomp server returned an error frame"):
		return isePxGridE2EStreamFailureSTOMPErrorFrame
	case strings.Contains(message, "stomp expected connected"):
		return isePxGridE2EStreamFailureSTOMPHandshake
	case strings.Contains(message, "discover pxgrid subscription service"):
		return isePxGridE2EStreamFailureServiceDiscovery
	case strings.Contains(message, "websocket") &&
		(strings.Contains(message, "dial") || strings.Contains(message, "handshake") || strings.Contains(message, "bad status")):
		return isePxGridE2EStreamFailureWebSocketDial
	}

	var protocolError *websocket.ProtocolError
	if errors.As(err, &protocolError) || errors.Is(err, websocket.ErrFrameTooLarge) ||
		(strings.Contains(message, "pxgrid stomp") &&
			(strings.Contains(message, "malformed") || strings.Contains(message, "exceeds") ||
				strings.Contains(message, "ack identifier"))) {
		return isePxGridE2EStreamFailureProtocol
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return isePxGridE2EStreamFailureEOF
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return isePxGridE2EStreamFailureTimeout
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE) ||
		strings.Contains(message, "broken pipe") || strings.Contains(message, "connection reset") ||
		strings.Contains(message, "closed network connection") {
		return isePxGridE2EStreamFailureConnectionReset
	}
	if errors.As(err, &networkError) {
		return isePxGridE2EStreamFailureReadWrite
	}
	if strings.Contains(message, "read") || strings.Contains(message, "write") ||
		strings.Contains(message, "acknowledge") {
		return isePxGridE2EStreamFailureReadWrite
	}
	return isePxGridE2EStreamFailureOther
}

func TestISEPxGridE2EOperationSelectionRequiresExplicitActivation(t *testing.T) {
	t.Setenv(iseE2EPxGridOperationsEnv, "pxgrid.version")
	selected := configureISEPxGridE2EOperations(t, false)
	require.Equal(t, map[string]struct{}{"pxgrid.version": {}}, selected)
	assert.Empty(t, isePxGridE2EDynamicOperations(selected))
}

func TestISEPxGridE2EExactVersionScrapeUpdatesHealth(t *testing.T) {
	var requestedPaths []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.Path)
		if r.URL.Path != "/pxgrid/control/version" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"version":"2.0"}`))
	}))
	defer server.Close()

	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.Timeout = time.Second
	cfg.ISE = defaultISEConfig()
	cfg.ISE.Enabled = true
	cfg.ISE.Endpoint = server.URL
	cfg.ISE.Auth.Username = "unused"
	cfg.ISE.Auth.Password = configopaque.String("unused")
	cfg.ISE.InsecureSkipVerify = true
	for name := range cfg.ISE.groups() {
		require.True(t, setISEE2ERESTGroup(&cfg.ISE, name, ISEGroupConfig{MaxResults: 3}))
	}
	cfg.ISE.PxGrid.Enabled = true
	cfg.ISE.PxGrid.Endpoint = server.URL + "/pxgrid"
	cfg.ISE.PxGrid.NodeName = "collector"
	cfg.ISE.PxGrid.Password = configopaque.String("account-password")
	cfg.ISE.PxGrid.InsecureSkipVerify = true
	cfg.ISE.PxGrid.MaxResults = 3
	receiver, err := newISEMetricsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)

	options := isePxGridE2EOptions{operations: map[string]struct{}{"pxgrid.version": {}}}
	md, counts, lookups, err := scrapeISEPxGridE2EMetrics(t.Context(), receiver, options)
	require.NoError(t, err)
	assert.Equal(t, []string{"/pxgrid/control/version"}, requestedPaths)
	assert.Equal(t, map[string]int{"pxgrid.version": 1}, counts)
	assert.Empty(t, lookups)
	requireISEE2EOperationsSucceeded(t, "pxGrid self-test", receiver.stats, []string{"pxgrid.version"}, nil)
	requireISEE2EIntGaugeValue(t, md, "ise.controller.up", 1)
	requireISEE2EIntGaugeValue(t, md, "ise.scrape.partial_success", 0)
}

func TestISEPxGridE2EQueryDependenciesAreBounded(t *testing.T) {
	selected := map[string]struct{}{"pxgrid.session.get_sessions": {}}
	assert.Equal(t, map[string]struct{}{
		"pxgrid.access_secret":  {},
		"pxgrid.service_lookup": {},
	}, isePxGridE2EDynamicOperations(selected))
}

func TestISEPxGridE2ESubscriptionsRequireStreamingOptIn(t *testing.T) {
	t.Setenv(iseE2EPxGridSubscriptionsEnv, "session,radius_failures")
	subscriptions := configureISEPxGridE2ESubscriptions(t, true)
	require.Len(t, subscriptions, 2)
	configured := isePxGridE2ESubscriptionConfig(subscriptions)
	assert.True(t, configured.Session)
	assert.True(t, configured.RadiusFailures)
	assert.False(t, configured.Endpoint)
	assert.False(t, configured.TrustSec)
}

func TestISEPxGridE2EStreamRequireMessageDefaultsTrue(t *testing.T) {
	t.Setenv(iseE2EPxGridStreamRequireMessageEnv, "")
	assert.True(t, isePxGridE2EStreamRequireMessage(t))
	t.Setenv(iseE2EPxGridStreamRequireMessageEnv, "false")
	assert.False(t, isePxGridE2EStreamRequireMessage(t))
}

func TestWaitForISEPxGridE2EIdleWindowAllowsZeroMessagesAtTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	received, completed, early, duplicateReady := waitForISEPxGridE2EIdleWindow(
		ctx,
		make(chan string),
		make(chan string),
		make(chan isePxGridE2EStreamResult),
	)
	assert.Empty(t, received)
	assert.Empty(t, completed)
	assert.Nil(t, early)
	assert.Empty(t, duplicateReady)
}

func TestWaitForISEPxGridE2EReadyRequiresEverySubscription(t *testing.T) {
	ready := make(chan string, 2)
	ready <- "com.cisco.ise.session"
	ready <- "com.cisco.ise.radius"
	services, completed, early, duplicateReady := waitForISEPxGridE2EReady(
		t.Context(),
		ready,
		make(chan isePxGridE2EStreamResult),
		2,
	)
	assert.Equal(t, map[string]struct{}{
		"com.cisco.ise.radius":  {},
		"com.cisco.ise.session": {},
	}, services)
	assert.Empty(t, completed)
	assert.Nil(t, early)
	assert.Empty(t, duplicateReady)
}

func TestWaitForISEPxGridE2EReadyReturnsEarlySubscriptionExit(t *testing.T) {
	results := make(chan isePxGridE2EStreamResult, 1)
	results <- isePxGridE2EStreamResult{service: "com.cisco.ise.session", err: errors.New("handshake failed")}
	services, completed, early, duplicateReady := waitForISEPxGridE2EReady(t.Context(), make(chan string), results, 1)
	assert.Empty(t, services)
	assert.Empty(t, completed)
	require.NotNil(t, early)
	assert.Equal(t, "com.cisco.ise.session", early.service)
	assert.Empty(t, duplicateReady)
}

func TestWaitForISEPxGridE2EReadyRejectsDuplicateService(t *testing.T) {
	ready := make(chan string, 2)
	ready <- "com.cisco.ise.session"
	ready <- "com.cisco.ise.session"
	services, completed, early, duplicateReady := waitForISEPxGridE2EReady(
		t.Context(),
		ready,
		make(chan isePxGridE2EStreamResult),
		2,
	)
	assert.Equal(t, map[string]struct{}{"com.cisco.ise.session": {}}, services)
	assert.Empty(t, completed)
	assert.Nil(t, early)
	assert.Equal(t, "com.cisco.ise.session", duplicateReady)
}

func TestWaitForISEPxGridE2EIdleWindowRejectsReconnectReadiness(t *testing.T) {
	ready := make(chan string, 1)
	ready <- "com.cisco.ise.session"
	received, completed, early, duplicateReady := waitForISEPxGridE2EIdleWindow(
		t.Context(),
		ready,
		make(chan string),
		make(chan isePxGridE2EStreamResult),
	)
	assert.Empty(t, received)
	assert.Empty(t, completed)
	assert.Nil(t, early)
	assert.Equal(t, "com.cisco.ise.session", duplicateReady)
}

func TestISEPxGridE2EReadySignalDoesNotBlockAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	tracker := &isePxGridE2EReadyTracker{
		expected: 1,
		seen:     make(map[string]struct{}),
		snapshot: func() isePxGridE2EStreamDependencyCounts { return isePxGridE2EStreamDependencyCounts{} },
	}
	tracker.signal(ctx, make(chan string), "com.cisco.ise.session")
	baseline, ok := tracker.dependencyBaseline()
	assert.True(t, ok)
	assert.Equal(t, isePxGridE2EStreamDependencyCounts{}, baseline)
}

func TestWaitForISEPxGridE2EIdleWindowReturnsEarlySubscriptionExit(t *testing.T) {
	results := make(chan isePxGridE2EStreamResult, 1)
	results <- isePxGridE2EStreamResult{service: "com.cisco.ise.session", err: errors.New("early failure")}
	received, completed, early, duplicateReady := waitForISEPxGridE2EIdleWindow(t.Context(), make(chan string), make(chan string), results)
	assert.Empty(t, received)
	assert.Empty(t, completed)
	require.NotNil(t, early)
	assert.Equal(t, "com.cisco.ise.session", early.service)
	assert.Equal(t, isePxGridE2EStreamFailureOther, classifyISEPxGridE2EStreamFailure(early.err))
	assert.Empty(t, duplicateReady)
}

func TestRequireISEPxGridE2EMessageDeliveryWaitsForEveryAckWrite(t *testing.T) {
	services := []string{"com.cisco.ise.session", "com.cisco.ise.radius"}
	options := isePxGridE2EOptions{subscriptions: []ise.PxGridSubscription{
		{Service: services[0]},
		{Service: services[1]},
	}}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	messages := make(chan string, len(services))
	acknowledged := make(chan string, len(services))
	results := make(chan isePxGridE2EStreamResult, len(services))
	for _, service := range services {
		messages <- service
	}
	// Reverse ACK order to prove accounting is per service rather than tied to
	// channel arrival order.
	acknowledged <- services[1]
	acknowledged <- services[0]
	go func() {
		<-ctx.Done()
		for _, service := range services {
			results <- isePxGridE2EStreamResult{service: service, err: ctx.Err()}
		}
	}()

	received := requireISEPxGridE2EMessageDelivery(t, options, ctx, cancel, messages, acknowledged, results)
	assert.Equal(t, map[string]int{services[0]: 1, services[1]: 1}, received)
}

func TestISEPxGridE2EStreamEndedByContext(t *testing.T) {
	assert.True(t, isePxGridE2EStreamEndedByContext(context.Canceled))
	assert.True(t, isePxGridE2EStreamEndedByContext(fmt.Errorf("wrapped: %w", context.DeadlineExceeded)))
	assert.False(t, isePxGridE2EStreamEndedByContext(nil))
	assert.False(t, isePxGridE2EStreamEndedByContext(errors.New("transport failed")))
}

func TestISEPxGridE2EStreamSetupTimeoutIsBounded(t *testing.T) {
	assert.Equal(t, 20*time.Second, isePxGridE2EStreamSetupTimeout(20*time.Second, 30*time.Second))
	assert.Equal(t, 30*time.Second, isePxGridE2EStreamSetupTimeout(time.Minute, 30*time.Second))
	assert.Equal(t, 30*time.Second, isePxGridE2EStreamSetupTimeout(0, 30*time.Second))
}

func TestISEPxGridE2EStreamDependencyGrowth(t *testing.T) {
	current := isePxGridE2EStreamDependencyCounts{serviceLookup: 2, accessSecret: 2}
	tracker := &isePxGridE2EReadyTracker{
		expected: 2,
		seen:     make(map[string]struct{}),
		snapshot: func() isePxGridE2EStreamDependencyCounts { return current },
	}
	ready := make(chan string, 2)
	tracker.signal(t.Context(), ready, "com.cisco.ise.session")
	_, baselineSet := tracker.dependencyBaseline()
	assert.False(t, baselineSet)
	tracker.signal(t.Context(), ready, "com.cisco.ise.radius")
	baseline, baselineSet := tracker.dependencyBaseline()
	require.True(t, baselineSet)
	assert.Equal(t, current, baseline)
	assert.False(t, isePxGridE2EStreamDependenciesGrew(baseline, current))
	current.accessSecret++
	assert.True(t, isePxGridE2EStreamDependenciesGrew(baseline, current))
}

func TestClassifyISEPxGridE2EStreamFailure(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected isePxGridE2EStreamFailure
	}{
		{name: "nil", expected: isePxGridE2EStreamFailureOther},
		{name: "context", err: fmt.Errorf("wrapped: %w", context.DeadlineExceeded), expected: isePxGridE2EStreamFailureContext},
		{name: "missing topic", err: errors.New("service entry is missing properties.wsPubsubService or topic property sessionTopic"), expected: isePxGridE2EStreamFailureMissingTopic},
		{name: "pubsub unavailable", err: errors.New(`pubsub service "com.cisco.ise.pubsub" is unavailable`), expected: isePxGridE2EStreamFailurePubSubUnavailable},
		{name: "origin", err: errors.New("discovered pxGrid origin is not authorized by allowed_service_origins: wss://sensitive.example:8910"), expected: isePxGridE2EStreamFailureOriginNotAllowed},
		{name: "access secret", err: errors.New(`pubsub node "sensitive-node" access secret: denied`), expected: isePxGridE2EStreamFailureAccessSecret},
		{name: "websocket dial", err: &websocket.DialError{Err: errors.New("dial wss://user:secret@sensitive.example:8910 failed")}, expected: isePxGridE2EStreamFailureWebSocketDial},
		{name: "tls", err: &httpclient.CertificateVerificationError{Err: errors.New("certificate for sensitive.example failed")}, expected: isePxGridE2EStreamFailureTLS},
		{name: "stomp error frame", err: errors.New("pxGrid STOMP server returned an error frame"), expected: isePxGridE2EStreamFailureSTOMPErrorFrame},
		{name: "stomp handshake", err: errors.New("pxGrid STOMP expected CONNECTED, got MESSAGE"), expected: isePxGridE2EStreamFailureSTOMPHandshake},
		{name: "eof", err: fmt.Errorf("receive message: %w", io.ErrUnexpectedEOF), expected: isePxGridE2EStreamFailureEOF},
		{name: "timeout", err: &net.DNSError{Err: "i/o timeout", IsTimeout: true}, expected: isePxGridE2EStreamFailureTimeout},
		{name: "protocol", err: fmt.Errorf("receive message: %w", websocket.ErrBadFrame), expected: isePxGridE2EStreamFailureProtocol},
		{name: "connection reset", err: fmt.Errorf("read socket: %w", syscall.ECONNRESET), expected: isePxGridE2EStreamFailureConnectionReset},
		{name: "read write", err: errors.New("read socket failed"), expected: isePxGridE2EStreamFailureReadWrite},
		{name: "service discovery", err: errors.New(`discover pxGrid subscription service "sensitive": unauthorized`), expected: isePxGridE2EStreamFailureServiceDiscovery},
		{name: "other", err: errors.New("opaque failure containing secret-value and https://sensitive.example/path"), expected: isePxGridE2EStreamFailureOther},
	}
	allowed := map[isePxGridE2EStreamFailure]struct{}{
		isePxGridE2EStreamFailureMissingTopic:      {},
		isePxGridE2EStreamFailurePubSubUnavailable: {},
		isePxGridE2EStreamFailureOriginNotAllowed:  {},
		isePxGridE2EStreamFailureAccessSecret:      {},
		isePxGridE2EStreamFailureWebSocketDial:     {},
		isePxGridE2EStreamFailureTLS:               {},
		isePxGridE2EStreamFailureSTOMPErrorFrame:   {},
		isePxGridE2EStreamFailureSTOMPHandshake:    {},
		isePxGridE2EStreamFailureEOF:               {},
		isePxGridE2EStreamFailureTimeout:           {},
		isePxGridE2EStreamFailureProtocol:          {},
		isePxGridE2EStreamFailureConnectionReset:   {},
		isePxGridE2EStreamFailureReadWrite:         {},
		isePxGridE2EStreamFailureContext:           {},
		isePxGridE2EStreamFailureServiceDiscovery:  {},
		isePxGridE2EStreamFailureOther:             {},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := classifyISEPxGridE2EStreamFailure(test.err)
			assert.Equal(t, test.expected, actual)
			assert.Contains(t, allowed, actual)
			assert.NotContains(t, string(actual), "sensitive")
			assert.NotContains(t, string(actual), "secret-value")
			assert.NotContains(t, string(actual), "user:secret")
			assert.NotContains(t, string(actual), "://")
		})
	}
}
