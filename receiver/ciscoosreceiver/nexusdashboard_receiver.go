// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/nexusdashboard"
)

const nexusDashboardScopeName = "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/nexusdashboard"

// classifyNexusDashboardError buckets an error into a small, fixed set of
// categories so it can be used as a metric attribute without exploding metric
// cardinality. Raw err.Error() (which embeds the HTTP response body) must never
// be used as a Sum attribute.
func classifyNexusDashboardError(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	var apiErr *nexusdashboard.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return "auth"
		case http.StatusNotFound:
			return "not_found"
		case http.StatusTooManyRequests:
			return "rate_limited"
		case http.StatusRequestTimeout, http.StatusGatewayTimeout:
			return "timeout"
		default:
			if apiErr.StatusCode >= 500 {
				return "transport"
			}
			return "other"
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return "timeout"
		}
		return "transport"
	}
	if strings.Contains(err.Error(), "decode") {
		return "decode"
	}
	return "other"
}

type nexusDashboardMetricsReceiver struct {
	settings receiver.Settings
	config   *Config
	consumer consumer.Metrics
	client   *nexusdashboard.Client
	counters *counterStore
	obs      *receiverhelper.ObsReport
	success  scrapeSuccessState

	startMu sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}

	statsMu sync.Mutex
	stats   []nexusdashboard.RequestStat
}

type nexusDashboardLogsReceiver struct {
	settings receiver.Settings
	config   *Config
	consumer consumer.Logs
	client   *nexusdashboard.Client
	obs      *receiverhelper.ObsReport

	startMu sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}

	seen *logDeduplicator
}

type nexusDashboardEndpoint struct {
	group       string
	operation   string
	path        string
	objectType  string
	product     string
	selectorKey string
	query       func(*Config, time.Time) url.Values
}

type nexusDashboardEndpointInstance struct {
	nexusDashboardEndpoint
	path    string
	attrs   map[string]string
	skipped bool
}

func newNexusDashboardMetricsReceiver(set receiver.Settings, conf *Config, consumer consumer.Metrics) (*nexusDashboardMetricsReceiver, error) {
	client, err := newNexusDashboardClient(conf)
	if err != nil {
		return nil, err
	}
	r := &nexusDashboardMetricsReceiver{
		settings: set,
		config:   conf,
		consumer: consumer,
		client:   client,
		counters: newCounterStore(),
		obs:      newPlatformObsReport(set, "http"),
		done:     make(chan struct{}),
	}
	client.OnRequest = r.recordRequest
	return r, nil
}

func newNexusDashboardLogsReceiver(set receiver.Settings, conf *Config, consumer consumer.Logs) (*nexusDashboardLogsReceiver, error) {
	client, err := newNexusDashboardClient(conf)
	if err != nil {
		return nil, err
	}
	return &nexusDashboardLogsReceiver{
		settings: set,
		config:   conf,
		consumer: consumer,
		client:   client,
		obs:      newPlatformObsReport(set, "http"),
		done:     make(chan struct{}),
		seen:     newLogDeduplicator(),
	}, nil
}

func newNexusDashboardClient(conf *Config) (*nexusdashboard.Client, error) {
	return nexusdashboard.NewClient(nexusdashboard.Config{
		Endpoint:           conf.NexusDashboard.Endpoint,
		AuthMode:           inferredControllerAuthMode(conf.NexusDashboard.Auth),
		Username:           conf.NexusDashboard.Auth.Username,
		Password:           string(conf.NexusDashboard.Auth.Password),
		APIKey:             string(conf.NexusDashboard.Auth.APIKey),
		Domain:             conf.NexusDashboard.Auth.Domain,
		UserAgent:          conf.NexusDashboard.UserAgent,
		Timeout:            conf.Timeout,
		MaxRetries:         conf.NexusDashboard.MaxRetries,
		PageSize:           conf.NexusDashboard.PageSize,
		InsecureSkipVerify: conf.NexusDashboard.InsecureSkipVerify,
	})
}

func (r *nexusDashboardMetricsReceiver) Start(_ context.Context, _ component.Host) error {
	r.startMu.Lock()
	defer r.startMu.Unlock()
	if r.cancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go r.run(ctx)
	return nil
}

func (r *nexusDashboardMetricsReceiver) Shutdown(ctx context.Context) error {
	r.startMu.Lock()
	cancel := r.cancel
	r.startMu.Unlock()
	if cancel == nil {
		r.client.CloseIdleConnections()
		return nil
	}
	cancel()
	defer r.client.CloseIdleConnections()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *nexusDashboardMetricsReceiver) run(ctx context.Context) {
	defer close(r.done)
	r.collect(ctx)
	ticker := time.NewTicker(r.config.CollectionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.collect(ctx)
		}
	}
}

func (r *nexusDashboardMetricsReceiver) collect(ctx context.Context) {
	scrapeCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()

	obsCtx := startMetricsOp(ctx, r.obs)
	md, scrapeErr := r.scrape(scrapeCtx)
	if scrapeErr != nil {
		r.settings.Logger.Error("Nexus Dashboard scrape failed", zap.Error(scrapeErr))
	}
	metricCount, consumeErr := consumeMetricsIfPresent(ctx, r.consumer, md)
	if consumeErr != nil {
		r.settings.Logger.Error("Nexus Dashboard metrics consumer failed", zap.Error(consumeErr))
	}
	endMetricsOp(obsCtx, r.obs, metricCount, combineSignalErrors(scrapeErr, consumeErr))
}

func (r *nexusDashboardMetricsReceiver) scrape(ctx context.Context) (pmetric.Metrics, error) {
	r.resetRequestStats()
	now := time.Now()
	builder := newNexusDashboardMetricsBuilder(now, r.config.NexusDashboard.Endpoint, r.counters)
	selector := newDeviceSelectionMatcher(r.config.DeviceSelection)
	partial := false

	endpoints := nexusDashboardMetricEndpointInstances(r.config)
	for i := range endpoints {
		endpoint := &endpoints[i]
		if !nexusDashboardGroupEnabled(r.config.NexusDashboard, endpoint.group) {
			continue
		}
		if endpoint.skipped {
			partial = true
			builder.recordSkippedEndpoint(*endpoint)
			continue
		}
		objects, err := r.client.List(ctx, endpoint.operation, endpoint.path, nexusDashboardEndpointQuery(endpoint.nexusDashboardEndpoint, r.config, now), nexusDashboardGroupMaxResults(r.config.NexusDashboard, endpoint.group))
		for _, obj := range filterNexusDashboardObjects(objects, r.config.NexusDashboard.Targets) {
			if !selector.allows(nexusDashboardObjectIdentity(obj)) {
				continue
			}
			builder.recordObject(*endpoint, obj)
		}
		if err != nil {
			if ctx.Err() != nil {
				partial = true
				return r.finishScrape(builder, now, partial), ctx.Err()
			}
			partial = true
			builder.recordFailedEndpoint(*endpoint, err)
			r.settings.Logger.Warn("Nexus Dashboard endpoint failed", zap.String("operation", endpoint.operation), zap.Error(err))
			continue
		}
	}

	return r.finishScrape(builder, now, partial), nil
}

func (r *nexusDashboardMetricsReceiver) finishScrape(builder *nexusDashboardMetricsBuilder, _ time.Time, partial bool) pmetric.Metrics {
	r.recordAPIRequestMetrics(builder)
	r.statsMu.Lock()
	stats := append([]nexusdashboard.RequestStat(nil), r.stats...)
	r.statsMu.Unlock()
	outcome := summarizeAPIOutcomes(stats, func(stat nexusdashboard.RequestStat) string { return stat.Outcome })
	rb := builder.controllerResource()
	rb.recordInt("nexus_dashboard.scrape.partial_success", "Whether one or more Nexus Dashboard endpoint families failed or were skipped during the scrape.", "1", boolToInt(partial), nil)
	if lastSuccess, ok := r.success.observe(time.Now(), !partial && outcome.succeeded); ok {
		rb.recordInt("nexus_dashboard.scrape.last_success", "Unix timestamp of the most recent fully successful Nexus Dashboard scrape.", "s", lastSuccess.Unix(), nil)
	}
	builder.flushCounts()
	return builder.emit()
}

func (r *nexusDashboardMetricsReceiver) recordRequest(stat nexusdashboard.RequestStat) {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats = append(r.stats, stat)
}

func (r *nexusDashboardMetricsReceiver) resetRequestStats() {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats = nil
}

func (r *nexusDashboardMetricsReceiver) recordAPIRequestMetrics(builder *nexusDashboardMetricsBuilder) {
	r.statsMu.Lock()
	stats := append([]nexusdashboard.RequestStat(nil), r.stats...)
	r.statsMu.Unlock()
	observations := make([]apiRequestObservation, 0, len(stats))
	for _, stat := range stats {
		attrs := map[string]string{
			"nexus_dashboard.api.operation": stat.Operation,
			"http.request.method":           stat.Method,
			"nexus_dashboard.api.path":      stat.Path,
			"nexus_dashboard.api.outcome":   stat.Outcome,
		}
		if stat.StatusCode > 0 {
			attrs["http.response.status_code"] = strconv.Itoa(stat.StatusCode)
		}
		observations = append(observations, apiRequestObservation{attrs: attrs, durationSeconds: stat.Duration.Seconds(), failed: stat.Outcome != "success", rateLimited: stat.RateLimited})
	}
	for _, aggregate := range aggregateAPIRequestObservations(observations) {
		rb := builder.controllerResource()
		rb.recordDouble("nexus_dashboard.api.request.duration", "Average duration of Nexus Dashboard API request attempts in this scrape.", "s", aggregate.averageDurationSeconds, aggregate.attrs)
		if aggregate.errors > 0 {
			rb.recordSum("nexus_dashboard.api.request.errors", "Nexus Dashboard API request errors.", "{error}", aggregate.errors, aggregate.attrs)
		}
		if aggregate.rateLimited > 0 {
			rb.recordSum("nexus_dashboard.api.rate_limited", "Nexus Dashboard API requests that were rate limited.", "{request}", aggregate.rateLimited, aggregate.attrs)
		}
	}
}

func (r *nexusDashboardLogsReceiver) Start(_ context.Context, _ component.Host) error {
	r.startMu.Lock()
	defer r.startMu.Unlock()
	if r.cancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go r.run(ctx)
	return nil
}

func (r *nexusDashboardLogsReceiver) Shutdown(ctx context.Context) error {
	r.startMu.Lock()
	cancel := r.cancel
	r.startMu.Unlock()
	if cancel == nil {
		r.client.CloseIdleConnections()
		return nil
	}
	cancel()
	defer r.client.CloseIdleConnections()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *nexusDashboardLogsReceiver) run(ctx context.Context) {
	defer close(r.done)
	r.collect(ctx)
	ticker := time.NewTicker(r.config.CollectionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.collect(ctx)
		}
	}
}

func (r *nexusDashboardLogsReceiver) collect(ctx context.Context) {
	scrapeCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()

	r.seen.BeginBatch()
	obsCtx := startLogsOp(ctx, r.obs)
	ld, scrapeErr := r.scrape(scrapeCtx)
	if scrapeErr != nil {
		r.settings.Logger.Error("Nexus Dashboard log scrape failed", zap.Error(scrapeErr))
	}
	logCount, consumeErr := consumeDeduplicatedLogs(ctx, r.consumer, r.seen, ld)
	if consumeErr != nil {
		r.settings.Logger.Error("Nexus Dashboard logs consumer failed", zap.Error(consumeErr))
	}
	endLogsOp(obsCtx, r.obs, logCount, combineSignalErrors(scrapeErr, consumeErr))
}

func (r *nexusDashboardLogsReceiver) scrape(ctx context.Context) (plog.Logs, error) {
	ld := plog.NewLogs()
	now := time.Now()
	var endpointErrors []error
	selector := newDeviceSelectionMatcher(r.config.DeviceSelection)
	endpoints := nexusDashboardLogEndpointInstances(r.config)
	for i := range endpoints {
		endpoint := &endpoints[i]
		if !nexusDashboardGroupEnabled(r.config.NexusDashboard, endpoint.group) || endpoint.skipped {
			continue
		}
		objects, err := r.client.List(ctx, endpoint.operation, endpoint.path, nexusDashboardEndpointQuery(endpoint.nexusDashboardEndpoint, r.config, now), nexusDashboardGroupMaxResults(r.config.NexusDashboard, endpoint.group))
		for _, obj := range filterNexusDashboardObjects(objects, r.config.NexusDashboard.Targets) {
			if !selector.allows(nexusDashboardObjectIdentity(obj)) {
				continue
			}
			if r.seenBefore(*endpoint, obj, now) {
				continue
			}
			appendNexusDashboardLog(ld, *endpoint, obj, r.config.NexusDashboard.Endpoint, now)
		}
		if err != nil {
			if ctx.Err() != nil {
				return ld, ctx.Err()
			}
			r.settings.Logger.Warn("Nexus Dashboard log endpoint failed", zap.String("operation", endpoint.operation), zap.Error(err))
			endpointErrors = append(endpointErrors, fmt.Errorf("Nexus Dashboard %s: %w", endpoint.operation, err))
			continue
		}
	}
	r.expireSeen(now)
	return ld, errors.Join(endpointErrors...)
}

func (r *nexusDashboardLogsReceiver) seenBefore(endpoint nexusDashboardEndpointInstance, obj nexusdashboard.Object, now time.Time) bool {
	stableID := nexusdashboard.String(obj, "id", "uuid", "eventId", "eventID", "auditId", "recordId", "dn")
	key := logDedupKey(endpoint.operation, stableID, obj)
	return !r.seen.MarkPending(key, now)
}

func (r *nexusDashboardLogsReceiver) expireSeen(now time.Time) {
	ttl := r.config.NexusDashboard.EventLookback
	if ttl <= 0 {
		ttl = defaultNexusDashboardConfig().EventLookback
	}
	ttl *= 2
	r.seen.Expire(now.Add(-ttl), 0)
}

type nexusDashboardMetricsBuilder struct {
	metrics   pmetric.Metrics
	now       pcommon.Timestamp
	start     pcommon.Timestamp
	resources map[string]*resourceMetricsBuilder
	counts    map[string]*nexusDashboardCount
	endpoint  string
	counters  *counterStore
}

type nexusDashboardCount struct {
	value int64
	attrs map[string]string
}

func newNexusDashboardMetricsBuilder(now time.Time, endpoint string, counters *counterStore) *nexusDashboardMetricsBuilder {
	if counters == nil {
		counters = newCounterStore()
	}
	ts := pcommon.NewTimestampFromTime(now)
	return &nexusDashboardMetricsBuilder{
		metrics:   pmetric.NewMetrics(),
		now:       ts,
		start:     pcommon.NewTimestampFromTime(counters.StartTime()),
		resources: map[string]*resourceMetricsBuilder{},
		counts:    map[string]*nexusDashboardCount{},
		endpoint:  endpoint,
		counters:  counters,
	}
}

func (b *nexusDashboardMetricsBuilder) emit() pmetric.Metrics {
	return b.metrics
}

func (b *nexusDashboardMetricsBuilder) controllerResource() *resourceMetricsBuilder {
	rb := b.resource("controller")
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", "nexus-dashboard:"+b.endpoint)
	putStr(attrs, "host.name", "Nexus Dashboard")
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Nexus Dashboard")
	putStr(attrs, "cisco.controller.type", "nexus_dashboard")
	putStr(attrs, "cisco.controller.endpoint", b.endpoint)
	return rb
}

func (b *nexusDashboardMetricsBuilder) objectResource(endpoint nexusDashboardEndpointInstance, obj nexusdashboard.Object) *resourceMetricsBuilder {
	serial := firstNonEmpty(nexusdashboard.String(obj, "serialNumber", "serialNo", "serial", "switchSerialNo", "switchSerial"), endpoint.attrs["cisco.switch.serial"])
	switchID := firstNonEmpty(nexusdashboard.String(obj, "switchDbId", "switchId", "nodeId", "id"), endpoint.attrs["ndfc.switch.id"])
	hostID := firstNonEmpty(serial, switchID, nexusdashboard.String(obj, "hostName", "hostname", "switchName", "name", "nodeName", "siteName", "fabricName"), endpoint.operation)
	rb := b.resource(endpoint.operation + ":" + hostID)
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", hostID)
	putStr(attrs, "host.name", firstNonEmpty(nexusdashboard.String(obj, "hostName", "hostname", "switchName", "nodeName", "name"), hostID))
	putIPAttrs(attrs, "host.ip", nexusdashboard.String(obj, "ipAddress"), nexusdashboard.String(obj, "ip"), nexusdashboard.String(obj, "mgmtIpAddress"), nexusdashboard.String(obj, "managementIp"), nexusdashboard.String(obj, "oobMgmtIpAddress"))
	putStr(attrs, "host.type", firstNonEmpty(nexusdashboard.String(obj, "model", "platform", "deviceType", "role"), endpoint.objectType))
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", firstNonEmpty(nexusdashboard.String(obj, "osType", "imageName"), "NX-OS"))
	putStr(attrs, "os.version", nexusdashboard.String(obj, "release", "version", "nxosVersion", "softwareVersion"))
	putStr(attrs, "cisco.controller.type", "nexus_dashboard")
	putStr(attrs, "cisco.controller.endpoint", b.endpoint)
	putStr(attrs, "cisco.fabric.name", firstNonEmpty(nexusdashboard.String(obj, "fabricName", "fabric"), endpoint.attrs["cisco.fabric.name"]))
	putStr(attrs, "cisco.site.name", firstNonEmpty(nexusdashboard.String(obj, "siteName", "site"), endpoint.attrs["cisco.site.name"]))
	putStr(attrs, "cisco.switch.role", nexusdashboard.String(obj, "role", "switchRole", "nodeRole"))
	putStr(attrs, "cisco.switch.serial", serial)
	putStr(attrs, "ndfc.switch.id", switchID)
	putStr(attrs, "nd.service.name", firstNonEmpty(nexusdashboard.String(obj, "serviceName", "appName", "featureName"), endpoint.attrs["nd.service.name"]))
	putStr(attrs, "nexus_dashboard.product", endpoint.product)
	putStr(attrs, "nexus_dashboard.resource.type", endpoint.objectType)
	return rb
}

func (b *nexusDashboardMetricsBuilder) resource(key string) *resourceMetricsBuilder {
	if rb := b.resources[key]; rb != nil {
		return rb
	}
	rm := b.metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName(nexusDashboardScopeName)
	rb := &resourceMetricsBuilder{
		resource:         rm.Resource(),
		scope:            sm,
		metrics:          map[string]pmetric.Metric{},
		now:              b.now,
		start:            b.start,
		counterNamespace: key,
		counters:         b.counters,
	}
	b.resources[key] = rb
	return rb
}

func (b *nexusDashboardMetricsBuilder) recordObject(endpoint nexusDashboardEndpointInstance, obj nexusdashboard.Object) {
	rb := b.objectResource(endpoint, obj)
	status := nexusDashboardObjectStatus(obj)
	severity := strings.ToLower(firstNonEmpty(nexusdashboard.String(obj, "severity", "Severity", "level"), status))
	attrs := compactAttrs(map[string]string{
		"nexus_dashboard.product":       endpoint.product,
		"nexus_dashboard.group":         endpoint.group,
		"nexus_dashboard.resource.type": endpoint.objectType,
		"nexus_dashboard.status":        status,
		"nexus_dashboard.severity":      severity,
	})
	rb.recordInt("nexus_dashboard.resource.info", "Nexus Dashboard resource metadata.", "1", 1, attrs)
	if code, ok := statusCode(status); ok {
		rb.recordInt("nexus_dashboard.resource.status", "Nexus Dashboard resource status encoded for troubleshooting.", "1", code, attrs)
	}
	b.addCount("nexus_dashboard.resource.count", attrs)
	evidenceAttrs := compactAttrs(map[string]string{
		"nexus_dashboard.product":       endpoint.product,
		"nexus_dashboard.group":         endpoint.group,
		"nexus_dashboard.operation":     endpoint.operation,
		"nexus_dashboard.resource.type": endpoint.objectType,
		"nexus_dashboard.status":        firstNonEmpty(status, "present"),
		"nexus_dashboard.severity":      firstNonEmpty(severity, "unknown"),
	})
	switch nexusDashboardEvidenceMetric(endpoint) {
	case "audit":
		b.addCount("nexus_dashboard.audit.record.count", evidenceAttrs)
	case "event":
		b.addCount("nexus_dashboard.event.count", evidenceAttrs)
	}

	switch endpoint.group {
	case "platform":
		b.recordPlatformObject(rb, obj, status)
	case "ndfc":
		b.recordNDFCObject(rb, obj, status)
	case "insights":
		b.recordInsightsObject(rb, obj, status, severity)
	case "orchestrator":
		b.recordOrchestratorObject(rb, obj, status)
	case "data_broker":
		b.recordDataBrokerObject(rb, obj, status)
	case "performance":
		b.recordPerformanceObject(rb, obj)
	}
}

func (*nexusDashboardMetricsBuilder) recordPlatformObject(rb *resourceMetricsBuilder, obj nexusdashboard.Object, status string) {
	if code, ok := statusCode(status); ok {
		rb.recordInt("nexus_dashboard.service.health", "Nexus Dashboard platform, node, service, license, and storage health.", "1", code, map[string]string{
			"nd.service.name": nexusdashboard.String(obj, "serviceName", "appName", "featureName", "name"),
			"nd.node.name":    nexusdashboard.String(obj, "nodeName", "hostName", "name"),
			"nd.status":       status,
		})
	}
	recordNexusDashboardNumeric(rb, obj, "cpuUsage", "system.cpu.utilization", "CPU utilization reported by Nexus Dashboard.", "1", map[string]string{"cpu.mode": "total"}, 0.01)
	recordNexusDashboardNumeric(rb, obj, "memoryUsage", "system.memory.utilization", "Memory utilization reported by Nexus Dashboard.", "1", map[string]string{"system.memory.state": "used"}, 0.01)
	recordNexusDashboardNumeric(rb, obj, "diskUsage", "nexus_dashboard.storage.utilization", "Storage utilization reported by Nexus Dashboard.", "1", nil, 0.01)
}

func (*nexusDashboardMetricsBuilder) recordNDFCObject(rb *resourceMetricsBuilder, obj nexusdashboard.Object, status string) {
	if looksLikeSwitch(obj) {
		if up, ok := upStatus(status); ok {
			rb.recordInt("cisco.device.up", "Nexus switch availability reported by Nexus Dashboard or NDFC.", "1", up, nil)
		}
	}
	recordNexusDashboardFirstNumeric(rb, obj, []string{"health", "healthScore"}, "nexus_dashboard.fabric.health", "Fabric or switch health score reported by NDFC.", "1", nil, 1)
	recordNexusDashboardNumeric(rb, obj, "compliance", "nexus_dashboard.config.compliance", "NDFC configuration compliance score.", "1", nil, 0.01)
	recordNexusDashboardNumeric(rb, obj, "endpointCount", "nexus_dashboard.endpoint.count", "Endpoints reported by NDFC.", "{endpoint}", nil, 1)
	recordNexusDashboardNumeric(rb, obj, "vpcPeerCount", "nexus_dashboard.vpc.peer.count", "vPC peers reported by NDFC.", "{peer}", nil, 1)
	recordControllerStringState(rb, "nexus_dashboard.deployment.status", "NDFC policy, image, or change-control deployment status.", status, "nexus_dashboard.status", map[string]string{"nexus_dashboard.product": "ndfc"})
}

func (b *nexusDashboardMetricsBuilder) recordInsightsObject(rb *resourceMetricsBuilder, obj nexusdashboard.Object, status, severity string) {
	attrs := compactAttrs(map[string]string{
		"nexus_dashboard.insights.severity": severity,
		"nexus_dashboard.insights.category": nexusdashboard.String(obj, "category", "type", "anomalyType"),
	})
	rb.recordInt("nexus_dashboard.insights.anomaly.active", "Active Nexus Dashboard Insights anomaly or advisory.", "1", 1, attrs)
	b.addCount("nexus_dashboard.insights.anomaly.count", attrs)
	recordNexusDashboardNumeric(rb, obj, "score", "nexus_dashboard.insights.score", "Insights site, fabric, anomaly, or advisory score.", "1", attrs, 1)
	recordNexusDashboardNumeric(rb, obj, "confidence", "nexus_dashboard.insights.confidence", "Insights root-cause confidence.", "1", attrs, 0.01)
	recordControllerStringState(rb, "nexus_dashboard.insights.status", "Insights anomaly, advisory, flow, compliance, or recommendation status.", status, "nexus_dashboard.status", attrs)
}

func (*nexusDashboardMetricsBuilder) recordOrchestratorObject(rb *resourceMetricsBuilder, obj nexusdashboard.Object, status string) {
	attrs := compactAttrs(map[string]string{
		"nexus_dashboard.ndo.site":   nexusdashboard.String(obj, "siteName", "site"),
		"nexus_dashboard.ndo.schema": nexusdashboard.String(obj, "schemaName", "schema"),
	})
	recordControllerStringState(rb, "nexus_dashboard.orchestrator.deployment.status", "Nexus Dashboard Orchestrator deployment, template, schema, or site sync status.", status, "nexus_dashboard.status", attrs)
	recordNexusDashboardNumeric(rb, obj, "deploymentCount", "nexus_dashboard.orchestrator.deployment.count", "NDO deployments.", "{deployment}", attrs, 1)
	recordNexusDashboardNumeric(rb, obj, "policyDeltaCount", "nexus_dashboard.orchestrator.policy_delta.count", "NDO policy deltas.", "{delta}", attrs, 1)
}

func (*nexusDashboardMetricsBuilder) recordDataBrokerObject(rb *resourceMetricsBuilder, obj nexusdashboard.Object, status string) {
	attrs := compactAttrs(map[string]string{
		"nexus_dashboard.databroker.rule":    nexusdashboard.String(obj, "ruleName", "name"),
		"nexus_dashboard.databroker.session": nexusdashboard.String(obj, "sessionName", "sessionId"),
	})
	recordControllerStringState(rb, "nexus_dashboard.data_broker.status", "Nexus Dashboard Data Broker broker, TAP, SPAN, rule, filter, or session status.", status, "nexus_dashboard.status", attrs)
	recordNexusDashboardNumeric(rb, obj, "ruleCount", "nexus_dashboard.data_broker.rule.count", "Data Broker rules.", "{rule}", attrs, 1)
	recordNexusDashboardNumeric(rb, obj, "sessionCount", "nexus_dashboard.data_broker.session.count", "Data Broker sessions.", "{session}", attrs, 1)
}

func (*nexusDashboardMetricsBuilder) recordPerformanceObject(rb *resourceMetricsBuilder, obj nexusdashboard.Object) {
	if ifName := nexusdashboard.String(obj, "ifName", "interfaceName", "portName"); ifName != "" {
		attrs := interfaceAttrs(ifName, nexusdashboard.String(obj, "macAddress"), nexusdashboard.String(obj, "description", "descr"), nexusdashboard.String(obj, "speed"))
		if status := nexusDashboardObjectStatus(obj); status != "" {
			if up, ok := upStatus(status); ok {
				rb.recordInt("system.network.interface.status", "Interface operational status reported by Nexus Dashboard or NDFC.", "1", up, attrs)
			}
		}
		recordNexusDashboardNumeric(rb, obj, "rxRate", "cisco.interface.io.rate", "Interface traffic rate.", "bit/s", withAttr(attrs, "network.io.direction", "receive"), 1)
		recordNexusDashboardNumeric(rb, obj, "txRate", "cisco.interface.io.rate", "Interface traffic rate.", "bit/s", withAttr(attrs, "network.io.direction", "transmit"), 1)
		recordNexusDashboardNumeric(rb, obj, "rxUtilization", "cisco.interface.utilization", "Interface utilization as a ratio from 0 to 1.", "1", withAttr(attrs, "network.io.direction", "receive"), 0.01)
		recordNexusDashboardNumeric(rb, obj, "txUtilization", "cisco.interface.utilization", "Interface utilization as a ratio from 0 to 1.", "1", withAttr(attrs, "network.io.direction", "transmit"), 0.01)
	}
}

func (b *nexusDashboardMetricsBuilder) recordSkippedEndpoint(endpoint nexusDashboardEndpointInstance) {
	attrs := compactAttrs(map[string]string{
		"nexus_dashboard.product":       endpoint.product,
		"nexus_dashboard.group":         endpoint.group,
		"nexus_dashboard.api.operation": endpoint.operation,
		"nexus_dashboard.skip.reason":   "missing_target_filter",
	})
	maps.Copy(attrs, endpoint.attrs)
	b.controllerResource().recordInt("nexus_dashboard.service.skipped", "Nexus Dashboard service or target-specific endpoint skipped because the required app or target filter was unavailable.", "1", 1, attrs)
}

func (b *nexusDashboardMetricsBuilder) recordFailedEndpoint(endpoint nexusDashboardEndpointInstance, err error) {
	attrs := compactAttrs(map[string]string{
		"nexus_dashboard.product":       endpoint.product,
		"nexus_dashboard.group":         endpoint.group,
		"nexus_dashboard.api.operation": endpoint.operation,
		"nexus_dashboard.api.path":      endpoint.path,
		"nexus_dashboard.error":         classifyNexusDashboardError(err),
	})
	var apiErr *nexusdashboard.APIError
	if errors.As(err, &apiErr) {
		attrs["http.response.status_code"] = strconv.Itoa(apiErr.StatusCode)
		if apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusForbidden {
			b.controllerResource().recordInt("nexus_dashboard.service.unavailable", "Nexus Dashboard service endpoint unavailable, disabled, unauthorized, or not installed.", "1", 1, attrs)
			return
		}
	}
	b.controllerResource().recordSum("nexus_dashboard.api.endpoint.error", "Nexus Dashboard endpoint scrape error.", "{error}", 1, attrs)
}

func (b *nexusDashboardMetricsBuilder) addCount(name string, attrs map[string]string) {
	keyParts := []string{name}
	attrKeys := make([]string, 0, len(attrs))
	for key := range attrs {
		attrKeys = append(attrKeys, key)
	}
	sort.Strings(attrKeys)
	for _, key := range attrKeys {
		keyParts = append(keyParts, key+"="+attrs[key])
	}
	key := strings.Join(keyParts, "|")
	if existing := b.counts[key]; existing != nil {
		existing.value++
		return
	}
	b.counts[key] = &nexusDashboardCount{value: 1, attrs: attrs}
}

func (b *nexusDashboardMetricsBuilder) flushCounts() {
	rb := b.controllerResource()
	keys := make([]string, 0, len(b.counts))
	for key := range b.counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		count := b.counts[key]
		metricName, _, _ := strings.Cut(key, "|")
		rb.recordInt(metricName, nexusDashboardCountDescription(metricName), "1", count.value, count.attrs)
	}
}

func appendNexusDashboardLog(ld plog.Logs, endpoint nexusDashboardEndpointInstance, obj nexusdashboard.Object, controllerEndpoint string, now time.Time) {
	rl := ld.ResourceLogs().AppendEmpty()
	attrs := rl.Resource().Attributes()
	putStr(attrs, "host.id", firstNonEmpty(nexusdashboard.String(obj, "serialNumber", "serialNo", "serial", "switchSerialNo", "switchSerial"), nexusdashboard.String(obj, "nodeId", "switchId", "id", "dn")))
	putStr(attrs, "host.name", nexusdashboard.String(obj, "hostName", "hostname", "switchName", "nodeName", "name"))
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Nexus Dashboard")
	putStr(attrs, "cisco.controller.type", "nexus_dashboard")
	putStr(attrs, "cisco.controller.endpoint", controllerEndpoint)
	putStr(attrs, "cisco.fabric.name", firstNonEmpty(nexusdashboard.String(obj, "fabricName", "fabric"), endpoint.attrs["cisco.fabric.name"]))
	putStr(attrs, "cisco.site.name", firstNonEmpty(nexusdashboard.String(obj, "siteName", "site"), endpoint.attrs["cisco.site.name"]))
	putStr(attrs, "cisco.switch.serial", nexusdashboard.String(obj, "serialNumber", "serialNo", "serial", "switchSerialNo", "switchSerial"))
	putStr(attrs, "ndfc.switch.id", nexusdashboard.String(obj, "switchDbId", "switchId", "nodeId", "id"))
	putStr(attrs, "nexus_dashboard.product", endpoint.product)

	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName(nexusDashboardScopeName)
	record := sl.LogRecords().AppendEmpty()
	record.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	if ts, ok := nexusDashboardLogTimestamp(obj); ok {
		if timestamp, valid := pdataTimestampFromTime(ts); valid {
			record.SetTimestamp(timestamp)
		}
	}
	status := nexusDashboardObjectStatus(obj)
	severity := firstNonEmpty(nexusdashboard.String(obj, "severity", "Severity", "level"), status)
	record.SetSeverityText(severity)
	record.SetSeverityNumber(logSeverityNumber(severity))
	record.Body().SetEmptyMap()
	body := record.Body().Map()
	for key, value := range obj {
		setLogValue(body, key, value)
	}
	logAttrs := record.Attributes()
	putStr(logAttrs, "event.domain", "nexus_dashboard")
	putStr(logAttrs, "event.name", endpoint.operation)
	putStr(logAttrs, "nexus_dashboard.operation", endpoint.operation)
	putStr(logAttrs, "nexus_dashboard.group", endpoint.group)
	putStr(logAttrs, "nexus_dashboard.status", status)
	putStr(logAttrs, "nexus_dashboard.severity", strings.ToLower(severity))
	putStr(logAttrs, "user.name", nexusdashboard.String(obj, "user", "userName", "createdBy", "modifiedBy"))
}

func nexusDashboardMetricEndpointInstances(cfg *Config) []nexusDashboardEndpointInstance {
	return expandNexusDashboardEndpoints(nexusDashboardMetricEndpoints(), cfg)
}

func nexusDashboardLogEndpointInstances(cfg *Config) []nexusDashboardEndpointInstance {
	return expandNexusDashboardEndpoints(nexusDashboardLogEndpoints(), cfg)
}

func expandNexusDashboardEndpoints(endpoints []nexusDashboardEndpoint, cfg *Config) []nexusDashboardEndpointInstance {
	var out []nexusDashboardEndpointInstance
	for _, endpoint := range endpoints {
		switch endpoint.selectorKey {
		case "":
			out = append(out, nexusDashboardEndpointInstance{nexusDashboardEndpoint: endpoint, path: endpoint.path})
		case "fabric":
			values := uniqueStrings(cfg.NexusDashboard.Targets.Fabrics)
			if len(values) == 0 {
				out = append(out, nexusDashboardEndpointInstance{nexusDashboardEndpoint: endpoint, path: endpoint.path, skipped: true})
				continue
			}
			for _, fabric := range values {
				out = append(out, nexusDashboardEndpointInstance{
					nexusDashboardEndpoint: endpoint,
					path:                   strings.ReplaceAll(endpoint.path, "{fabricName}", url.PathEscape(fabric)),
					attrs:                  map[string]string{"cisco.fabric.name": fabric},
				})
			}
		case "switch_id":
			values := uniqueStrings(cfg.NexusDashboard.Targets.SwitchIDs)
			if len(values) == 0 {
				out = append(out, nexusDashboardEndpointInstance{nexusDashboardEndpoint: endpoint, path: endpoint.path, skipped: true})
				continue
			}
			for _, switchID := range values {
				out = append(out, nexusDashboardEndpointInstance{
					nexusDashboardEndpoint: endpoint,
					path:                   strings.ReplaceAll(endpoint.path, "{switchId}", url.PathEscape(switchID)),
					attrs:                  map[string]string{"ndfc.switch.id": switchID},
				})
			}
		case "serial":
			values := uniqueStrings(cfg.NexusDashboard.Targets.SwitchSerials)
			if len(values) == 0 {
				out = append(out, nexusDashboardEndpointInstance{nexusDashboardEndpoint: endpoint, path: endpoint.path, skipped: true})
				continue
			}
			for _, serial := range values {
				out = append(out, nexusDashboardEndpointInstance{
					nexusDashboardEndpoint: endpoint,
					path:                   strings.ReplaceAll(endpoint.path, "{serialNumber}", url.PathEscape(serial)),
					attrs:                  map[string]string{"cisco.switch.serial": serial},
				})
			}
		}
	}
	return out
}

func nexusDashboardMetricEndpoints() []nexusDashboardEndpoint {
	return []nexusDashboardEndpoint{
		{group: "platform", product: "platform", operation: "nd.cluster.health", path: "/api/v1/infra/cluster/health", objectType: "nd.cluster"},
		{group: "platform", product: "platform", operation: "nd.nodes", path: "/api/v1/infra/nodes", objectType: "nd.node"},
		{group: "platform", product: "platform", operation: "nd.services", path: "/api/v1/infra/services", objectType: "nd.service"},
		{group: "platform", product: "platform", operation: "nd.apps", path: "/api/v1/infra/apps", objectType: "nd.app"},
		{group: "platform", product: "platform", operation: "nd.storage", path: "/api/v1/infra/storage", objectType: "nd.storage"},
		{group: "platform", product: "platform", operation: "nd.licenses", path: "/api/v1/infra/licenses", objectType: "nd.license"},
		{group: "ndfc", product: "ndfc", operation: "ndfc.manage.fabrics", path: "/api/v1/manage/fabrics", objectType: "ndfc.fabric"},
		{group: "ndfc", product: "ndfc", operation: "ndfc.manage.fabric_switches", path: "/api/v1/manage/fabric-switches/summary", objectType: "ndfc.switch"},
		{group: "ndfc", product: "ndfc", operation: "ndfc.fabric.status", path: "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/fabricstatus", objectType: "ndfc.fabric_status"},
		{group: "ndfc", product: "ndfc", operation: "ndfc.switches", path: "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/switches", objectType: "ndfc.switch"},
		{group: "ndfc", product: "ndfc", operation: "ndfc.fabric.switch_overview", path: "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/{fabricName}/switches", objectType: "ndfc.switch", selectorKey: "fabric"},
		{group: "ndfc", product: "ndfc", operation: "ndfc.vpc.pairs", path: "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/vpcpairs", objectType: "ndfc.vpc"},
		{group: "ndfc", product: "ndfc", operation: "ndfc.endpoints", path: "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/{fabricName}/endpoints", objectType: "ndfc.endpoint", selectorKey: "fabric"},
		{group: "ndfc", product: "ndfc", operation: "ndfc.policy.deployment", path: "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/switches/{serialNumber}/intent-config", objectType: "ndfc.policy", selectorKey: "serial"},
		{group: "ndfc", product: "ndfc", operation: "ndfc.audit", path: "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/audit", objectType: "ndfc.audit", query: recentNexusDashboardQuery},
		{group: "ndfc", product: "ndfc", operation: "ndfc.events", path: "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/events", objectType: "ndfc.event", query: recentNexusDashboardQuery},
		{group: "performance", product: "ndfc", operation: "ndfc.interface.stats", path: "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/lanSwitches/{switchId}/interfaces", objectType: "ndfc.interface", selectorKey: "switch_id"},
		{group: "performance", product: "ndfc", operation: "ndfc.telemetry.sync", path: "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/telemetry/sync/status", objectType: "ndfc.telemetry"},
		{group: "insights", product: "insights", operation: "insights.anomalies", path: "/nexus/insights/api/v1/anomalies", objectType: "insights.anomaly", query: recentNexusDashboardQuery},
		{group: "insights", product: "insights", operation: "insights.advisories", path: "/nexus/insights/api/v1/advisories", objectType: "insights.advisory", query: recentNexusDashboardQuery},
		{group: "insights", product: "insights", operation: "insights.root_causes", path: "/nexus/insights/api/v1/rootcauses", objectType: "insights.root_cause", query: recentNexusDashboardQuery},
		{group: "insights", product: "insights", operation: "insights.sites", path: "/nexus/insights/api/v1/sites", objectType: "insights.site"},
		{group: "insights", product: "insights", operation: "insights.flow_analyses", path: "/nexus/insights/api/v1/flow/analyses", objectType: "insights.flow"},
		{group: "insights", product: "insights", operation: "insights.recommendations", path: "/nexus/insights/api/v1/recommendations", objectType: "insights.recommendation"},
		{group: "orchestrator", product: "orchestrator", operation: "ndo.sites", path: "/mso/api/v1/sites", objectType: "ndo.site"},
		{group: "orchestrator", product: "orchestrator", operation: "ndo.schemas", path: "/mso/api/v1/schemas", objectType: "ndo.schema"},
		{group: "orchestrator", product: "orchestrator", operation: "ndo.deployments", path: "/mso/api/v1/tasks", objectType: "ndo.deployment", query: recentNexusDashboardQuery},
		{group: "orchestrator", product: "orchestrator", operation: "ndo.alerts", path: "/mso/api/v1/alerts", objectType: "ndo.alert", query: recentNexusDashboardQuery},
		{group: "orchestrator", product: "orchestrator", operation: "ndo.audit", path: "/mso/api/v1/audit", objectType: "ndo.audit", query: recentNexusDashboardQuery},
		{group: "data_broker", product: "data_broker", operation: "nddb.health", path: "/api/v1/nddb/health", objectType: "nddb.health"},
		{group: "data_broker", product: "data_broker", operation: "nddb.switches", path: "/api/v1/nddb/switches", objectType: "nddb.switch"},
		{group: "data_broker", product: "data_broker", operation: "nddb.rules", path: "/api/v1/nddb/rules", objectType: "nddb.rule"},
		{group: "data_broker", product: "data_broker", operation: "nddb.sessions", path: "/api/v1/nddb/sessions", objectType: "nddb.session"},
		{group: "data_broker", product: "data_broker", operation: "nddb.events", path: "/api/v1/nddb/events", objectType: "nddb.event", query: recentNexusDashboardQuery},
	}
}

func nexusDashboardLogEndpoints() []nexusDashboardEndpoint {
	return []nexusDashboardEndpoint{
		{group: "ndfc", product: "ndfc", operation: "ndfc.audit", path: "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/audit", objectType: "ndfc.audit", query: recentNexusDashboardQuery},
		{group: "ndfc", product: "ndfc", operation: "ndfc.events", path: "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/events", objectType: "ndfc.event", query: recentNexusDashboardQuery},
		{group: "insights", product: "insights", operation: "insights.anomalies", path: "/nexus/insights/api/v1/anomalies", objectType: "insights.anomaly", query: recentNexusDashboardQuery},
		{group: "insights", product: "insights", operation: "insights.advisories", path: "/nexus/insights/api/v1/advisories", objectType: "insights.advisory", query: recentNexusDashboardQuery},
		{group: "insights", product: "insights", operation: "insights.root_causes", path: "/nexus/insights/api/v1/rootcauses", objectType: "insights.root_cause", query: recentNexusDashboardQuery},
		{group: "orchestrator", product: "orchestrator", operation: "ndo.audit", path: "/mso/api/v1/audit", objectType: "ndo.audit", query: recentNexusDashboardQuery},
		{group: "orchestrator", product: "orchestrator", operation: "ndo.deployments", path: "/mso/api/v1/tasks", objectType: "ndo.deployment", query: recentNexusDashboardQuery},
		{group: "data_broker", product: "data_broker", operation: "nddb.events", path: "/api/v1/nddb/events", objectType: "nddb.event", query: recentNexusDashboardQuery},
	}
}

func nexusDashboardEndpointQuery(endpoint nexusDashboardEndpoint, cfg *Config, now time.Time) url.Values {
	if endpoint.query == nil {
		return nil
	}
	return endpoint.query(cfg, now)
}

func recentNexusDashboardQuery(cfg *Config, now time.Time) url.Values {
	lookback := cfg.NexusDashboard.EventLookback
	if lookback <= 0 {
		lookback = defaultNexusDashboardConfig().EventLookback
	}
	return nexusdashboard.Query(map[string]string{
		"from": now.Add(-lookback).UTC().Format(time.RFC3339),
		"to":   now.UTC().Format(time.RFC3339),
	})
}

func nexusDashboardGroupEnabled(cfg NexusDashboardConfig, group string) bool {
	switch group {
	case "platform":
		return cfg.Platform.Enabled
	case "ndfc":
		return cfg.NDFC.Enabled
	case "insights":
		return cfg.Insights.Enabled
	case "orchestrator":
		return cfg.Orchestrator.Enabled
	case "data_broker":
		return cfg.DataBroker.Enabled
	case "performance":
		return cfg.Performance.Enabled
	default:
		return true
	}
}

func nexusDashboardGroupMaxResults(cfg NexusDashboardConfig, group string) int {
	switch group {
	case "platform":
		return cfg.Platform.MaxResults
	case "ndfc":
		return cfg.NDFC.MaxResults
	case "insights":
		return cfg.Insights.MaxResults
	case "orchestrator":
		return cfg.Orchestrator.MaxResults
	case "data_broker":
		return cfg.DataBroker.MaxResults
	case "performance":
		return cfg.Performance.MaxResults
	default:
		return 0
	}
}

func filterNexusDashboardObjects(objects []nexusdashboard.Object, filters NexusDashboardTargetFilters) []nexusdashboard.Object {
	needles := makeFilterNeedles(filters.Sites, filters.Fabrics, filters.SwitchSerials, filters.SwitchIDs, filters.InterfaceNames, filters.ServiceNames)
	if len(needles) == 0 {
		return objects
	}
	filtered := make([]nexusdashboard.Object, 0, len(objects))
	for _, obj := range objects {
		text := nexusdashboard.SearchText(obj)
		for needle := range needles {
			if strings.Contains(text, needle) {
				filtered = append(filtered, obj)
				break
			}
		}
	}
	return filtered
}

func makeFilterNeedles(groups ...[]string) map[string]struct{} {
	needles := map[string]struct{}{}
	for _, group := range groups {
		for _, value := range group {
			value = strings.ToLower(strings.TrimSpace(value))
			if value != "" {
				needles[value] = struct{}{}
			}
		}
	}
	return needles
}

func nexusDashboardObjectStatus(obj nexusdashboard.Object) string {
	return firstNonEmpty(
		nexusdashboard.String(obj, "status", "Status"),
		nexusdashboard.String(obj, "operSt", "operState", "operStatus"),
		nexusdashboard.String(obj, "state", "State"),
		nexusdashboard.String(obj, "health", "healthStatus"),
		nexusdashboard.String(obj, "severity", "Severity"),
		nexusdashboard.String(obj, "deploymentStatus", "syncStatus", "configStatus", "complianceStatus"),
	)
}

func nexusDashboardEvidenceMetric(endpoint nexusDashboardEndpointInstance) string {
	operation := strings.ToLower(endpoint.operation)
	objectType := strings.ToLower(endpoint.objectType)
	if strings.Contains(operation, ".audit") || strings.Contains(objectType, ".audit") {
		return "audit"
	}
	for _, needle := range []string{".events", ".anomalies", ".advisories", ".alerts", ".root_causes"} {
		if strings.Contains(operation, needle) {
			return "event"
		}
	}
	if strings.Contains(objectType, ".event") || strings.Contains(objectType, ".anomaly") || strings.Contains(objectType, ".advisory") || strings.Contains(objectType, ".alert") || strings.Contains(objectType, ".root_cause") {
		return "event"
	}
	return ""
}

func recordNexusDashboardNumeric(rb *resourceMetricsBuilder, obj nexusdashboard.Object, key, name, description, unit string, attrs map[string]string, multiplier float64) {
	value, ok := nexusdashboard.Float64(obj, key)
	if !ok {
		return
	}
	if multiplier != 0 && multiplier != 1 {
		value *= multiplier
	}
	rb.recordDouble(name, description, unit, value, attrs)
}

func recordNexusDashboardFirstNumeric(rb *resourceMetricsBuilder, obj nexusdashboard.Object, keys []string, name, description, unit string, attrs map[string]string, multiplier float64) {
	for _, key := range keys {
		if _, ok := nexusdashboard.Float64(obj, key); !ok {
			continue
		}
		recordNexusDashboardNumeric(rb, obj, key, name, description, unit, attrs, multiplier)
		return
	}
}

func recordControllerStringState(rb *resourceMetricsBuilder, name, description, status, statusAttr string, attrs map[string]string) {
	code, ok := statusCode(status)
	if !ok {
		return
	}
	if attrs == nil {
		attrs = map[string]string{}
	}
	attrs = withAttr(attrs, statusAttr, status)
	rb.recordInt(name, description, "1", code, attrs)
}

func looksLikeSwitch(obj nexusdashboard.Object) bool {
	return firstNonEmpty(nexusdashboard.String(obj, "serialNumber", "serialNo", "serial", "switchSerialNo", "switchSerial"), nexusdashboard.String(obj, "switchDbId", "switchId")) != ""
}

func nexusDashboardLogTimestamp(obj nexusdashboard.Object) (time.Time, bool) {
	for _, key := range []string{"timestamp", "createdAt", "createTime", "modTime", "lastTransitionTime", "lastUpdated", "updatedAt"} {
		if ts, ok := nexusdashboard.Time(obj, key); ok {
			return ts, true
		}
	}
	return time.Time{}, false
}

func nexusDashboardCountDescription(name string) string {
	switch name {
	case "nexus_dashboard.resource.count":
		return "Nexus Dashboard resources by product, group, resource type, status, and severity."
	case "nexus_dashboard.audit.record.count":
		return "Nexus Dashboard audit records by bounded product, operation, status, and severity attributes."
	case "nexus_dashboard.event.count":
		return "Nexus Dashboard events, anomalies, advisories, alerts, and root causes by bounded product, operation, status, and severity attributes."
	case "nexus_dashboard.insights.anomaly.count":
		return "Nexus Dashboard Insights anomalies and advisories."
	default:
		return "Nexus Dashboard resources."
	}
}
