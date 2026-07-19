// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
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

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/aci"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

// classifyACIError buckets a client error returned by the APIC into a small
// enum suitable for use as a metric attribute. Free-form err.Error() text would
// blow up Splunk O11y MTS cardinality with endpoint paths and request bodies.
func classifyACIError(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	var paginationErr *httpclient.PaginationLimitError
	if errors.As(err, &paginationErr) {
		return "pagination_limit"
	}
	var apiErr *aci.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return "auth"
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

const aciScopeName = "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/aci"

type aciMetricsReceiver struct {
	settings receiver.Settings
	config   *Config
	consumer consumer.Metrics
	clients  []*aci.Client
	counters *counterStore
	obs      *receiverhelper.ObsReport
	success  scrapeSuccessState

	startMu sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}

	statsMu sync.Mutex
	stats   []aci.RequestStat
}

type aciLogsReceiver struct {
	settings receiver.Settings
	config   *Config
	consumer consumer.Logs
	clients  []*aci.Client
	obs      *receiverhelper.ObsReport

	startMu sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}

	seen *logDeduplicator
}

type aciEndpoint struct {
	group      string
	operation  string
	className  string
	objectType string
	query      func(*Config, time.Time, string) url.Values
}

// aciSanitizedLog is the complete semantic log content produced from an APIC
// record. ObservedTimestamp is intentionally added only when the record is
// appended because it describes the local scrape attempt, not controller
// content, and therefore must not participate in replay deduplication.
type aciSanitizedLog struct {
	ScopeName          string
	Body               map[string]string
	ResourceAttributes map[string]string
	RecordAttributes   map[string]string
	Timestamp          pcommon.Timestamp
	SeverityText       string
	SeverityNumber     plog.SeverityNumber
}

// aciInstanceID returns a stable identifier for the configured ACI deployment so
// that the global resource's host.id does not collide with other ACI receivers
// in the same Splunk O11y tenant.
func aciInstanceID(conf *Config) string {
	if conf == nil {
		return ""
	}
	for _, c := range conf.ACI.Controllers {
		if id := firstNonEmpty(c.Name, c.Endpoint); id != "" {
			return id
		}
	}
	return ""
}

func newACIMetricsReceiver(set receiver.Settings, conf *Config, consumer consumer.Metrics) (*aciMetricsReceiver, error) {
	clients, err := newACIClients(conf)
	if err != nil {
		return nil, err
	}
	r := &aciMetricsReceiver{
		settings: set,
		config:   conf,
		consumer: consumer,
		clients:  clients,
		counters: newCounterStore(),
		obs:      newPlatformObsReport(set, "http"),
		done:     make(chan struct{}),
	}
	for _, client := range clients {
		client.OnRequest = r.recordRequest
	}
	return r, nil
}

func newACILogsReceiver(set receiver.Settings, conf *Config, consumer consumer.Logs) (*aciLogsReceiver, error) {
	clients, err := newACIClients(conf)
	if err != nil {
		return nil, err
	}
	return &aciLogsReceiver{
		settings: set,
		config:   conf,
		consumer: consumer,
		clients:  clients,
		obs:      newPlatformObsReport(set, "http"),
		done:     make(chan struct{}),
		seen:     newLogDeduplicator(),
	}, nil
}

func newACIClients(conf *Config) ([]*aci.Client, error) {
	clients := make([]*aci.Client, 0, len(conf.ACI.Controllers))
	for _, controller := range conf.ACI.Controllers {
		client, err := aci.NewClient(aci.Config{
			Endpoint:           controller.Endpoint,
			Name:               controller.Name,
			Username:           conf.ACI.Auth.Username,
			Password:           string(conf.ACI.Auth.Password),
			Domain:             conf.ACI.Auth.Domain,
			UserAgent:          conf.ACI.UserAgent,
			Timeout:            conf.Timeout,
			MaxRetries:         conf.ACI.MaxRetries,
			PageSize:           conf.ACI.PageSize,
			CAFile:             conf.ACI.CAFile,
			ServerName:         conf.ACI.ServerName,
			InsecureSkipVerify: conf.ACI.InsecureSkipVerify,
		})
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	return clients, nil
}

func (r *aciMetricsReceiver) Start(_ context.Context, _ component.Host) error {
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

func (r *aciMetricsReceiver) Shutdown(ctx context.Context) error {
	r.startMu.Lock()
	cancel := r.cancel
	r.startMu.Unlock()
	if cancel == nil {
		for _, client := range r.clients {
			client.CloseIdleConnections()
		}
		return nil
	}
	cancel()
	defer func() {
		for _, client := range r.clients {
			client.CloseIdleConnections()
		}
	}()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *aciMetricsReceiver) run(ctx context.Context) {
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

func (r *aciMetricsReceiver) collect(ctx context.Context) {
	scrapeCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()

	obsCtx := startMetricsOp(ctx, r.obs)
	md, scrapeErr := r.scrape(scrapeCtx)
	if scrapeErr != nil && ctx.Err() != nil && errors.Is(scrapeErr, context.Canceled) {
		endMetricsOp(obsCtx, r.obs, 0, nil)
		return
	}
	if scrapeErr != nil {
		r.settings.Logger.Error("ACI scrape failed", zap.Error(scrapeErr))
	}
	metricCount, consumeErr := consumeMetricsIfPresent(ctx, r.consumer, md)
	if consumeErr != nil {
		r.settings.Logger.Error("ACI metrics consumer failed", zap.Error(consumeErr))
	}
	endMetricsOp(obsCtx, r.obs, metricCount, combineSignalErrors(scrapeErr, consumeErr))
}

func (r *aciMetricsReceiver) scrape(ctx context.Context) (pmetric.Metrics, error) {
	r.resetRequestStats()
	now := time.Now()
	builder := newACIMetricsBuilder(now, aciInstanceID(r.config), r.counters)
	selector := newDeviceSelectionMatcher(r.config.DeviceSelection)
	partial := false

	for _, client := range r.clients {
		for _, endpoint := range aciMetricEndpoints() {
			if !aciGroupEnabled(r.config.ACI, endpoint.group) {
				continue
			}
			include := aciEndpointIncludePredicate(endpoint, r.config.ACI.Targets, selector)
			objects, err := client.ListClassFiltered(ctx, endpoint.operation, endpoint.className, aciEndpointQuery(endpoint, r.config, now), aciGroupMaxResults(r.config.ACI, endpoint.group), include)
			for _, obj := range objects {
				builder.recordObject(client.ControllerName(), client.Endpoint(), endpoint, obj)
			}
			if err != nil {
				if ctx.Err() != nil {
					partial = true
					return r.finishScrape(builder, now, partial), ctx.Err()
				}
				partial = true
				r.settings.Logger.Warn("ACI endpoint failed", zap.String("controller", client.ControllerName()), zap.String("operation", endpoint.operation), zap.Error(err))
				builder.controllerResource(client.ControllerName(), client.Endpoint()).recordSum("aci.api.endpoint.error", "APIC class or endpoint-family scrape failures.", "{error}", 1, map[string]string{
					"aci.api.operation": endpoint.operation,
					"aci.class":         endpoint.className,
					"aci.error.kind":    classifyACIError(err),
				})
				continue
			}
		}
	}
	return r.finishScrape(builder, now, partial), nil
}

func (r *aciMetricsReceiver) finishScrape(builder *aciMetricsBuilder, _ time.Time, partial bool) pmetric.Metrics {
	r.statsMu.Lock()
	stats := append([]aci.RequestStat(nil), r.stats...)
	r.statsMu.Unlock()
	r.recordAPIRequestMetrics(builder)

	for _, client := range r.clients {
		controllerStats := make([]aci.RequestStat, 0, len(stats))
		for _, stat := range stats {
			if stat.Controller == client.ControllerName() {
				controllerStats = append(controllerStats, stat)
			}
		}
		outcome := summarizeAPIOutcomes(controllerStats, func(stat aci.RequestStat) string { return stat.Outcome })
		if availability, ok := outcome.availability(); ok {
			builder.controllerResource(client.ControllerName(), client.Endpoint()).recordInt("aci.controller.up", "Whether an APIC controller API was reachable for the scrape.", "1", availability, nil)
		}
	}

	overall := summarizeAPIOutcomes(stats, func(stat aci.RequestStat) string { return stat.Outcome })
	rb := builder.globalResource()
	rb.recordInt("aci.scrape.partial_success", "Whether one or more APIC endpoint families failed during the scrape.", "1", boolToInt(partial), nil)
	if lastSuccess, ok := r.success.observe(time.Now(), !partial && overall.succeeded); ok {
		rb.recordInt("aci.scrape.last_success", "Unix timestamp of the most recent fully successful APIC scrape.", "s", lastSuccess.Unix(), nil)
	}
	builder.flushCounts()
	return builder.emit()
}

func (r *aciMetricsReceiver) recordRequest(stat aci.RequestStat) {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats = append(r.stats, stat)
}

func (r *aciMetricsReceiver) resetRequestStats() {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats = nil
}

func (r *aciMetricsReceiver) recordAPIRequestMetrics(builder *aciMetricsBuilder) {
	r.statsMu.Lock()
	stats := append([]aci.RequestStat(nil), r.stats...)
	r.statsMu.Unlock()
	observations := make([]apiRequestObservation, 0, len(stats))
	for _, stat := range stats {
		attrs := map[string]string{
			"aci.controller.name": stat.Controller,
			"aci.api.operation":   stat.Operation,
			"http.request.method": stat.Method,
			"aci.api.path":        stat.Path,
			"aci.api.outcome":     stat.Outcome,
		}
		if stat.StatusCode > 0 {
			attrs["http.response.status_code"] = strconv.Itoa(stat.StatusCode)
		}
		observations = append(observations, apiRequestObservation{resource: stat.Controller, attrs: attrs, durationSeconds: stat.Duration.Seconds(), failed: stat.Outcome != "success", rateLimited: stat.RateLimited})
	}
	for _, aggregate := range aggregateAPIRequestObservations(observations) {
		rb := builder.controllerResource(aggregate.resource, "")
		rb.recordDouble("aci.api.request.duration", "Average duration of APIC API request attempts within the scrape for each matching request-attribute set.", "s", aggregate.averageDurationSeconds, aggregate.attrs)
		if aggregate.errors > 0 {
			rb.recordSum("aci.api.request.errors", "APIC API request failures.", "{error}", aggregate.errors, aggregate.attrs)
		}
		if aggregate.rateLimited > 0 {
			rb.recordSum("aci.api.rate_limited", "APIC requests that received HTTP 429.", "{request}", aggregate.rateLimited, aggregate.attrs)
		}
	}
}

func (r *aciLogsReceiver) Start(_ context.Context, _ component.Host) error {
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

func (r *aciLogsReceiver) Shutdown(ctx context.Context) error {
	r.startMu.Lock()
	cancel := r.cancel
	r.startMu.Unlock()
	if cancel == nil {
		for _, client := range r.clients {
			client.CloseIdleConnections()
		}
		return nil
	}
	cancel()
	defer func() {
		for _, client := range r.clients {
			client.CloseIdleConnections()
		}
	}()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *aciLogsReceiver) run(ctx context.Context) {
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

func (r *aciLogsReceiver) collect(ctx context.Context) {
	scrapeCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()

	r.seen.BeginBatch()
	obsCtx := startLogsOp(ctx, r.obs)
	ld, scrapeErr := r.scrape(scrapeCtx)
	if scrapeErr != nil && ctx.Err() != nil && errors.Is(scrapeErr, context.Canceled) {
		r.seen.RollbackBatch()
		endLogsOp(obsCtx, r.obs, 0, nil)
		return
	}
	if scrapeErr != nil {
		r.settings.Logger.Error("ACI log scrape failed", zap.Error(scrapeErr))
	}
	logCount, consumeErr := consumeDeduplicatedLogs(ctx, r.consumer, r.seen, ld)
	if consumeErr != nil {
		r.settings.Logger.Error("ACI logs consumer failed", zap.Error(consumeErr))
	}
	endLogsOp(obsCtx, r.obs, logCount, combineSignalErrors(scrapeErr, consumeErr))
}

func (r *aciLogsReceiver) scrape(ctx context.Context) (plog.Logs, error) {
	ld := plog.NewLogs()
	now := time.Now()
	var endpointErrors []error
	selector := newDeviceSelectionMatcher(r.config.DeviceSelection)
	for _, client := range r.clients {
		for _, endpoint := range aciLogEndpoints() {
			if !aciLogEnabled(r.config.ACI, endpoint.group) {
				continue
			}
			include := aciEndpointIncludePredicate(endpoint, r.config.ACI.Targets, selector)
			objects, err := client.ListClassFiltered(ctx, endpoint.operation, endpoint.className, aciEndpointQuery(endpoint, r.config, now), aciGroupMaxResults(r.config.ACI, endpoint.group), include)
			for _, obj := range objects {
				if r.seenBefore(client.ControllerName(), client.Endpoint(), endpoint, obj, now) {
					continue
				}
				appendACILog(ld, client.ControllerName(), client.Endpoint(), endpoint, obj, now)
			}
			if err != nil {
				if ctx.Err() != nil {
					return ld, ctx.Err()
				}
				r.settings.Logger.Warn("ACI log endpoint failed", zap.String("controller", client.ControllerName()), zap.String("operation", endpoint.operation), zap.Error(err))
				endpointErrors = append(endpointErrors, fmt.Errorf("ACI %s %s: %w", client.ControllerName(), endpoint.operation, err))
				continue
			}
		}
	}
	r.expireSeen(now)
	return ld, errors.Join(endpointErrors...)
}

func (r *aciLogsReceiver) seenBefore(controllerName, controllerEndpoint string, endpoint aciEndpoint, obj aci.Object, now time.Time) bool {
	record := sanitizeACILog(controllerName, controllerEndpoint, endpoint, obj)
	stableID, content := aciLogDedupIdentity(endpoint, record)
	// A configured controller name and endpoint deliberately scope replay
	// identity. APIC transaction IDs are not safe logical-fabric identifiers,
	// so records from independently configured controllers are never collapsed.
	namespace := strings.Join([]string{controllerName, controllerEndpoint, endpoint.operation}, "\x00")
	key := logDedupKey(namespace, stableID, content)
	return !r.seen.MarkPending(key, now)
}

// aciSeenMaxEntries caps the dedup map so a busy fabric with thousands of
// churning faults cannot grow it without bound between TTL expiries.
const aciSeenMaxEntries = 50000

func (r *aciLogsReceiver) expireSeen(now time.Time) {
	ttl := r.config.ACI.EventLookback
	if ttl <= 0 {
		ttl = defaultACIConfig().EventLookback
	}
	ttl *= 2
	r.seen.Expire(now.Add(-ttl), aciSeenMaxEntries)
}

type aciMetricsBuilder struct {
	metrics   pmetric.Metrics
	now       pcommon.Timestamp
	start     pcommon.Timestamp
	instance  string
	resources map[string]*resourceMetricsBuilder
	counts    map[string]*aciCount
	counters  *counterStore
}

type aciCount struct {
	value int64
	attrs map[string]string
}

func newACIMetricsBuilder(now time.Time, instance string, counters *counterStore) *aciMetricsBuilder {
	if counters == nil {
		counters = newCounterStore()
	}
	ts := pcommon.NewTimestampFromTime(now)
	return &aciMetricsBuilder{
		metrics:   pmetric.NewMetrics(),
		now:       ts,
		start:     pcommon.NewTimestampFromTime(counters.StartTime()),
		instance:  instance,
		resources: map[string]*resourceMetricsBuilder{},
		counts:    map[string]*aciCount{},
		counters:  counters,
	}
}

func (b *aciMetricsBuilder) emit() pmetric.Metrics {
	return b.metrics
}

func (b *aciMetricsBuilder) globalResource() *resourceMetricsBuilder {
	rb := b.resource("aci")
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", "apic:"+firstNonEmpty(b.instance, "default"))
	putStr(attrs, "host.name", "Cisco ACI")
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Cisco ACI")
	putStr(attrs, "cisco.controller.type", "apic")
	return rb
}

func (b *aciMetricsBuilder) controllerResource(name, endpoint string) *resourceMetricsBuilder {
	rb := b.resource("controller:" + name)
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", "apic:"+name)
	putStr(attrs, "host.name", name)
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Cisco APIC")
	putStr(attrs, "cisco.controller.type", "apic")
	putStr(attrs, "cisco.controller.endpoint", endpoint)
	putStr(attrs, "aci.controller.name", name)
	return rb
}

func (b *aciMetricsBuilder) objectResource(controllerName, controllerEndpoint string, endpoint aciEndpoint, obj aci.Object) *resourceMetricsBuilder {
	dn := aci.String(obj, "dn")
	nodeID := firstNonEmpty(aci.String(obj, "nodeId", "id"), nodeIDFromACIDN(dn))
	if endpoint.objectType == "aci.interface" {
		nodeID = firstNonEmpty(aci.String(obj, "nodeId"), nodeIDFromACIDN(dn), aci.String(obj, "id"))
	}
	serial := aci.String(obj, "serial")
	hostID := firstNonEmpty(serial, nodeID, dn, aci.String(obj, "name", "mac", "ip"), endpoint.operation)
	if endpoint.group == "controller_health" || strings.Contains(aci.String(obj, "role"), "controller") {
		hostID = firstNonEmpty(hostID, controllerName)
	}
	resourceKey := controllerName + ":" + endpoint.operation + ":" + hostID
	if endpoint.objectType == "aci.interface" {
		interfaceID := interfaceNameFromACIDN(dn)
		if interfaceID == "" {
			interfaceID = interfaceNameFromACIDN(aci.String(obj, "id", "name"))
		}
		if interfaceID != "" {
			resourceKey += ":interface:" + interfaceID
		} else if dn != "" {
			resourceKey += ":dn:" + dn
		}
	}
	rb := b.resource(resourceKey)
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", hostID)
	putStr(attrs, "host.name", firstNonEmpty(aci.String(obj, "name", "hostName", "nodeName"), aciNodeName(nodeID), hostID))
	putIPAttrs(attrs, "host.ip", aci.String(obj, "address"), aci.String(obj, "oobMgmtAddr"), aci.String(obj, "inbMgmtAddr"), aci.String(obj, "ip"))
	putStr(attrs, "host.type", firstNonEmpty(aci.String(obj, "model", "role", "type"), endpoint.objectType))
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Cisco ACI")
	putStr(attrs, "os.version", aci.String(obj, "version", "fwVer"))
	putStr(attrs, "cisco.controller.type", "apic")
	putStr(attrs, "cisco.controller.endpoint", controllerEndpoint)
	putStr(attrs, "aci.controller.name", controllerName)
	putStr(attrs, "aci.node.id", nodeID)
	putStr(attrs, "cisco.switch.serial", serial)
	putStr(attrs, "cisco.switch.role", aci.String(obj, "role"))
	putStr(attrs, "cisco.fabric.name", aciFabricName(obj))
	putStr(attrs, "aci.dn", dn)
	putStr(attrs, "aci.class", aci.String(obj, "aci.class"))
	putStr(attrs, "aci.resource.type", endpoint.objectType)
	return rb
}

func (b *aciMetricsBuilder) resource(key string) *resourceMetricsBuilder {
	if rb := b.resources[key]; rb != nil {
		return rb
	}
	rm := b.metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName(aciScopeName)
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

func (b *aciMetricsBuilder) recordObject(controllerName, controllerEndpoint string, endpoint aciEndpoint, obj aci.Object) {
	rb := b.objectResource(controllerName, controllerEndpoint, endpoint, obj)
	status := aciObjectStatus(obj)
	severity := strings.ToLower(firstNonEmpty(aci.String(obj, "severity", "lc", "type"), status))
	attrs := compactAttrs(map[string]string{
		"aci.group":         endpoint.group,
		"aci.class":         aci.String(obj, "aci.class"),
		"aci.resource.type": endpoint.objectType,
		"aci.status":        status,
		"aci.severity":      severity,
	})
	rb.recordInt("aci.resource.info", "Bounded metadata for APIC managed objects.", "1", 1, attrs)
	if code, ok := statusCode(status); ok {
		rb.recordInt("aci.resource.status", "Encoded APIC object status with original state attributes.", "1", code, attrs)
	}
	b.addCount("aci.resource.count", attrs)
	evidenceAttrs := compactAttrs(map[string]string{
		"aci.group":         endpoint.group,
		"aci.operation":     endpoint.operation,
		"aci.resource.type": endpoint.objectType,
		"aci.status":        firstNonEmpty(status, "present"),
		"aci.severity":      firstNonEmpty(severity, "unknown"),
	})
	switch endpoint.group {
	case "audit":
		b.addCount("aci.audit.record.count", evidenceAttrs)
	case "events":
		b.addCount("aci.event.count", evidenceAttrs)
	}

	switch endpoint.group {
	case "fabric", "nodes", "controller_health":
		b.recordFabricObject(rb, obj, status)
	case "faults":
		b.recordFaultObject(rb, obj, severity)
	case "stats":
		b.recordStatsObject(rb, obj)
	case "endpoints":
		b.recordEndpointObject(rb, obj)
	case "tenants":
		b.recordTenantObject(rb, obj, status)
	case "topology":
		b.recordTopologyObject(rb, obj)
	}
}

func (*aciMetricsBuilder) recordFabricObject(rb *resourceMetricsBuilder, obj aci.Object, status string) {
	if aci.String(obj, "serial") != "" || aci.String(obj, "nodeId", "id") != "" {
		if up, ok := upStatus(status); ok {
			rb.recordInt("cisco.device.up", "Device availability (1 = up, 0 = down)", "1", up, nil)
		}
	}
	recordACIFirstNumeric(rb, obj, []string{"cur", "health", "healthScore"}, "aci.fabric.health", "ACI fabric, pod, node, or tenant health score.", "1", nil, 1)
}

func (b *aciMetricsBuilder) recordFaultObject(rb *resourceMetricsBuilder, obj aci.Object, severity string) {
	attrs := compactAttrs(map[string]string{
		"aci.fault.code":     aci.String(obj, "code"),
		"aci.fault.severity": severity,
		"aci.fault.domain":   aci.String(obj, "domain"),
		"aci.fault.type":     aci.String(obj, "type"),
	})
	rb.recordInt("aci.fault.active", "Active APIC fault instance.", "1", 1, attrs)
	b.addCount("aci.fault.count", attrs)
}

func (*aciMetricsBuilder) recordStatsObject(rb *resourceMetricsBuilder, obj aci.Object) {
	if ifName := interfaceNameFromACIDN(aci.String(obj, "dn", "id", "name")); ifName != "" {
		attrs := interfaceAttrs(ifName, "", aci.String(obj, "descr"), aci.String(obj, "speed", "ethpmCfgSpeed"))
		if status := aciObjectStatus(obj); status != "" {
			if up, ok := upStatus(status); ok {
				rb.recordInt("system.network.interface.status", "Interface operational status (1 = up, 0 = down)", "1", up, attrs)
			}
		}
		switch strings.ToLower(aci.String(obj, "aci.class")) {
		case "eqptingrtotal5min":
			recordACIEquipmentInterfaceStats(rb, obj, attrs, "receive")
		case "eqptegrtotal5min":
			recordACIEquipmentInterfaceStats(rb, obj, attrs, "transmit")
		case "rmonifin":
			recordACIRMONInterfaceStats(rb, obj, attrs, "receive")
		case "rmonifout":
			recordACIRMONInterfaceStats(rb, obj, attrs, "transmit")
		default:
			// Preserve the legacy generic mappings for APIC releases that expose
			// these fields directly on the physical-interface classes.
			recordACINumeric(rb, obj, "bytesRate", "cisco.interface.io.rate", "Interface traffic rate.", "bit/s", attrs, 8)
			recordACINumeric(rb, obj, "pktsRate", "cisco.interface.packet.rate", "Interface packet rate.", "{packet}/s", attrs, 1)
			recordACINumeric(rb, obj, "dropRate", "cisco.interface.drop.rate", "Interface drop rate.", "{drop}/s", attrs, 1)
		}
	}
	recordACIFirstPercentRatio(rb, obj, []string{"userLast"}, "system.cpu.utilization", "CPU utilization reported by APIC.", map[string]string{"cpu.mode": "user"})
	recordACIFirstPercentRatio(rb, obj, []string{"kernelLast"}, "system.cpu.utilization", "CPU utilization reported by APIC.", map[string]string{"cpu.mode": "kernel"})
	if strings.EqualFold(aci.String(obj, "aci.class"), "procSysMem5min") {
		recordACIMemoryUtilization(rb, obj)
	}
	if strings.EqualFold(aci.String(obj, "aci.class"), "fabricOverallHealthHist5min") {
		recordACINumeric(rb, obj, "healthAvg", "aci.fabric.health", "ACI fabric, pod, node, or tenant health score.", "1", nil, 1)
	}
}

func recordACIMemoryUtilization(rb *resourceMetricsBuilder, obj aci.Object) {
	used, ok := aci.Float64(obj, "usedLast")
	if !ok || math.IsNaN(used) || math.IsInf(used, 0) || used < 0 {
		return
	}
	total, ok := aci.Float64(obj, "totalLast")
	if ok && (math.IsNaN(total) || math.IsInf(total, 0)) {
		return
	}
	if !ok {
		free, freeOK := aci.Float64(obj, "freeLast")
		if !freeOK || math.IsNaN(free) || math.IsInf(free, 0) || free < 0 {
			return
		}
		total = used + free
	}
	if math.IsNaN(total) || math.IsInf(total, 0) || total <= 0 || used > total {
		return
	}
	rb.recordDouble("system.memory.utilization", "Ratio of memory bytes in use, from 0 to 1.", "1", used/total, map[string]string{"system.memory.state": "used"})
}

func recordACIEquipmentInterfaceStats(rb *resourceMetricsBuilder, obj aci.Object, attrs map[string]string, direction string) {
	attrs = withAttr(attrs, "network.io.direction", direction)
	recordACINumeric(rb, obj, "bytesRate", "cisco.interface.io.rate", "Interface traffic rate.", "bit/s", attrs, 8)
	recordACINumeric(rb, obj, "pktsRate", "cisco.interface.packet.rate", "Interface packet rate.", "{packet}/s", attrs, 1)
	recordACIFirstPercentRatio(rb, obj, []string{"utilLast", "utilAvg"}, "cisco.interface.utilization", "Interface utilization as a ratio from 0 to 1.", attrs)
}

func recordACIRMONInterfaceStats(rb *resourceMetricsBuilder, obj aci.Object, attrs map[string]string, direction string) {
	attrs = withAttr(attrs, "network.io.direction", direction)
	recordACIAbsoluteSumInt(rb, obj, "octets", "system.network.io", "The number of bytes transmitted and received.", "By", attrs)
	recordACISummedAbsoluteSumInt(rb, obj, []string{"ucastPkts", "nUcastPkts"}, "system.network.packet.count", "The number of packets transmitted or received.", "{packet}", attrs)
	recordACIAbsoluteSumInt(rb, obj, "errors", "system.network.errors", "The number of errors encountered.", "{error}", attrs)
	recordACIAbsoluteSumInt(rb, obj, "discards", "system.network.packet.dropped", "The number of packets dropped.", "{packet}", attrs)
}

func (b *aciMetricsBuilder) recordEndpointObject(rb *resourceMetricsBuilder, obj aci.Object) {
	attrs := compactAttrs(map[string]string{
		"aci.endpoint.mac": aci.String(obj, "mac"),
		"aci.endpoint.ip":  aci.String(obj, "ip"),
		"aci.endpoint.dn":  aci.String(obj, "dn"),
	})
	rb.recordInt("aci.endpoint.present", "Endpoint MAC/IP presence.", "1", 1, attrs)
	b.addCount("aci.endpoint.count", map[string]string{
		"aci.tenant": tenantFromACIDN(aci.String(obj, "dn")),
		"aci.epg":    epgFromACIDN(aci.String(obj, "dn")),
	})
}

func (b *aciMetricsBuilder) recordTenantObject(rb *resourceMetricsBuilder, obj aci.Object, status string) {
	attrs := compactAttrs(map[string]string{
		"aci.tenant": aciTenantName(obj),
		"aci.vrf":    vrfFromACIDN(aci.String(obj, "dn")),
		"aci.bd":     bdFromACIDN(aci.String(obj, "dn")),
		"aci.epg":    epgFromACIDN(aci.String(obj, "dn")),
	})
	recordControllerStringState(rb, "aci.tenant.status", "ACI tenant, VRF, bridge domain, EPG, app profile, contract, or L3Out status.", status, "aci.status", attrs)
	b.addCount("aci.tenant.object.count", attrs)
}

func (*aciMetricsBuilder) recordTopologyObject(rb *resourceMetricsBuilder, obj aci.Object) {
	protocol := topologyProtocol(aci.String(obj, "aci.class"))
	legacyPeerName := aci.String(obj, "sysName", "chassisIdV", "portIdV", "name")
	neighborAddress := aci.String(obj, "mgmtIp", "mgmtPortMac", "mac")
	attrs := compactAttrs(map[string]string{
		// Keep the legacy network.* vocabulary for compatibility while exposing
		// the more specific bounded topology attributes alongside it.
		"network.peer.name":                 legacyPeerName,
		"network.peer.address":              neighborAddress,
		"network.protocol.name":             protocol,
		"cisco.topology.protocol":           protocol,
		"network.interface.name":            interfaceNameFromACIDN(aci.String(obj, "dn", "id")),
		"cisco.topology.neighbor.name":      aci.String(obj, "sysName", "chassisIdV", "name"),
		"cisco.topology.neighbor.interface": aci.String(obj, "portIdV", "portId", "portDesc"),
		"cisco.topology.neighbor.platform":  aci.String(obj, "platform", "sysDesc"),
		"cisco.topology.neighbor.address":   neighborAddress,
	})
	rb.recordInt("cisco.topology.neighbor.info", "LLDP, CDP, and fabric-link neighbor information.", "1", 1, attrs)
}

func (b *aciMetricsBuilder) addCount(name string, attrs map[string]string) {
	attrs = compactAttrs(attrs)
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
	b.counts[key] = &aciCount{value: 1, attrs: attrs}
}

func (b *aciMetricsBuilder) flushCounts() {
	rb := b.globalResource()
	keys := make([]string, 0, len(b.counts))
	for key := range b.counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		count := b.counts[key]
		metricName, _, _ := strings.Cut(key, "|")
		rb.recordInt(metricName, aciCountDescription(metricName), "1", count.value, count.attrs)
	}
}

func appendACILog(ld plog.Logs, controllerName, controllerEndpoint string, endpoint aciEndpoint, obj aci.Object, now time.Time) {
	recordContent := sanitizeACILog(controllerName, controllerEndpoint, endpoint, obj)

	rl := ld.ResourceLogs().AppendEmpty()
	attrs := rl.Resource().Attributes()
	for key, value := range recordContent.ResourceAttributes {
		putStr(attrs, key, value)
	}

	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName(recordContent.ScopeName)
	record := sl.LogRecords().AppendEmpty()
	record.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	if recordContent.Timestamp != 0 {
		record.SetTimestamp(recordContent.Timestamp)
	}
	record.SetSeverityText(recordContent.SeverityText)
	record.SetSeverityNumber(recordContent.SeverityNumber)
	record.Body().SetEmptyMap()
	body := record.Body().Map()
	for key, value := range recordContent.Body {
		putStr(body, key, value)
	}
	logAttrs := record.Attributes()
	for key, value := range recordContent.RecordAttributes {
		putStr(logAttrs, key, value)
	}
}

// sanitizeACILog is the sole boundary between an untrusted APIC object and an
// exported log. Every body field and derived attribute comes from aciLogBody;
// the remaining values are fixed receiver metadata or configured controller
// identity. No raw APIC attribute is read outside the signal allowlist.
func sanitizeACILog(controllerName, controllerEndpoint string, endpoint aciEndpoint, obj aci.Object) aciSanitizedLog {
	body := aciLogBody(endpoint, obj)
	dn := body["dn"]
	affected := body["affected"]

	identitySource := firstNonEmpty(dn, affected)
	hostID := firstNonEmpty(nodeIDFromACIDN(identitySource), body["id"], identitySource)
	if endpoint.group == "audit" && body["txId"] != "" {
		// aaaModLR id and dn are replica-local when APIC returns one record per
		// controller. Prefer the transaction target for stable resource identity.
		identitySource = firstNonEmpty(affected, body["txId"])
		hostID = firstNonEmpty(nodeIDFromACIDN(affected), identitySource)
	}
	nodeID := nodeIDFromACIDN(identitySource)
	status := firstNonEmpty(body["status"], body["severity"], body["lc"])
	severity := firstNonEmpty(body["severity"], body["lc"], body["type"], status)

	result := aciSanitizedLog{
		ScopeName: aciScopeName,
		Body:      body,
		ResourceAttributes: compactAttrs(map[string]string{
			"host.id":                   hostID,
			"host.name":                 identitySource,
			"hw.type":                   "network",
			"os.name":                   "Cisco ACI",
			"cisco.controller.type":     "apic",
			"cisco.controller.endpoint": controllerEndpoint,
			"aci.controller.name":       controllerName,
			"aci.node.id":               nodeID,
			"aci.dn":                    dn,
			"aci.class":                 aciLogClassName(endpoint),
		}),
		RecordAttributes: compactAttrs(map[string]string{
			"event.domain":  "aci",
			"event.name":    endpoint.operation,
			"aci.operation": endpoint.operation,
			"aci.group":     endpoint.group,
			"aci.status":    status,
			"aci.severity":  strings.ToLower(severity),
			"user.name":     body["user"],
		}),
		SeverityText:   severity,
		SeverityNumber: logSeverityNumber(severity),
	}
	if ts, ok := aciLogTimestamp(body); ok {
		if timestamp, valid := pdataTimestampFromTime(ts); valid {
			result.Timestamp = timestamp
		}
	}
	return result
}

func aciLogClassName(endpoint aciEndpoint) string {
	if endpoint.className != "" {
		return endpoint.className
	}
	switch endpoint.group {
	case "faults":
		return "faultInst"
	case "audit":
		return "aaaModLR"
	case "events":
		return "eventRecord"
	default:
		return ""
	}
}

// aciLogBody returns the documented, signal-specific APIC record envelope.
// APIC managed-object attributes are strings; rejecting non-string values
// prevents a malformed or future nested attribute from bypassing this
// top-level allowlist.
func aciLogBody(endpoint aciEndpoint, obj aci.Object) map[string]string {
	var fields []string
	switch endpoint.group {
	case "faults":
		fields = []string{
			"ack", "affected", "cause", "code", "created", "descr", "dn", "domain", "highestSeverity",
			"id", "lastTransition", "lc", "occur", "origSeverity", "prevSeverity", "rule", "severity", "status", "type",
		}
	case "audit":
		fields = []string{
			"affected", "cause", "code", "created", "descr", "dn", "id", "ind", "severity", "status", "trig", "txId", "user",
		}
	case "events":
		fields = []string{
			"affected", "cause", "code", "created", "descr", "dn", "id", "ind", "severity", "status", "trig", "txId", "user",
		}
	default:
		return map[string]string{}
	}

	body := make(map[string]string, len(fields))
	for _, key := range fields {
		value, ok := obj[key].(string)
		if ok && value != "" {
			body[key] = value
		}
	}
	return body
}

// aciLogDedupIdentity hashes the complete sanitized semantic record so every
// visible source-content change remains eligible for emission. APIC 6.0 and
// later can return replicated aaaModLR records with different id and dn values
// but identical transaction data; txId-backed audit identities deliberately
// omit only those replica-local body fields and the resource copy of dn.
func aciLogDedupIdentity(endpoint aciEndpoint, record aciSanitizedLog) (string, aciSanitizedLog) {
	body := record.Body
	switch endpoint.group {
	case "faults":
		return firstNonEmpty(body["dn"], body["id"], body["code"]), record
	case "audit":
		if body["txId"] == "" {
			return firstNonEmpty(body["id"], body["dn"]), record
		}
		content := cloneACISanitizedLog(record)
		delete(content.Body, "id")
		delete(content.Body, "dn")
		delete(content.ResourceAttributes, "aci.dn")
		return aciLogCompositeIdentity(body, "txId", "affected", "created", "code"), content
	case "events":
		stableID := firstNonEmpty(body["id"], body["dn"])
		if stableID == "" {
			stableID = aciLogCompositeIdentity(body, "txId", "affected", "created", "code")
		}
		return stableID, record
	default:
		return "", record
	}
}

func cloneACISanitizedLog(record aciSanitizedLog) aciSanitizedLog {
	record.Body = maps.Clone(record.Body)
	record.ResourceAttributes = maps.Clone(record.ResourceAttributes)
	record.RecordAttributes = maps.Clone(record.RecordAttributes)
	return record
}

func aciLogCompositeIdentity(body map[string]string, fields ...string) string {
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		if value := body[field]; value != "" {
			parts = append(parts, field+"="+value)
		}
	}
	return strings.Join(parts, "\x00")
}

func aciMetricEndpoints() []aciEndpoint {
	return []aciEndpoint{
		{group: "controller_health", operation: "apic.top_system", className: "topSystem", objectType: "aci.controller"},
		{group: "controller_health", operation: "apic.firmware", className: "firmwareCtrlrRunning", objectType: "aci.controller_firmware"},
		{group: "fabric", operation: "fabric.pods", className: "fabricPod", objectType: "aci.pod"},
		{group: "fabric", operation: "fabric.health", className: "fabricHealthTotal", objectType: "aci.fabric_health"},
		{group: "nodes", operation: "fabric.nodes", className: "fabricNode", objectType: "aci.node"},
		{group: "nodes", operation: "fabric.membership", className: "fabricLooseNode", objectType: "aci.node"},
		{group: "faults", operation: "fault.instances", className: "faultInst", objectType: "aci.fault", query: activeACIQuery},
		{group: "audit", operation: "audit.modifications", className: "aaaModLR", objectType: "aci.audit", query: recentACIQuery},
		{group: "events", operation: "events.records", className: "eventRecord", objectType: "aci.event", query: recentACIQuery},
		{group: "stats", operation: "stats.interfaces.l1", className: "l1PhysIf", objectType: "aci.interface"},
		{group: "stats", operation: "stats.interfaces.ethpm", className: "ethpmPhysIf", objectType: "aci.interface"},
		{group: "stats", operation: "stats.interfaces.ingress", className: "eqptIngrTotal5min", objectType: "aci.interface"},
		{group: "stats", operation: "stats.interfaces.egress", className: "eqptEgrTotal5min", objectType: "aci.interface"},
		{group: "stats", operation: "stats.interfaces.rmon_in", className: "rmonIfIn", objectType: "aci.interface"},
		{group: "stats", operation: "stats.interfaces.rmon_out", className: "rmonIfOut", objectType: "aci.interface"},
		{group: "stats", operation: "stats.cpu", className: "procSysCPU5min", objectType: "aci.cpu"},
		{group: "stats", operation: "stats.memory", className: "procSysMem5min", objectType: "aci.memory"},
		{group: "stats", operation: "stats.fabric_health", className: "fabricOverallHealthHist5min", objectType: "aci.fabric_health", query: currentACIStatsQuery},
		{group: "endpoints", operation: "endpoints.mac", className: "fvCEp", objectType: "aci.endpoint"},
		{group: "endpoints", operation: "endpoints.ip", className: "fvIp", objectType: "aci.endpoint_ip"},
		{group: "tenants", operation: "tenant.tenants", className: "fvTenant", objectType: "aci.tenant"},
		{group: "tenants", operation: "tenant.vrfs", className: "fvCtx", objectType: "aci.vrf"},
		{group: "tenants", operation: "tenant.bridge_domains", className: "fvBD", objectType: "aci.bridge_domain"},
		{group: "tenants", operation: "tenant.app_profiles", className: "fvAp", objectType: "aci.app_profile"},
		{group: "tenants", operation: "tenant.epgs", className: "fvAEPg", objectType: "aci.epg"},
		{group: "tenants", operation: "tenant.contracts", className: "vzBrCP", objectType: "aci.contract"},
		{group: "tenants", operation: "tenant.l3outs", className: "l3extOut", objectType: "aci.l3out"},
		{group: "topology", operation: "topology.lldp", className: "lldpAdjEp", objectType: "aci.lldp"},
		{group: "topology", operation: "topology.cdp", className: "cdpAdjEp", objectType: "aci.cdp"},
		{group: "topology", operation: "topology.links", className: "fabricLink", objectType: "aci.fabric_link"},
	}
}

func aciLogEndpoints() []aciEndpoint {
	return []aciEndpoint{
		{group: "faults", operation: "fault.instances", className: "faultInst", objectType: "aci.fault", query: activeACIQuery},
		{group: "audit", operation: "audit.modifications", className: "aaaModLR", objectType: "aci.audit", query: recentACIQuery},
		{group: "events", operation: "events.records", className: "eventRecord", objectType: "aci.event", query: recentACIQuery},
	}
}

func aciEndpointQuery(endpoint aciEndpoint, cfg *Config, now time.Time) url.Values {
	if endpoint.query == nil {
		return nil
	}
	return endpoint.query(cfg, now, endpoint.className)
}

func activeACIQuery(_ *Config, _ time.Time, _ string) url.Values {
	return aci.Query(map[string]string{
		"query-target-filter": `not(wcard(faultInst.lc,"soaking"))`,
		"order-by":            "faultInst.lastTransition|desc",
	})
}

func recentACIQuery(cfg *Config, now time.Time, className string) url.Values {
	lookback := cfg.ACI.EventLookback
	if lookback <= 0 {
		lookback = defaultACIConfig().EventLookback
	}
	return aci.Query(map[string]string{
		"query-target-filter": fmt.Sprintf("gt(%s.created,%q)", className, now.Add(-lookback).UTC().Format(time.RFC3339)),
		"order-by":            className + ".created|desc",
	})
}

func currentACIStatsQuery(_ *Config, _ time.Time, className string) url.Values {
	return aci.Query(map[string]string{
		"query-target-filter": fmt.Sprintf(`eq(%s.index,"0")`, className),
	})
}

func aciGroupEnabled(cfg ACIConfig, group string) bool {
	switch group {
	case "fabric":
		return cfg.Fabric.Enabled
	case "controller_health":
		return cfg.ControllerHealth.Enabled
	case "nodes":
		return cfg.Nodes.Enabled
	case "faults":
		return cfg.Faults.Enabled
	case "audit":
		return cfg.Audit.Enabled
	case "events":
		return cfg.Events.Enabled
	case "stats":
		return cfg.Stats.Enabled
	case "endpoints":
		return cfg.Endpoints.Enabled
	case "tenants":
		return cfg.Tenants.Enabled
	case "topology":
		return cfg.Topology.Enabled
	default:
		return true
	}
}

func aciLogEnabled(cfg ACIConfig, group string) bool {
	switch group {
	case "faults":
		return cfg.Logs.Faults.Enabled
	case "audit":
		return cfg.Logs.Audit.Enabled
	case "events":
		return cfg.Logs.Events.Enabled
	default:
		return false
	}
}

func aciGroupMaxResults(cfg ACIConfig, group string) int {
	switch group {
	case "fabric":
		return cfg.Fabric.MaxResults
	case "controller_health":
		return cfg.ControllerHealth.MaxResults
	case "nodes":
		return cfg.Nodes.MaxResults
	case "faults":
		return cfg.Faults.MaxResults
	case "audit":
		return cfg.Audit.MaxResults
	case "events":
		return cfg.Events.MaxResults
	case "stats":
		return cfg.Stats.MaxResults
	case "endpoints":
		return cfg.Endpoints.MaxResults
	case "tenants":
		return cfg.Tenants.MaxResults
	case "topology":
		return cfg.Topology.MaxResults
	default:
		return 0
	}
}

type aciTargetMatcher struct {
	sites          map[string]struct{}
	fabrics        map[string]struct{}
	nodeIDs        map[string]struct{}
	serials        map[string]struct{}
	tenants        map[string]struct{}
	vrfs           map[string]struct{}
	bridgeDomains  map[string]struct{}
	epgs           map[string]struct{}
	interfaceNames map[string]struct{}
}

func newACITargetMatcher(filters ACITargetFilters) aciTargetMatcher {
	return aciTargetMatcher{
		sites:          normalizedSet(filters.Sites, normalizeACITargetName),
		fabrics:        normalizedSet(filters.Fabrics, normalizeACITargetName),
		nodeIDs:        normalizedSet(filters.NodeIDs, normalizeACINodeID),
		serials:        normalizedSet(filters.Serials, normalizeACITargetName),
		tenants:        normalizedSet(filters.Tenants, normalizeACITargetName),
		vrfs:           normalizedSet(filters.VRFs, normalizeACITargetName),
		bridgeDomains:  normalizedSet(filters.BridgeDomains, normalizeACITargetName),
		epgs:           normalizedSet(filters.EPGs, normalizeACITargetName),
		interfaceNames: normalizedSet(filters.InterfaceNames, normalizeACIInterfaceName),
	}
}

func (m aciTargetMatcher) empty() bool {
	return len(m.sites) == 0 && len(m.fabrics) == 0 && len(m.nodeIDs) == 0 && len(m.serials) == 0 &&
		len(m.tenants) == 0 && len(m.vrfs) == 0 && len(m.bridgeDomains) == 0 && len(m.epgs) == 0 &&
		len(m.interfaceNames) == 0
}

func (m aciTargetMatcher) allows(obj aci.Object) bool {
	return aciTargetDimensionAllows(m.sites, aciObjectFields(obj, "siteName", "site"), normalizeACITargetName) &&
		aciTargetDimensionAllows(m.fabrics, aciObjectFields(obj, "fabricName", "fabric"), normalizeACITargetName) &&
		aciTargetDimensionAllows(m.nodeIDs, aciObjectNodeIDs(obj), normalizeACINodeID) &&
		aciTargetDimensionAllows(m.serials, aciObjectFields(obj, "serial"), normalizeACITargetName) &&
		aciTargetDimensionAllows(m.tenants, aciObjectTenantNames(obj), normalizeACITargetName) &&
		aciTargetDimensionAllows(m.vrfs, aciObjectVRFNames(obj), normalizeACITargetName) &&
		aciTargetDimensionAllows(m.bridgeDomains, aciObjectBridgeDomainNames(obj), normalizeACITargetName) &&
		aciTargetDimensionAllows(m.epgs, aciObjectEPGNames(obj), normalizeACITargetName) &&
		aciTargetDimensionAllows(m.interfaceNames, aciObjectInterfaceNames(obj), normalizeACIInterfaceName)
}

func aciTargetDimensionAllows(configured map[string]struct{}, values []string, normalize func(string) string) bool {
	return len(configured) == 0 || matchAny(configured, values, normalize)
}

func aciObjectFields(obj aci.Object, keys ...string) []string {
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		if value := aci.String(obj, key); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func aciObjectNodeIDs(obj aci.Object) []string {
	values := []string{
		nodeIDFromACIDN(aci.String(obj, "dn")),
		nodeIDFromACIDN(aci.String(obj, "rn")),
		aci.String(obj, "nodeId"),
		aci.String(obj, "nodeID"),
	}
	switch strings.ToLower(aci.String(obj, "aci.class")) {
	case "fabricnode", "fabricloosenode", "topsystem":
		values = append(values, aci.String(obj, "id"))
	case "fabriclink":
		values = append(values, aci.String(obj, "n1"), aci.String(obj, "n2"))
	}
	return values
}

func aciObjectTenantNames(obj aci.Object) []string {
	values := []string{
		tenantFromACIDN(aci.String(obj, "dn")),
		tenantFromACIDN(aci.String(obj, "rn")),
		tenantFromACIDN(aci.String(obj, "tenantDn")),
		aci.String(obj, "tenant"),
		aci.String(obj, "tenantName"),
		aci.String(obj, "tnFvTenantName"),
	}
	if strings.EqualFold(aci.String(obj, "aci.class"), "fvTenant") {
		values = append(values, aci.String(obj, "name"))
	}
	return values
}

func aciObjectVRFNames(obj aci.Object) []string {
	values := []string{
		vrfFromACIDN(aci.String(obj, "dn")),
		vrfFromACIDN(aci.String(obj, "rn")),
		vrfFromACIDN(aci.String(obj, "ctxDn")),
		aci.String(obj, "vrf"),
		aci.String(obj, "vrfName"),
		aci.String(obj, "tnFvCtxName"),
	}
	if strings.EqualFold(aci.String(obj, "aci.class"), "fvCtx") {
		values = append(values, aci.String(obj, "name"))
	}
	return values
}

func aciObjectBridgeDomainNames(obj aci.Object) []string {
	values := []string{
		bdFromACIDN(aci.String(obj, "dn")),
		bdFromACIDN(aci.String(obj, "rn")),
		bdFromACIDN(aci.String(obj, "bdDn")),
		aci.String(obj, "bd"),
		aci.String(obj, "bdName"),
		aci.String(obj, "tnFvBDName"),
	}
	if strings.EqualFold(aci.String(obj, "aci.class"), "fvBD") {
		values = append(values, aci.String(obj, "name"))
	}
	return values
}

func aciObjectEPGNames(obj aci.Object) []string {
	values := []string{
		epgFromACIDN(aci.String(obj, "dn")),
		epgFromACIDN(aci.String(obj, "rn")),
		epgFromACIDN(aci.String(obj, "epgDn")),
		aci.String(obj, "epg"),
		aci.String(obj, "epgName"),
		aci.String(obj, "tnFvAEPgName"),
	}
	if strings.EqualFold(aci.String(obj, "aci.class"), "fvAEPg") {
		values = append(values, aci.String(obj, "name"))
	}
	return values
}

func aciObjectInterfaceNames(obj aci.Object) []string {
	values := []string{
		interfaceNameFromACIDN(aci.String(obj, "dn")),
		interfaceNameFromACIDN(aci.String(obj, "rn")),
		aci.String(obj, "ifId"),
		aci.String(obj, "ifName"),
		aci.String(obj, "interfaceName"),
	}
	switch strings.ToLower(aci.String(obj, "aci.class")) {
	case "l1physif", "ethpmphysif":
		values = append(values, aci.String(obj, "id"), aci.String(obj, "name"))
	}
	return values
}

func normalizeACITargetName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func aciObjectIncludePredicate(filters ACITargetFilters, selector deviceSelectionMatcher) func(aci.Object) bool {
	targets := newACITargetMatcher(filters)
	if targets.empty() && selector.empty() {
		return nil
	}
	return func(obj aci.Object) bool {
		return targets.allows(obj) && selector.allows(aciObjectIdentity(obj))
	}
}

// aciEndpointIncludePredicate keeps controller, fabric, pod, and site-level
// health visible when a receiver also selects individual devices. Those
// aggregate objects do not reliably carry leaf/spine identity and applying a
// node, serial, or interface selector would turn an enabled health group into
// an empty result. Device- and object-scoped endpoint families retain the
// intersection of the native ACI target and shared device selectors.
func aciEndpointIncludePredicate(endpoint aciEndpoint, filters ACITargetFilters, selector deviceSelectionMatcher) func(aci.Object) bool {
	if endpoint.group == "controller_health" || endpoint.objectType == "aci.pod" || endpoint.objectType == "aci.fabric_health" {
		return nil
	}
	return aciObjectIncludePredicate(filters, selector)
}

func filterACIObjects(objects []aci.Object, filters ACITargetFilters) []aci.Object {
	matcher := newACITargetMatcher(filters)
	if matcher.empty() {
		return objects
	}
	filtered := make([]aci.Object, 0, len(objects))
	for _, obj := range objects {
		if matcher.allows(obj) {
			filtered = append(filtered, obj)
		}
	}
	return filtered
}

func normalizeACINodeID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if nodeID := nodeIDFromACIDN(value); nodeID != "" {
		return nodeID
	}
	return strings.TrimPrefix(value, "node-")
}

func normalizeACIInterfaceName(value string) string {
	value = strings.TrimSpace(value)
	if interfaceName := interfaceNameFromACIDN(value); interfaceName != "" {
		value = interfaceName
	}
	return strings.ToLower(strings.TrimSpace(strings.Trim(value, "[]")))
}

func aciObjectStatus(obj aci.Object) string {
	return firstNonEmpty(
		aci.String(obj, "status"),
		aci.String(obj, "operSt", "operState", "state"),
		aci.String(obj, "adminSt"),
		aci.String(obj, "health", "cur"),
		aci.String(obj, "severity", "lc"),
		aci.String(obj, "fabricSt"),
	)
}

func recordACINumeric(rb *resourceMetricsBuilder, obj aci.Object, key, name, description, unit string, attrs map[string]string, multiplier float64) {
	value, ok := aci.Float64(obj, key)
	if !ok {
		return
	}
	if multiplier != 0 && multiplier != 1 {
		value *= multiplier
	}
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return
	}
	rb.recordDouble(name, description, unit, value, attrs)
}

func recordACIAbsoluteSumInt(rb *resourceMetricsBuilder, obj aci.Object, key, name, description, unit string, attrs map[string]string) {
	value, ok := aci.Int64(obj, key)
	if !ok || value < 0 {
		return
	}
	rb.recordAbsoluteSumInt(name, description, unit, value, attrs)
}

func recordACISummedAbsoluteSumInt(rb *resourceMetricsBuilder, obj aci.Object, keys []string, name, description, unit string, attrs map[string]string) {
	var total int64
	found := false
	for _, key := range keys {
		value, ok := aci.Int64(obj, key)
		if !ok {
			continue
		}
		if value < 0 || total > math.MaxInt64-value {
			return
		}
		total += value
		found = true
	}
	if found {
		rb.recordAbsoluteSumInt(name, description, unit, total, attrs)
	}
}

func recordACIFirstNumeric(rb *resourceMetricsBuilder, obj aci.Object, keys []string, name, description, unit string, attrs map[string]string, multiplier float64) {
	for _, key := range keys {
		if _, ok := aci.Float64(obj, key); !ok {
			continue
		}
		recordACINumeric(rb, obj, key, name, description, unit, attrs, multiplier)
		return
	}
}

func recordACIFirstPercentRatio(rb *resourceMetricsBuilder, obj aci.Object, keys []string, name, description string, attrs map[string]string) {
	for _, key := range keys {
		value, ok := aci.Float64(obj, key)
		if !ok {
			continue
		}
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 100 {
			return
		}
		rb.recordDouble(name, description, "1", value/100, attrs)
		return
	}
}

func aciLogTimestamp(body map[string]string) (time.Time, bool) {
	for _, key := range []string{"created", "lastTransition"} {
		value := body[key]
		if value == "" {
			continue
		}
		if ts, err := time.Parse(time.RFC3339Nano, value); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}

func aciFabricName(obj aci.Object) string {
	return firstNonEmpty(aci.String(obj, "fabricName"), "aci")
}

func aciTenantName(obj aci.Object) string {
	if name := aci.String(obj, "name"); name != "" && strings.Contains(aci.String(obj, "aci.class"), "Tenant") {
		return name
	}
	return tenantFromACIDN(aci.String(obj, "dn"))
}

func tenantFromACIDN(dn string) string {
	return tokenAfterPrefix(dn, "tn-")
}

func vrfFromACIDN(dn string) string {
	return tokenAfterPrefix(dn, "ctx-")
}

func bdFromACIDN(dn string) string {
	return tokenAfterPrefix(dn, "BD-")
}

func epgFromACIDN(dn string) string {
	return tokenAfterPrefix(dn, "epg-")
}

func tokenAfterPrefix(dn, prefix string) string {
	for part := range strings.SplitSeq(dn, "/") {
		if after, ok := strings.CutPrefix(part, prefix); ok {
			return after
		}
	}
	return ""
}

func nodeIDFromACIDN(dn string) string {
	if node := tokenAfterPrefix(dn, "node-"); node != "" {
		return node
	}
	return ""
}

func aciNodeName(nodeID string) string {
	if nodeID == "" {
		return ""
	}
	return "node-" + nodeID
}

func interfaceNameFromACIDN(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, marker := range []string{"phys-[", "aggr-[", "mgmt-[", "if-["} {
		if start := strings.Index(value, marker); start >= 0 {
			rest := value[start+len(marker):]
			if end := strings.Index(rest, "]"); end >= 0 {
				return rest[:end]
			}
		}
	}
	trimmed := strings.Trim(value, "[]")
	for _, prefix := range []string{"eth", "po", "mgmt"} {
		if strings.HasPrefix(strings.ToLower(trimmed), prefix) {
			return trimmed
		}
	}
	parts := strings.Split(value, "/")
	for _, part := range slices.Backward(parts) {
		if strings.HasPrefix(part, "phys-[") && strings.HasSuffix(part, "]") {
			return strings.TrimSuffix(strings.TrimPrefix(part, "phys-["), "]")
		}
		if strings.Contains(part, "eth") {
			return strings.Trim(part, "[]")
		}
	}
	return ""
}

func topologyProtocol(className string) string {
	switch strings.ToLower(className) {
	case "lldpadjep":
		return "lldp"
	case "cdpadjep":
		return "cdp"
	default:
		return "aci"
	}
}

func aciCountDescription(name string) string {
	switch name {
	case "aci.resource.count":
		return "ACI resources by group, class, resource type, status, and severity."
	case "aci.audit.record.count":
		return "Recent APIC audit records by bounded operation, status, and severity attributes."
	case "aci.event.count":
		return "Recent APIC event records by bounded operation, status, and severity attributes."
	case "aci.fault.count":
		return "Active APIC faults."
	case "aci.endpoint.count":
		return "ACI endpoints."
	case "aci.tenant.object.count":
		return "ACI tenant, VRF, bridge domain, EPG, app profile, contract, and L3Out objects."
	default:
		return "ACI resources."
	}
}
