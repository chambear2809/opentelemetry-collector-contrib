// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"errors"
	"fmt"
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
			objects, err := client.ListClass(ctx, endpoint.operation, endpoint.className, aciEndpointQuery(endpoint, r.config, now), aciGroupMaxResults(r.config.ACI, endpoint.group))
			for _, obj := range filterACIObjects(objects, r.config.ACI.Targets) {
				if !selector.allows(aciObjectIdentity(obj)) {
					continue
				}
				builder.recordObject(client.ControllerName(), client.Endpoint(), endpoint, obj)
			}
			if err != nil {
				if ctx.Err() != nil {
					partial = true
					return r.finishScrape(builder, now, partial), ctx.Err()
				}
				partial = true
				r.settings.Logger.Warn("ACI endpoint failed", zap.String("controller", client.ControllerName()), zap.String("operation", endpoint.operation), zap.Error(err))
				builder.controllerResource(client.ControllerName(), client.Endpoint()).recordSum("aci.api.endpoint.error", "APIC endpoint scrape error.", "{error}", 1, map[string]string{
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
			builder.controllerResource(client.ControllerName(), client.Endpoint()).recordInt("aci.controller.up", "APIC controller API availability for this scrape.", "1", availability, nil)
		}
	}

	overall := summarizeAPIOutcomes(stats, func(stat aci.RequestStat) string { return stat.Outcome })
	rb := builder.globalResource()
	rb.recordInt("aci.scrape.partial_success", "Whether one or more APIC endpoint families failed during the scrape.", "1", boolToInt(partial), nil)
	if lastSuccess, ok := r.success.observe(time.Now(), !partial && overall.succeeded); ok {
		rb.recordInt("aci.scrape.last_success", "Unix timestamp of the most recent fully successful ACI scrape.", "s", lastSuccess.Unix(), nil)
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
		rb.recordDouble("aci.api.request.duration", "Average duration of APIC API request attempts in this scrape.", "s", aggregate.averageDurationSeconds, aggregate.attrs)
		if aggregate.errors > 0 {
			rb.recordSum("aci.api.request.errors", "APIC API request errors.", "{error}", aggregate.errors, aggregate.attrs)
		}
		if aggregate.rateLimited > 0 {
			rb.recordSum("aci.api.rate_limited", "APIC API requests that were rate limited.", "{request}", aggregate.rateLimited, aggregate.attrs)
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
			if !aciGroupEnabled(r.config.ACI, endpoint.group) {
				continue
			}
			objects, err := client.ListClass(ctx, endpoint.operation, endpoint.className, aciEndpointQuery(endpoint, r.config, now), aciGroupMaxResults(r.config.ACI, endpoint.group))
			for _, obj := range filterACIObjects(objects, r.config.ACI.Targets) {
				if !selector.allows(aciObjectIdentity(obj)) {
					continue
				}
				if r.seenBefore(client.ControllerName(), endpoint, obj, now) {
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

func (r *aciLogsReceiver) seenBefore(controller string, endpoint aciEndpoint, obj aci.Object, now time.Time) bool {
	stableID := aci.String(obj, "id", "uuid", "eventId", "eventID", "recordId", "dn")
	key := logDedupKey(controller+":"+endpoint.operation, stableID, obj)
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
	serial := aci.String(obj, "serial")
	hostID := firstNonEmpty(serial, nodeID, dn, aci.String(obj, "name", "mac", "ip"), endpoint.operation)
	if endpoint.group == "controllers" || strings.Contains(aci.String(obj, "role"), "controller") {
		hostID = firstNonEmpty(hostID, controllerName)
	}
	rb := b.resource(controllerName + ":" + endpoint.operation + ":" + hostID)
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
	rb.recordInt("aci.resource.info", "ACI managed object metadata.", "1", 1, attrs)
	if code, ok := statusCode(status); ok {
		rb.recordInt("aci.resource.status", "ACI managed object status encoded for troubleshooting.", "1", code, attrs)
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
	case "fabric", "nodes", "controllers":
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
			rb.recordInt("cisco.device.up", "ACI node availability reported by APIC.", "1", up, nil)
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
	rb.recordInt("aci.fault.active", "Active APIC fault.", "1", 1, attrs)
	b.addCount("aci.fault.count", attrs)
}

func (*aciMetricsBuilder) recordStatsObject(rb *resourceMetricsBuilder, obj aci.Object) {
	if ifName := interfaceNameFromACIDN(aci.String(obj, "dn", "id", "name")); ifName != "" {
		attrs := interfaceAttrs(ifName, "", aci.String(obj, "descr"), aci.String(obj, "speed", "ethpmCfgSpeed"))
		if status := aciObjectStatus(obj); status != "" {
			if up, ok := upStatus(status); ok {
				rb.recordInt("system.network.interface.status", "ACI interface operational status.", "1", up, attrs)
			}
		}
		recordACINumeric(rb, obj, "bytesRate", "cisco.interface.io.rate", "Interface traffic rate.", "bit/s", attrs, 8)
		recordACINumeric(rb, obj, "pktsRate", "cisco.interface.packet.rate", "Interface packet rate.", "{packet}/s", attrs, 1)
		recordACINumeric(rb, obj, "dropRate", "cisco.interface.drop.rate", "Interface drop rate.", "{drop}/s", attrs, 1)
	}
	recordACINumeric(rb, obj, "userLast", "system.cpu.utilization", "CPU utilization reported by APIC.", "1", map[string]string{"cpu.mode": "user"}, 0.01)
	recordACINumeric(rb, obj, "kernelLast", "system.cpu.utilization", "CPU utilization reported by APIC.", "1", map[string]string{"cpu.mode": "kernel"}, 0.01)
	recordACINumeric(rb, obj, "usedLast", "system.memory.utilization", "Memory utilization reported by APIC.", "1", map[string]string{"system.memory.state": "used"}, 0.01)
}

func (b *aciMetricsBuilder) recordEndpointObject(rb *resourceMetricsBuilder, obj aci.Object) {
	attrs := compactAttrs(map[string]string{
		"aci.endpoint.mac": aci.String(obj, "mac"),
		"aci.endpoint.ip":  aci.String(obj, "ip"),
		"aci.endpoint.dn":  aci.String(obj, "dn"),
	})
	rb.recordInt("aci.endpoint.present", "Endpoint observed by APIC.", "1", 1, attrs)
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
	attrs := compactAttrs(map[string]string{
		"network.interface.name": interfaceNameFromACIDN(aci.String(obj, "dn", "id")),
		"network.peer.name":      aci.String(obj, "sysName", "chassisIdV", "portIdV", "name"),
		"network.peer.address":   aci.String(obj, "mgmtIp", "mgmtPortMac", "mac"),
		"network.protocol.name":  topologyProtocol(aci.String(obj, "aci.class")),
	})
	rb.recordInt("cisco.topology.neighbor.info", "ACI topology neighbor information.", "1", 1, attrs)
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
	rl := ld.ResourceLogs().AppendEmpty()
	attrs := rl.Resource().Attributes()
	nodeID := firstNonEmpty(aci.String(obj, "nodeId", "id"), nodeIDFromACIDN(aci.String(obj, "dn")))
	putStr(attrs, "host.id", firstNonEmpty(aci.String(obj, "serial"), nodeID, aci.String(obj, "dn")))
	putStr(attrs, "host.name", firstNonEmpty(aci.String(obj, "name"), aci.String(obj, "dn")))
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Cisco ACI")
	putStr(attrs, "cisco.controller.type", "apic")
	putStr(attrs, "cisco.controller.endpoint", controllerEndpoint)
	putStr(attrs, "aci.controller.name", controllerName)
	putStr(attrs, "aci.node.id", nodeID)
	putStr(attrs, "cisco.switch.serial", aci.String(obj, "serial"))
	putStr(attrs, "cisco.fabric.name", aciFabricName(obj))
	putStr(attrs, "aci.dn", aci.String(obj, "dn"))
	putStr(attrs, "aci.class", aci.String(obj, "aci.class"))

	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName(aciScopeName)
	record := sl.LogRecords().AppendEmpty()
	record.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	if ts, ok := aciLogTimestamp(obj); ok {
		if timestamp, valid := pdataTimestampFromTime(ts); valid {
			record.SetTimestamp(timestamp)
		}
	}
	status := aciObjectStatus(obj)
	severity := firstNonEmpty(aci.String(obj, "severity", "lc", "type"), status)
	record.SetSeverityText(severity)
	record.SetSeverityNumber(logSeverityNumber(severity))
	record.Body().SetEmptyMap()
	body := record.Body().Map()
	for key, value := range obj {
		setLogValue(body, key, value)
	}
	logAttrs := record.Attributes()
	putStr(logAttrs, "event.domain", "aci")
	putStr(logAttrs, "event.name", endpoint.operation)
	putStr(logAttrs, "aci.operation", endpoint.operation)
	putStr(logAttrs, "aci.group", endpoint.group)
	putStr(logAttrs, "aci.status", status)
	putStr(logAttrs, "aci.severity", strings.ToLower(severity))
	putStr(logAttrs, "user.name", aci.String(obj, "user", "userName", "createdBy", "modTs"))
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
		{group: "stats", operation: "stats.cpu", className: "procSysCPU5min", objectType: "aci.cpu"},
		{group: "stats", operation: "stats.memory", className: "procSysMem5min", objectType: "aci.memory"},
		{group: "stats", operation: "stats.fabric_health", className: "fabricOverallHealthHist5min", objectType: "aci.fabric_health"},
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

func filterACIObjects(objects []aci.Object, filters ACITargetFilters) []aci.Object {
	needles := makeFilterNeedles(filters.Sites, filters.Fabrics, filters.NodeIDs, filters.Serials, filters.Tenants, filters.VRFs, filters.BridgeDomains, filters.EPGs, filters.InterfaceNames)
	if len(needles) == 0 {
		return objects
	}
	filtered := make([]aci.Object, 0, len(objects))
	for _, obj := range objects {
		text := aci.SearchText(obj)
		for needle := range needles {
			if strings.Contains(text, needle) {
				filtered = append(filtered, obj)
				break
			}
		}
	}
	return filtered
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

func recordACIFirstNumeric(rb *resourceMetricsBuilder, obj aci.Object, keys []string, name, description, unit string, attrs map[string]string, multiplier float64) {
	for _, key := range keys {
		if _, ok := aci.Float64(obj, key); !ok {
			continue
		}
		recordACINumeric(rb, obj, key, name, description, unit, attrs, multiplier)
		return
	}
}

func aciLogTimestamp(obj aci.Object) (time.Time, bool) {
	for _, key := range []string{"created", "modTs", "lastTransition", "changeSet", "ts"} {
		if ts, ok := aci.Time(obj, key); ok {
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
	if value == "" {
		return ""
	}
	if start := strings.Index(value, "phys-["); start >= 0 {
		rest := value[start+len("phys-["):]
		if end := strings.Index(rest, "]"); end >= 0 {
			return rest[:end]
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
