// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"reflect"
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

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/intersight"
)

const intersightScopeName = "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/intersight"

type intersightMetricsReceiver struct {
	settings receiver.Settings
	config   *Config
	consumer consumer.Metrics
	client   *intersight.Client
	counters *counterStore
	obs      *receiverhelper.ObsReport
	success  scrapeSuccessState

	startMu sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}

	statsMu sync.Mutex
	stats   []intersight.RequestStat
}

type intersightLogsReceiver struct {
	settings receiver.Settings
	config   *Config
	consumer consumer.Logs
	client   *intersight.Client
	obs      *receiverhelper.ObsReport

	startMu sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}

	seen *logDeduplicator
}

type intersightEndpoint struct {
	group        string
	operation    string
	path         string
	objectType   string
	selectFields []string
	query        func(*Config, time.Time) url.Values
}

type intersightTelemetryQuery struct {
	name        string
	dataSource  string
	instrument  string
	dimensions  []string
	field       string
	fieldName   string
	aggregation string
	metricName  string
	description string
	unit        string
}

func newIntersightMetricsReceiver(set receiver.Settings, conf *Config, consumer consumer.Metrics) (*intersightMetricsReceiver, error) {
	client, err := newIntersightClient(conf)
	if err != nil {
		return nil, err
	}
	r := &intersightMetricsReceiver{
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

func newIntersightLogsReceiver(set receiver.Settings, conf *Config, consumer consumer.Logs) (*intersightLogsReceiver, error) {
	client, err := newIntersightClient(conf)
	if err != nil {
		return nil, err
	}
	return &intersightLogsReceiver{
		settings: set,
		config:   conf,
		consumer: consumer,
		client:   client,
		obs:      newPlatformObsReport(set, "http"),
		done:     make(chan struct{}),
		seen:     newLogDeduplicator(),
	}, nil
}

func newIntersightClient(conf *Config) (*intersight.Client, error) {
	return intersight.NewClient(intersight.Config{
		KeyID:              conf.Intersight.Auth.KeyID,
		KeyPEM:             string(conf.Intersight.Auth.KeyPEM),
		KeyFile:            conf.Intersight.Auth.KeyFile,
		Endpoint:           conf.Intersight.Endpoint,
		UserAgent:          conf.Intersight.UserAgent,
		Timeout:            conf.ControllerConfig.Timeout,
		MaxRetries:         conf.Intersight.MaxRetries,
		PageSize:           conf.Intersight.PageSize,
		InsecureSkipVerify: conf.Intersight.InsecureSkipVerify,
	})
}

func (r *intersightMetricsReceiver) Start(_ context.Context, _ component.Host) error {
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

func (r *intersightMetricsReceiver) Shutdown(ctx context.Context) error {
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

func (r *intersightMetricsReceiver) run(ctx context.Context) {
	defer close(r.done)
	r.collect(ctx)
	ticker := time.NewTicker(r.config.ControllerConfig.CollectionInterval)
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

func (r *intersightMetricsReceiver) collect(ctx context.Context) {
	scrapeCtx, cancel := context.WithTimeout(ctx, r.config.ControllerConfig.Timeout)
	defer cancel()

	obsCtx := startMetricsOp(ctx, r.obs)
	md, scrapeErr := r.scrape(scrapeCtx)
	if scrapeErr != nil {
		r.settings.Logger.Error("Intersight scrape failed", zap.Error(scrapeErr))
	}
	metricCount, consumeErr := consumeMetricsIfPresent(ctx, r.consumer, md)
	if consumeErr != nil {
		r.settings.Logger.Error("Intersight metrics consumer failed", zap.Error(consumeErr))
	}
	endMetricsOp(obsCtx, r.obs, metricCount, combineSignalErrors(scrapeErr, consumeErr))
}

func (r *intersightMetricsReceiver) scrape(ctx context.Context) (pmetric.Metrics, error) {
	r.resetRequestStats()
	now := time.Now()
	builder := newIntersightMetricsBuilder(now, r.config.Intersight.Endpoint, r.counters)
	selector := newDeviceSelectionMatcher(r.config.DeviceSelection)
	partial := false

	for _, endpoint := range intersightMetricEndpoints() {
		if !intersightGroupEnabled(r.config.Intersight, endpoint.group) {
			continue
		}
		objects, err := r.client.List(ctx, endpoint.operation, endpoint.path, endpointQuery(endpoint, r.config, now), intersightGroupMaxResults(r.config.Intersight, endpoint.group))
		for _, obj := range filterIntersightObjects(objects, r.config.Intersight.Targets) {
			if !selector.allows(intersightObjectIdentity(obj)) {
				continue
			}
			builder.recordObject(endpoint, obj)
		}
		if err != nil {
			if ctx.Err() != nil {
				partial = true
				return r.finishScrape(builder, now, partial), ctx.Err()
			}
			partial = true
			r.settings.Logger.Warn("Intersight endpoint failed", zap.String("operation", endpoint.operation), zap.Error(err))
			continue
		}
	}

	if r.config.Intersight.Telemetry.Enabled {
		queries := intersightTelemetryQueries()
		for i := range queries {
			query := &queries[i]
			if err := r.scrapeTelemetry(ctx, builder, *query, now, selector); err != nil {
				if ctx.Err() != nil {
					partial = true
					return r.finishScrape(builder, now, partial), ctx.Err()
				}
				partial = true
				r.settings.Logger.Warn("Intersight telemetry query failed", zap.String("query", query.name), zap.Error(err))
			}
		}
	}

	return r.finishScrape(builder, now, partial), nil
}

func (r *intersightMetricsReceiver) finishScrape(builder *intersightMetricsBuilder, _ time.Time, partial bool) pmetric.Metrics {
	r.recordAPIRequestMetrics(builder)
	stats := r.requestStats()
	outcome := summarizeAPIOutcomes(stats, func(stat intersight.RequestStat) string { return stat.Outcome })
	rb := builder.accountResource()
	rb.recordInt("intersight.scrape.partial_success", "Whether one or more Intersight endpoint families failed during a scrape.", "1", boolToInt(partial), nil)
	if lastSuccess, ok := r.success.observe(time.Now(), !partial && outcome.succeeded); ok {
		rb.recordInt("intersight.scrape.last_success", "Unix timestamp of the most recent fully successful Intersight scrape.", "s", lastSuccess.Unix(), nil)
	}
	builder.flushCounts()
	return builder.emit()
}

func (r *intersightMetricsReceiver) scrapeTelemetry(ctx context.Context, builder *intersightMetricsBuilder, query intersightTelemetryQuery, now time.Time, selector deviceSelectionMatcher) error {
	lookback := r.config.Intersight.TelemetryLookback
	if lookback <= 0 {
		lookback = defaultIntersightConfig().TelemetryLookback
	}
	start := now.Add(-lookback).UTC().Format("2006-01-02T15:04:05.000Z")
	end := now.UTC().Format("2006-01-02T15:04:05.000Z")
	body := map[string]any{
		"queryType":   "groupBy",
		"dataSource":  query.dataSource,
		"granularity": "all",
		"intervals":   []string{start + "/" + end},
		"dimensions":  query.dimensions,
		"filter": map[string]any{
			"type": "and",
			"fields": []map[string]any{{
				"type":      "selector",
				"dimension": "instrument.name",
				"value":     query.instrument,
			}},
		},
		"aggregations": []map[string]any{{
			"type":      query.aggregation,
			"name":      query.fieldName,
			"fieldName": query.field,
		}},
	}
	response, err := r.client.PostJSON(ctx, "telemetry."+query.name, "/api/v1/telemetry/GroupBys", body)
	if err != nil {
		return err
	}
	results, ok := response.([]any)
	if !ok {
		return fmt.Errorf("decode Intersight telemetry.%s response: expected array", query.name)
	}
	builder.recordTelemetry(query, results, selector, r.config.Intersight.Telemetry.MaxResults)
	return nil
}

func (r *intersightMetricsReceiver) recordRequest(stat intersight.RequestStat) {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats = append(r.stats, stat)
}

func (r *intersightMetricsReceiver) resetRequestStats() {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats = nil
}

func (r *intersightMetricsReceiver) requestStats() []intersight.RequestStat {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	return append([]intersight.RequestStat(nil), r.stats...)
}

func (r *intersightMetricsReceiver) recordAPIRequestMetrics(builder *intersightMetricsBuilder) {
	stats := r.requestStats()
	observations := make([]apiRequestObservation, 0, len(stats))
	for _, stat := range stats {
		attrs := map[string]string{
			"intersight.api.operation": stat.Operation,
			"http.request.method":      stat.Method,
			"intersight.api.outcome":   stat.Outcome,
		}
		if stat.StatusCode > 0 {
			attrs["http.response.status_code"] = strconv.Itoa(stat.StatusCode)
		}
		observations = append(observations, apiRequestObservation{attrs: attrs, durationSeconds: stat.Duration.Seconds(), failed: stat.Outcome != "success", rateLimited: stat.RateLimited})
	}
	for _, aggregate := range aggregateAPIRequestObservations(observations) {
		rb := builder.accountResource()
		rb.recordDouble("intersight.api.request.duration", "Average duration of Intersight API request attempts within the scrape for each matching request-attribute set.", "s", aggregate.averageDurationSeconds, aggregate.attrs)
		if aggregate.errors > 0 {
			rb.recordSum("intersight.api.request.errors", "Intersight API request failures.", "{error}", aggregate.errors, aggregate.attrs)
		}
		if aggregate.rateLimited > 0 {
			rb.recordSum("intersight.api.rate_limited", "Requests that received HTTP 429.", "{request}", aggregate.rateLimited, aggregate.attrs)
		}
	}
}

func (r *intersightLogsReceiver) Start(_ context.Context, _ component.Host) error {
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

func (r *intersightLogsReceiver) Shutdown(ctx context.Context) error {
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

func (r *intersightLogsReceiver) run(ctx context.Context) {
	defer close(r.done)
	r.collect(ctx)
	ticker := time.NewTicker(r.config.ControllerConfig.CollectionInterval)
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

func (r *intersightLogsReceiver) collect(ctx context.Context) {
	scrapeCtx, cancel := context.WithTimeout(ctx, r.config.ControllerConfig.Timeout)
	defer cancel()

	r.seen.BeginBatch()
	obsCtx := startLogsOp(ctx, r.obs)
	ld, scrapeErr := r.scrape(scrapeCtx)
	if scrapeErr != nil {
		r.settings.Logger.Error("Intersight log scrape failed", zap.Error(scrapeErr))
	}
	logCount, consumeErr := consumeDeduplicatedLogs(ctx, r.consumer, r.seen, ld)
	if consumeErr != nil {
		r.settings.Logger.Error("Intersight logs consumer failed", zap.Error(consumeErr))
	}
	endLogsOp(obsCtx, r.obs, logCount, combineSignalErrors(scrapeErr, consumeErr))
}

func (r *intersightLogsReceiver) scrape(ctx context.Context) (plog.Logs, error) {
	ld := plog.NewLogs()
	now := time.Now()
	var endpointErrors []error
	selector := newDeviceSelectionMatcher(r.config.DeviceSelection)
	for _, endpoint := range intersightLogEndpoints() {
		if !intersightGroupEnabled(r.config.Intersight, endpoint.group) {
			continue
		}
		objects, err := r.client.List(ctx, endpoint.operation, endpoint.path, endpointQuery(endpoint, r.config, now), intersightGroupMaxResults(r.config.Intersight, endpoint.group))
		for _, obj := range filterIntersightObjects(objects, r.config.Intersight.Targets) {
			if !selector.allows(intersightObjectIdentity(obj)) {
				continue
			}
			if r.seenBefore(endpoint, obj, now) {
				continue
			}
			appendIntersightLog(ld, endpoint, obj, now)
		}
		if err != nil {
			if ctx.Err() != nil {
				return ld, ctx.Err()
			}
			r.settings.Logger.Warn("Intersight log endpoint failed", zap.String("operation", endpoint.operation), zap.Error(err))
			endpointErrors = append(endpointErrors, fmt.Errorf("Intersight %s: %w", endpoint.operation, err))
			continue
		}
	}
	r.expireSeen(now)
	return ld, errors.Join(endpointErrors...)
}

func (r *intersightLogsReceiver) seenBefore(endpoint intersightEndpoint, obj intersight.Object, now time.Time) bool {
	stableID := intersight.String(obj, "Moid", "InstId", "EventId", "EventMoid", "AuditRecordId", "RequestId")
	key := logDedupKey(endpoint.operation, stableID, obj)
	return !r.seen.MarkPending(key, now)
}

func (r *intersightLogsReceiver) expireSeen(now time.Time) {
	ttl := r.config.Intersight.EventLookback
	if ttl <= 0 {
		ttl = defaultIntersightConfig().EventLookback
	}
	ttl *= 2
	r.seen.Expire(now.Add(-ttl), 0)
}

type intersightMetricsBuilder struct {
	metrics   pmetric.Metrics
	now       pcommon.Timestamp
	start     pcommon.Timestamp
	resources map[string]*resourceMetricsBuilder
	counts    map[string]*intersightCount
	endpoint  string
	counters  *counterStore
}

type intersightCount struct {
	value int64
	attrs map[string]string
}

func newIntersightMetricsBuilder(now time.Time, endpoint string, counters *counterStore) *intersightMetricsBuilder {
	if counters == nil {
		counters = newCounterStore()
	}
	ts := pcommon.NewTimestampFromTime(now)
	return &intersightMetricsBuilder{
		metrics:   pmetric.NewMetrics(),
		now:       ts,
		start:     pcommon.NewTimestampFromTime(counters.StartTime()),
		resources: map[string]*resourceMetricsBuilder{},
		counts:    map[string]*intersightCount{},
		endpoint:  endpoint,
		counters:  counters,
	}
}

func (b *intersightMetricsBuilder) emit() pmetric.Metrics {
	return b.metrics
}

func (b *intersightMetricsBuilder) accountResource() *resourceMetricsBuilder {
	rb := b.resource("account")
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", "intersight:"+firstNonEmpty(b.endpoint, "default"))
	putStr(attrs, "host.name", "Cisco Intersight")
	putStr(attrs, "os.name", "Intersight")
	putStr(attrs, "intersight.endpoint", b.endpoint)
	return rb
}

func (b *intersightMetricsBuilder) objectResource(objectType string, obj intersight.Object) *resourceMetricsBuilder {
	serial := firstNonEmpty(intersight.String(obj, "Serial", "SerialNumber"), firstString(intersight.StringSlice(obj, "Serial")))
	moid := intersight.String(obj, "Moid")
	hostID := firstNonEmpty(serial, moid, intersight.String(obj, "DeviceMoId"), intersight.String(obj, "ClusterUuid", "NodeUuid"), intersight.String(obj, "Name", "HostName"), objectType)
	resourceID := firstNonEmpty(moid, serial, intersight.String(obj, "DeviceMoId"), intersight.String(obj, "ClusterUuid", "NodeUuid"), intersight.String(obj, "Name", "HostName"), objectType)
	rb := b.resource(objectType + ":" + resourceID)
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", hostID)
	putStr(attrs, "host.name", firstNonEmpty(intersight.String(obj, "Name", "HostName"), firstString(intersight.StringSlice(obj, "DeviceHostname")), hostID))
	putIPAttrs(attrs, "host.ip", append([]string{
		intersight.String(obj, "MgmtIpAddress"),
		intersight.String(obj, "Ipv4Address"),
		intersight.String(obj, "OutOfBandIpAddress"),
		intersight.String(obj, "InbandIpAddress"),
	}, intersight.StringSlice(obj, "DeviceIpAddress")...)...)
	putStr(attrs, "host.type", firstNonEmpty(intersight.String(obj, "Model", "PlatformType", "SourceObjectType"), objectType))
	putStr(attrs, "os.name", "Intersight")
	putStr(attrs, "os.version", firstNonEmpty(intersight.String(obj, "Firmware", "Version", "BundleVersion", "HxdpBuildVersion"), intersight.String(obj, "DisplayVersion")))
	putStr(attrs, "intersight.moid", moid)
	putStr(attrs, "intersight.resource.type", objectType)
	putStr(attrs, "intersight.device.registration_moid", intersight.RelationshipMoid(obj, "RegisteredDevice"))
	putStr(attrs, "intersight.serial", serial)
	return rb
}

func (b *intersightMetricsBuilder) resource(key string) *resourceMetricsBuilder {
	if rb := b.resources[key]; rb != nil {
		return rb
	}
	rm := b.metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName(intersightScopeName)
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

func (b *intersightMetricsBuilder) addCount(name string, attrs map[string]string) {
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
	b.counts[key] = &intersightCount{value: 1, attrs: attrs}
}

func (b *intersightMetricsBuilder) flushCounts() {
	rb := b.accountResource()
	keys := make([]string, 0, len(b.counts))
	for key := range b.counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		count := b.counts[key]
		metricName, _, _ := strings.Cut(key, "|")
		rb.recordInt(metricName, intersightCountDescription(metricName), "1", count.value, count.attrs)
	}
}

func (b *intersightMetricsBuilder) recordObject(endpoint intersightEndpoint, obj intersight.Object) {
	objectType := intersight.ObjectType(obj, endpoint.objectType)
	if endpoint.group == "audit" {
		b.addCount("intersight.audit.record.count", map[string]string{"intersight.audit.user": firstNonEmpty(intersight.String(obj, "UserIdOrEmail", "Email"), "unknown")})
		return
	}
	rb := b.objectResource(objectType, obj)
	status := objectStatus(obj)
	severity := strings.ToLower(firstNonEmpty(intersight.String(obj, "Severity", "OrigSeverity"), status))

	infoAttrs := map[string]string{
		"intersight.resource.type": objectType,
		"intersight.status":        status,
		"intersight.severity":      severity,
	}
	putNonEmpty(infoAttrs, "intersight.model", intersight.String(obj, "Model", "PlatformType"))
	putNonEmpty(infoAttrs, "intersight.source_object_type", intersight.String(obj, "SourceObjectType", "AffectedMoType", "AffectedObjectType"))
	rb.recordInt("intersight.resource.info", "Inventory metadata for an Intersight resource.", "1", 1, infoAttrs)
	if code, ok := statusCode(status); ok {
		rb.recordInt("intersight.resource.status", "Encoded resource status, with the original status retained as an attribute.", "1", code, map[string]string{
			"intersight.resource.type": objectType,
			"intersight.status":        status,
		})
	}
	b.addCount("intersight.resource.count", compactAttrs(map[string]string{
		"intersight.resource.type": objectType,
		"intersight.status":        status,
		"intersight.severity":      severity,
	}))

	switch endpoint.group {
	case "events":
		b.recordEventObject(rb, endpoint, obj, objectType, status, severity)
	case "inventory", "equipment", "network":
		b.recordInventoryObject(rb, obj, objectType, status)
	case "firmware":
		if version := intersight.String(obj, "BundleVersion", "Version"); version != "" {
			rb.recordInt("intersight.firmware.bundle.info", "Firmware bundle identity with the version in `intersight.firmware.version`.", "1", 1, map[string]string{"intersight.firmware.version": version})
		}
	case "storage":
		b.recordStorageObject(rb, obj)
	case "hyperflex":
		b.recordHyperFlexObject(rb, obj)
	case "kubernetes":
		recordStringState(rb, "intersight.kubernetes.cluster.connection_status", "Kubernetes cluster connection status.", status)
	case "virtualization":
		b.recordVirtualizationObject(rb, obj)
	}
}

func (b *intersightMetricsBuilder) recordEventObject(rb *resourceMetricsBuilder, endpoint intersightEndpoint, obj intersight.Object, objectType, status, severity string) {
	attrs := compactAttrs(map[string]string{
		"intersight.resource.type": objectType,
		"intersight.status":        status,
		"intersight.severity":      severity,
		"intersight.acknowledge":   intersight.String(obj, "Acknowledge"),
	})
	switch {
	case strings.Contains(endpoint.operation, "alarm"):
		rb.recordInt("intersight.alarm.active", "Active alarm instances.", "1", 1, attrs)
		b.addCount("intersight.alarm.count", attrs)
	case strings.Contains(endpoint.operation, "advisory") || strings.Contains(endpoint.operation, "advisories"):
		rb.recordInt("intersight.advisory.active", "Active advisory or security advisory exposure.", "1", 1, attrs)
		b.addCount("intersight.advisory.count", attrs)
	case strings.Contains(endpoint.operation, "hcl"):
		if code, ok := statusCode(status); ok {
			rb.recordInt("intersight.hcl.status", "Hardware compatibility/compliance status.", "1", code, attrs)
		}
		b.addCount("intersight.hcl.status.count", attrs)
	case strings.Contains(endpoint.operation, "task"):
		if code, ok := statusCode(status); ok {
			rb.recordInt("intersight.task.status", "Workflow task execution status.", "1", code, attrs)
		}
		b.addCount("intersight.task.count", attrs)
	case strings.Contains(endpoint.operation, "workflow"):
		if code, ok := statusCode(status); ok {
			rb.recordInt("intersight.workflow.status", "Workflow execution status.", "1", code, attrs)
		}
		b.addCount("intersight.workflow.count", attrs)
	case strings.Contains(endpoint.operation, "techsupport"):
		if code, ok := statusCode(status); ok {
			rb.recordInt("intersight.techsupport.status", "Tech-support collection/upload status.", "1", code, attrs)
		}
		b.addCount("intersight.techsupport.count", attrs)
	}
}

func (*intersightMetricsBuilder) recordInventoryObject(rb *resourceMetricsBuilder, obj intersight.Object, objectType, status string) {
	if strings.Contains(objectType, "DeviceRegistration") || strings.Contains(objectType, "Target") || strings.Contains(objectType, "PhysicalSummary") || strings.Contains(objectType, "Blade") || strings.Contains(objectType, "RackUnit") || strings.Contains(objectType, "Network") {
		if up, ok := upStatus(status); ok {
			rb.recordInt("cisco.device.up", "Device availability (1 = up, 0 = down)", "1", up, nil)
		}
	}
	recordIfInt(rb, obj, "NumCpuCores", "system.cpu.logical.count", "Number of CPU cores reported by Intersight.", "{cpu}", nil)
	recordIfInt(rb, obj, "NumThreads", "intersight.compute.thread.count", "Number of CPU threads reported by Intersight.", "{thread}", nil)
	recordIfInt(rb, obj, "AvailableMemory", "intersight.compute.available_memory", "Available server memory reported by Intersight.", "MBy", nil)
	recordIfInt(rb, obj, "FaultSummary", "intersight.fault.count", "Faults summarized by Intersight.", "{fault}", nil)
	recordStringState(rb, "intersight.target.connection_status", "Intersight target connection status.", status)
}

func (*intersightMetricsBuilder) recordStorageObject(rb *resourceMetricsBuilder, obj intersight.Object) {
	recordIfInt(rb, obj, "MediaErrorCount", "intersight.storage.media_error.count", "Storage media errors reported by Intersight.", "{error}", nil)
	recordIfInt(rb, obj, "PredictiveFailureCount", "intersight.storage.predictive_failure.count", "Storage predictive failures reported by Intersight.", "{failure}", nil)
	recordIfInt(rb, obj, "PercentLifeLeft", "intersight.storage.life_left", "Storage device remaining life percentage.", "%", nil)
	recordIfInt(rb, obj, "OperatingTemperature", "intersight.storage.temperature", "Storage device operating temperature.", "Cel", nil)
	recordIfInt(rb, obj, "PowerOnHours", "intersight.storage.power_on.hours", "Storage device power-on hours.", "h", nil)
	recordIfInt(rb, obj, "RebuildRatePercent", "intersight.storage.rebuild.rate", "Storage controller rebuild rate.", "%", nil)
	recordStringState(rb, "intersight.storage.status", "Storage status reported by Intersight.", objectStatus(obj))
}

func (*intersightMetricsBuilder) recordHyperFlexObject(rb *resourceMetricsBuilder, obj intersight.Object) {
	recordIfInt(rb, obj, "VmCount", "intersight.virtual_machine.count", "Virtual machines reported by Intersight.", "{vm}", nil)
	recordIfInt(rb, obj, "FltAggr", "intersight.fault.count", "Faults summarized by HyperFlex.", "{fault}", map[string]string{"intersight.platform": "hyperflex"})
	recordStringState(rb, "intersight.hyperflex.status", "HyperFlex status reported by Intersight.", objectStatus(obj))
}

func (*intersightMetricsBuilder) recordVirtualizationObject(rb *resourceMetricsBuilder, obj intersight.Object) {
	recordIfInt(rb, obj, "Cpu", "intersight.virtual_machine.cpu.count", "Virtual machine CPU count.", "{cpu}", nil)
	recordIfInt(rb, obj, "Memory", "intersight.virtual_machine.memory", "Virtual machine configured memory.", "MBy", nil)
	recordStringState(rb, "intersight.virtual_machine.power_state", "Virtual machine power state.", intersight.String(obj, "PowerState"))
}

func (b *intersightMetricsBuilder) recordTelemetry(query intersightTelemetryQuery, results []any, selector deviceSelectionMatcher, maxResults int) {
	outcomes := map[string]int64{"emitted": 0}
	retained := results
	if maxResults > 0 && len(retained) > maxResults {
		outcomes["max_results"] = int64(len(retained) - maxResults)
		retained = retained[:maxResults]
	}
	for _, item := range retained {
		obj, ok := item.(map[string]any)
		if !ok {
			outcomes["malformed_row"]++
			continue
		}
		event, ok := obj["event"].(map[string]any)
		if !ok {
			outcomes["malformed_row"]++
			continue
		}
		if !selector.allows(intersightTelemetryIdentity(event)) {
			outcomes["device_filtered"]++
			continue
		}
		rawValue, exists := event[query.fieldName]
		if !exists {
			outcomes["missing_value"]++
			continue
		}
		if rawValue == nil {
			outcomes["null_value"]++
			continue
		}
		value, ok := numberFromAny(rawValue)
		if !ok {
			outcomes["invalid_value"]++
			continue
		}
		resourceID := firstNonEmpty(stringFromAny(event["host.name"]), stringFromAny(event["name"]), stringFromAny(event["deviceId"]), query.name)
		rb := b.resource("telemetry:" + query.metricName + ":" + resourceID)
		attrs := rb.resource.Attributes()
		putStr(attrs, "host.id", resourceID)
		putStr(attrs, "host.name", resourceID)
		putStr(attrs, "os.name", "Intersight")
		putStr(attrs, "intersight.telemetry.datasource", query.dataSource)
		putStr(attrs, "intersight.telemetry.instrument", query.instrument)
		putStr(attrs, "intersight.telemetry.device_id", stringFromAny(event["deviceId"]))
		putStr(attrs, "intersight.serial", firstNonEmpty(stringFromAny(event["serial"]), stringFromAny(event["Serial"]), stringFromAny(event["serialNumber"]), stringFromAny(event["SerialNumber"])))
		pointAttrs := map[string]string{}
		if query.metricName == "system.cpu.utilization" {
			pointAttrs["cpu.mode"] = "user"
		}
		if query.metricName == "system.memory.utilization" {
			pointAttrs["system.memory.state"] = "used"
		}
		for _, dim := range query.dimensions {
			putNonEmpty(pointAttrs, "intersight."+strings.ReplaceAll(dim, ".", "_"), stringFromAny(event[dim]))
		}
		rb.recordDouble(query.metricName, query.description, query.unit, value, pointAttrs)
		outcomes["emitted"]++
	}

	rb := b.accountResource()
	for _, outcome := range []string{"emitted", "max_results", "device_filtered", "null_value", "missing_value", "invalid_value", "malformed_row"} {
		rows := outcomes[outcome]
		if rows == 0 && outcome != "emitted" {
			continue
		}
		rb.recordInt("intersight.telemetry.query.rows", "Per-query telemetry rows classified by the bounded `intersight.telemetry.outcome` attribute as emitted, capped, filtered, sparse, invalid, or malformed.", "{row}", rows, map[string]string{
			"intersight.telemetry.query":   query.name,
			"intersight.telemetry.outcome": outcome,
		})
	}
}

func appendIntersightLog(ld plog.Logs, endpoint intersightEndpoint, obj intersight.Object, now time.Time) {
	rl := ld.ResourceLogs().AppendEmpty()
	attrs := rl.Resource().Attributes()
	putStr(attrs, "os.name", "Intersight")
	putStr(attrs, "intersight.resource.type", intersight.ObjectType(obj, endpoint.objectType))
	putStr(attrs, "intersight.moid", intersight.String(obj, "Moid"))
	putStr(attrs, "host.id", firstNonEmpty(intersight.String(obj, "Serial", "SerialNumber"), firstString(intersight.StringSlice(obj, "Serial")), intersight.String(obj, "AffectedMoId", "AffectedObjectMoid"), intersight.String(obj, "Moid")))
	putStr(attrs, "host.name", firstNonEmpty(intersight.String(obj, "AffectedMoDisplayName", "Name", "HostName"), firstString(intersight.StringSlice(obj, "DeviceHostname"))))

	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName(intersightScopeName)
	record := sl.LogRecords().AppendEmpty()
	record.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	if ts, ok := logTimestamp(obj); ok {
		if timestamp, valid := pdataTimestampFromTime(ts); valid {
			record.SetTimestamp(timestamp)
		}
	}
	status := objectStatus(obj)
	severity := firstNonEmpty(intersight.String(obj, "Severity", "OrigSeverity"), status)
	record.SetSeverityText(severity)
	record.SetSeverityNumber(logSeverityNumber(severity))
	record.Body().SetEmptyMap()
	body := record.Body().Map()
	for key, value := range obj {
		setLogValue(body, key, value)
	}
	logAttrs := record.Attributes()
	putStr(logAttrs, "event.domain", "intersight")
	putStr(logAttrs, "event.name", endpoint.operation)
	putStr(logAttrs, "intersight.operation", endpoint.operation)
	putStr(logAttrs, "intersight.status", status)
	putStr(logAttrs, "intersight.severity", strings.ToLower(severity))
	putStr(logAttrs, "intersight.affected_moid", firstNonEmpty(intersight.String(obj, "AffectedMoId", "AffectedObjectMoid"), intersight.RelationshipMoid(obj, "AffectedObject")))
	putStr(logAttrs, "user.email", firstNonEmpty(intersight.String(obj, "UserIdOrEmail", "Email"), ""))
}

func intersightMetricEndpoints() []intersightEndpoint {
	return []intersightEndpoint{
		{group: "inventory", operation: "asset.device_registrations", path: "/api/v1/asset/DeviceRegistrations", objectType: "asset.DeviceRegistration", selectFields: []string{"Moid", "ObjectType", "CreateTime", "ModTime", "DeviceHostname", "DeviceIpAddress", "Serial", "PlatformType", "Vendor", "ReadOnly", "ExecutionMode", "ConnectionStatus", "Status"}},
		{group: "inventory", operation: "asset.targets", path: "/api/v1/asset/Targets", objectType: "asset.Target", selectFields: []string{"Moid", "ObjectType", "CreateTime", "ModTime", "Name", "Type", "ConnectionStatus", "Status"}},
		{group: "inventory", operation: "compute.physical_summaries", path: "/api/v1/compute/PhysicalSummaries", objectType: "compute.PhysicalSummary", selectFields: []string{"Moid", "ObjectType", "Name", "Serial", "Model", "PlatformType", "SourceObjectType", "ConnectionStatus", "OperState", "Operability", "OperPowerState", "MgmtIpAddress", "Ipv4Address", "Firmware", "AvailableMemory", "NumCpuCores", "NumCpus", "NumThreads", "FaultSummary", "ServiceProfile", "RegisteredDevice"}},
		{group: "inventory", operation: "compute.blades", path: "/api/v1/compute/Blades", objectType: "compute.Blade", selectFields: []string{"Moid", "ObjectType", "Name", "Serial", "Model", "OperState", "Operability", "OperPowerState", "FaultSummary", "RegisteredDevice"}},
		{group: "inventory", operation: "compute.rack_units", path: "/api/v1/compute/RackUnits", objectType: "compute.RackUnit", selectFields: []string{"Moid", "ObjectType", "Name", "Serial", "Model", "OperState", "Operability", "OperPowerState", "FaultSummary", "RegisteredDevice"}},
		intersightAuditEndpoint(),
		{group: "events", operation: "cond.alarms", path: "/api/v1/cond/Alarms", objectType: "cond.Alarm", selectFields: []string{"Moid", "ObjectType", "CreateTime", "ModTime", "Acknowledge", "AffectedMoDisplayName", "AffectedMoId", "AffectedMoType", "AffectedObject", "Code", "CreationTime", "Description", "LastTransitionTime", "Name", "OrigSeverity", "Severity", "RegisteredDevice"}, query: activeAlarmQuery},
		{group: "events", operation: "cond.hcl_statuses", path: "/api/v1/cond/HclStatuses", objectType: "cond.HclStatus", selectFields: []string{"Moid", "ObjectType", "CreateTime", "ModTime", "Name", "Status", "Model", "Serial", "ManagedObject", "RegisteredDevice"}},
		{group: "events", operation: "tam.advisory_instances", path: "/api/v1/tam/AdvisoryInstances", objectType: "tam.AdvisoryInstance", selectFields: []string{"Moid", "ObjectType", "CreateTime", "ModTime", "AffectedObjectMoid", "AffectedObjectType", "LastStateChangeTime", "LastVerifiedTime", "State", "AffectedObject", "DeviceRegistration"}, query: recentCreateQuery},
		{group: "events", operation: "tam.security_advisories", path: "/api/v1/tam/SecurityAdvisories", objectType: "tam.SecurityAdvisory", selectFields: []string{"Moid", "ObjectType", "CreateTime", "ModTime", "Name", "Severity", "Status", "State"}, query: recentCreateQuery},
		{group: "events", operation: "workflow.workflow_infos", path: "/api/v1/workflow/WorkflowInfos", objectType: "workflow.WorkflowInfo", selectFields: []string{"Moid", "ObjectType", "CreateTime", "ModTime", "Action", "Email", "EndTime", "Name", "Progress", "StartTime", "Status", "TraceId", "Type", "UserActionRequired", "UserId", "AssociatedObject"}, query: recentCreateQuery},
		{group: "events", operation: "workflow.task_infos", path: "/api/v1/workflow/TaskInfos", objectType: "workflow.TaskInfo", selectFields: []string{"Moid", "ObjectType", "CreateTime", "ModTime", "Description", "EndTime", "FailureReason", "Name", "RetryCount", "StartTime", "Status", "WorkflowInfo"}, query: recentCreateQuery},
		{group: "events", operation: "techsupportmanagement.techsupport_statuses", path: "/api/v1/techsupportmanagement/TechSupportStatuses", objectType: "techsupportmanagement.TechSupportStatus", selectFields: []string{"Moid", "ObjectType", "CreateTime", "ModTime", "FileName", "Reason", "RelayReason", "RelayStatus", "RequestTs", "Status", "DeviceRegistration", "OriginResource"}, query: recentCreateQuery},
		{group: "equipment", operation: "equipment.device_summaries", path: "/api/v1/equipment/DeviceSummaries", objectType: "equipment.DeviceSummary", selectFields: []string{"Moid", "ObjectType", "Dn", "Model", "Serial", "SourceObjectType", "RegisteredDevice"}},
		{group: "equipment", operation: "equipment.chasses", path: "/api/v1/equipment/Chasses", objectType: "equipment.Chassis", selectFields: []string{"Moid", "ObjectType", "Name", "Model", "Serial", "OperState", "Operability", "Thermal", "FaultSummary", "RegisteredDevice"}},
		{group: "equipment", operation: "equipment.fans", path: "/api/v1/equipment/Fans", objectType: "equipment.Fan", selectFields: []string{"Moid", "ObjectType", "Name", "Model", "Serial", "OperState", "Operability", "Presence", "RegisteredDevice"}},
		{group: "equipment", operation: "equipment.fan_modules", path: "/api/v1/equipment/FanModules", objectType: "equipment.FanModule", selectFields: []string{"Moid", "ObjectType", "Name", "Model", "Serial", "OperState", "Operability", "Presence", "RegisteredDevice"}},
		{group: "equipment", operation: "equipment.psus", path: "/api/v1/equipment/Psus", objectType: "equipment.Psu", selectFields: []string{"Moid", "ObjectType", "Name", "Model", "Serial", "OperState", "Operability", "Presence", "RegisteredDevice"}},
		{group: "equipment", operation: "equipment.io_cards", path: "/api/v1/equipment/IoCards", objectType: "equipment.IoCard", selectFields: []string{"Moid", "ObjectType", "Name", "Model", "Serial", "OperState", "Operability", "Presence", "RegisteredDevice"}},
		{group: "equipment", operation: "equipment.fexes", path: "/api/v1/equipment/Fexes", objectType: "equipment.Fex", selectFields: []string{"Moid", "ObjectType", "Name", "Model", "Serial", "OperState", "Operability", "Presence", "RegisteredDevice"}},
		{group: "equipment", operation: "equipment.transceivers", path: "/api/v1/equipment/Transceivers", objectType: "equipment.Transceiver", selectFields: []string{"Moid", "ObjectType", "Name", "Model", "Serial", "OperState", "Operability", "Presence", "RegisteredDevice"}},
		{group: "network", operation: "network.elements", path: "/api/v1/network/Elements", objectType: "network.Element", selectFields: []string{"Moid", "ObjectType", "Name", "Serial", "Model", "ManagementMode", "Operability", "Status", "Thermal", "Version", "OutOfBandIpAddress", "FaultSummary", "RegisteredDevice"}},
		{group: "firmware", operation: "firmware.firmware_summaries", path: "/api/v1/firmware/FirmwareSummaries", objectType: "firmware.FirmwareSummary", selectFields: []string{"Moid", "ObjectType", "BundleVersion", "Server", "RegisteredDevice"}},
		{group: "storage", operation: "storage.controllers", path: "/api/v1/storage/Controllers", objectType: "storage.Controller", selectFields: []string{"Moid", "ObjectType", "Name", "ControllerStatus", "OperState", "Operability", "Model", "Type", "MemoryCorrectableErrors", "RebuildRatePercent", "RegisteredDevice"}},
		{group: "storage", operation: "storage.physical_disks", path: "/api/v1/storage/PhysicalDisks", objectType: "storage.PhysicalDisk", selectFields: []string{"Moid", "ObjectType", "Name", "DiskState", "DriveState", "Operability", "OperPowerState", "MediaErrorCount", "PredictiveFailureCount", "PercentLifeLeft", "OperatingTemperature", "PowerOnHours", "Serial", "Pid", "RegisteredDevice"}},
		{group: "storage", operation: "storage.virtual_drives", path: "/api/v1/storage/VirtualDrives", objectType: "storage.VirtualDrive", selectFields: []string{"Moid", "ObjectType", "Name", "ConfigState", "DriveState", "OperState", "Operability", "Size", "VirtualDriveId", "RegisteredDevice"}},
		{group: "hyperflex", operation: "hyperflex.clusters", path: "/api/v1/hyperflex/Clusters", objectType: "hyperflex.Cluster", selectFields: []string{"Moid", "ObjectType", "Name", "ClusterUuid", "DeviceId", "EncryptionStatus", "FltAggr", "HxdpBuildVersion", "Status", "UpgradeStatus", "VmCount", "RegisteredDevice"}},
		{group: "hyperflex", operation: "hyperflex.nodes", path: "/api/v1/hyperflex/Nodes", objectType: "hyperflex.Node", selectFields: []string{"Moid", "ObjectType", "HostName", "Hypervisor", "ModelNumber", "NodeMaintenanceMode", "NodeStatus", "NodeUuid", "Role", "SerialNumber", "Status", "Version", "ClusterMember"}},
		{group: "kubernetes", operation: "kubernetes.clusters", path: "/api/v1/kubernetes/Clusters", objectType: "kubernetes.Cluster", selectFields: []string{"Moid", "ObjectType", "Name", "ConnectionStatus", "RegisteredDevices"}},
		{group: "kubernetes", operation: "kubernetes.nodes", path: "/api/v1/kubernetes/Nodes", objectType: "kubernetes.Node", selectFields: []string{"Moid", "ObjectType", "Name", "Status", "RegisteredDevice"}},
		{group: "virtualization", operation: "virtualization.virtual_machines", path: "/api/v1/virtualization/VirtualMachines", objectType: "virtualization.VirtualMachine", selectFields: []string{"Moid", "ObjectType", "Name", "Cpu", "Memory", "PowerState", "GuestOs", "HostEsxi", "ClusterEsxi", "HypervisorType", "RegisteredDevice"}},
	}
}

func intersightLogEndpoints() []intersightEndpoint {
	return []intersightEndpoint{
		intersightAuditEndpoint(),
		{group: "events", operation: "cond.alarms", path: "/api/v1/cond/Alarms", objectType: "cond.Alarm", selectFields: []string{"Moid", "ObjectType", "CreateTime", "ModTime", "Acknowledge", "AffectedMoDisplayName", "AffectedMoId", "AffectedMoType", "AffectedObject", "Code", "CreationTime", "Description", "LastTransitionTime", "Name", "OrigSeverity", "Severity", "RegisteredDevice"}, query: activeAlarmQuery},
		{group: "events", operation: "tam.advisory_instances", path: "/api/v1/tam/AdvisoryInstances", objectType: "tam.AdvisoryInstance", selectFields: []string{"Moid", "ObjectType", "CreateTime", "ModTime", "AffectedObjectMoid", "AffectedObjectType", "LastStateChangeTime", "LastVerifiedTime", "State", "AffectedObject", "DeviceRegistration"}, query: recentCreateQuery},
		{group: "events", operation: "tam.security_advisories", path: "/api/v1/tam/SecurityAdvisories", objectType: "tam.SecurityAdvisory", selectFields: []string{"Moid", "ObjectType", "CreateTime", "ModTime", "Name", "Severity", "Status", "State"}, query: recentCreateQuery},
		{group: "events", operation: "workflow.workflow_infos", path: "/api/v1/workflow/WorkflowInfos", objectType: "workflow.WorkflowInfo", selectFields: []string{"Moid", "ObjectType", "CreateTime", "ModTime", "Action", "Email", "EndTime", "Name", "Progress", "StartTime", "Status", "TraceId", "Type", "UserActionRequired", "UserId", "AssociatedObject"}, query: recentCreateQuery},
		{group: "events", operation: "workflow.task_infos", path: "/api/v1/workflow/TaskInfos", objectType: "workflow.TaskInfo", selectFields: []string{"Moid", "ObjectType", "CreateTime", "ModTime", "Description", "EndTime", "FailureReason", "Name", "RetryCount", "StartTime", "Status", "WorkflowInfo"}, query: recentCreateQuery},
		{group: "events", operation: "techsupportmanagement.techsupport_statuses", path: "/api/v1/techsupportmanagement/TechSupportStatuses", objectType: "techsupportmanagement.TechSupportStatus", selectFields: []string{"Moid", "ObjectType", "CreateTime", "ModTime", "FileName", "Reason", "RelayReason", "RelayStatus", "RequestTs", "Status", "DeviceRegistration", "OriginResource"}, query: recentCreateQuery},
	}
}

func intersightAuditEndpoint() intersightEndpoint {
	return intersightEndpoint{group: "audit", operation: "aaa.audit_records", path: "/api/v1/aaa/AuditRecords", objectType: "aaa.AuditRecord", selectFields: []string{"Moid", "ObjectType", "CreateTime", "ModTime", "Email", "InstId", "SessionId", "SourceIp", "Timestamp", "UserIdOrEmail"}, query: recentCreateQuery}
}

func intersightTelemetryQueries() []intersightTelemetryQuery {
	return []intersightTelemetryQuery{
		{name: "fan_speed", dataSource: "PhysicalEntities", instrument: "hw.fan", dimensions: []string{"host.name"}, field: "hw.fan.speed", fieldName: "hw.fan.speed-Mean", aggregation: "doubleMean", metricName: "intersight.ucs.fan.speed", description: "Mean fan speed from Intersight telemetry GroupBy.", unit: "1/min"},
		{name: "fan_speed_ratio", dataSource: "PhysicalEntities", instrument: "hw.fan", dimensions: []string{"host.name"}, field: "hw.fan.speed_ratio", fieldName: "hw.fan.speed_ratio-Mean", aggregation: "doubleMean", metricName: "intersight.ucs.fan.speed_ratio", description: "Mean fan speed as a percentage of maximum.", unit: "%"},
		{name: "host_power", dataSource: "PhysicalEntities", instrument: "hw.host", dimensions: []string{"name"}, field: "hw.host.power", fieldName: "hw.host.power-Mean", aggregation: "doubleMean", metricName: "intersight.ucs.host.power", description: "Mean host power from Intersight telemetry GroupBy.", unit: "W"},
		{name: "host_energy", dataSource: "PhysicalEntities", instrument: "hw.host", dimensions: []string{"name"}, field: "hw.host.energy", fieldName: "hw.host.energy-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.host.energy", description: "Host energy consumption from Intersight telemetry.", unit: "J"},
		{name: "host_power_state", dataSource: "PhysicalEntities", instrument: "hw.host", dimensions: []string{"name"}, field: "hw.host.power_state", fieldName: "hw.host.power_state-Max", aggregation: "longMax", metricName: "intersight.ucs.host.power_state", description: "Encoded host power state from telemetry.", unit: "1"},
		{name: "temperature", dataSource: "PhysicalEntities", instrument: "hw.temperature", dimensions: []string{"host.name"}, field: "hw.temperature", fieldName: "hw.temperature-Mean", aggregation: "doubleMean", metricName: "intersight.ucs.temperature", description: "Mean temperature from Intersight telemetry GroupBy.", unit: "Cel"},
		{name: "temperature_high_critical", dataSource: "PhysicalEntities", instrument: "hw.temperature", dimensions: []string{"host.name"}, field: "hw.temperature.limit_high_critical", fieldName: "hw.temperature.limit_high_critical-Max", aggregation: "doubleMax", metricName: "intersight.ucs.temperature.limit_high_critical", description: "High critical temperature threshold.", unit: "Cel"},
		{name: "temperature_low_critical", dataSource: "PhysicalEntities", instrument: "hw.temperature", dimensions: []string{"host.name"}, field: "hw.temperature.limit_low_critical", fieldName: "hw.temperature.limit_low_critical-Min", aggregation: "doubleMin", metricName: "intersight.ucs.temperature.limit_low_critical", description: "Low critical temperature threshold.", unit: "Cel"},
		{name: "voltage", dataSource: "PhysicalEntities", instrument: "hw.voltage", dimensions: []string{"host.name"}, field: "hw.voltage", fieldName: "hw.voltage-Mean", aggregation: "doubleMean", metricName: "intersight.ucs.voltage", description: "Mean voltage from Intersight telemetry GroupBy.", unit: "V"},
		{name: "current", dataSource: "PhysicalEntities", instrument: "hw.current", dimensions: []string{"host.name"}, field: "hw.current", fieldName: "hw.current-Mean", aggregation: "doubleMean", metricName: "intersight.ucs.current", description: "Mean current from Intersight telemetry GroupBy.", unit: "A"},
		{name: "cpu_user", dataSource: "HostResources", instrument: "system.cpu", dimensions: []string{"host.name"}, field: "system.cpu.utilization_user", fieldName: "system.cpu.utilization_user-Max", aggregation: "doubleMax", metricName: "system.cpu.utilization", description: "Ratio of CPU time in use, from 0 to 1.", unit: "1"},
		{name: "cpu_system", dataSource: "HostResources", instrument: "system.cpu", dimensions: []string{"host.name"}, field: "system.cpu.utilization_system", fieldName: "system.cpu.utilization_system-Max", aggregation: "doubleMax", metricName: "intersight.ucs.cpu.system.utilization", description: "System CPU utilization from Intersight telemetry.", unit: "1"},
		{name: "cpu_idle", dataSource: "HostResources", instrument: "system.cpu", dimensions: []string{"host.name"}, field: "system.cpu.utilization_idle", fieldName: "system.cpu.utilization_idle-Max", aggregation: "doubleMax", metricName: "intersight.ucs.cpu.idle.utilization", description: "Idle CPU utilization from Intersight telemetry.", unit: "1"},
		{name: "memory_utilization", dataSource: "HostResources", instrument: "system.memory", dimensions: []string{"host.name"}, field: "system.memory.utilization", fieldName: "system.memory.utilization-Max", aggregation: "doubleMax", metricName: "system.memory.utilization", description: "Ratio of memory bytes in use, from 0 to 1.", unit: "1"},
		{name: "memory_used", dataSource: "PhysicalEntities", instrument: "system.memory", dimensions: []string{"host.name"}, field: "system.memory.usage_used", fieldName: "system.memory.usage_used-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.memory.used", description: "Used system memory from Intersight telemetry.", unit: "By"},
		{name: "memory_free", dataSource: "PhysicalEntities", instrument: "system.memory", dimensions: []string{"host.name"}, field: "system.memory.usage_free", fieldName: "system.memory.usage_free-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.memory.free", description: "Free system memory from Intersight telemetry.", unit: "By"},
		{name: "memory_cached", dataSource: "PhysicalEntities", instrument: "system.memory", dimensions: []string{"host.name"}, field: "system.memory.usage_cached", fieldName: "system.memory.usage_cached-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.memory.cached", description: "Cached system memory from Intersight telemetry.", unit: "By"},
		{name: "memory_module_size", dataSource: "PhysicalEntities", instrument: "hw.memory", dimensions: []string{"host.name"}, field: "hw.memory.size", fieldName: "hw.memory.size-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.memory.module.size", description: "Memory module size from Intersight telemetry.", unit: "By"},
		{name: "memory_correctable_ecc", dataSource: "PhysicalEntities", instrument: "hw.memory", dimensions: []string{"host.name"}, field: "hw.errors_correctable_ecc_errors", fieldName: "hw.errors_correctable_ecc_errors-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.memory.ecc.correctable", description: "Correctable memory ECC errors.", unit: "{error}"},
		{name: "memory_uncorrectable_ecc", dataSource: "PhysicalEntities", instrument: "hw.memory", dimensions: []string{"host.name"}, field: "hw.errors_uncorrectable_ecc_errors", fieldName: "hw.errors_uncorrectable_ecc_errors-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.memory.ecc.uncorrectable", description: "Uncorrectable memory ECC errors.", unit: "{error}"},
		{name: "network_rx", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.network.io_receive", fieldName: "hw.network.io_receive-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.network.receive", description: "Network receive volume from Intersight telemetry.", unit: "By"},
		{name: "network_tx", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.network.io_transmit", fieldName: "hw.network.io_transmit-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.network.transmit", description: "Network transmit volume from Intersight telemetry.", unit: "By"},
		{name: "network_errors", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.errors_network_receive_all", fieldName: "hw.errors_network_receive_all-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.network.receive.errors", description: "Receive errors from Intersight telemetry.", unit: "{error}"},
		{name: "network_tx_errors", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.errors_network_transmit_all", fieldName: "hw.errors_network_transmit_all-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.network.transmit.errors", description: "Transmit errors from Intersight telemetry.", unit: "{error}"},
		{name: "network_rx_crc_errors", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.errors_network_receive_crc", fieldName: "hw.errors_network_receive_crc-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.network.receive.crc_errors", description: "Receive CRC errors from Intersight telemetry.", unit: "{error}"},
		{name: "network_rx_discards", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.errors_network_receive_discard", fieldName: "hw.errors_network_receive_discard-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.network.receive.discards", description: "Receive discards from Intersight telemetry.", unit: "{discard}"},
		{name: "network_rx_no_buffer", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.errors_network_receive_no_buffer", fieldName: "hw.errors_network_receive_no_buffer-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.network.receive.no_buffer", description: "Receive no-buffer errors from Intersight telemetry.", unit: "{error}"},
		{name: "network_rx_drops", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.errors_receive_drops", fieldName: "hw.errors_receive_drops-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.network.receive.drops", description: "Receive drops from Intersight telemetry.", unit: "{drop}"},
		{name: "network_tx_discards", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.errors_network_transmit_discard", fieldName: "hw.errors_network_transmit_discard-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.network.transmit.discards", description: "Transmit discards from Intersight telemetry.", unit: "{discard}"},
		{name: "network_rx_packets", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.network.packets_receive_unicast", fieldName: "hw.network.packets_receive_unicast-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.network.receive.packets", description: "Receive packet volume from Intersight telemetry.", unit: "{packet}"},
		{name: "network_tx_packets", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.network.packets_transmit_unicast", fieldName: "hw.network.packets_transmit_unicast-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.network.transmit.packets", description: "Transmit packet volume from Intersight telemetry.", unit: "{packet}"},
		{name: "network_rx_pause_frames", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.errors_network_receive_pause", fieldName: "hw.errors_network_receive_pause-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.network.receive.pause_frames", description: "Receive pause frames from Intersight telemetry.", unit: "{frame}"},
		{name: "network_tx_pause_frames", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.errors_network_transmit_pause", fieldName: "hw.errors_network_transmit_pause-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.network.transmit.pause_frames", description: "Transmit pause frames from Intersight telemetry.", unit: "{frame}"},
		{name: "network_tx_drops", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.errors_transmit_drops", fieldName: "hw.errors_transmit_drops-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.network.transmit.drops", description: "Transmit drops from Intersight telemetry.", unit: "{drop}"},
		{name: "network_utilization", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.network.bandwidth.utilization_all", fieldName: "hw.network.bandwidth.utilization_all-Max", aggregation: "doubleMax", metricName: "intersight.ucs.network.utilization", description: "Network bandwidth utilization.", unit: "%"},
		{name: "network_link_speed", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.network.bandwidth.limit", fieldName: "hw.network.bandwidth.limit-Max", aggregation: "doubleMax", metricName: "intersight.ucs.network.speed", description: "Operational link speed.", unit: "By/s"},
		{name: "network_link_status", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.network.up", fieldName: "hw.network.up-Max", aggregation: "longMax", metricName: "intersight.ucs.network.link.status", description: "Network link status from Intersight telemetry.", unit: "1"},
		{name: "network_link_failures", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.errors_network_link_failures", fieldName: "hw.errors_network_link_failures-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.network.link_failures", description: "Link failure counters from Intersight telemetry.", unit: "{failure}"},
		{name: "network_signal_losses", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.errors_network_signal_losses", fieldName: "hw.errors_network_signal_losses-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.network.signal_losses", description: "Signal-loss counters from Intersight telemetry.", unit: "{error}"},
		{name: "network_interface_resets", dataSource: "NetworkInterfaces", instrument: "hw.network", dimensions: []string{"host.name"}, field: "hw.network.interface_resets", fieldName: "hw.network.interface_resets-Sum", aggregation: "doubleSum", metricName: "intersight.ucs.network.interface_resets", description: "Interface reset counters from Intersight telemetry.", unit: "{reset}"},
		{name: "psu_output_power", dataSource: "PhysicalEntities", instrument: "hw.power_supply", dimensions: []string{"host.name"}, field: "hw.power_out", fieldName: "hw.power_out-Mean", aggregation: "doubleMean", metricName: "intersight.ucs.power_supply.output_power", description: "PSU output power.", unit: "W"},
		{name: "psu_utilization", dataSource: "PhysicalEntities", instrument: "hw.power_supply", dimensions: []string{"host.name"}, field: "hw.power_supply.utilization", fieldName: "hw.power_supply.utilization-Max", aggregation: "doubleMax", metricName: "intersight.ucs.power_supply.utilization", description: "PSU utilization.", unit: "%"},
		{name: "psu_status", dataSource: "PhysicalEntities", instrument: "hw.power_supply", dimensions: []string{"host.name"}, field: "hw.status", fieldName: "hw.status-Min", aggregation: "longMin", metricName: "intersight.ucs.power_supply.status", description: "PSU operational status from Intersight telemetry.", unit: "1"},
		{name: "fan_status", dataSource: "PhysicalEntities", instrument: "hw.fan", dimensions: []string{"host.name"}, field: "hw.status", fieldName: "hw.status-Min", aggregation: "longMin", metricName: "intersight.ucs.fan.status", description: "Fan operational status from Intersight telemetry.", unit: "1"},
		{name: "memory_status", dataSource: "PhysicalEntities", instrument: "hw.memory", dimensions: []string{"host.name"}, field: "hw.status", fieldName: "hw.status-Min", aggregation: "longMin", metricName: "intersight.ucs.memory.status", description: "Memory module operational status from Intersight telemetry.", unit: "1"},
		{name: "temperature_status", dataSource: "PhysicalEntities", instrument: "hw.temperature", dimensions: []string{"host.name"}, field: "hw.status", fieldName: "hw.status-Min", aggregation: "longMin", metricName: "intersight.ucs.temperature.status", description: "Temperature sensor operational status from Intersight telemetry.", unit: "1"},
		{name: "signal_power_rx", dataSource: "PhysicalEntities", instrument: "hw.signal_power", dimensions: []string{"host.name"}, field: "hw.signal_power_receive", fieldName: "hw.signal_power_receive-Mean", aggregation: "doubleMean", metricName: "intersight.ucs.signal_power.receive", description: "Transceiver receive optical power.", unit: "dB{mW}"},
		{name: "signal_power_tx", dataSource: "PhysicalEntities", instrument: "hw.signal_power", dimensions: []string{"host.name"}, field: "hw.signal_power_transmit", fieldName: "hw.signal_power_transmit-Mean", aggregation: "doubleMean", metricName: "intersight.ucs.signal_power.transmit", description: "Transceiver transmit optical power.", unit: "dB{mW}"},
		{name: "hyperflex_read_iops", dataSource: "HyperFlexClusters", instrument: "hyperflex.cluster", dimensions: []string{"deviceId"}, field: "hyperflex.read.iops", fieldName: "hyperflex.read.iops-Sum", aggregation: "doubleSum", metricName: "intersight.hyperflex.read.iops", description: "HyperFlex read IOPS.", unit: "{operation}/s"},
		{name: "hyperflex_write_iops", dataSource: "HyperFlexClusters", instrument: "hyperflex.cluster", dimensions: []string{"deviceId"}, field: "hyperflex.write.iops", fieldName: "hyperflex.write.iops-Sum", aggregation: "doubleSum", metricName: "intersight.hyperflex.write.iops", description: "HyperFlex write IOPS.", unit: "{operation}/s"},
		{name: "hyperflex_read_latency", dataSource: "HyperFlexClusters", instrument: "hyperflex.cluster", dimensions: []string{"deviceId"}, field: "hyperflex.read.latency", fieldName: "hyperflex.read.latency-Max", aggregation: "doubleMax", metricName: "intersight.hyperflex.read.latency", description: "HyperFlex read latency.", unit: "ms"},
		{name: "hyperflex_write_latency", dataSource: "HyperFlexClusters", instrument: "hyperflex.cluster", dimensions: []string{"deviceId"}, field: "hyperflex.write.latency", fieldName: "hyperflex.write.latency-Max", aggregation: "doubleMax", metricName: "intersight.hyperflex.write.latency", description: "HyperFlex write latency.", unit: "ms"},
	}
}

func endpointQuery(endpoint intersightEndpoint, cfg *Config, now time.Time) url.Values {
	var query url.Values
	if endpoint.query != nil {
		query = endpoint.query(cfg, now)
	} else {
		query = intersight.Query(nil, "")
	}
	if len(endpoint.selectFields) > 0 && query.Get("$select") == "" {
		query.Set("$select", strings.Join(endpoint.selectFields, ","))
	}
	return query
}

func activeAlarmQuery(_ *Config, _ time.Time) url.Values {
	return intersight.Query(nil, "Acknowledge eq 'None'")
}

func recentCreateQuery(cfg *Config, now time.Time) url.Values {
	lookback := cfg.Intersight.EventLookback
	if lookback <= 0 {
		lookback = defaultIntersightConfig().EventLookback
	}
	ts := now.Add(-lookback).UTC().Format(time.RFC3339Nano)
	return intersight.Query(nil, "CreateTime gt "+ts)
}

func intersightGroupEnabled(cfg IntersightConfig, group string) bool {
	switch group {
	case "inventory":
		return cfg.Inventory.Enabled
	case "events":
		return cfg.Events.Enabled
	case "audit":
		return cfg.Audit.Enabled
	case "telemetry":
		return cfg.Telemetry.Enabled
	case "equipment":
		return cfg.Equipment.Enabled
	case "network":
		return cfg.Network.Enabled
	case "firmware":
		return cfg.Firmware.Enabled
	case "storage":
		return cfg.Storage.Enabled
	case "hyperflex":
		return cfg.HyperFlex.Enabled
	case "kubernetes":
		return cfg.Kubernetes.Enabled
	case "virtualization":
		return cfg.Virtualization.Enabled
	default:
		return false
	}
}

func intersightGroupMaxResults(cfg IntersightConfig, group string) int {
	switch group {
	case "inventory":
		return cfg.Inventory.MaxResults
	case "events":
		return cfg.Events.MaxResults
	case "audit":
		return cfg.Audit.MaxResults
	case "telemetry":
		return cfg.Telemetry.MaxResults
	case "equipment":
		return cfg.Equipment.MaxResults
	case "network":
		return cfg.Network.MaxResults
	case "firmware":
		return cfg.Firmware.MaxResults
	case "storage":
		return cfg.Storage.MaxResults
	case "hyperflex":
		return cfg.HyperFlex.MaxResults
	case "kubernetes":
		return cfg.Kubernetes.MaxResults
	case "virtualization":
		return cfg.Virtualization.MaxResults
	default:
		return 0
	}
}

func filterIntersightObjects(objects []intersight.Object, filters IntersightTargetFilters) []intersight.Object {
	if len(filters.Serials) == 0 && len(filters.MoIDs) == 0 {
		return objects
	}
	needles := map[string]struct{}{}
	for _, value := range append(append([]string{}, filters.Serials...), filters.MoIDs...) {
		if value != "" {
			needles[strings.ToLower(value)] = struct{}{}
		}
	}
	filtered := make([]intersight.Object, 0, len(objects))
	for _, obj := range objects {
		text := intersight.SearchText(obj)
		for needle := range needles {
			if strings.Contains(text, needle) {
				filtered = append(filtered, obj)
				break
			}
		}
	}
	return filtered
}

func objectStatus(obj intersight.Object) string {
	return firstNonEmpty(
		intersight.String(obj, "Severity"),
		intersight.String(obj, "Status"),
		intersight.String(obj, "ConnectionStatus"),
		intersight.String(obj, "ControllerStatus"),
		intersight.String(obj, "OperState"),
		intersight.String(obj, "Operability"),
		intersight.String(obj, "OperPowerState"),
		intersight.String(obj, "PowerState"),
		intersight.String(obj, "State"),
		intersight.String(obj, "DriveState"),
		intersight.String(obj, "DiskState"),
		intersight.String(obj, "NodeStatus"),
		intersight.String(obj, "RelayStatus"),
		intersight.String(obj, "UpgradeStatus"),
		intersight.String(obj, "Thermal"),
	)
}

func statusCode(status string) (int64, bool) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "ok", "online", "connected", "operable", "up", "healthy", "normal", "completed", "complete", "collectioncomplete", "uploadpartscomplete", "on", "powered-on", "poweredon", "ready", "running", "success", "successful", "reachable", "managed", "active", "enabled", "valid", "available", "synchronized", "in-service", "inservice", "passed", "pass", "true", "present", "learned", "established":
		return 1, true
	case "info", "informational", "pending", "collectioninprogress", "uploadpending", "uploadinprogress", "inprogress", "in-progress", "not-started", "degraded", "created", "modified", "raised", "powering", "dormant":
		return 2, true
	case "warning", "warn", "minor", "medium", "major", "alerting":
		return 3, true
	case "critical", "error", "failed", "failure", "collectionfailed", "uploadfailed", "fatal", "offline", "disconnected", "inoperable", "down", "unhealthy", "unreachable", "disabled", "invalid", "inactive", "not-reachable", "false", "unsupported":
		return 4, true
	default:
		return 0, false
	}
}

func upStatus(status string) (int64, bool) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "ok", "online", "connected", "operable", "up", "healthy", "normal", "on", "powered-on", "poweredon", "ready", "running", "reachable", "managed", "active", "enabled", "available", "synchronized", "in-service", "inservice", "established":
		return 1, true
	case "critical", "error", "failed", "failure", "fatal", "offline", "disconnected", "inoperable", "down", "unhealthy", "unreachable", "disabled", "inactive", "not-reachable", "false":
		return 0, true
	default:
		return 0, false
	}
}

func recordStringState(rb *resourceMetricsBuilder, name, description, status string) {
	if status == "" {
		return
	}
	code, ok := statusCode(status)
	if !ok {
		return
	}
	attrs := withAttr(nil, "intersight.status", status)
	rb.recordInt(name, description, "1", code, attrs)
}

func recordIfInt(rb *resourceMetricsBuilder, obj intersight.Object, key, name, description, unit string, attrs map[string]string) {
	value, ok := intersight.Int64(obj, key)
	if !ok {
		return
	}
	rb.recordInt(name, description, unit, value, attrs)
}

func intersightCountDescription(name string) string {
	switch name {
	case "intersight.alarm.count":
		return "Active Intersight alarms."
	case "intersight.advisory.count":
		return "Active Intersight advisory exposures."
	case "intersight.audit.record.count":
		return "Intersight audit records."
	case "intersight.workflow.count":
		return "Intersight workflows."
	case "intersight.task.count":
		return "Intersight workflow tasks."
	case "intersight.techsupport.count":
		return "Intersight tech-support status records."
	case "intersight.hcl.status.count":
		return "Intersight HCL status records."
	default:
		return "Intersight resources."
	}
}

func logTimestamp(obj intersight.Object) (time.Time, bool) {
	for _, key := range []string{"Timestamp", "CreationTime", "CreateTime", "LastTransitionTime", "LastStateChangeTime", "StartTime", "RequestTs", "ModTime"} {
		if ts, ok := intersight.Time(obj, key); ok {
			return ts, true
		}
	}
	return time.Time{}, false
}

func logSeverityNumber(severity string) plog.SeverityNumber {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "0", "emergency", "emerg":
		return plog.SeverityNumberFatal4
	case "1", "alert":
		return plog.SeverityNumberFatal3
	case "2", "critical", "fatal":
		return plog.SeverityNumberFatal
	case "3", "error", "failed", "failure", "major":
		return plog.SeverityNumberError
	case "4", "warning", "warn", "minor":
		return plog.SeverityNumberWarn
	case "5", "notice":
		return plog.SeverityNumberInfo2
	case "6", "info", "informational", "ok", "completed", "complete", "cleared", "clear", "resolved":
		return plog.SeverityNumberInfo
	case "7", "debug":
		return plog.SeverityNumberDebug
	default:
		return plog.SeverityNumberUnspecified
	}
}

func setLogValue(target pcommon.Map, key string, value any) {
	if value == nil {
		return
	}
	if isSensitiveLogKey(key) {
		target.PutStr(key, redactedLogValue)
		return
	}
	switch typed := value.(type) {
	case string:
		target.PutStr(key, typed)
	case bool:
		target.PutBool(key, typed)
	case float64:
		target.PutDouble(key, typed)
	case int64:
		target.PutInt(key, typed)
	case []any, map[string]any:
		bytes, err := typedJSON(redactLogValue(typed))
		if err == nil {
			target.PutStr(key, bytes)
		}
	default:
		redacted := redactLogValue(typed)
		kind := reflect.ValueOf(redacted)
		if kind.IsValid() && (kind.Kind() == reflect.Map || kind.Kind() == reflect.Slice || kind.Kind() == reflect.Array) {
			if bytes, err := typedJSON(redacted); err == nil {
				target.PutStr(key, bytes)
				return
			}
		}
		target.PutStr(key, fmt.Sprint(typed))
	}
}

func typedJSON(value any) (string, error) {
	bytes, err := jsonMarshal(value)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func jsonMarshal(value any) ([]byte, error) {
	return json.Marshal(value)
}

func compactAttrs(attrs map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range attrs {
		if value != "" {
			out[key] = value
		}
	}
	return out
}

func putNonEmpty(attrs map[string]string, key, value string) {
	if value != "" {
		attrs[key] = value
	}
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

func numberFromAny(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, !math.IsNaN(typed) && !math.IsInf(typed, 0)
	case int64:
		return float64(typed), true
	case int:
		return float64(typed), true
	case json.Number:
		f, err := typed.Float64()
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	case string:
		f, err := strconv.ParseFloat(typed, 64)
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	default:
		return 0, false
	}
}
