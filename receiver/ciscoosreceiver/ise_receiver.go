// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"crypto/sha256"
	"encoding/json"
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

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/ise"
)

const iseScopeName = "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/ise"

type iseDataConnectClient interface {
	Close() error
	Ping(context.Context) error
	QueryView(context.Context, ise.DataConnectView) ([]ise.Object, error)
}

// classifyISEError buckets a client error returned by ISE into a small enum
// suitable for use as a metric attribute. Free-form err.Error() text would blow
// up Splunk O11y MTS cardinality with endpoint paths and request bodies.
func classifyISEError(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	var apiErr *ise.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return "auth"
		case http.StatusTooManyRequests:
			return "rate_limited"
		case http.StatusRequestTimeout, http.StatusGatewayTimeout:
			return "timeout"
		default:
			if apiErr.StatusCode >= 300 && apiErr.StatusCode < 400 {
				return "redirect"
			}
			if apiErr.StatusCode >= 500 {
				return "transport"
			}
			return "other"
		}
	}
	var contentErr *ise.ResponseContentError
	if errors.As(err, &contentErr) {
		return "protocol"
	}
	var paginationErr *httpclient.PaginationLimitError
	if errors.As(err, &paginationErr) {
		return "pagination_limit"
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

type iseMetricsReceiver struct {
	settings    receiver.Settings
	config      *Config
	iseConfig   ISEConfig
	consumer    consumer.Metrics
	client      *ise.Client
	pxGrid      *ise.PxGridClient
	dataConnect iseDataConnectClient
	counters    *counterStore
	obs         *receiverhelper.ObsReport
	success     scrapeSuccessState

	startMu   sync.Mutex
	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
	closeDone chan struct{}

	statsMu sync.Mutex
	stats   []ise.RequestStat

	queryMu sync.Mutex
	queries []ise.DataConnectStat

	referenceMu          sync.Mutex
	failureReasons       []ise.Object
	failureReasonsLoaded bool
}

type iseLogsReceiver struct {
	settings    receiver.Settings
	config      *Config
	iseConfig   ISEConfig
	consumer    consumer.Logs
	client      *ise.Client
	pxGrid      *ise.PxGridClient
	dataConnect iseDataConnectClient
	obs         *receiverhelper.ObsReport

	startMu   sync.Mutex
	cancel    context.CancelFunc
	done      chan struct{}
	workers   sync.WaitGroup
	closeOnce sync.Once
	closeDone chan struct{}

	seen *logDeduplicator
}

type iseEndpointMode string

const (
	iseEndpointGet     iseEndpointMode = "get"
	iseEndpointList    iseEndpointMode = "list"
	iseEndpointERSList iseEndpointMode = "ers_list"
)

type iseEndpointSpec struct {
	group      string
	operation  string
	path       string
	objectType string
	mode       iseEndpointMode
	query      func(*Config, time.Time) url.Values
	pathFunc   func(*Config, time.Time) string
}

type iseCount struct {
	name  string
	value int64
	attrs map[string]string
}

func newISEMetricsReceiver(set receiver.Settings, conf *Config, consumer consumer.Metrics) (*iseMetricsReceiver, error) {
	iseCfg := conf.ISE.withDefaults()
	client, err := newISERestClient(conf, iseCfg)
	if err != nil {
		return nil, err
	}
	r := &iseMetricsReceiver{
		settings:  set,
		config:    conf,
		iseConfig: iseCfg,
		consumer:  consumer,
		client:    client,
		counters:  newCounterStore(),
		obs:       newPlatformObsReport(set, "http"),
		done:      make(chan struct{}),
		closeDone: make(chan struct{}),
	}
	client.OnRequest = r.recordRequest
	if iseCfg.PxGrid.Enabled {
		pxGrid, err := newISEPxGridClient(conf, iseCfg)
		if err != nil {
			return nil, err
		}
		pxGrid.SetOnRequest(r.recordRequest)
		r.pxGrid = pxGrid
	}
	if iseCfg.DataConnect.Enabled {
		dataConnect, err := newISEDataConnectClient(iseCfg)
		if err != nil {
			return nil, err
		}
		dataConnect.OnQuery = r.recordDataConnectQuery
		r.dataConnect = dataConnect
	}
	return r, nil
}

func newISELogsReceiver(set receiver.Settings, conf *Config, consumer consumer.Logs) (*iseLogsReceiver, error) {
	iseCfg := conf.ISE.withDefaults()
	client, err := newISERestClient(conf, iseCfg)
	if err != nil {
		return nil, err
	}
	r := &iseLogsReceiver{
		settings:  set,
		config:    conf,
		iseConfig: iseCfg,
		consumer:  consumer,
		client:    client,
		obs:       newPlatformObsReport(set, "http"),
		done:      make(chan struct{}),
		closeDone: make(chan struct{}),
		seen:      newLogDeduplicator(),
	}
	if iseCfg.PxGrid.Enabled {
		pxGrid, err := newISEPxGridClient(conf, iseCfg)
		if err != nil {
			return nil, err
		}
		r.pxGrid = pxGrid
	}
	if iseCfg.DataConnect.Enabled {
		dataConnect, err := newISEDataConnectClient(iseCfg)
		if err != nil {
			return nil, err
		}
		r.dataConnect = dataConnect
	}
	return r, nil
}

func newISERestClient(conf *Config, iseCfg ISEConfig) (*ise.Client, error) {
	return ise.NewClient(ise.Config{
		Endpoint:           iseCfg.Endpoint,
		Username:           iseCfg.Auth.Username,
		Password:           string(iseCfg.Auth.Password),
		UserAgent:          iseCfg.UserAgent,
		Timeout:            conf.ControllerConfig.Timeout,
		MaxRetries:         iseCfg.MaxRetries,
		PageSize:           iseCfg.PageSize,
		CAFile:             iseCfg.CAFile,
		ServerName:         iseCfg.ServerName,
		InsecureSkipVerify: iseCfg.InsecureSkipVerify,
	})
}

func newISEPxGridClient(conf *Config, iseCfg ISEConfig) (*ise.PxGridClient, error) {
	endpoint := iseCfg.PxGrid.Endpoint
	if endpoint == "" {
		endpoint = defaultISEPxGridEndpoint(iseCfg.Endpoint)
	}
	return ise.NewPxGridClient(ise.PxGridConfig{
		Endpoint:              endpoint,
		NodeName:              iseCfg.PxGrid.NodeName,
		Password:              string(iseCfg.PxGrid.Password),
		CertFile:              iseCfg.PxGrid.CertFile,
		KeyFile:               iseCfg.PxGrid.KeyFile,
		KeyPassword:           string(iseCfg.PxGrid.KeyPassword),
		CAFile:                iseCfg.PxGrid.CAFile,
		ServerName:            iseCfg.PxGrid.ServerName,
		InsecureSkipVerify:    iseCfg.PxGrid.InsecureSkipVerify,
		AllowedServiceHosts:   iseCfg.PxGrid.AllowedServiceHosts,
		AllowedServiceOrigins: iseCfg.PxGrid.AllowedServiceOrigins,
		Timeout:               conf.ControllerConfig.Timeout,
		UserAgent:             iseCfg.UserAgent,
		MaxRetries:            iseCfg.MaxRetries,
	})
}

func newISEDataConnectClient(iseCfg ISEConfig) (*ise.DataConnectClient, error) {
	dc := iseCfg.DataConnect
	return ise.NewDataConnectClient(ise.DataConnectConfig{
		Host:               dc.Host,
		Port:               dc.Port,
		ServiceName:        dc.ServiceName,
		Username:           dc.Username,
		Password:           string(dc.Password),
		WalletDir:          dc.WalletDir,
		CAFile:             dc.CAFile,
		ServerName:         dc.ServerName,
		SSL:                dc.SSL,
		SSLVerify:          dc.SSLVerify,
		Lookback:           dc.Lookback,
		RowLimit:           dc.RowLimit,
		FullViews:          dc.FullViews,
		AdditionalReadOnly: dc.AdditionalReadOnly,
	})
}

func defaultISEPxGridEndpoint(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		return endpoint
	}
	host := parsed.Hostname()
	if host == "" {
		return endpoint
	}
	parsed.Host = net.JoinHostPort(host, "8910")
	parsed.Path = "/pxgrid"
	return parsed.String()
}

func (r *iseMetricsReceiver) Start(_ context.Context, _ component.Host) error {
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

func (r *iseMetricsReceiver) Shutdown(ctx context.Context) error {
	r.startMu.Lock()
	cancel := r.cancel
	r.startMu.Unlock()
	var workerDone <-chan struct{}
	if cancel != nil {
		cancel()
		workerDone = r.done
	}
	return waitForISEShutdown(ctx, workerDone, r.beginClose())
}

func (r *iseMetricsReceiver) beginClose() <-chan struct{} {
	r.closeOnce.Do(func() {
		if r.closeDone == nil {
			r.closeDone = make(chan struct{})
		}
		go func() {
			defer close(r.closeDone)
			r.close()
		}()
	})
	return r.closeDone
}

func (r *iseMetricsReceiver) close() {
	if r.client != nil {
		r.client.CloseIdleConnections()
	}
	if r.pxGrid != nil {
		r.pxGrid.CloseIdleConnections()
	}
	if r.dataConnect != nil {
		if err := r.dataConnect.Close(); err != nil {
			r.settings.Logger.Warn("ISE Data Connect close failed", zap.Error(err))
		}
	}
}

func (r *iseMetricsReceiver) run(ctx context.Context) {
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

func (r *iseMetricsReceiver) collect(ctx context.Context) {
	scrapeCtx, cancel := context.WithTimeout(ctx, r.config.ControllerConfig.Timeout)
	defer cancel()

	obsCtx := startMetricsOp(ctx, r.obs)
	md, scrapeErr := r.scrape(scrapeCtx)
	if scrapeErr != nil {
		r.settings.Logger.Error("ISE scrape failed", zap.Error(scrapeErr))
	}
	metricCount, consumeErr := consumeMetricsIfPresent(ctx, r.consumer, md)
	if consumeErr != nil {
		r.settings.Logger.Error("ISE metrics consumer failed", zap.Error(consumeErr))
	}
	endMetricsOp(obsCtx, r.obs, metricCount, combineSignalErrors(scrapeErr, consumeErr))
}

func (r *iseMetricsReceiver) scrape(ctx context.Context) (pmetric.Metrics, error) {
	r.resetRequestStats()
	r.resetDataConnectQueries()
	now := time.Now()
	builder := newISEMetricsBuilder(now, r.iseConfig.Endpoint, r.counters)
	selector := newISEDeviceSelectionMatcher(r.config)
	targets := newISETargetMatcher(r.iseConfig.Targets)
	partial := false

	for _, spec := range iseMetricEndpoints() {
		if !iseGroupEnabled(r.iseConfig, spec.group) {
			continue
		}
		objects, err := r.fetchEndpoint(ctx, spec, now)
		if err != nil {
			if ctx.Err() != nil {
				partial = true
				return r.finishScrape(builder, now, partial, apiOutcomeSummary{}), ctx.Err()
			}
			partial = true
			builder.recordEndpointError(iseEndpointSpecWithPath(r.config, spec, now), err)
			r.settings.Logger.Warn("ISE endpoint failed", zap.String("operation", spec.operation), zap.Error(err))
		}
		for _, obj := range objects {
			if spec.operation == "openapi.webhooks" {
				if r.scrapeWebhookDeliveries(ctx, builder, obj, targets, selector, now) {
					partial = true
					if ctx.Err() != nil {
						return r.finishScrape(builder, now, partial, apiOutcomeSummary{}), ctx.Err()
					}
				}
			}
			if !iseObjectSelected(obj, targets, selector) {
				continue
			}
			builder.recordObject(spec, obj)
		}
	}
	pxGridPartial, pxGridOutcome := r.scrapePxGrid(ctx, builder, targets, selector, now)
	if pxGridPartial {
		partial = true
	}
	if r.scrapeDataConnect(ctx, builder, targets, selector) {
		partial = true
	}
	return r.finishScrape(builder, now, partial, pxGridOutcome), nil
}

func (r *iseMetricsReceiver) finishScrape(builder *iseMetricsBuilder, _ time.Time, partial bool, pxGridOutcome apiOutcomeSummary) pmetric.Metrics {
	r.statsMu.Lock()
	stats := append([]ise.RequestStat(nil), r.stats...)
	r.statsMu.Unlock()
	r.queryMu.Lock()
	queries := append([]ise.DataConnectStat(nil), r.queries...)
	r.queryMu.Unlock()
	r.recordAPIRequestMetrics(builder)
	r.recordDataConnectMetrics(builder)

	outcome := summarizeAPIOutcomes(stats, func(stat ise.RequestStat) string { return stat.Outcome })
	dataConnectOutcome := summarizeAPIOutcomes(queries, func(stat ise.DataConnectStat) string { return stat.Outcome })
	outcome.attempted = outcome.attempted || dataConnectOutcome.attempted
	outcome.succeeded = outcome.succeeded || dataConnectOutcome.succeeded
	outcome.attempted = outcome.attempted || pxGridOutcome.attempted
	outcome.succeeded = outcome.succeeded || pxGridOutcome.succeeded
	rb := builder.controllerResource()
	if availability, ok := outcome.availability(); ok {
		rb.recordInt("ise.controller.up", "Whether any ISE REST, pxGrid, or Data Connect operation succeeded in the scrape.", "1", availability, nil)
	}
	rb.recordInt("ise.scrape.partial_success", "Whether one or more ISE endpoint families failed or were skipped.", "1", boolToInt(partial), nil)
	if lastSuccess, ok := r.success.observe(time.Now(), !partial && outcome.succeeded); ok {
		rb.recordInt("ise.scrape.last_success", "Unix timestamp of the most recent fully successful ISE scrape.", "s", lastSuccess.Unix(), nil)
	}
	builder.flushCounts()
	return builder.emit()
}

func (r *iseMetricsReceiver) scrapeWebhookDeliveries(ctx context.Context, builder *iseMetricsBuilder, webhook ise.Object, targets iseTargetMatcher, selector deviceSelectionMatcher, now time.Time) bool {
	spec, ok := iseWebhookDeliveriesSpec(webhook)
	if !ok {
		return false
	}
	objects, err := r.fetchEndpoint(ctx, spec, now)
	if err != nil {
		builder.recordEndpointError(iseEndpointSpecWithPath(r.config, spec, now), err)
		r.settings.Logger.Warn("ISE webhook delivery endpoint failed", zap.String("operation", spec.operation), zap.Error(err))
		if ctx.Err() != nil {
			return true
		}
	}
	for _, obj := range objects {
		if iseObjectSelected(obj, targets, selector) {
			builder.recordObject(spec, obj)
		}
	}
	return err != nil
}

func (r *iseMetricsReceiver) fetchEndpoint(ctx context.Context, spec iseEndpointSpec, now time.Time) ([]ise.Object, error) {
	if spec.operation == "mnt.failure_reasons" {
		r.referenceMu.Lock()
		if r.failureReasonsLoaded {
			objects := append([]ise.Object(nil), r.failureReasons...)
			r.referenceMu.Unlock()
			return objects, nil
		}
		r.referenceMu.Unlock()
	}
	query := url.Values{}
	if spec.query != nil {
		query = spec.query(r.config, now)
	}
	path := iseEndpointPath(r.config, spec, now)
	maxResults := iseGroupMaxResults(r.iseConfig, spec.group)
	var (
		objects []ise.Object
		err     error
	)
	switch spec.mode {
	case iseEndpointERSList:
		objects, err = r.client.ListERS(ctx, spec.operation, path, query, maxResults)
	case iseEndpointGet:
		var obj ise.Object
		obj, err = r.client.GetObject(ctx, spec.operation, path, query)
		if err == nil {
			objects = []ise.Object{obj}
		}
	default:
		objects, err = r.client.List(ctx, spec.operation, path, query, maxResults)
	}
	if spec.operation == "mnt.failure_reasons" && err == nil {
		r.referenceMu.Lock()
		if !r.failureReasonsLoaded {
			r.failureReasons = append([]ise.Object(nil), objects...)
			r.failureReasonsLoaded = true
		}
		r.referenceMu.Unlock()
	}
	return objects, err
}

func iseEndpointSpecWithPath(conf *Config, spec iseEndpointSpec, now time.Time) iseEndpointSpec {
	spec.path = iseEndpointPath(conf, spec, now)
	return spec
}

func iseEndpointPath(conf *Config, spec iseEndpointSpec, now time.Time) string {
	if spec.pathFunc != nil {
		return spec.pathFunc(conf, now)
	}
	return spec.path
}

func (r *iseMetricsReceiver) scrapePxGrid(ctx context.Context, builder *iseMetricsBuilder, targets iseTargetMatcher, selector deviceSelectionMatcher, now time.Time) (bool, apiOutcomeSummary) {
	outcome := apiOutcomeSummary{}
	if r.pxGrid == nil {
		if r.iseConfig.PxGrid.Enabled {
			builder.recordServiceSkipped("pxgrid", "pxgrid.client", "pxGrid client not configured")
			outcome.attempted = true
			return true, outcome
		}
		return false, outcome
	}
	partial := false
	if r.iseConfig.PxGrid.AutoActivate {
		outcome.attempted = true
		obj, err := r.pxGrid.AccountActivate(ctx)
		if err != nil {
			partial = true
			builder.recordServiceUnavailable("pxgrid", "pxgrid.account_activate", err)
		} else {
			outcome.succeeded = true
			builder.recordObject(iseEndpointSpec{group: "pxgrid", operation: "pxgrid.account_activate", objectType: "pxgrid_account", mode: iseEndpointGet}, obj)
		}
	}
	outcome.attempted = true
	if obj, err := r.pxGrid.Version(ctx); err != nil {
		partial = true
		builder.recordServiceUnavailable("pxgrid", "pxgrid.version", err)
	} else {
		outcome.succeeded = true
		builder.recordObject(iseEndpointSpec{group: "pxgrid", operation: "pxgrid.version", objectType: "pxgrid_version", mode: iseEndpointGet}, obj)
	}
	services := r.iseConfig.Targets.PxGridServices
	if len(services) == 0 {
		services = []string{"com.cisco.ise.session", "com.cisco.ise.radius", "com.cisco.ise.system", "com.cisco.ise.config.trustsec", "com.cisco.ise.endpoint"}
	}
	for _, service := range services {
		outcome.attempted = true
		objects, err := r.pxGrid.ServiceLookup(ctx, service)
		spec := iseEndpointSpec{group: "pxgrid", operation: "pxgrid.service_lookup", objectType: "pxgrid_service", mode: iseEndpointList}
		if err != nil {
			partial = true
			builder.recordServiceUnavailable("pxgrid", "pxgrid.service_lookup", err)
			continue
		}
		outcome.succeeded = true
		if len(objects) == 0 {
			builder.recordServiceSkipped("pxgrid", "pxgrid.service_lookup", service)
		}
		for _, obj := range objects {
			if iseObjectSelected(obj, targets, selector) {
				builder.recordObject(spec, obj)
			}
		}
	}
	for _, query := range isePxGridRESTQueries(r.iseConfig, now) {
		outcome.attempted = true
		objects, err := r.pxGrid.PostObjects(ctx, query.operation, query.service, query.path, query.payload, r.iseConfig.PxGrid.MaxResults)
		if err != nil {
			partial = true
			builder.recordServiceUnavailable("pxgrid", query.operation, err)
			continue
		}
		outcome.succeeded = true
		for _, obj := range objects {
			if iseObjectSelected(obj, targets, selector) {
				builder.recordObject(iseEndpointSpec{group: "pxgrid", operation: query.operation, objectType: query.objectType, mode: iseEndpointList}, obj)
			}
		}
	}
	if r.iseConfig.PxGrid.Streaming {
		for _, subscription := range isePxGridSubscriptions(r.iseConfig.PxGrid.Subscriptions) {
			builder.controllerResource().recordInt("ise.pxgrid.subscription.status", "Configured pxGrid subscription status by topic.", "1", 1, map[string]string{"ise.pxgrid.topic": isePxGridSubscriptionLabel(subscription)})
		}
	}
	return partial, outcome
}

func (r *iseMetricsReceiver) scrapeDataConnect(ctx context.Context, builder *iseMetricsBuilder, targets iseTargetMatcher, selector deviceSelectionMatcher) bool {
	if r.dataConnect == nil {
		return false
	}
	if err := r.dataConnect.Ping(ctx); err != nil {
		builder.recordServiceUnavailable("data_connect", "data_connect.ping", err)
		return true
	}
	partial := false
	for _, view := range iseDataConnectViews(r.iseConfig) {
		objects, err := r.dataConnect.QueryView(ctx, view)
		spec := iseEndpointSpec{group: "data_connect", operation: "data_connect." + strings.ToLower(view.Name), objectType: "data_connect_" + strings.ToLower(view.Category), mode: iseEndpointList}
		if err != nil {
			partial = true
			builder.recordServiceUnavailable("data_connect", spec.operation, err)
			if ctx.Err() != nil {
				return true
			}
		}
		for _, obj := range objects {
			if iseObjectSelected(obj, targets, selector) {
				builder.recordObject(spec, obj)
			}
		}
	}
	return partial
}

func (r *iseMetricsReceiver) recordRequest(stat ise.RequestStat) {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats = append(r.stats, stat)
}

func (r *iseMetricsReceiver) resetRequestStats() {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats = nil
}

func (r *iseMetricsReceiver) recordAPIRequestMetrics(builder *iseMetricsBuilder) {
	r.statsMu.Lock()
	stats := append([]ise.RequestStat(nil), r.stats...)
	r.statsMu.Unlock()
	observations := make([]apiRequestObservation, 0, len(stats))
	for _, stat := range stats {
		attrs := map[string]string{
			"ise.api.operation":   stat.Operation,
			"http.request.method": stat.Method,
			"ise.api.path":        iseMetricAPIPath(stat.Operation, stat.Path),
			"ise.api.outcome":     stat.Outcome,
		}
		if stat.StatusCode > 0 {
			attrs["http.response.status_code"] = strconv.Itoa(stat.StatusCode)
		}
		observations = append(observations, apiRequestObservation{attrs: attrs, durationSeconds: stat.Duration.Seconds(), failed: stat.Outcome != "success", rateLimited: stat.RateLimited})
	}
	for _, aggregate := range aggregateAPIRequestObservations(observations) {
		rb := builder.controllerResource()
		rb.recordDouble("ise.api.request.duration", "Average duration of ISE REST/OpenAPI/ERS/MnT and pxGrid REST request attempts within the scrape for each matching request-attribute set.", "s", aggregate.averageDurationSeconds, aggregate.attrs)
		if aggregate.errors > 0 {
			rb.recordSum("ise.api.request.errors", "ISE API request failures.", "{error}", aggregate.errors, aggregate.attrs)
		}
		if aggregate.rateLimited > 0 {
			rb.recordSum("ise.api.rate_limited", "ISE API requests that were rate limited.", "{request}", aggregate.rateLimited, aggregate.attrs)
		}
	}
}

func (r *iseMetricsReceiver) recordDataConnectQuery(stat ise.DataConnectStat) {
	r.queryMu.Lock()
	defer r.queryMu.Unlock()
	r.queries = append(r.queries, stat)
}

func (r *iseMetricsReceiver) resetDataConnectQueries() {
	r.queryMu.Lock()
	defer r.queryMu.Unlock()
	r.queries = nil
}

func (r *iseMetricsReceiver) recordDataConnectMetrics(builder *iseMetricsBuilder) {
	r.queryMu.Lock()
	queries := append([]ise.DataConnectStat(nil), r.queries...)
	r.queryMu.Unlock()
	for _, query := range queries {
		attrs := map[string]string{
			"ise.dataconnect.view":    query.View,
			"ise.dataconnect.outcome": query.Outcome,
		}
		builder.controllerResource().recordDouble("ise.dataconnect.query.duration", "Duration of each Data Connect query.", "s", query.Duration.Seconds(), attrs)
		builder.controllerResource().recordInt("ise.dataconnect.query.rows", "Rows returned from each allowlisted Data Connect view.", "{row}", int64(query.Rows), attrs)
		if query.Outcome != "success" {
			builder.controllerResource().recordSum("ise.dataconnect.query.errors", "Data Connect query failures.", "{error}", 1, attrs)
		}
	}
}

func (r *iseLogsReceiver) Start(_ context.Context, _ component.Host) error {
	r.startMu.Lock()
	defer r.startMu.Unlock()
	if r.cancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.workers.Go(func() {
		r.run(ctx)
	})
	if r.seen.checkpointEnabled() {
		r.workers.Go(func() {
			r.runCheckpointFlusher(ctx)
		})
	}
	if r.pxGrid != nil && r.iseConfig.PxGrid.Streaming {
		for _, subscription := range isePxGridSubscriptions(r.iseConfig.PxGrid.Subscriptions) {
			r.workers.Go(func() {
				r.runPxGridSubscription(ctx, subscription)
			})
		}
	}
	go func() {
		r.workers.Wait()
		close(r.done)
	}()
	return nil
}

func (r *iseLogsReceiver) Shutdown(ctx context.Context) error {
	r.startMu.Lock()
	cancel := r.cancel
	r.startMu.Unlock()
	var workerDone <-chan struct{}
	if cancel != nil {
		cancel()
		workerDone = r.done
	}
	closeDone := r.beginClose()
	if err := waitForISEShutdown(ctx, workerDone, nil); err != nil {
		return err
	}
	flushCtx, flushCancel := checkpointFlushContext(ctx)
	r.seen.persistCheckpoint(flushCtx, true)
	flushCancel()
	return waitForISEShutdown(ctx, nil, closeDone)
}

func (r *iseLogsReceiver) beginClose() <-chan struct{} {
	r.closeOnce.Do(func() {
		if r.closeDone == nil {
			r.closeDone = make(chan struct{})
		}
		go func() {
			defer close(r.closeDone)
			r.close()
		}()
	})
	return r.closeDone
}

func (r *iseLogsReceiver) close() {
	if r.client != nil {
		r.client.CloseIdleConnections()
	}
	if r.pxGrid != nil {
		r.pxGrid.CloseIdleConnections()
	}
	if r.dataConnect != nil {
		if err := r.dataConnect.Close(); err != nil {
			r.settings.Logger.Warn("ISE Data Connect close failed", zap.Error(err))
		}
	}
}

func waitForISEShutdown(ctx context.Context, workerDone, closeDone <-chan struct{}) error {
	for workerDone != nil || closeDone != nil {
		select {
		case <-workerDone:
			workerDone = nil
		case <-closeDone:
			closeDone = nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (r *iseLogsReceiver) run(ctx context.Context) {
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

func (r *iseLogsReceiver) runCheckpointFlusher(ctx context.Context) {
	ticker := time.NewTicker(logCheckpointFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.seen.persistCheckpoint(ctx, false)
		}
	}
}

func (r *iseLogsReceiver) collect(ctx context.Context) {
	scrapeCtx, cancel := context.WithTimeout(ctx, r.config.ControllerConfig.Timeout)
	defer cancel()
	r.seen.BeginBatch()
	obsCtx := startLogsOp(ctx, r.obs)
	ld, scrapeErr := r.scrape(scrapeCtx)
	if scrapeErr != nil {
		r.settings.Logger.Error("ISE log scrape failed", zap.Error(scrapeErr))
	}
	logCount, consumeErr := consumeDeduplicatedLogs(ctx, r.consumer, r.seen, ld)
	if consumeErr != nil {
		r.settings.Logger.Error("ISE logs consumer failed", zap.Error(consumeErr))
	}
	endLogsOp(obsCtx, r.obs, logCount, combineSignalErrors(scrapeErr, consumeErr))
}

func (r *iseLogsReceiver) scrape(ctx context.Context) (plog.Logs, error) {
	now := time.Now()
	builder := newISELogsBuilder(now, r.iseConfig.Endpoint)
	var endpointErrors []error
	selector := newISEDeviceSelectionMatcher(r.config)
	targets := newISETargetMatcher(r.iseConfig.Targets)
	r.pruneSeen(now)
	for _, spec := range iseLogEndpoints() {
		if !iseGroupEnabled(r.iseConfig, spec.group) {
			continue
		}
		objects, err := r.fetchEndpoint(ctx, spec, now)
		if err != nil {
			if ctx.Err() != nil {
				return builder.emit(), ctx.Err()
			}
			r.settings.Logger.Warn("ISE log endpoint failed", zap.String("operation", spec.operation), zap.Error(err))
			endpointErrors = append(endpointErrors, fmt.Errorf("ISE %s: %w", spec.operation, err))
		}
		for _, obj := range objects {
			if spec.operation == "openapi.webhooks" {
				// Webhook definitions are configuration and may contain delivery
				// credentials. Use them only to discover event deliveries.
				if err := r.scrapeWebhookDeliveryLogs(ctx, builder, obj, targets, selector, now); err != nil {
					if ctx.Err() != nil {
						return builder.emit(), ctx.Err()
					}
					endpointErrors = append(endpointErrors, err)
				}
				continue
			}
			if !iseObjectSelected(obj, targets, selector) {
				continue
			}
			if !r.markSeen(spec, obj, now) {
				continue
			}
			builder.recordObject(spec, obj)
		}
	}
	if r.pxGrid != nil {
		for _, query := range isePxGridLogQueries(r.iseConfig, now) {
			objects, err := r.pxGrid.PostObjects(ctx, query.operation, query.service, query.path, query.payload, r.iseConfig.PxGrid.MaxResults)
			if err != nil {
				if ctx.Err() != nil {
					return builder.emit(), ctx.Err()
				}
				r.settings.Logger.Warn("ISE pxGrid REST log endpoint failed", zap.String("operation", query.operation), zap.Error(err))
				endpointErrors = append(endpointErrors, fmt.Errorf("ISE pxGrid %s: %w", query.operation, err))
				continue
			}
			spec := iseEndpointSpec{group: "pxgrid", operation: query.operation, objectType: query.objectType}
			for _, obj := range objects {
				if iseObjectSelected(obj, targets, selector) && r.markSeen(spec, obj, now) {
					builder.recordObject(spec, obj)
				}
			}
		}
	}
	if r.dataConnect != nil {
		for _, view := range iseDataConnectLogViews(r.iseConfig) {
			objects, err := r.dataConnect.QueryView(ctx, view)
			if err != nil && ctx.Err() != nil {
				return builder.emit(), ctx.Err()
			}
			if err != nil {
				r.settings.Logger.Warn("ISE Data Connect log view failed", zap.String("view", view.Name), zap.Error(err))
				endpointErrors = append(endpointErrors, fmt.Errorf("ISE Data Connect %s: %w", view.Name, err))
			}
			spec := iseEndpointSpec{group: "data_connect", operation: "data_connect." + strings.ToLower(view.Name), objectType: "data_connect_" + strings.ToLower(view.Category)}
			for _, obj := range objects {
				if iseObjectSelected(obj, targets, selector) && r.markSeen(spec, obj, now) {
					builder.recordObject(spec, obj)
				}
			}
		}
	}
	return builder.emit(), errors.Join(endpointErrors...)
}

func (r *iseLogsReceiver) scrapeWebhookDeliveryLogs(ctx context.Context, builder *iseLogsBuilder, webhook ise.Object, targets iseTargetMatcher, selector deviceSelectionMatcher, now time.Time) error {
	spec, ok := iseWebhookDeliveriesSpec(webhook)
	if !ok {
		return nil
	}
	objects, err := r.fetchEndpoint(ctx, spec, now)
	if err != nil {
		r.settings.Logger.Warn("ISE webhook delivery log endpoint failed", zap.String("operation", spec.operation), zap.Error(err))
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	for _, obj := range objects {
		if iseObjectSelected(obj, targets, selector) && r.markSeen(spec, obj, now) {
			builder.recordObject(spec, obj)
		}
	}
	if err != nil {
		return fmt.Errorf("ISE %s: %w", spec.operation, err)
	}
	return nil
}

func (r *iseLogsReceiver) fetchEndpoint(ctx context.Context, spec iseEndpointSpec, now time.Time) ([]ise.Object, error) {
	query := url.Values{}
	if spec.query != nil {
		query = spec.query(r.config, now)
	}
	path := iseEndpointPath(r.config, spec, now)
	maxResults := iseGroupMaxResults(r.iseConfig, spec.group)
	switch spec.mode {
	case iseEndpointERSList:
		return r.client.ListERS(ctx, spec.operation, path, query, maxResults)
	case iseEndpointGet:
		obj, err := r.client.GetObject(ctx, spec.operation, path, query)
		if err != nil {
			return nil, err
		}
		return []ise.Object{obj}, nil
	default:
		return r.client.List(ctx, spec.operation, path, query, maxResults)
	}
}

func (r *iseLogsReceiver) runPxGridSubscription(ctx context.Context, subscription ise.PxGridSubscription) {
	for {
		if ctx.Err() != nil {
			return
		}
		err := r.pxGrid.Subscribe(ctx, subscription, func(message ise.StompMessage) error {
			return r.consumePxGridMessage(ctx, message)
		})
		if ctx.Err() != nil {
			return
		}
		r.settings.Logger.Warn("ISE pxGrid subscription disconnected", zap.String("service", subscription.Service), zap.String("topic_property", subscription.TopicProperty), zap.Error(err))
		timer := time.NewTimer(30 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (r *iseLogsReceiver) consumePxGridMessage(ctx context.Context, message ise.StompMessage) error {
	now := time.Now()
	builder := newISELogsBuilder(now, r.iseConfig.Endpoint)
	obj := ise.Object{"topic": message.Topic, "message_id": message.MessageID}
	for key, value := range message.Headers {
		obj[key] = value
	}
	if len(message.Body) > 0 {
		var body ise.Object
		if err := httpclient.DecodeJSON(message.Body, &body); err == nil {
			maps.Copy(obj, body)
		} else {
			fingerprint := sha256.Sum256(message.Body)
			obj["body_decode_error"] = true
			obj["body_sha256"] = fmt.Sprintf("%x", fingerprint)
		}
	}
	if !newISEDeviceSelectionMatcher(r.config).allows(iseObjectIdentity(obj)) {
		return nil
	}
	spec := iseEndpointSpec{group: "pxgrid", operation: "pxgrid.subscription", objectType: "pxgrid_message"}
	key := iseSeenKey(spec, obj)
	if !r.seen.MarkCommitted(key, now) {
		return nil
	}
	builder.recordObject(spec, obj)
	if err := r.consumer.ConsumeLogs(ctx, builder.emit()); err != nil {
		r.seen.Forget(key)
		r.settings.Logger.Error("ISE pxGrid log consumer failed", zap.Error(err))
		return err
	}
	r.seen.ConfirmCommitted(key)
	r.seen.persistCheckpoint(ctx, false)
	return nil
}

func (r *iseLogsReceiver) markSeen(spec iseEndpointSpec, obj ise.Object, now time.Time) bool {
	return r.seen.MarkPending(iseSeenKey(spec, obj), now)
}

func iseSeenKey(spec iseEndpointSpec, obj ise.Object) string {
	return logDedupKey(spec.operation, ise.StableID(obj), redactISELogObject(obj))
}

// iseSeenMaxEntries caps the dedup map so a deployment with large config
// inventories cannot grow it without bound between TTL expiries.
const iseSeenMaxEntries = 50000

func (r *iseLogsReceiver) pruneSeen(now time.Time) {
	ttl := r.iseConfig.EventLookback
	if ttl <= 0 {
		ttl = defaultISEConfig().EventLookback
	}
	cutoff := now.Add(-ttl)
	r.seen.Expire(cutoff, iseSeenMaxEntries)
}

type iseMetricsBuilder struct {
	metrics   pmetric.Metrics
	now       pcommon.Timestamp
	start     pcommon.Timestamp
	endpoint  string
	resources map[string]*resourceMetricsBuilder
	counts    []iseCount
	counters  *counterStore
}

func newISEMetricsBuilder(now time.Time, endpoint string, counters *counterStore) *iseMetricsBuilder {
	if counters == nil {
		counters = newCounterStore()
	}
	ts := pcommon.NewTimestampFromTime(now)
	return &iseMetricsBuilder{
		metrics:   pmetric.NewMetrics(),
		now:       ts,
		start:     pcommon.NewTimestampFromTime(counters.StartTime()),
		endpoint:  endpoint,
		resources: map[string]*resourceMetricsBuilder{},
		counters:  counters,
	}
}

func (b *iseMetricsBuilder) emit() pmetric.Metrics {
	return b.metrics
}

func (b *iseMetricsBuilder) controllerResource() *resourceMetricsBuilder {
	rb := b.resource("ise:controller")
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", "ise:"+b.endpoint)
	putStr(attrs, "host.name", "Cisco ISE")
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Cisco ISE")
	putStr(attrs, "cisco.controller.type", "ise")
	putStr(attrs, "ise.endpoint", b.endpoint)
	return rb
}

func (b *iseMetricsBuilder) objectResource(spec iseEndpointSpec, obj ise.Object) *resourceMetricsBuilder {
	if iseControllerResourceMetricGroup(spec.group) {
		return b.controllerResource()
	}
	id := firstNonEmpty(ise.StableID(obj), ise.String(obj, "name", "Name", "hostname", "nodeName", "mac", "macAddress", "user_name", "username"))
	if id == "" {
		return b.controllerResource()
	}
	rb := b.resource(spec.objectType + ":" + id)
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", "ise:"+spec.objectType+":"+id)
	putStr(attrs, "host.name", firstNonEmpty(ise.String(obj, "name", "Name", "hostname", "nodeName", "network_device_name"), id))
	putIPAttrs(attrs, "host.ip", ise.String(obj, "ipaddress"), ise.String(obj, "ipAddress"), ise.String(obj, "nas_ip_address"), ise.String(obj, "device_ip_address"))
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Cisco ISE")
	putStr(attrs, "cisco.controller.type", "ise")
	putStr(attrs, "ise.endpoint", b.endpoint)
	return rb
}

func iseControllerResourceMetricGroup(group string) bool {
	switch group {
	case "sessions", "session_details", "auth_failures", "accounting", "pxgrid", "data_connect":
		return true
	default:
		return false
	}
}

func (b *iseMetricsBuilder) resource(key string) *resourceMetricsBuilder {
	if rb := b.resources[key]; rb != nil {
		return rb
	}
	rm := b.metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName(iseScopeName)
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

func (b *iseMetricsBuilder) recordObject(spec iseEndpointSpec, obj ise.Object) {
	rb := b.objectResource(spec, obj)
	status := iseObjectStatus(obj)
	attrs := iseMetricObjectAttrs(spec, obj)
	evidenceAttrs := iseMetricEvidenceAttrs(spec, obj, attrs)
	// FailureReasons is a static reference catalog, not authentication-event
	// inventory. Emitting a generic evidence row for every long-form cause would
	// create thousands of high-cardinality metric series on every scrape.
	if spec.operation != "mnt.failure_reasons" {
		rb.recordInt("ise.resource.info", "Bounded metadata for ISE resources and evidence records.", "1", 1, evidenceAttrs)
		recordISEStatus(rb, "ise.resource.status", "Cisco ISE resource status encoded as a numeric state.", status, withAttr(evidenceAttrs, "ise.status", status))
	}
	switch spec.group {
	case "deployment":
		if spec.objectType == "deployment" || strings.Contains(spec.objectType, "node") {
			b.addCount("ise.deployment.node.count", withAttr(attrs, "ise.status", status))
			recordISEStatus(rb, "ise.deployment.node.status", "Cisco ISE deployment node or persona status.", status, withAttr(attrs, "ise.status", status))
		}
	case "network_devices":
		if spec.objectType == "network_device" {
			b.addCount("ise.network_device.count", withAttr(attrs, "ise.status", status))
			recordISEStatus(rb, "ise.network_device.status", "Cisco ISE network access device status.", status, withAttr(attrs, "ise.status", status))
		}
	case "endpoints":
		if spec.objectType == "endpoint" || spec.objectType == "rejected_endpoint" {
			b.addCount("ise.endpoint.count", withAttr(attrs, "ise.status", status))
			recordISEStatus(rb, "ise.endpoint.status", "Cisco ISE endpoint status.", status, withAttr(attrs, "ise.status", status))
		}
	case "sessions", "session_details":
		b.recordSessionObject(rb, spec, obj, attrs, evidenceAttrs)
	case "auth_failures":
		recordISEAuthFailureObject(rb, spec, obj)
	case "accounting":
		b.addCount("ise.accounting.session.count", attrs)
	case "policy":
		b.addCount("ise.policy.object.count", attrs)
		recordISEStatus(rb, "ise.policy.status", "Cisco ISE policy object status.", status, withAttr(attrs, "ise.status", status))
	case "posture":
		b.addCount("ise.endpoint.posture.count", withAttr(attrs, "ise.posture.status", firstNonEmpty(status, ise.String(obj, "posture_status", "postureStatus"))))
	case "profiler":
		b.addCount("ise.endpoint.profile.count", attrs)
		recordISEStatus(rb, "ise.profiler.policy.status", "Cisco ISE profiler policy status.", status, withAttr(attrs, "ise.status", status))
	case "trustsec":
		b.addCount("ise.trustsec.resource.count", attrs)
		recordISEStatus(rb, "ise.trustsec.resource.status", "Cisco ISE TrustSec resource status.", status, withAttr(attrs, "ise.status", status))
	case "alarms":
		b.addCount("ise.alarm.count", withAttr(attrs, "ise.severity", firstNonEmpty(ise.String(obj, "severity", "Severity"), status)))
	case "certificates":
		b.addCount("ise.certificate.count", attrs)
		if expiry, ok := ise.Time(obj, "expirationDate", "expiration_date", "validTo", "notAfter"); ok {
			rb.recordInt("ise.certificate.expiration", "Certificate expiration Unix timestamp.", "s", expiry.Unix(), attrs)
		}
	case "licensing":
		b.addCount("ise.license.count", withAttr(attrs, "ise.status", status))
		recordISEStatus(rb, "ise.license.status", "Cisco ISE license status.", status, withAttr(attrs, "ise.status", status))
	case "webhooks":
		if spec.objectType == "webhook_delivery" {
			b.addCount("ise.webhook.delivery.count", withAttr(attrs, "ise.status", status))
		}
	case "pxgrid":
		b.recordPxGridObject(rb, spec, obj, attrs, evidenceAttrs)
	case "data_connect":
		b.recordDataConnectObject(rb, spec, obj, attrs, evidenceAttrs)
	}
}

func (b *iseMetricsBuilder) recordSessionObject(rb *resourceMetricsBuilder, spec iseEndpointSpec, obj ise.Object, attrs, evidenceAttrs map[string]string) {
	count, hasCount := ise.Float64(obj, "count", "activeCount", "active_count", "total")
	switch spec.operation {
	case "mnt.session.active_count":
		if hasCount {
			rb.recordDouble("ise.session.active.count", "Active session counters from MnT.", "{session}", count, evidenceAttrs)
		}
		return
	case "mnt.session.posture_count":
		if hasCount {
			rb.recordInt("ise.endpoint.posture.count", "Endpoint posture records by bounded posture status.", "{item}", int64(count), evidenceAttrs)
		}
		return
	case "mnt.session.profiler_count":
		if hasCount {
			rb.recordInt("ise.endpoint.profile.count", "Endpoint profiler records by bounded object type.", "{item}", int64(count), evidenceAttrs)
		}
		return
	}
	b.recordSessionEvidence(rb, obj, attrs, evidenceAttrs)
}

func recordISEStatus(rb *resourceMetricsBuilder, name, description, value string, attrs map[string]string) {
	if code, ok := statusCode(value); ok {
		rb.recordInt(name, description, "1", code, attrs)
	}
}

func (b *iseMetricsBuilder) recordSessionEvidence(rb *resourceMetricsBuilder, obj ise.Object, attrs, evidenceAttrs map[string]string) {
	b.addCount("ise.session.count", withAttr(attrs, "ise.posture.status", ise.String(obj, "posture_status", "postureStatus")))
	posture := ise.String(obj, "posture_status", "postureStatus")
	recordISEStatus(rb, "ise.endpoint.posture.status", "Cisco ISE endpoint posture status.", posture, withAttr(evidenceAttrs, "ise.posture.status", posture))
}

func recordISEAuthFailureObject(rb *resourceMetricsBuilder, spec iseEndpointSpec, obj ise.Object) {
	if spec.operation != "mnt.failure_reasons" {
		// The remaining MnT object in this group is Version. It proves API
		// reachability but is not authentication-failure evidence.
		return
	}
	code := ise.String(obj, "message_code", "messageCode", "code")
	if code == "" {
		return
	}
	reasonAttrs := map[string]string{
		"ise.group":        spec.group,
		"ise.object.type":  spec.objectType,
		"ise.message.code": code,
	}
	rb.recordInt("ise.auth.failure.reason.info", "Bounded authentication-failure reason evidence.", "1", 1, reasonAttrs)
}

func (b *iseMetricsBuilder) recordAuthenticationFailure(obj ise.Object, attrs map[string]string) {
	protocol := strings.ToLower(firstNonEmpty(
		ise.String(obj, "authentication_protocol", "authenticationProtocol", "protocol"),
		attrs["ise.protocol"],
	))
	if strings.Contains(protocol, "tacacs") {
		b.addCount("ise.tacacs.failure.count", attrs)
		return
	}
	if strings.Contains(protocol, "radius") {
		b.addCount("ise.radius.failure.count", attrs)
	}
}

func (b *iseMetricsBuilder) recordPxGridObject(rb *resourceMetricsBuilder, spec iseEndpointSpec, obj ise.Object, attrs, evidenceAttrs map[string]string) {
	switch spec.operation {
	case "pxgrid.service_lookup":
		rb.recordInt("ise.pxgrid.service.status", "pxGrid service lookup and pxGrid Cloud/Direct status.", "1", 1, evidenceAttrs)
	case "pxgrid.session.get_sessions":
		b.addCount("ise.pxgrid.message.count", attrs)
		b.recordSessionEvidence(rb, obj, attrs, evidenceAttrs)
	case "pxgrid.radius.get_failures":
		b.addCount("ise.pxgrid.message.count", attrs)
		b.recordAuthenticationFailure(obj, attrs)
	case "pxgrid.trustsec.get_security_groups", "pxgrid.trustsec.get_sgacls", "pxgrid.trustsec.get_egress_policies":
		b.addCount("ise.pxgrid.message.count", attrs)
		b.addCount("ise.trustsec.resource.count", attrs)
		status := iseObjectStatus(obj)
		recordISEStatus(rb, "ise.trustsec.resource.status", "Cisco ISE TrustSec resource status.", status, withAttr(attrs, "ise.status", status))
	case "pxgrid.session.get_user_groups", "pxgrid.system.get_healths", "pxgrid.system.get_performances":
		b.addCount("ise.pxgrid.message.count", attrs)
	}
}

func (b *iseMetricsBuilder) recordDataConnectObject(rb *resourceMetricsBuilder, spec iseEndpointSpec, obj ise.Object, attrs, evidenceAttrs map[string]string) {
	b.addCount("ise.dataconnect.row.count", attrs)
	operation := strings.ToLower(spec.operation)
	switch {
	case strings.Contains(operation, "radius_accounting"),
		strings.Contains(operation, "tacacs_accounting"),
		strings.Contains(operation, "tacacs_command_accounting"):
		b.addCount("ise.accounting.session.count", attrs)
	case strings.Contains(operation, "radius_authentication"), strings.Contains(operation, "tacacs_authentication"), strings.Contains(operation, "tacacs_authorization"):
		if iseAuthenticationFailed(obj) {
			b.recordAuthenticationFailure(obj, attrs)
		}
	case strings.Contains(operation, "posture"):
		posture := ise.String(obj, "posture_status", "postureStatus", "status")
		b.addCount("ise.endpoint.posture.count", withAttr(attrs, "ise.posture.status", posture))
		recordISEStatus(rb, "ise.endpoint.posture.status", "Cisco ISE endpoint posture status.", posture, withAttr(evidenceAttrs, "ise.posture.status", posture))
	case strings.Contains(operation, "profil"):
		b.addCount("ise.endpoint.profile.count", attrs)
	}
}

func iseAuthenticationFailed(obj ise.Object) bool {
	if ise.String(obj, "failure_reason", "failureReason", "cause") != "" {
		return true
	}
	outcome := strings.ToLower(ise.String(obj,
		"authentication_status", "authenticationStatus", "status", "response", "outcome",
	))
	return strings.Contains(outcome, "fail") ||
		strings.Contains(outcome, "reject") ||
		strings.Contains(outcome, "deny") ||
		strings.Contains(outcome, "error")
}

func (b *iseMetricsBuilder) recordEndpointError(spec iseEndpointSpec, err error) {
	attrs := map[string]string{
		"ise.group":         spec.group,
		"ise.api.operation": spec.operation,
		"ise.api.path":      iseMetricAPIPath(spec.operation, spec.path),
		"ise.error.kind":    classifyISEError(err),
	}
	b.controllerResource().recordSum("ise.api.endpoint.error", "Endpoint-family scrape failures.", "{error}", 1, attrs)
	if ise.IsUnavailable(err) {
		b.recordServiceUnavailable(spec.group, spec.operation, err)
	}
}

func iseMetricAPIPath(operation, path string) string {
	switch operation {
	case "mnt.session.auth_list":
		return "/admin/API/mnt/Session/AuthList/{start}/{end}"
	case "openapi.alarm_instances":
		return "/api/v1/alarms/instances/{page}/{size}"
	case "openapi.webhook_deliveries":
		return "/api/v1/webhooks/{webhookId}/deliveries"
	default:
		return path
	}
}

func (b *iseMetricsBuilder) recordServiceUnavailable(group, operation string, err error) {
	b.controllerResource().recordInt("ise.service.unavailable", "ISE API, pxGrid, or Data Connect service unavailable, disabled, unauthorized, or not installed.", "1", 1, map[string]string{
		"ise.group":         group,
		"ise.api.operation": operation,
		"ise.error.kind":    classifyISEError(err),
	})
}

func (b *iseMetricsBuilder) recordServiceSkipped(group, operation, reason string) {
	b.controllerResource().recordInt("ise.service.skipped", "ISE service or endpoint family skipped because required target scope was not configured.", "1", 1, map[string]string{
		"ise.group":         group,
		"ise.api.operation": operation,
		"ise.skip.reason":   reason,
	})
}

func (b *iseMetricsBuilder) addCount(name string, attrs map[string]string) {
	b.counts = append(b.counts, iseCount{name: name, value: 1, attrs: attrs})
}

func (b *iseMetricsBuilder) flushCounts() {
	totals := map[string]int64{}
	attrsByKey := map[string]map[string]string{}
	for _, count := range b.counts {
		key := count.name + "|" + attrsKey(count.attrs)
		totals[key] += count.value
		attrsByKey[key] = count.attrs
	}
	for key, value := range totals {
		name, _, _ := strings.Cut(key, "|")
		b.controllerResource().recordInt(name, "Cisco ISE aggregated count.", "{item}", value, attrsByKey[key])
	}
}

type iseLogsBuilder struct {
	logs     plog.Logs
	now      pcommon.Timestamp
	endpoint string
}

func newISELogsBuilder(now time.Time, endpoint string) *iseLogsBuilder {
	return &iseLogsBuilder{logs: plog.NewLogs(), now: pcommon.NewTimestampFromTime(now), endpoint: endpoint}
}

func (b *iseLogsBuilder) emit() plog.Logs {
	return b.logs
}

func (b *iseLogsBuilder) recordObject(spec iseEndpointSpec, obj ise.Object) {
	rl := b.logs.ResourceLogs().AppendEmpty()
	attrs := rl.Resource().Attributes()
	putStr(attrs, "host.id", "ise:"+b.endpoint)
	putStr(attrs, "host.name", "Cisco ISE")
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Cisco ISE")
	putStr(attrs, "cisco.controller.type", "ise")
	putStr(attrs, "ise.endpoint", b.endpoint)
	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName(iseScopeName)
	record := sl.LogRecords().AppendEmpty()
	if sourceTime, ok := ise.Time(obj, "timestamp", "eventTimestamp", "createTime", "updateTime", "LOGGED_AT", "LOGGED_TIME"); ok {
		if timestamp, valid := pdataTimestampFromTime(sourceTime); valid {
			record.SetTimestamp(timestamp)
		}
	}
	record.SetObservedTimestamp(b.now)
	record.Body().SetStr(mustJSON(redactISELogObject(obj)))
	record.Attributes().PutStr("event.domain", "ise")
	record.Attributes().PutStr("event.name", spec.operation)
	record.Attributes().PutStr("ise.group", spec.group)
	record.Attributes().PutStr("ise.object.type", spec.objectType)
	for key, value := range iseObjectAttrs(spec, obj) {
		putStr(record.Attributes(), key, value)
	}
}

func iseMetricEndpoints() []iseEndpointSpec {
	return []iseEndpointSpec{
		{group: "deployment", operation: "deployment.nodes", path: "/api/v1/deployment/node", objectType: "deployment_node", mode: iseEndpointList},
		{group: "deployment", operation: "openapi.deployment.node_groups", path: "/api/v1/deployment/node-group", objectType: "deployment_node_group", mode: iseEndpointList},
		{group: "deployment", operation: "openapi.deployment.pan_ha", path: "/api/v1/deployment/pan-ha", objectType: "deployment_ha", mode: iseEndpointGet},
		{group: "deployment", operation: "openapi.task_service", path: "/api/v1/task", objectType: "task", mode: iseEndpointList},
		{group: "deployment", operation: "openapi.system.proxy", path: "/api/v1/system-settings/proxy", objectType: "system_setting", mode: iseEndpointGet},
		{group: "deployment", operation: "openapi.system.transport_gateway", path: "/api/v1/system-settings/telemetry/transport-gateway", objectType: "system_setting", mode: iseEndpointGet},
		{group: "deployment", operation: "openapi.repository", path: "/api/v1/repository", objectType: "repository", mode: iseEndpointList},
		{group: "deployment", operation: "openapi.backup_restore.last_backup_status", path: "/api/v1/backup-restore/config/last-backup-status", objectType: "backup_restore_status", mode: iseEndpointGet},
		{group: "deployment", operation: "openapi.upgrade.prepare_status", path: "/api/v1/upgrade/prepare/get-status", objectType: "upgrade_status", mode: iseEndpointGet},
		{group: "deployment", operation: "openapi.upgrade.stage_status", path: "/api/v1/upgrade/stage/get-status", objectType: "upgrade_status", mode: iseEndpointGet},
		{group: "deployment", operation: "openapi.upgrade.proceed_status", path: "/api/v1/upgrade/proceed/get-status", objectType: "upgrade_status", mode: iseEndpointGet},
		{group: "deployment", operation: "openapi.upgrade.summary_status", path: "/api/v1/upgrade/summary/get-status", objectType: "upgrade_status", mode: iseEndpointGet},
		{group: "deployment", operation: "openapi.patch.prechecks_status", path: "/api/v1/upgrade-patch/patch-install/pre-checks-status", objectType: "patch_status", mode: iseEndpointGet},
		{group: "deployment", operation: "openapi.patch.install_status", path: "/api/v1/upgrade-patch/patch-install/get-status", objectType: "patch_status", mode: iseEndpointGet},
		{group: "deployment", operation: "openapi.patch.list", path: "/api/v1/upgrade-patch/patch-install/list-patch", objectType: "patch", mode: iseEndpointList},
		{group: "deployment", operation: "openapi.patch.install_summary", path: "/api/v1/upgrade-patch/patch-install/get-summary", objectType: "patch_status", mode: iseEndpointGet},
		{group: "deployment", operation: "openapi.patch.rollback_prechecks_status", path: "/api/v1/rollback/patch-rollback/pre-checks-status", objectType: "patch_status", mode: iseEndpointGet},
		{group: "deployment", operation: "openapi.patch.rollback_summary", path: "/api/v1/rollback/patch-rollback/summary", objectType: "patch_status", mode: iseEndpointGet},
		{group: "deployment", operation: "openapi.patch.rollback_status", path: "/api/v1/rollback/patch-rollback/get-status", objectType: "patch_status", mode: iseEndpointGet},
		{group: "deployment", operation: "ers.nodes", path: "/ers/config/node", objectType: "deployment_node", mode: iseEndpointERSList},
		{group: "deployment", operation: "ers.session_service_nodes", path: "/ers/config/sessionservicenode", objectType: "session_service_node", mode: iseEndpointERSList},
		{group: "deployment", operation: "ers.deployment_info", path: "/ers/config/deploymentinfo/getAllInfo", objectType: "deployment", mode: iseEndpointGet},
		{group: "deployment", operation: "ers.services", path: "/ers/config/service", objectType: "ise_service", mode: iseEndpointERSList},
		{group: "deployment", operation: "ers.support_bundle_status", path: "/ers/config/supportbundlestatus", objectType: "support_bundle_status", mode: iseEndpointERSList},
		{group: "network_devices", operation: "ers.network_devices", path: "/ers/config/networkdevice", objectType: "network_device", mode: iseEndpointERSList},
		{group: "network_devices", operation: "ers.network_device_groups", path: "/ers/config/networkdevicegroup", objectType: "network_device_group", mode: iseEndpointERSList},
		{group: "network_devices", operation: "ers.external_radius_servers", path: "/ers/config/externalradiusserver", objectType: "external_radius_server", mode: iseEndpointERSList},
		{group: "network_devices", operation: "ers.telemetry_info", path: "/ers/config/telemetryinfo", objectType: "telemetry_info", mode: iseEndpointERSList},
		{group: "endpoints", operation: "ers.endpoints", path: "/ers/config/endpoint", objectType: "endpoint", mode: iseEndpointERSList},
		{group: "endpoints", operation: "ers.rejected_endpoints", path: "/ers/config/endpoint/getrejectedendpoints", objectType: "rejected_endpoint", mode: iseEndpointERSList},
		{group: "endpoints", operation: "ers.endpoint_groups", path: "/ers/config/endpointgroup", objectType: "endpoint_group", mode: iseEndpointERSList},
		{group: "endpoints", operation: "openapi.endpoints", path: "/api/v1/endpoint", objectType: "endpoint", mode: iseEndpointList},
		{group: "endpoints", operation: "openapi.endpoint_device_type_summary", path: "/api/v1/endpoint/deviceType/summary", objectType: "endpoint_summary", mode: iseEndpointList},
		{group: "endpoints", operation: "openapi.endpoint_custom_attributes", path: "/api/v1/endpoint-custom-attribute", objectType: "endpoint_custom_attribute", mode: iseEndpointList},
		{group: "endpoints", operation: "openapi.fiveg.user_equipment", path: "/api/v1/fiveg/user-equipment", objectType: "fiveg_user_equipment", mode: iseEndpointList},
		{group: "endpoints", operation: "openapi.fiveg.subscribers", path: "/api/v1/fiveg/subscriber", objectType: "fiveg_subscriber", mode: iseEndpointList},
		{group: "sessions", operation: "mnt.session.active_count", path: "/admin/API/mnt/Session/ActiveCount", objectType: "session_count", mode: iseEndpointGet},
		{group: "sessions", operation: "mnt.session.posture_count", path: "/admin/API/mnt/Session/PostureCount", objectType: "session_count", mode: iseEndpointGet},
		{group: "sessions", operation: "mnt.session.profiler_count", path: "/admin/API/mnt/Session/ProfilerCount", objectType: "session_count", mode: iseEndpointGet},
		{group: "session_details", operation: "mnt.session.active_list", path: "/admin/API/mnt/Session/ActiveList", objectType: "session", mode: iseEndpointList},
		{group: "session_details", operation: "mnt.session.auth_list", objectType: "auth_session", mode: iseEndpointList, pathFunc: iseAuthSessionsListPath},
		{group: "auth_failures", operation: "mnt.version", path: "/admin/API/mnt/Version", objectType: "mnt_version", mode: iseEndpointGet},
		{group: "auth_failures", operation: "mnt.failure_reasons", path: "/admin/API/mnt/FailureReasons", objectType: "failure_reason", mode: iseEndpointList},
		{group: "policy", operation: "openapi.rbac.admin_groups", path: "/api/v1/rbac/admin-group", objectType: "rbac_admin_group", mode: iseEndpointList},
		{group: "policy", operation: "openapi.rbac.admin_users", path: "/api/v1/rbac/admin-user", objectType: "rbac_admin_user", mode: iseEndpointList},
		{group: "policy", operation: "openapi.rbac.data_access", path: "/api/v1/rbac/data-access", objectType: "rbac_data_access", mode: iseEndpointList},
		{group: "policy", operation: "openapi.rbac.external_groups", path: "/api/v1/rbac/external-groups", objectType: "rbac_external_group", mode: iseEndpointList},
		{group: "policy", operation: "openapi.rbac.menu_access", path: "/api/v1/rbac/menu-access", objectType: "rbac_menu_access", mode: iseEndpointList},
		{group: "policy", operation: "openapi.rbac.network_users", path: "/api/v1/rbac/network-users", objectType: "rbac_network_user", mode: iseEndpointList},
		{group: "policy", operation: "openapi.rbac.policy", path: "/api/v1/rbac/policy", objectType: "rbac_policy", mode: iseEndpointList},
		{group: "policy", operation: "openapi.mfa.configurations", path: "/api/v1/duo-mfa/mfa", objectType: "mfa_configuration", mode: iseEndpointList},
		{group: "policy", operation: "openapi.mfa.status", path: "/api/v1/duo-mfa/status", objectType: "mfa_status", mode: iseEndpointGet},
		{group: "policy", operation: "openapi.oidc.configurations", path: "/api/v1/oidc", objectType: "oidc_configuration", mode: iseEndpointList},
		{group: "policy", operation: "openapi.duo_identitysync.active_directories", path: "/api/v1/duo-identitysync/activedirectories", objectType: "identity_sync_directory", mode: iseEndpointList},
		{group: "policy", operation: "openapi.duo_identitysync.configurations", path: "/api/v1/duo-identitysync/identitysync", objectType: "identity_sync_configuration", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.network_access", path: "/api/v1/policy/network-access/policy-set", objectType: "policy_set", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.network_access.authorization_profiles", path: "/api/v1/policy/network-access/authorization-profiles", objectType: "authorization_profile", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.network_access.conditions", path: "/api/v1/policy/network-access/condition", objectType: "policy_condition", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.network_access.authentication_conditions", path: "/api/v1/policy/network-access/condition/authentication", objectType: "policy_condition", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.network_access.authorization_conditions", path: "/api/v1/policy/network-access/condition/authorization", objectType: "policy_condition", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.network_access.policyset_conditions", path: "/api/v1/policy/network-access/condition/policyset", objectType: "policy_condition", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.network_access.dictionaries", path: "/api/v1/policy/network-access/dictionaries", objectType: "policy_dictionary", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.network_access.authentication_dictionaries", path: "/api/v1/policy/network-access/dictionaries/authentication", objectType: "policy_dictionary", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.network_access.authorization_dictionaries", path: "/api/v1/policy/network-access/dictionaries/authorization", objectType: "policy_dictionary", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.network_access.policyset_dictionaries", path: "/api/v1/policy/network-access/dictionaries/policyset", objectType: "policy_dictionary", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.network_access.identity_stores", path: "/api/v1/policy/network-access/identity-stores", objectType: "identity_store", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.network_access.network_conditions", path: "/api/v1/policy/network-access/network-condition", objectType: "policy_condition", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.network_access.global_exceptions", path: "/api/v1/policy/network-access/policy-set/global-exception", objectType: "policy_rule", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.network_access.security_groups", path: "/api/v1/policy/network-access/security-groups", objectType: "security_group", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.network_access.service_names", path: "/api/v1/policy/network-access/service-names", objectType: "policy_service", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.network_access.time_conditions", path: "/api/v1/policy/network-access/time-condition", objectType: "policy_condition", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.device_admin", path: "/api/v1/policy/device-admin/policy-set", objectType: "policy_set", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.device_admin.command_sets", path: "/api/v1/policy/device-admin/command-sets", objectType: "tacacs_command_set", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.device_admin.conditions", path: "/api/v1/policy/device-admin/condition", objectType: "policy_condition", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.device_admin.authentication_conditions", path: "/api/v1/policy/device-admin/condition/authentication", objectType: "policy_condition", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.device_admin.authorization_conditions", path: "/api/v1/policy/device-admin/condition/authorization", objectType: "policy_condition", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.device_admin.policyset_conditions", path: "/api/v1/policy/device-admin/condition/policyset", objectType: "policy_condition", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.device_admin.authentication_dictionaries", path: "/api/v1/policy/device-admin/dictionaries/authentication", objectType: "policy_dictionary", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.device_admin.authorization_dictionaries", path: "/api/v1/policy/device-admin/dictionaries/authorization", objectType: "policy_dictionary", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.device_admin.policyset_dictionaries", path: "/api/v1/policy/device-admin/dictionaries/policyset", objectType: "policy_dictionary", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.device_admin.identity_stores", path: "/api/v1/policy/device-admin/identity-stores", objectType: "identity_store", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.device_admin.network_conditions", path: "/api/v1/policy/device-admin/network-condition", objectType: "policy_condition", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.device_admin.global_exceptions", path: "/api/v1/policy/device-admin/policy-set/global-exception", objectType: "policy_rule", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.device_admin.service_names", path: "/api/v1/policy/device-admin/service-names", objectType: "policy_service", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.device_admin.shell_profiles", path: "/api/v1/policy/device-admin/shell-profiles", objectType: "tacacs_profile", mode: iseEndpointList},
		{group: "policy", operation: "openapi.policy.device_admin.time_conditions", path: "/api/v1/policy/device-admin/time-condition", objectType: "policy_condition", mode: iseEndpointList},
		{group: "policy", operation: "openapi.prometheus_alertmanager.receivers", path: "/api/v1/prometheus-alertmanager/receiver", objectType: "alertmanager_receiver", mode: iseEndpointList},
		{group: "policy", operation: "openapi.prometheus_alertmanager.routes", path: "/api/v1/prometheus-alertmanager/route", objectType: "alertmanager_route", mode: iseEndpointList},
		{group: "policy", operation: "openapi.prometheus_alertmanager.rules", path: "/api/v1/prometheus-alertmanager/rule", objectType: "alertmanager_rule", mode: iseEndpointList},
		{group: "policy", operation: "ers.identity_groups", path: "/ers/config/identitygroup", objectType: "identity_group", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.internal_users", path: "/ers/config/internaluser", objectType: "internal_user", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.admin_users", path: "/ers/config/adminuser", objectType: "admin_user", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.authorization_profiles", path: "/ers/config/authorizationprofile", objectType: "authorization_profile", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.downloadable_acls", path: "/ers/config/downloadableacl", objectType: "downloadable_acl", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.allowed_protocols", path: "/ers/config/allowedprotocols", objectType: "allowed_protocol", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.id_store_sequences", path: "/ers/config/idstoresequence", objectType: "id_store_sequence", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.active_directories", path: "/ers/config/activedirectory", objectType: "active_directory", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.ad_resource_reservations", path: "/ers/config/adresourcereservation", objectType: "ad_resource_reservation", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.ldap", path: "/ers/config/ldap", objectType: "ldap_store", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.radius_server_sequences", path: "/ers/config/radiusserversequence", objectType: "radius_server_sequence", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.tacacs_external_servers", path: "/ers/config/tacacsexternalservers", objectType: "tacacs_external_server", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.tacacs_server_sequences", path: "/ers/config/tacacsserversequence", objectType: "tacacs_server_sequence", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.guest_users", path: "/ers/config/guestuser", objectType: "guest_user", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.guest_smtp_notification_settings", path: "/ers/config/guestsmtpnotificationsettings", objectType: "guest_smtp_notification_setting", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.guest_types", path: "/ers/config/guesttype", objectType: "guest_type", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.guest_locations", path: "/ers/config/guestlocation", objectType: "guest_location", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.guest_ssids", path: "/ers/config/guestssid", objectType: "guest_ssid", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.sponsor_portals", path: "/ers/config/sponsorportal", objectType: "sponsor_portal", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.sponsor_groups", path: "/ers/config/sponsorgroup", objectType: "sponsor_group", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.sponsor_group_members", path: "/ers/config/sponsorgroupmember", objectType: "sponsor_group_member", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.byod_portals", path: "/ers/config/byodportal", objectType: "byod_portal", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.hotspot_portals", path: "/ers/config/hotspotportal", objectType: "hotspot_portal", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.my_device_portals", path: "/ers/config/mydeviceportal", objectType: "my_device_portal", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.self_reg_portals", path: "/ers/config/selfregportal", objectType: "self_reg_portal", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.sponsored_guest_portals", path: "/ers/config/sponsoredguestportal", objectType: "sponsored_guest_portal", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.portals", path: "/ers/config/portal", objectType: "portal", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.portal_global_settings", path: "/ers/config/portalglobalsetting", objectType: "portal_setting", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.portal_themes", path: "/ers/config/portaltheme", objectType: "portal_theme", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.sms_providers", path: "/ers/config/smsprovider", objectType: "sms_provider", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.nsp_profiles", path: "/ers/config/nspprofile", objectType: "nsp_profile", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.rest_id_stores", path: "/ers/config/restidstore", objectType: "rest_id_store", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.rest_id_store_settings", path: "/ers/config/restidstoresettings", objectType: "rest_id_store_setting", mode: iseEndpointGet},
		{group: "policy", operation: "ers.tacacs_command_sets", path: "/ers/config/tacacscommandsets", objectType: "tacacs_command_set", mode: iseEndpointERSList},
		{group: "policy", operation: "ers.tacacs_profiles", path: "/ers/config/tacacsprofile", objectType: "tacacs_profile", mode: iseEndpointERSList},
		{group: "posture", operation: "mnt.posture.count", path: "/admin/API/mnt/Session/PostureCount", objectType: "posture", mode: iseEndpointGet},
		{group: "posture", operation: "openapi.exim.posture_export_status", path: "/api/v1/exim/export/posture/current-status", objectType: "posture_export_status", mode: iseEndpointGet},
		{group: "posture", operation: "openapi.exim.posture_import_conditions", path: "/api/v1/exim/import/posture/conditions", objectType: "posture_import_conflict", mode: iseEndpointList},
		{group: "posture", operation: "openapi.exim.posture_import_details", path: "/api/v1/exim/import/posture/details", objectType: "posture_import_detail", mode: iseEndpointGet},
		{group: "posture", operation: "openapi.exim.posture_import_other_conditions", path: "/api/v1/exim/import/posture/othercondition", objectType: "posture_import_conflict", mode: iseEndpointList},
		{group: "posture", operation: "openapi.exim.posture_import_policies", path: "/api/v1/exim/import/posture/policies", objectType: "posture_import_conflict", mode: iseEndpointList},
		{group: "posture", operation: "openapi.exim.posture_import_remediations", path: "/api/v1/exim/import/posture/remediations", objectType: "posture_import_conflict", mode: iseEndpointList},
		{group: "posture", operation: "openapi.exim.posture_import_requirements", path: "/api/v1/exim/import/posture/requirements", objectType: "posture_import_conflict", mode: iseEndpointList},
		{group: "posture", operation: "openapi.exim.posture_import_select_rules", path: "/api/v1/exim/import/posture/selectrules", objectType: "posture_import_rule", mode: iseEndpointList},
		{group: "posture", operation: "openapi.exim.posture_import_status", path: "/api/v1/exim/import/posture/status", objectType: "posture_import_status", mode: iseEndpointGet},
		{group: "posture", operation: "openapi.exim.posture_import_step_status", path: "/api/v1/exim/import/posture/stepstatus", objectType: "posture_import_status", mode: iseEndpointGet},
		{group: "posture", operation: "openapi.exim.posture_import_summary", path: "/api/v1/exim/import/posture/summary", objectType: "posture_import_summary", mode: iseEndpointGet},
		{group: "profiler", operation: "ers.profiler_profiles", path: "/ers/config/profilerprofile", objectType: "profiler_profile", mode: iseEndpointERSList},
		{group: "profiler", operation: "openapi.profiler_policy", path: "/api/v1/profiler/policy", objectType: "profiler_policy", mode: iseEndpointList},
		{group: "profiler", operation: "openapi.profiler.endpoint_custom_dictionary", path: "/api/v1/profiler/endpoint-custom-dictionary", objectType: "profiler_dictionary", mode: iseEndpointList},
		{group: "profiler", operation: "openapi.profiler.endpoint_direct_dictionary", path: "/api/v1/profiler/endpoint-direct-dictionary", objectType: "profiler_dictionary", mode: iseEndpointList},
		{group: "profiler", operation: "openapi.profiler.mfc_values", path: "/api/v1/profiler/policy/mfc-values", objectType: "profiler_value", mode: iseEndpointList},
		{group: "trustsec", operation: "ers.sgt", path: "/ers/config/sgt", objectType: "sgt", mode: iseEndpointERSList},
		{group: "trustsec", operation: "ers.sgacl", path: "/ers/config/sgacl", objectType: "sgacl", mode: iseEndpointERSList},
		{group: "trustsec", operation: "ers.sgmapping", path: "/ers/config/sgmapping", objectType: "sgmapping", mode: iseEndpointERSList},
		{group: "trustsec", operation: "ers.sgmapping_deploy_status", path: "/ers/config/sgmapping/deploy/status", objectType: "sgmapping_deploy_status", mode: iseEndpointGet},
		{group: "trustsec", operation: "ers.sgmapping_groups", path: "/ers/config/sgmappinggroup", objectType: "sgmapping_group", mode: iseEndpointERSList},
		{group: "trustsec", operation: "ers.sgmapping_group_deploy_status", path: "/ers/config/sgmappinggroup/deploy/status", objectType: "sgmapping_deploy_status", mode: iseEndpointGet},
		{group: "trustsec", operation: "ers.sgt_vn_vlans", path: "/ers/config/sgtvnvlan", objectType: "sgt_vn_vlan", mode: iseEndpointERSList},
		{group: "trustsec", operation: "ers.egress_matrix_cells", path: "/ers/config/egressmatrixcell", objectType: "egress_matrix_cell", mode: iseEndpointERSList},
		{group: "trustsec", operation: "ers.filter_policies", path: "/ers/config/filterpolicy", objectType: "filter_policy", mode: iseEndpointERSList},
		{group: "trustsec", operation: "ers.anc_endpoints", path: "/ers/config/ancendpoint", objectType: "anc_endpoint", mode: iseEndpointERSList},
		{group: "trustsec", operation: "ers.anc_policies", path: "/ers/config/ancpolicy", objectType: "anc_policy", mode: iseEndpointERSList},
		{group: "trustsec", operation: "ers.sxp_connections", path: "/ers/config/sxpconnections", objectType: "sxp_connection", mode: iseEndpointERSList},
		{group: "trustsec", operation: "ers.sxp_local_bindings", path: "/ers/config/sxplocalbindings", objectType: "sxp_local_binding", mode: iseEndpointERSList},
		{group: "trustsec", operation: "ers.sxp_vpns", path: "/ers/config/sxpvpns", objectType: "sxp_vpn", mode: iseEndpointERSList},
		{group: "trustsec", operation: "ers.aci_settings", path: "/ers/config/acisettings", objectType: "aci_setting", mode: iseEndpointGet},
		{group: "trustsec", operation: "ers.aci_bindings", path: "/ers/config/acibindings/getall", objectType: "aci_binding", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.general_settings", path: "/api/v1/trustsec/general-settings", objectType: "trustsec_setting", mode: iseEndpointGet},
		{group: "trustsec", operation: "openapi.trustsec.https_servers", path: "/api/v1/trustsec/https-server", objectType: "trustsec_https_server", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.classification_policy", path: "/api/v1/trustsec/classification-policy", objectType: "trustsec_policy", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.classification_dictionaries", path: "/api/v1/trustsec/classification-policy/dictionaries", objectType: "trustsec_dictionary", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.inbound_rule", path: "/api/v1/trustsec/inbound-rule", objectType: "trustsec_policy", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.inbound_dictionaries", path: "/api/v1/trustsec/inbound-rule/dictionaries", objectType: "trustsec_dictionary", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.inbound_mapping_count", path: "/api/v1/trustsec/inbound-rule/previewMappingCount", objectType: "trustsec_mapping_count", mode: iseEndpointGet},
		{group: "trustsec", operation: "openapi.trustsec.aci_connections", path: "/api/v1/trustsec/integration/aci-connection", objectType: "trustsec_aci_connection", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.aci_readiness", path: "/api/v1/trustsec/integration/aci-connection/ise-readiness", objectType: "trustsec_aci_readiness", mode: iseEndpointGet},
		{group: "trustsec", operation: "openapi.trustsec.aci_sgt_ranges", path: "/api/v1/trustsec/integration/aci-connection/sgt-range", objectType: "trustsec_aci_sgt_range", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.aci_status", path: "/api/v1/trustsec/integration/aci-connection/status", objectType: "trustsec_aci_status", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.external_connections", path: "/api/v1/trustsec/integration/external-connection", objectType: "trustsec_external_connection", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.workload_connections", path: "/api/v1/trustsec/integration/workload-connection", objectType: "trustsec_workload_connection", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.workload_attributes", path: "/api/v1/trustsec/integration/workload-connection/attribute", objectType: "trustsec_workload_attribute", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.workload_names", path: "/api/v1/trustsec/integration/workload-connection/names", objectType: "trustsec_workload_name", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.workload_service_status", path: "/api/v1/trustsec/integration/workload-connection/services/status", objectType: "trustsec_workload_status", mode: iseEndpointGet},
		{group: "trustsec", operation: "openapi.trustsec.workload_service_threshold", path: "/api/v1/trustsec/integration/workload-connection/services/threshold", objectType: "trustsec_workload_threshold", mode: iseEndpointGet},
		{group: "trustsec", operation: "openapi.trustsec.matrix", path: "/api/v1/trustsec/matrix", objectType: "trustsec_matrix", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.matrix_workflow_settings", path: "/api/v1/trustsec/matrix-workflow-settings", objectType: "trustsec_setting", mode: iseEndpointGet},
		{group: "trustsec", operation: "openapi.trustsec.matrix_default_policy", path: "/api/v1/trustsec/matrix/defaultPolicy", objectType: "trustsec_matrix_policy", mode: iseEndpointGet},
		{group: "trustsec", operation: "openapi.trustsec.matrix_policies_view", path: "/api/v1/trustsec/matrix/matrixPoliciesView", objectType: "trustsec_matrix_policy", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.outbound_rule", path: "/api/v1/trustsec/outbound-rule", objectType: "trustsec_policy", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.outbound_dictionaries", path: "/api/v1/trustsec/outbound-rule/dictionaries", objectType: "trustsec_dictionary", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.device_report", path: "/api/v1/trustsec/policy/device-report", objectType: "trustsec_device_report", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.sxp_rules", path: "/api/v1/trustsec/rule/all-sxp", objectType: "trustsec_sxp_rule", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.sgt_rules", path: "/api/v1/trustsec/rule/sgt", objectType: "trustsec_sgt_rule", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.sxp_domains", path: "/api/v1/trustsec/rule/sxp-domains", objectType: "trustsec_sxp_domain", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.security_groups", path: "/api/v1/trustsec/security-group", objectType: "sgt", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.nbar_apps", path: "/api/v1/trustsec/sgacl/nbarapp", objectType: "nbar_application", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.shared_mappings", path: "/api/v1/trustsec/shared-mappings", objectType: "trustsec_shared_mapping", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.sxp_domain", path: "/api/v1/trustsec/sxp/domain", objectType: "trustsec_sxp_domain", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.trustsec.virtual_networks", path: "/api/v1/trustsec/virtualnetwork", objectType: "virtual_network", mode: iseEndpointList},
		{group: "trustsec", operation: "openapi.sgt_reservations", path: "/api/v1/sgt/reservation", objectType: "sgt_reservation", mode: iseEndpointList},
		{group: "alarms", operation: "openapi.alarms", path: "/api/v1/alarms", objectType: "alarm", mode: iseEndpointList},
		{group: "alarms", operation: "openapi.alarm_instances", objectType: "alarm_instance", mode: iseEndpointList, pathFunc: iseAlarmInstancesPath},
		{group: "alarms", operation: "openapi.alarm_detail_report_definitions", path: "/api/v1/alarms/details-report/definitions", objectType: "alarm_report_definition", mode: iseEndpointList},
		{group: "alarms", operation: "openapi.alarm_priming_data", path: "/api/v1/alarms/primingData", objectType: "alarm_priming_data", mode: iseEndpointList},
		{group: "alarms", operation: "openapi.alarm_summary", path: "/api/v1/alarms/summary/groupByAlarms", objectType: "alarm_summary", mode: iseEndpointList},
		{group: "certificates", operation: "ers.system_certificates", path: "/ers/config/systemcertificate", objectType: "certificate", mode: iseEndpointERSList},
		{group: "certificates", operation: "ers.certificate_profiles", path: "/ers/config/certificateprofile", objectType: "certificate_profile", mode: iseEndpointERSList},
		{group: "certificates", operation: "ers.certificate_templates", path: "/ers/config/certificatetemplate", objectType: "certificate_template", mode: iseEndpointERSList},
		{group: "certificates", operation: "openapi.certificate_signing_requests", path: "/api/v1/certs/certificate-signing-request", objectType: "certificate_signing_request", mode: iseEndpointList},
		{group: "certificates", operation: "openapi.trusted_certificates", path: "/api/v1/certs/trusted-certificate", objectType: "certificate", mode: iseEndpointList},
		{group: "certificates", operation: "openapi.ipsec.certificates", path: "/api/v1/ipsec/certificates", objectType: "certificate", mode: iseEndpointList},
		{group: "deployment", operation: "openapi.ipsec.nodes", path: "/api/v1/ipsec", objectType: "ipsec_node", mode: iseEndpointList},
		{group: "licensing", operation: "openapi.license.connection_type", path: "/api/v1/license/system/connection-type", objectType: "license", mode: iseEndpointGet},
		{group: "licensing", operation: "openapi.license.eval_license", path: "/api/v1/license/system/eval-license", objectType: "license", mode: iseEndpointGet},
		{group: "licensing", operation: "openapi.license.feature_tier_mapping", path: "/api/v1/license/system/feature-to-tier-mapping", objectType: "license", mode: iseEndpointList},
		{group: "licensing", operation: "openapi.license.miscellaneous", path: "/api/v1/license/system/miscellaneous-license", objectType: "license", mode: iseEndpointGet},
		{group: "licensing", operation: "openapi.license.registration", path: "/api/v1/license/system/register", objectType: "license", mode: iseEndpointGet},
		{group: "licensing", operation: "openapi.license.smart_state", path: "/api/v1/license/system/smart-state", objectType: "license", mode: iseEndpointGet},
		{group: "licensing", operation: "openapi.license.tier_state", path: "/api/v1/license/system/tier-state", objectType: "license", mode: iseEndpointList},
		{group: "webhooks", operation: "openapi.webhooks", path: "/api/v1/webhooks", objectType: "webhook", mode: iseEndpointList},
		{group: "webhooks", operation: "openapi.webhook_alarm_rules", path: "/api/v1/webhooks/alarms", objectType: "webhook_alarm_rule", mode: iseEndpointList},
		{group: "pxgrid", operation: "ers.pxgrid_nodes", path: "/ers/config/pxgridnode", objectType: "pxgrid_node", mode: iseEndpointERSList},
		{group: "pxgrid", operation: "openapi.pxgrid_cloud.activation_url", path: "/api/v1/pxgrid/cloud/activation-url", objectType: "pxgrid_cloud_status", mode: iseEndpointGet},
		{group: "pxgrid", operation: "openapi.pxgrid_cloud.enrollment_info", path: "/api/v1/pxgrid/cloud/enrollment-info", objectType: "pxgrid_cloud_status", mode: iseEndpointGet},
		{group: "pxgrid", operation: "openapi.pxgrid_cloud.regions", path: "/api/v1/pxgrid/cloud/regions", objectType: "pxgrid_cloud_region", mode: iseEndpointList},
		{group: "pxgrid", operation: "openapi.pxgrid_direct.connector_config", path: "/api/v1/pxgrid-direct/connector-config", objectType: "pxgrid_direct_connector", mode: iseEndpointList},
		{group: "pxgrid", operation: "openapi.pxgrid_direct.dictionary_references", path: "/api/v1/pxgrid-direct/dictionary-references", objectType: "pxgrid_direct_dictionary", mode: iseEndpointList},
		{group: "data_connect", operation: "openapi.data_connect.details", path: "/api/v1/mnt/data-connect/details", objectType: "data_connect_status", mode: iseEndpointGet},
		{group: "data_connect", operation: "openapi.data_connect.settings", path: "/api/v1/mnt/data-connect/settings", objectType: "data_connect_status", mode: iseEndpointGet},
	}
}

func iseLogEndpoints() []iseEndpointSpec {
	specs := make([]iseEndpointSpec, 0)
	for _, spec := range iseMetricEndpoints() {
		if iseLogEndpointAllowed(spec.operation) {
			specs = append(specs, spec)
		}
	}
	return specs
}

// iseLogEndpointAllowed is intentionally an allowlist. Metric collection may
// inspect configuration and inventory endpoints, but raw logs are limited to
// operational events and status evidence to avoid exporting sensitive ISE
// configuration. openapi.webhooks is discovery-only; its objects are never
// emitted, only their delivery evidence is.
func iseLogEndpointAllowed(operation string) bool {
	switch operation {
	case "openapi.task_service",
		"ers.support_bundle_status",
		"openapi.backup_restore.last_backup_status",
		"openapi.upgrade.prepare_status",
		"openapi.upgrade.stage_status",
		"openapi.upgrade.proceed_status",
		"openapi.upgrade.summary_status",
		"openapi.patch.prechecks_status",
		"openapi.patch.install_status",
		"openapi.patch.install_summary",
		"openapi.patch.rollback_prechecks_status",
		"openapi.patch.rollback_summary",
		"openapi.patch.rollback_status",
		"ers.rejected_endpoints",
		"mnt.session.active_list",
		"mnt.session.auth_list",
		"openapi.exim.posture_export_status",
		"openapi.exim.posture_import_status",
		"openapi.exim.posture_import_step_status",
		"openapi.exim.posture_import_summary",
		"ers.sgmapping_deploy_status",
		"ers.sgmapping_group_deploy_status",
		"openapi.trustsec.aci_readiness",
		"openapi.trustsec.aci_status",
		"openapi.trustsec.workload_service_status",
		"openapi.alarms",
		"openapi.alarm_instances",
		"openapi.webhooks":
		return true
	default:
		return false
	}
}

func iseAuthSessionsListPath(conf *Config, now time.Time) string {
	lookback := conf.ISE.withDefaults().SessionLookback
	start := now.Add(-lookback).UTC().Format("2006-01-02 15:04:05")
	return "/admin/API/mnt/Session/AuthList/" + start + "/null"
}

func iseAlarmInstancesPath(conf *Config, _ time.Time) string {
	size := iseGroupMaxResults(conf.ISE.withDefaults(), "alarms")
	if size <= 0 || size > 100 {
		size = 100
	}
	return fmt.Sprintf("/api/v1/alarms/instances/1/%d", size)
}

func iseWebhookDeliveriesSpec(webhook ise.Object) (iseEndpointSpec, bool) {
	id := firstNonEmpty(ise.String(webhook, "id", "uuid", "webhookId", "webhook_id"), ise.StableID(webhook))
	id = strings.TrimSpace(id)
	if id == "" || strings.Contains(id, "/") {
		return iseEndpointSpec{}, false
	}
	return iseEndpointSpec{
		group:      "webhooks",
		operation:  "openapi.webhook_deliveries",
		path:       "/api/v1/webhooks/" + id + "/deliveries",
		objectType: "webhook_delivery",
		mode:       iseEndpointList,
	}, true
}

type isePxGridQuery struct {
	operation  string
	path       string
	objectType string
	service    string
	payload    any
}

func isePxGridRESTQueries(cfg ISEConfig, now time.Time) []isePxGridQuery {
	payload := map[string]any{}
	if cfg.EventLookback > 0 {
		payload["startTimestamp"] = now.Add(-cfg.EventLookback).UTC().Format(time.RFC3339Nano)
	}
	queries := []isePxGridQuery{
		{operation: "pxgrid.session.get_sessions", path: "/getSessions", objectType: "pxgrid_session", service: "com.cisco.ise.session", payload: payload},
		{operation: "pxgrid.session.get_user_groups", path: "/getUserGroups", objectType: "pxgrid_user_group", service: "com.cisco.ise.session", payload: payload},
		{operation: "pxgrid.radius.get_failures", path: "/getFailures", objectType: "pxgrid_radius_failure", service: "com.cisco.ise.radius", payload: payload},
		{operation: "pxgrid.system.get_healths", path: "/getHealths", objectType: "pxgrid_system_health", service: "com.cisco.ise.system", payload: payload},
		{operation: "pxgrid.system.get_performances", path: "/getPerformances", objectType: "pxgrid_system_performance", service: "com.cisco.ise.system", payload: payload},
		{operation: "pxgrid.trustsec.get_security_groups", path: "/getSecurityGroups", objectType: "pxgrid_sgt", service: "com.cisco.ise.config.trustsec", payload: payload},
		{operation: "pxgrid.trustsec.get_sgacls", path: "/getSecurityGroupAcls", objectType: "pxgrid_sgacl", service: "com.cisco.ise.config.trustsec", payload: payload},
		{operation: "pxgrid.trustsec.get_egress_policies", path: "/getEgressPolicies", objectType: "pxgrid_egress_policy", service: "com.cisco.ise.config.trustsec", payload: payload},
	}
	if len(cfg.Targets.PxGridServices) == 0 {
		return queries
	}
	allowed := map[string]struct{}{}
	for _, service := range cfg.Targets.PxGridServices {
		allowed[strings.ToLower(strings.TrimSpace(service))] = struct{}{}
	}
	filtered := queries[:0]
	for _, query := range queries {
		if _, ok := allowed[strings.ToLower(query.service)]; ok {
			filtered = append(filtered, query)
		}
	}
	return filtered
}

// isePxGridLogQueries is intentionally narrower than metric polling. Session
// and RADIUS failure records are operational evidence; user-group, TrustSec,
// and system-health responses are configuration or metric snapshots and must
// not be exported as raw logs.
func isePxGridLogQueries(cfg ISEConfig, now time.Time) []isePxGridQuery {
	queries := isePxGridRESTQueries(cfg, now)
	logs := make([]isePxGridQuery, 0, 2)
	for _, query := range queries {
		switch query.operation {
		case "pxgrid.session.get_sessions", "pxgrid.radius.get_failures":
			logs = append(logs, query)
		}
	}
	return logs
}

func isePxGridSubscriptions(subscriptions ISEPxGridSubscriptionConfig) []ise.PxGridSubscription {
	var configured []ise.PxGridSubscription
	if subscriptions.Session {
		configured = append(configured, ise.PxGridSubscription{Service: "com.cisco.ise.session", TopicProperty: "sessionTopic"})
	}
	if subscriptions.RadiusFailures {
		configured = append(configured, ise.PxGridSubscription{Service: "com.cisco.ise.radius", TopicProperty: "failureTopic"})
	}
	if subscriptions.Endpoint {
		configured = append(configured, ise.PxGridSubscription{Service: "com.cisco.ise.endpoint", TopicProperty: "topic"})
	}
	if subscriptions.TrustSec {
		configured = append(configured, ise.PxGridSubscription{
			Service:                  "com.cisco.ise.config.trustsec",
			TopicProperty:            "securityGroupTopic",
			AlternateTopicProperties: []string{"securityGroupAclTopic", "securityGroupVnVlanTopic"},
		})
	}
	return configured
}

func isePxGridSubscriptionLabel(subscription ise.PxGridSubscription) string {
	property := subscription.TopicProperty
	if property == "" {
		property = "unsupported"
	}
	return subscription.Service + "#" + property
}

func iseDataConnectViews(cfg ISEConfig) []ise.DataConnectView {
	configured := map[string]ISEGroupConfig{}
	for name, group := range cfg.DataConnect.Views {
		configured[strings.ToUpper(strings.TrimSpace(name))] = group
	}
	defaults := ise.DefaultDataConnectViews()
	if cfg.DataConnect.FullViews {
		defaults = append(defaults, ise.FullDataConnectViews()...)
	}
	views := make([]ise.DataConnectView, 0, len(defaults)+len(cfg.DataConnect.AdditionalReadOnly))
	seen := map[string]struct{}{}
	addView := func(view ise.DataConnectView) {
		view.Name = strings.ToUpper(strings.TrimSpace(view.Name))
		if view.Name == "" {
			return
		}
		if _, ok := seen[view.Name]; ok {
			return
		}
		seen[view.Name] = struct{}{}
		views = append(views, view)
	}
	for _, view := range defaults {
		group, ok := configured[view.Name]
		if ok && !group.Enabled {
			continue
		}
		if ok && group.MaxResults > 0 {
			view.MaxResults = group.MaxResults
		}
		addView(view)
	}
	for _, view := range cfg.DataConnect.AdditionalReadOnly {
		view = strings.ToUpper(strings.TrimSpace(view))
		if !ise.ValidDataConnectViewName(view) || ise.IsInternalDataConnectView(view) {
			continue
		}
		addView(ise.DataConnectView{Name: view, Category: "additional", MaxResults: cfg.DataConnect.RowLimit})
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Name < views[j].Name })
	return views
}

// iseDataConnectLogViews limits raw logs to time-oriented operational evidence.
// Inventory, policy, identity, profiling, administrator configuration, and
// generic OpenAPI audit rows remain available to metrics but are not emitted
// as log bodies because they may contain sensitive configuration.
func iseDataConnectLogViews(cfg ISEConfig) []ise.DataConnectView {
	views := iseDataConnectViews(cfg)
	logs := make([]ise.DataConnectView, 0, len(views))
	for _, view := range views {
		if iseDataConnectLogViewAllowed(view.Name) {
			logs = append(logs, view)
		}
	}
	return logs
}

func iseDataConnectLogViewAllowed(name string) bool {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "ADMINISTRATOR_LOGINS",
		"RADIUS_AUTHENTICATIONS_WEEK",
		"RADIUS_AUTHENTICATIONS",
		"RADIUS_ACCOUNTING_WEEK",
		"RADIUS_ACCOUNTING",
		"TACACS_AUTHENTICATION_LAST_TWO_DAYS",
		"TACACS_AUTHENTICATION",
		"TACACS_AUTHORIZATION_LAST_TWO_DAYS",
		"TACACS_AUTHORIZATION",
		"TACACS_ACCOUNTING_LAST_TWO_DAYS",
		"TACACS_ACCOUNTING",
		"TACACS_COMMAND_ACCOUNTING",
		"POSTURE_ASSESSMENT_BY_ENDPOINT",
		"ADAPTIVE_NETWORK_CONTROL",
		"THREAT_EVENTS":
		return true
	default:
		return false
	}
}

func iseGroupEnabled(cfg ISEConfig, group string) bool {
	if group == "pxgrid" {
		return cfg.PxGrid.Enabled
	}
	if group == "data_connect" {
		return cfg.DataConnect.Enabled
	}
	groupCfg, ok := cfg.groups()[group]
	return ok && groupCfg.Enabled
}

func iseGroupMaxResults(cfg ISEConfig, group string) int {
	if group == "pxgrid" {
		return cfg.PxGrid.MaxResults
	}
	if group == "data_connect" {
		return cfg.DataConnect.RowLimit
	}
	if groupCfg, ok := cfg.groups()[group]; ok && groupCfg.MaxResults > 0 {
		return groupCfg.MaxResults
	}
	return cfg.MaxResults
}

type iseTargetMatcher struct {
	targets map[string][]string
}

func newISETargetMatcher(targets ISETargetFilters) iseTargetMatcher {
	return iseTargetMatcher{targets: map[string][]string{
		"node":           normalizeTargetValues(targets.NodeNames),
		"network_device": normalizeTargetValues(append(targets.NetworkDeviceNames, targets.NetworkDeviceIPs...)),
		"endpoint":       normalizeTargetValues(targets.EndpointMACs),
		"user":           normalizeTargetValues(targets.Usernames),
		"policy":         normalizeTargetValues(targets.PolicyNames),
		"security_group": normalizeTargetValues(targets.SecurityGroupNames),
		"pxgrid_service": normalizeTargetValues(targets.PxGridServices),
	}}
}

func (m iseTargetMatcher) allows(obj ise.Object) bool {
	text := ise.SearchText(obj)
	hasTargets := false
	for _, values := range m.targets {
		if len(values) == 0 {
			continue
		}
		hasTargets = true
		for _, value := range values {
			if strings.Contains(text, value) {
				return true
			}
		}
	}
	return !hasTargets
}

func normalizeTargetValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func iseObjectIdentity(obj ise.Object) deviceIdentity {
	identity := deviceIdentity{}
	appendISEObjectIdentity(&identity, obj, 0)
	return identity
}

func appendISEObjectIdentity(identity *deviceIdentity, value any, depth int) {
	if depth > 8 {
		return
	}
	var obj ise.Object
	switch typed := value.(type) {
	case ise.Object:
		obj = typed
	case map[string]any:
		obj = ise.Object(typed)
	case []any:
		for _, nested := range typed {
			appendISEObjectIdentity(identity, nested, depth+1)
		}
		return
	case []ise.Object:
		for _, nested := range typed {
			appendISEObjectIdentity(identity, nested, depth+1)
		}
		return
	default:
		return
	}

	identity.hostNames = append(identity.hostNames, ise.String(obj,
		"name", "hostname", "nodeName", "serverName", "network_device_name", "networkDeviceName", "deviceName", "nasIdentifier",
	))
	identity.hostIPs = append(identity.hostIPs, ise.String(obj,
		"ipaddress", "ipAddress", "nas_ip_address", "nasIpAddress", "device_ip_address", "deviceIpAddress", "networkDeviceIp",
	))
	identity.hostIDs = append(identity.hostIDs, ise.StableID(obj))
	identity.serials = append(identity.serials, ise.String(obj, "serial", "serialNumber"))
	identity.deviceIDs = append(identity.deviceIDs, ise.String(obj,
		"id", "uuid", "deviceId", "endpointId", "mac", "macAddress", "calling_station_id", "callingStationId",
	))
	for _, nested := range obj {
		appendISEObjectIdentity(identity, nested, depth+1)
	}
}

func newISEDeviceSelectionMatcher(config *Config) deviceSelectionMatcher {
	if config == nil {
		return newDeviceSelectionMatcher(DeviceSelectionConfig{})
	}
	return newDeviceSelectionMatcher(config.DeviceSelection)
}

func iseObjectSelected(obj ise.Object, targets iseTargetMatcher, selector deviceSelectionMatcher) bool {
	return targets.allows(obj) && selector.allows(iseObjectIdentity(obj))
}

func iseObjectAttrs(spec iseEndpointSpec, obj ise.Object) map[string]string {
	attrs := map[string]string{
		"ise.group":       spec.group,
		"ise.object.type": spec.objectType,
	}
	putIf(attrs, "ise.node.name", ise.String(obj, "nodeName", "node_name", "serverName", "server_name", "hostname"))
	putIf(attrs, "ise.protocol", firstNonEmpty(ise.String(obj, "authentication_protocol", "authenticationProtocol", "protocol"), protocolFromSpec(spec)))
	putIf(attrs, "event.outcome", firstNonEmpty(ise.String(obj, "response", "Response", "outcome", "status"), outcomeFromSpec(spec)))
	putIf(attrs, "ise.failure.reason", ise.String(obj, "failure_reason", "failureReason", "cause"))
	putIf(attrs, "ise.message.code", ise.String(obj, "message_code", "messageCode", "code"))
	putIf(attrs, "ise.policy.set", ise.String(obj, "policy_set_name", "policySetName", "policySet"))
	putIf(attrs, "ise.policy.rule", ise.String(obj, "authorization_rule", "authorizationRule", "ruleName"))
	putIf(attrs, "ise.authorization.profile", ise.String(obj, "authorization_profile", "authorizationProfile", "selectedAznProfiles"))
	putIf(attrs, "ise.network_device.name", ise.String(obj, "network_device_name", "networkDeviceName", "deviceName"))
	putIf(attrs, "ise.network_device.ip", ise.String(obj, "nas_ip_address", "nasIpAddress", "device_ip_address", "ipaddress", "ipAddress"))
	putIf(attrs, "network.peer.address", ise.String(obj, "nas_ip_address", "nasIpAddress", "device_ip_address", "ipaddress", "ipAddress"))
	putIf(attrs, "ise.endpoint.mac", ise.String(obj, "mac", "macAddress", "calling_station_id", "callingStationId"))
	putIf(attrs, "device.mac", ise.String(obj, "mac", "macAddress", "calling_station_id", "callingStationId"))
	putIf(attrs, "user.name", ise.String(obj, "user_name", "userName", "username"))
	putIf(attrs, "event.id", ise.StableID(obj))
	return attrs
}

func iseMetricObjectAttrs(spec iseEndpointSpec, obj ise.Object) map[string]string {
	attrs := iseObjectAttrs(spec, obj)
	for _, key := range []string{
		"event.id",
		"ise.endpoint.mac",
		"device.mac",
		"user.name",
		"ise.network_device.name",
		"ise.network_device.ip",
		"network.peer.address",
	} {
		delete(attrs, key)
	}
	return attrs
}

// iseMetricEvidenceAttrs keeps low-cardinality aggregate dimensions while
// assigning each controller-level evidence row a stable, opaque identity.
// Without this identity, multiple sessions or Data Connect rows can produce
// indistinguishable datapoints with the same resource, metric, attributes, and
// timestamp in a single OTLP batch.
func iseMetricEvidenceAttrs(spec iseEndpointSpec, obj ise.Object, attrs map[string]string) map[string]string {
	if !iseControllerResourceMetricGroup(spec.group) {
		return attrs
	}
	evidenceAttrs := cloneAttrs(attrs)
	stableID := ise.StableID(obj)
	var fallback any
	if stableID == "" {
		fallback = obj
	}
	evidenceAttrs["ise.row.id"] = logDedupKey(
		"ise.metric."+spec.group+"."+spec.operation+"."+spec.objectType,
		stableID,
		fallback,
	)
	return evidenceAttrs
}

func iseObjectStatus(obj ise.Object) string {
	return firstNonEmpty(
		ise.String(obj, "status", "Status"),
		ise.String(obj, "state", "State"),
		ise.String(obj, "enabled", "Enabled"),
		ise.String(obj, "posture_status", "postureStatus"),
		ise.String(obj, "response", "Response"),
		ise.String(obj, "severity", "Severity"),
		ise.String(obj, "smartLicensingStatus"),
	)
}

func protocolFromSpec(spec iseEndpointSpec) string {
	switch {
	case strings.Contains(spec.operation, "tacacs"):
		return "tacacs"
	case strings.Contains(spec.operation, "radius"):
		return "radius"
	default:
		return ""
	}
}

func outcomeFromSpec(spec iseEndpointSpec) string {
	if strings.Contains(spec.operation, "failure") {
		return "failure"
	}
	return ""
}

func attrsKey(attrs map[string]string) string {
	if len(attrs) == 0 {
		return ""
	}
	keys := make([]string, 0, len(attrs))
	for key := range attrs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+attrs[key])
	}
	return strings.Join(parts, ",")
}

func putIf(attrs map[string]string, key, value string) {
	if value != "" {
		attrs[key] = value
	}
}

const iseRedactedLogValue = "[REDACTED]"

func redactISELogObject(obj ise.Object) ise.Object {
	redacted := make(ise.Object, len(obj))
	for key, value := range obj {
		if isSensitiveISELogKey(key) {
			redacted[key] = iseRedactedLogValue
			continue
		}
		redacted[key] = redactISELogValue(value)
	}
	return redacted
}

func redactISELogValue(value any) any {
	switch typed := value.(type) {
	case ise.Object:
		return redactISELogObject(typed)
	case map[string]any:
		return redactISELogObject(ise.Object(typed))
	case map[string]string:
		redacted := make(map[string]string, len(typed))
		for key, nested := range typed {
			if isSensitiveISELogKey(key) {
				redacted[key] = iseRedactedLogValue
			} else {
				redacted[key] = nested
			}
		}
		return redacted
	case []any:
		redacted := make([]any, len(typed))
		for i, nested := range typed {
			redacted[i] = redactISELogValue(nested)
		}
		return redacted
	case []ise.Object:
		redacted := make([]ise.Object, len(typed))
		for i, nested := range typed {
			redacted[i] = redactISELogObject(nested)
		}
		return redacted
	case []map[string]any:
		redacted := make([]ise.Object, len(typed))
		for i, nested := range typed {
			redacted[i] = redactISELogObject(ise.Object(nested))
		}
		return redacted
	default:
		return value
	}
}

func isSensitiveISELogKey(key string) bool {
	return isSensitiveLogKey(key)
}

func mustJSON(obj ise.Object) string {
	data, err := json.Marshal(obj)
	if err != nil {
		return fmt.Sprintf("%v", map[string]any(obj))
	}
	return string(data)
}
