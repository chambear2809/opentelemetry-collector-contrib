// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
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

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/fmc"
)

const fmcScopeName = "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/fmc"

// fmcInstanceID returns a stable identifier for the configured FMC deployment so
// that the global resource's host.id does not collide with other FMC receivers
// in the same Splunk O11y tenant.
func fmcInstanceID(conf *Config) string {
	if conf == nil {
		return ""
	}
	for _, c := range conf.FMC.Controllers {
		if id := firstNonEmpty(c.Name, c.Endpoint); id != "" {
			return id
		}
	}
	return ""
}

// classifyFMCError buckets a client error returned by FMC into a small enum
// suitable for use as a metric attribute. Free-form err.Error() text would blow
// up Splunk O11y MTS cardinality with endpoint paths and request bodies.
func classifyFMCError(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	var apiErr *fmc.APIError
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

type fmcMetricsReceiver struct {
	settings receiver.Settings
	config   *Config
	consumer consumer.Metrics
	clients  []*fmc.Client
	counters *counterStore
	obs      *receiverhelper.ObsReport
	success  scrapeSuccessState

	startMu sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}

	statsMu sync.Mutex
	stats   []fmc.RequestStat
}

type fmcLogsReceiver struct {
	settings receiver.Settings
	config   *Config
	consumer consumer.Logs
	clients  []*fmc.Client
	obs      *receiverhelper.ObsReport

	startMu sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}

	seen *logDeduplicator
}

type fmcEStreamerLogsReceiver struct {
	settings receiver.Settings
	config   *Config
	consumer consumer.Logs
	clients  []*fmc.EStreamerClient
	obs      *receiverhelper.ObsReport

	startMu sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
}

type fmcEndpoint struct {
	group      string
	operation  string
	path       string
	objectType string
	method     string
	query      func(*Config, time.Time) url.Values
}

type fmcScopedEndpoint struct {
	group      string
	operation  string
	path       string
	objectType string
	source     string
	method     string
	query      func(*Config, time.Time, fmc.Object) url.Values
}

type fmcControllerCache struct {
	devices           []fmc.Object
	deployableDevices []fmc.Object
	tunnelStatuses    []fmc.Object
	haPairs           []fmc.Object
	chassis           []fmc.Object
	accessPolicies    []fmc.Object
	natPolicies       []fmc.Object
	prefilterPolicies []fmc.Object
}

func newFMCMetricsReceiver(set receiver.Settings, conf *Config, consumer consumer.Metrics) (*fmcMetricsReceiver, error) {
	clients, err := newFMCClients(conf)
	if err != nil {
		return nil, err
	}
	r := &fmcMetricsReceiver{
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

func newFMCLogsReceiver(set receiver.Settings, conf *Config, consumer consumer.Logs) (*fmcLogsReceiver, error) {
	clients, err := newFMCClients(conf)
	if err != nil {
		return nil, err
	}
	return &fmcLogsReceiver{
		settings: set,
		config:   conf,
		consumer: consumer,
		clients:  clients,
		obs:      newPlatformObsReport(set, "http"),
		done:     make(chan struct{}),
		seen:     newLogDeduplicator(),
	}, nil
}

func newFMCEStreamerLogsReceiver(set receiver.Settings, conf *Config, consumer consumer.Logs) (*fmcEStreamerLogsReceiver, error) {
	clients, err := newFMCEStreamerClients(conf)
	if err != nil {
		return nil, err
	}
	return &fmcEStreamerLogsReceiver{
		settings: set,
		config:   conf,
		consumer: consumer,
		clients:  clients,
		obs:      newPlatformObsReport(set, "tcp"),
		done:     make(chan struct{}),
	}, nil
}

func newFMCClients(conf *Config) ([]*fmc.Client, error) {
	clients := make([]*fmc.Client, 0, len(conf.FMC.Controllers))
	for _, controller := range conf.FMC.Controllers {
		client, err := fmc.NewClient(fmc.Config{
			Endpoint:           controller.Endpoint,
			Name:               controller.Name,
			Username:           conf.FMC.Auth.Username,
			Password:           string(conf.FMC.Auth.Password),
			DomainUUID:         controller.DomainUUID,
			UserAgent:          conf.FMC.UserAgent,
			Timeout:            conf.Timeout,
			MaxRetries:         conf.FMC.MaxRetries,
			PageSize:           conf.FMC.PageSize,
			InsecureSkipVerify: conf.FMC.InsecureSkipVerify,
		})
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	return clients, nil
}

func newFMCEStreamerClients(conf *Config) ([]*fmc.EStreamerClient, error) {
	targets := conf.FMC.EStreamer.Targets
	if len(targets) == 0 {
		for _, controller := range conf.FMC.Controllers {
			endpoint, err := estreamerEndpointFromFMCController(controller.Endpoint)
			if err != nil {
				return nil, err
			}
			targets = append(targets, FMCEStreamerTargetConfig{Endpoint: endpoint, Name: controller.Name})
		}
	}
	tlsConfig, err := loadFMCEStreamerTLS(conf.FMC.EStreamer.TLS)
	if err != nil {
		return nil, err
	}
	lookback := conf.FMC.EStreamer.Lookback
	if lookback <= 0 {
		lookback = defaultFMCConfig().EStreamer.Lookback
	}
	var initialTime time.Time
	if lookback > 0 {
		initialTime = time.Now().Add(-lookback)
	}
	clients := make([]*fmc.EStreamerClient, 0, len(targets))
	for _, target := range targets {
		client, err := fmc.NewEStreamerClient(fmc.EStreamerConfig{
			Address:         target.Endpoint,
			Name:            target.Name,
			TLSConfig:       tlsConfig,
			InitialTime:     initialTime,
			EventTypes:      conf.FMC.EStreamer.EventTypes,
			DialTimeout:     conf.Timeout,
			ReadTimeout:     conf.CollectionInterval * 2,
			MaxMessageBytes: conf.FMC.EStreamer.MaxMessageBytes,
		})
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	return clients, nil
}

func (r *fmcMetricsReceiver) Start(_ context.Context, _ component.Host) error {
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

func (r *fmcMetricsReceiver) Shutdown(ctx context.Context) error {
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

func (r *fmcMetricsReceiver) run(ctx context.Context) {
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

func (r *fmcMetricsReceiver) collect(ctx context.Context) {
	scrapeCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()
	obsCtx := startMetricsOp(ctx, r.obs)
	md, scrapeErr := r.scrape(scrapeCtx)
	if scrapeErr != nil {
		r.settings.Logger.Error("FMC scrape failed", zap.Error(scrapeErr))
	}
	metricCount, consumeErr := consumeMetricsIfPresent(ctx, r.consumer, md)
	if consumeErr != nil {
		r.settings.Logger.Error("FMC metrics consumer failed", zap.Error(consumeErr))
	}
	endMetricsOp(obsCtx, r.obs, metricCount, combineSignalErrors(scrapeErr, consumeErr))
}

func (r *fmcMetricsReceiver) scrape(ctx context.Context) (pmetric.Metrics, error) {
	r.resetRequestStats()
	now := time.Now()
	builder := newFMCMetricsBuilder(now, fmcInstanceID(r.config), r.counters)
	selector := newDeviceSelectionMatcher(r.config.DeviceSelection)
	partial := false

	for _, client := range r.clients {
		controllerRB := builder.controllerResource(client.ControllerName(), client.Endpoint(), "")
		domainUUID, err := client.DomainUUID(ctx)
		if err != nil {
			partial = true
			controllerRB.recordSum("fmc.api.endpoint.error", "FMC endpoint scrape error.", "{error}", 1, map[string]string{
				"fmc.api.operation": "auth.domain_uuid",
				"fmc.error.kind":    classifyFMCError(err),
			})
			continue
		}
		cache := fmcControllerCache{}
		if fmcGroupEnabled(r.config.FMC, "inventory") || fmcGroupEnabled(r.config.FMC, "interfaces") {
			devices, err := r.fetchEndpoint(ctx, client, domainUUID, fmcEndpoint{group: "inventory", operation: "devices.records", path: "devices/devicerecords", objectType: "fmc.device"}, now)
			cache.devices = filterFMCObjects(devices, r.config.FMC.Targets)
			if fmcGroupEnabled(r.config.FMC, "inventory") {
				for _, obj := range cache.devices {
					if !selector.allows(fmcObjectIdentity(obj)) {
						continue
					}
					builder.recordObject(client.ControllerName(), client.Endpoint(), domainUUID, fmcEndpoint{group: "inventory", operation: "devices.records", objectType: "fmc.device"}, obj)
				}
			}
			if err != nil {
				if ctx.Err() != nil {
					return r.finishScrape(builder, now, true), ctx.Err()
				}
				partial = true
				r.recordEndpointError(builder, client, domainUUID, "devices.records", err)
			}
		}

		for _, endpoint := range fmcMetricEndpoints() {
			if !fmcGroupEnabled(r.config.FMC, endpoint.group) {
				continue
			}
			objects, err := r.fetchEndpoint(ctx, client, domainUUID, endpoint, now)
			objects = filterFMCObjects(objects, r.config.FMC.Targets)
			switch endpoint.operation {
			case "deployment.deployable_devices":
				cache.deployableDevices = append(cache.deployableDevices, objects...)
			case "vpn.tunnel_statuses":
				cache.tunnelStatuses = append(cache.tunnelStatuses, objects...)
			case "ha.ftd_pairs":
				cache.haPairs = append(cache.haPairs, objects...)
			case "inventory.chassis":
				cache.chassis = append(cache.chassis, objects...)
			case "policy.access_policies":
				cache.accessPolicies = append(cache.accessPolicies, objects...)
			case "policy.nat_policies":
				cache.natPolicies = append(cache.natPolicies, objects...)
			case "policy.prefilter_policies":
				cache.prefilterPolicies = append(cache.prefilterPolicies, objects...)
			}
			for _, obj := range objects {
				if !selector.allows(fmcObjectIdentity(obj)) {
					continue
				}
				builder.recordObject(client.ControllerName(), client.Endpoint(), domainUUID, endpoint, obj)
			}
			if err != nil {
				if ctx.Err() != nil {
					return r.finishScrape(builder, now, true), ctx.Err()
				}
				partial = true
				r.recordEndpointError(builder, client, domainUUID, endpoint.operation, err)
				continue
			}
		}

		if fmcGroupEnabled(r.config.FMC, "interfaces") {
			for _, device := range cache.devices {
				if !selector.allows(fmcObjectIdentity(device)) {
					continue
				}
				for _, endpoint := range fmcDeviceScopedEndpoints() {
					objects, err := r.fetchScopedEndpoint(ctx, client, domainUUID, endpoint, device, now)
					for _, obj := range filterFMCObjects(objects, r.config.FMC.Targets) {
						inheritFMCDevice(obj, device)
						if !selector.allows(fmcObjectIdentity(obj)) {
							continue
						}
						builder.recordObject(client.ControllerName(), client.Endpoint(), domainUUID, endpoint.asEndpoint(), obj)
					}
					if err != nil {
						if ctx.Err() != nil {
							return r.finishScrape(builder, now, true), ctx.Err()
						}
						partial = true
						r.recordEndpointError(builder, client, domainUUID, endpoint.operation, err)
						continue
					}
				}
			}
			for _, chassis := range cache.chassis {
				if !selector.allows(fmcObjectIdentity(chassis)) {
					continue
				}
				for _, endpoint := range fmcChassisScopedEndpoints() {
					objects, err := r.fetchScopedEndpoint(ctx, client, domainUUID, endpoint, chassis, now)
					for _, obj := range filterFMCObjects(objects, r.config.FMC.Targets) {
						inheritFMCDevice(obj, chassis)
						if !selector.allows(fmcObjectIdentity(obj)) {
							continue
						}
						builder.recordObject(client.ControllerName(), client.Endpoint(), domainUUID, endpoint.asEndpoint(), obj)
					}
					if err != nil {
						if ctx.Err() != nil {
							return r.finishScrape(builder, now, true), ctx.Err()
						}
						partial = true
						r.recordEndpointError(builder, client, domainUUID, endpoint.operation, err)
						continue
					}
				}
			}
		}

		if fmcGroupEnabled(r.config.FMC, "health") {
			for _, device := range cache.devices {
				if !selector.allows(fmcObjectIdentity(device)) {
					continue
				}
				for _, endpoint := range fmcHealthScopedEndpoints() {
					objects, err := r.fetchScopedEndpoint(ctx, client, domainUUID, endpoint, device, now)
					for _, obj := range filterFMCObjects(objects, r.config.FMC.Targets) {
						inheritFMCDevice(obj, device)
						if !selector.allows(fmcObjectIdentity(obj)) {
							continue
						}
						builder.recordObject(client.ControllerName(), client.Endpoint(), domainUUID, endpoint.asEndpoint(), obj)
					}
					if err != nil {
						if ctx.Err() != nil {
							return r.finishScrape(builder, now, true), ctx.Err()
						}
						partial = true
						r.recordEndpointError(builder, client, domainUUID, endpoint.operation, err)
						continue
					}
				}
			}
		}

		if fmcGroupEnabled(r.config.FMC, "vpn") {
			for _, tunnel := range cache.tunnelStatuses {
				for _, endpoint := range fmcVPNTunnelScopedEndpoints() {
					objects, err := r.fetchScopedEndpoint(ctx, client, domainUUID, endpoint, tunnel, now)
					for _, obj := range filterFMCObjects(objects, r.config.FMC.Targets) {
						if !selector.allows(fmcObjectIdentity(obj)) {
							continue
						}
						builder.recordObject(client.ControllerName(), client.Endpoint(), domainUUID, endpoint.asEndpoint(), obj)
					}
					if err != nil {
						if ctx.Err() != nil {
							return r.finishScrape(builder, now, true), ctx.Err()
						}
						partial = true
						r.recordEndpointError(builder, client, domainUUID, endpoint.operation, err)
						continue
					}
				}
			}
		}

		if fmcGroupEnabled(r.config.FMC, "ha") {
			for _, pair := range cache.haPairs {
				for _, endpoint := range fmcHAScopedEndpoints() {
					objects, err := r.fetchScopedEndpoint(ctx, client, domainUUID, endpoint, pair, now)
					for _, obj := range filterFMCObjects(objects, r.config.FMC.Targets) {
						if !selector.allows(fmcObjectIdentity(obj)) {
							continue
						}
						builder.recordObject(client.ControllerName(), client.Endpoint(), domainUUID, endpoint.asEndpoint(), obj)
					}
					if err != nil {
						if ctx.Err() != nil {
							return r.finishScrape(builder, now, true), ctx.Err()
						}
						partial = true
						r.recordEndpointError(builder, client, domainUUID, endpoint.operation, err)
						continue
					}
				}
			}
		}

		if fmcGroupEnabled(r.config.FMC, "policy") {
			for _, scoped := range fmcPolicyScopedEndpoints() {
				for _, policy := range cache.objectsForSource(scoped.source) {
					objects, err := r.fetchScopedEndpoint(ctx, client, domainUUID, scoped, policy, now)
					for _, obj := range filterFMCObjects(objects, r.config.FMC.Targets) {
						inheritFMCPolicy(obj, policy)
						builder.recordObject(client.ControllerName(), client.Endpoint(), domainUUID, scoped.asEndpoint(), obj)
					}
					if err != nil {
						if ctx.Err() != nil {
							return r.finishScrape(builder, now, true), ctx.Err()
						}
						partial = true
						r.recordEndpointError(builder, client, domainUUID, scoped.operation, err)
						continue
					}
				}
			}
		}

		if fmcGroupEnabled(r.config.FMC, "deployments") {
			for _, deployable := range cache.deployableDevices {
				for _, scoped := range fmcDeploymentScopedEndpoints() {
					objects, err := r.fetchScopedEndpoint(ctx, client, domainUUID, scoped, deployable, now)
					for _, obj := range filterFMCObjects(objects, r.config.FMC.Targets) {
						inheritFMCDevice(obj, deployable)
						if !selector.allows(fmcObjectIdentity(obj)) {
							continue
						}
						builder.recordObject(client.ControllerName(), client.Endpoint(), domainUUID, scoped.asEndpoint(), obj)
					}
					if err != nil {
						if ctx.Err() != nil {
							return r.finishScrape(builder, now, true), ctx.Err()
						}
						partial = true
						r.recordEndpointError(builder, client, domainUUID, scoped.operation, err)
						continue
					}
				}
			}
		}
	}
	return r.finishScrape(builder, now, partial), nil
}

func (r *fmcMetricsReceiver) finishScrape(builder *fmcMetricsBuilder, _ time.Time, partial bool) pmetric.Metrics {
	r.statsMu.Lock()
	stats := append([]fmc.RequestStat(nil), r.stats...)
	r.statsMu.Unlock()
	r.recordAPIRequestMetrics(builder)

	for _, client := range r.clients {
		controllerStats := make([]fmc.RequestStat, 0, len(stats))
		for _, stat := range stats {
			if stat.Controller == client.ControllerName() {
				controllerStats = append(controllerStats, stat)
			}
		}
		outcome := summarizeAPIOutcomes(controllerStats, func(stat fmc.RequestStat) string { return stat.Outcome })
		if availability, ok := outcome.availability(); ok {
			builder.controllerResource(client.ControllerName(), client.Endpoint(), "").recordInt("fmc.manager.up", "FMC REST API availability for this scrape.", "1", availability, nil)
		}
	}

	overall := summarizeAPIOutcomes(stats, func(stat fmc.RequestStat) string { return stat.Outcome })
	rb := builder.globalResource()
	rb.recordInt("fmc.scrape.partial_success", "Whether one or more FMC endpoint families failed during the scrape.", "1", boolToInt(partial), nil)
	if lastSuccess, ok := r.success.observe(time.Now(), !partial && overall.succeeded); ok {
		rb.recordInt("fmc.scrape.last_success", "Unix timestamp of the most recent fully successful FMC scrape.", "s", lastSuccess.Unix(), nil)
	}
	builder.flushCounts()
	return builder.emit()
}

func (r *fmcMetricsReceiver) fetchEndpoint(ctx context.Context, client *fmc.Client, domainUUID string, endpoint fmcEndpoint, now time.Time) ([]fmc.Object, error) {
	path := fmcDomainPath(domainUUID, endpoint.path)
	query := fmcEndpointQuery(endpoint, r.config, now)
	if endpoint.method == "POST" {
		return client.PostList(ctx, endpoint.operation, path, query, []byte("{}"), fmcGroupMaxResults(r.config.FMC, endpoint.group))
	}
	return client.List(ctx, endpoint.operation, path, query, fmcGroupMaxResults(r.config.FMC, endpoint.group))
}

func (r *fmcMetricsReceiver) fetchScopedEndpoint(ctx context.Context, client *fmc.Client, domainUUID string, endpoint fmcScopedEndpoint, parent fmc.Object, now time.Time) ([]fmc.Object, error) {
	id := fmc.StableID(parent)
	if id == "" {
		return nil, nil
	}
	path := strings.ReplaceAll(endpoint.path, "{containerUUID}", url.PathEscape(id))
	path = strings.ReplaceAll(path, "{policyUUID}", url.PathEscape(id))
	path = strings.ReplaceAll(path, "{deviceUUID}", url.PathEscape(id))
	path = fmcDomainPath(domainUUID, path)
	query := fmcScopedEndpointQuery(endpoint, r.config, now, parent)
	if endpoint.method == "POST" {
		return client.PostList(ctx, endpoint.operation, path, query, []byte("{}"), fmcGroupMaxResults(r.config.FMC, endpoint.group))
	}
	return client.List(ctx, endpoint.operation, path, query, fmcGroupMaxResults(r.config.FMC, endpoint.group))
}

func (r *fmcLogsReceiver) fetchEndpoint(ctx context.Context, client *fmc.Client, domainUUID string, endpoint fmcEndpoint, now time.Time) ([]fmc.Object, error) {
	path := fmcDomainPath(domainUUID, endpoint.path)
	query := fmcEndpointQuery(endpoint, r.config, now)
	if endpoint.method == "POST" {
		return client.PostList(ctx, endpoint.operation, path, query, []byte("{}"), fmcGroupMaxResults(r.config.FMC, endpoint.group))
	}
	return client.List(ctx, endpoint.operation, path, query, fmcGroupMaxResults(r.config.FMC, endpoint.group))
}

func (r *fmcMetricsReceiver) recordEndpointError(builder *fmcMetricsBuilder, client *fmc.Client, domainUUID, operation string, err error) {
	builder.controllerResource(client.ControllerName(), client.Endpoint(), domainUUID).recordSum("fmc.api.endpoint.error", "FMC endpoint scrape error.", "{error}", 1, map[string]string{
		"fmc.api.operation": operation,
		"fmc.error.kind":    classifyFMCError(err),
	})
	r.settings.Logger.Warn("FMC endpoint failed", zap.String("controller", client.ControllerName()), zap.String("operation", operation), zap.Error(err))
}

func (r *fmcMetricsReceiver) recordRequest(stat fmc.RequestStat) {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats = append(r.stats, stat)
}

func (r *fmcMetricsReceiver) resetRequestStats() {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats = nil
}

func (r *fmcMetricsReceiver) recordAPIRequestMetrics(builder *fmcMetricsBuilder) {
	r.statsMu.Lock()
	stats := append([]fmc.RequestStat(nil), r.stats...)
	r.statsMu.Unlock()
	observations := make([]apiRequestObservation, 0, len(stats))
	for _, stat := range stats {
		attrs := map[string]string{
			"fmc.controller.name": stat.Controller,
			"fmc.api.operation":   stat.Operation,
			"http.request.method": stat.Method,
			"fmc.api.path":        stat.Path,
			"fmc.api.outcome":     stat.Outcome,
		}
		if stat.StatusCode > 0 {
			attrs["http.response.status_code"] = strconv.Itoa(stat.StatusCode)
		}
		observations = append(observations, apiRequestObservation{resource: stat.Controller, attrs: attrs, durationSeconds: stat.Duration.Seconds(), failed: stat.Outcome != "success", rateLimited: stat.RateLimited})
	}
	for _, aggregate := range aggregateAPIRequestObservations(observations) {
		rb := builder.controllerResource(aggregate.resource, "", "")
		rb.recordDouble("fmc.api.request.duration", "Average duration of FMC REST API request attempts in this scrape.", "s", aggregate.averageDurationSeconds, aggregate.attrs)
		if aggregate.errors > 0 {
			rb.recordSum("fmc.api.request.errors", "FMC REST API request errors.", "{error}", aggregate.errors, aggregate.attrs)
		}
		if aggregate.rateLimited > 0 {
			rb.recordSum("fmc.api.rate_limited", "FMC REST API requests that were rate limited.", "{request}", aggregate.rateLimited, aggregate.attrs)
		}
	}
}

func (r *fmcLogsReceiver) Start(_ context.Context, _ component.Host) error {
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

func (r *fmcLogsReceiver) Shutdown(ctx context.Context) error {
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

func (r *fmcLogsReceiver) run(ctx context.Context) {
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

func (r *fmcLogsReceiver) collect(ctx context.Context) {
	scrapeCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()
	r.seen.BeginBatch()
	obsCtx := startLogsOp(ctx, r.obs)
	ld, scrapeErr := r.scrape(scrapeCtx)
	if scrapeErr != nil {
		r.settings.Logger.Error("FMC log scrape failed", zap.Error(scrapeErr))
	}
	logCount, consumeErr := consumeDeduplicatedLogs(ctx, r.consumer, r.seen, ld)
	if consumeErr != nil {
		r.settings.Logger.Error("FMC logs consumer failed", zap.Error(consumeErr))
	}
	endLogsOp(obsCtx, r.obs, logCount, combineSignalErrors(scrapeErr, consumeErr))
}

func (r *fmcLogsReceiver) scrape(ctx context.Context) (plog.Logs, error) {
	ld := plog.NewLogs()
	now := time.Now()
	var endpointErrors []error
	selector := newDeviceSelectionMatcher(r.config.DeviceSelection)
	for _, client := range r.clients {
		domainUUID, err := client.DomainUUID(ctx)
		if err != nil {
			r.settings.Logger.Warn("FMC log auth failed", zap.String("controller", client.ControllerName()), zap.Error(err))
			endpointErrors = append(endpointErrors, fmt.Errorf("FMC %s authentication: %w", client.ControllerName(), err))
			continue
		}
		for _, endpoint := range fmcLogEndpoints() {
			if !fmcGroupEnabled(r.config.FMC, endpoint.group) {
				continue
			}
			objects, err := r.fetchEndpoint(ctx, client, domainUUID, endpoint, now)
			for _, obj := range filterFMCObjects(objects, r.config.FMC.Targets) {
				if !selector.allows(fmcObjectIdentity(obj)) {
					continue
				}
				if r.seenBefore(client.ControllerName(), endpoint, obj, now) {
					continue
				}
				appendFMCLog(ld, client.ControllerName(), client.Endpoint(), domainUUID, endpoint, obj, now)
			}
			if err != nil {
				if ctx.Err() != nil {
					return ld, ctx.Err()
				}
				r.settings.Logger.Warn("FMC log endpoint failed", zap.String("controller", client.ControllerName()), zap.String("operation", endpoint.operation), zap.Error(err))
				endpointErrors = append(endpointErrors, fmt.Errorf("FMC %s %s: %w", client.ControllerName(), endpoint.operation, err))
				continue
			}
		}
	}
	r.expireSeen(now)
	return ld, errors.Join(endpointErrors...)
}

func (r *fmcLogsReceiver) seenBefore(controller string, endpoint fmcEndpoint, obj fmc.Object, now time.Time) bool {
	key := logDedupKey(controller+":"+endpoint.operation, fmc.StableID(obj), obj)
	return !r.seen.MarkPending(key, now)
}

func (r *fmcLogsReceiver) expireSeen(now time.Time) {
	ttl := r.config.FMC.EventLookback
	if ttl <= 0 {
		ttl = defaultFMCConfig().EventLookback
	}
	ttl *= 2
	r.seen.Expire(now.Add(-ttl), 0)
}

func (r *fmcEStreamerLogsReceiver) Start(_ context.Context, _ component.Host) error {
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

func (r *fmcEStreamerLogsReceiver) Shutdown(ctx context.Context) error {
	r.startMu.Lock()
	cancel := r.cancel
	r.startMu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *fmcEStreamerLogsReceiver) run(ctx context.Context) {
	defer close(r.done)
	var wg sync.WaitGroup
	for _, client := range r.clients {
		client.OnStat = func(stat fmc.EStreamerStat) {
			if stat.Err != nil {
				r.settings.Logger.Warn("FMC eStreamer event", zap.String("controller", stat.Controller), zap.String("outcome", stat.Outcome), zap.Error(stat.Err))
			} else {
				r.settings.Logger.Debug("FMC eStreamer event", zap.String("controller", stat.Controller), zap.String("outcome", stat.Outcome), zap.Int("events", stat.Events), zap.Int("bytes", stat.Bytes))
			}
		}
		wg.Go(func() {
			r.runEStreamerClient(ctx, client)
		})
	}
	wg.Wait()
}

// fmcEStreamerBackoffSchedule caps how aggressively eStreamer reconnects after
// repeated failures so that a wedged consumer or auth error cannot trigger a
// tight reconnect loop.
var fmcEStreamerBackoffSchedule = []time.Duration{
	1 * time.Second,
	5 * time.Second,
	15 * time.Second,
	30 * time.Second,
}

const (
	// The protocol request cursor has one-second resolution. Replaying one full
	// second before the newest delivered event avoids losing events that share a
	// cursor second or are returned by a server with exclusive cursor semantics.
	fmcEStreamerResumeOverlap = time.Second

	// The replay set is intentionally in-memory and bounded. Collector restarts
	// can therefore replay the configured startup lookback (at-least-once), but a
	// reconnect in the same process suppresses events already accepted downstream.
	fmcEStreamerSeenLimit          = 100_000
	fmcEStreamerSeenPruneThreshold = 110_000
)

type fmcEStreamerSeenEvent struct {
	eventTime time.Time
	seenAt    time.Time
}

type fmcEStreamerResumeState struct {
	initialTime time.Time
	cursor      time.Time
	seen        map[string]fmcEStreamerSeenEvent
}

func newFMCEStreamerResumeState(initialTime time.Time) *fmcEStreamerResumeState {
	return &fmcEStreamerResumeState{
		initialTime: initialTime,
		seen:        make(map[string]fmcEStreamerSeenEvent),
	}
}

func (s *fmcEStreamerResumeState) requestStart() time.Time {
	if s.cursor.IsZero() {
		return s.initialTime
	}
	resume := s.cursor.UTC().Truncate(time.Second).Add(-fmcEStreamerResumeOverlap)
	if s.initialTime.IsZero() || resume.After(s.initialTime) {
		return resume
	}
	return s.initialTime
}

func (s *fmcEStreamerResumeState) seenBefore(key string) bool {
	_, ok := s.seen[key]
	return ok
}

func (s *fmcEStreamerResumeState) commit(key string, eventTime, seenAt time.Time) {
	s.seen[key] = fmcEStreamerSeenEvent{eventTime: eventTime, seenAt: seenAt}
	if eventTime.After(s.cursor) {
		s.cursor = eventTime.UTC()
	}
	if len(s.seen) >= fmcEStreamerSeenPruneThreshold {
		s.prune()
	}
}

func (s *fmcEStreamerResumeState) prune() {
	cutoff := s.requestStart()
	if !cutoff.IsZero() {
		for key, item := range s.seen {
			if !item.eventTime.IsZero() && item.eventTime.Before(cutoff) {
				delete(s.seen, key)
			}
		}
	}
	if len(s.seen) <= fmcEStreamerSeenLimit {
		return
	}
	type seenEntry struct {
		key    string
		seenAt time.Time
	}
	entries := make([]seenEntry, 0, len(s.seen))
	for key, item := range s.seen {
		entries = append(entries, seenEntry{key: key, seenAt: item.seenAt})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].seenAt.Before(entries[j].seenAt)
	})
	for _, entry := range entries[:len(entries)-fmcEStreamerSeenLimit] {
		delete(s.seen, entry.key)
	}
}

func fmcEStreamerEventKey(event fmc.EStreamerEvent) string {
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "%d\x00%s\x00", event.RecordType, event.EventType)
	if id := fmc.StableID(event.Body); id != "" {
		_, _ = hash.Write([]byte("id:\x00"))
		_, _ = hash.Write([]byte(id))
		return fmt.Sprintf("sha256:%x", hash.Sum(nil))
	}
	_, _ = fmt.Fprintf(hash, "timestamp:\x00%d\x00payload:\x00", event.Timestamp.UnixNano())
	payload := []byte(event.Raw)
	if len(payload) == 0 {
		payload, _ = json.Marshal(event.Body)
	}
	_, _ = hash.Write(payload)
	return fmt.Sprintf("sha256:%x", hash.Sum(nil))
}

func (r *fmcEStreamerLogsReceiver) runEStreamerClient(ctx context.Context, client *fmc.EStreamerClient) {
	reconnect := r.config.FMC.EStreamer.ReconnectInterval
	if reconnect <= 0 {
		reconnect = defaultFMCConfig().EStreamer.ReconnectInterval
	}
	resume := newFMCEStreamerResumeState(client.InitialTime())
	failures := 0
	for {
		err := client.RunFrom(ctx, resume.requestStart(), func(event fmc.EStreamerEvent) error {
			return r.consumeEStreamerEvent(ctx, client, resume, event)
		})
		if ctx.Err() != nil {
			return
		}
		failures++
		r.settings.Logger.Warn("FMC eStreamer disconnected",
			zap.String("controller", client.ControllerName()),
			zap.Int("consecutive_failures", failures),
			zap.Error(err))
		wait := reconnect
		if failures-1 < len(fmcEStreamerBackoffSchedule) {
			if backoff := fmcEStreamerBackoffSchedule[failures-1]; backoff > wait {
				wait = backoff
			}
		} else if backoff := fmcEStreamerBackoffSchedule[len(fmcEStreamerBackoffSchedule)-1]; backoff > wait {
			wait = backoff
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (r *fmcEStreamerLogsReceiver) consumeEStreamerEvent(ctx context.Context, client *fmc.EStreamerClient, resume *fmcEStreamerResumeState, event fmc.EStreamerEvent) error {
	key := fmcEStreamerEventKey(event)
	if resume.seenBefore(key) {
		return nil
	}
	now := time.Now()
	ld := plog.NewLogs()
	appendFMCEStreamerLog(ld, client.ControllerName(), client.Address(), event, now)
	if ld.LogRecordCount() > 0 {
		obsCtx := startLogsOp(ctx, r.obs)
		logCount := ld.LogRecordCount()
		consumeErr := r.consumer.ConsumeLogs(ctx, ld)
		endLogsOp(obsCtx, r.obs, logCount, consumeErr)
		if consumeErr != nil {
			return consumeErr
		}
	}
	// Commit only after the next consumer accepts the event. A failed consume is
	// retried from the previous cursor; after a successful consume, the overlap
	// may replay it from FMC but this in-memory fingerprint suppresses re-export.
	resume.commit(key, event.Timestamp, now)
	return nil
}

type fmcMetricsBuilder struct {
	metrics   pmetric.Metrics
	now       pcommon.Timestamp
	start     pcommon.Timestamp
	instance  string
	resources map[string]*resourceMetricsBuilder
	counts    map[string]*fmcCount
	counters  *counterStore
}

type fmcCount struct {
	value int64
	attrs map[string]string
}

func newFMCMetricsBuilder(now time.Time, instance string, counters *counterStore) *fmcMetricsBuilder {
	if counters == nil {
		counters = newCounterStore()
	}
	ts := pcommon.NewTimestampFromTime(now)
	return &fmcMetricsBuilder{
		metrics:   pmetric.NewMetrics(),
		now:       ts,
		start:     pcommon.NewTimestampFromTime(counters.StartTime()),
		instance:  instance,
		resources: map[string]*resourceMetricsBuilder{},
		counts:    map[string]*fmcCount{},
		counters:  counters,
	}
}

func (b *fmcMetricsBuilder) emit() pmetric.Metrics {
	return b.metrics
}

func (b *fmcMetricsBuilder) globalResource() *resourceMetricsBuilder {
	rb := b.resource("fmc")
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", "fmc:"+firstNonEmpty(b.instance, "default"))
	putStr(attrs, "host.name", "Cisco Secure Firewall Management Center")
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Cisco Secure Firewall Management Center")
	putStr(attrs, "cisco.controller.type", "fmc")
	return rb
}

func (b *fmcMetricsBuilder) controllerResource(name, endpoint, domainUUID string) *resourceMetricsBuilder {
	rb := b.resource("controller:" + name)
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", "fmc:"+name)
	putStr(attrs, "host.name", name)
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Cisco Secure Firewall Management Center")
	putStr(attrs, "cisco.controller.type", "fmc")
	putStr(attrs, "cisco.controller.endpoint", endpoint)
	putStr(attrs, "fmc.controller.name", name)
	putStr(attrs, "fmc.domain.uuid", domainUUID)
	return rb
}

func (b *fmcMetricsBuilder) objectResource(controllerName, controllerEndpoint, domainUUID string, endpoint fmcEndpoint, obj fmc.Object) *resourceMetricsBuilder {
	hostID := firstNonEmpty(fmc.String(obj, "serialNumber", "serial"), fmc.StableID(obj), fmc.String(obj, "name"))
	rb := b.resource(controllerName + ":" + endpoint.operation + ":" + hostID)
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", hostID)
	putStr(attrs, "host.name", firstNonEmpty(fmc.String(obj, "name", "hostName", "displayName"), hostID))
	putIPAttrs(attrs, "host.ip", fmc.String(obj, "managementIpAddress"), fmc.String(obj, "managementIP"), fmc.String(obj, "mgmtIp"), fmc.String(obj, "ipAddress"), fmc.String(obj, "ip"))
	putStr(attrs, "host.type", firstNonEmpty(fmc.String(obj, "model", "deviceType", "type"), endpoint.objectType))
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Cisco Secure Firewall")
	putStr(attrs, "os.version", fmc.String(obj, "softwareVersion", "sw_version", "version"))
	putStr(attrs, "cisco.controller.type", "fmc")
	putStr(attrs, "cisco.controller.endpoint", controllerEndpoint)
	putStr(attrs, "fmc.controller.name", controllerName)
	putStr(attrs, "fmc.domain.uuid", domainUUID)
	putStr(attrs, "fmc.object.id", fmc.StableID(obj))
	putStr(attrs, "fmc.resource.type", endpoint.objectType)
	putStr(attrs, "fmc.group", endpoint.group)
	putStr(attrs, "fmc.policy.id", firstNonEmpty(fmc.String(obj, "policyId"), fmc.String(obj, "parent.policy.id")))
	putStr(attrs, "fmc.policy.name", firstNonEmpty(fmc.String(obj, "policyName"), fmc.String(obj, "parent.policy.name")))
	putStr(attrs, "network.interface.name", fmc.String(obj, "name", "ifname", "interfaceName"))
	putStr(attrs, "cisco.device.serial", fmc.String(obj, "serialNumber", "serial", "parent.device.serial"))
	return rb
}

func (b *fmcMetricsBuilder) resource(key string) *resourceMetricsBuilder {
	if rb := b.resources[key]; rb != nil {
		return rb
	}
	rm := b.metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName(fmcScopeName)
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

func (b *fmcMetricsBuilder) recordObject(controllerName, controllerEndpoint, domainUUID string, endpoint fmcEndpoint, obj fmc.Object) {
	rb := b.objectResource(controllerName, controllerEndpoint, domainUUID, endpoint, obj)
	status := fmcObjectStatus(obj)
	severity := strings.ToLower(firstNonEmpty(fmc.String(obj, "severity", "eventSeverity", "healthStatus"), status))
	attrs := compactAttrs(map[string]string{
		"fmc.group":         endpoint.group,
		"fmc.operation":     endpoint.operation,
		"fmc.resource.type": endpoint.objectType,
		"fmc.status":        firstNonEmpty(status, "present"),
		"fmc.severity":      firstNonEmpty(severity, "unknown"),
	})
	rb.recordInt("fmc.resource.info", "FMC managed object metadata.", "1", 1, attrs)
	if code, ok := statusCode(status); ok {
		rb.recordInt("fmc.resource.status", "FMC managed object status encoded for troubleshooting.", "1", code, attrs)
	}
	b.addCount("fmc.resource.count", attrs)

	switch endpoint.group {
	case "inventory":
		if up, ok := upStatus(status); ok {
			rb.recordInt("cisco.device.up", "FMC-managed firewall availability reported by FMC.", "1", up, nil)
		}
	case "interfaces":
		recordControllerStringState(rb, "system.network.interface.status", "FMC-managed firewall interface status.", status, "fmc.interface.status", interfaceAttrs(fmc.String(obj, "name", "ifname", "interfaceName"), fmc.String(obj, "macAddress", "mac"), fmc.String(obj, "description", "descr"), fmc.String(obj, "speed")))
	case "health":
		recordControllerStringState(rb, "fmc.health.status", "FMC health, alert, and module status.", status, "fmc.health.status", attrs)
		b.addCount("fmc.health.event.count", attrs)
	case "vpn":
		recordControllerStringState(rb, "fmc.vpn.tunnel.status", "Secure Firewall VPN tunnel or remote-access gateway status.", status, "fmc.vpn.status", attrs)
	case "ha":
		recordControllerStringState(rb, "fmc.ha.status", "FMC or managed firewall HA/failover status.", status, "fmc.ha.status", attrs)
	case "policy":
		b.addCount("fmc.policy.object.count", attrs)
	case "deployments":
		recordControllerStringState(rb, "fmc.deployment.status", "FMC deployment job, deployable device, or pending-change status.", status, "fmc.deployment.status", attrs)
		b.addCount("fmc.deployment.pending.count", attrs)
	case "audit":
		b.addCount("fmc.audit.record.count", attrs)
	}
}

func (b *fmcMetricsBuilder) addCount(name string, attrs map[string]string) {
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
	b.counts[key] = &fmcCount{value: 1, attrs: attrs}
}

func (b *fmcMetricsBuilder) flushCounts() {
	rb := b.globalResource()
	keys := make([]string, 0, len(b.counts))
	for key := range b.counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		count := b.counts[key]
		metricName, _, _ := strings.Cut(key, "|")
		rb.recordInt(metricName, fmcCountDescription(metricName), "1", count.value, count.attrs)
	}
}

func appendFMCLog(ld plog.Logs, controllerName, controllerEndpoint, domainUUID string, endpoint fmcEndpoint, obj fmc.Object, now time.Time) {
	rl := ld.ResourceLogs().AppendEmpty()
	attrs := rl.Resource().Attributes()
	putStr(attrs, "host.id", firstNonEmpty(fmc.String(obj, "serialNumber", "serial"), fmc.StableID(obj), controllerName))
	putStr(attrs, "host.name", firstNonEmpty(fmc.String(obj, "name", "hostName", "displayName"), controllerName))
	putIPAttrs(attrs, "host.ip", fmc.String(obj, "managementIpAddress"), fmc.String(obj, "managementIP"), fmc.String(obj, "mgmtIp"), fmc.String(obj, "ipAddress"), fmc.String(obj, "ip"))
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Cisco Secure Firewall")
	putStr(attrs, "cisco.controller.type", "fmc")
	putStr(attrs, "cisco.controller.endpoint", controllerEndpoint)
	putStr(attrs, "fmc.controller.name", controllerName)
	putStr(attrs, "fmc.domain.uuid", domainUUID)
	putStr(attrs, "fmc.object.id", fmc.StableID(obj))
	putStr(attrs, "fmc.resource.type", endpoint.objectType)

	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName(fmcScopeName)
	record := sl.LogRecords().AppendEmpty()
	record.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	if ts, ok := fmcLogTimestamp(obj); ok {
		if timestamp, valid := pdataTimestampFromTime(ts); valid {
			record.SetTimestamp(timestamp)
		}
	}
	severity := firstNonEmpty(fmc.String(obj, "severity", "eventSeverity", "healthStatus"), fmcObjectStatus(obj))
	record.SetSeverityText(severity)
	record.SetSeverityNumber(logSeverityNumber(severity))
	record.Body().SetEmptyMap()
	body := record.Body().Map()
	for key, value := range obj {
		setLogValue(body, key, value)
	}
	logAttrs := record.Attributes()
	putStr(logAttrs, "event.domain", "fmc")
	putStr(logAttrs, "event.name", endpoint.operation)
	putStr(logAttrs, "fmc.operation", endpoint.operation)
	putStr(logAttrs, "fmc.group", endpoint.group)
	putStr(logAttrs, "fmc.status", fmcObjectStatus(obj))
	putStr(logAttrs, "fmc.severity", strings.ToLower(severity))
	putStr(logAttrs, "user.name", fmc.String(obj, "user", "userName", "username", "initiatorName"))
}

func appendFMCEStreamerLog(ld plog.Logs, controllerName, address string, event fmc.EStreamerEvent, now time.Time) {
	rl := ld.ResourceLogs().AppendEmpty()
	attrs := rl.Resource().Attributes()
	putStr(attrs, "host.id", firstNonEmpty(fmc.String(event.Body, "SensorId", "sensorId", "DeviceUUID", "deviceUUID"), controllerName))
	putStr(attrs, "host.name", firstNonEmpty(fmc.String(event.Body, "SensorName", "sensorName", "DeviceName", "deviceName"), controllerName))
	putIPAttrs(attrs, "host.ip", fmc.String(event.Body, "InitiatorIP"), fmc.String(event.Body, "initiatorIp"), fmc.String(event.Body, "SensorIP"), fmc.String(event.Body, "sensorIp"))
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Cisco Secure Firewall")
	putStr(attrs, "cisco.controller.type", "fmc")
	putStr(attrs, "fmc.controller.name", controllerName)
	putStr(attrs, "fmc.estreamer.address", address)

	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName(fmcScopeName)
	record := sl.LogRecords().AppendEmpty()
	record.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	if !event.Timestamp.IsZero() {
		if timestamp, valid := pdataTimestampFromTime(event.Timestamp); valid {
			record.SetTimestamp(timestamp)
		}
	}
	severity := fmc.String(event.Body, "Severity", "severity", "Impact", "impact")
	record.SetSeverityText(severity)
	record.SetSeverityNumber(logSeverityNumber(severity))
	record.Body().SetEmptyMap()
	body := record.Body().Map()
	if len(event.Body) > 0 {
		for key, value := range event.Body {
			setLogValue(body, key, value)
		}
	} else {
		body.PutStr("message", event.Raw)
	}
	logAttrs := record.Attributes()
	putStr(logAttrs, "event.domain", "fmc.estreamer")
	putStr(logAttrs, "event.name", event.EventType)
	putStr(logAttrs, "fmc.estreamer.event.type", event.EventType)
	putStr(logAttrs, "fmc.estreamer.record.type", strconv.FormatUint(uint64(event.RecordType), 10))
	putStr(logAttrs, "source.address", fmc.String(event.Body, "InitiatorIP", "initiatorIp", "SrcIP", "srcIp"))
	putStr(logAttrs, "destination.address", fmc.String(event.Body, "ResponderIP", "responderIp", "DstIP", "dstIp"))
}

func fmcMetricEndpoints() []fmcEndpoint {
	return []fmcEndpoint{
		{group: "manager", operation: "manager.domains", path: "/api/fmc_platform/v1/info/domain", objectType: "fmc.domain"},
		{group: "manager", operation: "manager.server_versions", path: "/api/fmc_platform/v1/info/serverversion", objectType: "fmc.server_version"},
		{group: "manager", operation: "manager.device_licenses", path: "/api/fmc_platform/v1/license/devicelicenses", objectType: "fmc.device_license"},
		{group: "manager", operation: "manager.smart_licenses", path: "/api/fmc_platform/v1/license/smartlicenses", objectType: "fmc.smart_license"},
		{group: "manager", operation: "manager.upgrade_packages", path: "/api/fmc_platform/v1/updates/upgradepackages", objectType: "fmc.upgrade_package"},
		{group: "inventory", operation: "inventory.device_groups", path: "devicegroups/devicegrouprecords", objectType: "fmc.device_group"},
		{group: "inventory", operation: "inventory.chassis", path: "chassis/fmcmanagedchassis", objectType: "fmc.chassis"},
		{group: "health", operation: "health.alerts", path: "health/alerts", objectType: "fmc.health_alert", query: recentFMCQuery},
		{group: "health", operation: "health.events", path: "health/events", objectType: "fmc.health_event", query: recentFMCQuery},
		{group: "health", operation: "health.path_monitored_interfaces", path: "health/pathmonitoredinterfaces", objectType: "fmc.path_monitored_interface"},
		{group: "vpn", operation: "vpn.tunnel_statuses", path: "health/tunnelstatuses", objectType: "fmc.vpn_tunnel"},
		{group: "vpn", operation: "vpn.tunnel_summaries", path: "health/tunnelsummaries", objectType: "fmc.vpn_summary"},
		{group: "vpn", operation: "vpn.ra_gateways", path: "health/ravpngateways", objectType: "fmc.ra_vpn_gateway"},
		{group: "vpn", operation: "vpn.s2s_policies", path: "policy/ftds2svpns", objectType: "fmc.s2s_vpn_policy"},
		{group: "vpn", operation: "vpn.ra_policies", path: "policy/ravpns", objectType: "fmc.ra_vpn_policy"},
		{group: "vpn", operation: "vpn.s2s_summaries", path: "policy/s2svpnsummaries", objectType: "fmc.s2s_vpn_policy_summary"},
		{group: "ha", operation: "ha.fmc_statuses", path: "integration/fmchastatuses", objectType: "fmc.ha_status"},
		{group: "ha", operation: "ha.ftd_pairs", path: "devicehapairs/ftddevicehapairs", objectType: "fmc.ftd_ha_pair"},
		{group: "ha", operation: "ha.ftd_clusters", path: "deviceclusters/ftddevicecluster", objectType: "fmc.ftd_cluster"},
		{group: "policy", operation: "policy.assignments", path: "assignment/policyassignments", objectType: "fmc.policy_assignment"},
		{group: "policy", operation: "policy.access_policies", path: "policy/accesspolicies", objectType: "fmc.access_policy"},
		{group: "policy", operation: "policy.prefilter_policies", path: "policy/prefilterpolicies", objectType: "fmc.prefilter_policy"},
		{group: "policy", operation: "policy.nat_policies", path: "policy/ftdnatpolicies", objectType: "fmc.nat_policy"},
		{group: "policy", operation: "policy.intrusion_policies", path: "policy/intrusionpolicies", objectType: "fmc.intrusion_policy"},
		{group: "policy", operation: "policy.file_policies", path: "policy/filepolicies", objectType: "fmc.file_policy"},
		{group: "policy", operation: "policy.dns_policies", path: "policy/dnspolicies", objectType: "fmc.dns_policy"},
		{group: "policy", operation: "policy.ssl_policies", path: "policy/decryptionpolicies", objectType: "fmc.ssl_policy"},
		{group: "policy", operation: "policy.health_policies", path: "policy/healthpolicies", objectType: "fmc.health_policy"},
		{group: "policy", operation: "policy.platform_settings", path: "policy/ftdplatformsettingspolicies", objectType: "fmc.platform_settings_policy"},
		{group: "policy", operation: "policy.security_intelligence", path: "policy/securityintelligencepolicies", objectType: "fmc.security_intelligence_policy"},
		{group: "policy", operation: "policy.syslog_alerts", path: "policy/syslogalerts", objectType: "fmc.syslog_alert"},
		{group: "policy", operation: "objects.security_zones", path: "object/securityzones", objectType: "fmc.security_zone"},
		{group: "policy", operation: "objects.networks", path: "object/networks", objectType: "fmc.network_object"},
		{group: "policy", operation: "objects.network_groups", path: "object/networkgroups", objectType: "fmc.network_group"},
		{group: "policy", operation: "objects.hosts", path: "object/hosts", objectType: "fmc.host_object"},
		{group: "policy", operation: "objects.port_objects", path: "object/protocolportobjects", objectType: "fmc.port_object"},
		{group: "policy", operation: "objects.port_groups", path: "object/portobjectgroups", objectType: "fmc.port_group"},
		{group: "policy", operation: "objects.applications", path: "object/applications", objectType: "fmc.application"},
		{group: "policy", operation: "objects.security_group_tags", path: "object/securitygrouptags", objectType: "fmc.security_group_tag"},
		{group: "policy", operation: "objects.security_intelligence_network_lists", path: "object/sinetworklists", objectType: "fmc.si_network_list"},
		{group: "policy", operation: "objects.security_intelligence_network_feeds", path: "object/sinetworkfeeds", objectType: "fmc.si_network_feed"},
		{group: "policy", operation: "objects.security_intelligence_url_lists", path: "object/siurllists", objectType: "fmc.si_url_list"},
		{group: "policy", operation: "objects.security_intelligence_url_feeds", path: "object/siurlfeeds", objectType: "fmc.si_url_feed"},
		{group: "policy", operation: "objects.custom_security_intelligence_network_lists", path: "object/customsiiplists", objectType: "fmc.custom_si_network_list"},
		{group: "policy", operation: "objects.custom_security_intelligence_url_lists", path: "object/customsiurllists", objectType: "fmc.custom_si_url_list"},
		{group: "deployments", operation: "deployment.deployable_devices", path: "deployment/deployabledevices", objectType: "fmc.deployable_device"},
		{group: "deployments", operation: "deployment.job_histories", path: "deployment/jobhistories", objectType: "fmc.deployment_job", query: recentFMCQuery},
		{group: "audit", operation: "audit.records", path: "/api/fmc_platform/v1/domain/{domainUUID}/audit/auditrecords", objectType: "fmc.audit_record"},
		{group: "audit", operation: "audit.config_changes", path: "/api/fmc_platform/v1/domain/{domainUUID}/audit/configchanges", objectType: "fmc.config_change"},
	}
}

func fmcLogEndpoints() []fmcEndpoint {
	return []fmcEndpoint{
		{group: "health", operation: "health.alerts", path: "health/alerts", objectType: "fmc.health_alert", query: recentFMCQuery},
		{group: "health", operation: "health.events", path: "health/events", objectType: "fmc.health_event", query: recentFMCQuery},
		{group: "deployments", operation: "deployment.job_histories", path: "deployment/jobhistories", objectType: "fmc.deployment_job", query: recentFMCQuery},
		{group: "audit", operation: "audit.records", path: "/api/fmc_platform/v1/domain/{domainUUID}/audit/auditrecords", objectType: "fmc.audit_record"},
		{group: "audit", operation: "audit.config_changes", path: "/api/fmc_platform/v1/domain/{domainUUID}/audit/configchanges", objectType: "fmc.config_change"},
	}
}

func fmcDeviceScopedEndpoints() []fmcScopedEndpoint {
	return []fmcScopedEndpoint{
		{group: "interfaces", operation: "interfaces.all", path: "devices/devicerecords/{containerUUID}/ftdallinterfaces", objectType: "fmc.interface", source: "devices"},
		{group: "interfaces", operation: "interfaces.physical", path: "devices/devicerecords/{containerUUID}/fpphysicalinterfaces", objectType: "fmc.physical_interface", source: "devices"},
		{group: "interfaces", operation: "interfaces.logical", path: "devices/devicerecords/{containerUUID}/fplogicalinterfaces", objectType: "fmc.logical_interface", source: "devices"},
		{group: "interfaces", operation: "interfaces.inlinesets", path: "devices/devicerecords/{containerUUID}/inlinesets", objectType: "fmc.inline_set", source: "devices"},
		{group: "interfaces", operation: "interfaces.statistics", path: "devices/devicerecords/{containerUUID}/fpinterfacestatistics", objectType: "fmc.interface_statistics", source: "devices"},
		{group: "interfaces", operation: "interfaces.events", path: "devices/devicerecords/{containerUUID}/interfaceevents", objectType: "fmc.interface_event", source: "devices"},
		{group: "interfaces", operation: "interfaces.bridge_groups", path: "devices/devicerecords/{containerUUID}/bridgegroupinterfaces", objectType: "fmc.bridge_group_interface", source: "devices"},
		{group: "interfaces", operation: "interfaces.etherchannels", path: "devices/devicerecords/{containerUUID}/etherchannelinterfaces", objectType: "fmc.etherchannel_interface", source: "devices"},
		{group: "interfaces", operation: "interfaces.vni", path: "devices/devicerecords/{containerUUID}/vniinterfaces", objectType: "fmc.vni_interface", source: "devices"},
		{group: "interfaces", operation: "interfaces.vtep_policies", path: "devices/devicerecords/{containerUUID}/vteppolicies", objectType: "fmc.vtep_policy", source: "devices"},
		{group: "interfaces", operation: "routing.ipv4_static_routes", path: "devices/devicerecords/{containerUUID}/routing/ipv4staticroutes", objectType: "fmc.ipv4_static_route", source: "devices"},
		{group: "interfaces", operation: "routing.ipv6_static_routes", path: "devices/devicerecords/{containerUUID}/routing/ipv6staticroutes", objectType: "fmc.ipv6_static_route", source: "devices"},
	}
}

func fmcChassisScopedEndpoints() []fmcScopedEndpoint {
	return []fmcScopedEndpoint{
		{group: "interfaces", operation: "chassis.interfaces", path: "chassis/fmcmanagedchassis/{containerUUID}/interfaces", objectType: "fmc.chassis_interface", source: "chassis"},
		{group: "interfaces", operation: "chassis.interface_summaries", path: "chassis/fmcmanagedchassis/{containerUUID}/interfacesummary", objectType: "fmc.chassis_interface_summary", source: "chassis"},
		{group: "interfaces", operation: "chassis.interface_events", path: "chassis/fmcmanagedchassis/{containerUUID}/chassisinterfaceevents", objectType: "fmc.chassis_interface_event", source: "chassis"},
		{group: "inventory", operation: "chassis.inventory_summaries", path: "chassis/fmcmanagedchassis/{containerUUID}/inventorysummary", objectType: "fmc.chassis_inventory_summary", source: "chassis"},
		{group: "inventory", operation: "chassis.instance_summaries", path: "chassis/fmcmanagedchassis/{containerUUID}/instancesummary", objectType: "fmc.chassis_instance_summary", source: "chassis"},
		{group: "inventory", operation: "chassis.logical_devices", path: "chassis/fmcmanagedchassis/{containerUUID}/logicaldevices", objectType: "fmc.chassis_logical_device", source: "chassis"},
	}
}

func fmcHealthScopedEndpoints() []fmcScopedEndpoint {
	return []fmcScopedEndpoint{
		{group: "health", operation: "health.aggregate_cpu", path: "health/aggregatemetrics", objectType: "fmc.health_cpu_metric", source: "devices", query: aggregateHealthMetricQuery("CPU")},
		{group: "health", operation: "health.aggregate_memory", path: "health/aggregatemetrics", objectType: "fmc.health_memory_metric", source: "devices", query: aggregateHealthMetricQuery("MEM")},
		{group: "health", operation: "health.aggregate_interfaces", path: "health/aggregatemetrics", objectType: "fmc.health_interface_metric", source: "devices", query: aggregateHealthMetricQuery("INTERFACE")},
		{group: "health", operation: "health.aggregate_disk", path: "health/aggregatemetrics", objectType: "fmc.health_disk_metric", source: "devices", query: aggregateHealthMetricQuery("DISK_STATS")},
		{group: "health", operation: "health.aggregate_chassis", path: "health/aggregatemetrics", objectType: "fmc.health_chassis_metric", source: "devices", query: aggregateHealthMetricQuery("CHASSIS_STATS")},
	}
}

func fmcVPNTunnelScopedEndpoints() []fmcScopedEndpoint {
	return []fmcScopedEndpoint{
		{group: "vpn", operation: "vpn.tunnel_details", path: "health/tunnelstatuses/{containerUUID}/tunneldetails", objectType: "fmc.vpn_tunnel_detail", source: "tunnel_statuses"},
	}
}

func fmcHAScopedEndpoints() []fmcScopedEndpoint {
	return []fmcScopedEndpoint{
		{group: "ha", operation: "ha.monitored_interfaces", path: "devicehapairs/ftddevicehapairs/{containerUUID}/monitoredinterfaces", objectType: "fmc.ha_monitored_interface", source: "ha_pairs"},
	}
}

func fmcPolicyScopedEndpoints() []fmcScopedEndpoint {
	return []fmcScopedEndpoint{
		{group: "policy", operation: "policy.access_rules", path: "policy/accesspolicies/{containerUUID}/accessrules", objectType: "fmc.access_rule", source: "access_policies"},
		{group: "policy", operation: "policy.prefilter_rules", path: "policy/prefilterpolicies/{containerUUID}/prefilterrules", objectType: "fmc.prefilter_rule", source: "prefilter_policies"},
		{group: "policy", operation: "policy.manual_nat_rules", path: "policy/ftdnatpolicies/{containerUUID}/manualnatrules", objectType: "fmc.manual_nat_rule", source: "nat_policies"},
		{group: "policy", operation: "policy.auto_nat_rules", path: "policy/ftdnatpolicies/{containerUUID}/autonatrules", objectType: "fmc.auto_nat_rule", source: "nat_policies"},
	}
}

func fmcDeploymentScopedEndpoints() []fmcScopedEndpoint {
	return []fmcScopedEndpoint{
		{group: "deployments", operation: "deployment.pending_changes", path: "deployment/deployabledevices/{containerUUID}/pendingchanges", objectType: "fmc.pending_change", source: "deployable_devices"},
		{group: "deployments", operation: "deployment.device_deployments", path: "deployment/deployabledevices/{containerUUID}/deployments", objectType: "fmc.device_deployment", source: "deployable_devices", query: scopedRecentFMCQuery},
	}
}

func (e fmcScopedEndpoint) asEndpoint() fmcEndpoint {
	var query func(*Config, time.Time) url.Values
	if e.query != nil {
		query = func(cfg *Config, now time.Time) url.Values {
			return e.query(cfg, now, fmc.Object{})
		}
	}
	return fmcEndpoint{group: e.group, operation: e.operation, path: e.path, objectType: e.objectType, method: e.method, query: query}
}

func (c fmcControllerCache) objectsForSource(source string) []fmc.Object {
	switch source {
	case "access_policies":
		return c.accessPolicies
	case "nat_policies":
		return c.natPolicies
	case "prefilter_policies":
		return c.prefilterPolicies
	case "deployable_devices":
		return c.deployableDevices
	case "tunnel_statuses":
		return c.tunnelStatuses
	case "ha_pairs":
		return c.haPairs
	case "chassis":
		return c.chassis
	default:
		return nil
	}
}

func fmcEndpointQuery(endpoint fmcEndpoint, cfg *Config, now time.Time) url.Values {
	query := fmc.Query(map[string]string{"expanded": "true"})
	if endpoint.query != nil {
		maps.Copy(query, endpoint.query(cfg, now))
	}
	return query
}

func fmcScopedEndpointQuery(endpoint fmcScopedEndpoint, cfg *Config, now time.Time, parent fmc.Object) url.Values {
	query := fmc.Query(map[string]string{"expanded": "true"})
	if endpoint.query != nil {
		maps.Copy(query, endpoint.query(cfg, now, parent))
	}
	return query
}

func recentFMCQuery(cfg *Config, now time.Time) url.Values {
	lookback := cfg.FMC.EventLookback
	if lookback <= 0 {
		lookback = defaultFMCConfig().EventLookback
	}
	since := now.Add(-lookback).Unix()
	until := now.Unix()
	return fmc.Query(map[string]string{
		"filter": fmt.Sprintf("startTime:%d;endTime:%d", since, until),
	})
}

func scopedRecentFMCQuery(cfg *Config, now time.Time, _ fmc.Object) url.Values {
	return recentFMCQuery(cfg, now)
}

func fmcDomainPath(domainUUID, path string) string {
	path = strings.ReplaceAll(path, "{domainUUID}", url.PathEscape(domainUUID))
	if strings.HasPrefix(path, "/api/") {
		return path
	}
	return "/api/fmc_config/v1/domain/" + url.PathEscape(domainUUID) + "/" + strings.TrimLeft(path, "/")
}

func aggregateHealthMetricQuery(metric string) func(*Config, time.Time, fmc.Object) url.Values {
	return func(_ *Config, _ time.Time, parent fmc.Object) url.Values {
		deviceID := fmc.StableID(parent)
		if deviceID == "" {
			return nil
		}
		return fmc.Query(map[string]string{
			"filter": fmt.Sprintf("device_uuid:%s;metric:%s;timeRange:5m", deviceID, metric),
		})
	}
}

func fmcGroupEnabled(cfg FMCConfig, group string) bool {
	switch group {
	case "manager":
		return cfg.Manager.Enabled
	case "inventory":
		return cfg.Inventory.Enabled
	case "interfaces":
		return cfg.Interfaces.Enabled
	case "health":
		return cfg.Health.Enabled
	case "vpn":
		return cfg.VPN.Enabled
	case "ha":
		return cfg.HA.Enabled
	case "policy":
		return cfg.Policy.Enabled
	case "deployments":
		return cfg.Deployments.Enabled
	case "audit":
		return cfg.Audit.Enabled
	default:
		return true
	}
}

func fmcGroupMaxResults(cfg FMCConfig, group string) int {
	switch group {
	case "manager":
		return cfg.Manager.MaxResults
	case "inventory":
		return cfg.Inventory.MaxResults
	case "interfaces":
		return cfg.Interfaces.MaxResults
	case "health":
		return cfg.Health.MaxResults
	case "vpn":
		return cfg.VPN.MaxResults
	case "ha":
		return cfg.HA.MaxResults
	case "policy":
		return cfg.Policy.MaxResults
	case "deployments":
		return cfg.Deployments.MaxResults
	case "audit":
		return cfg.Audit.MaxResults
	default:
		return 0
	}
}

func filterFMCObjects(objects []fmc.Object, filters FMCTargetFilters) []fmc.Object {
	needles := makeFilterNeedles(filters.DeviceIDs, filters.Serials, filters.Names, filters.ManagementIPs, filters.PolicyIDs, filters.PolicyNames, filters.InterfaceNames)
	if len(needles) == 0 {
		return objects
	}
	filtered := make([]fmc.Object, 0, len(objects))
	for _, obj := range objects {
		text := fmc.SearchText(obj)
		for needle := range needles {
			if strings.Contains(text, needle) {
				filtered = append(filtered, obj)
				break
			}
		}
	}
	return filtered
}

func fmcObjectStatus(obj fmc.Object) string {
	return firstNonEmpty(
		fmc.String(obj, "status", "healthStatus", "deploymentStatus", "state", "statusMessage", "operationalState", "enabled"),
		fmc.String(obj, "enabled"),
	)
}

func fmcLogTimestamp(obj fmc.Object) (time.Time, bool) {
	for _, key := range []string{"eventTime", "timestamp", "time", "createdTime", "createTime", "lastUpdated", "lastUpdatedTime", "startTime", "endTime"} {
		if ts, ok := fmc.Time(obj, key); ok {
			return ts, true
		}
	}
	return time.Time{}, false
}

func fmcCountDescription(name string) string {
	switch name {
	case "fmc.resource.count":
		return "FMC resources by group, operation, resource type, status, and severity."
	case "fmc.health.event.count":
		return "FMC health alerts and health events by bounded status and severity attributes."
	case "fmc.policy.object.count":
		return "FMC policy objects and rules by bounded policy and rule attributes."
	case "fmc.deployment.pending.count":
		return "FMC deployment jobs, deployable devices, and pending changes by bounded status attributes."
	case "fmc.audit.record.count":
		return "FMC audit and configuration-change records by bounded status and severity attributes."
	default:
		return "FMC resources."
	}
}

func inheritFMCDevice(obj, device fmc.Object) {
	for _, pair := range [][2]string{
		{"parent.device.id", "id"},
		{"parent.device.name", "name"},
		{"parent.device.serial", "serialNumber"},
		{"parent.device.ip", "managementIpAddress"},
	} {
		if obj[pair[0]] == nil {
			obj[pair[0]] = fmc.String(device, pair[1])
		}
	}
}

func inheritFMCPolicy(obj, policy fmc.Object) {
	if obj["parent.policy.id"] == nil {
		obj["parent.policy.id"] = fmc.StableID(policy)
	}
	if obj["parent.policy.name"] == nil {
		obj["parent.policy.name"] = fmc.String(policy, "name")
	}
}

func estreamerEndpointFromFMCController(endpoint string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("cannot derive eStreamer endpoint from FMC endpoint %q", endpoint)
	}
	host, _, splitErr := net.SplitHostPort(parsed.Host)
	if splitErr != nil {
		host = parsed.Hostname()
		if host == "" {
			host = parsed.Host
		}
	}
	return net.JoinHostPort(host, "8302"), nil
}

func loadFMCEStreamerTLS(cfg FMCEStreamerTLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{ServerName: cfg.ServerName, InsecureSkipVerify: cfg.InsecureSkipVerify}
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	if cfg.CAFile != "" {
		pemBytes, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("fmc.estreamer.tls.ca_file did not contain PEM certificates")
		}
		tlsConfig.RootCAs = pool
	}
	return tlsConfig, nil
}
