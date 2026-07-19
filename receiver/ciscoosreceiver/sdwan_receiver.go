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
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/sdwan"
)

const (
	sdwanScopeName        = "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/sdwan"
	sdwanEventsPath       = "/event"
	sdwanLegacyEventsPath = "/events"
)

// classifySDWANError returns a bounded value suitable for a metric attribute.
// Transport errors can include request URLs and device identifiers, so raw
// error strings must remain in diagnostic logs rather than metric dimensions.
func classifySDWANError(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	if httpclient.IsResponseBodyReadError(err) {
		return "transport"
	}
	var apiErr *sdwan.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return "auth"
		case http.StatusNotFound, http.StatusMethodNotAllowed:
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
	if strings.Contains(strings.ToLower(err.Error()), "decode") {
		return "decode"
	}
	return "other"
}

type sdwanMetricsReceiver struct {
	settings receiver.Settings
	config   *Config
	consumer consumer.Metrics
	client   *sdwan.Client
	counters *counterStore
	obs      *receiverhelper.ObsReport
	success  scrapeSuccessState

	startMu sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}

	statsMu sync.Mutex
	stats   []sdwan.RequestStat
}

type sdwanLogsReceiver struct {
	settings receiver.Settings
	config   *Config
	consumer consumer.Logs
	client   *sdwan.Client
	obs      *receiverhelper.ObsReport

	startMu sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}

	seen *logDeduplicator
}

type sdwanCount struct {
	value int64
	attrs map[string]string
}

type sdwanEndpointSpec struct {
	group        string
	operation    string
	path         string
	deviceScoped bool
}

func newSDWANMetricsReceiver(set receiver.Settings, conf *Config, consumer consumer.Metrics) (*sdwanMetricsReceiver, error) {
	client, err := newSDWANClient(conf)
	if err != nil {
		return nil, err
	}
	r := &sdwanMetricsReceiver{
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

func newSDWANLogsReceiver(set receiver.Settings, conf *Config, consumer consumer.Logs) (*sdwanLogsReceiver, error) {
	client, err := newSDWANClient(conf)
	if err != nil {
		return nil, err
	}
	return &sdwanLogsReceiver{
		settings: set,
		config:   conf,
		consumer: consumer,
		client:   client,
		done:     make(chan struct{}),
		seen:     newLogDeduplicator(),
		obs:      newPlatformObsReport(set, "http"),
	}, nil
}

func newSDWANClient(conf *Config) (*sdwan.Client, error) {
	return sdwan.NewClient(sdwan.Config{
		Endpoint:           conf.SDWAN.Endpoint,
		AuthMode:           conf.SDWAN.Auth.Mode,
		Username:           conf.SDWAN.Auth.Username,
		Password:           string(conf.SDWAN.Auth.Password),
		BearerToken:        string(conf.SDWAN.Auth.BearerToken),
		JSessionID:         string(conf.SDWAN.Auth.JSessionID),
		XSRFToken:          string(conf.SDWAN.Auth.XSRFToken),
		UserAgent:          conf.SDWAN.UserAgent,
		Timeout:            conf.Timeout,
		MaxRetries:         conf.SDWAN.MaxRetries,
		PageSize:           conf.SDWAN.PageSize,
		InsecureSkipVerify: conf.SDWAN.InsecureSkipVerify,
	})
}

func (r *sdwanMetricsReceiver) Start(_ context.Context, _ component.Host) error {
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

func (r *sdwanMetricsReceiver) Shutdown(ctx context.Context) error {
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

func (r *sdwanMetricsReceiver) run(ctx context.Context) {
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

func (r *sdwanMetricsReceiver) collect(ctx context.Context) {
	scrapeCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()

	obsCtx := startMetricsOp(ctx, r.obs)
	md, scrapeErr := r.scrape(scrapeCtx)
	if scrapeErr != nil {
		r.settings.Logger.Error("SD-WAN scrape failed", zap.Error(scrapeErr))
	}
	metricCount, consumeErr := consumeMetricsIfPresent(ctx, r.consumer, md)
	if consumeErr != nil {
		r.settings.Logger.Error("SD-WAN metrics consumer failed", zap.Error(consumeErr))
	}
	endMetricsOp(obsCtx, r.obs, metricCount, combineSignalErrors(scrapeErr, consumeErr))
}

func (r *sdwanMetricsReceiver) scrape(ctx context.Context) (pmetric.Metrics, error) {
	r.resetRequestStats()
	now := time.Now()
	builder := newSDWANMetricsBuilder(now, r.config.SDWAN.Endpoint, r.counters)
	selector := newDeviceSelectionMatcher(r.config.DeviceSelection)
	targets := newSDWANTargetMatcher(r.config.SDWAN.Targets)
	partial := false

	if r.config.SDWAN.Manager.Enabled {
		groupPartial, err := r.scrapeManager(ctx, builder)
		partial = partial || groupPartial
		if err != nil {
			if ctx.Err() != nil {
				return r.finishScrape(builder, now, true), ctx.Err()
			}
			partial = true
			r.settings.Logger.Warn("SD-WAN Manager endpoint failed", zap.Error(err))
		}
	}
	if r.config.SDWAN.Inventory.Enabled {
		if err := r.scrapeInventory(ctx, builder, selector, targets); err != nil {
			if ctx.Err() != nil {
				return r.finishScrape(builder, now, true), ctx.Err()
			}
			partial = true
			r.settings.Logger.Warn("SD-WAN inventory endpoint failed", zap.Error(err))
		}
	}
	if sdwanEventGroupsEnabled(r.config.SDWAN) && (!selector.empty() || targets.hasAny()) && !builder.inventoryLoaded {
		if err := r.loadSDWANEventFilterInventory(ctx, builder); err != nil {
			if ctx.Err() != nil {
				return r.finishScrape(builder, now, true), ctx.Err()
			}
			partial = true
			r.settings.Logger.Warn("SD-WAN event filter inventory endpoint failed", zap.Error(err))
		}
	}
	if r.config.SDWAN.ControlPlane.Enabled {
		if r.scrapeDeviceGroup(ctx, builder, selector, targets, r.config.SDWAN.ControlPlane, sdwanControlPlaneSpecs(), r.recordControlPlaneObject) {
			partial = true
		}
		if ctx.Err() != nil {
			return r.finishScrape(builder, now, true), ctx.Err()
		}
	}
	if r.config.SDWAN.BFD.Enabled {
		if r.scrapeDeviceGroup(ctx, builder, selector, targets, r.config.SDWAN.BFD, sdwanBFDSpecs(), r.recordBFDObject) {
			partial = true
		}
		if ctx.Err() != nil {
			return r.finishScrape(builder, now, true), ctx.Err()
		}
	}
	if r.config.SDWAN.AppRoute.Enabled {
		if r.scrapeDeviceGroup(ctx, builder, selector, targets, r.config.SDWAN.AppRoute, sdwanAppRouteSpecs(), r.recordAppRouteObject) {
			partial = true
		}
		if ctx.Err() != nil {
			return r.finishScrape(builder, now, true), ctx.Err()
		}
	}
	if r.config.SDWAN.Interfaces.Enabled {
		if r.scrapeDeviceGroup(ctx, builder, selector, targets, r.config.SDWAN.Interfaces, sdwanInterfaceSpecs(), r.recordInterfaceObject) {
			partial = true
		}
		if ctx.Err() != nil {
			return r.finishScrape(builder, now, true), ctx.Err()
		}
	}
	if r.config.SDWAN.Alarms.Enabled {
		if err := r.scrapeEventMetricGroup(ctx, builder, selector, targets, "alarms", "/alarms", r.config.SDWAN.Alarms); err != nil {
			if ctx.Err() != nil {
				return r.finishScrape(builder, now, true), ctx.Err()
			}
			partial = true
			r.settings.Logger.Warn("SD-WAN alarms endpoint failed", zap.Error(err))
		}
	}
	if r.config.SDWAN.Events.Enabled {
		if err := r.scrapeEventMetricGroup(ctx, builder, selector, targets, "events", sdwanEventsPath, r.config.SDWAN.Events); err != nil {
			if ctx.Err() != nil {
				return r.finishScrape(builder, now, true), ctx.Err()
			}
			partial = true
			r.settings.Logger.Warn("SD-WAN events endpoint failed", zap.Error(err))
		}
	}
	if r.config.SDWAN.Audit.Enabled {
		if err := r.scrapeEventMetricGroup(ctx, builder, selector, targets, "audit", "/auditlog", r.config.SDWAN.Audit); err != nil {
			if ctx.Err() != nil {
				return r.finishScrape(builder, now, true), ctx.Err()
			}
			partial = true
			r.settings.Logger.Warn("SD-WAN audit endpoint failed", zap.Error(err))
		}
	}
	if r.scrapeOptInGroups(ctx, builder, selector, targets) {
		partial = true
	}
	if ctx.Err() != nil {
		return r.finishScrape(builder, now, true), ctx.Err()
	}

	return r.finishScrape(builder, now, partial), nil
}

func (r *sdwanMetricsReceiver) finishScrape(builder *sdwanMetricsBuilder, _ time.Time, partial bool) pmetric.Metrics {
	r.recordAPIRequestMetrics(builder)
	outcome := summarizeAPIOutcomes(r.requestStats(), func(stat sdwan.RequestStat) string { return stat.Outcome })
	rb := builder.managerResource()
	rb.recordInt("sdwan.scrape.partial_success", "Whether one or more SD-WAN endpoint families failed or were skipped.", "1", boolToInt(partial), nil)
	if lastSuccess, ok := r.success.observe(time.Now(), !partial && outcome.succeeded); ok {
		rb.recordInt("sdwan.scrape.last_success", "Unix timestamp of the most recent fully successful SD-WAN scrape.", "s", lastSuccess.Unix(), nil)
	}
	builder.flushCounts()
	return builder.emit()
}

func (r *sdwanMetricsReceiver) scrapeManager(ctx context.Context, builder *sdwanMetricsBuilder) (partial bool, err error) {
	succeeded := false
	defer func() {
		builder.managerResource().recordInt("sdwan.manager.up", "Whether at least one SD-WAN Manager API operation succeeded in the scrape.", "1", boolToInt(succeeded), nil)
	}()
	for _, spec := range []sdwanEndpointSpec{
		{group: "manager", operation: "manager.cluster_health", path: "/clusterManagement/health/summary"},
		{group: "manager", operation: "manager.server_info", path: "/client/server"},
		{group: "manager", operation: "manager.settings", path: "/settings/configuration/device"},
	} {
		obj, err := r.client.GetObject(ctx, spec.operation, spec.path, nil)
		if err != nil {
			partial = true
			builder.recordServiceUnavailable(spec.group, spec.operation, err)
			if ctx.Err() != nil {
				return true, ctx.Err()
			}
			continue
		}
		succeeded = true
		builder.recordManagerObject(spec.operation, obj)
	}
	return partial, nil
}

func (r *sdwanMetricsReceiver) scrapeInventory(ctx context.Context, builder *sdwanMetricsBuilder, selector deviceSelectionMatcher, targets sdwanTargetMatcher) error {
	devices, err := r.client.List(ctx, "inventory.devices", "/device", nil, r.config.SDWAN.Inventory.MaxResults)
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	builder.inventoryLoaded = err == nil || len(devices) > 0
	for _, device := range devices {
		builder.inventory.add(device)
		if !targets.allowsDevice(device) || !selector.allows(sdwanObjectIdentity(device)) {
			continue
		}
		builder.recordDevice(device)
	}
	builder.managerResource().recordInt("sdwan.inventory.device.count", "Device inventory count after target and shared selection.", "{device}", int64(len(builder.devicesForDetail())), nil)
	return err
}

func (r *sdwanMetricsReceiver) loadSDWANEventFilterInventory(ctx context.Context, builder *sdwanMetricsBuilder) error {
	devices, err := r.client.List(ctx, "events.filter_inventory", "/device", nil, r.config.SDWAN.Inventory.MaxResults)
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	builder.inventoryLoaded = err == nil || len(devices) > 0
	for _, device := range devices {
		builder.inventory.add(device)
	}
	return err
}

func (r *sdwanMetricsReceiver) scrapeDeviceGroup(
	ctx context.Context,
	builder *sdwanMetricsBuilder,
	selector deviceSelectionMatcher,
	targets sdwanTargetMatcher,
	group SDWANGroupConfig,
	specs []sdwanEndpointSpec,
	record func(*sdwanMetricsBuilder, sdwan.Object, sdwan.Object, sdwanEndpointSpec),
) bool {
	partial := false
	devices := selectedSDWANDevices(builder.devicesForDetail(), selector, targets, group.MaxResults)
	if len(devices) == 0 && targets.hasSystemIPs() {
		devices = syntheticSDWANDevices(targets.systemIPs)
	}
	if len(devices) == 0 && allSDWANSpecsDeviceScoped(specs) {
		for _, spec := range specs {
			builder.recordServiceSkipped(spec.group, spec.operation, "no_selected_devices")
		}
		return true
	}
	for _, spec := range specs {
		if !spec.deviceScoped {
			objects, err := r.client.List(ctx, spec.operation, spec.path, nil, group.MaxResults)
			if err != nil {
				builder.recordServiceUnavailable(spec.group, spec.operation, err)
				partial = true
				if ctx.Err() != nil {
					return true
				}
			}
			builder.addCount("sdwan.collection.object.count", compactAttrs(map[string]string{
				"sdwan.collection.group":     spec.group,
				"sdwan.collection.operation": spec.operation,
			}), int64(len(objects)))
			managerDevice := sdwan.Object{"host-name": "Cisco Catalyst SD-WAN Manager", "personality": "sdwan_manager"}
			for _, obj := range objects {
				record(builder, managerDevice, obj, spec)
			}
			continue
		}
		for _, device := range devices {
			systemIP := sdwanSystemIP(device)
			if systemIP == "" {
				builder.recordServiceSkipped(spec.group, spec.operation, "missing_system_ip")
				partial = true
				continue
			}
			query := url.Values{"deviceId": {systemIP}}
			objects, err := r.client.List(ctx, spec.operation, spec.path, query, group.MaxResults)
			if err != nil {
				builder.recordServiceUnavailable(spec.group, spec.operation, err)
				partial = true
				if ctx.Err() != nil {
					return true
				}
			}
			builder.addCount("sdwan.collection.object.count", compactAttrs(map[string]string{
				"sdwan.collection.group":     spec.group,
				"sdwan.collection.operation": spec.operation,
			}), int64(len(objects)))
			for _, obj := range objects {
				record(builder, device, obj, spec)
			}
		}
		if len(devices) == 0 {
			builder.recordServiceSkipped(spec.group, spec.operation, "no_selected_devices")
			partial = true
		}
	}
	return partial
}

func (r *sdwanMetricsReceiver) scrapeEventMetricGroup(
	ctx context.Context,
	builder *sdwanMetricsBuilder,
	selector deviceSelectionMatcher,
	targets sdwanTargetMatcher,
	name, path string,
	group SDWANGroupConfig,
) error {
	objects, selectedPath, err := postSDWANEventQuery(
		ctx,
		r.client,
		"events."+name,
		path,
		sdwanLookbackQuery(r.config.SDWAN.EventLookback, group.MaxResults),
		group.MaxResults,
	)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A non-empty result means POST succeeded for at least one page. Keep
		// that valid prefix and surface the pagination failure; GET is only a
		// compatibility fallback when POST produced no usable data at all.
		if len(objects) == 0 {
			objects, err = r.client.List(ctx, "events."+name+".get", selectedPath, nil, group.MaxResults)
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
	}
	for _, obj := range objects {
		if !sdwanEventAllowed(obj, builder.inventory, selector, targets) {
			continue
		}
		attrs := compactAttrs(map[string]string{
			"sdwan.event.type":     name,
			"sdwan.severity":       strings.ToLower(sdwan.String(obj, "severity", "severity_level", "severityLevel")),
			"sdwan.status":         sdwan.String(obj, "status", "state"),
			"sdwan.system_ip":      sdwan.String(obj, "system-ip", "systemIp", "system_ip", "deviceId"),
			"sdwan.site.id":        sdwan.String(obj, "site-id", "siteId", "site_id"),
			"sdwan.policy.name":    sdwan.String(obj, "policy", "policyName", "policy-name"),
			"sdwan.collection.url": selectedPath,
		})
		builder.addCount("sdwan.event.count", attrs, 1)
	}
	return err
}

func (r *sdwanMetricsReceiver) scrapeOptInGroups(ctx context.Context, builder *sdwanMetricsBuilder, selector deviceSelectionMatcher, targets sdwanTargetMatcher) bool {
	partial := false
	for _, group := range sdwanOptInGroups(r.config.SDWAN) {
		if !group.config.Enabled {
			continue
		}
		if group.requiresTargets && !targets.hasAny() {
			builder.recordServiceSkipped(group.name, group.name, "missing_target_filters")
			partial = true
			continue
		}
		if r.scrapeDeviceGroup(ctx, builder, selector, targets, group.config, group.specs, r.recordGenericObject) {
			partial = true
		}
	}
	return partial
}

func (r *sdwanMetricsReceiver) recordControlPlaneObject(builder *sdwanMetricsBuilder, device, obj sdwan.Object, _ sdwanEndpointSpec) {
	if !newSDWANTargetMatcher(r.config.SDWAN.Targets).allowsPath(obj) {
		return
	}
	rb := builder.deviceResource(device)
	attrs := sdwanPathAttrs(device, obj)
	putNonEmpty(attrs, "sdwan.peer.type", sdwan.String(obj, "peer-type", "peerType", "peer_type", "personality"))
	state := sdwan.String(obj, "state", "status", "local-state", "localState")
	if code, ok := statusCode(state); ok {
		rb.recordInt("sdwan.control.connection.status", "Encoded control connection status.", "1", code, withAttr(attrs, "sdwan.status", state))
	}
	builder.addCount("sdwan.control.connection.count", withAttr(attrs, "sdwan.status", firstNonEmpty(state, "unknown")), 1)
	if expected, ok := sdwan.Int(obj, "expected", "expectedControlConnections", "expectedConnections"); ok {
		rb.recordInt("sdwan.control.expected_connections", "Expected control connections when exposed.", "{connection}", expected, attrs)
	}
	if actual, ok := sdwan.Int(obj, "actual", "actualControlConnections", "actualConnections", "num-vsmart-connections"); ok {
		rb.recordInt("sdwan.control.actual_connections", "Actual control connections when exposed.", "{connection}", actual, attrs)
	}
}

func (r *sdwanMetricsReceiver) recordBFDObject(builder *sdwanMetricsBuilder, device, obj sdwan.Object, _ sdwanEndpointSpec) {
	if !newSDWANTargetMatcher(r.config.SDWAN.Targets).allowsPath(obj) {
		return
	}
	rb := builder.deviceResource(device)
	attrs := sdwanPathAttrs(device, obj)
	state := sdwan.String(obj, "state", "status", "session-state", "sessionState")
	if code, ok := statusCode(state); ok {
		rb.recordInt("sdwan.bfd.session.status", "Encoded BFD session status.", "1", code, withAttr(attrs, "sdwan.status", state))
	}
	builder.addCount("sdwan.bfd.session.count", withAttr(attrs, "sdwan.status", firstNonEmpty(state, "unknown")), 1)
	recordSDWANAbsoluteSumInt(rb, obj, "transitions", "sdwan.bfd.session.transitions", "SD-WAN BFD session transition count.", "{transition}", attrs, "transitions", "state-transitions", "stateTransitions")
	recordSDWANAbsoluteSumInt(rb, obj, "flaps", "sdwan.bfd.session.flap.count", "SD-WAN BFD session flap count.", "{flap}", attrs, "flaps", "flapCount")
}

func (r *sdwanMetricsReceiver) recordAppRouteObject(builder *sdwanMetricsBuilder, device, obj sdwan.Object, _ sdwanEndpointSpec) {
	if !newSDWANTargetMatcher(r.config.SDWAN.Targets).allowsApplicationPath(obj) {
		return
	}
	rb := builder.deviceResource(device)
	attrs := sdwanPathAttrs(device, obj)
	putNonEmpty(attrs, "sdwan.sla_class", sdwan.String(obj, "sla-class", "slaClass", "sla_class"))
	putNonEmpty(attrs, "sdwan.app_probe_class", sdwan.String(obj, "app-probe-class", "appProbeClass", "app_probe_class"))
	putNonEmpty(attrs, "sdwan.application", sdwan.String(obj, "application", "app", "app-name", "appName"))
	recordSDWANDouble(rb, obj, "latency", "sdwan.app_route.latency", "SD-WAN application-aware routing latency.", "ms", attrs, "latency", "latency-average", "latencyAvg")
	recordSDWANDouble(rb, obj, "jitter", "sdwan.app_route.jitter", "SD-WAN application-aware routing jitter.", "ms", attrs, "jitter", "jitter-average", "jitterAvg")
	recordSDWANDouble(rb, obj, "loss", "sdwan.app_route.loss", "SD-WAN application-aware routing loss.", "%", attrs, "loss", "loss_percentage", "lossPercentage", "loss-percent")
	state := sdwan.String(obj, "sla-state", "slaState", "state", "status")
	if code, ok := statusCode(state); ok {
		rb.recordInt("sdwan.app_route.sla.status", "Encoded app-route SLA state.", "1", code, withAttr(attrs, "sdwan.status", state))
	}
}

func (r *sdwanMetricsReceiver) recordInterfaceObject(builder *sdwanMetricsBuilder, device, obj sdwan.Object, spec sdwanEndpointSpec) {
	if !newSDWANTargetMatcher(r.config.SDWAN.Targets).allowsInterface(obj) {
		return
	}
	rb := builder.deviceResource(device)
	attrs := compactAttrs(map[string]string{
		"network.interface.name": sdwan.String(obj, "ifname", "interface", "interfaceName", "name", "if-name"),
		"network.interface.type": sdwan.String(obj, "iftype", "interface-type", "interfaceType", "type"),
		"sdwan.tloc.color":       sdwan.String(obj, "color", "local-color", "localColor"),
		"sdwan.vpn.id":           sdwan.String(obj, "vpn-id", "vpnId", "vpn"),
		"sdwan.collection.group": spec.group,
	})
	status := firstNonEmpty(sdwan.String(obj, "oper-status", "operStatus", "status", "state"), "")
	if up, ok := upStatus(status); ok {
		rb.recordInt("system.network.interface.status", "Interface operational status (1 = up, 0 = down)", "1", up, withAttr(attrs, "sdwan.status", status))
	}
	if code, ok := statusCode(status); ok {
		rb.recordInt("sdwan.transport.interface.status", "SD-WAN transport or service interface state.", "1", code, withAttr(attrs, "sdwan.status", status))
	}
	admin := sdwan.String(obj, "admin-status", "adminStatus", "admin_state")
	if up, ok := upStatus(admin); ok {
		rb.recordInt("cisco.interface.admin.status", "Cisco interface administrative status (1 = administratively enabled, 0 = administratively disabled)", "1", up, withAttr(attrs, "sdwan.status", admin))
	}
	recordSDWANInterfaceSpeed(rb, obj, attrs)
	recordSDWANInterfaceRate(rb, obj, "rx-kbps", withAttr(attrs, "network.io.direction", "receive"), "rx-kbps", "rxKbps")
	recordSDWANInterfaceRate(rb, obj, "tx-kbps", withAttr(attrs, "network.io.direction", "transmit"), "tx-kbps", "txKbps")
	recordSDWANAbsoluteSumInt(rb, obj, "rx-bytes", "system.network.io", "SD-WAN interface received bytes.", "By", withAttr(attrs, "network.io.direction", "receive"), "rx-bytes", "rxBytes", "rx_octets")
	recordSDWANAbsoluteSumInt(rb, obj, "tx-bytes", "system.network.io", "SD-WAN interface transmitted bytes.", "By", withAttr(attrs, "network.io.direction", "transmit"), "tx-bytes", "txBytes", "tx_octets")
	recordSDWANAbsoluteSumInt(rb, obj, "rx-packets", "system.network.packet.count", "SD-WAN interface received packets.", "{packet}", withAttr(attrs, "network.io.direction", "receive"), "rx-packets", "rxPackets", "rx-pkts", "rxPkts", "rx_pkts", "rx_packets")
	recordSDWANAbsoluteSumInt(rb, obj, "tx-packets", "system.network.packet.count", "SD-WAN interface transmitted packets.", "{packet}", withAttr(attrs, "network.io.direction", "transmit"), "tx-packets", "txPackets", "tx-pkts", "txPkts", "tx_pkts", "tx_packets")
	recordSDWANAbsoluteSumInt(rb, obj, "rx-errors", "system.network.errors", "SD-WAN interface receive errors.", "{error}", withAttr(attrs, "network.io.direction", "receive"), "rx-errors", "rxErrors", "rx_errors")
	recordSDWANAbsoluteSumInt(rb, obj, "tx-errors", "system.network.errors", "SD-WAN interface transmit errors.", "{error}", withAttr(attrs, "network.io.direction", "transmit"), "tx-errors", "txErrors", "tx_errors")
	recordSDWANAbsoluteSumInt(rb, obj, "rx-drops", "system.network.packet.dropped", "SD-WAN interface receive drops.", "{packet}", withAttr(attrs, "network.io.direction", "receive"), "rx-drops", "rxDrops", "rx_drops")
	recordSDWANAbsoluteSumInt(rb, obj, "tx-drops", "system.network.packet.dropped", "SD-WAN interface transmit drops.", "{packet}", withAttr(attrs, "network.io.direction", "transmit"), "tx-drops", "txDrops", "tx_drops")
}

func (*sdwanMetricsReceiver) recordGenericObject(builder *sdwanMetricsBuilder, device, obj sdwan.Object, spec sdwanEndpointSpec) {
	rb := builder.deviceResource(device)
	attrs := sdwanPathAttrs(device, obj)
	putNonEmpty(attrs, "sdwan.collection.group", spec.group)
	putNonEmpty(attrs, "sdwan.collection.operation", spec.operation)
	status := sdwan.String(obj, "status", "state", "oper-status", "operState")
	if code, ok := statusCode(status); ok {
		rb.recordInt("sdwan.resource.status", "Encoded SD-WAN resource or opt-in object status.", "1", code, withAttr(attrs, "sdwan.status", status))
	}
	builder.addCount("sdwan.collection.object.count", compactAttrs(map[string]string{
		"sdwan.collection.group":     spec.group,
		"sdwan.collection.operation": spec.operation,
		"sdwan.status":               firstNonEmpty(status, "present"),
	}), 1)
}

func (r *sdwanMetricsReceiver) recordRequest(stat sdwan.RequestStat) {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats = append(r.stats, stat)
}

func (r *sdwanMetricsReceiver) resetRequestStats() {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats = nil
}

func (r *sdwanMetricsReceiver) requestStats() []sdwan.RequestStat {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	return append([]sdwan.RequestStat(nil), r.stats...)
}

func (r *sdwanMetricsReceiver) recordAPIRequestMetrics(builder *sdwanMetricsBuilder) {
	stats := r.requestStats()
	observations := make([]apiRequestObservation, 0, len(stats))
	for _, stat := range stats {
		attrs := map[string]string{
			"sdwan.api.operation": stat.Operation,
			"http.request.method": stat.Method,
			"sdwan.api.path":      stat.Path,
			"sdwan.api.outcome":   stat.Outcome,
		}
		if stat.StatusCode > 0 {
			attrs["http.response.status_code"] = strconv.Itoa(stat.StatusCode)
		}
		observations = append(observations, apiRequestObservation{attrs: attrs, durationSeconds: stat.Duration.Seconds(), failed: stat.Outcome != "success", rateLimited: stat.RateLimited})
	}
	for _, aggregate := range aggregateAPIRequestObservations(observations) {
		rb := builder.managerResource()
		rb.recordDouble("sdwan.api.request.duration", "Average duration of SD-WAN Manager API request attempts within the scrape for each matching request-attribute set.", "s", aggregate.averageDurationSeconds, aggregate.attrs)
		if aggregate.errors > 0 {
			rb.recordSum("sdwan.api.request.errors", "API, auth, permission, timeout, or decode failures.", "{error}", aggregate.errors, aggregate.attrs)
		}
		if aggregate.rateLimited > 0 {
			rb.recordSum("sdwan.api.rate_limited", "Requests that received HTTP 429.", "{request}", aggregate.rateLimited, aggregate.attrs)
		}
	}
}

func (r *sdwanLogsReceiver) Start(_ context.Context, _ component.Host) error {
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

func (r *sdwanLogsReceiver) Shutdown(ctx context.Context) error {
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

func (r *sdwanLogsReceiver) run(ctx context.Context) {
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

func (r *sdwanLogsReceiver) collect(ctx context.Context) {
	scrapeCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()

	r.seen.BeginBatch()
	obsCtx := startLogsOp(ctx, r.obs)
	ld, scrapeErr := r.scrape(scrapeCtx)
	if scrapeErr != nil {
		r.settings.Logger.Error("SD-WAN logs scrape failed", zap.Error(scrapeErr))
	}
	logCount, consumeErr := consumeDeduplicatedLogs(ctx, r.consumer, r.seen, ld)
	if consumeErr != nil {
		r.settings.Logger.Error("SD-WAN logs consumer failed", zap.Error(consumeErr))
	}
	endLogsOp(obsCtx, r.obs, logCount, combineSignalErrors(scrapeErr, consumeErr))
}

func (r *sdwanLogsReceiver) scrape(ctx context.Context) (plog.Logs, error) {
	now := time.Now()
	builder := newSDWANLogsBuilder(now, r.config.SDWAN.Endpoint)
	var endpointErrors []error
	selector := newDeviceSelectionMatcher(r.config.DeviceSelection)
	targets := newSDWANTargetMatcher(r.config.SDWAN.Targets)
	inventory := sdwanDeviceIndex{}
	if !selector.empty() || targets.hasAny() {
		devices, err := r.client.List(ctx, "logs.filter_inventory", "/device", nil, r.config.SDWAN.Inventory.MaxResults)
		if err != nil {
			if ctx.Err() != nil {
				return builder.emit(), ctx.Err()
			}
			r.settings.Logger.Warn("SD-WAN logs filter inventory endpoint failed", zap.Error(err))
			endpointErrors = append(endpointErrors, fmt.Errorf("SD-WAN filter inventory: %w", err))
		}
		for _, device := range devices {
			inventory.add(device)
		}
	}
	for _, endpoint := range []struct {
		enabled bool
		name    string
		path    string
		group   SDWANGroupConfig
	}{
		{r.config.SDWAN.Alarms.Enabled, "alarms", "/alarms", r.config.SDWAN.Alarms},
		{r.config.SDWAN.Events.Enabled, "events", sdwanEventsPath, r.config.SDWAN.Events},
		{r.config.SDWAN.Audit.Enabled, "audit", "/auditlog", r.config.SDWAN.Audit},
	} {
		if !endpoint.enabled {
			continue
		}
		objects, selectedPath, err := postSDWANEventQuery(
			ctx,
			r.client,
			"logs."+endpoint.name,
			endpoint.path,
			sdwanLookbackQuery(r.config.SDWAN.EventLookback, endpoint.group.MaxResults),
			endpoint.group.MaxResults,
		)
		if err != nil {
			if ctx.Err() != nil {
				return builder.emit(), ctx.Err()
			}
			// Preserve a valid POST prefix on later-page failures. Fall back to
			// GET only when POST did not return any usable objects.
			if len(objects) == 0 {
				objects, err = r.client.List(ctx, "logs."+endpoint.name+".get", selectedPath, nil, endpoint.group.MaxResults)
				if ctx.Err() != nil {
					return builder.emit(), ctx.Err()
				}
			}
			if err != nil {
				r.settings.Logger.Warn("SD-WAN logs endpoint failed", zap.String("endpoint", endpoint.name), zap.Error(err))
				endpointErrors = append(endpointErrors, fmt.Errorf("SD-WAN %s: %w", endpoint.name, err))
			}
		}
		for _, obj := range objects {
			if !sdwanEventAllowed(obj, inventory, selector, targets) {
				continue
			}
			if r.seenBefore(endpoint.name, obj, now) {
				continue
			}
			builder.appendEvent(endpoint.name, obj)
		}
	}
	r.expireSeen(now)
	return builder.emit(), errors.Join(endpointErrors...)
}

// postSDWANEventQuery handles the event endpoint rename across supported
// Catalyst SD-WAN Manager releases. Current releases use /event, while older
// releases expose the same query API at /events. Only an explicit endpoint
// absence with no usable response prefix permits the compatibility request.
func postSDWANEventQuery(
	ctx context.Context,
	client *sdwan.Client,
	operation, path string,
	payload any,
	maxResults int,
) ([]sdwan.Object, string, error) {
	objects, err := client.PostQuery(ctx, operation, path, payload, maxResults)
	if path != sdwanEventsPath || len(objects) > 0 || !sdwanEndpointUnavailable(err) {
		return objects, path, err
	}

	objects, err = client.PostQuery(ctx, operation+".legacy", sdwanLegacyEventsPath, payload, maxResults)
	return objects, sdwanLegacyEventsPath, err
}

func sdwanEndpointUnavailable(err error) bool {
	var apiErr *sdwan.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusMethodNotAllowed
}

func (r *sdwanLogsReceiver) seenBefore(endpoint string, obj sdwan.Object, now time.Time) bool {
	stableID := sdwan.String(obj, "uuid", "id", "eventId", "event-id", "entry_uuid", "entryUuid")
	key := logDedupKey(endpoint, stableID, obj)
	return !r.seen.MarkPending(key, now)
}

func (r *sdwanLogsReceiver) expireSeen(now time.Time) {
	ttl := r.config.SDWAN.EventLookback * 2
	if ttl <= 0 {
		ttl = 48 * time.Hour
	}
	r.seen.Expire(now.Add(-ttl), 0)
}

type sdwanMetricsBuilder struct {
	metrics         pmetric.Metrics
	now             pcommon.Timestamp
	start           pcommon.Timestamp
	resources       map[string]*resourceMetricsBuilder
	devices         map[string]sdwan.Object
	deviceKeys      []string
	inventory       sdwanDeviceIndex
	inventoryLoaded bool
	counts          map[string]*sdwanCount
	endpoint        string
	counters        *counterStore
}

type sdwanManagerMetricField struct {
	field       string
	metricName  string
	description string
	unit        string
}

var sdwanManagerUtilizationMetricFields = [...]sdwanManagerMetricField{
	{field: "cpuLoad", metricName: "system.cpu.utilization", description: "Ratio of CPU time in use, from 0 to 1.", unit: "1"},
	{field: "cpu-load", metricName: "system.cpu.utilization", description: "Ratio of CPU time in use, from 0 to 1.", unit: "1"},
	{field: "memUsage", metricName: "system.memory.utilization", description: "Ratio of memory bytes in use, from 0 to 1.", unit: "1"},
	{field: "mem-usage", metricName: "system.memory.utilization", description: "Ratio of memory bytes in use, from 0 to 1.", unit: "1"},
}

var sdwanManagerHealthMetricFields = [...]sdwanManagerMetricField{
	{field: "clusterHealth", metricName: "sdwan.manager.health.score", description: "Manager cluster or resource health value where exposed.", unit: "1"},
	{field: "cluster-health", metricName: "sdwan.manager.health.score", description: "Manager cluster or resource health value where exposed.", unit: "1"},
	{field: "vmanageHealth", metricName: "sdwan.manager.health.score", description: "Manager cluster or resource health value where exposed.", unit: "1"},
	{field: "vmanage-health", metricName: "sdwan.manager.health.score", description: "Manager cluster or resource health value where exposed.", unit: "1"},
}

func newSDWANMetricsBuilder(now time.Time, endpoint string, counters *counterStore) *sdwanMetricsBuilder {
	if counters == nil {
		counters = newCounterStore()
	}
	ts := pcommon.NewTimestampFromTime(now)
	return &sdwanMetricsBuilder{
		metrics:   pmetric.NewMetrics(),
		now:       ts,
		start:     pcommon.NewTimestampFromTime(counters.StartTime()),
		resources: map[string]*resourceMetricsBuilder{},
		devices:   map[string]sdwan.Object{},
		inventory: sdwanDeviceIndex{},
		counts:    map[string]*sdwanCount{},
		endpoint:  endpoint,
		counters:  counters,
	}
}

func (b *sdwanMetricsBuilder) emit() pmetric.Metrics {
	return b.metrics
}

func (b *sdwanMetricsBuilder) managerResource() *resourceMetricsBuilder {
	rb := b.resource("manager")
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", "sdwan_manager:"+firstNonEmpty(b.endpoint, "default"))
	putStr(attrs, "host.name", "Cisco Catalyst SD-WAN Manager")
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Catalyst SD-WAN Manager")
	putStr(attrs, "cisco.controller.type", "sdwan_manager")
	putStr(attrs, "cisco.controller.endpoint", b.endpoint)
	return rb
}

func (b *sdwanMetricsBuilder) deviceResource(device sdwan.Object) *resourceMetricsBuilder {
	hostID := firstNonEmpty(sdwanSerial(device), sdwan.String(device, "uuid", "deviceId"), sdwanSystemIP(device), sdwanHostName(device), "unknown")
	rb := b.resource("device:" + hostID)
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", hostID)
	putStr(attrs, "host.name", firstNonEmpty(sdwanHostName(device), hostID))
	putIPAttrs(attrs, "host.ip", sdwanSystemIP(device), sdwan.String(device, "managementIp"), sdwan.String(device, "mgmt-ip"), sdwan.String(device, "local-system-ip"))
	putStr(attrs, "host.type", firstNonEmpty(sdwanDeviceModel(device), sdwanDeviceType(device)))
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", sdwanOSName(device))
	putStr(attrs, "os.version", sdwan.String(device, "version", "softwareVersion", "device-os-version"))
	putStr(attrs, "cisco.controller.type", "sdwan_manager")
	putStr(attrs, "cisco.controller.endpoint", b.endpoint)
	putStr(attrs, "sdwan.system_ip", sdwanSystemIP(device))
	putStr(attrs, "sdwan.uuid", sdwan.String(device, "uuid", "deviceId"))
	putStr(attrs, "sdwan.chassis_serial", sdwan.String(device, "chasisNumber", "chassisSerialNumber", "chassis-serial-number"))
	putStr(attrs, "sdwan.board_serial", sdwan.String(device, "board-serial", "boardSerial", "boardSerialNumber"))
	putStr(attrs, "sdwan.site.id", sdwanSiteID(device))
	putStr(attrs, "sdwan.personality", sdwanPersonality(device))
	putStr(attrs, "sdwan.device.type", sdwanDeviceType(device))
	putStr(attrs, "sdwan.device.model", sdwanDeviceModel(device))
	putStr(attrs, "sdwan.validity", sdwan.String(device, "validity", "validity-status", "validityStatus"))
	putStr(attrs, "sdwan.certificate.validity", sdwan.String(device, "certificateValidity", "certificate-validity", "cert-validity"))
	return rb
}

func (b *sdwanMetricsBuilder) recordManagerObject(operation string, obj sdwan.Object) {
	rb := b.managerResource()
	rb.recordInt("sdwan.manager.endpoint.status", "Whether a Manager endpoint family returned data.", "1", 1, map[string]string{"sdwan.api.operation": operation})
	for _, field := range sdwanManagerUtilizationMetricFields {
		if value, ok := sdwan.Number(obj, field.field); ok {
			if ratio, valid := sdwanPercentRatio(value); valid {
				attrs := map[string]string{"sdwan.api.operation": operation, "sdwan.manager.field": field.field}
				if field.metricName == "system.cpu.utilization" {
					attrs["cpu.mode"] = "total"
				} else {
					attrs["system.memory.state"] = "used"
				}
				rb.recordDouble(field.metricName, field.description, field.unit, ratio, attrs)
			}
		}
	}
	for _, field := range sdwanManagerHealthMetricFields {
		if value, ok := sdwan.Number(obj, field.field); ok {
			rb.recordDouble(field.metricName, field.description, field.unit, value, map[string]string{"sdwan.api.operation": operation, "sdwan.manager.field": field.field})
		}
	}
	state := sdwan.String(obj, "status", "state", "health", "clusterStatus")
	if code, ok := statusCode(state); ok {
		rb.recordInt("sdwan.manager.status", "Encoded SD-WAN Manager status.", "1", code, map[string]string{"sdwan.status": state, "sdwan.api.operation": operation})
	}
}

func (b *sdwanMetricsBuilder) recordDevice(device sdwan.Object) {
	b.inventory.add(device)
	for _, key := range []string{sdwanSystemIP(device), sdwan.String(device, "uuid", "deviceId"), sdwanSerial(device), sdwanHostName(device)} {
		if key != "" {
			if _, exists := b.devices[key]; !exists {
				b.deviceKeys = append(b.deviceKeys, key)
			}
			b.devices[key] = device
		}
	}
	rb := b.deviceResource(device)
	attrs := compactAttrs(map[string]string{
		"sdwan.resource.type": sdwanPersonality(device),
		"sdwan.status":        sdwanDeviceStatus(device),
	})
	rb.recordInt("sdwan.resource.info", "Stable SD-WAN resource identity.", "1", 1, attrs)
	if code, ok := statusCode(sdwanDeviceStatus(device)); ok {
		rb.recordInt("sdwan.resource.status", "Encoded SD-WAN resource or opt-in object status.", "1", code, attrs)
	}
	if up, ok := upStatus(sdwan.String(device, "reachability", "reachabilityStatus", "status")); ok {
		rb.recordInt("sdwan.device.reachability.status", "Encoded SD-WAN device reachability.", "1", up, attrs)
		rb.recordInt("cisco.device.up", "Device availability (1 = up, 0 = down)", "1", up, attrs)
	}
	if validity := sdwan.String(device, "validity", "validity-status", "validityStatus"); validity != "" {
		if code, ok := statusCode(validity); ok {
			rb.recordInt("sdwan.device.validity.status", "Encoded device validity state.", "1", code, withAttr(attrs, "sdwan.validity", validity))
		}
	}
	if cert := sdwan.String(device, "certificateValidity", "certificate-validity", "cert-validity"); cert != "" {
		if code, ok := statusCode(cert); ok {
			rb.recordInt("sdwan.device.certificate.status", "Encoded certificate validity state.", "1", code, withAttr(attrs, "sdwan.certificate.validity", cert))
		}
	}
	recordSDWANPercentRatio(rb, device, "cpu", "system.cpu.utilization", "SD-WAN device CPU utilization as a ratio from 0 to 1.", withAttr(attrs, "cpu.mode", "total"), "cpuLoad", "cpu-load", "cpuUtilization", "cpu")
	recordSDWANPercentRatio(rb, device, "memory", "system.memory.utilization", "SD-WAN device memory utilization as a ratio from 0 to 1.", withAttr(attrs, "system.memory.state", "used"), "memUsage", "mem-usage", "memoryUtilization", "memory")
	recordSDWANInt(rb, device, "uptime", "system.uptime", "SD-WAN device uptime.", "s", attrs, "uptime-date", "uptimeSeconds", "upTime")
	b.addCount("sdwan.inventory.device.count", compactAttrs(map[string]string{
		"sdwan.personality":  sdwanPersonality(device),
		"sdwan.device.type":  sdwanDeviceType(device),
		"sdwan.device.model": sdwanDeviceModel(device),
		"sdwan.site.id":      sdwanSiteID(device),
		"sdwan.status":       sdwanDeviceStatus(device),
	}), 1)
}

func (b *sdwanMetricsBuilder) devicesForDetail() []sdwan.Object {
	seen := map[string]struct{}{}
	out := make([]sdwan.Object, 0, len(b.deviceKeys))
	for _, key := range b.deviceKeys {
		device := b.devices[key]
		hostID := firstNonEmpty(sdwanSerial(device), sdwan.String(device, "uuid", "deviceId"), sdwanSystemIP(device), sdwanHostName(device))
		if _, ok := seen[hostID]; ok {
			continue
		}
		seen[hostID] = struct{}{}
		out = append(out, device)
	}
	sort.Slice(out, func(i, j int) bool { return sdwanSystemIP(out[i]) < sdwanSystemIP(out[j]) })
	return out
}

func (b *sdwanMetricsBuilder) resource(key string) *resourceMetricsBuilder {
	if rb := b.resources[key]; rb != nil {
		return rb
	}
	rm := b.metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName(sdwanScopeName)
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

func (b *sdwanMetricsBuilder) recordServiceUnavailable(group, operation string, err error) {
	b.managerResource().recordInt("sdwan.service.unavailable", "Feature or endpoint was unavailable, unauthorized, unsupported, or missing.", "1", 1, compactAttrs(map[string]string{
		"sdwan.collection.group":     group,
		"sdwan.collection.operation": operation,
		"sdwan.error":                classifySDWANError(err),
	}))
}

func (b *sdwanMetricsBuilder) recordServiceSkipped(group, operation, reason string) {
	b.managerResource().recordInt("sdwan.service.skipped", "Feature or endpoint was skipped because target scope was missing.", "1", 1, compactAttrs(map[string]string{
		"sdwan.collection.group":     group,
		"sdwan.collection.operation": operation,
		"sdwan.skip.reason":          reason,
	}))
}

func (b *sdwanMetricsBuilder) addCount(name string, attrs map[string]string, increment int64) {
	if increment == 0 {
		return
	}
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
		existing.value += increment
		return
	}
	b.counts[key] = &sdwanCount{value: increment, attrs: attrs}
}

func (b *sdwanMetricsBuilder) flushCounts() {
	rb := b.managerResource()
	keys := make([]string, 0, len(b.counts))
	for key := range b.counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		count := b.counts[key]
		metricName, _, _ := strings.Cut(key, "|")
		rb.recordInt(metricName, sdwanCountDescription(metricName), "{item}", count.value, count.attrs)
	}
}

type sdwanLogsBuilder struct {
	logs      plog.Logs
	now       pcommon.Timestamp
	resources map[string]plog.ScopeLogs
	endpoint  string
}

func newSDWANLogsBuilder(now time.Time, endpoint string) *sdwanLogsBuilder {
	return &sdwanLogsBuilder{
		logs:      plog.NewLogs(),
		now:       pcommon.NewTimestampFromTime(now),
		resources: map[string]plog.ScopeLogs{},
		endpoint:  endpoint,
	}
}

func (b *sdwanLogsBuilder) emit() plog.Logs {
	return b.logs
}

func (b *sdwanLogsBuilder) appendEvent(name string, obj sdwan.Object) {
	sl := b.scope("manager")
	lr := sl.LogRecords().AppendEmpty()
	lr.SetTimestamp(sdwanLogTimestamp(obj))
	lr.SetObservedTimestamp(b.now)
	severity := firstNonEmpty(sdwan.String(obj, "severity", "severity_level", "severityLevel"), "info")
	lr.SetSeverityNumber(logSeverityNumber(severity))
	lr.SetSeverityText(severity)
	attrs := lr.Attributes()
	putStr(attrs, "event.domain", "sdwan")
	putStr(attrs, "event.name", name)
	putStr(attrs, "sdwan.severity", severity)
	putStr(attrs, "sdwan.status", sdwan.String(obj, "status", "state"))
	putStr(attrs, "sdwan.system_ip", sdwan.String(obj, "system-ip", "systemIp", "system_ip", "deviceId"))
	putStr(attrs, "sdwan.site.id", sdwan.String(obj, "site-id", "siteId", "site_id"))
	putStr(attrs, "sdwan.uuid", sdwan.String(obj, "uuid", "deviceId"))
	putStr(attrs, "sdwan.policy.name", sdwan.String(obj, "policy", "policyName", "policy-name"))
	putStr(attrs, "user.name", sdwan.String(obj, "user", "userName", "username"))
	putStr(attrs, "user.email", sdwan.String(obj, "email", "userEmail"))
	body := lr.Body().SetEmptyMap()
	putSDWANLogObject(body, obj)
}

func (b *sdwanLogsBuilder) scope(key string) plog.ScopeLogs {
	if sl, ok := b.resources[key]; ok {
		return sl
	}
	rl := b.logs.ResourceLogs().AppendEmpty()
	attrs := rl.Resource().Attributes()
	putStr(attrs, "host.id", "sdwan_manager:"+firstNonEmpty(b.endpoint, "default"))
	putStr(attrs, "host.name", "Cisco Catalyst SD-WAN Manager")
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Catalyst SD-WAN Manager")
	putStr(attrs, "cisco.controller.type", "sdwan_manager")
	putStr(attrs, "cisco.controller.endpoint", b.endpoint)
	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName(sdwanScopeName)
	b.resources[key] = sl
	return sl
}

type sdwanTargetMatcher struct {
	siteIDs             map[string]struct{}
	systemIPs           map[string]struct{}
	uuids               map[string]struct{}
	serials             map[string]struct{}
	deviceTypes         map[string]struct{}
	personalities       map[string]struct{}
	colors              map[string]struct{}
	interfaceNames      map[string]struct{}
	vpnIDs              map[string]struct{}
	applications        map[string]struct{}
	applicationFamilies map[string]struct{}
	cloudProviders      map[string]struct{}
	serviceTypes        map[string]struct{}
}

type sdwanDeviceIndex map[string]sdwan.Object

func (idx sdwanDeviceIndex) add(device sdwan.Object) {
	for _, key := range sdwanDeviceLookupKeys(device) {
		idx[key] = device
	}
}

func (idx sdwanDeviceIndex) enrich(obj sdwan.Object) (sdwan.Object, bool) {
	for _, key := range sdwanDeviceLookupKeys(obj) {
		device, ok := idx[key]
		if !ok {
			continue
		}
		merged := make(sdwan.Object, len(device)+len(obj))
		maps.Copy(merged, device)
		maps.Copy(merged, obj)
		return merged, true
	}
	return obj, false
}

func sdwanDeviceLookupKeys(obj sdwan.Object) []string {
	keys := make([]string, 0, 4)
	add := func(kind, value string) {
		value = normalizeSelectorText(value)
		if value != "" {
			keys = append(keys, kind+":"+value)
		}
	}
	add("ip", sdwanSystemIP(obj))
	add("uuid", sdwan.String(obj, "uuid", "deviceId"))
	add("serial", sdwanSerial(obj))
	add("host", sdwanHostName(obj))
	return keys
}

func newSDWANTargetMatcher(cfg SDWANTargetFilters) sdwanTargetMatcher {
	return sdwanTargetMatcher{
		siteIDs:             normalizedSet(cfg.SiteIDs, normalizeSelectorText),
		systemIPs:           normalizedSet(cfg.SystemIPs, normalizeSelectorIP),
		uuids:               normalizedSet(cfg.UUIDs, normalizeSelectorText),
		serials:             normalizedSet(cfg.Serials, normalizeSelectorText),
		deviceTypes:         normalizedSet(cfg.DeviceTypes, normalizeSelectorText),
		personalities:       normalizedSet(cfg.Personalities, normalizeSelectorText),
		colors:              normalizedSet(cfg.Colors, normalizeSelectorText),
		interfaceNames:      normalizedSet(cfg.InterfaceNames, normalizeSelectorText),
		vpnIDs:              normalizedSet(cfg.VPNIDs, normalizeSelectorText),
		applications:        normalizedSet(cfg.Applications, normalizeSelectorText),
		applicationFamilies: normalizedSet(cfg.ApplicationFamilies, normalizeSelectorText),
		cloudProviders:      normalizedSet(cfg.CloudProviders, normalizeSelectorText),
		serviceTypes:        normalizedSet(cfg.ServiceTypes, normalizeSelectorText),
	}
}

func (m sdwanTargetMatcher) hasAny() bool {
	return len(m.siteIDs) > 0 || len(m.systemIPs) > 0 || len(m.uuids) > 0 || len(m.serials) > 0 ||
		len(m.deviceTypes) > 0 || len(m.personalities) > 0 || len(m.colors) > 0 || len(m.interfaceNames) > 0 ||
		len(m.vpnIDs) > 0 || len(m.applications) > 0 || len(m.applicationFamilies) > 0 || len(m.cloudProviders) > 0 || len(m.serviceTypes) > 0
}

func (m sdwanTargetMatcher) hasSystemIPs() bool {
	return len(m.systemIPs) > 0
}

func (m sdwanTargetMatcher) allowsDevice(obj sdwan.Object) bool {
	return targetMatch(m.siteIDs, []string{sdwanSiteID(obj)}, normalizeSelectorText) &&
		targetMatch(m.systemIPs, []string{sdwanSystemIP(obj)}, normalizeSelectorIP) &&
		targetMatch(m.uuids, []string{sdwan.String(obj, "uuid", "deviceId")}, normalizeSelectorText) &&
		targetMatch(m.serials, []string{sdwanSerial(obj)}, normalizeSelectorText) &&
		targetMatch(m.deviceTypes, []string{sdwanDeviceType(obj), sdwanDeviceModel(obj)}, normalizeSelectorText) &&
		targetMatch(m.personalities, []string{sdwanPersonality(obj)}, normalizeSelectorText)
}

func (m sdwanTargetMatcher) allowsInterface(obj sdwan.Object) bool {
	return targetMatch(m.interfaceNames, []string{sdwan.String(obj, "ifname", "interface", "interfaceName", "name", "if-name")}, normalizeSelectorText) &&
		targetMatch(m.colors, []string{sdwan.String(obj, "color", "local-color", "localColor")}, normalizeSelectorText) &&
		targetMatch(m.vpnIDs, []string{sdwan.String(obj, "vpn-id", "vpnId", "vpn")}, normalizeSelectorText)
}

func (m sdwanTargetMatcher) allowsPath(obj sdwan.Object) bool {
	return targetMatch(m.colors, []string{
		sdwan.String(obj, "color", "local-color", "localColor"),
		sdwan.String(obj, "remote-color", "remoteColor"),
	}, normalizeSelectorText) &&
		targetMatch(m.vpnIDs, []string{sdwan.String(obj, "vpn-id", "vpnId", "vpn")}, normalizeSelectorText)
}

func (m sdwanTargetMatcher) allowsApplicationPath(obj sdwan.Object) bool {
	return m.allowsPath(obj) &&
		targetMatch(m.applications, []string{sdwan.String(obj, "application", "app", "app-name", "appName")}, normalizeSelectorText) &&
		targetMatch(m.applicationFamilies, []string{sdwan.String(obj, "application-family", "applicationFamily", "app-family", "appFamily")}, normalizeSelectorText)
}

func (m sdwanTargetMatcher) allowsEvent(obj sdwan.Object) bool {
	return m.allowsDevice(obj) &&
		targetMatch(m.colors, []string{
			sdwan.String(obj, "color", "local-color", "localColor"),
			sdwan.String(obj, "remote-color", "remoteColor"),
		}, normalizeSelectorText) &&
		targetMatch(m.interfaceNames, []string{sdwan.String(obj, "ifname", "interface", "interfaceName", "name", "if-name")}, normalizeSelectorText) &&
		targetMatch(m.vpnIDs, []string{sdwan.String(obj, "vpn-id", "vpnId", "vpn")}, normalizeSelectorText) &&
		targetMatch(m.applications, []string{sdwan.String(obj, "application", "app", "app-name", "appName")}, normalizeSelectorText) &&
		targetMatch(m.applicationFamilies, []string{sdwan.String(obj, "application-family", "applicationFamily", "app-family", "appFamily")}, normalizeSelectorText) &&
		targetMatch(m.cloudProviders, []string{sdwan.String(obj, "cloud-provider", "cloudProvider", "provider")}, normalizeSelectorText) &&
		targetMatch(m.serviceTypes, []string{sdwan.String(obj, "service-type", "serviceType", "service")}, normalizeSelectorText)
}

func sdwanEventAllowed(obj sdwan.Object, inventory sdwanDeviceIndex, selector deviceSelectionMatcher, targets sdwanTargetMatcher) bool {
	enriched, matchedInventory := inventory.enrich(obj)
	if !targets.allowsEvent(enriched) {
		return false
	}
	if selector.empty() {
		return true
	}
	// Event records commonly contain only a system IP. Requiring inventory
	// enrichment before evaluating shared filters prevents a serial, host-name,
	// or device-ID exclusion from being bypassed by that reduced event shape.
	if !matchedInventory {
		return false
	}
	return selector.allows(sdwanEventIdentity(enriched))
}

func sdwanEventIdentity(obj sdwan.Object) deviceIdentity {
	serial := sdwanSerial(obj)
	systemIP := sdwanSystemIP(obj)
	uuid := sdwan.String(obj, "uuid", "deviceId")
	siteID := sdwanSiteID(obj)
	return deviceIdentity{
		hostNames: []string{sdwanHostName(obj)},
		hostIDs:   []string{serial, uuid, systemIP, siteID},
		hostIPs:   []string{systemIP, sdwan.String(obj, "managementIp", "mgmt-ip", "local-system-ip")},
		serials:   []string{serial},
		deviceIDs: []string{uuid, systemIP},
	}
}

func targetMatch(set map[string]struct{}, values []string, normalize func(string) string) bool {
	if len(set) == 0 {
		return true
	}
	return matchAny(set, values, normalize)
}

type sdwanOptInGroup struct {
	name            string
	config          SDWANGroupConfig
	requiresTargets bool
	specs           []sdwanEndpointSpec
}

func sdwanOptInGroups(cfg SDWANConfig) []sdwanOptInGroup {
	return []sdwanOptInGroup{
		{"realtime_details", cfg.RealtimeDetails, true, []sdwanEndpointSpec{{"realtime_details", "realtime.system_status", "/device/system/status", true}}},
		{"tunnels", cfg.Tunnels, false, []sdwanEndpointSpec{{"tunnels", "tunnels.ipsec", "/device/ipsec/localsa", true}, {"tunnels", "tunnels.transport", "/device/tunnel/statistics", true}}},
		{"flows", cfg.Flows, false, []sdwanEndpointSpec{{"flows", "flows.dpi", "/device/dpi/applications", true}, {"flows", "flows.cflowd", "/device/cflowd/flows", true}}},
		{"policy_qos", cfg.PolicyQoS, false, []sdwanEndpointSpec{{"policy_qos", "policy_qos.acl", "/device/policy/accesslistcounters", true}, {"policy_qos", "policy_qos.qos", "/device/qos/queue_stats", true}}},
		{"security", cfg.Security, false, []sdwanEndpointSpec{{"security", "security.umbrella", "/device/umbrella/overview", true}, {"security", "security.zbfw", "/device/zbfw/statistics", true}, {"security", "security.utd", "/device/utd/dataplane/stats", true}}},
		{"appqoe", cfg.AppQoE, false, []sdwanEndpointSpec{{"appqoe", "appqoe.status", "/device/appqoe/status", true}, {"appqoe", "appqoe.dre", "/device/dre/status", true}}},
		{"cloud_onramp", cfg.CloudOnRamp, false, []sdwanEndpointSpec{{"cloud_onramp", "cloud_onramp.saas", "/device/cloudx/applications", true}, {"cloud_onramp", "cloud_onramp.gateways", "/cloudservices/status", false}}},
		{"nwpi", cfg.NWPI, false, []sdwanEndpointSpec{{"nwpi", "nwpi.tasks", "/stream/device/nwpi/tasks", false}, {"nwpi", "nwpi.events", "/stream/device/nwpi/eventReadout", false}}},
		{"underlay", cfg.Underlay, false, []sdwanEndpointSpec{{"underlay", "underlay.summary", "/device/underlay/summary", true}, {"underlay", "underlay.alarms", "/underlay/alarm/overview", false}}},
		{"cellular", cfg.Cellular, false, []sdwanEndpointSpec{{"cellular", "cellular.radio", "/device/cellular/radio", true}, {"cellular", "cellular.sessions", "/device/cellular/sessions", true}}},
		{"hardware_energy", cfg.HardwareEnergy, false, []sdwanEndpointSpec{{"hardware_energy", "hardware.environment", "/device/environment", true}, {"hardware_energy", "hardware.energy", "/device/power-consumption", true}}},
		{"routing_services", cfg.RoutingServices, false, []sdwanEndpointSpec{{"routing_services", "routing.bgp", "/device/bgp/neighbors", true}, {"routing_services", "routing.routes", "/device/ip/routes", true}}},
		{"branch_services", cfg.BranchServices, false, []sdwanEndpointSpec{{"branch_services", "branch.wlan", "/device/wlan/clients", true}, {"branch_services", "branch.voice", "/device/voice/calls", true}}},
		{"lifecycle_compliance", cfg.LifecycleCompliance, false, []sdwanEndpointSpec{{"lifecycle_compliance", "lifecycle.reboot", "/device/reboot/history", true}, {"lifecycle_compliance", "lifecycle.crashlog", "/device/crashlog/synced", true}}},
		{"thousandeyes", cfg.ThousandEyes, false, []sdwanEndpointSpec{{"thousandeyes", "thousandeyes.agents", "/device/thousandeyes/agents", true}}},
		{"management_security", cfg.ManagementSecurity, false, []sdwanEndpointSpec{{"management_security", "management.users", "/admin/user", false}, {"management_security", "management.sessions", "/admin/user/activeSessions", false}}},
	}
}

func sdwanControlPlaneSpecs() []sdwanEndpointSpec {
	return []sdwanEndpointSpec{
		{group: "control_plane", operation: "control.connections", path: "/device/control/synced/connections", deviceScoped: true},
	}
}

func sdwanBFDSpecs() []sdwanEndpointSpec {
	return []sdwanEndpointSpec{
		{group: "bfd", operation: "bfd.sessions", path: "/device/bfd/synced/sessions", deviceScoped: true},
	}
}

func sdwanAppRouteSpecs() []sdwanEndpointSpec {
	return []sdwanEndpointSpec{
		{group: "app_route", operation: "app_route.statistics", path: "/device/app-route/statistics", deviceScoped: true},
	}
}

func sdwanInterfaceSpecs() []sdwanEndpointSpec {
	return []sdwanEndpointSpec{
		{group: "interfaces", operation: "interfaces.synced", path: "/device/interface/synced", deviceScoped: true},
	}
}

func allSDWANSpecsDeviceScoped(specs []sdwanEndpointSpec) bool {
	for _, spec := range specs {
		if !spec.deviceScoped {
			return false
		}
	}
	return true
}

func selectedSDWANDevices(devices []sdwan.Object, selector deviceSelectionMatcher, targets sdwanTargetMatcher, maxResults int) []sdwan.Object {
	out := make([]sdwan.Object, 0, len(devices))
	for _, device := range devices {
		if !targets.allowsDevice(device) || !selector.allows(sdwanObjectIdentity(device)) {
			continue
		}
		out = append(out, device)
		if maxResults > 0 && len(out) >= maxResults {
			break
		}
	}
	return out
}

func syntheticSDWANDevices(systemIPs map[string]struct{}) []sdwan.Object {
	out := make([]sdwan.Object, 0, len(systemIPs))
	for systemIP := range systemIPs {
		out = append(out, sdwan.Object{"system-ip": systemIP})
	}
	sort.Slice(out, func(i, j int) bool { return sdwanSystemIP(out[i]) < sdwanSystemIP(out[j]) })
	return out
}

func sdwanLookbackQuery(lookback time.Duration, maxResults int) map[string]any {
	if lookback <= 0 {
		lookback = defaultSDWANConfig().EventLookback
	}
	hours := int64(lookback / time.Hour)
	if lookback%time.Hour != 0 {
		hours++
	}
	if hours < 1 {
		hours = 1
	}
	size := maxResults
	if size <= 0 {
		size = 1000
	}
	return map[string]any{
		"query": map[string]any{
			"condition": "AND",
			"rules": []map[string]any{{
				"field":    "entry_time",
				"type":     "date",
				"operator": "last_n_hours",
				"value":    []string{strconv.FormatInt(hours, 10)},
			}},
		},
		"size": size,
	}
}

func sdwanEventGroupsEnabled(cfg SDWANConfig) bool {
	return cfg.Alarms.Enabled || cfg.Events.Enabled || cfg.Audit.Enabled
}

func sdwanPathAttrs(device, obj sdwan.Object) map[string]string {
	return compactAttrs(map[string]string{
		"sdwan.system_ip":        sdwanSystemIP(device),
		"sdwan.remote.system_ip": sdwan.String(obj, "remote-system-ip", "remoteSystemIp", "remote_system_ip", "dst-ip"),
		"sdwan.local.color":      sdwan.String(obj, "local-color", "localColor", "color"),
		"sdwan.remote.color":     sdwan.String(obj, "remote-color", "remoteColor"),
		"sdwan.tloc.color":       sdwan.String(obj, "color", "local-color", "localColor"),
		"sdwan.vpn.id":           sdwan.String(obj, "vpn-id", "vpnId", "vpn"),
		"network.interface.name": sdwan.String(obj, "ifname", "interface", "interfaceName", "name", "if-name"),
	})
}

func sdwanSystemIP(obj sdwan.Object) string {
	return sdwan.String(obj, "system-ip", "systemIp", "system_ip", "vdevice-name", "deviceIP", "deviceIp")
}

func sdwanSiteID(obj sdwan.Object) string {
	return sdwan.String(obj, "site-id", "siteId", "site_id")
}

func sdwanSerial(obj sdwan.Object) string {
	return firstNonEmpty(
		sdwan.String(obj, "chasisNumber", "chassisSerialNumber", "chassis-serial-number"),
		sdwan.String(obj, "board-serial", "boardSerial", "boardSerialNumber"),
		sdwan.String(obj, "serialNumber", "serial-number", "serial"),
	)
}

func sdwanHostName(obj sdwan.Object) string {
	return sdwan.String(obj, "host-name", "hostName", "hostname", "name")
}

func sdwanPersonality(obj sdwan.Object) string {
	return sdwan.String(obj, "personality", "device-type", "deviceType")
}

func sdwanDeviceType(obj sdwan.Object) string {
	return sdwan.String(obj, "device-type", "deviceType", "personality")
}

func sdwanDeviceModel(obj sdwan.Object) string {
	return sdwan.String(obj, "device-model", "deviceModel", "model", "platform", "platformId")
}

func sdwanDeviceStatus(obj sdwan.Object) string {
	return sdwan.String(obj, "status", "state", "reachability", "reachabilityStatus")
}

func sdwanOSName(obj sdwan.Object) string {
	personality := strings.ToLower(sdwanPersonality(obj))
	if strings.Contains(personality, "vmanage") || strings.Contains(personality, "manager") {
		return "Catalyst SD-WAN Manager"
	}
	if strings.Contains(personality, "vsmart") || strings.Contains(personality, "controller") {
		return "Catalyst SD-WAN Controller"
	}
	if strings.Contains(personality, "vbond") || strings.Contains(personality, "validator") {
		return "Catalyst SD-WAN Validator"
	}
	return "Cisco IOS XE SD-WAN"
}

func recordSDWANDouble(rb *resourceMetricsBuilder, obj sdwan.Object, field, name, description, unit string, attrs map[string]string, keys ...string) {
	value, ok := sdwan.Number(obj, keys...)
	if !ok {
		return
	}
	rb.recordDouble(name, description, unit, value, withAttr(attrs, "sdwan.field", field))
}

func recordSDWANAbsoluteSumInt(rb *resourceMetricsBuilder, obj sdwan.Object, field, name, description, unit string, attrs map[string]string, keys ...string) {
	value, ok := sdwan.Int(obj, keys...)
	if !ok || value < 0 {
		return
	}
	rb.recordAbsoluteSumInt(name, description, unit, value, withAttr(attrs, "sdwan.field", field))
}

func recordSDWANInt(rb *resourceMetricsBuilder, obj sdwan.Object, field, name, description, unit string, attrs map[string]string, keys ...string) {
	value, ok := sdwan.Int(obj, keys...)
	if !ok {
		return
	}
	rb.recordInt(name, description, unit, value, withAttr(attrs, "sdwan.field", field))
}

func recordSDWANPercentRatio(rb *resourceMetricsBuilder, obj sdwan.Object, field, name, description string, attrs map[string]string, keys ...string) {
	value, ok := sdwan.Number(obj, keys...)
	if !ok {
		return
	}
	ratio, ok := sdwanPercentRatio(value)
	if !ok {
		return
	}
	rb.recordDouble(name, description, "1", ratio, withAttr(attrs, "sdwan.field", field))
}

func sdwanPercentRatio(value float64) (float64, bool) {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 100 {
		return 0, false
	}
	if value <= 1 {
		return value, true
	}
	return value / 100, true
}

func recordSDWANInterfaceSpeed(rb *resourceMetricsBuilder, obj sdwan.Object, attrs map[string]string) {
	const bitsPerMegabit = int64(1_000_000)
	if speedMbps, ok := sdwan.Int(obj, "speed-mbps", "speedMbps"); ok && speedMbps >= 0 && speedMbps <= math.MaxInt64/bitsPerMegabit {
		rb.recordInt("cisco.interface.speed", "The numeric line speed of a Cisco interface", "bit/s", speedMbps*bitsPerMegabit, withAttr(attrs, "sdwan.field", "speed-mbps"))
		return
	}
	if speedMbps, ok := sdwan.Number(obj, "speed-mbps", "speedMbps"); ok && speedMbps >= 0 && !math.IsNaN(speedMbps) && !math.IsInf(speedMbps, 0) {
		speedBits := speedMbps * float64(bitsPerMegabit)
		// cisco.interface.speed is declared as an integer gauge. Fractional
		// megabits are still valid when they resolve to an exact whole bit rate,
		// but must not change the metric descriptor's datapoint value type.
		if speedBits < float64(math.MaxInt64) && math.Trunc(speedBits) == speedBits {
			rb.recordInt("cisco.interface.speed", "The numeric line speed of a Cisco interface", "bit/s", int64(speedBits), withAttr(attrs, "sdwan.field", "speed-mbps"))
			return
		}
	}
	recordSDWANInt(rb, obj, "speed", "cisco.interface.speed", "SD-WAN interface speed.", "bit/s", attrs, "speed")
}

func recordSDWANInterfaceRate(rb *resourceMetricsBuilder, obj sdwan.Object, field string, attrs map[string]string, keys ...string) {
	value, ok := sdwan.Number(obj, keys...)
	if !ok || value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return
	}
	rate := value * 1000
	if math.IsInf(rate, 0) {
		return
	}
	rb.recordDouble("cisco.interface.io.rate", "The device-reported interface traffic rate", "bit/s", rate, withAttr(attrs, "sdwan.field", field))
}

func (rb *resourceMetricsBuilder) recordAbsoluteSumInt(name, description, unit string, value int64, attrs map[string]string) {
	description, unit = governedFixedMetricMetadata(name, pmetric.MetricTypeSum, fixedMetricValueTypeInt, description, unit)
	dp := rb.sumMetric(name, description, unit).Sum().DataPoints().AppendEmpty()
	dp.SetTimestamp(rb.now)
	dp.SetStartTimestamp(rb.start)
	dp.SetIntValue(value)
	putAttrs(dp.Attributes(), attrs)
}

func sdwanCountDescription(name string) string {
	switch name {
	case "sdwan.inventory.device.count":
		return "SD-WAN device inventory count grouped by device attributes."
	case "sdwan.event.count":
		return "SD-WAN alarm, event, and audit records grouped by bounded attributes."
	case "sdwan.control.connection.count":
		return "SD-WAN control connection count grouped by connection attributes."
	case "sdwan.bfd.session.count":
		return "SD-WAN BFD session count grouped by session attributes."
	case "sdwan.collection.object.count":
		return "SD-WAN opt-in collection object count grouped by endpoint family."
	default:
		return "SD-WAN grouped count."
	}
}

func sdwanLogTimestamp(obj sdwan.Object) pcommon.Timestamp {
	for _, key := range []string{"entry_time", "entryTime", "timestamp", "time", "createTime", "eventTime"} {
		raw := sdwan.String(obj, key)
		if raw == "" {
			continue
		}
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil {
			var candidate time.Time
			if parsed > 1_000_000_000_000 {
				candidate = time.UnixMilli(parsed)
			} else {
				candidate = time.Unix(parsed, 0)
			}
			if timestamp, valid := pdataTimestampFromTime(candidate); valid {
				return timestamp
			}
			continue
		}
		if ts, err := time.Parse(time.RFC3339, raw); err == nil {
			if timestamp, valid := pdataTimestampFromTime(ts); valid {
				return timestamp
			}
		}
	}
	return 0
}

func putSDWANLogObject(target pcommon.Map, obj sdwan.Object) {
	for key, value := range obj {
		setLogValue(target, key, value)
	}
}
