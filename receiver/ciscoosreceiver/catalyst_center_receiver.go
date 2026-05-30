// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/catalystcenter"
)

const (
	catalystCenterScopeName           = "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/catalystcenter"
	catalystCenterSiteHealthPageLimit = 20
)

type catalystCenterMetricsReceiver struct {
	settings receiver.Settings
	config   *Config
	consumer consumer.Metrics
	client   *catalystcenter.Client
	counters *counterStore
	obs      *receiverhelper.ObsReport

	startMu sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}

	statsMu sync.Mutex
	stats   []catalystcenter.RequestStat
}

type catalystCenterCount struct {
	value int64
	attrs map[string]string
}

func newCatalystCenterMetricsReceiver(set receiver.Settings, conf *Config, consumer consumer.Metrics) (*catalystCenterMetricsReceiver, error) {
	client, err := catalystcenter.NewClient(catalystcenter.Config{
		Endpoint:           conf.CatalystCenter.Endpoint,
		AuthMode:           inferredCatalystCenterAuthMode(conf.CatalystCenter.Auth),
		Username:           conf.CatalystCenter.Auth.Username,
		Password:           string(conf.CatalystCenter.Auth.Password),
		AESCredentials:     string(conf.CatalystCenter.Auth.AESCredentials),
		UserAgent:          conf.CatalystCenter.UserAgent,
		Timeout:            conf.Timeout,
		MaxRetries:         conf.CatalystCenter.MaxRetries,
		PageSize:           conf.CatalystCenter.PageSize,
		InsecureSkipVerify: conf.CatalystCenter.InsecureSkipVerify,
	})
	if err != nil {
		return nil, err
	}
	r := &catalystCenterMetricsReceiver{
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

func (r *catalystCenterMetricsReceiver) Start(_ context.Context, _ component.Host) error {
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

func (r *catalystCenterMetricsReceiver) Shutdown(ctx context.Context) error {
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

func (r *catalystCenterMetricsReceiver) run(ctx context.Context) {
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

func (r *catalystCenterMetricsReceiver) collect(ctx context.Context) {
	scrapeCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()

	obsCtx := startMetricsOp(r.obs, ctx)
	md, err := r.scrape(scrapeCtx)
	if err != nil {
		r.settings.Logger.Error("Catalyst Center scrape failed", zap.Error(err))
		endMetricsOp(r.obs, obsCtx, md, err)
		return
	}
	if md.MetricCount() == 0 {
		endMetricsOp(r.obs, obsCtx, md, nil)
		return
	}
	consumeErr := r.consumer.ConsumeMetrics(ctx, md)
	endMetricsOp(r.obs, obsCtx, md, consumeErr)
	if consumeErr != nil {
		r.settings.Logger.Error("Catalyst Center metrics consumer failed", zap.Error(consumeErr))
	}
}

func (r *catalystCenterMetricsReceiver) scrape(ctx context.Context) (pmetric.Metrics, error) {
	r.resetRequestStats()
	now := time.Now()
	builder := newCatalystCenterMetricsBuilder(now, r.config.CatalystCenter.Endpoint, r.counters)
	selector := newDeviceSelectionMatcher(r.config.DeviceSelection)
	partial := false

	if r.config.CatalystCenter.Inventory.Enabled {
		if err := r.scrapeInventory(ctx, builder, selector); err != nil {
			if ctx.Err() != nil {
				return builder.emit(), ctx.Err()
			}
			partial = true
			r.settings.Logger.Warn("Catalyst Center inventory endpoint failed", zap.Error(err))
		}
	}
	if r.config.CatalystCenter.Interfaces.Enabled {
		if err := r.scrapeInterfaces(ctx, builder, selector); err != nil {
			if ctx.Err() != nil {
				return builder.emit(), ctx.Err()
			}
			partial = true
			r.settings.Logger.Warn("Catalyst Center interface endpoint failed", zap.Error(err))
		}
	}
	if r.config.CatalystCenter.Health.Enabled {
		if r.scrapeHealth(ctx, builder, now) {
			partial = true
		}
	}
	if r.config.CatalystCenter.Topology.Enabled {
		if err := r.scrapeTopology(ctx, builder, selector); err != nil {
			if ctx.Err() != nil {
				return builder.emit(), ctx.Err()
			}
			partial = true
			r.settings.Logger.Warn("Catalyst Center topology endpoint failed", zap.Error(err))
		}
	}
	if r.config.CatalystCenter.Issues.Enabled {
		if err := r.scrapeIssues(ctx, builder, now, selector); err != nil {
			if ctx.Err() != nil {
				return builder.emit(), ctx.Err()
			}
			partial = true
			r.settings.Logger.Warn("Catalyst Center issues endpoint failed", zap.Error(err))
		}
	}
	if r.config.CatalystCenter.Details.Enabled {
		if r.scrapeDetails(ctx, builder, selector) {
			partial = true
		}
	}

	r.recordAPIRequestMetrics(builder)
	builder.accountResource().recordInt("catalyst_center.scrape.partial_success", "Whether one or more Catalyst Center endpoint families failed during the scrape.", "1", boolToInt(partial), nil)
	builder.accountResource().recordInt("catalyst_center.scrape.last_success", "Unix timestamp of the most recent Catalyst Center scrape completion.", "s", now.Unix(), nil)
	builder.flushCounts()
	return builder.emit(), nil
}

func (r *catalystCenterMetricsReceiver) scrapeInventory(ctx context.Context, builder *catalystCenterMetricsBuilder, selector deviceSelectionMatcher) error {
	if count, err := catalystcenter.GetCount(ctx, r.client, "devices.count", "/dna/intent/api/v1/network-device/count", nil); err == nil {
		builder.accountResource().recordInt("catalyst_center.inventory.device.count", "Catalyst Center network-device inventory count.", "{device}", count, nil)
	}
	devices, err := catalystcenter.GetPaginatedJSON[catalystcenter.Device](ctx, r.client, "devices", "/dna/intent/api/v1/network-device", nil, r.config.CatalystCenter.Inventory.MaxResults)
	if err != nil {
		return err
	}
	for _, device := range devices {
		if !selector.allows(catalystDeviceIdentity(device)) {
			continue
		}
		rb := builder.deviceResource(device)
		rb.recordInt("cisco.device.up", "Device availability reported by Catalyst Center.", "1", reachableStatus(device.ReachabilityStatus), nil)
		recordCatalystStatus(rb, "catalyst_center.device.reachability.status", "Catalyst Center device reachability status.", device.ReachabilityStatus, map[string]string{
			"catalyst_center.device.collection_status": device.CollectionStatus,
		})
		recordCatalystStatus(rb, "catalyst_center.device.collection.status", "Catalyst Center device collection status.", device.CollectionStatus, nil)
		if value, ok := parseIntString(device.InterfaceCount); ok {
			rb.recordInt("catalyst_center.device.interface.count", "Interface count reported for a Catalyst Center device.", "{interface}", value, nil)
		}
		if device.UptimeSeconds > 0 {
			rb.recordInt("catalyst_center.device.uptime", "Device uptime reported by Catalyst Center.", "s", device.UptimeSeconds, nil)
		}
	}
	return nil
}

func (r *catalystCenterMetricsReceiver) scrapeInterfaces(ctx context.Context, builder *catalystCenterMetricsBuilder, selector deviceSelectionMatcher) error {
	if count, err := catalystcenter.GetCount(ctx, r.client, "interfaces.count", "/dna/intent/api/v1/interface/count", nil); err == nil {
		builder.accountResource().recordInt("catalyst_center.interface.count", "Catalyst Center interface inventory count.", "{interface}", count, nil)
	}
	interfaces, err := catalystcenter.GetPaginatedJSON[catalystcenter.Interface](ctx, r.client, "interfaces", "/dna/intent/api/v1/interface", nil, r.config.CatalystCenter.Interfaces.MaxResults)
	if err != nil {
		return err
	}
	for _, iface := range interfaces {
		device, _ := builder.deviceFor(firstNonEmpty(iface.DeviceID, iface.SerialNo, iface.MacAddress))
		if !selector.allows(catalystInterfaceIdentity(iface, device)) {
			continue
		}
		rb := builder.interfaceResource(iface)
		attrs := catalystInterfaceAttrs(iface)
		if iface.Status != "" {
			rb.recordInt("system.network.interface.status", "Interface operational status reported by Catalyst Center.", "1", connectedStatus(iface.Status), attrs)
		}
		if iface.AdminStatus != "" {
			rb.recordInt("cisco.interface.admin.status", "Interface administrative status reported by Catalyst Center.", "1", connectedStatus(iface.AdminStatus), attrs)
		}
		if speed, speedText := parseCatalystSpeed(iface.Speed); speed > 0 {
			rb.recordInt("cisco.interface.speed", "Interface line speed reported by Catalyst Center.", "bit/s", speed, withAttr(attrs, "network.interface.speed", speedText))
		}
	}
	return nil
}

func (r *catalystCenterMetricsReceiver) scrapeHealth(ctx context.Context, builder *catalystCenterMetricsBuilder, now time.Time) bool {
	partial := false
	networkHealth, err := catalystcenter.GetJSON[catalystcenter.NetworkHealth](ctx, r.client, "network_health", "/dna/intent/api/v1/network-health", nil)
	if err != nil {
		r.settings.Logger.Warn("Catalyst Center network health endpoint failed", zap.Error(err))
		partial = true
	} else {
		builder.recordNetworkHealth(networkHealth)
	}

	clientHealth, err := catalystcenter.GetJSON[catalystcenter.ClientHealth](ctx, r.client, "client_health", "/dna/intent/api/v1/client-health", nil)
	if err != nil {
		r.settings.Logger.Warn("Catalyst Center client health endpoint failed", zap.Error(err))
		partial = true
	} else {
		builder.recordClientHealth(clientHealth)
	}

	siteQuery := catalystWindowQuery(r.config.CatalystCenter.Lookback, now)
	sites, err := catalystcenter.GetPaginatedJSONWithPageLimit[catalystcenter.SiteHealthSummary](ctx, r.client, "site_health", "/dna/data/api/v1/siteHealthSummaries", siteQuery, r.config.CatalystCenter.Health.MaxResults, catalystCenterSiteHealthPageLimit)
	if err != nil {
		r.settings.Logger.Warn("Catalyst Center site health endpoint failed", zap.Error(err))
		partial = true
	} else {
		for _, site := range sites {
			builder.recordSiteHealth(site)
		}
	}
	return partial
}

func (r *catalystCenterMetricsReceiver) scrapeTopology(ctx context.Context, builder *catalystCenterMetricsBuilder, selector deviceSelectionMatcher) error {
	topology, err := catalystcenter.GetResponseJSON[catalystcenter.Topology](ctx, r.client, "physical_topology", "/dna/intent/api/v1/topology/physical-topology", url.Values{"nodeType": {"device"}})
	if err != nil {
		return err
	}
	builder.recordTopology(topology, r.config.CatalystCenter.Topology.MaxResults, selector)
	return nil
}

func (r *catalystCenterMetricsReceiver) scrapeIssues(ctx context.Context, builder *catalystCenterMetricsBuilder, now time.Time, selector deviceSelectionMatcher) error {
	query := catalystWindowQuery(r.config.CatalystCenter.Lookback, now)
	if selector.empty() {
		if count, err := catalystcenter.GetCount(ctx, r.client, "issues.count", "/dna/data/api/v1/assuranceIssues/count", query); err == nil {
			builder.accountResource().recordInt("catalyst_center.issue.count", "Catalyst Center assurance issue count in the configured lookback window.", "{issue}", count, map[string]string{"catalyst_center.issue.window": "lookback"})
		}
	}
	startTime, _ := strconv.ParseInt(query.Get("startTime"), 10, 64)
	endTime, _ := strconv.ParseInt(query.Get("endTime"), 10, 64)
	body := map[string]any{
		"startTime": startTime,
		"endTime":   endTime,
		"filters":   []any{},
	}
	issues, err := catalystcenter.PostPaginatedJSON[catalystcenter.Issue](ctx, r.client, "issues.query", "/dna/data/api/v1/assuranceIssues/query", body, r.config.CatalystCenter.Issues.MaxResults)
	if err != nil {
		return err
	}
	selectedIssues := 0
	for _, issue := range issues {
		device, _ := builder.deviceFor(issue.EntityID)
		if !selector.allows(catalystIssueIdentity(issue, device)) {
			continue
		}
		selectedIssues++
		builder.addCount("catalyst_center.issue.active.count", compactAttrs(map[string]string{
			"catalyst_center.issue.severity":    strings.ToLower(issue.Severity),
			"catalyst_center.issue.priority":    strings.ToLower(issue.Priority),
			"catalyst_center.issue.status":      strings.ToLower(issue.Status),
			"catalyst_center.issue.category":    issue.Category,
			"catalyst_center.issue.entity_type": issue.EntityType,
			"catalyst_center.site.id":           issue.SiteID,
			"catalyst_center.site.name":         issue.SiteName,
		}))
	}
	if !selector.empty() {
		builder.accountResource().recordInt("catalyst_center.issue.count", "Catalyst Center assurance issue count in the configured lookback window.", "{issue}", int64(selectedIssues), map[string]string{"catalyst_center.issue.window": "lookback"})
	}
	return nil
}

func (r *catalystCenterMetricsReceiver) scrapeDetails(ctx context.Context, builder *catalystCenterMetricsBuilder, selector deviceSelectionMatcher) bool {
	partial := false
	for _, target := range r.config.CatalystCenter.Targets.DeviceDetails {
		query := url.Values{
			"identifier": {canonicalCatalystCenterDeviceIdentifier(target.Identifier)},
			"searchBy":   {target.SearchBy},
		}
		detail, err := catalystcenter.GetResponseJSON[catalystcenter.Object](ctx, r.client, "device_detail", "/dna/intent/api/v1/device-detail", query)
		if err != nil {
			r.settings.Logger.Warn("Catalyst Center device detail endpoint failed", zap.String("identifier", target.Identifier), zap.String("search_by", target.SearchBy), zap.Error(err))
			partial = true
			continue
		}
		if !selector.allows(catalystDeviceIdentity(catalystDeviceFromDetail(detail))) {
			continue
		}
		builder.recordDeviceDetail(target, detail)
	}
	for _, mac := range uniqueStrings(r.config.CatalystCenter.Targets.ClientMACs) {
		query := url.Values{
			"macAddress": {mac},
		}
		detail, err := catalystcenter.GetResponseJSON[catalystcenter.Object](ctx, r.client, "client_detail", "/dna/intent/api/v1/client-detail", query)
		if err != nil {
			r.settings.Logger.Warn("Catalyst Center client detail endpoint failed", zap.String("mac_address", mac), zap.Error(err))
			partial = true
			continue
		}
		if !selector.allows(catalystClientDetailIdentity(mac, detail)) {
			continue
		}
		builder.recordClientDetail(mac, detail)
	}
	return partial
}

func (r *catalystCenterMetricsReceiver) recordRequest(stat catalystcenter.RequestStat) {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats = append(r.stats, stat)
}

func (r *catalystCenterMetricsReceiver) resetRequestStats() {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats = nil
}

func (r *catalystCenterMetricsReceiver) requestStats() []catalystcenter.RequestStat {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	return append([]catalystcenter.RequestStat(nil), r.stats...)
}

func (r *catalystCenterMetricsReceiver) recordAPIRequestMetrics(builder *catalystCenterMetricsBuilder) {
	for _, stat := range r.requestStats() {
		attrs := map[string]string{
			"catalyst_center.api.operation": stat.Operation,
			"http.request.method":           stat.Method,
			"catalyst_center.api.path":      stat.Path,
			"catalyst_center.api.outcome":   stat.Outcome,
		}
		if stat.StatusCode > 0 {
			attrs["http.response.status_code"] = strconv.Itoa(stat.StatusCode)
		}
		rb := builder.accountResource()
		rb.recordDouble("catalyst_center.api.request.duration", "Duration of Catalyst Center API requests.", "s", stat.Duration.Seconds(), attrs)
		if stat.Outcome != "success" {
			rb.recordSum("catalyst_center.api.request.errors", "Catalyst Center API request errors.", "{error}", 1, attrs)
		}
		if stat.RateLimited {
			rb.recordSum("catalyst_center.api.rate_limited", "Catalyst Center API requests that were rate limited.", "{request}", 1, attrs)
		}
	}
}

type catalystCenterMetricsBuilder struct {
	metrics   pmetric.Metrics
	now       pcommon.Timestamp
	start     pcommon.Timestamp
	resources map[string]*resourceMetricsBuilder
	devices   map[string]catalystcenter.Device
	counts    map[string]*catalystCenterCount
	endpoint  string
	counters  *counterStore
}

func newCatalystCenterMetricsBuilder(now time.Time, endpoint string, counters *counterStore) *catalystCenterMetricsBuilder {
	if counters == nil {
		counters = newCounterStore()
	}
	ts := pcommon.NewTimestampFromTime(now)
	return &catalystCenterMetricsBuilder{
		metrics:   pmetric.NewMetrics(),
		now:       ts,
		start:     ts,
		resources: map[string]*resourceMetricsBuilder{},
		devices:   map[string]catalystcenter.Device{},
		counts:    map[string]*catalystCenterCount{},
		endpoint:  endpoint,
		counters:  counters,
	}
}

func (b *catalystCenterMetricsBuilder) emit() pmetric.Metrics {
	return b.metrics
}

func (b *catalystCenterMetricsBuilder) accountResource() *resourceMetricsBuilder {
	rb := b.resource("account")
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", "catalyst_center:"+firstNonEmpty(b.endpoint, "default"))
	putStr(attrs, "host.name", "Cisco Catalyst Center")
	putStr(attrs, "os.name", "Catalyst Center")
	putStr(attrs, "catalyst_center.endpoint", b.endpoint)
	return rb
}

func (b *catalystCenterMetricsBuilder) deviceResource(device catalystcenter.Device) *resourceMetricsBuilder {
	hostID := firstNonEmpty(device.SerialNumber, device.ID, device.InstanceUUID, device.MacAddress, device.Hostname)
	if hostID == "" {
		hostID = "unknown"
	}
	for _, key := range []string{device.ID, device.InstanceUUID, device.SerialNumber, device.MacAddress, device.Hostname} {
		if key != "" {
			b.devices[key] = device
		}
	}
	rb := b.resource("device:" + hostID)
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", hostID)
	putStr(attrs, "host.name", firstNonEmpty(device.Hostname, hostID))
	putStr(attrs, "host.ip", firstNonEmpty(device.ManagementIPAddress, device.DNSResolvedManagementAddr, device.APManagerInterfaceIP))
	putStr(attrs, "host.type", firstNonEmpty(device.PlatformID, device.Type, device.Family))
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Catalyst Center")
	putStr(attrs, "os.version", device.SoftwareVersion)
	putStr(attrs, "catalyst_center.device.id", device.ID)
	putStr(attrs, "catalyst_center.device.instance_uuid", device.InstanceUUID)
	putStr(attrs, "catalyst_center.device.serial", device.SerialNumber)
	putStr(attrs, "catalyst_center.device.family", device.Family)
	putStr(attrs, "catalyst_center.device.role", device.Role)
	putStr(attrs, "catalyst_center.site.name", firstNonEmpty(device.LocationName, device.Location))
	return rb
}

func (b *catalystCenterMetricsBuilder) interfaceResource(iface catalystcenter.Interface) *resourceMetricsBuilder {
	if device, ok := b.devices[iface.DeviceID]; ok {
		return b.deviceResource(device)
	}
	rb := b.resource("device:" + firstNonEmpty(iface.DeviceID, iface.SerialNo, iface.MacAddress, "unknown"))
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", firstNonEmpty(iface.DeviceID, iface.SerialNo, iface.MacAddress, "unknown"))
	putStr(attrs, "host.type", iface.Series)
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Catalyst Center")
	putStr(attrs, "catalyst_center.device.id", iface.DeviceID)
	putStr(attrs, "catalyst_center.device.serial", iface.SerialNo)
	return rb
}

func (b *catalystCenterMetricsBuilder) deviceFor(keys ...string) (catalystcenter.Device, bool) {
	for _, key := range keys {
		if key == "" {
			continue
		}
		if device, ok := b.devices[key]; ok {
			return device, true
		}
	}
	return catalystcenter.Device{}, false
}

func (b *catalystCenterMetricsBuilder) siteResource(site catalystcenter.SiteHealthSummary) *resourceMetricsBuilder {
	siteID := firstNonEmpty(site.SiteID, site.ID, site.SiteHierarchyID, site.SiteName, "unknown")
	rb := b.resource("site:" + siteID)
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", "catalyst_center:site:"+siteID)
	putStr(attrs, "host.name", firstNonEmpty(site.SiteName, site.SiteHierarchy, siteID))
	putStr(attrs, "os.name", "Catalyst Center")
	putStr(attrs, "catalyst_center.site.id", siteID)
	putStr(attrs, "catalyst_center.site.name", site.SiteName)
	putStr(attrs, "catalyst_center.site.type", site.SiteType)
	putStr(attrs, "catalyst_center.site.hierarchy", site.SiteHierarchy)
	return rb
}

func (b *catalystCenterMetricsBuilder) clientResource(mac string, detail catalystcenter.Object) *resourceMetricsBuilder {
	hostID := firstNonEmpty(mac, catalystObjectString(detail, "hostMac", "macAddress", "id"), "unknown")
	rb := b.resource("client:" + hostID)
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", hostID)
	putStr(attrs, "host.name", catalystObjectString(detail, "hostName", "userId", "id"))
	putStr(attrs, "host.ip", firstNonEmpty(catalystObjectString(detail, "hostIpV4"), catalystObjectString(detail, "hostIpV6")))
	putStr(attrs, "os.name", catalystObjectString(detail, "hostOs"))
	putStr(attrs, "catalyst_center.client.mac", hostID)
	putStr(attrs, "catalyst_center.client.type", catalystObjectString(detail, "hostType", "subType"))
	return rb
}

func (b *catalystCenterMetricsBuilder) resource(key string) *resourceMetricsBuilder {
	if rb := b.resources[key]; rb != nil {
		return rb
	}
	rm := b.metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName(catalystCenterScopeName)
	rb := &resourceMetricsBuilder{
		resource: rm.Resource(),
		scope:    sm,
		metrics:  map[string]pmetric.Metric{},
		now:      b.now,
		start:    b.start,
		counters: b.counters,
	}
	b.resources[key] = rb
	return rb
}

func (b *catalystCenterMetricsBuilder) addCount(name string, attrs map[string]string) {
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
	b.counts[key] = &catalystCenterCount{value: 1, attrs: attrs}
}

func (b *catalystCenterMetricsBuilder) flushCounts() {
	rb := b.accountResource()
	keys := make([]string, 0, len(b.counts))
	for key := range b.counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		count := b.counts[key]
		metricName, _, _ := strings.Cut(key, "|")
		rb.recordInt(metricName, catalystCenterCountDescription(metricName), "{item}", count.value, count.attrs)
	}
}

func (b *catalystCenterMetricsBuilder) recordNetworkHealth(health catalystcenter.NetworkHealth) {
	rb := b.accountResource()
	rb.recordInt("catalyst_center.network.health.score", "Latest Catalyst Center network health score.", "1", health.LatestHealthScore, map[string]string{"catalyst_center.health.measured_by": health.MeasuredBy})
	for state, value := range map[string]int64{
		"total":        health.TotalDevices,
		"monitored":    health.MonitoredDevices,
		"healthy":      health.MonitoredHealthyDevices,
		"unhealthy":    health.MonitoredUnHealthyDevices,
		"fair":         health.MonitoredFairHealthDevices,
		"poor":         health.MonitoredPoorHealthDevices,
		"unmonitored":  health.UnMonitoredDevices,
		"no_health":    health.NoHealthDevices,
		"contributing": health.HealthContributingDevices,
	} {
		rb.recordInt("catalyst_center.network.device.count", "Catalyst Center network device count by health state.", "{device}", value, map[string]string{"catalyst_center.health.state": state})
	}
	for _, entry := range health.Response {
		attrs := map[string]string{"catalyst_center.health.entity": entry.Entity}
		rb.recordInt("catalyst_center.network.health.entity.score", "Catalyst Center network health score by entity.", "1", entry.HealthScore, attrs)
		for state, value := range map[string]int64{
			"total":       entry.TotalCount,
			"good":        entry.GoodCount,
			"fair":        entry.FairCount,
			"bad":         entry.BadCount,
			"no_health":   entry.NoHealthCount,
			"unmonitored": entry.UnmonCount,
			"maintenance": entry.MaintenanceModeCount,
		} {
			rb.recordInt("catalyst_center.network.health.entity.count", "Catalyst Center network health entity count by state.", "{device}", value, withAttr(attrs, "catalyst_center.health.state", state))
		}
	}
	distribution := health.HealthDistribution
	if len(distribution) == 0 {
		distribution = health.HealthDistirubution
	}
	for _, item := range distribution {
		attrs := map[string]string{"catalyst_center.device.category": item.Category}
		rb.recordDouble("catalyst_center.network.health.category.score", "Catalyst Center network health score by device category.", "1", item.HealthScore, attrs)
	}
}

func (b *catalystCenterMetricsBuilder) recordClientHealth(health catalystcenter.ClientHealth) {
	for _, site := range health.Response {
		for _, score := range site.ScoreDetail {
			b.recordClientHealthScore(site.SiteID, score)
			for _, nested := range score.ScoreList {
				b.recordClientHealthScore(site.SiteID, nested)
			}
		}
	}
}

func (b *catalystCenterMetricsBuilder) recordClientHealthScore(siteID string, score catalystcenter.ClientHealthScore) {
	attrs := compactAttrs(map[string]string{
		"catalyst_center.site.id":               siteID,
		"catalyst_center.client.score_category": firstNonEmpty(score.ScoreCategory.Value, score.ScoreCategory.ScoreCategory),
	})
	rb := b.accountResource()
	rb.recordDouble("catalyst_center.client.health.score", "Catalyst Center client health score.", "1", score.ScoreValue, attrs)
	rb.recordInt("catalyst_center.client.count", "Catalyst Center client count by health category.", "{client}", score.ClientCount, attrs)
	rb.recordInt("catalyst_center.client.unique.count", "Catalyst Center unique client count by health category.", "{client}", score.ClientUniqueCount, attrs)
}

func (b *catalystCenterMetricsBuilder) recordSiteHealth(site catalystcenter.SiteHealthSummary) {
	rb := b.siteResource(site)
	rb.recordDouble("catalyst_center.site.network_device.health.percentage", "Catalyst Center site network-device good health percentage.", "%", site.NetworkDeviceGoodHealthPercentage, nil)
	rb.recordDouble("catalyst_center.site.client.health.percentage", "Catalyst Center site client good health percentage.", "%", site.ClientGoodHealthPercentage, nil)
	for priority, value := range map[string]int64{
		"p1":  site.P1IssueCount,
		"p2":  site.P2IssueCount,
		"p3":  site.P3IssueCount,
		"p4":  site.P4IssueCount,
		"all": site.IssueCount,
	} {
		rb.recordInt("catalyst_center.site.issue.count", "Catalyst Center site issue count by priority.", "{issue}", value, map[string]string{"catalyst_center.issue.priority": priority})
	}
	for clientType, value := range map[string]int64{
		"all":      site.ClientCount,
		"wired":    site.WiredClientCount,
		"wireless": site.WirelessClientCount,
	} {
		rb.recordInt("catalyst_center.site.client.count", "Catalyst Center site client count by client type and health state.", "{client}", value, map[string]string{
			"catalyst_center.client.type":  clientType,
			"catalyst_center.health.state": "total",
		})
	}
	rb.recordInt("catalyst_center.site.client.count", "Catalyst Center site client count by client type and health state.", "{client}", site.ClientGoodHealthCount, map[string]string{
		"catalyst_center.client.type":  "all",
		"catalyst_center.health.state": "good",
	})
	for role, counts := range map[string]struct {
		total int64
		good  int64
	}{
		"all":          {total: site.NetworkDeviceCount, good: site.NetworkDeviceGoodHealthCount},
		"access":       {total: site.AccessDeviceCount, good: site.AccessDeviceGoodHealthCount},
		"core":         {total: site.CoreDeviceCount, good: site.CoreDeviceGoodHealthCount},
		"distribution": {total: site.DistributionDeviceCount, good: site.DistributionDeviceGoodHealthCount},
		"router":       {total: site.RouterDeviceCount, good: site.RouterDeviceGoodHealthCount},
		"wireless":     {total: site.WirelessDeviceCount, good: site.WirelessDeviceGoodHealthCount},
		"ap":           {total: site.APDeviceCount, good: site.APDeviceGoodHealthCount},
		"wlc":          {total: site.WLCDeviceCount, good: site.WLCDeviceGoodHealthCount},
		"switch":       {total: site.SwitchDeviceCount, good: site.SwitchDeviceGoodHealthCount},
	} {
		for state, value := range map[string]int64{"total": counts.total, "good": counts.good} {
			rb.recordInt("catalyst_center.site.network_device.count", "Catalyst Center site network device count by role and health state.", "{device}", value, map[string]string{
				"catalyst_center.device.role":  role,
				"catalyst_center.health.state": state,
			})
		}
	}
	for state, value := range map[string]int64{
		"network_device_total":  site.NetworkDeviceCount,
		"network_device_good":   site.NetworkDeviceGoodHealthCount,
		"client_total":          site.ClientCount,
		"client_good":           site.ClientGoodHealthCount,
		"wired_client_total":    site.WiredClientCount,
		"wireless_client_total": site.WirelessClientCount,
		"access_total":          site.AccessDeviceCount,
		"access_good":           site.AccessDeviceGoodHealthCount,
		"core_total":            site.CoreDeviceCount,
		"core_good":             site.CoreDeviceGoodHealthCount,
		"distribution_total":    site.DistributionDeviceCount,
		"distribution_good":     site.DistributionDeviceGoodHealthCount,
		"router_total":          site.RouterDeviceCount,
		"router_good":           site.RouterDeviceGoodHealthCount,
		"wireless_total":        site.WirelessDeviceCount,
		"wireless_good":         site.WirelessDeviceGoodHealthCount,
		"ap_total":              site.APDeviceCount,
		"ap_good":               site.APDeviceGoodHealthCount,
		"wlc_total":             site.WLCDeviceCount,
		"wlc_good":              site.WLCDeviceGoodHealthCount,
		"switch_total":          site.SwitchDeviceCount,
		"switch_good":           site.SwitchDeviceGoodHealthCount,
		"issues_p1":             site.P1IssueCount,
		"issues_p2":             site.P2IssueCount,
		"issues_p3":             site.P3IssueCount,
		"issues_p4":             site.P4IssueCount,
		"issues_total":          site.IssueCount,
	} {
		rb.recordInt("catalyst_center.site.health.count", "Catalyst Center site health count.", "{item}", value, map[string]string{"catalyst_center.site.health.state": state})
	}
}

func (b *catalystCenterMetricsBuilder) recordTopology(topology catalystcenter.Topology, maxResults int, selector deviceSelectionMatcher) {
	nodes := make([]catalystcenter.TopologyNode, 0, len(topology.Nodes))
	allowedNodeIDs := map[string]struct{}{}
	for _, node := range topology.Nodes {
		device, _ := b.deviceFor(node.ID, node.Label)
		if !selector.allows(catalystTopologyNodeIdentity(node, device)) {
			continue
		}
		nodes = append(nodes, node)
		if node.ID != "" {
			allowedNodeIDs[node.ID] = struct{}{}
		}
	}
	links := make([]catalystcenter.TopologyLink, 0, len(topology.Links))
	for _, link := range topology.Links {
		if selector.empty() || linkReferencesAllowedCatalystNode(link, allowedNodeIDs) {
			links = append(links, link)
		}
	}
	rb := b.accountResource()
	rb.recordInt("catalyst_center.topology.node.count", "Catalyst Center physical topology node count.", "{node}", int64(len(nodes)), map[string]string{"catalyst_center.topology.scope": "total"})
	rb.recordInt("catalyst_center.topology.link.count", "Catalyst Center physical topology link count.", "{link}", int64(len(links)), map[string]string{"catalyst_center.topology.scope": "total"})
	for i, node := range nodes {
		if maxResults > 0 && i >= maxResults {
			break
		}
		b.addCount("catalyst_center.topology.node.count", compactAttrs(map[string]string{
			"catalyst_center.topology.node_type": firstNonEmpty(node.NodeType, "unknown"),
			"catalyst_center.device.family":      node.Family,
			"catalyst_center.device.role":        node.Role,
		}))
	}
	for i, link := range links {
		if maxResults > 0 && i >= maxResults {
			break
		}
		b.addCount("catalyst_center.topology.link.count", compactAttrs(map[string]string{
			"catalyst_center.topology.link_status": firstNonEmpty(link.LinkStatus, "unknown"),
		}))
	}
}

func (b *catalystCenterMetricsBuilder) recordDeviceDetail(target CatalystCenterDeviceDetailTarget, detail catalystcenter.Object) {
	device := catalystDeviceFromDetail(detail)
	rb := b.deviceResource(device)
	attrs := map[string]string{
		"catalyst_center.detail.identifier": target.Identifier,
	}
	recordObjectDouble(rb, detail, "overallHealth", "catalyst_center.device.detail.health.score", "Catalyst Center device detail overall health score.", "1", attrs)
	recordObjectDouble(rb, detail, "cpu", "system.cpu.utilization", "CPU utilization reported by Catalyst Center device detail.", "1", attrs)
	recordObjectDouble(rb, detail, "memory", "system.memory.utilization", "Memory utilization reported by Catalyst Center device detail.", "1", attrs)
	recordCatalystStatus(rb, "catalyst_center.device.detail.communication.status", "Catalyst Center device communication status.", catalystObjectString(detail, "communicationState", "opState"), attrs)
}

func catalystDeviceFromDetail(detail catalystcenter.Object) catalystcenter.Device {
	return catalystcenter.Device{
		ID:                  catalystObjectString(detail, "nwDeviceId", "id"),
		Hostname:            catalystObjectString(detail, "nwDeviceName", "hostname"),
		ManagementIPAddress: catalystObjectString(detail, "managementIpAddr", "ip_addr_managementIpAddr"),
		SerialNumber:        catalystObjectString(detail, "serialNumber"),
		MacAddress:          catalystObjectString(detail, "macAddress", "ethernetMac"),
		Family:              catalystObjectString(detail, "nwDeviceFamily"),
		Type:                catalystObjectString(detail, "nwDeviceType"),
		Series:              catalystObjectString(detail, "deviceSeries"),
		PlatformID:          catalystObjectString(detail, "platformId"),
		Role:                catalystObjectString(detail, "nwDeviceRole"),
		SoftwareVersion:     catalystObjectString(detail, "softwareVersion"),
		CollectionStatus:    catalystObjectString(detail, "collectionStatus"),
	}
}

func linkReferencesAllowedCatalystNode(link catalystcenter.TopologyLink, allowedNodeIDs map[string]struct{}) bool {
	if len(allowedNodeIDs) == 0 {
		return false
	}
	_, sourceOK := allowedNodeIDs[link.Source]
	_, targetOK := allowedNodeIDs[link.Target]
	return sourceOK || targetOK
}

func (b *catalystCenterMetricsBuilder) recordClientDetail(mac string, detail catalystcenter.Object) {
	rb := b.clientResource(mac, detail)
	attrs := map[string]string{
		"catalyst_center.client.connection_status": catalystObjectString(detail, "connectionStatus", "clientConnection"),
		"catalyst_center.client.type":              catalystObjectString(detail, "hostType", "subType"),
	}
	if !recordClientDetailHealthScores(rb, detail, attrs) {
		recordObjectDouble(rb, detail, "healthScore", "catalyst_center.client.detail.health.score", "Catalyst Center client detail health score.", "1", attrs)
	}
	recordObjectInt(rb, detail, "issueCount", "catalyst_center.client.issue.count", "Catalyst Center client issue count.", "{issue}", attrs)
	recordObjectDouble(rb, detail, "rssi", "catalyst_center.client.wireless.rssi", "Catalyst Center client RSSI.", "dBm", attrs)
	recordObjectDouble(rb, detail, "snr", "catalyst_center.client.wireless.snr", "Catalyst Center client SNR.", "dB", attrs)
	recordObjectDouble(rb, detail, "txBytes", "catalyst_center.client.network.io", "Catalyst Center client transmitted bytes.", "By", withAttr(attrs, "network.io.direction", "transmit"))
	recordObjectDouble(rb, detail, "rxBytes", "catalyst_center.client.network.io", "Catalyst Center client received bytes.", "By", withAttr(attrs, "network.io.direction", "receive"))
}

func catalystWindowQuery(lookback time.Duration, now time.Time) url.Values {
	if lookback <= 0 {
		lookback = defaultCatalystCenterConfig().Lookback
	}
	return url.Values{
		"startTime": {strconv.FormatInt(now.Add(-lookback).UnixMilli(), 10)},
		"endTime":   {strconv.FormatInt(now.UnixMilli(), 10)},
	}
}

func catalystInterfaceAttrs(iface catalystcenter.Interface) map[string]string {
	return compactAttrs(map[string]string{
		"network.interface.name":         firstNonEmpty(iface.PortName, iface.Name),
		"network.interface.type":         iface.InterfaceType,
		"network.interface.mac":          iface.MacAddress,
		"network.interface.duplex":       iface.Duplex,
		"catalyst_center.interface.id":   firstNonEmpty(iface.ID, iface.InstanceUUID),
		"catalyst_center.interface.vlan": firstNonEmpty(iface.VLANID, iface.NativeVLANID),
		"catalyst_center.device.id":      iface.DeviceID,
	})
}

func parseCatalystSpeed(speed string) (int64, string) {
	speed = strings.TrimSpace(speed)
	if speed == "" {
		return 0, ""
	}
	if value, err := strconv.ParseInt(speed, 10, 64); err == nil {
		return value, speed
	}
	return parseMerakiSpeed(speed)
}

func parseIntString(value string) (int64, bool) {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return parsed, err == nil
}

func recordCatalystStatus(rb *resourceMetricsBuilder, name, description, status string, attrs map[string]string) {
	if status == "" {
		return
	}
	if attrs == nil {
		attrs = map[string]string{}
	}
	rb.recordInt(name, description, "1", catalystStatusCode(status), withAttr(attrs, "catalyst_center.status", status))
}

func catalystStatusCode(status string) int64 {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "reachable", "managed", "success", "collectioncomplete", "synchronized":
		return 1
	case "unreachable", "incomplete", "partialcollectionfailure", "collectionfailure", "collectionfailed":
		return 4
	default:
		return statusCode(status)
	}
}

func recordClientDetailHealthScores(rb *resourceMetricsBuilder, detail catalystcenter.Object, attrs map[string]string) bool {
	raw, ok := detail["healthScore"].([]any)
	if !ok {
		return false
	}
	for _, item := range raw {
		scoreObj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		score, ok := numberFromAny(scoreObj["score"])
		if !ok {
			continue
		}
		scoreAttrs := cloneStringMap(attrs)
		putNonEmpty(scoreAttrs, "catalyst_center.client.health_type", stringFromAny(scoreObj["healthType"]))
		putNonEmpty(scoreAttrs, "catalyst_center.client.health_reason", stringFromAny(scoreObj["reason"]))
		rb.recordDouble("catalyst_center.client.detail.health.score", "Catalyst Center client detail health score.", "1", score, scoreAttrs)
	}
	return true
}

func recordObjectDouble(rb *resourceMetricsBuilder, obj catalystcenter.Object, key, name, description, unit string, attrs map[string]string) {
	value, ok := numberFromAny(obj[key])
	if !ok {
		return
	}
	rb.recordDouble(name, description, unit, value, attrs)
}

func recordObjectInt(rb *resourceMetricsBuilder, obj catalystcenter.Object, key, name, description, unit string, attrs map[string]string) {
	value, ok := numberFromAny(obj[key])
	if !ok {
		return
	}
	rb.recordInt(name, description, unit, int64(value), attrs)
}

func catalystObjectString(obj catalystcenter.Object, keys ...string) string {
	for _, key := range keys {
		value, ok := obj[key]
		if !ok || value == nil {
			continue
		}
		if str := stringFromAny(value); str != "" && str != "<nil>" {
			return str
		}
	}
	return ""
}

func catalystCenterCountDescription(name string) string {
	switch name {
	case "catalyst_center.issue.active.count":
		return "Catalyst Center assurance issue count grouped by issue attributes."
	case "catalyst_center.topology.node.count":
		return "Catalyst Center physical topology node count grouped by node attributes."
	case "catalyst_center.topology.link.count":
		return "Catalyst Center physical topology link count grouped by link attributes."
	default:
		return "Catalyst Center grouped count."
	}
}
