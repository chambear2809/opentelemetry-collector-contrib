// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/nexusdashboard"
)

func TestNexusDashboardScrapeEmitsTroubleshootingMetrics(t *testing.T) {
	server := newNexusDashboardFixtureServer(t, map[string]string{
		"/api/v1/infra/cluster/health": `{"name":"nd-cluster","status":"healthy","healthScore":98}`,
		"/api/v1/manage/fabric-switches/summary": `{"switches":[
			{"switchName":"leaf101","serialNumber":"N9K-SERIAL-1","switchDbId":"101","fabricName":"fabric-a","role":"leaf","status":"ok","model":"N9K-C93180YC-FX3","nxosVersion":"10.3(5)","ipAddress":"10.0.0.101"}
		]}`,
		"/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/lanSwitches/101/interfaces": `{"interfaces":[
			{"ifName":"eth1/1","switchDbId":"101","serialNumber":"N9K-SERIAL-1","fabricName":"fabric-a","status":"up","speed":"100000000000","rxRate":1000,"txRate":2000,"rxUtilization":10,"txUtilization":20}
		]}`,
		"/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/audit": `{"items":[
			{"id":"audit-1","userName":"operator","status":"success","serialNumber":"N9K-SERIAL-1","fabricName":"fabric-a"}
		]}`,
		"/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/events": `{"items":[
			{"id":"event-1","status":"active","severity":"critical","serialNumber":"N9K-SERIAL-1","fabricName":"fabric-a"}
		]}`,
		"/nexus/insights/api/v1/anomalies": `{"anomalies":[
			{"id":"anomaly-1","name":"CRC spike","siteName":"site-a","fabricName":"fabric-a","serialNumber":"N9K-SERIAL-1","severity":"critical","status":"active","score":90,"confidence":95}
		]}`,
		"/mso/api/v1/tasks": `{"items":[
			{"id":"deploy-1","siteName":"site-a","schemaName":"prod","status":"failed","policyDeltaCount":2}
		]}`,
		"/api/v1/nddb/sessions": `{"items":[
			{"sessionName":"tap-session-1","siteName":"site-a","fabricName":"fabric-a","status":"enabled","ruleCount":3}
		]}`,
	})
	defer server.Close()

	receiver := newTestNexusDashboardMetricsReceiver(t, server.URL)
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	names := metricNames(md)
	assert.Contains(t, names, "nexus_dashboard.api.request.duration")
	assert.Contains(t, names, "nexus_dashboard.resource.info")
	assert.Contains(t, names, "nexus_dashboard.audit.record.count")
	assert.Contains(t, names, "nexus_dashboard.event.count")
	assert.Contains(t, names, "cisco.device.up")
	assert.Contains(t, names, "cisco.interface.io.rate")
	assert.Contains(t, names, "nexus_dashboard.insights.anomaly.active")
	assert.Contains(t, names, "nexus_dashboard.orchestrator.deployment.status")
	assert.Contains(t, names, "nexus_dashboard.data_broker.status")
	assert.True(t, hasResourceHostID(md, "N9K-SERIAL-1"))
	assert.True(t, intMetricValueExists(md, "nexus_dashboard.scrape.partial_success", 0))
	assert.True(t, intMetricValueExists(md, "nexus_dashboard.audit.record.count", 1))
	assert.True(t, intMetricValueExists(md, "nexus_dashboard.event.count", 1))
	assert.True(t, hasMetricDatapointAttribute(md, "nexus_dashboard.audit.record.count", "nexus_dashboard.operation", "ndfc.audit"))
	assert.False(t, hasMetricDatapointAttribute(md, "nexus_dashboard.audit.record.count", "user.name", "operator"))
}

func TestNexusDashboardMissingTargetFiltersReportSkippedPartial(t *testing.T) {
	server := newNexusDashboardFixtureServer(t, map[string]string{
		"/api/v1/infra/cluster/health": `{"name":"nd-cluster","status":"healthy","healthScore":98}`,
	})
	defer server.Close()

	receiver := newTestNexusDashboardMetricsReceiver(t, server.URL)
	receiver.config.NexusDashboard.Targets = NexusDashboardTargetFilters{}
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, intMetricValueExists(md, "nexus_dashboard.scrape.partial_success", 1))
	assert.NotContains(t, metricNames(md), "nexus_dashboard.scrape.last_success")

	skipped := requireMetricByName(t, md, "nexus_dashboard.service.skipped")
	require.Equal(t, 4, skipped.Gauge().DataPoints().Len())
	for _, operation := range []string{
		"ndfc.fabric.switch_overview",
		"ndfc.endpoints",
		"ndfc.policy.deployment",
		"ndfc.interface.stats",
	} {
		assert.True(t, hasMetricDatapointAttribute(md, "nexus_dashboard.service.skipped", "nexus_dashboard.api.operation", operation))
	}
	assert.True(t, hasMetricDatapointAttribute(md, "nexus_dashboard.service.skipped", "nexus_dashboard.skip.reason", "missing_target_filter"))
}

func TestNexusDashboardPlatformOnlyWithoutTargetsIsComplete(t *testing.T) {
	server := newNexusDashboardFixtureServer(t, map[string]string{
		"/api/v1/infra/cluster/health": `{"name":"nd-cluster","status":"healthy","healthScore":98}`,
	})
	defer server.Close()

	receiver := newTestNexusDashboardMetricsReceiver(t, server.URL)
	receiver.config.NexusDashboard.Targets = NexusDashboardTargetFilters{}
	receiver.config.NexusDashboard.NDFC.Enabled = false
	receiver.config.NexusDashboard.Insights.Enabled = false
	receiver.config.NexusDashboard.Orchestrator.Enabled = false
	receiver.config.NexusDashboard.DataBroker.Enabled = false
	receiver.config.NexusDashboard.Performance.Enabled = false
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	names := metricNames(md)
	assert.True(t, intMetricValueExists(md, "nexus_dashboard.scrape.partial_success", 0))
	assert.Contains(t, names, "nexus_dashboard.scrape.last_success")
	assert.NotContains(t, names, "nexus_dashboard.service.skipped")
	assert.Contains(t, names, "nexus_dashboard.service.health")
}

func TestNexusDashboardScrapeAppliesSharedDeviceSelection(t *testing.T) {
	server := newNexusDashboardFixtureServer(t, map[string]string{
		"/api/v1/manage/fabric-switches/summary": `{"switches":[
			{"switchName":"leaf101","serialNumber":"N9K-SERIAL-1","switchDbId":"101","fabricName":"fabric-a","status":"ok"},
			{"switchName":"leaf909","serialNumber":"N9K-SERIAL-9","switchDbId":"909","fabricName":"fabric-a","status":"ok"}
		]}`,
	})
	defer server.Close()

	receiver := newTestNexusDashboardMetricsReceiver(t, server.URL)
	receiver.config.NexusDashboard.Targets.SwitchSerials = []string{"N9K-SERIAL-1", "N9K-SERIAL-9"}
	receiver.config.NexusDashboard.Targets.SwitchIDs = []string{"101", "909"}
	receiver.config.DeviceSelection.Include.Serials = []string{"N9K-SERIAL-1"}
	receiver.config.DeviceSelection.Exclude.Serials = []string{"N9K-SERIAL-9"}
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, hasResourceHostID(md, "N9K-SERIAL-1"))
	assert.False(t, hasResourceHostID(md, "N9K-SERIAL-9"))
}

func TestNexusDashboardLogsApplySharedDeviceSelection(t *testing.T) {
	server := newNexusDashboardFixtureServer(t, map[string]string{
		"/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/audit": `{"items":[
			{"id":"audit-1","userName":"operator","status":"success","createdAt":"2026-05-25T10:00:00Z","serialNumber":"N9K-SERIAL-1","fabricName":"fabric-a"},
			{"id":"audit-9","userName":"operator","status":"success","createdAt":"2026-05-25T10:00:00Z","serialNumber":"N9K-SERIAL-9","fabricName":"fabric-a"}
		]}`,
	})
	defer server.Close()

	receiver := newTestNexusDashboardLogsReceiver(t, server.URL)
	receiver.config.NexusDashboard.Targets.SwitchSerials = []string{"N9K-SERIAL-1", "N9K-SERIAL-9"}
	receiver.config.DeviceSelection.Include.Serials = []string{"N9K-SERIAL-1"}
	receiver.config.DeviceSelection.Exclude.Serials = []string{"N9K-SERIAL-9"}
	ld, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.Equal(t, 1, ld.LogRecordCount())
	assert.True(t, hasLogResourceAttribute(ld, "N9K-SERIAL-1"))
	assert.False(t, hasLogResourceAttribute(ld, "N9K-SERIAL-9"))
}

func TestNexusDashboardLogsEmitEvidenceAndDeduplicate(t *testing.T) {
	server := newNexusDashboardFixtureServer(t, map[string]string{
		"/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/audit": `{"items":[
			{"id":"audit-1","userName":"operator","status":"success","createdAt":"2026-05-25T10:00:00Z","serialNumber":"N9K-SERIAL-1","fabricName":"fabric-a"}
		]}`,
		"/nexus/insights/api/v1/rootcauses": `{"items":[
			{"id":"rca-1","name":"CRC burst","severity":"critical","status":"active","createdAt":"2026-05-25T10:01:00Z","serialNumber":"N9K-SERIAL-1","fabricName":"fabric-a"}
		]}`,
	})
	defer server.Close()

	receiver := newTestNexusDashboardLogsReceiver(t, server.URL)
	ld, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 2, ld.LogRecordCount())
	assert.True(t, hasLogRecordAttribute(ld, "event.name", "ndfc.audit"))
	assert.True(t, hasLogRecordAttribute(ld, "event.name", "insights.root_causes"))
	assert.True(t, hasLogRecordAttribute(ld, "user.name", "operator"))

	ld, err = receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 0, ld.LogRecordCount())
}

func TestNexusDashboardCatalogCoversTroubleshootingDomains(t *testing.T) {
	groups := map[string]bool{}
	operations := map[string]bool{}
	for _, endpoint := range nexusDashboardMetricEndpoints(nexusDashboardAPIProfileLegacy) {
		groups[endpoint.group] = true
		operations[endpoint.operation] = true
	}
	for _, endpoint := range nexusDashboardLogEndpoints(nexusDashboardAPIProfileLegacy) {
		groups[endpoint.group] = true
		operations[endpoint.operation] = true
	}
	for _, group := range []string{"platform", "ndfc", "insights", "orchestrator", "data_broker", "performance"} {
		assert.True(t, groups[group], "missing Nexus Dashboard group %q", group)
	}
	for _, operation := range []string{
		"nd.cluster.health",
		"ndfc.manage.fabrics",
		"ndfc.manage.fabric_switches",
		"ndfc.interface.stats",
		"insights.anomalies",
		"insights.advisories",
		"ndo.sites",
		"ndo.deployments",
		"nddb.health",
		"nddb.sessions",
		"ndfc.audit",
	} {
		assert.True(t, operations[operation], "missing Nexus Dashboard operation %q", operation)
	}
}

func TestNexusDashboardUnifiedCatalogUsesVerifiedCurrentAPIs(t *testing.T) {
	endpoints := nexusDashboardMetricEndpoints(nexusDashboardAPIProfileUnified)
	require.Len(t, endpoints, 7)
	assert.Empty(t, nexusDashboardLogEndpoints(nexusDashboardAPIProfileUnified))

	wantPaths := map[string]bool{
		"/api/v1/infra/clusterhealth/status":                   true,
		"/api/v1/infra/cluster/nodes":                          true,
		"/api/v1/infra/systemResources/nodes/hardware":         true,
		"/api/v1/infra/systemResources/summary":                true,
		"/api/v1/manage/fabrics":                               true,
		"/api/v1/manage/fabrics/{fabricName}/switches":         true,
		"/api/v1/manage/fabrics/{fabricName}/switches/summary": true,
	}
	for _, endpoint := range endpoints {
		assert.True(t, wantPaths[endpoint.path], "unexpected unified endpoint %q", endpoint.path)
		assert.NotContains(t, endpoint.path, "/appcenter/")
		assert.NotContains(t, endpoint.path, "/nexus/insights/")
		assert.NotContains(t, endpoint.path, "/mso/")
		assert.NotContains(t, endpoint.path, "/nddb/")
		delete(wantPaths, endpoint.path)
	}
	assert.Empty(t, wantPaths)

	legacyPaths := map[string]bool{}
	for _, endpoint := range nexusDashboardMetricEndpoints("") {
		legacyPaths[endpoint.path] = true
	}
	assert.True(t, legacyPaths["/api/v1/infra/cluster/health"])
	assert.True(t, legacyPaths["/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/fabricstatus"])
	assert.False(t, legacyPaths["/api/v1/infra/clusterhealth/status"])
}

func TestNexusDashboardUnifiedScrapeUsesAllVerifiedEndpoints(t *testing.T) {
	routes := map[string]string{
		"/api/v1/infra/clusterhealth/status":               `{"isHealthy":true,"severity":"info","nodes":[],"coreInfra":[],"features":[],"k8s":[]}`,
		"/api/v1/infra/cluster/nodes":                      `{"nodes":[{"name":"nd-node-1","serialNumber":"ND-SERIAL-1","firmwareVersion":"4.2.0","operationalState":"active"}]}`,
		"/api/v1/infra/systemResources/nodes/hardware":     `{"nodes":[{"cpus":{"processorsCount":8},"memory":{"total":"32 GB"},"storage":{"total":"1 TB"}}]}`,
		"/api/v1/infra/systemResources/summary":            `{"nodes":[{"name":"nd-node-1","namespaces":[]}]}`,
		"/api/v1/manage/fabrics":                           `{"fabrics":[{"name":"fabric-a","category":"vxlan"}]}`,
		"/api/v1/manage/fabrics/fabric-a/switches":         `{"switches":[{"hostname":"leaf101","serialNumber":"N9K-SERIAL-1","switchId":"switch-1","fabricName":"fabric-a","switchRole":"leaf","model":"N9K-C93180YC-FX3","softwareVersion":"10.6(1)","fabricManagementIp":"192.0.2.10","additionalData":{"discoveryStatus":"ok","configSyncStatus":"inSync"}}]}`,
		"/api/v1/manage/fabrics/fabric-a/switches/summary": `{"anomalyLevel":{"counters":[]},"configSyncStatus":{"counters":[{"name":"inSync","count":1}]},"role":{"counters":[{"name":"leaf","count":1}]},"softwareVersion":{"counters":[{"name":"10.6(1)","count":1}]}}`,
	}

	var callsMu sync.Mutex
	calls := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "admin", r.Header.Get("X-Nd-Username"))
		assert.Equal(t, "nd-api-key", r.Header.Get("X-Nd-Apikey"))
		callsMu.Lock()
		calls[r.URL.Path]++
		callsMu.Unlock()
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	receiver := newTestNexusDashboardMetricsReceiver(t, server.URL)
	receiver.config.NexusDashboard.APIProfile = nexusDashboardAPIProfileUnified
	receiver.config.NexusDashboard.Targets = NexusDashboardTargetFilters{Fabrics: []string{"fabric-a"}}
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	callsMu.Lock()
	assert.Len(t, calls, len(routes))
	for path := range routes {
		assert.Equal(t, 1, calls[path], path)
	}
	callsMu.Unlock()

	names := metricNames(md)
	assert.True(t, intMetricValueExists(md, "nexus_dashboard.scrape.partial_success", 0))
	assert.Contains(t, names, "nexus_dashboard.scrape.last_success")
	assert.Contains(t, names, "nexus_dashboard.resource.info")
	assert.Contains(t, names, "nexus_dashboard.resource.count")
	assert.NotContains(t, names, "nexus_dashboard.api.request.errors")
	assert.NotContains(t, names, "nexus_dashboard.api.endpoint.error")
	assert.NotContains(t, names, "nexus_dashboard.service.unavailable")
	assert.NotContains(t, names, "nexus_dashboard.service.skipped")
	assert.True(t, intMetricValueExists(md, "cisco.device.up", 1))
	assert.True(t, hasResourceHostID(md, "N9K-SERIAL-1"))
	assert.True(t, hasNexusDashboardResourceAttribute(md, "N9K-SERIAL-1", "os.version", "10.6(1)"))
	for _, resourceType := range []string{
		"nd.cluster",
		"nd.node",
		"nd.node_hardware",
		"nd.system_resources",
		"ndfc.fabric",
		"ndfc.switch",
		"ndfc.switch_summary",
	} {
		assert.True(t, hasMetricDatapointAttribute(md, "nexus_dashboard.resource.info", "nexus_dashboard.resource.type", resourceType), resourceType)
	}
	for _, operation := range []string{
		"nd.cluster.health",
		"nd.nodes",
		"nd.hardware",
		"nd.system.resources",
		"ndfc.manage.fabrics",
		"ndfc.manage.fabric_switches",
		"ndfc.manage.fabric_switches_summary",
	} {
		assert.True(t, hasMetricDatapointAttribute(md, "nexus_dashboard.api.request.duration", "nexus_dashboard.api.operation", operation), operation)
	}
}

func TestNexusDashboardUnifiedMissingFabricReportsScopedEndpoints(t *testing.T) {
	server := newNexusDashboardFixtureServer(t, map[string]string{
		"/api/v1/manage/fabrics": `{"fabrics":[]}`,
	})
	defer server.Close()

	receiver := newTestNexusDashboardMetricsReceiver(t, server.URL)
	receiver.config.NexusDashboard.APIProfile = nexusDashboardAPIProfileUnified
	receiver.config.NexusDashboard.Targets = NexusDashboardTargetFilters{}
	receiver.config.NexusDashboard.Platform.Enabled = false
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, intMetricValueExists(md, "nexus_dashboard.scrape.partial_success", 1))
	skipped := requireMetricByName(t, md, "nexus_dashboard.service.skipped")
	require.Equal(t, 2, skipped.Gauge().DataPoints().Len())
	for _, operation := range []string{"ndfc.manage.fabric_switches", "ndfc.manage.fabric_switches_summary"} {
		assert.True(t, hasMetricDatapointAttribute(md, "nexus_dashboard.service.skipped", "nexus_dashboard.api.operation", operation))
	}
}

func TestNexusDashboardCurrentStatusAliases(t *testing.T) {
	assert.Equal(t, "active", nexusDashboardObjectStatus(nexusdashboard.Object{"operationalState": "active"}))
	assert.Equal(t, "healthy", nexusDashboardObjectStatus(nexusdashboard.Object{"isHealthy": true}))
	assert.Equal(t, "unhealthy", nexusDashboardObjectStatus(nexusdashboard.Object{"isHealthy": false}))
	assert.Equal(t, "ok", nexusDashboardObjectStatus(nexusdashboard.Object{"additionalData": map[string]any{"discoveryStatus": "ok"}}))
	assert.Empty(t, nexusDashboardObjectStatus(nexusdashboard.Object{"configSyncStatus": map[string]any{"counters": []any{map[string]any{"name": "inSync", "count": 1}}}}))
}

func TestNexusDashboardLoginNegotiationIsNotAnAPIError(t *testing.T) {
	receiver := &nexusDashboardMetricsReceiver{}
	receiver.recordRequest(nexusdashboard.RequestStat{
		Operation:  "infra.login",
		Method:     http.MethodPost,
		Path:       "/api/v1/infra/login",
		Outcome:    "fallback",
		StatusCode: http.StatusUnauthorized,
		Duration:   time.Millisecond,
	})
	builder := newNexusDashboardMetricsBuilder(time.Now(), "test", nil)
	receiver.recordAPIRequestMetrics(builder)

	names := metricNames(builder.emit())
	assert.Contains(t, names, "nexus_dashboard.api.request.duration")
	assert.NotContains(t, names, "nexus_dashboard.api.request.errors")
}

func TestNexusDashboardFabricHealthUsesFirstPresentSynonym(t *testing.T) {
	builder := newNexusDashboardMetricsBuilder(time.Now(), "test", nil)
	builder.recordNDFCObject(builder.controllerResource(), nexusdashboard.Object{
		"health":      float64(92),
		"healthScore": float64(71),
	}, "")

	metric := requireMetricByName(t, builder.emit(), "nexus_dashboard.fabric.health")
	require.Equal(t, 1, metric.Gauge().DataPoints().Len())
	assert.Equal(t, float64(92), metric.Gauge().DataPoints().At(0).DoubleValue())
}

func newTestNexusDashboardMetricsReceiver(t *testing.T, endpoint string) *nexusDashboardMetricsReceiver {
	t.Helper()
	cfg := testNexusDashboardConfig(endpoint)
	receiver, err := newNexusDashboardMetricsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)
	return receiver
}

func newTestNexusDashboardLogsReceiver(t *testing.T, endpoint string) *nexusDashboardLogsReceiver {
	t.Helper()
	cfg := testNexusDashboardConfig(endpoint)
	receiver, err := newNexusDashboardLogsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, &consumertest.LogsSink{})
	require.NoError(t, err)
	return receiver
}

func testNexusDashboardConfig(endpoint string) *Config {
	cfg := createDefaultConfig().(*Config)
	cfg.Timeout = 5 * time.Second
	cfg.NexusDashboard = defaultNexusDashboardConfig()
	cfg.NexusDashboard.Enabled = true
	cfg.NexusDashboard.Endpoint = endpoint
	cfg.NexusDashboard.MaxRetries = 1
	cfg.NexusDashboard.Auth = ControllerAuthConfig{
		Mode:     "api_key",
		Username: "admin",
		APIKey:   configopaque.String("nd-api-key"),
	}
	cfg.NexusDashboard.Targets = NexusDashboardTargetFilters{
		Sites:          []string{"site-a"},
		Fabrics:        []string{"fabric-a"},
		SwitchSerials:  []string{"N9K-SERIAL-1"},
		SwitchIDs:      []string{"101"},
		InterfaceNames: []string{"eth1/1"},
	}
	return cfg
}

func newNexusDashboardFixtureServer(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "admin", r.Header.Get("X-Nd-Username"))
		assert.Equal(t, "nd-api-key", r.Header.Get("X-Nd-Apikey"))
		if body, ok := routes[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		switch {
		case strings.Contains(r.URL.Path, "/anomalies"),
			strings.Contains(r.URL.Path, "/advisories"),
			strings.Contains(r.URL.Path, "/interfaces"),
			strings.Contains(r.URL.Path, "/sessions"),
			strings.Contains(r.URL.Path, "/events"),
			strings.Contains(r.URL.Path, "/audit"):
			_, _ = w.Write([]byte(`{"items":[]}`))
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
}

func hasNexusDashboardResourceAttribute(md pmetric.Metrics, hostID, key, expected string) bool {
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		attrs := md.ResourceMetrics().At(i).Resource().Attributes()
		id, ok := attrs.Get("host.id")
		if !ok || id.Str() != hostID {
			continue
		}
		value, ok := attrs.Get(key)
		if ok && value.Str() == expected {
			return true
		}
	}
	return false
}
