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
		"/api/v1/infra/cluster/health": `{"name":"nd-cluster","status":"healthy","healthScore":98,"meta":{"counts":{"remaining":0}}}`,
		"/api/v1/manage/fabric-switches/summary": `{"switches":[
			{"switchName":"leaf101","serialNumber":"N9K-SERIAL-1","switchDbId":"101","fabricName":"fabric-a","role":"leaf","status":"ok","model":"N9K-C93180YC-FX3","nxosVersion":"10.3(5)","ipAddress":"10.0.0.101"}
		],"meta":{"counts":{"remaining":0}}}`,
		"/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/lanSwitches/101/interfaces": `{"interfaces":[
			{"ifName":"eth1/1","switchDbId":"101","serialNumber":"N9K-SERIAL-1","fabricName":"fabric-a","status":"up","speed":"100000000000","rxRate":1000,"txRate":2000,"rxUtilization":10,"txUtilization":20}
		],"meta":{"counts":{"remaining":0}}}`,
		"/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/audit": `{"items":[
			{"id":"audit-1","userName":"operator","status":"success","serialNumber":"N9K-SERIAL-1","fabricName":"fabric-a"}
		],"meta":{"counts":{"remaining":0}}}`,
		"/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/events": `{"items":[
			{"id":"event-1","status":"active","severity":"critical","serialNumber":"N9K-SERIAL-1","fabricName":"fabric-a"}
		],"meta":{"counts":{"remaining":0}}}`,
		"/nexus/insights/api/v1/anomalies": `{"anomalies":[
			{"id":"anomaly-1","name":"CRC spike","siteName":"site-a","fabricName":"fabric-a","serialNumber":"N9K-SERIAL-1","severity":"critical","status":"active","score":90,"confidence":95}
		],"meta":{"counts":{"remaining":0}}}`,
		"/mso/api/v1/tasks": `{"items":[
			{"id":"deploy-1","siteName":"site-a","schemaName":"prod","status":"failed","policyDeltaCount":2}
		],"meta":{"counts":{"remaining":0}}}`,
		"/api/v1/nddb/sessions": `{"items":[
			{"sessionName":"tap-session-1","siteName":"site-a","fabricName":"fabric-a","status":"enabled","ruleCount":3}
		],"meta":{"counts":{"remaining":0}}}`,
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
		"/api/v1/infra/cluster/health": `{"name":"nd-cluster","status":"healthy","healthScore":98,"meta":{"counts":{"remaining":0}}}`,
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
		"/api/v1/infra/cluster/health": `{"name":"nd-cluster","status":"healthy","healthScore":98,"meta":{"counts":{"remaining":0}}}`,
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
		],"meta":{"counts":{"remaining":0}}}`,
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
		],"meta":{"counts":{"remaining":0}}}`,
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
		],"meta":{"counts":{"remaining":0}}}`,
		"/nexus/insights/api/v1/rootcauses": `{"items":[
			{"id":"rca-1","name":"CRC burst","severity":"critical","status":"active","createdAt":"2026-05-25T10:01:00Z","serialNumber":"N9K-SERIAL-1","fabricName":"fabric-a"}
		],"meta":{"counts":{"remaining":0}}}`,
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

func TestNexusDashboardLogsGroupMaxResultsStopsLaterEndpoint(t *testing.T) {
	var callsMu sync.Mutex
	calls := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callsMu.Lock()
		calls[r.URL.Path]++
		callsMu.Unlock()
		switch r.URL.Path {
		case "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/audit":
			_, _ = w.Write([]byte(`{"items":[
				{"id":"audit-1","status":"success","fabricName":"fabric-a"},
				{"id":"audit-2","status":"success","fabricName":"fabric-a"}
			],"meta":{"counts":{"remaining":0}}}`))
		case "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/events":
			_, _ = w.Write([]byte(`{"items":[{"id":"must-not-be-fetched","status":"active"}],"meta":{"counts":{"remaining":0}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	receiver := newTestNexusDashboardLogsReceiver(t, server.URL)
	receiver.config.NexusDashboard.NDFC.MaxResults = 2
	receiver.config.NexusDashboard.Insights.Enabled = false
	receiver.config.NexusDashboard.Orchestrator.Enabled = false
	receiver.config.NexusDashboard.DataBroker.Enabled = false
	receiver.config.NexusDashboard.Targets = NexusDashboardTargetFilters{}

	ld, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 2, ld.LogRecordCount())
	assert.True(t, hasLogRecordAttribute(ld, "event.name", "ndfc.audit"))

	callsMu.Lock()
	assert.Equal(t, 1, calls["/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/audit"])
	assert.Zero(t, calls["/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/events"], "collection must stop when the shared log group result budget reaches zero")
	callsMu.Unlock()
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

func TestNexusDashboardSelectorPathsEscapeSegmentsOnce(t *testing.T) {
	const selector = "selector A/B"
	tests := []struct {
		name         string
		endpoint     nexusDashboardEndpoint
		configure    func(*NexusDashboardTargetFilters)
		expectedPath string
	}{
		{
			name: "fabric",
			endpoint: nexusDashboardEndpoint{
				operation:   "fabric",
				path:        "/api/v1/manage/fabrics/{fabricName}/switches",
				selectorKey: "fabric",
			},
			configure: func(targets *NexusDashboardTargetFilters) {
				targets.Fabrics = []string{selector}
			},
			expectedPath: "/reverse/proxy/api/v1/manage/fabrics/selector%20A%2FB/switches",
		},
		{
			name: "switch ID",
			endpoint: nexusDashboardEndpoint{
				operation:   "switch",
				path:        "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/lanSwitches/{switchId}/interfaces",
				selectorKey: "switch_id",
			},
			configure: func(targets *NexusDashboardTargetFilters) {
				targets.SwitchIDs = []string{selector}
			},
			expectedPath: "/reverse/proxy/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/lanSwitches/selector%20A%2FB/interfaces",
		},
		{
			name: "serial",
			endpoint: nexusDashboardEndpoint{
				operation:   "serial",
				path:        "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/switches/{serialNumber}/intent-config",
				selectorKey: "serial",
			},
			configure: func(targets *NexusDashboardTargetFilters) {
				targets.SwitchSerials = []string{selector}
			},
			expectedPath: "/reverse/proxy/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/switches/selector%20A%2FB/intent-config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestPath := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestPath <- r.URL.EscapedPath()
				_, _ = w.Write([]byte(`{"items":[]}`))
			}))
			defer server.Close()

			cfg := testNexusDashboardConfig(server.URL + "/reverse/proxy")
			cfg.NexusDashboard.Targets = NexusDashboardTargetFilters{}
			tt.configure(&cfg.NexusDashboard.Targets)
			instances := expandNexusDashboardEndpoints([]nexusDashboardEndpoint{tt.endpoint}, cfg)
			require.Len(t, instances, 1)
			require.False(t, instances[0].skipped)

			client, err := newNexusDashboardClient(cfg)
			require.NoError(t, err)
			objects, err := client.List(t.Context(), tt.endpoint.operation, instances[0].path, nil, nexusdashboard.PaginationSingle, 0)
			require.NoError(t, err)
			assert.Empty(t, objects)

			escapedPath := <-requestPath
			assert.Equal(t, tt.expectedPath, escapedPath)
			assert.Contains(t, escapedPath, "%20")
			assert.Contains(t, escapedPath, "%2F")
			assert.NotContains(t, escapedPath, "%2520")
			assert.NotContains(t, escapedPath, "%252F")
		})
	}
}

func TestNexusDashboardPaginationContractsMatchDocumentedCatalog(t *testing.T) {
	type expectation struct {
		strategy      nexusdashboard.PaginationStrategy
		specification string
		reference     string
	}

	const (
		infraSpec       = "Cisco Nexus Dashboard Infrastructure v1 1.1.136 (Nexus Dashboard API v1, Release 4.2 and above)"
		manageSpec      = "Cisco Nexus Dashboard Manage v1 1.1.411 (Nexus Dashboard API v1, Release 4.2 and above)"
		ndfcSpec        = "Cisco Nexus Dashboard Fabric Controller API - LAN 12.5.0 (Nexus Dashboard API v1, Release 4.2 and above)"
		ndoSpec         = "Cisco Nexus Dashboard Orchestrator 5.2.1 (Nexus Dashboard API v1, Release 4.2 and above)"
		legacyInfraSpec = "Legacy infrastructure compatibility route absent from Cisco Nexus Dashboard API 4.2.1 and Infrastructure v1 1.1.136"
		legacyNDFCSpec  = "Legacy NDFC compatibility route absent from Cisco Nexus Dashboard Fabric Controller API - LAN 12.5.0"
		legacyNDOSpec   = "Legacy NDO compatibility route absent from Cisco Nexus Dashboard Orchestrator 5.2.1"
		legacyNISpec    = "Legacy Insights compatibility route absent from Cisco Nexus Dashboard Insights API 6.8.0 and Analyze v1 1.1.209"
		legacyNDDBSpec  = "Legacy Data Broker compatibility route absent from the Cisco Nexus Dashboard API 4.2.1 catalog"

		infraURL    = "https://pubhub.devnetcloud.com/media/nexus-dashboard-api-v1/docs/reference/infra.json"
		manageURL   = "https://pubhub.devnetcloud.com/media/nexus-dashboard-api-v1/docs/reference/manage.json"
		ndfcURL     = "https://pubhub.devnetcloud.com/media/nexus-dashboard-api-v1/docs/reference/nd-fabric-controller-lan-1242.json"
		ndoURL      = "https://pubhub.devnetcloud.com/media/nexus-dashboard-api-v1/docs/reference/orchestration.json"
		legacyURL   = "https://pubhub.devnetcloud.com/media/nexus-dashboard-api-v1/docs/reference/nexus-dashboard-421.json"
		insightsURL = "https://pubhub.devnetcloud.com/media/nexus-dashboard-api-v1/docs/reference/nd-insights-v2.json"
	)

	key := func(profile, signal, operation, path string) string {
		return strings.Join([]string{profile, signal, operation, path}, "|")
	}
	expected := map[string]expectation{}
	add := func(profile, signal string, strategy nexusdashboard.PaginationStrategy, specification, reference string, routes ...string) {
		t.Helper()
		for _, route := range routes {
			operation, path, ok := strings.Cut(route, "\t")
			require.True(t, ok, "invalid pagination contract route %q", route)
			routeKey := key(profile, signal, operation, path)
			require.NotContains(t, expected, routeKey, "duplicate pagination contract route")
			expected[routeKey] = expectation{strategy: strategy, specification: specification, reference: reference}
		}
	}

	add(nexusDashboardAPIProfileUnified, "metrics", nexusdashboard.PaginationSingle, infraSpec, infraURL,
		"nd.cluster.health\t/api/v1/infra/clusterhealth/status",
		"nd.nodes\t/api/v1/infra/cluster/nodes",
		"nd.hardware\t/api/v1/infra/systemResources/nodes/hardware",
		"nd.system.resources\t/api/v1/infra/systemResources/summary",
	)
	add(nexusDashboardAPIProfileUnified, "metrics", nexusdashboard.PaginationOffset, manageSpec, manageURL,
		"ndfc.manage.fabrics\t/api/v1/manage/fabrics",
		"ndfc.manage.fabric_switches\t/api/v1/manage/fabrics/{fabricName}/switches",
	)
	add(nexusDashboardAPIProfileUnified, "metrics", nexusdashboard.PaginationSingle, manageSpec, manageURL,
		"ndfc.manage.fabric_switches_summary\t/api/v1/manage/fabrics/{fabricName}/switches/summary",
	)

	add(nexusDashboardAPIProfileLegacy, "metrics", nexusdashboard.PaginationUnknown, legacyInfraSpec, legacyURL,
		"nd.cluster.health\t/api/v1/infra/cluster/health",
		"nd.nodes\t/api/v1/infra/nodes",
		"nd.services\t/api/v1/infra/services",
		"nd.apps\t/api/v1/infra/apps",
		"nd.storage\t/api/v1/infra/storage",
		"nd.licenses\t/api/v1/infra/licenses",
	)
	add(nexusDashboardAPIProfileLegacy, "metrics", nexusdashboard.PaginationOffset, manageSpec, manageURL,
		"ndfc.manage.fabrics\t/api/v1/manage/fabrics",
	)
	add(nexusDashboardAPIProfileLegacy, "metrics", nexusdashboard.PaginationUnknown, "Legacy Manage compatibility route absent from "+manageSpec, manageURL,
		"ndfc.manage.fabric_switches\t/api/v1/manage/fabric-switches/summary",
	)
	add(nexusDashboardAPIProfileLegacy, "metrics", nexusdashboard.PaginationSingle, ndfcSpec, ndfcURL,
		"ndfc.fabric.status\t/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/fabricstatus",
	)
	add(nexusDashboardAPIProfileLegacy, "metrics", nexusdashboard.PaginationUnknown, legacyNDFCSpec, ndfcURL,
		"ndfc.switches\t/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/switches",
		"ndfc.fabric.switch_overview\t/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/{fabricName}/switches",
		"ndfc.vpc.pairs\t/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/vpcpairs",
		"ndfc.endpoints\t/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/{fabricName}/endpoints",
		"ndfc.policy.deployment\t/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/switches/{serialNumber}/intent-config",
		"ndfc.audit\t/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/audit",
		"ndfc.events\t/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/events",
		"ndfc.interface.stats\t/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/lanSwitches/{switchId}/interfaces",
		"ndfc.telemetry.sync\t/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/telemetry/sync/status",
	)
	add(nexusDashboardAPIProfileLegacy, "metrics", nexusdashboard.PaginationUnknown, legacyNISpec, insightsURL,
		"insights.anomalies\t/nexus/insights/api/v1/anomalies",
		"insights.advisories\t/nexus/insights/api/v1/advisories",
		"insights.root_causes\t/nexus/insights/api/v1/rootcauses",
		"insights.sites\t/nexus/insights/api/v1/sites",
		"insights.flow_analyses\t/nexus/insights/api/v1/flow/analyses",
		"insights.recommendations\t/nexus/insights/api/v1/recommendations",
	)
	add(nexusDashboardAPIProfileLegacy, "metrics", nexusdashboard.PaginationSingle, ndoSpec, ndoURL,
		"ndo.sites\t/mso/api/v1/sites",
		"ndo.schemas\t/mso/api/v1/schemas",
	)
	add(nexusDashboardAPIProfileLegacy, "metrics", nexusdashboard.PaginationUnknown, legacyNDOSpec, ndoURL,
		"ndo.deployments\t/mso/api/v1/tasks",
		"ndo.alerts\t/mso/api/v1/alerts",
		"ndo.audit\t/mso/api/v1/audit",
	)
	add(nexusDashboardAPIProfileLegacy, "metrics", nexusdashboard.PaginationUnknown, legacyNDDBSpec, legacyURL,
		"nddb.health\t/api/v1/nddb/health",
		"nddb.switches\t/api/v1/nddb/switches",
		"nddb.rules\t/api/v1/nddb/rules",
		"nddb.sessions\t/api/v1/nddb/sessions",
		"nddb.events\t/api/v1/nddb/events",
	)

	add(nexusDashboardAPIProfileLegacy, "logs", nexusdashboard.PaginationUnknown, legacyNDFCSpec, ndfcURL,
		"ndfc.audit\t/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/audit",
		"ndfc.events\t/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/events",
	)
	add(nexusDashboardAPIProfileLegacy, "logs", nexusdashboard.PaginationUnknown, legacyNISpec, insightsURL,
		"insights.anomalies\t/nexus/insights/api/v1/anomalies",
		"insights.advisories\t/nexus/insights/api/v1/advisories",
		"insights.root_causes\t/nexus/insights/api/v1/rootcauses",
	)
	add(nexusDashboardAPIProfileLegacy, "logs", nexusdashboard.PaginationUnknown, legacyNDOSpec, ndoURL,
		"ndo.audit\t/mso/api/v1/audit",
		"ndo.deployments\t/mso/api/v1/tasks",
	)
	add(nexusDashboardAPIProfileLegacy, "logs", nexusdashboard.PaginationUnknown, legacyNDDBSpec, legacyURL,
		"nddb.events\t/api/v1/nddb/events",
	)

	catalogs := []struct {
		profile   string
		signal    string
		endpoints []nexusDashboardEndpoint
	}{
		{profile: nexusDashboardAPIProfileUnified, signal: "metrics", endpoints: nexusDashboardMetricEndpoints(nexusDashboardAPIProfileUnified)},
		{profile: nexusDashboardAPIProfileUnified, signal: "logs", endpoints: nexusDashboardLogEndpoints(nexusDashboardAPIProfileUnified)},
		{profile: nexusDashboardAPIProfileLegacy, signal: "metrics", endpoints: nexusDashboardMetricEndpoints(nexusDashboardAPIProfileLegacy)},
		{profile: nexusDashboardAPIProfileLegacy, signal: "logs", endpoints: nexusDashboardLogEndpoints(nexusDashboardAPIProfileLegacy)},
	}
	seen := map[string]bool{}
	for _, catalog := range catalogs {
		for _, endpoint := range catalog.endpoints {
			routeKey := key(catalog.profile, catalog.signal, endpoint.operation, endpoint.path)
			require.False(t, seen[routeKey], "duplicate endpoint catalog entry %q", routeKey)
			seen[routeKey] = true
			want, ok := expected[routeKey]
			require.True(t, ok, "endpoint %q is missing from the documented pagination contract table", routeKey)
			assert.Equal(t, want.strategy, endpoint.pagination.strategy, routeKey)
			assert.Equal(t, want.specification, endpoint.pagination.specification, routeKey)
			assert.Equal(t, want.reference, endpoint.pagination.reference, routeKey)
			delete(expected, routeKey)
		}
	}
	assert.Empty(t, expected, "documented pagination routes missing from endpoint catalogs")
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
		switch r.URL.Path {
		case "/api/v1/manage/fabrics", "/api/v1/manage/fabrics/fabric-a/switches":
			assert.Equal(t, "100", r.URL.Query().Get("max"))
			assert.Equal(t, "0", r.URL.Query().Get("offset"))
		default:
			assert.False(t, r.URL.Query().Has("max"), r.URL.Path)
			assert.False(t, r.URL.Query().Has("offset"), r.URL.Path)
		}
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

func TestNexusDashboardGroupMaxResultsSpansEndpointInstancesBeforeFiltering(t *testing.T) {
	routes := map[string]string{
		"/api/v1/infra/clusterhealth/status":           `{"isHealthy":true,"name":"filtered"}`,
		"/api/v1/infra/cluster/nodes":                  `{"nodes":[]}`,
		"/api/v1/infra/systemResources/nodes/hardware": `{"nodes":[{"name":"keep-1","id":"keep-1"},{"name":"keep-2","id":"keep-2"}]}`,
		"/api/v1/infra/systemResources/summary":        `{"nodes":[{"name":"must-not-be-fetched","id":"unexpected"}]}`,
	}

	var callsMu sync.Mutex
	calls := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	receiver.config.NexusDashboard.Platform.MaxResults = 3
	receiver.config.NexusDashboard.NDFC.Enabled = false
	receiver.config.NexusDashboard.Insights.Enabled = false
	receiver.config.NexusDashboard.Orchestrator.Enabled = false
	receiver.config.NexusDashboard.DataBroker.Enabled = false
	receiver.config.NexusDashboard.Performance.Enabled = false
	receiver.config.DeviceSelection = DeviceSelectionConfig{
		Include: DeviceSelectionMatchConfig{HostNames: []string{"keep-1", "keep-2"}},
	}

	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.True(t, hasResourceHostID(md, "keep-1"))
	assert.True(t, hasResourceHostID(md, "keep-2"))
	assert.False(t, hasResourceHostID(md, "filtered"))
	assert.False(t, hasResourceHostID(md, "unexpected"))
	assert.True(t, intMetricValueExists(md, "nexus_dashboard.scrape.partial_success", 0))
	assert.NotContains(t, metricNames(md), "nexus_dashboard.service.skipped")

	callsMu.Lock()
	assert.Equal(t, map[string]int{
		"/api/v1/infra/clusterhealth/status":           1,
		"/api/v1/infra/cluster/nodes":                  1,
		"/api/v1/infra/systemResources/nodes/hardware": 1,
	}, calls, "all-real endpoint collection must stop without an extra request when the group budget reaches zero")
	callsMu.Unlock()
}

func TestNexusDashboardGroupMaxResultsConsumesPartialErrorResults(t *testing.T) {
	var callsMu sync.Mutex
	calls := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callsMu.Lock()
		calls[r.URL.Path]++
		callsMu.Unlock()
		switch r.URL.Path {
		case "/api/v1/infra/clusterhealth/status":
			_, _ = w.Write([]byte(`{"isHealthy":true,"name":"partial","meta":{"counts":{"remaining":1}}}`))
		case "/api/v1/infra/cluster/nodes":
			_, _ = w.Write([]byte(`{"nodes":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	receiver := newTestNexusDashboardMetricsReceiver(t, server.URL)
	receiver.config.NexusDashboard.APIProfile = nexusDashboardAPIProfileUnified
	receiver.config.NexusDashboard.Platform.MaxResults = 1
	receiver.config.NexusDashboard.NDFC.Enabled = false
	receiver.config.NexusDashboard.Insights.Enabled = false
	receiver.config.NexusDashboard.Orchestrator.Enabled = false
	receiver.config.NexusDashboard.DataBroker.Enabled = false
	receiver.config.NexusDashboard.Performance.Enabled = false
	receiver.config.DeviceSelection = DeviceSelectionConfig{}

	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.True(t, hasResourceHostID(md, "partial"))
	assert.True(t, intMetricValueExists(md, "nexus_dashboard.scrape.partial_success", 1))

	callsMu.Lock()
	assert.Equal(t, 1, calls["/api/v1/infra/clusterhealth/status"])
	assert.Zero(t, calls["/api/v1/infra/cluster/nodes"], "partial results must consume the group budget before error handling")
	callsMu.Unlock()
}

func TestNexusDashboardUnifiedMissingFabricReportsScopedEndpointsAcrossGroupBudget(t *testing.T) {
	for _, test := range []struct {
		name     string
		response string
	}{
		{name: "budget available", response: `{"fabrics":[],"meta":{"counts":{"total":0}}}`},
		{name: "budget exhausted", response: `{"fabrics":[{"name":"fabric-a"}],"meta":{"counts":{"total":1}}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var callsMu sync.Mutex
			calls := map[string]int{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				callsMu.Lock()
				calls[r.URL.Path]++
				callsMu.Unlock()
				if r.URL.Path != "/api/v1/manage/fabrics" {
					http.NotFound(w, r)
					return
				}
				_, _ = w.Write([]byte(test.response))
			}))
			defer server.Close()

			receiver := newTestNexusDashboardMetricsReceiver(t, server.URL)
			receiver.config.NexusDashboard.APIProfile = nexusDashboardAPIProfileUnified
			receiver.config.NexusDashboard.NDFC.MaxResults = 1
			receiver.config.NexusDashboard.Targets = NexusDashboardTargetFilters{}
			receiver.config.NexusDashboard.Platform.Enabled = false
			md, err := receiver.scrape(t.Context())
			require.NoError(t, err)

			assert.True(t, intMetricValueExists(md, "nexus_dashboard.scrape.partial_success", 1))
			assert.NotContains(t, metricNames(md), "nexus_dashboard.scrape.last_success")
			skipped := requireMetricByName(t, md, "nexus_dashboard.service.skipped")
			require.Equal(t, 2, skipped.Gauge().DataPoints().Len())
			for _, operation := range []string{"ndfc.manage.fabric_switches", "ndfc.manage.fabric_switches_summary"} {
				assert.True(t, hasMetricDatapointAttribute(md, "nexus_dashboard.service.skipped", "nexus_dashboard.api.operation", operation))
			}

			callsMu.Lock()
			assert.Equal(t, map[string]int{"/api/v1/manage/fabrics": 1}, calls, "synthetic skipped endpoints must not issue requests")
			callsMu.Unlock()
		})
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
	cfg.ControllerConfig.Timeout = 5 * time.Second
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
		if r.URL.Path == "/api/v1/manage/fabrics" {
			assert.True(t, r.URL.Query().Has("max"))
			assert.True(t, r.URL.Query().Has("offset"))
		} else {
			assert.False(t, r.URL.Query().Has("max"), r.URL.Path)
			assert.False(t, r.URL.Query().Has("offset"), r.URL.Path)
		}
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
