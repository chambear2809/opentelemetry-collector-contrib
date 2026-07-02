// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer/consumertest"
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
	assert.True(t, hasLogResourceAttribute(ld, "host.id", "N9K-SERIAL-1"))
	assert.False(t, hasLogResourceAttribute(ld, "host.id", "N9K-SERIAL-9"))
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
	for _, endpoint := range nexusDashboardMetricEndpoints() {
		groups[endpoint.group] = true
		operations[endpoint.operation] = true
	}
	for _, endpoint := range nexusDashboardLogEndpoints() {
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
