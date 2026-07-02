// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/aci"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestACIScrapeEmitsTroubleshootingMetrics(t *testing.T) {
	server := newACIFixtureServer(t, map[string]string{
		"/api/class/fabricNode.json": `{"totalCount":"1","imdata":[
			{"fabricNode":{"attributes":{"dn":"topology/pod-1/node-101","id":"101","serial":"ACI-SERIAL-1","name":"leaf101","role":"leaf","fabricSt":"active","model":"N9K-C93180YC-FX3","version":"15.2(8)"}}}
		]}`,
		"/api/class/faultInst.json": `{"totalCount":"1","imdata":[
			{"faultInst":{"attributes":{"dn":"topology/pod-1/node-101/sys/ch/fault-F123","code":"F123","severity":"critical","lc":"raised","domain":"infra","descr":"Interface errors above threshold","lastTransition":"2026-05-25T10:00:00Z"}}}
		]}`,
		"/api/class/l1PhysIf.json": `{"totalCount":"1","imdata":[
			{"l1PhysIf":{"attributes":{"dn":"topology/pod-1/node-101/sys/phys-[eth1/1]","id":"eth1/1","operSt":"up","speed":"100G"}}}
		]}`,
		"/api/class/fvCEp.json": `{"totalCount":"1","imdata":[
			{"fvCEp":{"attributes":{"dn":"uni/tn-prod/ap-app/epg-web/cep-00:11:22:33:44:55","mac":"00:11:22:33:44:55","ip":"10.1.1.10","lcC":"learned"}}}
		]}`,
		"/api/class/fvTenant.json": `{"totalCount":"1","imdata":[
			{"fvTenant":{"attributes":{"dn":"uni/tn-prod","name":"prod","status":"created"}}}
		]}`,
		"/api/class/aaaModLR.json": `{"totalCount":"1","imdata":[
			{"aaaModLR":{"attributes":{"dn":"uni/tn-prod","severity":"info","status":"modified","user":"operator","descr":"tenant changed"}}}
		]}`,
		"/api/class/eventRecord.json": `{"totalCount":"1","imdata":[
			{"eventRecord":{"attributes":{"dn":"topology/pod-1/node-101","severity":"warning","status":"raised","descr":"link flap"}}}
		]}`,
	})
	defer server.Close()

	receiver := newTestACIMetricsReceiver(t, server.URL)
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	names := metricNames(md)
	assert.Contains(t, names, "aci.api.request.duration")
	assert.Contains(t, names, "aci.resource.info")
	assert.Contains(t, names, "aci.audit.record.count")
	assert.Contains(t, names, "aci.event.count")
	assert.Contains(t, names, "cisco.device.up")
	assert.Contains(t, names, "aci.fault.active")
	assert.Contains(t, names, "system.network.interface.status")
	assert.Contains(t, names, "aci.endpoint.present")
	assert.Contains(t, names, "aci.tenant.status")
	assert.True(t, hasResourceHostID(md, "ACI-SERIAL-1"))
	assert.True(t, intMetricValueExists(md, "aci.scrape.partial_success", 0))
	assert.True(t, intMetricValueExists(md, "aci.audit.record.count", 1))
	assert.True(t, intMetricValueExists(md, "aci.event.count", 1))
	assert.True(t, hasMetricDatapointAttribute(md, "aci.audit.record.count", "aci.operation", "audit.modifications"))
	assert.False(t, hasMetricDatapointAttribute(md, "aci.audit.record.count", "user.name", "operator"))
}

func TestACIScrapeAppliesSharedDeviceSelection(t *testing.T) {
	server := newACIFixtureServer(t, map[string]string{
		"/api/class/fabricNode.json": `{"totalCount":"2","imdata":[
			{"fabricNode":{"attributes":{"dn":"topology/pod-1/node-101","id":"101","serial":"ACI-SERIAL-1","name":"leaf101","fabricSt":"active"}}},
			{"fabricNode":{"attributes":{"dn":"topology/pod-1/node-909","id":"909","serial":"ACI-SERIAL-9","name":"leaf909","fabricSt":"active"}}}
		]}`,
	})
	defer server.Close()

	receiver := newTestACIMetricsReceiver(t, server.URL)
	receiver.config.ACI.Targets.NodeIDs = []string{"101", "909"}
	receiver.config.ACI.Targets.Serials = []string{"ACI-SERIAL-1", "ACI-SERIAL-9"}
	receiver.config.DeviceSelection.Include.Serials = []string{"ACI-SERIAL-1"}
	receiver.config.DeviceSelection.Exclude.Serials = []string{"ACI-SERIAL-9"}
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, hasResourceHostID(md, "ACI-SERIAL-1"))
	assert.False(t, hasResourceHostID(md, "ACI-SERIAL-9"))
}

func TestACILogsApplySharedDeviceSelection(t *testing.T) {
	server := newACIFixtureServer(t, map[string]string{
		"/api/class/faultInst.json": `{"totalCount":"2","imdata":[
			{"faultInst":{"attributes":{"dn":"topology/pod-1/node-101/sys/ch/fault-F123","code":"F123","severity":"critical","lc":"raised","descr":"Interface errors"}}},
			{"faultInst":{"attributes":{"dn":"topology/pod-1/node-909/sys/ch/fault-F999","code":"F999","severity":"critical","lc":"raised","descr":"Interface errors"}}}
		]}`,
	})
	defer server.Close()

	receiver := newTestACILogsReceiver(t, server.URL)
	receiver.config.ACI.Targets.NodeIDs = []string{"101", "909"}
	receiver.config.DeviceSelection.Include.DeviceIDs = []string{"101"}
	receiver.config.DeviceSelection.Exclude.DeviceIDs = []string{"909"}
	ld, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.Equal(t, 1, ld.LogRecordCount())
	assert.True(t, hasLogResourceAttribute(ld, "host.id", "101"))
	assert.False(t, hasLogResourceAttribute(ld, "host.id", "909"))
}

func TestACILogsEmitEvidenceAndDeduplicate(t *testing.T) {
	server := newACIFixtureServer(t, map[string]string{
		"/api/class/faultInst.json": `{"totalCount":"1","imdata":[
			{"faultInst":{"attributes":{"dn":"topology/pod-1/node-101/sys/ch/fault-F123","code":"F123","severity":"critical","lc":"raised","descr":"Interface errors above threshold","lastTransition":"2026-05-25T10:00:00Z"}}}
		]}`,
		"/api/class/aaaModLR.json": `{"totalCount":"1","imdata":[
			{"aaaModLR":{"attributes":{"dn":"uni/tn-prod","user":"operator","created":"2026-05-25T10:01:00Z","descr":"tenant changed"}}}
		]}`,
		"/api/class/eventRecord.json": `{"totalCount":"1","imdata":[
			{"eventRecord":{"attributes":{"dn":"topology/pod-1/node-101","severity":"warning","created":"2026-05-25T10:02:00Z","descr":"link flap"}}}
		]}`,
	})
	defer server.Close()

	receiver := newTestACILogsReceiver(t, server.URL)
	ld, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 3, ld.LogRecordCount())
	assert.True(t, hasLogRecordAttribute(ld, "event.name", "fault.instances"))
	assert.True(t, hasLogRecordAttribute(ld, "event.name", "audit.modifications"))
	assert.True(t, hasLogRecordAttribute(ld, "event.name", "events.records"))
	assert.True(t, hasLogRecordAttribute(ld, "user.name", "operator"))

	ld, err = receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 0, ld.LogRecordCount())
}

func TestACICatalogCoversTroubleshootingDomains(t *testing.T) {
	groups := map[string]bool{}
	operations := map[string]bool{}
	for _, endpoint := range aciMetricEndpoints() {
		groups[endpoint.group] = true
		operations[endpoint.operation] = true
	}
	for _, endpoint := range aciLogEndpoints() {
		groups[endpoint.group] = true
		operations[endpoint.operation] = true
	}
	for _, group := range []string{"controller_health", "fabric", "nodes", "faults", "audit", "events", "stats", "endpoints", "tenants", "topology"} {
		assert.True(t, groups[group], "missing ACI group %q", group)
	}
	for _, operation := range []string{
		"apic.top_system",
		"fabric.nodes",
		"fault.instances",
		"audit.modifications",
		"events.records",
		"stats.interfaces.l1",
		"endpoints.mac",
		"tenant.tenants",
		"tenant.contracts",
		"topology.lldp",
		"topology.links",
	} {
		assert.True(t, operations[operation], "missing ACI operation %q", operation)
	}
}

func TestInterfaceNameFromACIDNHandlesSlashedInterfaceNames(t *testing.T) {
	assert.Equal(t, "eth1/34", interfaceNameFromACIDN("topology/pod-1/node-202/sys/phys-[eth1/34]/phys"))
	assert.Equal(t, "eth1/1", interfaceNameFromACIDN("topology/pod-1/node-101/sys/phys-[eth1/1]"))
}

func TestNodeIDFromACIDN(t *testing.T) {
	assert.Equal(t, "202", nodeIDFromACIDN("topology/pod-1/node-202/sys/procsys/CDprocSysCPU5min"))
	assert.Equal(t, "101", nodeIDFromACIDN("topology/pod-1/node-101/sys/phys-[eth1/1]"))
	assert.Empty(t, nodeIDFromACIDN("uni/tn-prod/ap-app/epg-web"))
}

func TestACIInterfaceRatesUseCanonicalDescriptors(t *testing.T) {
	builder := newACIMetricsBuilder(time.Now(), "test", nil)
	builder.recordStatsObject(builder.globalResource(), aci.Object{
		"dn":        "topology/pod-1/node-101/sys/phys-[eth1/1]",
		"bytesRate": float64(1),
		"pktsRate":  float64(2),
	})

	ioRate := requireMetricByName(t, builder.emit(), "cisco.interface.io.rate")
	assert.Equal(t, "bit/s", ioRate.Unit())
	require.Equal(t, 1, ioRate.Gauge().DataPoints().Len())
	assert.Equal(t, float64(8), ioRate.Gauge().DataPoints().At(0).DoubleValue())

	packetRate := requireMetricByName(t, builder.emit(), "cisco.interface.packet.rate")
	assert.Equal(t, "{packet}/s", packetRate.Unit())
	assert.Equal(t, float64(2), packetRate.Gauge().DataPoints().At(0).DoubleValue())
	assert.NotContains(t, metricNames(builder.emit()), "system.network.packets")
}

func TestACIFabricHealthUsesFirstPresentSynonym(t *testing.T) {
	builder := newACIMetricsBuilder(time.Now(), "test", nil)
	builder.recordFabricObject(builder.globalResource(), aci.Object{
		"cur":         float64(91),
		"health":      float64(82),
		"healthScore": float64(73),
	}, "")

	metric := requireMetricByName(t, builder.emit(), "aci.fabric.health")
	require.Equal(t, 1, metric.Gauge().DataPoints().Len())
	assert.Equal(t, float64(91), metric.Gauge().DataPoints().At(0).DoubleValue())
}

func requireMetricByName(t *testing.T, md pmetric.Metrics, name string) pmetric.Metric {
	t.Helper()
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		for j := 0; j < md.ResourceMetrics().At(i).ScopeMetrics().Len(); j++ {
			metrics := md.ResourceMetrics().At(i).ScopeMetrics().At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				if metrics.At(k).Name() == name {
					return metrics.At(k)
				}
			}
		}
	}
	require.FailNow(t, "metric not found", name)
	return pmetric.Metric{}
}

func newTestACIMetricsReceiver(t *testing.T, endpoint string) *aciMetricsReceiver {
	t.Helper()
	cfg := testACIConfig(endpoint)
	receiver, err := newACIMetricsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)
	return receiver
}

func newTestACILogsReceiver(t *testing.T, endpoint string) *aciLogsReceiver {
	t.Helper()
	cfg := testACIConfig(endpoint)
	receiver, err := newACILogsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, &consumertest.LogsSink{})
	require.NoError(t, err)
	return receiver
}

func testACIConfig(endpoint string) *Config {
	cfg := createDefaultConfig().(*Config)
	cfg.Timeout = 5 * time.Second
	cfg.ACI = defaultACIConfig()
	cfg.ACI.Enabled = true
	cfg.ACI.Controllers = []ACIControllerConfig{{Endpoint: endpoint, Name: "apic-1"}}
	cfg.ACI.MaxRetries = 1
	cfg.ACI.Auth = ControllerAuthConfig{
		Username: "admin",
		Password: configopaque.String("password"),
	}
	cfg.ACI.Targets = ACITargetFilters{
		NodeIDs:        []string{"101"},
		Serials:        []string{"ACI-SERIAL-1"},
		Tenants:        []string{"prod"},
		EPGs:           []string{"web"},
		InterfaceNames: []string{"eth1/1"},
	}
	return cfg
}

func newACIFixtureServer(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token"}}}]}`))
			return
		}
		cookie, err := r.Cookie("APIC-cookie")
		require.NoError(t, err)
		assert.Equal(t, "apic-token", cookie.Value)
		if body, ok := routes[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
	}))
}
