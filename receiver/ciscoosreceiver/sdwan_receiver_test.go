// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestSDWANScrapeEmitsCoreMetrics(t *testing.T) {
	server, _ := newSDWANFixtureServer(t, map[string]string{
		"/dataservice/clusterManagement/health/summary": `{"status":"normal","clusterHealth":98}`,
		"/dataservice/client/server":                    `{"status":"running","version":"20.18.1"}`,
		"/dataservice/settings/configuration/device":    `{"status":"ok"}`,
		"/dataservice/device": `{"data":[
			{"host-name":"edge-1","system-ip":"10.0.0.1","uuid":"uuid-1","chasisNumber":"SDWAN-SERIAL-1","site-id":"100","personality":"vedge","device-type":"vedge","device-model":"C8000V","version":"20.18.1","status":"normal","reachability":"reachable","validity":"valid","certificateValidity":"valid","cpuLoad":25,"memUsage":40,"uptimeSeconds":3600}
		]}`,
		"/dataservice/device/control/synced/connections": `{"data":[{"state":"up","peer-type":"vsmart","local-color":"biz-internet","remote-color":"mpls","remote-system-ip":"10.0.0.2","actualConnections":2,"expectedConnections":2}]}`,
		"/dataservice/device/bfd/synced/sessions":        `{"data":[{"state":"up","local-color":"biz-internet","remote-color":"mpls","remote-system-ip":"10.0.0.2","transitions":1,"flaps":0}]}`,
		"/dataservice/device/app-route/statistics":       `{"data":[{"latency":12,"jitter":3,"loss":0.1,"local-color":"biz-internet","remote-color":"mpls","sla-class":"ai-critical","application":"openai-api","sla-state":"ok"}]}`,
		"/dataservice/device/interface/synced":           `{"data":[{"ifname":"ge0/0","oper-status":"up","admin-status":"up","speed":1000000000,"rx-bytes":1024,"tx-bytes":2048,"rx-packets":10,"tx-packets":20,"rx-errors":1,"rx-drops":3,"tx-drops":2,"color":"biz-internet","vpn-id":"0"}]}`,
		"/dataservice/alarms":                            `{"data":[{"id":"alarm-1","severity":"critical","status":"active","system-ip":"10.0.0.1","site-id":"100"}]}`,
		"/dataservice/events":                            `{"data":[{"eventId":"event-1","severity":"info","system-ip":"10.0.0.1"}]}`,
		"/dataservice/auditlog":                          `{"data":[{"entry_uuid":"audit-1","severity":"info","user":"admin"}]}`,
	}, nil)
	defer server.Close()

	receiver := newTestSDWANReceiver(t, server.URL, nil)
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	names := metricNames(md)
	for _, name := range []string{
		"sdwan.api.request.duration",
		"sdwan.scrape.partial_success",
		"sdwan.scrape.last_success",
		"sdwan.resource.info",
		"sdwan.resource.status",
		"cisco.device.up",
		"system.cpu.utilization",
		"system.memory.utilization",
		"sdwan.control.connection.status",
		"sdwan.bfd.session.status",
		"sdwan.app_route.latency",
		"sdwan.app_route.loss",
		"system.network.interface.status",
		"system.network.io",
		"system.network.packet.count",
		"sdwan.event.count",
	} {
		assert.Contains(t, names, name)
	}
	assert.True(t, hasResourceHostID(md, "SDWAN-SERIAL-1"))
	assert.True(t, intMetricValueExists(md, "sdwan.scrape.partial_success", 0))
	assert.True(t, intMetricValueExists(md, "cisco.device.up", 1))
	assert.Equal(t, 2, metricDataPointCount(md, "system.network.packet.count"))
	assert.Equal(t, 2, metricDataPointCount(md, "system.network.packet.dropped"))
}

func TestSDWANScrapeAppliesTargetAndDeviceSelection(t *testing.T) {
	server, _ := newSDWANFixtureServer(t, map[string]string{
		"/dataservice/device": `{"data":[
			{"host-name":"edge-1","system-ip":"10.0.0.1","uuid":"uuid-1","chasisNumber":"SDWAN-SERIAL-1","site-id":"100","personality":"vedge","status":"reachable"},
			{"host-name":"edge-2","system-ip":"10.0.0.2","uuid":"uuid-2","chasisNumber":"SDWAN-SERIAL-2","site-id":"200","personality":"vedge","status":"reachable"}
		]}`,
		"/dataservice/alarms":   `{"data":[]}`,
		"/dataservice/events":   `{"data":[]}`,
		"/dataservice/auditlog": `{"data":[]}`,
	}, nil)
	defer server.Close()

	receiver := newTestSDWANReceiver(t, server.URL, func(cfg *Config) {
		cfg.SDWAN.Manager.Enabled = false
		cfg.SDWAN.ControlPlane.Enabled = false
		cfg.SDWAN.BFD.Enabled = false
		cfg.SDWAN.AppRoute.Enabled = false
		cfg.SDWAN.Interfaces.Enabled = false
		cfg.SDWAN.Targets.SiteIDs = []string{"100"}
		cfg.DeviceSelection.Include.Serials = []string{"SDWAN-SERIAL-1"}
		cfg.DeviceSelection.Exclude.Serials = []string{"SDWAN-SERIAL-2"}
	})
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, hasResourceHostID(md, "SDWAN-SERIAL-1"))
	assert.False(t, hasResourceHostID(md, "SDWAN-SERIAL-2"))
}

func TestSDWANMetricSemanticsAndIntegerPrecision(t *testing.T) {
	server, _ := newSDWANFixtureServer(t, map[string]string{
		"/dataservice/device": `{"data":[
			{"host-name":"edge-1","system-ip":"10.0.0.1","uuid":"uuid-1","chasisNumber":"SDWAN-SERIAL-1","site-id":"100","personality":"vedge","status":"reachable","cpuLoad":25,"memUsage":0.4}
		]}`,
		"/dataservice/device/bfd/synced/sessions": `{"data":[{"state":"up","transitions":9007199254740993,"flaps":9007199254740994}]}`,
		"/dataservice/device/interface/synced": `{"data":[{
			"ifname":"ge0/0","oper-status":"up","speed-mbps":1000,
			"rx-kbps":123.5,"tx-kbps":50,
			"rx-bytes":9007199254740993,"tx-bytes":9007199254740994,
			"rx-packets":9007199254740995,"tx-packets":9007199254740996,
			"rx-errors":9007199254740997,"tx-errors":9007199254740998,
			"rx-drops":9007199254740999,"tx-drops":9007199254741000
		}]}`,
	}, nil)
	defer server.Close()

	receiver := newTestSDWANReceiver(t, server.URL, func(cfg *Config) {
		cfg.SDWAN.Manager.Enabled = false
		cfg.SDWAN.ControlPlane.Enabled = false
		cfg.SDWAN.AppRoute.Enabled = false
		cfg.SDWAN.Alarms.Enabled = false
		cfg.SDWAN.Events.Enabled = false
		cfg.SDWAN.Audit.Enabled = false
	})
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.Equal(t, 0.25, sdwanGaugeDoubleValue(t, md, "SDWAN-SERIAL-1", "system.cpu.utilization", "", ""))
	assert.Equal(t, 0.4, sdwanGaugeDoubleValue(t, md, "SDWAN-SERIAL-1", "system.memory.utilization", "", ""))
	assert.Equal(t, int64(1_000_000_000), sdwanGaugeIntValue(t, md, "SDWAN-SERIAL-1", "cisco.interface.speed", "", ""))
	assert.Equal(t, "bit/s", findSDWANMetricForHost(t, md, "SDWAN-SERIAL-1", "cisco.interface.speed").Unit())
	assert.Equal(t, 123_500.0, sdwanGaugeDoubleValue(t, md, "SDWAN-SERIAL-1", "cisco.interface.io.rate", "network.io.direction", "receive"))
	assert.Equal(t, 50_000.0, sdwanGaugeDoubleValue(t, md, "SDWAN-SERIAL-1", "cisco.interface.io.rate", "network.io.direction", "transmit"))
	assert.Equal(t, "bit/s", findSDWANMetricForHost(t, md, "SDWAN-SERIAL-1", "cisco.interface.io.rate").Unit())
	assert.Equal(t, 2, metricDataPointCount(md, "cisco.interface.io.rate"))

	assertSDWANCumulativeInt(t, md, "SDWAN-SERIAL-1", "system.network.io", "network.io.direction", "receive", 9007199254740993)
	assertSDWANCumulativeInt(t, md, "SDWAN-SERIAL-1", "system.network.io", "network.io.direction", "transmit", 9007199254740994)
	assert.Equal(t, "By", findSDWANMetricForHost(t, md, "SDWAN-SERIAL-1", "system.network.io").Unit())
	assert.Equal(t, 2, metricDataPointCount(md, "system.network.io"), "kbps window rates must not be exported as byte totals")
	assertSDWANCumulativeInt(t, md, "SDWAN-SERIAL-1", "system.network.packet.count", "network.io.direction", "receive", 9007199254740995)
	assertSDWANCumulativeInt(t, md, "SDWAN-SERIAL-1", "system.network.errors", "network.io.direction", "receive", 9007199254740997)
	assertSDWANCumulativeInt(t, md, "SDWAN-SERIAL-1", "system.network.packet.dropped", "network.io.direction", "receive", 9007199254740999)
	assertSDWANCumulativeInt(t, md, "SDWAN-SERIAL-1", "sdwan.bfd.session.transitions", "", "", 9007199254740993)
	assertSDWANCumulativeInt(t, md, "SDWAN-SERIAL-1", "sdwan.bfd.session.flap.count", "", "", 9007199254740994)
}

func TestSDWANPercentRatioDoesNotDoubleScaleRatios(t *testing.T) {
	tests := map[string]struct {
		input float64
		want  float64
		ok    bool
	}{
		"percentage":    {input: 25, want: 0.25, ok: true},
		"already ratio": {input: 0.25, want: 0.25, ok: true},
		"one":           {input: 1, want: 1, ok: true},
		"invalid high":  {input: 101, ok: false},
		"invalid low":   {input: -1, ok: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := sdwanPercentRatio(tt.input)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSDWANEventMetricsAndLogsApplyNativeAndSharedFilters(t *testing.T) {
	server, _ := newSDWANFixtureServer(t, map[string]string{
		"/dataservice/device": `{"data":[
			{"host-name":"edge-1","system-ip":"10.0.0.1","uuid":"uuid-1","chasisNumber":"SDWAN-SERIAL-1","site-id":"100","personality":"vedge","status":"reachable"},
			{"host-name":"edge-2","system-ip":"10.0.0.2","uuid":"uuid-2","chasisNumber":"SDWAN-SERIAL-2","site-id":"200","personality":"vedge","status":"reachable"},
			{"host-name":"edge-3","system-ip":"10.0.0.3","uuid":"uuid-3","chasisNumber":"SDWAN-SERIAL-3","site-id":"300","personality":"vedge","status":"reachable"}
		]}`,
		"/dataservice/alarms": `{"data":[
			{"id":"alarm-1","severity":"critical","system-ip":"10.0.0.1","site-id":"100"},
			{"id":"alarm-2","severity":"critical","system-ip":"10.0.0.2","site-id":"200"},
			{"id":"alarm-3","severity":"critical","system-ip":"10.0.0.3","site-id":"300"}
		]}`,
		"/dataservice/events":   `{"data":[]}`,
		"/dataservice/auditlog": `{"data":[]}`,
	}, nil)
	defer server.Close()

	configureFilters := func(cfg *Config) {
		cfg.SDWAN.Manager.Enabled = false
		cfg.SDWAN.ControlPlane.Enabled = false
		cfg.SDWAN.BFD.Enabled = false
		cfg.SDWAN.AppRoute.Enabled = false
		cfg.SDWAN.Interfaces.Enabled = false
		cfg.SDWAN.Targets.SiteIDs = []string{"100", "200"}
		cfg.DeviceSelection.Exclude.Serials = []string{"SDWAN-SERIAL-2"}
	}

	metricsReceiver := newTestSDWANReceiver(t, server.URL, configureFilters)
	md, err := metricsReceiver.scrape(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1, metricDataPointCount(md, "sdwan.event.count"))
	assert.True(t, hasMetricDatapointAttribute(md, "sdwan.event.count", "sdwan.system_ip", "10.0.0.1"))
	assert.False(t, hasMetricDatapointAttribute(md, "sdwan.event.count", "sdwan.system_ip", "10.0.0.2"))
	assert.False(t, hasMetricDatapointAttribute(md, "sdwan.event.count", "sdwan.system_ip", "10.0.0.3"))

	logsReceiver := newTestSDWANLogsReceiver(t, server.URL, configureFilters)
	ld, err := logsReceiver.scrape(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1, ld.LogRecordCount())
	assert.True(t, logRecordAttributeExists(ld, "sdwan.system_ip", "10.0.0.1"))
	assert.False(t, logRecordAttributeExists(ld, "sdwan.system_ip", "10.0.0.2"))
	assert.False(t, logRecordAttributeExists(ld, "sdwan.system_ip", "10.0.0.3"))
}

func TestMetricFilterDropsConfiguredMetrics(t *testing.T) {
	server, _ := newSDWANFixtureServer(t, map[string]string{
		"/dataservice/device": `{"data":[
			{"host-name":"edge-1","system-ip":"10.0.0.1","uuid":"uuid-1","chasisNumber":"SDWAN-SERIAL-1","site-id":"100","personality":"vedge","status":"reachable"}
		]}`,
		"/dataservice/device/app-route/statistics": `{"data":[{"latency":12,"jitter":3,"loss":0.1,"local-color":"biz-internet","application":"openai-api","sla-state":"ok"}]}`,
		"/dataservice/device/interface/synced":     `{"data":[{"ifname":"ge0/0","oper-status":"up","admin-status":"up","rx-bytes":1024,"rx-errors":1,"color":"biz-internet","vpn-id":"0"}]}`,
		"/dataservice/alarms":                      `{"data":[]}`,
		"/dataservice/events":                      `{"data":[]}`,
		"/dataservice/auditlog":                    `{"data":[]}`,
	}, nil)
	defer server.Close()

	receiver := newTestSDWANReceiver(t, server.URL, func(cfg *Config) {
		cfg.SDWAN.Manager.Enabled = false
		cfg.SDWAN.ControlPlane.Enabled = false
		cfg.SDWAN.BFD.Enabled = false
		cfg.Metrics = map[string]MetricConfig{
			"sdwan.app_route.loss":  {Enabled: false},
			"system.network.errors": {Enabled: false},
		}
	})
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	filterMetricsByConfig(md, receiver.config)
	names := metricNames(md)
	assert.NotContains(t, names, "sdwan.app_route.loss")
	assert.NotContains(t, names, "system.network.errors")
	assert.Contains(t, names, "sdwan.app_route.latency")
	assert.Contains(t, names, "system.network.io")
}

func TestMetricFilterSupportsGlobPatternsWithExactOverride(t *testing.T) {
	server, _ := newSDWANFixtureServer(t, map[string]string{
		"/dataservice/device": `{"data":[
			{"host-name":"edge-1","system-ip":"10.0.0.1","uuid":"uuid-1","chasisNumber":"SDWAN-SERIAL-1","site-id":"100","personality":"vedge","status":"reachable"}
		]}`,
		"/dataservice/device/app-route/statistics": `{"data":[{"latency":12,"jitter":3,"loss":0.1,"local-color":"biz-internet","application":"openai-api","sla-state":"ok"}]}`,
		"/dataservice/device/interface/synced":     `{"data":[{"ifname":"ge0/0","oper-status":"up","admin-status":"up","rx-bytes":1024,"rx-errors":1,"color":"biz-internet","vpn-id":"0"}]}`,
		"/dataservice/alarms":                      `{"data":[]}`,
		"/dataservice/events":                      `{"data":[]}`,
		"/dataservice/auditlog":                    `{"data":[]}`,
	}, nil)
	defer server.Close()

	receiver := newTestSDWANReceiver(t, server.URL, func(cfg *Config) {
		cfg.SDWAN.Manager.Enabled = false
		cfg.SDWAN.ControlPlane.Enabled = false
		cfg.SDWAN.BFD.Enabled = false
		cfg.Metrics = map[string]MetricConfig{
			"sdwan.app_route.*":     {Enabled: false},
			"sdwan.app_route.loss":  {Enabled: true},
			"system.network.errors": {Enabled: false},
		}
	})
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	filterMetricsByConfig(md, receiver.config)
	names := metricNames(md)
	assert.NotContains(t, names, "sdwan.app_route.latency")
	assert.NotContains(t, names, "sdwan.app_route.jitter")
	assert.Contains(t, names, "sdwan.app_route.loss")
	assert.NotContains(t, names, "system.network.errors")
	assert.Contains(t, names, "system.network.io")
}

func TestSDWANLogsPreserveEventBodies(t *testing.T) {
	server, _ := newSDWANFixtureServer(t, map[string]string{
		"/dataservice/alarms":   `{"data":[{"id":"alarm-1","severity":"critical","status":"active","system-ip":"10.0.0.1","message":"BFD down"}]}`,
		"/dataservice/events":   `{"data":[{"eventId":"event-1","severity":"info","system-ip":"10.0.0.1"}]}`,
		"/dataservice/auditlog": `{"data":[{"entry_uuid":"audit-1","severity":"info","user":"admin","policyName":"app-route-ai"}]}`,
	}, nil)
	defer server.Close()

	receiver := newTestSDWANLogsReceiver(t, server.URL, nil)
	ld, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.Equal(t, 3, ld.LogRecordCount())
	assert.True(t, logRecordAttributeExists(ld, "event.domain", "sdwan"))
	assert.True(t, logRecordAttributeExists(ld, "sdwan.policy.name", "app-route-ai"))
}

func newTestSDWANReceiver(t *testing.T, endpoint string, mutate func(*Config)) *sdwanMetricsReceiver {
	t.Helper()
	cfg := createDefaultConfig().(*Config)
	cfg.Timeout = 10 * time.Second
	cfg.SDWAN = defaultSDWANConfig()
	cfg.SDWAN.Enabled = true
	cfg.SDWAN.Endpoint = endpoint
	cfg.SDWAN.Auth.Mode = "bearer"
	cfg.SDWAN.Auth.BearerToken = configopaque.String("token")
	if mutate != nil {
		mutate(cfg)
	}
	receiver, err := newSDWANMetricsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)
	return receiver
}

func newTestSDWANLogsReceiver(t *testing.T, endpoint string, mutate func(*Config)) *sdwanLogsReceiver {
	t.Helper()
	cfg := createDefaultConfig().(*Config)
	cfg.Timeout = 10 * time.Second
	cfg.SDWAN = defaultSDWANConfig()
	cfg.SDWAN.Enabled = true
	cfg.SDWAN.Endpoint = endpoint
	cfg.SDWAN.Auth.Mode = "bearer"
	cfg.SDWAN.Auth.BearerToken = configopaque.String("token")
	if mutate != nil {
		mutate(cfg)
	}
	receiver, err := newSDWANLogsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)
	return receiver
}

type sdwanCapturedRequest struct {
	path string
	body string
}

func newSDWANFixtureServer(t *testing.T, routes map[string]string, failures map[string]int) (*httptest.Server, *[]sdwanCapturedRequest) {
	t.Helper()
	var mu sync.Mutex
	requests := []sdwanCapturedRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer token", r.Header.Get("Authorization"))
		bodyBytes, _ := io.ReadAll(r.Body)
		mu.Lock()
		requests = append(requests, sdwanCapturedRequest{path: r.URL.Path, body: string(bodyBytes)})
		mu.Unlock()

		if status := failures[r.URL.Path]; status != 0 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`failed`))
			return
		}
		if body, ok := routes[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	return server, &requests
}

func logRecordAttributeExists(ld plog.Logs, key, value string) bool {
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		rl := ld.ResourceLogs().At(i)
		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			sl := rl.ScopeLogs().At(j)
			for k := 0; k < sl.LogRecords().Len(); k++ {
				attr, ok := sl.LogRecords().At(k).Attributes().Get(key)
				if ok && attr.AsString() == value {
					return true
				}
			}
		}
	}
	return false
}

func findSDWANMetricForHost(t *testing.T, md pmetric.Metrics, hostID, name string) pmetric.Metric {
	t.Helper()
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		resourceHostID, ok := rm.Resource().Attributes().Get("host.id")
		if !ok || resourceHostID.AsString() != hostID {
			continue
		}
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			metrics := rm.ScopeMetrics().At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				if metrics.At(k).Name() == name {
					return metrics.At(k)
				}
			}
		}
	}
	require.FailNowf(t, "metric not found", "missing %s for host %s", name, hostID)
	return pmetric.Metric{}
}

func sdwanGaugeDoubleValue(t *testing.T, md pmetric.Metrics, hostID, name, attrKey, attrValue string) float64 {
	t.Helper()
	metric := findSDWANMetricForHost(t, md, hostID, name)
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	dps := metric.Gauge().DataPoints()
	for i := 0; i < dps.Len(); i++ {
		dp := dps.At(i)
		if attrKey == "" || attrValueMatches(dp.Attributes(), attrKey, attrValue) {
			require.Equal(t, pmetric.NumberDataPointValueTypeDouble, dp.ValueType())
			return dp.DoubleValue()
		}
	}
	require.FailNowf(t, "datapoint not found", "missing %s datapoint with %s=%s", name, attrKey, attrValue)
	return 0
}

func sdwanGaugeIntValue(t *testing.T, md pmetric.Metrics, hostID, name, attrKey, attrValue string) int64 {
	t.Helper()
	metric := findSDWANMetricForHost(t, md, hostID, name)
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	dps := metric.Gauge().DataPoints()
	for i := 0; i < dps.Len(); i++ {
		dp := dps.At(i)
		if attrKey == "" || attrValueMatches(dp.Attributes(), attrKey, attrValue) {
			require.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
			return dp.IntValue()
		}
	}
	require.FailNowf(t, "datapoint not found", "missing %s datapoint with %s=%s", name, attrKey, attrValue)
	return 0
}

func assertSDWANCumulativeInt(t *testing.T, md pmetric.Metrics, hostID, name, attrKey, attrValue string, want int64) {
	t.Helper()
	metric := findSDWANMetricForHost(t, md, hostID, name)
	require.Equal(t, pmetric.MetricTypeSum, metric.Type())
	assert.True(t, metric.Sum().IsMonotonic())
	assert.Equal(t, pmetric.AggregationTemporalityCumulative, metric.Sum().AggregationTemporality())
	dps := metric.Sum().DataPoints()
	for i := 0; i < dps.Len(); i++ {
		dp := dps.At(i)
		if attrKey == "" || attrValueMatches(dp.Attributes(), attrKey, attrValue) {
			require.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
			assert.Equal(t, want, dp.IntValue())
			return
		}
	}
	require.FailNowf(t, "datapoint not found", "missing %s datapoint with %s=%s", name, attrKey, attrValue)
}

func attrValueMatches(attrs pcommon.Map, key, value string) bool {
	attr, ok := attrs.Get(key)
	return ok && attr.AsString() == value
}
