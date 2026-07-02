// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
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

	merakimodel "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/meraki"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestMerakiScrapeEmitsResourcesAndMetrics(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/123456/devices": `[
			{"name":"Switch 1","networkId":"N_1","serial":"Q234-ABCD-0001","model":"MS120-8","mac":"00:11:22:33:44:55","lanIp":"10.0.0.10","firmware":"switch-17-1","productType":"switch"},
			{"name":"MX 1","networkId":"N_2","serial":"Q234-ABCD-0002","model":"MX68","mac":"00:11:22:33:44:66","lanIp":"10.0.0.1","firmware":"appliance-18-1","productType":"appliance"}
		]`,
		"/api/v1/organizations/123456/devices/statuses": `[
			{"name":"Switch 1","serial":"Q234-ABCD-0001","networkId":"N_1","status":"online","lanIp":"10.0.0.10","productType":"switch","model":"MS120-8"},
			{"name":"MX 1","serial":"Q234-ABCD-0002","networkId":"N_2","status":"alerting","lanIp":"10.0.0.1","productType":"appliance","model":"MX68"}
		]`,
		"/api/v1/organizations/123456/devices/system/memory/usage/history/byInterval": `{"items":[
			{"serial":"Q234-ABCD-0001","model":"MS120-8","name":"Switch 1","mac":"00:11:22:33:44:55","network":{"id":"N_1"},"intervals":[{"memory":{"used":{"median":100,"percentages":{"median":50}},"free":{"median":100}}}]}
		]}`,
		"/api/v1/organizations/123456/switch/ports/statuses/bySwitch": `{"items":[
			{"name":"Switch 1","serial":"Q234-ABCD-0001","mac":"00:11:22:33:44:55","network":{"id":"N_1"},"model":"MS120-8","ports":[{"portId":"1","enabled":true,"status":"Connected","speed":"1 Gbps","errors":["CRC"],"warnings":["duplex"],"poe":{"isAllocated":true}}]}
		]}`,
		"/api/v1/organizations/123456/switch/ports/usage/history/byDevice/byInterval": `{"items":[
			{"name":"Switch 1","serial":"Q234-ABCD-0001","mac":"00:11:22:33:44:55","network":{"id":"N_1"},"model":"MS120-8","ports":[{"portId":"1","intervals":[{"data":{"usage":{"upstream":200,"downstream":100}},"bandwidth":{"usage":{"upstream":2,"downstream":1}}}]}]}
		]}`,
		"/api/v1/organizations/123456/uplinks/statuses": `[
			{"networkId":"N_2","serial":"Q234-ABCD-0002","model":"MX68","uplinks":[{"interface":"wan1","status":"active","ip":"10.0.0.1","signalStat":{"rsrp":"-90","rsrq":"-10"}}]}
		]`,
		"/api/v1/organizations/123456/devices/uplinksLossAndLatency": `[
			{"networkId":"N_2","serial":"Q234-ABCD-0002","uplink":"wan1","ip":"10.0.0.1","timeSeries":[{"lossPercent":0.1,"latencyMs":12.5}]}
		]`,
		"/api/v1/devices/Q234-ABCD-0002/appliance/performance": `{"perfScore": 95}`,
	}
	server, _ := newMerakiFixtureServer(t, routes, nil)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth: MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Organizations: []MerakiOrganizationConfig{{
			OrganizationID: "123456",
		}},
	})

	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	names := metricNames(md)
	assert.Contains(t, names, "cisco.device.up")
	assert.Contains(t, names, "system.memory.utilization")
	assert.Contains(t, names, "system.network.interface.status")
	assert.Contains(t, names, "cisco.interface.io.rate")
	assert.Contains(t, names, "meraki.uplink.status")
	assert.Contains(t, names, "meraki.switch.port.alert.active")
	assert.Contains(t, names, "meraki.appliance.performance.score")
	assert.Contains(t, names, "meraki.api.request.duration")
	assert.Contains(t, names, "meraki.controller.up")
	assert.Contains(t, names, "meraki.scrape.last_success")
	assert.True(t, hasResourceHostID(md, "Q234-ABCD-0001"))
	assert.True(t, hasResourceHostID(md, "Q234-ABCD-0002"))
	assert.True(t, intMetricValueExists(md, "cisco.scrape.partial_success", 0))
	assert.Equal(t, pmetric.MetricTypeGauge, requireMetricByName(t, md, "meraki.switch.port.alert.active").Type())
	assert.Equal(t, 2, metricDataPointCount(md, "meraki.switch.port.alert.active"))
}

func TestMerakiScrapeSerialScopedFiltersReturnedDevices(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/123456/devices": `[
			{"name":"Switch 1","networkId":"N_1","serial":"Q234-ABCD-0001","model":"MS120-8","productType":"switch"}
		]`,
		"/api/v1/organizations/123456/devices/statuses": `[
			{"name":"Switch 1","serial":"Q234-ABCD-0001","networkId":"N_1","status":"online","productType":"switch","model":"MS120-8"},
			{"name":"Switch 2","serial":"Q234-ABCD-0009","networkId":"N_9","status":"online","productType":"switch","model":"MS120-8"}
		]`,
	}
	server, requests := newMerakiFixtureServer(t, routes, nil)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth: MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Devices: []MerakiDeviceConfig{{
			OrganizationID: "123456",
			Serial:         "Q234-ABCD-0001",
		}},
	})

	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.True(t, hasResourceHostID(md, "Q234-ABCD-0001"))
	assert.False(t, hasResourceHostID(md, "Q234-ABCD-0009"))
	assert.True(t, sawQueryValue(requests, "/api/v1/organizations/123456/devices", "serials[]", "Q234-ABCD-0001"))
	assert.True(t, sawQueryValue(requests, "/api/v1/organizations/123456/devices/statuses", "serials[]", "Q234-ABCD-0001"))
}

func TestMerakiScrapeAppliesSharedDeviceSelection(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/123456/devices": `[
			{"name":"MX 1","networkId":"N_1","serial":"Q234-ABCD-0001","model":"MX68","productType":"appliance"},
			{"name":"MX 9","networkId":"N_9","serial":"Q234-ABCD-0009","model":"MX68","productType":"appliance"}
		]`,
		"/api/v1/organizations/123456/devices/statuses": `[
			{"name":"MX 1","serial":"Q234-ABCD-0001","networkId":"N_1","status":"online","productType":"appliance","model":"MX68"},
			{"name":"MX 9","serial":"Q234-ABCD-0009","networkId":"N_9","status":"online","productType":"appliance","model":"MX68"}
		]`,
		"/api/v1/organizations/123456/appliance/vpn/statuses": `[
			{"networkId":"N_1","networkName":"Branch 1","deviceSerial":"Q234-ABCD-0001","merakiVpnPeers":[{"networkId":"N_hub","networkName":"Hub","reachability":"reachable"}]},
			{"networkId":"N_9","networkName":"Branch 9","deviceSerial":"Q234-ABCD-0009","merakiVpnPeers":[{"networkId":"N_hub","networkName":"Hub","reachability":"reachable"}]}
		]`,
		"/api/v1/organizations/123456/appliance/vpn/stats": `[
			{"networkId":"N_1","networkName":"Branch 1","merakiVpnPeers":[{"networkId":"N_hub","networkName":"Hub","usageSummary":{"receivedInKilobytes":10,"sentInKilobytes":20}}]},
			{"networkId":"N_9","networkName":"Branch 9","merakiVpnPeers":[{"networkId":"N_hub","networkName":"Hub","usageSummary":{"receivedInKilobytes":90,"sentInKilobytes":100}}]}
		]`,
	}
	server, _ := newMerakiFixtureServer(t, routes, nil)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth:          MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Organizations: []MerakiOrganizationConfig{{OrganizationID: "123456"}},
	})
	receiver.config.DeviceSelection.Include.Serials = []string{"Q234-ABCD-0001"}
	receiver.config.DeviceSelection.Exclude.Serials = []string{"Q234-ABCD-0009"}

	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.True(t, hasResourceHostID(md, "Q234-ABCD-0001"))
	assert.False(t, hasResourceHostID(md, "Q234-ABCD-0009"))
	assert.False(t, hasResourceHostID(md, "meraki:network:N_9"), "VPN network-level metrics must not leak excluded networks")
	assert.True(t, intMetricValueExists(md, "meraki.vpn.peer.usage", 10))
	assert.False(t, intMetricValueExists(md, "meraki.vpn.peer.usage", 90))
}

func TestMerakiScrapeRecordsPartialSuccessOnEndpointFailure(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/123456/devices":          `[{"name":"Switch 1","networkId":"N_1","serial":"Q234-ABCD-0001","model":"MS120-8","productType":"switch"}]`,
		"/api/v1/organizations/123456/devices/statuses": `[{"name":"Switch 1","serial":"Q234-ABCD-0001","networkId":"N_1","status":"online","productType":"switch","model":"MS120-8"}]`,
	}
	failures := map[string]int{
		"/api/v1/organizations/123456/devices/system/memory/usage/history/byInterval": http.StatusInternalServerError,
	}
	server, _ := newMerakiFixtureServer(t, routes, failures)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth:          MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Organizations: []MerakiOrganizationConfig{{OrganizationID: "123456"}},
	})

	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.True(t, intMetricValueExists(md, "cisco.scrape.partial_success", 1))
	assert.True(t, intMetricValueExists(md, "meraki.controller.up", 1), "partial collection with successful API calls remains reachable")
	assert.NotContains(t, metricNames(md), "meraki.scrape.last_success", "an initial partial scrape must not claim a full success")
	assert.Contains(t, metricNames(md), "meraki.api.request.errors")
}

func TestMerakiScrapeRetainsEarlierPagesWhenLaterPagesFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer meraki-key", r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/api/v1/organizations/123456/devices":
			_, _ = w.Write([]byte(`[{"name":"Switch 1","networkId":"N_1","serial":"Q234-ABCD-0001","model":"MS120-8","productType":"switch"}]`))
		case "/api/v1/organizations/123456/devices/statuses":
			if r.URL.Query().Get("cursor") == "next" {
				http.Error(w, "page failed", http.StatusBadRequest)
				return
			}
			w.Header().Set("Link", `</api/v1/organizations/123456/devices/statuses?cursor=next>; rel="next"`)
			_, _ = w.Write([]byte(`[{"name":"Switch 1","serial":"Q234-ABCD-0001","networkId":"N_1","status":"online","productType":"switch","model":"MS120-8"}]`))
		case "/api/v1/organizations/123456/devices/system/memory/usage/history/byInterval":
			if r.URL.Query().Get("cursor") == "next" {
				http.Error(w, "page failed", http.StatusBadRequest)
				return
			}
			w.Header().Set("Link", `</api/v1/organizations/123456/devices/system/memory/usage/history/byInterval?cursor=next>; rel="next"`)
			_, _ = w.Write([]byte(`{"items":[{"serial":"Q234-ABCD-0001","model":"MS120-8","name":"Switch 1","network":{"id":"N_1"},"intervals":[{"memory":{"used":{"percentages":{"median":50}}}}]}]}`))
		default:
			switch {
			case strings.Contains(r.URL.Path, "/switch/ports/statuses/bySwitch"),
				strings.Contains(r.URL.Path, "/switch/ports/usage/history/byDevice/byInterval"),
				strings.Contains(r.URL.Path, "/wireless/clients/overview/byDevice"),
				strings.Contains(r.URL.Path, "/wireless/ssids/statuses/byDevice"),
				strings.Contains(r.URL.Path, "/switch/ports/topology/discovery/byDevice"),
				strings.Contains(r.URL.Path, "/appliance/devices/ports/transceivers/readings/history/byDevice"):
				_, _ = w.Write([]byte(`{"items":[]}`))
			default:
				_, _ = w.Write([]byte(`[]`))
			}
		}
	}))
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth:          MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Organizations: []MerakiOrganizationConfig{{OrganizationID: "123456"}},
	})
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, hasResourceHostID(md, "Q234-ABCD-0001"))
	assert.Contains(t, metricNames(md), "cisco.device.up")
	assert.Contains(t, metricNames(md), "system.memory.utilization")
	assert.True(t, intMetricValueExists(md, "cisco.scrape.partial_success", 1))
}

func TestMerakiScrapeFinalizesHealthMetricsOnTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		<-req.Context().Done()
	}))
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth:          MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Organizations: []MerakiOrganizationConfig{{OrganizationID: "123456"}},
	})
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	md, err := receiver.scrape(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	assert.Equal(t, int64(1), resourceMetricIntValue(t, md, "meraki:org:123456", "cisco.scrape.partial_success"))
	assert.Equal(t, int64(0), resourceMetricIntValue(t, md, "meraki:org:123456", "meraki.controller.up"))
	assert.True(t, resourceHasMetric(md, "meraki:org:123456", "meraki.api.request.errors"))
	assert.False(t, resourceHasMetric(md, "meraki:org:123456", "meraki.scrape.last_success"))
}

func TestNormalizeMerakiTargetsMergesOneOrganization(t *testing.T) {
	targets := normalizeMerakiTargets(MerakiConfig{
		Organizations: []MerakiOrganizationConfig{{OrganizationID: "123", NetworkIDs: []string{"N_1"}, Serials: []string{"A"}}},
		Devices:       []MerakiDeviceConfig{{OrganizationID: "123", Serial: "B"}, {OrganizationID: "123", Serial: "A"}},
	})

	require.Len(t, targets, 1)
	assert.Equal(t, "123", targets[0].OrganizationID)
	assert.Equal(t, []string{"A", "B"}, targets[0].Serials)
	assert.Equal(t, []string{"N_1"}, targets[0].NetworkIDs)
}

func TestMerakiScrapeTracksPartialSuccessPerOrganization(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/good/devices":          `[]`,
		"/api/v1/organizations/good/devices/statuses": `[]`,
		"/api/v1/organizations/bad/devices":           `[]`,
		"/api/v1/organizations/bad/devices/statuses":  `[]`,
	}
	failures := map[string]int{
		"/api/v1/organizations/bad/devices/system/memory/usage/history/byInterval": http.StatusInternalServerError,
	}
	server, _ := newMerakiFixtureServer(t, routes, failures)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth: MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Organizations: []MerakiOrganizationConfig{
			{OrganizationID: "good"},
			{OrganizationID: "bad"},
		},
	})
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.Equal(t, int64(0), resourceMetricIntValue(t, md, "meraki:org:good", "cisco.scrape.partial_success"))
	assert.Equal(t, int64(1), resourceMetricIntValue(t, md, "meraki:org:bad", "cisco.scrape.partial_success"))
	assert.True(t, resourceHasMetric(md, "meraki:org:good", "meraki.scrape.last_success"))
	assert.False(t, resourceHasMetric(md, "meraki:org:bad", "meraki.scrape.last_success"))
}

func TestRecordWirelessPacketLossUsesWindowGauges(t *testing.T) {
	builder := newMerakiMetricsBuilder(time.Unix(200, 0), newCounterStoreAt(time.Unix(100, 0))).orgResource("org-a")
	recordWirelessPacketLoss(builder, "receive", merakimodel.PacketLossDirection{
		Total:          10,
		Lost:           2,
		LossPercentage: 20,
	})

	packetCount := builder.metrics["meraki.wireless.packet.count"]
	packetLoss := builder.metrics["meraki.wireless.packet.loss"]
	require.Equal(t, pmetric.MetricTypeGauge, packetCount.Type())
	require.Equal(t, pmetric.MetricTypeGauge, packetLoss.Type())
	assert.Equal(t, int64(10), packetCount.Gauge().DataPoints().At(0).IntValue())
	assert.Equal(t, int64(2), packetLoss.Gauge().DataPoints().At(0).IntValue())
}

func TestRecordTransceiverValueKeepsOneMetricDescriptorUnit(t *testing.T) {
	rb := newMerakiMetricsBuilder(time.Unix(200, 0), nil).orgResource("org-a")
	recordTransceiverValue(rb, map[string]string{"network.interface.name": "1"}, "temperature", "Cel", merakimodel.SummaryValue{Median: 42})
	recordTransceiverValue(rb, map[string]string{"network.interface.name": "2"}, "rx_power", "dBm", merakimodel.SummaryValue{Median: -7})

	metric := rb.metrics["cisco.transceiver.sensor"]
	assert.Equal(t, "1", metric.Unit())
	require.Equal(t, 2, metric.Gauge().DataPoints().Len())
	assert.Equal(t, "Cel", attrValue(t, metric.Gauge().DataPoints().At(0).Attributes(), "cisco.transceiver.sensor.unit"))
	assert.Equal(t, "dBm", attrValue(t, metric.Gauge().DataPoints().At(1).Attributes(), "cisco.transceiver.sensor.unit"))
}

func newTestMerakiReceiver(t *testing.T, baseURL string, merakiCfg MerakiConfig) *merakiMetricsReceiver {
	t.Helper()
	cfg := createDefaultConfig().(*Config)
	cfg.Timeout = 5 * time.Second
	cfg.Meraki = merakiCfg
	cfg.Meraki.BaseURL = baseURL + "/api/v1"
	receiver, err := newMerakiMetricsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)
	return receiver
}

type capturedRequest struct {
	path  string
	query string
}

func newMerakiFixtureServer(t *testing.T, routes map[string]string, failures map[string]int) (*httptest.Server, *[]capturedRequest) {
	t.Helper()
	var mu sync.Mutex
	requests := []capturedRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer meraki-key", r.Header.Get("Authorization"))
		mu.Lock()
		requests = append(requests, capturedRequest{path: r.URL.Path, query: r.URL.RawQuery})
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
		switch {
		case strings.Contains(r.URL.Path, "/devices/system/memory/"),
			strings.Contains(r.URL.Path, "/switch/ports/statuses/bySwitch"),
			strings.Contains(r.URL.Path, "/switch/ports/usage/history/byDevice/byInterval"),
			strings.Contains(r.URL.Path, "/wireless/clients/overview/byDevice"),
			strings.Contains(r.URL.Path, "/wireless/ssids/statuses/byDevice"),
			strings.Contains(r.URL.Path, "/switch/ports/topology/discovery/byDevice"),
			strings.Contains(r.URL.Path, "/appliance/devices/ports/transceivers/readings/history/byDevice"):
			_, _ = w.Write([]byte(`{"items":[]}`))
			return
		case strings.Contains(r.URL.Path, "/appliance/performance"):
			_, _ = w.Write([]byte(`{"perfScore":0}`))
			return
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	return server, &requests
}

func sawQueryValue(requests *[]capturedRequest, path, key, value string) bool {
	for _, req := range *requests {
		if req.path == path {
			values, err := url.ParseQuery(req.query)
			if err == nil && values.Get(key) == value {
				return true
			}
		}
	}
	return false
}

func metricNames(md pmetric.Metrics) map[string]int {
	names := map[string]int{}
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			for k := 0; k < sm.Metrics().Len(); k++ {
				names[sm.Metrics().At(k).Name()]++
			}
		}
	}
	return names
}

func hasResourceHostID(md pmetric.Metrics, hostID string) bool {
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		value, ok := md.ResourceMetrics().At(i).Resource().Attributes().Get("host.id")
		if ok && value.Str() == hostID {
			return true
		}
	}
	return false
}

func intMetricValueExists(md pmetric.Metrics, name string, value int64) bool {
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			for k := 0; k < sm.Metrics().Len(); k++ {
				metric := sm.Metrics().At(k)
				if metric.Name() != name {
					continue
				}
				points := metric.Gauge().DataPoints()
				for l := 0; l < points.Len(); l++ {
					if points.At(l).IntValue() == value {
						return true
					}
				}
			}
		}
	}
	return false
}

func hasMetricDatapointAttribute(md pmetric.Metrics, metricName, attrName, attrValue string) bool {
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			for k := 0; k < sm.Metrics().Len(); k++ {
				metric := sm.Metrics().At(k)
				if metric.Name() != metricName {
					continue
				}
				points := metric.Gauge().DataPoints()
				for l := 0; l < points.Len(); l++ {
					attr, ok := points.At(l).Attributes().Get(attrName)
					if ok && attr.Str() == attrValue {
						return true
					}
				}
			}
		}
	}
	return false
}

func metricDataPointCount(md pmetric.Metrics, metricName string) int {
	count := 0
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			for k := 0; k < sm.Metrics().Len(); k++ {
				metric := sm.Metrics().At(k)
				if metric.Name() != metricName {
					continue
				}
				switch metric.Type() {
				case pmetric.MetricTypeGauge:
					count += metric.Gauge().DataPoints().Len()
				case pmetric.MetricTypeSum:
					count += metric.Sum().DataPoints().Len()
				}
			}
		}
	}
	return count
}

func resourceMetricIntValue(t *testing.T, md pmetric.Metrics, hostID, metricName string) int64 {
	t.Helper()
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		if value, ok := rm.Resource().Attributes().Get("host.id"); !ok || value.AsString() != hostID {
			continue
		}
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			metrics := rm.ScopeMetrics().At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				metric := metrics.At(k)
				if metric.Name() == metricName && metric.Type() == pmetric.MetricTypeGauge && metric.Gauge().DataPoints().Len() > 0 {
					return metric.Gauge().DataPoints().At(0).IntValue()
				}
			}
		}
	}
	require.FailNowf(t, "metric not found", "%s for %s", metricName, hostID)
	return 0
}

func resourceHasMetric(md pmetric.Metrics, hostID, metricName string) bool {
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		if value, ok := rm.Resource().Attributes().Get("host.id"); !ok || value.AsString() != hostID {
			continue
		}
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			metrics := rm.ScopeMetrics().At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				if metrics.At(k).Name() == metricName {
					return true
				}
			}
		}
	}
	return false
}
