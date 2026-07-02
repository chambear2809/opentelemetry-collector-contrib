// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"encoding/base64"
	"io"
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
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/catalystcenter"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestCatalystCenterScrapeEmitsAssuranceMetrics(t *testing.T) {
	server, requests := newCatalystCenterFixtureServer(t, map[string]string{
		"/dna/intent/api/v1/network-device": `{"response":[
			{"id":"device-1","instanceUuid":"uuid-1","hostname":"edge-1","managementIpAddress":"10.0.0.1","serialNumber":"FOC1234","family":"Switches and Hubs","type":"Cisco Catalyst 9300","platformId":"C9300","role":"ACCESS","softwareVersion":"17.12.1","collectionStatus":"Managed","reachabilityStatus":"Reachable","interfaceCount":"2","uptimeSeconds":3600}
		],"version":"1.0"}`,
		"/dna/intent/api/v1/interface": `{"response":[
			{"id":"int-1","deviceId":"device-1","name":"GigabitEthernet1/0/1","portName":"GigabitEthernet1/0/1","status":"up","adminStatus":"up","speed":"1000000000","interfaceType":"Physical","macAddress":"00:11:22:33:44:55","vlanId":"10","lastIncomingPacketTime":1779727875000,"lastOutgoingPacketTime":1779727866000}
		],"version":"1.0"}`,
		"/dna/intent/api/v1/network-health":             `{"version":"1.0","latestHealthScore":95,"measuredBy":"global","monitoredDevices":1,"monitoredHealthyDevices":1,"totalDevices":1,"response":[{"entity":"Access","healthScore":95,"totalCount":1,"goodCount":1}]}`,
		"/dna/intent/api/v1/client-health":              `{"version":"1.0","response":[{"siteId":"global","scoreDetail":[{"scoreCategory":{"value":"Wired"},"scoreValue":90,"clientCount":12,"clientUniqueCount":10}]}]}`,
		"/dna/data/api/v1/siteHealthSummaries":          `{"response":[{"id":"site-1","siteName":"Global/Building 1","siteType":"building","networkDeviceGoodHealthPercentage":100,"networkDeviceGoodHealthCount":1,"networkDeviceCount":1,"clientGoodHealthPercentage":90,"clientGoodHealthCount":9,"clientCount":10,"wiredClientCount":6,"wirelessClientCount":4,"accessDeviceCount":1,"accessDeviceGoodHealthCount":1,"p1IssueCount":1,"issueCount":2}],"page":{"limit":500,"offset":1,"count":1},"version":"1.0"}`,
		"/dna/intent/api/v1/topology/physical-topology": `{"response":{"nodes":[{"id":"device-1","label":"edge-1","nodeType":"device","family":"Switches and Hubs","role":"ACCESS"}],"links":[{"id":"link-1","source":"device-1","target":"device-2","linkStatus":"up"}]},"version":"1.0"}`,
		"/dna/data/api/v1/assuranceIssues/query":        `{"response":[{"issueId":"issue-1","severity":"High","priority":"P1","status":"active","category":"Connectivity","entityType":"network_device","siteId":"site-1","siteName":"Global/Building 1"}],"page":{"limit":500,"offset":1,"count":1},"version":"1.0"}`,
		"/dna/intent/api/v1/device-detail":              `{"response":{"nwDeviceId":"device-1","nwDeviceName":"edge-1","serialNumber":"FOC1234","managementIpAddr":"10.0.0.1","nwDeviceFamily":"Switches and Hubs","nwDeviceType":"Cisco Catalyst 9300","platformId":"C9300","softwareVersion":"17.12.1","overallHealth":95,"cpu":30,"memory":45,"communicationState":"Reachable"}}`,
		"/dna/intent/api/v1/client-detail":              `{"detail":{"id":"client-1","hostMac":"AA:BB:CC:DD:EE:FF","hostName":"client-1","hostIpV4":"10.0.0.20","connectionStatus":"CONNECTED","hostType":"Wired","healthScore":[{"healthType":"OVERALL","reason":"healthy","score":88}],"issueCount":1,"txBytes":1024,"rxBytes":2048}}`,
	}, nil)
	defer server.Close()

	receiver := newTestCatalystCenterReceiver(t, server.URL, func(cfg *Config) {
		cfg.CatalystCenter.Targets.DeviceDetails = []CatalystCenterDeviceDetailTarget{{Identifier: "UUID", SearchBy: "device-1"}}
		cfg.CatalystCenter.Targets.ClientMACs = []string{"AA:BB:CC:DD:EE:FF"}
	})
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	names := metricNames(md)
	for _, name := range []string{
		"catalyst_center.api.request.duration",
		"catalyst_center.scrape.partial_success",
		"catalyst_center.scrape.last_success",
		"catalyst_center.inventory.device.count",
		"cisco.device.up",
		"catalyst_center.device.reachability.status",
		"system.network.interface.status",
		"cisco.interface.admin.status",
		"cisco.interface.speed",
		"catalyst_center.network.health.score",
		"catalyst_center.client.health.score",
		"catalyst_center.site.network_device.health.percentage",
		"catalyst_center.site.issue.count",
		"catalyst_center.site.client.count",
		"catalyst_center.site.network_device.count",
		"catalyst_center.topology.node.count",
		"catalyst_center.issue.active.count",
		"catalyst_center.device.detail.health.score",
		"catalyst_center.client.detail.health.score",
	} {
		assert.Contains(t, names, name)
	}
	assert.True(t, hasResourceHostID(md, "FOC1234"))
	assert.True(t, intMetricValueExists(md, "catalyst_center.scrape.partial_success", 0))
	assert.True(t, intMetricValueExists(md, "cisco.interface.speed", 1_000_000_000))
	assert.True(t, intMetricValueExists(md, "catalyst_center.site.issue.count", 2))
	assert.True(t, intMetricValueExists(md, "catalyst_center.site.client.count", 10))
	assert.True(t, intMetricValueExists(md, "catalyst_center.site.network_device.count", 1))
	assert.True(t, hasMetricDatapointAttribute(md, "catalyst_center.site.issue.count", "catalyst_center.issue.priority", "p1"))
	assert.False(t, hasMetricDatapointAttribute(md, "catalyst_center.site.issue.count", "user.name", "admin"))
	assert.True(t, catalystCenterRequestExists(*requests, "/dna/data/api/v1/siteHealthSummaries", "limit=20"), "site health must use Catalyst Center's 20 item page cap")
	assert.True(t, catalystCenterRequestExists(*requests, "/dna/intent/api/v1/device-detail", "identifier=uuid"), "device detail identifier should be canonicalized")
}

func TestCatalystCenterScrapeAppliesSharedDeviceSelection(t *testing.T) {
	server, _ := newCatalystCenterFixtureServer(t, map[string]string{
		"/dna/intent/api/v1/network-device": `{"response":[
			{"id":"device-1","instanceUuid":"uuid-1","hostname":"edge-1","managementIpAddress":"10.0.0.1","serialNumber":"FOC1234","reachabilityStatus":"Reachable","interfaceCount":"1"},
			{"id":"device-9","instanceUuid":"uuid-9","hostname":"edge-9","managementIpAddress":"10.0.0.9","serialNumber":"FOC9999","reachabilityStatus":"Reachable","interfaceCount":"1"}
		],"version":"1.0"}`,
		"/dna/intent/api/v1/interface": `{"response":[
			{"id":"int-1","deviceId":"device-1","serialNo":"FOC1234","name":"GigabitEthernet1/0/1","portName":"GigabitEthernet1/0/1","status":"up","adminStatus":"up","speed":"1000000000"},
			{"id":"int-9","deviceId":"device-9","serialNo":"FOC9999","name":"GigabitEthernet1/0/9","portName":"GigabitEthernet1/0/9","status":"up","adminStatus":"up","speed":"1000000000"}
		],"version":"1.0"}`,
		"/dna/intent/api/v1/network-health":             `{"response":[]}`,
		"/dna/intent/api/v1/client-health":              `{"response":[]}`,
		"/dna/data/api/v1/siteHealthSummaries":          `{"response":[],"page":{"limit":500,"offset":1,"count":0},"version":"1.0"}`,
		"/dna/intent/api/v1/topology/physical-topology": `{"response":{"nodes":[{"id":"device-1","label":"edge-1","nodeType":"device"},{"id":"device-9","label":"edge-9","nodeType":"device"}],"links":[{"id":"link-1","source":"device-1","target":"device-9","linkStatus":"up"}]},"version":"1.0"}`,
		"/dna/data/api/v1/assuranceIssues/query": `{"response":[
			{"issueId":"issue-1","severity":"High","priority":"P1","status":"active","category":"Connectivity","entityType":"network_device","entityId":"device-1"},
			{"issueId":"issue-9","severity":"High","priority":"P1","status":"active","category":"Connectivity","entityType":"network_device","entityId":"device-9"}
		],"page":{"limit":500,"offset":1,"count":2},"version":"1.0"}`,
	}, nil)
	defer server.Close()

	receiver := newTestCatalystCenterReceiver(t, server.URL, func(cfg *Config) {
		cfg.DeviceSelection.Include.Serials = []string{"FOC1234"}
		cfg.DeviceSelection.Exclude.Serials = []string{"FOC9999"}
	})
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, hasResourceHostID(md, "FOC1234"))
	assert.False(t, hasResourceHostID(md, "FOC9999"))
	assert.True(t, intMetricValueExists(md, "catalyst_center.issue.count", 1))
	assert.True(t, intMetricValueExists(md, "catalyst_center.topology.node.count", 1))
	assert.False(t, hasMetricDatapointAttribute(md, "system.network.interface.status", "catalyst_center.device.id", "device-9"))
}

func TestCatalystCenterScrapeRecordsPartialSuccess(t *testing.T) {
	server, _ := newCatalystCenterFixtureServer(t, map[string]string{
		"/dna/intent/api/v1/network-device": `{"response":[
			{"id":"device-1","hostname":"edge-1","serialNumber":"FOC1234","reachabilityStatus":"Reachable"}
		]}`,
		"/dna/intent/api/v1/interface":                  `{"response":[]}`,
		"/dna/intent/api/v1/network-health":             `{"response":[]}`,
		"/dna/intent/api/v1/client-health":              `{"response":[]}`,
		"/dna/intent/api/v1/topology/physical-topology": `{"response":{"nodes":[],"links":[]}}`,
		"/dna/data/api/v1/assuranceIssues/query":        `{"response":[],"page":{"limit":500,"offset":1,"count":0}}`,
	}, map[string]int{
		"/dna/data/api/v1/siteHealthSummaries": http.StatusInternalServerError,
	})
	defer server.Close()

	receiver := newTestCatalystCenterReceiver(t, server.URL, nil)
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, intMetricValueExists(md, "catalyst_center.scrape.partial_success", 1))
	assert.Contains(t, metricNames(md), "catalyst_center.api.request.errors")
	assert.True(t, hasResourceHostID(md, "FOC1234"))
}

func TestCatalystCenterDeviceUtilizationNormalizesPercentages(t *testing.T) {
	builder := newCatalystCenterMetricsBuilder(time.Now(), "test", nil)
	rb := builder.accountResource()
	for _, value := range []any{float64(42), float64(0.42), float64(-1), float64(101), "NaN", "Inf"} {
		recordObjectRatio(rb, catalystcenter.Object{"cpu": value}, "cpu", "system.cpu.utilization", "CPU utilization.", nil)
	}

	metric := requireMetricByName(t, builder.emit(), "system.cpu.utilization")
	require.Equal(t, 2, metric.Gauge().DataPoints().Len())
	assert.InDelta(t, 0.42, metric.Gauge().DataPoints().At(0).DoubleValue(), 1e-12)
	assert.InDelta(t, 0.42, metric.Gauge().DataPoints().At(1).DoubleValue(), 1e-12)
}

func newTestCatalystCenterReceiver(t *testing.T, endpoint string, mutate func(*Config)) *catalystCenterMetricsReceiver {
	t.Helper()
	cfg := createDefaultConfig().(*Config)
	cfg.Timeout = 10 * time.Second
	cfg.CatalystCenter = defaultCatalystCenterConfig()
	cfg.CatalystCenter.Enabled = true
	cfg.CatalystCenter.Endpoint = endpoint
	cfg.CatalystCenter.Auth.Username = "admin"
	cfg.CatalystCenter.Auth.Password = configopaque.String("password")
	if mutate != nil {
		mutate(cfg)
	}
	receiver, err := newCatalystCenterMetricsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)
	return receiver
}

type catalystCenterCapturedRequest struct {
	path     string
	rawQuery string
	body     string
}

func newCatalystCenterFixtureServer(t *testing.T, routes map[string]string, failures map[string]int) (*httptest.Server, *[]catalystCenterCapturedRequest) {
	t.Helper()
	var mu sync.Mutex
	requests := []catalystCenterCapturedRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dna/system/api/v1/auth/token" {
			assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:password")), r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`{"Token":"token-1"}`))
			return
		}
		assert.Equal(t, "token-1", r.Header.Get("X-Auth-Token"))
		bodyBytes, _ := io.ReadAll(r.Body)
		mu.Lock()
		requests = append(requests, catalystCenterCapturedRequest{path: r.URL.Path, rawQuery: r.URL.RawQuery, body: string(bodyBytes)})
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
		case strings.HasSuffix(r.URL.Path, "/count"):
			_, _ = w.Write([]byte(`{"response":0,"version":"1.0"}`))
		default:
			_, _ = w.Write([]byte(`{"response":[],"version":"1.0"}`))
		}
	}))
	return server, &requests
}

func catalystCenterRequestExists(requests []catalystCenterCapturedRequest, path, rawQueryPart string) bool {
	for _, request := range requests {
		if request.path == path && strings.Contains(request.rawQuery, rawQueryPart) {
			return true
		}
	}
	return false
}
