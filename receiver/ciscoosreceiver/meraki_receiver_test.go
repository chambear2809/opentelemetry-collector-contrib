// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"math"
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
			{"name":"Switch 1","serial":"Q234-ABCD-0001","mac":"00:11:22:33:44:55","network":{"id":"N_1"},"model":"MS120-8","ports":[{"portId":"1","intervals":[
				{"startTs":"2026-01-01T00:05:00Z","endTs":"2026-01-01T00:10:00Z","data":{"usage":{"upstream":400,"downstream":300}},"bandwidth":{"usage":{"upstream":4,"downstream":3}}},
				{"startTs":"2026-01-01T00:00:00Z","endTs":"2026-01-01T00:05:00Z","data":{"usage":{"upstream":200,"downstream":100}},"bandwidth":{"usage":{"upstream":2,"downstream":1}}}
			]}]}
		]}`,
		"/api/v1/organizations/123456/uplinks/statuses": `[
			{"networkId":"N_2","serial":"Q234-ABCD-0002","model":"MX68","uplinks":[{"interface":"wan1","status":"active","ip":"10.0.0.1","signalStat":{"rsrp":"-90","rsrq":"-10"}}]}
		]`,
		"/api/v1/organizations/123456/devices/uplinksLossAndLatency": `[
			{"networkId":"N_2","serial":"Q234-ABCD-0002","uplink":"wan1","ip":"10.0.0.1","timeSeries":[
				{"ts":"2026-01-01T00:10:00Z","lossPercent":0.2,"latencyMs":20},
				{"ts":"2026-01-01T00:05:00Z","lossPercent":0.1,"latencyMs":12.5}
			]}
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
	assert.True(t, intMetricValueExists(md, "cisco.interface.io.rate", 3000), "expected the interval with the latest endTs")
	assert.False(t, intMetricValueExists(md, "cisco.interface.io.rate", 1000), "older switch interval must not be emitted")
	ioRate := requireMetricByName(t, md, "cisco.interface.io.rate")
	foundLatestReceive := false
	for i := 0; i < ioRate.Gauge().DataPoints().Len(); i++ {
		point := ioRate.Gauge().DataPoints().At(i)
		if point.IntValue() == 3000 {
			foundLatestReceive = true
			assert.Equal(t, time.Date(2026, 1, 1, 0, 10, 0, 0, time.UTC), point.Timestamp().AsTime())
		}
	}
	assert.True(t, foundLatestReceive)
	assert.Equal(t, 20.0, requireGaugeDoubleValueWithAttrs(t, md, "meraki.uplink.latency", map[string]string{"meraki.uplink.interface": "wan1"}))
}

func TestMerakiScrapeSerialScopedFiltersReturnedDevices(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/123456/devices": `[
			{"name":"Switch 1","networkId":"N_1","serial":"Q234-ABCD-0001","model":"MS120-8","productType":"switch"},
			{"name":"Switch 2","networkId":"N_9","serial":"Q234-ABCD-0009","model":"MS120-8","productType":"switch"}
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

func TestMerakiInventoryIntersectionCannotReappearDownstream(t *testing.T) {
	routes := map[string]string{
		// Simulate a Dashboard response that ignores the requested product and
		// network filters. The receiver must enforce the intersection locally.
		"/api/v1/organizations/123456/devices": `[
			{"name":"Other MX","networkId":"N_9","serial":"MX-OTHER","model":"MX68","productType":"appliance","tags":["other"]}
		]`,
		"/api/v1/organizations/123456/devices/statuses": `[
			{"name":"Other MX","networkId":"N_9","serial":"MX-OTHER","model":"MX68","productType":"appliance","status":"online"}
		]`,
	}
	server, requests := newMerakiFixtureServer(t, routes, nil)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth: MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Organizations: []MerakiOrganizationConfig{{
			OrganizationID: "123456",
			NetworkIDs:     []string{"N_1"},
			Serials:        []string{"MX-OTHER"},
			ProductTypes:   []string{"switch"},
			Tags:           []string{"selected"},
		}},
	})

	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.False(t, hasResourceHostID(md, "MX-OTHER"))
	assert.Zero(t, requestCount(requests, "/api/v1/organizations/123456/devices/statuses"), "an empty authoritative inventory intersection should stop downstream collection")
	assert.True(t, intMetricValueExists(md, "cisco.scrape.partial_success", 0))
}

func TestMerakiInventoryFailureFailsClosedForDynamicScope(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/123456/devices/statuses": `[
			{"name":"Excluded","networkId":"N_9","serial":"MX-OTHER","model":"MX68","productType":"appliance","status":"online"}
		]`,
	}
	failures := map[string]int{
		"/api/v1/organizations/123456/devices": http.StatusInternalServerError,
	}
	server, requests := newMerakiFixtureServer(t, routes, failures)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth: MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Organizations: []MerakiOrganizationConfig{{
			OrganizationID: "123456",
			ProductTypes:   []string{"switch"},
		}},
	})

	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.False(t, hasResourceHostID(md, "MX-OTHER"))
	assert.Zero(t, requestCount(requests, "/api/v1/organizations/123456/devices/statuses"))
	assert.True(t, intMetricValueExists(md, "cisco.scrape.partial_success", 1))
}

func TestMerakiInventoryFailureRetainsExactSerialScope(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/123456/devices/statuses": `[
			{"name":"Selected","networkId":"N_1","serial":"MX-SELECTED","model":"MX68","productType":"appliance","status":"online"}
		]`,
	}
	failures := map[string]int{
		"/api/v1/organizations/123456/devices": http.StatusInternalServerError,
	}
	server, requests := newMerakiFixtureServer(t, routes, failures)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth:    MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Devices: []MerakiDeviceConfig{{OrganizationID: "123456", Serial: "MX-SELECTED"}},
	})

	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.True(t, hasResourceHostID(md, "MX-SELECTED"))
	assert.Equal(t, 1, requestCount(requests, "/api/v1/organizations/123456/devices/statuses"))
	assert.True(t, intMetricValueExists(md, "cisco.scrape.partial_success", 1))
}

func TestMerakiInventoryFailureRetainsSerialOnlyUnionArm(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/123456/devices/statuses": `[
			{"name":"Selected","networkId":"N_1","serial":"MX-SAFE","model":"MX68","productType":"appliance","status":"online"},
			{"name":"Unresolved","networkId":"N_2","serial":"MX-TAGGED","model":"MX68","productType":"appliance","status":"online","tags":["prod"]}
		]`,
	}
	failures := map[string]int{
		"/api/v1/organizations/123456/devices": http.StatusInternalServerError,
	}
	server, _ := newMerakiFixtureServer(t, routes, failures)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth: MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Organizations: []MerakiOrganizationConfig{
			{OrganizationID: "123456", Serials: []string{"MX-SAFE"}},
			{OrganizationID: "123456", Tags: []string{"prod"}},
		},
	})

	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.True(t, hasResourceHostID(md, "MX-SAFE"))
	assert.False(t, hasResourceHostID(md, "MX-TAGGED"))
	assert.True(t, intMetricValueExists(md, "cisco.scrape.partial_success", 1))
}

func TestMerakiInventoryFailureDoesNotBypassSharedSelector(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/123456/devices/statuses": `[
			{"name":"Excluded","networkId":"N_1","serial":"MX-SELECTED","model":"MX68","productType":"appliance","status":"online"}
		]`,
	}
	failures := map[string]int{
		"/api/v1/organizations/123456/devices": http.StatusInternalServerError,
	}
	server, requests := newMerakiFixtureServer(t, routes, failures)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth:    MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Devices: []MerakiDeviceConfig{{OrganizationID: "123456", Serial: "MX-SELECTED"}},
	})
	receiver.config.DeviceSelection.Exclude.HostNames = []string{"Excluded"}

	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.False(t, hasResourceHostID(md, "MX-SELECTED"))
	assert.Zero(t, requestCount(requests, "/api/v1/organizations/123456/devices/statuses"), "inventory-backed selection must fail closed")
	assert.True(t, intMetricValueExists(md, "cisco.scrape.partial_success", 1))
}

func TestMerakiQueryPageSizesMatchEndpointLimits(t *testing.T) {
	target := merakiTarget{
		OrganizationID: "123456",
		NetworkIDs:     []string{"N_1"},
		Serials:        []string{"Q234-ABCD-0001"},
		ProductTypes:   []string{"switch"},
		Tags:           []string{"lab"},
	}

	assert.Equal(t, "5000", target.deviceInventoryQuery().Get("perPage"))
	assert.Equal(t, "1000", target.deviceStatusQuery().Get("perPage"))
	assert.Equal(t, "20", target.memoryQuery().Get("perPage"))
	assert.Equal(t, "300", target.memoryQuery().Get("timespan"))
	assert.Equal(t, "300", target.memoryQuery().Get("interval"))
	assert.Empty(t, target.memoryQuery()["tags[]"], "memory endpoint does not accept tag filters")
	assert.Empty(t, target.memoryQuery().Get("tagsFilterType"))
	assert.Equal(t, "20", target.switchStatusQuery().Get("perPage"))
	assert.Equal(t, "50", target.switchUsageQuery().Get("perPage"))
	assert.Equal(t, "1200", target.switchUsageQuery().Get("timespan"))
	assert.Equal(t, "300", target.switchUsageQuery().Get("interval"))
	assert.Equal(t, "1000", target.uplinkStatusQuery().Get("perPage"))
	assert.Equal(t, "1000", target.wirelessClientsQuery().Get("perPage"))
	assert.Equal(t, "300", target.wirelessChannelQuery().Get("interval"))
	assert.Equal(t, "1000", target.wirelessChannelQuery().Get("perPage"))
	assert.Equal(t, "1000", target.wirelessPacketLossQuery().Get("perPage"))
	assert.Equal(t, "500", target.wirelessSSIDQuery().Get("perPage"))
	assert.Equal(t, "300", target.vpnStatusQuery().Get("perPage"))
	assert.Equal(t, "300", target.vpnStatsQuery().Get("perPage"))
	assert.Equal(t, "1000", target.powerModulesQuery().Get("perPage"))
	assert.Equal(t, "20", target.topologyQuery().Get("perPage"))
	assert.Equal(t, "10", target.applianceTransceiverQuery().Get("perPage"))
	assert.Equal(t, "100", target.switchTransceiverQuery().Get("perPage"))
	assert.Equal(t, "1200", target.applianceTransceiverQuery().Get("timespan"))
	assert.Equal(t, "300", target.switchTransceiverQuery().Get("interval"))
}

func TestMerakiMemoryUtilizationUsesNewestSnapshot(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/123456/devices": `[
			{"name":"Switch 1","networkId":"N_1","serial":"Q234-ABCD-0001","model":"MS120-8","productType":"switch"}
		]`,
		"/api/v1/organizations/123456/devices/system/memory/usage/history/byInterval": `{"items":[
			{"serial":"Q234-ABCD-0001","model":"MS120-8","name":"Switch 1","network":{"id":"N_1"},"intervals":[
				{"startTs":"2026-01-01T00:00:00Z","endTs":"2026-01-01T00:05:00Z","memory":{"used":{"percentages":{"median":25}}}},
				{"startTs":"2026-01-01T00:05:00Z","endTs":"2026-01-01T00:10:00Z","memory":{"used":{"percentages":{"median":75}}}}
			]}
		]}`,
	}
	server, _ := newMerakiFixtureServer(t, routes, nil)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth:          MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Organizations: []MerakiOrganizationConfig{{OrganizationID: "123456"}},
	})
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	metric := requireMetricByName(t, md, "system.memory.utilization")
	require.Equal(t, 1, metric.Gauge().DataPoints().Len())
	point := metric.Gauge().DataPoints().At(0)
	assert.InDelta(t, 0.75, point.DoubleValue(), 1e-12)
	assert.Equal(t, time.Date(2026, 1, 1, 0, 10, 0, 0, time.UTC), point.Timestamp().AsTime())
}

func TestMerakiMemoryUtilizationRejectsInvalidRatios(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value float64
	}{
		{name: "negative percentage", value: -1},
		{name: "percentage over one hundred", value: 101},
		{name: "not a number", value: math.NaN()},
		{name: "infinite", value: math.Inf(1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			usage := merakimodel.DeviceMemoryUsage{Intervals: make([]merakimodel.DeviceMemoryInterval, 1)}
			usage.Intervals[0].Memory.Used.Percentages.Median = merakiFloatPtr(tc.value)
			_, _, ok := memoryUtilization(usage)
			assert.False(t, ok)
		})
	}

	usage := merakimodel.DeviceMemoryUsage{Intervals: make([]merakimodel.DeviceMemoryInterval, 1)}
	usage.Intervals[0].Memory.Used.Median = merakiFloatPtr(-1)
	usage.Intervals[0].Memory.Free.Median = merakiFloatPtr(100)
	_, _, ok := memoryUtilization(usage)
	assert.False(t, ok)

	zero := merakimodel.DeviceMemoryUsage{Intervals: make([]merakimodel.DeviceMemoryInterval, 1)}
	zero.Intervals[0].Memory.Used.Percentages.Median = merakiFloatPtr(0)
	ratio, _, ok := memoryUtilization(zero)
	assert.True(t, ok)
	assert.Zero(t, ratio)

	overProvisioned := merakimodel.DeviceMemoryUsage{
		Provisioned: merakiFloatPtr(100),
	}
	overProvisioned.Used.Median = merakiFloatPtr(101)
	_, _, ok = memoryUtilization(overProvisioned)
	assert.False(t, ok)
}

func TestMerakiDerivedInterfaceRatiosAreBounded(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value float64
		ok    bool
	}{
		{name: "zero", value: 0, ok: true},
		{name: "positive", value: 1.5, ok: true},
		{name: "largest safe conversion", value: math.Nextafter(float64(math.MaxInt64)/1000, 0), ok: true},
		{name: "conversion overflow", value: float64(math.MaxInt64) / 1000},
		{name: "negative", value: -1},
		{name: "not a number", value: math.NaN()},
		{name: "infinite", value: math.Inf(1)},
		{name: "large overflow", value: float64(math.MaxInt64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := merakiKilobitsToBits(tc.value)
			assert.Equal(t, tc.ok, ok)
		})
	}

	for _, tc := range []struct {
		name      string
		rate      int64
		speed     int64
		validRate bool
		want      float64
		ok        bool
	}{
		{name: "zero", speed: 100, validRate: true, ok: true},
		{name: "bounded", rate: 50, speed: 100, validRate: true, want: 0.5, ok: true},
		{name: "equal", rate: 100, speed: 100, validRate: true, want: 1, ok: true},
		{name: "over speed", rate: 101, speed: 100, validRate: true},
		{name: "invalid rate", rate: 50, speed: 100},
		{name: "zero speed", rate: 0, validRate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := merakiInterfaceUtilization(tc.rate, tc.speed, tc.validRate)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func merakiFloatPtr(value float64) *float64 {
	return &value
}

func TestFirstValidTimestampFallsBackFromMalformedEndTime(t *testing.T) {
	assert.Equal(t, "2026-01-01T00:05:00Z", firstValidTimestamp("not-a-timestamp", "2026-01-01T00:05:00Z"))
}

func TestMerakiAppliancePerformanceTargetsOnlyPrimaryMX(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/123456/devices": `[
			{"name":"Primary","networkId":"N_1","serial":"PRIMARY-MX","model":"MX95","productType":"appliance"},
			{"name":"Spare","networkId":"N_2","serial":"SPARE-MX","model":"MX95","productType":"appliance"},
			{"name":"Hub","networkId":"N_3","serial":"CPSC-HUB","model":"CPSC-HUB","productType":"appliance"}
		]`,
		"/api/v1/organizations/123456/uplinks/statuses": `[
			{"networkId":"N_1","serial":"PRIMARY-MX","model":"MX95","highAvailability":{"enabled":true,"role":"primary"}},
			{"networkId":"N_2","serial":"SPARE-MX","model":"MX95","highAvailability":{"enabled":true,"role":"spare"}},
			{"networkId":"N_3","serial":"CPSC-HUB","model":"CPSC-HUB"}
		]`,
		"/api/v1/devices/PRIMARY-MX/appliance/performance": `{"perfScore":91}`,
	}
	server, requests := newMerakiFixtureServer(t, routes, nil)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth:          MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Organizations: []MerakiOrganizationConfig{{OrganizationID: "123456"}},
	})
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, intMetricValueExists(md, "cisco.scrape.partial_success", 0))
	assert.True(t, doubleMetricValueExists(md, "meraki.appliance.performance.score", 91))
	assert.Equal(t, 1, requestCount(requests, "/api/v1/devices/PRIMARY-MX/appliance/performance"))
	assert.Zero(t, requestCount(requests, "/api/v1/devices/SPARE-MX/appliance/performance"))
	assert.Zero(t, requestCount(requests, "/api/v1/devices/CPSC-HUB/appliance/performance"))
}

func TestMerakiAppliancePerformanceNoContentAndErrors(t *testing.T) {
	for _, tc := range []struct {
		name           string
		status         int
		partial        int64
		expectAPIError bool
	}{
		{name: "no content is expected no data", status: http.StatusNoContent, partial: 0},
		{name: "primary MX error remains partial", status: http.StatusBadRequest, partial: 1, expectAPIError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes := map[string]string{
				"/api/v1/organizations/123456/devices":          `[{"networkId":"N_1","serial":"PRIMARY-MX","model":"MX95","productType":"appliance"}]`,
				"/api/v1/organizations/123456/uplinks/statuses": `[{"networkId":"N_1","serial":"PRIMARY-MX","model":"MX95","highAvailability":{"enabled":true,"role":"primary"}}]`,
			}
			failures := map[string]int{"/api/v1/devices/PRIMARY-MX/appliance/performance": tc.status}
			server, _ := newMerakiFixtureServer(t, routes, failures)
			defer server.Close()

			receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
				Auth:          MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
				Organizations: []MerakiOrganizationConfig{{OrganizationID: "123456"}},
			})
			md, err := receiver.scrape(t.Context())
			require.NoError(t, err)

			assert.True(t, intMetricValueExists(md, "cisco.scrape.partial_success", tc.partial))
			assert.Equal(t, tc.expectAPIError, resourceHasMetric(md, "meraki:org:123456", "meraki.api.request.errors"))
			assert.Equal(t, !tc.expectAPIError, resourceHasMetric(md, "meraki:org:123456", "meraki.scrape.last_success"))
			assert.NotContains(t, metricNames(md), "meraki.appliance.performance.score")
		})
	}
}

func TestMerakiScrapeCollectsApplianceAndSwitchTransceivers(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/123456/devices": `[
			{"networkId":"N_1","serial":"MX-1","model":"MX95","productType":"appliance"},
			{"networkId":"N_2","serial":"MS-1","model":"MS250-24P","productType":"switch"}
		]`,
		"/api/v1/organizations/123456/appliance/devices/ports/transceivers/readings/history/byDevice": `{"items":[
			{"serial":"MX-1","network":{"id":"N_1"},"ports":[{"portId":"wan1","readings":[
				{"startTs":"2026-01-01T00:00:00Z","endTs":"2026-01-01T00:05:00Z","sfpProductId":"SFP-MX-OLDER","byMetric":{"power":{"receive":{"median":-99}}}},
				{"startTs":"2026-01-01T00:05:00Z","endTs":"2026-01-01T00:10:00Z","sfpProductId":"SFP-MX","byMetric":{"power":{"receive":{"median":-7}},"supplyVoltage":{"level":{"median":3.3}},"laserBiasCurrent":{"draw":{"median":6}}}}
			]}]}
		]}`,
		"/api/v1/organizations/123456/switch/ports/transceivers/readings/history/bySwitch": `{"items":[
			{"serial":"MS-1","network":{"id":"N_2"},"ports":[{"portId":"24","readings":[{"endTs":"2026-01-01T00:10:00Z","sfpProductId":"SFP-MS","byMetric":{"temperature":{"celsius":{"median":42}}}}]}]}
		]}`,
	}
	server, requests := newMerakiFixtureServer(t, routes, nil)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth:               MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		SwitchTransceivers: MerakiSwitchTransceiversConfig{Enabled: true},
		Organizations:      []MerakiOrganizationConfig{{OrganizationID: "123456"}},
	})
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.Equal(t, 4, metricDataPointCount(md, "cisco.transceiver.sensor"))
	assert.True(t, hasMetricDatapointAttribute(md, "cisco.transceiver.sensor", "meraki.transceiver.sfp_product_id", "SFP-MX"))
	assert.True(t, hasMetricDatapointAttribute(md, "cisco.transceiver.sensor", "meraki.transceiver.sfp_product_id", "SFP-MS"))
	assert.False(t, hasMetricDatapointAttribute(md, "cisco.transceiver.sensor", "meraki.transceiver.sfp_product_id", "SFP-MX-OLDER"))
	assert.Equal(t, float64(-7), requireGaugeDoubleValueWithAttrs(t, md, "cisco.transceiver.sensor", map[string]string{
		"meraki.transceiver.sfp_product_id": "SFP-MX",
		"cisco.transceiver.sensor":          "rx_power",
	}))
	assert.Equal(t, 3.3, requireGaugeDoubleValueWithAttrs(t, md, "cisco.transceiver.sensor", map[string]string{
		"meraki.transceiver.sfp_product_id": "SFP-MX",
		"cisco.transceiver.sensor":          "voltage",
	}))
	assert.Equal(t, 6.0, requireGaugeDoubleValueWithAttrs(t, md, "cisco.transceiver.sensor", map[string]string{
		"meraki.transceiver.sfp_product_id": "SFP-MX",
		"cisco.transceiver.sensor":          "current",
	}))
	assert.Equal(t, 1, requestCount(requests, "/api/v1/organizations/123456/appliance/devices/ports/transceivers/readings/history/byDevice"))
	assert.Equal(t, 1, requestCount(requests, "/api/v1/organizations/123456/switch/ports/transceivers/readings/history/bySwitch"))
}

func TestMerakiSwitchTransceiversRequireExplicitBetaOptIn(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/123456/devices": `[
			{"networkId":"N_1","serial":"MS-1","model":"MS250-24P","productType":"switch"}
		]`,
	}
	server, requests := newMerakiFixtureServer(t, routes, nil)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth:          MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Organizations: []MerakiOrganizationConfig{{OrganizationID: "123456"}},
	})
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.Zero(t, requestCount(requests, "/api/v1/organizations/123456/switch/ports/transceivers/readings/history/bySwitch"))
	assert.Equal(t, 1, requestCount(requests, "/api/v1/organizations/123456/appliance/devices/ports/transceivers/readings/history/byDevice"))
	assert.True(t, intMetricValueExists(md, "cisco.scrape.partial_success", 0))
}

func TestMerakiSwitchTransceiverBetaFailureIsPartialWhenEnabled(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/123456/devices": `[
			{"networkId":"N_1","serial":"MS-1","model":"MS250-24P","productType":"switch"}
		]`,
	}
	failures := map[string]int{
		"/api/v1/organizations/123456/switch/ports/transceivers/readings/history/bySwitch": http.StatusNotFound,
	}
	server, requests := newMerakiFixtureServer(t, routes, failures)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth:               MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		SwitchTransceivers: MerakiSwitchTransceiversConfig{Enabled: true},
		Organizations:      []MerakiOrganizationConfig{{OrganizationID: "123456"}},
	})
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.Equal(t, 1, requestCount(requests, "/api/v1/organizations/123456/switch/ports/transceivers/readings/history/bySwitch"))
	assert.True(t, intMetricValueExists(md, "cisco.scrape.partial_success", 1))
	assert.False(t, resourceHasMetric(md, "meraki:org:123456", "meraki.scrape.last_success"))
}

func TestMerakiSerialScopeFiltersVPNStatsAndUsesNetworkResource(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/123456/devices": `[
			{"name":"Selected MX","networkId":"N_1","serial":"SELECTED-MX","model":"MX95","productType":"appliance"}
		]`,
		"/api/v1/organizations/123456/appliance/vpn/statuses": `[
			{"networkId":"N_1","networkName":"Selected Network","deviceSerial":"SELECTED-MX"},
			{"networkId":"N_9","networkName":"Other Network","deviceSerial":"OTHER-MX"}
		]`,
		"/api/v1/organizations/123456/appliance/vpn/stats": `[
			{"networkId":"N_1","networkName":"Selected Network","merakiVpnPeers":[{"networkId":"N_HUB","networkName":"Hub","usageSummary":{"receivedInKilobytes":10,"sentInKilobytes":20}}]},
			{"networkId":"N_9","networkName":"Other Network","merakiVpnPeers":[{"networkId":"N_HUB","networkName":"Hub","usageSummary":{"receivedInKilobytes":90,"sentInKilobytes":100}}]}
		]`,
	}
	server, _ := newMerakiFixtureServer(t, routes, nil)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth:    MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Devices: []MerakiDeviceConfig{{OrganizationID: "123456", Serial: "SELECTED-MX"}},
	})
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, resourceHasMetric(md, "meraki:network:N_1", "meraki.vpn.peer.usage"))
	assert.False(t, resourceHasMetric(md, "SELECTED-MX", "meraki.vpn.peer.usage"), "network aggregates must not be attributed to an arbitrary device")
	assert.False(t, hasResourceHostID(md, "meraki:network:N_9"), "serial-scoped collection must not leak other network aggregates")
	assert.True(t, intMetricValueExists(md, "meraki.vpn.peer.usage", 10))
	assert.False(t, intMetricValueExists(md, "meraki.vpn.peer.usage", 90))
}

func TestMerakiBuilderPrunesEmptyInventoryResources(t *testing.T) {
	builder := newMerakiMetricsBuilder(time.Unix(200, 0), nil)
	builder.deviceResource(deviceResource{Serial: "EMPTY", Model: "MS120-8"})

	assert.Zero(t, builder.emit().ResourceMetrics().Len())
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

func TestMerakiSharedSelectorUsesInventoryIdentityForSparseEndpoints(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/123456/devices": `[
			{"name":"Selected Branch","networkId":"N_1","serial":"MX-1","model":"MX68","productType":"appliance"}
		]`,
		// Uplink status intentionally omits the device name. The already selected
		// inventory identity must be merged before the shared selector is applied.
		"/api/v1/organizations/123456/uplinks/statuses": `[
			{"networkId":"N_1","serial":"MX-1","model":"MX68","uplinks":[{"interface":"wan1","status":"active"}]}
		]`,
	}
	server, _ := newMerakiFixtureServer(t, routes, nil)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth:          MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Organizations: []MerakiOrganizationConfig{{OrganizationID: "123456"}},
	})
	receiver.config.DeviceSelection.Include.HostNames = []string{"Selected Branch"}

	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.True(t, resourceHasMetric(md, "MX-1", "meraki.uplink.status"))
}

func TestMerakiSharedHostIPSelectorUsesCompleteDeviceIdentity(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		exclude  bool
		selected bool
	}{
		{name: "include status public IP", ip: "198.51.100.10", selected: true},
		{name: "exclude status public IP", ip: "198.51.100.10", exclude: true},
		{name: "include uplink IP", ip: "192.0.2.10", selected: true},
		{name: "exclude uplink public IP", ip: "203.0.113.10", exclude: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			routes := map[string]string{
				"/api/v1/organizations/123456/devices": `[
					{"name":"Branch","networkId":"N_1","serial":"MX-1","model":"MX68","productType":"appliance","lanIp":"10.0.0.1"}
				]`,
				"/api/v1/organizations/123456/devices/statuses": `[
					{"name":"Branch","networkId":"N_1","serial":"MX-1","model":"MX68","productType":"appliance","status":"online","lanIp":"10.0.0.1","publicIp":"198.51.100.10"}
				]`,
				"/api/v1/organizations/123456/uplinks/statuses": `[
					{"networkId":"N_1","serial":"MX-1","model":"MX68","uplinks":[{"interface":"wan1","status":"active","ip":"192.0.2.10","publicIp":"203.0.113.10"}]}
				]`,
			}
			server, _ := newMerakiFixtureServer(t, routes, nil)
			defer server.Close()

			receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
				Auth:          MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
				Organizations: []MerakiOrganizationConfig{{OrganizationID: "123456"}},
			})
			if tc.exclude {
				receiver.config.DeviceSelection.Exclude.HostIPs = []string{tc.ip}
			} else {
				receiver.config.DeviceSelection.Include.HostIPs = []string{tc.ip}
			}

			md, err := receiver.scrape(t.Context())
			require.NoError(t, err)
			assert.Equal(t, tc.selected, hasResourceHostID(md, "MX-1"))
			assert.Equal(t, tc.selected, resourceHasMetric(md, "MX-1", "meraki.uplink.status"))
		})
	}
}

func TestMerakiHostIPExclusionFailsClosedWhenUplinkIdentityIsMissing(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/123456/devices": `[
			{"name":"Branch","networkId":"N_1","serial":"MX-1","model":"MX68","productType":"appliance","lanIp":"10.0.0.1"}
		]`,
		"/api/v1/organizations/123456/devices/statuses": `[
			{"name":"Branch","networkId":"N_1","serial":"MX-1","model":"MX68","productType":"appliance","status":"online","lanIp":"10.0.0.1"}
		]`,
		"/api/v1/organizations/123456/uplinks/statuses": `[]`,
	}
	server, _ := newMerakiFixtureServer(t, routes, nil)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth:          MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Organizations: []MerakiOrganizationConfig{{OrganizationID: "123456"}},
	})
	receiver.config.DeviceSelection.Exclude.HostIPs = []string{"203.0.113.10"}

	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.False(t, hasResourceHostID(md, "MX-1"))
	assert.True(t, intMetricValueExists(md, "cisco.scrape.partial_success", 1))
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
				strings.Contains(r.URL.Path, "/appliance/devices/ports/transceivers/readings/history/byDevice"),
				strings.Contains(r.URL.Path, "/switch/ports/transceivers/readings/history/bySwitch"):
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

func TestNormalizeMerakiTargetsPreservesUnionSemantics(t *testing.T) {
	targets := normalizeMerakiTargets(MerakiConfig{
		Organizations: []MerakiOrganizationConfig{{OrganizationID: "123", NetworkIDs: []string{"N_1"}, Serials: []string{"A"}}},
		Devices:       []MerakiDeviceConfig{{OrganizationID: "123", Serial: "B"}, {OrganizationID: "123", Serial: "A"}},
	})

	require.Len(t, targets, 1)
	assert.Equal(t, "123", targets[0].OrganizationID)
	assert.Empty(t, targets[0].Serials, "intersecting query fields cannot represent a filtered-target union")
	assert.Empty(t, targets[0].NetworkIDs)
	assert.True(t, targets[0].unionRequiresInventory)
	assert.Equal(t, []string{"A", "B"}, targets[0].explicitSerials)
}

func TestMerakiFilteredOrganizationAndExplicitDeviceAreUnioned(t *testing.T) {
	routes := map[string]string{
		"/api/v1/organizations/123456/devices": `[
			{"name":"Network Switch","networkId":"N_1","serial":"MS-N1","model":"MS120-8","productType":"switch"},
			{"name":"Explicit MX","networkId":"N_2","serial":"MX-N2","model":"MX68","productType":"appliance"},
			{"name":"Unselected","networkId":"N_3","serial":"MS-N3","model":"MS120-8","productType":"switch"}
		]`,
		"/api/v1/organizations/123456/devices/statuses": `[
			{"name":"Network Switch","networkId":"N_1","serial":"MS-N1","model":"MS120-8","productType":"switch","status":"online"},
			{"name":"Explicit MX","networkId":"N_2","serial":"MX-N2","model":"MX68","productType":"appliance","status":"online"},
			{"name":"Unselected","networkId":"N_3","serial":"MS-N3","model":"MS120-8","productType":"switch","status":"online"}
		]`,
	}
	server, requests := newMerakiFixtureServer(t, routes, nil)
	defer server.Close()

	receiver := newTestMerakiReceiver(t, server.URL, MerakiConfig{
		Auth: MerakiAuthConfig{APIKey: configopaque.String("meraki-key")},
		Organizations: []MerakiOrganizationConfig{{
			OrganizationID: "123456",
			NetworkIDs:     []string{"N_1"},
		}},
		Devices: []MerakiDeviceConfig{{OrganizationID: "123456", Serial: "MX-N2"}},
	})
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, hasResourceHostID(md, "MS-N1"))
	assert.True(t, hasResourceHostID(md, "MX-N2"))
	assert.False(t, hasResourceHostID(md, "MS-N3"))
	assert.False(t, sawQueryValue(requests, "/api/v1/organizations/123456/devices", "networkIds[]", "N_1"), "the union must not be reduced to an intersecting Dashboard query")
	assert.False(t, sawQueryValue(requests, "/api/v1/organizations/123456/devices", "serials[]", "MX-N2"))
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
	recordTransceiverValue(rb, map[string]string{"network.interface.name": "1"}, "temperature", "Cel", merakimodel.SummaryValue{Median: float64Pointer(42)})
	recordTransceiverValue(rb, map[string]string{"network.interface.name": "2"}, "rx_power", "dBm", merakimodel.SummaryValue{Median: float64Pointer(-7)})

	metric := rb.metrics["cisco.transceiver.sensor"]
	assert.Equal(t, "1", metric.Unit())
	require.Equal(t, 2, metric.Gauge().DataPoints().Len())
	assert.Equal(t, "Cel", attrValue(t, metric.Gauge().DataPoints().At(0).Attributes(), "cisco.transceiver.sensor.unit"))
	assert.Equal(t, "dBm", attrValue(t, metric.Gauge().DataPoints().At(1).Attributes(), "cisco.transceiver.sensor.unit"))
}

func TestRecordTransceiverValuePreservesExplicitZero(t *testing.T) {
	rb := newMerakiMetricsBuilder(time.Unix(200, 0), nil).orgResource("org-a")
	recordTransceiverValue(rb, map[string]string{"network.interface.name": "1"}, "temperature", "Cel", merakimodel.SummaryValue{Median: float64Pointer(0)})

	metric := rb.metrics["cisco.transceiver.sensor"]
	require.Equal(t, 1, metric.Gauge().DataPoints().Len())
	assert.Zero(t, metric.Gauge().DataPoints().At(0).DoubleValue())
}

func float64Pointer(value float64) *float64 {
	return &value
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
			if status != http.StatusNoContent {
				_, _ = w.Write([]byte(`failed`))
			}
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
			strings.Contains(r.URL.Path, "/appliance/devices/ports/transceivers/readings/history/byDevice"),
			strings.Contains(r.URL.Path, "/switch/ports/transceivers/readings/history/bySwitch"):
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

func requestCount(requests *[]capturedRequest, path string) int {
	count := 0
	for _, req := range *requests {
		if req.path == path {
			count++
		}
	}
	return count
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
