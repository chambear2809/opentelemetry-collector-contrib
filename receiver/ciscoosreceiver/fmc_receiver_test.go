// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.opentelemetry.io/collector/scraper/scraperhelper"

	fmcinternal "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/fmc"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestFMCMetricsReceiverScrape(t *testing.T) {
	server := httptest.NewServer(fmcTestHandler(t))
	defer server.Close()

	cfg := fmcTestConfig(server.URL)
	cfg.FMC.Inventory = FMCGroupConfig{Enabled: true, MaxResults: 10}
	receiver, err := newFMCMetricsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)

	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, metricNameExists(md, "fmc.manager.up"))
	assert.True(t, metricNameExists(md, "fmc.resource.info"))
	assert.True(t, metricNameExists(md, "cisco.device.up"))
	assert.True(t, fmcIntMetricValueExists(md, "fmc.scrape.partial_success", 0))
}

func TestFMCManagerAggregatesBypassOnlyDeviceFilters(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Config)
	}{
		{
			name: "FMC targets",
			configure: func(cfg *Config) {
				cfg.FMC.Targets = FMCTargetFilters{DeviceIDs: []string{"selected-device"}}
			},
		},
		{
			name: "shared device selection",
			configure: func(cfg *Config) {
				cfg.DeviceSelection = DeviceSelectionConfig{
					Include: DeviceSelectionMatchConfig{DeviceIDs: []string{"selected-device"}},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var interfaceRequests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/fmc_platform/v1/auth/generatetoken":
					w.Header().Set("X-auth-access-token", "access-1")
					w.Header().Set("X-auth-refresh-token", "refresh-1")
					w.Header().Set("DOMAIN_UUID", "domain-1")
					w.WriteHeader(http.StatusNoContent)
				case "/api/fmc_platform/v1/info/domain":
					_, _ = w.Write([]byte(`{"items":[{"id":"domain-1","name":"Global"}],"paging":{"count":1}}`))
				case "/api/fmc_platform/v1/info/serverversion":
					_, _ = w.Write([]byte(`{"items":[{"id":"server-1","name":"fmc-controller","serverVersion":"7.7"}],"paging":{"count":1}}`))
				case "/api/fmc_platform/v1/license/devicelicenses":
					_, _ = w.Write([]byte(`{"items":[{"id":"license-1","name":"device-license"}],"paging":{"count":1}}`))
				case "/api/fmc_platform/v1/license/smartlicenses":
					_, _ = w.Write([]byte(`{"items":[{"id":"smart-license-1","name":"smart-license"}],"paging":{"count":1}}`))
				case "/api/fmc_platform/v1/updates/upgradepackages":
					_, _ = w.Write([]byte(`{"items":[{"id":"upgrade-1","name":"upgrade-package"}],"paging":{"count":1}}`))
				case "/api/fmc_config/v1/domain/domain-1/devices/devicerecords":
					_, _ = w.Write([]byte(`{"items":[{"id":"unselected-device","name":"unselected-device","serialNumber":"UNSELECTED"}],"paging":{"count":1}}`))
				case "/api/fmc_config/v1/domain/domain-1/policy/accesspolicies":
					_, _ = w.Write([]byte(`{"items":[{"id":"unselected-policy","name":"unselected-policy"}],"paging":{"count":1}}`))
				default:
					if strings.Contains(r.URL.Path, "/devices/devicerecords/unselected-device/") {
						interfaceRequests.Add(1)
					}
					_, _ = w.Write([]byte(`{"items":[],"paging":{"count":0}}`))
				}
			}))
			defer server.Close()

			cfg := fmcTestConfig(server.URL)
			enabled := FMCGroupConfig{Enabled: true, MaxResults: 10}
			cfg.FMC.Manager = enabled
			cfg.FMC.Inventory = enabled
			cfg.FMC.Interfaces = enabled
			cfg.FMC.Policy = enabled
			tt.configure(cfg)

			receiver, err := newFMCMetricsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
			require.NoError(t, err)
			md, err := receiver.scrape(t.Context())
			require.NoError(t, err)

			for _, operation := range []string{
				"manager.domains",
				"manager.server_versions",
				"manager.device_licenses",
				"manager.smart_licenses",
				"manager.upgrade_packages",
			} {
				assert.True(t, hasMetricDatapointAttribute(md, "fmc.resource.info", "fmc.operation", operation), operation)
			}
			assert.False(t, hasMetricDatapointAttribute(md, "fmc.resource.info", "fmc.operation", "devices.records"))
			assert.False(t, hasMetricDatapointAttribute(md, "fmc.resource.info", "fmc.operation", "policy.access_policies"))
			assert.Zero(t, interfaceRequests.Load(), "unselected devices must not fan out to interface endpoints")
		})
	}
}

func metricNameExists(md pmetric.Metrics, name string) bool {
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		scopeMetrics := md.ResourceMetrics().At(i).ScopeMetrics()
		for j := 0; j < scopeMetrics.Len(); j++ {
			metrics := scopeMetrics.At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				if metrics.At(k).Name() == name {
					return true
				}
			}
		}
	}
	return false
}

func TestFMCLogsReceiverScrape(t *testing.T) {
	server := httptest.NewServer(fmcTestHandler(t))
	defer server.Close()

	cfg := fmcTestConfig(server.URL)
	cfg.FMC.Health = FMCGroupConfig{Enabled: true, MaxResults: 10}
	receiver, err := newFMCLogsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, &consumertest.LogsSink{})
	require.NoError(t, err)

	ld, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	require.Equal(t, 1, ld.LogRecordCount())
	assert.True(t, fmcHasLogRecordAttribute(ld, "event.domain", "fmc"))
	assert.True(t, fmcHasLogRecordAttribute(ld, "event.name", "health.alerts"))
}

func TestRecentFMCQueryUsesEpochSecondWindow(t *testing.T) {
	cfg := fmcTestConfig("https://fmc.example.test")
	cfg.FMC.EventLookback = time.Hour

	query := recentFMCQuery(cfg, time.Unix(1_800_000_000, 0))

	assert.Equal(t, "startTime:1799996400;endTime:1800000000", query.Get("filter"))
}

func TestLoadFMCEStreamerTLSSupportsInsecureSkipVerify(t *testing.T) {
	tlsConfig, err := loadFMCEStreamerTLS(FMCEStreamerTLSConfig{
		ServerName:         "fmc.example.com",
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	assert.Equal(t, "fmc.example.com", tlsConfig.ServerName)
	assert.True(t, tlsConfig.InsecureSkipVerify)
}

func TestFMCEStreamerReconnectAdvancesCursorAndSuppressesDeliveredDuplicate(t *testing.T) {
	initial := time.Unix(1_800_000_000, 0).UTC()
	client, err := fmcinternal.NewEStreamerClient(fmcinternal.EStreamerConfig{
		Address:     "fmc.example.test:8302",
		Name:        "fmc-test",
		InitialTime: initial,
	})
	require.NoError(t, err)
	deliveryErr := errors.New("downstream unavailable")
	receiver := &fmcEStreamerLogsReceiver{
		settings: receivertest.NewNopSettings(metadata.Type),
		config:   &Config{FMC: FMCConfig{}},
		consumer: consumertest.NewErr(deliveryErr),
	}
	resume := newFMCEStreamerResumeState(client.InitialTime())
	eventTime := time.Unix(1_800_000_123, 750_000_000).UTC()
	resume.now = func() time.Time { return eventTime }
	event := fmcinternal.EStreamerEvent{
		EventType:  "connection",
		RecordType: 3,
		Timestamp:  eventTime,
		Body: fmcinternal.Object{
			"eventId":     "event-1",
			"InitiatorIP": "192.0.2.10",
		},
		Raw: `{"eventId":"event-1","InitiatorIP":"192.0.2.10"}`,
	}

	require.ErrorIs(t, receiver.consumeEStreamerEvent(t.Context(), client, resume, event), deliveryErr)
	assert.Empty(t, resume.seen)
	assert.True(t, resume.cursor.IsZero())
	assert.Equal(t, initial, resume.requestStart())

	sink := &consumertest.LogsSink{}
	receiver.consumer = sink
	require.NoError(t, receiver.consumeEStreamerEvent(t.Context(), client, resume, event))
	assert.Equal(t, 1, sink.LogRecordCount())
	assert.Equal(t, eventTime, resume.cursor)
	assert.Equal(t, time.Unix(1_800_000_122, 0).UTC(), resume.requestStart())

	// FMC can replay the inclusive cursor boundary after reconnect. A record
	// already accepted by the next consumer must not be exported again.
	require.NoError(t, receiver.consumeEStreamerEvent(t.Context(), client, resume, event))
	assert.Equal(t, 1, sink.LogRecordCount())
}

func TestFMCEStreamerEventKeyHasFixedSizeForControllerIdentifier(t *testing.T) {
	key := fmcEStreamerEventKey(fmcinternal.EStreamerEvent{
		EventType:  "connection",
		RecordType: 3,
		Body:       fmcinternal.Object{"eventId": strings.Repeat("x", 1_000_000)},
	})
	assert.Len(t, key, len("sha256:")+64)
}

func fmcIntMetricValueExists(md pmetric.Metrics, name string, value int64) bool {
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		scopeMetrics := md.ResourceMetrics().At(i).ScopeMetrics()
		for j := 0; j < scopeMetrics.Len(); j++ {
			metrics := scopeMetrics.At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				metric := metrics.At(k)
				if metric.Name() != name || metric.Type() != pmetric.MetricTypeGauge {
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

func fmcHasLogRecordAttribute(ld plog.Logs, name, value string) bool {
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		scopeLogs := ld.ResourceLogs().At(i).ScopeLogs()
		for j := 0; j < scopeLogs.Len(); j++ {
			records := scopeLogs.At(j).LogRecords()
			for k := 0; k < records.Len(); k++ {
				attr, ok := records.At(k).Attributes().Get(name)
				if ok && attr.Str() == value {
					return true
				}
			}
		}
	}
	return false
}

func fmcTestConfig(endpoint string) *Config {
	cfg := &Config{
		ControllerConfig: scraperhelper.ControllerConfig{
			Timeout:            30 * time.Second,
			CollectionInterval: time.Minute,
		},
		FMC: FMCConfig{
			Enabled: true,
			Controllers: []FMCControllerConfig{{
				Endpoint: endpoint,
				Name:     "fmc-test",
			}},
			Auth: ControllerAuthConfig{
				Username: "admin",
				Password: configopaque.String("password"),
			},
			PageSize:      10,
			MaxRetries:    1,
			EventLookback: time.Hour,
			Manager:       FMCGroupConfig{Enabled: true, MaxResults: 10},
		},
	}
	return cfg
}

func fmcTestHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/fmc_platform/v1/auth/generatetoken":
			w.Header().Set("X-auth-access-token", "access-1")
			w.Header().Set("X-auth-refresh-token", "refresh-1")
			w.Header().Set("DOMAIN_UUID", "domain-1")
			w.WriteHeader(http.StatusNoContent)
		case "/api/fmc_platform/v1/info/domain":
			_, _ = w.Write([]byte(`{"items":[{"id":"domain-1","name":"Global"}],"paging":{"count":1}}`))
		case "/api/fmc_platform/v1/info/serverversion":
			_, _ = w.Write([]byte(`{"items":[{"id":"server-1","name":"fmc-test","serverVersion":"7.7"}],"paging":{"count":1}}`))
		case "/api/fmc_platform/v1/license/devicelicenses",
			"/api/fmc_platform/v1/license/smartlicenses",
			"/api/fmc_platform/v1/updates/upgradepackages",
			"/api/fmc_config/v1/domain/domain-1/devicegroups/devicegrouprecords",
			"/api/fmc_config/v1/domain/domain-1/chassis/fmcmanagedchassis":
			_, _ = w.Write([]byte(`{"items":[],"paging":{"count":0}}`))
		case "/api/fmc_config/v1/domain/domain-1/devices/devicerecords":
			assert.Equal(t, "access-1", r.Header.Get("X-auth-access-token"))
			_, _ = w.Write([]byte(`{"items":[{"id":"dev-1","name":"ftd-edge-1","serialNumber":"FMC-SERIAL-1","managementIpAddress":"192.0.2.40","healthStatus":"healthy","softwareVersion":"7.4"}],"paging":{"count":1}}`))
		case "/api/fmc_config/v1/domain/domain-1/health/alerts":
			assert.Equal(t, "access-1", r.Header.Get("X-auth-access-token"))
			_, _ = w.Write([]byte(`{"items":[{"id":"alert-1","name":"Intrusion Policy Out Of Date","severity":"warning","status":"active","eventTime":"2026-01-01T00:00:00Z"}],"paging":{"count":1}}`))
		case "/api/fmc_config/v1/domain/domain-1/health/events":
			assert.Equal(t, "access-1", r.Header.Get("X-auth-access-token"))
			_, _ = w.Write([]byte(`{"items":[],"paging":{"count":0}}`))
		default:
			assert.Equal(t, "access-1", r.Header.Get("X-auth-access-token"))
			_, _ = w.Write([]byte(`{"items":[],"paging":{"count":0}}`))
		}
	}
}
