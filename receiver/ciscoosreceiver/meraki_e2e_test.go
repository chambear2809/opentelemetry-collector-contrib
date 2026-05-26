// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package ciscoosreceiver

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

const (
	merakiE2EAPIKeyEnv  = "MERAKI_DASHBOARD_API_KEY"
	merakiE2EOrgIDEnv   = "MERAKI_E2E_ORG_ID"
	merakiE2ESerialsEnv = "MERAKI_E2E_SERIALS"

	intersightE2EKeyIDEnv   = "INTERSIGHT_KEY_ID"
	intersightE2EKeyFileEnv = "INTERSIGHT_KEY_FILE"
	intersightE2EKeyPEMEnv  = "INTERSIGHT_KEY_PEM"
	intersightE2EEndpoint   = "INTERSIGHT_ENDPOINT"
	intersightE2ESerialsEnv = "INTERSIGHT_E2E_SERIALS"
	intersightE2EMoIDsEnv   = "INTERSIGHT_E2E_MOIDS"
	intersightE2ETelemetry  = "INTERSIGHT_E2E_TELEMETRY"

	catalystCenterE2EEndpointEnv      = "CATALYST_CENTER_ENDPOINT"
	catalystCenterE2EUsernameEnv      = "CATALYST_CENTER_USERNAME"
	catalystCenterE2EPasswordEnv      = "CATALYST_CENTER_PASSWORD"
	catalystCenterE2EInsecureEnv      = "CATALYST_CENTER_INSECURE_SKIP_VERIFY"
	catalystCenterE2EDeviceDetailsEnv = "CATALYST_CENTER_E2E_DEVICE_DETAILS"
	catalystCenterE2EClientMACsEnv    = "CATALYST_CENTER_E2E_CLIENT_MACS"
)

// TestE2ELiveMeraki exercises the Meraki Dashboard API receiver path.
//
// Required environment:
//
//	MERAKI_DASHBOARD_API_KEY
//	MERAKI_E2E_ORG_ID
//
// Optional:
//
//	MERAKI_E2E_SERIALS=Q234-ABCD-0001,Q234-ABCD-0002
func TestE2ELiveMeraki(t *testing.T) {
	apiKey := os.Getenv(merakiE2EAPIKeyEnv)
	orgID := os.Getenv(merakiE2EOrgIDEnv)
	if apiKey == "" || orgID == "" {
		t.Skipf("set %s and %s to run live Meraki e2e test", merakiE2EAPIKeyEnv, merakiE2EOrgIDEnv)
	}

	cfg := createDefaultConfig().(*Config)
	cfg.Timeout = 30 * time.Second
	cfg.CollectionInterval = 60 * time.Second
	cfg.Meraki.Auth.APIKey = configopaque.String(apiKey)

	serials := merakiE2ECSVEnv(merakiE2ESerialsEnv)
	if len(serials) == 0 {
		cfg.Meraki.Organizations = []MerakiOrganizationConfig{{OrganizationID: orgID}}
	} else {
		for _, serial := range serials {
			cfg.Meraki.Devices = append(cfg.Meraki.Devices, MerakiDeviceConfig{
				OrganizationID: orgID,
				Serial:         serial,
			})
		}
	}

	rcvr, err := newMerakiMetricsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)
	t.Cleanup(rcvr.client.CloseIdleConnections)
	md, err := rcvr.scrape(t.Context())
	require.NoError(t, err)
	require.Positive(t, md.MetricCount())

	names := merakiE2EMetricNames(md)
	assert.Contains(t, names, "cisco.device.up")
	assert.Contains(t, names, "meraki.api.request.duration")

	if len(serials) > 0 {
		for _, serial := range serials {
			assert.True(t, merakiE2EHasResourceHostID(md, serial), "expected Meraki resource for serial %s", serial)
		}
	}
	assert.True(t, merakiE2EHasAny(names,
		"system.memory.utilization",
		"system.network.interface.status",
		"meraki.uplink.status",
		"meraki.wireless.client.count",
		"meraki.appliance.performance.score",
	), "expected at least one product-specific Meraki metric")
}

// TestE2ELiveIntersight exercises the native Intersight receiver path.
//
// Required environment:
//
//	INTERSIGHT_KEY_ID
//	INTERSIGHT_KEY_FILE or INTERSIGHT_KEY_PEM
//
// Optional:
//
//	INTERSIGHT_ENDPOINT=https://intersight.com
//	INTERSIGHT_E2E_SERIALS=SERIAL1,SERIAL2
//	INTERSIGHT_E2E_MOIDS=moid1,moid2
//	INTERSIGHT_E2E_TELEMETRY=true
func TestE2ELiveIntersight(t *testing.T) {
	keyID := os.Getenv(intersightE2EKeyIDEnv)
	keyFile := os.Getenv(intersightE2EKeyFileEnv)
	keyPEM := os.Getenv(intersightE2EKeyPEMEnv)
	if keyID == "" || (keyFile == "" && keyPEM == "") {
		t.Skipf("set %s and %s or %s to run live Intersight e2e test", intersightE2EKeyIDEnv, intersightE2EKeyFileEnv, intersightE2EKeyPEMEnv)
	}

	cfg := createDefaultConfig().(*Config)
	cfg.Timeout = 30 * time.Second
	cfg.CollectionInterval = 60 * time.Second
	cfg.Intersight.Enabled = true
	cfg.Intersight.Auth.KeyID = keyID
	cfg.Intersight.Auth.KeyFile = keyFile
	cfg.Intersight.Auth.KeyPEM = configopaque.String(keyPEM)
	if endpoint := os.Getenv(intersightE2EEndpoint); endpoint != "" {
		cfg.Intersight.Endpoint = endpoint
	}
	cfg.Intersight.PageSize = 10
	cfg.Intersight.MaxRetries = 2
	cfg.Intersight.Targets.Serials = merakiE2ECSVEnv(intersightE2ESerialsEnv)
	cfg.Intersight.Targets.MoIDs = merakiE2ECSVEnv(intersightE2EMoIDsEnv)
	setIntersightE2EMaxResults(&cfg.Intersight, 10)
	cfg.Intersight.Telemetry.Enabled = intersightE2EBoolEnv(intersightE2ETelemetry)
	if cfg.Intersight.Telemetry.Enabled {
		cfg.Timeout = 2 * time.Minute
	}

	rcvr, err := newIntersightMetricsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)
	t.Cleanup(rcvr.client.CloseIdleConnections)
	md, err := rcvr.scrape(t.Context())
	require.NoError(t, err)
	require.Positive(t, md.MetricCount())

	names := merakiE2EMetricNames(md)
	assert.Contains(t, names, "intersight.api.request.duration")
	assert.Contains(t, names, "intersight.scrape.last_success")
	assert.False(t, intersightE2EHasAPIStatus(md, "401"), "Intersight returned HTTP 401; verify the key ID, private key, API key status, account, and endpoint")
	assert.True(t, intMetricValueExists(md, "intersight.scrape.partial_success", 0), "expected all enabled Intersight endpoint and telemetry families to scrape successfully")
	if len(cfg.Intersight.Targets.Serials) > 0 {
		for _, serial := range cfg.Intersight.Targets.Serials {
			assert.True(t, merakiE2EHasResourceHostID(md, serial), "expected Intersight resource for serial %s", serial)
		}
	}
}

// TestE2ELiveCatalystCenter exercises the native Catalyst Center receiver path.
//
// Required environment:
//
//	CATALYST_CENTER_ENDPOINT
//	CATALYST_CENTER_USERNAME
//	CATALYST_CENTER_PASSWORD
//
// Optional:
//
//	CATALYST_CENTER_INSECURE_SKIP_VERIFY=true
//	CATALYST_CENTER_E2E_DEVICE_DETAILS=uuid:device-uuid-1,macAddress:00:11:22:33:44:55
//	CATALYST_CENTER_E2E_CLIENT_MACS=00:11:22:33:44:55,AA:BB:CC:DD:EE:FF
func TestE2ELiveCatalystCenter(t *testing.T) {
	endpoint := os.Getenv(catalystCenterE2EEndpointEnv)
	username := os.Getenv(catalystCenterE2EUsernameEnv)
	password := os.Getenv(catalystCenterE2EPasswordEnv)
	if endpoint == "" || username == "" || password == "" {
		t.Skipf("set %s, %s, and %s to run live Catalyst Center e2e test", catalystCenterE2EEndpointEnv, catalystCenterE2EUsernameEnv, catalystCenterE2EPasswordEnv)
	}

	cfg := createDefaultConfig().(*Config)
	cfg.Timeout = 2 * time.Minute
	cfg.CollectionInterval = 60 * time.Second
	cfg.CatalystCenter.Enabled = true
	cfg.CatalystCenter.Endpoint = endpoint
	cfg.CatalystCenter.Auth.Username = username
	cfg.CatalystCenter.Auth.Password = configopaque.String(password)
	cfg.CatalystCenter.PageSize = 25
	cfg.CatalystCenter.MaxRetries = 2
	cfg.CatalystCenter.InsecureSkipVerify = intersightE2EBoolEnv(catalystCenterE2EInsecureEnv)
	setCatalystCenterE2EMaxResults(&cfg.CatalystCenter, 25)
	cfg.CatalystCenter.Targets.DeviceDetails = catalystCenterE2EDeviceDetails()
	cfg.CatalystCenter.Targets.ClientMACs = merakiE2ECSVEnv(catalystCenterE2EClientMACsEnv)

	rcvr, err := newCatalystCenterMetricsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)
	t.Cleanup(rcvr.client.CloseIdleConnections)
	md, err := rcvr.scrape(t.Context())
	require.NoError(t, err)
	require.Positive(t, md.MetricCount())

	names := merakiE2EMetricNames(md)
	assert.Contains(t, names, "catalyst_center.api.request.duration")
	assert.Contains(t, names, "catalyst_center.scrape.last_success")
	assert.True(t, intMetricValueExists(md, "catalyst_center.scrape.partial_success", 0), "expected all enabled Catalyst Center endpoint families to scrape successfully; API errors: %v", catalystCenterE2EAPIErrors(md))
	assert.True(t, merakiE2EHasAny(names,
		"cisco.device.up",
		"catalyst_center.network.health.score",
		"catalyst_center.site.network_device.health.percentage",
		"catalyst_center.issue.count",
	), "expected at least one Catalyst Center assurance metric, got %v with API statuses %v", names, catalystCenterE2EAPIStatuses(md))
}

func merakiE2EMetricNames(md pmetric.Metrics) map[string]struct{} {
	names := map[string]struct{}{}
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			for k := 0; k < sm.Metrics().Len(); k++ {
				names[sm.Metrics().At(k).Name()] = struct{}{}
			}
		}
	}
	return names
}

func catalystCenterE2EDeviceDetails() []CatalystCenterDeviceDetailTarget {
	raw := os.Getenv(catalystCenterE2EDeviceDetailsEnv)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]CatalystCenterDeviceDetailTarget, 0, len(parts))
	for _, part := range parts {
		identifier, searchBy, ok := strings.Cut(strings.TrimSpace(part), ":")
		if ok && identifier != "" && searchBy != "" {
			out = append(out, CatalystCenterDeviceDetailTarget{Identifier: identifier, SearchBy: searchBy})
		}
	}
	return out
}

func merakiE2EHasResourceHostID(md pmetric.Metrics, hostID string) bool {
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		value, ok := md.ResourceMetrics().At(i).Resource().Attributes().Get("host.id")
		if ok && value.Str() == hostID {
			return true
		}
	}
	return false
}

func merakiE2EHasAny(names map[string]struct{}, candidates ...string) bool {
	for _, candidate := range candidates {
		if _, ok := names[candidate]; ok {
			return true
		}
	}
	return false
}

func intersightE2EHasAPIStatus(md pmetric.Metrics, status string) bool {
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			for k := 0; k < sm.Metrics().Len(); k++ {
				metric := sm.Metrics().At(k)
				if metric.Name() != "intersight.api.request.errors" {
					continue
				}
				points := metric.Gauge().DataPoints()
				for l := 0; l < points.Len(); l++ {
					value, ok := points.At(l).Attributes().Get("http.response.status_code")
					if ok && value.Str() == status {
						return true
					}
				}
			}
		}
	}
	return false
}

func catalystCenterE2EAPIStatuses(md pmetric.Metrics) map[string]int {
	statuses := map[string]int{}
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			for k := 0; k < sm.Metrics().Len(); k++ {
				metric := sm.Metrics().At(k)
				if metric.Name() != "catalyst_center.api.request.errors" {
					continue
				}
				points := metric.Gauge().DataPoints()
				for l := 0; l < points.Len(); l++ {
					status := "none"
					if value, ok := points.At(l).Attributes().Get("http.response.status_code"); ok {
						status = value.Str()
					}
					statuses[status]++
				}
			}
		}
	}
	return statuses
}

func catalystCenterE2EAPIErrors(md pmetric.Metrics) map[string]int {
	errors := map[string]int{}
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			for k := 0; k < sm.Metrics().Len(); k++ {
				metric := sm.Metrics().At(k)
				if metric.Name() != "catalyst_center.api.request.errors" {
					continue
				}
				points := metric.Gauge().DataPoints()
				for l := 0; l < points.Len(); l++ {
					attrs := points.At(l).Attributes()
					operation := "unknown"
					if value, ok := attrs.Get("catalyst_center.api.operation"); ok {
						operation = value.Str()
					}
					status := "none"
					if value, ok := attrs.Get("http.response.status_code"); ok {
						status = value.Str()
					}
					errors[operation+"/"+status]++
				}
			}
		}
	}
	return errors
}

func merakiE2ECSVEnv(key string) []string {
	raw := os.Getenv(key)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func intersightE2EBoolEnv(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func setIntersightE2EMaxResults(cfg *IntersightConfig, maxResults int) {
	cfg.Inventory.MaxResults = maxResults
	cfg.Events.MaxResults = maxResults
	cfg.Audit.MaxResults = maxResults
	cfg.Telemetry.MaxResults = maxResults
	cfg.Equipment.MaxResults = maxResults
	cfg.Network.MaxResults = maxResults
	cfg.Firmware.MaxResults = maxResults
	cfg.Storage.MaxResults = maxResults
	cfg.HyperFlex.MaxResults = maxResults
	cfg.Kubernetes.MaxResults = maxResults
	cfg.Virtualization.MaxResults = maxResults
}

func setCatalystCenterE2EMaxResults(cfg *CatalystCenterConfig, maxResults int) {
	cfg.Inventory.MaxResults = maxResults
	cfg.Interfaces.MaxResults = maxResults
	cfg.Health.MaxResults = maxResults
	cfg.Topology.MaxResults = maxResults
	cfg.Issues.MaxResults = maxResults
	cfg.Details.MaxResults = maxResults
}
