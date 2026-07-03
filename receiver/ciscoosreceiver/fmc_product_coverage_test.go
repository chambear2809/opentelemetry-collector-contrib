// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestFMCScopedFamiliesCollectWithOwningGroupOnly(t *testing.T) {
	interfaceChassis := fmcProductEndpointsForGroup(fmcChassisScopedEndpoints(), "interfaces")
	inventoryChassis := fmcProductEndpointsForGroup(fmcChassisScopedEndpoints(), "inventory")
	interfaceEndpoints := append(append([]fmcScopedEndpoint{}, fmcDeviceScopedEndpoints()...), interfaceChassis...)

	require.Len(t, interfaceEndpoints, 15)
	require.Len(t, inventoryChassis, 3)
	require.Len(t, fmcHealthScopedEndpoints(), 5)
	require.Len(t, fmcVPNTunnelScopedEndpoints(), 1)
	require.Len(t, fmcHAScopedEndpoints(), 1)
	require.Len(t, fmcPolicyScopedEndpoints(), 4)
	require.Len(t, fmcDeploymentScopedEndpoints(), 2)

	tests := []struct {
		name      string
		group     string
		endpoints []fmcScopedEndpoint
		sources   []string
		forbidden []fmcScopedEndpoint
	}{
		{
			name:      "interfaces loads device and chassis parents",
			group:     "interfaces",
			endpoints: interfaceEndpoints,
			sources:   []string{"devices", "chassis"},
			forbidden: inventoryChassis,
		},
		{
			name:      "inventory owns chassis summaries",
			group:     "inventory",
			endpoints: inventoryChassis,
			sources:   []string{"devices", "chassis"},
			forbidden: interfaceChassis,
		},
		{
			name:      "health loads device parents",
			group:     "health",
			endpoints: fmcHealthScopedEndpoints(),
			sources:   []string{"devices"},
		},
		{
			name:      "vpn loads tunnel parents",
			group:     "vpn",
			endpoints: fmcVPNTunnelScopedEndpoints(),
			sources:   []string{"tunnel_statuses"},
		},
		{
			name:      "ha loads pair parents",
			group:     "ha",
			endpoints: fmcHAScopedEndpoints(),
			sources:   []string{"ha_pairs"},
		},
		{
			name:      "policy loads every policy parent family",
			group:     "policy",
			endpoints: fmcPolicyScopedEndpoints(),
			sources:   []string{"access_policies", "prefilter_policies", "nat_policies"},
		},
		{
			name:      "deployments loads deployable device parents",
			group:     "deployments",
			endpoints: fmcDeploymentScopedEndpoints(),
			sources:   []string{"deployable_devices"},
		},
	}

	allScopedSources := map[string]struct{}{}
	for _, endpoints := range [][]fmcScopedEndpoint{
		fmcDeviceScopedEndpoints(),
		fmcChassisScopedEndpoints(),
		fmcHealthScopedEndpoints(),
		fmcVPNTunnelScopedEndpoints(),
		fmcHAScopedEndpoints(),
		fmcPolicyScopedEndpoints(),
		fmcDeploymentScopedEndpoints(),
	} {
		for _, endpoint := range endpoints {
			allScopedSources[endpoint.source] = struct{}{}
		}
	}
	coveredSources := map[string]struct{}{}
	for _, tt := range tests {
		for _, source := range tt.sources {
			coveredSources[source] = struct{}{}
		}
	}
	assert.Equal(t, fmcProductSortedKeys(allScopedSources), fmcProductSortedKeys(coveredSources), "every scoped source must have an owning-group regression case")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parentIDs := map[string]string{
				"devices":            "device-1",
				"chassis":            "chassis-1",
				"tunnel_statuses":    "tunnel-1",
				"ha_pairs":           "ha-pair-1",
				"access_policies":    "access-policy-1",
				"prefilter_policies": "prefilter-policy-1",
				"nat_policies":       "nat-policy-1",
				"deployable_devices": "deployable-1",
			}
			sourcePaths := map[string]string{
				"devices":            fmcDomainPath("domain-1", "devices/devicerecords"),
				"chassis":            fmcDomainPath("domain-1", "chassis/fmcmanagedchassis"),
				"tunnel_statuses":    fmcDomainPath("domain-1", "health/tunnelstatuses"),
				"ha_pairs":           fmcDomainPath("domain-1", "devicehapairs/ftddevicehapairs"),
				"access_policies":    fmcDomainPath("domain-1", "policy/accesspolicies"),
				"prefilter_policies": fmcDomainPath("domain-1", "policy/prefilterpolicies"),
				"nat_policies":       fmcDomainPath("domain-1", "policy/ftdnatpolicies"),
				"deployable_devices": fmcDomainPath("domain-1", "deployment/deployabledevices"),
			}
			parentsByPath := map[string]string{}
			for source, path := range sourcePaths {
				parentsByPath[path] = parentIDs[source]
			}
			scopedPaths := map[string]struct{}{}
			for _, endpoint := range tt.endpoints {
				scopedPaths[fmcProductScopedPath(endpoint, parentIDs[endpoint.source])] = struct{}{}
			}

			var requestsMu sync.Mutex
			requests := make([]fmcProductRequest, 0, len(tt.endpoints)+len(tt.sources))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/fmc_platform/v1/auth/generatetoken" {
					w.Header().Set("X-auth-access-token", "access-1")
					w.Header().Set("X-auth-refresh-token", "refresh-1")
					w.Header().Set("DOMAIN_UUID", "domain-1")
					w.WriteHeader(http.StatusNoContent)
					return
				}
				assert.Equal(t, "access-1", r.Header.Get("X-auth-access-token"))
				requestsMu.Lock()
				requests = append(requests, fmcProductRequest{path: r.URL.Path, query: r.URL.Query()})
				requestsMu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if parentID, ok := parentsByPath[r.URL.Path]; ok {
					_, _ = fmt.Fprintf(w, `{"items":[{"id":%q,"name":"parent","status":"active"}],"paging":{"count":1}}`, parentID)
					return
				}
				if _, ok := scopedPaths[r.URL.Path]; ok {
					_, _ = w.Write([]byte(`{"items":[{"id":"child-1","name":"child","status":"active"}],"paging":{"count":1}}`))
					return
				}
				_, _ = w.Write([]byte(`{"items":[],"paging":{"count":0}}`))
			}))
			defer server.Close()

			cfg := fmcTestConfig(server.URL)
			disableFMCProductGroups(&cfg.FMC)
			enableFMCProductGroup(&cfg.FMC, tt.group)
			receiver, err := newFMCMetricsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
			require.NoError(t, err)

			md, err := receiver.scrape(t.Context())
			require.NoError(t, err)

			requestsMu.Lock()
			gotRequests := append([]fmcProductRequest(nil), requests...)
			requestsMu.Unlock()
			for _, source := range tt.sources {
				assert.Equal(t, 1, fmcProductRequestCount(gotRequests, sourcePaths[source], ""), "source %s", source)
			}
			for _, endpoint := range tt.endpoints {
				path := fmcProductScopedPath(endpoint, parentIDs[endpoint.source])
				filter := fmcProductExpectedFilter(endpoint, parentIDs[endpoint.source])
				assert.Equal(t, 1, fmcProductRequestCount(gotRequests, path, filter), endpoint.operation)
				assert.True(t, hasMetricDatapointAttribute(md, "fmc.resource.info", "fmc.operation", endpoint.operation), endpoint.operation)
			}
			for _, endpoint := range tt.forbidden {
				path := fmcProductScopedPath(endpoint, parentIDs[endpoint.source])
				assert.Equal(t, 0, fmcProductRequestCount(gotRequests, path, ""), endpoint.operation)
			}
			assert.True(t, fmcIntMetricValueExists(md, "fmc.scrape.partial_success", 0))
		})
	}
}

type fmcProductRequest struct {
	path  string
	query url.Values
}

func fmcProductEndpointsForGroup(endpoints []fmcScopedEndpoint, group string) []fmcScopedEndpoint {
	result := make([]fmcScopedEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.group == group {
			result = append(result, endpoint)
		}
	}
	return result
}

func fmcProductScopedPath(endpoint fmcScopedEndpoint, parentID string) string {
	path := strings.ReplaceAll(endpoint.path, "{containerUUID}", url.PathEscape(parentID))
	path = strings.ReplaceAll(path, "{policyUUID}", url.PathEscape(parentID))
	path = strings.ReplaceAll(path, "{deviceUUID}", url.PathEscape(parentID))
	return fmcDomainPath("domain-1", path)
}

func fmcProductExpectedFilter(endpoint fmcScopedEndpoint, parentID string) string {
	switch endpoint.operation {
	case "health.aggregate_cpu":
		return "device_uuid:" + parentID + ";metric:CPU;timeRange:5m"
	case "health.aggregate_memory":
		return "device_uuid:" + parentID + ";metric:MEM;timeRange:5m"
	case "health.aggregate_interfaces":
		return "device_uuid:" + parentID + ";metric:INTERFACE;timeRange:5m"
	case "health.aggregate_disk":
		return "device_uuid:" + parentID + ";metric:DISK_STATS;timeRange:5m"
	case "health.aggregate_chassis":
		return "device_uuid:" + parentID + ";metric:CHASSIS_STATS;timeRange:5m"
	case "deployment.device_deployments":
		return "recent-window"
	default:
		return ""
	}
}

func fmcProductRequestCount(requests []fmcProductRequest, path, filter string) int {
	count := 0
	for _, request := range requests {
		if request.path != path || request.query.Get("expanded") != "true" {
			continue
		}
		requestFilter := request.query.Get("filter")
		switch filter {
		case "":
			if requestFilter != "" {
				continue
			}
		case "recent-window":
			if !strings.HasPrefix(requestFilter, "startTime:") || !strings.Contains(requestFilter, ";endTime:") {
				continue
			}
		default:
			if requestFilter != filter {
				continue
			}
		}
		count++
	}
	return count
}

func disableFMCProductGroups(cfg *FMCConfig) {
	disabled := FMCGroupConfig{Enabled: false, MaxResults: 2}
	cfg.Manager = disabled
	cfg.Inventory = disabled
	cfg.Interfaces = disabled
	cfg.Health = disabled
	cfg.VPN = disabled
	cfg.HA = disabled
	cfg.Policy = disabled
	cfg.Deployments = disabled
	cfg.Audit = disabled
	cfg.MaxRetries = 0
}

func enableFMCProductGroup(cfg *FMCConfig, group string) {
	enabled := FMCGroupConfig{Enabled: true, MaxResults: 2}
	switch group {
	case "inventory":
		cfg.Inventory = enabled
	case "interfaces":
		cfg.Interfaces = enabled
	case "health":
		cfg.Health = enabled
	case "vpn":
		cfg.VPN = enabled
	case "ha":
		cfg.HA = enabled
	case "policy":
		cfg.Policy = enabled
	case "deployments":
		cfg.Deployments = enabled
	}
}

func fmcProductSortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
