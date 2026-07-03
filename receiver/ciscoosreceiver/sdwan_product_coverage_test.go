// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSDWANOptInGroupsRequestEveryConfiguredEndpoint(t *testing.T) {
	tests := []struct {
		name   string
		enable func(*SDWANConfig)
		specs  []sdwanEndpointSpec
	}{
		{
			name: "realtime_details",
			enable: func(cfg *SDWANConfig) {
				cfg.RealtimeDetails = SDWANGroupConfig{Enabled: true, MaxResults: 1}
			},
			specs: []sdwanEndpointSpec{{group: "realtime_details", operation: "realtime.system_status", path: "/device/system/status", deviceScoped: true}},
		},
		{
			name: "tunnels",
			enable: func(cfg *SDWANConfig) {
				cfg.Tunnels = SDWANGroupConfig{Enabled: true, MaxResults: 1}
			},
			specs: []sdwanEndpointSpec{
				{group: "tunnels", operation: "tunnels.ipsec", path: "/device/ipsec/localsa", deviceScoped: true},
				{group: "tunnels", operation: "tunnels.transport", path: "/device/tunnel/statistics", deviceScoped: true},
			},
		},
		{
			name: "flows",
			enable: func(cfg *SDWANConfig) {
				cfg.Flows = SDWANGroupConfig{Enabled: true, MaxResults: 1}
			},
			specs: []sdwanEndpointSpec{
				{group: "flows", operation: "flows.dpi", path: "/device/dpi/applications", deviceScoped: true},
				{group: "flows", operation: "flows.cflowd", path: "/device/cflowd/flows", deviceScoped: true},
			},
		},
		{
			name: "policy_qos",
			enable: func(cfg *SDWANConfig) {
				cfg.PolicyQoS = SDWANGroupConfig{Enabled: true, MaxResults: 1}
			},
			specs: []sdwanEndpointSpec{
				{group: "policy_qos", operation: "policy_qos.acl", path: "/device/policy/accesslistcounters", deviceScoped: true},
				{group: "policy_qos", operation: "policy_qos.qos", path: "/device/qos/queue_stats", deviceScoped: true},
			},
		},
		{
			name: "security",
			enable: func(cfg *SDWANConfig) {
				cfg.Security = SDWANGroupConfig{Enabled: true, MaxResults: 1}
			},
			specs: []sdwanEndpointSpec{
				{group: "security", operation: "security.umbrella", path: "/device/umbrella/overview", deviceScoped: true},
				{group: "security", operation: "security.zbfw", path: "/device/zbfw/statistics", deviceScoped: true},
				{group: "security", operation: "security.utd", path: "/device/utd/dataplane/stats", deviceScoped: true},
			},
		},
		{
			name: "appqoe",
			enable: func(cfg *SDWANConfig) {
				cfg.AppQoE = SDWANGroupConfig{Enabled: true, MaxResults: 1}
			},
			specs: []sdwanEndpointSpec{
				{group: "appqoe", operation: "appqoe.status", path: "/device/appqoe/status", deviceScoped: true},
				{group: "appqoe", operation: "appqoe.dre", path: "/device/dre/status", deviceScoped: true},
			},
		},
		{
			name: "cloud_onramp",
			enable: func(cfg *SDWANConfig) {
				cfg.CloudOnRamp = SDWANGroupConfig{Enabled: true, MaxResults: 1}
			},
			specs: []sdwanEndpointSpec{
				{group: "cloud_onramp", operation: "cloud_onramp.saas", path: "/device/cloudx/applications", deviceScoped: true},
				{group: "cloud_onramp", operation: "cloud_onramp.gateways", path: "/cloudservices/status"},
			},
		},
		{
			name: "nwpi",
			enable: func(cfg *SDWANConfig) {
				cfg.NWPI = SDWANGroupConfig{Enabled: true, MaxResults: 1}
			},
			specs: []sdwanEndpointSpec{
				{group: "nwpi", operation: "nwpi.tasks", path: "/stream/device/nwpi/tasks"},
				{group: "nwpi", operation: "nwpi.events", path: "/stream/device/nwpi/eventReadout"},
			},
		},
		{
			name: "underlay",
			enable: func(cfg *SDWANConfig) {
				cfg.Underlay = SDWANGroupConfig{Enabled: true, MaxResults: 1}
			},
			specs: []sdwanEndpointSpec{
				{group: "underlay", operation: "underlay.summary", path: "/device/underlay/summary", deviceScoped: true},
				{group: "underlay", operation: "underlay.alarms", path: "/underlay/alarm/overview"},
			},
		},
		{
			name: "cellular",
			enable: func(cfg *SDWANConfig) {
				cfg.Cellular = SDWANGroupConfig{Enabled: true, MaxResults: 1}
			},
			specs: []sdwanEndpointSpec{
				{group: "cellular", operation: "cellular.radio", path: "/device/cellular/radio", deviceScoped: true},
				{group: "cellular", operation: "cellular.sessions", path: "/device/cellular/sessions", deviceScoped: true},
			},
		},
		{
			name: "hardware_energy",
			enable: func(cfg *SDWANConfig) {
				cfg.HardwareEnergy = SDWANGroupConfig{Enabled: true, MaxResults: 1}
			},
			specs: []sdwanEndpointSpec{
				{group: "hardware_energy", operation: "hardware.environment", path: "/device/environment", deviceScoped: true},
				{group: "hardware_energy", operation: "hardware.energy", path: "/device/power-consumption", deviceScoped: true},
			},
		},
		{
			name: "routing_services",
			enable: func(cfg *SDWANConfig) {
				cfg.RoutingServices = SDWANGroupConfig{Enabled: true, MaxResults: 1}
			},
			specs: []sdwanEndpointSpec{
				{group: "routing_services", operation: "routing.bgp", path: "/device/bgp/neighbors", deviceScoped: true},
				{group: "routing_services", operation: "routing.routes", path: "/device/ip/routes", deviceScoped: true},
			},
		},
		{
			name: "branch_services",
			enable: func(cfg *SDWANConfig) {
				cfg.BranchServices = SDWANGroupConfig{Enabled: true, MaxResults: 1}
			},
			specs: []sdwanEndpointSpec{
				{group: "branch_services", operation: "branch.wlan", path: "/device/wlan/clients", deviceScoped: true},
				{group: "branch_services", operation: "branch.voice", path: "/device/voice/calls", deviceScoped: true},
			},
		},
		{
			name: "lifecycle_compliance",
			enable: func(cfg *SDWANConfig) {
				cfg.LifecycleCompliance = SDWANGroupConfig{Enabled: true, MaxResults: 1}
			},
			specs: []sdwanEndpointSpec{
				{group: "lifecycle_compliance", operation: "lifecycle.reboot", path: "/device/reboot/history", deviceScoped: true},
				{group: "lifecycle_compliance", operation: "lifecycle.crashlog", path: "/device/crashlog/synced", deviceScoped: true},
			},
		},
		{
			name: "thousandeyes",
			enable: func(cfg *SDWANConfig) {
				cfg.ThousandEyes = SDWANGroupConfig{Enabled: true, MaxResults: 1}
			},
			specs: []sdwanEndpointSpec{{group: "thousandeyes", operation: "thousandeyes.agents", path: "/device/thousandeyes/agents", deviceScoped: true}},
		},
		{
			name: "management_security",
			enable: func(cfg *SDWANConfig) {
				cfg.ManagementSecurity = SDWANGroupConfig{Enabled: true, MaxResults: 1}
			},
			specs: []sdwanEndpointSpec{
				{group: "management_security", operation: "management.users", path: "/admin/user"},
				{group: "management_security", operation: "management.sessions", path: "/admin/user/activeSessions"},
			},
		},
	}
	require.Len(t, tests, 16, "keep this table aligned with the public SD-WAN opt-in groups")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requestsMu sync.Mutex
			requests := make([]sdwanProductRequest, 0, len(tt.specs))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "Bearer token", r.Header.Get("Authorization"))
				requestsMu.Lock()
				requests = append(requests, sdwanProductRequest{
					method:   r.Method,
					path:     r.URL.Path,
					deviceID: r.URL.Query().Get("deviceId"),
				})
				requestsMu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"data":[{"id":"object-1","state":"up","system-ip":"10.0.0.1"}]}`))
			}))
			defer server.Close()

			receiver := newTestSDWANReceiver(t, server.URL, func(cfg *Config) {
				disableCoreSDWANGroups(&cfg.SDWAN)
				cfg.SDWAN.MaxRetries = 0
				cfg.SDWAN.Targets.SystemIPs = []string{"10.0.0.1"}
				tt.enable(&cfg.SDWAN)
			})

			enabled := make([]sdwanOptInGroup, 0, 1)
			for _, group := range sdwanOptInGroups(receiver.config.SDWAN) {
				if group.config.Enabled {
					enabled = append(enabled, group)
				}
			}
			require.Len(t, enabled, 1)
			assert.Equal(t, tt.name, enabled[0].name)
			assert.Equal(t, tt.specs, enabled[0].specs)

			md, err := receiver.scrape(t.Context())
			require.NoError(t, err)

			requestsMu.Lock()
			gotRequests := append([]sdwanProductRequest(nil), requests...)
			requestsMu.Unlock()
			require.Len(t, gotRequests, len(tt.specs))
			for _, spec := range tt.specs {
				wantDeviceID := ""
				if spec.deviceScoped {
					wantDeviceID = "10.0.0.1"
				}
				assert.Contains(t, gotRequests, sdwanProductRequest{
					method:   http.MethodGet,
					path:     "/dataservice" + spec.path,
					deviceID: wantDeviceID,
				})
				assert.True(t, hasMetricDatapointAttribute(md, "sdwan.resource.status", "sdwan.collection.operation", spec.operation))
			}
			assert.Equal(t, len(tt.specs), metricDataPointCount(md, "sdwan.resource.status"))
			assert.Equal(t, 2*len(tt.specs), metricDataPointCount(md, "sdwan.collection.object.count"))
			assert.True(t, intMetricValueExists(md, "sdwan.scrape.partial_success", 0))
		})
	}
}

type sdwanProductRequest struct {
	method   string
	path     string
	deviceID string
}

func disableCoreSDWANGroups(cfg *SDWANConfig) {
	disabled := SDWANGroupConfig{Enabled: false, MaxResults: 1}
	cfg.Manager = disabled
	cfg.Inventory = disabled
	cfg.ControlPlane = disabled
	cfg.BFD = disabled
	cfg.AppRoute = disabled
	cfg.Interfaces = disabled
	cfg.Alarms = disabled
	cfg.Events = disabled
	cfg.Audit = disabled
}
