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
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"

	iseinternal "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/ise"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestISEMetricsReceiverScrapesNetworkDevices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ers/config/networkdevice":
			_, _ = w.Write([]byte(`{"SearchResult":{"total":1,"resources":[{"id":"nad-1","name":"edge-switch-1","ipAddress":"192.0.2.10","status":"enabled"}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := createDefaultConfig().(*Config)
	cfg.ISE.Enabled = true
	cfg.ISE.Endpoint = server.URL
	cfg.ISE.Auth.Username = "admin"
	cfg.ISE.Auth.Password = configopaque.String("password")
	disableISEGroups(&cfg.ISE)
	cfg.ISE.NetworkDevices.Enabled = true

	receiver, err := newISEMetricsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assertISEMetricExists(t, md, "ise.network_device.count")
	assertISEMetricExists(t, md, "ise.api.request.duration")
	assertISEMetricExists(t, md, "ise.scrape.partial_success")
}

func TestISELogsReceiverPreservesRawEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ers/config/networkdevice":
			_, _ = w.Write([]byte(`{"SearchResult":{"total":1,"resources":[{"id":"nad-1","name":"edge-switch-1","ipAddress":"192.0.2.10","status":"enabled"}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := createDefaultConfig().(*Config)
	cfg.ISE.Enabled = true
	cfg.ISE.Endpoint = server.URL
	cfg.ISE.Auth.Username = "admin"
	cfg.ISE.Auth.Password = configopaque.String("password")
	disableISEGroups(&cfg.ISE)
	cfg.ISE.NetworkDevices.Enabled = true

	receiver, err := newISELogsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, &consumertest.LogsSink{})
	require.NoError(t, err)
	ld, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	require.Equal(t, 1, ld.LogRecordCount())
	record := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	assert.Contains(t, record.Body().AsString(), "edge-switch-1")
	domain, ok := record.Attributes().Get("event.domain")
	require.True(t, ok)
	assert.Equal(t, "ise", domain.AsString())
}

func TestISEMetricsReceiverUsesDocumentedMNTSessionPaths(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.EscapedPath())
		switch {
		case r.URL.Path == "/admin/API/mnt/Session/ActiveSessionsList":
			_, _ = w.Write([]byte(`<activeSessionList noOfActiveSession="1"><activeSession><user_name>alice</user_name><calling_station_id>00:11:22:33:44:55</calling_station_id></activeSession></activeSessionList>`))
		case strings.HasPrefix(r.URL.Path, "/admin/API/mnt/Session/AuthSessionsList/"):
			_, _ = w.Write([]byte(`<authSessionList noOfAuthSession="1"><authSession><user_name>bob</user_name><calling_station_id>66:77:88:99:AA:BB</calling_station_id></authSession></authSessionList>`))
		case r.URL.Path == "/admin/API/mnt/Session/ActiveCount" || r.URL.Path == "/admin/API/mnt/Session/PostureCount" || r.URL.Path == "/admin/API/mnt/Session/ProfilerCount":
			_, _ = w.Write([]byte(`<sessionCount><count>1</count></sessionCount>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := createDefaultConfig().(*Config)
	cfg.ISE.Enabled = true
	cfg.ISE.Endpoint = server.URL
	cfg.ISE.Auth.Username = "admin"
	cfg.ISE.Auth.Password = configopaque.String("password")
	disableISEGroups(&cfg.ISE)
	cfg.ISE.Sessions.Enabled = true

	receiver, err := newISEMetricsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assertISEMetricExists(t, md, "ise.session.active.count")
	assertISEMetricExists(t, md, "ise.session.count")
	assert.Contains(t, paths, "/admin/API/mnt/Session/ActiveSessionsList")
	assert.True(t, containsPathPrefix(paths, "/admin/API/mnt/Session/AuthSessionsList/"))
}

func TestISELogsReceiverCollectsWebhookDeliveries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/webhooks":
			_, _ = w.Write([]byte(`{"response":[{"id":"wh-1","name":"ops-webhook"}]}`))
		case "/api/v1/webhooks/wh-1/deliveries":
			_, _ = w.Write([]byte(`{"response":[{"id":"delivery-1","status":"success","httpStatus":200}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := createDefaultConfig().(*Config)
	cfg.ISE.Enabled = true
	cfg.ISE.Endpoint = server.URL
	cfg.ISE.Auth.Username = "admin"
	cfg.ISE.Auth.Password = configopaque.String("password")
	disableISEGroups(&cfg.ISE)
	cfg.ISE.Webhooks.Enabled = true

	receiver, err := newISELogsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, &consumertest.LogsSink{})
	require.NoError(t, err)
	ld, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	require.Equal(t, 2, ld.LogRecordCount())
	eventName, ok := ld.ResourceLogs().At(1).ScopeLogs().At(0).LogRecords().At(0).Attributes().Get("event.name")
	require.True(t, ok)
	assert.Equal(t, "openapi.webhook_deliveries", eventName.AsString())
}

func TestISETargetMatcherAllowsAnyConfiguredTargetFamily(t *testing.T) {
	matcher := newISETargetMatcher(ISETargetFilters{
		NetworkDeviceNames: []string{"edge-switch-1"},
		Usernames:          []string{"alice"},
	})

	assert.True(t, matcher.allows(iseObject("name", "edge-switch-1")))
	assert.True(t, matcher.allows(iseObject("userName", "alice")))
	assert.False(t, matcher.allows(iseObject("name", "unrelated")))
}

func TestISEObjectAttrsDoNotMislabelNamesAsPolicySets(t *testing.T) {
	networkDeviceAttrs := iseObjectAttrs(iseEndpointSpec{group: "network_devices", objectType: "network_device"}, iseinternal.Object{"name": "edge-switch-1"})
	assert.NotContains(t, networkDeviceAttrs, "ise.policy.set")

	policyAttrs := iseObjectAttrs(iseEndpointSpec{group: "policy", objectType: "policy_set"}, iseinternal.Object{"policySetName": "wired-access"})
	assert.Equal(t, "wired-access", policyAttrs["ise.policy.set"])
}

func TestISEEndpointSpecWithPathPreservesPathFuncForErrorMetrics(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.ISE.SessionLookback = 10 * time.Minute
	now := time.Date(2026, 5, 27, 12, 30, 0, 0, time.UTC)

	spec := iseEndpointSpec{operation: "mnt.session.auth_list", pathFunc: iseAuthSessionsListPath}
	resolved := iseEndpointSpecWithPath(cfg, spec, now)

	assert.Equal(t, "/admin/API/mnt/Session/AuthSessionsList/2026-05-27 12:20:00/null", resolved.path)
}

func TestISEDataConnectViewsDeduplicateAndNormalizeOverrides(t *testing.T) {
	cfg := defaultISEConfig()
	cfg.DataConnect.FullViews = true
	cfg.DataConnect.AdditionalReadOnly = []string{"radius_authentications"}
	cfg.DataConnect.Views = map[string]ISEGroupConfig{"radius_authentications_week": {Enabled: true, MaxResults: 123}}

	views := iseDataConnectViews(cfg)

	counts := map[string]int{}
	maxResults := map[string]int{}
	for _, view := range views {
		counts[view.Name]++
		maxResults[view.Name] = view.MaxResults
	}
	assert.Equal(t, 1, counts["RADIUS_AUTHENTICATIONS"])
	assert.Equal(t, 123, maxResults["RADIUS_AUTHENTICATIONS_WEEK"])
}

func TestISEMetricEndpointsIncludeDocumentedISEProductCoverage(t *testing.T) {
	operations := map[string]iseEndpointSpec{}
	for _, spec := range iseMetricEndpoints() {
		operations[spec.operation] = spec
	}

	for _, operation := range []string{
		"openapi.deployment.nodes",
		"openapi.repository",
		"openapi.backup_restore.last_backup_status",
		"openapi.upgrade.summary_status",
		"openapi.patch.list",
		"openapi.rbac.admin_users",
		"openapi.mfa.status",
		"openapi.oidc.configurations",
		"openapi.policy.network_access.authorization_profiles",
		"openapi.policy.device_admin.command_sets",
		"openapi.prometheus_alertmanager.rules",
		"ers.identity_groups",
		"ers.internal_users",
		"ers.authorization_profiles",
		"ers.allowed_protocols",
		"ers.active_directories",
		"ers.ldap",
		"ers.tacacs_external_servers",
		"ers.guest_users",
		"openapi.exim.posture_import_summary",
		"openapi.profiler.endpoint_custom_dictionary",
		"ers.sxp_connections",
		"openapi.trustsec.matrix",
		"openapi.trustsec.virtual_networks",
		"openapi.sgt_reservations",
		"openapi.certificate_signing_requests",
		"openapi.license.connection_type",
		"openapi.pxgrid_cloud.activation_url",
		"openapi.fiveg.subscribers",
		"openapi.endpoint_custom_attributes",
	} {
		spec, ok := operations[operation]
		require.True(t, ok, "missing ISE endpoint coverage for %s", operation)
		assert.NotEmpty(t, spec.group)
		assert.NotEmpty(t, spec.objectType)
		assert.True(t, spec.path != "" || spec.pathFunc != nil, "missing path for %s", operation)
	}
}

func TestISEMetricEndpointsStayReadOnlyAndConcrete(t *testing.T) {
	for _, spec := range iseMetricEndpoints() {
		assert.Contains(t, []iseEndpointMode{iseEndpointGet, iseEndpointList, iseEndpointERSList}, spec.mode, spec.operation)
		if spec.path == "" {
			continue
		}
		assert.NotContains(t, spec.path, "{", spec.operation)
		assert.NotContains(t, spec.path, "}", spec.operation)
		for _, segment := range strings.Split(strings.ToLower(spec.path), "/") {
			assert.NotContains(t, []string{
				"coa",
				"delete",
				"cancel",
				"discard",
				"download",
				"generate",
				"regenerate",
				"renew",
				"bind",
				"trigger",
				"syncnow",
				"test-connector",
				"fetch-new-attributes",
			}, segment, spec.operation)
		}
	}
}

func TestISEMetricObjectAttrsExcludeHighCardinalityIdentityFields(t *testing.T) {
	spec := iseEndpointSpec{group: "sessions", operation: "mnt.session.auth_list", objectType: "auth_session"}
	obj := iseinternal.Object{
		"auditSessionId":     "audit-1",
		"userName":           "alice",
		"calling_station_id": "00:11:22:33:44:55",
		"nas_ip_address":     "192.0.2.10",
		"networkDeviceName":  "edge-switch-1",
		"failureReason":      "invalid password",
	}

	logAttrs := iseObjectAttrs(spec, obj)
	metricAttrs := iseMetricObjectAttrs(spec, obj)

	require.Equal(t, "alice", logAttrs["user.name"])
	require.Equal(t, "00:11:22:33:44:55", logAttrs["ise.endpoint.mac"])
	require.Equal(t, "audit-1", logAttrs["event.id"])
	assert.Equal(t, "invalid password", metricAttrs["ise.failure.reason"])
	assert.NotContains(t, metricAttrs, "user.name")
	assert.NotContains(t, metricAttrs, "ise.endpoint.mac")
	assert.NotContains(t, metricAttrs, "device.mac")
	assert.NotContains(t, metricAttrs, "event.id")
	assert.NotContains(t, metricAttrs, "ise.network_device.name")
	assert.NotContains(t, metricAttrs, "ise.network_device.ip")
}

func TestISEEventEvidenceMetricsUseControllerResource(t *testing.T) {
	builder := newISEMetricsBuilder(time.Unix(1, 0), "https://ise.example")
	builder.recordObject(iseEndpointSpec{group: "sessions", operation: "mnt.session.auth_list", objectType: "auth_session"}, iseinternal.Object{
		"auditSessionId": "audit-1",
		"userName":       "alice",
	})

	md := builder.emit()
	require.Equal(t, 1, md.ResourceMetrics().Len())
	hostID, ok := md.ResourceMetrics().At(0).Resource().Attributes().Get("host.id")
	require.True(t, ok)
	assert.Equal(t, "ise:https://ise.example", hostID.AsString())
}

func TestISEPxGridStreamingLogsDeduplicateMessages(t *testing.T) {
	sink := &consumertest.LogsSink{}
	receiver := &iseLogsReceiver{
		iseConfig: defaultISEConfig(),
		consumer:  sink,
		seen:      map[string]time.Time{},
	}
	message := iseinternal.StompMessage{
		Topic:     "/topic/com.cisco.ise.session",
		MessageID: "message-1",
		Headers:   map[string]string{"message-id": "message-1"},
		Body:      []byte(`{"userName":"alice"}`),
	}

	receiver.consumePxGridMessage(t.Context(), message)
	receiver.consumePxGridMessage(t.Context(), message)

	assert.Equal(t, 1, sink.LogRecordCount())
}

func disableISEGroups(cfg *ISEConfig) {
	cfg.Deployment.Enabled = false
	cfg.NetworkDevices.Enabled = false
	cfg.Endpoints.Enabled = false
	cfg.Sessions.Enabled = false
	cfg.AuthFailures.Enabled = false
	cfg.Accounting.Enabled = false
	cfg.Policy.Enabled = false
	cfg.Posture.Enabled = false
	cfg.Profiler.Enabled = false
	cfg.TrustSec.Enabled = false
	cfg.Alarms.Enabled = false
	cfg.Certificates.Enabled = false
	cfg.Licensing.Enabled = false
	cfg.Webhooks.Enabled = false
	cfg.PxGrid.Enabled = false
	cfg.PxGrid.Streaming = false
	cfg.DataConnect.Enabled = false
}

func assertISEMetricExists(t *testing.T, md pmetric.Metrics, name string) {
	t.Helper()
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		scopeMetrics := md.ResourceMetrics().At(i).ScopeMetrics()
		for j := 0; j < scopeMetrics.Len(); j++ {
			metrics := scopeMetrics.At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				if metrics.At(k).Name() == name {
					return
				}
			}
		}
	}
	t.Fatalf("metric %q not found", name)
}

func containsPathPrefix(paths []string, prefix string) bool {
	for _, path := range paths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func iseObject(key, value string) iseinternal.Object {
	return iseinternal.Object{key: value}
}
