// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"encoding/json"
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

func TestISELogsReceiverPreservesOperationalEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/alarms":
			_, _ = w.Write([]byte(`{"response":[{"id":"alarm-1","name":"Switch link down","severity":"critical"}]}`))
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
	cfg.ISE.Alarms.Enabled = true

	receiver, err := newISELogsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, &consumertest.LogsSink{})
	require.NoError(t, err)
	ld, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	require.Equal(t, 1, ld.LogRecordCount())
	record := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	assert.Contains(t, record.Body().AsString(), "Switch link down")
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
	require.Equal(t, 1, ld.LogRecordCount())
	record := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	eventName, ok := record.Attributes().Get("event.name")
	require.True(t, ok)
	assert.Equal(t, "openapi.webhook_deliveries", eventName.AsString())
	assert.NotContains(t, record.Body().AsString(), "ops-webhook")
}

func TestISEWebhookDeliveriesApplySharedDeviceSelection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/webhooks":
			_, _ = w.Write([]byte(`{"response":[{"id":"wh-1","name":"ops-webhook"}]}`))
		case "/api/v1/webhooks/wh-1/deliveries":
			_, _ = w.Write([]byte(`{"response":[
				{"id":"delivery-denied","status":"failed"},
				{"id":"delivery-allowed","status":"success"}
			]}`))
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
	cfg.DeviceSelection.Exclude.DeviceIDs = []string{"delivery-denied"}

	receiver, err := newISELogsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, &consumertest.LogsSink{})
	require.NoError(t, err)
	ld, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	require.Equal(t, 1, ld.LogRecordCount())
	body := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().AsString()
	assert.Contains(t, body, "delivery-allowed")
	assert.NotContains(t, body, "delivery-denied")
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

func TestISEObjectSelectedAppliesSharedDeviceSelection(t *testing.T) {
	targets := newISETargetMatcher(ISETargetFilters{})
	selector := newDeviceSelectionMatcher(DeviceSelectionConfig{
		Exclude: DeviceSelectionMatchConfig{HostNames: []string{"edge-denied"}},
	})

	assert.False(t, iseObjectSelected(iseinternal.Object{"networkDeviceName": "edge-denied"}, targets, selector))
	assert.True(t, iseObjectSelected(iseinternal.Object{"networkDeviceName": "edge-allowed"}, targets, selector))
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

func TestISEDataConnectLogViewsUseOperationalEvidenceAllowlist(t *testing.T) {
	cfg := defaultISEConfig()
	cfg.DataConnect.FullViews = true
	cfg.DataConnect.AdditionalReadOnly = []string{"CUSTOM_CONFIGURATION_VIEW"}

	views := iseDataConnectLogViews(cfg)
	names := make([]string, 0, len(views))
	for _, view := range views {
		names = append(names, view.Name)
	}
	for _, allowed := range []string{
		"ADMINISTRATOR_LOGINS",
		"RADIUS_AUTHENTICATIONS_WEEK",
		"RADIUS_ACCOUNTING_WEEK",
		"TACACS_AUTHENTICATION_LAST_TWO_DAYS",
		"TACACS_AUTHORIZATION_LAST_TWO_DAYS",
		"TACACS_ACCOUNTING_LAST_TWO_DAYS",
		"TACACS_COMMAND_ACCOUNTING",
		"POSTURE_ASSESSMENT_BY_ENDPOINT",
		"ADAPTIVE_NETWORK_CONTROL",
		"THREAT_EVENTS",
	} {
		assert.Contains(t, names, allowed)
	}
	for _, excluded := range []string{
		"NODE_LIST",
		"NETWORK_DEVICES",
		"NETWORK_DEVICE_GROUPS",
		"POLICY_SETS",
		"OPENAPI_OPERATIONS",
		"ADMIN_USERS",
		"PROFILED_ENDPOINTS_SUMMARY",
		"PROFILING_POLICIES",
		"USER_IDENTITY_GROUPS",
		"CUSTOM_CONFIGURATION_VIEW",
	} {
		assert.NotContains(t, names, excluded)
	}
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

func TestISELogEndpointsUseExplicitEvidenceAllowlist(t *testing.T) {
	expectedOperations := []string{
		"openapi.task_service",
		"ers.support_bundle_status",
		"openapi.backup_restore.last_backup_status",
		"openapi.upgrade.prepare_status",
		"openapi.upgrade.stage_status",
		"openapi.upgrade.proceed_status",
		"openapi.upgrade.summary_status",
		"openapi.patch.prechecks_status",
		"openapi.patch.install_status",
		"openapi.patch.install_summary",
		"openapi.patch.rollback_prechecks_status",
		"openapi.patch.rollback_summary",
		"openapi.patch.rollback_status",
		"ers.rejected_endpoints",
		"mnt.session.active_list",
		"mnt.session.auth_list",
		"openapi.exim.posture_export_status",
		"openapi.exim.posture_import_status",
		"openapi.exim.posture_import_step_status",
		"openapi.exim.posture_import_summary",
		"ers.sgmapping_deploy_status",
		"ers.sgmapping_group_deploy_status",
		"openapi.trustsec.aci_readiness",
		"openapi.trustsec.aci_status",
		"openapi.trustsec.workload_service_status",
		"openapi.alarms",
		"openapi.alarm_instances",
		"openapi.webhooks",
	}

	var actualOperations []string
	for _, spec := range iseLogEndpoints() {
		actualOperations = append(actualOperations, spec.operation)
		assert.NotContains(t, []string{"network_devices", "policy", "certificates"}, spec.group, spec.operation)
	}
	assert.ElementsMatch(t, expectedOperations, actualOperations)

	for _, excluded := range []string{
		"ers.network_devices",
		"ers.network_device_groups",
		"ers.admin_users",
		"ers.internal_users",
		"ers.guest_users",
		"ers.active_directories",
		"ers.ldap",
		"ers.rest_id_stores",
		"openapi.rbac.admin_users",
		"openapi.mfa.configurations",
		"openapi.mfa.status",
		"openapi.oidc.configurations",
		"openapi.policy.network_access",
		"openapi.policy.network_access.identity_stores",
		"openapi.policy.device_admin",
		"openapi.policy.device_admin.identity_stores",
		"ers.system_certificates",
		"openapi.trusted_certificates",
		"openapi.certificate_signing_requests",
	} {
		assert.NotContains(t, actualOperations, excluded)
	}
}

func TestISELogsBuilderRecursivelyRedactsSensitiveRawFields(t *testing.T) {
	obj := iseinternal.Object{
		"id":         "event-1",
		"message":    "keep this evidence",
		"password":   "top-password",
		"passphrase": "top-passphrase",
		"nested": map[string]any{
			"clientSecret": "nested-secret",
			"safe":         "keep nested",
			"items": []any{
				map[string]any{
					"X-API-Key":           "api-key-value",
					"authorizationHeader": "Bearer sensitive",
					"note":                "keep list item",
				},
				iseinternal.Object{
					"private_key_pem": "private-key-value",
					"credentialValue": "credential-value",
					"refreshToken":    "refresh-token-value",
					"passwd":          "passwd-value",
					"pwd":             "pwd-value",
				},
			},
		},
		"headers": map[string]string{
			"authorization": "Basic sensitive",
			"content-type":  "application/json",
		},
	}

	builder := newISELogsBuilder(time.Unix(1, 0), "https://ise.example")
	builder.recordObject(iseEndpointSpec{group: "alarms", operation: "openapi.alarms", objectType: "alarm"}, obj)
	record := builder.emit().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	body := record.Body().AsString()

	assert.JSONEq(t, `{
		"id":"event-1",
		"message":"keep this evidence",
		"password":"[REDACTED]",
		"passphrase":"[REDACTED]",
		"nested":{
			"clientSecret":"[REDACTED]",
			"safe":"keep nested",
			"items":[
				{"X-API-Key":"[REDACTED]","authorizationHeader":"[REDACTED]","note":"keep list item"},
				{"private_key_pem":"[REDACTED]","credentialValue":"[REDACTED]","refreshToken":"[REDACTED]","passwd":"[REDACTED]","pwd":"[REDACTED]"}
			]
		},
		"headers":{"authorization":"[REDACTED]","content-type":"application/json"}
	}`, body)
	for _, secret := range []string{
		"top-password",
		"top-passphrase",
		"nested-secret",
		"api-key-value",
		"Bearer sensitive",
		"private-key-value",
		"credential-value",
		"refresh-token-value",
		"passwd-value",
		"pwd-value",
		"Basic sensitive",
	} {
		assert.NotContains(t, body, secret)
	}
	assert.Equal(t, "top-password", obj["password"], "redaction must not mutate the source object")

	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &decoded))
	assert.Equal(t, "keep this evidence", decoded["message"])
}

func TestISESeenKeyDistinguishesEventsWithSameMessageCode(t *testing.T) {
	spec := iseEndpointSpec{group: "alarms", operation: "openapi.alarms", objectType: "alarm"}
	first := iseinternal.Object{"message_code": "5200", "timestamp": "2026-07-02T10:00:00Z", "message": "first"}
	second := iseinternal.Object{"message_code": "5200", "timestamp": "2026-07-02T10:00:01Z", "message": "second"}

	assert.NotEqual(t, iseSeenKey(spec, first), iseSeenKey(spec, second))
	receiver := &iseLogsReceiver{seen: newLogDeduplicator()}
	assert.True(t, receiver.markSeen(spec, first, time.Unix(1, 0)))
	assert.True(t, receiver.markSeen(spec, second, time.Unix(2, 0)))
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
	builder := newISEMetricsBuilder(time.Unix(1, 0), "https://ise.example", newCounterStore())
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
		seen:      newLogDeduplicator(),
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

func TestISEPxGridStreamingLogsApplySharedDeviceSelection(t *testing.T) {
	sink := &consumertest.LogsSink{}
	cfg := createDefaultConfig().(*Config)
	cfg.DeviceSelection.Exclude.HostNames = []string{"edge-denied"}
	receiver := &iseLogsReceiver{
		config:    cfg,
		iseConfig: defaultISEConfig(),
		consumer:  sink,
		seen:      newLogDeduplicator(),
	}

	receiver.consumePxGridMessage(t.Context(), iseinternal.StompMessage{
		Topic:     "/topic/discovered/session",
		MessageID: "message-denied",
		Body:      []byte(`{"sessions":[{"networkDeviceName":"edge-denied"}]}`),
	})
	receiver.consumePxGridMessage(t.Context(), iseinternal.StompMessage{
		Topic:     "/topic/discovered/session",
		MessageID: "message-allowed",
		Body:      []byte(`{"sessions":[{"networkDeviceName":"edge-allowed"}]}`),
	})

	require.Equal(t, 1, sink.LogRecordCount())
	body := sink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().AsString()
	assert.Contains(t, body, "edge-allowed")
	assert.NotContains(t, body, "edge-denied")
}

func TestISEPxGridQueriesUseDiscoveredServiceSuffixes(t *testing.T) {
	queries := isePxGridRESTQueries(defaultISEConfig(), time.Unix(1, 0))
	require.NotEmpty(t, queries)
	for _, query := range queries {
		assert.NotEmpty(t, query.service, query.operation)
		assert.True(t, strings.HasPrefix(query.path, "/"), query.operation)
		assert.Equal(t, 1, strings.Count(strings.TrimPrefix(query.path, "/"), "/")+1, query.operation)
		assert.NotContains(t, query.path, "/ise/", query.operation)
		assert.NotContains(t, query.path, "/mnt/", query.operation)
	}
}

func TestISEPxGridLogQueriesExcludeConfigurationAndMetricSnapshots(t *testing.T) {
	queries := isePxGridLogQueries(defaultISEConfig(), time.Unix(1, 0))
	operations := make([]string, 0, len(queries))
	for _, query := range queries {
		operations = append(operations, query.operation)
	}
	assert.ElementsMatch(t, []string{
		"pxgrid.session.get_sessions",
		"pxgrid.radius.get_failures",
	}, operations)
	for _, excluded := range []string{
		"pxgrid.session.get_user_groups",
		"pxgrid.system.get_healths",
		"pxgrid.system.get_performances",
		"pxgrid.trustsec.get_security_groups",
		"pxgrid.trustsec.get_sgacls",
		"pxgrid.trustsec.get_egress_policies",
	} {
		assert.NotContains(t, operations, excluded)
	}
}

func TestISEPxGridSubscriptionsUseServiceProperties(t *testing.T) {
	assert.False(t, defaultISEConfig().PxGrid.Subscriptions.SystemHealth, "unsupported System streaming must not be enabled by default")
	subscriptions := isePxGridSubscriptions(ISEPxGridSubscriptionConfig{
		Session:        true,
		RadiusFailures: true,
		Endpoint:       true,
		TrustSec:       true,
		SystemHealth:   true,
	})
	require.Len(t, subscriptions, 5)
	assert.Equal(t, "sessionTopic", subscriptions[0].TopicProperty)
	assert.Equal(t, "failureTopic", subscriptions[1].TopicProperty)
	assert.Equal(t, "topic", subscriptions[2].TopicProperty)
	assert.Equal(t, "securityGroupTopic", subscriptions[3].TopicProperty)
	assert.Contains(t, subscriptions[3].AlternateTopicProperties, "securityGroupAclTopic")
	assert.Empty(t, subscriptions[4].TopicProperty)
	for _, subscription := range subscriptions[:4] {
		assert.NotEmpty(t, subscription.Service)
		assert.NotContains(t, subscription.TopicProperty, "/topic/")
	}
	assert.Equal(t, "com.cisco.ise.system#unsupported", isePxGridSubscriptionLabel(subscriptions[4]))
}

func TestISELogsBuilderUsesSourceTimestampAndCollectionObservedTime(t *testing.T) {
	collectedAt := time.Date(2026, 7, 2, 15, 0, 0, 0, time.UTC)
	sourceTime := time.Date(2026, 7, 2, 14, 59, 30, 123000000, time.UTC)
	builder := newISELogsBuilder(collectedAt, "https://ise.example")
	builder.recordObject(
		iseEndpointSpec{group: "alarms", operation: "openapi.alarms", objectType: "alarm"},
		iseinternal.Object{"id": "alarm-1", "eventTimestamp": sourceTime.Format(time.RFC3339Nano)},
	)

	record := builder.emit().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	assert.Equal(t, sourceTime, record.Timestamp().AsTime())
	assert.Equal(t, collectedAt, record.ObservedTimestamp().AsTime())
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
