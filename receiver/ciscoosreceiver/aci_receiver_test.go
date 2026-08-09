// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"maps"
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

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/aci"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestAppendACILogUsesOnlyAllowlistedUserAndTimestampFields(t *testing.T) {
	logs := plog.NewLogs()
	appendACILog(
		logs,
		"apic-1",
		"https://apic.example.test",
		aciEndpoint{group: "audit", operation: "audit.modifications", className: "aaaModLR"},
		aci.Object{
			"modifiedBy": "must-not-leak-modified-by",
			"createdBy":  "must-not-leak-created-by",
			"userName":   "must-not-leak-user-name",
			"modTs":      "2026-05-25T10:00:00Z",
		},
		time.Unix(1_800_000_000, 0),
	)

	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	_, found := record.Attributes().Get("user.name")
	assert.False(t, found)
	assert.Zero(t, record.Timestamp(), "excluded modTs must not become the event timestamp")

	logs = plog.NewLogs()
	appendACILog(
		logs,
		"apic-1",
		"https://apic.example.test",
		aciEndpoint{group: "audit", operation: "audit.modifications", className: "aaaModLR"},
		aci.Object{"user": "operator", "created": "2026-05-25T10:00:00Z"},
		time.Unix(1_800_000_000, 0),
	)
	record = logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	username, found := record.Attributes().Get("user.name")
	require.True(t, found)
	assert.Equal(t, "operator", username.Str())
}

func TestAppendACILogUsesSignalSpecificAllowlistedBodies(t *testing.T) {
	tests := []struct {
		name     string
		endpoint aciEndpoint
		object   aci.Object
		want     map[string]any
	}{
		{
			name:     "fault",
			endpoint: aciEndpoint{group: "faults", operation: "fault.instances"},
			object: aci.Object{
				"aci.class":       "faultInst",
				"code":            "F123",
				"descr":           "Interface errors above threshold",
				"dn":              "topology/pod-1/node-101/sys/ch/fault-F123",
				"lastTransition":  "2026-05-25T10:00:00Z",
				"severity":        "critical",
				"password":        "must-not-leak",
				"unexpectedToken": "must-not-leak",
				"changeSet":       "pwd: must-not-leak",
				"future":          map[string]any{"api_key": "must-not-leak"},
			},
			want: map[string]any{
				"code":           "F123",
				"descr":          "Interface errors above threshold",
				"dn":             "topology/pod-1/node-101/sys/ch/fault-F123",
				"lastTransition": "2026-05-25T10:00:00Z",
				"severity":       "critical",
			},
		},
		{
			name:     "audit",
			endpoint: aciEndpoint{group: "audit", operation: "audit.modifications"},
			object: aci.Object{
				"aci.class": "aaaModLR",
				"affected":  "uni/tn-prod",
				"cause":     "transition",
				"code":      "E4205213",
				"created":   "2026-05-25T10:01:00Z",
				"descr":     "Tenant prod modified",
				"dn":        "subj-[uni/tn-prod]/mod-4294967339",
				"id":        "4294967339",
				"ind":       "modification",
				"severity":  "info",
				"trig":      "config",
				"txId":      "9799832789158202025",
				"user":      "operator",
				"changeSet": "password: must-not-leak",
				"sessionId": "must-not-leak",
				"apiSecret": "must-not-leak",
			},
			want: map[string]any{
				"affected": "uni/tn-prod",
				"cause":    "transition",
				"code":     "E4205213",
				"created":  "2026-05-25T10:01:00Z",
				"descr":    "Tenant prod modified",
				"dn":       "subj-[uni/tn-prod]/mod-4294967339",
				"id":       "4294967339",
				"ind":      "modification",
				"severity": "info",
				"trig":     "config",
				"txId":     "9799832789158202025",
				"user":     "operator",
			},
		},
		{
			name:     "event",
			endpoint: aciEndpoint{group: "events", operation: "events.records"},
			object: aci.Object{
				"aci.class":    "eventRecord",
				"affected":     "topology/pod-1/lnkcnt-1/lnk-101-1-1-to-1-1-3",
				"cause":        "link-state-change",
				"code":         "E4208219",
				"created":      "2026-05-25T10:02:00Z",
				"descr":        "Link state changed",
				"dn":           "subj-[topology/pod-1/lnkcnt-1]/rec-4294968577",
				"id":           "4294968577",
				"ind":          "state-transition",
				"severity":     "warning",
				"trig":         "oper",
				"txId":         "1729382256910270971",
				"user":         "internal",
				"privateKey":   "must-not-leak",
				"unknownField": "must-not-leak",
				"status":       []any{"malformed", map[string]any{"token": "must-not-leak"}},
			},
			want: map[string]any{
				"affected": "topology/pod-1/lnkcnt-1/lnk-101-1-1-to-1-1-3",
				"cause":    "link-state-change",
				"code":     "E4208219",
				"created":  "2026-05-25T10:02:00Z",
				"descr":    "Link state changed",
				"dn":       "subj-[topology/pod-1/lnkcnt-1]/rec-4294968577",
				"id":       "4294968577",
				"ind":      "state-transition",
				"severity": "warning",
				"trig":     "oper",
				"txId":     "1729382256910270971",
				"user":     "internal",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := plog.NewLogs()
			appendACILog(logs, "apic-1", "https://apic.example.test", tt.endpoint, tt.object, time.Unix(1_800_000_000, 0))

			record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			assert.Equal(t, tt.want, record.Body().Map().AsRaw())
		})
	}
}

func TestAppendACILogSanitizesCompleteExportedRecord(t *testing.T) {
	logs := plog.NewLogs()
	appendACILog(
		logs,
		"apic-1",
		"https://apic.example.test",
		aciEndpoint{group: "audit", operation: "audit.modifications", className: "aaaModLR"},
		aci.Object{
			"affected":   "uni/tn-prod",
			"dn":         "subj-[uni/tn-prod]/mod-4294967339",
			"id":         "4294967339",
			"severity":   "info",
			"status":     "created",
			"txId":       "9799832789158202025",
			"user":       "operator",
			"aci.class":  "must-not-leak-class",
			"name":       "must-not-leak-name",
			"serial":     "must-not-leak-serial",
			"nodeId":     "must-not-leak-node-id",
			"fabricName": "must-not-leak-fabric",
			"userName":   "must-not-leak-user-name",
			"createdBy":  "must-not-leak-created-by",
			"modifiedBy": "must-not-leak-modified-by",
			"operSt":     "must-not-leak-oper-status",
			"type":       "must-not-leak-type",
			"modTs":      "2026-05-25T10:00:00Z",
			"changeSet":  "password: must-not-leak-change-set",
			"future": map[string]any{
				"apiSecret": "must-not-leak-nested-secret",
				"items":     []any{"must-not-leak-nested-item"},
			},
		},
		time.Unix(1_800_000_000, 0),
	)

	resourceLogs := logs.ResourceLogs().At(0)
	record := resourceLogs.ScopeLogs().At(0).LogRecords().At(0)
	exported := map[string]any{
		"body":                record.Body().AsRaw(),
		"resource_attributes": resourceLogs.Resource().Attributes().AsRaw(),
		"record_attributes":   record.Attributes().AsRaw(),
	}
	assertACIValueDoesNotContain(t, exported, "must-not-leak")

	className, found := resourceLogs.Resource().Attributes().Get("aci.class")
	require.True(t, found)
	assert.Equal(t, "aaaModLR", className.Str())
	_, found = resourceLogs.Resource().Attributes().Get("cisco.switch.serial")
	assert.False(t, found)
	username, found := record.Attributes().Get("user.name")
	require.True(t, found)
	assert.Equal(t, "operator", username.Str())
	assert.Equal(t, "info", record.SeverityText())
	status, found := record.Attributes().Get("aci.status")
	require.True(t, found)
	assert.Equal(t, "created", status.Str())
	assert.Zero(t, record.Timestamp(), "excluded timestamps must not affect the exported record")
}

func TestACILogDedupUsesStableAllowlistedIdentityAndControllerScope(t *testing.T) {
	receiver := &aciLogsReceiver{seen: newLogDeduplicator()}
	endpoint := aciEndpoint{group: "audit", operation: "audit.modifications", className: "aaaModLR"}
	controllerEndpoint := "https://apic-1.example.test"
	base := aci.Object{
		"affected": "uni/tn-prod",
		"code":     "E4205213",
		"created":  "2026-05-25T10:01:00Z",
		"descr":    "Tenant prod modified",
		"txId":     "9799832789158202025",
		"user":     "operator",
	}
	now := time.Unix(1_800_000_000, 0)
	receiver.seen.BeginBatch()

	first := maps.Clone(base)
	first["id"] = "4294967339"
	first["dn"] = "subj-[uni/tn-prod]/mod-4294967339"
	first["password"] = "first-secret"
	assert.False(t, receiver.seenBefore("apic-1", controllerEndpoint, endpoint, first, now))

	replica := maps.Clone(base)
	replica["id"] = "8589934635"
	replica["dn"] = "subj-[uni/tn-prod]/mod-8589934635"
	replica["password"] = "different-secret"
	assert.True(t, receiver.seenBefore("apic-1", controllerEndpoint, endpoint, replica, now), "APIC replica-local IDs and excluded fields must not change audit identity")

	transition := maps.Clone(replica)
	transition["descr"] = "Tenant prod deleted"
	assert.False(t, receiver.seenBefore("apic-1", controllerEndpoint, endpoint, transition, now), "an exported operational change must remain eligible")

	assert.False(t, receiver.seenBefore("apic-2", "https://apic-2.example.test", endpoint, replica, now), "dedup must remain controller-scoped without a safe logical-fabric identity")
}

func TestACILogDedupHashesCompleteSanitizedEmittedContent(t *testing.T) {
	endpoint := aciEndpoint{group: "events", operation: "events.records", className: "eventRecord"}
	base := sanitizeACILog(
		"apic-1",
		"https://apic-1.example.test",
		endpoint,
		aci.Object{
			"affected": "topology/pod-1/node-101",
			"created":  "2026-05-25T10:02:00Z",
			"descr":    "Link state changed",
			"dn":       "subj-[topology/pod-1/node-101]/rec-4294968577",
			"id":       "4294968577",
			"severity": "warning",
			"status":   "created",
			"user":     "operator",
		},
	)
	keyFor := func(record aciSanitizedLog) string {
		stableID, content := aciLogDedupIdentity(endpoint, record)
		return logDedupKey("apic-1\x00https://apic-1.example.test\x00events.records", stableID, content)
	}
	baseKey := keyFor(base)

	tests := []struct {
		name   string
		mutate func(*aciSanitizedLog)
	}{
		{name: "body", mutate: func(record *aciSanitizedLog) { record.Body["descr"] = "Link state cleared" }},
		{name: "resource attributes", mutate: func(record *aciSanitizedLog) { record.ResourceAttributes["host.name"] = "other-host" }},
		{name: "record attributes", mutate: func(record *aciSanitizedLog) { record.RecordAttributes["aci.status"] = "deleted" }},
		{name: "event timestamp", mutate: func(record *aciSanitizedLog) { record.Timestamp++ }},
		{name: "severity text", mutate: func(record *aciSanitizedLog) { record.SeverityText = "error" }},
		{name: "severity number", mutate: func(record *aciSanitizedLog) { record.SeverityNumber = plog.SeverityNumberError }},
		{name: "scope", mutate: func(record *aciSanitizedLog) { record.ScopeName = "other-scope" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := cloneACISanitizedLog(base)
			tt.mutate(&changed)
			assert.NotEqual(t, baseKey, keyFor(changed))
		})
	}
}

func TestACIScrapeEmitsTroubleshootingMetrics(t *testing.T) {
	server := newACIFixtureServer(t, map[string]string{
		"/api/class/fabricNode.json": `{"totalCount":"1","imdata":[
			{"fabricNode":{"attributes":{"dn":"topology/pod-1/node-101","id":"101","serial":"ACI-SERIAL-1","name":"leaf101","role":"leaf","fabricSt":"active","model":"N9K-C93180YC-FX3","version":"15.2(8)"}}}
		]}`,
		"/api/class/faultInst.json": `{"totalCount":"1","imdata":[
			{"faultInst":{"attributes":{"dn":"topology/pod-1/node-101/sys/ch/fault-F123","code":"F123","severity":"critical","lc":"raised","domain":"infra","descr":"Interface errors above threshold","lastTransition":"2026-05-25T10:00:00Z"}}}
		]}`,
		"/api/class/l1PhysIf.json": `{"totalCount":"1","imdata":[
			{"l1PhysIf":{"attributes":{"dn":"topology/pod-1/node-101/sys/phys-[eth1/1]","id":"eth1/1","operSt":"up","speed":"100G"}}}
		]}`,
		"/api/class/fvCEp.json": `{"totalCount":"1","imdata":[
			{"fvCEp":{"attributes":{"dn":"uni/tn-prod/ap-app/epg-web/cep-00:11:22:33:44:55","mac":"00:11:22:33:44:55","ip":"10.1.1.10","lcC":"learned"}}}
		]}`,
		"/api/class/fvTenant.json": `{"totalCount":"1","imdata":[
			{"fvTenant":{"attributes":{"dn":"uni/tn-prod","name":"prod","status":"created"}}}
		]}`,
		"/api/class/aaaModLR.json": `{"totalCount":"1","imdata":[
			{"aaaModLR":{"attributes":{"dn":"uni/tn-prod","severity":"info","status":"modified","user":"operator","descr":"tenant changed"}}}
		]}`,
		"/api/class/eventRecord.json": `{"totalCount":"1","imdata":[
			{"eventRecord":{"attributes":{"dn":"topology/pod-1/node-101","severity":"warning","status":"raised","descr":"link flap"}}}
		]}`,
	})
	defer server.Close()

	receiver := newTestACIMetricsReceiver(t, server.URL)
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	names := metricNames(md)
	assert.Contains(t, names, "aci.api.request.duration")
	assert.Contains(t, names, "aci.resource.info")
	assert.Contains(t, names, "aci.audit.record.count")
	assert.Contains(t, names, "aci.event.count")
	assert.Contains(t, names, "cisco.device.up")
	assert.Contains(t, names, "aci.fault.active")
	assert.Contains(t, names, "system.network.interface.status")
	assert.Contains(t, names, "aci.endpoint.present")
	assert.Contains(t, names, "aci.tenant.status")
	assert.True(t, hasResourceHostID(md, "ACI-SERIAL-1"))
	assert.True(t, intMetricValueExists(md, "aci.scrape.partial_success", 0))
	assert.True(t, intMetricValueExists(md, "aci.audit.record.count", 1))
	assert.True(t, intMetricValueExists(md, "aci.event.count", 1))
	assert.True(t, hasMetricDatapointAttribute(md, "aci.audit.record.count", "aci.operation", "audit.modifications"))
	assert.False(t, hasMetricDatapointAttribute(md, "aci.audit.record.count", "user.name", "operator"))
}

func TestACIScrapeReportsConfiguredPaginationTruncation(t *testing.T) {
	server := newACIFixtureServer(t, map[string]string{
		"/api/class/fabricNode.json": `{"totalCount":"3","imdata":[
			{"fabricNode":{"attributes":{"dn":"topology/pod-1/node-101","id":"101","serial":"ACI-SERIAL-1","name":"leaf101","fabricSt":"active"}}},
			{"fabricNode":{"attributes":{"dn":"topology/pod-1/node-102","id":"102","serial":"ACI-SERIAL-2","name":"leaf102","fabricSt":"active"}}}
		]}`,
	})
	defer server.Close()

	receiver := newTestACIMetricsReceiver(t, server.URL)
	receiver.config.ACI.Nodes.MaxResults = 2
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, hasResourceHostID(md, "ACI-SERIAL-1"), "partial results must remain observable")
	assert.True(t, hasResourceHostID(md, "ACI-SERIAL-2"), "partial results must remain observable")
	assert.True(t, intMetricValueExists(md, "aci.scrape.partial_success", 1))
	errorMetric := requireMetricByName(t, md, "aci.api.endpoint.error")
	require.Equal(t, pmetric.MetricTypeSum, errorMetric.Type())
	require.Equal(t, 1, errorMetric.Sum().DataPoints().Len())
	assert.True(t, aciTestAttrsMatch(errorMetric.Sum().DataPoints().At(0).Attributes(), map[string]string{
		"aci.api.operation": "fabric.nodes",
		"aci.error.kind":    "pagination_limit",
	}))
}

func TestClassifyACIErrorRecognizesPaginationLimits(t *testing.T) {
	for _, err := range []error{
		httpclient.NewConfiguredPaginationLimitError("events.records", "result", 1000, 1000),
		httpclient.NewPaginationLimitError("events.records", "page", 100, 1000),
	} {
		assert.Equal(t, "pagination_limit", classifyACIError(err))
	}
}

func TestACIScrapeAppliesSharedDeviceSelection(t *testing.T) {
	server := newACIFixtureServer(t, map[string]string{
		"/api/class/fabricNode.json": `{"totalCount":"2","imdata":[
			{"fabricNode":{"attributes":{"dn":"topology/pod-1/node-101","id":"101","serial":"ACI-SERIAL-1","name":"leaf101","fabricSt":"active"}}},
			{"fabricNode":{"attributes":{"dn":"topology/pod-1/node-909","id":"909","serial":"ACI-SERIAL-9","name":"leaf909","fabricSt":"active"}}}
		]}`,
	})
	defer server.Close()

	receiver := newTestACIMetricsReceiver(t, server.URL)
	receiver.config.ACI.Targets.NodeIDs = []string{"101", "909"}
	receiver.config.ACI.Targets.Serials = []string{"ACI-SERIAL-1", "ACI-SERIAL-9"}
	receiver.config.DeviceSelection.Include.Serials = []string{"ACI-SERIAL-1"}
	receiver.config.DeviceSelection.Exclude.Serials = []string{"ACI-SERIAL-9"}
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, hasResourceHostID(md, "ACI-SERIAL-1"))
	assert.False(t, hasResourceHostID(md, "ACI-SERIAL-9"))
}

func TestACIScrapeKeepsAggregateHealthWithDeviceSelection(t *testing.T) {
	server := newACIFixtureServer(t, map[string]string{
		"/api/class/topSystem.json": `{"totalCount":"1","imdata":[
			{"topSystem":{"attributes":{"id":"controller-1","name":"apic-1","state":"in-service"}}}
		]}`,
		"/api/class/firmwareCtrlrRunning.json": `{"totalCount":"1","imdata":[
			{"firmwareCtrlrRunning":{"attributes":{"dn":"topology/pod-1/node-1/sys/ctrlrfwstatuscont/ctrlrrunning","version":"6.1(2)"}}}
		]}`,
		"/api/class/fabricPod.json": `{"totalCount":"1","imdata":[
			{"fabricPod":{"attributes":{"dn":"topology/pod-1","id":"1","name":"pod-1"}}}
		]}`,
		"/api/class/fabricHealthTotal.json": `{"totalCount":"1","imdata":[
			{"fabricHealthTotal":{"attributes":{"dn":"topology/health","cur":"95"}}}
		]}`,
		"/api/class/fabricOverallHealthHist5min.json": `{"totalCount":"1","imdata":[
			{"fabricOverallHealthHist5min":{"attributes":{"dn":"uni/fabric/overallhealth5min-0","index":"0","healthAvg":"94"}}}
		]}`,
		"/api/class/fabricNode.json": `{"totalCount":"2","imdata":[
			{"fabricNode":{"attributes":{"dn":"topology/pod-1/node-101","id":"101","serial":"ACI-SERIAL-1","name":"leaf101","fabricSt":"active"}}},
			{"fabricNode":{"attributes":{"dn":"topology/pod-1/node-909","id":"909","serial":"ACI-SERIAL-9","name":"leaf909","fabricSt":"active"}}}
		]}`,
	})
	defer server.Close()

	receiver := newTestACIMetricsReceiver(t, server.URL)
	receiver.config.ACI.Targets = ACITargetFilters{NodeIDs: []string{"101"}}
	receiver.config.DeviceSelection.Include.DeviceIDs = []string{"101"}
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	for _, resourceType := range []string{"aci.controller", "aci.controller_firmware", "aci.pod", "aci.fabric_health"} {
		assert.True(t, hasMetricDatapointAttribute(md, "aci.resource.info", "aci.resource.type", resourceType), resourceType)
	}
	assert.Equal(t, 2, metricDataPointCount(md, "aci.fabric.health"))
	assert.True(t, hasResourceHostID(md, "ACI-SERIAL-1"))
	assert.False(t, hasResourceHostID(md, "ACI-SERIAL-9"))
}

func TestACIInterfaceResourcesRetainOwnDNRegardlessInputOrder(t *testing.T) {
	endpoint := aciEndpoint{
		group:      "stats",
		operation:  "stats.interfaces.ingress",
		className:  "eqptIngrTotal5min",
		objectType: "aci.interface",
	}
	objects := []aci.Object{
		{
			"aci.class": "eqptIngrTotal5min",
			"dn":        "topology/pod-1/node-101/sys/phys-[eth1/1]/ingrTotal5min",
			"id":        "eth1/1",
			"bytesRate": float64(125),
		},
		{
			"aci.class": "eqptIngrTotal5min",
			"dn":        "topology/pod-1/node-101/sys/phys-[eth1/2]/ingrTotal5min",
			"id":        "eth1/2",
			"bytesRate": float64(250),
		},
	}
	want := map[string]string{
		"eth1/1": "topology/pod-1/node-101/sys/phys-[eth1/1]/ingrTotal5min",
		"eth1/2": "topology/pod-1/node-101/sys/phys-[eth1/2]/ingrTotal5min",
	}

	for _, tc := range []struct {
		name  string
		order []int
	}{
		{name: "forward", order: []int{0, 1}},
		{name: "reverse", order: []int{1, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builder := newACIMetricsBuilder(time.Now(), "test", nil)
			for _, index := range tc.order {
				builder.recordObject("apic-1", "https://apic.example", endpoint, objects[index])
			}

			md := builder.emit()
			require.Equal(t, 2, md.ResourceMetrics().Len(), "each interface must have an isolated resource")
			got := make(map[string]string, 2)
			for i := 0; i < md.ResourceMetrics().Len(); i++ {
				rm := md.ResourceMetrics().At(i)
				assert.Equal(t, "101", requireACIStringAttr(t, rm.Resource().Attributes(), "host.id"), "interface resources must retain node host identity")
				dn := requireACIStringAttr(t, rm.Resource().Attributes(), "aci.dn")
				metrics := rm.ScopeMetrics().At(0).Metrics()
				for j := 0; j < metrics.Len(); j++ {
					metric := metrics.At(j)
					if metric.Name() != "cisco.interface.io.rate" {
						continue
					}
					require.Equal(t, 1, metric.Gauge().DataPoints().Len())
					ifName := requireACIStringAttr(t, metric.Gauge().DataPoints().At(0).Attributes(), "network.interface.name")
					got[ifName] = dn
				}
			}
			assert.Equal(t, want, got)
		})
	}
}

func TestACILogsApplySharedDeviceSelection(t *testing.T) {
	server := newACIFixtureServer(t, map[string]string{
		"/api/class/faultInst.json": `{"totalCount":"2","imdata":[
			{"faultInst":{"attributes":{"dn":"topology/pod-1/node-101/sys/ch/fault-F123","code":"F123","severity":"critical","lc":"raised","descr":"Interface errors"}}},
			{"faultInst":{"attributes":{"dn":"topology/pod-1/node-909/sys/ch/fault-F999","code":"F999","severity":"critical","lc":"raised","descr":"Interface errors"}}}
		]}`,
	})
	defer server.Close()

	receiver := newTestACILogsReceiver(t, server.URL)
	receiver.config.ACI.Targets.NodeIDs = []string{"101", "909"}
	receiver.config.DeviceSelection.Include.DeviceIDs = []string{"101"}
	receiver.config.DeviceSelection.Exclude.DeviceIDs = []string{"909"}
	ld, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.Equal(t, 1, ld.LogRecordCount())
	assert.True(t, hasLogResourceAttribute(ld, "101"))
	assert.False(t, hasLogResourceAttribute(ld, "909"))
}

func TestACIObjectFiltersApplyBeforeResultLimit(t *testing.T) {
	tests := []struct {
		name            string
		className       string
		firstPage       string
		secondPage      string
		targets         ACITargetFilters
		deviceSelection DeviceSelectionConfig
		wantID          string
	}{
		{
			name:       "node target beyond first raw result",
			className:  "fabricNode",
			firstPage:  `{"totalCount":"2","imdata":[{"fabricNode":{"attributes":{"dn":"topology/pod-1/node-1010","id":"1010"}}}]}`,
			secondPage: `{"totalCount":"2","imdata":[{"fabricNode":{"attributes":{"dn":"topology/pod-1/node-101","id":"101"}}}]}`,
			targets:    ACITargetFilters{NodeIDs: []string{"101"}},
			wantID:     "101",
		},
		{
			name:       "interface target beyond prefix lookalike",
			className:  "l1PhysIf",
			firstPage:  `{"totalCount":"2","imdata":[{"l1PhysIf":{"attributes":{"dn":"topology/pod-1/node-101/sys/phys-[eth1/10]","id":"eth1/10"}}}]}`,
			secondPage: `{"totalCount":"2","imdata":[{"l1PhysIf":{"attributes":{"dn":"topology/pod-1/node-101/sys/phys-[eth1/1]","id":"eth1/1"}}}]}`,
			targets:    ACITargetFilters{InterfaceNames: []string{"ETH1/1"}},
			wantID:     "eth1/1",
		},
		{
			name:       "shared device selection beyond first target match",
			className:  "fabricNode",
			firstPage:  `{"totalCount":"2","imdata":[{"fabricNode":{"attributes":{"dn":"topology/pod-1/node-909","id":"909"}}}]}`,
			secondPage: `{"totalCount":"2","imdata":[{"fabricNode":{"attributes":{"dn":"topology/pod-1/node-101","id":"101"}}}]}`,
			targets:    ACITargetFilters{NodeIDs: []string{"909", "101"}},
			deviceSelection: DeviceSelectionConfig{
				Include: DeviceSelectionMatchConfig{DeviceIDs: []string{"101"}},
			},
			wantID: "101",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/aaaLogin.json" {
					_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token","refreshTimeoutSeconds":"600"}}}]}`))
					return
				}
				assert.Equal(t, "/api/class/"+tc.className+".json", r.URL.Path)
				assert.Equal(t, "1", r.URL.Query().Get("page-size"))
				requests++
				switch r.URL.Query().Get("page") {
				case "0":
					_, _ = w.Write([]byte(tc.firstPage))
				case "1":
					_, _ = w.Write([]byte(tc.secondPage))
				default:
					assert.Fail(t, "unexpected APIC page", r.URL.RawQuery)
					http.Error(w, "unexpected APIC page", http.StatusBadRequest)
				}
			}))
			defer server.Close()

			client, err := aci.NewClient(aci.Config{
				Endpoint:   server.URL,
				Username:   "admin",
				Password:   "password",
				Timeout:    time.Second,
				MaxRetries: 0,
				PageSize:   1,
			})
			require.NoError(t, err)
			include := aciObjectIncludePredicate(tc.targets, newDeviceSelectionMatcher(tc.deviceSelection))

			got, err := client.ListClassFiltered(t.Context(), "test", tc.className, nil, 1, include)
			require.NoError(t, err)
			require.Len(t, got, 1)
			assert.Equal(t, tc.wantID, aci.String(got[0], "id"))
			assert.Equal(t, 2, requests)
		})
	}
}

func TestACILogsAreDisabledByDefaultAndOptInPerSignal(t *testing.T) {
	server := newACIFixtureServer(t, map[string]string{
		"/api/class/faultInst.json": `{"totalCount":"1","imdata":[
			{"faultInst":{"attributes":{"dn":"topology/pod-1/node-101/sys/ch/fault-F123","code":"F123","severity":"critical"}}}
		]}`,
		"/api/class/aaaModLR.json": `{"totalCount":"1","imdata":[
			{"aaaModLR":{"attributes":{"dn":"uni/tn-prod","user":"operator","created":"2026-05-25T10:01:00Z","descr":"tenant changed"}}}
		]}`,
		"/api/class/eventRecord.json": `{"totalCount":"1","imdata":[
			{"eventRecord":{"attributes":{"dn":"topology/pod-1/node-101","severity":"warning","created":"2026-05-25T10:02:00Z"}}}
		]}`,
	})
	defer server.Close()

	cfg := testACIConfig(server.URL)
	receiver, err := newACILogsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, &consumertest.LogsSink{})
	require.NoError(t, err)

	ld, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 0, ld.LogRecordCount())

	receiver.config.ACI.Logs.Audit.Enabled = true
	ld, err = receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1, ld.LogRecordCount())
	assert.True(t, hasLogRecordAttribute(ld, "event.name", "audit.modifications"))
	assert.False(t, hasLogRecordAttribute(ld, "event.name", "fault.instances"))
	assert.False(t, hasLogRecordAttribute(ld, "event.name", "events.records"))
}

func TestACILogsEmitEvidenceAndDeduplicate(t *testing.T) {
	server := newACIFixtureServer(t, map[string]string{
		"/api/class/faultInst.json": `{"totalCount":"1","imdata":[
			{"faultInst":{"attributes":{"dn":"topology/pod-1/node-101/sys/ch/fault-F123","code":"F123","severity":"critical","lc":"raised","descr":"Interface errors above threshold","lastTransition":"2026-05-25T10:00:00Z"}}}
		]}`,
		"/api/class/aaaModLR.json": `{"totalCount":"1","imdata":[
			{"aaaModLR":{"attributes":{"dn":"uni/tn-prod","user":"operator","created":"2026-05-25T10:01:00Z","descr":"tenant changed"}}}
		]}`,
		"/api/class/eventRecord.json": `{"totalCount":"1","imdata":[
			{"eventRecord":{"attributes":{"dn":"topology/pod-1/node-101","severity":"warning","created":"2026-05-25T10:02:00Z","descr":"link flap"}}}
		]}`,
	})
	defer server.Close()

	receiver := newTestACILogsReceiver(t, server.URL)
	ld, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 3, ld.LogRecordCount())
	assert.True(t, hasLogRecordAttribute(ld, "event.name", "fault.instances"))
	assert.True(t, hasLogRecordAttribute(ld, "event.name", "audit.modifications"))
	assert.True(t, hasLogRecordAttribute(ld, "event.name", "events.records"))
	assert.True(t, hasLogRecordAttribute(ld, "user.name", "operator"))

	ld, err = receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 0, ld.LogRecordCount())
}

func TestACICollectionDropsCanceledPartialScrapes(t *testing.T) {
	t.Run("metrics", func(t *testing.T) {
		server, blocked := newACICancelAfterDataServer(t, map[string]string{
			"/api/class/topSystem.json": `{"totalCount":"1","imdata":[
				{"topSystem":{"attributes":{"dn":"topology/pod-1/node-101/sys","id":"101","serial":"APIC-SERIAL-1","status":"active"}}}
			]}`,
		}, "/api/class/firmwareCtrlrRunning.json")
		defer server.Close()

		sink := &consumertest.MetricsSink{}
		receiver := newTestACIMetricsReceiver(t, server.URL)
		receiver.config.ACI.Targets = ACITargetFilters{}
		receiver.consumer = sink
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan struct{})
		go func() {
			receiver.collect(ctx)
			close(done)
		}()

		waitForACITestSignal(t, blocked, "metrics scrape did not reach the blocking endpoint")
		cancel()
		waitForACITestSignal(t, done, "metrics collection did not stop after cancellation")
		assert.Empty(t, sink.AllMetrics(), "cancellation must discard metrics built from earlier endpoints")
	})

	t.Run("logs rollback dedup", func(t *testing.T) {
		server, blocked := newACICancelAfterDataServer(t, map[string]string{
			"/api/class/faultInst.json": `{"totalCount":"1","imdata":[
				{"faultInst":{"attributes":{"dn":"topology/pod-1/node-101/sys/ch/fault-F123","code":"F123","severity":"critical","lc":"raised","lastTransition":"2026-05-25T10:00:00Z"}}}
			]}`,
		}, "/api/class/aaaModLR.json")
		defer server.Close()

		sink := &consumertest.LogsSink{}
		receiver := newTestACILogsReceiver(t, server.URL)
		receiver.config.ACI.Targets = ACITargetFilters{}
		receiver.consumer = sink
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan struct{})
		go func() {
			receiver.collect(ctx)
			close(done)
		}()

		waitForACITestSignal(t, blocked, "logs scrape did not reach the blocking endpoint")
		cancel()
		waitForACITestSignal(t, done, "logs collection did not stop after cancellation")
		assert.Empty(t, sink.AllLogs(), "cancellation must discard logs built from earlier endpoints")

		receiver.collect(t.Context())
		require.Len(t, sink.AllLogs(), 1, "the canceled fault must be eligible for replay")
		replayed := sink.AllLogs()[0]
		assert.Equal(t, 1, replayed.LogRecordCount())
		assert.True(t, hasLogRecordAttribute(replayed, "event.name", "fault.instances"))
	})
}

func TestACICatalogCoversTroubleshootingDomains(t *testing.T) {
	groups := map[string]bool{}
	operations := map[string]bool{}
	for _, endpoint := range aciMetricEndpoints() {
		groups[endpoint.group] = true
		operations[endpoint.operation] = true
	}
	for _, endpoint := range aciLogEndpoints() {
		groups[endpoint.group] = true
		operations[endpoint.operation] = true
	}
	for _, group := range []string{"controller_health", "fabric", "nodes", "faults", "audit", "events", "stats", "endpoints", "tenants", "topology"} {
		assert.True(t, groups[group], "missing ACI group %q", group)
	}
	for _, operation := range []string{
		"apic.top_system",
		"fabric.nodes",
		"fault.instances",
		"audit.modifications",
		"events.records",
		"stats.interfaces.l1",
		"stats.interfaces.ingress",
		"stats.interfaces.egress",
		"stats.interfaces.rmon_in",
		"stats.interfaces.rmon_out",
		"endpoints.mac",
		"tenant.tenants",
		"tenant.contracts",
		"topology.lldp",
		"topology.links",
	} {
		assert.True(t, operations[operation], "missing ACI operation %q", operation)
	}
}

func TestInterfaceNameFromACIDNHandlesSlashedInterfaceNames(t *testing.T) {
	assert.Equal(t, "eth1/34", interfaceNameFromACIDN("topology/pod-1/node-202/sys/phys-[eth1/34]/phys"))
	assert.Equal(t, "eth1/1", interfaceNameFromACIDN("topology/pod-1/node-101/sys/phys-[eth1/1]"))
	assert.Equal(t, "po1", interfaceNameFromACIDN("topology/pod-1/node-101/sys/aggr-[po1]/dbgIfIn"))
	assert.Equal(t, "mgmt0", interfaceNameFromACIDN("topology/pod-1/node-101/sys/mgmt-[mgmt0]/dbgIfOut"))
	assert.Equal(t, "eth1/48", interfaceNameFromACIDN("eth1/48"))
}

func TestACITargetFiltersUseExactCanonicalNodeAndInterfaceNames(t *testing.T) {
	t.Run("node ID", func(t *testing.T) {
		objects := []aci.Object{
			{"dn": "topology/pod-1/node-1010", "id": "1010"},
			{"dn": "topology/pod-1/node-101", "id": "101"},
		}
		got := filterACIObjects(objects, ACITargetFilters{NodeIDs: []string{"NODE-101"}})
		require.Len(t, got, 1)
		assert.Equal(t, "101", aci.String(got[0], "id"))
	})

	t.Run("interface name", func(t *testing.T) {
		objects := []aci.Object{
			{"dn": "topology/pod-1/node-101/sys/phys-[eth1/10]", "id": "eth1/10"},
			{"dn": "topology/pod-1/node-101/sys/phys-[eth1/1]", "id": "eth1/1"},
		}
		got := filterACIObjects(objects, ACITargetFilters{InterfaceNames: []string{"ETH1/1"}})
		require.Len(t, got, 1)
		assert.Equal(t, "eth1/1", aci.String(got[0], "id"))
	})
}

func TestACITargetFiltersRequireEveryConfiguredDimension(t *testing.T) {
	filters := ACITargetFilters{
		Sites:          []string{"SITE-A"},
		Fabrics:        []string{"FABRIC-A"},
		NodeIDs:        []string{"NODE-101"},
		Serials:        []string{"SERIAL-101"},
		Tenants:        []string{"PROD"},
		VRFs:           []string{"USER"},
		BridgeDomains:  []string{"WEB-BD"},
		EPGs:           []string{"WEB"},
		InterfaceNames: []string{"ETH1/1"},
	}
	matching := aci.Object{
		"siteName":      "site-a",
		"fabricName":    "fabric-a",
		"nodeId":        "101",
		"serial":        "serial-101",
		"tenant":        "prod",
		"vrf":           "user",
		"bd":            "web-bd",
		"epg":           "web",
		"interfaceName": "eth1/1",
	}

	matcher := newACITargetMatcher(filters)
	assert.True(t, matcher.allows(matching))

	for _, tc := range []struct {
		name  string
		field string
		value string
	}{
		{name: "site", field: "siteName", value: "site-a-secondary"},
		{name: "fabric", field: "fabricName", value: "fabric-a-secondary"},
		{name: "node", field: "nodeId", value: "1010"},
		{name: "serial", field: "serial", value: "serial-101-extra"},
		{name: "tenant", field: "tenant", value: "prod-east"},
		{name: "vrf", field: "vrf", value: "user-services"},
		{name: "bridge domain", field: "bd", value: "web-bd-backup"},
		{name: "EPG", field: "epg", value: "web-api"},
		{name: "interface", field: "interfaceName", value: "eth1/10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obj := make(aci.Object, len(matching))
			maps.Copy(obj, matching)
			obj[tc.field] = tc.value
			assert.False(t, matcher.allows(obj), "a substring match in one dimension must not satisfy the complete target")
		})
	}
}

func TestACITargetFiltersDeriveCanonicalValuesFromAPICFieldsAndDNs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		object  aci.Object
		filters ACITargetFilters
	}{
		{
			name:    "node from topology DN",
			object:  aci.Object{"dn": "topology/pod-1/node-101/sys/procsys/CDprocSysCPU5min"},
			filters: ACITargetFilters{NodeIDs: []string{"node-101"}},
		},
		{
			name:    "fabric node ID field",
			object:  aci.Object{"aci.class": "fabricNode", "id": "101"},
			filters: ACITargetFilters{NodeIDs: []string{"101"}},
		},
		{
			name:    "tenant from DN",
			object:  aci.Object{"dn": "uni/tn-prod/ap-app/epg-web"},
			filters: ACITargetFilters{Tenants: []string{"prod"}},
		},
		{
			name:    "VRF from reference DN",
			object:  aci.Object{"ctxDn": "uni/tn-prod/ctx-user"},
			filters: ACITargetFilters{VRFs: []string{"user"}},
		},
		{
			name:    "bridge domain from class name",
			object:  aci.Object{"aci.class": "fvBD", "name": "web-bd"},
			filters: ACITargetFilters{BridgeDomains: []string{"WEB-BD"}},
		},
		{
			name:    "EPG from DN",
			object:  aci.Object{"dn": "uni/tn-prod/ap-app/epg-web"},
			filters: ACITargetFilters{EPGs: []string{"web"}},
		},
		{
			name:    "interface from physical DN",
			object:  aci.Object{"dn": "topology/pod-1/node-101/sys/phys-[eth1/1]"},
			filters: ACITargetFilters{InterfaceNames: []string{"ETH1/1"}},
		},
		{
			name:    "interface from LLDP DN",
			object:  aci.Object{"dn": "topology/pod-1/node-101/sys/lldp/inst/if-[eth1/1]/adj-1"},
			filters: ACITargetFilters{InterfaceNames: []string{"eth1/1"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, newACITargetMatcher(tc.filters).allows(tc.object))
		})
	}
}

func TestACITargetFiltersDoNotInferSiteFabricOrNodeFromUnrelatedText(t *testing.T) {
	obj := aci.Object{
		"aci.class": "eventRecord",
		"id":        "101",
		"name":      "site-a",
		"descr":     "event in fabric-a for tenant prod",
	}

	assert.False(t, newACITargetMatcher(ACITargetFilters{Sites: []string{"site-a"}}).allows(obj))
	assert.False(t, newACITargetMatcher(ACITargetFilters{Fabrics: []string{"fabric-a"}}).allows(obj))
	assert.False(t, newACITargetMatcher(ACITargetFilters{NodeIDs: []string{"101"}}).allows(obj))
	assert.False(t, newACITargetMatcher(ACITargetFilters{Tenants: []string{"prod"}}).allows(obj))

	obj["siteName"] = "site-a"
	obj["fabricName"] = "fabric-a"
	assert.True(t, newACITargetMatcher(ACITargetFilters{
		Sites:   []string{"SITE-A"},
		Fabrics: []string{"FABRIC-A"},
	}).allows(obj))
}

func TestNodeIDFromACIDN(t *testing.T) {
	assert.Equal(t, "202", nodeIDFromACIDN("topology/pod-1/node-202/sys/procsys/CDprocSysCPU5min"))
	assert.Equal(t, "101", nodeIDFromACIDN("topology/pod-1/node-101/sys/phys-[eth1/1]"))
	assert.Empty(t, nodeIDFromACIDN("uni/tn-prod/ap-app/epg-web"))
}

func TestACIInterfaceRatesUseCanonicalDescriptors(t *testing.T) {
	builder := newACIMetricsBuilder(time.Now(), "test", nil)
	builder.recordStatsObject(builder.globalResource(), aci.Object{
		"dn":        "topology/pod-1/node-101/sys/phys-[eth1/1]",
		"bytesRate": float64(1),
		"pktsRate":  float64(2),
	})

	ioRate := requireMetricByName(t, builder.emit(), "cisco.interface.io.rate")
	assert.Equal(t, "bit/s", ioRate.Unit())
	require.Equal(t, 1, ioRate.Gauge().DataPoints().Len())
	assert.Equal(t, float64(8), ioRate.Gauge().DataPoints().At(0).DoubleValue())

	packetRate := requireMetricByName(t, builder.emit(), "cisco.interface.packet.rate")
	assert.Equal(t, "{packet}/s", packetRate.Unit())
	assert.Equal(t, float64(2), packetRate.Gauge().DataPoints().At(0).DoubleValue())
	assert.NotContains(t, metricNames(builder.emit()), "system.network.packets")
}

func TestACIEquipmentStatsEmitDirectionalRatesAndUtilization(t *testing.T) {
	builder := newACIMetricsBuilder(time.Now(), "test", nil)
	rb := builder.globalResource()
	builder.recordStatsObject(rb, aci.Object{
		"aci.class": "eqptIngrTotal5min",
		"dn":        "topology/pod-1/node-101/sys/phys-[eth1/1]/ingrTotal5min",
		"bytesRate": float64(125),
		"pktsRate":  float64(20),
		"utilLast":  float64(25),
		"utilAvg":   float64(10),
	})
	builder.recordStatsObject(rb, aci.Object{
		"aci.class": "eqptEgrTotal5min",
		"dn":        "topology/pod-1/node-101/sys/aggr-[po1]/egrTotal5min",
		"bytesRate": float64(250),
		"pktsRate":  float64(40),
		"utilAvg":   float64(50),
	})

	md := builder.emit()
	assert.Equal(t, float64(1000), requireGaugeDoubleValueWithAttrs(t, md, "cisco.interface.io.rate", map[string]string{
		"network.io.direction":   "receive",
		"network.interface.name": "eth1/1",
	}))
	assert.Equal(t, float64(2000), requireGaugeDoubleValueWithAttrs(t, md, "cisco.interface.io.rate", map[string]string{
		"network.io.direction":   "transmit",
		"network.interface.name": "po1",
	}))
	assert.Equal(t, float64(20), requireGaugeDoubleValueWithAttrs(t, md, "cisco.interface.packet.rate", map[string]string{
		"network.io.direction": "receive",
	}))
	assert.Equal(t, 0.25, requireGaugeDoubleValueWithAttrs(t, md, "cisco.interface.utilization", map[string]string{
		"network.io.direction": "receive",
	}), "utilLast must take precedence over utilAvg")
	assert.Equal(t, 0.5, requireGaugeDoubleValueWithAttrs(t, md, "cisco.interface.utilization", map[string]string{
		"network.io.direction": "transmit",
	}), "utilAvg must be used when utilLast is absent")
}

func TestACIStatsRejectOutOfRangePercentageRatios(t *testing.T) {
	for _, value := range []any{float64(-1), float64(101), "NaN", "+Inf"} {
		builder := newACIMetricsBuilder(time.Now(), "test", nil)
		builder.recordStatsObject(builder.globalResource(), aci.Object{
			"aci.class": "eqptIngrTotal5min",
			"utilLast":  value,
		})
		builder.recordStatsObject(builder.globalResource(), aci.Object{
			"aci.class": "procSysCPU5min",
			"userLast":  value,
		})
		assert.NotContains(t, metricNames(builder.emit()), "cisco.interface.utilization")
		assert.NotContains(t, metricNames(builder.emit()), "system.cpu.utilization")
	}
}

func TestACIRMONStatsEmitDirectionalCumulativeCounters(t *testing.T) {
	builder := newACIMetricsBuilder(time.Now(), "test", nil)
	rb := builder.globalResource()
	builder.recordStatsObject(rb, aci.Object{
		"aci.class":     "rmonIfIn",
		"dn":            "topology/pod-1/node-101/sys/phys-[eth1/1]/dbgIfIn",
		"octets":        "1000",
		"ucastPkts":     "100",
		"nUcastPkts":    "20",
		"multicastPkts": "15",
		"broadcastPkts": "5",
		"errors":        "3",
		"discards":      "4",
	})
	builder.recordStatsObject(rb, aci.Object{
		"aci.class":  "rmonIfOut",
		"dn":         "topology/pod-1/node-101/sys/mgmt-[mgmt0]/dbgIfOut",
		"octets":     "2000",
		"ucastPkts":  "200",
		"nUcastPkts": "30",
		"errors":     "6",
		"discards":   "8",
	})

	md := builder.emit()
	assert.Equal(t, int64(1000), requireCumulativeSumIntValueWithAttrs(t, md, "system.network.io", map[string]string{
		"network.io.direction":   "receive",
		"network.interface.name": "eth1/1",
	}))
	assert.Equal(t, int64(2000), requireCumulativeSumIntValueWithAttrs(t, md, "system.network.io", map[string]string{
		"network.io.direction":   "transmit",
		"network.interface.name": "mgmt0",
	}))
	assert.Equal(t, int64(120), requireCumulativeSumIntValueWithAttrs(t, md, "system.network.packet.count", map[string]string{
		"network.io.direction": "receive",
	}), "packet totals must use ucastPkts+nUcastPkts without double-counting multicast/broadcast")
	assert.Equal(t, int64(3), requireCumulativeSumIntValueWithAttrs(t, md, "system.network.errors", map[string]string{
		"network.io.direction": "receive",
	}))
	assert.Equal(t, int64(8), requireCumulativeSumIntValueWithAttrs(t, md, "system.network.packet.dropped", map[string]string{
		"network.io.direction": "transmit",
	}))
}

func TestACIStatsDeriveMemoryRatioFromDocumentedLastValues(t *testing.T) {
	builder := newACIMetricsBuilder(time.Now(), "test", nil)
	rb := builder.globalResource()
	builder.recordStatsObject(rb, aci.Object{
		"aci.class": "procSysMem5min",
		"usedLast":  float64(14915112),
		"totalLast": float64(24499856),
	})
	builder.recordStatsObject(rb, aci.Object{
		"aci.class": "fabricOverallHealthHist5min",
		"healthAvg": float64(88),
	})

	md := builder.emit()
	assert.InDelta(t, 14915112.0/24499856.0, requireGaugeDoubleValueWithAttrs(t, md, "system.memory.utilization", map[string]string{
		"system.memory.state": "used",
	}), 1e-12)
	assert.Equal(t, float64(88), requireGaugeDoubleValueWithAttrs(t, md, "aci.fabric.health", nil))

	legacyBuilder := newACIMetricsBuilder(time.Now(), "test", nil)
	legacyBuilder.recordStatsObject(legacyBuilder.globalResource(), aci.Object{"usedLast": float64(45)})
	assert.NotContains(t, metricNames(legacyBuilder.emit()), "system.memory.utilization")
}

func TestACIStatsDeriveMemoryRatioFromFreeWhenTotalIsAbsent(t *testing.T) {
	builder := newACIMetricsBuilder(time.Now(), "test", nil)
	builder.recordStatsObject(builder.globalResource(), aci.Object{
		"aci.class": "procSysMem5min",
		"usedLast":  float64(75),
		"freeLast":  float64(25),
	})

	assert.Equal(t, 0.75, requireGaugeDoubleValueWithAttrs(t, builder.emit(), "system.memory.utilization", map[string]string{
		"system.memory.state": "used",
	}))
}

func TestACIStatsRejectInvalidMemoryRatioInputs(t *testing.T) {
	for _, tc := range []struct {
		name string
		obj  aci.Object
	}{
		{name: "non-finite used", obj: aci.Object{"usedLast": "NaN", "totalLast": "100"}},
		{name: "non-finite total", obj: aci.Object{"usedLast": "50", "totalLast": "+Inf"}},
		{name: "non-finite free", obj: aci.Object{"usedLast": "50", "freeLast": "+Inf"}},
		{name: "used plus free overflow", obj: aci.Object{"usedLast": "1e308", "freeLast": "1e308"}},
		{name: "negative used", obj: aci.Object{"usedLast": "-1", "totalLast": "100"}},
		{name: "used exceeds total", obj: aci.Object{"usedLast": "101", "totalLast": "100"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builder := newACIMetricsBuilder(time.Now(), "test", nil)
			tc.obj["aci.class"] = "procSysMem5min"
			builder.recordStatsObject(builder.globalResource(), tc.obj)
			assert.NotContains(t, metricNames(builder.emit()), "system.memory.utilization")
		})
	}
}

func TestACIControllerHealthUsesFabricMappings(t *testing.T) {
	builder := newACIMetricsBuilder(time.Now(), "test", nil)
	builder.recordObject("apic-1", "https://apic.example", aciEndpoint{
		group:      "controller_health",
		operation:  "apic.top_system",
		className:  "topSystem",
		objectType: "aci.controller",
	}, aci.Object{
		"aci.class":   "topSystem",
		"id":          "1",
		"serial":      "APIC-SERIAL-1",
		"status":      "active",
		"healthScore": float64(97),
	})

	names := metricNames(builder.emit())
	assert.Contains(t, names, "cisco.device.up")
	assert.Contains(t, names, "aci.fabric.health")
}

func TestACICatalogIncludesDeepInterfaceStatsClasses(t *testing.T) {
	want := map[string]string{
		"eqptIngrTotal5min": "stats.interfaces.ingress",
		"eqptEgrTotal5min":  "stats.interfaces.egress",
		"rmonIfIn":          "stats.interfaces.rmon_in",
		"rmonIfOut":         "stats.interfaces.rmon_out",
	}
	for _, endpoint := range aciMetricEndpoints() {
		operation, ok := want[endpoint.className]
		if !ok {
			continue
		}
		assert.Equal(t, operation, endpoint.operation)
		assert.Equal(t, "stats", endpoint.group)
		assert.Equal(t, "aci.interface", endpoint.objectType)
		delete(want, endpoint.className)
	}
	assert.Empty(t, want, "missing deep interface statistics classes")
}

func TestACIFabricHealthHistoryQueriesOnlyCurrentBucket(t *testing.T) {
	var endpoint aciEndpoint
	for _, candidate := range aciMetricEndpoints() {
		if candidate.className == "fabricOverallHealthHist5min" {
			endpoint = candidate
			break
		}
	}
	require.Equal(t, "stats.fabric_health", endpoint.operation)
	require.NotNil(t, endpoint.query)

	query := aciEndpointQuery(endpoint, &Config{}, time.Now())
	assert.Equal(t, `eq(fabricOverallHealthHist5min.index,"0")`, query.Get("query-target-filter"))
	assert.Len(t, query, 1)
}

func TestACIFabricHealthUsesFirstPresentSynonym(t *testing.T) {
	builder := newACIMetricsBuilder(time.Now(), "test", nil)
	builder.recordFabricObject(builder.globalResource(), aci.Object{
		"cur":         float64(91),
		"health":      float64(82),
		"healthScore": float64(73),
	}, "")

	metric := requireMetricByName(t, builder.emit(), "aci.fabric.health")
	require.Equal(t, 1, metric.Gauge().DataPoints().Len())
	assert.Equal(t, float64(91), metric.Gauge().DataPoints().At(0).DoubleValue())
}

func assertACIValueDoesNotContain(t *testing.T, value any, excluded string) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			assert.NotContains(t, key, excluded)
			assertACIValueDoesNotContain(t, nested, excluded)
		}
	case []any:
		for _, nested := range typed {
			assertACIValueDoesNotContain(t, nested, excluded)
		}
	case string:
		assert.NotContains(t, typed, excluded)
	}
}

func TestACITopologyPreservesLegacyAndGovernedNeighborAttributes(t *testing.T) {
	builder := newACIMetricsBuilder(time.Now(), "test", nil)
	builder.recordTopologyObject(builder.globalResource(), aci.Object{
		"aci.class": "lldpAdjEp",
		"dn":        "topology/pod-1/node-101/sys/lldp/inst/if-[eth1/17]/adj-1",
		"portIdV":   "Ethernet1/18",
		"sysDesc":   "Nexus 9000",
		"mgmtIp":    "192.0.2.102",
	})

	metric := requireMetricByName(t, builder.emit(), "cisco.topology.neighbor.info")
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	assert.Equal(t, "LLDP, CDP, and fabric-link neighbor information.", metric.Description())
	assert.Equal(t, "1", metric.Unit())
	require.Equal(t, 1, metric.Gauge().DataPoints().Len())
	point := metric.Gauge().DataPoints().At(0)
	require.Equal(t, pmetric.NumberDataPointValueTypeInt, point.ValueType())
	assert.Equal(t, int64(1), point.IntValue())

	actual := map[string]string{}
	point.Attributes().Range(func(key string, value pcommon.Value) bool {
		actual[key] = value.AsString()
		return true
	})
	assert.Equal(t, map[string]string{
		"network.peer.name":                 "Ethernet1/18",
		"network.peer.address":              "192.0.2.102",
		"network.protocol.name":             "lldp",
		"cisco.topology.protocol":           "lldp",
		"network.interface.name":            "eth1/17",
		"cisco.topology.neighbor.interface": "Ethernet1/18",
		"cisco.topology.neighbor.platform":  "Nexus 9000",
		"cisco.topology.neighbor.address":   "192.0.2.102",
	}, actual)
}

func TestACITopologyMapsWireCDPNeighborAttributes(t *testing.T) {
	builder := newACIMetricsBuilder(time.Now(), "test", nil)
	builder.recordTopologyObject(builder.globalResource(), aci.Object{
		"aci.class": "cdpAdjEp",
		"dn":        "topology/pod-1/node-101/sys/cdp/inst/if-[eth1/1]/adj-1",
		"devId":     "FE-TOR-S1A.cisco.com",
		"platId":    "cisco WS-C3750G-24TS",
		"portId":    "GigabitEthernet1/0/5",
	})

	metric := requireMetricByName(t, builder.emit(), "cisco.topology.neighbor.info")
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	require.Equal(t, 1, metric.Gauge().DataPoints().Len())
	point := metric.Gauge().DataPoints().At(0)
	assert.Equal(t, int64(1), point.IntValue())

	actual := map[string]string{}
	point.Attributes().Range(func(key string, value pcommon.Value) bool {
		actual[key] = value.AsString()
		return true
	})
	assert.Equal(t, map[string]string{
		"network.peer.name":                 "FE-TOR-S1A.cisco.com",
		"network.protocol.name":             "cdp",
		"cisco.topology.protocol":           "cdp",
		"network.interface.name":            "eth1/1",
		"cisco.topology.neighbor.name":      "FE-TOR-S1A.cisco.com",
		"cisco.topology.neighbor.interface": "GigabitEthernet1/0/5",
		"cisco.topology.neighbor.platform":  "cisco WS-C3750G-24TS",
	}, actual)
}

func requireMetricByName(t *testing.T, md pmetric.Metrics, name string) pmetric.Metric {
	t.Helper()
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		for j := 0; j < md.ResourceMetrics().At(i).ScopeMetrics().Len(); j++ {
			metrics := md.ResourceMetrics().At(i).ScopeMetrics().At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				if metrics.At(k).Name() == name {
					return metrics.At(k)
				}
			}
		}
	}
	require.FailNow(t, "metric not found", name)
	return pmetric.Metric{}
}

func requireGaugeDoubleValueWithAttrs(t *testing.T, md pmetric.Metrics, name string, wantAttrs map[string]string) float64 {
	t.Helper()
	metric := requireMetricByName(t, md, name)
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	points := metric.Gauge().DataPoints()
	for i := 0; i < points.Len(); i++ {
		point := points.At(i)
		if aciTestAttrsMatch(point.Attributes(), wantAttrs) {
			return point.DoubleValue()
		}
	}
	require.FailNow(t, "metric data point not found", "%s attributes: %v", name, wantAttrs)
	return 0
}

func requireCumulativeSumIntValueWithAttrs(t *testing.T, md pmetric.Metrics, name string, wantAttrs map[string]string) int64 {
	t.Helper()
	metric := requireMetricByName(t, md, name)
	require.Equal(t, pmetric.MetricTypeSum, metric.Type())
	require.True(t, metric.Sum().IsMonotonic())
	require.Equal(t, pmetric.AggregationTemporalityCumulative, metric.Sum().AggregationTemporality())
	points := metric.Sum().DataPoints()
	for i := 0; i < points.Len(); i++ {
		point := points.At(i)
		if aciTestAttrsMatch(point.Attributes(), wantAttrs) {
			return point.IntValue()
		}
	}
	require.FailNow(t, "metric data point not found", "%s attributes: %v", name, wantAttrs)
	return 0
}

func aciTestAttrsMatch(attrs pcommon.Map, want map[string]string) bool {
	for key, value := range want {
		actual, ok := attrs.Get(key)
		if !ok || actual.Str() != value {
			return false
		}
	}
	return true
}

func requireACIStringAttr(t *testing.T, attrs pcommon.Map, key string) string {
	t.Helper()
	value, ok := attrs.Get(key)
	require.True(t, ok, "missing attribute %q", key)
	return value.Str()
}

func waitForACITestSignal(t *testing.T, signal <-chan struct{}, failureMessage string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		require.FailNow(t, failureMessage)
	}
}

func newTestACIMetricsReceiver(t *testing.T, endpoint string) *aciMetricsReceiver {
	t.Helper()
	cfg := testACIConfig(endpoint)
	receiver, err := newACIMetricsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)
	return receiver
}

func newTestACILogsReceiver(t *testing.T, endpoint string) *aciLogsReceiver {
	t.Helper()
	cfg := testACIConfig(endpoint)
	enableAllACILogs(&cfg.ACI)
	receiver, err := newACILogsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, &consumertest.LogsSink{})
	require.NoError(t, err)
	return receiver
}

func enableAllACILogs(cfg *ACIConfig) {
	cfg.Logs.Faults.Enabled = true
	cfg.Logs.Audit.Enabled = true
	cfg.Logs.Events.Enabled = true
}

func testACIConfig(endpoint string) *Config {
	cfg := createDefaultConfig().(*Config)
	cfg.ControllerConfig.Timeout = 5 * time.Second
	cfg.ACI = defaultACIConfig()
	cfg.ACI.Enabled = true
	cfg.ACI.Controllers = []ACIControllerConfig{{Endpoint: endpoint, Name: "apic-1"}}
	cfg.ACI.MaxRetries = 1
	cfg.ACI.Auth = ControllerAuthConfig{
		Username: "admin",
		Password: configopaque.String("password"),
	}
	return cfg
}

func newACIFixtureServer(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token","refreshTimeoutSeconds":"600"}}}]}`))
			return
		}
		cookie, err := r.Cookie("APIC-cookie")
		if !assert.NoError(t, err) {
			http.Error(w, "missing authentication cookie", http.StatusUnauthorized)
			return
		}
		assert.Equal(t, "apic-token", cookie.Value)
		if body, ok := routes[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
	}))
}

func newACICancelAfterDataServer(t *testing.T, routes map[string]string, blockingPath string) (*httptest.Server, <-chan struct{}) {
	t.Helper()
	blocked := make(chan struct{})
	var blockOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token","refreshTimeoutSeconds":"600"}}}]}`))
			return
		}
		cookie, err := r.Cookie("APIC-cookie")
		if err != nil || cookie.Value != "apic-token" {
			http.Error(w, "missing authentication cookie", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == blockingPath {
			blockThisRequest := false
			blockOnce.Do(func() {
				blockThisRequest = true
				close(blocked)
			})
			if blockThisRequest {
				select {
				case <-r.Context().Done():
				case <-t.Context().Done():
				}
				return
			}
		}
		if body, ok := routes[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
	}))
	return server, blocked
}
