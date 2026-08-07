// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/intersight"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestIntersightScrapeEmitsTroubleshootingMetrics(t *testing.T) {
	server := newIntersightFixtureServer(t, map[string]string{
		"/api/v1/asset/DeviceRegistrations": `{"Results":[
			{"Moid":"reg-1","ObjectType":"asset.DeviceRegistration","DeviceHostname":["fi-a"],"DeviceIpAddress":["10.0.0.10"],"Serial":["FDO1234"],"PlatformType":"UCS-FI","ConnectionStatus":"Connected"}
		]}`,
		"/api/v1/compute/PhysicalSummaries": `{"Results":[
			{"Moid":"server-1","ObjectType":"compute.PhysicalSummary","Name":"ucs-server-1","Serial":"SERIAL-1","Model":"UCSX-210C-M7","OperState":"ok","AvailableMemory":262144,"NumCpuCores":64,"FaultSummary":2}
		]}`,
		"/api/v1/cond/Alarms": `{"Results":[
			{"Moid":"alarm-1","ObjectType":"cond.Alarm","AffectedMoDisplayName":"ucs-server-1","AffectedMoId":"server-1","Severity":"Critical","Acknowledge":"None","CreationTime":"2026-05-25T10:00:00Z","Description":"Thermal threshold exceeded"}
		]}`,
		"/api/v1/cond/HclStatuses": `{"Results":[
			{"Moid":"hcl-1","ObjectType":"cond.HclStatus","Name":"ucs-server-1","Serial":"SERIAL-1","Status":"Unsupported"}
		]}`,
		"/api/v1/workflow/TaskInfos": `{"Results":[
			{"Moid":"task-1","ObjectType":"workflow.TaskInfo","Name":"Firmware update","Status":"Failed","FailureReason":"Image download failed","CreateTime":"2026-05-25T10:00:00Z"}
		]}`,
		"/api/v1/storage/PhysicalDisks": `{"Results":[
			{"Moid":"disk-1","ObjectType":"storage.PhysicalDisk","Name":"Disk 1","Serial":"DISK-1","DriveState":"Online","MediaErrorCount":3,"PredictiveFailureCount":1,"PercentLifeLeft":82,"OperatingTemperature":38}
		]}`,
		"/api/v1/hyperflex/Clusters": `{"Results":[
			{"Moid":"hx-1","ObjectType":"hyperflex.Cluster","Name":"hx-prod","ClusterUuid":"hx-prod","Status":"Healthy","VmCount":24,"FltAggr":1}
		]}`,
		"/api/v1/virtualization/VirtualMachines": `{"Results":[
			{"Moid":"vm-1","ObjectType":"virtualization.VirtualMachine","Name":"vm-prod-1","PowerState":"PoweredOn","Cpu":8,"Memory":32768}
		]}`,
		"/api/v1/telemetry/GroupBys": intersightTelemetryFixture(),
	}, nil)
	defer server.Close()

	receiver := newTestIntersightMetricsReceiver(t, server.URL, nil)
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	names := metricNames(md)
	for _, name := range []string{
		"intersight.api.request.duration",
		"intersight.scrape.partial_success",
		"intersight.scrape.last_success",
		"intersight.resource.info",
		"intersight.resource.count",
		"cisco.device.up",
		"system.cpu.logical.count",
		"intersight.compute.available_memory",
		"intersight.alarm.active",
		"intersight.hcl.status",
		"intersight.task.status",
		"intersight.storage.media_error.count",
		"intersight.virtual_machine.count",
		"intersight.virtual_machine.memory",
		"intersight.ucs.fan.speed",
		"intersight.ucs.current",
		"intersight.ucs.memory.ecc.uncorrectable",
		"intersight.ucs.network.receive.crc_errors",
		"intersight.ucs.network.receive.drops",
		"intersight.ucs.network.transmit.errors",
		"intersight.ucs.network.link.status",
		"intersight.ucs.network.interface_resets",
		"intersight.ucs.power_supply.output_power",
		"intersight.ucs.power_supply.status",
		"intersight.ucs.signal_power.receive",
		"intersight.hyperflex.read.iops",
		"intersight.hyperflex.write.iops",
		"intersight.hyperflex.read.latency",
		"intersight.hyperflex.write.latency",
		"intersight.telemetry.query.rows",
	} {
		assert.Contains(t, names, name)
	}
	assert.True(t, hasResourceHostID(md, "SERIAL-1"))
	assert.True(t, hasResourceHostID(md, "FDO1234"))
	assert.True(t, intMetricValueExists(md, "intersight.scrape.partial_success", 0))
	assert.True(t, doubleMetricValueExists(md, "intersight.ucs.fan.speed", 12000))
	assert.True(t, doubleMetricValueExists(md, "intersight.hyperflex.read.iops", 900))
	assert.True(t, doubleMetricValueExists(md, "intersight.hyperflex.write.iops", 700))
	assert.True(t, doubleMetricValueExists(md, "intersight.hyperflex.read.latency", 3.2))
	assert.True(t, doubleMetricValueExists(md, "intersight.hyperflex.write.latency", 4.4))
}

func TestIntersightObjectsWithSharedSerialRemainDistinctByMoid(t *testing.T) {
	builder := newIntersightMetricsBuilder(time.Unix(1_800_000_000, 0), "https://intersight.example.test", nil)
	endpoint := intersightEndpoint{
		group:      "equipment",
		operation:  "equipment.fans",
		objectType: "equipment.Fan",
	}
	for _, moid := range []string{"fan-1", "fan-2"} {
		builder.recordObject(endpoint, intersight.Object{
			"Moid":       moid,
			"ObjectType": "equipment.Fan",
			"Name":       "Fan 1",
			"Serial":     "SHARED-SERIAL",
			"OperState":  "operable",
		})
	}

	md := builder.emit()
	require.Equal(t, 2, md.ResourceMetrics().Len())
	assert.Equal(t, 2, metricNames(md)["intersight.resource.info"])
	fanResources := map[string]string{}
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		attrs := md.ResourceMetrics().At(i).Resource().Attributes()
		resourceType, ok := attrs.Get("intersight.resource.type")
		if !ok || resourceType.Str() != "equipment.Fan" {
			continue
		}
		moid, ok := attrs.Get("intersight.moid")
		require.True(t, ok)
		hostID, ok := attrs.Get("host.id")
		require.True(t, ok)
		fanResources[moid.Str()] = hostID.Str()
	}

	assert.Equal(t, map[string]string{
		"fan-1": "SHARED-SERIAL",
		"fan-2": "SHARED-SERIAL",
	}, fanResources)
}

func TestIntersightMetricsCollectAuditCounts(t *testing.T) {
	server := newIntersightFixtureServer(t, map[string]string{
		"/api/v1/aaa/AuditRecords": `{"Results":[
			{"Moid":"audit-1","ObjectType":"aaa.AuditRecord","UserIdOrEmail":"operator@example.com","CreateTime":"2026-05-25T10:01:00Z"},
			{"Moid":"audit-2","ObjectType":"aaa.AuditRecord","UserIdOrEmail":"operator@example.com","CreateTime":"2026-05-25T10:02:00Z"}
		]}`,
		"/api/v1/telemetry/GroupBys": `[]`,
	}, nil)
	defer server.Close()

	receiver := newTestIntersightMetricsReceiver(t, server.URL, nil)
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, intMetricValueWithAttributesExists(md, "intersight.audit.record.count", 2, map[string]string{
		"intersight.audit.user": "operator@example.com",
	}))
	assert.True(t, hasMetricDatapointAttribute(md, "intersight.api.request.duration", "intersight.api.operation", "aaa.audit_records"))
	assert.True(t, intMetricValueExists(md, "intersight.scrape.partial_success", 0))
}

func TestIntersightScrapeAppliesTargetFilters(t *testing.T) {
	server := newIntersightFixtureServer(t, map[string]string{
		"/api/v1/compute/PhysicalSummaries": `{"Results":[
			{"Moid":"server-1","ObjectType":"compute.PhysicalSummary","Name":"included","Serial":"SERIAL-1","OperState":"ok"},
			{"Moid":"server-2","ObjectType":"compute.PhysicalSummary","Name":"excluded","Serial":"SERIAL-9","OperState":"ok"}
		]}`,
		"/api/v1/telemetry/GroupBys": `[]`,
	}, nil)
	defer server.Close()

	receiver := newTestIntersightMetricsReceiver(t, server.URL, func(cfg *Config) {
		cfg.Intersight.Targets.Serials = []string{"SERIAL-1"}
	})
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, hasResourceHostID(md, "SERIAL-1"))
	assert.False(t, hasResourceHostID(md, "SERIAL-9"))
}

func TestIntersightMetricsPreserveEarlierPagesOnLaterPageFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/compute/PhysicalSummaries" {
			if r.URL.Query().Get("$skip") == "0" {
				_, _ = w.Write([]byte(`{"Results":[
					{"Moid":"server-1","ObjectType":"compute.PhysicalSummary","Name":"first","Serial":"SERIAL-1","OperState":"ok"},
					{"Moid":"server-2","ObjectType":"compute.PhysicalSummary","Name":"second","Serial":"SERIAL-2","OperState":"ok"}
				]}`))
				return
			}
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_, _ = w.Write([]byte(`{"Results":[]}`))
	}))
	defer server.Close()

	receiver := newTestIntersightMetricsReceiver(t, server.URL, nil)
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, hasResourceHostID(md, "SERIAL-1"))
	assert.True(t, hasResourceHostID(md, "SERIAL-2"))
	assert.True(t, intMetricValueExists(md, "intersight.scrape.partial_success", 1))
}

func TestIntersightTelemetryRespectsSharedDeviceSelection(t *testing.T) {
	builder := newIntersightMetricsBuilder(time.Now(), "https://intersight.example.com", newCounterStore())
	selector := newDeviceSelectionMatcher(DeviceSelectionConfig{
		Include: DeviceSelectionMatchConfig{HostNames: []string{"ucs-server-1"}},
		Exclude: DeviceSelectionMatchConfig{DeviceIDs: []string{"excluded-device"}},
	})
	query := intersightTelemetryQuery{
		name:        "fan_speed",
		dataSource:  "PhysicalEntities",
		instrument:  "hw.fan",
		dimensions:  []string{"host.name", "deviceId"},
		fieldName:   "hw.fan.speed-Mean",
		metricName:  "intersight.ucs.fan.speed",
		description: "Mean fan speed from Intersight telemetry.",
		unit:        "1/min",
	}
	response := []any{
		map[string]any{"event": map[string]any{"host.name": "ucs-server-1", "deviceId": "included-device", "hw.fan.speed-Mean": 12000}},
		map[string]any{"event": map[string]any{"host.name": "ucs-server-9", "deviceId": "excluded-device", "hw.fan.speed-Mean": 9000}},
	}

	builder.recordTelemetry(query, response, selector, 0)
	md := builder.emit()

	assert.True(t, hasResourceHostID(md, "ucs-server-1"))
	assert.False(t, hasResourceHostID(md, "ucs-server-9"))
	assert.True(t, doubleMetricValueExists(md, "intersight.ucs.fan.speed", 12000))
	assert.False(t, doubleMetricValueExists(md, "intersight.ucs.fan.speed", 9000))
}

func TestIntersightTelemetryMaxResultsCapsEachQuery(t *testing.T) {
	builder := newIntersightMetricsBuilder(time.Unix(1_800_000_000, 0), "https://intersight.example.test", nil)
	query := intersightTelemetryQuery{
		name:        "fan_speed",
		dataSource:  "PhysicalEntities",
		instrument:  "hw.fan",
		dimensions:  []string{"host.name"},
		fieldName:   "hw.fan.speed-Mean",
		metricName:  "intersight.ucs.fan.speed",
		description: "Mean fan speed from Intersight telemetry.",
		unit:        "1/min",
	}
	response := []any{
		map[string]any{"event": map[string]any{"host.name": "host-1", "hw.fan.speed-Mean": 1000}},
		map[string]any{"event": map[string]any{"host.name": "host-2", "hw.fan.speed-Mean": 2000}},
		map[string]any{"event": map[string]any{"host.name": "host-3", "hw.fan.speed-Mean": 3000}},
	}

	builder.recordTelemetry(query, response, deviceSelectionMatcher{}, 2)
	md := builder.emit()

	assert.Equal(t, 2, metricDataPointCount(md, "intersight.ucs.fan.speed"))
	assert.True(t, intMetricValueWithAttributesExists(md, "intersight.telemetry.query.rows", 2, map[string]string{
		"intersight.telemetry.query":   "fan_speed",
		"intersight.telemetry.outcome": "emitted",
	}))
	assert.True(t, intMetricValueWithAttributesExists(md, "intersight.telemetry.query.rows", 1, map[string]string{
		"intersight.telemetry.query":   "fan_speed",
		"intersight.telemetry.outcome": "max_results",
	}))
}

func TestIntersightTelemetryClassifiesEveryRow(t *testing.T) {
	builder := newIntersightMetricsBuilder(time.Unix(1_800_000_000, 0), "https://intersight.example.test", nil)
	selector := newDeviceSelectionMatcher(DeviceSelectionConfig{
		Include: DeviceSelectionMatchConfig{HostNames: []string{"included"}},
	})
	query := intersightTelemetryQuery{
		name:        "fan_speed",
		dataSource:  "PhysicalEntities",
		instrument:  "hw.fan",
		dimensions:  []string{"host.name"},
		fieldName:   "hw.fan.speed-Mean",
		metricName:  "intersight.ucs.fan.speed",
		description: "Mean fan speed from Intersight telemetry.",
		unit:        "1/min",
	}
	response := []any{
		map[string]any{"event": map[string]any{"host.name": "included", "hw.fan.speed-Mean": 1000.0}},
		map[string]any{"event": map[string]any{"host.name": "included", "hw.fan.speed-Mean": "2000"}},
		map[string]any{"event": map[string]any{"host.name": "included", "hw.fan.speed-Mean": json.Number("3000")}},
		map[string]any{"event": map[string]any{"host.name": "included", "hw.fan.speed-Mean": nil}},
		map[string]any{"event": map[string]any{"host.name": "included"}},
		map[string]any{"event": map[string]any{"host.name": "included", "hw.fan.speed-Mean": "invalid"}},
		map[string]any{"event": map[string]any{"host.name": "excluded", "hw.fan.speed-Mean": 4000}},
		map[string]any{"event": "invalid"},
		"invalid",
	}

	builder.recordTelemetry(query, response, selector, 0)
	md := builder.emit()

	assert.Equal(t, 3, metricDataPointCount(md, "intersight.ucs.fan.speed"))
	for outcome, value := range map[string]int64{
		"emitted":         3,
		"device_filtered": 1,
		"null_value":      1,
		"missing_value":   1,
		"invalid_value":   1,
		"malformed_row":   2,
	} {
		assert.True(t, intMetricValueWithAttributesExists(md, "intersight.telemetry.query.rows", value, map[string]string{
			"intersight.telemetry.query":   "fan_speed",
			"intersight.telemetry.outcome": outcome,
		}), outcome)
	}
}

func TestIntersightTelemetryRejectsNonArrayResponse(t *testing.T) {
	server := newIntersightFixtureServer(t, map[string]string{
		"/api/v1/telemetry/GroupBys": `{}`,
	}, nil)
	defer server.Close()

	receiver := newTestIntersightMetricsReceiver(t, server.URL, nil)
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, intMetricValueExists(md, "intersight.scrape.partial_success", 1))
}

func TestIntersightLiveEmptyDomainsHaveMetricContracts(t *testing.T) {
	tests := []struct {
		name     string
		endpoint intersightEndpoint
		object   intersight.Object
		want     map[string]int64
	}{
		{
			name:     "advisory instance",
			endpoint: intersightEndpoint{group: "events", operation: "tam.advisory_instances", objectType: "tam.AdvisoryInstance"},
			object:   intersight.Object{"Moid": "advisory-instance-1", "ObjectType": "tam.AdvisoryInstance", "State": "Active"},
			want:     map[string]int64{"intersight.advisory.active": 1, "intersight.advisory.count": 1},
		},
		{
			name:     "security advisory",
			endpoint: intersightEndpoint{group: "events", operation: "tam.security_advisories", objectType: "tam.SecurityAdvisory"},
			object:   intersight.Object{"Moid": "security-advisory-1", "ObjectType": "tam.SecurityAdvisory", "Status": "Active", "Severity": "Critical"},
			want:     map[string]int64{"intersight.advisory.active": 1, "intersight.advisory.count": 1},
		},
		{
			name:     "workflow",
			endpoint: intersightEndpoint{group: "events", operation: "workflow.workflow_infos", objectType: "workflow.WorkflowInfo"},
			object:   intersight.Object{"Moid": "workflow-1", "ObjectType": "workflow.WorkflowInfo", "Status": "Failed"},
			want:     map[string]int64{"intersight.workflow.status": 4, "intersight.workflow.count": 1},
		},
		{
			name:     "task",
			endpoint: intersightEndpoint{group: "events", operation: "workflow.task_infos", objectType: "workflow.TaskInfo"},
			object:   intersight.Object{"Moid": "task-1", "ObjectType": "workflow.TaskInfo", "Status": "Failed"},
			want:     map[string]int64{"intersight.task.status": 4, "intersight.task.count": 1},
		},
		{
			name:     "tech support",
			endpoint: intersightEndpoint{group: "events", operation: "techsupportmanagement.techsupport_statuses", objectType: "techsupportmanagement.TechSupportStatus"},
			object:   intersight.Object{"Moid": "techsupport-1", "ObjectType": "techsupportmanagement.TechSupportStatus", "Status": "CollectionComplete"},
			want:     map[string]int64{"intersight.techsupport.status": 1, "intersight.techsupport.count": 1},
		},
		{
			name:     "equipment chassis",
			endpoint: intersightEndpoint{group: "equipment", operation: "equipment.chasses", objectType: "equipment.Chassis"},
			object:   intersight.Object{"Moid": "chassis-1", "ObjectType": "equipment.Chassis", "OperState": "ok", "FaultSummary": 2},
			want:     map[string]int64{"intersight.target.connection_status": 1, "intersight.fault.count": 2},
		},
		{
			name:     "firmware summary",
			endpoint: intersightEndpoint{group: "firmware", operation: "firmware.firmware_summaries", objectType: "firmware.FirmwareSummary"},
			object:   intersight.Object{"Moid": "firmware-1", "ObjectType": "firmware.FirmwareSummary", "BundleVersion": "5.0(1)"},
			want:     map[string]int64{"intersight.firmware.bundle.info": 1},
		},
		{
			name:     "storage controller",
			endpoint: intersightEndpoint{group: "storage", operation: "storage.controllers", objectType: "storage.Controller"},
			object:   intersight.Object{"Moid": "controller-1", "ObjectType": "storage.Controller", "ControllerStatus": "ok", "RebuildRatePercent": 42},
			want:     map[string]int64{"intersight.storage.rebuild.rate": 42, "intersight.storage.status": 1},
		},
		{
			name:     "physical disk",
			endpoint: intersightEndpoint{group: "storage", operation: "storage.physical_disks", objectType: "storage.PhysicalDisk"},
			object:   intersight.Object{"Moid": "disk-1", "ObjectType": "storage.PhysicalDisk", "DriveState": "ok", "MediaErrorCount": 3, "PredictiveFailureCount": 1, "PercentLifeLeft": 82, "OperatingTemperature": 38, "PowerOnHours": 100},
			want:     map[string]int64{"intersight.storage.media_error.count": 3, "intersight.storage.predictive_failure.count": 1, "intersight.storage.life_left": 82, "intersight.storage.temperature": 38, "intersight.storage.power_on.hours": 100, "intersight.storage.status": 1},
		},
		{
			name:     "virtual drive",
			endpoint: intersightEndpoint{group: "storage", operation: "storage.virtual_drives", objectType: "storage.VirtualDrive"},
			object:   intersight.Object{"Moid": "virtual-drive-1", "ObjectType": "storage.VirtualDrive", "DriveState": "ok"},
			want:     map[string]int64{"intersight.storage.status": 1},
		},
		{
			name:     "hyperflex cluster",
			endpoint: intersightEndpoint{group: "hyperflex", operation: "hyperflex.clusters", objectType: "hyperflex.Cluster"},
			object:   intersight.Object{"Moid": "hx-cluster-1", "ObjectType": "hyperflex.Cluster", "Status": "Healthy", "VmCount": 24, "FltAggr": 1},
			want:     map[string]int64{"intersight.virtual_machine.count": 24, "intersight.fault.count": 1, "intersight.hyperflex.status": 1},
		},
		{
			name:     "hyperflex node",
			endpoint: intersightEndpoint{group: "hyperflex", operation: "hyperflex.nodes", objectType: "hyperflex.Node"},
			object:   intersight.Object{"Moid": "hx-node-1", "ObjectType": "hyperflex.Node", "Status": "Healthy"},
			want:     map[string]int64{"intersight.hyperflex.status": 1},
		},
		{
			name:     "kubernetes cluster",
			endpoint: intersightEndpoint{group: "kubernetes", operation: "kubernetes.clusters", objectType: "kubernetes.Cluster"},
			object:   intersight.Object{"Moid": "k8s-cluster-1", "ObjectType": "kubernetes.Cluster", "ConnectionStatus": "Connected"},
			want:     map[string]int64{"intersight.kubernetes.cluster.connection_status": 1},
		},
		{
			name:     "kubernetes node",
			endpoint: intersightEndpoint{group: "kubernetes", operation: "kubernetes.nodes", objectType: "kubernetes.Node"},
			object:   intersight.Object{"Moid": "k8s-node-1", "ObjectType": "kubernetes.Node", "Status": "Ready"},
			want:     map[string]int64{"intersight.kubernetes.cluster.connection_status": 1},
		},
		{
			name:     "virtual machine",
			endpoint: intersightEndpoint{group: "virtualization", operation: "virtualization.virtual_machines", objectType: "virtualization.VirtualMachine"},
			object:   intersight.Object{"Moid": "vm-1", "ObjectType": "virtualization.VirtualMachine", "PowerState": "PoweredOn", "Cpu": 8, "Memory": 32768},
			want:     map[string]int64{"intersight.virtual_machine.cpu.count": 8, "intersight.virtual_machine.memory": 32768, "intersight.virtual_machine.power_state": 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := newIntersightMetricsBuilder(time.Unix(1_800_000_000, 0), "https://intersight.example.test", nil)
			builder.recordObject(tt.endpoint, tt.object)
			builder.flushCounts()
			md := builder.emit()
			for metricName, value := range tt.want {
				assert.True(t, intMetricValueExists(md, metricName, value), "%s=%d", metricName, value)
			}
		})
	}
}

func TestIntersightScrapeRecordsPartialSuccess(t *testing.T) {
	server := newIntersightFixtureServer(t, map[string]string{
		"/api/v1/asset/DeviceRegistrations": `{"Results":[
			{"Moid":"reg-1","ObjectType":"asset.DeviceRegistration","DeviceHostname":["fi-a"],"Serial":["FDO1234"],"ConnectionStatus":"Connected"}
		]}`,
		"/api/v1/telemetry/GroupBys": `[]`,
	}, map[string]int{
		"/api/v1/storage/PhysicalDisks": http.StatusInternalServerError,
	})
	defer server.Close()

	receiver := newTestIntersightMetricsReceiver(t, server.URL, nil)
	md, err := receiver.scrape(t.Context())
	require.NoError(t, err)

	assert.True(t, intMetricValueExists(md, "intersight.scrape.partial_success", 1))
	assert.Contains(t, metricNames(md), "intersight.api.request.errors")
}

func TestIntersightLogsEmitEventEvidenceAndDeduplicate(t *testing.T) {
	server := newIntersightFixtureServer(t, map[string]string{
		"/api/v1/aaa/AuditRecords": `{"Results":[
			{"Moid":"audit-1","ObjectType":"aaa.AuditRecord","Email":"operator@example.com","Timestamp":"2026-05-25T10:01:00Z","InstId":"fabric-profile/update"}
		]}`,
		"/api/v1/cond/Alarms": `{"Results":[
			{"Moid":"alarm-1","ObjectType":"cond.Alarm","AffectedMoDisplayName":"ucs-server-1","AffectedMoId":"server-1","Severity":"Critical","Acknowledge":"None","CreationTime":"2026-05-25T10:00:00Z","Description":"Thermal threshold exceeded"}
		]}`,
		"/api/v1/tam/AdvisoryInstances": `{"Results":[
			{"Moid":"advisory-instance-1","ObjectType":"tam.AdvisoryInstance","AffectedObjectMoid":"server-1","AffectedObjectType":"compute.PhysicalSummary","State":"Active","CreateTime":"2026-05-25T10:00:00Z"}
		]}`,
		"/api/v1/tam/SecurityAdvisories": `{"Results":[
			{"Moid":"security-advisory-1","ObjectType":"tam.SecurityAdvisory","Name":"Security advisory","Severity":"Critical","Status":"Active","CreateTime":"2026-05-25T10:00:00Z"}
		]}`,
		"/api/v1/workflow/WorkflowInfos": `{"Results":[
			{"Moid":"workflow-1","ObjectType":"workflow.WorkflowInfo","Name":"Firmware workflow","Status":"Failed","CreateTime":"2026-05-25T10:00:00Z"}
		]}`,
		"/api/v1/workflow/TaskInfos": `{"Results":[
			{"Moid":"task-1","ObjectType":"workflow.TaskInfo","Name":"Firmware update","Status":"Failed","FailureReason":"Image download failed","CreateTime":"2026-05-25T10:00:00Z"}
		]}`,
		"/api/v1/techsupportmanagement/TechSupportStatuses": `{"Results":[
			{"Moid":"techsupport-1","ObjectType":"techsupportmanagement.TechSupportStatus","Status":"CollectionComplete","CreateTime":"2026-05-25T10:00:00Z"}
		]}`,
	}, nil)
	defer server.Close()

	receiver := newTestIntersightLogsReceiver(t, server.URL)
	ld, err := receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 7, ld.LogRecordCount())
	assert.True(t, hasLogRecordAttribute(ld, "event.name", "aaa.audit_records"))
	assert.True(t, hasLogRecordAttribute(ld, "event.name", "cond.alarms"))
	assert.True(t, hasLogRecordAttribute(ld, "event.name", "tam.advisory_instances"))
	assert.True(t, hasLogRecordAttribute(ld, "event.name", "tam.security_advisories"))
	assert.True(t, hasLogRecordAttribute(ld, "event.name", "workflow.workflow_infos"))
	assert.True(t, hasLogRecordAttribute(ld, "event.name", "workflow.task_infos"))
	assert.True(t, hasLogRecordAttribute(ld, "event.name", "techsupportmanagement.techsupport_statuses"))
	assert.True(t, hasLogRecordAttribute(ld, "user.email", "operator@example.com"))

	ld, err = receiver.scrape(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 0, ld.LogRecordCount())
}

func TestIntersightLogsPreserveEarlierPagesOnLaterPageFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/aaa/AuditRecords" {
			if r.URL.Query().Get("$skip") == "0" {
				_, _ = w.Write([]byte(`{"Results":[
					{"Moid":"audit-1","ObjectType":"aaa.AuditRecord","Email":"one@example.com","Timestamp":"2026-05-25T10:01:00Z"},
					{"Moid":"audit-2","ObjectType":"aaa.AuditRecord","Email":"two@example.com","Timestamp":"2026-05-25T10:02:00Z"}
				]}`))
				return
			}
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"Results":[]}`))
	}))
	defer server.Close()

	receiver := newTestIntersightLogsReceiver(t, server.URL)
	ld, err := receiver.scrape(t.Context())
	require.Error(t, err)
	assert.Equal(t, 2, ld.LogRecordCount())
	assert.True(t, hasLogRecordAttribute(ld, "user.email", "one@example.com"))
	assert.True(t, hasLogRecordAttribute(ld, "user.email", "two@example.com"))
}

func TestIntersightEndpointQueriesIncludeSelectAndLookback(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)

	alarmQuery := endpointQuery(intersightLogEndpoints()[1], cfg, now)
	assert.Equal(t, "Acknowledge eq 'None'", alarmQuery.Get("$filter"))
	assert.Contains(t, alarmQuery.Get("$select"), "AffectedMoDisplayName")

	auditQuery := endpointQuery(intersightLogEndpoints()[0], cfg, now)
	assert.Equal(t, "CreateTime gt 2026-05-24T12:00:00Z", auditQuery.Get("$filter"))
	assert.Contains(t, auditQuery.Get("$select"), "UserIdOrEmail")

	for _, endpoint := range intersightLogEndpoints() {
		switch endpoint.operation {
		case "tam.advisory_instances", "tam.security_advisories", "workflow.workflow_infos", "workflow.task_infos", "techsupportmanagement.techsupport_statuses":
			assert.Equal(t, "CreateTime gt 2026-05-24T12:00:00Z", endpointQuery(endpoint, cfg, now).Get("$filter"), endpoint.operation)
		}
	}

	for _, endpoint := range intersightMetricEndpoints() {
		if endpoint.operation == "hyperflex.clusters" {
			assert.Contains(t, endpoint.selectFields, "Status")
		}
	}
}

func TestIntersightAuditEndpointIsInBothSignalCatalogs(t *testing.T) {
	var metricEndpoints, logEndpoints []intersightEndpoint
	for _, endpoint := range intersightMetricEndpoints() {
		if endpoint.operation == "aaa.audit_records" {
			metricEndpoints = append(metricEndpoints, endpoint)
		}
	}
	for _, endpoint := range intersightLogEndpoints() {
		if endpoint.operation == "aaa.audit_records" {
			logEndpoints = append(logEndpoints, endpoint)
		}
	}
	require.Len(t, metricEndpoints, 1)
	require.Len(t, logEndpoints, 1)

	metricEndpoint := metricEndpoints[0]
	logEndpoint := logEndpoints[0]
	assert.Equal(t, logEndpoint.group, metricEndpoint.group)
	assert.Equal(t, logEndpoint.path, metricEndpoint.path)
	assert.Equal(t, logEndpoint.objectType, metricEndpoint.objectType)
	assert.Equal(t, logEndpoint.selectFields, metricEndpoint.selectFields)
	cfg := createDefaultConfig().(*Config)
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, endpointQuery(logEndpoint, cfg, now), endpointQuery(metricEndpoint, cfg, now))
}

func TestIntersightCatalogCoversTroubleshootingDomains(t *testing.T) {
	endpointGroups := map[string]bool{}
	operations := map[string]bool{}
	for _, endpoint := range intersightMetricEndpoints() {
		endpointGroups[endpoint.group] = true
		operations[endpoint.operation] = true
	}
	for _, endpoint := range intersightLogEndpoints() {
		endpointGroups[endpoint.group] = true
		operations[endpoint.operation] = true
	}
	for _, group := range []string{
		"inventory",
		"events",
		"audit",
		"equipment",
		"network",
		"firmware",
		"storage",
		"hyperflex",
		"kubernetes",
		"virtualization",
	} {
		assert.True(t, endpointGroups[group], "missing Intersight endpoint group %q", group)
	}
	for _, operation := range []string{
		"aaa.audit_records",
		"asset.device_registrations",
		"asset.targets",
		"compute.physical_summaries",
		"compute.blades",
		"compute.rack_units",
		"cond.alarms",
		"cond.hcl_statuses",
		"tam.advisory_instances",
		"tam.security_advisories",
		"workflow.workflow_infos",
		"workflow.task_infos",
		"techsupportmanagement.techsupport_statuses",
		"equipment.device_summaries",
		"equipment.chasses",
		"equipment.fans",
		"equipment.fan_modules",
		"equipment.psus",
		"equipment.io_cards",
		"equipment.fexes",
		"equipment.transceivers",
		"network.elements",
		"firmware.firmware_summaries",
		"storage.controllers",
		"storage.physical_disks",
		"storage.virtual_drives",
		"hyperflex.clusters",
		"hyperflex.nodes",
		"kubernetes.clusters",
		"kubernetes.nodes",
		"virtualization.virtual_machines",
	} {
		assert.True(t, operations[operation], "missing Intersight operation %q", operation)
	}

	telemetryNames := map[string]bool{}
	for _, query := range intersightTelemetryQueries() {
		telemetryNames[query.name] = true
	}
	for _, name := range []string{
		"fan_speed",
		"fan_speed_ratio",
		"host_power",
		"host_energy",
		"host_power_state",
		"temperature",
		"temperature_high_critical",
		"temperature_low_critical",
		"voltage",
		"current",
		"cpu_user",
		"cpu_system",
		"cpu_idle",
		"memory_utilization",
		"memory_used",
		"memory_free",
		"memory_cached",
		"memory_module_size",
		"memory_correctable_ecc",
		"memory_uncorrectable_ecc",
		"network_rx",
		"network_tx",
		"network_errors",
		"network_tx_errors",
		"network_rx_crc_errors",
		"network_rx_discards",
		"network_rx_no_buffer",
		"network_rx_drops",
		"network_tx_discards",
		"network_rx_packets",
		"network_tx_packets",
		"network_rx_pause_frames",
		"network_tx_pause_frames",
		"network_tx_drops",
		"network_utilization",
		"network_link_speed",
		"network_link_status",
		"network_link_failures",
		"network_signal_losses",
		"network_interface_resets",
		"psu_output_power",
		"psu_utilization",
		"psu_status",
		"fan_status",
		"memory_status",
		"temperature_status",
		"signal_power_rx",
		"signal_power_tx",
		"hyperflex_read_iops",
		"hyperflex_write_iops",
		"hyperflex_read_latency",
		"hyperflex_write_latency",
	} {
		assert.True(t, telemetryNames[name], "missing Intersight telemetry query %q", name)
	}
}

func newTestIntersightMetricsReceiver(t *testing.T, endpoint string, mutate func(*Config)) *intersightMetricsReceiver {
	t.Helper()
	cfg := createDefaultConfig().(*Config)
	cfg.ControllerConfig.Timeout = 5 * time.Second
	cfg.Intersight = defaultIntersightConfig()
	cfg.Intersight.Enabled = true
	cfg.Intersight.Endpoint = endpoint
	cfg.Intersight.Auth.KeyID = "test-key"
	cfg.Intersight.Auth.KeyPEM = configopaque.String(testIntersightPrivateKeyPEM(t))
	cfg.Intersight.MaxRetries = 1
	cfg.Intersight.PageSize = 2
	if mutate != nil {
		mutate(cfg)
	}
	receiver, err := newIntersightMetricsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)
	return receiver
}

func newTestIntersightLogsReceiver(t *testing.T, endpoint string) *intersightLogsReceiver {
	t.Helper()
	cfg := createDefaultConfig().(*Config)
	cfg.ControllerConfig.Timeout = 5 * time.Second
	cfg.Intersight = defaultIntersightConfig()
	cfg.Intersight.Enabled = true
	cfg.Intersight.Endpoint = endpoint
	cfg.Intersight.Auth.KeyID = "test-key"
	cfg.Intersight.Auth.KeyPEM = configopaque.String(testIntersightPrivateKeyPEM(t))
	cfg.Intersight.MaxRetries = 1
	cfg.Intersight.PageSize = 2
	receiver, err := newIntersightLogsReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)
	return receiver
}

func newIntersightFixtureServer(t *testing.T, routes map[string]string, failures map[string]int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.Header.Get("Authorization"), `Signature keyId="test-key"`)
		assert.NotEmpty(t, r.Header.Get("Date"))
		assert.NotEmpty(t, r.Header.Get("Digest"))

		if status := failures[r.URL.Path]; status != 0 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`failed`))
			return
		}
		if r.Method == http.MethodGet && r.URL.Query().Get("$skip") != "" && r.URL.Query().Get("$skip") != "0" {
			_, _ = w.Write([]byte(`{"Results":[]}`))
			return
		}
		if body, ok := routes[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		if strings.EqualFold(r.Method, http.MethodPost) {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_, _ = w.Write([]byte(`{"Results":[]}`))
	}))
	return server
}

func intersightTelemetryFixture() string {
	return `[{"event":{
		"host.name":"ucs-server-1",
		"name":"ucs-server-1",
		"deviceId":"hx-prod",
		"hw.fan.speed-Mean":12000,
		"hw.fan.speed_ratio-Mean":64,
		"hw.host.power-Mean":420,
		"hw.host.energy-Sum":1512000,
		"hw.host.power_state-Max":1,
		"hw.temperature-Mean":37,
		"hw.temperature.limit_high_critical-Max":75,
		"hw.temperature.limit_low_critical-Min":5,
		"hw.voltage-Mean":12,
		"hw.current-Mean":8,
		"system.cpu.utilization_user-Max":0.42,
		"system.cpu.utilization_system-Max":0.23,
		"system.cpu.utilization_idle-Max":0.35,
		"system.memory.utilization-Max":0.68,
		"system.memory.usage_used-Sum":17179869184,
		"system.memory.usage_free-Sum":8589934592,
		"system.memory.usage_cached-Sum":4294967296,
		"hw.memory.size-Sum":34359738368,
		"hw.errors_correctable_ecc_errors-Sum":2,
		"hw.errors_uncorrectable_ecc_errors-Sum":1,
		"hw.network.io_receive-Sum":1000,
		"hw.network.io_transmit-Sum":2000,
		"hw.errors_network_receive_all-Sum":1,
		"hw.errors_network_transmit_all-Sum":2,
		"hw.errors_network_receive_crc-Sum":3,
		"hw.errors_network_receive_discard-Sum":4,
		"hw.errors_network_receive_no_buffer-Sum":5,
		"hw.errors_receive_drops-Sum":6,
		"hw.errors_network_transmit_discard-Sum":7,
		"hw.network.packets_receive_unicast-Sum":300,
		"hw.network.packets_transmit_unicast-Sum":400,
		"hw.errors_network_receive_pause-Sum":8,
		"hw.errors_network_transmit_pause-Sum":9,
		"hw.errors_transmit_drops-Sum":3,
		"hw.network.bandwidth.utilization_all-Max":72,
		"hw.network.bandwidth.limit-Max":25000000000,
		"hw.network.up-Max":1,
		"hw.errors_network_link_failures-Sum":10,
		"hw.errors_network_signal_losses-Sum":11,
		"hw.network.interface_resets-Sum":12,
		"hw.power_out-Mean":380,
		"hw.power_supply.utilization-Max":58,
		"hw.status-Min":1,
		"hw.signal_power_receive-Mean":-2.8,
		"hw.signal_power_transmit-Mean":-1.9,
		"hyperflex.read.iops-Sum":900,
		"hyperflex.write.iops-Sum":700,
		"hyperflex.read.latency-Max":3.2,
		"hyperflex.write.latency-Max":4.4
	}}]`
}

func doubleMetricValueExists(md pmetric.Metrics, name string, value float64) bool {
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
					if points.At(l).DoubleValue() == value {
						return true
					}
				}
			}
		}
	}
	return false
}

func intMetricValueWithAttributesExists(md pmetric.Metrics, name string, value int64, attrs map[string]string) bool {
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			for k := 0; k < sm.Metrics().Len(); k++ {
				metric := sm.Metrics().At(k)
				if metric.Name() != name || metric.Type() != pmetric.MetricTypeGauge {
					continue
				}
				points := metric.Gauge().DataPoints()
				for l := 0; l < points.Len(); l++ {
					point := points.At(l)
					if point.IntValue() != value {
						continue
					}
					matches := true
					for key, want := range attrs {
						got, ok := point.Attributes().Get(key)
						if !ok || got.Str() != want {
							matches = false
							break
						}
					}
					if matches {
						return true
					}
				}
			}
		}
	}
	return false
}

func hasLogRecordAttribute(ld plog.Logs, name, value string) bool {
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		rl := ld.ResourceLogs().At(i)
		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			sl := rl.ScopeLogs().At(j)
			for k := 0; k < sl.LogRecords().Len(); k++ {
				attr, ok := sl.LogRecords().At(k).Attributes().Get(name)
				if ok && attr.Str() == value {
					return true
				}
			}
		}
	}
	return false
}

func hasLogResourceAttribute(ld plog.Logs, value string) bool {
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		attr, ok := ld.ResourceLogs().At(i).Resource().Attributes().Get("host.id")
		if ok && attr.Str() == value {
			return true
		}
	}
	return false
}

func TestLogSeverityNumberCoversCiscoAndSyslogLevels(t *testing.T) {
	assert.Equal(t, plog.SeverityNumberFatal4, logSeverityNumber("emergency"))
	assert.Equal(t, plog.SeverityNumberFatal3, logSeverityNumber("1"))
	assert.Equal(t, plog.SeverityNumberError, logSeverityNumber("major"))
	assert.Equal(t, plog.SeverityNumberInfo2, logSeverityNumber("notice"))
	assert.Equal(t, plog.SeverityNumberInfo, logSeverityNumber("cleared"))
	assert.Equal(t, plog.SeverityNumberDebug, logSeverityNumber("7"))
	assert.Equal(t, plog.SeverityNumberUnspecified, logSeverityNumber("vendor-specific"))
}

func testIntersightPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
}
