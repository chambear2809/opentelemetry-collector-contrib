// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package ciscoosreceiver

import (
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
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
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

// TestE2EACIFullTelemetryInventory performs exactly one metrics scrape and one
// logs scrape. It proves that every configured APIC class operation succeeds,
// while reporting data-dependent metric, class, and log inventories without
// exposing APIC object bodies or credentials.
func TestE2EACIFullTelemetryInventory(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.ControllerConfig.Timeout = durationEnv(t, nexusControllerE2ETimeoutEnv, 45*time.Second)
	cfg.ACI = defaultACIConfig()
	cfg.ACI.Enabled = true
	cfg.ACI.Controllers = []ACIControllerConfig{{
		Endpoint: requiredEnvOrSkip(t, aciE2EEndpointEnv),
		Name:     "apic-e2e-inventory",
	}}
	cfg.ACI.InsecureSkipVerify = boolEnv(t, aciE2EInsecureSkipEnv, false)
	cfg.ACI.Auth.Username = requiredEnvOrSkip(t, aciE2EUsernameEnv)
	cfg.ACI.Auth.Password = configopaque.String(requiredEnvOrSkip(t, aciE2EPasswordEnv))
	cfg.ACI.Auth.Domain = strings.TrimSpace(os.Getenv(aciE2EDomainEnv))
	enableAllACILogs(&cfg.ACI)
	require.NoError(t, cfg.Validate())

	ctx, cancel := context.WithTimeout(t.Context(), durationEnv(t, nexusControllerE2EWaitTimeoutEnv, 2*time.Minute))
	defer cancel()

	metricsReceiver, err := newACIMetricsReceiver(
		receivertest.NewNopSettings(metadata.Type),
		cfg,
		consumertest.NewNop(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, metricsReceiver.Shutdown(context.Background())) })

	md, err := metricsReceiver.scrape(ctx)
	require.NoError(t, err)
	metricsReceiver.statsMu.Lock()
	metricRequestStats := append([]aci.RequestStat(nil), metricsReceiver.stats...)
	metricsReceiver.statsMu.Unlock()
	requireACIE2EOperationsSucceeded(t, metricRequestStats, aciMetricEndpoints())
	require.True(t, intMetricValueExists(md, "aci.controller.up", 1))
	require.True(t, intMetricValueExists(md, "aci.scrape.partial_success", 0))

	metricCounts, objectCounts := aciE2EMetricInventory(md)
	require.NotZero(t, metricCounts["aci.resource.info"])
	for _, name := range []string{
		"cisco.interface.io.rate",
		"cisco.interface.packet.rate",
		"cisco.interface.utilization",
		"system.network.io",
		"system.network.packet.count",
		"system.network.errors",
		"system.network.packet.dropped",
	} {
		require.NotZero(t, metricCounts[name], "deep APIC statistics must emit %s", name)
	}
	requireACIE2EGaugeRange(t, md, "system.memory.utilization", 0, 1)
	requireACIE2EGaugeRange(t, md, "cisco.interface.utilization", 0, 1)
	t.Logf("ACI metric inventory (%d families): %s", len(metricCounts), formatACIInventory(metricCounts))
	t.Logf("ACI non-empty class inventory (%d classes): %s", len(objectCounts), formatACIInventory(objectCounts))

	logsReceiver, err := newACILogsReceiver(
		receivertest.NewNopSettings(metadata.Type),
		cfg,
		&consumertest.LogsSink{},
	)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, logsReceiver.Shutdown(context.Background())) })

	var (
		logStatsMu sync.Mutex
		logStats   []aci.RequestStat
	)
	for _, client := range logsReceiver.clients {
		client.OnRequest = func(stat aci.RequestStat) {
			logStatsMu.Lock()
			logStats = append(logStats, stat)
			logStatsMu.Unlock()
		}
	}
	ld, err := logsReceiver.scrape(ctx)
	require.NoError(t, err)
	logStatsMu.Lock()
	logRequestStats := append([]aci.RequestStat(nil), logStats...)
	logStatsMu.Unlock()
	requireACIE2EOperationsSucceeded(t, logRequestStats, aciLogEndpoints())

	logCounts := aciE2ELogInventory(t, ld)
	t.Logf("ACI log inventory (%d event/class combinations): %s", len(logCounts), formatACIInventory(logCounts))
}

func requireACIE2EOperationsSucceeded(t *testing.T, stats []aci.RequestStat, endpoints []aciEndpoint) {
	t.Helper()
	successes := make(map[string]int)
	failures := make(map[string]int)
	for _, stat := range stats {
		if stat.Outcome == "success" {
			successes[stat.Operation]++
		} else {
			failures[stat.Operation]++
		}
	}
	require.NotZero(t, successes["aaaLogin"], "APIC login must succeed")
	for _, endpoint := range endpoints {
		require.NotZero(t, successes[endpoint.operation], "APIC operation %s (%s) must succeed", endpoint.operation, endpoint.className)
		assert.Zero(t, failures[endpoint.operation], "APIC operation %s (%s) must not fail", endpoint.operation, endpoint.className)
	}
	t.Logf("ACI successful operation inventory (%d operations): %s", len(successes), formatACIInventory(successes))
}

func aciE2EMetricInventory(md pmetric.Metrics) (map[string]int, map[string]int) {
	metricCounts := make(map[string]int)
	objectCounts := make(map[string]int)
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			metrics := rm.ScopeMetrics().At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				metric := metrics.At(k)
				aciE2EVisitMetricAttrs(metric, func(attrs pcommon.Map) {
					metricCounts[metric.Name()]++
					if metric.Name() != "aci.resource.info" {
						return
					}
					group := aciE2EAttr(attrs, "aci.group")
					className := aciE2EAttr(attrs, "aci.class")
					resourceType := aciE2EAttr(attrs, "aci.resource.type")
					objectCounts[group+"/"+className+"/"+resourceType]++
				})
			}
		}
	}
	return metricCounts, objectCounts
}

func aciE2EVisitMetricAttrs(metric pmetric.Metric, visit func(pcommon.Map)) {
	switch metric.Type() {
	case pmetric.MetricTypeGauge:
		points := metric.Gauge().DataPoints()
		for i := 0; i < points.Len(); i++ {
			visit(points.At(i).Attributes())
		}
	case pmetric.MetricTypeSum:
		points := metric.Sum().DataPoints()
		for i := 0; i < points.Len(); i++ {
			visit(points.At(i).Attributes())
		}
	case pmetric.MetricTypeHistogram:
		points := metric.Histogram().DataPoints()
		for i := 0; i < points.Len(); i++ {
			visit(points.At(i).Attributes())
		}
	case pmetric.MetricTypeExponentialHistogram:
		points := metric.ExponentialHistogram().DataPoints()
		for i := 0; i < points.Len(); i++ {
			visit(points.At(i).Attributes())
		}
	case pmetric.MetricTypeSummary:
		points := metric.Summary().DataPoints()
		for i := 0; i < points.Len(); i++ {
			visit(points.At(i).Attributes())
		}
	case pmetric.MetricTypeEmpty:
	}
}

func requireACIE2EGaugeRange(t *testing.T, md pmetric.Metrics, name string, minimum, maximum float64) {
	t.Helper()
	found := false
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			metrics := rm.ScopeMetrics().At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				metric := metrics.At(k)
				if metric.Name() != name {
					continue
				}
				require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
				points := metric.Gauge().DataPoints()
				for index := 0; index < points.Len(); index++ {
					found = true
					point := points.At(index)
					require.Equal(t, pmetric.NumberDataPointValueTypeDouble, point.ValueType())
					value := point.DoubleValue()
					assert.GreaterOrEqual(t, value, minimum, "%s must not be below its ratio range", name)
					assert.LessOrEqual(t, value, maximum, "%s must not exceed its ratio range", name)
				}
			}
		}
	}
	require.True(t, found, "%s must contain at least one data point", name)
}

func aciE2ELogInventory(t *testing.T, ld plog.Logs) map[string]int {
	t.Helper()
	counts := make(map[string]int)
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		rl := ld.ResourceLogs().At(i)
		className := aciE2EAttr(rl.Resource().Attributes(), "aci.class")
		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			records := rl.ScopeLogs().At(j).LogRecords()
			for k := 0; k < records.Len(); k++ {
				record := records.At(k)
				require.Equal(t, "aci", aciE2EAttr(record.Attributes(), "event.domain"))
				require.NotEqual(t, pcommon.ValueTypeEmpty, record.Body().Type())
				eventName := aciE2EAttr(record.Attributes(), "event.name")
				counts[eventName+"/"+className]++
			}
		}
	}
	return counts
}

func aciE2EAttr(attrs pcommon.Map, key string) string {
	value, ok := attrs.Get(key)
	if !ok {
		return "<unset>"
	}
	return value.AsString()
}

func formatACIInventory(counts map[string]int) string {
	entries := make([]string, 0, len(counts))
	for key, count := range counts {
		entries = append(entries, key+"="+strconv.Itoa(count))
	}
	sort.Strings(entries)
	return strings.Join(entries, ", ")
}
