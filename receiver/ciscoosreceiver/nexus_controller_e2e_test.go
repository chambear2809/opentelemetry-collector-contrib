// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package ciscoosreceiver

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

const (
	nexusDashboardE2EEndpointEnv       = "CISCOOS_E2E_NEXUS_DASHBOARD_ENDPOINT"
	nexusDashboardE2EUsernameEnv       = "CISCOOS_E2E_NEXUS_DASHBOARD_USERNAME"
	nexusDashboardE2EAPIKeyEnv         = "CISCOOS_E2E_NEXUS_DASHBOARD_API_KEY"
	nexusDashboardE2EPasswordEnv       = "CISCOOS_E2E_NEXUS_DASHBOARD_PASSWORD"
	nexusDashboardE2EInsecureSkipEnv   = "CISCOOS_E2E_NEXUS_DASHBOARD_INSECURE_SKIP_VERIFY"
	nexusDashboardE2EFabricsEnv        = "CISCOOS_E2E_NEXUS_DASHBOARD_FABRICS"
	nexusDashboardE2ESwitchIDsEnv      = "CISCOOS_E2E_NEXUS_DASHBOARD_SWITCH_IDS"
	nexusDashboardE2ESwitchSerialsEnv  = "CISCOOS_E2E_NEXUS_DASHBOARD_SWITCH_SERIALS"
	aciE2EEndpointEnv                  = "CISCOOS_E2E_APIC_ENDPOINT"
	aciE2EUsernameEnv                  = "CISCOOS_E2E_APIC_USERNAME"
	aciE2EPasswordEnv                  = "CISCOOS_E2E_APIC_PASSWORD"
	aciE2EDomainEnv                    = "CISCOOS_E2E_APIC_DOMAIN"
	aciE2EInsecureSkipEnv              = "CISCOOS_E2E_APIC_INSECURE_SKIP_VERIFY"
	aciE2ENodeIDsEnv                   = "CISCOOS_E2E_APIC_NODE_IDS"
	aciE2ETenantsEnv                   = "CISCOOS_E2E_APIC_TENANTS"
	nexusControllerE2ECollectionIntEnv = "CISCOOS_E2E_CONTROLLER_COLLECTION_INTERVAL"
	nexusControllerE2ETimeoutEnv       = "CISCOOS_E2E_CONTROLLER_TIMEOUT"
	nexusControllerE2EWaitTimeoutEnv   = "CISCOOS_E2E_CONTROLLER_WAIT_TIMEOUT"
)

func TestE2ENexusDashboardControllerAPI(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.CollectionInterval = durationEnv(t, nexusControllerE2ECollectionIntEnv, 10*time.Second)
	cfg.Timeout = durationEnv(t, nexusControllerE2ETimeoutEnv, 45*time.Second)
	cfg.NexusDashboard = defaultNexusDashboardConfig()
	cfg.NexusDashboard.Enabled = true
	cfg.NexusDashboard.Endpoint = requiredEnvOrSkip(t, nexusDashboardE2EEndpointEnv)
	cfg.NexusDashboard.InsecureSkipVerify = boolEnv(t, nexusDashboardE2EInsecureSkipEnv, false)
	cfg.NexusDashboard.Targets.Fabrics = csvEnv(nexusDashboardE2EFabricsEnv)
	cfg.NexusDashboard.Targets.SwitchIDs = csvEnv(nexusDashboardE2ESwitchIDsEnv)
	cfg.NexusDashboard.Targets.SwitchSerials = csvEnv(nexusDashboardE2ESwitchSerialsEnv)
	cfg.NexusDashboard.Auth.Username = requiredEnvOrSkip(t, nexusDashboardE2EUsernameEnv)
	if apiKey := os.Getenv(nexusDashboardE2EAPIKeyEnv); apiKey != "" {
		cfg.NexusDashboard.Auth.Mode = "api_key"
		cfg.NexusDashboard.Auth.APIKey = configopaque.String(apiKey)
	} else {
		cfg.NexusDashboard.Auth.Mode = "username_password"
		cfg.NexusDashboard.Auth.Password = configopaque.String(requiredEnvOrSkip(t, nexusDashboardE2EPasswordEnv))
	}
	require.NoError(t, cfg.Validate())

	sink := new(consumertest.MetricsSink)
	rcvr, err := NewFactory().CreateMetrics(t.Context(), receivertest.NewNopSettings(metadata.Type), cfg, sink)
	require.NoError(t, err)
	require.NoError(t, rcvr.Start(t.Context(), componenttest.NewNopHost()))
	t.Cleanup(func() {
		assert.NoError(t, rcvr.Shutdown(context.Background()))
	})

	require.EventuallyWithT(t, func(tt *assert.CollectT) {
		summary := summarizeCiscoOSE2EMetrics(sink.AllMetrics())
		assert.Contains(tt, summary.metricNames, "nexus_dashboard.api.request.duration")
		assert.Contains(tt, summary.metricNames, "nexus_dashboard.scrape.partial_success")
	}, durationEnv(t, nexusControllerE2EWaitTimeoutEnv, 2*time.Minute), time.Second)
}

func TestE2EACIControllerAPI(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.CollectionInterval = durationEnv(t, nexusControllerE2ECollectionIntEnv, 10*time.Second)
	cfg.Timeout = durationEnv(t, nexusControllerE2ETimeoutEnv, 45*time.Second)
	cfg.ACI = defaultACIConfig()
	cfg.ACI.Enabled = true
	cfg.ACI.Controllers = []ACIControllerConfig{{
		Endpoint: requiredEnvOrSkip(t, aciE2EEndpointEnv),
		Name:     "apic-e2e",
	}}
	cfg.ACI.InsecureSkipVerify = boolEnv(t, aciE2EInsecureSkipEnv, false)
	cfg.ACI.Auth.Username = requiredEnvOrSkip(t, aciE2EUsernameEnv)
	cfg.ACI.Auth.Password = configopaque.String(requiredEnvOrSkip(t, aciE2EPasswordEnv))
	cfg.ACI.Auth.Domain = os.Getenv(aciE2EDomainEnv)
	cfg.ACI.Targets.NodeIDs = csvEnv(aciE2ENodeIDsEnv)
	cfg.ACI.Targets.Tenants = csvEnv(aciE2ETenantsEnv)
	require.NoError(t, cfg.Validate())

	sink := new(consumertest.MetricsSink)
	rcvr, err := NewFactory().CreateMetrics(t.Context(), receivertest.NewNopSettings(metadata.Type), cfg, sink)
	require.NoError(t, err)
	require.NoError(t, rcvr.Start(t.Context(), componenttest.NewNopHost()))
	t.Cleanup(func() {
		assert.NoError(t, rcvr.Shutdown(context.Background()))
	})

	require.EventuallyWithT(t, func(tt *assert.CollectT) {
		allMetrics := sink.AllMetrics()
		summary := summarizeCiscoOSE2EMetrics(allMetrics)
		assert.Contains(tt, summary.metricNames, "aci.api.request.duration")
		assert.True(tt, ciscoOSE2EIntMetricValueExists(allMetrics, "aci.controller.up", 1),
			"APIC authentication and collection must produce controller.up=1")
		assert.True(tt, ciscoOSE2EIntMetricValueExists(allMetrics, "aci.scrape.partial_success", 0),
			"every enabled APIC endpoint family must complete successfully")
		assert.Contains(tt, summary.metricNames, "aci.resource.info")
		assert.Contains(tt, summary.metricNames, "aci.fabric.health")
		assert.True(tt, summary.deviceUp, "at least one APIC fabric node must be reported up")
	}, durationEnv(t, nexusControllerE2EWaitTimeoutEnv, 2*time.Minute), time.Second)
}

func ciscoOSE2EIntMetricValueExists(allMetrics []pmetric.Metrics, name string, value int64) bool {
	for _, metrics := range allMetrics {
		if intMetricValueExists(metrics, name, value) {
			return true
		}
	}
	return false
}
