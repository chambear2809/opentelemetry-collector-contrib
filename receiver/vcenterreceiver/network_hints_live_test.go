// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build live

package vcenterreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/vcenterreceiver"

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/vcenterreceiver/internal/metadata"
)

// TestLiveNetworkHints validates the read-only network-hint path against a
// caller-provided vCenter. Credentials are supplied only through environment
// variables and are never stored in the repository.
func TestLiveNetworkHints(t *testing.T) {
	endpoint := os.Getenv("VCENTER_ENDPOINT")
	username := os.Getenv("VCENTER_USERNAME")
	password := os.Getenv("VCENTER_PASSWORD")
	if endpoint == "" || username == "" || password == "" {
		t.Skip("set VCENTER_ENDPOINT, VCENTER_USERNAME, and VCENTER_PASSWORD to run live validation")
	}

	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = endpoint
	cfg.Username = username
	cfg.Password = configopaque.String(password)
	cfg.ClientConfig = configtls.ClientConfig{Insecure: true}

	settings := receivertest.NewNopSettings(metadata.Type)
	scraper := newVmwareVcenterScraper(zap.NewNop(), cfg, settings)
	defer func() {
		shutdownErr := scraper.Shutdown(context.Background())
		if scraper.client != nil && scraper.client.vimDriver != nil {
			scraper.client.vimDriver.CloseIdleConnections()
		}
		require.NoError(t, shutdownErr)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	logs, err := scraper.scrapeNetworkHints(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, logs.ResourceLogs())

	states := make(map[string]int)
	cdpCount := 0
	lldpCount := 0
	for i := 0; i < logs.ResourceLogs().Len(); i++ {
		resourceLogs := logs.ResourceLogs().At(i)
		require.Equal(t, 1, resourceLogs.ScopeLogs().Len())
		for j := 0; j < resourceLogs.ScopeLogs().At(0).LogRecords().Len(); j++ {
			body := resourceLogs.ScopeLogs().At(0).LogRecords().At(j).Body().Map().AsRaw()
			state, ok := body["snapshot_state"].(string)
			require.True(t, ok)
			states[state]++
			physicalNics, ok := body["physical_nics"].([]any)
			require.True(t, ok)
			for _, physicalNic := range physicalNics {
				physicalNicMap, ok := physicalNic.(map[string]any)
				require.True(t, ok)
				if _, ok := physicalNicMap["cdp"]; ok {
					cdpCount++
				}
				if _, ok := physicalNicMap["lldp"]; ok {
					lldpCount++
				}
			}
		}
	}
	t.Logf("validated %d host network-hint snapshots: %v; CDP records=%d, LLDP records=%d", logs.ResourceLogs().Len(), states, cdpCount, lldpCount)

	metrics, err := scraper.scrape(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, metrics.ResourceMetrics())
	metricNames := make(map[string]struct{})
	for i := 0; i < metrics.ResourceMetrics().Len(); i++ {
		for j := 0; j < metrics.ResourceMetrics().At(i).ScopeMetrics().Len(); j++ {
			metricSlice := metrics.ResourceMetrics().At(i).ScopeMetrics().At(j).Metrics()
			for k := 0; k < metricSlice.Len(); k++ {
				metricNames[metricSlice.At(k).Name()] = struct{}{}
			}
		}
	}
	for _, name := range []string{
		"vcenter.host.network.throughput",
		"vcenter.host.network.packet.rate",
		"vcenter.vm.network.throughput",
		"vcenter.vm.network.packet.rate",
		"vcenter.vm.cpu.usage",
		"vcenter.vm.memory.usage",
		"vcenter.vm.disk.throughput",
	} {
		_, ok := metricNames[name]
		require.Truef(t, ok, "live metric %q was not emitted", name)
	}
	t.Logf("validated %d distinct metrics across %d resource groups", len(metricNames), metrics.ResourceMetrics().Len())
}
