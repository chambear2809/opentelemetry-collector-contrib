// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kvmreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kvmreceiver"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/scraper"
	"go.opentelemetry.io/collector/scraper/scraperhelper"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kvmreceiver/internal/metadata"
)

// NewFactory creates a new KVM receiver factory.
func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		metadata.Type,
		newDefaultConfig,
		receiver.WithMetrics(newMetricsReceiver, metadata.MetricsStability),
	)
}

func newMetricsReceiver(
	_ context.Context,
	settings receiver.Settings,
	rCfg component.Config,
	metricsConsumer consumer.Metrics,
) (receiver.Metrics, error) {
	cfg := rCfg.(*Config)
	s := newScraper(cfg, settings)

	scrape, err := scraper.NewMetrics(
		s.scrape,
		scraper.WithStart(s.start),
		scraper.WithShutdown(s.shutdown),
	)
	if err != nil {
		return nil, err
	}

	return scraperhelper.NewMetricsController(
		&cfg.ControllerConfig,
		settings,
		metricsConsumer,
		scraperhelper.AddMetricsScraper(metadata.Type, scrape),
	)
}
