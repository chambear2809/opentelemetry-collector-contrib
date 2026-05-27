// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/xreceiver"
	"go.opentelemetry.io/collector/scraper"
	"go.opentelemetry.io/collector/scraper/scraperhelper"
	"go.uber.org/multierr"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/interfacesscraper"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/systemscraper"
)

var scraperFactories = map[component.Type]scraper.Factory{
	component.MustNewType("system"):     systemscraper.NewFactory(),
	component.MustNewType("interfaces"): interfacesscraper.NewFactory(),
}

func NewFactory() receiver.Factory {
	return xreceiver.NewFactory(
		metadata.Type,
		createDefaultConfig,
		xreceiver.WithMetrics(createMetricsReceiver, component.StabilityLevelAlpha),
		xreceiver.WithLogs(createLogsReceiver, component.StabilityLevelAlpha),
		xreceiver.WithDeprecatedTypeAlias(metadata.DeprecatedType),
	)
}

func createDefaultConfig() component.Config {
	cfg := scraperhelper.NewDefaultControllerConfig()
	cfg.Timeout = 30 * time.Second
	cfg.CollectionInterval = 60 * time.Second

	return &Config{
		ControllerConfig: cfg,
		Devices:          []DeviceConfig{},
		DeviceSelection:  DeviceSelectionConfig{},
		Meraki:           defaultMerakiConfig(),
		Intersight:       defaultIntersightConfig(),
		CatalystCenter:   defaultCatalystCenterConfig(),
		SDWAN:            defaultSDWANConfig(),
		NexusDashboard:   defaultNexusDashboardConfig(),
		ACI:              defaultACIConfig(),
		Scrapers:         map[component.Type]component.Config{},
	}
}

func createMetricsReceiver(
	_ context.Context,
	set receiver.Settings,
	cfg component.Config,
	consumer consumer.Metrics,
) (receiver.Metrics, error) {
	conf := cfg.(*Config)
	selector := newDeviceSelectionMatcher(conf.DeviceSelection)
	consumer = newMetricFilteringConsumer(consumer, conf)

	var receivers []receiver.Metrics
	for _, device := range conf.Devices {
		if !selector.allows(sshDeviceIdentity(device)) {
			continue
		}
		connDevice := connection.DeviceConfig{
			Device: connection.DeviceInfo{
				Host: connection.HostInfo{
					Name: device.Name,
					IP:   device.Host,
					Port: device.Port,
				},
			},
			Auth: device.Auth,
		}

		var scraperOptions []scraperhelper.ControllerOption
		for scraperType, scraperCfg := range conf.Scrapers {
			factory, exists := scraperFactories[scraperType]
			if !exists {
				set.Logger.Warn("Unsupported scraper type",
					zap.String("type", scraperType.String()),
					zap.String("device", device.Name))
				continue
			}

			freshCfg := factory.CreateDefaultConfig()

			switch typedCfg := scraperCfg.(type) {
			case *systemscraper.Config:
				freshCfg = cloneSystemScraperConfig(factory, typedCfg, connDevice, conf.Timeout)
			case *interfacesscraper.Config:
				freshCfg = cloneInterfacesScraperConfig(factory, typedCfg, connDevice, conf.Timeout)
			}

			scraperOptions = append(scraperOptions, scraperhelper.AddFactoryWithConfig(factory, freshCfg))
		}

		if len(scraperOptions) == 0 {
			continue
		}

		rcvr, err := scraperhelper.NewMetricsController(
			&conf.ControllerConfig,
			set,
			consumer,
			scraperOptions...,
		)
		if err != nil {
			return nil, err
		}
		receivers = append(receivers, rcvr)
	}

	if conf.Meraki.hasTargets() {
		rcvr, err := newMerakiMetricsReceiver(set, conf, consumer)
		if err != nil {
			return nil, err
		}
		receivers = append(receivers, rcvr)
	}

	if conf.Intersight.hasTarget() {
		rcvr, err := newIntersightMetricsReceiver(set, conf, consumer)
		if err != nil {
			return nil, err
		}
		receivers = append(receivers, rcvr)
	}

	if conf.CatalystCenter.hasTarget() {
		rcvr, err := newCatalystCenterMetricsReceiver(set, conf, consumer)
		if err != nil {
			return nil, err
		}
		receivers = append(receivers, rcvr)
	}

	if conf.SDWAN.hasTarget() {
		rcvr, err := newSDWANMetricsReceiver(set, conf, consumer)
		if err != nil {
			return nil, err
		}
		receivers = append(receivers, rcvr)
	}

	if conf.NexusDashboard.hasTarget() {
		rcvr, err := newNexusDashboardMetricsReceiver(set, conf, consumer)
		if err != nil {
			return nil, err
		}
		receivers = append(receivers, rcvr)
	}

	if conf.ACI.hasTarget() {
		rcvr, err := newACIMetricsReceiver(set, conf, consumer)
		if err != nil {
			return nil, err
		}
		receivers = append(receivers, rcvr)
	}

	if len(receivers) == 0 {
		return &nopMetricsReceiver{}, nil
	}

	if len(receivers) == 1 {
		return receivers[0], nil
	}

	return &multiMetricsReceiver{receivers: receivers}, nil
}

func createLogsReceiver(
	_ context.Context,
	set receiver.Settings,
	cfg component.Config,
	consumer consumer.Logs,
) (receiver.Logs, error) {
	conf := cfg.(*Config)
	var receivers []receiver.Logs
	if conf.Intersight.hasTarget() {
		rcvr, err := newIntersightLogsReceiver(set, conf, consumer)
		if err != nil {
			return nil, err
		}
		receivers = append(receivers, rcvr)
	}
	if conf.SDWAN.hasTarget() {
		rcvr, err := newSDWANLogsReceiver(set, conf, consumer)
		if err != nil {
			return nil, err
		}
		receivers = append(receivers, rcvr)
	}
	if conf.NexusDashboard.hasTarget() {
		rcvr, err := newNexusDashboardLogsReceiver(set, conf, consumer)
		if err != nil {
			return nil, err
		}
		receivers = append(receivers, rcvr)
	}
	if conf.ACI.hasTarget() {
		rcvr, err := newACILogsReceiver(set, conf, consumer)
		if err != nil {
			return nil, err
		}
		receivers = append(receivers, rcvr)
	}
	if len(receivers) == 0 {
		return &nopLogsReceiver{}, nil
	}
	if len(receivers) == 1 {
		return receivers[0], nil
	}
	return &multiLogsReceiver{receivers: receivers}, nil
}

func cloneSystemScraperConfig(factory scraper.Factory, source *systemscraper.Config, device connection.DeviceConfig, timeout time.Duration) *systemscraper.Config {
	cfg := factory.CreateDefaultConfig().(*systemscraper.Config)
	cfg.MetricsBuilderConfig = source.MetricsBuilderConfig
	cfg.ProtocolTraffic = source.ProtocolTraffic
	cfg.ControlPlane = source.ControlPlane
	cfg.RoutingForwarding = source.RoutingForwarding
	cfg.RouterDataplane = source.RouterDataplane
	cfg.HardwareHealth = source.HardwareHealth
	cfg.RoutingNeighbors = source.RoutingNeighbors
	cfg.Fabric = source.Fabric
	cfg.Device = device
	cfg.Timeout = timeout
	return cfg
}

func cloneInterfacesScraperConfig(factory scraper.Factory, source *interfacesscraper.Config, device connection.DeviceConfig, timeout time.Duration) *interfacesscraper.Config {
	cfg := factory.CreateDefaultConfig().(*interfacesscraper.Config)
	cfg.MetricsBuilderConfig = source.MetricsBuilderConfig
	cfg.Rates = source.Rates
	cfg.Counters = source.Counters
	cfg.L2Topology = source.L2Topology
	cfg.Transceiver = source.Transceiver
	cfg.Device = device
	cfg.Timeout = timeout
	return cfg
}

type nopMetricsReceiver struct{}

func (*nopMetricsReceiver) Start(_ context.Context, _ component.Host) error { return nil }
func (*nopMetricsReceiver) Shutdown(_ context.Context) error                { return nil }

type nopLogsReceiver struct{}

func (*nopLogsReceiver) Start(_ context.Context, _ component.Host) error { return nil }
func (*nopLogsReceiver) Shutdown(_ context.Context) error                { return nil }

type multiMetricsReceiver struct {
	receivers []receiver.Metrics
}

func (m *multiMetricsReceiver) Start(ctx context.Context, host component.Host) error {
	var err error
	for _, r := range m.receivers {
		err = multierr.Append(err, r.Start(ctx, host))
	}
	return err
}

func (m *multiMetricsReceiver) Shutdown(ctx context.Context) error {
	var err error
	for _, r := range m.receivers {
		err = multierr.Append(err, r.Shutdown(ctx))
	}
	return err
}

type multiLogsReceiver struct {
	receivers []receiver.Logs
}

func (m *multiLogsReceiver) Start(ctx context.Context, host component.Host) error {
	var err error
	for _, r := range m.receivers {
		err = multierr.Append(err, r.Start(ctx, host))
	}
	return err
}

func (m *multiLogsReceiver) Shutdown(ctx context.Context) error {
	var err error
	for _, r := range m.receivers {
		err = multierr.Append(err, r.Shutdown(ctx))
	}
	return err
}
