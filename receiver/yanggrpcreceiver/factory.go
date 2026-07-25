// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package yanggrpcreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver"

import (
	"context"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/xreceiver"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver/internal/metadata"
)

func NewFactory() receiver.Factory {
	return xreceiver.NewFactory(
		metadata.Type,
		createDefaultConfig,
		xreceiver.WithMetrics(func(ctx context.Context, settings receiver.Settings, config component.Config, metrics consumer.Metrics) (receiver.Metrics, error) {
			return createMetricsReceiver(ctx, settings, config, metrics), nil
		}, metadata.MetricsStability),
		xreceiver.WithDeprecatedTypeAlias(metadata.DeprecatedType),
	)
}

func createDefaultConfig() component.Config {
	config := &Config{
		ServerConfig:             configgrpc.NewDefaultServerConfig(),
		MaxConnections:           defaultMaxConnections,
		MaxConcurrentConversions: defaultMaxConcurrentConversions,
		ConnectionTimeout:        defaultConnectionTimeout,
		StreamIdleTimeout:        defaultStreamIdleTimeout,
		Security: SecurityConfig{
			RateLimiting: RateLimitingConfig{
				Enabled:           false,
				RequestsPerSecond: 100.0,
				BurstSize:         10,
				CleanupInterval:   time.Minute,
			},
		},
	}
	config.ServerConfig.NetAddr.Transport = "tcp"
	config.ServerConfig.NetAddr.Endpoint = "localhost:57500"
	config.ServerConfig.MaxRecvMsgSizeMiB = 4
	config.ServerConfig.MaxConcurrentStreams = defaultMaxConcurrentStreams
	config.ServerConfig.Keepalive.GetOrInsertDefault().ServerParameters.GetOrInsertDefault().MaxConnectionIdle = defaultMaxConnectionIdle
	config.ServerConfig.Keepalive.GetOrInsertDefault().ServerParameters.GetOrInsertDefault().Time = 30 * time.Second
	config.ServerConfig.Keepalive.GetOrInsertDefault().ServerParameters.GetOrInsertDefault().Timeout = 10 * time.Second

	return config
}
