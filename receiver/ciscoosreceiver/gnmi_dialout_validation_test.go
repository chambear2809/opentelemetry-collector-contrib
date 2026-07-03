// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/config/configtls"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver"
)

func TestGNMIDialOutValidationOwnsDependencySecurityContract(t *testing.T) {
	remote := configgrpc.NewDefaultServerConfig()
	remote.NetAddr.Endpoint = "0.0.0.0:57500"
	remote.MaxRecvMsgSizeMiB = 4
	remote.MaxConcurrentStreams = 100

	loopback := remote
	loopback.NetAddr.Endpoint = "127.0.0.1:57500"
	require.NoError(t, validateGNMIDialOutConfig(loopback, nil, defaultGNMIDialOutStreamsPerIP, yanggrpcreceiver.RateLimitingConfig{}))

	err := validateGNMIDialOutConfig(remote, nil, defaultGNMIDialOutStreamsPerIP, yanggrpcreceiver.RateLimitingConfig{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "non-loopback listeners require TLS")
	assert.ErrorContains(t, err, "non-loopback listeners require mutual TLS or at least one allowed_clients entry")
	assert.ErrorContains(t, err, "non-loopback listeners require per-message rate limiting")

	secure := remote
	secure.TLS = configoptional.Some(configtls.ServerConfig{Config: configtls.Config{
		CertFile: "server.crt",
		KeyFile:  "server.key",
	}})
	rateLimit := yanggrpcreceiver.RateLimitingConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		BurstSize:         10,
		CleanupInterval:   time.Minute,
	}
	require.NoError(t, validateGNMIDialOutConfig(secure, []string{"10.0.0.0/8"}, defaultGNMIDialOutStreamsPerIP, rateLimit))

	secure.TLS = configoptional.Some(configtls.ServerConfig{
		Config:       configtls.Config{CertFile: "server.crt", KeyFile: "server.key"},
		ClientCAFile: "client-ca.crt",
	})
	require.NoError(t, validateGNMIDialOutConfig(secure, nil, defaultGNMIDialOutStreamsPerIP, rateLimit))
}

func TestGNMIDialOutOmittedPerClientStreamCapTracksGlobalCap(t *testing.T) {
	server := configgrpc.NewDefaultServerConfig()
	server.NetAddr.Endpoint = "localhost:57500"
	server.MaxRecvMsgSizeMiB = 4
	server.MaxConcurrentStreams = 1

	require.Equal(t, uint32(1), effectiveGNMIDialOutMaxStreamsPerClient(0, server.MaxConcurrentStreams))
	require.NoError(t, validateGNMIDialOutConfig(server, nil, 0, yanggrpcreceiver.RateLimitingConfig{}))
	require.ErrorContains(
		t,
		validateGNMIDialOutConfig(server, nil, 2, yanggrpcreceiver.RateLimitingConfig{}),
		"max_streams_per_client must be between 1 and max_concurrent_streams (1)",
	)
}

func TestGNMIDialOutValidationRejectsUnsafeDependencyValues(t *testing.T) {
	server := configgrpc.NewDefaultServerConfig()
	server.NetAddr.Endpoint = "localhost:57500"
	server.MaxRecvMsgSizeMiB = 4
	server.MaxConcurrentStreams = 100
	validRateLimit := yanggrpcreceiver.RateLimitingConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		BurstSize:         10,
		CleanupInterval:   time.Minute,
	}

	tests := []struct {
		name                string
		mutate              func(*configgrpc.ServerConfig, *yanggrpcreceiver.RateLimitingConfig)
		allowed             []string
		maxStreamsPerClient uint32
		errContains         string
	}{
		{
			name: "receive size below minimum",
			mutate: func(server *configgrpc.ServerConfig, _ *yanggrpcreceiver.RateLimitingConfig) {
				server.MaxRecvMsgSizeMiB = 0
			},
			errContains: "max_recv_msg_size_mib must be between 1 and 16",
		},
		{
			name: "receive size above maximum",
			mutate: func(server *configgrpc.ServerConfig, _ *yanggrpcreceiver.RateLimitingConfig) {
				server.MaxRecvMsgSizeMiB = 17
			},
			errContains: "max_recv_msg_size_mib must be between 1 and 16",
		},
		{
			name: "streams below minimum",
			mutate: func(server *configgrpc.ServerConfig, _ *yanggrpcreceiver.RateLimitingConfig) {
				server.MaxConcurrentStreams = 0
			},
			errContains: "max_concurrent_streams must be between 1 and 1000",
		},
		{
			name: "streams above maximum",
			mutate: func(server *configgrpc.ServerConfig, _ *yanggrpcreceiver.RateLimitingConfig) {
				server.MaxConcurrentStreams = 1001
			},
			errContains: "max_concurrent_streams must be between 1 and 1000",
		},
		{
			name:                "per-client streams exceed global limit",
			maxStreamsPerClient: 101,
			errContains:         "max_streams_per_client must be between 1 and max_concurrent_streams (100)",
		},
		{
			name:        "invalid allowlist entry",
			allowed:     []string{"not-an-address"},
			errContains: "allowed_clients[0] must be an IP address or CIDR",
		},
		{
			name: "zero burst",
			mutate: func(_ *configgrpc.ServerConfig, rate *yanggrpcreceiver.RateLimitingConfig) {
				rate.BurstSize = 0
			},
			errContains: "burst_size must be positive",
		},
		{
			name: "non-finite request rate",
			mutate: func(_ *configgrpc.ServerConfig, rate *yanggrpcreceiver.RateLimitingConfig) {
				rate.RequestsPerSecond = math.Inf(1)
			},
			errContains: "requests_per_second must be positive and finite",
		},
		{
			name: "zero cleanup interval",
			mutate: func(_ *configgrpc.ServerConfig, rate *yanggrpcreceiver.RateLimitingConfig) {
				rate.CleanupInterval = 0
			},
			errContains: "cleanup_interval must be positive",
		},
		{
			name: "cleanup interval too short",
			mutate: func(_ *configgrpc.ServerConfig, rate *yanggrpcreceiver.RateLimitingConfig) {
				rate.CleanupInterval = time.Millisecond
			},
			errContains: "cleanup_interval must be at least 1s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidateServer := server
			candidateRateLimit := validRateLimit
			candidateMaxStreamsPerClient := uint32(defaultGNMIDialOutStreamsPerIP)
			if tt.maxStreamsPerClient > 0 {
				candidateMaxStreamsPerClient = tt.maxStreamsPerClient
			}
			if tt.mutate != nil {
				tt.mutate(&candidateServer, &candidateRateLimit)
			}
			require.ErrorContains(t,
				validateGNMIDialOutConfig(candidateServer, tt.allowed, candidateMaxStreamsPerClient, candidateRateLimit),
				tt.errContains,
			)
		})
	}
}
