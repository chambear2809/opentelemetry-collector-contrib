// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package yanggrpcreceiver

import (
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/confmap/confmaptest"
)

func TestRuntimeHardeningVersion(t *testing.T) {
	cfg := &Config{}
	assert.Equal(t, 2, cfg.RuntimeHardeningVersion())
	cfg.SetMaxConcurrentStreamsPerClient(7)
	assert.Equal(t, uint32(7), cfg.MaxConcurrentStreamsPerClient)
}

func TestSecurityConfig_Validation(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid security config",
			config: &Config{
				ServerConfig: validTestServerConfig(),
				Security: SecurityConfig{
					RateLimiting: RateLimitingConfig{
						Enabled:           true,
						RequestsPerSecond: 100.0,
						BurstSize:         10,
						CleanupInterval:   time.Minute,
					},
				},
			},
			expectError: false,
		},
		{
			name: "Invalid rate limiting - negative requests per second",
			config: &Config{
				Security: SecurityConfig{
					RateLimiting: RateLimitingConfig{
						Enabled:           true,
						RequestsPerSecond: -1.0,
						BurstSize:         10,
					},
				},
				ServerConfig: configgrpc.NewDefaultServerConfig(),
			},
			expectError: true,
			errorMsg:    "requests_per_second must be positive",
		},
		{
			name: "Invalid rate limiting - NaN requests per second",
			config: &Config{
				Security: SecurityConfig{RateLimiting: RateLimitingConfig{
					Enabled:           true,
					RequestsPerSecond: math.NaN(),
					BurstSize:         10,
					CleanupInterval:   time.Minute,
				}},
				ServerConfig: configgrpc.NewDefaultServerConfig(),
			},
			expectError: true,
			errorMsg:    "requests_per_second must be positive",
		},
		{
			name: "Invalid rate limiting - infinite requests per second",
			config: &Config{
				Security: SecurityConfig{RateLimiting: RateLimitingConfig{
					Enabled:           true,
					RequestsPerSecond: math.Inf(1),
					BurstSize:         10,
					CleanupInterval:   time.Minute,
				}},
				ServerConfig: configgrpc.NewDefaultServerConfig(),
			},
			expectError: true,
			errorMsg:    "requests_per_second must be positive and finite",
		},
		{
			name: "Invalid rate limiting - zero burst",
			config: &Config{
				Security: SecurityConfig{RateLimiting: RateLimitingConfig{
					Enabled:           true,
					RequestsPerSecond: 1,
					CleanupInterval:   time.Minute,
				}},
				ServerConfig: configgrpc.NewDefaultServerConfig(),
			},
			expectError: true,
			errorMsg:    "burst_size must be positive",
		},
		{
			name: "Invalid rate limiting - zero cleanup interval",
			config: &Config{
				Security: SecurityConfig{RateLimiting: RateLimitingConfig{
					Enabled:           true,
					RequestsPerSecond: 1,
					BurstSize:         1,
				}},
				ServerConfig: configgrpc.NewDefaultServerConfig(),
			},
			expectError: true,
			errorMsg:    "cleanup_interval must be positive",
		},
		{
			name: "Invalid rate limiting - cleanup interval too short",
			config: &Config{
				Security: SecurityConfig{RateLimiting: RateLimitingConfig{
					Enabled:           true,
					RequestsPerSecond: 1,
					BurstSize:         1,
					CleanupInterval:   time.Millisecond,
				}},
				ServerConfig: configgrpc.NewDefaultServerConfig(),
			},
			expectError: true,
			errorMsg:    "cleanup_interval must be at least 1s",
		},
		{
			name: "Invalid allowed client",
			config: &Config{
				Security:     SecurityConfig{AllowedClients: []string{"not-an-ip"}},
				ServerConfig: configgrpc.NewDefaultServerConfig(),
			},
			expectError: true,
			errorMsg:    "allowed_clients[0] must be an IP address or CIDR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config.MaxRecvMsgSizeMiB == 0 {
				tt.config.MaxRecvMsgSizeMiB = 4
			}
			if tt.config.MaxConcurrentStreams == 0 {
				tt.config.MaxConcurrentStreams = defaultMaxConcurrentStreams
			}
			err := tt.config.Validate()
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfigs(t *testing.T) {
	cm, err := confmaptest.LoadConf(filepath.Join("testdata", "config.yaml"))
	require.NoError(t, err)
	for _, test := range []struct {
		name string
	}{
		{
			"yang_grpc/production",
		},
		{
			"yang_grpc/default",
		},
	} {
		c, err := cm.Sub(test.name)
		require.NoError(t, err)
		var cfg Config
		require.NoError(t, c.Unmarshal(&cfg))
		require.NoError(t, cfg.Validate())
	}
}

func validTestServerConfig() configgrpc.ServerConfig {
	server := configgrpc.NewDefaultServerConfig()
	server.NetAddr.Endpoint = "localhost:57500"
	server.MaxRecvMsgSizeMiB = 4
	server.MaxConcurrentStreams = defaultMaxConcurrentStreams
	return server
}

func TestServerResourceLimitValidation(t *testing.T) {
	defaults := createDefaultConfig().(*Config)
	assert.Equal(t, 4, defaults.MaxRecvMsgSizeMiB)
	assert.Equal(t, uint32(defaultMaxConcurrentStreams), defaults.MaxConcurrentStreams)
	assert.Equal(t, uint32(defaultMaxConnections), defaults.MaxConnections)
	assert.Zero(t, defaults.MaxConcurrentStreamsPerClient)
	assert.Equal(t, defaultMaxStreamsPerClient, effectiveMaxConcurrentStreamsPerClient(
		defaults.MaxConcurrentStreamsPerClient,
		defaults.MaxConcurrentStreams,
	))
	assert.Equal(t, uint32(defaultMaxConcurrentConversions), defaults.MaxConcurrentConversions)
	assert.Equal(t, defaultConnectionTimeout, defaults.ConnectionTimeout)
	assert.Equal(t, defaultMaxConnectionIdle, defaults.Keepalive.GetOrInsertDefault().ServerParameters.GetOrInsertDefault().MaxConnectionIdle)
	require.NoError(t, defaults.Validate())

	for _, test := range []struct {
		name             string
		recvMiB          int
		streams          uint32
		streamsPerClient uint32
		errorPart        string
	}{
		{name: "minimum", recvMiB: 1, streams: 1, streamsPerClient: 1},
		{name: "aggregate ceiling", recvMiB: 16, streams: 16},
		{name: "aggregate ceiling exceeded", recvMiB: 4, streams: 65, errorPart: "max_concurrent_streams multiplied by max_recv_msg_size_mib must not exceed 256 MiB"},
		{name: "zero receive size", recvMiB: 0, streams: 100, errorPart: "max_recv_msg_size_mib must be between 1 and 16"},
		{name: "oversize receive", recvMiB: 17, streams: 100, errorPart: "max_recv_msg_size_mib must be between 1 and 16"},
		{name: "zero streams", recvMiB: 4, streams: 0, errorPart: "max_concurrent_streams must be between 1 and 1000"},
		{name: "too many streams", recvMiB: 4, streams: 1001, errorPart: "max_concurrent_streams must be between 1 and 1000"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := createDefaultConfig().(*Config)
			cfg.MaxRecvMsgSizeMiB = test.recvMiB
			cfg.MaxConcurrentStreams = test.streams
			if test.streamsPerClient != 0 {
				cfg.MaxConcurrentStreamsPerClient = test.streamsPerClient
			}
			err := cfg.Validate()
			if test.errorPart == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.errorPart)
		})
	}

	cfg := createDefaultConfig().(*Config)
	cfg.MaxConcurrentStreamsPerClient = maxMaxConcurrentStreams + 1
	require.ErrorContains(t, cfg.Validate(), "max_concurrent_streams_per_client must not exceed 1000")
	assert.Equal(t, defaultMaxStreamsPerClient, effectiveMaxConcurrentStreamsPerClient(0, defaultMaxConcurrentStreams))
	assert.Equal(t, 4, effectiveMaxConcurrentStreamsPerClient(0, 4))

	cfg = createDefaultConfig().(*Config)
	cfg.MaxConcurrentStreams = 4
	require.NoError(t, cfg.Validate(), "the omitted per-client limit must follow a lower global limit")
	cfg.MaxConcurrentStreamsPerClient = 5
	require.ErrorContains(t, cfg.Validate(), "max_concurrent_streams_per_client must not exceed max_concurrent_streams")
}

func TestRuntimeAvailabilityValidation(t *testing.T) {
	for _, test := range []struct {
		name                  string
		maxConnections        uint32
		maxConversions        uint32
		connectionTimeout     time.Duration
		wantEffectiveConns    int
		wantEffectiveConverts int
		wantEffectiveTimeout  time.Duration
		errorPart             string
	}{
		{
			name:                  "zero values select bounded defaults",
			wantEffectiveConns:    defaultMaxConnections,
			wantEffectiveConverts: defaultMaxConcurrentConversions,
			wantEffectiveTimeout:  defaultConnectionTimeout,
		},
		{
			name:                  "minimum configured values",
			maxConnections:        1,
			maxConversions:        1,
			connectionTimeout:     minConnectionTimeout,
			wantEffectiveConns:    1,
			wantEffectiveConverts: 1,
			wantEffectiveTimeout:  minConnectionTimeout,
		},
		{
			name:                  "maximum configured values",
			maxConnections:        maxMaxConnections,
			maxConversions:        maxMaxConcurrentConversions,
			connectionTimeout:     maxConnectionTimeout,
			wantEffectiveConns:    maxMaxConnections,
			wantEffectiveConverts: maxMaxConcurrentConversions,
			wantEffectiveTimeout:  maxConnectionTimeout,
		},
		{
			name:           "too many connections",
			maxConnections: maxMaxConnections + 1,
			errorPart:      "max_connections must not exceed 1024",
		},
		{
			name:           "too many conversions",
			maxConversions: maxMaxConcurrentConversions + 1,
			errorPart:      "max_concurrent_conversions must not exceed 16",
		},
		{
			name:              "connection timeout too short",
			connectionTimeout: minConnectionTimeout - time.Nanosecond,
			errorPart:         "connection_timeout must be zero or between 1s and 2m0s",
		},
		{
			name:              "connection timeout too long",
			connectionTimeout: maxConnectionTimeout + time.Nanosecond,
			errorPart:         "connection_timeout must be zero or between 1s and 2m0s",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := createDefaultConfig().(*Config)
			cfg.MaxConnections = test.maxConnections
			cfg.MaxConcurrentConversions = test.maxConversions
			cfg.ConnectionTimeout = test.connectionTimeout

			err := cfg.Validate()
			if test.errorPart != "" {
				require.ErrorContains(t, err, test.errorPart)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.wantEffectiveConns, effectiveMaxConnections(cfg.MaxConnections))
			assert.Equal(t, test.wantEffectiveConverts, effectiveMaxConcurrentConversions(cfg.MaxConcurrentConversions))
			assert.Equal(t, test.wantEffectiveTimeout, effectiveConnectionTimeout(cfg.ConnectionTimeout))
		})
	}
}

func TestRemoteListenerSecurityValidation(t *testing.T) {
	remoteServer := configgrpc.NewDefaultServerConfig()
	remoteServer.NetAddr.Endpoint = "0.0.0.0:57500"
	remoteServer.MaxRecvMsgSizeMiB = 4
	remoteServer.MaxConcurrentStreams = defaultMaxConcurrentStreams
	loopbackServer := configgrpc.NewDefaultServerConfig()
	loopbackServer.NetAddr.Endpoint = "127.0.0.1:57500"
	loopbackServer.MaxRecvMsgSizeMiB = 4
	loopbackServer.MaxConcurrentStreams = defaultMaxConcurrentStreams
	secureRemoteServer := remoteServer
	secureRemoteServer.TLS = configoptional.Some(configtls.ServerConfig{
		Config: configtls.Config{
			CertFile: "server.crt",
			KeyFile:  "server.key",
		},
	})
	secureRemoteMTLSServer := secureRemoteServer
	secureRemoteMTLSServer.TLS = configoptional.Some(configtls.ServerConfig{
		Config: configtls.Config{
			CertFile: "server.crt",
			KeyFile:  "server.key",
		},
		ClientCAFile: "client-ca.crt",
	})
	rateLimiting := RateLimitingConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		BurstSize:         10,
		CleanupInterval:   time.Minute,
	}

	tests := []struct {
		name       string
		config     Config
		errorParts []string
	}{
		{
			name:   "loopback may use local development defaults",
			config: Config{ServerConfig: loopbackServer},
		},
		{
			name:   "remote plaintext unrestricted listener is rejected",
			config: Config{ServerConfig: remoteServer},
			errorParts: []string{
				"non-loopback listeners require TLS",
				"non-loopback listeners require mutual TLS or at least one allowed_clients entry",
				"non-loopback listeners require per-message rate limiting",
			},
		},
		{
			name: "remote TLS listener with allowlist and rate limiting",
			config: Config{
				ServerConfig: secureRemoteServer,
				Security: SecurityConfig{
					AllowedClients: []string{"10.0.0.0/8"},
					RateLimiting:   rateLimiting,
				},
			},
		},
		{
			name: "remote mutual TLS listener with rate limiting",
			config: Config{
				ServerConfig: secureRemoteMTLSServer,
				Security: SecurityConfig{
					RateLimiting: rateLimiting,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if len(tt.errorParts) == 0 {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			for _, part := range tt.errorParts {
				assert.ErrorContains(t, err, part)
			}
		})
	}
}
