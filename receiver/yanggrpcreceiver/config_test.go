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
				tt.config.MaxConcurrentStreams = 100
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
	server.MaxConcurrentStreams = 100
	return server
}

func TestServerResourceLimitValidation(t *testing.T) {
	defaults := createDefaultConfig().(*Config)
	assert.Equal(t, 4, defaults.MaxRecvMsgSizeMiB)
	assert.Equal(t, uint32(100), defaults.MaxConcurrentStreams)
	require.NoError(t, defaults.Validate())

	for _, test := range []struct {
		name      string
		recvMiB   int
		streams   uint32
		errorPart string
	}{
		{name: "minimum", recvMiB: 1, streams: 1},
		{name: "maximum", recvMiB: 16, streams: 1000},
		{name: "zero receive size", recvMiB: 0, streams: 100, errorPart: "max_recv_msg_size_mib must be between 1 and 16"},
		{name: "oversize receive", recvMiB: 17, streams: 100, errorPart: "max_recv_msg_size_mib must be between 1 and 16"},
		{name: "zero streams", recvMiB: 4, streams: 0, errorPart: "max_concurrent_streams must be between 1 and 1000"},
		{name: "too many streams", recvMiB: 4, streams: 1001, errorPart: "max_concurrent_streams must be between 1 and 1000"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := createDefaultConfig().(*Config)
			cfg.MaxRecvMsgSizeMiB = test.recvMiB
			cfg.MaxConcurrentStreams = test.streams
			err := cfg.Validate()
			if test.errorPart == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.errorPart)
		})
	}
}

func TestRemoteListenerSecurityValidation(t *testing.T) {
	remoteServer := configgrpc.NewDefaultServerConfig()
	remoteServer.NetAddr.Endpoint = "0.0.0.0:57500"
	remoteServer.MaxRecvMsgSizeMiB = 4
	remoteServer.MaxConcurrentStreams = 100
	loopbackServer := configgrpc.NewDefaultServerConfig()
	loopbackServer.NetAddr.Endpoint = "127.0.0.1:57500"
	loopbackServer.MaxRecvMsgSizeMiB = 4
	loopbackServer.MaxConcurrentStreams = 100
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
