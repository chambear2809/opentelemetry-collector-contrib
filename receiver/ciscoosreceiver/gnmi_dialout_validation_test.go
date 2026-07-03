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
	remote.MaxConcurrentStreams = defaultGNMIDialOutStreams

	loopback := remote
	loopback.NetAddr.Endpoint = "127.0.0.1:57500"
	require.NoError(t, validateGNMIDialOutConfig(
		loopback,
		nil,
		defaultGNMIDialOutStreamsPerIP,
		yanggrpcreceiver.RateLimitingConfig{},
		gnmiDialOutIdentityLegacy,
		nil,
	))

	err := validateGNMIDialOutConfig(
		remote,
		nil,
		defaultGNMIDialOutStreamsPerIP,
		yanggrpcreceiver.RateLimitingConfig{},
		gnmiDialOutIdentityLegacy,
		nil,
	)
	require.Error(t, err)
	assert.ErrorContains(t, err, "non-loopback listeners require TLS")
	assert.ErrorContains(t, err, "non-loopback listeners require mutual TLS or at least one allowed_clients entry")
	assert.ErrorContains(t, err, "non-loopback listeners require per-message rate limiting")
	assert.ErrorContains(t, err, "non-loopback listeners require identity_verification: required")

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
	identityBindings := []GNMIDialOutIdentityBindingConfig{{
		Sources: []string{"10.0.0.0/8"},
		NodeIDs: []string{"router-1"},
	}}
	require.NoError(t, validateGNMIDialOutConfig(
		secure,
		[]string{"10.0.0.0/8"},
		defaultGNMIDialOutStreamsPerIP,
		rateLimit,
		gnmiDialOutIdentityRequired,
		identityBindings,
	))
	delegated := yanggrpcreceiver.NewFactory().CreateDefaultConfig().(*yanggrpcreceiver.Config)
	delegated.ServerConfig = secure
	allowedClients := []string{"10.0.0.0/8"}
	configureHardenedYangGRPCSecurity(delegated, allowedClients, rateLimit)
	allowedClients[0] = "192.0.2.0/24"
	require.Equal(t, []string{"10.0.0.0/8"}, delegated.Security.AllowedClients)
	require.NoError(t, delegated.Validate(), "delegated YANG runtime must accept the same secure remote-listener contract")

	secure.TLS = configoptional.Some(configtls.ServerConfig{
		Config:       configtls.Config{CertFile: "server.crt", KeyFile: "server.key"},
		ClientCAFile: "client-ca.crt",
	})
	require.NoError(t, validateGNMIDialOutConfig(
		secure,
		nil,
		defaultGNMIDialOutStreamsPerIP,
		rateLimit,
		gnmiDialOutIdentityRequired,
		identityBindings,
	))
}

func TestGNMIDialOutIdentityBindingValidation(t *testing.T) {
	server := configgrpc.NewDefaultServerConfig()
	server.NetAddr.Endpoint = "127.0.0.1:57500"
	server.MaxRecvMsgSizeMiB = 4
	server.MaxConcurrentStreams = defaultGNMIDialOutStreams
	validBinding := GNMIDialOutIdentityBindingConfig{
		Sources: []string{"192.0.2.0/24"},
		NodeIDs: []string{"router-a", "router-b"},
	}

	tests := []struct {
		name        string
		mode        string
		bindings    []GNMIDialOutIdentityBindingConfig
		errContains string
	}{
		{
			name:     "valid required binding",
			mode:     gnmiDialOutIdentityRequired,
			bindings: []GNMIDialOutIdentityBindingConfig{validBinding},
		},
		{
			name:        "invalid verification mode",
			mode:        "optional",
			errContains: "identity_verification must be legacy or required",
		},
		{
			name:        "required without bindings",
			mode:        gnmiDialOutIdentityRequired,
			errContains: "requires at least one identity_bindings entry",
		},
		{
			name:        "legacy with unused bindings",
			mode:        gnmiDialOutIdentityLegacy,
			bindings:    []GNMIDialOutIdentityBindingConfig{validBinding},
			errContains: "identity_bindings require identity_verification: required",
		},
		{
			name: "empty source selector",
			mode: gnmiDialOutIdentityRequired,
			bindings: []GNMIDialOutIdentityBindingConfig{{
				Sources: []string{""},
				NodeIDs: []string{"router-a"},
			}},
			errContains: "sources[0] must not be empty",
		},
		{
			name: "malformed CIDR",
			mode: gnmiDialOutIdentityRequired,
			bindings: []GNMIDialOutIdentityBindingConfig{{
				Sources: []string{"192.0.2.0/99"},
				NodeIDs: []string{"router-a"},
			}},
			errContains: "must be an IP address or CIDR",
		},
		{
			name: "zoned IPv6 source",
			mode: gnmiDialOutIdentityRequired,
			bindings: []GNMIDialOutIdentityBindingConfig{{
				Sources: []string{"fe80::1%eth0"},
				NodeIDs: []string{"router-a"},
			}},
			errContains: "scoped IPv6 zones are not supported",
		},
		{
			name: "IPv6 link-local source",
			mode: gnmiDialOutIdentityRequired,
			bindings: []GNMIDialOutIdentityBindingConfig{{
				Sources: []string{"fe80::/10"},
				NodeIDs: []string{"router-a"},
			}},
			errContains: "link-local source selectors are not supported",
		},
		{
			name: "IPv4 link-local source",
			mode: gnmiDialOutIdentityRequired,
			bindings: []GNMIDialOutIdentityBindingConfig{{
				Sources: []string{"169.254.10.20"},
				NodeIDs: []string{"router-a"},
			}},
			errContains: "link-local source selectors are not supported",
		},
		{
			name: "unspecified source",
			mode: gnmiDialOutIdentityRequired,
			bindings: []GNMIDialOutIdentityBindingConfig{{
				Sources: []string{"0.0.0.0"},
				NodeIDs: []string{"router-a"},
			}},
			errContains: "global-unicast or loopback addresses",
		},
		{
			name: "multicast source prefix",
			mode: gnmiDialOutIdentityRequired,
			bindings: []GNMIDialOutIdentityBindingConfig{{
				Sources: []string{"224.0.0.0/4"},
				NodeIDs: []string{"router-a"},
			}},
			errContains: "global-unicast or loopback addresses",
		},
		{
			name: "duplicate normalized source selector",
			mode: gnmiDialOutIdentityRequired,
			bindings: []GNMIDialOutIdentityBindingConfig{{
				Sources: []string{"192.0.2.10", "192.0.2.10/32"},
				NodeIDs: []string{"router-a"},
			}},
			errContains: "duplicates source selector",
		},
		{
			name: "empty node ID",
			mode: gnmiDialOutIdentityRequired,
			bindings: []GNMIDialOutIdentityBindingConfig{{
				Sources: []string{"192.0.2.10"},
				NodeIDs: []string{""},
			}},
			errContains: "node_ids[0] must not be empty",
		},
		{
			name: "duplicate node ID",
			mode: gnmiDialOutIdentityRequired,
			bindings: []GNMIDialOutIdentityBindingConfig{{
				Sources: []string{"192.0.2.10"},
				NodeIDs: []string{"router-a", "router-a"},
			}},
			errContains: "duplicates node ID within the binding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGNMIDialOutConfig(
				server,
				nil,
				defaultGNMIDialOutStreamsPerIP,
				yanggrpcreceiver.RateLimitingConfig{},
				tt.mode,
				tt.bindings,
			)
			if tt.errContains == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestGNMIDialOutRequiredIdentityRejectsNonTCPTransport(t *testing.T) {
	server := configgrpc.NewDefaultServerConfig()
	server.NetAddr.Transport = "unix"
	server.NetAddr.Endpoint = "/tmp/ciscoos-identity-test.sock"
	server.MaxRecvMsgSizeMiB = 4
	server.MaxConcurrentStreams = defaultGNMIDialOutStreams

	err := validateGNMIDialOutConfig(
		server,
		nil,
		defaultGNMIDialOutStreamsPerIP,
		yanggrpcreceiver.RateLimitingConfig{},
		gnmiDialOutIdentityRequired,
		[]GNMIDialOutIdentityBindingConfig{{
			Sources: []string{"127.0.0.1"},
			NodeIDs: []string{"router-a"},
		}},
	)
	require.ErrorContains(t, err, "identity_verification: required requires tcp, tcp4, or tcp6 transport")
}

func TestGNMIDialOutIPSecurityRejectsNonTCPTransport(t *testing.T) {
	server := configgrpc.NewDefaultServerConfig()
	server.NetAddr.Transport = "unix"
	server.NetAddr.Endpoint = "/tmp/ciscoos-ip-security-test.sock"
	server.MaxRecvMsgSizeMiB = 4
	server.MaxConcurrentStreams = defaultGNMIDialOutStreams

	require.NoError(t, validateGNMIDialOutConfig(
		server,
		nil,
		defaultGNMIDialOutStreamsPerIP,
		yanggrpcreceiver.RateLimitingConfig{},
		gnmiDialOutIdentityLegacy,
		nil,
	), "a legacy Unix listener without IP-based controls remains supported")

	for name, controls := range map[string]struct {
		allowed []string
		rate    yanggrpcreceiver.RateLimitingConfig
	}{
		"allowlist": {allowed: []string{"127.0.0.1"}},
		"rate limiting": {rate: yanggrpcreceiver.RateLimitingConfig{
			Enabled: true, RequestsPerSecond: 1, BurstSize: 1, CleanupInterval: time.Minute,
		}},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateGNMIDialOutConfig(
				server,
				controls.allowed,
				defaultGNMIDialOutStreamsPerIP,
				controls.rate,
				gnmiDialOutIdentityLegacy,
				nil,
			)
			require.ErrorContains(t, err, "requires tcp, tcp4, or tcp6 transport")
		})
	}
}

func TestGNMIDialOutIdentityBindingBounds(t *testing.T) {
	tests := []struct {
		name        string
		bindings    []GNMIDialOutIdentityBindingConfig
		errContains string
	}{
		{
			name:        "binding count",
			bindings:    make([]GNMIDialOutIdentityBindingConfig, maxGNMIDialOutIdentityBindings+1),
			errContains: "identity_bindings must contain at most 256 entries",
		},
		{
			name: "sources per binding",
			bindings: []GNMIDialOutIdentityBindingConfig{{
				Sources: make([]string, maxGNMIDialOutIdentitySourcesPerBind+1),
				NodeIDs: []string{"router-a"},
			}},
			errContains: "sources must contain at most 64 entries",
		},
		{
			name: "node IDs per binding",
			bindings: []GNMIDialOutIdentityBindingConfig{{
				Sources: []string{"192.0.2.10"},
				NodeIDs: make([]string, maxGNMIDialOutIdentityNodeIDsPerBind+1),
			}},
			errContains: "node_ids must contain at most 64 entries",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := compileGNMIDialOutIdentityVerifier(gnmiDialOutIdentityRequired, tt.bindings)
			require.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestGNMIDialOutOmittedPerClientStreamCapTracksGlobalCap(t *testing.T) {
	server := configgrpc.NewDefaultServerConfig()
	server.NetAddr.Endpoint = "localhost:57500"
	server.MaxRecvMsgSizeMiB = 4
	server.MaxConcurrentStreams = 1

	require.Equal(t, uint32(1), effectiveGNMIDialOutMaxStreamsPerClient(0, server.MaxConcurrentStreams))
	require.NoError(t, validateGNMIDialOutConfig(
		server,
		nil,
		0,
		yanggrpcreceiver.RateLimitingConfig{},
		gnmiDialOutIdentityLegacy,
		nil,
	))
	require.ErrorContains(
		t,
		validateGNMIDialOutConfig(
			server,
			nil,
			2,
			yanggrpcreceiver.RateLimitingConfig{},
			gnmiDialOutIdentityLegacy,
			nil,
		),
		"max_streams_per_client must be between 1 and max_concurrent_streams (1)",
	)
}

func TestGNMIDialOutValidationRejectsUnsafeDependencyValues(t *testing.T) {
	server := configgrpc.NewDefaultServerConfig()
	server.NetAddr.Endpoint = "localhost:57500"
	server.MaxRecvMsgSizeMiB = 4
	server.MaxConcurrentStreams = defaultGNMIDialOutStreams
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
			name: "aggregate decoded frame ceiling exceeded",
			mutate: func(server *configgrpc.ServerConfig, _ *yanggrpcreceiver.RateLimitingConfig) {
				server.MaxConcurrentStreams = defaultGNMIDialOutStreams + 1
			},
			errContains: "max_concurrent_streams multiplied by max_recv_msg_size_mib must not exceed 256 MiB",
		},
		{
			name:                "per-client streams exceed global limit",
			maxStreamsPerClient: defaultGNMIDialOutStreams + 1,
			errContains:         "max_streams_per_client must be between 1 and max_concurrent_streams (64)",
		},
		{
			name:        "invalid allowlist entry",
			allowed:     []string{"not-an-address"},
			errContains: "allowed_clients[0] must be an IP address or CIDR",
		},
		{
			name:        "non-unicast allowlist entry",
			allowed:     []string{"ff00::/8"},
			errContains: "allowed_clients[0] source selectors must use global-unicast or loopback addresses",
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
				validateGNMIDialOutConfig(
					candidateServer,
					tt.allowed,
					candidateMaxStreamsPerClient,
					candidateRateLimit,
					gnmiDialOutIdentityLegacy,
					nil,
				),
				tt.errContains,
			)
		})
	}
}
