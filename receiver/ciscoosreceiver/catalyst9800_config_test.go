// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/confmap"
)

func validCatalyst9800Config() *Config {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.Catalyst9800.Enabled = true
	cfg.Catalyst9800.DialIn.Targets = []Catalyst9800TargetConfig{{
		ClientConfig: configgrpc.ClientConfig{Endpoint: "10.0.0.20:57400"},
		Name:         "wlc-9800-1",
		Credentials: Catalyst9800CredentialsConfig{
			Username: "admin",
			Password: configopaque.String("password"),
		},
	}}
	return cfg
}

func TestCatalyst9800DefaultConfigUsesSafeWirelessCoverage(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig().(*Config)

	assert.False(t, cfg.Catalyst9800.Enabled)
	assert.Equal(t, iosXRUnsupportedWarn, cfg.Catalyst9800.UnsupportedPathAction)
	assert.Equal(t, []string{"json_ietf", "json"}, cfg.Catalyst9800.EncodingPreference)
	assert.Equal(t, iosXRSubscribeModeStream, cfg.Catalyst9800.Subscription.Mode)
	assert.Equal(t, iosXRStreamModeSample, cfg.Catalyst9800.Subscription.StreamMode)
	assert.Equal(t, time.Minute, cfg.Catalyst9800.Subscription.SampleInterval)
	assert.Equal(t, time.Minute, cfg.Catalyst9800.Subscription.HeartbeatInterval)
	assert.True(t, cfg.Catalyst9800.Subscription.suppressRedundant())
	assert.False(t, cfg.Catalyst9800.Subscription.updatesOnly())
	assert.False(t, cfg.Catalyst9800.Subscription.allowAggregation())
	assert.Equal(t, directGNMIDefaultMaxDatapoints, cfg.Catalyst9800.MaxDatapointsPerBatch)
	assert.Zero(t, cfg.Catalyst9800.DialOut.MaxStreamsPerClient)
	assert.Equal(t, uint32(defaultGNMIDialOutStreamsPerIP), cfg.Catalyst9800.withDefaults().DialOut.MaxStreamsPerClient)
	assert.Equal(t, 100.0, cfg.Catalyst9800.DialOut.RateLimiting.RequestsPerSecond)
	assert.Equal(t, 10, cfg.Catalyst9800.DialOut.RateLimiting.BurstSize)
	assert.Equal(t, time.Minute, cfg.Catalyst9800.DialOut.RateLimiting.CleanupInterval)

	for _, group := range []string{"ap", "rf", "ssid", "mobility", "ha", "auth_summary", "controller_system"} {
		assert.True(t, cfg.Catalyst9800.PathGroups[group].Enabled, "path group %s should be enabled by default", group)
	}
	for _, group := range []string{"client_detail", "capwap_packets", "neighbors"} {
		assert.False(t, cfg.Catalyst9800.PathGroups[group].Enabled, "path group %s should be opt-in", group)
	}
}

func TestCatalyst9800ConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*Config)
		expectedErr string
	}{
		{
			name: "valid dial in",
		},
		{
			name: "valid dial out only",
			mutate: func(cfg *Config) {
				cfg.Catalyst9800.DialIn.Targets = nil
				cfg.Catalyst9800.DialOut.Enabled = true
			},
		},
		{
			name: "omitted per-client cap follows a lower existing global cap",
			mutate: func(cfg *Config) {
				cfg.Catalyst9800.DialIn.Targets = nil
				cfg.Catalyst9800.DialOut.Enabled = true
				cfg.Catalyst9800.DialOut.MaxConcurrentStreams = 1
				cfg.Catalyst9800.DialOut.MaxStreamsPerClient = 0
			},
		},
		{
			name: "invalid dial out rate limit",
			mutate: func(cfg *Config) {
				cfg.Catalyst9800.DialOut.Enabled = true
				cfg.Catalyst9800.DialOut.RateLimiting.Enabled = true
				cfg.Catalyst9800.DialOut.RateLimiting.CleanupInterval = -time.Second
			},
			expectedErr: "catalyst_9800.dial_out: cleanup_interval must be positive",
		},
		{
			name: "dial out receive size exceeds YANG receiver cap",
			mutate: func(cfg *Config) {
				cfg.Catalyst9800.DialIn.Targets = nil
				cfg.Catalyst9800.DialOut.Enabled = true
				cfg.Catalyst9800.DialOut.MaxRecvMsgSizeMiB = 17
			},
			expectedErr: "catalyst_9800.dial_out: max_recv_msg_size_mib must be between 1 and 16",
		},
		{
			name: "dial out concurrent streams exceed YANG receiver cap",
			mutate: func(cfg *Config) {
				cfg.Catalyst9800.DialIn.Targets = nil
				cfg.Catalyst9800.DialOut.Enabled = true
				cfg.Catalyst9800.DialOut.MaxConcurrentStreams = 1001
			},
			expectedErr: "catalyst_9800.dial_out: max_concurrent_streams must be between 1 and 1000",
		},
		{
			name: "target requires enabled Catalyst 9800",
			mutate: func(cfg *Config) {
				cfg.Catalyst9800.Enabled = false
			},
			expectedErr: "catalyst_9800.enabled must be true",
		},
		{
			name: "invalid endpoint",
			mutate: func(cfg *Config) {
				cfg.Catalyst9800.DialIn.Targets[0].Endpoint = "10.0.0.20"
			},
			expectedErr: "endpoint must be host:port",
		},
		{
			name: "invalid gRPC client option",
			mutate: func(cfg *Config) {
				cfg.Catalyst9800.DialIn.Targets[0].BalancerName = "not_registered"
			},
			expectedErr: "invalid balancer_name",
		},
		{
			name: "plaintext gNMI credentials are rejected",
			mutate: func(cfg *Config) {
				cfg.Catalyst9800.DialIn.Targets[0].TLS.Insecure = true
			},
			expectedErr: "tls.insecure must be false because gNMI credentials require TLS",
		},
		{
			name: "proto is rejected for gNMI",
			mutate: func(cfg *Config) {
				cfg.Catalyst9800.DialIn.Targets[0].EncodingPreference = []string{"proto"}
			},
			expectedErr: "must be json_ietf or json",
		},
		{
			name: "wildcard include is rejected",
			mutate: func(cfg *Config) {
				cfg.Catalyst9800.DialIn.Targets[0].Paths.Include = []string{"wireless-client-oper:client-oper-data/*"}
			},
			expectedErr: "cannot contain wildcards",
		},
		{
			name: "unknown path group",
			mutate: func(cfg *Config) {
				cfg.Catalyst9800.PathGroups["unknown"] = Catalyst9800PathGroupConfig{Enabled: true}
			},
			expectedErr: "is not a known Catalyst 9800 path group",
		},
		{
			name: "negative batch limit",
			mutate: func(cfg *Config) {
				cfg.Catalyst9800.MaxDatapointsPerBatch = -1
			},
			expectedErr: "max_datapoints_per_batch must not be negative",
		},
		{
			name: "batch limit exceeds hard ceiling",
			mutate: func(cfg *Config) {
				cfg.Catalyst9800.MaxDatapointsPerBatch = directGNMIHardMaxDatapoints + 1
			},
			expectedErr: "max_datapoints_per_batch must not exceed 100000",
		},
		{
			name: "no enabled groups or paths",
			mutate: func(cfg *Config) {
				groups := defaultCatalyst9800PathGroups()
				for name := range groups {
					groups[name] = Catalyst9800PathGroupConfig{}
				}
				cfg.Catalyst9800.PathGroups = groups
			},
			expectedErr: "requires at least one enabled path group or custom path include",
		},
		{
			name: "target path override without global groups",
			mutate: func(cfg *Config) {
				groups := defaultCatalyst9800PathGroups()
				for name := range groups {
					groups[name] = Catalyst9800PathGroupConfig{}
				}
				cfg.Catalyst9800.PathGroups = groups
				cfg.Catalyst9800.DialIn.Targets[0].Paths.Include = []string{"wireless-client-oper:client-oper-data/common-oper-data"}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validCatalyst9800Config()
			if tt.mutate != nil {
				tt.mutate(cfg)
			}

			err := cfg.Validate()
			if tt.expectedErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestCatalyst9800TargetSubscriptionBooleanInheritance(t *testing.T) {
	parent := defaultCatalyst9800Config()
	parent.Subscription.UpdatesOnly = configoptional.Some(true)
	parent.Subscription.AllowAggregation = configoptional.Some(true)

	inherited := (Catalyst9800TargetConfig{}).withDefaults(parent)
	assert.True(t, inherited.Subscription.suppressRedundant())
	assert.True(t, inherited.Subscription.updatesOnly())
	assert.True(t, inherited.Subscription.allowAggregation())

	explicitFalse := (Catalyst9800TargetConfig{Subscription: Catalyst9800SubscriptionConfig{
		SuppressRedundant: configoptional.Some(false),
		UpdatesOnly:       configoptional.Some(false),
		AllowAggregation:  configoptional.Some(false),
	}}).withDefaults(parent)
	assert.False(t, explicitFalse.Subscription.suppressRedundant())
	assert.False(t, explicitFalse.Subscription.updatesOnly())
	assert.False(t, explicitFalse.Subscription.allowAggregation())
}

func TestCatalyst9800SubscriptionExplicitFalseUnmarshalsAsPresent(t *testing.T) {
	var sub Catalyst9800SubscriptionConfig
	require.NoError(t, confmap.NewFromStringMap(map[string]any{
		"suppress_redundant": false,
		"updates_only":       false,
		"allow_aggregation":  false,
	}).Unmarshal(&sub))

	assert.True(t, sub.SuppressRedundant.HasValue())
	assert.True(t, sub.UpdatesOnly.HasValue())
	assert.True(t, sub.AllowAggregation.HasValue())
	assert.False(t, sub.suppressRedundant())
	assert.False(t, sub.updatesOnly())
	assert.False(t, sub.allowAggregation())
}

func TestCatalyst9800RejectsUnsecuredRemoteDialOutListener(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Catalyst9800.Enabled = true
	cfg.Catalyst9800.DialOut.Enabled = true
	cfg.Catalyst9800.DialOut.NetAddr.Endpoint = "0.0.0.0:57501"

	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorContains(t, err, "catalyst_9800.dial_out: non-loopback listeners require TLS")
}
