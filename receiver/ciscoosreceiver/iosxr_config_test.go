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

func validIOSXRConfig() *Config {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.IOSXR.Enabled = true
	cfg.IOSXR.PathGroups["interfaces"] = IOSXRPathGroupConfig{Enabled: true}
	cfg.IOSXR.DialIn.Targets = []IOSXRTargetConfig{{
		ClientConfig: configgrpc.ClientConfig{Endpoint: "10.0.0.10:57400"},
		Name:         "core-asr9k-1",
		Credentials: IOSXRCredentialsConfig{
			Username: "admin",
			Password: configopaque.String("password"),
		},
	}}
	return cfg
}

func TestIOSXRDefaultConfigIsConservative(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig().(*Config)

	assert.False(t, cfg.IOSXR.Enabled)
	assert.Equal(t, iosXRUnsupportedWarn, cfg.IOSXR.UnsupportedPathAction)
	assert.Equal(t, []string{"json_ietf", "json", "proto"}, cfg.IOSXR.EncodingPreference)
	assert.Equal(t, iosXRSubscribeModeStream, cfg.IOSXR.Subscription.Mode)
	assert.Equal(t, iosXRStreamModeSample, cfg.IOSXR.Subscription.StreamMode)
	assert.Equal(t, time.Minute, cfg.IOSXR.Subscription.SampleInterval)
	assert.Equal(t, time.Minute, cfg.IOSXR.Subscription.HeartbeatInterval)
	assert.True(t, cfg.IOSXR.Subscription.suppressRedundant())
	assert.False(t, cfg.IOSXR.Subscription.updatesOnly())
	assert.False(t, cfg.IOSXR.Subscription.allowAggregation())
	assert.Equal(t, directGNMIDefaultMaxDatapoints, cfg.IOSXR.MaxDatapointsPerBatch)
	assert.Equal(t, 100.0, cfg.IOSXR.DialOut.RateLimiting.RequestsPerSecond)
	assert.Equal(t, 10, cfg.IOSXR.DialOut.RateLimiting.BurstSize)
	assert.Equal(t, time.Minute, cfg.IOSXR.DialOut.RateLimiting.CleanupInterval)
	for group, groupCfg := range cfg.IOSXR.PathGroups {
		assert.False(t, groupCfg.Enabled, "path group %s should be opt-in", group)
	}
}

func TestIOSXRConfigValidate(t *testing.T) {
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
				cfg.IOSXR.DialIn.Targets = nil
				cfg.IOSXR.DialOut.Enabled = true
			},
		},
		{
			name: "invalid dial out rate limit",
			mutate: func(cfg *Config) {
				cfg.IOSXR.DialOut.Enabled = true
				cfg.IOSXR.DialOut.RateLimiting.Enabled = true
				cfg.IOSXR.DialOut.RateLimiting.CleanupInterval = -time.Second
			},
			expectedErr: "ios_xr.dial_out: cleanup_interval must be positive",
		},
		{
			name: "dial out receive size exceeds YANG receiver cap",
			mutate: func(cfg *Config) {
				cfg.IOSXR.DialIn.Targets = nil
				cfg.IOSXR.DialOut.Enabled = true
				cfg.IOSXR.DialOut.MaxRecvMsgSizeMiB = 17
			},
			expectedErr: "ios_xr.dial_out: max_recv_msg_size_mib must be between 1 and 16",
		},
		{
			name: "dial out concurrent streams exceed YANG receiver cap",
			mutate: func(cfg *Config) {
				cfg.IOSXR.DialIn.Targets = nil
				cfg.IOSXR.DialOut.Enabled = true
				cfg.IOSXR.DialOut.MaxConcurrentStreams = 1001
			},
			expectedErr: "ios_xr.dial_out: max_concurrent_streams must be between 1 and 1000",
		},
		{
			name: "target requires enabled IOS XR",
			mutate: func(cfg *Config) {
				cfg.IOSXR.Enabled = false
			},
			expectedErr: "ios_xr.enabled must be true",
		},
		{
			name: "invalid endpoint",
			mutate: func(cfg *Config) {
				cfg.IOSXR.DialIn.Targets[0].Endpoint = "10.0.0.10"
			},
			expectedErr: "endpoint must be host:port",
		},
		{
			name: "invalid gRPC client option",
			mutate: func(cfg *Config) {
				cfg.IOSXR.DialIn.Targets[0].BalancerName = "not_registered"
			},
			expectedErr: "invalid balancer_name",
		},
		{
			name: "plaintext gNMI credentials are rejected",
			mutate: func(cfg *Config) {
				cfg.IOSXR.DialIn.Targets[0].TLS.Insecure = true
			},
			expectedErr: "tls.insecure must be false because gNMI credentials require TLS",
		},
		{
			name: "invalid mode",
			mutate: func(cfg *Config) {
				cfg.IOSXR.DialIn.Targets[0].Subscription.Mode = "subscribe_forever"
			},
			expectedErr: "mode must be once, poll, or stream",
		},
		{
			name: "no enabled groups or paths",
			mutate: func(cfg *Config) {
				cfg.IOSXR.PathGroups["interfaces"] = IOSXRPathGroupConfig{}
			},
			expectedErr: "requires at least one enabled path group or custom path include",
		},
		{
			name: "negative duration",
			mutate: func(cfg *Config) {
				cfg.IOSXR.DialIn.Targets[0].Subscription.SampleInterval = -time.Second
			},
			expectedErr: "sample_interval must not be negative",
		},
		{
			name: "duplicate target names",
			mutate: func(cfg *Config) {
				cfg.IOSXR.DialIn.Targets = append(cfg.IOSXR.DialIn.Targets, cfg.IOSXR.DialIn.Targets[0])
			},
			expectedErr: "name must be unique",
		},
		{
			name: "unknown path group",
			mutate: func(cfg *Config) {
				cfg.IOSXR.PathGroups["unknown"] = IOSXRPathGroupConfig{Enabled: true}
			},
			expectedErr: "is not a known IOS XR path group",
		},
		{
			name: "invalid unsupported action",
			mutate: func(cfg *Config) {
				cfg.IOSXR.UnsupportedPathAction = "drop"
			},
			expectedErr: "unsupported_path_action must be warn, error, or ignore",
		},
		{
			name: "batch limit exceeds hard ceiling",
			mutate: func(cfg *Config) {
				cfg.IOSXR.MaxDatapointsPerBatch = directGNMIHardMaxDatapoints + 1
			},
			expectedErr: "max_datapoints_per_batch must not exceed 100000",
		},
		{
			name: "target path override without global groups",
			mutate: func(cfg *Config) {
				cfg.IOSXR.PathGroups["interfaces"] = IOSXRPathGroupConfig{}
				cfg.IOSXR.DialIn.Targets[0].Paths.Include = []string{"openconfig-interfaces:interfaces/interface/state"}
			},
		},
		{
			name: "invalid custom path",
			mutate: func(cfg *Config) {
				cfg.IOSXR.DialIn.Targets[0].Paths.Include = []string{"openconfig-interfaces:interfaces/interface[state"}
			},
			expectedErr: "must be a valid gNMI path",
		},
		{
			name: "wildcard custom path",
			mutate: func(cfg *Config) {
				cfg.IOSXR.DialIn.Targets[0].Paths.Include = []string{"openconfig-interfaces:interfaces/*"}
			},
			expectedErr: "cannot contain wildcards",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validIOSXRConfig()
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

func TestIOSXRTargetSubscriptionBooleanInheritance(t *testing.T) {
	parent := defaultIOSXRConfig()
	parent.Subscription.UpdatesOnly = configoptional.Some(true)
	parent.Subscription.AllowAggregation = configoptional.Some(true)

	inherited := (IOSXRTargetConfig{}).withDefaults(parent)
	assert.True(t, inherited.Subscription.suppressRedundant())
	assert.True(t, inherited.Subscription.updatesOnly())
	assert.True(t, inherited.Subscription.allowAggregation())

	explicitFalse := (IOSXRTargetConfig{Subscription: IOSXRSubscriptionConfig{
		SuppressRedundant: configoptional.Some(false),
		UpdatesOnly:       configoptional.Some(false),
		AllowAggregation:  configoptional.Some(false),
	}}).withDefaults(parent)
	assert.False(t, explicitFalse.Subscription.suppressRedundant())
	assert.False(t, explicitFalse.Subscription.updatesOnly())
	assert.False(t, explicitFalse.Subscription.allowAggregation())
}

func TestIOSXRSubscriptionExplicitFalseUnmarshalsAsPresent(t *testing.T) {
	var sub IOSXRSubscriptionConfig
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

func TestIOSXRUnsupportedPathActions(t *testing.T) {
	for _, action := range []string{iosXRUnsupportedWarn, iosXRUnsupportedError, iosXRUnsupportedIgnore} {
		t.Run(action, func(t *testing.T) {
			cfg := validIOSXRConfig()
			cfg.IOSXR.UnsupportedPathAction = action
			require.NoError(t, cfg.Validate())
		})
	}
}

func TestIOSXRRejectsUnsecuredRemoteDialOutListener(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.IOSXR.Enabled = true
	cfg.IOSXR.DialOut.Enabled = true
	cfg.IOSXR.DialOut.NetAddr.Endpoint = "0.0.0.0:57500"

	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorContains(t, err, "ios_xr.dial_out: non-loopback listeners require TLS")
}
