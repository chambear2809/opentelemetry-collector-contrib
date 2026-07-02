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
	assert.Equal(t, 50000, cfg.IOSXR.MaxDatapointsPerBatch)
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

func TestIOSXRUnsupportedPathActions(t *testing.T) {
	for _, action := range []string{iosXRUnsupportedWarn, iosXRUnsupportedError, iosXRUnsupportedIgnore} {
		t.Run(action, func(t *testing.T) {
			cfg := validIOSXRConfig()
			cfg.IOSXR.UnsupportedPathAction = action
			require.NoError(t, cfg.Validate())
		})
	}
}
