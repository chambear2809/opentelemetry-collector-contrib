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
	assert.Equal(t, 50000, cfg.Catalyst9800.MaxDatapointsPerBatch)

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
