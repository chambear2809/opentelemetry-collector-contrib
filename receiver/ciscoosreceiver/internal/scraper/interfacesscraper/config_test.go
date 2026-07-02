// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package interfacesscraper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		require.NoError(t, createDefaultConfig().(*Config).Validate())
	})

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "negative per-interface cap",
			mutate: func(cfg *Config) {
				cfg.Counters.MaxPerInterface = -1
			},
			wantErr: "counters.max_per_interface must not be negative",
		},
		{
			name: "negative counter interface cap",
			mutate: func(cfg *Config) {
				cfg.Counters.MaxInterfaces = -1
			},
			wantErr: "counters.max_interfaces must not be negative",
		},
		{
			name: "negative L2 cap",
			mutate: func(cfg *Config) {
				cfg.L2Topology.MaxVLANs = -1
			},
			wantErr: "l2_topology.max_vlans must not be negative",
		},
		{
			name: "negative transceiver cap",
			mutate: func(cfg *Config) {
				cfg.Transceiver.MaxInterfaces = -1
			},
			wantErr: "transceiver.max_interfaces must not be negative",
		},
		{
			name: "empty counter glob",
			mutate: func(cfg *Config) {
				cfg.Counters.Include = []string{" "}
			},
			wantErr: "counters.include[0] cannot be empty",
		},
		{
			name: "invalid counter glob",
			mutate: func(cfg *Config) {
				cfg.Counters.Exclude = []string{"[unterminated"}
			},
			wantErr: "counters.exclude[0] must be a valid glob",
		},
		{
			name: "invalid L2 glob",
			mutate: func(cfg *Config) {
				cfg.L2Topology.Include = []string{"[unterminated"}
			},
			wantErr: "l2_topology.include[0] must be a valid glob",
		},
		{
			name: "invalid transceiver glob",
			mutate: func(cfg *Config) {
				cfg.Transceiver.Exclude = []string{"[unterminated"}
			},
			wantErr: "transceiver.exclude[0] must be a valid glob",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createDefaultConfig().(*Config)
			tt.mutate(cfg)
			require.ErrorContains(t, cfg.Validate(), tt.wantErr)
		})
	}
}

func TestConfigValidateAllowsDocumentedZeroAndValidGlobs(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Counters.MaxPerInterface = 0
	cfg.Counters.MaxInterfaces = 0
	cfg.L2Topology.MaxInterfaces = 0
	cfg.L2Topology.MaxVLANs = 0
	cfg.Transceiver.MaxInterfaces = 0
	cfg.Counters.Include = []string{"*error*", "queue_[0-9]"}
	cfg.L2Topology.Include = []string{"Gi*", "Eth*/[1-9]"}
	cfg.Transceiver.Exclude = []string{"*0/48"}
	require.NoError(t, cfg.Validate())
}
