// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package systemscraper

import (
	"strings"
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
			name: "negative process cap",
			mutate: func(cfg *Config) {
				cfg.ControlPlane.ProcessTopN = -1
			},
			wantErr: "control_plane.process_top_n must not be negative",
		},
		{
			name: "negative routing cap",
			mutate: func(cfg *Config) {
				cfg.RoutingForwarding.MaxVRFs = -1
			},
			wantErr: "routing_forwarding.max_vrfs must not be negative",
		},
		{
			name: "negative hardware cap",
			mutate: func(cfg *Config) {
				cfg.HardwareHealth.MaxComponents = -1
			},
			wantErr: "hardware_health.max_components must not be negative",
		},
		{
			name: "negative neighbor cap",
			mutate: func(cfg *Config) {
				cfg.RoutingNeighbors.MaxNeighbors = -1
			},
			wantErr: "routing_neighbors.max_neighbors must not be negative",
		},
		{
			name: "negative fabric cap",
			mutate: func(cfg *Config) {
				cfg.Fabric.MaxVNIs = -1
			},
			wantErr: "fabric.max_vnis must not be negative",
		},
		{
			name: "empty VRF",
			mutate: func(cfg *Config) {
				cfg.RoutingForwarding.VRFs = []string{""}
			},
			wantErr: "routing_forwarding.vrfs[0] cannot be empty",
		},
		{
			name: "VRF CLI pipe",
			mutate: func(cfg *Config) {
				cfg.RoutingForwarding.VRFs = []string{"blue|include secrets"}
			},
			wantErr: "routing_forwarding.vrfs[0] must contain only",
		},
		{
			name: "VRF command delimiter",
			mutate: func(cfg *Config) {
				cfg.RoutingNeighbors.VRFs = []string{"blue;show version"}
			},
			wantErr: "routing_neighbors.vrfs[0] must contain only",
		},
		{
			name: "VRF control character",
			mutate: func(cfg *Config) {
				cfg.RoutingNeighbors.VRFs = []string{"blue\nshow version"}
			},
			wantErr: "routing_neighbors.vrfs[0] must contain only",
		},
		{
			name: "oversized VRF",
			mutate: func(cfg *Config) {
				cfg.RoutingNeighbors.VRFs = []string{strings.Repeat("a", 256)}
			},
			wantErr: "routing_neighbors.vrfs[0] must not exceed 255 characters",
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

func TestConfigValidateAllowsZeroDefaultsAndSafeVRFs(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.ControlPlane.ProcessTopN = 0
	cfg.RoutingForwarding.MaxVRFs = 0
	cfg.HardwareHealth.MaxComponents = 0
	cfg.RoutingNeighbors.MaxVRFs = 0
	cfg.RoutingNeighbors.MaxNeighbors = 0
	cfg.Fabric.MaxPeers = 0
	cfg.Fabric.MaxVNIs = 0
	cfg.RoutingForwarding.VRFs = []string{"default", "Mgmt-vrf", "customer_1", "corp.prod:1"}
	cfg.RoutingNeighbors.VRFs = []string{"default", "blue_1"}
	require.NoError(t, cfg.Validate())
}
