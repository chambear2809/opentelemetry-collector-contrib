// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package systemscraper // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/systemscraper"

import (
	"fmt"
	"time"

	"go.uber.org/multierr"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/systemscraper/internal/metadata"
)

// Config holds configuration for the system scraper.
type Config struct {
	metadata.MetricsBuilderConfig `mapstructure:",squash"`
	// Device and Timeout are passed from the main receiver config (not from YAML)
	Device            connection.DeviceConfig `mapstructure:"-"`
	Timeout           time.Duration           `mapstructure:"-"`
	ProtocolTraffic   ProtocolTrafficConfig   `mapstructure:"protocol_traffic"`
	ControlPlane      ControlPlaneConfig      `mapstructure:"control_plane"`
	RoutingForwarding RoutingForwardingConfig `mapstructure:"routing_forwarding"`
	RouterDataplane   RouterDataplaneConfig   `mapstructure:"router_dataplane"`
	HardwareHealth    HardwareHealthConfig    `mapstructure:"hardware_health"`
	RoutingNeighbors  RoutingNeighborsConfig  `mapstructure:"routing_neighbors"`
	Fabric            FabricConfig            `mapstructure:"fabric"`
}

// ProtocolTrafficConfig controls protocol statistics from show ip traffic.
type ProtocolTrafficConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

func defaultProtocolTrafficConfig() ProtocolTrafficConfig {
	return ProtocolTrafficConfig{}
}

// ControlPlaneConfig controls optional control-plane troubleshooting collection.
type ControlPlaneConfig struct {
	Enabled     bool                       `mapstructure:"enabled"`
	ProcessTopN int                        `mapstructure:"process_top_n"`
	Commands    ControlPlaneCommandsConfig `mapstructure:"commands"`
}

// ControlPlaneCommandsConfig controls individual control-plane command families.
type ControlPlaneCommandsConfig struct {
	All          bool `mapstructure:"all"`
	CPUProcesses bool `mapstructure:"cpu_processes"`
	CoPP         bool `mapstructure:"copp"`
	PuntRates    bool `mapstructure:"punt_rates"`
}

// RoutingForwardingConfig controls optional routing and forwarding troubleshooting collection.
type RoutingForwardingConfig struct {
	Enabled  bool                            `mapstructure:"enabled"`
	VRFs     []string                        `mapstructure:"vrfs"`
	MaxVRFs  int                             `mapstructure:"max_vrfs"`
	Commands RoutingForwardingCommandsConfig `mapstructure:"commands"`
}

// RoutingForwardingCommandsConfig controls individual routing and forwarding command families.
type RoutingForwardingCommandsConfig struct {
	All             bool `mapstructure:"all"`
	RouteSummary    bool `mapstructure:"route_summary"`
	ARP             bool `mapstructure:"arp"`
	CEFFIB          bool `mapstructure:"cef_fib"`
	Adjacency       bool `mapstructure:"adjacency"`
	ForwardingDrops bool `mapstructure:"forwarding_drops"`
}

// RouterDataplaneConfig controls optional IOS XE router dataplane collection.
type RouterDataplaneConfig struct {
	Enabled  bool                          `mapstructure:"enabled"`
	Commands RouterDataplaneCommandsConfig `mapstructure:"commands"`
}

// RouterDataplaneCommandsConfig controls individual QFP dataplane command families.
type RouterDataplaneCommandsConfig struct {
	All            bool `mapstructure:"all"`
	QFPUtilization bool `mapstructure:"qfp_utilization"`
	QFPDrops       bool `mapstructure:"qfp_drops"`
	InterfaceDrops bool `mapstructure:"interface_drops"`
	QoSDrops       bool `mapstructure:"qos_drops"`
	CryptoDrops    bool `mapstructure:"crypto_drops"`
	NATDrops       bool `mapstructure:"nat_drops"`
	PuntDrops      bool `mapstructure:"punt_drops"`
	IPDrops        bool `mapstructure:"ip_drops"`
}

// HardwareHealthConfig controls optional environment, inventory, and module health collection.
type HardwareHealthConfig struct {
	Enabled       bool                         `mapstructure:"enabled"`
	MaxComponents int                          `mapstructure:"max_components"`
	Commands      HardwareHealthCommandsConfig `mapstructure:"commands"`
}

type HardwareHealthCommandsConfig struct {
	All         bool `mapstructure:"all"`
	Environment bool `mapstructure:"environment"`
	Module      bool `mapstructure:"module"`
	Inventory   bool `mapstructure:"inventory"`
}

// RoutingNeighborsConfig controls optional routing protocol neighbor collection.
type RoutingNeighborsConfig struct {
	Enabled      bool                           `mapstructure:"enabled"`
	VRFs         []string                       `mapstructure:"vrfs"`
	MaxVRFs      int                            `mapstructure:"max_vrfs"`
	MaxNeighbors int                            `mapstructure:"max_neighbors"`
	Commands     RoutingNeighborsCommandsConfig `mapstructure:"commands"`
}

type RoutingNeighborsCommandsConfig struct {
	All   bool `mapstructure:"all"`
	BGP   bool `mapstructure:"bgp"`
	OSPF  bool `mapstructure:"ospf"`
	EIGRP bool `mapstructure:"eigrp"`
	ISIS  bool `mapstructure:"isis"`
}

// FabricConfig controls optional VXLAN/EVPN fabric collection.
type FabricConfig struct {
	Enabled  bool                 `mapstructure:"enabled"`
	MaxPeers int                  `mapstructure:"max_peers"`
	MaxVNIs  int                  `mapstructure:"max_vnis"`
	Commands FabricCommandsConfig `mapstructure:"commands"`
}

type FabricCommandsConfig struct {
	All        bool `mapstructure:"all"`
	NVEPeers   bool `mapstructure:"nve_peers"`
	NVEVNIs    bool `mapstructure:"nve_vnis"`
	EVPNRoutes bool `mapstructure:"evpn_routes"`
}

// Validate rejects values that would otherwise be silently replaced by a
// default and VRF names that are interpolated into device CLI commands.
func (cfg *Config) Validate() error {
	var err error
	for name, value := range map[string]int{
		"control_plane.process_top_n":     cfg.ControlPlane.ProcessTopN,
		"routing_forwarding.max_vrfs":     cfg.RoutingForwarding.MaxVRFs,
		"hardware_health.max_components":  cfg.HardwareHealth.MaxComponents,
		"routing_neighbors.max_vrfs":      cfg.RoutingNeighbors.MaxVRFs,
		"routing_neighbors.max_neighbors": cfg.RoutingNeighbors.MaxNeighbors,
		"fabric.max_peers":                cfg.Fabric.MaxPeers,
		"fabric.max_vnis":                 cfg.Fabric.MaxVNIs,
	} {
		if value < 0 {
			err = multierr.Append(err, fmt.Errorf("%s must not be negative", name))
		}
	}
	err = multierr.Append(err, validateVRFNames("routing_forwarding.vrfs", cfg.RoutingForwarding.VRFs))
	err = multierr.Append(err, validateVRFNames("routing_neighbors.vrfs", cfg.RoutingNeighbors.VRFs))
	return err
}

func validateVRFNames(prefix string, values []string) error {
	var err error
	for i, value := range values {
		if value == "" {
			err = multierr.Append(err, fmt.Errorf("%s[%d] cannot be empty", prefix, i))
			continue
		}
		if len(value) > 255 {
			err = multierr.Append(err, fmt.Errorf("%s[%d] must not exceed 255 characters", prefix, i))
			continue
		}
		for _, r := range value {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				continue
			}
			switch r {
			case '.', '_', '-', ':':
				continue
			default:
				err = multierr.Append(err, fmt.Errorf("%s[%d] must contain only letters, digits, '.', '_', '-', or ':'", prefix, i))
			}
			break
		}
	}
	return err
}

func defaultControlPlaneConfig() ControlPlaneConfig {
	return ControlPlaneConfig{
		ProcessTopN: 10,
	}
}

func defaultRoutingForwardingConfig() RoutingForwardingConfig {
	return RoutingForwardingConfig{
		VRFs:    []string{"default"},
		MaxVRFs: 16,
	}
}

func defaultRouterDataplaneConfig() RouterDataplaneConfig {
	return RouterDataplaneConfig{}
}

func defaultHardwareHealthConfig() HardwareHealthConfig {
	return HardwareHealthConfig{MaxComponents: 256}
}

func defaultRoutingNeighborsConfig() RoutingNeighborsConfig {
	return RoutingNeighborsConfig{
		VRFs:         []string{"default"},
		MaxVRFs:      16,
		MaxNeighbors: 512,
	}
}

func defaultFabricConfig() FabricConfig {
	return FabricConfig{
		MaxPeers: 512,
		MaxVNIs:  2048,
	}
}

func (cfg ControlPlaneConfig) commandEnabled(feature string) bool {
	if cfg.Commands.All {
		return true
	}
	switch feature {
	case "control_cpu_processes":
		return cfg.Enabled || cfg.Commands.CPUProcesses
	case "control_copp":
		return cfg.Enabled || cfg.Commands.CoPP
	case "control_punt_rates":
		return cfg.Enabled || cfg.Commands.PuntRates
	default:
		return false
	}
}

func (cfg ControlPlaneConfig) emitsMetrics() bool {
	return cfg.Enabled || cfg.Commands.anyEnabled()
}

func (cfg ControlPlaneCommandsConfig) anyEnabled() bool {
	return cfg.All || cfg.CPUProcesses || cfg.CoPP || cfg.PuntRates
}

func (cfg RoutingForwardingConfig) commandEnabled(feature string) bool {
	if cfg.Commands.All {
		return true
	}
	switch feature {
	case "routing_route_summary":
		return cfg.Enabled || cfg.Commands.RouteSummary
	case "routing_arp":
		return cfg.Enabled || cfg.Commands.ARP
	case "routing_cef_fib":
		return cfg.Enabled || cfg.Commands.CEFFIB
	case "routing_adjacency":
		return cfg.Enabled || cfg.Commands.Adjacency
	case "routing_forwarding_drops":
		return cfg.Enabled || cfg.Commands.ForwardingDrops
	default:
		return false
	}
}

func (cfg RoutingForwardingConfig) emitsMetrics() bool {
	return cfg.Enabled || cfg.Commands.anyEnabled()
}

func (cfg RoutingForwardingCommandsConfig) anyEnabled() bool {
	return cfg.All || cfg.RouteSummary || cfg.ARP || cfg.CEFFIB || cfg.Adjacency || cfg.ForwardingDrops
}

func (cfg RouterDataplaneConfig) commandEnabled(feature string) bool {
	if cfg.Commands.All {
		return true
	}
	switch feature {
	case "router_qfp_utilization":
		return cfg.Enabled || cfg.Commands.QFPUtilization
	case "router_qfp_drops":
		return cfg.Enabled || cfg.Commands.QFPDrops
	case "router_interface_drops":
		return cfg.Enabled || cfg.Commands.InterfaceDrops
	case "router_qos_drops":
		return cfg.Enabled || cfg.Commands.QoSDrops
	case "router_crypto_drops":
		return cfg.Enabled || cfg.Commands.CryptoDrops
	case "router_nat_drops":
		return cfg.Enabled || cfg.Commands.NATDrops
	case "router_punt_drops":
		return cfg.Enabled || cfg.Commands.PuntDrops
	case "router_ip_drops":
		return cfg.Enabled || cfg.Commands.IPDrops
	default:
		return false
	}
}

func (cfg RouterDataplaneConfig) emitsMetrics() bool {
	return cfg.Enabled || cfg.Commands.anyEnabled()
}

func (cfg RouterDataplaneCommandsConfig) anyEnabled() bool {
	return cfg.All ||
		cfg.QFPUtilization ||
		cfg.QFPDrops ||
		cfg.InterfaceDrops ||
		cfg.QoSDrops ||
		cfg.CryptoDrops ||
		cfg.NATDrops ||
		cfg.PuntDrops ||
		cfg.IPDrops
}

func (cfg HardwareHealthConfig) emitsMetrics() bool {
	return cfg.Enabled || cfg.Commands.anyEnabled()
}

func (cfg HardwareHealthConfig) commandEnabled(feature string) bool {
	if cfg.Commands.All {
		return true
	}
	switch feature {
	case "hardware_environment":
		return cfg.Enabled || cfg.Commands.Environment
	case "hardware_module":
		return cfg.Enabled || cfg.Commands.Module
	case "hardware_inventory":
		return cfg.Enabled || cfg.Commands.Inventory
	default:
		return false
	}
}

func (cfg HardwareHealthCommandsConfig) anyEnabled() bool {
	return cfg.All || cfg.Environment || cfg.Module || cfg.Inventory
}

func (cfg RoutingNeighborsConfig) emitsMetrics() bool {
	return cfg.Enabled || cfg.Commands.anyEnabled()
}

func (cfg RoutingNeighborsConfig) commandEnabled(feature string) bool {
	if cfg.Commands.All {
		return true
	}
	switch feature {
	case "routing_bgp_neighbors":
		return cfg.Enabled || cfg.Commands.BGP
	case "routing_ospf_neighbors":
		return cfg.Enabled || cfg.Commands.OSPF
	case "routing_eigrp_neighbors":
		return cfg.Enabled || cfg.Commands.EIGRP
	case "routing_isis_neighbors":
		return cfg.Enabled || cfg.Commands.ISIS
	default:
		return false
	}
}

func (cfg RoutingNeighborsCommandsConfig) anyEnabled() bool {
	return cfg.All || cfg.BGP || cfg.OSPF || cfg.EIGRP || cfg.ISIS
}

func (cfg FabricConfig) emitsMetrics() bool {
	return cfg.Enabled || cfg.Commands.anyEnabled()
}

func (cfg FabricConfig) commandEnabled(feature string) bool {
	if cfg.Commands.All {
		return true
	}
	switch feature {
	case "fabric_nve_peers":
		return cfg.Enabled || cfg.Commands.NVEPeers
	case "fabric_nve_vni":
		return cfg.Enabled || cfg.Commands.NVEVNIs
	case "fabric_evpn_routes":
		return cfg.Enabled || cfg.Commands.EVPNRoutes
	default:
		return false
	}
}

func (cfg FabricCommandsConfig) anyEnabled() bool {
	return cfg.All || cfg.NVEPeers || cfg.NVEVNIs || cfg.EVPNRoutes
}
