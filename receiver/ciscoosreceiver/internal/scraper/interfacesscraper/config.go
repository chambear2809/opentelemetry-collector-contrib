// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package interfacesscraper // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/interfacesscraper"

import (
	"fmt"
	"path"
	"strings"
	"time"

	"go.uber.org/multierr"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/interfacesscraper/internal/metadata"
)

// Config holds configuration for the interfaces scraper
type Config struct {
	metadata.MetricsBuilderConfig `mapstructure:",squash"`
	Device                        connection.DeviceConfig `mapstructure:"-"` // Passed from receiver config
	Timeout                       time.Duration           `mapstructure:"-"` // Passed from receiver config
	Rates                         RateCollectionConfig    `mapstructure:"rates"`
	Counters                      CounterCollectionConfig `mapstructure:"counters"`
	L2Topology                    L2TopologyConfig        `mapstructure:"l2_topology"`
	Transceiver                   TransceiverConfig       `mapstructure:"transceiver"`
}

// RateCollectionConfig controls bounded Cisco rate metrics parsed from show interface.
type RateCollectionConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// CounterCollectionConfig controls high-cardinality Cisco interface counter collection.
type CounterCollectionConfig struct {
	Enabled         bool                       `mapstructure:"enabled"`
	Include         []string                   `mapstructure:"include"`
	Exclude         []string                   `mapstructure:"exclude"`
	MaxPerInterface int                        `mapstructure:"max_per_interface"`
	MaxInterfaces   int                        `mapstructure:"max_interfaces"`
	Commands        CounterCommandGroupsConfig `mapstructure:"commands"`
}

// CounterCommandGroupsConfig controls optional show commands that can add many
// cisco.interface.counter series.
type CounterCommandGroupsConfig struct {
	All                 bool `mapstructure:"all"`
	InterfaceCounters   bool `mapstructure:"interface_counters"`
	InterfaceErrors     bool `mapstructure:"interface_errors"`
	FlowControl         bool `mapstructure:"flowcontrol"`
	PriorityFlowControl bool `mapstructure:"priority_flow_control"`
	Queueing            bool `mapstructure:"queueing"`
	PFCWatchdog         bool `mapstructure:"pfc_watchdog"`
	QoSPolicy           bool `mapstructure:"qos_policy"`
	PlatformQueueStats  bool `mapstructure:"platform_queue_stats"`
}

func defaultRateCollectionConfig() RateCollectionConfig {
	return RateCollectionConfig{}
}

func defaultCounterCollectionConfig() CounterCollectionConfig {
	return CounterCollectionConfig{
		MaxPerInterface: 100,
		MaxInterfaces:   256,
	}
}

// L2TopologyConfig controls optional Layer 2 topology troubleshooting collection.
type L2TopologyConfig struct {
	Enabled       bool                     `mapstructure:"enabled"`
	Include       []string                 `mapstructure:"include"`
	Exclude       []string                 `mapstructure:"exclude"`
	MaxInterfaces int                      `mapstructure:"max_interfaces"`
	MaxVLANs      int                      `mapstructure:"max_vlans"`
	Commands      L2TopologyCommandsConfig `mapstructure:"commands"`
}

// L2TopologyCommandsConfig controls individual Layer 2 topology command families.
type L2TopologyCommandsConfig struct {
	All         bool `mapstructure:"all"`
	STP         bool `mapstructure:"stp"`
	PortChannel bool `mapstructure:"port_channel"`
	LACP        bool `mapstructure:"lacp"`
	ErrDisabled bool `mapstructure:"err_disabled"`
	VPC         bool `mapstructure:"vpc"`
	LLDP        bool `mapstructure:"lldp"`
	CDP         bool `mapstructure:"cdp"`
}

// TransceiverConfig controls optional transceiver DOM troubleshooting collection.
type TransceiverConfig struct {
	Enabled       bool     `mapstructure:"enabled"`
	Include       []string `mapstructure:"include"`
	Exclude       []string `mapstructure:"exclude"`
	MaxInterfaces int      `mapstructure:"max_interfaces"`
}

func defaultL2TopologyConfig() L2TopologyConfig {
	return L2TopologyConfig{
		MaxInterfaces: 256,
		MaxVLANs:      128,
	}
}

func defaultTransceiverConfig() TransceiverConfig {
	return TransceiverConfig{
		MaxInterfaces: 256,
	}
}

// Validate rejects invalid limits and globs instead of allowing them to be
// silently interpreted as defaults, unlimited collection, or non-matches.
func (cfg *Config) Validate() error {
	var err error
	for name, value := range map[string]int{
		"counters.max_per_interface": cfg.Counters.MaxPerInterface,
		"counters.max_interfaces":    cfg.Counters.MaxInterfaces,
		"l2_topology.max_interfaces": cfg.L2Topology.MaxInterfaces,
		"l2_topology.max_vlans":      cfg.L2Topology.MaxVLANs,
		"transceiver.max_interfaces": cfg.Transceiver.MaxInterfaces,
	} {
		if value < 0 {
			err = multierr.Append(err, fmt.Errorf("%s must not be negative", name))
		}
	}
	err = multierr.Append(err, validateGlobPatterns("counters.include", cfg.Counters.Include))
	err = multierr.Append(err, validateGlobPatterns("counters.exclude", cfg.Counters.Exclude))
	err = multierr.Append(err, validateGlobPatterns("l2_topology.include", cfg.L2Topology.Include))
	err = multierr.Append(err, validateGlobPatterns("l2_topology.exclude", cfg.L2Topology.Exclude))
	err = multierr.Append(err, validateGlobPatterns("transceiver.include", cfg.Transceiver.Include))
	err = multierr.Append(err, validateGlobPatterns("transceiver.exclude", cfg.Transceiver.Exclude))
	return err
}

func validateGlobPatterns(prefix string, patterns []string) error {
	var err error
	for i, value := range patterns {
		pattern := strings.TrimSpace(value)
		if pattern == "" {
			err = multierr.Append(err, fmt.Errorf("%s[%d] cannot be empty", prefix, i))
			continue
		}
		if _, matchErr := path.Match(normalizeGlobSlashes(pattern), ""); matchErr != nil {
			err = multierr.Append(err, fmt.Errorf("%s[%d] must be a valid glob: %w", prefix, i, matchErr))
		}
	}
	return err
}

func (cfg L2TopologyConfig) emitsMetrics() bool {
	return cfg.Enabled || cfg.Commands.anyEnabled()
}

func (cfg L2TopologyConfig) commandEnabled(feature string) bool {
	if cfg.Commands.All {
		return true
	}
	switch feature {
	case "l2_stp":
		return cfg.Enabled || cfg.Commands.STP
	case "l2_port_channel":
		return cfg.Enabled || cfg.Commands.PortChannel
	case "l2_lacp":
		return cfg.Enabled || cfg.Commands.LACP
	case "l2_err_disabled":
		return cfg.Enabled || cfg.Commands.ErrDisabled
	case "l2_vpc":
		return cfg.Enabled || cfg.Commands.VPC
	case "l2_lldp":
		return cfg.Commands.LLDP
	case "l2_cdp":
		return cfg.Commands.CDP
	default:
		return false
	}
}

func (cfg L2TopologyCommandsConfig) anyEnabled() bool {
	return cfg.All || cfg.STP || cfg.PortChannel || cfg.LACP || cfg.ErrDisabled || cfg.VPC || cfg.LLDP || cfg.CDP
}

func (cfg CounterCollectionConfig) emitsCounters() bool {
	return cfg.Enabled || cfg.Commands.anyEnabled()
}

func (cfg CounterCollectionConfig) commandEnabled(feature string) bool {
	if cfg.Commands.All {
		return true
	}

	switch feature {
	case "interface_counters":
		return cfg.Enabled || cfg.Commands.InterfaceCounters
	case "interface_error_counters":
		return cfg.Enabled || cfg.Commands.InterfaceErrors
	case "interface_flowcontrol":
		return cfg.Commands.FlowControl
	case "interface_priority_flow_control":
		return cfg.Commands.PriorityFlowControl
	case "interface_queueing":
		return cfg.Commands.Queueing
	case "interface_pfc_watchdog":
		return cfg.Commands.PFCWatchdog
	case "interface_qos_policy":
		return cfg.Commands.QoSPolicy
	case "interface_platform_queue_stats":
		return cfg.Commands.PlatformQueueStats
	default:
		return false
	}
}

func (cfg CounterCommandGroupsConfig) anyEnabled() bool {
	return cfg.All ||
		cfg.InterfaceCounters ||
		cfg.InterfaceErrors ||
		cfg.FlowControl ||
		cfg.PriorityFlowControl ||
		cfg.Queueing ||
		cfg.PFCWatchdog ||
		cfg.QoSPolicy ||
		cfg.PlatformQueueStats
}
