// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package connection // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"

import "go.opentelemetry.io/collector/config/configopaque"

// DeviceConfig represents configuration for a single Cisco device using semantic conventions
type DeviceConfig struct {
	Device DeviceInfo `mapstructure:"device"`
	Auth   AuthConfig `mapstructure:"auth"`
}

// DeviceInfo follows semantic conventions for device identification
type DeviceInfo struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Host HostInfo `mapstructure:"host"`
}

// HostInfo contains host-specific information
type HostInfo struct {
	Name string `mapstructure:"name"`
	IP   string `mapstructure:"ip"`
	Port int    `mapstructure:"port"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Username       string              `mapstructure:"username"`
	Password       configopaque.String `mapstructure:"password"`
	EnablePassword configopaque.String `mapstructure:"enable_password"`
	KeyFile        string              `mapstructure:"key_file"`
	// KnownHostsFile is the path to a known_hosts file used for SSH host key verification.
	// Either KnownHostsFile or InsecureSkipVerify must be set.
	KnownHostsFile string `mapstructure:"known_hosts_file"`
	// InsecureSkipVerify disables SSH host key verification. Dangerous in production;
	// only use in isolated lab environments. Either this or KnownHostsFile is required.
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify"`
}
