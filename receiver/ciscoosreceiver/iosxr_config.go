// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.uber.org/multierr"
)

const (
	iosXRUnsupportedWarn   = "warn"
	iosXRUnsupportedError  = "error"
	iosXRUnsupportedIgnore = "ignore"

	iosXRSubscribeModeOnce   = "once"
	iosXRSubscribeModePoll   = "poll"
	iosXRSubscribeModeStream = "stream"

	iosXRStreamModeSample        = "sample"
	iosXRStreamModeOnChange      = "on_change"
	iosXRStreamModeTargetDefined = "target_defined"
)

// IOSXRCredentialsConfig represents IOS XR gNMI metadata credentials.
type IOSXRCredentialsConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Username string              `mapstructure:"username"`
	Password configopaque.String `mapstructure:"password"`
}

// IOSXRPathGroupConfig controls a curated IOS XR telemetry path group.
type IOSXRPathGroupConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled bool `mapstructure:"enabled"`
}

// IOSXRPathOverrideConfig provides custom IOS XR path include/exclude controls.
type IOSXRPathOverrideConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Include []string `mapstructure:"include"`
	Exclude []string `mapstructure:"exclude"`
}

// IOSXRSubscriptionConfig defines IOS XR gNMI subscription behavior.
type IOSXRSubscriptionConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Mode              string        `mapstructure:"mode"`
	StreamMode        string        `mapstructure:"stream_mode"`
	SampleInterval    time.Duration `mapstructure:"sample_interval"`
	HeartbeatInterval time.Duration `mapstructure:"heartbeat_interval"`
	PollInterval      time.Duration `mapstructure:"poll_interval"`
	SuppressRedundant bool          `mapstructure:"suppress_redundant"`
	UpdatesOnly       bool          `mapstructure:"updates_only"`
	AllowAggregation  bool          `mapstructure:"allow_aggregation"`
}

// IOSXRTargetConfig identifies one IOS XR gNMI dial-in target.
type IOSXRTargetConfig struct {
	configgrpc.ClientConfig `mapstructure:",squash"`

	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Name               string                          `mapstructure:"name"`
	PlatformFamily     string                          `mapstructure:"platform_family"`
	Credentials        IOSXRCredentialsConfig          `mapstructure:"credentials"`
	Subscription       IOSXRSubscriptionConfig         `mapstructure:"subscription"`
	EncodingPreference []string                        `mapstructure:"encoding_preference"`
	PathGroups         map[string]IOSXRPathGroupConfig `mapstructure:"path_groups"`
	Paths              IOSXRPathOverrideConfig         `mapstructure:"paths"`
	SkipCapabilities   bool                            `mapstructure:"skip_capabilities"`
}

// IOSXRDialInConfig defines dynamic IOS XR gNMI subscriptions initiated by the collector.
type IOSXRDialInConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Targets []IOSXRTargetConfig `mapstructure:"targets"`
}

// IOSXRDialOutConfig defines IOS XR MDT gRPC dial-out server settings.
type IOSXRDialOutConfig struct {
	configgrpc.ServerConfig `mapstructure:",squash"`

	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled        bool     `mapstructure:"enabled"`
	AllowedClients []string `mapstructure:"allowed_clients"`
	ModulePaths    []string `mapstructure:"module_paths"`
}

// IOSXRConfig defines IOS XR gNMI/MDT telemetry settings.
type IOSXRConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled               bool                            `mapstructure:"enabled"`
	PathGroups            map[string]IOSXRPathGroupConfig `mapstructure:"path_groups"`
	DialIn                IOSXRDialInConfig               `mapstructure:"dial_in"`
	DialOut               IOSXRDialOutConfig              `mapstructure:"dial_out"`
	Paths                 IOSXRPathOverrideConfig         `mapstructure:"paths"`
	UnsupportedPathAction string                          `mapstructure:"unsupported_path_action"`
	EncodingPreference    []string                        `mapstructure:"encoding_preference"`
	Subscription          IOSXRSubscriptionConfig         `mapstructure:"subscription"`
	MaxDatapointsPerBatch int                             `mapstructure:"max_datapoints_per_batch"`
}

func defaultIOSXRConfig() IOSXRConfig {
	server := configgrpc.NewDefaultServerConfig()
	server.NetAddr.Endpoint = "localhost:57500"
	server.NetAddr.Transport = "tcp"
	server.MaxRecvMsgSizeMiB = 4
	server.MaxConcurrentStreams = 100
	server.Keepalive.GetOrInsertDefault().ServerParameters.GetOrInsertDefault().Time = 30 * time.Second
	server.Keepalive.GetOrInsertDefault().ServerParameters.GetOrInsertDefault().Timeout = 10 * time.Second

	return IOSXRConfig{
		PathGroups:            defaultIOSXRPathGroups(),
		DialOut:               IOSXRDialOutConfig{ServerConfig: server},
		UnsupportedPathAction: iosXRUnsupportedWarn,
		EncodingPreference:    []string{"json_ietf", "json", "proto"},
		Subscription:          defaultIOSXRSubscriptionConfig(),
		MaxDatapointsPerBatch: 50000,
	}
}

func defaultIOSXRPathGroups() map[string]IOSXRPathGroupConfig {
	groups := make(map[string]IOSXRPathGroupConfig, len(iosXRPathGroupNames()))
	for _, name := range iosXRPathGroupNames() {
		groups[name] = IOSXRPathGroupConfig{}
	}
	return groups
}

func defaultIOSXRTargetConfig() IOSXRTargetConfig {
	return IOSXRTargetConfig{
		ClientConfig:       configgrpc.NewDefaultClientConfig(),
		Subscription:       defaultIOSXRSubscriptionConfig(),
		EncodingPreference: []string{"json_ietf", "json", "proto"},
		PathGroups:         defaultIOSXRPathGroups(),
	}
}

func defaultIOSXRSubscriptionConfig() IOSXRSubscriptionConfig {
	return IOSXRSubscriptionConfig{
		Mode:              iosXRSubscribeModeStream,
		StreamMode:        iosXRStreamModeSample,
		SampleInterval:    time.Minute,
		HeartbeatInterval: time.Minute,
		SuppressRedundant: true,
	}
}

func (cfg IOSXRConfig) hasTarget() bool {
	return cfg.Enabled || cfg.DialOut.Enabled || len(cfg.DialIn.Targets) > 0
}

func (cfg *Config) validateIOSXR() error {
	if !cfg.IOSXR.hasTarget() {
		return nil
	}

	var err error
	iosxr := cfg.IOSXR.withDefaults()
	if !iosxr.Enabled && (iosxr.DialOut.Enabled || len(iosxr.DialIn.Targets) > 0) {
		err = multierr.Append(err, errors.New("ios_xr.enabled must be true when IOS XR dial_in targets or dial_out are configured"))
	}
	if !validIOSXRUnsupportedAction(iosxr.UnsupportedPathAction) {
		err = multierr.Append(err, errors.New("ios_xr.unsupported_path_action must be warn, error, or ignore"))
	}
	if iosxr.MaxDatapointsPerBatch < 0 {
		err = multierr.Append(err, errors.New("ios_xr.max_datapoints_per_batch must not be negative"))
	}
	err = multierr.Append(err, validateIOSXREncodings("ios_xr.encoding_preference", iosxr.EncodingPreference))
	err = multierr.Append(err, validateIOSXRSubscription("ios_xr.subscription", iosxr.Subscription, false))
	err = multierr.Append(err, validateIOSXRPathGroups("ios_xr.path_groups", iosxr.PathGroups))
	err = multierr.Append(err, validateIOSXRPaths("ios_xr.paths", iosxr.Paths))

	if len(iosxr.DialIn.Targets) == 0 && !iosxr.DialOut.Enabled {
		err = multierr.Append(err, errors.New("ios_xr requires at least one dial_in target or dial_out.enabled: true"))
	}
	names := map[string]struct{}{}
	for i, target := range iosxr.DialIn.Targets {
		target = target.withDefaults(iosxr)
		prefix := fmt.Sprintf("ios_xr.dial_in.targets[%d]", i)
		if strings.TrimSpace(target.Name) == "" {
			err = multierr.Append(err, fmt.Errorf("%s.name cannot be empty", prefix))
		} else {
			key := normalizeSelectorText(target.Name)
			if _, ok := names[key]; ok {
				err = multierr.Append(err, fmt.Errorf("%s.name must be unique", prefix))
			}
			names[key] = struct{}{}
		}
		if strings.TrimSpace(target.Endpoint) == "" {
			err = multierr.Append(err, fmt.Errorf("%s.endpoint cannot be empty", prefix))
		} else if _, _, splitErr := net.SplitHostPort(target.Endpoint); splitErr != nil {
			err = multierr.Append(err, fmt.Errorf("%s.endpoint must be host:port", prefix))
		}
		if target.Credentials.Username == "" {
			err = multierr.Append(err, fmt.Errorf("%s.credentials.username cannot be empty", prefix))
		}
		if target.Credentials.Password == "" {
			err = multierr.Append(err, fmt.Errorf("%s.credentials.password cannot be empty", prefix))
		}
		err = multierr.Append(err, validateIOSXREncodings(prefix+".encoding_preference", target.EncodingPreference))
		err = multierr.Append(err, validateIOSXRSubscription(prefix+".subscription", target.Subscription, true))
		err = multierr.Append(err, validateIOSXRPathGroups(prefix+".path_groups", target.PathGroups))
		err = multierr.Append(err, validateIOSXRPaths(prefix+".paths", target.Paths))
		if len(resolveIOSXRPathSelection(iosxr.PathGroups, iosxr.Paths, &target)) == 0 {
			err = multierr.Append(err, fmt.Errorf("%s requires at least one enabled path group or custom path include", prefix))
		}
	}

	if iosxr.DialOut.Enabled {
		if grpcErr := iosxr.DialOut.ServerConfig.Validate(); grpcErr != nil {
			err = multierr.Append(err, fmt.Errorf("ios_xr.dial_out: %w", grpcErr))
		}
	}

	return err
}

func (cfg IOSXRConfig) withDefaults() IOSXRConfig {
	defaults := defaultIOSXRConfig()
	if cfg.UnsupportedPathAction == "" {
		cfg.UnsupportedPathAction = defaults.UnsupportedPathAction
	}
	if len(cfg.EncodingPreference) == 0 {
		cfg.EncodingPreference = defaults.EncodingPreference
	}
	cfg.Subscription = cfg.Subscription.withDefaults(defaults.Subscription)
	if cfg.PathGroups == nil {
		cfg.PathGroups = defaults.PathGroups
	}
	if cfg.MaxDatapointsPerBatch == 0 {
		cfg.MaxDatapointsPerBatch = defaults.MaxDatapointsPerBatch
	}
	if cfg.DialOut.ServerConfig.NetAddr.Endpoint == "" {
		cfg.DialOut.ServerConfig = defaults.DialOut.ServerConfig
	}
	for i := range cfg.DialIn.Targets {
		cfg.DialIn.Targets[i] = cfg.DialIn.Targets[i].withDefaults(cfg)
	}
	return cfg
}

func (target IOSXRTargetConfig) withDefaults(parent IOSXRConfig) IOSXRTargetConfig {
	defaults := defaultIOSXRTargetConfig()
	if target.Endpoint == "" {
		target.ClientConfig = defaults.ClientConfig
	}
	target.Subscription = target.Subscription.withDefaults(parent.Subscription)
	if len(target.EncodingPreference) == 0 {
		target.EncodingPreference = parent.EncodingPreference
	}
	if target.PathGroups == nil {
		target.PathGroups = parent.PathGroups
	}
	if target.PlatformFamily == "" {
		target.PlatformFamily = "ios_xr"
	}
	return target
}

func (sub IOSXRSubscriptionConfig) withDefaults(defaults IOSXRSubscriptionConfig) IOSXRSubscriptionConfig {
	if sub.Mode == "" {
		sub.Mode = defaults.Mode
	}
	if sub.StreamMode == "" {
		sub.StreamMode = defaults.StreamMode
	}
	if sub.SampleInterval == 0 {
		sub.SampleInterval = defaults.SampleInterval
	}
	if sub.HeartbeatInterval == 0 {
		sub.HeartbeatInterval = defaults.HeartbeatInterval
	}
	if sub.PollInterval == 0 {
		sub.PollInterval = sub.SampleInterval
	}
	return sub
}

func validIOSXRUnsupportedAction(action string) bool {
	switch action {
	case iosXRUnsupportedWarn, iosXRUnsupportedError, iosXRUnsupportedIgnore:
		return true
	default:
		return false
	}
}

func validateIOSXREncodings(prefix string, values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("%s must include at least one encoding", prefix)
	}
	var err error
	for i, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "json_ietf", "json", "proto":
		default:
			err = multierr.Append(err, fmt.Errorf("%s[%d] must be json_ietf, json, or proto", prefix, i))
		}
	}
	return err
}

func validateIOSXRSubscription(prefix string, sub IOSXRSubscriptionConfig, targetDefinedNative bool) error {
	var err error
	switch sub.Mode {
	case iosXRSubscribeModeOnce, iosXRSubscribeModePoll, iosXRSubscribeModeStream:
	default:
		err = multierr.Append(err, fmt.Errorf("%s.mode must be once, poll, or stream", prefix))
	}
	switch sub.StreamMode {
	case iosXRStreamModeSample, iosXRStreamModeOnChange, iosXRStreamModeTargetDefined:
	default:
		err = multierr.Append(err, fmt.Errorf("%s.stream_mode must be sample, on_change, or target_defined", prefix))
	}
	if sub.SampleInterval < 0 {
		err = multierr.Append(err, fmt.Errorf("%s.sample_interval must not be negative", prefix))
	}
	if sub.HeartbeatInterval < 0 {
		err = multierr.Append(err, fmt.Errorf("%s.heartbeat_interval must not be negative", prefix))
	}
	if sub.PollInterval < 0 {
		err = multierr.Append(err, fmt.Errorf("%s.poll_interval must not be negative", prefix))
	}
	if sub.Mode == iosXRSubscribeModePoll && sub.PollInterval == 0 && sub.SampleInterval == 0 {
		err = multierr.Append(err, fmt.Errorf("%s.poll_interval or %s.sample_interval must be positive for poll mode", prefix, prefix))
	}
	_ = targetDefinedNative
	return err
}

func validateIOSXRPathGroups(prefix string, groups map[string]IOSXRPathGroupConfig) error {
	var err error
	for name := range groups {
		if !isKnownIOSXRPathGroup(name) {
			err = multierr.Append(err, fmt.Errorf("%s.%s is not a known IOS XR path group", prefix, name))
		}
	}
	return err
}

func validateIOSXRPaths(prefix string, paths IOSXRPathOverrideConfig) error {
	var err error
	for i, path := range paths.Include {
		path = strings.TrimSpace(path)
		if path == "" {
			err = multierr.Append(err, fmt.Errorf("%s.include[%d] cannot be empty", prefix, i))
			continue
		}
		if strings.Contains(path, "*") {
			err = multierr.Append(err, fmt.Errorf("%s.include[%d] cannot contain wildcards because IOS XR gNMI does not support wildcard paths", prefix, i))
			continue
		}
		if _, parseErr := parseGNMIPath(path); parseErr != nil {
			err = multierr.Append(err, fmt.Errorf("%s.include[%d] must be a valid gNMI path: %w", prefix, i, parseErr))
		}
	}
	for i, path := range paths.Exclude {
		if strings.TrimSpace(path) == "" {
			err = multierr.Append(err, fmt.Errorf("%s.exclude[%d] cannot be empty", prefix, i))
		}
	}
	return err
}
