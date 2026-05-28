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

// Catalyst9800CredentialsConfig represents Catalyst 9800 gNMI metadata credentials.
type Catalyst9800CredentialsConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Username string              `mapstructure:"username"`
	Password configopaque.String `mapstructure:"password"`
}

// Catalyst9800PathGroupConfig controls a curated Catalyst 9800 telemetry path group.
type Catalyst9800PathGroupConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled bool `mapstructure:"enabled"`
}

// Catalyst9800PathOverrideConfig provides custom Catalyst 9800 path include/exclude controls.
type Catalyst9800PathOverrideConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Include []string `mapstructure:"include"`
	Exclude []string `mapstructure:"exclude"`
}

// Catalyst9800SubscriptionConfig defines Catalyst 9800 gNMI subscription behavior.
type Catalyst9800SubscriptionConfig struct {
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

// Catalyst9800TargetConfig identifies one Catalyst 9800 gNMI dial-in target.
type Catalyst9800TargetConfig struct {
	configgrpc.ClientConfig `mapstructure:",squash"`

	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Name               string                                 `mapstructure:"name"`
	PlatformFamily     string                                 `mapstructure:"platform_family"`
	Credentials        Catalyst9800CredentialsConfig          `mapstructure:"credentials"`
	Subscription       Catalyst9800SubscriptionConfig         `mapstructure:"subscription"`
	EncodingPreference []string                               `mapstructure:"encoding_preference"`
	PathGroups         map[string]Catalyst9800PathGroupConfig `mapstructure:"path_groups"`
	Paths              Catalyst9800PathOverrideConfig         `mapstructure:"paths"`
	SkipCapabilities   bool                                   `mapstructure:"skip_capabilities"`
}

// Catalyst9800DialInConfig defines dynamic Catalyst 9800 gNMI subscriptions initiated by the collector.
type Catalyst9800DialInConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Targets []Catalyst9800TargetConfig `mapstructure:"targets"`
}

// Catalyst9800DialOutConfig defines Catalyst 9800 MDT gRPC dial-out server settings.
type Catalyst9800DialOutConfig struct {
	configgrpc.ServerConfig `mapstructure:",squash"`

	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled        bool     `mapstructure:"enabled"`
	AllowedClients []string `mapstructure:"allowed_clients"`
	ModulePaths    []string `mapstructure:"module_paths"`
}

// Catalyst9800Config defines direct Catalyst 9800 WLC telemetry settings.
type Catalyst9800Config struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled               bool                                   `mapstructure:"enabled"`
	PathGroups            map[string]Catalyst9800PathGroupConfig `mapstructure:"path_groups"`
	DialIn                Catalyst9800DialInConfig               `mapstructure:"dial_in"`
	DialOut               Catalyst9800DialOutConfig              `mapstructure:"dial_out"`
	Paths                 Catalyst9800PathOverrideConfig         `mapstructure:"paths"`
	UnsupportedPathAction string                                 `mapstructure:"unsupported_path_action"`
	EncodingPreference    []string                               `mapstructure:"encoding_preference"`
	Subscription          Catalyst9800SubscriptionConfig         `mapstructure:"subscription"`
	MaxDatapointsPerBatch int                                    `mapstructure:"max_datapoints_per_batch"`
}

func defaultCatalyst9800Config() Catalyst9800Config {
	server := configgrpc.NewDefaultServerConfig()
	server.NetAddr.Endpoint = "localhost:57501"
	server.NetAddr.Transport = "tcp"
	server.MaxRecvMsgSizeMiB = 4
	server.MaxConcurrentStreams = 100
	server.Keepalive.GetOrInsertDefault().ServerParameters.GetOrInsertDefault().Time = 30 * time.Second
	server.Keepalive.GetOrInsertDefault().ServerParameters.GetOrInsertDefault().Timeout = 10 * time.Second

	return Catalyst9800Config{
		PathGroups:            defaultCatalyst9800PathGroups(),
		DialOut:               Catalyst9800DialOutConfig{ServerConfig: server},
		UnsupportedPathAction: iosXRUnsupportedWarn,
		EncodingPreference:    []string{"json_ietf", "json"},
		Subscription:          defaultCatalyst9800SubscriptionConfig(),
		MaxDatapointsPerBatch: 50000,
	}
}

func defaultCatalyst9800PathGroups() map[string]Catalyst9800PathGroupConfig {
	groups := make(map[string]Catalyst9800PathGroupConfig, len(catalyst9800PathGroupNames()))
	for _, name := range catalyst9800PathGroupNames() {
		_, enabled := catalyst9800SafeDefaultPathGroups[name]
		groups[name] = Catalyst9800PathGroupConfig{Enabled: enabled}
	}
	return groups
}

func defaultCatalyst9800TargetConfig() Catalyst9800TargetConfig {
	return Catalyst9800TargetConfig{
		ClientConfig:       configgrpc.NewDefaultClientConfig(),
		Subscription:       defaultCatalyst9800SubscriptionConfig(),
		EncodingPreference: []string{"json_ietf", "json"},
		PathGroups:         defaultCatalyst9800PathGroups(),
		PlatformFamily:     "catalyst_9800",
	}
}

func defaultCatalyst9800SubscriptionConfig() Catalyst9800SubscriptionConfig {
	return Catalyst9800SubscriptionConfig{
		Mode:              iosXRSubscribeModeStream,
		StreamMode:        iosXRStreamModeSample,
		SampleInterval:    time.Minute,
		HeartbeatInterval: time.Minute,
		SuppressRedundant: true,
	}
}

func (cfg Catalyst9800Config) hasTarget() bool {
	return cfg.Enabled || cfg.DialOut.Enabled || len(cfg.DialIn.Targets) > 0
}

func (cfg *Config) validateCatalyst9800() error {
	if !cfg.Catalyst9800.hasTarget() {
		return nil
	}

	var err error
	wlc := cfg.Catalyst9800.withDefaults()
	if !wlc.Enabled && (wlc.DialOut.Enabled || len(wlc.DialIn.Targets) > 0) {
		err = multierr.Append(err, errors.New("catalyst_9800.enabled must be true when Catalyst 9800 dial_in targets or dial_out are configured"))
	}
	if !validIOSXRUnsupportedAction(wlc.UnsupportedPathAction) {
		err = multierr.Append(err, errors.New("catalyst_9800.unsupported_path_action must be warn, error, or ignore"))
	}
	if wlc.MaxDatapointsPerBatch < 0 {
		err = multierr.Append(err, errors.New("catalyst_9800.max_datapoints_per_batch must not be negative"))
	}
	err = multierr.Append(err, validateCatalyst9800Encodings("catalyst_9800.encoding_preference", wlc.EncodingPreference))
	err = multierr.Append(err, validateCatalyst9800Subscription("catalyst_9800.subscription", wlc.Subscription))
	err = multierr.Append(err, validateCatalyst9800PathGroups("catalyst_9800.path_groups", wlc.PathGroups))
	err = multierr.Append(err, validateCatalyst9800Paths("catalyst_9800.paths", wlc.Paths))

	if len(wlc.DialIn.Targets) == 0 && !wlc.DialOut.Enabled {
		err = multierr.Append(err, errors.New("catalyst_9800 requires at least one dial_in target or dial_out.enabled: true"))
	}
	names := map[string]struct{}{}
	for i, target := range wlc.DialIn.Targets {
		target = target.withDefaults(wlc)
		prefix := fmt.Sprintf("catalyst_9800.dial_in.targets[%d]", i)
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
		err = multierr.Append(err, validateCatalyst9800Encodings(prefix+".encoding_preference", target.EncodingPreference))
		err = multierr.Append(err, validateCatalyst9800Subscription(prefix+".subscription", target.Subscription))
		err = multierr.Append(err, validateCatalyst9800PathGroups(prefix+".path_groups", target.PathGroups))
		err = multierr.Append(err, validateCatalyst9800Paths(prefix+".paths", target.Paths))
		if len(resolveCatalyst9800PathSelection(wlc.PathGroups, wlc.Paths, &target)) == 0 {
			err = multierr.Append(err, fmt.Errorf("%s requires at least one enabled path group or custom path include", prefix))
		}
	}

	if wlc.DialOut.Enabled {
		if grpcErr := wlc.DialOut.ServerConfig.Validate(); grpcErr != nil {
			err = multierr.Append(err, fmt.Errorf("catalyst_9800.dial_out: %w", grpcErr))
		}
	}

	return err
}

func (cfg Catalyst9800Config) withDefaults() Catalyst9800Config {
	defaults := defaultCatalyst9800Config()
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

func (target Catalyst9800TargetConfig) withDefaults(parent Catalyst9800Config) Catalyst9800TargetConfig {
	defaults := defaultCatalyst9800TargetConfig()
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
		target.PlatformFamily = "catalyst_9800"
	}
	return target
}

func (sub Catalyst9800SubscriptionConfig) withDefaults(defaults Catalyst9800SubscriptionConfig) Catalyst9800SubscriptionConfig {
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

func validateCatalyst9800Encodings(prefix string, values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("%s must include at least one encoding", prefix)
	}
	var err error
	for i, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "json_ietf", "json":
		default:
			err = multierr.Append(err, fmt.Errorf("%s[%d] must be json_ietf or json", prefix, i))
		}
	}
	return err
}

func validateCatalyst9800Subscription(prefix string, sub Catalyst9800SubscriptionConfig) error {
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
	return err
}

func validateCatalyst9800PathGroups(prefix string, groups map[string]Catalyst9800PathGroupConfig) error {
	var err error
	for name := range groups {
		if !isKnownCatalyst9800PathGroup(name) {
			err = multierr.Append(err, fmt.Errorf("%s.%s is not a known Catalyst 9800 path group", prefix, name))
		}
	}
	return err
}

func validateCatalyst9800Paths(prefix string, paths Catalyst9800PathOverrideConfig) error {
	var err error
	for i, path := range paths.Include {
		path = strings.TrimSpace(path)
		if path == "" {
			err = multierr.Append(err, fmt.Errorf("%s.include[%d] cannot be empty", prefix, i))
			continue
		}
		if strings.Contains(path, "*") {
			err = multierr.Append(err, fmt.Errorf("%s.include[%d] cannot contain wildcards because Catalyst 9800 gNMI does not support wildcard paths", prefix, i))
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
