// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"errors"
	"fmt"
	"math"
	"net"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/collector/config/configopaque"
	"go.uber.org/multierr"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

const (
	gnmiPlatformIOSXE = "ios_xe"
	gnmiPlatformIOSXR = "ios_xr"
	gnmiPlatformNXOS  = "nx_os"

	gnmiCredentialUsernamePassword     = "username_password"
	gnmiCredentialMTLS                 = "mtls"
	gnmiCredentialMTLSUsernamePassword = "mtls_username_password" //nolint:gosec // Credential-mode enum identifier, not a credential.

	gnmiModeStream = "stream"
	gnmiModeOnce   = "once"
	gnmiModePoll   = "poll"

	gnmiStreamModeAuto          = "auto"
	gnmiStreamModeSample        = "sample"
	gnmiStreamModeOnChange      = "on_change"
	gnmiStreamModeTargetDefined = "target_defined"

	gnmiEncodingAuto     = "auto"
	gnmiEncodingProto    = "proto"
	gnmiEncodingJSONIETF = "json_ietf"
	gnmiEncodingJSON     = "json"

	gnmiDefaultSyncTimeout = 2 * time.Minute
	gnmiMaximumSyncTimeout = 30 * time.Minute
	gnmiDefaultMaxStreams  = 4
	gnmiMaximumStreams     = 16

	// grpc-go buffers the frame before the forced response codec can scan its
	// wire complexity and build protobuf objects. Keep a hard frame ceiling
	// aligned with the receiver's other network payload limits to prevent
	// multi-gigabyte allocation attempts from a compromised telemetry endpoint.
	gnmiMaxRecvMsgSizeMiB     = 16
	gnmiMaxDatapointsPerChunk = 10_000
	gnmiMaximumCachedSeries   = 500_000
	gnmiMaximumTargets        = 256
	gnmiMaximumInFlightMiB    = 512
)

var (
	normalizedMetricNamePattern    = regexp.MustCompile(`^[a-z][a-z0-9_.]*$`)
	normalizedAttributeNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]*$`)
	normalizedGNMIGroupNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	gnmiUCUMAnnotationPattern      = regexp.MustCompile(`^\{[A-Za-z][A-Za-z0-9_.-]*\}$`)
)

var gnmiUCUMAtoms = map[string]struct{}{
	"A": {}, "B": {}, "By": {}, "C": {}, "Cel": {}, "F": {}, "H": {}, "Hz": {}, "J": {}, "K": {},
	"L": {}, "N": {}, "Ohm": {}, "Pa": {}, "S": {}, "T": {}, "Torr": {}, "V": {}, "W": {}, "Wb": {},
	"[deg]": {}, "[degF]": {}, "a": {}, "atm": {}, "bar": {}, "bit": {}, "cd": {}, "d": {}, "dB": {},
	"deg": {}, "eV": {}, "g": {}, "h": {}, "l": {}, "m": {}, "min": {}, "mo": {}, "mol": {}, "rad": {},
	"s": {}, "sr": {}, "wk": {},
}

var gnmiUCUMPrefixableAtoms = map[string]struct{}{
	"A": {}, "By": {}, "C": {}, "F": {}, "H": {}, "Hz": {}, "J": {}, "K": {}, "L": {}, "N": {},
	"Ohm": {}, "Pa": {}, "S": {}, "T": {}, "V": {}, "W": {}, "Wb": {}, "bit": {}, "eV": {}, "g": {},
	"l": {}, "m": {}, "mol": {}, "rad": {}, "s": {}, "sr": {},
}

var gnmiUCUMPrefixes = []string{
	"Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "da", "Y", "Z", "E", "P", "T", "G", "M", "k", "h", "d", "c", "m", "u", "n", "p", "f", "a", "z", "y",
}

var gnmiUCUMSpecialUnits = map[string]struct{}{
	"1": {}, "%": {}, "dB[mW]": {}, "B[SPL]": {}, "B[V]": {}, "B[mV]": {}, "B[uV]": {}, "B[W]": {}, "B[kW]": {},
}

// GNMICredentialsConfig configures the deliberately small set of supported
// gNMI authentication modes. Credentials are sent as gRPC metadata only for
// modes that include username/password.
type GNMICredentialsConfig struct {
	_ struct{} `mapstructure:"-"`

	Mode     string              `mapstructure:"mode"`
	Username string              `mapstructure:"username"`
	Password configopaque.String `mapstructure:"password"`
}

// GNMITLSConfig exposes only verified TLS settings used by the shared client.
// The insecure fields are retained solely so configuration validation can
// reject them with a specific error rather than silently accepting them.
type GNMITLSConfig struct {
	_ struct{} `mapstructure:"-"`

	CAFile             string        `mapstructure:"ca_file"`
	CertFile           string        `mapstructure:"cert_file"`
	KeyFile            string        `mapstructure:"key_file"`
	MinVersion         string        `mapstructure:"min_version"`
	ServerNameOverride string        `mapstructure:"server_name_override"`
	ReloadInterval     time.Duration `mapstructure:"reload_interval"`
	Insecure           bool          `mapstructure:"insecure"`
	InsecureSkipVerify bool          `mapstructure:"insecure_skip_verify"`
}

// GNMIKeepaliveConfig controls client-side HTTP/2 keepalive without exposing
// the Collector gRPC ClientConfig or arbitrary request headers.
type GNMIKeepaliveConfig struct {
	_ struct{} `mapstructure:"-"`

	Time                time.Duration `mapstructure:"time"`
	Timeout             time.Duration `mapstructure:"timeout"`
	PermitWithoutStream *bool         `mapstructure:"permit_without_stream"`
}

// GNMIProfileConfig controls one curated subscription profile. Pointer booleans
// preserve the distinction between an omitted value and enabled: false.
type GNMIProfileConfig struct {
	_ struct{} `mapstructure:"-"`

	Enabled        *bool                      `mapstructure:"enabled"`
	Required       bool                       `mapstructure:"required"`
	SampleInterval time.Duration              `mapstructure:"sample_interval"`
	StreamMode     string                     `mapstructure:"stream_mode"`
	Groups         map[string]GNMIGroupConfig `mapstructure:"groups"`
	// streamModeDefaulted preserves whether sample came from the public default
	// so catalog-only paths (notably bootstrap identity) can conservatively
	// select their sole declared mode without treating a user-specified sample
	// as implicit.
	streamModeDefaulted bool
}

// GNMIGroupConfig controls one catalog-declared group within a normalized
// profile. Selectors are exact matches on catalog-declared keys.
type GNMIGroupConfig struct {
	_ struct{} `mapstructure:"-"`

	Enabled        *bool               `mapstructure:"enabled"`
	Required       bool                `mapstructure:"required"`
	SampleInterval time.Duration       `mapstructure:"sample_interval"`
	StreamMode     string              `mapstructure:"stream_mode"`
	SyncTimeout    time.Duration       `mapstructure:"sync_timeout"`
	MaxEntities    int                 `mapstructure:"max_entities"`
	Selectors      map[string][]string `mapstructure:"selectors"`
	// streamModeDefaulted records that stream_mode inherited the profile
	// value. Runtime stream planning uses it to conservatively select a sole
	// catalog-declared mode without treating the inherited value as an
	// explicit request.
	streamModeDefaulted bool
}

// GNMIProfilesConfig contains the normalized profile set.
type GNMIProfilesConfig struct {
	_ struct{} `mapstructure:"-"`

	Identity             GNMIProfileConfig `mapstructure:"identity"`
	System               GNMIProfileConfig `mapstructure:"system"`
	Interfaces           GNMIProfileConfig `mapstructure:"interfaces"`
	Optics               GNMIProfileConfig `mapstructure:"optics"`
	Catalyst9800Wireless GNMIProfileConfig `mapstructure:"catalyst_9800_wireless"`
	Inventory            GNMIProfileConfig `mapstructure:"inventory"`
	Environment          GNMIProfileConfig `mapstructure:"environment"`
	L2                   GNMIProfileConfig `mapstructure:"l2"`
	Routing              GNMIProfileConfig `mapstructure:"routing"`
	MPLS                 GNMIProfileConfig `mapstructure:"mpls"`
	Overlay              GNMIProfileConfig `mapstructure:"overlay"`
	QoS                  GNMIProfileConfig `mapstructure:"qos"`
	ACL                  GNMIProfileConfig `mapstructure:"acl"`
	Topology             GNMIProfileConfig `mapstructure:"topology"`
	PoE                  GNMIProfileConfig `mapstructure:"poe"`
	TimeSync             GNMIProfileConfig `mapstructure:"time_sync"`
	HighAvailability     GNMIProfileConfig `mapstructure:"high_availability"`
	ASIC                 GNMIProfileConfig `mapstructure:"asic"`
	TelemetrySelf        GNMIProfileConfig `mapstructure:"telemetry_self"`
}

// GNMIMetricMappingConfig is a complete scalar-to-gauge mapping. PathKeys maps
// "element.key" selectors to bounded OTLP attribute names.
type GNMIMetricMappingConfig struct {
	_ struct{} `mapstructure:"-"`

	Path        string            `mapstructure:"path"`
	MetricName  string            `mapstructure:"metric_name"`
	Description string            `mapstructure:"description"`
	Unit        string            `mapstructure:"unit"`
	Scale       *float64          `mapstructure:"scale"`
	GaugeType   string            `mapstructure:"gauge_type"`
	PathKeys    map[string]string `mapstructure:"path_keys"`
}

// GNMICustomSubscriptionConfig defines explicitly mapped custom scalar paths.
// Origin is independent of every path; raw origin:path strings are rejected by
// the path parser.
type GNMICustomSubscriptionConfig struct {
	_ struct{} `mapstructure:"-"`

	Name           string                    `mapstructure:"name"`
	Origin         string                    `mapstructure:"origin"`
	Mode           string                    `mapstructure:"mode"`
	SampleInterval time.Duration             `mapstructure:"sample_interval"`
	PollInterval   time.Duration             `mapstructure:"poll_interval"`
	Required       bool                      `mapstructure:"required"`
	Encoding       string                    `mapstructure:"encoding"`
	Mappings       []GNMIMetricMappingConfig `mapstructure:"mappings"`
}

// GNMITargetConfig identifies one statically owned dial-in target.
type GNMITargetConfig struct {
	_ struct{} `mapstructure:"-"`

	Name                string                         `mapstructure:"name"`
	Endpoint            string                         `mapstructure:"endpoint"`
	Platform            string                         `mapstructure:"platform"`
	ProductFamily       string                         `mapstructure:"product_family"`
	MaxRecvMsgSizeMiB   int                            `mapstructure:"max_recv_msg_size_mib"`
	MaxStreams          int                            `mapstructure:"max_streams"`
	ConnectTimeout      time.Duration                  `mapstructure:"connect_timeout"`
	CapabilitiesTimeout time.Duration                  `mapstructure:"capabilities_timeout"`
	SyncTimeout         time.Duration                  `mapstructure:"sync_timeout"`
	EncodingPreference  []string                       `mapstructure:"encoding_preference"`
	Credentials         GNMICredentialsConfig          `mapstructure:"credentials"`
	TLS                 GNMITLSConfig                  `mapstructure:"tls"`
	Keepalive           GNMIKeepaliveConfig            `mapstructure:"keepalive"`
	Profiles            GNMIProfilesConfig             `mapstructure:"profiles"`
	CustomSubscriptions []GNMICustomSubscriptionConfig `mapstructure:"custom_subscriptions"`
}

// GNMIConfig configures the shared production gNMI engine.
type GNMIConfig struct {
	_ struct{} `mapstructure:"-"`

	MaxDatapointsPerChunk int                `mapstructure:"max_datapoints_per_chunk"`
	MaxCachedSeries       int                `mapstructure:"max_cached_series"`
	Targets               []GNMITargetConfig `mapstructure:"targets"`
}

func defaultGNMIConfig() GNMIConfig {
	return GNMIConfig{MaxDatapointsPerChunk: gnmiMaxDatapointsPerChunk, MaxCachedSeries: gnmiMaximumCachedSeries}
}

func (cfg GNMIConfig) hasTargets() bool { return len(cfg.Targets) > 0 }

func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func (profile GNMIProfileConfig) withDefaults(enabled bool, interval, syncTimeout time.Duration) GNMIProfileConfig {
	if profile.Enabled == nil {
		profile.Enabled = new(bool)
		*profile.Enabled = enabled
	}
	if profile.SampleInterval == 0 {
		profile.SampleInterval = interval
	}
	if profile.StreamMode == "" {
		profile.StreamMode = gnmiStreamModeSample
		profile.streamModeDefaulted = true
	}
	if profile.Groups != nil {
		groups := make(map[string]GNMIGroupConfig, len(profile.Groups))
		for name, group := range profile.Groups {
			if group.SampleInterval == 0 {
				group.SampleInterval = profile.SampleInterval
			}
			if group.StreamMode == "" {
				group.StreamMode = profile.StreamMode
				group.streamModeDefaulted = profile.streamModeDefaulted
			}
			if group.SyncTimeout == 0 {
				group.SyncTimeout = syncTimeout
			}
			groups[name] = group
		}
		profile.Groups = groups
	}
	return profile
}

func (profiles GNMIProfilesConfig) withDefaults(syncTimeout time.Duration) GNMIProfilesConfig {
	profiles.Identity = profiles.Identity.withDefaults(true, 5*time.Minute, syncTimeout)
	profiles.System = profiles.System.withDefaults(true, time.Minute, syncTimeout)
	profiles.Interfaces = profiles.Interfaces.withDefaults(true, time.Minute, syncTimeout)
	profiles.Optics = profiles.Optics.withDefaults(false, 30*time.Second, syncTimeout)
	profiles.Catalyst9800Wireless = profiles.Catalyst9800Wireless.withDefaults(false, time.Minute, syncTimeout)
	profiles.Inventory = profiles.Inventory.withDefaults(false, time.Minute, syncTimeout)
	profiles.Environment = profiles.Environment.withDefaults(false, time.Minute, syncTimeout)
	profiles.L2 = profiles.L2.withDefaults(false, time.Minute, syncTimeout)
	profiles.Routing = profiles.Routing.withDefaults(false, time.Minute, syncTimeout)
	profiles.MPLS = profiles.MPLS.withDefaults(false, time.Minute, syncTimeout)
	profiles.Overlay = profiles.Overlay.withDefaults(false, time.Minute, syncTimeout)
	profiles.QoS = profiles.QoS.withDefaults(false, time.Minute, syncTimeout)
	profiles.ACL = profiles.ACL.withDefaults(false, time.Minute, syncTimeout)
	profiles.Topology = profiles.Topology.withDefaults(false, time.Minute, syncTimeout)
	profiles.PoE = profiles.PoE.withDefaults(false, time.Minute, syncTimeout)
	profiles.TimeSync = profiles.TimeSync.withDefaults(false, time.Minute, syncTimeout)
	profiles.HighAvailability = profiles.HighAvailability.withDefaults(false, time.Minute, syncTimeout)
	profiles.ASIC = profiles.ASIC.withDefaults(false, time.Minute, syncTimeout)
	profiles.TelemetrySelf = profiles.TelemetrySelf.withDefaults(false, time.Minute, syncTimeout)
	return profiles
}

func (target GNMITargetConfig) withDefaults() GNMITargetConfig {
	target.ProductFamily = strings.ToLower(strings.TrimSpace(target.ProductFamily))
	if target.MaxRecvMsgSizeMiB == 0 {
		target.MaxRecvMsgSizeMiB = 16
	}
	if target.MaxStreams == 0 {
		target.MaxStreams = gnmiDefaultMaxStreams
	}
	if target.ConnectTimeout == 0 {
		target.ConnectTimeout = 15 * time.Second
	}
	if target.CapabilitiesTimeout == 0 {
		target.CapabilitiesTimeout = 15 * time.Second
	}
	if target.SyncTimeout == 0 {
		target.SyncTimeout = gnmiDefaultSyncTimeout
	}
	if len(target.EncodingPreference) == 0 {
		target.EncodingPreference = []string{gnmiEncodingJSONIETF, gnmiEncodingJSON}
	} else {
		target.EncodingPreference = append([]string(nil), target.EncodingPreference...)
	}
	if target.Credentials.Mode == "" {
		target.Credentials.Mode = gnmiCredentialUsernamePassword
	}
	if target.TLS.MinVersion == "" {
		target.TLS.MinVersion = "1.2"
	}
	if target.Keepalive.Time == 0 {
		target.Keepalive.Time = 30 * time.Second
	}
	if target.Keepalive.Timeout == 0 {
		target.Keepalive.Timeout = 10 * time.Second
	}
	if target.Keepalive.PermitWithoutStream == nil {
		target.Keepalive.PermitWithoutStream = new(bool)
		*target.Keepalive.PermitWithoutStream = true
	}
	target.Profiles = target.Profiles.withDefaults(target.SyncTimeout)
	for i := range target.CustomSubscriptions {
		if target.CustomSubscriptions[i].Mode == "" {
			target.CustomSubscriptions[i].Mode = gnmiModeStream
		}
		if target.CustomSubscriptions[i].SampleInterval == 0 {
			target.CustomSubscriptions[i].SampleInterval = time.Minute
		}
		if target.CustomSubscriptions[i].PollInterval == 0 {
			target.CustomSubscriptions[i].PollInterval = target.CustomSubscriptions[i].SampleInterval
		}
		if target.CustomSubscriptions[i].Encoding == "" {
			target.CustomSubscriptions[i].Encoding = gnmiEncodingAuto
		}
	}
	return target
}

func (cfg *Config) validateGNMI() error {
	var err error
	err = multierr.Append(err, cfg.validateGNMITelemetryResourceLimits())
	if !cfg.GNMI.hasTargets() {
		return err
	}
	defaults := defaultGNMIConfig()
	maxChunk := cfg.GNMI.MaxDatapointsPerChunk
	if maxChunk == 0 {
		maxChunk = defaults.MaxDatapointsPerChunk
	}
	if maxChunk <= 0 {
		err = multierr.Append(err, errors.New("gnmi.max_datapoints_per_chunk must be positive"))
	} else if maxChunk > gnmiMaxDatapointsPerChunk {
		err = multierr.Append(err, fmt.Errorf("gnmi.max_datapoints_per_chunk must not exceed %d", gnmiMaxDatapointsPerChunk))
	}
	maxSeries := cfg.GNMI.MaxCachedSeries
	if maxSeries == 0 {
		maxSeries = defaults.MaxCachedSeries
	}
	if maxSeries <= 0 {
		err = multierr.Append(err, errors.New("gnmi.max_cached_series must be positive"))
	} else if maxSeries > gnmiMaximumCachedSeries {
		err = multierr.Append(err, fmt.Errorf("gnmi.max_cached_series must not exceed %d", gnmiMaximumCachedSeries))
	}

	names := map[string]int{}
	endpoints := map[string]int{}
	legacy := cfg.legacyGNMIEndpoints()
	selector := newDeviceSelectionMatcher(cfg.DeviceSelection)
	selectedTargets := 0
	for i := range cfg.GNMI.Targets {
		target := cfg.GNMI.Targets[i].withDefaults()
		prefix := fmt.Sprintf("gnmi.targets[%d]", i)
		name := strings.ToLower(strings.TrimSpace(target.Name))
		if name == "" {
			err = multierr.Append(err, fmt.Errorf("%s.name cannot be empty", prefix))
		} else if previous, ok := names[name]; ok {
			err = multierr.Append(err, fmt.Errorf("%s.name duplicates gnmi.targets[%d].name", prefix, previous))
		} else {
			names[name] = i
		}
		endpoint := strings.ToLower(strings.TrimSpace(target.Endpoint))
		if endpoint == "" {
			err = multierr.Append(err, fmt.Errorf("%s.endpoint cannot be empty", prefix))
		} else if _, _, splitErr := net.SplitHostPort(target.Endpoint); splitErr != nil {
			err = multierr.Append(err, fmt.Errorf("%s.endpoint must be host:port: %w", prefix, splitErr))
		} else if previous, ok := endpoints[endpoint]; ok {
			err = multierr.Append(err, fmt.Errorf("%s.endpoint duplicates gnmi.targets[%d].endpoint", prefix, previous))
		} else if legacyName, ok := legacy[endpoint]; ok {
			err = multierr.Append(err, fmt.Errorf("%s.endpoint is already configured by legacy %s dial_in", prefix, legacyName))
		} else {
			endpoints[endpoint] = i
		}
		err = multierr.Append(err, validateGNMITarget(prefix, target))
		if selector.allows(sharedGNMITargetIdentity(target)) &&
			target.MaxRecvMsgSizeMiB > 0 && target.MaxRecvMsgSizeMiB <= gnmiMaxRecvMsgSizeMiB &&
			target.MaxStreams > 0 && target.MaxStreams <= gnmiMaximumStreams {
			selectedTargets++
		}
	}
	if maxSeries > 0 && selectedTargets > maxSeries {
		err = multierr.Append(err, fmt.Errorf(
			"gnmi.max_cached_series %d is smaller than the selected target count %d",
			maxSeries,
			selectedTargets,
		))
	}
	err = multierr.Append(err, validateGNMIMetricContracts(cfg.GNMI.Targets))
	return err
}

func (cfg *Config) validateGNMITelemetryResourceLimits() error {
	targetDefinitions := uint64(len(cfg.GNMI.Targets)) +
		uint64(len(cfg.IOSXR.DialIn.Targets)) +
		uint64(len(cfg.Catalyst9800.DialIn.Targets))
	if targetDefinitions > gnmiMaximumTargets {
		return fmt.Errorf(
			"gnmi.targets, ios_xr.dial_in.targets, and catalyst_9800.dial_in.targets must contain at most %d targets in total",
			gnmiMaximumTargets,
		)
	}

	selector := newDeviceSelectionMatcher(cfg.DeviceSelection)
	aggregateInFlightMiB := uint64(0)
	for i := range cfg.GNMI.Targets {
		target := cfg.GNMI.Targets[i].withDefaults()
		if selector.allows(sharedGNMITargetIdentity(target)) &&
			target.MaxRecvMsgSizeMiB > 0 && target.MaxRecvMsgSizeMiB <= gnmiMaxRecvMsgSizeMiB &&
			target.MaxStreams > 0 && target.MaxStreams <= gnmiMaximumStreams {
			aggregateInFlightMiB += uint64(target.MaxRecvMsgSizeMiB) * uint64(target.MaxStreams)
		}
	}

	for i := range cfg.IOSXR.DialIn.Targets {
		if selector.allows(iosXRTargetIdentity(cfg.IOSXR.DialIn.Targets[i])) {
			aggregateInFlightMiB += legacyGNMIMaxRecvMsgSizeMiB
		}
	}
	for i := range cfg.Catalyst9800.DialIn.Targets {
		if selector.allows(catalyst9800TargetIdentity(cfg.Catalyst9800.DialIn.Targets[i])) {
			aggregateInFlightMiB += legacyGNMIMaxRecvMsgSizeMiB
		}
	}
	if dialOut := cfg.IOSXR.withDefaults().DialOut; dialOut.Enabled &&
		dialOut.MaxRecvMsgSizeMiB >= minimumGNMIDialOutReceiveSizeMiB &&
		dialOut.MaxRecvMsgSizeMiB <= maximumGNMIDialOutReceiveSizeMiB &&
		dialOut.MaxConcurrentStreams >= minimumGNMIDialOutStreams &&
		dialOut.MaxConcurrentStreams <= maximumGNMIDialOutStreams {
		aggregateInFlightMiB += uint64(dialOut.MaxRecvMsgSizeMiB) * uint64(dialOut.MaxConcurrentStreams)
	}
	if dialOut := cfg.Catalyst9800.withDefaults().DialOut; dialOut.Enabled &&
		dialOut.MaxRecvMsgSizeMiB >= minimumGNMIDialOutReceiveSizeMiB &&
		dialOut.MaxRecvMsgSizeMiB <= maximumGNMIDialOutReceiveSizeMiB &&
		dialOut.MaxConcurrentStreams >= minimumGNMIDialOutStreams &&
		dialOut.MaxConcurrentStreams <= maximumGNMIDialOutStreams {
		aggregateInFlightMiB += uint64(dialOut.MaxRecvMsgSizeMiB) * uint64(dialOut.MaxConcurrentStreams)
	}

	if aggregateInFlightMiB > gnmiMaximumInFlightMiB {
		return fmt.Errorf(
			"selected gNMI dial-in targets and enabled dial-out servers require %d MiB of stream-by-frame capacity, exceeding the %d MiB receiver-wide limit",
			aggregateInFlightMiB,
			gnmiMaximumInFlightMiB,
		)
	}
	return nil
}

func validateGNMITarget(prefix string, target GNMITargetConfig) error {
	var err error
	switch target.Platform {
	case "", gnmiPlatformIOSXE, gnmiPlatformIOSXR, gnmiPlatformNXOS:
	default:
		err = multierr.Append(err, fmt.Errorf("%s.platform must be empty, ios_xe, ios_xr, or nx_os", prefix))
	}
	if target.MaxRecvMsgSizeMiB <= 0 {
		err = multierr.Append(err, fmt.Errorf("%s.max_recv_msg_size_mib must be positive", prefix))
	} else if target.MaxRecvMsgSizeMiB > gnmiMaxRecvMsgSizeMiB {
		err = multierr.Append(err, fmt.Errorf("%s.max_recv_msg_size_mib must not exceed %d", prefix, gnmiMaxRecvMsgSizeMiB))
	}
	switch {
	case target.MaxStreams < 1 || target.MaxStreams > gnmiMaximumStreams:
		err = multierr.Append(err, fmt.Errorf("%s.max_streams must be between 1 and %d", prefix, gnmiMaximumStreams))
	case target.MaxStreams > gnmiDefaultMaxStreams && strings.TrimSpace(target.ProductFamily) == "":
		err = multierr.Append(err, fmt.Errorf("%s.product_family is required when max_streams exceeds %d", prefix, gnmiDefaultMaxStreams))
	case strings.TrimSpace(target.ProductFamily) != "":
		family, ok := gnmiCatalogProductFamily(target.ProductFamily)
		if !ok {
			err = multierr.Append(err, fmt.Errorf("%s.product_family %q is not present in the generated gNMI catalog", prefix, target.ProductFamily))
		} else {
			if target.Platform != "" && target.Platform != family.Platform {
				err = multierr.Append(err, fmt.Errorf("%s.product_family %q belongs to platform %q, not configured platform %q", prefix, target.ProductFamily, family.Platform, target.Platform))
			}
			if target.MaxStreams > family.MaxStreams {
				err = multierr.Append(err, fmt.Errorf("%s.max_streams %d exceeds generated catalog limit %d for product_family %q", prefix, target.MaxStreams, family.MaxStreams, target.ProductFamily))
			}
		}
	}
	if target.ConnectTimeout <= 0 || target.CapabilitiesTimeout <= 0 {
		err = multierr.Append(err, fmt.Errorf("%s connection and capabilities timeouts must be positive", prefix))
	}
	if target.SyncTimeout <= 0 || target.SyncTimeout > gnmiMaximumSyncTimeout {
		err = multierr.Append(err, fmt.Errorf("%s.sync_timeout must be positive and not exceed %s", prefix, gnmiMaximumSyncTimeout))
	}
	if target.Keepalive.Time <= 0 || target.Keepalive.Timeout <= 0 {
		err = multierr.Append(err, fmt.Errorf("%s.keepalive time and timeout must be positive", prefix))
	}
	err = multierr.Append(err, validateGNMICredentials(prefix, target))
	err = multierr.Append(err, validateGNMITLS(prefix, target.TLS))
	err = multierr.Append(err, validateGNMIEncodingPreference(prefix+".encoding_preference", target.EncodingPreference))
	err = multierr.Append(err, validateGNMIProfiles(prefix, target))
	err = multierr.Append(err, validateGNMICustomSubscriptions(prefix, target))
	if streams := estimateGNMIStreams(target); streams == 0 {
		err = multierr.Append(err, fmt.Errorf("%s requires at least one enabled profile or custom subscription", prefix))
	} else if streams > target.MaxStreams {
		err = multierr.Append(err, fmt.Errorf("%s requires %d compatible subscription streams, exceeding max_streams %d", prefix, streams, target.MaxStreams))
	}
	return err
}

func validateGNMICredentials(prefix string, target GNMITargetConfig) error {
	var err error
	credentials := target.Credentials
	needsPassword := credentials.Mode == gnmiCredentialUsernamePassword || credentials.Mode == gnmiCredentialMTLSUsernamePassword
	needsMTLS := credentials.Mode == gnmiCredentialMTLS || credentials.Mode == gnmiCredentialMTLSUsernamePassword
	if credentials.Mode != gnmiCredentialUsernamePassword && credentials.Mode != gnmiCredentialMTLS && credentials.Mode != gnmiCredentialMTLSUsernamePassword {
		return fmt.Errorf("%s.credentials.mode must be username_password, mtls, or mtls_username_password", prefix)
	}
	if needsPassword && strings.TrimSpace(credentials.Username) == "" {
		err = multierr.Append(err, fmt.Errorf("%s.credentials.username is required for %s", prefix, credentials.Mode))
	}
	if needsPassword && credentials.Password == "" {
		err = multierr.Append(err, fmt.Errorf("%s.credentials.password is required for %s", prefix, credentials.Mode))
	}
	if needsMTLS && (target.TLS.CertFile == "" || target.TLS.KeyFile == "") {
		err = multierr.Append(err, fmt.Errorf("%s.tls.cert_file and key_file are required for %s", prefix, credentials.Mode))
	}
	if !needsMTLS && (target.TLS.CertFile != "" || target.TLS.KeyFile != "") {
		err = multierr.Append(err, fmt.Errorf("%s.tls.cert_file and key_file require an mTLS credentials mode", prefix))
	}
	if credentials.Mode == gnmiCredentialMTLS && (credentials.Username != "" || credentials.Password != "") {
		err = multierr.Append(err, fmt.Errorf("%s.credentials username/password require username_password or mtls_username_password mode", prefix))
	}
	return err
}

func validateGNMITLS(prefix string, tls GNMITLSConfig) error {
	var err error
	if tls.Insecure {
		err = multierr.Append(err, fmt.Errorf("%s.tls.insecure is forbidden", prefix))
	}
	if tls.InsecureSkipVerify {
		err = multierr.Append(err, fmt.Errorf("%s.tls.insecure_skip_verify is forbidden", prefix))
	}
	if tls.MinVersion != "1.2" && tls.MinVersion != "1.3" {
		err = multierr.Append(err, fmt.Errorf("%s.tls.min_version must be 1.2 or 1.3", prefix))
	}
	if (tls.CertFile == "") != (tls.KeyFile == "") {
		err = multierr.Append(err, fmt.Errorf("%s.tls.cert_file and key_file must be configured together", prefix))
	}
	if tls.ReloadInterval < 0 {
		err = multierr.Append(err, fmt.Errorf("%s.tls.reload_interval must not be negative", prefix))
	}
	return err
}

func validateGNMIProfiles(prefix string, target GNMITargetConfig) error {
	profiles := []struct {
		name    string
		profile GNMIProfileConfig
	}{
		{"identity", target.Profiles.Identity},
		{"system", target.Profiles.System},
		{"interfaces", target.Profiles.Interfaces},
		{"optics", target.Profiles.Optics},
		{"catalyst_9800_wireless", target.Profiles.Catalyst9800Wireless},
		{"inventory", target.Profiles.Inventory},
		{"environment", target.Profiles.Environment},
		{"l2", target.Profiles.L2},
		{"routing", target.Profiles.Routing},
		{"mpls", target.Profiles.MPLS},
		{"overlay", target.Profiles.Overlay},
		{"qos", target.Profiles.QoS},
		{"acl", target.Profiles.ACL},
		{"topology", target.Profiles.Topology},
		{"poe", target.Profiles.PoE},
		{"time_sync", target.Profiles.TimeSync},
		{"high_availability", target.Profiles.HighAvailability},
		{"asic", target.Profiles.ASIC},
		{"telemetry_self", target.Profiles.TelemetrySelf},
	}
	platforms := gnmiCatalogPlatformsForTarget(target)
	var err error
	for _, item := range profiles {
		enabled := boolValue(item.profile.Enabled, false)
		profilePrefix := prefix + ".profiles." + item.name
		cataloged := false
		for _, platform := range platforms {
			if _, ok := builtinGNMIProfile(platform, item.name); ok {
				cataloged = true
				break
			}
		}
		if enabled && !cataloged {
			err = multierr.Append(err, fmt.Errorf("%s has no implemented paths in the generated catalog for the expected platform", profilePrefix))
		}
		if item.profile.Required && !enabled {
			err = multierr.Append(err, fmt.Errorf("%s cannot be required when disabled", profilePrefix))
		}
		if enabled && item.profile.SampleInterval <= 0 {
			err = multierr.Append(err, fmt.Errorf("%s.sample_interval must be positive", profilePrefix))
		}
		if !validGNMIStreamMode(item.profile.StreamMode) {
			err = multierr.Append(err, fmt.Errorf("%s.stream_mode must be auto, sample, on_change, or target_defined", profilePrefix))
		}
		err = multierr.Append(err, validateGNMIGroups(profilePrefix, item.name, platforms, enabled, item.profile))
	}
	if boolValue(target.Profiles.Catalyst9800Wireless.Enabled, false) && target.Platform != "" && target.Platform != gnmiPlatformIOSXE {
		err = multierr.Append(err, fmt.Errorf("%s.profiles.catalyst_9800_wireless is supported only on ios_xe", prefix))
	}
	return err
}

func gnmiCatalogPlatformsForTarget(target GNMITargetConfig) []string {
	if family := strings.ToLower(strings.TrimSpace(target.ProductFamily)); family != "" {
		for _, definition := range builtinGNMICatalogProductFamilies {
			if definition.ID == family {
				return []string{definition.Platform}
			}
		}
	}
	if target.Platform != "" {
		return []string{target.Platform}
	}
	return []string{gnmiPlatformIOSXE, gnmiPlatformIOSXR, gnmiPlatformNXOS}
}

func validateGNMIGroups(
	profilePrefix string,
	profileName string,
	platforms []string,
	profileEnabled bool,
	profile GNMIProfileConfig,
) error {
	var err error
	catalogGroups := make(map[string]gnmiCatalogGroupDefinition)
	for _, platform := range platforms {
		for _, definition := range builtinGNMIProfileGroups(platform, profileName) {
			merged := catalogGroups[definition.Name]
			merged.Name = definition.Name
			merged.HighCardinality = merged.HighCardinality || definition.HighCardinality
			merged.RequiresMaxEntities = merged.RequiresMaxEntities || definition.RequiresMaxEntities
			merged.SelectorKeys = append(merged.SelectorKeys, definition.SelectorKeys...)
			slices.Sort(merged.SelectorKeys)
			merged.SelectorKeys = slices.Compact(merged.SelectorKeys)
			catalogGroups[definition.Name] = merged
		}
	}
	catalogGroupNames := make([]string, 0, len(catalogGroups))
	for name := range catalogGroups {
		catalogGroupNames = append(catalogGroupNames, name)
	}
	sort.Strings(catalogGroupNames)
	for _, name := range catalogGroupNames {
		definition := catalogGroups[name]
		configured, exists := profile.Groups[name]
		groupEnabled := profileEnabled && (!exists || boolValue(configured.Enabled, true))
		if groupEnabled && definition.RequiresMaxEntities && (!exists || configured.MaxEntities <= 0) {
			err = multierr.Append(err, fmt.Errorf(
				"%s.groups.%s.max_entities must be positive when enabling a high-cardinality catalog group",
				profilePrefix,
				name,
			))
		}
	}
	configuredGroupNames := make([]string, 0, len(profile.Groups))
	for name := range profile.Groups {
		configuredGroupNames = append(configuredGroupNames, name)
	}
	sort.Strings(configuredGroupNames)
	for _, name := range configuredGroupNames {
		group := profile.Groups[name]
		groupPrefix := profilePrefix + ".groups." + name
		if !normalizedGNMIGroupNamePattern.MatchString(name) {
			err = multierr.Append(err, fmt.Errorf("%s group name must use lowercase letters, numbers, and underscores", groupPrefix))
		}
		enabled := profileEnabled && boolValue(group.Enabled, true)
		if group.Required && !enabled {
			err = multierr.Append(err, fmt.Errorf("%s cannot be required when disabled", groupPrefix))
		}
		if enabled && group.SampleInterval <= 0 {
			err = multierr.Append(err, fmt.Errorf("%s.sample_interval must be positive", groupPrefix))
		}
		if !validGNMIStreamMode(group.StreamMode) {
			err = multierr.Append(err, fmt.Errorf("%s.stream_mode must be auto, sample, on_change, or target_defined", groupPrefix))
		}
		if group.SyncTimeout <= 0 || group.SyncTimeout > gnmiMaximumSyncTimeout {
			err = multierr.Append(err, fmt.Errorf("%s.sync_timeout must be positive and not exceed %s", groupPrefix, gnmiMaximumSyncTimeout))
		}
		if group.MaxEntities < 0 {
			err = multierr.Append(err, fmt.Errorf("%s.max_entities must not be negative", groupPrefix))
		}
		if enabled && len(group.Selectors) > 0 && group.MaxEntities <= 0 {
			err = multierr.Append(err, fmt.Errorf("%s.max_entities must be positive when selectors are configured", groupPrefix))
		}
		catalogGroup, cataloged := catalogGroups[name]
		selectorKeys := make(map[string]struct{}, len(catalogGroup.SelectorKeys))
		for _, selector := range catalogGroup.SelectorKeys {
			selectorKeys[selector] = struct{}{}
		}
		if !cataloged {
			err = multierr.Append(err, fmt.Errorf("%s is not declared by the generated catalog for profile %q and the expected platform", groupPrefix, profileName))
		}
		for selector, values := range group.Selectors {
			selectorPrefix := groupPrefix + ".selectors." + selector
			if !normalizedAttributeNamePattern.MatchString(selector) {
				err = multierr.Append(err, fmt.Errorf("%s key must be a normalized catalog selector", selectorPrefix))
			}
			if _, ok := selectorKeys[selector]; cataloged && !ok {
				err = multierr.Append(err, fmt.Errorf("%s is not declared by the generated catalog group", selectorPrefix))
			}
			if len(values) == 0 {
				err = multierr.Append(err, fmt.Errorf("%s must contain at least one exact value", selectorPrefix))
				continue
			}
			seen := make(map[string]struct{}, len(values))
			for index, value := range values {
				if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value {
					err = multierr.Append(err, fmt.Errorf("%s[%d] must be a non-empty exact value without surrounding whitespace", selectorPrefix, index))
					continue
				}
				if strings.ContainsAny(value, "*?") {
					err = multierr.Append(err, fmt.Errorf("%s[%d] must be an exact value, not a wildcard", selectorPrefix, index))
				}
				if _, duplicate := seen[value]; duplicate {
					err = multierr.Append(err, fmt.Errorf("%s[%d] duplicates another selector value", selectorPrefix, index))
				}
				seen[value] = struct{}{}
			}
		}
	}
	return err
}

func validGNMIStreamMode(value string) bool {
	switch value {
	case gnmiStreamModeAuto, gnmiStreamModeSample, gnmiStreamModeOnChange, gnmiStreamModeTargetDefined:
		return true
	default:
		return false
	}
}

func validateGNMIEncodingPreference(prefix string, values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("%s must include at least one encoding", prefix)
	}
	var err error
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if value != gnmiEncodingProto && value != gnmiEncodingJSONIETF && value != gnmiEncodingJSON {
			err = multierr.Append(err, fmt.Errorf("%s[%d] must be proto, json_ietf, or json", prefix, index))
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			err = multierr.Append(err, fmt.Errorf("%s[%d] duplicates encoding %q", prefix, index, value))
		}
		seen[value] = struct{}{}
	}
	return err
}

func validateGNMICustomSubscriptions(prefix string, target GNMITargetConfig) error {
	var err error
	names := map[string]struct{}{}
	outputIdentities := map[string]string{}
	for i, subscription := range target.CustomSubscriptions {
		itemPrefix := fmt.Sprintf("%s.custom_subscriptions[%d]", prefix, i)
		name := strings.ToLower(strings.TrimSpace(subscription.Name))
		if name == "" {
			err = multierr.Append(err, fmt.Errorf("%s.name cannot be empty", itemPrefix))
		} else if isBuiltinGNMIProfileName(name) {
			err = multierr.Append(err, fmt.Errorf("%s.name %q is reserved for a built-in profile", itemPrefix, subscription.Name))
		} else if _, duplicate := names[name]; duplicate {
			err = multierr.Append(err, fmt.Errorf("%s.name must be unique", itemPrefix))
		} else {
			names[name] = struct{}{}
		}
		if strings.TrimSpace(subscription.Origin) == "" {
			err = multierr.Append(err, fmt.Errorf("%s.origin cannot be empty", itemPrefix))
		}
		if subscription.Mode != gnmiModeStream && subscription.Mode != gnmiModeOnce && subscription.Mode != gnmiModePoll {
			err = multierr.Append(err, fmt.Errorf("%s.mode must be stream, once, or poll", itemPrefix))
		}
		if subscription.Encoding != gnmiEncodingAuto && subscription.Encoding != gnmiEncodingProto && subscription.Encoding != gnmiEncodingJSONIETF && subscription.Encoding != gnmiEncodingJSON {
			err = multierr.Append(err, fmt.Errorf("%s.encoding must be auto, proto, json_ietf, or json", itemPrefix))
		}
		if target.Platform == gnmiPlatformIOSXE && subscription.Mode != gnmiModeStream {
			err = multierr.Append(err, fmt.Errorf("%s.mode %s is not supported on ios_xe", itemPrefix, subscription.Mode))
		}
		if subscription.SampleInterval <= 0 {
			err = multierr.Append(err, fmt.Errorf("%s.sample_interval must be positive", itemPrefix))
		}
		if subscription.Mode == gnmiModePoll && subscription.PollInterval <= 0 {
			err = multierr.Append(err, fmt.Errorf("%s.poll_interval must be positive for poll mode", itemPrefix))
		}
		if len(subscription.Mappings) == 0 {
			err = multierr.Append(err, fmt.Errorf("%s.mappings cannot be empty", itemPrefix))
		}
		paths := map[string]struct{}{}
		for j, mapping := range subscription.Mappings {
			mappingPrefix := fmt.Sprintf("%s.mappings[%d]", itemPrefix, j)
			path := strings.Trim(strings.TrimSpace(mapping.Path), "/")
			mappingValid := true
			if path == "" || gnmiPathIncludesOrigin(path, subscription.Origin) {
				err = multierr.Append(err, fmt.Errorf("%s.path must be a non-empty origin-free path", mappingPrefix))
				mappingValid = false
			}
			if _, duplicate := paths[path]; duplicate {
				err = multierr.Append(err, fmt.Errorf("%s.path duplicates another mapping", mappingPrefix))
			}
			paths[path] = struct{}{}
			if !normalizedMetricNamePattern.MatchString(mapping.MetricName) || strings.HasSuffix(mapping.MetricName, "_info") {
				err = multierr.Append(err, fmt.Errorf("%s.metric_name must be a normalized non-info metric name", mappingPrefix))
				mappingValid = false
			} else if _, reserved := builtinGNMIMetricMetadata[mapping.MetricName]; reserved {
				err = multierr.Append(err, fmt.Errorf("%s.metric_name %q is reserved for a built-in metric", mappingPrefix, mapping.MetricName))
				mappingValid = false
			}
			if strings.TrimSpace(mapping.Description) == "" || !validGNMIUCUMUnit(mapping.Unit) {
				err = multierr.Append(err, fmt.Errorf("%s.description and UCUM unit are required", mappingPrefix))
				mappingValid = false
			}
			if mapping.Scale == nil || *mapping.Scale == 0 || math.IsNaN(*mapping.Scale) || math.IsInf(*mapping.Scale, 0) {
				err = multierr.Append(err, fmt.Errorf("%s.scale must be explicitly set and non-zero", mappingPrefix))
				mappingValid = false
			}
			if mapping.GaugeType != "int" && mapping.GaugeType != "double" {
				err = multierr.Append(err, fmt.Errorf("%s.gauge_type must be int or double", mappingPrefix))
				mappingValid = false
			}
			if mapping.PathKeys == nil {
				err = multierr.Append(err, fmt.Errorf("%s.path_keys must be explicitly configured", mappingPrefix))
				mappingValid = false
			}
			pathElements := map[string]struct{}{}
			pathElementCounts := map[string]int{}
			configuredPathKeys := map[string]struct{}{}
			if path != "" && !gnmiPathIncludesOrigin(path, subscription.Origin) {
				parsed, parseErr := internalgnmi.ParsePath("", subscription.Origin, path)
				if parseErr != nil {
					err = multierr.Append(err, fmt.Errorf("%s.path is invalid: %w", mappingPrefix, parseErr))
					mappingValid = false
				} else if series, splitErr := parsed.SplitLeaf(); splitErr != nil {
					err = multierr.Append(err, fmt.Errorf("%s.path is invalid: %w", mappingPrefix, splitErr))
					mappingValid = false
				} else {
					for _, element := range series.Elements {
						pathElements[element.Name] = struct{}{}
						pathElementCounts[element.Name]++
						for key := range element.Keys {
							configuredPathKeys[element.Name+"."+key] = struct{}{}
						}
					}
				}
			}
			mappedAttributes := map[string]struct{}{}
			for source, attribute := range mapping.PathKeys {
				element, key, selectorOK := strings.Cut(source, ".")
				if !selectorOK || element == "" || key == "" || strings.Contains(key, ".") || !normalizedAttributeNamePattern.MatchString(attribute) {
					err = multierr.Append(err, fmt.Errorf("%s.path_keys must map element.key selectors to non-empty attributes", mappingPrefix))
					mappingValid = false
					continue
				}
				if _, exists := pathElements[element]; !exists {
					err = multierr.Append(err, fmt.Errorf("%s.path_keys selector %q references an element not present in path", mappingPrefix, source))
					mappingValid = false
				} else if pathElementCounts[element] > 1 {
					err = multierr.Append(err, fmt.Errorf("%s.path_keys selector %q is ambiguous because element %q occurs more than once in path", mappingPrefix, source, element))
					mappingValid = false
				}
				if _, duplicate := mappedAttributes[attribute]; duplicate {
					err = multierr.Append(err, fmt.Errorf("%s.path_keys maps more than one selector to attribute %q", mappingPrefix, attribute))
					mappingValid = false
				}
				mappedAttributes[attribute] = struct{}{}
				delete(configuredPathKeys, source)
			}
			for selector := range configuredPathKeys {
				err = multierr.Append(err, fmt.Errorf("%s.path_keys must map configured path selector %q", mappingPrefix, selector))
				mappingValid = false
			}
			if mappingValid {
				attributeNames := make([]string, 0, len(mapping.PathKeys))
				for _, attribute := range mapping.PathKeys {
					attributeNames = append(attributeNames, attribute)
				}
				sort.Strings(attributeNames)
				identity := mapping.MetricName + "\x00" + strings.Join(attributeNames, "\x00")
				source := subscription.Origin + "\x00" + path
				if previous, duplicate := outputIdentities[identity]; duplicate {
					err = multierr.Append(err, fmt.Errorf("%s can collide with source %q because both produce metric %q with the same output attributes", mappingPrefix, previous, mapping.MetricName))
					mappingValid = false
				} else {
					outputIdentities[identity] = source
				}
			}
			if mappingValid {
				if _, _, conversionErr := convertCustomGNMIMapping(subscription.Origin, mapping); conversionErr != nil {
					err = multierr.Append(err, fmt.Errorf("%s is invalid: %w", mappingPrefix, conversionErr))
				}
			}
		}
	}
	return err
}

func isBuiltinGNMIProfileName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case builtinGNMIProfileIdentity, builtinGNMIProfileSystem, builtinGNMIProfileInterfaces, builtinGNMIProfileOptics, builtinGNMIProfileCatalyst9800Wireless,
		"inventory", "environment", "l2", "routing", "mpls", "overlay", "qos", "acl", "topology", "poe", "time_sync", "high_availability", "asic", "telemetry_self":
		return true
	default:
		return false
	}
}

func gnmiPathIncludesOrigin(path, origin string) bool {
	if origin == "" {
		return false
	}
	path = strings.TrimLeft(path, "/")
	first, _, _ := strings.Cut(path, "/")
	// Only the element name can carry an RFC7951 module/origin prefix. A
	// colon inside a list-key value (for example an IPv6 address) is data.
	name, _, _ := strings.Cut(first, "[")
	return strings.Contains(name, ":")
}

type gnmiConfigMetricContract struct {
	description string
	unit        string
	gaugeType   internalgnmi.GaugeValueType
	metricType  internalgnmi.MetricType
	monotonic   bool
}

func validateGNMIMetricContracts(rawTargets []GNMITargetConfig) error {
	contracts := map[string]gnmiConfigMetricContract{}
	for _, platform := range []string{gnmiPlatformIOSXE, gnmiPlatformIOSXR, gnmiPlatformNXOS} {
		for _, profile := range builtinGNMIProfiles(platform) {
			mappings := append([]builtinGNMIMapping(nil), profile.SyntheticMappings...)
			for pathIndex := range profile.Paths {
				path := profile.Paths[pathIndex]
				mappings = append(mappings, path.Mappings...)
			}
			for i := range mappings {
				mapping := mappings[i].Mapping
				contract := gnmiConfigMetricContract{
					description: mapping.Metric.Description,
					unit:        mapping.Metric.Unit,
					gaugeType:   mapping.GaugeType,
					metricType:  mapping.MetricType,
					monotonic:   mapping.Monotonic,
				}
				if existing, ok := contracts[mapping.Metric.Name]; ok && existing != contract {
					return fmt.Errorf("built-in gNMI metric %q has conflicting contracts", mapping.Metric.Name)
				}
				contracts[mapping.Metric.Name] = contract
			}
		}
	}

	var err error
	for targetIndex := range rawTargets {
		target := rawTargets[targetIndex].withDefaults()
		for subscriptionIndex, subscription := range target.CustomSubscriptions {
			for mappingIndex, mapping := range subscription.Mappings {
				if !normalizedMetricNamePattern.MatchString(mapping.MetricName) || strings.HasSuffix(mapping.MetricName, "_info") || strings.TrimSpace(mapping.Description) == "" || !validGNMIUCUMUnit(mapping.Unit) {
					continue
				}
				gaugeType := internalgnmi.GaugeValueType(mapping.GaugeType)
				if gaugeType != internalgnmi.GaugeInt && gaugeType != internalgnmi.GaugeDouble {
					continue
				}
				contract := gnmiConfigMetricContract{
					description: mapping.Description,
					unit:        mapping.Unit,
					gaugeType:   gaugeType,
					metricType:  internalgnmi.MetricGauge,
				}
				if existing, ok := contracts[mapping.MetricName]; ok && existing != contract {
					err = multierr.Append(err, fmt.Errorf(
						"gnmi.targets[%d].custom_subscriptions[%d].mappings[%d] conflicts with the established contract for metric %q",
						targetIndex, subscriptionIndex, mappingIndex, mapping.MetricName,
					))
					continue
				}
				contracts[mapping.MetricName] = contract
			}
		}
	}
	return err
}

func validGNMIUCUMUnit(unit string) bool {
	if unit == "" || strings.TrimSpace(unit) != unit || strings.ContainsAny(unit, "()") {
		return false
	}
	termStart := 0
	for index, char := range unit {
		if char != '.' && char != '/' && char != '*' {
			continue
		}
		if index == termStart || !validGNMIUCUMTerm(unit[termStart:index]) {
			return false
		}
		termStart = index + 1
	}
	return termStart < len(unit) && validGNMIUCUMTerm(unit[termStart:])
}

func validGNMIUCUMTerm(term string) bool {
	if _, ok := gnmiUCUMSpecialUnits[term]; ok {
		return true
	}
	if gnmiUCUMAnnotationPattern.MatchString(term) {
		return true
	}
	if exponent := strings.LastIndexByte(term, '^'); exponent >= 0 {
		if exponent == 0 || exponent == len(term)-1 {
			return false
		}
		if _, err := strconv.Atoi(term[exponent+1:]); err != nil {
			return false
		}
		term = term[:exponent]
	}
	if _, ok := gnmiUCUMAtoms[term]; ok {
		return true
	}
	for _, prefix := range gnmiUCUMPrefixes {
		if !strings.HasPrefix(term, prefix) || len(term) == len(prefix) {
			continue
		}
		if _, ok := gnmiUCUMPrefixableAtoms[term[len(prefix):]]; ok {
			return true
		}
	}
	return false
}

func estimateGNMIStreams(target GNMITargetConfig) int {
	planningTarget := target
	if planningTarget.Platform == "" && planningTarget.ProductFamily != "" {
		if family, ok := gnmiCatalogProductFamily(planningTarget.ProductFamily); ok {
			planningTarget.Platform = family.Platform
		}
	}
	if planningTarget.Platform != "" {
		// Count the actual compatibility plan, including group overrides. The
		// caller compares the result with the configured limit; use a planning
		// ceiling here so buildSharedGNMIStreams can return the complete plan.
		planningTarget.MaxStreams = math.MaxInt
		if planned, err := buildSharedGNMIStreams(planningTarget); err == nil {
			return len(planned)
		}
	}

	streams := 0
	if boolValue(target.Profiles.Identity.Enabled, false) && target.Platform != gnmiPlatformIOSXR {
		streams++
	}
	if boolValue(target.Profiles.System.Enabled, false) {
		if target.Platform == gnmiPlatformIOSXR {
			streams += 3
		} else {
			streams++
		}
	}
	if boolValue(target.Profiles.Interfaces.Enabled, false) {
		streams++
	}
	if boolValue(target.Profiles.Optics.Enabled, false) {
		if target.Platform == gnmiPlatformIOSXR {
			streams += 2 // controller-optics and controller-otu module origins.
		} else {
			streams++
		}
	}
	if boolValue(target.Profiles.Catalyst9800Wireless.Enabled, false) {
		streams++
	}
	for _, profile := range []GNMIProfileConfig{
		target.Profiles.Inventory,
		target.Profiles.Environment,
		target.Profiles.L2,
		target.Profiles.Routing,
		target.Profiles.MPLS,
		target.Profiles.Overlay,
		target.Profiles.QoS,
		target.Profiles.ACL,
		target.Profiles.Topology,
		target.Profiles.PoE,
		target.Profiles.TimeSync,
		target.Profiles.HighAvailability,
		target.Profiles.ASIC,
		target.Profiles.TelemetrySelf,
	} {
		if boolValue(profile.Enabled, false) {
			streams++
		}
	}
	streams += len(target.CustomSubscriptions)
	return streams
}

func (cfg *Config) legacyGNMIEndpoints() map[string]string {
	legacy := map[string]string{}
	for i := range cfg.IOSXR.DialIn.Targets {
		legacy[strings.ToLower(strings.TrimSpace(cfg.IOSXR.DialIn.Targets[i].Endpoint))] = "ios_xr"
	}
	for i := range cfg.Catalyst9800.DialIn.Targets {
		legacy[strings.ToLower(strings.TrimSpace(cfg.Catalyst9800.DialIn.Targets[i].Endpoint))] = "catalyst_9800"
	}
	return legacy
}

func sortedGNMIPathKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
