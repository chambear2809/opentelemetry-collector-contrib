// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
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

	// Custom plans are configuration-owned rather than device-owned, but they
	// still allocate request protobufs and mapping registries outside the state
	// cache. Bound both each stream and the complete receiver configuration so a
	// single syntactically valid stream cannot bypass the runtime memory budgets.
	gnmiMaximumCustomSubscriptionsPerTarget  = 8
	gnmiMaximumCustomPathsPerSubscription    = 256
	gnmiMaximumCustomMappingsPerSubscription = 1_024
	gnmiMaximumCustomModelsPerSubscription   = 32
	gnmiMaximumCustomMappingAttributes       = 64
	gnmiMaximumEncodingPreferences           = 3
	gnmiMaximumProfilePathOverrides          = 64
	gnmiMaximumCustomPaths                   = 4_096
	gnmiMaximumCustomMappings                = 16_384
	gnmiMaximumProfilePathOverridesTotal     = 4_096
	gnmiMaximumCustomConfigurationBytes      = 64 * 1024 * 1024
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
	"1": {}, "%": {}, "dB{mW}": {}, "B[SPL]": {}, "B[V]": {}, "B[mV]": {}, "B[uV]": {}, "B[W]": {}, "B[kW]": {},
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

// GNMITLSConfig exposes the TLS settings used by the shared client. Plaintext
// transport is always rejected. Certificate verification can be disabled only
// through the explicit lab-oriented InsecureSkipVerify option.
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

// GNMIPathOptionsConfig controls how one path behaves within a STREAM
// SubscriptionList. Pointer fields preserve omission, including the gNMI
// SAMPLE convention where an explicit zero requests the fastest supported
// interval.
type GNMIPathOptionsConfig struct {
	_ struct{} `mapstructure:"-"`

	StreamMode        string         `mapstructure:"stream_mode"`
	SampleInterval    *time.Duration `mapstructure:"sample_interval"`
	HeartbeatInterval *time.Duration `mapstructure:"heartbeat_interval"`
	SuppressRedundant *bool          `mapstructure:"suppress_redundant"`
}

// GNMISubscriptionPathConfig is one explicit custom subscription selector.
// The selector may be an ancestor of one or more mapped scalar leaves.
type GNMISubscriptionPathConfig struct {
	_ struct{} `mapstructure:"-"`

	Path                  string `mapstructure:"path"`
	GNMIPathOptionsConfig `mapstructure:",squash"`
}

// GNMIExtensionsConfig contains the bounded, read-only gNMI extensions
// supported by this receiver.
type GNMIExtensionsConfig struct {
	_ struct{} `mapstructure:"-"`

	Depth *uint32 `mapstructure:"depth"`
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
// the path parser. PathTarget is decoder-only and always rejected because every
// built-in direct-device product contract forbids proxy target prefixes.
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

	Name string `mapstructure:"name"`
	// Endpoint is a direct-device TCP endpoint in strict host:port form.
	Endpoint string `mapstructure:"endpoint"`
	// Product is one of the canonical product contracts: catalyst_9300,
	// catalyst_9500, catalyst_9800, asr_9000, ncs_5500, nexus_9000, or
	// nexus_3500.
	Product string `mapstructure:"product"`
	// SoftwareVersion is the expected public release label. OS-specific parsers
	// canonicalize numeric components before comparing it with the release
	// observed during product identity preflight.
	SoftwareVersion string `mapstructure:"software_version"`
	// AllowUnqualified explicitly acknowledges that the selected product
	// contract requires an opt-in because retained physical-device
	// qualification is incomplete. It is rejected for contracts that do not
	// require this acknowledgement.
	AllowUnqualified bool `mapstructure:"allow_unqualified"`
	// Platform remains decoder-only so configurations from the OS-family
	// preview receive an actionable migration error instead of an unknown-key
	// diagnostic. It is never used to select profiles or runtime behavior.
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
	EncodingPreference  []string                       `mapstructure:"encoding_preference"`
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

// canonicalGNMIDialInEndpoint validates the deliberately narrow direct-device
// address contract and returns a comparison key. The original endpoint remains
// untouched for dialing and TLS/SNI behavior.
func canonicalGNMIDialInEndpoint(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return "", errors.New("must be host:port without surrounding whitespace")
	}
	host, rawPort, err := net.SplitHostPort(raw)
	if err != nil {
		return "", fmt.Errorf("must be host:port: %w", err)
	}
	if host == "" || strings.TrimSpace(host) != host || strings.IndexFunc(host, func(character rune) bool {
		return unicode.IsSpace(character) || unicode.IsControl(character)
	}) >= 0 {
		return "", errors.New("must contain a non-empty host without whitespace or control characters")
	}
	for _, character := range rawPort {
		if character < '0' || character > '9' {
			return "", errors.New("must contain a numeric port between 1 and 65535")
		}
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return "", errors.New("must contain a numeric port between 1 and 65535")
	}

	var canonicalHost string
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		if address.Zone() != "" {
			return "", errors.New("must not use a scoped IPv6 zone")
		}
		address = address.Unmap()
		if address.IsUnspecified() {
			return "", errors.New("must not use an unspecified IP address")
		}
		canonicalHost = address.String()
	} else {
		canonicalHost, err = canonicalGNMIHostname(host)
		if err != nil {
			return "", err
		}
	}
	return net.JoinHostPort(canonicalHost, strconv.FormatUint(port, 10)), nil
}

func canonicalGNMIHostname(host string) (string, error) {
	if strings.Contains(host, ":") {
		return "", errors.New("must contain a valid IP address or DNS hostname")
	}
	canonical := strings.ToLower(strings.TrimSuffix(host, "."))
	if legacyNumericIPv4Hostname(canonical) {
		return "", errors.New("must use canonical dotted-decimal syntax for an IPv4 address")
	}
	if canonical == "" || len(canonical) > 253 {
		return "", errors.New("must contain a valid DNS hostname of at most 253 bytes")
	}
	for label := range strings.SplitSeq(canonical, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("must contain a valid DNS hostname")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') && character != '-' {
				return "", errors.New("must contain a valid DNS hostname")
			}
		}
	}
	return canonical, nil
}

// legacyNumericIPv4Hostname detects resolver-dependent IPv4 spellings such as
// 127.1, 2130706433, 0177.0.0.1, and 0x7f000001. Treating these as DNS names
// would let endpoint ownership validation disagree with the OS resolver.
func legacyNumericIPv4Hostname(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		digits := part
		base := 10
		if len(part) > 2 && strings.HasPrefix(part, "0x") {
			digits = part[2:]
			base = 16
		}
		if digits == "" {
			return false
		}
		for _, character := range digits {
			if (character < '0' || character > '9') &&
				(base != 16 || character < 'a' || character > 'f') {
				return false
			}
		}
	}
	return true
}

type gnmiConfigurationShapeLimits struct {
	customSubscriptionsPerTarget  int
	customPathsPerSubscription    int
	customMappingsPerSubscription int
	customModelsPerSubscription   int
	customMappingAttributes       int
	encodingPreferences           int
	profilePathOverrides          int
	customPaths                   int
	customMappings                int
	profilePathOverridesTotal     int
	customConfigurationBytes      uint64
}

func defaultGNMIConfigurationShapeLimits() gnmiConfigurationShapeLimits {
	return gnmiConfigurationShapeLimits{
		customSubscriptionsPerTarget:  gnmiMaximumCustomSubscriptionsPerTarget,
		customPathsPerSubscription:    gnmiMaximumCustomPathsPerSubscription,
		customMappingsPerSubscription: gnmiMaximumCustomMappingsPerSubscription,
		customModelsPerSubscription:   gnmiMaximumCustomModelsPerSubscription,
		customMappingAttributes:       gnmiMaximumCustomMappingAttributes,
		encodingPreferences:           gnmiMaximumEncodingPreferences,
		profilePathOverrides:          gnmiMaximumProfilePathOverrides,
		customPaths:                   gnmiMaximumCustomPaths,
		customMappings:                gnmiMaximumCustomMappings,
		profilePathOverridesTotal:     gnmiMaximumProfilePathOverridesTotal,
		customConfigurationBytes:      gnmiMaximumCustomConfigurationBytes,
	}
}

func validateGNMIConfigurationShape(targets []GNMITargetConfig) error {
	return validateGNMIConfigurationShapeWithLimits(targets, defaultGNMIConfigurationShapeLimits())
}

func validateGNMIConfigurationShapeWithLimits(targets []GNMITargetConfig, limits gnmiConfigurationShapeLimits) error {
	if limits.customSubscriptionsPerTarget <= 0 || limits.customPathsPerSubscription <= 0 ||
		limits.customMappingsPerSubscription <= 0 || limits.customModelsPerSubscription <= 0 || limits.customMappingAttributes <= 0 ||
		limits.encodingPreferences <= 0 || limits.profilePathOverrides <= 0 || limits.customPaths <= 0 ||
		limits.customMappings <= 0 || limits.profilePathOverridesTotal <= 0 || limits.customConfigurationBytes == 0 {
		return errors.New("internal gNMI configuration shape limits must be positive")
	}

	customPaths := uint64(0)
	customMappings := uint64(0)
	profilePathOverrides := uint64(0)
	for targetIndex := range targets {
		target := &targets[targetIndex]
		targetPrefix := fmt.Sprintf("gnmi.targets[%d]", targetIndex)
		if len(target.EncodingPreference) > limits.encodingPreferences {
			return fmt.Errorf("%s.encoding_preference must contain at most %d entries", targetPrefix, limits.encodingPreferences)
		}
		if len(target.CustomSubscriptions) > limits.customSubscriptionsPerTarget {
			return fmt.Errorf("%s.custom_subscriptions must contain at most %d entries", targetPrefix, limits.customSubscriptionsPerTarget)
		}

		profiles := []struct {
			name   string
			config *GNMIProfileConfig
		}{
			{name: builtinGNMIProfileIdentity, config: &target.Profiles.Identity},
			{name: builtinGNMIProfileSystem, config: &target.Profiles.System},
			{name: builtinGNMIProfileInterfaces, config: &target.Profiles.Interfaces},
			{name: builtinGNMIProfileOptics, config: &target.Profiles.Optics},
			{name: builtinGNMIProfileCatalyst9800Wireless, config: &target.Profiles.Catalyst9800Wireless},
		}
		for _, profile := range profiles {
			profilePrefix := targetPrefix + ".profiles." + profile.name
			if len(profile.config.EncodingPreference) > limits.encodingPreferences {
				return fmt.Errorf("%s.encoding_preference must contain at most %d entries", profilePrefix, limits.encodingPreferences)
			}
			if len(profile.config.PathOverrides) > limits.profilePathOverrides {
				return fmt.Errorf("%s.path_overrides must contain at most %d entries", profilePrefix, limits.profilePathOverrides)
			}
			profilePathOverrides += uint64(len(profile.config.PathOverrides))
			if profilePathOverrides > uint64(limits.profilePathOverridesTotal) {
				return fmt.Errorf("gnmi profile path overrides must contain at most %d entries receiver-wide", limits.profilePathOverridesTotal)
			}
		}

		for subscriptionIndex := range target.CustomSubscriptions {
			subscription := &target.CustomSubscriptions[subscriptionIndex]
			subscriptionPrefix := fmt.Sprintf("%s.custom_subscriptions[%d]", targetPrefix, subscriptionIndex)
			if len(subscription.EncodingPreference) > limits.encodingPreferences {
				return fmt.Errorf("%s.encoding_preference must contain at most %d entries", subscriptionPrefix, limits.encodingPreferences)
			}
			if len(subscription.Paths) > limits.customPathsPerSubscription {
				return fmt.Errorf("%s.paths must contain at most %d entries", subscriptionPrefix, limits.customPathsPerSubscription)
			}
			if len(subscription.Mappings) > limits.customMappingsPerSubscription {
				return fmt.Errorf("%s.mappings must contain at most %d entries", subscriptionPrefix, limits.customMappingsPerSubscription)
			}
			if len(subscription.Models) > limits.customModelsPerSubscription {
				return fmt.Errorf("%s.models must contain at most %d entries", subscriptionPrefix, limits.customModelsPerSubscription)
			}
			effectivePaths := len(subscription.Paths)
			if effectivePaths == 0 {
				effectivePaths = len(subscription.Mappings)
			}
			if effectivePaths > limits.customPathsPerSubscription {
				return fmt.Errorf("%s derives %d request paths; at most %d are allowed", subscriptionPrefix, effectivePaths, limits.customPathsPerSubscription)
			}
			customPaths += uint64(effectivePaths)
			if customPaths > uint64(limits.customPaths) {
				return fmt.Errorf("gnmi custom subscriptions must contain at most %d effective request paths receiver-wide", limits.customPaths)
			}
			customMappings += uint64(len(subscription.Mappings))
			if customMappings > uint64(limits.customMappings) {
				return fmt.Errorf("gnmi custom subscriptions must contain at most %d mappings receiver-wide", limits.customMappings)
			}
			for mappingIndex := range subscription.Mappings {
				if len(subscription.Mappings[mappingIndex].PathKeys) > limits.customMappingAttributes {
					return fmt.Errorf("%s.mappings[%d].path_keys must contain at most %d entries", subscriptionPrefix, mappingIndex, limits.customMappingAttributes)
				}
			}
		}
	}

	configuredBytes := uint64(0)
	addString := func(field, value string) error {
		valueBytes := uint64(len(value))
		if valueBytes > limits.customConfigurationBytes-configuredBytes {
			return fmt.Errorf("gnmi custom subscription and profile plan strings exceed the receiver-wide limit of %d bytes at %s", limits.customConfigurationBytes, field)
		}
		configuredBytes += valueBytes
		return nil
	}
	addStrings := func(field string, values []string) error {
		for index, value := range values {
			if err := addString(fmt.Sprintf("%s[%d]", field, index), value); err != nil {
				return err
			}
		}
		return nil
	}
	for targetIndex := range targets {
		target := &targets[targetIndex]
		targetPrefix := fmt.Sprintf("gnmi.targets[%d]", targetIndex)
		if err := addStrings(targetPrefix+".encoding_preference", target.EncodingPreference); err != nil {
			return err
		}
		profiles := []struct {
			name   string
			config *GNMIProfileConfig
		}{
			{name: builtinGNMIProfileIdentity, config: &target.Profiles.Identity},
			{name: builtinGNMIProfileSystem, config: &target.Profiles.System},
			{name: builtinGNMIProfileInterfaces, config: &target.Profiles.Interfaces},
			{name: builtinGNMIProfileOptics, config: &target.Profiles.Optics},
			{name: builtinGNMIProfileCatalyst9800Wireless, config: &target.Profiles.Catalyst9800Wireless},
		}
		for _, profile := range profiles {
			profilePrefix := targetPrefix + ".profiles." + profile.name
			if err := addStrings(profilePrefix+".encoding_preference", profile.config.EncodingPreference); err != nil {
				return err
			}
			paths := make([]string, 0, len(profile.config.PathOverrides))
			for path := range profile.config.PathOverrides {
				paths = append(paths, path)
			}
			sort.Strings(paths)
			for _, path := range paths {
				options := profile.config.PathOverrides[path]
				if err := addString(profilePrefix+".path_overrides", path); err != nil {
					return err
				}
				if err := addString(profilePrefix+".path_overrides.stream_mode", options.StreamMode); err != nil {
					return err
				}
			}
		}
		for subscriptionIndex := range target.CustomSubscriptions {
			subscription := &target.CustomSubscriptions[subscriptionIndex]
			subscriptionPrefix := fmt.Sprintf("%s.custom_subscriptions[%d]", targetPrefix, subscriptionIndex)
			for _, field := range []struct {
				name  string
				value string
			}{
				{name: "name", value: subscription.Name},
				{name: "path_target", value: subscription.PathTarget},
				{name: "origin", value: subscription.Origin},
				{name: "mode", value: subscription.Mode},
			} {
				if err := addString(subscriptionPrefix+"."+field.name, field.value); err != nil {
					return err
				}
			}
			if err := addStrings(subscriptionPrefix+".encoding_preference", subscription.EncodingPreference); err != nil {
				return err
			}
			if err := addStrings(subscriptionPrefix+".models", subscription.Models); err != nil {
				return err
			}
			for pathIndex := range subscription.Paths {
				pathPrefix := fmt.Sprintf("%s.paths[%d]", subscriptionPrefix, pathIndex)
				if err := addString(pathPrefix+".path", subscription.Paths[pathIndex].Path); err != nil {
					return err
				}
				if err := addString(pathPrefix+".stream_mode", subscription.Paths[pathIndex].StreamMode); err != nil {
					return err
				}
			}
			for mappingIndex := range subscription.Mappings {
				mapping := &subscription.Mappings[mappingIndex]
				mappingPrefix := fmt.Sprintf("%s.mappings[%d]", subscriptionPrefix, mappingIndex)
				for _, field := range []struct {
					name  string
					value string
				}{
					{name: "path", value: mapping.Path},
					{name: "metric_name", value: mapping.MetricName},
					{name: "description", value: mapping.Description},
					{name: "unit", value: mapping.Unit},
					{name: "gauge_type", value: mapping.GaugeType},
				} {
					if err := addString(mappingPrefix+"."+field.name, field.value); err != nil {
						return err
					}
				}
				sources := make([]string, 0, len(mapping.PathKeys))
				for source := range mapping.PathKeys {
					sources = append(sources, source)
				}
				sort.Strings(sources)
				for _, source := range sources {
					attribute := mapping.PathKeys[source]
					if err := addString(mappingPrefix+".path_keys.source", source); err != nil {
						return err
					}
					if err := addString(mappingPrefix+".path_keys.attribute", attribute); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func (cfg *Config) validateGNMIDialInEndpointOwnership() error {
	type endpointDefinition struct {
		prefix   string
		endpoint string
		legacy   string
	}
	definitions := make([]endpointDefinition, 0,
		len(cfg.GNMI.Targets)+len(cfg.IOSXR.DialIn.Targets)+len(cfg.Catalyst9800.DialIn.Targets))
	for index := range cfg.GNMI.Targets {
		definitions = append(definitions, endpointDefinition{
			prefix:   fmt.Sprintf("gnmi.targets[%d]", index),
			endpoint: cfg.GNMI.Targets[index].Endpoint,
		})
	}
	for index := range cfg.IOSXR.DialIn.Targets {
		definitions = append(definitions, endpointDefinition{
			prefix:   fmt.Sprintf("ios_xr.dial_in.targets[%d]", index),
			endpoint: cfg.IOSXR.DialIn.Targets[index].Endpoint,
			legacy:   "ios_xr",
		})
	}
	for index := range cfg.Catalyst9800.DialIn.Targets {
		definitions = append(definitions, endpointDefinition{
			prefix:   fmt.Sprintf("catalyst_9800.dial_in.targets[%d]", index),
			endpoint: cfg.Catalyst9800.DialIn.Targets[index].Endpoint,
			legacy:   "catalyst_9800",
		})
	}

	owners := make(map[string]endpointDefinition, len(definitions))
	var validationErr error
	for _, definition := range definitions {
		key, err := canonicalGNMIDialInEndpoint(definition.endpoint)
		if err != nil {
			// The owning target validator reports the address diagnostic. Skip it
			// here so endpoint ownership does not duplicate the same error.
			continue
		}
		if previous, duplicate := owners[key]; duplicate {
			message := fmt.Sprintf(
				"%s.endpoint duplicates %s.endpoint after canonical address normalization",
				definition.prefix,
				previous.prefix,
			)
			legacy := definition.legacy
			if legacy == "" {
				legacy = previous.legacy
			}
			if legacy != "" {
				message += fmt.Sprintf("; legacy %s dial_in cannot share endpoint ownership", legacy)
			}
			validationErr = multierr.Append(validationErr, errors.New(message))
			continue
		}
		owners[key] = definition
	}
	return validationErr
}

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
	err = multierr.Append(err, cfg.validateGNMIDialInEndpointOwnership())
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
	if shapeErr := validateGNMIConfigurationShape(cfg.GNMI.Targets); shapeErr != nil {
		return multierr.Append(err, shapeErr)
	}

	names := map[string]int{}
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
		if strings.TrimSpace(target.Endpoint) == "" {
			err = multierr.Append(err, fmt.Errorf("%s.endpoint cannot be empty", prefix))
		} else if _, endpointErr := canonicalGNMIDialInEndpoint(target.Endpoint); endpointErr != nil {
			err = multierr.Append(err, fmt.Errorf("%s.endpoint %w", prefix, endpointErr))
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
	err = multierr.Append(err, validateGNMIEncodingPreferences(prefix+".encoding_preference", target.EncodingPreference))
	err = multierr.Append(err, validateGNMIProductEncodingPreferences(prefix+".encoding_preference", target.EncodingPreference, contract))
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

func validateGNMIPinnedModelBoundary(prefix string, target GNMITargetConfig, contract *gnmiProductContract) error {
	if contract == nil || len(contract.RequiredModelData) == 0 {
		return nil
	}
	streams, err := buildSharedGNMIStreams(target)
	if err != nil {
		// The field-level validators report malformed streams with their exact
		// configuration paths. Avoid replacing those diagnostics with a derived
		// model-boundary error.
		return nil
	}
	if unpinned := unpinnedGNMIRequiredModels(contract, streams); len(unpinned) > 0 {
		return fmt.Errorf(
			"%s requires models outside product %q's reviewed ModelData allowlist: %s",
			prefix,
			contract.Product,
			strings.Join(unpinned, ", "),
		)
	}
	return nil
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

func validateGNMIProfiles(prefix string, target GNMITargetConfig, contract *gnmiProductContract) error {
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
		itemPrefix := fmt.Sprintf("%s.profiles.%s", prefix, item.name)
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
		err = multierr.Append(err, validateGNMIEncodingPreferences(itemPrefix+".encoding_preference", item.profile.EncodingPreference))
		err = multierr.Append(err, validateGNMIProductEncodingPreferences(itemPrefix+".encoding_preference", item.profile.EncodingPreference, contract))
		effectiveEncodings := effectiveGNMIEncodingPreferences(item.profile.EncodingPreference, target.EncodingPreference, false)
		err = multierr.Append(err, validateGNMIListOptions(
			itemPrefix,
			gnmiModeStream,
			effectiveEncodings,
			item.profile.UpdatesOnly,
			item.profile.AllowAggregation,
			item.profile.QoSMarking,
			item.profile.GNMIExtensions,
		))
		if enabled {
			err = multierr.Append(err, validateGNMIProductListPolicy(
				itemPrefix, contract,
				item.profile.UpdatesOnly, item.profile.AllowAggregation,
				item.profile.QoSMarking, item.profile.GNMIExtensions,
			))
		}
		definition, ok := builtinGNMIProfile(contract, item.name)
		if !ok {
			configured := enabled || item.profile.Required || item.profile.SampleInterval != 0 ||
				len(item.profile.EncodingPreference) != 0 || item.profile.UpdatesOnly || item.profile.AllowAggregation ||
				item.profile.QoSMarking != nil || item.profile.GNMIExtensions.Depth != nil || len(item.profile.PathOverrides) != 0
			if configured && contract != nil {
				err = multierr.Append(err, fmt.Errorf(
					"%s is not supported on product %q release train %s",
					itemPrefix,
					contract.Product,
					contract.ReleaseTrain,
				))
			}
			for pathID := range item.profile.PathOverrides {
				err = multierr.Append(err, fmt.Errorf("%s.path_overrides.%s is not a known path ID for the selected product", itemPrefix, pathID))
			}
			continue
		}
		if enabled {
			pathOptions := make([]GNMIPathOptionsConfig, 0, len(definition.Paths))
			for _, path := range definition.Paths {
				pathOptions = append(pathOptions, item.profile.PathOverrides[path.ID])
			}
			err = multierr.Append(err, validateGNMIProductSamplePlan(itemPrefix, contract, item.profile.SampleInterval, pathOptions))
		}
		err = multierr.Append(err, validateGNMIBuiltinPathOverrides(itemPrefix, definition, item.profile, contract))
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

func validateGNMIBuiltinPathOverrides(
	prefix string,
	definition builtinGNMIProfileDefinition,
	profile GNMIProfileConfig,
	contract *gnmiProductContract,
) error {
	known := make(map[string]struct{}, len(definition.Paths))
	for _, path := range definition.Paths {
		known[path.ID] = struct{}{}
	}
	var err error
	pathIDs := make([]string, 0, len(profile.PathOverrides))
	for pathID := range profile.PathOverrides {
		pathIDs = append(pathIDs, pathID)
	}
	sort.Strings(pathIDs)
	for _, pathID := range pathIDs {
		options := profile.PathOverrides[pathID]
		if _, ok := known[pathID]; !ok {
			err = multierr.Append(err, fmt.Errorf("%s.path_overrides.%s is not a known path ID for this profile and selected product", prefix, pathID))
			continue
		}
		err = multierr.Append(err, validateGNMIPathOptions(prefix+".path_overrides."+pathID, gnmiModeStream, options))
		err = multierr.Append(err, validateGNMIProductPathPolicy(prefix+".path_overrides."+pathID, contract, options))
	}

	// Catalog entries can intentionally share one physical selector so their
	// mappings are coalesced. Such aliases must resolve to identical wire
	// behavior; a target cannot apply two modes to one selector deterministically.
	type duplicatePath struct {
		id      string
		options resolvedGNMIPathOptions
	}
	seen := map[string]duplicatePath{}
	for _, path := range definition.Paths {
		options := resolveGNMIPathOptions(profile.PathOverrides[path.ID], profile.SampleInterval)
		key := sharedGNMIPathKey(sharedGNMIPath{
			PathTarget: path.PathTarget,
			Origin:     path.Origin,
			Path:       strings.Trim(path.Path, "/"),
		})
		if previous, ok := seen[key]; ok && previous.options != options {
			err = multierr.Append(err, fmt.Errorf(
				"%s.path_overrides.%s conflicts with %s for duplicate catalog selector %q",
				prefix, path.ID, previous.id, path.Path,
			))
			continue
		}
		seen[key] = duplicatePath{id: path.ID, options: options}
	}
	return err
}

type resolvedGNMIPathOptions struct {
	streamMode        string
	sampleInterval    time.Duration
	heartbeatInterval time.Duration
	suppressRedundant bool
}

func resolveGNMIPathOptions(options GNMIPathOptionsConfig, fallbackSampleInterval time.Duration) resolvedGNMIPathOptions {
	mode := options.StreamMode
	if mode == "" {
		mode = gnmiStreamModeSample
	}
	resolved := resolvedGNMIPathOptions{streamMode: mode}
	switch mode {
	case gnmiStreamModeSample:
		resolved.sampleInterval = fallbackSampleInterval
		if options.SampleInterval != nil {
			resolved.sampleInterval = *options.SampleInterval
		}
		if options.HeartbeatInterval != nil {
			resolved.heartbeatInterval = *options.HeartbeatInterval
		}
		resolved.suppressRedundant = boolValue(options.SuppressRedundant, false)
	case gnmiStreamModeOnChange:
		if options.HeartbeatInterval != nil {
			resolved.heartbeatInterval = *options.HeartbeatInterval
		}
	}
	return resolved
}

func validateGNMIEncodingPreferences(prefix string, preferences []string) error {
	seen := map[gnmipb.Encoding]struct{}{}
	var err error
	for i, preference := range preferences {
		encoding, ok := encodingNameToGNMI(preference)
		if !ok {
			err = multierr.Append(err, fmt.Errorf("%s[%d] must be json_ietf, json, or proto", prefix, i))
			continue
		}
		if _, duplicate := seen[encoding]; duplicate {
			err = multierr.Append(err, fmt.Errorf("%s[%d] duplicates encoding %q", prefix, i, strings.ToLower(strings.TrimSpace(preference))))
			continue
		}
		seen[encoding] = struct{}{}
	}
	return err
}

func effectiveGNMIEncodingPreferences(local, target []string, dme bool) []string {
	preferences := local
	if len(preferences) == 0 {
		preferences = target
	}
	if len(preferences) == 0 {
		if dme {
			return []string{"json", "json_ietf"}
		}
		return []string{"json_ietf", "json"}
	}
	out := make([]string, 0, len(preferences))
	for _, preference := range preferences {
		if encoding, ok := encodingNameToGNMI(preference); ok {
			out = append(out, sharedGNMIEncodingName(encoding))
		} else {
			out = append(out, strings.ToLower(strings.TrimSpace(preference)))
		}
	}
	return out
}

func sharedGNMIEncodingName(encoding gnmipb.Encoding) string {
	switch encoding {
	case gnmipb.Encoding_JSON_IETF:
		return "json_ietf"
	case gnmipb.Encoding_PROTO:
		return "proto"
	default:
		return "json"
	}
}

func validateGNMIListOptions(
	prefix, mode string,
	encodingPreferences []string,
	updatesOnly, allowAggregation bool,
	qosMarking *uint32,
	extensions GNMIExtensionsConfig,
) error {
	var err error
	if mode != gnmiModeStream && updatesOnly {
		err = multierr.Append(err, fmt.Errorf("%s.updates_only is supported only for stream mode", prefix))
	}
	if qosMarking != nil && *qosMarking > 63 {
		err = multierr.Append(err, fmt.Errorf("%s.qos_marking must be between 0 and 63", prefix))
	}
	if extensions.Depth != nil && (*extensions.Depth < 1 || *extensions.Depth > 128) {
		err = multierr.Append(err, fmt.Errorf("%s.gnmi_extensions.depth must be between 1 and 128", prefix))
	}
	if allowAggregation && !gnmiEncodingPreferencesContainJSON(encodingPreferences) {
		err = multierr.Append(err, fmt.Errorf("%s.allow_aggregation requires a json or json_ietf encoding preference", prefix))
	}
	return err
}

func gnmiEncodingPreferencesContainJSON(preferences []string) bool {
	for _, preference := range preferences {
		encoding, ok := encodingNameToGNMI(preference)
		if ok && (encoding == gnmipb.Encoding_JSON || encoding == gnmipb.Encoding_JSON_IETF) {
			return true
		}
	}
	return false
}

func validateGNMIPathOptions(prefix, listMode string, options GNMIPathOptionsConfig) error {
	if listMode != gnmiModeStream {
		if gnmiPathOptionsConfigured(options) {
			return fmt.Errorf("%s path options are supported only for stream mode", prefix)
		}
		return nil
	}
	mode := options.StreamMode
	if mode == "" {
		mode = gnmiStreamModeSample
	}
	var err error
	switch mode {
	case gnmiStreamModeSample:
		if options.SampleInterval != nil && *options.SampleInterval < 0 {
			err = multierr.Append(err, fmt.Errorf("%s.sample_interval must not be negative", prefix))
		}
		if options.HeartbeatInterval != nil && *options.HeartbeatInterval <= 0 {
			err = multierr.Append(err, fmt.Errorf("%s.heartbeat_interval must be positive when configured", prefix))
		}
	case gnmiStreamModeOnChange:
		if options.SampleInterval != nil {
			err = multierr.Append(err, fmt.Errorf("%s.sample_interval is forbidden for on_change mode", prefix))
		}
		if options.SuppressRedundant != nil {
			err = multierr.Append(err, fmt.Errorf("%s.suppress_redundant is forbidden for on_change mode", prefix))
		}
		if options.HeartbeatInterval != nil && *options.HeartbeatInterval <= 0 {
			err = multierr.Append(err, fmt.Errorf("%s.heartbeat_interval must be positive when configured", prefix))
		}
	case gnmiStreamModeTargetDefined:
		if options.SampleInterval != nil || options.HeartbeatInterval != nil || options.SuppressRedundant != nil {
			err = multierr.Append(err, fmt.Errorf("%s timing and suppression fields are forbidden for target_defined mode", prefix))
		}
	default:
		err = multierr.Append(err, fmt.Errorf("%s.stream_mode must be sample, on_change, or target_defined", prefix))
	}
	return err
}

func gnmiPathOptionsConfigured(options GNMIPathOptionsConfig) bool {
	return options.StreamMode != "" || options.SampleInterval != nil || options.HeartbeatInterval != nil || options.SuppressRedundant != nil
}

func validateGNMICustomSubscriptions(prefix string, target GNMITargetConfig, contract *gnmiProductContract) error {
	var err error
	names := map[string]struct{}{}
	outputIdentities := map[string]string{}
	for i := range target.CustomSubscriptions {
		subscription := &target.CustomSubscriptions[i]
		itemPrefix := fmt.Sprintf("%s.custom_subscriptions[%d]", prefix, i)
		canonicalMappingSources := map[string]string{}
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
		err = multierr.Append(err, validateGNMICustomSubscriptionAddress(itemPrefix, *subscription))
		err = multierr.Append(err, validateGNMICustomSubscriptionModels(itemPrefix, *subscription, contract))
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
		err = multierr.Append(err, validateGNMIEncodingPreferences(itemPrefix+".encoding_preference", subscription.EncodingPreference))
		err = multierr.Append(err, validateGNMIProductEncodingPreferences(itemPrefix+".encoding_preference", subscription.EncodingPreference, contract))
		effectiveEncodings := effectiveGNMIEncodingPreferences(
			subscription.EncodingPreference,
			target.EncodingPreference,
			subscription.Origin == builtinGNMIOriginDME,
		)
		err = multierr.Append(err, validateGNMIListOptions(
			itemPrefix,
			subscription.Mode,
			effectiveEncodings,
			subscription.UpdatesOnly,
			subscription.AllowAggregation,
			subscription.QoSMarking,
			subscription.GNMIExtensions,
		))
		if contract != nil && contract.RequestPolicy.StreamOnly && subscription.Mode != gnmiModeStream {
			if contract.RequestPolicy.ConservativeSampleOnly {
				err = multierr.Append(err, fmt.Errorf("%s supports only SAMPLE STREAM subscriptions on product %s", itemPrefix, contract.Product))
			} else {
				err = multierr.Append(err, fmt.Errorf("%s.mode must be stream on product %s", itemPrefix, contract.Product))
			}
		}
		err = multierr.Append(err, validateGNMIProductListPolicy(
			itemPrefix, contract,
			subscription.UpdatesOnly, subscription.AllowAggregation,
			subscription.QoSMarking, subscription.GNMIExtensions,
		))
		pathOptions := make([]GNMIPathOptionsConfig, 0, len(subscription.Paths))
		for _, path := range subscription.Paths {
			pathOptions = append(pathOptions, path.GNMIPathOptionsConfig)
		}
		err = multierr.Append(err, validateGNMIProductSamplePlan(itemPrefix, contract, subscription.SampleInterval, pathOptions))
		err = multierr.Append(err, validateGNMICustomSubscriptionPaths(itemPrefix, *subscription, contract))
		if len(subscription.Mappings) == 0 {
			err = multierr.Append(err, fmt.Errorf("%s.mappings cannot be empty", itemPrefix))
		}
		paths := map[string]struct{}{}
		for j, mapping := range subscription.Mappings {
			mappingPrefix := fmt.Sprintf("%s.mappings[%d]", itemPrefix, j)
			path := strings.Trim(strings.TrimSpace(mapping.Path), "/")
			mappingValid := true
			if path == "" || !gnmiCustomPathNamespaceValid(path, subscription.Origin) {
				err = multierr.Append(err, fmt.Errorf("%s.path must be a non-empty origin-free path using the namespace form required by origin %q", mappingPrefix, subscription.Origin))
				mappingValid = false
			}
			if contract != nil && !contract.RequestPolicy.AllowWildcards &&
				gnmiPathContainsWildcard(sharedGNMIPath{PathTarget: subscription.PathTarget, Origin: subscription.Origin, Path: path}) {
				err = multierr.Append(err, fmt.Errorf("%s.path contains an explicit asterisk wildcard that is not qualified on product %s", mappingPrefix, contract.Product))
				mappingValid = false
			}
			if _, duplicate := paths[path]; duplicate {
				err = multierr.Append(err, fmt.Errorf("%s.path duplicates another mapping", mappingPrefix))
				mappingValid = false
			}
			paths[path] = struct{}{}
			if !normalizedMetricNamePattern.MatchString(mapping.MetricName) || strings.HasSuffix(mapping.MetricName, "_info") {
				err = multierr.Append(err, fmt.Errorf("%s.metric_name must be a normalized non-info metric name", mappingPrefix))
				mappingValid = false
			} else if contract, reserved := governedMetricNameCollision(mapping.MetricName); reserved {
				err = multierr.Append(err, fmt.Errorf("%s.metric_name %q is reserved by %s", mappingPrefix, mapping.MetricName, contract))
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
			if path != "" && gnmiCustomPathNamespaceValid(path, subscription.Origin) {
				parsed, parseErr := internalgnmi.ParsePath("", subscription.Origin, path)
				parsed.PathTarget = subscription.PathTarget
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
				source := subscription.PathTarget + "\x00" + subscription.Origin + "\x00" + path
				if previous, duplicate := outputIdentities[identity]; duplicate {
					err = multierr.Append(err, fmt.Errorf("%s can collide with source %q because both produce metric %q with the same output attributes", mappingPrefix, previous, mapping.MetricName))
					mappingValid = false
				} else {
					outputIdentities[identity] = source
				}
			}
			if mappingValid {
				converted, _, conversionErr := convertCustomGNMIMapping(subscription.PathTarget, subscription.Origin, mapping)
				if conversionErr != nil {
					err = multierr.Append(err, fmt.Errorf("%s is invalid: %w", mappingPrefix, conversionErr))
					continue
				}
				sourceKey := converted.Mapping.Source.Key()
				if previous, duplicate := canonicalMappingSources[sourceKey]; duplicate {
					err = multierr.Append(err, fmt.Errorf(
						"%s has the same canonical mapping source as %s; configured list-key values and key order do not distinguish mapping sources",
						mappingPrefix,
						previous,
					))
				} else {
					canonicalMappingSources[sourceKey] = mappingPrefix
				}
			}
		}
	}
	return err
}

func validateGNMICustomSubscriptionAddress(
	prefix string,
	subscription GNMICustomSubscriptionConfig,
) error {
	pathTarget := strings.TrimSpace(subscription.PathTarget)
	origin := strings.TrimSpace(subscription.Origin)
	if subscription.PathTarget != pathTarget {
		return fmt.Errorf("%s.path_target must not contain surrounding whitespace", prefix)
	}
	if subscription.Origin != origin {
		return fmt.Errorf("%s.origin must not contain surrounding whitespace", prefix)
	}
	if origin != "" && !gnmiYANGIdentifierPattern.MatchString(origin) {
		return fmt.Errorf("%s.origin must be a valid YANG identifier", prefix)
	}
	if err := internalgnmi.ValidatePath(internalgnmi.Path{PathTarget: pathTarget, Origin: origin}); err != nil {
		return fmt.Errorf("%s path_target/origin is invalid: %w", prefix, err)
	}
	var err error
	if pathTarget != "" {
		err = multierr.Append(err, fmt.Errorf("%s.path_target is not supported by a built-in Cisco product contract", prefix))
	}
	if origin == "" {
		err = multierr.Append(err, fmt.Errorf("%s.origin cannot be empty", prefix))
	}
	return err
}

func validateGNMICustomSubscriptionModels(
	prefix string,
	subscription GNMICustomSubscriptionConfig,
	contract *gnmiProductContract,
) error {
	var err error
	origin := strings.TrimSpace(subscription.Origin)
	if origin == builtinGNMIOriginOpenConfig && len(subscription.Models) == 0 {
		err = multierr.Append(err, fmt.Errorf(
			"%s.models must contain at least one exact Capabilities model name when origin is %q",
			prefix,
			builtinGNMIOriginOpenConfig,
		))
	}
	if contract != nil && contract.OSFamily == gnmiPlatformNXOS {
		if strings.EqualFold(origin, builtinGNMIOriginOpenConfig) && origin != builtinGNMIOriginOpenConfig {
			err = multierr.Append(err, fmt.Errorf(
				"%s.origin must use the exact NX-OS OpenConfig origin %q",
				prefix,
				builtinGNMIOriginOpenConfig,
			))
		}
		if strings.HasPrefix(strings.ToLower(origin), "openconfig-") {
			err = multierr.Append(err, fmt.Errorf(
				"%s.origin must be %q for NX-OS OpenConfig requests; list %q in models instead",
				prefix,
				builtinGNMIOriginOpenConfig,
				origin,
			))
		}
	}
	seen := make(map[string]struct{}, len(subscription.Models))
	for index, rawModel := range subscription.Models {
		modelPrefix := fmt.Sprintf("%s.models[%d]", prefix, index)
		model := strings.TrimSpace(rawModel)
		switch {
		case model != rawModel:
			err = multierr.Append(err, fmt.Errorf("%s must not contain surrounding whitespace", modelPrefix))
		case !gnmiYANGIdentifierPattern.MatchString(model):
			err = multierr.Append(err, fmt.Errorf("%s must be a valid YANG module identifier", modelPrefix))
		case model == builtinGNMIOriginOpenConfig:
			err = multierr.Append(err, fmt.Errorf("%s must identify a concrete model, not the generic origin %q", modelPrefix, model))
		default:
			if _, duplicate := seen[model]; duplicate {
				err = multierr.Append(err, fmt.Errorf("%s duplicates another required model", modelPrefix))
			} else {
				seen[model] = struct{}{}
			}
		}
	}
	return err
}

func validateGNMICustomSubscriptionPaths(prefix string, subscription GNMICustomSubscriptionConfig, contract *gnmiProductContract) error {
	if len(subscription.Paths) == 0 {
		return nil
	}
	type parsedSelector struct {
		index int
		path  internalgnmi.Path
	}
	selectors := make([]parsedSelector, 0, len(subscription.Paths))
	var err error
	for i, configured := range subscription.Paths {
		pathPrefix := fmt.Sprintf("%s.paths[%d]", prefix, i)
		path := strings.Trim(strings.TrimSpace(configured.Path), "/")
		if path == "" || !gnmiCustomPathNamespaceValid(path, subscription.Origin) {
			err = multierr.Append(err, fmt.Errorf("%s.path must be a non-empty origin-free path using the namespace form required by origin %q", pathPrefix, subscription.Origin))
			continue
		}
		if contract != nil && !contract.RequestPolicy.AllowWildcards &&
			gnmiPathContainsWildcard(sharedGNMIPath{PathTarget: subscription.PathTarget, Origin: subscription.Origin, Path: path}) {
			err = multierr.Append(err, fmt.Errorf("%s.path contains an explicit asterisk wildcard that is not qualified on product %s", pathPrefix, contract.Product))
			continue
		}
		err = multierr.Append(err, validateGNMIPathOptions(pathPrefix, subscription.Mode, configured.GNMIPathOptionsConfig))
		err = multierr.Append(err, validateGNMIProductPathPolicy(pathPrefix, contract, configured.GNMIPathOptionsConfig))
		parsed, parseErr := internalgnmi.ParsePath("", subscription.Origin, path)
		parsed.PathTarget = subscription.PathTarget
		if parseErr != nil {
			err = multierr.Append(err, fmt.Errorf("%s.path is invalid: %w", pathPrefix, parseErr))
			continue
		}
		for _, previous := range selectors {
			if parsed.HasPrefix(previous.path) || previous.path.HasPrefix(parsed) {
				err = multierr.Append(err, fmt.Errorf(
					"%s.path duplicates or conflicts with %s.paths[%d]",
					pathPrefix, prefix, previous.index,
				))
				break
			}
		}
		selectors = append(selectors, parsedSelector{index: i, path: parsed})
	}

	for i, mapping := range subscription.Mappings {
		mappingPath := strings.Trim(strings.TrimSpace(mapping.Path), "/")
		if mappingPath == "" || !gnmiCustomPathNamespaceValid(mappingPath, subscription.Origin) {
			continue
		}
		parsed, parseErr := internalgnmi.ParsePath("", subscription.Origin, mappingPath)
		parsed.PathTarget = subscription.PathTarget
		if parseErr != nil {
			continue
		}
		matched := false
		for _, selector := range selectors {
			if parsed.HasPrefix(selector.path) {
				matched = true
				break
			}
		}
		if !matched {
			err = multierr.Append(err, fmt.Errorf(
				"%s.mappings[%d].path must equal or descend from at least one subscription selector with compatible keys",
				prefix, i,
			))
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
	parsed, err := internalgnmi.ParsePath("", origin, path)
	if err != nil || len(parsed.Elements) == 0 {
		return false
	}
	_, qualified := splitGNMIQualifiedName(parsed.Elements[0].Name)
	return qualified
}

func gnmiCustomPathNamespaceValid(path, origin string) bool {
	if origin != "" && !gnmiYANGIdentifierPattern.MatchString(origin) {
		return false
	}
	parsed, err := internalgnmi.ParsePath("", origin, path)
	if err != nil || len(parsed.Elements) == 0 {
		return false
	}
	firstQualified := false
	anyQualified := false
	for index := range parsed.Elements {
		element := parsed.Elements[index]
		for key := range element.Keys {
			if !gnmiYANGIdentifierPattern.MatchString(key) {
				return false
			}
		}
		name := element.Name
		if name == "*" {
			continue
		}
		if !strings.Contains(name, ":") {
			if !gnmiYANGIdentifierPattern.MatchString(name) {
				return false
			}
			continue
		}
		if _, qualified := splitGNMIQualifiedName(name); !qualified {
			return false
		}
		anyQualified = true
		firstQualified = firstQualified || index == 0
	}
	if origin == "" {
		return true
	}
	if origin == builtinGNMIOriginRFC7951 {
		return firstQualified
	}
	return !anyQualified
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
	seenCatalogs := map[gnmiProductContractKey]struct{}{}
	for key, productContract := range gnmiProductContracts {
		if _, seen := seenCatalogs[key]; seen {
			continue
		}
		seenCatalogs[key] = struct{}{}
		for _, profile := range builtinGNMIProfiles(productContract) {
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
		for subscriptionIndex := range target.CustomSubscriptions {
			subscription := &target.CustomSubscriptions[subscriptionIndex]
			for mappingIndex := range subscription.Mappings {
				mapping := &subscription.Mappings[mappingIndex]
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
	for _, profileName := range []string{
		builtinGNMIProfileIdentity,
		builtinGNMIProfileSystem,
		builtinGNMIProfileInterfaces,
		builtinGNMIProfileOptics,
		builtinGNMIProfileCatalyst9800Wireless,
	} {
		profileConfig := sharedGNMIProfileConfig(target.Profiles, profileName)
		if !boolValue(profileConfig.Enabled, false) {
			continue
		}
		definition, ok := builtinGNMIProfile(contract, profileName)
		if !ok {
			continue
		}
		streams += len(buildBuiltinProfileStreams(contract, definition, profileConfig))
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

func sortedGNMIPathKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
