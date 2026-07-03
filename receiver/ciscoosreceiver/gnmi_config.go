// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"errors"
	"fmt"
	"math"
	"net"
	"regexp"
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

	// grpc-go allocates the complete protobuf before the receiver can apply its
	// per-value decoder budgets. Keep a hard frame ceiling aligned with the
	// receiver's other network payload limits to prevent multi-gigabyte
	// allocation attempts from a device or compromised telemetry endpoint.
	gnmiMaxRecvMsgSizeMiB     = 16
	gnmiMaxDatapointsPerChunk = 10_000
	gnmiMaximumCachedSeries   = 500_000
)

var (
	normalizedMetricNamePattern    = regexp.MustCompile(`^[a-z][a-z0-9_.]*$`)
	normalizedAttributeNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]*$`)
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

	Enabled        *bool         `mapstructure:"enabled"`
	Required       bool          `mapstructure:"required"`
	SampleInterval time.Duration `mapstructure:"sample_interval"`
}

// GNMIProfilesConfig contains the normalized profile set.
type GNMIProfilesConfig struct {
	_ struct{} `mapstructure:"-"`

	Identity             GNMIProfileConfig `mapstructure:"identity"`
	System               GNMIProfileConfig `mapstructure:"system"`
	Interfaces           GNMIProfileConfig `mapstructure:"interfaces"`
	Optics               GNMIProfileConfig `mapstructure:"optics"`
	Catalyst9800Wireless GNMIProfileConfig `mapstructure:"catalyst_9800_wireless"`
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
	Mappings       []GNMIMetricMappingConfig `mapstructure:"mappings"`
}

// GNMITargetConfig identifies one statically owned dial-in target.
type GNMITargetConfig struct {
	_ struct{} `mapstructure:"-"`

	Name                string                         `mapstructure:"name"`
	Endpoint            string                         `mapstructure:"endpoint"`
	Platform            string                         `mapstructure:"platform"`
	MaxRecvMsgSizeMiB   int                            `mapstructure:"max_recv_msg_size_mib"`
	MaxStreams          int                            `mapstructure:"max_streams"`
	ConnectTimeout      time.Duration                  `mapstructure:"connect_timeout"`
	CapabilitiesTimeout time.Duration                  `mapstructure:"capabilities_timeout"`
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

func (profile GNMIProfileConfig) withDefaults(enabled bool, interval time.Duration) GNMIProfileConfig {
	if profile.Enabled == nil {
		profile.Enabled = new(bool)
		*profile.Enabled = enabled
	}
	if profile.SampleInterval == 0 {
		profile.SampleInterval = interval
	}
	return profile
}

func (profiles GNMIProfilesConfig) withDefaults() GNMIProfilesConfig {
	profiles.Identity = profiles.Identity.withDefaults(true, 5*time.Minute)
	profiles.System = profiles.System.withDefaults(true, time.Minute)
	profiles.Interfaces = profiles.Interfaces.withDefaults(true, time.Minute)
	profiles.Optics = profiles.Optics.withDefaults(false, 30*time.Second)
	profiles.Catalyst9800Wireless = profiles.Catalyst9800Wireless.withDefaults(false, time.Minute)
	return profiles
}

func (target GNMITargetConfig) withDefaults() GNMITargetConfig {
	if target.MaxRecvMsgSizeMiB == 0 {
		target.MaxRecvMsgSizeMiB = 16
	}
	if target.MaxStreams == 0 {
		target.MaxStreams = 4
	}
	if target.ConnectTimeout == 0 {
		target.ConnectTimeout = 15 * time.Second
	}
	if target.CapabilitiesTimeout == 0 {
		target.CapabilitiesTimeout = 15 * time.Second
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
	target.Profiles = target.Profiles.withDefaults()
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
	}
	return target
}

func (cfg *Config) validateGNMI() error {
	if !cfg.GNMI.hasTargets() {
		return nil
	}
	var err error
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
	}
	err = multierr.Append(err, validateGNMIMetricContracts(cfg.GNMI.Targets))
	return err
}

func validateGNMITarget(prefix string, target GNMITargetConfig) error {
	var err error
	switch target.Platform {
	case gnmiPlatformIOSXE, gnmiPlatformIOSXR, gnmiPlatformNXOS:
	default:
		err = multierr.Append(err, fmt.Errorf("%s.platform must be ios_xe, ios_xr, or nx_os", prefix))
	}
	if target.MaxRecvMsgSizeMiB <= 0 {
		err = multierr.Append(err, fmt.Errorf("%s.max_recv_msg_size_mib must be positive", prefix))
	} else if target.MaxRecvMsgSizeMiB > gnmiMaxRecvMsgSizeMiB {
		err = multierr.Append(err, fmt.Errorf("%s.max_recv_msg_size_mib must not exceed %d", prefix, gnmiMaxRecvMsgSizeMiB))
	}
	if target.MaxStreams < 1 || target.MaxStreams > 8 {
		err = multierr.Append(err, fmt.Errorf("%s.max_streams must be between 1 and 8", prefix))
	}
	if target.ConnectTimeout <= 0 || target.CapabilitiesTimeout <= 0 {
		err = multierr.Append(err, fmt.Errorf("%s connection and capabilities timeouts must be positive", prefix))
	}
	if target.Keepalive.Time <= 0 || target.Keepalive.Timeout <= 0 {
		err = multierr.Append(err, fmt.Errorf("%s.keepalive time and timeout must be positive", prefix))
	}
	err = multierr.Append(err, validateGNMICredentials(prefix, target))
	err = multierr.Append(err, validateGNMITLS(prefix, target.TLS))
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
	}
	var err error
	for _, item := range profiles {
		enabled := boolValue(item.profile.Enabled, false)
		if item.profile.Required && !enabled {
			err = multierr.Append(err, fmt.Errorf("%s.profiles.%s cannot be required when disabled", prefix, item.name))
		}
		if enabled && item.profile.SampleInterval <= 0 {
			err = multierr.Append(err, fmt.Errorf("%s.profiles.%s.sample_interval must be positive", prefix, item.name))
		}
	}
	if boolValue(target.Profiles.Catalyst9800Wireless.Enabled, false) && target.Platform != gnmiPlatformIOSXE {
		err = multierr.Append(err, fmt.Errorf("%s.profiles.catalyst_9800_wireless is supported only on ios_xe", prefix))
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
	case builtinGNMIProfileIdentity, builtinGNMIProfileSystem, builtinGNMIProfileInterfaces, builtinGNMIProfileOptics, builtinGNMIProfileCatalyst9800Wireless:
		return true
	default:
		return false
	}
}

func gnmiPathIncludesOrigin(path, origin string) bool {
	path = strings.TrimLeft(path, "/")
	first, _, hasChild := strings.Cut(path, "/")
	return origin != "" && hasChild && strings.HasSuffix(first, ":")
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
			for _, path := range profile.Paths {
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
