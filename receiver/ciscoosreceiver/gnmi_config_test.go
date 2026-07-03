// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"fmt"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/confmap/confmaptest"
)

func boolPtr(value bool) *bool { return &value }

func validGNMITestConfig() *Config {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.GNMI.Targets = []GNMITargetConfig{{
		Name:     "edge-1",
		Endpoint: "edge-1.example.test:57400",
		Platform: gnmiPlatformIOSXR,
		Credentials: GNMICredentialsConfig{
			Username: "telemetry",
			Password: configopaque.String("secret"),
		},
	}}
	return cfg
}

func validCustomGNMISubscription() GNMICustomSubscriptionConfig {
	scale := 0.001
	return GNMICustomSubscriptionConfig{
		Name:           "custom-temperature",
		Origin:         "openconfig-platform",
		Mode:           gnmiModeStream,
		SampleInterval: 30 * time.Second,
		Mappings: []GNMIMetricMappingConfig{{
			Path:        "components/component/state/temperature/instant",
			MetricName:  "cisco.environment.temperature",
			Description: "Component temperature",
			Unit:        "Cel",
			Scale:       &scale,
			GaugeType:   "double",
			PathKeys:    map[string]string{"component.name": "hw.name"},
		}},
	}
}

func TestGNMIDefaults(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	assert.Equal(t, 10_000, cfg.GNMI.MaxDatapointsPerChunk)
	assert.Equal(t, 500_000, cfg.GNMI.MaxCachedSeries)

	target := (GNMITargetConfig{}).withDefaults()
	assert.Equal(t, 16, target.MaxRecvMsgSizeMiB)
	assert.Equal(t, 4, target.MaxStreams)
	assert.Equal(t, 15*time.Second, target.ConnectTimeout)
	assert.Equal(t, 15*time.Second, target.CapabilitiesTimeout)
	assert.Equal(t, gnmiCredentialUsernamePassword, target.Credentials.Mode)
	assert.Equal(t, "1.2", target.TLS.MinVersion)
	assert.Equal(t, 30*time.Second, target.Keepalive.Time)
	assert.Equal(t, 10*time.Second, target.Keepalive.Timeout)
	require.NotNil(t, target.Keepalive.PermitWithoutStream)
	assert.True(t, *target.Keepalive.PermitWithoutStream)

	assert.True(t, boolValue(target.Profiles.Identity.Enabled, false))
	assert.True(t, boolValue(target.Profiles.System.Enabled, false))
	assert.True(t, boolValue(target.Profiles.Interfaces.Enabled, false))
	assert.False(t, boolValue(target.Profiles.Optics.Enabled, true))
	assert.False(t, boolValue(target.Profiles.Catalyst9800Wireless.Enabled, true))
	assert.Equal(t, 5*time.Minute, target.Profiles.Identity.SampleInterval)
	assert.Equal(t, time.Minute, target.Profiles.System.SampleInterval)
	assert.Equal(t, time.Minute, target.Profiles.Interfaces.SampleInterval)
	assert.Equal(t, 30*time.Second, target.Profiles.Optics.SampleInterval)
}

func TestGNMIConfigUnmarshal(t *testing.T) {
	conf, err := confmaptest.LoadConf(filepath.Join("testdata", "gnmi-config.yaml"))
	require.NoError(t, err)
	sub, err := conf.Sub("receivers::cisco_os")
	require.NoError(t, err)
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	require.NoError(t, sub.Unmarshal(cfg))
	require.NoError(t, cfg.Validate())
	require.Len(t, cfg.GNMI.Targets, 1)
	target := cfg.GNMI.Targets[0].withDefaults()
	assert.Equal(t, "nexus-shard-01", target.Name)
	assert.Equal(t, gnmiPlatformNXOS, target.Platform)
	assert.Equal(t, configopaque.String("secret"), target.Credentials.Password)
	assert.Equal(t, time.Hour, target.TLS.ReloadInterval)
	require.NotNil(t, target.Keepalive.PermitWithoutStream)
	assert.False(t, *target.Keepalive.PermitWithoutStream)
	assert.True(t, boolValue(target.Profiles.Optics.Enabled, false))
	assert.True(t, target.Profiles.Optics.Required)
}

func TestGNMICredentialModes(t *testing.T) {
	tests := []struct {
		name        string
		credentials GNMICredentialsConfig
		tls         GNMITLSConfig
		errContains string
	}{
		{
			name: "default username password",
			credentials: GNMICredentialsConfig{
				Username: "telemetry", Password: configopaque.String("secret"),
			},
		},
		{
			name:        "mtls",
			credentials: GNMICredentialsConfig{Mode: gnmiCredentialMTLS},
			tls:         GNMITLSConfig{CertFile: "client.crt", KeyFile: "client.key"},
		},
		{
			name: "mtls username password",
			credentials: GNMICredentialsConfig{
				Mode: gnmiCredentialMTLSUsernamePassword, Username: "telemetry", Password: configopaque.String("secret"),
			},
			tls: GNMITLSConfig{CertFile: "client.crt", KeyFile: "client.key"},
		},
		{name: "unknown mode", credentials: GNMICredentialsConfig{Mode: "token"}, errContains: "credentials.mode"},
		{name: "missing username", credentials: GNMICredentialsConfig{Mode: gnmiCredentialUsernamePassword, Password: configopaque.String("secret")}, errContains: "credentials.username"},
		{name: "missing password", credentials: GNMICredentialsConfig{Mode: gnmiCredentialUsernamePassword, Username: "telemetry"}, errContains: "credentials.password"},
		{name: "mtls missing certificate", credentials: GNMICredentialsConfig{Mode: gnmiCredentialMTLS}, errContains: "required for mtls"},
		{name: "client certificate with password-only mode", credentials: GNMICredentialsConfig{Mode: gnmiCredentialUsernamePassword, Username: "telemetry", Password: configopaque.String("secret")}, tls: GNMITLSConfig{CertFile: "client.crt", KeyFile: "client.key"}, errContains: "require an mTLS"},
		{name: "password ignored by mtls mode", credentials: GNMICredentialsConfig{Mode: gnmiCredentialMTLS, Username: "telemetry", Password: configopaque.String("secret")}, tls: GNMITLSConfig{CertFile: "client.crt", KeyFile: "client.key"}, errContains: "username/password require"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validGNMITestConfig()
			cfg.GNMI.Targets[0].Credentials = tt.credentials
			cfg.GNMI.Targets[0].TLS = tt.tls
			err := cfg.validateGNMI()
			if tt.errContains == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestGNMITLSValidation(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*GNMITLSConfig)
		errContains string
	}{
		{name: "verified defaults"},
		{name: "tls 1.3", mutate: func(tls *GNMITLSConfig) { tls.MinVersion = "1.3" }},
		{name: "insecure", mutate: func(tls *GNMITLSConfig) { tls.Insecure = true }, errContains: "tls.insecure is forbidden"},
		{name: "skip verify", mutate: func(tls *GNMITLSConfig) { tls.InsecureSkipVerify = true }, errContains: "tls.insecure_skip_verify is forbidden"},
		{name: "tls 1.1", mutate: func(tls *GNMITLSConfig) { tls.MinVersion = "1.1" }, errContains: "tls.min_version"},
		{name: "certificate without key", mutate: func(tls *GNMITLSConfig) { tls.CertFile = "client.crt" }, errContains: "configured together"},
		{name: "key without certificate", mutate: func(tls *GNMITLSConfig) { tls.KeyFile = "client.key" }, errContains: "configured together"},
		{name: "negative reload", mutate: func(tls *GNMITLSConfig) { tls.ReloadInterval = -time.Second }, errContains: "reload_interval"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validGNMITestConfig()
			if tt.mutate != nil {
				tt.mutate(&cfg.GNMI.Targets[0].TLS)
			}
			err := cfg.validateGNMI()
			if tt.errContains == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestGNMIRejectsDuplicateAndLegacyTargets(t *testing.T) {
	t.Run("duplicate name", func(t *testing.T) {
		cfg := validGNMITestConfig()
		second := cfg.GNMI.Targets[0]
		second.Endpoint = "edge-2.example.test:57400"
		cfg.GNMI.Targets = append(cfg.GNMI.Targets, second)
		require.ErrorContains(t, cfg.validateGNMI(), "name duplicates")
	})
	t.Run("duplicate endpoint", func(t *testing.T) {
		cfg := validGNMITestConfig()
		second := cfg.GNMI.Targets[0]
		second.Name = "edge-2"
		cfg.GNMI.Targets = append(cfg.GNMI.Targets, second)
		require.ErrorContains(t, cfg.validateGNMI(), "endpoint duplicates")
	})
	t.Run("legacy ios xr overlap", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.IOSXR.DialIn.Targets = []IOSXRTargetConfig{{
			ClientConfig: configgrpc.ClientConfig{Endpoint: cfg.GNMI.Targets[0].Endpoint},
		}}
		require.ErrorContains(t, cfg.validateGNMI(), "legacy ios_xr dial_in")
	})
	t.Run("legacy catalyst overlap", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.Catalyst9800.DialIn.Targets = []Catalyst9800TargetConfig{{
			ClientConfig: configgrpc.ClientConfig{Endpoint: cfg.GNMI.Targets[0].Endpoint},
		}}
		require.ErrorContains(t, cfg.validateGNMI(), "legacy catalyst_9800 dial_in")
	})
}

func TestGNMIProfileValidation(t *testing.T) {
	t.Run("wireless supported on ios xe", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.GNMI.Targets[0].Platform = gnmiPlatformIOSXE
		cfg.GNMI.Targets[0].Profiles.Catalyst9800Wireless.Enabled = boolPtr(true)
		require.NoError(t, cfg.validateGNMI())
	})
	t.Run("wireless rejected elsewhere", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.GNMI.Targets[0].Profiles.Catalyst9800Wireless.Enabled = boolPtr(true)
		require.ErrorContains(t, cfg.validateGNMI(), "supported only on ios_xe")
	})
	t.Run("required profile must be enabled", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.GNMI.Targets[0].Profiles.Optics.Enabled = boolPtr(false)
		cfg.GNMI.Targets[0].Profiles.Optics.Required = true
		require.ErrorContains(t, cfg.validateGNMI(), "cannot be required when disabled")
	})
	t.Run("at least one profile or custom subscription", func(t *testing.T) {
		cfg := validGNMITestConfig()
		disabled := false
		cfg.GNMI.Targets[0].Profiles = GNMIProfilesConfig{
			Identity: GNMIProfileConfig{Enabled: &disabled}, Interfaces: GNMIProfileConfig{Enabled: &disabled},
			System: GNMIProfileConfig{Enabled: &disabled}, Optics: GNMIProfileConfig{Enabled: &disabled},
			Catalyst9800Wireless: GNMIProfileConfig{Enabled: &disabled},
		}
		require.ErrorContains(t, cfg.validateGNMI(), "requires at least one enabled profile")
	})
	t.Run("ios xr identity alone has no subscription path", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.GNMI.Targets[0].Profiles = subscriptionProfilesOnly(builtinGNMIProfileIdentity)
		require.ErrorContains(t, cfg.validateGNMI(), "requires at least one enabled profile")
	})
}

func TestGNMICustomSubscriptionValidation(t *testing.T) {
	t.Run("complete mapping", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.GNMI.Targets[0].MaxStreams = 5
		cfg.GNMI.Targets[0].CustomSubscriptions = []GNMICustomSubscriptionConfig{validCustomGNMISubscription()}
		require.NoError(t, cfg.validateGNMI())
	})
	t.Run("built-in profile name is reserved", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.GNMI.Targets[0].MaxStreams = 5
		subscription := validCustomGNMISubscription()
		subscription.Name = "system"
		cfg.GNMI.Targets[0].CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
		require.ErrorContains(t, cfg.validateGNMI(), "reserved for a built-in profile")
	})

	mappingTests := []struct {
		name        string
		mutate      func(*GNMIMetricMappingConfig)
		errContains string
	}{
		{name: "path", mutate: func(mapping *GNMIMetricMappingConfig) { mapping.Path = "" }, errContains: "origin-free path"},
		{name: "origin kept separate", mutate: func(mapping *GNMIMetricMappingConfig) {
			mapping.Path = "openconfig-platform:/components/component/state"
		}, errContains: "origin-free path"},
		{name: "qualified first element", mutate: func(mapping *GNMIMetricMappingConfig) {
			mapping.Path = "openconfig-platform:components/component/state/value"
		}, errContains: "origin-free path"},
		{name: "qualified single element", mutate: func(mapping *GNMIMetricMappingConfig) {
			mapping.Path = "openconfig-platform:components"
		}, errContains: "origin-free path"},
		{name: "metric name", mutate: func(mapping *GNMIMetricMappingConfig) { mapping.MetricName = "" }, errContains: "metric_name"},
		{name: "dynamic info", mutate: func(mapping *GNMIMetricMappingConfig) { mapping.MetricName = "cisco.custom_info" }, errContains: "non-info"},
		{name: "description", mutate: func(mapping *GNMIMetricMappingConfig) { mapping.Description = "" }, errContains: "description and UCUM"},
		{name: "unit", mutate: func(mapping *GNMIMetricMappingConfig) { mapping.Unit = "degrees Celsius" }, errContains: "description and UCUM"},
		{name: "unknown UCUM atom", mutate: func(mapping *GNMIMetricMappingConfig) { mapping.Unit = "bananas" }, errContains: "description and UCUM"},
		{name: "malformed UCUM logarithmic unit", mutate: func(mapping *GNMIMetricMappingConfig) { mapping.Unit = "dB[" }, errContains: "description and UCUM"},
		{name: "scale omitted", mutate: func(mapping *GNMIMetricMappingConfig) { mapping.Scale = nil }, errContains: "scale"},
		{name: "scale zero", mutate: func(mapping *GNMIMetricMappingConfig) { *mapping.Scale = 0 }, errContains: "scale"},
		{name: "scale non-finite", mutate: func(mapping *GNMIMetricMappingConfig) { *mapping.Scale = math.Inf(1) }, errContains: "scale"},
		{name: "custom sum", mutate: func(mapping *GNMIMetricMappingConfig) { mapping.GaugeType = "sum" }, errContains: "gauge_type"},
		{name: "path keys omitted", mutate: func(mapping *GNMIMetricMappingConfig) { mapping.PathKeys = nil }, errContains: "path_keys"},
		{name: "bad path key", mutate: func(mapping *GNMIMetricMappingConfig) { mapping.PathKeys = map[string]string{"name": "hw.name"} }, errContains: "element.key"},
		{name: "unknown path key element", mutate: func(mapping *GNMIMetricMappingConfig) {
			mapping.PathKeys = map[string]string{"missing.name": "hw.name"}
		}, errContains: "not present in path"},
		{name: "ambiguous repeated path key element", mutate: func(mapping *GNMIMetricMappingConfig) {
			mapping.Path = "components/component/children/component/state/temperature/instant"
		}, errContains: "occurs more than once"},
		{name: "duplicate path key attribute", mutate: func(mapping *GNMIMetricMappingConfig) {
			mapping.PathKeys = map[string]string{"component.name": "hw.name", "components.name": "hw.name"}
		}, errContains: "more than one selector"},
		{name: "malformed mapped path", mutate: func(mapping *GNMIMetricMappingConfig) {
			mapping.Path = "components/component[name=x/state/value"
		}, errContains: "path is invalid"},
		{name: "configured path key omitted from attributes", mutate: func(mapping *GNMIMetricMappingConfig) {
			mapping.Path = "components/component[name=x][serial=y]/state/temperature/instant"
		}, errContains: "must map configured path selector"},
	}

	t.Run("colliding output series", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.GNMI.Targets[0].MaxStreams = 6
		first := validCustomGNMISubscription()
		second := validCustomGNMISubscription()
		second.Name = "custom-temperature-backup"
		second.Mappings[0].Path = "components/component/state/temperature/backup"
		cfg.GNMI.Targets[0].CustomSubscriptions = []GNMICustomSubscriptionConfig{first, second}
		require.ErrorContains(t, cfg.validateGNMI(), "can collide")
	})
	for _, tt := range mappingTests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validGNMITestConfig()
			subscription := validCustomGNMISubscription()
			tt.mutate(&subscription.Mappings[0])
			cfg.GNMI.Targets[0].CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
			require.ErrorContains(t, cfg.validateGNMI(), tt.errContains)
		})
	}

	for _, mode := range []string{gnmiModeOnce, gnmiModePoll} {
		t.Run("ios xe rejects "+mode, func(t *testing.T) {
			cfg := validGNMITestConfig()
			cfg.GNMI.Targets[0].Platform = gnmiPlatformIOSXE
			subscription := validCustomGNMISubscription()
			subscription.Mode = mode
			cfg.GNMI.Targets[0].CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
			require.ErrorContains(t, cfg.validateGNMI(), "not supported on ios_xe")
		})
	}
}

func TestGNMIPathIncludesOriginIgnoresColonInListKeyValue(t *testing.T) {
	assert.False(t, gnmiPathIncludesOrigin("neighbors/neighbor[address=2001:db8::1]/state/value", "openconfig-bgp"))
	assert.True(t, gnmiPathIncludesOrigin("openconfig-bgp:neighbors/neighbor/state/value", "openconfig-bgp"))
	assert.False(t, gnmiPathIncludesOrigin("openconfig-bgp:neighbors/neighbor/state/value", ""))
}

func TestGNMIRejectsConflictingMetricContracts(t *testing.T) {
	t.Run("custom conflicts with built-in aggregation", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.GNMI.Targets[0].MaxStreams = 5
		subscription := validCustomGNMISubscription()
		subscription.Mappings[0].MetricName = "system.network.io"
		subscription.Mappings[0].Description = "The number of bytes transmitted and received"
		subscription.Mappings[0].Unit = "By"
		subscription.Mappings[0].GaugeType = "int"
		cfg.GNMI.Targets[0].CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
		require.ErrorContains(t, cfg.validateGNMI(), "conflicts with the established contract")
	})

	t.Run("custom conflicts across targets", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.GNMI.Targets[0].MaxStreams = 5
		first := validCustomGNMISubscription()
		cfg.GNMI.Targets[0].CustomSubscriptions = []GNMICustomSubscriptionConfig{first}
		secondTarget := cfg.GNMI.Targets[0]
		secondTarget.Name = "edge-2"
		secondTarget.Endpoint = "edge-2.example.test:57400"
		secondTarget.CustomSubscriptions = []GNMICustomSubscriptionConfig{validCustomGNMISubscription()}
		secondTarget.CustomSubscriptions[0].Mappings[0].Description = "A conflicting description"
		cfg.GNMI.Targets = append(cfg.GNMI.Targets, secondTarget)
		require.ErrorContains(t, cfg.validateGNMI(), "conflicts with the established contract")
	})
}

func TestGNMIStreamCaps(t *testing.T) {
	cfg := validGNMITestConfig()
	cfg.GNMI.Targets[0].MaxStreams = 2
	require.ErrorContains(t, cfg.validateGNMI(), "exceeding max_streams 2")

	cfg.GNMI.Targets[0].MaxStreams = 8
	cfg.GNMI.Targets[0].Profiles.Optics.Enabled = boolPtr(true)
	require.NoError(t, cfg.validateGNMI())

	cfg.GNMI.Targets[0].MaxStreams = 9
	require.ErrorContains(t, cfg.validateGNMI(), "max_streams must be between 1 and 8")

	cfg = validGNMITestConfig()
	cfg.GNMI.Targets[0].MaxRecvMsgSizeMiB = 16
	require.NoError(t, cfg.validateGNMI())
	cfg.GNMI.Targets[0].MaxRecvMsgSizeMiB = 17
	require.ErrorContains(t, cfg.validateGNMI(), "max_recv_msg_size_mib must not exceed 16")
}

func TestGNMIHardResourceLimits(t *testing.T) {
	cfg := validGNMITestConfig()
	cfg.GNMI.MaxDatapointsPerChunk = gnmiMaxDatapointsPerChunk
	cfg.GNMI.MaxCachedSeries = gnmiMaximumCachedSeries
	require.NoError(t, cfg.validateGNMI())

	cfg.GNMI.MaxDatapointsPerChunk++
	require.ErrorContains(t, cfg.validateGNMI(), "max_datapoints_per_chunk must not exceed 10000")
	cfg.GNMI.MaxDatapointsPerChunk = gnmiMaxDatapointsPerChunk
	cfg.GNMI.MaxCachedSeries++
	require.ErrorContains(t, cfg.validateGNMI(), "max_cached_series must not exceed 500000")
}

func TestGNMIReceiverWideTargetAndFrameLimits(t *testing.T) {
	buildTargets := func(count, recvMiB, streams int) []GNMITargetConfig {
		base := validGNMITestConfig().GNMI.Targets[0]
		targets := make([]GNMITargetConfig, 0, count)
		for index := range count {
			target := base
			target.Name = fmt.Sprintf("edge-%d", index)
			target.Endpoint = fmt.Sprintf("edge-%d.example.test:57400", index)
			target.MaxRecvMsgSizeMiB = recvMiB
			target.MaxStreams = streams
			targets = append(targets, target)
		}
		return targets
	}

	cfg := validGNMITestConfig()
	cfg.GNMI.Targets = buildTargets(8, 16, 4)
	require.NoError(t, cfg.validateGNMI(), "eight default-sized targets exactly fit the aggregate frame limit")
	cfg.GNMI.Targets = buildTargets(9, 16, 4)
	require.ErrorContains(t, cfg.validateGNMI(), "exceeding the 512 MiB receiver-wide limit")
	cfg.DeviceSelection.Include.HostNames = []string{"edge-0"}
	require.NoError(t, cfg.validateGNMI(), "receiver-wide frame accounting must include only selected targets")

	cfg = validGNMITestConfig()
	cfg.GNMI.Targets = buildTargets(gnmiMaximumTargets+1, 1, 1)
	require.ErrorContains(t, cfg.validateGNMI(), "must contain at most 256 targets in total")
}

func TestGNMIUCUMValidation(t *testing.T) {
	for _, unit := range []string{"1", "%", "Cel", "mA", "dB[mW]", "ps/nm", "bit/s", "{packet}/s", "m^2"} {
		assert.True(t, validGNMIUCUMUnit(unit), unit)
	}
	for _, unit := range []string{"", " bananas", "bananas", "dB[", "m//s", "m/", "m^nope"} {
		assert.False(t, validGNMIUCUMUnit(unit), unit)
	}
}
