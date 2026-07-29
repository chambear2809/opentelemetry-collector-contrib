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
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/confmaptest"
)

func boolPtr(value bool) *bool { return &value }

func validGNMITestConfig() *Config {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.GNMI.Targets = []GNMITargetConfig{{
		Name:            "edge-1",
		Endpoint:        "edge-1.example.test:57400",
		Product:         gnmiProductASR9000,
		SoftwareVersion: "24.4.1",
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
	assert.False(t, target.TLS.InsecureSkipVerify)
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

func TestGNMIProfileDefaultsComeFromSelectedContractCatalog(t *testing.T) {
	for _, test := range []struct{ product, version string }{
		{gnmiProductCatalyst9300, "17.18.1"},
		{gnmiProductCatalyst9500, "17.18.1"},
		{gnmiProductCatalyst9800, "17.18.1"},
		{gnmiProductASR9000, "24.4.1"},
		{gnmiProductNCS5500, "24.4.1"},
		{gnmiProductNexus9000, "10.6(1)"},
		{gnmiProductNexus3500, "10.5(1)"},
	} {
		t.Run(test.product, func(t *testing.T) {
			target := (GNMITargetConfig{Product: test.product, SoftwareVersion: test.version}).withDefaults()
			contract, _, err := resolveGNMIProductContract(test.product, test.version)
			require.NoError(t, err)
			for _, definition := range builtinGNMIProfiles(contract) {
				profile := sharedGNMIProfileConfig(target.Profiles, definition.Name)
				assert.Equal(t, definition.DefaultEnabled, boolValue(profile.Enabled, false), definition.Name)
				assert.Equal(t, definition.DefaultInterval, profile.SampleInterval, definition.Name)
			}
			if test.product != gnmiProductCatalyst9800 {
				assert.False(t, boolValue(target.Profiles.Catalyst9800Wireless.Enabled, true))
			}
		})
	}
}

func TestGNMIUnsupportedProductProfileFailsClosed(t *testing.T) {
	for _, mutate := range []func(*GNMIProfileConfig){
		func(profile *GNMIProfileConfig) { profile.Enabled = boolPtr(true) },
		func(profile *GNMIProfileConfig) { profile.Required = true },
		func(profile *GNMIProfileConfig) { profile.SampleInterval = time.Minute },
		func(profile *GNMIProfileConfig) { profile.EncodingPreference = []string{"json"} },
		func(profile *GNMIProfileConfig) {
			profile.PathOverrides = map[string]GNMIPathOptionsConfig{"system.cpu": {}}
		},
	} {
		cfg := validGNMITestConfig()
		target := &cfg.GNMI.Targets[0]
		target.Product = gnmiProductNexus9000
		target.SoftwareVersion = "10.6(1)F"
		mutate(&target.Profiles.System)
		require.ErrorContains(t, cfg.Validate(), `profiles.system is not supported on product "nexus_9000" release train 10.6`)
	}

	cfg := validGNMITestConfig()
	target := &cfg.GNMI.Targets[0]
	target.Product = gnmiProductNexus9000
	target.SoftwareVersion = "10.6(1)F"
	target.Profiles.System.Enabled = boolPtr(false)
	require.NoError(t, cfg.Validate(), "an explicitly disabled unsupported profile is a valid migration aid")
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
	assert.Equal(t, gnmiProductNexus9000, target.Product)
	assert.Equal(t, "10.6(1)", target.SoftwareVersion)
	assert.Empty(t, target.Platform)
	assert.Equal(t, configopaque.String("secret"), target.Credentials.Password)
	assert.Equal(t, time.Hour, target.TLS.ReloadInterval)
	require.NotNil(t, target.Keepalive.PermitWithoutStream)
	assert.False(t, *target.Keepalive.PermitWithoutStream)
	assert.True(t, boolValue(target.Profiles.Optics.Enabled, false))
	assert.True(t, target.Profiles.Optics.Required)
}

func TestGNMIParityConfigUnmarshalPreservesPointerPresence(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	require.NoError(t, cfg.Unmarshal(confmap.NewFromStringMap(map[string]any{
		"gnmi": map[string]any{
			"targets": []any{map[string]any{
				"name":                "edge-1",
				"encoding_preference": []any{"proto", "json_ietf"},
				"profiles": map[string]any{
					"system": map[string]any{
						"qos_marking":     0,
						"gnmi_extensions": map[string]any{"depth": 4},
						"path_overrides": map[string]any{
							"system.cpu": map[string]any{
								"stream_mode":        "sample",
								"sample_interval":    "0s",
								"suppress_redundant": false,
							},
						},
					},
				},
			}},
		},
	})))
	target := cfg.GNMI.Targets[0]
	assert.Equal(t, []string{"proto", "json_ietf"}, target.EncodingPreference)
	require.NotNil(t, target.Profiles.System.QoSMarking)
	assert.Zero(t, *target.Profiles.System.QoSMarking)
	require.NotNil(t, target.Profiles.System.GNMIExtensions.Depth)
	assert.Equal(t, uint32(4), *target.Profiles.System.GNMIExtensions.Depth)
	override := target.Profiles.System.PathOverrides["system.cpu"]
	require.NotNil(t, override.SampleInterval)
	assert.Zero(t, *override.SampleInterval)
	require.NotNil(t, override.SuppressRedundant)
	assert.False(t, *override.SuppressRedundant)
}

func TestGNMIProductReleaseValidation(t *testing.T) {
	accepted := []struct {
		product, version string
	}{
		{gnmiProductCatalyst9300, "17.18.1"},
		{gnmiProductCatalyst9500, "17.18.01"},
		{gnmiProductCatalyst9800, "17.18.01a"},
		{gnmiProductASR9000, "24.4.2"},
		{gnmiProductNCS5500, "24.4.3"},
		{gnmiProductNexus9000, "10.6(2)F"},
		{gnmiProductNexus3500, "10.5(3)M"},
	}
	for _, test := range accepted {
		t.Run(test.product, func(t *testing.T) {
			cfg := validGNMITestConfig()
			cfg.GNMI.Targets[0].Product = test.product
			cfg.GNMI.Targets[0].SoftwareVersion = test.version
			cfg.GNMI.Targets[0].AllowUnqualified = test.product == gnmiProductCatalyst9300 ||
				test.product == gnmiProductCatalyst9500
			require.NoError(t, cfg.validateGNMI())
		})
	}

	tests := []struct {
		name   string
		mutate func(*GNMITargetConfig)
		want   string
	}{
		{name: "platform migration field", mutate: func(target *GNMITargetConfig) { target.Platform = gnmiPlatformIOSXR }, want: "platform is no longer supported"},
		{name: "platform only", mutate: func(target *GNMITargetConfig) {
			target.Platform = gnmiPlatformIOSXR
			target.Product = ""
			target.SoftwareVersion = ""
		}, want: "replace it with a canonical product and exact software_version"},
		{name: "wrong train", mutate: func(target *GNMITargetConfig) { target.SoftwareVersion = "25.1.1" }, want: "requires release train 24.4"},
		{name: "exact product spelling", mutate: func(target *GNMITargetConfig) { target.Product = "ASR_9000" }, want: "product must be one of"},
		{name: "SONiC is unsupported", mutate: func(target *GNMITargetConfig) {
			target.Product = "sonic"
		}, want: "SONiC"},
		{name: "Cisco SONiC alias is unsupported", mutate: func(target *GNMITargetConfig) {
			target.Product = "cisco_sonic"
		}, want: "SONiC"},
		{name: "missing canonical release", mutate: func(target *GNMITargetConfig) { target.SoftwareVersion = "" }, want: "expected canonical public release"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validGNMITestConfig()
			test.mutate(&cfg.GNMI.Targets[0])
			require.ErrorContains(t, cfg.validateGNMI(), test.want)
		})
	}
}

func TestGNMIProductContractsRejectPathTarget(t *testing.T) {
	tests := []struct {
		product, version string
	}{
		{gnmiProductCatalyst9300, "17.18.1"},
		{gnmiProductCatalyst9500, "17.18.1"},
		{gnmiProductCatalyst9800, "17.18.1"},
		{gnmiProductASR9000, "24.4.1"},
		{gnmiProductNCS5500, "24.4.1"},
		{gnmiProductNexus9000, "10.6(1)"},
		{gnmiProductNexus3500, "10.5(1)"},
	}
	for _, test := range tests {
		t.Run(test.product, func(t *testing.T) {
			cfg := validGNMITestConfig()
			target := &cfg.GNMI.Targets[0]
			target.Product = test.product
			target.SoftwareVersion = test.version
			target.MaxStreams = 5
			subscription := validCustomGNMISubscription()
			subscription.PathTarget = "proxy-target"
			target.CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
			require.ErrorContains(t, cfg.validateGNMI(), "path_target is not supported by a built-in Cisco product contract")
		})
	}
}

func TestGNMINexusProductsUseProtocolValidatedOptions(t *testing.T) {
	tests := []struct {
		product, version string
	}{
		{gnmiProductNexus9000, "10.6(1)"},
		{gnmiProductNexus3500, "10.5(1)"},
	}
	for _, test := range tests {
		t.Run(test.product+" rejects json_ietf", func(t *testing.T) {
			cfg := validGNMITestConfig()
			cfg.GNMI.Targets[0].Product = test.product
			cfg.GNMI.Targets[0].SoftwareVersion = test.version
			cfg.GNMI.Targets[0].EncodingPreference = []string{"json_ietf"}
			require.ErrorContains(t, cfg.validateGNMI(), "not approved")
		})

		t.Run(test.product+" rejects optional list flags", func(t *testing.T) {
			cfg := validGNMITestConfig()
			target := &cfg.GNMI.Targets[0]
			target.Product = test.product
			target.SoftwareVersion = test.version
			target.MaxStreams = 5
			subscription := validCustomGNMISubscription()
			subscription.UpdatesOnly = true
			target.CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
			require.ErrorContains(t, cfg.validateGNMI(), "updates_only must be false")
		})

		t.Run(test.product+" rejects on_change", func(t *testing.T) {
			cfg := validGNMITestConfig()
			target := &cfg.GNMI.Targets[0]
			target.Product = test.product
			target.SoftwareVersion = test.version
			target.MaxStreams = 5
			subscription := validCustomGNMISubscription()
			subscription.Paths = []GNMISubscriptionPathConfig{{
				Path: "components/component/state",
				GNMIPathOptionsConfig: GNMIPathOptionsConfig{
					StreamMode: gnmiStreamModeOnChange,
				},
			}}
			target.CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
			require.ErrorContains(t, cfg.validateGNMI(), "stream_mode must be sample")
		})

		t.Run(test.product+" rejects out-of-range sample interval", func(t *testing.T) {
			cfg := validGNMITestConfig()
			target := &cfg.GNMI.Targets[0]
			target.Product = test.product
			target.SoftwareVersion = test.version
			target.MaxStreams = 5
			subscription := validCustomGNMISubscription()
			subscription.SampleInterval = 500 * time.Millisecond
			target.CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
			require.ErrorContains(t, cfg.validateGNMI(), "between 1s and 604800s")
		})

		t.Run(test.product+" rejects mixed path sample intervals", func(t *testing.T) {
			cfg := validGNMITestConfig()
			target := &cfg.GNMI.Targets[0]
			target.Product = test.product
			target.SoftwareVersion = test.version
			target.MaxStreams = 5
			subscription := validCustomGNMISubscription()
			fifteenSeconds := 15 * time.Second
			subscription.Paths = []GNMISubscriptionPathConfig{
				{Path: "components/component/state/temperature"},
				{Path: "components/component/state/cpu", GNMIPathOptionsConfig: GNMIPathOptionsConfig{SampleInterval: &fifteenSeconds}},
			}
			target.CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
			require.ErrorContains(t, cfg.validateGNMI(), "one common sample_interval")
		})
	}
}

func TestGNMICatalystSwitchProductsUseConservativeContractPolicy(t *testing.T) {
	for _, product := range []string{gnmiProductCatalyst9300, gnmiProductCatalyst9500} {
		newConfig := func() *Config {
			cfg := validGNMITestConfig()
			target := &cfg.GNMI.Targets[0]
			target.Product = product
			target.SoftwareVersion = "17.18.1"
			target.AllowUnqualified = true
			target.EncodingPreference = []string{"json_ietf"}
			return cfg
		}

		t.Run(product+" accepts contract defaults", func(t *testing.T) {
			require.NoError(t, newConfig().validateGNMI())
		})

		t.Run(product+" requires explicit unqualified acknowledgement", func(t *testing.T) {
			cfg := newConfig()
			cfg.GNMI.Targets[0].AllowUnqualified = false
			require.ErrorContains(t, cfg.validateGNMI(), "allow_unqualified must be true")
		})

		t.Run(product+" rejects other release trains", func(t *testing.T) {
			cfg := newConfig()
			cfg.GNMI.Targets[0].SoftwareVersion = "17.17.1"
			require.ErrorContains(t, cfg.validateGNMI(), "requires release train 17.18")
		})

		t.Run(product+" rejects unreviewed releases in the accepted train", func(t *testing.T) {
			cfg := newConfig()
			cfg.GNMI.Targets[0].SoftwareVersion = "17.18.2"
			require.ErrorContains(t, cfg.validateGNMI(), "permits only reviewed release(s): 17.18.1")
		})

		for _, encoding := range []string{"json", "proto"} {
			t.Run(product+" rejects "+encoding, func(t *testing.T) {
				cfg := newConfig()
				cfg.GNMI.Targets[0].EncodingPreference = []string{encoding}
				require.ErrorContains(t, cfg.validateGNMI(), "not approved for product "+product)
			})
		}

		listOptions := []struct {
			name   string
			mutate func(*GNMIProfileConfig)
			want   string
		}{
			{name: "updates_only", mutate: func(profile *GNMIProfileConfig) { profile.UpdatesOnly = true }, want: "updates_only must be false"},
			{name: "aggregation", mutate: func(profile *GNMIProfileConfig) { profile.AllowAggregation = true }, want: "allow_aggregation must be false"},
			{name: "qos", mutate: func(profile *GNMIProfileConfig) {
				value := uint32(0)
				profile.QoSMarking = &value
			}, want: "qos_marking is not qualified"},
			{name: "extension", mutate: func(profile *GNMIProfileConfig) {
				value := uint32(1)
				profile.GNMIExtensions.Depth = &value
			}, want: "gnmi_extensions.depth is not qualified"},
		}
		for _, option := range listOptions {
			t.Run(product+" rejects "+option.name, func(t *testing.T) {
				cfg := newConfig()
				option.mutate(&cfg.GNMI.Targets[0].Profiles.Interfaces)
				require.ErrorContains(t, cfg.validateGNMI(), option.want)
			})
		}

		heartbeat := time.Minute
		pathOptions := []struct {
			name    string
			options GNMIPathOptionsConfig
			want    string
		}{
			{name: "on_change", options: GNMIPathOptionsConfig{StreamMode: gnmiStreamModeOnChange}, want: "stream_mode must be sample"},
			{name: "target_defined", options: GNMIPathOptionsConfig{StreamMode: gnmiStreamModeTargetDefined}, want: "stream_mode must be sample"},
			{name: "heartbeat", options: GNMIPathOptionsConfig{HeartbeatInterval: &heartbeat}, want: "optional subscription flags are not qualified"},
			{name: "suppress_redundant", options: GNMIPathOptionsConfig{SuppressRedundant: boolPtr(false)}, want: "optional subscription flags are not qualified"},
		}
		for _, option := range pathOptions {
			t.Run(product+" rejects "+option.name, func(t *testing.T) {
				cfg := newConfig()
				cfg.GNMI.Targets[0].Profiles.Interfaces.PathOverrides = map[string]GNMIPathOptionsConfig{
					"interfaces.openconfig": option.options,
				}
				require.ErrorContains(t, cfg.validateGNMI(), option.want)
			})
		}

		t.Run(product+" rejects sub-second SAMPLE", func(t *testing.T) {
			cfg := newConfig()
			cfg.GNMI.Targets[0].Profiles.Interfaces.SampleInterval = 500 * time.Millisecond
			require.ErrorContains(t, cfg.validateGNMI(), "between 1s and 604800s")
		})

		t.Run(product+" rejects mixed SAMPLE cadence", func(t *testing.T) {
			cfg := newConfig()
			interval := 30 * time.Second
			cfg.GNMI.Targets[0].Profiles.System.PathOverrides = map[string]GNMIPathOptionsConfig{
				"system.cpu": {SampleInterval: &interval},
			}
			require.ErrorContains(t, cfg.validateGNMI(), "one common sample_interval")
		})

		t.Run(product+" rejects wildcard selectors", func(t *testing.T) {
			cfg := newConfig()
			subscription := validCustomGNMISubscription()
			subscription.Mappings[0].Path = "components/component[name=*]/state/temperature/instant"
			cfg.GNMI.Targets[0].CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
			require.ErrorContains(t, cfg.validateGNMI(), "explicit asterisk wildcard")
		})
	}

	cfg := validGNMITestConfig()
	cfg.GNMI.Targets[0].AllowUnqualified = true
	require.ErrorContains(t, cfg.validateGNMI(), "valid only when the selected product contract requires explicit acknowledgement")
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
		{name: "lab self-signed certificate", mutate: func(tls *GNMITLSConfig) { tls.InsecureSkipVerify = true }},
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

func TestCanonicalGNMIDialInEndpoint(t *testing.T) {
	valid := map[string]string{
		"EDGE-1.Example.Test.:057400": "edge-1.example.test:57400",
		"192.0.2.1:57400":             "192.0.2.1:57400",
		"[2001:0DB8::1]:57400":        "[2001:db8::1]:57400",
		"[::ffff:192.0.2.1]:57400":    "192.0.2.1:57400",
	}
	for endpoint, expected := range valid {
		t.Run(endpoint, func(t *testing.T) {
			actual, err := canonicalGNMIDialInEndpoint(endpoint)
			require.NoError(t, err)
			assert.Equal(t, expected, actual)
		})
	}

	for _, endpoint := range []string{
		"", " edge.example.test:57400", "edge.example.test:57400 ",
		":57400", "edge.example.test:", "edge.example.test:http", "edge.example.test:+57400",
		"edge.example.test:0", "edge.example.test:65536", "0.0.0.0:57400", "[::]:57400",
		"[::ffff:0.0.0.0]:57400",
		"127.1:57400", "2130706433:57400", "0177.0.0.1:57400", "0x7f000001:57400", "0x7f.0.0.1:57400",
		"[fe80::1%en0]:57400", "[fe80::1%en\v0]:57400",
		"bad_name.example.test:57400", "-edge.example.test:57400", "edge..example.test:57400",
	} {
		t.Run("reject "+endpoint, func(t *testing.T) {
			_, err := canonicalGNMIDialInEndpoint(endpoint)
			require.Error(t, err)
		})
	}
}

func TestGNMIDialInEndpointOwnershipUsesCanonicalAddressesAcrossAllSurfaces(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.GNMI.Targets = []GNMITargetConfig{
		{Name: "first", Endpoint: "EDGE.EXAMPLE.TEST.:057400"},
		{Name: "second", Endpoint: "edge.example.test:57400"},
	}
	err := cfg.validateGNMIDialInEndpointOwnership()
	require.ErrorContains(t, err, "gnmi.targets[1].endpoint duplicates gnmi.targets[0].endpoint")

	cfg.GNMI.Targets = []GNMITargetConfig{{Name: "shared", Endpoint: "[::ffff:192.0.2.1]:57400"}}
	cfg.IOSXR.DialIn.Targets = []IOSXRTargetConfig{{
		ClientConfig: configgrpc.ClientConfig{Endpoint: "192.0.2.1:57400"},
	}}
	err = cfg.validateGNMIDialInEndpointOwnership()
	require.ErrorContains(t, err, "legacy ios_xr dial_in")

	cfg.GNMI.Targets = nil
	cfg.IOSXR.DialIn.Targets = []IOSXRTargetConfig{{
		ClientConfig: configgrpc.ClientConfig{Endpoint: "[2001:db8::1]:57400"},
	}}
	cfg.Catalyst9800.DialIn.Targets = []Catalyst9800TargetConfig{{
		ClientConfig: configgrpc.ClientConfig{Endpoint: "[2001:0db8:0:0::1]:57400"},
	}}
	err = cfg.validateGNMIDialInEndpointOwnership()
	require.ErrorContains(t, err, "catalyst_9800.dial_in.targets[0].endpoint duplicates ios_xr.dial_in.targets[0].endpoint")
}

func TestGNMIProfileValidation(t *testing.T) {
	t.Run("wireless supported on catalyst 9800", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.GNMI.Targets[0].Product = gnmiProductCatalyst9800
		cfg.GNMI.Targets[0].SoftwareVersion = "17.18.1"
		cfg.GNMI.Targets[0].Profiles.Catalyst9800Wireless.Enabled = boolPtr(true)
		require.NoError(t, cfg.validateGNMI())
	})
	t.Run("wireless rejected elsewhere", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.GNMI.Targets[0].Profiles.Catalyst9800Wireless.Enabled = boolPtr(true)
		require.ErrorContains(t, cfg.validateGNMI(), "supported only on product catalyst_9800")
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
		{name: "root catalog collision", mutate: func(mapping *GNMIMetricMappingConfig) {
			mapping.MetricName = "cisco.iosxr.receiver.updates"
		}, errContains: "reserved by a fixed Cisco OS receiver metric catalog"},
		{name: "system scraper catalog collision", mutate: func(mapping *GNMIMetricMappingConfig) {
			mapping.MetricName = "cisco.control_plane.cpu.process.utilization"
		}, errContains: "reserved by a fixed Cisco OS receiver metric catalog"},
		{name: "interfaces scraper catalog collision", mutate: func(mapping *GNMIMetricMappingConfig) {
			mapping.MetricName = "cisco.lacp.errors"
		}, errContains: "reserved by a fixed Cisco OS receiver metric catalog"},
		{name: "model-defined YANG collision", mutate: func(mapping *GNMIMetricMappingConfig) {
			mapping.MetricName = "cisco.iosxr.yang" + ".reserved"
		}, errContains: "reserved by IOS XR model-defined YANG metrics"},
		{name: "IOS XR model-defined YANG root collision", mutate: func(mapping *GNMIMetricMappingConfig) {
			mapping.MetricName = "cisco.iosxr.yang"
		}, errContains: "reserved by IOS XR model-defined YANG metrics"},
		{name: "Catalyst model-defined YANG collision", mutate: func(mapping *GNMIMetricMappingConfig) {
			mapping.MetricName = "cisco.catalyst9800.yang" + ".reserved"
		}, errContains: "reserved by Catalyst 9800 model-defined YANG metrics"},
		{name: "Catalyst model-defined YANG root collision", mutate: func(mapping *GNMIMetricMappingConfig) {
			mapping.MetricName = "cisco.catalyst9800.yang"
		}, errContains: "reserved by Catalyst 9800 model-defined YANG metrics"},
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
		}, errContains: "namespace form required"},
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

	for _, product := range []string{gnmiProductASR9000, gnmiProductNCS5500} {
		for _, mode := range []string{gnmiModeOnce, gnmiModePoll} {
			t.Run(product+" accepts protocol "+mode, func(t *testing.T) {
				cfg := validGNMITestConfig()
				cfg.GNMI.Targets[0].Product = product
				cfg.GNMI.Targets[0].SoftwareVersion = map[string]string{
					gnmiProductASR9000: "24.4.1",
					gnmiProductNCS5500: "24.4.1",
				}[product]
				cfg.GNMI.Targets[0].MaxStreams = 5
				subscription := validCustomGNMISubscription()
				subscription.Mode = mode
				if mode == gnmiModePoll {
					subscription.PollInterval = time.Minute
				}
				cfg.GNMI.Targets[0].CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
				require.NoError(t, cfg.validateGNMI())
			})
		}
	}

	for _, test := range []struct {
		product, version, want string
	}{
		{gnmiProductCatalyst9300, "17.18.1", "SAMPLE STREAM subscriptions"},
		{gnmiProductCatalyst9500, "17.18.1", "SAMPLE STREAM subscriptions"},
		{gnmiProductCatalyst9800, "17.18.1", "mode must be stream"},
		{gnmiProductNexus9000, "10.6(1)", "SAMPLE STREAM subscriptions"},
		{gnmiProductNexus3500, "10.5(1)", "SAMPLE STREAM subscriptions"},
	} {
		for _, mode := range []string{gnmiModeOnce, gnmiModePoll} {
			t.Run(test.product+" rejects protocol "+mode, func(t *testing.T) {
				cfg := validGNMITestConfig()
				cfg.GNMI.Targets[0].Product = test.product
				cfg.GNMI.Targets[0].SoftwareVersion = test.version
				subscription := validCustomGNMISubscription()
				subscription.Mode = mode
				if mode == gnmiModePoll {
					subscription.PollInterval = time.Minute
				}
				cfg.GNMI.Targets[0].CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
				require.ErrorContains(t, cfg.validateGNMI(), test.want)
			})
		}
	}

	t.Run("nexus rejects wildcard path", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.GNMI.Targets[0].Product = gnmiProductNexus9000
		cfg.GNMI.Targets[0].SoftwareVersion = "10.6(1)"
		cfg.GNMI.Targets[0].MaxStreams = 5
		subscription := validCustomGNMISubscription()
		subscription.Mappings[0].Path = "components/component[name=*]/state/temperature/instant"
		cfg.GNMI.Targets[0].CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
		require.ErrorContains(t, cfg.validateGNMI(), "explicit asterisk wildcard")
	})

	t.Run("qualified RFC7951 custom path contributes its model", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.GNMI.Targets[0].Product = gnmiProductCatalyst9800
		cfg.GNMI.Targets[0].SoftwareVersion = "17.18.1"
		cfg.GNMI.Targets[0].MaxStreams = 5
		subscription := validCustomGNMISubscription()
		subscription.Origin = builtinGNMIOriginRFC7951
		subscription.Mappings[0].Path = "example-custom-model:components/component/state/temperature/instant"
		cfg.GNMI.Targets[0].CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
		require.NoError(t, cfg.validateGNMI())

		contract, _, err := gnmiProductContractForTarget(cfg.GNMI.Targets[0])
		require.NoError(t, err)
		streams, err := buildSharedGNMIStreams(cfg.GNMI.Targets[0])
		require.NoError(t, err)
		assert.Contains(t, requiredGNMIModels(contract, streams), "example-custom-model")
	})

	for _, product := range []string{gnmiProductCatalyst9300, gnmiProductCatalyst9500} {
		t.Run(product+" rejects custom models outside pinned catalog", func(t *testing.T) {
			cfg := validGNMITestConfig()
			target := &cfg.GNMI.Targets[0]
			target.Product = product
			target.SoftwareVersion = "17.18.1"
			target.AllowUnqualified = true
			target.MaxStreams = 5
			subscription := validCustomGNMISubscription()
			subscription.Origin = builtinGNMIOriginRFC7951
			subscription.Mappings[0].Path = "example-custom-model:components/component/state/temperature/instant"
			target.CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}

			require.ErrorContains(t, cfg.validateGNMI(), "outside product")
			require.ErrorContains(t, cfg.validateGNMI(), "example-custom-model")
		})
	}
}

func TestGNMINXOpenConfigCustomSubscriptionRequiresConcreteModels(t *testing.T) {
	valid := func(product, version string) *Config {
		cfg := validGNMITestConfig()
		target := &cfg.GNMI.Targets[0]
		target.Product = product
		target.SoftwareVersion = version
		target.MaxStreams = 5
		subscription := validCustomGNMISubscription()
		subscription.Origin = builtinGNMIOriginOpenConfig
		subscription.Models = []string{"openconfig-platform"}
		target.CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
		return cfg
	}

	for _, test := range []struct {
		product, version string
	}{
		{product: gnmiProductNexus9000, version: "10.6(1)"},
		{product: gnmiProductNexus3500, version: "10.5(1)"},
	} {
		t.Run(test.product+" accepts generic wire origin with concrete model", func(t *testing.T) {
			cfg := valid(test.product, test.version)
			require.NoError(t, cfg.validateGNMI())
			contract, _, err := gnmiProductContractForTarget(cfg.GNMI.Targets[0])
			require.NoError(t, err)
			streams, err := buildSharedGNMIStreams(cfg.GNMI.Targets[0])
			require.NoError(t, err)
			assert.Contains(t, requiredGNMIModels(contract, streams), "openconfig-platform")
			assert.NotContains(t, requiredGNMIModels(contract, streams), builtinGNMIOriginOpenConfig)
		})

		t.Run(test.product+" rejects missing model", func(t *testing.T) {
			cfg := valid(test.product, test.version)
			cfg.GNMI.Targets[0].CustomSubscriptions[0].Models = nil
			require.ErrorContains(t, cfg.validateGNMI(), "models must contain at least one exact Capabilities model name")
		})

		t.Run(test.product+" rejects module name as wire origin", func(t *testing.T) {
			cfg := valid(test.product, test.version)
			cfg.GNMI.Targets[0].CustomSubscriptions[0].Origin = "openconfig-platform"
			require.ErrorContains(t, cfg.validateGNMI(), `origin must be "openconfig" for NX-OS OpenConfig requests`)
		})

		t.Run(test.product+" rejects noncanonical generic wire origin", func(t *testing.T) {
			cfg := valid(test.product, test.version)
			cfg.GNMI.Targets[0].CustomSubscriptions[0].Origin = "OpenConfig"
			require.ErrorContains(t, cfg.validateGNMI(), `origin must use the exact NX-OS OpenConfig origin "openconfig"`)
		})

		t.Run(test.product+" rejects generic origin as model", func(t *testing.T) {
			cfg := valid(test.product, test.version)
			cfg.GNMI.Targets[0].CustomSubscriptions[0].Models = []string{builtinGNMIOriginOpenConfig}
			require.ErrorContains(t, cfg.validateGNMI(), "must identify a concrete model")
		})

		t.Run(test.product+" rejects duplicate concrete models", func(t *testing.T) {
			cfg := valid(test.product, test.version)
			cfg.GNMI.Targets[0].CustomSubscriptions[0].Models = []string{"openconfig-platform", "openconfig-platform"}
			require.ErrorContains(t, cfg.validateGNMI(), "duplicates another required model")
		})

		for _, malformed := range []struct {
			name, model, want string
		}{
			{name: "empty", model: "", want: "valid YANG module identifier"},
			{name: "surrounding whitespace", model: " openconfig-platform", want: "must not contain surrounding whitespace"},
			{name: "invalid identifier", model: "9openconfig-platform", want: "valid YANG module identifier"},
		} {
			t.Run(test.product+" rejects "+malformed.name+" model", func(t *testing.T) {
				cfg := valid(test.product, test.version)
				cfg.GNMI.Targets[0].CustomSubscriptions[0].Models = []string{malformed.model}
				require.ErrorContains(t, cfg.validateGNMI(), malformed.want)
			})
		}

		t.Run(test.product+" enforces production model bound", func(t *testing.T) {
			cfg := valid(test.product, test.version)
			models := make([]string, gnmiMaximumCustomModelsPerSubscription+1)
			for index := range models {
				models[index] = fmt.Sprintf("openconfig-example-%d", index)
			}
			cfg.GNMI.Targets[0].CustomSubscriptions[0].Models = models
			require.ErrorContains(t, cfg.validateGNMI(), "models must contain at most 32 entries")
		})
	}
}

func TestGNMICustomSubscriptionModuleOriginDoesNotRequireExplicitModels(t *testing.T) {
	cfg := validGNMITestConfig()
	cfg.GNMI.Targets[0].MaxStreams = 5
	cfg.GNMI.Targets[0].CustomSubscriptions = []GNMICustomSubscriptionConfig{validCustomGNMISubscription()}
	require.NoError(t, cfg.validateGNMI())
}

func TestGNMIPathIncludesOriginIgnoresColonInListKeyValue(t *testing.T) {
	assert.False(t, gnmiPathIncludesOrigin("neighbors/neighbor[address=2001:db8::1]/state/value", "openconfig-bgp"))
	assert.True(t, gnmiPathIncludesOrigin("openconfig-bgp:neighbors/neighbor/state/value", "openconfig-bgp"))
	assert.False(t, gnmiPathIncludesOrigin("openconfig-bgp:neighbors/neighbor/state/value", ""))
}

func TestGNMIRFC7951NamespaceValidationRejectsMalformedQualifiedNames(t *testing.T) {
	for _, path := range []string{
		":components/component/state/value",
		"module:/component/state/value",
		"a:b:c/component/state/value",
		"1module:components/component/state/value",
		"example:components/1component/state/value",
		"example:components/component[1name=value]/state/value",
	} {
		t.Run(path, func(t *testing.T) {
			assert.False(t, gnmiCustomPathNamespaceValid(path, builtinGNMIOriginRFC7951))
			cfg := validGNMITestConfig()
			target := &cfg.GNMI.Targets[0]
			target.Product = gnmiProductCatalyst9800
			target.SoftwareVersion = "17.18.1"
			target.MaxStreams = 5
			subscription := validCustomGNMISubscription()
			subscription.Origin = builtinGNMIOriginRFC7951
			subscription.Mappings[0].Path = path
			target.CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
			require.ErrorContains(t, cfg.validateGNMI(), "namespace form required")
		})
	}

	assert.False(t, gnmiCustomPathNamespaceValid(
		"interfaces/openconfig-if-ethernet:ethernet/state/value",
		"openconfig-interfaces",
	), "non-RFC7951 origins must not smuggle a qualified descendant module")
	assert.False(t, gnmiCustomPathNamespaceValid("components/component/state/value", "1invalid-origin"))
	assert.False(t, gnmiCustomPathNamespaceValid("components/1component/state/value", "openconfig-platform"))
	assert.False(t, gnmiCustomPathNamespaceValid("components/component[1name=value]/state/value", "openconfig-platform"))
	assert.True(t, gnmiCustomPathNamespaceValid("components/component[name=*]/state/value", "openconfig-platform"))
	assert.True(t, gnmiCustomPathNamespaceValid("sys/intf", builtinGNMIOriginDME))

	cfg := validGNMITestConfig()
	cfg.GNMI.Targets[0].MaxStreams = 5
	subscription := validCustomGNMISubscription()
	subscription.Origin = "1invalid-origin"
	cfg.GNMI.Targets[0].CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
	require.ErrorContains(t, cfg.validateGNMI(), "origin must be a valid YANG identifier")
}

func TestGNMICustomMappingsRejectCanonicalDuplicateSources(t *testing.T) {
	cfg := validGNMITestConfig()
	cfg.GNMI.Targets[0].MaxStreams = 5
	subscription := validCustomGNMISubscription()
	first := subscription.Mappings[0]
	first.Path = "components/component[name=first][slot=one]/state/temperature/instant"
	first.PathKeys = map[string]string{
		"component.name": "hw.name",
		"component.slot": "hw.slot",
	}
	second := first
	second.Path = "components/component[slot=two][name=second]/state/temperature/instant"
	second.MetricName = "cisco.environment.temperature.secondary"
	subscription.Mappings = []GNMIMetricMappingConfig{first, second}
	cfg.GNMI.Targets[0].CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
	require.ErrorContains(t, cfg.validateGNMI(), "same canonical mapping source")
}

func TestGNMIConfigurationShapeBounds(t *testing.T) {
	scale := 1.0
	mapping := GNMIMetricMappingConfig{
		Path: "root/list[name=one]/state/value", MetricName: "example.value",
		Description: "Example value", Unit: "1", Scale: &scale, GaugeType: "double",
		PathKeys: map[string]string{"list.name": "example.name"},
	}
	target := GNMITargetConfig{
		EncodingPreference: []string{"json"},
		Profiles: GNMIProfilesConfig{System: GNMIProfileConfig{
			EncodingPreference: []string{"json"},
			PathOverrides:      map[string]GNMIPathOptionsConfig{"system.cpu": {StreamMode: gnmiStreamModeSample}},
		}},
		CustomSubscriptions: []GNMICustomSubscriptionConfig{{
			Name: "custom", Origin: "example", Mode: gnmiModeStream,
			EncodingPreference: []string{"json"},
			Models:             []string{"example"},
			Paths:              []GNMISubscriptionPathConfig{{Path: "root/list/state"}},
			Mappings:           []GNMIMetricMappingConfig{mapping},
		}},
	}
	limits := gnmiConfigurationShapeLimits{
		customSubscriptionsPerTarget:  2,
		customPathsPerSubscription:    2,
		customMappingsPerSubscription: 2,
		customModelsPerSubscription:   2,
		customMappingAttributes:       2,
		encodingPreferences:           3,
		profilePathOverrides:          2,
		customPaths:                   2,
		customMappings:                2,
		profilePathOverridesTotal:     2,
		customConfigurationBytes:      4 * 1024,
	}
	require.NoError(t, validateGNMIConfigurationShapeWithLimits([]GNMITargetConfig{target}, limits))
	cloneTarget := func() GNMITargetConfig {
		cloned := target
		cloned.EncodingPreference = append([]string(nil), target.EncodingPreference...)
		cloned.Profiles.System.EncodingPreference = append([]string(nil), target.Profiles.System.EncodingPreference...)
		cloned.Profiles.System.PathOverrides = map[string]GNMIPathOptionsConfig{
			"system.cpu": {StreamMode: gnmiStreamModeSample},
		}
		cloned.CustomSubscriptions = append([]GNMICustomSubscriptionConfig(nil), target.CustomSubscriptions...)
		cloned.CustomSubscriptions[0].EncodingPreference = append(
			[]string(nil),
			target.CustomSubscriptions[0].EncodingPreference...,
		)
		cloned.CustomSubscriptions[0].Models = append(
			[]string(nil),
			target.CustomSubscriptions[0].Models...,
		)
		cloned.CustomSubscriptions[0].Paths = append(
			[]GNMISubscriptionPathConfig(nil),
			target.CustomSubscriptions[0].Paths...,
		)
		cloned.CustomSubscriptions[0].Mappings = append(
			[]GNMIMetricMappingConfig(nil),
			target.CustomSubscriptions[0].Mappings...,
		)
		cloned.CustomSubscriptions[0].Mappings[0].PathKeys = map[string]string{"list.name": "example.name"}
		return cloned
	}

	tests := []struct {
		name   string
		mutate func(*[]GNMITargetConfig, *gnmiConfigurationShapeLimits)
		want   string
	}{
		{name: "subscriptions per target", mutate: func(targets *[]GNMITargetConfig, _ *gnmiConfigurationShapeLimits) {
			(*targets)[0].CustomSubscriptions = append((*targets)[0].CustomSubscriptions, GNMICustomSubscriptionConfig{}, GNMICustomSubscriptionConfig{})
		}, want: "custom_subscriptions must contain at most 2"},
		{name: "paths per subscription", mutate: func(targets *[]GNMITargetConfig, _ *gnmiConfigurationShapeLimits) {
			(*targets)[0].CustomSubscriptions[0].Paths = append((*targets)[0].CustomSubscriptions[0].Paths, GNMISubscriptionPathConfig{}, GNMISubscriptionPathConfig{})
		}, want: "paths must contain at most 2"},
		{name: "mappings per subscription", mutate: func(targets *[]GNMITargetConfig, _ *gnmiConfigurationShapeLimits) {
			(*targets)[0].CustomSubscriptions[0].Mappings = append((*targets)[0].CustomSubscriptions[0].Mappings, mapping, mapping)
		}, want: "mappings must contain at most 2"},
		{name: "models per subscription", mutate: func(targets *[]GNMITargetConfig, _ *gnmiConfigurationShapeLimits) {
			(*targets)[0].CustomSubscriptions[0].Models = append((*targets)[0].CustomSubscriptions[0].Models, "example-two", "example-three")
		}, want: "models must contain at most 2"},
		{name: "derived request paths", mutate: func(targets *[]GNMITargetConfig, limits *gnmiConfigurationShapeLimits) {
			limits.customMappingsPerSubscription = 3
			(*targets)[0].CustomSubscriptions[0].Paths = nil
			(*targets)[0].CustomSubscriptions[0].Mappings = []GNMIMetricMappingConfig{mapping, mapping, mapping}
		}, want: "derives 3 request paths"},
		{name: "mapping attributes", mutate: func(targets *[]GNMITargetConfig, _ *gnmiConfigurationShapeLimits) {
			(*targets)[0].CustomSubscriptions[0].Mappings[0].PathKeys = map[string]string{"a.a": "a", "b.b": "b", "c.c": "c"}
		}, want: "path_keys must contain at most 2"},
		{name: "encoding preferences", mutate: func(targets *[]GNMITargetConfig, _ *gnmiConfigurationShapeLimits) {
			(*targets)[0].EncodingPreference = []string{"json", "json_ietf", "proto", "json"}
		}, want: "encoding_preference must contain at most 3"},
		{name: "profile overrides", mutate: func(targets *[]GNMITargetConfig, _ *gnmiConfigurationShapeLimits) {
			(*targets)[0].Profiles.System.PathOverrides["two"] = GNMIPathOptionsConfig{}
			(*targets)[0].Profiles.System.PathOverrides["three"] = GNMIPathOptionsConfig{}
		}, want: "path_overrides must contain at most 2"},
		{name: "receiver paths", mutate: func(targets *[]GNMITargetConfig, limits *gnmiConfigurationShapeLimits) {
			limits.customPaths = 1
			(*targets)[0].CustomSubscriptions[0].Paths = append(
				(*targets)[0].CustomSubscriptions[0].Paths,
				GNMISubscriptionPathConfig{Path: "another/path"},
			)
		}, want: "effective request paths receiver-wide"},
		{name: "receiver mappings", mutate: func(targets *[]GNMITargetConfig, limits *gnmiConfigurationShapeLimits) {
			limits.customMappings = 1
			(*targets)[0].CustomSubscriptions[0].Mappings = append((*targets)[0].CustomSubscriptions[0].Mappings, mapping)
		}, want: "mappings receiver-wide"},
		{name: "receiver overrides", mutate: func(targets *[]GNMITargetConfig, limits *gnmiConfigurationShapeLimits) {
			limits.profilePathOverridesTotal = 1
			(*targets)[0].Profiles.Interfaces.PathOverrides = map[string]GNMIPathOptionsConfig{"interfaces.state": {}}
		}, want: "path overrides must contain at most 1 entries receiver-wide"},
		{name: "configuration bytes", mutate: func(_ *[]GNMITargetConfig, limits *gnmiConfigurationShapeLimits) {
			limits.customConfigurationBytes = 1
		}, want: "plan strings exceed the receiver-wide limit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			targets := []GNMITargetConfig{cloneTarget()}
			configuredLimits := limits
			test.mutate(&targets, &configuredLimits)
			require.ErrorContains(t, validateGNMIConfigurationShapeWithLimits(targets, configuredLimits), test.want)
		})
	}
}

func TestGNMIConfigurationShapeProductionLimits(t *testing.T) {
	assert.Equal(t, 8, gnmiMaximumCustomSubscriptionsPerTarget)
	assert.Equal(t, 256, gnmiMaximumCustomPathsPerSubscription)
	assert.Equal(t, 1_024, gnmiMaximumCustomMappingsPerSubscription)
	assert.Equal(t, 32, gnmiMaximumCustomModelsPerSubscription)
	assert.Equal(t, 64, gnmiMaximumCustomMappingAttributes)
	assert.Equal(t, 64, gnmiMaximumProfilePathOverrides)
	assert.Equal(t, 4_096, gnmiMaximumCustomPaths)
	assert.Equal(t, 16_384, gnmiMaximumCustomMappings)
	assert.Equal(t, 4_096, gnmiMaximumProfilePathOverridesTotal)
	assert.Equal(t, uint64(64*1024*1024), defaultGNMIConfigurationShapeLimits().customConfigurationBytes)
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
	cfg.GNMI.Targets[0].MaxStreams = 1
	require.ErrorContains(t, cfg.validateGNMI(), "exceeding max_streams 1")

	cfg.GNMI.Targets[0].MaxStreams = 2
	require.NoError(t, cfg.validateGNMI())

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
	for _, unit := range []string{"1", "%", "Cel", "mA", "dB{mW}", "ps/nm", "bit/s", "{packet}/s", "m^2"} {
		assert.True(t, validGNMIUCUMUnit(unit), unit)
	}
	for _, unit := range []string{"", " bananas", "bananas", "dB[", "m//s", "m/", "m^nope"} {
		assert.False(t, validGNMIUCUMUnit(unit), unit)
	}
}

func TestGNMIPathOptionValidationMatrix(t *testing.T) {
	zero := time.Duration(0)
	positive := time.Minute
	negative := -time.Second
	valueFalse := false
	tests := []struct {
		name    string
		mode    string
		options GNMIPathOptionsConfig
		wantErr string
	}{
		{name: "sample inherits"},
		{name: "sample fastest", options: GNMIPathOptionsConfig{StreamMode: gnmiStreamModeSample, SampleInterval: &zero}},
		{name: "sample heartbeat suppression", options: GNMIPathOptionsConfig{HeartbeatInterval: &positive, SuppressRedundant: &valueFalse}},
		{name: "sample negative", options: GNMIPathOptionsConfig{SampleInterval: &negative}, wantErr: "must not be negative"},
		{name: "on change", options: GNMIPathOptionsConfig{StreamMode: gnmiStreamModeOnChange, HeartbeatInterval: &positive}},
		{name: "on change sample forbidden", options: GNMIPathOptionsConfig{StreamMode: gnmiStreamModeOnChange, SampleInterval: &zero}, wantErr: "forbidden for on_change"},
		{name: "on change explicit suppression forbidden", options: GNMIPathOptionsConfig{StreamMode: gnmiStreamModeOnChange, SuppressRedundant: &valueFalse}, wantErr: "forbidden for on_change"},
		{name: "target defined", options: GNMIPathOptionsConfig{StreamMode: gnmiStreamModeTargetDefined}},
		{name: "target defined timing forbidden", options: GNMIPathOptionsConfig{StreamMode: gnmiStreamModeTargetDefined, HeartbeatInterval: &positive}, wantErr: "forbidden for target_defined"},
		{name: "once options forbidden", mode: gnmiModeOnce, options: GNMIPathOptionsConfig{StreamMode: gnmiStreamModeSample}, wantErr: "only for stream"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode := tt.mode
			if mode == "" {
				mode = gnmiModeStream
			}
			err := validateGNMIPathOptions("path", mode, tt.options)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}

func TestGNMIParityListAndOverrideValidation(t *testing.T) {
	t.Run("bounds", func(t *testing.T) {
		cfg := validGNMITestConfig()
		qos := uint32(64)
		depth := uint32(0)
		cfg.GNMI.Targets[0].Profiles.System.QoSMarking = &qos
		cfg.GNMI.Targets[0].Profiles.System.GNMIExtensions.Depth = &depth
		err := cfg.validateGNMI()
		require.ErrorContains(t, err, "qos_marking must be between 0 and 63")
		require.ErrorContains(t, err, "depth must be between 1 and 128")
	})

	t.Run("product-approved encoding precedes aggregation options", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.GNMI.Targets[0].EncodingPreference = []string{"proto"}
		cfg.GNMI.Targets[0].Profiles.System.AllowAggregation = true
		require.ErrorContains(t, cfg.validateGNMI(), "not approved for product asr_9000")

		cfg.GNMI.Targets[0].EncodingPreference = []string{"json_ietf"}
		require.NoError(t, cfg.validateGNMI())

		cfg = validGNMITestConfig()
		cfg.GNMI.Targets[0].Profiles.System.EncodingPreference = []string{"proto"}
		require.ErrorContains(t, cfg.validateGNMI(), "not approved for product asr_9000")
	})

	t.Run("unknown built in path ID", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.GNMI.Targets[0].Profiles.System.PathOverrides = map[string]GNMIPathOptionsConfig{
			"system.unknown": {StreamMode: gnmiStreamModeOnChange},
		}
		require.ErrorContains(t, cfg.validateGNMI(), "not a known path ID")
	})

	t.Run("removed unsupported coherent path rejected", func(t *testing.T) {
		cfg := validGNMITestConfig()
		cfg.GNMI.Targets[0].MaxStreams = 8
		cfg.GNMI.Targets[0].Profiles.Optics.Enabled = boolPtr(true)
		cfg.GNMI.Targets[0].Profiles.Optics.PathOverrides = map[string]GNMIPathOptionsConfig{
			"optics.coherent": {StreamMode: gnmiStreamModeOnChange},
		}
		require.ErrorContains(t, cfg.validateGNMI(), "not a known path ID")
	})
}

func TestGNMICustomSubscriptionSelectorValidation(t *testing.T) {
	validConfig := func() *Config {
		cfg := validGNMITestConfig()
		cfg.GNMI.Targets[0].MaxStreams = 5
		subscription := validCustomGNMISubscription()
		subscription.Paths = []GNMISubscriptionPathConfig{{
			Path:                  "components/component/state",
			GNMIPathOptionsConfig: GNMIPathOptionsConfig{StreamMode: gnmiStreamModeOnChange},
		}}
		cfg.GNMI.Targets[0].CustomSubscriptions = []GNMICustomSubscriptionConfig{subscription}
		return cfg
	}

	t.Run("ancestor selector", func(t *testing.T) {
		require.NoError(t, validConfig().validateGNMI())
	})

	t.Run("mapping outside selector", func(t *testing.T) {
		cfg := validConfig()
		cfg.GNMI.Targets[0].CustomSubscriptions[0].Paths[0].Path = "interfaces/interface/state"
		require.ErrorContains(t, cfg.validateGNMI(), "must equal or descend")
	})

	t.Run("selector key must be a subset match", func(t *testing.T) {
		cfg := validConfig()
		cfg.GNMI.Targets[0].CustomSubscriptions[0].Paths[0].Path = "components/component[name=other]/state"
		require.ErrorContains(t, cfg.validateGNMI(), "compatible keys")
	})

	t.Run("overlapping selectors rejected", func(t *testing.T) {
		cfg := validConfig()
		cfg.GNMI.Targets[0].CustomSubscriptions[0].Paths = append(
			cfg.GNMI.Targets[0].CustomSubscriptions[0].Paths,
			GNMISubscriptionPathConfig{Path: "components/component/state/temperature"},
		)
		require.ErrorContains(t, cfg.validateGNMI(), "duplicates or conflicts")
	})

	t.Run("once path options and updates only rejected", func(t *testing.T) {
		cfg := validConfig()
		subscription := &cfg.GNMI.Targets[0].CustomSubscriptions[0]
		subscription.Mode = gnmiModeOnce
		subscription.UpdatesOnly = true
		err := cfg.validateGNMI()
		require.ErrorContains(t, err, "updates_only is supported only for stream")
		require.ErrorContains(t, err, "path options are supported only for stream")
	})
}
