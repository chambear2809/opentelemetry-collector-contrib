// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configopaque"
)

func TestISEConfigValidateValidRESTPxGridAndDataConnect(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.ISE.Enabled = true
	cfg.ISE.Endpoint = "https://ise.example.com"
	cfg.ISE.Auth.Username = "admin"
	cfg.ISE.Auth.Password = configopaque.String("password")
	cfg.ISE.PxGrid.Enabled = true
	cfg.ISE.PxGrid.NodeName = "otel-collector"
	cfg.ISE.PxGrid.Password = configopaque.String("pxgrid-secret")
	cfg.ISE.DataConnect.Enabled = true
	cfg.ISE.DataConnect.Host = "ise.example.com"
	cfg.ISE.DataConnect.ServiceName = "cpm10"
	cfg.ISE.DataConnect.Username = "dataconnect"
	cfg.ISE.DataConnect.Password = configopaque.String("db-secret")

	require.NoError(t, cfg.Validate())
}

func TestISEConfigValidateRequiresRESTCredentials(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.ISE.Enabled = true
	cfg.ISE.Endpoint = "https://ise.example.com"

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ise.auth.username must be provided")
	assert.Contains(t, err.Error(), "ise.auth.password must be provided")
}

func TestISEConfigValidatePageSizeAndLookbacks(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.ISE.Enabled = true
	cfg.ISE.Endpoint = "https://ise.example.com"
	cfg.ISE.Auth.Username = "admin"
	cfg.ISE.Auth.Password = configopaque.String("password")
	cfg.ISE.PageSize = 101
	cfg.ISE.MaxRetries = 11
	cfg.ISE.EventLookback = -time.Second
	cfg.ISE.SessionLookback = -time.Second
	cfg.ISE.MaxResults = 100_001
	cfg.ISE.AuthFailures.MaxResults = -1
	cfg.ISE.Sessions.MaxResults = 100_001

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ise.page_size must be between 1 and 100")
	assert.Contains(t, err.Error(), "ise.max_retries must not exceed 10")
	assert.Contains(t, err.Error(), "ise.event_lookback must not be negative")
	assert.Contains(t, err.Error(), "ise.session_lookback must not be negative")
	assert.Contains(t, err.Error(), "ise.max_results must not exceed the hard pagination limit of 100000")
	assert.Contains(t, err.Error(), "ise.auth_failures.max_results must not be negative")
	assert.Contains(t, err.Error(), "ise.sessions.max_results must not exceed the hard pagination limit of 100000")
}

func TestISEConfigValidatePxGridCredentials(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.ISE.Enabled = true
	cfg.ISE.Endpoint = "https://ise.example.com"
	cfg.ISE.Auth.Username = "admin"
	cfg.ISE.Auth.Password = configopaque.String("password")
	cfg.ISE.PxGrid.Enabled = true
	cfg.ISE.PxGrid.Streaming = true

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ise.pxgrid.node_name must be provided")
	assert.Contains(t, err.Error(), "ise.pxgrid.password or both ise.pxgrid.cert_file and ise.pxgrid.key_file must be provided")
}

func TestISEConfigValidatePxGridServiceOrigins(t *testing.T) {
	base := createDefaultConfig().(*Config)
	base.ISE.Enabled = true
	base.ISE.Endpoint = "https://ise.example.com"
	base.ISE.Auth.Username = "admin"
	base.ISE.Auth.Password = configopaque.String("password")
	base.ISE.PxGrid.Enabled = true
	base.ISE.PxGrid.NodeName = "otel-collector"
	base.ISE.PxGrid.Password = configopaque.String("pxgrid-secret")

	valid := *base
	valid.ISE.PxGrid.AllowedServiceOrigins = []string{"https://ise-psn.example.com:8910", "wss://ise-pubsub.example.com:8910/"}
	require.NoError(t, valid.Validate())

	for _, origin := range []string{
		"http://ise-psn.example.com:8910",
		"https://user:secret@ise-psn.example.com:8910",
		"https://ise-psn.example.com:8910/pxgrid",
	} {
		t.Run(origin, func(t *testing.T) {
			cfg := *base
			cfg.ISE.PxGrid.AllowedServiceOrigins = []string{origin}
			err := cfg.Validate()
			require.ErrorContains(t, err, "ise.pxgrid.allowed_service_origins[0]")
		})
	}
}

func TestISEConfigRejectsUnsupportedSystemHealthStreaming(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.ISE.PxGrid.Enabled = true
	cfg.ISE.PxGrid.Streaming = true
	cfg.ISE.PxGrid.NodeName = "otel-collector"
	cfg.ISE.PxGrid.Password = configopaque.String("pxgrid-secret")
	cfg.ISE.PxGrid.Subscriptions.SystemHealth = true

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ise.pxgrid.subscriptions.system_health is not supported for streaming")
}

func TestISEConfigValidateDataConnectAllowlist(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.ISE.Enabled = true
	cfg.ISE.Endpoint = "https://ise.example.com"
	cfg.ISE.Auth.Username = "admin"
	cfg.ISE.Auth.Password = configopaque.String("password")
	cfg.ISE.DataConnect.Enabled = true
	cfg.ISE.DataConnect.Host = "ise.example.com"
	cfg.ISE.DataConnect.ServiceName = "cpm10"
	cfg.ISE.DataConnect.Username = "dataconnect"
	cfg.ISE.DataConnect.Password = configopaque.String("db-secret")
	cfg.ISE.DataConnect.AdditionalReadOnly = []string{"UPSPOLICY"}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not include internal view UPSPOLICY")
}

func TestISEConfigRejectsPlaintextDataConnectCredentials(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.ISE.DataConnect.Enabled = true
	cfg.ISE.DataConnect.Host = "ise.example.com"
	cfg.ISE.DataConnect.ServiceName = "cpm10"
	cfg.ISE.DataConnect.Username = "dataconnect"
	cfg.ISE.DataConnect.Password = configopaque.String("db-secret")
	cfg.ISE.DataConnect.SSL = false

	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorContains(t, err, "ise.data_connect.ssl must be true because Data Connect credentials require TLS")
}

func TestISEConfigValidateDataConnectAdditionalViews(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.ISE.Enabled = true
	cfg.ISE.Endpoint = "https://ise.example.com"
	cfg.ISE.Auth.Username = "admin"
	cfg.ISE.Auth.Password = configopaque.String("password")
	cfg.ISE.DataConnect.Enabled = true
	cfg.ISE.DataConnect.Host = "ise.example.com"
	cfg.ISE.DataConnect.ServiceName = "cpm10"
	cfg.ISE.DataConnect.Username = "dataconnect"
	cfg.ISE.DataConnect.Password = configopaque.String("db-secret")
	cfg.ISE.DataConnect.AdditionalReadOnly = []string{"THREAT_EVENTS", "THREAT_EVENTS", "bad-view"}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicates another view")
	assert.Contains(t, err.Error(), "must be a valid view name")
}

func TestISEConfigValidateDataConnectViewOverrides(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.ISE.Enabled = true
	cfg.ISE.Endpoint = "https://ise.example.com"
	cfg.ISE.Auth.Username = "admin"
	cfg.ISE.Auth.Password = configopaque.String("password")
	cfg.ISE.DataConnect.Enabled = true
	cfg.ISE.DataConnect.Host = "ise.example.com"
	cfg.ISE.DataConnect.ServiceName = "cpm10"
	cfg.ISE.DataConnect.Username = "dataconnect"
	cfg.ISE.DataConnect.Password = configopaque.String("db-secret")
	cfg.ISE.DataConnect.Views = map[string]ISEGroupConfig{
		"UPSPOLICYSET": defaultISEGroupConfig(100),
		"bad-view":     defaultISEGroupConfig(100),
	}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ise.data_connect.views.UPSPOLICYSET must not include internal view UPSPOLICYSET")
	assert.Contains(t, err.Error(), "ise.data_connect.views.bad-view must be a valid view name")
}

func TestISEWithDefaultsPreservesExplicitDisabledGroups(t *testing.T) {
	cfg := defaultISEConfig()
	cfg.Deployment = ISEGroupConfig{Enabled: false, MaxResults: 0}
	cfg.PxGrid.Subscriptions = ISEPxGridSubscriptionConfig{}

	resolved := cfg.withDefaults()
	assert.False(t, resolved.Deployment.Enabled)
	assert.Equal(t, defaultISEConfig().Deployment.MaxResults, resolved.Deployment.MaxResults)
	assert.Equal(t, ISEPxGridSubscriptionConfig{}, resolved.PxGrid.Subscriptions)
}
