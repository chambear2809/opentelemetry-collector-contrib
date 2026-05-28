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
	cfg.ISE.EventLookback = -time.Second
	cfg.ISE.SessionLookback = -time.Second
	cfg.ISE.AuthFailures.MaxResults = -1

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ise.page_size must be between 1 and 100")
	assert.Contains(t, err.Error(), "ise.event_lookback must not be negative")
	assert.Contains(t, err.Error(), "ise.session_lookback must not be negative")
	assert.Contains(t, err.Error(), "ise.auth_failures.max_results must not be negative")
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
		"UPSPOLICYSET": defaultISEGroupConfig(true, 100),
		"bad-view":     defaultISEGroupConfig(true, 100),
	}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ise.data_connect.views.UPSPOLICYSET must not include internal view UPSPOLICYSET")
	assert.Contains(t, err.Error(), "ise.data_connect.views.bad-view must be a valid view name")
}
