// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestWarnInsecureTLSOptionsIsSilentByDefault(t *testing.T) {
	core, observed := observer.New(zap.WarnLevel)
	warnInsecureTLSOptions(zap.New(core), createDefaultConfig().(*Config))
	assert.Empty(t, observed.All())
}

func TestWarnInsecureTLSOptionsNamesEveryExplicitLabBypass(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Devices = []DeviceConfig{{Host: "router.example.test", Port: 22}}
	cfg.Devices[0].Auth.InsecureSkipVerify = true
	cfg.Meraki.Organizations = []MerakiOrganizationConfig{{OrganizationID: "org-1"}}
	cfg.Meraki.InsecureSkipVerify = true
	cfg.Intersight.Enabled = true
	cfg.Intersight.InsecureSkipVerify = true
	cfg.CatalystCenter.Enabled = true
	cfg.CatalystCenter.InsecureSkipVerify = true
	cfg.SDWAN.Enabled = true
	cfg.SDWAN.InsecureSkipVerify = true
	cfg.NexusDashboard.Enabled = true
	cfg.NexusDashboard.InsecureSkipVerify = true
	cfg.ACI.Enabled = true
	cfg.ACI.Controllers = []ACIControllerConfig{{Endpoint: "https://apic.example.test"}}
	cfg.ACI.InsecureSkipVerify = true
	cfg.FMC.Enabled = true
	cfg.FMC.Controllers = []FMCControllerConfig{{Endpoint: "https://fmc.example.test"}}
	cfg.FMC.InsecureSkipVerify = true
	cfg.FMC.EStreamer.Enabled = true
	cfg.FMC.EStreamer.Targets = []FMCEStreamerTargetConfig{{Endpoint: "fmc.example.test:8302"}}
	cfg.FMC.EStreamer.TLS.InsecureSkipVerify = true
	cfg.ISE.Enabled = true
	cfg.ISE.InsecureSkipVerify = true
	cfg.ISE.PxGrid.Enabled = true
	cfg.ISE.PxGrid.InsecureSkipVerify = true
	cfg.ISE.DataConnect.Enabled = true
	cfg.ISE.DataConnect.SSLVerify = false
	cfg.Catalyst9800.DialIn.Targets = []Catalyst9800TargetConfig{{}}
	cfg.Catalyst9800.DialIn.Targets[0].TLS.InsecureSkipVerify = true
	cfg.IOSXR.DialIn.Targets = []IOSXRTargetConfig{{}}
	cfg.IOSXR.DialIn.Targets[0].TLS.InsecureSkipVerify = true
	cfg.GNMI.Targets = []GNMITargetConfig{{Endpoint: "router.example.test:57400", TLS: GNMITLSConfig{InsecureSkipVerify: true}}}

	core, observed := observer.New(zap.WarnLevel)
	warnInsecureTLSOptions(zap.New(core), cfg)

	paths := make(map[string]struct{}, observed.Len())
	for _, entry := range observed.All() {
		assert.Equal(t, "Server identity verification is disabled for an isolated lab", entry.Message)
		context := entry.ContextMap()
		path, ok := context["config"].(string)
		require.True(t, ok)
		paths[path] = struct{}{}
		assert.NotEmpty(t, context["production_action"])
	}
	for _, path := range []string{
		"devices[0].auth.insecure_skip_verify",
		"meraki.insecure_skip_verify",
		"intersight.insecure_skip_verify",
		"catalyst_center.insecure_skip_verify",
		"sdwan.insecure_skip_verify",
		"nexus_dashboard.insecure_skip_verify",
		"aci.insecure_skip_verify",
		"fmc.insecure_skip_verify",
		"fmc.estreamer.tls.insecure_skip_verify",
		"ise.insecure_skip_verify",
		"ise.pxgrid.insecure_skip_verify",
		"ise.data_connect.ssl_verify=false",
		"catalyst_9800.dial_in.targets[0].tls.insecure_skip_verify",
		"ios_xr.dial_in.targets[0].tls.insecure_skip_verify",
		"gnmi.targets[0].tls.insecure_skip_verify",
	} {
		assert.Contains(t, paths, path)
	}
}

func TestWarnInsecureTLSOptionsIncludesControllerDerivedEStreamerTargets(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.FMC.Controllers = []FMCControllerConfig{{Endpoint: "https://fmc.example.test"}}
	cfg.FMC.EStreamer.Enabled = true
	cfg.FMC.EStreamer.TLS.InsecureSkipVerify = true

	options := configuredInsecureTLSOptions(cfg)
	require.Len(t, options, 1)
	assert.Equal(t, "fmc.estreamer.tls.insecure_skip_verify", options[0].configPath)
	assert.Equal(t, "fmc.example.test:8302", options[0].endpoint)
}

func TestWarnInsecureTLSOptionsDoesNotWarnWhenKnownHostsWins(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Devices = []DeviceConfig{{Host: "router.example.test", Port: 22}}
	cfg.Devices[0].Auth.KnownHostsFile = "/etc/ssh/known_hosts"
	cfg.Devices[0].Auth.InsecureSkipVerify = true

	assert.Empty(t, configuredInsecureTLSOptions(cfg))
}
