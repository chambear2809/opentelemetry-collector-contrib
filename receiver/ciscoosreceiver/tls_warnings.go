// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"fmt"

	"go.uber.org/zap"
)

type insecureTLSOption struct {
	configPath string
	endpoint   string
}

// warnInsecureTLSOptions makes every explicit lab-mode certificate bypass
// visible once when a signal receiver is constructed. Verification remains the
// default, and request paths never fall back to insecure TLS automatically.
func warnInsecureTLSOptions(logger *zap.Logger, cfg *Config) {
	if logger == nil || cfg == nil {
		return
	}
	for _, option := range configuredInsecureTLSOptions(cfg) {
		logger.Warn(
			"Server identity verification is disabled for an isolated lab",
			zap.String("config", option.configPath),
			zap.String("endpoint", option.endpoint),
			zap.String("production_action", "configure trusted CA or host-key material and disable this bypass before production"),
		)
	}
}

func configuredInsecureTLSOptions(cfg *Config) []insecureTLSOption {
	options := make([]insecureTLSOption, 0, 16)
	add := func(enabled bool, configPath, endpoint string) {
		if enabled {
			options = append(options, insecureTLSOption{configPath: configPath, endpoint: endpoint})
		}
	}

	for i := range cfg.Devices {
		device := &cfg.Devices[i]
		add(
			device.Auth.InsecureSkipVerify && device.Auth.KnownHostsFile == "",
			fmt.Sprintf("devices[%d].auth.insecure_skip_verify", i),
			fmt.Sprintf("%s:%d", device.Host, device.Port),
		)
	}
	add(cfg.Meraki.hasTargets() && cfg.Meraki.InsecureSkipVerify, "meraki.insecure_skip_verify", cfg.Meraki.BaseURL)
	add(cfg.Intersight.hasTarget() && cfg.Intersight.InsecureSkipVerify, "intersight.insecure_skip_verify", cfg.Intersight.Endpoint)
	add(cfg.CatalystCenter.hasTarget() && cfg.CatalystCenter.InsecureSkipVerify, "catalyst_center.insecure_skip_verify", cfg.CatalystCenter.Endpoint)
	add(cfg.SDWAN.hasTarget() && cfg.SDWAN.InsecureSkipVerify, "sdwan.insecure_skip_verify", cfg.SDWAN.Endpoint)
	add(cfg.NexusDashboard.hasTarget() && cfg.NexusDashboard.InsecureSkipVerify, "nexus_dashboard.insecure_skip_verify", cfg.NexusDashboard.Endpoint)
	if cfg.ACI.hasTarget() && cfg.ACI.InsecureSkipVerify {
		for _, controller := range cfg.ACI.Controllers {
			add(true, "aci.insecure_skip_verify", controller.Endpoint)
		}
	}
	if cfg.FMC.hasRESTTarget() && cfg.FMC.InsecureSkipVerify {
		for _, controller := range cfg.FMC.Controllers {
			add(true, "fmc.insecure_skip_verify", controller.Endpoint)
		}
	}
	if cfg.FMC.EStreamer.hasTarget() && cfg.FMC.EStreamer.TLS.InsecureSkipVerify {
		if len(cfg.FMC.EStreamer.Targets) > 0 {
			for _, target := range cfg.FMC.EStreamer.Targets {
				add(true, "fmc.estreamer.tls.insecure_skip_verify", target.Endpoint)
			}
		} else {
			for _, controller := range cfg.FMC.Controllers {
				endpoint, err := estreamerEndpointFromFMCController(controller.Endpoint)
				if err != nil {
					endpoint = controller.Endpoint
				}
				add(true, "fmc.estreamer.tls.insecure_skip_verify", endpoint)
			}
		}
	}
	iseRESTConfigured := cfg.ISE.Enabled || cfg.ISE.Endpoint != "" || cfg.ISE.Auth.Username != "" || cfg.ISE.Auth.Password != ""
	add(iseRESTConfigured && cfg.ISE.InsecureSkipVerify, "ise.insecure_skip_verify", cfg.ISE.Endpoint)
	add(cfg.ISE.PxGrid.hasTarget() && cfg.ISE.PxGrid.InsecureSkipVerify, "ise.pxgrid.insecure_skip_verify", cfg.ISE.PxGrid.Endpoint)
	add(cfg.ISE.DataConnect.hasTarget() && !cfg.ISE.DataConnect.SSLVerify, "ise.data_connect.ssl_verify=false", cfg.ISE.DataConnect.Host)

	for i := range cfg.Catalyst9800.DialIn.Targets {
		target := &cfg.Catalyst9800.DialIn.Targets[i]
		add(target.TLS.InsecureSkipVerify, fmt.Sprintf("catalyst_9800.dial_in.targets[%d].tls.insecure_skip_verify", i), target.Endpoint)
	}
	for i := range cfg.IOSXR.DialIn.Targets {
		target := &cfg.IOSXR.DialIn.Targets[i]
		add(target.TLS.InsecureSkipVerify, fmt.Sprintf("ios_xr.dial_in.targets[%d].tls.insecure_skip_verify", i), target.Endpoint)
	}
	for i := range cfg.GNMI.Targets {
		target := &cfg.GNMI.Targets[i]
		add(target.TLS.InsecureSkipVerify, fmt.Sprintf("gnmi.targets[%d].tls.insecure_skip_verify", i), target.Endpoint)
	}
	return options
}
