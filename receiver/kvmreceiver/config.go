// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kvmreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kvmreceiver"

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/scraper/scraperhelper"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kvmreceiver/internal/metadata"
)

type Config struct {
	ControllerConfig     scraperhelper.ControllerConfig `mapstructure:",squash"`
	MetricsBuilderConfig metadata.MetricsBuilderConfig  `mapstructure:",squash"`
	// Endpoint is the libvirt URI used to connect to the QEMU/KVM daemon.
	// The default is qemu:///system. Remote transports such as qemu+ssh and
	// qemu+tls are also supported by the libvirt client.
	Endpoint string `mapstructure:"endpoint"`
}

func newDefaultConfig() component.Config {
	controllerConfig := scraperhelper.NewDefaultControllerConfig()
	controllerConfig.CollectionInterval = time.Minute

	return &Config{
		ControllerConfig:     controllerConfig,
		MetricsBuilderConfig: metadata.NewDefaultMetricsBuilderConfig(),
		Endpoint:             "qemu:///system",
	}
}

func (c *Config) Validate() error {
	if strings.TrimSpace(c.Endpoint) == "" {
		return errors.New("endpoint must not be empty")
	}

	parsed, err := url.Parse(c.Endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint %q: %w", c.Endpoint, err)
	}
	if parsed.Scheme == "" {
		return fmt.Errorf("endpoint %q must include a libvirt URI scheme", c.Endpoint)
	}
	if strings.SplitN(parsed.Scheme, "+", 2)[0] != "qemu" {
		return fmt.Errorf("endpoint %q must use the qemu libvirt driver", c.Endpoint)
	}
	if parsed.Path == "" {
		return fmt.Errorf("endpoint %q must include a libvirt connection path", c.Endpoint)
	}
	if parsed.Scheme == "qemu+ssh" {
		if err := validateSSHURI(parsed); err != nil {
			return fmt.Errorf("invalid endpoint %q: %w", c.Endpoint, err)
		}
	}

	return nil
}
