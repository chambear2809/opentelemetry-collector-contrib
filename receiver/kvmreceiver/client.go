// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kvmreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kvmreceiver"

import (
	"fmt"
	"net/url"

	"github.com/digitalocean/go-libvirt"
)

type libvirtClient interface {
	ConnectListAllDomains(int32, libvirt.ConnectListAllDomainsFlags) ([]libvirt.Domain, uint32, error)
	DomainGetInfo(libvirt.Domain) (uint8, uint64, uint64, uint16, uint64, error)
	DomainGetXMLDesc(libvirt.Domain, libvirt.DomainXMLFlags) (string, error)
	DomainBlockStats(libvirt.Domain, string) (int64, int64, int64, int64, int64, error)
	DomainInterfaceStats(libvirt.Domain, string) (int64, int64, int64, int64, int64, int64, int64, int64, error)
	Disconnect() error
}

var newLibvirtClient = func(endpoint string) (libvirtClient, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse libvirt endpoint: %w", err)
	}
	if parsed.Scheme == "qemu+ssh" {
		return connectLibvirtSSH(parsed)
	}

	client, err := libvirt.ConnectToURI(parsed)
	if err != nil {
		return nil, err
	}
	return client, nil
}
