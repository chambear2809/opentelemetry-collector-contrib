// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kvmreceiver

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		endpoint  string
		wantError string
	}{
		{name: "local system", endpoint: "qemu:///system"},
		{name: "remote ssh", endpoint: "qemu+ssh://hypervisor.example/system"},
		{name: "empty", endpoint: "", wantError: "endpoint must not be empty"},
		{name: "missing scheme", endpoint: "/var/run/libvirt/libvirt-sock", wantError: "must include a libvirt URI scheme"},
		{name: "non qemu driver", endpoint: "xen:///system", wantError: "must use the qemu libvirt driver"},
		{name: "missing path", endpoint: "qemu://hypervisor.example", wantError: "must include a libvirt connection path"},
		{name: "ssh missing host", endpoint: "qemu+ssh:///system", wantError: "ssh endpoint must include a host"},
		{name: "ssh invalid no verify", endpoint: "qemu+ssh://hypervisor.example/system?no_verify=yes", wantError: "invalid no_verify"},
		{name: "ssh direct mode", endpoint: "qemu+ssh://hypervisor.example/system?mode=direct", wantError: "cannot connect in direct mode"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Endpoint: tt.endpoint}
			err := cfg.Validate()
			if tt.wantError == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantError)
		})
	}
}
