// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kvmreceiver

import (
	"net"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSSHSocketDialer(t *testing.T) {
	endpoint, err := url.Parse("qemu+ssh://alice@example.test:2222/system?socket=/run/libvirt/libvirt-sock-ro&keyfile=/tmp/id_test&no_verify=1")
	require.NoError(t, err)

	dialer, err := newSSHSocketDialer(endpoint)
	require.NoError(t, err)
	assert.Equal(t, "example.test", dialer.host)
	assert.Equal(t, "2222", dialer.port)
	assert.Equal(t, "alice", dialer.username)
	assert.Equal(t, "/tmp/id_test", dialer.keyFile)
	assert.Equal(t, "/run/libvirt/libvirt-sock-ro", dialer.remoteSocket)
	assert.True(t, dialer.insecure)
}

func TestNewSSHSocketDialerRejectsInvalidOptions(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{name: "missing host", endpoint: "qemu+ssh:///system", want: "must include a host"},
		{name: "invalid no verify", endpoint: "qemu+ssh://example.test/system?no_verify=yes", want: "invalid no_verify"},
		{name: "direct mode", endpoint: "qemu+ssh://example.test/system?mode=direct", want: "cannot connect in direct mode"},
		{name: "libssh option", endpoint: "qemu+ssh://example.test/system?known_hosts=/tmp/hosts", want: "not supported with the ssh transport"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint, err := url.Parse(tt.endpoint)
			require.NoError(t, err)
			_, err = newSSHSocketDialer(endpoint)
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestSSHStreamConnClosesParentConnections(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	parent := &recordingCloser{}
	agent := &recordingCloser{}
	connection := &sshStreamConn{Conn: client, parent: parent, agent: agent}

	require.NoError(t, connection.Close())
	require.NoError(t, connection.Close())
	assert.Equal(t, 1, parent.calls)
	assert.Equal(t, 1, agent.calls)
}

type recordingCloser struct {
	calls int
}

func (c *recordingCloser) Close() error {
	c.calls++
	return nil
}
