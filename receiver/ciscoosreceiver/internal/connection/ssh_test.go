// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package connection

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	cryptossh "golang.org/x/crypto/ssh"
)

func startSSHExecTestServer(t *testing.T, rejectedCommand string) (string, <-chan string) {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := cryptossh.NewSignerFromKey(privateKey)
	require.NoError(t, err)
	serverConfig := &cryptossh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	commands := make(chan string, 4)
	serverDone := make(chan struct{})
	var (
		acceptedMu sync.Mutex
		accepted   net.Conn
	)
	go func() {
		defer close(serverDone)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		acceptedMu.Lock()
		accepted = connection
		acceptedMu.Unlock()
		defer connection.Close()

		serverConnection, channels, requests, handshakeErr := cryptossh.NewServerConn(connection, serverConfig)
		if handshakeErr != nil {
			return
		}
		defer serverConnection.Close()
		go cryptossh.DiscardRequests(requests)

		for newChannel := range channels {
			if newChannel.ChannelType() != "session" {
				_ = newChannel.Reject(cryptossh.UnknownChannelType, "session channel required")
				continue
			}
			channel, sessionRequests, channelErr := newChannel.Accept()
			if channelErr != nil {
				return
			}
			for request := range sessionRequests {
				if request.Type != "exec" {
					_ = request.Reply(false, nil)
					continue
				}
				var payload struct {
					Command string
				}
				if cryptossh.Unmarshal(request.Payload, &payload) != nil {
					_ = request.Reply(false, nil)
					_ = channel.Close()
					break
				}
				commands <- payload.Command
				if payload.Command == rejectedCommand {
					_ = request.Reply(false, nil)
					_ = channel.Close()
					break
				}
				_ = request.Reply(true, nil)
				_, _ = io.WriteString(channel, "output for "+payload.Command)
				_, _ = channel.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{Status: 0}))
				_ = channel.Close()
				break
			}
		}
	}()

	t.Cleanup(func() {
		_ = listener.Close()
		acceptedMu.Lock()
		if accepted != nil {
			_ = accepted.Close()
		}
		acceptedMu.Unlock()
		select {
		case <-serverDone:
		case <-time.After(2 * time.Second):
			t.Error("SSH exec test server did not stop")
		}
	})
	return listener.Addr().String(), commands
}

func testReconnectClient(address string) *Client {
	return &Client{
		Target:  address,
		Logger:  zap.NewNop(),
		network: "tcp",
		address: address,
		config: &cryptossh.ClientConfig{
			User:            "collector",
			HostKeyCallback: cryptossh.InsecureIgnoreHostKey(), // #nosec G106 -- loopback-only test server
			Timeout:         2 * time.Second,
		},
	}
}

func TestReconnectDisablesPagingBeforeRequestedCommand(t *testing.T) {
	address, commands := startSSHExecTestServer(t, "")
	client := testReconnectClient(address)
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	output, err := client.ExecuteCommand(ctx, "show version")
	require.NoError(t, err)
	assert.Equal(t, "output for show version", output)
	assert.Equal(t, int64(1), client.ReconnectCount())
	assert.Equal(t, "terminal length 0", <-commands)
	assert.Equal(t, "show version", <-commands)
}

func TestReconnectRejectsConnectionWhenPagingInitializationFails(t *testing.T) {
	address, commands := startSSHExecTestServer(t, "terminal length 0")
	client := testReconnectClient(address)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err := client.ExecuteCommand(ctx, "show version")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to disable CLI pagination after SSH reconnect")
	assert.Equal(t, int64(0), client.ReconnectCount())
	assert.Nil(t, client.Connection)
	assert.Equal(t, "terminal length 0", <-commands)
	select {
	case command := <-commands:
		t.Fatalf("requested command %q ran before paging initialization succeeded", command)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestClientClosePreventsInFlightReconnectFromPublishingConnection(t *testing.T) {
	address, commands := startSSHExecTestServer(t, "")
	client := testReconnectClient(address)

	originalDialSSH := dialSSH
	dialed := make(chan struct{})
	releaseDial := make(chan struct{})
	var releaseDialOnce sync.Once
	release := func() { releaseDialOnce.Do(func() { close(releaseDial) }) }
	dialSSH = func(ctx context.Context, network, address string, config *cryptossh.ClientConfig) (*cryptossh.Client, error) {
		conn, err := originalDialSSH(ctx, network, address, config)
		close(dialed)
		<-releaseDial
		return conn, err
	}
	t.Cleanup(func() {
		release()
		dialSSH = originalDialSSH
		_ = client.Close()
	})

	result := make(chan error, 1)
	go func() {
		_, err := client.ExecuteCommand(t.Context(), "show version")
		result <- err
	}()

	select {
	case <-dialed:
	case <-time.After(5 * time.Second):
		t.Fatal("SSH reconnect did not reach the dial barrier")
	}
	require.NoError(t, client.Close())
	release()

	select {
	case err := <-result:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("SSH command did not stop after the client was closed")
	}
	conn, closed := client.currentConnection()
	assert.True(t, closed)
	assert.Nil(t, conn, "an in-flight reconnect must not resurrect a closed client")
	assert.Equal(t, int64(0), client.ReconnectCount())

	// The reconnect may initialize its private candidate connection, but the
	// requested command must never run after Close has made the client terminal.
	assert.Equal(t, "terminal length 0", <-commands)
	select {
	case command := <-commands:
		t.Fatalf("requested command %q ran after client close", command)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestClient_DetectOSType(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		expected string
	}{
		{
			name:     "IOS XE detection",
			output:   "Cisco IOS XE Software, Version 16.9.1",
			expected: "IOS XE",
		},
		{
			name:     "NX-OS detection with Nexus",
			output:   "Cisco Nexus Operating System (NX-OS) Software",
			expected: "NX-OS",
		},
		{
			name:     "NX-OS detection with NX-OS",
			output:   "Cisco NX-OS(tm) Software, Version 9.3(5)",
			expected: "NX-OS",
		},
		{
			name: "NX-OS detection from live NXOS fields",
			output: `Software
  NXOS: version 10.4(5) [Maintenance Release]
  Host NXOS: version 10.4(5)

Hardware
  cisco Nexus9000 C9316D-GX Chassis`,
			expected: "NX-OS",
		},
		{
			name:     "IOS detection",
			output:   "Cisco IOS Software, C2960 Software",
			expected: "IOS",
		},
		{
			name:     "Unknown defaults to IOS XE",
			output:   "Some other output",
			expected: "IOS XE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectOSTypeFromShowVersion(tt.output)
			if result == "" {
				result = "IOS XE"
			}
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestOutputNeedsInteractiveShell(t *testing.T) {
	assert.True(t, outputNeedsInteractiveShell(`Line has invalid autocommand "show platform hardware qfp active datapath utilization"`))
	assert.False(t, outputNeedsInteractiveShell("Cisco IOS XE Software, Version 17.09.02a"))
}

func TestCommandOutputCaptureBoundsCombinedStdoutAndStderr(t *testing.T) {
	stdout, stderr, limit := newCommandOutputCapture(5)

	written, err := stdout.Write([]byte("abc"))
	assert.NoError(t, err)
	assert.Equal(t, 3, written)
	written, err = stderr.Write([]byte("def"))
	assert.NoError(t, err)
	assert.Equal(t, 3, written)

	select {
	case <-limit.overflow:
	default:
		t.Fatal("combined SSH output overflow was not signaled")
	}
	assert.True(t, limit.Exceeded())
	assert.Equal(t, "abcde", stdout.String()+stderr.String())
}

func TestCommandOutputCaptureIsRaceSafe(t *testing.T) {
	stdout, stderr, limit := newCommandOutputCapture(1024)
	var wg sync.WaitGroup
	for _, output := range []*boundedCommandBuffer{stdout, stderr} {
		wg.Go(func() {
			_, _ = output.Write([]byte(strings.Repeat("x", 2048)))
		})
	}
	wg.Wait()

	assert.True(t, limit.Exceeded())
	assert.Len(t, stdout.String()+stderr.String(), 1024)
}

func TestParseDeviceMetadataFromShowVersionIOSXE(t *testing.T) {
	now := time.Unix(100, 0)
	output := `Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a
cisco C9300-48P (X86) processor with 1417496K/6147K bytes of memory.
Processor board ID FCW1234L0AB
Switch uptime is 2 weeks, 3 days, 4 hours, 5 minutes`

	metadata := parseDeviceMetadataFromShowVersion(output, now)

	assert.Equal(t, "IOS XE", metadata.OSType)
	assert.Equal(t, "17.09.04a", metadata.OSVersion)
	assert.Equal(t, "Switch", metadata.HostName)
	assert.Equal(t, "C9300-48P", metadata.Model)
	assert.Equal(t, "FCW1234L0AB", metadata.Serial)
	assert.Equal(t, metadata.Serial, metadata.HostID)
	assert.Equal(t, metadata.Model, metadata.HostType)
	assert.Equal(t, int64((17*24*time.Hour + 4*time.Hour + 5*time.Minute).Seconds()), metadata.UptimeSeconds(now))
	assert.Equal(t, int64((17*24*time.Hour + 4*time.Hour + 6*time.Minute).Seconds()), metadata.UptimeSeconds(now.Add(time.Minute)))
}

func TestParseDeviceMetadataFromShowVersionNXOS(t *testing.T) {
	output := `Cisco Nexus Operating System (NX-OS) Software
Software
  NXOS: version 10.4(5) [Maintenance Release]
  Device name: leaf-01
Hardware
  cisco Nexus9000 C9316D-GX Chassis
  System serial number: FDO12345678
  Kernel uptime is 104 day(s), 6 hour(s), 10 minute(s), 20 second(s)`

	metadata := parseDeviceMetadataFromShowVersion(output, time.Unix(0, 0))

	assert.Equal(t, "NX-OS", metadata.OSType)
	assert.Equal(t, "10.4(5)", metadata.OSVersion)
	assert.Equal(t, "leaf-01", metadata.HostName)
	assert.Equal(t, "Nexus9000 C9316D-GX", metadata.Model)
	assert.Equal(t, "FDO12345678", metadata.Serial)
	assert.Equal(t, int64((104*24*time.Hour + 6*time.Hour + 10*time.Minute + 20*time.Second).Seconds()), metadata.UptimeSeconds(time.Unix(0, 0)))
}
