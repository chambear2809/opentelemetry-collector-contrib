// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package connection

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.uber.org/zap"
	cryptossh "golang.org/x/crypto/ssh"
)

func withFailingDialer(t *testing.T) *string {
	t.Helper()
	var capturedAddress string
	previousDialer := dialSSH
	dialSSH = func(_ context.Context, _, address string, _ *cryptossh.ClientConfig) (*cryptossh.Client, error) {
		capturedAddress = address
		return nil, errors.New("mock dial failure")
	}
	t.Cleanup(func() {
		dialSSH = previousDialer
	})
	return &capturedAddress
}

type stalledSSHAcceptResult struct {
	conn net.Conn
	err  error
}

func startStalledSSHServer(t *testing.T) (string, <-chan stalledSSHAcceptResult, <-chan error) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = listener.Close()
	})

	accepted := make(chan stalledSSHAcceptResult, 1)
	remoteClosed := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		accepted <- stalledSSHAcceptResult{conn: conn, err: acceptErr}
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		buffer := make([]byte, 256)
		for {
			if _, readErr := conn.Read(buffer); readErr != nil {
				remoteClosed <- readErr
				return
			}
		}
	}()

	return listener.Addr().String(), accepted, remoteClosed
}

func waitForStalledSSHAccept(t *testing.T, accepted <-chan stalledSSHAcceptResult) {
	t.Helper()

	select {
	case result := <-accepted:
		require.NoError(t, result.err)
		require.NotNil(t, result.conn)
		t.Cleanup(func() {
			_ = result.conn.Close()
		})
		return
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for stalled SSH server to accept connection")
		return
	}
}

func requirePromptRemoteClose(t *testing.T, remoteClosed <-chan error) {
	t.Helper()

	select {
	case err := <-remoteClosed:
		require.Error(t, err)
		assert.ErrorIs(t, err, io.EOF)
	case <-time.After(2 * time.Second):
		t.Fatal("SSH client did not promptly close the stalled server connection")
	}
}

func TestDialSSHContextCancellationClosesStalledHandshake(t *testing.T) {
	address, accepted, remoteClosed := startStalledSSHServer(t)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	config := &cryptossh.ClientConfig{
		User:            "test-user",
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(), // #nosec G106 -- loopback-only stalled test server
		Timeout:         10 * time.Second,
	}
	dialDone := make(chan error, 1)
	go func() {
		client, err := dialSSH(ctx, "tcp", address, config)
		if client != nil {
			_ = client.Close()
		}
		dialDone <- err
	}()

	waitForStalledSSHAccept(t, accepted)
	cancelStarted := time.Now()
	cancel()

	select {
	case err := <-dialDone:
		require.ErrorIs(t, err, context.Canceled)
		assert.Less(t, time.Since(cancelStarted), time.Second)
	case <-time.After(2 * time.Second):
		t.Fatal("SSH handshake did not return promptly after context cancellation")
	}
	requirePromptRemoteClose(t, remoteClosed)
}

func TestDialSSHHandshakeTimeoutClosesStalledConnection(t *testing.T) {
	address, accepted, remoteClosed := startStalledSSHServer(t)
	config := &cryptossh.ClientConfig{
		User:            "test-user",
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(), // #nosec G106 -- loopback-only stalled test server
		Timeout:         250 * time.Millisecond,
	}

	type dialResult struct {
		client *cryptossh.Client
		err    error
	}
	dialDone := make(chan dialResult, 1)
	dialStarted := time.Now()
	go func() {
		client, err := dialSSH(t.Context(), "tcp", address, config)
		dialDone <- dialResult{client: client, err: err}
	}()

	waitForStalledSSHAccept(t, accepted)
	select {
	case result := <-dialDone:
		if result.client != nil {
			_ = result.client.Close()
		}
		require.Error(t, result.err)
		var netErr net.Error
		require.ErrorAs(t, result.err, &netErr)
		assert.True(t, netErr.Timeout())
		assert.Less(t, time.Since(dialStarted), 2*time.Second)
	case <-time.After(2 * time.Second):
		t.Fatal("SSH handshake did not honor the configured timeout")
	}
	requirePromptRemoteClose(t, remoteClosed)
}

// Helper function to create DeviceConfig for tests
func createTestDeviceConfig(hostName, hostIP string, hostPort int, username, password, keyFile string) DeviceConfig {
	return DeviceConfig{
		Device: DeviceInfo{
			Host: HostInfo{
				Name: hostName,
				IP:   hostIP,
				Port: hostPort,
			},
		},
		Auth: AuthConfig{
			Username:           username,
			Password:           configopaque.String(password),
			KeyFile:            keyFile,
			InsecureSkipVerify: true,
		},
	}
}

func TestBuildAuthMethods_Password(t *testing.T) {
	logger := zap.NewNop()

	auth := AuthConfig{
		Username: "testuser",
		Password: "testpass",
	}

	authMethods, err := buildAuthMethods(auth, logger)
	require.NoError(t, err)
	assert.Len(t, authMethods, 1, "Should have one auth method for password")
}

func TestBuildAuthMethods_KeyFile(t *testing.T) {
	// Create temporary SSH key file
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test_key")

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Encode private key to PEM
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Write key to file
	keyData := pem.EncodeToMemory(privateKeyPEM)
	err = os.WriteFile(keyFile, keyData, 0o600)
	require.NoError(t, err)

	logger := zap.NewNop()

	auth := AuthConfig{
		Username: "testuser",
		KeyFile:  keyFile,
	}

	authMethods, err := buildAuthMethods(auth, logger)
	require.NoError(t, err)
	assert.Len(t, authMethods, 1, "Should have one auth method for key file")
}

func TestBuildAuthMethods_BothPasswordAndKey(t *testing.T) {
	// Create temporary SSH key file
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test_key")

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Encode private key to PEM
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Write key to file
	keyData := pem.EncodeToMemory(privateKeyPEM)
	err = os.WriteFile(keyFile, keyData, 0o600)
	require.NoError(t, err)

	logger := zap.NewNop()

	auth := AuthConfig{
		Username: "testuser",
		Password: "testpass",
		KeyFile:  keyFile,
	}

	authMethods, err := buildAuthMethods(auth, logger)
	require.NoError(t, err)
	assert.Len(t, authMethods, 2, "Should have two auth methods when both password and key are provided")
}

func TestBuildAuthMethods_NoAuthProvided(t *testing.T) {
	logger := zap.NewNop()

	auth := AuthConfig{
		Username: "testuser",
		// No password or key file
	}

	authMethods, err := buildAuthMethods(auth, logger)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no authentication method provided")
	assert.Nil(t, authMethods)
}

func TestBuildAuthMethods_InvalidKeyFile(t *testing.T) {
	logger := zap.NewNop()

	auth := AuthConfig{
		Username: "testuser",
		KeyFile:  "/nonexistent/path/to/key",
	}

	authMethods, err := buildAuthMethods(auth, logger)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load SSH key")
	assert.Nil(t, authMethods)
}

func TestPublicKeyAuth_ValidKey(t *testing.T) {
	// Create temporary SSH key file
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test_key")

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Encode private key to PEM
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Write key to file
	keyData := pem.EncodeToMemory(privateKeyPEM)
	err = os.WriteFile(keyFile, keyData, 0o600)
	require.NoError(t, err)

	authMethod, err := publicKeyAuth(keyFile)
	require.NoError(t, err)
	assert.NotNil(t, authMethod)
}

func TestPublicKeyAuth_InvalidKeyFormat(t *testing.T) {
	// Create temporary file with invalid key data
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "invalid_key")

	err := os.WriteFile(keyFile, []byte("not a valid SSH key"), 0o600)
	require.NoError(t, err)

	authMethod, err := publicKeyAuth(keyFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to parse private key")
	assert.Nil(t, authMethod)
}

func TestPublicKeyAuth_EncryptedKey(t *testing.T) {
	// Create temporary SSH key file (encrypted)
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "encrypted_key")

	// Generate RSA key and encrypt it using SSH library
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Use SSH library to marshal encrypted key (passphrase protected)
	passphrase := []byte("testpassphrase")
	encryptedPEM, err := cryptossh.MarshalPrivateKeyWithPassphrase(privateKey, "", passphrase)
	require.NoError(t, err)

	// Write encrypted key to file
	err = os.WriteFile(keyFile, pem.EncodeToMemory(encryptedPEM), 0o600)
	require.NoError(t, err)

	authMethod, err := publicKeyAuth(keyFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SSH key is encrypted but passphrase is not supported")
	assert.Nil(t, authMethod)
}

func TestPublicKeyAuth_OpenSSHFormat(t *testing.T) {
	// Create temporary SSH key file in OpenSSH format
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "openssh_key")

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Convert to OpenSSH format
	sshPrivateKey, err := cryptossh.NewSignerFromKey(privateKey)
	require.NoError(t, err)

	// Marshal to OpenSSH format
	opensshKey, err := cryptossh.MarshalPrivateKey(privateKey, "")
	require.NoError(t, err)

	// Write key to file
	err = os.WriteFile(keyFile, pem.EncodeToMemory(opensshKey), 0o600)
	require.NoError(t, err)

	authMethod, err := publicKeyAuth(keyFile)
	require.NoError(t, err)
	assert.NotNil(t, authMethod)
	_ = sshPrivateKey // Use the variable to avoid unused warning
}

func TestEstablishDeviceConnection_NoAuthProvided(t *testing.T) {
	logger := zap.NewNop()

	// Test with no password and no key file
	deviceConfig := createTestDeviceConfig("test-device", "192.168.1.1", 22, "testuser", "", "")
	_, err := EstablishDeviceConnection(t.Context(), deviceConfig, 30*time.Second, logger)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no authentication method provided")
}

func TestEstablishDeviceConnection_InvalidKeyFile(t *testing.T) {
	logger := zap.NewNop()

	// Test with invalid key file path
	deviceConfig := createTestDeviceConfig("test-device", "192.168.1.1", 22, "testuser", "", "/nonexistent/path/to/key")
	_, err := EstablishDeviceConnection(t.Context(), deviceConfig, 30*time.Second, logger)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load SSH key")
}

func TestEstablishDeviceConnection_PasswordAuth(t *testing.T) {
	withFailingDialer(t)
	logger := zap.NewNop()

	// Test with password authentication
	// This will fail to connect (no SSH server), but we verify the auth methods are built correctly
	deviceConfig := createTestDeviceConfig("test-device", "192.168.1.1", 22, "testuser", "testpass", "")
	_, err := EstablishDeviceConnection(t.Context(), deviceConfig, 30*time.Second, logger)

	// Should fail due to SSH connection failure, not auth method building
	require.Error(t, err)
	// The error should be about SSH connection, not authentication method building
	assert.NotContains(t, err.Error(), "no authentication method provided")
}

func TestEstablishDeviceConnection_KeyFileAuth(t *testing.T) {
	withFailingDialer(t)
	// Create temporary SSH key file
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test_key")

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Encode private key to PEM
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Write key to file
	keyData := pem.EncodeToMemory(privateKeyPEM)
	err = os.WriteFile(keyFile, keyData, 0o600)
	require.NoError(t, err)

	logger := zap.NewNop()

	// Test with key file authentication
	// This will fail to connect (no SSH server), but we verify the auth methods are built correctly
	deviceConfig := createTestDeviceConfig("test-device", "192.168.1.1", 22, "testuser", "", keyFile)
	_, err = EstablishDeviceConnection(t.Context(), deviceConfig, 30*time.Second, logger)

	// Should fail due to SSH connection failure, not auth method building
	require.Error(t, err)
	// The error should be about SSH connection, not authentication method building
	assert.NotContains(t, err.Error(), "failed to load SSH key")
	assert.NotContains(t, err.Error(), "no authentication method provided")
}

func TestEstablishDeviceConnection_BothPasswordAndKey(t *testing.T) {
	withFailingDialer(t)
	// Create temporary SSH key file
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test_key")

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Encode private key to PEM
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Write key to file
	keyData := pem.EncodeToMemory(privateKeyPEM)
	err = os.WriteFile(keyFile, keyData, 0o600)
	require.NoError(t, err)

	logger := zap.NewNop()

	// Test with both password and key file authentication
	deviceConfig := createTestDeviceConfig("test-device", "192.168.1.1", 22, "testuser", "testpass", keyFile)
	_, err = EstablishDeviceConnection(t.Context(), deviceConfig, 30*time.Second, logger)

	// Should fail due to SSH connection failure, not auth method building
	require.Error(t, err)
	// The error should be about SSH connection, not authentication method building
	assert.NotContains(t, err.Error(), "failed to load SSH key")
	assert.NotContains(t, err.Error(), "at least one of auth.password or auth.key_file is required")
}

// Edge case tests

func TestEstablishDeviceConnection_EmptyHostName(t *testing.T) {
	withFailingDialer(t)
	logger := zap.NewNop()

	// Host name is optional, empty string should be valid
	deviceConfig := createTestDeviceConfig("", "192.168.1.1", 22, "testuser", "testpass", "")
	_, err := EstablishDeviceConnection(t.Context(), deviceConfig, 30*time.Second, logger)

	// Should fail due to SSH connection, not validation
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "device.host.name")
}

func TestEstablishDeviceConnection_PortBoundaries(t *testing.T) {
	withFailingDialer(t)
	logger := zap.NewNop()

	tests := []struct {
		name string
		port int
	}{
		{
			name: "port one",
			port: 1,
		},
		{
			name: "standard SSH port",
			port: 22,
		},
		{
			name: "high port",
			port: 65535,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deviceConfig := createTestDeviceConfig("test-device", "192.168.1.1", tt.port, "testuser", "testpass", "")
			_, err := EstablishDeviceConnection(t.Context(), deviceConfig, 30*time.Second, logger)
			// Should fail with connection error, not validation error
			if err != nil {
				assert.NotContains(t, err.Error(), "is required")
			}
		})
	}
}

func TestEstablishDeviceConnection_IPv6Address(t *testing.T) {
	capturedAddress := withFailingDialer(t)
	logger := zap.NewNop()

	// Test with IPv6 address
	deviceConfig := createTestDeviceConfig("test-device", "2001:db8::1", 22, "testuser", "testpass", "")
	_, err := EstablishDeviceConnection(t.Context(), deviceConfig, 30*time.Second, logger)

	// Should fail due to SSH connection, not validation
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "device.host.ip is required")
	assert.Equal(t, "[2001:db8::1]:22", *capturedAddress)
}

func TestEstablishDeviceConnection_SpecialCharactersInPassword(t *testing.T) {
	withFailingDialer(t)
	logger := zap.NewNop()

	// Test with special characters in password
	deviceConfig := createTestDeviceConfig("test-device", "192.168.1.1", 22, "testuser", "p@$$w0rd!#%&*()[]{}|<>?/\\\"'`~", "")
	_, err := EstablishDeviceConnection(t.Context(), deviceConfig, 30*time.Second, logger)

	// Should fail due to SSH connection, not validation
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "at least one of auth.password or auth.key_file is required")
}

func TestEstablishDeviceConnection_NonStandardPort(t *testing.T) {
	capturedAddress := withFailingDialer(t)
	logger := zap.NewNop()

	// Test with non-standard SSH port
	deviceConfig := createTestDeviceConfig("test-device", "192.168.1.1", 2222, "testuser", "testpass", "")
	_, err := EstablishDeviceConnection(t.Context(), deviceConfig, 30*time.Second, logger)

	// Should fail due to SSH connection, not validation
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "device.host.port is required")
	assert.Equal(t, "192.168.1.1:2222", *capturedAddress)
}

func TestEstablishDeviceConnection_AllFieldsPopulated(t *testing.T) {
	withFailingDialer(t)
	// Create temporary SSH key file
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test_key")

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Encode private key to PEM
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Write key to file
	keyData := pem.EncodeToMemory(privateKeyPEM)
	err = os.WriteFile(keyFile, keyData, 0o600)
	require.NoError(t, err)

	logger := zap.NewNop()

	// Test with all fields populated including optional host name
	deviceConfig := createTestDeviceConfig("cisco-switch-01", "192.168.1.1", 22, "admin", "password123", keyFile)
	_, err = EstablishDeviceConnection(t.Context(), deviceConfig, 30*time.Second, logger)

	// Should fail due to SSH connection, but all validation passed
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "is required")
	assert.NotContains(t, err.Error(), "at least one of")
}

func TestEstablishDeviceConnection_SkipsStandalonePagingWhenEnablePasswordSet(t *testing.T) {
	address, transcript := startSSHShellTestServer(t, map[string]string{
		"show version": "Cisco IOS XE Software, Version 17.12.02\r\n",
	})
	host, portText, err := net.SplitHostPort(address)
	require.NoError(t, err)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err)

	deviceConfig := createTestDeviceConfig("test-device", host, port, "testuser", "testpass", "")
	deviceConfig.Auth.EnablePassword = configopaque.String("enable-secret")
	client, err := EstablishDeviceConnection(t.Context(), deviceConfig, 30*time.Second, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, client.SSHClient.Close())
	})
	assert.Equal(t, "IOS XE", client.OSType)

	var lines []string
	for i := 0; i < 5; i++ {
		select {
		case line := <-transcript:
			lines = append(lines, line)
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for transcript line %d", i+1)
		}
	}
	assert.Equal(t, []string{
		"shell:enable",
		"shell:enable-secret",
		"shell:terminal length 0",
		"shell:show version",
		"shell:exit",
	}, lines)
	select {
	case line := <-transcript:
		t.Fatalf("unexpected extra transcript line: %s", line)
	case <-time.After(100 * time.Millisecond):
	}
}
