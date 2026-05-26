// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package connection // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type sshDialer func(ctx context.Context, network, address string, config *cryptossh.ClientConfig) (*cryptossh.Client, error)

var dialSSH sshDialer = func(ctx context.Context, network, address string, config *cryptossh.ClientConfig) (*cryptossh.Client, error) {
	type dialResult struct {
		conn *cryptossh.Client
		err  error
	}
	ch := make(chan dialResult, 1)
	go func() {
		conn, err := cryptossh.Dial(network, address, config)
		ch <- dialResult{conn, err}
	}()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		// The dial goroutine is still running. When it completes, close any
		// connection it returns so we don't leak an open SSH socket.
		go func() {
			if r := <-ch; r.conn != nil {
				r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// EstablishDeviceConnection creates a device connection using the provided DeviceConfig.
func EstablishDeviceConnection(ctx context.Context, device DeviceConfig, timeout time.Duration, logger *zap.Logger) (*RPCClient, error) {
	authMethods, err := buildAuthMethods(device.Auth, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to build auth methods: %w", err)
	}

	hostKeyCallback, err := buildHostKeyCallback(device.Auth, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to build host key callback: %w", err)
	}

	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	sshConfig := &cryptossh.ClientConfig{
		User:            device.Auth.Username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         timeout,
	}

	address := net.JoinHostPort(device.Device.Host.IP, strconv.Itoa(device.Device.Host.Port))

	conn, err := dialSSH(ctx, "tcp", address, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("SSH connection failed to %s: %w", address, err)
	}

	sshClient := &Client{
		Target:         address,
		Username:       device.Auth.Username,
		EnablePassword: string(device.Auth.EnablePassword),
		Connection:     conn,
		Logger:         logger,
		network:        "tcp",
		address:        address,
		config:         sshConfig,
	}

	// Disable CLI pagination once per connection so all subsequent show
	// commands return full output without interactive page prompts.
	if disablePagingErr := sshClient.DisablePaging(ctx); disablePagingErr != nil {
		logger.Warn("Failed to disable CLI pagination; output may be truncated", zap.Error(disablePagingErr))
	}

	deviceMetadata, err := sshClient.DetectDeviceMetadata(ctx)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("OS detection failed: %w", err)
	}

	rpcClient := &RPCClient{
		SSHClient:      sshClient,
		OSType:         deviceMetadata.OSType,
		DeviceMetadata: deviceMetadata,
		Timeout:        timeout,
		Logger:         logger,
	}

	return rpcClient, nil
}

// buildHostKeyCallback returns an SSH HostKeyCallback based on the auth config.
// Requires either KnownHostsFile or InsecureSkipVerify to be set.
func buildHostKeyCallback(auth AuthConfig, logger *zap.Logger) (cryptossh.HostKeyCallback, error) {
	if auth.KnownHostsFile != "" {
		cb, err := knownhosts.New(auth.KnownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load known_hosts file %s: %w", auth.KnownHostsFile, err)
		}
		return cb, nil
	}
	if auth.InsecureSkipVerify {
		logger.Warn("SSH host key verification is disabled (insecure_skip_verify=true); this is insecure outside of isolated lab environments")
		return cryptossh.InsecureIgnoreHostKey(), nil // #nosec G106
	}
	return nil, errors.New("SSH host key verification is not configured: set auth.known_hosts_file or set auth.insecure_skip_verify: true (lab only)")
}

// buildAuthMethods builds SSH authentication methods from the provided auth config.
// Supports both password and SSH key file authentication.
func buildAuthMethods(auth AuthConfig, logger *zap.Logger) ([]cryptossh.AuthMethod, error) {
	var authMethods []cryptossh.AuthMethod
	if auth.KeyFile != "" {
		keyAuth, err := publicKeyAuth(auth.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load SSH key from %s: %w", auth.KeyFile, err)
		}
		authMethods = append(authMethods, keyAuth)
		logger.Debug("Using SSH key file authentication", zap.String("key_file", auth.KeyFile))
	}

	if auth.Password != "" {
		authMethods = append(authMethods, cryptossh.Password(string(auth.Password)))
		logger.Debug("Using password authentication")
	}

	if len(authMethods) == 0 {
		return nil, errors.New("no authentication method provided: either password or key_file is required")
	}

	return authMethods, nil
}

func publicKeyAuth(keyFile string) (cryptossh.AuthMethod, error) {
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key file: %w", err)
	}

	signer, err := cryptossh.ParsePrivateKey(key)
	if err != nil {
		var passphraseErr *cryptossh.PassphraseMissingError
		if errors.As(err, &passphraseErr) {
			return nil, fmt.Errorf("SSH key is encrypted but passphrase is not supported: %w", err)
		}
		return nil, fmt.Errorf("unable to parse private key: %w", err)
	}

	return cryptossh.PublicKeys(signer), nil
}
