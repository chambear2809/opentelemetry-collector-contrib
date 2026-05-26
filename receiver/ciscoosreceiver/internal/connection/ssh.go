// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package connection // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	cryptossh "golang.org/x/crypto/ssh"
)

// Client represents SSH client connection to Cisco device
type Client struct {
	Target         string
	Username       string
	EnablePassword string
	Connection     *cryptossh.Client
	Logger         *zap.Logger
	network        string
	address        string
	config         *cryptossh.ClientConfig
	reconnectCount int64
}

// DisablePaging disables CLI pagination so command output is not truncated.
// This must be called once after establishing the SSH connection, before any
// show commands are issued. On Cisco IOS/IOS-XE/NX-OS, "terminal length 0"
// is sent as its own exec session so it takes effect device-wide for the
// connection, avoiding the use of shell semicolons which are not supported
// on Cisco SSH exec sessions.
func (s *Client) DisablePaging(ctx context.Context) error {
	_, err := s.executeCommand(ctx, "terminal length 0", true)
	return err
}

// ExecuteCommand executes a command on the Cisco device via SSH.
// Each call opens a new exec session (no PTY) so that output is returned
// directly without interactive pagination. The session is explicitly closed
// when the context expires so that the underlying goroutine is unblocked.
func (s *Client) ExecuteCommand(ctx context.Context, command string) (string, error) {
	if s.EnablePassword != "" {
		return s.executeCommandInShell(ctx, command, true)
	}
	output, err := s.executeCommand(ctx, command, false)
	if err == nil && outputNeedsInteractiveShell(output) {
		return s.executeCommandInShell(ctx, command, false)
	}
	return output, err
}

func (s *Client) executeCommand(ctx context.Context, command string, ignoreExitStatus bool) (string, error) {
	s.Logger.Debug("Executing SSH command", zap.String("command", command))

	session, err := s.newSession(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %w", err)
	}

	type result struct {
		output string
		err    error
	}
	resultChan := make(chan result, 1)

	go func() {
		// Capture stdout and stderr together so Cisco error lines (e.g. "% Invalid
		// input detected") are visible in parser output. We use Run rather than
		// Output so that non-zero exit codes do not discard the output — Cisco IOS
		// frequently exits non-zero even for successful commands.
		var stdout, stderr bytes.Buffer
		session.Stdout = &stdout
		session.Stderr = &stderr
		execErr := session.Run(command)
		out := stdout.String() + stderr.String()
		// Treat non-zero exit codes from the device as non-fatal: return the
		// output so parsers can handle it. Only return an error if there is truly
		// no output AND the session errored (i.e., connection-level failure).
		if execErr != nil {
			var exitErr *cryptossh.ExitError
			if errors.As(execErr, &exitErr) && (out != "" || ignoreExitStatus) {
				// Device returned output with a non-zero exit — treat as success.
				execErr = nil
			}
		}
		resultChan <- result{out, execErr}
	}()

	select {
	case r := <-resultChan:
		session.Close()
		if r.err != nil {
			return "", fmt.Errorf("command execution failed: %w", r.err)
		}
		s.Logger.Debug("Command executed successfully",
			zap.String("command", command),
			zap.Int("output_length", len(r.output)))
		return r.output, nil

	case <-ctx.Done():
		// Close the session to unblock the goroutine reading from the device.
		session.Close()
		return "", fmt.Errorf("command execution timeout: %w", ctx.Err())
	}
}

func (s *Client) executeCommandInShell(ctx context.Context, command string, enable bool) (string, error) {
	s.Logger.Debug("Executing SSH command through interactive shell",
		zap.String("command", command),
		zap.Bool("enable_mode", enable))

	session, err := s.newSession(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %w", err)
	}

	modes := cryptossh.TerminalModes{
		cryptossh.ECHO:          0,
		cryptossh.TTY_OP_ISPEED: 14400,
		cryptossh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("vt100", 80, 240, modes); err != nil {
		session.Close()
		return "", fmt.Errorf("failed to request SSH PTY: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		return "", fmt.Errorf("failed to open SSH stdin pipe: %w", err)
	}

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	if err := session.Shell(); err != nil {
		session.Close()
		return "", fmt.Errorf("failed to start SSH shell: %w", err)
	}

	type result struct {
		output string
		err    error
	}
	resultChan := make(chan result, 1)

	go func() {
		var writeErr error
		lines := []string{"terminal length 0", command, "exit"}
		if enable {
			lines = append([]string{"enable", s.EnablePassword}, lines...)
		}
		for _, line := range lines {
			if _, writeErr = fmt.Fprintln(stdin, line); writeErr != nil {
				break
			}
		}
		_ = stdin.Close()

		waitErr := session.Wait()
		out := stdout.String() + stderr.String()
		if writeErr != nil {
			resultChan <- result{out, writeErr}
			return
		}
		if waitErr != nil {
			var exitErr *cryptossh.ExitError
			if errors.As(waitErr, &exitErr) && out != "" {
				waitErr = nil
			}
		}
		resultChan <- result{out, waitErr}
	}()

	select {
	case r := <-resultChan:
		session.Close()
		if r.err != nil {
			return "", fmt.Errorf("command execution failed: %w", r.err)
		}
		s.Logger.Debug("Command executed successfully through interactive shell",
			zap.String("command", command),
			zap.Int("output_length", len(r.output)))
		return r.output, nil

	case <-ctx.Done():
		session.Close()
		return "", fmt.Errorf("command execution timeout: %w", ctx.Err())
	}
}

func outputNeedsInteractiveShell(output string) bool {
	return strings.Contains(strings.ToLower(output), "line has invalid autocommand")
}

func (s *Client) newSession(ctx context.Context) (*cryptossh.Session, error) {
	if s.Connection == nil {
		if err := s.reconnect(ctx); err != nil {
			return nil, err
		}
		return s.openSession(ctx)
	}

	session, err := s.openSession(ctx)
	if err == nil {
		return session, nil
	}
	if ctx.Err() != nil {
		return nil, err
	}
	if s.config == nil || s.address == "" || s.network == "" {
		return nil, err
	}

	s.Logger.Debug("Failed to create SSH session; reconnecting before retry",
		zap.String("target", s.Target),
		zap.Error(err))
	if reconnectErr := s.reconnect(ctx); reconnectErr != nil {
		return nil, fmt.Errorf("failed to reconnect after session creation failed: %w (original error: %v)", reconnectErr, err)
	}

	session, retryErr := s.openSession(ctx)
	if retryErr != nil {
		return nil, fmt.Errorf("failed to create SSH session after reconnect: %w (original error: %v)", retryErr, err)
	}
	return session, nil
}

func (s *Client) openSession(ctx context.Context) (*cryptossh.Session, error) {
	type sessionResult struct {
		session *cryptossh.Session
		err     error
	}
	resultChan := make(chan sessionResult, 1)
	go func() {
		session, err := s.Connection.NewSession()
		resultChan <- sessionResult{session: session, err: err}
	}()

	select {
	case r := <-resultChan:
		return r.session, r.err
	case <-ctx.Done():
		if s.Connection != nil {
			_ = s.Connection.Close()
			s.Connection = nil
		}
		go func() {
			if r := <-resultChan; r.session != nil {
				_ = r.session.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

func (s *Client) reconnect(ctx context.Context) error {
	if s.config == nil || s.address == "" || s.network == "" {
		return errors.New("SSH reconnect is not configured")
	}
	if s.Connection != nil {
		_ = s.Connection.Close()
	}
	conn, err := dialSSH(ctx, s.network, s.address, s.config)
	if err != nil {
		return err
	}
	s.Connection = conn
	atomic.AddInt64(&s.reconnectCount, 1)
	return nil
}

func (s *Client) ReconnectCount() int64 {
	return atomic.LoadInt64(&s.reconnectCount)
}

// DetectOSType executes "show version" to detect Cisco OS type
func (s *Client) DetectOSType(ctx context.Context) (string, error) {
	metadata, err := s.DetectDeviceMetadata(ctx)
	if err != nil {
		return "", err
	}
	return metadata.OSType, nil
}

// DetectDeviceMetadata executes "show version" to detect Cisco OS type and
// stable device identity fields.
func (s *Client) DetectDeviceMetadata(ctx context.Context) (DeviceMetadata, error) {
	s.Logger.Debug("Executing 'show version' command for OS detection")

	output, err := s.ExecuteCommand(ctx, "show version")
	if err != nil {
		return DeviceMetadata{}, fmt.Errorf("failed to execute 'show version': %w", err)
	}

	s.Logger.Debug("Analyzing show version output", zap.Int("output_length", len(output)))

	metadata := parseDeviceMetadataFromShowVersion(output, time.Now())
	if metadata.OSType == "" {
		s.Logger.Warn("Unable to detect OS type from show version output, defaulting to IOS XE")
		metadata.OSType = "IOS XE"
	}

	return metadata, nil
}

func detectOSTypeFromShowVersion(output string) string {
	output = strings.ToLower(output)
	switch {
	case strings.Contains(output, "ios xe"):
		return "IOS XE"
	case strings.Contains(output, "nx-os") ||
		strings.Contains(output, "nxos:") ||
		strings.Contains(output, "host nxos") ||
		strings.Contains(output, "nexus operating system") ||
		strings.Contains(output, "nexus9000"):
		return "NX-OS"
	case strings.Contains(output, "ios software"):
		return "IOS"
	default:
		return ""
	}
}

// Close closes SSH connection
func (s *Client) Close() error {
	if s.Connection != nil {
		return s.Connection.Close()
	}
	return nil
}
