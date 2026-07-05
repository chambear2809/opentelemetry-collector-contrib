// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package connection // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	cryptossh "golang.org/x/crypto/ssh"
)

const defaultMaxSSHCommandOutputBytes = 16 * 1024 * 1024

var errSSHCommandOutputTooLarge = errors.New("SSH command output exceeds limit")

var (
	iosXEShowVersionSignature = regexp.MustCompile(`(?im)^\s*(?:cisco ios xe software|cisco ios software[^\r\n]*(?:\bios[- ]?xe software\b|(?:\b|_)iosxe\b))[^\r\n]*\bversion\s+\S+`)
	iosShowVersionSignature   = regexp.MustCompile(`(?im)^\s*cisco ios software[^\r\n]*\bversion\s+\S+`)
	// Older IOS releases split the product banner and the version-bearing image
	// line. Requiring the adjacent, structured pair avoids treating login-banner
	// prose containing the well-known product name as command output.
	classicIOSShowVersionPair = regexp.MustCompile(`(?im)^[ \t]*cisco internetwork operating system software[ \t]*\r?\n[ \t]*(?:cisco[ \t]+)?ios[ \t]*\([ \t]*tm[ \t]*\)[ \t]+(?:[a-z0-9][a-z0-9._+/\-]*[ \t]+)+software[ \t]+\([a-z0-9][a-z0-9._+\-]*\),[ \t]+(?:experimental[ \t]+)?version[ \t]+([^,\s]+)(?:[ \t]+\[[^\]\r\n]+\])?(?:,[^\r\n]*)?[ \t]*\r?$`)
	nxOSShowVersionSignature  = regexp.MustCompile(`(?im)(?:^\s*(?:nxos|host nxos|system|kickstart):\s*version\s+\S+|^\s*cisco nx-os[^\r\n]*\bversion\s+\S+)`)
	showVersionFailureLine    = regexp.MustCompile(`(?im)^\s*%?\s*(?:authorization failed|command authorization failed|not authorized|permission denied|invalid input detected|unknown command)\b`)
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
	reconnectCount atomic.Int64
	connectionMu   sync.Mutex
	reconnectMu    sync.Mutex
	closed         bool
	// maxCommandOutputBytes is test-injectable; zero uses the production cap.
	maxCommandOutputBytes int
}

type commandOutputLimit struct {
	mu        sync.Mutex
	remaining int
	exceeded  bool
	overflow  chan struct{}
}

type boundedCommandBuffer struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	limit *commandOutputLimit
}

func newCommandOutputCapture(limit int) (*boundedCommandBuffer, *boundedCommandBuffer, *commandOutputLimit) {
	state := &commandOutputLimit{remaining: limit, overflow: make(chan struct{})}
	return &boundedCommandBuffer{limit: state}, &boundedCommandBuffer{limit: state}, state
}

func (b *boundedCommandBuffer) Write(payload []byte) (int, error) {
	allowed := b.limit.claim(len(payload))
	if allowed > 0 {
		b.mu.Lock()
		_, _ = b.buf.Write(payload[:allowed])
		b.mu.Unlock()
	}
	// Report the full write as consumed so the SSH transport continues draining
	// until the caller closes the session after observing the overflow signal.
	return len(payload), nil
}

func (b *boundedCommandBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (l *commandOutputLimit) claim(requested int) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	allowed := min(requested, l.remaining)
	l.remaining -= allowed
	if allowed < requested && !l.exceeded {
		l.exceeded = true
		close(l.overflow)
	}
	return allowed
}

func (l *commandOutputLimit) Exceeded() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.exceeded
}

func (s *Client) commandOutputLimit() int {
	if s.maxCommandOutputBytes > 0 {
		return s.maxCommandOutputBytes
	}
	return defaultMaxSSHCommandOutputBytes
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
	return s.executeCommandWithSession(ctx, session, command, ignoreExitStatus)
}

// executeCommandWithSession executes an exec request on a session that has
// already been opened. Keeping session acquisition out of this helper lets a
// reconnect initialize the new connection without recursively triggering
// another reconnect through newSession.
func (s *Client) executeCommandWithSession(ctx context.Context, session *cryptossh.Session, command string, ignoreExitStatus bool) (string, error) {
	type result struct {
		output string
		err    error
	}
	resultChan := make(chan result, 1)
	stdout, stderr, outputLimit := newCommandOutputCapture(s.commandOutputLimit())

	go func() {
		// Capture stdout and stderr together so Cisco error lines (e.g. "% Invalid
		// input detected") are visible in parser output. We use Run rather than
		// Output so that non-zero exit codes do not discard the output — Cisco IOS
		// frequently exits non-zero even for successful commands.
		session.Stdout = stdout
		session.Stderr = stderr
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
		if outputLimit.Exceeded() {
			return "", fmt.Errorf("%w: limit is %d bytes", errSSHCommandOutputTooLarge, s.commandOutputLimit())
		}
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

	case <-outputLimit.overflow:
		session.Close()
		return "", fmt.Errorf("%w: limit is %d bytes", errSSHCommandOutputTooLarge, s.commandOutputLimit())
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
	if ptyErr := session.RequestPty("vt100", 80, 240, modes); ptyErr != nil {
		session.Close()
		return "", fmt.Errorf("failed to request SSH PTY: %w", ptyErr)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		return "", fmt.Errorf("failed to open SSH stdin pipe: %w", err)
	}

	stdout, stderr, outputLimit := newCommandOutputCapture(s.commandOutputLimit())
	session.Stdout = stdout
	session.Stderr = stderr
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
		if outputLimit.Exceeded() {
			return "", fmt.Errorf("%w: limit is %d bytes", errSSHCommandOutputTooLarge, s.commandOutputLimit())
		}
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

	case <-outputLimit.overflow:
		session.Close()
		return "", fmt.Errorf("%w: limit is %d bytes", errSSHCommandOutputTooLarge, s.commandOutputLimit())
	}
}

func outputNeedsInteractiveShell(output string) bool {
	return strings.Contains(strings.ToLower(output), "line has invalid autocommand")
}

func (s *Client) newSession(ctx context.Context) (*cryptossh.Session, error) {
	conn, closed := s.currentConnection()
	if closed {
		return nil, net.ErrClosed
	}
	if conn == nil {
		if err := s.reconnect(ctx, nil); err != nil {
			return nil, err
		}
		conn, closed = s.currentConnection()
		if closed || conn == nil {
			return nil, net.ErrClosed
		}
		return s.openSession(ctx, conn)
	}

	session, err := s.openSession(ctx, conn)
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
	if reconnectErr := s.reconnect(ctx, conn); reconnectErr != nil {
		return nil, fmt.Errorf("failed to reconnect after session creation failed: %w (original error: %w)", reconnectErr, err)
	}

	conn, closed = s.currentConnection()
	if closed || conn == nil {
		return nil, fmt.Errorf("failed to create SSH session after reconnect: %w (original error: %w)", net.ErrClosed, err)
	}
	session, retryErr := s.openSession(ctx, conn)
	if retryErr != nil {
		return nil, fmt.Errorf("failed to create SSH session after reconnect: %w (original error: %w)", retryErr, err)
	}
	return session, nil
}

func (s *Client) openSession(ctx context.Context, conn *cryptossh.Client) (*cryptossh.Session, error) {
	if conn == nil {
		return nil, net.ErrClosed
	}
	type sessionResult struct {
		session *cryptossh.Session
		err     error
	}
	resultChan := make(chan sessionResult, 1)
	go func() {
		session, err := conn.NewSession()
		resultChan <- sessionResult{session: session, err: err}
	}()

	select {
	case r := <-resultChan:
		return r.session, r.err
	case <-ctx.Done():
		_ = conn.Close()
		s.clearConnection(conn)
		go func() {
			if r := <-resultChan; r.session != nil {
				_ = r.session.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

func (s *Client) currentConnection() (*cryptossh.Client, bool) {
	s.connectionMu.Lock()
	defer s.connectionMu.Unlock()
	return s.Connection, s.closed
}

func (s *Client) clearConnection(conn *cryptossh.Client) {
	s.connectionMu.Lock()
	defer s.connectionMu.Unlock()
	if s.Connection == conn {
		s.Connection = nil
	}
}

func (s *Client) reconnect(ctx context.Context, failedConn *cryptossh.Client) error {
	if s.config == nil || s.address == "" || s.network == "" {
		return errors.New("SSH reconnect is not configured")
	}
	s.reconnectMu.Lock()
	defer s.reconnectMu.Unlock()

	s.connectionMu.Lock()
	if s.closed {
		s.connectionMu.Unlock()
		return net.ErrClosed
	}
	current := s.Connection
	// A concurrent caller may already have installed a replacement while this
	// caller waited for reconnectMu. Reuse it rather than tearing it down.
	if current != nil && (failedConn == nil || current != failedConn) {
		s.connectionMu.Unlock()
		return nil
	}
	s.Connection = nil
	s.connectionMu.Unlock()
	if current != nil {
		_ = current.Close()
	}

	conn, err := dialSSH(ctx, s.network, s.address, s.config)
	if err != nil {
		return err
	}

	// Cisco pagination settings are scoped to the SSH connection. Reapply the
	// same initialization performed for the original connection before a show
	// command is allowed to use this replacement connection. Open the session
	// directly rather than calling DisablePaging, which would route back through
	// newSession and could recurse into reconnect.
	pagingSession, err := s.openSession(ctx, conn)
	if err == nil {
		_, err = s.executeCommandWithSession(ctx, pagingSession, "terminal length 0", true)
	}
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("failed to disable CLI pagination after SSH reconnect: %w", err)
	}

	s.connectionMu.Lock()
	if s.closed {
		s.connectionMu.Unlock()
		_ = conn.Close()
		return net.ErrClosed
	}
	stale := s.Connection
	s.Connection = conn
	s.connectionMu.Unlock()
	if stale != nil && stale != conn {
		_ = stale.Close()
	}

	s.reconnectCount.Add(1)
	return nil
}

func (s *Client) ReconnectCount() int64 {
	return s.reconnectCount.Load()
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
		return DeviceMetadata{}, errors.New("show version did not identify a supported Cisco OS (IOS, IOS XE, or NX-OS)")
	}

	return metadata, nil
}

func detectOSTypeFromShowVersion(output string) string {
	if showVersionFailureLine.MatchString(output) {
		return ""
	}
	switch {
	case iosXEShowVersionSignature.MatchString(output):
		return "IOS XE"
	case nxOSShowVersionSignature.MatchString(output):
		return "NX-OS"
	case iosShowVersionSignature.MatchString(output), classicIOSShowVersionPair.MatchString(output):
		return "IOS"
	default:
		return ""
	}
}

// Close closes SSH connection
func (s *Client) Close() error {
	s.connectionMu.Lock()
	conn := s.Connection
	s.Connection = nil
	s.closed = true
	s.connectionMu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}
