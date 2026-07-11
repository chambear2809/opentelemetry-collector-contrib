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

var (
	// ErrSSHCommandOutputTooLarge marks a command that received device output
	// but exceeded the configured in-memory capture bound.
	ErrSSHCommandOutputTooLarge = errors.New("SSH command output exceeds limit")
	// ErrCiscoCLICommandRejected marks a bounded Cisco CLI rejection without
	// retaining or exposing the device's raw output.
	ErrCiscoCLICommandRejected = errors.New("Cisco CLI command rejected")
)

var (
	iosXEShowVersionSignature = regexp.MustCompile(`(?im)^\s*(?:cisco ios xe software|cisco ios software[^\r\n]*(?:\bios[- ]?xe software\b|(?:\b|_)iosxe\b))[^\r\n]*\bversion\s+\S+`)
	iosShowVersionSignature   = regexp.MustCompile(`(?im)^\s*cisco ios software[^\r\n]*\bversion\s+\S+`)
	// Older IOS releases split the product banner and the version-bearing image
	// line. Requiring the adjacent, structured pair avoids treating login-banner
	// prose containing the well-known product name as command output.
	classicIOSShowVersionPair = regexp.MustCompile(`(?im)^[ \t]*cisco internetwork operating system software[ \t]*\r?\n[ \t]*(?:cisco[ \t]+)?ios[ \t]*\([ \t]*tm[ \t]*\)[ \t]+(?:[a-z0-9][a-z0-9._+/\-]*[ \t]+)+software[ \t]+\([a-z0-9][a-z0-9._+\-]*\),[ \t]+(?:experimental[ \t]+)?version[ \t]+([^,\s]+)(?:[ \t]+\[[^\]\r\n]+\])?(?:,[^\r\n]*)?[ \t]*\r?$`)
	nxOSShowVersionSignature  = regexp.MustCompile(`(?im)(?:^\s*(?:nxos|host nxos|system|kickstart):\s*version\s+\S+|^\s*cisco nx-os[^\r\n]*\bversion\s+\S+)`)
	ciscoCLIRejectionLine     = regexp.MustCompile(`(?im)^[ \t]*%?[ \t]*(?:authorization failed|command authorization failed|not authorized|permission denied|invalid (?:input(?: detected)?|command)|incomplete command|ambiguous command|unknown command|unrecognized command)\b`)
	ciscoCLIPromptLine        = regexp.MustCompile(`^\S+[>#]\s*$`)
	ciscoCLIExitLine          = regexp.MustCompile(`^\S+[>#]\s*exit\s*$`)
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
	deviceMetadata atomic.Pointer[DeviceMetadata]
	metadataStore  *DeviceMetadataStore
	connectionMu   sync.Mutex
	reconnectMu    sync.Mutex
	closed         bool
	forceShell     atomic.Bool
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

// ErrorIndicatesCommandResponse reports whether an error proves that the
// device returned a command response, even though the response was unusable.
func ErrorIndicatesCommandResponse(err error) bool {
	return errors.Is(err, ErrCiscoCLICommandRejected) || errors.Is(err, ErrSSHCommandOutputTooLarge)
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

func (s *Client) usesInteractiveShell() bool {
	return s.EnablePassword != "" || s.forceShell.Load()
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
	if s.usesInteractiveShell() {
		return s.executeCommandInShell(ctx, command, s.EnablePassword != "")
	}
	output, err := s.executeCommand(ctx, command, false)
	if err != nil && shouldRetryWithInteractiveShell(err) {
		s.forceShell.Store(true)
		return s.executeCommandInShell(ctx, command, false)
	}
	if err == nil && outputNeedsInteractiveShell(output) {
		s.forceShell.Store(true)
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
		stdoutOutput := stdout.String()
		stderrOutput := stderr.String()
		out := stdoutOutput + stderrOutput
		// Explicit Cisco CLI rejection lines remain errors, even when the device
		// reports exit status zero, so optional collectors can try aliases and
		// record scrape health. Paging initialization deliberately ignores device
		// exit status and rejection text for compatibility.
		if !ignoreExitStatus && (ciscoCLIRejectionLine.MatchString(stdoutOutput) || ciscoCLIRejectionLine.MatchString(stderrOutput)) {
			var exitErr *cryptossh.ExitError
			if errors.As(execErr, &exitErr) {
				execErr = fmt.Errorf("%w (exit status %d)", ErrCiscoCLICommandRejected, exitErr.ExitStatus())
			} else {
				execErr = ErrCiscoCLICommandRejected
			}
		} else if execErr != nil {
			var exitErr *cryptossh.ExitError
			if errors.As(execErr, &exitErr) {
				switch {
				case ignoreExitStatus:
					// Paging setup deliberately tolerates any device exit status.
					execErr = nil
				case out != "":
					// Device returned ordinary output with a non-zero exit.
					execErr = nil
				}
			}
		}
		resultChan <- result{out, execErr}
	}()

	select {
	case r := <-resultChan:
		session.Close()
		if outputLimit.Exceeded() {
			return "", fmt.Errorf("%w: limit is %d bytes", ErrSSHCommandOutputTooLarge, s.commandOutputLimit())
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
		return "", fmt.Errorf("%w: limit is %d bytes", ErrSSHCommandOutputTooLarge, s.commandOutputLimit())
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
	return s.executeCommandInShellWithSession(ctx, session, command, enable)
}

// executeCommandInShellWithSession executes an interactive command on a
// session that has already been opened. Reconnect uses this helper to
// initialize and identify a candidate connection without routing back through
// newSession while reconnectMu is held.
func (s *Client) executeCommandInShellWithSession(ctx context.Context, session *cryptossh.Session, command string, enable bool) (string, error) {
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
		stdoutOutput := stdout.String()
		stderrOutput := stderr.String()
		out := stdoutOutput + stderrOutput
		if writeErr != nil {
			resultChan <- result{out, writeErr}
			return
		}
		classifiedOutput, rejected := classifyInteractiveCiscoCLIOutput(stdoutOutput, stderrOutput)
		if rejected {
			resultChan <- result{"", ErrCiscoCLICommandRejected}
			return
		}
		out = classifiedOutput
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
			return "", fmt.Errorf("%w: limit is %d bytes", ErrSSHCommandOutputTooLarge, s.commandOutputLimit())
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
		return "", fmt.Errorf("%w: limit is %d bytes", ErrSSHCommandOutputTooLarge, s.commandOutputLimit())
	}
}

// classifyInteractiveCiscoCLIOutput distinguishes rejection of the requested
// command from a tolerated rejection of the paging setup command that is sent
// first in the same shell. When the final rejection line has substantive
// output after it, that later output belongs to the requested command and the
// paging diagnostic is removed. A final rejection with only a prompt/caret is
// treated as rejection of the requested command.
func classifyInteractiveCiscoCLIOutput(stdout, stderr string) (string, bool) {
	output := stdout
	if output != "" && stderr != "" && !strings.HasSuffix(output, "\n") {
		output += "\n"
	}
	output += stderr
	matches := ciscoCLIRejectionLine.FindAllStringIndex(output, -1)
	if len(matches) == 0 {
		return output, false
	}

	lastRejection := matches[len(matches)-1]
	tailStart := len(output)
	if newline := strings.IndexByte(output[lastRejection[0]:], '\n'); newline >= 0 {
		tailStart = lastRejection[0] + newline + 1
	}
	tail := output[tailStart:]
	for line := range strings.Lines(tail) {
		line = strings.TrimSpace(line)
		if line == "" || line == "^" || strings.EqualFold(line, "exit") || ciscoCLIPromptLine.MatchString(line) || ciscoCLIExitLine.MatchString(line) {
			continue
		}
		return tail, false
	}
	return "", true
}

func outputNeedsInteractiveShell(output string) bool {
	return strings.Contains(strings.ToLower(output), "line has invalid autocommand")
}

func shouldRetryWithInteractiveShell(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "failed to disable cli pagination after ssh reconnect") {
		return false
	}
	return strings.Contains(message, "failed to create ssh session") ||
		strings.Contains(message, "failed to reconnect after session creation failed") ||
		strings.Contains(message, "command execution timeout") ||
		strings.Contains(message, "broken pipe") ||
		strings.Contains(message, "connection reset") ||
		strings.Contains(message, "eof")
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

	// Interactive-shell mode already prepends "terminal length 0" inside the
	// PTY-backed command session, so repeating the standalone exec request here
	// is redundant and can destabilize some IOS XE devices.
	if !s.usesInteractiveShell() {
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
	}

	// Device identity can change behind a stable target after a failover or
	// replacement. Refresh it on the private candidate connection before that
	// connection becomes visible. Opening the session directly is important:
	// DetectDeviceMetadata routes through newSession and would recursively enter
	// reconnect while reconnectMu is held.
	var refreshedMetadata *DeviceMetadata
	if s.deviceMetadata.Load() != nil {
		metadata, metadataErr := s.detectDeviceMetadataOnConnection(ctx, conn)
		if metadataErr != nil {
			_ = conn.Close()
			return fmt.Errorf("failed to refresh device metadata after SSH reconnect: %w", metadataErr)
		}
		refreshedMetadata = &metadata
	}

	s.connectionMu.Lock()
	if s.closed {
		s.connectionMu.Unlock()
		_ = conn.Close()
		return net.ErrClosed
	}
	stale := s.Connection
	if refreshedMetadata != nil {
		s.storeDeviceMetadata(*refreshedMetadata)
	}
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

func (s *Client) currentDeviceMetadata() (DeviceMetadata, bool) {
	metadata := s.deviceMetadata.Load()
	if metadata == nil {
		return DeviceMetadata{}, false
	}
	return *metadata, true
}

func (s *Client) storeDeviceMetadata(metadata DeviceMetadata) {
	s.deviceMetadata.Store(&metadata)
	s.metadataStore.Store(metadata)
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

	metadata, err := deviceMetadataFromShowVersion(output, time.Now())
	if err != nil {
		return DeviceMetadata{}, err
	}
	return metadata, nil
}

func (s *Client) detectDeviceMetadataOnConnection(ctx context.Context, conn *cryptossh.Client) (DeviceMetadata, error) {
	var (
		output string
		err    error
	)
	if s.usesInteractiveShell() {
		var session *cryptossh.Session
		session, err = s.openSession(ctx, conn)
		if err == nil {
			output, err = s.executeCommandInShellWithSession(ctx, session, "show version", s.EnablePassword != "")
		}
	} else {
		var session *cryptossh.Session
		session, err = s.openSession(ctx, conn)
		if err == nil {
			output, err = s.executeCommandWithSession(ctx, session, "show version", false)
		}
	}
	if err != nil {
		return DeviceMetadata{}, fmt.Errorf("failed to execute 'show version': %w", err)
	}
	return deviceMetadataFromShowVersion(output, time.Now())
}

func deviceMetadataFromShowVersion(output string, detectedAt time.Time) (DeviceMetadata, error) {
	metadata := parseDeviceMetadataFromShowVersion(output, detectedAt)
	if metadata.OSType == "" {
		return DeviceMetadata{}, errors.New("show version did not identify a supported Cisco OS (IOS, IOS XE, or NX-OS)")
	}
	return metadata, nil
}

func detectOSTypeFromShowVersion(output string) string {
	if ciscoCLIRejectionLine.MatchString(output) {
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
