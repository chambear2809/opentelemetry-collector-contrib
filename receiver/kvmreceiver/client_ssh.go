// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kvmreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kvmreceiver"

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/digitalocean/go-libvirt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	defaultSSHPort     = "22"
	defaultSSHTimeout  = 20 * time.Second
	defaultLibvirtSock = "/var/run/libvirt/libvirt-sock"
)

type sshSocketDialer struct {
	host           string
	port           string
	username       string
	password       string
	keyFile        string
	knownHostsFile string
	remoteSocket   string
	timeout        time.Duration
	insecure       bool
	mu             sync.Mutex
	connection     io.Closer
}

type sshLibvirtClient struct {
	*libvirt.Libvirt
	dialer *sshSocketDialer
}

func (c *sshLibvirtClient) Disconnect() error {
	return errors.Join(c.Libvirt.Disconnect(), c.dialer.Close())
}

func connectLibvirtSSH(uri *url.URL) (libvirtClient, error) {
	dialer, err := newSSHSocketDialer(uri)
	if err != nil {
		return nil, err
	}

	client := libvirt.NewWithDialer(dialer)
	if err := client.ConnectToURI(libvirt.RemoteURI(uri)); err != nil {
		_ = dialer.Close()
		return nil, fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	return &sshLibvirtClient{Libvirt: client, dialer: dialer}, nil
}

func newSSHSocketDialer(uri *url.URL) (*sshSocketDialer, error) {
	if err := validateSSHURI(uri); err != nil {
		return nil, err
	}

	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("resolve current user: %w", err)
	}

	username := currentUser.Username
	password := ""
	if uri.User != nil {
		if value := uri.User.Username(); value != "" {
			username = value
		}
		password, _ = uri.User.Password()
	}

	port := uri.Port()
	if port == "" {
		port = defaultSSHPort
	}

	remoteSocket := uri.Query().Get("socket")
	if remoteSocket == "" {
		remoteSocket = defaultLibvirtSock
	}

	keyFile := uri.Query().Get("keyfile")
	if keyFile == "" {
		keyFile = defaultSSHKeyFile(currentUser.HomeDir)
	}

	insecure, err := parseNoVerify(uri.Query().Get("no_verify"))
	if err != nil {
		return nil, err
	}

	return &sshSocketDialer{
		host:           uri.Hostname(),
		port:           port,
		username:       username,
		password:       password,
		keyFile:        keyFile,
		knownHostsFile: filepath.Join(currentUser.HomeDir, ".ssh", "known_hosts"),
		remoteSocket:   remoteSocket,
		timeout:        defaultSSHTimeout,
		insecure:       insecure,
	}, nil
}

func validateSSHURI(uri *url.URL) error {
	if uri.Hostname() == "" {
		return errors.New("ssh endpoint must include a host")
	}
	if _, err := parseNoVerify(uri.Query().Get("no_verify")); err != nil {
		return err
	}
	if err := validateSSHMode(uri.Query().Get("mode")); err != nil {
		return err
	}
	for _, field := range []string{"known_hosts", "known_hosts_verify", "sshauth"} {
		if uri.Query().Get(field) != "" {
			return fmt.Errorf("%s option is not supported with the ssh transport", field)
		}
	}
	return nil
}

func (d *sshSocketDialer) Dial() (net.Conn, error) {
	hostKeyCallback, err := d.hostKeyCallback()
	if err != nil {
		return nil, err
	}

	authMethods, agentConnection, authErrors := d.authMethods()
	config := &ssh.ClientConfig{
		User:            d.username,
		HostKeyCallback: hostKeyCallback,
		Auth:            authMethods,
		Timeout:         d.timeout,
	}

	sshClient, err := ssh.Dial("tcp", net.JoinHostPort(d.host, d.port), config)
	if err != nil {
		closeIfNotNil(agentConnection)
		return nil, errors.Join(append([]error{err}, authErrors...)...)
	}

	stream, err := sshClient.Dial("unix", d.remoteSocket)
	if err != nil {
		_ = sshClient.Close()
		closeIfNotNil(agentConnection)
		return nil, fmt.Errorf("connect to remote libvirt socket %s: %w", d.remoteSocket, err)
	}

	connection := &sshStreamConn{
		Conn:   stream,
		parent: sshClient,
		agent:  agentConnection,
	}
	d.mu.Lock()
	d.connection = connection
	d.mu.Unlock()
	return connection, nil
}

func (d *sshSocketDialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.connection == nil {
		return nil
	}
	err := d.connection.Close()
	d.connection = nil
	return err
}

func (d *sshSocketDialer) hostKeyCallback() (ssh.HostKeyCallback, error) {
	if d.insecure {
		return ssh.InsecureIgnoreHostKey(), nil //nolint:gosec
	}
	callback, err := knownhosts.New(d.knownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("load SSH known hosts file %s: %w", d.knownHostsFile, err)
	}
	return callback, nil
}

func (d *sshSocketDialer) authMethods() ([]ssh.AuthMethod, io.Closer, []error) {
	var (
		signers         []ssh.Signer
		agentConnection io.Closer
		authErrors      []error
	)

	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		connection, err := net.DialTimeout("unix", socket, d.timeout)
		if err != nil {
			authErrors = append(authErrors, fmt.Errorf("connect to SSH agent: %w", err))
		} else {
			agentSigners, signerErr := agent.NewClient(connection).Signers()
			if signerErr != nil {
				_ = connection.Close()
				authErrors = append(authErrors, fmt.Errorf("get SSH agent signers: %w", signerErr))
			} else {
				agentConnection = connection
				signers = append(signers, agentSigners...)
			}
		}
	}

	if d.keyFile != "" {
		key, err := os.ReadFile(d.keyFile)
		if err != nil {
			authErrors = append(authErrors, fmt.Errorf("read SSH key %s: %w", d.keyFile, err))
		} else if signer, parseErr := ssh.ParsePrivateKey(key); parseErr != nil {
			authErrors = append(authErrors, fmt.Errorf("parse SSH key %s: %w", d.keyFile, parseErr))
		} else {
			signers = append(signers, signer)
		}
	}

	methods := make([]ssh.AuthMethod, 0, 2)
	if len(signers) > 0 {
		methods = append(methods, ssh.PublicKeys(signers...))
	}
	if d.password != "" {
		methods = append(methods, ssh.Password(d.password))
	}
	return methods, agentConnection, authErrors
}

type sshStreamConn struct {
	net.Conn
	parent io.Closer
	agent  io.Closer
	once   sync.Once
	err    error
}

func (c *sshStreamConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		closeIfNotNil(c.parent)
		closeIfNotNil(c.agent)
	})
	return c.err
}

func closeIfNotNil(closer io.Closer) {
	if closer != nil {
		_ = closer.Close()
	}
}

func defaultSSHKeyFile(homeDir string) string {
	for _, name := range []string{"identity", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"} {
		path := filepath.Join(homeDir, ".ssh", name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func parseNoVerify(value string) (bool, error) {
	if value == "" {
		return false, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return false, fmt.Errorf("invalid no_verify value %q: %w", value, err)
	}
	return parsed != 0, nil
}

func validateSSHMode(mode string) error {
	switch strings.ToLower(mode) {
	case "", "legacy", "auto":
		return nil
	case "direct":
		return errors.New("cannot connect in direct mode")
	default:
		return fmt.Errorf("invalid SSH mode %q", mode)
	}
}
