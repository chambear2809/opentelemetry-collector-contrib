// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/websocket"
)

const (
	pxGridDefaultPath      = "/pxgrid"
	pxGridPubSubPath       = "/pxgrid/ise/pubsub"
	pxGridDefaultWSOrigin  = "https://localhost/"
	stompHeartbeatInterval = 30 * time.Second
)

// PxGridConfig controls the Cisco ISE pxGrid client.
type PxGridConfig struct {
	Endpoint           string
	NodeName           string
	Password           string
	CertFile           string
	KeyFile            string
	CAFile             string
	ServerName         string
	InsecureSkipVerify bool
	Timeout            time.Duration
	UserAgent          string
	MaxRetries         int
}

// PxGridClient is a small pxGrid REST and WebSocket/STOMP client.
type PxGridClient struct {
	rest      *Client
	endpoint  *url.URL
	nodeName  string
	password  string
	tlsConfig *tls.Config
	userAgent string
}

// StompMessage is a decoded pxGrid STOMP MESSAGE frame.
type StompMessage struct {
	Topic     string
	MessageID string
	Headers   map[string]string
	Body      []byte
}

// NewPxGridClient creates a pxGrid client.
func NewPxGridClient(cfg PxGridConfig) (*PxGridClient, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("pxGrid endpoint is required")
	}
	parsed, err := url.Parse(cfg.Endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid pxGrid endpoint %q", cfg.Endpoint)
	}
	if cfg.NodeName == "" {
		return nil, errors.New("pxGrid node name is required")
	}
	if cfg.Password == "" && (cfg.CertFile == "" || cfg.KeyFile == "") {
		return nil, errors.New("pxGrid password or client certificate/key is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	tlsConfig, err := pxGridTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	rest, err := NewClient(Config{
		Endpoint:           pxGridRESTEndpoint(parsed).String(),
		Username:           cfg.NodeName,
		Password:           cfg.Password,
		AllowEmptyPassword: true,
		UserAgent:          cfg.UserAgent,
		Timeout:            timeout,
		MaxRetries:         cfg.MaxRetries,
		PageSize:           defaultPageSize,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	})
	if err != nil {
		return nil, err
	}
	rest.client.Transport = transport
	if cfg.Password == "" {
		rest.password = ""
	}
	userAgent := cfg.UserAgent
	if userAgent == "" {
		userAgent = defaultUserAgent
	}
	return &PxGridClient{
		rest:      rest,
		endpoint:  parsed,
		nodeName:  cfg.NodeName,
		password:  cfg.Password,
		tlsConfig: tlsConfig,
		userAgent: userAgent,
	}, nil
}

// CloseIdleConnections closes idle HTTP connections held by the pxGrid REST client.
func (c *PxGridClient) CloseIdleConnections() {
	c.rest.CloseIdleConnections()
}

// SetOnRequest records pxGrid REST request attempts through the shared ISE request stat shape.
func (c *PxGridClient) SetOnRequest(fn func(RequestStat)) {
	c.rest.OnRequest = fn
}

// AccountActivate asks pxGrid to activate this client account.
func (c *PxGridClient) AccountActivate(ctx context.Context) (Object, error) {
	return c.rest.PostObject(ctx, "pxgrid.account_activate", "/control/AccountActivate", map[string]any{})
}

// ServiceLookup looks up pxGrid services.
func (c *PxGridClient) ServiceLookup(ctx context.Context, service string) ([]Object, error) {
	return c.rest.PostQuery(ctx, "pxgrid.service_lookup", "/control/ServiceLookup", map[string]any{"name": service}, 0)
}

// AccessSecret requests an access secret for a pxGrid peer.
func (c *PxGridClient) AccessSecret(ctx context.Context, peerNodeName string) (Object, error) {
	return c.rest.PostObject(ctx, "pxgrid.access_secret", "/control/AccessSecret", map[string]any{"peerNodeName": peerNodeName})
}

// PostObjects posts a pxGrid REST query payload and returns normalized objects.
func (c *PxGridClient) PostObjects(ctx context.Context, operation, path string, payload any, maxResults int) ([]Object, error) {
	return c.rest.PostQuery(ctx, operation, path, payload, maxResults)
}

// Version returns the pxGrid controller version.
func (c *PxGridClient) Version(ctx context.Context) (Object, error) {
	return c.rest.GetObject(ctx, "pxgrid.version", "/control/version", nil)
}

// Subscribe subscribes to one pxGrid STOMP topic until ctx is cancelled.
func (c *PxGridClient) Subscribe(ctx context.Context, topic string, handler func(StompMessage)) error {
	if topic == "" {
		return errors.New("pxGrid topic cannot be empty")
	}
	wsURL := c.pubSubURL()
	config, err := websocket.NewConfig(wsURL, pxGridDefaultWSOrigin)
	if err != nil {
		return err
	}
	config.TlsConfig = c.tlsConfig
	config.Header = http.Header{"User-Agent": []string{c.userAgent}}
	config.Protocol = []string{"v12.stomp"}
	ws, err := websocket.DialConfig(config)
	if err != nil {
		return err
	}
	defer ws.Close()

	if err := writeSTOMP(ws, "CONNECT", map[string]string{
		"accept-version": "1.2",
		"host":           c.endpoint.Host,
		"login":          c.nodeName,
		"passcode":       c.password,
		"heart-beat":     "30000,30000",
	}, nil); err != nil {
		return err
	}
	frame, err := readSTOMP(ws)
	if err != nil {
		return err
	}
	if frame.command != "CONNECTED" {
		return fmt.Errorf("pxGrid STOMP expected CONNECTED, got %s", frame.command)
	}
	if err := writeSTOMP(ws, "SUBSCRIBE", map[string]string{
		"id":          topic,
		"destination": topic,
		"ack":         "auto",
	}, nil); err != nil {
		return err
	}

	heartbeat := time.NewTicker(stompHeartbeatInterval)
	defer heartbeat.Stop()
	errCh := make(chan error, 1)
	msgCh := make(chan stompFrame, 1)
	go func() {
		for {
			frame, readErr := readSTOMP(ws)
			if readErr != nil {
				errCh <- readErr
				return
			}
			msgCh <- frame
		}
	}()
	for {
		select {
		case <-ctx.Done():
			_ = writeSTOMP(ws, "DISCONNECT", map[string]string{}, nil)
			return ctx.Err()
		case <-heartbeat.C:
			if _, err := ws.Write([]byte("\n")); err != nil {
				return err
			}
		case err := <-errCh:
			return err
		case frame := <-msgCh:
			if frame.command == "ERROR" {
				return fmt.Errorf("pxGrid STOMP error: %s", string(frame.body))
			}
			if frame.command != "MESSAGE" {
				continue
			}
			handler(StompMessage{
				Topic:     firstNonEmpty(frame.headers["destination"], topic),
				MessageID: frame.headers["message-id"],
				Headers:   frame.headers,
				Body:      frame.body,
			})
		}
	}
}

func pxGridRESTEndpoint(endpoint *url.URL) *url.URL {
	result := *endpoint
	if result.Path == "" || result.Path == "/" {
		result.Path = pxGridDefaultPath
	}
	return &result
}

func (c *PxGridClient) pubSubURL() string {
	result := *c.endpoint
	switch result.Scheme {
	case "http":
		result.Scheme = "ws"
	default:
		result.Scheme = "wss"
	}
	result.Path = pxGridPubSubPath
	result.RawQuery = ""
	return result.String()
}

func pxGridTLSConfig(cfg PxGridConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{ServerName: cfg.ServerName} //nolint:gosec // InsecureSkipVerify is an explicit receiver setting below.
	if cfg.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true //nolint:gosec // Explicit opt-in for private ISE pxGrid appliances.
	}
	if cfg.CAFile != "" {
		caBytes, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("pxGrid CA file %s did not contain a PEM certificate", cfg.CAFile)
		}
		tlsConfig.RootCAs = pool
	}
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, errors.New("pxGrid cert_file and key_file must be provided together")
		}
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return tlsConfig, nil
}

type stompFrame struct {
	command string
	headers map[string]string
	body    []byte
}

func writeSTOMP(ws *websocket.Conn, command string, headers map[string]string, body []byte) error {
	var buffer bytes.Buffer
	buffer.WriteString(command)
	buffer.WriteByte('\n')
	for key, value := range headers {
		buffer.WriteString(key)
		buffer.WriteByte(':')
		buffer.WriteString(value)
		buffer.WriteByte('\n')
	}
	buffer.WriteByte('\n')
	buffer.Write(body)
	buffer.WriteByte(0)
	_, err := ws.Write(buffer.Bytes())
	return err
}

func readSTOMP(ws *websocket.Conn) (stompFrame, error) {
	var data []byte
	if err := websocket.Message.Receive(ws, &data); err != nil {
		return stompFrame{}, err
	}
	data = bytes.TrimLeft(data, "\n")
	data = bytes.TrimRight(data, "\x00")
	if len(data) == 0 {
		return stompFrame{command: "HEARTBEAT", headers: map[string]string{}}, nil
	}
	reader := bufio.NewReader(bytes.NewReader(data))
	command, err := reader.ReadString('\n')
	if err != nil {
		return stompFrame{}, err
	}
	frame := stompFrame{
		command: strings.TrimSpace(command),
		headers: map[string]string{},
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return stompFrame{}, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		key, value, found := strings.Cut(line, ":")
		if found {
			frame.headers[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	body, err := ioReadAll(reader)
	if err != nil {
		return stompFrame{}, err
	}
	frame.body = bytes.TrimRight(body, "\x00")
	return frame, nil
}

func ioReadAll(reader *bufio.Reader) ([]byte, error) {
	var buffer bytes.Buffer
	_, err := buffer.ReadFrom(reader)
	return buffer.Bytes(), err
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
