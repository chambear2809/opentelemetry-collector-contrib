// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/websocket"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

const (
	pxGridDefaultPath      = "/pxgrid"
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
	nodeName  string
	tlsConfig *tls.Config
	userAgent string
}

// PxGridSubscription identifies a service and the ServiceLookup property that
// contains its topic. AlternateTopicProperties supports documented services
// that advertise more than one compatible event topic across ISE versions.
// Topic destinations must always come from ServiceLookup; callers must never
// put a hard-coded STOMP destination in this descriptor.
type PxGridSubscription struct {
	Service                  string
	TopicProperty            string
	AlternateTopicProperties []string
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
		nodeName:  cfg.NodeName,
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

// PostObjects discovers the requested pxGrid service, obtains an access secret
// for the service node, and posts to its advertised restBaseUrl.
func (c *PxGridClient) PostObjects(ctx context.Context, operation, service, path string, payload any, maxResults int) ([]Object, error) {
	if strings.TrimSpace(service) == "" {
		return nil, errors.New("pxGrid REST service is required")
	}
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("pxGrid REST operation path is required")
	}
	services, err := c.ServiceLookup(ctx, service)
	if err != nil {
		return nil, fmt.Errorf("discover pxGrid REST service %q: %w", service, err)
	}
	if len(services) == 0 {
		return nil, fmt.Errorf("pxGrid REST service %q is unavailable", service)
	}

	var attempts []error
	for _, discovered := range services {
		peerNodeName := strings.TrimSpace(String(discovered, "nodeName"))
		restBaseURL := strings.TrimSpace(pxGridServiceProperty(discovered, "restBaseUrl"))
		if peerNodeName == "" || restBaseURL == "" {
			attempts = append(attempts, errors.New("service entry is missing nodeName or properties.restBaseUrl"))
			continue
		}
		if err := validatePxGridURL(restBaseURL, "http", "https"); err != nil {
			attempts = append(attempts, fmt.Errorf("service node %q: %w", peerNodeName, err))
			continue
		}
		secret, err := c.accessSecret(ctx, peerNodeName)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			attempts = append(attempts, fmt.Errorf("service node %q access secret: %w", peerNodeName, err))
			continue
		}
		serviceClient, err := c.discoveredRESTClient(restBaseURL, secret)
		if err != nil {
			attempts = append(attempts, fmt.Errorf("service node %q REST client: %w", peerNodeName, err))
			continue
		}
		objects, err := serviceClient.PostQuery(ctx, operation, path, payload, maxResults)
		if err == nil {
			return objects, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		attempts = append(attempts, fmt.Errorf("service node %q request: %w", peerNodeName, err))
	}
	return nil, fmt.Errorf("pxGrid REST service %q has no usable endpoint: %w", service, errors.Join(attempts...))
}

// Version returns the pxGrid controller version.
func (c *PxGridClient) Version(ctx context.Context) (Object, error) {
	return c.rest.GetObject(ctx, "pxgrid.version", "/control/version", nil)
}

// Subscribe discovers a service's advertised topic and pubsub endpoint, then
// subscribes until ctx is cancelled. Calling Subscribe again performs fresh
// discovery so reconnects pick up ISE service changes.
func (c *PxGridClient) Subscribe(ctx context.Context, subscription PxGridSubscription, handler func(StompMessage)) error {
	service := strings.TrimSpace(subscription.Service)
	if service == "" {
		return errors.New("pxGrid subscription service is required")
	}
	if handler == nil {
		return errors.New("pxGrid subscription handler is required")
	}
	topicProperties := subscription.topicProperties()
	if len(topicProperties) == 0 {
		return fmt.Errorf("pxGrid subscription service %q has no documented topic property", service)
	}
	services, err := c.ServiceLookup(ctx, service)
	if err != nil {
		return fmt.Errorf("discover pxGrid subscription service %q: %w", service, err)
	}
	if len(services) == 0 {
		return fmt.Errorf("pxGrid subscription service %q is unavailable", service)
	}

	var attempts []error
	for _, discovered := range services {
		pubSubService := strings.TrimSpace(pxGridServiceProperty(discovered, "wsPubsubService"))
		topic, topicProperty := firstPxGridServiceProperty(discovered, topicProperties...)
		if pubSubService == "" || topic == "" {
			attempts = append(attempts, fmt.Errorf("service entry is missing properties.wsPubsubService or topic property %s", strings.Join(topicProperties, ", ")))
			continue
		}
		pubSubServices, lookupErr := c.ServiceLookup(ctx, pubSubService)
		if lookupErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			attempts = append(attempts, fmt.Errorf("discover pubsub service %q: %w", pubSubService, lookupErr))
			continue
		}
		if len(pubSubServices) == 0 {
			attempts = append(attempts, fmt.Errorf("pubsub service %q is unavailable", pubSubService))
			continue
		}
		for _, pubSub := range pubSubServices {
			peerNodeName := strings.TrimSpace(String(pubSub, "nodeName"))
			wsURL := strings.TrimSpace(pxGridServiceProperty(pubSub, "wsUrl"))
			if peerNodeName == "" || wsURL == "" {
				attempts = append(attempts, fmt.Errorf("pubsub service %q is missing nodeName or properties.wsUrl", pubSubService))
				continue
			}
			if err := validatePxGridURL(wsURL, "ws", "wss"); err != nil {
				attempts = append(attempts, fmt.Errorf("pubsub node %q: %w", peerNodeName, err))
				continue
			}
			secret, secretErr := c.accessSecret(ctx, peerNodeName)
			if secretErr != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				attempts = append(attempts, fmt.Errorf("pubsub node %q access secret: %w", peerNodeName, secretErr))
				continue
			}
			if err := c.subscribeEndpoint(ctx, wsURL, peerNodeName, secret, topic, handler); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				attempts = append(attempts, fmt.Errorf("pubsub node %q topic property %q: %w", peerNodeName, topicProperty, err))
				continue
			}
			return nil
		}
	}
	return fmt.Errorf("pxGrid subscription service %q has no usable endpoint for topic properties [%s]: %w", service, strings.Join(topicProperties, ", "), errors.Join(attempts...))
}

func (c *PxGridClient) subscribeEndpoint(ctx context.Context, wsURL, peerNodeName, secret, topic string, handler func(StompMessage)) error {
	config, err := websocket.NewConfig(wsURL, pxGridDefaultWSOrigin)
	if err != nil {
		return err
	}
	config.TlsConfig = c.tlsConfig
	config.Header = http.Header{
		"Authorization": []string{"Basic " + base64.StdEncoding.EncodeToString([]byte(c.nodeName+":"+secret))},
		"User-Agent":    []string{c.userAgent},
	}
	config.Protocol = []string{"v12.stomp"}
	ws, err := config.DialContext(ctx)
	if err != nil {
		return err
	}
	defer ws.Close()
	ws.MaxPayloadBytes = int(httpclient.MaxResponseBodySize)

	if err := writeSTOMP(ws, "CONNECT", map[string]string{
		"accept-version": "1.2",
		"host":           peerNodeName,
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
	type readResult struct {
		frame stompFrame
		err   error
	}
	readCh := make(chan readResult, 1)
	go func() {
		for {
			frame, readErr := readSTOMP(ws)
			if readErr != nil {
				select {
				case readCh <- readResult{err: readErr}:
				case <-ctx.Done():
				}
				return
			}
			select {
			case readCh <- readResult{frame: frame}:
			case <-ctx.Done():
				return
			}
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
		case result := <-readCh:
			if result.err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return result.err
			}
			frame := result.frame
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

func (s PxGridSubscription) topicProperties() []string {
	properties := make([]string, 0, 1+len(s.AlternateTopicProperties))
	seen := map[string]struct{}{}
	for _, property := range append([]string{s.TopicProperty}, s.AlternateTopicProperties...) {
		property = strings.TrimSpace(property)
		if property == "" {
			continue
		}
		normalized := strings.ToLower(property)
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		properties = append(properties, property)
	}
	return properties
}

func pxGridServiceProperty(service Object, property string) string {
	properties, ok := service["properties"]
	if !ok {
		for key, value := range service {
			if strings.EqualFold(key, "properties") {
				properties = value
				ok = true
				break
			}
		}
	}
	if !ok {
		return ""
	}
	switch typed := properties.(type) {
	case Object:
		return String(typed, property)
	case map[string]any:
		return String(Object(typed), property)
	case map[string]string:
		for key, value := range typed {
			if strings.EqualFold(key, property) {
				return value
			}
		}
	}
	return ""
}

func firstPxGridServiceProperty(service Object, properties ...string) (string, string) {
	for _, property := range properties {
		if value := strings.TrimSpace(pxGridServiceProperty(service, property)); value != "" {
			return value, property
		}
	}
	return "", ""
}

func validatePxGridURL(rawURL string, allowedSchemes ...string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return fmt.Errorf("invalid discovered pxGrid URL %q", rawURL)
	}
	for _, scheme := range allowedSchemes {
		if strings.EqualFold(parsed.Scheme, scheme) {
			return nil
		}
	}
	return fmt.Errorf("discovered pxGrid URL %q must use %s", rawURL, strings.Join(allowedSchemes, " or "))
}

func (c *PxGridClient) accessSecret(ctx context.Context, peerNodeName string) (string, error) {
	secretObject, err := c.AccessSecret(ctx, peerNodeName)
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(String(secretObject, "secret"))
	if secret == "" {
		return "", errors.New("pxGrid AccessSecret response did not contain a secret")
	}
	return secret, nil
}

func (c *PxGridClient) discoveredRESTClient(endpoint, secret string) (*Client, error) {
	client, err := NewClient(Config{
		Endpoint:           endpoint,
		Username:           c.nodeName,
		Password:           secret,
		AllowEmptyPassword: false,
		UserAgent:          c.userAgent,
		Timeout:            c.rest.client.Timeout,
		MaxRetries:         c.rest.retries,
		PageSize:           c.rest.pageSize,
	})
	if err != nil {
		return nil, err
	}
	// Reuse the authenticated client's TLS transport so certificate-based
	// pxGrid accounts and private CA configuration apply to discovered nodes.
	client.client.Transport = c.rest.client.Transport
	client.OnRequest = c.rest.OnRequest
	return client, nil
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
