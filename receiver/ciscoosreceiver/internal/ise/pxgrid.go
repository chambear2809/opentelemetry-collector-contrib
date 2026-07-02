// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/websocket"
)

const (
	pxGridDefaultPath      = "/pxgrid"
	pxGridDefaultWSOrigin  = "https://localhost/"
	stompHeartbeatInterval = 30 * time.Second
	stompMaxFrameBytes     = 4 * 1024 * 1024
	stompMaxBodyBytes      = 4 * 1024 * 1024
	stompMaxHeaders        = 256
	stompMaxHeaderBytes    = 64 * 1024
	stompMaxLineBytes      = 8 * 1024
)

// PxGridConfig controls the Cisco ISE pxGrid client.
type PxGridConfig struct {
	Endpoint              string
	NodeName              string
	Password              string
	CertFile              string
	KeyFile               string
	CAFile                string
	ServerName            string
	InsecureSkipVerify    bool
	AllowedServiceHosts   []string
	AllowedServiceOrigins []string
	Timeout               time.Duration
	UserAgent             string
	MaxRetries            int
}

// PxGridClient is a small pxGrid REST and WebSocket/STOMP client.
type PxGridClient struct {
	rest                  *Client
	nodeName              string
	tlsConfig             *tls.Config
	userAgent             string
	ioTimeout             time.Duration
	allowedServiceOrigins map[string]struct{}
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
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("invalid pxGrid endpoint")
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return nil, errors.New("pxGrid endpoint must use https")
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
	allowedServiceOrigins := make(map[string]struct{}, 2+len(cfg.AllowedServiceHosts)*2+len(cfg.AllowedServiceOrigins))
	controlPort := pxGridOriginPort(parsed)
	addPxGridOriginPair(allowedServiceOrigins, normalizePxGridHost(parsed.Hostname()), controlPort)
	for _, host := range cfg.AllowedServiceHosts {
		normalized := normalizePxGridHost(host)
		if normalized == "" {
			return nil, fmt.Errorf("invalid empty pxGrid allowed service host %q", host)
		}
		addPxGridOriginPair(allowedServiceOrigins, normalized, controlPort)
	}
	for _, origin := range cfg.AllowedServiceOrigins {
		canonical, err := canonicalPxGridOriginString(origin)
		if err != nil {
			return nil, fmt.Errorf("invalid pxGrid allowed service origin: %w", err)
		}
		allowedServiceOrigins[canonical] = struct{}{}
	}
	return &PxGridClient{
		rest:                  rest,
		nodeName:              cfg.NodeName,
		tlsConfig:             tlsConfig,
		userAgent:             userAgent,
		ioTimeout:             timeout,
		allowedServiceOrigins: allowedServiceOrigins,
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
		if err := c.validateDiscoveredURL(restBaseURL, "https"); err != nil {
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
func (c *PxGridClient) Subscribe(ctx context.Context, subscription PxGridSubscription, handler func(StompMessage) error) error {
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
			if err := c.validateDiscoveredURL(wsURL, "wss"); err != nil {
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

func (c *PxGridClient) subscribeEndpoint(ctx context.Context, wsURL, peerNodeName, secret, topic string, handler func(StompMessage) error) error {
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
	ws.MaxPayloadBytes = stompMaxFrameBytes

	if err := writeSTOMPContext(ctx, ws, c.ioTimeout, "CONNECT", map[string]string{
		"accept-version": "1.2",
		"host":           peerNodeName,
		"heart-beat":     "30000,30000",
	}, nil); err != nil {
		return err
	}
	frame, err := readSTOMPContext(ctx, ws, c.ioTimeout)
	if err != nil {
		return err
	}
	if frame.command != "CONNECTED" {
		return fmt.Errorf("pxGrid STOMP expected CONNECTED, got %s", frame.command)
	}
	if err := writeSTOMPContext(ctx, ws, c.ioTimeout, "SUBSCRIBE", map[string]string{
		"id":          topic,
		"destination": topic,
		"ack":         "client-individual",
	}, nil); err != nil {
		return err
	}

	heartbeat := time.NewTicker(stompHeartbeatInterval)
	defer heartbeat.Stop()
	readCtx, cancelRead := context.WithCancel(ctx)
	type readResult struct {
		frame stompFrame
		err   error
	}
	readCh := make(chan readResult, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			frame, readErr := readSTOMPWithDeadline(ws, maxDuration(c.ioTimeout, 2*stompHeartbeatInterval))
			if readErr != nil {
				select {
				case readCh <- readResult{err: readErr}:
				case <-readCtx.Done():
				}
				return
			}
			select {
			case readCh <- readResult{frame: frame}:
			case <-readCtx.Done():
				return
			}
		}
	}()
	defer func() {
		// The reader belongs to this subscription attempt. Cancel pending channel
		// delivery, close the socket to interrupt a blocked WebSocket read, and
		// join the goroutine before the caller starts another endpoint attempt.
		cancelRead()
		_ = ws.Close()
		<-readerDone
	}()
	for {
		select {
		case <-ctx.Done():
			// Closing the socket is the only reliable way to interrupt a peer
			// that completed the WebSocket handshake but stopped reading or
			// writing STOMP frames.
			_ = ws.Close()
			return ctx.Err()
		case <-heartbeat.C:
			if err := writeWebSocketContext(ctx, ws, c.ioTimeout, []byte("\n")); err != nil {
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
				return errors.New("pxGrid STOMP server returned an error frame")
			}
			if frame.command != "MESSAGE" {
				continue
			}
			message := StompMessage{
				Topic:     firstNonEmpty(frame.headers["destination"], topic),
				MessageID: frame.headers["message-id"],
				Headers:   frame.headers,
				Body:      frame.body,
			}
			if err := handler(message); err != nil {
				// Closing without ACK asks the broker to redeliver the message after
				// the reconnect loop establishes a new client-individual session.
				return fmt.Errorf("pxGrid STOMP message delivery failed: %w", err)
			}
			ackID := firstNonEmpty(frame.headers["ack"], frame.headers["message-id"])
			if ackID == "" {
				return errors.New("pxGrid STOMP MESSAGE did not contain an ACK identifier")
			}
			// If shutdown races with ACK, close without acknowledging so pxGrid
			// redelivers the message under its at-least-once contract.
			if err := writeSTOMPContext(ctx, ws, c.ioTimeout, "ACK", map[string]string{"id": ackID}, nil); err != nil {
				return fmt.Errorf("acknowledge pxGrid STOMP message: %w", err)
			}
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
		return errors.New("invalid discovered pxGrid URL")
	}
	for _, scheme := range allowedSchemes {
		if strings.EqualFold(parsed.Scheme, scheme) {
			return nil
		}
	}
	return fmt.Errorf("discovered pxGrid URL must use %s", strings.Join(allowedSchemes, " or "))
}

func (c *PxGridClient) validateDiscoveredURL(rawURL string, allowedSchemes ...string) error {
	if err := validatePxGridURL(rawURL, allowedSchemes...); err != nil {
		return err
	}
	parsed, _ := url.Parse(rawURL)
	origin, err := canonicalPxGridOrigin(parsed)
	if err != nil {
		return err
	}
	if _, ok := c.allowedServiceOrigins[origin]; !ok {
		return errors.New("discovered pxGrid origin is not authorized by allowed_service_origins")
	}
	return nil
}

func canonicalPxGridOriginString(rawOrigin string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawOrigin))
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return "", errors.New("origin must be an absolute HTTPS or WSS URL without user information")
	}
	if parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("origin must not contain a path, query, or fragment")
	}
	return canonicalPxGridOrigin(parsed)
}

func canonicalPxGridOrigin(parsed *url.URL) (string, error) {
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && scheme != "wss" {
		return "", errors.New("origin scheme must be https or wss")
	}
	host := normalizePxGridHost(parsed.Hostname())
	if host == "" {
		return "", errors.New("origin host must not be empty")
	}
	return scheme + "://" + net.JoinHostPort(host, pxGridOriginPort(parsed)), nil
}

func pxGridOriginPort(parsed *url.URL) string {
	if port := parsed.Port(); port != "" {
		return port
	}
	return "443"
}

func addPxGridOriginPair(origins map[string]struct{}, host, port string) {
	authority := net.JoinHostPort(host, port)
	origins["https://"+authority] = struct{}{}
	origins["wss://"+authority] = struct{}{}
}

func normalizePxGridHost(value string) string {
	value = strings.TrimSpace(value)
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.Trim(strings.TrimSuffix(value, "."), "[]")
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return strings.ToLower(value)
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

func writeSTOMPContext(ctx context.Context, ws *websocket.Conn, timeout time.Duration, command string, headers map[string]string, body []byte) error {
	return withWebSocketWriteContext(ctx, ws, timeout, func() error {
		return writeSTOMP(ws, command, headers, body)
	})
}

func writeWebSocketContext(ctx context.Context, ws *websocket.Conn, timeout time.Duration, payload []byte) error {
	return withWebSocketWriteContext(ctx, ws, timeout, func() error {
		_, err := ws.Write(payload)
		return err
	})
}

func withWebSocketWriteContext(ctx context.Context, ws *websocket.Conn, timeout time.Duration, write func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	if err := ws.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	stopCancelDeadline := context.AfterFunc(ctx, func() {
		_ = ws.SetWriteDeadline(time.Now())
	})
	err := write()
	stopCancelDeadline()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

type stompReadResult struct {
	frame stompFrame
	err   error
}

func readSTOMPContext(ctx context.Context, ws *websocket.Conn, timeout time.Duration) (stompFrame, error) {
	result := make(chan stompReadResult, 1)
	go func() {
		frame, err := readSTOMPWithDeadline(ws, timeout)
		result <- stompReadResult{frame: frame, err: err}
	}()
	select {
	case read := <-result:
		return read.frame, read.err
	case <-ctx.Done():
		_ = ws.Close()
		<-result
		return stompFrame{}, ctx.Err()
	}
}

func readSTOMPWithDeadline(ws *websocket.Conn, timeout time.Duration) (stompFrame, error) {
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	if err := ws.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return stompFrame{}, err
	}
	return readSTOMP(ws)
}

func maxDuration(left, right time.Duration) time.Duration {
	if left > right {
		return left
	}
	return right
}

func readSTOMP(ws *websocket.Conn) (stompFrame, error) {
	var data []byte
	if err := websocket.Message.Receive(ws, &data); err != nil {
		return stompFrame{}, err
	}
	return parseSTOMPFrame(data)
}

func parseSTOMPFrame(data []byte) (stompFrame, error) {
	if len(data) > stompMaxFrameBytes {
		return stompFrame{}, fmt.Errorf("pxGrid STOMP frame exceeds %d-byte limit", stompMaxFrameBytes)
	}
	data = bytes.TrimLeft(data, "\n")
	if len(data) == 0 {
		return stompFrame{command: "HEARTBEAT", headers: map[string]string{}}, nil
	}
	command, next, err := nextSTOMPLine(data, 0)
	if err != nil {
		return stompFrame{}, err
	}
	frame := stompFrame{
		command: strings.TrimSpace(string(command)),
		headers: map[string]string{},
	}
	headerCount := 0
	headerBytes := 0
	for {
		lineStart := next
		line, nextLine, err := nextSTOMPLine(data, next)
		if err != nil {
			return stompFrame{}, err
		}
		next = nextLine
		if len(line) == 0 {
			break
		}
		headerCount++
		if headerCount > stompMaxHeaders {
			return stompFrame{}, fmt.Errorf("pxGrid STOMP frame exceeds %d-header limit", stompMaxHeaders)
		}
		headerBytes += next - lineStart
		if headerBytes > stompMaxHeaderBytes {
			return stompFrame{}, fmt.Errorf("pxGrid STOMP headers exceed %d-byte limit", stompMaxHeaderBytes)
		}
		key, value, found := bytes.Cut(line, []byte(":"))
		if !found || len(bytes.TrimSpace(key)) == 0 {
			return stompFrame{}, errors.New("pxGrid STOMP header is malformed")
		}
		frame.headers[strings.TrimSpace(string(key))] = strings.TrimSpace(string(value))
	}
	body := bytes.TrimRight(data[next:], "\x00")
	if len(body) > stompMaxBodyBytes {
		return stompFrame{}, fmt.Errorf("pxGrid STOMP body exceeds %d-byte limit", stompMaxBodyBytes)
	}
	frame.body = body
	return frame, nil
}

func nextSTOMPLine(data []byte, start int) ([]byte, int, error) {
	if start < 0 || start > len(data) {
		return nil, start, errors.New("invalid pxGrid STOMP frame offset")
	}
	relativeEnd := bytes.IndexByte(data[start:], '\n')
	if relativeEnd < 0 {
		return nil, start, errors.New("pxGrid STOMP frame contains an unterminated line")
	}
	end := start + relativeEnd
	line := data[start:end]
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	if len(line) > stompMaxLineBytes {
		return nil, start, fmt.Errorf("pxGrid STOMP line exceeds %d-byte limit", stompMaxLineBytes)
	}
	return line, end + 1, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
