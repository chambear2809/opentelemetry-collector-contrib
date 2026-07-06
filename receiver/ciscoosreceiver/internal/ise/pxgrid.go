// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/ise"

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/websocket"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

const (
	pxGridDefaultPath                  = "/pxgrid"
	pxGridDefaultWSOrigin              = "https://localhost/"
	pxGridWebSocketPingInterval        = 54 * time.Second
	pxGridWebSocketPingWriteTimeout    = time.Second
	pxGridWebSocketCloseWriteTimeout   = 100 * time.Millisecond
	stompMaxFrameBytes                 = 4 * 1024 * 1024
	stompMaxBodyBytes                  = 4 * 1024 * 1024
	stompMaxHeaders                    = 256
	stompMaxHeaderBytes                = 64 * 1024
	stompMaxLineBytes                  = 8 * 1024
	pxGridCAConfigPath                 = "ise.pxgrid.ca_file"
	pxGridInsecureSkipVerifyConfigPath = "ise.pxgrid.insecure_skip_verify"
	maxPxGridCertificatePEMBytes       = 1024 * 1024
	maxPxGridPrivateKeyPEMBytes        = 128 * 1024
	maxPxGridCAPEMBytes                = 1024 * 1024
)

// PxGridConfig controls the Cisco ISE pxGrid client.
type PxGridConfig struct {
	Endpoint              string
	NodeName              string
	Password              string
	CertFile              string
	KeyFile               string
	KeyPassword           string
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

// PxGridSubscriptionLifecycle reports successful subscription protocol
// transitions without exposing message contents. Callbacks run synchronously
// and must return promptly. Ready runs after CONNECTED is received and
// SUBSCRIBE is written. Acknowledged runs only after an ACK frame is written
// successfully for a MESSAGE whose handler returned nil.
type PxGridSubscriptionLifecycle struct {
	Ready        func()
	Acknowledged func()
}

// StompMessage is a decoded pxGrid STOMP MESSAGE frame.
type StompMessage struct {
	Topic     string
	MessageID string
	Headers   map[string]string
	Body      []byte
}

var pxGridWebSocketPingCodec = websocket.Codec{Marshal: func(any) ([]byte, byte, error) {
	return nil, websocket.PingFrame, nil
}}

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
	if cfg.KeyPassword != "" && (cfg.CertFile == "" || cfg.KeyFile == "") {
		return nil, errors.New("pxGrid key_password requires both cert_file and key_file")
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
		Endpoint:                     pxGridRESTEndpoint(parsed).String(),
		Username:                     cfg.NodeName,
		Password:                     cfg.Password,
		AllowEmptyPassword:           true,
		UserAgent:                    cfg.UserAgent,
		Timeout:                      timeout,
		MaxRetries:                   cfg.MaxRetries,
		PageSize:                     defaultPageSize,
		InsecureSkipVerify:           cfg.InsecureSkipVerify,
		caConfigPath:                 pxGridCAConfigPath,
		insecureSkipVerifyConfigPath: pxGridInsecureSkipVerifyConfigPath,
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
	return c.subscribe(ctx, subscription, PxGridSubscriptionLifecycle{}, handler)
}

// SubscribeWithReady is Subscribe with an optional readiness callback. The
// callback runs after the client receives STOMP CONNECTED and successfully
// writes SUBSCRIBE. It does not imply broker acceptance because the client does
// not request a STOMP receipt. Once an endpoint is ready, a later disconnect is
// returned immediately instead of silently failing over; ordinary Subscribe
// retains its endpoint failover behavior.
func (c *PxGridClient) SubscribeWithReady(
	ctx context.Context,
	subscription PxGridSubscription,
	onReady func(),
	handler func(StompMessage) error,
) error {
	return c.subscribe(ctx, subscription, PxGridSubscriptionLifecycle{Ready: onReady}, handler)
}

// SubscribeWithLifecycle is Subscribe with protocol lifecycle callbacks. A
// non-nil Ready callback also selects strict continuous-connection behavior:
// once ready, a disconnect is returned instead of hidden by endpoint failover.
func (c *PxGridClient) SubscribeWithLifecycle(
	ctx context.Context,
	subscription PxGridSubscription,
	lifecycle PxGridSubscriptionLifecycle,
	handler func(StompMessage) error,
) error {
	return c.subscribe(ctx, subscription, lifecycle, handler)
}

func (c *PxGridClient) subscribe(
	ctx context.Context,
	subscription PxGridSubscription,
	lifecycle PxGridSubscriptionLifecycle,
	handler func(StompMessage) error,
) error {
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
			endpointReady := false
			endpointReadyCallback := func() {
				endpointReady = true
				if lifecycle.Ready != nil {
					lifecycle.Ready()
				}
			}
			if err := c.subscribeEndpointWithReady(ctx, wsURL, peerNodeName, secret, topic, endpointReadyCallback, lifecycle.Acknowledged, handler); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				// Readiness callers are qualifying one continuous connection. Once
				// that connection reached STOMP CONNECTED and sent SUBSCRIBE, do not
				// hide its failure by silently moving to another advertised endpoint.
				if lifecycle.Ready != nil && endpointReady {
					return fmt.Errorf("pxGrid subscription ended after readiness: %w", err)
				}
				attempts = append(attempts, fmt.Errorf("pubsub node %q topic property %q: %w", peerNodeName, topicProperty, err))
				continue
			}
			return nil
		}
	}
	return fmt.Errorf("pxGrid subscription service %q has no usable endpoint for topic properties [%s]: %w", service, strings.Join(topicProperties, ", "), errors.Join(attempts...))
}

func (c *PxGridClient) subscribeEndpointWithReady(
	ctx context.Context,
	wsURL, peerNodeName, secret, topic string,
	onReady func(),
	onAcknowledged func(),
	handler func(StompMessage) error,
) error {
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
		// x/net/websocket's DialError predates error unwrapping. Inspect its
		// exported cause so typed x509 failures still receive the shared hint.
		var dialErr *websocket.DialError
		if errors.As(err, &dialErr) && dialErr.Err != nil {
			decoratedCause := httpclient.DecorateCertificateVerificationError(dialErr.Err, pxGridCAConfigPath, pxGridInsecureSkipVerifyConfigPath)
			var certificateErr *httpclient.CertificateVerificationError
			if errors.As(decoratedCause, &certificateErr) {
				return errors.Join(err, decoratedCause)
			}
		}
		return httpclient.DecorateCertificateVerificationError(err, pxGridCAConfigPath, pxGridInsecureSkipVerifyConfigPath)
	}
	// Cisco's pxGrid WebSocket samples send STOMP payloads as binary messages.
	// Conn.Write uses PayloadType for every subsequent STOMP data write.
	ws.PayloadType = websocket.BinaryFrame
	closed := false
	closeWS := func() {
		if closed {
			return
		}
		closed = true
		_ = closeWebSocketNow(ws)
	}
	defer closeWS()
	ws.MaxPayloadBytes = stompMaxFrameBytes

	if writeErr := writeSTOMPContext(ctx, ws, c.ioTimeout, "CONNECT", map[string]string{
		"accept-version": "1.2",
		"host":           peerNodeName,
		"heart-beat":     "0,0",
	}, nil); writeErr != nil {
		return writeErr
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
	// The handshake read is request-bounded. Steady-state subscriptions may be
	// legitimately idle, so clear that deadline and rely on context cancellation
	// plus bounded WebSocket Ping keepalives.
	if err := ws.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear pxGrid WebSocket handshake read deadline: %w", err)
	}
	if onReady != nil {
		onReady()
	}

	ping := time.NewTicker(pxGridWebSocketPingInterval)
	defer ping.Stop()
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
			frame, readErr := readSTOMP(ws)
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
		closeWS()
		<-readerDone
	}()
	for {
		select {
		case <-ctx.Done():
			// Closing the socket is the only reliable way to interrupt a peer
			// that completed the WebSocket handshake but stopped reading or
			// writing STOMP frames.
			closeWS()
			return ctx.Err()
		case <-ping.C:
			if err := writeWebSocketPingContext(ctx, ws, min(c.ioTimeout, pxGridWebSocketPingWriteTimeout)); err != nil {
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
			if onAcknowledged != nil {
				onAcknowledged()
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
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return errors.New("discovered pxGrid URL must not contain a query or fragment")
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
		Endpoint:                     endpoint,
		Username:                     c.nodeName,
		Password:                     secret,
		AllowEmptyPassword:           false,
		UserAgent:                    c.userAgent,
		Timeout:                      c.rest.client.Timeout,
		MaxRetries:                   c.rest.retries,
		PageSize:                     c.rest.pageSize,
		caConfigPath:                 c.rest.caConfigPath,
		insecureSkipVerifyConfigPath: c.rest.insecureSkipVerifyConfigPath,
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
	tlsConfig := &tls.Config{ServerName: cfg.ServerName}
	if cfg.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}
	if cfg.CAFile != "" {
		caBytes, err := readPxGridPEMFile(cfg.CAFile, "ca_file", maxPxGridCAPEMBytes)
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
		cert, err := loadPxGridKeyPair(cfg.CertFile, cfg.KeyFile, cfg.KeyPassword)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return tlsConfig, nil
}

func loadPxGridKeyPair(certFile, keyFile, keyPassword string) (tls.Certificate, error) {
	certPEM, err := readPxGridPEMFile(certFile, "cert_file", maxPxGridCertificatePEMBytes)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := readPxGridPEMFile(keyFile, "key_file", maxPxGridPrivateKeyPEMBytes)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer clear(keyPEM)
	if keyPassword == "" {
		certificate, pairErr := tls.X509KeyPair(certPEM, keyPEM)
		if pairErr != nil {
			return tls.Certificate{}, fmt.Errorf("failed to load pxGrid client certificate and private key: %w", pairErr)
		}
		return certificate, nil
	}

	block, remainder := pem.Decode(keyPEM)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" || len(bytes.TrimSpace(remainder)) != 0 {
		return tls.Certificate{}, errors.New("pxGrid key_file must contain exactly one PEM ENCRYPTED PRIVATE KEY when key_password is configured")
	}

	password := []byte(keyPassword)
	privateKey, err := parseEncryptedPKCS8PrivateKey(block.Bytes, password)
	clear(password)
	if err != nil {
		return tls.Certificate{}, errors.New("failed to decrypt pxGrid PKCS#8 private key; verify key_password and key format")
	}

	decryptedDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, errors.New("failed to prepare decrypted pxGrid PKCS#8 private key")
	}
	defer clear(decryptedDER)
	decryptedPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: decryptedDER})
	defer clear(decryptedPEM)

	certificate, err := tls.X509KeyPair(certPEM, decryptedPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load pxGrid client certificate and decrypted private key: %w", err)
	}
	return certificate, nil
}

func readPxGridPEMFile(path, field string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read pxGrid %s: %w", field, err)
	}
	defer file.Close()

	contents, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		clear(contents)
		return nil, fmt.Errorf("failed to read pxGrid %s: %w", field, err)
	}
	if int64(len(contents)) > maxBytes {
		clear(contents)
		return nil, fmt.Errorf("pxGrid %s exceeds the %d-byte size limit", field, maxBytes)
	}
	return contents, nil
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

func writeWebSocketPingContext(ctx context.Context, ws *websocket.Conn, timeout time.Duration) error {
	return withWebSocketWriteContext(ctx, ws, timeout, func() error {
		return pxGridWebSocketPingCodec.Send(ws, struct{}{})
	})
}

// closeWebSocketNow gives x/net/websocket a brief opportunity to send its
// Close control frame while guaranteeing that a writer or automatic Pong
// already holding the write lock cannot make shutdown wait indefinitely.
func closeWebSocketNow(ws *websocket.Conn) error {
	deadlineErr := ws.SetWriteDeadline(time.Now().Add(pxGridWebSocketCloseWriteTimeout))
	closeErr := ws.Close()
	return errors.Join(deadlineErr, closeErr)
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
	cancelDeadlineDone := make(chan struct{})
	stopCancelDeadline := context.AfterFunc(ctx, func() {
		defer close(cancelDeadlineDone)
		_ = ws.SetWriteDeadline(time.Now())
	})
	writeErr := write()
	if !stopCancelDeadline() {
		// If cancellation won the race, wait for its deadline write to finish so
		// it cannot reinstall an expired deadline after the clear below.
		<-cancelDeadlineDone
	}
	// x/net/websocket writes automatic Pong control frames from the reader.
	// Do not leave an application-write deadline installed: an otherwise healthy
	// idle subscription could receive a later server Ping after that deadline and
	// fail its automatic Pong with an i/o timeout.
	clearErr := ws.SetWriteDeadline(time.Time{})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if writeErr != nil {
		return writeErr
	}
	return clearErr
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
		_ = closeWebSocketNow(ws)
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
