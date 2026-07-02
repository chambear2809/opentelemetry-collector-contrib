// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

const (
	defaultUserAgent      = "opentelemetry-collector-contrib-ciscoosreceiver"
	defaultRequestTimeout = 30 * time.Second
	defaultMaxRetries     = 3
	defaultPageSize       = 100
	defaultRequestSpacing = 20 * time.Millisecond
)

// Config controls the Cisco ISE REST/OpenAPI/ERS/MnT client.
type Config struct {
	Endpoint           string
	Username           string
	Password           string
	AllowEmptyPassword bool
	UserAgent          string
	Timeout            time.Duration
	MaxRetries         int
	PageSize           int
	CAFile             string
	ServerName         string
	InsecureSkipVerify bool
}

// RequestStat describes a single Cisco ISE API request attempt.
type RequestStat struct {
	Operation   string
	Method      string
	Path        string
	Outcome     string
	StatusCode  int
	Duration    time.Duration
	RateLimited bool
	Err         error
}

// APIError is returned for non-success Cisco ISE API responses.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("ise API returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("ise API returned HTTP %d: %s", e.StatusCode, e.Body)
}

// IsUnavailable reports whether err means an ISE API family is missing, disabled, or unauthorized.
func IsUnavailable(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusUnauthorized ||
		apiErr.StatusCode == http.StatusForbidden ||
		apiErr.StatusCode == http.StatusNotFound ||
		apiErr.StatusCode == http.StatusServiceUnavailable
}

// Client is a compact Cisco ISE REST/OpenAPI/ERS/MnT client.
type Client struct {
	endpoint  *url.URL
	username  string
	password  string
	userAgent string
	client    *http.Client
	retries   int
	pageSize  int
	spacing   time.Duration

	limitMu  sync.Mutex
	nextSend time.Time

	OnRequest func(RequestStat)
}

// NewClient creates a Cisco ISE REST/OpenAPI/ERS/MnT client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("ise endpoint is required")
	}
	parsed, err := url.Parse(cfg.Endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid ise endpoint %q", cfg.Endpoint)
	}
	if cfg.Username == "" || cfg.Password == "" && !cfg.AllowEmptyPassword {
		return nil, errors.New("ise username and password are required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	userAgent := cfg.UserAgent
	if userAgent == "" {
		userAgent = defaultUserAgent
	}
	retries := cfg.MaxRetries
	if retries < 0 {
		retries = 0
	}
	if retries == 0 {
		retries = defaultMaxRetries
	}
	pageSize := cfg.PageSize
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if pageSize > defaultPageSize {
		pageSize = defaultPageSize
	}
	tlsConfig, err := clientTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig
	}
	return &Client{
		endpoint:  parsed,
		username:  cfg.Username,
		password:  cfg.Password,
		userAgent: userAgent,
		client:    &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: httpclient.SameOriginRedirectPolicy(parsed)},
		retries:   retries,
		pageSize:  pageSize,
		spacing:   defaultRequestSpacing,
	}, nil
}

func clientTLSConfig(cfg Config) (*tls.Config, error) {
	if cfg.CAFile == "" && cfg.ServerName == "" && !cfg.InsecureSkipVerify {
		return nil, nil
	}
	tlsConfig := &tls.Config{ServerName: cfg.ServerName} //nolint:gosec // InsecureSkipVerify is an explicit receiver setting below.
	if cfg.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true //nolint:gosec // Explicit opt-in for private ISE appliances.
	}
	if cfg.CAFile == "" {
		return tlsConfig, nil
	}
	caBytes, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("ISE REST CA file %s did not contain PEM certificates", cfg.CAFile)
	}
	tlsConfig.RootCAs = pool
	return tlsConfig, nil
}

// CloseIdleConnections closes idle HTTP connections held by the client.
func (c *Client) CloseIdleConnections() {
	c.client.CloseIdleConnections()
}

// Endpoint returns the configured Cisco ISE endpoint URL.
func (c *Client) Endpoint() string {
	return c.endpoint.String()
}

// Query returns URL values with string keys and values.
func Query(values map[string]string) url.Values {
	query := url.Values{}
	for key, value := range values {
		if value != "" {
			query.Set(key, value)
		}
	}
	return query
}

// GetObject fetches a JSON or XML document and returns it as an object.
func (c *Client) GetObject(ctx context.Context, operation, path string, query url.Values) (Object, error) {
	body, _, err := c.do(ctx, http.MethodGet, operation, path, query, nil)
	if err != nil {
		return nil, err
	}
	obj, err := decodeObject(body)
	if err != nil {
		return nil, fmt.Errorf("decode ise %s response: %w", operation, err)
	}
	return obj, nil
}

// List fetches generic objects from a Cisco ISE endpoint.
func (c *Client) List(ctx context.Context, operation, path string, query url.Values, maxResults int) ([]Object, error) {
	body, _, err := c.do(ctx, http.MethodGet, operation, path, query, nil)
	if err != nil {
		return nil, err
	}
	objects, _, err := decodeObjects(body)
	if err != nil {
		return nil, fmt.Errorf("decode ise %s response: %w", operation, err)
	}
	return capObjects(objects, maxResults), nil
}

// ListERS fetches ERS search endpoints using ISE page/size pagination.
func (c *Client) ListERS(ctx context.Context, operation, path string, query url.Values, maxResults int) ([]Object, error) {
	if query == nil {
		query = url.Values{}
	}
	var results []Object
	for page := 1; ; page++ {
		pageQuery := cloneValues(query)
		pageSize := c.pageSize
		if maxResults > 0 {
			remaining := maxResults - len(results)
			if remaining <= 0 {
				return results, nil
			}
			if remaining < pageSize {
				pageSize = remaining
			}
		}
		if _, ok := pageQuery["page"]; !ok {
			pageQuery.Set("page", strconv.Itoa(page))
		}
		if _, ok := pageQuery["size"]; !ok {
			pageQuery.Set("size", strconv.Itoa(pageSize))
		}
		body, _, err := c.do(ctx, http.MethodGet, operation, path, pageQuery, nil)
		if err != nil {
			return results, err
		}
		objects, total, err := decodeObjects(body)
		if err != nil {
			return results, fmt.Errorf("decode ise %s response: %w", operation, err)
		}
		results = append(results, objects...)
		if maxResults > 0 && len(results) >= maxResults {
			return results[:maxResults], nil
		}
		if len(objects) == 0 || len(objects) < pageSize || total > -1 && len(results) >= total {
			return results, nil
		}
	}
}

// PostQuery posts a JSON payload and returns normalized objects from the response.
func (c *Client) PostQuery(ctx context.Context, operation, path string, payload any, maxResults int) ([]Object, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	body, _, err := c.do(ctx, http.MethodPost, operation, path, nil, bodyBytes)
	if err != nil {
		return nil, err
	}
	objects, _, err := decodeObjects(body)
	if err != nil {
		return nil, fmt.Errorf("decode ise %s response: %w", operation, err)
	}
	return capObjects(objects, maxResults), nil
}

// PostObject posts a JSON payload and returns one normalized object from the response.
func (c *Client) PostObject(ctx context.Context, operation, path string, payload any) (Object, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	body, _, err := c.do(ctx, http.MethodPost, operation, path, nil, bodyBytes)
	if err != nil {
		return nil, err
	}
	obj, err := decodeObject(body)
	if err != nil {
		return nil, fmt.Errorf("decode ise %s response: %w", operation, err)
	}
	return obj, nil
}

func (c *Client) do(ctx context.Context, method, operation, path string, query url.Values, payload []byte) ([]byte, http.Header, error) {
	var lastErr error
	attempts := c.retries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		body, header, status, err := c.doOnce(ctx, method, operation, path, query, payload)
		if err == nil {
			return body, header, nil
		}
		lastErr = err
		if ctx.Err() != nil || !retryableStatus(status) || attempt == attempts-1 {
			break
		}
		sleep := time.Duration(1<<attempt)*100*time.Millisecond + time.Duration(rand.Int63n(int64(50*time.Millisecond))) //nolint:gosec // Retry jitter does not need crypto randomness.
		timer := time.NewTimer(sleep)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, nil, lastErr
}

func (c *Client) doOnce(ctx context.Context, method, operation, path string, query url.Values, payload []byte) ([]byte, http.Header, int, error) {
	if err := c.waitTurn(ctx); err != nil {
		return nil, nil, 0, err
	}
	target := c.resolve(path, query)
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, nil, 0, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json, application/xml, text/xml")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.SetBasicAuth(c.username, c.password)

	start := time.Now()
	resp, err := c.client.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "error", Duration: duration, Err: err})
		return nil, nil, 0, err
	}
	defer resp.Body.Close()

	respBody, readErr := httpclient.ReadResponseBody(resp.Body)
	if readErr != nil {
		c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: readErr})
		return nil, resp.Header, resp.StatusCode, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(respBody))}
		c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, RateLimited: resp.StatusCode == http.StatusTooManyRequests, Err: apiErr})
		return nil, resp.Header, resp.StatusCode, apiErr
	}
	c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "success", StatusCode: resp.StatusCode, Duration: duration})
	return respBody, resp.Header, resp.StatusCode, nil
}

func (c *Client) resolve(path string, query url.Values) string {
	target := *c.endpoint
	basePath := strings.TrimRight(target.Path, "/")
	requestPath := "/" + strings.TrimLeft(path, "/")
	if basePath != "" && basePath != "/" && !strings.HasPrefix(requestPath, basePath+"/") {
		target.Path = basePath + requestPath
	} else {
		target.Path = requestPath
	}
	target.RawQuery = query.Encode()
	return target.String()
}

func (c *Client) waitTurn(ctx context.Context) error {
	c.limitMu.Lock()
	now := time.Now()
	wait := time.Duration(0)
	if c.nextSend.After(now) {
		wait = c.nextSend.Sub(now)
	}
	c.nextSend = now.Add(wait + c.spacing)
	c.limitMu.Unlock()
	if wait == 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	select {
	case <-ctx.Done():
		timer.Stop()
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) record(stat RequestStat) {
	if c.OnRequest != nil {
		c.OnRequest(stat)
	}
}

func retryableStatus(status int) bool {
	return status == 0 || status == http.StatusTooManyRequests || status >= 500
}

func cloneValues(values url.Values) url.Values {
	clone := url.Values{}
	for key, current := range values {
		clone[key] = append([]string(nil), current...)
	}
	return clone
}

func capObjects(objects []Object, maxResults int) []Object {
	if maxResults > 0 && len(objects) > maxResults {
		return objects[:maxResults]
	}
	return objects
}
