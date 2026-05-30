// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package aci

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultUserAgent      = "opentelemetry-collector-contrib-ciscoosreceiver"
	defaultRequestTimeout = 30 * time.Second
	defaultMaxRetries     = 3
	defaultPageSize       = 100
)

// Config controls the Cisco APIC API client.
type Config struct {
	Endpoint           string
	Name               string
	Username           string
	Password           string
	Domain             string
	UserAgent          string
	Timeout            time.Duration
	MaxRetries         int
	PageSize           int
	InsecureSkipVerify bool
}

// RequestStat describes a single APIC API request attempt.
type RequestStat struct {
	Controller  string
	Operation   string
	Method      string
	Path        string
	Outcome     string
	StatusCode  int
	Duration    time.Duration
	RateLimited bool
	Err         error
}

// APIError is returned for non-success APIC API responses.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("apic API returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("apic API returned HTTP %d: %s", e.StatusCode, e.Body)
}

// Client is a compact Cisco APIC REST API client.
type Client struct {
	endpoint   *url.URL
	name       string
	username   string
	password   string
	domain     string
	userAgent  string
	client     *http.Client
	retries    int
	pageSize   int
	controller string

	tokenMu       sync.Mutex
	token         string
	loginInflight chan struct{}
	lastAuthErr   error
	lastAuthAt    time.Time
	authFailures  int

	OnRequest func(RequestStat)
}

// authBackoffSchedule defines the wait that ensureToken honors after a failed
// login. It avoids hammering the APIC and locking out the user account when
// credentials are wrong.
var authBackoffSchedule = []time.Duration{
	1 * time.Second,
	5 * time.Second,
	30 * time.Second,
	5 * time.Minute,
}

func authBackoffFor(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	idx := failures - 1
	if idx >= len(authBackoffSchedule) {
		idx = len(authBackoffSchedule) - 1
	}
	return authBackoffSchedule[idx]
}

// NewClient creates an APIC API client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("apic endpoint is required")
	}
	parsed, err := url.Parse(cfg.Endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid apic endpoint %q", cfg.Endpoint)
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, errors.New("apic username and password are required")
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
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // Explicit opt-in for private APIC appliances.
	}
	name := cfg.Name
	if name == "" {
		name = parsed.Host
	}

	return &Client{
		endpoint:   parsed,
		name:       name,
		username:   cfg.Username,
		password:   cfg.Password,
		domain:     cfg.Domain,
		userAgent:  userAgent,
		client:     &http.Client{Timeout: timeout, Transport: transport},
		retries:    retries,
		pageSize:   pageSize,
		controller: parsed.Host,
	}, nil
}

// CloseIdleConnections closes idle HTTP connections held by the client.
func (c *Client) CloseIdleConnections() {
	c.client.CloseIdleConnections()
}

// ControllerName returns a stable display name for the APIC endpoint.
func (c *Client) ControllerName() string {
	return c.name
}

// Endpoint returns the configured APIC endpoint URL.
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

// ListClass fetches all pages from an APIC class query endpoint.
func (c *Client) ListClass(ctx context.Context, operation, className string, query url.Values, maxResults int) ([]Object, error) {
	path := "/api/class/" + strings.TrimSuffix(strings.TrimPrefix(className, "/"), ".json") + ".json"
	return c.List(ctx, operation, path, query, maxResults)
}

// List fetches all pages for an APIC endpoint.
func (c *Client) List(ctx context.Context, operation, path string, query url.Values, maxResults int) ([]Object, error) {
	if query == nil {
		query = url.Values{}
	}
	var results []Object
	page := 0
	for {
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
		if _, ok := pageQuery["page-size"]; !ok {
			pageQuery.Set("page-size", strconv.Itoa(pageSize))
		}
		if _, ok := pageQuery["page"]; !ok {
			pageQuery.Set("page", strconv.Itoa(page))
		}
		body, header, err := c.do(ctx, http.MethodGet, operation, path, pageQuery, nil)
		if err != nil {
			return results, err
		}
		pageObjects, total, err := decodeObjects(body)
		if err != nil {
			return results, fmt.Errorf("decode apic %s response: %w", operation, err)
		}
		results = append(results, pageObjects...)
		if maxResults > 0 && len(results) >= maxResults {
			return results[:maxResults], nil
		}
		next := nextLink(header.Get("Link"))
		if len(pageObjects) == 0 || len(pageObjects) < pageSize || total > -1 && len(results) >= total {
			return results, nil
		}
		if total < 0 && next == "" {
			return results, nil
		}
		page++
	}
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
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			// Drop the token but do not retry inline — a bad credential would
			// otherwise loop login → fail → login on every attempt and risk
			// locking the APIC user account. ensureToken applies a backoff so
			// the next scrape is the next retry boundary.
			c.clearToken()
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			return nil, nil, err
		}
		retryHeader := ""
		if header != nil {
			retryHeader = header.Get("Retry-After")
		}
		if !retryableStatus(status) || !sleepBeforeRetry(ctx, attempt, retryAfter(retryHeader)) {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			return nil, nil, err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("apic request failed")
	}
	return nil, nil, lastErr
}

func (c *Client) doOnce(ctx context.Context, method, operation, path string, query url.Values, payload []byte) ([]byte, http.Header, int, error) {
	reqURL := c.buildURL(path, query)
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	token, err := c.ensureToken(ctx)
	if err != nil {
		return nil, nil, 0, err
	}
	req.AddCookie(&http.Cookie{Name: "APIC-cookie", Value: token})

	start := time.Now()
	resp, err := c.client.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.record(RequestStat{Controller: c.name, Operation: operation, Method: method, Path: path, Outcome: "error", Duration: duration, Err: err})
		return nil, nil, 0, err
	}
	bodyBytes, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		c.record(RequestStat{Controller: c.name, Operation: operation, Method: method, Path: path, Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: readErr})
		return nil, resp.Header, resp.StatusCode, readErr
	}
	if closeErr != nil {
		return nil, resp.Header, resp.StatusCode, closeErr
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.record(RequestStat{Controller: c.name, Operation: operation, Method: method, Path: path, Outcome: "success", StatusCode: resp.StatusCode, Duration: duration})
		return bodyBytes, resp.Header, resp.StatusCode, nil
	}
	apiErr := &APIError{StatusCode: resp.StatusCode, Body: string(bodyBytes)}
	c.record(RequestStat{
		Controller:  c.name,
		Operation:   operation,
		Method:      method,
		Path:        path,
		Outcome:     "error",
		StatusCode:  resp.StatusCode,
		Duration:    duration,
		RateLimited: resp.StatusCode == http.StatusTooManyRequests,
		Err:         apiErr,
	})
	return nil, resp.Header, resp.StatusCode, apiErr
}

func (c *Client) ensureToken(ctx context.Context) (string, error) {
	for {
		c.tokenMu.Lock()
		if c.token != "" {
			tok := c.token
			c.tokenMu.Unlock()
			return tok, nil
		}
		// If a backoff window is active after a recent failed login, return
		// the cached error without hitting the wire.
		if c.authFailures > 0 && time.Since(c.lastAuthAt) < authBackoffFor(c.authFailures) {
			err := c.lastAuthErr
			c.tokenMu.Unlock()
			if err == nil {
				err = errors.New("apic auth in backoff")
			}
			return "", err
		}
		// Concurrent callers wait on the inflight channel rather than racing
		// the login.
		if c.loginInflight != nil {
			ch := c.loginInflight
			c.tokenMu.Unlock()
			select {
			case <-ch:
			case <-ctx.Done():
				return "", ctx.Err()
			}
			continue
		}
		ch := make(chan struct{})
		c.loginInflight = ch
		c.tokenMu.Unlock()

		token, err := c.login(ctx)

		c.tokenMu.Lock()
		c.loginInflight = nil
		if err != nil {
			c.authFailures++
			c.lastAuthErr = err
			c.lastAuthAt = time.Now()
		} else {
			c.token = token
			c.authFailures = 0
			c.lastAuthErr = nil
		}
		close(ch)
		c.tokenMu.Unlock()
		if err != nil {
			return "", err
		}
		return token, nil
	}
}

func (c *Client) login(ctx context.Context) (string, error) {
	loginName := c.username
	if c.domain != "" && c.domain != "local" {
		loginName = "apic:" + c.domain + `\` + c.username
	}
	payload, err := json.Marshal(map[string]any{
		"aaaUser": map[string]any{
			"attributes": map[string]string{
				"name": loginName,
				"pwd":  c.password,
			},
		},
	})
	if err != nil {
		return "", err
	}
	reqURL := c.buildURL("/api/aaaLogin.json", nil)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	start := time.Now()
	resp, err := c.client.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.record(RequestStat{Controller: c.name, Operation: "aaaLogin", Method: http.MethodPost, Path: "/api/aaaLogin.json", Outcome: "error", Duration: duration, Err: err})
		return "", err
	}
	bodyBytes, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		c.record(RequestStat{Controller: c.name, Operation: "aaaLogin", Method: http.MethodPost, Path: "/api/aaaLogin.json", Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: readErr})
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode, Body: string(bodyBytes)}
		c.record(RequestStat{Controller: c.name, Operation: "aaaLogin", Method: http.MethodPost, Path: "/api/aaaLogin.json", Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: apiErr})
		return "", apiErr
	}
	token, err := loginToken(bodyBytes)
	if err != nil {
		c.record(RequestStat{Controller: c.name, Operation: "aaaLogin", Method: http.MethodPost, Path: "/api/aaaLogin.json", Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: err})
		return "", err
	}
	c.record(RequestStat{Controller: c.name, Operation: "aaaLogin", Method: http.MethodPost, Path: "/api/aaaLogin.json", Outcome: "success", StatusCode: resp.StatusCode, Duration: duration})
	return token, nil
}

func (c *Client) clearToken() {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	c.token = ""
}

func (c *Client) buildURL(path string, query url.Values) string {
	u := *c.endpoint
	basePath := strings.TrimRight(u.Path, "/")
	cleanPath := "/" + strings.TrimLeft(path, "/")
	u.Path = basePath + cleanPath
	if query != nil {
		u.RawQuery = query.Encode()
	}
	return u.String()
}

func (c *Client) record(stat RequestStat) {
	if c.OnRequest != nil {
		c.OnRequest(stat)
	}
}

func loginToken(body []byte) (string, error) {
	var envelope struct {
		IMData []map[string]struct {
			Attributes map[string]string `json:"attributes"`
		} `json:"imdata"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", err
	}
	for _, item := range envelope.IMData {
		if login, ok := item["aaaLogin"]; ok {
			if token := login.Attributes["token"]; token != "" {
				return token, nil
			}
		}
	}
	return "", errors.New("apic login response did not include a token")
}

func decodeObjects(body []byte) ([]Object, int, error) {
	var envelope struct {
		TotalCount string           `json:"totalCount"`
		IMData     []map[string]any `json:"imdata"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && envelope.IMData != nil {
		out := make([]Object, 0, len(envelope.IMData))
		for _, item := range envelope.IMData {
			for className, raw := range item {
				obj := Object{"aci.class": className}
				if rawMap, ok := raw.(map[string]any); ok {
					if attrs, ok := rawMap["attributes"].(map[string]any); ok {
						for key, value := range attrs {
							obj[key] = value
						}
					}
					if children, ok := rawMap["children"].([]any); ok && len(children) > 0 {
						obj["children.count"] = len(children)
					}
				}
				out = append(out, obj)
			}
		}
		total := -1
		if envelope.TotalCount != "" {
			if parsed, err := strconv.Atoi(envelope.TotalCount); err == nil {
				total = parsed
			}
		}
		return out, total, nil
	}

	var array []Object
	if err := json.Unmarshal(body, &array); err == nil {
		return array, len(array), nil
	}
	var obj Object
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, -1, err
	}
	return []Object{obj}, 1, nil
}

func cloneValues(values url.Values) url.Values {
	if values == nil {
		return url.Values{}
	}
	cloned := make(url.Values, len(values))
	for key, vals := range values {
		cloned[key] = append([]string(nil), vals...)
	}
	return cloned
}

func retryableStatus(status int) bool {
	switch status {
	case 0, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func retryAfter(value string) time.Duration {
	if value == "" {
		return -1
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		return time.Duration(seconds) * time.Second
	}
	if ts, err := http.ParseTime(value); err == nil {
		return time.Until(ts)
	}
	return -1
}

func sleepBeforeRetry(ctx context.Context, attempt int, retryAfter time.Duration) bool {
	if retryAfter < 0 {
		backoff := time.Duration(200*(1<<attempt)) * time.Millisecond
		jitter := time.Duration(rand.Int63n(int64(100 * time.Millisecond))) //nolint:gosec // Jitter only.
		retryAfter = backoff + jitter
	}
	timer := time.NewTimer(retryAfter)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func nextLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		sections := strings.Split(part, ";")
		if len(sections) < 2 {
			continue
		}
		if strings.Contains(sections[1], `rel="next"`) {
			return strings.Trim(strings.TrimSpace(sections[0]), "<>")
		}
	}
	return ""
}
