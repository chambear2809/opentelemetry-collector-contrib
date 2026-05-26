// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nexusdashboard

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

// Config controls the Nexus Dashboard API client.
type Config struct {
	Endpoint           string
	AuthMode           string
	Username           string
	Password           string
	APIKey             string
	Domain             string
	UserAgent          string
	Timeout            time.Duration
	MaxRetries         int
	PageSize           int
	InsecureSkipVerify bool
}

// RequestStat describes a single Nexus Dashboard API request attempt.
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

// APIError is returned for non-success Nexus Dashboard API responses.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("nexus dashboard API returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("nexus dashboard API returned HTTP %d: %s", e.StatusCode, e.Body)
}

// Client is a compact Nexus Dashboard API client.
type Client struct {
	endpoint  *url.URL
	authMode  string
	username  string
	password  string
	apiKey    string
	domain    string
	userAgent string
	client    *http.Client
	retries   int
	pageSize  int

	tokenMu sync.Mutex
	token   string

	OnRequest func(RequestStat)
}

// NewClient creates a Nexus Dashboard API client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("nexus dashboard endpoint is required")
	}
	parsed, err := url.Parse(cfg.Endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid nexus dashboard endpoint %q", cfg.Endpoint)
	}
	authMode := cfg.AuthMode
	if authMode == "" || authMode == "auto" {
		if cfg.APIKey != "" {
			authMode = "api_key"
		} else {
			authMode = "username_password"
		}
	}
	switch authMode {
	case "api_key":
		if cfg.Username == "" || cfg.APIKey == "" {
			return nil, errors.New("nexus dashboard api_key auth requires username and api key")
		}
	case "username_password":
		if cfg.Username == "" || cfg.Password == "" {
			return nil, errors.New("nexus dashboard username_password auth requires username and password")
		}
	default:
		return nil, fmt.Errorf("unsupported nexus dashboard auth mode %q", authMode)
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
	domain := cfg.Domain
	if domain == "" {
		domain = "local"
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // Explicit opt-in for private Nexus Dashboard appliances.
	}

	return &Client{
		endpoint:  parsed,
		authMode:  authMode,
		username:  cfg.Username,
		password:  cfg.Password,
		apiKey:    cfg.APIKey,
		domain:    domain,
		userAgent: userAgent,
		client:    &http.Client{Timeout: timeout, Transport: transport},
		retries:   retries,
		pageSize:  pageSize,
	}, nil
}

// CloseIdleConnections closes idle HTTP connections held by the client.
func (c *Client) CloseIdleConnections() {
	c.client.CloseIdleConnections()
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

// List fetches generic objects from a Nexus Dashboard endpoint.
func (c *Client) List(ctx context.Context, operation, path string, query url.Values, maxResults int) ([]Object, error) {
	if query == nil {
		query = url.Values{}
	}
	var results []Object
	offset := 0
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
		if _, hasMax := pageQuery["max"]; !hasMax {
			pageQuery.Set("max", strconv.Itoa(pageSize))
		}
		if _, hasOffset := pageQuery["offset"]; !hasOffset {
			pageQuery.Set("offset", strconv.Itoa(offset))
		}

		body, header, err := c.do(ctx, http.MethodGet, operation, path, pageQuery, nil)
		if err != nil {
			return results, err
		}
		page, next, remaining, err := decodeObjects(body, header)
		if err != nil {
			return results, fmt.Errorf("decode nexus dashboard %s response: %w", operation, err)
		}
		results = append(results, page...)
		if maxResults > 0 && len(results) >= maxResults {
			return results[:maxResults], nil
		}
		if next != "" {
			path, query = splitNextURL(next)
			offset = 0
			continue
		}
		if len(page) == 0 || len(page) < pageSize || remaining == 0 {
			return results, nil
		}
		if remaining < 0 {
			return results, nil
		}
		offset += len(page)
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
		if c.authMode == "username_password" && (status == http.StatusUnauthorized || status == http.StatusForbidden) {
			c.clearToken()
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
		lastErr = errors.New("nexus dashboard request failed")
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
	if err := c.authorize(ctx, req); err != nil {
		return nil, nil, 0, err
	}

	start := time.Now()
	resp, err := c.client.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "error", Duration: duration, Err: err})
		return nil, nil, 0, err
	}
	bodyBytes, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: readErr})
		return nil, resp.Header, resp.StatusCode, readErr
	}
	if closeErr != nil {
		return nil, resp.Header, resp.StatusCode, closeErr
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "success", StatusCode: resp.StatusCode, Duration: duration})
		return bodyBytes, resp.Header, resp.StatusCode, nil
	}
	apiErr := &APIError{StatusCode: resp.StatusCode, Body: string(bodyBytes)}
	c.record(RequestStat{
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

func (c *Client) authorize(ctx context.Context, req *http.Request) error {
	switch c.authMode {
	case "api_key":
		req.Header.Set("X-Nd-Username", c.username)
		req.Header.Set("X-Nd-Apikey", c.apiKey)
		return nil
	case "username_password":
		token, err := c.ensureToken(ctx)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.AddCookie(&http.Cookie{Name: "AuthCookie", Value: token})
		return nil
	default:
		return fmt.Errorf("unsupported nexus dashboard auth mode %q", c.authMode)
	}
}

func (c *Client) ensureToken(ctx context.Context) (string, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.token != "" {
		return c.token, nil
	}
	payload, err := json.Marshal(map[string]string{
		"domain":     c.domain,
		"userName":   c.username,
		"userPasswd": c.password,
	})
	if err != nil {
		return "", err
	}
	reqURL := c.buildURL("/api/v1/infra/login", nil)
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
		c.record(RequestStat{Operation: "infra.login", Method: http.MethodPost, Path: "/api/v1/infra/login", Outcome: "error", Duration: duration, Err: err})
		return "", err
	}
	bodyBytes, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		c.record(RequestStat{Operation: "infra.login", Method: http.MethodPost, Path: "/api/v1/infra/login", Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: readErr})
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode, Body: string(bodyBytes)}
		c.record(RequestStat{Operation: "infra.login", Method: http.MethodPost, Path: "/api/v1/infra/login", Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: apiErr})
		return "", apiErr
	}
	var login struct {
		Token    string `json:"token"`
		JWTToken string `json:"jwttoken"`
	}
	if err := json.Unmarshal(bodyBytes, &login); err != nil {
		c.record(RequestStat{Operation: "infra.login", Method: http.MethodPost, Path: "/api/v1/infra/login", Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: err})
		return "", err
	}
	token := login.Token
	if token == "" {
		token = login.JWTToken
	}
	if token == "" {
		err := errors.New("nexus dashboard login response did not include a token")
		c.record(RequestStat{Operation: "infra.login", Method: http.MethodPost, Path: "/api/v1/infra/login", Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: err})
		return "", err
	}
	c.record(RequestStat{Operation: "infra.login", Method: http.MethodPost, Path: "/api/v1/infra/login", Outcome: "success", StatusCode: resp.StatusCode, Duration: duration})
	c.token = token
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

func decodeObjects(body []byte, header http.Header) ([]Object, string, int, error) {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return nil, "", 0, err
	}
	objects := objectsFromValue(value)
	next := nextLink(header.Get("Link"))
	remaining := -1
	if root, ok := value.(map[string]any); ok {
		next = firstNonEmpty(next, stringFromPath(root, "meta", "links", "next"), stringFromPath(root, "links", "next"), stringFromPath(root, "pagination", "next"))
		remaining = intFromPath(root, "meta", "counts", "remaining")
		if remaining < 0 {
			remaining = intFromPath(root, "pagination", "remaining")
		}
	}
	return objects, next, remaining, nil
}

func objectsFromValue(value any) []Object {
	switch typed := value.(type) {
	case []any:
		out := make([]Object, 0, len(typed))
		for _, item := range typed {
			if obj, ok := objectFromValue(item); ok {
				out = append(out, obj)
			}
		}
		return out
	case map[string]any:
		for _, key := range []string{"items", "data", "results", "fabrics", "switches", "interfaces", "anomalies", "advisories", "nodes", "services", "sites", "schemas", "rules", "sessions", "flows", "events", "faults", "auditLog", "logs", "records"} {
			if items, ok := typed[key].([]any); ok {
				out := make([]Object, 0, len(items))
				for _, item := range items {
					if obj, ok := objectFromValue(item); ok {
						if fabric := String(Object(typed), "fabricName", "siteName"); fabric != "" {
							obj["_parent"] = fabric
						}
						out = append(out, obj)
					}
				}
				return out
			}
		}
		return []Object{Object(typed)}
	default:
		return nil
	}
}

func objectFromValue(value any) (Object, bool) {
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	return Object(obj), true
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
	case 0, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusUnauthorized, http.StatusForbidden:
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
		if !strings.Contains(sections[1], `rel="next"`) {
			continue
		}
		return strings.Trim(strings.TrimSpace(sections[0]), "<>")
	}
	return ""
}

func splitNextURL(nextURL string) (string, url.Values) {
	parsed, err := url.Parse(nextURL)
	if err != nil {
		return nextURL, nil
	}
	return parsed.Path, parsed.Query()
}

func stringFromPath(obj map[string]any, path ...string) string {
	var current any = obj
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = m[key]
	}
	if current == nil {
		return ""
	}
	if s, ok := current.(string); ok {
		return s
	}
	return fmt.Sprint(current)
}

func intFromPath(obj map[string]any, path ...string) int {
	value := stringFromPath(obj, path...)
	if value == "" {
		return -1
	}
	i, err := strconv.Atoi(value)
	if err != nil {
		return -1
	}
	return i
}
