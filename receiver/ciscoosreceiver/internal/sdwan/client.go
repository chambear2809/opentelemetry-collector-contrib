// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sdwan

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
	defaultPageSize       = 500
	defaultRequestSpacing = 10 * time.Millisecond
)

// Config controls the Catalyst SD-WAN Manager API client.
type Config struct {
	Endpoint           string
	AuthMode           string
	Username           string
	Password           string
	BearerToken        string
	JSessionID         string
	XSRFToken          string
	UserAgent          string
	Timeout            time.Duration
	MaxRetries         int
	PageSize           int
	InsecureSkipVerify bool
}

// RequestStat describes a single Catalyst SD-WAN Manager API request attempt.
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

// APIError is returned for non-success Catalyst SD-WAN Manager API responses.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("sdwan API returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("sdwan API returned HTTP %d: %s", e.StatusCode, e.Body)
}

// Client is a compact Catalyst SD-WAN Manager REST client.
type Client struct {
	endpoint    *url.URL
	authMode    string
	username    string
	password    string
	bearerToken string
	jsessionID  string
	xsrfToken   string
	userAgent   string
	client      *http.Client
	retries     int
	pageSize    int
	spacing     time.Duration

	authMu        sync.Mutex
	loginInflight chan struct{}
	lastAuthErr   error
	lastAuthAt    time.Time
	authFailures  int

	limitMu  sync.Mutex
	nextSend time.Time

	OnRequest func(RequestStat)
}

// authBackoffSchedule defines the wait that ensureAuth honors after a failed
// login. It avoids hammering the SD-WAN Manager and locking out the user
// account when credentials are wrong.
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

// NewClient creates a Catalyst SD-WAN Manager API client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("sdwan endpoint is required")
	}
	parsed, err := url.Parse(cfg.Endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid sdwan endpoint %q", cfg.Endpoint)
	}

	authMode := cfg.AuthMode
	if authMode == "" || authMode == "auto" {
		switch {
		case cfg.BearerToken != "":
			authMode = "bearer"
		case cfg.JSessionID != "" || cfg.XSRFToken != "":
			authMode = "cookie"
		case cfg.Username != "" || cfg.Password != "":
			authMode = "auto"
		default:
			authMode = ""
		}
	}
	switch authMode {
	case "auto", "jwt", "session":
		if cfg.Username == "" || cfg.Password == "" {
			return nil, fmt.Errorf("sdwan %s auth requires username and password", authMode)
		}
	case "bearer":
		if cfg.BearerToken == "" {
			return nil, errors.New("sdwan bearer auth requires bearer token")
		}
	case "cookie":
		if cfg.JSessionID == "" || cfg.XSRFToken == "" {
			return nil, errors.New("sdwan cookie auth requires JSESSIONID and XSRF token")
		}
	default:
		return nil, fmt.Errorf("unsupported sdwan auth mode %q", authMode)
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
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // Explicit opt-in for private SD-WAN Manager appliances.
	}

	return &Client{
		endpoint:    parsed,
		authMode:    authMode,
		username:    cfg.Username,
		password:    cfg.Password,
		bearerToken: cfg.BearerToken,
		jsessionID:  cfg.JSessionID,
		xsrfToken:   cfg.XSRFToken,
		userAgent:   userAgent,
		client:      &http.Client{Timeout: timeout, Transport: transport},
		retries:     retries,
		pageSize:    pageSize,
		spacing:     defaultRequestSpacing,
	}, nil
}

// CloseIdleConnections closes idle HTTP connections held by the client.
func (c *Client) CloseIdleConnections() {
	c.client.CloseIdleConnections()
}

// GetObject fetches a JSON document and returns it as an object.
func (c *Client) GetObject(ctx context.Context, operation, path string, query url.Values) (Object, error) {
	body, _, err := c.do(ctx, http.MethodGet, operation, path, query, nil)
	if err != nil {
		return nil, err
	}
	obj, err := decodeObject(body)
	if err != nil {
		return nil, fmt.Errorf("decode sdwan %s response: %w", operation, err)
	}
	return obj, nil
}

// List fetches generic objects from an SD-WAN endpoint.
func (c *Client) List(ctx context.Context, operation, path string, query url.Values, maxResults int) ([]Object, error) {
	body, header, err := c.do(ctx, http.MethodGet, operation, path, query, nil)
	if err != nil {
		return nil, err
	}
	objects, err := decodeObjects(body, header)
	if err != nil {
		return nil, fmt.Errorf("decode sdwan %s response: %w", operation, err)
	}
	return capObjects(objects, maxResults), nil
}

// PostQuery fetches generic objects with a POST JSON payload.
func (c *Client) PostQuery(ctx context.Context, operation, path string, payload any, maxResults int) ([]Object, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	body, header, err := c.do(ctx, http.MethodPost, operation, path, nil, bodyBytes)
	if err != nil {
		return nil, err
	}
	objects, err := decodeObjects(body, header)
	if err != nil {
		return nil, fmt.Errorf("decode sdwan %s response: %w", operation, err)
	}
	return capObjects(objects, maxResults), nil
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
			// Drop auth state but do not retry inline — the next scrape is the
			// next retry boundary, and ensureAuth applies a backoff so a bad
			// credential cannot lock out the SD-WAN user.
			c.clearAuth()
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
		lastErr = errors.New("sdwan request failed")
	}
	return nil, nil, lastErr
}

func (c *Client) doOnce(ctx context.Context, method, operation, path string, query url.Values, payload []byte) ([]byte, http.Header, int, error) {
	if err := c.ensureAuth(ctx); err != nil {
		stat := RequestStat{Operation: operation, Method: method, Path: path, Outcome: "auth_error", Err: err}
		c.emit(stat)
		return nil, nil, 0, err
	}
	if err := c.wait(ctx); err != nil {
		return nil, nil, 0, err
	}

	req, err := c.newRequest(ctx, method, path, query, payload)
	if err != nil {
		return nil, nil, 0, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.applyAuth(req)

	start := time.Now()
	resp, err := c.client.Do(req)
	duration := time.Since(start)
	stat := RequestStat{Operation: operation, Method: method, Path: path, Duration: duration}
	if err != nil {
		stat.Outcome = "error"
		stat.Err = err
		c.emit(stat)
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	stat.StatusCode = resp.StatusCode
	stat.RateLimited = resp.StatusCode == http.StatusTooManyRequests
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		stat.Outcome = "error"
		stat.Err = readErr
		c.emit(stat)
		return nil, resp.Header, resp.StatusCode, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(body))}
		stat.Outcome = "http_error"
		stat.Err = apiErr
		c.emit(stat)
		return nil, resp.Header, resp.StatusCode, apiErr
	}
	stat.Outcome = "success"
	c.emit(stat)
	return body, resp.Header, resp.StatusCode, nil
}

func (c *Client) ensureAuth(ctx context.Context) error {
	switch c.authMode {
	case "bearer", "cookie":
		return nil
	}
	for {
		c.authMu.Lock()
		if c.bearerToken != "" || c.jsessionID != "" {
			c.authMu.Unlock()
			return nil
		}
		if c.authFailures > 0 && time.Since(c.lastAuthAt) < authBackoffFor(c.authFailures) {
			err := c.lastAuthErr
			c.authMu.Unlock()
			if err == nil {
				err = errors.New("sdwan auth in backoff")
			}
			return err
		}
		if c.loginInflight != nil {
			ch := c.loginInflight
			c.authMu.Unlock()
			select {
			case <-ch:
			case <-ctx.Done():
				return ctx.Err()
			}
			continue
		}
		ch := make(chan struct{})
		c.loginInflight = ch
		c.authMu.Unlock()

		err := c.performLogin(ctx)

		c.authMu.Lock()
		c.loginInflight = nil
		if err != nil {
			c.authFailures++
			c.lastAuthErr = err
			c.lastAuthAt = time.Now()
		} else {
			c.authFailures = 0
			c.lastAuthErr = nil
		}
		close(ch)
		c.authMu.Unlock()
		return err
	}
}

func (c *Client) performLogin(ctx context.Context) error {
	if c.authMode == "jwt" || c.authMode == "auto" {
		if err := c.loginJWT(ctx); err == nil {
			return nil
		} else if c.authMode == "jwt" {
			return err
		}
	}
	return c.loginSession(ctx)
}

func (c *Client) loginJWT(ctx context.Context) error {
	payload, err := json.Marshal(map[string]string{"username": c.username, "password": c.password})
	if err != nil {
		return err
	}
	req, err := c.newAuthRequest(ctx, http.MethodPost, "/jwt/login", payload)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return err
	}
	token := firstStringValue(decoded, "token", "access_token", "accessToken", "jwt", "id_token")
	csrf := firstStringValue(decoded, "csrf", "xsrf", "xsrfToken", "XSRF-TOKEN")
	if token == "" {
		return errors.New("sdwan jwt login response did not include token")
	}
	c.bearerToken = token
	c.xsrfToken = csrf
	return nil
}

func (c *Client) loginSession(ctx context.Context) error {
	form := url.Values{}
	form.Set("j_username", c.username)
	form.Set("j_password", c.password)
	req, err := c.newAuthRequest(ctx, http.MethodPost, "/j_security_check", []byte(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || strings.Contains(strings.ToLower(string(body)), "<html") {
		return &APIError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	for _, cookie := range resp.Cookies() {
		if strings.EqualFold(cookie.Name, "JSESSIONID") && cookie.Value != "" {
			c.jsessionID = cookie.Value
			break
		}
	}
	if c.jsessionID == "" {
		return errors.New("sdwan session login response did not include JSESSIONID")
	}
	tokenReq, err := c.newAuthRequest(ctx, http.MethodGet, "/dataservice/client/token", nil)
	if err != nil {
		return err
	}
	tokenReq.Header.Set("Cookie", "JSESSIONID="+c.jsessionID)
	tokenResp, err := c.client.Do(tokenReq)
	if err != nil {
		return err
	}
	defer tokenResp.Body.Close()
	tokenBody, _ := io.ReadAll(tokenResp.Body)
	if tokenResp.StatusCode < 200 || tokenResp.StatusCode >= 300 {
		return &APIError{StatusCode: tokenResp.StatusCode, Body: strings.TrimSpace(string(tokenBody))}
	}
	c.xsrfToken = strings.TrimSpace(string(tokenBody))
	return nil
}

func (c *Client) clearAuth() {
	if c.authMode == "bearer" || c.authMode == "cookie" {
		return
	}
	c.authMu.Lock()
	defer c.authMu.Unlock()
	c.bearerToken = ""
	c.jsessionID = ""
	c.xsrfToken = ""
}

func (c *Client) applyAuth(req *http.Request) {
	if c.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearerToken)
	}
	if c.jsessionID != "" {
		req.Header.Set("Cookie", "JSESSIONID="+c.jsessionID)
	}
	if c.xsrfToken != "" && req.Method != http.MethodGet {
		req.Header.Set("X-XSRF-TOKEN", c.xsrfToken)
	}
}

func (c *Client) newRequest(ctx context.Context, method, path string, query url.Values, payload []byte) (*http.Request, error) {
	return c.newRequestWithPrefix(ctx, method, path, query, payload, true)
}

func (c *Client) newAuthRequest(ctx context.Context, method, path string, payload []byte) (*http.Request, error) {
	return c.newRequestWithPrefix(ctx, method, path, nil, payload, false)
}

func (c *Client) newRequestWithPrefix(ctx context.Context, method, path string, query url.Values, payload []byte, prefixDataservice bool) (*http.Request, error) {
	u := *c.endpoint
	cleanPath := "/" + strings.TrimLeft(path, "/")
	if prefixDataservice && !strings.HasPrefix(cleanPath, "/dataservice/") && cleanPath != "/dataservice" {
		cleanPath = "/dataservice" + cleanPath
	}
	basePath := strings.TrimRight(u.Path, "/")
	if basePath != "" && basePath != "/" && !strings.HasPrefix(cleanPath, basePath+"/") {
		cleanPath = basePath + cleanPath
	}
	u.Path = cleanPath
	u.RawQuery = query.Encode()
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	return http.NewRequestWithContext(ctx, method, u.String(), body)
}

func (c *Client) wait(ctx context.Context) error {
	if c.spacing <= 0 {
		return nil
	}
	c.limitMu.Lock()
	now := time.Now()
	waitUntil := c.nextSend
	if now.After(waitUntil) {
		waitUntil = now
	}
	c.nextSend = waitUntil.Add(c.spacing)
	c.limitMu.Unlock()
	if delay := time.Until(waitUntil); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

func (c *Client) emit(stat RequestStat) {
	if c.OnRequest != nil {
		c.OnRequest(stat)
	}
}

func decodeObject(body []byte) (Object, error) {
	var obj Object
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, err
	}
	return obj, nil
}

func decodeObjects(body []byte, header http.Header) ([]Object, error) {
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}
	return objectsFromAny(decoded), nil
}

func objectsFromAny(value any) []Object {
	switch typed := value.(type) {
	case []any:
		return objectsFromArray(typed)
	case map[string]any:
		for _, key := range []string{"data", "response", "items", "records"} {
			if arr, ok := typed[key].([]any); ok {
				return objectsFromArray(arr)
			}
		}
		if obj, ok := typed["data"].(map[string]any); ok {
			return []Object{Object(obj)}
		}
		return []Object{Object(typed)}
	default:
		return nil
	}
}

func objectsFromArray(values []any) []Object {
	out := make([]Object, 0, len(values))
	for _, value := range values {
		if obj, ok := value.(map[string]any); ok {
			out = append(out, Object(obj))
		}
	}
	return out
}

func capObjects(objects []Object, maxResults int) []Object {
	if maxResults > 0 && len(objects) > maxResults {
		return objects[:maxResults]
	}
	return objects
}

func firstStringValue(obj map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := StringValue(obj[key]); value != "" {
			return value
		}
	}
	return ""
}

func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusRequestTimeout || status >= 500 || status == 0
}

func retryAfter(value string) time.Duration {
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		return time.Duration(seconds) * time.Second
	}
	if parsed, err := http.ParseTime(value); err == nil {
		return time.Until(parsed)
	}
	return 0
}

func sleepBeforeRetry(ctx context.Context, attempt int, retryAfter time.Duration) bool {
	delay := retryAfter
	if delay <= 0 {
		delay = time.Duration(100*(1<<attempt)) * time.Millisecond
		delay += time.Duration(rand.Intn(100)) * time.Millisecond //nolint:gosec // jitter only
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
