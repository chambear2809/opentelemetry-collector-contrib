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
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

const (
	defaultUserAgent      = "opentelemetry-collector-contrib-ciscoosreceiver"
	defaultRequestTimeout = 30 * time.Second
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
}

func (e *APIError) Error() string {
	return httpclient.StatusError("nexus dashboard", e.StatusCode)
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

	tokenMu         sync.Mutex
	token           string
	tokenGeneration uint64
	loginInflight   chan struct{}
	lastAuthErr     error
	lastAuthStatus  int
	lastAuthAt      time.Time
	authFailures    int

	OnRequest func(RequestStat)
}

// tokenSnapshot identifies the exact credential used by one request. Both the
// generation and value are checked before invalidating shared state so a late
// 401 cannot erase a token acquired by a newer login.
type tokenSnapshot struct {
	value      string
	generation uint64
}

type requestAuthState struct {
	token          tokenSnapshot
	loginAttempted bool
	failed         bool
}

// authBackoffSchedule bounds authentication attempts shared by all endpoint
// groups. This is intentionally independent of ordinary request retries: one
// operation may retry its own transient login failure, while later operations
// observe the shared backoff instead of starting a login storm.
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
	retries, err := httpclient.RetryCount(cfg.MaxRetries)
	if err != nil {
		return nil, fmt.Errorf("invalid nexus dashboard max retries: %w", err)
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
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &Client{
		endpoint:  parsed,
		authMode:  authMode,
		username:  cfg.Username,
		password:  cfg.Password,
		apiKey:    cfg.APIKey,
		domain:    domain,
		userAgent: userAgent,
		client:    &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: httpclient.SameOriginRedirectPolicy(parsed)},
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
	resultLimit, hardResultLimit := httpclient.EffectivePaginationResultLimit(maxResults)
	offset := 0
	pages := 0
	var byteBudget httpclient.PaginationByteBudget
	seenRequests := make(map[string]struct{})
	for {
		if len(results) >= resultLimit {
			if hardResultLimit {
				return results, httpclient.NewPaginationLimitError(operation, "result", resultLimit, len(results))
			}
			return results, nil
		}
		if pages >= httpclient.HardMaxPaginationPages {
			return results, httpclient.NewPaginationLimitError(operation, "page", httpclient.HardMaxPaginationPages, len(results))
		}
		pageQuery := cloneValues(query)
		pageSize := c.pageSize
		if remaining := resultLimit - len(results); remaining < pageSize {
			pageSize = remaining
		}
		if _, hasMax := pageQuery["max"]; !hasMax {
			pageQuery.Set("max", strconv.Itoa(pageSize))
		}
		if _, hasOffset := pageQuery["offset"]; !hasOffset {
			pageQuery.Set("offset", strconv.Itoa(offset))
		}
		requestKey := path + "?" + pageQuery.Encode()
		if _, seen := seenRequests[requestKey]; seen {
			return results, fmt.Errorf("paginate nexus dashboard %s response: detected continuation cycle after %d partial results", operation, len(results))
		}
		seenRequests[requestKey] = struct{}{}

		body, header, err := c.do(ctx, http.MethodGet, operation, path, pageQuery, nil)
		if err != nil {
			return results, err
		}
		if budgetErr := byteBudget.Charge(operation, len(body), len(results)); budgetErr != nil {
			return results, budgetErr
		}
		pages++
		page, next, remaining, err := decodeObjects(body, header)
		if err != nil {
			return results, fmt.Errorf("decode nexus dashboard %s response: %w", operation, err)
		}
		results = append(results, page...)
		complete := next == "" && (len(page) == 0 || len(page) < pageSize || remaining <= 0)
		truncated := len(results) > resultLimit
		if len(results) >= resultLimit {
			results = results[:resultLimit]
			if hardResultLimit && (truncated || !complete) {
				return results, httpclient.NewPaginationLimitError(operation, "result", resultLimit, len(results))
			}
			return results, nil
		}
		if next != "" {
			path, query = splitNextURL(next)
			offset = 0
			continue
		}
		if complete {
			return results, nil
		}
		offset += len(page)
	}
}

func (c *Client) do(ctx context.Context, method, operation, path string, query url.Values, payload []byte) ([]byte, http.Header, error) {
	var lastErr error
	attempts := c.retries + 1
	bypassAuthBackoff := false
	for attempt := range attempts {
		body, header, status, requestAuth, err := c.doOnce(ctx, method, operation, path, query, payload, bypassAuthBackoff)
		if err == nil {
			c.markAuthSuccess(requestAuth.token)
			return body, header, nil
		}
		lastErr = err
		if status == http.StatusUnauthorized {
			// Login failures are charged by ensureToken. A data request clears only
			// the exact token snapshot it used so a delayed response cannot erase a
			// replacement token published by another request.
			c.clearToken(requestAuth.token, err)
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			return nil, nil, err
		}
		if status == http.StatusForbidden {
			// A valid token may simply lack access to one optional endpoint. Keep
			// it so later endpoint groups can still return partial results.
			return nil, nil, err
		}
		if requestAuth.failed && !requestAuth.loginAttempted {
			// This operation observed a failure already cached by another endpoint.
			// It must not turn an ordinary request retry into another login attempt.
			return nil, nil, err
		}
		retryHeader := ""
		if header != nil {
			retryHeader = header.Get("Retry-After")
		}
		if !retryableStatus(status) || attempt == attempts-1 || !sleepBeforeRetry(ctx, attempt, retryAfter(retryHeader)) {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			return nil, nil, err
		}
		// Only the operation that actually made a transient login attempt may
		// bypass the shared auth backoff for its configured inline retry.
		bypassAuthBackoff = requestAuth.failed && requestAuth.loginAttempted
	}
	if lastErr == nil {
		lastErr = errors.New("nexus dashboard request failed")
	}
	return nil, nil, lastErr
}

func (c *Client) doOnce(
	ctx context.Context,
	method, operation, path string,
	query url.Values,
	payload []byte,
	bypassAuthBackoff bool,
) ([]byte, http.Header, int, requestAuthState, error) {
	reqURL := c.buildURL(path, query)
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, nil, 0, requestAuthState{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	requestAuth, authStatus, authErr := c.authorize(ctx, req, bypassAuthBackoff)
	if authErr != nil {
		return nil, nil, authStatus, requestAuth, authErr
	}

	start := time.Now()
	resp, err := c.client.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "error", Duration: duration, Err: err})
		return nil, nil, 0, requestAuth, err
	}
	bodyBytes, readErr := httpclient.ReadResponseBody(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: readErr})
		return nil, resp.Header, resp.StatusCode, requestAuth, readErr
	}
	if closeErr != nil {
		return nil, resp.Header, resp.StatusCode, requestAuth, closeErr
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "success", StatusCode: resp.StatusCode, Duration: duration})
		return bodyBytes, resp.Header, resp.StatusCode, requestAuth, nil
	}
	apiErr := &APIError{StatusCode: resp.StatusCode}
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
	return nil, resp.Header, resp.StatusCode, requestAuth, apiErr
}

func (c *Client) authorize(ctx context.Context, req *http.Request, bypassAuthBackoff bool) (requestAuthState, int, error) {
	switch c.authMode {
	case "api_key":
		req.Header.Set("X-Nd-Username", c.username)
		req.Header.Set("X-Nd-Apikey", c.apiKey)
		return requestAuthState{}, 0, nil
	case "username_password":
		token, status, attempted, err := c.ensureToken(ctx, bypassAuthBackoff)
		requestAuth := requestAuthState{token: token, loginAttempted: attempted, failed: err != nil}
		if err != nil {
			return requestAuth, status, err
		}
		req.Header.Set("Authorization", "Bearer "+token.value)
		req.AddCookie(&http.Cookie{Name: "AuthCookie", Value: token.value})
		return requestAuth, 0, nil
	default:
		return requestAuthState{}, 0, fmt.Errorf("unsupported nexus dashboard auth mode %q", c.authMode)
	}
}

func (c *Client) ensureToken(ctx context.Context, bypassAuthBackoff bool) (tokenSnapshot, int, bool, error) {
	for {
		c.tokenMu.Lock()
		if c.token != "" {
			token := tokenSnapshot{value: c.token, generation: c.tokenGeneration}
			c.tokenMu.Unlock()
			return token, 0, false, nil
		}
		if c.loginInflight != nil {
			inflight := c.loginInflight
			c.tokenMu.Unlock()
			select {
			case <-inflight:
				// The completed login was the shared attempt for this caller. If it
				// failed, observe its backoff rather than immediately trying again.
				bypassAuthBackoff = false
			case <-ctx.Done():
				return tokenSnapshot{}, 0, false, ctx.Err()
			}
			continue
		}
		if !bypassAuthBackoff && c.authFailures > 0 && time.Since(c.lastAuthAt) < authBackoffFor(c.authFailures) {
			err := c.lastAuthErr
			status := c.lastAuthStatus
			c.tokenMu.Unlock()
			if err == nil {
				err = errors.New("nexus dashboard auth in backoff")
			}
			return tokenSnapshot{}, status, false, err
		}
		inflight := make(chan struct{})
		c.loginInflight = inflight
		c.tokenMu.Unlock()

		tokenValue, status, err := c.login(ctx)

		c.tokenMu.Lock()
		c.loginInflight = nil
		if err != nil {
			if ctx.Err() == nil {
				c.authFailures++
				c.lastAuthErr = err
				c.lastAuthStatus = status
				c.lastAuthAt = time.Now()
			}
		} else {
			// Do not reset authFailures here. Only an authenticated data response
			// proves that the new token is accepted by the controller.
			c.tokenGeneration++
			c.token = tokenValue
		}
		generation := c.tokenGeneration
		close(inflight)
		c.tokenMu.Unlock()
		if err != nil {
			if ctx.Err() != nil {
				return tokenSnapshot{}, status, true, ctx.Err()
			}
			return tokenSnapshot{}, status, true, err
		}
		return tokenSnapshot{value: tokenValue, generation: generation}, status, true, nil
	}
}

func (c *Client) login(ctx context.Context) (string, int, error) {
	payload, err := json.Marshal(map[string]string{
		"domain":     c.domain,
		"userName":   c.username,
		"userPasswd": c.password,
	})
	if err != nil {
		return "", 0, err
	}
	reqURL := c.buildURL("/api/v1/infra/login", nil)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(payload))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	start := time.Now()
	resp, err := c.client.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.record(RequestStat{Operation: "infra.login", Method: http.MethodPost, Path: "/api/v1/infra/login", Outcome: "error", Duration: duration, Err: err})
		return "", 0, err
	}
	bodyBytes, readErr := httpclient.ReadResponseBody(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		c.record(RequestStat{Operation: "infra.login", Method: http.MethodPost, Path: "/api/v1/infra/login", Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: readErr})
		return "", resp.StatusCode, readErr
	}
	if closeErr != nil {
		return "", resp.StatusCode, closeErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode}
		c.record(RequestStat{Operation: "infra.login", Method: http.MethodPost, Path: "/api/v1/infra/login", Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: apiErr})
		return "", resp.StatusCode, apiErr
	}
	var login struct {
		Token    string `json:"token"`
		JWTToken string `json:"jwttoken"`
	}
	if err := json.Unmarshal(bodyBytes, &login); err != nil {
		c.record(RequestStat{Operation: "infra.login", Method: http.MethodPost, Path: "/api/v1/infra/login", Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: err})
		return "", resp.StatusCode, err
	}
	token := login.Token
	if token == "" {
		token = login.JWTToken
	}
	if token == "" {
		err := errors.New("nexus dashboard login response did not include a token")
		c.record(RequestStat{Operation: "infra.login", Method: http.MethodPost, Path: "/api/v1/infra/login", Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: err})
		return "", resp.StatusCode, err
	}
	c.record(RequestStat{Operation: "infra.login", Method: http.MethodPost, Path: "/api/v1/infra/login", Outcome: "success", StatusCode: resp.StatusCode, Duration: duration})
	return token, resp.StatusCode, nil
}

func (c *Client) clearToken(token tokenSnapshot, authErr error) {
	if c.authMode != "username_password" || token.value == "" {
		return
	}
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.tokenGeneration != token.generation || c.token != token.value {
		return
	}
	c.tokenGeneration++
	c.token = ""
	c.authFailures++
	if authErr == nil {
		authErr = errors.New("nexus dashboard authentication rejected")
	}
	c.lastAuthErr = authErr
	c.lastAuthStatus = http.StatusUnauthorized
	c.lastAuthAt = time.Now()
}

func (c *Client) markAuthSuccess(token tokenSnapshot) {
	if c.authMode != "username_password" || token.value == "" {
		return
	}
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.tokenGeneration != token.generation || c.token != token.value {
		return
	}
	c.authFailures = 0
	c.lastAuthErr = nil
	c.lastAuthStatus = 0
	c.lastAuthAt = time.Time{}
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
	if err := httpclient.DecodeJSON(body, &value); err != nil {
		return nil, "", 0, err
	}
	objects := objectsFromValue(value)
	next := httpclient.NextLink(header.Get("Link"))
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
		jitter := time.Duration(rand.Int64N(int64(100 * time.Millisecond)))
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
