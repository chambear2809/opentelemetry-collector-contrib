// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package fmc

import (
	"bytes"
	"context"
	"crypto/tls"
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
	tokenRefreshAfter     = 25 * time.Minute
)

// Config controls the Cisco Secure Firewall Management Center REST API client.
type Config struct {
	Endpoint           string
	Name               string
	Username           string
	Password           string
	DomainUUID         string
	UserAgent          string
	Timeout            time.Duration
	MaxRetries         int
	PageSize           int
	InsecureSkipVerify bool
}

// RequestStat describes a single FMC REST API request attempt.
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

// APIError is returned for non-success FMC REST API responses.
type APIError struct {
	StatusCode int
}

func (e *APIError) Error() string {
	return httpclient.StatusError("fmc", e.StatusCode)
}

// Client is a compact FMC REST API client.
type Client struct {
	endpoint   *url.URL
	name       string
	username   string
	password   string
	domainUUID string
	userAgent  string
	client     *http.Client
	retries    int
	pageSize   int

	tokenMu      sync.Mutex
	accessToken  string
	refreshToken string
	tokenAt      time.Time
	refreshes    int

	OnRequest func(RequestStat)
}

// NewClient creates an FMC REST API client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("fmc endpoint is required")
	}
	parsed, err := url.Parse(cfg.Endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid fmc endpoint %q", cfg.Endpoint)
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, errors.New("fmc username and password are required")
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
		return nil, fmt.Errorf("invalid fmc max retries: %w", err)
	}
	pageSize := cfg.PageSize
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
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
		domainUUID: cfg.DomainUUID,
		userAgent:  userAgent,
		client:     &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: httpclient.SameOriginRedirectPolicy(parsed)},
		retries:    retries,
		pageSize:   pageSize,
	}, nil
}

// CloseIdleConnections closes idle HTTP connections held by the client.
func (c *Client) CloseIdleConnections() {
	c.client.CloseIdleConnections()
}

// ControllerName returns a stable display name for the FMC endpoint.
func (c *Client) ControllerName() string {
	return c.name
}

// Endpoint returns the configured FMC endpoint URL.
func (c *Client) Endpoint() string {
	return c.endpoint.String()
}

// DomainUUID returns the FMC domain UUID for config API requests.
func (c *Client) DomainUUID(ctx context.Context) (string, error) {
	if c.domainUUID != "" {
		return c.domainUUID, nil
	}
	if err := c.ensureToken(ctx); err != nil {
		return "", err
	}
	if c.domainUUID == "" {
		return "", errors.New("fmc authentication response did not include DOMAIN_UUID; configure fmc.controllers[].domain_uuid")
	}
	return c.domainUUID, nil
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

// List fetches all pages for an FMC REST endpoint.
func (c *Client) List(ctx context.Context, operation, path string, query url.Values, maxResults int) ([]Object, error) {
	return c.list(ctx, http.MethodGet, operation, path, query, nil, maxResults)
}

// PostList fetches all pages for an FMC REST endpoint that uses POST for read-only queries.
func (c *Client) PostList(ctx context.Context, operation, path string, query url.Values, payload []byte, maxResults int) ([]Object, error) {
	return c.list(ctx, http.MethodPost, operation, path, query, payload, maxResults)
}

func (c *Client) list(ctx context.Context, method, operation, path string, query url.Values, payload []byte, maxResults int) ([]Object, error) {
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
		if _, ok := pageQuery["limit"]; !ok {
			pageQuery.Set("limit", strconv.Itoa(pageSize))
		}
		if _, ok := pageQuery["offset"]; !ok {
			pageQuery.Set("offset", strconv.Itoa(offset))
		}
		requestKey := method + " " + path + "?" + pageQuery.Encode()
		if _, seen := seenRequests[requestKey]; seen {
			return results, fmt.Errorf("paginate fmc %s response: detected continuation cycle after %d partial results", operation, len(results))
		}
		seenRequests[requestKey] = struct{}{}

		body, _, err := c.do(ctx, method, operation, path, pageQuery, payload)
		if err != nil {
			return results, err
		}
		if budgetErr := byteBudget.Charge(operation, len(body), len(results)); budgetErr != nil {
			return results, budgetErr
		}
		pages++
		pageObjects, next, total, err := decodeObjects(body)
		if err != nil {
			return results, fmt.Errorf("decode fmc %s response: %w", operation, err)
		}
		results = append(results, pageObjects...)
		complete := len(pageObjects) == 0 || len(pageObjects) < pageSize || total > -1 && len(results) >= total || next == "" && total < 0
		truncated := len(results) > resultLimit
		if len(results) >= resultLimit {
			results = results[:resultLimit]
			if hardResultLimit && (truncated || !complete) {
				return results, httpclient.NewPaginationLimitError(operation, "result", resultLimit, len(results))
			}
			return results, nil
		}
		if complete {
			return results, nil
		}
		offset += len(pageObjects)
	}
}

func (c *Client) do(ctx context.Context, method, operation, path string, query url.Values, payload []byte) ([]byte, http.Header, error) {
	var lastErr error
	attempts := c.retries + 1
	for attempt := range attempts {
		body, header, status, err := c.doOnce(ctx, method, operation, path, query, payload)
		if err == nil {
			return body, header, nil
		}
		lastErr = err
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			// Drop the token but do not retry inline — a bad credential would
			// otherwise loop login → fail → login on every attempt and risk
			// locking the FMC user account. The next scrape re-authenticates.
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
		if !retryableStatus(status) || attempt == attempts-1 || !sleepBeforeRetry(ctx, attempt, retryAfter(retryHeader)) {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			return nil, nil, err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("fmc request failed")
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
	if tokenErr := c.ensureToken(ctx); tokenErr != nil {
		return nil, nil, 0, tokenErr
	}
	c.tokenMu.Lock()
	accessToken := c.accessToken
	c.tokenMu.Unlock()
	req.Header.Set("X-auth-access-token", accessToken)

	start := time.Now()
	resp, err := c.client.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.record(RequestStat{Controller: c.name, Operation: operation, Method: method, Path: path, Outcome: "error", Duration: duration, Err: err})
		return nil, nil, 0, err
	}
	bodyBytes, readErr := httpclient.ReadResponseBody(resp.Body)
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
	apiErr := &APIError{StatusCode: resp.StatusCode}
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

func (c *Client) ensureToken(ctx context.Context) error {
	c.tokenMu.Lock()
	if c.accessToken != "" && time.Since(c.tokenAt) < tokenRefreshAfter {
		c.tokenMu.Unlock()
		return nil
	}
	canRefresh := c.refreshToken != "" && c.refreshes < 3
	c.tokenMu.Unlock()
	if canRefresh {
		if err := c.refresh(ctx); err == nil {
			return nil
		}
	}
	return c.generateToken(ctx)
}

func (c *Client) generateToken(ctx context.Context) error {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.accessToken != "" && time.Since(c.tokenAt) < tokenRefreshAfter {
		return nil
	}
	reqURL := c.buildURL("/api/fmc_platform/v1/auth/generatetoken", nil)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, http.NoBody)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	start := time.Now()
	resp, err := c.client.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.record(RequestStat{Controller: c.name, Operation: "auth.generatetoken", Method: http.MethodPost, Path: "/api/fmc_platform/v1/auth/generatetoken", Outcome: "error", Duration: duration, Err: err})
		return err
	}
	_, readErr := httpclient.ReadResponseBody(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		c.record(RequestStat{Controller: c.name, Operation: "auth.generatetoken", Method: http.MethodPost, Path: "/api/fmc_platform/v1/auth/generatetoken", Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: readErr})
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode}
		c.record(RequestStat{Controller: c.name, Operation: "auth.generatetoken", Method: http.MethodPost, Path: "/api/fmc_platform/v1/auth/generatetoken", Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: apiErr})
		return apiErr
	}
	access := firstHeader(resp.Header, "X-auth-access-token", "x-auth-access-token")
	refresh := firstHeader(resp.Header, "X-auth-refresh-token", "x-auth-refresh-token")
	if access == "" {
		err := errors.New("fmc authentication response did not include X-auth-access-token")
		c.record(RequestStat{Controller: c.name, Operation: "auth.generatetoken", Method: http.MethodPost, Path: "/api/fmc_platform/v1/auth/generatetoken", Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: err})
		return err
	}
	c.accessToken = access
	c.refreshToken = refresh
	c.tokenAt = time.Now()
	c.refreshes = 0
	if c.domainUUID == "" {
		c.domainUUID = firstHeader(resp.Header, "DOMAIN_UUID", "domain_uuid", "Domain-UUID")
	}
	c.record(RequestStat{Controller: c.name, Operation: "auth.generatetoken", Method: http.MethodPost, Path: "/api/fmc_platform/v1/auth/generatetoken", Outcome: "success", StatusCode: resp.StatusCode, Duration: duration})
	return nil
}

func (c *Client) refresh(ctx context.Context) error {
	c.tokenMu.Lock()
	refreshToken := c.refreshToken
	c.tokenMu.Unlock()
	if refreshToken == "" {
		return errors.New("fmc refresh token is empty")
	}

	reqURL := c.buildURL("/api/fmc_platform/v1/auth/refreshtoken", nil)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("X-auth-refresh-token", refreshToken)

	start := time.Now()
	resp, err := c.client.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.record(RequestStat{Controller: c.name, Operation: "auth.refreshtoken", Method: http.MethodPost, Path: "/api/fmc_platform/v1/auth/refreshtoken", Outcome: "error", Duration: duration, Err: err})
		return err
	}
	_, readErr := httpclient.ReadResponseBody(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		c.record(RequestStat{Controller: c.name, Operation: "auth.refreshtoken", Method: http.MethodPost, Path: "/api/fmc_platform/v1/auth/refreshtoken", Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: readErr})
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode}
		c.record(RequestStat{Controller: c.name, Operation: "auth.refreshtoken", Method: http.MethodPost, Path: "/api/fmc_platform/v1/auth/refreshtoken", Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: apiErr})
		return apiErr
	}
	access := firstHeader(resp.Header, "X-auth-access-token", "x-auth-access-token")
	refresh := firstHeader(resp.Header, "X-auth-refresh-token", "x-auth-refresh-token")
	if access == "" {
		err := errors.New("fmc refresh response did not include X-auth-access-token")
		c.record(RequestStat{Controller: c.name, Operation: "auth.refreshtoken", Method: http.MethodPost, Path: "/api/fmc_platform/v1/auth/refreshtoken", Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: err})
		return err
	}
	c.tokenMu.Lock()
	c.accessToken = access
	c.refreshToken = refresh
	c.tokenAt = time.Now()
	c.refreshes++
	c.tokenMu.Unlock()
	c.record(RequestStat{Controller: c.name, Operation: "auth.refreshtoken", Method: http.MethodPost, Path: "/api/fmc_platform/v1/auth/refreshtoken", Outcome: "success", StatusCode: resp.StatusCode, Duration: duration})
	return nil
}

func (c *Client) clearToken() {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	c.accessToken = ""
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

func decodeObjects(body []byte) ([]Object, string, int, error) {
	var raw any
	if err := httpclient.DecodeJSON(body, &raw); err != nil {
		return nil, "", -1, err
	}
	return objectsFromRaw(raw)
}

func objectsFromRaw(raw any) ([]Object, string, int, error) {
	switch typed := raw.(type) {
	case map[string]any:
		next := ""
		total := -1
		if paging, ok := typed["paging"].(map[string]any); ok {
			next = String(paging, "next")
			if count, ok := Float64(Object(paging), "count", "total", "totalCount"); ok {
				total = int(count)
			}
		}
		if metadata, ok := typed["metadata"].(map[string]any); ok && total < 0 {
			if count, ok := Float64(Object(metadata), "count", "total", "totalCount"); ok {
				total = int(count)
			}
		}
		for _, key := range []string{"items", "data", "results"} {
			if items, ok := typed[key].([]any); ok {
				return objectsFromArray(items), next, total, nil
			}
		}
		return []Object{Object(typed)}, next, 1, nil
	case []any:
		items := objectsFromArray(typed)
		return items, "", len(items), nil
	default:
		return nil, "", -1, fmt.Errorf("unexpected FMC response type %T", raw)
	}
}

func objectsFromArray(items []any) []Object {
	out := make([]Object, 0, len(items))
	for _, item := range items {
		if obj, ok := item.(map[string]any); ok {
			out = append(out, Object(obj))
		}
	}
	return out
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

func firstHeader(header http.Header, keys ...string) string {
	for _, key := range keys {
		if value := header.Get(key); value != "" {
			return value
		}
	}
	return ""
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
