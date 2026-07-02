// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package catalystcenter // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/catalystcenter"

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

const (
	defaultUserAgent          = "opentelemetry-collector-contrib-ciscoosreceiver"
	defaultRequestTimeout     = 30 * time.Second
	defaultPageSize           = 500
	defaultRequestSpacing     = 250 * time.Millisecond
	catalystCenterTokenMargin = 5 * time.Minute
	catalystCenterTokenTTL    = time.Hour
)

// Config controls the Catalyst Center API client.
type Config struct {
	Endpoint           string
	AuthMode           string
	Username           string
	Password           string
	AESCredentials     string
	UserAgent          string
	Timeout            time.Duration
	MaxRetries         int
	PageSize           int
	InsecureSkipVerify bool
}

// RequestStat describes a single Catalyst Center API request attempt.
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

// APIError is returned for non-success Catalyst Center API responses.
type APIError struct {
	StatusCode int
}

func (e *APIError) Error() string {
	return httpclient.StatusError("catalyst center", e.StatusCode)
}

// Client is a compact Catalyst Center REST client with token caching.
type Client struct {
	endpoint       *url.URL
	authMode       string
	username       string
	password       string
	aesCredentials string
	userAgent      string
	client         *http.Client
	retries        int
	pageSize       int
	spacing        time.Duration

	tokenMu     sync.Mutex
	token       string
	tokenExpiry time.Time
	authMu      sync.Mutex

	limitMu     sync.Mutex
	nextRequest time.Time

	OnRequest func(RequestStat)
}

// NewClient creates a Catalyst Center API client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("catalyst center endpoint is required")
	}
	parsed, err := url.Parse(cfg.Endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid catalyst center endpoint %q", cfg.Endpoint)
	}

	authMode := cfg.AuthMode
	if authMode == "" || authMode == "auto" {
		if cfg.AESCredentials != "" {
			authMode = "aes"
		} else {
			authMode = "basic"
		}
	}
	switch authMode {
	case "basic":
		if cfg.Username == "" || cfg.Password == "" {
			return nil, errors.New("catalyst center username and password are required for basic auth")
		}
	case "aes":
		if cfg.AESCredentials == "" {
			return nil, errors.New("catalyst center AES credentials are required for aes auth")
		}
	default:
		return nil, fmt.Errorf("unsupported catalyst center auth mode %q", authMode)
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
		return nil, fmt.Errorf("invalid catalyst center max retries: %w", err)
	}
	pageSize := cfg.PageSize
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if pageSize > defaultPageSize {
		pageSize = defaultPageSize
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // Explicit opt-in for lab Catalyst Center appliances.
	}

	return &Client{
		endpoint:       parsed,
		authMode:       authMode,
		username:       cfg.Username,
		password:       cfg.Password,
		aesCredentials: cfg.AESCredentials,
		userAgent:      userAgent,
		client:         &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: httpclient.SameOriginRedirectPolicy(parsed)},
		retries:        retries,
		pageSize:       pageSize,
		spacing:        defaultRequestSpacing,
	}, nil
}

// CloseIdleConnections closes idle HTTP connections held by the client.
func (c *Client) CloseIdleConnections() {
	c.client.CloseIdleConnections()
}

// GetJSON fetches a JSON document and decodes the complete response body.
func GetJSON[T any](ctx context.Context, c *Client, operation, path string, query url.Values) (T, error) {
	var out T
	body, err := c.do(ctx, http.MethodGet, operation, path, query, nil)
	if err != nil {
		return out, err
	}
	if err := httpclient.DecodeJSON(body, &out); err != nil {
		return out, fmt.Errorf("decode catalyst center %s response: %w", operation, err)
	}
	return out, nil
}

// GetResponseJSON fetches a JSON document and decodes the response property.
func GetResponseJSON[T any](ctx context.Context, c *Client, operation, path string, query url.Values) (T, error) {
	var out T
	body, err := c.do(ctx, http.MethodGet, operation, path, query, nil)
	if err != nil {
		return out, err
	}
	if err := decodeResponse(body, &out); err != nil {
		return out, fmt.Errorf("decode catalyst center %s response: %w", operation, err)
	}
	return out, nil
}

// GetCount fetches a count endpoint whose response value can be a number or an object containing count.
func GetCount(ctx context.Context, c *Client, operation, path string, query url.Values) (int64, error) {
	body, err := c.do(ctx, http.MethodGet, operation, path, query, nil)
	if err != nil {
		return 0, err
	}
	count, err := decodeCount(body)
	if err != nil {
		return 0, fmt.Errorf("decode catalyst center %s count: %w", operation, err)
	}
	return count, nil
}

// GetPaginatedJSON fetches all pages for an offset/limit response-array endpoint.
func GetPaginatedJSON[T any](ctx context.Context, c *Client, operation, path string, query url.Values, maxResults int) ([]T, error) {
	return GetPaginatedJSONWithPageLimit[T](ctx, c, operation, path, query, maxResults, 0)
}

// GetPaginatedJSONWithPageLimit fetches pages while applying an endpoint-specific page-size cap.
func GetPaginatedJSONWithPageLimit[T any](ctx context.Context, c *Client, operation, path string, query url.Values, maxResults, pageLimit int) ([]T, error) {
	if query == nil {
		query = url.Values{}
	}
	var results []T
	resultLimit, hardResultLimit := httpclient.EffectivePaginationResultLimit(maxResults)
	offset := 1
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
		pageSize := c.pageSizeFor(pageLimit)
		if remaining := resultLimit - len(results); remaining < pageSize {
			pageSize = remaining
		}
		pageQuery := cloneValues(query)
		pageQuery.Set("limit", strconv.Itoa(pageSize))
		pageQuery.Set("offset", strconv.Itoa(offset))
		requestKey := path + "?" + pageQuery.Encode()
		if _, seen := seenRequests[requestKey]; seen {
			return results, fmt.Errorf("paginate catalyst center %s response: detected continuation cycle after %d partial results", operation, len(results))
		}
		seenRequests[requestKey] = struct{}{}
		body, err := c.do(ctx, http.MethodGet, operation, path, pageQuery, nil)
		if err != nil {
			return results, err
		}
		if err := byteBudget.Charge(operation, len(body), len(results)); err != nil {
			return results, err
		}
		pages++
		var page []T
		pageInfo, hasPageInfo, err := decodePage(body, &page)
		if err != nil {
			return results, fmt.Errorf("decode catalyst center %s page: %w", operation, err)
		}
		results = append(results, page...)
		complete := len(page) == 0 || len(page) < pageSize || pageInfo.complete(len(page), hasPageInfo)
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
		offset += len(page)
	}
}

// PostPaginatedJSON fetches all pages for a POST endpoint with response and page envelope fields.
func PostPaginatedJSON[T any](ctx context.Context, c *Client, operation, path string, body map[string]any, maxResults int) ([]T, error) {
	var results []T
	resultLimit, hardResultLimit := httpclient.EffectivePaginationResultLimit(maxResults)
	offset := 1
	pages := 0
	var byteBudget httpclient.PaginationByteBudget
	seenOffsets := make(map[int]struct{})
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
		if _, seen := seenOffsets[offset]; seen {
			return results, fmt.Errorf("paginate catalyst center %s response: detected continuation cycle after %d partial results", operation, len(results))
		}
		seenOffsets[offset] = struct{}{}
		pageSize := c.pageSize
		if remaining := resultLimit - len(results); remaining < pageSize {
			pageSize = remaining
		}
		pageBody := cloneMap(body)
		pageBody["page"] = map[string]any{
			"limit":  pageSize,
			"offset": offset,
		}
		payload, err := json.Marshal(pageBody)
		if err != nil {
			return results, err
		}
		responseBody, err := c.do(ctx, http.MethodPost, operation, path, nil, payload)
		if err != nil {
			return results, err
		}
		if err := byteBudget.Charge(operation, len(responseBody), len(results)); err != nil {
			return results, err
		}
		pages++
		var page []T
		pageInfo, hasPageInfo, err := decodePage(responseBody, &page)
		if err != nil {
			return results, fmt.Errorf("decode catalyst center %s page: %w", operation, err)
		}
		results = append(results, page...)
		complete := len(page) == 0 || len(page) < pageSize || pageInfo.complete(len(page), hasPageInfo)
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
		offset += len(page)
	}
}

func (c *Client) pageSizeFor(pageLimit int) int {
	pageSize := c.pageSize
	if pageLimit > 0 && pageLimit < pageSize {
		pageSize = pageLimit
	}
	return pageSize
}

func (c *Client) do(ctx context.Context, method, operation, path string, query url.Values, payload []byte) ([]byte, error) {
	for authAttempt := 0; authAttempt < 2; authAttempt++ {
		token, err := c.getToken(ctx)
		if err != nil {
			return nil, err
		}
		body, err := c.doWithToken(ctx, method, operation, path, query, payload, token)
		if err == nil {
			return body, nil
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized || authAttempt > 0 {
			return nil, err
		}
		c.invalidateToken()
	}
	return nil, errors.New("catalyst center request failed")
}

func (c *Client) getToken(ctx context.Context) (string, error) {
	c.tokenMu.Lock()
	if c.token != "" && time.Until(c.tokenExpiry) > catalystCenterTokenMargin {
		token := c.token
		c.tokenMu.Unlock()
		return token, nil
	}
	c.tokenMu.Unlock()

	c.authMu.Lock()
	defer c.authMu.Unlock()

	c.tokenMu.Lock()
	if c.token != "" && time.Until(c.tokenExpiry) > catalystCenterTokenMargin {
		token := c.token
		c.tokenMu.Unlock()
		return token, nil
	}
	c.tokenMu.Unlock()

	token, err := c.authenticate(ctx)
	if err != nil {
		return "", err
	}
	c.tokenMu.Lock()
	c.token = token
	c.tokenExpiry = time.Now().Add(catalystCenterTokenTTL)
	c.tokenMu.Unlock()
	return token, nil
}

func (c *Client) invalidateToken() {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	c.token = ""
	c.tokenExpiry = time.Time{}
}

func (c *Client) authenticate(ctx context.Context) (string, error) {
	body, err := c.doRaw(ctx, http.MethodPost, "auth.token", "/dna/system/api/v1/auth/token", nil, nil, "", c.authHeader())
	if err != nil {
		return "", err
	}
	var envelope struct {
		Token string `json:"Token"`
	}
	if err := httpclient.DecodeJSON(body, &envelope); err != nil {
		return "", fmt.Errorf("decode catalyst center auth token response: %w", err)
	}
	if envelope.Token == "" {
		return "", errors.New("catalyst center auth token response did not include Token")
	}
	return envelope.Token, nil
}

func (c *Client) doWithToken(ctx context.Context, method, operation, path string, query url.Values, payload []byte, token string) ([]byte, error) {
	return c.doRaw(ctx, method, operation, path, query, payload, token, "")
}

func (c *Client) doRaw(ctx context.Context, method, operation, path string, query url.Values, payload []byte, token, authorization string) ([]byte, error) {
	var lastErr error
	attempts := c.retries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		if err := c.wait(ctx); err != nil {
			return nil, err
		}
		reqURL := c.buildURL(path, query)
		var body io.Reader
		if payload != nil {
			body = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.userAgent)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set("X-Auth-Token", token)
		}
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
			req.Header.Set("Content-Type", "application/json")
		}

		start := time.Now()
		resp, err := c.client.Do(req)
		duration := time.Since(start)
		if err != nil {
			lastErr = err
			c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "error", Duration: duration, Err: err})
			if attempt == attempts-1 || !sleepBeforeRetry(ctx, attempt, -1) {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				return nil, err
			}
			continue
		}

		bodyBytes, readErr := httpclient.ReadResponseBody(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: readErr})
			return nil, readErr
		}
		if closeErr != nil {
			lastErr = closeErr
			return nil, closeErr
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "success", StatusCode: resp.StatusCode, Duration: duration})
			return bodyBytes, nil
		}

		apiErr := &APIError{StatusCode: resp.StatusCode}
		lastErr = apiErr
		rateLimited := resp.StatusCode == http.StatusTooManyRequests
		c.record(RequestStat{
			Operation:   operation,
			Method:      method,
			Path:        path,
			Outcome:     "error",
			StatusCode:  resp.StatusCode,
			Duration:    duration,
			RateLimited: rateLimited,
			Err:         apiErr,
		})
		if !retryableStatus(resp.StatusCode) || attempt == attempts-1 || !sleepBeforeRetry(ctx, attempt, retryAfter(resp.Header.Get("Retry-After"))) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, apiErr
		}
	}
	if lastErr == nil {
		lastErr = errors.New("catalyst center request failed")
	}
	return nil, lastErr
}

func (c *Client) authHeader() string {
	if c.authMode == "aes" {
		return "CSCO-AES-256 credentials=" + c.aesCredentials
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.username+":"+c.password))
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

func (c *Client) wait(ctx context.Context) error {
	c.limitMu.Lock()
	delay := time.Until(c.nextRequest)
	if delay <= 0 {
		c.nextRequest = time.Now().Add(c.spacing)
		c.limitMu.Unlock()
		return nil
	}
	c.limitMu.Unlock()

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		c.limitMu.Lock()
		if time.Now().After(c.nextRequest) {
			c.nextRequest = time.Now().Add(c.spacing)
		} else {
			c.nextRequest = c.nextRequest.Add(c.spacing)
		}
		c.limitMu.Unlock()
		return nil
	}
}

func (c *Client) record(stat RequestStat) {
	if c.OnRequest != nil {
		c.OnRequest(stat)
	}
}

func decodeResponse(body []byte, out any) error {
	_, _, err := decodePage(body, out)
	return err
}

type pageMetadata struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
	Count  int `json:"count"`
}

func (p pageMetadata) complete(items int, ok bool) bool {
	if !ok || p.Count <= 0 || p.Offset <= 0 {
		return false
	}
	return p.Offset+items-1 >= p.Count
}

func decodePage(body []byte, out any) (pageMetadata, bool, error) {
	var envelope struct {
		Response json.RawMessage `json:"response"`
		Detail   json.RawMessage `json:"detail"`
		Page     *pageMetadata   `json:"page"`
	}
	if err := httpclient.DecodeJSON(body, &envelope); err != nil {
		return pageMetadata{}, false, err
	}
	raw := envelope.Response
	if len(raw) == 0 {
		raw = envelope.Detail
	}
	if len(raw) == 0 {
		return pageMetadata{}, envelope.Page != nil, errors.New("missing response field")
	}
	if err := httpclient.DecodeJSON(raw, out); err != nil {
		return pageMetadata{}, envelope.Page != nil, err
	}
	if envelope.Page == nil {
		return pageMetadata{}, false, nil
	}
	return *envelope.Page, true, nil
}

func decodeCount(body []byte) (int64, error) {
	var envelope struct {
		Response any `json:"response"`
	}
	if err := httpclient.DecodeJSON(body, &envelope); err != nil {
		return 0, err
	}
	return countFromAny(envelope.Response)
}

func countFromAny(value any) (int64, error) {
	switch typed := value.(type) {
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || math.Trunc(typed) != typed || typed < float64(math.MinInt64) || typed >= float64(math.MaxInt64) {
			return 0, fmt.Errorf("invalid count value %v", typed)
		}
		return int64(typed), nil
	case int64:
		return typed, nil
	case json.Number:
		count, err := typed.Int64()
		if err != nil {
			return 0, fmt.Errorf("invalid count value %q: %w", typed, err)
		}
		return count, nil
	case map[string]any:
		if count, ok := typed["count"]; ok {
			return countFromAny(count)
		}
	case nil:
		return 0, errors.New("missing response field")
	}
	return 0, fmt.Errorf("unsupported count response %T", value)
}

func cloneValues(values url.Values) url.Values {
	out := url.Values{}
	for key, value := range values {
		out[key] = append([]string(nil), value...)
	}
	return out
}

func cloneMap(values map[string]any) map[string]any {
	out := make(map[string]any, len(values)+1)
	for key, value := range values {
		out[key] = value
	}
	return out
}

func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout || status >= 500
}

func retryAfter(header string) time.Duration {
	if header == "" {
		return -1
	}
	if seconds, err := strconv.Atoi(header); err == nil {
		return time.Duration(seconds) * time.Second
	}
	if ts, err := http.ParseTime(header); err == nil {
		return time.Until(ts)
	}
	return -1
}

func sleepBeforeRetry(ctx context.Context, attempt int, retryAfter time.Duration) bool {
	delay := retryAfter
	if delay < 0 {
		base := time.Duration(1<<attempt) * 200 * time.Millisecond
		jitter := time.Duration(rand.Int63n(int64(100 * time.Millisecond))) //nolint:gosec // Non-cryptographic retry jitter.
		delay = base + jitter
	}
	if delay <= 0 {
		return true
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
