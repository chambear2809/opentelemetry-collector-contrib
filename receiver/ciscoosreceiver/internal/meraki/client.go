// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meraki // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/meraki"

import (
	"context"
	"errors"
	"fmt"
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
	defaultBaseURL        = "https://api.meraki.com/api/v1"
	defaultUserAgent      = "opentelemetry-collector-contrib-ciscoosreceiver"
	defaultRequestTimeout = 30 * time.Second
)

// Config controls the Meraki Dashboard API client.
type Config struct {
	APIKey     string
	BaseURL    string
	UserAgent  string
	Timeout    time.Duration
	MaxRetries int
}

// RequestStat describes a single API request attempt.
type RequestStat struct {
	OrganizationID string
	Operation      string
	Method         string
	Path           string
	Outcome        string
	StatusCode     int
	Duration       time.Duration
	RateLimited    bool
	Err            error
}

// APIError is returned for non-success Meraki API responses.
type APIError struct {
	StatusCode int
}

func (e *APIError) Error() string {
	return httpclient.StatusError("meraki", e.StatusCode)
}

// Client is a small Meraki Dashboard API HTTP client.
type Client struct {
	apiKey    string
	baseURL   *url.URL
	userAgent string
	client    *http.Client
	retries   int

	sourceLimiter *limiter
	orgLimiters   map[string]*limiter
	orgMu         sync.Mutex

	OnRequest func(RequestStat)
}

// NewClient creates a Meraki API client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.APIKey == "" {
		return nil, errors.New("meraki API key is required")
	}
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid meraki base URL %q", baseURL)
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
		return nil, fmt.Errorf("invalid meraki max retries: %w", err)
	}

	return &Client{
		apiKey:        cfg.APIKey,
		baseURL:       parsed,
		userAgent:     userAgent,
		client:        &http.Client{Timeout: timeout, CheckRedirect: httpclient.SameOriginRedirectPolicy(parsed)},
		retries:       retries,
		sourceLimiter: newLimiter(100),
		orgLimiters:   map[string]*limiter{},
	}, nil
}

// CloseIdleConnections closes idle HTTP connections held by the client.
func (c *Client) CloseIdleConnections() {
	c.client.CloseIdleConnections()
}

// GetJSON fetches a single JSON document.
func GetJSON[T any](ctx context.Context, c *Client, organizationID, operation, path string, query url.Values) (T, error) {
	var out T
	body, _, err := c.do(ctx, organizationID, operation, path, query)
	if err != nil {
		return out, err
	}
	if err := httpclient.DecodeJSON(body, &out); err != nil {
		return out, fmt.Errorf("decode meraki %s response: %w", operation, err)
	}
	return out, nil
}

// GetPaginatedJSON fetches all pages for an array-returning JSON endpoint.
func GetPaginatedJSON[T any](ctx context.Context, c *Client, organizationID, operation, path string, query url.Values) ([]T, error) {
	var results []T
	nextPath := path
	nextQuery := cloneValues(query)
	visited := map[string]struct{}{c.buildURL(nextPath, nextQuery): {}}
	pages := 0
	var byteBudget httpclient.PaginationByteBudget
	for {
		pages++
		body, header, err := c.do(ctx, organizationID, operation, nextPath, nextQuery)
		if err != nil {
			return results, err
		}
		if budgetErr := byteBudget.Charge(operation, len(body), len(results)); budgetErr != nil {
			return results, budgetErr
		}
		var page []T
		if decodeErr := httpclient.DecodeJSON(body, &page); decodeErr != nil {
			return results, fmt.Errorf("decode meraki %s page: %w", operation, decodeErr)
		}
		if len(page) > httpclient.HardMaxPaginationResults-len(results) {
			remaining := httpclient.HardMaxPaginationResults - len(results)
			results = append(results, page[:remaining]...)
			return results, httpclient.NewPaginationLimitError(operation, "result", httpclient.HardMaxPaginationResults, len(results))
		}
		results = append(results, page...)
		nextURL := httpclient.NextLink(header.Get("Link"))
		if nextURL == "" {
			return results, nil
		}
		nextPath, nextQuery, err = c.splitNextURL(nextURL)
		if err != nil {
			return results, fmt.Errorf("invalid meraki %s pagination link: %w", operation, err)
		}
		if pages >= httpclient.HardMaxPaginationPages {
			return results, httpclient.NewPaginationLimitError(operation, "page", httpclient.HardMaxPaginationPages, len(results))
		}
		key := c.buildURL(nextPath, nextQuery)
		if _, exists := visited[key]; exists {
			return results, fmt.Errorf("meraki %s pagination link cycle detected", operation)
		}
		visited[key] = struct{}{}
	}
}

// GetPaginatedItemsJSON fetches all pages for endpoints that return an object
// envelope with an items array.
func GetPaginatedItemsJSON[T any](ctx context.Context, c *Client, organizationID, operation, path string, query url.Values) ([]T, error) {
	var results []T
	nextPath := path
	nextQuery := cloneValues(query)
	visited := map[string]struct{}{c.buildURL(nextPath, nextQuery): {}}
	pages := 0
	var byteBudget httpclient.PaginationByteBudget
	for {
		pages++
		body, header, err := c.do(ctx, organizationID, operation, nextPath, nextQuery)
		if err != nil {
			return results, err
		}
		if budgetErr := byteBudget.Charge(operation, len(body), len(results)); budgetErr != nil {
			return results, budgetErr
		}
		var page struct {
			Items []T `json:"items"`
		}
		if decodeErr := httpclient.DecodeJSON(body, &page); decodeErr != nil {
			return results, fmt.Errorf("decode meraki %s page: %w", operation, decodeErr)
		}
		if len(page.Items) > httpclient.HardMaxPaginationResults-len(results) {
			remaining := httpclient.HardMaxPaginationResults - len(results)
			results = append(results, page.Items[:remaining]...)
			return results, httpclient.NewPaginationLimitError(operation, "result", httpclient.HardMaxPaginationResults, len(results))
		}
		results = append(results, page.Items...)
		nextURL := httpclient.NextLink(header.Get("Link"))
		if nextURL == "" {
			return results, nil
		}
		nextPath, nextQuery, err = c.splitNextURL(nextURL)
		if err != nil {
			return results, fmt.Errorf("invalid meraki %s pagination link: %w", operation, err)
		}
		if pages >= httpclient.HardMaxPaginationPages {
			return results, httpclient.NewPaginationLimitError(operation, "page", httpclient.HardMaxPaginationPages, len(results))
		}
		key := c.buildURL(nextPath, nextQuery)
		if _, exists := visited[key]; exists {
			return results, fmt.Errorf("meraki %s pagination link cycle detected", operation)
		}
		visited[key] = struct{}{}
	}
}

func (c *Client) do(ctx context.Context, organizationID, operation, path string, query url.Values) ([]byte, http.Header, error) {
	if query == nil {
		query = url.Values{}
	}
	var lastErr error
	attempts := c.retries + 1
	for attempt := range attempts {
		if err := c.sourceLimiter.wait(ctx); err != nil {
			return nil, nil, err
		}
		if organizationID != "" {
			if err := c.orgLimiter(organizationID).wait(ctx); err != nil {
				return nil, nil, err
			}
		}

		reqURL := c.buildURL(path, query)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.userAgent)

		start := time.Now()
		resp, err := c.client.Do(req)
		duration := time.Since(start)
		if err != nil {
			lastErr = err
			c.record(RequestStat{
				OrganizationID: organizationID,
				Operation:      operation,
				Method:         http.MethodGet,
				Path:           path,
				Outcome:        "error",
				Duration:       duration,
				Err:            err,
			})
			if attempt == attempts-1 || !sleepBeforeRetry(ctx, attempt, -1) {
				if ctx.Err() != nil {
					return nil, nil, ctx.Err()
				}
				return nil, nil, err
			}
			continue
		}

		body, readErr := httpclient.ReadResponseBody(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil {
			c.record(RequestStat{
				OrganizationID: organizationID,
				Operation:      operation,
				Method:         http.MethodGet,
				Path:           path,
				Outcome:        "error",
				StatusCode:     resp.StatusCode,
				Duration:       duration,
				Err:            readErr,
			})
			return nil, resp.Header, readErr
		}
		if closeErr != nil {
			return nil, resp.Header, closeErr
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			c.record(RequestStat{
				OrganizationID: organizationID,
				Operation:      operation,
				Method:         http.MethodGet,
				Path:           path,
				Outcome:        "success",
				StatusCode:     resp.StatusCode,
				Duration:       duration,
			})
			return body, resp.Header, nil
		}

		apiErr := &APIError{StatusCode: resp.StatusCode}
		lastErr = apiErr
		rateLimited := resp.StatusCode == http.StatusTooManyRequests
		c.record(RequestStat{
			OrganizationID: organizationID,
			Operation:      operation,
			Method:         http.MethodGet,
			Path:           path,
			Outcome:        "error",
			StatusCode:     resp.StatusCode,
			Duration:       duration,
			RateLimited:    rateLimited,
			Err:            apiErr,
		})
		if resp.StatusCode != http.StatusTooManyRequests && (resp.StatusCode < 500 || resp.StatusCode > 599) {
			return nil, resp.Header, apiErr
		}
		if attempt == attempts-1 || !sleepBeforeRetry(ctx, attempt, retryAfter(resp.Header.Get("Retry-After"))) {
			if ctx.Err() != nil {
				return nil, resp.Header, ctx.Err()
			}
			return nil, resp.Header, apiErr
		}
	}
	return nil, nil, lastErr
}

func (c *Client) buildURL(path string, query url.Values) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		u, err := url.Parse(path)
		if err == nil {
			return u.String()
		}
	}
	u := *c.baseURL
	basePath := strings.TrimRight(u.Path, "/")
	requestPath := "/" + strings.TrimLeft(path, "/")
	if basePath != "" && (requestPath == basePath || strings.HasPrefix(requestPath, basePath+"/")) {
		u.Path = requestPath
	} else {
		u.Path = basePath + requestPath
	}
	u.RawQuery = query.Encode()
	return u.String()
}

func (c *Client) orgLimiter(organizationID string) *limiter {
	c.orgMu.Lock()
	defer c.orgMu.Unlock()
	if existing := c.orgLimiters[organizationID]; existing != nil {
		return existing
	}
	created := newLimiter(10)
	c.orgLimiters[organizationID] = created
	return created
}

func (c *Client) record(stat RequestStat) {
	if c.OnRequest != nil {
		c.OnRequest(stat)
	}
}

type limiter struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

func newLimiter(requestsPerSecond int) *limiter {
	if requestsPerSecond <= 0 {
		requestsPerSecond = 1
	}
	return &limiter{interval: time.Second / time.Duration(requestsPerSecond)}
}

func (l *limiter) wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	wait := l.next.Sub(now)
	if wait <= 0 {
		l.next = now.Add(l.interval)
		l.mu.Unlock()
		return nil
	}
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func retryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return -1
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		if delay := time.Until(when); delay > 0 {
			return delay
		}
		return 0
	}
	return -1
}

func sleepBeforeRetry(ctx context.Context, attempt int, serverDelay time.Duration) bool {
	delay := serverDelay
	if delay < 0 {
		delay = time.Duration(1<<attempt) * time.Second
		delay = min(delay, 5*time.Second)
		if delay > 4*time.Nanosecond {
			delay += time.Duration(rand.Int64N(int64(delay / 4)))
		}
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

func (c *Client) splitNextURL(next string) (string, url.Values, error) {
	u, err := url.Parse(next)
	if err != nil {
		return "", nil, err
	}
	resolved := c.baseURL.ResolveReference(u)
	if !httpclient.SameOrigin(c.baseURL, resolved) {
		return "", nil, fmt.Errorf("cross-origin URL %q", next)
	}
	return resolved.Path, resolved.Query(), nil
}

func cloneValues(values url.Values) url.Values {
	if values == nil {
		return nil
	}
	cloned := make(url.Values, len(values))
	for key, vals := range values {
		cloned[key] = append([]string(nil), vals...)
	}
	return cloned
}

// Query builds Meraki query strings using the bracketed array form used in
// Dashboard API examples, such as serials[]=Q234-ABCD-5678.
func Query(values map[string][]string, scalars map[string]string) url.Values {
	query := url.Values{}
	for key, vals := range values {
		for _, val := range vals {
			if strings.TrimSpace(val) != "" {
				query.Add(key+"[]", val)
			}
		}
	}
	for key, val := range scalars {
		if strings.TrimSpace(val) != "" {
			query.Set(key, val)
		}
	}
	return query
}

// OrganizationPath escapes an organization ID into an endpoint path.
func OrganizationPath(organizationID, suffix string) string {
	return "/organizations/" + url.PathEscape(organizationID) + suffix
}
