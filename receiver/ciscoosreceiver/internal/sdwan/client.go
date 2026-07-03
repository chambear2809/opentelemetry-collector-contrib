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
	defaultPageSize       = 500
	defaultRequestSpacing = 10 * time.Millisecond
	defaultMaxPages       = 100
	defaultMaxResults     = 100000
	maxPageSize           = 10000
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
}

func (e *APIError) Error() string {
	return httpclient.StatusError("sdwan", e.StatusCode)
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
	maxPages    int
	maxResults  int

	authMu         sync.Mutex
	authGeneration uint64
	loginInflight  chan struct{}
	lastAuthErr    error
	lastAuthAt     time.Time
	authFailures   int

	limitMu  sync.Mutex
	nextSend time.Time

	OnRequest func(RequestStat)
}

// authBundle is one complete, immutable set of credentials used by a request.
// Dynamic login methods build a bundle locally and publish it under authMu only
// after every step of the authentication flow has succeeded.
type authBundle struct {
	bearerToken string
	jsessionID  string
	xsrfToken   string
	generation  uint64
}

func (a authBundle) complete(mode string) bool {
	switch mode {
	case "bearer", "jwt":
		return a.bearerToken != ""
	case "cookie", "session":
		return a.jsessionID != "" && a.xsrfToken != ""
	case "auto":
		return a.bearerToken != "" || (a.jsessionID != "" && a.xsrfToken != "")
	default:
		return false
	}
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
	retries, err := httpclient.RetryCount(cfg.MaxRetries)
	if err != nil {
		return nil, fmt.Errorf("invalid sdwan max retries: %w", err)
	}
	pageSize := cfg.PageSize
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
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
		client:      &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: httpclient.SameOriginRedirectPolicy(parsed)},
		retries:     retries,
		pageSize:    pageSize,
		spacing:     defaultRequestSpacing,
		maxPages:    defaultMaxPages,
		maxResults:  defaultMaxResults,
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
	return c.collectPages(ctx, http.MethodGet, operation, path, cloneValues(query), nil, maxResults)
}

// PostQuery fetches generic objects with a POST JSON payload.
func (c *Client) PostQuery(ctx context.Context, operation, path string, payload any, maxResults int) ([]Object, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return c.collectPages(ctx, http.MethodPost, operation, path, url.Values{}, bodyBytes, maxResults)
}

func (c *Client) collectPages(ctx context.Context, method, operation, path string, pageQuery url.Values, payload []byte, maxResults int) ([]Object, error) {
	seenRequests := make(map[string]struct{})
	results := make([]Object, 0)
	var byteBudget httpclient.PaginationByteBudget

	for page := 0; ; page++ {
		if page >= c.maxPages {
			return results, fmt.Errorf("paginate sdwan %s response: exceeded %d pages", operation, c.maxPages)
		}
		requestKey := method + " " + path + "?" + pageQuery.Encode()
		if _, seen := seenRequests[requestKey]; seen {
			return results, fmt.Errorf("paginate sdwan %s response: detected continuation cycle", operation)
		}
		seenRequests[requestKey] = struct{}{}

		body, header, err := c.do(ctx, method, operation, path, pageQuery, payload)
		if err != nil {
			return results, err
		}
		if budgetErr := byteBudget.Charge(operation, len(body), len(results)); budgetErr != nil {
			return results, budgetErr
		}
		objects, pageInfo, err := decodeObjectsPage(body, header)
		if err != nil {
			return results, fmt.Errorf("decode sdwan %s response: %w", operation, err)
		}
		results = append(results, objects...)
		if len(results) > c.maxResults {
			return results[:c.maxResults], fmt.Errorf("paginate sdwan %s response: exceeded %d results", operation, c.maxResults)
		}
		if maxResults > 0 && len(results) >= maxResults {
			return results[:maxResults], nil
		}

		continuationPageSize := c.pageSize
		remaining := c.maxResults - len(results)
		if maxResults > 0 && maxResults-len(results) < remaining {
			remaining = maxResults - len(results)
		}
		if remaining > 0 && remaining < continuationPageSize {
			continuationPageSize = remaining
		}
		nextQuery, more, err := pageInfo.nextQuery(pageQuery, continuationPageSize)
		if err != nil {
			return results, fmt.Errorf("paginate sdwan %s response: %w", operation, err)
		}
		if !more {
			return results, nil
		}
		if len(results) >= c.maxResults {
			return results, fmt.Errorf("paginate sdwan %s response: exceeded %d results", operation, c.maxResults)
		}
		pageQuery = nextQuery
	}
}

func (c *Client) do(ctx context.Context, method, operation, path string, query url.Values, payload []byte) ([]byte, http.Header, error) {
	var lastErr error
	attempts := c.retries + 1
	for attempt := range attempts {
		body, header, status, requestAuth, err := c.doOnce(ctx, method, operation, path, query, payload)
		if err == nil {
			c.markAuthSuccess(requestAuth.generation)
			return body, header, nil
		}
		lastErr = err
		if !requestAuth.complete(c.authMode) {
			// ensureAuth owns the configured authentication retry budget. Do not
			// multiply it through the outer data-request retry loop.
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			return nil, nil, err
		}
		if status == http.StatusUnauthorized {
			// Drop only the credential generation used by this request and charge
			// the shared authentication backoff. A successful login does not reset
			// the streak; only a successful authenticated data request proves that
			// the replacement credential is usable.
			c.clearAuth(requestAuth.generation, err)
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			return nil, nil, err
		}
		if status == http.StatusForbidden {
			// A valid session may lack permission for one optional endpoint. Keep
			// it so later endpoint groups can still produce partial results without
			// provoking a login storm.
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
		lastErr = errors.New("sdwan request failed")
	}
	return nil, nil, lastErr
}

func (c *Client) doOnce(ctx context.Context, method, operation, path string, query url.Values, payload []byte) ([]byte, http.Header, int, authBundle, error) {
	requestAuth, err := c.ensureAuth(ctx)
	if err != nil {
		stat := RequestStat{Operation: operation, Method: method, Path: path, Outcome: "auth_error", Err: err}
		c.emit(stat)
		return nil, nil, 0, authBundle{}, err
	}
	if waitErr := c.wait(ctx); waitErr != nil {
		return nil, nil, 0, requestAuth, waitErr
	}

	req, err := c.newRequest(ctx, method, path, query, payload)
	if err != nil {
		return nil, nil, 0, requestAuth, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	applyAuth(req, requestAuth)

	start := time.Now()
	resp, err := c.client.Do(req)
	duration := time.Since(start)
	stat := RequestStat{Operation: operation, Method: method, Path: path, Duration: duration}
	if err != nil {
		stat.Outcome = "error"
		stat.Err = err
		c.emit(stat)
		return nil, nil, 0, requestAuth, err
	}
	defer resp.Body.Close()
	stat.StatusCode = resp.StatusCode
	stat.RateLimited = resp.StatusCode == http.StatusTooManyRequests
	body, readErr := httpclient.ReadResponseBody(resp.Body)
	if readErr != nil {
		stat.Outcome = "error"
		stat.Err = readErr
		c.emit(stat)
		return nil, resp.Header, resp.StatusCode, requestAuth, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode}
		stat.Outcome = "http_error"
		stat.Err = apiErr
		c.emit(stat)
		return nil, resp.Header, resp.StatusCode, requestAuth, apiErr
	}
	stat.Outcome = "success"
	c.emit(stat)
	return body, resp.Header, resp.StatusCode, requestAuth, nil
}

func (c *Client) ensureAuth(ctx context.Context) (authBundle, error) {
	switch c.authMode {
	case "bearer", "cookie":
		c.authMu.Lock()
		bundle := c.authBundleLocked()
		c.authMu.Unlock()
		return bundle, nil
	}
	for {
		c.authMu.Lock()
		if bundle := c.authBundleLocked(); bundle.complete(c.authMode) {
			c.authMu.Unlock()
			return bundle, nil
		}
		if c.authFailures > 0 && time.Since(c.lastAuthAt) < authBackoffFor(c.authFailures) {
			err := c.lastAuthErr
			c.authMu.Unlock()
			if err == nil {
				err = errors.New("sdwan auth in backoff")
			}
			return authBundle{}, err
		}
		if c.loginInflight != nil {
			ch := c.loginInflight
			c.authMu.Unlock()
			select {
			case <-ch:
			case <-ctx.Done():
				return authBundle{}, ctx.Err()
			}
			continue
		}
		ch := make(chan struct{})
		c.loginInflight = ch
		c.authMu.Unlock()

		bundle, err := c.performLoginWithRetry(ctx)
		if err == nil && !bundle.complete(c.authMode) {
			err = errors.New("sdwan login did not return complete authentication state")
		}

		c.authMu.Lock()
		c.loginInflight = nil
		if err != nil {
			if ctx.Err() == nil {
				c.authFailures++
				c.lastAuthErr = err
				c.lastAuthAt = time.Now()
			}
		} else {
			c.authGeneration++
			bundle.generation = c.authGeneration
			c.setAuthBundleLocked(bundle)
		}
		close(ch)
		c.authMu.Unlock()
		if err != nil {
			if ctx.Err() != nil {
				return authBundle{}, ctx.Err()
			}
			return authBundle{}, err
		}
		return bundle, nil
	}
}

func (c *Client) performLoginWithRetry(ctx context.Context) (authBundle, error) {
	var lastErr error
	attempts := c.retries + 1
	for attempt := range attempts {
		bundle, header, status, err := c.performLogin(ctx)
		if err == nil {
			return bundle, nil
		}
		lastErr = err
		retryHeader := ""
		if header != nil {
			retryHeader = header.Get("Retry-After")
		}
		if !retryableStatus(status) || attempt == attempts-1 || !sleepBeforeRetry(ctx, attempt, retryAfter(retryHeader)) {
			if ctx.Err() != nil {
				return authBundle{}, ctx.Err()
			}
			return authBundle{}, err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("sdwan authentication failed")
	}
	return authBundle{}, lastErr
}

func (c *Client) performLogin(ctx context.Context) (authBundle, http.Header, int, error) {
	if c.authMode == "jwt" || c.authMode == "auto" {
		if bundle, header, status, err := c.loginJWT(ctx); err == nil {
			return bundle, header, status, nil
		} else if c.authMode == "jwt" {
			return authBundle{}, header, status, err
		}
	}
	return c.loginSession(ctx)
}

func (c *Client) loginJWT(ctx context.Context) (authBundle, http.Header, int, error) {
	payload, err := json.Marshal(map[string]string{"username": c.username, "password": c.password})
	if err != nil {
		return authBundle{}, nil, 0, err
	}
	req, err := c.newAuthRequest(ctx, http.MethodPost, "/jwt/login", payload)
	if err != nil {
		return authBundle{}, nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return authBundle{}, nil, 0, err
	}
	defer resp.Body.Close()
	body, err := httpclient.ReadResponseBody(resp.Body)
	if err != nil {
		return authBundle{}, resp.Header, resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return authBundle{}, resp.Header, resp.StatusCode, &APIError{StatusCode: resp.StatusCode}
	}
	var decoded map[string]any
	if err := httpclient.DecodeJSON(body, &decoded); err != nil {
		return authBundle{}, resp.Header, resp.StatusCode, err
	}
	token := firstStringValue(decoded, "token", "access_token", "accessToken", "jwt", "id_token")
	csrf := firstStringValue(decoded, "csrf", "xsrf", "xsrfToken", "XSRF-TOKEN")
	if token == "" {
		return authBundle{}, resp.Header, resp.StatusCode, errors.New("sdwan jwt login response did not include token")
	}
	return authBundle{bearerToken: token, xsrfToken: csrf}, resp.Header, resp.StatusCode, nil
}

func (c *Client) loginSession(ctx context.Context) (authBundle, http.Header, int, error) {
	form := url.Values{}
	form.Set("j_username", c.username)
	form.Set("j_password", c.password)
	req, err := c.newAuthRequest(ctx, http.MethodPost, "/j_security_check", []byte(form.Encode()))
	if err != nil {
		return authBundle{}, nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.client.Do(req)
	if err != nil {
		return authBundle{}, nil, 0, err
	}
	defer resp.Body.Close()
	body, err := httpclient.ReadResponseBody(resp.Body)
	if err != nil {
		return authBundle{}, resp.Header, resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || strings.Contains(strings.ToLower(string(body)), "<html") {
		return authBundle{}, resp.Header, resp.StatusCode, &APIError{StatusCode: resp.StatusCode}
	}
	var jsessionID string
	for _, cookie := range resp.Cookies() {
		if strings.EqualFold(cookie.Name, "JSESSIONID") && cookie.Value != "" {
			jsessionID = cookie.Value
			break
		}
	}
	if jsessionID == "" {
		return authBundle{}, resp.Header, resp.StatusCode, errors.New("sdwan session login response did not include JSESSIONID")
	}
	tokenReq, err := c.newAuthRequest(ctx, http.MethodGet, "/dataservice/client/token", nil)
	if err != nil {
		return authBundle{}, nil, 0, err
	}
	tokenReq.Header.Set("Cookie", "JSESSIONID="+jsessionID)
	tokenResp, err := c.client.Do(tokenReq)
	if err != nil {
		return authBundle{}, nil, 0, err
	}
	defer tokenResp.Body.Close()
	tokenBody, err := httpclient.ReadResponseBody(tokenResp.Body)
	if err != nil {
		return authBundle{}, tokenResp.Header, tokenResp.StatusCode, err
	}
	if tokenResp.StatusCode < 200 || tokenResp.StatusCode >= 300 {
		return authBundle{}, tokenResp.Header, tokenResp.StatusCode, &APIError{StatusCode: tokenResp.StatusCode}
	}
	xsrfToken := strings.TrimSpace(string(tokenBody))
	if xsrfToken == "" {
		return authBundle{}, tokenResp.Header, tokenResp.StatusCode, errors.New("sdwan session token response did not include XSRF token")
	}
	return authBundle{jsessionID: jsessionID, xsrfToken: xsrfToken}, tokenResp.Header, tokenResp.StatusCode, nil
}

func (c *Client) authBundleLocked() authBundle {
	return authBundle{
		bearerToken: c.bearerToken,
		jsessionID:  c.jsessionID,
		xsrfToken:   c.xsrfToken,
		generation:  c.authGeneration,
	}
}

func (c *Client) setAuthBundleLocked(bundle authBundle) {
	c.bearerToken = bundle.bearerToken
	c.jsessionID = bundle.jsessionID
	c.xsrfToken = bundle.xsrfToken
}

func (c *Client) clearAuth(generation uint64, authErr error) {
	if c.authMode == "bearer" || c.authMode == "cookie" {
		return
	}
	c.authMu.Lock()
	defer c.authMu.Unlock()
	// A delayed 401 from a request using an old bundle must not erase credentials
	// acquired by a newer login while that request was in flight.
	if c.authGeneration != generation {
		return
	}
	c.authGeneration++
	c.bearerToken = ""
	c.jsessionID = ""
	c.xsrfToken = ""
	c.authFailures++
	if authErr == nil {
		authErr = errors.New("sdwan authentication rejected")
	}
	c.lastAuthErr = authErr
	c.lastAuthAt = time.Now()
}

func (c *Client) markAuthSuccess(generation uint64) {
	if c.authMode == "bearer" || c.authMode == "cookie" {
		return
	}
	c.authMu.Lock()
	defer c.authMu.Unlock()
	// A success from an older in-flight request cannot prove that the current
	// replacement bundle is valid.
	if c.authGeneration != generation {
		return
	}
	c.authFailures = 0
	c.lastAuthErr = nil
	c.lastAuthAt = time.Time{}
}

func applyAuth(req *http.Request, bundle authBundle) {
	if bundle.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bundle.bearerToken)
	}
	if bundle.jsessionID != "" {
		req.Header.Set("Cookie", "JSESSIONID="+bundle.jsessionID)
	}
	if bundle.xsrfToken != "" && req.Method != http.MethodGet {
		req.Header.Set("X-XSRF-TOKEN", bundle.xsrfToken)
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
	if err := httpclient.DecodeJSON(body, &obj); err != nil {
		return nil, err
	}
	return obj, nil
}

type responsePageInfo struct {
	scrollID      string
	startID       string
	endID         string
	hasMoreData   bool
	hasMoreDataOK bool
	moreEntries   bool
	moreEntriesOK bool
	count         int64
}

func decodeObjectsPage(body []byte, _ http.Header) ([]Object, responsePageInfo, error) {
	var decoded any
	if err := httpclient.DecodeJSON(body, &decoded); err != nil {
		return nil, responsePageInfo{}, err
	}
	pageInfo := responsePageInfo{}
	if root, ok := decoded.(map[string]any); ok {
		for _, key := range []string{"pageInfo", "PageInfo"} {
			rawPage, ok := root[key].(map[string]any)
			if !ok {
				continue
			}
			pageInfo.scrollID = strings.TrimSpace(firstStringValue(rawPage, "scrollId", "scrollID"))
			pageInfo.startID = strings.TrimSpace(firstStringValue(rawPage, "startId", "startID"))
			pageInfo.endID = strings.TrimSpace(firstStringValue(rawPage, "endId", "endID"))
			pageInfo.hasMoreData, pageInfo.hasMoreDataOK = booleanValue(rawPage["hasMoreData"])
			pageInfo.moreEntries, pageInfo.moreEntriesOK = booleanValue(rawPage["moreEntries"])
			if count, ok := integerValue(rawPage["count"]); ok && count > 0 {
				pageInfo.count = count
			}
			break
		}
	}
	return objectsFromAny(decoded), pageInfo, nil
}

func (p responsePageInfo) nextQuery(current url.Values, pageSize int) (url.Values, bool, error) {
	if p.hasMoreDataOK {
		if !p.hasMoreData {
			return nil, false, nil
		}
		if p.scrollID == "" {
			return nil, false, errors.New("pageInfo.hasMoreData is true but pageInfo.scrollId is empty")
		}
		next := url.Values{"scrollId": {p.scrollID}}
		if count := continuationCount(current.Get("count"), p.count, pageSize); count > 0 {
			next.Set("count", strconv.FormatInt(count, 10))
		}
		return next, true, nil
	}

	if p.moreEntriesOK {
		if !p.moreEntries {
			return nil, false, nil
		}
		if p.endID == "" {
			return nil, false, fmt.Errorf("pageInfo.moreEntries is true but pageInfo.endId is empty (startId %q)", p.startID)
		}
		next := cloneValues(current)
		next.Del("scrollId")
		next.Set("startId", p.endID)
		if count := continuationCount(current.Get("count"), p.count, pageSize); count > 0 {
			next.Set("count", strconv.FormatInt(count, 10))
		}
		return next, true, nil
	}

	return nil, false, nil
}

func paginationCount(responseCount int64, pageSize int) int64 {
	if responseCount > maxPageSize {
		responseCount = maxPageSize
	}
	if pageSize > 0 && (responseCount <= 0 || responseCount > int64(pageSize)) {
		return int64(pageSize)
	}
	return responseCount
}

func continuationCount(current string, responseCount int64, pageSize int) int64 {
	if parsed, err := strconv.ParseInt(strings.TrimSpace(current), 10, 64); err == nil && parsed > 0 {
		responseCount = parsed
	}
	return paginationCount(responseCount, pageSize)
}

func booleanValue(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		return false, false
	}
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

func cloneValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values))
	for key, current := range values {
		cloned[key] = append([]string(nil), current...)
	}
	return cloned
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
		delay += time.Duration(rand.IntN(100)) * time.Millisecond
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
