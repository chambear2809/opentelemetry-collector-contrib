// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nexusdashboard // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/nexusdashboard"

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	defaultUserAgent             = "opentelemetry-collector-contrib-ciscoosreceiver"
	defaultRequestTimeout        = 30 * time.Second
	defaultPageSize              = 100
	insecureSkipVerifyConfigPath = "nexus_dashboard.insecure_skip_verify"
	modernLoginPath              = "/api/v1/infra/login"
	legacyLoginPath              = "/login"
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

// PaginationStrategy identifies the continuation contract for one Nexus
// Dashboard route. Cisco's APIs mix max/offset endpoints with server-driven
// next-link endpoints and single-response resources, so callers must select a
// strategy from the versioned endpoint catalog instead of inferring one from a
// response body.
type PaginationStrategy string

const (
	// PaginationSingle performs exactly one request. It is reserved for routes
	// whose documented response is a single resource or complete collection.
	PaginationSingle PaginationStrategy = "single"
	// PaginationLink follows only continuation links returned by the server. It
	// never adds max or offset query parameters.
	PaginationLink PaginationStrategy = "link"
	// PaginationUnknown is the conservative contract for compatibility routes
	// that are absent from the versioned Cisco specifications used by the
	// endpoint catalog. It follows an explicit server continuation, never adds
	// pagination parameters, and requires explicit terminal metadata for every
	// nonempty response instead of inferring completeness from its length.
	PaginationUnknown PaginationStrategy = "unknown"
	// PaginationOffset uses Cisco's max/offset query contract. When a server
	// omits optional continuation metadata, a full page advances by its actual
	// result count until a safe termination condition is observed.
	PaginationOffset PaginationStrategy = "offset"
)

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
	// maxPaginationBytes remains fixed at the shared hard ceiling in production.
	// Keeping it on the client makes aggregate-budget behavior deterministic in
	// focused tests without allocating tens of megabytes per test case.
	maxPaginationBytes int

	tokenMu         sync.Mutex
	token           string
	tokenGeneration uint64
	loginInflight   chan struct{}
	lastAuthErr     error
	lastAuthStatus  int
	lastAuthAt      time.Time
	authFailures    int
	loginPath       string

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

// redactedURLRequestError keeps the transport error chain available for
// errors.Is/errors.As without rendering url.Error.URL, which may contain a
// server-provided continuation query.
type redactedURLRequestError struct {
	err error
}

func (*redactedURLRequestError) Error() string {
	return "nexus dashboard HTTP request failed"
}

func (e *redactedURLRequestError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
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
		endpoint:           parsed,
		authMode:           authMode,
		username:           cfg.Username,
		password:           cfg.Password,
		apiKey:             cfg.APIKey,
		domain:             domain,
		userAgent:          userAgent,
		client:             &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: httpclient.SameOriginRedirectPolicy(parsed)},
		retries:            retries,
		pageSize:           pageSize,
		maxPaginationBytes: httpclient.HardMaxPaginationBytes,
		loginPath:          modernLoginPath,
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

// List fetches generic objects from a Nexus Dashboard endpoint using its
// explicit versioned pagination contract. path is an endpoint-relative escaped
// path so selector values escaped as individual URL segments remain segments
// when the request URL is assembled.
func (c *Client) List(
	ctx context.Context,
	operation, path string,
	query url.Values,
	pagination PaginationStrategy,
	maxResults int,
) ([]Object, error) {
	if !validPaginationStrategy(pagination) {
		return nil, fmt.Errorf("unsupported nexus dashboard pagination strategy %q for %s", pagination, operation)
	}
	if query == nil {
		query = url.Values{}
	}
	var results []Object
	resultLimit, hardResultLimit := httpclient.EffectivePaginationResultLimit(maxResults)
	requestPath := path
	requestQuery := cloneValues(query)
	offset := queryInt(requestQuery, "offset", 0)
	serverContinuation := false
	pages := 0
	byteBudget := httpclient.NewPaginationByteBudget(c.maxPaginationBytes)
	seenRequests := make(map[string]struct{})
	completedPageObjects := make(map[[sha256.Size]byte]struct{})
	for {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		if len(results) >= resultLimit {
			if hardResultLimit {
				return results, httpclient.NewPaginationLimitError(operation, "result", resultLimit, len(results))
			}
			return results, nil
		}
		if pages >= httpclient.HardMaxPaginationPages {
			return results, httpclient.NewPaginationLimitError(operation, "page", httpclient.HardMaxPaginationPages, len(results))
		}

		pageQuery := cloneValues(requestQuery)
		requestOffset := offset
		requestedPageSize := 0
		if pagination == PaginationOffset {
			if serverContinuation {
				requestOffset = queryInt(pageQuery, "offset", offset)
				requestedPageSize = queryInt(pageQuery, "max", 0)
			} else {
				requestedPageSize = min(c.pageSize, resultLimit-len(results))
				pageQuery.Set("max", strconv.Itoa(requestedPageSize))
				pageQuery.Set("offset", strconv.Itoa(requestOffset))
			}
		}
		requestKey := requestPath + "?" + pageQuery.Encode()
		if _, seen := seenRequests[requestKey]; seen {
			return results, fmt.Errorf("paginate nexus dashboard %s response: detected continuation cycle after %d partial results", operation, len(results))
		}
		seenRequests[requestKey] = struct{}{}

		body, header, err := c.do(ctx, http.MethodGet, operation, requestPath, pageQuery, nil)
		if err != nil {
			return results, err
		}
		if budgetErr := byteBudget.Charge(operation, len(body), len(results)); budgetErr != nil {
			return results, budgetErr
		}
		pages++
		page, metadata, err := decodeObjects(body, header)
		if err != nil {
			return results, fmt.Errorf("decode nexus dashboard %s response page %d from %s: %w", operation, pages, requestPath, err)
		}
		rawPageLength := len(page)
		page, madeProgress, err := filterObjectProgress(page, completedPageObjects)
		if err != nil {
			return results, fmt.Errorf("track nexus dashboard %s pagination progress: %w", operation, err)
		}
		if rawPageLength > 0 && !madeProgress {
			return results, fmt.Errorf("paginate nexus dashboard %s response: endpoint made no progress after %d partial results", operation, len(results))
		}
		results = append(results, page...)
		processedOffset := requestOffset + rawPageLength
		if pagination == PaginationSingle && metadata.claimsMore(processedOffset) {
			if len(results) > resultLimit {
				results = results[:resultLimit]
			}
			return results, fmt.Errorf("paginate nexus dashboard %s response: single-response contract claimed continuation after %d partial results", operation, len(results))
		}
		if pagination == PaginationUnknown && rawPageLength > 0 && metadata.next == "" && !metadata.terminal(processedOffset) {
			if len(results) > resultLimit {
				results = results[:resultLimit]
			}
			if metadata.claimsMore(processedOffset) {
				return results, fmt.Errorf("paginate nexus dashboard %s response: unverified pagination contract reported continuation without a next link after %d partial results", operation, len(results))
			}
			return results, fmt.Errorf("paginate nexus dashboard %s response: unverified pagination contract returned %d results without continuation or terminal metadata", operation, rawPageLength)
		}
		complete := paginationPageComplete(pagination, rawPageLength, requestedPageSize, processedOffset, metadata)
		truncated := len(results) > resultLimit
		if len(results) >= resultLimit {
			results = results[:resultLimit]
			if hardResultLimit && (truncated || !complete) {
				return results, httpclient.NewPaginationLimitError(operation, "result", resultLimit, len(results))
			}
			return results, nil
		}
		if rawPageLength == 0 && metadata.claimsMore(processedOffset) {
			return results, fmt.Errorf("paginate nexus dashboard %s response: endpoint made no progress with continuation metadata after %d partial results", operation, len(results))
		}
		if metadata.next != "" {
			nextPath, nextQuery, err := c.resolveNextURL(requestPath, pageQuery, metadata.next)
			if err != nil {
				return results, fmt.Errorf("paginate nexus dashboard %s response: resolve continuation after %d partial results: %w", operation, len(results), err)
			}
			requestPath, requestQuery = nextPath, nextQuery
			offset = queryInt(requestQuery, "offset", processedOffset)
			serverContinuation = true
			continue
		}
		if complete {
			return results, nil
		}
		switch pagination {
		case PaginationSingle:
			return results, fmt.Errorf("paginate nexus dashboard %s response: single-response contract reported more than %d partial results", operation, len(results))
		case PaginationLink:
			return results, fmt.Errorf("paginate nexus dashboard %s response: continuation metadata omitted a next link after %d partial results", operation, len(results))
		case PaginationUnknown:
			if metadata.claimsMore(processedOffset) {
				return results, fmt.Errorf("paginate nexus dashboard %s response: unverified pagination contract reported continuation without a next link after %d partial results", operation, len(results))
			}
			return results, fmt.Errorf("paginate nexus dashboard %s response: unverified pagination contract returned %d results without continuation or terminal metadata", operation, rawPageLength)
		case PaginationOffset:
			offset = processedOffset
			requestQuery = pageQuery
			serverContinuation = false
		}
	}
}

type paginationMetadata struct {
	next           string
	remaining      int
	remainingKnown bool
	total          int
	totalKnown     bool
}

func (m paginationMetadata) claimsMore(processedOffset int) bool {
	return m.next != "" ||
		m.remainingKnown && m.remaining > 0 ||
		m.totalKnown && processedOffset < m.total
}

func (m paginationMetadata) terminal(processedOffset int) bool {
	if m.claimsMore(processedOffset) {
		return false
	}
	return m.remainingKnown && m.remaining <= 0 ||
		m.totalKnown && processedOffset >= m.total
}

func validPaginationStrategy(strategy PaginationStrategy) bool {
	switch strategy {
	case PaginationSingle, PaginationLink, PaginationUnknown, PaginationOffset:
		return true
	default:
		return false
	}
}

func paginationPageComplete(
	strategy PaginationStrategy,
	pageLength, requestedPageSize, processedOffset int,
	metadata paginationMetadata,
) bool {
	if metadata.next != "" {
		return false
	}
	if pageLength == 0 {
		return !metadata.claimsMore(processedOffset)
	}
	if metadata.claimsMore(processedOffset) {
		// An offset endpoint can return fewer objects than requested while
		// authoritative metadata still identifies later objects. Continuation
		// metadata takes precedence over the short-page fallback.
		return false
	}
	if metadata.terminal(processedOffset) {
		return true
	}
	if strategy == PaginationOffset && requestedPageSize > 0 && pageLength < requestedPageSize {
		return true
	}
	switch strategy {
	case PaginationSingle, PaginationLink:
		return !metadata.claimsMore(processedOffset)
	case PaginationUnknown:
		return false
	default:
		return false
	}
}

func filterObjectProgress(page []Object, completedPages map[[sha256.Size]byte]struct{}) ([]Object, bool, error) {
	filtered := make([]Object, 0, len(page))
	pageFingerprints := make(map[[sha256.Size]byte]struct{}, len(page))
	progress := false
	for _, object := range page {
		encoded, err := json.Marshal(object)
		if err != nil {
			return nil, false, err
		}
		fingerprint := sha256.Sum256(encoded)
		pageFingerprints[fingerprint] = struct{}{}
		if _, ok := completedPages[fingerprint]; ok {
			continue
		}
		filtered = append(filtered, object)
		progress = true
	}
	// Merge only after filtering so byte-identical rows first observed together
	// remain distinct while later pages can still discard exact overlaps.
	for fingerprint := range pageFingerprints {
		completedPages[fingerprint] = struct{}{}
	}
	return filtered, progress, nil
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
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		if httpclient.IsCertificateVerificationError(err) {
			return nil, nil, err
		}
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
		retryable := retryableStatus(status) ||
			httpclient.IsResponseBodyReadError(err) && status >= 200 && status < 300
		if !retryable || attempt == attempts-1 || !sleepBeforeRetry(ctx, attempt, retryAfter(retryHeader)) {
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
		err = redactURLRequestError(err)
		err = httpclient.DecorateCertificateVerificationError(err, "", insecureSkipVerifyConfigPath)
		c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "error", Duration: duration, Err: err})
		return nil, nil, 0, requestAuth, err
	}
	bodyBytes, readErr := httpclient.ReadResponseBody(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, RateLimited: resp.StatusCode == http.StatusTooManyRequests, Err: readErr})
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

func redactURLRequestError(err error) error {
	if err == nil {
		return nil
	}
	var requestErr *url.Error
	if !errors.As(err, &requestErr) {
		return err
	}
	return &redactedURLRequestError{err: err}
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

	path := c.loginPath
	token, status, body, stat, err := c.loginAtPath(ctx, path, payload)
	if !loginEndpointUnsupported(status, body, err) {
		c.record(stat)
		return token, status, err
	}
	stat.Outcome = "fallback"
	stat.Err = nil
	c.record(stat)

	path = alternateLoginPath(path)
	c.loginPath = path
	token, status, _, stat, err = c.loginAtPath(ctx, path, payload)
	c.record(stat)
	return token, status, err
}

func (c *Client) loginAtPath(ctx context.Context, path string, payload []byte) (string, int, []byte, RequestStat, error) {
	stat := RequestStat{Operation: "infra.login", Method: http.MethodPost, Path: path}
	reqURL := c.buildURL(path, nil)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(payload))
	if err != nil {
		stat.Outcome = "error"
		stat.Err = err
		return "", 0, nil, stat, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	start := time.Now()
	resp, err := c.client.Do(req)
	duration := time.Since(start)
	stat.Duration = duration
	if err != nil {
		err = httpclient.DecorateCertificateVerificationError(err, "", insecureSkipVerifyConfigPath)
		stat.Outcome = "error"
		stat.Err = err
		return "", 0, nil, stat, err
	}
	stat.StatusCode = resp.StatusCode
	stat.RateLimited = resp.StatusCode == http.StatusTooManyRequests
	bodyBytes, readErr := httpclient.ReadResponseBody(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		stat.Outcome = "error"
		stat.Err = readErr
		return "", resp.StatusCode, bodyBytes, stat, readErr
	}
	if closeErr != nil {
		stat.Outcome = "error"
		stat.Err = closeErr
		return "", resp.StatusCode, bodyBytes, stat, closeErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode}
		stat.Outcome = "error"
		stat.Err = apiErr
		return "", resp.StatusCode, bodyBytes, stat, apiErr
	}
	var login struct {
		Token    string `json:"token"`
		JWTToken string `json:"jwttoken"`
	}
	if err := json.Unmarshal(bodyBytes, &login); err != nil {
		stat.Outcome = "error"
		stat.Err = err
		return "", resp.StatusCode, bodyBytes, stat, err
	}
	token := login.Token
	if token == "" {
		token = login.JWTToken
	}
	if token == "" {
		err := errors.New("nexus dashboard login response did not include a token")
		stat.Outcome = "error"
		stat.Err = err
		return "", resp.StatusCode, bodyBytes, stat, err
	}
	stat.Outcome = "success"
	return token, resp.StatusCode, bodyBytes, stat, nil
}

func alternateLoginPath(path string) string {
	if path == legacyLoginPath {
		return modernLoginPath
	}
	return legacyLoginPath
}

func loginEndpointUnsupported(status int, body []byte, err error) bool {
	switch status {
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		// These statuses identify an unsupported login route independently of
		// the response body. Preserve endpoint fallback even if that error body
		// is truncated before it can be read completely.
		return true
	case http.StatusUnauthorized:
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != status {
			return false
		}
		return bytes.Contains(bytes.ToLower(body), []byte("authorization field missing"))
	default:
		return false
	}
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
	u := c.endpointRequestURL(path)
	if query != nil {
		u.RawQuery = query.Encode()
	}
	return u.String()
}

func (c *Client) endpointRequestURL(path string) url.URL {
	u := *c.endpoint
	escapedPath := endpointRequestPath(u.EscapedPath(), path)
	decodedPath, err := url.PathUnescape(escapedPath)
	if err != nil {
		// Preserve the previous behavior for a malformed server-provided path:
		// URL.String will safely escape it before the request is sent.
		u.Path = endpointRequestPath(u.Path, path)
		u.RawPath = ""
		return u
	}
	u.Path = decodedPath
	u.RawPath = escapedPath
	return u
}

func endpointRequestPath(endpointPath, requestPath string) string {
	basePath := strings.TrimRight(endpointPath, "/")
	cleanPath := "/" + strings.TrimLeft(requestPath, "/")
	return basePath + cleanPath
}

func (c *Client) record(stat RequestStat) {
	if c.OnRequest != nil {
		c.OnRequest(stat)
	}
}

func decodeObjects(body []byte, header http.Header) ([]Object, paginationMetadata, error) {
	var value any
	if err := httpclient.DecodeJSON(body, &value); err != nil {
		return nil, paginationMetadata{}, err
	}
	objects, err := objectsFromValue(value)
	if err != nil {
		return nil, paginationMetadata{}, err
	}
	metadata := paginationMetadata{next: httpclient.NextLink(header.Get("Link"))}
	if root, ok := value.(map[string]any); ok {
		metadata.next = firstNonEmpty(
			metadata.next,
			stringFromPath(root, "meta", "links", "next"),
			stringFromPath(root, "links", "next"),
			stringFromPath(root, "pagination", "next"),
		)
		metadata.remaining, metadata.remainingKnown = firstNonNegativeIntFromPaths(root,
			[]string{"meta", "counts", "remaining"},
			[]string{"meta", "remaining"},
			[]string{"pagination", "remaining"},
		)
		metadata.total, metadata.totalKnown = firstNonNegativeIntFromPaths(root,
			[]string{"meta", "counts", "total"},
			[]string{"meta", "total"},
			[]string{"pagination", "total"},
		)
	}
	return objects, metadata, nil
}

func objectsFromValue(value any) ([]Object, error) {
	switch typed := value.(type) {
	case []any:
		return objectsFromRows(typed, "top-level response", "")
	case map[string]any:
		var collectionKey string
		var collectionRows []any
		// A recognized collection key is an explicit envelope-shape contract.
		// Validate every present key before singleton handling so a malformed
		// collection can never turn envelope metadata into a fabricated row.
		for _, key := range []string{"items", "data", "results", "fabrics", "switches", "interfaces", "anomalies", "advisories", "nodes", "services", "sites", "schemas", "rules", "sessions", "flows", "events", "faults", "auditLog", "logs", "records"} {
			collectionValue, present := typed[key]
			if !present {
				continue
			}
			items, ok := collectionValue.([]any)
			if !ok {
				return nil, fmt.Errorf("response field %q is %s, expected an array", key, jsonValueType(collectionValue))
			}
			if collectionKey == "" {
				collectionKey = key
				collectionRows = items
			}
		}
		// Cluster health is a true singleton envelope whose recognized nested
		// fields (such as nodes) are arrays; retain the envelope after validation.
		if _, ok := typed["isHealthy"]; ok {
			return []Object{Object(typed)}, nil
		}
		if collectionKey != "" {
			return objectsFromRows(collectionRows, fmt.Sprintf("response field %q", collectionKey), String(Object(typed), "fabricName", "siteName"))
		}
		return []Object{Object(typed)}, nil
	default:
		return nil, fmt.Errorf("top-level response is %s, expected object or array", jsonValueType(value))
	}
}

func objectsFromRows(rows []any, location, parent string) ([]Object, error) {
	out := make([]Object, 0, len(rows))
	for index, row := range rows {
		obj, ok := objectFromValue(row)
		if !ok {
			return nil, fmt.Errorf("%s row %d is %s, expected object", location, index, jsonValueType(row))
		}
		if parent != "" {
			obj["_parent"] = parent
		}
		out = append(out, obj)
	}
	return out, nil
}

func jsonValueType(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case []any:
		return "an array"
	case string:
		return "a string"
	case json.Number, float64:
		return "a number"
	case bool:
		return "a boolean"
	case map[string]any:
		return "an object"
	default:
		return fmt.Sprintf("a %T value", value)
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

func (c *Client) resolveNextURL(currentPath string, currentQuery url.Values, nextURL string) (string, url.Values, error) {
	parsed, err := url.Parse(nextURL)
	if err != nil {
		return "", nil, errors.New("parse continuation metadata: invalid URL")
	}
	if err = validateContinuationEscapedPath(parsed.EscapedPath()); err != nil {
		return "", nil, fmt.Errorf("reject continuation metadata: %w", err)
	}
	base := c.endpointRequestURL(currentPath)
	base.RawQuery = currentQuery.Encode()
	resolved := base.ResolveReference(parsed)
	// Continuation metadata controls only the path and query. Discard its
	// origin so authentication can never escape the configured controller, and
	// normalize the path back to endpoint-relative form so buildURL applies a
	// configured reverse-proxy prefix exactly once.
	relativePath, err := endpointRelativeEscapedPath(c.endpoint, resolved)
	if err != nil {
		return "", nil, fmt.Errorf("rebase continuation metadata: %w", err)
	}
	return relativePath, resolved.Query(), nil
}

func validateContinuationEscapedPath(escapedPath string) error {
	// A reverse proxy and its backend can each decode or normalize a path.
	// Validate both stages so double-encoded separators and dot bytes cannot
	// become a traversal segment after the continuation has been rebased.
	decodedPath, ok := decodeEscapedPath(escapedPath, true)
	if !ok {
		return errors.New("path contains an invalid escape")
	}
	if containsPathTraversalSegment(decodedPath) {
		return errors.New("path contains a traversal segment that decodes to \"..\"")
	}
	// The wire-level path must be valid, but the result of its first decode may
	// legitimately contain a literal percent (for example an escaped selector
	// value ending in %25). A second normalizer would decode only valid %HH
	// triplets, so preserve other percent bytes during this defensive pass.
	decodedPath, _ = decodeEscapedPath(decodedPath, false)
	if containsPathTraversalSegment(decodedPath) {
		return errors.New("path contains a traversal segment that decodes to \"..\"")
	}
	return nil
}

func decodeEscapedPath(escapedPath string, rejectInvalidEscapes bool) (string, bool) {
	if !strings.Contains(escapedPath, "%") {
		return escapedPath, true
	}
	var decoded strings.Builder
	decoded.Grow(len(escapedPath))
	for encodedIndex := 0; encodedIndex < len(escapedPath); {
		value, nextIndex, ok := decodeEscapedPathByte(escapedPath, encodedIndex)
		if !ok {
			if rejectInvalidEscapes {
				return "", false
			}
			decoded.WriteByte(escapedPath[encodedIndex])
			encodedIndex++
			continue
		}
		decoded.WriteByte(value)
		encodedIndex = nextIndex
	}
	return decoded.String(), true
}

func containsPathTraversalSegment(path string) bool {
	segmentStart := 0
	for index := 0; index < len(path); index++ {
		if path[index] != '/' && path[index] != '\\' {
			continue
		}
		if path[segmentStart:index] == ".." {
			return true
		}
		segmentStart = index + 1
	}
	return path[segmentStart:] == ".."
}

func endpointRelativeEscapedPath(endpoint, resolved *url.URL) (string, error) {
	basePath := strings.TrimRight(endpoint.Path, "/")
	cleanPath := "/" + strings.TrimLeft(resolved.Path, "/")
	cleanEscapedPath := "/" + strings.TrimLeft(resolved.EscapedPath(), "/")
	if basePath == "" || (cleanPath != basePath && !strings.HasPrefix(cleanPath, basePath+"/")) {
		return cleanEscapedPath, nil
	}

	prefixEnd, ok := escapedDecodedPrefixLength(cleanEscapedPath, basePath)
	if !ok {
		return "", errors.New("resolved path does not preserve the configured endpoint prefix")
	}
	if cleanPath == basePath {
		return "/", nil
	}
	separatorEnd, ok := escapedDecodedPrefixLength(cleanEscapedPath[prefixEnd:], "/")
	if !ok {
		return "", errors.New("resolved path does not contain a separator after the configured endpoint prefix")
	}
	return "/" + cleanEscapedPath[prefixEnd+separatorEnd:], nil
}

// escapedDecodedPrefixLength returns the encoded byte length corresponding to
// decodedPrefix. It permits equivalent URL spellings (including hex-case and
// escaped-unreserved differences) without re-encoding the remaining path.
func escapedDecodedPrefixLength(escapedPath, decodedPrefix string) (int, bool) {
	return escapedDecodedPrefixLengthWithOperations(escapedPath, decodedPrefix, nil)
}

// escapedDecodedPrefixLengthWithOperations exposes the number of decoded-byte
// comparisons for a deterministic complexity regression. Each iteration
// consumes either one literal byte or one complete percent escape.
func escapedDecodedPrefixLengthWithOperations(escapedPath, decodedPrefix string, operations *int) (int, bool) {
	encodedIndex := 0
	for decodedIndex := 0; decodedIndex < len(decodedPrefix); decodedIndex++ {
		if operations != nil {
			*operations++
		}
		decoded, nextIndex, ok := decodeEscapedPathByte(escapedPath, encodedIndex)
		if !ok || decoded != decodedPrefix[decodedIndex] {
			return 0, false
		}
		encodedIndex = nextIndex
	}
	return encodedIndex, true
}

func decodeEscapedPathByte(escapedPath string, encodedIndex int) (byte, int, bool) {
	if encodedIndex >= len(escapedPath) {
		return 0, encodedIndex, false
	}
	if escapedPath[encodedIndex] != '%' {
		return escapedPath[encodedIndex], encodedIndex + 1, true
	}
	if encodedIndex+2 >= len(escapedPath) {
		return 0, encodedIndex, false
	}
	high, highOK := hexValue(escapedPath[encodedIndex+1])
	low, lowOK := hexValue(escapedPath[encodedIndex+2])
	if !highOK || !lowOK {
		return 0, encodedIndex, false
	}
	return high<<4 | low, encodedIndex + 3, true
}

func hexValue(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func queryInt(query url.Values, key string, fallback int) int {
	value := query.Get(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return fallback
	}
	return parsed
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

func firstNonNegativeIntFromPaths(obj map[string]any, paths ...[]string) (int, bool) {
	for _, path := range paths {
		value := intFromPath(obj, path...)
		if value >= 0 {
			return value, true
		}
	}
	return 0, false
}
