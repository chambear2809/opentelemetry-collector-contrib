// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package aci // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/aci"

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
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
	defaultUserAgent             = "opentelemetry-collector-contrib-ciscoosreceiver"
	defaultRequestTimeout        = 30 * time.Second
	defaultPageSize              = 100
	refreshDeadlineDivisor       = 2
	caFileConfigPath             = "aci.ca_file"
	serverNameConfigPath         = "aci.server_name"
	insecureSkipVerifyConfigPath = "aci.insecure_skip_verify"
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
	CAFile             string
	ServerName         string
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
	body       []byte
}

func (e *APIError) Error() string {
	return httpclient.StatusError("apic", e.StatusCode)
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

	tokenMu                  sync.Mutex
	token                    string
	refreshTimeout           time.Duration
	refreshDeadline          time.Time
	sessionExpiry            time.Time
	tokenAccepted            bool
	tokenGeneration          uint64
	generationRejected       bool
	rejectedGeneration       uint64
	generationRejectedSignal chan struct{}
	loginInflight            chan struct{}
	lastAuthErr              error
	lastAuthAt               time.Time
	authFailures             int
	lastRefreshErr           error
	refreshRetryAt           time.Time
	refreshFailures          int

	OnRequest func(RequestStat)
}

type tokenSnapshot struct {
	value          string
	generation     uint64
	refreshTimeout time.Duration
	sessionExpiry  time.Time
}

type tokenRecovery struct {
	done       chan struct{}
	generation uint64
}

type tokenRejection struct {
	retry    bool
	joined   bool
	recovery *tokenRecovery
}

type authSession struct {
	token           string
	refreshTimeout  time.Duration
	refreshDeadline time.Time
	sessionExpiry   time.Time
}

// authBackoffSchedule defines the wait that ensureToken honors after a failed
// login or a token rejected by a data request. It avoids hammering the APIC and
// locking out the user account when credentials are wrong.
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
	retries, err := httpclient.RetryCount(cfg.MaxRetries)
	if err != nil {
		return nil, fmt.Errorf("invalid apic max retries: %w", err)
	}
	pageSize := cfg.PageSize
	if pageSize <= 0 {
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
		client:     &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: httpclient.SameOriginRedirectPolicy(parsed)},
		retries:    retries,
		pageSize:   pageSize,
		controller: parsed.Host,
	}, nil
}

func clientTLSConfig(cfg Config) (*tls.Config, error) {
	if cfg.CAFile == "" && cfg.ServerName == "" && !cfg.InsecureSkipVerify {
		return nil, nil
	}
	tlsConfig := &tls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
	if cfg.CAFile == "" {
		return tlsConfig, nil
	}

	caBytes, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read APIC CA file %q: %w", cfg.CAFile, err)
	}
	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if !rootCAs.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("%s %q did not contain PEM certificates", caFileConfigPath, cfg.CAFile)
	}
	tlsConfig.RootCAs = rootCAs
	return tlsConfig, nil
}

func decorateCertificateVerificationError(err error) error {
	decorated := httpclient.DecorateCertificateVerificationError(err, caFileConfigPath, insecureSkipVerifyConfigPath)
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return fmt.Errorf("configure %s with a DNS name or IP address present in the APIC certificate SAN: %w", serverNameConfigPath, decorated)
	}
	return decorated
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
	return c.ListClassFiltered(ctx, operation, className, query, maxResults, nil)
}

// ListClassFiltered fetches APIC class query pages until maxResults objects
// accepted by include have been collected. The predicate is applied before the
// result limit so selective filters do not silently discard matches that occur
// after the first maxResults raw objects.
func (c *Client) ListClassFiltered(ctx context.Context, operation, className string, query url.Values, maxResults int, include func(Object) bool) ([]Object, error) {
	path := "/api/class/" + strings.TrimSuffix(strings.TrimPrefix(className, "/"), ".json") + ".json"
	return c.list(ctx, operation, path, query, maxResults, include)
}

// List fetches all pages for an APIC endpoint.
func (c *Client) List(ctx context.Context, operation, path string, query url.Values, maxResults int) ([]Object, error) {
	return c.list(ctx, operation, path, query, maxResults, nil)
}

func (c *Client) list(ctx context.Context, operation, path string, query url.Values, maxResults int, include func(Object) bool) ([]Object, error) {
	if query == nil {
		query = url.Values{}
	}
	var results []Object
	rawResults := 0
	resultLimit, hardResultLimit := httpclient.EffectivePaginationResultLimit(maxResults)
	page := 0
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
		if remaining := resultLimit - len(results); include == nil && remaining < pageSize {
			pageSize = remaining
		}
		if _, ok := pageQuery["page-size"]; !ok {
			pageQuery.Set("page-size", strconv.Itoa(pageSize))
		}
		if _, ok := pageQuery["page"]; !ok {
			pageQuery.Set("page", strconv.Itoa(page))
		}
		requestKey := path + "?" + pageQuery.Encode()
		if _, seen := seenRequests[requestKey]; seen {
			return results, fmt.Errorf("paginate apic %s response: detected continuation cycle after %d partial results", operation, len(results))
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
		pageObjects, total, err := decodeObjects(body)
		if err != nil {
			return results, fmt.Errorf("decode apic %s response: %w", operation, err)
		}
		rawResults += len(pageObjects)
		if include == nil {
			results = append(results, pageObjects...)
		} else {
			for _, object := range pageObjects {
				if include(object) {
					results = append(results, object)
				}
			}
		}
		next := httpclient.NextLink(header.Get("Link"))
		complete := len(pageObjects) == 0
		if !complete {
			switch {
			case next != "":
				// An explicit continuation link is authoritative even when the
				// controller returned fewer objects than requested.
				complete = false
			case total >= 0:
				complete = rawResults >= total
			default:
				complete = len(pageObjects) < pageSize
			}
		}
		truncated := len(results) > resultLimit
		if len(results) >= resultLimit {
			results = results[:resultLimit]
			if truncated || !complete {
				if hardResultLimit {
					return results, httpclient.NewPaginationLimitError(operation, "result", resultLimit, len(results))
				}
				return results, httpclient.NewConfiguredPaginationLimitError(operation, "result", resultLimit, len(results))
			}
			return results, nil
		}
		if complete {
			return results, nil
		}
		page++
	}
}

func (c *Client) do(ctx context.Context, method, operation, path string, query url.Values, payload []byte) ([]byte, http.Header, error) {
	retryAttempt := 0
	authRecoveryUsed := false
	joinedRecovery := false
	var joinedGeneration uint64
	for {
		body, header, status, requestToken, err := c.doOnce(ctx, method, operation, path, query, payload)
		if joinedRecovery && requestToken.value != "" {
			// Joining an inflight refresh spends this request's bounded recovery
			// only if that operation actually produced a replacement generation.
			if requestToken.generation != joinedGeneration {
				authRecoveryUsed = true
			}
			joinedRecovery = false
		}
		if err == nil {
			c.markTokenSuccess(requestToken)
			return body, header, nil
		}
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		if httpclient.IsCertificateVerificationError(err) {
			return nil, nil, err
		}
		if requestToken.value == "" {
			// login owns the configured authentication retry budget. A failed
			// login must not be multiplied by the outer data-request retry loop;
			// this is especially important for rejected credentials.
			return nil, nil, err
		}
		if authorizationDenied(err) {
			// APIC can return either 401 or 403 for RBAC and security-domain
			// denials. A structured authorization error proves this generation
			// authenticated, but must not retire it or poison authentication backoff.
			c.markTokenSuccess(requestToken)
			return nil, nil, err
		}
		if status == http.StatusForbidden && !authenticationRejected(err) {
			// Only an APIC error that specifically identifies an invalid session
			// turns a 403 into an authentication failure.
			return nil, nil, err
		}
		if authenticationRejected(err) {
			// Only a token generation already accepted by a data request can be
			// treated as expired and recovered inline. A freshly issued token that
			// APIC rejects still enters the shared authentication backoff.
			rejection := c.rejectToken(requestToken, err, !authRecoveryUsed)
			if !rejection.retry {
				return nil, nil, err
			}
			if rejection.joined {
				joinedRecovery = true
				joinedGeneration = requestToken.generation
			} else {
				authRecoveryUsed = true
			}
			if rejection.recovery != nil {
				if recoveryErr := c.recoverToken(ctx, *rejection.recovery); recoveryErr != nil {
					return nil, nil, recoveryErr
				}
			}
			continue
		}
		retryHeader := ""
		if header != nil {
			retryHeader = header.Get("Retry-After")
		}
		retryable := retryableStatus(status) ||
			httpclient.IsResponseBodyReadError(err) && status >= 200 && status < 300
		if !retryable || retryAttempt == c.retries || !sleepBeforeRetry(ctx, retryAttempt, retryAfter(retryHeader)) {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			return nil, nil, err
		}
		retryAttempt++
	}
}

func (c *Client) doOnce(ctx context.Context, method, operation, path string, query url.Values, payload []byte) ([]byte, http.Header, int, tokenSnapshot, error) {
	reqURL := c.buildURL(path, query)
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, nil, 0, tokenSnapshot{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	token, err := c.ensureToken(ctx)
	if err != nil {
		return nil, nil, 0, tokenSnapshot{}, err
	}
	req.AddCookie(&http.Cookie{Name: "APIC-cookie", Value: token.value})

	start := time.Now()
	resp, err := c.client.Do(req)
	duration := time.Since(start)
	if err != nil {
		err = decorateCertificateVerificationError(err)
		c.record(RequestStat{Controller: c.name, Operation: operation, Method: method, Path: path, Outcome: "error", Duration: duration, Err: err})
		return nil, nil, 0, token, err
	}
	bodyBytes, readErr := httpclient.ReadResponseBody(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		c.record(RequestStat{Controller: c.name, Operation: operation, Method: method, Path: path, Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, RateLimited: resp.StatusCode == http.StatusTooManyRequests, Err: readErr})
		return nil, resp.Header, resp.StatusCode, token, readErr
	}
	if closeErr != nil {
		return nil, resp.Header, resp.StatusCode, token, closeErr
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.record(RequestStat{Controller: c.name, Operation: operation, Method: method, Path: path, Outcome: "success", StatusCode: resp.StatusCode, Duration: duration})
		return bodyBytes, resp.Header, resp.StatusCode, token, nil
	}
	apiErr := &APIError{StatusCode: resp.StatusCode, body: bodyBytes}
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
	return nil, resp.Header, resp.StatusCode, token, apiErr
}

func (c *Client) ensureToken(ctx context.Context) (tokenSnapshot, error) {
	for {
		c.tokenMu.Lock()
		now := time.Now()
		tokenUsable := c.token != "" && (c.sessionExpiry.IsZero() || now.Before(c.sessionExpiry))
		if tokenUsable && (now.Before(c.refreshDeadline) || now.Before(c.refreshRetryAt)) {
			tok := c.tokenSnapshotLocked()
			c.tokenMu.Unlock()
			return tok, nil
		}
		// Concurrent callers wait on the same login or refresh. Waiting does not
		// bypass backoff if that shared authentication attempt fails.
		if c.loginInflight != nil {
			ch := c.loginInflight
			c.tokenMu.Unlock()
			select {
			case <-ch:
			case <-ctx.Done():
				return tokenSnapshot{}, ctx.Err()
			}
			continue
		}
		if c.token != "" && now.Before(c.refreshRetryAt) {
			err := c.lastRefreshErr
			c.tokenMu.Unlock()
			if err == nil {
				err = errors.New("apic session refresh in backoff")
			}
			return tokenSnapshot{}, err
		}
		// If a backoff window is active after a recent failed authentication,
		// return the cached error without hitting the wire. Expired-session
		// recovery claims ownership before entering this path.
		if c.authFailures > 0 && time.Since(c.lastAuthAt) < authBackoffFor(c.authFailures) {
			err := c.lastAuthErr
			c.tokenMu.Unlock()
			if err == nil {
				err = errors.New("apic auth in backoff")
			}
			return tokenSnapshot{}, err
		}
		ch := make(chan struct{})
		c.loginInflight = ch
		refreshToken := c.tokenSnapshotLocked()
		refreshing := refreshToken.value != ""
		refreshAccepted := c.tokenAccepted
		c.tokenMu.Unlock()

		var session authSession
		var err error
		refreshRejected := false
		refreshGenerationRejected := false
		replacementLogin := false
		tokenLockHeld := false
		if refreshing {
			session, err = c.refresh(ctx, refreshToken)
			refreshRejected = err != nil && refreshAccepted && authenticationRejected(err)
			refreshExpired := !refreshToken.sessionExpiry.IsZero() && !time.Now().Before(refreshToken.sessionExpiry)
			if err != nil && refreshAccepted && !refreshRejected && !refreshExpired {
				// Keep the rejection check and completion of a failed proactive
				// refresh atomic. A data request that rejects this generation either
				// joins this owner before it completes, or claims recovery itself
				// after loginInflight is cleared; it must never resend the rejected
				// generation under refresh backoff.
				c.tokenMu.Lock()
				tokenLockHeld = true
				refreshGenerationRejected = c.generationRejectedLocked(refreshToken.generation)
			}
			replacementLogin = err != nil && refreshAccepted && ctx.Err() == nil &&
				(refreshRejected || refreshExpired || refreshGenerationRejected)
			if replacementLogin {
				// An established session can expire before refresh reaches APIC or
				// be rejected by a data request while proactive refresh is in flight.
				// Recover with one full login while retaining ownership of the
				// inflight operation.
				if tokenLockHeld {
					c.tokenMu.Unlock()
					tokenLockHeld = false
				}
				session, err = c.login(ctx)
			}
		} else {
			session, err = c.login(ctx)
		}

		if !tokenLockHeld {
			c.tokenMu.Lock()
		}
		c.loginInflight = nil
		if err != nil {
			sameRefreshGeneration := refreshing && c.tokenGeneration == refreshToken.generation && c.token == refreshToken.value
			retireRefresh := refreshRejected || refreshGenerationRejected || replacementLogin
			if retireRefresh && sameRefreshGeneration {
				// APIC or a data request definitively rejected this session, or its
				// locally expired generation failed replacement login. Retire it even
				// when the owner was canceled so a waiter can take over safely.
				c.clearTokenLocked()
			}
			if ctx.Err() == nil {
				if sameRefreshGeneration && refreshAccepted && !retireRefresh && !authenticationRejected(err) {
					// A bounded proactive refresh failed for a non-authentication
					// reason. Keep the accepted token usable until its real expiry and
					// schedule a separate bounded refresh retry.
					c.recordRefreshFailureLocked(err)
					snapshot := c.tokenSnapshotLocked()
					usable := c.sessionExpiry.IsZero() || time.Now().Before(c.sessionExpiry)
					close(ch)
					c.tokenMu.Unlock()
					if usable {
						return snapshot, nil
					}
					return tokenSnapshot{}, err
				}
				if sameRefreshGeneration && !retireRefresh && authenticationRejected(err) {
					c.clearTokenLocked()
				}
				c.recordAuthFailureLocked(err)
			}
			close(ch)
			c.tokenMu.Unlock()
			if ctx.Err() != nil {
				return tokenSnapshot{}, ctx.Err()
			}
			return tokenSnapshot{}, err
		}
		if refreshing && (c.tokenGeneration != refreshToken.generation || c.token != refreshToken.value) {
			close(ch)
			c.tokenMu.Unlock()
			continue
		}
		c.installSessionLocked(session)
		snapshot := c.tokenSnapshotLocked()
		close(ch)
		c.tokenMu.Unlock()
		return snapshot, nil
	}
}

func (c *Client) login(ctx context.Context) (authSession, error) {
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
		return authSession{}, err
	}
	return c.retrySessionRequest(ctx, func() (authSession, http.Header, int, error) {
		return c.loginOnce(ctx, payload)
	})
}

func (c *Client) refresh(ctx context.Context, token tokenSnapshot) (authSession, error) {
	return c.retrySessionRequest(ctx, func() (authSession, http.Header, int, error) {
		return c.refreshOnce(ctx, token)
	})
}

func (c *Client) retrySessionRequest(ctx context.Context, request func() (authSession, http.Header, int, error)) (authSession, error) {
	var lastErr error
	for attempt := range c.retries + 1 {
		session, header, status, err := request()
		if err == nil {
			return session, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return authSession{}, ctx.Err()
		}
		if httpclient.IsCertificateVerificationError(err) {
			return authSession{}, err
		}
		retryable := retryableStatus(status) ||
			httpclient.IsResponseBodyReadError(err) && status >= 200 && status < 300
		retryDelay := time.Duration(-1)
		if header != nil {
			retryDelay = retryAfter(header.Get("Retry-After"))
		}
		if !retryable || attempt == c.retries || !sleepBeforeRetry(ctx, attempt, retryDelay) {
			if ctx.Err() != nil {
				return authSession{}, ctx.Err()
			}
			return authSession{}, err
		}
	}
	return authSession{}, lastErr
}

func (c *Client) loginOnce(ctx context.Context, payload []byte) (authSession, http.Header, int, error) {
	return c.sessionRequestOnce(ctx, http.MethodPost, "aaaLogin", "/api/aaaLogin.json", payload, tokenSnapshot{})
}

func (c *Client) refreshOnce(ctx context.Context, token tokenSnapshot) (authSession, http.Header, int, error) {
	return c.sessionRequestOnce(ctx, http.MethodGet, "aaaRefresh", "/api/aaaRefresh.json", nil, token)
}

// sessionRequestOnce deliberately performs a raw authentication request. In
// particular, aaaRefresh must use its captured cookie rather than recursively
// entering ensureToken.
func (c *Client) sessionRequestOnce(ctx context.Context, method, operation, path string, payload []byte, token tokenSnapshot) (authSession, http.Header, int, error) {
	reqURL := c.buildURL(path, nil)
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return authSession{}, nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token.value != "" {
		req.AddCookie(&http.Cookie{Name: "APIC-cookie", Value: token.value})
	}
	start := time.Now()
	resp, err := c.client.Do(req)
	duration := time.Since(start)
	if err != nil {
		err = decorateCertificateVerificationError(err)
		c.record(RequestStat{Controller: c.name, Operation: operation, Method: method, Path: path, Outcome: "error", Duration: duration, Err: err})
		return authSession{}, nil, 0, err
	}
	bodyBytes, readErr := httpclient.ReadResponseBody(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		c.record(RequestStat{Controller: c.name, Operation: operation, Method: method, Path: path, Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, RateLimited: resp.StatusCode == http.StatusTooManyRequests, Err: readErr})
		return authSession{}, resp.Header, resp.StatusCode, readErr
	}
	if closeErr != nil {
		return authSession{}, resp.Header, resp.StatusCode, closeErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode, body: bodyBytes}
		c.record(RequestStat{Controller: c.name, Operation: operation, Method: method, Path: path, Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: apiErr})
		return authSession{}, resp.Header, resp.StatusCode, apiErr
	}
	var session authSession
	if token.value == "" {
		session, err = parseLoginSession(bodyBytes)
	} else {
		session, err = parseRefreshSession(bodyBytes, token.refreshTimeout)
	}
	if err != nil {
		c.record(RequestStat{Controller: c.name, Operation: operation, Method: method, Path: path, Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: err})
		return authSession{}, resp.Header, resp.StatusCode, err
	}
	session.refreshDeadline = safeRefreshDeadline(start, session.refreshTimeout)
	session.sessionExpiry = start.Add(session.refreshTimeout)
	c.record(RequestStat{Controller: c.name, Operation: operation, Method: method, Path: path, Outcome: "success", StatusCode: resp.StatusCode, Duration: duration})
	return session, resp.Header, resp.StatusCode, nil
}

func (c *Client) rejectToken(token tokenSnapshot, authErr error, allowRecovery bool) tokenRejection {
	if token.value == "" {
		return tokenRejection{}
	}
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.tokenGeneration != token.generation || c.token != token.value {
		// A newer generation already exists, or an accepted generation was
		// atomically retired by a recovery owner. Share that replacement only
		// while this request still has its one recovery attempt available.
		if allowRecovery && (c.token != "" || c.loginInflight != nil) {
			return tokenRejection{retry: true, joined: true}
		}
		return tokenRejection{}
	}
	if c.loginInflight != nil {
		if c.tokenAccepted && allowRecovery {
			// Tell the refresh owner that APIC rejected its captured generation.
			// A successful refresh can still install its replacement, but any
			// failure must retire this generation and hand off or perform the one
			// bounded login without letting a caller resend it.
			c.markGenerationRejectedLocked(token.generation)
			return tokenRejection{retry: true, joined: true}
		}
		if c.tokenAccepted {
			return tokenRejection{}
		}
		// A never-accepted token remains a credential/authentication failure
		// even if a refresh happened to start concurrently.
		c.clearTokenLocked()
		if authErr == nil {
			authErr = errors.New("apic authentication rejected")
		}
		c.recordAuthFailureLocked(authErr)
		return tokenRejection{}
	}
	accepted := c.tokenAccepted
	c.clearTokenLocked()
	if authErr == nil {
		authErr = errors.New("apic authentication rejected")
	}
	if !accepted || !allowRecovery {
		// Fresh token rejection and rejection of the one bounded replacement
		// remain immediate authentication failures. Expiry of an established
		// generation is recorded only if its recovery login actually fails, so
		// cancellation can hand ownership to a waiter without poisoning backoff.
		c.recordAuthFailureLocked(authErr)
		return tokenRejection{}
	}

	done := make(chan struct{})
	c.loginInflight = done
	return tokenRejection{
		retry: true,
		recovery: &tokenRecovery{
			done:       done,
			generation: c.tokenGeneration,
		},
	}
}

func (c *Client) recoverToken(ctx context.Context, recovery tokenRecovery) error {
	session, err := c.login(ctx)

	c.tokenMu.Lock()
	if c.loginInflight != recovery.done {
		c.tokenMu.Unlock()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	c.loginInflight = nil
	if err != nil {
		if ctx.Err() == nil {
			c.recordAuthFailureLocked(err)
		}
		close(recovery.done)
		c.tokenMu.Unlock()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if c.tokenGeneration == recovery.generation && c.token == "" {
		c.installSessionLocked(session)
	}
	close(recovery.done)
	c.tokenMu.Unlock()
	return nil
}

func (c *Client) markTokenSuccess(token tokenSnapshot) {
	if token.value == "" {
		return
	}
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.tokenGeneration != token.generation || c.token != token.value {
		return
	}
	c.tokenAccepted = true
	c.authFailures = 0
	c.lastAuthErr = nil
	c.lastAuthAt = time.Time{}
}

func (c *Client) recordAuthFailureLocked(err error) {
	c.authFailures++
	c.lastAuthErr = err
	c.lastAuthAt = time.Now()
}

func (c *Client) recordRefreshFailureLocked(err error) {
	c.refreshFailures++
	c.lastRefreshErr = err
	now := time.Now()
	retryAt := now.Add(authBackoffFor(c.refreshFailures))
	if !c.sessionExpiry.IsZero() && now.Before(c.sessionExpiry) && retryAt.After(c.sessionExpiry) {
		retryAt = c.sessionExpiry
	}
	c.refreshRetryAt = retryAt
}

func (c *Client) generationRejectedLocked(generation uint64) bool {
	return c.generationRejected && c.rejectedGeneration == generation
}

func (c *Client) markGenerationRejectedLocked(generation uint64) {
	if c.tokenGeneration != generation || c.generationRejectedLocked(generation) {
		return
	}
	c.generationRejected = true
	c.rejectedGeneration = generation
	if c.generationRejectedSignal == nil {
		c.generationRejectedSignal = make(chan struct{})
	}
	close(c.generationRejectedSignal)
}

func (c *Client) clearTokenLocked() {
	c.tokenGeneration++
	c.token = ""
	c.refreshTimeout = 0
	c.refreshDeadline = time.Time{}
	c.sessionExpiry = time.Time{}
	c.tokenAccepted = false
	c.generationRejected = false
	c.rejectedGeneration = 0
	c.generationRejectedSignal = nil
	c.lastRefreshErr = nil
	c.refreshRetryAt = time.Time{}
	c.refreshFailures = 0
}

func (c *Client) installSessionLocked(session authSession) {
	c.tokenGeneration++
	c.token = session.token
	c.refreshTimeout = session.refreshTimeout
	c.refreshDeadline = session.refreshDeadline
	c.sessionExpiry = session.sessionExpiry
	c.tokenAccepted = false
	c.generationRejected = false
	c.rejectedGeneration = 0
	c.generationRejectedSignal = make(chan struct{})
	c.lastRefreshErr = nil
	c.refreshRetryAt = time.Time{}
	c.refreshFailures = 0
}

func (c *Client) tokenSnapshotLocked() tokenSnapshot {
	return tokenSnapshot{value: c.token, generation: c.tokenGeneration, refreshTimeout: c.refreshTimeout, sessionExpiry: c.sessionExpiry}
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

func parseLoginSession(body []byte) (authSession, error) {
	return parseAuthSession(body, 0)
}

func parseRefreshSession(body []byte, previousTimeout time.Duration) (authSession, error) {
	return parseAuthSession(body, previousTimeout)
}

// parseAuthSession accepts both response classes because APIC can return either
// aaaLogin or aaaRefresh from both authentication endpoints. Only refresh may
// reuse a prior timeout when APIC returns the documented zero value.
func parseAuthSession(body []byte, zeroTimeoutFallback time.Duration) (authSession, error) {
	var envelope struct {
		IMData []map[string]struct {
			Attributes map[string]any `json:"attributes"`
		} `json:"imdata"`
	}
	if err := httpclient.DecodeJSON(body, &envelope); err != nil {
		return authSession{}, err
	}
	for _, item := range envelope.IMData {
		for _, className := range []string{"aaaLogin", "aaaRefresh"} {
			response, ok := item[className]
			if !ok {
				continue
			}
			attributes := Object(response.Attributes)
			token := String(attributes, "token")
			if token == "" {
				return authSession{}, errors.New("apic authentication response did not include a token")
			}
			timeoutValue := String(attributes, "refreshTimeoutSeconds")
			seconds, err := strconv.ParseInt(timeoutValue, 10, 64)
			maxDurationSeconds := int64((time.Duration(1<<63 - 1)) / time.Second)
			if err != nil || seconds < 0 || seconds > maxDurationSeconds {
				return authSession{}, fmt.Errorf("apic authentication response included invalid refreshTimeoutSeconds %q", timeoutValue)
			}
			refreshTimeout := time.Duration(seconds) * time.Second
			if refreshTimeout == 0 {
				if zeroTimeoutFallback <= 0 {
					return authSession{}, fmt.Errorf("apic authentication response included invalid refreshTimeoutSeconds %q", timeoutValue)
				}
				refreshTimeout = zeroTimeoutFallback
			}
			return authSession{token: token, refreshTimeout: refreshTimeout}, nil
		}
	}
	return authSession{}, errors.New("apic authentication response did not include aaaLogin or aaaRefresh")
}

func safeRefreshDeadline(start time.Time, timeout time.Duration) time.Time {
	return start.Add(timeout / refreshDeadlineDivisor)
}

func authenticationRejected(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.StatusCode == http.StatusUnauthorized {
		// Unknown and unstructured 401 responses retain the original expired-
		// session recovery behavior. Only an explicit authorization denial is
		// excluded.
		text, ok := apicErrorText(apiErr)
		return !ok || !authorizationDeniedText(text)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		return false
	}
	text, ok := apicErrorText(apiErr)
	if !ok {
		return false
	}
	return invalidSessionText(text)
}

func authorizationDenied(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || (apiErr.StatusCode != http.StatusUnauthorized && apiErr.StatusCode != http.StatusForbidden) {
		return false
	}
	text, ok := apicErrorText(apiErr)
	return ok && !invalidSessionText(text) && authorizationDeniedText(text)
}

func invalidSessionText(text string) bool {
	normalized := strings.ToLower(strings.TrimSpace(text))
	return strings.HasPrefix(normalized, "token was invalid") ||
		strings.HasPrefix(normalized, "invalid session") ||
		strings.HasPrefix(normalized, "session is invalid")
}

func authorizationDeniedText(text string) bool {
	normalized := strings.ToLower(strings.TrimSpace(text))
	if strings.Contains(normalized, "rbac") || strings.Contains(normalized, "security domain") ||
		strings.Contains(normalized, "not authorized") || strings.Contains(normalized, "authorization denied") ||
		strings.Contains(normalized, "access denied") {
		return true
	}
	if strings.Contains(normalized, "privilege") {
		return strings.Contains(normalized, "insufficient") || strings.Contains(normalized, "does not have") ||
			strings.Contains(normalized, "lacks")
	}
	return strings.Contains(normalized, "permission") &&
		(strings.Contains(normalized, "denied") || strings.Contains(normalized, "does not have") || strings.Contains(normalized, "lacks"))
}

func apicErrorText(apiErr *APIError) (string, bool) {
	var envelope struct {
		IMData []map[string]struct {
			Attributes map[string]any `json:"attributes"`
		} `json:"imdata"`
	}
	if apiErr == nil || httpclient.DecodeJSON(apiErr.body, &envelope) != nil {
		return "", false
	}
	for _, item := range envelope.IMData {
		response, ok := item["error"]
		if !ok {
			continue
		}
		attributes := Object(response.Attributes)
		code := String(attributes, "code")
		if code != "" && code != strconv.Itoa(apiErr.StatusCode) {
			continue
		}
		text := String(attributes, "text")
		if text != "" {
			return text, true
		}
	}
	return "", false
}

func decodeObjects(body []byte) ([]Object, int, error) {
	var envelope struct {
		TotalCount string           `json:"totalCount"`
		IMData     []map[string]any `json:"imdata"`
	}
	if err := httpclient.DecodeJSON(body, &envelope); err == nil && envelope.IMData != nil {
		out := make([]Object, 0, len(envelope.IMData))
		for _, item := range envelope.IMData {
			for className, raw := range item {
				obj := Object{"aci.class": className}
				if rawMap, ok := raw.(map[string]any); ok {
					if attrs, ok := rawMap["attributes"].(map[string]any); ok {
						maps.Copy(obj, attrs)
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
	if err := httpclient.DecodeJSON(body, &array); err == nil {
		return array, len(array), nil
	}
	var obj Object
	if err := httpclient.DecodeJSON(body, &obj); err != nil {
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
	return status == 0 || status == http.StatusTooManyRequests || status >= 500
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
