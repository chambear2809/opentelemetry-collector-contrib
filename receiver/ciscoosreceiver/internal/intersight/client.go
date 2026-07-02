// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package intersight // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/intersight"

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

const (
	defaultEndpoint       = "https://intersight.com"
	defaultUserAgent      = "opentelemetry-collector-contrib-ciscoosreceiver"
	defaultRequestTimeout = 30 * time.Second
	defaultPageSize       = 100
)

// Config controls the Cisco Intersight API client.
type Config struct {
	KeyID              string
	KeyPEM             string
	KeyFile            string
	Endpoint           string
	UserAgent          string
	Timeout            time.Duration
	MaxRetries         int
	PageSize           int
	InsecureSkipVerify bool
}

// RequestStat describes a single Intersight API request attempt.
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

// APIError is returned for non-success Intersight API responses.
type APIError struct {
	StatusCode int
}

func (e *APIError) Error() string {
	return httpclient.StatusError("intersight", e.StatusCode)
}

// Client is a compact Cisco Intersight REST and telemetry client.
type Client struct {
	keyID     string
	signer    signer
	endpoint  *url.URL
	userAgent string
	client    *http.Client
	retries   int
	pageSize  int

	OnRequest func(RequestStat)
}

// NewClient creates an Intersight API client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.KeyID == "" {
		return nil, errors.New("intersight key ID is required")
	}
	signer, err := newSigner(cfg.KeyPEM, cfg.KeyFile)
	if err != nil {
		return nil, err
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid intersight endpoint %q", endpoint)
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
		return nil, fmt.Errorf("invalid intersight max retries: %w", err)
	}
	pageSize := cfg.PageSize
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // Explicit opt-in for private Intersight appliances.
	}

	return &Client{
		keyID:     cfg.KeyID,
		signer:    signer,
		endpoint:  parsed,
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

// Query returns URL values for common OData query options.
func Query(selectFields []string, filter string) url.Values {
	query := url.Values{}
	if len(selectFields) > 0 {
		query.Set("$select", strings.Join(selectFields, ","))
	}
	if filter != "" {
		query.Set("$filter", filter)
	}
	return query
}

// List fetches all pages for a standard Intersight list endpoint.
func (c *Client) List(ctx context.Context, operation, path string, query url.Values, maxResults int) ([]Object, error) {
	if query == nil {
		query = url.Values{}
	}
	var results []Object
	resultLimit, hardResultLimit := httpclient.EffectivePaginationResultLimit(maxResults)
	skip := 0
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
		pageQuery.Set("$top", strconv.Itoa(pageSize))
		pageQuery.Set("$skip", strconv.Itoa(skip))
		requestKey := path + "?" + pageQuery.Encode()
		if _, seen := seenRequests[requestKey]; seen {
			return results, fmt.Errorf("paginate intersight %s response: detected continuation cycle after %d partial results", operation, len(results))
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

		page, err := decodeList(body)
		if err != nil {
			return results, fmt.Errorf("decode intersight %s page: %w", operation, err)
		}
		results = append(results, page...)
		complete := len(page) < pageSize
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
		skip += len(page)
	}
}

// PostJSON posts a JSON body and decodes the response as a generic value.
func (c *Client) PostJSON(ctx context.Context, operation, path string, body any) (any, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	response, err := c.do(ctx, http.MethodPost, operation, path, nil, payload)
	if err != nil {
		return nil, err
	}
	var out any
	if err := httpclient.DecodeJSON(response, &out); err != nil {
		return nil, fmt.Errorf("decode intersight %s response: %w", operation, err)
	}
	return out, nil
}

func (c *Client) do(ctx context.Context, method, operation, path string, query url.Values, payload []byte) ([]byte, error) {
	var lastErr error
	attempts := c.retries + 1
	for attempt := 0; attempt < attempts; attempt++ {
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
		if err := c.sign(req, payload); err != nil {
			return nil, err
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
		lastErr = errors.New("intersight request failed")
	}
	return nil, lastErr
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

func (c *Client) sign(req *http.Request, payload []byte) error {
	date := time.Now().UTC().Format(http.TimeFormat)
	digest := sha256.Sum256(payload)
	digestHeader := "SHA-256=" + base64.StdEncoding.EncodeToString(digest[:])
	req.Header.Set("Date", date)
	req.Header.Set("Digest", digestHeader)

	headers := []string{"(request-target)", "host", "date", "digest"}
	values := []string{
		"(request-target): " + strings.ToLower(req.Method) + " " + req.URL.RequestURI(),
		"host: " + req.URL.Host,
		"date: " + date,
		"digest: " + digestHeader,
	}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		headers = append(headers, "content-type")
		values = append(values, "content-type: "+ct)
	}

	signature, err := c.signer.sign([]byte(strings.Join(values, "\n")))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf(
		`Signature keyId="%s",algorithm="%s",headers="%s",signature="%s"`,
		c.keyID,
		c.signer.algorithm(),
		strings.Join(headers, " "),
		base64.StdEncoding.EncodeToString(signature),
	))
	return nil
}

func (c *Client) record(stat RequestStat) {
	if c.OnRequest != nil {
		c.OnRequest(stat)
	}
}

func decodeList(body []byte) ([]Object, error) {
	var envelope struct {
		Results []Object `json:"Results"`
		Count   int64    `json:"Count"`
	}
	if err := httpclient.DecodeJSON(body, &envelope); err == nil && envelope.Results != nil {
		return envelope.Results, nil
	}

	var array []Object
	if err := httpclient.DecodeJSON(body, &array); err != nil {
		return nil, err
	}
	return array, nil
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
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
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
