// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	defaultUserAgent      = "opentelemetry-collector-contrib-ciscoosreceiver"
	defaultRequestTimeout = 30 * time.Second
	defaultPageSize       = 100
	defaultRequestSpacing = 20 * time.Millisecond
	defaultMaxPages       = 100
	defaultMaxResults     = 100000
)

// Config controls the Cisco ISE REST/OpenAPI/ERS/MnT client.
type Config struct {
	Endpoint           string
	Username           string
	Password           string
	AllowEmptyPassword bool
	UserAgent          string
	Timeout            time.Duration
	MaxRetries         int
	PageSize           int
	CAFile             string
	ServerName         string
	InsecureSkipVerify bool
}

// RequestStat describes a single Cisco ISE API request attempt.
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

// APIError is returned for non-success Cisco ISE API responses.
type APIError struct {
	StatusCode int
}

func (e *APIError) Error() string {
	return httpclient.StatusError("ise", e.StatusCode)
}

// IsUnavailable reports whether err means an ISE API family is missing, disabled, or unauthorized.
func IsUnavailable(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusUnauthorized ||
		apiErr.StatusCode == http.StatusForbidden ||
		apiErr.StatusCode == http.StatusNotFound ||
		apiErr.StatusCode == http.StatusServiceUnavailable
}

// Client is a compact Cisco ISE REST/OpenAPI/ERS/MnT client.
type Client struct {
	endpoint   *url.URL
	username   string
	password   string
	userAgent  string
	client     *http.Client
	retries    int
	pageSize   int
	spacing    time.Duration
	maxPages   int
	maxResults int

	limitMu  sync.Mutex
	nextSend time.Time

	OnRequest func(RequestStat)
}

// NewClient creates a Cisco ISE REST/OpenAPI/ERS/MnT client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("ise endpoint is required")
	}
	parsed, err := url.Parse(cfg.Endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid ise endpoint %q", cfg.Endpoint)
	}
	if cfg.Username == "" || cfg.Password == "" && !cfg.AllowEmptyPassword {
		return nil, errors.New("ise username and password are required")
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
		return nil, fmt.Errorf("invalid ise max retries: %w", err)
	}
	pageSize := cfg.PageSize
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if pageSize > defaultPageSize {
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
	return &Client{
		endpoint:   parsed,
		username:   cfg.Username,
		password:   cfg.Password,
		userAgent:  userAgent,
		client:     &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: httpclient.SameOriginRedirectPolicy(parsed)},
		retries:    retries,
		pageSize:   pageSize,
		spacing:    defaultRequestSpacing,
		maxPages:   defaultMaxPages,
		maxResults: defaultMaxResults,
	}, nil
}

func clientTLSConfig(cfg Config) (*tls.Config, error) {
	if cfg.CAFile == "" && cfg.ServerName == "" && !cfg.InsecureSkipVerify {
		return nil, nil
	}
	tlsConfig := &tls.Config{ServerName: cfg.ServerName}
	if cfg.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}
	if cfg.CAFile == "" {
		return tlsConfig, nil
	}
	caBytes, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("ISE REST CA file %s did not contain PEM certificates", cfg.CAFile)
	}
	tlsConfig.RootCAs = pool
	return tlsConfig, nil
}

// CloseIdleConnections closes idle HTTP connections held by the client.
func (c *Client) CloseIdleConnections() {
	c.client.CloseIdleConnections()
}

// Endpoint returns the configured Cisco ISE endpoint URL.
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

// GetObject fetches a JSON or XML document and returns it as an object.
func (c *Client) GetObject(ctx context.Context, operation, path string, query url.Values) (Object, error) {
	body, _, err := c.do(ctx, http.MethodGet, operation, path, query, nil)
	if err != nil {
		return nil, err
	}
	obj, err := decodeObject(body)
	if err != nil {
		return nil, fmt.Errorf("decode ise %s response: %w", operation, err)
	}
	return obj, nil
}

// List fetches generic objects from a Cisco ISE endpoint.
func (c *Client) List(ctx context.Context, operation, path string, query url.Values, maxResults int) ([]Object, error) {
	pagePath := path
	pageQuery := cloneValues(query)
	seenRequests := make(map[string]struct{})
	results := make([]Object, 0)
	var byteBudget httpclient.PaginationByteBudget

	for page := 0; ; page++ {
		if page >= c.maxPages {
			return results, fmt.Errorf("paginate ise %s response: exceeded %d pages", operation, c.maxPages)
		}
		requestKey := c.resolve(pagePath, pageQuery)
		if _, seen := seenRequests[requestKey]; seen {
			return results, fmt.Errorf("paginate ise %s response: detected continuation cycle", operation)
		}
		seenRequests[requestKey] = struct{}{}

		body, header, err := c.do(ctx, http.MethodGet, operation, pagePath, pageQuery, nil)
		if err != nil {
			return results, err
		}
		if budgetErr := byteBudget.Charge(operation, len(body), len(results)); budgetErr != nil {
			return results, budgetErr
		}
		objects, _, err := decodeObjects(body)
		if err != nil {
			return results, fmt.Errorf("decode ise %s response: %w", operation, err)
		}
		results = append(results, objects...)
		if len(results) > c.maxResults {
			return results[:c.maxResults], fmt.Errorf("paginate ise %s response: exceeded %d results", operation, c.maxResults)
		}
		if maxResults > 0 && len(results) >= maxResults {
			return results[:maxResults], nil
		}

		pagination := paginationFromResponse(body, header)
		nextPath, nextQuery, more, err := c.nextListPage(pagePath, pageQuery, pagination, len(objects))
		if err != nil {
			return results, fmt.Errorf("paginate ise %s response: %w", operation, err)
		}
		if !more {
			return results, nil
		}
		if len(results) >= c.maxResults {
			return results, fmt.Errorf("paginate ise %s response: exceeded %d results", operation, c.maxResults)
		}
		pagePath = nextPath
		pageQuery = nextQuery
	}
}

// ListERS fetches ERS search endpoints using ISE page/size pagination.
func (c *Client) ListERS(ctx context.Context, operation, path string, query url.Values, maxResults int) ([]Object, error) {
	if query == nil {
		query = url.Values{}
	}
	startPage := 1
	if configuredPage, err := strconv.Atoi(query.Get("page")); err == nil && configuredPage >= 1 {
		startPage = configuredPage
	}
	configuredPageSize := c.pageSize
	if requestedSize, err := strconv.Atoi(query.Get("size")); err == nil && requestedSize > 0 && requestedSize <= defaultPageSize {
		configuredPageSize = requestedSize
	}
	seenRequests := make(map[string]struct{})
	var results []Object
	var byteBudget httpclient.PaginationByteBudget
	for requestNumber, page := 0, startPage; ; requestNumber, page = requestNumber+1, page+1 {
		if requestNumber >= c.maxPages {
			return results, fmt.Errorf("paginate ise %s response: exceeded %d pages", operation, c.maxPages)
		}
		pageQuery := cloneValues(query)
		pageSize := configuredPageSize
		if maxResults > 0 {
			remaining := maxResults - len(results)
			if remaining <= 0 {
				return results, nil
			}
			if remaining < pageSize {
				pageSize = remaining
			}
		}
		if remaining := c.maxResults - len(results); remaining <= 0 {
			return results, fmt.Errorf("paginate ise %s response: exceeded %d results", operation, c.maxResults)
		} else if remaining < pageSize {
			pageSize = remaining
		}
		pageQuery.Set("page", strconv.Itoa(page))
		pageQuery.Set("size", strconv.Itoa(pageSize))
		requestKey := c.resolve(path, pageQuery)
		if _, seen := seenRequests[requestKey]; seen {
			return results, fmt.Errorf("paginate ise %s response: detected continuation cycle", operation)
		}
		seenRequests[requestKey] = struct{}{}
		body, _, err := c.do(ctx, http.MethodGet, operation, path, pageQuery, nil)
		if err != nil {
			return results, err
		}
		if budgetErr := byteBudget.Charge(operation, len(body), len(results)); budgetErr != nil {
			return results, budgetErr
		}
		objects, total, err := decodeObjects(body)
		if err != nil {
			return results, fmt.Errorf("decode ise %s response: %w", operation, err)
		}
		results = append(results, objects...)
		if len(results) > c.maxResults {
			return results[:c.maxResults], fmt.Errorf("paginate ise %s response: exceeded %d results", operation, c.maxResults)
		}
		if maxResults > 0 && len(results) >= maxResults {
			return results[:maxResults], nil
		}
		if len(objects) == 0 || len(objects) < pageSize || total > -1 && len(results) >= total {
			return results, nil
		}
		if len(results) >= c.maxResults {
			return results, fmt.Errorf("paginate ise %s response: exceeded %d results", operation, c.maxResults)
		}
	}
}

// PostQuery posts a JSON payload and returns normalized objects from the response.
func (c *Client) PostQuery(ctx context.Context, operation, path string, payload any, maxResults int) ([]Object, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	body, _, err := c.do(ctx, http.MethodPost, operation, path, nil, bodyBytes)
	if err != nil {
		return nil, err
	}
	objects, _, err := decodeObjects(body)
	if err != nil {
		return nil, fmt.Errorf("decode ise %s response: %w", operation, err)
	}
	return capObjects(objects, maxResults), nil
}

// PostObject posts a JSON payload and returns one normalized object from the response.
func (c *Client) PostObject(ctx context.Context, operation, path string, payload any) (Object, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	body, _, err := c.do(ctx, http.MethodPost, operation, path, nil, bodyBytes)
	if err != nil {
		return nil, err
	}
	obj, err := decodeObject(body)
	if err != nil {
		return nil, fmt.Errorf("decode ise %s response: %w", operation, err)
	}
	return obj, nil
}

type responsePagination struct {
	nextLink string
	offset   int
	limit    int
	total    int
	hasRange bool
}

func paginationFromResponse(body []byte, header http.Header) responsePagination {
	pagination := responsePagination{nextLink: nextLink(header.Get("Link"))}
	root, err := decodeObject(body)
	if err != nil {
		return pagination
	}
	if pagination.nextLink == "" {
		pagination.nextLink = bodyNextLink(root)
	}

	candidates := []Object{root}
	for _, key := range []string{"pagination", "pageInfo", "meta"} {
		if nested, ok := objectField(root, key); ok {
			candidates = append(candidates, nested)
		}
	}
	for _, candidate := range candidates {
		offset, hasOffset := integerField(candidate, "offset")
		limit, hasLimit := integerField(candidate, "limit")
		total, hasTotal := integerField(candidate, "total", "totalCount", "total_count", "totalItemsCount", "totalResultsCount")
		if hasOffset && hasLimit && hasTotal && offset >= 0 && limit > 0 && total >= 0 {
			pagination.offset = offset
			pagination.limit = limit
			pagination.total = total
			pagination.hasRange = true
			break
		}
	}
	return pagination
}

func (c *Client) nextListPage(currentPath string, currentQuery url.Values, pagination responsePagination, objectCount int) (string, url.Values, bool, error) {
	if pagination.nextLink != "" {
		nextPath, nextQuery, err := c.splitNextURL(currentPath, currentQuery, pagination.nextLink)
		if err != nil {
			return "", nil, false, err
		}
		return nextPath, nextQuery, true, nil
	}
	if !pagination.hasRange {
		return "", nil, false, nil
	}
	nextOffset := pagination.offset + objectCount
	if nextOffset >= pagination.total {
		return "", nil, false, nil
	}
	if objectCount == 0 || nextOffset <= pagination.offset {
		return "", nil, false, errors.New("offset pagination did not advance")
	}
	nextQuery := cloneValues(currentQuery)
	nextQuery.Set("offset", strconv.Itoa(nextOffset))
	limit := pagination.limit
	if c.pageSize > 0 && limit > c.pageSize {
		limit = c.pageSize
	}
	nextQuery.Set("limit", strconv.Itoa(limit))
	return currentPath, nextQuery, true, nil
}

func (c *Client) splitNextURL(currentPath string, currentQuery url.Values, next string) (string, url.Values, error) {
	currentURL, err := url.Parse(c.resolve(currentPath, currentQuery))
	if err != nil {
		return "", nil, err
	}
	nextReference, err := url.Parse(strings.TrimSpace(next))
	if err != nil {
		return "", nil, fmt.Errorf("invalid next-page URL: %w", err)
	}
	resolved := currentURL.ResolveReference(nextReference)
	if resolved.User != nil {
		return "", nil, errors.New("next-page URL must not contain user information")
	}
	if !httpclient.SameOrigin(c.endpoint, resolved) {
		return "", nil, errors.New("cross-origin next-page URL")
	}
	return resolved.Path, resolved.Query(), nil
}

func bodyNextLink(root Object) string {
	candidates := []Object{root}
	for _, key := range []string{"SearchResult", "searchResult", "ERSResponse", "ersResponse"} {
		if nested, ok := objectField(root, key); ok {
			candidates = append(candidates, nested)
		}
	}
	for _, candidate := range candidates {
		if value, ok := valueForKey(candidate, "nextPage"); ok {
			if link := linkFromValue(value); link != "" {
				return link
			}
		}
		for _, key := range []string{"_links", "links", "pagination", "pageInfo"} {
			container, ok := objectField(candidate, key)
			if !ok {
				continue
			}
			if value, ok := valueForKey(container, "next"); ok {
				if link := linkFromValue(value); link != "" {
					return link
				}
			}
		}
		if meta, ok := objectField(candidate, "meta"); ok {
			if links, ok := objectField(meta, "links"); ok {
				if value, ok := valueForKey(links, "next"); ok {
					if link := linkFromValue(value); link != "" {
						return link
					}
				}
			}
		}
	}
	return ""
}

func linkFromValue(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case Object:
		return strings.TrimSpace(String(typed, "href", "@href", "url", "value"))
	case map[string]any:
		return strings.TrimSpace(String(Object(typed), "href", "@href", "url", "value"))
	default:
		return ""
	}
}

func objectField(obj Object, key string) (Object, bool) {
	value, ok := valueForKey(obj, key)
	if !ok {
		return nil, false
	}
	switch typed := value.(type) {
	case Object:
		return typed, true
	case map[string]any:
		return Object(typed), true
	default:
		return nil, false
	}
}

func integerField(obj Object, keys ...string) (int, bool) {
	for _, key := range keys {
		value, ok := valueForKey(obj, key)
		if !ok {
			continue
		}
		var text string
		switch typed := value.(type) {
		case json.Number:
			text = typed.String()
		case string:
			text = strings.TrimSpace(typed)
		case int:
			return typed, true
		case int64:
			if int64(int(typed)) == typed {
				return int(typed), true
			}
		case float64:
			if typed == float64(int(typed)) {
				return int(typed), true
			}
		}
		if text != "" {
			parsed, err := strconv.Atoi(text)
			if err == nil {
				return parsed, true
			}
		}
	}
	return 0, false
}

func nextLink(linkHeader string) string {
	for _, part := range splitLinkHeader(linkHeader) {
		part = strings.TrimSpace(part)
		start := strings.Index(part, "<")
		end := strings.Index(part, ">")
		if start >= 0 && end > start && linkHasNextRelation(part[end+1:]) {
			return strings.TrimSpace(part[start+1 : end])
		}
	}
	return ""
}

func splitLinkHeader(header string) []string {
	var parts []string
	start := 0
	inAngle := false
	inQuote := false
	escaped := false
	for index, char := range header {
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' && inQuote {
			escaped = true
			continue
		}
		switch char {
		case '<':
			if !inQuote {
				inAngle = true
			}
		case '>':
			if !inQuote {
				inAngle = false
			}
		case '"':
			if !inAngle {
				inQuote = !inQuote
			}
		case ',':
			if !inAngle && !inQuote {
				parts = append(parts, header[start:index])
				start = index + 1
			}
		}
	}
	parts = append(parts, header[start:])
	return parts
}

func linkHasNextRelation(parameters string) bool {
	for parameter := range strings.SplitSeq(parameters, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "rel") {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		for relation := range strings.FieldsSeq(value) {
			if strings.EqualFold(relation, "next") {
				return true
			}
		}
	}
	return false
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
		if ctx.Err() != nil || !retryableStatus(status) || attempt == attempts-1 {
			break
		}
		sleep := time.Duration(1<<attempt)*100*time.Millisecond + time.Duration(rand.Int64N(int64(50*time.Millisecond)))
		timer := time.NewTimer(sleep)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, nil, lastErr
}

func (c *Client) doOnce(ctx context.Context, method, operation, path string, query url.Values, payload []byte) ([]byte, http.Header, int, error) {
	if err := c.waitTurn(ctx); err != nil {
		return nil, nil, 0, err
	}
	target := c.resolve(path, query)
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, nil, 0, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json, application/xml, text/xml")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.SetBasicAuth(c.username, c.password)

	start := time.Now()
	resp, err := c.client.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "error", Duration: duration, Err: err})
		return nil, nil, 0, err
	}
	defer resp.Body.Close()

	respBody, readErr := httpclient.ReadResponseBody(resp.Body)
	if readErr != nil {
		c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, Err: readErr})
		return nil, resp.Header, resp.StatusCode, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode}
		c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, RateLimited: resp.StatusCode == http.StatusTooManyRequests, Err: apiErr})
		return nil, resp.Header, resp.StatusCode, apiErr
	}
	c.record(RequestStat{Operation: operation, Method: method, Path: path, Outcome: "success", StatusCode: resp.StatusCode, Duration: duration})
	return respBody, resp.Header, resp.StatusCode, nil
}

func (c *Client) resolve(path string, query url.Values) string {
	target := *c.endpoint
	basePath := strings.TrimRight(target.Path, "/")
	requestPath := "/" + strings.TrimLeft(path, "/")
	if basePath != "" && basePath != "/" && !strings.HasPrefix(requestPath, basePath+"/") {
		target.Path = basePath + requestPath
	} else {
		target.Path = requestPath
	}
	target.RawQuery = query.Encode()
	return target.String()
}

func (c *Client) waitTurn(ctx context.Context) error {
	c.limitMu.Lock()
	now := time.Now()
	wait := time.Duration(0)
	if c.nextSend.After(now) {
		wait = c.nextSend.Sub(now)
	}
	c.nextSend = now.Add(wait + c.spacing)
	c.limitMu.Unlock()
	if wait == 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	select {
	case <-ctx.Done():
		timer.Stop()
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) record(stat RequestStat) {
	if c.OnRequest != nil {
		c.OnRequest(stat)
	}
}

func retryableStatus(status int) bool {
	return status == 0 || status == http.StatusTooManyRequests || status >= 500
}

func cloneValues(values url.Values) url.Values {
	clone := url.Values{}
	for key, current := range values {
		clone[key] = append([]string(nil), current...)
	}
	return clone
}

func capObjects(objects []Object, maxResults int) []Object {
	if maxResults > 0 && len(objects) > maxResults {
		return objects[:maxResults]
	}
	return objects
}
