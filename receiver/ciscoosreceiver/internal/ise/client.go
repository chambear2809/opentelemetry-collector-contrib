// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/ise"

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"mime"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

const (
	defaultUserAgent                 = "opentelemetry-collector-contrib-ciscoosreceiver"
	defaultRequestTimeout            = 30 * time.Second
	defaultPageSize                  = 100
	defaultRequestSpacing            = 20 * time.Millisecond
	defaultMaxPages                  = 100
	defaultMaxResults                = 100000
	restCAConfigPath                 = "ise.ca_file"
	restInsecureSkipVerifyConfigPath = "ise.insecure_skip_verify"
	ersCSRFHeader                    = "X-CSRF-TOKEN"
	ersCSRFFetchValue                = "fetch"
	ersCSRFRequiredValue             = "required"
	ersCSRFOperation                 = "ers.csrf_token"
	ersCSRFStatPath                  = "/ers/config"
	maxERSCSRFTokenLength            = 4096
)

// Config controls the Cisco ISE REST/OpenAPI/ERS/MnT client.
type Config struct {
	Endpoint                     string
	Username                     string
	Password                     string
	AllowEmptyPassword           bool
	UserAgent                    string
	Timeout                      time.Duration
	MaxRetries                   int
	PageSize                     int
	CAFile                       string
	ServerName                   string
	InsecureSkipVerify           bool
	caConfigPath                 string
	insecureSkipVerifyConfigPath string
}

// RequestStat describes a single Cisco ISE API request attempt.
type RequestStat struct {
	Operation     string
	Method        string
	Path          string
	Outcome       string
	StatusCode    int
	Duration      time.Duration
	RateLimited   bool
	CSRFProtected bool
	Err           error
}

// APIError is returned for non-success Cisco ISE API responses.
type APIError struct {
	StatusCode int
}

func (e *APIError) Error() string {
	return httpclient.StatusError("ise", e.StatusCode)
}

// ResponseContentError reports a successful HTTP response that is not a
// supported ISE API representation. It deliberately excludes response data.
type ResponseContentError struct {
	Kind        string
	ContentType string
}

func (e *ResponseContentError) Error() string {
	if e.ContentType == "" {
		return fmt.Sprintf("ISE API response has %s content", e.Kind)
	}
	return fmt.Sprintf("ISE API response has %s content (content-type %s)", e.Kind, e.ContentType)
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
	endpoint                     *url.URL
	username                     string
	password                     string
	userAgent                    string
	client                       *http.Client
	retries                      int
	pageSize                     int
	spacing                      time.Duration
	maxPages                     int
	maxResults                   int
	caConfigPath                 string
	insecureSkipVerifyConfigPath string

	limitMu  sync.Mutex
	nextSend time.Time

	ersMu             sync.Mutex
	ersCSRFToken      string
	ersCSRFNegotiated bool

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
	caConfigPath := cfg.caConfigPath
	if caConfigPath == "" {
		caConfigPath = restCAConfigPath
	}
	insecureSkipVerifyConfigPath := cfg.insecureSkipVerifyConfigPath
	if insecureSkipVerifyConfigPath == "" {
		insecureSkipVerifyConfigPath = restInsecureSkipVerifyConfigPath
	}
	tlsConfig, err := clientTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create ISE cookie jar: %w", err)
	}
	return &Client{
		endpoint:  parsed,
		username:  cfg.Username,
		password:  cfg.Password,
		userAgent: userAgent,
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			Jar:       jar,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		retries:                      retries,
		pageSize:                     pageSize,
		spacing:                      defaultRequestSpacing,
		maxPages:                     defaultMaxPages,
		maxResults:                   defaultMaxResults,
		caConfigPath:                 caConfigPath,
		insecureSkipVerifyConfigPath: insecureSkipVerifyConfigPath,
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
			return results[:c.maxResults], httpclient.NewPaginationLimitError(operation, "result", c.maxResults, c.maxResults)
		}

		pagination := paginationFromResponse(body, header)
		nextPath, nextQuery, more, err := c.nextListPage(pagePath, pageQuery, pagination, len(objects))
		if err != nil {
			return results, fmt.Errorf("paginate ise %s response: %w", operation, err)
		}
		if maxResults > 0 && len(results) >= maxResults {
			truncated := len(results) > maxResults
			results = results[:maxResults]
			if truncated || more {
				return results, httpclient.NewConfiguredPaginationLimitError(operation, "result", maxResults, len(results))
			}
			return results, nil
		}
		if !more {
			return results, nil
		}
		if len(results) >= c.maxResults {
			return results, httpclient.NewPaginationLimitError(operation, "result", c.maxResults, len(results))
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
	authoritativeTotal := -1
	for requestNumber, page := 0, startPage; ; requestNumber, page = requestNumber+1, page+1 {
		if requestNumber >= c.maxPages {
			return results, httpclient.NewPaginationLimitError(operation, "page", c.maxPages, len(results))
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
			return results, httpclient.NewPaginationLimitError(operation, "result", c.maxResults, len(results))
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
		if total >= 0 {
			if authoritativeTotal >= 0 && total != authoritativeTotal {
				return results, fmt.Errorf(
					"paginate ise %s response: page %d changed advertised total from %d to %d",
					operation,
					page,
					authoritativeTotal,
					total,
				)
			}
			authoritativeTotal = total
		}
		results = append(results, objects...)
		if len(results) > c.maxResults {
			return results[:c.maxResults], httpclient.NewPaginationLimitError(operation, "result", c.maxResults, c.maxResults)
		}
		var complete bool
		if authoritativeTotal >= 0 {
			complete = len(results) >= authoritativeTotal
			if len(objects) == 0 && !complete {
				return results, fmt.Errorf(
					"paginate ise %s response: page %d returned no results after %d of %d advertised results",
					operation,
					page,
					len(results),
					authoritativeTotal,
				)
			}
		} else {
			complete = len(objects) == 0 || len(objects) < pageSize
		}
		if maxResults > 0 && len(results) >= maxResults {
			truncated := len(results) > maxResults
			results = results[:maxResults]
			if truncated || !complete {
				return results, httpclient.NewConfiguredPaginationLimitError(operation, "result", maxResults, len(results))
			}
			return results, nil
		}
		if complete {
			return results, nil
		}
		if len(results) >= c.maxResults {
			return results, httpclient.NewPaginationLimitError(operation, "result", c.maxResults, len(results))
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
	if maxResults > 0 && len(objects) > maxResults {
		return objects[:maxResults], httpclient.NewConfiguredPaginationLimitError(operation, "result", maxResults, maxResults)
	}
	return objects, nil
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

type ersCSRFMode uint8

const (
	ersCSRFNone ersCSRFMode = iota
	ersCSRFFetch
	ersCSRFToken
)

func (c *Client) do(ctx context.Context, method, operation, path string, query url.Values, payload []byte) ([]byte, http.Header, error) {
	ersRequest := isERSRequestPath(path)
	if !ersRequest {
		body, header, _, err := c.doWithRetries(ctx, method, operation, path, query, payload, ersCSRFNone)
		return body, header, err
	}

	// An ERS CSRF token is tied to the HTTP session cookies. Serialize ERS
	// negotiation and requests so concurrently completing token-fetch requests
	// cannot pair a token from one session with cookies from another.
	c.ersMu.Lock()
	defer c.ersMu.Unlock()

	if !c.ersCSRFNegotiated {
		if err := c.negotiateERSCSRF(ctx, path, query); err != nil {
			return nil, nil, err
		}
	}
	mode := c.ersRequestCSRFMode()
	body, header, status, err := c.doWithRetries(ctx, method, operation, path, query, payload, mode)
	if err == nil || status != http.StatusForbidden || !ersCSRFFailureNeedsRefresh(header, mode == ersCSRFToken) {
		return body, header, err
	}

	// A token/session can expire independently of the long-lived collector.
	// Refresh at most once for this logical request; ordinary retry policy does
	// not retry 403 responses.
	c.ersCSRFToken = ""
	c.ersCSRFNegotiated = false
	if refreshErr := c.negotiateERSCSRF(ctx, path, query); refreshErr != nil {
		return nil, header, fmt.Errorf("refresh ISE ERS CSRF session: %w", errors.Join(err, refreshErr))
	}
	body, header, _, err = c.doWithRetries(ctx, method, operation, path, query, payload, c.ersRequestCSRFMode())
	return body, header, err
}

func (c *Client) negotiateERSCSRF(ctx context.Context, path string, query url.Values) error {
	_, _, _, err := c.doWithRetries(ctx, http.MethodGet, ersCSRFOperation, path, query, nil, ersCSRFFetch)
	if err != nil {
		return fmt.Errorf("negotiate ISE ERS CSRF session: %w", err)
	}
	c.ersCSRFNegotiated = true
	return nil
}

func (c *Client) ersRequestCSRFMode() ersCSRFMode {
	if c.ersCSRFToken != "" {
		return ersCSRFToken
	}
	return ersCSRFNone
}

func (c *Client) doWithRetries(
	ctx context.Context,
	method, operation, path string,
	query url.Values,
	payload []byte,
	csrfMode ersCSRFMode,
) ([]byte, http.Header, int, error) {
	var lastErr error
	var lastHeader http.Header
	var lastStatus int
	for attempt := 0; ; attempt++ {
		body, header, status, err := c.doOnce(ctx, method, operation, path, query, payload, csrfMode)
		if err == nil {
			return body, header, status, nil
		}
		lastErr = err
		lastHeader = header
		lastStatus = status
		if ctx.Err() != nil {
			return nil, nil, status, ctx.Err()
		}
		if httpclient.IsCertificateVerificationError(err) {
			break
		}
		if !retryableStatus(status) || attempt >= c.retries {
			break
		}
		sleep := time.Duration(1<<attempt)*100*time.Millisecond + time.Duration(rand.Int64N(int64(50*time.Millisecond)))
		timer := time.NewTimer(sleep)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, nil, status, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, lastHeader, lastStatus, lastErr
}

func (c *Client) doOnce(
	ctx context.Context,
	method, operation, path string,
	query url.Values,
	payload []byte,
	csrfMode ersCSRFMode,
) ([]byte, http.Header, int, error) {
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
	csrfProtected := false
	switch csrfMode {
	case ersCSRFFetch:
		// ISE's ERS CSRF fetch flow expects an explicit representation type
		// even though the handshake itself is a GET with no body.
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(ersCSRFHeader, ersCSRFFetchValue)
	case ersCSRFToken:
		if c.ersCSRFToken != "" {
			req.Header.Set(ersCSRFHeader, c.ersCSRFToken)
			csrfProtected = true
		}
	}
	req.SetBasicAuth(c.username, c.password)
	statPath := path
	if operation == ersCSRFOperation {
		statPath = ersCSRFStatPath
	}

	start := time.Now()
	resp, err := c.client.Do(req)
	duration := time.Since(start)
	if err != nil {
		err = httpclient.DecorateCertificateVerificationError(err, c.caConfigPath, c.insecureSkipVerifyConfigPath)
		c.record(RequestStat{Operation: operation, Method: method, Path: statPath, Outcome: "error", Duration: duration, CSRFProtected: csrfProtected, Err: err})
		return nil, nil, 0, err
	}
	defer resp.Body.Close()

	respBody, readErr := httpclient.ReadResponseBody(resp.Body)
	if readErr != nil {
		c.record(RequestStat{Operation: operation, Method: method, Path: statPath, Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, CSRFProtected: csrfProtected, Err: readErr})
		return nil, resp.Header, resp.StatusCode, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode}
		c.record(RequestStat{Operation: operation, Method: method, Path: statPath, Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, RateLimited: resp.StatusCode == http.StatusTooManyRequests, CSRFProtected: csrfProtected, Err: apiErr})
		return nil, resp.Header, resp.StatusCode, apiErr
	}
	if contentErr := validateISEResponseContent(respBody, resp.Header.Get("Content-Type")); contentErr != nil {
		c.record(RequestStat{Operation: operation, Method: method, Path: statPath, Outcome: "error", StatusCode: resp.StatusCode, Duration: duration, CSRFProtected: csrfProtected, Err: contentErr})
		return nil, resp.Header, resp.StatusCode, contentErr
	}
	if csrfMode != ersCSRFNone {
		c.captureERSCSRFToken(resp.Header)
	}
	c.record(RequestStat{Operation: operation, Method: method, Path: statPath, Outcome: "success", StatusCode: resp.StatusCode, Duration: duration, CSRFProtected: csrfProtected})
	return respBody, resp.Header, resp.StatusCode, nil
}

func isERSRequestPath(path string) bool {
	parsed, err := url.Parse(path)
	if err == nil && parsed.Path != "" {
		path = parsed.Path
	}
	for segment := range strings.SplitSeq(strings.Trim(path, "/"), "/") {
		if segment == "ers" {
			return true
		}
	}
	return false
}

func ersCSRFFailureNeedsRefresh(header http.Header, sentToken bool) bool {
	if sentToken {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(header.Get(ersCSRFHeader)), ersCSRFRequiredValue)
}

func (c *Client) captureERSCSRFToken(header http.Header) {
	token := strings.TrimSpace(header.Get(ersCSRFHeader))
	if token == "" || len(token) > maxERSCSRFTokenLength ||
		strings.EqualFold(token, ersCSRFFetchValue) ||
		strings.EqualFold(token, ersCSRFRequiredValue) {
		return
	}
	c.ersCSRFToken = token
}

type iseResponseFormat uint8

const (
	iseResponseUnknown iseResponseFormat = iota
	iseResponseJSON
	iseResponseXML
	iseResponseHTML
)

func validateISEResponseContent(body []byte, contentType string) error {
	format := detectISEResponseFormat(body)
	mediaType := ""
	if strings.TrimSpace(contentType) != "" {
		parsed, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			return &ResponseContentError{Kind: "invalid-content-type"}
		}
		mediaType = strings.ToLower(parsed)
	}

	if mediaType == "text/html" || format == iseResponseHTML {
		return &ResponseContentError{Kind: "HTML", ContentType: mediaType}
	}
	if format == iseResponseUnknown {
		return &ResponseContentError{Kind: "unrecognized", ContentType: mediaType}
	}

	switch {
	case mediaType == "", mediaType == "text/plain":
		// A few legacy ISE routes and test doubles omit a media type or use
		// text/plain for otherwise valid JSON/XML. Require a recognized body in
		// those cases instead of accepting arbitrary text.
		return nil
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		if format != iseResponseJSON {
			return &ResponseContentError{Kind: "content-type-mismatch", ContentType: mediaType}
		}
		return nil
	case mediaType == "application/xml" || mediaType == "text/xml" || strings.HasSuffix(mediaType, "+xml"):
		if format != iseResponseXML {
			return &ResponseContentError{Kind: "content-type-mismatch", ContentType: mediaType}
		}
		return nil
	default:
		return &ResponseContentError{Kind: "unsupported", ContentType: mediaType}
	}
}

func detectISEResponseFormat(body []byte) iseResponseFormat {
	trimmed := bytes.TrimSpace(body)
	trimmed = bytes.TrimPrefix(trimmed, []byte{0xef, 0xbb, 0xbf})
	trimmed = bytes.TrimSpace(trimmed)
	if len(trimmed) == 0 {
		return iseResponseUnknown
	}
	if json.Valid(trimmed) {
		return iseResponseJSON
	}
	if trimmed[0] != '<' {
		return iseResponseUnknown
	}

	decoder := xml.NewDecoder(bytes.NewReader(trimmed))
	for {
		token, err := decoder.Token()
		if err != nil {
			return iseResponseUnknown
		}
		switch typed := token.(type) {
		case xml.Directive:
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(string(typed))), "doctype html") {
				return iseResponseHTML
			}
		case xml.StartElement:
			if strings.EqualFold(typed.Name.Local, "html") {
				return iseResponseHTML
			}
			return iseResponseXML
		}
	}
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
