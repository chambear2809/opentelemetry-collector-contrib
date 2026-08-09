// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package httpclient contains safety helpers shared by the Cisco REST clients.
package httpclient // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	// MaxResponseBodySize is the largest response body accepted by Cisco REST clients.
	MaxResponseBodySize int64 = 16 * 1024 * 1024
	// HardMaxJSONDepth bounds nesting before controller responses are decoded
	// into allocation-heavy maps and slices.
	HardMaxJSONDepth = 128
	// HardMaxJSONTokens bounds total JSON syntax and value tokens.
	HardMaxJSONTokens = 450_000
	// HardMaxJSONNodes bounds containers and primitive values. Object keys are
	// charged as tokens but are not separately charged as value nodes.
	HardMaxJSONNodes = 250_000
	// HardMaxRequestRetries keeps exponential backoff arithmetic and scrape
	// duration bounded even for direct internal-client callers.
	HardMaxRequestRetries = 10
)

// ErrResponseBodyTooLarge is returned when an HTTP response exceeds MaxResponseBodySize.
var ErrResponseBodyTooLarge = errors.New("HTTP response body is too large")

// ResponseBodyReadError identifies a transport failure that happened after an
// HTTP response was received but before its body could be read completely.
// Clients can safely distinguish this transient case from deterministic body
// limits and decide whether the response status is otherwise retryable.
type ResponseBodyReadError struct {
	Err error
}

func (e *ResponseBodyReadError) Error() string {
	if e == nil || e.Err == nil {
		return "read HTTP response body"
	}
	return fmt.Sprintf("read HTTP response body: %v", e.Err)
}

func (e *ResponseBodyReadError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// IsResponseBodyReadError reports whether err came from an incomplete response
// body read rather than a configured size or complexity limit.
func IsResponseBodyReadError(err error) bool {
	var readErr *ResponseBodyReadError
	return errors.As(err, &readErr)
}

// JSONComplexityLimitError reports that a response exceeded a hard structural
// ceiling before it was decoded into the caller's target.
type JSONComplexityLimitError struct {
	Kind    string
	Maximum int
}

func (e *JSONComplexityLimitError) Error() string {
	return fmt.Sprintf("JSON response exceeds hard %s limit of %d", e.Kind, e.Maximum)
}

// RetryCount validates a configured retry count without treating zero as an
// omitted value. Factory defaults own the default of three; explicit zero
// means one request attempt and no retries.
func RetryCount(configured int) (int, error) {
	if configured < 0 || configured > HardMaxRequestRetries {
		return 0, fmt.Errorf("retry count must be between 0 and %d", HardMaxRequestRetries)
	}
	return configured, nil
}

// DecodeJSON validates structural complexity with a streaming token pass before
// decoding the response into allocation-heavy maps or slices. It preserves
// integer tokens as json.Number in generic targets and requires exactly one
// top-level JSON value. Controller counters routinely exceed float64's exact
// integer range.
func DecodeJSON(data []byte, target any) error {
	if err := validateJSONComplexity(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON response contains multiple values")
		}
		return err
	}
	return nil
}

type jsonContainer struct {
	object       bool
	expectingKey bool
}

func validateJSONComplexity(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	containers := make([]jsonContainer, 0, 16)
	tokens := 0
	nodes := 0
	rootStarted := false
	rootComplete := false

	chargeNode := func() error {
		nodes++
		if nodes > HardMaxJSONNodes {
			return &JSONComplexityLimitError{Kind: "node", Maximum: HardMaxJSONNodes}
		}
		return nil
	}
	startValue := func() error {
		if len(containers) == 0 {
			if rootStarted {
				return errors.New("JSON response contains multiple values")
			}
			rootStarted = true
			return nil
		}
		parent := &containers[len(containers)-1]
		if parent.object {
			if parent.expectingKey {
				return errors.New("invalid JSON object value")
			}
			parent.expectingKey = true
		}
		return nil
	}

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			switch {
			case !rootStarted:
				return io.EOF
			case !rootComplete:
				return io.ErrUnexpectedEOF
			default:
				return nil
			}
		}
		if err != nil {
			return err
		}
		tokens++
		if tokens > HardMaxJSONTokens {
			return &JSONComplexityLimitError{Kind: "token", Maximum: HardMaxJSONTokens}
		}
		if rootComplete {
			return errors.New("JSON response contains multiple values")
		}

		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				if err := startValue(); err != nil {
					return err
				}
				if err := chargeNode(); err != nil {
					return err
				}
				if len(containers)+1 > HardMaxJSONDepth {
					return &JSONComplexityLimitError{Kind: "depth", Maximum: HardMaxJSONDepth}
				}
				containers = append(containers, jsonContainer{object: delimiter == '{', expectingKey: delimiter == '{'})
			case '}', ']':
				if len(containers) == 0 {
					return errors.New("invalid unmatched JSON delimiter")
				}
				container := containers[len(containers)-1]
				if container.object && !container.expectingKey {
					return errors.New("invalid JSON object without a value")
				}
				containers = containers[:len(containers)-1]
				if len(containers) == 0 {
					rootComplete = true
				}
			}
			continue
		}

		if len(containers) > 0 {
			container := &containers[len(containers)-1]
			if container.object && container.expectingKey {
				if _, ok := token.(string); !ok {
					return errors.New("invalid non-string JSON object key")
				}
				container.expectingKey = false
				continue
			}
		}
		if err := startValue(); err != nil {
			return err
		}
		if err := chargeNode(); err != nil {
			return err
		}
		if len(containers) == 0 {
			rootComplete = true
		}
	}
}

// StatusError returns a safe error string for a non-success response. Raw
// response bodies are intentionally excluded because authentication proxies
// and controller errors can echo credentials or authorization headers.
func StatusError(service string, statusCode int) string {
	return fmt.Sprintf("%s API returned HTTP %d", service, statusCode)
}

// ReadResponseBody reads a bounded HTTP response body and reports truncation explicitly.
func ReadResponseBody(body io.Reader) ([]byte, error) {
	limited := &io.LimitedReader{R: body, N: MaxResponseBodySize + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, &ResponseBodyReadError{Err: err}
	}
	if int64(len(data)) > MaxResponseBodySize {
		return nil, fmt.Errorf("%w: limit is %d bytes", ErrResponseBodyTooLarge, MaxResponseBodySize)
	}
	return data, nil
}

// SameOrigin reports whether two URLs have the same scheme, host, and effective port.
func SameOrigin(left, right *url.URL) bool {
	if left == nil || right == nil {
		return false
	}
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Hostname(), right.Hostname()) &&
		effectivePort(left) == effectivePort(right)
}

// SameOriginRedirectPolicy allows normal redirects only within the configured API origin.
// Returning http.ErrUseLastResponse leaves a cross-origin redirect as a regular 3xx
// response, preventing custom authentication headers from being copied to another host.
func SameOriginRedirectPolicy(origin *url.URL) func(*http.Request, []*http.Request) error {
	configuredOrigin := *origin
	return func(req *http.Request, via []*http.Request) error {
		if !SameOrigin(&configuredOrigin, req.URL) {
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
}

// NextLink returns the target of an RFC 8288 Link header entry whose relation
// includes "next". Commas inside the angle-bracket URI or a quoted parameter
// are not entry separators, and relation names are matched exactly.
func NextLink(header string) string {
	for _, part := range splitLinkHeader(header) {
		part = strings.TrimSpace(part)
		start := strings.IndexByte(part, '<')
		if start < 0 {
			continue
		}
		endOffset := strings.IndexByte(part[start+1:], '>')
		if endOffset < 0 {
			continue
		}
		end := start + 1 + endOffset
		if linkHasRelation(part[end+1:], "next") {
			return strings.TrimSpace(part[start+1 : end])
		}
	}
	return ""
}

func splitLinkHeader(header string) []string {
	parts := make([]string, 0, 2)
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
	return append(parts, header[start:])
}

func linkHasRelation(parameters, wanted string) bool {
	for parameter := range strings.SplitSeq(parameters, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "rel") {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		for relation := range strings.FieldsSeq(value) {
			if strings.EqualFold(relation, wanted) {
				return true
			}
		}
	}
	return false
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}
