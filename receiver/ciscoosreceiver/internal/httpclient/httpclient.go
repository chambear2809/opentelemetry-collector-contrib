// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package httpclient contains safety helpers shared by the Cisco REST clients.
package httpclient

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// MaxResponseBodySize is the largest response body accepted by Cisco REST clients.
const MaxResponseBodySize int64 = 16 * 1024 * 1024

// ErrResponseBodyTooLarge is returned when an HTTP response exceeds MaxResponseBodySize.
var ErrResponseBodyTooLarge = errors.New("HTTP response body is too large")

// ReadResponseBody reads a bounded HTTP response body and reports truncation explicitly.
func ReadResponseBody(body io.Reader) ([]byte, error) {
	limited := &io.LimitedReader{R: body, N: MaxResponseBodySize + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read HTTP response body: %w", err)
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
