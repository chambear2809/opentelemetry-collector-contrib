// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package aci

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

func TestClientRetryValidationPreservesExplicitZero(t *testing.T) {
	client, err := NewClient(Config{Endpoint: "https://apic.example.test", Username: "admin", Password: "password", MaxRetries: 0})
	require.NoError(t, err)
	assert.Zero(t, client.retries)
	for _, retries := range []int{-1, httpclient.HardMaxRequestRetries + 1} {
		_, err = NewClient(Config{Endpoint: "https://apic.example.test", Username: "admin", Password: "password", MaxRetries: retries})
		require.ErrorContains(t, err, "invalid apic max retries")
	}
}

func TestClientRetriesIncompleteSuccessfulResponseBody(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token","refreshTimeoutSeconds":"600"}}}]}`))
			return
		}
		if requests.Add(1) == 1 {
			w.Header().Set("Content-Length", "100")
			w.Header().Set("Retry-After", "0")
			_, _ = w.Write([]byte(`{"imdata":`))
			return
		}
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", MaxRetries: 1})
	require.NoError(t, err)
	objects, err := client.List(t.Context(), "test.list", "/api/test.json", nil, 10)
	require.NoError(t, err)
	assert.Empty(t, objects)
	assert.Equal(t, int64(2), requests.Load())
}

func TestClientPreservesStatusAndReadErrorForIncompleteNonAuthenticationResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token","refreshTimeoutSeconds":"600"}}}]}`))
			return
		}
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"imdata":`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", MaxRetries: 0})
	require.NoError(t, err)
	_, err = client.List(t.Context(), "test.list", "/api/test.json", nil, 10)
	require.Error(t, err)
	assert.True(t, httpclient.IsResponseBodyReadError(err))
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusTeapot, apiErr.StatusCode)
}

func TestClientRetriesIncompleteSuccessfulLoginBodyWithoutAPIError(t *testing.T) {
	var logins atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			if logins.Add(1) == 1 {
				w.Header().Set("Content-Length", "100")
				_, _ = w.Write([]byte(`{"imdata":`))
				return
			}
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token","refreshTimeoutSeconds":"600"}}}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", MaxRetries: 1})
	require.NoError(t, err)
	var stats []RequestStat
	client.OnRequest = func(stat RequestStat) {
		stats = append(stats, stat)
	}
	_, err = client.List(t.Context(), "test.list", "/api/test.json", nil, 10)
	require.NoError(t, err)
	assert.Equal(t, int64(2), logins.Load())
	require.NotEmpty(t, stats)
	assert.Equal(t, "aaaLogin", stats[0].Operation)
	assert.Equal(t, "error", stats[0].Outcome)
	assert.Equal(t, http.StatusOK, stats[0].StatusCode)
	assert.True(t, httpclient.IsResponseBodyReadError(stats[0].Err))
	var apiErr *APIError
	assert.NotErrorAs(t, stats[0].Err, &apiErr, "a truncated 2xx response must not masquerade as an API status error")
}

func TestClientRetriesTransientLoginStatuses(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusNotImplemented, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var logins atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/aaaLogin.json" {
					if logins.Add(1) == 1 {
						w.Header().Set("Retry-After", "0")
						http.Error(w, "temporary login failure", status)
						return
					}
					_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token","refreshTimeoutSeconds":"600"}}}]}`))
					return
				}
				_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
			}))
			defer server.Close()

			client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", MaxRetries: 1})
			require.NoError(t, err)
			_, err = client.List(t.Context(), "test.list", "/api/test.json", nil, 10)
			require.NoError(t, err)
			assert.Equal(t, int64(2), logins.Load())
		})
	}
}

func TestClientRetriesLoginTransportFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token","refreshTimeoutSeconds":"600"}}}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", MaxRetries: 1})
	require.NoError(t, err)
	transport := &failOnceLoginTransport{next: client.client.Transport}
	client.client.Transport = transport

	_, err = client.List(t.Context(), "test.list", "/api/test.json", nil, 10)
	require.NoError(t, err)
	assert.Equal(t, int64(2), transport.attempts.Load())
}

func TestClientDoesNotRetryRejectedLogin(t *testing.T) {
	var logins atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			logins.Add(1)
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", MaxRetries: 3})
	require.NoError(t, err)
	_, err = client.List(t.Context(), "test.list", "/api/test.json", nil, 10)
	require.ErrorContains(t, err, "HTTP 401")
	assert.Equal(t, int64(1), logins.Load())
}

func TestClientIncompleteUnauthorizedLoginPreservesStatusAndEntersBackoff(t *testing.T) {
	var logins atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/aaaLogin.json" {
			http.NotFound(w, r)
			return
		}
		logins.Add(1)
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"imdata":`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", MaxRetries: 3})
	require.NoError(t, err)
	for range 2 {
		_, err = client.List(t.Context(), "test.list", "/api/test.json", nil, 10)
		require.Error(t, err)
		assert.True(t, httpclient.IsResponseBodyReadError(err))
		var apiErr *APIError
		require.ErrorAs(t, err, &apiErr)
		assert.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
		assert.True(t, authenticationRejected(err))
	}

	assert.Equal(t, int64(1), logins.Load(), "the second request must use authentication backoff")
	client.tokenMu.Lock()
	assert.Empty(t, client.token)
	assert.Equal(t, 1, client.authFailures)
	lastAuthErr := client.lastAuthErr
	client.tokenMu.Unlock()
	assert.True(t, httpclient.IsResponseBodyReadError(lastAuthErr))
	var apiErr *APIError
	require.ErrorAs(t, lastAuthErr, &apiErr)
	assert.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
}

func TestClientLoginCookieAndClassDecode(t *testing.T) {
	var logins atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			logins.Add(1)
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token","refreshTimeoutSeconds":"600"}}}]}`))
			return
		}
		assert.Equal(t, "/api/class/fabricNode.json", r.URL.Path)
		assert.Equal(t, "1", r.URL.Query().Get("page-size"))
		assert.Equal(t, "0", r.URL.Query().Get("page"))
		cookie, err := r.Cookie("APIC-cookie")
		if !assert.NoError(t, err) {
			http.Error(w, "missing authentication cookie", http.StatusUnauthorized)
			return
		}
		assert.Equal(t, "apic-token", cookie.Value)
		_, _ = w.Write([]byte(`{"totalCount":"1","imdata":[{"fabricNode":{"attributes":{"id":"101","serial":"ABC123","name":"leaf101"}}}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 1,
		PageSize:   25,
	})
	require.NoError(t, err)

	got, err := client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 1)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "fabricNode", got[0]["aci.class"])
	assert.Equal(t, "ABC123", got[0]["serial"])
	assert.Equal(t, int64(1), logins.Load())
}

func TestParseAuthSessionTimeout(t *testing.T) {
	start := time.Date(2026, time.July, 19, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name        string
		className   string
		timeoutJSON string
		parse       func([]byte) (authSession, error)
		wantTimeout time.Duration
	}{
		{name: "login aaaLogin string timeout", className: "aaaLogin", timeoutJSON: `"300"`, parse: parseLoginSession, wantTimeout: 5 * time.Minute},
		{name: "login accepts aaaRefresh envelope", className: "aaaRefresh", timeoutJSON: `120`, parse: parseLoginSession, wantTimeout: 2 * time.Minute},
		{name: "refresh aaaRefresh numeric timeout", className: "aaaRefresh", timeoutJSON: `120`, parse: func(body []byte) (authSession, error) {
			return parseRefreshSession(body, 10*time.Minute)
		}, wantTimeout: 2 * time.Minute},
		{name: "refresh accepts documented aaaLogin zero timeout", className: "aaaLogin", timeoutJSON: `"0"`, parse: func(body []byte) (authSession, error) {
			return parseRefreshSession(body, 10*time.Minute)
		}, wantTimeout: 10 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"imdata":[{%q:{"attributes":{"token":"token-1","refreshTimeoutSeconds":%s}}}]}`, tt.className, tt.timeoutJSON)
			session, err := tt.parse([]byte(body))
			require.NoError(t, err)
			assert.Equal(t, "token-1", session.token)
			assert.Equal(t, tt.wantTimeout, session.refreshTimeout)
			assert.Equal(t, start.Add(tt.wantTimeout/2), safeRefreshDeadline(start, session.refreshTimeout))
		})
	}

	boundary, err := parseLoginSession([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"token-1","refreshTimeoutSeconds":"9223372036"}}}]}`))
	require.NoError(t, err)
	assert.Equal(t, time.Duration(9223372036)*time.Second, boundary.refreshTimeout)
	assert.Equal(t, start.Add(boundary.refreshTimeout/2), safeRefreshDeadline(start, boundary.refreshTimeout))

	for _, tt := range []struct {
		name string
		body string
	}{
		{name: "missing", body: `{"imdata":[{"aaaLogin":{"attributes":{"token":"token-1"}}}]}`},
		{name: "zero", body: `{"imdata":[{"aaaLogin":{"attributes":{"token":"token-1","refreshTimeoutSeconds":"0"}}}]}`},
		{name: "negative", body: `{"imdata":[{"aaaLogin":{"attributes":{"token":"token-1","refreshTimeoutSeconds":"-1"}}}]}`},
		{name: "invalid", body: `{"imdata":[{"aaaLogin":{"attributes":{"token":"token-1","refreshTimeoutSeconds":"soon"}}}]}`},
		{name: "overflow", body: `{"imdata":[{"aaaLogin":{"attributes":{"token":"token-1","refreshTimeoutSeconds":"9223372037"}}}]}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, parseErr := parseLoginSession([]byte(tt.body))
			require.ErrorContains(t, parseErr, "invalid refreshTimeoutSeconds")
		})
	}

	_, err = parseRefreshSession([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"token-1","refreshTimeoutSeconds":"0"}}}]}`), 0)
	require.ErrorContains(t, err, "invalid refreshTimeoutSeconds")
}

func TestClientRefreshRejectionFallsBackToOneLoginForEstablishedSession(t *testing.T) {
	var refreshes atomic.Int64
	var logins atomic.Int64
	var dataRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/aaaRefresh.json":
			refreshes.Add(1)
			cookie, err := r.Cookie("APIC-cookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			assert.Equal(t, "expired-token", cookie.Value)
			writeAPICError(w, http.StatusForbidden, "Token was invalid (Error: Token timeout)")
		case "/api/aaaLogin.json":
			logins.Add(1)
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"login-replacement","refreshTimeoutSeconds":"600"}}}]}`))
		default:
			dataRequests.Add(1)
			cookie, err := r.Cookie("APIC-cookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			assert.Equal(t, "login-replacement", cookie.Value)
			_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 0})
	require.NoError(t, err)
	client.tokenMu.Lock()
	client.token = "expired-token"
	client.refreshTimeout = 10 * time.Minute
	client.refreshDeadline = time.Now().Add(-time.Second)
	client.tokenAccepted = true
	client.tokenGeneration = 1
	client.tokenMu.Unlock()

	_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(1), refreshes.Load())
	assert.Equal(t, int64(1), logins.Load())
	assert.Equal(t, int64(1), dataRequests.Load())
	client.tokenMu.Lock()
	assert.Equal(t, "login-replacement", client.token)
	assert.True(t, client.tokenAccepted)
	assert.Zero(t, client.authFailures)
	client.tokenMu.Unlock()
}

func TestClientIncompleteUnauthorizedRefreshForcesOneReplacementLogin(t *testing.T) {
	var refreshes atomic.Int64
	var logins atomic.Int64
	var dataRequests atomic.Int64
	var staleDataRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/aaaRefresh.json":
			refreshes.Add(1)
			cookie, err := r.Cookie("APIC-cookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			assert.Equal(t, "expiring-token", cookie.Value)
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"imdata":`))
		case "/api/aaaLogin.json":
			logins.Add(1)
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"login-replacement","refreshTimeoutSeconds":"600"}}}]}`))
		default:
			dataRequests.Add(1)
			cookie, err := r.Cookie("APIC-cookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			if cookie.Value == "expiring-token" {
				staleDataRequests.Add(1)
				writeAPICError(w, http.StatusUnauthorized, "Token was invalid (Error: Token timeout)")
				return
			}
			assert.Equal(t, "login-replacement", cookie.Value)
			_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 3})
	require.NoError(t, err)
	var refreshErr error
	client.OnRequest = func(stat RequestStat) {
		if stat.Operation == "aaaRefresh" && stat.Outcome == "error" {
			refreshErr = stat.Err
		}
	}
	seedProactiveRefreshAcceptedSession(client)

	_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(1), refreshes.Load())
	assert.Equal(t, int64(1), logins.Load())
	assert.Equal(t, int64(1), dataRequests.Load())
	assert.Zero(t, staleDataRequests.Load(), "the rejected refresh generation must be retired before a data request")
	assert.True(t, httpclient.IsResponseBodyReadError(refreshErr))
	var apiErr *APIError
	require.ErrorAs(t, refreshErr, &apiErr)
	assert.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
	assert.True(t, authenticationRejected(refreshErr))
	client.tokenMu.Lock()
	assert.Equal(t, "login-replacement", client.token)
	assert.Equal(t, uint64(2), client.tokenGeneration)
	assert.True(t, client.tokenAccepted)
	assert.Zero(t, client.authFailures)
	assert.Zero(t, client.refreshFailures)
	client.tokenMu.Unlock()
}

func TestClientRejectedRefreshOfUnacceptedSessionEntersBackoff(t *testing.T) {
	var refreshes atomic.Int64
	var logins atomic.Int64
	var dataRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/aaaRefresh.json":
			refreshes.Add(1)
			http.Error(w, "rejected", http.StatusUnauthorized)
		case "/api/aaaLogin.json":
			logins.Add(1)
			http.Error(w, "unexpected login", http.StatusInternalServerError)
		default:
			dataRequests.Add(1)
			_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 0})
	require.NoError(t, err)
	client.tokenMu.Lock()
	client.token = "unaccepted-token"
	client.refreshTimeout = 10 * time.Minute
	client.refreshDeadline = time.Now().Add(-time.Second)
	client.tokenGeneration = 1
	client.tokenMu.Unlock()

	for range 2 {
		_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
		require.ErrorContains(t, err, "HTTP 401")
	}
	assert.Equal(t, int64(1), refreshes.Load())
	assert.Zero(t, logins.Load())
	assert.Zero(t, dataRequests.Load())
	client.tokenMu.Lock()
	assert.Empty(t, client.token)
	assert.Equal(t, 1, client.authFailures)
	client.tokenMu.Unlock()
}

func TestClientProactivelyRefreshesSessionAndUsesReplacementToken(t *testing.T) {
	var logins atomic.Int64
	var refreshes atomic.Int64
	var dataRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/aaaLogin.json":
			logins.Add(1)
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"login-token","refreshTimeoutSeconds":"600"}}}]}`))
		case "/api/aaaRefresh.json":
			refreshes.Add(1)
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Zero(t, r.ContentLength)
			cookie, err := r.Cookie("APIC-cookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			assert.Equal(t, "login-token", cookie.Value)
			// Cisco's documented successful refresh fixture uses aaaLogin and zero;
			// the client must retain the prior positive timeout.
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"replacement-token","refreshTimeoutSeconds":"0"}}}]}`))
		default:
			request := dataRequests.Add(1)
			cookie, err := r.Cookie("APIC-cookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			if request == 1 {
				assert.Equal(t, "login-token", cookie.Value)
			} else {
				assert.Equal(t, "replacement-token", cookie.Value)
			}
			_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 0})
	require.NoError(t, err)
	_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.NoError(t, err)

	client.tokenMu.Lock()
	client.refreshDeadline = time.Now().Add(-time.Second)
	client.tokenMu.Unlock()
	beforeRefresh := time.Now()
	_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.NoError(t, err)
	afterRefresh := time.Now()

	assert.Equal(t, int64(1), logins.Load())
	assert.Equal(t, int64(1), refreshes.Load())
	assert.Equal(t, int64(2), dataRequests.Load())
	client.tokenMu.Lock()
	assert.Equal(t, "replacement-token", client.token)
	assert.Equal(t, 10*time.Minute, client.refreshTimeout)
	assert.False(t, client.refreshDeadline.Before(beforeRefresh.Add(5*time.Minute)))
	assert.False(t, client.refreshDeadline.After(afterRefresh.Add(5*time.Minute)))
	assert.True(t, client.tokenAccepted)
	client.tokenMu.Unlock()
}

func TestClientAuthorizationDeniedPreservesAcceptedSession(t *testing.T) {
	var logins atomic.Int64
	var deniedRequests atomic.Int64
	var authorizedRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/aaaLogin.json":
			logins.Add(1)
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"rbac-token","refreshTimeoutSeconds":"600"}}}]}`))
		case "/api/denied.json":
			deniedRequests.Add(1)
			cookie, err := r.Cookie("APIC-cookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			assert.Equal(t, "rbac-token", cookie.Value)
			writeAPICError(w, http.StatusForbidden, "User does not have permission to access this managed object")
		case "/api/authorized.json":
			authorizedRequests.Add(1)
			cookie, err := r.Cookie("APIC-cookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			assert.Equal(t, "rbac-token", cookie.Value)
			_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 0})
	require.NoError(t, err)
	for range 2 {
		_, err = client.List(t.Context(), "test.denied", "/api/denied.json", nil, 10)
		require.ErrorContains(t, err, "HTTP 403")
	}

	client.tokenMu.Lock()
	assert.Equal(t, "rbac-token", client.token)
	assert.True(t, client.tokenAccepted, "a parsed RBAC denial proves the token authenticated")
	assert.Zero(t, client.authFailures)
	client.tokenMu.Unlock()

	_, err = client.List(t.Context(), "test.authorized", "/api/authorized.json", nil, 10)
	require.NoError(t, err)
	assert.Equal(t, int64(1), logins.Load())
	assert.Equal(t, int64(2), deniedRequests.Load())
	assert.Equal(t, int64(1), authorizedRequests.Load())
}

func TestClientUnauthorizedPrivilegeDeniedPreservesAcceptedSession(t *testing.T) {
	var logins atomic.Int64
	var authorizedRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/aaaLogin.json":
			logins.Add(1)
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"privileged-token","refreshTimeoutSeconds":"600"}}}]}`))
		case "/api/denied.json":
			writeAPICError(w, http.StatusUnauthorized, "User has insufficient privileges to read this managed object")
		case "/api/authorized.json":
			authorizedRequests.Add(1)
			cookie, err := r.Cookie("APIC-cookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			assert.Equal(t, "privileged-token", cookie.Value)
			_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 0})
	require.NoError(t, err)
	_, err = client.List(t.Context(), "test.denied", "/api/denied.json", nil, 10)
	require.ErrorContains(t, err, "HTTP 401")
	_, err = client.List(t.Context(), "test.authorized", "/api/authorized.json", nil, 10)
	require.NoError(t, err)

	assert.Equal(t, int64(1), logins.Load())
	assert.Equal(t, int64(1), authorizedRequests.Load())
	client.tokenMu.Lock()
	assert.Equal(t, "privileged-token", client.token)
	assert.Equal(t, uint64(1), client.tokenGeneration)
	assert.True(t, client.tokenAccepted)
	assert.Zero(t, client.authFailures)
	client.tokenMu.Unlock()
}

func TestClientAuthorizationDeniedAllowsRefreshRejectionRecovery(t *testing.T) {
	var logins atomic.Int64
	var refreshes atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/aaaLogin.json":
			token := fmt.Sprintf("token-%d", logins.Add(1))
			_, _ = fmt.Fprintf(w, `{"imdata":[{"aaaLogin":{"attributes":{"token":%q,"refreshTimeoutSeconds":"600"}}}]}`, token)
		case "/api/aaaRefresh.json":
			refreshes.Add(1)
			cookie, err := r.Cookie("APIC-cookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			assert.Equal(t, "token-1", cookie.Value)
			http.Error(w, "expired", http.StatusUnauthorized)
		case "/api/denied.json":
			writeAPICError(w, http.StatusForbidden, "User is not authorized for this security domain")
		case "/api/authorized.json":
			cookie, err := r.Cookie("APIC-cookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			assert.Equal(t, "token-2", cookie.Value)
			_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 0})
	require.NoError(t, err)
	_, err = client.List(t.Context(), "test.denied", "/api/denied.json", nil, 10)
	require.ErrorContains(t, err, "HTTP 403")
	client.tokenMu.Lock()
	require.True(t, client.tokenAccepted)
	client.refreshDeadline = time.Now().Add(-time.Second)
	client.tokenMu.Unlock()

	_, err = client.List(t.Context(), "test.authorized", "/api/authorized.json", nil, 10)
	require.NoError(t, err)
	assert.Equal(t, int64(1), refreshes.Load())
	assert.Equal(t, int64(2), logins.Load())
	client.tokenMu.Lock()
	assert.Equal(t, "token-2", client.token)
	assert.True(t, client.tokenAccepted)
	assert.Zero(t, client.authFailures)
	client.tokenMu.Unlock()
}

func TestClientConcurrentRequestsShareSessionRefresh(t *testing.T) {
	const callers = 12
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var startedOnce sync.Once
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseRefresh) }) }
	var refreshes atomic.Int64
	var dataRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaRefresh.json" {
			refreshes.Add(1)
			cookie, err := r.Cookie("APIC-cookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			assert.Equal(t, "expiring-token", cookie.Value)
			startedOnce.Do(func() { close(refreshStarted) })
			<-releaseRefresh
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"shared-replacement","refreshTimeoutSeconds":"600"}}}]}`))
			return
		}
		if r.URL.Path == "/api/aaaLogin.json" {
			http.Error(w, "unexpected login", http.StatusInternalServerError)
			return
		}
		cookie, err := r.Cookie("APIC-cookie")
		if !assert.NoError(t, err) {
			http.Error(w, "missing cookie", http.StatusUnauthorized)
			return
		}
		if cookie.Value != "shared-replacement" {
			http.Error(w, "wrong replacement token", http.StatusUnauthorized)
			return
		}
		dataRequests.Add(1)
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
	}))
	defer server.Close()
	defer release()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: 5 * time.Second, MaxRetries: 0})
	require.NoError(t, err)
	client.tokenMu.Lock()
	client.token = "expiring-token"
	client.refreshTimeout = 10 * time.Minute
	client.refreshDeadline = time.Now().Add(-time.Second)
	client.tokenAccepted = true
	client.tokenGeneration = 1
	client.tokenMu.Unlock()

	start := make(chan struct{})
	errs := make(chan error, callers)
	var workers sync.WaitGroup
	for range callers {
		workers.Go(func() {
			<-start
			_, requestErr := client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
			errs <- requestErr
		})
	}
	close(start)
	select {
	case <-refreshStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for APIC session refresh")
	}
	release()
	workers.Wait()
	close(errs)
	for requestErr := range errs {
		require.NoError(t, requestErr)
	}
	assert.Equal(t, int64(1), refreshes.Load())
	assert.Equal(t, int64(callers), dataRequests.Load())
}

func TestClientJoinedRefreshGenerationAccounting(t *testing.T) {
	for _, tt := range []struct {
		name             string
		refreshReplaces  bool
		wantJoinedError  bool
		wantLogins       int64
		wantRequests     int64
		wantToken        string
		wantAuthFailures int
	}{
		{
			name:            "transient refresh failure replaces rejected generation",
			wantLogins:      1,
			wantRequests:    2,
			wantToken:       "login-replacement",
			refreshReplaces: false,
		},
		{
			name:             "replacement generation consumes recovery",
			refreshReplaces:  true,
			wantJoinedError:  true,
			wantRequests:     2,
			wantToken:        "",
			wantAuthFailures: 1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			firstRequestStarted := make(chan struct{})
			releaseFirstRequest := make(chan struct{})
			refreshStarted := make(chan struct{})
			releaseRefresh := make(chan struct{})
			replacementRequestStarted := make(chan struct{})
			releaseReplacementRequest := make(chan struct{})
			var firstRequestStartedOnce sync.Once
			var refreshStartedOnce sync.Once
			var replacementRequestStartedOnce sync.Once
			var releaseFirstOnce sync.Once
			var releaseRefreshOnce sync.Once
			var releaseReplacementOnce sync.Once
			releaseFirst := func() { releaseFirstOnce.Do(func() { close(releaseFirstRequest) }) }
			releaseAuth := func() { releaseRefreshOnce.Do(func() { close(releaseRefresh) }) }
			releaseReplacement := func() { releaseReplacementOnce.Do(func() { close(releaseReplacementRequest) }) }
			var refreshes atomic.Int64
			var logins atomic.Int64
			var joinedRequests atomic.Int64

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/aaaRefresh.json":
					refreshes.Add(1)
					refreshStartedOnce.Do(func() { close(refreshStarted) })
					select {
					case <-releaseRefresh:
					case <-r.Context().Done():
						return
					}
					if tt.refreshReplaces {
						_, _ = w.Write([]byte(`{"imdata":[{"aaaRefresh":{"attributes":{"token":"refresh-replacement","refreshTimeoutSeconds":"600"}}}]}`))
						return
					}
					http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
				case "/api/aaaLogin.json":
					logins.Add(1)
					token := "login-replacement"
					if tt.refreshReplaces {
						token = "unexpected-second-login"
					}
					_, _ = fmt.Fprintf(w, `{"imdata":[{"aaaLogin":{"attributes":{"token":%q,"refreshTimeoutSeconds":"600"}}}]}`, token)
				case "/api/joined.json":
					joinedRequests.Add(1)
					cookie, err := r.Cookie("APIC-cookie")
					if !assert.NoError(t, err) {
						http.Error(w, "missing cookie", http.StatusUnauthorized)
						return
					}
					switch cookie.Value {
					case "expiring-token":
						firstRequestStartedOnce.Do(func() { close(firstRequestStarted) })
						select {
						case <-releaseFirstRequest:
						case <-r.Context().Done():
							return
						}
						writeAPICError(w, http.StatusUnauthorized, "Token was invalid (Error: Token timeout)")
					case "refresh-replacement":
						replacementRequestStartedOnce.Do(func() { close(replacementRequestStarted) })
						select {
						case <-releaseReplacementRequest:
						case <-r.Context().Done():
							return
						}
						writeAPICError(w, http.StatusUnauthorized, "Token was invalid (Error: Token timeout)")
					case "login-replacement", "unexpected-second-login":
						_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
					default:
						http.Error(w, "unexpected token", http.StatusUnauthorized)
					}
				case "/api/owner.json":
					cookie, err := r.Cookie("APIC-cookie")
					if !assert.NoError(t, err) {
						http.Error(w, "missing cookie", http.StatusUnauthorized)
						return
					}
					if tt.refreshReplaces {
						assert.Equal(t, "refresh-replacement", cookie.Value)
					} else {
						assert.Equal(t, "login-replacement", cookie.Value)
					}
					_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			defer releaseFirst()
			defer releaseAuth()
			defer releaseReplacement()

			client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: 5 * time.Second, MaxRetries: 0})
			require.NoError(t, err)
			seedProactiveRefreshAcceptedSession(client)
			client.tokenMu.Lock()
			client.refreshDeadline = time.Now().Add(5 * time.Minute)
			client.tokenMu.Unlock()

			joinedErr := make(chan error, 1)
			go func() {
				_, requestErr := client.List(t.Context(), "joined.data", "/api/joined.json", nil, 10)
				joinedErr <- requestErr
			}()
			select {
			case <-firstRequestStarted:
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for the G1 data request")
			}

			client.tokenMu.Lock()
			client.refreshDeadline = time.Now().Add(-time.Second)
			client.tokenMu.Unlock()
			ownerErr := make(chan error, 1)
			go func() {
				_, requestErr := client.List(t.Context(), "owner.data", "/api/owner.json", nil, 10)
				ownerErr <- requestErr
			}()
			select {
			case <-refreshStarted:
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for proactive refresh")
			}
			client.tokenMu.Lock()
			rejectionSignal := client.generationRejectedSignal
			client.tokenMu.Unlock()
			require.NotNil(t, rejectionSignal)

			releaseFirst()
			select {
			case <-rejectionSignal:
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for the shared G1 rejection signal")
			}
			releaseAuth()
			if tt.refreshReplaces {
				select {
				case <-replacementRequestStarted:
				case <-time.After(5 * time.Second):
					t.Fatal("timed out waiting for the G2 data request")
				}
				require.NoError(t, <-ownerErr)
				releaseReplacement()
			} else {
				require.NoError(t, <-ownerErr)
			}

			requestErr := <-joinedErr
			if tt.wantJoinedError {
				require.ErrorContains(t, requestErr, "HTTP 401")
			} else {
				require.NoError(t, requestErr)
			}
			assert.Equal(t, int64(1), refreshes.Load())
			assert.Equal(t, tt.wantLogins, logins.Load())
			assert.Equal(t, tt.wantRequests, joinedRequests.Load())
			client.tokenMu.Lock()
			assert.Equal(t, tt.wantToken, client.token)
			assert.Equal(t, tt.wantAuthFailures, client.authFailures)
			client.tokenMu.Unlock()
		})
	}
}

func TestClientJoinedRefreshReplacementFailureEntersSharedBackoff(t *testing.T) {
	firstRequestStarted := make(chan struct{})
	releaseFirstRequest := make(chan struct{})
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	loginStarted := make(chan struct{})
	releaseLogin := make(chan struct{})
	var firstRequestStartedOnce sync.Once
	var refreshStartedOnce sync.Once
	var loginStartedOnce sync.Once
	var releaseFirstOnce sync.Once
	var releaseRefreshOnce sync.Once
	var releaseLoginOnce sync.Once
	releaseFirst := func() { releaseFirstOnce.Do(func() { close(releaseFirstRequest) }) }
	releaseAuthRefresh := func() { releaseRefreshOnce.Do(func() { close(releaseRefresh) }) }
	releaseAuthLogin := func() { releaseLoginOnce.Do(func() { close(releaseLogin) }) }
	var refreshes atomic.Int64
	var logins atomic.Int64
	var dataRequests atomic.Int64
	var ownerRequests atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/aaaRefresh.json":
			refreshes.Add(1)
			refreshStartedOnce.Do(func() { close(refreshStarted) })
			select {
			case <-releaseRefresh:
			case <-r.Context().Done():
				return
			}
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		case "/api/aaaLogin.json":
			logins.Add(1)
			loginStartedOnce.Do(func() { close(loginStarted) })
			select {
			case <-releaseLogin:
			case <-r.Context().Done():
				return
			}
			http.Error(w, "replacement login rejected", http.StatusUnauthorized)
		case "/api/joined.json":
			dataRequests.Add(1)
			cookie, err := r.Cookie("APIC-cookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			assert.Equal(t, "expiring-token", cookie.Value)
			firstRequestStartedOnce.Do(func() { close(firstRequestStarted) })
			select {
			case <-releaseFirstRequest:
			case <-r.Context().Done():
				return
			}
			writeAPICError(w, http.StatusUnauthorized, "Token was invalid (Error: Token timeout)")
		case "/api/owner.json":
			ownerRequests.Add(1)
			http.Error(w, "unexpected data request", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	defer releaseFirst()
	defer releaseAuthRefresh()
	defer releaseAuthLogin()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: 5 * time.Second, MaxRetries: 0})
	require.NoError(t, err)
	seedProactiveRefreshAcceptedSession(client)
	client.tokenMu.Lock()
	client.refreshDeadline = time.Now().Add(5 * time.Minute)
	client.tokenMu.Unlock()

	joinedErr := make(chan error, 1)
	go func() {
		_, requestErr := client.List(t.Context(), "joined.data", "/api/joined.json", nil, 10)
		joinedErr <- requestErr
	}()
	select {
	case <-firstRequestStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the G1 data request")
	}

	client.tokenMu.Lock()
	client.refreshDeadline = time.Now().Add(-time.Second)
	client.tokenMu.Unlock()
	ownerErr := make(chan error, 1)
	go func() {
		_, requestErr := client.List(t.Context(), "owner.data", "/api/owner.json", nil, 10)
		ownerErr <- requestErr
	}()
	select {
	case <-refreshStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for proactive refresh")
	}
	client.tokenMu.Lock()
	rejectionSignal := client.generationRejectedSignal
	client.tokenMu.Unlock()
	require.NotNil(t, rejectionSignal)

	releaseFirst()
	select {
	case <-rejectionSignal:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the shared G1 rejection signal")
	}
	releaseAuthRefresh()
	select {
	case <-loginStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for replacement login")
	}
	releaseAuthLogin()

	require.ErrorContains(t, <-ownerErr, "HTTP 401")
	require.ErrorContains(t, <-joinedErr, "HTTP 401")
	_, err = client.List(t.Context(), "cached.data", "/api/owner.json", nil, 10)
	require.ErrorContains(t, err, "HTTP 401")
	assert.Equal(t, int64(1), refreshes.Load())
	assert.Equal(t, int64(1), logins.Load())
	assert.Equal(t, int64(1), dataRequests.Load(), "the rejected G1 must not be resent")
	assert.Zero(t, ownerRequests.Load())
	client.tokenMu.Lock()
	assert.Empty(t, client.token)
	assert.Equal(t, 1, client.authFailures)
	assert.False(t, client.generationRejected)
	assert.Nil(t, client.generationRejectedSignal)
	assert.Nil(t, client.loginInflight)
	client.tokenMu.Unlock()
}

func TestClientJoinedRefreshCanceledOwnerHandsOffRecovery(t *testing.T) {
	firstRequestStarted := make(chan struct{})
	releaseFirstRequest := make(chan struct{})
	refreshStarted := make(chan struct{})
	refreshCanceled := make(chan struct{})
	releaseRefresh := make(chan struct{})
	loginStarted := make(chan struct{})
	releaseLogin := make(chan struct{})
	var firstRequestStartedOnce sync.Once
	var refreshStartedOnce sync.Once
	var refreshCanceledOnce sync.Once
	var loginStartedOnce sync.Once
	var releaseFirstOnce sync.Once
	var releaseRefreshOnce sync.Once
	var releaseLoginOnce sync.Once
	releaseFirst := func() { releaseFirstOnce.Do(func() { close(releaseFirstRequest) }) }
	releaseAuthRefresh := func() { releaseRefreshOnce.Do(func() { close(releaseRefresh) }) }
	releaseAuthLogin := func() { releaseLoginOnce.Do(func() { close(releaseLogin) }) }
	var refreshes atomic.Int64
	var logins atomic.Int64
	var joinedRequests atomic.Int64
	var ownerRequests atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/aaaRefresh.json":
			refreshes.Add(1)
			refreshStartedOnce.Do(func() { close(refreshStarted) })
			select {
			case <-releaseRefresh:
				http.Error(w, "unexpected refresh release", http.StatusServiceUnavailable)
			case <-r.Context().Done():
				refreshCanceledOnce.Do(func() { close(refreshCanceled) })
			}
		case "/api/aaaLogin.json":
			logins.Add(1)
			loginStartedOnce.Do(func() { close(loginStarted) })
			select {
			case <-releaseLogin:
			case <-r.Context().Done():
				return
			}
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"waiter-replacement","refreshTimeoutSeconds":"600"}}}]}`))
		case "/api/joined.json":
			joinedRequests.Add(1)
			cookie, err := r.Cookie("APIC-cookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			switch cookie.Value {
			case "expiring-token":
				firstRequestStartedOnce.Do(func() { close(firstRequestStarted) })
				select {
				case <-releaseFirstRequest:
				case <-r.Context().Done():
					return
				}
				writeAPICError(w, http.StatusUnauthorized, "Token was invalid (Error: Token timeout)")
			case "waiter-replacement":
				_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
			default:
				http.Error(w, "unexpected token", http.StatusUnauthorized)
			}
		case "/api/owner.json":
			ownerRequests.Add(1)
			http.Error(w, "unexpected owner data request", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	defer releaseFirst()
	defer releaseAuthRefresh()
	defer releaseAuthLogin()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: 5 * time.Second, MaxRetries: 0})
	require.NoError(t, err)
	seedProactiveRefreshAcceptedSession(client)
	client.tokenMu.Lock()
	client.refreshDeadline = time.Now().Add(5 * time.Minute)
	client.tokenMu.Unlock()

	joinedErr := make(chan error, 1)
	go func() {
		_, requestErr := client.List(t.Context(), "joined.data", "/api/joined.json", nil, 10)
		joinedErr <- requestErr
	}()
	select {
	case <-firstRequestStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the G1 data request")
	}

	client.tokenMu.Lock()
	client.refreshDeadline = time.Now().Add(-time.Second)
	client.tokenMu.Unlock()
	ownerCtx, cancelOwner := context.WithCancel(t.Context())
	ownerErr := make(chan error, 1)
	go func() {
		_, requestErr := client.List(ownerCtx, "owner.data", "/api/owner.json", nil, 10)
		ownerErr <- requestErr
	}()
	select {
	case <-refreshStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for proactive refresh")
	}
	client.tokenMu.Lock()
	rejectionSignal := client.generationRejectedSignal
	client.tokenMu.Unlock()
	require.NotNil(t, rejectionSignal)

	releaseFirst()
	select {
	case <-rejectionSignal:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the shared G1 rejection signal")
	}
	cancelOwner()
	select {
	case <-refreshCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for canceled refresh")
	}
	require.ErrorIs(t, <-ownerErr, context.Canceled)
	select {
	case <-loginStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for waiter-owned login")
	}
	client.tokenMu.Lock()
	assert.Empty(t, client.token)
	assert.Zero(t, client.authFailures)
	assert.False(t, client.generationRejected)
	assert.Nil(t, client.generationRejectedSignal)
	assert.NotNil(t, client.loginInflight)
	client.tokenMu.Unlock()
	releaseAuthLogin()

	require.NoError(t, <-joinedErr)
	assert.Equal(t, int64(1), refreshes.Load())
	assert.Equal(t, int64(1), logins.Load())
	assert.Equal(t, int64(2), joinedRequests.Load(), "the waiter must move directly from rejected G1 to G2")
	assert.Zero(t, ownerRequests.Load())
	client.tokenMu.Lock()
	assert.Equal(t, "waiter-replacement", client.token)
	assert.True(t, client.tokenAccepted)
	assert.Zero(t, client.authFailures)
	assert.False(t, client.generationRejected)
	assert.NotNil(t, client.generationRejectedSignal)
	assert.Nil(t, client.loginInflight)
	client.tokenMu.Unlock()
}

func TestClientRefreshOwnerCancellationReleasesInflight(t *testing.T) {
	refreshStarted := make(chan struct{})
	var refreshStartedOnce sync.Once
	var refreshes atomic.Int64
	var dataRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/aaaRefresh.json":
			if refreshes.Add(1) == 1 {
				refreshStartedOnce.Do(func() { close(refreshStarted) })
				<-r.Context().Done()
				return
			}
			_, _ = w.Write([]byte(`{"imdata":[{"aaaRefresh":{"attributes":{"token":"replacement-token","refreshTimeoutSeconds":"600"}}}]}`))
		case "/api/aaaLogin.json":
			http.Error(w, "unexpected login", http.StatusInternalServerError)
		default:
			dataRequests.Add(1)
			cookie, err := r.Cookie("APIC-cookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			assert.Equal(t, "replacement-token", cookie.Value)
			_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: 5 * time.Second, MaxRetries: 0})
	require.NoError(t, err)
	seedProactiveRefreshAcceptedSession(client)

	ownerCtx, cancelOwner := context.WithCancel(t.Context())
	ownerErr := make(chan error, 1)
	go func() {
		_, requestErr := client.ListClass(ownerCtx, "fabric.nodes", "fabricNode", nil, 0)
		ownerErr <- requestErr
	}()
	select {
	case <-refreshStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for refresh owner")
	}
	cancelOwner()
	require.ErrorIs(t, <-ownerErr, context.Canceled)

	client.tokenMu.Lock()
	assert.Nil(t, client.loginInflight)
	assert.Equal(t, "expiring-token", client.token)
	assert.Zero(t, client.authFailures)
	client.tokenMu.Unlock()

	_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(2), refreshes.Load())
	assert.Equal(t, int64(1), dataRequests.Load())
}

func TestClientRefreshWaiterCancellationDoesNotCancelOwner(t *testing.T) {
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var refreshStartedOnce sync.Once
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseRefresh) }) }
	var refreshes atomic.Int64
	var dataRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaRefresh.json" {
			refreshes.Add(1)
			refreshStartedOnce.Do(func() { close(refreshStarted) })
			select {
			case <-releaseRefresh:
			case <-r.Context().Done():
				return
			}
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"replacement-token","refreshTimeoutSeconds":"0"}}}]}`))
			return
		}
		if r.URL.Path == "/api/aaaLogin.json" {
			http.Error(w, "unexpected login", http.StatusInternalServerError)
			return
		}
		dataRequests.Add(1)
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
	}))
	defer server.Close()
	defer release()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: 5 * time.Second, MaxRetries: 0})
	require.NoError(t, err)
	seedProactiveRefreshAcceptedSession(client)

	ownerErr := make(chan error, 1)
	go func() {
		_, requestErr := client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
		ownerErr <- requestErr
	}()
	select {
	case <-refreshStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for refresh owner")
	}

	waiterCtx, cancelWaiter := context.WithCancel(t.Context())
	waiterErr := make(chan error, 1)
	client.tokenMu.Lock()
	go func() {
		_, requestErr := client.ListClass(waiterCtx, "fabric.nodes", "fabricNode", nil, 0)
		waiterErr <- requestErr
	}()
	cancelWaiter()
	client.tokenMu.Unlock()
	require.ErrorIs(t, <-waiterErr, context.Canceled)
	assert.Equal(t, int64(1), refreshes.Load())

	release()
	require.NoError(t, <-ownerErr)
	assert.Equal(t, int64(1), refreshes.Load())
	assert.Equal(t, int64(1), dataRequests.Load())
}

func TestClientRefreshRetryBounds(t *testing.T) {
	t.Run("Retry-After is bounded by context deadline", func(t *testing.T) {
		var refreshes atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/aaaRefresh.json" {
				http.Error(w, "unexpected request", http.StatusInternalServerError)
				return
			}
			refreshes.Add(1)
			w.Header().Set("Retry-After", "60")
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		}))
		defer server.Close()

		client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: 5 * time.Second, MaxRetries: 3})
		require.NoError(t, err)
		seedProactiveRefreshAcceptedSession(client)
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		_, err = client.ListClass(ctx, "fabric.nodes", "fabricNode", nil, 0)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, int64(1), refreshes.Load())
	})

	t.Run("attempt budget preserves accepted session", func(t *testing.T) {
		var refreshes atomic.Int64
		var dataRequests atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/aaaRefresh.json" {
				if refreshes.Add(1) <= 3 {
					w.Header().Set("Retry-After", "0")
					http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
					return
				}
				_, _ = w.Write([]byte(`{"imdata":[{"aaaRefresh":{"attributes":{"token":"replacement-token","refreshTimeoutSeconds":"600"}}}]}`))
				return
			}
			cookie, err := r.Cookie("APIC-cookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			request := dataRequests.Add(1)
			if request <= 2 {
				assert.Equal(t, "expiring-token", cookie.Value)
			} else {
				assert.Equal(t, "replacement-token", cookie.Value)
			}
			_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
		}))
		defer server.Close()

		client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: 5 * time.Second, MaxRetries: 2})
		require.NoError(t, err)
		seedProactiveRefreshAcceptedSession(client)
		_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
		require.NoError(t, err)
		assert.Equal(t, int64(3), refreshes.Load())
		_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
		require.NoError(t, err)
		assert.Equal(t, int64(3), refreshes.Load(), "the transient retry window should prevent refresh hammering")
		client.tokenMu.Lock()
		assert.Equal(t, "expiring-token", client.token)
		assert.True(t, client.tokenAccepted)
		assert.Zero(t, client.authFailures)
		assert.Equal(t, 1, client.refreshFailures)
		assert.True(t, client.refreshRetryAt.After(time.Now()))
		client.sessionExpiry = time.Now().Add(-time.Second)
		client.refreshRetryAt = time.Now().Add(-time.Second)
		client.tokenMu.Unlock()

		_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
		require.NoError(t, err)
		assert.Equal(t, int64(4), refreshes.Load())
		assert.Equal(t, int64(3), dataRequests.Load())
		client.tokenMu.Lock()
		assert.Equal(t, "replacement-token", client.token)
		assert.Zero(t, client.refreshFailures)
		client.tokenMu.Unlock()
	})
}

func TestClientExpiredRefreshFailureFallsBackToLogin(t *testing.T) {
	var refreshes atomic.Int64
	var logins atomic.Int64
	var dataRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/aaaRefresh.json":
			refreshes.Add(1)
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		case "/api/aaaLogin.json":
			logins.Add(1)
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"login-replacement","refreshTimeoutSeconds":"600"}}}]}`))
		default:
			dataRequests.Add(1)
			cookie, err := r.Cookie("APIC-cookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			assert.Equal(t, "login-replacement", cookie.Value)
			_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 0})
	require.NoError(t, err)
	seedExpiredAcceptedSession(client)
	_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.NoError(t, err)

	assert.Equal(t, int64(1), refreshes.Load())
	assert.Equal(t, int64(1), logins.Load())
	assert.Equal(t, int64(1), dataRequests.Load())
	client.tokenMu.Lock()
	assert.Equal(t, "login-replacement", client.token)
	assert.True(t, client.tokenAccepted)
	assert.Zero(t, client.authFailures)
	assert.Zero(t, client.refreshFailures)
	client.tokenMu.Unlock()
}

func TestClientExpiredRefreshFailureLoginFailureEntersSharedBackoff(t *testing.T) {
	for _, loginStatus := range []int{http.StatusUnauthorized, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(loginStatus), func(t *testing.T) {
			var refreshes atomic.Int64
			var logins atomic.Int64
			var dataRequests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/aaaRefresh.json":
					refreshes.Add(1)
					http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
				case "/api/aaaLogin.json":
					logins.Add(1)
					http.Error(w, "replacement login failed", loginStatus)
				default:
					dataRequests.Add(1)
					_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
				}
			}))
			defer server.Close()

			client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 0})
			require.NoError(t, err)
			seedExpiredAcceptedSession(client)
			_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
			require.ErrorContains(t, err, fmt.Sprintf("HTTP %d", loginStatus))
			client.tokenMu.Lock()
			assert.Empty(t, client.token)
			assert.Equal(t, uint64(2), client.tokenGeneration)
			assert.Equal(t, 1, client.authFailures)
			client.lastAuthAt = time.Now()
			client.tokenMu.Unlock()
			_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
			require.ErrorContains(t, err, fmt.Sprintf("HTTP %d", loginStatus))

			assert.Equal(t, int64(1), refreshes.Load())
			assert.Equal(t, int64(1), logins.Load())
			assert.Zero(t, dataRequests.Load())
			client.tokenMu.Lock()
			assert.Equal(t, 1, client.authFailures)
			assert.Zero(t, client.refreshFailures)
			assert.Nil(t, client.loginInflight)
			client.tokenMu.Unlock()
		})
	}
}

func TestClientConcurrentExpiredRefreshFailureSharesLogin(t *testing.T) {
	const callers = 12
	loginStarted := make(chan struct{})
	releaseLogin := make(chan struct{})
	var loginStartedOnce sync.Once
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseLogin) }) }
	var refreshes atomic.Int64
	var logins atomic.Int64
	var dataRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/aaaRefresh.json":
			refreshes.Add(1)
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		case "/api/aaaLogin.json":
			logins.Add(1)
			loginStartedOnce.Do(func() { close(loginStarted) })
			select {
			case <-releaseLogin:
			case <-r.Context().Done():
				return
			}
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"shared-login-replacement","refreshTimeoutSeconds":"600"}}}]}`))
		default:
			cookie, err := r.Cookie("APIC-cookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			assert.Equal(t, "shared-login-replacement", cookie.Value)
			dataRequests.Add(1)
			_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
		}
	}))
	defer server.Close()
	defer release()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: 5 * time.Second, MaxRetries: 0})
	require.NoError(t, err)
	seedExpiredAcceptedSession(client)

	start := make(chan struct{})
	errs := make(chan error, callers)
	var workers sync.WaitGroup
	for range callers {
		workers.Go(func() {
			<-start
			_, requestErr := client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
			errs <- requestErr
		})
	}
	close(start)
	select {
	case <-loginStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for expired-session replacement login")
	}
	release()
	workers.Wait()
	close(errs)
	for requestErr := range errs {
		require.NoError(t, requestErr)
	}

	assert.Equal(t, int64(1), refreshes.Load())
	assert.Equal(t, int64(1), logins.Load())
	assert.Equal(t, int64(callers), dataRequests.Load())
}

func TestClientRecoversEstablishedExpiredSessionOnce(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var logins atomic.Int64
			var dataRequests atomic.Int64
			var expireFirst atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/aaaLogin.json" {
					token := fmt.Sprintf("token-%d", logins.Add(1))
					_, _ = fmt.Fprintf(w, `{"imdata":[{"aaaLogin":{"attributes":{"token":%q,"refreshTimeoutSeconds":"600"}}}]}`, token)
					return
				}
				dataRequests.Add(1)
				cookie, err := r.Cookie("APIC-cookie")
				if !assert.NoError(t, err) {
					http.Error(w, "missing cookie", http.StatusUnauthorized)
					return
				}
				if cookie.Value == "token-1" && expireFirst.Load() {
					writeAPICError(w, status, "Token was invalid (Error: Token timeout)")
					return
				}
				assert.Contains(t, []string{"token-1", "token-2"}, cookie.Value)
				_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
			}))
			defer server.Close()

			client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 0})
			require.NoError(t, err)
			_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
			require.NoError(t, err)
			expireFirst.Store(true)

			_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
			require.NoError(t, err)
			assert.Equal(t, int64(2), logins.Load())
			assert.Equal(t, int64(3), dataRequests.Load())
			client.tokenMu.Lock()
			assert.Equal(t, "token-2", client.token)
			assert.True(t, client.tokenAccepted)
			assert.Zero(t, client.authFailures)
			client.tokenMu.Unlock()
		})
	}
}

func TestClientRecoversEstablishedSessionFromIncompleteUnauthorizedResponse(t *testing.T) {
	var logins atomic.Int64
	var dataRequests atomic.Int64
	var expireFirst atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			token := fmt.Sprintf("token-%d", logins.Add(1))
			_, _ = fmt.Fprintf(w, `{"imdata":[{"aaaLogin":{"attributes":{"token":%q,"refreshTimeoutSeconds":"600"}}}]}`, token)
			return
		}
		dataRequests.Add(1)
		cookie, err := r.Cookie("APIC-cookie")
		if !assert.NoError(t, err) {
			http.Error(w, "missing cookie", http.StatusUnauthorized)
			return
		}
		if cookie.Value == "token-1" && expireFirst.Load() {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"imdata":`))
			return
		}
		assert.Contains(t, []string{"token-1", "token-2"}, cookie.Value)
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 0})
	require.NoError(t, err)
	_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.NoError(t, err)
	expireFirst.Store(true)

	_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(2), logins.Load())
	assert.Equal(t, int64(3), dataRequests.Load())
	client.tokenMu.Lock()
	assert.Equal(t, "token-2", client.token)
	assert.True(t, client.tokenAccepted)
	assert.Zero(t, client.authFailures)
	client.tokenMu.Unlock()
}

func TestClientConcurrentStaleUnauthorizedSharesOneReauthentication(t *testing.T) {
	const callers = 2
	allStaleRequests := make(chan struct{})
	allStaleResponses := make(chan struct{})
	var staleRequestOnce sync.Once
	var staleResponseOnce sync.Once
	var logins atomic.Int64
	var staleRequests atomic.Int64
	var staleResponses atomic.Int64
	var replacementRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			login := logins.Add(1)
			if login == 2 {
				select {
				case <-allStaleResponses:
				case <-r.Context().Done():
					return
				}
			}
			_, _ = fmt.Fprintf(w, `{"imdata":[{"aaaLogin":{"attributes":{"token":"token-%d","refreshTimeoutSeconds":"600"}}}]}`, login)
			return
		}

		cookie, err := r.Cookie("APIC-cookie")
		if !assert.NoError(t, err) {
			http.Error(w, "missing cookie", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/api/prime.json" {
			assert.Equal(t, "token-1", cookie.Value)
			_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
			return
		}
		if cookie.Value == "token-1" {
			if staleRequests.Add(1) == callers {
				staleRequestOnce.Do(func() { close(allStaleRequests) })
			}
			select {
			case <-allStaleRequests:
			case <-r.Context().Done():
				return
			}
			http.Error(w, "expired", http.StatusUnauthorized)
			if staleResponses.Add(1) == callers {
				staleResponseOnce.Do(func() { close(allStaleResponses) })
			}
			return
		}
		assert.Equal(t, "token-2", cookie.Value)
		replacementRequests.Add(1)
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: 5 * time.Second, MaxRetries: 0})
	require.NoError(t, err)
	_, err = client.List(t.Context(), "test.prime", "/api/prime.json", nil, 10)
	require.NoError(t, err)

	start := make(chan struct{})
	errs := make(chan error, callers)
	var workers sync.WaitGroup
	for range callers {
		workers.Go(func() {
			<-start
			_, requestErr := client.List(t.Context(), "test.stale", "/api/stale.json", nil, 10)
			errs <- requestErr
		})
	}
	close(start)
	workers.Wait()
	close(errs)
	for requestErr := range errs {
		require.NoError(t, requestErr)
	}

	assert.Equal(t, int64(2), logins.Load(), "stale callers must share one reauthentication")
	assert.Equal(t, int64(callers), staleRequests.Load())
	assert.Equal(t, int64(callers), replacementRequests.Load())
	client.tokenMu.Lock()
	assert.Equal(t, "token-2", client.token)
	assert.True(t, client.tokenAccepted)
	assert.Zero(t, client.authFailures)
	client.tokenMu.Unlock()
}

func TestClientCanceledExpiredSessionRecoveryLetsWaiterTakeOver(t *testing.T) {
	recoveryLoginStarted := make(chan struct{})
	var logins atomic.Int64
	var authorizedRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			login := logins.Add(1)
			_, _ = fmt.Fprintf(w, `{"imdata":[{"aaaLogin":{"attributes":{"token":"token-%d","refreshTimeoutSeconds":"600"}}}]}`, login)
			return
		}

		cookie, err := r.Cookie("APIC-cookie")
		if !assert.NoError(t, err) {
			http.Error(w, "missing cookie", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/prime.json":
			assert.Equal(t, "token-1", cookie.Value)
			_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
		case "/api/stale.json":
			assert.Equal(t, "token-1", cookie.Value)
			http.Error(w, "expired", http.StatusUnauthorized)
		case "/api/authorized.json":
			authorizedRequests.Add(1)
			assert.Equal(t, "token-2", cookie.Value)
			_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: 5 * time.Second, MaxRetries: 0})
	require.NoError(t, err)
	transport := &cancelSecondLoginTransport{next: client.client.Transport, started: recoveryLoginStarted}
	client.client.Transport = transport
	_, err = client.List(t.Context(), "test.prime", "/api/prime.json", nil, 10)
	require.NoError(t, err)

	ownerCtx, cancelOwner := context.WithCancel(t.Context())
	ownerErr := make(chan error, 1)
	go func() {
		_, requestErr := client.List(ownerCtx, "test.stale", "/api/stale.json", nil, 10)
		ownerErr <- requestErr
	}()
	select {
	case <-recoveryLoginStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for recovery login")
	}

	waiterStarted := make(chan struct{})
	waiterErr := make(chan error, 1)
	go func() {
		close(waiterStarted)
		_, requestErr := client.List(t.Context(), "test.authorized", "/api/authorized.json", nil, 10)
		waiterErr <- requestErr
	}()
	<-waiterStarted
	cancelOwner()
	require.ErrorIs(t, <-ownerErr, context.Canceled)
	require.NoError(t, <-waiterErr)

	assert.Equal(t, int64(3), transport.attempts.Load(), "the waiter should take over after the canceled recovery")
	assert.Equal(t, int64(2), logins.Load(), "the canceled recovery must not reach APIC")
	assert.Equal(t, int64(1), authorizedRequests.Load())
	client.tokenMu.Lock()
	assert.Equal(t, "token-2", client.token)
	assert.True(t, client.tokenAccepted)
	assert.Zero(t, client.authFailures)
	client.tokenMu.Unlock()
}

func TestClientExpiredSessionRecoveryIsBounded(t *testing.T) {
	var logins atomic.Int64
	var dataRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			token := fmt.Sprintf("token-%d", logins.Add(1))
			_, _ = fmt.Fprintf(w, `{"imdata":[{"aaaLogin":{"attributes":{"token":%q,"refreshTimeoutSeconds":"600"}}}]}`, token)
			return
		}
		if dataRequests.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
			return
		}
		http.Error(w, "expired", http.StatusUnauthorized)
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 3})
	require.NoError(t, err)
	_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.NoError(t, err)

	_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.ErrorContains(t, err, "HTTP 401")
	assert.Equal(t, int64(2), logins.Load(), "only one inline reauthentication is allowed")
	assert.Equal(t, int64(3), dataRequests.Load(), "only one data request retry is allowed")

	_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.ErrorContains(t, err, "HTTP 401")
	assert.Equal(t, int64(2), logins.Load(), "subsequent requests must honor authentication backoff")
	assert.Equal(t, int64(3), dataRequests.Load())
}

func TestDecodeObjectsPreservesLargeInteger(t *testing.T) {
	objects, total, err := decodeObjects([]byte(`{"totalCount":"1","imdata":[{"ethpmPhysIf":{"attributes":{"bytes":9007199254740993}}}]}`))
	require.NoError(t, err)
	require.Len(t, objects, 1)
	assert.Equal(t, 1, total)
	value, ok := Int64(objects[0], "bytes")
	require.True(t, ok)
	assert.Equal(t, int64(9007199254740993), value)
}

func TestClientSupportsSelfSignedTLSWithInsecureSkipVerify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token","refreshTimeoutSeconds":"600"}}}]}`))
			return
		}
		assert.Equal(t, "/api/class/fabricNode.json", r.URL.Path)
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
	}))
	defer server.Close()

	verifiedClient, err := NewClient(Config{
		Endpoint:   server.URL,
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 0,
	})
	require.NoError(t, err)
	_, err = verifiedClient.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.ErrorContains(t, err, "configure aci.ca_file with the issuing CA (preferred)")
	require.ErrorContains(t, err, "set aci.insecure_skip_verify: true")

	client, err := NewClient(Config{
		Endpoint:           server.URL,
		Username:           "admin",
		Password:           "password",
		Timeout:            time.Second,
		MaxRetries:         1,
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)

	got, err := client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestClientSupportsPrivateCAAndServerName(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token","refreshTimeoutSeconds":"600"}}}]}`))
			return
		}
		assert.Equal(t, "/api/class/fabricNode.json", r.URL.Path)
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
	}))
	defer server.Close()

	certificate := server.Certificate()
	require.NotEmpty(t, certificate.DNSNames)
	caFile := filepath.Join(t.TempDir(), "apic-ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600))
	endpoint := strings.Replace(server.URL, "127.0.0.1", "localhost", 1)

	nameMismatchClient, err := NewClient(Config{
		Endpoint:   endpoint,
		Username:   "admin",
		Password:   "password",
		CAFile:     caFile,
		MaxRetries: 0,
	})
	require.NoError(t, err)
	_, err = nameMismatchClient.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.ErrorContains(t, err, "configure aci.server_name")
	require.ErrorContains(t, err, "certificate SAN")

	client, err := NewClient(Config{
		Endpoint:   endpoint,
		Username:   "admin",
		Password:   "password",
		CAFile:     caFile,
		ServerName: certificate.DNSNames[0],
		MaxRetries: 0,
	})
	require.NoError(t, err)

	transport := client.client.Transport.(*http.Transport)
	require.NotNil(t, transport.TLSClientConfig)
	assert.Equal(t, certificate.DNSNames[0], transport.TLSClientConfig.ServerName)
	require.NotNil(t, transport.TLSClientConfig.RootCAs)

	got, err := client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestClientRejectsInvalidCAFile(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		caFile := filepath.Join(t.TempDir(), "missing-ca.pem")
		_, err := NewClient(Config{
			Endpoint: "https://apic.example.test",
			Username: "admin",
			Password: "password",
			CAFile:   caFile,
		})
		require.ErrorContains(t, err, "read APIC CA file")
		require.ErrorContains(t, err, caFile)
	})

	t.Run("invalid PEM", func(t *testing.T) {
		caFile := filepath.Join(t.TempDir(), "invalid-ca.pem")
		require.NoError(t, os.WriteFile(caFile, []byte("not a certificate"), 0o600))
		_, err := NewClient(Config{
			Endpoint: "https://apic.example.test",
			Username: "admin",
			Password: "password",
			CAFile:   caFile,
		})
		require.ErrorContains(t, err, "aci.ca_file")
		require.ErrorContains(t, err, "did not contain PEM certificates")
	})
}

func TestClientCertificateVerificationFailureIsTerminal(t *testing.T) {
	t.Run("login", func(t *testing.T) {
		client, err := NewClient(Config{
			Endpoint:   "https://apic.example.test",
			Username:   "admin",
			Password:   "password",
			MaxRetries: 3,
		})
		require.NoError(t, err)
		transport := &certificateFailureTransport{}
		client.client.Transport = transport

		// A regression would wait in the outer data retry loop after the one
		// failed login and return the deadline instead of the certificate error.
		ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		defer cancel()
		_, err = client.ListClass(ctx, "fabric.nodes", "fabricNode", nil, 0)
		require.Error(t, err)
		assert.True(t, httpclient.IsCertificateVerificationError(err))
		assert.NotErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, int64(1), transport.attempts.Load())
	})

	t.Run("data", func(t *testing.T) {
		client, err := NewClient(Config{
			Endpoint:   "https://apic.example.test",
			Username:   "admin",
			Password:   "password",
			MaxRetries: 3,
		})
		require.NoError(t, err)
		transport := &certificateFailureTransport{}
		client.client.Transport = transport
		client.tokenMu.Lock()
		client.token = "apic-token"
		client.refreshTimeout = time.Hour
		client.refreshDeadline = time.Now().Add(time.Hour)
		client.tokenGeneration = 1
		client.tokenMu.Unlock()

		_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
		require.Error(t, err)
		assert.True(t, httpclient.IsCertificateVerificationError(err))
		assert.Equal(t, int64(1), transport.attempts.Load())
	})
}

type certificateFailureTransport struct {
	attempts atomic.Int64
}

type failOnceLoginTransport struct {
	next     http.RoundTripper
	attempts atomic.Int64
}

type cancelSecondLoginTransport struct {
	next     http.RoundTripper
	started  chan struct{}
	attempts atomic.Int64
	once     sync.Once
}

func seedProactiveRefreshAcceptedSession(client *Client) {
	client.tokenMu.Lock()
	defer client.tokenMu.Unlock()
	client.token = "expiring-token"
	client.refreshTimeout = 10 * time.Minute
	client.refreshDeadline = time.Now().Add(-time.Second)
	client.sessionExpiry = time.Now().Add(10 * time.Minute)
	client.tokenAccepted = true
	client.tokenGeneration = 1
	client.generationRejected = false
	client.rejectedGeneration = 0
	client.generationRejectedSignal = make(chan struct{})
}

func seedExpiredAcceptedSession(client *Client) {
	seedProactiveRefreshAcceptedSession(client)
	client.tokenMu.Lock()
	defer client.tokenMu.Unlock()
	client.sessionExpiry = time.Now().Add(-time.Second)
}

func writeAPICError(w http.ResponseWriter, status int, text string) {
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"totalCount":"1","imdata":[{"error":{"attributes":{"code":%q,"text":%q}}}]}`, strconv.Itoa(status), text)
}

func (t *failOnceLoginTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == "/api/aaaLogin.json" && t.attempts.Add(1) == 1 {
		return nil, errors.New("temporary login transport failure")
	}
	return t.next.RoundTrip(req)
}

func (t *cancelSecondLoginTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == "/api/aaaLogin.json" && t.attempts.Add(1) == 2 {
		t.once.Do(func() { close(t.started) })
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	return t.next.RoundTrip(req)
}

func (t *certificateFailureTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.attempts.Add(1)
	return nil, x509.UnknownAuthorityError{}
}

func TestClientRetriesRateLimitsAndRecordsStats(t *testing.T) {
	var attempts atomic.Int64
	var stats []RequestStat
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token","refreshTimeoutSeconds":"600"}}}]}`))
			return
		}
		if attempts.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)
	client.OnRequest = func(stat RequestStat) {
		stats = append(stats, stat)
	}

	got, err := client.ListClass(t.Context(), "fault.instances", "faultInst", nil, 0)
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Equal(t, int64(2), attempts.Load())
	assert.True(t, stats[1].RateLimited)
	assert.Equal(t, "success", stats[2].Outcome)
}

func TestClientRejectedIssuedTokenEntersSharedBackoffUntilDataSucceeds(t *testing.T) {
	var logins atomic.Int64
	var dataRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			token := fmt.Sprintf("apic-token-%d", logins.Add(1))
			_, _ = fmt.Fprintf(w, `{"imdata":[{"aaaLogin":{"attributes":{"token":%q,"refreshTimeoutSeconds":"600"}}}]}`, token)
			return
		}
		dataRequests.Add(1)
		cookie, err := r.Cookie("APIC-cookie")
		if !assert.NoError(t, err) {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		if cookie.Value == "apic-token-1" {
			http.Error(w, "issued token rejected", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 0,
	})
	require.NoError(t, err)

	_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.ErrorContains(t, err, "HTTP 401")
	_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.ErrorContains(t, err, "HTTP 401")
	assert.Equal(t, int64(1), logins.Load(), "the next endpoint must honor shared auth backoff")
	assert.Equal(t, int64(1), dataRequests.Load())
	client.tokenMu.Lock()
	assert.Equal(t, 1, client.authFailures)
	assert.Empty(t, client.token)
	client.lastAuthAt = time.Now().Add(-authBackoffFor(client.authFailures))
	client.tokenMu.Unlock()

	_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(2), logins.Load())
	assert.Equal(t, int64(2), dataRequests.Load())
	client.tokenMu.Lock()
	assert.Zero(t, client.authFailures, "only an accepted data request should clear auth backoff")
	assert.NoError(t, client.lastAuthErr)
	assert.True(t, client.lastAuthAt.IsZero())
	client.tokenMu.Unlock()
}

func TestClientConcurrentRequestsShareLogin(t *testing.T) {
	const callers = 12
	loginStarted := make(chan struct{})
	releaseLogin := make(chan struct{})
	var startedOnce sync.Once
	var loginCalls atomic.Int64
	var dataCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			loginCalls.Add(1)
			startedOnce.Do(func() { close(loginStarted) })
			<-releaseLogin
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"shared-token","refreshTimeoutSeconds":"600"}}}]}`))
			return
		}
		cookie, err := r.Cookie("APIC-cookie")
		if err != nil || cookie.Value != "shared-token" {
			http.Error(w, "missing shared token", http.StatusUnauthorized)
			return
		}
		dataCalls.Add(1)
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		Username:   "admin",
		Password:   "password",
		Timeout:    5 * time.Second,
		MaxRetries: 0,
	})
	require.NoError(t, err)

	errs := make(chan error, callers)
	var workers sync.WaitGroup
	for range callers {
		workers.Go(func() {
			_, requestErr := client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
			errs <- requestErr
		})
	}
	<-loginStarted
	close(releaseLogin)
	workers.Wait()
	close(errs)
	for requestErr := range errs {
		require.NoError(t, requestErr)
	}
	assert.Equal(t, int64(1), loginCalls.Load())
	assert.Equal(t, int64(callers), dataCalls.Load())
}

func TestClientStaleUnauthorizedDoesNotClearReplacementToken(t *testing.T) {
	client, err := NewClient(Config{
		Endpoint: "https://apic.example.test",
		Username: "admin",
		Password: "password",
	})
	require.NoError(t, err)

	client.tokenMu.Lock()
	client.token = "new-token"
	client.refreshTimeout = time.Hour
	client.refreshDeadline = time.Now().Add(time.Hour)
	client.tokenGeneration = 4
	client.tokenMu.Unlock()

	client.rejectToken(tokenSnapshot{value: "old-token", generation: 3}, &APIError{StatusCode: http.StatusUnauthorized}, true)
	client.tokenMu.Lock()
	assert.Equal(t, "new-token", client.token)
	assert.Equal(t, uint64(4), client.tokenGeneration)
	assert.Zero(t, client.authFailures)
	client.tokenMu.Unlock()

	client.rejectToken(tokenSnapshot{value: "new-token", generation: 4}, &APIError{StatusCode: http.StatusUnauthorized}, true)
	client.tokenMu.Lock()
	assert.Empty(t, client.token)
	assert.Equal(t, uint64(5), client.tokenGeneration)
	assert.Equal(t, 1, client.authFailures)
	client.tokenMu.Unlock()
}

func TestClientFiltersBeforeMaxResultsAcrossPages(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token","refreshTimeoutSeconds":"600"}}}]}`))
			return
		}
		assert.Equal(t, "/api/class/fabricNode.json", r.URL.Path)
		assert.Equal(t, "2", r.URL.Query().Get("page-size"), "filtered pagination must keep a stable raw page size")
		requests.Add(1)
		switch r.URL.Query().Get("page") {
		case "0":
			_, _ = w.Write([]byte(`{"totalCount":"5","imdata":[
				{"fabricNode":{"attributes":{"id":"1"}}},
				{"fabricNode":{"attributes":{"id":"2"}}}
			]}`))
		case "1":
			_, _ = w.Write([]byte(`{"totalCount":"5","imdata":[
				{"fabricNode":{"attributes":{"id":"3"}}},
				{"fabricNode":{"attributes":{"id":"4"}}}
			]}`))
		case "2":
			_, _ = w.Write([]byte(`{"totalCount":"5","imdata":[
				{"fabricNode":{"attributes":{"id":"5"}}}
			]}`))
		default:
			assert.Fail(t, "unexpected APIC page", r.URL.RawQuery)
			http.Error(w, "unexpected APIC page", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 0,
		PageSize:   2,
	})
	require.NoError(t, err)

	got, err := client.ListClassFiltered(t.Context(), "fabric.nodes", "fabricNode", nil, 2, func(obj Object) bool {
		return String(obj, "id") == "3" || String(obj, "id") == "5"
	})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "3", String(got[0], "id"))
	assert.Equal(t, "5", String(got[1], "id"))
	assert.Equal(t, int64(3), requests.Load())
}

func TestClientConfiguredPaginationResultLimit(t *testing.T) {
	tests := []struct {
		name      string
		total     string
		filtered  bool
		wantError bool
	}{
		{
			name:  "exact complete at cap",
			total: "2",
		},
		{
			name:      "truncated at cap",
			total:     "3",
			wantError: true,
		},
		{
			name:     "filtered exact complete at cap",
			total:    "3",
			filtered: true,
		},
		{
			name:      "filtered truncated at cap",
			total:     "4",
			filtered:  true,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/aaaLogin.json" {
					_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token","refreshTimeoutSeconds":"600"}}}]}`))
					return
				}
				assert.Equal(t, "/api/class/fabricNode.json", r.URL.Path)
				assert.Equal(t, "0", r.URL.Query().Get("page"))
				requests.Add(1)
				if tt.filtered {
					assert.Equal(t, "3", r.URL.Query().Get("page-size"), "filtered pagination must keep the configured raw page size")
					_, _ = fmt.Fprintf(w, `{"totalCount":%q,"imdata":[
						{"fabricNode":{"attributes":{"id":"skip"}}},
						{"fabricNode":{"attributes":{"id":"101"}}},
						{"fabricNode":{"attributes":{"id":"102"}}}
					]}`, tt.total)
					return
				}
				assert.Equal(t, "2", r.URL.Query().Get("page-size"))
				_, _ = fmt.Fprintf(w, `{"totalCount":%q,"imdata":[
					{"fabricNode":{"attributes":{"id":"101"}}},
					{"fabricNode":{"attributes":{"id":"102"}}}
				]}`, tt.total)
			}))
			defer server.Close()

			client, err := NewClient(Config{
				Endpoint:   server.URL,
				Username:   "admin",
				Password:   "password",
				Timeout:    time.Second,
				MaxRetries: 0,
				PageSize:   3,
			})
			require.NoError(t, err)

			var got []Object
			if tt.filtered {
				got, err = client.ListClassFiltered(t.Context(), "fabric.nodes", "fabricNode", nil, 2, func(obj Object) bool {
					return String(obj, "id") != "skip"
				})
			} else {
				got, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 2)
			}
			require.Len(t, got, 2)
			assert.Equal(t, "101", String(got[0], "id"))
			assert.Equal(t, "102", String(got[1], "id"))
			assert.Equal(t, int64(1), requests.Load())
			if !tt.wantError {
				require.NoError(t, err)
				return
			}
			var limitErr *httpclient.PaginationLimitError
			require.ErrorAs(t, err, &limitErr)
			assert.Equal(t, "fabric.nodes", limitErr.Operation)
			assert.Equal(t, "result", limitErr.Kind)
			assert.Equal(t, 2, limitErr.Maximum)
			assert.Equal(t, 2, limitErr.Results)
			assert.False(t, limitErr.Hard)
			require.ErrorContains(t, err, "configured result limit")
		})
	}
}

func TestClientPaginationContinuesAfterShortPageWhenTotalCountHasMore(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token","refreshTimeoutSeconds":"600"}}}]}`))
			return
		}
		assert.Equal(t, "/api/class/fabricNode.json", r.URL.Path)
		assert.Equal(t, "2", r.URL.Query().Get("page-size"))
		requests.Add(1)
		switch r.URL.Query().Get("page") {
		case "0":
			_, _ = w.Write([]byte(`{"totalCount":"2","imdata":[{"fabricNode":{"attributes":{"id":"101"}}}]}`))
		case "1":
			_, _ = w.Write([]byte(`{"totalCount":"2","imdata":[{"fabricNode":{"attributes":{"id":"102"}}}]}`))
		default:
			t.Fatalf("unexpected APIC page %q", r.URL.Query().Get("page"))
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 0,
		PageSize:   2,
	})
	require.NoError(t, err)

	got, err := client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "101", String(got[0], "id"))
	assert.Equal(t, "102", String(got[1], "id"))
	assert.Equal(t, int64(2), requests.Load())
}

func TestClientPaginationHardPageLimitReturnsPartialResults(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token","refreshTimeoutSeconds":"600"}}}]}`))
			return
		}
		page := r.URL.Query().Get("page")
		requests.Add(1)
		_, _ = fmt.Fprintf(w, `{"totalCount":"%d","imdata":[{"fabricNode":{"attributes":{"id":"%s"}}}]}`, httpclient.HardMaxPaginationPages+1, page)
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 1, PageSize: 1})
	require.NoError(t, err)

	got, err := client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	var limitErr *httpclient.PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.Equal(t, "page", limitErr.Kind)
	assert.Len(t, got, httpclient.HardMaxPaginationPages)
	assert.Equal(t, int64(httpclient.HardMaxPaginationPages), requests.Load())
}

func TestClientFilteredPaginationStillHonorsHardPageLimit(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token","refreshTimeoutSeconds":"600"}}}]}`))
			return
		}
		page := r.URL.Query().Get("page")
		requests.Add(1)
		_, _ = fmt.Fprintf(w, `{"totalCount":"%d","imdata":[{"fabricNode":{"attributes":{"id":%q}}}]}`, httpclient.HardMaxPaginationPages+1, page)
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 0,
		PageSize:   1,
	})
	require.NoError(t, err)

	got, err := client.ListClassFiltered(t.Context(), "fabric.nodes", "fabricNode", nil, 1, func(Object) bool { return false })
	var limitErr *httpclient.PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.Equal(t, "page", limitErr.Kind)
	assert.Empty(t, got)
	assert.Equal(t, int64(httpclient.HardMaxPaginationPages), requests.Load())
}

func TestClientRejectsFixedPagePaginationCycle(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token","refreshTimeoutSeconds":"600"}}}]}`))
			return
		}
		requests.Add(1)
		_, _ = w.Write([]byte(`{"totalCount":"2","imdata":[{"fabricNode":{"attributes":{"id":"101"}}}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 1, PageSize: 1})
	require.NoError(t, err)

	got, err := client.ListClass(t.Context(), "fabric.nodes", "fabricNode", url.Values{"page": {"0"}}, 0)
	require.ErrorContains(t, err, "continuation cycle")
	assert.Len(t, got, 1)
	assert.Equal(t, int64(1), requests.Load())
}

func TestClientRejectsInvalidConfig(t *testing.T) {
	_, err := NewClient(Config{})
	require.Error(t, err)

	_, err = NewClient(Config{Endpoint: "://bad", Username: "admin", Password: "password"})
	require.Error(t, err)

	_, err = NewClient(Config{Endpoint: "https://apic.example.com", Username: "admin"})
	require.Error(t, err)
}
