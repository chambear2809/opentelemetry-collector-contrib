// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nexusdashboard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

func TestClientRetryValidationPreservesExplicitZero(t *testing.T) {
	client, err := NewClient(Config{Endpoint: "https://nexus.example.test", AuthMode: "api_key", Username: "admin", APIKey: "key", MaxRetries: 0})
	require.NoError(t, err)
	assert.Zero(t, client.retries)
	for _, retries := range []int{-1, httpclient.HardMaxRequestRetries + 1} {
		_, err = NewClient(Config{Endpoint: "https://nexus.example.test", AuthMode: "api_key", Username: "admin", APIKey: "key", MaxRetries: retries})
		require.ErrorContains(t, err, "invalid nexus dashboard max retries")
	}
}

func TestClientAuthenticationRetryPolicy(t *testing.T) {
	tests := []struct {
		name             string
		authenticate     func(http.ResponseWriter, int64)
		wantErr          string
		wantAuthRequests int64
	}{
		{
			name: "rejected credentials",
			authenticate: func(w http.ResponseWriter, _ int64) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			},
			wantErr:          "HTTP 401",
			wantAuthRequests: 1,
		},
		{
			name: "invalid successful login response",
			authenticate: func(w http.ResponseWriter, _ int64) {
				_, _ = w.Write([]byte(`{"not_token":"missing"}`))
			},
			wantErr:          "did not include a token",
			wantAuthRequests: 1,
		},
		{
			name: "transient authentication server failure",
			authenticate: func(w http.ResponseWriter, attempt int64) {
				if attempt == 1 {
					http.Error(w, "unavailable", http.StatusServiceUnavailable)
					return
				}
				_, _ = w.Write([]byte(`{"token":"nd-token"}`))
			},
			wantAuthRequests: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var authRequests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/infra/login" {
					tt.authenticate(w, authRequests.Add(1))
					return
				}
				_, _ = w.Write([]byte(`{"items":[]}`))
			}))
			defer server.Close()

			client, err := NewClient(Config{
				Endpoint:   server.URL,
				AuthMode:   "username_password",
				Username:   "admin",
				Password:   "password",
				Timeout:    time.Second,
				MaxRetries: 1,
			})
			require.NoError(t, err)

			_, err = client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, 1)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.wantErr)
			}
			assert.Equal(t, tt.wantAuthRequests, authRequests.Load())
		})
	}
}

func TestClientRetriesAuthenticationTransportFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/infra/login" {
			_, _ = w.Write([]byte(`{"token":"nd-token"}`))
			return
		}
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		AuthMode:   "username_password",
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 1,
	})
	require.NoError(t, err)
	transport := &failOnceTransport{next: client.client.Transport, path: "/api/v1/infra/login"}
	client.client.Transport = transport

	_, err = client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, 1)
	require.NoError(t, err)
	assert.Equal(t, int64(2), transport.attempts.Load())
}

func TestClientAuthenticationFailuresEnterSharedBackoff(t *testing.T) {
	tests := []struct {
		name          string
		handleLogin   func(http.ResponseWriter)
		handleData    func(http.ResponseWriter)
		wantDataCalls int64
	}{
		{
			name: "login rejected",
			handleLogin: func(w http.ResponseWriter) {
				http.Error(w, "invalid credentials", http.StatusUnauthorized)
			},
			handleData: func(w http.ResponseWriter) {
				_, _ = w.Write([]byte(`{"items":[]}`))
			},
		},
		{
			name: "issued token rejected",
			handleLogin: func(w http.ResponseWriter) {
				_, _ = w.Write([]byte(`{"token":"rejected-token"}`))
			},
			handleData: func(w http.ResponseWriter) {
				http.Error(w, "token rejected", http.StatusUnauthorized)
			},
			wantDataCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var loginCalls atomic.Int64
			var dataCalls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/infra/login" {
					loginCalls.Add(1)
					tt.handleLogin(w)
					return
				}
				dataCalls.Add(1)
				tt.handleData(w)
			}))
			defer server.Close()

			client, err := NewClient(Config{
				Endpoint:   server.URL,
				AuthMode:   "username_password",
				Username:   "admin",
				Password:   "password",
				Timeout:    time.Second,
				MaxRetries: 2,
			})
			require.NoError(t, err)

			_, firstErr := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, 1)
			require.ErrorContains(t, firstErr, "HTTP 401")
			_, secondErr := client.List(t.Context(), "switches", "/api/v1/manage/switches", nil, 1)
			require.ErrorContains(t, secondErr, "HTTP 401")

			assert.Equal(t, int64(1), loginCalls.Load())
			assert.Equal(t, tt.wantDataCalls, dataCalls.Load())
			client.tokenMu.Lock()
			assert.Equal(t, 1, client.authFailures)
			client.tokenMu.Unlock()
		})
	}
}

func TestClientStaleUnauthorizedDoesNotClearNewerToken(t *testing.T) {
	client, err := NewClient(Config{
		Endpoint: "https://nexus.example.test",
		AuthMode: "username_password",
		Username: "admin",
		Password: "password",
	})
	require.NoError(t, err)

	client.tokenMu.Lock()
	client.token = "new-token"
	client.tokenGeneration = 4
	client.tokenMu.Unlock()

	client.clearToken(tokenSnapshot{value: "old-token", generation: 3}, &APIError{StatusCode: http.StatusUnauthorized})
	client.tokenMu.Lock()
	assert.Equal(t, "new-token", client.token)
	assert.Equal(t, uint64(4), client.tokenGeneration)
	assert.Zero(t, client.authFailures)
	client.tokenMu.Unlock()

	client.clearToken(tokenSnapshot{value: "new-token", generation: 4}, &APIError{StatusCode: http.StatusUnauthorized})
	client.tokenMu.Lock()
	assert.Empty(t, client.token)
	assert.Equal(t, uint64(5), client.tokenGeneration)
	assert.Equal(t, 1, client.authFailures)
	client.tokenMu.Unlock()
}

func TestClientForbiddenRetainsTokenAndDataSuccessResetsAuthFailures(t *testing.T) {
	var loginCalls atomic.Int64
	var dataCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/infra/login" {
			loginCalls.Add(1)
			_, _ = w.Write([]byte(`{"token":"valid-token"}`))
			return
		}
		assert.Equal(t, "Bearer valid-token", r.Header.Get("Authorization"))
		if dataCalls.Add(1) == 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		AuthMode:   "username_password",
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 1,
	})
	require.NoError(t, err)
	client.tokenMu.Lock()
	client.authFailures = 2
	client.lastAuthErr = errors.New("previous authentication failure")
	client.lastAuthStatus = http.StatusUnauthorized
	client.lastAuthAt = time.Now().Add(-time.Hour)
	client.tokenMu.Unlock()

	_, firstErr := client.List(t.Context(), "restricted", "/api/v1/manage/restricted", nil, 1)
	require.ErrorContains(t, firstErr, "HTTP 403")
	client.tokenMu.Lock()
	assert.Equal(t, "valid-token", client.token)
	assert.Equal(t, 2, client.authFailures, "a successful login and 403 must not reset the failure streak")
	client.tokenMu.Unlock()

	_, secondErr := client.List(t.Context(), "allowed", "/api/v1/manage/allowed", nil, 1)
	require.NoError(t, secondErr)
	assert.Equal(t, int64(1), loginCalls.Load())
	assert.Equal(t, int64(2), dataCalls.Load())
	client.tokenMu.Lock()
	assert.Zero(t, client.authFailures)
	assert.NoError(t, client.lastAuthErr)
	assert.Zero(t, client.lastAuthStatus)
	assert.True(t, client.lastAuthAt.IsZero())
	client.tokenMu.Unlock()
}

func TestClientConcurrentRequestsShareLogin(t *testing.T) {
	const callers = 16
	loginStarted := make(chan struct{}, 1)
	releaseLogin := make(chan struct{})
	var loginCalls atomic.Int64
	var dataCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/infra/login" {
			loginCalls.Add(1)
			loginStarted <- struct{}{}
			<-releaseLogin
			_, _ = w.Write([]byte(`{"token":"shared-token"}`))
			return
		}
		dataCalls.Add(1)
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint: server.URL,
		AuthMode: "username_password",
		Username: "admin",
		Password: "password",
		Timeout:  time.Second,
	})
	require.NoError(t, err)

	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			_, requestErr := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, 1)
			errs <- requestErr
		})
	}
	<-loginStarted
	close(releaseLogin)
	wg.Wait()
	close(errs)
	for requestErr := range errs {
		require.NoError(t, requestErr)
	}
	assert.Equal(t, int64(1), loginCalls.Load())
	assert.Equal(t, int64(callers), dataCalls.Load())
}

func TestClientCanceledLoginOwnerDoesNotBackoffLiveWaiter(t *testing.T) {
	var loginCalls atomic.Int64
	firstLoginStarted := make(chan struct{})
	releaseFirstLogin := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/infra/login" {
			http.NotFound(w, r)
			return
		}
		if loginCalls.Add(1) == 1 {
			close(firstLoginStarted)
			<-releaseFirstLogin
			return
		}
		_, _ = w.Write([]byte(`{"token":"replacement-token"}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint: server.URL,
		AuthMode: "username_password",
		Username: "admin",
		Password: "password",
		Timeout:  5 * time.Second,
	})
	require.NoError(t, err)

	ownerCtx, cancelOwner := context.WithCancel(t.Context())
	ownerResult := make(chan error, 1)
	go func() {
		_, _, _, authErr := client.ensureToken(ownerCtx, false)
		ownerResult <- authErr
	}()
	<-firstLoginStarted

	client.tokenMu.Lock()
	waiterResult := make(chan error, 1)
	go func() {
		_, _, _, authErr := client.ensureToken(t.Context(), false)
		waiterResult <- authErr
	}()
	cancelOwner()
	close(releaseFirstLogin)
	client.tokenMu.Unlock()

	require.ErrorIs(t, <-ownerResult, context.Canceled)
	require.NoError(t, <-waiterResult)
	assert.Equal(t, int64(2), loginCalls.Load())
	client.tokenMu.Lock()
	assert.Zero(t, client.authFailures)
	client.tokenMu.Unlock()
}

type failOnceTransport struct {
	next     http.RoundTripper
	path     string
	attempts atomic.Int64
}

func (t *failOnceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == t.path && t.attempts.Add(1) == 1 {
		return nil, errors.New("temporary transport failure")
	}
	return t.next.RoundTrip(req)
}

func TestClientAPIKeyHeadersAndPagination(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "admin", r.Header.Get("X-Nd-Username"))
		assert.Equal(t, "nd-api-key", r.Header.Get("X-Nd-Apikey"))
		switch requests.Add(1) {
		case 1:
			assert.Equal(t, "0", r.URL.Query().Get("offset"))
			w.Header().Set("Link", `</api/v1/manage/fabrics?filter=a,b&offset=1&max=1>; rel="prev next"`)
			_, _ = w.Write([]byte(`{"items":[{"fabricName":"fabric-a"}]}`))
		default:
			assert.Equal(t, "1", r.URL.Query().Get("offset"))
			assert.Equal(t, "a,b", r.URL.Query().Get("filter"))
			_, _ = w.Write([]byte(`{"items":[{"fabricName":"fabric-b"}]}`))
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		AuthMode:   "api_key",
		Username:   "admin",
		APIKey:     "nd-api-key",
		Timeout:    time.Second,
		MaxRetries: 1,
		PageSize:   1,
	})
	require.NoError(t, err)

	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, 2)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "fabric-a", got[0]["fabricName"])
	assert.Equal(t, "fabric-b", got[1]["fabricName"])
	assert.Equal(t, int64(2), requests.Load())
}

func TestDecodeObjectsPreservesLargeInteger(t *testing.T) {
	objects, _, _, err := decodeObjects([]byte(`{"items":[{"bytes":9007199254740993}]}`), nil)
	require.NoError(t, err)
	require.Len(t, objects, 1)
	value, ok := Int64(objects[0], "bytes")
	require.True(t, ok)
	assert.Equal(t, int64(9007199254740993), value)
}

func TestClientRejectsPaginationCycle(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Link", `</api/v1/manage/fabrics?max=1&offset=0>; rel="next"`)
		_, _ = w.Write([]byte(`{"items":[{"fabricName":"fabric-a"}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		AuthMode:   "api_key",
		Username:   "admin",
		APIKey:     "nd-api-key",
		Timeout:    time.Second,
		MaxRetries: 1,
		PageSize:   1,
	})
	require.NoError(t, err)

	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, 10)
	require.ErrorContains(t, err, "continuation cycle")
	require.Len(t, got, 1)
	assert.Equal(t, "fabric-a", got[0]["fabricName"])
	assert.Equal(t, int64(1), requests.Load())
}

func TestClientSupportsSelfSignedTLSWithInsecureSkipVerify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "admin", r.Header.Get("X-Nd-Username"))
		assert.Equal(t, "nd-api-key", r.Header.Get("X-Nd-Apikey"))
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer server.Close()

	verifiedClient, err := NewClient(Config{
		Endpoint:   server.URL,
		AuthMode:   "api_key",
		Username:   "admin",
		APIKey:     "nd-api-key",
		Timeout:    time.Second,
		MaxRetries: 3,
	})
	require.NoError(t, err)
	verifiedAttempts := 0
	verifiedClient.OnRequest = func(RequestStat) { verifiedAttempts++ }
	_, err = verifiedClient.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, 0)
	require.ErrorContains(t, err, "trust the issuing CA in the Collector host trust store (preferred)")
	require.ErrorContains(t, err, "set nexus_dashboard.insecure_skip_verify: true")
	assert.Equal(t, 1, verifiedAttempts)

	passwordClient, err := NewClient(Config{
		Endpoint:   server.URL,
		AuthMode:   "username_password",
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 3,
	})
	require.NoError(t, err)
	passwordAttempts := 0
	passwordClient.OnRequest = func(RequestStat) { passwordAttempts++ }
	_, err = passwordClient.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, 0)
	require.ErrorContains(t, err, "trust the issuing CA in the Collector host trust store (preferred)")
	require.ErrorContains(t, err, "set nexus_dashboard.insecure_skip_verify: true")
	assert.Equal(t, 1, passwordAttempts)

	client, err := NewClient(Config{
		Endpoint:           server.URL,
		AuthMode:           "api_key",
		Username:           "admin",
		APIKey:             "nd-api-key",
		Timeout:            time.Second,
		MaxRetries:         1,
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)

	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, 0)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestClientUsernamePasswordLoginToken(t *testing.T) {
	var logins atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/infra/login" {
			logins.Add(1)
			_, _ = w.Write([]byte(`{"token":"nd-token"}`))
			return
		}
		assert.Equal(t, "Bearer nd-token", r.Header.Get("Authorization"))
		cookie, err := r.Cookie("AuthCookie")
		if !assert.NoError(t, err) {
			http.Error(w, "missing authentication cookie", http.StatusUnauthorized)
			return
		}
		assert.Equal(t, "nd-token", cookie.Value)
		_, _ = w.Write([]byte(`[{"name":"nd-cluster"}]`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		AuthMode:   "username_password",
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 1,
	})
	require.NoError(t, err)

	got, err := client.List(t.Context(), "cluster", "/api/v1/infra/cluster/health", nil, 1)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, int64(1), logins.Load())
}

func TestClientStopsWhenFullPageHasNoNextOrRemaining(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assert.Equal(t, "0", r.URL.Query().Get("offset"))
		_, _ = w.Write([]byte(`{"items":[{"fabricName":"fabric-a"}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		AuthMode:   "api_key",
		Username:   "admin",
		APIKey:     "nd-api-key",
		Timeout:    time.Second,
		MaxRetries: 1,
		PageSize:   1,
	})
	require.NoError(t, err)

	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, 0)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "fabric-a", got[0]["fabricName"])
	assert.Equal(t, int64(1), requests.Load())
}

func TestClientPaginationHardPageLimitReturnsPartialResults(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"items":[{"fabricName":"fabric-a"}],"pagination":{"remaining":1}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		AuthMode:   "api_key",
		Username:   "admin",
		APIKey:     "nd-api-key",
		Timeout:    time.Second,
		MaxRetries: 1,
		PageSize:   1,
	})
	require.NoError(t, err)

	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, 0)
	var limitErr *httpclient.PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.Equal(t, "page", limitErr.Kind)
	assert.Len(t, got, httpclient.HardMaxPaginationPages)
	assert.Equal(t, int64(httpclient.HardMaxPaginationPages), requests.Load())
}

func TestClientRejectsInvalidConfig(t *testing.T) {
	_, err := NewClient(Config{})
	require.Error(t, err)

	_, err = NewClient(Config{Endpoint: "://bad", AuthMode: "api_key", Username: "admin", APIKey: "key"})
	require.Error(t, err)

	_, err = NewClient(Config{Endpoint: "https://nd.example.com", AuthMode: "api_key", APIKey: "key"})
	require.Error(t, err)
}
