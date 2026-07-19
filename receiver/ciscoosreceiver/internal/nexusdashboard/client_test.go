// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nexusdashboard

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	client, err := NewClient(Config{Endpoint: "https://nexus.example.test", AuthMode: "api_key", Username: "admin", APIKey: "key", MaxRetries: 0})
	require.NoError(t, err)
	assert.Zero(t, client.retries)
	for _, retries := range []int{-1, httpclient.HardMaxRequestRetries + 1} {
		_, err = NewClient(Config{Endpoint: "https://nexus.example.test", AuthMode: "api_key", Username: "admin", APIKey: "key", MaxRetries: retries})
		require.ErrorContains(t, err, "invalid nexus dashboard max retries")
	}
}

func TestClientRetriesIncompleteSuccessfulResponseBody(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("Content-Length", "100")
			w.Header().Set("Retry-After", "0")
			_, _ = w.Write([]byte(`{"items":`))
			return
		}
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", MaxRetries: 1})
	require.NoError(t, err)
	objects, err := client.List(t.Context(), "test.list", "/api/v1/test", nil, PaginationOffset, 10)
	require.NoError(t, err)
	assert.Empty(t, objects)
	assert.Equal(t, int64(2), requests.Load())
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
		{
			name: "incomplete successful authentication body",
			authenticate: func(w http.ResponseWriter, attempt int64) {
				if attempt == 1 {
					w.Header().Set("Content-Length", "100")
					_, _ = w.Write([]byte(`{"token":`))
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

			_, err = client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 1)
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

	_, err = client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 1)
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

			_, firstErr := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 1)
			require.ErrorContains(t, firstErr, "HTTP 401")
			_, secondErr := client.List(t.Context(), "switches", "/api/v1/manage/switches", nil, PaginationOffset, 1)
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

	_, firstErr := client.List(t.Context(), "restricted", "/api/v1/manage/restricted", nil, PaginationOffset, 1)
	require.ErrorContains(t, firstErr, "HTTP 403")
	client.tokenMu.Lock()
	assert.Equal(t, "valid-token", client.token)
	assert.Equal(t, 2, client.authFailures, "a successful login and 403 must not reset the failure streak")
	client.tokenMu.Unlock()

	_, secondErr := client.List(t.Context(), "allowed", "/api/v1/manage/allowed", nil, PaginationOffset, 1)
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
			_, requestErr := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 1)
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

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestClientLinkPaginationDoesNotInventOffsets(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "admin", r.Header.Get("X-Nd-Username"))
		assert.Equal(t, "nd-api-key", r.Header.Get("X-Nd-Apikey"))
		switch requests.Add(1) {
		case 1:
			assert.False(t, r.URL.Query().Has("offset"))
			assert.False(t, r.URL.Query().Has("max"))
			w.Header().Set("Link", `</api/v1/manage/fabrics?filter=a,b&cursor=page-2>; rel="prev next"`)
			_, _ = w.Write([]byte(`{"items":[{"fabricName":"fabric-a"}]}`))
		default:
			assert.False(t, r.URL.Query().Has("offset"))
			assert.False(t, r.URL.Query().Has("max"))
			assert.Equal(t, "page-2", r.URL.Query().Get("cursor"))
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

	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationLink, 2)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "fabric-a", got[0]["fabricName"])
	assert.Equal(t, "fabric-b", got[1]["fabricName"])
	assert.Equal(t, int64(2), requests.Load())
}

func TestClientLinkPaginationRedactsContinuationTransportErrors(t *testing.T) {
	const continuationSecret = "continuation-secret"
	var serverRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, int64(1), serverRequests.Add(1))
		assert.Empty(t, r.URL.Query().Get("cursor"))
		_, _ = w.Write([]byte(`{"items":[{"id":"page-1"}],"meta":{"links":{"next":"?cursor=` + continuationSecret + `"}}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		AuthMode:   "api_key",
		Username:   "admin",
		APIKey:     "nd-api-key",
		MaxRetries: 3,
		PageSize:   1,
	})
	require.NoError(t, err)

	transportSentinel := errors.New("classified continuation transport failure")
	tlsCause := x509.UnknownAuthorityError{Cert: &x509.Certificate{}}
	transportCause := fmt.Errorf("%w: %w", transportSentinel, tlsCause)
	nextTransport := client.client.Transport
	var transportFailures atomic.Int64
	client.client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Query().Get("cursor") == continuationSecret {
			transportFailures.Add(1)
			return nil, transportCause
		}
		return nextTransport.RoundTrip(req)
	})

	var recordedError error
	var recordedPath string
	client.OnRequest = func(stat RequestStat) {
		if stat.Err != nil {
			recordedError = stat.Err
			recordedPath = stat.Path
		}
	}

	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationLink, 2)
	require.Error(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "page-1", got[0]["id"])
	assert.ErrorIs(t, err, transportSentinel)
	var unknownAuthority x509.UnknownAuthorityError
	assert.ErrorAs(t, err, &unknownAuthority)
	var requestError *url.Error
	assert.ErrorAs(t, err, &requestError)
	assert.True(t, httpclient.IsCertificateVerificationError(err))
	assert.ErrorContains(t, err, "TLS certificate verification failed")
	assert.NotContains(t, err.Error(), continuationSecret)
	assert.NotContains(t, err.Error(), "cursor=")

	require.Error(t, recordedError)
	assert.ErrorIs(t, recordedError, transportSentinel)
	assert.True(t, httpclient.IsCertificateVerificationError(recordedError))
	assert.NotContains(t, recordedError.Error(), continuationSecret)
	assert.NotContains(t, recordedError.Error(), "cursor=")
	assert.NotContains(t, recordedPath, continuationSecret)
	assert.Equal(t, int64(1), serverRequests.Load())
	assert.Equal(t, int64(1), transportFailures.Load())
}

func TestClientLinkPaginationPreservesEndpointPathPrefix(t *testing.T) {
	tests := []struct {
		name string
		next func(controllerURL, otherURL string) string
	}{
		{
			name: "same-origin absolute with prefix",
			next: func(controllerURL, _ string) string {
				return controllerURL + "/proxy/api/v1/manage/fabrics?cursor=page-2"
			},
		},
		{
			name: "root-relative with prefix",
			next: func(_, _ string) string {
				return "/proxy/api/v1/manage/fabrics?cursor=page-2"
			},
		},
		{
			name: "root-relative without prefix",
			next: func(_, _ string) string {
				return "/api/v1/manage/fabrics?cursor=page-2"
			},
		},
		{
			name: "query-only",
			next: func(_, _ string) string {
				return "?cursor=page-2"
			},
		},
		{
			name: "cross-origin absolute with prefix",
			next: func(_, otherURL string) string {
				return otherURL + "/proxy/api/v1/manage/fabrics?cursor=page-2"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var otherRequests atomic.Int64
			otherServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				otherRequests.Add(1)
				http.Error(w, "continuation escaped configured controller", http.StatusBadGateway)
			}))
			defer otherServer.Close()

			var requests atomic.Int64
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/proxy/api/v1/manage/fabrics", r.URL.Path)
				assert.Equal(t, "admin", r.Header.Get("X-Nd-Username"))
				assert.Equal(t, "nd-api-key", r.Header.Get("X-Nd-Apikey"))
				assert.False(t, r.URL.Query().Has("offset"))
				assert.False(t, r.URL.Query().Has("max"))
				switch requests.Add(1) {
				case 1:
					assert.Empty(t, r.URL.Query().Get("cursor"))
					_, _ = fmt.Fprintf(w, `{"items":[{"id":"a"}],"meta":{"links":{"next":%q}}}`, tt.next(server.URL, otherServer.URL))
				case 2:
					assert.Equal(t, "page-2", r.URL.Query().Get("cursor"))
					_, _ = w.Write([]byte(`{"items":[{"id":"b"}]}`))
				default:
					t.Fatalf("unexpected request %d", requests.Load())
				}
			}))
			defer server.Close()

			client, err := NewClient(Config{
				Endpoint: server.URL + "/proxy",
				AuthMode: "api_key",
				Username: "admin",
				APIKey:   "nd-api-key",
				PageSize: 1,
			})
			require.NoError(t, err)

			got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationLink, 2)
			require.NoError(t, err)
			require.Len(t, got, 2)
			assert.Equal(t, "a", got[0]["id"])
			assert.Equal(t, "b", got[1]["id"])
			assert.Equal(t, int64(2), requests.Load())
			assert.Zero(t, otherRequests.Load())
		})
	}
}

func TestClientLinkPaginationPreservesEscapedSelectorsWithEndpointPathPrefix(t *testing.T) {
	tests := []struct {
		name         string
		resourcePath string
	}{
		{
			name:         "escaped slash",
			resourcePath: "/api/v1/manage/fabrics/fabric%20A%2FB/switches",
		},
		{
			name:         "escaped literal percent",
			resourcePath: "/api/v1/manage/fabrics/rate%25/switches",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			escapedPath := "/proxy" + tt.resourcePath
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, escapedPath, r.URL.EscapedPath())
				assert.NotContains(t, r.URL.EscapedPath(), "%2525")
				assert.NotContains(t, r.URL.EscapedPath(), "%252F")
				switch requests.Add(1) {
				case 1:
					next := escapedPath + "?cursor=page-2"
					_, _ = fmt.Fprintf(w, `{"items":[{"id":"a"}],"meta":{"links":{"next":%q}}}`, next)
				case 2:
					assert.Equal(t, "page-2", r.URL.Query().Get("cursor"))
					_, _ = w.Write([]byte(`{"items":[{"id":"b"}]}`))
				default:
					t.Fatalf("unexpected request %d", requests.Load())
				}
			}))
			defer server.Close()

			client, err := NewClient(Config{
				Endpoint: server.URL + "/proxy",
				AuthMode: "api_key",
				Username: "admin",
				APIKey:   "nd-api-key",
				PageSize: 1,
			})
			require.NoError(t, err)

			got, err := client.List(t.Context(), "fabrics", tt.resourcePath, nil, PaginationLink, 2)
			require.NoError(t, err)
			assert.Len(t, got, 2)
			assert.Equal(t, int64(2), requests.Load())
		})
	}
}

func TestClientLinkPaginationPreservesEscapedSelectorAcrossEquivalentPrefixSpellings(t *testing.T) {
	tests := []struct {
		name               string
		configuredPrefix   string
		continuationPrefix string
	}{
		{
			name:               "percent escape hex case",
			configuredPrefix:   "/reverse%2fproxy",
			continuationPrefix: "/reverse%2Fproxy",
		},
		{
			name:               "escaped unreserved character",
			configuredPrefix:   "/rev%65rse/proxy",
			continuationPrefix: "/reverse/proxy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var otherRequests atomic.Int64
			otherServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				otherRequests.Add(1)
				http.Error(w, "continuation escaped configured controller", http.StatusBadGateway)
			}))
			defer otherServer.Close()

			const resourcePath = "/api/v1/manage/fabrics/fabric%20A%2FB/switches"
			const continuationResourcePath = "/api/v1/manage/fabrics/fabric%20A%2fB/switches"
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				request := requests.Add(1)
				expectedPath := tt.configuredPrefix + resourcePath
				if request == 2 {
					expectedPath = tt.configuredPrefix + continuationResourcePath
				}
				assert.Equal(t, expectedPath, r.URL.EscapedPath())
				assert.NotContains(t, r.URL.EscapedPath(), "%2520")
				assert.NotContains(t, r.URL.EscapedPath(), "%252F")
				assert.NotContains(t, r.URL.EscapedPath(), "%252f")

				switch request {
				case 1:
					next := otherServer.URL + tt.continuationPrefix + continuationResourcePath + "?cursor=page-2"
					_, _ = fmt.Fprintf(w, `{"items":[{"id":"a"}],"meta":{"links":{"next":%q}}}`, next)
				case 2:
					assert.Equal(t, "page-2", r.URL.Query().Get("cursor"))
					_, _ = w.Write([]byte(`{"items":[{"id":"b"}]}`))
				default:
					t.Fatalf("unexpected request %d", request)
				}
			}))
			defer server.Close()

			client, err := NewClient(Config{
				Endpoint: server.URL + tt.configuredPrefix,
				AuthMode: "api_key",
				Username: "admin",
				APIKey:   "nd-api-key",
				PageSize: 1,
			})
			require.NoError(t, err)

			got, err := client.List(t.Context(), "fabrics", resourcePath, nil, PaginationLink, 2)
			require.NoError(t, err)
			assert.Len(t, got, 2)
			assert.Equal(t, int64(2), requests.Load())
			assert.Zero(t, otherRequests.Load())
		})
	}
}

func TestClientLinkPaginationRejectsContinuationPathTraversal(t *testing.T) {
	tests := []struct {
		name    string
		next    string
		wantErr string
		secrets []string
	}{
		{
			name:    "literal dot-dot segment",
			next:    "/proxy/../admin?cursor=page-2",
			wantErr: `path contains a traversal segment that decodes to ".."`,
		},
		{
			name:    "percent-encoded dot-dot segment",
			next:    "/proxy/%2e%2e/admin?cursor=page-2",
			wantErr: `path contains a traversal segment that decodes to ".."`,
		},
		{
			name:    "mixed literal and encoded dots",
			next:    "/proxy/.%2E/admin?cursor=page-2",
			wantErr: `path contains a traversal segment that decodes to ".."`,
		},
		{
			name:    "encoded and literal dots",
			next:    "/proxy/%2e./admin?cursor=page-2",
			wantErr: `path contains a traversal segment that decodes to ".."`,
		},
		{
			name:    "encoded slash terminates dot-dot segment",
			next:    "/proxy/%2e%2e%2Fadmin?cursor=page-2",
			wantErr: `path contains a traversal segment that decodes to ".."`,
		},
		{
			name:    "double-encoded slash terminates dot-dot segment",
			next:    "/proxy/%2e%2e%252Fadmin?cursor=page-2",
			wantErr: `path contains a traversal segment that decodes to ".."`,
		},
		{
			name:    "decoded backslash terminates dot-dot segment",
			next:    "/proxy/..%5cadmin?cursor=page-2",
			wantErr: `path contains a traversal segment that decodes to ".."`,
		},
		{
			name:    "double-encoded traversal metadata is redacted",
			next:    "https://continuation-user:continuation-password@untrusted.example/proxy/%252e%252e%252fadmin?cursor=continuation-secret-token",
			wantErr: `path contains a traversal segment that decodes to ".."`,
			secrets: []string{"continuation-user", "continuation-password", "untrusted.example", "continuation-secret-token"},
		},
		{
			name:    "invalid continuation metadata is redacted",
			next:    "https://parse-user:parse-password@untrusted.example/proxy/%2g%2e/admin?cursor=parse-secret-token",
			wantErr: "parse continuation metadata: invalid URL",
			secrets: []string{"parse-user", "parse-password", "untrusted.example", "parse-secret-token"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/proxy/api/v1/manage/fabrics", r.URL.EscapedPath())
				if request := requests.Add(1); request != 1 {
					t.Fatalf("unexpected request %d to %s", request, r.URL.EscapedPath())
				}
				_, _ = fmt.Fprintf(w, `{"items":[{"id":"page-1"}],"meta":{"links":{"next":%q}}}`, tt.next)
			}))
			defer server.Close()

			client, err := NewClient(Config{
				Endpoint: server.URL + "/proxy",
				AuthMode: "api_key",
				Username: "admin",
				APIKey:   "nd-api-key",
				PageSize: 1,
			})
			require.NoError(t, err)

			got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationLink, 2)
			require.ErrorContains(t, err, "paginate nexus dashboard fabrics response: resolve continuation after 1 partial results")
			require.ErrorContains(t, err, tt.wantErr)
			assert.NotContains(t, err.Error(), tt.next)
			for _, secret := range tt.secrets {
				assert.NotContains(t, err.Error(), secret)
			}
			require.Len(t, got, 1)
			assert.Equal(t, "page-1", got[0]["id"])
			assert.Equal(t, int64(1), requests.Load())
		})
	}
}

func TestEscapedDecodedPrefixLength(t *testing.T) {
	tests := []struct {
		name          string
		escapedPath   string
		decodedPrefix string
		wantBoundary  int
		wantOK        bool
	}{
		{
			name:          "literal bytes",
			escapedPath:   "/reverse/proxy/resource",
			decodedPrefix: "/reverse/proxy",
			wantBoundary:  len("/reverse/proxy"),
			wantOK:        true,
		},
		{
			name:          "mixed percent-hex case",
			escapedPath:   "/one%2ftwo%2Fthree/resource",
			decodedPrefix: "/one/two/three",
			wantBoundary:  len("/one%2ftwo%2Fthree"),
			wantOK:        true,
		},
		{
			name:          "escaped unreserved bytes",
			escapedPath:   "/%72ev%65rse/proxy/resource",
			decodedPrefix: "/reverse/proxy",
			wantBoundary:  len("/%72ev%65rse/proxy"),
			wantOK:        true,
		},
		{
			name:          "UTF-8 bytes",
			escapedPath:   "/caf%C3%a9/%e2%98%83/resource",
			decodedPrefix: "/café/☃",
			wantBoundary:  len("/caf%C3%a9/%e2%98%83"),
			wantOK:        true,
		},
		{
			name:          "invalid percent hex",
			escapedPath:   "/reverse%2Gproxy/resource",
			decodedPrefix: "/reverse/proxy",
			wantOK:        false,
		},
		{
			name:          "truncated escape",
			escapedPath:   "/reverse%2",
			decodedPrefix: "/reverse/",
			wantOK:        false,
		},
		{
			name:          "decoded mismatch",
			escapedPath:   "/reverse/proxy/resource",
			decodedPrefix: "/reverse/other",
			wantOK:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			boundary, ok := escapedDecodedPrefixLength(tt.escapedPath, tt.decodedPrefix)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantBoundary, boundary)
		})
	}
}

func TestEscapedDecodedPrefixLengthHasLinearOperationBound(t *testing.T) {
	const prefixBytes = 64 * 1024
	decodedPrefix := "/" + strings.Repeat("a", prefixBytes)
	escapedPrefix := "/" + strings.Repeat("%61", prefixBytes)
	escapedPath := escapedPrefix + "/fabric%2Fselector"
	operations := 0

	boundary, ok := escapedDecodedPrefixLengthWithOperations(escapedPath, decodedPrefix, &operations)

	require.True(t, ok)
	assert.Equal(t, len(escapedPrefix), boundary)
	assert.Equal(t, "/fabric%2Fselector", escapedPath[boundary:])
	assert.LessOrEqual(t, operations, len(decodedPrefix))
}

func TestClientEndpointRequestURLKeepsLoginAndSelectorRawPathsValid(t *testing.T) {
	client, err := NewClient(Config{
		Endpoint: "https://nexus.example.test/reverse/proxy",
		AuthMode: "api_key",
		Username: "admin",
		APIKey:   "nd-api-key",
	})
	require.NoError(t, err)

	tests := []struct {
		name         string
		path         string
		expectedPath string
	}{
		{
			name:         "login",
			path:         modernLoginPath,
			expectedPath: "/reverse/proxy/api/v1/infra/login",
		},
		{
			name:         "escaped selector",
			path:         "/api/v1/manage/fabrics/fabric%20A%2FB/switches",
			expectedPath: "/reverse/proxy/api/v1/manage/fabrics/fabric%20A%2FB/switches",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestURL := client.endpointRequestURL(tt.path)
			assert.Equal(t, tt.expectedPath, requestURL.RawPath)
			assert.Equal(t, requestURL.RawPath, requestURL.EscapedPath())
			assert.Equal(t, "https://nexus.example.test"+tt.expectedPath, requestURL.String())
		})
	}
}

func TestClientSinglePaginationRejectsContinuationWithoutFollowing(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assert.False(t, r.URL.Query().Has("offset"))
		assert.False(t, r.URL.Query().Has("max"))
		_, _ = w.Write([]byte(`{"items":[{"id":"only-request"}],"meta":{"links":{"next":"/api/v1/test?cursor=page-2"}}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", PageSize: 1})
	require.NoError(t, err)
	got, err := client.List(t.Context(), "single", "/api/v1/test", nil, PaginationSingle, 1)
	require.ErrorContains(t, err, "single-response contract claimed continuation")
	assert.Len(t, got, 1)
	assert.Equal(t, int64(1), requests.Load())
}

func TestClientSinglePaginationPreservesByteIdenticalRowsWithinPage(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assert.False(t, r.URL.Query().Has("offset"))
		assert.False(t, r.URL.Query().Has("max"))
		_, _ = w.Write([]byte(`{"items":[{"state":"up"},{"state":"up"}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", PageSize: 2})
	require.NoError(t, err)
	got, err := client.List(t.Context(), "single", "/api/v1/test", nil, PaginationSingle, 2)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "up", got[0]["state"])
	assert.Equal(t, "up", got[1]["state"])
	assert.Equal(t, int64(1), requests.Load())
}

func TestClientUnknownPaginationDoesNotInferCompletionFromConfiguredPageSize(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assert.False(t, r.URL.Query().Has("offset"))
		assert.False(t, r.URL.Query().Has("max"))
		_, _ = w.Write([]byte(`{"items":[`))
		for i := range 25 {
			if i > 0 {
				_, _ = w.Write([]byte(","))
			}
			_, _ = fmt.Fprintf(w, `{"id":"item-%d"}`, i)
		}
		_, _ = w.Write([]byte(`]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", PageSize: 500})
	require.NoError(t, err)
	got, err := client.List(t.Context(), "legacy", "/api/v1/legacy", nil, PaginationUnknown, 25)
	require.ErrorContains(t, err, "unverified pagination contract returned 25 results without continuation or terminal metadata")
	assert.Len(t, got, 25)
	assert.Equal(t, int64(1), requests.Load())
}

func TestClientUnknownPaginationAcceptsExplicitTerminalMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.False(t, r.URL.Query().Has("offset"))
		assert.False(t, r.URL.Query().Has("max"))
		_, _ = w.Write([]byte(`{"items":[{"id":"complete"}],"meta":{"counts":{"remaining":0}}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", PageSize: 500})
	require.NoError(t, err)
	got, err := client.List(t.Context(), "legacy", "/api/v1/legacy", nil, PaginationUnknown, 0)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

func TestDecodeObjectsPreservesLargeInteger(t *testing.T) {
	objects, _, err := decodeObjects([]byte(`{"items":[{"bytes":9007199254740993}]}`), nil)
	require.NoError(t, err)
	require.Len(t, objects, 1)
	value, ok := Int64(objects[0], "bytes")
	require.True(t, ok)
	assert.Equal(t, int64(9007199254740993), value)
}

func TestDecodeObjectsRejectsMalformedRecognizedCollections(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name:    "null",
			body:    `{"items":null}`,
			wantErr: `response field "items" is null, expected an array`,
		},
		{
			name:    "object",
			body:    `{"items":{"id":"fabricated"}}`,
			wantErr: `response field "items" is an object, expected an array`,
		},
		{
			name:    "cluster health envelope with malformed collection",
			body:    `{"isHealthy":true,"nodes":[],"items":null}`,
			wantErr: `response field "items" is null, expected an array`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objects, metadata, err := decodeObjects([]byte(tt.body), nil)
			require.ErrorContains(t, err, tt.wantErr)
			assert.Empty(t, objects)
			assert.Equal(t, paginationMetadata{}, metadata)
		})
	}
}

func TestDecodeObjectsPreservesTrueSingletonObject(t *testing.T) {
	objects, _, err := decodeObjects([]byte(`{"id":"singleton","status":"healthy"}`), nil)
	require.NoError(t, err)
	require.Len(t, objects, 1)
	assert.Equal(t, "singleton", objects[0]["id"])
}

func TestDecodeObjectsPreservesClusterHealthEnvelope(t *testing.T) {
	objects, _, err := decodeObjects([]byte(`{"isHealthy":true,"severity":"info","nodes":[{"name":"node-1"}]}`), nil)
	require.NoError(t, err)
	require.Len(t, objects, 1)
	assert.Equal(t, "info", String(objects[0], "severity"))
	healthy, ok := Bool(objects[0], "isHealthy")
	require.True(t, ok)
	assert.True(t, healthy)
}

func TestScalarStringDoesNotFormatStructuredValues(t *testing.T) {
	obj := Object{
		"map":   map[string]any{"status": "inSync"},
		"array": []any{"active"},
		"bool":  true,
	}
	assert.Empty(t, ScalarString(obj, "map", "array"))
	assert.Equal(t, "true", ScalarString(obj, "map", "array", "bool"))
}

func TestClientRejectsPaginationCycle(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Link", `</api/v1/manage/fabrics>; rel="next"`)
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

	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationLink, 10)
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
	_, err = verifiedClient.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 0)
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
	_, err = passwordClient.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 0)
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

	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 0)
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

	got, err := client.List(t.Context(), "cluster", "/api/v1/infra/cluster/health", nil, PaginationSingle, 1)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, int64(1), logins.Load())
}

func TestClientFallsBackToLegacyLoginAndCachesPath(t *testing.T) {
	var modernLogins atomic.Int64
	var legacyLogins atomic.Int64
	var dataCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case modernLoginPath:
			modernLogins.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"Authorization field missing"}`))
		case legacyLoginPath:
			legacyLogins.Add(1)
			_, _ = w.Write([]byte(`{"jwttoken":"legacy-token"}`))
		default:
			dataCalls.Add(1)
			assert.Equal(t, "Bearer legacy-token", r.Header.Get("Authorization"))
			cookie, err := r.Cookie("AuthCookie")
			if !assert.NoError(t, err) {
				http.Error(w, "missing auth cookie", http.StatusUnauthorized)
				return
			}
			assert.Equal(t, "legacy-token", cookie.Value)
			_, _ = w.Write([]byte(`{"items":[]}`))
		}
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

	var loginStats []RequestStat
	client.OnRequest = func(stat RequestStat) {
		if stat.Operation == "infra.login" {
			loginStats = append(loginStats, stat)
		}
	}

	_, err = client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 1)
	require.NoError(t, err)

	client.tokenMu.Lock()
	client.token = ""
	client.tokenMu.Unlock()
	_, err = client.List(t.Context(), "switches", "/api/v1/manage/switches", nil, PaginationOffset, 1)
	require.NoError(t, err)

	assert.Equal(t, int64(1), modernLogins.Load())
	assert.Equal(t, int64(2), legacyLogins.Load())
	assert.Equal(t, int64(2), dataCalls.Load())
	require.Len(t, loginStats, 3)
	assert.Equal(t, modernLoginPath, loginStats[0].Path)
	assert.Equal(t, "fallback", loginStats[0].Outcome)
	assert.Equal(t, http.StatusUnauthorized, loginStats[0].StatusCode)
	assert.Equal(t, legacyLoginPath, loginStats[1].Path)
	assert.Equal(t, "success", loginStats[1].Outcome)
	assert.Equal(t, legacyLoginPath, loginStats[2].Path)
	assert.Equal(t, "success", loginStats[2].Outcome)
}

func TestClientFallsBackAfterIncompleteUnsupportedLoginResponse(t *testing.T) {
	var modernLogins atomic.Int64
	var legacyLogins atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case modernLoginPath:
			modernLogins.Add(1)
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`unsupported`))
		case legacyLoginPath:
			legacyLogins.Add(1)
			_, _ = w.Write([]byte(`{"jwttoken":"legacy-token"}`))
		default:
			assert.Equal(t, "Bearer legacy-token", r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`{"items":[]}`))
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		AuthMode:   "username_password",
		Username:   "admin",
		Password:   "password",
		MaxRetries: 0,
	})
	require.NoError(t, err)

	_, err = client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 1)
	require.NoError(t, err)
	assert.Equal(t, int64(1), modernLogins.Load())
	assert.Equal(t, int64(1), legacyLogins.Load())
	assert.Equal(t, legacyLoginPath, client.loginPath)
}

func TestLoginEndpointUnsupported(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		err    error
		want   bool
	}{
		{name: "not found", status: http.StatusNotFound, err: &APIError{StatusCode: http.StatusNotFound}, want: true},
		{name: "method not allowed", status: http.StatusMethodNotAllowed, err: &APIError{StatusCode: http.StatusMethodNotAllowed}, want: true},
		{name: "not implemented", status: http.StatusNotImplemented, err: &APIError{StatusCode: http.StatusNotImplemented}, want: true},
		{name: "truncated not found", status: http.StatusNotFound, err: &httpclient.ResponseBodyReadError{Err: io.ErrUnexpectedEOF}, want: true},
		{name: "truncated method not allowed", status: http.StatusMethodNotAllowed, err: &httpclient.ResponseBodyReadError{Err: io.ErrUnexpectedEOF}, want: true},
		{name: "truncated not implemented", status: http.StatusNotImplemented, err: &httpclient.ResponseBodyReadError{Err: io.ErrUnexpectedEOF}, want: true},
		{name: "legacy gateway authorization response", status: http.StatusUnauthorized, body: `{"error":"Authorization field missing"}`, err: &APIError{StatusCode: http.StatusUnauthorized}, want: true},
		{name: "invalid credentials", status: http.StatusUnauthorized, body: `{"error":"Invalid Username/Password"}`, err: &APIError{StatusCode: http.StatusUnauthorized}},
		{name: "body read failure", status: http.StatusUnauthorized, body: `{"error":"Authorization field missing"}`, err: io.ErrUnexpectedEOF},
		{name: "status mismatch", status: http.StatusUnauthorized, body: `{"error":"Authorization field missing"}`, err: &APIError{StatusCode: http.StatusNotFound}},
		{name: "forbidden", status: http.StatusForbidden, err: &APIError{StatusCode: http.StatusForbidden}},
		{name: "rate limited", status: http.StatusTooManyRequests, err: &APIError{StatusCode: http.StatusTooManyRequests}},
		{name: "server error", status: http.StatusInternalServerError, err: &APIError{StatusCode: http.StatusInternalServerError}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, loginEndpointUnsupported(tt.status, []byte(tt.body), tt.err))
		})
	}
}

func TestClientOffsetPaginationContinuesFullPagesWithoutMetadata(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assert.Equal(t, "2", r.URL.Query().Get("max"))
		switch r.URL.Query().Get("offset") {
		case "0":
			_, _ = w.Write([]byte(`{"items":[{"fabricName":"fabric-a"},{"fabricName":"fabric-b"}]}`))
		case "2":
			_, _ = w.Write([]byte(`{"items":[{"fabricName":"fabric-c"},{"fabricName":"fabric-d"}]}`))
		case "4":
			_, _ = w.Write([]byte(`{"items":[{"fabricName":"fabric-e"}]}`))
		default:
			t.Fatalf("unexpected offset %q", r.URL.Query().Get("offset"))
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
		PageSize:   2,
	})
	require.NoError(t, err)

	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 0)
	require.NoError(t, err)
	require.Len(t, got, 5)
	assert.Equal(t, "fabric-a", got[0]["fabricName"])
	assert.Equal(t, "fabric-e", got[4]["fabricName"])
	assert.Equal(t, int64(3), requests.Load())
}

func TestClientOffsetPaginationRejectsMalformedRowsWithMetadata(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch request := requests.Add(1); request {
		case 1:
			assert.Equal(t, "0", r.URL.Query().Get("offset"))
			_, _ = w.Write([]byte(`{"items":[{"id":"a"},{"id":"b"}],"meta":{"counts":{"total":4}}}`))
		case 2:
			assert.Equal(t, "2", r.URL.Query().Get("offset"))
			_, _ = w.Write([]byte(`{"items":[{"id":"c"},null],"meta":{"counts":{"total":4}}}`))
		default:
			t.Fatalf("unexpected request %d at offset %q", request, r.URL.Query().Get("offset"))
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", PageSize: 2})
	require.NoError(t, err)
	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 0)
	require.ErrorContains(t, err, "decode nexus dashboard fabrics response page 2 from /api/v1/manage/fabrics")
	require.ErrorContains(t, err, `response field "items" row 1 is null, expected object`)
	require.Len(t, got, 2)
	assert.Equal(t, []any{"a", "b"}, []any{got[0]["id"], got[1]["id"]})
	assert.Equal(t, int64(2), requests.Load())
}

func TestClientOffsetPaginationRejectsMalformedRecognizedCollectionsWithoutAdvancing(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name:    "null",
			body:    `{"items":null,"meta":{"counts":{"total":2}}}`,
			wantErr: `response field "items" is null, expected an array`,
		},
		{
			name:    "object",
			body:    `{"items":{"id":"fabricated"},"meta":{"counts":{"total":2}}}`,
			wantErr: `response field "items" is an object, expected an array`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var offsetsMu sync.Mutex
			var offsets []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				offsetsMu.Lock()
				offsets = append(offsets, r.URL.Query().Get("offset"))
				offsetsMu.Unlock()
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", PageSize: 1})
			require.NoError(t, err)
			got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 0)
			require.ErrorContains(t, err, "decode nexus dashboard fabrics response page 1")
			require.ErrorContains(t, err, tt.wantErr)
			assert.Empty(t, got)

			offsetsMu.Lock()
			defer offsetsMu.Unlock()
			assert.Equal(t, []string{"0"}, offsets)
		})
	}
}

func TestClientOffsetPaginationRejectsMalformedRowsWithoutMetadata(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assert.Equal(t, "0", r.URL.Query().Get("offset"))
		_, _ = w.Write([]byte(`{"items":[{"id":"a"},"malformed"]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", PageSize: 2})
	require.NoError(t, err)
	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 0)
	require.ErrorContains(t, err, "decode nexus dashboard fabrics response page 1 from /api/v1/manage/fabrics")
	require.ErrorContains(t, err, `response field "items" row 1 is a string, expected object`)
	assert.Empty(t, got)
	assert.Equal(t, int64(1), requests.Load())
}

func TestClientOffsetPaginationContinuesShortPagesWhileRemainingClaimsMore(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assert.Equal(t, "4", r.URL.Query().Get("max"))
		switch r.URL.Query().Get("offset") {
		case "0":
			_, _ = w.Write([]byte(`{"items":[{"id":"a"},{"id":"b"}],"meta":{"counts":{"remaining":3}}}`))
		case "2":
			_, _ = w.Write([]byte(`{"items":[{"id":"c"}],"meta":{"counts":{"remaining":2}}}`))
		case "3":
			_, _ = w.Write([]byte(`{"items":[{"id":"d"},{"id":"e"}],"meta":{"counts":{"remaining":0}}}`))
		default:
			t.Fatalf("unexpected offset %q", r.URL.Query().Get("offset"))
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", PageSize: 4})
	require.NoError(t, err)
	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 0)
	require.NoError(t, err)
	assert.Len(t, got, 5)
	assert.Equal(t, int64(3), requests.Load())
}

func TestClientOffsetPaginationContinuesShortPagesWhileTotalClaimsMore(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assert.Equal(t, "4", r.URL.Query().Get("max"))
		switch r.URL.Query().Get("offset") {
		case "0":
			_, _ = w.Write([]byte(`{"items":[{"id":"a"},{"id":"b"}],"meta":{"counts":{"total":5}}}`))
		case "2":
			_, _ = w.Write([]byte(`{"items":[{"id":"c"}],"meta":{"counts":{"total":5}}}`))
		case "3":
			_, _ = w.Write([]byte(`{"items":[{"id":"d"},{"id":"e"}],"meta":{"counts":{"total":5}}}`))
		default:
			t.Fatalf("unexpected offset %q", r.URL.Query().Get("offset"))
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", PageSize: 4})
	require.NoError(t, err)
	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 0)
	require.NoError(t, err)
	assert.Len(t, got, 5)
	assert.Equal(t, int64(3), requests.Load())
}

func TestClientOffsetPaginationProbesAfterExactFullBoundaryWithoutMetadata(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Query().Get("offset") {
		case "0":
			_, _ = w.Write([]byte(`{"items":[{"id":"a"},{"id":"b"}]}`))
		case "2":
			_, _ = w.Write([]byte(`{"items":[{"id":"c"},{"id":"d"}]}`))
		case "4":
			_, _ = w.Write([]byte(`{"items":[]}`))
		default:
			t.Fatalf("unexpected offset %q", r.URL.Query().Get("offset"))
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", PageSize: 2})
	require.NoError(t, err)
	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 0)
	require.NoError(t, err)
	assert.Len(t, got, 4)
	assert.Equal(t, int64(3), requests.Load())
}

func TestClientOffsetPaginationStopsAtKnownExactBoundary(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := requests.Add(1)
		switch r.URL.Query().Get("offset") {
		case "0":
			_, _ = w.Write([]byte(`{"items":[{"id":"a"},{"id":"b"}],"meta":{"counts":{"total":4}}}`))
		case "2":
			_, _ = w.Write([]byte(`{"items":[{"id":"c"},{"id":"d"}],"meta":{"counts":{"total":4}}}`))
		default:
			t.Fatalf("unexpected request %d offset %q", request, r.URL.Query().Get("offset"))
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", PageSize: 2})
	require.NoError(t, err)
	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 0)
	require.NoError(t, err)
	assert.Len(t, got, 4)
	assert.Equal(t, int64(2), requests.Load())
}

func TestClientConfiguredResultLimitStopsAtExactBoundary(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		request := requests.Add(1)
		_, _ = fmt.Fprintf(w, `{"items":[{"id":"%d-a"},{"id":"%d-b"}]}`, request, request)
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", PageSize: 2})
	require.NoError(t, err)
	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 4)
	require.NoError(t, err)
	assert.Len(t, got, 4)
	assert.Equal(t, int64(2), requests.Load())
}

func TestClientConfiguredResultLimitCountsUniqueObjectsAcrossOverlappingPages(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Query().Get("offset") {
		case "0":
			assert.Equal(t, "2", r.URL.Query().Get("max"))
			_, _ = w.Write([]byte(`{"items":[{"id":"a"},{"id":"b"}]}`))
		case "2":
			assert.Equal(t, "2", r.URL.Query().Get("max"))
			_, _ = w.Write([]byte(`{"items":[{"id":"b"},{"id":"c"}]}`))
		case "4":
			assert.Equal(t, "1", r.URL.Query().Get("max"))
			_, _ = w.Write([]byte(`{"items":[{"id":"d"}]}`))
		default:
			t.Fatalf("unexpected offset %q", r.URL.Query().Get("offset"))
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", PageSize: 2})
	require.NoError(t, err)
	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 4)
	require.NoError(t, err)
	require.Len(t, got, 4)
	assert.Equal(t, []any{"a", "b", "c", "d"}, []any{got[0]["id"], got[1]["id"], got[2]["id"], got[3]["id"]})
	assert.Equal(t, int64(3), requests.Load())
}

func TestClientOffsetPaginationPreservesSamePageDuplicatesAndFiltersPriorPageOverlap(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Query().Get("offset") {
		case "0":
			assert.Equal(t, "2", r.URL.Query().Get("max"))
			_, _ = w.Write([]byte(`{"items":[{"id":"same"},{"id":"same"}],"meta":{"counts":{"total":4}}}`))
		case "2":
			assert.Equal(t, "2", r.URL.Query().Get("max"))
			_, _ = w.Write([]byte(`{"items":[{"id":"same"},{"id":"new"}],"meta":{"counts":{"total":4}}}`))
		default:
			t.Fatalf("unexpected offset %q", r.URL.Query().Get("offset"))
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", PageSize: 2})
	require.NoError(t, err)
	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 0)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, []any{"same", "same", "new"}, []any{got[0]["id"], got[1]["id"], got[2]["id"]})
	assert.Equal(t, int64(2), requests.Load())
}

func TestClientOffsetPaginationHonorsExplicitNextAndRemaining(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch requests.Add(1) {
		case 1:
			assert.Equal(t, "0", r.URL.Query().Get("offset"))
			assert.Equal(t, "2", r.URL.Query().Get("max"))
			_, _ = w.Write([]byte(`{"items":[{"id":"a"},{"id":"b"}],"meta":{"counts":{"remaining":1},"links":{"next":"/api/v1/manage/fabrics?offset=7&max=1&filter=active"}}}`))
		case 2:
			assert.Equal(t, "7", r.URL.Query().Get("offset"))
			assert.Equal(t, "1", r.URL.Query().Get("max"))
			assert.Equal(t, "active", r.URL.Query().Get("filter"))
			_, _ = w.Write([]byte(`{"items":[{"id":"c"}],"meta":{"counts":{"remaining":0}}}`))
		default:
			t.Fatalf("unexpected request")
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", PageSize: 2})
	require.NoError(t, err)
	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 0)
	require.NoError(t, err)
	assert.Len(t, got, 3)
	assert.Equal(t, int64(2), requests.Load())
}

func TestClientOffsetPaginationRejectsRepeatedFullPage(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"items":[{"id":"a"},{"id":"b"}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", PageSize: 2})
	require.NoError(t, err)
	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 0)
	require.ErrorContains(t, err, "made no progress")
	assert.Len(t, got, 2)
	assert.Equal(t, int64(2), requests.Load())
}

func TestClientPaginationPreservesCancellationBetweenPages(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"items":[{"id":"a"}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", PageSize: 1})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	client.OnRequest = func(stat RequestStat) {
		if stat.Operation == "fabrics" && stat.Outcome == "success" {
			cancel()
		}
	}
	got, err := client.List(ctx, "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 0)
	require.ErrorIs(t, err, context.Canceled)
	assert.Len(t, got, 1)
	assert.Equal(t, int64(1), requests.Load())
}

func TestClientPaginationEnforcesAggregateByteBudget(t *testing.T) {
	firstBody := `{"items":[{"id":"first","padding":"1234567890"}]}`
	secondBody := `{"items":[{"id":"second","padding":"1234567890"}]}`
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			_, _ = w.Write([]byte(firstBody))
			return
		}
		_, _ = w.Write([]byte(secondBody))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "api_key", Username: "admin", APIKey: "key", PageSize: 1})
	require.NoError(t, err)
	client.maxPaginationBytes = len(firstBody) + len(secondBody) - 1
	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 0)
	var limitErr *httpclient.PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.Equal(t, "byte", limitErr.Kind)
	assert.Len(t, got, 1)
	assert.Equal(t, int64(2), requests.Load())
}

func TestClientPaginationHardPageLimitReturnsPartialResults(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := requests.Add(1)
		_, _ = fmt.Fprintf(w, `{"items":[{"fabricName":"fabric-%s-%d"}],"pagination":{"remaining":1}}`, r.URL.Query().Get("offset"), request)
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

	got, err := client.List(t.Context(), "fabrics", "/api/v1/manage/fabrics", nil, PaginationOffset, 0)
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
