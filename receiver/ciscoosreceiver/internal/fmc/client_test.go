// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package fmc

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

func TestClientRetryValidationPreservesExplicitZero(t *testing.T) {
	client, err := NewClient(Config{Endpoint: "https://fmc.example.test", Username: "admin", Password: "password", MaxRetries: 0})
	require.NoError(t, err)
	assert.Zero(t, client.retries)
	for _, retries := range []int{-1, httpclient.HardMaxRequestRetries + 1} {
		_, err = NewClient(Config{Endpoint: "https://fmc.example.test", Username: "admin", Password: "password", MaxRetries: retries})
		require.ErrorContains(t, err, "invalid fmc max retries")
	}
}

func TestClientRetriesIncompleteSuccessfulResponseBody(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/fmc_platform/v1/auth/generatetoken" {
			w.Header().Set("X-auth-access-token", "access-token")
			w.Header().Set("DOMAIN_UUID", "domain-1")
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if requests.Add(1) == 1 {
			w.Header().Set("Content-Length", "100")
			w.Header().Set("Retry-After", "0")
			_, _ = w.Write([]byte(`{"items":`))
			return
		}
		_, _ = w.Write([]byte(`{"items":[],"paging":{"count":0}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", MaxRetries: 1})
	require.NoError(t, err)
	objects, err := client.List(t.Context(), "test.list", "/api/fmc_config/v1/domain/domain-1/test", nil, 10)
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
			name: "invalid successful token response",
			authenticate: func(w http.ResponseWriter, _ int64) {
				w.WriteHeader(http.StatusNoContent)
			},
			wantErr:          "did not include X-auth-access-token",
			wantAuthRequests: 1,
		},
		{
			name: "transient authentication server failure",
			authenticate: func(w http.ResponseWriter, attempt int64) {
				if attempt == 1 {
					http.Error(w, "unavailable", http.StatusServiceUnavailable)
					return
				}
				w.Header().Set("X-auth-access-token", "access-1")
				w.WriteHeader(http.StatusNoContent)
			},
			wantAuthRequests: 2,
		},
		{
			name: "incomplete successful authentication body",
			authenticate: func(w http.ResponseWriter, attempt int64) {
				if attempt == 1 {
					w.Header().Set("Content-Length", "100")
					w.Header().Set("Retry-After", "0")
					_, _ = w.Write([]byte(`{`))
					return
				}
				w.Header().Set("X-auth-access-token", "access-1")
				w.WriteHeader(http.StatusNoContent)
			},
			wantAuthRequests: 2,
		},
		{
			name: "persistent authentication server failure uses one retry budget",
			authenticate: func(w http.ResponseWriter, _ int64) {
				w.Header().Set("Retry-After", "0")
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
			},
			wantErr:          "HTTP 503",
			wantAuthRequests: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var authRequests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/fmc_platform/v1/auth/generatetoken" {
					tt.authenticate(w, authRequests.Add(1))
					return
				}
				_, _ = w.Write([]byte(`{"items":[]}`))
			}))
			defer server.Close()

			client, err := NewClient(Config{
				Endpoint:   server.URL,
				Username:   "admin",
				Password:   "password",
				Timeout:    time.Second,
				MaxRetries: 1,
			})
			require.NoError(t, err)

			_, err = client.List(t.Context(), "devices", "/api/fmc_config/v1/devices", nil, 1)
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
		if r.URL.Path == "/api/fmc_platform/v1/auth/generatetoken" {
			w.Header().Set("X-auth-access-token", "access-1")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 1,
	})
	require.NoError(t, err)
	transport := &failOnceTransport{next: client.client.Transport, path: "/api/fmc_platform/v1/auth/generatetoken"}
	client.client.Transport = transport

	_, err = client.List(t.Context(), "devices", "/api/fmc_config/v1/devices", nil, 1)
	require.NoError(t, err)
	assert.Equal(t, int64(2), transport.attempts.Load())
}

func TestClientDomainUUIDAuthenticationRetryPolicy(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var authRequests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/api/fmc_platform/v1/auth/generatetoken", r.URL.Path)
				if authRequests.Add(1) == 1 {
					w.Header().Set("Retry-After", "0")
					http.Error(w, http.StatusText(status), status)
					return
				}
				w.Header().Set("X-auth-access-token", "access-1")
				w.Header().Set("DOMAIN_UUID", "domain-1")
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			client, err := NewClient(Config{
				Endpoint:   server.URL,
				Username:   "admin",
				Password:   "password",
				Timeout:    time.Second,
				MaxRetries: 1,
			})
			require.NoError(t, err)

			domain, err := client.DomainUUID(t.Context())
			require.NoError(t, err)
			assert.Equal(t, "domain-1", domain)
			assert.Equal(t, int64(2), authRequests.Load())
		})
	}

	t.Run("transport failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/fmc_platform/v1/auth/generatetoken", r.URL.Path)
			w.Header().Set("X-auth-access-token", "access-1")
			w.Header().Set("DOMAIN_UUID", "domain-1")
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		client, err := NewClient(Config{
			Endpoint:   server.URL,
			Username:   "admin",
			Password:   "password",
			Timeout:    time.Second,
			MaxRetries: 1,
		})
		require.NoError(t, err)
		transport := &failOnceTransport{next: client.client.Transport, path: "/api/fmc_platform/v1/auth/generatetoken"}
		client.client.Transport = transport

		domain, err := client.DomainUUID(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "domain-1", domain)
		assert.Equal(t, int64(2), transport.attempts.Load())
	})

	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status)+" is not retried", func(t *testing.T) {
			var authRequests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/api/fmc_platform/v1/auth/generatetoken", r.URL.Path)
				authRequests.Add(1)
				http.Error(w, http.StatusText(status), status)
			}))
			defer server.Close()

			client, err := NewClient(Config{
				Endpoint:   server.URL,
				Username:   "admin",
				Password:   "password",
				Timeout:    time.Second,
				MaxRetries: 3,
			})
			require.NoError(t, err)

			_, err = client.DomainUUID(t.Context())
			require.ErrorContains(t, err, "HTTP "+strconv.Itoa(status))
			assert.Equal(t, int64(1), authRequests.Load())
		})
	}
}

func TestClientStaleUnauthorizedDoesNotClearNewerToken(t *testing.T) {
	var authRequests atomic.Int64
	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(releaseSlow)
		}
	}()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/fmc_platform/v1/auth/generatetoken":
			attempt := authRequests.Add(1)
			w.Header().Set("X-auth-access-token", "access-"+strconv.FormatInt(attempt, 10))
			w.WriteHeader(http.StatusNoContent)
		case "/slow":
			assert.Equal(t, "access-1", r.Header.Get("X-auth-access-token"))
			close(slowStarted)
			<-releaseSlow
			http.Error(w, "expired", http.StatusUnauthorized)
		case "/fast":
			assert.Equal(t, "access-2", r.Header.Get("X-auth-access-token"))
			_, _ = w.Write([]byte(`{"items":[]}`))
		default:
			http.NotFound(w, r)
		}
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

	slowErr := make(chan error, 1)
	go func() {
		_, requestErr := client.List(t.Context(), "slow", "/slow", nil, 1)
		slowErr <- requestErr
	}()

	select {
	case <-slowStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for slow request")
	}

	client.tokenMu.Lock()
	client.tokenAt = time.Now().Add(-tokenRefreshAfter)
	client.tokenMu.Unlock()

	_, err = client.List(t.Context(), "fast", "/fast", nil, 1)
	require.NoError(t, err)
	close(releaseSlow)
	released = true
	require.ErrorContains(t, <-slowErr, "HTTP 401")

	client.tokenMu.Lock()
	snapshot := client.tokenSnapshotLocked()
	authFailures := client.authFailures
	client.tokenMu.Unlock()
	assert.Equal(t, tokenSnapshot{accessToken: "access-2", generation: 2}, snapshot)
	assert.Zero(t, authFailures)
	assert.Equal(t, int64(2), authRequests.Load())
}

func TestClientUnauthorizedBackoffIsSharedAcrossEndpoints(t *testing.T) {
	var authRequests atomic.Int64
	var dataRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/fmc_platform/v1/auth/generatetoken" {
			attempt := authRequests.Add(1)
			w.Header().Set("X-auth-access-token", "access-"+strconv.FormatInt(attempt, 10))
			w.WriteHeader(http.StatusNoContent)
			return
		}
		dataRequests.Add(1)
		if r.URL.Path == "/success" {
			_, _ = w.Write([]byte(`{"items":[]}`))
			return
		}
		http.Error(w, "expired", http.StatusUnauthorized)
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

	_, err = client.List(t.Context(), "first", "/first", nil, 1)
	require.ErrorContains(t, err, "HTTP 401")
	_, err = client.List(t.Context(), "second", "/second", nil, 1)
	require.ErrorContains(t, err, "HTTP 401")
	assert.Equal(t, int64(1), authRequests.Load())
	assert.Equal(t, int64(1), dataRequests.Load())

	client.tokenMu.Lock()
	assert.Equal(t, 1, client.authFailures)
	client.lastAuthAt = time.Now().Add(-fmcAuthBackoffFor(client.authFailures))
	client.tokenMu.Unlock()

	// The new login succeeds, but the streak remains until its token succeeds
	// on a data request. A second 401 therefore advances to the longer backoff.
	_, err = client.List(t.Context(), "second", "/second", nil, 1)
	require.ErrorContains(t, err, "HTTP 401")
	client.tokenMu.Lock()
	assert.Equal(t, 2, client.authFailures)
	client.tokenMu.Unlock()

	_, err = client.List(t.Context(), "third", "/third", nil, 1)
	require.ErrorContains(t, err, "HTTP 401")
	assert.Equal(t, int64(2), authRequests.Load())
	assert.Equal(t, int64(2), dataRequests.Load())

	client.tokenMu.Lock()
	client.lastAuthAt = time.Now().Add(-fmcAuthBackoffFor(client.authFailures))
	client.tokenMu.Unlock()
	_, err = client.List(t.Context(), "success", "/success", nil, 1)
	require.NoError(t, err)
	client.tokenMu.Lock()
	assert.Zero(t, client.authFailures)
	client.tokenMu.Unlock()
	assert.Equal(t, int64(3), authRequests.Load())
	assert.Equal(t, int64(3), dataRequests.Load())
}

func TestClientAuthenticationFailureBackoffIsSharedAcrossEndpoints(t *testing.T) {
	var authRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		authRequests.Add(1)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
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

	for _, path := range []string{"/first", "/second"} {
		_, requestErr := client.List(t.Context(), path, path, nil, 1)
		require.ErrorContains(t, requestErr, "HTTP 401")
	}
	assert.Equal(t, int64(1), authRequests.Load())
}

func TestClientForbiddenDoesNotClearTokenOrReauthenticate(t *testing.T) {
	var authRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/fmc_platform/v1/auth/generatetoken":
			authRequests.Add(1)
			w.Header().Set("X-auth-access-token", "access-1")
			w.WriteHeader(http.StatusNoContent)
		case "/forbidden":
			assert.Equal(t, "access-1", r.Header.Get("X-auth-access-token"))
			http.Error(w, "forbidden", http.StatusForbidden)
		case "/allowed":
			assert.Equal(t, "access-1", r.Header.Get("X-auth-access-token"))
			_, _ = w.Write([]byte(`{"items":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 1,
	})
	require.NoError(t, err)

	_, err = client.List(t.Context(), "forbidden", "/forbidden", nil, 1)
	require.ErrorContains(t, err, "HTTP 403")
	_, err = client.List(t.Context(), "allowed", "/allowed", nil, 1)
	require.NoError(t, err)

	client.tokenMu.Lock()
	snapshot := client.tokenSnapshotLocked()
	client.tokenMu.Unlock()
	assert.Equal(t, "access-1", snapshot.accessToken)
	assert.Equal(t, int64(1), authRequests.Load())
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

func TestClientTokenAndPagination(t *testing.T) {
	var sawToken bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/fmc_platform/v1/auth/generatetoken":
			assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:password")), r.Header.Get("Authorization"))
			w.Header().Set("X-auth-access-token", "access-1")
			w.Header().Set("X-auth-refresh-token", "refresh-1")
			w.Header().Set("DOMAIN_UUID", "domain-1")
			w.WriteHeader(http.StatusNoContent)
		case "/api/fmc_config/v1/domain/domain-1/devices/devicerecords":
			assert.Equal(t, "access-1", r.Header.Get("X-auth-access-token"))
			sawToken = true
			switch r.URL.Query().Get("offset") {
			case "0":
				_, _ = w.Write([]byte(`{"items":[{"id":"dev-1","name":"ftd-1"},{"id":"dev-2","name":"asa-1"}],"paging":{"count":3}}`))
			case "2":
				_, _ = w.Write([]byte(`{"items":[{"id":"dev-3","name":"ftd-2"}],"paging":{"count":3}}`))
			default:
				t.Fatalf("unexpected offset %q", r.URL.Query().Get("offset"))
			}
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		Username:   "admin",
		Password:   "password",
		PageSize:   2,
		MaxRetries: 1,
	})
	require.NoError(t, err)

	domain, err := client.DomainUUID(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "domain-1", domain)

	objects, err := client.List(t.Context(), "devices.records", "/api/fmc_config/v1/domain/domain-1/devices/devicerecords", nil, 0)
	require.NoError(t, err)
	require.Len(t, objects, 3)
	assert.Equal(t, "ftd-1", String(objects[0], "name"))
	assert.True(t, sawToken)
}

func TestClientPaginationContinuesAfterShortPageWhenNextLinkExists(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/fmc_platform/v1/auth/generatetoken" {
			w.Header().Set("X-auth-access-token", "access-1")
			w.Header().Set("DOMAIN_UUID", "domain-1")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		assert.Equal(t, "/events", r.URL.Path)
		assert.Equal(t, "2", r.URL.Query().Get("limit"))
		requests.Add(1)
		switch r.URL.Query().Get("offset") {
		case "0":
			_, _ = w.Write([]byte(`{"items":[{"id":"event-1"}],"paging":{"next":"/events?offset=1"}}`))
		case "1":
			_, _ = w.Write([]byte(`{"items":[{"id":"event-2"}],"paging":{}}`))
		default:
			t.Fatalf("unexpected FMC offset %q", r.URL.Query().Get("offset"))
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

	got, err := client.List(t.Context(), "events", "/events", nil, 0)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "event-1", String(got[0], "id"))
	assert.Equal(t, "event-2", String(got[1], "id"))
	assert.Equal(t, int64(2), requests.Load())
}

func TestClientSupportsSelfSignedTLSWithInsecureSkipVerify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/fmc_platform/v1/auth/generatetoken", r.URL.Path)
		w.Header().Set("X-auth-access-token", "access-1")
		w.Header().Set("X-auth-refresh-token", "refresh-1")
		w.Header().Set("DOMAIN_UUID", "domain-1")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	verifiedClient, err := NewClient(Config{
		Endpoint:   server.URL,
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 3,
	})
	require.NoError(t, err)
	verifiedAttempts := 0
	verifiedClient.OnRequest = func(RequestStat) { verifiedAttempts++ }
	// A deterministic refresh certificate failure must not fall through to a
	// second generate-token attempt against the same endpoint.
	verifiedClient.tokenMu.Lock()
	verifiedClient.refreshToken = "refresh-1"
	verifiedClient.tokenMu.Unlock()
	_, err = verifiedClient.DomainUUID(t.Context())
	require.ErrorContains(t, err, "trust the issuing CA in the Collector host trust store (preferred)")
	require.ErrorContains(t, err, "set fmc.insecure_skip_verify: true")
	assert.Equal(t, 1, verifiedAttempts)

	client, err := NewClient(Config{
		Endpoint:           server.URL,
		Username:           "admin",
		Password:           "password",
		MaxRetries:         1,
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)

	domain, err := client.DomainUUID(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "domain-1", domain)
}

func TestClientPaginationHardPageLimitReturnsPartialResults(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/fmc_platform/v1/auth/generatetoken" {
			w.Header().Set("X-auth-access-token", "access-1")
			w.Header().Set("DOMAIN_UUID", "domain-1")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		offset := r.URL.Query().Get("offset")
		requests.Add(1)
		_, _ = w.Write([]byte(`{"items":[{"id":"` + offset + `"}],"paging":{"count":` + strconv.Itoa(httpclient.HardMaxPaginationPages+1) + `}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 1, PageSize: 1})
	require.NoError(t, err)

	got, err := client.List(t.Context(), "events", "/api/fmc_eventing/v1/domain/domain-1/events", nil, 0)
	var limitErr *httpclient.PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.Equal(t, "page", limitErr.Kind)
	assert.Len(t, got, httpclient.HardMaxPaginationPages)
	assert.Equal(t, int64(httpclient.HardMaxPaginationPages), requests.Load())
}

func TestClientRejectsFixedOffsetPaginationCycle(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/fmc_platform/v1/auth/generatetoken" {
			w.Header().Set("X-auth-access-token", "access-1")
			w.Header().Set("DOMAIN_UUID", "domain-1")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		requests.Add(1)
		_, _ = w.Write([]byte(`{"items":[{"id":"event-1"}],"paging":{"count":2}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 1, PageSize: 1})
	require.NoError(t, err)

	got, err := client.List(t.Context(), "events", "/api/fmc_eventing/v1/domain/domain-1/events", url.Values{"offset": {"0"}}, 0)
	require.ErrorContains(t, err, "continuation cycle")
	assert.Len(t, got, 1)
	assert.Equal(t, int64(1), requests.Load())
}

func TestClientPaginationAdvancesByOverReturnedObjectCount(t *testing.T) {
	var offsets []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/fmc_platform/v1/auth/generatetoken" {
			w.Header().Set("X-auth-access-token", "access-1")
			w.Header().Set("DOMAIN_UUID", "domain-1")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		offset := r.URL.Query().Get("offset")
		offsets = append(offsets, offset)
		switch offset {
		case "0":
			_, _ = w.Write([]byte(`{"items":[{"id":"event-0"},{"id":"event-1"}],"paging":{"count":3}}`))
		case "2":
			_, _ = w.Write([]byte(`{"items":[{"id":"event-2"}],"paging":{"count":3}}`))
		default:
			t.Fatalf("unexpected overlapping offset %q", offset)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 1, PageSize: 1})
	require.NoError(t, err)

	got, err := client.List(t.Context(), "events", "/api/fmc_eventing/v1/domain/domain-1/events", nil, 0)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, []string{"0", "2"}, offsets)
	assert.Equal(t, "event-2", got[2]["id"])
}

func TestDecodeEStreamerBundle(t *testing.T) {
	eventPayload := encodeEStreamerRecord(0, 400, time.Time{}, []byte(`{"EventType":"ConnectionEvent","InitiatorIP":"10.0.0.1","ResponderIP":"10.0.0.2"}`))
	eventMessage := encodeEStreamerMessage(estreamerMessageEventV3, eventPayload)
	bundle := make([]byte, 8)
	bundle = append(bundle, eventMessage...)

	events, err := decodeEStreamerBundle("fmc-1", bundle)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "fmc-1", events[0].Controller)
	assert.Equal(t, "connection_event", events[0].EventType)
	assert.Equal(t, "10.0.0.1", String(events[0].Body, "InitiatorIP"))
}

func TestFMCGenericDecodersPreserveLargeIntegers(t *testing.T) {
	objects, _, _, err := decodeObjects([]byte(`{"items":[{"counter":9007199254740993}]}`))
	require.NoError(t, err)
	require.Len(t, objects, 1)
	number, ok := objects[0]["counter"].(json.Number)
	require.True(t, ok)
	assert.Equal(t, "9007199254740993", number.String())

	eventPayload := encodeEStreamerRecord(0, 400, time.Time{}, []byte(`{"EventType":"ConnectionEvent","counter":9007199254740993}`))
	event, err := decodeEStreamerEvent("fmc-1", eventPayload)
	require.NoError(t, err)
	number, ok = event.Body["counter"].(json.Number)
	require.True(t, ok)
	assert.Equal(t, "9007199254740993", number.String())
}

func TestDecodeEStreamerBundleRejectsMoreThanHardRecordLimit(t *testing.T) {
	eventHeader := encodeEStreamerMessage(estreamerMessageEventV3, encodeEStreamerRecord(0, 400, time.Time{}, nil))
	bundle := make([]byte, 8, 8+len(eventHeader)*(estreamerMaxBundleRecords+1))
	bundle = append(bundle, bytes.Repeat(eventHeader, estreamerMaxBundleRecords+1)...)

	events, err := decodeEStreamerBundle("fmc-1", bundle)
	require.ErrorContains(t, err, "hard record/event limit")
	assert.Len(t, events, estreamerMaxBundleRecords)
}

func TestDecodeEStreamerBundleNullRecordsCannotBypassHardLimit(t *testing.T) {
	nullHeader := encodeEStreamerMessage(estreamerMessageNull, nil)
	bundle := make([]byte, 8, 8+len(nullHeader)*(estreamerMaxBundleRecords+1))
	bundle = append(bundle, bytes.Repeat(nullHeader, estreamerMaxBundleRecords+1)...)

	events, err := decodeEStreamerBundle("fmc-1", bundle)
	require.ErrorContains(t, err, "hard record/event limit")
	assert.Empty(t, events)
}

func TestDecodeEStreamerErrorDoesNotExposeServerPayload(t *testing.T) {
	payload := make([]byte, 6)
	binary.BigEndian.PutUint32(payload[:4], 17)
	binary.BigEndian.PutUint16(payload[4:6], uint16(len("server-secret")))
	payload = append(payload, "server-secret"...)

	err := decodeEStreamerError(payload)
	require.Error(t, err)
	assert.ErrorContains(t, err, "code=17")
	assert.ErrorContains(t, err, fmt.Sprintf("payload_length=%d", len(payload)))
	assert.ErrorContains(t, err, "payload_sha256=")
	assert.NotContains(t, err.Error(), "server-secret")

	shortErr := decodeEStreamerError([]byte("raw-secret"[:3]))
	require.Error(t, shortErr)
	assert.ErrorContains(t, shortErr, "code=unavailable")
	assert.NotContains(t, shortErr.Error(), "raw")
}

func TestNewEStreamerClientEnforcesHardMessageLimit(t *testing.T) {
	client, err := NewEStreamerClient(EStreamerConfig{Address: "fmc.example.test:8302"})
	require.NoError(t, err)
	assert.Equal(t, estreamerMaxMessageBytes, client.maxMessageBytes)

	client, err = NewEStreamerClient(EStreamerConfig{Address: "fmc.example.test:8302", MaxMessageBytes: estreamerMaxMessageBytes})
	require.NoError(t, err)
	assert.Equal(t, estreamerMaxMessageBytes, client.maxMessageBytes)

	for _, maxBytes := range []int{-1, estreamerMaxMessageBytes + 1} {
		_, err = NewEStreamerClient(EStreamerConfig{Address: "fmc.example.test:8302", MaxMessageBytes: maxBytes})
		require.ErrorContains(t, err, "max message bytes")
	}
}

func TestNewEStreamerClientAddsDefaultPortToIPv6Address(t *testing.T) {
	client, err := NewEStreamerClient(EStreamerConfig{Address: "2001:db8::10"})
	require.NoError(t, err)
	assert.Equal(t, "[2001:db8::10]:8302", client.Address())
}

func TestDecodeEStreamerEventDoesNotForwardMalformedRawPayload(t *testing.T) {
	payload := encodeEStreamerRecord(0, 400, time.Time{}, []byte(`{"password":"do-not-export"`))
	event, err := decodeEStreamerEvent("fmc-1", payload)
	require.NoError(t, err)
	assert.Equal(t, "decode_error", event.EventType)
	assert.Empty(t, event.Raw)
	assert.Equal(t, true, event.Body["decode_error"])
	assert.Len(t, String(event.Body, "payload_sha256"), 64)
	assert.NotContains(t, fmt.Sprint(event.Body), "do-not-export")
}

func TestDecodeEStreamerEventDoesNotRetainSuccessfulFramingText(t *testing.T) {
	payload := encodeEStreamerRecord(0, 400, time.Time{}, []byte(`password=prefix-secret {"EventType":"ConnectionEvent","id":"event-1"} password=suffix-secret`))
	event, err := decodeEStreamerEvent("fmc-1", payload)
	require.NoError(t, err)
	assert.Equal(t, "connection_event", event.EventType)
	assert.Empty(t, event.Raw)
	assert.Equal(t, "event-1", String(event.Body, "id"))
	assert.NotContains(t, fmt.Sprint(event.Body), "prefix-secret")
	assert.NotContains(t, fmt.Sprint(event.Body), "suffix-secret")
}

func TestDecodeEStreamerExtendedRecordUsesDeclaredContentLength(t *testing.T) {
	timestamp := time.Unix(1_800_000_123, 0).UTC()
	payload := encodeEStreamerRecord(17, 401, timestamp, []byte(`{"EventType":"IntrusionEvent","id":"event-1"}`))

	event, err := decodeEStreamerEvent("fmc-1", payload)
	require.NoError(t, err)
	assert.Equal(t, uint32(401), event.RecordType)
	assert.Equal(t, timestamp, event.Timestamp)
	assert.Equal(t, "intrusion_event", event.EventType)
	assert.Equal(t, "event-1", String(event.Body, "id"))
}

func TestDecodeEStreamerEventRejectsMalformedRecordFraming(t *testing.T) {
	payload := encodeEStreamerRecord(17, 401, time.Unix(1_800_000_123, 0), []byte(`{"id":"event-1"}`))

	_, err := decodeEStreamerEvent("fmc-1", payload[:estreamerExtendedRecordHeaderLen-1])
	require.ErrorContains(t, err, "extended event record header is truncated")

	binary.BigEndian.PutUint32(payload[4:8], uint32(len(payload)))
	_, err = decodeEStreamerEvent("fmc-1", payload)
	require.ErrorContains(t, err, "record length")
}

func encodeEStreamerRecord(netmapID, recordType uint16, timestamp time.Time, data []byte) []byte {
	headerLength := estreamerRecordHeaderLen
	if !timestamp.IsZero() {
		headerLength = estreamerExtendedRecordHeaderLen
		netmapID |= estreamerExtendedRecordFlag
	}
	payload := make([]byte, headerLength+len(data))
	binary.BigEndian.PutUint16(payload[0:2], netmapID)
	binary.BigEndian.PutUint16(payload[2:4], recordType)
	binary.BigEndian.PutUint32(payload[4:8], uint32(len(data)))
	if headerLength == estreamerExtendedRecordHeaderLen {
		binary.BigEndian.PutUint32(payload[8:12], uint32(timestamp.Unix()))
	}
	copy(payload[headerLength:], data)
	return payload
}

func TestNormalizeFQEEventTypesSupportsOperationalAliases(t *testing.T) {
	assert.Equal(t,
		[]string{"connection", "file", "intrusion_packet"},
		normalizeFQEEventTypes([]string{"security_intelligence", "malware", "IntrusionPacket"}),
	)
}

func TestEStreamerRunCancellationInterruptsIdleRead(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	client, err := NewEStreamerClient(EStreamerConfig{
		Address:     "fmc.example.test:8302",
		ReadTimeout: time.Hour,
	})
	require.NoError(t, err)
	client.dialContext = func(context.Context, string, string) (net.Conn, error) {
		return clientConn, nil
	}

	requestReceived := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		for range 2 {
			headerBytes := make([]byte, estreamerMessageHeaderLen)
			if _, readErr := io.ReadFull(serverConn, headerBytes); readErr != nil {
				serverDone <- readErr
				return
			}
			header := decodeHeader(headerBytes)
			if _, readErr := io.CopyN(io.Discard, serverConn, int64(header.length)); readErr != nil {
				serverDone <- readErr
				return
			}
		}
		close(requestReceived)
		var payload [1]byte
		_, readErr := serverConn.Read(payload[:])
		serverDone <- readErr
	}()

	ctx, cancel := context.WithCancel(t.Context())
	runDone := make(chan error, 1)
	go func() {
		runDone <- client.Run(ctx, func(EStreamerEvent) error { return nil })
	}()

	select {
	case <-requestReceived:
	case <-time.After(time.Second):
		t.Fatal("eStreamer request was not received")
	}
	cancel()
	select {
	case runErr := <-runDone:
		require.ErrorIs(t, runErr, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("eStreamer Run did not unblock promptly after cancellation")
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server side did not observe the cancelled connection")
	}
}

func TestEStreamerCertificateFailureNamesTrustAndOptInPaths(t *testing.T) {
	client, err := NewEStreamerClient(EStreamerConfig{Address: "fmc.example.test:8302"})
	require.NoError(t, err)
	cause := x509.UnknownAuthorityError{Cert: &x509.Certificate{}}
	client.dialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, cause
	}

	err = client.Run(t.Context(), func(EStreamerEvent) error { return nil })
	require.ErrorContains(t, err, "configure fmc.estreamer.tls.ca_file with the issuing CA (preferred)")
	require.ErrorContains(t, err, "set fmc.estreamer.tls.insecure_skip_verify: true")
	assert.ErrorIs(t, err, cause)
}

func TestEStreamerWriteRequestHandlesShortWritesAndUsesResumeCursor(t *testing.T) {
	client, err := NewEStreamerClient(EStreamerConfig{Address: "fmc.example.test:8302"})
	require.NoError(t, err)
	writer := &chunkWriter{max: 3}
	resume := time.Unix(1_800_000_123, 0).UTC()

	require.NoError(t, client.writeRequest(writer, resume))
	written := writer.Bytes()
	reader := bytes.NewReader(written)

	headerBytes := make([]byte, estreamerMessageHeaderLen)
	require.NoError(t, readFull(reader, headerBytes))
	header := decodeHeader(headerBytes)
	assert.Equal(t, estreamerMessageRequest, header.messageType)
	assert.Equal(t, uint32(8), header.length)
	initializer := make([]byte, header.length)
	require.NoError(t, readFull(reader, initializer))
	assert.Equal(t, uint32(resume.Unix()), binary.BigEndian.Uint32(initializer[:4]))
	assert.Zero(t, binary.BigEndian.Uint32(initializer[4:8]))

	require.NoError(t, readFull(reader, headerBytes))
	header = decodeHeader(headerBytes)
	assert.Equal(t, estreamerMessageRequest, header.messageType)
	payload := make([]byte, header.length)
	require.NoError(t, readFull(reader, payload))
	assert.Equal(t, uint32(resume.Unix()), binary.BigEndian.Uint32(payload[:4]))
	assert.Equal(t, estreamerRequestBitExtendedHeader, binary.BigEndian.Uint32(payload[4:8]))
	assert.JSONEq(t, string(mustJSON(t, defaultFQERequest(nil))), string(payload[8:]))
	assert.Zero(t, reader.Len())
}

func readFull(reader io.Reader, payload []byte) error {
	_, err := io.ReadFull(reader, payload)
	return err
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	require.NoError(t, err)
	return payload
}

type chunkWriter struct {
	bytes.Buffer
	max int
}

func (w *chunkWriter) Write(payload []byte) (int, error) {
	if len(payload) > w.max {
		payload = payload[:w.max]
	}
	return w.Buffer.Write(payload)
}
