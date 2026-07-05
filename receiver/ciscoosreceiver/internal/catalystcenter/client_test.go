// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package catalystcenter

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	client, err := NewClient(Config{Endpoint: "https://catalyst.example.test", Username: "admin", Password: "password", MaxRetries: 0})
	require.NoError(t, err)
	assert.Zero(t, client.retries)
	for _, retries := range []int{-1, httpclient.HardMaxRequestRetries + 1} {
		_, err = NewClient(Config{Endpoint: "https://catalyst.example.test", Username: "admin", Password: "password", MaxRetries: retries})
		require.ErrorContains(t, err, "invalid catalyst center max retries")
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
			name: "invalid successful token response",
			authenticate: func(w http.ResponseWriter, _ int64) {
				_, _ = w.Write([]byte(`{"not_token":"missing"}`))
			},
			wantErr:          "did not include Token",
			wantAuthRequests: 1,
		},
		{
			name: "transient authentication server failure",
			authenticate: func(w http.ResponseWriter, attempt int64) {
				if attempt == 1 {
					http.Error(w, "unavailable", http.StatusServiceUnavailable)
					return
				}
				_, _ = w.Write([]byte(`{"Token":"token-1"}`))
			},
			wantAuthRequests: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var authRequests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/dna/system/api/v1/auth/token" {
					tt.authenticate(w, authRequests.Add(1))
					return
				}
				_, _ = w.Write([]byte(`{"response":1}`))
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
			client.spacing = 0

			_, err = GetCount(t.Context(), client, "devices.count", "/dna/intent/api/v1/network-device/count", nil)
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
		if r.URL.Path == "/dna/system/api/v1/auth/token" {
			_, _ = w.Write([]byte(`{"Token":"token-1"}`))
			return
		}
		_, _ = w.Write([]byte(`{"response":1}`))
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
	client.spacing = 0
	transport := &failOnceTransport{next: client.client.Transport, path: "/dna/system/api/v1/auth/token"}
	client.client.Transport = transport

	_, err = GetCount(t.Context(), client, "devices.count", "/dna/intent/api/v1/network-device/count", nil)
	require.NoError(t, err)
	assert.Equal(t, int64(2), transport.attempts.Load())
}

func TestClientCertificateVerificationFailureIsTerminal(t *testing.T) {
	newClient := func(t *testing.T) (*Client, *certificateFailureTransport) {
		client, err := NewClient(Config{
			Endpoint:   "https://catalyst.example.test",
			Username:   "admin",
			Password:   "password",
			MaxRetries: 3,
		})
		require.NoError(t, err)
		client.spacing = 0
		transport := &certificateFailureTransport{}
		client.client.Transport = transport
		return client, transport
	}

	t.Run("authentication", func(t *testing.T) {
		client, transport := newClient(t)
		_, err := GetCount(t.Context(), client, "devices.count", "/dna/intent/api/v1/network-device/count", nil)
		require.Error(t, err)
		assert.True(t, httpclient.IsCertificateVerificationError(err))
		assert.Equal(t, int64(1), transport.attempts.Load())
	})

	t.Run("data", func(t *testing.T) {
		client, transport := newClient(t)
		client.tokenMu.Lock()
		client.token = "token-1"
		client.tokenExpiry = time.Now().Add(time.Hour)
		client.tokenGeneration = 1
		client.tokenMu.Unlock()

		_, err := GetCount(t.Context(), client, "devices.count", "/dna/intent/api/v1/network-device/count", nil)
		require.Error(t, err)
		assert.True(t, httpclient.IsCertificateVerificationError(err))
		assert.Equal(t, int64(1), transport.attempts.Load())
	})
}

func TestClientAuthenticationFailuresEnterSharedBackoff(t *testing.T) {
	tests := []struct {
		name             string
		authenticate     func(http.ResponseWriter)
		data             func(http.ResponseWriter)
		wantAuthRequests int64
		wantDataRequests int64
		wantFailures     int
	}{
		{
			name: "login rejected",
			authenticate: func(w http.ResponseWriter) {
				http.Error(w, "invalid credentials", http.StatusUnauthorized)
			},
			data: func(w http.ResponseWriter) {
				_, _ = w.Write([]byte(`{"response":1}`))
			},
			wantAuthRequests: 1,
			wantFailures:     1,
		},
		{
			name: "issued tokens rejected",
			authenticate: func(w http.ResponseWriter) {
				_, _ = w.Write([]byte(`{"Token":"rejected-token"}`))
			},
			data: func(w http.ResponseWriter) {
				http.Error(w, "token rejected", http.StatusUnauthorized)
			},
			wantAuthRequests: 2,
			wantDataRequests: 2,
			wantFailures:     2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var authRequests atomic.Int64
			var dataRequests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/dna/system/api/v1/auth/token" {
					authRequests.Add(1)
					tt.authenticate(w)
					return
				}
				dataRequests.Add(1)
				tt.data(w)
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
			client.spacing = 0

			for _, path := range []string{"/first", "/second"} {
				_, requestErr := GetCount(t.Context(), client, path, path, nil)
				require.ErrorContains(t, requestErr, "HTTP 401")
			}
			assert.Equal(t, tt.wantAuthRequests, authRequests.Load())
			assert.Equal(t, tt.wantDataRequests, dataRequests.Load())
			client.tokenMu.Lock()
			assert.Equal(t, tt.wantFailures, client.authFailures)
			client.tokenMu.Unlock()
		})
	}
}

func TestClientConcurrentRequestsShareLogin(t *testing.T) {
	const callers = 16
	loginStarted := make(chan struct{})
	releaseLogin := make(chan struct{})
	var startedOnce sync.Once
	var loginCalls atomic.Int64
	var dataCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dna/system/api/v1/auth/token" {
			loginCalls.Add(1)
			startedOnce.Do(func() { close(loginStarted) })
			<-releaseLogin
			_, _ = w.Write([]byte(`{"Token":"shared-token"}`))
			return
		}
		if r.Header.Get("X-Auth-Token") != "shared-token" {
			http.Error(w, "missing shared token", http.StatusUnauthorized)
			return
		}
		dataCalls.Add(1)
		_, _ = w.Write([]byte(`{"response":1}`))
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
	client.spacing = 0

	errs := make(chan error, callers)
	var workers sync.WaitGroup
	for range callers {
		workers.Go(func() {
			_, requestErr := GetCount(t.Context(), client, "count", "/count", nil)
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

func TestClientAuthBackoffResetsOnlyAfterAcceptedDataRequest(t *testing.T) {
	thirdDataStarted := make(chan struct{})
	releaseThirdData := make(chan struct{})
	var thirdStartedOnce sync.Once
	var releaseOnce sync.Once
	releaseThird := func() { releaseOnce.Do(func() { close(releaseThirdData) }) }
	t.Cleanup(releaseThird)
	var authCalls atomic.Int64
	var dataCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dna/system/api/v1/auth/token" {
			switch authCalls.Add(1) {
			case 1:
				_, _ = w.Write([]byte(`{"Token":"token-1"}`))
			case 2:
				_, _ = w.Write([]byte(`{"Token":"token-2"}`))
			default:
				_, _ = w.Write([]byte(`{"Token":"token-3"}`))
			}
			return
		}
		dataCalls.Add(1)
		if r.Header.Get("X-Auth-Token") != "token-3" {
			http.Error(w, "token rejected", http.StatusUnauthorized)
			return
		}
		thirdStartedOnce.Do(func() { close(thirdDataStarted) })
		<-releaseThirdData
		_, _ = w.Write([]byte(`{"response":3}`))
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
	client.spacing = 0

	_, err = GetCount(t.Context(), client, "first", "/count", nil)
	require.ErrorContains(t, err, "HTTP 401")
	_, err = GetCount(t.Context(), client, "cached", "/count", nil)
	require.ErrorContains(t, err, "HTTP 401")
	assert.Equal(t, int64(2), authCalls.Load())
	assert.Equal(t, int64(2), dataCalls.Load())

	client.tokenMu.Lock()
	assert.Equal(t, 2, client.authFailures)
	client.lastAuthAt = time.Now().Add(-catalystCenterAuthBackoffFor(client.authFailures))
	client.tokenMu.Unlock()

	result := make(chan error, 1)
	go func() {
		_, requestErr := GetCount(t.Context(), client, "recovered", "/count", nil)
		result <- requestErr
	}()
	select {
	case <-thirdDataStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for recovered data request")
	}
	client.tokenMu.Lock()
	assert.Equal(t, 2, client.authFailures, "a token response alone must not reset the failure streak")
	assert.Equal(t, "token-3", client.token)
	client.tokenMu.Unlock()

	releaseThird()
	require.NoError(t, <-result)
	client.tokenMu.Lock()
	assert.Zero(t, client.authFailures)
	assert.NoError(t, client.lastAuthErr)
	assert.True(t, client.lastAuthAt.IsZero())
	client.tokenMu.Unlock()
	assert.Equal(t, int64(3), authCalls.Load())
	assert.Equal(t, int64(3), dataCalls.Load())
}

func TestClientStaleUnauthorizedDoesNotClearNewerToken(t *testing.T) {
	client, err := NewClient(Config{
		Endpoint: "https://catalyst.example.test",
		Username: "admin",
		Password: "password",
	})
	require.NoError(t, err)

	client.tokenMu.Lock()
	client.token = "new-token"
	client.tokenExpiry = time.Now().Add(time.Hour)
	client.tokenGeneration = 4
	client.tokenMu.Unlock()

	client.rejectToken(tokenSnapshot{value: "old-token", generation: 3}, &APIError{StatusCode: http.StatusUnauthorized})
	client.tokenMu.Lock()
	assert.Equal(t, "new-token", client.token)
	assert.Equal(t, uint64(4), client.tokenGeneration)
	assert.Zero(t, client.authFailures)
	client.tokenMu.Unlock()

	client.rejectToken(tokenSnapshot{value: "new-token", generation: 4}, &APIError{StatusCode: http.StatusUnauthorized})
	client.tokenMu.Lock()
	assert.Empty(t, client.token)
	assert.Equal(t, uint64(5), client.tokenGeneration)
	assert.Equal(t, 1, client.authFailures)
	client.tokenMu.Unlock()
}

type failOnceTransport struct {
	next     http.RoundTripper
	path     string
	attempts atomic.Int64
}

type certificateFailureTransport struct {
	attempts atomic.Int64
}

func (t *certificateFailureTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.attempts.Add(1)
	return nil, x509.UnknownAuthorityError{}
}

func (t *failOnceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == t.path && t.attempts.Add(1) == 1 {
		return nil, errors.New("temporary transport failure")
	}
	return t.next.RoundTrip(req)
}

func TestClientBasicAuthHeadersAndTokenCache(t *testing.T) {
	var authCalls atomic.Int64
	var dataCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dna/system/api/v1/auth/token":
			authCalls.Add(1)
			assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:password")), r.Header.Get("Authorization"))
			assert.Equal(t, "test-agent", r.Header.Get("User-Agent"))
			_, _ = w.Write([]byte(`{"Token":"token-1"}`))
		case "/dna/intent/api/v1/network-device/count":
			dataCalls.Add(1)
			assert.Equal(t, "token-1", r.Header.Get("X-Auth-Token"))
			_, _ = w.Write([]byte(`{"response":4,"version":"1.0"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", UserAgent: "test-agent", Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)
	client.spacing = 0

	for range 2 {
		got, err := GetCount(t.Context(), client, "devices.count", "/dna/intent/api/v1/network-device/count", nil)
		require.NoError(t, err)
		assert.Equal(t, int64(4), got)
	}
	assert.Equal(t, int64(1), authCalls.Load())
	assert.Equal(t, int64(2), dataCalls.Load())
}

func TestDecodeCountPreservesLargeInteger(t *testing.T) {
	count, err := decodeCount([]byte(`{"response":9007199254740993}`))
	require.NoError(t, err)
	assert.Equal(t, int64(9007199254740993), count)
}

func TestDecodePagePreservesLargeGenericInteger(t *testing.T) {
	var out []map[string]any
	_, _, err := decodePage([]byte(`{"response":[{"counter":9007199254740993}]}`), &out)
	require.NoError(t, err)
	require.Len(t, out, 1)
	number, ok := out[0]["counter"].(json.Number)
	require.True(t, ok)
	assert.Equal(t, "9007199254740993", number.String())
}

func TestClientAESAuthPassthrough(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dna/system/api/v1/auth/token":
			assert.Equal(t, "CSCO-AES-256 credentials=opaque-ciphertext", r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`{"Token":"token-1"}`))
		case "/dna/intent/api/v1/network-device/count":
			assert.Equal(t, "token-1", r.Header.Get("X-Auth-Token"))
			_, _ = w.Write([]byte(`{"response":{"count":7},"version":"1.0"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "aes", AESCredentials: "opaque-ciphertext", Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)
	client.spacing = 0

	got, err := GetCount(t.Context(), client, "devices.count", "/dna/intent/api/v1/network-device/count", nil)
	require.NoError(t, err)
	assert.Equal(t, int64(7), got)
}

func TestClientSupportsSelfSignedTLSWithInsecureSkipVerify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dna/system/api/v1/auth/token":
			_, _ = w.Write([]byte(`{"Token":"token-1"}`))
		case "/dna/intent/api/v1/network-device/count":
			assert.Equal(t, "token-1", r.Header.Get("X-Auth-Token"))
			_, _ = w.Write([]byte(`{"response":4}`))
		default:
			http.NotFound(w, r)
		}
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
	verifiedClient.spacing = 0
	_, err = GetCount(t.Context(), verifiedClient, "devices.count", "/dna/intent/api/v1/network-device/count", nil)
	require.ErrorContains(t, err, "trust the issuing CA in the Collector host trust store (preferred)")
	require.ErrorContains(t, err, "set catalyst_center.insecure_skip_verify: true")

	client, err := NewClient(Config{
		Endpoint:           server.URL,
		Username:           "admin",
		Password:           "password",
		Timeout:            time.Second,
		MaxRetries:         1,
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	client.spacing = 0

	got, err := GetCount(t.Context(), client, "devices.count", "/dna/intent/api/v1/network-device/count", nil)
	require.NoError(t, err)
	assert.Equal(t, int64(4), got)
}

func TestClientRefreshesTokenOnceOnUnauthorized(t *testing.T) {
	var authCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dna/system/api/v1/auth/token":
			token := "token-1"
			if authCalls.Add(1) == 2 {
				token = "token-2"
			}
			_, _ = w.Write([]byte(`{"Token":"` + token + `"}`))
		case "/dna/intent/api/v1/network-device/count":
			if r.Header.Get("X-Auth-Token") == "token-1" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`expired`))
				return
			}
			assert.Equal(t, "token-2", r.Header.Get("X-Auth-Token"))
			_, _ = w.Write([]byte(`{"response":4}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)
	client.spacing = 0

	got, err := GetCount(t.Context(), client, "devices.count", "/dna/intent/api/v1/network-device/count", nil)
	require.NoError(t, err)
	assert.Equal(t, int64(4), got)
	assert.Equal(t, int64(2), authCalls.Load())
}

func TestClientGetPagination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dna/system/api/v1/auth/token":
			_, _ = w.Write([]byte(`{"Token":"token-1"}`))
		case "/dna/intent/api/v1/network-device":
			assert.Equal(t, "2", r.URL.Query().Get("limit"))
			switch r.URL.Query().Get("offset") {
			case "1":
				_, _ = w.Write([]byte(`{"response":[{"hostname":"one"},{"hostname":"two"}]}`))
			case "3":
				_, _ = w.Write([]byte(`{"response":[{"hostname":"three"}]}`))
			default:
				t.Fatalf("unexpected offset %q", r.URL.Query().Get("offset"))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", PageSize: 2, Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)
	client.spacing = 0

	got, err := GetPaginatedJSON[Device](t.Context(), client, "devices", "/dna/intent/api/v1/network-device", nil, 0)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "three", got[2].Hostname)
}

func TestClientGetPaginationContinuesAfterShortPageWhenCountHasMore(t *testing.T) {
	var dataCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dna/system/api/v1/auth/token":
			_, _ = w.Write([]byte(`{"Token":"token-1"}`))
		case "/dna/intent/api/v1/network-device":
			dataCalls.Add(1)
			assert.Equal(t, "2", r.URL.Query().Get("limit"))
			switch r.URL.Query().Get("offset") {
			case "1":
				_, _ = w.Write([]byte(`{"response":[{"hostname":"one"}],"page":{"limit":2,"offset":1,"count":2}}`))
			case "2":
				_, _ = w.Write([]byte(`{"response":[{"hostname":"two"}],"page":{"limit":2,"offset":2,"count":2}}`))
			default:
				t.Fatalf("unexpected offset %q", r.URL.Query().Get("offset"))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", PageSize: 2, Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)
	client.spacing = 0

	got, err := GetPaginatedJSON[Device](t.Context(), client, "devices", "/dna/intent/api/v1/network-device", nil, 0)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "one", got[0].Hostname)
	assert.Equal(t, "two", got[1].Hostname)
	assert.Equal(t, int64(2), dataCalls.Load())
}

func TestClientGetPaginationAppliesEndpointPageLimitAndPageEnvelope(t *testing.T) {
	var dataCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dna/system/api/v1/auth/token":
			_, _ = w.Write([]byte(`{"Token":"token-1"}`))
		case "/dna/data/api/v1/siteHealthSummaries":
			dataCalls.Add(1)
			assert.Equal(t, "20", r.URL.Query().Get("limit"))
			assert.Equal(t, "1", r.URL.Query().Get("offset"))
			_, _ = w.Write([]byte(`{"response":[{"id":"site-1"},{"id":"site-2"}],"page":{"limit":20,"offset":1,"count":2}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", PageSize: 500, Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)
	client.spacing = 0

	got, err := GetPaginatedJSONWithPageLimit[SiteHealthSummary](t.Context(), client, "site_health", "/dna/data/api/v1/siteHealthSummaries", nil, 0, 20)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, int64(1), dataCalls.Load())
}

func TestClientGetPaginationCapsOverReturnedPage(t *testing.T) {
	var dataCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dna/system/api/v1/auth/token":
			_, _ = w.Write([]byte(`{"Token":"token-1"}`))
		case "/dna/intent/api/v1/network-device":
			dataCalls.Add(1)
			assert.Equal(t, "2", r.URL.Query().Get("limit"))
			_, _ = w.Write([]byte(`{"response":[{"hostname":"one"},{"hostname":"two"},{"hostname":"unexpected"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)
	client.spacing = 0

	got, err := GetPaginatedJSON[Device](t.Context(), client, "devices", "/dna/intent/api/v1/network-device", nil, 2)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "two", got[1].Hostname)
	assert.Equal(t, int64(1), dataCalls.Load())
}

func TestClientPostPagination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dna/system/api/v1/auth/token":
			_, _ = w.Write([]byte(`{"Token":"token-1"}`))
		case "/dna/data/api/v1/assuranceIssues/query":
			var body map[string]any
			if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&body)) {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			page := body["page"].(map[string]any)
			assert.Equal(t, float64(2), page["limit"])
			switch page["offset"] {
			case float64(1):
				_, _ = w.Write([]byte(`{"response":[{"issueId":"one"},{"issueId":"two"}],"page":{"limit":2,"offset":1,"count":3}}`))
			case float64(3):
				_, _ = w.Write([]byte(`{"response":[{"issueId":"three"}],"page":{"limit":2,"offset":3,"count":3}}`))
			default:
				t.Fatalf("unexpected offset %v", page["offset"])
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", PageSize: 2, Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)
	client.spacing = 0

	got, err := PostPaginatedJSON[Issue](t.Context(), client, "issues.query", "/dna/data/api/v1/assuranceIssues/query", map[string]any{"filters": []any{}}, 0)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "three", got[2].IssueID)
}

func TestClientPostPaginationContinuesAfterShortPageWhenCountHasMore(t *testing.T) {
	var dataCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dna/system/api/v1/auth/token":
			_, _ = w.Write([]byte(`{"Token":"token-1"}`))
		case "/dna/data/api/v1/assuranceIssues/query":
			dataCalls.Add(1)
			var body map[string]any
			if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&body)) {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			page := body["page"].(map[string]any)
			assert.Equal(t, float64(2), page["limit"])
			switch page["offset"] {
			case float64(1):
				_, _ = w.Write([]byte(`{"response":[{"issueId":"one"}],"page":{"limit":2,"offset":1,"count":2}}`))
			case float64(2):
				_, _ = w.Write([]byte(`{"response":[{"issueId":"two"}],"page":{"limit":2,"offset":2,"count":2}}`))
			default:
				t.Fatalf("unexpected offset %v", page["offset"])
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", PageSize: 2, Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)
	client.spacing = 0

	got, err := PostPaginatedJSON[Issue](t.Context(), client, "issues.query", "/dna/data/api/v1/assuranceIssues/query", map[string]any{"filters": []any{}}, 0)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "one", got[0].IssueID)
	assert.Equal(t, "two", got[1].IssueID)
	assert.Equal(t, int64(2), dataCalls.Load())
}

func TestClientPostPaginationCapsOverReturnedPage(t *testing.T) {
	var dataCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dna/system/api/v1/auth/token":
			_, _ = w.Write([]byte(`{"Token":"token-1"}`))
		case "/dna/data/api/v1/assuranceIssues/query":
			dataCalls.Add(1)
			var body map[string]any
			if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&body)) {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			page := body["page"].(map[string]any)
			assert.Equal(t, float64(2), page["limit"])
			_, _ = w.Write([]byte(`{"response":[{"issueId":"one"},{"issueId":"two"},{"issueId":"unexpected"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)
	client.spacing = 0

	got, err := PostPaginatedJSON[Issue](t.Context(), client, "issues.query", "/dna/data/api/v1/assuranceIssues/query", map[string]any{"filters": []any{}}, 2)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "two", got[1].IssueID)
	assert.Equal(t, int64(1), dataCalls.Load())
}

func TestClientPaginationHardPageLimitReturnsPartialResults(t *testing.T) {
	t.Run("GET", func(t *testing.T) {
		var dataCalls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/dna/system/api/v1/auth/token":
				_, _ = w.Write([]byte(`{"Token":"token-1"}`))
			case "/dna/intent/api/v1/network-device":
				dataCalls.Add(1)
				_, _ = w.Write([]byte(`{"response":[{"hostname":"one"}]}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", PageSize: 1, Timeout: time.Second, MaxRetries: 1})
		require.NoError(t, err)
		client.spacing = 0

		got, err := GetPaginatedJSON[Device](t.Context(), client, "devices", "/dna/intent/api/v1/network-device", nil, 0)
		var limitErr *httpclient.PaginationLimitError
		require.ErrorAs(t, err, &limitErr)
		assert.Equal(t, "page", limitErr.Kind)
		assert.Len(t, got, httpclient.HardMaxPaginationPages)
		assert.Equal(t, int64(httpclient.HardMaxPaginationPages), dataCalls.Load())
	})

	t.Run("POST", func(t *testing.T) {
		var dataCalls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/dna/system/api/v1/auth/token":
				_, _ = w.Write([]byte(`{"Token":"token-1"}`))
			case "/dna/data/api/v1/assuranceIssues/query":
				dataCalls.Add(1)
				_, _ = w.Write([]byte(`{"response":[{"issueId":"one"}]}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", PageSize: 1, Timeout: time.Second, MaxRetries: 1})
		require.NoError(t, err)
		client.spacing = 0

		got, err := PostPaginatedJSON[Issue](t.Context(), client, "issues.query", "/dna/data/api/v1/assuranceIssues/query", map[string]any{}, 0)
		var limitErr *httpclient.PaginationLimitError
		require.ErrorAs(t, err, &limitErr)
		assert.Equal(t, "page", limitErr.Kind)
		assert.Len(t, got, httpclient.HardMaxPaginationPages)
		assert.Equal(t, int64(httpclient.HardMaxPaginationPages), dataCalls.Load())
	})
}

func TestClientPaginationHardResultLimitTruncatesOverReturnedPage(t *testing.T) {
	values := make([]int, httpclient.HardMaxPaginationResults+1)
	var dataCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dna/system/api/v1/auth/token":
			_, _ = w.Write([]byte(`{"Token":"token-1"}`))
		case "/dna/intent/api/v1/values":
			dataCalls.Add(1)
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{"response": values}))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)
	client.spacing = 0

	got, err := GetPaginatedJSON[int](t.Context(), client, "values", "/dna/intent/api/v1/values", nil, 0)
	var limitErr *httpclient.PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.Equal(t, "result", limitErr.Kind)
	assert.Len(t, got, httpclient.HardMaxPaginationResults)
	assert.Equal(t, int64(1), dataCalls.Load())
}

func TestClientRetries429RetryAfter(t *testing.T) {
	var attempts atomic.Int64
	var stats []RequestStat
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dna/system/api/v1/auth/token":
			_, _ = w.Write([]byte(`{"Token":"token-1"}`))
		case "/dna/intent/api/v1/network-device/count":
			if attempts.Add(1) == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`rate limited`))
				return
			}
			_, _ = w.Write([]byte(`{"response":4}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)
	client.spacing = 0
	client.OnRequest = func(stat RequestStat) {
		stats = append(stats, stat)
	}

	got, err := GetCount(t.Context(), client, "devices.count", "/dna/intent/api/v1/network-device/count", nil)
	require.NoError(t, err)
	assert.Equal(t, int64(4), got)
	assert.Equal(t, int64(2), attempts.Load())
	require.GreaterOrEqual(t, len(stats), 3)
	assert.True(t, stats[1].RateLimited)
	assert.Equal(t, "success", stats[2].Outcome)
}

func TestClientDecodeErrorIncludesOperation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dna/system/api/v1/auth/token":
			_, _ = w.Write([]byte(`{"Token":"token-1"}`))
		case "/dna/intent/api/v1/network-device":
			_, _ = w.Write([]byte(`not-json`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)
	client.spacing = 0

	_, err = GetPaginatedJSON[Device](t.Context(), client, "devices", "/dna/intent/api/v1/network-device", nil, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode catalyst center devices page")
}
