// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package catalystcenter

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	for i := 0; i < 2; i++ {
		got, err := GetCount(t.Context(), client, "devices.count", "/dna/intent/api/v1/network-device/count", nil)
		require.NoError(t, err)
		assert.Equal(t, int64(4), got)
	}
	assert.Equal(t, int64(1), authCalls.Load())
	assert.Equal(t, int64(2), dataCalls.Load())
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

func TestClientPostPagination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dna/system/api/v1/auth/token":
			_, _ = w.Write([]byte(`{"Token":"token-1"}`))
		case "/dna/data/api/v1/assuranceIssues/query":
			var body map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
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
