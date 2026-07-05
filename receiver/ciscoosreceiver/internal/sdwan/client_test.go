// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sdwan

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

func TestClientRetryCountValidation(t *testing.T) {
	client, err := NewClient(Config{
		Endpoint:    "https://sdwan.example.com",
		AuthMode:    "bearer",
		BearerToken: "token",
		MaxRetries:  0,
	})
	require.NoError(t, err)
	assert.Zero(t, client.retries)

	for _, retries := range []int{-1, httpclient.HardMaxRequestRetries + 1} {
		_, err := NewClient(Config{
			Endpoint:    "https://sdwan.example.com",
			AuthMode:    "bearer",
			BearerToken: "token",
			MaxRetries:  retries,
		})
		require.ErrorContains(t, err, "invalid sdwan max retries")
	}
}

func TestClientBearerList(t *testing.T) {
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		assert.Equal(t, "/dataservice/device", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"host-name": "edge-1"}},
		})
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:    server.URL,
		AuthMode:    "bearer",
		BearerToken: "token",
		Timeout:     time.Second,
	})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.List(t.Context(), "devices", "/device", nil, 0)
	require.NoError(t, err)
	require.Len(t, objects, 1)
	assert.Equal(t, "edge-1", String(objects[0], "host-name"))
	assert.Equal(t, "Bearer token", authHeader)
}

func TestClientCertificateVerificationFailureIsTerminal(t *testing.T) {
	t.Run("data", func(t *testing.T) {
		client, err := NewClient(Config{
			Endpoint:    "https://sdwan.example.test",
			AuthMode:    "bearer",
			BearerToken: "token",
			MaxRetries:  3,
		})
		require.NoError(t, err)
		client.spacing = 0
		transport := &certificateFailureTransport{}
		client.client.Transport = transport

		_, err = client.List(t.Context(), "devices", "/device", nil, 0)
		require.Error(t, err)
		assert.True(t, httpclient.IsCertificateVerificationError(err))
		assert.Equal(t, int64(1), transport.attempts.Load())
		assert.Equal(t, []string{"/dataservice/device"}, transport.paths)
	})

	t.Run("auto authentication does not fall back", func(t *testing.T) {
		client, err := NewClient(Config{
			Endpoint:   "https://sdwan.example.test",
			AuthMode:   "auto",
			Username:   "admin",
			Password:   "password",
			MaxRetries: 3,
		})
		require.NoError(t, err)
		client.spacing = 0
		transport := &certificateFailureTransport{}
		client.client.Transport = transport

		_, err = client.List(t.Context(), "devices", "/device", nil, 0)
		require.Error(t, err)
		assert.True(t, httpclient.IsCertificateVerificationError(err))
		assert.Equal(t, int64(1), transport.attempts.Load())
		assert.Equal(t, []string{"/jwt/login"}, transport.paths)
	})
}

type certificateFailureTransport struct {
	attempts atomic.Int64
	paths    []string
}

func (t *certificateFailureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.attempts.Add(1)
	t.paths = append(t.paths, req.URL.Path)
	return nil, x509.UnknownAuthorityError{}
}

func TestClientListPaginatesStatisticsScrollID(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		assert.Equal(t, "/dataservice/data/device/statistics/interfacestatistics", r.URL.Path)
		switch r.URL.Query().Get("scrollId") {
		case "":
			assert.Equal(t, "2026-07-01T00:00:00", r.URL.Query().Get("startDate"))
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "1"}, {"id": "2"}},
				"pageInfo": map[string]any{
					"scrollId":    "scroll-1",
					"hasMoreData": true,
					"count":       2,
				},
			})
		case "scroll-1":
			assert.Equal(t, "2", r.URL.Query().Get("count"))
			assert.Empty(t, r.URL.Query().Get("startDate"))
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "3"}},
				"pageInfo": map[string]any{
					"scrollId":    "scroll-2",
					"hasMoreData": false,
					"count":       1,
				},
			})
		default:
			http.Error(w, "unexpected scroll ID", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "bearer", BearerToken: "token", Timeout: time.Second})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.List(t.Context(), "statistics.interfaces", "/data/device/statistics/interfacestatistics", url.Values{"startDate": {"2026-07-01T00:00:00"}}, 0)
	require.NoError(t, err)
	require.Len(t, objects, 3)
	assert.Equal(t, "3", String(objects[2], "id"))
	assert.Equal(t, 2, requests)
}

func TestClientListPaginatesStateFromEndID(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		assert.Equal(t, "edge-1", r.URL.Query().Get("deviceId"))
		switch r.URL.Query().Get("startId") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "1"}, {"id": "2"}},
				"pageInfo": map[string]any{
					"startId":     "49:1",
					"endId":       "49:2",
					"moreEntries": true,
					"count":       2,
				},
			})
		case "49:2":
			assert.Equal(t, "2", r.URL.Query().Get("count"))
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "3"}},
				"pageInfo": map[string]any{
					"startId":     "50:3",
					"endId":       "50:3",
					"moreEntries": false,
					"count":       1,
				},
			})
		default:
			http.Error(w, "unexpected start ID", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "bearer", BearerToken: "token", Timeout: time.Second})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.List(t.Context(), "state.interfaces", "/data/device/state/Interface", url.Values{"deviceId": {"edge-1"}}, 0)
	require.NoError(t, err)
	require.Len(t, objects, 3)
	assert.Equal(t, "3", String(objects[2], "id"))
	assert.Equal(t, 2, requests)
}

func TestClientListDetectsContinuationCycle(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"id": requests}},
			"pageInfo": map[string]any{
				"scrollId":    "repeated-scroll",
				"hasMoreData": true,
				"count":       1,
			},
		})
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "bearer", BearerToken: "token", Timeout: time.Second})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.List(t.Context(), "statistics.cycle", "/statistics/cycle", nil, 0)
	require.ErrorContains(t, err, "continuation cycle")
	assert.Len(t, objects, 2)
	assert.Equal(t, 2, requests)
}

func TestClientListRejectsMissingContinuationToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data":     []map[string]any{{"id": "1"}},
			"pageInfo": map[string]any{"hasMoreData": true, "count": 1},
		})
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "bearer", BearerToken: "token", Timeout: time.Second})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.List(t.Context(), "statistics.missing_token", "/statistics/missing-token", nil, 0)
	require.ErrorContains(t, err, "pageInfo.scrollId is empty")
	assert.Len(t, objects, 1)
}

func TestClientListPreservesLaterPageError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("scrollId") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data":     []map[string]any{{"id": "1"}},
				"pageInfo": map[string]any{"scrollId": "next", "hasMoreData": true, "count": 1},
			})
			return
		}
		http.Error(w, "failed", http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "bearer", BearerToken: "token", Timeout: time.Second})
	require.NoError(t, err)
	client.spacing = 0
	client.retries = 0

	objects, err := client.List(t.Context(), "statistics.error", "/statistics/error", nil, 0)
	require.Error(t, err)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusInternalServerError, apiErr.StatusCode)
	assert.Len(t, objects, 1)
}

func TestClientListEnforcesHardResultLimit(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data":     []map[string]any{{"id": "1"}, {"id": "2"}, {"id": "3"}},
			"pageInfo": map[string]any{"scrollId": "next", "hasMoreData": true, "count": 3},
		})
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "bearer", BearerToken: "token", Timeout: time.Second})
	require.NoError(t, err)
	client.spacing = 0
	client.maxResults = 2

	objects, err := client.List(t.Context(), "statistics.limit", "/statistics/limit", nil, 0)
	require.ErrorContains(t, err, "exceeded 2 results")
	assert.Len(t, objects, 2)
	assert.Equal(t, 1, requests)
}

func TestClientListEnforcesPageLimit(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data":     []map[string]any{{"id": "1"}},
			"pageInfo": map[string]any{"scrollId": "next", "hasMoreData": true, "count": 1},
		})
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "bearer", BearerToken: "token", Timeout: time.Second})
	require.NoError(t, err)
	client.spacing = 0
	client.maxPages = 1

	objects, err := client.List(t.Context(), "statistics.page_limit", "/statistics/page-limit", nil, 0)
	require.ErrorContains(t, err, "exceeded 1 pages")
	assert.Len(t, objects, 1)
	assert.Equal(t, 1, requests)
}

func TestClientPostQueryPaginatesStatisticsScrollID(t *testing.T) {
	var requests int
	var bodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/dataservice/statistics/query", r.URL.Path)
		body, err := io.ReadAll(r.Body)
		if !assert.NoError(t, err) {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		bodies = append(bodies, body)

		switch r.URL.Query().Get("scrollId") {
		case "":
			assert.Empty(t, r.URL.Query().Get("count"))
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "1"}, {"id": "2"}},
				"pageInfo": map[string]any{
					"scrollId":    "scroll-1",
					"hasMoreData": true,
					"count":       2,
				},
			})
		case "scroll-1":
			assert.Equal(t, "2", r.URL.Query().Get("count"))
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "3"}},
				"pageInfo": map[string]any{
					"scrollId":    "scroll-2",
					"hasMoreData": false,
					"count":       1,
				},
			})
		default:
			http.Error(w, "unexpected scroll ID", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "bearer", BearerToken: "token", Timeout: time.Second})
	require.NoError(t, err)
	client.spacing = 0

	payload := map[string]any{"query": map[string]any{"field": "entry_time"}, "size": 2}
	objects, err := client.PostQuery(t.Context(), "statistics.query", "/statistics/query", payload, 0)
	require.NoError(t, err)
	require.Len(t, objects, 3)
	assert.Equal(t, "3", String(objects[2], "id"))
	assert.Equal(t, 2, requests)
	require.Len(t, bodies, 2)
	assert.JSONEq(t, string(bodies[0]), string(bodies[1]))
}

func TestClientPostQueryDetectsContinuationCycle(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		assert.Equal(t, http.MethodPost, r.Method)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"id": requests}},
			"pageInfo": map[string]any{
				"scrollId":    "repeated-scroll",
				"hasMoreData": true,
				"count":       1,
			},
		})
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "bearer", BearerToken: "token", Timeout: time.Second})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.PostQuery(t.Context(), "statistics.cycle", "/statistics/cycle", map[string]any{"size": 1}, 0)
	require.ErrorContains(t, err, "continuation cycle")
	assert.Len(t, objects, 2)
	assert.Equal(t, 2, requests)
}

func TestClientPostQueryPreservesLaterPageError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		if r.URL.Query().Get("scrollId") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data":     []map[string]any{{"id": "1"}},
				"pageInfo": map[string]any{"scrollId": "next", "hasMoreData": true, "count": 1},
			})
			return
		}
		http.Error(w, "failed", http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "bearer", BearerToken: "token", Timeout: time.Second})
	require.NoError(t, err)
	client.spacing = 0
	client.retries = 0

	objects, err := client.PostQuery(t.Context(), "statistics.error", "/statistics/error", map[string]any{"size": 1}, 0)
	require.Error(t, err)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusInternalServerError, apiErr.StatusCode)
	assert.Len(t, objects, 1)
}

func TestClientPostQueryEnforcesHardResultLimit(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		assert.Equal(t, http.MethodPost, r.Method)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data":     []map[string]any{{"id": "1"}, {"id": "2"}, {"id": "3"}},
			"pageInfo": map[string]any{"scrollId": "next", "hasMoreData": true, "count": 3},
		})
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, AuthMode: "bearer", BearerToken: "token", Timeout: time.Second})
	require.NoError(t, err)
	client.spacing = 0
	client.maxResults = 2

	objects, err := client.PostQuery(t.Context(), "statistics.limit", "/statistics/limit", map[string]any{"size": 3}, 10)
	require.ErrorContains(t, err, "exceeded 2 results")
	assert.Len(t, objects, 2)
	assert.Equal(t, 1, requests)
}

func TestClientPreservesLargeJSONIntegers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"rx-packets":9007199254740993,"tx-packets":9007199254740993.0}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:    server.URL,
		AuthMode:    "bearer",
		BearerToken: "token",
		Timeout:     time.Second,
	})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.List(t.Context(), "interfaces", "/device/interface", nil, 0)
	require.NoError(t, err)
	require.Len(t, objects, 1)
	value, ok := Int(objects[0], "rx-packets")
	require.True(t, ok)
	assert.Equal(t, int64(9007199254740993), value)
	value, ok = Int(objects[0], "tx-packets")
	require.True(t, ok)
	assert.Equal(t, int64(9007199254740993), value)
}

func TestClientSupportsSelfSignedTLSWithInsecureSkipVerify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/dataservice/device", r.URL.Path)
		assert.Equal(t, "Bearer token", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"host-name": "edge-1"}},
		})
	}))
	defer server.Close()

	verifiedClient, err := NewClient(Config{
		Endpoint:    server.URL,
		AuthMode:    "bearer",
		BearerToken: "token",
		Timeout:     time.Second,
	})
	require.NoError(t, err)
	verifiedClient.spacing = 0
	_, err = verifiedClient.List(t.Context(), "devices", "/device", nil, 0)
	require.ErrorContains(t, err, "trust the issuing CA in the Collector host trust store (preferred)")
	require.ErrorContains(t, err, "set sdwan.insecure_skip_verify: true")

	client, err := NewClient(Config{
		Endpoint:           server.URL,
		AuthMode:           "bearer",
		BearerToken:        "token",
		Timeout:            time.Second,
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.List(t.Context(), "devices", "/device", nil, 0)
	require.NoError(t, err)
	require.Len(t, objects, 1)
	assert.Equal(t, "edge-1", String(objects[0], "host-name"))
}

func TestClientAutoJWTLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwt/login":
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "jwt-token", "xsrfToken": "csrf"})
		case "/dataservice/device":
			assert.Equal(t, "Bearer jwt-token", r.Header.Get("Authorization"))
			_ = json.NewEncoder(w).Encode([]map[string]any{{"system-ip": "10.0.0.1"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint: server.URL,
		AuthMode: "auto",
		Username: "admin",
		Password: "password",
		Timeout:  time.Second,
	})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.List(t.Context(), "devices", "/device", nil, 0)
	require.NoError(t, err)
	require.Len(t, objects, 1)
	assert.Equal(t, "10.0.0.1", String(objects[0], "system-ip"))
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
			wantErr:          "did not include token",
			wantAuthRequests: 1,
		},
		{
			name: "transient authentication server failure",
			authenticate: func(w http.ResponseWriter, attempt int64) {
				if attempt == 1 {
					w.Header().Set("Retry-After", "0")
					http.Error(w, "unavailable", http.StatusServiceUnavailable)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"token": "jwt-token"})
			},
			wantAuthRequests: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var authRequests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/jwt/login":
					tt.authenticate(w, authRequests.Add(1))
				case "/dataservice/device":
					_ = json.NewEncoder(w).Encode([]map[string]any{{"system-ip": "10.0.0.1"}})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			client, err := NewClient(Config{
				Endpoint:   server.URL,
				AuthMode:   "jwt",
				Username:   "admin",
				Password:   "password",
				Timeout:    time.Second,
				MaxRetries: 1,
			})
			require.NoError(t, err)
			client.spacing = 0

			_, err = client.List(t.Context(), "devices", "/device", nil, 1)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.wantErr)
			}
			assert.Equal(t, tt.wantAuthRequests, authRequests.Load())
		})
	}
}

func TestClientAutoFallsBackToSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwt/login":
			http.Error(w, "not supported", http.StatusNotFound)
		case "/j_security_check":
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "session-id"})
			w.WriteHeader(http.StatusOK)
		case "/dataservice/client/token":
			assert.Equal(t, "JSESSIONID=session-id", r.Header.Get("Cookie"))
			_, _ = w.Write([]byte("xsrf-token"))
		case "/dataservice/events":
			assert.Equal(t, "JSESSIONID=session-id", r.Header.Get("Cookie"))
			assert.Equal(t, "xsrf-token", r.Header.Get("X-XSRF-TOKEN"))
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"eventId": "event-1"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint: server.URL,
		AuthMode: "auto",
		Username: "admin",
		Password: "password",
		Timeout:  time.Second,
	})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.PostQuery(t.Context(), "events", "/events", map[string]any{"size": 1}, 0)
	require.NoError(t, err)
	require.Len(t, objects, 1)
	assert.Equal(t, "event-1", String(objects[0], "eventId"))
}

func TestClientAutoRetriesTransientJWTFailure(t *testing.T) {
	var jwtRequests atomic.Int64
	var sessionRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwt/login":
			if jwtRequests.Add(1) == 1 {
				w.Header().Set("Retry-After", "0")
				http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "jwt-token"})
		case "/j_security_check":
			sessionRequests.Add(1)
			http.NotFound(w, r)
		case "/dataservice/device":
			assert.Equal(t, "Bearer jwt-token", r.Header.Get("Authorization"))
			_ = json.NewEncoder(w).Encode([]map[string]any{{"system-ip": "10.0.0.1"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		AuthMode:   "auto",
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 1,
	})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.List(t.Context(), "devices", "/device", nil, 0)
	require.NoError(t, err)
	require.Len(t, objects, 1)
	assert.Equal(t, int64(2), jwtRequests.Load())
	assert.Zero(t, sessionRequests.Load())
}

func TestClientSessionAuthPublishesOnlyCompleteBundle(t *testing.T) {
	const workers = 16

	var loginRequests atomic.Int64
	var tokenRequests atomic.Int64
	var dataRequests atomic.Int64
	var invalidAuthHeaders atomic.Int64
	tokenStarted := make(chan struct{})
	releaseToken := make(chan struct{})
	var tokenStartedOnce sync.Once
	var releaseTokenOnce sync.Once
	release := func() {
		releaseTokenOnce.Do(func() { close(releaseToken) })
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/j_security_check":
			loginRequests.Add(1)
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "session-id"})
			w.WriteHeader(http.StatusOK)
		case "/dataservice/client/token":
			tokenRequests.Add(1)
			if r.Header.Get("Cookie") != "JSESSIONID=session-id" {
				invalidAuthHeaders.Add(1)
			}
			tokenStartedOnce.Do(func() { close(tokenStarted) })
			<-releaseToken
			_, _ = w.Write([]byte("xsrf-token"))
		case "/dataservice/events":
			dataRequests.Add(1)
			if r.Header.Get("Cookie") != "JSESSIONID=session-id" || r.Header.Get("X-XSRF-TOKEN") != "xsrf-token" {
				invalidAuthHeaders.Add(1)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"eventId": "event-1"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	defer release()

	client, err := NewClient(Config{
		Endpoint: server.URL,
		AuthMode: "session",
		Username: "admin",
		Password: "password",
		Timeout:  5 * time.Second,
	})
	require.NoError(t, err)
	client.spacing = 0

	start := make(chan struct{})
	results := make(chan error, workers)
	for range workers {
		go func() {
			<-start
			_, requestErr := client.PostQuery(t.Context(), "events", "/events", map[string]any{"size": 1}, 0)
			results <- requestErr
		}()
	}
	close(start)

	select {
	case <-tokenStarted:
	case <-time.After(time.Second):
		t.Fatal("session token request did not start")
	}

	client.authMu.Lock()
	inflight := client.loginInflight != nil
	published := client.authBundleLocked()
	client.authMu.Unlock()
	assert.True(t, inflight)
	assert.Empty(t, published.bearerToken)
	assert.Empty(t, published.jsessionID)
	assert.Empty(t, published.xsrfToken)

	release()
	for range workers {
		require.NoError(t, <-results)
	}

	assert.Equal(t, int64(1), loginRequests.Load())
	assert.Equal(t, int64(1), tokenRequests.Load())
	assert.Equal(t, int64(workers), dataRequests.Load())
	assert.Zero(t, invalidAuthHeaders.Load())
}

func TestClientCanceledLoginOwnerDoesNotBackoffLiveWaiter(t *testing.T) {
	var loginRequests atomic.Int64
	firstLoginStarted := make(chan struct{})
	releaseFirstLogin := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwt/login" {
			http.NotFound(w, r)
			return
		}
		if loginRequests.Add(1) == 1 {
			close(firstLoginStarted)
			<-releaseFirstLogin
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "replacement-token"})
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint: server.URL,
		AuthMode: "jwt",
		Username: "admin",
		Password: "password",
		Timeout:  5 * time.Second,
	})
	require.NoError(t, err)

	ownerCtx, cancelOwner := context.WithCancel(t.Context())
	ownerResult := make(chan error, 1)
	go func() {
		_, authErr := client.ensureAuth(ownerCtx)
		ownerResult <- authErr
	}()
	<-firstLoginStarted

	// Queue both the live waiter and the canceled owner behind the state lock.
	// Regardless of which acquires it first, the cancellation must not become a
	// shared authentication failure.
	client.authMu.Lock()
	waiterResult := make(chan error, 1)
	go func() {
		_, authErr := client.ensureAuth(t.Context())
		waiterResult <- authErr
	}()
	cancelOwner()
	close(releaseFirstLogin)
	client.authMu.Unlock()

	require.ErrorIs(t, <-ownerResult, context.Canceled)
	require.NoError(t, <-waiterResult)
	assert.Equal(t, int64(2), loginRequests.Load())
	client.authMu.Lock()
	assert.Zero(t, client.authFailures)
	client.authMu.Unlock()
}

func TestClientSessionTokenFailureDoesNotPublishPartialAuth(t *testing.T) {
	var loginRequests atomic.Int64
	var tokenRequests atomic.Int64
	var dataRequests atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/j_security_check":
			loginRequests.Add(1)
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "partial-session"})
			w.WriteHeader(http.StatusOK)
		case "/dataservice/client/token":
			tokenRequests.Add(1)
			http.Error(w, "token unavailable", http.StatusServiceUnavailable)
		case "/dataservice/events":
			dataRequests.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"eventId": "unexpected"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		AuthMode:   "session",
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 0,
	})
	require.NoError(t, err)
	client.spacing = 0

	for range 2 {
		_, requestErr := client.PostQuery(t.Context(), "events", "/events", map[string]any{"size": 1}, 0)
		require.Error(t, requestErr)
	}

	client.authMu.Lock()
	published := client.authBundleLocked()
	client.authMu.Unlock()
	assert.Empty(t, published.bearerToken)
	assert.Empty(t, published.jsessionID)
	assert.Empty(t, published.xsrfToken)
	assert.Equal(t, int64(1), loginRequests.Load())
	assert.Equal(t, int64(1), tokenRequests.Load())
	assert.Zero(t, dataRequests.Load())
}

func TestClientStaleUnauthorizedDoesNotClearNewerAuth(t *testing.T) {
	client, err := NewClient(Config{
		Endpoint: "https://sdwan.example.com",
		AuthMode: "session",
		Username: "admin",
		Password: "password",
	})
	require.NoError(t, err)

	client.authMu.Lock()
	client.authGeneration = 2
	client.setAuthBundleLocked(authBundle{jsessionID: "new-session", xsrfToken: "new-xsrf"})
	client.authMu.Unlock()

	client.clearAuth(1, &APIError{StatusCode: http.StatusUnauthorized})
	client.authMu.Lock()
	retained := client.authBundleLocked()
	staleFailures := client.authFailures
	client.authMu.Unlock()
	assert.Equal(t, uint64(2), retained.generation)
	assert.Equal(t, "new-session", retained.jsessionID)
	assert.Equal(t, "new-xsrf", retained.xsrfToken)
	assert.Zero(t, staleFailures)

	client.clearAuth(2, &APIError{StatusCode: http.StatusUnauthorized})
	client.authMu.Lock()
	cleared := client.authBundleLocked()
	failures := client.authFailures
	client.authMu.Unlock()
	assert.Equal(t, uint64(3), cleared.generation)
	assert.Empty(t, cleared.jsessionID)
	assert.Empty(t, cleared.xsrfToken)
	assert.Equal(t, 1, failures)
}

func TestClientUnauthorizedEntersSharedAuthBackoff(t *testing.T) {
	var loginRequests atomic.Int64
	var dataRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwt/login":
			loginRequests.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "rejected-token"})
		case "/dataservice/device":
			dataRequests.Add(1)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint: server.URL,
		AuthMode: "jwt",
		Username: "admin",
		Password: "password",
		Timeout:  time.Second,
	})
	require.NoError(t, err)
	client.spacing = 0

	_, firstErr := client.List(t.Context(), "devices", "/device", nil, 0)
	require.Error(t, firstErr)
	_, secondErr := client.List(t.Context(), "devices", "/device", nil, 0)
	require.Error(t, secondErr)

	assert.Equal(t, int64(1), loginRequests.Load())
	assert.Equal(t, int64(1), dataRequests.Load())
	client.authMu.Lock()
	assert.Equal(t, 1, client.authFailures)
	client.authMu.Unlock()
}

func TestClientForbiddenRetainsAuthAndSuccessfulDataResetsFailureStreak(t *testing.T) {
	var loginRequests atomic.Int64
	var dataRequests atomic.Int64
	var client *Client
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwt/login":
			loginRequests.Add(1)
			client.authMu.Lock()
			client.authFailures = 3
			client.lastAuthErr = &APIError{StatusCode: http.StatusUnauthorized}
			client.lastAuthAt = time.Now()
			client.authMu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "valid-token"})
		case "/dataservice/device":
			request := dataRequests.Add(1)
			if request == 1 {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{{"system-ip": "10.0.0.1"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var err error
	client, err = NewClient(Config{
		Endpoint: server.URL,
		AuthMode: "jwt",
		Username: "admin",
		Password: "password",
		Timeout:  time.Second,
	})
	require.NoError(t, err)
	client.spacing = 0

	_, firstErr := client.List(t.Context(), "devices", "/device", nil, 0)
	require.Error(t, firstErr)
	objects, secondErr := client.List(t.Context(), "devices", "/device", nil, 0)
	require.NoError(t, secondErr)
	require.Len(t, objects, 1)

	assert.Equal(t, int64(1), loginRequests.Load())
	assert.Equal(t, int64(2), dataRequests.Load())
	client.authMu.Lock()
	assert.Zero(t, client.authFailures)
	assert.NoError(t, client.lastAuthErr)
	assert.True(t, client.lastAuthAt.IsZero())
	client.authMu.Unlock()
}
