// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sdwan

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
