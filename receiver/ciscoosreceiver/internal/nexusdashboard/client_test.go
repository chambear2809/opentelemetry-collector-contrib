// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nexusdashboard

import (
	"net/http"
	"net/http/httptest"
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
