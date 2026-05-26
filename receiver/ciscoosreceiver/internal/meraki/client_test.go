// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meraki

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientAuthHeadersAndQuery(t *testing.T) {
	var sawRequest atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawRequest.Store(true)
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))
		assert.Equal(t, "test-agent", r.Header.Get("User-Agent"))
		assert.Equal(t, "Q234-ABCD-5678", r.URL.Query().Get("serials[]"))
		assert.Equal(t, "1000", r.URL.Query().Get("perPage"))
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		APIKey:     "test-key",
		BaseURL:    server.URL + "/api/v1",
		UserAgent:  "test-agent",
		Timeout:    time.Second,
		MaxRetries: 1,
	})
	require.NoError(t, err)

	query := Query(map[string][]string{"serials": {"Q234-ABCD-5678"}}, map[string]string{"perPage": "1000"})
	got, err := GetJSON[map[string]bool](t.Context(), client, "123456", "test", "/organizations/123456/devices", query)
	require.NoError(t, err)
	assert.True(t, got["ok"])
	assert.True(t, sawRequest.Load())
}

func TestClientPaginationWithAbsoluteAndRelativeLinks(t *testing.T) {
	var count atomic.Int64
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch count.Add(1) {
		case 1:
			assert.Equal(t, "/api/v1/organizations/123456/devices", r.URL.Path)
			w.Header().Set("Link", `<`+serverURL+`/api/v1/organizations/123456/devices?startingAfter=first>; rel="next"`)
			_, _ = w.Write([]byte(`[{"serial":"first"}]`))
		default:
			assert.Equal(t, "/api/v1/organizations/123456/devices", r.URL.Path)
			assert.Equal(t, "first", r.URL.Query().Get("startingAfter"))
			_, _ = w.Write([]byte(`[{"serial":"second"}]`))
		}
	}))
	defer server.Close()
	serverURL = server.URL

	client, err := NewClient(Config{APIKey: "test-key", BaseURL: server.URL + "/api/v1", Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)

	got, err := GetPaginatedJSON[Device](t.Context(), client, "123456", "devices", "/organizations/123456/devices", nil)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "first", got[0].Serial)
	assert.Equal(t, "second", got[1].Serial)
}

func TestClientPaginatedItemsEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{"serial":"Q234-ABCD-5678"}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{APIKey: "test-key", BaseURL: server.URL, Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)

	got, err := GetPaginatedItemsJSON[Device](t.Context(), client, "123456", "devices", "/devices", nil)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "Q234-ABCD-5678", got[0].Serial)
}

func TestClientRetries429RetryAfter(t *testing.T) {
	var attempts atomic.Int64
	var stats []RequestStat
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`rate limited`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{APIKey: "test-key", BaseURL: server.URL, Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)
	client.OnRequest = func(stat RequestStat) {
		stats = append(stats, stat)
	}

	got, err := GetJSON[map[string]bool](t.Context(), client, "123456", "test", "/test", nil)
	require.NoError(t, err)
	assert.True(t, got["ok"])
	assert.Equal(t, int64(2), attempts.Load())
	require.Len(t, stats, 2)
	assert.True(t, stats[0].RateLimited)
	assert.Equal(t, http.StatusTooManyRequests, stats[0].StatusCode)
	assert.Equal(t, "success", stats[1].Outcome)
}

func TestClientRetries5xx(t *testing.T) {
	var attempts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{APIKey: "test-key", BaseURL: server.URL, Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)

	got, err := GetJSON[map[string]bool](t.Context(), client, "123456", "test", "/test", nil)
	require.NoError(t, err)
	assert.True(t, got["ok"])
	assert.Equal(t, int64(2), attempts.Load())
}

func TestClientContextTimeoutDuringRetry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := NewClient(Config{APIKey: "test-key", BaseURL: server.URL, Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	_, err = GetJSON[map[string]bool](ctx, client, "123456", "test", "/test", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestClientLimiterSpacesRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{APIKey: "test-key", BaseURL: server.URL, Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)

	start := time.Now()
	_, err = GetJSON[map[string]bool](t.Context(), client, "123456", "first", "/test", nil)
	require.NoError(t, err)
	_, err = GetJSON[map[string]bool](t.Context(), client, "123456", "second", "/test", nil)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, time.Since(start), 90*time.Millisecond)
}

func TestClientRejectsInvalidConfig(t *testing.T) {
	_, err := NewClient(Config{})
	require.Error(t, err)

	_, err = NewClient(Config{APIKey: "test-key", BaseURL: "://bad"})
	require.Error(t, err)
}

func TestQueryEncoding(t *testing.T) {
	got := Query(map[string][]string{
		"serials": {"Q234-ABCD-5678", ""},
	}, map[string]string{
		"perPage": "1000",
	})
	assert.Equal(t, url.Values{
		"serials[]": {"Q234-ABCD-5678"},
		"perPage":   {"1000"},
	}, got)
}

func TestDecodeErrorIncludesOperation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer server.Close()

	client, err := NewClient(Config{APIKey: "test-key", BaseURL: server.URL, Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)

	_, err = GetJSON[json.RawMessage](t.Context(), client, "123456", "decode_test", "/test", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode meraki decode_test response")
}
