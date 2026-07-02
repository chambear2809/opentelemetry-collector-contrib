// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meraki

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

func TestClientRetryCountValidation(t *testing.T) {
	client, err := NewClient(Config{
		APIKey:     "test-key",
		BaseURL:    "https://api.meraki.example.com/api/v1",
		MaxRetries: 0,
	})
	require.NoError(t, err)
	assert.Zero(t, client.retries)

	for _, retries := range []int{-1, httpclient.HardMaxRequestRetries + 1} {
		_, err := NewClient(Config{
			APIKey:     "test-key",
			BaseURL:    "https://api.meraki.example.com/api/v1",
			MaxRetries: retries,
		})
		require.ErrorContains(t, err, "invalid meraki max retries")
	}
}

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

func TestClientPreservesLargeGenericJSONInteger(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"counter":9007199254740993}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{APIKey: "test-key", BaseURL: server.URL, Timeout: time.Second})
	require.NoError(t, err)
	got, err := GetJSON[map[string]any](t.Context(), client, "", "counter", "/counter", nil)
	require.NoError(t, err)
	number, ok := got["counter"].(json.Number)
	require.True(t, ok)
	assert.Equal(t, "9007199254740993", number.String())
}

func TestClientPaginationWithAbsoluteAndRelativeLinks(t *testing.T) {
	var count atomic.Int64
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch count.Add(1) {
		case 1:
			assert.Equal(t, "/api/v1/organizations/123456/devices", r.URL.Path)
			w.Header().Set("Link", `<`+serverURL+`/api/v1/organizations/123456/devices?filter=a,b&startingAfter=first>; rel="prev next"`)
			_, _ = w.Write([]byte(`[{"serial":"first"}]`))
		case 2:
			assert.Equal(t, "/api/v1/organizations/123456/devices", r.URL.Path)
			assert.Equal(t, "a,b", r.URL.Query().Get("filter"))
			assert.Equal(t, "first", r.URL.Query().Get("startingAfter"))
			w.Header().Set("Link", `</api/v1/organizations/123456/devices?startingAfter=second>; rel=next`)
			_, _ = w.Write([]byte(`[{"serial":"second"}]`))
		default:
			assert.Equal(t, "/api/v1/organizations/123456/devices", r.URL.Path)
			assert.Equal(t, "second", r.URL.Query().Get("startingAfter"))
			_, _ = w.Write([]byte(`[{"serial":"third"}]`))
		}
	}))
	defer server.Close()
	serverURL = server.URL

	client, err := NewClient(Config{APIKey: "test-key", BaseURL: server.URL + "/api/v1", Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)

	got, err := GetPaginatedJSON[Device](t.Context(), client, "123456", "devices", "/organizations/123456/devices", nil)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "first", got[0].Serial)
	assert.Equal(t, "second", got[1].Serial)
	assert.Equal(t, "third", got[2].Serial)
}

func TestClientRejectsCrossOriginPaginationLink(t *testing.T) {
	var leakedRequests atomic.Int64
	otherOrigin := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		leakedRequests.Add(1)
	}))
	defer otherOrigin.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", `<`+otherOrigin.URL+`/api/v1/devices?startingAfter=secret>; rel="next"`)
		_, _ = w.Write([]byte(`[{"serial":"first"}]`))
	}))
	defer origin.Close()

	client, err := NewClient(Config{APIKey: "test-key", BaseURL: origin.URL + "/api/v1", Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)

	got, err := GetPaginatedJSON[Device](t.Context(), client, "123456", "devices", "/devices", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cross-origin")
	require.Len(t, got, 1)
	assert.Zero(t, leakedRequests.Load())
}

func TestClientRejectsPaginationLinkCycle(t *testing.T) {
	var requests atomic.Int64
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Link", `<`+serverURL+`/api/v1/devices>; rel="next"`)
		_, _ = w.Write([]byte(`[{"serial":"first"}]`))
	}))
	defer server.Close()
	serverURL = server.URL

	client, err := NewClient(Config{APIKey: "test-key", BaseURL: server.URL + "/api/v1", Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)

	got, err := GetPaginatedJSON[Device](t.Context(), client, "123456", "devices", "/devices", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycle detected")
	require.Len(t, got, 1)
	assert.Equal(t, int64(1), requests.Load())
}

func TestClientPaginationUsesSharedTypedPageLimit(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		page := requests.Add(1)
		w.Header().Set("Link", fmt.Sprintf("</devices?page=%d>; rel=next", page+1))
		_, _ = w.Write([]byte(`[{"serial":"device"}]`))
	}))
	defer server.Close()

	client, err := NewClient(Config{APIKey: "test-key", BaseURL: server.URL, Timeout: time.Second})
	require.NoError(t, err)
	client.sourceLimiter.interval = 0

	got, err := GetPaginatedJSON[Device](t.Context(), client, "", "devices", "/devices", nil)
	var limitErr *httpclient.PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.Equal(t, "page", limitErr.Kind)
	assert.Equal(t, httpclient.HardMaxPaginationPages, limitErr.Maximum)
	assert.Len(t, got, httpclient.HardMaxPaginationPages)
	assert.Equal(t, int64(httpclient.HardMaxPaginationPages), requests.Load())
}

func TestClientPaginationReturnsTypedPartialResultLimit(t *testing.T) {
	body := "[" + strings.Repeat("0,", httpclient.HardMaxPaginationResults) + "0]"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	client, err := NewClient(Config{APIKey: "test-key", BaseURL: server.URL, Timeout: time.Second})
	require.NoError(t, err)
	got, err := GetPaginatedJSON[int](t.Context(), client, "", "values", "/values", nil)
	var limitErr *httpclient.PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.Equal(t, "result", limitErr.Kind)
	assert.Equal(t, httpclient.HardMaxPaginationResults, limitErr.Maximum)
	assert.Len(t, got, httpclient.HardMaxPaginationResults)
}

func TestAPIErrorUsesSafeStatusOnlyMessage(t *testing.T) {
	err := (&APIError{StatusCode: http.StatusUnauthorized}).Error()
	assert.Equal(t, "meraki API returned HTTP 401", err)
}

func TestClientDoesNotFollowCrossOriginRedirect(t *testing.T) {
	var leakedAuthorization atomic.Bool
	otherOrigin := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		leakedAuthorization.Store(r.Header.Get("Authorization") != "")
	}))
	defer otherOrigin.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, otherOrigin.URL+"/stolen", http.StatusFound)
	}))
	defer origin.Close()

	client, err := NewClient(Config{APIKey: "test-key", BaseURL: origin.URL, Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)

	_, err = GetJSON[map[string]bool](t.Context(), client, "123456", "redirect", "/test", nil)
	require.Error(t, err)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusFound, apiErr.StatusCode)
	assert.False(t, leakedAuthorization.Load())
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

func TestClientDoesNotSleepAfterFinalRetry(t *testing.T) {
	var attempts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempt := attempts.Add(1)
		if attempt == 1 {
			w.Header().Set("Retry-After", "0")
		} else {
			w.Header().Set("Retry-After", "2")
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client, err := NewClient(Config{APIKey: "test-key", BaseURL: server.URL, Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)

	start := time.Now()
	_, err = GetJSON[map[string]bool](t.Context(), client, "123456", "test", "/test", nil)
	require.Error(t, err)
	assert.Equal(t, int64(2), attempts.Load())
	assert.Less(t, time.Since(start), 500*time.Millisecond)
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
