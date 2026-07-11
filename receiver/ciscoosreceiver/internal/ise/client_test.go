// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

func TestClientRetriesIncompleteSuccessfulResponseBody(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("Content-Length", "100")
			w.Header().Set("Retry-After", "0")
			_, _ = w.Write([]byte(`{"ok":`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", MaxRetries: 1})
	require.NoError(t, err)
	object, err := client.GetObject(t.Context(), "test.get", "/api/v1/test", nil)
	require.NoError(t, err)
	assert.Equal(t, true, object["ok"])
	assert.Equal(t, int64(2), requests.Load())
}

func TestClientHonorsRetryAfter(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", MaxRetries: 1})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	_, err = client.GetObject(ctx, "test.rate_limit", "/api/v1/test", nil)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, int64(1), requests.Load())
	assert.Equal(t, 3*time.Second, retryAfter("3"))
}

func TestClientRetryCountValidation(t *testing.T) {
	client, err := NewClient(Config{
		Endpoint:   "https://ise.example.com",
		Username:   "admin",
		Password:   "password",
		MaxRetries: 0,
	})
	require.NoError(t, err)
	assert.Zero(t, client.retries)

	for _, retries := range []int{-1, httpclient.HardMaxRequestRetries + 1} {
		_, err := NewClient(Config{
			Endpoint:   "https://ise.example.com",
			Username:   "admin",
			Password:   "password",
			MaxRetries: retries,
		})
		require.ErrorContains(t, err, "invalid ise max retries")
	}
}

func TestClientRejectsRedirectsWithoutFollowingOrForwardingAuthorization(t *testing.T) {
	t.Run("same origin", func(t *testing.T) {
		requests := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			if r.URL.Path == "/login" {
				t.Error("ISE client followed a same-origin API redirect")
			}
			http.Redirect(w, r, "/login", http.StatusFound)
		}))
		defer server.Close()

		client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password"})
		require.NoError(t, err)
		client.spacing = 0

		_, err = client.GetObject(t.Context(), "openapi.redirect", "/api/v1/resource", nil)
		var apiErr *APIError
		require.ErrorAs(t, err, &apiErr)
		assert.Equal(t, http.StatusFound, apiErr.StatusCode)
		assert.Equal(t, 1, requests)
	})

	t.Run("cross origin", func(t *testing.T) {
		attackerRequests := make(chan string, 1)
		attacker := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			attackerRequests <- r.Header.Get("Authorization")
		}))
		defer attacker.Close()
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, attacker.URL+"/login", http.StatusFound)
		}))
		defer origin.Close()

		client, err := NewClient(Config{Endpoint: origin.URL, Username: "admin", Password: "password"})
		require.NoError(t, err)
		client.spacing = 0

		_, err = client.GetObject(t.Context(), "openapi.cross_origin_redirect", "/api/v1/resource", nil)
		var apiErr *APIError
		require.ErrorAs(t, err, &apiErr)
		assert.Equal(t, http.StatusFound, apiErr.StatusCode)
		select {
		case auth := <-attackerRequests:
			t.Fatalf("cross-origin server received redirected authorization %q", auth)
		default:
		}
	})
}

func TestClientRejectsHTMLAndUnsupportedResponseContent(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		kind        string
	}{
		{name: "declared HTML", contentType: "text/html; charset=utf-8", body: `<html><body>secret-login-form</body></html>`, kind: "HTML"},
		{name: "mislabeled HTML", contentType: "application/json", body: `<?xml version="1.0"?><html><body>secret-login-form</body></html>`, kind: "HTML"},
		{name: "unsupported type", contentType: "application/octet-stream", body: `{"id":"one"}`, kind: "unsupported"},
		{name: "JSON type with XML", contentType: "application/json", body: `<resource><id>one</id></resource>`, kind: "content-type-mismatch"},
		{name: "plain arbitrary text", contentType: "text/plain", body: `secret-login-form`, kind: "unrecognized"},
		{name: "invalid type", contentType: `application/json; charset="`, body: `{"id":"one"}`, kind: "invalid-content-type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password"})
			require.NoError(t, err)
			client.spacing = 0
			var stats []RequestStat
			client.OnRequest = func(stat RequestStat) { stats = append(stats, stat) }

			_, err = client.GetObject(t.Context(), "openapi.content", "/api/v1/resource", nil)
			var contentErr *ResponseContentError
			require.ErrorAs(t, err, &contentErr)
			assert.Equal(t, tt.kind, contentErr.Kind)
			assert.NotContains(t, err.Error(), "secret-login-form")
			require.Len(t, stats, 1)
			assert.Equal(t, "error", stats[0].Outcome)
			assert.Same(t, contentErr, stats[0].Err)
		})
	}
}

func TestClientAcceptsCiscoVendorJSONAndXMLContentTypes(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "JSON", contentType: "application/vnd.com.cisco.ise.identity.networkdevice.1.1+json", body: `{"id":"one"}`},
		{name: "XML", contentType: "application/vnd.com.cisco.ise.identity.networkdevice.1.1+xml", body: `<networkDevice><id>one</id></networkDevice>`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password"})
			require.NoError(t, err)
			client.spacing = 0

			obj, err := client.GetObject(t.Context(), "openapi.content", "/api/v1/resource", nil)
			require.NoError(t, err)
			assert.Equal(t, "one", String(obj, "id"))
		})
	}
}

func TestClientERSCSRFNegotiatesSessionAndReusesToken(t *testing.T) {
	const (
		sessionCookie = "session-one"
		csrfToken     = "csrf-token-one" //nolint:gosec // Test protocol token, not a credential.
	)
	var fetches, protected int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		switch r.Header.Get(ersCSRFHeader) {
		case ersCSRFFetchValue:
			fetches++
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			http.SetCookie(w, &http.Cookie{Name: "APPSESSIONID", Value: sessionCookie, Path: "/"})
			w.Header().Set(ersCSRFHeader, csrfToken)
		case csrfToken:
			protected++
			cookie, err := r.Cookie("APPSESSIONID")
			if assert.NoError(t, err) {
				assert.Equal(t, sessionCookie, cookie.Value)
			}
		default:
			t.Errorf("ERS request did not contain the expected CSRF header")
		}
		if r.URL.Query().Get("page") == "2" {
			_, _ = w.Write([]byte(`{"SearchResult":{"total":2,"resources":[{"id":"2"}]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"SearchResult":{"total":2,"resources":[{"id":"1"}]}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", PageSize: 1})
	require.NoError(t, err)
	client.spacing = 0
	var stats []RequestStat
	client.OnRequest = func(stat RequestStat) { stats = append(stats, stat) }

	objects, err := client.ListERS(t.Context(), "ers.network_devices", "/ers/config/networkdevice", nil, 0)
	require.NoError(t, err)
	require.Len(t, objects, 2)
	assert.Equal(t, 1, fetches)
	assert.Equal(t, 2, protected)
	require.Len(t, stats, 3)
	assert.Equal(t, ersCSRFOperation, stats[0].Operation)
	assert.Equal(t, ersCSRFStatPath, stats[0].Path)
	assert.False(t, stats[0].CSRFProtected)
	for _, stat := range stats[1:] {
		assert.Equal(t, "ers.network_devices", stat.Operation)
		assert.True(t, stat.CSRFProtected)
		assert.NotContains(t, stat.Path, csrfToken)
	}
}

func TestClientERSCSRFNegotiationFallsBackWhenServerDoesNotIssueToken(t *testing.T) {
	var fetches, ordinary int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(ersCSRFHeader) == ersCSRFFetchValue {
			fetches++
		} else {
			ordinary++
			assert.Empty(t, r.Header.Get(ersCSRFHeader))
		}
		_, _ = w.Write([]byte(`{"id":"one"}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password"})
	require.NoError(t, err)
	client.spacing = 0
	var stats []RequestStat
	client.OnRequest = func(stat RequestStat) { stats = append(stats, stat) }

	_, err = client.GetObject(t.Context(), "ers.first", "/ers/config/networkdevice/one", nil)
	require.NoError(t, err)
	_, err = client.GetObject(t.Context(), "ers.second", "/ers/config/networkdevice/two", nil)
	require.NoError(t, err)
	assert.Equal(t, 1, fetches)
	assert.Equal(t, 2, ordinary)
	require.Len(t, stats, 3)
	assert.Equal(t, ersCSRFOperation, stats[0].Operation)
	assert.False(t, stats[1].CSRFProtected)
	assert.False(t, stats[2].CSRFProtected)
}

func TestClientERSCSRFRefreshesExpiredSessionOnce(t *testing.T) {
	var fetches, protected int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get(ersCSRFHeader)
		if header == ersCSRFFetchValue {
			fetches++
			suffix := "old"
			if fetches == 2 {
				suffix = "new"
			}
			http.SetCookie(w, &http.Cookie{Name: "APPSESSIONID", Value: "session-" + suffix, Path: "/"})
			w.Header().Set(ersCSRFHeader, "token-"+suffix)
			_, _ = w.Write([]byte(`{"id":"handshake"}`))
			return
		}
		protected++
		cookie, err := r.Cookie("APPSESSIONID")
		if !assert.NoError(t, err) {
			http.Error(w, "missing session", http.StatusBadRequest)
			return
		}
		if header == "token-old" {
			assert.Equal(t, "session-old", cookie.Value)
			w.Header().Set(ersCSRFHeader, ersCSRFRequiredValue)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		assert.Equal(t, "token-new", header)
		assert.Equal(t, "session-new", cookie.Value)
		_, _ = w.Write([]byte(`{"id":"one"}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password"})
	require.NoError(t, err)
	client.spacing = 0
	var stats []RequestStat
	client.OnRequest = func(stat RequestStat) { stats = append(stats, stat) }

	obj, err := client.GetObject(t.Context(), "ers.network_device", "/ers/config/networkdevice/one", nil)
	require.NoError(t, err)
	assert.Equal(t, "one", String(obj, "id"))
	assert.Equal(t, 2, fetches)
	assert.Equal(t, 2, protected)
	require.Len(t, stats, 4)
	assert.Equal(t, []string{ersCSRFOperation, "ers.network_device", ersCSRFOperation, "ers.network_device"}, []string{
		stats[0].Operation,
		stats[1].Operation,
		stats[2].Operation,
		stats[3].Operation,
	})
	assert.Equal(t, http.StatusForbidden, stats[1].StatusCode)
	assert.True(t, stats[1].CSRFProtected)
	assert.True(t, stats[3].CSRFProtected)
}

func TestClientERSCSRFDoesNotRefreshMoreThanOnce(t *testing.T) {
	var fetches, protected int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(ersCSRFHeader) == ersCSRFFetchValue {
			fetches++
			w.Header().Set(ersCSRFHeader, "token")
			_, _ = w.Write([]byte(`{"id":"handshake"}`))
			return
		}
		protected++
		w.Header().Set(ersCSRFHeader, ersCSRFRequiredValue)
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password"})
	require.NoError(t, err)
	client.spacing = 0

	_, err = client.GetObject(t.Context(), "ers.network_device", "/ers/config/networkdevice/one", nil)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusForbidden, apiErr.StatusCode)
	assert.Equal(t, 2, fetches)
	assert.Equal(t, 2, protected)
}

func TestClientListERSPaginatesAndRecordsStats(t *testing.T) {
	var fetchAccept string
	var pageAccepts []string
	var pages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:password")), r.Header.Get("Authorization"))
		if r.Header.Get(ersCSRFHeader) == ersCSRFFetchValue {
			fetchAccept = r.Header.Get("Accept")
		} else {
			pageAccepts = append(pageAccepts, r.Header.Get("Accept"))
		}
		pages = append(pages, r.URL.Query().Get("page"))
		switch r.URL.Query().Get("page") {
		case "1":
			_, _ = w.Write([]byte(`{"SearchResult":{"total":3,"resources":[{"id":"1"},{"id":"2"}]}}`))
		case "2":
			_, _ = w.Write([]byte(`{"SearchResult":{"total":3,"resources":[{"id":"3"}]}}`))
		default:
			http.Error(w, "unexpected page", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", PageSize: 2, MaxRetries: 1})
	require.NoError(t, err)
	var stats []RequestStat
	client.OnRequest = func(stat RequestStat) { stats = append(stats, stat) }

	objects, err := client.ListERS(t.Context(), "ers.network_devices", "/ers/config/networkdevice", nil, 0)
	require.NoError(t, err)
	require.Len(t, objects, 3)
	assert.Equal(t, []string{"1", "1", "2"}, pages)
	assert.Equal(t, "application/json", fetchAccept)
	assert.Equal(t, []string{"application/json", "application/json"}, pageAccepts)
	assert.Equal(t, "3", String(objects[2], "id"))
	require.Len(t, stats, 3)
	assert.Equal(t, ersCSRFOperation, stats[0].Operation)
	assert.Equal(t, ersCSRFStatPath, stats[0].Path)
	assert.Equal(t, "success", stats[0].Outcome)
	assert.Equal(t, "ers.network_devices", stats[1].Operation)
}

func TestClientNonERSRequestsPreserveBroadAcceptHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json, application/xml, text/xml", r.Header.Get("Accept"))
		_, _ = w.Write([]byte(`{"id":"one"}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password"})
	require.NoError(t, err)
	client.spacing = 0

	obj, err := client.GetObject(t.Context(), "openapi.resource", "/api/v1/resource", nil)
	require.NoError(t, err)
	assert.Equal(t, "one", String(obj, "id"))
}

func TestClientListERSUsesAuthoritativeTotalWhenServerClampsPages(t *testing.T) {
	var pages, sizes []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		if r.Header.Get(ersCSRFHeader) != ersCSRFFetchValue {
			pages = append(pages, page)
			sizes = append(sizes, r.URL.Query().Get("size"))
		}
		switch page {
		case "1":
			_, _ = w.Write([]byte(`{"SearchResult":{"total":3,"resources":[{"id":"1"}]}}`))
		case "2":
			_, _ = w.Write([]byte(`{"SearchResult":{"resources":[{"id":"2"}]}}`))
		case "3":
			_, _ = w.Write([]byte(`{"SearchResult":{"resources":[{"id":"3"}]}}`))
		default:
			http.Error(w, "unexpected page", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", PageSize: 3})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.ListERS(t.Context(), "ers.clamped", "/ers/config/networkdevice", nil, 0)
	require.NoError(t, err)
	require.Len(t, objects, 3)
	assert.Equal(t, "3", String(objects[2], "id"))
	assert.Equal(t, []string{"1", "2", "3"}, pages)
	assert.Equal(t, []string{"3", "3", "3"}, sizes)
}

func TestClientListERSRejectsPrematureEmptyPageBeforeAdvertisedTotal(t *testing.T) {
	var pages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		if r.Header.Get(ersCSRFHeader) != ersCSRFFetchValue {
			pages = append(pages, page)
		}
		if page == "1" {
			_, _ = w.Write([]byte(`{"SearchResult":{"total":2,"resources":[{"id":"1"}]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"SearchResult":{"resources":[]}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", PageSize: 1})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.ListERS(t.Context(), "ers.premature_empty", "/ers/config/networkdevice", nil, 0)
	require.ErrorContains(t, err, "returned no results after 1 of 2 advertised results")
	assert.Len(t, objects, 1)
	assert.Equal(t, []string{"1", "2"}, pages)
}

func TestClientListERSRejectsContradictoryAdvertisedTotals(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			_, _ = w.Write([]byte(`{"SearchResult":{"total":3,"resources":[{"id":"1"}]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"SearchResult":{"total":2,"resources":[{"id":"2"}]}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", PageSize: 1})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.ListERS(t.Context(), "ers.total_changed", "/ers/config/networkdevice", nil, 0)
	require.ErrorContains(t, err, "changed advertised total from 3 to 2")
	assert.Len(t, objects, 1, "the contradictory page must not be appended")
}

func TestClientListFollowsSameOriginNextLink(t *testing.T) {
	var cursors []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:password")), r.Header.Get("Authorization"))
		cursor := r.URL.Query().Get("cursor")
		cursors = append(cursors, cursor)
		if cursor == "" {
			_, _ = w.Write([]byte(`{"items":[{"id":"1"}],"nextPage":{"href":"/api/v1/things?cursor=next"}}`))
			return
		}
		assert.Equal(t, "next", cursor)
		_, _ = w.Write([]byte(`{"items":[{"id":"2"}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password"})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.List(t.Context(), "openapi.things", "/api/v1/things", nil, 0)
	require.NoError(t, err)
	require.Len(t, objects, 2)
	assert.Equal(t, "2", String(objects[1], "id"))
	assert.Equal(t, []string{"", "next"}, cursors)
}

func TestNextLinkParsesExactRelationAndURLComma(t *testing.T) {
	header := `</api/v1/things?filter=a,b&cursor=next>; rel="next", </api/v1/things?cursor=previous>; rel="prev"`
	assert.Equal(t, "/api/v1/things?filter=a,b&cursor=next", nextLink(header))
	assert.Empty(t, nextLink(`</api/v1/things?cursor=wrong>; rel="next-page"`))
}

func TestClientListUsesExplicitOffsetMetadata(t *testing.T) {
	var offsets []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offset := r.URL.Query().Get("offset")
		offsets = append(offsets, offset)
		switch offset {
		case "":
			_, _ = w.Write([]byte(`{"content":[{"id":"1"},{"id":"2"}],"pagination":{"offset":0,"limit":2,"total":3}}`))
		case "2":
			assert.Equal(t, "2", r.URL.Query().Get("limit"))
			_, _ = w.Write([]byte(`{"content":[{"id":"3"}],"pagination":{"offset":2,"limit":2,"total":3}}`))
		default:
			http.Error(w, "unexpected offset", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password"})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.List(t.Context(), "openapi.offset", "/api/v1/offset", url.Values{"filter": {"active"}}, 0)
	require.NoError(t, err)
	require.Len(t, objects, 3)
	assert.Equal(t, "3", String(objects[2], "id"))
	assert.Equal(t, []string{"", "2"}, offsets)
}

func TestClientListRejectsNonAdvancingOffsetPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[],"pagination":{"offset":0,"limit":2,"total":3}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password"})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.List(t.Context(), "openapi.non_advancing", "/api/v1/offset", nil, 0)
	require.ErrorContains(t, err, "offset pagination did not advance")
	assert.Empty(t, objects)
}

func TestClientListRejectsCrossOriginNextLinkWithoutLeakingAuth(t *testing.T) {
	attackerRequests := make(chan string, 1)
	attacker := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		attackerRequests <- r.Header.Get("Authorization")
	}))
	defer attacker.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{"id":"1"}],"nextPage":{"href":"` + attacker.URL + `/steal"}}`))
	}))
	defer origin.Close()

	client, err := NewClient(Config{Endpoint: origin.URL, Username: "admin", Password: "password"})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.List(t.Context(), "openapi.cross_origin", "/api/v1/things", nil, 0)
	require.ErrorContains(t, err, "cross-origin next-page URL")
	assert.Len(t, objects, 1)
	select {
	case auth := <-attackerRequests:
		t.Fatalf("cross-origin server received request with authorization %q", auth)
	default:
	}
}

func TestClientListDetectsNextLinkCycle(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Link", `</api/v1/things?cursor=same>; rel="next"`)
		_, _ = w.Write([]byte(`{"items":[{"id":"1"}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password"})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.List(t.Context(), "openapi.cycle", "/api/v1/things", nil, 0)
	require.ErrorContains(t, err, "continuation cycle")
	assert.Len(t, objects, 2)
	assert.Equal(t, 2, requests)
}

func TestClientListPreservesLaterPageError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cursor") == "" {
			w.Header().Set("Link", `</api/v1/things?cursor=next>; rel="next"`)
			_, _ = w.Write([]byte(`{"items":[{"id":"1"}]}`))
			return
		}
		http.Error(w, "failed", http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password"})
	require.NoError(t, err)
	client.spacing = 0
	client.retries = 0

	objects, err := client.List(t.Context(), "openapi.error", "/api/v1/things", nil, 0)
	require.Error(t, err)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusInternalServerError, apiErr.StatusCode)
	assert.Len(t, objects, 1)
}

func TestClientListEnforcesHardResultLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{"id":"1"},{"id":"2"},{"id":"3"}],"nextPage":{"href":"/api/v1/things?cursor=next"}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password"})
	require.NoError(t, err)
	client.spacing = 0
	client.maxResults = 2

	objects, err := client.List(t.Context(), "openapi.limit", "/api/v1/things", nil, 10)
	require.ErrorContains(t, err, "hard result limit of 2 exhausted")
	var limitErr *httpclient.PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.True(t, limitErr.Hard)
	assert.Len(t, objects, 2)
}

func TestClientListReportsConfiguredPartialResultLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{"id":"1"},{"id":"2"},{"id":"3"}],"nextPage":{"href":"/api/v1/things?cursor=next"}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password"})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.List(t.Context(), "openapi.configured_limit", "/api/v1/things", nil, 2)
	var limitErr *httpclient.PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.False(t, limitErr.Hard)
	assert.Len(t, objects, 2)
}

func TestClientListERSEnforcesHardResultLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"SearchResult":{"total":3,"resources":[{"id":"1"},{"id":"2"},{"id":"3"}]}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password"})
	require.NoError(t, err)
	client.spacing = 0
	client.maxResults = 2

	objects, err := client.ListERS(t.Context(), "ers.result_limit", "/ers/config/networkdevice", nil, 10)
	require.ErrorContains(t, err, "hard result limit of 2 exhausted")
	var limitErr *httpclient.PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.True(t, limitErr.Hard)
	assert.Len(t, objects, 2)
}

func TestClientListERSReportsConfiguredPartialResultLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"SearchResult":{"total":3,"resources":[{"id":"1"},{"id":"2"}]}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", PageSize: 2})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.ListERS(t.Context(), "ers.configured_limit", "/ers/config/networkdevice", nil, 2)
	var limitErr *httpclient.PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.False(t, limitErr.Hard)
	assert.Len(t, objects, 2)
}

func TestClientListERSExactConfiguredLimitCanBeComplete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"SearchResult":{"total":2,"resources":[{"id":"1"},{"id":"2"}]}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", PageSize: 2})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.ListERS(t.Context(), "ers.complete_limit", "/ers/config/networkdevice", nil, 2)
	require.NoError(t, err)
	assert.Len(t, objects, 2)
}

func TestClientPostQueryReportsConfiguredPartialResultLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		_, _ = w.Write([]byte(`{"items":[{"id":"1"},{"id":"2"},{"id":"3"}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password"})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.PostQuery(t.Context(), "pxgrid.session.get_sessions", "/getSessions", map[string]any{}, 2)
	var limitErr *httpclient.PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.Equal(t, "pxgrid.session.get_sessions", limitErr.Operation)
	assert.Equal(t, "result", limitErr.Kind)
	assert.Equal(t, 2, limitErr.Maximum)
	assert.Equal(t, 2, limitErr.Results)
	assert.False(t, limitErr.Hard)
	require.Len(t, objects, 2)
	assert.Equal(t, "2", String(objects[1], "id"))
}

func TestClientPostQueryPreservesCompleteResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{"id":"1"},{"id":"2"}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password"})
	require.NoError(t, err)
	client.spacing = 0

	for _, maxResults := range []int{0, 2, 3} {
		objects, err := client.PostQuery(t.Context(), "pxgrid.session.get_sessions", "/getSessions", map[string]any{}, maxResults)
		require.NoError(t, err)
		assert.Len(t, objects, 2)
	}
}

func TestClientListERSHonorsPageLimit(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write([]byte(`{"SearchResult":{"resources":[{"id":"1"}]}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", PageSize: 1})
	require.NoError(t, err)
	client.spacing = 0
	client.maxPages = 1

	objects, err := client.ListERS(t.Context(), "ers.limit", "/ers/config/networkdevice", nil, 0)
	var limitErr *httpclient.PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.True(t, limitErr.Hard)
	assert.Equal(t, "page", limitErr.Kind)
	assert.Equal(t, 1, limitErr.Maximum)
	assert.Equal(t, 1, limitErr.Results)
	assert.Len(t, objects, 1)
	assert.Equal(t, 2, requests)
}

func TestClientSupportsPrivateCAAndServerName(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"ise-1"}`))
	}))
	defer server.Close()
	cert := server.Certificate()
	serverName := "example.com"
	if len(cert.DNSNames) > 0 {
		serverName = cert.DNSNames[0]
	}
	caFile := t.TempDir() + "/ise-ca.pem"
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600))

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		Username:   "admin",
		Password:   "password",
		CAFile:     caFile,
		ServerName: serverName,
	})
	require.NoError(t, err)

	obj, err := client.GetObject(t.Context(), "deployment.primary", "/api/v1/deployment/primary", nil)
	require.NoError(t, err)
	assert.Equal(t, "ise-1", String(obj, "id"))
}

func TestClientSupportsSelfSignedTLSWithInsecureSkipVerify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"ise-1"}`))
	}))
	defer server.Close()

	verifiedClient, err := NewClient(Config{
		Endpoint:   server.URL,
		Username:   "admin",
		Password:   "password",
		MaxRetries: 3,
	})
	require.NoError(t, err)
	verifiedAttempts := 0
	verifiedClient.OnRequest = func(RequestStat) { verifiedAttempts++ }
	_, err = verifiedClient.GetObject(t.Context(), "deployment.primary", "/api/v1/deployment/primary", nil)
	require.ErrorContains(t, err, "configure ise.ca_file with the issuing CA (preferred)")
	require.ErrorContains(t, err, "set ise.insecure_skip_verify: true")
	assert.Equal(t, 1, verifiedAttempts)

	client, err := NewClient(Config{
		Endpoint:           server.URL,
		Username:           "admin",
		Password:           "password",
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)

	obj, err := client.GetObject(t.Context(), "deployment.primary", "/api/v1/deployment/primary", nil)
	require.NoError(t, err)
	assert.Equal(t, "ise-1", String(obj, "id"))
}

func TestClientRejectsInvalidCAFile(t *testing.T) {
	caFile := t.TempDir() + "/invalid-ca.pem"
	require.NoError(t, os.WriteFile(caFile, []byte("not a certificate"), 0o600))

	_, err := NewClient(Config{
		Endpoint: "https://ise.example.com",
		Username: "admin",
		Password: "password",
		CAFile:   caFile,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not contain PEM certificates")
}

func TestClientClassifiesUnavailableErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "ERS disabled", http.StatusForbidden)
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password"})
	require.NoError(t, err)
	_, err = client.GetObject(t.Context(), "ers.disabled", "/ers/config/networkdevice", nil)
	require.Error(t, err)
	assert.True(t, IsUnavailable(err))
}
