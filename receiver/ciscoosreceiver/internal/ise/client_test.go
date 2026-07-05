// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

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

func TestClientListERSPaginatesAndRecordsStats(t *testing.T) {
	var pages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:password")), r.Header.Get("Authorization"))
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
	assert.Equal(t, []string{"1", "2"}, pages)
	assert.Equal(t, "3", String(objects[2], "id"))
	require.Len(t, stats, 2)
	assert.Equal(t, "success", stats[0].Outcome)
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
	require.ErrorContains(t, err, "exceeded 2 results")
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
	require.ErrorContains(t, err, "exceeded 2 results")
	assert.Len(t, objects, 2)
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
	require.ErrorContains(t, err, "exceeded 1 pages")
	assert.Len(t, objects, 1)
	assert.Equal(t, 1, requests)
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
