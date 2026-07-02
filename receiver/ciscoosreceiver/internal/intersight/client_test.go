// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package intersight

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
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

func TestClientRetryValidationPreservesExplicitZero(t *testing.T) {
	key := testPrivateKeyPEM(t)
	client, err := NewClient(Config{Endpoint: "https://intersight.example.test", KeyID: "key-id", KeyPEM: key, MaxRetries: 0})
	require.NoError(t, err)
	assert.Zero(t, client.retries)
	for _, retries := range []int{-1, httpclient.HardMaxRequestRetries + 1} {
		_, err = NewClient(Config{Endpoint: "https://intersight.example.test", KeyID: "key-id", KeyPEM: key, MaxRetries: retries})
		require.ErrorContains(t, err, "invalid intersight max retries")
	}
}

func TestClientSignsRequestsAndEncodesODataQuery(t *testing.T) {
	var sawRequest atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawRequest.Store(true)
		assert.Equal(t, "/api/v1/compute/PhysicalSummaries", r.URL.Path)
		assert.Equal(t, "test-agent", r.Header.Get("User-Agent"))
		assert.Contains(t, r.Header.Get("Authorization"), `Signature keyId="test-key"`)
		assert.Contains(t, r.Header.Get("Authorization"), `algorithm="ed25519"`)
		assert.Contains(t, r.Header.Get("Authorization"), `(request-target) host date digest`)
		assert.NotEmpty(t, r.Header.Get("Date"))
		assert.NotEmpty(t, r.Header.Get("Digest"))
		assert.Equal(t, "Moid,Name", r.URL.Query().Get("$select"))
		assert.Equal(t, "Status eq 'Connected'", r.URL.Query().Get("$filter"))
		assert.Equal(t, "25", r.URL.Query().Get("$top"))
		assert.Equal(t, "0", r.URL.Query().Get("$skip"))
		_, _ = w.Write([]byte(`{"Results":[{"Moid":"moid-1","Name":"server-1"}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		KeyID:      "test-key",
		KeyPEM:     testPrivateKeyPEM(t),
		Endpoint:   server.URL,
		UserAgent:  "test-agent",
		Timeout:    time.Second,
		MaxRetries: 1,
		PageSize:   25,
	})
	require.NoError(t, err)

	got, err := client.List(t.Context(), "compute.physical_summaries", "/api/v1/compute/PhysicalSummaries", Query([]string{"Moid", "Name"}, "Status eq 'Connected'"), 0)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "moid-1", got[0]["Moid"])
	assert.True(t, sawRequest.Load())
}

func TestDecodeListPreservesLargeInteger(t *testing.T) {
	objects, err := decodeList([]byte(`{"Results":[{"Bytes":9007199254740993}]}`))
	require.NoError(t, err)
	require.Len(t, objects, 1)
	value, ok := Int64(objects[0], "Bytes")
	require.True(t, ok)
	assert.Equal(t, int64(9007199254740993), value)
}

func TestClientSignsECDSARequestsWithHS2019(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.Header.Get("Authorization"), `Signature keyId="test-key"`)
		assert.Contains(t, r.Header.Get("Authorization"), `algorithm="hs2019"`)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		KeyID:      "test-key",
		KeyPEM:     testECDSAPrivateKeyPEM(t),
		Endpoint:   server.URL,
		Timeout:    time.Second,
		MaxRetries: 1,
	})
	require.NoError(t, err)

	_, err = client.List(t.Context(), "asset.targets", "/api/v1/asset/Targets", nil, 1)
	require.NoError(t, err)
}

func TestClientSupportsSelfSignedTLSWithInsecureSkipVerify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/asset/Targets", r.URL.Path)
		assert.Contains(t, r.Header.Get("Authorization"), `Signature keyId="test-key"`)
		_, _ = w.Write([]byte(`{"Results":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		KeyID:              "test-key",
		KeyPEM:             testPrivateKeyPEM(t),
		Endpoint:           server.URL,
		Timeout:            time.Second,
		MaxRetries:         1,
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)

	got, err := client.List(t.Context(), "asset.targets", "/api/v1/asset/Targets", nil, 0)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestClientPaginatesWithTopSkipAndMaxResults(t *testing.T) {
	var attempts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch attempts.Add(1) {
		case 1:
			assert.Equal(t, "2", r.URL.Query().Get("$top"))
			assert.Equal(t, "0", r.URL.Query().Get("$skip"))
			_, _ = w.Write([]byte(`{"Results":[{"Moid":"first"},{"Moid":"second"}]}`))
		default:
			assert.Equal(t, "1", r.URL.Query().Get("$top"))
			assert.Equal(t, "2", r.URL.Query().Get("$skip"))
			_, _ = w.Write([]byte(`{"Results":[{"Moid":"third"}]}`))
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{KeyID: "test-key", KeyPEM: testPrivateKeyPEM(t), Endpoint: server.URL, Timeout: time.Second, MaxRetries: 1, PageSize: 2})
	require.NoError(t, err)

	got, err := client.List(t.Context(), "asset.targets", "/api/v1/asset/Targets", nil, 3)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, int64(2), attempts.Load())
	assert.Equal(t, "third", got[2]["Moid"])
}

func TestClientMaxResultsCapsOverReturnedPage(t *testing.T) {
	var attempts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		assert.Equal(t, "2", r.URL.Query().Get("$top"))
		_, _ = w.Write([]byte(`{"Results":[{"Moid":"first"},{"Moid":"second"},{"Moid":"unexpected"}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{KeyID: "test-key", KeyPEM: testPrivateKeyPEM(t), Endpoint: server.URL, Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)

	got, err := client.List(t.Context(), "asset.targets", "/api/v1/asset/Targets", nil, 2)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "second", got[1]["Moid"])
	assert.Equal(t, int64(1), attempts.Load())
}

func TestClientPaginationHardPageLimitReturnsPartialResults(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"Results":[{"Moid":"` + r.URL.Query().Get("$skip") + `"}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		KeyID:      "test-key",
		KeyPEM:     testPrivateKeyPEM(t),
		Endpoint:   server.URL,
		Timeout:    time.Second,
		MaxRetries: 1,
		PageSize:   1,
	})
	require.NoError(t, err)

	got, err := client.List(t.Context(), "asset.targets", "/api/v1/asset/Targets", nil, 0)
	var limitErr *httpclient.PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.Equal(t, "page", limitErr.Kind)
	assert.Len(t, got, httpclient.HardMaxPaginationPages)
	assert.Equal(t, int64(httpclient.HardMaxPaginationPages), requests.Load())
}

func TestClientRetriesRateLimitsAndRecordsStats(t *testing.T) {
	var attempts atomic.Int64
	var stats []RequestStat
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`rate limited`))
			return
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	client, err := NewClient(Config{KeyID: "test-key", KeyPEM: testPrivateKeyPEM(t), Endpoint: server.URL, Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)
	client.OnRequest = func(stat RequestStat) {
		stats = append(stats, stat)
	}

	got, err := client.List(t.Context(), "cond.alarms", "/api/v1/cond/Alarms", nil, 0)
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Equal(t, int64(2), attempts.Load())
	require.Len(t, stats, 2)
	assert.True(t, stats[0].RateLimited)
	assert.Equal(t, http.StatusTooManyRequests, stats[0].StatusCode)
	assert.Equal(t, "success", stats[1].Outcome)
}

func TestClientPostJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/telemetry/GroupBys", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Contains(t, r.Header.Get("Authorization"), `Signature keyId="test-key"`)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), `"queryType":"groupBy"`)
		_, _ = w.Write([]byte(`[{"event":{"host.name":"server-1","hw.fan.speed-Sum":12000}}]`))
	}))
	defer server.Close()

	client, err := NewClient(Config{KeyID: "test-key", KeyPEM: testPrivateKeyPEM(t), Endpoint: server.URL, Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)

	got, err := client.PostJSON(t.Context(), "telemetry.fan_speed", "/api/v1/telemetry/GroupBys", map[string]any{"queryType": "groupBy"})
	require.NoError(t, err)
	results, ok := got.([]any)
	require.True(t, ok)
	require.Len(t, results, 1)
}

func TestClientRejectsInvalidConfig(t *testing.T) {
	_, err := NewClient(Config{})
	require.Error(t, err)

	_, err = NewClient(Config{KeyID: "test-key", KeyPEM: testPrivateKeyPEM(t), Endpoint: "://bad"})
	require.Error(t, err)

	_, err = NewClient(Config{KeyID: "test-key", KeyPEM: "not-pem"})
	require.Error(t, err)
}

func TestQuery(t *testing.T) {
	got := Query([]string{"Moid", "Name"}, "Status eq 'Connected'")
	assert.Equal(t, url.Values{
		"$select": {"Moid,Name"},
		"$filter": {"Status eq 'Connected'"},
	}, got)

	assert.Empty(t, Query(nil, ""))
}

func TestDecodeListSupportsArrayAndEnvelope(t *testing.T) {
	envelope, err := decodeList([]byte(`{"Results":[{"Moid":"moid-1"}],"Count":1}`))
	require.NoError(t, err)
	require.Len(t, envelope, 1)
	assert.Equal(t, "moid-1", envelope[0]["Moid"])

	array, err := decodeList([]byte(`[{"Moid":"moid-2"}]`))
	require.NoError(t, err)
	require.Len(t, array, 1)
	assert.Equal(t, "moid-2", array[0]["Moid"])

	_, err = decodeList([]byte(`not-json`))
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "invalid character"))
}

func testPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
}

func testECDSAPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))
}
