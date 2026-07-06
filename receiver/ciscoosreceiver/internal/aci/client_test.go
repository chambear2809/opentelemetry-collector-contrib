// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package aci

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

func TestClientRetryValidationPreservesExplicitZero(t *testing.T) {
	client, err := NewClient(Config{Endpoint: "https://apic.example.test", Username: "admin", Password: "password", MaxRetries: 0})
	require.NoError(t, err)
	assert.Zero(t, client.retries)
	for _, retries := range []int{-1, httpclient.HardMaxRequestRetries + 1} {
		_, err = NewClient(Config{Endpoint: "https://apic.example.test", Username: "admin", Password: "password", MaxRetries: retries})
		require.ErrorContains(t, err, "invalid apic max retries")
	}
}

func TestClientLoginCookieAndClassDecode(t *testing.T) {
	var logins atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			logins.Add(1)
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token"}}}]}`))
			return
		}
		assert.Equal(t, "/api/class/fabricNode.json", r.URL.Path)
		assert.Equal(t, "1", r.URL.Query().Get("page-size"))
		assert.Equal(t, "0", r.URL.Query().Get("page"))
		cookie, err := r.Cookie("APIC-cookie")
		if !assert.NoError(t, err) {
			http.Error(w, "missing authentication cookie", http.StatusUnauthorized)
			return
		}
		assert.Equal(t, "apic-token", cookie.Value)
		_, _ = w.Write([]byte(`{"totalCount":"1","imdata":[{"fabricNode":{"attributes":{"id":"101","serial":"ABC123","name":"leaf101"}}}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 1,
		PageSize:   25,
	})
	require.NoError(t, err)

	got, err := client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 1)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "fabricNode", got[0]["aci.class"])
	assert.Equal(t, "ABC123", got[0]["serial"])
	assert.Equal(t, int64(1), logins.Load())
}

func TestDecodeObjectsPreservesLargeInteger(t *testing.T) {
	objects, total, err := decodeObjects([]byte(`{"totalCount":"1","imdata":[{"ethpmPhysIf":{"attributes":{"bytes":9007199254740993}}}]}`))
	require.NoError(t, err)
	require.Len(t, objects, 1)
	assert.Equal(t, 1, total)
	value, ok := Int64(objects[0], "bytes")
	require.True(t, ok)
	assert.Equal(t, int64(9007199254740993), value)
}

func TestClientSupportsSelfSignedTLSWithInsecureSkipVerify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token"}}}]}`))
			return
		}
		assert.Equal(t, "/api/class/fabricNode.json", r.URL.Path)
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
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
	_, err = verifiedClient.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.ErrorContains(t, err, "configure aci.ca_file with the issuing CA (preferred)")
	require.ErrorContains(t, err, "set aci.insecure_skip_verify: true")

	client, err := NewClient(Config{
		Endpoint:           server.URL,
		Username:           "admin",
		Password:           "password",
		Timeout:            time.Second,
		MaxRetries:         1,
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)

	got, err := client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestClientSupportsPrivateCAAndServerName(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token"}}}]}`))
			return
		}
		assert.Equal(t, "/api/class/fabricNode.json", r.URL.Path)
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
	}))
	defer server.Close()

	certificate := server.Certificate()
	require.NotEmpty(t, certificate.DNSNames)
	caFile := filepath.Join(t.TempDir(), "apic-ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600))
	endpoint := strings.Replace(server.URL, "127.0.0.1", "localhost", 1)

	nameMismatchClient, err := NewClient(Config{
		Endpoint:   endpoint,
		Username:   "admin",
		Password:   "password",
		CAFile:     caFile,
		MaxRetries: 0,
	})
	require.NoError(t, err)
	_, err = nameMismatchClient.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.ErrorContains(t, err, "configure aci.server_name")
	require.ErrorContains(t, err, "certificate SAN")

	client, err := NewClient(Config{
		Endpoint:   endpoint,
		Username:   "admin",
		Password:   "password",
		CAFile:     caFile,
		ServerName: certificate.DNSNames[0],
		MaxRetries: 0,
	})
	require.NoError(t, err)

	transport := client.client.Transport.(*http.Transport)
	require.NotNil(t, transport.TLSClientConfig)
	assert.Equal(t, certificate.DNSNames[0], transport.TLSClientConfig.ServerName)
	require.NotNil(t, transport.TLSClientConfig.RootCAs)

	got, err := client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestClientRejectsInvalidCAFile(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		caFile := filepath.Join(t.TempDir(), "missing-ca.pem")
		_, err := NewClient(Config{
			Endpoint: "https://apic.example.test",
			Username: "admin",
			Password: "password",
			CAFile:   caFile,
		})
		require.ErrorContains(t, err, "read APIC CA file")
		require.ErrorContains(t, err, caFile)
	})

	t.Run("invalid PEM", func(t *testing.T) {
		caFile := filepath.Join(t.TempDir(), "invalid-ca.pem")
		require.NoError(t, os.WriteFile(caFile, []byte("not a certificate"), 0o600))
		_, err := NewClient(Config{
			Endpoint: "https://apic.example.test",
			Username: "admin",
			Password: "password",
			CAFile:   caFile,
		})
		require.ErrorContains(t, err, "aci.ca_file")
		require.ErrorContains(t, err, "did not contain PEM certificates")
	})
}

func TestClientCertificateVerificationFailureIsTerminal(t *testing.T) {
	t.Run("login", func(t *testing.T) {
		client, err := NewClient(Config{
			Endpoint:   "https://apic.example.test",
			Username:   "admin",
			Password:   "password",
			MaxRetries: 3,
		})
		require.NoError(t, err)
		transport := &certificateFailureTransport{}
		client.client.Transport = transport

		// A regression would wait in the outer data retry loop after the one
		// failed login and return the deadline instead of the certificate error.
		ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		defer cancel()
		_, err = client.ListClass(ctx, "fabric.nodes", "fabricNode", nil, 0)
		require.Error(t, err)
		assert.True(t, httpclient.IsCertificateVerificationError(err))
		assert.NotErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, int64(1), transport.attempts.Load())
	})

	t.Run("data", func(t *testing.T) {
		client, err := NewClient(Config{
			Endpoint:   "https://apic.example.test",
			Username:   "admin",
			Password:   "password",
			MaxRetries: 3,
		})
		require.NoError(t, err)
		transport := &certificateFailureTransport{}
		client.client.Transport = transport
		client.tokenMu.Lock()
		client.token = "apic-token"
		client.tokenGeneration = 1
		client.tokenMu.Unlock()

		_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
		require.Error(t, err)
		assert.True(t, httpclient.IsCertificateVerificationError(err))
		assert.Equal(t, int64(1), transport.attempts.Load())
	})
}

type certificateFailureTransport struct {
	attempts atomic.Int64
}

func (t *certificateFailureTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.attempts.Add(1)
	return nil, x509.UnknownAuthorityError{}
}

func TestClientRetriesRateLimitsAndRecordsStats(t *testing.T) {
	var attempts atomic.Int64
	var stats []RequestStat
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token"}}}]}`))
			return
		}
		if attempts.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 1})
	require.NoError(t, err)
	client.OnRequest = func(stat RequestStat) {
		stats = append(stats, stat)
	}

	got, err := client.ListClass(t.Context(), "fault.instances", "faultInst", nil, 0)
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Equal(t, int64(2), attempts.Load())
	assert.True(t, stats[1].RateLimited)
	assert.Equal(t, "success", stats[2].Outcome)
}

func TestClientRejectedIssuedTokenEntersSharedBackoffUntilDataSucceeds(t *testing.T) {
	var logins atomic.Int64
	var dataRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			token := fmt.Sprintf("apic-token-%d", logins.Add(1))
			_, _ = fmt.Fprintf(w, `{"imdata":[{"aaaLogin":{"attributes":{"token":%q}}}]}`, token)
			return
		}
		dataRequests.Add(1)
		cookie, err := r.Cookie("APIC-cookie")
		if !assert.NoError(t, err) {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		if cookie.Value == "apic-token-1" {
			http.Error(w, "issued token rejected", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
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

	_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.ErrorContains(t, err, "HTTP 401")
	_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.ErrorContains(t, err, "HTTP 401")
	assert.Equal(t, int64(1), logins.Load(), "the next endpoint must honor shared auth backoff")
	assert.Equal(t, int64(1), dataRequests.Load())
	client.tokenMu.Lock()
	assert.Equal(t, 1, client.authFailures)
	assert.Empty(t, client.token)
	client.lastAuthAt = time.Now().Add(-authBackoffFor(client.authFailures))
	client.tokenMu.Unlock()

	_, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(2), logins.Load())
	assert.Equal(t, int64(2), dataRequests.Load())
	client.tokenMu.Lock()
	assert.Zero(t, client.authFailures, "only an accepted data request should clear auth backoff")
	assert.NoError(t, client.lastAuthErr)
	assert.True(t, client.lastAuthAt.IsZero())
	client.tokenMu.Unlock()
}

func TestClientConcurrentRequestsShareLogin(t *testing.T) {
	const callers = 12
	loginStarted := make(chan struct{})
	releaseLogin := make(chan struct{})
	var startedOnce sync.Once
	var loginCalls atomic.Int64
	var dataCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			loginCalls.Add(1)
			startedOnce.Do(func() { close(loginStarted) })
			<-releaseLogin
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"shared-token"}}}]}`))
			return
		}
		cookie, err := r.Cookie("APIC-cookie")
		if err != nil || cookie.Value != "shared-token" {
			http.Error(w, "missing shared token", http.StatusUnauthorized)
			return
		}
		dataCalls.Add(1)
		_, _ = w.Write([]byte(`{"totalCount":"0","imdata":[]}`))
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

	errs := make(chan error, callers)
	var workers sync.WaitGroup
	for range callers {
		workers.Go(func() {
			_, requestErr := client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
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

func TestClientStaleUnauthorizedDoesNotClearReplacementToken(t *testing.T) {
	client, err := NewClient(Config{
		Endpoint: "https://apic.example.test",
		Username: "admin",
		Password: "password",
	})
	require.NoError(t, err)

	client.tokenMu.Lock()
	client.token = "new-token"
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

func TestClientFiltersBeforeMaxResultsAcrossPages(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token"}}}]}`))
			return
		}
		assert.Equal(t, "/api/class/fabricNode.json", r.URL.Path)
		assert.Equal(t, "2", r.URL.Query().Get("page-size"), "filtered pagination must keep a stable raw page size")
		requests.Add(1)
		switch r.URL.Query().Get("page") {
		case "0":
			_, _ = w.Write([]byte(`{"totalCount":"5","imdata":[
				{"fabricNode":{"attributes":{"id":"1"}}},
				{"fabricNode":{"attributes":{"id":"2"}}}
			]}`))
		case "1":
			_, _ = w.Write([]byte(`{"totalCount":"5","imdata":[
				{"fabricNode":{"attributes":{"id":"3"}}},
				{"fabricNode":{"attributes":{"id":"4"}}}
			]}`))
		case "2":
			_, _ = w.Write([]byte(`{"totalCount":"5","imdata":[
				{"fabricNode":{"attributes":{"id":"5"}}}
			]}`))
		default:
			assert.Fail(t, "unexpected APIC page", r.URL.RawQuery)
			http.Error(w, "unexpected APIC page", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 0,
		PageSize:   2,
	})
	require.NoError(t, err)

	got, err := client.ListClassFiltered(t.Context(), "fabric.nodes", "fabricNode", nil, 2, func(obj Object) bool {
		return String(obj, "id") == "3" || String(obj, "id") == "5"
	})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "3", String(got[0], "id"))
	assert.Equal(t, "5", String(got[1], "id"))
	assert.Equal(t, int64(3), requests.Load())
}

func TestClientConfiguredPaginationResultLimit(t *testing.T) {
	tests := []struct {
		name      string
		total     string
		filtered  bool
		wantError bool
	}{
		{
			name:  "exact complete at cap",
			total: "2",
		},
		{
			name:      "truncated at cap",
			total:     "3",
			wantError: true,
		},
		{
			name:     "filtered exact complete at cap",
			total:    "3",
			filtered: true,
		},
		{
			name:      "filtered truncated at cap",
			total:     "4",
			filtered:  true,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/aaaLogin.json" {
					_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token"}}}]}`))
					return
				}
				assert.Equal(t, "/api/class/fabricNode.json", r.URL.Path)
				assert.Equal(t, "0", r.URL.Query().Get("page"))
				requests.Add(1)
				if tt.filtered {
					assert.Equal(t, "3", r.URL.Query().Get("page-size"), "filtered pagination must keep the configured raw page size")
					_, _ = fmt.Fprintf(w, `{"totalCount":%q,"imdata":[
						{"fabricNode":{"attributes":{"id":"skip"}}},
						{"fabricNode":{"attributes":{"id":"101"}}},
						{"fabricNode":{"attributes":{"id":"102"}}}
					]}`, tt.total)
					return
				}
				assert.Equal(t, "2", r.URL.Query().Get("page-size"))
				_, _ = fmt.Fprintf(w, `{"totalCount":%q,"imdata":[
					{"fabricNode":{"attributes":{"id":"101"}}},
					{"fabricNode":{"attributes":{"id":"102"}}}
				]}`, tt.total)
			}))
			defer server.Close()

			client, err := NewClient(Config{
				Endpoint:   server.URL,
				Username:   "admin",
				Password:   "password",
				Timeout:    time.Second,
				MaxRetries: 0,
				PageSize:   3,
			})
			require.NoError(t, err)

			var got []Object
			if tt.filtered {
				got, err = client.ListClassFiltered(t.Context(), "fabric.nodes", "fabricNode", nil, 2, func(obj Object) bool {
					return String(obj, "id") != "skip"
				})
			} else {
				got, err = client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 2)
			}
			require.Len(t, got, 2)
			assert.Equal(t, "101", String(got[0], "id"))
			assert.Equal(t, "102", String(got[1], "id"))
			assert.Equal(t, int64(1), requests.Load())
			if !tt.wantError {
				require.NoError(t, err)
				return
			}
			var limitErr *httpclient.PaginationLimitError
			require.ErrorAs(t, err, &limitErr)
			assert.Equal(t, "fabric.nodes", limitErr.Operation)
			assert.Equal(t, "result", limitErr.Kind)
			assert.Equal(t, 2, limitErr.Maximum)
			assert.Equal(t, 2, limitErr.Results)
			assert.False(t, limitErr.Hard)
			require.ErrorContains(t, err, "configured result limit")
		})
	}
}

func TestClientPaginationContinuesAfterShortPageWhenTotalCountHasMore(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token"}}}]}`))
			return
		}
		assert.Equal(t, "/api/class/fabricNode.json", r.URL.Path)
		assert.Equal(t, "2", r.URL.Query().Get("page-size"))
		requests.Add(1)
		switch r.URL.Query().Get("page") {
		case "0":
			_, _ = w.Write([]byte(`{"totalCount":"2","imdata":[{"fabricNode":{"attributes":{"id":"101"}}}]}`))
		case "1":
			_, _ = w.Write([]byte(`{"totalCount":"2","imdata":[{"fabricNode":{"attributes":{"id":"102"}}}]}`))
		default:
			t.Fatalf("unexpected APIC page %q", r.URL.Query().Get("page"))
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 0,
		PageSize:   2,
	})
	require.NoError(t, err)

	got, err := client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "101", String(got[0], "id"))
	assert.Equal(t, "102", String(got[1], "id"))
	assert.Equal(t, int64(2), requests.Load())
}

func TestClientPaginationHardPageLimitReturnsPartialResults(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token"}}}]}`))
			return
		}
		page := r.URL.Query().Get("page")
		requests.Add(1)
		_, _ = fmt.Fprintf(w, `{"totalCount":"%d","imdata":[{"fabricNode":{"attributes":{"id":"%s"}}}]}`, httpclient.HardMaxPaginationPages+1, page)
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 1, PageSize: 1})
	require.NoError(t, err)

	got, err := client.ListClass(t.Context(), "fabric.nodes", "fabricNode", nil, 0)
	var limitErr *httpclient.PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.Equal(t, "page", limitErr.Kind)
	assert.Len(t, got, httpclient.HardMaxPaginationPages)
	assert.Equal(t, int64(httpclient.HardMaxPaginationPages), requests.Load())
}

func TestClientFilteredPaginationStillHonorsHardPageLimit(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token"}}}]}`))
			return
		}
		page := r.URL.Query().Get("page")
		requests.Add(1)
		_, _ = fmt.Fprintf(w, `{"totalCount":"%d","imdata":[{"fabricNode":{"attributes":{"id":%q}}}]}`, httpclient.HardMaxPaginationPages+1, page)
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		Username:   "admin",
		Password:   "password",
		Timeout:    time.Second,
		MaxRetries: 0,
		PageSize:   1,
	})
	require.NoError(t, err)

	got, err := client.ListClassFiltered(t.Context(), "fabric.nodes", "fabricNode", nil, 1, func(Object) bool { return false })
	var limitErr *httpclient.PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.Equal(t, "page", limitErr.Kind)
	assert.Empty(t, got)
	assert.Equal(t, int64(httpclient.HardMaxPaginationPages), requests.Load())
}

func TestClientRejectsFixedPagePaginationCycle(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/aaaLogin.json" {
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"apic-token"}}}]}`))
			return
		}
		requests.Add(1)
		_, _ = w.Write([]byte(`{"totalCount":"2","imdata":[{"fabricNode":{"attributes":{"id":"101"}}}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 1, PageSize: 1})
	require.NoError(t, err)

	got, err := client.ListClass(t.Context(), "fabric.nodes", "fabricNode", url.Values{"page": {"0"}}, 0)
	require.ErrorContains(t, err, "continuation cycle")
	assert.Len(t, got, 1)
	assert.Equal(t, int64(1), requests.Load())
}

func TestClientRejectsInvalidConfig(t *testing.T) {
	_, err := NewClient(Config{})
	require.Error(t, err)

	_, err = NewClient(Config{Endpoint: "://bad", Username: "admin", Password: "password"})
	require.Error(t, err)

	_, err = NewClient(Config{Endpoint: "https://apic.example.com", Username: "admin"})
	require.Error(t, err)
}
