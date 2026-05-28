// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package aci

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		require.NoError(t, err)
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

func TestClientRejectsInvalidConfig(t *testing.T) {
	_, err := NewClient(Config{})
	require.Error(t, err)

	_, err = NewClient(Config{Endpoint: "://bad", Username: "admin", Password: "password"})
	require.Error(t, err)

	_, err = NewClient(Config{Endpoint: "https://apic.example.com", Username: "admin"})
	require.Error(t, err)
}
