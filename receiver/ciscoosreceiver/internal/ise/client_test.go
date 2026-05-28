// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
