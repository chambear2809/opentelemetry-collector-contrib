// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPxGridControlUsesDocumentedPostCalls(t *testing.T) {
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/pxgrid/control/AccountActivate":
			assert.Equal(t, http.MethodPost, r.Method)
			_, _ = w.Write([]byte(`{"accountState":"ENABLED","version":"2.0"}`))
		case "/pxgrid/control/AccessSecret":
			assert.Equal(t, http.MethodPost, r.Method)
			_, _ = w.Write([]byte(`{"secret":"shared-secret"}`))
		case "/pxgrid/control/version":
			assert.Equal(t, http.MethodGet, r.Method)
			_, _ = w.Write([]byte(`{"version":"2.0"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewPxGridClient(PxGridConfig{Endpoint: server.URL + "/pxgrid", NodeName: "collector", Password: "account-password"})
	require.NoError(t, err)
	activate, err := client.AccountActivate(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "ENABLED", String(activate, "accountState"))
	secret, err := client.AccessSecret(t.Context(), "ise-psn-1")
	require.NoError(t, err)
	assert.Equal(t, "shared-secret", String(secret, "secret"))
	version, err := client.Version(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "2.0", String(version, "version"))
	assert.Equal(t, []string{
		"POST /pxgrid/control/AccountActivate",
		"POST /pxgrid/control/AccessSecret",
		"GET /pxgrid/control/version",
	}, methods)
}

func TestPxGridSupportsSelfSignedTLSWithInsecureSkipVerify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/pxgrid/control/version", r.URL.Path)
		_, _ = w.Write([]byte(`{"version":"2.0"}`))
	}))
	defer server.Close()

	client, err := NewPxGridClient(PxGridConfig{
		Endpoint:           server.URL + "/pxgrid",
		NodeName:           "collector",
		Password:           "account-password",
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)

	version, err := client.Version(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "2.0", String(version, "version"))
}
