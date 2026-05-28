// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sdwan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientBearerList(t *testing.T) {
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		assert.Equal(t, "/dataservice/device", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"host-name": "edge-1"}},
		})
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:    server.URL,
		AuthMode:    "bearer",
		BearerToken: "token",
		Timeout:     time.Second,
	})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.List(context.Background(), "devices", "/device", nil, 0)
	require.NoError(t, err)
	require.Len(t, objects, 1)
	assert.Equal(t, "edge-1", String(objects[0], "host-name"))
	assert.Equal(t, "Bearer token", authHeader)
}

func TestClientSupportsSelfSignedTLSWithInsecureSkipVerify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/dataservice/device", r.URL.Path)
		assert.Equal(t, "Bearer token", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"host-name": "edge-1"}},
		})
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:           server.URL,
		AuthMode:           "bearer",
		BearerToken:        "token",
		Timeout:            time.Second,
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.List(context.Background(), "devices", "/device", nil, 0)
	require.NoError(t, err)
	require.Len(t, objects, 1)
	assert.Equal(t, "edge-1", String(objects[0], "host-name"))
}

func TestClientAutoJWTLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwt/login":
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "jwt-token", "xsrfToken": "csrf"})
		case "/dataservice/device":
			assert.Equal(t, "Bearer jwt-token", r.Header.Get("Authorization"))
			_ = json.NewEncoder(w).Encode([]map[string]any{{"system-ip": "10.0.0.1"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint: server.URL,
		AuthMode: "auto",
		Username: "admin",
		Password: "password",
		Timeout:  time.Second,
	})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.List(context.Background(), "devices", "/device", nil, 0)
	require.NoError(t, err)
	require.Len(t, objects, 1)
	assert.Equal(t, "10.0.0.1", String(objects[0], "system-ip"))
}

func TestClientAutoFallsBackToSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwt/login":
			http.Error(w, "not supported", http.StatusNotFound)
		case "/j_security_check":
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "session-id"})
			w.WriteHeader(http.StatusOK)
		case "/dataservice/client/token":
			assert.Equal(t, "JSESSIONID=session-id", r.Header.Get("Cookie"))
			_, _ = w.Write([]byte("xsrf-token"))
		case "/dataservice/events":
			assert.Equal(t, "JSESSIONID=session-id", r.Header.Get("Cookie"))
			assert.Equal(t, "xsrf-token", r.Header.Get("X-XSRF-TOKEN"))
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"eventId": "event-1"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint: server.URL,
		AuthMode: "auto",
		Username: "admin",
		Password: "password",
		Timeout:  time.Second,
	})
	require.NoError(t, err)
	client.spacing = 0

	objects, err := client.PostQuery(context.Background(), "events", "/events", map[string]any{"size": 1}, 0)
	require.NoError(t, err)
	require.Len(t, objects, 1)
	assert.Equal(t, "event-1", String(objects[0], "eventId"))
}
