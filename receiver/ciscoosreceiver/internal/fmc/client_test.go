// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package fmc

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientTokenAndPagination(t *testing.T) {
	var sawToken bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/fmc_platform/v1/auth/generatetoken":
			assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:password")), r.Header.Get("Authorization"))
			w.Header().Set("X-auth-access-token", "access-1")
			w.Header().Set("X-auth-refresh-token", "refresh-1")
			w.Header().Set("DOMAIN_UUID", "domain-1")
			w.WriteHeader(http.StatusNoContent)
		case "/api/fmc_config/v1/domain/domain-1/devices/devicerecords":
			assert.Equal(t, "access-1", r.Header.Get("X-auth-access-token"))
			sawToken = true
			switch r.URL.Query().Get("offset") {
			case "0":
				_, _ = w.Write([]byte(`{"items":[{"id":"dev-1","name":"ftd-1"},{"id":"dev-2","name":"asa-1"}],"paging":{"count":3}}`))
			case "2":
				_, _ = w.Write([]byte(`{"items":[{"id":"dev-3","name":"ftd-2"}],"paging":{"count":3}}`))
			default:
				t.Fatalf("unexpected offset %q", r.URL.Query().Get("offset"))
			}
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:   server.URL,
		Username:   "admin",
		Password:   "password",
		PageSize:   2,
		MaxRetries: 1,
	})
	require.NoError(t, err)

	domain, err := client.DomainUUID(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "domain-1", domain)

	objects, err := client.List(context.Background(), "devices.records", "/api/fmc_config/v1/domain/domain-1/devices/devicerecords", nil, 0)
	require.NoError(t, err)
	require.Len(t, objects, 3)
	assert.Equal(t, "ftd-1", String(objects[0], "name"))
	assert.True(t, sawToken)
}

func TestClientSupportsSelfSignedTLSWithInsecureSkipVerify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/fmc_platform/v1/auth/generatetoken", r.URL.Path)
		w.Header().Set("X-auth-access-token", "access-1")
		w.Header().Set("X-auth-refresh-token", "refresh-1")
		w.Header().Set("DOMAIN_UUID", "domain-1")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:           server.URL,
		Username:           "admin",
		Password:           "password",
		MaxRetries:         1,
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)

	domain, err := client.DomainUUID(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "domain-1", domain)
}

func TestDecodeEStreamerBundle(t *testing.T) {
	eventPayload := make([]byte, 8)
	eventPayload = append(eventPayload, []byte(`{"EventType":"ConnectionEvent","InitiatorIP":"10.0.0.1","ResponderIP":"10.0.0.2"}`)...)
	eventMessage := encodeEStreamerMessage(estreamerMessageEventV3, eventPayload)
	bundle := make([]byte, 8)
	bundle = append(bundle, eventMessage...)

	events, err := decodeEStreamerBundle("fmc-1", bundle)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "fmc-1", events[0].Controller)
	assert.Equal(t, "connection_event", events[0].EventType)
	assert.Equal(t, "10.0.0.1", String(events[0].Body, "InitiatorIP"))
}

func TestNormalizeFQEEventTypesSupportsOperationalAliases(t *testing.T) {
	assert.Equal(t,
		[]string{"connection", "file", "intrusion_packet"},
		normalizeFQEEventTypes([]string{"security_intelligence", "malware", "IntrusionPacket"}),
	)
}
