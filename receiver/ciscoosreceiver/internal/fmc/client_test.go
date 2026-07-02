// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package fmc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestEStreamerRunCancellationInterruptsIdleRead(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	client, err := NewEStreamerClient(EStreamerConfig{
		Address:     "fmc.example.test:8302",
		ReadTimeout: time.Hour,
	})
	require.NoError(t, err)
	client.dialContext = func(context.Context, string, string) (net.Conn, error) {
		return clientConn, nil
	}

	requestReceived := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		headerBytes := make([]byte, estreamerMessageHeaderLen)
		if _, readErr := io.ReadFull(serverConn, headerBytes); readErr != nil {
			serverDone <- readErr
			return
		}
		header := decodeHeader(headerBytes)
		if _, readErr := io.CopyN(io.Discard, serverConn, int64(header.length)); readErr != nil {
			serverDone <- readErr
			return
		}
		close(requestReceived)
		var payload [1]byte
		_, readErr := serverConn.Read(payload[:])
		serverDone <- readErr
	}()

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() {
		runDone <- client.Run(ctx, func(EStreamerEvent) error { return nil })
	}()

	select {
	case <-requestReceived:
	case <-time.After(time.Second):
		t.Fatal("eStreamer request was not received")
	}
	cancel()
	select {
	case runErr := <-runDone:
		require.ErrorIs(t, runErr, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("eStreamer Run did not unblock promptly after cancellation")
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server side did not observe the cancelled connection")
	}
}

func TestEStreamerWriteRequestHandlesShortWritesAndUsesResumeCursor(t *testing.T) {
	client, err := NewEStreamerClient(EStreamerConfig{Address: "fmc.example.test:8302"})
	require.NoError(t, err)
	writer := &chunkWriter{max: 3}
	resume := time.Unix(1_800_000_123, 0).UTC()

	require.NoError(t, client.writeRequest(writer, resume))
	written := writer.Bytes()
	require.GreaterOrEqual(t, len(written), estreamerMessageHeaderLen+8)
	header := decodeHeader(written[:estreamerMessageHeaderLen])
	assert.Equal(t, estreamerMessageRequest, header.messageType)
	assert.Equal(t, uint32(len(written)-estreamerMessageHeaderLen), header.length)
	payload := written[estreamerMessageHeaderLen:]
	assert.Equal(t, uint32(resume.Unix()), binary.BigEndian.Uint32(payload[:4]))
	assert.Equal(t, estreamerRequestBitExtendedHeader, binary.BigEndian.Uint32(payload[4:8]))
}

type chunkWriter struct {
	bytes.Buffer
	max int
}

func (w *chunkWriter) Write(payload []byte) (int, error) {
	if len(payload) > w.max {
		payload = payload[:w.max]
	}
	return w.Buffer.Write(payload)
}
