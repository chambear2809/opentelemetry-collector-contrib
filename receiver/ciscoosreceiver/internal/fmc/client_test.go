// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package fmc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

func TestClientRetryValidationPreservesExplicitZero(t *testing.T) {
	client, err := NewClient(Config{Endpoint: "https://fmc.example.test", Username: "admin", Password: "password", MaxRetries: 0})
	require.NoError(t, err)
	assert.Zero(t, client.retries)
	for _, retries := range []int{-1, httpclient.HardMaxRequestRetries + 1} {
		_, err = NewClient(Config{Endpoint: "https://fmc.example.test", Username: "admin", Password: "password", MaxRetries: retries})
		require.ErrorContains(t, err, "invalid fmc max retries")
	}
}

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

func TestClientPaginationHardPageLimitReturnsPartialResults(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/fmc_platform/v1/auth/generatetoken" {
			w.Header().Set("X-auth-access-token", "access-1")
			w.Header().Set("DOMAIN_UUID", "domain-1")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		offset := r.URL.Query().Get("offset")
		requests.Add(1)
		_, _ = w.Write([]byte(`{"items":[{"id":"` + offset + `"}],"paging":{"count":` + strconv.Itoa(httpclient.HardMaxPaginationPages+1) + `}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 1, PageSize: 1})
	require.NoError(t, err)

	got, err := client.List(t.Context(), "events", "/api/fmc_eventing/v1/domain/domain-1/events", nil, 0)
	var limitErr *httpclient.PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.Equal(t, "page", limitErr.Kind)
	assert.Len(t, got, httpclient.HardMaxPaginationPages)
	assert.Equal(t, int64(httpclient.HardMaxPaginationPages), requests.Load())
}

func TestClientRejectsFixedOffsetPaginationCycle(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/fmc_platform/v1/auth/generatetoken" {
			w.Header().Set("X-auth-access-token", "access-1")
			w.Header().Set("DOMAIN_UUID", "domain-1")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		requests.Add(1)
		_, _ = w.Write([]byte(`{"items":[{"id":"event-1"}],"paging":{"count":2}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 1, PageSize: 1})
	require.NoError(t, err)

	got, err := client.List(t.Context(), "events", "/api/fmc_eventing/v1/domain/domain-1/events", url.Values{"offset": {"0"}}, 0)
	require.ErrorContains(t, err, "continuation cycle")
	assert.Len(t, got, 1)
	assert.Equal(t, int64(1), requests.Load())
}

func TestClientPaginationAdvancesByOverReturnedObjectCount(t *testing.T) {
	var offsets []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/fmc_platform/v1/auth/generatetoken" {
			w.Header().Set("X-auth-access-token", "access-1")
			w.Header().Set("DOMAIN_UUID", "domain-1")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		offset := r.URL.Query().Get("offset")
		offsets = append(offsets, offset)
		switch offset {
		case "0":
			_, _ = w.Write([]byte(`{"items":[{"id":"event-0"},{"id":"event-1"}],"paging":{"count":3}}`))
		case "2":
			_, _ = w.Write([]byte(`{"items":[{"id":"event-2"}],"paging":{"count":3}}`))
		default:
			t.Fatalf("unexpected overlapping offset %q", offset)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{Endpoint: server.URL, Username: "admin", Password: "password", Timeout: time.Second, MaxRetries: 1, PageSize: 1})
	require.NoError(t, err)

	got, err := client.List(t.Context(), "events", "/api/fmc_eventing/v1/domain/domain-1/events", nil, 0)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, []string{"0", "2"}, offsets)
	assert.Equal(t, "event-2", got[2]["id"])
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

func TestFMCGenericDecodersPreserveLargeIntegers(t *testing.T) {
	objects, _, _, err := decodeObjects([]byte(`{"items":[{"counter":9007199254740993}]}`))
	require.NoError(t, err)
	require.Len(t, objects, 1)
	number, ok := objects[0]["counter"].(json.Number)
	require.True(t, ok)
	assert.Equal(t, "9007199254740993", number.String())

	eventPayload := make([]byte, 8)
	eventPayload = append(eventPayload, []byte(`{"EventType":"ConnectionEvent","counter":9007199254740993}`)...)
	event, err := decodeEStreamerEvent("fmc-1", eventPayload)
	require.NoError(t, err)
	number, ok = event.Body["counter"].(json.Number)
	require.True(t, ok)
	assert.Equal(t, "9007199254740993", number.String())
}

func TestDecodeEStreamerBundleRejectsMoreThanHardRecordLimit(t *testing.T) {
	eventHeader := encodeEStreamerMessage(estreamerMessageEventV3, nil)
	bundle := make([]byte, 8, 8+len(eventHeader)*(estreamerMaxBundleRecords+1))
	bundle = append(bundle, bytes.Repeat(eventHeader, estreamerMaxBundleRecords+1)...)

	events, err := decodeEStreamerBundle("fmc-1", bundle)
	require.ErrorContains(t, err, "hard record/event limit")
	assert.Len(t, events, estreamerMaxBundleRecords)
}

func TestDecodeEStreamerBundleNullRecordsCannotBypassHardLimit(t *testing.T) {
	nullHeader := encodeEStreamerMessage(estreamerMessageNull, nil)
	bundle := make([]byte, 8, 8+len(nullHeader)*(estreamerMaxBundleRecords+1))
	bundle = append(bundle, bytes.Repeat(nullHeader, estreamerMaxBundleRecords+1)...)

	events, err := decodeEStreamerBundle("fmc-1", bundle)
	require.ErrorContains(t, err, "hard record/event limit")
	assert.Empty(t, events)
}

func TestDecodeEStreamerErrorDoesNotExposeServerPayload(t *testing.T) {
	payload := make([]byte, 6)
	binary.BigEndian.PutUint32(payload[:4], 17)
	binary.BigEndian.PutUint16(payload[4:6], uint16(len("server-secret")))
	payload = append(payload, "server-secret"...)

	err := decodeEStreamerError(payload)
	require.Error(t, err)
	assert.ErrorContains(t, err, "code=17")
	assert.ErrorContains(t, err, fmt.Sprintf("payload_length=%d", len(payload)))
	assert.ErrorContains(t, err, "payload_sha256=")
	assert.NotContains(t, err.Error(), "server-secret")

	shortErr := decodeEStreamerError([]byte("raw-secret"[:3]))
	require.Error(t, shortErr)
	assert.ErrorContains(t, shortErr, "code=unavailable")
	assert.NotContains(t, shortErr.Error(), "raw")
}

func TestNewEStreamerClientEnforcesHardMessageLimit(t *testing.T) {
	client, err := NewEStreamerClient(EStreamerConfig{Address: "fmc.example.test:8302"})
	require.NoError(t, err)
	assert.Equal(t, estreamerMaxMessageBytes, client.maxMessageBytes)

	client, err = NewEStreamerClient(EStreamerConfig{Address: "fmc.example.test:8302", MaxMessageBytes: estreamerMaxMessageBytes})
	require.NoError(t, err)
	assert.Equal(t, estreamerMaxMessageBytes, client.maxMessageBytes)

	for _, maxBytes := range []int{-1, estreamerMaxMessageBytes + 1} {
		_, err = NewEStreamerClient(EStreamerConfig{Address: "fmc.example.test:8302", MaxMessageBytes: maxBytes})
		require.ErrorContains(t, err, "max message bytes")
	}
}

func TestDecodeEStreamerEventDoesNotForwardMalformedRawPayload(t *testing.T) {
	event, err := decodeEStreamerEvent("fmc-1", []byte(`{"password":"do-not-export"`))
	require.NoError(t, err)
	assert.Equal(t, "decode_error", event.EventType)
	assert.Empty(t, event.Raw)
	assert.Equal(t, true, event.Body["decode_error"])
	assert.Len(t, String(event.Body, "payload_sha256"), 64)
	assert.NotContains(t, fmt.Sprint(event.Body), "do-not-export")
}

func TestDecodeEStreamerEventDoesNotRetainSuccessfulFramingText(t *testing.T) {
	event, err := decodeEStreamerEvent("fmc-1", []byte(`12345678password=prefix-secret {"EventType":"ConnectionEvent","id":"event-1"} password=suffix-secret`))
	require.NoError(t, err)
	assert.Equal(t, "connection_event", event.EventType)
	assert.Empty(t, event.Raw)
	assert.Equal(t, "event-1", String(event.Body, "id"))
	assert.NotContains(t, fmt.Sprint(event.Body), "prefix-secret")
	assert.NotContains(t, fmt.Sprint(event.Body), "suffix-secret")
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
