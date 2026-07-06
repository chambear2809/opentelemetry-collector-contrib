// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6455 mandates SHA-1 for Sec-WebSocket-Accept.
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/youmark/pkcs8"
	"go.uber.org/goleak"
	"golang.org/x/net/websocket"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

func TestPxGridRESTDiscoversServiceEndpointAndPeerSecret(t *testing.T) {
	const (
		collectorNode  = "collector"
		accountSecret  = "account-password"
		serviceNode    = "ise-mnt-2"
		serviceSecret  = "service-access-secret"
		sessionService = "com.cisco.ise.session"
	)

	serviceServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/pxgrid/mnt/sd/getSessions", r.URL.Path)
		username, password, ok := r.BasicAuth()
		if !assert.True(t, ok) {
			http.Error(w, "missing basic authentication", http.StatusUnauthorized)
			return
		}
		assert.Equal(t, collectorNode, username)
		assert.Equal(t, serviceSecret, password)
		assert.NotEqual(t, accountSecret, password)
		_, _ = w.Write([]byte(`{"sessions":[{"id":"session-1"}]}`))
	}))
	defer serviceServer.Close()

	var (
		mu              sync.Mutex
		lookedUpService string
		secretPeer      string
	)
	controlServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !assert.True(t, ok) {
			http.Error(w, "missing basic authentication", http.StatusUnauthorized)
			return
		}
		assert.Equal(t, collectorNode, username)
		assert.Equal(t, accountSecret, password)
		switch r.URL.Path {
		case "/pxgrid/control/ServiceLookup":
			var request struct {
				Name string `json:"name"`
			}
			if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&request)) {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			mu.Lock()
			lookedUpService = request.Name
			mu.Unlock()
			_, _ = w.Write([]byte(`{"services":[{"name":"com.cisco.ise.session","nodeName":"ise-mnt-2","properties":{"restBaseUrl":"` + serviceServer.URL + `/pxgrid/mnt/sd"}}]}`))
		case "/pxgrid/control/AccessSecret":
			var request struct {
				PeerNodeName string `json:"peerNodeName"`
			}
			if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&request)) {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			mu.Lock()
			secretPeer = request.PeerNodeName
			mu.Unlock()
			_, _ = w.Write([]byte(`{"secret":"service-access-secret"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer controlServer.Close()

	client, err := NewPxGridClient(PxGridConfig{
		Endpoint:              controlServer.URL + "/pxgrid",
		NodeName:              collectorNode,
		Password:              accountSecret,
		InsecureSkipVerify:    true,
		AllowedServiceOrigins: []string{serviceServer.URL},
	})
	require.NoError(t, err)
	objects, err := client.PostObjects(t.Context(), "pxgrid.session.get_sessions", sessionService, "/getSessions", map[string]any{}, 10)
	require.NoError(t, err)
	require.Len(t, objects, 1)
	assert.Equal(t, "session-1", String(objects[0], "id"))

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, sessionService, lookedUpService)
	assert.Equal(t, serviceNode, secretPeer)
}

func TestPxGridSubscribeDiscoversPubSubURLTopicAndPeerSecret(t *testing.T) {
	const (
		collectorNode   = "collector"
		accountSecret   = "account-password"
		pubSubService   = "com.cisco.ise.pubsub.discovered"
		pubSubNode      = "ise-pubsub-2"
		pubSubSecret    = "pubsub-access-secret" //nolint:gosec // Test-only fixture credential.
		discoveredTopic = "/topic/discovered/session"
	)

	connectFrames := make(chan stompFrame, 1)
	subscribeFrames := make(chan stompFrame, 1)
	ackFrames := make(chan stompFrame, 1)
	authenticated := make(chan struct{}, 1)
	wsHandler := websocket.Handler(func(ws *websocket.Conn) {
		connect, err := readSTOMP(ws)
		if err != nil {
			return
		}
		connectFrames <- connect
		if writeErr := writeSTOMP(ws, "CONNECTED", map[string]string{"version": "1.2"}, nil); writeErr != nil {
			return
		}
		subscribe, err := readSTOMP(ws)
		if err != nil {
			return
		}
		subscribeFrames <- subscribe
		_ = writeSTOMP(ws, "MESSAGE", map[string]string{
			"destination": discoveredTopic,
			"message-id":  "message-1",
			"ack":         "ack-1",
		}, []byte(`{"id":"session-1"}`))
		ack, err := readSTOMP(ws)
		if err == nil {
			ackFrames <- ack
		}
	})
	pubSubServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/discovered/ws", r.URL.Path)
		username, password, ok := r.BasicAuth()
		if !assert.True(t, ok) {
			http.Error(w, "missing basic authentication", http.StatusUnauthorized)
			return
		}
		assert.Equal(t, collectorNode, username)
		assert.Equal(t, pubSubSecret, password)
		assert.NotEqual(t, accountSecret, password)
		authenticated <- struct{}{}
		wsHandler.ServeHTTP(w, r)
	}))
	defer pubSubServer.Close()

	var (
		mu          sync.Mutex
		lookups     []string
		secretPeers []string
	)
	controlServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !assert.True(t, ok) {
			http.Error(w, "missing basic authentication", http.StatusUnauthorized)
			return
		}
		assert.Equal(t, collectorNode, username)
		assert.Equal(t, accountSecret, password)
		switch r.URL.Path {
		case "/pxgrid/control/ServiceLookup":
			var request struct {
				Name string `json:"name"`
			}
			if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&request)) {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			mu.Lock()
			lookups = append(lookups, request.Name)
			mu.Unlock()
			switch request.Name {
			case "com.cisco.ise.session":
				_, _ = w.Write([]byte(`{"services":[{"name":"com.cisco.ise.session","nodeName":"ise-mnt-1","properties":{"wsPubsubService":"` + pubSubService + `","sessionTopic":"` + discoveredTopic + `"}}]}`))
			case pubSubService:
				_, _ = w.Write([]byte(`{"services":[{"name":"` + pubSubService + `","nodeName":"` + pubSubNode + `","properties":{"wsUrl":"` + "wss" + pubSubServer.URL[len("https"):] + `/discovered/ws"}}]}`))
			default:
				_, _ = w.Write([]byte(`{"services":[]}`))
			}
		case "/pxgrid/control/AccessSecret":
			var request struct {
				PeerNodeName string `json:"peerNodeName"`
			}
			if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&request)) {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			mu.Lock()
			secretPeers = append(secretPeers, request.PeerNodeName)
			mu.Unlock()
			_, _ = w.Write([]byte(`{"secret":"` + pubSubSecret + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer controlServer.Close()

	client, err := NewPxGridClient(PxGridConfig{
		Endpoint:              controlServer.URL + "/pxgrid",
		NodeName:              collectorNode,
		Password:              accountSecret,
		InsecureSkipVerify:    true,
		AllowedServiceOrigins: []string{"wss" + pubSubServer.URL[len("https"):]},
	})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	messages := make(chan StompMessage, 1)
	ready := make(chan struct{}, 1)
	acknowledged := make(chan struct{}, 1)
	err = client.SubscribeWithLifecycle(
		ctx,
		PxGridSubscription{Service: "com.cisco.ise.session", TopicProperty: "sessionTopic"},
		PxGridSubscriptionLifecycle{
			Ready:        func() { ready <- struct{}{} },
			Acknowledged: func() { acknowledged <- struct{}{} },
		},
		func(message StompMessage) error {
			messages <- message
			return nil
		},
	)
	require.Error(t, err)

	select {
	case <-authenticated:
	default:
		t.Fatal("discovered WebSocket endpoint was not authenticated")
	}
	connect := <-connectFrames
	assert.Equal(t, "CONNECT", connect.command)
	assert.Equal(t, pubSubNode, connect.headers["host"])
	assert.NotContains(t, connect.headers, "login")
	assert.NotContains(t, connect.headers, "passcode")
	for _, value := range connect.headers {
		assert.NotContains(t, value, accountSecret)
	}
	subscribe := <-subscribeFrames
	assert.Equal(t, "SUBSCRIBE", subscribe.command)
	assert.Equal(t, discoveredTopic, subscribe.headers["destination"])
	message := <-messages
	assert.Equal(t, discoveredTopic, message.Topic)
	assert.Equal(t, "message-1", message.MessageID)
	select {
	case ack := <-ackFrames:
		assert.Equal(t, "ACK", ack.command)
		assert.Equal(t, "ack-1", ack.headers["id"])
	case <-time.After(2 * time.Second):
		t.Fatal("pxGrid message was not acknowledged after handler success")
	}
	select {
	case <-acknowledged:
	case <-time.After(2 * time.Second):
		t.Fatal("pxGrid subscription did not report the completed ACK write")
	}
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("pxGrid subscription did not report readiness after STOMP CONNECTED and SUBSCRIBE")
	}

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"com.cisco.ise.session", pubSubService}, lookups)
	assert.Equal(t, []string{pubSubNode}, secretPeers)
}

func TestPxGridSubscribeWithReadyDoesNotFailOverAfterReadyDisconnect(t *testing.T) {
	const pubSubService = "com.cisco.ise.pubsub"
	firstHandler := websocket.Handler(func(ws *websocket.Conn) {
		if _, err := readSTOMP(ws); err != nil {
			return
		}
		if err := writeSTOMP(ws, "CONNECTED", map[string]string{"version": "1.2"}, nil); err != nil {
			return
		}
		// Close the first ready connection immediately after SUBSCRIBE.
		_, _ = readSTOMP(ws)
	})
	firstServer := httptest.NewTLSServer(http.HandlerFunc(firstHandler.ServeHTTP))
	defer firstServer.Close()

	secondAttempted := make(chan struct{}, 1)
	secondHandler := websocket.Handler(func(*websocket.Conn) {
		secondAttempted <- struct{}{}
	})
	secondServer := httptest.NewTLSServer(http.HandlerFunc(secondHandler.ServeHTTP))
	defer secondServer.Close()

	var (
		mu          sync.Mutex
		secretPeers []string
	)
	controlServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pxgrid/control/ServiceLookup":
			var request struct {
				Name string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			switch request.Name {
			case "com.cisco.ise.session":
				_, _ = w.Write([]byte(`{"services":[{"name":"com.cisco.ise.session","nodeName":"ise-mnt","properties":{"wsPubsubService":"` + pubSubService + `","sessionTopic":"/topic/session"}}]}`))
			case pubSubService:
				_, _ = w.Write([]byte(`{"services":[` +
					`{"name":"` + pubSubService + `","nodeName":"ise-pubsub-1","properties":{"wsUrl":"wss` + firstServer.URL[len("https"):] + `"}},` +
					`{"name":"` + pubSubService + `","nodeName":"ise-pubsub-2","properties":{"wsUrl":"wss` + secondServer.URL[len("https"):] + `"}}]}`))
			default:
				_, _ = w.Write([]byte(`{"services":[]}`))
			}
		case "/pxgrid/control/AccessSecret":
			var request struct {
				PeerNodeName string `json:"peerNodeName"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			mu.Lock()
			secretPeers = append(secretPeers, request.PeerNodeName)
			mu.Unlock()
			_, _ = w.Write([]byte(`{"secret":"peer-secret"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer controlServer.Close()

	client, err := NewPxGridClient(PxGridConfig{
		Endpoint:           controlServer.URL + "/pxgrid",
		NodeName:           "collector",
		Password:           "account-password",
		InsecureSkipVerify: true,
		AllowedServiceOrigins: []string{
			"wss" + firstServer.URL[len("https"):],
			"wss" + secondServer.URL[len("https"):],
		},
	})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ready := make(chan struct{}, 1)
	err = client.SubscribeWithReady(
		ctx,
		PxGridSubscription{Service: "com.cisco.ise.session", TopicProperty: "sessionTopic"},
		func() { ready <- struct{}{} },
		func(StompMessage) error { return nil },
	)
	require.ErrorContains(t, err, "subscription ended after readiness")
	select {
	case <-ready:
	default:
		t.Fatal("first endpoint did not report readiness")
	}
	select {
	case <-secondAttempted:
		t.Fatal("readiness subscription silently failed over to a second endpoint")
	default:
	}
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"ise-pubsub-1"}, secretPeers)
}

func TestPxGridSubscribeSendsBinarySTOMPFrames(t *testing.T) {
	serverFrames := make(chan []stompFrame, 1)
	serverErr := make(chan error, 1)
	wsHandler := websocket.Handler(func(ws *websocket.Conn) {
		// Server responses are binary as well, matching ISE pxGrid behavior.
		ws.PayloadType = websocket.BinaryFrame
		connect, err := readBinarySTOMP(ws)
		if err != nil {
			serverErr <- err
			return
		}
		if writeErr := writeSTOMP(ws, "CONNECTED", map[string]string{"version": "1.2"}, nil); writeErr != nil {
			serverErr <- writeErr
			return
		}
		subscribe, err := readBinarySTOMP(ws)
		if err != nil {
			serverErr <- err
			return
		}
		if writeErr := writeSTOMP(ws, "MESSAGE", map[string]string{
			"destination": "/topic/session",
			"message-id":  "message-1",
			"ack":         "ack-1",
		}, []byte(`{"id":"session-1"}`)); writeErr != nil {
			serverErr <- writeErr
			return
		}
		ack, err := readBinarySTOMP(ws)
		if err != nil {
			serverErr <- err
			return
		}
		serverFrames <- []stompFrame{connect, subscribe, ack}
		serverErr <- nil
	})
	server := httptest.NewTLSServer(http.HandlerFunc(wsHandler.ServeHTTP))
	defer server.Close()

	client, err := NewPxGridClient(PxGridConfig{
		Endpoint:           server.URL + "/pxgrid",
		NodeName:           "collector",
		Password:           "account-password",
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	messages := make(chan StompMessage, 1)
	err = client.subscribeEndpointWithReady(ctx, "wss"+server.URL[len("https"):], "ise-pubsub", "peer-secret", "/topic/session", nil, nil, func(message StompMessage) error {
		messages <- message
		return nil
	})
	require.Error(t, err, "the test server closes after observing the ACK")
	require.NoError(t, <-serverErr, "CONNECT, SUBSCRIBE, and ACK must all use binary WebSocket frames")

	frames := <-serverFrames
	require.Len(t, frames, 3)
	assert.Equal(t, "CONNECT", frames[0].command)
	assert.Equal(t, "SUBSCRIBE", frames[1].command)
	assert.Equal(t, "ACK", frames[2].command)
	assert.Equal(t, "ack-1", frames[2].headers["id"])
	message := <-messages
	assert.Equal(t, "message-1", message.MessageID)
}

func readBinarySTOMP(ws *websocket.Conn) (stompFrame, error) {
	var payload []byte
	binaryOnly := websocket.Codec{Unmarshal: func(data []byte, payloadType byte, value any) error {
		if payloadType != websocket.BinaryFrame {
			return errors.New("pxGrid client sent a non-binary WebSocket frame")
		}
		target, ok := value.(*[]byte)
		if !ok {
			return errors.New("binary STOMP test codec received an unsupported target")
		}
		*target = append((*target)[:0], data...)
		return nil
	}}
	if err := binaryOnly.Receive(ws, &payload); err != nil {
		return stompFrame{}, err
	}
	return parseSTOMPFrame(payload)
}

func TestPxGridWebSocketPingUsesControlFrameAndRestoresBinaryPayload(t *testing.T) {
	type serverResult struct {
		opcode byte
		err    error
	}
	result := make(chan serverResult, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := upgradeTestWebSocket(w, r)
		if err != nil {
			result <- serverResult{err: err}
			return
		}
		defer conn.Close()
		opcode, payload, err := readMaskedWebSocketFrame(rw.Reader)
		if err == nil && len(payload) != 0 {
			err = errors.New("expected an empty WebSocket control frame")
		}
		result <- serverResult{opcode: opcode, err: err}
	}))
	defer server.Close()

	config, err := websocket.NewConfig("ws"+server.URL[len("http"):], pxGridDefaultWSOrigin)
	require.NoError(t, err)
	ws, err := config.DialContext(t.Context())
	require.NoError(t, err)
	defer ws.Close()
	ws.PayloadType = websocket.BinaryFrame
	require.NoError(t, writeWebSocketPingContext(t.Context(), ws, time.Second))
	assert.Equal(t, byte(websocket.BinaryFrame), ws.PayloadType, "Ping must restore binary STOMP framing")
	observed := <-result
	require.NoError(t, observed.err)
	assert.Equal(t, byte(websocket.PingFrame), observed.opcode)
	assert.Equal(t, 54*time.Second, pxGridWebSocketPingInterval)
}

func upgradeTestWebSocket(w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("test server does not support hijacking")
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	digest := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) // #nosec G401 -- RFC 6455 mandates SHA-1 here.
	accept := base64.StdEncoding.EncodeToString(digest[:])
	_, err = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n")
	if err == nil {
		err = rw.Flush()
	}
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, rw, nil
}

func readMaskedWebSocketFrame(reader *bufio.Reader) (byte, []byte, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	second, err := reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	if second&0x80 == 0 {
		return 0, nil, errors.New("client WebSocket frame was not masked")
	}
	length := int(second & 0x7f)
	if length > 125 {
		return 0, nil, errors.New("test WebSocket frame exceeds the short-frame limit")
	}
	mask := make([]byte, 4)
	if _, err := io.ReadFull(reader, mask); err != nil {
		return 0, nil, err
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%len(mask)]
	}
	return first & 0x0f, payload, nil
}

func writeUnmaskedWebSocketFrame(rw *bufio.ReadWriter, opcode byte, payload []byte) error {
	if len(payload) > 125 {
		return errors.New("test WebSocket frame exceeds the short-frame limit")
	}
	if err := rw.WriteByte(0x80 | opcode); err != nil {
		return err
	}
	if err := rw.WriteByte(byte(len(payload))); err != nil {
		return err
	}
	if _, err := rw.Write(payload); err != nil {
		return err
	}
	return rw.Flush()
}

func TestWebSocketWriteDeadlineClearedForAutomaticPong(t *testing.T) {
	for _, test := range []struct {
		name        string
		cancelWrite bool
	}{
		{name: "after bounded write"},
		{name: "after cancellation race", cancelWrite: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			type serverResult struct {
				opcode  byte
				payload []byte
				err     error
			}
			const writeTimeout = 25 * time.Millisecond
			pingPayload := []byte("ise-ping")
			sendPing := make(chan struct{})
			var sendPingOnce sync.Once
			releaseServer := func() { sendPingOnce.Do(func() { close(sendPing) }) }
			result := make(chan serverResult, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, rw, err := upgradeTestWebSocket(w, r)
				if err != nil {
					result <- serverResult{err: err}
					return
				}
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				opcode, _, err := readMaskedWebSocketFrame(rw.Reader)
				if err != nil {
					result <- serverResult{err: err}
					return
				}
				if opcode != websocket.BinaryFrame {
					result <- serverResult{err: errors.New("initial client frame was not binary")}
					return
				}
				<-sendPing
				err = writeUnmaskedWebSocketFrame(rw, websocket.PingFrame, pingPayload)
				if err != nil {
					result <- serverResult{err: err}
					return
				}
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				opcode, payload, err := readMaskedWebSocketFrame(rw.Reader)
				if err == nil {
					err = writeUnmaskedWebSocketFrame(rw, websocket.BinaryFrame, []byte("released"))
				}
				result <- serverResult{opcode: opcode, payload: payload, err: err}
			}))
			defer server.Close()
			defer releaseServer()

			config, err := websocket.NewConfig("ws"+server.URL[len("http"):], pxGridDefaultWSOrigin)
			require.NoError(t, err)
			ws, err := config.DialContext(t.Context())
			require.NoError(t, err)
			defer ws.Close()
			ws.PayloadType = websocket.BinaryFrame
			received := make(chan error, 1)
			go func() {
				var payload []byte
				err := websocket.Message.Receive(ws, &payload)
				if err == nil && string(payload) != "released" {
					err = errors.New("client received an unexpected release payload")
				}
				received <- err
			}()

			if !test.cancelWrite {
				require.NoError(t, withWebSocketWriteContext(t.Context(), ws, writeTimeout, func() error {
					_, err := ws.Write([]byte("application"))
					return err
				}))
				time.Sleep(3 * writeTimeout)
			} else {
				ctx, cancel := context.WithCancel(t.Context())
				writeStarted := make(chan struct{})
				finishWrite := make(chan struct{})
				writeResult := make(chan error, 1)
				go func() {
					writeResult <- withWebSocketWriteContext(ctx, ws, time.Second, func() error {
						_, err := ws.Write([]byte("application"))
						close(writeStarted)
						<-finishWrite
						return err
					})
				}()
				<-writeStarted
				cancel()
				close(finishWrite)
				require.ErrorIs(t, <-writeResult, context.Canceled)
			}
			releaseServer()
			observed := <-result
			require.NoError(t, observed.err)
			assert.Equal(t, byte(websocket.PongFrame), observed.opcode)
			assert.Equal(t, pingPayload, observed.payload)
			require.NoError(t, <-received)
		})
	}
}

func TestCloseWebSocketNowInterruptsBlockedWriterAndAutomaticPong(t *testing.T) {
	sendPing := make(chan struct{})
	pingSent := make(chan error, 1)
	releaseServer := make(chan struct{})
	var releaseServerOnce sync.Once
	release := func() { releaseServerOnce.Do(func() { close(releaseServer) }) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := upgradeTestWebSocket(w, r)
		if err != nil {
			pingSent <- err
			return
		}
		defer conn.Close()
		<-sendPing
		pingSent <- writeUnmaskedWebSocketFrame(rw, websocket.PingFrame, []byte("server-ping"))
		<-releaseServer
	}))
	defer server.Close()

	config, err := websocket.NewConfig("ws"+server.URL[len("http"):], pxGridDefaultWSOrigin)
	require.NoError(t, err)
	ws, err := config.DialContext(t.Context())
	require.NoError(t, err)
	ws.PayloadType = websocket.BinaryFrame
	var closeOnce sync.Once
	closeClient := func() { closeOnce.Do(func() { _ = closeWebSocketNow(ws) }) }
	defer func() {
		release()
		closeClient()
	}()

	readerDone := make(chan error, 1)
	go func() {
		var payload []byte
		readerDone <- websocket.Message.Receive(ws, &payload)
	}()
	writerStarted := make(chan struct{})
	writerDone := make(chan error, 1)
	go func() {
		payload := make([]byte, 1024*1024)
		close(writerStarted)
		for {
			if _, err := ws.Write(payload); err != nil {
				writerDone <- err
				return
			}
		}
	}()
	<-writerStarted
	// The peer intentionally never reads application frames, causing the client
	// writer to fill the TCP window and hold x/net/websocket's write lock.
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-writerDone:
		require.FailNowf(t, "writer ended before cancellation", "error type %T", err)
	default:
	}
	close(sendPing)
	require.NoError(t, <-pingSent)
	// Let the reader consume the server Ping and queue its automatic Pong behind
	// the blocked application writer before cancellation begins.
	time.Sleep(50 * time.Millisecond)

	closeDuration := make(chan time.Duration, 1)
	go func() {
		started := time.Now()
		closeClient()
		closeDuration <- time.Since(started)
	}()
	select {
	case elapsed := <-closeDuration:
		assert.Less(t, elapsed, 5*pxGridWebSocketCloseWriteTimeout)
	case <-time.After(5 * pxGridWebSocketCloseWriteTimeout):
		// Release the peer before failing so a close regression cannot strand a
		// goroutine until the package-wide test timeout.
		release()
		select {
		case <-closeDuration:
		case <-time.After(time.Second):
		}
		t.Fatal("bounded WebSocket close blocked behind a writer or automatic Pong")
	}
	release()
	select {
	case <-writerDone:
	case <-time.After(time.Second):
		t.Fatal("blocked WebSocket writer did not stop after bounded close")
	}
	select {
	case <-readerDone:
	case <-time.After(time.Second):
		t.Fatal("WebSocket reader handling the server Ping did not stop after bounded close")
	}
}

func TestPxGridIdleSubscriptionClearsHandshakeReadDeadline(t *testing.T) {
	connectFrames := make(chan stompFrame, 1)
	serverDone := make(chan struct{})
	wsHandler := websocket.Handler(func(ws *websocket.Conn) {
		defer close(serverDone)
		ws.PayloadType = websocket.BinaryFrame
		connect, err := readSTOMP(ws)
		if err != nil {
			return
		}
		connectFrames <- connect
		if err := writeSTOMP(ws, "CONNECTED", map[string]string{"version": "1.2"}, nil); err != nil {
			return
		}
		if _, err := readSTOMP(ws); err != nil {
			return
		}
		// A quiet pxGrid topic is valid. Stay idle until cancellation closes it.
		_, _ = readSTOMP(ws)
	})
	server := httptest.NewTLSServer(http.HandlerFunc(wsHandler.ServeHTTP))
	defer server.Close()

	client, err := NewPxGridClient(PxGridConfig{
		Endpoint:           server.URL + "/pxgrid",
		NodeName:           "collector",
		Password:           "account-password",
		InsecureSkipVerify: true,
		Timeout:            100 * time.Millisecond,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	ready := make(chan struct{}, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- client.subscribeEndpointWithReady(
			ctx,
			"wss"+server.URL[len("https"):],
			"ise-pubsub",
			"peer-secret",
			"/topic/session",
			func() { ready <- struct{}{} },
			nil,
			func(StompMessage) error { return nil },
		)
	}()
	select {
	case <-ready:
	case err := <-errCh:
		require.FailNowf(t, "subscription ended before readiness", "error type %T", err)
	case <-time.After(time.Second):
		t.Fatal("subscription did not become ready")
	}
	connect := <-connectFrames
	assert.Equal(t, "0,0", connect.headers["heart-beat"])
	select {
	case err := <-errCh:
		require.FailNowf(t, "idle subscription inherited the handshake deadline", "error type %T", err)
	case <-time.After(300 * time.Millisecond):
	}
	cancel()
	require.ErrorIs(t, <-errCh, context.Canceled)
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("idle subscription server did not observe cancellation")
	}
}

func TestPxGridSubscribeFailsWhenAdvertisedTopicPropertyIsAbsent(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/pxgrid/control/ServiceLookup", r.URL.Path)
		_, _ = w.Write([]byte(`{"services":[{"name":"com.cisco.ise.session","nodeName":"ise-mnt-1","properties":{"wsPubsubService":"com.cisco.ise.pubsub"}}]}`))
	}))
	defer server.Close()

	client, err := NewPxGridClient(PxGridConfig{Endpoint: server.URL + "/pxgrid", NodeName: "collector", Password: "account-password", InsecureSkipVerify: true})
	require.NoError(t, err)
	err = client.Subscribe(t.Context(), PxGridSubscription{Service: "com.cisco.ise.session", TopicProperty: "sessionTopic"}, func(StompMessage) error { return nil })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sessionTopic")
	assert.Contains(t, err.Error(), "no usable endpoint")
}

func TestPxGridSubscribeDoesNotAckFailedDelivery(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	serverResult := make(chan stompFrame, 1)
	serverDone := make(chan struct{})
	wsHandler := websocket.Handler(func(ws *websocket.Conn) {
		defer close(serverDone)
		if _, err := readSTOMP(ws); err != nil {
			return
		}
		if err := writeSTOMP(ws, "CONNECTED", map[string]string{"version": "1.2"}, nil); err != nil {
			return
		}
		if _, err := readSTOMP(ws); err != nil {
			return
		}
		if err := writeSTOMP(ws, "MESSAGE", map[string]string{
			"destination": "/topic/session",
			"message-id":  "message-1",
			"ack":         "ack-1",
		}, []byte(`{"id":"session-1"}`)); err != nil {
			return
		}
		if frame, err := readSTOMP(ws); err == nil {
			serverResult <- frame
		}
	})
	server := httptest.NewTLSServer(http.HandlerFunc(wsHandler.ServeHTTP))
	defer server.Close()

	client, err := NewPxGridClient(PxGridConfig{
		Endpoint:           server.URL + "/pxgrid",
		NodeName:           "collector",
		Password:           "account-password",
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	deliveryErr := errors.New("downstream unavailable")
	acknowledged := make(chan struct{}, 1)
	err = client.subscribeEndpointWithReady(t.Context(), "wss"+server.URL[len("https"):], "ise-pubsub", "peer-secret", "/topic/session", nil, func() {
		acknowledged <- struct{}{}
	}, func(StompMessage) error {
		return deliveryErr
	})
	require.ErrorIs(t, err, deliveryErr)
	select {
	case <-acknowledged:
		t.Fatal("failed message delivery reported a completed ACK write")
	default:
	}

	select {
	case frame := <-serverResult:
		assert.NotEqual(t, "ACK", frame.command)
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("pxGrid WebSocket did not close after failed delivery")
	}
}

func TestPxGridSubscribeCancellationInterruptsSTOMPHandshake(t *testing.T) {
	connectReceived := make(chan struct{})
	serverDone := make(chan struct{})
	wsHandler := websocket.Handler(func(ws *websocket.Conn) {
		defer close(serverDone)
		if _, err := readSTOMP(ws); err != nil {
			return
		}
		close(connectReceived)
		// Never send CONNECTED. The client must close the socket when its
		// context is canceled rather than stranding this read and its worker.
		_, _ = readSTOMP(ws)
	})
	server := httptest.NewTLSServer(http.HandlerFunc(wsHandler.ServeHTTP))
	defer server.Close()

	client, err := NewPxGridClient(PxGridConfig{
		Endpoint:           server.URL + "/pxgrid",
		NodeName:           "collector",
		Password:           "account-password",
		InsecureSkipVerify: true,
		Timeout:            time.Minute,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)
	go func() {
		errCh <- client.subscribeEndpointWithReady(ctx, "wss"+server.URL[len("https"):], "ise-pubsub", "peer-secret", "/topic/session", nil, nil, func(StompMessage) error {
			return nil
		})
	}()

	select {
	case <-connectReceived:
	case <-time.After(5 * time.Second):
		t.Fatal("pxGrid client did not send STOMP CONNECT")
	}
	cancel()
	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("pxGrid subscription did not stop after cancellation")
	}
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("pxGrid WebSocket server remained blocked after cancellation")
	}
}

func TestPxGridSubscribeFailsWithoutDocumentedTopicProperty(t *testing.T) {
	client, err := NewPxGridClient(PxGridConfig{Endpoint: "https://ise.example:8910/pxgrid", NodeName: "collector", Password: "account-password"})
	require.NoError(t, err)

	err = client.Subscribe(t.Context(), PxGridSubscription{Service: "com.cisco.ise.system"}, func(StompMessage) error { return nil })
	require.Error(t, err)
	assert.Equal(t, `pxGrid subscription service "com.cisco.ise.system" has no documented topic property`, err.Error())
}

func TestPxGridControlUsesDocumentedPostCalls(t *testing.T) {
	var methods []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	client, err := NewPxGridClient(PxGridConfig{Endpoint: server.URL + "/pxgrid", NodeName: "collector", Password: "account-password", InsecureSkipVerify: true})
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

	verifiedClient, err := NewPxGridClient(PxGridConfig{
		Endpoint:   server.URL + "/pxgrid",
		NodeName:   "collector",
		Password:   "account-password",
		MaxRetries: 3,
	})
	require.NoError(t, err)
	verifiedAttempts := 0
	verifiedClient.SetOnRequest(func(RequestStat) { verifiedAttempts++ })
	_, err = verifiedClient.Version(t.Context())
	require.ErrorContains(t, err, "configure ise.pxgrid.ca_file with the issuing CA (preferred)")
	require.ErrorContains(t, err, "set ise.pxgrid.insecure_skip_verify: true")
	assert.Equal(t, 1, verifiedAttempts)

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

func TestPxGridTLSConfigLoadsEncryptedPKCS8Key(t *testing.T) {
	const keyPassword = "correct-test-key-password"
	certFile, keyFile := writePxGridClientKeyPair(t, keyPassword)

	tlsConfig, err := pxGridTLSConfig(PxGridConfig{
		CertFile:    certFile,
		KeyFile:     keyFile,
		KeyPassword: keyPassword,
	})
	require.NoError(t, err)
	require.Len(t, tlsConfig.Certificates, 1)
	assert.NotNil(t, tlsConfig.Certificates[0].PrivateKey)
}

func TestPxGridTLSConfigRejectsWrongEncryptedPKCS8PasswordWithoutLeakingIt(t *testing.T) {
	const (
		correctPassword = "correct-test-key-password"
		wrongPassword   = "wrong-password-must-not-leak"
	)
	certFile, keyFile := writePxGridClientKeyPair(t, correctPassword)

	_, err := pxGridTLSConfig(PxGridConfig{
		CertFile:    certFile,
		KeyFile:     keyFile,
		KeyPassword: wrongPassword,
	})
	require.ErrorContains(t, err, "failed to decrypt pxGrid PKCS#8 private key")
	assert.NotContains(t, err.Error(), correctPassword)
	assert.NotContains(t, err.Error(), wrongPassword)
}

func TestPxGridTLSConfigRetainsUnencryptedKeySupport(t *testing.T) {
	certFile, keyFile := writePxGridClientKeyPair(t, "")

	tlsConfig, err := pxGridTLSConfig(PxGridConfig{CertFile: certFile, KeyFile: keyFile})
	require.NoError(t, err)
	require.Len(t, tlsConfig.Certificates, 1)
	assert.NotNil(t, tlsConfig.Certificates[0].PrivateKey)
}

func TestLoadPxGridKeyPairRejectsOversizedKeyFile(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "pxgrid-client.crt")
	keyFile := filepath.Join(dir, "pxgrid-client.key")
	require.NoError(t, os.WriteFile(certFile, []byte("not parsed before both bounded reads complete"), 0o600))
	require.NoError(t, os.WriteFile(keyFile, make([]byte, maxPxGridPrivateKeyPEMBytes+1), 0o600))

	for _, keyPassword := range []string{"", "test-password"} {
		_, err := loadPxGridKeyPair(certFile, keyFile, keyPassword)
		require.ErrorContains(t, err, "pxGrid key_file exceeds the")
	}
}

func writePxGridClientKeyPair(t *testing.T, keyPassword string) (string, string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(4_102_444_800, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	var (
		keyDER    []byte
		blockType = "PRIVATE KEY"
	)
	if keyPassword == "" {
		keyDER, err = x509.MarshalPKCS8PrivateKey(privateKey)
	} else {
		keyDER, err = pkcs8.MarshalPrivateKey(privateKey, []byte(keyPassword), nil)
		blockType = "ENCRYPTED PRIVATE KEY"
	}
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: keyDER})

	dir := t.TempDir()
	certFile := filepath.Join(dir, "pxgrid-client.crt")
	keyFile := filepath.Join(dir, "pxgrid-client.key")
	require.NoError(t, os.WriteFile(certFile, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0o600))
	return certFile, keyFile
}

func TestPxGridWSSCertificateFailureNamesTrustAndOptInPaths(t *testing.T) {
	server := httptest.NewTLSServer(websocket.Handler(func(*websocket.Conn) {}))
	defer server.Close()

	client, err := NewPxGridClient(PxGridConfig{
		Endpoint: server.URL + "/pxgrid",
		NodeName: "collector",
		Password: "account-password",
	})
	require.NoError(t, err)
	err = client.subscribeEndpointWithReady(
		t.Context(),
		"wss"+server.URL[len("https"):],
		"ise-pubsub",
		"peer-secret",
		"/topic/session",
		nil,
		nil,
		func(StompMessage) error { return nil },
	)
	require.ErrorContains(t, err, "configure ise.pxgrid.ca_file with the issuing CA (preferred)")
	require.ErrorContains(t, err, "set ise.pxgrid.insecure_skip_verify: true")
	var dialErr *websocket.DialError
	require.ErrorAs(t, err, &dialErr)
	var certificateErr *httpclient.CertificateVerificationError
	require.ErrorAs(t, err, &certificateErr)
	assert.True(t, httpclient.IsCertificateVerificationError(err))
}

func TestPxGridRejectsPlaintextControlEndpoint(t *testing.T) {
	_, err := NewPxGridClient(PxGridConfig{
		Endpoint: "http://ise.example:8910/pxgrid",
		NodeName: "collector",
		Password: "account-password",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must use https")
}

func TestPxGridRejectsUnsafeDiscoveredEndpointBeforeAccessSecret(t *testing.T) {
	for _, advertised := range []string{
		"http://127.0.0.1:4444/pxgrid/mnt/sd",
		"https://127.0.0.1:4444/pxgrid/mnt/sd",
		"https://attacker.example/pxgrid/mnt/sd",
	} {
		t.Run(advertised, func(t *testing.T) {
			accessSecretCalls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/pxgrid/control/ServiceLookup":
					_, _ = w.Write([]byte(`{"services":[{"nodeName":"ise-psn-1","properties":{"restBaseUrl":"` + advertised + `"}}]}`))
				case "/pxgrid/control/AccessSecret":
					accessSecretCalls++
					_, _ = w.Write([]byte(`{"secret":"must-not-be-requested"}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			client, err := NewPxGridClient(PxGridConfig{
				Endpoint:           server.URL + "/pxgrid",
				NodeName:           "collector",
				Password:           "account-password",
				InsecureSkipVerify: true,
			})
			require.NoError(t, err)
			_, err = client.PostObjects(t.Context(), "sessions", "com.cisco.ise.session", "/getSessions", map[string]any{}, 10)
			require.Error(t, err)
			assert.Zero(t, accessSecretCalls)
		})
	}
}

func TestPxGridDiscoveredEndpointRequiresExactAuthorizedOrigin(t *testing.T) {
	client, err := NewPxGridClient(PxGridConfig{
		Endpoint:              "https://ise-control.example:8910/pxgrid",
		NodeName:              "collector",
		Password:              "account-password",
		AllowedServiceOrigins: []string{"https://ise-service.example:9443"},
	})
	require.NoError(t, err)

	require.NoError(t, client.validateDiscoveredURL("https://ise-control.example:8910/pxgrid/mnt", "https"))
	require.NoError(t, client.validateDiscoveredURL("wss://ise-control.example:8910/pxgrid/pubsub", "wss"))
	require.NoError(t, client.validateDiscoveredURL("https://ise-service.example:9443/pxgrid/mnt", "https"))
	require.ErrorContains(t, client.validateDiscoveredURL("https://ise-control.example:9444/pxgrid/mnt", "https"), "not authorized")
	require.ErrorContains(t, client.validateDiscoveredURL("wss://ise-service.example:9443/pxgrid/pubsub", "wss"), "not authorized")
	for _, endpoint := range []string{
		"https://ise-control.example:8910/pxgrid/mnt?",
		"https://ise-control.example:8910/pxgrid/mnt?token=secret",
		"wss://ise-control.example:8910/pxgrid/pubsub#fragment",
	} {
		require.ErrorContains(t, client.validateDiscoveredURL(endpoint, "https", "wss"), "must not contain a query or fragment")
	}
}

func TestNewPxGridClientRejectsMalformedAllowedServiceOrigin(t *testing.T) {
	for _, origin := range []string{
		"http://ise.example:8910",
		"https://user:password@ise.example:8910",
		"https://ise.example:8910/pxgrid",
		"https://ise.example:8910?target=other",
	} {
		t.Run(origin, func(t *testing.T) {
			_, err := NewPxGridClient(PxGridConfig{
				Endpoint:              "https://ise-control.example:8910/pxgrid",
				NodeName:              "collector",
				Password:              "account-password",
				AllowedServiceOrigins: []string{origin},
			})
			require.ErrorContains(t, err, "allowed service origin")
		})
	}
}

func TestParseSTOMPFrameEnforcesResourceLimits(t *testing.T) {
	validHeaders := "MESSAGE\n" + strings.Repeat("x:value\n", stompMaxHeaders) + "\n{}\x00"
	frame, err := parseSTOMPFrame([]byte(validHeaders))
	require.NoError(t, err)
	assert.Equal(t, "MESSAGE", frame.command)
	assert.Equal(t, []byte("{}"), frame.body)

	tests := []struct {
		name      string
		frame     []byte
		errorPart string
	}{
		{
			name:      "frame bytes",
			frame:     make([]byte, stompMaxFrameBytes+1),
			errorPart: "frame exceeds",
		},
		{
			name:      "header count",
			frame:     []byte("MESSAGE\n" + strings.Repeat("x:value\n", stompMaxHeaders+1) + "\n"),
			errorPart: "header limit",
		},
		{
			name:      "aggregate header bytes",
			frame:     []byte("MESSAGE\n" + strings.Repeat("x:"+strings.Repeat("v", stompMaxLineBytes-2)+"\n", stompMaxHeaderBytes/stompMaxLineBytes+1) + "\n"),
			errorPart: "headers exceed",
		},
		{
			name:      "line bytes",
			frame:     []byte("MESSAGE\nheader:" + strings.Repeat("v", stompMaxLineBytes) + "\n\n"),
			errorPart: "line exceeds",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseSTOMPFrame(test.frame)
			require.ErrorContains(t, err, test.errorPart)
		})
	}
}
