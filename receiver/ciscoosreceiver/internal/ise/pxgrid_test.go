// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"golang.org/x/net/websocket"
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
		assert.True(t, ok)
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
		assert.True(t, ok)
		assert.Equal(t, collectorNode, username)
		assert.Equal(t, accountSecret, password)
		switch r.URL.Path {
		case "/pxgrid/control/ServiceLookup":
			var request struct {
				Name string `json:"name"`
			}
			if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&request)) {
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
		pubSubSecret    = "pubsub-access-secret" //nolint:gosec // Test-only pxGrid peer credential.
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
		assert.True(t, ok)
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
		assert.True(t, ok)
		assert.Equal(t, collectorNode, username)
		assert.Equal(t, accountSecret, password)
		switch r.URL.Path {
		case "/pxgrid/control/ServiceLookup":
			var request struct {
				Name string `json:"name"`
			}
			if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&request)) {
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
	err = client.Subscribe(ctx, PxGridSubscription{Service: "com.cisco.ise.session", TopicProperty: "sessionTopic"}, func(message StompMessage) error {
		messages <- message
		return nil
	})
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

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"com.cisco.ise.session", pubSubService}, lookups)
	assert.Equal(t, []string{pubSubNode}, secretPeers)
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
	err = client.subscribeEndpoint(t.Context(), "wss"+server.URL[len("https"):], "ise-pubsub", "peer-secret", "/topic/session", func(StompMessage) error {
		return deliveryErr
	})
	require.ErrorIs(t, err, deliveryErr)

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
		errCh <- client.subscribeEndpoint(ctx, "wss"+server.URL[len("https"):], "ise-pubsub", "peer-secret", "/topic/session", func(StompMessage) error {
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
