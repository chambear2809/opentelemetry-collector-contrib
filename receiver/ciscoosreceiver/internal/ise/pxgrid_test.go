// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPxGridRESTDiscoversServiceEndpointAndPeerSecret(t *testing.T) {
	const (
		collectorNode  = "collector"
		accountSecret  = "account-password"
		serviceNode    = "ise-mnt-2"
		serviceSecret  = "service-access-secret"
		sessionService = "com.cisco.ise.session"
	)

	serviceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/pxgrid/mnt/sd/getSessions", r.URL.Path)
		username, password, ok := r.BasicAuth()
		require.True(t, ok)
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
	controlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		require.True(t, ok)
		assert.Equal(t, collectorNode, username)
		assert.Equal(t, accountSecret, password)
		switch r.URL.Path {
		case "/pxgrid/control/ServiceLookup":
			var request struct {
				Name string `json:"name"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			mu.Lock()
			lookedUpService = request.Name
			mu.Unlock()
			_, _ = w.Write([]byte(`{"services":[{"name":"com.cisco.ise.session","nodeName":"ise-mnt-2","properties":{"restBaseUrl":"` + serviceServer.URL + `/pxgrid/mnt/sd"}}]}`))
		case "/pxgrid/control/AccessSecret":
			var request struct {
				PeerNodeName string `json:"peerNodeName"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			mu.Lock()
			secretPeer = request.PeerNodeName
			mu.Unlock()
			_, _ = w.Write([]byte(`{"secret":"service-access-secret"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer controlServer.Close()

	client, err := NewPxGridClient(PxGridConfig{Endpoint: controlServer.URL + "/pxgrid", NodeName: collectorNode, Password: accountSecret})
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
		pubSubSecret    = "pubsub-access-secret"
		discoveredTopic = "/topic/discovered/session"
	)

	connectFrames := make(chan stompFrame, 1)
	subscribeFrames := make(chan stompFrame, 1)
	authenticated := make(chan struct{}, 1)
	wsHandler := websocket.Handler(func(ws *websocket.Conn) {
		connect, err := readSTOMP(ws)
		if err != nil {
			return
		}
		connectFrames <- connect
		if err := writeSTOMP(ws, "CONNECTED", map[string]string{"version": "1.2"}, nil); err != nil {
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
		}, []byte(`{"id":"session-1"}`))
	})
	pubSubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/discovered/ws", r.URL.Path)
		username, password, ok := r.BasicAuth()
		require.True(t, ok)
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
	controlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		require.True(t, ok)
		assert.Equal(t, collectorNode, username)
		assert.Equal(t, accountSecret, password)
		switch r.URL.Path {
		case "/pxgrid/control/ServiceLookup":
			var request struct {
				Name string `json:"name"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			mu.Lock()
			lookups = append(lookups, request.Name)
			mu.Unlock()
			switch request.Name {
			case "com.cisco.ise.session":
				_, _ = w.Write([]byte(`{"services":[{"name":"com.cisco.ise.session","nodeName":"ise-mnt-1","properties":{"wsPubsubService":"` + pubSubService + `","sessionTopic":"` + discoveredTopic + `"}}]}`))
			case pubSubService:
				_, _ = w.Write([]byte(`{"services":[{"name":"` + pubSubService + `","nodeName":"` + pubSubNode + `","properties":{"wsUrl":"` + "ws" + pubSubServer.URL[len("http"):] + `/discovered/ws"}}]}`))
			default:
				_, _ = w.Write([]byte(`{"services":[]}`))
			}
		case "/pxgrid/control/AccessSecret":
			var request struct {
				PeerNodeName string `json:"peerNodeName"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			mu.Lock()
			secretPeers = append(secretPeers, request.PeerNodeName)
			mu.Unlock()
			_, _ = w.Write([]byte(`{"secret":"` + pubSubSecret + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer controlServer.Close()

	client, err := NewPxGridClient(PxGridConfig{Endpoint: controlServer.URL + "/pxgrid", NodeName: collectorNode, Password: accountSecret})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	messages := make(chan StompMessage, 1)
	err = client.Subscribe(ctx, PxGridSubscription{Service: "com.cisco.ise.session", TopicProperty: "sessionTopic"}, func(message StompMessage) {
		messages <- message
		cancel()
	})
	require.ErrorIs(t, err, context.Canceled)

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

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"com.cisco.ise.session", pubSubService}, lookups)
	assert.Equal(t, []string{pubSubNode}, secretPeers)
}

func TestPxGridSubscribeFailsWhenAdvertisedTopicPropertyIsAbsent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/pxgrid/control/ServiceLookup", r.URL.Path)
		_, _ = w.Write([]byte(`{"services":[{"name":"com.cisco.ise.session","nodeName":"ise-mnt-1","properties":{"wsPubsubService":"com.cisco.ise.pubsub"}}]}`))
	}))
	defer server.Close()

	client, err := NewPxGridClient(PxGridConfig{Endpoint: server.URL + "/pxgrid", NodeName: "collector", Password: "account-password"})
	require.NoError(t, err)
	err = client.Subscribe(t.Context(), PxGridSubscription{Service: "com.cisco.ise.session", TopicProperty: "sessionTopic"}, func(StompMessage) {})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sessionTopic")
	assert.Contains(t, err.Error(), "no usable endpoint")
}

func TestPxGridSubscribeFailsWithoutDocumentedTopicProperty(t *testing.T) {
	client, err := NewPxGridClient(PxGridConfig{Endpoint: "https://ise.example:8910/pxgrid", NodeName: "collector", Password: "account-password"})
	require.NoError(t, err)

	err = client.Subscribe(t.Context(), PxGridSubscription{Service: "com.cisco.ise.system"}, func(StompMessage) {})
	require.Error(t, err)
	assert.Equal(t, `pxGrid subscription service "com.cisco.ise.system" has no documented topic property`, err.Error())
}

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
