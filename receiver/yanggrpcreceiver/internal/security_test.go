// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type testServerStream struct {
	grpc.ServerStream
	ctx       context.Context
	recvCount int
}

func (s *testServerStream) Context() context.Context {
	return s.ctx
}

func (s *testServerStream) RecvMsg(any) error {
	s.recvCount++
	return nil
}

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(1.0, 2, time.Minute) // 1 request per second, burst of 2
	defer rl.Stop()

	// First request should be allowed (from burst)
	assert.True(t, rl.Allow("192.168.1.1"))

	// Second request should be allowed (from burst)
	assert.True(t, rl.Allow("192.168.1.1"))

	// Third request should be denied (rate limited - burst exhausted)
	assert.False(t, rl.Allow("192.168.1.1"))

	// Different IP should be allowed (has its own bucket)
	assert.True(t, rl.Allow("192.168.1.2"))
}

func TestRateLimiterDefaultsInvalidCleanupInterval(t *testing.T) {
	rl := newRateLimiter(1.0, 1, 0)
	rl.Stop()
	assert.Equal(t, defaultRateLimiterCleanupInterval, rl.cleanupInterval)

	rl = newRateLimiter(1.0, 1, time.Millisecond)
	rl.Stop()
	assert.Equal(t, defaultRateLimiterCleanupInterval, rl.cleanupInterval)
}

func TestRateLimiterCleanupCannotResetTokensBeforeFullRefill(t *testing.T) {
	cleanupInterval := time.Second
	rl := newRateLimiter(0.5, 2, cleanupInterval)
	defer rl.Stop()
	now := time.Now()

	assert.True(t, rl.allowAt("192.0.2.1", now))
	assert.True(t, rl.allowAt("192.0.2.1", now))
	assert.False(t, rl.allowAt("192.0.2.1", now))

	rl.cleanupStale(now.Add(cleanupInterval))
	assert.Equal(t, 1, rl.clientCount())
	assert.False(t, rl.allowAt("192.0.2.1", now.Add(cleanupInterval)))

	rl.cleanupStale(now.Add(5*time.Second + time.Nanosecond))
	assert.Zero(t, rl.clientCount())
	assert.True(t, rl.allowAt("192.0.2.1", now.Add(5*time.Second+time.Nanosecond)))
}

func TestSecurityManager_ClientAuthTypes(t *testing.T) {
	sm := &SecurityManager{}

	tests := []struct {
		authType string
		expected tls.ClientAuthType
		hasError bool
	}{
		{"NoClientCert", tls.NoClientCert, false},
		{"RequestClientCert", tls.RequestClientCert, false},
		{"RequireAnyClientCert", tls.RequireAnyClientCert, false},
		{"VerifyClientCertIfGiven", tls.VerifyClientCertIfGiven, false},
		{"RequireAndVerifyClientCert", tls.RequireAndVerifyClientCert, false},
		{"InvalidAuthType", tls.NoClientCert, true},
	}

	for _, tt := range tests {
		t.Run(tt.authType, func(t *testing.T) {
			authType, err := sm.getClientAuthType(tt.authType)
			if tt.hasError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, authType)
			}
		})
	}
}

func TestSecurityManager_StreamInterceptorAuthorizesPeer(t *testing.T) {
	tests := []struct {
		name           string
		allowedClients []string
		ctx            context.Context
		wantCode       codes.Code
		wantHandled    bool
	}{
		{
			name:           "exact IP allowed",
			allowedClients: []string{"192.0.2.10"},
			ctx:            contextWithPeer("192.0.2.10"),
			wantCode:       codes.OK,
			wantHandled:    true,
		},
		{
			name:           "CIDR allowed",
			allowedClients: []string{"2001:db8::/32"},
			ctx:            contextWithPeer("2001:db8::10"),
			wantCode:       codes.OK,
			wantHandled:    true,
		},
		{
			name:           "equivalent IPv6 spelling allowed",
			allowedClients: []string{"2001:0db8:0:0:0:0:0:10"},
			ctx:            contextWithPeer("2001:db8::10"),
			wantCode:       codes.OK,
			wantHandled:    true,
		},
		{
			name:           "IP denied",
			allowedClients: []string{"192.0.2.10"},
			ctx:            contextWithPeer("198.51.100.20"),
			wantCode:       codes.PermissionDenied,
		},
		{
			name:           "peer unavailable with allowlist configured",
			allowedClients: []string{"192.0.2.10"},
			ctx:            t.Context(),
			wantCode:       codes.Unauthenticated,
		},
		{
			name:        "peer unavailable with security disabled",
			ctx:         t.Context(),
			wantCode:    codes.OK,
			wantHandled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewSecurityManager(tt.allowedClients, zap.NewNop(), false, 0, 0, time.Minute)
			stream := &testServerStream{ctx: tt.ctx}
			handled := false

			err := sm.CreateStreamSecurityInterceptor()(
				nil,
				stream,
				&grpc.StreamServerInfo{FullMethod: "/mdt_dialout.gRPCMdtDialout/MdtDialout"},
				func(any, grpc.ServerStream) error {
					handled = true
					return nil
				},
			)

			assert.Equal(t, tt.wantCode, status.Code(err))
			assert.Equal(t, tt.wantHandled, handled)
		})
	}
}

func TestSecurityManager_StreamInterceptorRateLimitsPeer(t *testing.T) {
	sm := NewSecurityManager(nil, zap.NewNop(), true, 0, 1, time.Minute)
	defer sm.Shutdown()

	stream := &testServerStream{ctx: contextWithPeer("192.0.2.10")}
	interceptor := sm.CreateStreamSecurityInterceptor()
	info := &grpc.StreamServerInfo{FullMethod: "/mdt_dialout.gRPCMdtDialout/MdtDialout"}
	handler := func(_ any, intercepted grpc.ServerStream) error {
		require.NoError(t, intercepted.RecvMsg(&struct{}{}))
		return intercepted.RecvMsg(&struct{}{})
	}

	err := interceptor(nil, stream, info, handler)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.Equal(t, 2, stream.recvCount)
}

func TestSecurityManager_UnaryAndStreamInterceptorsUseSameAuthorization(t *testing.T) {
	sm := NewSecurityManager([]string{"192.0.2.10"}, zap.NewNop(), false, 0, 0, time.Minute)
	ctx := contextWithPeer("198.51.100.20")

	_, unaryErr := sm.CreateSecurityInterceptor()(
		ctx,
		nil,
		&grpc.UnaryServerInfo{FullMethod: "/test.Service/Unary"},
		func(context.Context, any) (any, error) {
			t.Fatal("unary handler must not run for a denied peer")
			return nil, nil
		},
	)
	streamErr := sm.CreateStreamSecurityInterceptor()(
		nil,
		&testServerStream{ctx: ctx},
		&grpc.StreamServerInfo{FullMethod: "/test.Service/Stream"},
		func(any, grpc.ServerStream) error {
			t.Fatal("stream handler must not run for a denied peer")
			return nil
		},
	)

	assert.Equal(t, codes.PermissionDenied, status.Code(unaryErr))
	assert.Equal(t, status.Code(unaryErr), status.Code(streamErr))
}

func contextWithPeer(ip string) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 12345},
	})
}
