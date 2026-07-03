// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configmiddleware"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcmetadata "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver"
)

func TestGNMIDialOutStreamSecurityOwnsImmutableAllowlist(t *testing.T) {
	configured := []string{"192.0.2.10", "2001:db8::/32"}
	security, err := newGNMIDialOutStreamSecurity(configured, yanggrpcreceiver.RateLimitingConfig{}, zap.NewNop(), 10)
	require.NoError(t, err)
	configured[0] = "198.51.100.20"

	tests := []struct {
		name        string
		ctx         context.Context
		wantCode    codes.Code
		wantHandled bool
	}{
		{name: "exact IPv4 allowed", ctx: gnmiDialOutPeerContext(t.Context(), "192.0.2.10"), wantCode: codes.OK, wantHandled: true},
		{name: "IPv6 CIDR allowed", ctx: gnmiDialOutPeerContext(t.Context(), "2001:db8::5"), wantCode: codes.OK, wantHandled: true},
		{name: "mutated input not allowed", ctx: gnmiDialOutPeerContext(t.Context(), "198.51.100.20"), wantCode: codes.PermissionDenied},
		{name: "unlisted peer denied", ctx: gnmiDialOutPeerContext(t.Context(), "203.0.113.40"), wantCode: codes.PermissionDenied},
		{name: "missing peer rejected", ctx: t.Context(), wantCode: codes.Unauthenticated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handled := false
			err := security.StreamServerInterceptor()(
				nil,
				&gnmiDialOutTestServerStream{ctx: tt.ctx},
				&grpc.StreamServerInfo{FullMethod: gnmiDialOutTestMethod},
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

type gnmiDialOutTestRuntimeVersion int

func (v gnmiDialOutTestRuntimeVersion) RuntimeHardeningVersion() int { return int(v) }

func TestRequireHardenedYangGRPCRuntimeFailsClosed(t *testing.T) {
	require.ErrorContains(t, requireHardenedYangGRPCRuntime(struct{}{}), "runtime hardening version 1")
	require.ErrorContains(t, requireHardenedYangGRPCRuntime(gnmiDialOutTestRuntimeVersion(0)), "runtime hardening version 1")
	require.NoError(t, requireHardenedYangGRPCRuntime(gnmiDialOutTestRuntimeVersion(1)))

	_, err := hardenedYangGRPCConfig(gnmiDialOutTestRuntimeVersion(1))
	require.ErrorContains(t, err, "unexpected hardened config type")
	_, err = hardenedYangGRPCConfig(struct{}{})
	require.ErrorContains(t, err, "runtime hardening version 1")
	runtimeErr := requireHardenedYangGRPCRuntime(&yanggrpcreceiver.Config{})
	config, err := hardenedYangGRPCConfig(&yanggrpcreceiver.Config{})
	var typedNil *yanggrpcreceiver.Config
	_, typedNilErr := hardenedYangGRPCConfig(typedNil)
	if runtimeErr == nil {
		require.NoError(t, err)
		require.NotNil(t, config)
		require.ErrorContains(t, typedNilErr, "unexpected hardened config type")
	} else {
		require.ErrorContains(t, err, "runtime hardening version 1")
		require.ErrorContains(t, typedNilErr, "runtime hardening version 1")
	}
}

func TestGNMIDialOutStreamSecurityChargesEverySuccessfulMessage(t *testing.T) {
	security, err := newGNMIDialOutStreamSecurity(nil, yanggrpcreceiver.RateLimitingConfig{
		Enabled:           true,
		RequestsPerSecond: 0.000001,
		BurstSize:         1,
		CleanupInterval:   time.Hour,
	}, zap.NewNop(), 10)
	require.NoError(t, err)
	security.Start()
	t.Cleanup(security.Shutdown)

	stream := &gnmiDialOutTestServerStream{
		ctx:         gnmiDialOutPeerContext(t.Context(), "192.0.2.10"),
		recvResults: []error{nil, nil},
	}
	err = security.StreamServerInterceptor()(
		nil,
		stream,
		&grpc.StreamServerInfo{FullMethod: gnmiDialOutTestMethod},
		func(_ any, intercepted grpc.ServerStream) error {
			require.NoError(t, intercepted.RecvMsg(&struct{}{}))
			return intercepted.RecvMsg(&struct{}{})
		},
	)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.Equal(t, int64(2), stream.recvCount.Load())
}

func TestGNMIDialOutPeerRateLimiterBoundsAndCleansState(t *testing.T) {
	cleanupInterval := time.Minute
	limiter := newGNMIDialOutPeerRateLimiter(rate.Inf, 1, cleanupInterval, 2)
	t.Cleanup(limiter.Stop)
	initial := time.Unix(1_800_000_000, 0)

	assert.True(t, limiter.allowAt("192.0.2.1", initial))
	assert.True(t, limiter.allowAt("192.0.2.2", initial.Add(cleanupInterval)))
	assert.False(t, limiter.allowAt("192.0.2.3", initial.Add(cleanupInterval)))
	assert.Equal(t, 2, limiter.peerCount())

	limiter.cleanupStale(initial.Add(cleanupInterval + time.Nanosecond))
	assert.Equal(t, 1, limiter.peerCount())
	assert.True(t, limiter.allowAt("192.0.2.3", initial.Add(cleanupInterval+time.Nanosecond)))
	assert.Equal(t, 2, limiter.peerCount())

	lowRate := newGNMIDialOutPeerRateLimiter(0.5, 2, time.Second, 1)
	t.Cleanup(lowRate.Stop)
	assert.True(t, lowRate.allowAt("192.0.2.4", initial))
	assert.True(t, lowRate.allowAt("192.0.2.4", initial))
	assert.False(t, lowRate.allowAt("192.0.2.4", initial))
	lowRate.cleanupStale(initial.Add(time.Second))
	assert.Equal(t, 1, lowRate.peerCount())
	assert.False(t, lowRate.allowAt("192.0.2.4", initial.Add(time.Second)))
	lowRate.cleanupStale(initial.Add(5*time.Second + time.Nanosecond))
	assert.Zero(t, lowRate.peerCount())
}

func TestGNMIDialOutSecurityShutdownCancelsBlockedReceive(t *testing.T) {
	security, err := newGNMIDialOutStreamSecurity(nil, yanggrpcreceiver.RateLimitingConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		BurstSize:         1,
		CleanupInterval:   time.Hour,
	}, zap.NewNop(), 10)
	require.NoError(t, err)
	security.Start()

	receiveStarted := make(chan struct{})
	releaseReceive := make(chan struct{})
	stream := &gnmiDialOutTestServerStream{
		ctx:            gnmiDialOutPeerContext(t.Context(), "192.0.2.10"),
		receiveStarted: receiveStarted,
		releaseReceive: releaseReceive,
	}
	result := make(chan error, 1)
	var managed *gnmiDialOutManagedServerStream
	go func() {
		result <- security.StreamServerInterceptor()(
			nil,
			stream,
			&grpc.StreamServerInfo{FullMethod: gnmiDialOutTestMethod},
			func(_ any, intercepted grpc.ServerStream) error {
				rateLimited := intercepted.(*gnmiDialOutRateLimitedServerStream)
				managed = rateLimited.ServerStream.(*gnmiDialOutManagedServerStream)
				return intercepted.RecvMsg(&struct{}{})
			},
		)
	}()

	select {
	case <-receiveStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not enter RecvMsg")
	}
	security.Shutdown()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("active stream did not observe middleware shutdown")
	}
	close(releaseReceive)
	select {
	case <-managed.done:
	case <-time.After(5 * time.Second):
		t.Fatal("managed stream receive worker did not exit")
	}
}

func TestGNMIDialOutSecurityBoundsActiveStreamsAndRejectsAfterShutdown(t *testing.T) {
	security, err := newGNMIDialOutStreamSecurity(nil, yanggrpcreceiver.RateLimitingConfig{}, zap.NewNop(), 10)
	require.NoError(t, err)
	security.maxActiveStreams = 2

	type activeStream struct {
		started chan struct{}
		release chan struct{}
		result  chan error
	}
	startStream := func() activeStream {
		active := activeStream{started: make(chan struct{}), release: make(chan struct{}), result: make(chan error, 1)}
		go func() {
			active.result <- security.StreamServerInterceptor()(
				nil,
				&gnmiDialOutTestServerStream{ctx: t.Context()},
				&grpc.StreamServerInfo{FullMethod: gnmiDialOutTestMethod},
				func(_ any, stream grpc.ServerStream) error {
					close(active.started)
					select {
					case <-active.release:
						return nil
					case <-stream.Context().Done():
						return stream.Context().Err()
					}
				},
			)
		}()
		return active
	}

	first := startStream()
	second := startStream()
	for _, started := range []<-chan struct{}{first.started, second.started} {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("stream handler did not start")
		}
	}
	handled := false
	err = security.StreamServerInterceptor()(
		nil,
		&gnmiDialOutTestServerStream{ctx: t.Context()},
		&grpc.StreamServerInfo{FullMethod: gnmiDialOutTestMethod},
		func(any, grpc.ServerStream) error {
			handled = true
			return nil
		},
	)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.False(t, handled)

	close(first.release)
	require.NoError(t, <-first.result)
	require.NoError(t, security.StreamServerInterceptor()(
		nil,
		&gnmiDialOutTestServerStream{ctx: t.Context()},
		&grpc.StreamServerInfo{FullMethod: gnmiDialOutTestMethod},
		func(any, grpc.ServerStream) error { return nil },
	))

	security.Shutdown()
	require.ErrorIs(t, <-second.result, context.Canceled)
	err = security.StreamServerInterceptor()(
		nil,
		&gnmiDialOutTestServerStream{ctx: t.Context()},
		&grpc.StreamServerInfo{FullMethod: gnmiDialOutTestMethod},
		func(any, grpc.ServerStream) error { return nil },
	)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestGNMIDialOutSecurityBoundsActiveStreamsPerPeer(t *testing.T) {
	security, err := newGNMIDialOutStreamSecurity(nil, yanggrpcreceiver.RateLimitingConfig{}, zap.NewNop(), 10)
	require.NoError(t, err)
	security.maxActiveStreams = 3
	security.maxActiveStreamsPerPeer = 1

	started := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- security.StreamServerInterceptor()(
			nil,
			&gnmiDialOutTestServerStream{ctx: gnmiDialOutPeerContext(t.Context(), "192.0.2.10")},
			&grpc.StreamServerInfo{FullMethod: gnmiDialOutTestMethod},
			func(any, grpc.ServerStream) error {
				close(started)
				<-release
				return nil
			},
		)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first peer stream did not start")
	}

	handled := false
	err = security.StreamServerInterceptor()(
		nil,
		&gnmiDialOutTestServerStream{ctx: gnmiDialOutPeerContext(t.Context(), "192.0.2.10")},
		&grpc.StreamServerInfo{FullMethod: gnmiDialOutTestMethod},
		func(any, grpc.ServerStream) error {
			handled = true
			return nil
		},
	)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.False(t, handled)

	require.NoError(t, security.StreamServerInterceptor()(
		nil,
		&gnmiDialOutTestServerStream{ctx: gnmiDialOutPeerContext(t.Context(), "192.0.2.11")},
		&grpc.StreamServerInfo{FullMethod: gnmiDialOutTestMethod},
		func(any, grpc.ServerStream) error { return nil },
	))

	close(release)
	require.NoError(t, <-result)
}

func TestGNMIDialOutSecurityReceiverClonesHostAndDelegatesLifecycle(t *testing.T) {
	security, err := newGNMIDialOutStreamSecurity(nil, yanggrpcreceiver.RateLimitingConfig{
		Enabled:           true,
		RequestsPerSecond: 10,
		BurstSize:         1,
		CleanupInterval:   time.Hour,
	}, zap.NewNop(), 10)
	require.NoError(t, err)
	middleware := &gnmiDialOutSecurityMiddleware{security: security}
	middlewareID := component.NewIDWithName(gnmiDialOutSecurityMiddlewareType, "test")
	delegateErr := errors.New("delegate shutdown failed")
	delegate := &gnmiDialOutLifecycleTestReceiver{shutdownErr: delegateErr}
	rcvr := wrapGNMIDialOutSecurityReceiver(delegate, middlewareID, middleware, nil).(*gnmiDialOutSecurityReceiver)

	existingID := component.MustNewIDWithName("testextension", "existing")
	existing := &gnmiDialOutNopComponent{}
	originalExtensions := map[component.ID]component.Component{existingID: existing}
	host := gnmiDialOutTestHost{extensions: originalExtensions}
	require.NoError(t, rcvr.Start(t.Context(), host))
	require.NotNil(t, delegate.startHost)
	proxiedExtensions := delegate.startHost.GetExtensions()
	assert.Same(t, existing, proxiedExtensions[existingID])
	assert.Same(t, middleware, proxiedExtensions[middlewareID])
	assert.NotContains(t, originalExtensions, middlewareID)
	delete(proxiedExtensions, existingID)
	assert.Contains(t, originalExtensions, existingID)

	shutdownCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	require.ErrorIs(t, rcvr.Shutdown(shutdownCtx), delegateErr)
	assert.Equal(t, int64(1), delegate.starts.Load())
	assert.Equal(t, int64(1), delegate.shutdowns.Load())
	select {
	case <-security.limiter.finished:
	default:
		t.Fatal("rate limiter cleanup did not stop")
	}
}

func TestGNMIDialOutSecurityReceiverBoundsNonCooperativeShutdown(t *testing.T) {
	security, err := newGNMIDialOutStreamSecurity(nil, yanggrpcreceiver.RateLimitingConfig{}, zap.NewNop(), 10)
	require.NoError(t, err)
	release := make(chan struct{})
	delegate := &gnmiDialOutLifecycleTestReceiver{shutdownRelease: release}
	rcvr := wrapGNMIDialOutSecurityReceiver(
		delegate,
		component.NewIDWithName(gnmiDialOutSecurityMiddlewareType, "shutdown"),
		&gnmiDialOutSecurityMiddleware{security: security},
		nil,
	).(*gnmiDialOutSecurityReceiver)
	require.NoError(t, rcvr.Start(t.Context(), componenttest.NewNopHost()))

	shutdownCtx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, rcvr.Shutdown(shutdownCtx), context.DeadlineExceeded)
	close(release)
	select {
	case <-rcvr.shutdownDone:
	case <-time.After(5 * time.Second):
		t.Fatal("delegate shutdown goroutine did not finish after release")
	}
}

func TestGNMIDialOutSecurityReceiverStopsAfterStartFailure(t *testing.T) {
	security, err := newGNMIDialOutStreamSecurity(nil, yanggrpcreceiver.RateLimitingConfig{
		Enabled:           true,
		RequestsPerSecond: 10,
		BurstSize:         1,
		CleanupInterval:   time.Hour,
	}, zap.NewNop(), 10)
	require.NoError(t, err)
	startErr := errors.New("delegate start failed")
	delegate := &gnmiDialOutLifecycleTestReceiver{startErr: startErr}
	rcvr := wrapGNMIDialOutSecurityReceiver(
		delegate,
		component.NewIDWithName(gnmiDialOutSecurityMiddlewareType, "start_failure"),
		&gnmiDialOutSecurityMiddleware{security: security},
		nil,
	).(*gnmiDialOutSecurityReceiver)

	require.ErrorIs(t, rcvr.Start(t.Context(), componenttest.NewNopHost()), startErr)
	assert.Equal(t, int64(1), delegate.shutdowns.Load())
	select {
	case <-security.limiter.finished:
	default:
		t.Fatal("rate limiter cleanup did not stop after failed start")
	}
}

func TestGNMIDialOutSecurityReceiverPreflightsModulePaths(t *testing.T) {
	t.Run("readable directory", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "test.yang")
		require.NoError(t, os.WriteFile(path, []byte("module test {}"), 0o600))
		require.NoError(t, preflightGNMIDialOutModulePaths([]string{directory}))
	})

	t.Run("empty file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.yang")
		require.NoError(t, os.WriteFile(path, nil, 0o600))
		require.ErrorContains(t, preflightGNMIDialOutModulePaths([]string{path}), "is empty")
	})

	t.Run("per-file and aggregate byte limits", func(t *testing.T) {
		directory := t.TempDir()
		first := filepath.Join(directory, "first.yang")
		second := filepath.Join(directory, "second.yang")
		require.NoError(t, os.WriteFile(first, []byte("12345"), 0o600))
		require.NoError(t, os.WriteFile(second, []byte("67890"), 0o600))
		require.ErrorContains(t, preflightGNMIDialOutModulePathsWithByteLimits([]string{directory}, 4, 100), "hard size limit")
		require.ErrorContains(t, preflightGNMIDialOutModulePathsWithByteLimits([]string{directory}, 10, 9), "aggregate size limit")
	})

	t.Run("missing path fails before delegate start", func(t *testing.T) {
		security, err := newGNMIDialOutStreamSecurity(nil, yanggrpcreceiver.RateLimitingConfig{}, zap.NewNop(), 10)
		require.NoError(t, err)
		delegate := &gnmiDialOutLifecycleTestReceiver{}
		rcvr := wrapGNMIDialOutSecurityReceiver(
			delegate,
			component.NewIDWithName(gnmiDialOutSecurityMiddlewareType, "module_preflight"),
			&gnmiDialOutSecurityMiddleware{security: security},
			[]string{filepath.Join(t.TempDir(), "missing")},
		).(*gnmiDialOutSecurityReceiver)

		err = rcvr.Start(t.Context(), componenttest.NewNopHost())
		require.ErrorContains(t, err, "module_paths[0]")
		assert.Zero(t, delegate.starts.Load())
	})
}

func TestGNMIDialOutFactoriesWirePrivateStreamSecurity(t *testing.T) {
	settings := receivertest.NewNopSettings(componentmetadata.Type)
	rateConfig := yanggrpcreceiver.RateLimitingConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		BurstSize:         10,
		CleanupInterval:   time.Minute,
	}

	catalystConfig := defaultCatalyst9800Config()
	catalystConfig.DialOut.Enabled = true
	catalystConfig.DialOut.NetAddr.Endpoint = "127.0.0.1:0"
	catalystConfig.DialOut.MaxConcurrentStreams = 1
	catalystConfig.DialOut.MaxStreamsPerClient = 0
	catalystConfig.DialOut.AllowedClients = []string{"127.0.0.1"}
	catalystConfig.DialOut.RateLimiting = rateConfig
	catalystReceiver, err := newCatalyst9800DialOutReceiver(settings, catalystConfig, deviceSelectionMatcher{}, consumertest.NewNop())
	if runtimeErr := requireHardenedYangGRPCRuntime(&yanggrpcreceiver.Config{}); runtimeErr != nil {
		require.ErrorContains(t, err, "required runtime hardening version 1")
		iosXRConfig := defaultIOSXRConfig()
		iosXRConfig.DialOut.Enabled = true
		_, iosXRErr := newIOSXRDialOutReceiver(settings, iosXRConfig, deviceSelectionMatcher{}, consumertest.NewNop())
		require.ErrorContains(t, iosXRErr, "required runtime hardening version 1")
		return
	}
	require.NoError(t, err)

	iosXRConfig := defaultIOSXRConfig()
	iosXRConfig.DialOut.Enabled = true
	iosXRConfig.DialOut.NetAddr.Endpoint = "127.0.0.1:0"
	iosXRConfig.DialOut.MaxConcurrentStreams = 1
	iosXRConfig.DialOut.MaxStreamsPerClient = 0
	iosXRConfig.DialOut.AllowedClients = []string{"127.0.0.1"}
	iosXRConfig.DialOut.RateLimiting = rateConfig
	iosXRReceiver, err := newIOSXRDialOutReceiver(settings, iosXRConfig, deviceSelectionMatcher{}, consumertest.NewNop())
	require.NoError(t, err)

	receivers := []receiver.Metrics{catalystReceiver, iosXRReceiver}
	require.IsType(t, &gnmiDialOutSecurityReceiver{}, receivers[0])
	require.IsType(t, &gnmiDialOutSecurityReceiver{}, receivers[1])
	first := receivers[0].(*gnmiDialOutSecurityReceiver)
	second := receivers[1].(*gnmiDialOutSecurityReceiver)
	assert.NotEqual(t, first.middlewareID, second.middlewareID)
	assert.Equal(t, gnmiDialOutSecurityMiddlewareType, first.middlewareID.Type())
	assert.Equal(t, gnmiDialOutSecurityMiddlewareType, second.middlewareID.Type())
	assert.Equal(t, 1, first.middleware.security.maxActiveStreamsPerPeer)
	assert.Equal(t, 1, second.middleware.security.maxActiveStreamsPerPeer)

	for _, rcvr := range receivers {
		require.NoError(t, rcvr.Start(t.Context(), componenttest.NewNopHost()))
		shutdownCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		require.NoError(t, rcvr.Shutdown(shutdownCtx))
		cancel()
	}
}

func TestConfigureGNMIDialOutSecurityPrependsUniqueMiddleware(t *testing.T) {
	server := defaultIOSXRConfig().DialOut.ServerConfig
	existingID := component.MustNewIDWithName("testmiddleware", "existing")
	server.Middlewares = []configmiddleware.Config{{ID: existingID}}
	original := append([]configmiddleware.Config(nil), server.Middlewares...)

	parentID := component.MustNewIDWithName("cisco_os", "test")
	firstID, first, err := configureGNMIDialOutSecurity(&server, nil, defaultGNMIDialOutStreamsPerIP, yanggrpcreceiver.RateLimitingConfig{}, zap.NewNop(), parentID, "first")
	require.NoError(t, err)
	secondServer := defaultIOSXRConfig().DialOut.ServerConfig
	secondID, second, err := configureGNMIDialOutSecurity(&secondServer, nil, defaultGNMIDialOutStreamsPerIP, yanggrpcreceiver.RateLimitingConfig{}, zap.NewNop(), parentID, "second")
	require.NoError(t, err)
	t.Cleanup(first.security.Shutdown)
	t.Cleanup(second.security.Shutdown)

	require.Len(t, server.Middlewares, 2)
	assert.Equal(t, firstID, server.Middlewares[0].ID)
	assert.Equal(t, existingID, server.Middlewares[1].ID)
	assert.Equal(t, []configmiddleware.Config{{ID: existingID}}, original)
	assert.NotEqual(t, firstID, secondID)
}

const gnmiDialOutTestMethod = "/mdt_dialout.gRPCMdtDialout/MdtDialout"

func gnmiDialOutPeerContext(ctx context.Context, ip string) context.Context {
	return peer.NewContext(ctx, &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 12345},
	})
}

type gnmiDialOutTestServerStream struct {
	ctx            context.Context
	recvResults    []error
	receiveStarted chan struct{}
	releaseReceive chan struct{}
	recvCount      atomic.Int64
	startOnce      sync.Once
}

func (*gnmiDialOutTestServerStream) SetHeader(grpcmetadata.MD) error  { return nil }
func (*gnmiDialOutTestServerStream) SendHeader(grpcmetadata.MD) error { return nil }
func (*gnmiDialOutTestServerStream) SetTrailer(grpcmetadata.MD)       {}
func (*gnmiDialOutTestServerStream) SendMsg(any) error                { return nil }

func (s *gnmiDialOutTestServerStream) Context() context.Context {
	return s.ctx
}

func (s *gnmiDialOutTestServerStream) RecvMsg(any) error {
	index := int(s.recvCount.Add(1)) - 1
	if s.receiveStarted != nil {
		s.startOnce.Do(func() { close(s.receiveStarted) })
	}
	if s.releaseReceive != nil {
		<-s.releaseReceive
	}
	if index < len(s.recvResults) {
		return s.recvResults[index]
	}
	return io.EOF
}

type gnmiDialOutTestHost struct {
	extensions map[component.ID]component.Component
}

func (h gnmiDialOutTestHost) GetExtensions() map[component.ID]component.Component {
	return h.extensions
}

type gnmiDialOutNopComponent struct{}

func (*gnmiDialOutNopComponent) Start(context.Context, component.Host) error { return nil }
func (*gnmiDialOutNopComponent) Shutdown(context.Context) error              { return nil }

type gnmiDialOutLifecycleTestReceiver struct {
	startErr        error
	shutdownErr     error
	shutdownRelease <-chan struct{}
	startHost       component.Host
	starts          atomic.Int64
	shutdowns       atomic.Int64
}

func (r *gnmiDialOutLifecycleTestReceiver) Start(_ context.Context, host component.Host) error {
	r.starts.Add(1)
	r.startHost = host
	return r.startErr
}

func (r *gnmiDialOutLifecycleTestReceiver) Shutdown(context.Context) error {
	r.shutdowns.Add(1)
	if r.shutdownRelease != nil {
		<-r.shutdownRelease
	}
	return r.shutdownErr
}
