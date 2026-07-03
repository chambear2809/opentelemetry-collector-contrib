// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/configmiddleware"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver"
)

const (
	maxGNMIDialOutRateLimiterPeers  = 100_000
	maxGNMIDialOutModulePaths       = 64
	maxGNMIDialOutModuleFiles       = 10_000
	maxGNMIDialOutModuleWalkEntries = 100_000
	maxGNMIDialOutModuleFileBytes   = 16 * 1024 * 1024
	maxGNMIDialOutModuleTotalBytes  = 128 * 1024 * 1024
	defaultGNMIDialOutStreamsPerIP  = 16
	gnmiDialOutStartCleanupTimeout  = 5 * time.Second
	minGNMIDialOutLimiterCleanup    = time.Second
	maxGNMIDialOutLimiterIdleTTL    = time.Duration(1<<63 - 1)
	minimumYangGRPCRuntimeHardening = 2
)

var gnmiDialOutSecurityMiddlewareType = component.MustNewType("ciscoos_internal")

type yangGRPCRuntimeHardening interface {
	RuntimeHardeningVersion() int
}

type yangGRPCStreamAdmissionConfig interface {
	SetMaxConcurrentStreamsPerClient(uint32)
}

func requireHardenedYangGRPCRuntime(config any) error {
	hardened, ok := config.(yangGRPCRuntimeHardening)
	if !ok || hardened.RuntimeHardeningVersion() < minimumYangGRPCRuntimeHardening {
		return fmt.Errorf(
			"yanggrpcreceiver dependency does not provide required runtime hardening version %d; dial-out is disabled",
			minimumYangGRPCRuntimeHardening,
		)
	}
	return nil
}

func hardenedYangGRPCConfig(config any) (*yanggrpcreceiver.Config, error) {
	if err := requireHardenedYangGRPCRuntime(config); err != nil {
		return nil, err
	}
	yangConfig, ok := config.(*yanggrpcreceiver.Config)
	if !ok || yangConfig == nil {
		return nil, fmt.Errorf("yanggrpcreceiver returned unexpected hardened config type %T", config)
	}
	return yangConfig, nil
}

func configureHardenedYangGRPCStreamAdmission(config any, maxStreamsPerClient uint32) error {
	streamAdmission, ok := config.(yangGRPCStreamAdmissionConfig)
	if !ok {
		return errors.New("yanggrpcreceiver dependency does not expose required global stream-admission configuration")
	}
	streamAdmission.SetMaxConcurrentStreamsPerClient(maxStreamsPerClient)
	return nil
}

// configureHardenedYangGRPCSecurity mirrors the public dial-out controls into
// the delegated receiver as well as the receiver-private middleware. The YANG
// receiver validates and enforces its own remote-listener contract at Start;
// leaving this zeroed would make every otherwise-secure non-loopback Cisco
// listener fail closed during lifecycle startup.
func configureHardenedYangGRPCSecurity(
	config *yanggrpcreceiver.Config,
	allowedClients []string,
	rateLimiting yanggrpcreceiver.RateLimitingConfig,
) {
	config.Security.AllowedClients = append([]string(nil), allowedClients...)
	config.Security.RateLimiting = rateLimiting
}

// gnmiDialOutSecurityReceiver supplies receiver-private gRPC middleware to the
// delegated YANG receiver without changing the collector's global extension map.
type gnmiDialOutSecurityReceiver struct {
	delegate     receiver.Metrics
	middlewareID component.ID
	middleware   *gnmiDialOutSecurityMiddleware
	modulePaths  []string

	shutdownOnce sync.Once
	shutdownDone chan struct{}
	shutdownErr  error
}

func (r *gnmiDialOutSecurityReceiver) Start(ctx context.Context, host component.Host) error {
	if err := preflightGNMIDialOutModulePaths(r.modulePaths); err != nil {
		r.middleware.security.Shutdown()
		return err
	}
	extensions := map[component.ID]component.Component{}
	if host != nil {
		extensions = maps.Clone(host.GetExtensions())
		if extensions == nil {
			extensions = map[component.ID]component.Component{}
		}
	}
	if _, exists := extensions[r.middlewareID]; exists {
		r.middleware.security.Shutdown()
		return fmt.Errorf("private gNMI dial-out middleware ID %q collides with a configured extension", r.middlewareID)
	}
	extensions[r.middlewareID] = r.middleware
	r.middleware.security.Start()
	if err := r.delegate.Start(ctx, gnmiDialOutHost{extensions: extensions}); err != nil {
		r.middleware.security.Shutdown()
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), gnmiDialOutStartCleanupTimeout)
		defer cancel()
		r.beginDelegateShutdown(cleanupCtx)
		select {
		case <-r.shutdownDone:
			return errors.Join(err, r.shutdownErr)
		case <-cleanupCtx.Done():
			return errors.Join(err, fmt.Errorf("timed out cleaning up failed gNMI dial-out start: %w", cleanupCtx.Err()))
		}
	}
	return nil
}

func (r *gnmiDialOutSecurityReceiver) Shutdown(ctx context.Context) error {
	// Mark the middleware as shutting down before asking the delegated receiver
	// to GracefulStop. New streams are rejected and active RecvMsg calls are
	// released through their cancellation-aware stream wrappers.
	r.middleware.security.Shutdown()
	r.beginDelegateShutdown(ctx)
	select {
	case <-r.shutdownDone:
		return r.shutdownErr
	case <-ctx.Done():
		// Contract v1 requires deadline-aware shutdown. Keep the wrapper bounded
		// as a final defense if a future delegate violates that contract.
		return ctx.Err()
	}
}

func (r *gnmiDialOutSecurityReceiver) beginDelegateShutdown(ctx context.Context) {
	r.shutdownOnce.Do(func() {
		go func() {
			r.shutdownErr = r.delegate.Shutdown(ctx)
			close(r.shutdownDone)
		}()
	})
}

type gnmiDialOutHost struct {
	extensions map[component.ID]component.Component
}

func (h gnmiDialOutHost) GetExtensions() map[component.ID]component.Component {
	return h.extensions
}

// gnmiDialOutSecurityMiddleware is an in-process middleware extension. Its
// component lifecycle is owned by gnmiDialOutSecurityReceiver.
type gnmiDialOutSecurityMiddleware struct {
	security *gnmiDialOutStreamSecurity
}

func (*gnmiDialOutSecurityMiddleware) Start(context.Context, component.Host) error { return nil }
func (*gnmiDialOutSecurityMiddleware) Shutdown(context.Context) error              { return nil }

func (m *gnmiDialOutSecurityMiddleware) GetGRPCServerOptions(context.Context) ([]grpc.ServerOption, error) {
	return []grpc.ServerOption{grpc.ChainStreamInterceptor(m.security.StreamServerInterceptor())}, nil
}

func configureGNMIDialOutSecurity(
	server *configgrpc.ServerConfig,
	allowedClients []string,
	maxStreamsPerClient uint32,
	rateLimiting yanggrpcreceiver.RateLimitingConfig,
	identityVerification string,
	identityBindings []GNMIDialOutIdentityBindingConfig,
	logger *zap.Logger,
	parentID component.ID,
	owner string,
) (component.ID, *gnmiDialOutSecurityMiddleware, error) {
	identity, err := compileGNMIDialOutIdentityVerifier(identityVerification, identityBindings)
	if err != nil {
		return component.ID{}, nil, err
	}
	identityTransportSupported := gnmiDialOutIdentitySupportsTransport(string(server.NetAddr.Transport))
	if identity != nil && !identityTransportSupported {
		return component.ID{}, nil, errors.New("identity_verification: required requires tcp, tcp4, or tcp6 transport")
	}
	if gnmiDialOutEndpointRequiresIdentity(server.NetAddr.Endpoint) && identity == nil {
		return component.ID{}, nil, errors.New("non-loopback listeners require identity_verification: required with valid identity_bindings")
	}
	name := "gnmi_dialout_security_" + parentID.Type().String()
	if parentID.Name() != "" {
		name += "_" + parentID.Name()
	}
	name += "_" + owner
	middlewareID := component.NewIDWithName(
		gnmiDialOutSecurityMiddlewareType,
		name,
	)
	for index, configured := range server.Middlewares {
		if configured.ID == middlewareID {
			return component.ID{}, nil, fmt.Errorf(
				"middlewares[%d] duplicates receiver-private gNMI dial-out middleware ID %q",
				index,
				middlewareID,
			)
		}
	}
	security, err := newGNMIDialOutStreamSecurity(allowedClients, rateLimiting, logger, maxGNMIDialOutRateLimiterPeers)
	if err != nil {
		return component.ID{}, nil, err
	}
	security.identity = identity
	if server.MaxConcurrentStreams > 0 {
		security.maxActiveStreams = int(server.MaxConcurrentStreams)
	}
	if maxStreamsPerClient > 0 {
		security.maxActiveStreamsPerPeer = int(maxStreamsPerClient)
	}
	middlewares := make([]configmiddleware.Config, 1, len(server.Middlewares)+1)
	middlewares[0] = configmiddleware.Config{ID: middlewareID}
	server.Middlewares = append(middlewares, server.Middlewares...)
	return middlewareID, &gnmiDialOutSecurityMiddleware{security: security}, nil
}

func wrapGNMIDialOutSecurityReceiver(
	delegate receiver.Metrics,
	middlewareID component.ID,
	middleware *gnmiDialOutSecurityMiddleware,
	modulePaths []string,
) receiver.Metrics {
	return &gnmiDialOutSecurityReceiver{
		delegate:     delegate,
		middlewareID: middlewareID,
		middleware:   middleware,
		modulePaths:  modulePaths,
		shutdownDone: make(chan struct{}),
	}
}

type gnmiDialOutStreamSecurity struct {
	allowed  []netip.Prefix
	limiter  *gnmiDialOutPeerRateLimiter
	identity *gnmiDialOutIdentityVerifier
	logger   *zap.Logger

	activeMu                sync.Mutex
	active                  map[uint64]gnmiDialOutActiveStream
	activePerPeer           map[string]int
	nextStreamID            uint64
	shuttingDown            bool
	maxActiveStreams        int
	maxActiveStreamsPerPeer int
}

type gnmiDialOutActiveStream struct {
	cancel context.CancelFunc
	peerID string
}

func newGNMIDialOutStreamSecurity(
	allowedClients []string,
	rateLimiting yanggrpcreceiver.RateLimitingConfig,
	logger *zap.Logger,
	maxPeers int,
) (*gnmiDialOutStreamSecurity, error) {
	allowed := make([]netip.Prefix, 0, len(allowedClients))
	for index, value := range allowedClients {
		prefix, err := parseGNMIDialOutAllowedClient(value)
		if err != nil {
			return nil, fmt.Errorf("allowed_clients[%d]: %w", index, err)
		}
		allowed = append(allowed, prefix)
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	security := &gnmiDialOutStreamSecurity{
		allowed:                 allowed,
		logger:                  logger,
		active:                  make(map[uint64]gnmiDialOutActiveStream),
		activePerPeer:           make(map[string]int),
		maxActiveStreams:        maximumGNMIDialOutStreams,
		maxActiveStreamsPerPeer: defaultGNMIDialOutStreamsPerIP,
	}
	if !rateLimiting.Enabled {
		return security, nil
	}
	if rateLimiting.RequestsPerSecond <= 0 || math.IsNaN(rateLimiting.RequestsPerSecond) || math.IsInf(rateLimiting.RequestsPerSecond, 0) {
		return nil, errors.New("requests_per_second must be positive and finite")
	}
	if rateLimiting.BurstSize <= 0 {
		return nil, errors.New("burst_size must be positive")
	}
	if rateLimiting.CleanupInterval < minGNMIDialOutLimiterCleanup {
		return nil, fmt.Errorf("cleanup_interval must be at least %s", minGNMIDialOutLimiterCleanup)
	}
	security.limiter = newGNMIDialOutPeerRateLimiter(
		rate.Limit(rateLimiting.RequestsPerSecond),
		rateLimiting.BurstSize,
		rateLimiting.CleanupInterval,
		maxPeers,
	)
	return security, nil
}

func parseGNMIDialOutAllowedClient(value string) (netip.Prefix, error) {
	if address, err := netip.ParseAddr(value); err == nil {
		if address.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("scoped IPv6 zones are not supported: %q", value)
		}
		address = address.Unmap()
		if address.IsMulticast() {
			return netip.Prefix{}, fmt.Errorf("source selectors must use global-unicast or loopback addresses: %q", value)
		}
		if address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
			return netip.Prefix{}, fmt.Errorf("link-local source selectors are not supported: %q", value)
		}
		if !gnmiDialOutUsablePeerAddress(address) {
			return netip.Prefix{}, fmt.Errorf("source selectors must use global-unicast or loopback addresses: %q", value)
		}
		return netip.PrefixFrom(address, address.BitLen()), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("must be an IP address or CIDR: %q", value)
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("IPv4-mapped CIDR must have at least 96 prefix bits: %q", value)
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	prefix = prefix.Masked()
	if prefix.Addr().IsMulticast() {
		return netip.Prefix{}, fmt.Errorf("source selectors must use global-unicast or loopback addresses: %q", value)
	}
	if prefix.Addr().IsLinkLocalUnicast() || prefix.Addr().IsLinkLocalMulticast() {
		return netip.Prefix{}, fmt.Errorf("link-local source selectors are not supported: %q", value)
	}
	if !gnmiDialOutUsablePeerAddress(prefix.Addr()) {
		return netip.Prefix{}, fmt.Errorf("source selectors must use global-unicast or loopback addresses: %q", value)
	}
	return prefix, nil
}

func gnmiDialOutUsablePeerAddress(address netip.Addr) bool {
	return address.IsLoopback() || address.IsGlobalUnicast()
}

func (s *gnmiDialOutStreamSecurity) Start() {
	if s.limiter != nil {
		s.limiter.Start()
	}
}

func (s *gnmiDialOutStreamSecurity) Shutdown() {
	s.cancelActiveStreams()
	if s.limiter != nil {
		s.limiter.Stop()
	}
}

func (s *gnmiDialOutStreamSecurity) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(service any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		peerIP, err := s.authorizePeer(stream.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		var allowedNodeIDs map[string]struct{}
		if s.identity != nil {
			var matched bool
			allowedNodeIDs, matched = s.identity.nodeIDsForPeer(peerIP)
			if !matched {
				s.logger.Warn("gNMI dial-out client has no identity binding", zap.String("client_ip", peerIP.String()), zap.String("method", info.FullMethod))
				return status.Error(codes.PermissionDenied, "client has no dial-out identity binding")
			}
		}
		peerID := "unknown"
		if peerIP.IsValid() {
			peerID = peerIP.String()
		}
		streamContext, cancel := context.WithCancel(stream.Context())
		streamID, rejectionCode := s.registerStream(peerID, cancel)
		if rejectionCode != codes.OK {
			cancel()
			if rejectionCode == codes.Unavailable {
				return status.Error(rejectionCode, "receiver is shutting down")
			}
			return status.Error(rejectionCode, "too many active dial-out streams")
		}
		defer func() {
			s.unregisterStream(streamID)
			cancel()
		}()
		managedStream := newGNMIDialOutManagedServerStream(streamContext, stream)
		stream = managedStream
		if s.limiter != nil {
			stream = &gnmiDialOutRateLimitedServerStream{
				ServerStream: stream,
				limiter:      s.limiter,
				logger:       s.logger,
				peer:         peerIP.String(),
				method:       info.FullMethod,
			}
		}
		if s.identity != nil {
			stream = &gnmiDialOutIdentityServerStream{
				ServerStream:   stream,
				allowedNodeIDs: allowedNodeIDs,
			}
		}
		return handler(service, stream)
	}
}

func (s *gnmiDialOutStreamSecurity) registerStream(peerID string, cancel context.CancelFunc) (uint64, codes.Code) {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if s.shuttingDown {
		return 0, codes.Unavailable
	}
	if len(s.active) >= s.maxActiveStreams {
		return 0, codes.ResourceExhausted
	}
	if s.activePerPeer[peerID] >= s.maxActiveStreamsPerPeer {
		return 0, codes.ResourceExhausted
	}
	s.nextStreamID++
	s.active[s.nextStreamID] = gnmiDialOutActiveStream{cancel: cancel, peerID: peerID}
	s.activePerPeer[peerID]++
	return s.nextStreamID, codes.OK
}

func (s *gnmiDialOutStreamSecurity) unregisterStream(streamID uint64) {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	active, exists := s.active[streamID]
	if !exists {
		return
	}
	delete(s.active, streamID)
	if s.activePerPeer[active.peerID] <= 1 {
		delete(s.activePerPeer, active.peerID)
	} else {
		s.activePerPeer[active.peerID]--
	}
}

func (s *gnmiDialOutStreamSecurity) cancelActiveStreams() {
	s.activeMu.Lock()
	if s.shuttingDown {
		s.activeMu.Unlock()
		return
	}
	s.shuttingDown = true
	cancellations := make([]context.CancelFunc, 0, len(s.active))
	for _, active := range s.active {
		cancellations = append(cancellations, active.cancel)
	}
	s.activeMu.Unlock()
	for _, cancel := range cancellations {
		cancel()
	}
}

func (s *gnmiDialOutStreamSecurity) authorizePeer(ctx context.Context, method string) (netip.Addr, error) {
	peerIP, err := gnmiDialOutPeerIP(ctx)
	if len(s.allowed) == 0 && s.limiter == nil && s.identity == nil {
		if err != nil {
			return netip.Addr{}, nil
		}
		return peerIP, nil
	}
	if err != nil {
		s.logger.Warn("Unable to identify gNMI dial-out client", zap.String("method", method), zap.Error(err))
		return netip.Addr{}, status.Error(codes.Unauthenticated, "unable to identify client")
	}
	if len(s.allowed) > 0 && !s.isAllowed(peerIP) {
		s.logger.Warn("gNMI dial-out client is not in allowed_clients", zap.String("client_ip", peerIP.String()), zap.String("method", method))
		return netip.Addr{}, status.Error(codes.PermissionDenied, "client IP not allowed")
	}
	return peerIP, nil
}

func (s *gnmiDialOutStreamSecurity) isAllowed(peerIP netip.Addr) bool {
	peerIP = peerIP.Unmap()
	for _, prefix := range s.allowed {
		if prefix.Contains(peerIP) {
			return true
		}
	}
	return false
}

func gnmiDialOutPeerIP(ctx context.Context) (netip.Addr, error) {
	remote, ok := peer.FromContext(ctx)
	if !ok || remote.Addr == nil {
		return netip.Addr{}, errors.New("peer address is unavailable")
	}
	if !gnmiDialOutIdentitySupportsTransport(remote.Addr.Network()) {
		return netip.Addr{}, fmt.Errorf("unsupported peer network %q", remote.Addr.Network())
	}
	if tcpAddress, ok := remote.Addr.(*net.TCPAddr); ok {
		if tcpAddress.Zone != "" {
			return netip.Addr{}, fmt.Errorf("scoped TCP peer addresses are not supported: %q", tcpAddress)
		}
		address, valid := netip.AddrFromSlice(tcpAddress.IP)
		if !valid {
			return netip.Addr{}, fmt.Errorf("invalid TCP peer address %q", tcpAddress.IP)
		}
		address = address.Unmap()
		if address.IsMulticast() {
			return netip.Addr{}, fmt.Errorf("TCP peer address must be global-unicast or loopback: %q", tcpAddress)
		}
		if address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
			return netip.Addr{}, fmt.Errorf("link-local TCP peer addresses are not supported: %q", tcpAddress)
		}
		if !gnmiDialOutUsablePeerAddress(address) {
			return netip.Addr{}, fmt.Errorf("TCP peer address must be global-unicast or loopback: %q", tcpAddress)
		}
		return address, nil
	}
	host, _, err := net.SplitHostPort(remote.Addr.String())
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse peer address: %w", err)
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse peer IP: %w", err)
	}
	if address.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("scoped TCP peer addresses are not supported: %q", host)
	}
	address = address.Unmap()
	if address.IsMulticast() {
		return netip.Addr{}, fmt.Errorf("TCP peer address must be global-unicast or loopback: %q", host)
	}
	if address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return netip.Addr{}, fmt.Errorf("link-local TCP peer addresses are not supported: %q", host)
	}
	if !gnmiDialOutUsablePeerAddress(address) {
		return netip.Addr{}, fmt.Errorf("TCP peer address must be global-unicast or loopback: %q", host)
	}
	return address, nil
}

type gnmiDialOutRateLimitedServerStream struct {
	grpc.ServerStream
	limiter *gnmiDialOutPeerRateLimiter
	logger  *zap.Logger
	peer    string
	method  string
}

type gnmiDialOutRecvRequest struct {
	message any
	result  chan error
}

// gnmiDialOutManagedServerStream makes a blocked RecvMsg responsive to the
// receiver-private cancellation context. The single worker preserves gRPC's
// one-reader rule. If shutdown wins while the worker is inside the underlying
// RecvMsg, returning from the handler causes grpc-go to cancel the transport
// stream and release that worker.
type gnmiDialOutManagedServerStream struct {
	grpc.ServerStream
	ctx     context.Context
	receive chan gnmiDialOutRecvRequest
	done    chan struct{}
}

func newGNMIDialOutManagedServerStream(ctx context.Context, stream grpc.ServerStream) *gnmiDialOutManagedServerStream {
	managed := &gnmiDialOutManagedServerStream{
		ServerStream: stream,
		ctx:          ctx,
		receive:      make(chan gnmiDialOutRecvRequest),
		done:         make(chan struct{}),
	}
	go managed.receiveLoop()
	return managed
}

func (s *gnmiDialOutManagedServerStream) Context() context.Context {
	return s.ctx
}

func (s *gnmiDialOutManagedServerStream) RecvMsg(message any) error {
	request := gnmiDialOutRecvRequest{message: message, result: make(chan error, 1)}
	select {
	case s.receive <- request:
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
	select {
	case err := <-request.result:
		return err
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func (s *gnmiDialOutManagedServerStream) receiveLoop() {
	defer close(s.done)
	for {
		select {
		case request := <-s.receive:
			err := s.ServerStream.RecvMsg(request.message)
			request.result <- err
			if err != nil {
				return
			}
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *gnmiDialOutRateLimitedServerStream) RecvMsg(message any) error {
	if err := s.ServerStream.RecvMsg(message); err != nil {
		return err
	}
	if !s.limiter.Allow(s.peer) {
		s.logger.Warn("gNMI dial-out per-message rate limit exceeded", zap.String("client_ip", s.peer), zap.String("method", s.method))
		return status.Error(codes.ResourceExhausted, "rate limit exceeded")
	}
	return nil
}

type gnmiDialOutPeerRateLimiter struct {
	mu              sync.Mutex
	peers           map[string]*gnmiDialOutPeerRateLimiterEntry
	requestsPerSec  rate.Limit
	burstSize       int
	cleanupInterval time.Duration
	idleTTL         time.Duration
	maxPeers        int

	lifecycleMu sync.Mutex
	started     bool
	stopped     bool
	done        chan struct{}
	finished    chan struct{}
}

type gnmiDialOutPeerRateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newGNMIDialOutPeerRateLimiter(requestsPerSec rate.Limit, burstSize int, cleanupInterval time.Duration, maxPeers int) *gnmiDialOutPeerRateLimiter {
	if maxPeers <= 0 {
		maxPeers = maxGNMIDialOutRateLimiterPeers
	}
	if cleanupInterval < minGNMIDialOutLimiterCleanup {
		cleanupInterval = minGNMIDialOutLimiterCleanup
	}
	return &gnmiDialOutPeerRateLimiter{
		peers:           make(map[string]*gnmiDialOutPeerRateLimiterEntry),
		requestsPerSec:  requestsPerSec,
		burstSize:       burstSize,
		cleanupInterval: cleanupInterval,
		idleTTL:         gnmiDialOutRateLimiterIdleTTL(requestsPerSec, burstSize, cleanupInterval),
		maxPeers:        maxPeers,
		done:            make(chan struct{}),
		finished:        make(chan struct{}),
	}
}

func (l *gnmiDialOutPeerRateLimiter) Start() {
	l.lifecycleMu.Lock()
	defer l.lifecycleMu.Unlock()
	if l.started || l.stopped {
		return
	}
	l.started = true
	go l.cleanup()
}

func (l *gnmiDialOutPeerRateLimiter) Stop() {
	l.lifecycleMu.Lock()
	if l.stopped {
		finished := l.finished
		l.lifecycleMu.Unlock()
		<-finished
		return
	}
	l.stopped = true
	if !l.started {
		close(l.finished)
		l.lifecycleMu.Unlock()
		return
	}
	close(l.done)
	finished := l.finished
	l.lifecycleMu.Unlock()
	<-finished
}

func (l *gnmiDialOutPeerRateLimiter) Allow(peerID string) bool {
	return l.allowAt(peerID, time.Now())
}

func (l *gnmiDialOutPeerRateLimiter) allowAt(peerID string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, exists := l.peers[peerID]
	if !exists {
		if len(l.peers) >= l.maxPeers {
			return false
		}
		entry = &gnmiDialOutPeerRateLimiterEntry{
			limiter: rate.NewLimiter(l.requestsPerSec, l.burstSize),
		}
		l.peers[peerID] = entry
	}
	entry.lastSeen = now
	return entry.limiter.AllowN(now, 1)
}

func (l *gnmiDialOutPeerRateLimiter) cleanup() {
	ticker := time.NewTicker(l.cleanupInterval)
	defer func() {
		ticker.Stop()
		close(l.finished)
	}()
	for {
		select {
		case now := <-ticker.C:
			l.cleanupStale(now)
		case <-l.done:
			return
		}
	}
}

func (l *gnmiDialOutPeerRateLimiter) cleanupStale(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for peerID, entry := range l.peers {
		if now.Sub(entry.lastSeen) >= l.idleTTL {
			delete(l.peers, peerID)
		}
	}
}

func gnmiDialOutRateLimiterIdleTTL(requestsPerSec rate.Limit, burstSize int, cleanupInterval time.Duration) time.Duration {
	if requestsPerSec <= 0 || math.IsNaN(float64(requestsPerSec)) || burstSize <= 0 {
		return maxGNMIDialOutLimiterIdleTTL
	}
	refillNanos := math.Ceil(float64(burstSize) / float64(requestsPerSec) * float64(time.Second))
	if math.IsInf(refillNanos, 1) || refillNanos >= float64(maxGNMIDialOutLimiterIdleTTL) {
		return maxGNMIDialOutLimiterIdleTTL
	}
	refillDuration := time.Duration(refillNanos)
	if refillDuration > cleanupInterval {
		return refillDuration
	}
	return cleanupInterval
}

func (l *gnmiDialOutPeerRateLimiter) peerCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.peers)
}

func preflightGNMIDialOutModulePaths(modulePaths []string) error {
	return preflightGNMIDialOutModulePathsWithByteLimits(
		modulePaths,
		maxGNMIDialOutModuleFileBytes,
		maxGNMIDialOutModuleTotalBytes,
	)
}

func preflightGNMIDialOutModulePathsWithByteLimits(modulePaths []string, maxFileBytes, maxTotalBytes int64) error {
	if len(modulePaths) > maxGNMIDialOutModulePaths {
		return fmt.Errorf("gNMI dial-out YANG module_paths exceeds hard limit of %d", maxGNMIDialOutModulePaths)
	}
	totalFiles := 0
	totalEntries := 0
	var totalBytes int64
	for index, modulePath := range modulePaths {
		info, err := os.Stat(modulePath)
		if err != nil {
			return fmt.Errorf("gNMI dial-out YANG module_paths[%d] %q: %w", index, modulePath, err)
		}
		if !info.IsDir() {
			if !info.Mode().IsRegular() || filepath.Ext(modulePath) != ".yang" {
				return fmt.Errorf("gNMI dial-out YANG module_paths[%d] %q must be a .yang file or directory", index, modulePath)
			}
			if readabilityErr := preflightReadableYANGFile(modulePath, maxFileBytes, maxTotalBytes, &totalBytes); readabilityErr != nil {
				return fmt.Errorf("gNMI dial-out YANG module_paths[%d]: %w", index, readabilityErr)
			}
			totalFiles++
			continue
		}

		pathFiles := 0
		err = filepath.WalkDir(modulePath, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			totalEntries++
			if totalEntries > maxGNMIDialOutModuleWalkEntries {
				return fmt.Errorf("walk exceeds hard entry limit of %d", maxGNMIDialOutModuleWalkEntries)
			}
			if entry.IsDir() || filepath.Ext(path) != ".yang" {
				return nil
			}
			totalFiles++
			pathFiles++
			if totalFiles > maxGNMIDialOutModuleFiles {
				return fmt.Errorf("walk exceeds hard .yang file limit of %d", maxGNMIDialOutModuleFiles)
			}
			return preflightReadableYANGFile(path, maxFileBytes, maxTotalBytes, &totalBytes)
		})
		if err != nil {
			return fmt.Errorf("gNMI dial-out YANG module_paths[%d] %q: %w", index, modulePath, err)
		}
		if pathFiles == 0 {
			return fmt.Errorf("gNMI dial-out YANG module_paths[%d] %q contains no readable .yang files", index, modulePath)
		}
	}
	return nil
}

func preflightReadableYANGFile(path string, maxFileBytes, maxTotalBytes int64, totalBytes *int64) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat YANG file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("YANG file %q is not a regular file", path)
	}
	if info.Size() == 0 {
		return fmt.Errorf("YANG file %q is empty", path)
	}
	if maxFileBytes > 0 && info.Size() > maxFileBytes {
		return fmt.Errorf("YANG file %q exceeds hard size limit of %d bytes", path, maxFileBytes)
	}
	if maxTotalBytes > 0 && (*totalBytes > maxTotalBytes-info.Size()) {
		return fmt.Errorf("YANG modules exceed hard aggregate size limit of %d bytes", maxTotalBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open YANG file %q: %w", path, err)
	}
	var probe [1]byte
	_, readErr := file.Read(probe[:])
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return fmt.Errorf("read YANG file %q: %w", path, readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close YANG file %q: %w", path, closeErr)
	}
	*totalBytes += info.Size()
	return nil
}
