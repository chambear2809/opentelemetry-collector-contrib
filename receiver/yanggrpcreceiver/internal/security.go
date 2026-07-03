// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package internal // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver/internal"

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// SecurityManager manages security features for the gRPC receiver
type SecurityManager struct {
	allowedClients []string
	rateLimiter    *RateLimiter
	logger         *zap.Logger
}

// RateLimiter implements per-client rate limiting
type RateLimiter struct {
	limiters        map[string]*rateLimiterEntry
	mu              sync.Mutex
	requestsPerSec  rate.Limit
	burstSize       int
	cleanupInterval time.Duration
	idleTTL         time.Duration
	cleanupTicker   *time.Ticker
	done            chan struct{}
	stopped         chan struct{}
	stopOnce        sync.Once
}

type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

const (
	defaultRateLimiterCleanupInterval = time.Minute
	minimumRateLimiterCleanupInterval = time.Second
	maxRateLimiterClients             = 100_000
	maxRateLimiterIdleTTL             = time.Duration(1<<63 - 1)
)

// NewSecurityManager creates a new SecurityManager
func NewSecurityManager(allowedClients []string, logger *zap.Logger, ratelimitingEnabled bool, requestsPerSecond float64, burstSize int, cleanupInterval time.Duration) *SecurityManager {
	sm := &SecurityManager{
		allowedClients: allowedClients,
		logger:         logger,
	}

	// Initialize rate limiter if enabled
	if ratelimitingEnabled {
		sm.rateLimiter = newRateLimiter(
			rate.Limit(requestsPerSecond),
			burstSize,
			cleanupInterval,
		)
	}

	return sm
}

// newRateLimiter creates a new RateLimiter
func newRateLimiter(requestsPerSec rate.Limit, burstSize int, cleanupInterval time.Duration) *RateLimiter {
	// Configuration validation rejects non-positive intervals. Keep the
	// constructor defensive as it is also used directly by tests and internal
	// callers: time.NewTicker panics for a non-positive duration.
	if cleanupInterval < minimumRateLimiterCleanupInterval {
		cleanupInterval = defaultRateLimiterCleanupInterval
	}
	rl := &RateLimiter{
		limiters:        make(map[string]*rateLimiterEntry),
		requestsPerSec:  requestsPerSec,
		burstSize:       burstSize,
		cleanupInterval: cleanupInterval,
		idleTTL:         rateLimiterIdleTTL(requestsPerSec, burstSize, cleanupInterval),
		done:            make(chan struct{}),
		stopped:         make(chan struct{}),
	}

	// Start cleanup goroutine
	rl.cleanupTicker = time.NewTicker(cleanupInterval)
	go rl.cleanup()

	return rl
}

// Allow checks if the request from the given IP is allowed
func (rl *RateLimiter) Allow(ip string) bool {
	return rl.allowAt(ip, time.Now())
}

func (rl *RateLimiter) allowAt(ip string, now time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, exists := rl.limiters[ip]
	if !exists {
		// Refuse new identities after the hard ceiling instead of allowing a
		// source-IP flood to grow collector state without bound.
		if len(rl.limiters) >= maxRateLimiterClients {
			return false
		}
		entry = &rateLimiterEntry{limiter: rate.NewLimiter(rl.requestsPerSec, rl.burstSize)}
		rl.limiters[ip] = entry
	}
	entry.lastSeen = now
	return entry.limiter.AllowN(now, 1)
}

// cleanup removes unused rate limiters
func (rl *RateLimiter) cleanup() {
	defer close(rl.stopped)
	for {
		select {
		case now := <-rl.cleanupTicker.C:
			rl.cleanupStale(now)
		case <-rl.done:
			rl.cleanupTicker.Stop()
			return
		}
	}
}

func (rl *RateLimiter) cleanupStale(now time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for ip, entry := range rl.limiters {
		if now.Sub(entry.lastSeen) >= rl.idleTTL {
			delete(rl.limiters, ip)
		}
	}
}

func (rl *RateLimiter) clientCount() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.limiters)
}

func rateLimiterIdleTTL(requestsPerSec rate.Limit, burstSize int, cleanupInterval time.Duration) time.Duration {
	if requestsPerSec <= 0 || math.IsNaN(float64(requestsPerSec)) || burstSize <= 0 {
		return maxRateLimiterIdleTTL
	}
	refillNanos := math.Ceil(float64(burstSize) / float64(requestsPerSec) * float64(time.Second))
	if math.IsInf(refillNanos, 1) || refillNanos >= float64(maxRateLimiterIdleTTL) {
		return maxRateLimiterIdleTTL
	}
	refillDuration := time.Duration(refillNanos)
	if refillDuration > cleanupInterval {
		return refillDuration
	}
	return cleanupInterval
}

// Stop stops the rate limiter cleanup
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		close(rl.done)
		<-rl.stopped
	})
}

// getClientAuthType converts string auth type to tls.ClientAuthType
func (*SecurityManager) getClientAuthType(authType string) (tls.ClientAuthType, error) {
	authTypeMap := map[string]tls.ClientAuthType{
		"NoClientCert":               tls.NoClientCert,
		"RequestClientCert":          tls.RequestClientCert,
		"RequireAnyClientCert":       tls.RequireAnyClientCert,
		"VerifyClientCertIfGiven":    tls.VerifyClientCertIfGiven,
		"RequireAndVerifyClientCert": tls.RequireAndVerifyClientCert,
	}

	if authType, exists := authTypeMap[authType]; exists {
		return authType, nil
	}

	return tls.NoClientCert, fmt.Errorf("invalid client auth type: %s", authType)
}

// CreateSecurityInterceptor creates a unary gRPC interceptor for security enforcement.
func (sm *SecurityManager) CreateSecurityInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		clientIP, err := sm.authorizePeer(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		if err := sm.authorizeRate(clientIP, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// CreateStreamSecurityInterceptor creates a streaming gRPC interceptor for security enforcement.
func (sm *SecurityManager) CreateStreamSecurityInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		clientIP, err := sm.authorizePeer(stream.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		if sm.rateLimiter != nil {
			stream = &rateLimitedServerStream{
				ServerStream: stream,
				manager:      sm,
				clientIP:     clientIP,
				method:       info.FullMethod,
			}
		}
		return handler(srv, stream)
	}
}

// rateLimitedServerStream applies the configured token bucket to every
// successfully received stream message. Limiting only stream establishment
// leaves a long-lived MDT stream free to send an unlimited number of payloads.
type rateLimitedServerStream struct {
	grpc.ServerStream
	manager  *SecurityManager
	clientIP string
	method   string
}

func (s *rateLimitedServerStream) RecvMsg(message any) error {
	if err := s.ServerStream.RecvMsg(message); err != nil {
		return err
	}
	return s.manager.authorizeRate(s.clientIP, s.method)
}

func (sm *SecurityManager) authorizePeer(ctx context.Context, method string) (string, error) {
	clientIP, err := sm.getClientIP(ctx)
	if err != nil {
		sm.logger.Warn("Failed to get client IP", zap.String("method", method), zap.Error(err))
		if len(sm.allowedClients) > 0 || sm.rateLimiter != nil {
			return "", status.Error(codes.Unauthenticated, "unable to identify client")
		}
		return "", nil
	}

	if len(sm.allowedClients) > 0 && !sm.isIPAllowed(clientIP) {
		sm.logger.Warn("Client IP not in allowlist", zap.String("client_ip", clientIP), zap.String("method", method))
		return "", status.Error(codes.PermissionDenied, "client IP not allowed")
	}

	sm.logger.Debug("Security check passed", zap.String("client_ip", clientIP), zap.String("method", method))
	return clientIP, nil
}

func (sm *SecurityManager) authorizeRate(clientIP, method string) error {
	if sm.rateLimiter != nil && !sm.rateLimiter.Allow(clientIP) {
		sm.logger.Warn("Rate limit exceeded", zap.String("client_ip", clientIP), zap.String("method", method))
		return status.Error(codes.ResourceExhausted, "rate limit exceeded")
	}
	return nil
}

// getClientIP extracts the client IP from the gRPC context
func (*SecurityManager) getClientIP(ctx context.Context) (string, error) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return "", errors.New("no peer information in context")
	}

	if peer.Addr == nil {
		return "", errors.New("no address in peer information")
	}

	// Extract IP from address
	host, _, err := net.SplitHostPort(peer.Addr.String())
	if err != nil {
		return "", fmt.Errorf("failed to parse peer address: %w", err)
	}

	return host, nil
}

// isIPAllowed checks if the given IP is in the allowlist
func (sm *SecurityManager) isIPAllowed(clientIP string) bool {
	parsedClientIP := net.ParseIP(clientIP)
	for _, allowedIP := range sm.allowedClients {
		// Support CIDR notation
		if strings.Contains(allowedIP, "/") {
			_, cidr, err := net.ParseCIDR(allowedIP)
			if err != nil {
				sm.logger.Warn("Invalid CIDR in allowed_clients", zap.String("cidr", allowedIP))
				continue
			}
			if parsedClientIP != nil && cidr.Contains(parsedClientIP) {
				return true
			}
			// Direct IP match
		} else if parsedAllowedIP := net.ParseIP(allowedIP); parsedClientIP != nil && parsedAllowedIP != nil && parsedAllowedIP.Equal(parsedClientIP) {
			return true
		}
	}
	return false
}

// Shutdown stops the security manager
func (sm *SecurityManager) Shutdown() {
	if sm.rateLimiter != nil {
		sm.rateLimiter.Stop()
	}
}
