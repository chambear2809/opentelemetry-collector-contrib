// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package yanggrpcreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver"

import (
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"go.opentelemetry.io/collector/config/configgrpc"
)

const (
	minMaxRecvMsgSizeMiB            = 1
	maxMaxRecvMsgSizeMiB            = 16
	minMaxConcurrentStreams         = 1
	maxMaxConcurrentStreams         = 1000
	minRateLimiterCleanup           = time.Second
	defaultMaxConnections           = 256
	maxMaxConnections               = 1024
	defaultMaxConcurrentConversions = 8
	maxMaxConcurrentConversions     = 16
	defaultConnectionTimeout        = 30 * time.Second
	minConnectionTimeout            = time.Second
	maxConnectionTimeout            = 2 * time.Minute
	defaultMaxConnectionIdle        = 2 * time.Minute
)

// SecurityConfig contains security hardening options
type SecurityConfig struct {
	// RateLimiting contains rate limiting configuration
	RateLimiting RateLimitingConfig `mapstructure:"rate_limiting"`

	// AllowedClients contains client IP allowlist configuration
	AllowedClients []string `mapstructure:"allowed_clients"`
}

func (s *SecurityConfig) Validate() error {
	err := s.RateLimiting.Validate()
	for i, allowed := range s.AllowedClients {
		if net.ParseIP(allowed) != nil {
			continue
		}
		if _, _, parseErr := net.ParseCIDR(allowed); parseErr != nil {
			err = errors.Join(err, fmt.Errorf("allowed_clients[%d] must be an IP address or CIDR: %q", i, allowed))
		}
	}
	return err
}

// RateLimitingConfig contains rate limiting configuration
type RateLimitingConfig struct {
	// Enabled indicates whether rate limiting should be enabled
	Enabled bool `mapstructure:"enabled"`

	// RequestsPerSecond is the maximum number of received messages per second per client.
	RequestsPerSecond float64 `mapstructure:"requests_per_second"`

	// BurstSize is the maximum burst size for rate limiting
	BurstSize int `mapstructure:"burst_size"`

	// CleanupInterval is how often to clean up idle rate limiter entries.
	// Values below one second are rejected to prevent a hot cleanup loop.
	CleanupInterval time.Duration `mapstructure:"cleanup_interval"`
}

func (r *RateLimitingConfig) Validate() error {
	if !r.Enabled {
		return nil
	}
	if r.BurstSize <= 0 {
		return errors.New("burst_size must be positive")
	}
	if r.RequestsPerSecond <= 0 || math.IsNaN(r.RequestsPerSecond) || math.IsInf(r.RequestsPerSecond, 0) {
		return errors.New("requests_per_second must be positive and finite")
	}
	if r.CleanupInterval <= 0 {
		return errors.New("cleanup_interval must be positive")
	}
	if r.CleanupInterval < minRateLimiterCleanup {
		return fmt.Errorf("cleanup_interval must be at least %s", minRateLimiterCleanup)
	}
	return nil
}

// YANGConfig contains YANG parser configuration
type YANGConfig struct {
	_ struct{} `mapstructure:"-"`

	// ModulePaths defines the directories where .yang files are stored.
	// This is used by the internal parser to resolve Cisco-specific schemas.
	ModulePaths []string `mapstructure:"module_paths"`
}

// Config defines configuration for yanggrpc receiver.
type Config struct {
	configgrpc.ServerConfig `mapstructure:",squash"`

	// MaxConnections is the maximum number of accepted network connections.
	// Zero uses the default of 256.
	MaxConnections uint32 `mapstructure:"max_connections"`

	// MaxConcurrentConversions bounds telemetry messages being converted and
	// consumed concurrently across all streams. Zero uses the default of 8.
	MaxConcurrentConversions uint32 `mapstructure:"max_concurrent_conversions"`

	// ConnectionTimeout bounds connection establishment through the HTTP/2
	// handshake. Zero uses the default of 30 seconds.
	ConnectionTimeout time.Duration `mapstructure:"connection_timeout"`

	// YANG contains YANG parser configuration
	YANG YANGConfig `mapstructure:"yang"`

	// Security contains security hardening configuration
	Security SecurityConfig `mapstructure:"security"`
}

// RuntimeHardeningVersion advertises the receiver runtime safety contract to
// embedding components without requiring them to import implementation
// internals. Version 1 includes bounded connections and aggregate telemetry
// conversion, stream-aware downstream contexts, per-message stream security,
// and deadline-aware shutdown.
func (*Config) RuntimeHardeningVersion() int { return 1 }

// Validate checks the receiver configuration is valid.
func (c *Config) Validate() error {
	// Validate the base gRPC server configuration (endpoint, TLS, etc.)
	if err := c.ServerConfig.Validate(); err != nil {
		return err
	}
	if c.MaxRecvMsgSizeMiB < minMaxRecvMsgSizeMiB || c.MaxRecvMsgSizeMiB > maxMaxRecvMsgSizeMiB {
		return fmt.Errorf("max_recv_msg_size_mib must be between %d and %d", minMaxRecvMsgSizeMiB, maxMaxRecvMsgSizeMiB)
	}
	if c.MaxConcurrentStreams < minMaxConcurrentStreams || c.MaxConcurrentStreams > maxMaxConcurrentStreams {
		return fmt.Errorf("max_concurrent_streams must be between %d and %d", minMaxConcurrentStreams, maxMaxConcurrentStreams)
	}
	if err := c.validateRuntimeAvailability(); err != nil {
		return err
	}

	// Validate security settings
	if err := c.Security.Validate(); err != nil {
		return err
	}

	return c.validateRemoteListenerSecurity()
}

func (c *Config) validateRuntimeAvailability() error {
	if c.MaxConnections > maxMaxConnections {
		return fmt.Errorf("max_connections must not exceed %d", maxMaxConnections)
	}
	if c.MaxConcurrentConversions > maxMaxConcurrentConversions {
		return fmt.Errorf("max_concurrent_conversions must not exceed %d", maxMaxConcurrentConversions)
	}
	if c.ConnectionTimeout != 0 && (c.ConnectionTimeout < minConnectionTimeout || c.ConnectionTimeout > maxConnectionTimeout) {
		return fmt.Errorf("connection_timeout must be zero or between %s and %s", minConnectionTimeout, maxConnectionTimeout)
	}
	return nil
}

func effectiveMaxConnections(configured uint32) int {
	if configured == 0 {
		return defaultMaxConnections
	}
	return int(min(configured, uint32(maxMaxConnections)))
}

func effectiveMaxConcurrentConversions(configured uint32) int {
	if configured == 0 {
		return defaultMaxConcurrentConversions
	}
	return int(min(configured, uint32(maxMaxConcurrentConversions)))
}

func effectiveConnectionTimeout(configured time.Duration) time.Duration {
	if configured == 0 {
		return defaultConnectionTimeout
	}
	return configured
}

// validateRemoteListenerSecurity prevents accidentally exposing an
// unauthenticated telemetry-ingestion endpoint. The plaintext default remains
// available on loopback for local development and tests.
func (c *Config) validateRemoteListenerSecurity() error {
	endpoint := strings.TrimSpace(c.NetAddr.Endpoint)
	if endpoint == "" || strings.HasPrefix(endpoint, "unix://") {
		return nil
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		// ServerConfig.Validate reports malformed endpoints.
		return nil
	}
	parsedHost := net.ParseIP(host)
	if strings.EqualFold(host, "localhost") || parsedHost != nil && parsedHost.IsLoopback() {
		return nil
	}

	var validationErr error
	tlsConfig := c.TLS.Get()
	if tlsConfig == nil {
		validationErr = errors.Join(validationErr, errors.New("non-loopback listeners require TLS"))
	}
	if len(c.Security.AllowedClients) == 0 && (tlsConfig == nil || strings.TrimSpace(tlsConfig.ClientCAFile) == "") {
		validationErr = errors.Join(validationErr, errors.New("non-loopback listeners require mutual TLS or at least one allowed_clients entry"))
	}
	if !c.Security.RateLimiting.Enabled {
		validationErr = errors.Join(validationErr, errors.New("non-loopback listeners require per-message rate limiting"))
	}
	return validationErr
}
