// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"errors"
	"fmt"
	"math"
	"net"
	"strings"

	"go.opentelemetry.io/collector/config/configgrpc"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver"
)

const (
	minimumGNMIDialOutReceiveSizeMiB = 1
	maximumGNMIDialOutReceiveSizeMiB = 16
	minimumGNMIDialOutStreams        = 1
	maximumGNMIDialOutStreams        = 1000
)

// effectiveGNMIDialOutMaxStreamsPerClient resolves an omitted per-client cap
// after the global stream cap is known. This preserves configurations created
// before max_streams_per_client existed, including deployments whose global
// cap is lower than the new default.
func effectiveGNMIDialOutMaxStreamsPerClient(configured, global uint32) uint32 {
	if configured > 0 {
		return configured
	}
	if global > 0 && global < defaultGNMIDialOutStreamsPerIP {
		return global
	}
	return defaultGNMIDialOutStreamsPerIP
}

// validateGNMIDialOutConfig owns the security and resource invariants required
// by the Cisco dial-out integrations. Keep these checks here instead of
// relying only on yanggrpcreceiver.Config.Validate: a collector built from a
// released module may resolve a different yanggrpcreceiver implementation than
// the local monorepo replacement.
func validateGNMIDialOutConfig(
	server configgrpc.ServerConfig,
	allowedClients []string,
	maxStreamsPerClient uint32,
	rateLimiting yanggrpcreceiver.RateLimitingConfig,
) error {
	var err error
	maxStreamsPerClient = effectiveGNMIDialOutMaxStreamsPerClient(maxStreamsPerClient, server.MaxConcurrentStreams)
	if validationErr := server.Validate(); validationErr != nil {
		err = errors.Join(err, validationErr)
	}
	if server.MaxRecvMsgSizeMiB < minimumGNMIDialOutReceiveSizeMiB || server.MaxRecvMsgSizeMiB > maximumGNMIDialOutReceiveSizeMiB {
		err = errors.Join(err, fmt.Errorf(
			"max_recv_msg_size_mib must be between %d and %d",
			minimumGNMIDialOutReceiveSizeMiB,
			maximumGNMIDialOutReceiveSizeMiB,
		))
	}
	if server.MaxConcurrentStreams < minimumGNMIDialOutStreams || server.MaxConcurrentStreams > maximumGNMIDialOutStreams {
		err = errors.Join(err, fmt.Errorf(
			"max_concurrent_streams must be between %d and %d",
			minimumGNMIDialOutStreams,
			maximumGNMIDialOutStreams,
		))
	}
	if maxStreamsPerClient < minimumGNMIDialOutStreams || maxStreamsPerClient > server.MaxConcurrentStreams {
		err = errors.Join(err, fmt.Errorf(
			"max_streams_per_client must be between %d and max_concurrent_streams (%d)",
			minimumGNMIDialOutStreams,
			server.MaxConcurrentStreams,
		))
	}
	for index, allowed := range allowedClients {
		if _, parseErr := parseGNMIDialOutAllowedClient(allowed); parseErr != nil {
			err = errors.Join(err, fmt.Errorf("allowed_clients[%d] %w", index, parseErr))
		}
	}
	if rateLimiting.Enabled {
		if rateLimiting.BurstSize <= 0 {
			err = errors.Join(err, errors.New("burst_size must be positive"))
		}
		if rateLimiting.RequestsPerSecond <= 0 || math.IsNaN(rateLimiting.RequestsPerSecond) || math.IsInf(rateLimiting.RequestsPerSecond, 0) {
			err = errors.Join(err, errors.New("requests_per_second must be positive and finite"))
		}
		if rateLimiting.CleanupInterval <= 0 {
			err = errors.Join(err, errors.New("cleanup_interval must be positive"))
		} else if rateLimiting.CleanupInterval < minGNMIDialOutLimiterCleanup {
			err = errors.Join(err, fmt.Errorf("cleanup_interval must be at least %s", minGNMIDialOutLimiterCleanup))
		}
	}

	endpoint := strings.TrimSpace(server.NetAddr.Endpoint)
	if endpoint == "" || strings.HasPrefix(endpoint, "unix://") {
		return err
	}
	host, _, splitErr := net.SplitHostPort(endpoint)
	if splitErr != nil {
		// ServerConfig.Validate owns malformed endpoint diagnostics.
		return err
	}
	parsedHost := net.ParseIP(host)
	if strings.EqualFold(host, "localhost") || parsedHost != nil && parsedHost.IsLoopback() {
		return err
	}

	tlsConfig := server.TLS.Get()
	if tlsConfig == nil {
		err = errors.Join(err, errors.New("non-loopback listeners require TLS"))
	}
	if len(allowedClients) == 0 && (tlsConfig == nil || strings.TrimSpace(tlsConfig.ClientCAFile) == "") {
		err = errors.Join(err, errors.New("non-loopback listeners require mutual TLS or at least one allowed_clients entry"))
	}
	if !rateLimiting.Enabled {
		err = errors.Join(err, errors.New("non-loopback listeners require per-message rate limiting"))
	}
	return err
}
