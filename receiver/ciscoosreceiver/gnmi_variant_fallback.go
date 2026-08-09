// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"errors"
	"fmt"
	"strings"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"go.uber.org/zap"
)

func negotiateSharedGNMIRuntimeStreamEncodings(
	target GNMITargetConfig,
	capabilities *gnmipb.CapabilityResponse,
	stream *sharedGNMIRuntimeStream,
) error {
	if stream == nil {
		return errors.New("gNMI runtime stream is required")
	}
	if len(stream.variantFallbacks) == 0 {
		encoding, err := negotiateSharedGNMIStreamEncoding(target, capabilities, stream.sharedGNMIStream)
		if err != nil {
			return fmt.Errorf("profile %q encoding: %w", stream.Profile, err)
		}
		stream.wireEncoding = encoding
		return nil
	}
	for index := range stream.variantFallbacks {
		variant := &stream.variantFallbacks[index]
		encoding, err := negotiateSharedGNMIStreamEncoding(target, capabilities, variant.stream.sharedGNMIStream)
		if err != nil {
			variant.planningErr = err
			continue
		}
		variant.stream.wireEncoding = encoding
		if stream.wireEncoding == 0 {
			stream.wireEncoding = encoding
		}
	}
	return nil
}

func (r *sharedGNMIReceiver) selectSharedGNMIStreamVariants(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	client gnmipb.GNMIClient,
	streams []sharedGNMIRuntimeStream,
) ([]sharedGNMIRuntimeStream, error) {
	selected := make([]sharedGNMIRuntimeStream, 0, len(streams))
	for streamIndex := range streams {
		planned := streams[streamIndex]
		if len(planned.variantFallbacks) == 0 {
			selected = append(selected, planned)
			continue
		}

		chosen := false
		reasons := make([]string, 0, len(planned.variantFallbacks))
		for variantIndex := range planned.variantFallbacks {
			variant := &planned.variantFallbacks[variantIndex]
			if variant.planningErr != nil {
				reasons = append(reasons, fmt.Sprintf("%s: %v", variant.variantID, variant.planningErr))
				continue
			}
			if target.variantIsolated(planned.Profile, variant.pathSetID, variant.variantID) {
				reasons = append(reasons, variant.variantID+": retry window active")
				continue
			}
			available := target.filterIsolatedPathSets(variant.stream.Paths)
			if len(available) != len(variant.stream.Paths) {
				reasons = append(reasons, variant.variantID+": path-set retry window active")
				continue
			}

			err := r.probeSubscriptionUntilSync(ctx, target, client, variant.stream, variant.stream.wireEncoding)
			if err == nil {
				// Failures for higher-priority variants remain scheduled so the
				// receiver can move back to the preferred source. The selected and
				// lower-priority variants cannot improve this session, so stale entries
				// for them must not force an unrelated reconnect.
				for clearIndex := variantIndex; clearIndex < len(planned.variantFallbacks); clearIndex++ {
					fallback := planned.variantFallbacks[clearIndex]
					target.clearVariantNegative(planned.Profile, fallback.pathSetID, fallback.variantID)
				}
				candidate := variant.stream
				candidate.variantFallbacks = nil
				selected = append(selected, candidate)
				chosen = true
				break
			}
			reason := "unsupported_path"
			failure := "unsupported"
			var unsupported *sharedGNMIUnsupportedError
			var timeout *sharedGNMISyncTimeoutError
			if !errors.As(err, &unsupported) && !errors.As(err, &timeout) {
				return nil, fmt.Errorf(
					"probe gNMI profile %q path set %q variant %q: %w",
					planned.Profile,
					variant.pathSetID,
					variant.variantID,
					err,
				)
			}
			if timeout != nil {
				reason = "sync_timeout"
				failure = "sync timeout"
			}
			target.isolateVariant(planned.Profile, variant.pathSetID, variant.variantID)
			reasons = append(reasons, variant.variantID+": "+failure)
			r.telemetry.degraded(ctx, target.config.Name, planned.Profile, reason)
			r.settings.Logger.Warn("Cisco gNMI path-set variant suppressed until its retry window expires",
				zap.String("target", target.config.Name),
				zap.String("profile", planned.Profile),
				zap.String("path_set", variant.pathSetID),
				zap.String("variant", variant.variantID),
				zap.String("reason", reason))
		}
		if chosen {
			continue
		}

		exhausted := fmt.Errorf(
			"gNMI profile %q path set %q has no usable variant (%s)",
			planned.Profile,
			planned.variantFallbacks[0].pathSetID,
			strings.Join(reasons, "; "),
		)
		if planned.Required {
			if _, retry := target.nextNegativeRetry(); !retry {
				return nil, exhausted
			}
			// Preserve one unsynchronized readiness entry while the circuit breaker
			// waits. This plan is never launched and therefore owns no active decoder.
			planned.registry = nil
			planned.staticAttr = nil
			planned.Mappings = nil
			planned.JSONListKeySpecs = nil
			planned.JSONListKeys = nil
			planned.EntityLimits = nil
			selected = append(selected, planned)
			continue
		}
		r.telemetry.degraded(ctx, target.config.Name, planned.Profile, "unsupported_path")
		r.settings.Logger.Warn("Optional Cisco gNMI path set has no usable variant",
			zap.String("target", target.config.Name),
			zap.String("profile", planned.Profile),
			zap.String("path_set", planned.variantFallbacks[0].pathSetID),
			zap.Error(exhausted))
	}
	return selected, nil
}

func (target *sharedGNMITargetRuntime) applySelectedRuntimeStreams(streams []sharedGNMIRuntimeStream) error {
	target.deliveryMu.Lock()
	defer target.deliveryMu.Unlock()
	target.sessionMu.RLock()
	cache := target.cache
	target.sessionMu.RUnlock()
	if cache == nil {
		return errors.New("selected gNMI session has no state cache")
	}
	manager, err := newSharedGNMIEntityLimitManager(streams, cache.Snapshot())
	if err != nil {
		return fmt.Errorf("plan selected group entity limits: %w", err)
	}
	target.sessionMu.Lock()
	target.entityLimits = manager
	target.sessionMu.Unlock()
	return nil
}

func sharedGNMIVariantNegativeKey(profile, pathSetID, variantID string) string {
	return "\xffvariant\x00" + profile + "\x00" + pathSetID + "\x00" + variantID
}

func (target *sharedGNMITargetRuntime) isolateVariant(profile, pathSetID, variantID string) {
	fingerprint, now := target.negativeContext()
	key := sharedGNMIVariantNegativeKey(profile, pathSetID, variantID)
	target.stateMu.Lock()
	target.isolate[key] = nextSharedGNMINegativeEntry(target.isolate[key], fingerprint, now)
	target.stateMu.Unlock()
}

func (target *sharedGNMITargetRuntime) variantIsolated(profile, pathSetID, variantID string) bool {
	fingerprint, now := target.negativeContext()
	key := sharedGNMIVariantNegativeKey(profile, pathSetID, variantID)
	target.stateMu.RLock()
	entry, isolated := target.isolate[key]
	target.stateMu.RUnlock()
	return isolated && entry.fingerprint == fingerprint && now.Before(entry.retryAt)
}

func (target *sharedGNMITargetRuntime) clearVariantNegative(profile, pathSetID, variantID string) {
	fingerprint, _ := target.negativeContext()
	key := sharedGNMIVariantNegativeKey(profile, pathSetID, variantID)
	target.stateMu.Lock()
	if entry, ok := target.isolate[key]; ok && entry.fingerprint == fingerprint {
		delete(target.isolate, key)
	}
	target.stateMu.Unlock()
}

func (target *sharedGNMITargetRuntime) filterIsolatedPathSets(paths []sharedGNMIPath) []sharedGNMIPath {
	fingerprint, now := target.negativeContext()
	target.stateMu.RLock()
	defer target.stateMu.RUnlock()
	sets := sharedGNMIAtomicPathSets(paths)
	out := make([]sharedGNMIPath, 0, len(paths))
	for _, pathSet := range sets {
		isolated := false
		for _, path := range pathSet {
			entry, exists := target.isolate[sharedGNMIPathKey(path)]
			if exists && entry.fingerprint == fingerprint && now.Before(entry.retryAt) {
				isolated = true
				break
			}
		}
		if !isolated {
			out = append(out, pathSet...)
		}
	}
	return out
}
