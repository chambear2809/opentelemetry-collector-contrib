// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	grpcmetadata "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

const (
	sharedGNMITransport             = "gnmi"
	sharedGNMIAuthenticationBackoff = 5 * time.Minute
	sharedGNMIInitialBackoff        = 5 * time.Second
	sharedGNMIMaximumBackoff        = time.Minute
	sharedGNMIBackoffResetAfter     = time.Minute
	sharedGNMIMaxBisectionProbes    = 64
)

type sharedGNMIReceiver struct {
	settings        receiver.Settings
	config          GNMIConfig
	consumer        consumer.Metrics
	obs             *receiverhelper.ObsReport
	telemetry       *gnmiTelemetry
	targets         []*sharedGNMITargetRuntime
	maxDatapoints   int
	maxCachedSeries int

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
	host   component.Host
}

type sharedGNMITargetRuntime struct {
	config  GNMITargetConfig
	streams []sharedGNMIRuntimeStream
	cache   *internalgnmi.Cache
	stateMu sync.RWMutex
	isolate map[string]struct{}
	stopped map[string]struct{}
	rejects map[string]int

	nxMu      sync.Mutex
	nxSensors map[string]nxSensorState
	nxBudget  *sharedGNMIAuxiliaryBudget
	sessionUp atomic.Bool

	presenceMu     sync.Mutex
	opticalSources map[string]string
	presenceCounts map[string]int
	presenceAttrs  map[string]map[string]string
}

type sharedGNMIRuntimeStream struct {
	sharedGNMIStream
	registry   *internalgnmi.Registry
	staticAttr map[string]map[string]string
}

type nxSensorState struct {
	description          string
	unit                 string
	path                 internalgnmi.Path
	descriptionTimestamp time.Time
	unitTimestamp        time.Time
}

type sharedGNMIAuxiliaryBudget struct {
	mu      sync.Mutex
	maximum int
	used    int
}

func newSharedGNMIAuxiliaryBudget(maximum int) *sharedGNMIAuxiliaryBudget {
	return &sharedGNMIAuxiliaryBudget{maximum: maximum}
}

// beginChange holds the budget lock until finishChange so a concurrent target
// cannot consume capacity that a transaction may need to restore on rollback.
func (b *sharedGNMIAuxiliaryBudget) beginChange(delta int) (int, bool) {
	b.mu.Lock()
	if delta > 0 && b.used+delta > b.maximum {
		b.mu.Unlock()
		return b.used, false
	}
	if delta < 0 && b.used+delta < 0 {
		b.mu.Unlock()
		return b.used, false
	}
	if delta > 0 {
		b.used += delta
	}
	return b.used, true
}

func (b *sharedGNMIAuxiliaryBudget) finishChange(delta int, commit bool) {
	if commit && delta < 0 {
		b.used += delta
	} else if !commit && delta > 0 {
		b.used -= delta
	}
	b.mu.Unlock()
}

type nxSensorChange struct {
	state  nxSensorState
	exists bool
}

type nxSensorTransaction struct {
	target       *sharedGNMITargetRuntime
	changes      map[string]nxSensorChange
	budgetDelta  int
	budgetLocked bool
	done         bool
}

func (tx *nxSensorTransaction) commit() {
	if tx == nil || tx.done {
		return
	}
	// Copying each small transaction value keeps the map immutable while it is
	// published under nxMu.
	//nolint:gocritic // A map range cannot take a stable pointer to its value.
	for key, change := range tx.changes {
		if change.exists {
			tx.target.nxSensors[key] = change.state
		} else {
			delete(tx.target.nxSensors, key)
		}
	}
	tx.done = true
	tx.target.nxMu.Unlock()
	if tx.budgetLocked {
		tx.target.nxBudget.finishChange(tx.budgetDelta, true)
	}
}

func (tx *nxSensorTransaction) rollback() {
	if tx == nil || tx.done {
		return
	}
	tx.done = true
	tx.target.nxMu.Unlock()
	if tx.budgetLocked {
		tx.target.nxBudget.finishChange(tx.budgetDelta, false)
	}
}

type sharedGNMIStreamResult struct {
	stream   sharedGNMIRuntimeStream
	err      error
	terminal bool
}

type sharedGNMIUnsupportedError struct{ err error }

func (e *sharedGNMIUnsupportedError) Error() string { return e.err.Error() }
func (e *sharedGNMIUnsupportedError) Unwrap() error { return e.err }

type sharedGNMIProfileStopError struct{ err error }

func (e *sharedGNMIProfileStopError) Error() string { return e.err.Error() }
func (e *sharedGNMIProfileStopError) Unwrap() error { return e.err }

func newSharedGNMIReceiver(set receiver.Settings, cfg *Config, next consumer.Metrics) (receiver.Metrics, error) {
	defaults := defaultGNMIConfig()
	gnmiConfig := cfg.GNMI
	if gnmiConfig.MaxDatapointsPerChunk == 0 {
		gnmiConfig.MaxDatapointsPerChunk = defaults.MaxDatapointsPerChunk
	}
	if gnmiConfig.MaxCachedSeries == 0 {
		gnmiConfig.MaxCachedSeries = defaults.MaxCachedSeries
	}

	telemetryBuilder, err := componentmetadata.NewTelemetryBuilder(set.TelemetrySettings)
	if err != nil {
		return nil, fmt.Errorf("create gNMI telemetry: %w", err)
	}
	r := &sharedGNMIReceiver{
		settings:        set,
		config:          gnmiConfig,
		consumer:        next,
		obs:             newPlatformObsReport(set, sharedGNMITransport),
		telemetry:       &gnmiTelemetry{builder: telemetryBuilder},
		maxDatapoints:   gnmiConfig.MaxDatapointsPerChunk,
		maxCachedSeries: gnmiConfig.MaxCachedSeries,
		done:            make(chan struct{}),
	}
	sharedCache, err := internalgnmi.NewCache(gnmiConfig.MaxCachedSeries)
	if err != nil {
		telemetryBuilder.Shutdown()
		return nil, err
	}
	selector := newDeviceSelectionMatcher(cfg.DeviceSelection)
	auxiliaryBudget := newSharedGNMIAuxiliaryBudget(gnmiConfig.MaxCachedSeries)
	for targetIndex := range gnmiConfig.Targets {
		target := gnmiConfig.Targets[targetIndex].withDefaults()
		if !selector.allows(sharedGNMITargetIdentity(target)) {
			continue
		}
		runtime, err := newSharedGNMITargetRuntimeWithBudget(target, sharedCache, auxiliaryBudget)
		if err != nil {
			telemetryBuilder.Shutdown()
			return nil, fmt.Errorf("build gNMI target %q: %w", target.Name, err)
		}
		r.targets = append(r.targets, runtime)
	}
	return r, nil
}

func newSharedGNMITargetRuntime(target GNMITargetConfig, cache *internalgnmi.Cache) (*sharedGNMITargetRuntime, error) {
	if cache == nil {
		return nil, errors.New("shared gNMI cache cannot be nil")
	}
	return newSharedGNMITargetRuntimeWithBudget(target, cache, newSharedGNMIAuxiliaryBudget(cache.Capacity()))
}

func newSharedGNMITargetRuntimeWithBudget(
	target GNMITargetConfig,
	cache *internalgnmi.Cache,
	auxiliaryBudget *sharedGNMIAuxiliaryBudget,
) (*sharedGNMITargetRuntime, error) {
	streams, err := buildSharedGNMIStreams(target)
	if err != nil {
		return nil, err
	}
	if cache == nil {
		return nil, errors.New("shared gNMI cache cannot be nil")
	}
	if auxiliaryBudget == nil || auxiliaryBudget.maximum <= 0 {
		return nil, errors.New("shared gNMI auxiliary-state budget must be positive")
	}
	runtime := &sharedGNMITargetRuntime{
		config:         target,
		cache:          cache,
		isolate:        map[string]struct{}{},
		stopped:        map[string]struct{}{},
		rejects:        map[string]int{},
		nxSensors:      map[string]nxSensorState{},
		nxBudget:       auxiliaryBudget,
		opticalSources: map[string]string{},
		presenceCounts: map[string]int{},
		presenceAttrs:  map[string]map[string]string{},
	}
	for streamIndex := range streams {
		stream := streams[streamIndex]
		mappings := make([]internalgnmi.Mapping, 0, len(stream.Mappings))
		staticAttrs := make(map[string]map[string]string, len(stream.Mappings))
		for mappingIndex := range stream.Mappings {
			mapping := &stream.Mappings[mappingIndex]
			mappings = append(mappings, mapping.Mapping)
			if len(mapping.StaticAttributes) > 0 {
				staticAttrs[sharedGNMISourceKey(mapping.Mapping.Source)] = cloneGNMIAttributes(mapping.StaticAttributes)
			}
		}
		registry, err := internalgnmi.NewRegistry(mappings...)
		if err != nil {
			return nil, fmt.Errorf("profile %q mappings: %w", stream.Profile, err)
		}
		runtime.streams = append(runtime.streams, sharedGNMIRuntimeStream{
			sharedGNMIStream: stream,
			registry:         registry,
			staticAttr:       staticAttrs,
		})
	}
	return runtime, nil
}

func (r *sharedGNMIReceiver) Start(_ context.Context, host component.Host) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.host = host
	go r.run(ctx)
	return nil
}

func (r *sharedGNMIReceiver) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	cancel := r.cancel
	r.mu.Unlock()
	if cancel == nil {
		r.telemetry.shutdown()
		return nil
	}
	cancel()
	select {
	case <-r.done:
		r.telemetry.shutdown()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *sharedGNMIReceiver) run(ctx context.Context) {
	defer close(r.done)
	var wg sync.WaitGroup
	for _, target := range r.targets {
		wg.Go(func() {
			r.runTarget(ctx, target)
		})
	}
	wg.Wait()
}

func (r *sharedGNMIReceiver) runTarget(ctx context.Context, target *sharedGNMITargetRuntime) {
	attempt := 0
	for ctx.Err() == nil {
		terminal, resetBackoff, err := r.serveTarget(ctx, target)
		r.telemetry.connection(ctx, target.config.Name, false)
		if resetBackoff {
			attempt = 0
		}
		if terminal || ctx.Err() != nil {
			return
		}
		r.emitAvailability(ctx, target.config, false)
		delay := equalJitterGNMIBackoff(attempt)
		if isSharedGNMIAuthenticationError(err) {
			r.telemetry.authenticationFailure(ctx, target.config.Name)
			delay = sharedGNMIAuthenticationBackoff
		} else {
			attempt++
		}
		r.telemetry.reconnect(ctx, target.config.Name)
		r.settings.Logger.Warn("Cisco gNMI target disconnected",
			zap.String("target", target.config.Name),
			zap.String("endpoint", target.config.Endpoint),
			zap.Duration("retry_delay", delay),
			zap.Error(err))
		if !waitSharedGNMIBackoff(ctx, delay) {
			return
		}
	}
}

func (r *sharedGNMIReceiver) serveTarget(ctx context.Context, target *sharedGNMITargetRuntime) (bool, bool, error) {
	target.sessionUp.Store(false)
	if target.config.Platform == gnmiPlatformNXOS {
		// DME description/unit identity is scoped to a device session. Preserve
		// mapped cache and tombstones, but require fresh sensor identity before
		// values from a reconnected session can be mapped.
		target.clearNXSensorState()
		defer target.clearNXSensorState()
	}
	conn, err := r.dialTarget(ctx, target.config)
	if err != nil {
		return false, false, err
	}
	defer conn.Close()
	client := gnmipb.NewGNMIClient(conn)
	capCtx, cancel := context.WithTimeout(sharedGNMIOutgoingContext(ctx, target.config), target.config.CapabilitiesTimeout)
	capabilities, err := client.Capabilities(capCtx, &gnmipb.CapabilityRequest{})
	cancel()
	if err != nil {
		return false, false, fmt.Errorf("capabilities: %w", err)
	}
	encoding, err := negotiateSharedGNMIEncoding(target.config, capabilities, runtimeSharedGNMIStreams(target.streams))
	if err != nil {
		return false, false, err
	}
	r.telemetry.connection(ctx, target.config.Name, true)
	connectedAt := time.Now()
	terminal, err := r.serveTargetStreams(ctx, target, client, encoding)
	resetBackoff := terminal || time.Since(connectedAt) >= sharedGNMIBackoffResetAfter
	if err == nil && !terminal {
		return false, resetBackoff, io.ErrUnexpectedEOF
	}
	return terminal, resetBackoff, err
}

func (r *sharedGNMIReceiver) dialTarget(ctx context.Context, target GNMITargetConfig) (*grpc.ClientConn, error) {
	clientConfig := configgrpc.NewDefaultClientConfig()
	clientConfig.Endpoint = target.Endpoint
	clientConfig.TLS = configtls.ClientConfig{
		Config: configtls.Config{
			CAFile:         target.TLS.CAFile,
			CertFile:       target.TLS.CertFile,
			KeyFile:        target.TLS.KeyFile,
			MinVersion:     target.TLS.MinVersion,
			ReloadInterval: target.TLS.ReloadInterval,
		},
		ServerName: target.TLS.ServerNameOverride,
	}
	clientConfig.Keepalive = configoptional.Some(configgrpc.KeepaliveClientConfig{
		Time:                target.Keepalive.Time,
		Timeout:             target.Keepalive.Timeout,
		PermitWithoutStream: boolValue(target.Keepalive.PermitWithoutStream, true),
	})
	dialCtx, cancel := context.WithTimeout(ctx, target.ConnectTimeout)
	defer cancel()
	conn, err := clientConfig.ToClientConn(
		dialCtx,
		r.host.GetExtensions(),
		r.settings.TelemetrySettings,
		configgrpc.WithGrpcDialOption(grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(target.MaxRecvMsgSizeMiB*1024*1024))),
	)
	if err != nil {
		return nil, err
	}
	conn.Connect()
	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			return conn, nil
		}
		if state == connectivity.Shutdown {
			_ = conn.Close()
			return nil, errors.New("gNMI connection shut down before becoming ready")
		}
		if !conn.WaitForStateChange(dialCtx, state) {
			_ = conn.Close()
			return nil, fmt.Errorf("gNMI connection did not become ready: %w", dialCtx.Err())
		}
	}
}

func (r *sharedGNMIReceiver) serveTargetStreams(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	client gnmipb.GNMIClient,
	encoding gnmipb.Encoding,
) (bool, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan sharedGNMIStreamResult, 32)
	semaphore := make(chan struct{}, target.config.MaxStreams)
	profileCancels := map[string][]context.CancelFunc{}
	var wg sync.WaitGroup
	active := 0
	launch := func(stream sharedGNMIRuntimeStream) {
		if target.profileStopped(stream.Profile) {
			return
		}
		stream.Paths = target.filterIsolated(stream.Paths)
		if len(stream.Paths) == 0 {
			return
		}
		subscriptionCtx, subscriptionCancel := context.WithCancel(streamCtx)
		profileCancels[stream.Profile] = append(profileCancels[stream.Profile], subscriptionCancel)
		active++
		wg.Go(func() {
			defer subscriptionCancel()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-subscriptionCtx.Done():
				results <- sharedGNMIStreamResult{stream: stream, err: subscriptionCtx.Err()}
				return
			}
			terminal, err := r.runSubscription(subscriptionCtx, target, client, stream, encoding)
			results <- sharedGNMIStreamResult{stream: stream, terminal: terminal, err: err}
		})
	}
	for streamIndex := range target.streams {
		launch(target.streams[streamIndex])
	}
	if active == 0 {
		return true, nil
	}
	for active > 0 {
		select {
		case <-ctx.Done():
			cancel()
			wg.Wait()
			return false, ctx.Err()
		case result := <-results:
			active--
			if target.profileStopped(result.stream.Profile) {
				continue
			}
			if result.err == nil && result.terminal {
				continue
			}
			var unsupported *sharedGNMIUnsupportedError
			if errors.As(result.err, &unsupported) {
				select {
				case semaphore <- struct{}{}:
				case <-streamCtx.Done():
					cancel()
					wg.Wait()
					return false, streamCtx.Err()
				}
				validGroups, resolutionErr := r.resolveUnsupportedGNMIPaths(streamCtx, target, client, result.stream, encoding)
				<-semaphore
				if resolutionErr != nil {
					var stopped *sharedGNMIProfileStopError
					if errors.As(resolutionErr, &stopped) {
						r.stopGNMIProfile(ctx, target, result.stream, "bisection_limit", stopped, profileCancels)
						continue
					}
					cancel()
					wg.Wait()
					return false, resolutionErr
				}
				if len(validGroups) > 1 {
					if active+len(validGroups) > target.config.MaxStreams {
						r.stopGNMIProfile(ctx, target, result.stream, "incompatible_path_group", fmt.Errorf(
							"the target accepts %d path groups separately, but they would require %d of %d allowed streams",
							len(validGroups), active+len(validGroups), target.config.MaxStreams,
						), profileCancels)
						continue
					}
				}
				for _, validPaths := range validGroups {
					validated := result.stream
					validated.Paths = validPaths
					launch(validated)
				}
				continue
			}
			var stopped *sharedGNMIProfileStopError
			if errors.As(result.err, &stopped) {
				r.stopGNMIProfile(ctx, target, result.stream, "cache_limit", stopped, profileCancels)
				continue
			}
			cancel()
			wg.Wait()
			return false, result.err
		}
	}
	wg.Wait()
	return true, nil
}

// resolveUnsupportedGNMIPaths probes rejected path groups serially while
// holding the failed stream's slot. A valid STREAM probe is stopped after its
// initial sync_response; POLL probes also complete one poll cycle, and ONCE
// probes require clean completion. Probe updates are intentionally discarded
// so only the final subscriptions mutate cache state or emit metrics. This
// avoids deadlocking when all configured stream slots are already occupied.
func (r *sharedGNMIReceiver) resolveUnsupportedGNMIPaths(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	client gnmipb.GNMIClient,
	stream sharedGNMIRuntimeStream,
	encoding gnmipb.Encoding,
) ([][]sharedGNMIPath, error) {
	rejectionKey := sharedGNMIRejectedPathSetKey(stream)
	if target.recordRejectedPathSet(rejectionKey) > 1 {
		return nil, &sharedGNMIProfileStopError{err: errors.New("subscription path set was rejected repeatedly after bisection")}
	}
	probes := 0
	var resolve func([]sharedGNMIPath) ([][]sharedGNMIPath, error)
	resolve = func(paths []sharedGNMIPath) ([][]sharedGNMIPath, error) {
		if len(paths) == 0 {
			return nil, nil
		}
		if len(paths) == 1 {
			target.isolatePath(paths[0])
			if stream.Required {
				r.telemetry.degraded(ctx, target.config.Name, stream.Profile, "unsupported_path", true)
			}
			r.settings.Logger.Warn("Cisco gNMI path isolated until receiver restart",
				zap.String("target", target.config.Name),
				zap.String("profile", stream.Profile),
				zap.String("origin", paths[0].Origin),
				zap.String("path", paths[0].Path))
			return nil, nil
		}

		midpoint := len(paths) / 2
		halves := [][]sharedGNMIPath{paths[:midpoint], paths[midpoint:]}
		validGroups := make([][]sharedGNMIPath, 0, 2)
		for _, half := range halves {
			probes++
			if probes > sharedGNMIMaxBisectionProbes {
				return nil, &sharedGNMIProfileStopError{err: fmt.Errorf("subscription bisection exceeded %d probes", sharedGNMIMaxBisectionProbes)}
			}
			probe := stream
			probe.Paths = append([]sharedGNMIPath(nil), half...)
			err := r.probeSubscriptionUntilSync(ctx, target, client, probe, encoding)
			if err == nil {
				validGroups = append(validGroups, append([]sharedGNMIPath(nil), half...))
				continue
			}
			var unsupported *sharedGNMIUnsupportedError
			if !errors.As(err, &unsupported) {
				return nil, err
			}
			resolved, err := resolve(half)
			if err != nil {
				return nil, err
			}
			validGroups = append(validGroups, resolved...)
		}
		if len(validGroups) <= 1 {
			return validGroups, nil
		}
		combined := make([]sharedGNMIPath, 0, len(paths))
		for _, group := range validGroups {
			combined = append(combined, group...)
		}
		probes++
		if probes > sharedGNMIMaxBisectionProbes {
			return nil, &sharedGNMIProfileStopError{err: fmt.Errorf("subscription bisection exceeded %d probes", sharedGNMIMaxBisectionProbes)}
		}
		probe := stream
		probe.Paths = combined
		err := r.probeSubscriptionUntilSync(ctx, target, client, probe, encoding)
		if err == nil {
			return [][]sharedGNMIPath{combined}, nil
		}
		var unsupported *sharedGNMIUnsupportedError
		if !errors.As(err, &unsupported) {
			return nil, err
		}
		return validGroups, nil
	}

	return resolve(stream.Paths)
}

func (r *sharedGNMIReceiver) probeSubscriptionUntilSync(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	client gnmipb.GNMIClient,
	stream sharedGNMIRuntimeStream,
	encoding gnmipb.Encoding,
) error {
	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	r.telemetry.subscription(probeCtx, target.config.Name, stream.Profile, true)
	defer r.telemetry.subscription(context.Background(), target.config.Name, stream.Profile, false)

	request, err := buildSharedGNMISubscribeRequest(target.config, stream.sharedGNMIStream, encoding)
	if err != nil {
		return err
	}
	subscribe, err := client.Subscribe(sharedGNMIOutgoingContext(probeCtx, target.config))
	if err != nil {
		return classifySharedGNMIStreamError(err)
	}
	if err := subscribe.Send(request); err != nil {
		return classifySharedGNMIStreamError(err)
	}
	if stream.Mode == gnmiModeOnce {
		if err := subscribe.CloseSend(); err != nil {
			return classifySharedGNMIStreamError(err)
		}
	}
	if stream.Mode == gnmiModeOnce {
		return receiveSharedGNMIProbeOnce(subscribe)
	}
	if err := receiveSharedGNMIProbeUntilSync(subscribe); err != nil {
		return err
	}
	if stream.Mode != gnmiModePoll {
		return nil
	}
	if err := subscribe.Send(&gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Poll{Poll: &gnmipb.Poll{}}}); err != nil {
		return classifySharedGNMIStreamError(err)
	}
	return receiveSharedGNMIProbeUntilSync(subscribe)
}

//nolint:staticcheck // Deprecated in-band Error responses remain on the supported gNMI wire protocol.
func receiveSharedGNMIProbeUntilSync(subscribe grpc.BidiStreamingClient[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
	for {
		response, err := subscribe.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return classifySharedGNMIStreamError(err)
		}
		switch body := response.GetResponse().(type) {
		case *gnmipb.SubscribeResponse_SyncResponse:
			if body.SyncResponse {
				return nil
			}
		case *gnmipb.SubscribeResponse_Error:
			if body.Error == nil {
				return errors.New("empty gNMI subscribe error")
			}
			return classifySharedGNMIStreamError(sanitizedGNMISubscribeStatusError(body.Error))
		}
	}
}

//nolint:staticcheck // Deprecated in-band Error responses remain on the supported gNMI wire protocol.
func receiveSharedGNMIProbeOnce(subscribe grpc.BidiStreamingClient[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
	synced := false
	for {
		response, err := subscribe.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if synced {
					return nil
				}
				return io.ErrUnexpectedEOF
			}
			return classifySharedGNMIStreamError(err)
		}
		switch body := response.GetResponse().(type) {
		case *gnmipb.SubscribeResponse_SyncResponse:
			synced = synced || body.SyncResponse
		case *gnmipb.SubscribeResponse_Error:
			if body.Error == nil {
				return errors.New("empty gNMI subscribe error")
			}
			return classifySharedGNMIStreamError(sanitizedGNMISubscribeStatusError(body.Error))
		}
	}
}

func (r *sharedGNMIReceiver) stopGNMIProfile(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
	reason string,
	err error,
	profileCancels map[string][]context.CancelFunc,
) {
	target.stopProfile(stream.Profile)
	for _, profileCancel := range profileCancels[stream.Profile] {
		profileCancel()
	}
	if target.config.Platform == gnmiPlatformNXOS && stream.Optics {
		target.clearNXSensorState()
	}
	r.telemetry.degraded(ctx, target.config.Name, stream.Profile, reason, true)
	r.settings.Logger.Error("Cisco gNMI profile stopped until receiver restart",
		zap.String("target", target.config.Name),
		zap.String("profile", stream.Profile),
		zap.Bool("required", stream.Required),
		zap.String("reason", reason),
		zap.Error(err))
}

func (r *sharedGNMIReceiver) runSubscription(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	client gnmipb.GNMIClient,
	stream sharedGNMIRuntimeStream,
	encoding gnmipb.Encoding,
) (bool, error) {
	r.telemetry.subscription(ctx, target.config.Name, stream.Profile, true)
	defer r.telemetry.subscription(context.Background(), target.config.Name, stream.Profile, false)
	request, err := buildSharedGNMISubscribeRequest(target.config, stream.sharedGNMIStream, encoding)
	if err != nil {
		return false, err
	}
	subscribe, err := client.Subscribe(sharedGNMIOutgoingContext(ctx, target.config))
	if err != nil {
		return false, classifySharedGNMIStreamError(err)
	}
	if err := subscribe.Send(request); err != nil {
		return false, classifySharedGNMIStreamError(err)
	}
	switch stream.Mode {
	case gnmiModeOnce:
		if err := subscribe.CloseSend(); err != nil {
			return false, classifySharedGNMIStreamError(err)
		}
		if err := r.receiveOnceToCompletion(ctx, target, stream, subscribe); err != nil {
			return false, err
		}
		return true, nil
	case gnmiModePoll:
		if err := r.receiveUntilSync(ctx, target, stream, subscribe); err != nil {
			return false, err
		}
		for {
			if err := subscribe.Send(&gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Poll{Poll: &gnmipb.Poll{}}}); err != nil {
				return false, classifySharedGNMIStreamError(err)
			}
			if err := r.receiveUntilSync(ctx, target, stream, subscribe); err != nil {
				return false, err
			}
			timer := time.NewTimer(stream.PollInterval)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return false, ctx.Err()
			case <-timer.C:
			}
		}
	case gnmiModeStream:
		for {
			response, err := subscribe.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return false, io.ErrUnexpectedEOF
				}
				return false, classifySharedGNMIStreamError(err)
			}
			if _, err := r.handleSubscribeResponse(ctx, target, stream, response); err != nil {
				return false, err
			}
		}
	default:
		return false, fmt.Errorf("unsupported gNMI subscription mode %q", stream.Mode)
	}
}

func (r *sharedGNMIReceiver) receiveOnceToCompletion(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
	subscribe grpc.BidiStreamingClient[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse],
) error {
	synced := false
	for {
		response, err := subscribe.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if synced {
					return nil
				}
				return io.ErrUnexpectedEOF
			}
			return classifySharedGNMIStreamError(err)
		}
		responseSynced, err := r.handleSubscribeResponse(ctx, target, stream, response)
		if err != nil {
			return err
		}
		synced = synced || responseSynced
	}
}

func (r *sharedGNMIReceiver) receiveUntilSync(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
	subscribe grpc.BidiStreamingClient[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse],
) error {
	for {
		response, err := subscribe.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return classifySharedGNMIStreamError(err)
		}
		synced, err := r.handleSubscribeResponse(ctx, target, stream, response)
		if err != nil {
			return err
		}
		if synced {
			return nil
		}
	}
}

//nolint:staticcheck // Deprecated in-band Error responses remain on the supported gNMI wire protocol.
func (r *sharedGNMIReceiver) handleSubscribeResponse(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
	response *gnmipb.SubscribeResponse,
) (bool, error) {
	switch body := response.GetResponse().(type) {
	case *gnmipb.SubscribeResponse_Update:
		if body.Update == nil {
			return false, nil
		}
		if err := r.processNotification(ctx, target, stream, body.Update); err != nil {
			return false, err
		}
		r.emitTargetAvailable(ctx, target)
		return false, nil
	case *gnmipb.SubscribeResponse_SyncResponse:
		if body.SyncResponse {
			r.emitTargetAvailable(ctx, target)
		}
		return body.SyncResponse, nil
	case *gnmipb.SubscribeResponse_Error:
		if body.Error == nil {
			return false, errors.New("empty gNMI subscribe error")
		}
		return false, classifySharedGNMIStreamError(sanitizedGNMISubscribeStatusError(body.Error))
	default:
		return false, nil
	}
}

func (r *sharedGNMIReceiver) processNotification(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
	notification *gnmipb.Notification,
) error {
	if target.profileStopped(stream.Profile) {
		return nil
	}
	receiptTime := time.Now()
	decoded, decodeStats, err := internalgnmi.DecodeNotification(target.config.Name, notification, receiptTime)
	if err != nil {
		r.telemetry.decodeErrors(ctx, target.config.Name, stream.Profile, 1)
		return nil
	}
	var nxTransaction *nxSensorTransaction
	if target.config.Platform == gnmiPlatformNXOS && stream.Optics {
		decoded, nxTransaction, err = target.prepareNXNotification(decoded)
		if err != nil {
			return &sharedGNMIProfileStopError{err: err}
		}
		defer func() {
			if nxTransaction != nil {
				nxTransaction.rollback()
			}
		}()
	}
	normalizeGNMIStateValues(&decoded)
	r.telemetry.updates(ctx, target.config.Name, stream.Profile, len(decoded.Updates))
	r.telemetry.invalidTimestamps(ctx, target.config.Name, stream.Profile, decodeStats.InvalidTimestamps)
	r.telemetry.deletes(ctx, target.config.Name, stream.Profile, len(decoded.Deletes))

	cacheNotification := internalgnmi.CacheNotification{
		Prefix: decoded.Prefix, Timestamp: decoded.Timestamp, Atomic: decoded.Atomic, Deletes: decoded.Deletes,
	}
	for _, touched := range decoded.Touched {
		cacheNotification.Touched = append(cacheNotification.Touched, touched.Clone())
	}
	unmapped := decodeStats.UnmappedValues
	for pointIndex := range decoded.Updates {
		point := &decoded.Updates[pointIndex]
		mapped, ok := stream.registry.Map(*point)
		if !ok {
			if !stream.HealthOnly {
				unmapped++
			}
			continue
		}
		maps.Copy(mapped.Attributes, stream.staticAttr[sharedGNMISeriesSourceKey(point.Series)])
		cacheNotification.Updates = append(cacheNotification.Updates, mapped)
	}
	r.telemetry.unmapped(ctx, target.config.Name, stream.Profile, unmapped)
	if stream.HealthOnly {
		r.telemetry.success(ctx, target.config.Name, stream.Profile, receiptTime)
		return nil
	}
	var result internalgnmi.CacheResult
	if nxTransaction != nil {
		// Hold the profile read lock through the cache and NX auxiliary-state
		// commit. stopGNMIProfile takes the write lock before clearing NX state,
		// so a sibling stream cannot publish after that cleanup boundary.
		target.stateMu.RLock()
		_, stopped := target.stopped[stream.Profile]
		if stopped {
			target.stateMu.RUnlock()
			return nil
		}
		result, err = target.cache.Apply(cacheNotification)
		if err == nil {
			if result.Rejected {
				nxTransaction.rollback()
			} else {
				nxTransaction.commit()
			}
			nxTransaction = nil
		}
		target.stateMu.RUnlock()
	} else {
		result, err = target.cache.Apply(cacheNotification)
	}
	if err != nil {
		var capacity *internalgnmi.CapacityError
		if errors.As(err, &capacity) {
			return &sharedGNMIProfileStopError{err: err}
		}
		return err
	}
	if target.profileStopped(stream.Profile) {
		return nil
	}
	r.telemetry.duplicates(ctx, target.config.Name, stream.Profile, result.Duplicates)
	r.telemetry.cacheUtilization(ctx, target.cache.Len(), r.maxCachedSeries)
	r.telemetry.success(ctx, target.config.Name, stream.Profile, receiptTime)
	points := append([]internalgnmi.MappedPoint(nil), result.Applied...)
	if stream.Optics {
		points = append(points, target.updateOpticalPresence(result, decoded.Timestamp)...)
	}
	chunks, err := internalgnmi.BuildMetricChunks(points, r.maxDatapoints)
	if err != nil {
		return err
	}
	for _, chunk := range chunks {
		decorateSharedGNMIResources(chunk, target.config)
		opCtx := startMetricsOp(ctx, r.obs)
		consumeErr := r.consumer.ConsumeMetrics(opCtx, chunk)
		endMetricsOp(opCtx, r.obs, chunk.DataPointCount(), consumeErr)
		if consumeErr != nil {
			r.telemetry.consumerRefusal(ctx, target.config.Name, stream.Profile)
			r.settings.Logger.Warn("Downstream consumer refused Cisco gNMI metric chunk; chunk dropped",
				zap.String("target", target.config.Name),
				zap.String("profile", stream.Profile),
				zap.Int("datapoints", chunk.DataPointCount()),
				zap.Error(consumeErr))
		}
	}
	return nil
}

func (target *sharedGNMITargetRuntime) clearNXSensorState() {
	target.nxMu.Lock()
	count := len(target.nxSensors)
	if count == 0 {
		target.nxMu.Unlock()
		return
	}
	_, started := target.nxBudget.beginChange(-count)
	if !started {
		target.nxMu.Unlock()
		return
	}
	target.nxSensors = map[string]nxSensorState{}
	target.nxMu.Unlock()
	target.nxBudget.finishChange(-count, true)
}

func (r *sharedGNMIReceiver) emitTargetAvailable(ctx context.Context, target *sharedGNMITargetRuntime) {
	if target.sessionUp.CompareAndSwap(false, true) {
		r.emitAvailability(ctx, target.config, true)
	}
}

func (r *sharedGNMIReceiver) emitAvailability(ctx context.Context, target GNMITargetConfig, up bool) {
	value := int64(0)
	if up {
		value = 1
	}
	point := internalgnmi.MappedPoint{
		Source: internalgnmi.Series{
			Target: target.Name, Origin: builtinGNMISyntheticReceiverOrigin,
			Elements: []internalgnmi.PathElem{{Name: "target"}, {Name: target.Platform}}, Leaf: "up",
		},
		Metric:     builtinGNMIMetricMetadata["cisco.device.up"],
		GaugeType:  internalgnmi.GaugeInt,
		MetricType: internalgnmi.MetricGauge,
		IntValue:   value,
		Timestamp:  time.Now(),
	}
	chunks, err := internalgnmi.BuildMetricChunks([]internalgnmi.MappedPoint{point}, 1)
	if err != nil || len(chunks) == 0 {
		return
	}
	decorateSharedGNMIResources(chunks[0], target)
	opCtx := startMetricsOp(ctx, r.obs)
	consumeErr := r.consumer.ConsumeMetrics(opCtx, chunks[0])
	endMetricsOp(opCtx, r.obs, chunks[0].DataPointCount(), consumeErr)
	if consumeErr != nil {
		r.telemetry.consumerRefusal(ctx, target.Name, builtinGNMIProfileIdentity)
	}
}

func decorateSharedGNMIResources(metrics pmetric.Metrics, target GNMITargetConfig) {
	osName := map[string]string{
		gnmiPlatformIOSXE: "Cisco IOS XE",
		gnmiPlatformIOSXR: "Cisco IOS XR",
		gnmiPlatformNXOS:  "Cisco NX-OS",
	}[target.Platform]
	host, _, splitErr := net.SplitHostPort(target.Endpoint)
	for i := 0; i < metrics.ResourceMetrics().Len(); i++ {
		attributes := metrics.ResourceMetrics().At(i).Resource().Attributes()
		attributes.PutStr("hw.type", "network")
		attributes.PutStr("cisco.os.name", target.Platform)
		attributes.PutStr("cisco.platform.family", target.Platform)
		attributes.PutStr("cisco.telemetry.transport", "gnmi_dial_in")
		if osName != "" {
			attributes.PutStr("os.name", osName)
		}
		if splitErr == nil {
			putIPAttr(attributes, "host.ip", host)
		}
	}
}

func (target *sharedGNMITargetRuntime) updateOpticalPresence(result internalgnmi.CacheResult, timestamp time.Time) []internalgnmi.MappedPoint {
	target.presenceMu.Lock()
	defer target.presenceMu.Unlock()
	emit := map[string]int64{}
	authoritativeAbsent := map[string]struct{}{}
	for pointIndex := range result.Applied {
		point := &result.Applied[pointIndex]
		if point.Metric.Name != "cisco.optics.present" || gnmiMappedPointIsPresent(*point) {
			continue
		}
		presenceKey, attrs := opticalPresenceIdentity(point.Attributes)
		if presenceKey == "" {
			continue
		}
		authoritativeAbsent[presenceKey] = struct{}{}
		target.presenceAttrs[presenceKey] = attrs
		for sourceKey, trackedPresence := range target.opticalSources {
			if trackedPresence == presenceKey {
				delete(target.opticalSources, sourceKey)
			}
		}
		delete(target.presenceCounts, presenceKey)
	}
	for pointIndex := range result.Applied {
		point := &result.Applied[pointIndex]
		if !strings.HasPrefix(point.Metric.Name, "cisco.optics.") {
			continue
		}
		sourceKey := point.Source.Key()
		presenceKey, attrs := opticalPresenceIdentity(point.Attributes)
		if presenceKey == "" {
			continue
		}
		if _, absent := authoritativeAbsent[presenceKey]; absent {
			continue
		}
		if previous, exists := target.opticalSources[sourceKey]; exists && previous != presenceKey {
			target.presenceCounts[previous]--
		}
		if target.opticalSources[sourceKey] != presenceKey {
			target.opticalSources[sourceKey] = presenceKey
			target.presenceCounts[presenceKey]++
		}
		target.presenceAttrs[presenceKey] = attrs
		if point.Metric.Name != "cisco.optics.present" {
			emit[presenceKey] = 1
		}
	}
	removedSources := make([]internalgnmi.MappedPoint, 0, len(result.Removed)+len(result.Replaced))
	removedSources = append(removedSources, result.Removed...)
	removedSources = append(removedSources, result.Replaced...)
	for pointIndex := range removedSources {
		point := &removedSources[pointIndex]
		sourceKey := point.Source.Key()
		presenceKey, exists := target.opticalSources[sourceKey]
		if !exists {
			continue
		}
		delete(target.opticalSources, sourceKey)
		target.presenceCounts[presenceKey]--
		if target.presenceCounts[presenceKey] <= 0 {
			delete(target.presenceCounts, presenceKey)
			emit[presenceKey] = 0
		}
	}
	for presenceKey := range authoritativeAbsent {
		delete(emit, presenceKey)
		delete(target.presenceAttrs, presenceKey)
	}
	points := make([]internalgnmi.MappedPoint, 0, len(emit))
	for presenceKey, value := range emit {
		attrs := cloneGNMIAttributes(target.presenceAttrs[presenceKey])
		if value == 0 {
			delete(target.presenceAttrs, presenceKey)
		}
		points = append(points, internalgnmi.MappedPoint{
			Source: internalgnmi.Series{Target: target.config.Name, Origin: builtinGNMISyntheticReceiverOrigin, Elements: []internalgnmi.PathElem{{Name: "optics-presence", Keys: map[string]string{"id": presenceKey}}}, Leaf: "present"},
			Metric: builtinGNMIMetricMetadata["cisco.optics.present"], GaugeType: internalgnmi.GaugeInt,
			MetricType: internalgnmi.MetricGauge, IntValue: value, Attributes: attrs, Timestamp: timestamp,
		})
	}
	return points
}

func gnmiMappedPointIsPresent(point internalgnmi.MappedPoint) bool {
	if point.GaugeType == internalgnmi.GaugeDouble {
		return point.DoubleValue != 0
	}
	return point.IntValue != 0
}

func opticalPresenceIdentity(attributes map[string]string) (string, map[string]string) {
	name := attributes["network.interface.name"]
	if name == "" {
		return "", nil
	}
	attrs := map[string]string{"network.interface.name": name}
	for _, key := range []string{"cisco.optics.lane", "cisco.optics.profile", "cisco.optics.experimental"} {
		if value := attributes[key]; value != "" {
			attrs[key] = value
		}
	}
	return name + "\x00" + attrs["cisco.optics.lane"] + "\x00" + attrs["cisco.optics.profile"], attrs
}

func (target *sharedGNMITargetRuntime) normalizeNXNotification(notification internalgnmi.DecodedNotification) (internalgnmi.DecodedNotification, error) {
	normalized, transaction, err := target.prepareNXNotification(notification)
	if err != nil {
		return notification, err
	}
	transaction.commit()
	return normalized, nil
}

func (target *sharedGNMITargetRuntime) prepareNXNotification(
	notification internalgnmi.DecodedNotification,
) (internalgnmi.DecodedNotification, *nxSensorTransaction, error) {
	if notification.Prefix.Origin == builtinGNMIOriginDME {
		notification.Prefix.Elements = normalizeNXDMEElements(notification.Prefix.Elements)
	}
	for i := range notification.Deletes {
		if notification.Deletes[i].Origin == builtinGNMIOriginDME {
			notification.Deletes[i].Elements = normalizeNXDMEElements(notification.Deletes[i].Elements)
		}
	}
	for i := range notification.Updates {
		if notification.Updates[i].Series.Origin == builtinGNMIOriginDME {
			notification.Updates[i].Series.Elements = normalizeNXDMEElements(notification.Updates[i].Series.Elements)
		}
	}
	for i := range notification.Touched {
		if notification.Touched[i].Origin == builtinGNMIOriginDME {
			notification.Touched[i].Elements = normalizeNXDMEElements(notification.Touched[i].Elements)
		}
	}

	target.nxMu.Lock()
	changes := map[string]nxSensorChange{}
	stagingExceeded := false
	getState := func(key string) (nxSensorState, bool) {
		if change, changed := changes[key]; changed {
			return change.state, change.exists
		}
		state, exists := target.nxSensors[key]
		return state, exists
	}
	maxInt := int(^uint(0) >> 1)
	stagingLimit := target.nxBudget.maximum
	if stagingLimit <= maxInt/2 {
		stagingLimit *= 2
	} else {
		stagingLimit = maxInt
	}
	setState := func(key string, state nxSensorState, exists bool) {
		if _, changed := changes[key]; !changed && len(changes) >= stagingLimit {
			stagingExceeded = true
			return
		}
		changes[key] = nxSensorChange{state: state, exists: exists}
	}
	removeStates := func(selector internalgnmi.Path, timestamp time.Time) {
		keys := make(map[string]struct{}, len(target.nxSensors)+len(changes))
		for key := range target.nxSensors {
			keys[key] = struct{}{}
		}
		for key := range changes {
			keys[key] = struct{}{}
		}
		for key := range keys {
			if stagingExceeded {
				return
			}
			state, exists := getState(key)
			if !exists {
				continue
			}
			if state.path.HasPrefix(selector) {
				if !state.descriptionTimestamp.After(timestamp) {
					state.description = ""
					state.descriptionTimestamp = timestamp
				}
				if !state.unitTimestamp.After(timestamp) {
					state.unit = ""
					state.unitTimestamp = timestamp
				}
				setState(key, state, state.description != "" || state.unit != "")
				continue
			}
			if !selector.HasPrefix(state.path) || len(selector.Elements) != len(state.path.Elements)+1 {
				continue
			}
			switch normalizeGNMILeaf(selector.Elements[len(selector.Elements)-1].Name) {
			case "description", "descr", "sensor-description":
				if !state.descriptionTimestamp.After(timestamp) {
					state.description = ""
					state.descriptionTimestamp = timestamp
				}
			case "unit", "units", "sensor-unit":
				if !state.unitTimestamp.After(timestamp) {
					state.unit = ""
					state.unitTimestamp = timestamp
				}
			default:
				continue
			}
			setState(key, state, state.description != "" || state.unit != "")
		}
	}
	if notification.Atomic {
		removeStates(notification.Prefix, notification.Timestamp)
	}
	for _, deleted := range notification.Deletes {
		if stagingExceeded {
			break
		}
		removeStates(deleted, notification.Timestamp)
	}
	for pointIndex := range notification.Updates {
		point := &notification.Updates[pointIndex]
		if stagingExceeded {
			break
		}
		if point.Series.Origin != builtinGNMIOriginDME {
			continue
		}
		key := sharedGNMIParentSeriesKey(point.Series)
		state, exists := getState(key)
		if point.Value.Kind == internalgnmi.ValueString {
			changed := false
			switch normalizeGNMILeaf(point.Series.Leaf) {
			case "description", "descr", "sensor-description":
				if exists && point.Timestamp.Before(state.descriptionTimestamp) {
					continue
				}
				state.description = point.Value.String
				state.descriptionTimestamp = point.Timestamp
				changed = true
			case "unit", "units", "sensor-unit":
				if exists && point.Timestamp.Before(state.unitTimestamp) {
					continue
				}
				state.unit = point.Value.String
				state.unitTimestamp = point.Timestamp
				changed = true
			}
			if !changed {
				continue
			}
			if target.cache.IsStale(point.Series.Path(), point.Timestamp) {
				continue
			}
			state.path = (internalgnmi.Path{Target: point.Series.Target, Origin: point.Series.Origin, Elements: point.Series.Elements}).Clone()
			setState(key, state, true)
		}
	}
	if stagingExceeded {
		target.nxMu.Unlock()
		return notification, nil, &internalgnmi.CapacityError{Limit: stagingLimit, Current: len(changes), Requested: len(changes) + 1}
	}
	for i := range notification.Updates {
		point := &notification.Updates[i]
		if point.Series.Origin != builtinGNMIOriginDME {
			continue
		}
		leaf := normalizeGNMILeaf(point.Series.Leaf)
		if leaf != "value" && leaf != "current-value" && leaf != "reading" {
			continue
		}
		state, _ := getState(sharedGNMIParentSeriesKey(point.Series))
		if point.Timestamp.Before(state.descriptionTimestamp) || point.Timestamp.Before(state.unitTimestamp) {
			continue
		}
		definition, ok := normalizeNXOpticsSensor(state.description, state.unit)
		if !ok {
			continue
		}
		point.Series.Leaf = strings.TrimPrefix(definition.Metric.Name, "cisco.optics.")
		point.Series.Leaf = strings.ReplaceAll(point.Series.Leaf, "_", "-")
		point.Value = scaleGNMIValue(point.Value, definition.Scale)
	}
	delta := 0
	//nolint:gocritic // A map range cannot take a stable pointer to its value.
	for key, change := range changes {
		_, existed := target.nxSensors[key]
		switch {
		case !existed && change.exists:
			delta++
		case existed && !change.exists:
			delta--
		}
	}
	transaction := &nxSensorTransaction{target: target, changes: changes, budgetDelta: delta}
	if delta != 0 {
		current, started := target.nxBudget.beginChange(delta)
		if !started {
			target.nxMu.Unlock()
			requested := max(0, current+delta)
			return notification, nil, &internalgnmi.CapacityError{Limit: target.nxBudget.maximum, Current: current, Requested: requested}
		}
		transaction.budgetLocked = true
	}
	return notification, transaction, nil
}

func scaleGNMIValue(value internalgnmi.Value, scale float64) internalgnmi.Value {
	if scale == 0 || scale == 1 {
		return value
	}
	switch value.Kind {
	case internalgnmi.ValueInt:
		return internalgnmi.DoubleValue(float64(value.Int) * scale)
	case internalgnmi.ValueUint:
		return internalgnmi.DoubleValue(float64(value.Uint) * scale)
	case internalgnmi.ValueDouble:
		return internalgnmi.DoubleValue(value.Double * scale)
	default:
		return value
	}
}

func normalizeNXDMEElements(elements []internalgnmi.PathElem) []internalgnmi.PathElem {
	out := make([]internalgnmi.PathElem, 0, len(elements)+1)
	for _, element := range elements {
		parts := splitNXDMEElement(element.Name)
		for partIndex, name := range parts {
			if strings.HasPrefix(name, "phys-[") && strings.HasSuffix(name, "]") {
				out = append(out, internalgnmi.PathElem{Name: "phys", Keys: map[string]string{"id": strings.TrimSuffix(strings.TrimPrefix(name, "phys-["), "]")}})
				continue
			}
			if laneAndSensor, hasLane := strings.CutPrefix(name, "lane-"); hasLane {
				if lane, sensor, found := strings.Cut(laneAndSensor, "-sensor-"); found && lane != "" && sensor != "" {
					out = append(out,
						internalgnmi.PathElem{Name: "lane", Keys: map[string]string{"id": lane}},
						internalgnmi.PathElem{Name: "sensor", Keys: map[string]string{"id": sensor}},
					)
					continue
				}
			}
			keys := map[string]string(nil)
			if partIndex == len(parts)-1 {
				keys = element.Keys
			}
			out = append(out, internalgnmi.PathElem{Name: name, Keys: keys})
		}
	}
	return out
}

func splitNXDMEElement(value string) []string {
	if !strings.Contains(value, "/") {
		return []string{value}
	}
	parts := make([]string, 0, strings.Count(value, "/")+1)
	start, depth := 0, 0
	for index, char := range value {
		switch char {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case '/':
			if depth == 0 {
				if index > start {
					parts = append(parts, value[start:index])
				}
				start = index + 1
			}
		}
	}
	if start < len(value) {
		parts = append(parts, value[start:])
	}
	if len(parts) == 0 {
		return []string{value}
	}
	return parts
}

func normalizeGNMIStateValues(notification *internalgnmi.DecodedNotification) {
	for i := range notification.Updates {
		point := &notification.Updates[i]
		if point.Value.Kind != internalgnmi.ValueString {
			continue
		}
		switch normalizeGNMILeaf(point.Series.Leaf) {
		case "oper-status", "admin-status", "present", "is-joined":
			switch strings.ToLower(strings.TrimSpace(point.Value.String)) {
			case "up", "on", "true", "active", "enabled", "present", "joined", "ok":
				point.Value = internalgnmi.BoolValue(true)
			case "down", "off", "false", "inactive", "disabled", "absent", "not-present", "not joined", "failed":
				point.Value = internalgnmi.BoolValue(false)
			}
		}
	}
}

func normalizeGNMILeaf(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "_", "-"))
}

func classifySharedGNMIStreamError(err error) error {
	if err == nil {
		return nil
	}
	switch status.Code(err) {
	case codes.InvalidArgument, codes.Unimplemented:
		return &sharedGNMIUnsupportedError{err: err}
	default:
		return err
	}
}

func isSharedGNMIAuthenticationError(err error) bool {
	if err == nil {
		return false
	}
	switch status.Code(err) {
	case codes.Unauthenticated, codes.PermissionDenied:
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "authentication") || strings.Contains(message, "certificate") || strings.Contains(message, "unknown authority")
}

func sharedGNMIOutgoingContext(ctx context.Context, target GNMITargetConfig) context.Context {
	if target.Credentials.Mode != gnmiCredentialUsernamePassword && target.Credentials.Mode != gnmiCredentialMTLSUsernamePassword {
		return ctx
	}
	return grpcmetadata.AppendToOutgoingContext(ctx,
		"username", target.Credentials.Username,
		"password", string(target.Credentials.Password),
	)
}

func equalJitterGNMIBackoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	base := sharedGNMIInitialBackoff
	for range min(attempt, 8) {
		if base >= sharedGNMIMaximumBackoff/2 {
			base = sharedGNMIMaximumBackoff
			break
		}
		base *= 2
	}
	half := base / 2
	return half + time.Duration(rand.Int64N(int64(base-half)+1))
}

func waitSharedGNMIBackoff(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (target *sharedGNMITargetRuntime) isolatePath(path sharedGNMIPath) {
	target.stateMu.Lock()
	defer target.stateMu.Unlock()
	target.isolate[sharedGNMIPathKey(path)] = struct{}{}
}

func (target *sharedGNMITargetRuntime) stopProfile(profile string) {
	target.stateMu.Lock()
	defer target.stateMu.Unlock()
	target.stopped[profile] = struct{}{}
}

func (target *sharedGNMITargetRuntime) profileStopped(profile string) bool {
	target.stateMu.RLock()
	defer target.stateMu.RUnlock()
	_, stopped := target.stopped[profile]
	return stopped
}

func (target *sharedGNMITargetRuntime) pathIsolated(path sharedGNMIPath) bool {
	target.stateMu.RLock()
	defer target.stateMu.RUnlock()
	_, isolated := target.isolate[sharedGNMIPathKey(path)]
	return isolated
}

func (target *sharedGNMITargetRuntime) recordRejectedPathSet(key string) int {
	target.stateMu.Lock()
	defer target.stateMu.Unlock()
	target.rejects[key]++
	return target.rejects[key]
}

func (target *sharedGNMITargetRuntime) filterIsolated(paths []sharedGNMIPath) []sharedGNMIPath {
	target.stateMu.RLock()
	defer target.stateMu.RUnlock()
	out := make([]sharedGNMIPath, 0, len(paths))
	for _, path := range paths {
		if _, isolated := target.isolate[sharedGNMIPathKey(path)]; !isolated {
			out = append(out, path)
		}
	}
	return out
}

func sharedGNMIPathKey(path sharedGNMIPath) string { return path.Origin + "\x00" + path.Path }

func sharedGNMIRejectedPathSetKey(stream sharedGNMIRuntimeStream) string {
	var key strings.Builder
	key.WriteString(stream.Profile)
	key.WriteByte(0)
	key.WriteString(stream.Mode)
	for _, path := range stream.Paths {
		key.WriteByte(0)
		key.WriteString(sharedGNMIPathKey(path))
	}
	return key.String()
}

func runtimeSharedGNMIStreams(streams []sharedGNMIRuntimeStream) []sharedGNMIStream {
	out := make([]sharedGNMIStream, len(streams))
	for i := range streams {
		out[i] = streams[i].sharedGNMIStream
	}
	return out
}

func sharedGNMISourceKey(source internalgnmi.SourcePath) string {
	return source.Origin + "\x00" + strings.Join(source.Elements, "\x00") + "\x00" + source.Leaf
}

func sharedGNMISeriesSourceKey(series internalgnmi.Series) string {
	elements := make([]string, len(series.Elements))
	for i := range series.Elements {
		elements[i] = series.Elements[i].Name
	}
	return sharedGNMISourceKey(internalgnmi.SourcePath{Origin: series.Origin, Elements: elements, Leaf: series.Leaf})
}

func sharedGNMIParentSeriesKey(series internalgnmi.Series) string {
	return (internalgnmi.Path{Target: series.Target, Origin: series.Origin, Elements: series.Elements}).Key()
}

func cloneGNMIAttributes(attributes map[string]string) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	return maps.Clone(attributes)
}

func sharedGNMITargetIdentity(target GNMITargetConfig) deviceIdentity {
	host, _, err := net.SplitHostPort(target.Endpoint)
	if err != nil {
		host = target.Endpoint
	}
	return deviceIdentity{
		hostNames: []string{target.Name, host},
		hostIDs:   []string{target.Name, target.Endpoint, host},
		hostIPs:   []string{host},
		deviceIDs: []string{target.Name, target.Endpoint, host},
	}
}

var _ receiver.Metrics = (*sharedGNMIReceiver)(nil)
