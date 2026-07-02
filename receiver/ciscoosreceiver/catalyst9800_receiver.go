// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	yanggrpcreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver"
)

type catalyst9800CompositeReceiver struct {
	receivers []receiver.Metrics
}

func newCatalyst9800MetricsReceiver(set receiver.Settings, conf *Config, next consumer.Metrics) (receiver.Metrics, error) {
	cfg := conf.Catalyst9800.withDefaults()
	selector := newDeviceSelectionMatcher(conf.DeviceSelection)
	var receivers []receiver.Metrics

	if len(cfg.DialIn.Targets) > 0 {
		targets := make([]Catalyst9800TargetConfig, 0, len(cfg.DialIn.Targets))
		for i := range cfg.DialIn.Targets {
			target := cfg.DialIn.Targets[i].withDefaults(cfg)
			if selector.allows(catalyst9800TargetIdentity(target)) {
				targets = append(targets, target)
			}
		}
		if len(targets) > 0 {
			dialIn := &catalyst9800DialInReceiver{
				settings: set,
				config:   cfg,
				targets:  targets,
				consumer: next,
				health:   &catalyst9800Health{},
				done:     make(chan struct{}),
			}
			receivers = append(receivers, dialIn)
		}
	}

	if cfg.DialOut.Enabled {
		dialOut, err := newCatalyst9800DialOutReceiver(set, cfg, selector, next)
		if err != nil {
			return nil, err
		}
		receivers = append(receivers, dialOut)
	}

	if len(receivers) == 0 {
		return &nopMetricsReceiver{}, nil
	}
	if len(receivers) == 1 {
		return receivers[0], nil
	}
	return &catalyst9800CompositeReceiver{receivers: receivers}, nil
}

func (r *catalyst9800CompositeReceiver) Start(ctx context.Context, host component.Host) error {
	return startMetricsReceivers(ctx, host, r.receivers)
}

func (r *catalyst9800CompositeReceiver) Shutdown(ctx context.Context) error {
	var err error
	for _, receiver := range r.receivers {
		err = multierr.Append(err, receiver.Shutdown(ctx))
	}
	return err
}

func newCatalyst9800DialOutReceiver(set receiver.Settings, cfg Catalyst9800Config, selector deviceSelectionMatcher, next consumer.Metrics) (receiver.Metrics, error) {
	factory := yanggrpcreceiver.NewFactory()
	yangCfg := factory.CreateDefaultConfig().(*yanggrpcreceiver.Config)
	yangCfg.ServerConfig = cfg.DialOut.ServerConfig
	yangCfg.Security.AllowedClients = cfg.DialOut.AllowedClients
	yangCfg.Security.RateLimiting = cfg.DialOut.RateLimiting
	yangCfg.YANG.ModulePaths = cfg.DialOut.ModulePaths
	health := &catalyst9800Health{}
	normalizer := newCatalyst9800NormalizingConsumer(next, cfg, selector, health)
	return factory.CreateMetrics(context.Background(), set, yangCfg, normalizer)
}

type catalyst9800DialInReceiver struct {
	settings receiver.Settings
	config   Catalyst9800Config
	targets  []Catalyst9800TargetConfig
	consumer consumer.Metrics
	health   *catalyst9800Health

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
	host   component.Host

	subscribeTargetFn func(context.Context, Catalyst9800TargetConfig) (bool, error)
	retryWaitFn       func(context.Context, time.Duration) bool
	retryJitterFn     func(time.Duration) time.Duration
}

func (r *catalyst9800DialInReceiver) Start(_ context.Context, host component.Host) error {
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

func (r *catalyst9800DialInReceiver) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	cancel := r.cancel
	r.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *catalyst9800DialInReceiver) run(ctx context.Context) {
	defer close(r.done)
	var wg sync.WaitGroup
	for i := range r.targets {
		target := r.targets[i]
		wg.Go(func() {
			r.runTarget(ctx, target)
		})
	}
	wg.Wait()
}

func (r *catalyst9800DialInReceiver) runTarget(ctx context.Context, target Catalyst9800TargetConfig) {
	subscribe := r.subscribeTargetAttempt
	if r.subscribeTargetFn != nil {
		subscribe = r.subscribeTargetFn
	}
	waitRetry := waitForDirectGNMIRetry
	if r.retryWaitFn != nil {
		waitRetry = r.retryWaitFn
	}
	r.emitTargetHealth(ctx, target)
	consecutiveFailures := 0
	for {
		if ctx.Err() != nil {
			return
		}
		successful, err := subscribe(ctx, target)
		r.setTargetSubscriptionActive(ctx, target, false)
		if ctx.Err() != nil {
			return
		}
		if target.Subscription.Mode == iosXRSubscribeModeOnce && err == nil {
			return
		}
		if successful {
			consecutiveFailures = 0
		} else {
			consecutiveFailures++
		}
		if r.health != nil {
			r.health.addTargetReconnects(target.Name, 1)
		}
		if err != nil {
			r.settings.Logger.Warn("Catalyst 9800 gNMI subscription failed",
				zap.String("target", target.Name),
				zap.String("endpoint", target.Endpoint),
				zap.Error(err))
		}
		r.emitTargetHealth(ctx, target)
		retryOrdinal := consecutiveFailures
		if retryOrdinal == 0 {
			retryOrdinal = 1
		}
		delay := nextDirectGNMIRetryDelay(retryOrdinal, r.retryJitterFn)
		if !waitRetry(ctx, delay) {
			return
		}
	}
}

func (r *catalyst9800DialInReceiver) subscribeTargetAttempt(ctx context.Context, target Catalyst9800TargetConfig) (bool, error) {
	conn, err := target.ClientConfig.ToClientConn(ctx, r.host.GetExtensions(), r.settings.TelemetrySettings, configgrpc.WithGrpcDialOption(grpc.WithBlock())) //nolint:staticcheck // Blocking dial semantics remain required by the collector gNMI connection path.
	if err != nil {
		return false, err
	}
	defer conn.Close()

	client := gnmi.NewGNMIClient(conn)
	caps := &gnmi.CapabilityResponse{}
	if !target.SkipCapabilities {
		capCtx, cancel := context.WithTimeout(r.outgoingContext(ctx, target), 15*time.Second)
		defer cancel()
		caps, err = client.Capabilities(capCtx, &gnmi.CapabilityRequest{})
		if err != nil {
			return false, fmt.Errorf("capabilities: %w", err)
		}
	}

	paths, err := r.resolveTargetPaths(target, caps)
	if err != nil {
		return false, err
	}
	if len(paths) == 0 {
		return false, errors.New("no Catalyst 9800 paths available after capability filtering")
	}
	encoding, err := negotiateCatalyst9800Encoding(target.EncodingPreference, caps)
	if err != nil {
		return false, err
	}

	streamCtx, cancelStream := context.WithCancel(r.outgoingContext(ctx, target))
	defer cancelStream()
	stream, err := client.Subscribe(streamCtx)
	if err != nil {
		return false, err
	}
	if sendErr := stream.Send(buildCatalyst9800SubscribeRequest(target.Subscription, paths, encoding)); sendErr != nil {
		return false, sendErr
	}
	r.setTargetSubscriptionActive(ctx, target, true)
	defer r.setTargetSubscriptionActive(ctx, target, false)
	var progressed atomic.Bool

	if target.Subscription.Mode == iosXRSubscribeModePoll {
		recvErr := r.recvPoll(streamCtx, cancelStream, target, stream, &progressed)
		return progressed.Load(), recvErr
	}
	if target.Subscription.Mode == iosXRSubscribeModeOnce {
		if closeErr := stream.CloseSend(); closeErr != nil {
			r.settings.Logger.Debug("Catalyst 9800 gNMI once close send failed", zap.Error(closeErr))
		}
	}
	recvErr := r.recvLoop(ctx, target, stream, &progressed)
	return progressed.Load(), recvErr
}

func (r *catalyst9800DialInReceiver) setTargetSubscriptionActive(ctx context.Context, target Catalyst9800TargetConfig, active bool) {
	if r.health == nil || !r.health.setTargetSubscriptionActive(target.Name, active) {
		return
	}
	r.emitTargetHealth(ctx, target)
}

func (r *catalyst9800DialInReceiver) emitTargetHealth(ctx context.Context, target Catalyst9800TargetConfig) {
	if r.health == nil || r.consumer == nil || ctx.Err() != nil {
		return
	}
	md := pmetric.NewMetrics()
	appendCatalyst9800HealthMetrics(md, r.health, catalyst9800MetricContext{
		targetName:     target.Name,
		endpoint:       target.Endpoint,
		platformFamily: target.PlatformFamily,
		transport:      catalyst9800TelemetryTransportDialIn,
	}, pcommon.NewTimestampFromTime(time.Now()))
	if err := r.consumer.ConsumeMetrics(ctx, md); err != nil {
		r.settings.Logger.Warn("Catalyst 9800 gNMI health delivery failed", zap.String("target", target.Name), zap.Error(err))
	}
}

func (r *catalyst9800DialInReceiver) recvPoll(ctx context.Context, cancelStream context.CancelFunc, target Catalyst9800TargetConfig, stream grpc.BidiStreamingClient[gnmi.SubscribeRequest, gnmi.SubscribeResponse], progressed *atomic.Bool) error {
	interval := target.Subscription.PollInterval
	if interval <= 0 {
		interval = target.Subscription.SampleInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if err := stream.Send(&gnmi.SubscribeRequest{Request: &gnmi.SubscribeRequest_Poll{Poll: &gnmi.Poll{}}}); err != nil {
		return err
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- r.recvLoop(ctx, target, stream, progressed)
	}()
	readerJoined := false
	defer func() {
		cancelStream()
		if !readerJoined {
			<-errCh
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			readerJoined = true
			return err
		case <-ticker.C:
			if err := stream.Send(&gnmi.SubscribeRequest{Request: &gnmi.SubscribeRequest_Poll{Poll: &gnmi.Poll{}}}); err != nil {
				return err
			}
		}
	}
}

func (r *catalyst9800DialInReceiver) recvLoop(ctx context.Context, target Catalyst9800TargetConfig, stream grpc.BidiStreamingClient[gnmi.SubscribeRequest, gnmi.SubscribeResponse], progressed *atomic.Bool) error {
	decoder := catalyst9800GNMIUpdateDecoder{target: target, health: r.health, maxDatapoints: r.config.MaxDatapointsPerBatch}
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch body := resp.GetResponse().(type) {
		case *gnmi.SubscribeResponse_Update:
			if body.Update == nil {
				continue
			}
			r.health.addTargetUpdates(target.Name, int64(len(body.Update.GetUpdate())+len(body.Update.GetDelete())))
			md := decoder.decodeNotification(body.Update)
			if md.MetricCount() == 0 {
				progressed.Store(true)
				continue
			}
			if r.config.MaxDatapointsPerBatch > 0 {
				dropped := enforceIOSXRDatapointLimit(md, r.config.MaxDatapointsPerBatch)
				if dropped > 0 {
					r.health.addDroppedDatapoints(int64(dropped))
				}
			}
			if err := r.consumer.ConsumeMetrics(ctx, md); err != nil {
				return err
			}
			progressed.Store(true)
		case *gnmi.SubscribeResponse_SyncResponse:
			if body.SyncResponse {
				progressed.Store(true)
				r.settings.Logger.Debug("Catalyst 9800 gNMI initial sync complete", zap.String("target", target.Name))
			}
		case *gnmi.SubscribeResponse_Error:
			protocolErr := body.Error //nolint:staticcheck // Older gNMI targets still send the deprecated SubscribeResponse error field.
			if protocolErr != nil {
				return sanitizedGNMISubscribeError(protocolErr)
			}
		}
	}
}

func (*catalyst9800DialInReceiver) outgoingContext(ctx context.Context, target Catalyst9800TargetConfig) context.Context {
	return metadata.AppendToOutgoingContext(ctx,
		"username", target.Credentials.Username,
		"password", string(target.Credentials.Password),
	)
}

func (r *catalyst9800DialInReceiver) resolveTargetPaths(target Catalyst9800TargetConfig, caps *gnmi.CapabilityResponse) ([]catalyst9800PathDefinition, error) {
	selected := resolveCatalyst9800PathSelection(r.config.PathGroups, r.config.Paths, &target)
	if target.SkipCapabilities || caps == nil || len(caps.GetSupportedModels()) == 0 {
		return selected, nil
	}
	supported := map[string]struct{}{}
	for _, model := range caps.GetSupportedModels() {
		supported[strings.ToLower(model.GetName())] = struct{}{}
	}
	out := make([]catalyst9800PathDefinition, 0, len(selected))
	var unsupported []string
	for i := range selected {
		def := selected[i]
		candidates := catalyst9800ModuleCandidates(def.Path)
		if len(candidates) == 0 {
			out = append(out, def)
			continue
		}
		if catalyst9800AnyModelSupported(candidates, supported) {
			out = append(out, def)
			continue
		}
		unsupported = append(unsupported, def.Path)
	}
	if len(unsupported) > 0 {
		r.health.addUnsupportedPaths(int64(len(unsupported)))
		switch r.config.UnsupportedPathAction {
		case iosXRUnsupportedError:
			return nil, fmt.Errorf("Catalyst 9800 target %s does not advertise models for paths: %s", target.Name, strings.Join(unsupported, ", "))
		case iosXRUnsupportedWarn:
			r.settings.Logger.Warn("Catalyst 9800 target does not advertise models for some configured paths",
				zap.String("target", target.Name),
				zap.Strings("paths", unsupported))
		}
	}
	return out, nil
}

func catalyst9800AnyModelSupported(candidates []string, supported map[string]struct{}) bool {
	for _, candidate := range candidates {
		if _, ok := supported[strings.ToLower(candidate)]; ok {
			return true
		}
	}
	return false
}

func negotiateCatalyst9800Encoding(preferences []string, caps *gnmi.CapabilityResponse) (gnmi.Encoding, error) {
	if len(preferences) == 0 {
		preferences = []string{"json_ietf", "json"}
	}
	if caps == nil || len(caps.GetSupportedEncodings()) == 0 {
		encoding, _ := encodingNameToGNMI(preferences[0])
		return encoding, nil
	}
	supported := map[gnmi.Encoding]struct{}{}
	for _, encoding := range caps.GetSupportedEncodings() {
		supported[encoding] = struct{}{}
	}
	for _, preference := range preferences {
		encoding, ok := encodingNameToGNMI(preference)
		if !ok || encoding == gnmi.Encoding_PROTO {
			continue
		}
		if _, ok := supported[encoding]; ok {
			return encoding, nil
		}
	}
	return gnmi.Encoding_JSON, fmt.Errorf("target does not support requested Catalyst 9800 encodings: %s", strings.Join(preferences, ", "))
}

func buildCatalyst9800SubscribeRequest(sub Catalyst9800SubscriptionConfig, paths []catalyst9800PathDefinition, encoding gnmi.Encoding) *gnmi.SubscribeRequest {
	list := &gnmi.SubscriptionList{
		Mode:             subscriptionListMode(sub.Mode),
		Encoding:         encoding,
		UpdatesOnly:      sub.updatesOnly(),
		AllowAggregation: sub.allowAggregation(),
		Subscription:     make([]*gnmi.Subscription, 0, len(paths)),
	}
	for i := range paths {
		def := paths[i]
		if strings.Contains(def.Path, "*") {
			continue
		}
		p, err := parseGNMIPath(def.Path)
		if err != nil {
			continue
		}
		streamMode := sub.StreamMode
		if def.DefaultStreamMode != "" {
			streamMode = def.DefaultStreamMode
		}
		if streamMode == "" {
			streamMode = iosXRStreamModeSample
		}
		if streamMode == iosXRStreamModeTargetDefined && !strings.HasPrefix(def.Path, "openconfig-") && !strings.HasPrefix(def.Path, "ietf-") {
			streamMode = iosXRStreamModeSample
		}
		mode := subscriptionStreamMode(streamMode)
		sampleInterval := max(sub.SampleInterval, def.MinSampleInterval)
		sampleIntervalNanos := uint64(sampleInterval.Nanoseconds())
		if mode == gnmi.SubscriptionMode_ON_CHANGE {
			sampleIntervalNanos = 0
		}
		list.Subscription = append(list.Subscription, &gnmi.Subscription{
			Path:              p,
			Mode:              mode,
			SampleInterval:    sampleIntervalNanos,
			SuppressRedundant: sub.suppressRedundant(),
			HeartbeatInterval: uint64(sub.HeartbeatInterval.Nanoseconds()),
		})
	}
	return &gnmi.SubscribeRequest{Request: &gnmi.SubscribeRequest_Subscribe{Subscribe: list}}
}

func catalyst9800TargetIdentity(target Catalyst9800TargetConfig) deviceIdentity {
	host, _, _ := net.SplitHostPort(target.Endpoint)
	return deviceIdentity{
		hostNames: []string{target.Name},
		hostIDs:   []string{target.Name, target.Endpoint, host},
		hostIPs:   []string{host},
		deviceIDs: []string{target.Name, target.Endpoint, host},
	}
}

var (
	_ receiver.Metrics = (*catalyst9800CompositeReceiver)(nil)
	_ receiver.Metrics = (*catalyst9800DialInReceiver)(nil)
	_ consumer.Metrics = (*catalyst9800NormalizingConsumer)(nil)
	_                  = pmetric.NewMetrics
)
