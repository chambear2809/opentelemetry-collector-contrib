// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
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

type iosXRCompositeReceiver struct {
	receivers []receiver.Metrics
}

const (
	directGNMIRetryInitial = time.Second
	directGNMIRetryMax     = 30 * time.Second
)

func nextDirectGNMIRetryDelay(consecutiveFailures int, random func(time.Duration) time.Duration) time.Duration {
	if consecutiveFailures < 1 {
		consecutiveFailures = 1
	}
	base := directGNMIRetryInitial
	for failure := 1; failure < consecutiveFailures && base < directGNMIRetryMax; failure++ {
		if base > directGNMIRetryMax/2 {
			base = directGNMIRetryMax
		} else {
			base *= 2
		}
	}
	if base > directGNMIRetryMax {
		base = directGNMIRetryMax
	}
	// Equal jitter keeps retries in [base/2, base), bounding the maximum delay
	// while preventing synchronized reconnect storms across many targets.
	half := base / 2
	span := base - half
	if random == nil {
		random = randomDirectGNMIDuration
	}
	jitter := random(span)
	if jitter < 0 {
		jitter = 0
	}
	if jitter >= span {
		jitter = span - 1
	}
	return half + jitter
}

func randomDirectGNMIDuration(max time.Duration) time.Duration {
	if max <= 1 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(max))) //nolint:gosec // Retry jitter does not require cryptographic randomness.
}

func waitForDirectGNMIRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func newIOSXRMetricsReceiver(set receiver.Settings, conf *Config, next consumer.Metrics) (receiver.Metrics, error) {
	cfg := conf.IOSXR.withDefaults()
	selector := newDeviceSelectionMatcher(conf.DeviceSelection)
	var receivers []receiver.Metrics

	if len(cfg.DialIn.Targets) > 0 {
		targets := make([]IOSXRTargetConfig, 0, len(cfg.DialIn.Targets))
		for _, target := range cfg.DialIn.Targets {
			target = target.withDefaults(cfg)
			if selector.allows(iosXRTargetIdentity(target)) {
				targets = append(targets, target)
			}
		}
		if len(targets) > 0 {
			dialIn := &iosXRDialInReceiver{
				settings: set,
				config:   cfg,
				targets:  targets,
				consumer: next,
				health:   &iosXRHealth{},
				done:     make(chan struct{}),
			}
			receivers = append(receivers, dialIn)
		}
	}

	if cfg.DialOut.Enabled {
		dialOut, err := newIOSXRDialOutReceiver(set, cfg, selector, next)
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
	return &iosXRCompositeReceiver{receivers: receivers}, nil
}

func (r *iosXRCompositeReceiver) Start(ctx context.Context, host component.Host) error {
	return startMetricsReceivers(ctx, host, r.receivers)
}

func (r *iosXRCompositeReceiver) Shutdown(ctx context.Context) error {
	var err error
	for _, receiver := range r.receivers {
		err = multierr.Append(err, receiver.Shutdown(ctx))
	}
	return err
}

func newIOSXRDialOutReceiver(set receiver.Settings, cfg IOSXRConfig, selector deviceSelectionMatcher, next consumer.Metrics) (receiver.Metrics, error) {
	factory := yanggrpcreceiver.NewFactory()
	yangCfg := factory.CreateDefaultConfig().(*yanggrpcreceiver.Config)
	yangCfg.ServerConfig = cfg.DialOut.ServerConfig
	yangCfg.Security.AllowedClients = cfg.DialOut.AllowedClients
	yangCfg.YANG.ModulePaths = cfg.DialOut.ModulePaths
	health := &iosXRHealth{}
	normalizer := newIOSXRNormalizingConsumer(next, cfg, selector, iosXRTelemetryTransportDialOut, health)
	return factory.CreateMetrics(context.Background(), set, yangCfg, normalizer)
}

type iosXRDialInReceiver struct {
	settings receiver.Settings
	config   IOSXRConfig
	targets  []IOSXRTargetConfig
	consumer consumer.Metrics
	health   *iosXRHealth

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
	host   component.Host

	subscribeTargetFn func(context.Context, IOSXRTargetConfig) (bool, error)
	retryWaitFn       func(context.Context, time.Duration) bool
	retryJitterFn     func(time.Duration) time.Duration
}

func (r *iosXRDialInReceiver) Start(_ context.Context, host component.Host) error {
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

func (r *iosXRDialInReceiver) Shutdown(ctx context.Context) error {
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

func (r *iosXRDialInReceiver) run(ctx context.Context) {
	defer close(r.done)
	var wg sync.WaitGroup
	for _, target := range r.targets {
		target := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.runTarget(ctx, target)
		}()
	}
	wg.Wait()
}

func (r *iosXRDialInReceiver) runTarget(ctx context.Context, target IOSXRTargetConfig) {
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
			r.settings.Logger.Warn("IOS XR gNMI subscription failed",
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

func (r *iosXRDialInReceiver) subscribeTarget(ctx context.Context, target IOSXRTargetConfig) error {
	_, err := r.subscribeTargetAttempt(ctx, target)
	return err
}

func (r *iosXRDialInReceiver) subscribeTargetAttempt(ctx context.Context, target IOSXRTargetConfig) (bool, error) {
	conn, err := target.ClientConfig.ToClientConn(ctx, r.host.GetExtensions(), r.settings.TelemetrySettings, configgrpc.WithGrpcDialOption(grpc.WithBlock()))
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
		return false, errors.New("no IOS XR paths available after capability filtering")
	}
	encoding, err := negotiateIOSXREncoding(target.EncodingPreference, caps)
	if err != nil {
		return false, err
	}

	stream, err := client.Subscribe(r.outgoingContext(ctx, target))
	if err != nil {
		return false, err
	}
	if err := stream.Send(buildIOSXRSubscribeRequest(target.Subscription, paths, encoding)); err != nil {
		return false, err
	}
	r.setTargetSubscriptionActive(ctx, target, true)
	defer r.setTargetSubscriptionActive(ctx, target, false)

	if target.Subscription.Mode == iosXRSubscribeModePoll {
		return true, r.recvPoll(ctx, target, stream)
	}
	if target.Subscription.Mode == iosXRSubscribeModeOnce {
		if closeErr := stream.CloseSend(); closeErr != nil {
			r.settings.Logger.Debug("IOS XR gNMI once close send failed", zap.Error(closeErr))
		}
	}
	return true, r.recvLoop(ctx, target, stream)
}

func (r *iosXRDialInReceiver) setTargetSubscriptionActive(ctx context.Context, target IOSXRTargetConfig, active bool) {
	if r.health == nil || !r.health.setTargetSubscriptionActive(target.Name, active) {
		return
	}
	r.emitTargetHealth(ctx, target)
}

func (r *iosXRDialInReceiver) emitTargetHealth(ctx context.Context, target IOSXRTargetConfig) {
	if r.health == nil || r.consumer == nil || ctx.Err() != nil {
		return
	}
	md := pmetric.NewMetrics()
	appendIOSXRHealthMetrics(md, r.health, iosXRMetricContext{
		targetName:     target.Name,
		endpoint:       target.Endpoint,
		platformFamily: target.PlatformFamily,
		transport:      iosXRTelemetryTransportDialIn,
	}, pcommon.NewTimestampFromTime(time.Now()))
	if err := r.consumer.ConsumeMetrics(ctx, md); err != nil {
		r.settings.Logger.Warn("IOS XR gNMI health delivery failed", zap.String("target", target.Name), zap.Error(err))
	}
}

func (r *iosXRDialInReceiver) recvPoll(ctx context.Context, target IOSXRTargetConfig, stream grpc.BidiStreamingClient[gnmi.SubscribeRequest, gnmi.SubscribeResponse]) error {
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
		errCh <- r.recvLoop(ctx, target, stream)
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			return err
		case <-ticker.C:
			if err := stream.Send(&gnmi.SubscribeRequest{Request: &gnmi.SubscribeRequest_Poll{Poll: &gnmi.Poll{}}}); err != nil {
				return err
			}
		}
	}
}

func (r *iosXRDialInReceiver) recvLoop(ctx context.Context, target IOSXRTargetConfig, stream grpc.BidiStreamingClient[gnmi.SubscribeRequest, gnmi.SubscribeResponse]) error {
	decoder := iosXRGNMIUpdateDecoder{target: target, health: r.health}
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
			md := decoder.decodeNotification(body.Update, iosXRTelemetryTransportDialIn)
			if md.MetricCount() == 0 {
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
		case *gnmi.SubscribeResponse_SyncResponse:
			if body.SyncResponse {
				r.settings.Logger.Debug("IOS XR gNMI initial sync complete", zap.String("target", target.Name))
			}
		case *gnmi.SubscribeResponse_Error:
			if body.Error != nil {
				return fmt.Errorf("subscribe response error: %s", body.Error.GetMessage())
			}
		}
	}
}

func (r *iosXRDialInReceiver) outgoingContext(ctx context.Context, target IOSXRTargetConfig) context.Context {
	return metadata.AppendToOutgoingContext(ctx,
		"username", target.Credentials.Username,
		"password", string(target.Credentials.Password),
	)
}

func (r *iosXRDialInReceiver) resolveTargetPaths(target IOSXRTargetConfig, caps *gnmi.CapabilityResponse) ([]iosXRPathDefinition, error) {
	selected := resolveIOSXRPathSelection(r.config.PathGroups, r.config.Paths, &target)
	if target.SkipCapabilities || caps == nil || len(caps.GetSupportedModels()) == 0 {
		return selected, nil
	}
	supported := map[string]struct{}{}
	for _, model := range caps.GetSupportedModels() {
		supported[strings.ToLower(model.GetName())] = struct{}{}
	}
	out := make([]iosXRPathDefinition, 0, len(selected))
	var unsupported []string
	for _, def := range selected {
		module := moduleFromYANGPath(def.Path)
		if module == "" {
			out = append(out, def)
			continue
		}
		if _, ok := supported[strings.ToLower(module)]; ok {
			out = append(out, def)
			continue
		}
		unsupported = append(unsupported, def.Path)
	}
	if len(unsupported) > 0 {
		r.health.addUnsupportedPaths(int64(len(unsupported)))
		switch r.config.UnsupportedPathAction {
		case iosXRUnsupportedError:
			return nil, fmt.Errorf("IOS XR target %s does not advertise models for paths: %s", target.Name, strings.Join(unsupported, ", "))
		case iosXRUnsupportedWarn:
			r.settings.Logger.Warn("IOS XR target does not advertise models for some configured paths",
				zap.String("target", target.Name),
				zap.Strings("paths", unsupported))
		}
	}
	return out, nil
}

func negotiateIOSXREncoding(preferences []string, caps *gnmi.CapabilityResponse) (gnmi.Encoding, error) {
	if len(preferences) == 0 {
		preferences = []string{"json_ietf", "json", "proto"}
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
		if !ok {
			continue
		}
		if _, ok := supported[encoding]; ok {
			return encoding, nil
		}
	}
	return gnmi.Encoding_JSON, fmt.Errorf("target does not support requested IOS XR encodings: %s", strings.Join(preferences, ", "))
}

func buildIOSXRSubscribeRequest(sub IOSXRSubscriptionConfig, paths []iosXRPathDefinition, encoding gnmi.Encoding) *gnmi.SubscribeRequest {
	list := &gnmi.SubscriptionList{
		Mode:             subscriptionListMode(sub.Mode),
		Encoding:         encoding,
		UpdatesOnly:      sub.UpdatesOnly,
		AllowAggregation: sub.AllowAggregation,
		Subscription:     make([]*gnmi.Subscription, 0, len(paths)),
	}
	for _, def := range paths {
		p, err := parseGNMIPath(def.Path)
		if err != nil {
			continue
		}
		streamMode := sub.StreamMode
		// A path's catalog DefaultStreamMode is authoritative: event-style paths
		// (e.g. neighbor/state changes) are catalogued as on_change and must not
		// be downgraded to timer sampling by the global stream_mode default.
		if def.DefaultStreamMode != "" {
			streamMode = def.DefaultStreamMode
		}
		if streamMode == "" {
			streamMode = iosXRStreamModeSample
		}
		if streamMode == iosXRStreamModeTargetDefined && !strings.HasPrefix(def.Path, "openconfig-") {
			streamMode = iosXRStreamModeSample
		}
		sampleInterval := sub.SampleInterval
		if def.MinSampleInterval > sampleInterval {
			sampleInterval = def.MinSampleInterval
		}
		list.Subscription = append(list.Subscription, &gnmi.Subscription{
			Path:              p,
			Mode:              subscriptionStreamMode(streamMode),
			SampleInterval:    uint64(sampleInterval.Nanoseconds()),
			SuppressRedundant: sub.SuppressRedundant,
			HeartbeatInterval: uint64(sub.HeartbeatInterval.Nanoseconds()),
		})
	}
	return &gnmi.SubscribeRequest{Request: &gnmi.SubscribeRequest_Subscribe{Subscribe: list}}
}

func enforceIOSXRDatapointLimit(md pmetric.Metrics, limit int) int {
	if limit <= 0 {
		return 0
	}
	seen := 0
	dropped := 0
	rms := md.ResourceMetrics()
	for i := 0; i < rms.Len(); i++ {
		sms := rms.At(i).ScopeMetrics()
		for j := 0; j < sms.Len(); j++ {
			metrics := sms.At(j).Metrics()
			metrics.RemoveIf(func(metric pmetric.Metric) bool {
				count := metricDatapointCount(metric)
				if seen >= limit {
					dropped += count
					return true
				}
				if seen+count > limit {
					dropped += trimIOSXRMetricDatapoints(metric, limit-seen)
					seen = limit
					return metricDatapointCount(metric) == 0
				}
				seen += count
				return false
			})
		}
	}
	return dropped
}

func trimIOSXRMetricDatapoints(metric pmetric.Metric, keep int) int {
	if keep <= 0 {
		count := metricDatapointCount(metric)
		return count
	}
	switch metric.Type() {
	case pmetric.MetricTypeGauge:
		dps := metric.Gauge().DataPoints()
		return trimIOSXRNumberDatapoints(dps, keep)
	case pmetric.MetricTypeSum:
		dps := metric.Sum().DataPoints()
		return trimIOSXRNumberDatapoints(dps, keep)
	default:
		return 0
	}
}

func trimIOSXRNumberDatapoints(dps pmetric.NumberDataPointSlice, keep int) int {
	seen := 0
	dropped := 0
	dps.RemoveIf(func(pmetric.NumberDataPoint) bool {
		if seen >= keep {
			dropped++
			return true
		}
		seen++
		return false
	})
	return dropped
}

func metricDatapointCount(metric pmetric.Metric) int {
	switch metric.Type() {
	case pmetric.MetricTypeGauge:
		return metric.Gauge().DataPoints().Len()
	case pmetric.MetricTypeSum:
		return metric.Sum().DataPoints().Len()
	default:
		return 0
	}
}

func iosXRTargetIdentity(target IOSXRTargetConfig) deviceIdentity {
	host, _, _ := net.SplitHostPort(target.Endpoint)
	return deviceIdentity{
		hostNames: []string{target.Name},
		hostIDs:   []string{target.Name, target.Endpoint, host},
		hostIPs:   []string{host},
		deviceIDs: []string{target.Name, target.Endpoint, host},
	}
}
