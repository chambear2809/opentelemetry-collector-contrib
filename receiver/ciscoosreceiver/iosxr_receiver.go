// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"google.golang.org/grpc"

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
	jitter := max(random(span), 0)
	if jitter >= span {
		jitter = span - 1
	}
	return half + jitter
}

func randomDirectGNMIDuration(upperBound time.Duration) time.Duration {
	if upperBound <= 1 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(upperBound)))
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

func newIOSXRMetricsReceiver(
	set receiver.Settings,
	conf *Config,
	next consumer.Metrics,
	legacyProcessing *legacyGNMIProcessingLimiter,
) (receiver.Metrics, error) {
	cfg := conf.IOSXR.withDefaults()
	selector := newDeviceSelectionMatcher(conf.DeviceSelection)
	var receivers []receiver.Metrics

	if len(cfg.DialIn.Targets) > 0 {
		targets := make([]IOSXRTargetConfig, 0, len(cfg.DialIn.Targets))
		for i := range cfg.DialIn.Targets {
			target := cfg.DialIn.Targets[i].withDefaults(cfg)
			if selector.allows(iosXRTargetIdentity(target)) {
				targets = append(targets, target)
			}
		}
		if len(targets) > 0 {
			dialIn := &iosXRDialInReceiver{
				settings:   set,
				config:     cfg,
				targets:    targets,
				consumer:   next,
				health:     &iosXRHealth{},
				done:       make(chan struct{}),
				processing: legacyProcessing,
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
	yangCfg, err := hardenedYangGRPCConfig(factory.CreateDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("create IOS XR dial-out receiver: %w", err)
	}
	yangCfg.ServerConfig = cfg.DialOut.ServerConfig
	configureHardenedYangGRPCSecurity(yangCfg, cfg.DialOut.AllowedClients, cfg.DialOut.RateLimiting)
	maxStreamsPerClient := effectiveGNMIDialOutMaxStreamsPerClient(
		cfg.DialOut.MaxStreamsPerClient,
		cfg.DialOut.MaxConcurrentStreams,
	)
	if admissionErr := configureHardenedYangGRPCStreamAdmission(yangCfg, maxStreamsPerClient); admissionErr != nil {
		return nil, fmt.Errorf("configure IOS XR dial-out global stream admission: %w", admissionErr)
	}
	if idleErr := configureHardenedYangGRPCStreamIdleTimeout(yangCfg, cfg.DialOut.StreamIdleTimeout); idleErr != nil {
		return nil, fmt.Errorf("configure IOS XR dial-out stream idle timeout: %w", idleErr)
	}
	modulePaths := append([]string(nil), cfg.DialOut.ModulePaths...)
	yangCfg.YANG.ModulePaths = modulePaths
	middlewareID, middleware, err := configureGNMIDialOutSecurity(
		&yangCfg.ServerConfig,
		cfg.DialOut.AllowedClients,
		maxStreamsPerClient,
		cfg.DialOut.RateLimiting,
		cfg.DialOut.IdentityVerification,
		cfg.DialOut.IdentityBindings,
		set.Logger,
		set.ID,
		"iosxr",
	)
	if err != nil {
		return nil, fmt.Errorf("configure IOS XR dial-out stream security: %w", err)
	}
	health := &iosXRHealth{}
	normalizer := newIOSXRNormalizingConsumer(next, cfg, selector, iosXRTelemetryTransportDialOut, health)
	childSet := set
	childSet.ID = component.NewIDWithName(factory.Type(), middlewareID.Name())
	delegate, err := factory.CreateMetrics(context.Background(), childSet, yangCfg, normalizer)
	if err != nil {
		middleware.security.Shutdown()
		return nil, err
	}
	return wrapGNMIDialOutSecurityReceiver(delegate, middlewareID, middleware, modulePaths), nil
}

type iosXRDialInReceiver struct {
	settings   receiver.Settings
	config     IOSXRConfig
	targets    []IOSXRTargetConfig
	consumer   consumer.Metrics
	health     *iosXRHealth
	processing *legacyGNMIProcessingLimiter

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
	for i := range r.targets {
		target := r.targets[i]
		wg.Go(func() {
			r.runTarget(ctx, target)
		})
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
		if legacyGNMIRetryDelay(err) == legacyGNMIAuthenticationBackoff {
			delay = legacyGNMIAuthenticationBackoff
		}
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
	interval := target.Subscription.PollInterval
	if interval <= 0 {
		interval = target.Subscription.SampleInterval
	}
	decoder := iosXRGNMIUpdateDecoder{
		target:        target,
		health:        r.health,
		maxDatapoints: r.config.MaxDatapointsPerBatch,
	}
	var progressed atomic.Bool
	defer r.setTargetSubscriptionActive(ctx, target, false)

	err := legacyGNMISession{
		settings:                     r.settings,
		host:                         r.host,
		clientConfig:                 target.ClientConfig,
		username:                     target.Credentials.Username,
		password:                     string(target.Credentials.Password),
		skipCapabilities:             target.SkipCapabilities,
		pollInterval:                 interval,
		targetName:                   target.Name,
		onceCloseLog:                 "IOS XR gNMI once close send failed",
		insecureSkipVerifyConfigPath: "ios_xr.dial_in.targets[].tls.insecure_skip_verify",
		responseAdmission:            legacyGNMIResponseAdmission(r.processing),
		onSubscribed: func() {
			r.setTargetSubscriptionActive(ctx, target, true)
		},
		buildRequest: func(capabilities *gnmi.CapabilityResponse) (*gnmi.SubscribeRequest, error) {
			paths, err := r.resolveTargetPaths(target, capabilities)
			if err != nil {
				return nil, err
			}
			if len(paths) == 0 {
				return nil, errors.New("no IOS XR paths available after capability filtering")
			}
			encoding, err := negotiateIOSXREncoding(target.EncodingPreference, capabilities)
			if err != nil {
				return nil, err
			}
			return buildIOSXRSubscribeRequest(target.Subscription, paths, encoding), nil
		},
		handleUpdate: func(ctx context.Context, notification *gnmi.Notification) error {
			return r.processNotification(ctx, target, &decoder, notification, &progressed)
		},
		handleSync: func() {
			progressed.Store(true)
			r.settings.Logger.Debug("IOS XR gNMI initial sync complete", zap.String("target", target.Name))
		},
	}.run(ctx)
	return progressed.Load(), err
}

func (r *iosXRDialInReceiver) processNotification(
	ctx context.Context,
	target IOSXRTargetConfig,
	decoder *iosXRGNMIUpdateDecoder,
	notification *gnmi.Notification,
	progressed *atomic.Bool,
) error {
	return r.processing.run(ctx, func() error {
		r.health.addTargetUpdates(target.Name, int64(len(notification.GetUpdate())+len(notification.GetDelete())))
		md := decoder.decodeNotification(notification, iosXRTelemetryTransportDialIn)
		if md.MetricCount() == 0 {
			progressed.Store(true)
			return nil
		}
		if r.config.MaxDatapointsPerBatch > 0 {
			dropped := enforceIOSXRDatapointLimit(md, r.config.MaxDatapointsPerBatch)
			if dropped > 0 {
				r.health.addDroppedDatapoints(int64(dropped))
			}
		}
		if err := r.consumer.ConsumeMetrics(ctx, md); err != nil {
			r.health.addDroppedDatapoints(int64(md.DataPointCount()))
			return fmt.Errorf("deliver IOS XR gNMI metric batch for target %q: %w", target.Name, err)
		}
		progressed.Store(true)
		return nil
	})
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
	if err := r.processing.run(ctx, func() error { return r.consumer.ConsumeMetrics(ctx, md) }); err != nil && ctx.Err() == nil {
		r.settings.Logger.Warn("IOS XR gNMI health delivery failed", zap.String("target", target.Name), zap.Error(err))
	}
}

func (r *iosXRDialInReceiver) recvPoll(ctx context.Context, cancelStream context.CancelFunc, target IOSXRTargetConfig, stream grpc.BidiStreamingClient[gnmi.SubscribeRequest, gnmi.SubscribeResponse], progressed *atomic.Bool) error {
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
		// CloseSend only closes the client-to-server half of a gNMI stream. Cancel
		// the exact context passed to Subscribe so grpc-go also interrupts Recv,
		// then join the reader before this subscription attempt can reconnect or
		// report itself fully shut down.
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

func (r *iosXRDialInReceiver) recvLoop(ctx context.Context, target IOSXRTargetConfig, stream grpc.BidiStreamingClient[gnmi.SubscribeRequest, gnmi.SubscribeResponse], progressed *atomic.Bool) error {
	decoder := iosXRGNMIUpdateDecoder{target: target, health: r.health, maxDatapoints: r.config.MaxDatapointsPerBatch}
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
			if err := r.processNotification(ctx, target, &decoder, body.Update, progressed); err != nil {
				return err
			}
		case *gnmi.SubscribeResponse_SyncResponse:
			if body.SyncResponse {
				progressed.Store(true)
				r.settings.Logger.Debug("IOS XR gNMI initial sync complete", zap.String("target", target.Name))
			}
		case *gnmi.SubscribeResponse_Error:
			if body.Error != nil { //nolint:staticcheck // Legacy devices can still populate the deprecated in-band gNMI error.
				return sanitizedGNMISubscribeError(body.Error) //nolint:staticcheck // Preserve compatibility with legacy in-band gNMI errors.
			}
		}
	}
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
	for i := range selected {
		def := &selected[i]
		module := moduleFromYANGPath(def.Path)
		if module == "" {
			out = append(out, *def)
			continue
		}
		if _, ok := supported[strings.ToLower(module)]; ok {
			out = append(out, *def)
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
		UpdatesOnly:      sub.updatesOnly(),
		AllowAggregation: sub.allowAggregation(),
		Subscription:     make([]*gnmi.Subscription, 0, len(paths)),
	}
	for i := range paths {
		def := &paths[i]
		p, err := parseGNMIPath(def.Path)
		if err != nil {
			continue
		}
		streamMode := sub.StreamMode
		// A path's catalog DefaultStreamMode is authoritative: event-style paths
		// (e.g. neighbor/state changes) are cataloged as on_change and must not
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
		subscription := &gnmi.Subscription{Path: p}
		if sub.Mode == iosXRSubscribeModeStream {
			subscription.Mode = subscriptionStreamMode(streamMode)
			switch streamMode {
			case iosXRStreamModeSample:
				sampleInterval := max(def.MinSampleInterval, sub.SampleInterval)
				subscription.SampleInterval = uint64(sampleInterval.Nanoseconds())
				subscription.SuppressRedundant = sub.suppressRedundant()
				subscription.HeartbeatInterval = uint64(sub.heartbeatInterval().Nanoseconds())
			case iosXRStreamModeOnChange:
				subscription.HeartbeatInterval = uint64(sub.heartbeatInterval().Nanoseconds())
			}
		}
		list.Subscription = append(list.Subscription, subscription)
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
	case pmetric.MetricTypeHistogram:
		dps := metric.Histogram().DataPoints()
		return trimIOSXRHistogramDatapoints(dps, keep)
	case pmetric.MetricTypeExponentialHistogram:
		dps := metric.ExponentialHistogram().DataPoints()
		return trimIOSXRExponentialHistogramDatapoints(dps, keep)
	case pmetric.MetricTypeSummary:
		dps := metric.Summary().DataPoints()
		return trimIOSXRSummaryDatapoints(dps, keep)
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

func trimIOSXRHistogramDatapoints(dps pmetric.HistogramDataPointSlice, keep int) int {
	seen := 0
	dropped := 0
	dps.RemoveIf(func(pmetric.HistogramDataPoint) bool {
		if seen >= keep {
			dropped++
			return true
		}
		seen++
		return false
	})
	return dropped
}

func trimIOSXRExponentialHistogramDatapoints(dps pmetric.ExponentialHistogramDataPointSlice, keep int) int {
	seen := 0
	dropped := 0
	dps.RemoveIf(func(pmetric.ExponentialHistogramDataPoint) bool {
		if seen >= keep {
			dropped++
			return true
		}
		seen++
		return false
	})
	return dropped
}

func trimIOSXRSummaryDatapoints(dps pmetric.SummaryDataPointSlice, keep int) int {
	seen := 0
	dropped := 0
	dps.RemoveIf(func(pmetric.SummaryDataPoint) bool {
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
	case pmetric.MetricTypeHistogram:
		return metric.Histogram().DataPoints().Len()
	case pmetric.MetricTypeExponentialHistogram:
		return metric.ExponentialHistogram().DataPoints().Len()
	case pmetric.MetricTypeSummary:
		return metric.Summary().DataPoints().Len()
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
