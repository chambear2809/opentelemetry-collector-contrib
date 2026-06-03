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
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/consumer"
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
		for _, target := range cfg.DialIn.Targets {
			target = target.withDefaults(cfg)
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
	var err error
	for _, receiver := range r.receivers {
		err = multierr.Append(err, receiver.Start(ctx, host))
	}
	return err
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
	yangCfg.YANG.ModulePaths = cfg.DialOut.ModulePaths
	health := &catalyst9800Health{}
	normalizer := newCatalyst9800NormalizingConsumer(next, cfg, selector, catalyst9800TelemetryTransportDialOut, health)
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
	r.health.setActiveSubscriptions(int64(len(r.targets)))
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

func (r *catalyst9800DialInReceiver) runTarget(ctx context.Context, target Catalyst9800TargetConfig) {
	backoff := 5 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := r.subscribeTarget(ctx, target)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			r.health.addReconnects(1)
			r.settings.Logger.Warn("Catalyst 9800 gNMI subscription failed",
				zap.String("target", target.Name),
				zap.String("endpoint", target.Endpoint),
				zap.Error(err))
		}
		if target.Subscription.Mode == iosXRSubscribeModeOnce && err == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

func (r *catalyst9800DialInReceiver) subscribeTarget(ctx context.Context, target Catalyst9800TargetConfig) error {
	conn, err := target.ClientConfig.ToClientConn(ctx, r.host.GetExtensions(), r.settings.TelemetrySettings, configgrpc.WithGrpcDialOption(grpc.WithBlock()))
	if err != nil {
		return err
	}
	defer conn.Close()

	client := gnmi.NewGNMIClient(conn)
	caps := &gnmi.CapabilityResponse{}
	if !target.SkipCapabilities {
		capCtx, cancel := context.WithTimeout(r.outgoingContext(ctx, target), 15*time.Second)
		defer cancel()
		caps, err = client.Capabilities(capCtx, &gnmi.CapabilityRequest{})
		if err != nil {
			return fmt.Errorf("capabilities: %w", err)
		}
	}

	paths, err := r.resolveTargetPaths(target, caps)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New("no Catalyst 9800 paths available after capability filtering")
	}
	encoding, err := negotiateCatalyst9800Encoding(target.EncodingPreference, caps)
	if err != nil {
		return err
	}

	stream, err := client.Subscribe(r.outgoingContext(ctx, target))
	if err != nil {
		return err
	}
	if err := stream.Send(buildCatalyst9800SubscribeRequest(target.Subscription, paths, encoding)); err != nil {
		return err
	}

	if target.Subscription.Mode == iosXRSubscribeModePoll {
		return r.recvPoll(ctx, target, stream)
	}
	if target.Subscription.Mode == iosXRSubscribeModeOnce {
		if closeErr := stream.CloseSend(); closeErr != nil {
			r.settings.Logger.Debug("Catalyst 9800 gNMI once close send failed", zap.Error(closeErr))
		}
	}
	return r.recvLoop(ctx, target, stream)
}

func (r *catalyst9800DialInReceiver) recvPoll(ctx context.Context, target Catalyst9800TargetConfig, stream grpc.BidiStreamingClient[gnmi.SubscribeRequest, gnmi.SubscribeResponse]) error {
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

func (r *catalyst9800DialInReceiver) recvLoop(ctx context.Context, target Catalyst9800TargetConfig, stream grpc.BidiStreamingClient[gnmi.SubscribeRequest, gnmi.SubscribeResponse]) error {
	decoder := catalyst9800GNMIUpdateDecoder{target: target, health: r.health}
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
			r.health.addUpdates(int64(len(body.Update.GetUpdate()) + len(body.Update.GetDelete())))
			md := decoder.decodeNotification(body.Update, catalyst9800TelemetryTransportDialIn)
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
				r.settings.Logger.Debug("Catalyst 9800 gNMI initial sync complete", zap.String("target", target.Name))
			}
		case *gnmi.SubscribeResponse_Error:
			if body.Error != nil {
				return fmt.Errorf("subscribe response error: %s", body.Error.GetMessage())
			}
		}
	}
}

func (r *catalyst9800DialInReceiver) outgoingContext(ctx context.Context, target Catalyst9800TargetConfig) context.Context {
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
	for _, def := range selected {
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
		UpdatesOnly:      sub.UpdatesOnly,
		AllowAggregation: sub.AllowAggregation,
		Subscription:     make([]*gnmi.Subscription, 0, len(paths)),
	}
	for _, def := range paths {
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
		sampleInterval := sub.SampleInterval
		if def.MinSampleInterval > sampleInterval {
			sampleInterval = def.MinSampleInterval
		}
		sampleIntervalNanos := uint64(sampleInterval.Nanoseconds())
		if mode == gnmi.SubscriptionMode_ON_CHANGE {
			sampleIntervalNanos = 0
		}
		list.Subscription = append(list.Subscription, &gnmi.Subscription{
			Path:              p,
			Mode:              mode,
			SampleInterval:    sampleIntervalNanos,
			SuppressRedundant: sub.SuppressRedundant,
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

var _ receiver.Metrics = (*catalyst9800CompositeReceiver)(nil)
var _ receiver.Metrics = (*catalyst9800DialInReceiver)(nil)
var _ consumer.Metrics = (*catalyst9800NormalizingConsumer)(nil)
var _ = pmetric.NewMetrics
