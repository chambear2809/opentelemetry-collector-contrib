// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestFactorySharesGNMIProcessingAndResponseLimiters(t *testing.T) {
	cfg := validIOSXRConfig()
	cfg.Catalyst9800 = validCatalyst9800Config().Catalyst9800
	cfg.GNMI = validGNMITestConfig().GNMI
	require.NoError(t, cfg.Validate())

	created, err := createMetricsReceiver(
		t.Context(),
		receivertest.NewNopSettings(componentmetadata.Type),
		cfg,
		consumertest.NewNop(),
	)
	require.NoError(t, err)
	multi, ok := created.(*multiMetricsReceiver)
	require.True(t, ok)

	var iosXR *iosXRDialInReceiver
	var catalyst9800 *catalyst9800DialInReceiver
	var shared *sharedGNMIReceiver
	for _, child := range multi.receivers {
		switch receiver := child.(type) {
		case *iosXRDialInReceiver:
			iosXR = receiver
		case *catalyst9800DialInReceiver:
			catalyst9800 = receiver
		case *sharedGNMIReceiver:
			shared = receiver
		}
	}
	require.NotNil(t, iosXR)
	require.NotNil(t, catalyst9800)
	require.NotNil(t, shared)
	require.Same(t, iosXR.processing, catalyst9800.processing)
	require.Same(t, iosXR.processing.responseAdmission, shared.responseAdmission)
	assert.Equal(t, legacyGNMIMaxConcurrentProcessing, cap(iosXR.processing.slots))
	assert.Equal(t, gnmiWireMaximumDecodedResponses, cap(shared.responseAdmission.slots))
}

func TestLegacyGNMIProcessingLimiterBoundsBothProviders(t *testing.T) {
	limiter := newLegacyGNMIProcessingLimiter()
	consumer := &legacyGNMIConcurrencyConsumer{
		entered: make(chan struct{}, legacyGNMIMaxConcurrentProcessing+2),
		release: make(chan struct{}),
	}
	iosXRTarget := validIOSXRConfig().IOSXR.DialIn.Targets[0]
	catalystTarget := validCatalyst9800Config().Catalyst9800.DialIn.Targets[0]
	iosXR := &iosXRDialInReceiver{
		config: defaultIOSXRConfig(), consumer: consumer, health: &iosXRHealth{}, processing: limiter,
	}
	catalyst9800 := &catalyst9800DialInReceiver{
		config: defaultCatalyst9800Config(), consumer: consumer, health: &catalyst9800Health{}, processing: limiter,
	}
	notification := testDirectGNMIUpdate().GetUpdate()

	results := make(chan error, legacyGNMIMaxConcurrentProcessing+2)
	for index := range legacyGNMIMaxConcurrentProcessing + 2 {
		go func() {
			var progressed atomic.Bool
			if index%2 == 0 {
				decoder := iosXRGNMIUpdateDecoder{
					target: iosXRTarget, health: iosXR.health, maxDatapoints: iosXR.config.MaxDatapointsPerBatch,
				}
				results <- iosXR.processNotification(t.Context(), iosXRTarget, &decoder, notification, &progressed)
				return
			}
			decoder := catalyst9800GNMIUpdateDecoder{
				target: catalystTarget, health: catalyst9800.health, maxDatapoints: catalyst9800.config.MaxDatapointsPerBatch,
			}
			results <- catalyst9800.processNotification(t.Context(), catalystTarget, &decoder, notification, &progressed)
		}()
	}

	for range legacyGNMIMaxConcurrentProcessing {
		select {
		case <-consumer.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for the legacy processing gate to fill")
		}
	}
	select {
	case <-consumer.entered:
		t.Fatal("more than eight legacy notifications entered the downstream consumer")
	case <-time.After(100 * time.Millisecond):
	}
	assert.Equal(t, int64(legacyGNMIMaxConcurrentProcessing), consumer.maxActive.Load())

	close(consumer.release)
	for range legacyGNMIMaxConcurrentProcessing + 2 {
		require.NoError(t, <-results)
	}
	assert.Equal(t, int64(legacyGNMIMaxConcurrentProcessing), consumer.maxActive.Load())
}

func TestLegacyGNMIProcessingLimiterCancellationAndErrorRelease(t *testing.T) {
	limiter := newLegacyGNMIProcessingLimiter()
	preCanceled, cancelPreCanceled := context.WithCancel(t.Context())
	cancelPreCanceled()
	called := false
	err := limiter.run(preCanceled, func() error {
		called = true
		return nil
	})
	require.ErrorIs(t, err, context.Canceled)
	assert.False(t, called, "a pre-canceled operation must not win the available-slot select")
	assert.Empty(t, limiter.slots)

	for range legacyGNMIMaxConcurrentProcessing {
		limiter.slots <- struct{}{}
	}
	baseCtx, cancel := context.WithCancel(t.Context())
	ctx := &legacyGNMIDoneObservedContext{Context: baseCtx, observed: make(chan struct{}, 1)}
	result := make(chan error, 1)
	go func() {
		result <- limiter.run(ctx, func() error {
			called = true
			return nil
		})
	}()
	<-ctx.observed
	select {
	case err := <-result:
		t.Fatalf("full processing gate returned before cancellation: %v", err)
	default:
	}
	cancel()
	require.ErrorIs(t, <-result, context.Canceled)
	assert.False(t, called)
	for range legacyGNMIMaxConcurrentProcessing {
		<-limiter.slots
	}

	sentinel := errors.New("consumer refused")
	require.ErrorIs(t, limiter.run(t.Context(), func() error { return sentinel }), sentinel)
	assert.Empty(t, limiter.slots)
	require.NoError(t, limiter.run(t.Context(), func() error { return nil }))
	assert.Empty(t, limiter.slots)
}

func TestLegacyGNMIReceiveLimitIsPinnedAtFourMiB(t *testing.T) {
	endpoint := startFakeGNMIServer(t, &fakeGNMIServer{caps: &gnmi.CapabilityResponse{
		GNMIVersion: strings.Repeat("v", legacyGNMIMaxRecvMsgSizeMiB*1024*1024),
	}})
	session := legacyGNMISession{
		settings:     receivertest.NewNopSettings(componentmetadata.Type),
		host:         componenttest.NewNopHost(),
		clientConfig: mustIOSXRClientConfig(endpoint),
		buildRequest: func(*gnmi.CapabilityResponse) (*gnmi.SubscribeRequest, error) {
			return &gnmi.SubscribeRequest{Request: &gnmi.SubscribeRequest_Subscribe{
				Subscribe: &gnmi.SubscriptionList{Mode: gnmi.SubscriptionList_ONCE},
			}}, nil
		},
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := session.run(ctx)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.Contains(t, err.Error(), "code=ResourceExhausted")
	assert.NotContains(t, err.Error(), "received message larger than max")
}

func TestLegacyGNMITLSConnectionHintIsSecureByDefault(t *testing.T) {
	clientConfig := configgrpc.NewDefaultClientConfig()
	session := legacyGNMISession{
		clientConfig:                 clientConfig,
		insecureSkipVerifyConfigPath: "ios_xr.dial_in.targets[].tls.insecure_skip_verify",
	}
	cause := errors.New("connection did not become ready")
	err := session.decorateTLSConnectionError(cause)
	require.ErrorIs(t, err, cause)
	assert.ErrorContains(t, err, "verify endpoint reachability")
	assert.ErrorContains(t, err, "tls.server_name_override")
	assert.ErrorContains(t, err, "ios_xr.dial_in.targets[].tls.insecure_skip_verify: true")

	clientConfig.TLS.InsecureSkipVerify = true
	session.clientConfig = clientConfig
	assert.Same(t, cause, session.decorateTLSConnectionError(cause))
}

func TestLegacyGNMITLSConnectionHintSurvivesStatusSanitization(t *testing.T) {
	clientConfig := configgrpc.NewDefaultClientConfig()
	session := legacyGNMISession{
		clientConfig:                 clientConfig,
		insecureSkipVerifyConfigPath: "ios_xr.dial_in.targets[].tls.insecure_skip_verify",
	}

	err := session.decorateTLSConnectionError(sanitizedGNMIRPCError(
		status.Error(codes.Unavailable, "device-controlled secret"),
	))
	err = sanitizedGNMIRPCError(err)
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.ErrorContains(t, err, "verify endpoint reachability")
	assert.NotContains(t, err.Error(), "device-controlled")
	assert.NotContains(t, err.Error(), "secret")
}

type legacyGNMIConcurrencyConsumer struct {
	entered   chan struct{}
	release   chan struct{}
	active    atomic.Int64
	maxActive atomic.Int64
}

func (*legacyGNMIConcurrencyConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (c *legacyGNMIConcurrencyConsumer) ConsumeMetrics(context.Context, pmetric.Metrics) error {
	active := c.active.Add(1)
	for {
		maximum := c.maxActive.Load()
		if active <= maximum || c.maxActive.CompareAndSwap(maximum, active) {
			break
		}
	}
	c.entered <- struct{}{}
	<-c.release
	c.active.Add(-1)
	return nil
}

var _ consumer.Metrics = (*legacyGNMIConcurrencyConsumer)(nil)

type legacyGNMIDoneObservedContext struct {
	context.Context
	observed chan struct{}
}

func (c *legacyGNMIDoneObservedContext) Done() <-chan struct{} {
	select {
	case c.observed <- struct{}{}:
	default:
	}
	return c.Context.Done()
}
