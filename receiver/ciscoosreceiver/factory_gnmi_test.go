// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestFactoryDefaultConfigIncludesGNMILimits(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig().(*Config)

	assert.Equal(t, 10_000, cfg.GNMI.MaxDatapointsPerChunk)
	assert.Equal(t, 500_000, cfg.GNMI.MaxCachedSeries)
	assert.Empty(t, cfg.GNMI.Targets)
}

func TestCreateMetricsReceiverIncludesSharedGNMIReceiver(t *testing.T) {
	cfg := factoryGNMITestConfig()
	require.NoError(t, cfg.Validate())

	rcvr, err := createMetricsReceiver(
		t.Context(),
		receivertest.NewNopSettings(metadata.Type),
		cfg,
		consumertest.NewNop(),
	)
	require.NoError(t, err)

	shared, ok := rcvr.(*sharedGNMIReceiver)
	require.True(t, ok, "expected sharedGNMIReceiver for a shared gNMI-only config")
	require.Len(t, shared.targets, 1)
	assert.Equal(t, "edge-1", shared.targets[0].config.Name)
	require.NoError(t, shared.Shutdown(t.Context()))
}

func TestCreateMetricsReceiverFiltersSharedGNMITarget(t *testing.T) {
	cfg := factoryGNMITestConfig()
	cfg.DeviceSelection.Exclude.HostNames = []string{"edge-1"}
	require.NoError(t, cfg.Validate())

	rcvr, err := createMetricsReceiver(
		t.Context(),
		receivertest.NewNopSettings(metadata.Type),
		cfg,
		consumertest.NewNop(),
	)
	require.NoError(t, err)

	shared, ok := rcvr.(*sharedGNMIReceiver)
	require.True(t, ok, "expected the shared receiver to remain available with no selected targets")
	assert.Empty(t, shared.targets)
	require.NoError(t, shared.Shutdown(t.Context()))
}

func TestMultiMetricsReceiverStartRollsBackStartedReceivers(t *testing.T) {
	startErr := errors.New("start failed")
	events := []string{}
	first := &factoryLifecycleReceiver{name: "first", events: &events}
	second := &factoryLifecycleReceiver{name: "second", events: &events}
	failing := &factoryLifecycleReceiver{name: "failing", events: &events, startErr: startErr}
	rcvr := &multiMetricsReceiver{receivers: []receiver.Metrics{first, second, failing}}

	err := rcvr.Start(t.Context(), nil)
	require.ErrorIs(t, err, startErr)
	assert.Equal(t, []string{
		"start:first",
		"start:second",
		"start:failing",
		"shutdown:second",
		"shutdown:first",
	}, events)
}

func TestMultiLogsReceiverStartRollsBackStartedReceivers(t *testing.T) {
	startErr := errors.New("start failed")
	events := []string{}
	first := &factoryLifecycleReceiver{name: "first", events: &events}
	second := &factoryLifecycleReceiver{name: "second", events: &events}
	failing := &factoryLifecycleReceiver{name: "failing", events: &events, startErr: startErr}
	rcvr := &multiLogsReceiver{receivers: []receiver.Logs{first, second, failing}}

	err := rcvr.Start(t.Context(), nil)
	require.ErrorIs(t, err, startErr)
	assert.Equal(t, []string{
		"start:first",
		"start:second",
		"start:failing",
		"shutdown:second",
		"shutdown:first",
	}, events)
}

func factoryGNMITestConfig() *Config {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.GNMI.Targets = []GNMITargetConfig{{
		Name:     "edge-1",
		Endpoint: "edge-1.example.test:57400",
		Platform: gnmiPlatformIOSXE,
		Credentials: GNMICredentialsConfig{
			Username: "telemetry",
			Password: configopaque.String("secret"),
		},
	}}
	return cfg
}

type factoryLifecycleReceiver struct {
	name     string
	events   *[]string
	startErr error
}

func (r *factoryLifecycleReceiver) Start(_ context.Context, _ component.Host) error {
	*r.events = append(*r.events, "start:"+r.name)
	return r.startErr
}

func (r *factoryLifecycleReceiver) Shutdown(_ context.Context) error {
	*r.events = append(*r.events, "shutdown:"+r.name)
	return nil
}
