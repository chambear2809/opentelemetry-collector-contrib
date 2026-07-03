// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestPartitionSharedGNMICacheLimitsIsDeterministicAndConservative(t *testing.T) {
	limits, err := partitionSharedGNMICacheLimits(10, 100, 3)
	require.NoError(t, err)
	require.Equal(t, []sharedGNMICacheLimit{
		{series: 4, retainedBytes: 34},
		{series: 3, retainedBytes: 33},
		{series: 3, retainedBytes: 33},
	}, limits)

	_, err = partitionSharedGNMICacheLimits(1, 100, 2)
	require.ErrorContains(t, err, "smaller than selected target count")
	_, err = partitionSharedGNMICacheLimits(2, 1, 2)
	require.ErrorContains(t, err, "retained-byte cache limit")
	limits, err = partitionSharedGNMICacheLimits(1, 1, 0)
	require.NoError(t, err)
	assert.Nil(t, limits)
}

func TestSharedGNMIReceiverPartitionsCachePerSelectedTarget(t *testing.T) {
	cfg := validGNMITestConfig()
	first := cfg.GNMI.Targets[0]
	first.Name = "target-a"
	first.Endpoint = "target-a.example.test:57400"
	second := first
	second.Name = "target-b"
	second.Endpoint = "target-b.example.test:57400"
	cfg.GNMI.MaxCachedSeries = 5
	cfg.GNMI.Targets = []GNMITargetConfig{first, second}

	created, err := newSharedGNMIReceiver(
		receivertest.NewNopSettings(metadata.Type),
		cfg,
		consumertest.NewNop(),
	)
	require.NoError(t, err)
	receiver := created.(*sharedGNMIReceiver)
	t.Cleanup(func() { require.NoError(t, receiver.Shutdown(t.Context())) })
	require.Len(t, receiver.targets, 2)
	assert.NotSame(t, receiver.targets[0].cache, receiver.targets[1].cache)
	assert.Equal(t, 3, receiver.targets[0].cache.Capacity())
	assert.Equal(t, 2, receiver.targets[1].cache.Capacity())
	assert.Equal(
		t,
		internalgnmi.DefaultMaxCacheRetainedBytes,
		receiver.targets[0].cache.RetainedByteCapacity()+receiver.targets[1].cache.RetainedByteCapacity(),
	)
	assert.NotSame(t, receiver.targets[0].nxBudget, receiver.targets[1].nxBudget)
	assert.Equal(t, 10, receiver.targets[0].nxBudget.maximum)
	assert.Equal(t, 10, receiver.targets[1].nxBudget.maximum)
	assert.Equal(
		t,
		sharedGNMIAuxiliaryRetainedBytes,
		receiver.targets[0].nxBudget.maximumBytes+receiver.targets[1].nxBudget.maximumBytes,
	)
}

func TestPartitionSharedGNMIAuxiliaryLimitsMultipliesBeforePartitioning(t *testing.T) {
	limits, err := partitionSharedGNMIAuxiliaryLimits(1, 1)
	require.NoError(t, err)
	require.Len(t, limits, 1)
	assert.Equal(t, sharedGNMIAuxiliaryEntriesPerCachedSeries, limits[0].series)

	maximum := int(^uint(0) >> 1)
	_, err = partitionSharedGNMIAuxiliaryLimits(
		maximum/sharedGNMIAuxiliaryEntriesPerCachedSeries+1,
		1,
	)
	require.ErrorContains(t, err, "overflows int")
	_, err = partitionSharedGNMIAuxiliaryLimits(-1, 0)
	require.ErrorContains(t, err, "cannot be negative")
}

func TestSharedGNMIReceiverRejectsTooManyTargetsForGlobalCacheCount(t *testing.T) {
	cfg := validGNMITestConfig()
	first := cfg.GNMI.Targets[0]
	first.Name = "target-a"
	first.Endpoint = "target-a.example.test:57400"
	second := first
	second.Name = "target-b"
	second.Endpoint = "target-b.example.test:57400"
	cfg.GNMI.MaxCachedSeries = 1
	cfg.GNMI.Targets = []GNMITargetConfig{first, second}

	_, err := newSharedGNMIReceiver(
		receivertest.NewNopSettings(metadata.Type),
		cfg,
		consumertest.NewNop(),
	)
	require.ErrorContains(t, err, "smaller than selected target count")
}
