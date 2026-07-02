// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

func TestMetricFilteringConsumerCapabilitiesMutates(t *testing.T) {
	cfg := &Config{Metrics: map[string]MetricConfig{"foo": {Enabled: false}}}
	wrapped := newMetricFilteringConsumer(consumertest.NewNop(), cfg)
	require.True(t, wrapped.Capabilities().MutatesData,
		"filtering consumer mutates input via RemoveIf and must declare MutatesData=true")
}

func TestMetricFilteringConsumerNoConfigPassthrough(t *testing.T) {
	next := consumertest.NewNop()
	require.Same(t, next, newMetricFilteringConsumer(next, &Config{}),
		"with no metric filters, the wrapper must return the underlying consumer unwrapped")
	require.Same(t, next, newMetricFilteringConsumer(next, nil))
}

func TestMetricFilteringConsumerFiltersAndForwards(t *testing.T) {
	cfg := &Config{Metrics: map[string]MetricConfig{
		"keep": {Enabled: true},
		"drop": {Enabled: false},
	}}

	sink := &consumertest.MetricsSink{}
	wrapped := newMetricFilteringConsumer(sink, cfg)

	md := pmetric.NewMetrics()
	sm := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	sm.Metrics().AppendEmpty().SetName("keep")
	sm.Metrics().AppendEmpty().SetName("drop")

	require.NoError(t, wrapped.ConsumeMetrics(t.Context(), md))
	require.Len(t, sink.AllMetrics(), 1)
	got := sink.AllMetrics()[0]
	require.Equal(t, 1, got.MetricCount())
	assert.Equal(t, "keep", got.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Name())
}

var _ consumer.Metrics = (*metricFilteringConsumer)(nil)
