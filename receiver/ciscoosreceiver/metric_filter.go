// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"path"
	"strings"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

type metricFilteringConsumer struct {
	next   consumer.Metrics
	config *Config
}

func newMetricFilteringConsumer(next consumer.Metrics, config *Config) consumer.Metrics {
	if config == nil || len(config.Metrics) == 0 {
		return next
	}
	return &metricFilteringConsumer{
		next:   next,
		config: config,
	}
}

func (c *metricFilteringConsumer) Capabilities() consumer.Capabilities {
	return c.next.Capabilities()
}

func (c *metricFilteringConsumer) ConsumeMetrics(ctx context.Context, md pmetric.Metrics) error {
	filterMetricsByConfig(md, c.config)
	if md.MetricCount() == 0 {
		return nil
	}
	return c.next.ConsumeMetrics(ctx, md)
}

func filterMetricsByConfig(md pmetric.Metrics, config *Config) {
	if config == nil || len(config.Metrics) == 0 {
		return
	}

	md.ResourceMetrics().RemoveIf(func(rm pmetric.ResourceMetrics) bool {
		rm.ScopeMetrics().RemoveIf(func(sm pmetric.ScopeMetrics) bool {
			sm.Metrics().RemoveIf(func(metric pmetric.Metric) bool {
				return !config.metricEnabled(metric.Name())
			})
			return sm.Metrics().Len() == 0
		})
		return rm.ScopeMetrics().Len() == 0
	})
}

func (cfg *Config) metricEnabled(name string) bool {
	if cfg == nil {
		return true
	}
	metric, ok := cfg.Metrics[name]
	if ok {
		return metric.Enabled
	}

	matched := false
	bestPattern := ""
	bestPatternEnabled := true
	for pattern, metric := range cfg.Metrics {
		if !isMetricNamePattern(pattern) || !metricNamePatternMatches(pattern, name) {
			continue
		}
		if !matched || len(pattern) > len(bestPattern) || (len(pattern) == len(bestPattern) && pattern > bestPattern) {
			matched = true
			bestPattern = pattern
			bestPatternEnabled = metric.Enabled
		}
	}
	if matched {
		return bestPatternEnabled
	}
	return true
}

func isMetricNamePattern(name string) bool {
	return strings.ContainsAny(name, "*?[")
}

func validMetricNamePattern(pattern string) bool {
	_, err := path.Match(pattern, "")
	return err == nil
}

func metricNamePatternMatches(pattern, name string) bool {
	matches, err := path.Match(pattern, name)
	return err == nil && matches
}
