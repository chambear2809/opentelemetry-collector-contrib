// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package fixture

import "go.opentelemetry.io/collector/pdata/pmetric"

type metricBuilder struct {
	metric pmetric.Metric
}

func (b metricBuilder) setName(name string) {
	b.metric.SetName(name)
}

type unrelatedBuilder struct{}

func (unrelatedBuilder) SetName(_ string) {}

func emitMetrics(metrics metricBuilder, labels unrelatedBuilder) {
	metrics.setName("fixture.typed_callee")
	labels.SetName("not-a-metric")
}
