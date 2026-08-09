// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package fixture

import "go.opentelemetry.io/collector/pdata/pmetric"

var emitTopLevelMetric = func(metric pmetric.Metric) {
	metric.SetName("fixture.top_level_literal")
}

func emitCatalogedMetric(metric pmetric.Metric) {
	metric.SetName("fixture.cataloged")
}
