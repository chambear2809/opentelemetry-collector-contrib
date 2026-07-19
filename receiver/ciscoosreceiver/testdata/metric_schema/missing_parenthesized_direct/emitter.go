// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package fixture

import "go.opentelemetry.io/collector/pdata/pmetric"

func emitMetrics(metric pmetric.Metric) {
	metric.SetName("fixture.cataloged")
	(metric.SetName)("fixture.parenthesized_direct")
}
