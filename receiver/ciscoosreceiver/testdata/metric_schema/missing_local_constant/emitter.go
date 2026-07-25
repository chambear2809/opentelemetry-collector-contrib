// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package fixture

import "go.opentelemetry.io/collector/pdata/pmetric"

func emitMetrics(metric pmetric.Metric) {
	const name = "heartbeat"
	if false {
		metric.SetName(name)
	}
}
