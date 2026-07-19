// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package fixture

import (
	"strings"

	"go.opentelemetry.io/collector/pdata/pmetric"
)

func emitMetrics(metric pmetric.Metric, path []string) {
	metric.SetName("fixture.live")
	metric.SetName(strings.Join(path, "."))
}
