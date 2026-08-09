// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package fixture

func emitMetrics(recorder metricRecorder) {
	recorder.recordInt("fixture.numeric_conflict", "Fixture gauge.", "1", 1, nil)
	recorder.recordDouble("fixture.numeric_conflict", "Fixture gauge.", "1", 1, nil)
}

type metricRecorder interface {
	recordInt(string, string, string, int64, map[string]string)
	recordDouble(string, string, string, float64, map[string]string)
}
