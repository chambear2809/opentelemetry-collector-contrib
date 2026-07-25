// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package fixture

func emitMetrics(recorder metricRecorder) {
	recorder.recordInt("fixture.conflict", "Fixture metric.", "1", 1, nil)
	recorder.recordSum("fixture.conflict", "Fixture metric.", "1", 1, nil)
}

type metricRecorder interface {
	recordInt(string, string, string, int64, map[string]string)
	recordSum(string, string, string, int64, map[string]string)
}
