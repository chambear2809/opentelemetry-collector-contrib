// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
)

const obsReportFormat = "ciscoosreceiver"

// newPlatformObsReport returns a receiverhelper.ObsReport for a Cisco platform
// receiver. Errors are surfaced as nil so callers can no-op rather than fail
// receiver construction; obsreport is purely best-effort instrumentation.
func newPlatformObsReport(set receiver.Settings, transport string) *receiverhelper.ObsReport {
	obs, err := receiverhelper.NewObsReport(receiverhelper.ObsReportSettings{
		ReceiverID:             set.ID,
		Transport:              transport,
		ReceiverCreateSettings: set,
	})
	if err != nil {
		return nil
	}
	return obs
}

// startMetricsOp begins an obsreport metrics operation. Safe to call when obs
// is nil.
func startMetricsOp(obs *receiverhelper.ObsReport, ctx context.Context) context.Context {
	if obs == nil {
		return ctx
	}
	return obs.StartMetricsOp(ctx)
}

// endMetricsOp closes the metrics operation started by startMetricsOp.
func endMetricsOp(obs *receiverhelper.ObsReport, ctx context.Context, md pmetric.Metrics, err error) {
	if obs == nil {
		return
	}
	obs.EndMetricsOp(ctx, obsReportFormat, md.DataPointCount(), err)
}

// startLogsOp begins an obsreport logs operation. Safe to call when obs is
// nil.
func startLogsOp(obs *receiverhelper.ObsReport, ctx context.Context) context.Context {
	if obs == nil {
		return ctx
	}
	return obs.StartLogsOp(ctx)
}

// endLogsOp closes the logs operation started by startLogsOp.
func endLogsOp(obs *receiverhelper.ObsReport, ctx context.Context, ld plog.Logs, err error) {
	if obs == nil {
		return
	}
	obs.EndLogsOp(ctx, obsReportFormat, ld.LogRecordCount(), err)
}
