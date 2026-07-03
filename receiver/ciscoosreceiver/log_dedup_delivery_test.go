// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestConsumeDeduplicatedLogsCommitsAcceptedBatch(t *testing.T) {
	dedup := newLogDeduplicator()
	now := time.Unix(100, 0)
	dedup.BeginBatch()
	require.True(t, dedup.MarkPending("event-1", now))

	sink := &consumertest.LogsSink{}
	count, err := consumeDeduplicatedLogs(t.Context(), sink, dedup, oneLogRecord())
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, 1, sink.LogRecordCount())

	dedup.BeginBatch()
	assert.False(t, dedup.MarkPending("event-1", now), "accepted event must remain committed")
	dedup.CommitBatch()
}

func TestConsumeDeduplicatedLogsRollsBackRejectedBatch(t *testing.T) {
	dedup := newLogDeduplicator()
	now := time.Unix(100, 0)
	dedup.BeginBatch()
	require.True(t, dedup.MarkPending("event-1", now))
	deliveryErr := errors.New("downstream unavailable")

	count, err := consumeDeduplicatedLogs(t.Context(), consumertest.NewErr(deliveryErr), dedup, oneLogRecord())
	require.ErrorIs(t, err, deliveryErr)
	assert.Equal(t, 1, count)

	dedup.BeginBatch()
	assert.True(t, dedup.MarkPending("event-1", now), "rejected event must be eligible for replay")
	dedup.RollbackBatch()
}

func TestConsumeDeduplicatedLogsRollsBackEmptyBatchWithoutCallingConsumer(t *testing.T) {
	dedup := newLogDeduplicator()
	now := time.Unix(100, 0)
	dedup.BeginBatch()
	require.True(t, dedup.MarkPending("event-1", now))

	count, err := consumeDeduplicatedLogs(
		t.Context(),
		consumertest.NewErr(errors.New("must not be called")),
		dedup,
		plog.NewLogs(),
	)
	require.NoError(t, err)
	assert.Zero(t, count)

	dedup.BeginBatch()
	assert.True(t, dedup.MarkPending("event-1", now), "empty batch must not commit pending events")
	dedup.RollbackBatch()
}

func TestCombineSignalErrorsPreservesScrapeAndDeliveryFailures(t *testing.T) {
	scrapeErr := errors.New("scrape failed")
	deliveryErr := errors.New("delivery failed")

	err := combineSignalErrors(scrapeErr, deliveryErr)
	assert.ErrorIs(t, err, scrapeErr)
	assert.ErrorIs(t, err, deliveryErr)
}

func oneLogRecord() plog.Logs {
	logs := plog.NewLogs()
	logs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	return logs
}
