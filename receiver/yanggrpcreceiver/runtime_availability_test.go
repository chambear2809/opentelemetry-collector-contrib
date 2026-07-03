// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package yanggrpcreceiver

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver/internal"
	pb "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver/internal/proto/generated/proto"
)

type availabilityAcceptResult struct {
	conn net.Conn
	err  error
}

func TestLimitedListenerReleasesCapacityAndCloseUnblocksAccept(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	listener := limitTelemetryConnections(base, 1)
	t.Cleanup(func() { _ = listener.Close() })

	accept := func() <-chan availabilityAcceptResult {
		result := make(chan availabilityAcceptResult, 1)
		go func() {
			conn, acceptErr := listener.Accept()
			result <- availabilityAcceptResult{conn: conn, err: acceptErr}
		}()
		return result
	}

	firstAccept := accept()
	firstClient, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = firstClient.Close() })
	var first availabilityAcceptResult
	select {
	case first = <-firstAccept:
	case <-time.After(time.Second):
		t.Fatal("first connection was not accepted")
	}
	require.NoError(t, first.err)
	require.NotNil(t, first.conn)
	t.Cleanup(func() { _ = first.conn.Close() })

	secondAccept := accept()
	secondClient, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secondClient.Close() })
	select {
	case result := <-secondAccept:
		if result.conn != nil {
			_ = result.conn.Close()
		}
		t.Fatalf("second Accept returned before capacity was released: %v", result.err)
	case <-time.After(50 * time.Millisecond):
	}

	require.NoError(t, first.conn.Close())
	var second availabilityAcceptResult
	select {
	case second = <-secondAccept:
	case <-time.After(time.Second):
		t.Fatal("second Accept did not proceed after the first connection closed")
	}
	require.NoError(t, second.err)
	require.NotNil(t, second.conn)
	t.Cleanup(func() { _ = second.conn.Close() })

	blockedAccept := accept()
	require.NoError(t, listener.Close())
	select {
	case result := <-blockedAccept:
		if result.conn != nil {
			_ = result.conn.Close()
		}
		require.Error(t, result.err)
	case <-time.After(time.Second):
		t.Fatal("closing a saturated listener did not unblock Accept")
	}
}

func TestTelemetryProcessingGateBoundsDownstreamConcurrency(t *testing.T) {
	release := make(chan struct{})
	consumer := newAvailabilityBlockingConsumer(release)
	cfg := createValidTestConfig()
	cfg.MaxConcurrentConversions = 2
	receiver := createMetricsReceiver(t.Context(), createTestSettings(), cfg, consumer).(*yangReceiver)
	service := &grpcService{receiver: receiver, yangParser: internal.NewYANGParser()}
	request := availabilityTelemetryRequest(t)

	results := make(chan error, 3)
	for range 3 {
		go func() { results <- service.processTelemetryData(t.Context(), request) }()
	}

	for range 2 {
		select {
		case <-consumer.entered:
		case <-time.After(time.Second):
			t.Fatal("configured processing slots were not filled")
		}
	}
	select {
	case <-consumer.entered:
		t.Fatal("a third conversion reached the consumer while both slots were occupied")
	case <-time.After(50 * time.Millisecond):
	}
	assert.Equal(t, int32(2), consumer.maxActive.Load())

	close(release)
	for range 3 {
		require.NoError(t, <-results)
	}
	assert.Equal(t, int32(2), consumer.maxActive.Load())
}

func TestTelemetryProcessingGateCanceledWaiterDoesNotReachConsumer(t *testing.T) {
	release := make(chan struct{})
	consumer := newAvailabilityBlockingConsumer(release)
	cfg := createValidTestConfig()
	cfg.MaxConcurrentConversions = 1
	receiver := createMetricsReceiver(t.Context(), createTestSettings(), cfg, consumer).(*yangReceiver)
	service := &grpcService{receiver: receiver, yangParser: internal.NewYANGParser()}
	request := availabilityTelemetryRequest(t)

	firstResult := make(chan error, 1)
	go func() { firstResult <- service.processTelemetryData(t.Context(), request) }()
	select {
	case <-consumer.entered:
	case <-time.After(time.Second):
		t.Fatal("first conversion did not reach the consumer")
	}

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	err := service.processTelemetryData(canceled, request)
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, int32(1), consumer.calls.Load())

	close(release)
	require.NoError(t, <-firstResult)
}

func TestTelemetryStreamKeepsOneUnprocessedFrameInFlight(t *testing.T) {
	release := make(chan struct{})
	consumer := newAvailabilityBlockingConsumer(release)
	cfg := createValidTestConfig()
	receiver := createMetricsReceiver(t.Context(), createTestSettings(), cfg, consumer).(*yangReceiver)
	service := &grpcService{receiver: receiver, yangParser: internal.NewYANGParser()}
	request := availabilityTelemetryRequest(t)
	stream := &availabilityTelemetryStream{
		ServerStream: nil,
		ctx:          t.Context(),
		requests:     []*pb.MdtDialoutArgs{request, request},
	}

	result := make(chan error, 1)
	go func() { result <- service.MdtDialout(stream) }()
	select {
	case <-consumer.entered:
	case <-time.After(time.Second):
		t.Fatal("first frame did not reach the consumer")
	}
	assert.Equal(t, int32(1), stream.recvCalls.Load(), "the next frame must not be received while one is unprocessed")

	close(release)
	require.NoError(t, <-result)
	assert.Equal(t, int32(3), stream.recvCalls.Load(), "two frames plus the final EOF should be received")
}

type availabilityBlockingConsumer struct {
	entered   chan struct{}
	release   <-chan struct{}
	calls     atomic.Int32
	active    atomic.Int32
	maxActive atomic.Int32
}

type availabilityTelemetryStream struct {
	grpc.ServerStream
	ctx       context.Context
	requests  []*pb.MdtDialoutArgs
	recvCalls atomic.Int32
}

func (s *availabilityTelemetryStream) Context() context.Context { return s.ctx }

func (s *availabilityTelemetryStream) Recv() (*pb.MdtDialoutArgs, error) {
	index := int(s.recvCalls.Add(1) - 1)
	if index >= len(s.requests) {
		return nil, io.EOF
	}
	return s.requests[index], nil
}

func (*availabilityTelemetryStream) Send(*pb.MdtDialoutArgs) error { return nil }

func newAvailabilityBlockingConsumer(release <-chan struct{}) *availabilityBlockingConsumer {
	return &availabilityBlockingConsumer{
		entered: make(chan struct{}, 3),
		release: release,
	}
}

func (*availabilityBlockingConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (c *availabilityBlockingConsumer) ConsumeMetrics(ctx context.Context, _ pmetric.Metrics) error {
	c.calls.Add(1)
	active := c.active.Add(1)
	defer c.active.Add(-1)
	for {
		maximum := c.maxActive.Load()
		if active <= maximum || c.maxActive.CompareAndSwap(maximum, active) {
			break
		}
	}
	c.entered <- struct{}{}
	select {
	case <-c.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func availabilityTelemetryRequest(t *testing.T) *pb.MdtDialoutArgs {
	t.Helper()
	payload, err := proto.Marshal(&pb.Telemetry{MsgTimestamp: 1})
	require.NoError(t, err)
	return &pb.MdtDialoutArgs{Data: payload}
}
