// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package yanggrpcreceiver

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver/internal/proto/generated/proto"
)

func TestReceiverStreamSecurityInterceptor(t *testing.T) {
	tests := []struct {
		name           string
		allowedClients []string
		wantCode       codes.Code
	}{
		{
			name:           "allowed peer",
			allowedClients: []string{"127.0.0.1"},
			wantCode:       codes.OK,
		},
		{
			name:           "denied peer",
			allowedClients: []string{"192.0.2.10"},
			wantCode:       codes.PermissionDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := unusedLocalEndpoint(t)
			cfg := createDefaultConfig().(*Config)
			cfg.ServerConfig.NetAddr.Endpoint = endpoint
			cfg.Security.AllowedClients = tt.allowedClients

			rcvr := createMetricsReceiver(t.Context(), createTestSettings(), cfg, consumertest.NewNop())
			require.NoError(t, rcvr.Start(t.Context(), componenttest.NewNopHost()))
			t.Cleanup(func() {
				require.NoError(t, rcvr.Shutdown(context.WithoutCancel(t.Context())))
			})

			conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, conn.Close())
			})

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			stream, err := pb.NewGRPCMdtDialoutClient(conn).MdtDialout(ctx)
			require.NoError(t, err)
			require.NoError(t, stream.CloseSend())
			_, err = stream.Recv()

			if tt.wantCode == codes.OK {
				require.ErrorIs(t, err, io.EOF, "expected an accepted stream to close normally")
				return
			}
			require.Equal(t, tt.wantCode, status.Code(err))
		})
	}
}

func TestReceiverRateLimitsEachStreamMessage(t *testing.T) {
	endpoint := unusedLocalEndpoint(t)
	cfg := createDefaultConfig().(*Config)
	cfg.ServerConfig.NetAddr.Endpoint = endpoint
	cfg.Security.RateLimiting.Enabled = true
	cfg.Security.RateLimiting.RequestsPerSecond = 0.000001
	cfg.Security.RateLimiting.BurstSize = 1
	rcvr := createMetricsReceiver(t.Context(), createTestSettings(), cfg, consumertest.NewNop())
	require.NoError(t, rcvr.Start(t.Context(), componenttest.NewNopHost()))
	t.Cleanup(func() { require.NoError(t, rcvr.Shutdown(context.WithoutCancel(t.Context()))) })

	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, err := pb.NewGRPCMdtDialoutClient(conn).MdtDialout(ctx)
	require.NoError(t, err)
	payload, err := proto.Marshal(&pb.Telemetry{MsgTimestamp: 1})
	require.NoError(t, err)
	require.NoError(t, stream.Send(&pb.MdtDialoutArgs{Data: payload}))
	require.NoError(t, stream.Send(&pb.MdtDialoutArgs{Data: payload}))
	require.NoError(t, stream.CloseSend())
	_, err = stream.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
}

func TestReceiverStartRejectsAggregateFrameBudget(t *testing.T) {
	endpoint := unusedLocalEndpoint(t)
	cfg := createDefaultConfig().(*Config)
	cfg.ServerConfig.NetAddr.Endpoint = endpoint
	cfg.ServerConfig.MaxConcurrentStreams = 65
	receiver := createMetricsReceiver(t.Context(), createTestSettings(), cfg, consumertest.NewNop())
	require.ErrorContains(t, receiver.Start(t.Context(), componenttest.NewNopHost()), "must not exceed 256 MiB")
	require.NoError(t, receiver.Shutdown(t.Context()))

	listener, err := net.Listen("tcp", endpoint)
	require.NoError(t, err, "invalid configuration must be rejected before binding the listener")
	require.NoError(t, listener.Close())
}

func TestReceiverRejectsGlobalAndPerClientStreamExcess(t *testing.T) {
	tests := []struct {
		name            string
		globalLimit     uint32
		perClientLimit  uint32
		acceptedStreams int
		wantMessage     string
	}{
		{
			name:            "global limit spans connections",
			globalLimit:     2,
			perClientLimit:  2,
			acceptedStreams: 2,
			wantMessage:     "maximum active telemetry streams reached",
		},
		{
			name:            "per-client limit spans connections",
			globalLimit:     3,
			perClientLimit:  1,
			acceptedStreams: 1,
			wantMessage:     "maximum active telemetry streams for client reached",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := unusedLocalEndpoint(t)
			cfg := createDefaultConfig().(*Config)
			cfg.ServerConfig.NetAddr.Endpoint = endpoint
			cfg.ServerConfig.MaxConcurrentStreams = tt.globalLimit
			cfg.MaxConcurrentStreamsPerClient = tt.perClientLimit
			receiver := createMetricsReceiver(t.Context(), createTestSettings(), cfg, consumertest.NewNop()).(*yangReceiver)
			require.NoError(t, receiver.Start(t.Context(), componenttest.NewNopHost()))

			payload, err := proto.Marshal(&pb.Telemetry{MsgTimestamp: 1})
			require.NoError(t, err)
			var accepted []pb.GRPCMdtDialout_MdtDialoutClient
			var connections []*grpc.ClientConn
			for range tt.acceptedStreams {
				conn, stream := openTelemetryStream(t, endpoint)
				connections = append(connections, conn)
				accepted = append(accepted, stream)
				require.NoError(t, stream.Send(&pb.MdtDialoutArgs{Data: payload}))
			}
			require.Eventually(t, func() bool {
				return receiver.streamAdmission.activeCount() == tt.acceptedStreams
			}, 5*time.Second, 10*time.Millisecond)

			rejectedConn, rejected := openTelemetryStream(t, endpoint)
			connections = append(connections, rejectedConn)
			require.NoError(t, rejected.CloseSend())
			_, err = rejected.Recv()
			require.Equal(t, codes.ResourceExhausted, status.Code(err))
			assert.ErrorContains(t, err, tt.wantMessage)

			for _, stream := range accepted {
				require.NoError(t, stream.CloseSend())
				_, recvErr := stream.Recv()
				require.ErrorIs(t, recvErr, io.EOF)
			}
			require.Eventually(t, func() bool {
				return receiver.streamAdmission.activeCount() == 0
			}, 5*time.Second, 10*time.Millisecond)
			require.NoError(t, receiver.Shutdown(t.Context()))
			for _, conn := range connections {
				require.NoError(t, conn.Close())
			}
		})
	}
}

func TestReceiverGracefulShutdownCancelsIdleStream(t *testing.T) {
	endpoint := unusedLocalEndpoint(t)
	cfg := createDefaultConfig().(*Config)
	cfg.ServerConfig.NetAddr.Endpoint = endpoint
	receiver := createMetricsReceiver(t.Context(), createTestSettings(), cfg, consumertest.NewNop()).(*yangReceiver)
	require.NoError(t, receiver.Start(t.Context(), componenttest.NewNopHost()))

	conn, stream := openTelemetryStream(t, endpoint)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	require.Eventually(t, func() bool {
		return receiver.streamAdmission.activeCount() == 1
	}, 5*time.Second, 10*time.Millisecond)

	shutdownCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, receiver.Shutdown(shutdownCtx))
	assert.Zero(t, receiver.streamAdmission.activeCount())
	_, err := stream.Recv()
	require.Error(t, err)
}

func TestReceiverStreamIdleTimeoutReleasesAdmission(t *testing.T) {
	endpoint := unusedLocalEndpoint(t)
	cfg := createDefaultConfig().(*Config)
	cfg.ServerConfig.NetAddr.Endpoint = endpoint
	cfg.ServerConfig.MaxConcurrentStreams = 1
	cfg.MaxConcurrentStreamsPerClient = 1
	cfg.StreamIdleTimeout = minStreamIdleTimeout
	receiver := createMetricsReceiver(t.Context(), createTestSettings(), cfg, consumertest.NewNop()).(*yangReceiver)
	require.NoError(t, receiver.Start(t.Context(), componenttest.NewNopHost()))
	t.Cleanup(func() { require.NoError(t, receiver.Shutdown(context.WithoutCancel(t.Context()))) })

	conn, stream := openTelemetryStream(t, endpoint)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	require.Eventually(t, func() bool {
		return receiver.streamAdmission.activeCount() == 1
	}, 5*time.Second, 10*time.Millisecond)

	_, err := stream.Recv()
	require.Equal(t, codes.DeadlineExceeded, status.Code(err))
	assert.ErrorContains(t, err, "telemetry stream idle timeout exceeded after 1s")
	require.Eventually(t, func() bool {
		return receiver.streamAdmission.activeCount() == 0
	}, 5*time.Second, 10*time.Millisecond)

	// The expired stream must not retain either the global or per-client slot.
	replacementConn, replacement := openTelemetryStream(t, endpoint)
	t.Cleanup(func() { require.NoError(t, replacementConn.Close()) })
	require.NoError(t, replacement.CloseSend())
	_, err = replacement.Recv()
	require.ErrorIs(t, err, io.EOF)
}

func TestReceiverStreamActivityRefreshesIdleTimeout(t *testing.T) {
	endpoint := unusedLocalEndpoint(t)
	cfg := createDefaultConfig().(*Config)
	cfg.ServerConfig.NetAddr.Endpoint = endpoint
	cfg.StreamIdleTimeout = 2 * minStreamIdleTimeout
	sink := &consumertest.MetricsSink{}
	receiver := createMetricsReceiver(t.Context(), createTestSettings(), cfg, sink).(*yangReceiver)
	require.NoError(t, receiver.Start(t.Context(), componenttest.NewNopHost()))
	t.Cleanup(func() { require.NoError(t, receiver.Shutdown(context.WithoutCancel(t.Context()))) })

	conn, stream := openTelemetryStream(t, endpoint)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	payload, err := proto.Marshal(&pb.Telemetry{MsgTimestamp: 1})
	require.NoError(t, err)

	const messages = 5
	for i := range messages {
		require.NoError(t, stream.Send(&pb.MdtDialoutArgs{Data: payload}))
		require.Eventually(t, func() bool {
			return len(sink.AllMetrics()) == i+1
		}, 5*time.Second, 10*time.Millisecond)
		time.Sleep(500 * time.Millisecond)
	}

	// More than one idle period has elapsed since the stream was admitted, but
	// each received message refreshed the deadline.
	assert.Equal(t, 1, receiver.streamAdmission.activeCount())
	require.NoError(t, stream.CloseSend())
	_, err = stream.Recv()
	require.ErrorIs(t, err, io.EOF)
}

func TestReceiverStartFailureCleansUpSecurityAndListener(t *testing.T) {
	endpoint := unusedLocalEndpoint(t)
	cfg := createDefaultConfig().(*Config)
	cfg.ServerConfig.NetAddr.Endpoint = endpoint
	cfg.Security.RateLimiting.Enabled = true

	missingPEM := filepath.Join(t.TempDir(), "missing.pem")
	tlsConfig := confmap.NewFromStringMap(map[string]any{
		"tls": map[string]any{
			"cert_file": missingPEM,
			"key_file":  missingPEM,
		},
	})
	require.NoError(t, tlsConfig.Unmarshal(cfg))

	rcvr := createMetricsReceiver(t.Context(), createTestSettings(), cfg, consumertest.NewNop())
	require.Error(t, rcvr.Start(t.Context(), componenttest.NewNopHost()))
	require.NoError(t, rcvr.Shutdown(t.Context()))

	listener, err := net.Listen("tcp", endpoint)
	require.NoError(t, err, "failed Start must release the listener")
	require.NoError(t, listener.Close())
}

func TestReceiverModuleLoadFailureCleansUpSecurityAndListener(t *testing.T) {
	endpoint := unusedLocalEndpoint(t)
	cfg := createDefaultConfig().(*Config)
	cfg.ServerConfig.NetAddr.Endpoint = endpoint
	cfg.Security.RateLimiting.Enabled = true
	cfg.YANG.ModulePaths = []string{filepath.Join(t.TempDir(), "missing")}

	rcvr := createMetricsReceiver(t.Context(), createTestSettings(), cfg, consumertest.NewNop())
	require.ErrorContains(t, rcvr.Start(t.Context(), componenttest.NewNopHost()), "load YANG modules")
	require.NoError(t, rcvr.Shutdown(t.Context()))

	listener, err := net.Listen("tcp", endpoint)
	require.NoError(t, err, "failed Start must release the listener")
	require.NoError(t, listener.Close())
}

func TestReceiverShutdownCancelsActiveStreamBeforeGracefulStop(t *testing.T) {
	endpoint := unusedLocalEndpoint(t)
	cfg := createDefaultConfig().(*Config)
	cfg.ServerConfig.NetAddr.Endpoint = endpoint
	next := &blockingMetricsConsumer{started: make(chan struct{}), canceled: make(chan struct{})}
	rcvr := createMetricsReceiver(t.Context(), createTestSettings(), cfg, next)
	require.NoError(t, rcvr.Start(t.Context(), componenttest.NewNopHost()))

	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	stream, err := pb.NewGRPCMdtDialoutClient(conn).MdtDialout(t.Context())
	require.NoError(t, err)
	payload, err := proto.Marshal(&pb.Telemetry{MsgTimestamp: 1})
	require.NoError(t, err)
	require.NoError(t, stream.Send(&pb.MdtDialoutArgs{Data: payload}))

	select {
	case <-next.started:
	case <-time.After(5 * time.Second):
		t.Fatal("telemetry consumer did not start")
	}

	shutdownCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err = rcvr.Shutdown(shutdownCtx)
	require.NoError(t, err)
	select {
	case <-next.canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("forced shutdown did not cancel the stream consumer context")
	}
}

func TestReceiverShutdownDeadlineDoesNotWaitForBlockedDownstream(t *testing.T) {
	endpoint := unusedLocalEndpoint(t)
	cfg := createDefaultConfig().(*Config)
	cfg.ServerConfig.NetAddr.Endpoint = endpoint
	next := &nonCooperativeMetricsConsumer{
		started:  make(chan struct{}),
		release:  make(chan struct{}),
		finished: make(chan struct{}),
	}
	t.Cleanup(next.Release)
	rcvr := createMetricsReceiver(t.Context(), createTestSettings(), cfg, next)
	require.NoError(t, rcvr.Start(t.Context(), componenttest.NewNopHost()))

	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	stream, err := pb.NewGRPCMdtDialoutClient(conn).MdtDialout(t.Context())
	require.NoError(t, err)
	payload, err := proto.Marshal(&pb.Telemetry{MsgTimestamp: 1})
	require.NoError(t, err)
	require.NoError(t, stream.Send(&pb.MdtDialoutArgs{Data: payload}))

	select {
	case <-next.started:
	case <-time.After(5 * time.Second):
		t.Fatal("telemetry consumer did not start")
	}

	shutdownCtx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	shutdownResult := make(chan error, 1)
	go func() {
		shutdownResult <- rcvr.Shutdown(shutdownCtx)
	}()

	select {
	case err := <-shutdownResult:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(2 * time.Second):
		next.Release()
		select {
		case <-shutdownResult:
		case <-time.After(5 * time.Second):
		}
		t.Fatal("receiver shutdown remained blocked after its deadline")
	}

	next.Release()
	select {
	case <-next.finished:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked downstream consumer did not finish after release")
	}
	// Join the graceful-stop goroutine after the intentionally non-cooperative
	// consumer is released so this test itself leaves no background work behind.
	require.NoError(t, rcvr.Shutdown(t.Context()))
}

type blockingMetricsConsumer struct {
	started  chan struct{}
	canceled chan struct{}
}

type nonCooperativeMetricsConsumer struct {
	started     chan struct{}
	release     chan struct{}
	finished    chan struct{}
	once        sync.Once
	releaseOnce sync.Once
}

func (*nonCooperativeMetricsConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (c *nonCooperativeMetricsConsumer) ConsumeMetrics(context.Context, pmetric.Metrics) error {
	c.once.Do(func() { close(c.started) })
	<-c.release
	close(c.finished)
	return nil
}

func (c *nonCooperativeMetricsConsumer) Release() {
	c.releaseOnce.Do(func() { close(c.release) })
}

func (*blockingMetricsConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (c *blockingMetricsConsumer) ConsumeMetrics(ctx context.Context, _ pmetric.Metrics) error {
	close(c.started)
	<-ctx.Done()
	close(c.canceled)
	return ctx.Err()
}

func unusedLocalEndpoint(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	endpoint := listener.Addr().String()
	require.NoError(t, listener.Close())
	return endpoint
}

func openTelemetryStream(t *testing.T, endpoint string) (*grpc.ClientConn, pb.GRPCMdtDialout_MdtDialoutClient) {
	t.Helper()
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	stream, err := pb.NewGRPCMdtDialoutClient(conn).MdtDialout(ctx)
	require.NoError(t, err)
	return conn, stream
}
