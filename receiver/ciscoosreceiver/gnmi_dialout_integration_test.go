// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver"
)

func TestGNMIDialOutNetworkPathDeliversNormalizedTelemetry(t *testing.T) {
	requireGNMIDialOutIntegrationRuntime(t)
	tests := []struct {
		name         string
		encodingPath string
		metricPrefix string
		transport    string
		create       func(string, consumer.Metrics) (receiver.Metrics, error)
	}{
		{
			name:         "IOS XR",
			encodingPath: "Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/latest/generic-counters",
			metricPrefix: "cisco.iosxr.yang.",
			transport:    iosXRTelemetryTransportDialOut,
			create: func(endpoint string, next consumer.Metrics) (receiver.Metrics, error) {
				cfg := defaultIOSXRConfig()
				cfg.DialOut.NetAddr.Endpoint = endpoint
				cfg.DialOut.AllowedClients = []string{"127.0.0.1"}
				return newIOSXRDialOutReceiver(receivertest.NewNopSettings(componentmetadata.Type), cfg, deviceSelectionMatcher{}, next)
			},
		},
		{
			name:         "Catalyst 9800",
			encodingPath: "Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data/access-point",
			metricPrefix: "cisco.catalyst9800.yang.",
			transport:    catalyst9800TelemetryTransportDialOut,
			create: func(endpoint string, next consumer.Metrics) (receiver.Metrics, error) {
				cfg := defaultCatalyst9800Config()
				cfg.DialOut.NetAddr.Endpoint = endpoint
				cfg.DialOut.AllowedClients = []string{"127.0.0.1"}
				return newCatalyst9800DialOutReceiver(receivertest.NewNopSettings(componentmetadata.Type), cfg, deviceSelectionMatcher{}, next)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := unusedGNMIDialOutEndpoint(t)
			sink := &consumertest.MetricsSink{}
			rcvr, err := tt.create(endpoint, sink)
			require.NoError(t, err)
			startGNMIDialOutTestReceiver(t, rcvr)

			err = sendRawGNMIDialOut(t, endpoint, rawMDTDialOutFrame("router-1", tt.encodingPath, "utilization", 42))
			require.ErrorIs(t, err, io.EOF)
			requireNormalizedDialOutMetrics(t, sink.AllMetrics(), tt.metricPrefix, tt.transport)
		})
	}
}

func TestGNMIDialOutNetworkPathEnforcesAuthorizationAndMessageRate(t *testing.T) {
	requireGNMIDialOutIntegrationRuntime(t)
	t.Run("authorization denial", func(t *testing.T) {
		endpoint := unusedGNMIDialOutEndpoint(t)
		sink := &consumertest.MetricsSink{}
		cfg := defaultIOSXRConfig()
		cfg.DialOut.NetAddr.Endpoint = endpoint
		cfg.DialOut.AllowedClients = []string{"192.0.2.10"}
		rcvr, err := newIOSXRDialOutReceiver(receivertest.NewNopSettings(componentmetadata.Type), cfg, deviceSelectionMatcher{}, sink)
		require.NoError(t, err)
		startGNMIDialOutTestReceiver(t, rcvr)

		err = sendRawGNMIDialOut(t, endpoint, []byte{1}, rawMDTDialOutFrame("router-1", "Cisco-IOS-XR-infra-statsd-oper:infra-statistics", "utilization", 42))
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
		assert.Empty(t, sink.AllMetrics())
	})

	t.Run("per-message rate limiting", func(t *testing.T) {
		endpoint := unusedGNMIDialOutEndpoint(t)
		sink := &consumertest.MetricsSink{}
		cfg := defaultIOSXRConfig()
		cfg.DialOut.NetAddr.Endpoint = endpoint
		cfg.DialOut.AllowedClients = []string{"127.0.0.1"}
		cfg.DialOut.RateLimiting = yanggrpcreceiver.RateLimitingConfig{
			Enabled:           true,
			RequestsPerSecond: 0.000001,
			BurstSize:         1,
			CleanupInterval:   time.Minute,
		}
		rcvr, err := newIOSXRDialOutReceiver(receivertest.NewNopSettings(componentmetadata.Type), cfg, deviceSelectionMatcher{}, sink)
		require.NoError(t, err)
		startGNMIDialOutTestReceiver(t, rcvr)

		frame := rawMDTDialOutFrame("router-1", "Cisco-IOS-XR-infra-statsd-oper:infra-statistics", "utilization", 42)
		err = sendRawGNMIDialOut(t, endpoint, frame, frame)
		assert.Equal(t, codes.ResourceExhausted, status.Code(err))
		require.Len(t, sink.AllMetrics(), 1)
	})
}

func requireGNMIDialOutIntegrationRuntime(t *testing.T) {
	t.Helper()
	if err := requireHardenedYangGRPCRuntime(&yanggrpcreceiver.Config{}); err != nil {
		t.Skipf("linked yanggrpcreceiver is intentionally rejected: %v", err)
	}
}

func startGNMIDialOutTestReceiver(t *testing.T, rcvr receiver.Metrics) {
	t.Helper()
	require.NoError(t, rcvr.Start(t.Context(), componenttest.NewNopHost()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()
		require.NoError(t, rcvr.Shutdown(ctx))
	})
}

func unusedGNMIDialOutEndpoint(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	endpoint := listener.Addr().String()
	require.NoError(t, listener.Close())
	return endpoint
}

func sendRawGNMIDialOut(t *testing.T, endpoint string, frames ...[]byte) error {
	t.Helper()
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() { require.NoError(t, conn.Close()) }()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, err := conn.NewStream(
		ctx,
		&grpc.StreamDesc{StreamName: "MdtDialout", ClientStreams: true, ServerStreams: true},
		gnmiDialOutTestMethod,
		grpc.ForceCodec(gnmiDialOutRawCodec{}),
	)
	require.NoError(t, err)
	for _, payload := range frames {
		frame := gnmiDialOutRawFrame(payload)
		if err := stream.SendMsg(&frame); err != nil {
			return err
		}
	}
	require.NoError(t, stream.CloseSend())
	var response gnmiDialOutRawFrame
	return stream.RecvMsg(&response)
}

type gnmiDialOutRawFrame []byte

type gnmiDialOutRawCodec struct{}

func (gnmiDialOutRawCodec) Marshal(value any) ([]byte, error) {
	frame, ok := value.(*gnmiDialOutRawFrame)
	if !ok {
		return nil, fmt.Errorf("unexpected raw gNMI dial-out message type %T", value)
	}
	return append([]byte(nil), (*frame)...), nil
}

func (gnmiDialOutRawCodec) Unmarshal(data []byte, value any) error {
	frame, ok := value.(*gnmiDialOutRawFrame)
	if !ok {
		return fmt.Errorf("unexpected raw gNMI dial-out response type %T", value)
	}
	*frame = append((*frame)[:0], data...)
	return nil
}

func (gnmiDialOutRawCodec) Name() string { return "proto" }

func rawMDTDialOutFrame(nodeID, encodingPath, fieldName string, value uint64) []byte {
	field := protowire.AppendTag(nil, 2, protowire.BytesType)
	field = protowire.AppendString(field, fieldName)
	field = protowire.AppendTag(field, 8, protowire.VarintType)
	field = protowire.AppendVarint(field, value)

	telemetry := protowire.AppendTag(nil, 1, protowire.BytesType)
	telemetry = protowire.AppendString(telemetry, nodeID)
	telemetry = protowire.AppendTag(telemetry, 6, protowire.BytesType)
	telemetry = protowire.AppendString(telemetry, encodingPath)
	telemetry = protowire.AppendTag(telemetry, 10, protowire.VarintType)
	telemetry = protowire.AppendVarint(telemetry, uint64(time.Now().UnixMilli()))
	telemetry = protowire.AppendTag(telemetry, 11, protowire.BytesType)
	telemetry = protowire.AppendBytes(telemetry, field)

	request := protowire.AppendTag(nil, 1, protowire.VarintType)
	request = protowire.AppendVarint(request, 1)
	request = protowire.AppendTag(request, 2, protowire.BytesType)
	return protowire.AppendBytes(request, telemetry)
}

func requireNormalizedDialOutMetrics(t *testing.T, batches []pmetric.Metrics, prefix, transport string) {
	t.Helper()
	var foundMetric, foundTransport bool
	for _, batch := range batches {
		resourceMetrics := batch.ResourceMetrics()
		for i := 0; i < resourceMetrics.Len(); i++ {
			rm := resourceMetrics.At(i)
			if value, ok := rm.Resource().Attributes().Get("cisco.telemetry.transport"); ok && value.Str() == transport {
				foundTransport = true
			}
			scopeMetrics := rm.ScopeMetrics()
			for j := 0; j < scopeMetrics.Len(); j++ {
				metrics := scopeMetrics.At(j).Metrics()
				for k := 0; k < metrics.Len(); k++ {
					if strings.HasPrefix(metrics.At(k).Name(), prefix) {
						foundMetric = true
					}
				}
			}
		}
	}
	require.True(t, foundMetric, "expected a metric with prefix %q", prefix)
	require.True(t, foundTransport, "expected transport attribute %q", transport)
}
