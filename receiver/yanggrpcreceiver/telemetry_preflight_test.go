// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package yanggrpcreceiver

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	pb "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver/internal/proto/generated/proto"
)

func TestPreflightTelemetryPayloadRejectsExpansionBeforeUnmarshal(t *testing.T) {
	limits := telemetryConversionLimits{
		MaxFields:          2,
		MaxDepth:           2,
		MaxAttrKeyBytes:    8,
		MaxAttrValueBytes:  8,
		MaxAttributeBytes:  16,
		MaxMetrics:         10,
		MaxAttributes:      10,
		MaxAttrsPerMetric:  4,
		MaxMetricNameBytes: 32,
	}
	field := telemetryWireBytesField(2, []byte("leaf"))

	t.Run("field count", func(t *testing.T) {
		payload := appendTelemetryWireBytesField(nil, 11, field)
		payload = appendTelemetryWireBytesField(payload, 11, field)
		payload = appendTelemetryWireBytesField(payload, 11, field)
		err := preflightTelemetryPayload(payload, limits)
		require.Equal(t, codes.ResourceExhausted, status.Code(err))
		assert.ErrorContains(t, err, "exceeds 2 fields")
	})

	t.Run("depth", func(t *testing.T) {
		nested := appendTelemetryWireBytesField(nil, 15, field)
		nested = appendTelemetryWireBytesField(nil, 15, nested)
		payload := appendTelemetryWireBytesField(nil, 11, nested)
		err := preflightTelemetryPayload(payload, limits)
		require.Equal(t, codes.ResourceExhausted, status.Code(err))
		assert.ErrorContains(t, err, "exceeds 2 levels")
	})

	t.Run("node ID", func(t *testing.T) {
		payload := appendTelemetryWireBytesField(nil, 1, []byte(strings.Repeat("n", 9)))
		err := preflightTelemetryPayload(payload, limits)
		require.Equal(t, codes.ResourceExhausted, status.Code(err))
		assert.ErrorContains(t, err, "node_id_str exceeds 8 bytes")
	})

	t.Run("compact rows", func(t *testing.T) {
		table := appendTelemetryWireBytesField(nil, 1, nil)
		table = appendTelemetryWireBytesField(table, 1, nil)
		table = appendTelemetryWireBytesField(table, 1, nil)
		payload := appendTelemetryWireBytesField(nil, 12, table)
		err := preflightTelemetryPayload(payload, limits)
		require.Equal(t, codes.ResourceExhausted, status.Code(err))
		assert.ErrorContains(t, err, "exceeds 2 compact GPB rows")
	})

	t.Run("malformed", func(t *testing.T) {
		err := preflightTelemetryPayload([]byte{0x5a, 0x08, 0x01}, limits)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})
}

func TestPreflightTelemetryPayloadAcceptsValidGeneratedMessage(t *testing.T) {
	payload, err := proto.Marshal(&pb.Telemetry{
		NodeId:       &pb.Telemetry_NodeIdStr{NodeIdStr: "router-1"},
		EncodingPath: "interfaces/interface",
		DataGpbkv: []*pb.TelemetryField{{
			Name:        "packets",
			ValueByType: &pb.TelemetryField_Uint64Value{Uint64Value: 1},
		}},
	})
	require.NoError(t, err)
	require.NoError(t, preflightTelemetryPayload(payload, telemetryConversionLimits{}))
}

func TestPreflightTelemetryPayloadBoundsEveryWireOperation(t *testing.T) {
	limits := telemetryConversionLimits{MaxFields: 1}
	tests := []struct {
		name    string
		payload func() []byte
	}{
		{
			name: "top level unknown fields",
			payload: func() []byte {
				return repeatedTelemetryWireVarints(15, telemetryWireOperationsPerObject+1)
			},
		},
		{
			name: "nested field unknown fields",
			payload: func() []byte {
				field := repeatedTelemetryWireVarints(3, telemetryWireOperationsPerObject)
				return appendTelemetryWireBytesField(nil, 11, field)
			},
		},
		{
			name: "compact table unknown fields",
			payload: func() []byte {
				table := repeatedTelemetryWireVarints(2, telemetryWireOperationsPerObject)
				return appendTelemetryWireBytesField(nil, 12, table)
			},
		},
		{
			name: "compact row unknown fields",
			payload: func() []byte {
				row := repeatedTelemetryWireVarints(2, telemetryWireOperationsPerObject-1)
				table := appendTelemetryWireBytesField(nil, 1, row)
				return appendTelemetryWireBytesField(nil, 12, table)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := preflightTelemetryPayload(test.payload(), limits)
			require.Equal(t, codes.ResourceExhausted, status.Code(err))
			assert.ErrorContains(t, err, "protobuf wire operations")
		})
	}
}

func TestPreflightTelemetryPayloadRejectsUnsupportedOrMalformedWireData(t *testing.T) {
	t.Run("unknown group", func(t *testing.T) {
		payload := protowire.AppendTag(nil, 15, protowire.StartGroupType)
		payload = protowire.AppendTag(payload, 15, protowire.EndGroupType)
		err := preflightTelemetryPayload(payload, telemetryConversionLimits{})
		require.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.ErrorContains(t, err, "groups are not supported")
	})

	t.Run("field number above protobuf maximum", func(t *testing.T) {
		payload := protowire.AppendTag(nil, protowire.MaxValidNumber+1, protowire.VarintType)
		payload = protowire.AppendVarint(payload, 0)
		err := preflightTelemetryPayload(payload, telemetryConversionLimits{})
		require.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.ErrorContains(t, err, "invalid field number")
	})

	t.Run("malformed compact row", func(t *testing.T) {
		row := []byte{0x52, 0x08, 0x01} // keys claims eight bytes but contains one.
		table := appendTelemetryWireBytesField(nil, 1, row)
		payload := appendTelemetryWireBytesField(nil, 12, table)
		err := preflightTelemetryPayload(payload, telemetryConversionLimits{})
		require.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.ErrorContains(t, err, "invalid compact GPB row payload")
	})

	t.Run("known message field with wrong wire type", func(t *testing.T) {
		payload := protowire.AppendTag(nil, 11, protowire.VarintType)
		payload = protowire.AppendVarint(payload, 0)
		err := preflightTelemetryPayload(payload, telemetryConversionLimits{})
		require.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.ErrorContains(t, err, "data_gpbkv has invalid wire type")
	})
}

func TestPreflightTelemetryPayloadUsesOneNestedObjectBudget(t *testing.T) {
	field := telemetryWireBytesField(2, []byte("leaf"))
	row := appendTelemetryWireVarintField(nil, 1, 1)
	table := appendTelemetryWireBytesField(nil, 1, row)
	table = appendTelemetryWireBytesField(table, 1, row)
	payload := appendTelemetryWireBytesField(nil, 11, field)
	payload = appendTelemetryWireBytesField(payload, 12, table)

	err := preflightTelemetryPayload(payload, telemetryConversionLimits{MaxFields: 2})
	require.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.ErrorContains(t, err, "total GPB-KV fields and compact GPB rows")
}

func TestPreflightTelemetryPayloadChargesDuplicateSingularStrings(t *testing.T) {
	payload := appendTelemetryWireBytesField(nil, 1, []byte("first"))
	payload = appendTelemetryWireBytesField(payload, 1, []byte("other"))
	err := preflightTelemetryPayload(payload, telemetryConversionLimits{
		MaxFields:         1,
		MaxAttrValueBytes: 8,
		MaxAttributeBytes: 8,
	})
	require.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.ErrorContains(t, err, "string bytes")
}

func TestPreflightTelemetryPayloadBoundsDuplicateOneofAllocations(t *testing.T) {
	const fields = 20
	var payload []byte
	for range fields + telemetryWireVariantHeadroom + 1 {
		payload = appendTelemetryWireBytesField(payload, 1, nil)
	}
	err := preflightTelemetryPayload(payload, telemetryConversionLimits{MaxFields: fields})
	require.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.ErrorContains(t, err, "protobuf value variants")
}

func TestPreflightTelemetryPayloadBoundsDuplicateLengthDelimitedAllocations(t *testing.T) {
	const fields = 100
	maximum := fields*telemetryWireAllocationsPerObject + telemetryWireAllocationHeadroom

	t.Run("singular encoding path strings", func(t *testing.T) {
		var payload []byte
		for range maximum + 1 {
			payload = appendTelemetryWireBytesField(payload, 6, nil)
		}
		err := preflightTelemetryPayload(payload, telemetryConversionLimits{MaxFields: fields})
		require.Equal(t, codes.ResourceExhausted, status.Code(err))
		assert.ErrorContains(t, err, "protobuf allocation units")
	})

	t.Run("compact row byte assignments", func(t *testing.T) {
		var row []byte
		// The table and row consume two allocation units before their byte
		// assignments are scanned.
		for range maximum - 1 {
			row = appendTelemetryWireBytesField(row, 10, nil)
		}
		table := appendTelemetryWireBytesField(nil, 1, row)
		payload := appendTelemetryWireBytesField(nil, 12, table)
		err := preflightTelemetryPayload(payload, telemetryConversionLimits{MaxFields: fields})
		require.Equal(t, codes.ResourceExhausted, status.Code(err))
		assert.ErrorContains(t, err, "protobuf allocation units")
	})
}

func TestPreflightTelemetryPayloadAcceptsValidCompactRows(t *testing.T) {
	payload, err := proto.Marshal(&pb.Telemetry{
		NodeId: &pb.Telemetry_NodeIdStr{NodeIdStr: "router-1"},
		DataGpb: &pb.TelemetryGPBTable{Row: []*pb.TelemetryRowGPB{{
			Timestamp: 1,
			Keys:      []byte{1, 2, 3},
			Content:   []byte{4, 5, 6},
		}}},
	})
	require.NoError(t, err)
	require.NoError(t, preflightTelemetryPayload(payload, telemetryConversionLimits{}))
}

func telemetryWireBytesField(number protowire.Number, value []byte) []byte {
	return appendTelemetryWireBytesField(nil, number, value)
}

func appendTelemetryWireBytesField(destination []byte, number protowire.Number, value []byte) []byte {
	destination = protowire.AppendTag(destination, number, protowire.BytesType)
	return protowire.AppendBytes(destination, value)
}

func appendTelemetryWireVarintField(destination []byte, number protowire.Number, value uint64) []byte {
	destination = protowire.AppendTag(destination, number, protowire.VarintType)
	return protowire.AppendVarint(destination, value)
}

func repeatedTelemetryWireVarints(number protowire.Number, count int) []byte {
	var payload []byte
	for range count {
		payload = appendTelemetryWireVarintField(payload, number, 0)
	}
	return payload
}
