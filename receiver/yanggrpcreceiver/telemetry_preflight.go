// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package yanggrpcreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver"

import (
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
)

// telemetryWireBudget rejects protobuf expansion before proto.Unmarshal creates
// a Go object for every nested GPB-KV field. A small wire payload can otherwise
// encode millions of empty repeated messages and exceed the post-unmarshal
// conversion limits before those limits get a chance to run.
type telemetryWireBudget struct {
	limits      telemetryConversionLimits
	objects     int
	fields      int
	compactRows int
	variants    int
	allocations int
	wireOps     int
	stringBytes int
}

// Each decoded object normally contains only a handful of protobuf fields.
// Keep a separate, generous wire-operation multiplier so unknown fields can
// neither turn one bounded frame into millions of parser iterations nor make
// legitimate TelemetryField objects consume the entire operation budget.
const (
	telemetryWireOperationsPerObject = 8
	telemetryWireVariantHeadroom     = 16
	// A string-valued GPB-KV field can allocate the field object, a name
	// string, a oneof wrapper, and its string value. Keep the pre-unmarshal
	// allocation ceiling aligned with that densest valid shape while rejecting
	// duplicate singular strings/bytes that do not increase semantic fields.
	telemetryWireAllocationsPerObject = 4
	telemetryWireAllocationHeadroom   = 64
)

func preflightTelemetryPayload(raw []byte, limits telemetryConversionLimits) error {
	budget := telemetryWireBudget{limits: limits.withDefaults()}
	for len(raw) > 0 {
		number, wireType, value, rest, err := budget.consumeField(raw)
		if err != nil {
			if status.Code(err) == codes.ResourceExhausted {
				return err
			}
			return status.Errorf(codes.InvalidArgument, "invalid telemetry payload: %v", err)
		}
		switch number {
		case 1: // node_id_str
			if wireType == protowire.BytesType {
				if err := budget.reserveVariant(); err != nil {
					return err
				}
				if err := budget.reserveString("node_id_str", value, budget.limits.MaxAttrValueBytes); err != nil {
					return err
				}
			}
		case 3: // subscription_id_str
			if wireType == protowire.BytesType {
				if err := budget.reserveVariant(); err != nil {
					return err
				}
				if err := budget.reserveString("subscription_id_str", value, budget.limits.MaxAttrValueBytes); err != nil {
					return err
				}
			}
		case 4: // subscription_id
			if wireType == protowire.VarintType {
				if err := budget.reserveVariant(); err != nil {
					return err
				}
			}
		case 6: // encoding_path
			if wireType == protowire.BytesType {
				if err := budget.reserveString("encoding_path", value, budget.limits.MaxAttrValueBytes); err != nil {
					return err
				}
			}
		case 11: // data_gpbkv
			if wireType != protowire.BytesType {
				return status.Error(codes.InvalidArgument, "invalid telemetry payload: data_gpbkv has invalid wire type")
			}
			if err := budget.scanField(value, 1); err != nil {
				return err
			}
		case 12: // data_gpb
			if wireType != protowire.BytesType {
				return status.Error(codes.InvalidArgument, "invalid telemetry payload: data_gpb has invalid wire type")
			}
			if err := budget.reserveAllocation(); err != nil {
				return err
			}
			if err := budget.scanCompactTable(value); err != nil {
				return err
			}
		}
		raw = rest
	}
	return nil
}

func (b *telemetryWireBudget) scanField(raw []byte, depth int) error {
	if depth > b.limits.MaxDepth {
		return status.Errorf(codes.ResourceExhausted, "telemetry field nesting exceeds %d levels", b.limits.MaxDepth)
	}
	if err := b.reserveObject(false); err != nil {
		return err
	}
	for len(raw) > 0 {
		number, wireType, value, rest, err := b.consumeField(raw)
		if err != nil {
			if status.Code(err) == codes.ResourceExhausted {
				return err
			}
			return status.Errorf(codes.InvalidArgument, "invalid telemetry field payload: %v", err)
		}
		switch number {
		case 2: // name
			if wireType == protowire.BytesType {
				if err := b.reserveString("field name", value, b.limits.MaxAttrKeyBytes); err != nil {
					return err
				}
			}
		case 5: // string_value
			if wireType == protowire.BytesType {
				if err := b.reserveVariant(); err != nil {
					return err
				}
				if err := b.reserveString("field string value", value, b.limits.MaxAttrValueBytes); err != nil {
					return err
				}
			}
		case 4: // bytes_value
			if wireType == protowire.BytesType {
				if err := b.reserveVariant(); err != nil {
					return err
				}
				if err := b.reserveAllocation(); err != nil {
					return err
				}
			}
		case 6, 7, 8, 9, 10: // bool, uint32, uint64, sint32, sint64
			if wireType == protowire.VarintType {
				if err := b.reserveVariant(); err != nil {
					return err
				}
			}
		case 11: // double_value
			if wireType == protowire.Fixed64Type {
				if err := b.reserveVariant(); err != nil {
					return err
				}
			}
		case 12: // float_value
			if wireType == protowire.Fixed32Type {
				if err := b.reserveVariant(); err != nil {
					return err
				}
			}
		case 15: // fields
			if wireType != protowire.BytesType {
				return status.Error(codes.InvalidArgument, "invalid telemetry field payload: nested field has invalid wire type")
			}
			if err := b.scanField(value, depth+1); err != nil {
				return err
			}
		}
		raw = rest
	}
	return nil
}

func (b *telemetryWireBudget) scanCompactTable(raw []byte) error {
	for len(raw) > 0 {
		number, wireType, value, rest, err := b.consumeField(raw)
		if err != nil {
			if status.Code(err) == codes.ResourceExhausted {
				return err
			}
			return status.Errorf(codes.InvalidArgument, "invalid compact GPB payload: %v", err)
		}
		if number == 1 {
			if wireType != protowire.BytesType {
				return status.Error(codes.InvalidArgument, "invalid compact GPB payload: row has invalid wire type")
			}
			if err := b.reserveObject(true); err != nil {
				return err
			}
			if err := b.scanCompactRow(value); err != nil {
				return err
			}
		}
		raw = rest
	}
	return nil
}

func (b *telemetryWireBudget) scanCompactRow(raw []byte) error {
	for len(raw) > 0 {
		number, wireType, _, rest, err := b.consumeField(raw)
		if err != nil {
			if status.Code(err) == codes.ResourceExhausted {
				return err
			}
			return status.Errorf(codes.InvalidArgument, "invalid compact GPB row payload: %v", err)
		}
		switch number {
		case 1: // timestamp
			if wireType != protowire.VarintType {
				return status.Error(codes.InvalidArgument, "invalid compact GPB row payload: timestamp has invalid wire type")
			}
		case 10: // keys
			if wireType != protowire.BytesType {
				return status.Error(codes.InvalidArgument, "invalid compact GPB row payload: keys has invalid wire type")
			}
			if err := b.reserveAllocation(); err != nil {
				return err
			}
		case 11: // content
			if wireType != protowire.BytesType {
				return status.Error(codes.InvalidArgument, "invalid compact GPB row payload: content has invalid wire type")
			}
			if err := b.reserveAllocation(); err != nil {
				return err
			}
		}
		raw = rest
	}
	return nil
}

func (b *telemetryWireBudget) reserveObject(compactRow bool) error {
	if err := b.reserveAllocation(); err != nil {
		return err
	}
	b.objects++
	if compactRow {
		b.compactRows++
	} else {
		b.fields++
	}
	if b.objects <= b.limits.MaxFields {
		return nil
	}
	if b.fields == 0 {
		return status.Errorf(codes.ResourceExhausted, "telemetry payload exceeds %d compact GPB rows", b.limits.MaxFields)
	}
	if b.compactRows == 0 {
		return status.Errorf(codes.ResourceExhausted, "telemetry payload exceeds %d fields", b.limits.MaxFields)
	}
	return status.Errorf(
		codes.ResourceExhausted,
		"telemetry payload exceeds %d total GPB-KV fields and compact GPB rows",
		b.limits.MaxFields,
	)
}

func (b *telemetryWireBudget) reserveVariant() error {
	if err := b.reserveAllocation(); err != nil {
		return err
	}
	b.variants++
	maximum := b.limits.MaxFields
	if maximum <= int(^uint(0)>>1)-telemetryWireVariantHeadroom {
		maximum += telemetryWireVariantHeadroom
	} else {
		maximum = int(^uint(0) >> 1)
	}
	if b.variants > maximum {
		return status.Errorf(
			codes.ResourceExhausted,
			"telemetry payload exceeds %d protobuf value variants",
			maximum,
		)
	}
	return nil
}

func (b *telemetryWireBudget) reserveAllocation() error {
	maximum := telemetryWireAllocationHeadroom
	if b.limits.MaxFields > (int(^uint(0)>>1)-maximum)/telemetryWireAllocationsPerObject {
		maximum = int(^uint(0) >> 1)
	} else {
		maximum += b.limits.MaxFields * telemetryWireAllocationsPerObject
	}
	if b.allocations >= maximum {
		return status.Errorf(
			codes.ResourceExhausted,
			"telemetry payload exceeds %d protobuf allocation units",
			maximum,
		)
	}
	b.allocations++
	return nil
}

func (b *telemetryWireBudget) consumeField(raw []byte) (protowire.Number, protowire.Type, []byte, []byte, error) {
	b.wireOps++
	var maximum int
	if b.limits.MaxFields > int(^uint(0)>>1)/telemetryWireOperationsPerObject {
		maximum = int(^uint(0) >> 1)
	} else {
		maximum = b.limits.MaxFields * telemetryWireOperationsPerObject
	}
	if b.wireOps > maximum {
		return 0, 0, nil, nil, status.Errorf(
			codes.ResourceExhausted,
			"telemetry payload exceeds %d protobuf wire operations",
			maximum,
		)
	}
	return consumeTelemetryWireField(raw)
}

func (b *telemetryWireBudget) reserveString(name string, value []byte, maximum int) error {
	if err := b.reserveAllocation(); err != nil {
		return err
	}
	if len(value) > maximum {
		return status.Errorf(codes.ResourceExhausted, "telemetry %s exceeds %d bytes", name, maximum)
	}
	if len(value) > b.limits.MaxAttributeBytes-b.stringBytes {
		return status.Errorf(codes.ResourceExhausted, "telemetry payload exceeds %d string bytes", b.limits.MaxAttributeBytes)
	}
	b.stringBytes += len(value)
	return nil
}

func consumeTelemetryWireField(raw []byte) (protowire.Number, protowire.Type, []byte, []byte, error) {
	number, wireType, tagBytes := protowire.ConsumeTag(raw)
	if tagBytes < 0 {
		return 0, 0, nil, nil, protowire.ParseError(tagBytes)
	}
	if !number.IsValid() {
		return 0, 0, nil, nil, fmt.Errorf("invalid field number %d", number)
	}
	if wireType == protowire.StartGroupType || wireType == protowire.EndGroupType {
		return 0, 0, nil, nil, errors.New("protobuf groups are not supported")
	}
	payload := raw[tagBytes:]
	if wireType == protowire.BytesType {
		value, valueBytes := protowire.ConsumeBytes(payload)
		if valueBytes < 0 {
			return 0, 0, nil, nil, protowire.ParseError(valueBytes)
		}
		return number, wireType, value, payload[valueBytes:], nil
	}
	valueBytes := protowire.ConsumeFieldValue(number, wireType, payload)
	if valueBytes < 0 {
		return 0, 0, nil, nil, protowire.ParseError(valueBytes)
	}
	return number, wireType, nil, payload[valueBytes:], nil
}
