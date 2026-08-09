// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"unicode/utf8"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/mem"
	"google.golang.org/protobuf/encoding/protowire"
)

const (
	gnmiWireMaximumMessageMiB    = 16
	gnmiWireObjectsPerMessageMiB = 25_000
	gnmiWireObjectHeadroom       = 256
	gnmiWireOperationsPerObject  = 8
	gnmiWireMaximumMessageBytes  = gnmiWireMaximumMessageMiB * 1024 * 1024
	// Eight allocation-bearing wire objects per decoded-point ceiling admits
	// 50,000 ordinary updates containing an Update, one-element Path, element
	// name, TypedValue, and scalar oneof wrapper. Structurally denser messages
	// can be rejected below the point ceiling because this limit bounds raw
	// protobuf heap amplification rather than final metric cardinality.
	gnmiWireMaximumObjects          = gnmiWireMaximumMessageMiB*gnmiWireObjectsPerMessageMiB + gnmiWireObjectHeadroom
	gnmiWireMaximumOperations       = gnmiWireMaximumObjects * gnmiWireOperationsPerObject
	gnmiWireMaximumDepth            = 128
	gnmiWireMaximumStringBytes      = gnmiWireMaximumMessageBytes
	gnmiWireMaximumOpaqueBytes      = gnmiWireMaximumMessageBytes
	gnmiWireMaximumDecodedResponses = 8
)

type gnmiWirePreflightLimits struct {
	maxMessageBytes int
	maxObjects      int
	maxOperations   int
	maxDepth        int
	maxStringBytes  int
	maxOpaqueBytes  int
}

func defaultGNMIWirePreflightLimits() gnmiWirePreflightLimits {
	return gnmiWirePreflightLimits{
		maxMessageBytes: gnmiWireMaximumMessageBytes,
		maxObjects:      gnmiWireMaximumObjects,
		maxOperations:   gnmiWireMaximumOperations,
		maxDepth:        gnmiWireMaximumDepth,
		maxStringBytes:  gnmiWireMaximumStringBytes,
		maxOpaqueBytes:  gnmiWireMaximumOpaqueBytes,
	}
}

// gnmiWirePreflightLimitsForRecvSize aligns byte ceilings with the transport's
// per-stream frame allowance. The semantic object ceiling remains high enough
// for a dense 50,000-update response; gnmiResponseAdmission independently
// bounds how many expanded responses can be retained receiver-wide.
func gnmiWirePreflightLimitsForRecvSize(maxRecvMsgSizeMiB int) gnmiWirePreflightLimits {
	if maxRecvMsgSizeMiB <= 0 || maxRecvMsgSizeMiB > gnmiWireMaximumMessageMiB {
		return defaultGNMIWirePreflightLimits()
	}
	messageBytes := maxRecvMsgSizeMiB * 1024 * 1024
	return gnmiWirePreflightLimits{
		maxMessageBytes: messageBytes,
		maxObjects:      gnmiWireMaximumObjects,
		maxOperations:   gnmiWireMaximumOperations,
		maxDepth:        gnmiWireMaximumDepth,
		maxStringBytes:  messageBytes,
		maxOpaqueBytes:  messageBytes,
	}
}

// gnmiResponseAdmission bounds successfully unmarshaled responses that are
// retained by subscription goroutines. Acquisition happens inside the codec
// before materializing a potentially fragmented frame and proto.Unmarshal;
// the receiver releases the slot only after processing the returned response.
type gnmiResponseAdmission struct {
	slots chan struct{}
	mu    sync.Mutex
	// leases is keyed by the exact protobuf destination pointer. grpc-go can
	// unmarshal a second response into the same destination while checking a
	// unary RPC's cardinality. Treating that second decode as the same lease
	// prevents a malicious peer from deadlocking an already-admitted unary call.
	leases map[any]struct{}
}

func newGNMIResponseAdmission() *gnmiResponseAdmission {
	return newGNMIResponseAdmissionWithLimit(gnmiWireMaximumDecodedResponses)
}

func newGNMIResponseAdmissionWithLimit(limit int) *gnmiResponseAdmission {
	return &gnmiResponseAdmission{
		slots:  make(chan struct{}, limit),
		leases: make(map[any]struct{}, limit),
	}
}

func (a *gnmiResponseAdmission) acquire(value any, done <-chan struct{}) error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	_, alreadyAdmitted := a.leases[value]
	a.mu.Unlock()
	if alreadyAdmitted {
		return nil
	}
	if done == nil {
		a.slots <- struct{}{}
	} else {
		select {
		case <-done:
			return errors.New("gNMI response admission canceled")
		default:
		}
		select {
		case a.slots <- struct{}{}:
			select {
			case <-done:
				<-a.slots
				return errors.New("gNMI response admission canceled")
			default:
			}
		case <-done:
			return errors.New("gNMI response admission canceled")
		}
	}

	// The same destination is not used concurrently by grpc-go, but collapse
	// duplicate acquisition defensively so the channel and lease map cannot
	// diverge if a custom ClientConn implementation does so.
	a.mu.Lock()
	if _, exists := a.leases[value]; exists {
		a.mu.Unlock()
		<-a.slots
		return nil
	}
	a.leases[value] = struct{}{}
	a.mu.Unlock()
	return nil
}

func (a *gnmiResponseAdmission) release(value any) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.leases[value]; !exists {
		return
	}
	delete(a.leases, value)
	<-a.slots
}

// gnmiResponsePreflightCodec wraps grpc-go's registered protobuf codec. Only
// responses accepted from a device are inspected; request marshaling and every
// other protobuf type retain grpc-go's standard codec behavior.
type gnmiResponsePreflightCodec struct {
	protobuf  encoding.CodecV2
	limits    gnmiWirePreflightLimits
	admission *gnmiResponseAdmission
	done      <-chan struct{}
}

func newGNMIResponsePreflightCodec(limits gnmiWirePreflightLimits) *gnmiResponsePreflightCodec {
	protobuf := encoding.GetCodecV2("proto")
	if protobuf == nil {
		panic("grpc protobuf codec is not registered")
	}
	return &gnmiResponsePreflightCodec{protobuf: protobuf, limits: limits}
}

func (c *gnmiResponsePreflightCodec) Marshal(value any) (mem.BufferSlice, error) {
	return c.protobuf.Marshal(value)
}

func (c *gnmiResponsePreflightCodec) Unmarshal(data mem.BufferSlice, value any) error {
	var kind gnmiWireMessageKind
	switch value.(type) {
	case *gnmipb.CapabilityResponse:
		kind = gnmiWireCapabilityResponse
	case *gnmipb.SubscribeResponse:
		kind = gnmiWireSubscribeResponse
	default:
		return c.protobuf.Unmarshal(data, value)
	}

	if data.Len() > c.limits.maxMessageBytes {
		return fmt.Errorf("gNMI response preflight: message exceeds %d bytes", c.limits.maxMessageBytes)
	}
	if err := c.admission.acquire(value, c.done); err != nil {
		return err
	}
	// HTTP/2 transport data may be segmented. Materialize only after admission
	// so blocked streams cannot each retain an extra contiguous frame copy.
	buffer := data.MaterializeToBuffer(mem.DefaultBufferPool())
	defer buffer.Free()
	if err := preflightGNMIWireMessage(buffer.ReadOnlyData(), kind, c.limits); err != nil {
		c.admission.release(value)
		return fmt.Errorf("gNMI response preflight: %w", err)
	}
	// Delegate the already-materialized buffer. Passing the original fragmented
	// slice would make grpc-go's protobuf codec materialize a second contiguous
	// copy and double peak frame memory on the normal segmented transport path.
	if err := c.protobuf.Unmarshal(mem.BufferSlice{buffer}, value); err != nil {
		c.admission.release(value)
		return err
	}
	return nil
}

func (c *gnmiResponsePreflightCodec) Name() string {
	return c.protobuf.Name()
}

func gnmiResponsePreflightCallOption(
	maxRecvMsgSizeMiB int,
	admission *gnmiResponseAdmission,
	done <-chan struct{},
) grpc.CallOption {
	codec := newGNMIResponsePreflightCodec(gnmiWirePreflightLimitsForRecvSize(maxRecvMsgSizeMiB))
	codec.admission = admission
	codec.done = done
	return grpc.ForceCodecV2(codec)
}

// invokeGNMICapabilities retains ownership of the response destination even
// when grpc-go rejects a response trailer or unary cardinality. Generated gNMI
// code returns nil in those cases, which would otherwise make a codec-acquired
// admission lease impossible for the caller to identify and release.
func invokeGNMICapabilities(
	ctx context.Context,
	conn grpc.ClientConnInterface,
	admission *gnmiResponseAdmission,
	maxRecvMsgSizeMiB int,
) (*gnmipb.CapabilityResponse, error) {
	response := &gnmipb.CapabilityResponse{}
	err := conn.Invoke(
		ctx,
		gnmipb.GNMI_Capabilities_FullMethodName,
		&gnmipb.CapabilityRequest{},
		response,
		grpc.StaticMethod(),
		gnmiResponsePreflightCallOption(maxRecvMsgSizeMiB, admission, ctx.Done()),
	)
	if err != nil {
		admission.release(response)
		return nil, err
	}
	return response, nil
}

// receiveGNMISubscribeResponse keeps the response pointer in caller-owned
// scope even when a client-stream interceptor reports an error after the
// underlying RecvMsg decoded it. Generated Recv helpers return nil on any
// error, which would otherwise strand the keyed admission lease.
func receiveGNMISubscribeResponse(
	stream grpc.ClientStream,
	admission *gnmiResponseAdmission,
) (*gnmipb.SubscribeResponse, error) {
	response := &gnmipb.SubscribeResponse{}
	if err := stream.RecvMsg(response); err != nil {
		admission.release(response)
		return nil, err
	}
	return response, nil
}

type gnmiWireMessageKind uint8

const (
	gnmiWireCapabilityResponse gnmiWireMessageKind = iota
	gnmiWireModelData
	gnmiWireSubscribeResponse
	gnmiWireNotification
	gnmiWireUpdate
	gnmiWirePath
	gnmiWirePathElem
	gnmiWirePathElemKey
	gnmiWireValue
	gnmiWireTypedValue
	gnmiWireDecimal64
	gnmiWireScalarArray
	gnmiWireError
	gnmiWireAny
	gnmiWireExtension
	gnmiWireRegisteredExtension
	gnmiWireMasterArbitration
	gnmiWireRole
	gnmiWireUint128
	gnmiWireHistory
	gnmiWireTimeRange
	gnmiWireCommit
	gnmiWireCommitRequest
	gnmiWireDuration
	gnmiWireEmpty
	gnmiWireCommitSetRollbackDuration
	gnmiWireDepth
	gnmiWireConfigSubscription
	gnmiWireConfigSubscriptionSyncDone
)

func (k gnmiWireMessageKind) String() string {
	switch k {
	case gnmiWireCapabilityResponse:
		return "CapabilityResponse"
	case gnmiWireModelData:
		return "ModelData"
	case gnmiWireSubscribeResponse:
		return "SubscribeResponse"
	case gnmiWireNotification:
		return "Notification"
	case gnmiWireUpdate:
		return "Update"
	case gnmiWirePath:
		return "Path"
	case gnmiWirePathElem:
		return "PathElem"
	case gnmiWirePathElemKey:
		return "PathElem.key"
	case gnmiWireValue:
		return "Value"
	case gnmiWireTypedValue:
		return "TypedValue"
	case gnmiWireDecimal64:
		return "Decimal64"
	case gnmiWireScalarArray:
		return "ScalarArray"
	case gnmiWireError:
		return "Error"
	case gnmiWireAny:
		return "Any"
	case gnmiWireExtension:
		return "Extension"
	case gnmiWireRegisteredExtension:
		return "RegisteredExtension"
	case gnmiWireMasterArbitration:
		return "MasterArbitration"
	case gnmiWireRole:
		return "Role"
	case gnmiWireUint128:
		return "Uint128"
	case gnmiWireHistory:
		return "History"
	case gnmiWireTimeRange:
		return "TimeRange"
	case gnmiWireCommit:
		return "Commit"
	case gnmiWireCommitRequest:
		return "CommitRequest"
	case gnmiWireDuration:
		return "Duration"
	case gnmiWireEmpty:
		return "empty extension message"
	case gnmiWireCommitSetRollbackDuration:
		return "CommitSetRollbackDuration"
	case gnmiWireDepth:
		return "Depth"
	case gnmiWireConfigSubscription:
		return "ConfigSubscription"
	case gnmiWireConfigSubscriptionSyncDone:
		return "ConfigSubscriptionSyncDone"
	default:
		return "unknown message"
	}
}

type gnmiWireFieldKind uint8

const (
	gnmiWireVarint gnmiWireFieldKind = iota
	gnmiWireFixed32
	gnmiWireFixed64
	gnmiWireString
	gnmiWireOpaque
	gnmiWireMessage
	gnmiWireRepeatedVarint
)

type gnmiWireFieldSpec struct {
	kind    gnmiWireFieldKind
	message gnmiWireMessageKind
	oneof   bool
}

type gnmiWirePreflightBudget struct {
	limits      gnmiWirePreflightLimits
	objects     int
	operations  int
	stringBytes int
	opaqueBytes int
}

func preflightGNMIWireMessage(data []byte, kind gnmiWireMessageKind, limits gnmiWirePreflightLimits) error {
	if limits.maxMessageBytes <= 0 || limits.maxObjects <= 0 || limits.maxOperations <= 0 ||
		limits.maxDepth <= 0 || limits.maxStringBytes <= 0 || limits.maxOpaqueBytes <= 0 {
		return errors.New("invalid gNMI wire limits")
	}
	if len(data) > limits.maxMessageBytes {
		return fmt.Errorf("message exceeds %d bytes", limits.maxMessageBytes)
	}
	budget := gnmiWirePreflightBudget{limits: limits}
	return budget.scanMessage(data, kind, 1)
}

func (b *gnmiWirePreflightBudget) scanMessage(data []byte, kind gnmiWireMessageKind, depth int) error {
	if depth > b.limits.maxDepth {
		return fmt.Errorf("message nesting exceeds %d", b.limits.maxDepth)
	}
	if err := b.reserveObject(); err != nil {
		return err
	}
	for len(data) > 0 {
		if err := b.visitOperation(); err != nil {
			return err
		}
		number, wireType, tagBytes := protowire.ConsumeTag(data)
		if tagBytes < 0 {
			return fmt.Errorf("%s has malformed tag: %w", kind, protowire.ParseError(tagBytes))
		}
		if !number.IsValid() {
			return fmt.Errorf("%s has invalid field number %d", kind, number)
		}
		if wireType == protowire.StartGroupType || wireType == protowire.EndGroupType {
			return fmt.Errorf("%s field %d uses forbidden group wire type", kind, number)
		}
		data = data[tagBytes:]
		spec, known := gnmiWireKnownField(kind, number)
		var consumed int
		var err error
		if known {
			consumed, err = b.consumeKnownField(data, kind, number, wireType, spec, depth)
		} else {
			consumed, err = b.consumeUnknownField(data, kind, number, wireType)
		}
		if err != nil {
			return err
		}
		data = data[consumed:]
	}
	return nil
}

func (b *gnmiWirePreflightBudget) consumeKnownField(
	data []byte,
	message gnmiWireMessageKind,
	number protowire.Number,
	wireType protowire.Type,
	spec gnmiWireFieldSpec,
	depth int,
) (int, error) {
	switch spec.kind {
	case gnmiWireVarint:
		if err := requireGNMIWireType(message, number, wireType, protowire.VarintType); err != nil {
			return 0, err
		}
		_, consumed := protowire.ConsumeVarint(data)
		if consumed < 0 {
			return 0, malformedGNMIWireValue(message, number, consumed)
		}
		if spec.oneof {
			if err := b.reserveObject(); err != nil {
				return 0, err
			}
		}
		return consumed, nil
	case gnmiWireFixed32:
		if err := requireGNMIWireType(message, number, wireType, protowire.Fixed32Type); err != nil {
			return 0, err
		}
		_, consumed := protowire.ConsumeFixed32(data)
		if consumed < 0 {
			return 0, malformedGNMIWireValue(message, number, consumed)
		}
		if spec.oneof {
			if err := b.reserveObject(); err != nil {
				return 0, err
			}
		}
		return consumed, nil
	case gnmiWireFixed64:
		if err := requireGNMIWireType(message, number, wireType, protowire.Fixed64Type); err != nil {
			return 0, err
		}
		_, consumed := protowire.ConsumeFixed64(data)
		if consumed < 0 {
			return 0, malformedGNMIWireValue(message, number, consumed)
		}
		if spec.oneof {
			if err := b.reserveObject(); err != nil {
				return 0, err
			}
		}
		return consumed, nil
	case gnmiWireString, gnmiWireOpaque, gnmiWireMessage:
		if err := requireGNMIWireType(message, number, wireType, protowire.BytesType); err != nil {
			return 0, err
		}
		value, consumed := protowire.ConsumeBytes(data)
		if consumed < 0 {
			return 0, malformedGNMIWireValue(message, number, consumed)
		}
		if spec.oneof {
			if err := b.reserveObject(); err != nil {
				return 0, err
			}
		}
		switch spec.kind {
		case gnmiWireString:
			if !utf8.Valid(value) {
				return 0, fmt.Errorf("%s field %d contains invalid UTF-8", message, number)
			}
			if err := b.reserveObject(); err != nil {
				return 0, err
			}
			if err := b.reserveStringBytes(len(value)); err != nil {
				return 0, err
			}
		case gnmiWireOpaque:
			if err := b.reserveObject(); err != nil {
				return 0, err
			}
			if err := b.reserveOpaqueBytes(len(value)); err != nil {
				return 0, err
			}
		case gnmiWireMessage:
			if err := b.scanMessage(value, spec.message, depth+1); err != nil {
				return 0, fmt.Errorf("%s field %d: %w", message, number, err)
			}
		}
		return consumed, nil
	case gnmiWireRepeatedVarint:
		return b.consumeRepeatedVarint(data, message, number, wireType)
	default:
		return 0, fmt.Errorf("%s field %d has unsupported preflight specification", message, number)
	}
}

func (b *gnmiWirePreflightBudget) consumeRepeatedVarint(
	data []byte,
	message gnmiWireMessageKind,
	number protowire.Number,
	wireType protowire.Type,
) (int, error) {
	switch wireType {
	case protowire.VarintType:
		_, consumed := protowire.ConsumeVarint(data)
		if consumed < 0 {
			return 0, malformedGNMIWireValue(message, number, consumed)
		}
		if err := b.reserveObject(); err != nil {
			return 0, err
		}
		return consumed, nil
	case protowire.BytesType:
		packed, consumed := protowire.ConsumeBytes(data)
		if consumed < 0 {
			return 0, malformedGNMIWireValue(message, number, consumed)
		}
		for len(packed) > 0 {
			if err := b.visitOperation(); err != nil {
				return 0, err
			}
			_, valueBytes := protowire.ConsumeVarint(packed)
			if valueBytes < 0 {
				return 0, malformedGNMIWireValue(message, number, valueBytes)
			}
			if err := b.reserveObject(); err != nil {
				return 0, err
			}
			packed = packed[valueBytes:]
		}
		return consumed, nil
	default:
		return 0, fmt.Errorf("%s field %d has wire type %d, want varint or bytes", message, number, wireType)
	}
}

func (b *gnmiWirePreflightBudget) consumeUnknownField(
	data []byte,
	message gnmiWireMessageKind,
	number protowire.Number,
	wireType protowire.Type,
) (int, error) {
	if wireType == protowire.BytesType {
		value, consumed := protowire.ConsumeBytes(data)
		if consumed < 0 {
			return 0, malformedGNMIWireValue(message, number, consumed)
		}
		if err := b.reserveObject(); err != nil {
			return 0, err
		}
		if err := b.reserveOpaqueBytes(len(value)); err != nil {
			return 0, err
		}
		return consumed, nil
	}
	consumed := protowire.ConsumeFieldValue(number, wireType, data)
	if consumed < 0 {
		return 0, malformedGNMIWireValue(message, number, consumed)
	}
	return consumed, nil
}

func (b *gnmiWirePreflightBudget) reserveObject() error {
	if b.objects >= b.limits.maxObjects {
		return fmt.Errorf("decoded object count exceeds %d", b.limits.maxObjects)
	}
	b.objects++
	return nil
}

func (b *gnmiWirePreflightBudget) visitOperation() error {
	if b.operations >= b.limits.maxOperations {
		return fmt.Errorf("wire operation count exceeds %d", b.limits.maxOperations)
	}
	b.operations++
	return nil
}

func (b *gnmiWirePreflightBudget) reserveStringBytes(amount int) error {
	if amount < 0 || amount > b.limits.maxStringBytes-b.stringBytes {
		return fmt.Errorf("aggregate string bytes exceed %d", b.limits.maxStringBytes)
	}
	b.stringBytes += amount
	return nil
}

func (b *gnmiWirePreflightBudget) reserveOpaqueBytes(amount int) error {
	if amount < 0 || amount > b.limits.maxOpaqueBytes-b.opaqueBytes {
		return fmt.Errorf("aggregate opaque bytes exceed %d", b.limits.maxOpaqueBytes)
	}
	b.opaqueBytes += amount
	return nil
}

func requireGNMIWireType(message gnmiWireMessageKind, number protowire.Number, got, want protowire.Type) error {
	if got != want {
		return fmt.Errorf("%s field %d has wire type %d, want %d", message, number, got, want)
	}
	return nil
}

func malformedGNMIWireValue(message gnmiWireMessageKind, number protowire.Number, consumed int) error {
	return fmt.Errorf("%s field %d is malformed: %w", message, number, protowire.ParseError(consumed))
}

func gnmiWireKnownField(message gnmiWireMessageKind, number protowire.Number) (gnmiWireFieldSpec, bool) {
	varint := gnmiWireFieldSpec{kind: gnmiWireVarint}
	oneofVarint := gnmiWireFieldSpec{kind: gnmiWireVarint, oneof: true}
	oneofFixed32 := gnmiWireFieldSpec{kind: gnmiWireFixed32, oneof: true}
	oneofFixed64 := gnmiWireFieldSpec{kind: gnmiWireFixed64, oneof: true}
	stringField := gnmiWireFieldSpec{kind: gnmiWireString}
	oneofString := gnmiWireFieldSpec{kind: gnmiWireString, oneof: true}
	opaque := gnmiWireFieldSpec{kind: gnmiWireOpaque}
	oneofOpaque := gnmiWireFieldSpec{kind: gnmiWireOpaque, oneof: true}
	repeatedVarint := gnmiWireFieldSpec{kind: gnmiWireRepeatedVarint}
	nested := func(kind gnmiWireMessageKind) gnmiWireFieldSpec {
		return gnmiWireFieldSpec{kind: gnmiWireMessage, message: kind}
	}
	oneofNested := func(kind gnmiWireMessageKind) gnmiWireFieldSpec {
		return gnmiWireFieldSpec{kind: gnmiWireMessage, message: kind, oneof: true}
	}

	switch message {
	case gnmiWireCapabilityResponse:
		switch number {
		case 1:
			return nested(gnmiWireModelData), true
		case 2:
			return repeatedVarint, true
		case 3:
			return stringField, true
		case 4:
			return nested(gnmiWireExtension), true
		}
	case gnmiWireModelData:
		if number >= 1 && number <= 3 {
			return stringField, true
		}
	case gnmiWireSubscribeResponse:
		switch number {
		case 1:
			return oneofNested(gnmiWireNotification), true
		case 3:
			return oneofVarint, true
		case 4:
			return oneofNested(gnmiWireError), true
		case 5:
			return nested(gnmiWireExtension), true
		}
	case gnmiWireNotification:
		switch number {
		case 1, 6:
			return varint, true
		case 2:
			return nested(gnmiWirePath), true
		case 4:
			return nested(gnmiWireUpdate), true
		case 5:
			return nested(gnmiWirePath), true
		}
	case gnmiWireUpdate:
		switch number {
		case 1:
			return nested(gnmiWirePath), true
		case 2:
			return nested(gnmiWireValue), true
		case 3:
			return nested(gnmiWireTypedValue), true
		case 4:
			return varint, true
		}
	case gnmiWirePath:
		switch number {
		case 1, 2, 4:
			return stringField, true
		case 3:
			return nested(gnmiWirePathElem), true
		}
	case gnmiWirePathElem:
		switch number {
		case 1:
			return stringField, true
		case 2:
			return nested(gnmiWirePathElemKey), true
		}
	case gnmiWirePathElemKey:
		if number == 1 || number == 2 {
			return stringField, true
		}
	case gnmiWireValue:
		switch number {
		case 1:
			return opaque, true
		case 2:
			return varint, true
		}
	case gnmiWireTypedValue:
		switch number {
		case 1, 12:
			return oneofString, true
		case 2, 3, 4:
			return oneofVarint, true
		case 5, 10, 11, 13:
			return oneofOpaque, true
		case 6:
			return oneofFixed32, true
		case 7:
			return oneofNested(gnmiWireDecimal64), true
		case 8:
			return oneofNested(gnmiWireScalarArray), true
		case 9:
			return oneofNested(gnmiWireAny), true
		case 14:
			return oneofFixed64, true
		}
	case gnmiWireDecimal64:
		if number == 1 || number == 2 {
			return varint, true
		}
	case gnmiWireScalarArray:
		if number == 1 {
			return nested(gnmiWireTypedValue), true
		}
	case gnmiWireError:
		switch number {
		case 1:
			return varint, true
		case 2:
			return stringField, true
		case 3:
			return nested(gnmiWireAny), true
		}
	case gnmiWireAny:
		switch number {
		case 1:
			return stringField, true
		case 2:
			return opaque, true
		}
	case gnmiWireExtension:
		switch number {
		case 1:
			return oneofNested(gnmiWireRegisteredExtension), true
		case 2:
			return oneofNested(gnmiWireMasterArbitration), true
		case 3:
			return oneofNested(gnmiWireHistory), true
		case 4:
			return oneofNested(gnmiWireCommit), true
		case 5:
			return oneofNested(gnmiWireDepth), true
		case 6:
			return oneofNested(gnmiWireConfigSubscription), true
		}
	case gnmiWireRegisteredExtension:
		switch number {
		case 1:
			return varint, true
		case 2:
			return opaque, true
		}
	case gnmiWireMasterArbitration:
		switch number {
		case 1:
			return nested(gnmiWireRole), true
		case 2:
			return nested(gnmiWireUint128), true
		}
	case gnmiWireRole:
		if number == 1 {
			return stringField, true
		}
	case gnmiWireUint128, gnmiWireTimeRange, gnmiWireDuration:
		if number == 1 || number == 2 {
			return varint, true
		}
	case gnmiWireHistory:
		switch number {
		case 1:
			return oneofVarint, true
		case 2:
			return oneofNested(gnmiWireTimeRange), true
		}
	case gnmiWireCommit:
		switch number {
		case 1:
			return stringField, true
		case 2:
			return oneofNested(gnmiWireCommitRequest), true
		case 3, 4:
			return oneofNested(gnmiWireEmpty), true
		case 5:
			return oneofNested(gnmiWireCommitSetRollbackDuration), true
		}
	case gnmiWireCommitRequest, gnmiWireCommitSetRollbackDuration:
		if number == 1 {
			return nested(gnmiWireDuration), true
		}
	case gnmiWireDepth:
		if number == 1 {
			return varint, true
		}
	case gnmiWireConfigSubscription:
		switch number {
		case 1:
			return oneofNested(gnmiWireEmpty), true
		case 2:
			return oneofNested(gnmiWireConfigSubscriptionSyncDone), true
		}
	case gnmiWireConfigSubscriptionSyncDone:
		switch number {
		case 1, 2:
			return stringField, true
		case 3:
			return varint, true
		}
	case gnmiWireEmpty:
		// Empty extension messages intentionally accept valid unknown fields for
		// forward compatibility, subject to the global operation/byte limits.
	}
	return gnmiWireFieldSpec{}, false
}
