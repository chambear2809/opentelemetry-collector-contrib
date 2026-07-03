// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	gnmiext "github.com/openconfig/gnmi/proto/gnmi_ext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/mem"
	grpcmetadata "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

func TestGNMIResponsePreflightCodecRoundTrip(t *testing.T) {
	codec := newGNMIResponsePreflightCodec(defaultGNMIWirePreflightLimits())
	tests := []proto.Message{
		&gnmipb.CapabilityResponse{
			SupportedModels: []*gnmipb.ModelData{{Name: "openconfig-interfaces", Organization: "OpenConfig", Version: "1.0"}},
			SupportedEncodings: []gnmipb.Encoding{
				gnmipb.Encoding_JSON_IETF,
				gnmipb.Encoding_PROTO,
			},
			GNMIVersion: "0.10.0",
			Extension: []*gnmiext.Extension{{Ext: &gnmiext.Extension_RegisteredExt{RegisteredExt: &gnmiext.RegisteredExtension{
				Id:  gnmiext.ExtensionID_EID_EXPERIMENTAL,
				Msg: []byte{0xff, 0x00, 0x80}, // Registered payloads are intentionally opaque.
			}}}},
		},
		&gnmipb.SubscribeResponse{
			Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
				Timestamp: 123,
				Prefix: &gnmipb.Path{Origin: "openconfig", Elem: []*gnmipb.PathElem{{
					Name: "interface",
					Key:  map[string]string{"name": "Ethernet1"},
				}}},
				Update: []*gnmipb.Update{{
					Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "state"}}},
					Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_LeaflistVal{LeaflistVal: &gnmipb.ScalarArray{
						Element: []*gnmipb.TypedValue{
							{Value: &gnmipb.TypedValue_StringVal{StringVal: "up"}},
							{Value: &gnmipb.TypedValue_UintVal{UintVal: 42}},
						},
					}}},
				}},
			}},
			Extension: []*gnmiext.Extension{{Ext: &gnmiext.Extension_ConfigSubscription{ConfigSubscription: &gnmiext.ConfigSubscription{
				Action: &gnmiext.ConfigSubscription_SyncDone{SyncDone: &gnmiext.ConfigSubscriptionSyncDone{
					CommitConfirmId: "confirm",
					ServerCommitId:  "server",
					Done:            true,
				}},
			}}}},
		},
	}

	for _, input := range tests {
		t.Run(string(input.ProtoReflect().Descriptor().Name()), func(t *testing.T) {
			encoded, err := codec.Marshal(input)
			require.NoError(t, err)
			defer encoded.Free()
			output := input.ProtoReflect().New().Interface()
			require.NoError(t, codec.Unmarshal(encoded, output))
			assert.True(t, proto.Equal(input, output))
		})
	}
}

func TestGNMIWirePreflightLimitsScaleWithReceiveEnvelope(t *testing.T) {
	limits := gnmiWirePreflightLimitsForRecvSize(legacyGNMIMaxRecvMsgSizeMiB)
	assert.Equal(t, legacyGNMIMaxRecvMsgSizeMiB*1024*1024, limits.maxMessageBytes)
	assert.Equal(t, gnmiWireMaximumObjects, limits.maxObjects)
	assert.Equal(t, gnmiWireMaximumOperations, limits.maxOperations)
	assert.Equal(t, limits.maxMessageBytes, limits.maxStringBytes)
	assert.Equal(t, limits.maxMessageBytes, limits.maxOpaqueBytes)

	assert.Equal(t, defaultGNMIWirePreflightLimits(), gnmiWirePreflightLimitsForRecvSize(0))
	assert.Equal(t, defaultGNMIWirePreflightLimits(), gnmiWirePreflightLimitsForRecvSize(gnmiWireMaximumMessageMiB+1))
}

func TestGNMIResponsePreflightCodecRejectsMalformedWire(t *testing.T) {
	capabilityWrongWire := protowire.AppendTag(nil, 3, protowire.VarintType)
	capabilityWrongWire = protowire.AppendVarint(capabilityWrongWire, 1)
	capabilityInvalidUTF8 := protowire.AppendTag(nil, 3, protowire.BytesType)
	capabilityInvalidUTF8 = protowire.AppendBytes(capabilityInvalidUTF8, []byte{0xff})
	nestedGroup := protowire.AppendTag(nil, 1, protowire.StartGroupType)
	capabilityNestedGroup := protowire.AppendTag(nil, 1, protowire.BytesType)
	capabilityNestedGroup = protowire.AppendBytes(capabilityNestedGroup, nestedGroup)
	malformedPackedEncoding := protowire.AppendTag(nil, 2, protowire.BytesType)
	malformedPackedEncoding = protowire.AppendBytes(malformedPackedEncoding, []byte{0x80})

	tests := []struct {
		name  string
		raw   []byte
		value proto.Message
		err   string
	}{
		{name: "invalid field zero", raw: []byte{0}, value: &gnmipb.CapabilityResponse{}, err: "malformed tag"},
		{name: "group", raw: protowire.AppendTag(nil, 1, protowire.StartGroupType), value: &gnmipb.SubscribeResponse{}, err: "forbidden group"},
		{name: "wrong known wire type", raw: capabilityWrongWire, value: &gnmipb.CapabilityResponse{}, err: "wire type"},
		{name: "invalid UTF-8", raw: capabilityInvalidUTF8, value: &gnmipb.CapabilityResponse{}, err: "invalid UTF-8"},
		{name: "nested group", raw: capabilityNestedGroup, value: &gnmipb.CapabilityResponse{}, err: "forbidden group"},
		{name: "truncated length", raw: []byte{0x0a, 0x05, 0x01}, value: &gnmipb.CapabilityResponse{}, err: "malformed"},
		{name: "malformed packed enum", raw: malformedPackedEncoding, value: &gnmipb.CapabilityResponse{}, err: "malformed"},
	}

	codec := newGNMIResponsePreflightCodec(defaultGNMIWirePreflightLimits())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := codec.Unmarshal(gnmiWireTestBuffers(tt.raw), tt.value)
			require.ErrorContains(t, err, "gNMI response preflight")
			assert.ErrorContains(t, err, tt.err)
		})
	}
}

func TestGNMIWirePreflightChargesPackedRepeatedScalars(t *testing.T) {
	raw := protowire.AppendTag(nil, 2, protowire.BytesType)
	raw = protowire.AppendBytes(raw, []byte{byte(gnmipb.Encoding_JSON), byte(gnmipb.Encoding_PROTO)})

	operationLimits := defaultGNMIWirePreflightLimits()
	operationLimits.maxOperations = 2 // One field tag plus one packed element.
	require.ErrorContains(t, preflightGNMIWireMessage(raw, gnmiWireCapabilityResponse, operationLimits), "operation count")

	objectLimits := defaultGNMIWirePreflightLimits()
	objectLimits.maxObjects = 2 // Root response plus one repeated enum element.
	require.ErrorContains(t, preflightGNMIWireMessage(raw, gnmiWireCapabilityResponse, objectLimits), "object count")
}

func TestGNMIResponsePreflightCodecEnforcesAggregateLimits(t *testing.T) {
	capability := &gnmipb.CapabilityResponse{
		SupportedModels:    []*gnmipb.ModelData{{Name: "one"}, {Name: "two"}},
		SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON, gnmipb.Encoding_PROTO},
		GNMIVersion:        "1234",
	}
	capabilityWire, err := proto.Marshal(capability)
	require.NoError(t, err)
	subscriptionWire, err := proto.Marshal(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
		Update: []*gnmipb.Update{{Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonVal{JsonVal: []byte("not-json")}}}},
	}}})
	require.NoError(t, err)

	tests := []struct {
		name   string
		limits func(*gnmiWirePreflightLimits)
		raw    []byte
		value  proto.Message
		err    string
	}{
		{name: "message bytes", limits: func(l *gnmiWirePreflightLimits) { l.maxMessageBytes = len(capabilityWire) - 1 }, raw: capabilityWire, value: &gnmipb.CapabilityResponse{}, err: "message exceeds"},
		{name: "objects", limits: func(l *gnmiWirePreflightLimits) { l.maxObjects = 2 }, raw: capabilityWire, value: &gnmipb.CapabilityResponse{}, err: "object count"},
		{name: "operations", limits: func(l *gnmiWirePreflightLimits) { l.maxOperations = 1 }, raw: capabilityWire, value: &gnmipb.CapabilityResponse{}, err: "operation count"},
		{name: "strings", limits: func(l *gnmiWirePreflightLimits) { l.maxStringBytes = 3 }, raw: capabilityWire, value: &gnmipb.CapabilityResponse{}, err: "string bytes"},
		{name: "opaque bytes", limits: func(l *gnmiWirePreflightLimits) { l.maxOpaqueBytes = 3 }, raw: subscriptionWire, value: &gnmipb.SubscribeResponse{}, err: "opaque bytes"},
		{name: "depth", limits: func(l *gnmiWirePreflightLimits) { l.maxDepth = 3 }, raw: subscriptionWire, value: &gnmipb.SubscribeResponse{}, err: "nesting"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limits := defaultGNMIWirePreflightLimits()
			tt.limits(&limits)
			codec := newGNMIResponsePreflightCodec(limits)
			err := codec.Unmarshal(gnmiWireTestBuffers(tt.raw), tt.value)
			require.ErrorContains(t, err, tt.err)
		})
	}
}

func TestGNMIWirePreflightChargesDuplicateScalarOneofWrappers(t *testing.T) {
	varintTwice := func(field protowire.Number) []byte {
		raw := protowire.AppendTag(nil, field, protowire.VarintType)
		raw = protowire.AppendVarint(raw, 1)
		raw = protowire.AppendTag(raw, field, protowire.VarintType)
		return protowire.AppendVarint(raw, 2)
	}
	fixed32Twice := func(field protowire.Number) []byte {
		raw := protowire.AppendTag(nil, field, protowire.Fixed32Type)
		raw = protowire.AppendFixed32(raw, 1)
		raw = protowire.AppendTag(raw, field, protowire.Fixed32Type)
		return protowire.AppendFixed32(raw, 2)
	}
	fixed64Twice := func(field protowire.Number) []byte {
		raw := protowire.AppendTag(nil, field, protowire.Fixed64Type)
		raw = protowire.AppendFixed64(raw, 1)
		raw = protowire.AppendTag(raw, field, protowire.Fixed64Type)
		return protowire.AppendFixed64(raw, 2)
	}
	tests := []struct {
		name string
		kind gnmiWireMessageKind
		raw  []byte
	}{
		{name: "subscribe sync", kind: gnmiWireSubscribeResponse, raw: varintTwice(3)},
		{name: "typed int", kind: gnmiWireTypedValue, raw: varintTwice(2)},
		{name: "typed uint", kind: gnmiWireTypedValue, raw: varintTwice(3)},
		{name: "typed bool", kind: gnmiWireTypedValue, raw: varintTwice(4)},
		{name: "typed float", kind: gnmiWireTypedValue, raw: fixed32Twice(6)},
		{name: "typed double", kind: gnmiWireTypedValue, raw: fixed64Twice(14)},
		{name: "history snapshot", kind: gnmiWireHistory, raw: varintTwice(1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limits := defaultGNMIWirePreflightLimits()
			limits.maxObjects = 2 // Root message plus one scalar oneof wrapper.
			err := preflightGNMIWireMessage(tt.raw, tt.kind, limits)
			require.ErrorContains(t, err, "object count")
		})
	}

	limits := defaultGNMIWirePreflightLimits()
	limits.maxObjects = 1
	require.NoError(t, preflightGNMIWireMessage(varintTwice(1), gnmiWireNotification, limits),
		"ordinary scalar fields overwrite in place and must not consume allocation budget")
}

func TestGNMIWirePreflightObjectLimitAdmitsConfiguredPointBoundary(t *testing.T) {
	pathElement := protowire.AppendTag(nil, 1, protowire.BytesType)
	pathElement = protowire.AppendString(pathElement, "value")
	path := protowire.AppendTag(nil, 3, protowire.BytesType)
	path = protowire.AppendBytes(path, pathElement)
	typedValue := protowire.AppendTag(nil, 1, protowire.BytesType)
	typedValue = protowire.AppendString(typedValue, "up")
	update := protowire.AppendTag(nil, 1, protowire.BytesType)
	update = protowire.AppendBytes(update, path)
	update = protowire.AppendTag(update, 3, protowire.BytesType)
	update = protowire.AppendBytes(update, typedValue)
	responseWithUpdates := func(count int) []byte {
		notification := make([]byte, 0, count*(len(update)+4))
		for range count {
			notification = protowire.AppendTag(notification, 4, protowire.BytesType)
			notification = protowire.AppendBytes(notification, update)
		}
		response := protowire.AppendTag(nil, 1, protowire.BytesType)
		return protowire.AppendBytes(response, notification)
	}

	boundaryResponse := responseWithUpdates(50_000)
	require.LessOrEqual(t, len(boundaryResponse), 1024*1024,
		"the supported 50,000-point boundary must remain valid for a 1 MiB receive envelope")
	for _, recvMiB := range []int{1, legacyGNMIMaxRecvMsgSizeMiB, gnmiWireMaximumMessageMiB} {
		require.NoError(t, preflightGNMIWireMessage(
			boundaryResponse,
			gnmiWireSubscribeResponse,
			gnmiWirePreflightLimitsForRecvSize(recvMiB),
		))
	}
	limits := defaultGNMIWirePreflightLimits()
	require.ErrorContains(t, preflightGNMIWireMessage(responseWithUpdates(60_000), gnmiWireSubscribeResponse, limits), "object count")
}

func TestGNMIResponsePreflightCodecDelegatesOneMaterializedBuffer(t *testing.T) {
	input := &gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}}
	raw, err := proto.Marshal(input)
	require.NoError(t, err)
	require.Greater(t, len(raw), 1)

	spy := &gnmiBufferCountCodec{delegate: encoding.GetCodecV2("proto")}
	codec := newGNMIResponsePreflightCodec(defaultGNMIWirePreflightLimits())
	codec.protobuf = spy
	fragmented := mem.BufferSlice{
		mem.SliceBuffer(raw[:1]),
		mem.SliceBuffer(raw[1:]),
	}
	defer fragmented.Free()
	output := &gnmipb.SubscribeResponse{}
	require.NoError(t, codec.Unmarshal(fragmented, output))
	assert.Equal(t, 1, spy.lastUnmarshalBuffers)
	assert.True(t, proto.Equal(input, output))
}

func TestGNMIResponseAdmissionIsKeyedBoundedAndCancellationAware(t *testing.T) {
	admission := newGNMIResponseAdmissionWithLimit(1)
	first := &gnmipb.SubscribeResponse{}
	second := &gnmipb.SubscribeResponse{}
	require.NoError(t, admission.acquire(first, nil))
	require.NoError(t, admission.acquire(first, nil), "a repeated decode into one unary destination shares its lease")
	assert.Len(t, admission.slots, 1)

	acquired := make(chan error, 1)
	go func() { acquired <- admission.acquire(second, t.Context().Done()) }()
	select {
	case err := <-acquired:
		require.Failf(t, "second response was not bounded", "acquire returned early: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	admission.release(first)
	require.NoError(t, <-acquired)
	admission.release(second)
	assert.Empty(t, admission.slots)

	require.NoError(t, admission.acquire(first, nil))
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorContains(t, admission.acquire(second, canceled.Done()), "admission canceled")
	assert.Len(t, admission.slots, 1)
	admission.release(first)
	admission.release(first) // Idempotent release cannot consume another lease.
	assert.Empty(t, admission.slots)
}

func TestReceiveGNMISubscribeResponseReleasesPostDecodeInterceptorError(t *testing.T) {
	raw, err := proto.Marshal(&gnmipb.SubscribeResponse{
		Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
	})
	require.NoError(t, err)
	admission := newGNMIResponseAdmissionWithLimit(1)
	codec := newGNMIResponsePreflightCodec(defaultGNMIWirePreflightLimits())
	codec.admission = admission
	postDecodeErr := errors.New("post-decode interceptor failure")
	stream := &postDecodeErrorGNMIClientStream{codec: codec, raw: raw, err: postDecodeErr}
	response, err := receiveGNMISubscribeResponse(stream, admission)
	require.Nil(t, response)
	require.ErrorIs(t, err, postDecodeErr)
	assert.Empty(t, admission.slots)
	assert.Empty(t, admission.leases)
}

func TestInvokeGNMICapabilitiesReleasesLeaseOnAllErrors(t *testing.T) {
	raw, err := proto.Marshal(&gnmipb.CapabilityResponse{GNMIVersion: "0.10.0"})
	require.NoError(t, err)
	tests := []struct {
		name  string
		wires [][]byte
		err   error
	}{
		{
			name:  "response then non-OK trailer",
			wires: [][]byte{raw},
			err:   status.Error(codes.Unavailable, "trailer failure"),
		},
		{
			name:  "second unary response",
			wires: [][]byte{raw, raw},
			err:   status.Error(codes.Internal, "cardinality violation"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			admission := newGNMIResponseAdmissionWithLimit(1)
			codec := newGNMIResponsePreflightCodec(defaultGNMIWirePreflightLimits())
			codec.admission = admission
			codec.done = t.Context().Done()
			conn := &scriptedGNMICapabilityConn{codec: codec, wires: tt.wires, err: tt.err}
			response, invokeErr := invokeGNMICapabilities(t.Context(), conn, admission, 1)
			require.Nil(t, response)
			require.ErrorIs(t, invokeErr, tt.err)
			assert.Empty(t, admission.slots)
			assert.Empty(t, admission.leases)
		})
	}

	admission := newGNMIResponseAdmissionWithLimit(1)
	codec := newGNMIResponsePreflightCodec(defaultGNMIWirePreflightLimits())
	codec.admission = admission
	conn := &scriptedGNMICapabilityConn{codec: codec, wires: [][]byte{raw}}
	response, err := invokeGNMICapabilities(t.Context(), conn, admission, 1)
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Len(t, admission.slots, 1, "successful capability negotiation retains its decoded response")
	admission.release(response)
	assert.Empty(t, admission.slots)
}

func TestGNMIResponseAdmissionUsesExactRPCContext(t *testing.T) {
	material := runtimeTestTLSMaterial(t)
	server := &runtimeTestGNMIServer{}
	server.subscribe = func(stream grpc.BidiStreamingServer[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		return stream.Send(&gnmipb.SubscribeResponse{
			Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
		})
	}
	endpoint, _ := runtimeTestStartGNMIServer(t, server, material.serverTLS(false))
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		RootCAs:    material.caPool,
		ServerName: runtimeTestServerName,
		MinVersion: tls.VersionTLS12,
	})))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })

	admission := newGNMIResponseAdmissionWithLimit(1)
	warmCtx, warmCancel := context.WithTimeout(t.Context(), time.Second)
	warm, err := invokeGNMICapabilities(warmCtx, conn, admission, 1)
	warmCancel()
	require.NoError(t, err)
	admission.release(warm)

	held := &gnmipb.SubscribeResponse{}
	require.NoError(t, admission.acquire(held, nil))
	t.Cleanup(func() { admission.release(held) })

	capCtx, capCancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	started := time.Now()
	type capabilityResult struct {
		response *gnmipb.CapabilityResponse
		err      error
	}
	capabilityDone := make(chan capabilityResult, 1)
	go func() {
		response, invokeErr := invokeGNMICapabilities(capCtx, conn, admission, 1)
		capabilityDone <- capabilityResult{response: response, err: invokeErr}
	}()
	var capResult capabilityResult
	select {
	case capResult = <-capabilityDone:
	case <-time.After(2 * time.Second):
		admission.release(held)
		capResult = <-capabilityDone
		admission.release(capResult.response)
		require.FailNow(t, "capabilities did not honor its exact context")
	}
	capCancel()
	require.Error(t, capResult.err)
	assert.Less(t, time.Since(started), 2*time.Second)
	assert.Len(t, admission.slots, 1, "a canceled unary decode must not disturb the existing lease")

	subCtx, subCancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	client := gnmipb.NewGNMIClient(conn)
	stream, err := client.Subscribe(
		subCtx,
		gnmiResponsePreflightCallOption(1, admission, subCtx.Done()),
	)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{Subscribe: &gnmipb.SubscriptionList{}},
	}))
	started = time.Now()
	type subscribeResult struct {
		response *gnmipb.SubscribeResponse
		err      error
	}
	subscribeDone := make(chan subscribeResult, 1)
	go func() {
		response, receiveErr := receiveGNMISubscribeResponse(stream, admission)
		subscribeDone <- subscribeResult{response: response, err: receiveErr}
	}()
	var subResult subscribeResult
	select {
	case subResult = <-subscribeDone:
	case <-time.After(2 * time.Second):
		admission.release(held)
		subResult = <-subscribeDone
		admission.release(subResult.response)
		require.FailNow(t, "subscribe receive did not honor its exact context")
	}
	subCancel()
	require.Error(t, subResult.err)
	assert.Less(t, time.Since(started), 2*time.Second)
	assert.Len(t, admission.slots, 1, "a canceled streaming decode must not disturb the existing lease")
}

func TestGNMIWirePreflightDoesNotParseOpaquePayloads(t *testing.T) {
	response := &gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
		Update: []*gnmipb.Update{{
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte("not valid JSON or protobuf")}},
		}},
	}}}
	raw, err := proto.Marshal(response)
	require.NoError(t, err)
	codec := newGNMIResponsePreflightCodec(defaultGNMIWirePreflightLimits())
	require.NoError(t, codec.Unmarshal(gnmiWireTestBuffers(raw), &gnmipb.SubscribeResponse{}))
}

func TestGNMIWirePreflightSuccessPathDoesNotAllocate(t *testing.T) {
	raw, err := proto.Marshal(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
		Prefix: &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "system", Key: map[string]string{"name": "one"}}}},
		Update: []*gnmipb.Update{{
			Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "state"}}},
			Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "up"}},
		}},
	}}})
	require.NoError(t, err)
	limits := defaultGNMIWirePreflightLimits()
	allocations := testing.AllocsPerRun(100, func() {
		if scanErr := preflightGNMIWireMessage(raw, gnmiWireSubscribeResponse, limits); scanErr != nil {
			panic(scanErr)
		}
	})
	assert.Zero(t, allocations)
}

func TestGNMIClientConnectionsForceResponsePreflightCodec(t *testing.T) {
	t.Run("shared gNMI", func(t *testing.T) {
		material := runtimeTestTLSMaterial(t)
		endpoint := startMalformedCapabilityGNMIServer(t, material.serverTLS(false))
		target := runtimeTestTarget(endpoint, material.caFile, gnmiModeOnce, runtimeTestMapping("system/state", "test.value"))
		err := runtimeTestServeTarget(t, target)
		require.ErrorContains(t, err, "gNMI response preflight")
	})

	t.Run("legacy gNMI", func(t *testing.T) {
		endpoint := startMalformedCapabilityGNMIServer(t, nil)
		session := legacyGNMISession{
			settings:     receivertest.NewNopSettings(componentmetadata.Type),
			host:         componenttest.NewNopHost(),
			clientConfig: mustIOSXRClientConfig(endpoint),
			targetName:   "legacy-test",
		}
		err := session.run(t.Context())
		require.ErrorContains(t, err, "gNMI response preflight")
	})
}

func gnmiWireTestBuffers(data []byte) mem.BufferSlice {
	return mem.BufferSlice{mem.SliceBuffer(data)}
}

type gnmiBufferCountCodec struct {
	delegate             encoding.CodecV2
	lastUnmarshalBuffers int
}

func (c *gnmiBufferCountCodec) Marshal(value any) (mem.BufferSlice, error) {
	return c.delegate.Marshal(value)
}

func (c *gnmiBufferCountCodec) Unmarshal(data mem.BufferSlice, value any) error {
	c.lastUnmarshalBuffers = len(data)
	return c.delegate.Unmarshal(data, value)
}

func (c *gnmiBufferCountCodec) Name() string {
	return c.delegate.Name()
}

type scriptedGNMICapabilityConn struct {
	codec *gnmiResponsePreflightCodec
	wires [][]byte
	err   error
}

type postDecodeErrorGNMIClientStream struct {
	codec *gnmiResponsePreflightCodec
	raw   []byte
	err   error
}

func (*postDecodeErrorGNMIClientStream) Header() (grpcmetadata.MD, error) { return nil, nil }
func (*postDecodeErrorGNMIClientStream) Trailer() grpcmetadata.MD         { return nil }
func (*postDecodeErrorGNMIClientStream) CloseSend() error                 { return nil }
func (*postDecodeErrorGNMIClientStream) Context() context.Context         { return context.Background() }
func (*postDecodeErrorGNMIClientStream) SendMsg(any) error                { return nil }
func (s *postDecodeErrorGNMIClientStream) RecvMsg(value any) error {
	if err := s.codec.Unmarshal(gnmiWireTestBuffers(s.raw), value); err != nil {
		return err
	}
	return s.err
}

func (c *scriptedGNMICapabilityConn) Invoke(
	_ context.Context,
	_ string,
	_, reply any,
	_ ...grpc.CallOption,
) error {
	for _, wire := range c.wires {
		if err := c.codec.Unmarshal(gnmiWireTestBuffers(wire), reply); err != nil {
			return err
		}
	}
	return c.err
}

func (*scriptedGNMICapabilityConn) NewStream(
	context.Context,
	*grpc.StreamDesc,
	string,
	...grpc.CallOption,
) (grpc.ClientStream, error) {
	return nil, errors.New("unexpected stream")
}

type malformedCapabilityCodec struct {
	protobuf encoding.CodecV2
}

func (c malformedCapabilityCodec) Marshal(value any) (mem.BufferSlice, error) {
	if _, ok := value.(*gnmipb.CapabilityResponse); ok {
		// Field number zero is never valid. The distinctive preflight error in
		// the client proves the forced response codec was installed on the
		// ClientConn rather than relying on protobuf's later generic failure.
		return gnmiWireTestBuffers([]byte{0}), nil
	}
	return c.protobuf.Marshal(value)
}

func (c malformedCapabilityCodec) Unmarshal(data mem.BufferSlice, value any) error {
	return c.protobuf.Unmarshal(data, value)
}

func (c malformedCapabilityCodec) Name() string {
	return c.protobuf.Name()
}

func startMalformedCapabilityGNMIServer(t *testing.T, tlsConfig *tls.Config) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	codec := malformedCapabilityCodec{protobuf: encoding.GetCodecV2("proto")}
	options := []grpc.ServerOption{grpc.ForceServerCodecV2(codec)}
	if tlsConfig != nil {
		options = append(options, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}
	server := grpc.NewServer(options...)
	gnmipb.RegisterGNMIServer(server, &runtimeTestGNMIServer{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	return listener.Addr().String()
}

func TestDirectGNMIJSONDecodePreflightsComplexity(t *testing.T) {
	tests := map[string][]byte{
		"depth": []byte(strings.Repeat("[", httpclient.HardMaxJSONDepth+1) + "0" + strings.Repeat("]", httpclient.HardMaxJSONDepth+1)),
		"nodes": []byte("[" + strings.Repeat("0,", httpclient.HardMaxJSONNodes) + "0]"),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			iosHealth := &iosXRHealth{}
			iosDecoder := iosXRGNMIUpdateDecoder{target: IOSXRTargetConfig{Name: "xr"}, health: iosHealth}
			iosDecoder.decodeNotification(directGNMIJSONNotification(raw), iosXRTelemetryTransportDialIn)
			assert.Positive(t, iosHealth.snapshot().decodeErrors)

			catalystHealth := &catalyst9800Health{}
			catalystDecoder := catalyst9800GNMIUpdateDecoder{target: Catalyst9800TargetConfig{Name: "wlc"}, health: catalystHealth}
			catalystDecoder.decodeNotification(directGNMIJSONNotification(raw), catalyst9800TelemetryTransportDialIn)
			assert.Positive(t, catalystHealth.snapshot().decodeErrors)
		})
	}
}

func directGNMIJSONNotification(raw []byte) *gnmipb.Notification {
	return &gnmipb.Notification{
		Prefix: &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "system"}}},
		Update: []*gnmipb.Update{{
			Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "state"}}},
			Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonVal{JsonVal: raw}},
		}},
	}
}
