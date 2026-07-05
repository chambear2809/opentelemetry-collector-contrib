// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"google.golang.org/grpc"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

func TestValidateSharedGNMIResponseScope(t *testing.T) {
	selectors, err := sharedGNMIResponseSelectors("target", []sharedGNMIPath{{
		Origin: "openconfig-interfaces", Path: "interfaces/interface[name=*]/state",
	}})
	require.NoError(t, err)
	path := func(origin, raw string) internalgnmi.Path {
		t.Helper()
		parsed, parseErr := internalgnmi.ParsePath("target", origin, raw)
		require.NoError(t, parseErr)
		return parsed
	}
	validUpdate := path("openconfig-interfaces", "interfaces/interface[name=Ethernet1]/state/counters/in-octets")

	tests := []struct {
		name         string
		notification internalgnmi.DecodedNotification
		wantError    bool
	}{
		{name: "concrete descendant update", notification: internalgnmi.DecodedNotification{Touched: []internalgnmi.Path{validUpdate}}},
		{name: "ancestor delete", notification: internalgnmi.DecodedNotification{Deletes: []internalgnmi.Path{path("openconfig-interfaces", "interfaces")}}},
		{name: "unkeyed list delete overlaps wildcard selector", notification: internalgnmi.DecodedNotification{Deletes: []internalgnmi.Path{path("openconfig-interfaces", "interfaces/interface")}}},
		{name: "atomic common ancestor", notification: internalgnmi.DecodedNotification{Atomic: true, Prefix: path("openconfig-interfaces", "interfaces")}},
		{name: "unrelated update", notification: internalgnmi.DecodedNotification{Touched: []internalgnmi.Path{path("openconfig-interfaces", "system/state/hostname")}}, wantError: true},
		{name: "unrelated delete", notification: internalgnmi.DecodedNotification{Deletes: []internalgnmi.Path{path("openconfig-interfaces", "system")}}, wantError: true},
		{name: "wrong origin", notification: internalgnmi.DecodedNotification{Touched: []internalgnmi.Path{path("peer-origin", "interfaces/interface[name=Ethernet1]/state/oper-status")}}, wantError: true},
		{name: "wrong path target", notification: func() internalgnmi.DecodedNotification {
			wrong := validUpdate.Clone()
			wrong.PathTarget = "peer-target"
			return internalgnmi.DecodedNotification{Touched: []internalgnmi.Path{wrong}}
		}(), wantError: true},
		{name: "wildcard response path", notification: internalgnmi.DecodedNotification{Touched: []internalgnmi.Path{path("openconfig-interfaces", "interfaces/interface[name=*]/state/oper-status")}}, wantError: true},
		{name: "wrong atomic origin", notification: internalgnmi.DecodedNotification{Atomic: true, Prefix: path("peer-origin", "interfaces")}, wantError: true},
		{name: "empty non-atomic", notification: internalgnmi.DecodedNotification{}, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateSharedGNMIResponseScope(selectors, test.notification)
			if test.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestSplitStreamResponseSelectorsExcludeOriginalSibling(t *testing.T) {
	paths := []sharedGNMIPath{
		{Origin: "openconfig-interfaces", Path: "interfaces/interface/state"},
		{Origin: "openconfig-system", Path: "system/state"},
	}
	original, err := sharedGNMIResponseSelectors("target", paths)
	require.NoError(t, err)
	require.Len(t, original, 2)

	split, err := sharedGNMIResponseSelectors("target", paths[:1])
	require.NoError(t, err)
	require.Len(t, split, 1)
	sibling, err := internalgnmi.ParsePath("target", "openconfig-system", "system/state/hostname")
	require.NoError(t, err)
	require.Error(t, validateSharedGNMIResponseScope(split, internalgnmi.DecodedNotification{
		Touched: []internalgnmi.Path{sibling},
	}))
}

func TestDiagnosticProbeRejectsOutOfScopeUpdateBeforeSync(t *testing.T) {
	selectors, err := sharedGNMIResponseSelectors("target", []sharedGNMIPath{{
		Origin: runtimeTestOrigin, Path: "requested/state",
	}})
	require.NoError(t, err)
	target := &sharedGNMITargetRuntime{config: GNMITargetConfig{Name: "target", Platform: gnmiPlatformIOSXR}}
	runtimeStream := sharedGNMIRuntimeStream{responseSelectors: selectors}
	response := func() *gnmipb.SubscribeResponse {
		return &gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
			Timestamp: time.Now().UnixNano(), Prefix: &gnmipb.Path{Origin: runtimeTestOrigin},
			Update: []*gnmipb.Update{{
				Path: runtimeTestProtoPath(t, "outside/state"),
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: 1}},
			}},
		}}}
	}
	for name, receive := range map[string]func(
		grpc.BidiStreamingClient[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse],
		*gnmiResponseAdmission,
		*sharedGNMITargetRuntime,
		sharedGNMIRuntimeStream,
	) error{
		"until sync": receiveSharedGNMIProbeUntilSync,
		"once":       receiveSharedGNMIProbeOnce,
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			client := &singleUpdateGNMIClientStream{ctx: ctx, response: response()}
			err := receive(client, nil, target, runtimeStream)
			require.Error(t, err)
			var unsupported *sharedGNMIUnsupportedError
			assert.ErrorAs(t, err, &unsupported)
			assert.NotContains(t, err.Error(), "outside")
		})
	}
}

func TestProcessNotificationRejectsOutOfScopeStateWithoutMutation(t *testing.T) {
	mapping := runtimeTestMapping("interfaces/interface/state/value", "scope.value")
	targetConfig := runtimeTestTarget("127.0.0.1:57400", "", gnmiModeStream, mapping)
	receiver, target, stream := newDeliveryTestReceiver(t, targetConfig, 10, consumertest.NewNop())
	timestamp := time.Now().Add(-time.Minute)

	valid := &gnmipb.Notification{
		Timestamp: timestamp.UnixNano(), Prefix: &gnmipb.Path{Origin: runtimeTestOrigin},
		Update: []*gnmipb.Update{{
			Path: runtimeTestProtoPath(t, "interfaces/interface/state/value"),
			Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: 1}},
		}},
	}
	require.NoError(t, receiver.processNotification(t.Context(), target, stream, valid))
	require.Len(t, target.cache.Snapshot(), 1)

	outOfScope := &gnmipb.Notification{
		Timestamp: timestamp.Add(time.Second).UnixNano(), Prefix: &gnmipb.Path{Origin: runtimeTestOrigin},
		Delete: []*gnmipb.Path{runtimeTestProtoPath(t, "interfaces")},
		Update: []*gnmipb.Update{{
			Path: runtimeTestProtoPath(t, "system/state/secret"),
			Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "peer-controlled"}},
		}},
	}
	err := receiver.processNotification(t.Context(), target, stream, outOfScope)
	require.Error(t, err)
	assert.ErrorIs(t, err, errSharedGNMINotificationIgnored)
	assert.Len(t, target.cache.Snapshot(), 1, "out-of-scope state must not delete or replace committed data")
}
