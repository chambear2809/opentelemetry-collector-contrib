// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

func TestCanonicalizeIOSXERFC7951JSONIETFNotificationKeys(t *testing.T) {
	path := func(origin, value string) *gnmipb.Path {
		return &gnmipb.Path{
			Origin: origin,
			Elem: []*gnmipb.PathElem{
				{Name: "openconfig-interfaces:interfaces"},
				{Name: "interface", Key: map[string]string{"name": value, "index": `"1"`}},
			},
		}
	}
	prefixNotification := &gnmipb.Notification{
		Prefix: path(builtinGNMIOriginRFC7951, `"GigabitEthernet1\/0\/1"`),
	}
	require.NoError(t, canonicalizeIOSXERFC7951JSONIETFWireNotificationKeys(prefixNotification))
	assert.Equal(t, "GigabitEthernet1/0/1", prefixNotification.GetPrefix().GetElem()[1].GetKey()["name"])

	notification := &gnmipb.Notification{
		Prefix: &gnmipb.Path{Origin: builtinGNMIOriginRFC7951},
		Update: []*gnmipb.Update{{
			Path: path("", `"Forty\u0047igabitEthernet1/0/1"`),
		}},
		Delete: []*gnmipb.Path{path("", ` "TenGigabitEthernet1/0/1" `)},
	}

	require.NoError(t, canonicalizeIOSXERFC7951JSONIETFWireNotificationKeys(notification))
	assert.Equal(t, "FortyGigabitEthernet1/0/1", notification.GetUpdate()[0].GetPath().GetElem()[1].GetKey()["name"])
	assert.Equal(t, "TenGigabitEthernet1/0/1", notification.GetDelete()[0].GetElem()[1].GetKey()["name"])
	assert.Equal(t, `"1"`, prefixNotification.GetPrefix().GetElem()[1].GetKey()["index"],
		"unprofiled keys on a qualified list element must remain unchanged")

	otherOrigin := &gnmipb.Notification{Prefix: path("openconfig-interfaces", `"literal-quotes"`)}
	require.NoError(t, canonicalizeIOSXERFC7951JSONIETFWireNotificationKeys(otherOrigin))
	assert.Equal(t, `"literal-quotes"`, otherOrigin.GetPrefix().GetElem()[1].GetKey()["name"],
		"non-RFC7951 origins must not be changed")

	custom := &gnmipb.Notification{Prefix: &gnmipb.Path{
		Origin: builtinGNMIOriginRFC7951,
		Elem: []*gnmipb.PathElem{
			{Name: "example-custom:interfaces"},
			{Name: "interface", Key: map[string]string{"name": `"literal-quotes"`}},
		},
	}}
	require.NoError(t, canonicalizeIOSXERFC7951JSONIETFWireNotificationKeys(custom))
	assert.Equal(t, `"literal-quotes"`, custom.GetPrefix().GetElem()[1].GetKey()["name"],
		"custom RFC7951 models must retain standard PathElem key semantics")

	collision := &gnmipb.Notification{Prefix: &gnmipb.Path{
		Origin: builtinGNMIOriginRFC7951,
		Elem: []*gnmipb.PathElem{
			{Name: "openconfig-interfaces:interfaces"},
			{Name: "custom-container"},
			{Name: "interface", Key: map[string]string{"name": `"unterminated`}},
		},
	}}
	require.NoError(t, canonicalizeIOSXERFC7951JSONIETFWireNotificationKeys(collision))
	assert.Equal(t, `"unterminated`, collision.GetPrefix().GetElem()[2].GetKey()["name"],
		"same-module list-name collisions outside the exact ancestry must remain unchanged and unparsed")

	split := &gnmipb.Notification{
		Prefix: &gnmipb.Path{
			Origin: builtinGNMIOriginRFC7951,
			Elem:   []*gnmipb.PathElem{{Name: "openconfig-interfaces:interfaces"}},
		},
		Update: []*gnmipb.Update{{Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{
			{Name: "interface", Key: map[string]string{"name": `"GigabitEthernet1\/0\/2"`}},
			{Name: "state"},
		}}}},
	}
	require.NoError(t, canonicalizeIOSXERFC7951JSONIETFWireNotificationKeys(split))
	assert.Equal(t, "GigabitEthernet1/0/2", split.GetUpdate()[0].GetPath().GetElem()[0].GetKey()["name"],
		"exact ancestry must be evaluated across the notification prefix boundary")
}

func TestCanonicalizeIOSXERFC7951JSONIETFSharedPrefixKeysExactlyOnce(t *testing.T) {
	tests := []struct {
		name       string
		elements   []string
		actualName string
	}{
		{
			name: "interface key that would collapse on a second decode",
			elements: []string{
				"openconfig-interfaces:interfaces",
				"interface",
			},
			actualName: `"GigabitEthernet1/0/47"`,
		},
		{
			name: "transceiver key that would fail on a second decode",
			elements: []string{
				"Cisco-IOS-XE-transceiver-oper:transceiver-oper-data",
				"transceiver",
			},
			actualName: `"TwentyFiveGigE1/0/48`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prefix := &gnmipb.Path{Origin: builtinGNMIOriginRFC7951}
			for _, element := range test.elements {
				prefix.Elem = append(prefix.Elem, &gnmipb.PathElem{Name: element})
			}
			listElement := prefix.Elem[len(prefix.Elem)-1]
			listElement.Key = map[string]string{"name": fmt.Sprintf("%q", test.actualName)}
			notification := &gnmipb.Notification{
				Prefix: prefix,
				Update: []*gnmipb.Update{
					{Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "state"}, {Name: "oper-status"}}}},
					{Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "state"}, {Name: "counters"}}}},
					{Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "state"}, {Name: "description"}}}},
				},
				Delete: []*gnmipb.Path{
					{Elem: []*gnmipb.PathElem{{Name: "state"}, {Name: "last-change"}}},
					{Elem: []*gnmipb.PathElem{{Name: "state"}, {Name: "obsolete"}}},
				},
			}

			require.NoError(t, canonicalizeIOSXERFC7951JSONIETFWireNotificationKeys(notification))
			assert.Equal(t, test.actualName, listElement.GetKey()["name"],
				"all combined paths must share one canonicalization of their prefix PathElem")
			assert.NotEqual(t, strings.Trim(test.actualName, `"`), listElement.GetKey()["name"],
				"a legitimate leading or enclosing quote must not collapse")
		})
	}
}

func TestCanonicalizeIOSXERFC7951JSONIETFRequiresCompatibleCombinedOrigin(t *testing.T) {
	prefix := &gnmipb.Path{
		Origin: builtinGNMIOriginRFC7951,
		Elem: []*gnmipb.PathElem{
			{Name: "openconfig-interfaces:interfaces"},
			{Name: "interface", Key: map[string]string{"name": `"unterminated`}},
		},
	}
	notification := &gnmipb.Notification{
		Prefix: prefix,
		Update: []*gnmipb.Update{{
			Path: &gnmipb.Path{
				Origin: "openconfig-interfaces",
				Elem:   []*gnmipb.PathElem{{Name: "state"}, {Name: "oper-status"}},
			},
		}},
	}

	require.NoError(t, canonicalizeIOSXERFC7951JSONIETFWireNotificationKeys(notification))
	assert.Equal(t, `"unterminated`, prefix.GetElem()[1].GetKey()["name"],
		"a prefix must not be canonicalized outside a compatible effective RFC7951 path")
}

func TestCanonicalIOSXEJSONIETFKeyValueRejectsMalformedAndOversizedQuotedKeys(t *testing.T) {
	for _, raw := range []string{
		`"unterminated`,
		`"valid" trailing`,
		`"bad\q"`,
		`"\ud800"`,
		`"\udc00"`,
		`"\ud800\u0000"`,
		`"\ud800\udbff"`,
		`"\ud800x"`,
		string([]byte{'"', 0xff, '"'}),
	} {
		_, _, err := canonicalIOSXEJSONIETFKeyValue(raw)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), raw, "peer-controlled key values must not be reflected")
	}
	oversized := `"` + strings.Repeat("x", gnmiIOSXEJSONIETFMaximumKeyBytes) + `"`
	_, _, err := canonicalIOSXEJSONIETFKeyValue(oversized)
	require.ErrorContains(t, err, "bounded key size")

	got, changed, err := canonicalIOSXEJSONIETFKeyValue(`Ethernet"quoted`)
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Equal(t, `Ethernet"quoted`, got)
}

func TestCanonicalIOSXEJSONIETFKeyValuePreservesDistinctUnicodeScalars(t *testing.T) {
	replacement, changed, err := canonicalIOSXEJSONIETFKeyValue(`"\ufffd"`)
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, "\ufffd", replacement)

	rocket, changed, err := canonicalIOSXEJSONIETFKeyValue(`"\ud83d\ude80"`)
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, "🚀", rocket)
	assert.NotEqual(t, replacement, rocket)

	solidus, changed, err := canonicalIOSXEJSONIETFKeyValue(`"GigabitEthernet1\/0\/1"`)
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, "GigabitEthernet1/0/1", solidus)

	_, _, err = canonicalIOSXEJSONIETFKeyValue(`"\ud800"`)
	require.Error(t, err, "an unpaired surrogate must never collapse onto a real replacement character")
}

func TestIOSXEJSONIETFQuotedInterfaceKeyMapsWithoutLiteralQuotes(t *testing.T) {
	contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9300, "17.18.1")
	require.NoError(t, err)
	profile, ok := builtinGNMIProfile(contract, builtinGNMIProfileInterfaces)
	require.True(t, ok)
	require.Len(t, profile.Paths, 1)
	mappings := make([]internalgnmi.Mapping, 0, len(profile.Paths[0].Mappings))
	for _, mapping := range profile.Paths[0].Mappings {
		mappings = append(mappings, mapping.Mapping)
	}
	registry, err := internalgnmi.NewRegistry(mappings...)
	require.NoError(t, err)
	notification := &gnmipb.Notification{
		Timestamp: time.Now().UnixNano(),
		Prefix:    &gnmipb.Path{Origin: builtinGNMIOriginRFC7951},
		Update: []*gnmipb.Update{{
			Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{
				{Name: "openconfig-interfaces:interfaces"},
				{Name: "interface", Key: map[string]string{"name": `"GigabitEthernet1/0/1"`}},
				{Name: "state"},
				{Name: "oper-status"},
			}},
			Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`"UP"`)}},
		}},
	}
	require.NoError(t, canonicalizeIOSXERFC7951JSONIETFWireNotificationKeys(notification))
	decoded, _, err := internalgnmi.DecodeNotificationWithRegistry("switch", notification, time.Now(), registry)
	require.NoError(t, err)
	normalizeGNMIStateValues(&decoded)
	mapped, stats := registry.MapNotification(decoded)
	assert.Equal(t, internalgnmi.MappingStats{Mapped: 1}, stats)
	require.Len(t, mapped.Updates, 1)
	assert.Equal(t, "GigabitEthernet1/0/1", mapped.Updates[0].Attributes["network.interface.name"])
	assert.Equal(t, int64(1), mapped.Updates[0].IntValue)
}

func TestIOSXEJSONIETFQuotedKeyCanonicalizationRunsBeforeDecodeSemantics(t *testing.T) {
	t.Run("final update wins across quoted and unquoted forms", func(t *testing.T) {
		path := func(key string) *gnmipb.Path {
			return &gnmipb.Path{Elem: []*gnmipb.PathElem{
				{Name: "openconfig-interfaces:interfaces"},
				{Name: "interface", Key: map[string]string{"name": key}},
				{Name: "state"},
				{Name: "oper-status"},
			}}
		}
		notification := &gnmipb.Notification{
			Timestamp: time.Now().UnixNano(),
			Prefix:    &gnmipb.Path{Origin: builtinGNMIOriginRFC7951},
			Update: []*gnmipb.Update{
				{Path: path(`"GigabitEthernet1/0/1"`), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "DOWN"}}},
				{Path: path("GigabitEthernet1/0/1"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "UP"}}},
			},
			Delete: []*gnmipb.Path{path(`"GigabitEthernet1/0/2"`)},
		}
		require.NoError(t, canonicalizeIOSXERFC7951JSONIETFWireNotificationKeys(notification))
		decoded, _, err := internalgnmi.DecodeNotification("switch", notification, time.Now())
		require.NoError(t, err)
		require.Len(t, decoded.Updates, 1)
		assert.Equal(t, internalgnmi.StringValue("UP"), decoded.Updates[0].Value)
		assert.Equal(t, "GigabitEthernet1/0/1", decoded.Updates[0].Series.Elements[1].Keys["name"])
		require.Len(t, decoded.Deletes, 1)
		assert.Equal(t, "GigabitEthernet1/0/2", decoded.Deletes[0].Elements[1].Keys["name"])
	})

	t.Run("aggregated key leaf agrees with path key", func(t *testing.T) {
		contract, _, err := resolveGNMIProductContract(gnmiProductCatalyst9300, "17.18.1")
		require.NoError(t, err)
		profile, ok := builtinGNMIProfile(contract, builtinGNMIProfileInterfaces)
		require.True(t, ok)
		mappings := make([]internalgnmi.Mapping, 0, len(profile.Paths[0].Mappings))
		for _, mapping := range profile.Paths[0].Mappings {
			mappings = append(mappings, mapping.Mapping)
		}
		registry, err := internalgnmi.NewRegistry(mappings...)
		require.NoError(t, err)
		notification := &gnmipb.Notification{
			Timestamp: time.Now().UnixNano(),
			Prefix:    &gnmipb.Path{Origin: builtinGNMIOriginRFC7951},
			Update: []*gnmipb.Update{{
				Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{
					{Name: "openconfig-interfaces:interfaces"},
					{Name: "interface", Key: map[string]string{"name": `"GigabitEthernet1/0/1"`}},
				}},
				Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(
					`{"name":"GigabitEthernet1/0/1","state":{"oper-status":"UP"}}`,
				)}},
			}},
		}
		require.NoError(t, canonicalizeIOSXERFC7951JSONIETFWireNotificationKeys(notification))
		decoded, _, err := internalgnmi.DecodeNotificationWithRegistry("switch", notification, time.Now(), registry)
		require.NoError(t, err)
		normalizeGNMIStateValues(&decoded)
		mapped, stats := registry.MapNotification(decoded)
		assert.Equal(t, 1, stats.Mapped)
		require.Len(t, mapped.Updates, 1)
		assert.Equal(t, "GigabitEthernet1/0/1", mapped.Updates[0].Attributes["network.interface.name"])
	})
}

func TestRunGNMIIdentityPreflightAcceptsIOSXEDocumentedQuotedStringKeys(t *testing.T) {
	contract, configured, err := resolveGNMIProductContract(gnmiProductCatalyst9300, "17.18.1")
	require.NoError(t, err)
	hardware := runtimeTestXEHardwareIdentityResponse("C9300-48UXM")
	hardwarePath := hardware.GetNotification()[0].GetUpdate()[0].GetPath()
	hardwarePath.GetElem()[2].Key["hw-type"] = `"hw-type-chassis"`
	version := runtimeTestXEVersionIdentityResponseWithExtension("17.18.01.0.1186", "1750000000")
	versionPath := version.GetNotification()[0].GetUpdate()[0].GetPath()
	versionPath.GetElem()[1].Key["fru"] = `"fru-rp"`
	versionPath.GetElem()[2].Key["version"] = `"17.18.01.0.1186"`
	versionPath.GetElem()[2].Key["version-extension"] = `"1750000000"`
	runtimeTestAppendXEInstallBootMode(version, "install-boot-mode-install")
	bootPath := version.GetNotification()[0].GetUpdate()[1].GetPath()
	bootPath.GetElem()[1].Key["fru"] = `"fru-rp"`
	conn := &identitySequenceTestConn{responses: []*gnmipb.GetResponse{hardware, version}}

	verified, err := runGNMIIdentityPreflight(
		t.Context(), conn, newGNMIResponseAdmission(),
		GNMITargetConfig{Name: "switch", CapabilitiesTimeout: time.Second},
		contract, configured, gnmipb.Encoding_JSON_IETF,
	)
	require.NoError(t, err)
	assert.Equal(t, gnmiProductCatalyst9300, verified.Product)
	assert.Equal(t, "C9300-48UXM", verified.ModelIdentifier)
	assert.Equal(t, "17.18.1", verified.SoftwareVersion)
	assert.Equal(t, gnmiIOSXEBootModeInstall, verified.BootMode)
	assert.Equal(t, 2, conn.calls)
}

type identitySequenceTestConn struct {
	responses []*gnmipb.GetResponse
	calls     int
}

func (c *identitySequenceTestConn) Invoke(
	_ context.Context,
	method string,
	_, reply any,
	_ ...grpc.CallOption,
) error {
	if method != gnmipb.GNMI_Get_FullMethodName {
		return fmt.Errorf("unexpected RPC method %q", method)
	}
	if c.calls >= len(c.responses) {
		return errors.New("unexpected extra Get RPC")
	}
	response, ok := reply.(*gnmipb.GetResponse)
	if !ok {
		return fmt.Errorf("unexpected RPC response type %T", reply)
	}
	proto.Merge(response, c.responses[c.calls])
	c.calls++
	return nil
}

func (*identitySequenceTestConn) NewStream(
	context.Context,
	*grpc.StreamDesc,
	string,
	...grpc.CallOption,
) (grpc.ClientStream, error) {
	return nil, errors.New("unexpected streaming RPC")
}
