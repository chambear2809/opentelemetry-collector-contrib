// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

func TestBuildSharedGNMIStreamsDefaultsIntervalsAndStableOrder(t *testing.T) {
	target := subscriptionTestTarget(gnmiProductCatalyst9800, 4)
	target.Name = "xe-1"
	streams, err := buildSharedGNMIStreams(target)
	require.NoError(t, err)
	require.Len(t, streams, 3)
	assert.Equal(t, []string{builtinGNMIProfileIdentity, builtinGNMIProfileSystem, builtinGNMIProfileInterfaces}, sharedStreamProfiles(streams))
	assert.Equal(t, 5*time.Minute, streams[0].SampleInterval)
	assert.True(t, streams[0].HealthOnly)
	assert.Equal(t, time.Minute, streams[1].SampleInterval)
	assert.Equal(t, time.Minute, streams[2].SampleInterval)
	for _, stream := range streams {
		assert.Equal(t, gnmiModeStream, stream.Mode)
		assert.False(t, stream.Optics)
		for _, path := range stream.Paths {
			assert.Equal(t, builtinGNMIOriginRFC7951, path.Origin)
		}
	}
	assert.False(t, streams[1].HealthOnly)
	assert.False(t, streams[2].HealthOnly)

	target.Profiles.Interfaces.SampleInterval = 45 * time.Second
	streams, err = buildSharedGNMIStreams(target)
	require.NoError(t, err)
	assert.Equal(t, 45*time.Second, streams[2].SampleInterval)
}

func TestBuildSharedGNMIStreamsOriginGroupingAndDeduplication(t *testing.T) {
	t.Run("IOS XR splits prefix origins and deduplicates controller optics", func(t *testing.T) {
		target := subscriptionTestTarget(gnmiProductASR9000, 2)
		target.Name = "xr-1"
		target.Profiles = subscriptionProfilesOnly(builtinGNMIProfileOptics)
		target.Profiles.Optics.Required = true
		streams, err := buildSharedGNMIStreams(target)
		require.NoError(t, err)
		require.Len(t, streams, 1)
		assert.Len(t, streams, estimateGNMIStreams(target.withDefaults()))
		for _, stream := range streams {
			assert.Equal(t, builtinGNMIProfileOptics, stream.Profile)
			assert.True(t, stream.Required)
			assert.True(t, stream.Optics)
			assertAllPathsHaveOneOrigin(t, stream.Paths)
		}
		byOrigin := sharedStreamsByOrigin(streams)
		controller := byOrigin["Cisco-IOS-XR-controller-optics-oper"]
		require.Len(t, controller.Paths, 2)
		assert.Len(t, controller.Mappings, 8, "exact 24.4 controller and lane mappings must remain lossless")
		assert.NotContains(t, byOrigin, "Cisco-IOS-XR-controller-otu-oper", "unsafe string and split-mantissa OTU values must not be subscribed")
	})

	t.Run("NX keeps per-path origins in one profile stream", func(t *testing.T) {
		target := subscriptionTestTarget(gnmiProductNexus9000, 1)
		target.Name = "nx-1"
		target.Profiles = subscriptionProfilesOnly(builtinGNMIProfileOptics)
		streams, err := buildSharedGNMIStreams(target)
		require.NoError(t, err)
		require.Len(t, streams, 1)
		assert.Len(t, streams[0].Paths, 1)
		origins := map[string]bool{}
		for _, path := range streams[0].Paths {
			origins[path.Origin] = true
		}
		assert.True(t, origins[builtinGNMIOriginDME])
		assert.False(t, origins[builtinGNMIOriginNXDevice])
	})
}

func TestBuildSharedGNMIStreamsCustomMappingsAndModes(t *testing.T) {
	scale := .001
	target := GNMITargetConfig{
		Name:            "xr-custom",
		Product:         gnmiProductASR9000,
		SoftwareVersion: "24.4.1",
		MaxStreams:      1,
		Profiles:        subscriptionProfilesOnly(),
		CustomSubscriptions: []GNMICustomSubscriptionConfig{{
			Name:           "custom-optic",
			Origin:         "vendor-optics",
			Mode:           gnmiModePoll,
			SampleInterval: 30 * time.Second,
			PollInterval:   2 * time.Minute,
			Required:       true,
			Mappings: []GNMIMetricMappingConfig{{
				Path:        "ports/port[name=Eth1/1]/sensors/sensor[id=temp]/value",
				MetricName:  "example.optics.temperature",
				Description: "Example optic temperature",
				Unit:        "Cel",
				Scale:       &scale,
				GaugeType:   "double",
				PathKeys: map[string]string{
					"port.name": "network.interface.name",
					"sensor.id": "cisco.optics.sensor.id",
				},
			}},
		}},
	}

	streams, err := buildSharedGNMIStreams(target)
	require.NoError(t, err)
	require.Len(t, streams, 1)
	stream := streams[0]
	assert.Equal(t, "custom-optic", stream.Profile)
	assert.Equal(t, gnmiModePoll, stream.Mode)
	assert.Equal(t, 30*time.Second, stream.SampleInterval)
	assert.Equal(t, 2*time.Minute, stream.PollInterval)
	assert.True(t, stream.Required)
	require.Len(t, stream.Paths, 1)
	assert.Equal(t, sharedGNMIPath{Origin: "vendor-optics", Path: "ports/port[name=Eth1/1]/sensors/sensor[id=temp]/value"}, stream.Paths[0])
	require.Len(t, stream.Mappings, 1)
	converted := stream.Mappings[0]
	assert.Empty(t, converted.StaticAttributes)
	assert.Equal(t, internalgnmi.SourcePath{Origin: "vendor-optics", Elements: []string{"ports", "port", "sensors", "sensor"}, Leaf: "value"}, converted.Mapping.Source)
	assert.Equal(t, internalgnmi.MetricMetadata{Name: "example.optics.temperature", Description: "Example optic temperature", Unit: "Cel"}, converted.Mapping.Metric)
	assert.Equal(t, scale, converted.Mapping.Scale)
	assert.Equal(t, internalgnmi.GaugeDouble, converted.Mapping.GaugeType)
	assert.Equal(t, []internalgnmi.KeyAttribute{
		{Element: "port", Key: "name", Attribute: "network.interface.name"},
		{Element: "sensor", Key: "id", Attribute: "cisco.optics.sensor.id"},
	}, converted.Mapping.KeyAttributes)
}

func TestBuildSharedGNMINXOpenConfigProfilesSeparateWireOriginFromModels(t *testing.T) {
	for _, test := range []struct {
		product, version string
	}{
		{product: gnmiProductNexus9000, version: "10.6(1)"},
		{product: gnmiProductNexus3500, version: "10.5(1)"},
	} {
		t.Run(test.product, func(t *testing.T) {
			target := subscriptionTestTarget(test.product, 2)
			target.Profiles = subscriptionProfilesOnly(builtinGNMIProfileIdentity, builtinGNMIProfileInterfaces)
			streams, err := buildSharedGNMIStreams(target)
			require.NoError(t, err)
			require.Len(t, streams, 2)

			expectedModels := map[string]string{
				builtinGNMIProfileIdentity:   "openconfig-system",
				builtinGNMIProfileInterfaces: "openconfig-interfaces",
			}
			for _, stream := range streams {
				expectedModel, ok := expectedModels[stream.Profile]
				require.True(t, ok, stream.Profile)
				assert.Equal(t, []string{expectedModel}, stream.RequiredModels)
				require.NotEmpty(t, stream.Paths)
				for _, path := range stream.Paths {
					assert.Equal(t, builtinGNMIOriginOpenConfig, path.Origin)
				}
				for _, catalogMapping := range stream.Mappings {
					if catalogMapping.Mapping.Source.Origin != builtinGNMISyntheticReceiverOrigin {
						assert.Equal(t, builtinGNMIOriginOpenConfig, catalogMapping.Mapping.Source.Origin)
					}
				}

				request, requestErr := buildSharedGNMISubscribeRequest(target, stream, gnmipb.Encoding_JSON)
				require.NoError(t, requestErr)
				list := request.GetSubscribe()
				require.NotNil(t, list)
				assert.Nil(t, list.GetPrefix())
				for _, subscription := range list.GetSubscription() {
					assert.Equal(t, builtinGNMIOriginOpenConfig, subscription.GetPath().GetOrigin())
				}
			}

			contract, _, err := resolveGNMIProductContract(test.product, test.version)
			require.NoError(t, err)
			models := requiredGNMIModels(contract, streams)
			assert.Equal(t, []string{"openconfig-interfaces", "openconfig-platform", "openconfig-system"}, models)
			assert.NotContains(t, models, builtinGNMIOriginOpenConfig)
		})
	}
}

func TestBuildSharedGNMIStreamsPreservesBuiltinStaticAttributes(t *testing.T) {
	target := subscriptionTestTarget(gnmiProductNexus9000, 1)
	target.Name = "nx-1"
	target.Profiles = subscriptionProfilesOnly(builtinGNMIProfileOptics)
	streams, err := buildSharedGNMIStreams(target)
	require.NoError(t, err)
	require.Len(t, streams, 1)
	foundVDM := false
	for _, mapping := range streams[0].Mappings {
		if mapping.StaticAttributes["cisco.optics.profile"] != "vdm" {
			continue
		}
		foundVDM = true
		assert.Equal(t, "true", mapping.StaticAttributes["cisco.optics.experimental"])
	}
	assert.True(t, foundVDM)
}

func TestBuildSharedGNMIStreamsEnforcesMaxStreams(t *testing.T) {
	target := subscriptionTestTarget(gnmiProductCatalyst9800, 2)
	target.Name = "xe-1"
	_, err := buildSharedGNMIStreams(target)
	require.ErrorContains(t, err, "requires 3 compatible subscription streams")

	target.MaxStreams = 3
	streams, err := buildSharedGNMIStreams(target)
	require.NoError(t, err)
	assert.Len(t, streams, estimateGNMIStreams(target.withDefaults()))
}

func TestBuildSharedGNMISubscribeRequestModesAndOriginPlacement(t *testing.T) {
	tests := []struct {
		name            string
		product         string
		mode            string
		wantMode        gnmipb.SubscriptionList_Mode
		wantPathMode    gnmipb.SubscriptionMode
		wantSampleNanos uint64
	}{
		{name: "stream sample", product: gnmiProductASR9000, mode: gnmiModeStream, wantMode: gnmipb.SubscriptionList_STREAM, wantPathMode: gnmipb.SubscriptionMode_SAMPLE, wantSampleNanos: uint64((30 * time.Second).Nanoseconds())},
		{name: "once", product: gnmiProductASR9000, mode: gnmiModeOnce, wantMode: gnmipb.SubscriptionList_ONCE},
		{name: "poll", product: gnmiProductASR9000, mode: gnmiModePoll, wantMode: gnmipb.SubscriptionList_POLL},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stream := sharedGNMIStream{
				Profile:        "custom",
				Mode:           test.mode,
				SampleInterval: 30 * time.Second,
				PollInterval:   time.Minute,
				Paths:          []sharedGNMIPath{{Origin: "openconfig-interfaces", Path: "interfaces/interface/state/counters"}},
			}
			req, err := buildSharedGNMISubscribeRequest(subscriptionTestTarget(test.product, 1), stream, gnmipb.Encoding_JSON_IETF)
			require.NoError(t, err)
			list := req.GetSubscribe()
			require.NotNil(t, list)
			assert.Equal(t, test.wantMode, list.Mode)
			assert.Equal(t, "openconfig-interfaces", list.Prefix.Origin)
			require.Len(t, list.Subscription, 1)
			assert.Empty(t, list.Subscription[0].Path.Origin)
			assert.Equal(t, test.wantSampleNanos, list.Subscription[0].SampleInterval)
			assert.Equal(t, test.wantPathMode, list.Subscription[0].Mode)
		})
	}

	xeStream := sharedGNMIStream{Profile: builtinGNMIProfileOptics, Mode: gnmiModeStream, SampleInterval: 30 * time.Second, Paths: []sharedGNMIPath{{Origin: builtinGNMIOriginRFC7951, Path: "Cisco-IOS-XE-transceiver-oper:transceiver-oper-data/transceiver"}}}
	xeReq, err := buildSharedGNMISubscribeRequest(subscriptionTestTarget(gnmiProductCatalyst9800, 1), xeStream, gnmipb.Encoding_JSON_IETF)
	require.NoError(t, err)
	assert.Equal(t, builtinGNMIOriginRFC7951, xeReq.GetSubscribe().Prefix.Origin)
	assert.Equal(t, "Cisco-IOS-XE-transceiver-oper:transceiver-oper-data", xeReq.GetSubscribe().Subscription[0].Path.Elem[0].Name)

	nxStream := sharedGNMIStream{Profile: builtinGNMIProfileOptics, Mode: gnmiModeStream, SampleInterval: 30 * time.Second, Paths: []sharedGNMIPath{
		{Origin: builtinGNMIOriginDME, Path: "sys/intf"},
		{Origin: builtinGNMIOriginNXDevice, Path: "System/intf-items/phys-items/PhysIf-list/phys-items/fcotdd-items"},
	}}
	nxReq, err := buildSharedGNMISubscribeRequest(subscriptionTestTarget(gnmiProductNexus9000, 1), nxStream, gnmipb.Encoding_JSON)
	require.NoError(t, err)
	nxList := nxReq.GetSubscribe()
	assert.Nil(t, nxList.Prefix)
	assert.Equal(t, gnmipb.Encoding_JSON, nxList.GetEncoding())
	assert.Equal(t, gnmipb.SubscriptionList_STREAM, nxList.GetMode())
	assert.False(t, nxList.GetUpdatesOnly())
	assert.False(t, nxList.GetAllowAggregation())
	assert.Nil(t, nxList.GetQos())
	assert.Empty(t, nxReq.GetExtension())
	require.Len(t, nxList.Subscription, 2)
	assert.Equal(t, builtinGNMIOriginDME, nxList.Subscription[0].Path.Origin)
	assert.Len(t, nxList.Subscription[0].Path.Elem, 2)
	assert.Equal(t, builtinGNMIOriginNXDevice, nxList.Subscription[1].Path.Origin)
	for _, subscription := range nxList.Subscription {
		assert.Empty(t, subscription.GetPath().GetTarget())
		assert.Equal(t, gnmipb.SubscriptionMode_SAMPLE, subscription.GetMode())
		assert.Positive(t, subscription.GetSampleInterval())
		assert.Zero(t, subscription.GetHeartbeatInterval())
		assert.False(t, subscription.GetSuppressRedundant())
	}

	_, err = buildSharedGNMISubscribeRequest(subscriptionTestTarget(gnmiProductNexus9000, 1), nxStream, gnmipb.Encoding_JSON_IETF)
	require.ErrorContains(t, err, "not approved")

	nxStream.Mode = gnmiModePoll
	_, err = buildSharedGNMISubscribeRequest(subscriptionTestTarget(gnmiProductNexus9000, 1), nxStream, gnmipb.Encoding_JSON)
	require.ErrorContains(t, err, "SAMPLE STREAM subscriptions")
}

func TestBuildSharedGNMISubscribeRequestRejectsMixedPrefixOrigins(t *testing.T) {
	stream := sharedGNMIStream{Profile: "bad", Mode: gnmiModeStream, SampleInterval: time.Minute, Paths: []sharedGNMIPath{
		{Origin: "module-a", Path: "a/b"},
		{Origin: "module-b", Path: "c/d"},
	}}
	_, err := buildSharedGNMISubscribeRequest(subscriptionTestTarget(gnmiProductASR9000, 1), stream, gnmipb.Encoding_JSON)
	require.ErrorContains(t, err, "mixes prefix (path_target, origin) pairs")
}

func TestBuildSharedGNMISubscribeRequestRejectsMalformedRFC7951Namespace(t *testing.T) {
	stream := sharedGNMIStream{
		Profile: "bad", Mode: gnmiModeStream, SampleInterval: time.Minute,
		Paths: []sharedGNMIPath{{Origin: builtinGNMIOriginRFC7951, Path: "a:b:c/state"}},
	}
	_, err := buildSharedGNMISubscribeRequest(
		subscriptionTestTarget(gnmiProductCatalyst9800, 1),
		stream,
		gnmipb.Encoding_JSON_IETF,
	)
	require.ErrorContains(t, err, "namespace form required")
}

func TestNegotiateSharedGNMIEncoding(t *testing.T) {
	base := subscriptionTestTarget(gnmiProductNexus9000, 1)
	dme := []sharedGNMIStream{{Paths: []sharedGNMIPath{{Origin: builtinGNMIOriginDME, Path: "sys/intf"}}}}
	withoutDME := []sharedGNMIStream{{Paths: []sharedGNMIPath{{Origin: builtinGNMIOriginNXDevice, Path: "System"}}}}

	encoding, err := negotiateSharedGNMIEncoding(base, &gnmipb.CapabilityResponse{SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_PROTO, gnmipb.Encoding_JSON, gnmipb.Encoding_JSON_IETF}}, dme)
	require.NoError(t, err)
	assert.Equal(t, gnmipb.Encoding_JSON, encoding)

	encoding, err = negotiateSharedGNMIEncoding(base, &gnmipb.CapabilityResponse{SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_PROTO, gnmipb.Encoding_JSON}}, dme)
	require.NoError(t, err)
	assert.Equal(t, gnmipb.Encoding_JSON, encoding)

	encoding, err = negotiateSharedGNMIEncoding(base, &gnmipb.CapabilityResponse{SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON_IETF, gnmipb.Encoding_JSON}}, withoutDME)
	require.NoError(t, err)
	assert.Equal(t, gnmipb.Encoding_JSON, encoding)

	_, err = negotiateSharedGNMIEncoding(base, &gnmipb.CapabilityResponse{SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_PROTO}}, dme)
	require.ErrorContains(t, err, "no encoding authorized")

	_, err = negotiateSharedGNMIEncoding(base, &gnmipb.CapabilityResponse{SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_PROTO}}, withoutDME)
	require.ErrorContains(t, err, "no encoding authorized")

	_, err = negotiateSharedGNMIEncoding(base, &gnmipb.CapabilityResponse{}, withoutDME)
	require.ErrorContains(t, err, "no encoding authorized")
}

func TestBuildSharedGNMISubscribeRequestPathAndListOptions(t *testing.T) {
	zero := time.Duration(0)
	heartbeat := 5 * time.Minute
	suppress := true
	qos := uint32(0)
	depth := uint32(4)
	stream := sharedGNMIStream{
		Profile:          "custom",
		Mode:             gnmiModeStream,
		SampleInterval:   time.Minute,
		UpdatesOnly:      true,
		AllowAggregation: true,
		QoSMarking:       &qos,
		GNMIExtensions:   GNMIExtensionsConfig{Depth: &depth},
		Paths: []sharedGNMIPath{
			{Origin: "openconfig-interfaces", Path: "interfaces/interface/state/counters", StreamMode: gnmiStreamModeSample, SampleInterval: &zero, HeartbeatInterval: &heartbeat, SuppressRedundant: &suppress},
			{Origin: "openconfig-interfaces", Path: "interfaces/interface/state/oper-status", StreamMode: gnmiStreamModeOnChange, HeartbeatInterval: &heartbeat},
			{Origin: "openconfig-interfaces", Path: "interfaces/interface/state/admin-status", StreamMode: gnmiStreamModeTargetDefined},
		},
	}
	req, err := buildSharedGNMISubscribeRequest(subscriptionTestTarget(gnmiProductASR9000, 1), stream, gnmipb.Encoding_JSON_IETF)
	require.NoError(t, err)
	list := req.GetSubscribe()
	require.NotNil(t, list)
	assert.True(t, list.UpdatesOnly)
	assert.True(t, list.AllowAggregation)
	require.NotNil(t, list.Qos)
	assert.Zero(t, list.Qos.Marking)
	require.Len(t, list.Subscription, 3)
	assert.Equal(t, gnmipb.SubscriptionMode_SAMPLE, list.Subscription[0].Mode)
	assert.Zero(t, list.Subscription[0].SampleInterval)
	assert.Equal(t, uint64(heartbeat.Nanoseconds()), list.Subscription[0].HeartbeatInterval)
	assert.True(t, list.Subscription[0].SuppressRedundant)
	assert.Equal(t, gnmipb.SubscriptionMode_ON_CHANGE, list.Subscription[1].Mode)
	assert.Zero(t, list.Subscription[1].SampleInterval)
	assert.Equal(t, uint64(heartbeat.Nanoseconds()), list.Subscription[1].HeartbeatInterval)
	assert.False(t, list.Subscription[1].SuppressRedundant)
	assert.Equal(t, gnmipb.SubscriptionMode_TARGET_DEFINED, list.Subscription[2].Mode)
	assert.Zero(t, list.Subscription[2].SampleInterval)
	require.Len(t, req.Extension, 1)
	assert.Equal(t, depth, req.Extension[0].GetDepth().GetLevel())
}

func TestBuildSharedGNMISubscribeRequestValidatesProtocolOptionsAndWildcardPolicy(t *testing.T) {
	for _, product := range []string{gnmiProductNexus9000, gnmiProductNexus3500} {
		t.Run(product, func(t *testing.T) {
			target := subscriptionTestTarget(product, 1)
			stream := sharedGNMIStream{
				Profile: "custom", Mode: gnmiModeStream, SampleInterval: time.Minute,
				Paths: []sharedGNMIPath{{Origin: "openconfig", Path: "components/component/state"}},
			}

			stream.UpdatesOnly = true
			_, err := buildSharedGNMISubscribeRequest(target, stream, gnmipb.Encoding_JSON)
			require.ErrorContains(t, err, "updates_only must be false")

			stream.UpdatesOnly = false
			stream.Paths[0].StreamMode = gnmiStreamModeOnChange
			_, err = buildSharedGNMISubscribeRequest(target, stream, gnmipb.Encoding_JSON)
			require.ErrorContains(t, err, "stream_mode must be sample")

			stream.Paths[0].StreamMode = gnmiStreamModeSample
			stream.Paths[0].Path = "components/component[name=*]/state"
			_, err = buildSharedGNMISubscribeRequest(target, stream, gnmipb.Encoding_JSON)
			require.ErrorContains(t, err, "must be explicit and non-wildcard")

			thirtySeconds := 30 * time.Second
			stream.Paths = []sharedGNMIPath{
				{Origin: "openconfig", Path: "components/component[name=Chassis]/state"},
				{Origin: "openconfig", Path: "system/state", SampleInterval: &thirtySeconds},
			}
			_, err = buildSharedGNMISubscribeRequest(target, stream, gnmipb.Encoding_JSON)
			require.ErrorContains(t, err, "one common sample_interval")

			zero := time.Duration(0)
			stream.Paths = []sharedGNMIPath{{
				Origin: "openconfig", Path: "components/component[name=Chassis]/state", SampleInterval: &zero,
			}}
			_, err = buildSharedGNMISubscribeRequest(target, stream, gnmipb.Encoding_JSON)
			require.ErrorContains(t, err, "between 1s and 604800s")
		})
	}
}

func TestNegotiateSharedGNMIStreamEncodingFiltersToProductApprovedEncodings(t *testing.T) {
	target := subscriptionTestTarget(gnmiProductASR9000, 1)
	target.EncodingPreference = []string{"proto", "json_ietf"}
	caps := &gnmipb.CapabilityResponse{SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_PROTO, gnmipb.Encoding_JSON_IETF}}
	stream := sharedGNMIStream{Profile: "custom", EncodingPreference: []string{"proto", "json_ietf"}}
	encoding, err := negotiateSharedGNMIStreamEncoding(target, caps, stream)
	require.NoError(t, err)
	assert.Equal(t, gnmipb.Encoding_JSON_IETF, encoding)

	stream.AllowAggregation = true
	encoding, err = negotiateSharedGNMIStreamEncoding(target, caps, stream)
	require.NoError(t, err)
	assert.Equal(t, gnmipb.Encoding_JSON_IETF, encoding)

	dme := sharedGNMIStream{Profile: "dme", Paths: []sharedGNMIPath{{Origin: builtinGNMIOriginDME, Path: "sys/intf"}}}
	nexus := subscriptionTestTarget(gnmiProductNexus9000, 1)
	encoding, err = negotiateSharedGNMIStreamEncoding(nexus, &gnmipb.CapabilityResponse{SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON_IETF, gnmipb.Encoding_JSON}}, dme)
	require.NoError(t, err)
	assert.Equal(t, gnmipb.Encoding_JSON, encoding)
}

func TestSharedGNMIStreamOwnerIDIsStableAndBounded(t *testing.T) {
	stream := sharedGNMIStream{Profile: strings.Repeat("profile", 200)}
	for i := range 1000 {
		stream.Paths = append(stream.Paths, sharedGNMIPath{
			Origin: strings.Repeat("origin", 50),
			Path:   fmt.Sprintf("%s/%d", strings.Repeat("element", 50), i),
		})
	}
	first := sharedGNMIStreamOwnerID(strings.Repeat("target", 200), stream)
	second := sharedGNMIStreamOwnerID(strings.Repeat("target", 200), stream)
	assert.Equal(t, first, second)
	assert.Len(t, first, len("gnmi:")+sha256.Size*2)
	stream.Paths[0].Path += "/changed"
	assert.NotEqual(t, first, sharedGNMIStreamOwnerID(strings.Repeat("target", 200), stream))
	stream.Paths[0].Path = strings.TrimSuffix(stream.Paths[0].Path, "/changed")
	stream.Paths[0].PathTarget = "test-target"
	assert.NotEqual(t, first, sharedGNMIStreamOwnerID(strings.Repeat("target", 200), stream))
}

func TestSharedGNMIStaticAttributeSourceKeyRejectsNULBoundaryCollision(t *testing.T) {
	configured := internalgnmi.SourcePath{
		Origin:   "openconfig",
		Elements: []string{"interfaces", "interface"},
		Leaf:     "value",
	}
	deviceControlled := internalgnmi.SourcePath{
		PathTarget: "\x00openconfig",
		Origin:     "interfaces",
		Elements:   []string{"interface"},
		Leaf:       "value",
	}
	staticAttributes := map[string]map[string]string{
		sharedGNMISourceKey(configured): {"cisco.optics.profile": "configured"},
	}
	assert.Equal(t, configured.Key(), sharedGNMISourceKey(configured),
		"receiver and canonical registry source identities must use the same encoding")
	assert.NotEqual(t, sharedGNMISourceKey(configured), sharedGNMISourceKey(deviceControlled))
	assert.Nil(t, staticAttributes[sharedGNMISourceKey(deviceControlled)],
		"a device-controlled NUL must not inherit another mapping's static attributes")

	var encoded strings.Builder
	appendSharedGNMIKeyPart(&encoded, "a\x00b")
	assert.Equal(t, "3:a\x00b", encoded.String())
}

func subscriptionTestTarget(product string, maxStreams int) GNMITargetConfig {
	return GNMITargetConfig{
		Product: product,
		SoftwareVersion: map[string]string{
			gnmiProductCatalyst9800: "17.18.1",
			gnmiProductASR9000:      "24.4.1",
			gnmiProductNCS5500:      "24.4.1",
			gnmiProductNexus9000:    "10.6(1)",
			gnmiProductNexus3500:    "10.5(1)",
		}[product],
		MaxStreams: maxStreams,
	}
}

func subscriptionProfilesOnly(enabled ...string) GNMIProfilesConfig {
	profiles := GNMIProfilesConfig{
		Identity:             GNMIProfileConfig{Enabled: subscriptionBoolPtr(false)},
		System:               GNMIProfileConfig{Enabled: subscriptionBoolPtr(false)},
		Interfaces:           GNMIProfileConfig{Enabled: subscriptionBoolPtr(false)},
		Optics:               GNMIProfileConfig{Enabled: subscriptionBoolPtr(false)},
		Catalyst9800Wireless: GNMIProfileConfig{Enabled: subscriptionBoolPtr(false)},
	}
	for _, profile := range enabled {
		switch profile {
		case builtinGNMIProfileIdentity:
			profiles.Identity.Enabled = subscriptionBoolPtr(true)
		case builtinGNMIProfileSystem:
			profiles.System.Enabled = subscriptionBoolPtr(true)
		case builtinGNMIProfileInterfaces:
			profiles.Interfaces.Enabled = subscriptionBoolPtr(true)
		case builtinGNMIProfileOptics:
			profiles.Optics.Enabled = subscriptionBoolPtr(true)
		case builtinGNMIProfileCatalyst9800Wireless:
			profiles.Catalyst9800Wireless.Enabled = subscriptionBoolPtr(true)
		}
	}
	return profiles
}

func subscriptionBoolPtr(value bool) *bool { return &value }

func sharedStreamProfiles(streams []sharedGNMIStream) []string {
	out := make([]string, len(streams))
	for i := range streams {
		out[i] = streams[i].Profile
	}
	return out
}

func assertAllPathsHaveOneOrigin(t *testing.T, paths []sharedGNMIPath) {
	t.Helper()
	require.NotEmpty(t, paths)
	origin := paths[0].Origin
	for i := 1; i < len(paths); i++ {
		assert.Equal(t, origin, paths[i].Origin)
	}
}

func sharedStreamsByOrigin(streams []sharedGNMIStream) map[string]sharedGNMIStream {
	out := make(map[string]sharedGNMIStream, len(streams))
	for i := range streams {
		if len(streams[i].Paths) > 0 {
			out[streams[i].Paths[0].Origin] = streams[i]
		}
	}
	return out
}
