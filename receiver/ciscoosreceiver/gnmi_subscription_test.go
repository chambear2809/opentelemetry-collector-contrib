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
	for index, stream := range streams {
		assert.Equal(t, gnmiModeStream, stream.Mode)
		if index == 0 {
			assert.Equal(t, gnmiStreamModeTargetDefined, stream.StreamMode,
				"the identity path declares only target_defined")
		} else {
			assert.Equal(t, gnmiStreamModeSample, stream.StreamMode)
		}
		assert.Equal(t, gnmiEncodingAuto, stream.Encoding)
		assert.False(t, stream.Optics)
		for _, path := range stream.Paths {
			assert.Equal(t, builtinGNMIOriginRFC7951, path.Origin)
		}
	}
	assert.False(t, streams[1].HealthOnly)
	assert.False(t, streams[2].HealthOnly)

	target.Profiles.Interfaces.SampleInterval = 45 * time.Second
	target.Profiles.Interfaces.StreamMode = gnmiStreamModeOnChange
	_, err = buildSharedGNMIStreams(target)
	require.ErrorContains(t, err, `requested stream_mode "on_change"`)
	target.Profiles.Interfaces.StreamMode = gnmiStreamModeTargetDefined
	streams, err = buildSharedGNMIStreams(target)
	require.NoError(t, err)
	assert.Equal(t, 45*time.Second, streams[2].SampleInterval)
	assert.Equal(t, gnmiStreamModeTargetDefined, streams[2].StreamMode)
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

func TestBuildBuiltinProfileStreamsAppliesGroupOverridesIndependently(t *testing.T) {
	definition, ok := builtinGNMIProfile(gnmiPlatformIOSXE, builtinGNMIProfileSystem)
	require.True(t, ok)
	profile := GNMIProfileConfig{
		Required:       true,
		SampleInterval: time.Minute,
		StreamMode:     gnmiStreamModeSample,
		Groups: map[string]GNMIGroupConfig{
			"cpu": {
				SampleInterval: 15 * time.Second,
				StreamMode:     gnmiStreamModeTargetDefined,
				SyncTimeout:    45 * time.Second,
			},
			"memory": {Enabled: subscriptionBoolPtr(false)},
		},
	}
	streams, err := buildBuiltinProfileStreams(gnmiPlatformIOSXE, definition, profile, 2*time.Minute)
	require.NoError(t, err)
	require.Len(t, streams, 2)

	byGroup := map[string]sharedGNMIStream{}
	for _, stream := range streams {
		require.Len(t, stream.Groups, 1)
		byGroup[stream.Groups[0]] = stream
		assert.True(t, stream.Required, "an interval-only group override must retain a required profile contract")
	}
	cpu := byGroup["cpu"]
	assert.Equal(t, 15*time.Second, cpu.SampleInterval)
	assert.Equal(t, gnmiStreamModeTargetDefined, cpu.StreamMode)
	assert.Equal(t, 45*time.Second, cpu.SyncTimeout)
	uptime := byGroup["uptime"]
	assert.Equal(t, time.Minute, uptime.SampleInterval)
	assert.Equal(t, gnmiStreamModeSample, uptime.StreamMode)
	assert.Equal(t, 2*time.Minute, uptime.SyncTimeout)
	_, memoryPresent := byGroup["memory"]
	assert.False(t, memoryPresent)
}

func TestBuildBuiltinProfileStreamsExpandsExactSelectorsWithinMaxEntities(t *testing.T) {
	definition, ok := builtinGNMIProfile(gnmiPlatformIOSXE, builtinGNMIProfileCatalyst9800Wireless)
	require.True(t, ok)
	profile := GNMIProfileConfig{
		SampleInterval: time.Minute,
		StreamMode:     gnmiStreamModeSample,
		Groups: map[string]GNMIGroupConfig{
			"ap_capwap": {Enabled: subscriptionBoolPtr(false)},
			"rf_rrm": {
				MaxEntities: 4,
				Selectors: map[string][]string{
					"cisco.wlc.ap.mac":     {"00:11:22:33:44:55", "66:77:88:99:aa:bb"},
					"cisco.wlc.radio.slot": {"0", "1"},
				},
			},
			"wlan_ssid": {Enabled: subscriptionBoolPtr(false)},
		},
	}
	streams, err := buildBuiltinProfileStreams(gnmiPlatformIOSXE, definition, profile)
	require.NoError(t, err)
	require.Len(t, streams, 1)
	stream := streams[0]
	assert.Equal(t, []string{"rf_rrm"}, stream.Groups)
	require.Len(t, stream.Paths, 4)
	assert.Len(t, stream.Mappings, 1, "selector expansion must not duplicate metric mappings")
	for _, path := range stream.Paths {
		assert.Equal(t, "wireless.rf", path.PathSetID)
		parsed, parseErr := internalgnmi.ParsePath("", path.Origin, path.Path)
		require.NoError(t, parseErr)
		keys := parsed.Elements[len(parsed.Elements)-1].Keys
		assert.Contains(t, []string{"00:11:22:33:44:55", "66:77:88:99:aa:bb"}, keys["wtp-mac"])
		assert.Contains(t, []string{"0", "1"}, keys["radio-slot-id"])
	}
	pathSets := sharedGNMIAtomicPathSets(stream.Paths)
	require.Len(t, pathSets, 1, "all exact selector expansions retain their indivisible catalog path set")
	assert.Len(t, pathSets[0], 4)

	request, err := buildSharedGNMISubscribeRequest(
		GNMITargetConfig{Platform: gnmiPlatformIOSXE}, stream, gnmipb.Encoding_JSON_IETF,
	)
	require.NoError(t, err)
	require.Len(t, request.GetSubscribe().GetSubscription(), 4)
	for _, subscription := range request.GetSubscribe().GetSubscription() {
		keys := subscription.GetPath().GetElem()[1].GetKey()
		assert.NotEmpty(t, keys["wtp-mac"])
		assert.NotEmpty(t, keys["radio-slot-id"])
	}

	profile.Groups["rf_rrm"] = GNMIGroupConfig{
		MaxEntities: 3,
		Selectors: map[string][]string{
			"cisco.wlc.ap.mac":     {"00:11:22:33:44:55", "66:77:88:99:aa:bb"},
			"cisco.wlc.radio.slot": {"0", "1"},
		},
	}
	_, err = buildBuiltinProfileStreams(gnmiPlatformIOSXE, definition, profile)
	require.ErrorContains(t, err, "selector expansion exceeds max_entities 3")
}

func TestBuildBuiltinProfileStreamsExtendsDMEPathToSelectedCatalogLists(t *testing.T) {
	definition, ok := builtinGNMIProfile(gnmiPlatformNXOS, builtinGNMIProfileOptics)
	require.True(t, ok)
	profile := GNMIProfileConfig{
		SampleInterval: 30 * time.Second,
		StreamMode:     gnmiStreamModeSample,
		Groups: map[string]GNMIGroupConfig{
			"vdm": {
				MaxEntities: 2,
				Selectors: map[string][]string{
					"network.interface.name": {"eth1/1", "eth1/2"},
					"cisco.optics.lane":      {"0"},
				},
			},
		},
	}
	streams, err := buildBuiltinProfileStreams(gnmiPlatformNXOS, definition, profile)
	require.NoError(t, err)
	require.Len(t, streams, 1)
	require.Len(t, streams[0].Paths, 2)

	request, err := buildSharedGNMISubscribeRequest(
		GNMITargetConfig{Platform: gnmiPlatformNXOS}, streams[0], gnmipb.Encoding_JSON,
	)
	require.NoError(t, err)
	require.Len(t, request.GetSubscribe().GetSubscription(), 2)
	for _, subscription := range request.GetSubscribe().GetSubscription() {
		elements := subscription.GetPath().GetElem()
		require.Len(t, elements, 6)
		assert.Contains(t, []string{"eth1/1", "eth1/2"}, elements[2].GetKey()["id"])
		assert.Equal(t, "0", elements[5].GetKey()["id"])
		for _, element := range elements {
			assert.NotContains(t, element.GetName(), "[", "DME selectors must be PathElem keys, not bracket text in element names")
		}
	}
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
	assert.Equal(t, gnmiStreamModeSample, stream.StreamMode)
	assert.Equal(t, gnmiEncodingAuto, stream.Encoding)
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

func TestBuildSharedGNMIStreamsRejectsCatalogedButUnimplementedProfile(t *testing.T) {
	profiles := subscriptionProfilesOnly()
	profiles.Inventory.Enabled = subscriptionBoolPtr(true)
	_, err := buildSharedGNMIStreams(GNMITargetConfig{
		Name: "xr-1", Platform: gnmiPlatformIOSXR, MaxStreams: 4, Profiles: profiles,
	})
	require.ErrorContains(t, err, `profile "inventory" is not supported on platform "ios_xr"`)
}

func TestBuildSharedGNMISubscribeRequestModesAndOriginPlacement(t *testing.T) {
	tests := []struct {
		name            string
		product         string
		mode            string
		streamMode      string
		wantMode        gnmipb.SubscriptionList_Mode
		wantStreamMode  gnmipb.SubscriptionMode
		wantSampleNanos uint64
	}{
		{name: "stream sample", platform: gnmiPlatformIOSXR, mode: gnmiModeStream, streamMode: gnmiStreamModeSample, wantMode: gnmipb.SubscriptionList_STREAM, wantStreamMode: gnmipb.SubscriptionMode_SAMPLE, wantSampleNanos: uint64((30 * time.Second).Nanoseconds())},
		{name: "stream on change", platform: gnmiPlatformIOSXR, mode: gnmiModeStream, streamMode: gnmiStreamModeOnChange, wantMode: gnmipb.SubscriptionList_STREAM, wantStreamMode: gnmipb.SubscriptionMode_ON_CHANGE},
		{name: "stream target defined", platform: gnmiPlatformIOSXR, mode: gnmiModeStream, streamMode: gnmiStreamModeTargetDefined, wantMode: gnmipb.SubscriptionList_STREAM, wantStreamMode: gnmipb.SubscriptionMode_TARGET_DEFINED},
		{name: "stream auto", platform: gnmiPlatformIOSXR, mode: gnmiModeStream, streamMode: gnmiStreamModeAuto, wantMode: gnmipb.SubscriptionList_STREAM, wantStreamMode: gnmipb.SubscriptionMode_TARGET_DEFINED},
		{name: "once", platform: gnmiPlatformIOSXR, mode: gnmiModeOnce, wantMode: gnmipb.SubscriptionList_ONCE, wantStreamMode: gnmipb.SubscriptionMode_SAMPLE},
		{name: "poll", platform: gnmiPlatformIOSXR, mode: gnmiModePoll, wantMode: gnmipb.SubscriptionList_POLL, wantStreamMode: gnmipb.SubscriptionMode_SAMPLE},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stream := sharedGNMIStream{
				Profile:        "custom",
				Mode:           test.mode,
				StreamMode:     test.streamMode,
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
			assert.Equal(t, test.wantStreamMode, list.Subscription[0].Mode)
		})
	}

	_, err := buildSharedGNMISubscribeRequest(GNMITargetConfig{Platform: gnmiPlatformIOSXR}, sharedGNMIStream{
		Profile: "bad", Mode: gnmiModeStream, StreamMode: "sometimes",
		Paths: []sharedGNMIPath{{Origin: "openconfig-interfaces", Path: "interfaces/interface/state/counters"}},
	}, gnmipb.Encoding_JSON_IETF)
	require.ErrorContains(t, err, "unsupported gNMI stream mode")

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

func TestBuildCatalystSwitchSubscribeRequestUsesConservativeWireContract(t *testing.T) {
	for _, product := range []string{gnmiProductCatalyst9300, gnmiProductCatalyst9500} {
		t.Run(product, func(t *testing.T) {
			target := subscriptionTestTarget(product, 1)
			target.Profiles = subscriptionProfilesOnly(builtinGNMIProfileInterfaces)
			streams, err := buildSharedGNMIStreams(target)
			require.NoError(t, err)
			require.Len(t, streams, 1)
			stream := streams[0]
			assert.Equal(t, gnmiModeStream, stream.Mode)
			assert.Equal(t, time.Minute, stream.SampleInterval)
			require.Len(t, stream.Paths, 1)
			assert.NotContains(t, stream.Paths[0].Path, "*")

			request, err := buildSharedGNMISubscribeRequest(target, stream, gnmipb.Encoding_JSON_IETF)
			require.NoError(t, err)
			list := request.GetSubscribe()
			require.NotNil(t, list)
			assert.Equal(t, gnmipb.Encoding_JSON_IETF, list.GetEncoding())
			assert.Equal(t, gnmipb.SubscriptionList_STREAM, list.GetMode())
			assert.False(t, list.GetUpdatesOnly())
			assert.False(t, list.GetAllowAggregation())
			assert.Nil(t, list.GetQos())
			assert.Empty(t, request.GetExtension())
			require.NotNil(t, list.GetPrefix())
			assert.Equal(t, builtinGNMIOriginRFC7951, list.GetPrefix().GetOrigin())
			assert.Empty(t, list.GetPrefix().GetTarget())
			require.Len(t, list.GetSubscription(), 1)
			subscription := list.GetSubscription()[0]
			assert.Equal(t, gnmipb.SubscriptionMode_SAMPLE, subscription.GetMode())
			assert.Equal(t, uint64(time.Minute.Nanoseconds()), subscription.GetSampleInterval())
			assert.Zero(t, subscription.GetHeartbeatInterval())
			assert.False(t, subscription.GetSuppressRedundant())
			assert.Empty(t, subscription.GetPath().GetOrigin())
			assert.Empty(t, subscription.GetPath().GetTarget())
			require.Len(t, subscription.GetPath().GetElem(), 3)
			assert.Equal(t, "openconfig-interfaces:interfaces", subscription.GetPath().GetElem()[0].GetName())
			assert.Equal(t, "interface", subscription.GetPath().GetElem()[1].GetName())
			assert.Equal(t, "state", subscription.GetPath().GetElem()[2].GetName())

			encoding, err := negotiateSharedGNMIEncoding(target, &gnmipb.CapabilityResponse{
				SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_PROTO, gnmipb.Encoding_JSON, gnmipb.Encoding_JSON_IETF},
			}, streams)
			require.NoError(t, err)
			assert.Equal(t, gnmipb.Encoding_JSON_IETF, encoding)

			_, err = negotiateSharedGNMIEncoding(target, &gnmipb.CapabilityResponse{
				SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_PROTO, gnmipb.Encoding_JSON},
			}, streams)
			require.ErrorContains(t, err, "no encoding authorized")

			rejections := []struct {
				name     string
				encoding gnmipb.Encoding
				mutate   func(*sharedGNMIStream)
				want     string
			}{
				{name: "JSON", encoding: gnmipb.Encoding_JSON, want: "not approved"},
				{name: "PROTO", encoding: gnmipb.Encoding_PROTO, want: "not approved"},
				{name: "ONCE", encoding: gnmipb.Encoding_JSON_IETF, mutate: func(candidate *sharedGNMIStream) {
					candidate.Mode = gnmiModeOnce
				}, want: "SAMPLE STREAM subscriptions"},
				{name: "POLL", encoding: gnmipb.Encoding_JSON_IETF, mutate: func(candidate *sharedGNMIStream) {
					candidate.Mode = gnmiModePoll
				}, want: "SAMPLE STREAM subscriptions"},
				{name: "updates_only", encoding: gnmipb.Encoding_JSON_IETF, mutate: func(candidate *sharedGNMIStream) {
					candidate.UpdatesOnly = true
				}, want: "updates_only must be false"},
				{name: "aggregation", encoding: gnmipb.Encoding_JSON_IETF, mutate: func(candidate *sharedGNMIStream) {
					candidate.AllowAggregation = true
				}, want: "allow_aggregation must be false"},
				{name: "qos", encoding: gnmipb.Encoding_JSON_IETF, mutate: func(candidate *sharedGNMIStream) {
					value := uint32(0)
					candidate.QoSMarking = &value
				}, want: "qos_marking is not qualified"},
				{name: "extension", encoding: gnmipb.Encoding_JSON_IETF, mutate: func(candidate *sharedGNMIStream) {
					value := uint32(1)
					candidate.GNMIExtensions.Depth = &value
				}, want: "gnmi_extensions.depth is not qualified"},
				{name: "target_defined", encoding: gnmipb.Encoding_JSON_IETF, mutate: func(candidate *sharedGNMIStream) {
					candidate.Paths[0].StreamMode = gnmiStreamModeTargetDefined
				}, want: "stream_mode must be sample"},
				{name: "heartbeat", encoding: gnmipb.Encoding_JSON_IETF, mutate: func(candidate *sharedGNMIStream) {
					value := time.Minute
					candidate.Paths[0].HeartbeatInterval = &value
				}, want: "optional subscription flags are not qualified"},
				{name: "suppress_redundant", encoding: gnmipb.Encoding_JSON_IETF, mutate: func(candidate *sharedGNMIStream) {
					value := false
					candidate.Paths[0].SuppressRedundant = &value
				}, want: "optional subscription flags are not qualified"},
				{name: "wildcard", encoding: gnmipb.Encoding_JSON_IETF, mutate: func(candidate *sharedGNMIStream) {
					candidate.Paths[0].Path = "openconfig-interfaces:interfaces/interface[name=*]/state"
				}, want: "explicit asterisk wildcard"},
				{name: "sub-second SAMPLE", encoding: gnmipb.Encoding_JSON_IETF, mutate: func(candidate *sharedGNMIStream) {
					candidate.SampleInterval = 500 * time.Millisecond
				}, want: "between 1s and 604800s"},
			}
			for _, rejection := range rejections {
				t.Run("rejects "+rejection.name, func(t *testing.T) {
					candidate := stream
					candidate.Paths = append([]sharedGNMIPath(nil), stream.Paths...)
					if rejection.mutate != nil {
						rejection.mutate(&candidate)
					}
					_, requestErr := buildSharedGNMISubscribeRequest(target, candidate, rejection.encoding)
					require.ErrorContains(t, requestErr, rejection.want)
				})
			}
		})
	}
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
	base := GNMITargetConfig{Platform: gnmiPlatformNXOS, EncodingPreference: []string{gnmiEncodingProto, gnmiEncodingJSONIETF, gnmiEncodingJSON}}
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
	require.ErrorContains(t, err, "no common supported")

	encoding, err = negotiateSharedGNMIEncoding(base, &gnmipb.CapabilityResponse{SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_PROTO}}, withoutDME)
	require.NoError(t, err)
	assert.Equal(t, gnmipb.Encoding_PROTO, encoding)

	_, err = negotiateSharedGNMIEncoding(base, &gnmipb.CapabilityResponse{}, withoutDME)
	require.ErrorContains(t, err, "no common supported")
}

func TestNegotiateSharedGNMIStreamEncodingHonorsPerCustomSelection(t *testing.T) {
	target := GNMITargetConfig{
		Platform:           gnmiPlatformIOSXE,
		EncodingPreference: []string{gnmiEncodingProto, gnmiEncodingJSONIETF, gnmiEncodingJSON},
	}
	capabilities := &gnmipb.CapabilityResponse{SupportedEncodings: []gnmipb.Encoding{
		gnmipb.Encoding_PROTO,
		gnmipb.Encoding_JSON,
		gnmipb.Encoding_JSON_IETF,
	}}
	custom := sharedGNMIStream{Profile: "custom", Encoding: gnmiEncodingProto, Paths: []sharedGNMIPath{{Origin: "custom", Path: "state/value"}}}
	encoding, err := negotiateSharedGNMIStreamEncoding(target, capabilities, custom)
	require.NoError(t, err)
	assert.Equal(t, gnmipb.Encoding_PROTO, encoding)

	custom.Encoding = gnmiEncodingAuto
	encoding, err = negotiateSharedGNMIStreamEncoding(target, capabilities, custom)
	require.NoError(t, err)
	assert.Equal(t, gnmipb.Encoding_PROTO, encoding, "auto custom streams use the target preference after capability intersection")

	builtin := sharedGNMIStream{Profile: builtinGNMIProfileSystem, Encoding: gnmiEncodingAuto, Paths: []sharedGNMIPath{{Origin: builtinGNMIOriginRFC7951, Path: "system/state"}}}
	encoding, err = negotiateSharedGNMIStreamEncoding(target, capabilities, builtin)
	require.NoError(t, err)
	assert.Equal(t, gnmipb.Encoding_JSON_IETF, encoding, "unqualified built-in rows must not select PROTO")

	builtin.Encoding = gnmiEncodingProto
	_, err = negotiateSharedGNMIStreamEncoding(target, capabilities, builtin)
	require.ErrorContains(t, err, "cannot use requested encoding")
}

func TestNegotiateSharedGNMIStreamEncodingRestrictsNXDMEToJSON(t *testing.T) {
	target := GNMITargetConfig{
		Platform:           gnmiPlatformNXOS,
		EncodingPreference: []string{gnmiEncodingJSONIETF, gnmiEncodingJSON},
	}
	dme := sharedGNMIStream{Profile: "custom-dme", Encoding: gnmiEncodingAuto, Paths: []sharedGNMIPath{{Origin: builtinGNMIOriginDME, Path: "sys/intf"}}}
	capabilities := &gnmipb.CapabilityResponse{SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON_IETF, gnmipb.Encoding_JSON}}
	encoding, err := negotiateSharedGNMIStreamEncoding(target, capabilities, dme)
	require.NoError(t, err)
	assert.Equal(t, gnmipb.Encoding_JSON, encoding)

	capabilities.SupportedEncodings = []gnmipb.Encoding{gnmipb.Encoding_JSON_IETF, gnmipb.Encoding_PROTO}
	_, err = negotiateSharedGNMIStreamEncoding(target, capabilities, dme)
	require.ErrorContains(t, err, "no common supported")
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
	for streamIndex := range streams {
		stream := streams[streamIndex]
		if len(stream.Paths) > 0 {
			out[stream.Paths[0].Origin] = stream
		}
	}
	return out
}
