// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

func TestBuildSharedGNMIStreamsDefaultsIntervalsAndStableOrder(t *testing.T) {
	target := GNMITargetConfig{Name: "xe-1", Platform: gnmiPlatformIOSXE, MaxStreams: 4}
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
		target := GNMITargetConfig{
			Name:       "xr-1",
			Platform:   gnmiPlatformIOSXR,
			MaxStreams: 2,
			Profiles:   subscriptionProfilesOnly(builtinGNMIProfileOptics),
		}
		target.Profiles.Optics.Required = true
		streams, err := buildSharedGNMIStreams(target)
		require.NoError(t, err)
		require.Len(t, streams, 2)
		assert.Len(t, streams, estimateGNMIStreams(target.withDefaults()))
		for _, stream := range streams {
			assert.Equal(t, builtinGNMIProfileOptics, stream.Profile)
			assert.True(t, stream.Required)
			assert.True(t, stream.Optics)
			assertAllPathsHaveOneOrigin(t, stream.Paths)
		}
		byOrigin := sharedStreamsByOrigin(streams)
		controller := byOrigin["Cisco-IOS-XR-controller-optics-oper"]
		require.Len(t, controller.Paths, 2, "duplicate optics-info request path must be removed")
		assert.Len(t, controller.Mappings, 16, "DOM controller + lane and coherent mappings remain lossless")
		otu := byOrigin["Cisco-IOS-XR-controller-otu-oper"]
		require.Len(t, otu.Paths, 1)
		assert.Len(t, otu.Mappings, 2)
	})

	t.Run("NX keeps per-path origins in one profile stream", func(t *testing.T) {
		target := GNMITargetConfig{
			Name:       "nx-1",
			Platform:   gnmiPlatformNXOS,
			MaxStreams: 1,
			Profiles:   subscriptionProfilesOnly(builtinGNMIProfileOptics),
		}
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
		Name:       "xr-custom",
		Platform:   gnmiPlatformIOSXR,
		MaxStreams: 1,
		Profiles:   subscriptionProfilesOnly(),
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

func TestBuildSharedGNMIStreamsPreservesBuiltinStaticAttributes(t *testing.T) {
	target := GNMITargetConfig{Name: "nx-1", Platform: gnmiPlatformNXOS, MaxStreams: 1, Profiles: subscriptionProfilesOnly(builtinGNMIProfileOptics)}
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
	target := GNMITargetConfig{Name: "xe-1", Platform: gnmiPlatformIOSXE, MaxStreams: 2}
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
		platform        string
		mode            string
		wantMode        gnmipb.SubscriptionList_Mode
		wantSampleNanos uint64
	}{
		{name: "stream sample", platform: gnmiPlatformIOSXR, mode: gnmiModeStream, wantMode: gnmipb.SubscriptionList_STREAM, wantSampleNanos: uint64((30 * time.Second).Nanoseconds())},
		{name: "once", platform: gnmiPlatformIOSXR, mode: gnmiModeOnce, wantMode: gnmipb.SubscriptionList_ONCE},
		{name: "poll", platform: gnmiPlatformIOSXR, mode: gnmiModePoll, wantMode: gnmipb.SubscriptionList_POLL},
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
			req, err := buildSharedGNMISubscribeRequest(GNMITargetConfig{Platform: test.platform}, stream, gnmipb.Encoding_JSON_IETF)
			require.NoError(t, err)
			list := req.GetSubscribe()
			require.NotNil(t, list)
			assert.Equal(t, test.wantMode, list.Mode)
			assert.Equal(t, "openconfig-interfaces", list.Prefix.Origin)
			require.Len(t, list.Subscription, 1)
			assert.Empty(t, list.Subscription[0].Path.Origin)
			assert.Equal(t, test.wantSampleNanos, list.Subscription[0].SampleInterval)
			assert.Equal(t, gnmipb.SubscriptionMode_SAMPLE, list.Subscription[0].Mode)
		})
	}

	xeStream := sharedGNMIStream{Profile: builtinGNMIProfileOptics, Mode: gnmiModeStream, SampleInterval: 30 * time.Second, Paths: []sharedGNMIPath{{Origin: builtinGNMIOriginRFC7951, Path: "Cisco-IOS-XE-transceiver-oper:transceiver-oper-data/transceiver"}}}
	xeReq, err := buildSharedGNMISubscribeRequest(GNMITargetConfig{Platform: gnmiPlatformIOSXE}, xeStream, gnmipb.Encoding_JSON_IETF)
	require.NoError(t, err)
	assert.Equal(t, builtinGNMIOriginRFC7951, xeReq.GetSubscribe().Prefix.Origin)
	assert.Equal(t, "Cisco-IOS-XE-transceiver-oper:transceiver-oper-data", xeReq.GetSubscribe().Subscription[0].Path.Elem[0].Name)

	nxStream := sharedGNMIStream{Profile: builtinGNMIProfileOptics, Mode: gnmiModeStream, SampleInterval: 30 * time.Second, Paths: []sharedGNMIPath{
		{Origin: builtinGNMIOriginDME, Path: "sys/intf"},
		{Origin: builtinGNMIOriginNXDevice, Path: "System/intf-items/phys-items/PhysIf-list/phys-items/fcotdd-items"},
	}}
	nxReq, err := buildSharedGNMISubscribeRequest(GNMITargetConfig{Platform: gnmiPlatformNXOS}, nxStream, gnmipb.Encoding_JSON)
	require.NoError(t, err)
	assert.Nil(t, nxReq.GetSubscribe().Prefix)
	require.Len(t, nxReq.GetSubscribe().Subscription, 2)
	assert.Equal(t, builtinGNMIOriginDME, nxReq.GetSubscribe().Subscription[0].Path.Origin)
	assert.Len(t, nxReq.GetSubscribe().Subscription[0].Path.Elem, 2)
	assert.Equal(t, builtinGNMIOriginNXDevice, nxReq.GetSubscribe().Subscription[1].Path.Origin)
}

func TestBuildSharedGNMISubscribeRequestRejectsMixedPrefixOrigins(t *testing.T) {
	stream := sharedGNMIStream{Profile: "bad", Mode: gnmiModeStream, SampleInterval: time.Minute, Paths: []sharedGNMIPath{
		{Origin: "module-a", Path: "a/b"},
		{Origin: "module-b", Path: "c/d"},
	}}
	_, err := buildSharedGNMISubscribeRequest(GNMITargetConfig{Platform: gnmiPlatformIOSXR}, stream, gnmipb.Encoding_JSON)
	require.ErrorContains(t, err, "mixes prefix origins")
}

func TestNegotiateSharedGNMIEncoding(t *testing.T) {
	base := GNMITargetConfig{Platform: gnmiPlatformNXOS}
	dme := []sharedGNMIStream{{Paths: []sharedGNMIPath{{Origin: builtinGNMIOriginDME, Path: "sys/intf"}}}}
	withoutDME := []sharedGNMIStream{{Paths: []sharedGNMIPath{{Origin: builtinGNMIOriginNXDevice, Path: "System"}}}}

	encoding, err := negotiateSharedGNMIEncoding(base, &gnmipb.CapabilityResponse{SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_PROTO, gnmipb.Encoding_JSON, gnmipb.Encoding_JSON_IETF}}, dme)
	require.NoError(t, err)
	assert.Equal(t, gnmipb.Encoding_JSON, encoding)

	encoding, err = negotiateSharedGNMIEncoding(base, &gnmipb.CapabilityResponse{SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_PROTO, gnmipb.Encoding_JSON}}, dme)
	require.NoError(t, err)
	assert.Equal(t, gnmipb.Encoding_JSON, encoding)

	_, err = negotiateSharedGNMIEncoding(base, &gnmipb.CapabilityResponse{SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_PROTO}}, dme)
	require.ErrorContains(t, err, "cannot decode proto_bytes")

	_, err = negotiateSharedGNMIEncoding(base, &gnmipb.CapabilityResponse{SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_PROTO}}, withoutDME)
	require.ErrorContains(t, err, "cannot decode proto_bytes")

	_, err = negotiateSharedGNMIEncoding(base, &gnmipb.CapabilityResponse{}, withoutDME)
	require.ErrorContains(t, err, "no supported")
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
	for i, stream := range streams {
		out[i] = stream.Profile
	}
	return out
}

func assertAllPathsHaveOneOrigin(t *testing.T, paths []sharedGNMIPath) {
	t.Helper()
	require.NotEmpty(t, paths)
	origin := paths[0].Origin
	for _, path := range paths[1:] {
		assert.Equal(t, origin, path.Origin)
	}
}

func sharedStreamsByOrigin(streams []sharedGNMIStream) map[string]sharedGNMIStream {
	out := make(map[string]sharedGNMIStream, len(streams))
	for _, stream := range streams {
		if len(stream.Paths) > 0 {
			out[stream.Paths[0].Origin] = stream
		}
	}
	return out
}
