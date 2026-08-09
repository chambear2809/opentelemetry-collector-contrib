// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSharedGNMICatalogContractIntersectsEncodingAndResolvesAutoMode(t *testing.T) {
	definition := builtinGNMIProfileDefinition{
		Name: "contract-test",
		Paths: []builtinGNMIPathDefinition{
			{
				ID: "one", Origin: "vendor", Path: "one", PathSetID: "one", VariantID: "native",
				Encodings:   []string{gnmiEncodingJSONIETF, gnmiEncodingJSON},
				StreamModes: []string{gnmiStreamModeSample, gnmiStreamModeTargetDefined},
			},
			{
				ID: "two", Origin: "vendor", Path: "two", PathSetID: "two", VariantID: "native",
				Encodings:   []string{gnmiEncodingJSON},
				StreamModes: []string{gnmiStreamModeTargetDefined},
			},
		},
	}
	streams, err := buildBuiltinProfileStreams(gnmiPlatformNXOS, definition, GNMIProfileConfig{
		StreamMode: gnmiStreamModeAuto,
	})
	require.NoError(t, err)
	require.Len(t, streams, 1)
	assert.Equal(t, []string{gnmiEncodingJSON}, streams[0].CatalogEncodings)
	assert.Equal(t, []string{gnmiStreamModeTargetDefined}, streams[0].CatalogModes)
	assert.Equal(t, gnmiStreamModeTargetDefined, streams[0].StreamMode)

	encoding, err := negotiateSharedGNMIStreamEncoding(
		GNMITargetConfig{EncodingPreference: []string{gnmiEncodingJSONIETF, gnmiEncodingJSON}},
		&gnmipb.CapabilityResponse{SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON_IETF, gnmipb.Encoding_JSON}},
		streams[0],
	)
	require.NoError(t, err)
	assert.Equal(t, gnmipb.Encoding_JSON, encoding)
}

func TestSharedGNMICatalogContractRejectsExplicitUnsupportedModeAndEncoding(t *testing.T) {
	definition := builtinGNMIProfileDefinition{
		Name: "contract-test",
		Paths: []builtinGNMIPathDefinition{{
			ID: "one", Origin: "vendor", Path: "one", PathSetID: "one", VariantID: "native",
			Encodings:   []string{gnmiEncodingJSON},
			StreamModes: []string{gnmiStreamModeTargetDefined},
		}},
	}
	_, err := buildBuiltinProfileStreams(gnmiPlatformNXOS, definition, GNMIProfileConfig{
		StreamMode: gnmiStreamModeSample,
	})
	require.ErrorContains(t, err, `requested stream_mode "sample"`)

	streams, err := buildBuiltinProfileStreams(gnmiPlatformNXOS, definition, GNMIProfileConfig{
		StreamMode: gnmiStreamModeTargetDefined,
	})
	require.NoError(t, err)
	streams[0].Encoding = gnmiEncodingJSONIETF
	_, err = negotiateSharedGNMIStreamEncoding(
		GNMITargetConfig{EncodingPreference: []string{gnmiEncodingJSONIETF, gnmiEncodingJSON}},
		&gnmipb.CapabilityResponse{SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON_IETF, gnmipb.Encoding_JSON}},
		streams[0],
	)
	require.ErrorContains(t, err, `cannot use requested encoding "json_ietf"`)
}

func TestSharedGNMIIdentityDefaultConservativelyUsesDeclaredTargetDefined(t *testing.T) {
	profile := GNMIProfileConfig{}.withDefaults(true, 5*time.Minute, time.Minute)
	assert.True(t, profile.streamModeDefaulted)
	definition, ok := builtinGNMIProfile(gnmiPlatformIOSXE, builtinGNMIProfileIdentity)
	require.True(t, ok)
	streams, err := buildBuiltinProfileStreams(gnmiPlatformIOSXE, definition, profile)
	require.NoError(t, err)
	require.NotEmpty(t, streams)
	for _, stream := range streams {
		assert.Equal(t, gnmiStreamModeTargetDefined, stream.StreamMode)
		assert.Equal(t, []string{gnmiStreamModeTargetDefined}, stream.CatalogModes)
	}
}

func TestSharedGNMICustomStreamKeepsUnrestrictedCompatibilityContract(t *testing.T) {
	stream, err := buildCustomGNMIStream(GNMICustomSubscriptionConfig{
		Name: "custom", Origin: "vendor", Mode: gnmiModeStream, Encoding: gnmiEncodingProto,
		SampleInterval: time.Minute,
		Mappings:       []GNMIMetricMappingConfig{runtimeTestMapping("state/value", "runtime.custom.contract")},
	})
	require.NoError(t, err)
	assert.Nil(t, stream.CatalogEncodings)
	assert.Nil(t, stream.CatalogModes)
	encoding, err := negotiateSharedGNMIStreamEncoding(
		GNMITargetConfig{Platform: gnmiPlatformIOSXR, EncodingPreference: []string{gnmiEncodingProto}},
		&gnmipb.CapabilityResponse{SupportedEncodings: []gnmipb.Encoding{gnmipb.Encoding_PROTO}},
		stream,
	)
	require.NoError(t, err)
	assert.Equal(t, gnmipb.Encoding_PROTO, encoding)
}
