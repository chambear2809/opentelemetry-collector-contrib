// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"maps"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

const fixtureGNMITarget = "fixture-target"

var fixtureGNMIReceipt = time.Date(2026, 7, 2, 12, 5, 0, 0, time.UTC)

func TestGNMIFixtureIOSXERFC7951DOM(t *testing.T) {
	runtime := fixtureGNMIRuntime(t, gnmiPlatformIOSXE, builtinGNMIProfileOptics)
	stream := fixtureGNMIStream(t, runtime, builtinGNMIOriginRFC7951)
	response := fixtureGNMIJSONResponse(t, "ios_xe_rfc7951_dom.json", builtinGNMIOriginRFC7951, nil, true)

	decoded := fixtureGNMIDecode(t, response.GetUpdate())
	_, mapped, _ := fixtureGNMIMap(t, runtime, stream, decoded, false)

	assert.ElementsMatch(t, []string{
		"cisco.optics.laser_bias_current",
		"cisco.optics.present",
		"cisco.optics.rx_power",
		"cisco.optics.temperature",
		"cisco.optics.tx_power",
		"cisco.optics.voltage",
	}, fixtureGNMIMetricNames(mapped))
	for _, point := range mapped {
		assert.Equal(t, "TenGigabitEthernet1/0/1", point.Attributes["network.interface.name"])
		assert.Equal(t, "dom", point.Attributes["cisco.optics.profile"])
		assert.Equal(t, "false", point.Attributes["cisco.optics.experimental"])
	}

	temperature := fixtureGNMIMetric(t, mapped, "cisco.optics.temperature")
	assert.Equal(t, "Cel", temperature.Metric.Unit)
	assert.InDelta(t, 41.75, temperature.DoubleValue, 0.0001)
	voltage := fixtureGNMIMetric(t, mapped, "cisco.optics.voltage")
	assert.Equal(t, "V", voltage.Metric.Unit)
	assert.InDelta(t, 3.31, voltage.DoubleValue, 0.0001)
	laserBias := fixtureGNMIMetric(t, mapped, "cisco.optics.laser_bias_current")
	assert.Equal(t, "mA", laserBias.Metric.Unit)
	assert.InDelta(t, 6.4, laserBias.DoubleValue, 0.0001)
	rxPower := fixtureGNMIMetric(t, mapped, "cisco.optics.rx_power")
	assert.Equal(t, "dB[mW]", rxPower.Metric.Unit)
	assert.InDelta(t, -2.15, rxPower.DoubleValue, 0.0001)
	txPower := fixtureGNMIMetric(t, mapped, "cisco.optics.tx_power")
	assert.Equal(t, "dB[mW]", txPower.Metric.Unit)
	assert.InDelta(t, -1.05, txPower.DoubleValue, 0.0001)
	present := fixtureGNMIMetric(t, mapped, "cisco.optics.present")
	assert.Equal(t, "1", present.Metric.Unit)
	assert.Equal(t, int64(1), present.IntValue)
	assert.NotContains(t, present.Attributes, "cisco.optics.sensor")
}

func TestGNMIFixtureIOSXRNativeOpticsAndOTUScalar(t *testing.T) {
	runtime := fixtureGNMIRuntime(t, gnmiPlatformIOSXR, builtinGNMIProfileOptics)
	opticsOrigin := "Cisco-IOS-XR-controller-optics-oper"
	opticsStream := fixtureGNMIStream(t, runtime, opticsOrigin)
	response := fixtureGNMIJSONResponse(t, "ios_xr_native_optics.json", opticsOrigin, nil, true)

	decoded := fixtureGNMIDecode(t, response.GetUpdate())
	_, mapped, _ := fixtureGNMIMap(t, runtime, opticsStream, decoded, false)
	assert.ElementsMatch(t, []string{
		"cisco.optics.chromatic_dispersion",
		"cisco.optics.dgd",
		"cisco.optics.osnr",
		"cisco.optics.q_margin",
		"cisco.optics.rx_power",
		"cisco.optics.temperature",
	}, fixtureGNMIMetricNames(mapped))

	dom := fixtureGNMIMetric(t, mapped, "cisco.optics.temperature")
	assert.Equal(t, "Cel", dom.Metric.Unit)
	assert.Equal(t, "dom", dom.Attributes["cisco.optics.profile"])
	assert.Equal(t, "false", dom.Attributes["cisco.optics.experimental"])
	coherentUnits := map[string]string{
		"cisco.optics.q_margin":             "dB",
		"cisco.optics.osnr":                 "dB",
		"cisco.optics.dgd":                  "ps",
		"cisco.optics.chromatic_dispersion": "ps/nm",
	}
	for metricName, unit := range coherentUnits {
		point := fixtureGNMIMetric(t, mapped, metricName)
		assert.Equal(t, unit, point.Metric.Unit)
		assert.Equal(t, "HundredGigE0/0/0/0", point.Attributes["network.interface.name"])
		assert.Equal(t, "coherent", point.Attributes["cisco.optics.profile"])
		assert.Equal(t, "true", point.Attributes["cisco.optics.experimental"])
	}

	otuNotification := fixtureGNMILoadNotification(t, "ios_xr_otu_scalar.json")
	otuDecoded := fixtureGNMIDecode(t, otuNotification)
	require.Len(t, otuDecoded.Updates, 2)
	for _, point := range otuDecoded.Updates {
		assert.Equal(t, internalgnmi.ValueDouble, point.Value.Kind, "fixture must exercise scalar double wire values")
	}
	otuStream := fixtureGNMIStream(t, runtime, "Cisco-IOS-XR-controller-otu-oper")
	_, otuMapped, _ := fixtureGNMIMap(t, runtime, otuStream, otuDecoded, false)
	assert.ElementsMatch(t, []string{"cisco.optics.pre_fec_ber", "cisco.optics.q_factor"}, fixtureGNMIMetricNames(otuMapped))
	qFactor := fixtureGNMIMetric(t, otuMapped, "cisco.optics.q_factor")
	assert.Equal(t, "dB", qFactor.Metric.Unit)
	assert.InDelta(t, 11.75, qFactor.DoubleValue, 0.0001)
	assert.Equal(t, "Optics0/0/0/0", qFactor.Attributes["network.interface.name"])
	assert.Equal(t, "coherent", qFactor.Attributes["cisco.optics.profile"])
	assert.Equal(t, "true", qFactor.Attributes["cisco.optics.experimental"])
	preFEC := fixtureGNMIMetric(t, otuMapped, "cisco.optics.pre_fec_ber")
	assert.Equal(t, "1", preFEC.Metric.Unit)
	assert.InDelta(t, 0.00000024, preFEC.DoubleValue, 0.000000001)
}

func TestGNMIFixtureNXDMESensorAllowlist(t *testing.T) {
	runtime := fixtureGNMIRuntime(t, gnmiPlatformNXOS, builtinGNMIProfileOptics)
	stream := fixtureGNMIStream(t, runtime, builtinGNMIOriginDME)
	response := fixtureGNMIJSONResponse(t, "nx_dme_sensors.json", builtinGNMIOriginDME, []string{"sys", "intf"}, false)

	decoded := fixtureGNMIDecode(t, response.GetUpdate())
	normalized, mapped, unmapped := fixtureGNMIMap(t, runtime, stream, decoded, true)
	assert.Equal(t, 15, unmapped)
	assert.ElementsMatch(t, []string{"cisco.optics.esnr", "cisco.optics.tdecq", "cisco.optics.temperature"}, fixtureGNMIMetricNames(mapped))

	tdecq := fixtureGNMIMetric(t, mapped, "cisco.optics.tdecq")
	assert.Equal(t, "dB", tdecq.Metric.Unit)
	assert.InDelta(t, 2.4, tdecq.DoubleValue, 0.0001)
	assert.Equal(t, "Ethernet1/49", tdecq.Attributes["network.interface.name"])
	assert.Equal(t, "0", tdecq.Attributes["cisco.optics.lane"])
	assert.Equal(t, "vdm", tdecq.Attributes["cisco.optics.profile"])
	assert.Equal(t, "true", tdecq.Attributes["cisco.optics.experimental"])
	assert.Equal(t, "27", fixtureGNMISensorID(tdecq.Source.Elements))

	esnr := fixtureGNMIMetric(t, mapped, "cisco.optics.esnr")
	assert.Equal(t, "dB", esnr.Metric.Unit)
	assert.InDelta(t, 22.8, esnr.DoubleValue, 0.0001)
	assert.Equal(t, "1", esnr.Attributes["cisco.optics.lane"])
	assert.Equal(t, "30", fixtureGNMISensorID(esnr.Source.Elements))
	temperature := fixtureGNMIMetric(t, mapped, "cisco.optics.temperature")
	assert.Equal(t, "Cel", temperature.Metric.Unit)
	assert.InDelta(t, 46.5, temperature.DoubleValue, 0.0001)
	assert.Equal(t, "dom", temperature.Attributes["cisco.optics.profile"])
	assert.Equal(t, "false", temperature.Attributes["cisco.optics.experimental"])
	assert.Equal(t, "31", fixtureGNMISensorID(temperature.Source.Elements))

	var normalizedTDECQSensors, rejectedValueSensors []string
	for _, point := range normalized.Updates {
		sensorID := fixtureGNMISensorID(point.Series.Elements)
		switch point.Series.Leaf {
		case "tdecq":
			normalizedTDECQSensors = append(normalizedTDECQSensors, sensorID)
		case "value":
			rejectedValueSensors = append(rejectedValueSensors, sensorID)
		}
	}
	assert.Equal(t, []string{"27"}, normalizedTDECQSensors)
	assert.ElementsMatch(t, []string{"28", "29", "99"}, rejectedValueSensors,
		"PAM4 transition, wrong-unit TDECQ, and unknown sensors must remain unmapped raw values")
}

func TestGNMIFixtureAtomicAndDeleteNotifications(t *testing.T) {
	runtime := fixtureGNMIRuntime(t, gnmiPlatformIOSXR, builtinGNMIProfileInterfaces)
	stream := fixtureGNMIStream(t, runtime, "openconfig-interfaces")

	atomicDecoded := fixtureGNMIDecode(t, fixtureGNMILoadNotification(t, "atomic_interface_counters.json"))
	assert.True(t, atomicDecoded.Atomic)
	_, atomicMapped, _ := fixtureGNMIMap(t, runtime, stream, atomicDecoded, false)
	require.Len(t, atomicMapped, 2)
	for _, point := range atomicMapped {
		assert.Equal(t, "system.network.io", point.Metric.Name)
		assert.Equal(t, "By", point.Metric.Unit)
		assert.Equal(t, "HundredGigE0/0/0/0", point.Attributes["network.interface.name"])
		assert.Contains(t, []string{"receive", "transmit"}, point.Attributes["network.io.direction"])
	}
	atomicResult, err := runtime.cache.Apply(internalgnmi.CacheNotification{
		Prefix: atomicDecoded.Prefix, Timestamp: atomicDecoded.Timestamp, Atomic: true, Updates: atomicMapped,
	})
	require.NoError(t, err)
	assert.Len(t, atomicResult.Applied, 2)
	assert.Equal(t, 2, runtime.cache.Len())
	baselineTimestamp, ok := runtime.cache.AtomicBaseline(atomicDecoded.Prefix)
	require.True(t, ok)
	assert.Equal(t, atomicDecoded.Timestamp, baselineTimestamp)

	deleteDecoded := fixtureGNMIDecode(t, fixtureGNMILoadNotification(t, "delete_interface_counter.json"))
	assert.False(t, deleteDecoded.Atomic)
	require.Len(t, deleteDecoded.Deletes, 1)
	deletePath := deleteDecoded.Deletes[0]
	require.NotEmpty(t, deletePath.Elements)
	assert.Equal(t, "out-octets", deletePath.Elements[len(deletePath.Elements)-1].Name)
	_, deleteMapped, _ := fixtureGNMIMap(t, runtime, stream, deleteDecoded, false)
	assert.Empty(t, deleteMapped)
	deleteResult, err := runtime.cache.Apply(internalgnmi.CacheNotification{
		Prefix: deleteDecoded.Prefix, Timestamp: deleteDecoded.Timestamp, Deletes: deleteDecoded.Deletes,
	})
	require.NoError(t, err)
	require.Len(t, deleteResult.Removed, 1)
	assert.Equal(t, "system.network.io", deleteResult.Removed[0].Metric.Name)
	assert.Equal(t, "transmit", deleteResult.Removed[0].Attributes["network.io.direction"])
	assert.Equal(t, 1, deleteResult.AtomicBaselinesInvalidated)
	assert.Equal(t, 1, runtime.cache.Len())
	_, ok = runtime.cache.AtomicBaseline(atomicDecoded.Prefix)
	assert.False(t, ok)
}

func fixtureGNMIRuntime(t *testing.T, platform, profile string) *sharedGNMITargetRuntime {
	t.Helper()
	disabled, enabled := false, true
	profiles := GNMIProfilesConfig{
		Identity:             GNMIProfileConfig{Enabled: &disabled},
		System:               GNMIProfileConfig{Enabled: &disabled},
		Interfaces:           GNMIProfileConfig{Enabled: &disabled},
		Optics:               GNMIProfileConfig{Enabled: &disabled},
		Catalyst9800Wireless: GNMIProfileConfig{Enabled: &disabled},
	}
	switch profile {
	case builtinGNMIProfileIdentity:
		profiles.Identity.Enabled = &enabled
	case builtinGNMIProfileSystem:
		profiles.System.Enabled = &enabled
	case builtinGNMIProfileInterfaces:
		profiles.Interfaces.Enabled = &enabled
	case builtinGNMIProfileOptics:
		profiles.Optics.Enabled = &enabled
	case builtinGNMIProfileCatalyst9800Wireless:
		profiles.Catalyst9800Wireless.Enabled = &enabled
	default:
		require.FailNow(t, "unknown fixture profile", profile)
	}
	cache, err := internalgnmi.NewCache(100)
	require.NoError(t, err)
	runtime, err := newSharedGNMITargetRuntime(GNMITargetConfig{
		Name: fixtureGNMITarget, Platform: platform, MaxStreams: 8, Profiles: profiles,
	}, cache)
	require.NoError(t, err)
	return runtime
}

func fixtureGNMIStream(t *testing.T, runtime *sharedGNMITargetRuntime, origin string) sharedGNMIRuntimeStream {
	t.Helper()
	for i := range runtime.streams {
		for _, path := range runtime.streams[i].Paths {
			if path.Origin == origin {
				return runtime.streams[i]
			}
		}
	}
	require.FailNow(t, "fixture stream origin not found", origin)
	return sharedGNMIRuntimeStream{}
}

func fixtureGNMIJSONResponse(t *testing.T, name, origin string, prefixElements []string, ietf bool) *gnmipb.SubscribeResponse {
	t.Helper()
	raw := fixtureGNMIRead(t, name)
	prefix := &gnmipb.Path{Origin: origin}
	for _, element := range prefixElements {
		prefix.Elem = append(prefix.Elem, &gnmipb.PathElem{Name: element})
	}
	typed := &gnmipb.TypedValue{}
	if ietf {
		typed.Value = &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: raw}
	} else {
		typed.Value = &gnmipb.TypedValue_JsonVal{JsonVal: raw}
	}
	return &gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
		Timestamp: fixtureGNMIReceipt.Add(-time.Minute).UnixNano(),
		Prefix:    prefix,
		Update:    []*gnmipb.Update{{Path: &gnmipb.Path{}, Val: typed}},
	}}}
}

func fixtureGNMILoadNotification(t *testing.T, name string) *gnmipb.Notification {
	t.Helper()
	notification := &gnmipb.Notification{}
	require.NoError(t, protojson.Unmarshal(fixtureGNMIRead(t, name), notification))
	return notification
}

func fixtureGNMIRead(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "gnmi", name))
	require.NoError(t, err)
	return raw
}

func fixtureGNMIDecode(t *testing.T, notification *gnmipb.Notification) internalgnmi.DecodedNotification {
	t.Helper()
	decoded, stats, err := internalgnmi.DecodeNotification(fixtureGNMITarget, notification, fixtureGNMIReceipt)
	require.NoError(t, err)
	assert.Zero(t, stats.InvalidTimestamps)
	assert.Zero(t, stats.UnmappedValues)
	return decoded
}

func fixtureGNMIMap(
	tb testing.TB,
	runtime *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
	decoded internalgnmi.DecodedNotification,
	normalizeNX bool,
) (internalgnmi.DecodedNotification, []internalgnmi.MappedPoint, int) {
	tb.Helper()
	if normalizeNX {
		var err error
		decoded, err = runtime.normalizeNXNotification(decoded)
		require.NoError(tb, err)
	}
	normalizeGNMIStateValues(&decoded)
	var mapped []internalgnmi.MappedPoint
	unmapped := 0
	for i := range decoded.Updates {
		point := &decoded.Updates[i]
		metric, ok := stream.registry.Map(*point)
		if !ok {
			unmapped++
			continue
		}
		maps.Copy(metric.Attributes, stream.staticAttr[sharedGNMISeriesSourceKey(point.Series)])
		mapped = append(mapped, metric)
	}
	return decoded, mapped, unmapped
}

func fixtureGNMIMetric(t *testing.T, points []internalgnmi.MappedPoint, name string) internalgnmi.MappedPoint {
	t.Helper()
	var matches []internalgnmi.MappedPoint
	for i := range points {
		if points[i].Metric.Name == name {
			matches = append(matches, points[i])
		}
	}
	require.Len(t, matches, 1, "metric %q", name)
	return matches[0]
}

func fixtureGNMIMetricNames(points []internalgnmi.MappedPoint) []string {
	names := make([]string, 0, len(points))
	for i := range points {
		names = append(names, points[i].Metric.Name)
	}
	sort.Strings(names)
	return names
}

func fixtureGNMISensorID(elements []internalgnmi.PathElem) string {
	for _, element := range elements {
		if element.Name == "sensor" {
			return element.Keys["id"]
		}
	}
	return ""
}
