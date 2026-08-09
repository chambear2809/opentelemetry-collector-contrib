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

func runtimeTestCatalystSwitchModelData(names ...string) []*gnmipb.ModelData {
	models := make([]*gnmipb.ModelData, 0, len(names))
	for _, name := range names {
		contract, ok := iosXE17181ModelDataContract[name]
		if !ok || len(contract.Versions) == 0 {
			models = append(models, &gnmipb.ModelData{Name: name})
			continue
		}
		models = append(models, &gnmipb.ModelData{
			Name:         name,
			Organization: contract.Organization,
			Version:      contract.Versions[0],
		})
	}
	return models
}

func TestGNMIFixtureIOSXECatalystSwitchSystem(t *testing.T) {
	runtime := fixtureGNMIRuntime(t, gnmiPlatformIOSXE, builtinGNMIProfileSystem)
	assert.Equal(t, gnmiProductCatalyst9300, runtime.contract.Product)
	stream := fixtureGNMIStream(t, runtime, builtinGNMIOriginRFC7951)
	response := fixtureGNMIJSONResponse(t, "ios_xe_switch_system.json", builtinGNMIOriginRFC7951, nil, true)

	decoded := fixtureGNMIDecode(t, response.GetUpdate())
	_, mapped, _ := fixtureGNMIMap(t, runtime, stream, decoded, false)
	require.Len(t, mapped, 3)
	assert.ElementsMatch(t, []string{
		"system.cpu.utilization",
		"system.memory.utilization",
		"system.memory.utilization",
	}, fixtureGNMIMetricNames(mapped))
	assert.InDelta(t, .37, fixtureGNMIMetric(t, mapped, "system.cpu.utilization").DoubleValue, 0.0001)

	memory := fixtureGNMIMetrics(mapped, "system.memory.utilization")
	require.Len(t, memory, 2)
	memoryByFRU := make(map[string]internalgnmi.MappedPoint, len(memory))
	for _, point := range memory {
		memoryByFRU[point.Attributes["cisco.location.fru"]] = point
		assert.Equal(t, "1", point.Attributes["cisco.location.chassis"])
		assert.Equal(t, "0", point.Attributes["cisco.location.bay"])
	}
	assert.InDelta(t, .42, memoryByFRU["fru-rp"].DoubleValue, 0.0001)
	assert.Equal(t, "0", memoryByFRU["fru-rp"].Attributes["cisco.location.slot"])
	assert.InDelta(t, .55, memoryByFRU["fru-fp"].DoubleValue, 0.0001)
	assert.Equal(t, "1", memoryByFRU["fru-fp"].Attributes["cisco.location.slot"])
}

func TestGNMIFixtureIOSXECatalystSwitchInterfaces(t *testing.T) {
	runtime := fixtureGNMIRuntime(t, gnmiPlatformIOSXE, builtinGNMIProfileInterfaces)
	assert.Equal(t, gnmiProductCatalyst9300, runtime.contract.Product)
	stream := fixtureGNMIStream(t, runtime, builtinGNMIOriginRFC7951)
	response := fixtureGNMIJSONResponse(t, "ios_xe_switch_interfaces.json", builtinGNMIOriginRFC7951, nil, true)

	decoded := fixtureGNMIDecode(t, response.GetUpdate())
	_, mapped, _ := fixtureGNMIMap(t, runtime, stream, decoded, false)
	require.Len(t, mapped, 28)

	oper := fixtureGNMIMetrics(mapped, "system.network.interface.status")
	admin := fixtureGNMIMetrics(mapped, "cisco.interface.admin.status")
	require.Len(t, oper, 2)
	require.Len(t, admin, 2)
	assert.Equal(t, int64(1), fixtureGNMIInterfaceMetric(t, oper, "GigabitEthernet1/0/1").IntValue)
	down := fixtureGNMIInterfaceMetric(t, oper, "GigabitEthernet1/0/2")
	assert.Equal(t, int64(0), down.IntValue)
	assert.Equal(t, "Interface operational status (1 = up, 0 = not up)", down.Metric.Description)
	assert.Equal(t, int64(1), fixtureGNMIInterfaceMetric(t, admin, "GigabitEthernet1/0/1").IntValue)
	notEnabled := fixtureGNMIInterfaceMetric(t, admin, "GigabitEthernet1/0/2")
	assert.Equal(t, int64(0), notEnabled.IntValue)
	assert.Equal(t, "Cisco interface administrative status (1 = administratively enabled, 0 = not administratively enabled)", notEnabled.Metric.Description)

	ioPoints := fixtureGNMIMetrics(mapped, "system.network.io")
	require.Len(t, ioPoints, 4)
	var receive internalgnmi.MappedPoint
	for _, point := range ioPoints {
		if point.Attributes["network.interface.name"] == "GigabitEthernet1/0/1" &&
			point.Attributes["network.io.direction"] == "receive" {
			receive = point
		}
	}
	assert.Equal(t, int64(9007199254740993), receive.IntValue, "RFC7951 uint64 strings must retain integer precision")
}

func TestGNMIFixtureIOSXERFC7951DOM(t *testing.T) {
	runtime := fixtureGNMIRuntime(t, gnmiPlatformIOSXE, builtinGNMIProfileOptics)
	assert.Equal(t, gnmiProductCatalyst9300, runtime.contract.Product)
	stream := fixtureGNMIStream(t, runtime, builtinGNMIOriginRFC7951)
	response := fixtureGNMIJSONResponse(t, "ios_xe_rfc7951_dom.json", builtinGNMIOriginRFC7951, nil, true)

	decoded := fixtureGNMIDecode(t, response.GetUpdate(), stream.JSONListKeys)
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
		assert.Equal(t, "true", point.Attributes["cisco.optics.experimental"])
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
	assert.Equal(t, "dB{mW}", rxPower.Metric.Unit)
	assert.InDelta(t, -2.15, rxPower.DoubleValue, 0.0001)
	txPower := fixtureGNMIMetric(t, mapped, "cisco.optics.tx_power")
	assert.Equal(t, "dB{mW}", txPower.Metric.Unit)
	assert.InDelta(t, -1.05, txPower.DoubleValue, 0.0001)
	present := fixtureGNMIMetric(t, mapped, "cisco.optics.present")
	assert.Equal(t, "1", present.Metric.Unit)
	assert.Equal(t, int64(1), present.IntValue)
	assert.NotContains(t, present.Attributes, "cisco.optics.sensor")
}

func TestGNMIFixtureIOSXR2441NativeOptics(t *testing.T) {
	runtime := fixtureGNMIRuntime(t, gnmiPlatformIOSXR, builtinGNMIProfileOptics)
	opticsOrigin := "Cisco-IOS-XR-controller-optics-oper"
	opticsStream := fixtureGNMIStream(t, runtime, opticsOrigin)
	response := fixtureGNMIJSONResponse(t, "ios_xr_native_optics.json", opticsOrigin, nil, true)

	decoded := fixtureGNMIDecode(t, response.GetUpdate(), opticsStream.JSONListKeys)
	_, mapped, _ := fixtureGNMIMap(t, runtime, opticsStream, decoded, false)
	assert.ElementsMatch(t, []string{
		"cisco.optics.present",
		"cisco.optics.rx_power",
		"cisco.optics.temperature",
		"cisco.optics.tx_power",
		"cisco.optics.voltage",
	}, fixtureGNMIMetricNames(mapped))

	for _, point := range mapped {
		assert.Equal(t, "HundredGigE0/0/0/0", point.Attributes["network.interface.name"])
		assert.Equal(t, "dom", point.Attributes["cisco.optics.profile"])
		assert.Equal(t, "true", point.Attributes["cisco.optics.experimental"])
	}
	assert.InDelta(t, 44.25, fixtureGNMIMetric(t, mapped, "cisco.optics.temperature").DoubleValue, 0.0001)
	assert.InDelta(t, 3.31, fixtureGNMIMetric(t, mapped, "cisco.optics.voltage").DoubleValue, 0.0001)
	assert.InDelta(t, -3.10, fixtureGNMIMetric(t, mapped, "cisco.optics.rx_power").DoubleValue, 0.0001)
	assert.InDelta(t, -1.05, fixtureGNMIMetric(t, mapped, "cisco.optics.tx_power").DoubleValue, 0.0001)
	assert.Equal(t, int64(1), fixtureGNMIMetric(t, mapped, "cisco.optics.present").IntValue)

	laneDecoded := fixtureGNMIDecode(t, fixtureGNMILoadNotification(t, "ios_xr_lane_scalar.json"))
	_, laneMapped, _ := fixtureGNMIMap(t, runtime, opticsStream, laneDecoded, false)
	assert.ElementsMatch(t, []string{
		"cisco.optics.laser_bias_current",
		"cisco.optics.rx_power",
		"cisco.optics.tx_power",
	}, fixtureGNMIMetricNames(laneMapped))
	for _, point := range laneMapped {
		assert.Equal(t, "HundredGigE0/0/0/0", point.Attributes["network.interface.name"])
		assert.Equal(t, "0", point.Attributes["cisco.optics.lane"])
		assert.Equal(t, "true", point.Attributes["cisco.optics.experimental"])
	}
	assert.InDelta(t, 6.40, fixtureGNMIMetric(t, laneMapped, "cisco.optics.laser_bias_current").DoubleValue, 0.0001)
	assert.InDelta(t, -2.15, fixtureGNMIMetric(t, laneMapped, "cisco.optics.rx_power").DoubleValue, 0.0001)
	assert.InDelta(t, -1.05, fixtureGNMIMetric(t, laneMapped, "cisco.optics.tx_power").DoubleValue, 0.0001)
}

func TestGNMIFixtureNXDMESensorAllowlist(t *testing.T) {
	runtime := fixtureGNMIRuntime(t, gnmiPlatformNXOS, builtinGNMIProfileOptics)
	stream := fixtureGNMIStream(t, runtime, builtinGNMIOriginDME)
	response := fixtureGNMIJSONResponse(t, "nx_dme_sensors.json", builtinGNMIOriginDME, []string{"sys", "intf"}, false)

	decoded := fixtureGNMIDecode(t, response.GetUpdate(), stream.JSONListKeys)
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
	assert.Equal(t, "true", temperature.Attributes["cisco.optics.experimental"])
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
	product, version := gnmiProductCatalyst9300, "17.18.1"
	switch platform {
	case gnmiPlatformIOSXR:
		product, version = gnmiProductASR9000, "24.4.1"
	case gnmiPlatformNXOS:
		product, version = gnmiProductNexus9000, "10.6(1)"
	}
	if profile == builtinGNMIProfileCatalyst9800Wireless {
		product = gnmiProductCatalyst9800
	}
	runtime, err := newSharedGNMITargetRuntime(GNMITargetConfig{
		Name: fixtureGNMITarget, Product: product, SoftwareVersion: version, MaxStreams: 8, Profiles: profiles,
	}, cache)
	require.NoError(t, err)
	return runtime
}

func fixtureGNMIStream(t *testing.T, runtime *sharedGNMITargetRuntime, origin string) sharedGNMIRuntimeStream {
	t.Helper()
	for i := range runtime.streams {
		for pathIndex := range runtime.streams[i].Paths {
			if runtime.streams[i].Paths[pathIndex].Origin == origin {
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

func fixtureGNMIDecode(t *testing.T, notification *gnmipb.Notification, schemas ...*internalgnmi.JSONListKeySchema) internalgnmi.DecodedNotification {
	t.Helper()
	var schema *internalgnmi.JSONListKeySchema
	if len(schemas) > 0 {
		schema = schemas[0]
	}
	decoded, stats, err := internalgnmi.DecodeNotificationWithSchema(fixtureGNMITarget, notification, fixtureGNMIReceipt, schema)
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

func fixtureGNMIMetrics(points []internalgnmi.MappedPoint, name string) []internalgnmi.MappedPoint {
	var matches []internalgnmi.MappedPoint
	for i := range points {
		if points[i].Metric.Name == name {
			matches = append(matches, points[i])
		}
	}
	return matches
}

func fixtureGNMIInterfaceMetric(t *testing.T, points []internalgnmi.MappedPoint, interfaceName string) internalgnmi.MappedPoint {
	t.Helper()
	var matches []internalgnmi.MappedPoint
	for i := range points {
		if points[i].Attributes["network.interface.name"] == interfaceName {
			matches = append(matches, points[i])
		}
	}
	require.Len(t, matches, 1, "interface %q", interfaceName)
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
