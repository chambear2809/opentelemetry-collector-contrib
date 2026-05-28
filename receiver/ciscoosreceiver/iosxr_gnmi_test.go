// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

func TestIOSXRGNMIDecoderScalarsJSONLeaflistsAndDeletes(t *testing.T) {
	prefix := mustParseIOSXRPath(t, "openconfig-interfaces:interfaces/interface[name=HundredGigE0/0/0/0]/state")
	health := &iosXRHealth{}
	decoder := iosXRGNMIUpdateDecoder{
		target: IOSXRTargetConfig{
			ClientConfig:   mustIOSXRClientConfig("192.0.2.10:57400"),
			Name:           "core-asr9k-1",
			PlatformFamily: "ASR 9000",
		},
		health: health,
	}

	md := decoder.decodeNotification(&gnmi.Notification{
		Timestamp: time.Unix(1700000000, 0).UnixNano(),
		Prefix:    prefix,
		Delete: []*gnmi.Path{
			mustParseIOSXRPath(t, "oper-status"),
		},
		Update: []*gnmi.Update{
			{
				Path: mustParseIOSXRPath(t, "counters/in-octets"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_UintVal{UintVal: 42}},
			},
			{
				Path: mustParseIOSXRPath(t, "admin-status"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_StringVal{StringVal: "UP"}},
			},
			{
				Path: mustParseIOSXRPath(t, "enabled"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_BoolVal{BoolVal: true}},
			},
			{
				Path: mustParseIOSXRPath(t, "labels"),
				Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_LeaflistVal{LeaflistVal: &gnmi.ScalarArray{Element: []*gnmi.TypedValue{
					{Value: &gnmi.TypedValue_StringVal{StringVal: "core"}},
					{Value: &gnmi.TypedValue_StringVal{StringVal: "wan"}},
				}}}},
			},
			{
				Path: mustParseIOSXRPath(t, "json"),
				Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{
					"openconfig-interfaces:description": "uplink",
					"mtu": 9216,
					"counters": {"out-octets": 84},
					"openconfig-if-ip:ipv4": {"addresses": {"address": [{"ip": "192.0.2.1"}]}}
				}`)}},
			},
			{
				Path: mustParseIOSXRPath(t, "compact"),
				Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_ProtoBytes{ProtoBytes: []byte{0x01, 0x02}}},
			},
		},
	}, iosXRTelemetryTransportDialIn)

	assertMetricExists(t, md, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.counters.in_octets")
	assertMetricExists(t, md, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.enabled")
	assertInfoMetricValue(t, md, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.admin_status_info", "UP")
	assertInfoMetricValue(t, md, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.labels_info", "core,wan")
	assertInfoMetricValue(t, md, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.oper_status_info", "deleted")
	assertInfoMetricValue(t, md, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.json.description_info", "uplink")
	assertMetricExists(t, md, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.json.mtu")
	assertMetricExists(t, md, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.json.counters.out_octets")
	assertInfoMetricValue(t, md, "cisco.iosxr.yang.openconfig_if_ip.interfaces.interface.state.json.ipv4.addresses.address.ip_info", "192.0.2.1")
	assertMetricExists(t, md, "cisco.iosxr.receiver.compact_gpb_payloads")

	metric := mustFindIOSXRMetric(t, md, "cisco.iosxr.yang.openconfig_interfaces.interfaces.interface.state.counters.in_octets")
	require.Equal(t, pmetric.MetricTypeSum, metric.Type())
	dp := metric.Sum().DataPoints().At(0)
	assert.Equal(t, 42.0, dp.DoubleValue())
	iface, ok := dp.Attributes().Get("network.interface.name")
	require.True(t, ok)
	assert.Equal(t, "HundredGigE0/0/0/0", iface.AsString())

	resourceAttrs := md.ResourceMetrics().At(0).Resource().Attributes()
	assert.Equal(t, "core-asr9k-1", attrValue(t, resourceAttrs, "host.name"))
	assert.Equal(t, "192.0.2.10", attrValue(t, resourceAttrs, "host.ip"))
	assert.Equal(t, "ios_xr", attrValue(t, resourceAttrs, "cisco.os.name"))
	assert.Equal(t, "gnmi_dial_in", attrValue(t, resourceAttrs, "cisco.telemetry.transport"))
	assert.Equal(t, "openconfig-interfaces", attrValue(t, resourceAttrs, "cisco.yang.module"))
	assert.Equal(t, int64(1), health.snapshot().compactGPBPayloads)
}

func TestIOSXRGNMIDecoderInvalidJSONCountsDecodeErrors(t *testing.T) {
	health := &iosXRHealth{}
	decoder := iosXRGNMIUpdateDecoder{target: IOSXRTargetConfig{Name: "xr-1"}, health: health}
	md := decoder.decodeNotification(&gnmi.Notification{
		Prefix: mustParseIOSXRPath(t, "openconfig-system:system/state"),
		Update: []*gnmi.Update{{
			Path: mustParseIOSXRPath(t, "bad-json"),
			Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{"unterminated"`)}},
		}},
	}, iosXRTelemetryTransportDialIn)

	assert.Equal(t, int64(1), health.snapshot().decodeErrors)
	assertMetricExists(t, md, "cisco.iosxr.receiver.decode_errors")
}

func mustParseIOSXRPath(t *testing.T, raw string) *gnmi.Path {
	t.Helper()
	path, err := parseGNMIPath(raw)
	require.NoError(t, err)
	return path
}

func assertMetricExists(t *testing.T, md pmetric.Metrics, name string) {
	t.Helper()
	_ = mustFindIOSXRMetric(t, md, name)
}

func assertInfoMetricValue(t *testing.T, md pmetric.Metrics, name, value string) {
	t.Helper()
	metric := mustFindIOSXRMetric(t, md, name)
	require.Equal(t, pmetric.MetricTypeGauge, metric.Type())
	require.Equal(t, 1, metric.Gauge().DataPoints().Len())
	got, ok := metric.Gauge().DataPoints().At(0).Attributes().Get("value")
	require.True(t, ok)
	assert.Equal(t, value, got.AsString())
}

func mustFindIOSXRMetric(t *testing.T, md pmetric.Metrics, name string) pmetric.Metric {
	t.Helper()
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		sms := md.ResourceMetrics().At(i).ScopeMetrics()
		for j := 0; j < sms.Len(); j++ {
			metrics := sms.At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				if metrics.At(k).Name() == name {
					return metrics.At(k)
				}
			}
		}
	}
	require.FailNowf(t, "metric not found", "missing metric %s", name)
	return pmetric.Metric{}
}

func attrValue(t *testing.T, attrs pcommon.Map, key string) string {
	t.Helper()
	value, ok := attrs.Get(key)
	require.True(t, ok, "missing attribute %s", key)
	return value.AsString()
}

func mustIOSXRClientConfig(endpoint string) configgrpc.ClientConfig {
	cfg := configgrpc.NewDefaultClientConfig()
	cfg.Endpoint = endpoint
	cfg.TLS.Insecure = true
	return cfg
}
