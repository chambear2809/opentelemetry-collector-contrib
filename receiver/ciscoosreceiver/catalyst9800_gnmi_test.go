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
	"go.opentelemetry.io/collector/pdata/pmetric"
)

func TestCatalyst9800GNMIDecoderWirelessAliasesAndRawMetrics(t *testing.T) {
	decoder := catalyst9800GNMIUpdateDecoder{
		target: Catalyst9800TargetConfig{
			ClientConfig:   mustCatalyst9800ClientConfig("192.0.2.20:57400"),
			Name:           "wlc-9800-1",
			PlatformFamily: "catalyst_9800",
		},
		health: &catalyst9800Health{},
	}

	md := pmetric.NewMetrics()
	for _, notification := range []*gnmi.Notification{
		catalyst9800JSONNotification(t, "wireless-ap-global-oper:ap-global-oper-data/ap-join-stats[wtp-mac=AA:BB:CC:DD:EE:FF]", "ap-join-info", `{
			"ap-name": "AP-01",
			"is-joined": true,
			"last-join-failure-type": "max-retries",
			"disconnects": 2
		}`),
		catalyst9800JSONNotification(t, "wireless-access-point-oper:access-point-oper-data/capwap-data[wtp-mac=AA:BB:CC:DD:EE:FF]", "state", `{
			"ap-operation-state": "registered"
		}`),
		catalyst9800JSONNotification(t, "wireless-rrm-oper:rrm-oper-data/rrm-measurement[wtp-mac=AA:BB:CC:DD:EE:FF][radio-slot-id=0]", "measurement", `{
			"cca-util-percentage": 62,
			"noise": -92,
			"stations": 17,
			"chan-changes": 3
		}`),
		catalyst9800JSONNotification(t, "wireless-access-point-oper:access-point-oper-data/ssid-counters[wtp-mac=AA:BB:CC:DD:EE:FF][slot-id=0][wlan-id=42]", "counters", `{
			"vap-ssid": "Corp",
			"num-assoc-clients": 12,
			"bss-chan-util": 55,
			"tx-bytes-data": 1000,
			"rx-bytes-data": 2000,
			"tx-retries-data": 7,
			"noise-floor": -90
		}`),
		catalyst9800JSONNotification(t, "wireless-client-oper:client-oper-data/common-oper-data[client-mac=00:11:22:33:44:55]", "state", `{
			"co-state": "run"
		}`),
		catalyst9800JSONNotification(t, "wireless-client-oper:client-oper-data/dot11-oper-data[ms-mac-address=00:11:22:33:44:55]", "roam", `{
			"vap-ssid": "Corp",
			"dot11-roam-type": "l3",
			"roam-failure-count": 1
		}`),
		catalyst9800JSONNotification(t, "wireless-client-oper:client-oper-data/traffic-stats[ms-mac-address=00:11:22:33:44:55]", "stats", `{
			"most-recent-rssi": -51,
			"most-recent-snr": 38,
			"bytes-rx": 1234,
			"pkts-tx": 10
		}`),
		catalyst9800JSONNotification(t, "wireless-client-oper:client-oper-data/exclusion-data[client-mac=00:11:22:33:44:55]", "auth", `{
			"exclude-reason": "aaa-timeout"
		}`),
		catalyst9800JSONNotification(t, "wireless-mobility-oper:mobility-oper-data/mobility-node-data[node-ip=198.51.100.10]", "peer", `{
			"peer-status": "up",
			"l2-roam-cnt": 8,
			"l3-roam-cnt": 4,
			"handoff-sent-ok": 3,
			"handoff-sent-fail": 1
		}`),
		catalyst9800JSONNotification(t, "ha-ios-xe-oper:ha-oper-data/ha-infra", "state", `{
			"ha-state": "active",
			"ha-enabled": true,
			"switchover-count": 2,
			"standby-failure-count": 1
		}`),
		catalyst9800JSONNotification(t, "aaa-ios-xe-oper:aaa-data/aaa-radius-global-stats", "radius", `{
			"access-accepts": 50,
			"access-rejects": 5,
			"authen-timeouts": 2,
			"authen-avg-response-delay": 12,
			"authen-max-response-delay": 55,
			"authen-bad-authenticators": 1
		}`),
		catalyst9800JSONNotification(t, "process-cpu-ios-xe-oper:cpu-usage/cpu-utilization", "cpu", `{
			"five-seconds": 22
		}`),
	} {
		decoder.decodeNotification(notification, catalyst9800TelemetryTransportDialIn).ResourceMetrics().MoveAndAppendTo(md.ResourceMetrics())
	}

	assertMetricExists(t, md, "cisco.catalyst9800.yang.wireless_ap_global_oper.ap_global_oper_data.ap_join_stats.ap_join_info.is_joined")
	for _, name := range []string{
		"cisco.wlc.ap.join.status",
		"cisco.wlc.ap.join.failure",
		"cisco.wlc.ap.disconnect",
		"cisco.wlc.ap.capwap.state",
		"cisco.wlc.rf.channel.utilization",
		"cisco.wlc.rf.noise_floor",
		"cisco.wlc.rf.client.count",
		"cisco.wlc.rf.channel.change.count",
		"cisco.wlc.ssid.client.count",
		"cisco.wlc.ssid.channel.utilization",
		"cisco.wlc.ssid.network.io",
		"cisco.wlc.ssid.retry.count",
		"cisco.wlc.client.connection.state",
		"cisco.wlc.client.auth.failure",
		"cisco.wlc.client.roam.count",
		"cisco.wlc.client.roam.failure.count",
		"cisco.wlc.client.wireless.rssi",
		"cisco.wlc.client.wireless.snr",
		"cisco.wlc.mobility.peer.status",
		"cisco.wlc.mobility.roam.count",
		"cisco.wlc.mobility.handoff.count",
		"cisco.wlc.mobility.handoff.failure.count",
		"cisco.wlc.ha.state",
		"cisco.wlc.ha.enabled",
		"cisco.wlc.ha.switchover.count",
		"cisco.wlc.ha.standby.failure.count",
		"cisco.wlc.auth.radius.access.accept.count",
		"cisco.wlc.auth.radius.access.reject.count",
		"cisco.wlc.auth.radius.timeout.count",
		"cisco.wlc.auth.radius.response_delay.avg",
		"cisco.wlc.auth.radius.response_delay.max",
		"cisco.wlc.auth.radius.bad_authenticator.count",
		"cisco.wlc.controller.cpu.utilization",
	} {
		assertMetricExists(t, md, name)
	}

	join := mustFindIOSXRMetric(t, md, "cisco.wlc.ap.join.status")
	require.Equal(t, pmetric.MetricTypeGauge, join.Type())
	dp := join.Gauge().DataPoints().At(0)
	assert.Equal(t, 1.0, dp.DoubleValue())
	assert.Equal(t, "AA:BB:CC:DD:EE:FF", attrValue(t, dp.Attributes(), "cisco.wlc.ap.mac"))

	resourceAttrs := md.ResourceMetrics().At(0).Resource().Attributes()
	assert.Equal(t, "wlc-9800-1", attrValue(t, resourceAttrs, "host.name"))
	assert.Equal(t, "192.0.2.20", attrValue(t, resourceAttrs, "host.ip"))
	assert.Equal(t, "ios_xe", attrValue(t, resourceAttrs, "cisco.os.name"))
	assert.Equal(t, "catalyst_9800", attrValue(t, resourceAttrs, "cisco.platform.family"))
	assert.Equal(t, "gnmi_dial_in", attrValue(t, resourceAttrs, "cisco.telemetry.transport"))
}

func TestCatalyst9800GNMIDecoderInvalidJSONCountsDecodeErrors(t *testing.T) {
	health := &catalyst9800Health{}
	decoder := catalyst9800GNMIUpdateDecoder{target: Catalyst9800TargetConfig{Name: "wlc-1"}, health: health}
	md := decoder.decodeNotification(&gnmi.Notification{
		Prefix: mustParseIOSXRPath(t, "wireless-access-point-oper:access-point-oper-data/ssid-counters"),
		Update: []*gnmi.Update{{
			Path: mustParseIOSXRPath(t, "bad-json"),
			Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{"unterminated"`)}},
		}},
	}, catalyst9800TelemetryTransportDialIn)

	assert.Equal(t, int64(1), health.snapshot().decodeErrors)
	assertMetricExists(t, md, "cisco.catalyst9800.receiver.decode_errors")
}

func catalyst9800JSONNotification(t *testing.T, prefix, updatePath, body string) *gnmi.Notification {
	t.Helper()
	return &gnmi.Notification{
		Timestamp: time.Unix(1700000000, 0).UnixNano(),
		Prefix:    mustParseIOSXRPath(t, prefix),
		Update: []*gnmi.Update{{
			Path: mustParseIOSXRPath(t, updatePath),
			Val:  &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(body)}},
		}},
	}
}

func mustCatalyst9800ClientConfig(endpoint string) configgrpc.ClientConfig {
	cfg := configgrpc.NewDefaultClientConfig()
	cfg.Endpoint = endpoint
	cfg.TLS.Insecure = true
	return cfg
}
