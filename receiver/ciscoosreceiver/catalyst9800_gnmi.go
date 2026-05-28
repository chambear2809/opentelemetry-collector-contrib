// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

type catalyst9800GNMIUpdateDecoder struct {
	target Catalyst9800TargetConfig
	health *catalyst9800Health
}

func (d catalyst9800GNMIUpdateDecoder) decodeNotification(notification *gnmi.Notification, transport string) pmetric.Metrics {
	ts := pcommon.NewTimestampFromTime(time.Now())
	if notification.GetTimestamp() > 0 {
		ts = pcommon.Timestamp(notification.GetTimestamp())
	}
	prefix := notification.GetPrefix()
	prefixText := gnmiPathToString(prefix)
	module := moduleFromGNMIPath(prefix)
	if module == "" {
		module = moduleFromYANGPath(prefixText)
	}
	md, sm := newCatalyst9800Metrics(catalyst9800MetricContext{
		targetName:     d.target.Name,
		endpoint:       d.target.Endpoint,
		platformFamily: d.target.PlatformFamily,
		transport:      transport,
		yangPath:       prefixText,
		yangModule:     module,
	})

	for _, deleted := range notification.GetDelete() {
		parts, attrs := pathPartsAndAttrs(prefix, deleted)
		if len(parts) == 0 {
			continue
		}
		catalyst9800NormalizePathAttrs(attrs)
		attrs["deleted"] = "true"
		appendCatalyst9800InfoMetric(sm, moduleFromParts(module, parts), parts, "deleted", ts, attrs)
	}

	for _, update := range notification.GetUpdate() {
		parts, attrs := pathPartsAndAttrs(prefix, update.GetPath())
		catalyst9800NormalizePathAttrs(attrs)
		updateModule := moduleFromParts(module, parts)
		if updateModule == "" {
			updateModule = moduleFromGNMIPath(update.GetPath())
		}
		d.decodeTypedValue(sm, updateModule, parts, update.GetVal(), ts, attrs)
	}

	appendCatalyst9800HealthMetrics(md, d.health, catalyst9800MetricContext{
		targetName:     d.target.Name,
		endpoint:       d.target.Endpoint,
		platformFamily: d.target.PlatformFamily,
		transport:      transport,
	}, ts)
	return md
}

func (d catalyst9800GNMIUpdateDecoder) decodeTypedValue(sm pmetric.ScopeMetrics, module string, parts []string, value *gnmi.TypedValue, ts pcommon.Timestamp, attrs map[string]string) {
	if value == nil {
		return
	}
	switch v := value.GetValue().(type) {
	case *gnmi.TypedValue_StringVal:
		appendCatalyst9800InfoMetric(sm, module, parts, v.StringVal, ts, attrs)
	case *gnmi.TypedValue_AsciiVal:
		appendCatalyst9800InfoMetric(sm, module, parts, v.AsciiVal, ts, attrs)
	case *gnmi.TypedValue_IntVal:
		appendCatalyst9800NumberMetric(sm, module, parts, float64(v.IntVal), ts, attrs)
	case *gnmi.TypedValue_UintVal:
		appendCatalyst9800NumberMetric(sm, module, parts, float64(v.UintVal), ts, attrs)
	case *gnmi.TypedValue_BoolVal:
		if v.BoolVal {
			appendCatalyst9800NumberMetric(sm, module, parts, 1, ts, attrs)
		} else {
			appendCatalyst9800NumberMetric(sm, module, parts, 0, ts, attrs)
		}
	case *gnmi.TypedValue_FloatVal:
		appendCatalyst9800NumberMetric(sm, module, parts, float64(v.FloatVal), ts, attrs)
	case *gnmi.TypedValue_DoubleVal:
		appendCatalyst9800NumberMetric(sm, module, parts, v.DoubleVal, ts, attrs)
	case *gnmi.TypedValue_DecimalVal:
		if v.DecimalVal != nil {
			appendCatalyst9800NumberMetric(sm, module, parts, float64(v.DecimalVal.Digits)/pow10(v.DecimalVal.Precision), ts, attrs)
		}
	case *gnmi.TypedValue_LeaflistVal:
		values := make([]string, 0, len(v.LeaflistVal.GetElement()))
		for _, elem := range v.LeaflistVal.GetElement() {
			values = append(values, scalarTypedValueString(elem))
		}
		appendCatalyst9800InfoMetric(sm, module, parts, strings.Join(values, ","), ts, attrs)
	case *gnmi.TypedValue_JsonIetfVal:
		d.decodeJSONValue(sm, module, parts, v.JsonIetfVal, ts, attrs)
	case *gnmi.TypedValue_JsonVal:
		d.decodeJSONValue(sm, module, parts, v.JsonVal, ts, attrs)
	case *gnmi.TypedValue_BytesVal:
		appendCatalyst9800InfoMetric(sm, module, append(parts, "bytes"), fmt.Sprintf("%x", v.BytesVal), ts, attrs)
	case *gnmi.TypedValue_ProtoBytes:
		if d.health != nil {
			d.health.addCompactGPBPayloads(1)
		}
		appendGaugeMetric(sm, "cisco.catalyst9800.receiver.compact_gpb_payloads", 1, ts, attrs)
	case *gnmi.TypedValue_AnyVal:
		appendCatalyst9800InfoMetric(sm, module, append(parts, "any"), v.AnyVal.String(), ts, attrs)
	default:
		appendCatalyst9800InfoMetric(sm, module, parts, value.String(), ts, attrs)
	}
}

func (d catalyst9800GNMIUpdateDecoder) decodeJSONValue(sm pmetric.ScopeMetrics, module string, parts []string, raw []byte, ts pcommon.Timestamp, attrs map[string]string) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		if d.health != nil {
			d.health.addDecodeErrors(1)
		}
		return
	}
	walkCatalyst9800JSON(sm, module, parts, value, ts, attrs)
}

func walkCatalyst9800JSON(sm pmetric.ScopeMetrics, module string, parts []string, value any, ts pcommon.Timestamp, attrs map[string]string) {
	switch v := value.(type) {
	case map[string]any:
		nextAttrs := cloneAttrs(attrs)
		extractJSONIdentityAttrs(v, nextAttrs)
		extractCatalyst9800JSONIdentityAttrs(v, nextAttrs)
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			nextModule, part := splitYANGQualifiedName(module, key)
			walkCatalyst9800JSON(sm, nextModule, append(parts, part), v[key], ts, nextAttrs)
		}
	case []any:
		if allJSONScalars(v) {
			appendCatalyst9800InfoMetric(sm, module, parts, valueToInfoString(v), ts, attrs)
			return
		}
		for _, elem := range v {
			walkCatalyst9800JSON(sm, module, parts, elem, ts, attrs)
		}
	default:
		if n, ok := typedNumericValue(v); ok {
			appendCatalyst9800NumberMetric(sm, module, parts, n, ts, attrs)
			return
		}
		if value := valueToInfoString(v); value != "" {
			appendCatalyst9800InfoMetric(sm, module, parts, value, ts, attrs)
		}
	}
}

func extractCatalyst9800JSONIdentityAttrs(value map[string]any, attrs map[string]string) {
	for key, attrName := range map[string]string{
		"wtp-mac":        "cisco.wlc.ap.mac",
		"ap-mac":         "cisco.wlc.ap.mac",
		"ap-name":        "cisco.wlc.ap.name",
		"slot-id":        "cisco.wlc.radio.slot",
		"radio-slot-id":  "cisco.wlc.radio.slot",
		"wlan-id":        "cisco.wlc.wlan.id",
		"ssid":           "cisco.wlc.ssid",
		"vap-ssid":       "cisco.wlc.ssid",
		"client-mac":     "cisco.wlc.client.mac",
		"ms-mac-address": "cisco.wlc.client.mac",
		"node-ip":        "cisco.wlc.mobility.node_ip",
		"ap-ip":          "host.ip",
		"ip-addr":        "host.ip",
		"serial-num":     "hw.serial_number",
		"serial-number":  "hw.serial_number",
	} {
		if raw, ok := value[key]; ok {
			if text := scalarJSONIdentity(raw); text != "" {
				attrs[attrName] = text
				attrs["cisco.yang.key."+sanitizeMetricSegment(key)] = text
			}
		}
	}
	catalyst9800NormalizePathAttrs(attrs)
}

func catalyst9800NormalizePathAttrs(attrs map[string]string) {
	lookup := newCatalyst9800AttrLookup(attrs)
	if value := lookup("wtp-mac", "wtp_mac", "ap-mac", "ap_mac"); value != "" {
		attrs["cisco.wlc.ap.mac"] = value
	}
	if value := lookup("ap-name", "ap_name"); value != "" {
		attrs["cisco.wlc.ap.name"] = value
	}
	if value := lookup("slot-id", "slot_id", "radio-slot-id", "radio_slot_id"); value != "" {
		attrs["cisco.wlc.radio.slot"] = value
	}
	if value := lookup("wlan-id", "wlan_id"); value != "" {
		attrs["cisco.wlc.wlan.id"] = value
	}
	if value := lookup("client-mac", "client_mac", "ms-mac-address", "ms_mac_address"); value != "" {
		attrs["cisco.wlc.client.mac"] = value
	}
	if value := lookup("node-ip", "node_ip"); value != "" {
		attrs["cisco.wlc.mobility.node_ip"] = value
	}
}
