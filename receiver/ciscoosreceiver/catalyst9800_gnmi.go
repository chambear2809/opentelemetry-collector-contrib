// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

type catalyst9800GNMIUpdateDecoder struct {
	target        Catalyst9800TargetConfig
	health        *catalyst9800Health
	maxDatapoints int
	limits        directGNMIDecodeLimits
}

func (d *catalyst9800GNMIUpdateDecoder) decodeNotification(notification *gnmi.Notification) pmetric.Metrics {
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
		transport:      catalyst9800TelemetryTransportDialIn,
		yangPath:       prefixText,
		yangModule:     module,
	})
	budget := newDirectGNMIDecodeBudget(d.limits, d.maxDatapoints)
	metrics := newIndexedMetricBuilder(sm, budget)

	for _, deleted := range notification.GetDelete() {
		if !budget.visitField(1) {
			break
		}
		parts, attrs, ok := pathPartsAndAttrs(prefix, deleted, budget)
		if !ok {
			if budget.exhausted {
				break
			}
			continue
		}
		if len(parts) == 0 {
			continue
		}
		catalyst9800NormalizePathAttrs(attrs)
		attrs["deleted"] = "true"
		deleteModule := moduleFromParts(module, parts)
		putNonEmpty(attrs, "cisco.yang.path", prefixText)
		putNonEmpty(attrs, "cisco.yang.module", deleteModule)
		appendCatalyst9800InfoMetricIndexed(metrics, deleteModule, parts, "deleted", ts, attrs)
	}

	for _, update := range notification.GetUpdate() {
		if !budget.visitField(1) {
			break
		}
		parts, attrs, ok := pathPartsAndAttrs(prefix, update.GetPath(), budget)
		if !ok {
			if budget.exhausted {
				break
			}
			continue
		}
		catalyst9800NormalizePathAttrs(attrs)
		updateModule := moduleFromParts(module, parts)
		if updateModule == "" {
			updateModule = moduleFromGNMIPath(update.GetPath())
		}
		putNonEmpty(attrs, "cisco.yang.path", prefixText)
		putNonEmpty(attrs, "cisco.yang.module", updateModule)
		depth := len(parts)
		if depth == 0 {
			depth = 1
		}
		d.decodeTypedValue(metrics, updateModule, parts, update.GetVal(), ts, attrs, budget, depth)
	}
	if d.health != nil {
		if budget.decodeErrors > 0 {
			d.health.addDecodeErrors(budget.decodeErrors)
		}
		if budget.dropped > 0 {
			d.health.addDroppedDatapoints(budget.dropped)
		}
	}

	appendCatalyst9800HealthMetrics(md, d.health, catalyst9800MetricContext{
		targetName:     d.target.Name,
		endpoint:       d.target.Endpoint,
		platformFamily: d.target.PlatformFamily,
		transport:      catalyst9800TelemetryTransportDialIn,
	}, ts)
	return md
}

func (d catalyst9800GNMIUpdateDecoder) decodeTypedValue(metrics *indexedMetricBuilder, module string, parts []string, value *gnmi.TypedValue, ts pcommon.Timestamp, attrs map[string]string, budget *directGNMIDecodeBudget, depth int) {
	if value == nil || value.GetValue() == nil {
		budget.addDecodeError()
		budget.drop(false)
		return
	}
	switch v := value.GetValue().(type) {
	case *gnmi.TypedValue_StringVal:
		appendCatalyst9800InfoMetricIndexed(metrics, module, parts, v.StringVal, ts, attrs)
	case *gnmi.TypedValue_AsciiVal:
		appendCatalyst9800InfoMetricIndexed(metrics, module, parts, v.AsciiVal, ts, attrs)
	case *gnmi.TypedValue_IntVal:
		appendCatalyst9800MetricNumberIndexed(metrics, module, parts, intMetricNumber(v.IntVal), ts, attrs)
	case *gnmi.TypedValue_UintVal:
		if v.UintVal <= math.MaxInt64 {
			appendCatalyst9800MetricNumberIndexed(metrics, module, parts, intMetricNumber(int64(v.UintVal)), ts, attrs)
		} else {
			overflowAttrs := cloneAttrs(attrs)
			overflowAttrs["cisco.value.type"] = "uint64"
			overflowAttrs["cisco.value.out_of_range"] = "true"
			appendCatalyst9800InfoMetricIndexed(metrics, module, parts, strconv.FormatUint(v.UintVal, 10), ts, overflowAttrs)
		}
	case *gnmi.TypedValue_BoolVal:
		if v.BoolVal {
			appendCatalyst9800MetricNumberIndexed(metrics, module, parts, intMetricNumber(1), ts, attrs)
		} else {
			appendCatalyst9800MetricNumberIndexed(metrics, module, parts, intMetricNumber(0), ts, attrs)
		}
	case *gnmi.TypedValue_FloatVal:
		floatValue := v.FloatVal //nolint:staticcheck // Deprecated scalar remains required for older gNMI producers.
		appendCatalyst9800MetricNumberIndexed(metrics, module, parts, doubleMetricNumber(float64(floatValue)), ts, attrs)
	case *gnmi.TypedValue_DoubleVal:
		appendCatalyst9800MetricNumberIndexed(metrics, module, parts, doubleMetricNumber(v.DoubleVal), ts, attrs)
	case *gnmi.TypedValue_DecimalVal:
		decimalValue := v.DecimalVal //nolint:staticcheck // Deprecated scalar remains required for older gNMI producers.
		if decimalValue != nil {
			appendCatalyst9800MetricNumberIndexed(metrics, module, parts, doubleMetricNumber(float64(decimalValue.Digits)/pow10(decimalValue.Precision)), ts, attrs)
		} else {
			budget.addDecodeError()
			budget.drop(false)
		}
	case *gnmi.TypedValue_LeaflistVal:
		if v.LeaflistVal == nil {
			budget.addDecodeError()
			budget.drop(false)
			return
		}
		elements := v.LeaflistVal.GetElement()
		if !budget.consumeChildFields(len(elements), depth+1) {
			return
		}
		if len(elements)-1 > budget.limits.maxAttributeValueBytes {
			budget.drop(false)
			return
		}
		values := make([]string, 0, len(elements))
		joinedBytes := 0
		for _, elem := range elements {
			value := scalarTypedValueString(elem)
			separatorBytes := 0
			if len(values) > 0 {
				separatorBytes = 1
			}
			if len(value)+separatorBytes > budget.limits.maxAttributeValueBytes-joinedBytes {
				budget.drop(false)
				return
			}
			joinedBytes += len(value) + separatorBytes
			values = append(values, value)
		}
		appendCatalyst9800InfoMetricIndexed(metrics, module, parts, strings.Join(values, ","), ts, attrs)
	case *gnmi.TypedValue_JsonIetfVal:
		d.decodeJSONValue(metrics, module, parts, v.JsonIetfVal, ts, attrs, budget, depth+1)
	case *gnmi.TypedValue_JsonVal:
		d.decodeJSONValue(metrics, module, parts, v.JsonVal, ts, attrs, budget, depth+1)
	case *gnmi.TypedValue_BytesVal:
		if len(v.BytesVal) > budget.limits.maxAttributeValueBytes/2 {
			budget.drop(false)
			return
		}
		appendCatalyst9800InfoMetricIndexed(metrics, module, append(parts, "bytes"), fmt.Sprintf("%x", v.BytesVal), ts, attrs)
	case *gnmi.TypedValue_ProtoBytes:
		if d.health != nil {
			d.health.addCompactGPBPayloads(1)
		}
		metrics.appendNumber("cisco.catalyst9800.receiver.compact_gpb_payloads", pmetric.MetricTypeGauge, doubleMetricNumber(1), ts, attrs)
	case *gnmi.TypedValue_AnyVal:
		if v.AnyVal == nil {
			budget.addDecodeError()
			budget.drop(false)
			return
		}
		if len(v.AnyVal.GetTypeUrl())+len(v.AnyVal.GetValue()) > budget.limits.maxAttributeValueBytes {
			budget.drop(false)
			return
		}
		appendCatalyst9800InfoMetricIndexed(metrics, module, append(parts, "any"), v.AnyVal.String(), ts, attrs)
	default:
		appendCatalyst9800InfoMetricIndexed(metrics, module, parts, value.String(), ts, attrs)
	}
}

func (catalyst9800GNMIUpdateDecoder) decodeJSONValue(metrics *indexedMetricBuilder, module string, parts []string, raw []byte, ts pcommon.Timestamp, attrs map[string]string, budget *directGNMIDecodeBudget, depth int) {
	if len(raw) > directGNMIHardMaxPayloadBytes {
		budget.drop(true)
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		budget.addDecodeError()
		budget.drop(false)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		budget.addDecodeError()
		budget.drop(false)
		return
	}
	walkCatalyst9800JSON(metrics, module, parts, value, ts, attrs, budget, depth)
}

func walkCatalyst9800JSON(metrics *indexedMetricBuilder, module string, parts []string, value any, ts pcommon.Timestamp, attrs map[string]string, budget *directGNMIDecodeBudget, depth int) bool {
	if !budget.visitField(depth) {
		return false
	}
	switch v := value.(type) {
	case map[string]any:
		if !budget.ensureChildFieldCapacity(len(v), depth+1) {
			return false
		}
		nextAttrs := cloneAttrs(attrs)
		if !extractJSONIdentityAttrs(v, nextAttrs, budget) || !extractCatalyst9800JSONIdentityAttrs(v, nextAttrs, budget) {
			return !budget.exhausted
		}
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			nextModule, part := splitYANGQualifiedName(module, key)
			if !walkCatalyst9800JSON(metrics, nextModule, append(parts, part), v[key], ts, nextAttrs, budget, depth+1) && budget.exhausted {
				return false
			}
		}
	case []any:
		if !budget.ensureChildFieldCapacity(len(v), depth+1) {
			return false
		}
		if allJSONScalars(v) {
			if !budget.consumeChildFields(len(v), depth+1) {
				return false
			}
			appendCatalyst9800InfoMetricIndexed(metrics, module, parts, valueToInfoString(v), ts, attrs)
			return !budget.exhausted
		}
		for _, elem := range v {
			if !walkCatalyst9800JSON(metrics, module, parts, elem, ts, attrs, budget, depth+1) && budget.exhausted {
				return false
			}
		}
	default:
		if n, ok := typedNumericValue(v); ok {
			appendCatalyst9800MetricNumberIndexed(metrics, module, parts, n, ts, attrs)
			return !budget.exhausted
		}
		if value := valueToInfoString(v); value != "" {
			appendCatalyst9800InfoMetricIndexed(metrics, module, parts, value, ts, attrs)
		}
	}
	return !budget.exhausted
}

func extractCatalyst9800JSONIdentityAttrs(value map[string]any, attrs map[string]string, budget *directGNMIDecodeBudget) bool {
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
				if len(text) > budget.limits.maxAttributeValueBytes {
					budget.drop(false)
					return false
				}
				attrs[attrName] = text
				attrs["cisco.yang.key."+sanitizeMetricSegment(key)] = text
			}
		}
	}
	catalyst9800NormalizePathAttrs(attrs)
	return true
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
