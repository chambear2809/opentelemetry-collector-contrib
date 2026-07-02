// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

type iosXRGNMIUpdateDecoder struct {
	target IOSXRTargetConfig
	health *iosXRHealth
}

func (d iosXRGNMIUpdateDecoder) decodeNotification(notification *gnmi.Notification, transport string) pmetric.Metrics {
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
	md, sm := newIOSXRMetrics(iosXRMetricContext{
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
		attrs["deleted"] = "true"
		appendIOSXRInfoMetric(sm, moduleFromParts(module, parts), parts, "deleted", ts, attrs)
	}

	for _, update := range notification.GetUpdate() {
		parts, attrs := pathPartsAndAttrs(prefix, update.GetPath())
		updateModule := moduleFromParts(module, parts)
		if updateModule == "" {
			updateModule = moduleFromGNMIPath(update.GetPath())
		}
		d.decodeTypedValue(sm, updateModule, parts, update.GetVal(), ts, attrs)
	}

	appendIOSXRHealthMetrics(md, d.health, iosXRMetricContext{
		targetName:     d.target.Name,
		endpoint:       d.target.Endpoint,
		platformFamily: d.target.PlatformFamily,
		transport:      transport,
	}, ts)
	return md
}

func (d iosXRGNMIUpdateDecoder) decodeTypedValue(sm pmetric.ScopeMetrics, module string, parts []string, value *gnmi.TypedValue, ts pcommon.Timestamp, attrs map[string]string) {
	if value == nil {
		return
	}
	switch v := value.GetValue().(type) {
	case *gnmi.TypedValue_StringVal:
		appendIOSXRInfoMetric(sm, module, parts, v.StringVal, ts, attrs)
	case *gnmi.TypedValue_AsciiVal:
		appendIOSXRInfoMetric(sm, module, parts, v.AsciiVal, ts, attrs)
	case *gnmi.TypedValue_IntVal:
		appendIOSXRIntMetric(sm, module, parts, v.IntVal, ts, attrs)
	case *gnmi.TypedValue_UintVal:
		if v.UintVal <= math.MaxInt64 {
			appendIOSXRIntMetric(sm, module, parts, int64(v.UintVal), ts, attrs)
		} else {
			overflowAttrs := cloneAttrs(attrs)
			overflowAttrs["cisco.value.type"] = "uint64"
			overflowAttrs["cisco.value.out_of_range"] = "true"
			appendIOSXRInfoMetric(sm, module, parts, strconv.FormatUint(v.UintVal, 10), ts, overflowAttrs)
		}
	case *gnmi.TypedValue_BoolVal:
		if v.BoolVal {
			appendIOSXRIntMetric(sm, module, parts, 1, ts, attrs)
		} else {
			appendIOSXRIntMetric(sm, module, parts, 0, ts, attrs)
		}
	case *gnmi.TypedValue_FloatVal:
		appendIOSXRNumberMetric(sm, module, parts, float64(v.FloatVal), ts, attrs)
	case *gnmi.TypedValue_DoubleVal:
		appendIOSXRNumberMetric(sm, module, parts, v.DoubleVal, ts, attrs)
	case *gnmi.TypedValue_DecimalVal:
		if v.DecimalVal != nil {
			appendIOSXRNumberMetric(sm, module, parts, float64(v.DecimalVal.Digits)/pow10(v.DecimalVal.Precision), ts, attrs)
		}
	case *gnmi.TypedValue_LeaflistVal:
		values := make([]string, 0, len(v.LeaflistVal.GetElement()))
		for _, elem := range v.LeaflistVal.GetElement() {
			values = append(values, scalarTypedValueString(elem))
		}
		appendIOSXRInfoMetric(sm, module, parts, strings.Join(values, ","), ts, attrs)
	case *gnmi.TypedValue_JsonIetfVal:
		d.decodeJSONValue(sm, module, parts, v.JsonIetfVal, ts, attrs)
	case *gnmi.TypedValue_JsonVal:
		d.decodeJSONValue(sm, module, parts, v.JsonVal, ts, attrs)
	case *gnmi.TypedValue_BytesVal:
		appendIOSXRInfoMetric(sm, module, append(parts, "bytes"), fmt.Sprintf("%x", v.BytesVal), ts, attrs)
	case *gnmi.TypedValue_ProtoBytes:
		if d.health != nil {
			d.health.addCompactGPBPayloads(1)
		}
		appendGaugeMetric(sm, "cisco.iosxr.receiver.compact_gpb_payloads", 1, ts, attrs)
	case *gnmi.TypedValue_AnyVal:
		appendIOSXRInfoMetric(sm, module, append(parts, "any"), v.AnyVal.String(), ts, attrs)
	default:
		appendIOSXRInfoMetric(sm, module, parts, value.String(), ts, attrs)
	}
}

func (d iosXRGNMIUpdateDecoder) decodeJSONValue(sm pmetric.ScopeMetrics, module string, parts []string, raw []byte, ts pcommon.Timestamp, attrs map[string]string) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		if d.health != nil {
			d.health.addDecodeErrors(1)
		}
		return
	}
	walkIOSXRJSON(sm, module, parts, value, ts, attrs)
}

func walkIOSXRJSON(sm pmetric.ScopeMetrics, module string, parts []string, value any, ts pcommon.Timestamp, attrs map[string]string) {
	switch v := value.(type) {
	case map[string]any:
		nextAttrs := cloneAttrs(attrs)
		extractJSONIdentityAttrs(v, nextAttrs)
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			nextModule, part := splitYANGQualifiedName(module, key)
			walkIOSXRJSON(sm, nextModule, append(parts, part), v[key], ts, nextAttrs)
		}
	case []any:
		if allJSONScalars(v) {
			appendIOSXRInfoMetric(sm, module, parts, valueToInfoString(v), ts, attrs)
			return
		}
		for _, elem := range v {
			walkIOSXRJSON(sm, module, parts, elem, ts, attrs)
		}
	default:
		if n, ok := typedNumericValue(v); ok {
			appendIOSXRMetricNumber(sm, module, parts, n, ts, attrs)
			return
		}
		if value := valueToInfoString(v); value != "" {
			appendIOSXRInfoMetric(sm, module, parts, value, ts, attrs)
		}
	}
}

func allJSONScalars(values []any) bool {
	for _, value := range values {
		switch value.(type) {
		case map[string]any, []any:
			return false
		}
	}
	return true
}

func extractJSONIdentityAttrs(value map[string]any, attrs map[string]string) {
	for key, attrName := range map[string]string{
		"name":             "name",
		"id":               "id",
		"interface-name":   "network.interface.name",
		"interface":        "network.interface.name",
		"vrf-name":         "network.vrf.name",
		"vrf":              "network.vrf.name",
		"neighbor-address": "network.peer.address",
		"neighbor":         "network.peer.address",
		"address":          "network.address",
		"node-name":        "cisco.node.name",
		"node":             "cisco.node.name",
		"location":         "cisco.location",
		"component":        "hw.name",
	} {
		if raw, ok := value[key]; ok {
			if text := scalarJSONIdentity(raw); text != "" {
				attrs[attrName] = text
				if key == "name" && attrs["network.interface.name"] == "" && looksLikeInterfaceName(text) {
					attrs["network.interface.name"] = text
				}
			}
		}
	}
}

func scalarJSONIdentity(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return fmt.Sprintf("%g", v)
	case bool:
		return fmt.Sprintf("%t", v)
	default:
		return ""
	}
}

func looksLikeInterfaceName(value string) bool {
	value = strings.ToLower(value)
	return strings.Contains(value, "ethernet") ||
		strings.HasPrefix(value, "te") ||
		strings.HasPrefix(value, "gi") ||
		strings.HasPrefix(value, "hu") ||
		strings.HasPrefix(value, "fo") ||
		strings.HasPrefix(value, "bundle") ||
		strings.HasPrefix(value, "loopback") ||
		strings.HasPrefix(value, "mgmt")
}

func scalarTypedValueString(value *gnmi.TypedValue) string {
	if value == nil {
		return ""
	}
	switch v := value.GetValue().(type) {
	case *gnmi.TypedValue_StringVal:
		return v.StringVal
	case *gnmi.TypedValue_AsciiVal:
		return v.AsciiVal
	case *gnmi.TypedValue_IntVal:
		return fmt.Sprintf("%d", v.IntVal)
	case *gnmi.TypedValue_UintVal:
		return fmt.Sprintf("%d", v.UintVal)
	case *gnmi.TypedValue_BoolVal:
		return fmt.Sprintf("%t", v.BoolVal)
	case *gnmi.TypedValue_FloatVal:
		return fmt.Sprintf("%g", v.FloatVal)
	case *gnmi.TypedValue_DoubleVal:
		return fmt.Sprintf("%g", v.DoubleVal)
	default:
		return value.String()
	}
}

func pow10(precision uint32) float64 {
	out := 1.0
	for i := uint32(0); i < precision; i++ {
		out *= 10
	}
	return out
}

func cloneAttrs(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs)+4)
	for key, value := range attrs {
		out[key] = value
	}
	return out
}

func pathPartsAndAttrs(prefix, update *gnmi.Path) ([]string, map[string]string) {
	parts := make([]string, 0, len(prefix.GetElem())+len(update.GetElem()))
	attrs := map[string]string{}
	add := func(p *gnmi.Path) {
		if p == nil {
			return
		}
		for _, elem := range p.GetElem() {
			_, name := splitYANGQualifiedName("", elem.GetName())
			if name == "" {
				continue
			}
			parts = append(parts, name)
			for key, value := range elem.GetKey() {
				attr := "cisco.yang.key." + sanitizeMetricSegment(key)
				attrs[attr] = value
				switch strings.ToLower(key) {
				case "name", "interface-name":
					if looksLikeInterfaceName(value) {
						attrs["network.interface.name"] = value
					}
				case "vrf", "vrf-name":
					attrs["network.vrf.name"] = value
				case "neighbor", "neighbor-address":
					attrs["network.peer.address"] = value
				}
			}
		}
		for _, elem := range p.GetElement() {
			parts = append(parts, elem)
		}
	}
	add(prefix)
	add(update)
	return parts, attrs
}

func moduleFromParts(current string, parts []string) string {
	if current != "" {
		return current
	}
	for _, part := range parts {
		if idx := strings.Index(part, ":"); idx > 0 {
			return part[:idx]
		}
	}
	return ""
}

func splitYANGQualifiedName(currentModule, value string) (string, string) {
	if idx := strings.Index(value, ":"); idx > 0 {
		return value[:idx], value[idx+1:]
	}
	return currentModule, value
}

func moduleFromGNMIPath(p *gnmi.Path) string {
	if p == nil {
		return ""
	}
	if p.GetOrigin() != "" {
		return p.GetOrigin()
	}
	for _, elem := range p.GetElem() {
		if idx := strings.Index(elem.GetName(), ":"); idx > 0 {
			return elem.GetName()[:idx]
		}
	}
	return ""
}

func gnmiPathToString(p *gnmi.Path) string {
	if p == nil {
		return ""
	}
	parts := make([]string, 0, len(p.GetElem()))
	for _, elem := range p.GetElem() {
		name := elem.GetName()
		if len(elem.GetKey()) > 0 {
			keys := make([]string, 0, len(elem.GetKey()))
			for key := range elem.GetKey() {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				name += "[" + key + "=" + elem.GetKey()[key] + "]"
			}
		}
		parts = append(parts, name)
	}
	if len(parts) == 0 {
		parts = append(parts, p.GetElement()...)
	}
	out := strings.Join(parts, "/")
	if p.GetOrigin() != "" {
		out = p.GetOrigin() + ":" + out
	}
	return out
}
