// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
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
	target        IOSXRTargetConfig
	health        *iosXRHealth
	maxDatapoints int
	limits        directGNMIDecodeLimits
}

func (d *iosXRGNMIUpdateDecoder) decodeNotification(notification *gnmi.Notification, transport string) pmetric.Metrics { //nolint:unparam // Explicit transport keeps direct and future replay decoders distinguishable.
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
		transport:      iosXRTelemetryTransportDialIn,
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
		attrs["deleted"] = "true"
		deleteModule := moduleFromParts(module, parts)
		putNonEmpty(attrs, "cisco.yang.path", prefixText)
		putNonEmpty(attrs, "cisco.yang.module", deleteModule)
		appendIOSXRInfoMetricIndexed(metrics, deleteModule, parts, "deleted", ts, attrs)
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

	appendIOSXRHealthMetrics(md, d.health, iosXRMetricContext{
		targetName:     d.target.Name,
		endpoint:       d.target.Endpoint,
		platformFamily: d.target.PlatformFamily,
		transport:      iosXRTelemetryTransportDialIn,
	}, ts)
	return md
}

func (d iosXRGNMIUpdateDecoder) decodeTypedValue(metrics *indexedMetricBuilder, module string, parts []string, value *gnmi.TypedValue, ts pcommon.Timestamp, attrs map[string]string, budget *directGNMIDecodeBudget, depth int) {
	if value == nil || value.GetValue() == nil {
		budget.addDecodeError()
		budget.drop(false)
		return
	}
	switch v := value.GetValue().(type) {
	case *gnmi.TypedValue_StringVal:
		appendIOSXRInfoMetricIndexed(metrics, module, parts, v.StringVal, ts, attrs)
	case *gnmi.TypedValue_AsciiVal:
		appendIOSXRInfoMetricIndexed(metrics, module, parts, v.AsciiVal, ts, attrs)
	case *gnmi.TypedValue_IntVal:
		appendIOSXRMetricNumberIndexed(metrics, module, parts, intMetricNumber(v.IntVal), ts, attrs)
	case *gnmi.TypedValue_UintVal:
		if v.UintVal <= math.MaxInt64 {
			appendIOSXRMetricNumberIndexed(metrics, module, parts, intMetricNumber(int64(v.UintVal)), ts, attrs)
		} else {
			overflowAttrs := cloneAttrs(attrs)
			overflowAttrs["cisco.value.type"] = "uint64"
			overflowAttrs["cisco.value.out_of_range"] = "true"
			appendIOSXRInfoMetricIndexed(metrics, module, parts, strconv.FormatUint(v.UintVal, 10), ts, overflowAttrs)
		}
	case *gnmi.TypedValue_BoolVal:
		if v.BoolVal {
			appendIOSXRMetricNumberIndexed(metrics, module, parts, intMetricNumber(1), ts, attrs)
		} else {
			appendIOSXRMetricNumberIndexed(metrics, module, parts, intMetricNumber(0), ts, attrs)
		}
	case *gnmi.TypedValue_FloatVal:
		appendIOSXRMetricNumberIndexed(metrics, module, parts, doubleMetricNumber(float64(v.FloatVal)), ts, attrs) //nolint:staticcheck // Legacy Cisco devices still emit the deprecated gNMI float field.
	case *gnmi.TypedValue_DoubleVal:
		appendIOSXRMetricNumberIndexed(metrics, module, parts, doubleMetricNumber(v.DoubleVal), ts, attrs)
	case *gnmi.TypedValue_DecimalVal:
		if v.DecimalVal != nil { //nolint:staticcheck // Legacy Cisco devices still emit the deprecated gNMI decimal field.
			appendIOSXRMetricNumberIndexed(metrics, module, parts, doubleMetricNumber(float64(v.DecimalVal.Digits)/pow10(v.DecimalVal.Precision)), ts, attrs) //nolint:staticcheck // Preserve compatibility with legacy gNMI decimal payloads.
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
		joined := strings.Join(values, ",")
		appendIOSXRInfoMetricIndexed(metrics, module, parts, joined, ts, attrs)
	case *gnmi.TypedValue_JsonIetfVal:
		d.decodeJSONValue(metrics, module, parts, v.JsonIetfVal, ts, attrs, budget, depth+1)
	case *gnmi.TypedValue_JsonVal:
		d.decodeJSONValue(metrics, module, parts, v.JsonVal, ts, attrs, budget, depth+1)
	case *gnmi.TypedValue_BytesVal:
		if len(v.BytesVal) > budget.limits.maxAttributeValueBytes/2 {
			budget.drop(false)
			return
		}
		appendIOSXRInfoMetricIndexed(metrics, module, append(parts, "bytes"), fmt.Sprintf("%x", v.BytesVal), ts, attrs)
	case *gnmi.TypedValue_ProtoBytes:
		if d.health != nil {
			d.health.addCompactGPBPayloads(1)
		}
		metrics.appendNumber("cisco.iosxr.receiver.compact_gpb_payloads", pmetric.MetricTypeGauge, doubleMetricNumber(1), ts, attrs)
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
		appendIOSXRInfoMetricIndexed(metrics, module, append(parts, "any"), v.AnyVal.String(), ts, attrs)
	default:
		appendIOSXRInfoMetricIndexed(metrics, module, parts, value.String(), ts, attrs)
	}
}

func (iosXRGNMIUpdateDecoder) decodeJSONValue(metrics *indexedMetricBuilder, module string, parts []string, raw []byte, ts pcommon.Timestamp, attrs map[string]string, budget *directGNMIDecodeBudget, depth int) {
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
	walkIOSXRJSON(metrics, module, parts, value, ts, attrs, budget, depth)
}

func walkIOSXRJSON(metrics *indexedMetricBuilder, module string, parts []string, value any, ts pcommon.Timestamp, attrs map[string]string, budget *directGNMIDecodeBudget, depth int) bool {
	if !budget.visitField(depth) {
		return false
	}
	switch v := value.(type) {
	case map[string]any:
		if !budget.ensureChildFieldCapacity(len(v), depth+1) {
			return false
		}
		nextAttrs := cloneAttrs(attrs)
		if !extractJSONIdentityAttrs(v, nextAttrs, budget) {
			return !budget.exhausted
		}
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			nextModule, part := splitYANGQualifiedName(module, key)
			if !walkIOSXRJSON(metrics, nextModule, append(parts, part), v[key], ts, nextAttrs, budget, depth+1) && budget.exhausted {
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
			appendIOSXRInfoMetricIndexed(metrics, module, parts, valueToInfoString(v), ts, attrs)
			return !budget.exhausted
		}
		for _, elem := range v {
			if !walkIOSXRJSON(metrics, module, parts, elem, ts, attrs, budget, depth+1) && budget.exhausted {
				return false
			}
		}
	default:
		if n, ok := typedNumericValue(v); ok {
			appendIOSXRMetricNumberIndexed(metrics, module, parts, n, ts, attrs)
			return !budget.exhausted
		}
		if value := valueToInfoString(v); value != "" {
			appendIOSXRInfoMetricIndexed(metrics, module, parts, value, ts, attrs)
		}
	}
	return !budget.exhausted
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

func extractJSONIdentityAttrs(value map[string]any, attrs map[string]string, budget *directGNMIDecodeBudget) bool {
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
				if len(text) > budget.limits.maxAttributeValueBytes {
					budget.drop(false)
					return false
				}
				attrs[attrName] = text
				if key == "name" && attrs["network.interface.name"] == "" && looksLikeInterfaceName(text) {
					attrs["network.interface.name"] = text
				}
			}
		}
	}
	return true
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
		return fmt.Sprintf("%g", v.FloatVal) //nolint:staticcheck // Preserve string conversion for legacy gNMI float payloads.
	case *gnmi.TypedValue_DoubleVal:
		return fmt.Sprintf("%g", v.DoubleVal)
	default:
		return value.String()
	}
}

func pow10(precision uint32) float64 {
	if precision > 308 {
		return math.Inf(1)
	}
	return math.Pow10(int(precision))
}

func cloneAttrs(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs)+4)
	maps.Copy(out, attrs)
	return out
}

func pathPartsAndAttrs(prefix, update *gnmi.Path, budget *directGNMIDecodeBudget) ([]string, map[string]string, bool) {
	parts := make([]string, 0, len(prefix.GetElem())+len(update.GetElem()))
	attrs := map[string]string{}
	putAttr := func(key, value string) bool {
		if value == "" {
			return true
		}
		if !budget.validAttribute(key, value) {
			budget.drop(false)
			return false
		}
		if _, exists := attrs[key]; !exists && len(attrs) >= budget.limits.maxAttributes {
			budget.drop(false)
			return false
		}
		attrs[key] = value
		return true
	}
	add := func(p *gnmi.Path) bool {
		if p == nil {
			return true
		}
		for _, elem := range p.GetElem() {
			if !budget.visitField(len(parts) + 1) {
				return false
			}
			_, name := splitYANGQualifiedName("", elem.GetName())
			if name == "" {
				continue
			}
			parts = append(parts, name)
			for key, value := range elem.GetKey() {
				if len(key)+len("cisco.yang.key.") > budget.limits.maxAttributeKeyBytes {
					budget.drop(false)
					return false
				}
				attr := "cisco.yang.key." + sanitizeMetricSegment(key)
				if !putAttr(attr, value) {
					return false
				}
				switch strings.ToLower(key) {
				case "name", "interface-name":
					if looksLikeInterfaceName(value) {
						if !putAttr("network.interface.name", value) {
							return false
						}
					}
				case "vrf", "vrf-name":
					if !putAttr("network.vrf.name", value) {
						return false
					}
				case "neighbor", "neighbor-address":
					if !putAttr("network.peer.address", value) {
						return false
					}
				}
			}
		}
		for _, elem := range p.GetElement() { //nolint:staticcheck // Legacy gNMI paths can still use the deprecated Element representation.
			if !budget.visitField(len(parts) + 1) {
				return false
			}
			parts = append(parts, elem)
		}
		return true
	}
	if !add(prefix) || !add(update) {
		return nil, nil, false
	}
	return parts, attrs, true
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
		var name strings.Builder
		name.WriteString(elem.GetName())
		if len(elem.GetKey()) > 0 {
			keys := make([]string, 0, len(elem.GetKey()))
			for key := range elem.GetKey() {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				name.WriteString("[" + key + "=" + elem.GetKey()[key] + "]")
			}
		}
		parts = append(parts, name.String())
	}
	if len(parts) == 0 {
		parts = append(parts, p.GetElement()...) //nolint:staticcheck // Preserve legacy gNMI Element path compatibility.
	}
	out := strings.Join(parts, "/")
	if p.GetOrigin() != "" {
		out = p.GetOrigin() + ":" + out
	}
	return out
}
