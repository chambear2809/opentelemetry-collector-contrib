// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

type catalyst9800GNMIUpdateDecoder struct {
	target        Catalyst9800TargetConfig
	health        *catalyst9800Health
	maxDatapoints int
	limits        directGNMIDecodeLimits
}

func (d *catalyst9800GNMIUpdateDecoder) decodeNotification(notification *gnmi.Notification, transport string) pmetric.Metrics { //nolint:unparam // Explicit transport keeps direct and future replay decoders distinguishable.
	ts := directGNMITimestamp(notification.GetTimestamp(), time.Now())
	budget := newDirectGNMIDecodeBudget(d.limits, d.maxDatapoints)
	prefix := notification.GetPrefix()
	prefixText, validPrefix := gnmiPathToString(prefix, budget)
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
	metrics := newIndexedMetricBuilder(sm, budget)

	deletes := notification.GetDelete()
	updates := notification.GetUpdate()
	if !validPrefix {
		deletes = nil
		updates = nil
	}
	for _, deleted := range deletes {
		if !budget.visitField(1) {
			break
		}
		deletedText, validPath := gnmiPathToString(deleted, budget)
		if !validPath {
			if budget.exhausted {
				break
			}
			continue
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
		if !setDirectGNMISourcePath(attrs, prefixText, deletedText, budget) {
			continue
		}
		putNonEmpty(attrs, "cisco.yang.module", deleteModule)
		appendCatalyst9800InfoMetricIndexed(metrics, deleteModule, parts, "deleted", ts, attrs)
	}

	for _, update := range updates {
		if !budget.visitField(1) {
			break
		}
		updateText, validPath := gnmiPathToString(update.GetPath(), budget)
		if !validPath {
			if budget.exhausted {
				break
			}
			continue
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
		if !setDirectGNMISourcePath(attrs, prefixText, updateText, budget) {
			continue
		}
		putNonEmpty(attrs, "cisco.yang.module", updateModule)
		depth := len(parts)
		if depth == 0 {
			depth = 1
		}
		value, ok := resolveDirectGNMIUpdateValue(update, budget)
		if !ok {
			continue
		}
		d.decodeTypedValue(metrics, updateModule, parts, value, ts, attrs, budget, depth)
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
		appendCatalyst9800MetricNumberIndexed(metrics, module, parts, doubleMetricNumber(float64(v.FloatVal)), ts, attrs) //nolint:staticcheck // Legacy Cisco devices still emit the deprecated gNMI float field.
	case *gnmi.TypedValue_DoubleVal:
		appendCatalyst9800MetricNumberIndexed(metrics, module, parts, doubleMetricNumber(v.DoubleVal), ts, attrs)
	case *gnmi.TypedValue_DecimalVal:
		if v.DecimalVal != nil && v.DecimalVal.Precision <= 308 { //nolint:staticcheck // Legacy Cisco devices still emit the deprecated gNMI decimal field.
			appendCatalyst9800MetricNumberIndexed(metrics, module, parts, doubleMetricNumber(float64(v.DecimalVal.Digits)/pow10(v.DecimalVal.Precision)), ts, attrs) //nolint:staticcheck // Preserve compatibility with legacy gNMI decimal payloads.
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
		metrics.appendNumber(
			"cisco.catalyst9800.receiver.compact_gpb_payloads",
			pmetric.MetricTypeGauge,
			intMetricNumber(1),
			ts,
			attrs,
		)
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
	var value any
	if err := httpclient.DecodeJSON(raw, &value); err != nil {
		budget.addDecodeError()
		budget.drop(false)
		return
	}
	pathNameBytes, ok := directGNMIPathNameBytes(parts, budget.limits.maxMetricNameBytes)
	if !ok {
		budget.drop(false)
		return
	}
	walkCatalyst9800JSON(metrics, module, parts, value, ts, attrs, budget, depth, pathNameBytes)
}

func walkCatalyst9800JSON(metrics *indexedMetricBuilder, module string, parts []string, value any, ts pcommon.Timestamp, attrs map[string]string, budget *directGNMIDecodeBudget, depth, pathNameBytes int) bool {
	if !budget.visitField(depth) {
		return false
	}
	switch v := value.(type) {
	case map[string]any:
		if !budget.ensureChildFieldCapacity(len(v), depth+1) {
			return false
		}
		nextAttrs := cloneAttrs(attrs)
		if !extractJSONIdentityAttrs(v, nextAttrs, budget, parts) || !extractCatalyst9800JSONIdentityAttrs(v, nextAttrs, budget, parts) {
			return !budget.exhausted
		}
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			nextModule, part := splitYANGQualifiedName(module, key)
			if sanitizeMetricSegment(part) == "" {
				budget.drop(false)
				continue
			}
			nextPathNameBytes, ok := extendDirectGNMIPathNameBytes(pathNameBytes, part, budget.limits.maxMetricNameBytes)
			if !ok {
				budget.drop(false)
				continue
			}
			childAttrs := cloneAttrs(nextAttrs)
			if !extendDirectGNMISourcePath(childAttrs, key, budget) {
				continue
			}
			if !walkCatalyst9800JSON(metrics, nextModule, append(parts, part), v[key], ts, childAttrs, budget, depth+1, nextPathNameBytes) && budget.exhausted {
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
		if !validateCatalyst9800JSONArrayIdentity(v, attrs, budget, parts) {
			return !budget.exhausted
		}
		for _, elem := range v {
			if !walkCatalyst9800JSON(metrics, module, parts, elem, ts, attrs, budget, depth+1, pathNameBytes) && budget.exhausted {
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

// validateCatalyst9800JSONArrayIdentity rejects anonymous or duplicate
// effective identities before emitting any child of a multi-entry array.
func validateCatalyst9800JSONArrayIdentity(values []any, attrs map[string]string, budget *directGNMIDecodeBudget, objectPath []string) bool {
	if len(values) <= 1 {
		return true
	}
	seen := make(map[[32]byte]struct{}, len(values))
	for _, value := range values {
		projected := cloneAttrs(attrs)
		if object, ok := value.(map[string]any); ok {
			if !extractJSONIdentityAttrs(object, projected, budget, objectPath) ||
				!extractCatalyst9800JSONIdentityAttrs(object, projected, budget, objectPath) {
				return false
			}
		}
		digest, identified := directGNMIAttributeProjectionDigest(projected, attrs)
		if !identified {
			budget.drop(false)
			return false
		}
		if _, duplicate := seen[digest]; duplicate {
			budget.drop(false)
			return false
		}
		seen[digest] = struct{}{}
	}
	return true
}

func extractCatalyst9800JSONIdentityAttrs(value map[string]any, attrs map[string]string, budget *directGNMIDecodeBudget, objectPath []string) bool {
	identityValues := make(map[string]directGNMIJSONIdentity, 15)
	for _, key := range []string{
		"ap-ip",
		"ap-mac",
		"ap-name",
		"client-mac",
		"ip-addr",
		"ms-mac-address",
		"node-ip",
		"radio-slot-id",
		"serial-num",
		"serial-number",
		"slot-id",
		"ssid",
		"vap-ssid",
		"wlan-id",
		"wtp-mac",
	} {
		raw, exists := value[key]
		if !exists {
			continue
		}
		text, scalar := scalarJSONIdentity(raw)
		if !scalar {
			continue
		}
		if !putDirectGNMIJSONIdentityAttribute(attrs, directGNMIPathKeyAttributePrefix+sanitizeMetricSegment(key), text, objectPath, budget) {
			return false
		}
		identityValues[key] = directGNMIJSONIdentity{value: text}
	}

	// These ordered groups match the canonical Catalyst key spellings used by
	// path normalization and make synonym precedence independent of Go map
	// iteration order. Every present raw key remains available under its
	// cisco.yang.key.* attribute even when it does not win the semantic alias.
	if !putPreferredCatalyst9800JSONIdentity(attrs, identityValues, objectPath, budget, "cisco.wlc.ap.mac", "wtp-mac", "ap-mac") ||
		!putPreferredCatalyst9800JSONIdentity(attrs, identityValues, objectPath, budget, "cisco.wlc.ap.name", "ap-name", "") ||
		!putPreferredCatalyst9800JSONIdentity(attrs, identityValues, objectPath, budget, "cisco.wlc.radio.slot", "slot-id", "radio-slot-id") ||
		!putPreferredCatalyst9800JSONIdentity(attrs, identityValues, objectPath, budget, "cisco.wlc.wlan.id", "wlan-id", "") ||
		!putPreferredCatalyst9800JSONIdentity(attrs, identityValues, objectPath, budget, "cisco.wlc.ssid", "ssid", "vap-ssid") ||
		!putPreferredCatalyst9800JSONIdentity(attrs, identityValues, objectPath, budget, "cisco.wlc.client.mac", "client-mac", "ms-mac-address") ||
		!putPreferredCatalyst9800JSONIdentity(attrs, identityValues, objectPath, budget, "cisco.wlc.mobility.node_ip", "node-ip", "") ||
		!putPreferredCatalyst9800JSONIdentity(attrs, identityValues, objectPath, budget, "host.ip", "ap-ip", "ip-addr") ||
		!putPreferredCatalyst9800JSONIdentity(attrs, identityValues, objectPath, budget, "hw.serial_number", "serial-num", "serial-number") {
		return false
	}
	return true
}

type directGNMIJSONIdentity struct {
	value string
}

func putPreferredCatalyst9800JSONIdentity(attrs map[string]string, values map[string]directGNMIJSONIdentity, objectPath []string, budget *directGNMIDecodeBudget, attribute, preferred, fallback string) bool {
	selected, present := values[preferred]
	if !present {
		selected, present = values[fallback]
	}
	if !present {
		return true
	}
	return putDirectGNMIJSONIdentityAttribute(attrs, attribute, selected.value, objectPath, budget)
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
