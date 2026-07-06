// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
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
	budget := newDirectGNMIDecodeBudget(d.limits, d.maxDatapoints)
	prefix := notification.GetPrefix()
	prefixText, validPrefix := gnmiPathToString(prefix, budget)
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
		attrs["deleted"] = "true"
		deleteModule := moduleFromParts(module, parts)
		if !setDirectGNMISourcePath(attrs, prefixText, deletedText, budget) {
			continue
		}
		putNonEmpty(attrs, "cisco.yang.module", deleteModule)
		appendIOSXRInfoMetricIndexed(metrics, deleteModule, parts, "deleted", ts, attrs)
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
		if v.DecimalVal != nil && v.DecimalVal.Precision <= 308 { //nolint:staticcheck // Legacy Cisco devices still emit the deprecated gNMI decimal field.
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
	walkIOSXRJSON(metrics, module, parts, value, ts, attrs, budget, depth, pathNameBytes)
}

func walkIOSXRJSON(metrics *indexedMetricBuilder, module string, parts []string, value any, ts pcommon.Timestamp, attrs map[string]string, budget *directGNMIDecodeBudget, depth, pathNameBytes int) bool {
	if !budget.visitField(depth) {
		return false
	}
	switch v := value.(type) {
	case map[string]any:
		if !budget.ensureChildFieldCapacity(len(v), depth+1) {
			return false
		}
		nextAttrs := cloneAttrs(attrs)
		if !extractJSONIdentityAttrs(v, nextAttrs, budget, parts) {
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
			if !walkIOSXRJSON(metrics, nextModule, append(parts, part), v[key], ts, childAttrs, budget, depth+1, nextPathNameBytes) && budget.exhausted {
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
		if !validateIOSXRJSONArrayIdentity(v, attrs, budget, parts) {
			return !budget.exhausted
		}
		for _, elem := range v {
			if !walkIOSXRJSON(metrics, module, parts, elem, ts, attrs, budget, depth+1, pathNameBytes) && budget.exhausted {
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

// validateIOSXRJSONArrayIdentity rejects a multi-entry complex array before
// emitting any datapoints when an entry has no recognized identity or two
// entries have the same effective identity.
// JSON arrays are frequently YANG lists whose ordering is not stable, so an
// ordinal would prevent an in-batch collision while silently reassigning a
// time series after a reorder. Reusing the production extractors makes empty,
// missing, synonym, and inherited identity semantics exactly match emission.
func validateIOSXRJSONArrayIdentity(values []any, attrs map[string]string, budget *directGNMIDecodeBudget, objectPath []string) bool {
	if len(values) <= 1 {
		return true
	}
	seen := make(map[[sha256.Size]byte]struct{}, len(values))
	for _, value := range values {
		projected := cloneAttrs(attrs)
		if object, ok := value.(map[string]any); ok {
			if !extractJSONIdentityAttrs(object, projected, budget, objectPath) {
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

func directGNMIAttributeProjectionDigest(attrs, inherited map[string]string) ([sha256.Size]byte, bool) {
	// Inherited attributes are identical for every sibling. Hash only identity
	// attributes added by the entry so a large keyed prefix is not rehashed for
	// every array element.
	keys := make([]string, 0, len(attrs)-len(inherited))
	for key := range attrs {
		if _, exists := inherited[key]; !exists {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return [sha256.Size]byte{}, false
	}
	sort.Strings(keys)
	hash := sha256.New()
	add := func(value string) {
		var length [8]byte
		binary.LittleEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	for _, key := range keys {
		add(key)
		add(attrs[key])
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, true
}

func extractJSONIdentityAttrs(value map[string]any, attrs map[string]string, budget *directGNMIDecodeBudget, objectPath []string) bool {
	name, namePresent, ok := preferredScalarJSONIdentity(value, budget, "name")
	if !ok || (namePresent && !putDirectGNMIJSONIdentityAttribute(attrs, "name", name, objectPath, budget)) {
		return false
	}
	if !putPreferredScalarJSONIdentity(attrs, "id", value, objectPath, budget, "id") {
		return false
	}

	// The first key in each group is the explicit, canonical spelling. It must
	// win when a device sends multiple synonyms in the same object; map
	// iteration order must never select the series identity.
	interfaceName, interfacePresent, ok := preferredScalarJSONIdentity(value, budget, "interface-name", "interface")
	if !ok || (interfacePresent && !putDirectGNMIJSONIdentityAttribute(attrs, "network.interface.name", interfaceName, objectPath, budget)) {
		return false
	}
	if !interfacePresent && namePresent && looksLikeInterfaceName(name) {
		if !putDirectGNMIJSONIdentityAttribute(attrs, "network.interface.name", name, objectPath, budget) {
			return false
		}
	}
	if !putPreferredScalarJSONIdentity(attrs, "network.vrf.name", value, objectPath, budget, "vrf-name", "vrf") ||
		!putPreferredScalarJSONIdentity(attrs, "network.peer.address", value, objectPath, budget, "neighbor-address", "neighbor") ||
		!putPreferredScalarJSONIdentity(attrs, "network.address", value, objectPath, budget, "address") ||
		!putPreferredScalarJSONIdentity(attrs, "cisco.node.name", value, objectPath, budget, "node-name", "node") ||
		!putPreferredScalarJSONIdentity(attrs, "cisco.location", value, objectPath, budget, "location") ||
		!putPreferredScalarJSONIdentity(attrs, "hw.name", value, objectPath, budget, "component") {
		return false
	}
	return true
}

// preferredScalarJSONIdentity validates every supplied scalar synonym even
// though only the first present value is selected. Presence is independent of
// content so an explicit empty YANG key remains distinct from a missing key.
// A lower-priority oversized value must not bypass the decode budget merely
// because another synonym won.
func preferredScalarJSONIdentity(value map[string]any, budget *directGNMIDecodeBudget, keys ...string) (string, bool, bool) {
	selected := ""
	selectedPresent := false
	for _, key := range keys {
		raw, exists := value[key]
		if !exists {
			continue
		}
		text, scalar := scalarJSONIdentity(raw)
		if !scalar {
			continue
		}
		if len(text) > budget.limits.maxAttributeValueBytes {
			budget.drop(false)
			return "", false, false
		}
		if !selectedPresent {
			selected = text
			selectedPresent = true
		}
	}
	return selected, selectedPresent, true
}

func putPreferredScalarJSONIdentity(attrs map[string]string, attribute string, value map[string]any, objectPath []string, budget *directGNMIDecodeBudget, keys ...string) bool {
	selected, present, ok := preferredScalarJSONIdentity(value, budget, keys...)
	return ok && (!present || putDirectGNMIJSONIdentityAttribute(attrs, attribute, selected, objectPath, budget))
}

func scalarJSONIdentity(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case json.Number:
		return v.String(), true
	case float64:
		return fmt.Sprintf("%g", v), true
	case bool:
		return fmt.Sprintf("%t", v), true
	default:
		return "", false
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

func setDirectGNMISourcePath(attrs map[string]string, prefix, relative string, budget *directGNMIDecodeBudget) bool {
	joined := prefix
	if relative != "" {
		if joined != "" {
			joined += "/"
		}
		joined += relative
	}
	if len(joined) > budget.limits.maxAttributeValueBytes {
		budget.drop(false)
		return false
	}
	if joined != "" {
		attrs["cisco.yang.path"] = joined
	}
	return true
}

func extendDirectGNMISourcePath(attrs map[string]string, rawElement string, budget *directGNMIDecodeBudget) bool {
	// JSON Pointer escaping keeps arbitrary JSON object keys injective when
	// extending the original wire path used as a datapoint identity attribute.
	element := strings.ReplaceAll(strings.ReplaceAll(rawElement, "~", "~0"), "/", "~1")
	joined := attrs["cisco.yang.path"]
	if joined != "" {
		joined += "/"
	}
	if len(element) > budget.limits.maxAttributeValueBytes-len(joined) {
		budget.drop(false)
		return false
	}
	attrs["cisco.yang.path"] = joined + element
	return true
}

func putDirectGNMIAttributeValue(attrs map[string]string, key, value string, budget *directGNMIDecodeBudget) bool {
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

const (
	directGNMIIdentityEscapeBase     = "cisco.yang.key"
	directGNMIPathKeyAttributePrefix = directGNMIIdentityEscapeBase + "."
)

func isDirectGNMIPathKeyAttribute(key string) bool {
	return strings.HasPrefix(key, directGNMIPathKeyAttributePrefix)
}

func isDirectGNMIIdentityAttribute(key string) bool {
	if isDirectGNMIPathKeyAttribute(key) {
		return true
	}
	switch key {
	case "name", "id",
		"network.interface.name", "network.vrf.name", "network.peer.address", "network.address",
		"cisco.node.name", "cisco.location", "hw.name",
		"cisco.wlc.ap.mac", "cisco.wlc.ap.name", "cisco.wlc.radio.slot", "cisco.wlc.wlan.id",
		"cisco.wlc.ssid", "cisco.wlc.client.mac", "cisco.wlc.mobility.node_ip",
		"host.ip", "hw.serial_number":
		return true
	default:
		return false
	}
}

// putDirectGNMIJSONIdentityAttribute retains an inherited identity and places
// a nested collision under a deterministic object-path-qualified name. The
// common, non-colliding case preserves the historical attribute name.
func putDirectGNMIJSONIdentityAttribute(attrs map[string]string, attribute, value string, objectPath []string, budget *directGNMIDecodeBudget) bool {
	if _, exists := attrs[attribute]; !exists {
		return putDirectGNMIAttributeValue(attrs, attribute, value, budget)
	}
	return putDirectGNMIScopedIdentityCollision(attrs, "json", attribute, value, objectPath, budget)
}

func putDirectGNMIPathSemanticAttribute(attrs map[string]string, attribute, value string, elementPath []string, budget *directGNMIDecodeBudget) bool {
	if value == "" {
		return true
	}
	if _, exists := attrs[attribute]; !exists {
		return putDirectGNMIAttributeValue(attrs, attribute, value, budget)
	}
	return putDirectGNMIScopedIdentityCollision(attrs, "path", attribute, value, elementPath, budget)
}

func putDirectGNMIScopedIdentityCollision(
	attrs map[string]string,
	scope, attribute, value string,
	identityPath []string,
	budget *directGNMIDecodeBudget,
) bool {
	for index := 1; index <= len(attrs)+1; index++ {
		escaped, ok := directGNMIScopedIdentityAttributeName(scope, attribute, identityPath, index, budget.limits.maxAttributeKeyBytes)
		if !ok {
			budget.drop(false)
			return false
		}
		if _, exists := attrs[escaped]; exists {
			continue
		}
		return putDirectGNMIAttributeValue(attrs, escaped, value, budget)
	}
	budget.drop(false)
	return false
}

func putDirectGNMIPathKeyIdentityCollision(
	attrs map[string]string,
	key, normalized, value string,
	elementPath []string,
	budget *directGNMIDecodeBudget,
) (string, bool) {
	for index := 1; index <= len(attrs)+1; index++ {
		escaped, ok := directGNMIPathKeyIdentityAttributeName(key, normalized, elementPath, index, budget.limits.maxAttributeKeyBytes)
		if !ok {
			budget.drop(false)
			return "", false
		}
		if _, exists := attrs[escaped]; exists {
			continue
		}
		return escaped, putDirectGNMIAttributeValue(attrs, escaped, value, budget)
	}
	budget.drop(false)
	return "", false
}

func directGNMIScopedIdentityAttributeName(scope, attribute string, identityPath []string, index, maximumBytes int) (string, bool) {
	return directGNMIScopedIdentityAttributeNameWithDigest(scope, attribute, "", identityPath, index, maximumBytes)
}

func directGNMIPathKeyIdentityAttributeName(key, normalized string, identityPath []string, index, maximumBytes int) (string, bool) {
	digest := directGNMIScopedIdentityHash("path", key, identityPath, index)
	return directGNMIScopedIdentityAttributeNameWithDigest("path", normalized, digest, identityPath, index, maximumBytes)
}

func directGNMIScopedIdentityAttributeNameWithDigest(scope, attribute, digest string, identityPath []string, index, maximumBytes int) (string, bool) {
	var name strings.Builder
	appendPart := func(value string) bool {
		if value == "" {
			return true
		}
		separator := ""
		if name.Len() > 0 {
			separator = "."
		}
		if name.Len()+len(separator)+len(value) > maximumBytes {
			return false
		}
		name.WriteString(separator)
		name.WriteString(value)
		return true
	}

	if !appendPart(directGNMIIdentityEscapeBase) || !appendPart(scope) {
		return directGNMICompactScopedIdentityAttributeName(scope, attribute, digest, identityPath, index, maximumBytes)
	}
	if index > 1 && !appendPart(strconv.Itoa(index)) {
		return directGNMICompactScopedIdentityAttributeName(scope, attribute, digest, identityPath, index, maximumBytes)
	}
	pathAdded := false
	for _, part := range identityPath {
		cleaned := sanitizeMetricSegment(part)
		if cleaned == "" {
			continue
		}
		if !appendPart(cleaned) {
			return directGNMICompactScopedIdentityAttributeName(scope, attribute, digest, identityPath, index, maximumBytes)
		}
		pathAdded = true
	}
	if !pathAdded && !appendPart("root") {
		return directGNMICompactScopedIdentityAttributeName(scope, attribute, digest, identityPath, index, maximumBytes)
	}
	if digest != "" && !appendPart(digest) {
		return directGNMICompactScopedIdentityAttributeName(scope, attribute, digest, identityPath, index, maximumBytes)
	}
	cleanedAttribute := sanitizeMetricSegment(attribute)
	if cleanedAttribute == "" {
		cleanedAttribute = "attribute"
	}
	if !appendPart(cleanedAttribute) {
		return directGNMICompactScopedIdentityAttributeName(scope, attribute, digest, identityPath, index, maximumBytes)
	}
	return name.String(), true
}

func directGNMICompactScopedIdentityAttributeName(scope, attribute, digest string, identityPath []string, index, maximumBytes int) (string, bool) {
	if digest == "" {
		digest = directGNMIScopedIdentityHash(scope, attribute, identityPath, index)
	}
	compact := directGNMIPathKeyAttributePrefix + scope + "." + digest
	if len(compact) <= maximumBytes {
		return compact, true
	}
	ordinal := directGNMIPathKeyAttributePrefix + strconv.Itoa(index)
	if len(ordinal) <= maximumBytes {
		return ordinal, true
	}
	return "", false
}

func directGNMIScopedIdentityHash(scope, attribute string, identityPath []string, index int) string {
	hash := sha256.New()
	// Length-prefix every component so distinct path segmentations cannot share
	// a digest input. A 128-bit prefix keeps names compact while preventing a
	// device from feasibly engineering scoped-identity collisions.
	add := func(value string) {
		var length [8]byte
		binary.LittleEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	add(scope)
	add(attribute)
	for _, part := range identityPath {
		add(part)
	}
	var ordinal [8]byte
	binary.LittleEndian.PutUint64(ordinal[:], uint64(index))
	_, _ = hash.Write(ordinal[:])
	digest := hash.Sum(nil)
	var encoded [32]byte
	hex.Encode(encoded[:], digest[:16])
	return string(encoded[:])
}

// directGNMIPathKeyAttributes assigns one stable output attribute to every
// scoped PathElem key. The first key retains its historical
// cisco.yang.key.<normalized> name, distinct normalization collisions use
// numbered names, and the same raw key at a deeper element uses a qualified
// path escape. This prevents either collision class from merging identity.
type directGNMIPathKeyAttributes struct {
	inline   [4]directGNMIPathKeyAttribute
	count    int
	overflow map[directGNMIPathKeySource]string
}

type directGNMIPathKeySource struct {
	key   string
	scope int
}

type directGNMIPathKeyAttribute struct {
	source    directGNMIPathKeySource
	attribute string
}

func (a *directGNMIPathKeyAttributes) attribute(source directGNMIPathKeySource) (string, bool) {
	if a.overflow != nil {
		attribute, exists := a.overflow[source]
		return attribute, exists
	}
	for index := 0; index < a.count; index++ {
		if a.inline[index].source == source {
			return a.inline[index].attribute, true
		}
	}
	return "", false
}

func (a *directGNMIPathKeyAttributes) hasKey(key string) bool {
	if a.overflow != nil {
		for source := range a.overflow {
			if source.key == key {
				return true
			}
		}
		return false
	}
	for index := 0; index < a.count; index++ {
		if a.inline[index].source.key == key {
			return true
		}
	}
	return false
}

func (a *directGNMIPathKeyAttributes) record(source directGNMIPathKeySource, attribute string) {
	if a.count < len(a.inline) {
		a.inline[a.count] = directGNMIPathKeyAttribute{source: source, attribute: attribute}
		a.count++
		return
	}
	if a.overflow == nil {
		a.overflow = make(map[directGNMIPathKeySource]string, a.count+1)
		for _, assignment := range a.inline {
			a.overflow[assignment.source] = assignment.attribute
		}
	}
	a.overflow[source] = attribute
	a.count++
}

func (a *directGNMIPathKeyAttributes) put(attrs map[string]string, key, value string, scope int, elementPath []string, budget *directGNMIDecodeBudget) bool {
	if len(directGNMIPathKeyAttributePrefix)+len(key) > budget.limits.maxAttributeKeyBytes {
		budget.drop(false)
		return false
	}
	source := directGNMIPathKeySource{key: key, scope: scope}
	if attribute, exists := a.attribute(source); exists {
		return putDirectGNMIAttributeValue(attrs, attribute, value, budget)
	}

	normalized := sanitizeMetricSegment(key)
	if a.hasKey(key) {
		attribute, ok := putDirectGNMIPathKeyIdentityCollision(attrs, key, normalized, value, elementPath, budget)
		if ok {
			a.record(source, attribute)
		}
		return ok
	}
	for index := 1; index <= len(attrs)+1; index++ {
		attribute := directGNMIPathKeyAttributePrefix + normalized
		if index > 1 {
			attribute = directGNMIPathKeyAttributePrefix + strconv.Itoa(index) + "." + normalized
		}
		if len(attribute) > budget.limits.maxAttributeKeyBytes {
			var ok bool
			attribute, ok = directGNMIScopedIdentityAttributeName("key", normalized, []string{key}, index, budget.limits.maxAttributeKeyBytes)
			if !ok {
				budget.drop(false)
				return false
			}
		}
		if _, occupied := attrs[attribute]; occupied {
			continue
		}
		if !putDirectGNMIAttributeValue(attrs, attribute, value, budget) {
			return false
		}
		a.record(source, attribute)
		return true
	}

	budget.drop(false)
	return false
}

func preferredGNMIPathKeyValue(keys map[string]string, ordered []string, predicate func(string) bool, preferred ...string) string {
	for _, expected := range preferred {
		for _, key := range ordered {
			value := keys[key]
			if strings.EqualFold(key, expected) && value != "" && (predicate == nil || predicate(value)) {
				return value
			}
		}
	}
	return ""
}

func extendDirectGNMIPathNameBytes(current int, part string, maximum int) (int, bool) {
	if part == "" {
		return current, current >= 0 && current <= maximum
	}
	needed := len(part) + 1 // Metric-name separator.
	if current < 0 || current > maximum || needed > maximum-current {
		return 0, false
	}
	return current + needed, true
}

func directGNMIPathNameBytes(parts []string, maximum int) (int, bool) {
	total := 0
	for _, part := range parts {
		var ok bool
		total, ok = extendDirectGNMIPathNameBytes(total, part, maximum)
		if !ok {
			return 0, false
		}
	}
	return total, true
}

func pathPartsAndAttrs(prefix, update *gnmi.Path, budget *directGNMIDecodeBudget) ([]string, map[string]string, bool) {
	parts := make([]string, 0, len(prefix.GetElem())+len(update.GetElem()))
	attrs := map[string]string{}
	pathKeys := directGNMIPathKeyAttributes{}
	var keyScratch [directGNMIHardMaxAttributesPerPoint]string
	pathNameBytes := 0
	appendPart := func(value string) bool {
		next, ok := extendDirectGNMIPathNameBytes(pathNameBytes, value, budget.limits.maxMetricNameBytes)
		if !ok {
			budget.drop(false)
			return false
		}
		pathNameBytes = next
		parts = append(parts, value)
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
			if sanitizeMetricSegment(name) == "" {
				budget.drop(false)
				return false
			}
			if !appendPart(name) {
				return false
			}
			scope := len(parts)
			keys := elem.GetKey()
			if len(keys) > budget.limits.maxAttributes-len(attrs) {
				budget.drop(false)
				return false
			}
			orderedKeys := keyScratch[:0]
			if len(keys) > cap(orderedKeys) {
				// Production limits cap attributes at the inline capacity. Keep
				// lowered/overridden test limits safe without relying on it.
				orderedKeys = make([]string, 0, len(keys))
			}
			for key := range keys {
				orderedKeys = append(orderedKeys, key)
			}
			sort.Strings(orderedKeys)
			for _, key := range orderedKeys {
				if !pathKeys.put(attrs, key, keys[key], scope, parts, budget) {
					return false
				}
			}
			interfaceName := preferredGNMIPathKeyValue(keys, orderedKeys, nil, "interface-name")
			if interfaceName == "" {
				interfaceName = preferredGNMIPathKeyValue(keys, orderedKeys, looksLikeInterfaceName, "name")
			}
			if !putDirectGNMIPathSemanticAttribute(attrs, "network.interface.name", interfaceName, parts, budget) {
				return false
			}
			if !putDirectGNMIPathSemanticAttribute(attrs, "network.vrf.name", preferredGNMIPathKeyValue(keys, orderedKeys, nil, "vrf-name", "vrf"), parts, budget) {
				return false
			}
			if !putDirectGNMIPathSemanticAttribute(attrs, "network.peer.address", preferredGNMIPathKeyValue(keys, orderedKeys, nil, "neighbor-address", "neighbor"), parts, budget) {
				return false
			}
		}
		if len(p.GetElem()) == 0 {
			for _, elem := range p.GetElement() { //nolint:staticcheck // Legacy gNMI paths can still use the deprecated Element representation.
				if !budget.visitField(len(parts) + 1) {
					return false
				}
				if sanitizeMetricSegment(elem) == "" || !appendPart(elem) {
					if sanitizeMetricSegment(elem) == "" {
						budget.drop(false)
					}
					return false
				}
			}
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

func gnmiPathToString(p *gnmi.Path, budget *directGNMIDecodeBudget) (string, bool) {
	if p == nil {
		return "", true
	}
	reject := func() (string, bool) {
		budget.drop(false)
		return "", false
	}
	renderedBytes := 0
	pathNameBytes := 0
	addRenderedBytes := func(count int) bool {
		if count < 0 || count > budget.limits.maxAttributeValueBytes-renderedBytes {
			return false
		}
		renderedBytes += count
		return true
	}
	addPathName := func(value string) bool {
		if value == "" {
			return true
		}
		needed := len(value) + 1 // Metric-name separator.
		if needed > budget.limits.maxMetricNameBytes-pathNameBytes {
			return false
		}
		pathNameBytes += needed
		return true
	}
	encodedOrigin := ""
	if origin := p.GetOrigin(); origin != "" {
		encodedOrigin = escapeDirectGNMIPathComponent(origin, false)
		if !addRenderedBytes(len(encodedOrigin) + 1) { // origin:
			return reject()
		}
	}

	elements := p.GetElem()
	legacyElements := p.GetElement() //nolint:staticcheck // Preserve legacy gNMI Element path compatibility.
	if len(elements) > 0 {
		if len(elements) > budget.limits.maxDepth {
			return reject()
		}
		keyCount := 0
		for index, elem := range elements {
			if index > 0 && !addRenderedBytes(1) { // Path separator.
				return reject()
			}
			name := elem.GetName()
			_, metricName := splitYANGQualifiedName("", name)
			if sanitizeMetricSegment(metricName) == "" {
				return reject()
			}
			if !addRenderedBytes(len(escapeDirectGNMIPathComponent(name, encodedOrigin != "" || index > 0))) {
				return reject()
			}
			if !addPathName(metricName) {
				return reject()
			}
			keys := elem.GetKey()
			if len(keys) > budget.limits.maxAttributes-keyCount {
				return reject()
			}
			keyCount += len(keys)
			for key, value := range keys {
				if len(directGNMIPathKeyAttributePrefix)+len(key) > budget.limits.maxAttributeKeyBytes ||
					len(value) > budget.limits.maxAttributeValueBytes ||
					!addRenderedBytes(len(escapeDirectGNMIPathComponent(key, true))+len(escapeDirectGNMIPathComponent(value, true))+3) { // [key=value]
					return reject()
				}
			}
		}
	} else {
		if len(legacyElements) > budget.limits.maxDepth {
			return reject()
		}
		for index, element := range legacyElements {
			if sanitizeMetricSegment(element) == "" {
				return reject()
			}
			if index > 0 && !addRenderedBytes(1) { // Path separator.
				return reject()
			}
			if !addRenderedBytes(len(escapeDirectGNMIPathComponent(element, encodedOrigin != "" || index > 0))) || !addPathName(element) {
				return reject()
			}
		}
	}

	parts := make([]string, 0, len(p.GetElem()))
	var keyScratch [directGNMIHardMaxAttributesPerPoint]string
	for index, elem := range elements {
		var name strings.Builder
		name.WriteString(escapeDirectGNMIPathComponent(elem.GetName(), encodedOrigin != "" || index > 0))
		if len(elem.GetKey()) > 0 {
			keys := keyScratch[:0]
			if len(elem.GetKey()) > cap(keys) {
				keys = make([]string, 0, len(elem.GetKey()))
			}
			for key := range elem.GetKey() {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				name.WriteByte('[')
				name.WriteString(escapeDirectGNMIPathComponent(key, true))
				name.WriteByte('=')
				name.WriteString(escapeDirectGNMIPathComponent(elem.GetKey()[key], true))
				name.WriteByte(']')
			}
		}
		parts = append(parts, name.String())
	}
	if len(parts) == 0 {
		for index, element := range legacyElements {
			parts = append(parts, escapeDirectGNMIPathComponent(element, encodedOrigin != "" || index > 0))
		}
	}
	out := strings.Join(parts, "/")
	if encodedOrigin != "" {
		out = encodedOrigin + ":" + out
	}
	return out, true
}

// escapeDirectGNMIPathComponent percent-encodes every byte that can be
// mistaken for structural path syntax. Colons remain readable in element,
// key, and value components because module-qualified YANG names use them.
// Origins encode colons and frame the path as origin:. When there is no
// origin, a colon in the first element is encoded so the two forms remain
// distinguishable without changing established origin-qualified paths.
func escapeDirectGNMIPathComponent(value string, allowColon bool) string {
	isSafe := func(ch byte) bool {
		return ch >= 'a' && ch <= 'z' ||
			ch >= 'A' && ch <= 'Z' ||
			ch >= '0' && ch <= '9' ||
			ch == '-' || ch == '.' || ch == '_' || ch == '~' ||
			allowColon && ch == ':'
	}
	needsEscape := false
	for index := 0; index < len(value); index++ {
		if !isSafe(value[index]) {
			needsEscape = true
			break
		}
	}
	if !needsEscape {
		return value
	}
	const hexDigits = "0123456789ABCDEF"
	var escaped strings.Builder
	escaped.Grow(len(value))
	for index := 0; index < len(value); index++ {
		ch := value[index]
		if isSafe(ch) {
			escaped.WriteByte(ch)
			continue
		}
		escaped.WriteByte('%')
		escaped.WriteByte(hexDigits[ch>>4])
		escaped.WriteByte(hexDigits[ch&0x0f])
	}
	return escaped.String()
}
