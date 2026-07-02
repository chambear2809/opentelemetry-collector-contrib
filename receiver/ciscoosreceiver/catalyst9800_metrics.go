// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"net"
	"strings"
	"time"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

const (
	catalyst9800TelemetryTransportDialIn  = iosXRTelemetryTransportDialIn
	catalyst9800TelemetryTransportDialOut = iosXRTelemetryTransportDialOut
)

type catalyst9800Health = iosXRHealth

type catalyst9800MetricContext struct {
	targetName     string
	endpoint       string
	platformFamily string
	transport      string
	yangPath       string
	yangModule     string
}

func newCatalyst9800Metrics(ctx catalyst9800MetricContext) (pmetric.Metrics, pmetric.ScopeMetrics) {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	attrs := rm.Resource().Attributes()
	if ctx.targetName != "" {
		attrs.PutStr("host.name", ctx.targetName)
		attrs.PutStr("host.id", ctx.targetName)
	}
	if ctx.endpoint != "" {
		if host, _, err := net.SplitHostPort(ctx.endpoint); err == nil {
			if _, exists := attrs.Get("host.name"); !exists {
				attrs.PutStr("host.name", host)
			}
			putIPAttr(attrs, "host.ip", host)
		}
	}
	attrs.PutStr("hw.type", "network")
	attrs.PutStr("cisco.os.name", "ios_xe")
	attrs.PutStr("cisco.platform.family", firstNonEmpty(ctx.platformFamily, "catalyst_9800"))
	if ctx.transport != "" {
		attrs.PutStr("cisco.telemetry.transport", ctx.transport)
	}
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/catalyst9800")
	return md, sm
}

func appendCatalyst9800HealthMetrics(md pmetric.Metrics, health *catalyst9800Health, ctx catalyst9800MetricContext, ts pcommon.Timestamp) {
	if health == nil {
		return
	}
	rm := md.ResourceMetrics().AppendEmpty()
	attrs := rm.Resource().Attributes()
	if ctx.targetName != "" {
		attrs.PutStr("host.name", ctx.targetName)
		attrs.PutStr("host.id", ctx.targetName)
	}
	if ctx.endpoint != "" {
		if host, _, err := net.SplitHostPort(ctx.endpoint); err == nil {
			putIPAttr(attrs, "host.ip", host)
		}
	}
	attrs.PutStr("hw.type", "network")
	attrs.PutStr("cisco.os.name", "ios_xe")
	attrs.PutStr("cisco.platform.family", firstNonEmpty(ctx.platformFamily, "catalyst_9800"))
	if ctx.transport != "" {
		attrs.PutStr("cisco.telemetry.transport", ctx.transport)
	}
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/catalyst9800")
	snap := health.snapshotForTarget(ctx.targetName)
	appendGaugeMetric(sm, "cisco.catalyst9800.receiver.active_subscriptions", float64(snap.activeSubscriptions), ts, nil)
	appendSumMetric(sm, "cisco.catalyst9800.receiver.updates", float64(snap.updatesReceived), ts, nil)
	appendSumMetric(sm, "cisco.catalyst9800.receiver.decode_errors", float64(snap.decodeErrors), ts, nil)
	appendSumMetric(sm, "cisco.catalyst9800.receiver.unsupported_paths", float64(snap.unsupportedPaths), ts, nil)
	appendSumMetric(sm, "cisco.catalyst9800.receiver.reconnects", float64(snap.reconnects), ts, nil)
	appendSumMetric(sm, "cisco.catalyst9800.receiver.dropped_datapoints", float64(snap.droppedDatapoints), ts, nil)
	appendSumMetric(sm, "cisco.catalyst9800.receiver.compact_gpb_payloads", float64(snap.compactGPBPayloads), ts, nil)
	appendGaugeMetric(sm, "cisco.wlc.controller.receiver.active_subscriptions", float64(snap.activeSubscriptions), ts, nil)
	appendSumMetric(sm, "cisco.wlc.controller.receiver.updates", float64(snap.updatesReceived), ts, nil)
	appendSumMetric(sm, "cisco.wlc.controller.receiver.decode_errors", float64(snap.decodeErrors), ts, nil)
	if !snap.lastSuccess.IsZero() {
		appendGaugeMetric(sm, "cisco.catalyst9800.receiver.last_success_timestamp", float64(snap.lastSuccess.Unix()), ts, nil)
	}
	if ctx.targetName != "" {
		appendGaugeMetric(sm, "cisco.catalyst9800.receiver.target.subscription.active", float64(boolToInt(snap.targetActive)), ts, nil)
		appendSumMetric(sm, "cisco.catalyst9800.receiver.target.updates", float64(snap.targetUpdatesReceived), ts, nil)
		appendSumMetric(sm, "cisco.catalyst9800.receiver.target.reconnects", float64(snap.targetReconnects), ts, nil)
		if !snap.targetLastSuccess.IsZero() {
			appendGaugeMetric(sm, "cisco.catalyst9800.receiver.target.last_success_timestamp", float64(snap.targetLastSuccess.Unix()), ts, nil)
		}
		appendGaugeMetric(sm, "cisco.wlc.controller.receiver.subscription.active", float64(boolToInt(snap.targetActive)), ts, nil)
	}
}

func appendCatalyst9800MetricNumberIndexed(builder *indexedMetricBuilder, module string, pathParts []string, value metricNumber, ts pcommon.Timestamp, attrs map[string]string) {
	if builder.budget != nil && !builder.budget.allowMetricName("cisco.catalyst9800.yang", module, pathParts, "") {
		return
	}
	name := catalyst9800MetricName(module, pathParts)
	var appended bool
	if isCatalyst9800CounterMetric(pathParts) {
		appended = builder.appendNumber(name, pmetric.MetricTypeSum, value, ts, attrs)
	} else {
		appended = builder.appendNumber(name, pmetric.MetricTypeGauge, value, ts, attrs)
	}
	if appended {
		appendCatalyst9800AliasesForValueIndexed(builder, module, pathParts, value, ts, attrs)
	}
}

func appendCatalyst9800InfoMetricIndexed(builder *indexedMetricBuilder, module string, pathParts []string, value string, ts pcommon.Timestamp, attrs map[string]string) {
	if builder.budget != nil && !builder.budget.allowMetricName("cisco.catalyst9800.yang", module, pathParts, "_info") {
		return
	}
	name := catalyst9800MetricName(module, pathParts) + "_info"
	if !builder.appendInfo(name, value, ts, attrs) {
		return
	}
	appendCatalyst9800AliasesForValueIndexed(builder, module, pathParts, value, ts, attrs)
}

func catalyst9800MetricName(module string, pathParts []string) string {
	parts := []string{"cisco", "catalyst9800", "yang"}
	if module != "" {
		parts = append(parts, sanitizeMetricSegment(module))
	}
	for _, part := range pathParts {
		if cleaned := sanitizeMetricSegment(part); cleaned != "" {
			parts = append(parts, cleaned)
		}
	}
	return strings.Join(parts, ".")
}

func isCatalyst9800CounterMetric(pathParts []string) bool {
	return isUnambiguousYANGCounter(pathParts)
}

func appendCatalyst9800AliasesForValue(sm pmetric.ScopeMetrics, module string, pathParts []string, value any, ts pcommon.Timestamp, attrs map[string]string) {
	appendCatalyst9800AliasesForValueIndexed(newIndexedMetricBuilder(sm, nil), module, pathParts, value, ts, attrs)
}

func appendCatalyst9800AliasesForValueIndexed(builder *indexedMetricBuilder, module string, pathParts []string, value any, ts pcommon.Timestamp, attrs map[string]string) {
	_ = module
	if len(pathParts) == 0 {
		return
	}
	leaf := sanitizeMetricSegment(pathParts[len(pathParts)-1])
	pathText := catalyst9800CanonicalPath(pathParts)
	aliasAttrs := catalyst9800AliasAttrs(attrs)
	numericValue, numeric := typedNumericValue(value)
	textValue := ""
	if !numeric {
		textValue = valueToInfoString(value)
	}

	appendNumber := func(name string, extra map[string]string, asCounter bool, unit ...string) {
		if !numeric {
			return
		}
		next := mergeStringAttrs(aliasAttrs, extra)
		metricType := pmetric.MetricTypeGauge
		if asCounter {
			metricType = pmetric.MetricTypeSum
		}
		if !builder.appendNumber(name, metricType, numericValue, ts, next) {
			return
		}
		if len(unit) > 0 && unit[0] != "" {
			builder.getOrCreate(name, metricType).SetUnit(unit[0])
		}
	}
	appendState := func(name string, extra map[string]string) {
		next := mergeStringAttrs(aliasAttrs, extra)
		if numeric {
			builder.appendNumber(name, pmetric.MetricTypeGauge, numericValue, ts, next)
			return
		}
		if textValue == "" {
			return
		}
		next["state"] = textValue
		if state, ok := catalyst9800StateNumeric(textValue); ok {
			builder.appendNumber(name, pmetric.MetricTypeGauge, doubleMetricNumber(state), ts, next)
			return
		}
		builder.appendNumber(name, pmetric.MetricTypeGauge, doubleMetricNumber(1), ts, next)
	}
	appendInfo := func(name, attrName string) {
		next := mergeStringAttrs(aliasAttrs, nil)
		if numeric {
			textValue = numericValue.String()
		}
		if textValue == "" {
			return
		}
		next[attrName] = textValue
		builder.appendNumber(name, pmetric.MetricTypeGauge, doubleMetricNumber(1), ts, next)
	}

	switch leaf {
	case "is_joined":
		appendState("cisco.wlc.ap.join.status", nil)
	case "last_join_failure_type", "last_error_type":
		appendInfo("cisco.wlc.ap.join.failure.reason.info", "failure.reason")
	case "disconnects", "num_disconnects", "ap_disconnect_count":
		appendNumber("cisco.wlc.ap.disconnect", nil, true)
	case "disconnect_reason", "ap_disconnect_reason":
		appendInfo("cisco.wlc.ap.disconnect.reason.info", "reason")
	case "ap_operation_state", "capwap_state":
		appendState("cisco.wlc.ap.capwap.state", nil)
	case "link_encryption_enabled":
		appendState("cisco.wlc.ap.capwap.encryption.enabled", nil)
	case "rx_util_percentage", "tx_util_percentage", "cca_util_percentage", "rx_noise_channel_utilization", "non_wifi_inter", "bss_chan_util":
		appendNumber("cisco.wlc.rf.channel.utilization", map[string]string{"utilization.type": catalyst9800UtilizationType(leaf)}, false)
		if strings.Contains(pathText, "ssid_counters") {
			appendNumber("cisco.wlc.ssid.channel.utilization", map[string]string{"utilization.type": catalyst9800UtilizationType(leaf)}, false)
		}
	case "noise_floor", "noise":
		appendNumber("cisco.wlc.rf.noise_floor", nil, false)
	case "stations", "num_clients", "client_count":
		appendNumber("cisco.wlc.rf.client.count", nil, false)
	case "chan_changes", "channel_change_count":
		appendNumber("cisco.wlc.rf.channel.change.count", nil, true)
	case "best_chan":
		appendNumber("cisco.wlc.rf.channel.recommended", nil, false)
	case "num_assoc_clients":
		appendNumber("cisco.wlc.ssid.client.count", nil, false)
	case "tx_bytes_data":
		appendNumber("cisco.wlc.ssid.network.io", map[string]string{"direction": "tx"}, true, "By")
	case "rx_bytes_data":
		appendNumber("cisco.wlc.ssid.network.io", map[string]string{"direction": "rx"}, true, "By")
	case "tx_retries", "tx_retries_data", "rx_retries", "rx_retries_data":
		appendNumber("cisco.wlc.ssid.retry.count", map[string]string{"direction": catalyst9800Direction(leaf)}, true)
	case "co_state":
		appendState("cisco.wlc.client.connection.state", nil)
	case "exclude_reason":
		appendInfo("cisco.wlc.client.auth.failure.reason.info", "failure.reason")
	case "most_recent_rssi", "rssi":
		appendNumber("cisco.wlc.client.wireless.rssi", nil, false)
	case "most_recent_snr", "snr":
		appendNumber("cisco.wlc.client.wireless.snr", nil, false)
	case "dot11_roam_type", "mm_client_roam_type", "roam_type":
		appendInfo("cisco.wlc.client.roam.type.info", "roam.type")
	case "roam_failure_count":
		appendNumber("cisco.wlc.client.roam.failure.count", nil, true)
	case "ulink_status", "peer_status", "link_status", "connection_status":
		appendState("cisco.wlc.mobility.peer.status", map[string]string{"status.type": strings.TrimSuffix(leaf, "_status")})
	case "l2_roam_cnt":
		appendNumber("cisco.wlc.mobility.roam.count", map[string]string{"roam.layer": "l2"}, true)
		appendNumber("cisco.wlc.client.roam.count", map[string]string{"roam.layer": "l2"}, true)
	case "l3_roam_cnt":
		appendNumber("cisco.wlc.mobility.roam.count", map[string]string{"roam.layer": "l3"}, true)
		appendNumber("cisco.wlc.client.roam.count", map[string]string{"roam.layer": "l3"}, true)
	case "handoff_sent", "handoff_received", "handoff_received_ok", "handoff_sent_ok":
		appendNumber("cisco.wlc.mobility.handoff.count", map[string]string{"handoff.type": leaf}, true)
	case "handoff_sent_fail", "handoff_received_fail", "handoff_fail", "handoff_failure":
		appendNumber("cisco.wlc.mobility.handoff.failure.count", map[string]string{"handoff.type": leaf}, true)
	case "ha_state", "peer_state":
		appendState("cisco.wlc.ha.state", map[string]string{"ha.role": catalyst9800HARole(leaf)})
	case "ha_enabled":
		appendState("cisco.wlc.ha.enabled", nil)
	case "switchover_count":
		appendNumber("cisco.wlc.ha.switchover.count", nil, true)
	case "standby_failure_count":
		appendNumber("cisco.wlc.ha.standby.failure.count", nil, true)
	case "access_accepts":
		appendNumber("cisco.wlc.auth.radius.access.accept.count", nil, true)
	case "access_rejects":
		appendNumber("cisco.wlc.auth.radius.access.reject.count", nil, true)
	case "authen_timeouts", "acct_timeouts":
		appendNumber("cisco.wlc.auth.radius.timeout.count", map[string]string{"radius.phase": catalyst9800RadiusPhase(leaf)}, true)
	case "authen_avg_response_delay":
		appendNumber("cisco.wlc.auth.radius.response_delay.avg", nil, false)
	case "authen_max_response_delay":
		appendNumber("cisco.wlc.auth.radius.response_delay.max", nil, false)
	case "authen_bad_authenticators":
		appendNumber("cisco.wlc.auth.radius.bad_authenticator.count", nil, true)
	case "authen_responses_seen", "acct_responses_seen", "authen_with_response", "authen_without_response":
		appendNumber("cisco.wlc.auth.radius.response.count", map[string]string{"radius.counter": leaf}, true)
	case "five_seconds", "one_minute", "five_minutes", "five_sec", "one_min", "five_min":
		if strings.Contains(pathText, "cpu") {
			appendNumber("cisco.wlc.controller.cpu.utilization", map[string]string{"interval": leaf}, false)
		}
	case "memory_used", "used_memory", "memory_free", "free_memory":
		appendNumber("cisco.wlc.controller.memory.bytes", map[string]string{"state": catalyst9800MemoryState(leaf)}, false)
	}

	if leaf != "ap_operation_state" && leaf != "capwap_state" && strings.Contains(pathText, "capwap") && strings.HasSuffix(leaf, "state") {
		appendState("cisco.wlc.ap.capwap.state", nil)
	}
	if strings.Contains(pathText, "traffic_stats") {
		switch leaf {
		case "bytes_rx", "bytes_tx":
			appendNumber("cisco.wlc.client.network.io", map[string]string{"direction": catalyst9800Direction(leaf)}, true, "By")
		case "pkts_rx", "pkts_tx":
			appendNumber("cisco.wlc.client.network.packets", map[string]string{"direction": catalyst9800Direction(leaf)}, true, "{packet}")
		}
	}
}

func catalyst9800AliasAttrs(attrs map[string]string) map[string]string {
	out := cloneAttrs(attrs)
	lookup := newCatalyst9800AttrLookup(attrs)
	if value := lookup("wtp-mac", "wtp_mac", "ap-mac", "ap_mac"); value != "" {
		out["cisco.wlc.ap.mac"] = value
	}
	if value := lookup("ap-name", "ap_name", "ap-name-mac", "name"); value != "" {
		out["cisco.wlc.ap.name"] = value
	}
	if value := lookup("slot-id", "slot_id", "radio-slot-id", "radio_slot_id"); value != "" {
		out["cisco.wlc.radio.slot"] = value
	}
	if value := lookup("wlan-id", "wlan_id"); value != "" {
		out["cisco.wlc.wlan.id"] = value
	}
	if value := lookup("ssid", "vap-ssid", "vap_ssid"); value != "" {
		out["cisco.wlc.ssid"] = value
	}
	if value := lookup("client-mac", "client_mac", "ms-mac-address", "ms_mac_address"); value != "" {
		out["cisco.wlc.client.mac"] = value
	}
	if value := lookup("node-ip", "node_ip"); value != "" {
		out["cisco.wlc.mobility.node_ip"] = value
	}
	return out
}

func newCatalyst9800AttrLookup(attrs map[string]string) func(...string) string {
	normalized := map[string]string{}
	for key, value := range attrs {
		if value == "" {
			continue
		}
		lower := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
		normalized[lower] = value
		normalized[sanitizeMetricSegment(key)] = value
		if after, ok := strings.CutPrefix(lower, "cisco.yang.key."); ok {
			normalized[after] = value
		}
		if cleaned := sanitizeMetricSegment(key); strings.HasPrefix(cleaned, "cisco_yang_key_") {
			normalized[strings.TrimPrefix(cleaned, "cisco_yang_key_")] = value
		}
	}
	return func(keys ...string) string {
		for _, key := range keys {
			if value := attrs[key]; value != "" {
				return value
			}
			if value := attrs["cisco.yang.key."+sanitizeMetricSegment(key)]; value != "" {
				return value
			}
			if value := normalized[strings.ToLower(strings.ReplaceAll(key, "-", "_"))]; value != "" {
				return value
			}
			if value := normalized[sanitizeMetricSegment(key)]; value != "" {
				return value
			}
		}
		return ""
	}
}

func mergeStringAttrs(base, extra map[string]string) map[string]string {
	out := cloneAttrs(base)
	for key, value := range extra {
		if value != "" {
			out[key] = value
		}
	}
	return out
}

func catalyst9800CanonicalPath(pathParts []string) string {
	parts := make([]string, 0, len(pathParts))
	for _, part := range pathParts {
		if cleaned := sanitizeMetricSegment(part); cleaned != "" {
			parts = append(parts, cleaned)
		}
	}
	return strings.Join(parts, ".")
}

func catalyst9800StateNumeric(value string) (float64, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "up", "on", "active", "enabled", "joined", "join", "connected", "ready", "ok", "success", "succeeded", "run", "operational":
		return 1, true
	case "false", "no", "down", "off", "inactive", "disabled", "not-joined", "not_joined", "disconnected", "failed", "failure", "error", "reject", "timeout", "standby":
		return 0, true
	default:
		return 0, false
	}
}

func catalyst9800UtilizationType(leaf string) string {
	switch leaf {
	case "rx_util_percentage":
		return "rx"
	case "tx_util_percentage":
		return "tx"
	case "cca_util_percentage", "bss_chan_util":
		return "cca"
	case "rx_noise_channel_utilization":
		return "noise"
	case "non_wifi_inter":
		return "non_wifi"
	default:
		return leaf
	}
}

func catalyst9800Direction(leaf string) string {
	if strings.Contains(leaf, "_rx") || strings.HasPrefix(leaf, "rx_") || strings.HasSuffix(leaf, "_rx") {
		return "rx"
	}
	if strings.Contains(leaf, "_tx") || strings.HasPrefix(leaf, "tx_") || strings.HasSuffix(leaf, "_tx") {
		return "tx"
	}
	return ""
}

func catalyst9800HARole(leaf string) string {
	if leaf == "peer_state" {
		return "peer"
	}
	return "local"
}

func catalyst9800RadiusPhase(leaf string) string {
	if strings.HasPrefix(leaf, "acct_") {
		return "accounting"
	}
	return "authentication"
}

func catalyst9800MemoryState(leaf string) string {
	if strings.Contains(leaf, "free") {
		return "free"
	}
	return "used"
}

type catalyst9800NormalizingConsumer struct {
	next      consumer.Metrics
	config    Catalyst9800Config
	selector  deviceSelectionMatcher
	transport string
	health    *catalyst9800Health
}

func newCatalyst9800NormalizingConsumer(next consumer.Metrics, config Catalyst9800Config, selector deviceSelectionMatcher, transport string, health *catalyst9800Health) consumer.Metrics { //nolint:unparam // Transport remains explicit because the normalizer owns transport attribution.
	return &catalyst9800NormalizingConsumer{next: next, config: config, selector: selector, transport: transport, health: health}
}

func (*catalyst9800NormalizingConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

func (c *catalyst9800NormalizingConsumer) ConsumeMetrics(ctx context.Context, md pmetric.Metrics) error {
	c.normalize(md)
	if c.config.MaxDatapointsPerBatch > 0 {
		dropped := enforceIOSXRDatapointLimit(md, c.config.MaxDatapointsPerBatch)
		if dropped > 0 && c.health != nil {
			c.health.addDroppedDatapoints(int64(dropped))
		}
	}
	if md.MetricCount() == 0 {
		return nil
	}
	return c.next.ConsumeMetrics(ctx, md)
}

func (c *catalyst9800NormalizingConsumer) normalize(md pmetric.Metrics) {
	rms := md.ResourceMetrics()
	rms.RemoveIf(func(rm pmetric.ResourceMetrics) bool {
		resAttrs := rm.Resource().Attributes()
		normalizeHostIPAttr(resAttrs)
		resAttrs.PutStr("hw.type", "network")
		resAttrs.PutStr("cisco.os.name", "ios_xe")
		resAttrs.PutStr("cisco.platform.family", "catalyst_9800")
		resAttrs.PutStr("cisco.telemetry.transport", c.transport)
		if v, ok := resAttrs.Get("cisco.node_id"); ok && v.AsString() != "" {
			if _, exists := resAttrs.Get("host.name"); !exists {
				resAttrs.PutStr("host.name", v.AsString())
			}
			if _, exists := resAttrs.Get("host.id"); !exists {
				resAttrs.PutStr("host.id", v.AsString())
			}
		}
		if !c.selector.empty() && !c.selector.allowsResource(resAttrs) {
			return true
		}
		encodingPath := ""
		if v, ok := resAttrs.Get("cisco.encoding_path"); ok {
			encodingPath = v.AsString()
		}
		module := ""
		if v, ok := resAttrs.Get("cisco.yang.module"); ok {
			module = v.AsString()
		}
		if module == "" {
			module = moduleFromYANGPath(encodingPath)
		}
		resAttrs.Remove("cisco.encoding_path")
		resAttrs.Remove("cisco.yang.path")
		resAttrs.Remove("cisco.yang.module")
		sms := rm.ScopeMetrics()
		for j := 0; j < sms.Len(); j++ {
			sm := sms.At(j)
			metrics := sm.Metrics()
			originalLen := metrics.Len()
			metricIndex := newIndexedMetricBuilder(sm, nil)
			for k := range originalLen {
				metric := metrics.At(k)
				originalName := metric.Name()
				switch originalName {
				case "cisco.yang_grpc.compact_gpb_payloads":
					metric.SetName("cisco.catalyst9800.receiver.compact_gpb_payloads")
					if c.health != nil {
						c.health.addCompactGPBPayloads(metricNumericTotal(metric))
					}
				default:
					if strings.HasPrefix(originalName, "cisco.") && !strings.HasPrefix(originalName, "cisco.catalyst9800.") && !strings.HasPrefix(originalName, "cisco.wlc.") {
						name := strings.TrimPrefix(originalName, "cisco.")
						parts := strings.Split(name, ".")
						appendCatalyst9800AliasesFromMetric(metricIndex, metric, module, parts, encodingPath, c.transport)
						metric.SetName(catalyst9800MetricName(module, parts))
					}
				}
				annotateMetricDatapoints(metric, module, encodingPath, c.transport)
			}
			for k := originalLen; k < metrics.Len(); k++ {
				annotateMetricDatapoints(metrics.At(k), module, encodingPath, c.transport)
			}
			coalesceMetricStreams(sm)
		}
		return rm.ScopeMetrics().Len() == 0
	})
}

func appendCatalyst9800AliasesFromMetric(builder *indexedMetricBuilder, metric pmetric.Metric, module string, parts []string, yangPath, transport string) {
	ts := pcommon.NewTimestampFromTime(time.Now())
	aliasParts := parts
	if len(aliasParts) > 0 && strings.HasSuffix(aliasParts[len(aliasParts)-1], "_info") {
		aliasParts = append([]string{}, aliasParts...)
		aliasParts[len(aliasParts)-1] = strings.TrimSuffix(aliasParts[len(aliasParts)-1], "_info")
	}
	addCommonAttrs := func(attrs pcommon.Map) map[string]string {
		out := pcommonMapToStringMap(attrs)
		if module != "" {
			out["cisco.yang.module"] = module
		}
		if yangPath != "" {
			out["cisco.yang.path"] = yangPath
		}
		if transport != "" {
			out["cisco.telemetry.transport"] = transport
		}
		return out
	}
	switch metric.Type() {
	case pmetric.MetricTypeGauge:
		dps := metric.Gauge().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			dp := dps.At(i)
			if dp.Timestamp() != 0 {
				ts = dp.Timestamp()
			}
			if strings.HasSuffix(metric.Name(), "_info") {
				if v, ok := dp.Attributes().Get("value"); ok {
					appendCatalyst9800AliasesForValueIndexed(builder, module, aliasParts, v.AsString(), ts, addCommonAttrs(dp.Attributes()))
				}
				continue
			}
			appendCatalyst9800AliasesForValueIndexed(builder, module, aliasParts, numberDatapointValue(dp), ts, addCommonAttrs(dp.Attributes()))
		}
	case pmetric.MetricTypeSum:
		dps := metric.Sum().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			dp := dps.At(i)
			if dp.Timestamp() != 0 {
				ts = dp.Timestamp()
			}
			appendCatalyst9800AliasesForValueIndexed(builder, module, aliasParts, numberDatapointValue(dp), ts, addCommonAttrs(dp.Attributes()))
		}
	}
}

func numberDatapointValue(dp pmetric.NumberDataPoint) any {
	switch dp.ValueType() {
	case pmetric.NumberDataPointValueTypeInt:
		return dp.IntValue()
	default:
		return dp.DoubleValue()
	}
}

func pcommonMapToStringMap(attrs pcommon.Map) map[string]string {
	out := make(map[string]string, attrs.Len())
	attrs.Range(func(key string, value pcommon.Value) bool {
		if value.AsString() != "" {
			out[key] = value.AsString()
		}
		return true
	})
	return out
}
