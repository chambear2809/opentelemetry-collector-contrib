// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package interfacesscraper

import (
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/interfacesscraper/internal/metadata"
)

func (s *interfacesScraper) recordStructuredInterfaceCounters(ts pcommon.Timestamp, intf *Interface) {
	for counterName, value := range intf.Counters {
		if value < 0 {
			continue
		}
		if recordPauseCounter(s.mb, ts, intf.Name, counterName, value) {
			continue
		}
		if recordPolicyCounter(s.mb, ts, intf.Name, counterName, value) {
			continue
		}
		recordQueueCounter(s.mb, ts, intf.Name, counterName, value)
	}
}

func recordPauseCounter(mb *metadata.MetricsBuilder, ts pcommon.Timestamp, interfaceName, counterName string, value int64) bool {
	parts := strings.Split(counterName, "_")
	if !strings.Contains(counterName, "pause_frames") {
		return false
	}
	pauseType := "flowcontrol"
	priority := "all"
	if strings.HasPrefix(counterName, "pfc") {
		pauseType = "pfc"
	}
	direction := metadata.AttributeNetworkIoDirectionReceive
	if strings.Contains(counterName, "_tx_") || strings.Contains(counterName, "_transmit_") {
		direction = metadata.AttributeNetworkIoDirectionTransmit
	}
	if len(parts) >= 3 && parts[0] == "pfc" && parts[1] == "cos" {
		priority = parts[2]
	}
	mb.RecordCiscoInterfacePauseFramesDataPoint(ts, value, interfaceName, direction, pauseType, priority)
	return true
}

func recordQueueCounter(mb *metadata.MetricsBuilder, ts pcommon.Timestamp, interfaceName, counterName string, value int64) bool {
	switch {
	case strings.HasPrefix(counterName, "qos_group_"):
		return recordQOSGroupCounter(mb, ts, interfaceName, counterName, value)
	case strings.HasPrefix(counterName, "qos_wred_"):
		mb.RecordCiscoInterfaceQosQueuePacketsDataPoint(ts, value, interfaceName, metadata.AttributeNetworkIoDirectionTransmit, "unknown", "unknown", "drop", "wred", "queueing")
		return true
	case strings.HasPrefix(counterName, "qos_ingress_mmu_"):
		unit := "packets"
		if strings.HasSuffix(counterName, "_bytes") {
			unit = "bytes"
		}
		if unit == "bytes" {
			mb.RecordCiscoInterfaceQosQueueBytesDataPoint(ts, value, interfaceName, metadata.AttributeNetworkIoDirectionReceive, "ingress_mmu", "unknown", "drop", "mmu", "queueing")
		} else {
			mb.RecordCiscoInterfaceQosQueuePacketsDataPoint(ts, value, interfaceName, metadata.AttributeNetworkIoDirectionReceive, "ingress_mmu", "unknown", "drop", "mmu", "queueing")
		}
		return true
	case strings.HasPrefix(counterName, "pfc_watchdog_qos_group_"):
		return recordPFCWatchdogCounter(mb, ts, interfaceName, counterName, value)
	case strings.HasPrefix(counterName, "hardware_queue_"):
		return recordHardwareQueueCounter(mb, ts, interfaceName, counterName, value)
	default:
		return false
	}
}

func recordQOSGroupCounter(mb *metadata.MetricsBuilder, ts pcommon.Timestamp, interfaceName, counterName string, value int64) bool {
	rest := strings.TrimPrefix(counterName, "qos_group_")
	group, detail, ok := splitQOSGroupCounter(rest)
	if !ok {
		return false
	}
	queue := firstKnownToken(detail, []string{"unicast", "multicast", "broadcast", "oobfc", "queue"})
	action, reason := qosActionAndReason(detail)
	direction := qosDirection(detail)
	switch {
	case strings.HasSuffix(detail, "_bytes"):
		mb.RecordCiscoInterfaceQosQueueBytesDataPoint(ts, value, interfaceName, direction, queue, group, action, reason, "queueing")
	case strings.HasSuffix(detail, "_packets") || strings.Contains(detail, "packet"):
		mb.RecordCiscoInterfaceQosQueuePacketsDataPoint(ts, value, interfaceName, direction, queue, group, action, reason, "queueing")
	default:
		return false
	}
	return true
}

func splitQOSGroupCounter(rest string) (string, string, bool) {
	parts := strings.Split(rest, "_")
	if len(parts) < 2 {
		return "", "", false
	}
	if (parts[0] == "control" || parts[0] == "span") && len(parts) >= 3 && isNumericCounter(parts[1]) {
		return parts[0] + "_" + parts[1], strings.Join(parts[2:], "_"), true
	}
	return parts[0], strings.Join(parts[1:], "_"), true
}

func recordPFCWatchdogCounter(mb *metadata.MetricsBuilder, ts pcommon.Timestamp, interfaceName, counterName string, value int64) bool {
	rest := strings.TrimPrefix(counterName, "pfc_watchdog_qos_group_")
	group, detail, ok := strings.Cut(rest, "_")
	if !ok || !strings.Contains(detail, "packet") && !strings.Contains(detail, "event") {
		return false
	}
	action := "event"
	reason := "pfc_watchdog"
	if strings.Contains(detail, "drop") {
		action = "drop"
	}
	if strings.Contains(detail, "drain") {
		action = "drain"
	}
	mb.RecordCiscoInterfaceQosQueuePacketsDataPoint(ts, value, interfaceName, metadata.AttributeNetworkIoDirectionReceive, "pfc_watchdog", group, action, reason, "pfc_watchdog")
	return true
}

func recordHardwareQueueCounter(mb *metadata.MetricsBuilder, ts pcommon.Timestamp, interfaceName, counterName string, value int64) bool {
	rest := strings.TrimPrefix(counterName, "hardware_queue_")
	queue, detail, ok := strings.Cut(rest, "_")
	if !ok {
		return false
	}
	action, reason := qosActionAndReason(detail)
	mb.RecordCiscoInterfaceQosQueueBytesDataPoint(ts, value, interfaceName, metadata.AttributeNetworkIoDirectionTransmit, queue, "unknown", action, reason, "platform_queue_stats")
	return true
}

func recordPolicyCounter(mb *metadata.MetricsBuilder, ts pcommon.Timestamp, interfaceName, counterName string, value int64) bool {
	if !strings.HasPrefix(counterName, "qos_policy_class_") {
		return false
	}
	rest := strings.TrimPrefix(counterName, "qos_policy_class_")
	className := rest
	detail := ""
	for _, marker := range []string{"_wred_class_", "_wred_total_drop_", "_matched_", "_queue_matched_", "_total_drops", "_no_buffer_drops", "_output_", "_police_"} {
		if before, after, ok := strings.Cut(rest, marker); ok {
			className = before
			detail = strings.TrimPrefix(marker, "_") + after
			break
		}
	}
	if detail == "" {
		return false
	}
	action, reason := qosActionAndReason(detail)
	direction := qosDirection(detail)
	switch {
	case strings.HasSuffix(detail, "_bytes"):
		mb.RecordCiscoInterfaceQosPolicyBytesDataPoint(ts, value, interfaceName, direction, className, action, reason, "policy_map")
	case strings.HasSuffix(detail, "_packets") || strings.Contains(detail, "drop"):
		mb.RecordCiscoInterfaceQosPolicyPacketsDataPoint(ts, value, interfaceName, direction, className, action, reason, "policy_map")
	default:
		return false
	}
	return true
}

func qosActionAndReason(detail string) (string, string) {
	detail = strings.ToLower(detail)
	switch {
	case strings.Contains(detail, "ecn_mark"):
		return "mark", "ecn"
	case strings.Contains(detail, "wred"):
		if strings.Contains(detail, "drop") {
			return "drop", "wred"
		}
		return "transmit", "wred"
	case strings.Contains(detail, "drop") || strings.Contains(detail, "discard"):
		return "drop", firstKnownToken(detail, []string{"tail", "random", "no_buffer", "shared_buffer", "qeb", "policer", "mmu"})
	case strings.Contains(detail, "enqueue"):
		return "enqueue", "none"
	case strings.Contains(detail, "matched"):
		return "match", "none"
	case strings.Contains(detail, "output") || strings.Contains(detail, "transmit") || strings.Contains(detail, "sent"):
		return "transmit", "none"
	case strings.Contains(detail, "received"):
		return "receive", "none"
	default:
		return "unknown", "unknown"
	}
}

func qosDirection(detail string) metadata.AttributeNetworkIoDirection {
	detail = strings.ToLower(detail)
	if strings.Contains(detail, "rx") || strings.Contains(detail, "receive") || strings.Contains(detail, "ingress") {
		return metadata.AttributeNetworkIoDirectionReceive
	}
	return metadata.AttributeNetworkIoDirectionTransmit
}

func firstKnownToken(detail string, candidates []string) string {
	for _, candidate := range candidates {
		if strings.Contains(detail, candidate) {
			return candidate
		}
	}
	return "unknown"
}
