// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package interfacesscraper // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/interfacesscraper"

import (
	"regexp"
	"strings"

	"go.uber.org/zap"
)

var (
	counterLabelNonAlphaNumRegexp = regexp.MustCompile(`[^a-z0-9]+`)
	policyInterfaceRegexp         = regexp.MustCompile(`^[A-Za-z]+[A-Za-z-]*\d[A-Za-z0-9/.:_-]*$`)
)

func parseFlowControlCounters(output string, logger *zap.Logger) map[string]map[string]int64 {
	counters := map[string]map[string]int64{}

	lines := strings.SplitSeq(output, "\n")
	for line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 7 || !isInterfaceCounterRow(fields[0]) {
			continue
		}

		rxPause := fields[len(fields)-2]
		txPause := fields[len(fields)-1]
		if !isNumericCounter(rxPause) || !isNumericCounter(txPause) {
			continue
		}

		recordInterfaceCounter(counters, fields[0], "flowcontrol_rx_pause_frames", str2int64(rxPause))
		recordInterfaceCounter(counters, fields[0], "flowcontrol_tx_pause_frames", str2int64(txPause))
	}

	logger.Info("Parsed flow-control counters", zap.Int("interfaces", len(counters)))
	return counters
}

func parsePriorityFlowControlCounters(output string, logger *zap.Logger) map[string]map[string]int64 {
	counters := map[string]map[string]int64{}

	lines := strings.SplitSeq(output, "\n")
	for line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 || !isInterfaceCounterRow(fields[0]) {
			continue
		}

		rxPPP := fields[len(fields)-2]
		txPPP := fields[len(fields)-1]
		if !isNumericCounter(rxPPP) || !isNumericCounter(txPPP) {
			continue
		}

		recordInterfaceCounter(counters, fields[0], "pfc_rx_pause_frames", str2int64(rxPPP))
		recordInterfaceCounter(counters, fields[0], "pfc_tx_pause_frames", str2int64(txPPP))
	}

	logger.Info("Parsed PFC counters", zap.Int("interfaces", len(counters)))
	return counters
}

func parseQueueingCounters(output string, logger *zap.Logger) map[string]map[string]int64 {
	counters := map[string]map[string]int64{}

	queueingForRegexp := regexp.MustCompile(`(?:Egress|Ingress)\s+Queuing\s+for\s+(\S+)`)
	legacyQueueingRegexp := regexp.MustCompile(`^(\S+)\s+queuing information:`)
	qosGroupRegexp := regexp.MustCompile(`\|\s*(?:(CONTROL|SPAN)\s+)?QOS GROUP\s*(\d+)?\s*\|`)
	legacyQosGroupRegexp := regexp.MustCompile(`^\s*qos-group\s+(\d+)\b`)
	colonCounterRegexp := regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9 /+-]+?)\s*:\s*([0-9,]+)\s*$`)
	wredDropRegexp := regexp.MustCompile(`^\s*WRED Drop Pkts\s+([0-9,]+)\s*$`)
	ingressDropRegexp := regexp.MustCompile(`^\s*Ingress MMU Drop (Pkts|Bytes)\s+([0-9,]+)\s*$`)
	pfcPPPRegexp := regexp.MustCompile(`^\s*TxPPP:\s*([0-9,]+),\s*RxPPP:\s*([0-9,]+)\s*$`)

	var currentInterface string
	var currentQOSGroup string
	var queueColumns []string
	inPFCStats := false

	lines := strings.SplitSeq(output, "\n")
	for line := range lines {
		if matches := queueingForRegexp.FindStringSubmatch(line); matches != nil {
			currentInterface = matches[1]
			currentQOSGroup = ""
			queueColumns = nil
			inPFCStats = false
			continue
		}
		if matches := legacyQueueingRegexp.FindStringSubmatch(line); matches != nil {
			currentInterface = matches[1]
			currentQOSGroup = ""
			queueColumns = nil
			inPFCStats = false
			continue
		}
		if currentInterface == "" {
			continue
		}

		if matches := qosGroupRegexp.FindStringSubmatch(line); matches != nil {
			currentQOSGroup = normalizeQOSGroup(matches[1], matches[2])
			queueColumns = nil
			inPFCStats = false
			continue
		}
		if matches := legacyQosGroupRegexp.FindStringSubmatch(line); matches != nil {
			currentQOSGroup = matches[1]
			queueColumns = nil
			inPFCStats = false
			continue
		}

		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "COS QOS Group") {
			inPFCStats = true
			continue
		}
		if inPFCStats {
			if parseQueueingPFCStatsLine(counters, currentInterface, trimmed) {
				continue
			}
		}

		if matches := pfcPPPRegexp.FindStringSubmatch(line); matches != nil {
			recordInterfaceCounter(counters, currentInterface, "pfc_tx_pause_frames", str2int64(matches[1]))
			recordInterfaceCounter(counters, currentInterface, "pfc_rx_pause_frames", str2int64(matches[2]))
			continue
		}
		if matches := wredDropRegexp.FindStringSubmatch(line); matches != nil {
			recordInterfaceCounter(counters, currentInterface, "qos_wred_dropped_packets", str2int64(matches[1]))
			continue
		}
		if matches := ingressDropRegexp.FindStringSubmatch(line); matches != nil {
			unit := "packets"
			if strings.EqualFold(matches[1], "Bytes") {
				unit = "bytes"
			}
			recordInterfaceCounter(counters, currentInterface, "qos_ingress_mmu_dropped_"+unit, str2int64(matches[2]))
			continue
		}

		cells := splitTableCells(line)
		if len(cells) > 1 && currentQOSGroup != "" {
			if len(cells) > 0 && cells[0] == "" && hasNonNumericCells(cells[1:]) {
				queueColumns = normalizeCellLabels(cells[1:])
				continue
			}
			if len(queueColumns) > 0 && len(cells) == len(queueColumns)+1 && !isNumericCounter(cells[0]) {
				label := normalizeCounterLabel(cells[0])
				if isMonotonicQueueCounter(label) {
					for idx, value := range cells[1:] {
						if isNumericCounter(value) {
							recordInterfaceCounter(counters, currentInterface, counterName("qos_group", currentQOSGroup, queueColumns[idx], label), str2int64(value))
						}
					}
				}
				continue
			}
			if len(cells)%2 == 0 {
				for idx := 0; idx+1 < len(cells); idx += 2 {
					label := normalizeCounterLabel(cells[idx])
					value := cells[idx+1]
					if label == "" || !isMonotonicQueueCounter(label) || !isNumericCounter(value) {
						continue
					}
					recordInterfaceCounter(counters, currentInterface, counterName("qos_group", currentQOSGroup, label), str2int64(value))
				}
				continue
			}
		}

		if currentQOSGroup != "" {
			if matches := colonCounterRegexp.FindStringSubmatch(line); matches != nil {
				label := normalizeCounterLabel(matches[1])
				if isMonotonicQueueCounter(label) {
					recordInterfaceCounter(counters, currentInterface, counterName("qos_group", currentQOSGroup, label), str2int64(matches[2]))
				}
			}
		}
	}

	logger.Info("Parsed queueing counters", zap.Int("interfaces", len(counters)))
	return counters
}

func parsePFCWatchdogCounters(output string, logger *zap.Logger) map[string]map[string]int64 {
	counters := map[string]map[string]int64{}

	interfaceRegexp := regexp.MustCompile(`^\s*(\S+)\s+Interface PFC watchdog:`)
	qosGroupRegexp := regexp.MustCompile(`\|\s*QOS GROUP\s+(\d+)\b`)

	var currentInterface string
	var currentQOSGroup string

	lines := strings.SplitSeq(output, "\n")
	for line := range lines {
		if matches := interfaceRegexp.FindStringSubmatch(line); matches != nil {
			currentInterface = matches[1]
			currentQOSGroup = ""
			continue
		}
		if currentInterface == "" {
			continue
		}
		if matches := qosGroupRegexp.FindStringSubmatch(line); matches != nil {
			currentQOSGroup = matches[1]
			continue
		}
		if currentQOSGroup == "" {
			continue
		}

		cells := splitTableCells(line)
		if len(cells) != 2 || !isNumericCounter(cells[1]) {
			continue
		}
		label := normalizePFCWatchdogLabel(cells[0])
		if label == "" {
			continue
		}
		recordInterfaceCounter(counters, currentInterface, counterName("pfc_watchdog_qos_group", currentQOSGroup, label), str2int64(cells[1]))
	}

	logger.Info("Parsed PFC watchdog counters", zap.Int("interfaces", len(counters)))
	return counters
}

func parsePolicyMapInterfaceCounters(output string, logger *zap.Logger) map[string]map[string]int64 {
	counters := map[string]map[string]int64{}

	classMapRegexp := regexp.MustCompile(`^\s*Class-map(?:\s+\([^)]+\))?:\s*([^\s(]+)`)
	packetBytesRegexp := regexp.MustCompile(`^\s*([0-9,]+)\s+packets,\s+([0-9,]+)\s+bytes\b`)
	matchedRegexp := regexp.MustCompile(`^\s*\(pkts matched/bytes matched\)\s+([0-9,]+)/([0-9,]+)`)
	depthDropRegexp := regexp.MustCompile(`^\s*\(depth/total drops/no-buffer drops\)\s+[0-9,]+/([0-9,]+)/([0-9,]+)`)
	totalDropsRegexp := regexp.MustCompile(`^\s*\(total drops\)\s+([0-9,]+)`)
	bytesOutputRegexp := regexp.MustCompile(`^\s*\(bytes output\)\s+([0-9,]+)`)
	packetsOutputRegexp := regexp.MustCompile(`^\s*\((?:pkts|packets) output\)\s+([0-9,]+)`)
	policeActionRegexp := regexp.MustCompile(`^\s*(conformed|exceeded|violated)\s+([0-9,]+)\s+bytes\b`)
	wredRowRegexp := regexp.MustCompile(`^\s*(\S+)\s+([0-9,]+)/([0-9,]+)\s+([0-9,]+)/([0-9,]+)\s+([0-9,]+)/([0-9,]+)\b`)
	ecnRowRegexp := regexp.MustCompile(`^\s*(\S+)\s+([0-9,]+)/([0-9,]+)\s*$`)
	totalWREDDropsRegexp := regexp.MustCompile(`^\s*Total Drops\s*\((Bytes|Packets)\)\s*:\s*([0-9,]+)`)

	var currentInterface string
	var currentClass string
	tableMode := ""

	lines := strings.SplitSeq(output, "\n")
	for line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPolicyInterfaceLine(trimmed) {
			currentInterface = strings.Fields(trimmed)[0]
			currentClass = ""
			tableMode = ""
			continue
		}
		if currentInterface == "" {
			continue
		}

		if matches := classMapRegexp.FindStringSubmatch(line); matches != nil {
			currentClass = normalizeCounterLabel(matches[1])
			tableMode = ""
			continue
		}
		if currentClass == "" {
			continue
		}

		switch {
		case strings.Contains(trimmed, "Transmitted") && strings.Contains(trimmed, "Random drop") && strings.Contains(trimmed, "Tail drop"):
			tableMode = "wred"
			continue
		case strings.Contains(trimmed, "ECN Mark"):
			tableMode = "ecn"
			continue
		case strings.HasPrefix(trimmed, "AFD WRED STATS END"):
			tableMode = ""
			continue
		}

		if tableMode == "wred" {
			if matches := wredRowRegexp.FindStringSubmatch(line); matches != nil {
				virtualClass := normalizeCounterLabel(matches[1])
				prefix := counterName("qos_policy_class", currentClass, "wred_class", virtualClass)
				recordInterfaceCounter(counters, currentInterface, prefix+"_transmitted_packets", str2int64(matches[2]))
				recordInterfaceCounter(counters, currentInterface, prefix+"_transmitted_bytes", str2int64(matches[3]))
				recordInterfaceCounter(counters, currentInterface, prefix+"_random_drop_packets", str2int64(matches[4]))
				recordInterfaceCounter(counters, currentInterface, prefix+"_random_drop_bytes", str2int64(matches[5]))
				recordInterfaceCounter(counters, currentInterface, prefix+"_tail_drop_packets", str2int64(matches[6]))
				recordInterfaceCounter(counters, currentInterface, prefix+"_tail_drop_bytes", str2int64(matches[7]))
				continue
			}
		}
		if tableMode == "ecn" {
			if matches := ecnRowRegexp.FindStringSubmatch(line); matches != nil {
				virtualClass := normalizeCounterLabel(matches[1])
				prefix := counterName("qos_policy_class", currentClass, "wred_class", virtualClass)
				recordInterfaceCounter(counters, currentInterface, prefix+"_ecn_mark_packets", str2int64(matches[2]))
				recordInterfaceCounter(counters, currentInterface, prefix+"_ecn_mark_bytes", str2int64(matches[3]))
				continue
			}
		}

		prefix := counterName("qos_policy_class", currentClass)
		switch {
		case packetBytesRegexp.MatchString(line):
			matches := packetBytesRegexp.FindStringSubmatch(line)
			recordInterfaceCounter(counters, currentInterface, prefix+"_matched_packets", str2int64(matches[1]))
			recordInterfaceCounter(counters, currentInterface, prefix+"_matched_bytes", str2int64(matches[2]))
		case matchedRegexp.MatchString(line):
			matches := matchedRegexp.FindStringSubmatch(line)
			recordInterfaceCounter(counters, currentInterface, prefix+"_queue_matched_packets", str2int64(matches[1]))
			recordInterfaceCounter(counters, currentInterface, prefix+"_queue_matched_bytes", str2int64(matches[2]))
		case depthDropRegexp.MatchString(line):
			matches := depthDropRegexp.FindStringSubmatch(line)
			recordInterfaceCounter(counters, currentInterface, prefix+"_total_drops", str2int64(matches[1]))
			recordInterfaceCounter(counters, currentInterface, prefix+"_no_buffer_drops", str2int64(matches[2]))
		case totalDropsRegexp.MatchString(line):
			matches := totalDropsRegexp.FindStringSubmatch(line)
			recordInterfaceCounter(counters, currentInterface, prefix+"_total_drops", str2int64(matches[1]))
		case bytesOutputRegexp.MatchString(line):
			matches := bytesOutputRegexp.FindStringSubmatch(line)
			recordInterfaceCounter(counters, currentInterface, prefix+"_output_bytes", str2int64(matches[1]))
		case packetsOutputRegexp.MatchString(line):
			matches := packetsOutputRegexp.FindStringSubmatch(line)
			recordInterfaceCounter(counters, currentInterface, prefix+"_output_packets", str2int64(matches[1]))
		case policeActionRegexp.MatchString(line):
			matches := policeActionRegexp.FindStringSubmatch(line)
			recordInterfaceCounter(counters, currentInterface, counterName(prefix, "police", matches[1], "bytes"), str2int64(matches[2]))
		case totalWREDDropsRegexp.MatchString(line):
			matches := totalWREDDropsRegexp.FindStringSubmatch(line)
			unit := "packets"
			if strings.EqualFold(matches[1], "Bytes") {
				unit = "bytes"
			}
			recordInterfaceCounter(counters, currentInterface, prefix+"_wred_total_drop_"+unit, str2int64(matches[2]))
		}
	}

	logger.Info("Parsed policy-map interface counters", zap.Int("interfaces", len(counters)))
	return counters
}

func parsePlatformQueueStatsCounters(output string, logger *zap.Logger) map[string]int64 {
	counters := map[string]int64{}
	section := ""

	lines := strings.SplitSeq(output, "\n")
	for line := range lines {
		switch {
		case strings.Contains(line, "Enqueue Counters"):
			section = "enqueue"
			continue
		case strings.Contains(line, "Drop Counters") || strings.Contains(line, "Hardware Drop Counters"):
			section = "drop"
			continue
		}
		if section == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 || !isNumericCounter(fields[0]) {
			continue
		}

		queue := fields[0]
		switch section {
		case "enqueue":
			if len(fields) < 6 {
				continue
			}
			recordFlatCounter(counters, counterName("hardware_queue", queue, "enqueue_threshold_0_bytes"), str2int64(fields[2]))
			recordFlatCounter(counters, counterName("hardware_queue", queue, "enqueue_threshold_1_bytes"), str2int64(fields[3]))
			recordFlatCounter(counters, counterName("hardware_queue", queue, "enqueue_threshold_2_bytes"), str2int64(fields[4]))
			recordFlatCounter(counters, counterName("hardware_queue", queue, "policer_enqueue_bytes"), str2int64(fields[5]))
		case "drop":
			if len(fields) < 7 {
				continue
			}
			recordFlatCounter(counters, counterName("hardware_queue", queue, "drop_threshold_0_bytes"), str2int64(fields[1]))
			recordFlatCounter(counters, counterName("hardware_queue", queue, "drop_threshold_1_bytes"), str2int64(fields[2]))
			recordFlatCounter(counters, counterName("hardware_queue", queue, "drop_threshold_2_bytes"), str2int64(fields[3]))
			recordFlatCounter(counters, counterName("hardware_queue", queue, "shared_buffer_drop_bytes"), str2int64(fields[4]))
			recordFlatCounter(counters, counterName("hardware_queue", queue, "qeb_drop_bytes"), str2int64(fields[5]))
			recordFlatCounter(counters, counterName("hardware_queue", queue, "policer_drop_bytes"), str2int64(fields[6]))
		}
	}

	logger.Info("Parsed platform queue stats counters", zap.Int("counters", len(counters)))
	return counters
}

func parseQueueingPFCStatsLine(counters map[string]map[string]int64, intfName, line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 7 || !isNumericCounter(fields[0]) {
		return false
	}

	cos := fields[0]
	txCount := fields[4]
	rxCount := fields[6]
	if !isNumericCounter(txCount) || !isNumericCounter(rxCount) {
		return false
	}

	recordInterfaceCounter(counters, intfName, counterName("pfc_cos", cos, "tx_pause_frames"), str2int64(txCount))
	recordInterfaceCounter(counters, intfName, counterName("pfc_cos", cos, "rx_pause_frames"), str2int64(rxCount))
	return true
}

func recordInterfaceCounter(counters map[string]map[string]int64, intfName, name string, value int64) {
	if name == "" {
		return
	}
	if _, ok := counters[intfName]; !ok {
		counters[intfName] = map[string]int64{}
	}
	counters[intfName][name] = value
}

func recordFlatCounter(counters map[string]int64, name string, value int64) {
	if name == "" {
		return
	}
	counters[name] = value
}

func isInterfaceCounterRow(name string) bool {
	if name == "" {
		return false
	}
	return policyInterfaceRegexp.MatchString(name)
}

func isNumericCounter(value string) bool {
	value = strings.ReplaceAll(value, ",", "")
	if value == "" || value == "-" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func splitTableCells(line string) []string {
	if !strings.Contains(line, "|") {
		return nil
	}
	rawCells := strings.Split(strings.Trim(line, "|"), "|")
	cells := make([]string, 0, len(rawCells))
	for _, cell := range rawCells {
		cells = append(cells, strings.TrimSpace(cell))
	}
	return cells
}

func hasNonNumericCells(cells []string) bool {
	for _, cell := range cells {
		if cell != "" && !isNumericCounter(cell) {
			return true
		}
	}
	return false
}

func normalizeCellLabels(cells []string) []string {
	labels := make([]string, 0, len(cells))
	for _, cell := range cells {
		label := normalizeCounterLabel(cell)
		if label != "" {
			labels = append(labels, label)
		}
	}
	return labels
}

func normalizeQOSGroup(prefix, number string) string {
	switch strings.ToLower(prefix) {
	case "control":
		if number == "" {
			return "control"
		}
		return "control_" + number
	case "span":
		if number == "" {
			return "span"
		}
		return "span_" + number
	default:
		return number
	}
}

func normalizeCounterLabel(label string) string {
	label = strings.ToLower(strings.TrimSpace(label))
	label = strings.ReplaceAll(label, "pkts", "packets")
	label = strings.ReplaceAll(label, "byts", "bytes")
	label = strings.ReplaceAll(label, "rcv", "receive")
	label = strings.ReplaceAll(label, "xmit", "transmit")
	label = strings.ReplaceAll(label, "tx", "transmit")
	label = strings.ReplaceAll(label, "rx", "receive")
	label = counterLabelNonAlphaNumRegexp.ReplaceAllString(label, "_")
	label = strings.Trim(label, "_")
	for strings.Contains(label, "__") {
		label = strings.ReplaceAll(label, "__", "_")
	}
	return label
}

func normalizePFCWatchdogLabel(label string) string {
	switch normalizeCounterLabel(label) {
	case "shutdown":
		return "shutdown_events"
	case "restored":
		return "restored_events"
	case "total_packets_drained":
		return "total_packets_drained"
	case "total_packets_dropped":
		return "total_packets_dropped"
	case "total_packets_drained_dropped":
		return "total_packets_drained_dropped"
	case "aggregate_packets_dropped":
		return "aggregate_packets_dropped"
	case "total_ingress_packets_dropped":
		return "total_ingress_packets_dropped"
	case "aggregate_ingress_packets_dropped":
		return "aggregate_ingress_packets_dropped"
	default:
		return ""
	}
}

func isMonotonicQueueCounter(label string) bool {
	if label == "" {
		return false
	}
	if strings.Contains(label, "depth") || strings.Contains(label, "q_size") || strings.Contains(label, "queue_limit") {
		return false
	}
	return strings.Contains(label, "packet") ||
		strings.Contains(label, "byte") ||
		strings.Contains(label, "drop") ||
		strings.Contains(label, "discard")
}

func counterName(parts ...string) string {
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		part = normalizeCounterLabel(part)
		if part != "" {
			normalized = append(normalized, part)
		}
	}
	return strings.Join(normalized, "_")
}

func isPolicyInterfaceLine(line string) bool {
	if line == "" || strings.Contains(line, " ") {
		return false
	}
	if strings.HasPrefix(line, "Class-map") || strings.HasPrefix(line, "Service-policy") {
		return false
	}
	return isInterfaceCounterRow(line)
}

func supportsPlatformQueueStats(name string) bool {
	normalized := normalizeInterfaceName(name)
	return strings.HasPrefix(normalized, "gi") ||
		strings.HasPrefix(normalized, "te") ||
		strings.HasPrefix(normalized, "twe") ||
		strings.HasPrefix(normalized, "fo") ||
		strings.HasPrefix(normalized, "hu") ||
		strings.HasPrefix(normalized, "eth")
}
