// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package systemscraper // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/systemscraper"

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type controlPlaneCPUProcess struct {
	PID         string
	Name        string
	Window      string
	Utilization float64
}

type controlPlanePacketCounter struct {
	Source    string
	Class     string
	Direction string
	Value     int64
}

type controlPlaneDropCounter struct {
	Source string
	Class  string
	Reason string
	Value  int64
}

type controlPlanePuntRate struct {
	Queue     string
	Interface string
	Value     int64
}

type routingRouteCounter struct {
	VRF           string
	Source        string
	AddressFamily string
	Value         int64
}

type arpCounter struct {
	VRF           string
	AddressFamily string
	Value         int64
}

type fibCounter struct {
	VRF           string
	AddressFamily string
	Value         int64
}

type adjacencyCounter struct {
	VRF   string
	State string
	Value int64
}

type forwardingDropCounter struct {
	VRF    string
	Reason string
	Value  int64
}

type qfpDatapathRate struct {
	Direction        string
	TrafficClass     string
	Window           string
	PacketsPerSecond int64
	BitsPerSecond    int64
}

type qfpDatapathUtilization struct {
	LoadType string
	Window   string
	Value    float64
}

type qfpDropCounter struct {
	Source  string
	Reason  string
	Packets int64
	Octets  int64
}

type qfpInterfaceDropCounter struct {
	Interface string
	Direction string
	Packets   int64
}

var (
	percentFieldRegexp          = regexp.MustCompile(`^(\d+(?:\.\d+)?)%$`)
	controlPlaneClassRegexp     = regexp.MustCompile(`(?i)class(?:-map)?\s*[: ]\s*([A-Za-z0-9_.:/ -]+)`)
	classPacketCounterRegexp    = regexp.MustCompile(`(?i)^(\d[\d,]*)\s+packets?,\s+\d[\d,]*\s+bytes?`)
	conformedPacketRegexp       = regexp.MustCompile(`(?i)conformed\s+(\d[\d,]*)\s+packets?`)
	policeDropPacketRegexp      = regexp.MustCompile(`(?i)(?:exceeded|violated)\s+(\d[\d,]*)\s+packets?`)
	dropCounterRegexp           = regexp.MustCompile(`(?i)(?:drop(?:ped|s)?|discard(?:ed|s)?)\D+(\d[\d,]*)|(\d[\d,]*)\s+(?:packets?\s+)?(?:drop(?:ped|s)?|discard(?:ed|s)?)`)
	genericPacketDropRegexp     = regexp.MustCompile(`(?i)^\d[\d,]*\s+packets?\s+(?:drop(?:ped|s)?|discard(?:ed|s)?)$`)
	puntRateRegexp              = regexp.MustCompile(`(?i)(\d[\d,]*)\s*(?:pps|pkts?/sec|packets?/sec)`)
	routeTotalRegexp            = regexp.MustCompile(`(?i)(?:total(?: number of)?(?: routes| prefixes)?|routes total)\D+(\d[\d,]*)`)
	routeColonRegexp            = regexp.MustCompile(`(?i)^([A-Za-z][A-Za-z0-9_.:/ -]+?)\s*:\s*(\d[\d,]*)$`)
	arpTotalRegexp              = regexp.MustCompile(`(?i)^(?:total(?: number of)?(?: arp)? entries|number of arp entries|arp entries)\D+(\d[\d,]*)`)
	fibTotalRegexp              = regexp.MustCompile(`(?i)^(?:total(?: number of)?(?: prefixes| entries)?|fib entries|cef entries)\D+(\d[\d,]*)`)
	fibLeadingTotalRegexp       = regexp.MustCompile(`(?i)^(\d[\d,]*)\s+(?:routes|prefixes|entries)\b`)
	adjacencyTotalRegexp        = regexp.MustCompile(`(?i)^(?:total(?: adjacency)? entries|adjacency entries)\D+(\d[\d,]*)`)
	adjacencyStateRegexp        = regexp.MustCompile(`(?i)^(complete|incomplete|drop|discard|glean|punt|attached|cached|resolved|stale|dynamic|static|others?)\D+(\d[\d,]*)`)
	adjacencyLeadingStateRegexp = regexp.MustCompile(`(?i)^(\d[\d,]*)\s+(complete|incomplete|drop|discard|glean|punt|attached|cached|resolved|stale|dynamic|static|others?)\b`)
	adjacencyColonRegexp        = regexp.MustCompile(`(?i)^([A-Za-z][A-Za-z0-9_.:/ -]+?)\s*:\s*(\d[\d,]*)$`)
	forwardingDropLabeledRegexp = regexp.MustCompile(`(?i)^([A-Za-z][A-Za-z0-9_ /.-]*drop[A-Za-z0-9_ /.-]*)\D+(\d[\d,]*)`)
	qfpRateLineRegexp           = regexp.MustCompile(`(?i)^(?:(Priority|Non-Priority|Total)\s+)?\((pps|bps)\)\s+(.+)$`)
	qfpLoadLineRegexp           = regexp.MustCompile(`(?i)^(?:(Processing):\s*)?(?:(Load|Crypto|RX|TX|Idle):?\s*)?(Load\s*)?\(pct\)\s+(.+)$`)
)

func parseControlPlaneCPUProcesses(output string, topN int) []controlPlaneCPUProcess {
	processes := make([]controlPlaneCPUProcess, 0)
	for rawLine := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(rawLine)
		if len(fields) < 5 || !isInteger(fields[0]) {
			continue
		}

		percentIndexes := make([]int, 0, 4)
		var percentValue float64
		for i, field := range fields {
			matches := percentFieldRegexp.FindStringSubmatch(strings.TrimSpace(field))
			if len(matches) != 2 {
				continue
			}
			if len(percentIndexes) == 0 {
				percentValue, _ = strconv.ParseFloat(matches[1], 64)
			}
			percentIndexes = append(percentIndexes, i)
		}
		if len(percentIndexes) == 0 {
			continue
		}

		nameIndex := percentIndexes[len(percentIndexes)-1] + 1
		nameEnd := len(fields)
		window := "1s"
		if len(percentIndexes) >= 3 {
			window = "5s"
			nameIndex = percentIndexes[2] + 1
			if nameIndex < len(fields) && looksLikeCPUProcessTTY(fields[nameIndex]) {
				nameIndex++
			}
			if percentIndexes[len(percentIndexes)-1] > nameIndex {
				nameEnd = percentIndexes[len(percentIndexes)-1]
			}
		}
		if nameIndex >= nameEnd {
			continue
		}

		processes = append(processes, controlPlaneCPUProcess{
			PID:         fields[0],
			Name:        strings.Join(fields[nameIndex:nameEnd], " "),
			Window:      window,
			Utilization: percentValue / 100,
		})
	}

	sort.SliceStable(processes, func(i, j int) bool {
		return processes[i].Utilization > processes[j].Utilization
	})
	if topN > 0 && len(processes) > topN {
		return processes[:topN]
	}
	return processes
}

func parseControlPlanePolicy(output, source string) ([]controlPlanePacketCounter, []controlPlaneDropCounter) {
	var packets []controlPlanePacketCounter
	var drops []controlPlaneDropCounter
	className := "default"
	recordedPackets := map[string]struct{}{}
	recordedDrops := map[string]struct{}{}

	for rawLine := range strings.SplitSeq(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if matches := controlPlaneClassRegexp.FindStringSubmatch(line); len(matches) == 2 {
			className = normalizeTroubleshootingLabel(matches[1])
			continue
		}
		if shouldRecordControlPlanePacketLine(line) {
			if matches := classPacketCounterRegexp.FindStringSubmatch(line); len(matches) == 2 {
				packets = appendControlPlanePacket(packets, recordedPackets, controlPlanePacketCounter{
					Source:    source,
					Class:     className,
					Direction: protocolDirectionReceive,
					Value:     parseInt(matches[1]),
				})
			}
		} else if matches := conformedPacketRegexp.FindStringSubmatch(line); len(matches) == 2 {
			packets = appendControlPlanePacket(packets, recordedPackets, controlPlanePacketCounter{
				Source:    source,
				Class:     className,
				Direction: protocolDirectionReceive,
				Value:     parseInt(matches[1]),
			})
		}
		if matches := policeDropPacketRegexp.FindStringSubmatch(line); len(matches) == 2 && lineContainsDropAction(line) {
			drops = appendControlPlaneDrop(drops, recordedDrops, controlPlaneDropCounter{
				Source: source,
				Class:  className,
				Reason: "police_drop",
				Value:  parseInt(matches[1]),
			})
		} else if shouldRecordControlPlaneDropLine(line) {
			if matches := dropCounterRegexp.FindStringSubmatch(line); len(matches) == 3 {
				value := matches[1]
				if value == "" {
					value = matches[2]
				}
				reason := controlPlaneDropReason(line, value)
				if genericPacketDropRegexp.MatchString(line) && controlPlaneDropSeen(recordedDrops, source, className, "police_drop") {
					reason = "police_drop"
				}
				drops = appendControlPlaneDrop(drops, recordedDrops, controlPlaneDropCounter{
					Source: source,
					Class:  className,
					Reason: reason,
					Value:  parseInt(value),
				})
			}
		}
	}

	return packets, drops
}

func appendControlPlanePacket(packets []controlPlanePacketCounter, seen map[string]struct{}, packet controlPlanePacketCounter) []controlPlanePacketCounter {
	key := packet.Source + "\x00" + packet.Class + "\x00" + packet.Direction
	if _, ok := seen[key]; ok {
		return packets
	}
	seen[key] = struct{}{}
	return append(packets, packet)
}

func appendControlPlaneDrop(drops []controlPlaneDropCounter, seen map[string]struct{}, drop controlPlaneDropCounter) []controlPlaneDropCounter {
	key := controlPlaneDropKey(drop.Source, drop.Class, drop.Reason)
	if _, ok := seen[key]; ok {
		return drops
	}
	seen[key] = struct{}{}
	return append(drops, drop)
}

func controlPlaneDropSeen(seen map[string]struct{}, source, class, reason string) bool {
	_, ok := seen[controlPlaneDropKey(source, class, reason)]
	return ok
}

func controlPlaneDropKey(source, class, reason string) string {
	return source + "\x00" + class + "\x00" + reason
}

func controlPlaneDropReason(line, value string) string {
	if value != "" {
		line = strings.Replace(line, value, "", 1)
	}
	return normalizeTroubleshootingLabel(line)
}

func lineContainsDropAction(line string) bool {
	return strings.Contains(strings.ToLower(line), "drop")
}

func shouldRecordControlPlanePacketLine(line string) bool {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "burst") || strings.Contains(lower, "dropped") || strings.Contains(lower, "drops") || strings.Contains(lower, "drop rate") {
		return false
	}
	return classPacketCounterRegexp.MatchString(line)
}

func shouldRecordControlPlaneDropLine(line string) bool {
	if strings.Contains(strings.ToLower(line), "drop rate") {
		return false
	}
	return dropCounterRegexp.MatchString(line)
}

func parseControlPlanePuntRates(output string) []controlPlanePuntRate {
	rates := make([]controlPlanePuntRate, 0)
	for rawLine := range strings.SplitSeq(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.Contains(strings.ToLower(line), "rate") && !puntRateRegexp.MatchString(line) {
			continue
		}
		if rate, ok := parsePuntInterfaceRateLine(line); ok {
			rates = append(rates, rate)
			continue
		}
		if rate, ok := parsePuntCPUQRateLine(line); ok {
			rates = append(rates, rate)
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && isInteger(fields[0]) {
			continue
		}

		label := ""
		if matches := puntRateRegexp.FindStringSubmatch(line); len(matches) == 2 {
			value := parseInt(matches[1])
			if loc := puntRateRegexp.FindStringIndex(line); len(loc) == 2 {
				label = line[:loc[0]]
			}

			if value == 0 && !strings.Contains(strings.ToLower(line), "0") {
				continue
			}

			label = normalizeTroubleshootingLabel(label)
			if label == "" || strings.Contains(label, "queue rate") {
				continue
			}

			rate := controlPlanePuntRate{Queue: label, Value: value}
			if looksLikeInterface(label) {
				rate.Interface = label
				rate.Queue = "interface"
			}
			rates = append(rates, rate)
			continue
		}
	}
	return rates
}

func parseRouteSummary(output, vrf string) []routingRouteCounter {
	counters := make([]routingRouteCounter, 0)
	seenSources := make(map[string]struct{})
	for rawLine := range strings.SplitSeq(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if source, value, ok := parseRouteTableLine(line); ok && source == "total" {
			counters = appendRouteCounter(counters, seenSources, routingRouteCounter{VRF: vrf, Source: source, AddressFamily: "ipv4", Value: value})
			continue
		}
		if matches := routeTotalRegexp.FindStringSubmatch(line); len(matches) == 2 {
			counters = appendRouteCounter(counters, seenSources, routingRouteCounter{VRF: vrf, Source: "total", AddressFamily: "ipv4", Value: parseInt(matches[1])})
			continue
		}
		if matches := routeColonRegexp.FindStringSubmatch(line); len(matches) == 3 && isKnownRouteSource(normalizeTroubleshootingLabel(matches[1])) {
			counters = appendRouteCounter(counters, seenSources, routingRouteCounter{VRF: vrf, Source: normalizeTroubleshootingLabel(matches[1]), AddressFamily: "ipv4", Value: parseInt(matches[2])})
			continue
		}
		if source, value, ok := parseRouteTableLine(line); ok {
			counters = appendRouteCounter(counters, seenSources, routingRouteCounter{VRF: vrf, Source: source, AddressFamily: "ipv4", Value: value})
		}
	}
	return counters
}

func parseARPSummary(output, vrf string) []arpCounter {
	for rawLine := range strings.SplitSeq(output, "\n") {
		if matches := arpTotalRegexp.FindStringSubmatch(strings.TrimSpace(rawLine)); len(matches) == 2 {
			return []arpCounter{{VRF: vrf, AddressFamily: "ipv4", Value: parseInt(matches[1])}}
		}
	}
	return nil
}

func parseFIBSummary(output, vrf string) []fibCounter {
	for rawLine := range strings.SplitSeq(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if matches := fibTotalRegexp.FindStringSubmatch(line); len(matches) == 2 {
			return []fibCounter{{VRF: vrf, AddressFamily: "ipv4", Value: parseInt(matches[1])}}
		}
		if matches := fibLeadingTotalRegexp.FindStringSubmatch(line); len(matches) == 2 {
			return []fibCounter{{VRF: vrf, AddressFamily: "ipv4", Value: parseInt(matches[1])}}
		}
	}
	return nil
}

func parseAdjacencySummary(output, vrf string) []adjacencyCounter {
	counters := make([]adjacencyCounter, 0)
	for rawLine := range strings.SplitSeq(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if matches := adjacencyTotalRegexp.FindStringSubmatch(line); len(matches) == 2 {
			counters = append(counters, adjacencyCounter{VRF: vrf, State: "total", Value: parseInt(matches[1])})
			continue
		}
		if matches := adjacencyStateRegexp.FindStringSubmatch(line); len(matches) == 3 {
			counters = append(counters, adjacencyCounter{VRF: vrf, State: normalizeTroubleshootingLabel(matches[1]), Value: parseInt(matches[2])})
			continue
		}
		if matches := adjacencyLeadingStateRegexp.FindStringSubmatch(line); len(matches) == 3 {
			counters = append(counters, adjacencyCounter{VRF: vrf, State: normalizeTroubleshootingLabel(matches[2]), Value: parseInt(matches[1])})
			continue
		}
		if matches := adjacencyColonRegexp.FindStringSubmatch(line); len(matches) == 3 {
			state := normalizeTroubleshootingLabel(matches[1])
			if state == "total" {
				counters = append(counters, adjacencyCounter{VRF: vrf, State: "total", Value: parseInt(matches[2])})
			} else if isKnownAdjacencyState(state) {
				counters = append(counters, adjacencyCounter{VRF: vrf, State: state, Value: parseInt(matches[2])})
			}
		}
	}
	return counters
}

func parseForwardingDrops(output, vrf string) []forwardingDropCounter {
	counters := make([]forwardingDropCounter, 0)
	for rawLine := range strings.SplitSeq(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || !strings.Contains(strings.ToLower(line), "drop") {
			continue
		}
		if forwardingDropLineIsRateOrBytes(line) {
			continue
		}
		if matches := forwardingDropLabeledRegexp.FindStringSubmatch(line); len(matches) == 3 {
			counters = append(counters, forwardingDropCounter{VRF: vrf, Reason: normalizeTroubleshootingLabel(matches[1]), Value: parseInt(matches[2])})
			continue
		}
		if matches := dropCounterRegexp.FindStringSubmatch(line); len(matches) == 3 {
			value := matches[1]
			if value == "" {
				value = matches[2]
			}
			counters = append(counters, forwardingDropCounter{VRF: vrf, Reason: normalizeTroubleshootingLabel(line), Value: parseInt(value)})
		}
	}
	return counters
}

func parseQFPDatapathUtilization(output string) ([]qfpDatapathRate, []qfpDatapathUtilization) {
	rateValues := map[string]*qfpDatapathRate{}
	utilizations := make([]qfpDatapathUtilization, 0)
	direction := ""
	trafficClass := ""

	for rawLine := range strings.SplitSeq(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		if remaining, ok := trimQFPDirectionPrefix(line); ok {
			direction = remaining.direction
			line = remaining.line
		}

		if matches := qfpRateLineRegexp.FindStringSubmatch(line); len(matches) == 4 && direction != "" {
			if matches[1] != "" {
				trafficClass = normalizeQFPTrafficClass(matches[1])
			}
			if trafficClass == "" {
				trafficClass = "total"
			}
			values := parseQFPWindowValues(matches[3])
			for idx, value := range values {
				key := direction + "\x00" + trafficClass + "\x00" + qfpWindowLabel(idx)
				rate := rateValues[key]
				if rate == nil {
					rate = &qfpDatapathRate{
						Direction:    direction,
						TrafficClass: trafficClass,
						Window:       qfpWindowLabel(idx),
					}
					rateValues[key] = rate
				}
				switch strings.ToLower(matches[2]) {
				case "pps":
					rate.PacketsPerSecond = value
				case "bps":
					rate.BitsPerSecond = value
				}
			}
			continue
		}

		if matches := qfpLoadLineRegexp.FindStringSubmatch(line); len(matches) == 5 {
			loadType := normalizeQFPLoadType(matches[1], matches[2])
			if loadType == "" {
				continue
			}
			values := parseQFPWindowValues(matches[4])
			for idx, value := range values {
				utilizations = append(utilizations, qfpDatapathUtilization{
					LoadType: loadType,
					Window:   qfpWindowLabel(idx),
					Value:    float64(value) / 100,
				})
			}
		}
	}

	rates := make([]qfpDatapathRate, 0, len(rateValues))
	for _, rate := range rateValues {
		rates = append(rates, *rate)
	}
	sort.SliceStable(rates, func(i, j int) bool {
		if rates[i].Direction != rates[j].Direction {
			return rates[i].Direction < rates[j].Direction
		}
		if rates[i].TrafficClass != rates[j].TrafficClass {
			return rates[i].TrafficClass < rates[j].TrafficClass
		}
		return qfpWindowIndex(rates[i].Window) < qfpWindowIndex(rates[j].Window)
	})
	return rates, utilizations
}

func parseQFPDrops(output, source string) ([]qfpDropCounter, []qfpInterfaceDropCounter) {
	drops := make([]qfpDropCounter, 0)
	interfaceDrops := make([]qfpInterfaceDropCounter, 0)
	section := ""

	for rawLine := range strings.SplitSeq(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "---") {
			continue
		}

		lower := strings.ToLower(line)
		switch {
		case strings.Contains(lower, "global drop stats"):
			section = "global"
			continue
		case strings.Contains(lower, "drop stats summary") || strings.Contains(lower, "interface rx pkts"):
			section = "interface"
			continue
		}

		if drop, ok := parseQFPGlobalDropLine(line, source); ok {
			drops = append(drops, drop)
			continue
		}
		if section == "interface" {
			if parsed := parseQFPInterfaceDropLine(line); len(parsed) > 0 {
				interfaceDrops = append(interfaceDrops, parsed...)
			}
		}
	}

	return drops, interfaceDrops
}

type qfpDirectionLine struct {
	direction string
	line      string
}

func trimQFPDirectionPrefix(line string) (qfpDirectionLine, bool) {
	lower := strings.ToLower(line)
	switch {
	case strings.HasPrefix(lower, "input:"):
		return qfpDirectionLine{direction: protocolDirectionReceive, line: strings.TrimSpace(line[len("input:"):])}, true
	case strings.HasPrefix(lower, "output:"):
		return qfpDirectionLine{direction: protocolDirectionTransmit, line: strings.TrimSpace(line[len("output:"):])}, true
	default:
		return qfpDirectionLine{}, false
	}
}

func normalizeQFPTrafficClass(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "priority":
		return "priority"
	case "non-priority":
		return "non_priority"
	case "total":
		return "total"
	default:
		return normalizeTroubleshootingLabel(value)
	}
}

func normalizeQFPLoadType(processing, loadType string) string {
	if processing != "" {
		return "processing"
	}
	switch strings.ToLower(strings.TrimSpace(loadType)) {
	case "load":
		return "processing"
	case "crypto":
		return "crypto"
	case "rx":
		return "rx"
	case "tx":
		return "tx"
	case "idle":
		return "idle"
	default:
		return ""
	}
}

func parseQFPWindowValues(valueText string) []int64 {
	fields := strings.Fields(valueText)
	values := make([]int64, 0, 4)
	for _, field := range fields {
		if !integerFieldLooksNumeric(field) {
			continue
		}
		values = append(values, parseInt(field))
		if len(values) == 4 {
			break
		}
	}
	return values
}

func qfpWindowLabel(index int) string {
	switch index {
	case 0:
		return "5s"
	case 1:
		return "1m"
	case 2:
		return "5m"
	case 3:
		return "60m"
	default:
		return "unknown"
	}
}

func qfpWindowIndex(window string) int {
	switch window {
	case "5s":
		return 0
	case "1m":
		return 1
	case "5m":
		return 2
	case "60m":
		return 3
	default:
		return 4
	}
}

func parseQFPGlobalDropLine(line, source string) (qfpDropCounter, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 || !integerFieldLooksNumeric(fields[0]) {
		return qfpDropCounter{}, false
	}
	if !integerFieldLooksNumeric(fields[len(fields)-2]) || !integerFieldLooksNumeric(fields[len(fields)-1]) {
		return qfpDropCounter{}, false
	}
	reason := normalizeTroubleshootingLabel(strings.Join(fields[1:len(fields)-2], " "))
	if reason == "" || strings.Contains(reason, "packet") || strings.Contains(reason, "octet") {
		return qfpDropCounter{}, false
	}
	return qfpDropCounter{
		Source:  source,
		Reason:  reason,
		Packets: parseInt(fields[len(fields)-2]),
		Octets:  parseInt(fields[len(fields)-1]),
	}, true
}

func parseQFPInterfaceDropLine(line string) []qfpInterfaceDropCounter {
	fields := strings.Fields(line)
	if len(fields) < 3 || !looksLikeInterface(fields[0]) {
		return nil
	}
	if !integerFieldLooksNumeric(fields[1]) || !integerFieldLooksNumeric(fields[2]) {
		return nil
	}
	return []qfpInterfaceDropCounter{
		{Interface: fields[0], Direction: protocolDirectionReceive, Packets: parseInt(fields[1])},
		{Interface: fields[0], Direction: protocolDirectionTransmit, Packets: parseInt(fields[2])},
	}
}

func parsePuntCPUQRateLine(line string) (controlPlanePuntRate, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 || !isInteger(fields[0]) {
		return controlPlanePuntRate{}, false
	}
	queue := fields[1]
	if isInteger(queue) || !strings.HasPrefix(strings.ToLower(queue), "cpu_q_") {
		return controlPlanePuntRate{}, false
	}
	if len(fields) < 4 || !integerFieldLooksNumeric(fields[3]) {
		return controlPlanePuntRate{}, false
	}
	return controlPlanePuntRate{
		Queue: normalizeTroubleshootingLabel(queue),
		Value: parseInt(fields[3]),
	}, true
}

func parsePuntInterfaceRateLine(line string) (controlPlanePuntRate, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 || !looksLikeInterface(fields[0]) {
		return controlPlanePuntRate{}, false
	}
	for _, field := range fields[1:] {
		if strings.HasPrefix(strings.ToLower(field), "0x") {
			continue
		}
		if !integerFieldLooksNumeric(field) {
			continue
		}
		return controlPlanePuntRate{
			Queue:     "interface",
			Interface: normalizeTroubleshootingLabel(fields[0]),
			Value:     parseInt(field),
		}, true
	}
	return controlPlanePuntRate{}, false
}

func parseRouteTableLine(line string) (string, int64, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || strings.Contains(strings.ToLower(line), "route source") {
		return "", 0, false
	}
	if !isKnownRouteTableSource(fields[0]) {
		return "", 0, false
	}

	firstNumber := -1
	for i, field := range fields {
		if integerFieldLooksNumeric(field) {
			firstNumber = i
			break
		}
	}
	if firstNumber <= 0 {
		return "", 0, false
	}

	sourceEnd := firstNumber
	countStart := firstNumber
	if routeSourceUsuallyHasProcessID(fields[0]) && len(fields) > firstNumber+2 {
		sourceEnd = firstNumber + 1
		countStart = firstNumber + 1
	}
	if countStart >= len(fields) {
		return "", 0, false
	}

	counts := make([]int64, 0, 2)
	for _, field := range fields[countStart:] {
		if !integerFieldLooksNumeric(field) {
			break
		}
		counts = append(counts, parseInt(field))
		if len(counts) == 2 {
			break
		}
	}
	if len(counts) == 0 {
		return "", 0, false
	}

	value := counts[0]
	if len(counts) > 1 {
		value += counts[1]
	}
	return normalizeTroubleshootingLabel(strings.Join(fields[:sourceEnd], " ")), value, true
}

func forwardingDropLineIsRateOrBytes(line string) bool {
	line = strings.ToLower(line)
	return strings.Contains(line, "drop rate") ||
		strings.Contains(line, "bytes") ||
		strings.Contains(line, "bps") ||
		strings.Contains(line, "pps")
}

func appendRouteCounter(counters []routingRouteCounter, seenSources map[string]struct{}, counter routingRouteCounter) []routingRouteCounter {
	key := counter.VRF + "\x00" + counter.AddressFamily + "\x00" + counter.Source
	if _, ok := seenSources[key]; ok {
		return counters
	}
	seenSources[key] = struct{}{}
	return append(counters, counter)
}

func routeSourceUsuallyHasProcessID(source string) bool {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "eigrp", "ospf", "isis", "is-is", "bgp", "rip":
		return true
	default:
		return false
	}
}

func isKnownRouteTableSource(source string) bool {
	return isKnownRouteSource(normalizeTroubleshootingLabel(source))
}

func isKnownRouteSource(source string) bool {
	source = strings.ToLower(strings.TrimSpace(source))
	for _, prefix := range []string{
		"am",
		"application",
		"attached",
		"aggregate",
		"bgp",
		"connected",
		"direct",
		"discard",
		"eigrp",
		"internal",
		"isis",
		"is_is",
		"local",
		"ospf",
		"rip",
		"static",
		"summary",
		"total",
	} {
		if source == prefix || strings.HasPrefix(source, prefix+"_") {
			return true
		}
	}
	return false
}

func isKnownAdjacencyState(state string) bool {
	switch state {
	case "complete", "incomplete", "drop", "discard", "glean", "punt", "attached", "cached", "resolved", "stale", "dynamic", "static", "other", "others":
		return true
	default:
		return false
	}
}

func normalizeTroubleshootingLabel(label string) string {
	label = strings.ToLower(strings.TrimSpace(label))
	label = strings.Trim(label, ":,")
	label = strings.NewReplacer("(", " ", ")", " ", "/", " ", "-", " ", ".", " ").Replace(label)
	label = strings.Join(strings.Fields(label), "_")
	return label
}

func isInteger(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func integerFieldLooksNumeric(value string) bool {
	value = strings.Trim(value, ",")
	value = strings.ReplaceAll(value, ",", "")
	return isInteger(value)
}

func looksLikeCPUProcessTTY(value string) bool {
	return isInteger(value) || value == "-"
}

func looksLikeInterface(value string) bool {
	value = strings.ToLower(value)
	if !strings.ContainsAny(value, "0123456789") {
		return false
	}
	return strings.HasPrefix(value, "gi") ||
		strings.HasPrefix(value, "te") ||
		strings.HasPrefix(value, "twe") ||
		strings.HasPrefix(value, "twentyfivegige") ||
		strings.HasPrefix(value, "fo") ||
		strings.HasPrefix(value, "forty") ||
		strings.HasPrefix(value, "fi") ||
		strings.HasPrefix(value, "fiftygige") ||
		strings.HasPrefix(value, "hu") ||
		strings.HasPrefix(value, "hundredgige") ||
		strings.HasPrefix(value, "eth") ||
		strings.HasPrefix(value, "ethernet") ||
		strings.HasPrefix(value, "tunnel") ||
		strings.HasPrefix(value, "tu") ||
		strings.HasPrefix(value, "loopback") ||
		strings.HasPrefix(value, "lo") ||
		strings.HasPrefix(value, "vlan") ||
		strings.HasPrefix(value, "vl") ||
		strings.HasPrefix(value, "port-channel") ||
		strings.HasPrefix(value, "po")
}
