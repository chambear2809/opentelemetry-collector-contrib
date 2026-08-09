// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package interfacesscraper // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/interfacesscraper"

import (
	"regexp"
	"strings"
)

type stpInstanceCounter struct {
	State string
	Value int64
}

type stpTopologyChangeCounter struct {
	VLAN      string
	Interface string
	Value     int64
}

type stpBlockedPortCounter struct {
	VLAN      string
	Interface string
	Value     int64
}

type stpStats struct {
	Instances       []stpInstanceCounter
	TopologyChanges []stpTopologyChangeCounter
	BlockedPorts    []stpBlockedPortCounter
}

type portChannelStatus struct {
	Name  string
	State string
	Up    bool
}

type portChannelMemberStatus struct {
	PortChannel string
	Interface   string
	State       string
	Up          bool
}

type lacpPacketCounter struct {
	Interface string
	Type      string
	Direction string
	Value     int64
}

type lacpErrorCounter struct {
	Interface string
	Type      string
	Value     int64
}

type errDisabledInterface struct {
	Interface string
	Reason    string
}

type vpcStatus struct {
	Domain string
	Peer   string
	State  string
	Up     bool
}

type vpcConsistencyFailure struct {
	Check string
	Value int64
}

type transceiverSensor struct {
	Interface string
	Sensor    string
	Lane      string
	Unit      string
	Value     float64
}

type topologyNeighbor struct {
	Protocol          string
	LocalInterface    string
	NeighborName      string
	NeighborInterface string
	NeighborPlatform  string
	NeighborAddress   string
}

var (
	stpVLANRegexp              = regexp.MustCompile(`(?i)\bVLAN(?:0+)?(\d+)\b|Vlan\s+(\d+)`)
	stpInstanceRegexp          = regexp.MustCompile(`(?i)(\d[\d,]*)\s+(?:vlans?|instances?)`)
	stpStateCountRegexp        = regexp.MustCompile(`(?i)(\d[\d,]*)\s+(blocking|forwarding|learning|listening|disabled)`)
	stpTopologyRegexp          = regexp.MustCompile(`(?i)(?:number of topology changes|topology changes)\D+(\d[\d,]*)`)
	stpFromInterfaceRegexp     = regexp.MustCompile(`(?i)\bfrom\s+([A-Za-z][A-Za-z0-9/.-]+)`)
	stpBlockedLineRegexp       = regexp.MustCompile(`(?i)^(?:VLAN(?:0+)?(\d+)|(\d+))\s+(.+)$`)
	stpSummaryTableRegexp      = regexp.MustCompile(`(?i)^(VLAN(?:0+)?\d+|Total)\s+(\d[\d,]*)\s+(\d[\d,]*)\s+(\d[\d,]*)\s+(\d[\d,]*)\s+(\d[\d,]*)\b`)
	portChannelRegexp          = regexp.MustCompile(`(?i)\b(Po(?:rt-channel)?\d+)\(([^)]*)\)`)
	portChannelMemberRegexp    = regexp.MustCompile(`(?i)\b((?:Eth|Ethernet|Gi|GigabitEthernet|Te|TenGigabitEthernet|Twe|TwentyFiveGigE|Fo|FortyGigabitEthernet|Fi|FiftyGigE|Hu|HundredGigE)[A-Za-z0-9/.-]+)\(([^)]*)\)`)
	lacpCounterLineRegexp      = regexp.MustCompile(`(?i)^((?:Eth|Ethernet|Gi|GigabitEthernet|Te|TenGigabitEthernet|Twe|TwentyFiveGigE|Fo|FortyGigabitEthernet|Fi|FiftyGigE|Hu|HundredGigE)[A-Za-z0-9/.-]+)\s+(.+)$`)
	vpcDomainRegexp            = regexp.MustCompile(`(?i)vpc domain id\s*:\s*(\S+)`)
	vpcStatusRegexp            = regexp.MustCompile(`(?i)(peer status|keep-alive status|vpc peer-link status|[A-Za-z0-9 _/-]*consistency status)\s*:\s*(.+)$`)
	vpcConsistencyRegexp       = regexp.MustCompile(`(?i)^([A-Za-z0-9 _/-]*consistency[A-Za-z0-9 _/-]*)\s*:\s*(.+)$`)
	vpcTableLineRegexp         = regexp.MustCompile(`(?i)^(\d+)\s+(\S+)\s+(\S+)\s+(\S+).*$`)
	transceiverKeyValueRegexp  = regexp.MustCompile(`(?i)^([A-Za-z0-9 _/-]+)\s*:\s*(.+)$`)
	transceiverInterfaceRegexp = regexp.MustCompile(`(?i)^((?:Eth|Ethernet|Gi|GigabitEthernet|Te|TenGigabitEthernet|Twe|TwentyFiveGigE|Fo|FortyGigabitEthernet|Fi|FiftyGigE|Hu|HundredGigE)[A-Za-z0-9/.-]+)(?:\s+transceiver|\s*$|\s+)`)
	transceiverLaneRegexp      = regexp.MustCompile(`(?i)^Lane\s+(\S+)`)
	transceiverSensorRegexp    = regexp.MustCompile(`(?i)(Temperature|Voltage|Current|Bias Current|Tx Power|Rx Power|Transmit Power|Receive Power)\s+([-+]?\d+(?:\.\d+)?)\s*([A-Za-z/%]+)?`)
	lldpNeighborRegexp         = regexp.MustCompile(`(?i)^Chassis id:\s*(.+)$`)
	lldpSystemNameRegexp       = regexp.MustCompile(`(?i)^System Name:\s*(.+)$`)
	lldpLocalInterfaceRegexp   = regexp.MustCompile(`(?i)^Local Intf:\s*(.+)$`)
	lldpPortIDRegexp           = regexp.MustCompile(`(?i)^Port id:\s*(.+)$`)
	cdpDeviceIDRegexp          = regexp.MustCompile(`(?i)^Device ID:\s*(.+)$`)
	cdpInterfaceRegexp         = regexp.MustCompile(`(?i)^Interface:\s*([^,]+),\s*Port ID \(outgoing port\):\s*(.+)$`)
	platformRegexp             = regexp.MustCompile(`(?i)Platform:\s*([^,]+)`)
	addressRegexp              = regexp.MustCompile(`(?i)(?:IP address|Management Address|IPv4 Address):\s*([0-9A-Fa-f:.]+)`)
)

func parseSTPStats(output string) stpStats {
	stats := stpStats{}
	currentVLAN := ""
	currentInterface := ""
	inBlockedPorts := false
	pendingTopologyChange := -1

	for rawLine := range strings.SplitSeq(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			inBlockedPorts = false
			continue
		}
		if strings.Contains(strings.ToLower(line), "blocked interfaces list") {
			inBlockedPorts = true
			continue
		}
		if inBlockedPorts && strings.HasPrefix(line, "-") {
			continue
		}
		if vlan := parseSTPVLAN(line); vlan != "" {
			if vlan != currentVLAN {
				currentInterface = ""
			}
			currentVLAN = vlan
		}
		if matches := stpFromInterfaceRegexp.FindStringSubmatch(line); len(matches) == 2 {
			currentInterface = matches[1]
			if pendingTopologyChange >= 0 {
				stats.TopologyChanges[pendingTopologyChange].Interface = currentInterface
				pendingTopologyChange = -1
			}
		}
		if matches := stpInstanceRegexp.FindStringSubmatch(line); len(matches) == 2 {
			stats.Instances = append(stats.Instances, stpInstanceCounter{State: "total", Value: parseInterfaceInt(matches[1])})
		}
		if matches := stpSummaryTableRegexp.FindStringSubmatch(line); len(matches) == 7 && strings.EqualFold(matches[1], "Total") {
			for i, state := range []string{"blocking", "listening", "learning", "forwarding", "active"} {
				stats.Instances = append(stats.Instances, stpInstanceCounter{State: state, Value: parseInterfaceInt(matches[i+2])})
			}
		}
		for _, matches := range stpStateCountRegexp.FindAllStringSubmatch(line, -1) {
			if len(matches) == 3 {
				stats.Instances = append(stats.Instances, stpInstanceCounter{State: normalizeInterfaceLabel(matches[2]), Value: parseInterfaceInt(matches[1])})
			}
		}
		if matches := stpTopologyRegexp.FindStringSubmatch(line); len(matches) == 2 {
			stats.TopologyChanges = append(stats.TopologyChanges, stpTopologyChangeCounter{
				VLAN:      currentVLAN,
				Interface: currentInterface,
				Value:     parseInterfaceInt(matches[1]),
			})
			if currentInterface == "" {
				pendingTopologyChange = len(stats.TopologyChanges) - 1
			}
		}
		if inBlockedPorts && stpBlockedLineRegexp.MatchString(line) {
			matches := stpBlockedLineRegexp.FindStringSubmatch(line)
			vlan := matches[1]
			if vlan == "" {
				vlan = matches[2]
			}
			intfList := strings.NewReplacer(",", " ").Replace(matches[3])
			for intf := range strings.FieldsSeq(intfList) {
				if strings.Contains(strings.ToLower(intf), "interface") {
					continue
				}
				stats.BlockedPorts = append(stats.BlockedPorts, stpBlockedPortCounter{VLAN: vlan, Interface: intf, Value: 1})
			}
		}
	}

	return stats
}

func parsePortChannelSummary(output string) ([]portChannelStatus, []portChannelMemberStatus) {
	var channels []portChannelStatus
	var members []portChannelMemberStatus
	currentChannel := ""
	for rawLine := range strings.SplitSeq(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			currentChannel = ""
			continue
		}
		channelMatches := portChannelRegexp.FindStringSubmatch(line)
		if len(channelMatches) == 3 {
			channel := portChannelStatus{Name: normalizePortChannelName(channelMatches[1]), State: channelMatches[2], Up: strings.Contains(channelMatches[2], "U")}
			channels = append(channels, channel)
			currentChannel = channel.Name
		}
		if currentChannel == "" {
			continue
		}
		for _, memberMatches := range portChannelMemberRegexp.FindAllStringSubmatch(line, -1) {
			if len(memberMatches) != 3 {
				continue
			}
			state := memberMatches[2]
			members = append(members, portChannelMemberStatus{
				PortChannel: currentChannel,
				Interface:   memberMatches[1],
				State:       state,
				Up:          strings.Contains(state, "P") || strings.Contains(state, "U"),
			})
		}
	}
	return channels, members
}

func parseLACPCounters(output string) ([]lacpPacketCounter, []lacpErrorCounter) {
	var packets []lacpPacketCounter
	var errors []lacpErrorCounter
	firstDirection := "transmit"
	secondDirection := "receive"
	firstPacketIndex := 0
	secondPacketIndex := 1
	hasPacketErrorColumn := false
	packetErrorColumnType := ""
	seenHeader := false
	for rawLine := range strings.SplitSeq(output, "\n") {
		line := strings.TrimSpace(rawLine)
		lowerLine := strings.ToLower(line)
		if strings.Contains(lowerLine, "lacp") && strings.Contains(lowerLine, "sent") && strings.Contains(lowerLine, "recv") {
			firstDirection = "transmit"
			secondDirection = "receive"
			secondPacketIndex = 1
			switch {
			case strings.Contains(lowerLine, "illegal"):
				hasPacketErrorColumn = true
				packetErrorColumnType = "illegal"
			case strings.Contains(lowerLine, "unknown"):
				hasPacketErrorColumn = true
				packetErrorColumnType = "unknown"
			case strings.Contains(lowerLine, "err"):
				hasPacketErrorColumn = true
				packetErrorColumnType = "error"
			default:
				hasPacketErrorColumn = false
				packetErrorColumnType = ""
			}
			seenHeader = true
			continue
		}
		if strings.Contains(lowerLine, "lacp") && strings.Contains(lowerLine, "rx") && strings.Contains(lowerLine, "tx") {
			if strings.Index(lowerLine, "rx") < strings.Index(lowerLine, "tx") {
				firstDirection = "receive"
				secondDirection = "transmit"
				secondPacketIndex = -1
			}
			switch {
			case strings.Contains(lowerLine, "illegal"):
				hasPacketErrorColumn = true
				packetErrorColumnType = "illegal"
			case strings.Contains(lowerLine, "unknown"):
				hasPacketErrorColumn = true
				packetErrorColumnType = "unknown"
			case strings.Contains(lowerLine, "err"):
				hasPacketErrorColumn = true
				packetErrorColumnType = "error"
			default:
				hasPacketErrorColumn = false
				packetErrorColumnType = ""
			}
			seenHeader = true
			continue
		}
		if !seenHeader {
			continue
		}
		matches := lacpCounterLineRegexp.FindStringSubmatch(line)
		if len(matches) != 3 {
			continue
		}
		fields := strings.Fields(matches[2])
		if len(fields) < 2 || !interfaceFieldLooksNumeric(fields[0]) {
			continue
		}
		secondIndex := secondPacketIndex
		if secondIndex == -1 {
			secondIndex = len(fields) - 1
			if hasPacketErrorColumn {
				secondIndex--
			}
		}
		if secondIndex <= firstPacketIndex || secondIndex >= len(fields) || !interfaceFieldLooksNumeric(fields[secondIndex]) {
			continue
		}
		packets = append(packets,
			lacpPacketCounter{Interface: matches[1], Type: "lacpdu", Direction: firstDirection, Value: parseInterfaceInt(fields[firstPacketIndex])},
			lacpPacketCounter{Interface: matches[1], Type: "lacpdu", Direction: secondDirection, Value: parseInterfaceInt(fields[secondIndex])},
		)
		if hasPacketErrorColumn && len(fields) > 2 && parseInterfaceInt(fields[len(fields)-1]) > 0 {
			errors = append(errors, lacpErrorCounter{Interface: matches[1], Type: packetErrorColumnType, Value: parseInterfaceInt(fields[len(fields)-1])})
		}
	}
	return packets, errors
}

func parseErrDisabledInterfaces(output string) []errDisabledInterface {
	interfaces := make([]errDisabledInterface, 0)
	for rawLine := range strings.SplitSeq(output, "\n") {
		line := strings.TrimSpace(rawLine)
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.EqualFold(fields[0], "port") || !looksLikeInterfaceName(fields[0]) {
			continue
		}
		for i := 1; i < len(fields); i++ {
			status := normalizeInterfaceLabel(fields[i])
			if status != "err_disabled" && status != "errdisabled" && status != "errdisable" {
				continue
			}
			reason := "unknown"
			reasonStart := i + 1
			if i == len(fields)-1 && i > 1 {
				reasonStart = i - 1
			}
			if reasonStart < len(fields) {
				reason = normalizeInterfaceLabel(strings.Join(fields[reasonStart:], " "))
			}
			interfaces = append(interfaces, errDisabledInterface{Interface: fields[0], Reason: reason})
			break
		}
	}
	return interfaces
}

func parseVPC(output string) ([]vpcStatus, []vpcConsistencyFailure) {
	var statuses []vpcStatus
	var failures []vpcConsistencyFailure
	domain := ""
	currentVPCID := ""
	currentVPCPort := ""
	currentVPCStatus := ""
	for rawLine := range strings.SplitSeq(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if matches := vpcDomainRegexp.FindStringSubmatch(line); len(matches) == 2 {
			domain = matches[1]
			continue
		}
		if matches := vpcStatusRegexp.FindStringSubmatch(line); len(matches) == 3 {
			state := strings.TrimSpace(matches[2])
			statuses = append(statuses, vpcStatus{Domain: domain, Peer: normalizeInterfaceLabel(matches[1]), State: normalizeInterfaceLabel(state), Up: statusLooksUp(state)})
			if !statusLooksUp(state) {
				failures = append(failures, vpcConsistencyFailure{Check: normalizeInterfaceLabel(matches[1]), Value: 1})
			}
			continue
		}
		if matches := vpcConsistencyRegexp.FindStringSubmatch(line); len(matches) == 3 {
			if currentVPCID != "" && normalizeInterfaceLabel(matches[1]) == "consistency" {
				state := strings.TrimSpace(currentVPCStatus + " " + matches[2])
				peer := currentVPCID
				if currentVPCPort != "" {
					peer = currentVPCID + "_" + currentVPCPort
				}
				statuses = append(statuses, vpcStatus{Domain: domain, Peer: peer, State: normalizeInterfaceLabel(state), Up: statusLooksUp(state)})
				if !statusLooksUp(matches[2]) {
					failures = append(failures, vpcConsistencyFailure{Check: "vpc_" + currentVPCID + "_consistency", Value: 1})
				}
				continue
			}
			state := strings.TrimSpace(matches[2])
			if !statusLooksUp(state) {
				failures = append(failures, vpcConsistencyFailure{Check: normalizeInterfaceLabel(matches[1]), Value: 1})
			}
			continue
		}
		if matches := vpcTableLineRegexp.FindStringSubmatch(line); len(matches) == 5 && !strings.EqualFold(matches[1], "id") {
			state := matches[3] + "_" + matches[4]
			statuses = append(statuses, vpcStatus{Domain: domain, Peer: matches[1], State: normalizeInterfaceLabel(state), Up: statusLooksUp(state)})
			continue
		}
		if matches := transceiverKeyValueRegexp.FindStringSubmatch(line); len(matches) == 3 {
			key := normalizeInterfaceLabel(matches[1])
			value := strings.TrimSpace(matches[2])
			switch key {
			case "id":
				currentVPCID = value
				currentVPCPort = ""
				currentVPCStatus = ""
			case "port":
				currentVPCPort = value
			case "status":
				currentVPCStatus = value
			case "consistency":
				if currentVPCID == "" {
					continue
				}
				state := strings.TrimSpace(currentVPCStatus + " " + value)
				peer := currentVPCID
				if currentVPCPort != "" {
					peer = currentVPCID + "_" + currentVPCPort
				}
				statuses = append(statuses, vpcStatus{Domain: domain, Peer: peer, State: normalizeInterfaceLabel(state), Up: statusLooksUp(state)})
				if !statusLooksUp(value) {
					failures = append(failures, vpcConsistencyFailure{Check: "vpc_" + currentVPCID + "_consistency", Value: 1})
				}
			}
		}
	}
	return statuses, failures
}

func parseTransceiverSensors(output string) []transceiverSensor {
	sensors := make([]transceiverSensor, 0)
	currentInterface := ""
	currentLane := ""
	currentSectionSensor := ""
	for rawLine := range strings.SplitSeq(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if sensor := transceiverSectionSensor(line); sensor != "" {
			currentSectionSensor = sensor
			continue
		}
		if matches := transceiverInterfaceRegexp.FindStringSubmatch(line); len(matches) == 2 && looksLikeInterfaceName(matches[1]) {
			currentInterface = matches[1]
			currentLane = ""
		}
		if currentSectionSensor != "" {
			if sensor, ok := parseTransceiverSectionRow(line, currentSectionSensor); ok {
				sensors = append(sensors, sensor)
				currentInterface = sensor.Interface
				continue
			}
		}
		if matches := transceiverLaneRegexp.FindStringSubmatch(line); len(matches) == 2 {
			currentLane = matches[1]
		}
		if transceiverLineIsThreshold(line) {
			continue
		}
		for _, matches := range transceiverSensorRegexp.FindAllStringSubmatch(line, -1) {
			if len(matches) != 4 || currentInterface == "" {
				continue
			}
			unit := matches[3]
			if unit == "" {
				unit = "1"
			}
			sensors = append(sensors, transceiverSensor{
				Interface: currentInterface,
				Sensor:    normalizeInterfaceLabel(matches[1]),
				Lane:      currentLane,
				Unit:      unit,
				Value:     str2float64(matches[2]),
			})
		}
	}
	return sensors
}

func parseTopologyNeighbors(output, protocol string) []topologyNeighbor {
	var neighbors []topologyNeighbor
	current := topologyNeighbor{Protocol: protocol}
	flush := func() {
		if current.LocalInterface == "" || current.NeighborName == "" {
			current = topologyNeighbor{Protocol: protocol}
			return
		}
		neighbors = append(neighbors, current)
		current = topologyNeighbor{Protocol: protocol}
	}

	for rawLine := range strings.SplitSeq(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		switch protocol {
		case "lldp":
			if matches := lldpNeighborRegexp.FindStringSubmatch(line); len(matches) == 2 {
				flush()
				current.NeighborName = strings.TrimSpace(matches[1])
				continue
			}
			if matches := lldpSystemNameRegexp.FindStringSubmatch(line); len(matches) == 2 {
				current.NeighborName = strings.TrimSpace(matches[1])
				continue
			}
			if matches := lldpLocalInterfaceRegexp.FindStringSubmatch(line); len(matches) == 2 {
				current.LocalInterface = strings.TrimSpace(matches[1])
				continue
			}
			if matches := lldpPortIDRegexp.FindStringSubmatch(line); len(matches) == 2 {
				current.NeighborInterface = strings.TrimSpace(matches[1])
				continue
			}
		case "cdp":
			if matches := cdpDeviceIDRegexp.FindStringSubmatch(line); len(matches) == 2 {
				flush()
				current.NeighborName = strings.TrimSpace(matches[1])
				continue
			}
			if matches := cdpInterfaceRegexp.FindStringSubmatch(line); len(matches) == 3 {
				current.LocalInterface = strings.TrimSpace(matches[1])
				current.NeighborInterface = strings.TrimSpace(matches[2])
				continue
			}
		}
		if matches := platformRegexp.FindStringSubmatch(line); len(matches) == 2 {
			current.NeighborPlatform = strings.TrimSpace(matches[1])
			continue
		}
		if matches := addressRegexp.FindStringSubmatch(line); len(matches) == 2 {
			current.NeighborAddress = strings.TrimSpace(matches[1])
			continue
		}
	}
	flush()
	return neighbors
}

func parseSTPVLAN(line string) string {
	matches := stpVLANRegexp.FindStringSubmatch(line)
	if len(matches) != 3 {
		return ""
	}
	if matches[1] != "" {
		return matches[1]
	}
	return matches[2]
}

func parseInterfaceInt(raw string) int64 {
	return str2int64(raw)
}

func transceiverLineIsThreshold(line string) bool {
	line = strings.ToLower(line)
	return strings.Contains(line, "threshold") ||
		strings.Contains(line, "alarm") ||
		strings.Contains(line, "warn")
}

func transceiverSectionSensor(line string) string {
	normalized := normalizeInterfaceLabel(line)
	switch normalized {
	case "temperature":
		return "temperature"
	case "voltage":
		return "voltage"
	case "current":
		return "current"
	case "tx_power", "transmit_power":
		return "tx_power"
	case "rx_power", "receive_power":
		return "rx_power"
	}
	if !strings.Contains(normalized, "threshold") {
		return ""
	}
	switch {
	case strings.Contains(normalized, "temperature"):
		return "temperature"
	case strings.Contains(normalized, "voltage"):
		return "voltage"
	case strings.Contains(normalized, "current"):
		return "current"
	case strings.Contains(normalized, "transmit_power") || strings.Contains(normalized, "tx_power"):
		return "tx_power"
	case strings.Contains(normalized, "receive_power") || strings.Contains(normalized, "rx_power"):
		return "rx_power"
	default:
		return ""
	}
}

func parseTransceiverSectionRow(line, sensorName string) (transceiverSensor, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 || !looksLikeInterfaceName(fields[0]) {
		return transceiverSensor{}, false
	}
	if isNotAvailableField(fields[1]) || !fieldLooksFloat(fields[1]) {
		return transceiverSensor{}, false
	}
	unit := transceiverDefaultUnit(sensorName)
	lastField := fields[len(fields)-1]
	if !fieldLooksFloat(lastField) && !strings.EqualFold(lastField, "n/a") {
		unit = lastField
	}
	return transceiverSensor{
		Interface: fields[0],
		Sensor:    sensorName,
		Unit:      unit,
		Value:     str2float64(fields[1]),
	}, true
}

func isNotAvailableField(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "n/a" || value == "na" || value == "n.a."
}

func transceiverDefaultUnit(sensorName string) string {
	switch sensorName {
	case "temperature":
		return "Cel"
	case "voltage":
		return "V"
	case "current":
		return "mA"
	case "tx_power", "rx_power":
		return "dBm"
	default:
		return "1"
	}
}

func fieldLooksFloat(value string) bool {
	value = strings.ReplaceAll(strings.TrimSpace(value), ",", "")
	if value == "" || value == "-" {
		return false
	}
	if value[0] == '-' || value[0] == '+' {
		value = value[1:]
	}
	seenDigit := false
	seenDot := false
	for _, char := range value {
		switch {
		case char >= '0' && char <= '9':
			seenDigit = true
		case char == '.' && !seenDot:
			seenDot = true
		default:
			return false
		}
	}
	return seenDigit
}

func normalizeInterfaceLabel(label string) string {
	label = strings.ToLower(strings.TrimSpace(label))
	label = strings.Trim(label, ":,")
	label = strings.NewReplacer("(", " ", ")", " ", "/", " ", "-", " ", ".", " ").Replace(label)
	return strings.Join(strings.Fields(label), "_")
}

func normalizePortChannelName(name string) string {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(strings.ToLower(name), "po") && !strings.HasPrefix(strings.ToLower(name), "port-channel") {
		return "Port-channel" + strings.TrimPrefix(strings.TrimPrefix(name, "Po"), "po")
	}
	return name
}

func interfaceFieldLooksNumeric(value string) bool {
	if value == "" {
		return false
	}
	value = strings.ReplaceAll(value, ",", "")
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func looksLikeInterfaceName(value string) bool {
	value = strings.ToLower(value)
	if !strings.ContainsAny(value, "0123456789") {
		return false
	}
	return strings.HasPrefix(value, "eth") ||
		strings.HasPrefix(value, "ethernet") ||
		strings.HasPrefix(value, "gi") ||
		strings.HasPrefix(value, "gigabitethernet") ||
		strings.HasPrefix(value, "te") ||
		strings.HasPrefix(value, "tengigabitethernet") ||
		strings.HasPrefix(value, "twe") ||
		strings.HasPrefix(value, "twentyfivegige") ||
		strings.HasPrefix(value, "fo") ||
		strings.HasPrefix(value, "fortygigabitethernet") ||
		strings.HasPrefix(value, "fi") ||
		strings.HasPrefix(value, "fiftygige") ||
		strings.HasPrefix(value, "hu") ||
		strings.HasPrefix(value, "hundredgige")
}

func statusLooksUp(value string) bool {
	value = strings.ToLower(value)
	if strings.Contains(value, "down") ||
		strings.Contains(value, "fail") ||
		strings.Contains(value, "not") ||
		strings.Contains(value, "inconsistent") ||
		strings.Contains(value, "suspend") ||
		strings.Contains(value, "dead") {
		return false
	}
	return strings.Contains(value, "up") ||
		strings.Contains(value, "success") ||
		strings.Contains(value, "formed") ||
		strings.Contains(value, "alive") ||
		strings.Contains(value, "consistent") ||
		strings.Contains(value, "ok")
}
