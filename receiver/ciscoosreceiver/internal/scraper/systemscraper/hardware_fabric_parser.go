// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package systemscraper

import (
	"net"
	"regexp"
	"strings"
)

type hardwareStatus struct {
	Component string
	Name      string
	Slot      string
	State     string
	Value     int64
}

type hardwareTemperature struct {
	Name  string
	Slot  string
	State string
	Value float64
}

type routingNeighbor struct {
	Protocol      string
	VRF           string
	Peer          string
	State         string
	AddressFamily string
	Up            bool
	Prefixes      int64
	HasPrefixes   bool
}

type nvePeerStatus struct {
	Peer  string
	State string
	Up    bool
}

type nveVNIStatus struct {
	VNI   string
	Type  string
	State string
	Up    bool
}

type evpnRouteCounter struct {
	VRF       string
	RouteType string
	Value     int64
}

func parseHardwareHealth(output, source string) ([]hardwareStatus, []hardwareTemperature) {
	var statuses []hardwareStatus
	var temperatures []hardwareTemperature
	component := source
	if strings.Contains(source, "environment") {
		component = "environment"
	}

	for rawLine := range strings.SplitSeq(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.Contains(lower, "fan"):
			component = "fan"
		case strings.Contains(lower, "power") || strings.Contains(lower, "psu"):
			component = "power_supply"
		case strings.Contains(lower, "temperature") || strings.Contains(lower, "temp"):
			component = "temperature"
		case strings.Contains(lower, "module") || strings.Contains(lower, "mod "):
			component = "module"
		}

		if temp, ok := parseHardwareTemperatureLine(line); ok {
			temperatures = append(temperatures, temp)
			statuses = append(statuses, hardwareStatus{
				Component: "temperature",
				Name:      temp.Name,
				Slot:      temp.Slot,
				State:     temp.State,
				Value:     hardwareStatusValue(temp.State),
			})
			continue
		}

		if status, ok := parseHardwareStatusLine(line, component); ok {
			statuses = append(statuses, status)
		}
	}
	return statuses, temperatures
}

func parseHardwareStatusLine(line, component string) (hardwareStatus, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return hardwareStatus{}, false
	}
	state := ""
	for i := len(fields) - 1; i >= 0; i-- {
		if statusLooksKnown(fields[i]) {
			state = normalizeTroubleshootingLabel(fields[i])
			break
		}
	}
	if state == "" {
		return hardwareStatus{}, false
	}
	nameEnd := len(fields)
	for i, field := range fields {
		if normalizeTroubleshootingLabel(field) == state {
			nameEnd = i
			break
		}
	}
	name := strings.Trim(strings.Join(fields[:nameEnd], " "), ":")
	if name == "" || strings.EqualFold(name, "status") {
		return hardwareStatus{}, false
	}
	return hardwareStatus{
		Component: component,
		Name:      name,
		Slot:      firstNumericToken(fields),
		State:     state,
		Value:     hardwareStatusValue(state),
	}, true
}

func parseHardwareTemperatureLine(line string) (hardwareTemperature, bool) {
	lowerLine := strings.ToLower(line)
	if !strings.Contains(lowerLine, "temp") && !strings.Contains(lowerLine, "sensor") && !strings.Contains(lowerLine, "celsius") {
		return hardwareTemperature{}, false
	}
	fields := strings.Fields(strings.ReplaceAll(line, "Celsius", "Cel"))
	if len(fields) < 2 {
		return hardwareTemperature{}, false
	}
	var value float64
	valueIndex := -1
	for i, field := range fields {
		cleanedField := strings.Trim(field, "():,")
		cleaned := strings.TrimSuffix(strings.TrimSuffix(cleanedField, "C"), "Cel")
		if !fieldLooksFloat(cleaned) {
			continue
		}
		nextIsUnit := i+1 < len(fields) && temperatureUnit(fields[i+1])
		currentHasUnit := strings.HasSuffix(cleanedField, "C") || strings.HasSuffix(cleanedField, "Cel")
		if !nextIsUnit && !currentHasUnit {
			continue
		}
		value = parseFloat(cleaned)
		valueIndex = i
		break
	}
	if valueIndex < 0 {
		return hardwareTemperature{}, false
	}
	state := "unknown"
	for i := len(fields) - 1; i > valueIndex; i-- {
		if statusLooksKnown(fields[i]) {
			state = normalizeTroubleshootingLabel(fields[i])
			break
		}
	}
	name := strings.Trim(strings.Join(fields[:valueIndex], " "), ":")
	if name == "" {
		name = "temperature"
	}
	return hardwareTemperature{Name: name, Slot: firstNumericToken(fields[:valueIndex]), State: state, Value: value}, true
}

func temperatureUnit(value string) bool {
	value = strings.ToLower(strings.Trim(value, "():,"))
	return value == "c" || value == "cel" || value == "celsius"
}

func parseRoutingNeighbors(output, protocol, vrf string) []routingNeighbor {
	switch protocol {
	case "bgp":
		return parseBGPNeighbors(output, vrf)
	case "ospf":
		return parseStatefulNeighborRows(output, protocol, vrf, "full")
	case "eigrp":
		return parseEIGRPNeighbors(output, vrf)
	case "isis":
		return parseStatefulNeighborRows(output, protocol, vrf, "up")
	default:
		return nil
	}
}

func parseBGPNeighbors(output, vrf string) []routingNeighbor {
	var neighbors []routingNeighbor
	for rawLine := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(rawLine)
		if len(fields) < 2 || net.ParseIP(fields[0]) == nil {
			continue
		}
		last := fields[len(fields)-1]
		neighbor := routingNeighbor{
			Protocol:      "bgp",
			VRF:           vrf,
			Peer:          fields[0],
			State:         normalizeNeighborState(last),
			AddressFamily: addressFamily(fields[0]),
		}
		if integerFieldLooksNumeric(last) {
			neighbor.State = "established"
			neighbor.Up = true
			neighbor.Prefixes = parseInt(last)
			neighbor.HasPrefixes = true
		} else {
			neighbor.Up = neighborStateUp(neighbor.State, "established")
		}
		neighbors = append(neighbors, neighbor)
	}
	return neighbors
}

func parseStatefulNeighborRows(output, protocol, vrf, upState string) []routingNeighbor {
	var neighbors []routingNeighbor
	for rawLine := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(rawLine)
		if len(fields) < 3 || strings.Contains(strings.ToLower(rawLine), "neighbor") {
			continue
		}
		peer := fields[0]
		state := ""
		for _, field := range fields[1:] {
			normalized := normalizeNeighborState(field)
			if routingNeighborStateLooksKnown(normalized, upState) {
				state = normalized
				break
			}
		}
		if state == "" {
			continue
		}
		neighbors = append(neighbors, routingNeighbor{
			Protocol:      protocol,
			VRF:           vrf,
			Peer:          peer,
			State:         state,
			AddressFamily: addressFamily(peer),
			Up:            neighborStateUp(state, upState),
		})
	}
	return neighbors
}

func routingNeighborStateLooksKnown(state, upState string) bool {
	state = normalizeNeighborState(state)
	if state == upState || strings.Contains(state, upState) || statusLooksKnown(state) {
		return true
	}
	switch state {
	case "2way", "init", "attempt", "exstart", "exchange", "loading":
		return true
	case "idle", "active", "connect", "opensent", "openconfirm":
		return true
	default:
		return false
	}
}

func parseEIGRPNeighbors(output, vrf string) []routingNeighbor {
	var neighbors []routingNeighbor
	for rawLine := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(rawLine)
		if len(fields) < 3 || !integerFieldLooksNumeric(fields[0]) || net.ParseIP(fields[1]) == nil {
			continue
		}
		neighbors = append(neighbors, routingNeighbor{
			Protocol:      "eigrp",
			VRF:           vrf,
			Peer:          fields[1],
			State:         "up",
			AddressFamily: addressFamily(fields[1]),
			Up:            true,
		})
	}
	return neighbors
}

func parseNVEPeers(output string) []nvePeerStatus {
	var peers []nvePeerStatus
	for rawLine := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(rawLine)
		if len(fields) < 2 || net.ParseIP(fields[0]) == nil {
			continue
		}
		state := "unknown"
		for _, field := range fields[1:] {
			normalized := normalizeNeighborState(field)
			if statusLooksKnown(normalized) {
				state = normalized
				break
			}
		}
		peers = append(peers, nvePeerStatus{Peer: fields[0], State: state, Up: neighborStateUp(state, "up")})
	}
	return peers
}

func parseNVEVNIs(output string) []nveVNIStatus {
	var vnis []nveVNIStatus
	for rawLine := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(rawLine)
		if len(fields) < 2 || !integerFieldLooksNumeric(fields[0]) {
			continue
		}
		vniType := "unknown"
		state := "unknown"
		for _, field := range fields[1:] {
			normalized := normalizeTroubleshootingLabel(field)
			if normalized == "l2" || normalized == "l3" || normalized == "cp" || normalized == "dp" {
				vniType = normalized
			}
			if statusLooksKnown(field) {
				state = normalized
			}
		}
		vnis = append(vnis, nveVNIStatus{VNI: fields[0], Type: vniType, State: state, Up: neighborStateUp(state, "up")})
	}
	return vnis
}

func parseEVPNRoutes(output string) []evpnRouteCounter {
	counters := map[string]int64{}
	totalRegexp := regexp.MustCompile(`(?i)(route[- ]?type\s*\d+|type[- ]?\d+|mac/ip|imet|ip prefix|multicast)\D+(\d[\d,]*)`)
	for rawLine := range strings.SplitSeq(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if matches := totalRegexp.FindStringSubmatch(line); len(matches) == 3 {
			counters[normalizeTroubleshootingLabel(matches[1])] += parseInt(matches[2])
			continue
		}
		if strings.Contains(strings.ToLower(line), "route distinguisher") {
			counters["route_distinguisher"]++
		}
	}
	var out []evpnRouteCounter
	for routeType, value := range counters {
		out = append(out, evpnRouteCounter{VRF: "default", RouteType: routeType, Value: value})
	}
	return out
}

func hardwareStatusValue(state string) int64 {
	state = normalizeTroubleshootingLabel(state)
	switch {
	case state == "ok" || state == "good" || state == "pass" || state == "passed" || state == "active" || state == "online" || state == "present" || state == "normal":
		return 1
	case strings.Contains(state, "warn") || strings.Contains(state, "minor"):
		return 2
	case strings.Contains(state, "fail") || strings.Contains(state, "crit") || strings.Contains(state, "bad") || strings.Contains(state, "down") || strings.Contains(state, "fault") || strings.Contains(state, "absent"):
		return 0
	default:
		return -1
	}
}

func statusLooksKnown(value string) bool {
	value = normalizeTroubleshootingLabel(value)
	switch value {
	case "ok", "good", "pass", "passed", "active", "online", "present", "normal", "warning", "warn", "minor", "fail", "failed", "critical", "crit", "bad", "down", "fault", "absent", "up", "full", "established":
		return true
	default:
		return strings.Contains(value, "fail") || strings.Contains(value, "warn") || strings.Contains(value, "crit")
	}
}

func normalizeNeighborState(state string) string {
	state = strings.Trim(state, "(),")
	if before, _, ok := strings.Cut(state, "/"); ok {
		state = before
	}
	return normalizeTroubleshootingLabel(state)
}

func neighborStateUp(state, wanted string) bool {
	state = normalizeNeighborState(state)
	return state == wanted || strings.Contains(state, wanted) || state == "up" || state == "full" || state == "established"
}

func addressFamily(value string) string {
	ip := net.ParseIP(value)
	if ip == nil {
		return "unknown"
	}
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

func firstNumericToken(fields []string) string {
	for _, field := range fields {
		field = strings.Trim(field, "[]:,")
		if integerFieldLooksNumeric(field) {
			return field
		}
	}
	return ""
}

func fieldLooksFloat(value string) bool {
	value = strings.TrimSpace(strings.ReplaceAll(value, ",", ""))
	if value == "" {
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

func parseFloat(value string) float64 {
	value = strings.TrimSpace(strings.ReplaceAll(value, ",", ""))
	var result float64
	var divisor float64 = 1
	decimal := false
	sign := float64(1)
	if strings.HasPrefix(value, "-") {
		sign = -1
		value = strings.TrimPrefix(value, "-")
	}
	for _, char := range value {
		if char == '.' {
			decimal = true
			continue
		}
		if char < '0' || char > '9' {
			break
		}
		digit := float64(char - '0')
		if decimal {
			divisor *= 10
			result += digit / divisor
			continue
		}
		result = result*10 + digit
	}
	return result * sign
}
