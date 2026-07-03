// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package systemscraper // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/systemscraper"

import (
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
)

type protocolPacketCounter struct {
	Protocol    string
	MessageType string
	Direction   string
	Value       int64
}

type protocolErrorCounter struct {
	Protocol  string
	ErrorType string
	Value     int64
}

type protocolDropCounter struct {
	Protocol string
	Reason   string
	Value    int64
}

type protocolTrafficStats struct {
	Packets []protocolPacketCounter
	Errors  []protocolErrorCounter
	Drops   []protocolDropCounter
}

const (
	protocolDirectionReceive  = "receive"
	protocolDirectionTransmit = "transmit"
)

var (
	numberLabelRegexp      = regexp.MustCompile(`(\d+)\s+([A-Za-z][A-Za-z0-9' /_-]*?)(?:,|$|\()`)
	keyValueCounterRegexp  = regexp.MustCompile(`([A-Za-z][A-Za-z0-9 .()/_-]*):\s*(\d+)`)
	sentReceivedPairRegexp = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_ /-]*?):\s*(\d+)/(\d+)`)
	nxPacketSummaryRegexp  = regexp.MustCompile(`Packets received:\s*(\d+),\s*sent:\s*(\d+),\s*consumed:\s*(\d+)`)
	nxForwardedLineRegexp  = regexp.MustCompile(`Forwarded,\s*unicast:\s*(\d+),\s*multicast:\s*(\d+),\s*Label:\s*(\d+)`)
	nxFragmentLineRegexp   = regexp.MustCompile(`Fragments received:\s*(\d+),\s*fragments sent:\s*(\d+),\s*fragments created:\s*(\d+)`)
	nxFragmentDropsRegexp  = regexp.MustCompile(`Fragments dropped:\s*(\d+),\s*packets with DF:\s*(\d+),\s*packets reassembled:\s*(\d+)`)
	nxFragmentTimeoutRegex = regexp.MustCompile(`Fragments timed out:\s*(\d+)`)
)

func parseProtocolTraffic(output string) protocolTrafficStats {
	stats := protocolTrafficStats{}

	currentProtocol := ""
	currentDirection := ""
	currentMode := "packet"

	lines := strings.SplitSeq(output, "\n")
	for rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}

		if protocol, ok := protocolFromSectionHeader(line); ok {
			currentProtocol = protocol
			currentDirection = ""
			currentMode = "packet"
			continue
		}

		switch line {
		case "Transmission and reception:":
			currentProtocol = "ip"
			currentDirection = ""
			currentMode = "packet"
			continue
		case "Errors:":
			if currentProtocol == "" {
				currentProtocol = "ip"
			}
			currentMode = "error"
			continue
		case "Fragmentation/reassembly:":
			currentProtocol = "ip"
			currentMode = "packet"
			continue
		case "Transmission:":
			currentDirection = protocolDirectionTransmit
			currentMode = "packet"
			continue
		case "Transmission":
			currentDirection = protocolDirectionTransmit
			currentMode = "packet"
			continue
		case "Reception":
			currentDirection = protocolDirectionReceive
			currentMode = "packet"
			continue
		case "Reception:":
			currentDirection = protocolDirectionReceive
			currentMode = "packet"
			continue
		}

		if currentProtocol == "" {
			continue
		}

		if matches := nxPacketSummaryRegexp.FindStringSubmatch(line); len(matches) == 4 {
			stats.addPacket("ip", "total", protocolDirectionReceive, parseInt(matches[1]))
			stats.addPacket("ip", "total", protocolDirectionTransmit, parseInt(matches[2]))
			stats.addPacket("ip", "consumed", protocolDirectionReceive, parseInt(matches[3]))
			continue
		}
		if matches := nxForwardedLineRegexp.FindStringSubmatch(line); len(matches) == 4 {
			stats.addPacket("ip", "forwarded_unicast", protocolDirectionTransmit, parseInt(matches[1]))
			stats.addPacket("ip", "forwarded_multicast", protocolDirectionTransmit, parseInt(matches[2]))
			stats.addPacket("ip", "forwarded_label", protocolDirectionTransmit, parseInt(matches[3]))
			continue
		}
		if matches := nxFragmentLineRegexp.FindStringSubmatch(line); len(matches) == 4 {
			stats.addPacket("ip", "fragments", protocolDirectionReceive, parseInt(matches[1]))
			stats.addPacket("ip", "fragments", protocolDirectionTransmit, parseInt(matches[2]))
			stats.addPacket("ip", "fragments_created", protocolDirectionTransmit, parseInt(matches[3]))
			continue
		}
		if matches := nxFragmentDropsRegexp.FindStringSubmatch(line); len(matches) == 4 {
			stats.addDrop("ip", "fragments_dropped", parseInt(matches[1]))
			stats.addDrop("ip", "do_not_fragment", parseInt(matches[2]))
			stats.addPacket("ip", "fragments_reassembled", protocolDirectionReceive, parseInt(matches[3]))
			continue
		}
		if matches := nxFragmentTimeoutRegex.FindStringSubmatch(line); len(matches) == 2 {
			stats.addDrop("ip", "fragment_timeout", parseInt(matches[1]))
			continue
		}

		switch {
		case strings.HasPrefix(line, "Rcvd:"):
			currentDirection = protocolDirectionReceive
			currentMode = "packet"
			parseNumberLabelCounters(&stats, currentProtocol, currentDirection, currentMode, strings.TrimSpace(strings.TrimPrefix(line, "Rcvd:")))
		case strings.HasPrefix(line, "Sent:"):
			currentDirection = protocolDirectionTransmit
			currentMode = "packet"
			parseNumberLabelCounters(&stats, currentProtocol, currentDirection, currentMode, strings.TrimSpace(strings.TrimPrefix(line, "Sent:")))
		case strings.HasPrefix(line, "Drop:"):
			currentMode = "drop"
			parseNumberLabelCounters(&stats, currentProtocol, currentDirection, currentMode, strings.TrimSpace(strings.TrimPrefix(line, "Drop:")))
		case strings.HasPrefix(line, "Drop due to input queue full:"):
			stats.addDrop(currentProtocol, "input_queue_full", parseInt(strings.TrimSpace(strings.TrimPrefix(line, "Drop due to input queue full:"))))
		case strings.HasPrefix(line, "Frags:"):
			currentProtocol = "ip"
			currentMode = "fragment"
			parseIPFragmentCounters(&stats, currentProtocol, strings.TrimSpace(strings.TrimPrefix(line, "Frags:")))
		case strings.HasPrefix(line, "Bcast:"):
			currentMode = "packet"
			parseReceivedSentCounters(&stats, currentProtocol, "broadcast", strings.TrimSpace(strings.TrimPrefix(line, "Bcast:")))
		case strings.HasPrefix(line, "Mcast:"):
			currentMode = "packet"
			parseReceivedSentCounters(&stats, currentProtocol, "multicast", strings.TrimSpace(strings.TrimPrefix(line, "Mcast:")))
		case parseSentReceivedPairCounters(&stats, currentProtocol, line):
			parseNumberLabelCounters(&stats, currentProtocol, currentDirection, currentMode, line)
		case strings.Contains(line, ":"):
			parseKeyValueCounters(&stats, currentProtocol, currentDirection, currentMode, line)
		default:
			if currentMode == "fragment" {
				parseIPFragmentCounters(&stats, currentProtocol, line)
				continue
			}
			parseNumberLabelCounters(&stats, currentProtocol, currentDirection, currentMode, line)
		}
	}

	return stats
}

func protocolFromSectionHeader(line string) (string, bool) {
	switch {
	case line == "IP statistics:" || line == "IP Software Processed Traffic Statistics" || strings.HasPrefix(line, "RFC 4293: IP Software Processed Traffic Statistics"):
		return "ip", true
	case line == "ICMP statistics:" || line == "ICMP Software Processed Traffic Statistics":
		return "icmp", true
	case line == "TCP statistics:":
		return "tcp", true
	case line == "UDP statistics:":
		return "udp", true
	case line == "ARP statistics:":
		return "arp", true
	case line == "BGP statistics:":
		return "bgp", true
	case strings.HasPrefix(line, "OSPF statistics:"):
		return "ospf", true
	case strings.HasPrefix(line, "EIGRP-IPv4 statistics:"):
		return "eigrp", true
	case strings.HasPrefix(line, "PIM") && strings.Contains(line, "statistics:"):
		return "pim", true
	case strings.HasPrefix(line, "IGMP statistics:"):
		return "igmp", true
	case strings.HasPrefix(line, "Probe statistics:"):
		return "probe", true
	default:
		return "", false
	}
}

func parseNumberLabelCounters(stats *protocolTrafficStats, protocol, direction, mode, line string) {
	for _, match := range numberLabelRegexp.FindAllStringSubmatch(line, -1) {
		if len(match) != 3 {
			continue
		}

		value := parseInt(match[1])
		label := normalizeProtocolLabel(match[2])
		if shouldSkipProtocolLabel(label) {
			continue
		}
		addClassifiedProtocolCounter(stats, protocol, direction, mode, label, value)
	}
}

func parseKeyValueCounters(stats *protocolTrafficStats, protocol, direction, mode, line string) {
	for _, match := range keyValueCounterRegexp.FindAllStringSubmatch(line, -1) {
		if len(match) != 3 {
			continue
		}

		label := normalizeProtocolLabel(match[1])
		if shouldSkipProtocolLabel(label) {
			continue
		}
		addClassifiedProtocolCounter(stats, protocol, direction, mode, label, parseInt(match[2]))
	}
}

func parseSentReceivedPairCounters(stats *protocolTrafficStats, protocol, line string) bool {
	found := false
	for _, match := range sentReceivedPairRegexp.FindAllStringSubmatch(line, -1) {
		if len(match) != 4 {
			continue
		}

		label := normalizeProtocolLabel(match[1])
		if shouldSkipProtocolLabel(label) {
			continue
		}

		found = true
		sent := parseInt(match[2])
		received := parseInt(match[3])
		if isProtocolErrorLabel(label) {
			stats.addError(protocol, label+"_sent", sent)
			stats.addError(protocol, label+"_received", received)
			continue
		}
		if isProtocolDropLabel(label) {
			stats.addDrop(protocol, label+"_sent", sent)
			stats.addDrop(protocol, label+"_received", received)
			continue
		}
		stats.addPacket(protocol, label, protocolDirectionTransmit, sent)
		stats.addPacket(protocol, label, protocolDirectionReceive, received)
	}
	return found
}

func parseIPFragmentCounters(stats *protocolTrafficStats, protocol, line string) {
	for _, match := range numberLabelRegexp.FindAllStringSubmatch(line, -1) {
		if len(match) != 3 {
			continue
		}

		value := parseInt(match[1])
		label := normalizeProtocolLabel(match[2])
		switch label {
		case "reassembled", "packets_reassembled", "total_reassembled":
			stats.addPacket(protocol, "fragments_reassembled", protocolDirectionReceive, value)
		case "fragmented", "fragments", "fragmented_into":
			stats.addPacket(protocol, "fragments", protocolDirectionTransmit, value)
		case "timeouts", "reassembly_timeouts":
			stats.addDrop(protocol, "fragment_timeout", value)
		case "could_not_reassemble", "reassembly_failures":
			stats.addDrop(protocol, "reassembly_failures", value)
		case "could_not_fragment", "cannot_fragment", "failed":
			stats.addDrop(protocol, "cannot_fragment", value)
		default:
			if shouldSkipProtocolLabel(label) {
				continue
			}
			addClassifiedProtocolCounter(stats, protocol, protocolDirectionReceive, "packet", label, value)
		}
	}
}

func parseReceivedSentCounters(stats *protocolTrafficStats, protocol, messageType, line string) {
	receivedRegexp := regexp.MustCompile(`(\d+)\s+received`)
	sentRegexp := regexp.MustCompile(`(\d+)\s+sent`)
	if matches := receivedRegexp.FindStringSubmatch(line); len(matches) == 2 {
		stats.addPacket(protocol, messageType, protocolDirectionReceive, parseInt(matches[1]))
	}
	if matches := sentRegexp.FindStringSubmatch(line); len(matches) == 2 {
		stats.addPacket(protocol, messageType, protocolDirectionTransmit, parseInt(matches[1]))
	}
}

func addClassifiedProtocolCounter(stats *protocolTrafficStats, protocol, direction, mode, label string, value int64) {
	if mode == "drop" || isProtocolDropLabel(label) {
		stats.addDrop(protocol, label, value)
		return
	}
	if mode == "error" || isProtocolErrorLabel(label) {
		stats.addError(protocol, label, value)
		return
	}
	if direction == "" {
		return
	}
	stats.addPacket(protocol, label, direction, value)
}

func isProtocolErrorLabel(label string) bool {
	return strings.Contains(label, "error") ||
		strings.HasPrefix(label, "bad_") ||
		strings.Contains(label, "_bad_") ||
		strings.Contains(label, "checksum") ||
		strings.Contains(label, "format") ||
		strings.Contains(label, "unknown_protocol") ||
		strings.Contains(label, "non_existent_protocol") ||
		strings.Contains(label, "could_not_reassemble")
}

func isProtocolDropLabel(label string) bool {
	return strings.Contains(label, "drop") ||
		strings.Contains(label, "dropped") ||
		strings.Contains(label, "discard") ||
		strings.Contains(label, "fail") ||
		strings.Contains(label, "no_route") ||
		strings.Contains(label, "unresolved") ||
		strings.Contains(label, "no_adjacency") ||
		strings.Contains(label, "unicast_rpf") ||
		strings.Contains(label, "forced_drop") ||
		strings.Contains(label, "encapsulation_failed") ||
		strings.Contains(label, "source_ip_address_zero") ||
		strings.Contains(label, "could_not_forward") ||
		strings.Contains(label, "cannot_fragment") ||
		strings.Contains(label, "cant_frag") ||
		strings.Contains(label, "no_port")
}

func normalizeProtocolLabel(label string) string {
	label = strings.ToLower(strings.TrimSpace(label))
	label = strings.Trim(label, ":,")
	label = strings.ReplaceAll(label, "couldn't", "could_not")
	label = strings.ReplaceAll(label, "can't", "cannot")
	label = strings.ReplaceAll(label, "non-rp", "non_rp")
	label = strings.ReplaceAll(label, "non-sm", "non_sm")
	label = strings.ReplaceAll(label, "ip address", "ip_address")
	label = strings.NewReplacer(
		"(", "",
		")", "",
		".", "",
		"/", "_",
		"-", "_",
		" ", "_",
	).Replace(label)
	for strings.Contains(label, "__") {
		label = strings.ReplaceAll(label, "__", "_")
	}
	label = strings.Trim(label, "_")

	switch label {
	case "pkts_recv":
		return "total"
	case "outtransmits":
		return "total"
	case "inmcastpkts", "outmcastpkts":
		return "multicast"
	case "inbcastpkts", "outbcastpkts":
		return "broadcast"
	case "inforwdgrams", "outforwdgrams":
		return "forwarded"
	case "indelivers":
		return "delivered"
	case "inunknownprotos":
		return "unknown_protocol"
	case "inhdrerrors":
		return "header_errors"
	case "inaddrerrors":
		return "address_errors"
	case "intruncatedpkts":
		return "truncated_packets"
	case "innoroutes", "outnoroutes":
		return "no_route"
	case "indiscards", "outdiscards":
		return "discards"
	case "reasmfails":
		return "reassembly_failures"
	case "outfragfails":
		return "fragmentation_failures"
	default:
		return label
	}
}

func shouldSkipProtocolLabel(label string) bool {
	if label == "" {
		return true
	}
	return strings.Contains(label, "byte") || strings.Contains(label, "octet")
}

func parseInt(raw string) int64 {
	raw = strings.ReplaceAll(strings.TrimSpace(raw), ",", "")
	val, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return math.MaxInt64
		}
		return 0
	}
	return val
}

func (stats *protocolTrafficStats) addPacket(protocol, messageType, direction string, value int64) {
	stats.Packets = append(stats.Packets, protocolPacketCounter{
		Protocol:    protocol,
		MessageType: messageType,
		Direction:   direction,
		Value:       value,
	})
}

func (stats *protocolTrafficStats) addError(protocol, errorType string, value int64) {
	stats.Errors = append(stats.Errors, protocolErrorCounter{
		Protocol:  protocol,
		ErrorType: errorType,
		Value:     value,
	})
}

func (stats *protocolTrafficStats) addDrop(protocol, reason string, value int64) {
	stats.Drops = append(stats.Drops, protocolDropCounter{
		Protocol: protocol,
		Reason:   reason,
		Value:    value,
	})
}
