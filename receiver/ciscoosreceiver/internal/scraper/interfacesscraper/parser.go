// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package interfacesscraper // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/interfacesscraper"

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

// Interface represents a network interface on a Cisco device
type Interface struct {
	Name        string
	MACAddress  string
	Description string

	AdminStatus    string
	OperStatus     string
	HasAdminStatus bool
	HasOperStatus  bool

	InputErrors  int64
	OutputErrors int64

	InputDrops  int64
	OutputDrops int64

	InputBytes  int64
	OutputBytes int64

	InputPackets  int64
	OutputPackets int64

	InputUnicast         int64
	OutputUnicast        int64
	InputBroadcast       int64
	InputMulticast       int64
	InputIPMulticast     int64
	InputTotalMulticast  int64
	OutputBroadcast      int64
	OutputMulticast      int64
	HasInputPacketTypes  bool
	HasOutputPacketTypes bool

	InputRateBits     int64
	OutputRateBits    int64
	InputRatePackets  int64
	OutputRatePackets int64
	HasInputRate      bool
	HasOutputRate     bool

	Speed       int64
	SpeedString string

	Counters map[string]int64
}

const invalidCounterValue = int64(math.MinInt64)

const (
	StatusUp   = "up"
	StatusDown = "down"
)

func NewInterface(name string) *Interface {
	return &Interface{
		Name:                name,
		AdminStatus:         StatusDown,
		OperStatus:          StatusDown,
		InputErrors:         invalidCounterValue,
		OutputErrors:        invalidCounterValue,
		InputDrops:          invalidCounterValue,
		OutputDrops:         invalidCounterValue,
		InputBytes:          invalidCounterValue,
		OutputBytes:         invalidCounterValue,
		InputPackets:        invalidCounterValue,
		OutputPackets:       invalidCounterValue,
		InputUnicast:        invalidCounterValue,
		OutputUnicast:       invalidCounterValue,
		InputBroadcast:      invalidCounterValue,
		InputMulticast:      invalidCounterValue,
		InputIPMulticast:    invalidCounterValue,
		InputTotalMulticast: invalidCounterValue,
		OutputBroadcast:     invalidCounterValue,
		OutputMulticast:     invalidCounterValue,
		Counters:            map[string]int64{},
	}
}

// GetAdminStatusInt converts administrative status to integer (1=up/enabled, 0=down/disabled).
func (i *Interface) GetAdminStatusInt() int64 {
	if i.AdminStatus == StatusUp {
		return 1
	}
	return 0
}

// GetOperStatusInt converts operational status to integer (1=up, 0=down)
func (i *Interface) GetOperStatusInt() int64 {
	if i.OperStatus == StatusUp {
		return 1
	}
	return 0
}

// Validate ensures interface has required data and valid status
func (i *Interface) Validate() bool {
	if i.Name == "" {
		return false
	}
	if i.OperStatus != StatusUp && i.OperStatus != StatusDown {
		i.OperStatus = StatusDown
	}
	if i.AdminStatus != StatusUp && i.AdminStatus != StatusDown {
		i.AdminStatus = i.OperStatus
	}
	return true
}

// parseStatus normalizes status strings to "up" or "down"
func parseStatus(status string) string {
	switch status {
	case "up", "UP", "Up", "1":
		return StatusUp
	case "down", "DOWN", "Down", "0":
		return StatusDown
	default:
		return StatusDown
	}
}

// formatSpeed converts speed in bps to human-readable format
func formatSpeed(speedBps int64) string {
	if speedBps <= 0 {
		return ""
	}

	switch {
	case speedBps >= 1000000000:
		return fmt.Sprintf("%.0f Gb/s", float64(speedBps)/1000000000)
	case speedBps >= 1000000:
		return fmt.Sprintf("%.0f Mb/s", float64(speedBps)/1000000)
	case speedBps >= 1000:
		return fmt.Sprintf("%.0f Kb/s", float64(speedBps)/1000)
	default:
		return fmt.Sprintf("%d b/s", speedBps)
	}
}

func parseLineSpeed(value, unit string) int64 {
	value = strings.TrimSpace(value)
	unit = strings.ToLower(strings.TrimSpace(unit))
	if value == "" || unit == "" {
		return 0
	}
	raw, err := strconv.ParseFloat(value, 64)
	if err != nil || raw <= 0 {
		return 0
	}
	switch unit {
	case "b/s", "bps", "bit/s", "bits/sec":
		return int64(raw)
	case "kb/s", "kbps", "kbit/sec":
		return int64(raw * 1000)
	case "mb/s", "mbps", "mbit/sec":
		return int64(raw * 1000 * 1000)
	case "gb/s", "gbps", "gbit/sec":
		return int64(raw * 1000 * 1000 * 1000)
	case "tb/s", "tbps", "tbit/sec":
		return int64(raw * 1000 * 1000 * 1000 * 1000)
	default:
		return 0
	}
}

// str2float64 converts string to float64
func str2float64(s string) float64 {
	if s == "-" || s == "" {
		return 0
	}
	s = strings.ReplaceAll(s, ",", "")
	if val, err := strconv.ParseFloat(s, 64); err == nil {
		return val
	}
	return 0
}

// str2int64 converts a Cisco counter string to int64 without float64 precision
// loss. Invalid and unsigned values outside OTLP's signed int64 range use a
// sentinel so callers can omit them rather than manufacturing zeroes or
// clamping a device counter.
func str2int64(s string) int64 {
	if s == "-" || s == "" {
		return invalidCounterValue
	}
	s = strings.ReplaceAll(s, ",", "")
	if val, err := strconv.ParseInt(s, 10, 64); err == nil {
		if val < 0 {
			return invalidCounterValue
		}
		return val
	}
	// ParseInt rejects values >= 2^63; accept only unsigned values representable
	// in OTLP's signed int64 datapoint type.
	if val, err := strconv.ParseUint(s, 10, 64); err == nil {
		if val > math.MaxInt64 {
			return invalidCounterValue
		}
		return int64(val)
	}
	return invalidCounterValue
}

func validCounter(value int64) bool {
	return value != invalidCounterValue
}

func recordCounter(intf *Interface, name string, value int64) {
	if !validCounter(value) {
		return
	}
	if intf.Counters == nil {
		intf.Counters = map[string]int64{}
	}
	intf.Counters[name] = value
}

func recordDirectionalCounter(intf *Interface, isRx bool, name string, value int64) {
	direction := "output"
	if isRx {
		direction = "input"
	}
	recordCounter(intf, direction+"_"+name, value)
}

// parseInterfaces parses interface information from command output
func parseInterfaces(output string, logger *zap.Logger) []*Interface {
	macRegexp := regexp.MustCompile(`^\s+Hardware(?: is|:) .+, address(?: is|:) ([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})`)
	deviceNameRegexp := regexp.MustCompile(`^([a-zA-Z0-9/.-]+) is.*$`)
	iosStatusRegexp := regexp.MustCompile(`^.+ is (administratively\s+)?(up|down), line protocol is (up|down).*$`)
	nxosOperStatusRegexp := regexp.MustCompile(`^\S+ is (up|down)(?:\s|,)?(\(Administratively down\))?.*$`)
	nxosAdminStatusRegexp := regexp.MustCompile(`^\s*admin state is\s+(up|down).*$`)
	descRegexp := regexp.MustCompile(`^\s+Description: (.*)$`)
	dropsRegexp := regexp.MustCompile(`^\s+Input queue: \d+\/\d+\/(\d+|-)\/\d+ .+ Total output drops: (\d+|-)$`)
	runtsGiantsRegexp := regexp.MustCompile(`^\s+(\d+|-) runts,?\s+(\d+|-) giants,?\s+(\d+|-) throttles?.*$`)
	multiBroadNXOS := regexp.MustCompile(`^.* (\d+|-) multicast packets?\s+(\d+|-) broadcast pack`)
	packetTypesNXOS := regexp.MustCompile(`^\s+(\d+|-) unicast packets?\s+(\d+|-) multicast packets?\s+(\d+|-) broadcast packets?.*$`)
	multiBroadIOSXE := regexp.MustCompile(`^\s+Received\s+(\d+|-)\sbroadcasts \((\d+|-) (?:IP\s)?multicasts?\)`)
	multiBroadIOS := regexp.MustCompile(`^\s+Received (\d+|-) broadcasts.*$`)
	inputBytesRegexp := regexp.MustCompile(`^\s+(\d+|-) (?:packets input,|input packets)\s+(\d+|-) bytes.*$`)
	outputBytesRegexp := regexp.MustCompile(`^\s+(\d+|-) (?:packets output,|output packets)\s+(\d+|-) bytes(?:,\s+(\d+|-) underruns?)?.*$`)
	inputErrorsRegexp := regexp.MustCompile(`^\s+(\d+|-) input errors?,\s+(\d+|-) (?:CRC|crc),?\s+(\d+|-) frame(?:,?\s+(\d+|-) overrun,?\s+(\d+|-) ignored)?.*$`)
	outputErrorsRegexp := regexp.MustCompile(`^\s+(\d+|-) output errors?,\s+(\d+|-) collisions?,\s+(\d+|-) interface resets?.*$`)
	inputMiscRegexp := regexp.MustCompile(`^\s+(\d+|-) watchdog,?\s+(\d+|-) multicast,?\s+(\d+|-) pause input.*$`)
	outputMiscRegexp := regexp.MustCompile(`^\s+(\d+|-) babbles,?\s+(\d+|-) late collision,?\s+(\d+|-) deferred.*$`)
	carrierRegexp := regexp.MustCompile(`^\s+(\d+|-) lost carrier,?\s+(\d+|-) no carrier,?\s+(\d+|-) pause output.*$`)
	outputBufferRegexp := regexp.MustCompile(`^\s+(\d+|-) output buffer failures,?\s+(\d+|-) output buffers swapped out.*$`)
	unknownProtocolDropsRegexp := regexp.MustCompile(`^\s+(\d+|-) unknown protocol drops?.*$`)
	inputRateRegexp := regexp.MustCompile(`^\s+\d+\s+(?:second|seconds|minute|minutes)\s+input rate\s+(\d+|-)\s+(?:bits/sec|bps),\s+(\d+|-)\s+(?:packets/sec|pps).*$`)
	outputRateRegexp := regexp.MustCompile(`^\s+\d+\s+(?:second|seconds|minute|minutes)\s+output rate\s+(\d+|-)\s+(?:bits/sec|bps),\s+(\d+|-)\s+(?:packets/sec|pps).*$`)
	interfaceResetsRegexp := regexp.MustCompile(`^\s+(\d+|-) interface resets?.*$`)
	jumboStormRegexp := regexp.MustCompile(`^\s+(\d+|-) jumbo packets?\s+(\d+|-) storm suppression (bytes|packets).*$`)
	nxJumboOnlyRegexp := regexp.MustCompile(`^\s+(\d+|-) jumbo packets?\s*$`)
	nxRxPacketSummaryRegexp := regexp.MustCompile(`^\s+(\d+|-) input packets\s+(\d+|-) unicast packets\s+(\d+|-) multicast packets?.*$`)
	nxTxPacketSummaryRegexp := regexp.MustCompile(`^\s+(\d+|-) output packets(?:\s+(\d+|-) unicast packets)?\s+(\d+|-) multicast packets?.*$`)
	nxBroadcastBytesRegexp := regexp.MustCompile(`^\s+(\d+|-) broadcast packets?\s+(\d+|-) bytes.*$`)
	nxBroadcastJumboStormRegexp := regexp.MustCompile(`^\s+(\d+|-) broadcast packets?\s+(\d+|-) jumbo packets?(?:\s+(\d+|-) storm suppression (bytes|packets))?.*$`)
	nxBytesOnlyRegexp := regexp.MustCompile(`^\s+(\d+|-) bytes\s*$`)
	nxInputPhysicalRegexp := regexp.MustCompile(`^\s+(\d+|-) runts\s+(\d+|-) giants\s+(\d+|-) CRC\s+(\d+|-) no buffer.*$`)
	nxNoBufferRuntCRCRegexp := regexp.MustCompile(`^\s+(\d+|-) no buffer\s+(\d+|-) runts?\s+(\d+|-) CRC(?:\s+(\d+|-) ecc)?.*$`)
	nxRuntsGiantsRegexp := regexp.MustCompile(`^\s+(\d+|-) runts\s+(\d+|-) giants\s*$`)
	nxCRCRegexp := regexp.MustCompile(`^\s+(\d+|-) CRC\s*$`)
	nxNoBufferRegexp := regexp.MustCompile(`^\s+(\d+|-) no buffer\s*$`)
	nxInputErrorsRegexp := regexp.MustCompile(`^\s+(\d+|-) input errors?\s+(\d+|-) short frame\s+(\d+|-) overrun\s+(\d+|-) underrun\s+(\d+|-) ignored.*$`)
	nxInputErrorWatchdogRegexp := regexp.MustCompile(`^\s+(\d+|-) input errors?\s+(\d+|-) short frame\s+(\d+|-) watchdog.*$`)
	nxInputErrorRegexp := regexp.MustCompile(`^\s+(\d+|-) input errors?\s*$`)
	nxShortFrameRegexp := regexp.MustCompile(`^\s+(\d+|-) short frame\s+(\d+|-) overrun\s+(\d+|-) underrun\s+(\d+|-) ignored.*$`)
	nxOverrunDropRegexp := regexp.MustCompile(`^\s+(\d+|-) overrun\s+(\d+|-) underrun\s+(\d+|-) ignored\s+(\d+|-) bad etype drop.*$`)
	nxInputDropsRegexp := regexp.MustCompile(`^\s+(\d+|-) watchdog\s+(\d+|-) bad etype drop\s+(\d+|-) bad proto drop\s+(\d+|-) if down drop.*$`)
	nxBadProtoDribbleRegexp := regexp.MustCompile(`^\s+(\d+|-) bad proto drop\s+(\d+|-) if down drop\s+(\d+|-) input with dribble.*$`)
	nxInputDiscardRegexp := regexp.MustCompile(`^\s+(\d+|-) input with dribble\s+(\d+|-) input discard.*$`)
	nxInputDiscardOnlyRegexp := regexp.MustCompile(`^\s+(\d+|-) input discard\s*$`)
	nxRxPauseRegexp := regexp.MustCompile(`^\s+(\d+|-) Rx pause.*$`)
	nxOutputErrorsRegexp := regexp.MustCompile(`^\s+(\d+|-) output errors?\s+(\d+|-) collision\s+(\d+|-) deferred\s+(\d+|-) late collision.*$`)
	nxOutputErrorsPartialRegexp := regexp.MustCompile(`^\s+(\d+|-) output errors?\s+(\d+|-) collision\s+(\d+|-) deferred\s*$`)
	nxOutputCarrierRegexp := regexp.MustCompile(`^\s+(\d+|-) lost carrier\s+(\d+|-) no carrier\s+(\d+|-) babble\s+(\d+|-) output discard.*$`)
	nxLateCarrierRegexp := regexp.MustCompile(`^\s+(\d+|-) late collision\s+(\d+|-) lost carrier\s+(\d+|-) no carrier.*$`)
	nxBabbleRegexp := regexp.MustCompile(`^\s+(\d+|-) babble\s*$`)
	nxTxPauseRegexp := regexp.MustCompile(`^\s+(\d+|-) Tx pause.*$`)
	nxCombinedPauseRegexp := regexp.MustCompile(`^\s+(\d+|-) Rx pause\s+(\d+|-) Tx pause.*$`)
	nxStompedCRCRegexp := regexp.MustCompile(`^\s+(\d+|-) Stomped CRC\s*$`)
	nxCombinedRateRegexp := regexp.MustCompile(`^\s+input rate\s+(\d+|-)\s+bps,\s+(\d+|-)\s+pps;\s+output rate\s+(\d+|-)\s+bps,\s+(\d+|-)\s+pps.*$`)
	speedRegexp := regexp.MustCompile(`^\s+(.*)-duplex,\s+(\d+(?:\.\d+)?)\s+(([KMGT]?b)/s).*$`)
	newIfRegexp := regexp.MustCompile(`(?:^!?(?: |admin|show|.+#).*$|^$)`)

	isRx := true
	var current *Interface
	var interfaces []*Interface
	lines := strings.SplitSeq(output, "\n")

	for line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if current != nil {
			switch {
			case strings.EqualFold(trimmedLine, "rx"):
				isRx = true
				continue
			case strings.EqualFold(trimmedLine, "tx"):
				isRx = false
				continue
			}
		}

		if !newIfRegexp.MatchString(line) {
			if current != nil {
				finalizeInterfacePacketTypes(current)
				if current.Validate() {
					interfaces = append(interfaces, current)
				}
			}
			matches := deviceNameRegexp.FindStringSubmatch(line)
			if matches == nil {
				continue
			}
			current = NewInterface(matches[1])
			isRx = true
		}
		if current == nil {
			continue
		}
		switch {
		case iosStatusRegexp.MatchString(line):
			matches := iosStatusRegexp.FindStringSubmatch(line)
			current.AdminStatus = StatusUp
			if strings.TrimSpace(matches[1]) != "" {
				current.AdminStatus = StatusDown
			}
			current.OperStatus = parseStatus(matches[3])
			current.HasAdminStatus = true
			current.HasOperStatus = true
		case nxosOperStatusRegexp.MatchString(line):
			matches := nxosOperStatusRegexp.FindStringSubmatch(line)
			current.OperStatus = parseStatus(matches[1])
			current.HasOperStatus = true
		case nxosAdminStatusRegexp.MatchString(line):
			matches := nxosAdminStatusRegexp.FindStringSubmatch(line)
			current.AdminStatus = parseStatus(matches[1])
			current.HasAdminStatus = true
		case descRegexp.MatchString(line):
			matches := descRegexp.FindStringSubmatch(line)
			current.Description = matches[1]
		case macRegexp.MatchString(line):
			matches := macRegexp.FindStringSubmatch(line)
			current.MACAddress = matches[1]
		case dropsRegexp.MatchString(line):
			matches := dropsRegexp.FindStringSubmatch(line)
			current.InputDrops = str2int64(matches[1])
			current.OutputDrops = str2int64(matches[2])
			recordCounter(current, "input_queue_drops", current.InputDrops)
			recordCounter(current, "output_drops", current.OutputDrops)
		case runtsGiantsRegexp.MatchString(line):
			matches := runtsGiantsRegexp.FindStringSubmatch(line)
			recordCounter(current, "runts", str2int64(matches[1]))
			recordCounter(current, "giants", str2int64(matches[2]))
			recordCounter(current, "throttles", str2int64(matches[3]))
		case inputBytesRegexp.MatchString(line):
			matches := inputBytesRegexp.FindStringSubmatch(line)
			current.InputPackets = str2int64(matches[1])
			current.InputBytes = str2int64(matches[2])
		case outputBytesRegexp.MatchString(line):
			matches := outputBytesRegexp.FindStringSubmatch(line)
			current.OutputPackets = str2int64(matches[1])
			current.OutputBytes = str2int64(matches[2])
			if len(matches) > 3 {
				recordCounter(current, "underruns", str2int64(matches[3]))
			}
		case inputErrorsRegexp.MatchString(line):
			matches := inputErrorsRegexp.FindStringSubmatch(line)
			current.InputErrors = str2int64(matches[1])
			recordCounter(current, "input_errors", current.InputErrors)
			recordCounter(current, "crc", str2int64(matches[2]))
			recordCounter(current, "frame", str2int64(matches[3]))
			recordCounter(current, "overrun", str2int64(matches[4]))
			recordCounter(current, "ignored", str2int64(matches[5]))
		case outputErrorsRegexp.MatchString(line):
			matches := outputErrorsRegexp.FindStringSubmatch(line)
			current.OutputErrors = str2int64(matches[1])
			recordCounter(current, "output_errors", current.OutputErrors)
			recordCounter(current, "collisions", str2int64(matches[2]))
			recordCounter(current, "interface_resets", str2int64(matches[3]))
		case inputMiscRegexp.MatchString(line):
			matches := inputMiscRegexp.FindStringSubmatch(line)
			recordCounter(current, "watchdog", str2int64(matches[1]))
			current.InputTotalMulticast = str2int64(matches[2])
			current.HasInputPacketTypes = true
			recordCounter(current, "pause_input", str2int64(matches[3]))
		case outputMiscRegexp.MatchString(line):
			matches := outputMiscRegexp.FindStringSubmatch(line)
			recordCounter(current, "babbles", str2int64(matches[1]))
			recordCounter(current, "late_collision", str2int64(matches[2]))
			recordCounter(current, "deferred", str2int64(matches[3]))
		case carrierRegexp.MatchString(line):
			matches := carrierRegexp.FindStringSubmatch(line)
			recordCounter(current, "lost_carrier", str2int64(matches[1]))
			recordCounter(current, "no_carrier", str2int64(matches[2]))
			recordCounter(current, "pause_output", str2int64(matches[3]))
		case outputBufferRegexp.MatchString(line):
			matches := outputBufferRegexp.FindStringSubmatch(line)
			recordCounter(current, "output_buffer_failures", str2int64(matches[1]))
			recordCounter(current, "output_buffers_swapped_out", str2int64(matches[2]))
		case unknownProtocolDropsRegexp.MatchString(line):
			matches := unknownProtocolDropsRegexp.FindStringSubmatch(line)
			recordCounter(current, "unknown_protocol_drops", str2int64(matches[1]))
		case inputRateRegexp.MatchString(line):
			matches := inputRateRegexp.FindStringSubmatch(line)
			if matches[1] == "-" || matches[2] == "-" {
				continue
			}
			current.InputRateBits = str2int64(matches[1])
			current.InputRatePackets = str2int64(matches[2])
			current.HasInputRate = validCounter(current.InputRateBits) && validCounter(current.InputRatePackets)
		case outputRateRegexp.MatchString(line):
			matches := outputRateRegexp.FindStringSubmatch(line)
			if matches[1] == "-" || matches[2] == "-" {
				continue
			}
			current.OutputRateBits = str2int64(matches[1])
			current.OutputRatePackets = str2int64(matches[2])
			current.HasOutputRate = validCounter(current.OutputRateBits) && validCounter(current.OutputRatePackets)
		case speedRegexp.MatchString(line):
			matches := speedRegexp.FindStringSubmatch(line)
			current.SpeedString = matches[2] + " " + matches[3]
			current.Speed = parseLineSpeed(matches[2], matches[3])
		case interfaceResetsRegexp.MatchString(line):
			matches := interfaceResetsRegexp.FindStringSubmatch(line)
			recordCounter(current, "interface_resets", str2int64(matches[1]))
		case nxRxPacketSummaryRegexp.MatchString(line):
			matches := nxRxPacketSummaryRegexp.FindStringSubmatch(line)
			current.InputPackets = str2int64(matches[1])
			current.InputUnicast = str2int64(matches[2])
			current.InputMulticast = str2int64(matches[3])
			current.HasInputPacketTypes = true
		case nxTxPacketSummaryRegexp.MatchString(line):
			matches := nxTxPacketSummaryRegexp.FindStringSubmatch(line)
			current.OutputPackets = str2int64(matches[1])
			if matches[2] != "" {
				current.OutputUnicast = str2int64(matches[2])
			}
			current.OutputMulticast = str2int64(matches[3])
			current.HasOutputPacketTypes = true
		case packetTypesNXOS.MatchString(line):
			matches := packetTypesNXOS.FindStringSubmatch(line)
			if isRx {
				current.InputUnicast = str2int64(matches[1])
				current.InputMulticast = str2int64(matches[2])
				current.InputBroadcast = str2int64(matches[3])
				current.HasInputPacketTypes = true
			} else {
				current.OutputUnicast = str2int64(matches[1])
				current.OutputMulticast = str2int64(matches[2])
				current.OutputBroadcast = str2int64(matches[3])
				current.HasOutputPacketTypes = true
			}
		case multiBroadNXOS.MatchString(line):
			if isRx {
				matches := multiBroadNXOS.FindStringSubmatch(line)
				current.InputMulticast = str2int64(matches[1])
				current.InputBroadcast = str2int64(matches[2])
				current.HasInputPacketTypes = true
			}
		case multiBroadIOSXE.MatchString(line):
			matches := multiBroadIOSXE.FindStringSubmatch(line)
			current.InputBroadcast = str2int64(matches[1])
			current.InputIPMulticast = str2int64(matches[2])
			current.HasInputPacketTypes = true
		case multiBroadIOS.MatchString(line):
			matches := multiBroadIOS.FindStringSubmatch(line)
			current.InputBroadcast = str2int64(matches[1])
			current.HasInputPacketTypes = true
		case nxBroadcastBytesRegexp.MatchString(line):
			matches := nxBroadcastBytesRegexp.FindStringSubmatch(line)
			if isRx {
				current.InputBroadcast = str2int64(matches[1])
				current.InputBytes = str2int64(matches[2])
				current.HasInputPacketTypes = true
			} else {
				current.OutputBroadcast = str2int64(matches[1])
				current.OutputBytes = str2int64(matches[2])
				current.HasOutputPacketTypes = true
			}
		case nxBroadcastJumboStormRegexp.MatchString(line):
			matches := nxBroadcastJumboStormRegexp.FindStringSubmatch(line)
			if isRx {
				current.InputBroadcast = str2int64(matches[1])
				current.HasInputPacketTypes = true
			} else {
				current.OutputBroadcast = str2int64(matches[1])
				current.HasOutputPacketTypes = true
			}
			recordDirectionalCounter(current, isRx, "jumbo_packets", str2int64(matches[2]))
			if len(matches) > 4 && matches[3] != "" {
				recordDirectionalCounter(current, isRx, "storm_suppression_"+matches[4], str2int64(matches[3]))
			}
		case nxBytesOnlyRegexp.MatchString(line):
			matches := nxBytesOnlyRegexp.FindStringSubmatch(line)
			if isRx {
				current.InputBytes = str2int64(matches[1])
			} else {
				current.OutputBytes = str2int64(matches[1])
			}
		case jumboStormRegexp.MatchString(line):
			matches := jumboStormRegexp.FindStringSubmatch(line)
			recordDirectionalCounter(current, isRx, "jumbo_packets", str2int64(matches[1]))
			recordDirectionalCounter(current, isRx, "storm_suppression_"+matches[3], str2int64(matches[2]))
		case nxJumboOnlyRegexp.MatchString(line):
			matches := nxJumboOnlyRegexp.FindStringSubmatch(line)
			recordDirectionalCounter(current, isRx, "jumbo_packets", str2int64(matches[1]))
		case nxInputPhysicalRegexp.MatchString(line):
			matches := nxInputPhysicalRegexp.FindStringSubmatch(line)
			recordCounter(current, "runts", str2int64(matches[1]))
			recordCounter(current, "giants", str2int64(matches[2]))
			recordCounter(current, "crc", str2int64(matches[3]))
			recordCounter(current, "no_buffer", str2int64(matches[4]))
		case nxNoBufferRuntCRCRegexp.MatchString(line):
			matches := nxNoBufferRuntCRCRegexp.FindStringSubmatch(line)
			recordCounter(current, "no_buffer", str2int64(matches[1]))
			recordCounter(current, "runts", str2int64(matches[2]))
			recordCounter(current, "crc", str2int64(matches[3]))
			if len(matches) > 4 {
				recordCounter(current, "ecc", str2int64(matches[4]))
			}
		case nxRuntsGiantsRegexp.MatchString(line):
			matches := nxRuntsGiantsRegexp.FindStringSubmatch(line)
			recordCounter(current, "runts", str2int64(matches[1]))
			recordCounter(current, "giants", str2int64(matches[2]))
		case nxCRCRegexp.MatchString(line):
			matches := nxCRCRegexp.FindStringSubmatch(line)
			recordCounter(current, "crc", str2int64(matches[1]))
		case nxNoBufferRegexp.MatchString(line):
			matches := nxNoBufferRegexp.FindStringSubmatch(line)
			recordCounter(current, "no_buffer", str2int64(matches[1]))
		case nxInputErrorsRegexp.MatchString(line):
			matches := nxInputErrorsRegexp.FindStringSubmatch(line)
			current.InputErrors = str2int64(matches[1])
			recordCounter(current, "input_errors", current.InputErrors)
			recordCounter(current, "short_frame", str2int64(matches[2]))
			recordCounter(current, "overrun", str2int64(matches[3]))
			recordCounter(current, "underrun", str2int64(matches[4]))
			recordCounter(current, "ignored", str2int64(matches[5]))
		case nxInputErrorWatchdogRegexp.MatchString(line):
			matches := nxInputErrorWatchdogRegexp.FindStringSubmatch(line)
			current.InputErrors = str2int64(matches[1])
			recordCounter(current, "input_errors", current.InputErrors)
			recordCounter(current, "short_frame", str2int64(matches[2]))
			recordCounter(current, "watchdog", str2int64(matches[3]))
		case nxInputErrorRegexp.MatchString(line):
			matches := nxInputErrorRegexp.FindStringSubmatch(line)
			current.InputErrors = str2int64(matches[1])
			recordCounter(current, "input_errors", current.InputErrors)
		case nxShortFrameRegexp.MatchString(line):
			matches := nxShortFrameRegexp.FindStringSubmatch(line)
			recordCounter(current, "short_frame", str2int64(matches[1]))
			recordCounter(current, "overrun", str2int64(matches[2]))
			recordCounter(current, "underrun", str2int64(matches[3]))
			recordCounter(current, "ignored", str2int64(matches[4]))
		case nxOverrunDropRegexp.MatchString(line):
			matches := nxOverrunDropRegexp.FindStringSubmatch(line)
			recordCounter(current, "overrun", str2int64(matches[1]))
			recordCounter(current, "underrun", str2int64(matches[2]))
			recordCounter(current, "ignored", str2int64(matches[3]))
			recordCounter(current, "bad_etype_drops", str2int64(matches[4]))
		case nxInputDropsRegexp.MatchString(line):
			matches := nxInputDropsRegexp.FindStringSubmatch(line)
			recordCounter(current, "watchdog", str2int64(matches[1]))
			recordCounter(current, "bad_etype_drops", str2int64(matches[2]))
			recordCounter(current, "bad_proto_drops", str2int64(matches[3]))
			recordCounter(current, "if_down_drops", str2int64(matches[4]))
		case nxBadProtoDribbleRegexp.MatchString(line):
			matches := nxBadProtoDribbleRegexp.FindStringSubmatch(line)
			recordCounter(current, "bad_proto_drops", str2int64(matches[1]))
			recordCounter(current, "if_down_drops", str2int64(matches[2]))
			recordCounter(current, "input_dribble", str2int64(matches[3]))
		case nxInputDiscardRegexp.MatchString(line):
			matches := nxInputDiscardRegexp.FindStringSubmatch(line)
			recordCounter(current, "input_dribble", str2int64(matches[1]))
			current.InputDrops = str2int64(matches[2])
			recordCounter(current, "input_discards", current.InputDrops)
		case nxInputDiscardOnlyRegexp.MatchString(line):
			matches := nxInputDiscardOnlyRegexp.FindStringSubmatch(line)
			current.InputDrops = str2int64(matches[1])
			recordCounter(current, "input_discards", current.InputDrops)
		case nxCombinedPauseRegexp.MatchString(line):
			matches := nxCombinedPauseRegexp.FindStringSubmatch(line)
			recordCounter(current, "pause_input", str2int64(matches[1]))
			recordCounter(current, "pause_output", str2int64(matches[2]))
		case nxRxPauseRegexp.MatchString(line):
			matches := nxRxPauseRegexp.FindStringSubmatch(line)
			recordCounter(current, "pause_input", str2int64(matches[1]))
		case nxOutputErrorsRegexp.MatchString(line):
			matches := nxOutputErrorsRegexp.FindStringSubmatch(line)
			current.OutputErrors = str2int64(matches[1])
			recordCounter(current, "output_errors", current.OutputErrors)
			recordCounter(current, "collisions", str2int64(matches[2]))
			recordCounter(current, "deferred", str2int64(matches[3]))
			recordCounter(current, "late_collision", str2int64(matches[4]))
		case nxOutputErrorsPartialRegexp.MatchString(line):
			matches := nxOutputErrorsPartialRegexp.FindStringSubmatch(line)
			current.OutputErrors = str2int64(matches[1])
			recordCounter(current, "output_errors", current.OutputErrors)
			recordCounter(current, "collisions", str2int64(matches[2]))
			recordCounter(current, "deferred", str2int64(matches[3]))
		case nxOutputCarrierRegexp.MatchString(line):
			matches := nxOutputCarrierRegexp.FindStringSubmatch(line)
			recordCounter(current, "lost_carrier", str2int64(matches[1]))
			recordCounter(current, "no_carrier", str2int64(matches[2]))
			recordCounter(current, "babbles", str2int64(matches[3]))
			current.OutputDrops = str2int64(matches[4])
			recordCounter(current, "output_discards", current.OutputDrops)
		case nxLateCarrierRegexp.MatchString(line):
			matches := nxLateCarrierRegexp.FindStringSubmatch(line)
			recordCounter(current, "late_collision", str2int64(matches[1]))
			recordCounter(current, "lost_carrier", str2int64(matches[2]))
			recordCounter(current, "no_carrier", str2int64(matches[3]))
		case nxBabbleRegexp.MatchString(line):
			matches := nxBabbleRegexp.FindStringSubmatch(line)
			recordCounter(current, "babbles", str2int64(matches[1]))
		case nxTxPauseRegexp.MatchString(line):
			matches := nxTxPauseRegexp.FindStringSubmatch(line)
			recordCounter(current, "pause_output", str2int64(matches[1]))
		case nxStompedCRCRegexp.MatchString(line):
			matches := nxStompedCRCRegexp.FindStringSubmatch(line)
			recordCounter(current, "stomped_crc", str2int64(matches[1]))
		case nxCombinedRateRegexp.MatchString(line):
			matches := nxCombinedRateRegexp.FindStringSubmatch(line)
			if !current.HasInputRate {
				current.InputRateBits = str2int64(matches[1])
				current.InputRatePackets = str2int64(matches[2])
				current.HasInputRate = validCounter(current.InputRateBits) && validCounter(current.InputRatePackets)
			}
			if !current.HasOutputRate {
				current.OutputRateBits = str2int64(matches[3])
				current.OutputRatePackets = str2int64(matches[4])
				current.HasOutputRate = validCounter(current.OutputRateBits) && validCounter(current.OutputRatePackets)
			}
		}
	}

	if current != nil {
		finalizeInterfacePacketTypes(current)
		if current.Validate() {
			interfaces = append(interfaces, current)
		} else {
			logger.Warn("Skipping invalid interface", zap.String("name", current.Name))
		}
	}

	logger.Info("Parsed interfaces", zap.Int("count", len(interfaces)))

	return interfaces
}

func finalizeInterfacePacketTypes(intf *Interface) {
	// IOS and IOS-XE report IP multicast and total multicast on separate
	// lines. Resolve them after parsing the full interface so line order cannot
	// change the precedence, while retaining IP multicast as the fallback.
	if validCounter(intf.InputTotalMulticast) {
		intf.InputMulticast = intf.InputTotalMulticast
	} else if validCounter(intf.InputIPMulticast) {
		intf.InputMulticast = intf.InputIPMulticast
	}
}

func parseInterfaceCounterTables(output string, logger *zap.Logger) map[string]map[string]int64 {
	counterTables := map[string]map[string]int64{}
	var headers []string

	lines := strings.SplitSeq(output, "\n")
	for line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		if strings.EqualFold(fields[0], "Port") && hasKnownCounterHeader(fields[1:]) {
			headers = fields
			continue
		}

		if headers == nil || len(fields) < len(headers) {
			continue
		}

		intfName := fields[0]
		for idx := 1; idx < len(headers) && idx < len(fields); idx++ {
			counterName := normalizeCounterHeader(headers[idx])
			if counterName == "" {
				continue
			}
			if _, ok := counterTables[intfName]; !ok {
				counterTables[intfName] = map[string]int64{}
			}
			if value := str2int64(fields[idx]); validCounter(value) {
				counterTables[intfName][counterName] = value
			}
		}
	}

	logger.Info("Parsed interface counter tables", zap.Int("interfaces", len(counterTables)))
	return counterTables
}

func mergeInterfaceCounterTables(interfaces []*Interface, counterTables map[string]map[string]int64) []*Interface {
	if len(counterTables) == 0 {
		return interfaces
	}

	byName := make(map[string]*Interface, len(interfaces)*2)
	for _, intf := range interfaces {
		byName[intf.Name] = intf
		byName[normalizeInterfaceName(intf.Name)] = intf
	}

	for tableName, counters := range counterTables {
		intf := byName[tableName]
		if intf == nil {
			intf = byName[normalizeInterfaceName(tableName)]
		}
		if intf == nil {
			intf = NewInterface(tableName)
			interfaces = append(interfaces, intf)
			byName[tableName] = intf
			byName[normalizeInterfaceName(tableName)] = intf
		}

		for counterName, value := range counters {
			applyInterfaceCounterValue(intf, counterName, value)
		}
	}

	return interfaces
}

func hasKnownCounterHeader(headers []string) bool {
	for _, header := range headers {
		if normalizeCounterHeader(header) != "" {
			return true
		}
	}
	return false
}

func normalizeCounterHeader(header string) string {
	key := strings.ToLower(header)
	key = strings.NewReplacer("-", "", "_", "", ".", "").Replace(key)

	switch key {
	case "inoctets", "inoctet":
		return "input_octets"
	case "outoctets", "outoctet":
		return "output_octets"
	case "inucastpkts", "inunicastpkts":
		return "input_unicast_packets"
	case "outucastpkts", "outunicastpkts":
		return "output_unicast_packets"
	case "inmcastpkts", "inmulticastpkts":
		return "input_multicast_packets"
	case "outmcastpkts", "outmulticastpkts":
		return "output_multicast_packets"
	case "inbcastpkts", "inbroadcastpkts":
		return "input_broadcast_packets"
	case "outbcastpkts", "outbroadcastpkts":
		return "output_broadcast_packets"
	case "alignerr":
		return "align_errors"
	case "fcserr":
		return "fcs_errors"
	case "xmiterr":
		return "transmit_errors"
	case "rcverr":
		return "receive_errors"
	case "undersize":
		return "undersize"
	case "outdiscards", "outdiscard":
		return "output_discards"
	case "indiscards", "indiscard":
		return "input_discards"
	case "singlecol":
		return "single_collisions"
	case "multicol":
		return "multi_collisions"
	case "latecol":
		return "late_collision"
	case "excesscol", "excescol":
		return "excess_collisions"
	case "carrisen":
		return "carrier_sense"
	case "runts":
		return "runts"
	case "giants":
		return "giants"
	case "sqetesterr":
		return "sqetest_errors"
	case "deferredtx":
		return "deferred_transmit"
	case "intmactxer":
		return "internal_mac_transmit_errors"
	case "intmacrxer":
		return "internal_mac_receive_errors"
	case "symbolerr":
		return "symbol_errors"
	case "stompedcrc":
		return "stomped_crc"
	default:
		return ""
	}
}

func applyInterfaceCounterValue(intf *Interface, counterName string, value int64) {
	switch counterName {
	case "input_octets":
		intf.InputBytes = value
	case "output_octets":
		intf.OutputBytes = value
	case "input_unicast_packets":
		intf.InputUnicast = value
		intf.HasInputPacketTypes = true
	case "output_unicast_packets":
		intf.OutputUnicast = value
		intf.HasOutputPacketTypes = true
	case "input_multicast_packets":
		intf.InputMulticast = value
		intf.HasInputPacketTypes = true
	case "output_multicast_packets":
		intf.OutputMulticast = value
		intf.HasOutputPacketTypes = true
	case "input_broadcast_packets":
		intf.InputBroadcast = value
		intf.HasInputPacketTypes = true
	case "output_broadcast_packets":
		intf.OutputBroadcast = value
		intf.HasOutputPacketTypes = true
	case "input_discards":
		intf.InputDrops = value
		recordCounter(intf, counterName, value)
	case "output_discards":
		intf.OutputDrops = value
		recordCounter(intf, counterName, value)
	case "receive_errors":
		intf.InputErrors = value
		recordCounter(intf, counterName, value)
	case "transmit_errors":
		intf.OutputErrors = value
		recordCounter(intf, counterName, value)
	default:
		recordCounter(intf, counterName, value)
	}
}

func normalizeInterfaceName(name string) string {
	normalized := strings.ToLower(name)
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, " ", "")

	replacements := []struct {
		long  string
		short string
	}{
		{"tengigabitethernet", "te"},
		{"tengige", "te"},
		{"gigabitethernet", "gi"},
		{"fastethernet", "fa"},
		{"hundredgige", "hu"},
		{"fortygigabitethernet", "fo"},
		{"twentyfivegige", "twe"},
		{"ethernet", "eth"},
		{"portchannel", "po"},
		{"loopback", "lo"},
	}

	for _, replacement := range replacements {
		if suffix, ok := strings.CutPrefix(normalized, replacement.long); ok {
			return replacement.short + suffix
		}
	}
	return normalized
}

// parseSimpleInterfaces parses "show interface brief" output as fallback
func parseSimpleInterfaces(output string, _ *zap.Logger) []*Interface {
	interfaces := make([]*Interface, 0)

	lines := strings.SplitSeq(output, "\n")

	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 || !simpleInterfaceNameLooksValid(fields[0]) {
			continue
		}

		status := simpleInterfaceStatus(fields)
		iface := NewInterface(fields[0])
		iface.OperStatus = parseStatus(status)
		iface.AdminStatus = iface.OperStatus
		interfaces = append(interfaces, iface)
	}

	return interfaces
}

func simpleInterfaceStatus(fields []string) string {
	if len(fields) >= 5 && strings.EqualFold(fields[2], "eth") {
		return fields[4]
	}
	if len(fields) >= 3 && fields[1] == "--" {
		return fields[2]
	}
	if len(fields) >= 2 && simpleStatusField(fields[1]) {
		return fields[1]
	}
	return fields[len(fields)-1]
}

func simpleStatusField(value string) bool {
	value = strings.ToLower(value)
	return value == "up" || value == "down"
}

func simpleInterfaceNameLooksValid(name string) bool {
	name = strings.ToLower(name)
	if !strings.ContainsAny(name, "0123456789") {
		return false
	}
	return strings.HasPrefix(name, "eth") ||
		strings.HasPrefix(name, "ethernet") ||
		strings.HasPrefix(name, "gi") ||
		strings.HasPrefix(name, "gigabitethernet") ||
		strings.HasPrefix(name, "te") ||
		strings.HasPrefix(name, "tengigabitethernet") ||
		strings.HasPrefix(name, "lo") ||
		strings.HasPrefix(name, "loopback") ||
		strings.HasPrefix(name, "mgmt") ||
		strings.HasPrefix(name, "po") ||
		strings.HasPrefix(name, "port-channel") ||
		strings.HasPrefix(name, "vlan")
}
