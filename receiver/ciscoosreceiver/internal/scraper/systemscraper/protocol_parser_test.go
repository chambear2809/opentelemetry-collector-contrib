// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package systemscraper

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseProtocolTrafficIOS(t *testing.T) {
	output := `IP statistics:
  Rcvd:  27 total, 27 local destination
         1 format errors, 2 checksum errors, 3 bad hop count
         4 unknown protocol, 5 not a gateway
  Frags: 6 reassembled, 7 timeouts, 8 couldn't reassemble
         9 fragmented, 10 couldn't fragment
  Bcast: 27 received, 6 sent
  Mcast: 7 received, 8 sent
  Sent:  9 generated, 10 forwarded
  Drop:  11 encapsulation failed, 12 unresolved, 13 no adjacency
         14 no route, 15 unicast RPF, 16 forced drop
ICMP statistics:
  Rcvd: 17 format errors, 18 checksum errors, 19 redirects, 20 unreachable
        21 echo, 22 echo reply
  Sent: 23 redirects, 24 unreachable, 25 echo, 26 echo reply
TCP statistics:
  Rcvd: 27 total, 28 checksum errors, 29 no port
  Sent: 30 total
UDP statistics:
  Rcvd: 31 total, 32 checksum errors, 33 no port
  Sent: 34 total, 35 forwarded broadcasts
PIMv2 statistics: Sent/Received
  Total: 45/46, 47 checksum errors, 48 format errors
  Registers: 49/50 (51 non-rp, 52 non-sm-group), Register Stops: 53/54, Hellos: 55/56
IGMP statistics: Sent/Received
  Total: 57/58, Format errors: 59/60, Checksum errors: 61/62
  Host Queries: 63/64, Host Reports: 65/66
ARP statistics:
  Rcvd: 36 requests, 37 replies, 38 reverse, 39 other
  Sent: 40 requests, 41 replies (42 proxy), 43 reverse
  Drop due to input queue full: 44`

	stats := parseProtocolTraffic(output)

	assert.Contains(t, stats.Packets, protocolPacketCounter{Protocol: "ip", MessageType: "total", Direction: protocolDirectionReceive, Value: 27})
	assert.Contains(t, stats.Packets, protocolPacketCounter{Protocol: "ip", MessageType: "broadcast", Direction: protocolDirectionTransmit, Value: 6})
	assert.Contains(t, stats.Packets, protocolPacketCounter{Protocol: "ip", MessageType: "fragments_reassembled", Direction: protocolDirectionReceive, Value: 6})
	assert.Contains(t, stats.Packets, protocolPacketCounter{Protocol: "ip", MessageType: "fragments", Direction: protocolDirectionTransmit, Value: 9})
	assert.Contains(t, stats.Packets, protocolPacketCounter{Protocol: "udp", MessageType: "forwarded_broadcasts", Direction: protocolDirectionTransmit, Value: 35})
	assert.Contains(t, stats.Packets, protocolPacketCounter{Protocol: "pim", MessageType: "total", Direction: protocolDirectionTransmit, Value: 45})
	assert.Contains(t, stats.Packets, protocolPacketCounter{Protocol: "pim", MessageType: "registers", Direction: protocolDirectionReceive, Value: 50})
	assert.Contains(t, stats.Packets, protocolPacketCounter{Protocol: "igmp", MessageType: "host_queries", Direction: protocolDirectionTransmit, Value: 63})
	assert.Contains(t, stats.Packets, protocolPacketCounter{Protocol: "arp", MessageType: "requests", Direction: protocolDirectionReceive, Value: 36})
	assert.Contains(t, stats.Errors, protocolErrorCounter{Protocol: "ip", ErrorType: "format_errors", Value: 1})
	assert.Contains(t, stats.Errors, protocolErrorCounter{Protocol: "tcp", ErrorType: "checksum_errors", Value: 28})
	assert.Contains(t, stats.Errors, protocolErrorCounter{Protocol: "pim", ErrorType: "checksum_errors", Value: 47})
	assert.Contains(t, stats.Errors, protocolErrorCounter{Protocol: "igmp", ErrorType: "format_errors_sent", Value: 59})
	assert.Contains(t, stats.Errors, protocolErrorCounter{Protocol: "igmp", ErrorType: "format_errors_received", Value: 60})
	assert.Contains(t, stats.Drops, protocolDropCounter{Protocol: "ip", Reason: "encapsulation_failed", Value: 11})
	assert.Contains(t, stats.Drops, protocolDropCounter{Protocol: "ip", Reason: "fragment_timeout", Value: 7})
	assert.Contains(t, stats.Drops, protocolDropCounter{Protocol: "ip", Reason: "cannot_fragment", Value: 10})
	assert.Contains(t, stats.Drops, protocolDropCounter{Protocol: "udp", Reason: "no_port", Value: 33})
	assert.Contains(t, stats.Drops, protocolDropCounter{Protocol: "arp", Reason: "input_queue_full", Value: 44})
}

func TestParseProtocolTrafficNXOS(t *testing.T) {
	output := `IP Software Processed Traffic Statistics
----------------------------------------
Transmission and reception:
  Packets received: 217833, sent: 2572, consumed: 614,
  Forwarded, unicast: 1, multicast: 2, Label: 3
Errors:
  Bad checksum: 4, packet too small: 5, bad version: 6,
  Bad encapsulation: 7, no route: 8, non-existent protocol: 9
Fragmentation/reassembly:
  Fragments received: 10, fragments sent: 11, fragments created: 12,
  Fragments dropped: 13, packets with DF: 14, packets reassembled: 15,
  Fragments timed out: 16
ICMP Software Processed Traffic Statistics
------------------------------------------
Transmission:
  Redirect: 17, unreachable: 18, echo request: 19, echo reply: 20,
  Output Drops - badlen: 21, encap fail: 22, xmit fail: 23
Reception:
  Redirect: 24, unreachable: 25, echo request: 26, echo reply: 27,
  Format error: 28, checksum error: 29`

	stats := parseProtocolTraffic(output)

	assert.Contains(t, stats.Packets, protocolPacketCounter{Protocol: "ip", MessageType: "total", Direction: protocolDirectionReceive, Value: 217833})
	assert.Contains(t, stats.Packets, protocolPacketCounter{Protocol: "ip", MessageType: "forwarded_multicast", Direction: protocolDirectionTransmit, Value: 2})
	assert.Contains(t, stats.Packets, protocolPacketCounter{Protocol: "icmp", MessageType: "echo_reply", Direction: protocolDirectionTransmit, Value: 20})
	assert.Contains(t, stats.Errors, protocolErrorCounter{Protocol: "ip", ErrorType: "bad_checksum", Value: 4})
	assert.Contains(t, stats.Errors, protocolErrorCounter{Protocol: "icmp", ErrorType: "format_error", Value: 28})
	assert.Contains(t, stats.Drops, protocolDropCounter{Protocol: "ip", Reason: "no_route", Value: 8})
	assert.Contains(t, stats.Drops, protocolDropCounter{Protocol: "icmp", Reason: "output_drops_badlen", Value: 21})
	assert.Contains(t, stats.Drops, protocolDropCounter{Protocol: "ip", Reason: "fragments_dropped", Value: 13})
}

func TestParseProtocolTrafficNXOSRFC4293(t *testing.T) {
	output := `RFC 4293: IP Software Processed Traffic Statistics
----------------------------------------
Reception
  Pkts recv: 217833, Bytes recv: 16383836,
   inhdrerrors: 1, innoroutes: 2, inaddrerrors: 3,
   inunknownprotos: 4, intruncatedpkts: 5, inforwdgrams: 6,
   reasmreqds: 7, reasmoks: 8, reasmfails: 9,
   indiscards: 10, indelivers: 11,
   inmcastpkts: 12, inmcastbytes: 13,
   inbcastpkts: 14,
Transmission
  outrequests: 15, outnoroutes: 16, outforwdgrams: 17,
  outdiscards: 18, outfragreqds: 19, outfragoks: 20,
  outfragfails: 21, outfragcreates: 22, outtransmits: 23,
  bytes sent: 24, outmcastpkts: 25, outmcastbytes: 26,
  outbcastpkts: 27, outbcastbytes: 28`

	stats := parseProtocolTraffic(output)

	assert.Contains(t, stats.Packets, protocolPacketCounter{Protocol: "ip", MessageType: "total", Direction: protocolDirectionReceive, Value: 217833})
	assert.Contains(t, stats.Packets, protocolPacketCounter{Protocol: "ip", MessageType: "multicast", Direction: protocolDirectionReceive, Value: 12})
	assert.Contains(t, stats.Packets, protocolPacketCounter{Protocol: "ip", MessageType: "broadcast", Direction: protocolDirectionReceive, Value: 14})
	assert.Contains(t, stats.Packets, protocolPacketCounter{Protocol: "ip", MessageType: "total", Direction: protocolDirectionTransmit, Value: 23})
	assert.Contains(t, stats.Packets, protocolPacketCounter{Protocol: "ip", MessageType: "multicast", Direction: protocolDirectionTransmit, Value: 25})
	assert.Contains(t, stats.Packets, protocolPacketCounter{Protocol: "ip", MessageType: "broadcast", Direction: protocolDirectionTransmit, Value: 27})
	assert.Contains(t, stats.Errors, protocolErrorCounter{Protocol: "ip", ErrorType: "header_errors", Value: 1})
	assert.Contains(t, stats.Errors, protocolErrorCounter{Protocol: "ip", ErrorType: "unknown_protocol", Value: 4})
	assert.Contains(t, stats.Drops, protocolDropCounter{Protocol: "ip", Reason: "no_route", Value: 2})
	assert.Contains(t, stats.Drops, protocolDropCounter{Protocol: "ip", Reason: "discards", Value: 10})
	assert.Contains(t, stats.Drops, protocolDropCounter{Protocol: "ip", Reason: "fragmentation_failures", Value: 21})
	assert.NotContains(t, stats.Packets, protocolPacketCounter{Protocol: "ip", MessageType: "bytes_recv", Direction: protocolDirectionReceive, Value: 16383836})
}
