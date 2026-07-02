// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"path"
	"slices"
	"sort"
	"strings"
	"time"
)

type iosXRPathDefinition struct {
	ID                string
	Group             string
	Path              string
	Description       string
	Source            string
	ReleaseHint       string
	DefaultStreamMode string
	MinSampleInterval time.Duration
	HighVolume        bool
	Platforms         []string
}

func init() {
	for i := range iosXRPathCatalog {
		if len(iosXRPathCatalog[i].Platforms) == 0 {
			iosXRPathCatalog[i].Platforms = []string{"ASR 9000", "NCS 540", "NCS 5500", "NCS 5700"}
		}
		if iosXRPathCatalog[i].ReleaseHint == "" {
			iosXRPathCatalog[i].ReleaseHint = "Verify advertised YANG model support with gNMI Capabilities for the target IOS XR release"
		}
		if iosXRPathCatalog[i].Source == "" {
			if strings.HasPrefix(iosXRPathCatalog[i].Path, "openconfig-") {
				iosXRPathCatalog[i].Source = "OpenConfig model surfaced by IOS XR telemetry"
			} else {
				iosXRPathCatalog[i].Source = "Cisco IOS XR telemetry/YANG model guide"
			}
		}
	}
}

// The catalog intentionally uses specific gather-point paths instead of broad
// top-level containers. Cisco IOS XR telemetry docs warn that collection happens
// at gather points even when subscribing to individual leaves, so overly broad
// paths can add avoidable control-plane load.
var iosXRPathCatalog = []iosXRPathDefinition{
	{ID: "system.cpu", Group: "system", Path: "Cisco-IOS-XR-wdsysmon-fd-oper:system-monitoring/cpu-utilization", Description: "CPU utilization by node/process", MinSampleInterval: time.Minute},
	{ID: "system.memory", Group: "system", Path: "Cisco-IOS-XR-n" + "to-misc-oper:memory-summary/nodes/node/summary", Description: "Node memory summary", MinSampleInterval: time.Minute},
	{ID: "system.filesystem", Group: "system", Path: "Cisco-IOS-XR-shellutil-filesystem-oper:file-system/node", Description: "Filesystem state", MinSampleInterval: 5 * time.Minute},
	{ID: "platform.components", Group: "platform", Path: "openconfig-platform:components/component/state", Description: "OpenConfig platform component inventory/state", DefaultStreamMode: iosXRStreamModeTargetDefined, MinSampleInterval: 5 * time.Minute},
	{ID: "platform.native", Group: "platform", Path: "Cisco-IOS-XR-platform-oper:platform/racks/rack/slots/slot/instances/instance/state", Description: "Native IOS XR platform slot/instance state", MinSampleInterval: 5 * time.Minute},
	{ID: "environment.sensors", Group: "environment", Path: "Cisco-IOS-XR-sysadmin-envmon-ui:environment", Description: "Environmental telemetry for fan, PSU, voltage, and temperature state", MinSampleInterval: time.Minute},
	{ID: "environment.alarms", Group: "environment", Path: "Cisco-IOS-XR-alarmgr-server-oper:alarms/brief/brief-system", Description: "System alarm summary", DefaultStreamMode: iosXRStreamModeOnChange, MinSampleInterval: time.Minute},
	{ID: "interfaces.oc", Group: "interfaces", Path: "openconfig-interfaces:interfaces/interface/state", Description: "OpenConfig interface operational state", DefaultStreamMode: iosXRStreamModeTargetDefined, MinSampleInterval: time.Minute, HighVolume: true},
	{ID: "interfaces.counters", Group: "interfaces", Path: "Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/latest/generic-counters", Description: "Native interface counters", MinSampleInterval: time.Minute, HighVolume: true},
	{ID: "interfaces.rates", Group: "interfaces", Path: "Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/latest/data-rate", Description: "Native interface data rates", MinSampleInterval: time.Minute, HighVolume: true},
	{ID: "interfaces.ipv4", Group: "interfaces", Path: "openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/state", Description: "OpenConfig IPv4 subinterface state", DefaultStreamMode: iosXRStreamModeTargetDefined, MinSampleInterval: time.Minute, HighVolume: true},
	{ID: "interfaces.ipv6", Group: "interfaces", Path: "openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/state", Description: "OpenConfig IPv6 subinterface state", DefaultStreamMode: iosXRStreamModeTargetDefined, MinSampleInterval: time.Minute, HighVolume: true},
	{ID: "optics.controllers", Group: "optics", Path: "Cisco-IOS-XR-controller-optics-oper:optics-oper/optics-ports/optics-port/optics-info", Description: "Optical transceiver DOM and alarm state", MinSampleInterval: time.Minute, HighVolume: true},
	{ID: "optics.lanes", Group: "optics", Path: "Cisco-IOS-XR-controller-optics-oper:optics-oper/optics-ports/optics-port/optics-lane-info", Description: "Optical lane state", MinSampleInterval: time.Minute, HighVolume: true},
	{ID: "routing.rib.ipv4.summary", Group: "routing", Path: "Cisco-IOS-XR-ip-rib-ipv4-oper:rib/rib-table-ids/rib-table-id/summary-protos/summary-proto", Description: "IPv4 RIB route summary by protocol", MinSampleInterval: time.Minute},
	{ID: "routing.rib.ipv6.summary", Group: "routing", Path: "Cisco-IOS-XR-ip-rib-ipv6-oper:ipv6-rib/rib-table-ids/rib-table-id/summary-protos/summary-proto", Description: "IPv6 RIB route summary by protocol", MinSampleInterval: time.Minute},
	{ID: "routing.rib.ipv4.routes", Group: "routing", Path: "Cisco-IOS-XR-ip-rib-ipv4-oper:rib/vrfs/vrf/afs/af/safs/saf/ip-rib-route-table-names/ip-rib-route-table-name/routes/route", Description: "IPv4 RIB route entries", MinSampleInterval: 5 * time.Minute, HighVolume: true},
	{ID: "fib.drops", Group: "fib", Path: "Cisco-IOS-XR-fib-common-oper:fib-statistics/nodes/node/drops", Description: "FIB drop counters", MinSampleInterval: time.Minute},
	{ID: "fib.summary", Group: "fib", Path: "Cisco-IOS-XR-fib-common-oper:fib/nodes/node/protocols/protocol/vrfs/vrf/summary", Description: "CEF/FIB summary by protocol and VRF", MinSampleInterval: time.Minute},
	{ID: "fib.srv6loc", Group: "fib", Path: "Cisco-IOS-XR-fib-common-oper:cef/accounting/nodes/node/slot/protocols/protocol/vrfs/vrf/srv6locs/srv6loc", Description: "SRv6 local SID accounting", MinSampleInterval: time.Minute, HighVolume: true},
	{ID: "bgp.process", Group: "bgp", Path: "Cisco-IOS-XR-ipv4-bgp-oper:bgp/instances/instance/instance-active/default-vrf/process-info", Description: "BGP process state", MinSampleInterval: time.Minute},
	{ID: "bgp.neighbors", Group: "bgp", Path: "Cisco-IOS-XR-ipv4-bgp-oper:bgp/instances/instance/instance-active/default-vrf/neighbors/neighbor", Description: "BGP neighbor state", DefaultStreamMode: iosXRStreamModeOnChange, MinSampleInterval: time.Minute, HighVolume: true},
	{ID: "bgp.flowspec", Group: "bgp", Path: "Cisco-IOS-XR-flowspec-oper:flowspec/clients/client/afs/af/flows", Description: "BGP FlowSpec flow statistics", MinSampleInterval: time.Minute, HighVolume: true},
	{ID: "isis.global", Group: "isis", Path: "Cisco-IOS-XR-clns-isis-oper:isis/instances/instance/statistics-global", Description: "ISIS global statistics", MinSampleInterval: time.Minute},
	{ID: "isis.neighbors", Group: "isis", Path: "Cisco-IOS-XR-clns-isis-oper:isis/instances/instance/neighbors/neighbor", Description: "ISIS neighbor state", DefaultStreamMode: iosXRStreamModeOnChange, MinSampleInterval: time.Minute},
	{ID: "isis.adjacencies", Group: "isis", Path: "Cisco-IOS-XR-clns-isis-oper:isis/instances/instance/levels/level/adjacencies/adjacency", Description: "ISIS adjacency state", DefaultStreamMode: iosXRStreamModeOnChange, MinSampleInterval: time.Minute},
	{ID: "mpls.te.summary", Group: "mpls", Path: "Cisco-IOS-XR-mpls-te-oper:mpls-te/tunnels/summary", Description: "MPLS-TE tunnel summary", MinSampleInterval: time.Minute},
	{ID: "mpls.te.tunnels", Group: "mpls", Path: "Cisco-IOS-XR-mpls-te-oper:mpls-te/p2p-p2mp-tunnel/tunnel-heads/tunnel-head", Description: "MPLS-TE tunnel-head state", MinSampleInterval: time.Minute, HighVolume: true},
	{ID: "mpls.ldp.summary", Group: "mpls", Path: "Cisco-IOS-XR-mpls-ldp-oper:mpls-ldp/global/active/default-vrf/summary", Description: "MPLS LDP summary", MinSampleInterval: time.Minute},
	{ID: "mpls.ldp.neighbors", Group: "mpls", Path: "Cisco-IOS-XR-mpls-ldp-oper:mpls-ldp/nodes/node/default-vrf/neighbors/neighbor", Description: "MPLS LDP neighbor state", DefaultStreamMode: iosXRStreamModeOnChange, MinSampleInterval: time.Minute},
	{ID: "segment_routing.policies", Group: "segment_routing", Path: "Cisco-IOS-XR-infra-xtc-agent-oper:xtc/policies/policy", Description: "Segment routing traffic engineering policy state", MinSampleInterval: time.Minute},
	{ID: "segment_routing.srv6", Group: "segment_routing", Path: "Cisco-IOS-XR-segment-routing-srv6-oper:srv6/active/locators/locator", Description: "SRv6 locator and SID state", MinSampleInterval: time.Minute},
	{ID: "qos.policy", Group: "qos", Path: "Cisco-IOS-XR-infra-policymgr-oper:policy-manager/global/policy-map/policy-map-types/policy-map-type/vrf-table/vrf/afi-table/afi/stats", Description: "QoS/PBR policy-map statistics", MinSampleInterval: time.Minute, HighVolume: true},
	{ID: "qos.interface", Group: "qos", Path: "Cisco-IOS-XR-qos-ma-oper:qos/interface-table/interface/input/service-policy-names/service-policy-instance/statistics", Description: "Interface QoS service-policy statistics", MinSampleInterval: time.Minute, HighVolume: true},
	{ID: "security_policy.acl", Group: "security_policy", Path: "Cisco-IOS-XR-ipv4-acl-oper:ipv4-acl-and-prefix-list/access-list-manager/accesses/access", Description: "IPv4 ACL statistics", MinSampleInterval: time.Minute, HighVolume: true},
	{ID: "security_policy.flowspec", Group: "security_policy", Path: "Cisco-IOS-XR-flowspec-oper:flowspec/summary", Description: "FlowSpec summary", MinSampleInterval: time.Minute},
	{ID: "bfd.sessions", Group: "bfd", Path: "Cisco-IOS-XR-ip-bfd-oper:bfd/ipv4-single-hop-session-details/ipv4-single-hop-session-detail", Description: "BFD session details", DefaultStreamMode: iosXRStreamModeOnChange, MinSampleInterval: time.Minute},
	{ID: "topology.lldp.state", Group: "topology", Path: "openconfig-lldp:lldp/state", Description: "LLDP global state", DefaultStreamMode: iosXRStreamModeOnChange, MinSampleInterval: time.Minute},
	{ID: "topology.lldp.neighbors", Group: "topology", Path: "openconfig-lldp:lldp/interfaces/interface/neighbors/neighbor", Description: "LLDP neighbor state", DefaultStreamMode: iosXRStreamModeOnChange, MinSampleInterval: time.Minute},
	{ID: "time_sync.ntp", Group: "time_sync", Path: "openconfig-system:system/ntp", Description: "OpenConfig NTP state", MinSampleInterval: 5 * time.Minute},
	{ID: "time_sync.ptp", Group: "time_sync", Path: "Cisco-IOS-XR-ptp-oper:ptp/nodes/node", Description: "PTP node state", MinSampleInterval: time.Minute},
	{ID: "asic.errors", Group: "asic", Path: "Cisco-IOS-XR-fia-internal-tcam-oper:controller/dpa/nodes/node/internal-tcam-resources", Description: "ASIC/internal TCAM resources", MinSampleInterval: time.Minute},
	{ID: "asic.npu", Group: "asic", Path: "Cisco-IOS-XR-fia-oper:controllers/controller/dpa/resources", Description: "NPU forwarding ASIC resources", MinSampleInterval: time.Minute},
	{ID: "telemetry_self.subscriptions", Group: "telemetry_self", Path: "Cisco-IOS-XR-telemetry-model-driven-oper:telemetry-model-driven/subscriptions/subscription", Description: "IOS XR telemetry subscription state", MinSampleInterval: time.Minute},
	{ID: "telemetry_self.destinations", Group: "telemetry_self", Path: "Cisco-IOS-XR-telemetry-model-driven-oper:telemetry-model-driven/destinations/destination", Description: "IOS XR telemetry destination state", MinSampleInterval: time.Minute},
}

func iosXRPathGroupNames() []string {
	seen := map[string]struct{}{}
	for i := range iosXRPathCatalog {
		seen[iosXRPathCatalog[i].Group] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func isKnownIOSXRPathGroup(name string) bool {
	return slices.Contains(iosXRPathGroupNames(), name)
}

func resolveIOSXRPathSelection(globalGroups map[string]IOSXRPathGroupConfig, globalPaths IOSXRPathOverrideConfig, target *IOSXRTargetConfig) []iosXRPathDefinition {
	groups := globalGroups
	paths := globalPaths
	if target != nil {
		if target.PathGroups != nil {
			groups = target.PathGroups
		}
		if len(target.Paths.Include) > 0 || len(target.Paths.Exclude) > 0 {
			paths = target.Paths
		}
	}

	selected := make([]iosXRPathDefinition, 0, len(iosXRPathCatalog)+len(paths.Include))
	seen := map[string]struct{}{}
	for i := range iosXRPathCatalog {
		def := iosXRPathCatalog[i]
		if groups[def.Group].Enabled && !iosXRPathExcluded(def, paths.Exclude) {
			if _, ok := seen[def.Path]; !ok {
				selected = append(selected, def)
				seen[def.Path] = struct{}{}
			}
		}
	}
	for _, custom := range paths.Include {
		custom = strings.TrimSpace(custom)
		if custom == "" {
			continue
		}
		def := iosXRPathDefinition{
			ID:                "custom." + sanitizeMetricSegment(custom),
			Group:             "custom",
			Path:              custom,
			Description:       "Custom IOS XR telemetry path",
			DefaultStreamMode: iosXRStreamModeSample,
			MinSampleInterval: time.Minute,
		}
		if iosXRPathExcluded(def, paths.Exclude) {
			continue
		}
		if _, ok := seen[def.Path]; !ok {
			selected = append(selected, def)
			seen[def.Path] = struct{}{}
		}
	}
	return selected
}

func iosXRPathExcluded(def iosXRPathDefinition, excludes []string) bool {
	for _, exclude := range excludes {
		exclude = strings.TrimSpace(exclude)
		if exclude == "" {
			continue
		}
		if exclude == def.ID || exclude == def.Group || exclude == def.Path {
			return true
		}
		if ok, _ := path.Match(exclude, def.ID); ok {
			return true
		}
		if ok, _ := path.Match(exclude, def.Path); ok {
			return true
		}
		if strings.Contains(exclude, "*") && simpleWildcardMatch(exclude, def.Path) {
			return true
		}
	}
	return false
}

func simpleWildcardMatch(pattern, value string) bool {
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(value[pos:], part)
		if idx < 0 {
			return false
		}
		if i == 0 && !strings.HasPrefix(pattern, "*") && idx != 0 {
			return false
		}
		pos += idx + len(part)
	}
	return strings.HasSuffix(pattern, "*") || strings.HasSuffix(value, parts[len(parts)-1])
}
