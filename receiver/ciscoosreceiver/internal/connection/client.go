// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package connection // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// RPCClient represents RPC client for executing Cisco commands
type RPCClient struct {
	SSHClient      *Client
	OSType         string
	DeviceMetadata DeviceMetadata
	Timeout        time.Duration
	Logger         *zap.Logger
}

// GetOSType returns detected Cisco OS type
func (r *RPCClient) GetOSType() string {
	if r.SSHClient != nil {
		if metadata, ok := r.SSHClient.currentDeviceMetadata(); ok && metadata.OSType != "" {
			return metadata.OSType
		}
	}
	if r.OSType != "" {
		return r.OSType
	}
	return "unknown"
}

func (r *RPCClient) GetDeviceMetadata() DeviceMetadata {
	if r.SSHClient != nil {
		if metadata, ok := r.SSHClient.currentDeviceMetadata(); ok {
			return metadata
		}
	}
	metadata := r.DeviceMetadata
	if metadata.OSType == "" {
		metadata.OSType = r.GetOSType()
	}
	return metadata
}

func (r *RPCClient) GetReconnectCount() int64 {
	if r.SSHClient == nil {
		return 0
	}
	return r.SSHClient.ReconnectCount()
}

// GetCommand returns the appropriate command for the OS type and feature
func (r *RPCClient) GetCommand(feature string) string {
	commands := r.GetCommands(feature)
	if len(commands) > 0 {
		return commands[0]
	}
	return ""
}

// GetCommands returns candidate commands for the OS type and feature.
// Some optional counters live behind platform-specific show commands whose
// spelling varies across Cisco OS families and releases.
func (r *RPCClient) GetCommands(feature string) []string {
	osType := r.GetOSType()
	switch feature {
	case "version":
		return []string{"show version"}
	case "cpu":
		if osType == "NX-OS" {
			return []string{"show system resources"}
		}
		return []string{"show process cpu"}
	case "memory":
		if osType == "NX-OS" {
			return []string{"show system resources"}
		}
		return []string{"show process memory"}
	case "interfaces":
		return []string{"show interface"}
	case "interface_counters":
		if osType == "NX-OS" {
			return []string{"show interface counters"}
		}
		return []string{"show interfaces counters"}
	case "interface_error_counters":
		if osType == "NX-OS" {
			return []string{"show interface counters errors"}
		}
		return []string{"show interfaces counters errors"}
	case "interface_flowcontrol":
		if osType == "NX-OS" {
			return []string{"show interface flowcontrol"}
		}
		return []string{"show interfaces flowcontrol", "show flowcontrol"}
	case "interface_priority_flow_control":
		if osType == "NX-OS" {
			return []string{"show interface priority-flow-control detail", "show interface priority-flow-control"}
		}
		return nil
	case "interface_queueing":
		if osType == "NX-OS" {
			return []string{"show queuing interface", "show queuing"}
		}
		return nil
	case "interface_pfc_watchdog":
		if osType == "NX-OS" {
			return []string{"show queuing pfc-queue detail"}
		}
		return nil
	case "interface_qos_policy":
		return []string{"show policy-map interface"}
	case "interface_platform_queue_stats":
		if osType == "NX-OS" {
			return nil
		}
		return []string{
			"show platform hardware fed active qos queue stats interface",
			"show platform hardware fed switch active qos queue stats interface",
		}
	case "hardware_environment":
		if osType == "NX-OS" {
			return []string{"show environment"}
		}
		return []string{"show environment all", "show environment"}
	case "hardware_module":
		if osType == "NX-OS" {
			return []string{"show module"}
		}
		return []string{"show platform"}
	case "hardware_inventory":
		return []string{"show inventory"}
	case "ip_traffic":
		return []string{"show ip traffic"}
	case "control_cpu_processes":
		if osType == "NX-OS" {
			return []string{"show process cpu sort", "show processes cpu sort", "show process cpu", "show processes cpu"}
		}
		return []string{"show processes cpu sorted 5sec", "show process cpu sorted 5sec", "show processes cpu platform sorted"}
	case "control_copp":
		if osType == "NX-OS" {
			return []string{"show policy-map interface control-plane", "show copp status", "show hardware rate-limiter"}
		}
		return []string{"show policy-map control-plane", "show policy-map system-cpp-policy"}
	case "control_punt_rates":
		if osType == "NX-OS" {
			return nil
		}
		return []string{
			"show platform software fed active punt rates interfaces",
			"show platform software fed switch active punt rates interfaces",
		}
	case "routing_route_summary":
		if osType == "NX-OS" {
			return []string{"show ip route summary vrf %s", "show routing ip unicast summary vrf %s"}
		}
		return []string{"show ip route summary", "show ip route vrf %s summary"}
	case "routing_arp":
		if osType == "NX-OS" {
			return []string{"show ip arp summary vrf %s", "show ip arp statistics vrf %s"}
		}
		return []string{"show arp summary", "show ip arp summary", "show ip arp vrf %s summary"}
	case "routing_cef_fib":
		if osType == "NX-OS" {
			return []string{"show forwarding route summary vrf %s", "show ip route summary vrf %s"}
		}
		return []string{"show ip cef summary", "show ip cef vrf %s summary", "show ip cef detail"}
	case "routing_adjacency":
		if osType == "NX-OS" {
			return []string{"show ip adjacency summary vrf %s"}
		}
		return []string{"show adjacency summary", "show adjacency vrf %s summary"}
	case "routing_forwarding_drops":
		if osType == "NX-OS" {
			return []string{"show forwarding distribution drops vrf %s", "show hardware internal errors module all"}
		}
		return []string{
			"show cef drop",
			"show ip cef switching statistics",
			"show platform hardware fed active fwd-asic drops exceptions",
			"show platform hardware fed active fwd-asic drops cpu",
			"show platform hardware fed switch active fwd-asic drops exceptions",
			"show platform hardware fed switch active fwd-asic drops cpu",
			"show platform hardware fed active fwd-asic drops",
		}
	case "routing_bgp_neighbors":
		if osType == "NX-OS" {
			return []string{"show bgp ipv4 unicast summary vrf %s", "show ip bgp summary vrf %s"}
		}
		return []string{"show ip bgp summary", "show bgp ipv4 unicast summary", "show ip bgp vpnv4 vrf %s summary"}
	case "routing_ospf_neighbors":
		if osType == "NX-OS" {
			return []string{"show ip ospf neighbors vrf %s", "show ip ospf neighbor vrf %s"}
		}
		return []string{"show ip ospf neighbor", "show ip ospf neighbor vrf %s"}
	case "routing_eigrp_neighbors":
		if osType == "NX-OS" {
			return nil
		}
		return []string{"show ip eigrp neighbors", "show ip eigrp vrf %s neighbors"}
	case "routing_isis_neighbors":
		if osType == "NX-OS" {
			return []string{"show isis adjacency vrf %s", "show isis adjacency"}
		}
		return []string{"show isis adjacency"}
	case "router_qfp_utilization":
		if osType == "NX-OS" {
			return nil
		}
		return []string{
			"show platform hardware qfp active datapath utilization",
			"show platform hardware qfp active datapath utilization summary",
		}
	case "router_qfp_drops":
		if osType == "NX-OS" {
			return nil
		}
		return []string{
			"show drops qfp",
			"show platform hardware qfp active statistics drop detail",
		}
	case "router_interface_drops":
		if osType == "NX-OS" {
			return nil
		}
		return []string{
			"show platform hardware qfp active interface all statistics drop_summary",
			"show drops interface",
		}
	case "router_qos_drops":
		if osType == "NX-OS" {
			return nil
		}
		return []string{"show drops qos"}
	case "router_crypto_drops":
		if osType == "NX-OS" {
			return nil
		}
		return []string{"show drops crypto"}
	case "router_nat_drops":
		if osType == "NX-OS" {
			return nil
		}
		return []string{"show drops nat"}
	case "router_punt_drops":
		if osType == "NX-OS" {
			return nil
		}
		return []string{"show drops punt"}
	case "router_ip_drops":
		if osType == "NX-OS" {
			return nil
		}
		return []string{"show drops ip-all"}
	case "l2_stp":
		return []string{"show spanning-tree summary", "show spanning-tree detail", "show spanning-tree blockedports"}
	case "l2_port_channel":
		if osType == "NX-OS" {
			return []string{"show port-channel summary"}
		}
		return []string{"show etherchannel summary"}
	case "l2_lacp":
		return []string{"show lacp counters"}
	case "l2_err_disabled":
		if osType == "NX-OS" {
			return []string{"show interface status err-disabled"}
		}
		return []string{"show interfaces status err-disabled"}
	case "l2_vpc":
		if osType == "NX-OS" {
			return []string{"show vpc", "show vpc consistency-parameters global"}
		}
		return nil
	case "l2_lldp":
		return []string{"show lldp neighbors detail"}
	case "l2_cdp":
		return []string{"show cdp neighbors detail"}
	case "transceiver":
		if osType == "NX-OS" {
			return []string{"show interface transceiver details"}
		}
		return []string{"show interfaces transceiver details", "show interfaces transceiver detail"}
	case "fabric_nve_peers":
		if osType == "NX-OS" {
			return []string{"show nve peers"}
		}
		return nil
	case "fabric_nve_vni":
		if osType == "NX-OS" {
			return []string{"show nve vni"}
		}
		return nil
	case "fabric_evpn_routes":
		if osType == "NX-OS" {
			return []string{"show bgp l2vpn evpn summary", "show bgp l2vpn evpn route-type all summary"}
		}
		return nil
	default:
		return nil
	}
}

// ExecuteCommand executes a command on the Cisco device
func (r *RPCClient) ExecuteCommand(command string) (string, error) {
	return r.ExecuteCommandWithContext(context.Background(), command)
}

// ExecuteCommandWithContext executes a command on the Cisco device with the
// receiver command timeout layered on top of the caller's context.
func (r *RPCClient) ExecuteCommandWithContext(ctx context.Context, command string) (string, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return r.SSHClient.ExecuteCommand(ctx, command)
}

func (r *RPCClient) Close() error {
	if r.SSHClient == nil {
		return nil
	}
	return r.SSHClient.Close()
}
