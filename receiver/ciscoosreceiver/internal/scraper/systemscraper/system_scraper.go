// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package systemscraper // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/systemscraper"

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/scraper"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/systemscraper/internal/metadata"
)

type systemCommandClient interface {
	GetOSType() string
	GetCommand(string) string
	GetCommands(string) []string
	ExecuteCommand(string) (string, error)
	Close() error
}

type contextSystemCommandClient interface {
	ExecuteCommandWithContext(context.Context, string) (string, error)
}

type metadataSystemCommandClient interface {
	GetDeviceMetadata() connection.DeviceMetadata
}

type reconnectSystemCommandClient interface {
	GetReconnectCount() int64
}

var errCoreMetricOutputUnparseable = errors.New("core metric output unparseable")

type commandErrorKey struct {
	family    string
	errorType string
}

// systemScraper collects system-level metrics for the Cisco device
type systemScraper struct {
	logger             *zap.Logger
	config             *Config
	mb                 *metadata.MetricsBuilder
	collectionCount    int
	deviceTarget       string
	rpcClient          systemCommandClient
	lastReconnectCount int64
	totalReconnects    int64
	partialSuccess     bool
	commandErrors      map[commandErrorKey]int64
}

func (s *systemScraper) Start(_ context.Context, _ component.Host) error {
	s.logger.Info("Starting system scraper with metric configuration",
		zap.Bool("device_up_enabled", s.config.MetricsBuilderConfig.Metrics.CiscoDeviceUp.Enabled))

	s.mb = metadata.NewMetricsBuilder(s.config.MetricsBuilderConfig, scraper.Settings{
		ID:                component.MustNewIDWithName(metadata.Type.String(), "system"),
		TelemetrySettings: component.TelemetrySettings{Logger: s.logger},
	})
	s.commandErrors = make(map[commandErrorKey]int64)

	if s.config.Device.Device.Host.IP == "" {
		return errors.New("no device configured")
	}

	device := s.config.Device
	s.deviceTarget = device.Device.Host.IP

	// Log authentication method (key file is tried first when both are present)
	authMethod := "password"
	switch {
	case device.Auth.KeyFile != "" && device.Auth.Password != "":
		authMethod = "key_file_then_password"
	case device.Auth.KeyFile != "":
		authMethod = "key_file"
	}

	s.logger.Info("System scraper initialized - will establish persistent SSH connection on first collection",
		zap.String("target", s.deviceTarget),
		zap.Int("port", device.Device.Host.Port),
		zap.String("username", device.Auth.Username),
		zap.String("auth_method", authMethod))

	return nil
}

func (s *systemScraper) Shutdown(_ context.Context) error {
	s.logger.Info("Shutting down system scraper")

	if s.rpcClient != nil {
		s.logger.Info("Closing persistent SSH connection", zap.String("target", s.deviceTarget))
		if err := s.rpcClient.Close(); err != nil {
			s.logger.Warn("Error closing SSH connection", zap.Error(err))
		}
		s.rpcClient = nil
	}

	return nil
}

func (s *systemScraper) ScrapeMetrics(ctx context.Context) (pmetric.Metrics, error) {
	s.collectionCount++
	s.partialSuccess = false
	now := pcommon.NewTimestampFromTime(time.Now())

	if s.rpcClient == nil {
		s.logger.Info("Establishing persistent SSH connection",
			zap.String("target", s.deviceTarget),
			zap.Int("collection_number", s.collectionCount))

		rpcClient, err := connection.EstablishDeviceConnection(
			ctx,
			s.config.Device,
			s.config.Timeout,
			s.logger,
		)
		if err != nil {
			s.logger.Error("Device connection failed - recording cisco.device.up=0",
				zap.String("target", s.deviceTarget),
				zap.Int("collection_number", s.collectionCount),
				zap.String("error_type", fmt.Sprintf("%T", err)),
				zap.Error(err))

			s.rpcClient = nil
			s.mb.RecordCiscoDeviceUpDataPoint(now, 0)

			s.logger.Info("Device down - recorded metrics",
				zap.Float64("cisco.device.up", 0))

			// Set resource attributes
			s.recordScrapeHealth(now)
			rb := s.newResourceBuilder()

			return s.emitMetricsWithResource(rb), nil
		}

		s.rpcClient = rpcClient
		s.logger.Info("Persistent SSH connection established successfully",
			zap.String("target", s.deviceTarget),
			zap.String("os_type", s.rpcClient.GetOSType()))
	}

	cpuUtil, cpuErr := s.collectCPUUtilization(ctx)
	memUtil, memErr := s.collectMemoryUtilization(ctx)

	// Only two command-execution failures indicate that the established
	// connection is likely broken. A command that returned output which the
	// parser could not understand still proves that the device is reachable.
	if cpuErr != nil && memErr != nil &&
		!coreMetricErrorIndicatesCommandResponse(cpuErr) &&
		!coreMetricErrorIndicatesCommandResponse(memErr) {
		s.logger.Warn("Both CPU and memory collection failed; assuming connection broken, will reconnect next cycle",
			zap.String("target", s.deviceTarget),
			zap.Error(cpuErr))
		s.mb.RecordCiscoDeviceUpDataPoint(now, 0)
		s.recordScrapeHealth(now)
		rb := s.newResourceBuilder()
		metrics := s.emitMetricsWithResource(rb)
		s.rpcClient.Close()
		s.rpcClient = nil
		return metrics, nil
	}

	s.mb.RecordCiscoDeviceUpDataPoint(now, 1)
	s.recordSystemUptime(now)

	if cpuErr == nil {
		s.mb.RecordSystemCPUUtilizationDataPoint(now, cpuUtil)
	} else {
		s.partialSuccess = true
		s.logger.Warn("Failed to collect CPU utilization, skipping metric",
			zap.Error(cpuErr))
	}

	if memErr == nil {
		s.mb.RecordSystemMemoryUtilizationDataPoint(now, memUtil)
	} else {
		s.partialSuccess = true
		s.logger.Warn("Failed to collect memory utilization, skipping metric",
			zap.Error(memErr))
	}

	if s.config.ProtocolTraffic.Enabled {
		if protocolStats, err := s.collectProtocolTraffic(ctx); err == nil {
			s.recordProtocolTraffic(now, protocolStats)
		} else {
			s.partialSuccess = true
			s.logger.Warn("Failed to collect protocol traffic statistics, skipping metrics",
				zap.Error(err))
		}
	}

	optionalCtx, cancelOptional := context.WithTimeout(ctx, s.optionalCollectionBudget())
	defer cancelOptional()
	s.collectControlPlaneTroubleshooting(optionalCtx, now)
	s.collectRoutingForwardingTroubleshooting(optionalCtx, now)
	s.collectRouterDataplane(optionalCtx, now)
	s.collectHardwareHealth(optionalCtx, now)
	s.collectRoutingNeighbors(optionalCtx, now)
	s.collectFabric(optionalCtx, now)
	s.recordScrapeHealth(now)

	// Set resource attributes
	rb := s.newResourceBuilder()

	return s.emitMetricsWithResource(rb), nil
}

func coreMetricErrorIndicatesCommandResponse(err error) bool {
	return errors.Is(err, errCoreMetricOutputUnparseable) || connection.ErrorIndicatesCommandResponse(err)
}

func (s *systemScraper) collectControlPlaneTroubleshooting(ctx context.Context, ts pcommon.Timestamp) {
	if s.rpcClient == nil || !s.config.ControlPlane.emitsMetrics() {
		return
	}

	if s.config.ControlPlane.commandEnabled("control_cpu_processes") {
		for _, command := range s.rpcClient.GetCommands("control_cpu_processes") {
			if ctx.Err() != nil {
				return
			}
			output, err := s.executeOptionalCommand(ctx, "control_cpu_processes", command)
			if err != nil {
				s.logOptionalCommandFailure(command, err)
				continue
			}
			processes := parseControlPlaneCPUProcesses(output, s.controlPlaneProcessTopN())
			if len(processes) == 0 {
				s.logger.Debug("Control-plane CPU process command returned no parseable rows", zap.String("command", command))
				continue
			}
			for _, process := range processes {
				s.mb.RecordCiscoControlPlaneCPUProcessUtilizationDataPoint(ts, process.Utilization, process.Name, process.PID, process.Window)
			}
			break
		}
	}

	if s.config.ControlPlane.commandEnabled("control_copp") {
		for _, command := range s.rpcClient.GetCommands("control_copp") {
			if ctx.Err() != nil {
				return
			}
			output, err := s.executeOptionalCommand(ctx, "control_copp", command)
			if err != nil {
				s.logOptionalCommandFailure(command, err)
				continue
			}
			packets, drops := parseControlPlanePolicy(output, command)
			if len(packets) == 0 && len(drops) == 0 {
				s.logger.Debug("Control-plane policy command returned no parseable rows", zap.String("command", command))
				continue
			}
			for _, packet := range packets {
				direction, ok := protocolDirectionToAttribute(packet.Direction)
				if !ok {
					continue
				}
				s.mb.RecordCiscoControlPlanePacketsDataPoint(ts, packet.Value, packet.Source, packet.Class, direction)
			}
			for _, drop := range drops {
				s.mb.RecordCiscoControlPlaneDroppedDataPoint(ts, drop.Value, drop.Source, drop.Class, drop.Reason)
			}
			break
		}
	}

	if s.config.ControlPlane.commandEnabled("control_punt_rates") {
		for _, command := range s.rpcClient.GetCommands("control_punt_rates") {
			if ctx.Err() != nil {
				return
			}
			output, err := s.executeOptionalCommand(ctx, "control_punt_rates", command)
			if err != nil {
				s.logOptionalCommandFailure(command, err)
				continue
			}
			rates := parseControlPlanePuntRates(output)
			if len(rates) == 0 {
				s.logger.Debug("Control-plane punt rate command returned no parseable rows", zap.String("command", command))
				continue
			}
			for _, rate := range rates {
				s.mb.RecordCiscoControlPlanePuntRateDataPoint(ts, rate.Value, rate.Queue, rate.Interface)
			}
			break
		}
	}
}

func (s *systemScraper) collectRoutingForwardingTroubleshooting(ctx context.Context, ts pcommon.Timestamp) {
	if s.rpcClient == nil || !s.config.RoutingForwarding.emitsMetrics() {
		return
	}

	for _, vrf := range s.routingVRFs() {
		if s.config.RoutingForwarding.commandEnabled("routing_route_summary") {
			for _, command := range s.commandsForVRF("routing_route_summary", vrf) {
				if ctx.Err() != nil {
					return
				}
				output, err := s.executeOptionalCommand(ctx, "routing_route_summary", command)
				if err != nil {
					s.logOptionalCommandFailure(command, err)
					continue
				}
				routes := parseRouteSummary(output, vrf)
				for _, route := range routes {
					s.mb.RecordCiscoRoutingRoutesDataPoint(ts, route.Value, route.VRF, route.Source, route.AddressFamily)
				}
				if len(routes) > 0 {
					break
				}
			}
		}

		if s.config.RoutingForwarding.commandEnabled("routing_arp") {
			for _, command := range s.commandsForVRF("routing_arp", vrf) {
				if ctx.Err() != nil {
					return
				}
				output, err := s.executeOptionalCommand(ctx, "routing_arp", command)
				if err != nil {
					s.logOptionalCommandFailure(command, err)
					continue
				}
				entries := parseARPSummary(output, vrf)
				for _, entry := range entries {
					s.mb.RecordCiscoArpEntriesDataPoint(ts, entry.Value, entry.VRF, entry.AddressFamily)
				}
				if len(entries) > 0 {
					break
				}
			}
		}

		if s.config.RoutingForwarding.commandEnabled("routing_cef_fib") {
			for _, command := range s.commandsForVRF("routing_cef_fib", vrf) {
				if ctx.Err() != nil {
					return
				}
				output, err := s.executeOptionalCommand(ctx, "routing_cef_fib", command)
				if err != nil {
					s.logOptionalCommandFailure(command, err)
					continue
				}
				entries := parseFIBSummary(output, vrf)
				for _, entry := range entries {
					s.mb.RecordCiscoForwardingFibEntriesDataPoint(ts, entry.Value, entry.VRF, entry.AddressFamily)
				}
				if len(entries) > 0 {
					break
				}
			}
		}

		if s.config.RoutingForwarding.commandEnabled("routing_adjacency") {
			for _, command := range s.commandsForVRF("routing_adjacency", vrf) {
				if ctx.Err() != nil {
					return
				}
				output, err := s.executeOptionalCommand(ctx, "routing_adjacency", command)
				if err != nil {
					s.logOptionalCommandFailure(command, err)
					continue
				}
				entries := parseAdjacencySummary(output, vrf)
				for _, entry := range entries {
					s.mb.RecordCiscoAdjacencyEntriesDataPoint(ts, entry.Value, entry.VRF, entry.State)
				}
				if len(entries) > 0 {
					break
				}
			}
		}

		if s.config.RoutingForwarding.commandEnabled("routing_forwarding_drops") {
			for _, command := range s.commandsForVRF("routing_forwarding_drops", vrf) {
				if ctx.Err() != nil {
					return
				}
				output, err := s.executeOptionalCommand(ctx, "routing_forwarding_drops", command)
				if err != nil {
					s.logOptionalCommandFailure(command, err)
					continue
				}
				drops := parseForwardingDrops(output, vrf)
				for _, drop := range drops {
					s.mb.RecordCiscoForwardingDropsDataPoint(ts, drop.Value, drop.VRF, drop.Reason)
				}
				if len(drops) > 0 {
					break
				}
			}
		}
	}
}

func (s *systemScraper) collectRouterDataplane(ctx context.Context, ts pcommon.Timestamp) {
	if s.rpcClient == nil || !s.config.RouterDataplane.emitsMetrics() {
		return
	}

	if s.config.RouterDataplane.commandEnabled("router_qfp_utilization") {
		for _, command := range s.rpcClient.GetCommands("router_qfp_utilization") {
			if ctx.Err() != nil {
				return
			}
			output, err := s.executeOptionalCommand(ctx, "router_qfp_utilization", command)
			if err != nil {
				s.logOptionalCommandFailure(command, err)
				continue
			}
			rates, utilizations := parseQFPDatapathUtilization(output)
			for _, rate := range rates {
				direction, ok := protocolDirectionToAttribute(rate.Direction)
				if !ok {
					continue
				}
				s.mb.RecordCiscoQfpDatapathPacketRateDataPoint(ts, rate.PacketsPerSecond, direction, rate.TrafficClass, rate.Window)
				s.mb.RecordCiscoQfpDatapathIoDataPoint(ts, rate.BitsPerSecond, direction, rate.TrafficClass, rate.Window)
			}
			for _, utilization := range utilizations {
				s.mb.RecordCiscoQfpDatapathUtilizationDataPoint(ts, utilization.Value, utilization.LoadType, utilization.Window)
			}
			if len(rates) > 0 || len(utilizations) > 0 {
				break
			}
		}
	}

	s.collectRouterDropCommands(ctx, ts, "router_qfp_drops", "qfp")
	s.collectRouterDropCommands(ctx, ts, "router_interface_drops", "interface")
	s.collectRouterDropCommands(ctx, ts, "router_qos_drops", "qos")
	s.collectRouterDropCommands(ctx, ts, "router_crypto_drops", "crypto")
	s.collectRouterDropCommands(ctx, ts, "router_nat_drops", "nat")
	s.collectRouterDropCommands(ctx, ts, "router_punt_drops", "punt")
	s.collectRouterDropCommands(ctx, ts, "router_ip_drops", "ip_all")
}

func (s *systemScraper) collectRouterDropCommands(ctx context.Context, ts pcommon.Timestamp, feature, source string) {
	if !s.config.RouterDataplane.commandEnabled(feature) {
		return
	}

	for _, command := range s.rpcClient.GetCommands(feature) {
		if ctx.Err() != nil {
			return
		}
		output, err := s.executeOptionalCommand(ctx, feature, command)
		if err != nil {
			s.logOptionalCommandFailure(command, err)
			continue
		}
		drops, interfaceDrops := parseQFPDrops(output, source)
		for _, drop := range drops {
			s.mb.RecordCiscoQfpDropsDataPoint(ts, drop.Packets, drop.Source, drop.Reason)
			s.mb.RecordCiscoQfpDropBytesDataPoint(ts, drop.Octets, drop.Source, drop.Reason)
		}
		for _, drop := range interfaceDrops {
			direction, ok := protocolDirectionToAttribute(drop.Direction)
			if !ok {
				continue
			}
			s.mb.RecordCiscoQfpInterfaceDropsDataPoint(ts, drop.Packets, drop.Interface, direction)
		}
		if len(drops) > 0 || len(interfaceDrops) > 0 {
			break
		}
	}
}

func (s *systemScraper) collectHardwareHealth(ctx context.Context, ts pcommon.Timestamp) {
	if s.rpcClient == nil || !s.config.HardwareHealth.emitsMetrics() {
		return
	}

	admittedComponents := make(map[string]struct{}, s.hardwareMaxComponents())
	componentAllowed := func(name, slot string) bool {
		key := normalizeTroubleshootingLabel(name) + "\x00" + normalizeTroubleshootingLabel(slot)
		if _, admitted := admittedComponents[key]; admitted {
			return true
		}
		if len(admittedComponents) >= s.hardwareMaxComponents() {
			return false
		}
		admittedComponents[key] = struct{}{}
		return true
	}
	for _, feature := range []string{"hardware_environment", "hardware_module", "hardware_inventory"} {
		if !s.config.HardwareHealth.commandEnabled(feature) {
			continue
		}
		for _, command := range s.rpcClient.GetCommands(feature) {
			if ctx.Err() != nil {
				return
			}
			output, err := s.executeOptionalCommand(ctx, feature, command)
			if err != nil {
				s.logOptionalCommandFailure(command, err)
				continue
			}
			statuses, temperatures := parseHardwareHealth(output, feature)
			for _, status := range statuses {
				if !componentAllowed(status.Name, status.Slot) {
					continue
				}
				s.mb.RecordCiscoHardwareStatusDataPoint(ts, status.Value, status.Component, status.Name, status.Slot, status.State)
			}
			for _, temperature := range temperatures {
				if !componentAllowed(temperature.Name, temperature.Slot) {
					continue
				}
				s.mb.RecordCiscoHardwareTemperatureDataPoint(ts, temperature.Value, temperature.Name, temperature.Slot, temperature.State)
			}
			if len(statuses) > 0 || len(temperatures) > 0 {
				break
			}
		}
	}
}

func (s *systemScraper) collectRoutingNeighbors(ctx context.Context, ts pcommon.Timestamp) {
	if s.rpcClient == nil || !s.config.RoutingNeighbors.emitsMetrics() {
		return
	}

	recorded := 0
	features := []struct {
		name     string
		protocol string
	}{
		{name: "routing_bgp_neighbors", protocol: "bgp"},
		{name: "routing_ospf_neighbors", protocol: "ospf"},
		{name: "routing_eigrp_neighbors", protocol: "eigrp"},
		{name: "routing_isis_neighbors", protocol: "isis"},
	}
	for _, feature := range features {
		if !s.config.RoutingNeighbors.commandEnabled(feature.name) {
			continue
		}
		for _, vrf := range s.routingNeighborVRFs() {
			for _, command := range s.commandsForRoutingNeighborVRF(feature.name, vrf) {
				if ctx.Err() != nil || recorded >= s.routingNeighborMaxNeighbors() {
					return
				}
				output, err := s.executeOptionalCommand(ctx, feature.name, command)
				if err != nil {
					s.logOptionalCommandFailure(command, err)
					continue
				}
				neighbors := parseRoutingNeighbors(output, feature.protocol, vrf)
				for _, neighbor := range neighbors {
					if recorded >= s.routingNeighborMaxNeighbors() {
						return
					}
					s.mb.RecordCiscoRoutingNeighborStateDataPoint(ts, boolToInt(neighbor.Up), neighbor.Protocol, neighbor.VRF, neighbor.Peer, neighbor.State, neighbor.AddressFamily)
					if neighbor.HasPrefixes {
						s.mb.RecordCiscoRoutingNeighborPrefixesDataPoint(ts, neighbor.Prefixes, neighbor.Protocol, neighbor.VRF, neighbor.Peer, neighbor.AddressFamily)
					}
					recorded++
				}
				if len(neighbors) > 0 {
					break
				}
			}
		}
	}
}

func (s *systemScraper) collectFabric(ctx context.Context, ts pcommon.Timestamp) {
	if s.rpcClient == nil || !s.config.Fabric.emitsMetrics() {
		return
	}

	if s.config.Fabric.commandEnabled("fabric_nve_peers") {
		recorded := 0
		for _, command := range s.rpcClient.GetCommands("fabric_nve_peers") {
			output, err := s.executeOptionalCommand(ctx, "fabric_nve_peers", command)
			if err != nil {
				s.logOptionalCommandFailure(command, err)
				if ctx.Err() != nil {
					return
				}
				continue
			}
			for _, peer := range parseNVEPeers(output) {
				if recorded >= s.fabricMaxPeers() {
					break
				}
				s.mb.RecordCiscoNvePeerStatusDataPoint(ts, boolToInt(peer.Up), peer.Peer, peer.State)
				recorded++
			}
			if recorded > 0 {
				break
			}
		}
	}

	if s.config.Fabric.commandEnabled("fabric_nve_vni") {
		recorded := 0
		for _, command := range s.rpcClient.GetCommands("fabric_nve_vni") {
			output, err := s.executeOptionalCommand(ctx, "fabric_nve_vni", command)
			if err != nil {
				s.logOptionalCommandFailure(command, err)
				if ctx.Err() != nil {
					return
				}
				continue
			}
			for _, vni := range parseNVEVNIs(output) {
				if recorded >= s.fabricMaxVNIs() {
					break
				}
				s.mb.RecordCiscoNveVniStatusDataPoint(ts, boolToInt(vni.Up), vni.VNI, vni.Type, vni.State)
				recorded++
			}
			if recorded > 0 {
				break
			}
		}
	}

	if s.config.Fabric.commandEnabled("fabric_evpn_routes") {
		for _, command := range s.rpcClient.GetCommands("fabric_evpn_routes") {
			output, err := s.executeOptionalCommand(ctx, "fabric_evpn_routes", command)
			if err != nil {
				s.logOptionalCommandFailure(command, err)
				if ctx.Err() != nil {
					return
				}
				continue
			}
			routes := parseEVPNRoutes(output)
			for _, route := range routes {
				s.mb.RecordCiscoEvpnRoutesDataPoint(ts, route.Value, route.VRF, route.RouteType)
			}
			if len(routes) > 0 {
				break
			}
		}
	}
}

func (s *systemScraper) routingVRFs() []string {
	vrfs := s.config.RoutingForwarding.VRFs
	if len(vrfs) == 0 {
		vrfs = []string{"default"}
	}

	seen := map[string]struct{}{}
	limited := make([]string, 0, len(vrfs))
	for _, vrf := range vrfs {
		vrf = strings.TrimSpace(vrf)
		if vrf == "" {
			continue
		}
		if _, ok := seen[vrf]; ok {
			continue
		}
		seen[vrf] = struct{}{}
		limited = append(limited, vrf)
		if len(limited) >= s.routingForwardingMaxVRFs() {
			break
		}
	}
	if len(limited) == 0 {
		return []string{"default"}
	}
	return limited
}

func (s *systemScraper) commandsForVRF(feature, vrf string) []string {
	commands := make([]string, 0)
	for _, command := range s.rpcClient.GetCommands(feature) {
		if strings.Contains(command, "%s") {
			commands = append(commands, fmt.Sprintf(command, vrf))
			continue
		}
		if isDefaultVRF(vrf) {
			commands = append(commands, command)
		}
	}
	return commands
}

func (s *systemScraper) commandsForRoutingNeighborVRF(feature, vrf string) []string {
	commands := make([]string, 0)
	for _, command := range s.rpcClient.GetCommands(feature) {
		if strings.Contains(command, "%s") {
			commands = append(commands, fmt.Sprintf(command, vrf))
			continue
		}
		if isDefaultVRF(vrf) {
			commands = append(commands, command)
		}
	}
	return commands
}

func isDefaultVRF(vrf string) bool {
	return vrf == "" || strings.EqualFold(vrf, "default")
}

func (s *systemScraper) controlPlaneProcessTopN() int {
	if s.config.ControlPlane.ProcessTopN > 0 {
		return s.config.ControlPlane.ProcessTopN
	}
	return defaultControlPlaneConfig().ProcessTopN
}

func (s *systemScraper) routingForwardingMaxVRFs() int {
	if s.config.RoutingForwarding.MaxVRFs > 0 {
		return s.config.RoutingForwarding.MaxVRFs
	}
	return defaultRoutingForwardingConfig().MaxVRFs
}

func (s *systemScraper) hardwareMaxComponents() int {
	if s.config.HardwareHealth.MaxComponents > 0 {
		return s.config.HardwareHealth.MaxComponents
	}
	return defaultHardwareHealthConfig().MaxComponents
}

func (s *systemScraper) routingNeighborVRFs() []string {
	vrfs := s.config.RoutingNeighbors.VRFs
	if len(vrfs) == 0 {
		vrfs = []string{"default"}
	}
	seen := map[string]struct{}{}
	limited := make([]string, 0, len(vrfs))
	for _, vrf := range vrfs {
		vrf = strings.TrimSpace(vrf)
		if vrf == "" {
			continue
		}
		if _, ok := seen[vrf]; ok {
			continue
		}
		seen[vrf] = struct{}{}
		limited = append(limited, vrf)
		if len(limited) >= s.routingNeighborMaxVRFs() {
			break
		}
	}
	if len(limited) == 0 {
		return []string{"default"}
	}
	return limited
}

func (s *systemScraper) routingNeighborMaxVRFs() int {
	if s.config.RoutingNeighbors.MaxVRFs > 0 {
		return s.config.RoutingNeighbors.MaxVRFs
	}
	return defaultRoutingNeighborsConfig().MaxVRFs
}

func (s *systemScraper) routingNeighborMaxNeighbors() int {
	if s.config.RoutingNeighbors.MaxNeighbors > 0 {
		return s.config.RoutingNeighbors.MaxNeighbors
	}
	return defaultRoutingNeighborsConfig().MaxNeighbors
}

func (s *systemScraper) fabricMaxPeers() int {
	if s.config.Fabric.MaxPeers > 0 {
		return s.config.Fabric.MaxPeers
	}
	return defaultFabricConfig().MaxPeers
}

func (s *systemScraper) fabricMaxVNIs() int {
	if s.config.Fabric.MaxVNIs > 0 {
		return s.config.Fabric.MaxVNIs
	}
	return defaultFabricConfig().MaxVNIs
}

func (s *systemScraper) logOptionalCommandFailure(command string, err error) {
	s.logger.Warn("Optional Cisco troubleshooting command failed",
		zap.String("command", command),
		zap.Error(err))
}

func (s *systemScraper) executeOptionalCommand(ctx context.Context, family, command string) (string, error) {
	return s.executeCommand(ctx, family, command)
}

func (s *systemScraper) executeCommand(ctx context.Context, family, command string) (string, error) {
	if err := ctx.Err(); err != nil {
		s.recordCommandResult(family, 0, err)
		return "", err
	}
	start := time.Now()
	var (
		output string
		err    error
	)
	if client, ok := s.rpcClient.(contextSystemCommandClient); ok {
		output, err = client.ExecuteCommandWithContext(ctx, command)
	} else {
		output, err = s.rpcClient.ExecuteCommand(command)
	}
	s.recordCommandResult(family, time.Since(start), err)
	return output, err
}

func (s *systemScraper) recordCommandResult(family string, duration time.Duration, err error) {
	outcome := "success"
	if err != nil {
		outcome = "error"
		s.partialSuccess = true
		errorType := commandErrorType(err)
		key := commandErrorKey{family: family, errorType: errorType}
		if s.commandErrors == nil {
			s.commandErrors = make(map[commandErrorKey]int64)
		}
		s.commandErrors[key]++
	}
	s.mb.RecordCiscoScrapeCommandDurationDataPoint(pcommon.NewTimestampFromTime(time.Now()), duration.Seconds(), family, outcome)
}

func (s *systemScraper) optionalCollectionBudget() time.Duration {
	if s.config.Timeout > 0 {
		return s.config.Timeout
	}
	return 30 * time.Second
}

func (s *systemScraper) newResourceBuilder() *metadata.ResourceBuilder {
	rb := s.mb.NewResourceBuilder()
	if hostIP, err := netip.ParseAddr(strings.TrimSpace(s.deviceTarget)); err == nil {
		rb.SetHostIP(hostIP.Unmap().String())
	}
	rb.SetHwType("network")

	configuredHostName := s.config.Device.Device.Host.Name
	hostName := configuredHostName
	hostID := s.deviceTarget
	hostType := ""
	osName := ""
	osVersion := ""
	if s.rpcClient != nil {
		osName = s.rpcClient.GetOSType()
	}
	if deviceMetadata, ok := s.lastVerifiedDeviceMetadata(); ok {
		hostName = firstNonEmptyString(deviceMetadata.HostName, configuredHostName, s.deviceTarget)
		hostID = firstNonEmptyString(deviceMetadata.HostID, deviceMetadata.Serial, s.deviceTarget, configuredHostName)
		hostType = firstNonEmptyString(deviceMetadata.HostType, deviceMetadata.Model)
		osName = firstNonEmptyString(deviceMetadata.OSType, osName)
		osVersion = deviceMetadata.OSVersion
	}
	hostName = firstNonEmptyString(hostName, s.deviceTarget)
	hostID = firstNonEmptyString(hostID, s.deviceTarget)
	rb.SetHostName(hostName)
	rb.SetHostID(hostID)
	if hostType != "" {
		rb.SetHostType(hostType)
	}
	if osName != "" {
		rb.SetOsName(osName)
	}
	if osVersion != "" {
		rb.SetOsVersion(osVersion)
	}
	return rb
}

func (s *systemScraper) emitMetricsWithResource(rb *metadata.ResourceBuilder) pmetric.Metrics {
	resource := rb.Emit()
	if deviceMetadata, ok := s.lastVerifiedDeviceMetadata(); ok {
		if serial := strings.TrimSpace(deviceMetadata.Serial); serial != "" {
			resource.Attributes().PutStr("cisco.switch.serial", serial)
		}
	}
	return s.mb.Emit(metadata.WithResource(resource))
}

func (s *systemScraper) lastVerifiedDeviceMetadata() (connection.DeviceMetadata, bool) {
	if client, ok := s.rpcClient.(metadataSystemCommandClient); ok {
		return client.GetDeviceMetadata(), true
	}
	return s.config.Device.MetadataStore.Load()
}

func (s *systemScraper) recordSystemUptime(ts pcommon.Timestamp) {
	if s.rpcClient == nil {
		return
	}
	client, ok := s.rpcClient.(metadataSystemCommandClient)
	if !ok {
		return
	}
	uptime := client.GetDeviceMetadata().UptimeSeconds(time.Now())
	if uptime > 0 {
		s.mb.RecordSystemUptimeDataPoint(ts, uptime)
	}
}

func (s *systemScraper) recordScrapeHealth(ts pcommon.Timestamp) {
	s.mb.RecordCiscoScrapePartialSuccessDataPoint(ts, boolToInt(s.partialSuccess))
	s.recordCommandErrors(ts)
	if s.rpcClient == nil {
		s.mb.RecordCiscoSSHReconnectsDataPoint(ts, s.totalReconnects)
		return
	}
	client, ok := s.rpcClient.(reconnectSystemCommandClient)
	if !ok {
		s.mb.RecordCiscoSSHReconnectsDataPoint(ts, s.totalReconnects)
		return
	}
	current := client.GetReconnectCount()
	if current < s.lastReconnectCount {
		s.lastReconnectCount = 0
	}
	s.totalReconnects += current - s.lastReconnectCount
	s.lastReconnectCount = current
	s.mb.RecordCiscoSSHReconnectsDataPoint(ts, s.totalReconnects)
}

func (s *systemScraper) recordCommandErrors(ts pcommon.Timestamp) {
	keys := make([]commandErrorKey, 0, len(s.commandErrors))
	for key := range s.commandErrors {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].family == keys[j].family {
			return keys[i].errorType < keys[j].errorType
		}
		return keys[i].family < keys[j].family
	})
	for _, key := range keys {
		s.mb.RecordCiscoScrapeCommandErrorsDataPoint(ts, s.commandErrors[key], key.family, key.errorType)
	}
}

func commandErrorType(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "timeout"
	default:
		return "execution"
	}
}

func boolToInt(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

// collectCPUUtilization collects CPU utilization metric from the device
func (s *systemScraper) collectCPUUtilization(ctx context.Context) (float64, error) {
	if s.rpcClient == nil {
		return 0, errors.New("RPC client not initialized")
	}

	osType := s.rpcClient.GetOSType()
	command := s.rpcClient.GetCommand("cpu")
	if command == "" {
		return 0, fmt.Errorf("no CPU command available for OS type: %s", osType)
	}

	output, err := s.executeCommand(ctx, "cpu", command)
	output, osType, err = s.retryCoreMetricCommandAfterOSTypeChange(ctx, "cpu", osType, output, err)
	if err != nil {
		return 0, fmt.Errorf("failed to execute CPU command: %w", err)
	}

	// Parse based on OS type
	var cpuUtil float64
	if osType == "NX-OS" {
		cpuUtil, err = parseCPUUtilizationNXOS(output)
	} else {
		// IOS or IOS XE
		cpuUtil, err = parseCPUUtilizationIOS(output)
	}

	if err != nil {
		return 0, fmt.Errorf("%w: failed to parse CPU utilization: %w", errCoreMetricOutputUnparseable, err)
	}

	return cpuUtil, nil
}

// collectMemoryUtilization collects memory utilization metric from the device
func (s *systemScraper) collectMemoryUtilization(ctx context.Context) (float64, error) {
	if s.rpcClient == nil {
		return 0, errors.New("RPC client not initialized")
	}

	osType := s.rpcClient.GetOSType()
	command := s.rpcClient.GetCommand("memory")
	if command == "" {
		return 0, fmt.Errorf("no memory command available for OS type: %s", osType)
	}

	output, err := s.executeCommand(ctx, "memory", command)
	output, osType, err = s.retryCoreMetricCommandAfterOSTypeChange(ctx, "memory", osType, output, err)
	if err != nil {
		return 0, fmt.Errorf("failed to execute memory command: %w", err)
	}

	// Parse memory utilization
	memUtil, err := parseMemoryUtilization(output, osType)
	if err != nil {
		return 0, fmt.Errorf("%w: failed to parse memory utilization: %w", errCoreMetricOutputUnparseable, err)
	}

	return memUtil, nil
}

// retryCoreMetricCommandAfterOSTypeChange prevents a transparent reconnect to
// a different Cisco OS family from pairing the first command's output with the
// parser selected for the old connection. The new command is attempted once;
// another identity change during that retry is treated as unstable rather than
// risking incorrectly parsed telemetry.
func (s *systemScraper) retryCoreMetricCommandAfterOSTypeChange(
	ctx context.Context,
	feature string,
	initialOSType string,
	output string,
	commandErr error,
) (string, string, error) {
	currentOSType := s.rpcClient.GetOSType()
	if currentOSType == initialOSType {
		return output, initialOSType, commandErr
	}

	command := s.rpcClient.GetCommand(feature)
	if command == "" {
		return "", currentOSType, fmt.Errorf(
			"no %s command available after OS type changed from %s to %s",
			feature,
			initialOSType,
			currentOSType,
		)
	}

	s.logger.Info("Cisco OS type changed during core metric command; retrying with current command",
		zap.String("feature", feature),
		zap.String("previous_os_type", initialOSType),
		zap.String("current_os_type", currentOSType))

	output, err := s.executeCommand(ctx, feature, command)
	if err != nil {
		return "", currentOSType, err
	}
	finalOSType := s.rpcClient.GetOSType()
	if finalOSType != currentOSType {
		return "", finalOSType, fmt.Errorf(
			"OS type changed again during %s command retry: %s to %s",
			feature,
			currentOSType,
			finalOSType,
		)
	}
	return output, currentOSType, nil
}

func (s *systemScraper) collectProtocolTraffic(ctx context.Context) (protocolTrafficStats, error) {
	if s.rpcClient == nil {
		return protocolTrafficStats{}, errors.New("RPC client not initialized")
	}

	command := s.rpcClient.GetCommand("ip_traffic")
	if command == "" {
		return protocolTrafficStats{}, fmt.Errorf("no protocol traffic command available for OS type: %s", s.rpcClient.GetOSType())
	}

	output, err := s.executeCommand(ctx, "ip_traffic", command)
	if err != nil {
		return protocolTrafficStats{}, fmt.Errorf("failed to execute protocol traffic command: %w", err)
	}

	return parseProtocolTraffic(output), nil
}

func (s *systemScraper) recordProtocolTraffic(ts pcommon.Timestamp, stats protocolTrafficStats) {
	for _, packet := range stats.Packets {
		direction, ok := protocolDirectionToAttribute(packet.Direction)
		if !ok {
			continue
		}
		s.mb.RecordCiscoProtocolPacketsDataPoint(ts, packet.Value, packet.MessageType, packet.Protocol, direction)
	}
	for _, protocolError := range stats.Errors {
		s.mb.RecordCiscoProtocolErrorsDataPoint(ts, protocolError.Value, protocolError.ErrorType, protocolError.Protocol)
	}
	for _, drop := range stats.Drops {
		s.mb.RecordCiscoProtocolDroppedDataPoint(ts, drop.Value, drop.Reason, drop.Protocol)
	}
}

func protocolDirectionToAttribute(direction string) (metadata.AttributeNetworkIoDirection, bool) {
	switch direction {
	case protocolDirectionReceive:
		return metadata.AttributeNetworkIoDirectionReceive, true
	case protocolDirectionTransmit:
		return metadata.AttributeNetworkIoDirectionTransmit, true
	default:
		return 0, false
	}
}
