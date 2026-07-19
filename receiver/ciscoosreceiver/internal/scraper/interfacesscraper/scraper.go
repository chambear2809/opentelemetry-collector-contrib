// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package interfacesscraper // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/interfacesscraper"

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"sort"
	"strings"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/scraper"
	"go.opentelemetry.io/collector/scraper/scrapererror"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/interfacesscraper/internal/metadata"
)

type interfacesCommandClient interface {
	GetOSType() string
	GetCommand(string) string
	GetCommands(string) []string
	ExecuteCommand(string) (string, error)
	Close() error
}

type contextInterfacesCommandClient interface {
	ExecuteCommandWithContext(context.Context, string) (string, error)
}

type metadataInterfacesCommandClient interface {
	GetDeviceMetadata() connection.DeviceMetadata
}

type reconnectInterfacesCommandClient interface {
	GetReconnectCount() int64
}

type commandErrorKey struct {
	family    string
	errorType string
}

// interfacesScraper collects interface metrics from Cisco devices
type interfacesScraper struct {
	logger             *zap.Logger
	config             *Config
	mb                 *metadata.MetricsBuilder
	deviceTarget       string
	rpcClient          interfacesCommandClient
	lastReconnectCount int64
	totalReconnects    int64
	partialSuccess     bool
	commandErrors      map[commandErrorKey]int64
}

func (s *interfacesScraper) Start(_ context.Context, _ component.Host) error {
	s.mb = metadata.NewMetricsBuilder(s.config.MetricsBuilderConfig, scraper.Settings{
		ID:                component.MustNewIDWithName(metadata.Type.String(), "interfaces"),
		TelemetrySettings: component.TelemetrySettings{Logger: s.logger},
	})
	s.commandErrors = make(map[commandErrorKey]int64)

	if s.config.Device.Device.Host.IP == "" {
		return errors.New("no device configured")
	}

	device := s.config.Device
	s.deviceTarget = device.Device.Host.IP

	s.logger.Info("Interfaces scraper initialized", zap.String("target", s.deviceTarget))

	return nil
}

func (s *interfacesScraper) ScrapeMetrics(ctx context.Context) (pmetric.Metrics, error) {
	s.partialSuccess = false
	interfaces, err := s.parseInterfaceData(ctx)
	if err != nil {
		s.logger.Error("Failed to parse interface data", zap.Error(err))
		s.partialSuccess = true
		timestamp := pcommon.NewTimestampFromTime(time.Now())
		s.recordScrapeHealth(timestamp)
		rb := s.newResourceBuilder()
		metrics := s.emitMetricsWithResource(rb)
		if s.rpcClient != nil {
			if closeErr := s.rpcClient.Close(); closeErr != nil {
				s.logger.Warn("Failed to close SSH connection after interface scrape error", zap.Error(closeErr))
			}
			s.rpcClient = nil
		}
		// One target's interface dataset failed, but the scrape-health metrics are
		// valid and must be forwarded by scraperhelper.
		return metrics, scrapererror.NewPartialScrapeError(err, 1)
	}

	timestamp := pcommon.NewTimestampFromTime(time.Now())

	for _, intf := range interfaces {
		macAddress := intf.MACAddress
		description := intf.Description
		speedString := intf.SpeedString
		if speedString == "" && intf.Speed > 0 {
			speedString = formatSpeed(intf.Speed)
		}

		if !intf.HasOperStatus {
			s.logger.Warn("Interface operational status was not present; omitting status metric", zap.String("interface", intf.Name))
		}

		if validCounter(intf.InputBytes) {
			s.mb.RecordSystemNetworkIoDataPoint(timestamp, intf.InputBytes, metadata.AttributeNetworkIoDirectionReceive, description, macAddress, intf.Name, speedString)
		}
		if validCounter(intf.OutputBytes) {
			s.mb.RecordSystemNetworkIoDataPoint(timestamp, intf.OutputBytes, metadata.AttributeNetworkIoDirectionTransmit, description, macAddress, intf.Name, speedString)
		}
		if validCounter(intf.InputErrors) {
			s.mb.RecordSystemNetworkErrorsDataPoint(timestamp, intf.InputErrors, metadata.AttributeNetworkIoDirectionReceive, description, macAddress, intf.Name, speedString)
		}
		if validCounter(intf.OutputErrors) {
			s.mb.RecordSystemNetworkErrorsDataPoint(timestamp, intf.OutputErrors, metadata.AttributeNetworkIoDirectionTransmit, description, macAddress, intf.Name, speedString)
		}
		if validCounter(intf.InputDrops) {
			s.mb.RecordSystemNetworkPacketDroppedDataPoint(timestamp, intf.InputDrops, metadata.AttributeNetworkIoDirectionReceive, description, macAddress, intf.Name, speedString)
		}
		if validCounter(intf.OutputDrops) {
			s.mb.RecordSystemNetworkPacketDroppedDataPoint(timestamp, intf.OutputDrops, metadata.AttributeNetworkIoDirectionTransmit, description, macAddress, intf.Name, speedString)
		}

		recordPacketCounts(s.mb, timestamp, intf, description, macAddress, speedString)

		if intf.Speed > 0 {
			s.mb.RecordCiscoInterfaceSpeedDataPoint(timestamp, intf.Speed, description, macAddress, intf.Name)
			if intf.HasInputRate {
				s.mb.RecordCiscoInterfaceUtilizationDataPoint(timestamp, interfaceUtilization(intf.InputRateBits, intf.Speed), metadata.AttributeNetworkIoDirectionReceive, description, macAddress, intf.Name)
			}
			if intf.HasOutputRate {
				s.mb.RecordCiscoInterfaceUtilizationDataPoint(timestamp, interfaceUtilization(intf.OutputRateBits, intf.Speed), metadata.AttributeNetworkIoDirectionTransmit, description, macAddress, intf.Name)
			}
		}

		if s.config.Rates.Enabled && intf.HasInputRate {
			s.mb.RecordCiscoInterfaceIoRateDataPoint(timestamp, float64(intf.InputRateBits), metadata.AttributeNetworkIoDirectionReceive, description, macAddress, intf.Name, speedString)
			s.mb.RecordCiscoInterfacePacketRateDataPoint(timestamp, float64(intf.InputRatePackets), metadata.AttributeNetworkIoDirectionReceive, description, macAddress, intf.Name, speedString)
		}
		if s.config.Rates.Enabled && intf.HasOutputRate {
			s.mb.RecordCiscoInterfaceIoRateDataPoint(timestamp, float64(intf.OutputRateBits), metadata.AttributeNetworkIoDirectionTransmit, description, macAddress, intf.Name, speedString)
			s.mb.RecordCiscoInterfacePacketRateDataPoint(timestamp, float64(intf.OutputRatePackets), metadata.AttributeNetworkIoDirectionTransmit, description, macAddress, intf.Name, speedString)
		}

		if intf.HasOperStatus {
			s.mb.RecordSystemNetworkInterfaceStatusDataPoint(timestamp, intf.GetOperStatusInt(), description, macAddress, intf.Name, speedString)
		}
		if intf.HasAdminStatus {
			s.mb.RecordCiscoInterfaceAdminStatusDataPoint(timestamp, intf.GetAdminStatusInt(), description, macAddress, intf.Name, speedString)
		}
	}

	optionalCtx, cancelOptional := context.WithTimeout(ctx, s.optionalCollectionBudget())
	defer cancelOptional()

	if s.config.Counters.emitsCounters() {
		interfaces = s.enrichInterfaceCounters(optionalCtx, interfaces)
		for _, intf := range interfaces {
			macAddress := intf.MACAddress
			description := intf.Description
			speedString := intf.SpeedString
			if speedString == "" && intf.Speed > 0 {
				speedString = formatSpeed(intf.Speed)
			}
			s.recordCiscoInterfaceCounters(timestamp, intf, description, macAddress, speedString)
			s.recordStructuredInterfaceCounters(timestamp, intf)
		}
	}

	s.collectL2Topology(optionalCtx, timestamp)
	s.collectTransceiver(optionalCtx, timestamp)
	s.recordScrapeHealth(timestamp)

	rb := s.newResourceBuilder()

	return s.emitMetricsWithResource(rb), nil
}

func recordPacketCounts(mb *metadata.MetricsBuilder, timestamp pcommon.Timestamp, intf *Interface, description, macAddress, speedString string) {
	if intf.HasInputPacketTypes {
		intf.InputUnicast = inferUnicastIfAbsent(intf.InputPackets, intf.InputUnicast, intf.InputMulticast, intf.InputBroadcast)
	}
	if intf.HasOutputPacketTypes {
		intf.OutputUnicast = inferUnicastIfAbsent(intf.OutputPackets, intf.OutputUnicast, intf.OutputMulticast, intf.OutputBroadcast)
	}

	if intf.HasInputPacketTypes {
		recordPacketCountIfValid(mb, timestamp, intf.InputUnicast, metadata.AttributeNetworkIoDirectionReceive, metadata.AttributeNetworkPacketTypeUnicast, description, macAddress, intf.Name, speedString)
		recordPacketCountIfValid(mb, timestamp, intf.InputMulticast, metadata.AttributeNetworkIoDirectionReceive, metadata.AttributeNetworkPacketTypeMulticast, description, macAddress, intf.Name, speedString)
		recordPacketCountIfValid(mb, timestamp, intf.InputBroadcast, metadata.AttributeNetworkIoDirectionReceive, metadata.AttributeNetworkPacketTypeBroadcast, description, macAddress, intf.Name, speedString)
	}
	if intf.HasOutputPacketTypes {
		recordPacketCountIfValid(mb, timestamp, intf.OutputUnicast, metadata.AttributeNetworkIoDirectionTransmit, metadata.AttributeNetworkPacketTypeUnicast, description, macAddress, intf.Name, speedString)
		recordPacketCountIfValid(mb, timestamp, intf.OutputMulticast, metadata.AttributeNetworkIoDirectionTransmit, metadata.AttributeNetworkPacketTypeMulticast, description, macAddress, intf.Name, speedString)
		recordPacketCountIfValid(mb, timestamp, intf.OutputBroadcast, metadata.AttributeNetworkIoDirectionTransmit, metadata.AttributeNetworkPacketTypeBroadcast, description, macAddress, intf.Name, speedString)
	}
}

func inferUnicastIfAbsent(total, unicast, multicast, broadcast int64) int64 {
	if validCounter(unicast) {
		return unicast
	}
	if !validCounter(total) || !validCounter(multicast) || !validCounter(broadcast) ||
		total < 0 || multicast < 0 || broadcast < 0 || multicast > total {
		return invalidCounterValue
	}
	remaining := total - multicast
	if broadcast > remaining {
		return invalidCounterValue
	}
	return remaining - broadcast
}

func recordPacketCountIfValid(mb *metadata.MetricsBuilder, timestamp pcommon.Timestamp, value int64, direction metadata.AttributeNetworkIoDirection, packetType metadata.AttributeNetworkPacketType, description, macAddress, name, speedString string) {
	if validCounter(value) {
		mb.RecordSystemNetworkPacketCountDataPoint(timestamp, value, direction, packetType, description, macAddress, name, speedString)
	}
}

func (s *interfacesScraper) Shutdown(_ context.Context) error {
	if s.rpcClient != nil {
		if err := s.rpcClient.Close(); err != nil {
			s.logger.Warn("Failed to close SSH connection", zap.Error(err))
		}
		s.rpcClient = nil
	}

	return nil
}

func (s *interfacesScraper) parseInterfaceData(ctx context.Context) ([]*Interface, error) {
	if s.rpcClient == nil {
		rpcClient, err := connection.EstablishDeviceConnection(
			ctx,
			s.config.Device,
			s.config.Timeout,
			s.logger,
		)
		if err != nil {
			s.logger.Error("Failed to establish SSH connection", zap.String("target", s.deviceTarget), zap.Error(err))
			return []*Interface{}, fmt.Errorf("failed to establish connection: %w", err)
		}
		s.rpcClient = rpcClient
	}

	command := s.rpcClient.GetCommand("interfaces")
	if command == "" {
		return nil, fmt.Errorf("interfaces command not supported on OS type: %s", s.rpcClient.GetOSType())
	}

	output, err := s.executeCommand(ctx, "interfaces", command)
	usedFallback := false
	if err != nil {
		fallbackCommand := "show interface brief"
		s.logger.Warn("Primary command failed, using fallback", zap.String("fallback", fallbackCommand))
		output, err = s.executeCommand(ctx, "interfaces_fallback", fallbackCommand)
		if err != nil {
			return nil, fmt.Errorf("failed to execute interface commands '%s' and '%s': %w", command, fallbackCommand, err)
		}
		usedFallback = true
	}

	interfaces := parseInterfaceCommandOutput(output, s.logger)
	if len(interfaces) == 0 && !usedFallback {
		fallbackCommand := "show interface brief"
		s.logger.Warn("Primary command returned no parseable interfaces, using fallback",
			zap.String("command", command),
			zap.String("fallback", fallbackCommand))
		output, err = s.executeCommand(ctx, "interfaces_fallback", fallbackCommand)
		if err != nil {
			return nil, fmt.Errorf("interface command '%s' returned no parseable interfaces and fallback command '%s' failed: %w", command, fallbackCommand, err)
		}
		interfaces = parseInterfaceCommandOutput(output, s.logger)
	}
	if len(interfaces) == 0 {
		return nil, errors.New("no interfaces parsed from command output")
	}

	return interfaces, nil
}

func parseInterfaceCommandOutput(output string, logger *zap.Logger) []*Interface {
	if interfaceCommandOutputHasCLIError(output) {
		logger.Warn("Interface command returned Cisco CLI error output")
		return nil
	}

	interfaces := parseInterfaces(output, logger)
	if len(interfaces) == 0 {
		logger.Warn("No interfaces found, trying simple parsing")
		interfaces = parseSimpleInterfaces(output, logger)
	}
	return interfaces
}

func interfaceCommandOutputHasCLIError(output string) bool {
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if !strings.HasPrefix(line, "%") {
			continue
		}
		if strings.Contains(line, "invalid input") ||
			strings.Contains(line, "incomplete command") ||
			strings.Contains(line, "ambiguous command") ||
			strings.Contains(line, "unknown command") ||
			strings.Contains(line, "unrecognized command") ||
			strings.Contains(line, "authorization failed") ||
			strings.Contains(line, "permission denied") {
			return true
		}
	}
	return false
}

func (s *interfacesScraper) collectL2Topology(ctx context.Context, timestamp pcommon.Timestamp) {
	if s.rpcClient == nil || !s.config.L2Topology.emitsMetrics() {
		return
	}

	if s.config.L2Topology.commandEnabled("l2_stp") {
		for _, command := range s.rpcClient.GetCommands("l2_stp") {
			output, err := s.executeOptionalCommand(ctx, "l2_stp", command)
			if err != nil {
				s.logOptionalCommandFailure(command, err)
				if ctx.Err() != nil {
					return
				}
				continue
			}
			s.recordSTPStats(timestamp, parseSTPStats(output))
		}
	}

	if s.config.L2Topology.commandEnabled("l2_port_channel") {
		for _, command := range s.rpcClient.GetCommands("l2_port_channel") {
			output, err := s.executeOptionalCommand(ctx, "l2_port_channel", command)
			if err != nil {
				s.logOptionalCommandFailure(command, err)
				if ctx.Err() != nil {
					return
				}
				continue
			}
			channels, members := parsePortChannelSummary(output)
			recordedChannels := map[string]struct{}{}
			for _, channel := range channels {
				if !s.interfaceAllowedForL2(channel.Name) {
					continue
				}
				if !s.recordInterfaceWithinLimit(recordedChannels, channel.Name, s.l2MaxInterfaces()) {
					continue
				}
				s.mb.RecordCiscoPortChannelStatusDataPoint(timestamp, boolToInt(channel.Up), channel.Name, channel.State)
			}
			recordedMembers := 0
			for _, member := range members {
				if !s.interfaceAllowedForL2(member.Interface) {
					continue
				}
				if recordedMembers >= s.l2MaxInterfaces() {
					break
				}
				s.mb.RecordCiscoPortChannelMemberStatusDataPoint(timestamp, boolToInt(member.Up), member.PortChannel, member.Interface, member.State)
				recordedMembers++
			}
			if len(channels) > 0 || len(members) > 0 {
				break
			}
		}
	}

	if s.config.L2Topology.commandEnabled("l2_lacp") {
		for _, command := range s.rpcClient.GetCommands("l2_lacp") {
			output, err := s.executeOptionalCommand(ctx, "l2_lacp", command)
			if err != nil {
				s.logOptionalCommandFailure(command, err)
				if ctx.Err() != nil {
					return
				}
				continue
			}
			packets, errors := parseLACPCounters(output)
			recordedInterfaces := map[string]struct{}{}
			for _, packet := range packets {
				if !s.interfaceAllowedForL2(packet.Interface) || !s.recordInterfaceWithinLimit(recordedInterfaces, packet.Interface, s.l2MaxInterfaces()) {
					continue
				}
				direction := metadata.AttributeNetworkIoDirectionReceive
				if packet.Direction == "transmit" {
					direction = metadata.AttributeNetworkIoDirectionTransmit
				}
				s.mb.RecordCiscoLacpPacketsDataPoint(timestamp, packet.Value, packet.Interface, packet.Type, direction)
			}
			for _, lacpError := range errors {
				if !s.interfaceAllowedForL2(lacpError.Interface) || !s.recordInterfaceWithinLimit(recordedInterfaces, lacpError.Interface, s.l2MaxInterfaces()) {
					continue
				}
				s.mb.RecordCiscoLacpErrorsDataPoint(timestamp, lacpError.Value, lacpError.Interface, lacpError.Type)
			}
			if len(packets) > 0 || len(errors) > 0 {
				break
			}
		}
	}

	if s.config.L2Topology.commandEnabled("l2_err_disabled") {
		for _, command := range s.rpcClient.GetCommands("l2_err_disabled") {
			output, err := s.executeOptionalCommand(ctx, "l2_err_disabled", command)
			if err != nil {
				s.logOptionalCommandFailure(command, err)
				if ctx.Err() != nil {
					return
				}
				continue
			}
			recorded := 0
			for _, intf := range parseErrDisabledInterfaces(output) {
				if !s.interfaceAllowedForL2(intf.Interface) {
					continue
				}
				if recorded >= s.l2MaxInterfaces() {
					break
				}
				s.mb.RecordCiscoInterfaceErrdisabledDataPoint(timestamp, 1, intf.Interface, intf.Reason)
				recorded++
			}
			if recorded > 0 {
				break
			}
		}
	}

	if s.config.L2Topology.commandEnabled("l2_vpc") {
		for _, command := range s.rpcClient.GetCommands("l2_vpc") {
			output, err := s.executeOptionalCommand(ctx, "l2_vpc", command)
			if err != nil {
				s.logOptionalCommandFailure(command, err)
				if ctx.Err() != nil {
					return
				}
				continue
			}
			statuses, failures := parseVPC(output)
			for _, status := range statuses {
				s.mb.RecordCiscoVpcStatusDataPoint(timestamp, boolToInt(status.Up), status.Domain, status.Peer, status.State)
			}
			for _, failure := range failures {
				s.mb.RecordCiscoVpcConsistencyFailuresDataPoint(timestamp, failure.Value, failure.Check)
			}
		}
	}

	s.collectTopologyNeighbors(ctx, timestamp, "l2_lldp", "lldp")
	s.collectTopologyNeighbors(ctx, timestamp, "l2_cdp", "cdp")
}

func (s *interfacesScraper) collectTopologyNeighbors(ctx context.Context, timestamp pcommon.Timestamp, feature, protocol string) {
	if !s.config.L2Topology.commandEnabled(feature) {
		return
	}
	recorded := 0
	for _, command := range s.rpcClient.GetCommands(feature) {
		output, err := s.executeOptionalCommand(ctx, feature, command)
		if err != nil {
			s.logOptionalCommandFailure(command, err)
			if ctx.Err() != nil {
				return
			}
			continue
		}
		for _, neighbor := range parseTopologyNeighbors(output, protocol) {
			if !s.interfaceAllowedForL2(neighbor.LocalInterface) {
				continue
			}
			if recorded >= s.l2MaxInterfaces() {
				break
			}
			s.mb.RecordCiscoTopologyNeighborInfoDataPoint(
				timestamp,
				1,
				neighbor.Protocol,
				neighbor.LocalInterface,
				neighbor.NeighborName,
				neighbor.NeighborInterface,
				neighbor.NeighborPlatform,
				neighbor.NeighborAddress,
				neighbor.NeighborName,
				neighbor.NeighborAddress,
				neighbor.Protocol,
			)
			recorded++
		}
		if recorded > 0 {
			break
		}
	}
}

func (s *interfacesScraper) recordSTPStats(timestamp pcommon.Timestamp, stats stpStats) {
	for _, instance := range stats.Instances {
		s.mb.RecordCiscoL2StpInstancesDataPoint(timestamp, instance.Value, instance.State)
	}

	seenVLANs := map[string]struct{}{}
	for _, change := range stats.TopologyChanges {
		if !s.vlanWithinLimit(seenVLANs, change.VLAN) || !s.interfaceAllowedForL2(change.Interface) {
			continue
		}
		s.mb.RecordCiscoL2StpTopologyChangesDataPoint(timestamp, change.Value, change.VLAN, change.Interface)
	}

	seenVLANs = map[string]struct{}{}
	recordedInterfaces := map[string]struct{}{}
	for _, blocked := range stats.BlockedPorts {
		if !s.vlanWithinLimit(seenVLANs, blocked.VLAN) || !s.interfaceAllowedForL2(blocked.Interface) {
			continue
		}
		if !s.recordInterfaceWithinLimit(recordedInterfaces, blocked.Interface, s.l2MaxInterfaces()) {
			continue
		}
		s.mb.RecordCiscoL2StpBlockedPortsDataPoint(timestamp, blocked.Value, blocked.VLAN, blocked.Interface)
	}
}

func (s *interfacesScraper) collectTransceiver(ctx context.Context, timestamp pcommon.Timestamp) {
	if s.rpcClient == nil || !s.config.Transceiver.Enabled {
		return
	}

	for _, command := range s.rpcClient.GetCommands("transceiver") {
		output, err := s.executeOptionalCommand(ctx, "transceiver", command)
		if err != nil {
			s.logOptionalCommandFailure(command, err)
			if ctx.Err() != nil {
				return
			}
			continue
		}
		recordedInterfaces := map[string]struct{}{}
		recorded := 0
		for _, sensor := range parseTransceiverSensors(output) {
			if !s.interfaceAllowedForTransceiver(sensor.Interface) {
				continue
			}
			if !s.recordInterfaceWithinLimit(recordedInterfaces, sensor.Interface, s.transceiverMaxInterfaces()) {
				continue
			}
			s.mb.RecordCiscoTransceiverSensorDataPoint(timestamp, sensor.Value, sensor.Interface, sensor.Sensor, sensor.Lane, sensor.Unit)
			recorded++
		}
		if recorded > 0 {
			break
		}
	}
}

func (s *interfacesScraper) enrichInterfaceCounters(ctx context.Context, interfaces []*Interface) []*Interface {
	counterCommands := []struct {
		feature string
		parse   func(string, *zap.Logger) map[string]map[string]int64
	}{
		{feature: "interface_counters", parse: parseInterfaceCounterTables},
		{feature: "interface_error_counters", parse: parseInterfaceCounterTables},
		{feature: "interface_flowcontrol", parse: parseFlowControlCounters},
		{feature: "interface_priority_flow_control", parse: parsePriorityFlowControlCounters},
		{feature: "interface_queueing", parse: parseQueueingCounters},
		{feature: "interface_pfc_watchdog", parse: parsePFCWatchdogCounters},
		{feature: "interface_qos_policy", parse: parsePolicyMapInterfaceCounters},
	}

	for _, command := range counterCommands {
		if !s.config.Counters.commandEnabled(command.feature) {
			continue
		}
		interfaces = s.enrichOptionalInterfaceCounters(ctx, interfaces, command.feature, command.parse)
		if ctx.Err() != nil {
			return interfaces
		}
	}

	if s.config.Counters.commandEnabled("interface_platform_queue_stats") {
		interfaces = s.enrichPlatformQueueStats(ctx, interfaces)
	}

	return interfaces
}

func (s *interfacesScraper) recordCiscoInterfaceCounters(timestamp pcommon.Timestamp, intf *Interface, description, macAddress, speedString string) {
	if !s.config.Counters.emitsCounters() || len(intf.Counters) == 0 {
		return
	}

	counterNames := make([]string, 0, len(intf.Counters))
	for counterName := range intf.Counters {
		if counterNameAllowed(counterName, s.config.Counters.Include, s.config.Counters.Exclude) {
			counterNames = append(counterNames, counterName)
		}
	}
	sort.Strings(counterNames)

	limit := s.config.Counters.MaxPerInterface
	if limit > 0 && len(counterNames) > limit {
		s.logger.Debug("Limiting Cisco interface counters",
			zap.String("interface", intf.Name),
			zap.Int("allowed", len(counterNames)),
			zap.Int("limit", limit))
		counterNames = counterNames[:limit]
	}

	for _, counterName := range counterNames {
		s.mb.RecordCiscoInterfaceCounterDataPoint(timestamp, intf.Counters[counterName], counterName, description, macAddress, intf.Name, speedString)
	}
}

func counterNameAllowed(counterName string, include, exclude []string) bool {
	if len(include) > 0 && !counterNameMatchesAnyPattern(counterName, include) {
		return false
	}
	return !counterNameMatchesAnyPattern(counterName, exclude)
}

func counterNameMatchesAnyPattern(counterName string, patterns []string) bool {
	counterName = strings.ToLower(counterName)
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if matched, err := path.Match(normalizeGlobSlashes(pattern), normalizeGlobSlashes(counterName)); err == nil && matched {
			return true
		}
		if pattern == counterName {
			return true
		}
	}
	return false
}

func normalizeGlobSlashes(value string) string {
	return strings.ReplaceAll(value, "/", "\x00")
}

func (s *interfacesScraper) interfaceAllowedForL2(name string) bool {
	if name == "" {
		return true
	}
	return counterNameAllowed(name, s.config.L2Topology.Include, s.config.L2Topology.Exclude)
}

func (s *interfacesScraper) interfaceAllowedForTransceiver(name string) bool {
	return counterNameAllowed(name, s.config.Transceiver.Include, s.config.Transceiver.Exclude)
}

func (s *interfacesScraper) vlanWithinLimit(seen map[string]struct{}, vlan string) bool {
	if vlan == "" {
		return true
	}
	if _, ok := seen[vlan]; ok {
		return true
	}
	if len(seen) >= s.l2MaxVLANs() {
		return false
	}
	seen[vlan] = struct{}{}
	return true
}

func (*interfacesScraper) recordInterfaceWithinLimit(seen map[string]struct{}, name string, limit int) bool {
	if name == "" || limit <= 0 {
		return true
	}
	if _, ok := seen[name]; ok {
		return true
	}
	if len(seen) >= limit {
		return false
	}
	seen[name] = struct{}{}
	return true
}

func (s *interfacesScraper) l2MaxInterfaces() int {
	if s.config.L2Topology.MaxInterfaces > 0 {
		return s.config.L2Topology.MaxInterfaces
	}
	return defaultL2TopologyConfig().MaxInterfaces
}

func (s *interfacesScraper) l2MaxVLANs() int {
	if s.config.L2Topology.MaxVLANs > 0 {
		return s.config.L2Topology.MaxVLANs
	}
	return defaultL2TopologyConfig().MaxVLANs
}

func (s *interfacesScraper) transceiverMaxInterfaces() int {
	if s.config.Transceiver.MaxInterfaces > 0 {
		return s.config.Transceiver.MaxInterfaces
	}
	return defaultTransceiverConfig().MaxInterfaces
}

func (s *interfacesScraper) counterMaxInterfaces() int {
	if s.config.Counters.MaxInterfaces > 0 {
		return s.config.Counters.MaxInterfaces
	}
	return defaultCounterCollectionConfig().MaxInterfaces
}

func (s *interfacesScraper) logOptionalCommandFailure(command string, err error) {
	s.logger.Warn("Optional Cisco troubleshooting command failed",
		zap.String("command", command),
		zap.Error(err))
}

func boolToInt(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func (s *interfacesScraper) enrichOptionalInterfaceCounters(
	ctx context.Context,
	interfaces []*Interface,
	feature string,
	parse func(string, *zap.Logger) map[string]map[string]int64,
) []*Interface {
	for _, command := range s.rpcClient.GetCommands(feature) {
		output, err := s.executeOptionalCommand(ctx, feature, command)
		if err != nil {
			s.logger.Warn("Optional interface counter command failed",
				zap.String("command", command),
				zap.Error(err))
			if ctx.Err() != nil {
				return interfaces
			}
			continue
		}

		counters := parse(output, s.logger)
		if len(counters) == 0 {
			s.logger.Debug("Optional interface counter command returned no parseable counters",
				zap.String("command", command))
			continue
		}

		return mergeInterfaceCounterTables(interfaces, counters)
	}

	return interfaces
}

func (s *interfacesScraper) enrichPlatformQueueStats(ctx context.Context, interfaces []*Interface) []*Interface {
	commands := s.rpcClient.GetCommands("interface_platform_queue_stats")
	if len(commands) == 0 {
		return interfaces
	}

	maxInterfaces := s.counterMaxInterfaces()
	queried := 0

	for _, intf := range interfaces {
		if queried >= maxInterfaces {
			break
		}
		if !supportsPlatformQueueStats(intf.Name) {
			continue
		}

		queried++
		for _, commandPrefix := range commands {
			output, err := s.executeOptionalCommand(ctx, "interface_platform_queue_stats", commandPrefix+" "+intf.Name)
			if err != nil {
				s.logger.Warn("Optional interface platform queue stats command failed",
					zap.String("command", commandPrefix),
					zap.String("interface", intf.Name),
					zap.Error(err))
				if ctx.Err() != nil {
					return interfaces
				}
				continue
			}

			counters := parsePlatformQueueStatsCounters(output, s.logger)
			if len(counters) == 0 {
				s.logger.Debug("Optional interface platform queue stats command returned no parseable counters",
					zap.String("command", commandPrefix),
					zap.String("interface", intf.Name))
				continue
			}
			interfaces = mergeInterfaceCounterTables(interfaces, map[string]map[string]int64{
				intf.Name: counters,
			})
			break
		}
	}

	return interfaces
}

func (s *interfacesScraper) executeOptionalCommand(ctx context.Context, family, command string) (string, error) {
	return s.executeCommand(ctx, family, command)
}

func (s *interfacesScraper) executeCommand(ctx context.Context, family, command string) (string, error) {
	if err := ctx.Err(); err != nil {
		s.recordCommandResult(family, 0, err)
		return "", err
	}
	start := time.Now()
	var (
		output string
		err    error
	)
	if client, ok := s.rpcClient.(contextInterfacesCommandClient); ok {
		output, err = client.ExecuteCommandWithContext(ctx, command)
	} else {
		output, err = s.rpcClient.ExecuteCommand(command)
	}
	s.recordCommandResult(family, time.Since(start), err)
	return output, err
}

func (s *interfacesScraper) recordCommandResult(family string, duration time.Duration, err error) {
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

func (s *interfacesScraper) optionalCollectionBudget() time.Duration {
	if s.config.Timeout > 0 {
		return s.config.Timeout
	}
	return 30 * time.Second
}

func interfaceUtilization(rateBits, speedBits int64) float64 {
	if rateBits <= 0 || speedBits <= 0 {
		return 0
	}
	return float64(rateBits) / float64(speedBits)
}

func (s *interfacesScraper) newResourceBuilder() *metadata.ResourceBuilder {
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

func (s *interfacesScraper) emitMetricsWithResource(rb *metadata.ResourceBuilder) pmetric.Metrics {
	resource := rb.Emit()
	if deviceMetadata, ok := s.lastVerifiedDeviceMetadata(); ok {
		if serial := strings.TrimSpace(deviceMetadata.Serial); serial != "" {
			resource.Attributes().PutStr("cisco.switch.serial", serial)
		}
	}
	return s.mb.Emit(metadata.WithResource(resource))
}

func (s *interfacesScraper) lastVerifiedDeviceMetadata() (connection.DeviceMetadata, bool) {
	if client, ok := s.rpcClient.(metadataInterfacesCommandClient); ok {
		return client.GetDeviceMetadata(), true
	}
	return s.config.Device.MetadataStore.Load()
}

func (s *interfacesScraper) recordScrapeHealth(ts pcommon.Timestamp) {
	s.mb.RecordCiscoScrapePartialSuccessDataPoint(ts, boolToInt(s.partialSuccess))
	s.recordCommandErrors(ts)
	if s.rpcClient == nil {
		s.mb.RecordCiscoSSHReconnectsDataPoint(ts, s.totalReconnects)
		return
	}
	client, ok := s.rpcClient.(reconnectInterfacesCommandClient)
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

func (s *interfacesScraper) recordCommandErrors(ts pcommon.Timestamp) {
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

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
