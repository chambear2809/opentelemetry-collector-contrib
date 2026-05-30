// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/meraki"
)

const merakiScopeName = "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/meraki"

type merakiMetricsReceiver struct {
	settings receiver.Settings
	config   *Config
	consumer consumer.Metrics
	client   *meraki.Client
	targets  []merakiTarget
	counters *counterStore
	obs      *receiverhelper.ObsReport

	startMu sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}

	statsMu sync.Mutex
	stats   []meraki.RequestStat
}

type merakiTarget struct {
	OrganizationID string
	NetworkIDs     []string
	Serials        []string
	ProductTypes   []string
	Tags           []string
	TagsFilterType string
}

func newMerakiMetricsReceiver(set receiver.Settings, conf *Config, consumer consumer.Metrics) (*merakiMetricsReceiver, error) {
	client, err := meraki.NewClient(meraki.Config{
		APIKey:    string(conf.Meraki.Auth.APIKey),
		BaseURL:   conf.Meraki.BaseURL,
		UserAgent: conf.Meraki.UserAgent,
		Timeout:   conf.Timeout,
	})
	if err != nil {
		return nil, err
	}
	r := &merakiMetricsReceiver{
		settings: set,
		config:   conf,
		consumer: consumer,
		client:   client,
		targets:  normalizeMerakiTargets(conf.Meraki),
		counters: newCounterStore(),
		obs:      newPlatformObsReport(set, "http"),
		done:     make(chan struct{}),
	}
	client.OnRequest = r.recordRequest
	return r, nil
}

func normalizeMerakiTargets(cfg MerakiConfig) []merakiTarget {
	targets := make([]merakiTarget, 0, len(cfg.Organizations)+1)
	for _, org := range cfg.Organizations {
		targets = append(targets, merakiTarget{
			OrganizationID: org.OrganizationID,
			NetworkIDs:     uniqueStrings(org.NetworkIDs),
			Serials:        uniqueStrings(org.Serials),
			ProductTypes:   uniqueStrings(org.ProductTypes),
			Tags:           uniqueStrings(org.Tags),
			TagsFilterType: org.TagsFilterType,
		})
	}

	serialsByOrg := map[string][]string{}
	for _, device := range cfg.Devices {
		serialsByOrg[device.OrganizationID] = append(serialsByOrg[device.OrganizationID], device.Serial)
	}
	orgs := make([]string, 0, len(serialsByOrg))
	for orgID := range serialsByOrg {
		orgs = append(orgs, orgID)
	}
	sort.Strings(orgs)
	for _, orgID := range orgs {
		targets = append(targets, merakiTarget{
			OrganizationID: orgID,
			Serials:        uniqueStrings(serialsByOrg[orgID]),
		})
	}
	return targets
}

func (r *merakiMetricsReceiver) Start(_ context.Context, _ component.Host) error {
	r.startMu.Lock()
	defer r.startMu.Unlock()
	if r.cancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go r.run(ctx)
	return nil
}

func (r *merakiMetricsReceiver) Shutdown(ctx context.Context) error {
	r.startMu.Lock()
	cancel := r.cancel
	r.startMu.Unlock()
	if cancel == nil {
		r.client.CloseIdleConnections()
		return nil
	}
	cancel()
	defer r.client.CloseIdleConnections()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *merakiMetricsReceiver) run(ctx context.Context) {
	defer close(r.done)
	r.collect(ctx)
	ticker := time.NewTicker(r.config.CollectionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.collect(ctx)
		}
	}
}

func (r *merakiMetricsReceiver) collect(ctx context.Context) {
	scrapeCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()

	obsCtx := startMetricsOp(r.obs, ctx)
	md, err := r.scrape(scrapeCtx)
	if err != nil {
		r.settings.Logger.Error("Meraki scrape failed", zap.Error(err))
		endMetricsOp(r.obs, obsCtx, md, err)
		return
	}
	if md.MetricCount() == 0 {
		endMetricsOp(r.obs, obsCtx, md, nil)
		return
	}
	consumeErr := r.consumer.ConsumeMetrics(ctx, md)
	endMetricsOp(r.obs, obsCtx, md, consumeErr)
	if consumeErr != nil {
		r.settings.Logger.Error("Meraki metrics consumer failed", zap.Error(consumeErr))
	}
}

func (r *merakiMetricsReceiver) scrape(ctx context.Context) (pmetric.Metrics, error) {
	r.resetRequestStats()
	builder := newMerakiMetricsBuilder(time.Now(), r.counters)
	partial := false

	for _, target := range r.targets {
		targetPartial, err := r.scrapeTarget(ctx, builder, target)
		if err != nil {
			return builder.emit(), err
		}
		partial = partial || targetPartial
	}
	r.recordAPIRequestMetrics(builder)
	for _, target := range r.targets {
		builder.orgResource(target.OrganizationID).recordInt("cisco.scrape.partial_success", "Whether one or more Meraki endpoint families failed during the scrape.", "1", boolToInt(partial), nil)
	}
	return builder.emit(), nil
}

func (r *merakiMetricsReceiver) scrapeTarget(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget) (bool, error) {
	partial := false
	selector := newDeviceSelectionMatcher(r.config.DeviceSelection)
	allowedSerials := target.serialSet()
	devices, err := meraki.GetPaginatedJSON[meraki.Device](ctx, r.client, target.OrganizationID, "devices", meraki.OrganizationPath(target.OrganizationID, "/devices"), target.inventoryQuery())
	if err != nil {
		if ctx.Err() != nil {
			return partial, ctx.Err()
		}
		partial = true
		if target.hasInventoryScopedFilters() && allowedSerials == nil {
			allowedSerials = map[string]struct{}{}
		}
		r.settings.Logger.Warn("Meraki device inventory endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
	} else {
		inventorySerials := make(map[string]struct{}, len(devices))
		for _, device := range devices {
			if device.Serial == "" {
				continue
			}
			resource := deviceResourceFromInventory(device)
			if !selector.allows(merakiDeviceIdentity(resource)) {
				continue
			}
			inventorySerials[device.Serial] = struct{}{}
			builder.deviceResource(resource)
		}
		if len(inventorySerials) > 0 {
			allowedSerials = inventorySerials
		} else if len(target.Serials) == 0 {
			allowedSerials = map[string]struct{}{}
		}
	}

	if r.scrapeDeviceStatuses(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}
	if r.scrapeMemoryUsage(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}
	if r.scrapeSwitchPorts(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}
	if r.scrapeUplinks(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}
	if r.scrapeWireless(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}
	if r.scrapeVPN(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}
	if r.scrapePowerModules(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}
	if r.scrapeTopology(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}
	if r.scrapeTransceivers(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}
	if r.scrapeAppliancePerformance(ctx, builder, target, allowedSerials, selector) {
		partial = true
	}

	return partial, nil
}

func (r *merakiMetricsReceiver) scrapeDeviceStatuses(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	statuses, err := meraki.GetPaginatedJSON[meraki.DeviceStatus](ctx, r.client, target.OrganizationID, "device_statuses", meraki.OrganizationPath(target.OrganizationID, "/devices/statuses"), target.deviceQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki device status endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		return true
	}
	for _, status := range statuses {
		if !allowsSerial(allowedSerials, status.Serial) {
			continue
		}
		resource := deviceResourceFromStatus(status)
		if !selector.allows(merakiDeviceIdentity(resource)) {
			continue
		}
		rb := builder.deviceResource(resource)
		rb.recordInt("cisco.device.up", "Device availability (1 = up, 0 = down).", "1", merakiDeviceUp(status.Status), nil)
		rb.recordInt("meraki.device.status", "Meraki Dashboard device status.", "1", merakiStatusCode(status.Status), map[string]string{
			"meraki.device.status":       status.Status,
			"meraki.device.product_type": status.ProductType,
		})
	}
	return false
}

func (r *merakiMetricsReceiver) scrapeMemoryUsage(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	usages, err := meraki.GetPaginatedItemsJSON[meraki.DeviceMemoryUsage](ctx, r.client, target.OrganizationID, "device_memory", meraki.OrganizationPath(target.OrganizationID, "/devices/system/memory/usage/history/byInterval"), target.deviceQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki memory usage endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		return true
	}
	for _, usage := range usages {
		if !allowsSerial(allowedSerials, usage.Serial) {
			continue
		}
		resource := deviceResourceFromMemory(usage)
		if !selector.allows(merakiDeviceIdentity(resource)) {
			continue
		}
		rb := builder.deviceResource(resource)
		if value, ok := memoryUtilization(usage); ok {
			rb.recordDouble("system.memory.utilization", "Memory utilization as a ratio from 0 to 1.", "1", value, nil)
		}
	}
	return false
}

func (r *merakiMetricsReceiver) scrapeSwitchPorts(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	partial := false
	statuses, err := meraki.GetPaginatedItemsJSON[meraki.SwitchPortsStatus](ctx, r.client, target.OrganizationID, "switch_ports_status", meraki.OrganizationPath(target.OrganizationID, "/switch/ports/statuses/bySwitch"), target.networkSerialQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki switch port status endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		partial = true
	} else {
		for _, sw := range statuses {
			if !allowsSerial(allowedSerials, sw.Serial) {
				continue
			}
			resource := deviceResourceFromSwitch(sw)
			if !selector.allows(merakiDeviceIdentity(resource)) {
				continue
			}
			rb := builder.deviceResource(resource)
			for _, port := range sw.Ports {
				speedBits, speedString := parseMerakiSpeed(port.Speed)
				if speedBits > 0 {
					builder.setPortSpeed(sw.Serial, port.PortID, speedBits)
					rb.recordInt("cisco.interface.speed", "Interface line speed.", "bit/s", speedBits, interfaceAttrs(port.PortID, sw.MAC, "", speedString))
				}
				rb.recordInt("system.network.interface.status", "Interface operational status (1 = up, 0 = down).", "1", connectedStatus(port.Status), interfaceAttrs(port.PortID, sw.MAC, "", speedString))
				rb.recordInt("cisco.interface.admin.status", "Interface administrative status (1 = enabled, 0 = disabled).", "1", boolToInt(port.Enabled), interfaceAttrs(port.PortID, sw.MAC, "", speedString))
				rb.recordInt("meraki.switch.port.poe.allocated", "Whether Meraki reports PoE as allocated on the switch port.", "1", boolToInt(port.PoE.IsAllocated), interfaceAttrs(port.PortID, sw.MAC, "", speedString))
				for _, reason := range port.Errors {
					attrs := interfaceAttrs(port.PortID, sw.MAC, "", speedString)
					attrs["meraki.switch.port.alert.severity"] = "error"
					attrs["meraki.switch.port.alert.reason"] = reason
					rb.recordSum("meraki.switch.port.alert", "Meraki switch port error or warning.", "1", 1, attrs)
				}
				for _, reason := range port.Warnings {
					attrs := interfaceAttrs(port.PortID, sw.MAC, "", speedString)
					attrs["meraki.switch.port.alert.severity"] = "warning"
					attrs["meraki.switch.port.alert.reason"] = reason
					rb.recordSum("meraki.switch.port.alert", "Meraki switch port error or warning.", "1", 1, attrs)
				}
			}
		}
	}

	usages, err := meraki.GetPaginatedItemsJSON[meraki.SwitchPortsUsage](ctx, r.client, target.OrganizationID, "switch_ports_usage", meraki.OrganizationPath(target.OrganizationID, "/switch/ports/usage/history/byDevice/byInterval"), target.windowedSwitchQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki switch port usage endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		partial = true
	} else {
		for _, sw := range usages {
			if !allowsSerial(allowedSerials, sw.Serial) {
				continue
			}
			resource := deviceResourceFromSwitchUsage(sw)
			if !selector.allows(merakiDeviceIdentity(resource)) {
				continue
			}
			rb := builder.deviceResource(resource)
			for _, port := range sw.Ports {
				if len(port.Intervals) == 0 {
					continue
				}
				interval := port.Intervals[len(port.Intervals)-1]
				speedBits := builder.portSpeed(sw.Serial, port.PortID)
				speedString := ""
				if speedBits > 0 {
					speedString = strconv.FormatInt(speedBits, 10)
				}
				attrsRx := interfaceAttrs(port.PortID, sw.MAC, "", speedString)
				attrsRx["network.io.direction"] = "receive"
				attrsTx := interfaceAttrs(port.PortID, sw.MAC, "", speedString)
				attrsTx["network.io.direction"] = "transmit"
				rxBits := int64(interval.Bandwidth.Usage.Downstream * 1000)
				txBits := int64(interval.Bandwidth.Usage.Upstream * 1000)
				rb.recordInt("cisco.interface.io.rate", "Interface traffic rate.", "bit/s", rxBits, attrsRx)
				rb.recordInt("cisco.interface.io.rate", "Interface traffic rate.", "bit/s", txBits, attrsTx)
				rb.recordDouble("meraki.switch.port.usage", "Windowed switch port usage reported by Meraki.", "KBy", interval.Data.Usage.Downstream, attrsRx)
				rb.recordDouble("meraki.switch.port.usage", "Windowed switch port usage reported by Meraki.", "KBy", interval.Data.Usage.Upstream, attrsTx)
				if speedBits > 0 {
					rb.recordDouble("cisco.interface.utilization", "Interface traffic utilization as a ratio from 0 to 1.", "1", float64(rxBits)/float64(speedBits), attrsRx)
					rb.recordDouble("cisco.interface.utilization", "Interface traffic utilization as a ratio from 0 to 1.", "1", float64(txBits)/float64(speedBits), attrsTx)
				}
			}
		}
	}

	return partial
}

func (r *merakiMetricsReceiver) scrapeUplinks(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	partial := false
	statuses, err := meraki.GetPaginatedJSON[meraki.UplinkStatus](ctx, r.client, target.OrganizationID, "uplink_statuses", meraki.OrganizationPath(target.OrganizationID, "/uplinks/statuses"), target.networkSerialQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki uplink status endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		partial = true
	} else {
		for _, device := range statuses {
			if !allowsSerial(allowedSerials, device.Serial) {
				continue
			}
			resource := deviceResourceFromUplinkStatus(device)
			if !selector.allows(merakiDeviceIdentity(resource)) {
				continue
			}
			rb := builder.deviceResource(resource)
			for _, uplink := range device.Uplinks {
				attrs := map[string]string{
					"meraki.uplink.interface":       uplink.Interface,
					"meraki.uplink.status":          uplink.Status,
					"meraki.uplink.provider":        uplink.Provider,
					"meraki.uplink.connection_type": uplink.ConnectionType,
				}
				rb.recordInt("meraki.uplink.status", "Meraki uplink status.", "1", activeStatus(uplink.Status), attrs)
				if rsrp, ok := parseFloatString(uplink.SignalStat.RSRP); ok {
					rb.recordDouble("meraki.uplink.cellular.signal.rsrp", "Cellular uplink RSRP.", "dBm", rsrp, attrs)
				}
				if rsrq, ok := parseFloatString(uplink.SignalStat.RSRQ); ok {
					rb.recordDouble("meraki.uplink.cellular.signal.rsrq", "Cellular uplink RSRQ.", "dB", rsrq, attrs)
				}
			}
		}
	}

	lossLatency, err := meraki.GetJSON[[]meraki.UplinkLossLatency](ctx, r.client, target.OrganizationID, "uplink_loss_latency", meraki.OrganizationPath(target.OrganizationID, "/devices/uplinksLossAndLatency"), nil)
	if err != nil {
		r.settings.Logger.Warn("Meraki uplink loss and latency endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		partial = true
	} else {
		for _, uplink := range lossLatency {
			if !allowsSerial(allowedSerials, uplink.Serial) || len(uplink.TimeSeries) == 0 {
				continue
			}
			sample := uplink.TimeSeries[len(uplink.TimeSeries)-1]
			resource := deviceResource{Serial: uplink.Serial, NetworkID: uplink.NetworkID, LANIP: uplink.IP, OSName: "Meraki"}
			if !selector.allows(merakiDeviceIdentity(resource)) {
				continue
			}
			rb := builder.deviceResource(resource)
			attrs := map[string]string{"meraki.uplink.interface": uplink.Uplink}
			rb.recordDouble("meraki.uplink.loss", "Meraki uplink packet loss percentage.", "%", sample.LossPercent, attrs)
			rb.recordDouble("meraki.uplink.latency", "Meraki uplink latency.", "ms", sample.LatencyMS, attrs)
		}
	}
	return partial
}

func (r *merakiMetricsReceiver) scrapeWireless(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	partial := false
	clients, err := meraki.GetPaginatedItemsJSON[meraki.WirelessClientsOverview](ctx, r.client, target.OrganizationID, "wireless_clients", meraki.OrganizationPath(target.OrganizationID, "/wireless/clients/overview/byDevice"), target.networkSerialQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki wireless clients endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		partial = true
	} else {
		for _, device := range clients {
			if !allowsSerial(allowedSerials, device.Serial) {
				continue
			}
			resource := deviceResource{Serial: device.Serial, NetworkID: device.Network.ID, OSName: "Meraki"}
			if !selector.allows(merakiDeviceIdentity(resource)) {
				continue
			}
			rb := builder.deviceResource(resource)
			for status, count := range device.Counts.ByStatus {
				rb.recordInt("meraki.wireless.client.count", "Wireless client count by status.", "{client}", count, map[string]string{"meraki.wireless.client.status": status})
			}
		}
	}

	channels, err := meraki.GetPaginatedJSON[meraki.WirelessChannelUtilization](ctx, r.client, target.OrganizationID, "wireless_channel_utilization", meraki.OrganizationPath(target.OrganizationID, "/wireless/devices/channelUtilization/byDevice"), target.windowedDeviceQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki wireless channel utilization endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		partial = true
	} else {
		for _, device := range channels {
			if !allowsSerial(allowedSerials, device.Serial) {
				continue
			}
			resource := deviceResource{Serial: device.Serial, MAC: device.MAC, NetworkID: device.Network.ID, OSName: "Meraki"}
			if !selector.allows(merakiDeviceIdentity(resource)) {
				continue
			}
			rb := builder.deviceResource(resource)
			for _, band := range device.ByBand {
				attrs := map[string]string{"meraki.wireless.band": band.Band}
				rb.recordDouble("meraki.wireless.channel_utilization", "Wireless channel utilization percentage.", "%", band.Total.Percentage, withAttr(attrs, "meraki.wireless.utilization.type", "total"))
				rb.recordDouble("meraki.wireless.channel_utilization", "Wireless channel utilization percentage.", "%", band.WiFi.Percentage, withAttr(attrs, "meraki.wireless.utilization.type", "wifi"))
				rb.recordDouble("meraki.wireless.channel_utilization", "Wireless channel utilization percentage.", "%", band.NonWiFi.Percentage, withAttr(attrs, "meraki.wireless.utilization.type", "non_wifi"))
			}
		}
	}

	packetLoss, err := meraki.GetPaginatedJSON[meraki.WirelessPacketLoss](ctx, r.client, target.OrganizationID, "wireless_packet_loss", meraki.OrganizationPath(target.OrganizationID, "/wireless/devices/packetLoss/byDevice"), target.windowedDeviceQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki wireless packet loss endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		partial = true
	} else {
		for _, device := range packetLoss {
			if !allowsSerial(allowedSerials, device.Device.Serial) {
				continue
			}
			resource := deviceResource{Serial: device.Device.Serial, Name: device.Device.Name, MAC: device.Device.MAC, NetworkID: device.Network.ID, OSName: "Meraki"}
			if !selector.allows(merakiDeviceIdentity(resource)) {
				continue
			}
			rb := builder.deviceResource(resource)
			recordWirelessPacketLoss(rb, "receive", device.Downstream)
			recordWirelessPacketLoss(rb, "transmit", device.Upstream)
		}
	}

	ssids, err := meraki.GetPaginatedItemsJSON[meraki.WirelessSSIDStatus](ctx, r.client, target.OrganizationID, "wireless_ssids", meraki.OrganizationPath(target.OrganizationID, "/wireless/ssids/statuses/byDevice"), target.networkSerialQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki wireless SSID status endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		partial = true
	} else {
		for _, device := range ssids {
			if !allowsSerial(allowedSerials, device.Serial) {
				continue
			}
			resource := deviceResource{Serial: device.Serial, Name: device.Name, NetworkID: device.Network.ID, OSName: "Meraki"}
			if !selector.allows(merakiDeviceIdentity(resource)) {
				continue
			}
			rb := builder.deviceResource(resource)
			for _, bss := range device.BasicServiceSets {
				attrs := map[string]string{
					"meraki.wireless.ssid.name":   bss.SSID.Name,
					"meraki.wireless.ssid.number": strconv.FormatInt(bss.SSID.Number, 10),
					"meraki.wireless.bssid":       bss.BSSID,
					"meraki.wireless.band":        bss.Radio.Band,
					"meraki.wireless.radio.index": bss.Radio.Index,
				}
				rb.recordInt("meraki.wireless.ssid.status", "Wireless SSID enabled, advertised, and broadcasting status.", "1", boolToInt(bss.SSID.Enabled && bss.SSID.Advertised && bss.Radio.IsBroadcasting), attrs)
			}
		}
	}

	return partial
}

func (r *merakiMetricsReceiver) scrapeVPN(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	partial := false
	statuses, err := meraki.GetPaginatedJSON[meraki.VPNStatus](ctx, r.client, target.OrganizationID, "vpn_statuses", meraki.OrganizationPath(target.OrganizationID, "/appliance/vpn/statuses"), target.networkQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki VPN status endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		partial = true
	} else {
		for _, status := range statuses {
			if !allowsSerial(allowedSerials, status.DeviceSerial) {
				continue
			}
			resource := deviceResource{Serial: status.DeviceSerial, Name: status.NetworkName, NetworkID: status.NetworkID, OSName: "Meraki"}
			if !selector.allows(merakiDeviceIdentity(resource)) {
				continue
			}
			rb := builder.deviceResource(resource)
			for _, peer := range status.MerakiVPNPeers {
				rb.recordInt("meraki.vpn.peer.status", "Meraki VPN peer reachability.", "1", reachableStatus(peer.Reachability), map[string]string{
					"meraki.vpn.peer.type":         "meraki",
					"meraki.vpn.peer.network_id":   peer.NetworkID,
					"meraki.vpn.peer.name":         peer.NetworkName,
					"meraki.vpn.peer.reachability": peer.Reachability,
				})
			}
			for _, peer := range status.ThirdPartyVPNPeers {
				rb.recordInt("meraki.vpn.peer.status", "Meraki VPN peer reachability.", "1", reachableStatus(peer.Reachability), map[string]string{
					"meraki.vpn.peer.type":         "third_party",
					"meraki.vpn.peer.name":         peer.Name,
					"meraki.vpn.peer.public_ip":    peer.PublicIP,
					"meraki.vpn.peer.reachability": peer.Reachability,
				})
			}
		}
	}

	stats, err := meraki.GetPaginatedJSON[meraki.VPNStats](ctx, r.client, target.OrganizationID, "vpn_stats", meraki.OrganizationPath(target.OrganizationID, "/appliance/vpn/stats"), target.windowedNetworkQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki VPN stats endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		partial = true
	} else {
		for _, stat := range stats {
			if !builder.networkAllowed(stat.NetworkID, stat.NetworkName, selector) {
				continue
			}
			rb := builder.networkResource(stat.NetworkID, stat.NetworkName, target.OrganizationID)
			for _, peer := range stat.MerakiVPNPeers {
				peerAttrs := map[string]string{
					"meraki.vpn.peer.network_id": peer.NetworkID,
					"meraki.vpn.peer.name":       peer.NetworkName,
				}
				rb.recordInt("meraki.vpn.peer.usage", "Windowed Meraki VPN peer usage.", "KBy", peer.UsageSummary.ReceivedInKilobytes, withAttr(peerAttrs, "network.io.direction", "receive"))
				rb.recordInt("meraki.vpn.peer.usage", "Windowed Meraki VPN peer usage.", "KBy", peer.UsageSummary.SentInKilobytes, withAttr(peerAttrs, "network.io.direction", "transmit"))
				for _, latency := range peer.LatencySummaries {
					rb.recordDouble("meraki.vpn.peer.latency", "Meraki VPN peer latency.", "ms", latency.AvgLatencyMS, withVPNUplinks(peerAttrs, latency.SenderUplink, latency.ReceiverUplink))
				}
				for _, loss := range peer.LossPercentageSummaries {
					rb.recordDouble("meraki.vpn.peer.loss", "Meraki VPN peer packet loss percentage.", "%", loss.AvgLossPercentage, withVPNUplinks(peerAttrs, loss.SenderUplink, loss.ReceiverUplink))
				}
				for _, jitter := range peer.JitterSummaries {
					rb.recordDouble("meraki.vpn.peer.jitter", "Meraki VPN peer jitter.", "ms", jitter.AvgJitter, withVPNUplinks(peerAttrs, jitter.SenderUplink, jitter.ReceiverUplink))
				}
				for _, mos := range peer.MOSSummaries {
					rb.recordDouble("meraki.vpn.peer.mos", "Meraki VPN peer MOS score.", "1", mos.AvgMOS, withVPNUplinks(peerAttrs, mos.SenderUplink, mos.ReceiverUplink))
				}
			}
		}
	}
	return partial
}

func (r *merakiMetricsReceiver) scrapePowerModules(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	statuses, err := meraki.GetPaginatedJSON[meraki.PowerModuleStatus](ctx, r.client, target.OrganizationID, "power_modules", meraki.OrganizationPath(target.OrganizationID, "/devices/powerModules/statuses/byDevice"), target.inventoryQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki power module endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		return true
	}
	for _, device := range statuses {
		if !allowsSerial(allowedSerials, device.Serial) {
			continue
		}
		resource := deviceResource{Serial: device.Serial, Name: device.Name, MAC: device.MAC, ProductType: device.ProductType, NetworkID: device.Network.ID, OSName: "Meraki"}
		if !selector.allows(merakiDeviceIdentity(resource)) {
			continue
		}
		rb := builder.deviceResource(resource)
		for _, slot := range device.Slots {
			rb.recordInt("meraki.power.module.status", "Meraki power module status.", "1", powerModuleStatus(slot.Status), map[string]string{
				"meraki.power.slot":          strconv.FormatInt(slot.Number, 10),
				"meraki.power.module.serial": slot.Serial,
				"meraki.power.module.model":  slot.Model,
				"meraki.power.module.status": slot.Status,
			})
		}
	}
	return false
}

func (r *merakiMetricsReceiver) scrapeTopology(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	devices, err := meraki.GetPaginatedItemsJSON[meraki.TopologyDiscovery](ctx, r.client, target.OrganizationID, "switch_topology", meraki.OrganizationPath(target.OrganizationID, "/switch/ports/topology/discovery/byDevice"), target.networkSerialQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki topology discovery endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		return true
	}
	for _, device := range devices {
		if !allowsSerial(allowedSerials, device.Serial) {
			continue
		}
		resource := deviceResourceFromTopology(device)
		if !selector.allows(merakiDeviceIdentity(resource)) {
			continue
		}
		rb := builder.deviceResource(resource)
		for _, port := range device.Ports {
			recordTopologyProtocol(rb, "cdp", port.PortID, port.CDP)
			recordTopologyProtocol(rb, "lldp", port.PortID, port.LLDP)
		}
	}
	return false
}

func (r *merakiMetricsReceiver) scrapeTransceivers(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	devices, err := meraki.GetPaginatedItemsJSON[meraki.TransceiverReadings](ctx, r.client, target.OrganizationID, "transceivers", meraki.OrganizationPath(target.OrganizationID, "/appliance/devices/ports/transceivers/readings/history/byDevice"), target.windowedDeviceQuery())
	if err != nil {
		r.settings.Logger.Warn("Meraki transceiver endpoint failed", zap.String("organization_id", target.OrganizationID), zap.Error(err))
		return true
	}
	for _, device := range devices {
		if !allowsSerial(allowedSerials, device.Serial) {
			continue
		}
		resource := deviceResource{Serial: device.Serial, NetworkID: device.Network.ID, OSName: "Meraki"}
		if !selector.allows(merakiDeviceIdentity(resource)) {
			continue
		}
		rb := builder.deviceResource(resource)
		for _, port := range device.Ports {
			for _, reading := range port.Readings {
				attrs := interfaceAttrs(firstNonEmpty(port.InterfaceName, port.PortID), "", "", "")
				attrs["cisco.transceiver.lane"] = reading.SFPProductID
				recordTransceiverValue(rb, attrs, "tx_power", "dBm", reading.ByMetric.Power.Transmit)
				recordTransceiverValue(rb, attrs, "rx_power", "dBm", reading.ByMetric.Power.Receive)
				recordTransceiverValue(rb, attrs, "temperature", "Cel", reading.ByMetric.Temperature.Celsius)
				recordTransceiverValue(rb, attrs, "supply_voltage", "V", reading.ByMetric.SupplyVoltage.Level)
				recordTransceiverValue(rb, attrs, "laser_bias_current", "mA", reading.ByMetric.LaserBiasCurrent.Draw)
			}
		}
	}
	return false
}

func (r *merakiMetricsReceiver) scrapeAppliancePerformance(ctx context.Context, builder *merakiMetricsBuilder, target merakiTarget, allowedSerials map[string]struct{}, selector deviceSelectionMatcher) bool {
	partial := false
	for _, device := range builder.applianceDevices(allowedSerials) {
		if !selector.allows(merakiDeviceIdentity(device)) {
			continue
		}
		path := "/devices/" + url.PathEscape(device.Serial) + "/appliance/performance"
		perf, err := meraki.GetJSON[meraki.AppliancePerformance](ctx, r.client, target.OrganizationID, "appliance_performance", path, nil)
		if err != nil {
			r.settings.Logger.Warn("Meraki appliance performance endpoint failed", zap.String("organization_id", target.OrganizationID), zap.String("serial", device.Serial), zap.Error(err))
			partial = true
			continue
		}
		builder.deviceResource(device).recordDouble("meraki.appliance.performance.score", "Meraki appliance performance score.", "1", perf.PerfScore, nil)
	}
	return partial
}

func (r *merakiMetricsReceiver) recordRequest(stat meraki.RequestStat) {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats = append(r.stats, stat)
}

func (r *merakiMetricsReceiver) resetRequestStats() {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats = nil
}

func (r *merakiMetricsReceiver) recordAPIRequestMetrics(builder *merakiMetricsBuilder) {
	r.statsMu.Lock()
	stats := append([]meraki.RequestStat(nil), r.stats...)
	r.statsMu.Unlock()
	for _, stat := range stats {
		rb := builder.orgResource(stat.OrganizationID)
		attrs := map[string]string{
			"meraki.api.operation":   stat.Operation,
			"meraki.api.method":      stat.Method,
			"meraki.api.path":        stat.Path,
			"meraki.api.outcome":     stat.Outcome,
			"meraki.organization.id": stat.OrganizationID,
		}
		if stat.StatusCode > 0 {
			attrs["http.response.status_code"] = strconv.Itoa(stat.StatusCode)
		}
		rb.recordDouble("meraki.api.request.duration", "Meraki API request duration.", "s", stat.Duration.Seconds(), attrs)
		if stat.Err != nil {
			rb.recordSum("meraki.api.request.errors", "Meraki API request errors.", "{error}", 1, attrs)
		}
		if stat.RateLimited {
			rb.recordSum("meraki.api.request.rate_limited", "Meraki API requests that received HTTP 429.", "{request}", 1, attrs)
		}
	}
}

func (t merakiTarget) inventoryQuery() url.Values {
	return meraki.Query(map[string][]string{
		"networkIds":   t.NetworkIDs,
		"productTypes": t.ProductTypes,
		"serials":      t.Serials,
		"tags":         t.Tags,
	}, map[string]string{
		"perPage":        "1000",
		"tagsFilterType": t.TagsFilterType,
	})
}

func (t merakiTarget) deviceQuery() url.Values {
	return meraki.Query(map[string][]string{
		"networkIds":   t.NetworkIDs,
		"productTypes": t.ProductTypes,
		"serials":      t.Serials,
		"tags":         t.Tags,
	}, map[string]string{
		"perPage":        "1000",
		"tagsFilterType": t.TagsFilterType,
	})
}

func (t merakiTarget) networkSerialQuery() url.Values {
	return meraki.Query(map[string][]string{
		"networkIds": t.NetworkIDs,
		"serials":    t.Serials,
	}, map[string]string{"perPage": "1000"})
}

func (t merakiTarget) networkQuery() url.Values {
	return meraki.Query(map[string][]string{"networkIds": t.NetworkIDs}, map[string]string{"perPage": "1000"})
}

func (t merakiTarget) windowedDeviceQuery() url.Values {
	query := t.networkSerialQuery()
	query.Set("timespan", "300")
	return query
}

func (t merakiTarget) windowedSwitchQuery() url.Values {
	query := t.networkSerialQuery()
	query.Set("timespan", "300")
	query.Set("interval", "300")
	return query
}

func (t merakiTarget) windowedNetworkQuery() url.Values {
	query := t.networkQuery()
	query.Set("timespan", "300")
	return query
}

func (t merakiTarget) serialSet() map[string]struct{} {
	if len(t.Serials) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(t.Serials))
	for _, serial := range t.Serials {
		if serial != "" {
			out[serial] = struct{}{}
		}
	}
	return out
}

func (t merakiTarget) hasInventoryScopedFilters() bool {
	return len(t.ProductTypes) > 0 || len(t.Tags) > 0 || t.TagsFilterType != ""
}

type merakiMetricsBuilder struct {
	metrics       pmetric.Metrics
	now           pcommon.Timestamp
	start         pcommon.Timestamp
	resources     map[string]*resourceMetricsBuilder
	devices       map[string]deviceResource
	networkSerial map[string]string
	portSpeeds    map[string]int64
	counters      *counterStore
}

type deviceResource struct {
	Serial      string
	Name        string
	LANIP       string
	PublicIP    string
	MAC         string
	Model       string
	Firmware    string
	ProductType string
	NetworkID   string
	OSName      string
}

type resourceMetricsBuilder struct {
	resource pcommon.Resource
	scope    pmetric.ScopeMetrics
	metrics  map[string]pmetric.Metric
	now      pcommon.Timestamp
	start    pcommon.Timestamp
	counters *counterStore
}

func newMerakiMetricsBuilder(now time.Time, counters *counterStore) *merakiMetricsBuilder {
	if counters == nil {
		counters = newCounterStore()
	}
	ts := pcommon.NewTimestampFromTime(now)
	return &merakiMetricsBuilder{
		metrics:       pmetric.NewMetrics(),
		now:           ts,
		start:         ts,
		resources:     map[string]*resourceMetricsBuilder{},
		devices:       map[string]deviceResource{},
		networkSerial: map[string]string{},
		portSpeeds:    map[string]int64{},
		counters:      counters,
	}
}

func (b *merakiMetricsBuilder) emit() pmetric.Metrics {
	return b.metrics
}

func (b *merakiMetricsBuilder) deviceResource(device deviceResource) *resourceMetricsBuilder {
	if device.Serial == "" {
		device.Serial = firstNonEmpty(device.NetworkID, "unknown")
	}
	device.OSName = firstNonEmpty(device.OSName, "Meraki")
	if existing, ok := b.devices[device.Serial]; ok {
		device = mergeDeviceResource(existing, device)
	}
	b.devices[device.Serial] = device
	if device.NetworkID != "" {
		b.networkSerial[device.NetworkID] = device.Serial
	}

	key := "device:" + device.Serial
	rb := b.resource(key)
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", device.Serial)
	putStr(attrs, "host.ip", firstNonEmpty(device.LANIP, device.PublicIP))
	putStr(attrs, "host.name", device.Name)
	putStr(attrs, "host.type", firstNonEmpty(device.Model, device.ProductType))
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", device.OSName)
	putStr(attrs, "os.version", device.Firmware)
	putStr(attrs, "meraki.device.serial", device.Serial)
	putStr(attrs, "meraki.device.product_type", device.ProductType)
	putStr(attrs, "meraki.network.id", device.NetworkID)
	return rb
}

func (b *merakiMetricsBuilder) networkResource(networkID, networkName, organizationID string) *resourceMetricsBuilder {
	if serial := b.networkSerial[networkID]; serial != "" {
		device := b.devices[serial]
		if networkName != "" && device.Name == "" {
			device.Name = networkName
		}
		return b.deviceResource(device)
	}
	rb := b.resource("network:" + networkID)
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", "meraki:network:"+networkID)
	putStr(attrs, "host.name", firstNonEmpty(networkName, networkID))
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Meraki")
	putStr(attrs, "meraki.network.id", networkID)
	putStr(attrs, "meraki.organization.id", organizationID)
	return rb
}

func (b *merakiMetricsBuilder) networkAllowed(networkID, networkName string, selector deviceSelectionMatcher) bool {
	if selector.empty() {
		return true
	}
	if serial := b.networkSerial[networkID]; serial != "" {
		return selector.allows(merakiDeviceIdentity(b.devices[serial]))
	}
	return selector.allows(deviceIdentity{
		hostNames: []string{networkName},
		hostIDs:   []string{"meraki:network:" + networkID},
		deviceIDs: []string{networkID},
	})
}

func (b *merakiMetricsBuilder) orgResource(organizationID string) *resourceMetricsBuilder {
	rb := b.resource("org:" + organizationID)
	attrs := rb.resource.Attributes()
	putStr(attrs, "host.id", "meraki:org:"+organizationID)
	putStr(attrs, "host.name", "Meraki organization "+organizationID)
	putStr(attrs, "hw.type", "network")
	putStr(attrs, "os.name", "Meraki")
	putStr(attrs, "meraki.organization.id", organizationID)
	return rb
}

func (b *merakiMetricsBuilder) resource(key string) *resourceMetricsBuilder {
	if rb := b.resources[key]; rb != nil {
		return rb
	}
	rm := b.metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName(merakiScopeName)
	rb := &resourceMetricsBuilder{
		resource: rm.Resource(),
		scope:    sm,
		metrics:  map[string]pmetric.Metric{},
		now:      b.now,
		start:    b.start,
		counters: b.counters,
	}
	b.resources[key] = rb
	return rb
}

func (b *merakiMetricsBuilder) setPortSpeed(serial, portID string, speed int64) {
	if serial == "" || portID == "" || speed <= 0 {
		return
	}
	b.portSpeeds[serial+"/"+portID] = speed
}

func (b *merakiMetricsBuilder) portSpeed(serial, portID string) int64 {
	return b.portSpeeds[serial+"/"+portID]
}

func (b *merakiMetricsBuilder) applianceDevices(allowedSerials map[string]struct{}) []deviceResource {
	devices := make([]deviceResource, 0)
	for _, device := range b.devices {
		if !allowsSerial(allowedSerials, device.Serial) {
			continue
		}
		if strings.EqualFold(device.ProductType, "appliance") || strings.HasPrefix(strings.ToUpper(device.Model), "MX") {
			devices = append(devices, device)
		}
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].Serial < devices[j].Serial })
	return devices
}

func (rb *resourceMetricsBuilder) recordInt(name, description, unit string, value int64, attrs map[string]string) {
	dp := rb.gaugeMetric(name, description, unit).Gauge().DataPoints().AppendEmpty()
	dp.SetTimestamp(rb.now)
	dp.SetStartTimestamp(rb.start)
	dp.SetIntValue(value)
	putAttrs(dp.Attributes(), attrs)
}

func (rb *resourceMetricsBuilder) recordDouble(name, description, unit string, value float64, attrs map[string]string) {
	dp := rb.gaugeMetric(name, description, unit).Gauge().DataPoints().AppendEmpty()
	dp.SetTimestamp(rb.now)
	dp.SetStartTimestamp(rb.start)
	dp.SetDoubleValue(value)
	putAttrs(dp.Attributes(), attrs)
}

// recordSum accumulates delta into the receiver-scoped counter store and emits
// the running cumulative total as a monotonic Sum metric. Use this for
// counter-style observations (errors, rate-limit hits, packet counts) so
// SignalFlow rate()/sum_over_time() compute correctly.
func (rb *resourceMetricsBuilder) recordSum(name, description, unit string, delta int64, attrs map[string]string) {
	total := rb.counters.Add(name, attrs, float64(delta))
	dp := rb.sumMetric(name, description, unit).Sum().DataPoints().AppendEmpty()
	dp.SetTimestamp(rb.now)
	dp.SetStartTimestamp(rb.start)
	dp.SetIntValue(int64(total))
	putAttrs(dp.Attributes(), attrs)
}

func (rb *resourceMetricsBuilder) recordSumDouble(name, description, unit string, delta float64, attrs map[string]string) {
	total := rb.counters.Add(name, attrs, delta)
	dp := rb.sumMetric(name, description, unit).Sum().DataPoints().AppendEmpty()
	dp.SetTimestamp(rb.now)
	dp.SetStartTimestamp(rb.start)
	dp.SetDoubleValue(total)
	putAttrs(dp.Attributes(), attrs)
}

func (rb *resourceMetricsBuilder) gaugeMetric(name, description, unit string) pmetric.Metric {
	if metric, ok := rb.metrics[name]; ok {
		return metric
	}
	metric := rb.scope.Metrics().AppendEmpty()
	metric.SetName(name)
	metric.SetDescription(description)
	metric.SetUnit(unit)
	metric.SetEmptyGauge()
	rb.metrics[name] = metric
	return metric
}

func (rb *resourceMetricsBuilder) sumMetric(name, description, unit string) pmetric.Metric {
	if metric, ok := rb.metrics[name]; ok {
		return metric
	}
	metric := rb.scope.Metrics().AppendEmpty()
	metric.SetName(name)
	metric.SetDescription(description)
	metric.SetUnit(unit)
	sum := metric.SetEmptySum()
	sum.SetIsMonotonic(true)
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	rb.metrics[name] = metric
	return metric
}

// metric is retained for backwards compatibility with helpers that pre-existed
// the Sum/Gauge split. New code should prefer gaugeMetric or sumMetric.
func (rb *resourceMetricsBuilder) metric(name, description, unit string) pmetric.Metric {
	return rb.gaugeMetric(name, description, unit)
}

func deviceResourceFromInventory(device meraki.Device) deviceResource {
	return deviceResource{
		Serial:      device.Serial,
		Name:        device.Name,
		LANIP:       device.LANIP,
		MAC:         device.MAC,
		Model:       device.Model,
		Firmware:    device.Firmware,
		ProductType: device.ProductType,
		NetworkID:   device.NetworkID,
		OSName:      "Meraki",
	}
}

func deviceResourceFromStatus(status meraki.DeviceStatus) deviceResource {
	return deviceResource{
		Serial:      status.Serial,
		Name:        status.Name,
		LANIP:       status.LANIP,
		PublicIP:    status.PublicIP,
		MAC:         status.MAC,
		Model:       status.Model,
		ProductType: status.ProductType,
		NetworkID:   status.NetworkID,
		OSName:      "Meraki",
	}
}

func deviceResourceFromMemory(usage meraki.DeviceMemoryUsage) deviceResource {
	return deviceResource{
		Serial:    usage.Serial,
		Name:      usage.Name,
		MAC:       usage.MAC,
		Model:     usage.Model,
		NetworkID: usage.Network.ID,
		OSName:    "Meraki",
	}
}

func deviceResourceFromSwitch(sw meraki.SwitchPortsStatus) deviceResource {
	return deviceResource{Serial: sw.Serial, Name: sw.Name, MAC: sw.MAC, Model: sw.Model, NetworkID: sw.Network.ID, ProductType: "switch", OSName: "Meraki"}
}

func deviceResourceFromSwitchUsage(sw meraki.SwitchPortsUsage) deviceResource {
	return deviceResource{Serial: sw.Serial, Name: sw.Name, MAC: sw.MAC, Model: sw.Model, NetworkID: sw.Network.ID, ProductType: "switch", OSName: "Meraki"}
}

func deviceResourceFromUplinkStatus(status meraki.UplinkStatus) deviceResource {
	return deviceResource{Serial: status.Serial, LANIP: firstUplinkIP(status), Model: status.Model, NetworkID: status.NetworkID, OSName: "Meraki"}
}

func deviceResourceFromTopology(device meraki.TopologyDiscovery) deviceResource {
	return deviceResource{Serial: device.Serial, Name: device.Name, MAC: device.MAC, Model: device.Model, NetworkID: device.Network.ID, ProductType: "switch", OSName: "Meraki"}
}

func mergeDeviceResource(existing, update deviceResource) deviceResource {
	return deviceResource{
		Serial:      firstNonEmpty(update.Serial, existing.Serial),
		Name:        firstNonEmpty(update.Name, existing.Name),
		LANIP:       firstNonEmpty(update.LANIP, existing.LANIP),
		PublicIP:    firstNonEmpty(update.PublicIP, existing.PublicIP),
		MAC:         firstNonEmpty(update.MAC, existing.MAC),
		Model:       firstNonEmpty(update.Model, existing.Model),
		Firmware:    firstNonEmpty(update.Firmware, existing.Firmware),
		ProductType: firstNonEmpty(update.ProductType, existing.ProductType),
		NetworkID:   firstNonEmpty(update.NetworkID, existing.NetworkID),
		OSName:      firstNonEmpty(update.OSName, existing.OSName),
	}
}

func memoryUtilization(usage meraki.DeviceMemoryUsage) (float64, bool) {
	if len(usage.Intervals) > 0 {
		latest := usage.Intervals[len(usage.Intervals)-1]
		if latest.Memory.Used.Percentages.Median > 0 {
			return latest.Memory.Used.Percentages.Median / 100, true
		}
		if latest.Memory.Used.Percentages.Maximum > 0 {
			return latest.Memory.Used.Percentages.Maximum / 100, true
		}
		used := latest.Memory.Used.Median
		free := latest.Memory.Free.Median
		if used+free > 0 {
			return used / (used + free), true
		}
	}
	if usage.Used.Median+usage.Free.Median > 0 {
		return usage.Used.Median / (usage.Used.Median + usage.Free.Median), true
	}
	if usage.Provisioned > 0 && usage.Used.Median > 0 {
		return usage.Used.Median / usage.Provisioned, true
	}
	return 0, false
}

func recordWirelessPacketLoss(rb *resourceMetricsBuilder, direction string, loss meraki.PacketLossDirection) {
	attrs := map[string]string{"network.io.direction": direction}
	rb.recordSum("meraki.wireless.packet.count", "Wireless packets observed by Meraki.", "{packet}", loss.Total, attrs)
	rb.recordSum("meraki.wireless.packet.loss", "Wireless packets lost by Meraki.", "{packet}", loss.Lost, attrs)
	rb.recordDouble("meraki.wireless.packet.loss_percentage", "Wireless packet loss percentage.", "%", loss.LossPercentage, attrs)
}

func recordTopologyProtocol(rb *resourceMetricsBuilder, protocol, portID string, values []meraki.NameValue) {
	if len(values) == 0 {
		return
	}
	attrs := map[string]string{
		"cisco.topology.protocol":           protocol,
		"network.interface.name":            portID,
		"cisco.topology.neighbor.name":      topologyValue(values, "System name", "Device ID", "Chassis ID"),
		"cisco.topology.neighbor.interface": topologyValue(values, "Port ID", "Port description"),
		"cisco.topology.neighbor.platform":  topologyValue(values, "Platform", "System description"),
		"cisco.topology.neighbor.address":   topologyValue(values, "Management address", "Management Address"),
	}
	rb.recordInt("cisco.topology.neighbor.info", "Topology neighbor information.", "1", 1, attrs)
}

func recordTransceiverValue(rb *resourceMetricsBuilder, base map[string]string, sensor, unit string, value meraki.SummaryValue) {
	if value.Median == 0 && value.Minimum == 0 && value.Maximum == 0 {
		return
	}
	attrs := cloneStringMap(base)
	attrs["cisco.transceiver.sensor"] = sensor
	attrs["cisco.transceiver.sensor.unit"] = unit
	rb.recordDouble("cisco.transceiver.sensor", "Transceiver DOM sensor value.", unit, value.Median, attrs)
}

func topologyValue(values []meraki.NameValue, names ...string) string {
	for _, name := range names {
		for _, value := range values {
			if strings.EqualFold(value.Name, name) {
				return value.Value
			}
		}
	}
	return ""
}

func interfaceAttrs(name, mac, description, speed string) map[string]string {
	return map[string]string{
		"network.interface.name":        name,
		"network.interface.mac":         mac,
		"network.interface.description": description,
		"network.interface.speed":       speed,
	}
}

func withAttr(attrs map[string]string, key, value string) map[string]string {
	out := cloneStringMap(attrs)
	out[key] = value
	return out
}

func withVPNUplinks(attrs map[string]string, sender, receiver string) map[string]string {
	out := cloneStringMap(attrs)
	out["meraki.vpn.sender.uplink"] = sender
	out["meraki.vpn.receiver.uplink"] = receiver
	return out
}

func cloneStringMap(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs))
	for key, value := range attrs {
		out[key] = value
	}
	return out
}

func putAttrs(target pcommon.Map, attrs map[string]string) {
	for key, value := range attrs {
		putStr(target, key, value)
	}
}

func putStr(attrs pcommon.Map, key, value string) {
	if key != "" && value != "" {
		attrs.PutStr(key, value)
	}
}

func allowsSerial(allowed map[string]struct{}, serial string) bool {
	if allowed == nil {
		return true
	}
	_, ok := allowed[serial]
	return ok
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstUplinkIP(status meraki.UplinkStatus) string {
	for _, uplink := range status.Uplinks {
		if uplink.IP != "" {
			return uplink.IP
		}
	}
	return ""
}

func boolToInt(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func merakiDeviceUp(status string) int64 {
	switch strings.ToLower(status) {
	case "online", "alerting":
		return 1
	default:
		return 0
	}
}

func merakiStatusCode(status string) int64 {
	switch strings.ToLower(status) {
	case "online":
		return 1
	case "alerting":
		return 2
	case "dormant":
		return 3
	default:
		return 0
	}
}

func connectedStatus(status string) int64 {
	switch strings.ToLower(status) {
	case "connected", "up", "active", "ready":
		return 1
	default:
		return 0
	}
}

func activeStatus(status string) int64 {
	switch strings.ToLower(status) {
	case "active", "ready", "online":
		return 1
	default:
		return 0
	}
}

func reachableStatus(status string) int64 {
	if strings.EqualFold(status, "reachable") {
		return 1
	}
	return 0
}

func powerModuleStatus(status string) int64 {
	switch strings.ToLower(status) {
	case "connected", "powering", "ok", "present":
		return 1
	default:
		return 0
	}
}

func parseMerakiSpeed(speed string) (int64, string) {
	speed = strings.TrimSpace(speed)
	if speed == "" {
		return 0, ""
	}
	fields := strings.Fields(speed)
	if len(fields) < 2 {
		return 0, speed
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, speed
	}
	unit := strings.ToLower(fields[1])
	multiplier := float64(1)
	switch {
	case strings.HasPrefix(unit, "tb"):
		multiplier = 1_000_000_000_000
	case strings.HasPrefix(unit, "gb"):
		multiplier = 1_000_000_000
	case strings.HasPrefix(unit, "mb"):
		multiplier = 1_000_000
	case strings.HasPrefix(unit, "kb"):
		multiplier = 1_000
	default:
		return 0, speed
	}
	return int64(value * multiplier), speed
}

func parseFloatString(value string) (float64, bool) {
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	return parsed, err == nil
}

func (d deviceResource) String() string {
	return fmt.Sprintf("%s/%s", d.Serial, d.Name)
}
