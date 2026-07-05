// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meraki // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/meraki"

import (
	"encoding/json"
	"strconv"
)

// Device describes a Meraki organization inventory device.
type Device struct {
	Name        string   `json:"name"`
	NetworkID   string   `json:"networkId"`
	Serial      string   `json:"serial"`
	Model       string   `json:"model"`
	MAC         string   `json:"mac"`
	LANIP       string   `json:"lanIp"`
	Firmware    string   `json:"firmware"`
	ProductType string   `json:"productType"`
	Tags        []string `json:"tags"`
}

// DeviceStatus describes the Dashboard status for a device.
type DeviceStatus struct {
	Name           string   `json:"name"`
	Serial         string   `json:"serial"`
	MAC            string   `json:"mac"`
	PublicIP       string   `json:"publicIp"`
	NetworkID      string   `json:"networkId"`
	Status         string   `json:"status"`
	LastReportedAt string   `json:"lastReportedAt"`
	LANIP          string   `json:"lanIp"`
	ProductType    string   `json:"productType"`
	Model          string   `json:"model"`
	Tags           []string `json:"tags"`
}

// NetworkRef is the compact network object embedded by several organization endpoints.
type NetworkRef struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// DeviceMemoryUsage describes a device memory usage interval response item.
type DeviceMemoryUsage struct {
	Serial      string     `json:"serial"`
	Model       string     `json:"model"`
	Name        string     `json:"name"`
	MAC         string     `json:"mac"`
	Network     NetworkRef `json:"network"`
	Provisioned *float64   `json:"provisioned"`
	Used        struct {
		Median *float64 `json:"median"`
	} `json:"used"`
	Free struct {
		Median *float64 `json:"median"`
	} `json:"free"`
	Intervals []DeviceMemoryInterval `json:"intervals"`
}

// DeviceMemoryInterval is one timestamped memory snapshot.
type DeviceMemoryInterval struct {
	StartTS string `json:"startTs"`
	EndTS   string `json:"endTs"`
	Memory  struct {
		Used struct {
			Median      *float64 `json:"median"`
			Percentages struct {
				Maximum *float64 `json:"maximum"`
				Median  *float64 `json:"median"`
			} `json:"percentages"`
		} `json:"used"`
		Free struct {
			Median *float64 `json:"median"`
		} `json:"free"`
	} `json:"memory"`
}

// SwitchPortsStatus describes switch port status for one switch.
type SwitchPortsStatus struct {
	Name    string     `json:"name"`
	Serial  string     `json:"serial"`
	MAC     string     `json:"mac"`
	Network NetworkRef `json:"network"`
	Model   string     `json:"model"`
	Ports   []struct {
		PortID   string   `json:"portId"`
		Enabled  bool     `json:"enabled"`
		Status   string   `json:"status"`
		IsUplink bool     `json:"isUplink"`
		Errors   []string `json:"errors"`
		Warnings []string `json:"warnings"`
		Speed    string   `json:"speed"`
		Duplex   string   `json:"duplex"`
		PoE      struct {
			IsAllocated bool `json:"isAllocated"`
		} `json:"poe"`
	} `json:"ports"`
}

// SwitchPortsUsage describes switch port usage intervals for one switch.
type SwitchPortsUsage struct {
	Name    string     `json:"name"`
	Serial  string     `json:"serial"`
	MAC     string     `json:"mac"`
	Network NetworkRef `json:"network"`
	Model   string     `json:"model"`
	Ports   []struct {
		PortID    string                    `json:"portId"`
		Intervals []SwitchPortUsageInterval `json:"intervals"`
	} `json:"ports"`
}

// SwitchPortUsageInterval is one timestamped switch-port usage snapshot.
type SwitchPortUsageInterval struct {
	StartTS string `json:"startTs"`
	EndTS   string `json:"endTs"`
	Data    struct {
		Usage DirectionalNumber `json:"usage"`
	} `json:"data"`
	Bandwidth struct {
		Usage DirectionalNumber `json:"usage"`
	} `json:"bandwidth"`
	Energy struct {
		Usage struct {
			Total float64 `json:"total"`
		} `json:"usage"`
	} `json:"energy"`
}

// DirectionalNumber is a total/upstream/downstream value used by Meraki usage endpoints.
type DirectionalNumber struct {
	Total      float64 `json:"total"`
	Upstream   float64 `json:"upstream"`
	Downstream float64 `json:"downstream"`
}

// UplinkStatus describes appliance or device uplink status.
type UplinkStatus struct {
	NetworkID        string `json:"networkId"`
	Serial           string `json:"serial"`
	Model            string `json:"model"`
	LastReportedAt   string `json:"lastReportedAt"`
	HighAvailability struct {
		Enabled bool   `json:"enabled"`
		Role    string `json:"role"`
	} `json:"highAvailability"`
	Uplinks []struct {
		Interface      string `json:"interface"`
		Status         string `json:"status"`
		IP             string `json:"ip"`
		Gateway        string `json:"gateway"`
		PublicIP       string `json:"publicIp"`
		Provider       string `json:"provider"`
		ConnectionType string `json:"connectionType"`
		SignalType     string `json:"signalType"`
		SignalStat     struct {
			RSRP string `json:"rsrp"`
			RSRQ string `json:"rsrq"`
		} `json:"signalStat"`
	} `json:"uplinks"`
}

// UplinkLossLatency describes uplink loss and latency time-series samples.
type UplinkLossLatency struct {
	NetworkID  string                    `json:"networkId"`
	Serial     string                    `json:"serial"`
	Uplink     string                    `json:"uplink"`
	IP         string                    `json:"ip"`
	TimeSeries []UplinkLossLatencySample `json:"timeSeries"`
}

// UplinkLossLatencySample is one timestamped loss and latency observation.
type UplinkLossLatencySample struct {
	TS          string  `json:"ts"`
	LossPercent float64 `json:"lossPercent"`
	LatencyMS   float64 `json:"latencyMs"`
}

// WirelessClientsOverview describes wireless client counts for one AP.
type WirelessClientsOverview struct {
	Network NetworkRef `json:"network"`
	Serial  string     `json:"serial"`
	Counts  struct {
		ByStatus map[string]int64 `json:"byStatus"`
	} `json:"counts"`
}

// WirelessChannelUtilization describes channel utilization by radio band.
type WirelessChannelUtilization struct {
	Serial  string     `json:"serial"`
	MAC     string     `json:"mac"`
	Network NetworkRef `json:"network"`
	ByBand  []struct {
		Band    string       `json:"band"`
		WiFi    PercentValue `json:"wifi"`
		NonWiFi PercentValue `json:"nonWifi"`
		Total   PercentValue `json:"total"`
	} `json:"byBand"`
}

// PercentValue wraps a percentage field.
type PercentValue struct {
	Percentage float64 `json:"percentage"`
}

// WirelessPacketLoss describes packet loss by wireless device.
type WirelessPacketLoss struct {
	Downstream PacketLossDirection `json:"downstream"`
	Upstream   PacketLossDirection `json:"upstream"`
	Network    NetworkRef          `json:"network"`
	Device     struct {
		Name   string `json:"name"`
		Serial string `json:"serial"`
		MAC    string `json:"mac"`
	} `json:"device"`
}

// PacketLossDirection describes packet loss in one direction.
type PacketLossDirection struct {
	Total          int64   `json:"total"`
	Lost           int64   `json:"lost"`
	LossPercentage float64 `json:"lossPercentage"`
}

// WirelessSSIDStatus describes SSID status by AP.
type WirelessSSIDStatus struct {
	Serial           string     `json:"serial"`
	Name             string     `json:"name"`
	Network          NetworkRef `json:"network"`
	BasicServiceSets []struct {
		BSSID string `json:"bssid"`
		SSID  struct {
			Name       string `json:"name"`
			Number     int64  `json:"number"`
			Enabled    bool   `json:"enabled"`
			Advertised bool   `json:"advertised"`
		} `json:"ssid"`
		Radio struct {
			Band           string  `json:"band"`
			Channel        int64   `json:"channel"`
			ChannelWidth   int64   `json:"channelWidth"`
			Power          float64 `json:"power"`
			IsBroadcasting bool    `json:"isBroadcasting"`
			Index          string  `json:"index"`
		} `json:"radio"`
	} `json:"basicServiceSets"`
}

// VPNStatus describes Auto VPN peer reachability for one network appliance.
type VPNStatus struct {
	NetworkID          string    `json:"networkId"`
	NetworkName        string    `json:"networkName"`
	DeviceSerial       string    `json:"deviceSerial"`
	DeviceStatus       string    `json:"deviceStatus"`
	VPNMode            string    `json:"vpnMode"`
	MerakiVPNPeers     []VPNPeer `json:"merakiVpnPeers"`
	ThirdPartyVPNPeers []VPNPeer `json:"thirdPartyVpnPeers"`
}

// VPNPeer describes Meraki or third-party VPN peer status.
type VPNPeer struct {
	NetworkID    string `json:"networkId"`
	NetworkName  string `json:"networkName"`
	Name         string `json:"name"`
	PublicIP     string `json:"publicIp"`
	Reachability string `json:"reachability"`
	Priority     int64  `json:"priority"`
}

// VPNStats describes VPN traffic and quality summaries for one network.
type VPNStats struct {
	NetworkID      string `json:"networkId"`
	NetworkName    string `json:"networkName"`
	MerakiVPNPeers []struct {
		NetworkID    string `json:"networkId"`
		NetworkName  string `json:"networkName"`
		UsageSummary struct {
			ReceivedInKilobytes FlexibleInt64 `json:"receivedInKilobytes"`
			SentInKilobytes     FlexibleInt64 `json:"sentInKilobytes"`
		} `json:"usageSummary"`
		LatencySummaries []struct {
			SenderUplink   string  `json:"senderUplink"`
			ReceiverUplink string  `json:"receiverUplink"`
			AvgLatencyMS   float64 `json:"avgLatencyMs"`
			MinLatencyMS   float64 `json:"minLatencyMs"`
			MaxLatencyMS   float64 `json:"maxLatencyMs"`
		} `json:"latencySummaries"`
		LossPercentageSummaries []struct {
			SenderUplink      string  `json:"senderUplink"`
			ReceiverUplink    string  `json:"receiverUplink"`
			AvgLossPercentage float64 `json:"avgLossPercentage"`
			MinLossPercentage float64 `json:"minLossPercentage"`
			MaxLossPercentage float64 `json:"maxLossPercentage"`
		} `json:"lossPercentageSummaries"`
		JitterSummaries []struct {
			SenderUplink   string  `json:"senderUplink"`
			ReceiverUplink string  `json:"receiverUplink"`
			AvgJitter      float64 `json:"avgJitter"`
			MinJitter      float64 `json:"minJitter"`
			MaxJitter      float64 `json:"maxJitter"`
		} `json:"jitterSummaries"`
		MOSSummaries []struct {
			SenderUplink   string  `json:"senderUplink"`
			ReceiverUplink string  `json:"receiverUplink"`
			AvgMOS         float64 `json:"avgMos"`
			MinMOS         float64 `json:"minMos"`
			MaxMOS         float64 `json:"maxMos"`
		} `json:"mosSummaries"`
	} `json:"merakiVpnPeers"`
}

// FlexibleInt64 decodes Meraki numeric fields that can arrive as JSON numbers or quoted strings.
type FlexibleInt64 int64

// UnmarshalJSON accepts either a JSON number or a base-10 string.
func (v *FlexibleInt64) UnmarshalJSON(data []byte) error {
	var number int64
	if err := json.Unmarshal(data, &number); err == nil {
		*v = FlexibleInt64(number)
		return nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	parsed, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return err
	}
	*v = FlexibleInt64(parsed)
	return nil
}

// PowerModuleStatus describes power module state by device.
type PowerModuleStatus struct {
	MAC         string     `json:"mac"`
	Name        string     `json:"name"`
	Network     NetworkRef `json:"network"`
	ProductType string     `json:"productType"`
	Serial      string     `json:"serial"`
	Tags        []string   `json:"tags"`
	Slots       []struct {
		Number int64  `json:"number"`
		Serial string `json:"serial"`
		Model  string `json:"model"`
		Status string `json:"status"`
	} `json:"slots"`
}

// TopologyDiscovery describes CDP/LLDP neighbor data by switch port.
type TopologyDiscovery struct {
	Name    string     `json:"name"`
	Serial  string     `json:"serial"`
	MAC     string     `json:"mac"`
	Network NetworkRef `json:"network"`
	Model   string     `json:"model"`
	Ports   []struct {
		PortID string      `json:"portId"`
		CDP    []NameValue `json:"cdp"`
		LLDP   []NameValue `json:"lldp"`
	} `json:"ports"`
}

// NameValue is a Meraki topology key/value item.
type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// TransceiverReadings describes appliance or switch transceiver sensor windows.
type TransceiverReadings struct {
	Serial  string     `json:"serial"`
	Network NetworkRef `json:"network"`
	Ports   []struct {
		PortID        string               `json:"portId"`
		InterfaceName string               `json:"interfaceName"`
		Readings      []TransceiverReading `json:"readings"`
	} `json:"ports"`
}

// TransceiverReading is one timestamped DOM snapshot.
type TransceiverReading struct {
	StartTS      string `json:"startTs"`
	EndTS        string `json:"endTs"`
	SFPProductID string `json:"sfpProductId"`
	ByMetric     struct {
		Power struct {
			Transmit SummaryValue `json:"transmit"`
			Receive  SummaryValue `json:"receive"`
		} `json:"power"`
		Temperature struct {
			Celsius SummaryValue `json:"celsius"`
		} `json:"temperature"`
		SupplyVoltage struct {
			Level SummaryValue `json:"level"`
		} `json:"supplyVoltage"`
		LaserBiasCurrent struct {
			Draw SummaryValue `json:"draw"`
		} `json:"laserBiasCurrent"`
	} `json:"byMetric"`
}

// SummaryValue is a min/max/median metric value.
type SummaryValue struct {
	Minimum *float64 `json:"minimum"`
	Maximum *float64 `json:"maximum"`
	Median  *float64 `json:"median"`
}

// MedianValue returns the reported median while preserving an explicit zero.
func (v SummaryValue) MedianValue() (float64, bool) {
	if v.Median == nil {
		return 0, false
	}
	return *v.Median, true
}

// AppliancePerformance describes per-device MX performance score.
type AppliancePerformance struct {
	PerfScore float64 `json:"perfScore"`
}
