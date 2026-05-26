// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package catalystcenter // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/catalystcenter"

// Device describes a Catalyst Center network-device inventory item.
type Device struct {
	ID                        string `json:"id"`
	InstanceUUID              string `json:"instanceUuid"`
	Hostname                  string `json:"hostname"`
	ManagementIPAddress       string `json:"managementIpAddress"`
	SerialNumber              string `json:"serialNumber"`
	MacAddress                string `json:"macAddress"`
	Family                    string `json:"family"`
	Type                      string `json:"type"`
	Series                    string `json:"series"`
	PlatformID                string `json:"platformId"`
	Role                      string `json:"role"`
	SoftwareType              string `json:"softwareType"`
	SoftwareVersion           string `json:"softwareVersion"`
	CollectionStatus          string `json:"collectionStatus"`
	ReachabilityStatus        string `json:"reachabilityStatus"`
	ReachabilityFailureReason string `json:"reachabilityFailureReason"`
	ErrorCode                 string `json:"errorCode"`
	ErrorDescription          string `json:"errorDescription"`
	Location                  string `json:"location"`
	LocationName              string `json:"locationName"`
	UpTime                    string `json:"upTime"`
	UptimeSeconds             int64  `json:"uptimeSeconds"`
	InterfaceCount            string `json:"interfaceCount"`
	LastUpdated               string `json:"lastUpdated"`
	LastUpdateTime            int64  `json:"lastUpdateTime"`
	InventoryStatusDetail     string `json:"inventoryStatusDetail"`
	DeviceSupportLevel        string `json:"deviceSupportLevel"`
	ManagementState           string `json:"managementState"`
	PendingSyncRequestsCount  string `json:"pendingSyncRequestsCount"`
	ReasonsForDeviceResync    string `json:"reasonsForDeviceResync"`
	DNSResolvedManagementAddr string `json:"dnsResolvedManagementAddress"`
	AssociatedWlcIP           string `json:"associatedWlcIp"`
	APManagerInterfaceIP      string `json:"apManagerInterfaceIp"`
	APEthernetMacAddress      string `json:"apEthernetMacAddress"`
}

// Interface describes a Catalyst Center network-device interface item.
type Interface struct {
	ID                          string `json:"id"`
	InstanceUUID                string `json:"instanceUuid"`
	DeviceID                    string `json:"deviceId"`
	Name                        string `json:"name"`
	Description                 string `json:"description"`
	Status                      string `json:"status"`
	AdminStatus                 string `json:"adminStatus"`
	InterfaceType               string `json:"interfaceType"`
	PortName                    string `json:"portName"`
	PortType                    string `json:"portType"`
	PortMode                    string `json:"portMode"`
	Speed                       string `json:"speed"`
	Duplex                      string `json:"duplex"`
	MacAddress                  string `json:"macAddress"`
	IPv4Address                 string `json:"ipv4Address"`
	IPv4Mask                    string `json:"ipv4Mask"`
	VLANID                      string `json:"vlanId"`
	VoiceVLAN                   string `json:"voiceVlan"`
	NativeVLANID                string `json:"nativeVlanId"`
	MTU                         string `json:"mtu"`
	IfIndex                     string `json:"ifIndex"`
	PID                         string `json:"pid"`
	SerialNo                    string `json:"serialNo"`
	Series                      string `json:"series"`
	MediaType                   string `json:"mediaType"`
	LastUpdated                 string `json:"lastUpdated"`
	LastIncomingPacketTime      any    `json:"lastIncomingPacketTime"`
	LastOutgoingPacketTime      any    `json:"lastOutgoingPacketTime"`
	MappedPhysicalInterfaceID   string `json:"mappedPhysicalInterfaceId"`
	MappedPhysicalInterfaceName string `json:"mappedPhysicalInterfaceName"`
}

// NetworkHealth describes the overall network-health response.
type NetworkHealth struct {
	Version                    string                      `json:"version"`
	Response                   []NetworkHealthEntry        `json:"response"`
	MeasuredBy                 string                      `json:"measuredBy"`
	LatestMeasuredByEntity     string                      `json:"latestMeasuredByEntity"`
	LatestHealthScore          int64                       `json:"latestHealthScore"`
	MonitoredDevices           int64                       `json:"monitoredDevices"`
	MonitoredHealthyDevices    int64                       `json:"monitoredHealthyDevices"`
	MonitoredUnHealthyDevices  int64                       `json:"monitoredUnHealthyDevices"`
	UnMonitoredDevices         int64                       `json:"unMonitoredDevices"`
	NoHealthDevices            int64                       `json:"noHealthDevices"`
	TotalDevices               int64                       `json:"totalDevices"`
	MonitoredPoorHealthDevices int64                       `json:"monitoredPoorHealthDevices"`
	MonitoredFairHealthDevices int64                       `json:"monitoredFairHealthDevices"`
	HealthContributingDevices  int64                       `json:"healthContributingDevices"`
	HealthDistribution         []NetworkHealthDistribution `json:"healthDistribution"`
	HealthDistirubution        []NetworkHealthDistribution `json:"healthDistirubution"`
}

// NetworkHealthEntry describes network health for a device category or entity.
type NetworkHealthEntry struct {
	Time                 string `json:"time"`
	HealthScore          int64  `json:"healthScore"`
	TotalCount           int64  `json:"totalCount"`
	GoodCount            int64  `json:"goodCount"`
	NoHealthCount        int64  `json:"noHealthCount"`
	UnmonCount           int64  `json:"unmonCount"`
	FairCount            int64  `json:"fairCount"`
	BadCount             int64  `json:"badCount"`
	MaintenanceModeCount int64  `json:"maintenanceModeCount"`
	Entity               string `json:"entity"`
	TimeInMillis         int64  `json:"timeinMillis"`
}

// NetworkHealthDistribution describes a summary row in the overall network-health response.
type NetworkHealthDistribution struct {
	Category              string      `json:"category"`
	TotalCount            float64     `json:"totalCount"`
	HealthScore           float64     `json:"healthScore"`
	GoodPercentage        float64     `json:"goodPercentage"`
	BadPercentage         float64     `json:"badPercentage"`
	FairPercentage        float64     `json:"fairPercentage"`
	NoHealthPercentage    float64     `json:"noHealthPercentage"`
	UnmonPercentage       float64     `json:"unmonPercentage"`
	GoodCount             float64     `json:"goodCount"`
	BadCount              float64     `json:"badCount"`
	FairCount             float64     `json:"fairCount"`
	NoHealthCount         float64     `json:"noHealthCount"`
	UnmonCount            float64     `json:"unmonCount"`
	ThirdPartyDeviceCount float64     `json:"thirdPartyDeviceCount"`
	KPIMetrics            []KPIMetric `json:"kpiMetrics"`
}

// KPIMetric is a key/value metric embedded in Catalyst Center health responses.
type KPIMetric struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ClientHealth describes the overall client-health response.
type ClientHealth struct {
	Version  string             `json:"version"`
	Response []ClientHealthSite `json:"response"`
}

// ClientHealthSite describes client health for a site.
type ClientHealthSite struct {
	SiteID      string              `json:"siteId"`
	ScoreDetail []ClientHealthScore `json:"scoreDetail"`
}

// ClientHealthScore describes client health for a score category.
type ClientHealthScore struct {
	ScoreCategory                  ClientScoreCategory `json:"scoreCategory"`
	ScoreValue                     float64             `json:"scoreValue"`
	ClientCount                    int64               `json:"clientCount"`
	ClientUniqueCount              int64               `json:"clientUniqueCount"`
	MaintenanceAffectedClientCount int64               `json:"maintenanceAffectedClientCount"`
	RandomMacCount                 int64               `json:"randomMacCount"`
	DUIDCount                      int64               `json:"duidCount"`
	StartTime                      int64               `json:"starttime"`
	EndTime                        int64               `json:"endtime"`
	ConnectedToUDNCount            int64               `json:"connectedToUdnCount"`
	UnconnectedToUDNCount          int64               `json:"unconnectedToUdnCount"`
	ScoreList                      []ClientHealthScore `json:"scoreList"`
}

// ClientScoreCategory describes the client health category label.
type ClientScoreCategory struct {
	ScoreCategory string `json:"scoreCategory"`
	Value         string `json:"value"`
}

// SiteHealthSummary describes one site-health summary row.
type SiteHealthSummary struct {
	ID                                 string  `json:"id"`
	SiteID                             string  `json:"siteId"`
	SiteName                           string  `json:"siteName"`
	SiteHierarchy                      string  `json:"siteHierarchy"`
	SiteHierarchyID                    string  `json:"siteHierarchyId"`
	SiteType                           string  `json:"siteType"`
	NetworkDeviceGoodHealthPercentage  float64 `json:"networkDeviceGoodHealthPercentage"`
	NetworkDeviceGoodHealthCount       int64   `json:"networkDeviceGoodHealthCount"`
	NetworkDeviceCount                 int64   `json:"networkDeviceCount"`
	ClientGoodHealthPercentage         float64 `json:"clientGoodHealthPercentage"`
	ClientGoodHealthCount              int64   `json:"clientGoodHealthCount"`
	ClientCount                        int64   `json:"clientCount"`
	WiredClientGoodHealthPercentage    float64 `json:"wiredClientGoodHealthPercentage"`
	WirelessClientGoodHealthPercentage float64 `json:"wirelessClientGoodHealthPercentage"`
	WiredClientCount                   int64   `json:"wiredClientCount"`
	WirelessClientCount                int64   `json:"wirelessClientCount"`
	AccessDeviceCount                  int64   `json:"accessDeviceCount"`
	AccessDeviceGoodHealthCount        int64   `json:"accessDeviceGoodHealthCount"`
	CoreDeviceCount                    int64   `json:"coreDeviceCount"`
	CoreDeviceGoodHealthCount          int64   `json:"coreDeviceGoodHealthCount"`
	DistributionDeviceCount            int64   `json:"distributionDeviceCount"`
	DistributionDeviceGoodHealthCount  int64   `json:"distributionDeviceGoodHealthCount"`
	RouterDeviceCount                  int64   `json:"routerDeviceCount"`
	RouterDeviceGoodHealthCount        int64   `json:"routerDeviceGoodHealthCount"`
	WirelessDeviceCount                int64   `json:"wirelessDeviceCount"`
	WirelessDeviceGoodHealthCount      int64   `json:"wirelessDeviceGoodHealthCount"`
	APDeviceCount                      int64   `json:"apDeviceCount"`
	APDeviceGoodHealthCount            int64   `json:"apDeviceGoodHealthCount"`
	WLCDeviceCount                     int64   `json:"wlcDeviceCount"`
	WLCDeviceGoodHealthCount           int64   `json:"wlcDeviceGoodHealthCount"`
	SwitchDeviceCount                  int64   `json:"switchDeviceCount"`
	SwitchDeviceGoodHealthCount        int64   `json:"switchDeviceGoodHealthCount"`
	P1IssueCount                       int64   `json:"p1IssueCount"`
	P2IssueCount                       int64   `json:"p2IssueCount"`
	P3IssueCount                       int64   `json:"p3IssueCount"`
	P4IssueCount                       int64   `json:"p4IssueCount"`
	IssueCount                         int64   `json:"issueCount"`
}

// Topology describes a physical topology response.
type Topology struct {
	Nodes []TopologyNode `json:"nodes"`
	Links []TopologyLink `json:"links"`
}

// TopologyNode describes a topology node.
type TopologyNode struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	NodeType string `json:"nodeType"`
	Family   string `json:"family"`
	Role     string `json:"role"`
	Platform string `json:"platformId"`
}

// TopologyLink describes a topology link.
type TopologyLink struct {
	ID            string `json:"id"`
	Source        string `json:"source"`
	Target        string `json:"target"`
	LinkStatus    string `json:"linkStatus"`
	StartPortName string `json:"startPortName"`
	EndPortName   string `json:"endPortName"`
}

// Issue describes a Catalyst Center assurance issue.
type Issue struct {
	IssueID                string `json:"issueId"`
	Name                   string `json:"name"`
	Description            string `json:"description"`
	Summary                string `json:"summary"`
	Priority               string `json:"priority"`
	Severity               string `json:"severity"`
	DeviceType             string `json:"deviceType"`
	Category               string `json:"category"`
	EntityType             string `json:"entityType"`
	EntityID               string `json:"entityId"`
	FirstOccurredTime      int64  `json:"firstOccurredTime"`
	MostRecentOccurredTime int64  `json:"mostRecentOccurredTime"`
	Status                 string `json:"status"`
	IsGlobal               bool   `json:"isGlobal"`
	SiteID                 string `json:"siteId"`
	SiteName               string `json:"siteName"`
	SiteHierarchy          string `json:"siteHierarchy"`
	SiteHierarchyID        string `json:"siteHierarchyId"`
}

// Object is a generic Catalyst Center object used for detail responses.
type Object map[string]any
