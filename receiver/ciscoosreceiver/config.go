// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/xconfmap"
	"go.opentelemetry.io/collector/scraper/scraperhelper"
	"go.uber.org/multierr"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

// DeviceConfig represents configuration for a single Cisco device in the devices list.
type DeviceConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Name string `mapstructure:"name"`
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`

	Auth connection.AuthConfig `mapstructure:"auth"`
}

// MetricConfig controls whether a named metric or metric-name glob is forwarded by the Cisco OS receiver.
type MetricConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled bool `mapstructure:"enabled"`
}

// MerakiAuthConfig represents Meraki Dashboard API authentication settings.
type MerakiAuthConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	APIKey configopaque.String `mapstructure:"api_key"`
}

// MerakiOrganizationConfig represents an organization-level Meraki polling target.
type MerakiOrganizationConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	OrganizationID string   `mapstructure:"organization_id"`
	NetworkIDs     []string `mapstructure:"network_ids"`
	Serials        []string `mapstructure:"serials"`
	ProductTypes   []string `mapstructure:"product_types"`
	Tags           []string `mapstructure:"tags"`
	TagsFilterType string   `mapstructure:"tags_filter_type"`
}

// MerakiDeviceConfig represents a serial-scoped Meraki polling target.
type MerakiDeviceConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	OrganizationID string `mapstructure:"organization_id"`
	Serial         string `mapstructure:"serial"`
}

// MerakiConfig defines Meraki Dashboard API polling settings.
type MerakiConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Auth          MerakiAuthConfig           `mapstructure:"auth"`
	BaseURL       string                     `mapstructure:"base_url"`
	UserAgent     string                     `mapstructure:"user_agent"`
	MaxRetries    int                        `mapstructure:"max_retries"`
	Organizations []MerakiOrganizationConfig `mapstructure:"organizations"`
	Devices       []MerakiDeviceConfig       `mapstructure:"devices"`
}

func defaultMerakiConfig() MerakiConfig {
	return MerakiConfig{
		BaseURL:    "https://api.meraki.com/api/v1",
		UserAgent:  "opentelemetry-collector-contrib-ciscoosreceiver",
		MaxRetries: 3,
	}
}

func (cfg MerakiConfig) hasTargets() bool {
	return len(cfg.Organizations) > 0 || len(cfg.Devices) > 0
}

// IntersightAuthConfig represents Cisco Intersight API key authentication.
type IntersightAuthConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	KeyID   string              `mapstructure:"key_id"`
	KeyFile string              `mapstructure:"key_file"`
	KeyPEM  configopaque.String `mapstructure:"key_pem"`
}

// IntersightTargetFilters limits Intersight collection to known resources.
type IntersightTargetFilters struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Serials []string `mapstructure:"serials"`
	MoIDs   []string `mapstructure:"moids"`
}

// IntersightGroupConfig controls a curated Intersight collection group.
type IntersightGroupConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled    bool `mapstructure:"enabled"`
	MaxResults int  `mapstructure:"max_results"`
}

// IntersightConfig defines native Cisco Intersight API polling settings.
type IntersightConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled            bool                    `mapstructure:"enabled"`
	Auth               IntersightAuthConfig    `mapstructure:"auth"`
	Endpoint           string                  `mapstructure:"endpoint"`
	UserAgent          string                  `mapstructure:"user_agent"`
	PageSize           int                     `mapstructure:"page_size"`
	MaxRetries         int                     `mapstructure:"max_retries"`
	InsecureSkipVerify bool                    `mapstructure:"insecure_skip_verify"`
	EventLookback      time.Duration           `mapstructure:"event_lookback"`
	TelemetryLookback  time.Duration           `mapstructure:"telemetry_lookback"`
	Targets            IntersightTargetFilters `mapstructure:"targets"`
	Inventory          IntersightGroupConfig   `mapstructure:"inventory"`
	Events             IntersightGroupConfig   `mapstructure:"events"`
	Audit              IntersightGroupConfig   `mapstructure:"audit"`
	Telemetry          IntersightGroupConfig   `mapstructure:"telemetry"`
	Equipment          IntersightGroupConfig   `mapstructure:"equipment"`
	Network            IntersightGroupConfig   `mapstructure:"network"`
	Firmware           IntersightGroupConfig   `mapstructure:"firmware"`
	Storage            IntersightGroupConfig   `mapstructure:"storage"`
	HyperFlex          IntersightGroupConfig   `mapstructure:"hyperflex"`
	Kubernetes         IntersightGroupConfig   `mapstructure:"kubernetes"`
	Virtualization     IntersightGroupConfig   `mapstructure:"virtualization"`
}

func defaultIntersightGroupConfig(maxResults int) IntersightGroupConfig {
	return IntersightGroupConfig{
		Enabled:    true,
		MaxResults: maxResults,
	}
}

func defaultIntersightConfig() IntersightConfig {
	return IntersightConfig{
		Endpoint:          "https://intersight.com",
		UserAgent:         "opentelemetry-collector-contrib-ciscoosreceiver",
		PageSize:          100,
		MaxRetries:        3,
		EventLookback:     24 * time.Hour,
		TelemetryLookback: 30 * time.Minute,
		Inventory:         defaultIntersightGroupConfig(1000),
		Events:            defaultIntersightGroupConfig(500),
		Audit:             defaultIntersightGroupConfig(500),
		Telemetry:         defaultIntersightGroupConfig(500),
		Equipment:         defaultIntersightGroupConfig(1000),
		Network:           defaultIntersightGroupConfig(1000),
		Firmware:          defaultIntersightGroupConfig(1000),
		Storage:           defaultIntersightGroupConfig(1000),
		HyperFlex:         defaultIntersightGroupConfig(1000),
		Kubernetes:        defaultIntersightGroupConfig(1000),
		Virtualization:    defaultIntersightGroupConfig(1000),
	}
}

func (cfg IntersightConfig) hasTarget() bool {
	return cfg.Enabled || cfg.Auth.KeyID != "" || cfg.Auth.KeyFile != "" || cfg.Auth.KeyPEM != ""
}

// CatalystCenterAuthConfig represents Catalyst Center API token authentication settings.
type CatalystCenterAuthConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Mode           string              `mapstructure:"mode"`
	Username       string              `mapstructure:"username"`
	Password       configopaque.String `mapstructure:"password"`
	AESCredentials configopaque.String `mapstructure:"aes_credentials"`
}

// CatalystCenterDeviceDetailTarget identifies a device-detail lookup.
type CatalystCenterDeviceDetailTarget struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Identifier string `mapstructure:"identifier"`
	SearchBy   string `mapstructure:"search_by"`
}

// CatalystCenterTargetFilters limits Catalyst Center detail collection to known resources.
type CatalystCenterTargetFilters struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	DeviceDetails []CatalystCenterDeviceDetailTarget `mapstructure:"device_details"`
	ClientMACs    []string                           `mapstructure:"client_macs"`
}

// CatalystCenterGroupConfig controls a curated Catalyst Center collection group.
type CatalystCenterGroupConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled    bool `mapstructure:"enabled"`
	MaxResults int  `mapstructure:"max_results"`
}

// CatalystCenterConfig defines native Catalyst Center API polling settings.
type CatalystCenterConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled            bool                        `mapstructure:"enabled"`
	Endpoint           string                      `mapstructure:"endpoint"`
	Auth               CatalystCenterAuthConfig    `mapstructure:"auth"`
	UserAgent          string                      `mapstructure:"user_agent"`
	PageSize           int                         `mapstructure:"page_size"`
	MaxRetries         int                         `mapstructure:"max_retries"`
	InsecureSkipVerify bool                        `mapstructure:"insecure_skip_verify"`
	Lookback           time.Duration               `mapstructure:"lookback"`
	Targets            CatalystCenterTargetFilters `mapstructure:"targets"`
	Inventory          CatalystCenterGroupConfig   `mapstructure:"inventory"`
	Interfaces         CatalystCenterGroupConfig   `mapstructure:"interfaces"`
	Health             CatalystCenterGroupConfig   `mapstructure:"health"`
	Topology           CatalystCenterGroupConfig   `mapstructure:"topology"`
	Issues             CatalystCenterGroupConfig   `mapstructure:"issues"`
	Details            CatalystCenterGroupConfig   `mapstructure:"details"`
}

func defaultCatalystCenterGroupConfig(maxResults int) CatalystCenterGroupConfig {
	return CatalystCenterGroupConfig{
		Enabled:    true,
		MaxResults: maxResults,
	}
}

func defaultCatalystCenterConfig() CatalystCenterConfig {
	return CatalystCenterConfig{
		UserAgent:  "opentelemetry-collector-contrib-ciscoosreceiver",
		PageSize:   500,
		MaxRetries: 3,
		Lookback:   24 * time.Hour,
		Inventory:  defaultCatalystCenterGroupConfig(5000),
		Interfaces: defaultCatalystCenterGroupConfig(10000),
		Health:     defaultCatalystCenterGroupConfig(1000),
		Topology:   defaultCatalystCenterGroupConfig(10000),
		Issues:     defaultCatalystCenterGroupConfig(1000),
		Details:    defaultCatalystCenterGroupConfig(1000),
	}
}

func (cfg CatalystCenterConfig) hasTarget() bool {
	return cfg.Enabled
}

// SDWANAuthConfig represents Catalyst SD-WAN Manager authentication settings.
type SDWANAuthConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Mode        string              `mapstructure:"mode"`
	Username    string              `mapstructure:"username"`
	Password    configopaque.String `mapstructure:"password"`
	BearerToken configopaque.String `mapstructure:"bearer_token"`
	JSessionID  configopaque.String `mapstructure:"jsession_id"`
	XSRFToken   configopaque.String `mapstructure:"xsrf_token"`
}

// SDWANTargetFilters limits SD-WAN collection to known sites, devices, circuits, applications, and services.
type SDWANTargetFilters struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	SiteIDs             []string `mapstructure:"site_ids"`
	SystemIPs           []string `mapstructure:"system_ips"`
	UUIDs               []string `mapstructure:"uuids"`
	Serials             []string `mapstructure:"serials"`
	DeviceTypes         []string `mapstructure:"device_types"`
	Personalities       []string `mapstructure:"personalities"`
	Colors              []string `mapstructure:"colors"`
	InterfaceNames      []string `mapstructure:"interface_names"`
	VPNIDs              []string `mapstructure:"vpn_ids"`
	Applications        []string `mapstructure:"applications"`
	ApplicationFamilies []string `mapstructure:"application_families"`
	CloudProviders      []string `mapstructure:"cloud_providers"`
	ServiceTypes        []string `mapstructure:"service_types"`
}

// SDWANGroupConfig controls a curated Catalyst SD-WAN collection group.
type SDWANGroupConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled    bool `mapstructure:"enabled"`
	MaxResults int  `mapstructure:"max_results"`
}

// SDWANConfig defines native Catalyst SD-WAN Manager API polling settings.
type SDWANConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled             bool               `mapstructure:"enabled"`
	Endpoint            string             `mapstructure:"endpoint"`
	Auth                SDWANAuthConfig    `mapstructure:"auth"`
	UserAgent           string             `mapstructure:"user_agent"`
	PageSize            int                `mapstructure:"page_size"`
	MaxRetries          int                `mapstructure:"max_retries"`
	InsecureSkipVerify  bool               `mapstructure:"insecure_skip_verify"`
	EventLookback       time.Duration      `mapstructure:"event_lookback"`
	Targets             SDWANTargetFilters `mapstructure:"targets"`
	Manager             SDWANGroupConfig   `mapstructure:"manager"`
	Inventory           SDWANGroupConfig   `mapstructure:"inventory"`
	ControlPlane        SDWANGroupConfig   `mapstructure:"control_plane"`
	BFD                 SDWANGroupConfig   `mapstructure:"bfd"`
	AppRoute            SDWANGroupConfig   `mapstructure:"app_route"`
	Interfaces          SDWANGroupConfig   `mapstructure:"interfaces"`
	Alarms              SDWANGroupConfig   `mapstructure:"alarms"`
	Events              SDWANGroupConfig   `mapstructure:"events"`
	Audit               SDWANGroupConfig   `mapstructure:"audit"`
	RealtimeDetails     SDWANGroupConfig   `mapstructure:"realtime_details"`
	Tunnels             SDWANGroupConfig   `mapstructure:"tunnels"`
	Flows               SDWANGroupConfig   `mapstructure:"flows"`
	PolicyQoS           SDWANGroupConfig   `mapstructure:"policy_qos"`
	Security            SDWANGroupConfig   `mapstructure:"security"`
	AppQoE              SDWANGroupConfig   `mapstructure:"appqoe"`
	CloudOnRamp         SDWANGroupConfig   `mapstructure:"cloud_onramp"`
	NWPI                SDWANGroupConfig   `mapstructure:"nwpi"`
	Underlay            SDWANGroupConfig   `mapstructure:"underlay"`
	Cellular            SDWANGroupConfig   `mapstructure:"cellular"`
	HardwareEnergy      SDWANGroupConfig   `mapstructure:"hardware_energy"`
	RoutingServices     SDWANGroupConfig   `mapstructure:"routing_services"`
	BranchServices      SDWANGroupConfig   `mapstructure:"branch_services"`
	LifecycleCompliance SDWANGroupConfig   `mapstructure:"lifecycle_compliance"`
	ThousandEyes        SDWANGroupConfig   `mapstructure:"thousandeyes"`
	ManagementSecurity  SDWANGroupConfig   `mapstructure:"management_security"`
}

func defaultSDWANGroupConfig(enabled bool, maxResults int) SDWANGroupConfig {
	return SDWANGroupConfig{
		Enabled:    enabled,
		MaxResults: maxResults,
	}
}

func defaultSDWANConfig() SDWANConfig {
	return SDWANConfig{
		UserAgent:           "opentelemetry-collector-contrib-ciscoosreceiver",
		PageSize:            500,
		MaxRetries:          3,
		EventLookback:       24 * time.Hour,
		Manager:             defaultSDWANGroupConfig(true, 1000),
		Inventory:           defaultSDWANGroupConfig(true, 5000),
		ControlPlane:        defaultSDWANGroupConfig(true, 10000),
		BFD:                 defaultSDWANGroupConfig(true, 10000),
		AppRoute:            defaultSDWANGroupConfig(true, 10000),
		Interfaces:          defaultSDWANGroupConfig(true, 10000),
		Alarms:              defaultSDWANGroupConfig(true, 1000),
		Events:              defaultSDWANGroupConfig(true, 1000),
		Audit:               defaultSDWANGroupConfig(true, 1000),
		RealtimeDetails:     defaultSDWANGroupConfig(false, 1000),
		Tunnels:             defaultSDWANGroupConfig(false, 10000),
		Flows:               defaultSDWANGroupConfig(false, 10000),
		PolicyQoS:           defaultSDWANGroupConfig(false, 10000),
		Security:            defaultSDWANGroupConfig(false, 10000),
		AppQoE:              defaultSDWANGroupConfig(false, 10000),
		CloudOnRamp:         defaultSDWANGroupConfig(false, 10000),
		NWPI:                defaultSDWANGroupConfig(false, 10000),
		Underlay:            defaultSDWANGroupConfig(false, 10000),
		Cellular:            defaultSDWANGroupConfig(false, 10000),
		HardwareEnergy:      defaultSDWANGroupConfig(false, 10000),
		RoutingServices:     defaultSDWANGroupConfig(false, 10000),
		BranchServices:      defaultSDWANGroupConfig(false, 10000),
		LifecycleCompliance: defaultSDWANGroupConfig(false, 10000),
		ThousandEyes:        defaultSDWANGroupConfig(false, 1000),
		ManagementSecurity:  defaultSDWANGroupConfig(false, 1000),
	}
}

func (cfg SDWANConfig) hasTarget() bool {
	return cfg.Enabled || cfg.Endpoint != "" || cfg.Auth.BearerToken != "" || cfg.Auth.Username != "" || cfg.Auth.Password != "" || cfg.Auth.JSessionID != ""
}

// ControllerAuthConfig represents username/password or API-key authentication for Nexus controllers.
type ControllerAuthConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Mode     string              `mapstructure:"mode"`
	Username string              `mapstructure:"username"`
	Password configopaque.String `mapstructure:"password"`
	APIKey   configopaque.String `mapstructure:"api_key"`
	Domain   string              `mapstructure:"domain"`
}

// NexusDashboardTargetFilters limits Nexus Dashboard collection to relevant fabrics, switches, and services.
type NexusDashboardTargetFilters struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Sites          []string `mapstructure:"sites"`
	Fabrics        []string `mapstructure:"fabrics"`
	SwitchSerials  []string `mapstructure:"switch_serials"`
	SwitchIDs      []string `mapstructure:"switch_ids"`
	InterfaceNames []string `mapstructure:"interface_names"`
	ServiceNames   []string `mapstructure:"service_names"`
}

// ACIControllerConfig represents a single APIC controller endpoint.
type ACIControllerConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Endpoint string `mapstructure:"endpoint"`
	Name     string `mapstructure:"name"`
}

// ACITargetFilters limits APIC collection to relevant nodes, tenants, and objects.
type ACITargetFilters struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Sites          []string `mapstructure:"sites"`
	Fabrics        []string `mapstructure:"fabrics"`
	NodeIDs        []string `mapstructure:"node_ids"`
	Serials        []string `mapstructure:"serials"`
	Tenants        []string `mapstructure:"tenants"`
	VRFs           []string `mapstructure:"vrfs"`
	BridgeDomains  []string `mapstructure:"bridge_domains"`
	EPGs           []string `mapstructure:"epgs"`
	InterfaceNames []string `mapstructure:"interface_names"`
}

// NexusControllerGroupConfig controls a curated controller collection group.
type NexusControllerGroupConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled    bool `mapstructure:"enabled"`
	MaxResults int  `mapstructure:"max_results"`
}

// NexusDashboardConfig defines Nexus Dashboard, NDFC, Insights, NDO, OneManage, and Data Broker polling settings.
type NexusDashboardConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled            bool                        `mapstructure:"enabled"`
	Endpoint           string                      `mapstructure:"endpoint"`
	Auth               ControllerAuthConfig        `mapstructure:"auth"`
	UserAgent          string                      `mapstructure:"user_agent"`
	PageSize           int                         `mapstructure:"page_size"`
	MaxRetries         int                         `mapstructure:"max_retries"`
	InsecureSkipVerify bool                        `mapstructure:"insecure_skip_verify"`
	EventLookback      time.Duration               `mapstructure:"event_lookback"`
	Targets            NexusDashboardTargetFilters `mapstructure:"targets"`
	Platform           NexusControllerGroupConfig  `mapstructure:"platform"`
	NDFC               NexusControllerGroupConfig  `mapstructure:"ndfc"`
	Insights           NexusControllerGroupConfig  `mapstructure:"insights"`
	Orchestrator       NexusControllerGroupConfig  `mapstructure:"orchestrator"`
	DataBroker         NexusControllerGroupConfig  `mapstructure:"data_broker"`
	Performance        NexusControllerGroupConfig  `mapstructure:"performance"`
}

// ACIConfig defines APIC API polling settings.
type ACIConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled            bool                       `mapstructure:"enabled"`
	Controllers        []ACIControllerConfig      `mapstructure:"controllers"`
	Auth               ControllerAuthConfig       `mapstructure:"auth"`
	UserAgent          string                     `mapstructure:"user_agent"`
	PageSize           int                        `mapstructure:"page_size"`
	MaxRetries         int                        `mapstructure:"max_retries"`
	InsecureSkipVerify bool                       `mapstructure:"insecure_skip_verify"`
	EventLookback      time.Duration              `mapstructure:"event_lookback"`
	Targets            ACITargetFilters           `mapstructure:"targets"`
	Fabric             NexusControllerGroupConfig `mapstructure:"fabric"`
	ControllerHealth   NexusControllerGroupConfig `mapstructure:"controller_health"`
	Nodes              NexusControllerGroupConfig `mapstructure:"nodes"`
	Faults             NexusControllerGroupConfig `mapstructure:"faults"`
	Audit              NexusControllerGroupConfig `mapstructure:"audit"`
	Events             NexusControllerGroupConfig `mapstructure:"events"`
	Stats              NexusControllerGroupConfig `mapstructure:"stats"`
	Endpoints          NexusControllerGroupConfig `mapstructure:"endpoints"`
	Tenants            NexusControllerGroupConfig `mapstructure:"tenants"`
	Topology           NexusControllerGroupConfig `mapstructure:"topology"`
}

// FMCControllerConfig represents a single Secure Firewall Management Center endpoint.
type FMCControllerConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Endpoint   string `mapstructure:"endpoint"`
	Name       string `mapstructure:"name"`
	DomainUUID string `mapstructure:"domain_uuid"`
}

// FMCTargetFilters limits FMC collection to relevant managed firewalls, policies, and interfaces.
type FMCTargetFilters struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	DeviceIDs      []string `mapstructure:"device_ids"`
	Serials        []string `mapstructure:"serials"`
	Names          []string `mapstructure:"names"`
	ManagementIPs  []string `mapstructure:"management_ips"`
	PolicyIDs      []string `mapstructure:"policy_ids"`
	PolicyNames    []string `mapstructure:"policy_names"`
	InterfaceNames []string `mapstructure:"interface_names"`
}

// FMCGroupConfig controls a curated FMC collection group.
type FMCGroupConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled    bool `mapstructure:"enabled"`
	MaxResults int  `mapstructure:"max_results"`
}

// FMCEStreamerTLSConfig contains TLS settings for an eStreamer mutual-TLS client.
type FMCEStreamerTLSConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	CertFile           string `mapstructure:"cert_file"`
	KeyFile            string `mapstructure:"key_file"`
	CAFile             string `mapstructure:"ca_file"`
	ServerName         string `mapstructure:"server_name"`
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`
}

// FMCEStreamerTargetConfig represents a single eStreamer endpoint.
type FMCEStreamerTargetConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Endpoint string `mapstructure:"endpoint"`
	Name     string `mapstructure:"name"`
}

// FMCEStreamerConfig controls high-fidelity Secure Firewall event streaming.
type FMCEStreamerConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled           bool                       `mapstructure:"enabled"`
	Targets           []FMCEStreamerTargetConfig `mapstructure:"targets"`
	TLS               FMCEStreamerTLSConfig      `mapstructure:"tls"`
	EventTypes        []string                   `mapstructure:"event_types"`
	Lookback          time.Duration              `mapstructure:"lookback"`
	ReconnectInterval time.Duration              `mapstructure:"reconnect_interval"`
	MaxMessageBytes   int                        `mapstructure:"max_message_bytes"`
}

const maxFMCEStreamerMessageBytes = 16 * 1024 * 1024

// FMCConfig defines Secure Firewall Management Center REST and eStreamer settings.
type FMCConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled            bool                  `mapstructure:"enabled"`
	Controllers        []FMCControllerConfig `mapstructure:"controllers"`
	Auth               ControllerAuthConfig  `mapstructure:"auth"`
	UserAgent          string                `mapstructure:"user_agent"`
	PageSize           int                   `mapstructure:"page_size"`
	MaxRetries         int                   `mapstructure:"max_retries"`
	InsecureSkipVerify bool                  `mapstructure:"insecure_skip_verify"`
	EventLookback      time.Duration         `mapstructure:"event_lookback"`
	Targets            FMCTargetFilters      `mapstructure:"targets"`
	Manager            FMCGroupConfig        `mapstructure:"manager"`
	Inventory          FMCGroupConfig        `mapstructure:"inventory"`
	Interfaces         FMCGroupConfig        `mapstructure:"interfaces"`
	Health             FMCGroupConfig        `mapstructure:"health"`
	VPN                FMCGroupConfig        `mapstructure:"vpn"`
	HA                 FMCGroupConfig        `mapstructure:"ha"`
	Policy             FMCGroupConfig        `mapstructure:"policy"`
	Deployments        FMCGroupConfig        `mapstructure:"deployments"`
	Audit              FMCGroupConfig        `mapstructure:"audit"`
	EStreamer          FMCEStreamerConfig    `mapstructure:"estreamer"`
}

func defaultNexusControllerGroupConfig(maxResults int) NexusControllerGroupConfig {
	return NexusControllerGroupConfig{
		Enabled:    true,
		MaxResults: maxResults,
	}
}

func defaultNexusDashboardConfig() NexusDashboardConfig {
	return NexusDashboardConfig{
		UserAgent:     "opentelemetry-collector-contrib-ciscoosreceiver",
		PageSize:      100,
		MaxRetries:    3,
		EventLookback: 24 * time.Hour,
		Platform:      defaultNexusControllerGroupConfig(500),
		NDFC:          defaultNexusControllerGroupConfig(1000),
		Insights:      defaultNexusControllerGroupConfig(1000),
		Orchestrator:  defaultNexusControllerGroupConfig(1000),
		DataBroker:    defaultNexusControllerGroupConfig(1000),
		Performance:   defaultNexusControllerGroupConfig(1000),
	}
}

func defaultACIConfig() ACIConfig {
	return ACIConfig{
		UserAgent:        "opentelemetry-collector-contrib-ciscoosreceiver",
		PageSize:         100,
		MaxRetries:       3,
		EventLookback:    24 * time.Hour,
		Fabric:           defaultNexusControllerGroupConfig(1000),
		ControllerHealth: defaultNexusControllerGroupConfig(100),
		Nodes:            defaultNexusControllerGroupConfig(1000),
		Faults:           defaultNexusControllerGroupConfig(1000),
		Audit:            defaultNexusControllerGroupConfig(1000),
		Events:           defaultNexusControllerGroupConfig(1000),
		Stats:            defaultNexusControllerGroupConfig(1000),
		Endpoints:        defaultNexusControllerGroupConfig(1000),
		Tenants:          defaultNexusControllerGroupConfig(1000),
		Topology:         defaultNexusControllerGroupConfig(1000),
	}
}

func defaultFMCGroupConfig(maxResults int) FMCGroupConfig {
	return FMCGroupConfig{
		Enabled:    true,
		MaxResults: maxResults,
	}
}

func defaultFMCConfig() FMCConfig {
	return FMCConfig{
		UserAgent:     "opentelemetry-collector-contrib-ciscoosreceiver",
		PageSize:      100,
		MaxRetries:    3,
		EventLookback: 24 * time.Hour,
		Manager:       defaultFMCGroupConfig(100),
		Inventory:     defaultFMCGroupConfig(5000),
		Interfaces:    defaultFMCGroupConfig(10000),
		Health:        defaultFMCGroupConfig(2000),
		VPN:           defaultFMCGroupConfig(10000),
		HA:            defaultFMCGroupConfig(1000),
		Policy:        defaultFMCGroupConfig(10000),
		Deployments:   defaultFMCGroupConfig(5000),
		Audit:         defaultFMCGroupConfig(1000),
		EStreamer: FMCEStreamerConfig{
			EventTypes:        []string{"connection", "intrusion", "intrusion_packet", "file"},
			Lookback:          5 * time.Minute,
			ReconnectInterval: 30 * time.Second,
			MaxMessageBytes:   maxFMCEStreamerMessageBytes,
		},
	}
}

func (cfg NexusDashboardConfig) hasTarget() bool {
	return cfg.Enabled || cfg.Endpoint != "" || cfg.Auth.APIKey != "" || cfg.Auth.Username != "" || cfg.Auth.Password != ""
}

func (cfg ACIConfig) hasTarget() bool {
	return cfg.Enabled || len(cfg.Controllers) > 0 || cfg.Auth.Username != "" || cfg.Auth.Password != ""
}

func (cfg FMCConfig) hasTarget() bool {
	return cfg.hasRESTTarget() || cfg.EStreamer.hasTarget()
}

func (cfg FMCConfig) hasRESTTarget() bool {
	return cfg.Enabled || len(cfg.Controllers) > 0 || cfg.Auth.Username != "" || cfg.Auth.Password != ""
}

func (cfg FMCEStreamerConfig) hasTarget() bool {
	return cfg.Enabled || len(cfg.Targets) > 0
}

// Config defines configuration for Cisco OS receiver.
type Config struct {
	scraperhelper.ControllerConfig `mapstructure:",squash"`

	// Devices is the list of Cisco devices to monitor.
	Devices []DeviceConfig `mapstructure:"devices"`

	// DeviceSelection limits emitted telemetry to shared Cisco device identities.
	DeviceSelection DeviceSelectionConfig `mapstructure:"device_selection"`

	// Metrics controls per-metric forwarding for cost-sensitive destinations.
	Metrics map[string]MetricConfig `mapstructure:"metrics"`

	// Meraki contains Meraki Dashboard API polling targets.
	Meraki MerakiConfig `mapstructure:"meraki"`

	// Intersight contains Cisco Intersight API polling settings.
	Intersight IntersightConfig `mapstructure:"intersight"`

	// CatalystCenter contains Cisco Catalyst Center API polling settings.
	CatalystCenter CatalystCenterConfig `mapstructure:"catalyst_center"`

	// Catalyst9800 contains direct Catalyst 9800 WLC telemetry settings.
	Catalyst9800 Catalyst9800Config `mapstructure:"catalyst_9800"`

	// SDWAN contains Cisco Catalyst SD-WAN Manager API polling settings.
	SDWAN SDWANConfig `mapstructure:"sdwan"`

	// NexusDashboard contains Nexus Dashboard, NDFC, Insights, NDO, OneManage, and Data Broker API polling settings.
	NexusDashboard NexusDashboardConfig `mapstructure:"nexus_dashboard"`

	// ACI contains APIC API polling settings.
	ACI ACIConfig `mapstructure:"aci"`

	// FMC contains Secure Firewall Management Center REST and eStreamer settings.
	FMC FMCConfig `mapstructure:"fmc"`

	// ISE contains Cisco Identity Services Engine REST, pxGrid, and Data Connect settings.
	ISE ISEConfig `mapstructure:"ise"`

	// IOSXR contains IOS XR gNMI/MDT telemetry settings.
	IOSXR IOSXRConfig `mapstructure:"ios_xr"`

	// GNMI contains shared, normalized gNMI dial-in targets.
	GNMI GNMIConfig `mapstructure:"gnmi"`

	Scrapers map[component.Type]component.Config `mapstructure:"-"`
}

var (
	_ xconfmap.Validator  = (*Config)(nil)
	_ confmap.Unmarshaler = (*Config)(nil)
)

// Validate checks the receiver configuration is valid
func (cfg *Config) Validate() error {
	var err error

	if cfg.Timeout <= 0 {
		err = multierr.Append(err, errors.New("timeout must be positive"))
	}

	if cfg.CollectionInterval <= 0 {
		err = multierr.Append(err, errors.New("collection_interval must be positive"))
	}

	if len(cfg.Devices) == 0 && !cfg.Meraki.hasTargets() && !cfg.Intersight.hasTarget() && !cfg.CatalystCenter.hasTarget() && !cfg.Catalyst9800.hasTarget() && !cfg.SDWAN.hasTarget() && !cfg.NexusDashboard.hasTarget() && !cfg.ACI.hasTarget() && !cfg.FMC.hasTarget() && !cfg.ISE.hasTarget() && !cfg.IOSXR.hasTarget() && !cfg.GNMI.hasTargets() {
		err = multierr.Append(err, errors.New("must specify at least one SSH device, Meraki target, Intersight target, Catalyst Center target, Catalyst 9800 target, SD-WAN target, Nexus Dashboard target, ACI target, FMC target, ISE target, or IOS XR target; alternatively, specify a shared gNMI target"))
	}

	if len(cfg.Devices) > 0 && len(cfg.Scrapers) == 0 {
		err = multierr.Append(err, errors.New("must specify at least one scraper"))
	}

	for name := range cfg.Metrics {
		if strings.TrimSpace(name) == "" {
			err = multierr.Append(err, errors.New("metrics keys cannot be empty"))
			continue
		}
		if isMetricNamePattern(name) && !validMetricNamePattern(name) {
			err = multierr.Append(err, fmt.Errorf("metrics key %q must be a valid metric name glob", name))
		}
	}

	for i := range cfg.Devices {
		device := &cfg.Devices[i]
		if device.Host == "" {
			err = multierr.Append(err, fmt.Errorf("devices[%d].host cannot be empty", i))
		}
		if device.Port < 1 || device.Port > 65535 {
			err = multierr.Append(err, fmt.Errorf("devices[%d].port must be between 1 and 65535", i))
		}
		if device.Auth.Username == "" {
			err = multierr.Append(err, fmt.Errorf("devices[%d].auth.username cannot be empty", i))
		}
		if device.Auth.Password == "" && device.Auth.KeyFile == "" {
			err = multierr.Append(err, fmt.Errorf("devices[%d].auth.password or devices[%d].auth.key_file must be provided", i, i))
		}
		if device.Auth.KnownHostsFile == "" && !device.Auth.InsecureSkipVerify {
			err = multierr.Append(err, fmt.Errorf("devices[%d].auth.known_hosts_file or devices[%d].auth.insecure_skip_verify must be set", i, i))
		}
	}

	err = multierr.Append(err, cfg.validateMeraki())
	err = multierr.Append(err, cfg.validateIntersight())
	err = multierr.Append(err, cfg.validateCatalystCenter())
	err = multierr.Append(err, cfg.validateCatalyst9800())
	err = multierr.Append(err, cfg.validateSDWAN())
	err = multierr.Append(err, cfg.validateNexusDashboard())
	err = multierr.Append(err, cfg.validateACI())
	err = multierr.Append(err, cfg.validateFMC())
	err = multierr.Append(err, cfg.validateISE())
	err = multierr.Append(err, cfg.validateIOSXR())
	err = multierr.Append(err, cfg.validateGNMI())

	return err
}

func (cfg *Config) validateMeraki() error {
	if !cfg.Meraki.hasTargets() {
		return nil
	}

	var err error
	if cfg.Meraki.Auth.APIKey == "" {
		err = multierr.Append(err, errors.New("meraki.auth.api_key must be provided"))
	}
	err = multierr.Append(err, validateMaxRetries("meraki.max_retries", cfg.Meraki.MaxRetries))

	baseURL := cfg.Meraki.BaseURL
	if baseURL == "" {
		baseURL = defaultMerakiConfig().BaseURL
	}
	parsed, parseErr := url.Parse(baseURL)
	if parseErr != nil || parsed.Scheme == "" || parsed.Host == "" {
		err = multierr.Append(err, errors.New("meraki.base_url must be a valid absolute URL"))
	} else if contentErr := endpointURLContentError("meraki.base_url", parsed); contentErr != nil {
		err = multierr.Append(err, contentErr)
	} else if !strings.EqualFold(parsed.Scheme, "https") {
		err = multierr.Append(err, errors.New("meraki.base_url must use https"))
	}

	for i := range cfg.Meraki.Organizations {
		org := &cfg.Meraki.Organizations[i]
		if strings.TrimSpace(org.OrganizationID) == "" {
			err = multierr.Append(err, fmt.Errorf("meraki.organizations[%d].organization_id cannot be empty", i))
		}
		if org.TagsFilterType != "" && org.TagsFilterType != "withAnyTags" && org.TagsFilterType != "withAllTags" {
			err = multierr.Append(err, fmt.Errorf("meraki.organizations[%d].tags_filter_type must be withAnyTags or withAllTags", i))
		}
		err = multierr.Append(err, validateNonEmptyStringList(fmt.Sprintf("meraki.organizations[%d].network_ids", i), org.NetworkIDs))
		err = multierr.Append(err, validateNonEmptyStringList(fmt.Sprintf("meraki.organizations[%d].serials", i), org.Serials))
		err = multierr.Append(err, validateNonEmptyStringList(fmt.Sprintf("meraki.organizations[%d].product_types", i), org.ProductTypes))
		err = multierr.Append(err, validateNonEmptyStringList(fmt.Sprintf("meraki.organizations[%d].tags", i), org.Tags))
	}

	for i, device := range cfg.Meraki.Devices {
		if strings.TrimSpace(device.OrganizationID) == "" {
			err = multierr.Append(err, fmt.Errorf("meraki.devices[%d].organization_id cannot be empty", i))
		}
		if strings.TrimSpace(device.Serial) == "" {
			err = multierr.Append(err, fmt.Errorf("meraki.devices[%d].serial cannot be empty", i))
		}
	}

	return err
}

func (cfg *Config) validateIntersight() error {
	if !cfg.Intersight.hasTarget() {
		return nil
	}

	var err error
	if cfg.Intersight.Auth.KeyID == "" {
		err = multierr.Append(err, errors.New("intersight.auth.key_id must be provided"))
	}
	if cfg.Intersight.Auth.KeyFile == "" && cfg.Intersight.Auth.KeyPEM == "" {
		err = multierr.Append(err, errors.New("intersight.auth.key_file or intersight.auth.key_pem must be provided"))
	}

	endpoint := cfg.Intersight.Endpoint
	if endpoint == "" {
		endpoint = defaultIntersightConfig().Endpoint
	}
	parsed, parseErr := url.Parse(endpoint)
	if parseErr != nil || parsed.Scheme == "" || parsed.Host == "" {
		err = multierr.Append(err, errors.New("intersight.endpoint must be a valid absolute URL"))
	} else if contentErr := endpointURLContentError("intersight.endpoint", parsed); contentErr != nil {
		err = multierr.Append(err, contentErr)
	} else if !strings.EqualFold(parsed.Scheme, "https") {
		err = multierr.Append(err, errors.New("intersight.endpoint must use https"))
	}

	err = multierr.Append(err, validatePageSize("intersight.page_size", cfg.Intersight.PageSize))
	err = multierr.Append(err, validateMaxRetries("intersight.max_retries", cfg.Intersight.MaxRetries))
	if cfg.Intersight.EventLookback < 0 {
		err = multierr.Append(err, errors.New("intersight.event_lookback must not be negative"))
	}
	if cfg.Intersight.TelemetryLookback < 0 {
		err = multierr.Append(err, errors.New("intersight.telemetry_lookback must not be negative"))
	}
	err = multierr.Append(err, validateNonEmptyStringList("intersight.targets.serials", cfg.Intersight.Targets.Serials))
	err = multierr.Append(err, validateNonEmptyStringList("intersight.targets.moids", cfg.Intersight.Targets.MoIDs))

	groups := map[string]IntersightGroupConfig{
		"inventory":      cfg.Intersight.Inventory,
		"events":         cfg.Intersight.Events,
		"audit":          cfg.Intersight.Audit,
		"telemetry":      cfg.Intersight.Telemetry,
		"equipment":      cfg.Intersight.Equipment,
		"network":        cfg.Intersight.Network,
		"firmware":       cfg.Intersight.Firmware,
		"storage":        cfg.Intersight.Storage,
		"hyperflex":      cfg.Intersight.HyperFlex,
		"kubernetes":     cfg.Intersight.Kubernetes,
		"virtualization": cfg.Intersight.Virtualization,
	}
	for name, group := range groups {
		err = multierr.Append(err, validateMaxResults("intersight."+name+".max_results", group.MaxResults))
	}

	return err
}

func (cfg *Config) validateCatalystCenter() error {
	if !cfg.CatalystCenter.hasTarget() {
		return nil
	}

	var err error
	if cfg.CatalystCenter.Endpoint == "" {
		err = multierr.Append(err, errors.New("catalyst_center.endpoint must be provided"))
	} else {
		err = multierr.Append(err, validateHTTPURL("catalyst_center.endpoint", cfg.CatalystCenter.Endpoint, cfg.CatalystCenter.InsecureSkipVerify))
	}

	switch inferredCatalystCenterAuthMode(cfg.CatalystCenter.Auth) {
	case "basic":
		if cfg.CatalystCenter.Auth.Username == "" {
			err = multierr.Append(err, errors.New("catalyst_center.auth.username must be provided for basic auth"))
		}
		if cfg.CatalystCenter.Auth.Password == "" {
			err = multierr.Append(err, errors.New("catalyst_center.auth.password must be provided for basic auth"))
		}
	case "aes":
		if cfg.CatalystCenter.Auth.AESCredentials == "" {
			err = multierr.Append(err, errors.New("catalyst_center.auth.aes_credentials must be provided for aes auth"))
		}
	default:
		err = multierr.Append(err, errors.New("catalyst_center.auth.mode must be basic or aes"))
	}

	if cfg.CatalystCenter.PageSize < 0 || cfg.CatalystCenter.PageSize > 500 {
		err = multierr.Append(err, errors.New("catalyst_center.page_size must be between 1 and 500 when set"))
	}
	err = multierr.Append(err, validateMaxRetries("catalyst_center.max_retries", cfg.CatalystCenter.MaxRetries))
	if cfg.CatalystCenter.Lookback < 0 {
		err = multierr.Append(err, errors.New("catalyst_center.lookback must not be negative"))
	}

	for i, target := range cfg.CatalystCenter.Targets.DeviceDetails {
		if !validCatalystCenterDeviceIdentifier(target.Identifier) {
			err = multierr.Append(err, fmt.Errorf("catalyst_center.targets.device_details[%d].identifier must be macAddress, nwDeviceName, or uuid", i))
		}
		if strings.TrimSpace(target.SearchBy) == "" {
			err = multierr.Append(err, fmt.Errorf("catalyst_center.targets.device_details[%d].search_by cannot be empty", i))
		} else if canonicalCatalystCenterDeviceIdentifier(target.Identifier) == "macAddress" {
			err = multierr.Append(err, validateMACAddress(fmt.Sprintf("catalyst_center.targets.device_details[%d].search_by", i), target.SearchBy))
		}
	}
	err = multierr.Append(err, validateMACAddressList("catalyst_center.targets.client_macs", cfg.CatalystCenter.Targets.ClientMACs))

	groups := map[string]CatalystCenterGroupConfig{
		"inventory":  cfg.CatalystCenter.Inventory,
		"interfaces": cfg.CatalystCenter.Interfaces,
		"health":     cfg.CatalystCenter.Health,
		"topology":   cfg.CatalystCenter.Topology,
		"issues":     cfg.CatalystCenter.Issues,
		"details":    cfg.CatalystCenter.Details,
	}
	for name, group := range groups {
		err = multierr.Append(err, validateMaxResults("catalyst_center."+name+".max_results", group.MaxResults))
	}

	return err
}

func (cfg *Config) validateSDWAN() error {
	if !cfg.SDWAN.hasTarget() {
		return nil
	}

	var err error
	if cfg.SDWAN.Endpoint == "" {
		err = multierr.Append(err, errors.New("sdwan.endpoint must be provided"))
	} else {
		err = multierr.Append(err, validateHTTPURL("sdwan.endpoint", cfg.SDWAN.Endpoint, cfg.SDWAN.InsecureSkipVerify))
	}

	switch inferredSDWANAuthMode(cfg.SDWAN.Auth) {
	case "bearer":
		if cfg.SDWAN.Auth.BearerToken == "" {
			err = multierr.Append(err, errors.New("sdwan.auth.bearer_token must be provided for bearer auth"))
		}
	case "jwt", "session":
		if cfg.SDWAN.Auth.Username == "" {
			err = multierr.Append(err, fmt.Errorf("sdwan.auth.username must be provided for %s auth", inferredSDWANAuthMode(cfg.SDWAN.Auth)))
		}
		if cfg.SDWAN.Auth.Password == "" {
			err = multierr.Append(err, fmt.Errorf("sdwan.auth.password must be provided for %s auth", inferredSDWANAuthMode(cfg.SDWAN.Auth)))
		}
	case "cookie":
		if cfg.SDWAN.Auth.JSessionID == "" {
			err = multierr.Append(err, errors.New("sdwan.auth.jsession_id must be provided for cookie auth"))
		}
		if cfg.SDWAN.Auth.XSRFToken == "" {
			err = multierr.Append(err, errors.New("sdwan.auth.xsrf_token must be provided for cookie auth"))
		}
	default:
		err = multierr.Append(err, errors.New("sdwan.auth.mode must be auto, jwt, session, bearer, or cookie"))
	}

	err = multierr.Append(err, validatePageSize("sdwan.page_size", cfg.SDWAN.PageSize))
	err = multierr.Append(err, validateMaxRetries("sdwan.max_retries", cfg.SDWAN.MaxRetries))
	if cfg.SDWAN.EventLookback < 0 {
		err = multierr.Append(err, errors.New("sdwan.event_lookback must not be negative"))
	}
	if cfg.SDWAN.RealtimeDetails.Enabled && !cfg.SDWAN.Targets.hasDeviceScope() {
		err = multierr.Append(err, errors.New("sdwan.realtime_details requires at least one target filter: site_ids, system_ips, uuids, serials, device_types, personalities, colors, interface_names, vpn_ids, applications, or application_families"))
	}

	for name, values := range map[string][]string{
		"site_ids":             cfg.SDWAN.Targets.SiteIDs,
		"uuids":                cfg.SDWAN.Targets.UUIDs,
		"serials":              cfg.SDWAN.Targets.Serials,
		"device_types":         cfg.SDWAN.Targets.DeviceTypes,
		"personalities":        cfg.SDWAN.Targets.Personalities,
		"colors":               cfg.SDWAN.Targets.Colors,
		"interface_names":      cfg.SDWAN.Targets.InterfaceNames,
		"vpn_ids":              cfg.SDWAN.Targets.VPNIDs,
		"applications":         cfg.SDWAN.Targets.Applications,
		"application_families": cfg.SDWAN.Targets.ApplicationFamilies,
		"cloud_providers":      cfg.SDWAN.Targets.CloudProviders,
		"service_types":        cfg.SDWAN.Targets.ServiceTypes,
	} {
		for i, value := range values {
			if strings.TrimSpace(value) == "" {
				err = multierr.Append(err, fmt.Errorf("sdwan.targets.%s[%d] cannot be empty", name, i))
			}
		}
	}
	err = multierr.Append(err, validateIPAddressList("sdwan.targets.system_ips", cfg.SDWAN.Targets.SystemIPs))

	groups := map[string]SDWANGroupConfig{
		"manager":              cfg.SDWAN.Manager,
		"inventory":            cfg.SDWAN.Inventory,
		"control_plane":        cfg.SDWAN.ControlPlane,
		"bfd":                  cfg.SDWAN.BFD,
		"app_route":            cfg.SDWAN.AppRoute,
		"interfaces":           cfg.SDWAN.Interfaces,
		"alarms":               cfg.SDWAN.Alarms,
		"events":               cfg.SDWAN.Events,
		"audit":                cfg.SDWAN.Audit,
		"realtime_details":     cfg.SDWAN.RealtimeDetails,
		"tunnels":              cfg.SDWAN.Tunnels,
		"flows":                cfg.SDWAN.Flows,
		"policy_qos":           cfg.SDWAN.PolicyQoS,
		"security":             cfg.SDWAN.Security,
		"appqoe":               cfg.SDWAN.AppQoE,
		"cloud_onramp":         cfg.SDWAN.CloudOnRamp,
		"nwpi":                 cfg.SDWAN.NWPI,
		"underlay":             cfg.SDWAN.Underlay,
		"cellular":             cfg.SDWAN.Cellular,
		"hardware_energy":      cfg.SDWAN.HardwareEnergy,
		"routing_services":     cfg.SDWAN.RoutingServices,
		"branch_services":      cfg.SDWAN.BranchServices,
		"lifecycle_compliance": cfg.SDWAN.LifecycleCompliance,
		"thousandeyes":         cfg.SDWAN.ThousandEyes,
		"management_security":  cfg.SDWAN.ManagementSecurity,
	}
	for name, group := range groups {
		err = multierr.Append(err, validateMaxResults("sdwan."+name+".max_results", group.MaxResults))
	}

	return err
}

func (cfg *Config) validateNexusDashboard() error {
	if !cfg.NexusDashboard.hasTarget() {
		return nil
	}

	var err error
	if cfg.NexusDashboard.Endpoint == "" {
		err = multierr.Append(err, errors.New("nexus_dashboard.endpoint must be provided"))
	} else {
		err = multierr.Append(err, validateHTTPURL("nexus_dashboard.endpoint", cfg.NexusDashboard.Endpoint, cfg.NexusDashboard.InsecureSkipVerify))
	}

	authMode := inferredControllerAuthMode(cfg.NexusDashboard.Auth)
	switch authMode {
	case "api_key":
		if cfg.NexusDashboard.Auth.Username == "" {
			err = multierr.Append(err, errors.New("nexus_dashboard.auth.username must be provided for api_key auth"))
		}
		if cfg.NexusDashboard.Auth.APIKey == "" {
			err = multierr.Append(err, errors.New("nexus_dashboard.auth.api_key must be provided for api_key auth"))
		}
	case "username_password":
		if cfg.NexusDashboard.Auth.Username == "" {
			err = multierr.Append(err, errors.New("nexus_dashboard.auth.username must be provided for username_password auth"))
		}
		if cfg.NexusDashboard.Auth.Password == "" {
			err = multierr.Append(err, errors.New("nexus_dashboard.auth.password must be provided for username_password auth"))
		}
	default:
		err = multierr.Append(err, errors.New("nexus_dashboard.auth.mode must be api_key or username_password"))
	}

	err = multierr.Append(err, validatePageSize("nexus_dashboard.page_size", cfg.NexusDashboard.PageSize))
	err = multierr.Append(err, validateMaxRetries("nexus_dashboard.max_retries", cfg.NexusDashboard.MaxRetries))
	if cfg.NexusDashboard.EventLookback < 0 {
		err = multierr.Append(err, errors.New("nexus_dashboard.event_lookback must not be negative"))
	}
	for name, values := range map[string][]string{
		"sites":           cfg.NexusDashboard.Targets.Sites,
		"fabrics":         cfg.NexusDashboard.Targets.Fabrics,
		"switch_serials":  cfg.NexusDashboard.Targets.SwitchSerials,
		"switch_ids":      cfg.NexusDashboard.Targets.SwitchIDs,
		"interface_names": cfg.NexusDashboard.Targets.InterfaceNames,
		"service_names":   cfg.NexusDashboard.Targets.ServiceNames,
	} {
		err = multierr.Append(err, validateNonEmptyStringList("nexus_dashboard.targets."+name, values))
	}
	groups := map[string]NexusControllerGroupConfig{
		"platform":     cfg.NexusDashboard.Platform,
		"ndfc":         cfg.NexusDashboard.NDFC,
		"insights":     cfg.NexusDashboard.Insights,
		"orchestrator": cfg.NexusDashboard.Orchestrator,
		"data_broker":  cfg.NexusDashboard.DataBroker,
		"performance":  cfg.NexusDashboard.Performance,
	}
	err = multierr.Append(err, validateNexusControllerGroups("nexus_dashboard", groups))

	return err
}

func (cfg *Config) validateACI() error {
	if !cfg.ACI.hasTarget() {
		return nil
	}

	var err error
	if len(cfg.ACI.Controllers) == 0 {
		err = multierr.Append(err, errors.New("aci.controllers must include at least one APIC endpoint"))
	}
	for i, controller := range cfg.ACI.Controllers {
		if controller.Endpoint == "" {
			err = multierr.Append(err, fmt.Errorf("aci.controllers[%d].endpoint cannot be empty", i))
			continue
		}
		err = multierr.Append(err, validateHTTPURL(fmt.Sprintf("aci.controllers[%d].endpoint", i), controller.Endpoint, cfg.ACI.InsecureSkipVerify))
	}

	authMode := inferredControllerAuthMode(cfg.ACI.Auth)
	if authMode != "username_password" {
		err = multierr.Append(err, errors.New("aci.auth.mode must be username_password"))
	}
	if cfg.ACI.Auth.Username == "" {
		err = multierr.Append(err, errors.New("aci.auth.username must be provided"))
	}
	if cfg.ACI.Auth.Password == "" {
		err = multierr.Append(err, errors.New("aci.auth.password must be provided"))
	}

	err = multierr.Append(err, validatePageSize("aci.page_size", cfg.ACI.PageSize))
	err = multierr.Append(err, validateMaxRetries("aci.max_retries", cfg.ACI.MaxRetries))
	if cfg.ACI.EventLookback < 0 {
		err = multierr.Append(err, errors.New("aci.event_lookback must not be negative"))
	}
	for name, values := range map[string][]string{
		"sites":           cfg.ACI.Targets.Sites,
		"fabrics":         cfg.ACI.Targets.Fabrics,
		"node_ids":        cfg.ACI.Targets.NodeIDs,
		"serials":         cfg.ACI.Targets.Serials,
		"tenants":         cfg.ACI.Targets.Tenants,
		"vrfs":            cfg.ACI.Targets.VRFs,
		"bridge_domains":  cfg.ACI.Targets.BridgeDomains,
		"epgs":            cfg.ACI.Targets.EPGs,
		"interface_names": cfg.ACI.Targets.InterfaceNames,
	} {
		err = multierr.Append(err, validateNonEmptyStringList("aci.targets."+name, values))
	}
	groups := map[string]NexusControllerGroupConfig{
		"fabric":            cfg.ACI.Fabric,
		"controller_health": cfg.ACI.ControllerHealth,
		"nodes":             cfg.ACI.Nodes,
		"faults":            cfg.ACI.Faults,
		"audit":             cfg.ACI.Audit,
		"events":            cfg.ACI.Events,
		"stats":             cfg.ACI.Stats,
		"endpoints":         cfg.ACI.Endpoints,
		"tenants":           cfg.ACI.Tenants,
		"topology":          cfg.ACI.Topology,
	}
	err = multierr.Append(err, validateNexusControllerGroups("aci", groups))

	return err
}

func (cfg *Config) validateFMC() error {
	if !cfg.FMC.hasTarget() {
		return nil
	}

	var err error
	restTarget := cfg.FMC.Enabled || len(cfg.FMC.Controllers) > 0 || cfg.FMC.Auth.Username != "" || cfg.FMC.Auth.Password != ""
	if restTarget {
		if len(cfg.FMC.Controllers) == 0 {
			err = multierr.Append(err, errors.New("fmc.controllers must include at least one FMC endpoint"))
		}
		for i, controller := range cfg.FMC.Controllers {
			if controller.Endpoint == "" {
				err = multierr.Append(err, fmt.Errorf("fmc.controllers[%d].endpoint cannot be empty", i))
				continue
			}
			err = multierr.Append(err, validateHTTPURL(fmt.Sprintf("fmc.controllers[%d].endpoint", i), controller.Endpoint, cfg.FMC.InsecureSkipVerify))
		}

		authMode := inferredControllerAuthMode(cfg.FMC.Auth)
		if authMode != "username_password" {
			err = multierr.Append(err, errors.New("fmc.auth.mode must be username_password"))
		}
		if cfg.FMC.Auth.Username == "" {
			err = multierr.Append(err, errors.New("fmc.auth.username must be provided"))
		}
		if cfg.FMC.Auth.Password == "" {
			err = multierr.Append(err, errors.New("fmc.auth.password must be provided"))
		}
	}

	err = multierr.Append(err, validatePageSize("fmc.page_size", cfg.FMC.PageSize))
	err = multierr.Append(err, validateMaxRetries("fmc.max_retries", cfg.FMC.MaxRetries))
	if cfg.FMC.EventLookback < 0 {
		err = multierr.Append(err, errors.New("fmc.event_lookback must not be negative"))
	}
	for name, values := range map[string][]string{
		"device_ids":      cfg.FMC.Targets.DeviceIDs,
		"serials":         cfg.FMC.Targets.Serials,
		"names":           cfg.FMC.Targets.Names,
		"policy_ids":      cfg.FMC.Targets.PolicyIDs,
		"policy_names":    cfg.FMC.Targets.PolicyNames,
		"interface_names": cfg.FMC.Targets.InterfaceNames,
	} {
		err = multierr.Append(err, validateNonEmptyStringList("fmc.targets."+name, values))
	}
	err = multierr.Append(err, validateIPAddressList("fmc.targets.management_ips", cfg.FMC.Targets.ManagementIPs))

	groups := map[string]FMCGroupConfig{
		"manager":     cfg.FMC.Manager,
		"inventory":   cfg.FMC.Inventory,
		"interfaces":  cfg.FMC.Interfaces,
		"health":      cfg.FMC.Health,
		"vpn":         cfg.FMC.VPN,
		"ha":          cfg.FMC.HA,
		"policy":      cfg.FMC.Policy,
		"deployments": cfg.FMC.Deployments,
		"audit":       cfg.FMC.Audit,
	}
	for name, group := range groups {
		err = multierr.Append(err, validateMaxResults("fmc."+name+".max_results", group.MaxResults))
	}

	err = multierr.Append(err, cfg.validateFMCEStreamer())
	return err
}

func (cfg *Config) validateFMCEStreamer() error {
	if !cfg.FMC.EStreamer.hasTarget() {
		return nil
	}

	var err error
	if cfg.FMC.EStreamer.Enabled && len(cfg.FMC.EStreamer.Targets) == 0 && len(cfg.FMC.Controllers) == 0 {
		err = multierr.Append(err, errors.New("fmc.estreamer.targets or fmc.controllers must include at least one eStreamer endpoint"))
	}
	for i, target := range cfg.FMC.EStreamer.Targets {
		if target.Endpoint == "" {
			err = multierr.Append(err, fmt.Errorf("fmc.estreamer.targets[%d].endpoint cannot be empty", i))
			continue
		}
		err = multierr.Append(err, validateHostPortOrHost(fmt.Sprintf("fmc.estreamer.targets[%d].endpoint", i), target.Endpoint))
	}
	if cfg.FMC.EStreamer.TLS.CertFile == "" && cfg.FMC.EStreamer.TLS.KeyFile != "" {
		err = multierr.Append(err, errors.New("fmc.estreamer.tls.cert_file must be provided when key_file is set"))
	}
	if cfg.FMC.EStreamer.TLS.KeyFile == "" && cfg.FMC.EStreamer.TLS.CertFile != "" {
		err = multierr.Append(err, errors.New("fmc.estreamer.tls.key_file must be provided when cert_file is set"))
	}
	if cfg.FMC.EStreamer.hasTarget() && (cfg.FMC.EStreamer.TLS.CertFile == "" || cfg.FMC.EStreamer.TLS.KeyFile == "") {
		err = multierr.Append(err, errors.New("fmc.estreamer.tls.cert_file and fmc.estreamer.tls.key_file must be provided"))
	}
	if cfg.FMC.EStreamer.Lookback < 0 {
		err = multierr.Append(err, errors.New("fmc.estreamer.lookback must not be negative"))
	}
	if cfg.FMC.EStreamer.ReconnectInterval < 0 {
		err = multierr.Append(err, errors.New("fmc.estreamer.reconnect_interval must not be negative"))
	}
	if cfg.FMC.EStreamer.MaxMessageBytes < 0 || cfg.FMC.EStreamer.MaxMessageBytes > maxFMCEStreamerMessageBytes {
		err = multierr.Append(err, fmt.Errorf("fmc.estreamer.max_message_bytes must be between 1 and %d when set", maxFMCEStreamerMessageBytes))
	}
	for i, eventType := range cfg.FMC.EStreamer.EventTypes {
		if !validFMCEStreamerEventType(eventType) {
			err = multierr.Append(err, fmt.Errorf("fmc.estreamer.event_types[%d] must be connection, intrusion, intrusion_packet, or file", i))
		}
	}
	return err
}

func validateHTTPURL(name, value string, _ bool) error {
	parsed, parseErr := url.Parse(value)
	if parseErr != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("%s must be a valid absolute URL", name)
	}
	if err := endpointURLContentError(name, parsed); err != nil {
		return err
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("%s must use https", name)
	}
	return nil
}

func endpointURLContentError(name string, parsed *url.URL) error {
	if parsed.User != nil {
		return fmt.Errorf("%s must not include user information", name)
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return fmt.Errorf("%s must not include a query string", name)
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("%s must not include a fragment", name)
	}
	return nil
}

func validateHostPortOrHost(name, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s cannot be empty", name)
	}
	if strings.Contains(value, "://") {
		return fmt.Errorf("%s must be host or host:port, not a URL", name)
	}
	if strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return fmt.Errorf("%s must not contain spaces", name)
	}

	// An unbracketed IP address is a host without an explicit port. In
	// particular, a bare IPv6 address contains colons but is still valid.
	if net.ParseIP(value) != nil {
		return nil
	}

	host, port, splitErr := net.SplitHostPort(value)
	if splitErr == nil {
		if host == "" {
			return fmt.Errorf("%s host cannot be empty", name)
		}
		// Brackets are only valid around an IPv6 literal in a host:port pair.
		if strings.HasPrefix(value, "[") && (net.ParseIP(host) == nil || !strings.Contains(host, ":")) {
			return fmt.Errorf("%s must use brackets only around an IPv6 address with a port", name)
		}
		if !validHostOrIP(host) {
			return fmt.Errorf("%s host must be a valid hostname or IP address", name)
		}
		if port == "" || strings.IndexFunc(port, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return fmt.Errorf("%s port must be between 1 and 65535", name)
		}
		parsedPort, parseErr := strconv.Atoi(port)
		if parseErr != nil || parsedPort < 1 || parsedPort > 65535 {
			return fmt.Errorf("%s port must be between 1 and 65535", name)
		}
		return nil
	}

	// Any remaining colon or bracket is either a malformed host:port pair or a
	// malformed IP literal. Valid bare IP addresses were handled above.
	if strings.ContainsAny(value, ":[]") || !validHostOrIP(value) {
		return fmt.Errorf("%s must be a valid hostname, IP address, or host:port", name)
	}
	return nil
}

func validHostOrIP(value string) bool {
	if net.ParseIP(value) != nil {
		return true
	}
	if value == "" || len(value) > 253 {
		return false
	}
	if before, ok := strings.CutSuffix(value, "."); ok {
		value = before
		if value == "" {
			return false
		}
	}

	looksLikeIPv4 := strings.Contains(value, ".")
	for _, r := range value {
		if r != '.' && (r < '0' || r > '9') {
			looksLikeIPv4 = false
			break
		}
	}
	if looksLikeIPv4 {
		return false
	}

	for label := range strings.SplitSeq(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func inferredCatalystCenterAuthMode(auth CatalystCenterAuthConfig) string {
	switch auth.Mode {
	case "", "auto":
		if auth.AESCredentials != "" {
			return "aes"
		}
		if auth.Username != "" || auth.Password != "" {
			return "basic"
		}
		return ""
	default:
		return auth.Mode
	}
}

func inferredSDWANAuthMode(auth SDWANAuthConfig) string {
	switch auth.Mode {
	case "", "auto":
		if auth.BearerToken != "" {
			return "bearer"
		}
		if auth.JSessionID != "" || auth.XSRFToken != "" {
			return "cookie"
		}
		if auth.Username != "" || auth.Password != "" {
			return "jwt"
		}
		return ""
	default:
		return auth.Mode
	}
}

func (targets SDWANTargetFilters) hasDeviceScope() bool {
	return len(targets.SiteIDs) > 0 ||
		len(targets.SystemIPs) > 0 ||
		len(targets.UUIDs) > 0 ||
		len(targets.Serials) > 0 ||
		len(targets.DeviceTypes) > 0 ||
		len(targets.Personalities) > 0 ||
		len(targets.Colors) > 0 ||
		len(targets.InterfaceNames) > 0 ||
		len(targets.VPNIDs) > 0 ||
		len(targets.Applications) > 0 ||
		len(targets.ApplicationFamilies) > 0
}

func validCatalystCenterDeviceIdentifier(value string) bool {
	return canonicalCatalystCenterDeviceIdentifier(value) != ""
}

func canonicalCatalystCenterDeviceIdentifier(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "macaddress":
		return "macAddress"
	case "nwdevicename":
		return "nwDeviceName"
	case "uuid":
		return "uuid"
	default:
		return ""
	}
}

func inferredControllerAuthMode(auth ControllerAuthConfig) string {
	switch auth.Mode {
	case "", "auto":
		if auth.APIKey != "" {
			return "api_key"
		}
		if auth.Username != "" || auth.Password != "" {
			return "username_password"
		}
		return ""
	default:
		return auth.Mode
	}
}

func validFMCEStreamerEventType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(strings.ReplaceAll(value, "-", "_"))) {
	case "connection", "connection_event", "traffic", "security_intelligence", "si",
		"intrusion", "intrusion_event", "intrusion_packet", "intrusion_packet_event",
		"file", "file_event", "malware", "file_malware":
		return true
	default:
		return false
	}
}

func validateNexusControllerGroups(prefix string, groups map[string]NexusControllerGroupConfig) error {
	var err error
	for name, group := range groups {
		err = multierr.Append(err, validateMaxResults(prefix+"."+name+".max_results", group.MaxResults))
	}
	return err
}

func validatePageSize(name string, value int) error {
	if value < 0 {
		return fmt.Errorf("%s must not be negative", name)
	}
	if value > httpclient.HardMaxPaginationResults {
		return fmt.Errorf("%s must not exceed %d", name, httpclient.HardMaxPaginationResults)
	}
	return nil
}

func validateMaxRetries(name string, value int) error {
	if value < 0 {
		return fmt.Errorf("%s must not be negative", name)
	}
	if value > httpclient.HardMaxRequestRetries {
		return fmt.Errorf("%s must not exceed %d", name, httpclient.HardMaxRequestRetries)
	}
	return nil
}

func validateMaxResults(name string, value int) error {
	if value < 0 {
		return fmt.Errorf("%s must not be negative", name)
	}
	if value > httpclient.HardMaxPaginationResults {
		return fmt.Errorf("%s must not exceed the hard pagination limit of %d", name, httpclient.HardMaxPaginationResults)
	}
	return nil
}

func validateNonEmptyStringList(prefix string, values []string) error {
	var err error
	for i, value := range values {
		if strings.TrimSpace(value) == "" {
			err = multierr.Append(err, fmt.Errorf("%s[%d] cannot be empty", prefix, i))
		}
	}
	return err
}

func validateIPAddressList(prefix string, values []string) error {
	var err error
	for i, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			err = multierr.Append(err, fmt.Errorf("%s[%d] cannot be empty", prefix, i))
			continue
		}
		if _, parseErr := netip.ParseAddr(value); parseErr != nil {
			err = multierr.Append(err, fmt.Errorf("%s[%d] must be a valid IP address", prefix, i))
		}
	}
	return err
}

func validateMACAddressList(prefix string, values []string) error {
	var err error
	for i, value := range values {
		err = multierr.Append(err, validateMACAddress(fmt.Sprintf("%s[%d]", prefix, i), value))
	}
	return err
}

func validateMACAddress(prefix, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s cannot be empty", prefix)
	}
	mac, parseErr := net.ParseMAC(value)
	if parseErr != nil || len(mac) != 6 {
		return fmt.Errorf("%s must be a valid 48-bit MAC address", prefix)
	}
	return nil
}

// Unmarshal a config.Parser into the config struct.
func (cfg *Config) Unmarshal(componentParser *confmap.Conf) error {
	if componentParser == nil {
		return nil
	}

	// Decode the static receiver configuration strictly so misspelled settings
	// fail startup instead of silently disabling production controls. Scrapers
	// are factory-dispatched below, so remove only that dynamic section from the
	// strict pass.
	staticSettings := componentParser.ToStringMap()
	delete(staticSettings, "scrapers")
	type staticConfig Config
	if err := confmap.NewFromStringMap(staticSettings).Unmarshal((*staticConfig)(cfg)); err != nil {
		return err
	}

	// dynamically load the individual scraper configs based on the key name
	cfg.Scrapers = map[component.Type]component.Config{}

	if !componentParser.IsSet("scrapers") {
		return nil
	}

	scrapersSection, err := componentParser.Sub("scrapers")
	if err != nil {
		return err
	}

	for keyStr := range scrapersSection.ToStringMap() {
		key, err := component.NewType(keyStr)
		if err != nil {
			return fmt.Errorf("invalid scraper key name: %s", key)
		}

		factory, ok := scraperFactories[key]
		if !ok {
			return fmt.Errorf("invalid scraper key: %s", key)
		}

		scraperSection, err := scrapersSection.Sub(keyStr)
		if err != nil {
			return err
		}
		scraperCfg := factory.CreateDefaultConfig()
		if err = scraperSection.Unmarshal(scraperCfg); err != nil {
			return fmt.Errorf("error reading settings for scraper type %q: %w", key, err)
		}

		cfg.Scrapers[key] = scraperCfg
	}

	return nil
}
