// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/xconfmap"
	"go.opentelemetry.io/collector/scraper/scraperhelper"
	"go.uber.org/multierr"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/connection"
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
	Organizations []MerakiOrganizationConfig `mapstructure:"organizations"`
	Devices       []MerakiDeviceConfig       `mapstructure:"devices"`
}

func defaultMerakiConfig() MerakiConfig {
	return MerakiConfig{
		BaseURL:   "https://api.meraki.com/api/v1",
		UserAgent: "opentelemetry-collector-contrib-ciscoosreceiver",
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
	TelemetryLookback  time.Duration               `mapstructure:"telemetry_lookback"`
	ServiceDiscovery   bool                        `mapstructure:"service_discovery"`
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
	StatsLookback      time.Duration              `mapstructure:"stats_lookback"`
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

func defaultNexusControllerGroupConfig(maxResults int) NexusControllerGroupConfig {
	return NexusControllerGroupConfig{
		Enabled:    true,
		MaxResults: maxResults,
	}
}

func defaultNexusDashboardConfig() NexusDashboardConfig {
	return NexusDashboardConfig{
		UserAgent:         "opentelemetry-collector-contrib-ciscoosreceiver",
		PageSize:          100,
		MaxRetries:        3,
		EventLookback:     24 * time.Hour,
		TelemetryLookback: 30 * time.Minute,
		ServiceDiscovery:  true,
		Platform:          defaultNexusControllerGroupConfig(500),
		NDFC:              defaultNexusControllerGroupConfig(1000),
		Insights:          defaultNexusControllerGroupConfig(1000),
		Orchestrator:      defaultNexusControllerGroupConfig(1000),
		DataBroker:        defaultNexusControllerGroupConfig(1000),
		Performance:       defaultNexusControllerGroupConfig(1000),
	}
}

func defaultACIConfig() ACIConfig {
	return ACIConfig{
		UserAgent:        "opentelemetry-collector-contrib-ciscoosreceiver",
		PageSize:         100,
		MaxRetries:       3,
		EventLookback:    24 * time.Hour,
		StatsLookback:    30 * time.Minute,
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

func (cfg NexusDashboardConfig) hasTarget() bool {
	return cfg.Enabled || cfg.Endpoint != "" || cfg.Auth.APIKey != "" || cfg.Auth.Username != "" || cfg.Auth.Password != ""
}

func (cfg ACIConfig) hasTarget() bool {
	return cfg.Enabled || len(cfg.Controllers) > 0 || cfg.Auth.Username != "" || cfg.Auth.Password != ""
}

// Config defines configuration for Cisco OS receiver.
type Config struct {
	scraperhelper.ControllerConfig `mapstructure:",squash"`

	// Devices is the list of Cisco devices to monitor.
	Devices []DeviceConfig `mapstructure:"devices"`

	// DeviceSelection limits emitted telemetry to shared Cisco device identities.
	DeviceSelection DeviceSelectionConfig `mapstructure:"device_selection"`

	// Meraki contains Meraki Dashboard API polling targets.
	Meraki MerakiConfig `mapstructure:"meraki"`

	// Intersight contains Cisco Intersight API polling settings.
	Intersight IntersightConfig `mapstructure:"intersight"`

	// CatalystCenter contains Cisco Catalyst Center API polling settings.
	CatalystCenter CatalystCenterConfig `mapstructure:"catalyst_center"`

	// NexusDashboard contains Nexus Dashboard, NDFC, Insights, NDO, OneManage, and Data Broker API polling settings.
	NexusDashboard NexusDashboardConfig `mapstructure:"nexus_dashboard"`

	// ACI contains APIC API polling settings.
	ACI ACIConfig `mapstructure:"aci"`

	Scrapers map[component.Type]component.Config `mapstructure:"-"`
}

var (
	_ xconfmap.Validator  = (*Config)(nil)
	_ confmap.Unmarshaler = (*Config)(nil)
)

// Validate checks the receiver configuration is valid
func (cfg *Config) Validate() error {
	var err error

	if cfg.Timeout < 0 {
		err = multierr.Append(err, errors.New("timeout must not be negative"))
	}

	if cfg.CollectionInterval <= 0 {
		err = multierr.Append(err, errors.New("collection_interval must be positive"))
	}

	if len(cfg.Devices) == 0 && !cfg.Meraki.hasTargets() && !cfg.Intersight.hasTarget() && !cfg.CatalystCenter.hasTarget() && !cfg.NexusDashboard.hasTarget() && !cfg.ACI.hasTarget() {
		err = multierr.Append(err, errors.New("must specify at least one SSH device, Meraki target, Intersight target, Catalyst Center target, Nexus Dashboard target, or ACI target"))
	}

	if len(cfg.Devices) > 0 && len(cfg.Scrapers) == 0 {
		err = multierr.Append(err, errors.New("must specify at least one scraper"))
	}

	for i, device := range cfg.Devices {
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
	err = multierr.Append(err, cfg.validateNexusDashboard())
	err = multierr.Append(err, cfg.validateACI())

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

	baseURL := cfg.Meraki.BaseURL
	if baseURL == "" {
		baseURL = defaultMerakiConfig().BaseURL
	}
	parsed, parseErr := url.Parse(baseURL)
	if parseErr != nil || parsed.Scheme == "" || parsed.Host == "" {
		err = multierr.Append(err, errors.New("meraki.base_url must be a valid absolute URL"))
	} else if parsed.Scheme != "https" && parsed.Scheme != "http" {
		err = multierr.Append(err, errors.New("meraki.base_url scheme must be http or https"))
	}

	for i, org := range cfg.Meraki.Organizations {
		if org.OrganizationID == "" {
			err = multierr.Append(err, fmt.Errorf("meraki.organizations[%d].organization_id cannot be empty", i))
		}
		if org.TagsFilterType != "" && org.TagsFilterType != "withAnyTags" && org.TagsFilterType != "withAllTags" {
			err = multierr.Append(err, fmt.Errorf("meraki.organizations[%d].tags_filter_type must be withAnyTags or withAllTags", i))
		}
	}

	for i, device := range cfg.Meraki.Devices {
		if device.OrganizationID == "" {
			err = multierr.Append(err, fmt.Errorf("meraki.devices[%d].organization_id cannot be empty", i))
		}
		if device.Serial == "" {
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
	} else if parsed.Scheme != "https" && parsed.Scheme != "http" {
		err = multierr.Append(err, errors.New("intersight.endpoint scheme must be http or https"))
	}

	if cfg.Intersight.PageSize < 0 {
		err = multierr.Append(err, errors.New("intersight.page_size must not be negative"))
	}
	if cfg.Intersight.MaxRetries < 0 {
		err = multierr.Append(err, errors.New("intersight.max_retries must not be negative"))
	}
	if cfg.Intersight.EventLookback < 0 {
		err = multierr.Append(err, errors.New("intersight.event_lookback must not be negative"))
	}
	if cfg.Intersight.TelemetryLookback < 0 {
		err = multierr.Append(err, errors.New("intersight.telemetry_lookback must not be negative"))
	}

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
		if group.MaxResults < 0 {
			err = multierr.Append(err, fmt.Errorf("intersight.%s.max_results must not be negative", name))
		}
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
		err = multierr.Append(err, validateHTTPURL("catalyst_center.endpoint", cfg.CatalystCenter.Endpoint))
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
	if cfg.CatalystCenter.MaxRetries < 0 {
		err = multierr.Append(err, errors.New("catalyst_center.max_retries must not be negative"))
	}
	if cfg.CatalystCenter.Lookback < 0 {
		err = multierr.Append(err, errors.New("catalyst_center.lookback must not be negative"))
	}

	for i, target := range cfg.CatalystCenter.Targets.DeviceDetails {
		if !validCatalystCenterDeviceIdentifier(target.Identifier) {
			err = multierr.Append(err, fmt.Errorf("catalyst_center.targets.device_details[%d].identifier must be macAddress, nwDeviceName, or uuid", i))
		}
		if target.SearchBy == "" {
			err = multierr.Append(err, fmt.Errorf("catalyst_center.targets.device_details[%d].search_by cannot be empty", i))
		}
	}
	for i, mac := range cfg.CatalystCenter.Targets.ClientMACs {
		if mac == "" {
			err = multierr.Append(err, fmt.Errorf("catalyst_center.targets.client_macs[%d] cannot be empty", i))
		}
	}

	groups := map[string]CatalystCenterGroupConfig{
		"inventory":  cfg.CatalystCenter.Inventory,
		"interfaces": cfg.CatalystCenter.Interfaces,
		"health":     cfg.CatalystCenter.Health,
		"topology":   cfg.CatalystCenter.Topology,
		"issues":     cfg.CatalystCenter.Issues,
		"details":    cfg.CatalystCenter.Details,
	}
	for name, group := range groups {
		if group.MaxResults < 0 {
			err = multierr.Append(err, fmt.Errorf("catalyst_center.%s.max_results must not be negative", name))
		}
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
		err = multierr.Append(err, validateHTTPURL("nexus_dashboard.endpoint", cfg.NexusDashboard.Endpoint))
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

	if cfg.NexusDashboard.PageSize < 0 {
		err = multierr.Append(err, errors.New("nexus_dashboard.page_size must not be negative"))
	}
	if cfg.NexusDashboard.MaxRetries < 0 {
		err = multierr.Append(err, errors.New("nexus_dashboard.max_retries must not be negative"))
	}
	if cfg.NexusDashboard.EventLookback < 0 {
		err = multierr.Append(err, errors.New("nexus_dashboard.event_lookback must not be negative"))
	}
	if cfg.NexusDashboard.TelemetryLookback < 0 {
		err = multierr.Append(err, errors.New("nexus_dashboard.telemetry_lookback must not be negative"))
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
		err = multierr.Append(err, validateHTTPURL(fmt.Sprintf("aci.controllers[%d].endpoint", i), controller.Endpoint))
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

	if cfg.ACI.PageSize < 0 {
		err = multierr.Append(err, errors.New("aci.page_size must not be negative"))
	}
	if cfg.ACI.MaxRetries < 0 {
		err = multierr.Append(err, errors.New("aci.max_retries must not be negative"))
	}
	if cfg.ACI.EventLookback < 0 {
		err = multierr.Append(err, errors.New("aci.event_lookback must not be negative"))
	}
	if cfg.ACI.StatsLookback < 0 {
		err = multierr.Append(err, errors.New("aci.stats_lookback must not be negative"))
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

func validateHTTPURL(name, value string) error {
	parsed, parseErr := url.Parse(value)
	if parseErr != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("%s must be a valid absolute URL", name)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("%s scheme must be http or https", name)
	}
	return nil
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

func validateNexusControllerGroups(prefix string, groups map[string]NexusControllerGroupConfig) error {
	var err error
	for name, group := range groups {
		if group.MaxResults < 0 {
			err = multierr.Append(err, fmt.Errorf("%s.%s.max_results must not be negative", prefix, name))
		}
	}
	return err
}

// Unmarshal a config.Parser into the config struct.
func (cfg *Config) Unmarshal(componentParser *confmap.Conf) error {
	if componentParser == nil {
		return nil
	}

	// load the non-dynamic config normally
	if err := componentParser.Unmarshal(cfg, confmap.WithIgnoreUnused()); err != nil {
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
