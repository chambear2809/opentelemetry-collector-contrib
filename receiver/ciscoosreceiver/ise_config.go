// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/collector/config/configopaque"
	"go.uber.org/multierr"
)

const (
	defaultISEPortDataConnect = 2484
	maxISEERSPageSize         = 100
)

// ISEAuthConfig represents Cisco ISE REST API authentication settings.
type ISEAuthConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Username string              `mapstructure:"username"`
	Password configopaque.String `mapstructure:"password"`
}

// ISEGroupConfig controls a curated Cisco ISE collection group.
type ISEGroupConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled    bool `mapstructure:"enabled"`
	MaxResults int  `mapstructure:"max_results"`
}

// ISETargetFilters limits Cisco ISE collection to relevant nodes, users, devices, endpoints, and policies.
type ISETargetFilters struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	NodeNames          []string `mapstructure:"node_names"`
	NetworkDeviceNames []string `mapstructure:"network_device_names"`
	NetworkDeviceIPs   []string `mapstructure:"network_device_ips"`
	EndpointMACs       []string `mapstructure:"endpoint_macs"`
	Usernames          []string `mapstructure:"usernames"`
	PolicyNames        []string `mapstructure:"policy_names"`
	SecurityGroupNames []string `mapstructure:"security_group_names"`
	PxGridServices     []string `mapstructure:"pxgrid_services"`
}

// ISEPxGridSubscriptionConfig controls pxGrid streaming topics.
type ISEPxGridSubscriptionConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Session        bool `mapstructure:"session"`
	RadiusFailures bool `mapstructure:"radius_failures"`
	Endpoint       bool `mapstructure:"endpoint"`
	TrustSec       bool `mapstructure:"trustsec"`
	SystemHealth   bool `mapstructure:"system_health"`
}

// ISEPxGridConfig controls Cisco ISE pxGrid REST and streaming collection.
type ISEPxGridConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled               bool                        `mapstructure:"enabled"`
	Endpoint              string                      `mapstructure:"endpoint"`
	NodeName              string                      `mapstructure:"node_name"`
	Password              configopaque.String         `mapstructure:"password"`
	CertFile              string                      `mapstructure:"cert_file"`
	KeyFile               string                      `mapstructure:"key_file"`
	CAFile                string                      `mapstructure:"ca_file"`
	ServerName            string                      `mapstructure:"server_name"`
	InsecureSkipVerify    bool                        `mapstructure:"insecure_skip_verify"`
	AllowedServiceHosts   []string                    `mapstructure:"allowed_service_hosts"`
	AllowedServiceOrigins []string                    `mapstructure:"allowed_service_origins"`
	AutoActivate          bool                        `mapstructure:"auto_activate"`
	Streaming             bool                        `mapstructure:"streaming"`
	Subscriptions         ISEPxGridSubscriptionConfig `mapstructure:"subscriptions"`
	MaxResults            int                         `mapstructure:"max_results"`
}

// ISEDataConnectConfig controls Cisco ISE Data Connect read-only database access.
type ISEDataConnectConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled            bool                      `mapstructure:"enabled"`
	Host               string                    `mapstructure:"host"`
	Port               int                       `mapstructure:"port"`
	ServiceName        string                    `mapstructure:"service_name"`
	Username           string                    `mapstructure:"username"`
	Password           configopaque.String       `mapstructure:"password"`
	WalletDir          string                    `mapstructure:"wallet_dir"`
	CAFile             string                    `mapstructure:"ca_file"`
	ServerName         string                    `mapstructure:"server_name"`
	SSL                bool                      `mapstructure:"ssl"`
	SSLVerify          bool                      `mapstructure:"ssl_verify"`
	Lookback           time.Duration             `mapstructure:"lookback"`
	RowLimit           int                       `mapstructure:"row_limit"`
	FullViews          bool                      `mapstructure:"full_views"`
	AdditionalReadOnly []string                  `mapstructure:"additional_read_only_views"`
	Views              map[string]ISEGroupConfig `mapstructure:"views"`
}

// ISEConfig defines Cisco Identity Services Engine REST, pxGrid, and Data Connect polling settings.
type ISEConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Enabled            bool                 `mapstructure:"enabled"`
	Endpoint           string               `mapstructure:"endpoint"`
	Auth               ISEAuthConfig        `mapstructure:"auth"`
	UserAgent          string               `mapstructure:"user_agent"`
	PageSize           int                  `mapstructure:"page_size"`
	MaxRetries         int                  `mapstructure:"max_retries"`
	CAFile             string               `mapstructure:"ca_file"`
	ServerName         string               `mapstructure:"server_name"`
	InsecureSkipVerify bool                 `mapstructure:"insecure_skip_verify"`
	EventLookback      time.Duration        `mapstructure:"event_lookback"`
	SessionLookback    time.Duration        `mapstructure:"session_lookback"`
	MaxResults         int                  `mapstructure:"max_results"`
	Targets            ISETargetFilters     `mapstructure:"targets"`
	Deployment         ISEGroupConfig       `mapstructure:"deployment"`
	NetworkDevices     ISEGroupConfig       `mapstructure:"network_devices"`
	Endpoints          ISEGroupConfig       `mapstructure:"endpoints"`
	Sessions           ISEGroupConfig       `mapstructure:"sessions"`
	SessionDetails     ISEGroupConfig       `mapstructure:"session_details"`
	AuthFailures       ISEGroupConfig       `mapstructure:"auth_failures"`
	Accounting         ISEGroupConfig       `mapstructure:"accounting"`
	Policy             ISEGroupConfig       `mapstructure:"policy"`
	Posture            ISEGroupConfig       `mapstructure:"posture"`
	Profiler           ISEGroupConfig       `mapstructure:"profiler"`
	TrustSec           ISEGroupConfig       `mapstructure:"trustsec"`
	Alarms             ISEGroupConfig       `mapstructure:"alarms"`
	Certificates       ISEGroupConfig       `mapstructure:"certificates"`
	Licensing          ISEGroupConfig       `mapstructure:"licensing"`
	Webhooks           ISEGroupConfig       `mapstructure:"webhooks"`
	PxGrid             ISEPxGridConfig      `mapstructure:"pxgrid"`
	DataConnect        ISEDataConnectConfig `mapstructure:"data_connect"`
}

func defaultISEGroupConfig(maxResults int) ISEGroupConfig {
	return ISEGroupConfig{
		Enabled:    true,
		MaxResults: maxResults,
	}
}

func defaultISEOptInGroupConfig(maxResults int) ISEGroupConfig {
	return ISEGroupConfig{MaxResults: maxResults}
}

func defaultISEConfig() ISEConfig {
	return ISEConfig{
		UserAgent:       "opentelemetry-collector-contrib-ciscoosreceiver",
		PageSize:        maxISEERSPageSize,
		MaxRetries:      3,
		EventLookback:   24 * time.Hour,
		SessionLookback: 15 * time.Minute,
		MaxResults:      1000,
		Deployment:      defaultISEOptInGroupConfig(1000),
		NetworkDevices:  defaultISEOptInGroupConfig(5000),
		Endpoints:       defaultISEOptInGroupConfig(5000),
		Sessions:        defaultISEGroupConfig(5000),
		SessionDetails:  defaultISEOptInGroupConfig(5000),
		AuthFailures:    defaultISEOptInGroupConfig(5000),
		Accounting:      defaultISEOptInGroupConfig(5000),
		Policy:          defaultISEOptInGroupConfig(5000),
		Posture:         defaultISEOptInGroupConfig(5000),
		Profiler:        defaultISEOptInGroupConfig(5000),
		TrustSec:        defaultISEOptInGroupConfig(5000),
		Alarms:          defaultISEOptInGroupConfig(1000),
		Certificates:    defaultISEOptInGroupConfig(1000),
		Licensing:       defaultISEOptInGroupConfig(1000),
		Webhooks:        defaultISEOptInGroupConfig(1000),
		PxGrid: ISEPxGridConfig{
			Subscriptions: ISEPxGridSubscriptionConfig{
				Session:        true,
				RadiusFailures: true,
				Endpoint:       true,
				TrustSec:       true,
			},
			MaxResults: 5000,
		},
		DataConnect: ISEDataConnectConfig{
			Port:      defaultISEPortDataConnect,
			SSL:       true,
			SSLVerify: true,
			Lookback:  24 * time.Hour,
			RowLimit:  5000,
			Views: map[string]ISEGroupConfig{
				"NODE_LIST":                           defaultISEGroupConfig(1000),
				"NETWORK_DEVICES":                     defaultISEGroupConfig(5000),
				"NETWORK_DEVICE_GROUPS":               defaultISEGroupConfig(5000),
				"POLICY_SETS":                         defaultISEGroupConfig(5000),
				"OPENAPI_OPERATIONS":                  defaultISEGroupConfig(5000),
				"ADMINISTRATOR_LOGINS":                defaultISEGroupConfig(5000),
				"ADMIN_USERS":                         defaultISEGroupConfig(5000),
				"RADIUS_AUTHENTICATIONS_WEEK":         defaultISEGroupConfig(5000),
				"RADIUS_ACCOUNTING_WEEK":              defaultISEGroupConfig(5000),
				"TACACS_AUTHENTICATION_LAST_TWO_DAYS": defaultISEGroupConfig(5000),
				"TACACS_AUTHORIZATION_LAST_TWO_DAYS":  defaultISEGroupConfig(5000),
				"TACACS_ACCOUNTING_LAST_TWO_DAYS":     defaultISEGroupConfig(5000),
				"TACACS_COMMAND_ACCOUNTING":           defaultISEGroupConfig(5000),
				"POSTURE_ASSESSMENT_BY_ENDPOINT":      defaultISEGroupConfig(5000),
				"PROFILED_ENDPOINTS_SUMMARY":          defaultISEGroupConfig(5000),
				"PROFILING_POLICIES":                  defaultISEGroupConfig(5000),
				"ADAPTIVE_NETWORK_CONTROL":            defaultISEGroupConfig(5000),
				"THREAT_EVENTS":                       defaultISEGroupConfig(5000),
				"USER_IDENTITY_GROUPS":                defaultISEGroupConfig(5000),
			},
		},
	}
}

func (cfg ISEConfig) hasTarget() bool {
	return cfg.Enabled ||
		cfg.Endpoint != "" ||
		cfg.Auth.Username != "" ||
		cfg.Auth.Password != "" ||
		cfg.PxGrid.hasTarget() ||
		cfg.DataConnect.hasTarget()
}

func (cfg ISEPxGridConfig) hasTarget() bool {
	return cfg.Enabled ||
		cfg.Endpoint != "" ||
		cfg.NodeName != "" ||
		cfg.Password != "" ||
		cfg.CertFile != "" ||
		cfg.KeyFile != ""
}

func (cfg ISEDataConnectConfig) hasTarget() bool {
	return cfg.Enabled ||
		cfg.Host != "" ||
		cfg.ServiceName != "" ||
		cfg.Username != "" ||
		cfg.Password != "" ||
		cfg.WalletDir != "" ||
		cfg.CAFile != "" ||
		cfg.ServerName != ""
}

func (cfg *Config) validateISE() error {
	if !cfg.ISE.hasTarget() {
		return nil
	}

	var err error
	ise := cfg.ISE.withDefaults()
	if cfg.ISE.Endpoint == "" {
		err = multierr.Append(err, errors.New("ise.endpoint must be provided"))
	} else {
		err = multierr.Append(err, validateHTTPURL("ise.endpoint", cfg.ISE.Endpoint, cfg.ISE.InsecureSkipVerify))
	}
	if cfg.ISE.Auth.Username == "" {
		err = multierr.Append(err, errors.New("ise.auth.username must be provided"))
	}
	if cfg.ISE.Auth.Password == "" {
		err = multierr.Append(err, errors.New("ise.auth.password must be provided"))
	}
	if ise.PageSize < 1 || ise.PageSize > maxISEERSPageSize {
		err = multierr.Append(err, fmt.Errorf("ise.page_size must be between 1 and %d", maxISEERSPageSize))
	}
	err = multierr.Append(err, validateMaxRetries("ise.max_retries", ise.MaxRetries))
	if ise.EventLookback < 0 {
		err = multierr.Append(err, errors.New("ise.event_lookback must not be negative"))
	}
	if ise.SessionLookback < 0 {
		err = multierr.Append(err, errors.New("ise.session_lookback must not be negative"))
	}
	err = multierr.Append(err, validateMaxResults("ise.max_results", ise.MaxResults))
	if !ise.anyCollectionGroupEnabled() {
		err = multierr.Append(err, errors.New("ise requires at least one enabled collection group"))
	}
	err = multierr.Append(err, validateISETargets("ise.targets", ise.Targets))
	err = multierr.Append(err, validateISEGroups("ise", ise.groups()))
	pxGrid := ise.PxGrid
	if pxGrid.hasTarget() && pxGrid.Endpoint == "" {
		pxGrid.Endpoint = defaultISEPxGridEndpoint(ise.Endpoint)
	}
	err = multierr.Append(err, validateISEPxGrid(pxGrid))
	err = multierr.Append(err, validateISEDataConnect(ise.DataConnect))
	return err
}

func (cfg ISEConfig) withDefaults() ISEConfig {
	defaults := defaultISEConfig()
	if cfg.UserAgent == "" {
		cfg.UserAgent = defaults.UserAgent
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = defaults.PageSize
	}
	if cfg.EventLookback == 0 {
		cfg.EventLookback = defaults.EventLookback
	}
	if cfg.SessionLookback == 0 {
		cfg.SessionLookback = defaults.SessionLookback
	}
	if cfg.MaxResults == 0 {
		cfg.MaxResults = defaults.MaxResults
	}
	cfg.Deployment = cfg.Deployment.withDefault(defaults.Deployment)
	cfg.NetworkDevices = cfg.NetworkDevices.withDefault(defaults.NetworkDevices)
	cfg.Endpoints = cfg.Endpoints.withDefault(defaults.Endpoints)
	cfg.Sessions = cfg.Sessions.withDefault(defaults.Sessions)
	cfg.SessionDetails = cfg.SessionDetails.withDefault(defaults.SessionDetails)
	cfg.AuthFailures = cfg.AuthFailures.withDefault(defaults.AuthFailures)
	cfg.Accounting = cfg.Accounting.withDefault(defaults.Accounting)
	cfg.Policy = cfg.Policy.withDefault(defaults.Policy)
	cfg.Posture = cfg.Posture.withDefault(defaults.Posture)
	cfg.Profiler = cfg.Profiler.withDefault(defaults.Profiler)
	cfg.TrustSec = cfg.TrustSec.withDefault(defaults.TrustSec)
	cfg.Alarms = cfg.Alarms.withDefault(defaults.Alarms)
	cfg.Certificates = cfg.Certificates.withDefault(defaults.Certificates)
	cfg.Licensing = cfg.Licensing.withDefault(defaults.Licensing)
	cfg.Webhooks = cfg.Webhooks.withDefault(defaults.Webhooks)
	cfg.PxGrid = cfg.PxGrid.withDefault(defaults.PxGrid)
	cfg.DataConnect = cfg.DataConnect.withDefault(defaults.DataConnect)
	return cfg
}

func (cfg ISEGroupConfig) withDefault(defaults ISEGroupConfig) ISEGroupConfig {
	if cfg.MaxResults == 0 {
		cfg.MaxResults = defaults.MaxResults
	}
	return cfg
}

func (cfg ISEPxGridConfig) withDefault(defaults ISEPxGridConfig) ISEPxGridConfig {
	if cfg.MaxResults == 0 {
		cfg.MaxResults = defaults.MaxResults
	}
	return cfg
}

func (cfg ISEDataConnectConfig) withDefault(defaults ISEDataConnectConfig) ISEDataConnectConfig {
	if cfg.Port == 0 {
		cfg.Port = defaults.Port
	}
	if cfg.Lookback == 0 {
		cfg.Lookback = defaults.Lookback
	}
	if cfg.RowLimit == 0 {
		cfg.RowLimit = defaults.RowLimit
	}
	if cfg.Views == nil {
		cfg.Views = defaults.Views
	}
	return cfg
}

func (cfg ISEConfig) anyCollectionGroupEnabled() bool {
	for _, group := range cfg.groups() {
		if group.Enabled {
			return true
		}
	}
	return cfg.PxGrid.Enabled || cfg.DataConnect.Enabled
}

func (cfg ISEConfig) groups() map[string]ISEGroupConfig {
	return map[string]ISEGroupConfig{
		"deployment":      cfg.Deployment,
		"network_devices": cfg.NetworkDevices,
		"endpoints":       cfg.Endpoints,
		"sessions":        cfg.Sessions,
		"session_details": cfg.SessionDetails,
		"auth_failures":   cfg.AuthFailures,
		"accounting":      cfg.Accounting,
		"policy":          cfg.Policy,
		"posture":         cfg.Posture,
		"profiler":        cfg.Profiler,
		"trustsec":        cfg.TrustSec,
		"alarms":          cfg.Alarms,
		"certificates":    cfg.Certificates,
		"licensing":       cfg.Licensing,
		"webhooks":        cfg.Webhooks,
	}
}

func validateISEGroups(prefix string, groups map[string]ISEGroupConfig) error {
	var err error
	for name, group := range groups {
		err = multierr.Append(err, validateMaxResults(prefix+"."+name+".max_results", group.MaxResults))
	}
	return err
}

func validateISETargets(prefix string, targets ISETargetFilters) error {
	var err error
	for name, values := range map[string][]string{
		"node_names":           targets.NodeNames,
		"network_device_names": targets.NetworkDeviceNames,
		"usernames":            targets.Usernames,
		"policy_names":         targets.PolicyNames,
		"security_group_names": targets.SecurityGroupNames,
		"pxgrid_services":      targets.PxGridServices,
	} {
		seen := map[string]struct{}{}
		for i, value := range values {
			normalized := strings.ToLower(strings.TrimSpace(value))
			if normalized == "" {
				err = multierr.Append(err, fmt.Errorf("%s.%s[%d] cannot be empty", prefix, name, i))
				continue
			}
			if _, exists := seen[normalized]; exists {
				err = multierr.Append(err, fmt.Errorf("%s.%s[%d] duplicates another target", prefix, name, i))
			}
			seen[normalized] = struct{}{}
		}
	}
	err = multierr.Append(err, validateIPAddressList(prefix+".network_device_ips", targets.NetworkDeviceIPs))
	err = multierr.Append(err, validateMACAddressList(prefix+".endpoint_macs", targets.EndpointMACs))
	return err
}

func validateISEPxGrid(cfg ISEPxGridConfig) error {
	if !cfg.hasTarget() {
		return nil
	}
	var err error
	if cfg.Endpoint != "" {
		err = multierr.Append(err, validateHTTPURL("ise.pxgrid.endpoint", cfg.Endpoint, false))
	}
	for i, host := range cfg.AllowedServiceHosts {
		if !validHostOrIP(strings.TrimSpace(host)) {
			err = multierr.Append(err, fmt.Errorf("ise.pxgrid.allowed_service_hosts[%d] must be a valid hostname or IP address", i))
		}
	}
	for i, origin := range cfg.AllowedServiceOrigins {
		parsed, parseErr := url.Parse(strings.TrimSpace(origin))
		if parseErr != nil || parsed.Host == "" || parsed.User != nil ||
			(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" ||
			(!strings.EqualFold(parsed.Scheme, "https") && !strings.EqualFold(parsed.Scheme, "wss")) {
			err = multierr.Append(err, fmt.Errorf("ise.pxgrid.allowed_service_origins[%d] must be an HTTPS or WSS origin without a path, query, fragment, or user information", i))
		}
	}
	if cfg.Enabled {
		if cfg.NodeName == "" {
			err = multierr.Append(err, errors.New("ise.pxgrid.node_name must be provided when pxGrid is enabled"))
		}
		if cfg.Password == "" && (cfg.CertFile == "" || cfg.KeyFile == "") {
			err = multierr.Append(err, errors.New("ise.pxgrid.password or both ise.pxgrid.cert_file and ise.pxgrid.key_file must be provided"))
		}
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		err = multierr.Append(err, errors.New("ise.pxgrid.cert_file and ise.pxgrid.key_file must be provided together"))
	}
	if cfg.Streaming && !cfg.Enabled {
		err = multierr.Append(err, errors.New("ise.pxgrid.streaming requires ise.pxgrid.enabled"))
	}
	if cfg.Streaming && cfg.Subscriptions.SystemHealth {
		err = multierr.Append(err, errors.New("ise.pxgrid.subscriptions.system_health is not supported for streaming because Cisco ISE does not advertise a standard System topic"))
	}
	err = multierr.Append(err, validateMaxResults("ise.pxgrid.max_results", cfg.MaxResults))
	return err
}

func validateISEDataConnect(cfg ISEDataConnectConfig) error {
	if !cfg.hasTarget() {
		return nil
	}
	var err error
	if cfg.Port < 0 || cfg.Port > 65535 {
		err = multierr.Append(err, errors.New("ise.data_connect.port must be between 1 and 65535"))
	}
	if cfg.Enabled {
		if cfg.Host == "" {
			err = multierr.Append(err, errors.New("ise.data_connect.host must be provided when Data Connect is enabled"))
		}
		if cfg.ServiceName == "" {
			err = multierr.Append(err, errors.New("ise.data_connect.service_name must be provided when Data Connect is enabled"))
		}
		if cfg.Username == "" {
			err = multierr.Append(err, errors.New("ise.data_connect.username must be provided when Data Connect is enabled"))
		}
		if cfg.Password == "" {
			err = multierr.Append(err, errors.New("ise.data_connect.password must be provided when Data Connect is enabled"))
		}
		if !cfg.SSL {
			err = multierr.Append(err, errors.New("ise.data_connect.ssl must be true because Data Connect credentials require TLS"))
		}
	}
	if cfg.WalletDir != strings.TrimSpace(cfg.WalletDir) {
		err = multierr.Append(err, errors.New("ise.data_connect.wallet_dir must not contain surrounding whitespace"))
	} else if cfg.WalletDir != "" && strings.IndexByte(cfg.WalletDir, 0) >= 0 {
		err = multierr.Append(err, errors.New("ise.data_connect.wallet_dir must be a valid directory path"))
	}
	if cfg.CAFile != strings.TrimSpace(cfg.CAFile) {
		err = multierr.Append(err, errors.New("ise.data_connect.ca_file must not contain surrounding whitespace"))
	} else if cfg.CAFile != "" && strings.IndexByte(cfg.CAFile, 0) >= 0 {
		err = multierr.Append(err, errors.New("ise.data_connect.ca_file must be a valid file path"))
	}
	serverName := strings.TrimSpace(cfg.ServerName)
	if cfg.ServerName != serverName {
		err = multierr.Append(err, errors.New("ise.data_connect.server_name must not contain surrounding whitespace"))
	} else if serverName != "" && !validHostOrIP(serverName) {
		err = multierr.Append(err, errors.New("ise.data_connect.server_name must be a valid hostname or IP address without a scheme or port"))
	}
	if cfg.WalletDir != "" && cfg.CAFile != "" {
		err = multierr.Append(err, errors.New("ise.data_connect.wallet_dir cannot be combined with ca_file; use either an Oracle wallet or a PEM CA bundle"))
	}
	if !cfg.SSLVerify && cfg.CAFile != "" {
		err = multierr.Append(err, errors.New("ise.data_connect.ca_file requires ssl_verify to be true"))
	}
	if !cfg.SSLVerify && cfg.ServerName != "" {
		err = multierr.Append(err, errors.New("ise.data_connect.server_name requires ssl_verify to be true"))
	}
	if cfg.Lookback < 0 {
		err = multierr.Append(err, errors.New("ise.data_connect.lookback must not be negative"))
	}
	err = multierr.Append(err, validateMaxResults("ise.data_connect.row_limit", cfg.RowLimit))
	err = multierr.Append(err, validateISEGroups("ise.data_connect.views", cfg.Views))
	for view := range cfg.Views {
		normalized := strings.ToUpper(strings.TrimSpace(view))
		if normalized == "" {
			err = multierr.Append(err, errors.New("ise.data_connect.views cannot include an empty view name"))
			continue
		}
		if !validISEDataConnectViewName(normalized) {
			err = multierr.Append(err, fmt.Errorf("ise.data_connect.views.%s must be a valid view name", view))
		}
		if isISEInternalDataConnectView(normalized) {
			err = multierr.Append(err, fmt.Errorf("ise.data_connect.views.%s must not include internal view %s", view, view))
		}
	}
	seenAdditional := map[string]struct{}{}
	for i, view := range cfg.AdditionalReadOnly {
		normalized := strings.ToUpper(strings.TrimSpace(view))
		if normalized == "" {
			err = multierr.Append(err, fmt.Errorf("ise.data_connect.additional_read_only_views[%d] cannot be empty", i))
			continue
		}
		if !validISEDataConnectViewName(normalized) {
			err = multierr.Append(err, fmt.Errorf("ise.data_connect.additional_read_only_views[%d] must be a valid view name", i))
		}
		if isISEInternalDataConnectView(normalized) {
			err = multierr.Append(err, fmt.Errorf("ise.data_connect.additional_read_only_views[%d] must not include internal view %s", i, view))
		}
		if _, exists := seenAdditional[normalized]; exists {
			err = multierr.Append(err, fmt.Errorf("ise.data_connect.additional_read_only_views[%d] duplicates another view", i))
		}
		seenAdditional[normalized] = struct{}{}
	}
	return err
}

func validISEDataConnectViewName(view string) bool {
	if view == "" {
		return false
	}
	for i, r := range view {
		if i == 0 && (r < 'A' || r > 'Z') {
			return false
		}
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

func isISEInternalDataConnectView(view string) bool {
	switch strings.ToUpper(strings.TrimSpace(view)) {
	case "UPSPOLICY", "UPSPOLICYSET", "UPSPOLICYSET_POLICIES":
		return true
	default:
		return false
	}
}
