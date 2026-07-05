// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

const (
	gnmiProductCatalyst9800 = "catalyst_9800"
	gnmiProductASR9000      = "asr_9000"
	gnmiProductNCS5500      = "ncs_5500"
	gnmiProductNexus9000    = "nexus_9000"
	gnmiProductNexus3500    = "nexus_3500"

	gnmiReleaseTrainIOSXE1718 = "17.18"
	gnmiReleaseTrainIOSXR244  = "24.4"
	gnmiReleaseTrainNXOS106   = "10.6"
	gnmiReleaseTrainNXOS105   = "10.5"
)

type gnmiProductContractKey struct {
	Product      string
	ReleaseTrain string
}

// gnmiSoftwareVersion is the canonical build identity produced by a strict
// OS-family parser. Train remains populated for syntactically valid versions
// outside a contract's accepted train so live preflight can distinguish a
// release mismatch from malformed identity.
type gnmiSoftwareVersion struct {
	Canonical string
	Train     string
}

type gnmiIdentityProbe struct {
	Name         string
	Model        string
	PrefixTarget string
	PrefixOrigin string
	Paths        []sharedGNMIPath
}

type gnmiRequestPolicy struct {
	UsePathPrefix          bool
	StreamOnly             bool
	AllowWildcards         bool
	ConservativeSampleOnly bool
}

type gnmiVersionParser func(string) (gnmiSoftwareVersion, error)

// gnmiProductContract is the single internal authority for a qualified Cisco
// product and release train. Catalog maps and slices are immutable after
// package initialization.
type gnmiProductContract struct {
	Product           string
	ReleaseTrain      string
	OSFamily          string
	ChassisPattern    *regexp.Regexp
	ApprovedEncodings []gnmipb.Encoding
	IdentityProbes    []gnmiIdentityProbe
	RequestPolicy     gnmiRequestPolicy

	profiles      map[string]builtinGNMIProfileDefinition
	versionParser gnmiVersionParser
}

var (
	iosXEVersionPattern        = regexp.MustCompile(`^(\d{1,3})\.(\d{1,3})\.(\d{1,3})([A-Za-z])?$`)
	iosXEInstallVersionPattern = regexp.MustCompile(`^(\d{1,3})\.(\d{1,3})\.(\d{1,3})([A-Za-z]?)(\.0(?:\.[0-9]{1,10})?)$`)
	iosXRVersionPattern        = regexp.MustCompile(`^(\d{1,3})\.(\d{1,3})\.(\d{1,3})$`)
	nxOSVersionPattern         = regexp.MustCompile(`^([0-9]{1,3})\.([0-9]{1,3})\(([0-9]{1,3})([A-Za-z]?)\)([A-Za-z]?)$`)
	gnmiYANGIdentifierPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
)

var gnmiProductContracts = map[gnmiProductContractKey]*gnmiProductContract{
	{Product: gnmiProductCatalyst9800, ReleaseTrain: gnmiReleaseTrainIOSXE1718}: {
		Product:        gnmiProductCatalyst9800,
		ReleaseTrain:   gnmiReleaseTrainIOSXE1718,
		OSFamily:       gnmiPlatformIOSXE,
		ChassisPattern: regexp.MustCompile(`^(?:C9800-|CAT9800-)[A-Z0-9][A-Z0-9._-]*$`),
		ApprovedEncodings: []gnmipb.Encoding{
			gnmipb.Encoding_JSON_IETF,
			gnmipb.Encoding_JSON,
		},
		IdentityProbes: []gnmiIdentityProbe{
			{
				Name:         "ios_xe_hardware_inventory",
				Model:        "Cisco-IOS-XE-device-hardware-oper",
				PrefixOrigin: builtinGNMIOriginRFC7951,
				Paths: []sharedGNMIPath{{
					Path: "Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware/device-inventory",
				}},
			},
			{
				Name:         "ios_xe_current_install_version",
				Model:        "Cisco-IOS-XE-install-oper",
				PrefixOrigin: builtinGNMIOriginRFC7951,
				Paths: []sharedGNMIPath{{
					Path: "Cisco-IOS-XE-install-oper:install-oper-data/install-location-information/install-version-info",
				}},
			},
		},
		RequestPolicy: gnmiRequestPolicy{UsePathPrefix: true, StreamOnly: true, AllowWildcards: true},
		profiles:      iosXEBuiltinGNMIProfileCatalog,
		versionParser: parseIOSXESoftwareVersion,
	},
	{Product: gnmiProductASR9000, ReleaseTrain: gnmiReleaseTrainIOSXR244}: {
		Product:        gnmiProductASR9000,
		ReleaseTrain:   gnmiReleaseTrainIOSXR244,
		OSFamily:       gnmiPlatformIOSXR,
		ChassisPattern: regexp.MustCompile(`^ASR-9[A-Z0-9][A-Z0-9._-]*$`),
		ApprovedEncodings: []gnmipb.Encoding{
			gnmipb.Encoding_JSON_IETF,
			gnmipb.Encoding_JSON,
		},
		IdentityProbes: []gnmiIdentityProbe{{
			Name:         "ios_xr_install_version",
			Model:        "Cisco-IOS-XR-install-oper",
			PrefixOrigin: "Cisco-IOS-XR-install-oper",
			Paths:        []sharedGNMIPath{{Path: "install/version"}},
		}},
		RequestPolicy: gnmiRequestPolicy{UsePathPrefix: true, AllowWildcards: true},
		profiles:      iosXRBuiltinGNMIProfileCatalog,
		versionParser: parseIOSXRSoftwareVersion,
	},
	{Product: gnmiProductNCS5500, ReleaseTrain: gnmiReleaseTrainIOSXR244}: {
		Product:        gnmiProductNCS5500,
		ReleaseTrain:   gnmiReleaseTrainIOSXR244,
		OSFamily:       gnmiPlatformIOSXR,
		ChassisPattern: regexp.MustCompile(`^NCS-55[A-Z0-9][A-Z0-9._-]*$`),
		ApprovedEncodings: []gnmipb.Encoding{
			gnmipb.Encoding_JSON_IETF,
			gnmipb.Encoding_JSON,
		},
		IdentityProbes: []gnmiIdentityProbe{{
			Name:         "ios_xr_install_version",
			Model:        "Cisco-IOS-XR-install-oper",
			PrefixOrigin: "Cisco-IOS-XR-install-oper",
			Paths:        []sharedGNMIPath{{Path: "install/version"}},
		}},
		RequestPolicy: gnmiRequestPolicy{UsePathPrefix: true, AllowWildcards: true},
		profiles:      iosXRBuiltinGNMIProfileCatalog,
		versionParser: parseIOSXRSoftwareVersion,
	},
	{Product: gnmiProductNexus9000, ReleaseTrain: gnmiReleaseTrainNXOS106}: {
		Product:           gnmiProductNexus9000,
		ReleaseTrain:      gnmiReleaseTrainNXOS106,
		OSFamily:          gnmiPlatformNXOS,
		ChassisPattern:    regexp.MustCompile(`^N9K-[A-Z0-9][A-Z0-9._-]*$`),
		ApprovedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON},
		IdentityProbes: []gnmiIdentityProbe{{
			Name:  "nx_os_openconfig_platform",
			Model: "openconfig-platform",
			Paths: []sharedGNMIPath{{
				Origin: builtinGNMIOriginOpenConfig,
				Path:   "components/component/state",
			}},
		}},
		RequestPolicy: gnmiRequestPolicy{StreamOnly: true, ConservativeSampleOnly: true},
		profiles:      nxOSBuiltinGNMIProfileCatalog,
		versionParser: parseNXOSSoftwareVersion,
	},
	{Product: gnmiProductNexus3500, ReleaseTrain: gnmiReleaseTrainNXOS105}: {
		Product:           gnmiProductNexus3500,
		ReleaseTrain:      gnmiReleaseTrainNXOS105,
		OSFamily:          gnmiPlatformNXOS,
		ChassisPattern:    regexp.MustCompile(`^N3K-C35[A-Z0-9][A-Z0-9._-]*$`),
		ApprovedEncodings: []gnmipb.Encoding{gnmipb.Encoding_JSON},
		IdentityProbes: []gnmiIdentityProbe{{
			Name:  "nx_os_openconfig_platform",
			Model: "openconfig-platform",
			Paths: []sharedGNMIPath{{
				Origin: builtinGNMIOriginOpenConfig,
				Path:   "components/component/state",
			}},
		}},
		RequestPolicy: gnmiRequestPolicy{StreamOnly: true, ConservativeSampleOnly: true},
		profiles:      nxOSBuiltinGNMIProfileCatalog,
		versionParser: parseNXOSSoftwareVersion,
	},
}

func resolveGNMIProductContract(product, softwareVersion string) (*gnmiProductContract, gnmiSoftwareVersion, error) {
	if strings.EqualFold(strings.TrimSpace(product), "sonic") || strings.EqualFold(strings.TrimSpace(product), "cisco_sonic") {
		return nil, gnmiSoftwareVersion{}, errors.New("Cisco SONiC has no qualified gNMI product contract")
	}
	definition, ok := gnmiProductDefinition(product)
	if !ok {
		return nil, gnmiSoftwareVersion{}, fmt.Errorf(
			"product must be one of %s, %s, %s, %s, or %s",
			gnmiProductCatalyst9800,
			gnmiProductASR9000,
			gnmiProductNCS5500,
			gnmiProductNexus9000,
			gnmiProductNexus3500,
		)
	}
	if softwareVersion == "" {
		return nil, gnmiSoftwareVersion{}, errorsForMissingGNMISoftwareVersion(product)
	}
	parsed, err := definition.parser(softwareVersion)
	if err != nil {
		return nil, gnmiSoftwareVersion{}, fmt.Errorf("software_version %q is invalid for product %q: %w", softwareVersion, product, err)
	}
	contract := gnmiProductContracts[gnmiProductContractKey{Product: product, ReleaseTrain: parsed.Train}]
	if contract == nil {
		return nil, parsed, fmt.Errorf(
			"software_version %q is in release train %s, but product %q requires release train %s",
			softwareVersion,
			parsed.Train,
			product,
			definition.releaseTrain,
		)
	}
	return contract, parsed, nil
}

func errorsForMissingGNMISoftwareVersion(product string) error {
	return fmt.Errorf("software_version is required for product %q and must identify the exact expected running build", product)
}

func gnmiProductContractForTarget(target GNMITargetConfig) (*gnmiProductContract, gnmiSoftwareVersion, error) {
	return resolveGNMIProductContract(target.Product, target.SoftwareVersion)
}

func (contract *gnmiProductContract) ParseSoftwareVersion(raw string) (gnmiSoftwareVersion, error) {
	if contract == nil || contract.versionParser == nil {
		return gnmiSoftwareVersion{}, errors.New("gNMI product contract has no software-version parser")
	}
	return contract.versionParser(raw)
}

func (contract *gnmiProductContract) MatchesChassis(raw string) bool {
	if contract == nil || contract.ChassisPattern == nil {
		return false
	}
	return contract.ChassisPattern.MatchString(strings.ToUpper(strings.TrimSpace(raw)))
}

type gnmiProductDefinitionEntry struct {
	releaseTrain string
	parser       gnmiVersionParser
}

func gnmiProductDefinition(product string) (gnmiProductDefinitionEntry, bool) {
	switch product {
	case gnmiProductCatalyst9800:
		return gnmiProductDefinitionEntry{releaseTrain: gnmiReleaseTrainIOSXE1718, parser: parseIOSXESoftwareVersion}, true
	case gnmiProductASR9000, gnmiProductNCS5500:
		return gnmiProductDefinitionEntry{releaseTrain: gnmiReleaseTrainIOSXR244, parser: parseIOSXRSoftwareVersion}, true
	case gnmiProductNexus9000:
		return gnmiProductDefinitionEntry{releaseTrain: gnmiReleaseTrainNXOS106, parser: parseNXOSSoftwareVersion}, true
	case gnmiProductNexus3500:
		return gnmiProductDefinitionEntry{releaseTrain: gnmiReleaseTrainNXOS105, parser: parseNXOSSoftwareVersion}, true
	default:
		return gnmiProductDefinitionEntry{}, false
	}
}

func parseIOSXESoftwareVersion(raw string) (gnmiSoftwareVersion, error) {
	parts, err := parseGNMIVersionParts(raw, iosXEVersionPattern, "major.minor.maintenance with an optional single-letter rebuild suffix")
	if err != nil {
		return gnmiSoftwareVersion{}, err
	}
	suffix := strings.ToLower(parts[3])
	return gnmiSoftwareVersion{
		Canonical: parts[0] + "." + parts[1] + "." + parts[2] + suffix,
		Train:     parts[0] + "." + parts[1],
	}, nil
}

// parseIOSXEInstallSoftwareVersion normalizes the internal install-version
// list key documented by Cisco (for example, 17.18.01.0.1186) to the public
// IOS XE release label used by configuration and os.version. The separate
// opaque version-extension list key is not part of either representation.
func parseIOSXEInstallSoftwareVersion(raw string) (gnmiSoftwareVersion, error) {
	if parsed, err := parseIOSXESoftwareVersion(raw); err == nil {
		return parsed, nil
	}
	parts, err := parseGNMIVersionParts(
		raw,
		iosXEInstallVersionPattern,
		"the IOS XE install-version major.minor.maintenance[rebuild].0[.build] form",
	)
	if err != nil {
		return gnmiSoftwareVersion{}, err
	}
	suffix := strings.ToLower(parts[3])
	return gnmiSoftwareVersion{
		Canonical: parts[0] + "." + parts[1] + "." + parts[2] + suffix,
		Train:     parts[0] + "." + parts[1],
	}, nil
}

func parseIOSXRSoftwareVersion(raw string) (gnmiSoftwareVersion, error) {
	parts, err := parseGNMIVersionParts(raw, iosXRVersionPattern, "major.minor.maintenance")
	if err != nil {
		return gnmiSoftwareVersion{}, err
	}
	return gnmiSoftwareVersion{
		Canonical: parts[0] + "." + parts[1] + "." + parts[2],
		Train:     parts[0] + "." + parts[1],
	}, nil
}

func parseNXOSSoftwareVersion(raw string) (gnmiSoftwareVersion, error) {
	const syntax = "major.minor(maintenance) with optional single-letter maintenance and image suffixes"
	if raw == "" || strings.TrimSpace(raw) != raw {
		return gnmiSoftwareVersion{}, fmt.Errorf("must use %s without surrounding whitespace", syntax)
	}
	matches := nxOSVersionPattern.FindStringSubmatch(raw)
	if matches == nil {
		return gnmiSoftwareVersion{}, fmt.Errorf("must use %s", syntax)
	}
	parts := [3]string{}
	for index := range parts {
		value, err := strconv.ParseUint(matches[index+1], 10, 16)
		if err != nil {
			return gnmiSoftwareVersion{}, fmt.Errorf("numeric version component %q is invalid", matches[index+1])
		}
		parts[index] = strconv.FormatUint(value, 10)
	}
	maintenanceSuffix := strings.ToLower(matches[4])
	imageSuffix := strings.ToUpper(matches[5])
	return gnmiSoftwareVersion{
		Canonical: parts[0] + "." + parts[1] + "(" + parts[2] + maintenanceSuffix + ")" + imageSuffix,
		Train:     parts[0] + "." + parts[1],
	}, nil
}

func parseGNMIVersionParts(raw string, pattern *regexp.Regexp, syntax string) ([4]string, error) {
	var out [4]string
	if raw == "" || strings.TrimSpace(raw) != raw {
		return out, fmt.Errorf("must use %s without surrounding whitespace", syntax)
	}
	matches := pattern.FindStringSubmatch(raw)
	if matches == nil {
		return out, fmt.Errorf("must use %s", syntax)
	}
	for index := range 3 {
		value, err := strconv.ParseUint(matches[index+1], 10, 16)
		if err != nil {
			return out, fmt.Errorf("numeric version component %q is invalid", matches[index+1])
		}
		out[index] = strconv.FormatUint(value, 10)
	}
	if len(matches) > 4 {
		copy(out[3:], matches[4:])
	}
	return out, nil
}

// requiredGNMIModels returns the complete stable model set needed before the
// target can be queried or subscribed. RFC7951 profile paths derive their
// model from qualified path elements. Other module-specific origins identify
// a model directly; generic origins such as "openconfig" require an explicit
// stream model declaration.
func requiredGNMIModels(contract *gnmiProductContract, streams []sharedGNMIStream) []string {
	models := map[string]struct{}{}
	add := func(model string) {
		model = strings.TrimSpace(model)
		if model == "" {
			return
		}
		models[model] = struct{}{}
	}
	addQualifiedName := func(name string) {
		if module, qualified := splitGNMIQualifiedName(name); qualified {
			add(module)
		}
	}
	if contract != nil {
		for _, probe := range contract.IdentityProbes {
			add(probe.Model)
		}
	}
	for streamIndex := range streams {
		stream := &streams[streamIndex]
		for _, model := range stream.RequiredModels {
			add(model)
		}
		for pathIndex := range stream.Paths {
			path := &stream.Paths[pathIndex]
			parsed, err := sharedGNMIPathToProto(path.PathTarget, path.Origin, path.Path)
			if err == nil {
				for _, element := range parsed.GetElem() {
					addQualifiedName(element.GetName())
				}
			}
			if path.Origin == builtinGNMIOriginRFC7951 || path.Origin == builtinGNMIOriginOpenConfig {
				continue
			}
			add(path.Origin)
		}
		for mappingIndex := range stream.Mappings {
			source := &stream.Mappings[mappingIndex].Mapping.Source
			for _, element := range source.Elements {
				addQualifiedName(element)
			}
			addQualifiedName(source.Leaf)
		}
	}
	out := make([]string, 0, len(models))
	for model := range models {
		out = append(out, model)
	}
	sort.Strings(out)
	return out
}

func splitGNMIQualifiedName(name string) (string, bool) {
	if strings.Count(name, ":") != 1 {
		return "", false
	}
	module, identifier, _ := strings.Cut(name, ":")
	if !gnmiYANGIdentifierPattern.MatchString(module) || !gnmiYANGIdentifierPattern.MatchString(identifier) {
		return "", false
	}
	return module, true
}

func gnmiPathContainsWildcard(path sharedGNMIPath) bool {
	if strings.Contains(path.PathTarget, "*") || strings.Contains(path.Origin, "*") {
		return true
	}
	parsed, err := sharedGNMIPathToProto(path.PathTarget, path.Origin, path.Path)
	if err != nil {
		return strings.Contains(path.Path, "*")
	}
	for _, element := range parsed.GetElem() {
		if strings.Contains(element.GetName(), "*") {
			return true
		}
		for key, value := range element.GetKey() {
			if strings.Contains(key, "*") || strings.Contains(value, "*") {
				return true
			}
		}
	}
	return false
}
