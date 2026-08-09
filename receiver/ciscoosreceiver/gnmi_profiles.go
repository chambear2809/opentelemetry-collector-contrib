// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"maps"
	"sort"
	"strings"
	"time"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

const (
	builtinGNMIPlatformIOSXE = "ios_xe"
	builtinGNMIPlatformIOSXR = "ios_xr"
	builtinGNMIPlatformNXOS  = "nx_os"

	builtinGNMIProfileIdentity             = "identity"
	builtinGNMIProfileSystem               = "system"
	builtinGNMIProfileInterfaces           = "interfaces"
	builtinGNMIProfileOptics               = "optics"
	builtinGNMIProfileCatalyst9800Wireless = "catalyst_9800_wireless"
	builtinGNMIOriginRFC7951               = "rfc7951"
	builtinGNMIOriginDME                   = "DME"
	builtinGNMIOriginNXDevice              = "Cisco-NX-OS-device"
	builtinGNMISyntheticReceiverOrigin     = "cisco_os"
)

// builtinGNMIMapping adds bounded, catalog-owned attributes to the shared
// explicit mapping contract. Dynamic attributes may only come from modeled
// PathElem keys declared by Mapping.KeyAttributes.
type builtinGNMIMapping struct {
	Mapping          internalgnmi.Mapping
	StaticAttributes map[string]string
	// Groups is runtime-only provenance used to safely remove one bounded
	// group from a compatible packed stream. It is never emitted as an OTLP
	// attribute and generated catalog literals intentionally leave it empty.
	Groups []string
}

// builtinGNMIPathDefinition is one subscription path. Origin and Path remain
// separate so request builders cannot accidentally encode "origin:path".
type builtinGNMIPathDefinition struct {
	ID                   string
	Group                string
	PathSetID            string
	VariantID            string
	VariantOrder         int
	SourcePreference     string
	Origin               string
	Path                 string
	Encodings            []string
	StreamModes          []string
	SampleInterval       time.Duration
	FeaturePrerequisites []string
	SelectorKeys         []string
	HighCardinality      bool
	RequiresMaxEntities  bool
	ModelProvenance      string
	ModelRefs            []string
	Experimental         bool
	Disposition          string
	Findings             string
	FixtureIDs           []string
	LiveEvidence         []string
	CLIEvidence          []string
	JSONListKeys         []internalgnmi.JSONListKeySpec
	EntityJoins          []gnmiCatalogEntityJoinDefinition
	Mappings             []builtinGNMIMapping
}

type builtinGNMIProfileDefinition struct {
	Name              string
	DefaultEnabled    bool
	DefaultInterval   time.Duration
	SyntheticMappings []builtinGNMIMapping
	Paths             []builtinGNMIPathDefinition
}

// gnmiCatalogGroupDefinition is the catalog-owned configuration surface for a
// profile group. Callers can use it to reject unknown groups/selectors and to
// require a positive max_entities before enabling high-cardinality paths.
type gnmiCatalogGroupDefinition struct {
	Name                string
	SelectorKeys        []string
	HighCardinality     bool
	RequiresMaxEntities bool
}

// builtinGNMIProfiles returns profiles in stable name order. Catalog values are
// treated as immutable by receiver code.
func builtinGNMIProfiles(platform string) []builtinGNMIProfileDefinition {
	profiles := builtinGNMIProfileCatalog[platform]
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]builtinGNMIProfileDefinition, 0, len(names))
	for _, name := range names {
		out = append(out, cloneBuiltinGNMIProfile(profiles[name]))
	}
	return out
}

func builtinGNMIProfile(platform, profile string) (builtinGNMIProfileDefinition, bool) {
	definition, ok := builtinGNMIProfileCatalog[platform][profile]
	if !ok {
		return builtinGNMIProfileDefinition{}, false
	}
	return cloneBuiltinGNMIProfile(definition), true
}

func builtinGNMIProfileGroups(platform, profile string) []gnmiCatalogGroupDefinition {
	definition, ok := builtinGNMIProfileCatalog[platform][profile]
	if !ok {
		return nil
	}
	selectors := map[string]map[string]struct{}{}
	groups := map[string]gnmiCatalogGroupDefinition{}
	for pathIndex := range definition.Paths {
		path := definition.Paths[pathIndex]
		group := groups[path.Group]
		group.Name = path.Group
		group.HighCardinality = group.HighCardinality || path.HighCardinality
		group.RequiresMaxEntities = group.RequiresMaxEntities || path.RequiresMaxEntities
		groups[path.Group] = group
		if selectors[path.Group] == nil {
			selectors[path.Group] = map[string]struct{}{}
		}
		for _, selector := range path.SelectorKeys {
			selectors[path.Group][selector] = struct{}{}
		}
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]gnmiCatalogGroupDefinition, 0, len(names))
	for _, name := range names {
		group := groups[name]
		for selector := range selectors[name] {
			group.SelectorKeys = append(group.SelectorKeys, selector)
		}
		sort.Strings(group.SelectorKeys)
		out = append(out, group)
	}
	return out
}

func builtinGNMIProfileGroup(platform, profile, group string) (gnmiCatalogGroupDefinition, bool) {
	for _, definition := range builtinGNMIProfileGroups(platform, profile) {
		if definition.Name == group {
			return definition, true
		}
	}
	return gnmiCatalogGroupDefinition{}, false
}

func gnmiCatalogProductFamily(family string) (gnmiCatalogProductFamilyDefinition, bool) {
	family = strings.ToLower(strings.TrimSpace(family))
	for _, definition := range builtinGNMICatalogProductFamilies {
		if definition.ID == family {
			return definition, true
		}
	}
	return gnmiCatalogProductFamilyDefinition{}, false
}

type gnmiCatalogSourceDefinition struct {
	ID, Title, URL, PublishedOrUpdated, Accessed string
}

type gnmiCatalogProductFamilyDefinition struct {
	ID, Platform string
	MaxStreams   int
}

type gnmiCatalogProductDefinition struct {
	ID, Family                   string
	PIDPatterns, ReleasePatterns []string
	SourceIDs                    []string
	RuntimeEligible              bool
	Roles                        []string
	ControlPlanes                []string
	OperatingModes               []string
	HardwareClasses              []string
	Findings                     string
	Coverage                     map[string]string
}

type gnmiCatalogFixtureDefinition struct {
	ID, File, SHA256 string
}

type gnmiCatalogModelBundleDefinition struct {
	ID, Disposition, Findings string
	Modules                   []gnmiCatalogModelModuleDefinition
}

type gnmiCatalogModelModuleDefinition struct {
	ID, Name, Revision, File, SHA256 string
}

type gnmiCatalogEntityJoinDefinition struct {
	Entity         string
	Elements, Keys []string
}

func cloneBuiltinGNMIProfile(profile builtinGNMIProfileDefinition) builtinGNMIProfileDefinition {
	out := profile
	out.SyntheticMappings = cloneBuiltinGNMIMappings(profile.SyntheticMappings)
	out.Paths = make([]builtinGNMIPathDefinition, len(profile.Paths))
	for i := range profile.Paths {
		path := profile.Paths[i]
		out.Paths[i] = path
		out.Paths[i].Encodings = append([]string(nil), path.Encodings...)
		out.Paths[i].StreamModes = append([]string(nil), path.StreamModes...)
		out.Paths[i].FeaturePrerequisites = append([]string(nil), path.FeaturePrerequisites...)
		out.Paths[i].SelectorKeys = append([]string(nil), path.SelectorKeys...)
		out.Paths[i].ModelRefs = append([]string(nil), path.ModelRefs...)
		out.Paths[i].FixtureIDs = append([]string(nil), path.FixtureIDs...)
		out.Paths[i].LiveEvidence = append([]string(nil), path.LiveEvidence...)
		out.Paths[i].CLIEvidence = append([]string(nil), path.CLIEvidence...)
		out.Paths[i].JSONListKeys = make([]internalgnmi.JSONListKeySpec, len(path.JSONListKeys))
		for specIndex, spec := range path.JSONListKeys {
			out.Paths[i].JSONListKeys[specIndex] = spec
			out.Paths[i].JSONListKeys[specIndex].Elements = append([]string(nil), spec.Elements...)
			out.Paths[i].JSONListKeys[specIndex].Keys = append([]string(nil), spec.Keys...)
		}
		out.Paths[i].EntityJoins = make([]gnmiCatalogEntityJoinDefinition, len(path.EntityJoins))
		for joinIndex, join := range path.EntityJoins {
			out.Paths[i].EntityJoins[joinIndex] = join
			out.Paths[i].EntityJoins[joinIndex].Elements = append([]string(nil), join.Elements...)
			out.Paths[i].EntityJoins[joinIndex].Keys = append([]string(nil), join.Keys...)
		}
		out.Paths[i].Mappings = cloneBuiltinGNMIMappings(path.Mappings)
	}
	return out
}

func cloneBuiltinGNMIMappings(mappings []builtinGNMIMapping) []builtinGNMIMapping {
	out := make([]builtinGNMIMapping, len(mappings))
	for i := range mappings {
		mapping := mappings[i]
		out[i] = mapping
		out[i].Mapping.Source.Elements = append([]string(nil), mapping.Mapping.Source.Elements...)
		out[i].Mapping.KeyAttributes = append([]internalgnmi.KeyAttribute(nil), mapping.Mapping.KeyAttributes...)
		out[i].Groups = append([]string(nil), mapping.Groups...)
		if mapping.StaticAttributes != nil {
			out[i].StaticAttributes = make(map[string]string, len(mapping.StaticAttributes))
			maps.Copy(out[i].StaticAttributes, mapping.StaticAttributes)
		}
	}
	return out
}

type nxOpticsSensorDefinition struct {
	Metric  internalgnmi.MetricMetadata
	Profile string
	Scale   float64
}

// normalizeNXOpticsSensor applies the strict description-and-source-unit
// allowlist used for NX DME sensors. It intentionally contains no heuristic or
// numeric sensor-ID fallback. Benign case and repeated-space differences are
// normalized, but words and punctuation must otherwise match an entry.
func normalizeNXOpticsSensor(description, unit string) (nxOpticsSensorDefinition, bool) {
	key := normalizeNXSensorToken(description) + "\x00" + strings.TrimSpace(unit)
	definition, ok := nxOpticsSensorAllowlist[key]
	return definition, ok
}

func normalizeNXSensorToken(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

var nxOpticsSensorAllowlist = map[string]nxOpticsSensorDefinition{
	"temperature\x00Cel":       {Metric: builtinGNMIMetricMetadata["cisco.optics.temperature"], Profile: "dom", Scale: 1},
	"voltage\x00V":             {Metric: builtinGNMIMetricMetadata["cisco.optics.voltage"], Profile: "dom", Scale: 1},
	"laser bias current\x00mA": {Metric: builtinGNMIMetricMetadata["cisco.optics.laser_bias_current"], Profile: "dom", Scale: 1},
	"rx power\x00dBm":          {Metric: builtinGNMIMetricMetadata["cisco.optics.rx_power"], Profile: "dom", Scale: 1},
	"tx power\x00dBm":          {Metric: builtinGNMIMetricMetadata["cisco.optics.tx_power"], Profile: "dom", Scale: 1},
	"esnr\x00dB":               {Metric: builtinGNMIMetricMetadata["cisco.optics.esnr"], Profile: "vdm", Scale: 1},
	"tdecq\x00dB":              {Metric: builtinGNMIMetricMetadata["cisco.optics.tdecq"], Profile: "vdm", Scale: 1},
	"pre-fec ber\x001":         {Metric: builtinGNMIMetricMetadata["cisco.optics.pre_fec_ber"], Profile: "vdm", Scale: 1},
	"tec current\x00mA":        {Metric: builtinGNMIMetricMetadata["cisco.optics.tec_current"], Profile: "vdm", Scale: 1},
	"tec utilization\x001":     {Metric: builtinGNMIMetricMetadata["cisco.optics.tec_utilization"], Profile: "vdm", Scale: 1},
	"tec utilization\x00%":     {Metric: builtinGNMIMetricMetadata["cisco.optics.tec_utilization"], Profile: "vdm", Scale: .01},
}
