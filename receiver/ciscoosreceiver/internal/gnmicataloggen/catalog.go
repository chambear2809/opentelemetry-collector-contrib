// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package gnmicataloggen loads, validates, and renders the offline Cisco gNMI
// catalog. It deliberately performs no network access.
package gnmicataloggen

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openconfig/goyang/pkg/yang"
	"go.yaml.in/yaml/v3"
)

const schemaVersion = 1

var (
	idPattern             = regexp.MustCompile(`^[a-z][a-z0-9_.-]*$`)
	ucumAnnotationPattern = regexp.MustCompile(`^\{[A-Za-z][A-Za-z0-9_.-]*\}$`)
	yangModuleNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
	sha256Pattern         = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

var ucumAtoms = map[string]struct{}{
	"A": {}, "B": {}, "By": {}, "C": {}, "Cel": {}, "F": {}, "H": {}, "Hz": {}, "J": {}, "K": {},
	"L": {}, "N": {}, "Ohm": {}, "Pa": {}, "S": {}, "T": {}, "Torr": {}, "V": {}, "W": {}, "Wb": {},
	"[deg]": {}, "[degF]": {}, "a": {}, "atm": {}, "bar": {}, "bit": {}, "cd": {}, "d": {}, "dB": {},
	"deg": {}, "eV": {}, "g": {}, "h": {}, "l": {}, "m": {}, "min": {}, "mo": {}, "mol": {}, "rad": {},
	"s": {}, "sr": {}, "wk": {},
}

var ucumPrefixableAtoms = map[string]struct{}{
	"A": {}, "By": {}, "C": {}, "F": {}, "H": {}, "Hz": {}, "J": {}, "K": {}, "L": {}, "N": {},
	"Ohm": {}, "Pa": {}, "S": {}, "T": {}, "V": {}, "W": {}, "Wb": {}, "bit": {}, "eV": {}, "g": {},
	"l": {}, "m": {}, "mol": {}, "rad": {}, "s": {}, "sr": {},
}

var ucumPrefixes = []string{
	"Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "da", "Y", "Z", "E", "P", "T", "G", "M", "k", "h", "d", "c", "m", "u", "n", "p", "f", "a", "z", "y",
}

var ucumSpecialUnits = map[string]struct{}{
	"1": {}, "%": {}, "dB[mW]": {}, "B[SPL]": {}, "B[V]": {}, "B[mV]": {}, "B[uV]": {}, "B[W]": {}, "B[kW]": {},
}

type Manifest struct {
	SchemaVersion   int             `yaml:"schema_version"`
	SnapshotDate    string          `yaml:"snapshot_date"`
	Sources         []Source        `yaml:"sources"`
	Domains         []string        `yaml:"domains"`
	ProductFamilies []ProductFamily `yaml:"product_families"`
	Products        []Product       `yaml:"products"`
	ModelBundles    []ModelBundle   `yaml:"model_bundles"`
	Fixtures        []Fixture       `yaml:"fixtures"`
	MappingSets     []MappingSet    `yaml:"mapping_sets"`
	Profiles        []Profile       `yaml:"profiles"`
}

type Source struct {
	ID                 string `yaml:"id"`
	Title              string `yaml:"title"`
	URL                string `yaml:"url"`
	PublishedOrUpdated string `yaml:"published_or_updated"`
	Accessed           string `yaml:"accessed"`
}

type ProductFamily struct {
	ID         string `yaml:"id"`
	Platform   string `yaml:"platform"`
	MaxStreams int    `yaml:"max_streams"`
}

type Product struct {
	ID              string                          `yaml:"id"`
	Family          string                          `yaml:"family"`
	PIDPatterns     []string                        `yaml:"pid_patterns"`
	ReleasePatterns []string                        `yaml:"release_patterns"`
	Sources         []string                        `yaml:"sources"`
	RuntimeEligible bool                            `yaml:"runtime_eligible"`
	Roles           []string                        `yaml:"roles"`
	ControlPlanes   []string                        `yaml:"control_planes"`
	OperatingModes  []string                        `yaml:"operating_modes"`
	HardwareClasses []string                        `yaml:"hardware_classes"`
	Findings        string                          `yaml:"findings"`
	Coverage        map[string]string               `yaml:"coverage"`
	Qualifications  map[string]ProductQualification `yaml:"qualifications"`
}

// ProductQualification is deliberately nested under an exact product row and
// keyed by telemetry domain. A support claim therefore cannot reuse evidence
// from a sibling PID/release row. PathVariants identify complete, indivisible
// catalog variants rather than individual paths.
type ProductQualification struct {
	PathVariants []QualifiedPathVariant `yaml:"path_variants"`
	LiveEvidence []string               `yaml:"live_evidence"`
	CLIEvidence  []string               `yaml:"cli_evidence"`
}

type QualifiedPathVariant struct {
	Profile   string `yaml:"profile"`
	Group     string `yaml:"group"`
	PathSetID string `yaml:"path_set_id"`
	VariantID string `yaml:"variant_id"`
}

type Fixture struct {
	ID     string            `yaml:"id"`
	File   string            `yaml:"file"`
	SHA256 string            `yaml:"sha256"`
	Covers []FixtureCoverage `yaml:"covers"`
}

type FixtureCoverage struct {
	Platform string `yaml:"platform"`
	Profile  string `yaml:"profile"`
	PathID   string `yaml:"path"`
}

// ModelBundle records provenance for an operator-supplied local YANG/model
// bundle. Pending bundles intentionally contain no module records: the catalog
// must not invent file digests or revisions when no bundle was supplied.
type ModelBundle struct {
	ID          string        `yaml:"id"`
	Disposition string        `yaml:"disposition"`
	Findings    string        `yaml:"findings"`
	Modules     []ModelModule `yaml:"modules"`
}

type ModelModule struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Revision string `yaml:"revision"`
	File     string `yaml:"file"`
	SHA256   string `yaml:"sha256"`
}

type MappingSet struct {
	ID       string    `yaml:"id"`
	Mappings []Mapping `yaml:"mappings"`
}

type Profile struct {
	Platform          string    `yaml:"platform"`
	Name              string    `yaml:"name"`
	DefaultEnabled    bool      `yaml:"default_enabled"`
	DefaultInterval   string    `yaml:"default_interval"`
	SyntheticMappings []Mapping `yaml:"synthetic_mappings"`
	Paths             []Path    `yaml:"paths"`
}

type Path struct {
	ID                   string       `yaml:"id"`
	Group                string       `yaml:"group"`
	PathSetID            string       `yaml:"path_set_id"`
	VariantID            string       `yaml:"variant_id"`
	VariantOrder         int          `yaml:"variant_order"`
	SourcePreference     string       `yaml:"source_preference"`
	Origin               string       `yaml:"origin"`
	Path                 string       `yaml:"path"`
	Encodings            []string     `yaml:"encodings"`
	StreamModes          []string     `yaml:"stream_modes"`
	SampleInterval       string       `yaml:"sample_interval"`
	FeaturePrerequisites []string     `yaml:"feature_prerequisites"`
	SelectorKeys         []string     `yaml:"selector_keys"`
	HighCardinality      bool         `yaml:"high_cardinality"`
	RequiresMaxEntities  bool         `yaml:"requires_max_entities"`
	ModelProvenance      string       `yaml:"model_provenance"`
	ModelRefs            []string     `yaml:"model_refs"`
	Experimental         bool         `yaml:"experimental"`
	Disposition          string       `yaml:"disposition"`
	Findings             string       `yaml:"findings"`
	BaseElements         []string     `yaml:"base_elements"`
	ListKeys             []ListKey    `yaml:"list_keys"`
	EntityJoins          []EntityJoin `yaml:"entity_joins"`
	MappingSet           string       `yaml:"mapping_set"`
	Mappings             []Mapping    `yaml:"mappings"`
	Fixtures             []string     `yaml:"fixtures"`
	LiveEvidence         []string     `yaml:"live_evidence"`
	CLIEvidence          []string     `yaml:"cli_evidence"`
}

type ListKey struct {
	Elements []string `yaml:"elements"`
	Keys     []string `yaml:"keys"`
}

type EntityJoin struct {
	Entity   string   `yaml:"entity"`
	Elements []string `yaml:"elements"`
	Keys     []string `yaml:"keys"`
}

type Mapping struct {
	Origin           string            `yaml:"origin"`
	Elements         []string          `yaml:"elements"`
	RelativeElements []string          `yaml:"relative_elements"`
	Leaf             string            `yaml:"leaf"`
	Metric           string            `yaml:"metric"`
	Scale            float64           `yaml:"scale"`
	Keys             []KeyAttribute    `yaml:"keys"`
	Attributes       map[string]string `yaml:"attributes"`
}

type KeyAttribute struct {
	Element   string `yaml:"element"`
	Key       string `yaml:"key"`
	Attribute string `yaml:"attribute"`
}

type Metadata struct {
	Attributes map[string]MetadataAttribute `yaml:"attributes"`
	Metrics    map[string]MetadataMetric    `yaml:"metrics"`
}

type MetadataAttribute struct {
	Type string   `yaml:"type"`
	Enum []string `yaml:"enum"`
}

type MetadataMetric struct {
	Description string       `yaml:"description"`
	Unit        string       `yaml:"unit"`
	Attributes  []string     `yaml:"attributes"`
	Gauge       *MetricGauge `yaml:"gauge"`
	Sum         *MetricSum   `yaml:"sum"`
}

type MetricGauge struct {
	ValueType string `yaml:"value_type"`
}

type MetricSum struct {
	ValueType string `yaml:"value_type"`
	Monotonic bool   `yaml:"monotonic"`
}

type Catalog struct {
	Manifest     Manifest
	Metadata     Metadata
	Profiles     []ResolvedProfile
	modelSchemas map[string]*yang.Entry
}

type ResolvedProfile struct {
	Profile
	Interval  time.Duration
	Synthetic []ResolvedMapping
	Paths     []ResolvedPath
}

type ResolvedPath struct {
	Path
	Interval time.Duration
	Mappings []ResolvedMapping
}

type ResolvedMapping struct {
	Mapping
	Origin   string
	Elements []string
	Contract MetadataMetric
}

func Load(manifestPath, metadataPath string) (*Catalog, error) {
	return load(manifestPath, metadataPath, "")
}

// LoadWithModelBundle validates recorded model files against a separately
// supplied local bundle directory while keeping fixtures and generated outputs
// rooted beside the manifest. It performs no discovery or network access.
func LoadWithModelBundle(manifestPath, metadataPath, modelBundleDir string) (*Catalog, error) {
	if strings.TrimSpace(modelBundleDir) == "" {
		return nil, errors.New("local model bundle directory cannot be empty")
	}
	return load(manifestPath, metadataPath, modelBundleDir)
}

func load(manifestPath, metadataPath, modelBundleDir string) (*Catalog, error) {
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read catalog manifest: %w", err)
	}
	var syntax yaml.Node
	if syntaxErr := yaml.Unmarshal(manifestRaw, &syntax); syntaxErr != nil {
		return nil, fmt.Errorf("parse catalog manifest: %w", syntaxErr)
	}
	if duplicateErr := rejectDuplicateYAMLKeys(&syntax); duplicateErr != nil {
		return nil, fmt.Errorf("parse catalog manifest: %w", duplicateErr)
	}
	var manifest Manifest
	decoder := yaml.NewDecoder(bytes.NewReader(manifestRaw))
	decoder.KnownFields(true)
	if decodeErr := decoder.Decode(&manifest); decodeErr != nil {
		return nil, fmt.Errorf("decode catalog manifest: %w", decodeErr)
	}
	var trailing any
	if trailerErr := decoder.Decode(&trailing); !errors.Is(trailerErr, io.EOF) {
		if trailerErr == nil {
			return nil, errors.New("decode catalog manifest: multiple YAML documents are forbidden")
		}
		return nil, fmt.Errorf("decode catalog manifest trailer: %w", trailerErr)
	}

	metadataRaw, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("read component metadata: %w", err)
	}
	var metadata Metadata
	if metadataErr := yaml.Unmarshal(metadataRaw, &metadata); metadataErr != nil {
		return nil, fmt.Errorf("decode component metadata: %w", metadataErr)
	}

	catalog := &Catalog{Manifest: manifest, Metadata: metadata}
	if validationErr := catalog.validate(filepath.Dir(manifestPath), modelBundleDir); validationErr != nil {
		return nil, validationErr
	}
	return catalog, nil
}

func (catalog *Catalog) validate(baseDir, modelBundleDir string) error {
	if err := validateMetadataContracts(catalog.Metadata); err != nil {
		return err
	}
	if catalog.Manifest.SchemaVersion != schemaVersion {
		return fmt.Errorf("catalog schema_version must be %d", schemaVersion)
	}
	snapshot, err := time.Parse(time.DateOnly, catalog.Manifest.SnapshotDate)
	if err != nil {
		return fmt.Errorf("catalog snapshot_date: %w", err)
	}
	if len(catalog.Manifest.Sources) == 0 || len(catalog.Manifest.Domains) == 0 || len(catalog.Manifest.Products) == 0 || len(catalog.Manifest.Profiles) == 0 {
		return errors.New("catalog sources, domains, products, and profiles cannot be empty")
	}

	sources := map[string]struct{}{}
	for i, source := range catalog.Manifest.Sources {
		if err := validateID("source", source.ID); err != nil {
			return fmt.Errorf("sources[%d]: %w", i, err)
		}
		if _, duplicate := sources[source.ID]; duplicate {
			return fmt.Errorf("duplicate source %q", source.ID)
		}
		sources[source.ID] = struct{}{}
		if strings.TrimSpace(source.Title) == "" {
			return fmt.Errorf("source %q title cannot be empty", source.ID)
		}
		parsed, parseErr := url.Parse(source.URL)
		if parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return fmt.Errorf("source %q must use an absolute HTTPS URL", source.ID)
		}
		accessed, dateErr := time.Parse(time.DateOnly, source.Accessed)
		if dateErr != nil || accessed.After(snapshot) {
			return fmt.Errorf("source %q accessed date must be valid and no later than snapshot_date", source.ID)
		}
		if source.PublishedOrUpdated != "" {
			published, publishedErr := time.Parse(time.DateOnly, source.PublishedOrUpdated)
			if publishedErr != nil || published.After(snapshot) || published.After(accessed) {
				return fmt.Errorf("source %q published_or_updated date must be valid and no later than accessed or snapshot_date", source.ID)
			}
		}
	}

	domains := map[string]struct{}{}
	for i, domain := range catalog.Manifest.Domains {
		if err := validateID("domain", domain); err != nil {
			return fmt.Errorf("domains[%d]: %w", i, err)
		}
		if _, duplicate := domains[domain]; duplicate {
			return fmt.Errorf("duplicate domain %q", domain)
		}
		domains[domain] = struct{}{}
	}

	families := map[string]ProductFamily{}
	for i, family := range catalog.Manifest.ProductFamilies {
		if err := validateID("product family", family.ID); err != nil {
			return fmt.Errorf("product_families[%d]: %w", i, err)
		}
		if _, duplicate := families[family.ID]; duplicate {
			return fmt.Errorf("duplicate product family %q", family.ID)
		}
		if !validPlatform(family.Platform) || family.MaxStreams < 1 || family.MaxStreams > 16 {
			return fmt.Errorf("product family %q has invalid platform or max_streams", family.ID)
		}
		families[family.ID] = family
	}

	products := map[string]struct{}{}
	selectorOwners := map[string][]productSelectorContract{}
	for i := range catalog.Manifest.Products {
		product := &catalog.Manifest.Products[i]
		if err := validateID("product", product.ID); err != nil {
			return fmt.Errorf("products[%d]: %w", i, err)
		}
		if _, duplicate := products[product.ID]; duplicate {
			return fmt.Errorf("duplicate product %q", product.ID)
		}
		products[product.ID] = struct{}{}
		if _, ok := families[product.Family]; !ok {
			return fmt.Errorf("product %q references unknown family %q", product.ID, product.Family)
		}
		if len(product.PIDPatterns) == 0 || len(product.ReleasePatterns) == 0 || len(product.Sources) == 0 {
			return fmt.Errorf("product %q requires PID patterns, release patterns, and sources", product.ID)
		}
		if err := validateUniqueStrings("PID selector", product.PIDPatterns); err != nil {
			return fmt.Errorf("product %q: %w", product.ID, err)
		}
		if err := validateUniqueStrings("release selector", product.ReleasePatterns); err != nil {
			return fmt.Errorf("product %q: %w", product.ID, err)
		}
		for _, pattern := range append(slices.Clone(product.PIDPatterns), product.ReleasePatterns...) {
			if !strings.HasPrefix(pattern, "^") || !strings.HasSuffix(pattern, "$") {
				return fmt.Errorf("product %q selector %q must be anchored", product.ID, pattern)
			}
			if _, compileErr := regexp.Compile(pattern); compileErr != nil {
				return fmt.Errorf("product %q selector %q: %w", product.ID, pattern, compileErr)
			}
		}
		for _, source := range product.Sources {
			if _, ok := sources[source]; !ok {
				return fmt.Errorf("product %q references unknown source %q", product.ID, source)
			}
		}
		if err := validateUniqueIDs("source reference", product.Sources); err != nil {
			return fmt.Errorf("product %q: %w", product.ID, err)
		}
		for kind, values := range map[string][]string{
			"role": product.Roles, "control plane": product.ControlPlanes,
			"operating mode": product.OperatingModes, "hardware class": product.HardwareClasses,
		} {
			if err := validateUniqueIDs(kind, values); err != nil {
				return fmt.Errorf("product %q: %w", product.ID, err)
			}
		}
		if product.RuntimeEligible && (len(product.Roles) > 0 || len(product.ControlPlanes) > 0 || len(product.OperatingModes) > 0) {
			return fmt.Errorf(
				"product %q cannot be runtime_eligible while role, control-plane, or operating-mode predicates are not proven by bootstrap identity",
				product.ID,
			)
		}
		selectorContract := productSelectorContract{
			ProductID:       product.ID,
			RuntimeEligible: product.RuntimeEligible,
			Predicates:      productPredicateSignature(*product),
		}
		for _, pidPattern := range product.PIDPatterns {
			for _, releasePattern := range product.ReleasePatterns {
				selectorKey := families[product.Family].Platform + "\x00" + pidPattern + "\x00" + releasePattern
				for _, previous := range selectorOwners[selectorKey] {
					if (previous.RuntimeEligible && product.RuntimeEligible) || previous.Predicates == selectorContract.Predicates {
						return fmt.Errorf("product %q duplicates PID/release selector pair from %q", product.ID, previous.ProductID)
					}
				}
				selectorOwners[selectorKey] = append(selectorOwners[selectorKey], selectorContract)
			}
		}
		if len(product.Coverage) != len(domains) {
			return fmt.Errorf("product %q must explicitly disposition every domain", product.ID)
		}
		for domain := range domains {
			status, ok := product.Coverage[domain]
			if !ok || !validCoverageStatus(status) {
				return fmt.Errorf("product %q domain %q has missing or invalid disposition", product.ID, domain)
			}
			if status == "live_qualified" && !product.RuntimeEligible {
				return fmt.Errorf("product %q domain %q is live_qualified without runtime eligibility", product.ID, domain)
			}
		}
		for domain := range product.Coverage {
			if _, ok := domains[domain]; !ok {
				return fmt.Errorf("product %q has unknown domain %q", product.ID, domain)
			}
		}
	}

	modelModules := map[string]ModelModule{}
	modelSchemas := map[string]*yang.Entry{}
	modelBaseDir := baseDir
	if modelBundleDir != "" {
		modelBaseDir = modelBundleDir
	}
	modelIdentities := map[string]string{}
	modelFiles := map[string]string{}
	modelBundles := map[string]struct{}{}
	for bundleIndex, bundle := range catalog.Manifest.ModelBundles {
		if err := validateID("model bundle", bundle.ID); err != nil {
			return fmt.Errorf("model_bundles[%d]: %w", bundleIndex, err)
		}
		if _, duplicate := modelBundles[bundle.ID]; duplicate {
			return fmt.Errorf("duplicate model bundle %q", bundle.ID)
		}
		modelBundles[bundle.ID] = struct{}{}
		switch bundle.Disposition {
		case "pending":
			if len(bundle.Modules) != 0 || strings.TrimSpace(bundle.Findings) == "" {
				return fmt.Errorf("pending model bundle %q must have explicit findings and no fabricated modules", bundle.ID)
			}
		case "verified":
			if len(bundle.Modules) == 0 {
				return fmt.Errorf("verified model bundle %q must declare modules", bundle.ID)
			}
		default:
			return fmt.Errorf("model bundle %q has invalid disposition %q", bundle.ID, bundle.Disposition)
		}
		for moduleIndex, module := range bundle.Modules {
			if err := validateID("model module", module.ID); err != nil {
				return fmt.Errorf("model bundle %q module %d: %w", bundle.ID, moduleIndex, err)
			}
			if _, duplicate := modelModules[module.ID]; duplicate {
				return fmt.Errorf("duplicate model module ID %q", module.ID)
			}
			if !yangModuleNamePattern.MatchString(module.Name) {
				return fmt.Errorf("model module %q has invalid module name %q", module.ID, module.Name)
			}
			revision, revisionErr := time.Parse(time.DateOnly, module.Revision)
			if revisionErr != nil || revision.After(snapshot) {
				return fmt.Errorf("model module %q has invalid revision %q", module.ID, module.Revision)
			}
			if err := validateRelativeFile("model module", module.ID, module.File); err != nil {
				return err
			}
			if !sha256Pattern.MatchString(module.SHA256) {
				return fmt.Errorf("model module %q has invalid SHA-256", module.ID)
			}
			identity := module.Name + "@" + module.Revision
			if previous, duplicate := modelIdentities[identity]; duplicate {
				return fmt.Errorf("model module %q duplicates name and revision from %q", module.ID, previous)
			}
			if previous, duplicate := modelFiles[module.File]; duplicate {
				return fmt.Errorf("model module %q duplicates relative file from %q", module.ID, previous)
			}
			modelIdentities[identity] = module.ID
			modelFiles[module.File] = module.ID
			modelModules[module.ID] = module
		}
		if bundle.Disposition == "verified" {
			parsed, parseErr := loadVerifiedModelSchemas(modelBaseDir, bundle)
			if parseErr != nil {
				return fmt.Errorf("verified model bundle %q: %w", bundle.ID, parseErr)
			}
			maps.Copy(modelSchemas, parsed)
		}
	}
	if len(catalog.Manifest.ModelBundles) == 0 {
		return errors.New("catalog must explicitly declare model bundle provenance")
	}

	fixtures := map[string]Fixture{}
	unmatchedFixtureClaims := map[string]struct{}{}
	for i, fixture := range catalog.Manifest.Fixtures {
		if err := validateID("fixture", fixture.ID); err != nil {
			return fmt.Errorf("fixtures[%d]: %w", i, err)
		}
		if _, duplicate := fixtures[fixture.ID]; duplicate {
			return fmt.Errorf("duplicate fixture %q", fixture.ID)
		}
		if err := validateRelativeFile("fixture", fixture.ID, fixture.File); err != nil {
			return err
		}
		if !sha256Pattern.MatchString(fixture.SHA256) {
			return fmt.Errorf("fixture %q has invalid SHA-256", fixture.ID)
		}
		if len(fixture.Covers) == 0 {
			return fmt.Errorf("fixture %q must declare the exact catalog paths it covers", fixture.ID)
		}
		for coverageIndex, coverage := range fixture.Covers {
			if !validPlatform(coverage.Platform) {
				return fmt.Errorf("fixture %q covers[%d] has invalid platform %q", fixture.ID, coverageIndex, coverage.Platform)
			}
			if err := validateID("fixture profile", coverage.Profile); err != nil {
				return fmt.Errorf("fixture %q covers[%d]: %w", fixture.ID, coverageIndex, err)
			}
			if err := validateID("fixture path", coverage.PathID); err != nil {
				return fmt.Errorf("fixture %q covers[%d]: %w", fixture.ID, coverageIndex, err)
			}
			claim := fixtureCoverageKey(fixture.ID, coverage.Platform, coverage.Profile, coverage.PathID)
			if _, duplicate := unmatchedFixtureClaims[claim]; duplicate {
				return fmt.Errorf("fixture %q has duplicate coverage for %s/%s/%s", fixture.ID, coverage.Platform, coverage.Profile, coverage.PathID)
			}
			unmatchedFixtureClaims[claim] = struct{}{}
		}
		raw, readErr := os.ReadFile(filepath.Join(baseDir, fixture.File))
		if readErr != nil {
			return fmt.Errorf("fixture %q: %w", fixture.ID, readErr)
		}
		digest := sha256.Sum256(raw)
		if hex.EncodeToString(digest[:]) != fixture.SHA256 {
			return fmt.Errorf("fixture %q SHA-256 does not match %s", fixture.ID, fixture.File)
		}
		fixtures[fixture.ID] = fixture
	}

	mappingSets := map[string][]Mapping{}
	for i, set := range catalog.Manifest.MappingSets {
		if err := validateID("mapping set", set.ID); err != nil {
			return fmt.Errorf("mapping_sets[%d]: %w", i, err)
		}
		if _, duplicate := mappingSets[set.ID]; duplicate {
			return fmt.Errorf("duplicate mapping set %q", set.ID)
		}
		if len(set.Mappings) == 0 {
			return fmt.Errorf("mapping set %q cannot be empty", set.ID)
		}
		mappingSets[set.ID] = set.Mappings
	}

	profileKeys := map[string]struct{}{}
	for profileIndex := range catalog.Manifest.Profiles {
		profile := &catalog.Manifest.Profiles[profileIndex]
		if !validPlatform(profile.Platform) {
			return fmt.Errorf("profiles[%d] has invalid platform %q", profileIndex, profile.Platform)
		}
		if err := validateID("profile", profile.Name); err != nil {
			return fmt.Errorf("profiles[%d]: %w", profileIndex, err)
		}
		if _, ok := domains[profile.Name]; !ok {
			return fmt.Errorf("profile %q on %q does not map to a declared telemetry domain", profile.Name, profile.Platform)
		}
		profileKey := profile.Platform + "\x00" + profile.Name
		if _, duplicate := profileKeys[profileKey]; duplicate {
			return fmt.Errorf("duplicate profile %q on %q", profile.Name, profile.Platform)
		}
		profileKeys[profileKey] = struct{}{}
		interval, durationErr := time.ParseDuration(profile.DefaultInterval)
		if durationErr != nil || interval <= 0 {
			return fmt.Errorf("profile %q on %q has invalid default_interval", profile.Name, profile.Platform)
		}
		resolved := ResolvedProfile{Profile: *profile, Interval: interval}
		for mappingIndex := range profile.SyntheticMappings {
			mapped, mappingErr := catalog.resolveMapping(profile.SyntheticMappings[mappingIndex], "", nil)
			if mappingErr != nil {
				return fmt.Errorf("profile %q synthetic mapping %d: %w", profile.Name, mappingIndex, mappingErr)
			}
			resolved.Synthetic = append(resolved.Synthetic, mapped)
		}
		pathIDs := map[string]struct{}{}
		pathSetGroups := map[string]string{}
		groupContracts := map[string]pathGroupContract{}
		variantContracts := map[string]pathVariantContract{}
		variantOrders := map[string]map[int]string{}
		for pathIndex := range profile.Paths {
			path := &profile.Paths[pathIndex]
			if err := validateID("path", path.ID); err != nil {
				return fmt.Errorf("profile %q path %d: %w", profile.Name, pathIndex, err)
			}
			if _, duplicate := pathIDs[path.ID]; duplicate {
				return fmt.Errorf("profile %q has duplicate path ID %q", profile.Name, path.ID)
			}
			pathIDs[path.ID] = struct{}{}
			pathInterval, pathErr := validatePathContract(*path, modelModules)
			if pathErr != nil {
				return fmt.Errorf("profile %q path %q: %w", profile.Name, path.ID, pathErr)
			}
			if previous, exists := pathSetGroups[path.PathSetID]; exists && previous != path.Group {
				return fmt.Errorf("profile %q path set %q spans public groups %q and %q", profile.Name, path.PathSetID, previous, path.Group)
			}
			pathSetGroups[path.PathSetID] = path.Group
			groupContract := newPathGroupContract(*path)
			if previous, exists := groupContracts[path.Group]; exists && previous != groupContract {
				return fmt.Errorf("profile %q group %q has inconsistent selector or cardinality contracts", profile.Name, path.Group)
			}
			groupContracts[path.Group] = groupContract
			setKey := path.Group + "\x00" + path.PathSetID
			variantKey := setKey + "\x00" + path.VariantID
			contract := pathVariantContract{Order: path.VariantOrder, SourcePreference: path.SourcePreference}
			if previous, exists := variantContracts[variantKey]; exists && previous != contract {
				return fmt.Errorf("profile %q path set %q variant %q has inconsistent ordering or source preference", profile.Name, path.PathSetID, path.VariantID)
			}
			variantContracts[variantKey] = contract
			if variantOrders[setKey] == nil {
				variantOrders[setKey] = map[int]string{}
			}
			if previous, exists := variantOrders[setKey][path.VariantOrder]; exists && previous != path.VariantID {
				return fmt.Errorf("profile %q path set %q has duplicate variant_order %d", profile.Name, path.PathSetID, path.VariantOrder)
			}
			variantOrders[setKey][path.VariantOrder] = path.VariantID
			for _, fixture := range path.Fixtures {
				if _, ok := fixtures[fixture]; !ok {
					return fmt.Errorf("profile %q path %q references unknown fixture %q", profile.Name, path.ID, fixture)
				}
				claim := fixtureCoverageKey(fixture, profile.Platform, profile.Name, path.ID)
				if _, ok := unmatchedFixtureClaims[claim]; !ok {
					return fmt.Errorf("profile %q path %q references fixture %q without an exact coverage claim", profile.Name, path.ID, fixture)
				}
				delete(unmatchedFixtureClaims, claim)
			}
			pathMappings := path.Mappings
			if path.MappingSet != "" {
				if len(path.Mappings) > 0 {
					return fmt.Errorf("profile %q path %q cannot combine mapping_set and mappings", profile.Name, path.ID)
				}
				var ok bool
				pathMappings, ok = mappingSets[path.MappingSet]
				if !ok {
					return fmt.Errorf("profile %q path %q references unknown mapping set %q", profile.Name, path.ID, path.MappingSet)
				}
			}
			if (path.Disposition == "implemented" || path.Disposition == "fixture_passed" || path.Disposition == "live_qualified") && len(path.Fixtures) == 0 {
				return fmt.Errorf("profile %q path %q disposition %q requires fixtures", profile.Name, path.ID, path.Disposition)
			}
			if path.Disposition == "live_qualified" && (len(path.LiveEvidence) == 0 || len(path.CLIEvidence) == 0) {
				return fmt.Errorf("profile %q path %q is live_qualified without live and CLI evidence", profile.Name, path.ID)
			}
			if len(path.LiveEvidence) > 0 {
				if err := validateEvidenceRefs("live evidence", path.LiveEvidence); err != nil {
					return fmt.Errorf("profile %q path %q: %w", profile.Name, path.ID, err)
				}
			}
			if len(path.CLIEvidence) > 0 {
				if err := validateEvidenceRefs("CLI evidence", path.CLIEvidence); err != nil {
					return fmt.Errorf("profile %q path %q: %w", profile.Name, path.ID, err)
				}
			}
			if path.Disposition == "findings" && strings.TrimSpace(path.Findings) == "" {
				return fmt.Errorf("profile %q path %q findings disposition requires findings text", profile.Name, path.ID)
			}
			if err := validateListKeys(*path); err != nil {
				return fmt.Errorf("profile %q path %q: %w", profile.Name, path.ID, err)
			}
			if err := validateEntityJoins(*path); err != nil {
				return fmt.Errorf("profile %q path %q: %w", profile.Name, path.ID, err)
			}
			if schemaErr := validatePathAgainstVerifiedModels(*path, modelSchemas); schemaErr != nil {
				return fmt.Errorf("profile %q path %q schema: %w", profile.Name, path.ID, schemaErr)
			}
			resolvedPath := ResolvedPath{Path: *path, Interval: pathInterval}
			for mappingIndex := range pathMappings {
				mapped, mappingErr := catalog.resolveMapping(pathMappings[mappingIndex], path.Origin, path.BaseElements)
				if mappingErr != nil {
					return fmt.Errorf("profile %q path %q mapping %d: %w", profile.Name, path.ID, mappingIndex, mappingErr)
				}
				if mapped.Origin != path.Origin {
					return fmt.Errorf(
						"profile %q path %q mapping %d origin %q does not match subscription origin %q",
						profile.Name,
						path.ID,
						mappingIndex,
						mapped.Origin,
						path.Origin,
					)
				}
				if err := validateMappingListKeys(mapped, path.ListKeys); err != nil {
					return fmt.Errorf("profile %q path %q mapping %d: %w", profile.Name, path.ID, mappingIndex, err)
				}
				if schemaErr := validateMappingAgainstVerifiedModels(*path, mapped, modelSchemas); schemaErr != nil {
					return fmt.Errorf("profile %q path %q mapping %d schema: %w", profile.Name, path.ID, mappingIndex, schemaErr)
				}
				resolvedPath.Mappings = append(resolvedPath.Mappings, mapped)
			}
			if err := validateSelectorKeys(path.SelectorKeys, resolvedPath.Mappings); err != nil {
				return fmt.Errorf("profile %q path %q: %w", profile.Name, path.ID, err)
			}
			resolved.Paths = append(resolved.Paths, resolvedPath)
		}
		for setKey, orders := range variantOrders {
			seenNative := false
			for order := 1; order <= len(orders); order++ {
				variant, ok := orders[order]
				if !ok {
					return fmt.Errorf("profile %q path set %q has non-contiguous variant ordering", profile.Name, strings.ReplaceAll(setKey, "\x00", "/"))
				}
				source := variantContracts[setKey+"\x00"+variant].SourcePreference
				if source == "native" {
					seenNative = true
				} else if seenNative {
					return fmt.Errorf("profile %q path set %q orders OpenConfig after a native variant", profile.Name, strings.ReplaceAll(setKey, "\x00", "/"))
				}
			}
		}
		if err := validateProfileMappingIdentities(resolved); err != nil {
			return err
		}
		catalog.Profiles = append(catalog.Profiles, resolved)
	}
	if len(unmatchedFixtureClaims) > 0 {
		claims := sortedMapKeys(unmatchedFixtureClaims)
		return fmt.Errorf("fixture coverage claim %q does not match a referencing catalog path", claims[0])
	}
	if err := validateProductQualifications(catalog.Manifest.Products, families, catalog.Profiles); err != nil {
		return err
	}
	catalog.modelSchemas = modelSchemas
	return nil
}

func validateMetadataContracts(metadata Metadata) error {
	for name, attribute := range metadata.Attributes {
		if !idPattern.MatchString(name) {
			return fmt.Errorf("metadata attribute %q has an invalid name", name)
		}
		switch attribute.Type {
		case "string", "bool", "int", "double":
		default:
			return fmt.Errorf("metadata attribute %q has unsupported type %q", name, attribute.Type)
		}
		if len(attribute.Enum) > 0 && attribute.Type != "string" {
			return fmt.Errorf("metadata attribute %q has an enum but is not a string", name)
		}
		if err := validateUniqueStrings("metadata attribute enum", attribute.Enum); err != nil {
			return fmt.Errorf("metadata attribute %q: %w", name, err)
		}
	}
	for name, metric := range metadata.Metrics {
		if !idPattern.MatchString(name) {
			return fmt.Errorf("metadata metric %q has an invalid name", name)
		}
		if strings.TrimSpace(metric.Description) == "" || !validUCUMUnit(metric.Unit) || (metric.Gauge == nil) == (metric.Sum == nil) {
			return fmt.Errorf("metadata metric %q has an incomplete or invalid contract", name)
		}
		var valueType string
		if metric.Gauge != nil {
			valueType = metric.Gauge.ValueType
		} else {
			valueType = metric.Sum.ValueType
		}
		if valueType != "int" && valueType != "double" {
			return fmt.Errorf("metadata metric %q has unsupported value_type %q", name, valueType)
		}
		if err := validateUniqueStrings("metric attribute", metric.Attributes); err != nil {
			return fmt.Errorf("metadata metric %q: %w", name, err)
		}
		for _, attribute := range metric.Attributes {
			if _, ok := metadata.Attributes[attribute]; !ok {
				return fmt.Errorf("metadata metric %q references undeclared attribute %q", name, attribute)
			}
		}
	}
	return nil
}

func validUCUMUnit(unit string) bool {
	if unit == "" || strings.TrimSpace(unit) != unit || strings.ContainsAny(unit, "()") {
		return false
	}
	termStart := 0
	for index, char := range unit {
		if char != '.' && char != '/' && char != '*' {
			continue
		}
		if index == termStart || !validUCUMTerm(unit[termStart:index]) {
			return false
		}
		termStart = index + 1
	}
	return termStart < len(unit) && validUCUMTerm(unit[termStart:])
}

func validUCUMTerm(term string) bool {
	if _, ok := ucumSpecialUnits[term]; ok {
		return true
	}
	if ucumAnnotationPattern.MatchString(term) {
		return true
	}
	if exponent := strings.LastIndexByte(term, '^'); exponent >= 0 {
		if exponent == 0 || exponent == len(term)-1 {
			return false
		}
		if _, err := strconv.Atoi(term[exponent+1:]); err != nil {
			return false
		}
		term = term[:exponent]
	}
	if _, ok := ucumAtoms[term]; ok {
		return true
	}
	for _, prefix := range ucumPrefixes {
		if !strings.HasPrefix(term, prefix) || len(term) == len(prefix) {
			continue
		}
		if _, ok := ucumPrefixableAtoms[term[len(prefix):]]; ok {
			return true
		}
	}
	return false
}

func fixtureCoverageKey(fixture, platform, profile, path string) string {
	return strings.Join([]string{fixture, platform, profile, path}, "\x00")
}

func validateListKeys(path Path) error {
	seen := map[string]struct{}{}
	for index, spec := range path.ListKeys {
		if len(spec.Elements) == 0 || len(spec.Keys) == 0 {
			return fmt.Errorf("list_keys[%d] requires elements and keys", index)
		}
		for _, value := range append(slices.Clone(spec.Elements), spec.Keys...) {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("list_keys[%d] contains an empty element or key", index)
			}
		}
		identity := strings.Join(spec.Elements, "\x00")
		if _, duplicate := seen[identity]; duplicate {
			return fmt.Errorf("list_keys[%d] duplicates an element path", index)
		}
		seen[identity] = struct{}{}
	}
	return nil
}

type pathVariantContract struct {
	Order            int
	SourcePreference string
}

type pathGroupContract struct {
	Selectors           string
	HighCardinality     bool
	RequiresMaxEntities bool
}

func newPathGroupContract(path Path) pathGroupContract {
	selectors := slices.Clone(path.SelectorKeys)
	slices.Sort(selectors)
	return pathGroupContract{
		Selectors:           strings.Join(selectors, "\x00"),
		HighCardinality:     path.HighCardinality,
		RequiresMaxEntities: path.RequiresMaxEntities,
	}
}

type productSelectorContract struct {
	ProductID       string
	RuntimeEligible bool
	Predicates      string
}

func productPredicateSignature(product Product) string {
	parts := make([]string, 0, 4)
	for _, values := range [][]string{product.Roles, product.ControlPlanes, product.OperatingModes, product.HardwareClasses} {
		values = slices.Clone(values)
		slices.Sort(values)
		parts = append(parts, strings.Join(values, "\x00"))
	}
	return strings.Join(parts, "\x01")
}

func validateProductQualifications(products []Product, families map[string]ProductFamily, profiles []ResolvedProfile) error {
	type variantKey struct {
		platform, profile, group, pathSet, variant string
	}
	variants := map[variantKey][]ResolvedPath{}
	pathSets := map[string]map[string]struct{}{}
	for profileIndex := range profiles {
		profile := &profiles[profileIndex]
		for pathIndex := range profile.Paths {
			path := &profile.Paths[pathIndex]
			key := variantKey{profile.Platform, profile.Name, path.Group, path.PathSetID, path.VariantID}
			variants[key] = append(variants[key], *path)
			profileKey := profile.Platform + "\x00" + profile.Name
			if pathSets[profileKey] == nil {
				pathSets[profileKey] = map[string]struct{}{}
			}
			pathSets[profileKey][path.Group+"\x00"+path.PathSetID] = struct{}{}
		}
	}

	for productIndex := range products {
		product := &products[productIndex]
		family := families[product.Family]
		for domain, qualification := range product.Qualifications {
			status, known := product.Coverage[domain]
			if !known {
				return fmt.Errorf("product %q qualification references unknown domain %q", product.ID, domain)
			}
			if status != "live_qualified" {
				return fmt.Errorf("product %q domain %q has qualification evidence but disposition is %q", product.ID, domain, status)
			}
			if err := validateEvidenceRefs("live evidence", qualification.LiveEvidence); err != nil {
				return fmt.Errorf("product %q domain %q: %w", product.ID, domain, err)
			}
			if err := validateEvidenceRefs("CLI evidence", qualification.CLIEvidence); err != nil {
				return fmt.Errorf("product %q domain %q: %w", product.ID, domain, err)
			}
			if len(qualification.PathVariants) == 0 {
				return fmt.Errorf("product %q domain %q qualification requires applicable path variants", product.ID, domain)
			}

			seenVariants := map[variantKey]struct{}{}
			selectedPathSets := map[string]struct{}{}
			for index, reference := range qualification.PathVariants {
				for kind, value := range map[string]string{
					"profile": reference.Profile, "group": reference.Group,
					"path set": reference.PathSetID, "variant": reference.VariantID,
				} {
					if err := validateID(kind, value); err != nil {
						return fmt.Errorf("product %q domain %q path_variants[%d]: %w", product.ID, domain, index, err)
					}
				}
				if reference.Profile != domain {
					return fmt.Errorf("product %q domain %q path variant references profile/domain %q", product.ID, domain, reference.Profile)
				}
				key := variantKey{family.Platform, reference.Profile, reference.Group, reference.PathSetID, reference.VariantID}
				if _, duplicate := seenVariants[key]; duplicate {
					return fmt.Errorf("product %q domain %q duplicates a qualified path variant", product.ID, domain)
				}
				seenVariants[key] = struct{}{}
				pathSetKey := reference.Group + "\x00" + reference.PathSetID
				if _, duplicate := selectedPathSets[pathSetKey]; duplicate {
					return fmt.Errorf("product %q domain %q selects more than one variant for path set %q", product.ID, domain, reference.PathSetID)
				}
				selectedPathSets[pathSetKey] = struct{}{}
				paths := variants[key]
				if len(paths) == 0 {
					return fmt.Errorf("product %q domain %q references an unknown path-set variant for platform %q", product.ID, domain, family.Platform)
				}
				for pathIndex := range paths {
					path := &paths[pathIndex]
					if path.Disposition != "live_qualified" || len(path.Fixtures) == 0 {
						return fmt.Errorf("product %q domain %q path set %q variant %q is not live-qualified and fixture-backed", product.ID, domain, reference.PathSetID, reference.VariantID)
					}
					if !containsAll(qualification.LiveEvidence, path.LiveEvidence) || !containsAll(qualification.CLIEvidence, path.CLIEvidence) {
						return fmt.Errorf("product %q domain %q evidence does not cover path %q", product.ID, domain, path.ID)
					}
				}
			}
			for pathSet := range pathSets[family.Platform+"\x00"+domain] {
				if _, selected := selectedPathSets[pathSet]; !selected {
					return fmt.Errorf("product %q domain %q qualification omits applicable path set %q", product.ID, domain, strings.ReplaceAll(pathSet, "\x00", "/"))
				}
			}
		}
		for domain, status := range product.Coverage {
			if status != "live_qualified" {
				continue
			}
			if _, ok := product.Qualifications[domain]; !ok {
				return fmt.Errorf("product %q domain %q is live_qualified without product-scoped live and CLI evidence tied to path variants", product.ID, domain)
			}
		}
	}
	return nil
}

func validateEvidenceRefs(kind string, values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("%s references cannot be empty", kind)
	}
	seen := map[string]struct{}{}
	for _, value := range values {
		if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
			return fmt.Errorf("%s reference cannot be blank or padded", kind)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("duplicate %s reference %q", kind, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func containsAll(haystack, needles []string) bool {
	values := make(map[string]struct{}, len(haystack))
	for _, value := range haystack {
		values[value] = struct{}{}
	}
	for _, value := range needles {
		if _, ok := values[value]; !ok {
			return false
		}
	}
	return true
}

func validatePathContract(path Path, modelModules map[string]ModelModule) (time.Duration, error) {
	for kind, value := range map[string]string{
		"group": path.Group, "path set": path.PathSetID, "variant": path.VariantID,
	} {
		if err := validateID(kind, value); err != nil {
			return 0, err
		}
	}
	if path.VariantOrder < 1 {
		return 0, errors.New("variant_order must be positive")
	}
	if path.SourcePreference != "openconfig" && path.SourcePreference != "native" {
		return 0, fmt.Errorf("source_preference %q must be openconfig or native", path.SourcePreference)
	}
	if strings.TrimSpace(path.Origin) == "" || strings.Trim(path.Path, "/") != path.Path || path.Path == "" {
		return 0, errors.New("separate origin and clean path are required")
	}
	if err := validateStringSet("encoding", path.Encodings, map[string]struct{}{
		"proto": {}, "json_ietf": {}, "json": {},
	}); err != nil {
		return 0, err
	}
	if err := validateStringSet("stream mode", path.StreamModes, map[string]struct{}{
		"sample": {}, "on_change": {}, "target_defined": {},
	}); err != nil {
		return 0, err
	}
	interval, err := time.ParseDuration(path.SampleInterval)
	if err != nil || interval <= 0 {
		return 0, fmt.Errorf("sample_interval %q must be a positive duration", path.SampleInterval)
	}
	if len(path.FeaturePrerequisites) == 0 {
		return 0, errors.New("feature_prerequisites must explicitly declare at least one prerequisite")
	}
	if err := validateUniqueIDs("feature prerequisite", path.FeaturePrerequisites); err != nil {
		return 0, err
	}
	if err := validateUniqueIDs("selector key", path.SelectorKeys); err != nil {
		return 0, err
	}
	if path.HighCardinality != path.RequiresMaxEntities {
		return 0, errors.New("high_cardinality and requires_max_entities must be enabled together")
	}
	if path.HighCardinality && len(path.SelectorKeys) == 0 {
		return 0, errors.New("high-cardinality paths require at least one exact selector key")
	}
	switch path.ModelProvenance {
	case "pending":
		if len(path.ModelRefs) != 0 {
			return 0, errors.New("pending model provenance cannot contain model_refs")
		}
		if path.Disposition != "findings" {
			return 0, errors.New("pending model provenance requires findings disposition")
		}
	case "verified":
		if len(path.ModelRefs) == 0 {
			return 0, errors.New("verified model provenance requires model_refs")
		}
		if err := validateUniqueIDs("model reference", path.ModelRefs); err != nil {
			return 0, err
		}
		for _, ref := range path.ModelRefs {
			if _, ok := modelModules[ref]; !ok {
				return 0, fmt.Errorf("references unknown verified model module %q", ref)
			}
		}
	default:
		return 0, fmt.Errorf("model_provenance %q must be pending or verified", path.ModelProvenance)
	}
	if !validCoverageStatus(path.Disposition) {
		return 0, fmt.Errorf("invalid disposition %q", path.Disposition)
	}
	for _, evidence := range append(slices.Clone(path.LiveEvidence), path.CLIEvidence...) {
		if strings.TrimSpace(evidence) == "" {
			return 0, errors.New("live and CLI evidence references cannot be empty")
		}
	}
	return interval, nil
}

func validateStringSet(kind string, values []string, allowed map[string]struct{}) error {
	if len(values) == 0 {
		return fmt.Errorf("%ss cannot be empty", kind)
	}
	seen := map[string]struct{}{}
	for _, value := range values {
		if _, ok := allowed[value]; !ok {
			return fmt.Errorf("invalid %s %q", kind, value)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("duplicate %s %q", kind, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateUniqueIDs(kind string, values []string) error {
	seen := map[string]struct{}{}
	for _, value := range values {
		if err := validateID(kind, value); err != nil {
			return err
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("duplicate %s %q", kind, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateUniqueStrings(kind string, values []string) error {
	seen := map[string]struct{}{}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s cannot be empty", kind)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("duplicate %s %q", kind, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateEntityJoins(path Path) error {
	if len(path.EntityJoins) != len(path.ListKeys) {
		return errors.New("entity_joins must cover every list_keys entry exactly once")
	}
	matched := make([]bool, len(path.ListKeys))
	for index, join := range path.EntityJoins {
		if err := validateID("entity join", join.Entity); err != nil {
			return fmt.Errorf("entity_joins[%d]: %w", index, err)
		}
		found := -1
		for specIndex, spec := range path.ListKeys {
			if slices.Equal(join.Elements, spec.Elements) && slices.Equal(join.Keys, spec.Keys) {
				found = specIndex
				break
			}
		}
		if found < 0 {
			return fmt.Errorf("entity_joins[%d] does not match a declared list key", index)
		}
		if matched[found] {
			return fmt.Errorf("entity_joins[%d] duplicates a declared list key", index)
		}
		matched[found] = true
	}
	return nil
}

func validateSelectorKeys(selectors []string, mappings []ResolvedMapping) error {
	declared := make(map[string]struct{}, len(selectors))
	for _, selector := range selectors {
		declared[selector] = struct{}{}
	}
	required := map[string]struct{}{}
	for mappingIndex := range mappings {
		mapping := &mappings[mappingIndex]
		for _, key := range mapping.Keys {
			required[key.Attribute] = struct{}{}
		}
	}
	if len(declared) != len(required) {
		return errors.New("selector_keys must exactly match mapped list-key attributes")
	}
	for selector := range required {
		if _, ok := declared[selector]; !ok {
			return fmt.Errorf("selector_keys omits mapped list-key attribute %q", selector)
		}
	}
	return nil
}

func validateMappingListKeys(mapping ResolvedMapping, specs []ListKey) error {
	for _, key := range mapping.Keys {
		declared := false
		for _, spec := range specs {
			if len(spec.Elements) > len(mapping.Elements) || spec.Elements[len(spec.Elements)-1] != key.Element || !slices.Contains(spec.Keys, key.Key) {
				continue
			}
			if slices.Equal(spec.Elements, mapping.Elements[:len(spec.Elements)]) {
				declared = true
				break
			}
		}
		if !declared {
			return fmt.Errorf("list key %s.%s is not declared by path list_keys", key.Element, key.Key)
		}
	}
	for _, spec := range specs {
		if len(spec.Elements) > len(mapping.Elements) || !slices.Equal(spec.Elements, mapping.Elements[:len(spec.Elements)]) {
			continue
		}
		element := spec.Elements[len(spec.Elements)-1]
		for _, requiredKey := range spec.Keys {
			mapped := slices.ContainsFunc(mapping.Keys, func(key KeyAttribute) bool {
				return key.Element == element && key.Key == requiredKey
			})
			if !mapped {
				return fmt.Errorf("composite list key %s.%s is not mapped and would collapse distinct entities", element, requiredKey)
			}
		}
	}
	return nil
}

func rejectDuplicateYAMLKeys(node *yaml.Node) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]struct{}{}
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if _, duplicate := seen[key.Value]; duplicate {
				return fmt.Errorf("duplicate YAML key %q at line %d", key.Value, key.Line)
			}
			seen[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if child.Kind == yaml.AliasNode {
			continue
		}
		if err := rejectDuplicateYAMLKeys(child); err != nil {
			return err
		}
	}
	return nil
}

func (catalog *Catalog) resolveMapping(mapping Mapping, defaultOrigin string, base []string) (ResolvedMapping, error) {
	origin := mapping.Origin
	if origin == "" {
		origin = defaultOrigin
	}
	if origin == "" || mapping.Leaf == "" || mapping.Metric == "" || mapping.Scale == 0 || math.IsNaN(mapping.Scale) || math.IsInf(mapping.Scale, 0) {
		return ResolvedMapping{}, errors.New("origin, leaf, metric, and finite non-zero scale are required")
	}
	if len(mapping.Elements) > 0 && len(mapping.RelativeElements) > 0 {
		return ResolvedMapping{}, errors.New("elements and relative_elements are mutually exclusive")
	}
	var elements []string
	switch {
	case len(mapping.Elements) > 0:
		// Explicit absolute elements always win. Previously, merely supplying a
		// path base silently replaced these with the base when
		// relative_elements was empty.
		elements = slices.Clone(mapping.Elements)
	case len(mapping.RelativeElements) > 0:
		if len(base) == 0 {
			return ResolvedMapping{}, errors.New("relative_elements require path base_elements")
		}
		elements = append(slices.Clone(base), mapping.RelativeElements...)
	default:
		elements = slices.Clone(base)
	}
	if len(elements) == 0 {
		return ResolvedMapping{}, errors.New("mapping elements cannot be empty")
	}
	for _, element := range elements {
		if strings.TrimSpace(element) == "" {
			return ResolvedMapping{}, errors.New("mapping elements cannot contain empty values")
		}
	}
	contract, ok := catalog.Metadata.Metrics[mapping.Metric]
	if !ok {
		return ResolvedMapping{}, fmt.Errorf("metric %q is absent from metadata.yaml", mapping.Metric)
	}
	if contract.Description == "" || contract.Unit == "" || (contract.Gauge == nil) == (contract.Sum == nil) {
		return ResolvedMapping{}, fmt.Errorf("metric %q has an incomplete metadata contract", mapping.Metric)
	}
	allowedAttributes := map[string]struct{}{}
	for _, attribute := range contract.Attributes {
		allowedAttributes[attribute] = struct{}{}
		if _, exists := catalog.Metadata.Attributes[attribute]; !exists {
			return ResolvedMapping{}, fmt.Errorf("metric %q references undeclared metadata attribute %q", mapping.Metric, attribute)
		}
	}
	seenAttributes := map[string]struct{}{}
	for _, key := range mapping.Keys {
		if key.Element == "" || key.Key == "" || key.Attribute == "" || countString(elements, key.Element) == 0 {
			return ResolvedMapping{}, fmt.Errorf("metric %q has an invalid list-key mapping", mapping.Metric)
		}
		if _, allowed := allowedAttributes[key.Attribute]; !allowed {
			return ResolvedMapping{}, fmt.Errorf("metric %q key attribute %q is absent from its metadata contract", mapping.Metric, key.Attribute)
		}
		if _, duplicate := seenAttributes[key.Attribute]; duplicate {
			return ResolvedMapping{}, fmt.Errorf("metric %q maps duplicate attribute %q", mapping.Metric, key.Attribute)
		}
		seenAttributes[key.Attribute] = struct{}{}
	}
	for attribute, value := range mapping.Attributes {
		definition, declared := catalog.Metadata.Attributes[attribute]
		if !declared {
			return ResolvedMapping{}, fmt.Errorf("metric %q uses undeclared static attribute %q", mapping.Metric, attribute)
		}
		if _, allowed := allowedAttributes[attribute]; !allowed {
			return ResolvedMapping{}, fmt.Errorf("metric %q static attribute %q is absent from its metadata contract", mapping.Metric, attribute)
		}
		if _, duplicate := seenAttributes[attribute]; duplicate {
			return ResolvedMapping{}, fmt.Errorf("metric %q duplicates dynamic and static attribute %q", mapping.Metric, attribute)
		}
		if len(definition.Enum) > 0 && !slices.Contains(definition.Enum, value) {
			return ResolvedMapping{}, fmt.Errorf("metric %q static attribute %q has unbounded value %q", mapping.Metric, attribute, value)
		}
		if definition.Type == "bool" && value != "true" && value != "false" {
			return ResolvedMapping{}, fmt.Errorf("metric %q static bool attribute %q is invalid", mapping.Metric, attribute)
		}
		seenAttributes[attribute] = struct{}{}
	}
	return ResolvedMapping{Mapping: mapping, Origin: origin, Elements: elements, Contract: contract}, nil
}

func validateProfileMappingIdentities(profile ResolvedProfile) error {
	type mappingOwner struct {
		source, group, pathSet, variant string
		synthetic                       bool
	}
	sources := map[string]struct{}{}
	outputs := map[string][]mappingOwner{}
	validate := func(mapping ResolvedMapping, owner mappingOwner) error {
		source := mapping.Origin + "\x00" + strings.Join(mapping.Elements, "\x00") + "\x00" + mapping.Leaf
		if _, duplicate := sources[source]; duplicate {
			return fmt.Errorf("profile %q on %q has duplicate source mapping %q", profile.Name, profile.Platform, source)
		}
		sources[source] = struct{}{}
		attributes := make([]string, 0, len(mapping.Keys)+len(mapping.Attributes))
		for _, key := range mapping.Keys {
			attributes = append(attributes, key.Attribute)
		}
		for key, value := range mapping.Attributes {
			attributes = append(attributes, key+"="+value)
		}
		slices.Sort(attributes)
		output := mapping.Metric + "\x00" + strings.Join(attributes, "\x00")
		owner.source = source
		for _, previous := range outputs[output] {
			mutuallyExclusiveVariants := !owner.synthetic && !previous.synthetic &&
				owner.group == previous.group && owner.pathSet == previous.pathSet &&
				owner.variant != previous.variant
			if !mutuallyExclusiveVariants {
				return fmt.Errorf("profile %q on %q has colliding metric identity from %q and %q", profile.Name, profile.Platform, previous.source, source)
			}
		}
		outputs[output] = append(outputs[output], owner)
		return nil
	}
	for mappingIndex := range profile.Synthetic {
		if err := validate(profile.Synthetic[mappingIndex], mappingOwner{synthetic: true}); err != nil {
			return err
		}
	}
	for pathIndex := range profile.Paths {
		path := &profile.Paths[pathIndex]
		for mappingIndex := range path.Mappings {
			if err := validate(path.Mappings[mappingIndex], mappingOwner{
				group: path.Group, pathSet: path.PathSetID, variant: path.VariantID,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateID(kind, value string) error {
	if !idPattern.MatchString(value) {
		return fmt.Errorf("%s ID %q is invalid", kind, value)
	}
	return nil
}

func validateRelativeFile(kind, id, file string) error {
	if file == "" || filepath.IsAbs(file) || filepath.Clean(file) != file || file == ".." || strings.HasPrefix(file, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s %q file must be a clean relative path", kind, id)
	}
	return nil
}

func validPlatform(platform string) bool {
	return platform == "ios_xe" || platform == "ios_xr" || platform == "nx_os"
}

func validCoverageStatus(status string) bool {
	switch status {
	case "cataloged", "implemented", "fixture_passed", "live_qualified", "n_a", "findings":
		return true
	default:
		return false
	}
}

func countString(values []string, want string) int {
	count := 0
	for _, value := range values {
		if value == want {
			count++
		}
	}
	return count
}
