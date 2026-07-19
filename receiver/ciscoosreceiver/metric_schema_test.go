// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/constant"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
	"gopkg.in/yaml.v3"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metricschemagen"
)

type metricMetadataCatalog struct {
	Metrics map[string]struct{} `yaml:"metrics"`
}

type metricMetadataDocument struct {
	Metrics map[string]metricMetadataDefinition `yaml:"metrics"`
}

type metricMetadataDefinition struct {
	Description string               `yaml:"description"`
	Unit        string               `yaml:"unit"`
	Attributes  []string             `yaml:"attributes"`
	Gauge       *metricMetadataGauge `yaml:"gauge"`
	Sum         *metricMetadataSum   `yaml:"sum"`
}

type metricMetadataGauge struct {
	ValueType string `yaml:"value_type"`
}

type metricMetadataSum struct {
	AggregationTemporality string `yaml:"aggregation_temporality"`
	Monotonic              bool   `yaml:"monotonic"`
	ValueType              string `yaml:"value_type"`
}

type metricSchemaFunction struct {
	name       string
	file       string
	body       *ast.BlockStmt
	parameters map[string]int
	object     any
}

type metricSchemaSource struct {
	functions    []metricSchemaFunction
	fset         *token.FileSet
	packagePath  string
	typeInfo     *types.Info
	typedStrings map[token.Pos]string
	callAliases  map[any]any
}

type dynamicMetricRegistrySource uint8

const (
	dynamicMetricRegistrySourceUnknown dynamicMetricRegistrySource = iota
	dynamicMetricRegistryStaticCallsites
	dynamicMetricRegistryBuiltinOrConfiguredGNMI
	dynamicMetricRegistryIntersightQueries
	dynamicMetricRegistryYANGPath
	dynamicMetricRegistrySDWANManagerFields
)

type dynamicMetricInstrument uint8

const (
	dynamicMetricInstrumentUnknown dynamicMetricInstrument = iota
	dynamicMetricInstrumentGauge
	dynamicMetricInstrumentSum
	dynamicMetricInstrumentGaugeOrSum
	dynamicMetricInstrumentTypedRegistry
)

type dynamicMetricValueType uint8

const (
	dynamicMetricValueTypeUnknown dynamicMetricValueType = iota
	dynamicMetricValueTypeInt
	dynamicMetricValueTypeDouble
	// SourceNumber means one number type selected by the model-defined YANG
	// leaf; ConfiguredNumber means one type selected by an exact custom mapping.
	dynamicMetricValueTypeSourceNumber
	dynamicMetricValueTypeConfiguredNumber
	dynamicMetricValueTypeRegistryNumber
)

type dynamicMetricUnitSource uint8

const (
	dynamicMetricUnitSourceUnknown dynamicMetricUnitSource = iota
	dynamicMetricUnitSourceFixed
	dynamicMetricUnitSourceRegistry
	dynamicMetricUnitSourceConfiguration
	dynamicMetricUnitSourceEmpty
)

type dynamicMetricMonotonicity uint8

const (
	dynamicMetricMonotonicityUnknown dynamicMetricMonotonicity = iota
	dynamicMetricMonotonicityNotApplicable
	dynamicMetricMonotonicityCumulative
	dynamicMetricMonotonicityRegistry
)

type dynamicMetricSchema struct {
	instrument   dynamicMetricInstrument
	valueType    dynamicMetricValueType
	unitSource   dynamicMetricUnitSource
	monotonicity dynamicMetricMonotonicity
}

type typedDynamicMetricSite struct {
	count             int
	registrySource    dynamicMetricRegistrySource
	namePattern       string
	descriptionSource string
	schemas           []dynamicMetricSchema
}

var (
	dynamicGaugeIntFixed = []dynamicMetricSchema{{
		instrument:   dynamicMetricInstrumentGauge,
		valueType:    dynamicMetricValueTypeInt,
		unitSource:   dynamicMetricUnitSourceFixed,
		monotonicity: dynamicMetricMonotonicityNotApplicable,
	}}
	dynamicGaugeDoubleRegistry = []dynamicMetricSchema{{
		instrument:   dynamicMetricInstrumentGauge,
		valueType:    dynamicMetricValueTypeDouble,
		unitSource:   dynamicMetricUnitSourceRegistry,
		monotonicity: dynamicMetricMonotonicityNotApplicable,
	}}
	dynamicYANGNumber = []dynamicMetricSchema{
		{
			instrument:   dynamicMetricInstrumentGaugeOrSum,
			valueType:    dynamicMetricValueTypeSourceNumber,
			unitSource:   dynamicMetricUnitSourceEmpty,
			monotonicity: dynamicMetricMonotonicityCumulative,
		},
	}
	dynamicYANGInfo = []dynamicMetricSchema{{
		instrument:   dynamicMetricInstrumentGauge,
		valueType:    dynamicMetricValueTypeDouble,
		unitSource:   dynamicMetricUnitSourceEmpty,
		monotonicity: dynamicMetricMonotonicityNotApplicable,
	}}
)

var typedDynamicMetricSites = map[string]typedDynamicMetricSite{
	"aci_receiver.go:flushCounts: metricName": {
		count:             1,
		registrySource:    dynamicMetricRegistryStaticCallsites,
		namePattern:       "statically enumerated aciMetricsBuilder.addCount names",
		descriptionSource: "aciCountDescription and metadata.yaml",
		schemas:           dynamicGaugeIntFixed,
	},
	"batch.go:buildMetricChunk: point.Metric.Name": {
		count:             1,
		registrySource:    dynamicMetricRegistryBuiltinOrConfiguredGNMI,
		namePattern:       "builtinGNMIMetricMetadata or validated GNMIMetricMappingConfig.MetricName",
		descriptionSource: "builtinGNMIMetricDescriptors or validated GNMIMetricMappingConfig",
		schemas: []dynamicMetricSchema{
			{instrument: dynamicMetricInstrumentTypedRegistry, valueType: dynamicMetricValueTypeRegistryNumber, unitSource: dynamicMetricUnitSourceRegistry, monotonicity: dynamicMetricMonotonicityRegistry},
			{instrument: dynamicMetricInstrumentGauge, valueType: dynamicMetricValueTypeConfiguredNumber, unitSource: dynamicMetricUnitSourceConfiguration, monotonicity: dynamicMetricMonotonicityNotApplicable},
		},
	},
	"catalyst9800_metrics.go:appendCatalyst9800InfoMetricIndexed: name": {
		count:             1,
		registrySource:    dynamicMetricRegistryYANGPath,
		namePattern:       "cisco.catalyst9800.yang.<sanitized-module>.<sanitized-path>_info",
		descriptionSource: "governedDynamicMetricNamePatterns Catalyst 9800 info variant",
		schemas:           dynamicYANGInfo,
	},
	"catalyst9800_metrics.go:appendCatalyst9800MetricNumberIndexed: name": {
		count:             2,
		registrySource:    dynamicMetricRegistryYANGPath,
		namePattern:       "cisco.catalyst9800.yang.<sanitized-module>.<sanitized-path>",
		descriptionSource: "governedDynamicMetricNamePatterns Catalyst 9800 numeric variant",
		schemas:           dynamicYANGNumber,
	},
	"catalyst9800_metrics.go:normalize$literal: catalyst9800MetricName(module, parts)": {
		count:             1,
		registrySource:    dynamicMetricRegistryYANGPath,
		namePattern:       "cisco.catalyst9800.yang.<sanitized-module>.<sanitized-path>",
		descriptionSource: "governedDynamicMetricNamePatterns Catalyst 9800 numeric variant",
		schemas:           dynamicYANGNumber,
	},
	"catalyst_center_receiver.go:flushCounts: metricName": {
		count:             1,
		registrySource:    dynamicMetricRegistryStaticCallsites,
		namePattern:       "statically enumerated catalystCenterMetricsBuilder.addCount names",
		descriptionSource: "catalystCenterCountDescription and metadata.yaml",
		schemas:           dynamicGaugeIntFixed,
	},
	"fmc_receiver.go:flushCounts: metricName": {
		count:             1,
		registrySource:    dynamicMetricRegistryStaticCallsites,
		namePattern:       "statically enumerated fmcMetricsBuilder.addCount names",
		descriptionSource: "fmcCountDescription and metadata.yaml",
		schemas:           dynamicGaugeIntFixed,
	},
	"intersight_receiver.go:flushCounts: metricName": {
		count:             1,
		registrySource:    dynamicMetricRegistryStaticCallsites,
		namePattern:       "statically enumerated intersightMetricsBuilder.addCount names",
		descriptionSource: "intersightCountDescription and metadata.yaml",
		schemas:           dynamicGaugeIntFixed,
	},
	"intersight_receiver.go:recordTelemetry: query.metricName": {
		count:             1,
		registrySource:    dynamicMetricRegistryIntersightQueries,
		namePattern:       "intersightTelemetryQueries[*].metricName",
		descriptionSource: "intersightTelemetryQueries[*].description",
		schemas:           dynamicGaugeDoubleRegistry,
	},
	"iosxr_metrics.go:appendIOSXRInfoMetricIndexed: name": {
		count:             1,
		registrySource:    dynamicMetricRegistryYANGPath,
		namePattern:       "cisco.iosxr.yang.<sanitized-module>.<sanitized-path>_info",
		descriptionSource: "governedDynamicMetricNamePatterns IOS XR info variant",
		schemas:           dynamicYANGInfo,
	},
	"iosxr_metrics.go:appendIOSXRMetricNumberIndexed: name": {
		count:             2,
		registrySource:    dynamicMetricRegistryYANGPath,
		namePattern:       "cisco.iosxr.yang.<sanitized-module>.<sanitized-path>",
		descriptionSource: "governedDynamicMetricNamePatterns IOS XR numeric variant",
		schemas:           dynamicYANGNumber,
	},
	"iosxr_metrics.go:normalize$literal: iosXRMetricName(module, pathParts)": {
		count:             1,
		registrySource:    dynamicMetricRegistryYANGPath,
		namePattern:       "cisco.iosxr.yang.<sanitized-module>.<sanitized-path>",
		descriptionSource: "governedDynamicMetricNamePatterns IOS XR numeric variant",
		schemas:           dynamicYANGNumber,
	},
	"ise_receiver.go:flushCounts: name": {
		count:             1,
		registrySource:    dynamicMetricRegistryStaticCallsites,
		namePattern:       "statically enumerated iseMetricsBuilder.addCount names",
		descriptionSource: "iseCountDescription and metadata.yaml",
		schemas:           dynamicGaugeIntFixed,
	},
	"nexusdashboard_receiver.go:flushCounts: metricName": {
		count:             1,
		registrySource:    dynamicMetricRegistryStaticCallsites,
		namePattern:       "statically enumerated nexusDashboardMetricsBuilder.addCount names",
		descriptionSource: "nexusDashboardCountDescription and metadata.yaml",
		schemas:           dynamicGaugeIntFixed,
	},
	"sdwan_receiver.go:flushCounts: metricName": {
		count:             1,
		registrySource:    dynamicMetricRegistryStaticCallsites,
		namePattern:       "statically enumerated sdwanMetricsBuilder.addCount names",
		descriptionSource: "sdwanCountDescription and metadata.yaml",
		schemas:           dynamicGaugeIntFixed,
	},
	"sdwan_receiver.go:recordManagerObject: field.metricName": {
		count:             2,
		registrySource:    dynamicMetricRegistrySDWANManagerFields,
		namePattern:       "sdwanManagerUtilizationMetricFields or sdwanManagerHealthMetricFields",
		descriptionSource: "typed SD-WAN Manager field registry",
		schemas: []dynamicMetricSchema{{
			instrument: dynamicMetricInstrumentGauge, valueType: dynamicMetricValueTypeDouble, unitSource: dynamicMetricUnitSourceRegistry, monotonicity: dynamicMetricMonotonicityNotApplicable,
		}},
	},
}

func TestMetricMetadataCatalogsMatchStaticEmitters(t *testing.T) {
	receiverCatalog := loadMetricMetadataCatalog(t, "metadata.yaml")
	receiverSource := loadMetricSchemaSource(t, ".")
	receiverMetrics, dynamicSites := receiverSource.staticMetricNames()
	receiverSchemas := receiverSource.staticMetricSchemas()
	gnmiSource := loadMetricSchemaSource(t, "internal/gnmi")
	gnmiMetrics, gnmiDynamicSites := gnmiSource.staticMetricNames()
	mergeMetricNameSets(receiverMetrics, gnmiMetrics)
	mergeDynamicMetricSites(dynamicSites, gnmiDynamicSites)
	mergeStaticMetricSchemas(receiverSchemas, gnmiSource.staticMetricSchemas())
	for name := range builtinGNMIMetricMetadata {
		receiverMetrics[name] = struct{}{}
	}
	for _, query := range intersightTelemetryQueries() {
		receiverMetrics[query.metricName] = struct{}{}
	}
	for _, field := range sdwanManagerUtilizationMetricFields {
		receiverMetrics[field.metricName] = struct{}{}
	}
	for _, field := range sdwanManagerHealthMetricFields {
		receiverMetrics[field.metricName] = struct{}{}
	}

	require.NoError(t, validateMetricGovernance(receiverMetrics, receiverCatalog, dynamicSites, typedDynamicMetricSites))
	require.NoError(t, validateStaticMetricSchemas(receiverSchemas))
	require.Equal(t, receiverCatalog, generatedMetricNames(t, "internal/metadata/generated_metrics.go"), "run mdatagen after changing the receiver metric catalog")

	for _, tc := range []struct {
		name string
		dir  string
	}{
		{name: "system", dir: "internal/scraper/systemscraper"},
		{name: "interfaces", dir: "internal/scraper/interfacesscraper"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			catalog := loadMetricMetadataCatalog(t, filepath.Join(tc.dir, "metadata.yaml"))
			source := loadMetricSchemaSource(t, tc.dir)
			emitted, dynamicSites := source.staticMetricNames()
			mergeMetricNameSets(emitted, source.generatedBuilderMetricNames(map[string]map[string]string{
				source.packagePath + "/internal/metadata": generatedMetricMethods(t, filepath.Join(tc.dir, "internal/metadata/generated_metrics.go")),
			}))
			require.NoError(t, validateMetricGovernance(emitted, catalog, dynamicSites, nil))
			require.NoError(t, validateStaticMetricSchemas(source.staticMetricSchemas()))
			require.Equal(t, catalog, generatedMetricNames(t, filepath.Join(tc.dir, "internal/metadata/generated_metrics.go")), "run mdatagen after changing the scraper metric catalog")
		})
	}
}

func TestEveryMetricEmitterPackageHasAnExplicitCatalogOwner(t *testing.T) {
	const receiverPackage = "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"
	loaded, err := packages.Load(&packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedSyntax |
			packages.NeedTypes |
			packages.NeedTypesInfo |
			packages.NeedTypesSizes |
			packages.NeedImports |
			packages.NeedDeps,
		Dir:   ".",
		Tests: false,
	}, "./...")
	require.NoError(t, err)
	require.NotEmpty(t, loaded)
	owned := map[string]string{
		receiverPackage:                                                           "metadata.yaml",
		receiverPackage + "/internal/gnmi":                                        "metadata.yaml",
		receiverPackage + "/internal/metadata":                                    "metadata.yaml",
		receiverPackage + "/internal/scraper/systemscraper":                       "internal/scraper/systemscraper/metadata.yaml",
		receiverPackage + "/internal/scraper/systemscraper/internal/metadata":     "internal/scraper/systemscraper/metadata.yaml",
		receiverPackage + "/internal/scraper/interfacesscraper":                   "internal/scraper/interfacesscraper/metadata.yaml",
		receiverPackage + "/internal/scraper/interfacesscraper/internal/metadata": "internal/scraper/interfacesscraper/metadata.yaml",
	}
	generatedMethods := map[string]map[string]string{
		receiverPackage + "/internal/scraper/systemscraper/internal/metadata":     generatedMetricMethods(t, "internal/scraper/systemscraper/internal/metadata/generated_metrics.go"),
		receiverPackage + "/internal/scraper/interfacesscraper/internal/metadata": generatedMetricMethods(t, "internal/scraper/interfacesscraper/internal/metadata/generated_metrics.go"),
	}
	for _, pkg := range loaded {
		for _, packageError := range pkg.Errors {
			require.NoError(t, packageError, "type-check package %s", pkg.PkgPath)
		}
		source := metricSchemaSourceFromPackage(t, pkg)
		staticNames, dynamicSites := source.staticMetricNames()
		builderNames := source.generatedBuilderMetricNames(generatedMethods)
		catalogPath, cataloged := owned[pkg.PkgPath]
		if cataloged {
			catalog := loadMetricMetadataCatalog(t, catalogPath)
			allNames := make(map[string]struct{}, len(staticNames)+len(builderNames))
			mergeMetricNameSets(allNames, staticNames)
			mergeMetricNameSets(allNames, builderNames)
			require.Empty(t, setDifference(allNames, catalog), "%s emits metrics outside its declared catalog %s", pkg.PkgPath, catalogPath)
			if strings.HasSuffix(pkg.PkgPath, "/internal/metadata") {
				require.Empty(t, dynamicSites, "%s generated metadata constructs an ungoverned dynamic metric name", pkg.PkgPath)
			}
			continue
		}
		require.Empty(t, staticNames, "%s emits fixed metrics but has no explicit catalog owner", pkg.PkgPath)
		require.Empty(t, dynamicSites, "%s constructs dynamic metric names but has no explicit catalog owner", pkg.PkgPath)
		require.Empty(t, builderNames, "%s calls a generated metric builder but has no explicit catalog owner", pkg.PkgPath)
	}
}

func TestGeneratedFixedMetricSchemaMatchesMetadata(t *testing.T) {
	metadata, err := os.ReadFile("metadata.yaml")
	require.NoError(t, err)
	generated, err := metricschemagen.Generate(metadata)
	require.NoError(t, err)
	committed, err := os.ReadFile("generated_metric_schema.go")
	require.NoError(t, err)
	require.Equal(t, string(generated), string(committed), "run go generate after changing the receiver metric catalog")
	require.Len(t, fixedMetricDescriptors, len(loadMetricMetadataCatalog(t, "metadata.yaml")))
}

func TestMetricDocumentationRejectsStaleNames(t *testing.T) {
	paths := []string{"README.md"}
	require.NoError(t, filepath.WalkDir("docs", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".md") {
			paths = append(paths, path)
		}
		return nil
	}))
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NotContains(t, string(contents), "system.network.packets", "%s uses the removed metric name; use system.network.packet.count", path)
	}
}

func TestMetricGovernanceDocumentationDeclaresNarrowAttributeAndDynamicNameScope(t *testing.T) {
	contents, err := os.ReadFile("docs/metrics.md")
	require.NoError(t, err)
	documentation := string(contents)
	require.Contains(t, documentation, "Attribute governance is deliberately narrower")
	require.Contains(t, documentation, "does not claim an exhaustive attribute union")
	require.Contains(t, documentation, "exact fixed-name completeness")
	require.Contains(t, documentation, "injective `cisco.yang.source_path` attribute")
}

func TestGovernedDynamicYANGPatternsHaveTypedCollisionContracts(t *testing.T) {
	require.Len(t, governedDynamicMetricNamePatterns, 2)
	for _, pattern := range governedDynamicMetricNamePatterns {
		require.NotEmpty(t, pattern.prefix)
		require.NotEmpty(t, pattern.contract)
		require.Equal(t, "sanitized YANG module and leaf path", pattern.nameSource)
		require.Equal(t, "cisco.yang.source_path", pattern.collisionAttribute)
		require.Equal(t, "_info", pattern.reservedNumericSuffix)
		require.Equal(t, []governedDynamicMetricVariant{
			{
				instrument:  governedDynamicMetricInstrumentGaugeOrCumulativeSum,
				valueType:   governedDynamicMetricValueTypeSourceNumber,
				temporality: fixedMetricTemporalityCumulative,
				monotonic:   true,
			},
			{
				suffix:     "_info",
				instrument: governedDynamicMetricInstrumentGauge,
				valueType:  governedDynamicMetricValueTypeDouble,
			},
		}, pattern.variants)
	}
}

func TestMetricGovernanceRejectsInvalidFixtures(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fixture     string
		errorString string
	}{
		{
			name:        "emitted static name missing from catalog",
			fixture:     "missing_static",
			errorString: "emitted static metric names missing from catalog: fixture.missing",
		},
		{
			name:        "stale catalog entry",
			fixture:     "stale_catalog",
			errorString: "catalog entries without a static emitter: fixture.stale",
		},
		{
			name:        "dynamic construction without typed registry",
			fixture:     "unregistered_dynamic",
			errorString: "dynamic metric-name sites without an exact typed registry entry",
		},
		{
			name:        "unresolved metric-name wrapper without a typed caller",
			fixture:     "unresolved_wrapper",
			errorString: "unresolved metric-name parameter name",
		},
		{
			name:        "local constant without a dot in a dead branch is still governed",
			fixture:     "missing_local_constant",
			errorString: "emitted static metric names missing from catalog: heartbeat",
		},
		{
			name:        "package-level function literal is still governed",
			fixture:     "missing_top_level_literal",
			errorString: "emitted static metric names missing from catalog: fixture.top_level_literal",
		},
		{
			name:        "pmetric SetName method value retains its typed callee",
			fixture:     "missing_method_value",
			errorString: "emitted static metric names missing from catalog: fixture.method_value",
		},
		{
			name:        "parenthesized pmetric SetName retains its typed callee",
			fixture:     "missing_parenthesized_direct",
			errorString: "emitted static metric names missing from catalog: fixture.parenthesized_direct",
		},
		{
			name:        "parenthesized pmetric SetName method value retains its typed callee",
			fixture:     "missing_parenthesized_alias",
			errorString: "emitted static metric names missing from catalog: fixture.parenthesized_alias",
		},
		{
			name:        "owned child package direct SetName is reconciled to its catalog",
			fixture:     "owned_child_static",
			errorString: "emitted static metric names missing from catalog: fixture.owned_child",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join("testdata", "metric_schema", tc.fixture)
			emitted, dynamicSites := loadMetricSchemaSource(t, dir).staticMetricNames()
			catalog := loadMetricMetadataCatalog(t, filepath.Join(dir, "metadata.yaml"))

			err := validateMetricGovernance(emitted, catalog, dynamicSites, nil)
			require.ErrorContains(t, err, tc.errorString)
		})
	}
}

func TestMetricGovernanceResolvesTypedCallees(t *testing.T) {
	dir := filepath.Join("testdata", "metric_schema", "typed_callee")
	emitted, dynamicSites := loadMetricSchemaSource(t, dir).staticMetricNames()
	catalog := loadMetricMetadataCatalog(t, filepath.Join(dir, "metadata.yaml"))
	require.NoError(t, validateMetricGovernance(emitted, catalog, dynamicSites, nil))
}

func TestMetricGovernanceRejectsStaticSchemaConflictFixture(t *testing.T) {
	for _, tc := range []struct {
		fixture     string
		errorString string
	}{
		{fixture: "conflicting_schema", errorString: "conflicting static schemas for fixture.conflict"},
		{fixture: "conflicting_value_type", errorString: "conflicting static schemas for fixture.numeric_conflict"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			schemas := loadMetricSchemaSource(t, filepath.Join("testdata", "metric_schema", tc.fixture)).staticMetricSchemas()
			err := validateStaticMetricSchemas(schemas)
			require.ErrorContains(t, err, tc.errorString)
		})
	}
}

func validateMetricGovernance(
	emitted,
	catalog map[string]struct{},
	dynamicSites map[string]int,
	dynamicRegistry map[string]typedDynamicMetricSite,
) error {
	problems := make([]string, 0, 3)
	if missing := setDifference(emitted, catalog); len(missing) > 0 {
		problems = append(problems, "emitted static metric names missing from catalog: "+strings.Join(missing, ", "))
	}
	if stale := setDifference(catalog, emitted); len(stale) > 0 {
		problems = append(problems, "catalog entries without a static emitter: "+strings.Join(stale, ", "))
	}

	expectedDynamicSites, registryProblems := validateDynamicMetricRegistry(dynamicRegistry)
	problems = append(problems, registryProblems...)
	if unexpected := dynamicSiteDifferences(dynamicSites, expectedDynamicSites); len(unexpected) > 0 {
		problems = append(problems, "dynamic metric-name sites without an exact typed registry entry: "+strings.Join(unexpected, ", "))
	}
	if missing := dynamicSiteDifferences(expectedDynamicSites, dynamicSites); len(missing) > 0 {
		problems = append(problems, "typed dynamic metric registry entries without a matching construction site: "+strings.Join(missing, ", "))
	}

	if len(problems) > 0 {
		return fmt.Errorf("metric schema governance failed:\n- %s", strings.Join(problems, "\n- "))
	}
	return nil
}

func validateDynamicMetricRegistry(registry map[string]typedDynamicMetricSite) (map[string]int, []string) {
	counts := make(map[string]int, len(registry))
	problems := make([]string, 0)
	for site, documentation := range registry {
		siteProblems := make([]string, 0)
		if documentation.count <= 0 {
			siteProblems = append(siteProblems, "positive construction count")
		}
		if documentation.registrySource <= dynamicMetricRegistrySourceUnknown || documentation.registrySource > dynamicMetricRegistrySDWANManagerFields {
			siteProblems = append(siteProblems, "typed name source")
		}
		if documentation.namePattern == "" {
			siteProblems = append(siteProblems, "name pattern or exact registry")
		}
		if documentation.descriptionSource == "" {
			siteProblems = append(siteProblems, "description source")
		}
		if len(documentation.schemas) == 0 {
			siteProblems = append(siteProblems, "at least one metric schema")
		}
		for i, schema := range documentation.schemas {
			if problem := validateDynamicMetricSchema(schema); problem != "" {
				siteProblems = append(siteProblems, fmt.Sprintf("schema %d %s", i, problem))
			}
		}
		if len(siteProblems) > 0 {
			problems = append(problems, fmt.Sprintf("dynamic metric registry entry %q lacks %s", site, strings.Join(siteProblems, ", ")))
		}
		counts[site] = documentation.count
	}
	return counts, problems
}

func validateDynamicMetricSchema(schema dynamicMetricSchema) string {
	if schema.instrument <= dynamicMetricInstrumentUnknown || schema.instrument > dynamicMetricInstrumentTypedRegistry {
		return "a valid instrument"
	}
	if schema.valueType <= dynamicMetricValueTypeUnknown || schema.valueType > dynamicMetricValueTypeRegistryNumber {
		return "a valid value type"
	}
	if schema.unitSource <= dynamicMetricUnitSourceUnknown || schema.unitSource > dynamicMetricUnitSourceEmpty {
		return "a unit policy"
	}
	if schema.monotonicity <= dynamicMetricMonotonicityUnknown || schema.monotonicity > dynamicMetricMonotonicityRegistry {
		return "a monotonicity policy"
	}
	if schema.instrument == dynamicMetricInstrumentGauge && schema.monotonicity != dynamicMetricMonotonicityNotApplicable {
		return "gauge monotonicity marked not applicable"
	}
	if schema.instrument != dynamicMetricInstrumentGauge && schema.monotonicity == dynamicMetricMonotonicityNotApplicable {
		return "sum monotonicity"
	}
	if schema.instrument == dynamicMetricInstrumentTypedRegistry && schema.monotonicity != dynamicMetricMonotonicityRegistry {
		return "typed-registry monotonicity"
	}
	if schema.instrument == dynamicMetricInstrumentTypedRegistry && (schema.valueType != dynamicMetricValueTypeRegistryNumber || schema.unitSource != dynamicMetricUnitSourceRegistry) {
		return "one exact typed-registry descriptor"
	}
	if schema.instrument != dynamicMetricInstrumentTypedRegistry && schema.monotonicity == dynamicMetricMonotonicityRegistry {
		return "registry monotonicity only for typed-registry descriptors"
	}
	if schema.valueType == dynamicMetricValueTypeConfiguredNumber && (schema.instrument != dynamicMetricInstrumentGauge || schema.unitSource != dynamicMetricUnitSourceConfiguration) {
		return "one exact configured gauge descriptor"
	}
	return ""
}

func dynamicSiteDifferences(left, right map[string]int) []string {
	difference := make([]string, 0)
	for site, count := range left {
		if right[site] != count {
			difference = append(difference, fmt.Sprintf("%s (got %d, want %d)", site, count, right[site]))
		}
	}
	sort.Strings(difference)
	return difference
}

func loadMetricMetadataCatalog(t *testing.T, path string) map[string]struct{} {
	t.Helper()

	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	var catalog metricMetadataCatalog
	require.NoError(t, yaml.Unmarshal(contents, &catalog))
	require.NotEmpty(t, catalog.Metrics)
	return catalog.Metrics
}

func loadMetricMetadataDefinitions(t *testing.T, path string) map[string]metricMetadataDefinition {
	t.Helper()

	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	var document metricMetadataDocument
	require.NoError(t, yaml.Unmarshal(contents, &document))
	require.NotEmpty(t, document.Metrics)
	return document.Metrics
}

func loadMetricSchemaSource(t *testing.T, dir string) metricSchemaSource {
	t.Helper()

	absDir, err := filepath.Abs(dir)
	require.NoError(t, err)
	loaded, err := packages.Load(&packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedSyntax |
			packages.NeedTypes |
			packages.NeedTypesInfo |
			packages.NeedTypesSizes |
			packages.NeedImports |
			packages.NeedDeps,
		Dir:   absDir,
		Tests: false,
	}, ".")
	require.NoError(t, err)
	require.Len(t, loaded, 1, "metric emitter source must resolve to one Go package")
	pkg := loaded[0]
	for _, packageError := range pkg.Errors {
		require.NoError(t, packageError, "type-check metric emitter package %s", pkg.PkgPath)
	}
	return metricSchemaSourceFromPackage(t, pkg)
}

func metricSchemaSourceFromPackage(t *testing.T, pkg *packages.Package) metricSchemaSource {
	t.Helper()
	source := metricSchemaSource{
		fset:         pkg.Fset,
		packagePath:  pkg.PkgPath,
		typeInfo:     pkg.TypesInfo,
		typedStrings: map[token.Pos]string{},
		callAliases:  map[any]any{},
	}
	for index, file := range pkg.Syntax {
		path := pkg.CompiledGoFiles[index]
		base := filepath.Base(path)
		if strings.HasSuffix(base, "_test.go") {
			continue
		}
		ast.Inspect(file, func(node ast.Node) bool {
			expression, ok := node.(ast.Expr)
			if !ok {
				return true
			}
			value := pkg.TypesInfo.Types[expression].Value
			if value != nil && value.Kind() == constant.String {
				source.typedStrings[expression.Pos()] = constant.StringVal(value)
			}
			return true
		})

		registeredLiterals := map[token.Pos]struct{}{}
		registerLiteral := func(name string, literal *ast.FuncLit, object any) {
			if literal == nil {
				return
			}
			if _, exists := registeredLiterals[literal.Pos()]; exists {
				return
			}
			registeredLiterals[literal.Pos()] = struct{}{}
			source.functions = append(source.functions, metricSchemaFunction{
				name:       name,
				file:       path,
				body:       literal.Body,
				parameters: metricSchemaParameters(literal.Type),
				object:     object,
			})
		}

		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			source.functions = append(source.functions, metricSchemaFunction{
				name:       function.Name.Name,
				file:       path,
				body:       function.Body,
				parameters: metricSchemaParameters(function.Type),
				object:     pkg.TypesInfo.Defs[function.Name],
			})
			ast.Inspect(function.Body, func(node ast.Node) bool {
				if assignment, ok := node.(*ast.AssignStmt); ok && len(assignment.Lhs) == len(assignment.Rhs) {
					for i, rhs := range assignment.Rhs {
						literal, literalOK := rhs.(*ast.FuncLit)
						name, nameOK := assignment.Lhs[i].(*ast.Ident)
						if !literalOK || !nameOK {
							continue
						}
						registerLiteral(name.Name, literal, pkg.TypesInfo.Defs[name])
					}
				}
				if values, ok := node.(*ast.ValueSpec); ok && len(values.Names) == len(values.Values) {
					for i, value := range values.Values {
						if literal, literalOK := value.(*ast.FuncLit); literalOK {
							registerLiteral(values.Names[i].Name, literal, pkg.TypesInfo.Defs[values.Names[i]])
						}
					}
				}
				if literal, ok := node.(*ast.FuncLit); ok {
					registerLiteral(function.Name.Name+"$literal", literal, literal)
				}
				return true
			})
		}

		// Package-level function values are emitter code too, even if their
		// declaration is not a FuncDecl or the variable is never invoked.
		for _, declaration := range file.Decls {
			generated, ok := declaration.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, specification := range generated.Specs {
				values, ok := specification.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for index, value := range values.Values {
					name := "package$literal"
					var object any = value
					if index < len(values.Names) {
						name = values.Names[index].Name
						object = pkg.TypesInfo.Defs[values.Names[index]]
					}
					if literal, direct := value.(*ast.FuncLit); direct {
						registerLiteral(name, literal, object)
					}
					ast.Inspect(value, func(node ast.Node) bool {
						if literal, nested := node.(*ast.FuncLit); nested {
							registerLiteral(name+"$literal", literal, literal)
						}
						return true
					})
				}
			}
		}

		// Resolve local and package-level aliases of callable values. In
		// particular, a method value such as setName := metric.SetName must
		// retain the pmetric SetName identity at its later callsite.
		registerAlias := func(identifier *ast.Ident, expression ast.Expr) {
			if identifier == nil || expression == nil {
				return
			}
			typ := pkg.TypesInfo.TypeOf(expression)
			if typ == nil {
				return
			}
			if _, callable := typ.Underlying().(*types.Signature); !callable {
				return
			}
			alias := pkg.TypesInfo.Defs[identifier]
			if alias == nil {
				alias = pkg.TypesInfo.Uses[identifier]
			}
			if target := source.expressionObject(expression); alias != nil && target != nil && alias != target {
				source.callAliases[alias] = target
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.AssignStmt:
				if len(typed.Lhs) == len(typed.Rhs) {
					for index, rhs := range typed.Rhs {
						identifier, _ := typed.Lhs[index].(*ast.Ident)
						registerAlias(identifier, rhs)
					}
				}
			case *ast.ValueSpec:
				if len(typed.Names) == len(typed.Values) {
					for index, value := range typed.Values {
						registerAlias(typed.Names[index], value)
					}
				}
			}
			return true
		})
	}
	return source
}

func metricSchemaParameters(functionType *ast.FuncType) map[string]int {
	parameters := map[string]int{}
	index := 0
	if functionType.Params == nil {
		return parameters
	}
	for _, field := range functionType.Params.List {
		if len(field.Names) == 0 {
			index++
			continue
		}
		for _, name := range field.Names {
			parameters[name.Name] = index
			index++
		}
	}
	return parameters
}

func (s metricSchemaSource) staticMetricNames() (map[string]struct{}, map[string]int) {
	metricParameters := map[any]map[int]struct{}{}
	calledMetricParameters := map[any]map[int]struct{}{}
	for _, function := range s.functions {
		// Count aggregators retain the name separately from the eventual metric
		// builder call, so seed each concrete typed method explicitly.
		if function.name == "addCount" {
			addMetricParameter(metricParameters, function.object, 0)
		}
	}

	for _, function := range s.functions {
		inspectMetricSchemaFunction(function.body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || !s.isMetricSetName(call) || len(call.Args) != 1 {
				return true
			}
			if parameter, ok := call.Args[0].(*ast.Ident); ok {
				if index, exists := function.parameters[parameter.Name]; exists {
					addMetricParameter(metricParameters, function.object, index)
				}
			}
			return true
		})
	}

	changed := true
	for changed {
		changed = false
		for _, function := range s.functions {
			inspectMetricSchemaFunction(function.body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				callee := s.callObject(call)
				for index := range metricParameters[callee] {
					if index >= len(call.Args) {
						continue
					}
					parameter, ok := call.Args[index].(*ast.Ident)
					if !ok {
						continue
					}
					callerIndex, exists := function.parameters[parameter.Name]
					if exists && addMetricParameter(metricParameters, function.object, callerIndex) {
						changed = true
					}
				}
				return true
			})
		}
	}

	names := map[string]struct{}{}
	dynamic := map[string]int{}
	for _, function := range s.functions {
		inspectMetricSchemaFunction(function.body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if s.isMetricSetName(call) && len(call.Args) == 1 {
				s.collectMetricArgument(function, call.Args[0], names, dynamic)
				return true
			}
			for index := range metricParameters[s.callObject(call)] {
				if index < len(call.Args) {
					addMetricParameter(calledMetricParameters, s.callObject(call), index)
					s.collectMetricArgument(function, call.Args[index], names, dynamic)
				}
			}
			return true
		})
	}
	for _, function := range s.functions {
		for index := range metricParameters[function.object] {
			if _, called := calledMetricParameters[function.object][index]; called {
				continue
			}
			parameterName := "<unnamed>"
			for name, parameterIndex := range function.parameters {
				if parameterIndex == index {
					parameterName = name
					break
				}
			}
			dynamic[fmt.Sprintf("%s:%s: unresolved metric-name parameter %s", filepath.Base(function.file), function.name, parameterName)]++
		}
	}

	return names, dynamic
}

func (s metricSchemaSource) generatedBuilderMetricNames(methodsByPackage map[string]map[string]string) map[string]struct{} {
	names := map[string]struct{}{}
	for _, function := range s.functions {
		inspectMetricSchemaFunction(function.body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			method, ok := s.callObject(call).(*types.Func)
			if !ok || method.Pkg() == nil {
				return true
			}
			if metricName, exists := methodsByPackage[method.Pkg().Path()][method.Name()]; exists {
				names[metricName] = struct{}{}
			}
			return true
		})
	}
	return names
}

func inspectMetricSchemaFunction(body *ast.BlockStmt, visit func(ast.Node) bool) {
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nestedFunction := node.(*ast.FuncLit); nestedFunction {
			return false
		}
		return visit(node)
	})
}

func (s metricSchemaSource) collectMetricArgument(function metricSchemaFunction, expression ast.Expr, names map[string]struct{}, dynamic map[string]int) {
	if value, ok := s.staticString(expression); ok {
		names[value] = struct{}{}
		return
	}
	if identifier, ok := expression.(*ast.Ident); ok {
		if _, parameter := function.parameters[identifier.Name]; parameter {
			return
		}
	}
	var formatted bytes.Buffer
	if err := format.Node(&formatted, s.fset, expression); err != nil {
		formatted.WriteString("<unprintable>")
	}
	dynamic[fmt.Sprintf("%s:%s: %s", filepath.Base(function.file), function.name, formatted.String())]++
}

func addMetricParameter(parameters map[any]map[int]struct{}, function any, index int) bool {
	if function == nil {
		return false
	}
	if parameters[function] == nil {
		parameters[function] = map[int]struct{}{}
	}
	if _, exists := parameters[function][index]; exists {
		return false
	}
	parameters[function][index] = struct{}{}
	return true
}

func (s metricSchemaSource) callObject(call *ast.CallExpr) any {
	return s.resolveCallAlias(s.expressionObject(call.Fun))
}

func (s metricSchemaSource) expressionObject(expression ast.Expr) any {
	if s.typeInfo == nil || expression == nil {
		return nil
	}
	for {
		parenthesized, ok := expression.(*ast.ParenExpr)
		if !ok {
			break
		}
		expression = parenthesized.X
	}
	switch function := expression.(type) {
	case *ast.Ident:
		return s.typeInfo.Uses[function]
	case *ast.SelectorExpr:
		if selection := s.typeInfo.Selections[function]; selection != nil {
			return selection.Obj()
		}
		return s.typeInfo.Uses[function.Sel]
	default:
		return nil
	}
}

func (s metricSchemaSource) resolveCallAlias(object any) any {
	seen := map[any]struct{}{}
	for object != nil {
		if _, exists := seen[object]; exists {
			return nil
		}
		seen[object] = struct{}{}
		target, aliased := s.callAliases[object]
		if !aliased {
			return object
		}
		object = target
	}
	return nil
}

func (s metricSchemaSource) isMetricSetName(call *ast.CallExpr) bool {
	method, ok := s.callObject(call).(*types.Func)
	return ok && method.Name() == "SetName" && method.Pkg() != nil && method.Pkg().Path() == "go.opentelemetry.io/collector/pdata/pmetric"
}

func callName(call *ast.CallExpr) string {
	switch function := call.Fun.(type) {
	case *ast.Ident:
		return function.Name
	case *ast.SelectorExpr:
		return function.Sel.Name
	default:
		return ""
	}
}

func (s metricSchemaSource) staticString(expression ast.Expr) (string, bool) {
	if value, ok := s.typedStrings[expression.Pos()]; ok {
		return value, true
	}
	return staticStringLiteral(expression)
}

func staticStringLiteral(expression ast.Expr) (string, bool) {
	switch typed := expression.(type) {
	case *ast.BasicLit:
		if typed.Kind != token.STRING {
			return "", false
		}
		value, err := strconv.Unquote(typed.Value)
		return value, err == nil
	case *ast.BinaryExpr:
		if typed.Op != token.ADD {
			return "", false
		}
		left, leftOK := staticStringLiteral(typed.X)
		right, rightOK := staticStringLiteral(typed.Y)
		return left + right, leftOK && rightOK
	default:
		return "", false
	}
}

func generatedMetricMethods(t *testing.T, path string) map[string]string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	require.NoError(t, err)
	methodPattern := regexp.MustCompile(`^Record[^ ]+DataPoint adds a data point to ([^ ]+) metric\.$`)
	methods := map[string]string{}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Doc == nil {
			continue
		}
		match := methodPattern.FindStringSubmatch(strings.TrimSpace(function.Doc.Text()))
		if len(match) == 2 {
			methods[function.Name.Name] = match[1]
		}
	}
	require.NotEmpty(t, methods)
	return methods
}

func generatedMetricNames(t *testing.T, path string) map[string]struct{} {
	t.Helper()
	names := map[string]struct{}{}
	for _, name := range generatedMetricMethods(t, path) {
		names[name] = struct{}{}
	}
	return names
}

func setDifference(left, right map[string]struct{}) []string {
	difference := make([]string, 0)
	for name := range left {
		if _, exists := right[name]; !exists {
			difference = append(difference, name)
		}
	}
	sort.Strings(difference)
	return difference
}

func mergeMetricNameSets(destination, source map[string]struct{}) {
	for name := range source {
		destination[name] = struct{}{}
	}
}

func mergeDynamicMetricSites(destination, source map[string]int) {
	for site, count := range source {
		destination[site] += count
	}
}

func mergeStaticMetricSchemas(destination, source map[string][]metricSchemaExpectation) {
	for name, schemas := range source {
		for _, schema := range schemas {
			destination[name] = appendUniqueMetricSchema(destination[name], schema)
		}
	}
}
