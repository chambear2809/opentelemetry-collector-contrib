// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"fmt"
	"go/ast"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

type metricSchemaExpectation struct {
	description string
	instrument  string
	valueTypes  []string
	unit        string
	monotonic   bool
	temporality string
}

func TestMetricMetadataMatchesStaticCodeSchemas(t *testing.T) {
	metadata := loadMetricMetadataDefinitions(t, "metadata.yaml")
	codeSchemas := loadMetricSchemaSource(t, ".").staticMetricSchemas()
	builtinDescriptors, err := builtinGNMIMetricDescriptors()
	require.NoError(t, err)
	for name, descriptor := range builtinDescriptors {
		codeSchemas[name] = appendUniqueMetricSchema(codeSchemas[name], metricExpectationFromGovernedDescriptor(descriptor))
	}
	for _, name := range sortedMetricSchemaNames(codeSchemas) {
		t.Run(name, func(t *testing.T) {
			definition, cataloged := metadata[name]
			require.True(t, cataloged, "code schema audit found uncataloged metric %q", name)
			for i, schema := range codeSchemas[name] {
				t.Run(fmt.Sprintf("emitter_%d", i), func(t *testing.T) {
					assertMetricMetadataCodeSchema(t, name, definition, schema)
				})
			}
		})
	}
}

func TestBuiltinGNMIMetricDescriptorsMatchMetadata(t *testing.T) {
	metadata := loadMetricMetadataDefinitions(t, "metadata.yaml")
	descriptors, err := builtinGNMIMetricDescriptors()
	require.NoError(t, err)
	require.Len(t, descriptors, len(builtinGNMIMetricMetadata))
	for name, descriptor := range descriptors {
		t.Run(name, func(t *testing.T) {
			assertMetricMetadataDefinition(t, metadata[name], metricExpectationFromGovernedDescriptor(descriptor))
		})
	}
}

func TestBuiltinGNMIMetricAttributesUseTypedMappingUnion(t *testing.T) {
	descriptors, err := builtinGNMIMetricDescriptors()
	require.NoError(t, err)
	expected := map[string]map[string]struct{}{}
	for _, catalog := range []map[string]builtinGNMIProfileDefinition{
		iosXEBuiltinGNMIProfileCatalog,
		iosXRBuiltinGNMIProfileCatalog,
		nxOSBuiltinGNMIProfileCatalog,
	} {
		for _, profile := range catalog {
			mappings := append([]builtinGNMIMapping(nil), profile.SyntheticMappings...)
			for _, path := range profile.Paths {
				mappings = append(mappings, path.Mappings...)
			}
			for _, builtin := range mappings {
				name := builtin.Mapping.Metric.Name
				if expected[name] == nil {
					expected[name] = map[string]struct{}{}
				}
				for _, attribute := range builtin.Mapping.KeyAttributes {
					expected[name][attribute.Attribute] = struct{}{}
				}
				for attribute := range builtin.StaticAttributes {
					expected[name][attribute] = struct{}{}
				}
			}
		}
	}

	for name, descriptor := range descriptors {
		attributes := make([]string, 0, len(expected[name]))
		for attribute := range expected[name] {
			attributes = append(attributes, attribute)
		}
		sort.Strings(attributes)
		require.Equalf(t, attributes, descriptor.optionalAttributes, "%s optional attribute union differs from its typed mappings", name)
	}
}

func TestMetricCatalogDescriptorsAreCompatibleAcrossScrapers(t *testing.T) {
	catalogs := []struct {
		name string
		path string
	}{
		{name: "receiver", path: "metadata.yaml"},
		{name: "system", path: "internal/scraper/systemscraper/metadata.yaml"},
		{name: "interfaces", path: "internal/scraper/interfacesscraper/metadata.yaml"},
	}
	type catalogDefinition struct {
		catalog string
		metric  metricMetadataDefinition
	}
	definitions := map[string]catalogDefinition{}
	for _, catalog := range catalogs {
		for name, definition := range loadMetricMetadataDefinitions(t, catalog.path) {
			if existing, ok := definitions[name]; ok {
				t.Run(name, func(t *testing.T) {
					assertCompatibleCatalogDefinitions(t, existing.catalog, existing.metric, catalog.name, definition)
				})
				continue
			}
			definitions[name] = catalogDefinition{catalog: catalog.name, metric: definition}
		}
	}
}

func TestTopologyMetricAttributeContractIsCompatibleAcrossCatalogs(t *testing.T) {
	expectedOptional := []string{
		"cisco.topology.protocol",
		"network.interface.name",
		"cisco.topology.neighbor.name",
		"cisco.topology.neighbor.interface",
		"cisco.topology.neighbor.platform",
		"cisco.topology.neighbor.address",
		"network.peer.name",
		"network.peer.address",
		"network.protocol.name",
	}
	for _, path := range []string{
		"metadata.yaml",
		"internal/scraper/interfacesscraper/metadata.yaml",
	} {
		definition := loadMetricMetadataDefinitions(t, path)["cisco.topology.neighbor.info"]
		require.ElementsMatch(t, expectedOptional, definition.Attributes, path)
	}
	descriptor := fixedMetricDescriptors["cisco.topology.neighbor.info"]
	require.Empty(t, descriptor.requiredAttributes, "neighbor sources do not share a universally present metric attribute")
	require.ElementsMatch(t, expectedOptional, descriptor.optionalAttributes)
}

func TestAllFixedMetricEmitterSchemasAreCompatible(t *testing.T) {
	schemas := loadMetricSchemaSource(t, ".").staticMetricSchemas()
	mergeStaticMetricSchemas(schemas, loadMetricSchemaSource(t, "internal/gnmi").staticMetricSchemas())

	builtinDescriptors, err := builtinGNMIMetricDescriptors()
	require.NoError(t, err)
	for name, descriptor := range builtinDescriptors {
		schemas[name] = appendUniqueMetricSchema(schemas[name], metricExpectationFromGovernedDescriptor(descriptor))
	}
	for _, query := range intersightTelemetryQueries() {
		schemas[query.metricName] = appendUniqueMetricSchema(schemas[query.metricName], metricSchemaExpectation{
			description: query.description,
			instrument:  "gauge",
			valueTypes:  []string{"double"},
			unit:        query.unit,
		})
	}
	for _, fields := range [][]sdwanManagerMetricField{
		sdwanManagerUtilizationMetricFields[:],
		sdwanManagerHealthMetricFields[:],
	} {
		for _, field := range fields {
			schemas[field.metricName] = appendUniqueMetricSchema(schemas[field.metricName], metricSchemaExpectation{
				description: field.description,
				instrument:  "gauge",
				valueTypes:  []string{"double"},
				unit:        field.unit,
			})
		}
	}
	for _, path := range []string{
		"internal/scraper/systemscraper/metadata.yaml",
		"internal/scraper/interfacesscraper/metadata.yaml",
	} {
		for name, definition := range loadMetricMetadataDefinitions(t, path) {
			schemas[name] = appendUniqueMetricSchema(schemas[name], metricExpectationFromMetadata(t, definition))
		}
	}

	require.NoError(t, validateStaticMetricSchemas(schemas))
	typedNames := make(map[string]struct{}, len(schemas))
	for name := range schemas {
		typedNames[name] = struct{}{}
	}
	require.Empty(t, setDifference(loadMetricMetadataCatalog(t, "metadata.yaml"), typedNames), "fixed receiver catalog entries need a typed emitter path")
}

func validateStaticMetricSchemas(schemas map[string][]metricSchemaExpectation) error {
	problems := make([]string, 0)
	for _, name := range sortedMetricSchemaNames(schemas) {
		definitions := schemas[name]
		for i, definition := range definitions {
			if definition.description == "" {
				problems = append(problems, fmt.Sprintf("static schema for %s emitter %d has no governed description", name, i))
			}
			if definition.instrument != "gauge" && definition.instrument != "sum" {
				problems = append(problems, fmt.Sprintf("static schema for %s emitter %d has unresolved instrument %q", name, i, definition.instrument))
			}
			if len(definition.valueTypes) != 1 {
				problems = append(problems, fmt.Sprintf("static schema for %s emitter %d does not resolve to one numeric type: %v", name, i, definition.valueTypes))
			}
			if definition.instrument == "sum" && definition.temporality != "cumulative" {
				problems = append(problems, fmt.Sprintf("static sum schema for %s emitter %d has unsupported temporality %q", name, i, definition.temporality))
			}
			if definition.instrument == "gauge" && definition.temporality != "" {
				problems = append(problems, fmt.Sprintf("static gauge schema for %s emitter %d declares temporality %q", name, i, definition.temporality))
			}
			if definition.instrument == "gauge" && definition.monotonic {
				problems = append(problems, fmt.Sprintf("static gauge schema for %s emitter %d declares monotonicity", name, i))
			}
		}
		for i, left := range definitions {
			for _, right := range definitions[i+1:] {
				if !sameEmittedMetricSchema(left, right) {
					problems = append(problems, fmt.Sprintf(
						"conflicting static schemas for %s: %s versus %s",
						name,
						formatEmittedMetricSchema(left),
						formatEmittedMetricSchema(right),
					))
				}
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("static metric schema validation failed:\n- %s", strings.Join(problems, "\n- "))
	}
	return nil
}

func TestStaticMetricSchemaValidatorRejectsEveryDescriptorDimension(t *testing.T) {
	baseline := metricSchemaExpectation{
		description: "Fixture metric.",
		instrument:  "sum",
		valueTypes:  []string{"int"},
		unit:        "1",
		monotonic:   true,
		temporality: "cumulative",
	}
	tests := map[string]func(*metricSchemaExpectation){
		"description":  func(schema *metricSchemaExpectation) { schema.description = "Different description." },
		"instrument":   func(schema *metricSchemaExpectation) { schema.instrument = "gauge"; schema.temporality = "" },
		"value type":   func(schema *metricSchemaExpectation) { schema.valueTypes = []string{"double"} },
		"unit":         func(schema *metricSchemaExpectation) { schema.unit = "By" },
		"monotonicity": func(schema *metricSchemaExpectation) { schema.monotonic = false },
		"temporality":  func(schema *metricSchemaExpectation) { schema.temporality = "delta" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			conflict := baseline
			conflict.valueTypes = append([]string(nil), baseline.valueTypes...)
			mutate(&conflict)
			err := validateStaticMetricSchemas(map[string][]metricSchemaExpectation{
				"fixture.metric": {baseline, conflict},
			})
			require.ErrorContains(t, err, "conflicting static schemas for fixture.metric")
		})
	}
}

func TestStaticMetricSchemaValidatorRejectsMultiTypeEmitter(t *testing.T) {
	err := validateStaticMetricSchemas(map[string][]metricSchemaExpectation{
		"fixture.metric": {{
			description: "Fixture metric.",
			instrument:  "gauge",
			valueTypes:  []string{"int", "double"},
			unit:        "1",
		}},
	})
	require.ErrorContains(t, err, "does not resolve to one numeric type")
}

func sameEmittedMetricSchema(left, right metricSchemaExpectation) bool {
	return left.description == right.description &&
		left.instrument == right.instrument &&
		len(left.valueTypes) == 1 && len(right.valueTypes) == 1 && left.valueTypes[0] == right.valueTypes[0] &&
		left.unit == right.unit &&
		left.monotonic == right.monotonic &&
		left.temporality == right.temporality
}

func formatEmittedMetricSchema(schema metricSchemaExpectation) string {
	return fmt.Sprintf("description=%q instrument=%s value_type=%v unit=%q monotonic=%t temporality=%s", schema.description, schema.instrument, schema.valueTypes, schema.unit, schema.monotonic, schema.temporality)
}

func TestTypedMetricRegistriesMatchMetadata(t *testing.T) {
	metadata := loadMetricMetadataDefinitions(t, "metadata.yaml")
	for _, query := range intersightTelemetryQueries() {
		t.Run(query.metricName, func(t *testing.T) {
			assertMetricMetadataDefinition(t, metadata[query.metricName], metricSchemaExpectation{
				description: query.description,
				instrument:  "gauge",
				valueTypes:  []string{"double"},
				unit:        query.unit,
			})
		})
	}
	for _, fields := range [][]sdwanManagerMetricField{
		sdwanManagerUtilizationMetricFields[:],
		sdwanManagerHealthMetricFields[:],
	} {
		for _, field := range fields {
			t.Run(field.field, func(t *testing.T) {
				assertMetricMetadataDefinition(t, metadata[field.metricName], metricSchemaExpectation{
					description: field.description,
					instrument:  "gauge",
					valueTypes:  []string{"double"},
					unit:        field.unit,
				})
			})
		}
	}
}

func (s metricSchemaSource) staticMetricSchemas() map[string][]metricSchemaExpectation {
	schemas := make(map[string][]metricSchemaExpectation)
	for _, function := range s.functions {
		inspectMetricSchemaFunction(function.body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, schema, ok := s.staticMetricSchemaCall(call)
			if ok {
				schemas[name] = appendUniqueMetricSchema(schemas[name], schema)
			}
			return true
		})
	}
	s.mergePropagatedMetricSchemas(schemas)
	return schemas
}

func (s metricSchemaSource) staticMetricSchemaCall(call *ast.CallExpr) (string, metricSchemaExpectation, bool) {
	functionName := callName(call)
	if functionName == "appendNumber" {
		return s.staticAppendNumberSchema(call)
	}
	nameIndex, schema, ok := staticMetricCallKind(call)
	if !ok {
		return "", metricSchemaExpectation{}, false
	}

	if len(call.Args) <= nameIndex {
		return "", metricSchemaExpectation{}, false
	}
	name, ok := s.staticString(call.Args[nameIndex])
	if !ok || name == "" {
		return "", metricSchemaExpectation{}, false
	}
	directDescriptorArguments := nameIndex == 0 && strings.HasPrefix(functionName, "record")
	if directDescriptorArguments && len(call.Args) > 2 {
		if description, ok := s.staticString(call.Args[1]); ok {
			schema.description = description
		}
		if unit, ok := s.staticString(call.Args[2]); ok {
			schema.unit = unit
		}
	} else if descriptor, fixed := fixedMetricDescriptors[name]; fixed {
		schema.description = descriptor.description
		schema.unit = descriptor.unit
	}
	return name, schema, true
}

func staticMetricCallKind(call *ast.CallExpr) (int, metricSchemaExpectation, bool) {
	schema := metricSchemaExpectation{}
	switch callName(call) {
	case "recordInt", "recordIntAt":
		schema.instrument, schema.valueTypes = "gauge", []string{"int"}
	case "recordDouble", "recordDoubleAt":
		schema.instrument, schema.valueTypes = "gauge", []string{"double"}
	case "recordSum", "recordAbsoluteSumInt":
		schema.instrument, schema.valueTypes, schema.monotonic, schema.temporality = "sum", []string{"int"}, true, "cumulative"
	case "appendIntGaugeMetric":
		schema.instrument, schema.valueTypes = "gauge", []string{"int"}
		return 1, schema, true
	case "appendIntSumMetric":
		schema.instrument, schema.valueTypes, schema.monotonic, schema.temporality = "sum", []string{"int"}, true, "cumulative"
		return 1, schema, true
	case "normalizeCompactGPBDiagnostic":
		schema.instrument, schema.valueTypes = "gauge", []string{"int"}
		return 1, schema, true
	case "appendPercentageRatio":
		schema.instrument, schema.valueTypes, schema.unit = "gauge", []string{"double"}, "1"
	case "appendInfo":
		if len(call.Args) != 2 && len(call.Args) != 3 {
			return 0, metricSchemaExpectation{}, false
		}
		schema.instrument, schema.valueTypes = "gauge", []string{"double"}
	case "appendState":
		schema.instrument, schema.valueTypes = "gauge", []string{"int"}
	default:
		return 0, metricSchemaExpectation{}, false
	}
	return 0, schema, true
}

func (s metricSchemaSource) mergePropagatedMetricSchemas(schemas map[string][]metricSchemaExpectation) {
	parameterSchemas := map[any]map[int][]metricSchemaExpectation{}
	for _, function := range s.functions {
		if function.name == "addCount" {
			addMetricSchemaParameter(parameterSchemas, function.object, 0, metricSchemaExpectation{
				instrument: "gauge", valueTypes: []string{"int"},
			})
		}
		inspectMetricSchemaFunction(function.body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			nameIndex, schema, known := staticMetricCallKind(call)
			if !known || nameIndex >= len(call.Args) {
				return true
			}
			identifier, ok := call.Args[nameIndex].(*ast.Ident)
			if !ok {
				return true
			}
			if parameterIndex, exists := function.parameters[identifier.Name]; exists {
				addMetricSchemaParameter(parameterSchemas, function.object, parameterIndex, schema)
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
				for nameIndex, kinds := range parameterSchemas[s.callObject(call)] {
					if nameIndex >= len(call.Args) {
						continue
					}
					identifier, ok := call.Args[nameIndex].(*ast.Ident)
					if !ok {
						continue
					}
					callerIndex, exists := function.parameters[identifier.Name]
					if !exists {
						continue
					}
					for _, kind := range kinds {
						if addMetricSchemaParameter(parameterSchemas, function.object, callerIndex, kind) {
							changed = true
						}
					}
				}
				return true
			})
		}
	}

	for _, function := range s.functions {
		inspectMetricSchemaFunction(function.body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			for nameIndex, kinds := range parameterSchemas[s.callObject(call)] {
				if nameIndex >= len(call.Args) {
					continue
				}
				name, static := s.staticString(call.Args[nameIndex])
				if !static || name == "" {
					continue
				}
				for _, kind := range kinds {
					if descriptor, fixed := fixedMetricDescriptors[name]; fixed {
						kind.description = descriptor.description
						kind.unit = descriptor.unit
					}
					schemas[name] = appendUniqueMetricSchema(schemas[name], kind)
				}
			}
			return true
		})
	}
}

func addMetricSchemaParameter(
	parameters map[any]map[int][]metricSchemaExpectation,
	function any,
	index int,
	schema metricSchemaExpectation,
) bool {
	if function == nil {
		return false
	}
	if parameters[function] == nil {
		parameters[function] = map[int][]metricSchemaExpectation{}
	}
	previous := len(parameters[function][index])
	parameters[function][index] = appendUniqueMetricSchema(parameters[function][index], schema)
	return len(parameters[function][index]) != previous
}

func (s metricSchemaSource) staticAppendNumberSchema(call *ast.CallExpr) (string, metricSchemaExpectation, bool) {
	if len(call.Args) < 3 {
		return "", metricSchemaExpectation{}, false
	}
	name, ok := s.staticString(call.Args[0])
	if !ok || name == "" {
		return "", metricSchemaExpectation{}, false
	}
	schema := metricSchemaExpectation{valueTypes: []string{"double"}}
	if len(call.Args) == 3 || len(call.Args) == 4 {
		asCounter, ok := staticBool(call.Args[2])
		if !ok {
			return "", metricSchemaExpectation{}, false
		}
		if asCounter {
			schema.instrument, schema.monotonic, schema.temporality = "sum", true, "cumulative"
		} else {
			schema.instrument = "gauge"
		}
		if len(call.Args) == 4 {
			schema.unit, ok = s.staticString(call.Args[3])
			if !ok {
				return "", metricSchemaExpectation{}, false
			}
		}
		if descriptor, fixed := fixedMetricDescriptors[name]; fixed {
			schema.valueTypes = []string{fixedMetricValueTypeName(descriptor.valueType)}
			schema.description = descriptor.description
			schema.unit = descriptor.unit
		}
		return name, schema, true
	}

	if selector, ok := call.Args[1].(*ast.SelectorExpr); ok {
		switch selector.Sel.Name {
		case "MetricTypeGauge":
			schema.instrument = "gauge"
		case "MetricTypeSum":
			schema.instrument, schema.monotonic, schema.temporality = "sum", true, "cumulative"
		default:
			return "", metricSchemaExpectation{}, false
		}
	}
	if valueCall, ok := call.Args[2].(*ast.CallExpr); ok {
		switch callName(valueCall) {
		case "intMetricNumber":
			schema.valueTypes = []string{"int"}
		case "doubleMetricNumber":
			schema.valueTypes = []string{"double"}
		}
	}
	if descriptor, fixed := fixedMetricDescriptors[name]; fixed {
		schema.valueTypes = []string{fixedMetricValueTypeName(descriptor.valueType)}
		schema.description = descriptor.description
		schema.unit = descriptor.unit
	}
	return name, schema, schema.instrument != ""
}

func staticBool(expression ast.Expr) (bool, bool) {
	identifier, ok := expression.(*ast.Ident)
	if !ok {
		return false, false
	}
	switch identifier.Name {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func appendUniqueMetricSchema(schemas []metricSchemaExpectation, schema metricSchemaExpectation) []metricSchemaExpectation {
	for _, existing := range schemas {
		if fmt.Sprintf("%#v", existing) == fmt.Sprintf("%#v", schema) {
			return schemas
		}
	}
	return append(schemas, schema)
}

func assertMetricMetadataCodeSchema(t *testing.T, name string, actual metricMetadataDefinition, expected metricSchemaExpectation) {
	t.Helper()
	instrument, valueType, monotonic, temporality := metricDefinitionType(t, actual)
	require.Equalf(t, expected.instrument, instrument, "%s instrument differs from its static emitter", name)
	require.Len(t, expected.valueTypes, 1, "%s static emitter must resolve to one numeric type", name)
	require.Equalf(t, expected.valueTypes[0], valueType, "%s value type differs from its static emitter", name)
	require.Equalf(t, expected.unit, actual.Unit, "%s unit differs from its static emitter", name)
	require.Equalf(t, expected.monotonic, monotonic, "%s monotonicity differs from its static emitter", name)
	require.Equalf(t, expected.temporality, temporality, "%s temporality differs from its static emitter", name)
	if expected.description != "" {
		require.Equalf(t, expected.description, actual.Description, "%s description differs from its static emitter", name)
	}
}

func assertMetricMetadataDefinition(t *testing.T, actual metricMetadataDefinition, expected metricSchemaExpectation) {
	t.Helper()
	instrument, valueType, monotonic, temporality := metricDefinitionType(t, actual)
	require.Equal(t, expected.description, actual.Description)
	require.Equal(t, expected.instrument, instrument)
	require.Len(t, expected.valueTypes, 1)
	require.Equal(t, expected.valueTypes[0], valueType)
	require.Equal(t, expected.unit, actual.Unit)
	require.Equal(t, expected.monotonic, monotonic)
	require.Equal(t, expected.temporality, temporality)
}

func metricDefinitionType(t *testing.T, definition metricMetadataDefinition) (string, string, bool, string) {
	t.Helper()
	switch {
	case definition.Gauge != nil && definition.Sum == nil:
		return "gauge", definition.Gauge.ValueType, false, ""
	case definition.Gauge == nil && definition.Sum != nil:
		require.Equal(t, "cumulative", definition.Sum.AggregationTemporality)
		return "sum", definition.Sum.ValueType, definition.Sum.Monotonic, definition.Sum.AggregationTemporality
	default:
		require.FailNow(t, "metric metadata must define exactly one instrument")
		return "", "", false, ""
	}
}

func metricExpectationFromGovernedDescriptor(descriptor governedMetricDescriptor) metricSchemaExpectation {
	instrument := "gauge"
	if descriptor.instrument == internalgnmi.MetricSum {
		instrument = "sum"
	}
	return metricSchemaExpectation{
		description: descriptor.description,
		instrument:  instrument,
		valueTypes:  []string{string(descriptor.valueType)},
		unit:        descriptor.unit,
		monotonic:   descriptor.monotonic,
		temporality: fixedMetricTemporalityName(descriptor.temporality),
	}
}

func metricExpectationFromMetadata(t *testing.T, definition metricMetadataDefinition) metricSchemaExpectation {
	t.Helper()
	instrument, valueType, monotonic, temporality := metricDefinitionType(t, definition)
	return metricSchemaExpectation{
		description: definition.Description,
		instrument:  instrument,
		valueTypes:  []string{valueType},
		unit:        definition.Unit,
		monotonic:   monotonic,
		temporality: temporality,
	}
}

func fixedMetricTemporalityName(temporality fixedMetricTemporality) string {
	if temporality == fixedMetricTemporalityCumulative {
		return "cumulative"
	}
	return ""
}

func assertCompatibleCatalogDefinitions(
	t *testing.T,
	leftCatalog string,
	left metricMetadataDefinition,
	rightCatalog string,
	right metricMetadataDefinition,
) {
	t.Helper()
	leftInstrument, leftValueType, leftMonotonic, leftTemporality := metricDefinitionType(t, left)
	rightInstrument, rightValueType, rightMonotonic, rightTemporality := metricDefinitionType(t, right)
	require.Equalf(t, leftInstrument, rightInstrument, "%s and %s instruments differ", leftCatalog, rightCatalog)
	require.Equalf(t, leftValueType, rightValueType, "%s and %s value types differ", leftCatalog, rightCatalog)
	require.Equalf(t, left.Unit, right.Unit, "%s and %s units differ", leftCatalog, rightCatalog)
	require.Equalf(t, leftMonotonic, rightMonotonic, "%s and %s monotonicity differs", leftCatalog, rightCatalog)
	require.Equalf(t, leftTemporality, rightTemporality, "%s and %s temporalities differ", leftCatalog, rightCatalog)
	require.Equalf(t, left.Description, right.Description, "%s and %s descriptions differ", leftCatalog, rightCatalog)
}

func sortedMetricSchemaNames(schemas map[string][]metricSchemaExpectation) []string {
	names := make([]string, 0, len(schemas))
	for name := range schemas {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
