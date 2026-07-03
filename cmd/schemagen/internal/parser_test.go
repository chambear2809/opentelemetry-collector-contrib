//go:build !windows

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
package internal

import (
	"go/ast"
	goParser "go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
)

func TestComponentParser(t *testing.T) {
	type testCase struct {
		title              string
		inputFile          string
		expectedSchemaFile string
		rootType           string
	}

	testCases := []testCase{
		{
			title:              "Test Simple Config Parsing",
			inputFile:          "testdata/test00/SimpleConfig.go",
			expectedSchemaFile: "testdata/test00/simple_config.schema.yaml",
			rootType:           "SimpleConfig",
		},
		{
			title:              "Test Array field Config Parsing",
			inputFile:          "testdata/test01/ArrayFieldConfig.go",
			expectedSchemaFile: "testdata/test01/array_field_config.schema.yaml",
			rootType:           "SimpleArrayConfig",
		},
		{
			title:              "Test Nested Struct Config Parsing",
			inputFile:          "testdata/test02/NestedStructConfig.go",
			expectedSchemaFile: "testdata/test02/nested_struct_config.schema.yaml",
			rootType:           "Config",
		},
		{
			title:              "Test Map field Config Parsing",
			inputFile:          "testdata/test03/MapFieldConfig.go",
			expectedSchemaFile: "testdata/test03/map_field_config.schema.yaml",
			rootType:           "MapConfig",
		},
		{
			title:              "Test Ref field Config Parsing",
			inputFile:          "testdata/test04/RefFieldConfig.go",
			expectedSchemaFile: "testdata/test04/ref_field_config.schema.yaml",
			rootType:           "RefFieldConfig",
		},
		{
			title:              "Test Embedded Struct Config Parsing",
			inputFile:          "testdata/test05/EmbeddedStructConfig.go",
			expectedSchemaFile: "testdata/test05/embedded_struct_config.schema.yaml",
			rootType:           "EmbeddedStructConfig",
		},
		{
			title:              "Test Pointer field Config Parsing",
			inputFile:          "testdata/test06/PointerFieldConfig.go",
			expectedSchemaFile: "testdata/test06/pointer_field_config.schema.yaml",
			rootType:           "PointerFieldConfig",
		},
		{
			title:              "Test complex type field Config Parsing",
			inputFile:          "testdata/test07/ComplexTypeFieldConfig.go",
			expectedSchemaFile: "testdata/test07/complex_type_field_config.schema.yaml",
			rootType:           "ComplexTypeFieldConfig",
		},
		{
			title:              "Test time type fields Config Parsing",
			inputFile:          "testdata/test08/TimeTypeFieldConfig.go",
			expectedSchemaFile: "testdata/test08/time_type_field_config.schema.yaml",
			rootType:           "TimeTypeFieldConfig",
		},
		{
			title:              "Test Mixed Tags Config Parsing",
			inputFile:          "testdata/test09/MixedTagsConfig.go",
			expectedSchemaFile: "testdata/test09/mixed_tags_config.schema.yaml",
			rootType:           "MixedTagsConfig",
		},
		{
			title:              "Test Simple Type Aliases Parsing",
			inputFile:          "testdata/test10/AliasSimpleTypeConfig.go",
			expectedSchemaFile: "testdata/test10/alias_simple_type_config.schema.yaml",
			rootType:           "AliasSimpleTypeConfig",
		},
		{
			title:              "Test External Refs Parsing",
			inputFile:          "testdata/test11/ExternalRefsConfig.go",
			expectedSchemaFile: "testdata/test11/external_refs_config.schema.yaml",
			rootType:           "ExternalRefsConfig",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			expectedBytes, err := os.ReadFile(tc.expectedSchemaFile)
			if err != nil {
				t.Fatalf("Failed to read expected schema file %s: %v", tc.expectedSchemaFile, err)
			}
			expectedSchema := string(expectedBytes)

			dir, _ := filepath.Abs(filepath.Dir(tc.inputFile))
			cfg := &Config{
				Mode:     Component,
				DirPath:  dir,
				Mappings: testMappings(),
				AllowedRefs: []string{
					"go.opentelemetry.io/collector",
					"github.com/open-telemetry/opentelemetry-collector-contrib/cmd/schemagen",
				},
				Namespace: "github.com/open-telemetry/opentelemetry-collector-contrib",
			}
			if tc.rootType != "" {
				cfg.ConfigType = tc.rootType
			}
			parser := NewParser(cfg)

			schema, err := parser.Parse()
			require.NoError(t, err)

			rawYaml, err := schema.ToYAML()
			require.NoError(t, err)

			givenYaml := string(rawYaml)
			require.YAMLEq(t, expectedSchema, givenYaml)
		})
	}
}

func TestPackageParser(t *testing.T) {
	dir, _ := filepath.Abs("testdata/external/")
	cfg := &Config{
		Mode:     Package,
		DirPath:  dir,
		Mappings: testMappings(),
	}

	parser := NewParser(cfg)

	schema, err := parser.Parse()
	require.NoError(t, err)

	rawYaml, err := schema.ToYAML()
	require.NoError(t, err)

	expectedBytes, err := os.ReadFile("testdata/external/config.schema.yaml")
	if err != nil {
		t.Fatalf("Failed to read expected schema file: %v", err)
	}
	expectedSchema := string(expectedBytes)

	givenYaml := string(rawYaml)
	require.YAMLEq(t, expectedSchema, givenYaml)
}

func TestApplyFactoryMaps(t *testing.T) {
	const (
		packagePath = "example.test/receiver/testreceiver"
		source      = `package testreceiver

import (
	"example.test/component"
	alpha "example.test/receiver/testreceiver/internal/scraper/alphascraper"
	"example.test/receiver/testreceiver/internal/scraper/betascraper"
)

var scraperFactories = map[component.Type]any{
	component.MustNewType("alpha"): alpha.NewFactory(),
	"beta": betascraper.NewFactory(),
}
`
	)

	file, err := goParser.ParseFile(token.NewFileSet(), "factory.go", source, 0)
	require.NoError(t, err)
	schema := CreateSchema()
	parser := &Parser{
		config: &Config{FactoryMaps: []FactoryMapOverride{{
			Property:     "scrapers",
			FactoriesVar: "scraperFactories",
			Description:  "Map of scraper configurations.",
		}}},
		schema: schema,
		pkg:    &packages.Package{PkgPath: packagePath, Syntax: []*ast.File{file}},
	}

	require.NoError(t, parser.applyFactoryMaps())
	property, ok := schema.Properties["scrapers"].(*ObjectSchemaElement)
	require.True(t, ok)
	require.Equal(t, "Map of scraper configurations.", property.Description)
	require.Equal(t, SchemaTypeObject, property.ElementType)
	require.Equal(t, map[string]string{
		"alpha": "./internal/scraper/alphascraper.config",
		"beta":  "./internal/scraper/betascraper.config",
	}, factoryMapPropertyRefs(t, property))
}

func TestApplyFactoryMapsRejectsMissingVariable(t *testing.T) {
	file, err := goParser.ParseFile(token.NewFileSet(), "factory.go", "package testreceiver", 0)
	require.NoError(t, err)
	parser := &Parser{
		config: &Config{FactoryMaps: []FactoryMapOverride{{
			Property:     "scrapers",
			FactoriesVar: "missingFactories",
		}}},
		schema: CreateSchema(),
		pkg:    &packages.Package{PkgPath: "example.test/receiver/testreceiver", Syntax: []*ast.File{file}},
	}

	err = parser.applyFactoryMaps()
	require.ErrorContains(t, err, `factories variable "missingFactories" was not found`)
}

func factoryMapPropertyRefs(t *testing.T, property *ObjectSchemaElement) map[string]string {
	t.Helper()
	refs := make(map[string]string, len(property.Properties))
	for name, element := range property.Properties {
		ref, ok := element.(*RefSchemaElement)
		require.True(t, ok)
		refs[name] = ref.Ref
	}
	return refs
}

func testMappings() Mappings {
	return Mappings{
		"time": PackagesMapping{
			"Time": TypeDesc{
				SchemaType: SchemaTypeString,
				Format:     "date-time",
			},
			"Duration": TypeDesc{
				SchemaType: SchemaTypeString,
				Format:     "duration",
			},
		},
	}
}
