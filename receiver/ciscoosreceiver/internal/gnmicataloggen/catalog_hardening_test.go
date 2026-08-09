// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmicataloggen

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadIndependentlyVerifiesRecordedModelModules(t *testing.T) {
	module := qualifiedTestYANG("test-model", "2025-01-30")
	manifest, metadata := writeQualifiedCatalog(t, module)
	_, err := Load(manifest, metadata)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(manifest), "models", "test-model.yang"), []byte("changed\n"), 0o600))
	_, err = Load(manifest, metadata)
	require.ErrorContains(t, err, "SHA-256 mismatch")
}

func TestLoadWithModelBundleUsesSeparatelySuppliedLocalDirectory(t *testing.T) {
	module := qualifiedTestYANG("test-model", "2025-01-30")
	manifest, metadata := writeQualifiedCatalog(t, module)
	bundleDir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(bundleDir, "models"), 0o700))
	source := filepath.Join(filepath.Dir(manifest), "models", "test-model.yang")
	destination := filepath.Join(bundleDir, "models", "test-model.yang")
	require.NoError(t, os.Rename(source, destination))

	_, err := Load(manifest, metadata)
	require.ErrorContains(t, err, "is missing")
	_, err = LoadWithModelBundle(manifest, metadata, bundleDir)
	require.NoError(t, err)
}

func TestLoadRejectsRecordedModelIdentityMismatch(t *testing.T) {
	for name, module := range map[string][]byte{
		"name":     qualifiedTestYANG("another-model", "2025-01-30"),
		"revision": qualifiedTestYANG("test-model", "2024-01-01"),
	} {
		t.Run(name, func(t *testing.T) {
			manifest, metadata := writeQualifiedCatalog(t, module)
			_, err := Load(manifest, metadata)
			require.ErrorContains(t, err, "does not declare recorded "+name)
		})
	}
}

func TestProductQualificationMustBindExactProductDomainAndPathVariant(t *testing.T) {
	module := qualifiedTestYANG("test-model", "2025-01-30")
	tests := map[string]struct {
		mutate  func(string) string
		message string
	}{
		"missing product evidence": {
			mutate: func(raw string) string {
				start := strings.Index(raw, "    qualifications:\n")
				end := strings.Index(raw[start:], "    findings:")
				return raw[:start] + raw[start+end:]
			},
			message: "without product-scoped live and CLI evidence",
		},
		"wrong public group": {
			mutate:  func(raw string) string { return strings.Replace(raw, "group: dom", "group: other", 1) },
			message: "unknown path-set variant",
		},
		"path not live qualified": {
			mutate: func(raw string) string {
				return strings.Replace(raw, "disposition: live_qualified", "disposition: fixture_passed", 1)
			},
			message: "not live-qualified and fixture-backed",
		},
		"path evidence not covered": {
			mutate: func(raw string) string {
				return strings.Replace(raw, "      live_evidence: [lab-run-1]", "      live_evidence: [another-lab-run]", 1)
			},
			message: "evidence does not cover path",
		},
		"profile is not a domain": {
			mutate:  func(raw string) string { return strings.Replace(raw, "    name: optics", "    name: not_a_domain", 1) },
			message: "does not map to a declared telemetry domain",
		},
		"fixture does not claim path": {
			mutate: func(raw string) string {
				return strings.Replace(raw, "{platform: ios_xe, profile: optics, path: optics.dom}", "{platform: ios_xe, profile: optics, path: another.path}", 1)
			},
			message: "without an exact coverage claim",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			manifest, metadata := writeQualifiedCatalog(t, module)
			raw, err := os.ReadFile(manifest)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(manifest, []byte(test.mutate(string(raw))), 0o600))
			_, err = Load(manifest, metadata)
			require.ErrorContains(t, err, test.message)
		})
	}
}

func TestImplementedPathRequiresFixtureEvidence(t *testing.T) {
	module := qualifiedTestYANG("test-model", "2025-01-30")
	manifest, metadata := writeQualifiedCatalog(t, module)
	raw, err := os.ReadFile(manifest)
	require.NoError(t, err)
	withoutFixture := strings.Replace(string(raw), "        disposition: live_qualified", "        disposition: implemented", 1)
	withoutFixture = strings.Replace(withoutFixture, "        fixtures: [path_fixture]\n", "", 1)
	require.NoError(t, os.WriteFile(manifest, []byte(withoutFixture), 0o600))

	_, err = Load(manifest, metadata)
	require.ErrorContains(t, err, `disposition "implemented" requires fixtures`)
}

func TestProductSelectorPairsMustBeUnambiguous(t *testing.T) {
	module := qualifiedTestYANG("test-model", "2025-01-30")
	manifest, metadata := writeQualifiedCatalog(t, module)
	raw, err := os.ReadFile(manifest)
	require.NoError(t, err)
	rawString := string(raw)
	productStart := strings.Index(rawString, "  - id: exact_product\n")
	productEnd := strings.Index(rawString[productStart:], "\nmodel_bundles:")
	require.NotEqual(t, -1, productStart)
	require.NotEqual(t, -1, productEnd)
	duplicate := strings.Replace(rawString[productStart:productStart+productEnd], "id: exact_product", "id: duplicate_product", 1)
	mutated := rawString[:productStart+productEnd] + "\n" + duplicate + rawString[productStart+productEnd:]
	require.NoError(t, os.WriteFile(manifest, []byte(mutated), 0o600))
	_, err = Load(manifest, metadata)
	require.ErrorContains(t, err, "duplicates PID/release selector pair")
}

func TestRuntimeEligibleProductRejectsUnprovenBootstrapPredicates(t *testing.T) {
	module := qualifiedTestYANG("test-model", "2025-01-30")
	manifest, metadata := writeQualifiedCatalog(t, module)
	raw, err := os.ReadFile(manifest)
	require.NoError(t, err)
	raw = []byte(strings.Replace(string(raw), "    runtime_eligible: true\n", "    runtime_eligible: true\n    operating_modes: [nxos]\n", 1))
	require.NoError(t, os.WriteFile(manifest, raw, 0o600))
	_, err = Load(manifest, metadata)
	require.ErrorContains(t, err, "predicates are not proven by bootstrap identity")
}

func TestResolveMappingPreservesExplicitAbsoluteElements(t *testing.T) {
	catalog := &Catalog{Metadata: Metadata{Metrics: map[string]MetadataMetric{
		"test.metric": {Description: "test", Unit: "1", Gauge: &MetricGauge{ValueType: "double"}},
	}}}
	resolved, err := catalog.resolveMapping(Mapping{
		Elements: []string{"absolute", "state"}, Leaf: "value", Metric: "test.metric", Scale: 1,
	}, "test-origin", []string{"path", "base"})
	require.NoError(t, err)
	assert.Equal(t, []string{"absolute", "state"}, resolved.Elements)
}

func TestProfileMappingIdentityAllowsOnlyMutuallyExclusiveVariantParity(t *testing.T) {
	mapping := func(origin string) ResolvedMapping {
		return ResolvedMapping{
			Mapping: Mapping{Leaf: "value", Metric: "test.metric", Scale: 1},
			Origin:  origin, Elements: []string{"state"},
		}
	}
	profile := ResolvedProfile{Profile: Profile{Name: "routing", Platform: "ios_xe"}, Paths: []ResolvedPath{
		{Path: Path{Group: "rib", PathSetID: "routing.rib", VariantID: "openconfig"}, Mappings: []ResolvedMapping{mapping("openconfig")}},
		{Path: Path{Group: "rib", PathSetID: "routing.rib", VariantID: "native"}, Mappings: []ResolvedMapping{mapping("native")}},
	}}
	require.NoError(t, validateProfileMappingIdentities(profile))

	for name, mutate := range map[string]func(*ResolvedProfile){
		"same variant":       func(profile *ResolvedProfile) { profile.Paths[1].VariantID = "openconfig" },
		"different path set": func(profile *ResolvedProfile) { profile.Paths[1].PathSetID = "routing.fib" },
		"different group":    func(profile *ResolvedProfile) { profile.Paths[1].Group = "fib" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := profile
			candidate.Paths = append([]ResolvedPath(nil), profile.Paths...)
			mutate(&candidate)
			require.ErrorContains(t, validateProfileMappingIdentities(candidate), "colliding metric identity")
		})
	}
}

func TestMappingMustPreserveCompleteCompositeListIdentity(t *testing.T) {
	err := validateMappingListKeys(ResolvedMapping{
		Elements: []string{"root", "items", "state"},
		Mapping:  Mapping{Keys: []KeyAttribute{{Element: "items", Key: "name", Attribute: "entity.name"}}},
	}, []ListKey{{Elements: []string{"root", "items"}, Keys: []string{"name", "slot"}}})
	require.ErrorContains(t, err, "composite list key items.slot is not mapped")
}

func TestLoadRejectsMappingOriginDifferentFromSubscription(t *testing.T) {
	module := qualifiedTestYANG("test-model", "2025-01-30")
	manifest, metadata := writeQualifiedCatalog(t, module)
	raw, err := os.ReadFile(manifest)
	require.NoError(t, err)
	raw = []byte(strings.Replace(string(raw),
		"          - {leaf: value, metric: test.metric, scale: 1}",
		"          - {origin: another-model, leaf: value, metric: test.metric, scale: 1}", 1))
	require.NoError(t, os.WriteFile(manifest, raw, 0o600))
	_, err = Load(manifest, metadata)
	require.ErrorContains(t, err, "does not match subscription origin")
}

func TestLoadValidatesVerifiedYANGPathTypeAndUnit(t *testing.T) {
	for name, test := range map[string]struct {
		mutate  func([]byte) []byte
		message string
	}{
		"missing path": {
			mutate: func(raw []byte) []byte {
				return []byte(strings.Replace(string(raw), "container optics", "container absent", 1))
			},
			message: "subscription path",
		},
		"non numeric leaf": {
			mutate: func(raw []byte) []byte {
				return []byte(strings.Replace(string(raw), "type decimal64 { fraction-digits 2; }", "type string;", 1))
			},
			message: "non-numeric YANG type",
		},
		"unit mismatch": {
			mutate: func(raw []byte) []byte {
				return []byte(strings.Replace(string(raw), `units "1"`, `units "seconds"`, 1))
			},
			message: "YANG unit",
		},
		"invalid YANG": {
			mutate:  func(raw []byte) []byte { return append(raw, []byte("unexpected-token\n")...) },
			message: "parse model module",
		},
	} {
		t.Run(name, func(t *testing.T) {
			module := test.mutate(qualifiedTestYANG("test-model", "2025-01-30"))
			manifest, metadata := writeQualifiedCatalog(t, module)
			_, err := Load(manifest, metadata)
			require.ErrorContains(t, err, test.message)
		})
	}
}

func TestVerifiedYANGCompositeListKeysMustMatchSchema(t *testing.T) {
	module := []byte(`module list-model {
  yang-version 1.1;
  namespace "urn:test:list";
  prefix list;
  revision 2025-01-30;
  container interfaces {
    list interface {
      key "name slot";
      leaf name { type string; }
      leaf slot { type uint8; }
      container state { leaf counter { type uint64; units "1"; } }
    }
  }
}
`)
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "models"), 0o700))
	file := "models/list-model.yang"
	require.NoError(t, os.WriteFile(filepath.Join(dir, file), module, 0o600))
	digest := sha256.Sum256(module)
	bundle := ModelBundle{ID: "models", Disposition: "verified", Modules: []ModelModule{{
		ID: "list_model", Name: "list-model", Revision: "2025-01-30", File: file, SHA256: fmt.Sprintf("%x", digest),
	}}}
	schemas, err := loadVerifiedModelSchemas(dir, bundle)
	require.NoError(t, err)
	err = validatePathAgainstVerifiedModels(Path{
		ModelProvenance: "verified", ModelRefs: []string{"list_model"},
		BaseElements: []string{"interfaces", "interface", "state"},
		ListKeys:     []ListKey{{Elements: []string{"interfaces", "interface"}, Keys: []string{"name"}}},
	}, schemas)
	require.ErrorContains(t, err, "do not match YANG keys [name slot]")
}

func TestLoadRejectsInvalidMetadataUnitAndValueType(t *testing.T) {
	module := qualifiedTestYANG("test-model", "2025-01-30")
	for name, replacement := range map[string]string{
		"unit":       "unit: bananas",
		"value type": "value_type: histogram",
	} {
		t.Run(name, func(t *testing.T) {
			manifest, metadata := writeQualifiedCatalog(t, module)
			raw, err := os.ReadFile(metadata)
			require.NoError(t, err)
			switch name {
			case "unit":
				raw = []byte(strings.Replace(string(raw), `unit: "1"`, replacement, 1))
			case "value type":
				raw = []byte(strings.Replace(string(raw), "value_type: double", replacement, 1))
			}
			require.NoError(t, os.WriteFile(metadata, raw, 0o600))
			_, err = Load(manifest, metadata)
			require.Error(t, err)
		})
	}
}

func qualifiedTestYANG(name, revision string) []byte {
	return []byte(fmt.Sprintf(`module %s {
  yang-version 1.1;
  namespace "urn:test:%s";
  prefix test;
  revision %s;
  container optics {
    container state {
      leaf value {
        type decimal64 { fraction-digits 2; }
        units "1";
      }
    }
  }
}
`, name, name, revision))
}

func writeQualifiedCatalog(t *testing.T, module []byte) (string, string) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "models"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "models", "test-model.yang"), module, 0o600))
	fixture := []byte("{\"value\":1}\n")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "fixture.json"), fixture, 0o600))
	moduleDigest := sha256.Sum256(module)
	fixtureDigest := sha256.Sum256(fixture)

	manifest := filepath.Join(dir, "catalog.yaml")
	require.NoError(t, os.WriteFile(manifest, []byte(fmt.Sprintf(`schema_version: 1
snapshot_date: 2026-07-04
sources:
  - id: source
    title: Test source
    url: https://example.com/catalog
    accessed: 2026-07-04
domains: [optics]
product_families:
  - {id: ios_xe, platform: ios_xe, max_streams: 4}
products:
  - id: exact_product
    family: ios_xe
    pid_patterns: ['^PID-1$']
    release_patterns: ['^17\.15\.5$']
    sources: [source]
    runtime_eligible: true
    hardware_classes: [optics]
    coverage: {optics: live_qualified}
    qualifications:
      optics:
        path_variants:
          - {profile: optics, group: dom, path_set_id: optics.dom, variant_id: native}
        live_evidence: [lab-run-1]
        cli_evidence: [cli-snapshot-1]
    findings: Exact product qualification fixture.
model_bundles:
  - id: local_models
    disposition: verified
    findings: Locally supplied test model.
    modules:
      - id: test_model_2025_01_30
        name: test-model
        revision: 2025-01-30
        file: models/test-model.yang
        sha256: %x
fixtures:
  - id: path_fixture
    file: fixture.json
    sha256: %x
    covers:
      - {platform: ios_xe, profile: optics, path: optics.dom}
mapping_sets: []
profiles:
  - platform: ios_xe
    name: optics
    default_enabled: false
    default_interval: 30s
    paths:
      - id: optics.dom
        group: dom
        path_set_id: optics.dom
        variant_id: native
        variant_order: 1
        source_preference: native
        origin: test-model
        path: optics/state
        encodings: [json_ietf]
        stream_modes: [sample]
        sample_interval: 30s
        feature_prerequisites: [gnmi_subscribe]
        selector_keys: []
        high_cardinality: false
        requires_max_entities: false
        model_provenance: verified
        model_refs: [test_model_2025_01_30]
        disposition: live_qualified
        base_elements: [optics, state]
        fixtures: [path_fixture]
        live_evidence: [lab-run-1]
        cli_evidence: [cli-snapshot-1]
        mappings:
          - {leaf: value, metric: test.metric, scale: 1}
`, moduleDigest, fixtureDigest)), 0o600))

	metadata := filepath.Join(dir, "metadata.yaml")
	require.NoError(t, os.WriteFile(metadata, []byte(`attributes: {}
metrics:
  test.metric:
    description: Test metric.
    unit: "1"
    gauge:
      value_type: double
`), 0o600))
	return manifest, metadata
}
