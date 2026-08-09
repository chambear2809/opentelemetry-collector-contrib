// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmicataloggen"
)

func TestGNMICatalogGeneratedFilesCurrent(t *testing.T) {
	catalog := loadGNMICatalogForTest(t)
	outputs, err := gnmicataloggen.Render(catalog)
	require.NoError(t, err)

	for path, want := range map[string][]byte{
		"gnmi_catalog_generated.go": wantBytes(t, "gnmi_catalog_generated.go"),
		"docs/gnmi-coverage.md":     wantBytes(t, "docs/gnmi-coverage.md"),
		"docs/gnmi-metrics.md":      wantBytes(t, "docs/gnmi-metrics.md"),
	} {
		var got []byte
		switch path {
		case "gnmi_catalog_generated.go":
			got = outputs.Go
		case "docs/gnmi-coverage.md":
			got = outputs.Coverage
		case "docs/gnmi-metrics.md":
			got = outputs.Metrics
		}
		assert.True(t, bytes.Equal(want, got), "%s is stale; run make gnmi-catalog", path)
	}
}

func TestGNMICatalogProductDomainCompletenessAndNoLiveClaims(t *testing.T) {
	require.NotEmpty(t, builtinGNMICatalogProducts)
	require.NotEmpty(t, builtinGNMICatalogDomains)
	for _, product := range builtinGNMICatalogProducts {
		assert.Len(t, product.Coverage, len(builtinGNMICatalogDomains), product.ID)
		for _, domain := range builtinGNMICatalogDomains {
			status, ok := product.Coverage[domain]
			assert.True(t, ok, "%s/%s", product.ID, domain)
			assert.NotEqual(t, "live_qualified", status, "foundation rows must not claim live support")
		}
	}
	coverage := string(wantBytes(t, "docs/gnmi-coverage.md"))
	assert.NotContains(t, coverage, "| **Supported** |")
	assert.Contains(t, coverage, "Not supported (`findings`)")
}

func TestGNMICatalogAccessorsReturnDeepCopies(t *testing.T) {
	first, ok := builtinGNMIProfile(builtinGNMIPlatformIOSXE, builtinGNMIProfileOptics)
	require.True(t, ok)
	require.NotEmpty(t, first.Paths)
	require.NotEmpty(t, first.Paths[0].Mappings)
	originalPath := first.Paths[0].Path
	originalElement := first.Paths[0].Mappings[0].Mapping.Source.Elements[0]
	originalAttribute := first.Paths[0].Mappings[0].StaticAttributes["cisco.optics.profile"]
	require.NotEmpty(t, first.Paths[0].JSONListKeys)
	originalListElement := first.Paths[0].JSONListKeys[0].Elements[0]
	originalEncoding := first.Paths[0].Encodings[0]
	originalJoinElement := first.Paths[0].EntityJoins[0].Elements[0]

	first.Paths[0].Path = "mutated"
	first.Paths[0].Encodings[0] = "mutated"
	first.Paths[0].FeaturePrerequisites[0] = "mutated"
	first.Paths[0].SelectorKeys[0] = "mutated"
	first.Paths[0].Mappings[0].Mapping.Source.Elements[0] = "mutated"
	first.Paths[0].Mappings[0].Mapping.KeyAttributes[0].Attribute = "mutated"
	first.Paths[0].Mappings[0].StaticAttributes["cisco.optics.profile"] = "mutated"
	first.Paths[0].JSONListKeys[0].Elements[0] = "mutated"
	first.Paths[0].EntityJoins[0].Elements[0] = "mutated"

	second, ok := builtinGNMIProfile(builtinGNMIPlatformIOSXE, builtinGNMIProfileOptics)
	require.True(t, ok)
	assert.Equal(t, originalPath, second.Paths[0].Path)
	assert.Equal(t, originalElement, second.Paths[0].Mappings[0].Mapping.Source.Elements[0])
	assert.Equal(t, "network.interface.name", second.Paths[0].Mappings[0].Mapping.KeyAttributes[0].Attribute)
	assert.Equal(t, originalAttribute, second.Paths[0].Mappings[0].StaticAttributes["cisco.optics.profile"])
	assert.Equal(t, originalListElement, second.Paths[0].JSONListKeys[0].Elements[0])
	assert.Equal(t, originalEncoding, second.Paths[0].Encodings[0])
	assert.Equal(t, "gnmi_subscribe", second.Paths[0].FeaturePrerequisites[0])
	assert.Equal(t, "network.interface.name", second.Paths[0].SelectorKeys[0])
	assert.Equal(t, originalJoinElement, second.Paths[0].EntityJoins[0].Elements[0])
}

func TestGNMICatalogMetadataParityAndFixtureReferences(t *testing.T) {
	catalog := loadGNMICatalogForTest(t)
	referenced := map[string]struct{}{}
	for _, profile := range catalog.Profiles {
		for _, mapping := range profile.Synthetic {
			referenced[mapping.Metric] = struct{}{}
		}
		for _, path := range profile.Paths {
			for _, mapping := range path.Mappings {
				referenced[mapping.Metric] = struct{}{}
			}
		}
	}
	assert.Len(t, builtinGNMIMetricMetadata, len(referenced))
	for name := range referenced {
		metadata := catalog.Metadata.Metrics[name]
		assert.Equal(t, metadata.Description, builtinGNMIMetricMetadata[name].Description, name)
		assert.Equal(t, metadata.Unit, builtinGNMIMetricMetadata[name].Unit, name)
	}
	assert.Len(t, builtinGNMICatalogFixtures, len(catalog.Manifest.Fixtures))
}

func TestGNMICatalogStrictYAMLRejectsUnknownFields(t *testing.T) {
	raw := wantBytes(t, "gnmi_catalog.yaml")
	manifest := filepath.Join(t.TempDir(), "catalog.yaml")
	require.NoError(t, os.WriteFile(manifest, append(raw, []byte("\nunknown_catalog_field: true\n")...), 0o600))
	_, err := gnmicataloggen.Load(manifest, "metadata.yaml")
	require.ErrorContains(t, err, "field unknown_catalog_field not found")
}

func TestGNMICatalogStrictYAMLRejectsDuplicateKeys(t *testing.T) {
	raw := wantBytes(t, "gnmi_catalog.yaml")
	manifest := filepath.Join(t.TempDir(), "catalog.yaml")
	require.NoError(t, os.WriteFile(manifest, append(raw, []byte("\nschema_version: 1\n")...), 0o600))
	_, err := gnmicataloggen.Load(manifest, "metadata.yaml")
	require.ErrorContains(t, err, "duplicate YAML key \"schema_version\"")
}

func TestGNMICatalogLiveQualificationRequiresEvidence(t *testing.T) {
	raw := wantBytes(t, "gnmi_catalog.yaml")
	product := bytes.Index(raw, []byte("  - id: nx_os_nexus9300v\n"))
	require.NotEqual(t, -1, product)
	suffix := bytes.Replace(raw[product:], []byte("identity: findings"), []byte("identity: live_qualified"), 1)
	raw = append(bytes.Clone(raw[:product]), suffix...)
	manifest := writeGNMICatalogManifestForTest(t, raw)
	_, err := gnmicataloggen.Load(manifest, "metadata.yaml")
	require.ErrorContains(t, err, "live_qualified without product-scoped live and CLI evidence")
}

func TestGNMICatalogLocalModelBundleDigestVerification(t *testing.T) {
	module := []byte("module openconfig-interfaces { namespace urn:test; prefix test; revision 2025-01-30; }\n")
	digest := sha256.Sum256(module)

	raw := withVerifiedModelBundle(t, wantBytes(t, "gnmi_catalog.yaml"), fmt.Sprintf("%x", digest))
	manifest, metadata, bundleDir := writeGNMICatalogTreeForTest(t, raw, module)
	moduleFile := filepath.Join(bundleDir, "models", "openconfig-interfaces.yang")
	catalog, err := gnmicataloggen.Load(manifest, metadata)
	require.NoError(t, err)
	require.NoError(t, gnmicataloggen.VerifyLocalModelBundle(catalog, bundleDir))

	require.NoError(t, os.WriteFile(moduleFile, []byte("changed\n"), 0o600))
	_, err = gnmicataloggen.Load(manifest, metadata)
	require.ErrorContains(t, err, "SHA-256 mismatch")
	require.ErrorContains(t, gnmicataloggen.VerifyLocalModelBundle(catalog, bundleDir), "SHA-256 mismatch")
	require.NoError(t, os.Remove(moduleFile))
	require.ErrorContains(t, gnmicataloggen.VerifyLocalModelBundle(catalog, bundleDir), "is missing from local bundle")
}

func TestGNMICatalogPendingModelBundleDoesNotInventProvenance(t *testing.T) {
	catalog := loadGNMICatalogForTest(t)
	require.Len(t, catalog.Manifest.ModelBundles, 1)
	assert.Equal(t, "pending", catalog.Manifest.ModelBundles[0].Disposition)
	assert.Empty(t, catalog.Manifest.ModelBundles[0].Modules)
	require.ErrorContains(t, gnmicataloggen.VerifyLocalModelBundle(catalog, t.TempDir()), "no recorded model modules")

	require.Len(t, builtinGNMICatalogModelBundles, 1)
	assert.Equal(t, "pending", builtinGNMICatalogModelBundles[0].Disposition)
	assert.Empty(t, builtinGNMICatalogModelBundles[0].Modules)
}

func TestGNMICatalogPathSetVariantOrderingAndRuntimeMetadata(t *testing.T) {
	catalog := loadGNMICatalogForTest(t)
	for _, profile := range catalog.Profiles {
		for _, path := range profile.Paths {
			assert.NotEmpty(t, path.Group, profile.Name+"/"+path.ID)
			assert.NotEmpty(t, path.PathSetID, profile.Name+"/"+path.ID)
			assert.Positive(t, path.VariantOrder, profile.Name+"/"+path.ID)
			assert.NotEmpty(t, path.Encodings, profile.Name+"/"+path.ID)
			assert.NotEmpty(t, path.StreamModes, profile.Name+"/"+path.ID)
			assert.Positive(t, path.Interval, profile.Name+"/"+path.ID)
			assert.Equal(t, path.HighCardinality, path.RequiresMaxEntities, profile.Name+"/"+path.ID)
			assert.Equal(t, "pending", path.ModelProvenance, profile.Name+"/"+path.ID)
			assert.Empty(t, path.ModelRefs, profile.Name+"/"+path.ID)
			assert.Len(t, path.EntityJoins, len(path.ListKeys), profile.Name+"/"+path.ID)
		}
	}

	raw := wantBytes(t, "gnmi_catalog.yaml")
	old := "      - id: system.memory\n        group: memory\n        path_set_id: system.memory\n        variant_id: native\n        variant_order: 1"
	replacement := "      - id: system.memory\n        group: cpu\n        path_set_id: system.cpu\n        variant_id: native_fallback\n        variant_order: 3"
	require.Contains(t, string(raw), old)
	raw = bytes.Replace(raw, []byte(old), []byte(replacement), 1)
	manifest := writeGNMICatalogManifestForTest(t, raw)
	_, err := gnmicataloggen.Load(manifest, "metadata.yaml")
	require.ErrorContains(t, err, "non-contiguous variant ordering")

	raw = wantBytes(t, "gnmi_catalog.yaml")
	old = "        group: memory\n        path_set_id: system.memory\n        variant_id: native\n        variant_order: 1\n        source_preference: native"
	replacement = "        group: cpu\n        path_set_id: system.cpu\n        variant_id: openconfig_fallback\n        variant_order: 2\n        source_preference: openconfig"
	require.Contains(t, string(raw), old)
	manifest = writeGNMICatalogManifestForTest(t, bytes.Replace(raw, []byte(old), []byte(replacement), 1))
	_, err = gnmicataloggen.Load(manifest, "metadata.yaml")
	require.ErrorContains(t, err, "orders OpenConfig after a native variant")
}

func TestGNMICatalogProfileGroupsExposeSelectorAndCardinalityContract(t *testing.T) {
	groups := builtinGNMIProfileGroups(builtinGNMIPlatformIOSXE, builtinGNMIProfileCatalyst9800Wireless)
	require.Len(t, groups, 3)
	for _, group := range groups {
		assert.True(t, group.HighCardinality, group.Name)
		assert.True(t, group.RequiresMaxEntities, group.Name)
		assert.NotEmpty(t, group.SelectorKeys, group.Name)
	}
	ap, ok := builtinGNMIProfileGroup(builtinGNMIPlatformIOSXE, builtinGNMIProfileCatalyst9800Wireless, "ap_capwap")
	require.True(t, ok)
	assert.Equal(t, []string{"cisco.wlc.ap.mac"}, ap.SelectorKeys)
	ap.SelectorKeys[0] = "mutated"
	apAgain, ok := builtinGNMIProfileGroup(builtinGNMIPlatformIOSXE, builtinGNMIProfileCatalyst9800Wireless, "ap_capwap")
	require.True(t, ok)
	assert.Equal(t, []string{"cisco.wlc.ap.mac"}, apAgain.SelectorKeys)
	_, ok = builtinGNMIProfileGroup(builtinGNMIPlatformIOSXE, builtinGNMIProfileCatalyst9800Wireless, "unknown")
	assert.False(t, ok)
}

func TestGNMICatalogLiveQualificationRequiresRuntimeEligibility(t *testing.T) {
	raw := bytes.Replace(wantBytes(t, "gnmi_catalog.yaml"), []byte("inventory: findings"), []byte("inventory: live_qualified"), 1)
	manifest := writeGNMICatalogManifestForTest(t, raw)
	_, err := gnmicataloggen.Load(manifest, "metadata.yaml")
	require.ErrorContains(t, err, "live_qualified without runtime eligibility")
}

func TestGNMICatalogQualifiedPathEvidenceRequirements(t *testing.T) {
	module := []byte("module openconfig-interfaces { namespace urn:test; prefix test; revision 2025-01-30; }\n")
	digest := sha256.Sum256(module)
	raw := withVerifiedModelBundle(t, wantBytes(t, "gnmi_catalog.yaml"), fmt.Sprintf("%x", digest))
	old := "        model_provenance: pending\n        disposition: findings\n        findings: Model revision and fixture evidence are pending."
	fixturePassed := "        model_provenance: verified\n        model_refs: [openconfig_interfaces_2025_01_30]\n        disposition: fixture_passed\n        findings: Fixture qualification under test."
	require.Contains(t, string(raw), old)
	manifest, metadata, _ := writeGNMICatalogTreeForTest(t, bytes.Replace(raw, []byte(old), []byte(fixturePassed), 1), module)
	_, err := gnmicataloggen.Load(manifest, metadata)
	require.ErrorContains(t, err, "disposition \"fixture_passed\" requires fixtures")

	old = "        model_provenance: pending\n        disposition: findings\n        findings: A sanitized fixture exists; exact hardware live qualification is pending."
	liveQualified := "        model_provenance: verified\n        model_refs: [openconfig_interfaces_2025_01_30]\n        disposition: live_qualified\n        findings: Live qualification under test."
	require.Contains(t, string(raw), old)
	manifest, metadata, _ = writeGNMICatalogTreeForTest(t, bytes.Replace(raw, []byte(old), []byte(liveQualified), 1), module)
	_, err = gnmicataloggen.Load(manifest, metadata)
	require.ErrorContains(t, err, "live_qualified without live and CLI evidence")
}

func loadGNMICatalogForTest(t *testing.T) *gnmicataloggen.Catalog {
	t.Helper()
	catalog, err := gnmicataloggen.Load("gnmi_catalog.yaml", "metadata.yaml")
	require.NoError(t, err)
	return catalog
}

func wantBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	return raw
}

func writeGNMICatalogManifestForTest(t *testing.T, raw []byte) string {
	t.Helper()
	file, err := os.CreateTemp(".", "gnmi-catalog-test-*.yaml")
	require.NoError(t, err)
	path := file.Name()
	t.Cleanup(func() { _ = os.Remove(path) })
	_, err = file.Write(raw)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	return path
}

func withVerifiedModelBundle(t *testing.T, raw []byte, digest string) []byte {
	t.Helper()
	start := bytes.Index(raw, []byte("model_bundles:\n"))
	require.NotEqual(t, -1, start)
	endOffset := bytes.Index(raw[start:], []byte("\nfixtures:\n"))
	require.NotEqual(t, -1, endOffset)
	end := start + endOffset
	section := fmt.Sprintf(`model_bundles:
  - id: local_yang_snapshot
    disposition: verified
    findings: Verified from the test-supplied local bundle.
    modules:
      - id: openconfig_interfaces_2025_01_30
        name: openconfig-interfaces
        revision: 2025-01-30
        file: models/openconfig-interfaces.yang
        sha256: %s
`, digest)
	return []byte(string(raw[:start]) + strings.TrimSuffix(section, "\n") + string(raw[end:]))
}

func writeGNMICatalogTreeForTest(t *testing.T, raw, module []byte) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	manifest := filepath.Join(dir, "gnmi_catalog.yaml")
	metadata := filepath.Join(dir, "metadata.yaml")
	require.NoError(t, os.WriteFile(manifest, raw, 0o600))
	require.NoError(t, os.WriteFile(metadata, wantBytes(t, "metadata.yaml"), 0o600))

	fixtureDir := filepath.Join(dir, "testdata", "gnmi")
	require.NoError(t, os.MkdirAll(fixtureDir, 0o700))
	fixtures, err := filepath.Glob(filepath.Join("testdata", "gnmi", "*"))
	require.NoError(t, err)
	for _, fixture := range fixtures {
		info, statErr := os.Stat(fixture)
		require.NoError(t, statErr)
		if !info.Mode().IsRegular() {
			continue
		}
		contents, readErr := os.ReadFile(fixture)
		require.NoError(t, readErr)
		require.NoError(t, os.WriteFile(filepath.Join(fixtureDir, filepath.Base(fixture)), contents, 0o600))
	}

	modelDir := filepath.Join(dir, "models")
	require.NoError(t, os.MkdirAll(modelDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(modelDir, "openconfig-interfaces.yang"), module, 0o600))
	return manifest, metadata, dir
}
