// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectSharedGNMICatalogProductMatchesGeneratedExactRow(t *testing.T) {
	tests := []struct {
		name       string
		identity   sharedGNMIDeviceIdentity
		productID  string
		familyID   string
		maxStreams int
	}{
		{
			name: "IOS XR",
			identity: sharedGNMIDeviceIdentity{
				OSFamily: gnmiPlatformIOSXR, ModelIdentifier: "NCS-5501", SoftwareVersion: "25.2.21",
			},
			productID: "ios_xr_ncs5500", familyID: "ios_xr", maxStreams: 4,
		},
		{
			name: "IOS XE switching",
			identity: sharedGNMIDeviceIdentity{
				OSFamily: gnmiPlatformIOSXE, ModelIdentifier: "C9300-48UXM", SoftwareVersion: "17.15.5",
			},
			productID: "ios_xe_switching_c9300", familyID: "ios_xe_switching", maxStreams: 4,
		},
		{
			name: "NX-OS",
			identity: sharedGNMIDeviceIdentity{
				OSFamily: gnmiPlatformNXOS, ModelIdentifier: "N9K-C9300v", SoftwareVersion: "10.5(5)M",
			},
			productID: "nx_os_nexus9300v", familyID: "nx_os", maxStreams: 16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			product, family, err := selectSharedGNMICatalogProduct(tt.identity, "", "")
			require.NoError(t, err)
			assert.Equal(t, tt.productID, product.ID)
			assert.Equal(t, tt.familyID, family.ID)
			assert.Equal(t, tt.identity.OSFamily, family.Platform)
			assert.Equal(t, tt.maxStreams, family.MaxStreams)
			assert.Equal(t, "findings", product.Coverage["routing"],
				"a non-live coverage disposition must not prevent identity selection or become a support decision")
		})
	}
}

func TestSelectSharedGNMICatalogProductEnforcesExpectedValues(t *testing.T) {
	identity := sharedGNMIDeviceIdentity{
		OSFamily: gnmiPlatformIOSXR, ModelIdentifier: "NCS-5501", SoftwareVersion: "25.2.21",
	}

	_, _, err := selectSharedGNMICatalogProduct(identity, gnmiPlatformNXOS, "")
	require.ErrorContains(t, err, "configured platform")
	require.ErrorContains(t, err, "does not match subscribed OS family")

	_, _, err = selectSharedGNMICatalogProduct(identity, "", "nx_os")
	require.ErrorContains(t, err, `configured product_family "nx_os" belongs to platform "nx_os"`)

	product, _, err := selectSharedGNMICatalogProduct(identity, gnmiPlatformIOSXR, " IOS_XR ")
	require.NoError(t, err)
	assert.Equal(t, "ios_xr_ncs5500", product.ID)

	_, _, err = selectSharedGNMICatalogProduct(sharedGNMIDeviceIdentity{
		OSFamily: gnmiPlatformIOSXE, ModelIdentifier: "C9300-48UXM", SoftwareVersion: "17.15.5",
	}, gnmiPlatformIOSXE, "ios_xe_routing")
	require.ErrorContains(t, err, `configured product_family "ios_xe_routing" does not match subscribed product row`)
}

func TestSelectSharedGNMICatalogProductRejectsNoExactMatch(t *testing.T) {
	tests := []struct {
		name     string
		identity sharedGNMIDeviceIdentity
	}{
		{
			name: "unknown PID",
			identity: sharedGNMIDeviceIdentity{
				OSFamily: gnmiPlatformIOSXR, ModelIdentifier: "NCS-UNKNOWN", SoftwareVersion: "25.2.21",
			},
		},
		{
			name: "unlisted release",
			identity: sharedGNMIDeviceIdentity{
				OSFamily: gnmiPlatformNXOS, ModelIdentifier: "N9K-C9300v", SoftwareVersion: "10.7(1)",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			product, family, err := selectSharedGNMICatalogProduct(tt.identity, "", "")
			require.ErrorContains(t, err, "no runtime-eligible exact generated catalog product row matches")
			assert.Zero(t, product)
			assert.Zero(t, family)
		})
	}

	_, _, err := selectSharedGNMICatalogProduct(sharedGNMIDeviceIdentity{OSFamily: gnmiPlatformIOSXR}, "", "")
	require.ErrorContains(t, err, "requires OS family, model identifier, and software version")
}

func TestSelectSharedGNMICatalogProductRejectsAmbiguousRowsDeterministically(t *testing.T) {
	families := []gnmiCatalogProductFamilyDefinition{{ID: "ios_xr", Platform: gnmiPlatformIOSXR, MaxStreams: 8}}
	products := []gnmiCatalogProductDefinition{
		{ID: "z-row", Family: "ios_xr", PIDPatterns: []string{"^NCS-5501$"}, ReleasePatterns: []string{"^25\\.2\\.21$"}, RuntimeEligible: true, Coverage: map[string]string{"routing": "live_qualified"}},
		{ID: "a-row", Family: "ios_xr", PIDPatterns: []string{"^NCS-5501$"}, ReleasePatterns: []string{"^25\\.2\\.21$"}, RuntimeEligible: true, Coverage: map[string]string{"routing": "findings"}},
	}
	identity := sharedGNMIDeviceIdentity{
		OSFamily: gnmiPlatformIOSXR, ModelIdentifier: "NCS-5501", SoftwareVersion: "25.2.21",
	}

	product, family, err := selectSharedGNMICatalogProductFromDefinitions(identity, "", "", families, products)
	require.ErrorContains(t, err, "ambiguously matches generated catalog product rows a-row, z-row")
	assert.Zero(t, product)
	assert.Zero(t, family)
}

func TestSelectSharedGNMICatalogProductExpectedFamilyCannotDisambiguateIdentity(t *testing.T) {
	families := []gnmiCatalogProductFamilyDefinition{
		{ID: "family_a", Platform: gnmiPlatformIOSXE, MaxStreams: 4},
		{ID: "family_b", Platform: gnmiPlatformIOSXE, MaxStreams: 4},
	}
	products := []gnmiCatalogProductDefinition{
		{ID: "a-row", Family: "family_a", PIDPatterns: []string{"^PID-1$"}, ReleasePatterns: []string{"^17\\.15\\.5$"}, RuntimeEligible: true},
		{ID: "b-row", Family: "family_b", PIDPatterns: []string{"^PID-1$"}, ReleasePatterns: []string{"^17\\.15\\.5$"}, RuntimeEligible: true},
	}
	identity := sharedGNMIDeviceIdentity{OSFamily: gnmiPlatformIOSXE, ModelIdentifier: "PID-1", SoftwareVersion: "17.15.5"}

	_, _, err := selectSharedGNMICatalogProductFromDefinitions(identity, "", "family_a", families, products)
	require.ErrorContains(t, err, "ambiguously matches generated catalog product rows a-row, b-row")
}

func TestSelectSharedGNMICatalogProductRejectsUnprovenRuntimePredicate(t *testing.T) {
	families := []gnmiCatalogProductFamilyDefinition{{ID: "nx_os", Platform: gnmiPlatformNXOS, MaxStreams: 16}}
	products := []gnmiCatalogProductDefinition{{
		ID: "nx-row", Family: "nx_os", PIDPatterns: []string{"^N9K-C9300v$"},
		ReleasePatterns: []string{"^10\\.5\\(5\\)M$"}, RuntimeEligible: true, OperatingModes: []string{"nxos"},
	}}
	identity := sharedGNMIDeviceIdentity{OSFamily: gnmiPlatformNXOS, ModelIdentifier: "N9K-C9300v", SoftwareVersion: "10.5(5)M"}

	_, _, err := selectSharedGNMICatalogProductFromDefinitions(identity, "", "", families, products)
	require.ErrorContains(t, err, "predicates that bootstrap identity does not yet prove")
}

func TestSelectSharedGNMICatalogProductRejectsInventoryOnlyRow(t *testing.T) {
	families := []gnmiCatalogProductFamilyDefinition{{ID: "ios_xe_routing", Platform: gnmiPlatformIOSXE, MaxStreams: 4}}
	products := []gnmiCatalogProductDefinition{{
		ID: "inventory-only", Family: "ios_xe_routing", PIDPatterns: []string{"^CSR1000V$"},
		ReleasePatterns: []string{"^17\\.3\\.2$"}, RuntimeEligible: false,
	}}
	identity := sharedGNMIDeviceIdentity{
		OSFamily: gnmiPlatformIOSXE, ModelIdentifier: "CSR1000V", SoftwareVersion: "17.3.2",
	}
	_, _, err := selectSharedGNMICatalogProductFromDefinitions(identity, "", "", families, products)
	require.ErrorContains(t, err, "no runtime-eligible exact generated catalog product row matches")
}

func TestSelectSharedGNMICatalogProductValidatesExactSelectors(t *testing.T) {
	families := []gnmiCatalogProductFamilyDefinition{{ID: "nx_os", Platform: gnmiPlatformNXOS, MaxStreams: 16}}
	identity := sharedGNMIDeviceIdentity{
		OSFamily: gnmiPlatformNXOS, ModelIdentifier: "N9K-C93180", SoftwareVersion: "10.6(2)F",
	}
	tests := []struct {
		name        string
		pidPatterns []string
		releases    []string
		errContains string
	}{
		{name: "unanchored PID", pidPatterns: []string{"N9K-.*"}, releases: []string{"^10\\.6\\(2\\)F$"}, errContains: "must be anchored"},
		{name: "invalid PID", pidPatterns: []string{"^[N9K$"}, releases: []string{"^10\\.6\\(2\\)F$"}, errContains: "compile generated catalog"},
		{name: "missing PID", releases: []string{"^10\\.6\\(2\\)F$"}, errContains: "has no PID selectors"},
		{name: "unanchored release", pidPatterns: []string{"^N9K-.*$"}, releases: []string{"10.6"}, errContains: "must be anchored"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			products := []gnmiCatalogProductDefinition{{
				ID: "nx-row", Family: "nx_os", PIDPatterns: tt.pidPatterns, ReleasePatterns: tt.releases,
			}}
			product, family, err := selectSharedGNMICatalogProductFromDefinitions(identity, "", "", families, products)
			require.ErrorContains(t, err, tt.errContains)
			assert.Zero(t, product)
			assert.Zero(t, family)
		})
	}
}

func TestSelectSharedGNMICatalogProductReturnsImmutableCopies(t *testing.T) {
	identity := sharedGNMIDeviceIdentity{
		OSFamily: gnmiPlatformIOSXR, ModelIdentifier: "NCS-5501", SoftwareVersion: "25.2.21",
	}
	product, _, err := selectSharedGNMICatalogProduct(identity, "", "")
	require.NoError(t, err)
	product.PIDPatterns[0] = "mutated"
	product.Coverage["routing"] = "mutated"
	product.HardwareClasses[0] = "mutated"

	again, _, err := selectSharedGNMICatalogProduct(identity, "", "")
	require.NoError(t, err)
	assert.NotEqual(t, "mutated", again.PIDPatterns[0])
	assert.Equal(t, "findings", again.Coverage["routing"])
	assert.NotEqual(t, "mutated", again.HardwareClasses[0])
}
