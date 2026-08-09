// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// selectSharedGNMICatalogProduct matches Subscribe-discovered identity against
// the immutable generated catalog. Configured platform and product_family are
// expected-value assertions, not selection overrides.
func selectSharedGNMICatalogProduct(
	identity sharedGNMIDeviceIdentity,
	expectedPlatform string,
	expectedFamily string,
) (gnmiCatalogProductDefinition, gnmiCatalogProductFamilyDefinition, error) {
	return selectSharedGNMICatalogProductFromDefinitions(
		identity,
		expectedPlatform,
		expectedFamily,
		builtinGNMICatalogProductFamilies,
		builtinGNMICatalogProducts,
	)
}

func selectSharedGNMICatalogProductFromDefinitions(
	identity sharedGNMIDeviceIdentity,
	expectedPlatform string,
	expectedFamily string,
	families []gnmiCatalogProductFamilyDefinition,
	products []gnmiCatalogProductDefinition,
) (gnmiCatalogProductDefinition, gnmiCatalogProductFamilyDefinition, error) {
	osFamily := strings.ToLower(strings.TrimSpace(identity.OSFamily))
	model := strings.TrimSpace(identity.ModelIdentifier)
	release := strings.TrimSpace(identity.SoftwareVersion)
	if osFamily == "" || model == "" || release == "" {
		return gnmiCatalogProductDefinition{}, gnmiCatalogProductFamilyDefinition{}, errors.New("subscribed identity requires OS family, model identifier, and software version for catalog selection")
	}

	expectedPlatform = strings.ToLower(strings.TrimSpace(expectedPlatform))
	if expectedPlatform != "" && expectedPlatform != osFamily {
		return gnmiCatalogProductDefinition{}, gnmiCatalogProductFamilyDefinition{}, fmt.Errorf(
			"configured platform %q does not match subscribed OS family %q",
			expectedPlatform,
			osFamily,
		)
	}
	expectedFamily = strings.ToLower(strings.TrimSpace(expectedFamily))

	familyByID := make(map[string]gnmiCatalogProductFamilyDefinition, len(families))
	for index, family := range families {
		family.ID = strings.ToLower(strings.TrimSpace(family.ID))
		family.Platform = strings.ToLower(strings.TrimSpace(family.Platform))
		if family.ID == "" || family.Platform == "" {
			return gnmiCatalogProductDefinition{}, gnmiCatalogProductFamilyDefinition{}, fmt.Errorf("generated catalog product family %d has an empty ID or platform", index)
		}
		if _, duplicate := familyByID[family.ID]; duplicate {
			return gnmiCatalogProductDefinition{}, gnmiCatalogProductFamilyDefinition{}, fmt.Errorf("generated catalog duplicates product family %q", family.ID)
		}
		familyByID[family.ID] = family
	}
	if expectedFamily != "" {
		family, ok := familyByID[expectedFamily]
		if !ok {
			return gnmiCatalogProductDefinition{}, gnmiCatalogProductFamilyDefinition{}, fmt.Errorf("configured product_family %q is absent from the generated catalog", expectedFamily)
		}
		if family.Platform != osFamily {
			return gnmiCatalogProductDefinition{}, gnmiCatalogProductFamilyDefinition{}, fmt.Errorf(
				"configured product_family %q belongs to platform %q, not subscribed OS family %q",
				expectedFamily,
				family.Platform,
				osFamily,
			)
		}
	}

	type compiledProduct struct {
		definition gnmiCatalogProductDefinition
		family     gnmiCatalogProductFamilyDefinition
		pids       []*regexp.Regexp
		releases   []*regexp.Regexp
	}
	compiled := make([]compiledProduct, 0, len(products))
	productIDs := make(map[string]struct{}, len(products))
	for index := range products {
		product := products[index]
		product.ID = strings.TrimSpace(product.ID)
		product.Family = strings.ToLower(strings.TrimSpace(product.Family))
		if product.ID == "" || product.Family == "" {
			return gnmiCatalogProductDefinition{}, gnmiCatalogProductFamilyDefinition{}, fmt.Errorf("generated catalog product %d has an empty ID or family", index)
		}
		if _, duplicate := productIDs[product.ID]; duplicate {
			return gnmiCatalogProductDefinition{}, gnmiCatalogProductFamilyDefinition{}, fmt.Errorf("generated catalog duplicates product row %q", product.ID)
		}
		productIDs[product.ID] = struct{}{}
		if product.RuntimeEligible && (len(product.Roles) > 0 || len(product.ControlPlanes) > 0 || len(product.OperatingModes) > 0) {
			return gnmiCatalogProductDefinition{}, gnmiCatalogProductFamilyDefinition{}, fmt.Errorf(
				"generated catalog product %q is runtime-eligible but declares role, control-plane, or operating-mode predicates that bootstrap identity does not yet prove",
				product.ID,
			)
		}
		family, ok := familyByID[product.Family]
		if !ok {
			return gnmiCatalogProductDefinition{}, gnmiCatalogProductFamilyDefinition{}, fmt.Errorf("generated catalog product %q references unknown family %q", product.ID, product.Family)
		}
		pidPatterns, err := compileSharedGNMIExactPatterns(product.ID, "PID", product.PIDPatterns)
		if err != nil {
			return gnmiCatalogProductDefinition{}, gnmiCatalogProductFamilyDefinition{}, err
		}
		releasePatterns, err := compileSharedGNMIExactPatterns(product.ID, "release", product.ReleasePatterns)
		if err != nil {
			return gnmiCatalogProductDefinition{}, gnmiCatalogProductFamilyDefinition{}, err
		}
		compiled = append(compiled, compiledProduct{
			definition: product,
			family:     family,
			pids:       pidPatterns,
			releases:   releasePatterns,
		})
	}

	matches := make([]compiledProduct, 0, 1)
	for index := range compiled {
		product := compiled[index]
		if !product.definition.RuntimeEligible {
			continue
		}
		if product.family.Platform != osFamily {
			continue
		}
		if !matchesSharedGNMIExactPattern(product.pids, model) || !matchesSharedGNMIExactPattern(product.releases, release) {
			continue
		}
		matches = append(matches, product)
	}
	if len(matches) == 0 {
		expected := ""
		if expectedFamily != "" {
			expected = fmt.Sprintf(" with configured product_family %q", expectedFamily)
		}
		return gnmiCatalogProductDefinition{}, gnmiCatalogProductFamilyDefinition{}, fmt.Errorf(
			"no runtime-eligible exact generated catalog product row matches OS family %q, model %q, and software version %q%s",
			osFamily,
			model,
			release,
			expected,
		)
	}
	if len(matches) != 1 {
		ids := make([]string, len(matches))
		for index := range matches {
			ids[index] = matches[index].definition.ID
		}
		sort.Strings(ids)
		return gnmiCatalogProductDefinition{}, gnmiCatalogProductFamilyDefinition{}, fmt.Errorf(
			"subscribed identity ambiguously matches generated catalog product rows %s",
			strings.Join(ids, ", "),
		)
	}
	if expectedFamily != "" && matches[0].family.ID != expectedFamily {
		return gnmiCatalogProductDefinition{}, gnmiCatalogProductFamilyDefinition{}, fmt.Errorf(
			"configured product_family %q does not match subscribed product row %q in family %q",
			expectedFamily,
			matches[0].definition.ID,
			matches[0].family.ID,
		)
	}

	return cloneSharedGNMICatalogProduct(matches[0].definition), matches[0].family, nil
}

func compileSharedGNMIExactPatterns(productID, kind string, patterns []string) ([]*regexp.Regexp, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("generated catalog product %q has no %s selectors", productID, kind)
	}
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	seen := make(map[string]struct{}, len(patterns))
	for index, pattern := range patterns {
		if len(pattern) < 2 || pattern[0] != '^' || pattern[len(pattern)-1] != '$' {
			return nil, fmt.Errorf(
				"generated catalog product %q %s selector %d must be anchored with ^ and $",
				productID,
				kind,
				index,
			)
		}
		if _, duplicate := seen[pattern]; duplicate {
			return nil, fmt.Errorf("generated catalog product %q duplicates %s selector %q", productID, kind, pattern)
		}
		seen[pattern] = struct{}{}
		selector, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile generated catalog product %q %s selector %d: %w", productID, kind, index, err)
		}
		compiled = append(compiled, selector)
	}
	return compiled, nil
}

func matchesSharedGNMIExactPattern(patterns []*regexp.Regexp, value string) bool {
	return slices.ContainsFunc(patterns, func(pattern *regexp.Regexp) bool {
		location := pattern.FindStringIndex(value)
		return len(location) == 2 && location[0] == 0 && location[1] == len(value)
	})
}

func cloneSharedGNMICatalogProduct(product gnmiCatalogProductDefinition) gnmiCatalogProductDefinition {
	product.PIDPatterns = slices.Clone(product.PIDPatterns)
	product.ReleasePatterns = slices.Clone(product.ReleasePatterns)
	product.SourceIDs = slices.Clone(product.SourceIDs)
	product.Roles = slices.Clone(product.Roles)
	product.ControlPlanes = slices.Clone(product.ControlPlanes)
	product.OperatingModes = slices.Clone(product.OperatingModes)
	product.HardwareClasses = slices.Clone(product.HardwareClasses)
	product.Coverage = maps.Clone(product.Coverage)
	return product
}
