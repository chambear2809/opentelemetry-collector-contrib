// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmicataloggen

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/openconfig/goyang/pkg/yang"
)

// loadVerifiedModelSchemas parses a complete, digest-verified bundle as YANG,
// resolves imports/uses/augments, and returns the effective schema entry for
// every recorded module. Any transitively loaded but unrecorded module is an
// error: schema validation must never depend on bytes absent from provenance.
func loadVerifiedModelSchemas(baseDir string, bundle ModelBundle) (map[string]*yang.Entry, error) {
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, fmt.Errorf("open model bundle root: %w", err)
	}
	defer root.Close()

	modules := yang.NewModules()
	recorded := make(map[string]string, len(bundle.Modules))
	for _, module := range bundle.Modules {
		raw, readErr := root.ReadFile(module.File)
		if readErr != nil {
			return nil, fmt.Errorf("model module %q is missing from local bundle at %q: %w", module.ID, module.File, readErr)
		}
		if verifyErr := verifyModelModuleContent(module, raw); verifyErr != nil {
			return nil, verifyErr
		}
		if parseErr := modules.Parse(string(raw), module.File); parseErr != nil {
			return nil, fmt.Errorf("parse model module %q as YANG: %w", module.ID, parseErr)
		}
		recorded[module.Name+"@"+module.Revision] = module.ID
	}
	if processErrors := modules.Process(); len(processErrors) > 0 {
		messages := make([]string, len(processErrors))
		for index, processErr := range processErrors {
			messages[index] = processErr.Error()
		}
		sort.Strings(messages)
		return nil, fmt.Errorf("process verified model bundle %q: %s", bundle.ID, strings.Join(messages, "; "))
	}

	seen := map[*yang.Module]struct{}{}
	for _, collection := range []map[string]*yang.Module{modules.Modules, modules.SubModules} {
		for _, parsed := range collection {
			if parsed == nil {
				continue
			}
			if _, duplicate := seen[parsed]; duplicate {
				continue
			}
			seen[parsed] = struct{}{}
			if _, ok := recorded[parsed.FullName()]; !ok {
				return nil, fmt.Errorf("verified model bundle %q loaded unrecorded dependency %q", bundle.ID, parsed.FullName())
			}
		}
	}

	entries := make(map[string]*yang.Entry, len(bundle.Modules))
	for _, module := range bundle.Modules {
		parsed := modules.Modules[module.Name+"@"+module.Revision]
		if parsed == nil {
			// A submodule is provenance-bearing but cannot independently own an
			// operational data path. It is still parsed and dependency-checked.
			if modules.SubModules[module.Name+"@"+module.Revision] != nil {
				continue
			}
			return nil, fmt.Errorf("verified model module %q is absent after YANG processing", module.ID)
		}
		entry := yang.ToEntry(parsed)
		if entry == nil {
			return nil, fmt.Errorf("verified model module %q produced no effective schema", module.ID)
		}
		if schemaErrors := entry.GetErrors(); len(schemaErrors) > 0 {
			return nil, fmt.Errorf("verified model module %q schema: %w", module.ID, errors.Join(schemaErrors...))
		}
		entries[module.ID] = entry
	}
	return entries, nil
}

func validatePathAgainstVerifiedModels(path Path, schemas map[string]*yang.Entry) error {
	if path.ModelProvenance != "verified" {
		return nil
	}
	if len(path.ModelRefs) == 0 {
		return errors.New("verified model provenance requires model_refs")
	}
	entries := make([]*yang.Entry, 0, len(path.ModelRefs))
	for _, reference := range path.ModelRefs {
		entry := schemas[reference]
		if entry == nil {
			return fmt.Errorf("model reference %q has no parsed module schema", reference)
		}
		entries = append(entries, entry)
	}
	if len(path.BaseElements) == 0 {
		return errors.New("verified path requires base_elements for schema validation")
	}
	if _, err := findSchemaEntry(entries, path.BaseElements); err != nil {
		return fmt.Errorf("subscription path %q: %w", strings.Join(path.BaseElements, "/"), err)
	}
	for index, spec := range path.ListKeys {
		entry, err := findSchemaEntry(entries, spec.Elements)
		if err != nil {
			return fmt.Errorf("list_keys[%d]: %w", index, err)
		}
		if !entry.IsList() {
			return fmt.Errorf("list_keys[%d] path %q is not a YANG list", index, strings.Join(spec.Elements, "/"))
		}
		actual := strings.Fields(entry.Key)
		if !slices.Equal(actual, spec.Keys) {
			return fmt.Errorf("list_keys[%d] keys %v do not match YANG keys %v", index, spec.Keys, actual)
		}
	}
	return nil
}

func validateMappingAgainstVerifiedModels(path Path, mapping ResolvedMapping, schemas map[string]*yang.Entry) error {
	if path.ModelProvenance != "verified" {
		return nil
	}
	entries := make([]*yang.Entry, 0, len(path.ModelRefs))
	for _, reference := range path.ModelRefs {
		if entry := schemas[reference]; entry != nil {
			entries = append(entries, entry)
		}
	}
	leafPath := append(slices.Clone(mapping.Elements), mapping.Leaf)
	entry, err := findSchemaEntry(entries, leafPath)
	if err != nil {
		return err
	}
	if !entry.IsLeaf() {
		if entry.IsLeafList() {
			return fmt.Errorf("mapping leaf %q is a leaf-list without a declared bounded projection", strings.Join(leafPath, "/"))
		}
		return fmt.Errorf("mapping leaf %q is not a scalar YANG leaf", strings.Join(leafPath, "/"))
	}
	if entry.Type == nil || !numericYANGType(entry.Type) {
		kind := "unknown"
		if entry.Type != nil {
			kind = entry.Type.Kind.String()
		}
		return fmt.Errorf("mapping leaf %q has non-numeric YANG type %s without a declared enum/info projection", strings.Join(leafPath, "/"), kind)
	}
	if mapping.Contract.Gauge != nil && mapping.Contract.Gauge.ValueType == "int" && !integerYANGType(entry.Type) {
		return fmt.Errorf("mapping leaf %q has YANG type %s but metric requires an integer gauge", strings.Join(leafPath, "/"), entry.Type.Kind)
	}
	if mapping.Contract.Sum != nil && mapping.Contract.Sum.ValueType == "int" && !integerYANGType(entry.Type) {
		return fmt.Errorf("mapping leaf %q has YANG type %s but metric requires an integer sum", strings.Join(leafPath, "/"), entry.Type.Kind)
	}
	yangUnit := schemaYANGUnit(entry)
	if !compatibleYANGMetricUnit(yangUnit, mapping.Contract.Unit, mapping.Scale) {
		return fmt.Errorf(
			"mapping leaf %q YANG unit %q is incompatible with metric unit %q and scale %g",
			strings.Join(leafPath, "/"), yangUnit, mapping.Contract.Unit, mapping.Scale,
		)
	}
	return nil
}

func schemaYANGUnit(entry *yang.Entry) string {
	if entry == nil {
		return ""
	}
	if entry.Units != "" {
		return entry.Units
	}
	if entry.Type != nil && entry.Type.Units != "" {
		return entry.Type.Units
	}
	switch node := entry.Node.(type) {
	case *yang.Leaf:
		if node.Units != nil {
			return node.Units.Name
		}
	case *yang.LeafList:
		if node.Units != nil {
			return node.Units.Name
		}
	}
	return ""
}

func findSchemaEntry(roots []*yang.Entry, elements []string) (*yang.Entry, error) {
	for _, root := range roots {
		current := root
		matched := true
		for _, rawElement := range elements {
			element := localYANGName(rawElement)
			next := current.Dir[element]
			if next == nil {
				for name, candidate := range current.Dir {
					if localYANGName(name) == element {
						if next != nil {
							matched = false
							break
						}
						next = candidate
					}
				}
			}
			if !matched || next == nil {
				matched = false
				break
			}
			current = next
		}
		if matched {
			return current, nil
		}
	}
	return nil, fmt.Errorf("path %q is absent from every referenced verified YANG module", strings.Join(elements, "/"))
}

func localYANGName(value string) string {
	if index := strings.LastIndexByte(value, ':'); index >= 0 {
		return value[index+1:]
	}
	return value
}

func numericYANGType(value *yang.YangType) bool {
	if value == nil {
		return false
	}
	if integerYANGType(value) || value.Kind == yang.Ydecimal64 {
		return true
	}
	if value.Kind != yang.Yunion {
		return false
	}
	return len(value.Type) > 0 && slices.ContainsFunc(value.Type, numericYANGType)
}

func integerYANGType(value *yang.YangType) bool {
	if value == nil {
		return false
	}
	switch value.Kind {
	case yang.Yint8, yang.Yint16, yang.Yint32, yang.Yint64,
		yang.Yuint8, yang.Yuint16, yang.Yuint32, yang.Yuint64:
		return true
	case yang.Yunion:
		return len(value.Type) > 0 && slices.ContainsFunc(value.Type, integerYANGType)
	default:
		return false
	}
}

func compatibleYANGMetricUnit(yangUnit, metricUnit string, scale float64) bool {
	yangUnit = strings.ToLower(strings.TrimSpace(yangUnit))
	if yangUnit == "" {
		return true
	}
	if (yangUnit == "percent" || yangUnit == "percentage") && metricUnit == "1" && scale == 0.01 {
		return true
	}
	aliases := map[string]string{
		"1": "1", "percent": "%", "percentage": "%",
		"second": "s", "seconds": "s", "millisecond": "ms", "milliseconds": "ms",
		"microsecond": "us", "microseconds": "us", "nanosecond": "ns", "nanoseconds": "ns",
		"byte": "By", "bytes": "By", "bit": "bit", "bits": "bit",
		"degree celsius": "Cel", "degrees celsius": "Cel", "celsius": "Cel",
		"watt": "W", "watts": "W", "volt": "V", "volts": "V",
		"ampere": "A", "amperes": "A", "hertz": "Hz", "dbm": "dB[mW]",
	}
	canonical := aliases[yangUnit]
	if canonical == "" {
		canonical = strings.TrimSpace(yangUnit)
	}
	return canonical == metricUnit && scale == 1
}
