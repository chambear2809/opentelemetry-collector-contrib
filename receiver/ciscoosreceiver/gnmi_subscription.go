// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

type sharedGNMIPath struct {
	Origin          string
	Path            string
	PathSetID       string
	VariantID       string
	PathSetVariants []sharedGNMIPathSetVariant
	// Groups is catalog provenance for runtime packed-stream replanning. It is
	// not part of the wire path identity.
	Groups []string
}

type sharedGNMIPathSetVariant struct {
	PathSetID string
	VariantID string
}

// sharedGNMIStreamVariant is one indivisible catalog path-set implementation.
// Stream never contains VariantFallbacks itself, preventing recursive plans.
type sharedGNMIStreamVariant struct {
	PathSetID        string
	VariantID        string
	VariantOrder     int
	SourcePreference string
	Stream           sharedGNMIStream
}

type sharedGNMIStream struct {
	Profile             string
	Groups              []string
	Required            bool
	Mode                string
	StreamMode          string
	Encoding            string
	SampleInterval      time.Duration
	PollInterval        time.Duration
	SyncTimeout         time.Duration
	Paths               []sharedGNMIPath
	Mappings            []builtinGNMIMapping
	Optics              bool
	HealthOnly          bool
	JSONListKeySpecs    []internalgnmi.JSONListKeySpec
	JSONListKeyBindings []sharedGNMIJSONListKeyBinding
	JSONListKeys        *internalgnmi.JSONListKeySchema
	CatalogEncodings    []string
	CatalogModes        []string
	EntityLimits        []sharedGNMIEntityLimit
	VariantFallbacks    []sharedGNMIStreamVariant
	AtomicGroupSets     [][]string
	modeDefaulted       bool
}

type sharedGNMIJSONListKeyBinding struct {
	Spec   internalgnmi.JSONListKeySpec
	Groups []string
}

// sharedGNMIEntityLimit binds catalog mapping sources to the normalized key
// attributes which form one entity identity. These attributes are already
// part of the public metric contract; runtime accounting never adds hidden
// output attributes.
type sharedGNMIEntityLimit struct {
	Group       string
	MaxEntities int
	Sources     map[string][]string
}

// buildSharedGNMIStreams converts enabled built-in profiles and custom
// subscriptions into compatible streams. IOS XE and IOS XR require one prefix
// origin per stream. NX-OS retains origin on each subscribed path so DME,
// device-YANG, and OpenConfig paths can coexist in one profile stream.
func buildSharedGNMIStreams(rawTarget GNMITargetConfig) ([]sharedGNMIStream, error) {
	target := rawTarget.withDefaults()
	var streams []sharedGNMIStream

	for _, profileName := range []string{
		builtinGNMIProfileIdentity,
		builtinGNMIProfileSystem,
		builtinGNMIProfileInterfaces,
		builtinGNMIProfileOptics,
		builtinGNMIProfileCatalyst9800Wireless,
		"inventory",
		"environment",
		"l2",
		"routing",
		"mpls",
		"overlay",
		"qos",
		"acl",
		"topology",
		"poe",
		"time_sync",
		"high_availability",
		"asic",
		"telemetry_self",
	} {
		profileConfig := sharedGNMIProfileConfig(target.Profiles, profileName)
		if !boolValue(profileConfig.Enabled, false) {
			continue
		}
		definition, ok := builtinGNMIProfile(target.Platform, profileName)
		if !ok {
			return nil, fmt.Errorf("gNMI profile %q is not supported on platform %q", profileName, target.Platform)
		}
		profileStreams, err := buildBuiltinProfileStreams(target.Platform, definition, profileConfig, target.SyncTimeout)
		if err != nil {
			return nil, fmt.Errorf("gNMI profile %q list-key schema: %w", profileName, err)
		}
		streams = append(streams, profileStreams...)
	}

	for _, subscription := range target.CustomSubscriptions {
		stream, err := buildCustomGNMIStream(subscription, target.SyncTimeout)
		if err != nil {
			return nil, fmt.Errorf("custom subscription %q: %w", subscription.Name, err)
		}
		streams = append(streams, stream)
	}

	if len(streams) > target.MaxStreams {
		return nil, fmt.Errorf("target %q requires %d compatible subscription streams, exceeding max_streams %d", target.Name, len(streams), target.MaxStreams)
	}
	return streams, nil
}

func buildBuiltinProfileStreams(
	platform string,
	definition builtinGNMIProfileDefinition,
	config GNMIProfileConfig,
	syncTimeout ...time.Duration,
) ([]sharedGNMIStream, error) {
	defaultSyncTimeout := gnmiDefaultSyncTimeout
	if len(syncTimeout) > 0 && syncTimeout[0] > 0 {
		defaultSyncTimeout = syncTimeout[0]
	}
	profileModeDefaulted := config.streamModeDefaulted || config.StreamMode == ""
	if config.StreamMode == "" {
		config.StreamMode = gnmiStreamModeSample
	}

	plans, err := sharedGNMICatalogVariantPlans(definition.Paths)
	if err != nil {
		return nil, err
	}
	streams := make([]sharedGNMIStream, 0, len(plans))
	for _, plan := range plans {
		variants := make([]sharedGNMIStreamVariant, 0, len(plan.variants))
		for _, variant := range plan.variants {
			fragment, enabled, fragmentErr := buildBuiltinGNMIVariantFragment(
				platform,
				definition.Name,
				variant.paths,
				config,
				defaultSyncTimeout,
				profileModeDefaulted,
			)
			if fragmentErr != nil {
				return nil, fragmentErr
			}
			if !enabled {
				continue
			}
			variants = append(variants, sharedGNMIStreamVariant{
				PathSetID:        plan.pathSetID,
				VariantID:        variant.variantID,
				VariantOrder:     variant.order,
				SourcePreference: variant.sourcePreference,
				Stream:           fragment,
			})
		}
		if len(variants) == 0 {
			continue
		}
		sort.SliceStable(variants, func(i, j int) bool {
			if variants[i].VariantOrder != variants[j].VariantOrder {
				return variants[i].VariantOrder < variants[j].VariantOrder
			}
			if sharedGNMISourcePreferenceRank(variants[i].SourcePreference) != sharedGNMISourcePreferenceRank(variants[j].SourcePreference) {
				return sharedGNMISourcePreferenceRank(variants[i].SourcePreference) < sharedGNMISourcePreferenceRank(variants[j].SourcePreference)
			}
			return variants[i].VariantID < variants[j].VariantID
		})

		if len(variants) > 1 {
			for index := range variants {
				if err := finalizeSharedGNMIStreamCatalogContract(&variants[index].Stream, variants[index].Stream.modeDefaulted); err != nil {
					return nil, fmt.Errorf(
						"path set %q variant %q: %w",
						variants[index].PathSetID,
						variants[index].VariantID,
						err,
					)
				}
			}
			preferred := variants[0].Stream
			// Alternative-bearing path sets remain standalone. A later variant may
			// have a different origin, encoding, mode, mapping registry, or list
			// schema, so merging it with another path set before selection would
			// make safe replacement impossible.
			preferred.VariantFallbacks = variants
			streams = append(streams, preferred)
			continue
		}
		preferred := variants[0].Stream
		merged := false
		for index := range streams {
			if len(streams[index].VariantFallbacks) > 0 || !compatibleSharedGNMIStreams(platform, streams[index], preferred) {
				continue
			}
			mergeSharedGNMIStreams(&streams[index], preferred)
			merged = true
			break
		}
		if !merged {
			streams = append(streams, preferred)
		}
	}

	if len(streams) > 0 {
		streams[0].Mappings = append(definition.SyntheticMappings, streams[0].Mappings...)
		for index := range streams[0].VariantFallbacks {
			variant := &streams[0].VariantFallbacks[index]
			variant.Stream.Mappings = append(definition.SyntheticMappings, variant.Stream.Mappings...)
		}
	}
	for index := range streams {
		sortSharedGNMIPaths(streams[index].Paths)
		slices.Sort(streams[index].Groups)
		streams[index].Groups = slices.Compact(streams[index].Groups)
		if err := finalizeSharedGNMIStreamCatalogContract(&streams[index], streams[index].modeDefaulted); err != nil {
			return nil, err
		}
		if err := attachSharedGNMIJSONListKeySchema(&streams[index]); err != nil {
			return nil, err
		}
	}
	return streams, nil
}

type sharedGNMICatalogVariant struct {
	variantID        string
	order            int
	sourcePreference string
	paths            []builtinGNMIPathDefinition
}

type sharedGNMICatalogVariantPlan struct {
	pathSetID string
	variants  []sharedGNMICatalogVariant
}

func sharedGNMICatalogVariantPlans(paths []builtinGNMIPathDefinition) ([]sharedGNMICatalogVariantPlan, error) {
	plans := make([]sharedGNMICatalogVariantPlan, 0)
	planByID := map[string]int{}
	variantByPlan := map[string]map[string]int{}
	for pathIndex := range paths {
		path := paths[pathIndex]
		pathSetID := path.PathSetID
		if pathSetID == "" {
			pathSetID = "path." + path.ID
		}
		variantID := path.VariantID
		if variantID == "" {
			variantID = "default"
		}
		planIndex, ok := planByID[pathSetID]
		if !ok {
			planIndex = len(plans)
			planByID[pathSetID] = planIndex
			variantByPlan[pathSetID] = map[string]int{}
			plans = append(plans, sharedGNMICatalogVariantPlan{pathSetID: pathSetID})
		}
		variantIndex, ok := variantByPlan[pathSetID][variantID]
		if !ok {
			variantIndex = len(plans[planIndex].variants)
			variantByPlan[pathSetID][variantID] = variantIndex
			plans[planIndex].variants = append(plans[planIndex].variants, sharedGNMICatalogVariant{
				variantID: variantID, order: path.VariantOrder, sourcePreference: path.SourcePreference,
			})
		}
		variant := &plans[planIndex].variants[variantIndex]
		if variant.order != path.VariantOrder || variant.sourcePreference != path.SourcePreference {
			return nil, fmt.Errorf("path set %q variant %q has inconsistent ordering metadata", pathSetID, variantID)
		}
		variant.paths = append(variant.paths, path)
	}
	return plans, nil
}

func buildBuiltinGNMIVariantFragment(
	platform string,
	profileName string,
	paths []builtinGNMIPathDefinition,
	config GNMIProfileConfig,
	defaultSyncTimeout time.Duration,
	profileModeDefaulted bool,
) (sharedGNMIStream, bool, error) {
	var fragment sharedGNMIStream
	var enabledPaths, disabledPaths int
	for pathIndex := range paths {
		catalogPath := paths[pathIndex]
		effective, enabled := effectiveSharedGNMIGroupConfig(config, catalogPath.Group, defaultSyncTimeout, profileModeDefaulted)
		if !enabled {
			disabledPaths++
			continue
		}
		enabledPaths++
		pathFragment := sharedGNMIStream{
			Profile:        profileName,
			Groups:         []string{catalogPath.Group},
			Required:       effective.required,
			Mode:           gnmiModeStream,
			StreamMode:     effective.streamMode,
			Encoding:       gnmiEncodingAuto,
			SampleInterval: effective.sampleInterval,
			SyncTimeout:    effective.syncTimeout,
			Optics:         profileName == builtinGNMIProfileOptics,
			HealthOnly:     profileName == builtinGNMIProfileIdentity,
			modeDefaulted:  effective.modeDefaulted,
		}
		mergeSharedGNMIStreamCatalogContract(&pathFragment, catalogPath)
		if catalogPath.HighCardinality && effective.maxEntities > 0 {
			entityLimit, entityErr := sharedGNMIEntityLimitForCatalogPath(catalogPath, effective.maxEntities)
			if entityErr != nil {
				return sharedGNMIStream{}, false, fmt.Errorf("group %q path %q entity identity: %w", catalogPath.Group, catalogPath.ID, entityErr)
			}
			pathFragment.EntityLimits = append(pathFragment.EntityLimits, entityLimit)
		}
		expandedPaths, err := expandSharedGNMICatalogPath(catalogPath, effective.selectors, effective.maxEntities)
		if err != nil {
			return sharedGNMIStream{}, false, fmt.Errorf("group %q path %q selectors: %w", catalogPath.Group, catalogPath.ID, err)
		}
		for index, expandedPath := range expandedPaths {
			if index == 0 {
				appendSharedGNMIPath(&pathFragment, expandedPath, catalogPath.Mappings, catalogPath.JSONListKeys)
			} else {
				appendSharedGNMIPath(&pathFragment, expandedPath, nil, nil)
			}
		}
		if enabledPaths == 1 {
			fragment = pathFragment
			continue
		}
		if !compatibleSharedGNMIStreams(platform, fragment, pathFragment) {
			return sharedGNMIStream{}, false, fmt.Errorf(
				"path set %q variant %q cannot be represented as one atomic stream",
				catalogPath.PathSetID, catalogPath.VariantID,
			)
		}
		mergeSharedGNMIStreams(&fragment, pathFragment)
	}
	if enabledPaths > 0 && disabledPaths > 0 {
		return sharedGNMIStream{}, false, fmt.Errorf(
			"path set %q variant %q is only partially enabled",
			paths[0].PathSetID,
			paths[0].VariantID,
		)
	}
	if len(fragment.Paths) == 0 {
		return sharedGNMIStream{}, false, nil
	}
	sortSharedGNMIPaths(fragment.Paths)
	slices.Sort(fragment.Groups)
	fragment.Groups = slices.Compact(fragment.Groups)
	for index := range fragment.Paths {
		fragment.Paths[index].Groups = append([]string(nil), fragment.Groups...)
	}
	for index := range fragment.Mappings {
		fragment.Mappings[index].Groups = append([]string(nil), fragment.Groups...)
	}
	for index := range fragment.JSONListKeyBindings {
		fragment.JSONListKeyBindings[index].Groups = append([]string(nil), fragment.Groups...)
	}
	fragment.AtomicGroupSets = append(fragment.AtomicGroupSets, append([]string(nil), fragment.Groups...))
	if err := attachSharedGNMIJSONListKeySchema(&fragment); err != nil {
		return sharedGNMIStream{}, false, err
	}
	return fragment, true, nil
}

func sharedGNMISourcePreferenceRank(preference string) int {
	switch preference {
	case "openconfig":
		return 0
	case "native":
		return 1
	default:
		return 2
	}
}

type effectiveSharedGNMIGroup struct {
	required       bool
	sampleInterval time.Duration
	streamMode     string
	syncTimeout    time.Duration
	maxEntities    int
	selectors      map[string][]string
	modeDefaulted  bool
}

func effectiveSharedGNMIGroupConfig(
	profile GNMIProfileConfig,
	groupName string,
	defaultSyncTimeout time.Duration,
	profileModeDefaulted bool,
) (effectiveSharedGNMIGroup, bool) {
	effective := effectiveSharedGNMIGroup{
		required:       profile.Required,
		sampleInterval: profile.SampleInterval,
		streamMode:     profile.StreamMode,
		syncTimeout:    defaultSyncTimeout,
		modeDefaulted:  profileModeDefaulted,
	}
	group, configured := profile.Groups[groupName]
	if !configured {
		return effective, true
	}
	if !boolValue(group.Enabled, true) {
		return effectiveSharedGNMIGroup{}, false
	}
	effective.required = profile.Required || group.Required
	if group.SampleInterval > 0 {
		effective.sampleInterval = group.SampleInterval
	}
	if group.StreamMode != "" {
		effective.streamMode = group.StreamMode
		effective.modeDefaulted = group.streamModeDefaulted
	}
	if group.SyncTimeout > 0 {
		effective.syncTimeout = group.SyncTimeout
	}
	effective.maxEntities = group.MaxEntities
	effective.selectors = group.Selectors
	return effective, true
}

func compatibleSharedGNMIStreams(platform string, left, right sharedGNMIStream) bool {
	if left.Profile != right.Profile || left.Required != right.Required || left.Mode != right.Mode ||
		left.StreamMode != right.StreamMode || left.Encoding != right.Encoding ||
		left.SampleInterval != right.SampleInterval || left.PollInterval != right.PollInterval ||
		left.SyncTimeout != right.SyncTimeout || left.Optics != right.Optics || left.HealthOnly != right.HealthOnly {
		return false
	}
	if left.modeDefaulted != right.modeDefaulted {
		return false
	}
	if platform != gnmiPlatformNXOS && len(left.Paths) > 0 && len(right.Paths) > 0 && left.Paths[0].Origin != right.Paths[0].Origin {
		return false
	}
	encodings := intersectSharedGNMICatalogValues(left.CatalogEncodings, right.CatalogEncodings)
	if encodings != nil && len(encodings) == 0 {
		return false
	}
	modes := intersectSharedGNMICatalogValues(left.CatalogModes, right.CatalogModes)
	return modes == nil || len(modes) > 0
}

func mergeSharedGNMIStreams(target *sharedGNMIStream, fragment sharedGNMIStream) {
	target.CatalogEncodings = intersectSharedGNMICatalogValues(target.CatalogEncodings, fragment.CatalogEncodings)
	target.CatalogModes = intersectSharedGNMICatalogValues(target.CatalogModes, fragment.CatalogModes)
	target.Groups = append(target.Groups, fragment.Groups...)
	for _, path := range fragment.Paths {
		appendSharedGNMIPath(target, path, nil, nil)
	}
	target.Mappings = append(target.Mappings, fragment.Mappings...)
	target.JSONListKeySpecs = append(target.JSONListKeySpecs, fragment.JSONListKeySpecs...)
	target.JSONListKeyBindings = append(target.JSONListKeyBindings, fragment.JSONListKeyBindings...)
	for _, groups := range fragment.AtomicGroupSets {
		target.AtomicGroupSets = append(target.AtomicGroupSets, append([]string(nil), groups...))
	}
	mergeSharedGNMIEntityLimits(target, fragment.EntityLimits)
}

func sharedGNMIEntityLimitForCatalogPath(
	catalogPath builtinGNMIPathDefinition,
	maxEntities int,
) (sharedGNMIEntityLimit, error) {
	attributes := append([]string(nil), catalogPath.SelectorKeys...)
	sort.Strings(attributes)
	attributes = slices.Compact(attributes)
	if len(attributes) == 0 {
		return sharedGNMIEntityLimit{}, errors.New("high-cardinality path has no catalog selector keys")
	}
	limit := sharedGNMIEntityLimit{
		Group: catalogPath.Group, MaxEntities: maxEntities, Sources: map[string][]string{},
	}
	for mappingIndex := range catalogPath.Mappings {
		catalogMapping := catalogPath.Mappings[mappingIndex]
		declared := make(map[string]struct{}, len(catalogMapping.Mapping.KeyAttributes))
		for _, keyAttribute := range catalogMapping.Mapping.KeyAttributes {
			declared[keyAttribute.Attribute] = struct{}{}
		}
		for _, attribute := range attributes {
			if _, ok := declared[attribute]; !ok {
				return sharedGNMIEntityLimit{}, fmt.Errorf("mapping source %q does not expose selector attribute %q", sharedGNMISourceKey(catalogMapping.Mapping.Source), attribute)
			}
		}
		limit.Sources[sharedGNMISourceKey(catalogMapping.Mapping.Source)] = append([]string(nil), attributes...)
	}
	if len(limit.Sources) == 0 {
		return sharedGNMIEntityLimit{}, errors.New("high-cardinality path has no mapped entity sources")
	}
	return limit, nil
}

func mergeSharedGNMIEntityLimits(stream *sharedGNMIStream, incoming []sharedGNMIEntityLimit) {
	for _, candidate := range incoming {
		index := slices.IndexFunc(stream.EntityLimits, func(existing sharedGNMIEntityLimit) bool {
			return existing.Group == candidate.Group
		})
		if index < 0 {
			clone := sharedGNMIEntityLimit{
				Group: candidate.Group, MaxEntities: candidate.MaxEntities, Sources: make(map[string][]string, len(candidate.Sources)),
			}
			for source, attributes := range candidate.Sources {
				clone.Sources[source] = append([]string(nil), attributes...)
			}
			stream.EntityLimits = append(stream.EntityLimits, clone)
			continue
		}
		existing := &stream.EntityLimits[index]
		for source, attributes := range candidate.Sources {
			existing.Sources[source] = append([]string(nil), attributes...)
		}
	}
}

type sharedGNMISelectorBinding struct {
	element  string
	key      string
	elements []string
}

func expandSharedGNMICatalogPath(
	catalogPath builtinGNMIPathDefinition,
	selectors map[string][]string,
	maxEntities int,
) ([]sharedGNMIPath, error) {
	base := sharedGNMIPathFromCatalog(catalogPath)
	if len(selectors) == 0 {
		return []sharedGNMIPath{base}, nil
	}
	if maxEntities <= 0 {
		return nil, errors.New("max_entities must be positive when selectors are configured")
	}

	parsed, err := internalgnmi.ParsePath("", catalogPath.Origin, catalogPath.Path)
	if err != nil {
		return nil, err
	}
	template := parsed.Clone()
	selectorNames := make([]string, 0, len(selectors))
	bindings := make(map[string]sharedGNMISelectorBinding, len(selectors))
	for selector := range selectors {
		if !slices.Contains(catalogPath.SelectorKeys, selector) {
			return nil, fmt.Errorf("selector %q is not declared for this catalog path", selector)
		}
		binding, bindingErr := sharedGNMISelectorBindingForPath(catalogPath, selector)
		if bindingErr != nil {
			return nil, bindingErr
		}
		bindings[selector] = binding
		selectorNames = append(selectorNames, selector)
		if mergeErr := mergeSharedGNMISelectorTemplate(&template, binding.elements); mergeErr != nil {
			return nil, fmt.Errorf("selector %q: %w", selector, mergeErr)
		}
	}
	sort.Strings(selectorNames)

	paths := []internalgnmi.Path{template}
	for _, selector := range selectorNames {
		values := append([]string(nil), selectors[selector]...)
		sort.Strings(values)
		if len(values) == 0 {
			return nil, fmt.Errorf("selector %q has no exact values", selector)
		}
		if len(paths) > maxEntities/len(values) {
			return nil, fmt.Errorf("selector expansion exceeds max_entities %d", maxEntities)
		}
		binding := bindings[selector]
		position := len(binding.elements) - 1
		next := make([]internalgnmi.Path, 0, len(paths)*len(values))
		for _, path := range paths {
			for _, value := range values {
				expanded := path.Clone()
				if expanded.Elements[position].Keys == nil {
					expanded.Elements[position].Keys = map[string]string{}
				}
				expanded.Elements[position].Keys[binding.key] = value
				if validateErr := internalgnmi.ValidatePath(expanded); validateErr != nil {
					return nil, fmt.Errorf("selector %q value %q: %w", selector, value, validateErr)
				}
				next = append(next, expanded)
			}
		}
		paths = next
	}

	expanded := make([]sharedGNMIPath, 0, len(paths))
	for _, path := range paths {
		candidate := base
		candidate.Path = path.String()
		expanded = append(expanded, candidate)
	}
	return expanded, nil
}

func sharedGNMISelectorBindingForPath(
	catalogPath builtinGNMIPathDefinition,
	selector string,
) (sharedGNMISelectorBinding, error) {
	element, key := "", ""
	for mappingIndex := range catalogPath.Mappings {
		mapping := catalogPath.Mappings[mappingIndex]
		for _, keyAttribute := range mapping.Mapping.KeyAttributes {
			if keyAttribute.Attribute != selector {
				continue
			}
			if element != "" && (element != keyAttribute.Element || key != keyAttribute.Key) {
				return sharedGNMISelectorBinding{}, fmt.Errorf("selector %q has ambiguous catalog key mappings", selector)
			}
			element, key = keyAttribute.Element, keyAttribute.Key
		}
	}
	if element == "" || key == "" {
		return sharedGNMISelectorBinding{}, fmt.Errorf("selector %q has no catalog key mapping", selector)
	}

	var elements []string
	for _, spec := range catalogPath.JSONListKeys {
		if spec.Origin != catalogPath.Origin || len(spec.Elements) == 0 || spec.Elements[len(spec.Elements)-1] != element || !slices.Contains(spec.Keys, key) {
			continue
		}
		if elements != nil && !slices.Equal(elements, spec.Elements) {
			return sharedGNMISelectorBinding{}, fmt.Errorf("selector %q has ambiguous catalog list-key paths", selector)
		}
		elements = append([]string(nil), spec.Elements...)
	}
	if len(elements) == 0 {
		return sharedGNMISelectorBinding{}, fmt.Errorf("selector %q key %s.%s has no catalog list-key path", selector, element, key)
	}
	return sharedGNMISelectorBinding{element: element, key: key, elements: elements}, nil
}

func mergeSharedGNMISelectorTemplate(path *internalgnmi.Path, selectorElements []string) error {
	current := make([]string, len(path.Elements))
	for index := range path.Elements {
		current[index] = path.Elements[index].Name
	}
	common := min(len(current), len(selectorElements))
	if !slices.Equal(current[:common], selectorElements[:common]) {
		return fmt.Errorf("catalog list-key path %q is not compatible with subscription path %q", strings.Join(selectorElements, "/"), path.String())
	}
	if len(selectorElements) > len(current) {
		for _, element := range selectorElements[len(current):] {
			path.Elements = append(path.Elements, internalgnmi.PathElem{Name: element})
		}
	}
	return nil
}

func mergeSharedGNMIStreamCatalogContract(stream *sharedGNMIStream, path builtinGNMIPathDefinition) {
	stream.CatalogEncodings = intersectSharedGNMICatalogValues(stream.CatalogEncodings, path.Encodings)
	stream.CatalogModes = intersectSharedGNMICatalogValues(stream.CatalogModes, path.StreamModes)
}

func intersectSharedGNMICatalogValues(current, declared []string) []string {
	if len(declared) == 0 {
		return current
	}
	if current == nil {
		return append([]string(nil), declared...)
	}
	intersection := make([]string, 0, min(len(current), len(declared)))
	for _, value := range current {
		if slices.Contains(declared, value) {
			intersection = append(intersection, value)
		}
	}
	return intersection
}

func finalizeSharedGNMIStreamCatalogContract(stream *sharedGNMIStream, modeDefaulted bool) error {
	if stream == nil {
		return errors.New("gNMI stream is required")
	}
	if stream.CatalogEncodings != nil && len(stream.CatalogEncodings) == 0 {
		return fmt.Errorf("stream %q paths have no common catalog-declared encoding", stream.Profile)
	}
	if stream.CatalogModes == nil {
		return nil
	}
	if len(stream.CatalogModes) == 0 {
		return fmt.Errorf("stream %q paths have no common catalog-declared stream mode", stream.Profile)
	}
	if stream.StreamMode == gnmiStreamModeAuto || (modeDefaulted && !slices.Contains(stream.CatalogModes, stream.StreamMode)) {
		stream.StreamMode = stream.CatalogModes[0]
		return nil
	}
	if !slices.Contains(stream.CatalogModes, stream.StreamMode) {
		return fmt.Errorf(
			"stream %q requested stream_mode %q, but its paths declare only %s",
			stream.Profile,
			stream.StreamMode,
			strings.Join(stream.CatalogModes, ", "),
		)
	}
	return nil
}

func appendSharedGNMIPath(stream *sharedGNMIStream, path sharedGNMIPath, mappings []builtinGNMIMapping, listKeys []internalgnmi.JSONListKeySpec) {
	stream.JSONListKeySpecs = append(stream.JSONListKeySpecs, listKeys...)
	for _, spec := range listKeys {
		stream.JSONListKeyBindings = append(stream.JSONListKeyBindings, sharedGNMIJSONListKeyBinding{
			Spec: internalgnmi.JSONListKeySpec{
				Origin: spec.Origin, Elements: append([]string(nil), spec.Elements...), Keys: append([]string(nil), spec.Keys...),
			},
			Groups: append([]string(nil), path.Groups...),
		})
	}
	path = normalizeSharedGNMIPathVariants(path)
	for index := range stream.Paths {
		if sharedGNMIPathKey(stream.Paths[index]) != sharedGNMIPathKey(path) {
			continue
		}
		stream.Paths[index].PathSetVariants = mergeSharedGNMIPathSetVariants(
			stream.Paths[index].PathSetVariants,
			path.PathSetVariants,
		)
		stream.Paths[index].Groups = append(stream.Paths[index].Groups, path.Groups...)
		slices.Sort(stream.Paths[index].Groups)
		stream.Paths[index].Groups = slices.Compact(stream.Paths[index].Groups)
		stream.Mappings = append(stream.Mappings, mappings...)
		return
	}
	stream.Paths = append(stream.Paths, path)
	stream.Mappings = append(stream.Mappings, mappings...)
}

func sharedGNMIPathFromCatalog(path builtinGNMIPathDefinition) sharedGNMIPath {
	return normalizeSharedGNMIPathVariants(sharedGNMIPath{
		Origin:    path.Origin,
		Path:      path.Path,
		PathSetID: path.PathSetID,
		VariantID: path.VariantID,
		Groups:    []string{path.Group},
	})
}

func normalizeSharedGNMIPathVariants(path sharedGNMIPath) sharedGNMIPath {
	if path.PathSetID != "" {
		path.PathSetVariants = mergeSharedGNMIPathSetVariants(path.PathSetVariants, []sharedGNMIPathSetVariant{{
			PathSetID: path.PathSetID,
			VariantID: path.VariantID,
		}})
	}
	return path
}

func mergeSharedGNMIPathSetVariants(
	left []sharedGNMIPathSetVariant,
	right []sharedGNMIPathSetVariant,
) []sharedGNMIPathSetVariant {
	out := append([]sharedGNMIPathSetVariant(nil), left...)
	for _, candidate := range right {
		if candidate.PathSetID == "" || slices.Contains(out, candidate) {
			continue
		}
		out = append(out, candidate)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].PathSetID != out[j].PathSetID {
			return out[i].PathSetID < out[j].PathSetID
		}
		return out[i].VariantID < out[j].VariantID
	})
	return out
}

func sortSharedGNMIPaths(paths []sharedGNMIPath) {
	sort.SliceStable(paths, func(i, j int) bool {
		if paths[i].Origin != paths[j].Origin {
			return paths[i].Origin < paths[j].Origin
		}
		return paths[i].Path < paths[j].Path
	})
}

func buildCustomGNMIStream(subscription GNMICustomSubscriptionConfig, syncTimeout ...time.Duration) (sharedGNMIStream, error) {
	streamSyncTimeout := gnmiDefaultSyncTimeout
	if len(syncTimeout) > 0 && syncTimeout[0] > 0 {
		streamSyncTimeout = syncTimeout[0]
	}
	stream := sharedGNMIStream{
		Profile:        subscription.Name,
		Required:       subscription.Required,
		Mode:           subscription.Mode,
		StreamMode:     gnmiStreamModeSample,
		Encoding:       subscription.Encoding,
		SampleInterval: subscription.SampleInterval,
		PollInterval:   subscription.PollInterval,
		SyncTimeout:    streamSyncTimeout,
	}
	for i, configured := range subscription.Mappings {
		catalogMapping, path, err := convertCustomGNMIMapping(subscription.Origin, configured)
		if err != nil {
			return sharedGNMIStream{}, fmt.Errorf("mapping %d: %w", i, err)
		}
		appendSharedGNMIPath(&stream, path, []builtinGNMIMapping{catalogMapping}, nil)
	}
	sortSharedGNMIPaths(stream.Paths)
	stream.JSONListKeySpecs = sharedGNMIJSONListKeySpecsFromMappings(stream.Mappings)
	if err := attachSharedGNMIJSONListKeySchema(&stream); err != nil {
		return sharedGNMIStream{}, err
	}
	return stream, nil
}

func attachSharedGNMIJSONListKeySchema(stream *sharedGNMIStream) error {
	specs := deduplicateSharedGNMIJSONListKeySpecs(stream.JSONListKeySpecs)
	schema, err := internalgnmi.NewJSONListKeySchema(specs...)
	if err != nil {
		return err
	}
	stream.JSONListKeys = schema
	return nil
}

func sharedGNMIJSONListKeySpecsFromMappings(mappings []builtinGNMIMapping) []internalgnmi.JSONListKeySpec {
	var specs []internalgnmi.JSONListKeySpec
	for mappingIndex := range mappings {
		catalogMapping := mappings[mappingIndex]
		mapping := catalogMapping.Mapping
		for _, keyAttribute := range mapping.KeyAttributes {
			index := slices.Index(mapping.Source.Elements, keyAttribute.Element)
			if index < 0 {
				continue
			}
			specs = append(specs, internalgnmi.JSONListKeySpec{
				Origin: mapping.Source.Origin, Elements: append([]string(nil), mapping.Source.Elements[:index+1]...), Keys: []string{keyAttribute.Key},
			})
		}
	}
	return deduplicateSharedGNMIJSONListKeySpecs(specs)
}

func deduplicateSharedGNMIJSONListKeySpecs(specs []internalgnmi.JSONListKeySpec) []internalgnmi.JSONListKeySpec {
	type definition struct {
		origin, identity string
		elements         []string
		keys             map[string]struct{}
	}
	definitions := map[string]*definition{}
	for _, spec := range specs {
		identity := spec.Origin + "\x00" + strings.Join(spec.Elements, "\x00")
		item := definitions[identity]
		if item == nil {
			item = &definition{origin: spec.Origin, identity: identity, elements: append([]string(nil), spec.Elements...), keys: map[string]struct{}{}}
			definitions[identity] = item
		}
		for _, key := range spec.Keys {
			item.keys[key] = struct{}{}
		}
	}
	identities := make([]string, 0, len(definitions))
	for identity := range definitions {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	out := make([]internalgnmi.JSONListKeySpec, 0, len(identities))
	for _, identity := range identities {
		item := definitions[identity]
		keys := make([]string, 0, len(item.keys))
		for key := range item.keys {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out = append(out, internalgnmi.JSONListKeySpec{Origin: item.origin, Elements: item.elements, Keys: keys})
	}
	return out
}

func convertCustomGNMIMapping(origin string, configured GNMIMetricMappingConfig) (builtinGNMIMapping, sharedGNMIPath, error) {
	parsed, err := internalgnmi.ParsePath("", origin, configured.Path)
	if err != nil {
		return builtinGNMIMapping{}, sharedGNMIPath{}, err
	}
	series, err := parsed.SplitLeaf()
	if err != nil {
		return builtinGNMIMapping{}, sharedGNMIPath{}, err
	}
	elements := make([]string, len(series.Elements))
	for i, element := range series.Elements {
		elements[i] = element.Name
	}
	keys := make([]internalgnmi.KeyAttribute, 0, len(configured.PathKeys))
	for _, selector := range sortedGNMIPathKeys(configured.PathKeys) {
		element, key, ok := strings.Cut(selector, ".")
		if !ok || element == "" || key == "" {
			return builtinGNMIMapping{}, sharedGNMIPath{}, fmt.Errorf("invalid path key selector %q", selector)
		}
		keys = append(keys, internalgnmi.KeyAttribute{Element: element, Key: key, Attribute: configured.PathKeys[selector]})
	}
	if configured.Scale == nil {
		return builtinGNMIMapping{}, sharedGNMIPath{}, errors.New("scale must be explicitly configured")
	}
	gauge := internalgnmi.GaugeValueType(configured.GaugeType)
	converted := builtinGNMIMapping{Mapping: internalgnmi.Mapping{
		Source: internalgnmi.SourcePath{
			Origin:   origin,
			Elements: elements,
			Leaf:     series.Leaf,
		},
		Metric: internalgnmi.MetricMetadata{
			Name:        configured.MetricName,
			Description: configured.Description,
			Unit:        configured.Unit,
		},
		Scale:         *configured.Scale,
		GaugeType:     gauge,
		KeyAttributes: keys,
	}}
	if _, err := internalgnmi.NewRegistry(converted.Mapping); err != nil {
		return builtinGNMIMapping{}, sharedGNMIPath{}, err
	}
	return converted, sharedGNMIPath{Origin: origin, Path: strings.Trim(configured.Path, "/")}, nil
}

func sharedGNMIProfileConfig(profiles GNMIProfilesConfig, name string) GNMIProfileConfig {
	switch name {
	case builtinGNMIProfileIdentity:
		return profiles.Identity
	case builtinGNMIProfileSystem:
		return profiles.System
	case builtinGNMIProfileInterfaces:
		return profiles.Interfaces
	case builtinGNMIProfileOptics:
		return profiles.Optics
	case builtinGNMIProfileCatalyst9800Wireless:
		return profiles.Catalyst9800Wireless
	case "inventory":
		return profiles.Inventory
	case "environment":
		return profiles.Environment
	case "l2":
		return profiles.L2
	case "routing":
		return profiles.Routing
	case "mpls":
		return profiles.MPLS
	case "overlay":
		return profiles.Overlay
	case "qos":
		return profiles.QoS
	case "acl":
		return profiles.ACL
	case "topology":
		return profiles.Topology
	case "poe":
		return profiles.PoE
	case "time_sync":
		return profiles.TimeSync
	case "high_availability":
		return profiles.HighAvailability
	case "asic":
		return profiles.ASIC
	case "telemetry_self":
		return profiles.TelemetrySelf
	default:
		return GNMIProfileConfig{}
	}
}

// buildSharedGNMISubscribeRequest places IOS XE and IOS XR origins on the
// SubscriptionList prefix. NX-OS keeps each origin on its individual path.
func buildSharedGNMISubscribeRequest(target GNMITargetConfig, stream sharedGNMIStream, encoding gnmipb.Encoding) (*gnmipb.SubscribeRequest, error) {
	if len(stream.Paths) == 0 {
		return nil, fmt.Errorf("stream %q has no subscription paths", stream.Profile)
	}
	listMode, err := sharedGNMIListMode(stream.Mode)
	if err != nil {
		return nil, err
	}
	list := &gnmipb.SubscriptionList{
		Mode:         listMode,
		Encoding:     encoding,
		Subscription: make([]*gnmipb.Subscription, 0, len(stream.Paths)),
	}
	streamMode, err := sharedGNMISubscriptionMode(stream.StreamMode)
	if err != nil {
		return nil, err
	}
	if target.Platform != gnmiPlatformNXOS {
		origin := stream.Paths[0].Origin
		for _, path := range stream.Paths[1:] {
			if path.Origin != origin {
				return nil, fmt.Errorf("stream %q mixes prefix origins %q and %q", stream.Profile, origin, path.Origin)
			}
		}
		list.Prefix = &gnmipb.Path{Origin: origin}
	}
	for _, path := range stream.Paths {
		pathOrigin := ""
		if target.Platform == gnmiPlatformNXOS {
			pathOrigin = path.Origin
		}
		protoPath, err := sharedGNMIPathToProto(pathOrigin, path.Path)
		if err != nil {
			return nil, fmt.Errorf("path %q: %w", path.Path, err)
		}
		subscription := &gnmipb.Subscription{Path: protoPath, Mode: streamMode}
		if stream.Mode == gnmiModeStream && streamMode == gnmipb.SubscriptionMode_SAMPLE {
			subscription.SampleInterval = uint64(stream.SampleInterval.Nanoseconds())
		}
		list.Subscription = append(list.Subscription, subscription)
	}
	return &gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Subscribe{Subscribe: list}}, nil
}

func sharedGNMISubscriptionMode(mode string) (gnmipb.SubscriptionMode, error) {
	switch mode {
	case "", gnmiStreamModeSample:
		return gnmipb.SubscriptionMode_SAMPLE, nil
	case gnmiStreamModeOnChange:
		return gnmipb.SubscriptionMode_ON_CHANGE, nil
	case gnmiStreamModeAuto, gnmiStreamModeTargetDefined:
		return gnmipb.SubscriptionMode_TARGET_DEFINED, nil
	default:
		return gnmipb.SubscriptionMode_TARGET_DEFINED, fmt.Errorf("unsupported gNMI stream mode %q", mode)
	}
}

func sharedGNMIPathToProto(origin, path string) (*gnmipb.Path, error) {
	parsed, err := internalgnmi.ParsePath("", origin, path)
	if err != nil {
		return nil, err
	}
	return parsed.ToProto(), nil
}

func sharedGNMIListMode(mode string) (gnmipb.SubscriptionList_Mode, error) {
	switch mode {
	case gnmiModeStream:
		return gnmipb.SubscriptionList_STREAM, nil
	case gnmiModeOnce:
		return gnmipb.SubscriptionList_ONCE, nil
	case gnmiModePoll:
		return gnmipb.SubscriptionList_POLL, nil
	default:
		return gnmipb.SubscriptionList_STREAM, fmt.Errorf("unsupported subscription mode %q", mode)
	}
}

// negotiateSharedGNMIEncoding selects a common encoding for callers which
// still operate on a stream set. Runtime sessions select each stream with
// negotiateSharedGNMIStreamEncoding so explicit custom encodings do not force
// unrelated paths onto the same wire representation.
func negotiateSharedGNMIEncoding(target GNMITargetConfig, capabilities *gnmipb.CapabilityResponse, streams []sharedGNMIStream) (gnmipb.Encoding, error) {
	if capabilities == nil {
		return gnmipb.Encoding_JSON, errors.New("gNMI capabilities response is required")
	}
	for _, encoding := range sharedGNMIEncodingPreference(target) {
		if !sharedGNMICapabilitiesSupportEncoding(capabilities, encoding) {
			continue
		}
		compatible := true
		for i := range streams {
			if !sharedGNMIStreamAllowsEncoding(streams[i], encoding) {
				compatible = false
				break
			}
		}
		if compatible {
			return encoding, nil
		}
	}
	return gnmipb.Encoding_JSON, errors.New("target and selected paths have no common supported gNMI encoding")
}

// negotiateSharedGNMIStreamEncoding applies an explicit custom-subscription
// encoding first. For auto streams it preserves the target preference order
// after intersecting it with the server and path decoder capabilities.
func negotiateSharedGNMIStreamEncoding(
	target GNMITargetConfig,
	capabilities *gnmipb.CapabilityResponse,
	stream sharedGNMIStream,
) (gnmipb.Encoding, error) {
	if capabilities == nil {
		return gnmipb.Encoding_JSON, errors.New("gNMI capabilities response is required")
	}
	if stream.Encoding != "" && stream.Encoding != gnmiEncodingAuto {
		encoding, err := sharedGNMIEncodingFromConfig(stream.Encoding)
		if err != nil {
			return gnmipb.Encoding_JSON, err
		}
		if !sharedGNMIStreamAllowsEncoding(stream, encoding) {
			return gnmipb.Encoding_JSON, fmt.Errorf("stream %q cannot use requested encoding %q", stream.Profile, stream.Encoding)
		}
		if !sharedGNMICapabilitiesSupportEncoding(capabilities, encoding) {
			return gnmipb.Encoding_JSON, fmt.Errorf("stream %q requested encoding %q that the target does not advertise", stream.Profile, stream.Encoding)
		}
		return encoding, nil
	}
	for _, encoding := range sharedGNMIEncodingPreference(target) {
		if sharedGNMIStreamAllowsEncoding(stream, encoding) && sharedGNMICapabilitiesSupportEncoding(capabilities, encoding) {
			return encoding, nil
		}
	}
	return gnmipb.Encoding_JSON, fmt.Errorf("stream %q and target have no common supported gNMI encoding", stream.Profile)
}

func sharedGNMIEncodingPreference(target GNMITargetConfig) []gnmipb.Encoding {
	target = target.withDefaults()
	preference := make([]gnmipb.Encoding, 0, len(target.EncodingPreference))
	for _, configured := range target.EncodingPreference {
		encoding, err := sharedGNMIEncodingFromConfig(configured)
		if err == nil {
			preference = append(preference, encoding)
		}
	}
	return preference
}

func sharedGNMIEncodingFromConfig(configured string) (gnmipb.Encoding, error) {
	switch configured {
	case gnmiEncodingProto:
		return gnmipb.Encoding_PROTO, nil
	case gnmiEncodingJSONIETF:
		return gnmipb.Encoding_JSON_IETF, nil
	case gnmiEncodingJSON:
		return gnmipb.Encoding_JSON, nil
	default:
		return gnmipb.Encoding_JSON, fmt.Errorf("unsupported gNMI encoding %q", configured)
	}
}

func sharedGNMICapabilitiesSupportEncoding(capabilities *gnmipb.CapabilityResponse, wanted gnmipb.Encoding) bool {
	return slices.Contains(capabilities.GetSupportedEncodings(), wanted)
}

func sharedGNMIStreamAllowsEncoding(stream sharedGNMIStream, encoding gnmipb.Encoding) bool {
	configuredEncoding, ok := sharedGNMIEncodingConfigName(encoding)
	if !ok || (stream.CatalogEncodings != nil && !slices.Contains(stream.CatalogEncodings, configuredEncoding)) {
		return false
	}
	if sharedGNMIStreamsContainOrigin([]sharedGNMIStream{stream}, builtinGNMIOriginDME) {
		// NX DME publishes structured JSON. Opaque DME proto_bytes remain
		// disabled until a schema decoder is cataloged and qualified.
		return encoding == gnmipb.Encoding_JSON
	}
	if encoding == gnmipb.Encoding_PROTO && isBuiltinGNMIProfileName(stream.Profile) {
		// No generated product/path row currently carries the product-specific
		// IOS XE PROTO qualification evidence required by the public contract.
		return false
	}
	return encoding == gnmipb.Encoding_PROTO || encoding == gnmipb.Encoding_JSON_IETF || encoding == gnmipb.Encoding_JSON
}

func sharedGNMIEncodingConfigName(encoding gnmipb.Encoding) (string, bool) {
	switch encoding {
	case gnmipb.Encoding_PROTO:
		return gnmiEncodingProto, true
	case gnmipb.Encoding_JSON_IETF:
		return gnmiEncodingJSONIETF, true
	case gnmipb.Encoding_JSON:
		return gnmiEncodingJSON, true
	default:
		return "", false
	}
}

func sharedGNMIStreamsContainOrigin(streams []sharedGNMIStream, origin string) bool {
	for streamIndex := range streams {
		stream := streams[streamIndex]
		for _, path := range stream.Paths {
			if path.Origin == origin {
				return true
			}
		}
	}
	return false
}
