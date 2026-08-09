// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

type sharedGNMIEntityCapacityError struct {
	Profile, Group            string
	Limit, Current, Requested int
}

func (e *sharedGNMIEntityCapacityError) Error() string {
	return fmt.Sprintf(
		"gNMI group %q profile %q max_entities exceeded: limit=%d current=%d requested=%d",
		e.Group,
		e.Profile,
		e.Limit,
		e.Current,
		e.Requested,
	)
}

type sharedGNMIEntityDescriptor struct {
	groupKey   string
	attributes []string
}

type sharedGNMIEntityGroupState struct {
	profile, group string
	limit          int
	entities       map[string]int
}

// sharedGNMIEntityLimitManager accounts committed cache entries rather than
// delivery attempts. A refcount makes several metric leaves for one catalog
// entity consume one max_entities slot.
type sharedGNMIEntityLimitManager struct {
	mu sync.Mutex

	plans          map[string][]sharedGNMIEntityDescriptor
	groups         map[string]*sharedGNMIEntityGroupState
	sourceEntities map[string]map[string]string
}

func newSharedGNMIEntityLimitManager(
	streams []sharedGNMIRuntimeStream,
	snapshot []internalgnmi.MappedPoint,
) (*sharedGNMIEntityLimitManager, error) {
	manager := &sharedGNMIEntityLimitManager{
		plans:          map[string][]sharedGNMIEntityDescriptor{},
		groups:         map[string]*sharedGNMIEntityGroupState{},
		sourceEntities: map[string]map[string]string{},
	}
	registerLimits := func(profile string, limits []sharedGNMIEntityLimit) error {
		for _, limit := range limits {
			if limit.MaxEntities <= 0 {
				return fmt.Errorf("profile %q group %q has a non-positive entity limit", profile, limit.Group)
			}
			groupKey := sharedGNMIEntityGroupKey(profile, limit.Group)
			group := manager.groups[groupKey]
			if group == nil {
				group = &sharedGNMIEntityGroupState{
					profile: profile, group: limit.Group, limit: limit.MaxEntities, entities: map[string]int{},
				}
				manager.groups[groupKey] = group
			} else if group.limit != limit.MaxEntities {
				return fmt.Errorf(
					"profile %q group %q has conflicting max_entities values %d and %d",
					profile,
					limit.Group,
					group.limit,
					limit.MaxEntities,
				)
			}
			for source, attributes := range limit.Sources {
				descriptor := sharedGNMIEntityDescriptor{groupKey: groupKey, attributes: append([]string(nil), attributes...)}
				sort.Strings(descriptor.attributes)
				if err := appendSharedGNMIEntityDescriptor(manager.plans, source, descriptor); err != nil {
					return err
				}
			}
		}
		return nil
	}
	var registerStream func(sharedGNMIRuntimeStream) error
	registerStream = func(stream sharedGNMIRuntimeStream) error {
		if err := registerLimits(stream.Profile, stream.EntityLimits); err != nil {
			return err
		}
		for index := range stream.variantFallbacks {
			if err := registerStream(stream.variantFallbacks[index].stream); err != nil {
				return err
			}
		}
		// Directly constructed unit streams may still carry the pre-runtime
		// catalog form. Production buildSharedGNMIRuntimeStream moves these into
		// variantFallbacks after creating the variant-specific registries.
		for index := range stream.VariantFallbacks {
			fallback := &stream.VariantFallbacks[index]
			if err := registerLimits(fallback.Stream.Profile, fallback.Stream.EntityLimits); err != nil {
				return err
			}
		}
		return nil
	}
	for index := range streams {
		if err := registerStream(streams[index]); err != nil {
			return nil, err
		}
	}
	for index := range snapshot {
		point := &snapshot[index]
		planKey := sharedGNMISeriesSourceKey(point.Source)
		sourceKey := point.Key()
		for _, descriptor := range manager.plans[planKey] {
			entityKey, err := sharedGNMIEntityIdentity(descriptor.attributes, point.Attributes)
			if err != nil {
				return nil, fmt.Errorf("rebuild entity state for source %q: %w", sourceKey, err)
			}
			owners := manager.sourceEntities[sourceKey]
			if owners == nil {
				owners = map[string]string{}
				manager.sourceEntities[sourceKey] = owners
			}
			if previous, exists := owners[descriptor.groupKey]; exists {
				if previous != entityKey {
					return nil, fmt.Errorf("cached source %q has conflicting catalog entity identities", sourceKey)
				}
				continue
			}
			owners[descriptor.groupKey] = entityKey
			manager.groups[descriptor.groupKey].entities[entityKey]++
		}
	}
	for _, group := range manager.groups {
		if len(group.entities) > group.limit {
			return nil, &sharedGNMIEntityCapacityError{
				Profile: group.profile, Group: group.group, Limit: group.limit,
				Current: len(group.entities), Requested: len(group.entities),
			}
		}
	}
	return manager, nil
}

func appendSharedGNMIEntityDescriptor(
	plans map[string][]sharedGNMIEntityDescriptor,
	source string,
	descriptor sharedGNMIEntityDescriptor,
) error {
	for _, existing := range plans[source] {
		if existing.groupKey != descriptor.groupKey {
			continue
		}
		if !slices.Equal(existing.attributes, descriptor.attributes) {
			return fmt.Errorf("catalog source %q has conflicting entity keys in one group", source)
		}
		return nil
	}
	plans[source] = append(plans[source], descriptor)
	return nil
}

func sharedGNMIEntityGroupKey(profile, group string) string { return profile + "\x00" + group }

func sharedGNMIGroupSuppressionKey(profile, group string) string {
	return sharedGNMIEntityGroupKey(profile, group)
}

func filterSharedGNMIRuntimeGroups(
	stream sharedGNMIRuntimeStream,
	requested ...string,
) (sharedGNMIRuntimeStream, []string, bool, error) {
	removed := make(map[string]struct{}, len(requested))
	for _, group := range requested {
		if group != "" && slices.Contains(stream.Groups, group) {
			removed[group] = struct{}{}
		}
	}
	if len(removed) == 0 {
		return stream, nil, len(stream.Paths) > 0, nil
	}
	// A catalog path set is indivisible. Every path and mapping in one variant
	// carries the variant's group closure, so suppress all partner groups when
	// removing any member would otherwise split an atomic set.
	for changed := true; changed; {
		changed = false
		for _, atomicGroups := range stream.AtomicGroupSets {
			if !sharedGNMIGroupSetIntersects(atomicGroups, removed) {
				continue
			}
			for _, group := range atomicGroups {
				if _, exists := removed[group]; !exists {
					removed[group] = struct{}{}
					changed = true
				}
			}
		}
	}

	filtered := stream.sharedGNMIStream
	filtered.VariantFallbacks = nil
	filtered.Groups = removeSharedGNMIGroups(filtered.Groups, removed)
	filtered.Paths = make([]sharedGNMIPath, 0, len(stream.Paths))
	for _, path := range stream.Paths {
		remainingGroups := removeSharedGNMIGroups(path.Groups, removed)
		if len(path.Groups) > 0 && len(remainingGroups) == 0 {
			continue
		}
		clone := path
		clone.Groups = remainingGroups
		clone.PathSetVariants = append([]sharedGNMIPathSetVariant(nil), path.PathSetVariants...)
		filtered.Paths = append(filtered.Paths, clone)
	}
	filtered.Mappings = make([]builtinGNMIMapping, 0, len(stream.Mappings))
	for index := range stream.Mappings {
		mapping := &stream.Mappings[index]
		if len(mapping.Groups) > 0 && sharedGNMIGroupSetIntersects(mapping.Groups, removed) {
			continue
		}
		filtered.Mappings = append(filtered.Mappings, cloneBuiltinGNMIMappings(stream.Mappings[index : index+1])[0])
	}
	filtered.EntityLimits = make([]sharedGNMIEntityLimit, 0, len(stream.EntityLimits))
	for _, limit := range stream.EntityLimits {
		if _, drop := removed[limit.Group]; drop {
			continue
		}
		filtered.EntityLimits = append(filtered.EntityLimits, limit)
	}
	filtered.AtomicGroupSets = make([][]string, 0, len(stream.AtomicGroupSets))
	for _, groups := range stream.AtomicGroupSets {
		if sharedGNMIGroupSetIntersects(groups, removed) {
			continue
		}
		filtered.AtomicGroupSets = append(filtered.AtomicGroupSets, append([]string(nil), groups...))
	}
	filtered.JSONListKeySpecs = nil
	filtered.JSONListKeyBindings = make([]sharedGNMIJSONListKeyBinding, 0, len(stream.JSONListKeyBindings))
	for _, binding := range stream.JSONListKeyBindings {
		if len(binding.Groups) > 0 && sharedGNMIGroupSetIntersects(binding.Groups, removed) {
			continue
		}
		clone := sharedGNMIJSONListKeyBinding{
			Spec: internalgnmi.JSONListKeySpec{
				Origin:   binding.Spec.Origin,
				Elements: append([]string(nil), binding.Spec.Elements...),
				Keys:     append([]string(nil), binding.Spec.Keys...),
			},
			Groups: append([]string(nil), binding.Groups...),
		}
		filtered.JSONListKeyBindings = append(filtered.JSONListKeyBindings, clone)
		filtered.JSONListKeySpecs = append(filtered.JSONListKeySpecs, clone.Spec)
	}
	filtered.JSONListKeys = nil
	removedNames := make([]string, 0, len(removed))
	for group := range removed {
		removedNames = append(removedNames, group)
	}
	sort.Strings(removedNames)
	if len(filtered.Paths) == 0 {
		return sharedGNMIRuntimeStream{}, removedNames, false, nil
	}
	if err := attachSharedGNMIJSONListKeySchema(&filtered); err != nil {
		return sharedGNMIRuntimeStream{}, nil, false, err
	}
	runtime, err := buildSharedGNMIRuntimeStream(filtered)
	if err != nil {
		return sharedGNMIRuntimeStream{}, nil, false, err
	}
	runtime.wireEncoding = stream.wireEncoding
	return runtime, removedNames, true, nil
}

func sharedGNMIGroupSetIntersects(groups []string, selected map[string]struct{}) bool {
	for _, group := range groups {
		if _, ok := selected[group]; ok {
			return true
		}
	}
	return false
}

func removeSharedGNMIGroups(groups []string, removed map[string]struct{}) []string {
	filtered := make([]string, 0, len(groups))
	for _, group := range groups {
		if _, drop := removed[group]; !drop {
			filtered = append(filtered, group)
		}
	}
	return filtered
}

func sharedGNMIEntityIdentity(attributes []string, values map[string]string) (string, error) {
	if len(attributes) == 0 {
		return "", errors.New("catalog entity identity has no attributes")
	}
	var identity strings.Builder
	for _, attribute := range attributes {
		value, ok := values[attribute]
		if !ok || value == "" {
			return "", fmt.Errorf("mapped point is missing entity attribute %q", attribute)
		}
		fmt.Fprintf(&identity, "%d:%s%d:%s", len(attribute), attribute, len(value), value)
	}
	return identity.String(), nil
}

type sharedGNMIEntityLimitTransaction struct {
	manager       *sharedGNMIEntityLimitManager
	sourceChanges map[string]map[string]string
	entityDeltas  map[string]map[string]int
	done          bool
}

func (manager *sharedGNMIEntityLimitManager) prepare(
	result internalgnmi.CacheResult,
) (*sharedGNMIEntityLimitTransaction, error) {
	if manager == nil || len(manager.groups) == 0 {
		return nil, nil
	}
	manager.mu.Lock()
	transaction := &sharedGNMIEntityLimitTransaction{
		manager: manager, sourceChanges: map[string]map[string]string{}, entityDeltas: map[string]map[string]int{},
	}
	rollbackOnError := func(err error) (*sharedGNMIEntityLimitTransaction, error) {
		transaction.rollback()
		return nil, err
	}

	for index := range result.Removed {
		if err := transaction.removeSource(result.Removed[index].Key()); err != nil {
			return rollbackOnError(err)
		}
	}
	for index := range result.Replaced {
		if err := transaction.removeSource(result.Replaced[index].Key()); err != nil {
			return rollbackOnError(err)
		}
	}
	for index := range result.Applied {
		if err := transaction.applyPoint(&result.Applied[index]); err != nil {
			return rollbackOnError(err)
		}
	}
	for groupKey, deltas := range transaction.entityDeltas {
		group := manager.groups[groupKey]
		requested := len(group.entities)
		for entityKey, delta := range deltas {
			current := group.entities[entityKey]
			projected := current + delta
			if projected < 0 {
				return rollbackOnError(fmt.Errorf("profile %q group %q entity accounting underflow", group.profile, group.group))
			}
			if current == 0 && projected > 0 {
				requested++
			} else if current > 0 && projected == 0 {
				requested--
			}
		}
		if requested > group.limit {
			return rollbackOnError(&sharedGNMIEntityCapacityError{
				Profile: group.profile, Group: group.group, Limit: group.limit,
				Current: len(group.entities), Requested: requested,
			})
		}
	}
	return transaction, nil
}

func (transaction *sharedGNMIEntityLimitTransaction) owners(sourceKey string) map[string]string {
	if changed, ok := transaction.sourceChanges[sourceKey]; ok {
		return changed
	}
	committed := transaction.manager.sourceEntities[sourceKey]
	owners := maps.Clone(committed)
	if owners == nil {
		owners = map[string]string{}
	}
	transaction.sourceChanges[sourceKey] = owners
	return owners
}

func (transaction *sharedGNMIEntityLimitTransaction) addDelta(groupKey, entityKey string, delta int) {
	if transaction.entityDeltas[groupKey] == nil {
		transaction.entityDeltas[groupKey] = map[string]int{}
	}
	transaction.entityDeltas[groupKey][entityKey] += delta
}

func (transaction *sharedGNMIEntityLimitTransaction) removeSource(sourceKey string) error {
	owners := transaction.owners(sourceKey)
	for groupKey, entityKey := range owners {
		if transaction.manager.groups[groupKey] == nil {
			return fmt.Errorf("source %q refers to an unknown entity group", sourceKey)
		}
		transaction.addDelta(groupKey, entityKey, -1)
		delete(owners, groupKey)
	}
	return nil
}

func (transaction *sharedGNMIEntityLimitTransaction) applyPoint(point *internalgnmi.MappedPoint) error {
	planKey := sharedGNMISeriesSourceKey(point.Source)
	descriptors := transaction.manager.plans[planKey]
	if len(descriptors) == 0 {
		return nil
	}
	sourceKey := point.Key()
	owners := transaction.owners(sourceKey)
	for _, descriptor := range descriptors {
		entityKey, err := sharedGNMIEntityIdentity(descriptor.attributes, point.Attributes)
		if err != nil {
			return fmt.Errorf("source %q: %w", sourceKey, err)
		}
		if previous, exists := owners[descriptor.groupKey]; exists {
			if previous == entityKey {
				continue
			}
			transaction.addDelta(descriptor.groupKey, previous, -1)
		}
		transaction.addDelta(descriptor.groupKey, entityKey, 1)
		owners[descriptor.groupKey] = entityKey
	}
	return nil
}

func (transaction *sharedGNMIEntityLimitTransaction) commit() {
	if transaction == nil || transaction.done {
		return
	}
	transaction.done = true
	for groupKey, deltas := range transaction.entityDeltas {
		entities := transaction.manager.groups[groupKey].entities
		for entityKey, delta := range deltas {
			remaining := entities[entityKey] + delta
			if remaining == 0 {
				delete(entities, entityKey)
			} else {
				entities[entityKey] = remaining
			}
		}
	}
	for sourceKey, owners := range transaction.sourceChanges {
		if len(owners) == 0 {
			delete(transaction.manager.sourceEntities, sourceKey)
			continue
		}
		transaction.manager.sourceEntities[sourceKey] = owners
	}
	transaction.manager.mu.Unlock()
}

func (transaction *sharedGNMIEntityLimitTransaction) rollback() {
	if transaction == nil || transaction.done {
		return
	}
	transaction.done = true
	transaction.manager.mu.Unlock()
}
