// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"

import "time"

// cacheStructuralPlanningBudget bounds the work performed after the cheap
// retained-state cross-product preflight. The preflight counts logical pairs;
// this budget counts the actual path and trie nodes visited while resolving
// those pairs.
type cacheStructuralPlanningBudget struct {
	used    int
	maximum int
}

func (budget *cacheStructuralPlanningBudget) consume() bool {
	if budget == nil || budget.maximum <= 0 || budget.used >= budget.maximum {
		return false
	}
	budget.used++
	return true
}

func (budget *cacheStructuralPlanningBudget) consumePath(path Path) bool {
	if !budget.consume() { // target
		return false
	}
	if !budget.consume() { // origin
		return false
	}
	for _, element := range path.Elements {
		if !budget.consume() { // path element
			return false
		}
		for range element.Keys {
			if !budget.consume() { // key/value constraint
				return false
			}
		}
	}
	return true
}

func (budget *cacheStructuralPlanningBudget) consumeSeriesPath(series Series) bool {
	if !budget.consume() { // target
		return false
	}
	if !budget.consume() { // origin
		return false
	}
	for _, element := range series.Elements {
		if !budget.consume() { // path element
			return false
		}
		for range element.Keys {
			if !budget.consume() { // key/value constraint
				return false
			}
		}
	}
	return budget.consume() // leaf element
}

// seriesPathForStructuralPlan creates a read-only path view after charging
// every source element and key visited to materialize it. Key maps remain
// shared with the immutable series snapshot; planning never mutates them.
func seriesPathForStructuralPlan(
	series Series,
	budget *cacheStructuralPlanningBudget,
) (Path, bool) {
	if !budget.consumeSeriesPath(series) {
		return Path{}, false
	}
	elements := make([]PathElem, len(series.Elements)+1)
	copy(elements, series.Elements)
	elements[len(series.Elements)] = PathElem{Name: series.Leaf}
	return Path{Target: series.Target, Origin: series.Origin, Elements: elements}, true
}

func (idx *tombstonePrefixIndex) isStaleForStructuralPlan(
	path Path,
	timestamp time.Time,
	budget *cacheStructuralPlanningBudget,
) (bool, bool) {
	for _, targetName := range exactAndWildcard(path.Target) {
		if !budget.consume() {
			return false, false
		}
		target := idx.targets[targetName]
		if target == nil {
			continue
		}
		for _, origin := range exactAndWildcard(path.Origin) {
			if !budget.consume() {
				return false, false
			}
			root := target.origins[origin]
			if root == nil {
				continue
			}
			stale, complete := root.isStaleForStructuralPlan(path.Elements, 0, timestamp, budget)
			if !complete || stale {
				return stale, complete
			}
		}
	}
	return false, true
}

func (node *tombstonePathIndexNode) isStaleForStructuralPlan(
	elements []PathElem,
	index int,
	timestamp time.Time,
	budget *cacheStructuralPlanningBudget,
) (bool, bool) {
	if !budget.consume() {
		return false, false
	}
	if node.tombstoneKey != "" && !timestamp.After(node.tombstoneTimestamp) {
		return true, true
	}
	if index == len(elements) {
		return false, true
	}
	element := elements[index]
	if !budget.consume() {
		return false, false
	}
	elementIndex := node.children[element.Name]
	if elementIndex == nil {
		return false, true
	}
	return elementIndex.forEachSubsetForStructuralPlan(
		element.Keys,
		func(child *tombstonePathIndexNode) (bool, bool) {
			return child.isStaleForStructuralPlan(elements, index+1, timestamp, budget)
		},
		budget,
	)
}

func (idx *tombstoneElementIndex) forEachSubsetForStructuralPlan(
	keys map[string]string,
	visit func(*tombstonePathIndexNode) (bool, bool),
	budget *cacheStructuralPlanningBudget,
) (bool, bool) {
	ordered := sortedTombstoneKeys(keys)
	var walk func(*tombstoneKeyIndexNode, int) (bool, bool)
	walk = func(node *tombstoneKeyIndexNode, start int) (bool, bool) {
		if !budget.consume() {
			return false, false
		}
		if node.path != nil {
			selected, complete := visit(node.path)
			if !complete || selected {
				return selected, complete
			}
		}
		for keyIndex := start; keyIndex < len(ordered); keyIndex++ {
			if !budget.consume() {
				return false, false
			}
			key := ordered[keyIndex]
			if child := node.children[key][keys[key]]; child != nil {
				selected, complete := walk(child, keyIndex+1)
				if !complete || selected {
					return selected, complete
				}
			}
		}
		return false, true
	}
	return walk(&idx.selectors, 0)
}

func (idx *tombstonePrefixIndex) dominatedForStructuralPlan(
	selector Path,
	timestamp time.Time,
	budget *cacheStructuralPlanningBudget,
) (map[string]struct{}, bool) {
	dominated := map[string]struct{}{}
	if !budget.consume() {
		return nil, false
	}
	target := idx.targets[selector.Target]
	if target == nil {
		return dominated, true
	}
	visit := func(node *tombstonePathIndexNode) bool {
		return node.collectForStructuralPlan(timestamp, dominated, budget)
	}
	if selector.Origin != "" {
		if !budget.consume() {
			return nil, false
		}
		root := target.origins[selector.Origin]
		if root == nil {
			return dominated, true
		}
		if !root.forEachSelectedDescendantForStructuralPlan(selector.Elements, 0, visit, budget) {
			return nil, false
		}
		return dominated, true
	}
	for _, root := range target.origins {
		if !budget.consume() || !root.forEachSelectedDescendantForStructuralPlan(selector.Elements, 0, visit, budget) {
			return nil, false
		}
	}
	return dominated, true
}

func (node *tombstonePathIndexNode) forEachSelectedDescendantForStructuralPlan(
	elements []PathElem,
	index int,
	visit func(*tombstonePathIndexNode) bool,
	budget *cacheStructuralPlanningBudget,
) bool {
	if !budget.consume() {
		return false
	}
	if index == len(elements) {
		return visit(node)
	}
	element := elements[index]
	if !budget.consume() {
		return false
	}
	elementIndex := node.children[element.Name]
	if elementIndex == nil {
		return true
	}
	_, complete := elementIndex.forEachSupersetForStructuralPlan(
		element.Keys,
		func(child *tombstonePathIndexNode) (bool, bool) {
			return false, child.forEachSelectedDescendantForStructuralPlan(elements, index+1, visit, budget)
		},
		budget,
	)
	return complete
}

func (node *tombstonePathIndexNode) collectForStructuralPlan(
	timestamp time.Time,
	out map[string]struct{},
	budget *cacheStructuralPlanningBudget,
) bool {
	if !budget.consume() {
		return false
	}
	if node.tombstoneKey != "" && !node.tombstoneTimestamp.After(timestamp) {
		out[node.tombstoneKey] = struct{}{}
	}
	for _, elementIndex := range node.children {
		if !budget.consume() {
			return false
		}
		if !elementIndex.forEachPathForStructuralPlan(func(child *tombstonePathIndexNode) bool {
			return child.collectForStructuralPlan(timestamp, out, budget)
		}, budget) {
			return false
		}
	}
	return true
}

func (idx *tombstonePrefixIndex) hasSelectedDescendantForStructuralPlan(
	selector Path,
	budget *cacheStructuralPlanningBudget,
) (bool, bool) {
	visitTarget := func(target *tombstoneTargetIndex) (bool, bool) {
		if selector.Origin != "" {
			if !budget.consume() {
				return false, false
			}
			root := target.origins[selector.Origin]
			if root == nil {
				return false, true
			}
			return root.hasSelectedDescendantForStructuralPlan(selector.Elements, 0, budget)
		}
		for _, root := range target.origins {
			if !budget.consume() {
				return false, false
			}
			found, complete := root.hasSelectedDescendantForStructuralPlan(selector.Elements, 0, budget)
			if !complete || found {
				return found, complete
			}
		}
		return false, true
	}
	if selector.Target != "" {
		if !budget.consume() {
			return false, false
		}
		target := idx.targets[selector.Target]
		if target == nil {
			return false, true
		}
		return visitTarget(target)
	}
	for _, target := range idx.targets {
		if !budget.consume() {
			return false, false
		}
		found, complete := visitTarget(target)
		if !complete || found {
			return found, complete
		}
	}
	return false, true
}

func (node *tombstonePathIndexNode) hasSelectedDescendantForStructuralPlan(
	elements []PathElem,
	index int,
	budget *cacheStructuralPlanningBudget,
) (bool, bool) {
	if !budget.consume() {
		return false, false
	}
	if index == len(elements) {
		return node.hasTombstoneDescendantForStructuralPlan(budget)
	}
	element := elements[index]
	if !budget.consume() {
		return false, false
	}
	elementIndex := node.children[element.Name]
	if elementIndex == nil {
		return false, true
	}
	return elementIndex.forEachSupersetForStructuralPlan(
		element.Keys,
		func(child *tombstonePathIndexNode) (bool, bool) {
			return child.hasSelectedDescendantForStructuralPlan(elements, index+1, budget)
		},
		budget,
	)
}

func (node *tombstonePathIndexNode) hasTombstoneDescendantForStructuralPlan(
	budget *cacheStructuralPlanningBudget,
) (bool, bool) {
	if !budget.consume() {
		return false, false
	}
	if node.tombstoneKey != "" {
		return true, true
	}
	for _, elementIndex := range node.children {
		if !budget.consume() {
			return false, false
		}
		found, complete := elementIndex.forEachPathForStructuralPlanResult(
			func(child *tombstonePathIndexNode) (bool, bool) {
				return child.hasTombstoneDescendantForStructuralPlan(budget)
			},
			budget,
		)
		if !complete || found {
			return found, complete
		}
	}
	return false, true
}

func (idx *tombstoneElementIndex) forEachSupersetForStructuralPlan(
	keys map[string]string,
	visit func(*tombstonePathIndexNode) (bool, bool),
	budget *cacheStructuralPlanningBudget,
) (bool, bool) {
	ordered := sortedTombstoneKeys(keys)
	var walk func(*tombstoneKeyIndexNode, int) (bool, bool)
	walk = func(node *tombstoneKeyIndexNode, required int) (bool, bool) {
		if !budget.consume() {
			return false, false
		}
		if required == len(ordered) && node.path != nil {
			found, complete := visit(node.path)
			if !complete || found {
				return found, complete
			}
		}
		for key, values := range node.children {
			if !budget.consume() {
				return false, false
			}
			if required == len(ordered) || key < ordered[required] {
				for _, child := range values {
					if !budget.consume() {
						return false, false
					}
					found, complete := walk(child, required)
					if !complete || found {
						return found, complete
					}
				}
				continue
			}
			if key != ordered[required] {
				continue
			}
			if !budget.consume() {
				return false, false
			}
			if child := values[keys[key]]; child != nil {
				found, complete := walk(child, required+1)
				if !complete || found {
					return found, complete
				}
			}
		}
		return false, true
	}
	return walk(&idx.selectors, 0)
}

func (idx *tombstoneElementIndex) forEachPathForStructuralPlan(
	visit func(*tombstonePathIndexNode) bool,
	budget *cacheStructuralPlanningBudget,
) bool {
	_, complete := idx.forEachPathForStructuralPlanResult(func(node *tombstonePathIndexNode) (bool, bool) {
		return false, visit(node)
	}, budget)
	return complete
}

func (idx *tombstoneElementIndex) forEachPathForStructuralPlanResult(
	visit func(*tombstonePathIndexNode) (bool, bool),
	budget *cacheStructuralPlanningBudget,
) (bool, bool) {
	var walk func(*tombstoneKeyIndexNode) (bool, bool)
	walk = func(node *tombstoneKeyIndexNode) (bool, bool) {
		if !budget.consume() {
			return false, false
		}
		if node.path != nil {
			found, complete := visit(node.path)
			if !complete || found {
				return found, complete
			}
		}
		for _, values := range node.children {
			if !budget.consume() {
				return false, false
			}
			for _, child := range values {
				if !budget.consume() {
					return false, false
				}
				found, complete := walk(child)
				if !complete || found {
					return found, complete
				}
			}
		}
		return false, true
	}
	return walk(&idx.selectors)
}

func pathHasPrefixForStructuralPlan(
	path Path,
	selector Path,
	budget *cacheStructuralPlanningBudget,
) (bool, bool) {
	if !budget.consume() {
		return false, false
	}
	if selector.Target != "" && path.Target != selector.Target {
		return false, true
	}
	if !budget.consume() {
		return false, false
	}
	if selector.Origin != "" && path.Origin != selector.Origin {
		return false, true
	}
	if !budget.consume() {
		return false, false
	}
	if len(selector.Elements) > len(path.Elements) {
		return false, true
	}
	for index, want := range selector.Elements {
		if !budget.consume() {
			return false, false
		}
		got := path.Elements[index]
		if got.Name != want.Name {
			return false, true
		}
		for key, value := range want.Keys {
			if !budget.consume() {
				return false, false
			}
			if got.Keys[key] != value {
				return false, true
			}
		}
	}
	return true, true
}
