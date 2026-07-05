// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"

import (
	"fmt"
	"sort"
	"time"
)

// cacheSelectorIndex reuses the structural tombstone trie for ephemeral
// notification planning. Every selector is stored at timestamp zero, allowing
// the ancestor lookup to remain allocation-free for concrete retained paths.
type cacheSelectorIndex struct {
	paths *tombstonePrefixIndex
}

func newCacheSelectorIndex() *cacheSelectorIndex {
	return &cacheSelectorIndex{paths: newTombstonePrefixIndex()}
}

func (idx *cacheSelectorIndex) add(path Path) {
	idx.paths.upsert(path.Key(), stateTombstone{path: path, timestamp: time.Time{}})
}

// selects reports whether an indexed selector selects path.
func (idx *cacheSelectorIndex) selects(path Path) bool {
	return idx != nil && idx.paths.isStale(path, time.Time{})
}

type cacheSelectorPlanningBudget struct {
	used int
}

func (budget *cacheSelectorPlanningBudget) consume() bool {
	if budget.used >= maxCachePlanningComparisons {
		return false
	}
	budget.used++
	return true
}

// selectsForPlan mirrors tombstonePrefixIndex.isStale while charging every
// target/origin lookup, path node, and subset-trie edge considered. This keeps
// adversarial partial key combinations from making selector-plan construction
// quadratic before the retained-state planning limit is checked.
func (idx *cacheSelectorIndex) selectsForPlan(path Path, budget *cacheSelectorPlanningBudget) (bool, bool) {
	for _, targetName := range exactAndWildcard(path.Target) {
		for _, pathTarget := range exactAndWildcard(path.PathTarget) {
			if !budget.consume() {
				return false, false
			}
			target := idx.paths.targets[tombstoneScopeKey(targetName, pathTarget)]
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
				selected, complete := cacheSelectorPathSelectsForPlan(root, path.Elements, 0, budget)
				if !complete || selected {
					return selected, complete
				}
			}
		}
	}
	return false, true
}

func cacheSelectorPathSelectsForPlan(
	node *tombstonePathIndexNode,
	elements []PathElem,
	index int,
	budget *cacheSelectorPlanningBudget,
) (bool, bool) {
	if !budget.consume() {
		return false, false
	}
	if node.tombstoneKey != "" {
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
	return cacheSelectorSubsetSelectsForPlan(elementIndex, element.Keys, func(child *tombstonePathIndexNode) (bool, bool) {
		return cacheSelectorPathSelectsForPlan(child, elements, index+1, budget)
	}, budget)
}

func cacheSelectorSubsetSelectsForPlan(
	index *tombstoneElementIndex,
	keys map[string]string,
	visit func(*tombstonePathIndexNode) (bool, bool),
	budget *cacheSelectorPlanningBudget,
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
	return walk(&index.selectors, 0)
}

// overlaps preserves the cache's structural overlap definition: either an
// indexed selector selects path, or path selects an indexed selector.
func (idx *cacheSelectorIndex) overlaps(path Path) bool {
	return idx != nil && (idx.selects(path) || idx.paths.hasSelectedDescendant(path))
}

func (idx *cacheSelectorIndex) selectsForStructuralPlan(
	path Path,
	budget *cacheStructuralPlanningBudget,
) (bool, bool) {
	if idx == nil {
		return false, true
	}
	return idx.paths.isStaleForStructuralPlan(path, time.Time{}, budget)
}

func (idx *cacheSelectorIndex) overlapsForStructuralPlan(
	path Path,
	budget *cacheStructuralPlanningBudget,
) (bool, bool) {
	if idx == nil {
		return false, true
	}
	selected, complete := idx.selectsForStructuralPlan(path, budget)
	if !complete || selected {
		return selected, complete
	}
	return idx.paths.hasSelectedDescendantForStructuralPlan(path, budget)
}

func (idx *cacheSelectorIndex) hasSelectedPathForStructuralPlan(
	path Path,
	budget *cacheStructuralPlanningBudget,
) (bool, bool) {
	if idx == nil {
		return false, true
	}
	return idx.paths.hasSelectedDescendantForStructuralPlan(path, budget)
}

type cacheSelectorPlan struct {
	selectors []Path
	index     *cacheSelectorIndex
}

// buildCacheSelectorPlan orders broad selectors first, then drops exact
// duplicates and descendants already covered by an earlier selector. All
// selectors in one notification share its timestamp, so this collapse retains
// delete and tombstone semantics while bounding subsequent work.
func buildCacheSelectorPlan(paths []Path) (cacheSelectorPlan, error) {
	if len(paths) == 0 {
		return cacheSelectorPlan{}, nil
	}
	type candidate struct {
		path Path
		keys int
	}
	ordered := make([]candidate, len(paths))
	for index := range paths {
		ordered[index].path = paths[index]
		for _, element := range paths[index].Elements {
			ordered[index].keys += len(element.Keys)
		}
	}
	sort.SliceStable(ordered, func(left, right int) bool {
		leftPath, rightPath := ordered[left].path, ordered[right].path
		if len(leftPath.Elements) != len(rightPath.Elements) {
			return len(leftPath.Elements) < len(rightPath.Elements)
		}
		if (leftPath.Target == "") != (rightPath.Target == "") {
			return leftPath.Target == ""
		}
		if (leftPath.PathTarget == "") != (rightPath.PathTarget == "") {
			return leftPath.PathTarget == ""
		}
		if (leftPath.Origin == "") != (rightPath.Origin == "") {
			return leftPath.Origin == ""
		}
		return ordered[left].keys < ordered[right].keys
	})
	index := newCacheSelectorIndex()
	selectors := make([]Path, 0, len(ordered))
	budget := &cacheSelectorPlanningBudget{}
	for _, item := range ordered {
		selected, complete := index.selectsForPlan(item.path, budget)
		if !complete {
			return cacheSelectorPlan{}, fmt.Errorf(
				"cache selector planning work exceeds %d comparisons",
				maxCachePlanningComparisons,
			)
		}
		if selected {
			continue
		}
		selectors = append(selectors, item.path)
		index.add(item.path)
	}
	return cacheSelectorPlan{selectors: selectors, index: index}, nil
}

func buildCachePathIndex(paths []Path) *cacheSelectorIndex {
	if len(paths) == 0 {
		return nil
	}
	index := newCacheSelectorIndex()
	for pathIndex := range paths {
		index.add(paths[pathIndex])
	}
	return index
}

func buildCacheUpdateIndex(updates []MappedPoint) *cacheSelectorIndex {
	if len(updates) == 0 {
		return nil
	}
	index := newCacheSelectorIndex()
	for pointIndex := range updates {
		index.add(updates[pointIndex].Source.Path())
	}
	return index
}
