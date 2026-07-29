// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"

import (
	"slices"
	"sort"
	"strings"
	"time"
)

// tombstonePrefixIndex is a structural index for authoritative removal
// tombstones and equal-admitting semantic-invalidation watermarks. Configured
// subscription owner, target, gNMI path target, and origin form the first four
// logical levels. Path elements are indexed by name and then by their sorted
// key constraints, which lets lookups follow only selector key sets that are
// subsets of the concrete update path.
type tombstonePrefixIndex struct {
	targets map[string]*tombstoneTargetIndex
}

type tombstoneTargetIndex struct {
	target     string
	pathTarget string
	origins    map[string]*tombstonePathIndexNode
}

type tombstonePathIndexNode struct {
	tombstoneKey        string
	tombstoneTimestamp  time.Time
	tombstoneAllowEqual bool
	children            map[string]*tombstoneElementIndex
}

type tombstoneElementIndex struct {
	selectors tombstoneKeyIndexNode
}

// tombstoneKeyIndexNode is a trie of sorted key=value constraints. path is set
// only when the constraints consumed to reach this node describe a complete
// PathElem selector.
type tombstoneKeyIndexNode struct {
	path     *tombstonePathIndexNode
	children map[string]map[string]*tombstoneKeyIndexNode
}

func newTombstonePrefixIndex() *tombstonePrefixIndex {
	return &tombstonePrefixIndex{
		targets: map[string]*tombstoneTargetIndex{},
	}
}

func (idx *tombstonePrefixIndex) upsert(key string, tombstone stateTombstone) {
	scopeKey := tombstoneOwnerScopeKey(tombstone.ownerID, tombstone.path.Target, tombstone.path.PathTarget)
	target := idx.targets[scopeKey]
	if target == nil {
		target = &tombstoneTargetIndex{
			target: tombstone.path.Target, pathTarget: tombstone.path.PathTarget,
			origins: map[string]*tombstonePathIndexNode{},
		}
		idx.targets[scopeKey] = target
	}
	node := target.origins[tombstone.path.Origin]
	if node == nil {
		node = &tombstonePathIndexNode{}
		target.origins[tombstone.path.Origin] = node
	}
	for _, element := range tombstone.path.Elements {
		if node.children == nil {
			node.children = map[string]*tombstoneElementIndex{}
		}
		elementIndex := node.children[element.Name]
		if elementIndex == nil {
			elementIndex = &tombstoneElementIndex{}
			node.children[element.Name] = elementIndex
		}
		node = elementIndex.exactPath(element.Keys, true)
	}
	node.tombstoneKey = key
	node.tombstoneTimestamp = tombstone.timestamp
	node.tombstoneAllowEqual = tombstone.allowEqual
}

func (idx *tombstonePrefixIndex) remove(key string, path Path) {
	idx.removeForOwner("", key, path)
}

func (idx *tombstonePrefixIndex) removeForOwner(ownerID, key string, path Path) {
	scopeKey := tombstoneOwnerScopeKey(ownerID, path.Target, path.PathTarget)
	target := idx.targets[scopeKey]
	if target == nil {
		return
	}
	root := target.origins[path.Origin]
	if root == nil {
		return
	}
	removeTombstonePath(root, path.Elements, 0, key)
	if root.empty() {
		delete(target.origins, path.Origin)
	}
	if len(target.origins) == 0 {
		delete(idx.targets, scopeKey)
	}
}

func removeTombstonePath(node *tombstonePathIndexNode, elements []PathElem, index int, key string) {
	if index == len(elements) {
		if node.tombstoneKey == key {
			node.tombstoneKey = ""
			node.tombstoneTimestamp = time.Time{}
			node.tombstoneAllowEqual = false
		}
		return
	}
	element := elements[index]
	elementIndex := node.children[element.Name]
	if elementIndex == nil {
		return
	}
	child := elementIndex.exactPath(element.Keys, false)
	if child == nil {
		return
	}
	removeTombstonePath(child, elements, index+1, key)
	if child.empty() {
		elementIndex.removeExact(element.Keys)
	}
	if elementIndex.empty() {
		delete(node.children, element.Name)
		if len(node.children) == 0 {
			node.children = nil
		}
	}
}

func (idx *tombstonePrefixIndex) isStale(path Path, timestamp time.Time) bool {
	return idx.isStaleForOwner("", path, timestamp)
}

func (idx *tombstonePrefixIndex) isStaleForOwner(ownerID string, path Path, timestamp time.Time) bool {
	for _, targetName := range exactAndWildcard(path.Target) {
		for _, pathTarget := range exactAndWildcard(path.PathTarget) {
			target := idx.targets[tombstoneOwnerScopeKey(ownerID, targetName, pathTarget)]
			if target == nil {
				continue
			}
			for _, origin := range exactAndWildcard(path.Origin) {
				if root := target.origins[origin]; root != nil && root.isStale(path.Elements, 0, timestamp) {
					return true
				}
			}
		}
	}
	return false
}

func (node *tombstonePathIndexNode) isStale(elements []PathElem, index int, timestamp time.Time) bool {
	if node.tombstoneKey != "" && stateBarrierRejects(node.tombstoneTimestamp, node.tombstoneAllowEqual, timestamp) {
		return true
	}
	if index == len(elements) {
		return false
	}
	element := elements[index]
	elementIndex := node.children[element.Name]
	if elementIndex == nil {
		return false
	}
	return elementIndex.forEachSubset(element.Keys, func(child *tombstonePathIndexNode) bool {
		return child.isStale(elements, index+1, timestamp)
	})
}

func stateBarrierRejects(barrier time.Time, allowEqual bool, candidate time.Time) bool {
	return candidate.Before(barrier) || (!allowEqual && candidate.Equal(barrier))
}

// dominated returns only tombstones whose paths are selected by selector and
// whose timestamps are no newer than timestamp. Traversal starts in the
// selector's target scope and never visits sibling targets. An empty target is
// retained as its own wildcard root rather than expanded across every target;
// the wildcard still participates in lookups, while pruning remains local.
func (idx *tombstonePrefixIndex) dominated(selector Path, timestamp time.Time) map[string]struct{} {
	return idx.dominatedForOwner("", selector, timestamp)
}

func (idx *tombstonePrefixIndex) dominatedForOwner(ownerID string, selector Path, timestamp time.Time) map[string]struct{} {
	dominated := map[string]struct{}{}
	visit := func(node *tombstonePathIndexNode) {
		node.collect(timestamp, dominated)
	}
	for _, target := range idx.descendantTargetsForOwner(ownerID, selector.Target, selector.PathTarget) {
		for _, root := range descendantOrigins(target, selector.Origin) {
			root.forEachSelectedDescendant(selector.Elements, 0, visit)
		}
	}
	return dominated
}

// hasSelectedDescendant reports whether selector selects at least one indexed
// path. Unlike tombstone pruning, an empty target or origin expands across all
// indexed scopes so this also preserves Path.HasPrefix wildcard semantics for
// temporary notification selector indexes.
func (idx *tombstonePrefixIndex) hasSelectedDescendant(selector Path) bool {
	targets := make([]*tombstoneTargetIndex, 0, len(idx.targets))
	for _, target := range idx.targets {
		if selector.Target != "" && target.target != selector.Target {
			continue
		}
		if selector.PathTarget != "" && target.pathTarget != selector.PathTarget {
			continue
		}
		targets = append(targets, target)
	}
	for _, target := range targets {
		if selector.Origin != "" {
			if root := target.origins[selector.Origin]; root != nil && root.hasSelectedDescendant(selector.Elements, 0) {
				return true
			}
			continue
		}
		for _, root := range target.origins {
			if root.hasSelectedDescendant(selector.Elements, 0) {
				return true
			}
		}
	}
	return false
}

func (node *tombstonePathIndexNode) hasSelectedDescendant(elements []PathElem, index int) bool {
	if index == len(elements) {
		return node.hasTombstoneDescendant()
	}
	element := elements[index]
	elementIndex := node.children[element.Name]
	if elementIndex == nil {
		return false
	}
	return elementIndex.forEachSuperset(element.Keys, func(child *tombstonePathIndexNode) bool {
		return child.hasSelectedDescendant(elements, index+1)
	})
}

func (node *tombstonePathIndexNode) hasTombstoneDescendant() bool {
	if node.tombstoneKey != "" {
		return true
	}
	for _, elementIndex := range node.children {
		if elementIndex.forEachPath(func(child *tombstonePathIndexNode) bool {
			return child.hasTombstoneDescendant()
		}) {
			return true
		}
	}
	return false
}

func (node *tombstonePathIndexNode) forEachSelectedDescendant(
	elements []PathElem,
	index int,
	visit func(*tombstonePathIndexNode),
) {
	if index == len(elements) {
		visit(node)
		return
	}
	element := elements[index]
	elementIndex := node.children[element.Name]
	if elementIndex == nil {
		return
	}
	elementIndex.forEachSuperset(element.Keys, func(child *tombstonePathIndexNode) bool {
		child.forEachSelectedDescendant(elements, index+1, visit)
		return false
	})
}

func (node *tombstonePathIndexNode) collect(timestamp time.Time, out map[string]struct{}) {
	if node.tombstoneKey != "" && !node.tombstoneTimestamp.After(timestamp) {
		out[node.tombstoneKey] = struct{}{}
	}
	for _, elementIndex := range node.children {
		elementIndex.forEachPath(func(child *tombstonePathIndexNode) bool {
			child.collect(timestamp, out)
			return false
		})
	}
}

func (idx *tombstonePrefixIndex) descendantTargetsForOwner(ownerID, target, pathTarget string) []*tombstoneTargetIndex {
	if selected := idx.targets[tombstoneOwnerScopeKey(ownerID, target, pathTarget)]; selected != nil {
		return []*tombstoneTargetIndex{selected}
	}
	return nil
}

func tombstoneScopeKey(target, pathTarget string) string {
	return tombstoneOwnerScopeKey("", target, pathTarget)
}

func tombstoneOwnerScopeKey(ownerID, target, pathTarget string) string {
	var key strings.Builder
	if ownerID != "" {
		appendKeyPart(&key, ownerID)
	}
	appendKeyPart(&key, target)
	appendKeyPart(&key, pathTarget)
	return key.String()
}

func descendantOrigins(target *tombstoneTargetIndex, origin string) []*tombstonePathIndexNode {
	if origin != "" {
		if selected := target.origins[origin]; selected != nil {
			return []*tombstonePathIndexNode{selected}
		}
		return nil
	}
	out := make([]*tombstonePathIndexNode, 0, len(target.origins))
	for _, selected := range target.origins {
		out = append(out, selected)
	}
	return out
}

func exactAndWildcard(value string) []string {
	if value == "" {
		return []string{""}
	}
	return []string{value, ""}
}

func (node *tombstonePathIndexNode) empty() bool {
	return node.tombstoneKey == "" && len(node.children) == 0
}

func (idx *tombstoneElementIndex) exactPath(keys map[string]string, create bool) *tombstonePathIndexNode {
	node := &idx.selectors
	for _, key := range sortedTombstoneKeys(keys) {
		values := node.children[key]
		if values == nil {
			if !create {
				return nil
			}
			if node.children == nil {
				node.children = map[string]map[string]*tombstoneKeyIndexNode{}
			}
			values = map[string]*tombstoneKeyIndexNode{}
			node.children[key] = values
		}
		child := values[keys[key]]
		if child == nil {
			if !create {
				return nil
			}
			child = &tombstoneKeyIndexNode{}
			values[keys[key]] = child
		}
		node = child
	}
	if node.path == nil && create {
		node.path = &tombstonePathIndexNode{}
	}
	return node.path
}

func (idx *tombstoneElementIndex) removeExact(keys map[string]string) {
	type frame struct {
		parent *tombstoneKeyIndexNode
		key    string
		value  string
		child  *tombstoneKeyIndexNode
	}
	node := &idx.selectors
	frames := make([]frame, 0, len(keys))
	for _, key := range sortedTombstoneKeys(keys) {
		values := node.children[key]
		if values == nil || values[keys[key]] == nil {
			return
		}
		child := values[keys[key]]
		frames = append(frames, frame{parent: node, key: key, value: keys[key], child: child})
		node = child
	}
	node.path = nil
	for index := range slices.Backward(frames) {
		current := frames[index]
		if current.child.path != nil || len(current.child.children) > 0 {
			break
		}
		values := current.parent.children[current.key]
		delete(values, current.value)
		if len(values) == 0 {
			delete(current.parent.children, current.key)
		}
		if len(current.parent.children) == 0 {
			current.parent.children = nil
		}
	}
}

func (idx *tombstoneElementIndex) empty() bool {
	return idx.selectors.path == nil && len(idx.selectors.children) == 0
}

func (idx *tombstoneElementIndex) forEachSubset(keys map[string]string, visit func(*tombstonePathIndexNode) bool) bool {
	ordered := sortedTombstoneKeys(keys)
	var walk func(*tombstoneKeyIndexNode, int) bool
	walk = func(node *tombstoneKeyIndexNode, start int) bool {
		if node.path != nil && visit(node.path) {
			return true
		}
		for index := start; index < len(ordered); index++ {
			key := ordered[index]
			if child := node.children[key][keys[key]]; child != nil && walk(child, index+1) {
				return true
			}
		}
		return false
	}
	return walk(&idx.selectors, 0)
}

func (idx *tombstoneElementIndex) forEachSuperset(keys map[string]string, visit func(*tombstonePathIndexNode) bool) bool {
	ordered := sortedTombstoneKeys(keys)
	var walk func(*tombstoneKeyIndexNode, int) bool
	walk = func(node *tombstoneKeyIndexNode, required int) bool {
		if required == len(ordered) && node.path != nil && visit(node.path) {
			return true
		}
		for key, values := range node.children {
			if required == len(ordered) || key < ordered[required] {
				for _, child := range values {
					if walk(child, required) {
						return true
					}
				}
				continue
			}
			if key != ordered[required] {
				continue
			}
			if child := values[keys[key]]; child != nil && walk(child, required+1) {
				return true
			}
		}
		return false
	}
	return walk(&idx.selectors, 0)
}

func (idx *tombstoneElementIndex) forEachPath(visit func(*tombstonePathIndexNode) bool) bool {
	var walk func(*tombstoneKeyIndexNode) bool
	walk = func(node *tombstoneKeyIndexNode) bool {
		if node.path != nil && visit(node.path) {
			return true
		}
		for _, values := range node.children {
			for _, child := range values {
				if walk(child) {
					return true
				}
			}
		}
		return false
	}
	return walk(&idx.selectors)
}

func sortedTombstoneKeys(keys map[string]string) []string {
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	return ordered
}
