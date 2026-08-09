// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"errors"
	"fmt"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

// sharedGNMIResponseSelectors converts the exact SubscriptionList scope into
// canonical paths. The configured target identity is deliberately independent
// from the optional gNMI Path.target carried on the wire.
func sharedGNMIResponseSelectors(target string, paths []sharedGNMIPath) ([]internalgnmi.Path, error) {
	if target == "" {
		return nil, errors.New("gNMI response scope target cannot be empty")
	}
	if len(paths) == 0 {
		return nil, errors.New("gNMI response scope has no subscription paths")
	}
	selectors := make([]internalgnmi.Path, 0, len(paths))
	for index := range paths {
		configured := &paths[index]
		path, err := sharedGNMIPathToProto(configured.PathTarget, configured.Origin, configured.Path)
		if err != nil {
			return nil, fmt.Errorf("subscription selector %d is invalid: %w", index, err)
		}
		selector := internalgnmi.PathFromProto(path)
		selector.Target = target
		selectors = append(selectors, selector)
	}
	return selectors, nil
}

// validateSharedGNMIResponseScope rejects any device response that cannot be
// attributed to the SubscriptionList which produced it. Atomic prefixes and
// deletes may be ancestors because gNMI permits a server to report snapshot or
// removal state at a common container. Cache owner isolation confines those
// operations to this SubscriptionList.
func validateSharedGNMIResponseScope(
	selectors []internalgnmi.Path,
	notification internalgnmi.DecodedNotification,
) error {
	if len(selectors) == 0 {
		return errors.New("gNMI response scope has no subscription selectors")
	}
	for index := range notification.Touched {
		if !sharedGNMIResponsePathIsConcrete(notification.Touched[index]) {
			return errors.New("gNMI update contains a wildcard response path")
		}
		if !sharedGNMIPathSelectedByAny(notification.Touched[index], selectors) {
			return errors.New("gNMI update is outside the requested subscription scope")
		}
	}
	for index := range notification.Deletes {
		if !sharedGNMIResponsePathIsConcrete(notification.Deletes[index]) {
			return errors.New("gNMI delete contains a wildcard response path")
		}
		if !sharedGNMIPathOverlapsAny(notification.Deletes[index], selectors) {
			return errors.New("gNMI delete is outside the requested subscription scope")
		}
	}
	if notification.Atomic {
		if !sharedGNMIResponsePathIsConcrete(notification.Prefix) {
			return errors.New("gNMI atomic prefix contains a wildcard response path")
		}
		if !sharedGNMIPathOverlapsAny(notification.Prefix, selectors) {
			return errors.New("gNMI atomic prefix is outside the requested subscription scope")
		}
	}
	if !notification.Atomic && len(notification.Touched) == 0 && len(notification.Deletes) == 0 {
		return errors.New("gNMI notification contains no state operation")
	}
	return nil
}

func sharedGNMIPathSelectedByAny(path internalgnmi.Path, selectors []internalgnmi.Path) bool {
	for index := range selectors {
		if sharedGNMIPathSelected(path, selectors[index]) {
			return true
		}
	}
	return false
}

func sharedGNMIPathOverlapsAny(path internalgnmi.Path, selectors []internalgnmi.Path) bool {
	for index := range selectors {
		if sharedGNMIPathsOverlap(path, selectors[index]) {
			return true
		}
	}
	return false
}

// sharedGNMIPathSelected matches a concrete response path against a configured
// selector. Cisco IOS XE/XR contracts permit the standard whole-element and
// key-value wildcard; NX-OS contracts reject wildcard configuration earlier.
func sharedGNMIPathSelected(path, selector internalgnmi.Path) bool {
	if !sharedGNMIPathScopeEqual(path, selector) || len(path.Elements) < len(selector.Elements) {
		return false
	}
	for index := range selector.Elements {
		if !sharedGNMIPathElementSelected(path.Elements[index], selector.Elements[index]) {
			return false
		}
	}
	return true
}

// sharedGNMIPathsOverlap reports whether a concrete response branch and a
// configured selector share one possible subtree. This admits ancestor delete
// and atomic prefixes without admitting unrelated siblings.
func sharedGNMIPathsOverlap(path, selector internalgnmi.Path) bool {
	if !sharedGNMIPathScopeEqual(path, selector) {
		return false
	}
	common := min(len(path.Elements), len(selector.Elements))
	for index := range common {
		if !sharedGNMIPathElementsOverlap(path.Elements[index], selector.Elements[index]) {
			return false
		}
	}
	return true
}

func sharedGNMIPathScopeEqual(path, selector internalgnmi.Path) bool {
	return path.Target == selector.Target &&
		path.PathTarget == selector.PathTarget &&
		path.Origin == selector.Origin
}

func sharedGNMIPathElementSelected(concrete, selector internalgnmi.PathElem) bool {
	if selector.Name != "*" && concrete.Name != selector.Name {
		return false
	}
	for key, expected := range selector.Keys {
		actual, present := concrete.Keys[key]
		if !present || (expected != "*" && actual != expected) {
			return false
		}
	}
	return true
}

func sharedGNMIPathElementsOverlap(concrete, selector internalgnmi.PathElem) bool {
	if selector.Name != "*" && concrete.Name != selector.Name {
		return false
	}
	for key, expected := range selector.Keys {
		actual, present := concrete.Keys[key]
		if present && expected != "*" && actual != expected {
			return false
		}
	}
	return true
}

func sharedGNMIResponsePathIsConcrete(path internalgnmi.Path) bool {
	if path.PathTarget == "*" || path.Origin == "*" {
		return false
	}
	for index := range path.Elements {
		element := &path.Elements[index]
		if element.Name == "*" {
			return false
		}
		for key, value := range element.Keys {
			if key == "*" || value == "*" {
				return false
			}
		}
	}
	return true
}
