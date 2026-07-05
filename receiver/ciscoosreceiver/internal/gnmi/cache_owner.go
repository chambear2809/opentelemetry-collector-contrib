// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"

import (
	"errors"
	"fmt"
	"sort"
	"sync/atomic"
)

const (
	maxCacheOwnerIDBytes = 1024

	// Retained objects share the owner string's backing bytes through the owner
	// index, but each object retains its own string header.
	retainedCacheOwnerReferenceBytes int64 = retainedStringHeaderBytes
	// Charge a sparse top-level owner entry and a sparse per-owner item map.
	// Each owner-index item also charges its key backing bytes. Equal string keys
	// in separate Go maps are not guaranteed to share backing storage: tombstone
	// commits reconstruct their path key, and replacement in a primary map may
	// retain the primary map's older equal key.
	retainedCacheOwnerIndexBaseBytes int64 = 2*retainedSparseStringMapBytes + retainedCacheMapEntryBytes
	retainedCacheOwnerIndexItemBytes int64 = retainedCacheMapEntryBytes
)

type cacheOwnerItemKind uint8

const (
	cacheOwnerEntry cacheOwnerItemKind = 1 << iota
	cacheOwnerAtomicBaseline
	cacheOwnerTombstone
)

type cacheOwnerState struct {
	items map[string]cacheOwnerItemKind
}

type cacheOwnerIndexChange struct {
	before cacheOwnerItemKind
	after  cacheOwnerItemKind
}

// cacheOwnerIndexPlan stages sparse owner-index changes while Cache.Prepare
// holds the cache write lock. Applying it is allocation-only and cannot fail,
// so it remains part of the existing atomic commit boundary.
type cacheOwnerIndexPlan struct {
	cache   *Cache
	changes map[string]map[string]cacheOwnerIndexChange
}

func newCacheOwnerIndexPlan(cache *Cache) *cacheOwnerIndexPlan {
	return &cacheOwnerIndexPlan{cache: cache, changes: map[string]map[string]cacheOwnerIndexChange{}}
}

func (p *cacheOwnerIndexPlan) add(ownerID, key string, kind cacheOwnerItemKind) error {
	return p.change(ownerID, key, kind, true)
}

func (p *cacheOwnerIndexPlan) remove(ownerID, key string, kind cacheOwnerItemKind) error {
	return p.change(ownerID, key, kind, false)
}

func (p *cacheOwnerIndexPlan) change(ownerID, key string, kind cacheOwnerItemKind, add bool) error {
	if ownerID == "" {
		return nil
	}
	if err := validateCacheOwnerID(ownerID, false); err != nil {
		return err
	}
	ownerChanges := p.changes[ownerID]
	if ownerChanges == nil {
		ownerChanges = map[string]cacheOwnerIndexChange{}
		p.changes[ownerID] = ownerChanges
	}
	change, changed := ownerChanges[key]
	if !changed {
		if owner := p.cache.owners[ownerID]; owner != nil {
			change.before = owner.items[key]
		}
		change.after = change.before
	}
	if add {
		if change.after&kind != 0 {
			return fmt.Errorf("cache owner %q already indexes item %q kind %d", ownerID, key, kind)
		}
		change.after |= kind
	} else {
		if change.after&kind == 0 {
			return fmt.Errorf("cache owner %q is missing item %q kind %d", ownerID, key, kind)
		}
		change.after &^= kind
	}
	ownerChanges[key] = change
	return nil
}

func (p *cacheOwnerIndexPlan) retainedBytesDelta() (int64, error) {
	var delta int64
	for ownerID, changes := range p.changes {
		beforeCount := 0
		if owner := p.cache.owners[ownerID]; owner != nil {
			beforeCount = len(owner.items)
		}
		afterCount := beforeCount
		var ownerDelta int64
		for key, change := range changes {
			switch {
			case change.before == 0 && change.after != 0:
				afterCount++
				var err error
				ownerDelta, err = addCacheOwnerRetainedBytesDelta(
					ownerDelta,
					estimateCacheOwnerIndexItemRetainedBytes(key),
				)
				if err != nil {
					return 0, err
				}
			case change.before != 0 && change.after == 0:
				afterCount--
				var err error
				ownerDelta, err = addCacheOwnerRetainedBytesDelta(
					ownerDelta,
					-estimateCacheOwnerIndexItemRetainedBytes(key),
				)
				if err != nil {
					return 0, err
				}
			}
		}
		if afterCount < 0 {
			return 0, errors.New("cache owner index count underflow")
		}
		switch {
		case beforeCount == 0 && afterCount > 0:
			var err error
			ownerDelta, err = addCacheOwnerRetainedBytesDelta(
				ownerDelta,
				estimateCacheOwnerIndexBaseRetainedBytes(ownerID),
			)
			if err != nil {
				return 0, err
			}
		case beforeCount > 0 && afterCount == 0:
			var err error
			ownerDelta, err = addCacheOwnerRetainedBytesDelta(
				ownerDelta,
				-estimateCacheOwnerIndexBaseRetainedBytes(ownerID),
			)
			if err != nil {
				return 0, err
			}
		}
		var err error
		delta, err = addCacheOwnerRetainedBytesDelta(delta, ownerDelta)
		if err != nil {
			return 0, err
		}
	}
	return delta, nil
}

func addCacheOwnerRetainedBytesDelta(current, change int64) (int64, error) {
	const (
		maximum = int64(^uint64(0) >> 1)
		minimum = -maximum - 1
	)
	if change > 0 && current > maximum-change {
		return 0, errors.New("cache owner index retained-byte accounting overflow")
	}
	if change < 0 && current < minimum-change {
		return 0, errors.New("cache owner index retained-byte accounting underflow")
	}
	return current + change, nil
}

func (p *cacheOwnerIndexPlan) apply() {
	for ownerID, changes := range p.changes {
		owner := p.cache.owners[ownerID]
		for key, change := range changes {
			if change.after == 0 {
				if owner != nil {
					delete(owner.items, key)
				}
				continue
			}
			if owner == nil {
				owner = &cacheOwnerState{items: map[string]cacheOwnerItemKind{}}
				p.cache.owners[ownerID] = owner
			}
			owner.items[key] = change.after
		}
		if owner != nil && len(owner.items) == 0 {
			delete(p.cache.owners, ownerID)
		}
	}
}

func validateCacheOwnerID(ownerID string, required bool) error {
	if ownerID == "" {
		if required {
			return errors.New("cache owner ID cannot be empty")
		}
		return nil
	}
	if len(ownerID) > maxCacheOwnerIDBytes {
		return fmt.Errorf("cache owner ID exceeds %d bytes", maxCacheOwnerIDBytes)
	}
	return nil
}

func estimateCacheOwnerReferenceRetainedBytes(ownerID string) int64 {
	if ownerID == "" {
		return 0
	}
	return retainedCacheOwnerReferenceBytes
}

func estimateCacheOwnerIndexBaseRetainedBytes(ownerID string) int64 {
	if ownerID == "" {
		return 0
	}
	return saturatingRetainedByteAdd(retainedCacheOwnerIndexBaseBytes, retainedStringBytes(ownerID))
}

func estimateCacheOwnerIndexItemRetainedBytes(key string) int64 {
	return saturatingRetainedByteAdd(retainedCacheOwnerIndexItemBytes, retainedStringBytes(key))
}

func estimateCacheOwnerIndexRetainedBytes(ownerID string, items map[string]cacheOwnerItemKind) int64 {
	if ownerID == "" || len(items) == 0 {
		return 0
	}
	bytes := estimateCacheOwnerIndexBaseRetainedBytes(ownerID)
	for key := range items {
		bytes = saturatingRetainedByteAdd(bytes, estimateCacheOwnerIndexItemRetainedBytes(key))
	}
	return bytes
}

func (c *Cache) ownerIndexRetainedBytesLocked() int64 {
	var retained int64
	for ownerID, owner := range c.owners {
		retained = saturatingRetainedByteAdd(retained, estimateCacheOwnerIndexRetainedBytes(ownerID, owner.items))
	}
	return retained
}

// CacheOwnerResetResult describes state silently removed for one owner.
// Removed is populated only by the explicitly named reconciliation variants;
// counts-only resets avoid materializing retained points at reconnect scale.
type CacheOwnerResetResult struct {
	OwnerID         string
	Removed         []MappedPoint
	Entries         int
	AtomicBaselines int
	Tombstones      int
	RetainedBytes   int64
}

// CacheOwnerResetTransaction owns the cache write lock until Commit or
// Rollback. This lets callers stage dependent receiver state before publishing
// a reconnect reset.
type CacheOwnerResetTransaction struct {
	cache      *Cache
	result     CacheOwnerResetResult
	commitPlan func()
	done       atomic.Bool
}

func (tx *CacheOwnerResetTransaction) Result() CacheOwnerResetResult {
	if tx == nil {
		return CacheOwnerResetResult{}
	}
	return tx.result
}

func (tx *CacheOwnerResetTransaction) Commit() {
	if tx == nil || !tx.done.CompareAndSwap(false, true) {
		return
	}
	defer tx.cache.mu.Unlock()
	if tx.commitPlan != nil {
		tx.commitPlan()
	}
}

func (tx *CacheOwnerResetTransaction) Rollback() {
	if tx == nil || !tx.done.CompareAndSwap(false, true) {
		return
	}
	tx.cache.mu.Unlock()
}

// ResetOwner atomically and silently removes all retained state attributed to
// ownerID. Call PrepareResetOwner when dependent state must join the commit
// boundary.
func (c *Cache) ResetOwner(ownerID string) (CacheOwnerResetResult, error) {
	transaction, err := c.PrepareResetOwner(ownerID)
	return commitCacheOwnerReset(transaction, err)
}

// ResetOwnerForReconciliation atomically and silently removes one owner's
// retained state and materializes stable copies of removed points for a
// receiver-owned derived index. Prefer ResetOwner when reconciliation is not
// required.
func (c *Cache) ResetOwnerForReconciliation(ownerID string) (CacheOwnerResetResult, error) {
	transaction, err := c.PrepareResetOwnerForReconciliation(ownerID)
	return commitCacheOwnerReset(transaction, err)
}

func commitCacheOwnerReset(
	transaction *CacheOwnerResetTransaction,
	err error,
) (CacheOwnerResetResult, error) {
	if err != nil {
		return CacheOwnerResetResult{}, err
	}
	defer transaction.Rollback()
	result := transaction.Result()
	transaction.Commit()
	return result, nil
}

// PrepareResetOwner stages a complete owner reset without publishing it. The
// caller must always call Commit or Rollback.
func (c *Cache) PrepareResetOwner(ownerID string) (*CacheOwnerResetTransaction, error) {
	return c.prepareResetOwner(ownerID, false)
}

// PrepareResetOwnerForReconciliation stages a complete owner reset and
// materializes stable copies of removed points. The caller must always call
// Commit or Rollback. Prefer PrepareResetOwner for counts-only reset callers.
func (c *Cache) PrepareResetOwnerForReconciliation(ownerID string) (*CacheOwnerResetTransaction, error) {
	return c.prepareResetOwner(ownerID, true)
}

func (c *Cache) prepareResetOwner(
	ownerID string,
	materializeRemoved bool,
) (*CacheOwnerResetTransaction, error) {
	if c == nil {
		return nil, errors.New("gNMI state cache cannot be nil")
	}
	if err := validateCacheOwnerID(ownerID, true); err != nil {
		return nil, err
	}
	c.mu.Lock()
	handedOff := false
	defer func() {
		if !handedOff {
			c.mu.Unlock()
		}
	}()

	owner := c.owners[ownerID]
	result := CacheOwnerResetResult{OwnerID: ownerID}
	transaction := &CacheOwnerResetTransaction{cache: c, result: result}
	if owner == nil {
		handedOff = true
		return transaction, nil
	}

	removedBytes := estimateCacheOwnerIndexRetainedBytes(ownerID, owner.items)
	for key, kinds := range owner.items {
		if kinds&cacheOwnerEntry != 0 {
			entry, ok := c.entries[key]
			if !ok || entry.ownerID != ownerID {
				return nil, fmt.Errorf("cache owner %q entry index is inconsistent for %q", ownerID, key)
			}
			result.Entries++
			removedBytes = saturatingRetainedByteAdd(removedBytes, entry.retainedBytes)
		}
		if kinds&cacheOwnerAtomicBaseline != 0 {
			baseline, ok := c.atomic[key]
			if !ok || baseline.ownerID != ownerID {
				return nil, fmt.Errorf("cache owner %q baseline index is inconsistent for %q", ownerID, key)
			}
			result.AtomicBaselines++
			removedBytes = saturatingRetainedByteAdd(removedBytes, baseline.retainedBytes)
		}
		if kinds&cacheOwnerTombstone != 0 {
			tombstone, ok := c.tombstone[key]
			if !ok || tombstone.ownerID != ownerID {
				return nil, fmt.Errorf("cache owner %q tombstone index is inconsistent for %q", ownerID, key)
			}
			result.Tombstones++
			removedBytes = saturatingRetainedByteAdd(removedBytes, tombstone.retainedBytes)
		}
	}
	if removedBytes > c.retainedBytes {
		return nil, errors.New("gNMI state cache retained-byte accounting underflow")
	}
	if materializeRemoved && result.Entries > 0 {
		entryKeys := make([]string, 0, result.Entries)
		for key, kinds := range owner.items {
			if kinds&cacheOwnerEntry != 0 {
				entryKeys = append(entryKeys, key)
			}
		}
		sort.Strings(entryKeys)
		result.Removed = make([]MappedPoint, len(entryKeys))
		for i, key := range entryKeys {
			result.Removed[i] = cloneMappedPoint(c.entries[key].point)
		}
	}
	result.RetainedBytes = removedBytes
	transaction.result = result
	transaction.commitPlan = func() {
		for key, kinds := range owner.items {
			if kinds&cacheOwnerEntry != 0 {
				delete(c.entries, key)
			}
			if kinds&cacheOwnerAtomicBaseline != 0 {
				delete(c.atomic, key)
			}
			if kinds&cacheOwnerTombstone != 0 {
				c.removeTombstone(c.tombstone[key])
			}
		}
		delete(c.owners, ownerID)
		c.retainedBytes -= removedBytes
	}
	handedOff = true
	return transaction, nil
}
