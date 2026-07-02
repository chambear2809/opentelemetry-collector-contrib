// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"container/list"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultCounterStoreMaxEntries = 100_000
	defaultCounterStoreIdleTTL    = 24 * time.Hour
)

type counterStoreConfig struct {
	maxEntries int
	idleTTL    time.Duration
	now        func() time.Time
}

type counterValueType uint8

const (
	counterValueTypeInt counterValueType = iota
	counterValueTypeDouble
)

type counterSeriesRef struct {
	key       string
	valueType counterValueType
}

type intCounterSeries struct {
	value     int64
	startedAt time.Time
	lastSeen  time.Time
	lru       *list.Element
}

type doubleCounterSeries struct {
	value     float64
	startedAt time.Time
	lastSeen  time.Time
	lru       *list.Element
}

// counterStore tracks cumulative values for Sum metrics across scrapes within a
// single receiver instance. SignalFlow rate()/sum_over_time() expect monotonic
// cumulative counters, so per-scrape delta observations are accumulated here
// and emitted as a running total.
type counterStore struct {
	mu           sync.Mutex
	intValues    map[string]*intCounterSeries
	doubleValues map[string]*doubleCounterSeries
	lru          *list.List
	startedAt    time.Time
	maxEntries   int
	idleTTL      time.Duration
	now          func() time.Time
}

func newCounterStore() *counterStore {
	startedAt := time.Now()
	return newCounterStoreWithConfig(startedAt, counterStoreConfig{})
}

func newCounterStoreAt(startedAt time.Time) *counterStore {
	return newCounterStoreWithConfig(startedAt, counterStoreConfig{now: func() time.Time { return startedAt }})
}

func newCounterStoreWithConfig(startedAt time.Time, cfg counterStoreConfig) *counterStore {
	maxEntries := cfg.maxEntries
	if maxEntries <= 0 {
		maxEntries = defaultCounterStoreMaxEntries
	}
	idleTTL := cfg.idleTTL
	if idleTTL <= 0 {
		idleTTL = defaultCounterStoreIdleTTL
	}
	now := cfg.now
	if now == nil {
		now = time.Now
	}
	return &counterStore{
		intValues:    map[string]*intCounterSeries{},
		doubleValues: map[string]*doubleCounterSeries{},
		lru:          list.New(),
		startedAt:    startedAt,
		maxEntries:   maxEntries,
		idleTTL:      idleTTL,
		now:          now,
	}
}

// AddDouble increments a floating-point counter and returns its cumulative
// total and per-series start time. The resource namespace is required because
// OpenTelemetry resource attributes are part of a time series identity even
// though they are not repeated on each datapoint.
func (s *counterStore) AddDouble(resource, name string, attrs map[string]string, delta float64) (float64, time.Time) {
	if s == nil {
		return delta, time.Time{}
	}
	key := counterKey(resource, name, attrs)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.evictExpiredLocked(now)
	if series := s.doubleValues[key]; series != nil {
		series.value += delta
		series.lastSeen = now
		s.lru.MoveToBack(series.lru)
		return series.value, series.startedAt
	}
	s.makeRoomLocked()
	series := &doubleCounterSeries{value: delta, startedAt: now, lastSeen: now}
	series.lru = s.lru.PushBack(counterSeriesRef{key: key, valueType: counterValueTypeDouble})
	s.doubleValues[key] = series
	return series.value, series.startedAt
}

// AddInt is the integer-preserving counterpart to AddDouble. Counter values often
// exceed float64's exact integer range on busy network devices, so integer
// deltas must never pass through float64 on their way to an OTLP int datapoint.
func (s *counterStore) AddInt(resource, name string, attrs map[string]string, delta int64) (int64, time.Time) {
	if s == nil {
		return delta, time.Time{}
	}
	key := counterKey(resource, name, attrs)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.evictExpiredLocked(now)
	if series := s.intValues[key]; series != nil {
		series.value += delta
		series.lastSeen = now
		s.lru.MoveToBack(series.lru)
		return series.value, series.startedAt
	}
	s.makeRoomLocked()
	series := &intCounterSeries{value: delta, startedAt: now, lastSeen: now}
	series.lru = s.lru.PushBack(counterSeriesRef{key: key, valueType: counterValueTypeInt})
	s.intValues[key] = series
	return series.value, series.startedAt
}

func (s *counterStore) evictExpiredLocked(now time.Time) {
	if s.idleTTL <= 0 {
		return
	}
	cutoff := now.Add(-s.idleTTL)
	for oldest := s.lru.Front(); oldest != nil; oldest = s.lru.Front() {
		ref := oldest.Value.(counterSeriesRef)
		lastSeen := s.seriesLastSeenLocked(ref)
		if lastSeen.After(cutoff) {
			return
		}
		s.removeSeriesLocked(oldest, ref)
	}
}

func (s *counterStore) makeRoomLocked() {
	for s.lru.Len() >= s.maxEntries {
		oldest := s.lru.Front()
		if oldest == nil {
			return
		}
		s.removeSeriesLocked(oldest, oldest.Value.(counterSeriesRef))
	}
}

func (s *counterStore) seriesLastSeenLocked(ref counterSeriesRef) time.Time {
	if ref.valueType == counterValueTypeInt {
		if series := s.intValues[ref.key]; series != nil {
			return series.lastSeen
		}
		return time.Time{}
	}
	if series := s.doubleValues[ref.key]; series != nil {
		return series.lastSeen
	}
	return time.Time{}
}

func (s *counterStore) removeSeriesLocked(element *list.Element, ref counterSeriesRef) {
	if ref.valueType == counterValueTypeInt {
		delete(s.intValues, ref.key)
	} else {
		delete(s.doubleValues, ref.key)
	}
	s.lru.Remove(element)
}

func (s *counterStore) StartTime() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.startedAt
}

func counterKey(resource, name string, attrs map[string]string) string {
	var b strings.Builder
	b.Grow(len(resource) + len(name) + 17*len(attrs))
	b.WriteString(strconv.Quote(resource))
	b.WriteByte('|')
	b.WriteString(name)
	if len(attrs) == 0 {
		return b.String()
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteByte('|')
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strconv.Quote(attrs[k]))
	}
	return b.String()
}
