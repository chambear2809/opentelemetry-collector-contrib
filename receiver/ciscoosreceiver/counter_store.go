// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"sort"
	"strconv"
	"strings"
	"sync"
)

// counterStore tracks cumulative values for Sum metrics across scrapes within a
// single receiver instance. SignalFlow rate()/sum_over_time() expect monotonic
// cumulative counters, so per-scrape delta observations are accumulated here
// and emitted as a running total.
type counterStore struct {
	mu     sync.Mutex
	values map[string]float64
}

func newCounterStore() *counterStore {
	return &counterStore{values: map[string]float64{}}
}

// Add increments the counter identified by (name, attrs) by delta and returns
// the new cumulative value. attrs is canonicalized so attribute ordering does
// not split a single logical series.
func (s *counterStore) Add(name string, attrs map[string]string, delta float64) float64 {
	if s == nil {
		return delta
	}
	key := counterKey(name, attrs)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[key] += delta
	return s.values[key]
}

func counterKey(name string, attrs map[string]string) string {
	if len(attrs) == 0 {
		return name
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.Grow(len(name) + 16*len(attrs))
	b.WriteString(name)
	for _, k := range keys {
		b.WriteByte('|')
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strconv.Quote(attrs[k]))
	}
	return b.String()
}
