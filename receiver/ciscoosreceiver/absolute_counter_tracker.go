// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

const (
	absoluteCounterMaxSeries = 100_000
	absoluteCounterIdleTTL   = 24 * time.Hour
)

type absoluteCounterValue struct {
	isInt bool
	i     int64
	f     float64
}

func absoluteCounterValueFromDatapoint(dp pmetric.NumberDataPoint) (absoluteCounterValue, bool) {
	if dp.ValueType() == pmetric.NumberDataPointValueTypeInt {
		return absoluteCounterValue{isInt: true, i: dp.IntValue()}, true
	}
	value := dp.DoubleValue()
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return absoluteCounterValue{}, false
	}
	return absoluteCounterValue{f: value}, true
}

func (v absoluteCounterValue) lessThan(other absoluteCounterValue) bool {
	if v.isInt && other.isInt {
		return v.i < other.i
	}
	if !v.isInt && !other.isInt {
		return v.f < other.f
	}
	if v.isInt {
		return new(big.Float).SetInt64(v.i).Cmp(big.NewFloat(other.f)) < 0
	}
	return big.NewFloat(v.f).Cmp(new(big.Float).SetInt64(other.i)) < 0
}

type absoluteCounterEntry struct {
	key        string
	value      absoluteCounterValue
	start      time.Time
	observedAt time.Time
	lastSeen   time.Time
}

type absoluteCounterTracker struct {
	mu      sync.Mutex
	entries map[string]*list.Element
	lru     list.List
}

func newAbsoluteCounterTracker() *absoluteCounterTracker {
	return &absoluteCounterTracker{entries: make(map[string]*list.Element)}
}

func (t *absoluteCounterTracker) observe(key string, value absoluteCounterValue, observedAt, suppliedStart time.Time) time.Time {
	now := time.Now()
	if observedAt.IsZero() {
		observedAt = now
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expireLocked(now.Add(-absoluteCounterIdleTTL))
	if element := t.entries[key]; element != nil {
		entry := element.Value.(*absoluteCounterEntry)
		entry.lastSeen = now
		t.lru.MoveToFront(element)

		// A delayed datapoint belongs to an older counter epoch. It must not
		// reset or otherwise mutate the latest state, and its start timestamp
		// must never be later than the datapoint timestamp.
		if !observedAt.After(entry.observedAt) {
			if !suppliedStart.IsZero() && !suppliedStart.After(observedAt) {
				return suppliedStart
			}
			if !entry.start.After(observedAt) {
				return entry.start
			}
			return observedAt
		}
		if value.lessThan(entry.value) {
			entry.start = observedAt
		} else if !suppliedStart.IsZero() && suppliedStart.After(entry.start) && !suppliedStart.After(observedAt) {
			entry.start = suppliedStart
		}
		entry.value = value
		entry.observedAt = observedAt
		return entry.start
	}

	start := suppliedStart
	if start.IsZero() || start.After(observedAt) {
		start = observedAt
	}
	entry := &absoluteCounterEntry{key: key, value: value, start: start, observedAt: observedAt, lastSeen: now}
	t.entries[key] = t.lru.PushFront(entry)
	for len(t.entries) > absoluteCounterMaxSeries {
		t.removeElementLocked(t.lru.Back())
	}
	return start
}

func (t *absoluteCounterTracker) expireLocked(cutoff time.Time) {
	for element := t.lru.Back(); element != nil; {
		previous := element.Prev()
		entry := element.Value.(*absoluteCounterEntry)
		if !entry.lastSeen.Before(cutoff) {
			break
		}
		t.removeElementLocked(element)
		element = previous
	}
}

func (t *absoluteCounterTracker) removeElementLocked(element *list.Element) {
	if element == nil {
		return
	}
	entry := element.Value.(*absoluteCounterEntry)
	delete(t.entries, entry.key)
	t.lru.Remove(element)
}

func applyAbsoluteCounterStartTimestamps(md pmetric.Metrics, tracker *absoluteCounterTracker) {
	if tracker == nil {
		tracker = newAbsoluteCounterTracker()
	}
	resources := md.ResourceMetrics()
	for i := 0; i < resources.Len(); i++ {
		rm := resources.At(i)
		resourceIdentity := pcommonMapIdentity(rm.Resource().Attributes())
		scopes := rm.ScopeMetrics()
		for j := 0; j < scopes.Len(); j++ {
			sm := scopes.At(j)
			metrics := sm.Metrics()
			for k := 0; k < metrics.Len(); k++ {
				metric := metrics.At(k)
				if metric.Type() != pmetric.MetricTypeSum || !metric.Sum().IsMonotonic() || metric.Sum().AggregationTemporality() != pmetric.AggregationTemporalityCumulative {
					continue
				}
				points := metric.Sum().DataPoints()
				for l := 0; l < points.Len(); l++ {
					dp := points.At(l)
					value, ok := absoluteCounterValueFromDatapoint(dp)
					if !ok {
						continue
					}
					key := absoluteCounterSeriesKey(resourceIdentity, sm.Scope().Name(), metric.Name(), dp.Attributes())
					observedAt := pdataTimestampTime(dp.Timestamp())
					if observedAt.IsZero() {
						observedAt = time.Now()
						dp.SetTimestamp(pcommon.NewTimestampFromTime(observedAt))
					}
					suppliedStart := pdataTimestampTime(dp.StartTimestamp())
					start := tracker.observe(key, value, observedAt, suppliedStart)
					dp.SetStartTimestamp(pcommon.NewTimestampFromTime(start))
				}
			}
		}
	}
}

func pdataTimestampTime(timestamp pcommon.Timestamp) time.Time {
	if timestamp == 0 {
		return time.Time{}
	}
	return timestamp.AsTime()
}

func absoluteCounterSeriesKey(resourceIdentity, scopeName, metricName string, attrs pcommon.Map) string {
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "%s\x00%s\x00%s\x00%s", resourceIdentity, scopeName, metricName, pcommonMapIdentity(attrs))
	return hex.EncodeToString(hash.Sum(nil))
}

func pcommonMapIdentity(attrs pcommon.Map) string {
	keys := make([]string, 0, attrs.Len())
	attrs.Range(func(key string, _ pcommon.Value) bool {
		keys = append(keys, key)
		return true
	})
	sort.Strings(keys)
	var out strings.Builder
	for _, key := range keys {
		value, _ := attrs.Get(key)
		_, _ = fmt.Fprintf(&out, "%d:%s=%d:%s;", len(key), key, value.Type(), value.AsString())
	}
	return out.String()
}

type absoluteCounterTrackingConsumer struct {
	next    consumer.Metrics
	tracker *absoluteCounterTracker
}

func newAbsoluteCounterTrackingConsumer(next consumer.Metrics) consumer.Metrics {
	return &absoluteCounterTrackingConsumer{next: next, tracker: newAbsoluteCounterTracker()}
}

func (*absoluteCounterTrackingConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

func (c *absoluteCounterTrackingConsumer) ConsumeMetrics(ctx context.Context, md pmetric.Metrics) error {
	applyAbsoluteCounterStartTimestamps(md, c.tracker)
	return c.next.ConsumeMetrics(ctx, md)
}
