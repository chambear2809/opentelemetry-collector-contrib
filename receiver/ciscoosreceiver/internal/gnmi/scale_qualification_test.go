// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	gnmiScaleQualificationEnv = "CISCOOS_GNMI_RUN_SCALE_QUALIFICATION"

	scaleVCPUs              = 4
	scaleTargetCount        = 100
	scalePortsPerTarget     = 50
	scalePortCount          = scaleTargetCount * scalePortsPerTarget
	scaleLanesPerPort       = 8
	scalePortMetricCount    = 2
	scaleLaneMetricCount    = 11
	scaleCatalogPortMetrics = 4
	scaleCatalogLaneMetrics = 12
	scaleSeriesPerPort      = scalePortMetricCount + scaleLanesPerPort*scaleLaneMetricCount
	scaleActiveSeries       = scalePortCount * scaleSeriesPerPort
	scaleActivePerTarget    = scalePortsPerTarget * scaleSeriesPerPort
	scaleStateCapacity      = 500_000
	scaleCapacityPerTarget  = scaleStateCapacity / scaleTargetCount
	scaleDeleteBarriers     = 25_000
	scaleDeletesPerTarget   = scaleDeleteBarriers / scaleTargetCount
	scaleInvalidations      = scaleStateCapacity - scaleActiveSeries - scaleDeleteBarriers
	scaleInvalidatesTarget  = scaleInvalidations / scaleTargetCount
	scaleIntervalPoints     = 16_700
	scaleIntervalPerTarget  = scaleIntervalPoints / scaleTargetCount
	scaleCacheApplyBatch    = 10_000
	scaleDatapointsPerChunk = 10_000

	scaleIntervalLatencyLimit = 5 * time.Second
	scaleIntervalCadence      = time.Second
	scaleRSSLimitBytes        = uint64(32 * 1024 * 1024 * 1024 / 10) // 3.2 GiB.
)

// TestInternalGNMIScaleQualification_100Targets5000Ports500KStateCapacity is an
// opt-in deterministic qualification of the shared mapping, cache, and OTLP
// chunking layers. It models 100 target identities, 5,000 optical ports, eight
// lanes per port, and 450,000 active mapped series under the receiver-wide
// 500,000 total-state ceiling. The count and retained-byte ceilings are divided
// into the same 100 independent per-target cache partitions used at runtime:
// each target must hold 4,500 active series plus 250 authoritative-delete
// tombstones and 250 semantic-invalidation watermarks in its own 5,000-state
// and approximately 15.36 MiB partition. It also maps and chunks one
// 16,700-datapoint update interval with realistic configured-stream owner
// indexes. It intentionally does not create 100 TLS listeners and does not
// exercise gRPC scheduling, reconnect recovery, exporters, or physical Cisco
// behavior; those remain separate transport, CML, and hardware gates.
//
// Run with:
//
//	CISCOOS_GNMI_RUN_SCALE_QUALIFICATION=1 go test ./internal/gnmi \
//	  -run '^TestInternalGNMIScaleQualification_100Targets5000Ports500KStateCapacity$' \
//	  -count=1 -v
func TestInternalGNMIScaleQualification_100Targets5000Ports500KStateCapacity(t *testing.T) {
	if os.Getenv(gnmiScaleQualificationEnv) != "1" {
		t.Skipf("set %s=1 to run the memory-intensive internal gNMI scale qualification", gnmiScaleQualificationEnv)
	}

	previousProcs := runtime.GOMAXPROCS(scaleVCPUs)
	defer runtime.GOMAXPROCS(previousProcs)
	require.Equal(t, 5_000, scalePortCount)
	require.Equal(t, 450_000, scaleActiveSeries)
	require.Equal(t, 50_000, scaleStateCapacity-scaleActiveSeries)
	require.Equal(t, 4_500, scaleActivePerTarget)
	require.Equal(t, 5_000, scaleCapacityPerTarget)
	require.Equal(t, 250, scaleDeletesPerTarget)
	require.Equal(t, 250, scaleInvalidatesTarget)

	runtime.GC()
	var processStart runtime.MemStats
	runtime.ReadMemStats(&processStart)
	populationStarted := time.Now()
	registry := newScaleRegistry(t)
	caches := make([]*Cache, scaleTargetCount)
	var totalRetainedCapacity int64
	baseRetainedCapacity := DefaultMaxCacheRetainedBytes / scaleTargetCount
	extraRetainedCapacity := DefaultMaxCacheRetainedBytes % scaleTargetCount
	for targetIndex := range scaleTargetCount {
		retainedCapacity := baseRetainedCapacity
		if int64(targetIndex) < extraRetainedCapacity {
			retainedCapacity++
		}
		cache, err := NewCacheWithLimits(scaleCapacityPerTarget, retainedCapacity)
		require.NoError(t, err)
		caches[targetIndex] = cache
		totalRetainedCapacity += retainedCapacity
	}
	require.Equal(t, DefaultMaxCacheRetainedBytes, totalRetainedCapacity)

	intervalInput := make([]Point, 0, scaleIntervalPoints)
	intervalTargetCounts := make(map[string]int, scaleTargetCount)
	populationTimestamp := time.Unix(1_700_000_000, 0)
	generated := 0

	for targetIndex := range scaleTargetCount {
		target := fmt.Sprintf("scale-target-%03d", targetIndex)
		ownerID := scaleOwnerID(targetIndex)
		cache := caches[targetIndex]
		batch := make([]MappedPoint, 0, scaleCacheApplyBatch)
		flush := func() {
			if len(batch) == 0 {
				return
			}
			result, applyErr := cache.Apply(CacheNotification{
				OwnerID: ownerID, Timestamp: populationTimestamp, Updates: batch,
			})
			require.NoError(t, applyErr)
			require.Len(t, result.Applied, len(batch))
			batch = batch[:0]
		}
		appendPoint := func(point Point) {
			mapped, ok := registry.Map(point)
			if !ok {
				t.Fatalf("synthetic point %s must have an explicit mapping", point.Series.Key())
			}
			batch = append(batch, mapped)
			generated++
			if intervalTargetCounts[point.Series.Target] < scaleIntervalPerTarget {
				intervalInput = append(intervalInput, point)
				intervalTargetCounts[point.Series.Target]++
			}
			if len(batch) == cap(batch) {
				flush()
			}
		}
		for portIndex := range scalePortsPerTarget {
			port := fmt.Sprintf("Ethernet%d", portIndex)
			for sensorIndex := range scalePortMetricCount {
				appendPoint(scalePoint(target, port, "", scalePortLeaf(sensorIndex), generated, populationTimestamp))
			}
			for laneIndex := range scaleLanesPerPort {
				lane := strconv.Itoa(laneIndex)
				for sensorIndex := range scaleLaneMetricCount {
					appendPoint(scalePoint(target, port, lane, scaleLaneLeaf(sensorIndex), generated, populationTimestamp))
				}
			}
		}
		flush()
		require.Equal(t, scaleActivePerTarget, cache.Len())
	}
	require.Equal(t, scaleActiveSeries, generated)
	require.Len(t, intervalInput, scaleIntervalPoints)
	require.Len(t, intervalTargetCounts, scaleTargetCount)
	populationElapsed := time.Since(populationStarted)

	// Stabilize the heap before measuring the steady-state mapped interval. The
	// cache and canonical update set remain live across this collection.
	runtime.GC()
	var intervalBefore runtime.MemStats
	runtime.ReadMemStats(&intervalBefore)
	cpuBefore, cpuAvailable := readScaleProcessCPU()
	intervalTimestamp := populationTimestamp.Add(time.Second)
	for i := range intervalInput {
		intervalInput[i].Timestamp = intervalTimestamp
		intervalInput[i].Value = DoubleValue(float64(i) + 0.5)
	}

	intervalStarted := time.Now()
	applied := make([]MappedPoint, 0, scaleIntervalPoints)
	for targetIndex := range scaleTargetCount {
		ownerID := scaleOwnerID(targetIndex)
		start := targetIndex * scaleIntervalPerTarget
		end := start + scaleIntervalPerTarget
		notification, mappingStats := registry.MapNotification(DecodedNotification{
			Timestamp: intervalTimestamp,
			Updates:   intervalInput[start:end],
		})
		require.Equal(t, MappingStats{Mapped: scaleIntervalPerTarget}, mappingStats)
		notification.OwnerID = ownerID
		result, applyErr := caches[targetIndex].Apply(notification)
		require.NoError(t, applyErr)
		require.Len(t, result.Applied, scaleIntervalPerTarget)
		require.Empty(t, result.Removed)
		applied = append(applied, result.Applied...)
	}
	require.Len(t, applied, scaleIntervalPoints)
	chunks, err := BuildMetricChunks(applied, scaleDatapointsPerChunk)
	require.NoError(t, err)
	intervalElapsed := time.Since(intervalStarted)
	cpuAfter, cpuAfterAvailable := readScaleProcessCPU()
	var intervalAfter runtime.MemStats
	runtime.ReadMemStats(&intervalAfter)

	require.Len(t, chunks, 2)
	assert.Equal(t, []int{10_000, 6_700}, []int{chunks[0].DataPointCount(), chunks[1].DataPointCount()})
	chunkTargets := map[string]struct{}{}
	for _, chunk := range chunks {
		for i := 0; i < chunk.ResourceMetrics().Len(); i++ {
			value, ok := chunk.ResourceMetrics().At(i).Resource().Attributes().Get("host.name")
			require.True(t, ok)
			chunkTargets[value.Str()] = struct{}{}
		}
	}
	assert.Len(t, chunkTargets, scaleTargetCount, "the steady-state interval must exercise every target identity")
	for targetIndex := range scaleTargetCount {
		assert.Equalf(t, scaleActivePerTarget, caches[targetIndex].Len(),
			"steady-state updates must not grow or evict target %d's bounded cache", targetIndex)
	}
	assert.Less(t, intervalElapsed, scaleIntervalLatencyLimit)
	var activeRetainedBytes int64
	for _, cache := range caches {
		activeRetainedBytes += cache.RetainedBytes()
	}

	headroomStarted := time.Now()
	var postBarrierRetainedBytes int64
	for targetIndex := range scaleTargetCount {
		deletePaths := make([]Path, scaleDeletesPerTarget)
		for index := range deletePaths {
			deletePaths[index] = scaleHeadroomPath(targetIndex, index, "enabled")
		}
		invalidationPaths := make([]Path, scaleInvalidatesTarget)
		for index := range invalidationPaths {
			invalidationPaths[index] = scaleHeadroomPath(
				targetIndex,
				index+scaleDeletesPerTarget,
				"oper-status",
			)
		}
		cache := caches[targetIndex]
		headroomResult, err := cache.Apply(CacheNotification{
			OwnerID:     scaleOwnerID(targetIndex),
			Timestamp:   intervalTimestamp.Add(time.Second),
			Deletes:     deletePaths,
			Invalidates: invalidationPaths,
		})
		require.NoError(t, err)
		require.Empty(t, headroomResult.Removed)
		assert.Equal(t, CacheUsage{
			Entries: scaleActivePerTarget, Tombstones: scaleDeletesPerTarget,
			InvalidationWatermarks: scaleInvalidatesTarget,
			Total:                  scaleCapacityPerTarget,
			Limit:                  scaleCapacityPerTarget,
		}, cache.Usage())
		assert.LessOrEqual(t, cache.RetainedBytes(), cache.RetainedByteCapacity())
		postBarrierRetainedBytes += cache.RetainedBytes()
	}
	headroomElapsed := time.Since(headroomStarted)

	intervalAllocated := intervalAfter.TotalAlloc - intervalBefore.TotalAlloc
	intervalMallocs := intervalAfter.Mallocs - intervalBefore.Mallocs
	processAllocated := intervalAfter.TotalAlloc - processStart.TotalAlloc
	rssBytes, rssSource, rssAvailable := readScaleRSS()
	if rssAvailable {
		assert.LessOrEqual(t, rssBytes, scaleRSSLimitBytes)
	}

	burstCPUPercent := -1.0
	oneSecondCadenceCPUPercent := -1.0
	if cpuAvailable && cpuAfterAvailable && cpuAfter >= cpuBefore {
		cpuSeconds := cpuAfter - cpuBefore
		if intervalElapsed > 0 {
			burstCPUPercent = 100 * cpuSeconds / (float64(scaleVCPUs) * intervalElapsed.Seconds())
		}
		// The synthetic interval represents the ~16.7k datapoints produced per
		// second by the qualified 450k-active-series deployment.
		oneSecondCadenceCPUPercent = 100 * cpuSeconds / (float64(scaleVCPUs) * scaleIntervalCadence.Seconds())
		assert.LessOrEqual(t, oneSecondCadenceCPUPercent, 80.0)
	}

	t.Logf(
		"internal_gnmi_scale targets=%d ports=%d lanes_per_port=%d active_series=%d state_capacity=%d interval_datapoints=%d chunks=%d "+
			"population_elapsed=%s interval_elapsed=%s headroom_elapsed=%s interval_alloc_bytes=%d interval_mallocs=%d total_alloc_bytes=%d "+
			"active_caches_retained_bytes=%d post_barrier_caches_retained_bytes=%d cache_retained_limit_bytes=%d "+
			"heap_alloc_bytes=%d heap_sys_bytes=%d rss_bytes=%d rss_source=%s "+
			"burst_cpu_percent=%.2f one_second_cadence_cpu_percent=%.2f",
		scaleTargetCount, scalePortCount, scaleLanesPerPort, scaleActiveSeries, scaleStateCapacity, scaleIntervalPoints, len(chunks),
		populationElapsed, intervalElapsed, headroomElapsed, intervalAllocated, intervalMallocs, processAllocated,
		activeRetainedBytes, postBarrierRetainedBytes, totalRetainedCapacity, intervalAfter.HeapAlloc, intervalAfter.HeapSys,
		rssBytes, rssSource, burstCPUPercent, oneSecondCadenceCPUPercent,
	)
}

func newScaleRegistry(tb testing.TB) *Registry {
	tb.Helper()
	mappings := make([]Mapping, 0, scaleCatalogPortMetrics+scaleCatalogLaneMetrics)
	for i := range scaleCatalogPortMetrics {
		mappings = append(mappings, Mapping{
			Source:        SourcePath{Origin: "openconfig", Elements: []string{"interfaces", "interface", "transceiver"}, Leaf: scalePortLeaf(i)},
			Metric:        MetricMetadata{Name: fmt.Sprintf("cisco.synthetic.port.sensor_%02d", i), Description: "Synthetic port sensor for scale qualification.", Unit: "1"},
			Scale:         1,
			GaugeType:     GaugeDouble,
			MetricType:    MetricGauge,
			KeyAttributes: []KeyAttribute{{Element: "interface", Key: "name", Attribute: "network.interface.name"}},
		})
	}
	for i := range scaleCatalogLaneMetrics {
		mappings = append(mappings, Mapping{
			Source:     SourcePath{Origin: "openconfig", Elements: []string{"interfaces", "interface", "transceiver", "lane"}, Leaf: scaleLaneLeaf(i)},
			Metric:     MetricMetadata{Name: fmt.Sprintf("cisco.synthetic.lane.sensor_%02d", i), Description: "Synthetic lane sensor for scale qualification.", Unit: "1"},
			Scale:      1,
			GaugeType:  GaugeDouble,
			MetricType: MetricGauge,
			KeyAttributes: []KeyAttribute{
				{Element: "interface", Key: "name", Attribute: "network.interface.name"},
				{Element: "lane", Key: "index", Attribute: "cisco.optics.lane.index"},
			},
		})
	}
	registry, err := NewRegistry(mappings...)
	require.NoError(tb, err)
	require.Equal(tb, len(mappings), registry.Len())
	return registry
}

func scalePoint(target, port, lane, leaf string, value int, timestamp time.Time) Point {
	elements := []PathElem{
		{Name: "interfaces"},
		{Name: "interface", Keys: map[string]string{"name": port}},
		{Name: "transceiver"},
	}
	if lane != "" {
		elements = append(elements, PathElem{Name: "lane", Keys: map[string]string{"index": lane}})
	}
	return Point{
		Series:    Series{Target: target, Origin: "openconfig", Elements: elements, Leaf: leaf},
		Value:     DoubleValue(float64(value)),
		Timestamp: timestamp,
	}
}

func scalePortLeaf(index int) string { return fmt.Sprintf("port-sensor-%02d", index) }
func scaleLaneLeaf(index int) string { return fmt.Sprintf("lane-sensor-%02d", index) }

func scaleOwnerID(targetIndex int) string {
	return fmt.Sprintf("gnmi:%064x", targetIndex)
}

func scaleHeadroomPath(targetIndex, index int, leaf string) Path {
	return Path{
		Target: fmt.Sprintf("scale-target-%03d", targetIndex),
		Origin: "openconfig",
		Elements: []PathElem{
			{Name: "interfaces"},
			{Name: "interface", Keys: map[string]string{"name": fmt.Sprintf("Headroom%d", index)}},
			{Name: "state"},
			{Name: leaf},
		},
	}
}

func readScaleRSS() (uint64, string, bool) {
	if contents, err := os.ReadFile("/proc/self/status"); err == nil {
		for line := range strings.SplitSeq(string(contents), "\n") {
			if !strings.HasPrefix(line, "VmRSS:") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kilobytes, parseErr := strconv.ParseUint(fields[1], 10, 64)
				if parseErr == nil {
					return kilobytes * 1024, "procfs", true
				}
			}
		}
	}

	//nolint:gosec // The executable and flags are fixed; the only value is this process's PID.
	output, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		return 0, "unavailable", false
	}
	kilobytes, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
	if err != nil {
		return 0, "unavailable", false
	}
	return kilobytes * 1024, "ps", true
}
