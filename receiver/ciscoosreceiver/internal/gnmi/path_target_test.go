// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathTargetParticipatesInCanonicalIdentityAndSelection(t *testing.T) {
	base := Path{
		Target: "switch-1", PathTarget: "OTHERS", Origin: "",
		Elements: []PathElem{{Name: "proc"}, {Name: "uptime"}},
	}
	other := base.Clone()
	other.PathTarget = "OC-YANG"
	assert.NotEqual(t, base.Key(), other.Key())
	assert.False(t, base.HasPrefix(other))

	wildcard := base.Clone()
	wildcard.PathTarget = ""
	assert.True(t, base.HasPrefix(wildcard))
	assert.True(t, other.HasPrefix(wildcard))
}

func TestMappingRegistrySeparatesPathTarget(t *testing.T) {
	metadata := MetricMetadata{Name: "test.value", Description: "test value", Unit: "1"}
	mappings := []Mapping{
		{Source: SourcePath{PathTarget: "OTHERS", Elements: []string{"state"}, Leaf: "value"}, Metric: metadata, Scale: 1, GaugeType: GaugeInt},
		{Source: SourcePath{PathTarget: "OC-YANG", Elements: []string{"state"}, Leaf: "value"}, Metric: metadata, Scale: 1, GaugeType: GaugeInt},
	}
	registry, err := NewRegistry(mappings...)
	require.NoError(t, err)
	assert.Equal(t, 2, registry.Len())

	point := Point{Series: Series{Target: "switch-1", PathTarget: "OTHERS", Elements: []PathElem{{Name: "state"}}, Leaf: "value"}, Value: IntValue(1)}
	mapped, ok := registry.Map(point)
	require.True(t, ok)
	assert.Equal(t, int64(1), mapped.IntValue)

	point.Series.PathTarget = "unqualified"
	_, ok = registry.Map(point)
	assert.False(t, ok)
}

func TestMappingRegistrySourceIdentityRejectsNULBoundaryCollision(t *testing.T) {
	configured := SourcePath{
		Origin:   "openconfig",
		Elements: []string{"interfaces", "interface"},
		Leaf:     "value",
	}
	deviceControlled := SourcePath{
		PathTarget: "\x00openconfig",
		Origin:     "interfaces",
		Elements:   []string{"interface"},
		Leaf:       "value",
	}
	assert.NotEqual(t, configured.Key(), deviceControlled.Key())

	registry, err := NewRegistry(Mapping{
		Source: configured,
		Metric: MetricMetadata{Name: "test.value", Description: "test value", Unit: "1"},
		Scale:  1, GaugeType: GaugeInt,
	})
	require.NoError(t, err)
	_, mapped := registry.Map(Point{
		Series: Series{
			Target: "switch-1", PathTarget: deviceControlled.PathTarget,
			Origin: deviceControlled.Origin, Elements: []PathElem{{Name: "interface"}}, Leaf: "value",
		},
		Value: IntValue(1),
	})
	assert.False(t, mapped, "a device-controlled NUL must not shift source-path component boundaries")
}

func TestCacheSelectorsIsolatePathTargets(t *testing.T) {
	cache, err := NewCache(20)
	require.NoError(t, err)
	timestamp := time.Unix(100, 0)
	makePoint := func(pathTarget, name string) MappedPoint {
		return MappedPoint{
			Source: Series{
				Target: "switch-1", PathTarget: pathTarget,
				Elements: []PathElem{{Name: "interfaces"}, {Name: "interface", Keys: map[string]string{"name": name}}},
				Leaf:     "status",
			},
			Metric:    MetricMetadata{Name: "test.status", Description: "test status", Unit: "1"},
			GaugeType: GaugeInt, IntValue: 1,
			Attributes: map[string]string{"network.interface.name": name}, Timestamp: timestamp,
		}
	}
	others := makePoint("OTHERS", "Ethernet0")
	oc := makePoint("OC-YANG", "Ethernet4")
	_, err = cache.Apply(CacheNotification{Timestamp: timestamp, Updates: []MappedPoint{others, oc}})
	require.NoError(t, err)

	result, err := cache.Apply(CacheNotification{
		Timestamp: timestamp.Add(time.Second),
		Deletes:   []Path{{Target: "switch-1", PathTarget: "OTHERS", Elements: []PathElem{{Name: "interfaces"}}}},
	})
	require.NoError(t, err)
	require.Len(t, result.Removed, 1)
	assert.Equal(t, "OTHERS", result.Removed[0].Source.PathTarget)
	require.Len(t, cache.Snapshot(), 1)
	assert.Equal(t, "OC-YANG", cache.Snapshot()[0].Source.PathTarget)
}

func TestPathTargetRetainedBytesAreAccounted(t *testing.T) {
	without := Path{Target: "switch-1", Origin: "openconfig", Elements: []PathElem{{Name: "state"}}}
	with := without.Clone()
	with.PathTarget = "OC-YANG"
	assert.Equal(t,
		estimatePathRetainedBytes(without)+int64(len("OC-YANG")),
		estimatePathRetainedBytes(with),
	)
}
