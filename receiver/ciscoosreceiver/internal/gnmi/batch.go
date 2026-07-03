// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"

import (
	"errors"
	"fmt"
	"strconv"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

const instrumentationScope = "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"

// BuildMetricChunks losslessly converts mapped points into consumer payloads
// containing at most maxDatapoints each. Input order is retained across chunks.
func BuildMetricChunks(points []MappedPoint, maxDatapoints int) ([]pmetric.Metrics, error) {
	if maxDatapoints <= 0 {
		return nil, errors.New("max datapoints per chunk must be positive")
	}
	if len(points) == 0 {
		return nil, nil
	}
	chunks := make([]pmetric.Metrics, 0, (len(points)+maxDatapoints-1)/maxDatapoints)
	for start := 0; start < len(points); start += maxDatapoints {
		end := min(start+maxDatapoints, len(points))
		chunk, err := buildMetricChunk(points[start:end])
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, chunk)
	}
	return chunks, nil
}

func buildMetricChunk(points []MappedPoint) (pmetric.Metrics, error) {
	metrics := pmetric.NewMetrics()
	targets := map[string]pmetric.ScopeMetrics{}
	metricBySeries := map[string]pmetric.Metric{}
	gaugeTypes := map[string]GaugeValueType{}
	metricTypes := map[string]MetricType{}
	monotonic := map[string]bool{}

	for i := range points {
		point := &points[i]
		if point.Source.Target == "" {
			return pmetric.Metrics{}, errors.New("mapped point target cannot be empty")
		}
		scope, ok := targets[point.Source.Target]
		if !ok {
			resourceMetrics := metrics.ResourceMetrics().AppendEmpty()
			resourceMetrics.Resource().Attributes().PutStr("host.name", point.Source.Target)
			resourceMetrics.Resource().Attributes().PutStr("host.id", point.Source.Target)
			scope = resourceMetrics.ScopeMetrics().AppendEmpty()
			scope.Scope().SetName(instrumentationScope)
			targets[point.Source.Target] = scope
		}

		key := point.Source.Target + "\x00" + point.Metric.Name
		metric, ok := metricBySeries[key]
		switch {
		case !ok:
			if point.Metric.Name == "" || point.Metric.Description == "" || point.Metric.Unit == "" {
				return pmetric.Metrics{}, errors.New("mapped point metric metadata must be complete")
			}
			metric = scope.Metrics().AppendEmpty()
			metric.SetName(point.Metric.Name)
			metric.SetDescription(point.Metric.Description)
			metric.SetUnit(point.Metric.Unit)
			switch point.MetricType {
			case MetricGauge:
				metric.SetEmptyGauge()
			case MetricSum:
				metric.SetEmptySum()
				metric.Sum().SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
				metric.Sum().SetIsMonotonic(point.Monotonic)
			default:
				return pmetric.Metrics{}, fmt.Errorf("unsupported metric type %d", point.MetricType)
			}
			metricBySeries[key] = metric
			gaugeTypes[key] = point.GaugeType
			metricTypes[key] = point.MetricType
			monotonic[key] = point.Monotonic
		case metric.Description() != point.Metric.Description || metric.Unit() != point.Metric.Unit:
			return pmetric.Metrics{}, fmt.Errorf("conflicting metadata for metric %q", point.Metric.Name)
		case gaugeTypes[key] != point.GaugeType:
			return pmetric.Metrics{}, fmt.Errorf("conflicting gauge type for metric %q", point.Metric.Name)
		case metricTypes[key] != point.MetricType || monotonic[key] != point.Monotonic:
			return pmetric.Metrics{}, fmt.Errorf("conflicting aggregation for metric %q", point.Metric.Name)
		}

		var datapoint pmetric.NumberDataPoint
		switch point.MetricType {
		case MetricGauge:
			datapoint = metric.Gauge().DataPoints().AppendEmpty()
		case MetricSum:
			datapoint = metric.Sum().DataPoints().AppendEmpty()
		default:
			return pmetric.Metrics{}, fmt.Errorf("unsupported metric type %d", point.MetricType)
		}
		switch point.GaugeType {
		case GaugeInt:
			datapoint.SetIntValue(point.IntValue)
		case GaugeDouble:
			datapoint.SetDoubleValue(point.DoubleValue)
		default:
			return pmetric.Metrics{}, fmt.Errorf("unsupported gauge type %q", point.GaugeType)
		}
		datapoint.SetTimestamp(pcommon.NewTimestampFromTime(point.Timestamp))
		for key, value := range point.Attributes {
			if key == "cisco.optics.experimental" {
				if parsed, err := strconv.ParseBool(value); err == nil {
					datapoint.Attributes().PutBool(key, parsed)
					continue
				}
			}
			datapoint.Attributes().PutStr(key, value)
		}
	}
	return metrics, nil
}
