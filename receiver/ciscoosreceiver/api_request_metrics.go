// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import "sort"

// apiRequestObservation is normalized across the Cisco REST clients so retry
// and pagination attempts can be aggregated before OTLP datapoints are built.
// OTLP permits only one datapoint for a stream identity at a given timestamp.
type apiRequestObservation struct {
	resource        string
	attrs           map[string]string
	durationSeconds float64
	failed          bool
	rateLimited     bool
}

type apiRequestAggregate struct {
	resource               string
	attrs                  map[string]string
	averageDurationSeconds float64
	errors                 int64
	rateLimited            int64
}

func aggregateAPIRequestObservations(observations []apiRequestObservation) []apiRequestAggregate {
	type accumulator struct {
		apiRequestAggregate
		durationTotal float64
		count         int64
	}
	byKey := make(map[string]*accumulator, len(observations))
	for _, observation := range observations {
		key := counterKey(observation.resource, "api.request", observation.attrs)
		aggregate := byKey[key]
		if aggregate == nil {
			aggregate = &accumulator{apiRequestAggregate: apiRequestAggregate{
				resource: observation.resource,
				attrs:    observation.attrs,
			}}
			byKey[key] = aggregate
		}
		aggregate.durationTotal += observation.durationSeconds
		aggregate.count++
		if observation.failed {
			aggregate.errors++
		}
		if observation.rateLimited {
			aggregate.rateLimited++
		}
	}

	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]apiRequestAggregate, 0, len(keys))
	for _, key := range keys {
		aggregate := byKey[key]
		if aggregate.count > 0 {
			aggregate.averageDurationSeconds = aggregate.durationTotal / float64(aggregate.count)
		}
		out = append(out, aggregate.apiRequestAggregate)
	}
	return out
}
