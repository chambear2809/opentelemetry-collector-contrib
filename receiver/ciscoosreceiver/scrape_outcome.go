// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"sync"
	"time"
)

// scrapeSuccessState retains the last fully successful scrape timestamp. A
// partial or failed scrape reports the previous timestamp instead of making
// stale or incomplete data look fresh.
type scrapeSuccessState struct {
	mu          sync.Mutex
	lastSuccess time.Time
}

func (s *scrapeSuccessState) observe(now time.Time, fullySuccessful bool) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if fullySuccessful {
		s.lastSuccess = now
	}
	return s.lastSuccess, !s.lastSuccess.IsZero()
}

type apiOutcomeSummary struct {
	attempted bool
	succeeded bool
}

func summarizeAPIOutcomes[T any](stats []T, outcome func(T) string) apiOutcomeSummary {
	summary := apiOutcomeSummary{attempted: len(stats) > 0}
	for _, stat := range stats {
		if outcome(stat) == "success" {
			summary.succeeded = true
			break
		}
	}
	return summary
}

func (s apiOutcomeSummary) availability() (int64, bool) {
	if !s.attempted {
		return 0, false
	}
	return boolToInt(s.succeeded), true
}
