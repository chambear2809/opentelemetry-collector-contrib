// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package httpclient // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"

import "fmt"

const (
	// HardMaxPaginationPages bounds controller calls even when a receiver or a
	// direct client caller deliberately disables its configured result cap.
	HardMaxPaginationPages = 100
	// HardMaxPaginationResults bounds memory retained from a single paginated
	// operation. A configured positive limit at or below this value still wins.
	HardMaxPaginationResults = 100_000
	// HardMaxPaginationBytes bounds aggregate response bytes decoded and retained
	// by one paginated operation. The per-response limit alone would otherwise
	// permit 100 near-limit pages to expand into gigabytes of generic maps.
	HardMaxPaginationBytes = 64 * 1024 * 1024
)

// PaginationByteBudget tracks aggregate raw page bytes for one operation.
type PaginationByteBudget struct {
	used    int
	maximum int
}

// NewPaginationByteBudget creates an aggregate pagination budget. Values that
// are non-positive or exceed the hard ceiling resolve to the hard ceiling.
func NewPaginationByteBudget(maximum int) PaginationByteBudget {
	if maximum <= 0 || maximum > HardMaxPaginationBytes {
		maximum = HardMaxPaginationBytes
	}
	return PaginationByteBudget{maximum: maximum}
}

// Charge reserves one page before it is decoded. An over-budget page is not
// decoded or appended, so callers can safely return their prior partial slice.
func (b *PaginationByteBudget) Charge(operation string, pageBytes, partialResults int) error {
	maximum := b.maximum
	if maximum <= 0 || maximum > HardMaxPaginationBytes {
		maximum = HardMaxPaginationBytes
	}
	if pageBytes < 0 || pageBytes > maximum-b.used {
		return NewPaginationLimitError(operation, "byte", maximum, partialResults)
	}
	b.used += pageBytes
	return nil
}

// PaginationLimitError reports that a client returned partial results because
// continuing pagination would exceed a non-configurable safety ceiling.
type PaginationLimitError struct {
	Operation string
	Kind      string
	Maximum   int
	Results   int
	Hard      bool
}

func (e *PaginationLimitError) Error() string {
	source := "configured"
	if e.Hard {
		source = "hard"
	}
	return fmt.Sprintf(
		"paginate %s: %s %s limit of %d exhausted after %d partial results",
		e.Operation,
		source,
		e.Kind,
		e.Maximum,
		e.Results,
	)
}

// EffectivePaginationResultLimit returns the result ceiling and whether it is
// the hard client safety limit rather than a caller-configured cap.
func EffectivePaginationResultLimit(configured int) (limit int, hard bool) {
	if configured > 0 && configured <= HardMaxPaginationResults {
		return configured, false
	}
	return HardMaxPaginationResults, true
}

// NewPaginationLimitError builds the common partial-result exhaustion error.
func NewPaginationLimitError(operation, kind string, maximum, results int) error {
	return &PaginationLimitError{
		Operation: operation,
		Kind:      kind,
		Maximum:   maximum,
		Results:   results,
		Hard:      true,
	}
}

// NewConfiguredPaginationLimitError reports partial results caused by a
// caller-configured result cap rather than a non-configurable safety ceiling.
func NewConfiguredPaginationLimitError(operation, kind string, maximum, results int) error {
	return &PaginationLimitError{
		Operation: operation,
		Kind:      kind,
		Maximum:   maximum,
		Results:   results,
	}
}
