// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metricschemagen

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateProducesDeterministicTypedRegistry(t *testing.T) {
	metadata := []byte(`metrics:
  z.metric:
    attributes: [z.attr, a.attr]
    description: Z metric.
    unit: By
    sum:
      aggregation_temporality: cumulative
      monotonic: true
      value_type: int
  a.metric:
    description: A metric.
    unit: "1"
    gauge:
      value_type: double
`)
	first, err := Generate(metadata)
	require.NoError(t, err)
	second, err := Generate(metadata)
	require.NoError(t, err)
	require.Equal(t, first, second)
	generated := string(first)
	require.Less(t, strings.Index(generated, `"a.metric"`), strings.Index(generated, `"z.metric"`))
	require.Contains(t, generated, `optionalAttributes: []string{"a.attr", "z.attr"}`)
	require.Contains(t, generated, "fixedMetricTemporalityCumulative")
}

func TestGenerateRejectsIncompleteOrAmbiguousDescriptors(t *testing.T) {
	tests := map[string]struct {
		definition string
		problem    string
	}{
		"empty catalog": {
			definition: "metrics: {}\n",
			problem:    "catalog is empty",
		},
		"empty description": {
			definition: "metrics:\n  fixture.metric:\n    gauge:\n      value_type: int\n",
			problem:    "empty description",
		},
		"missing instrument": {
			definition: "metrics:\n  fixture.metric:\n    description: Fixture.\n",
			problem:    "exactly one gauge or sum",
		},
		"two instruments": {
			definition: "metrics:\n  fixture.metric:\n    description: Fixture.\n    gauge:\n      value_type: int\n    sum:\n      aggregation_temporality: cumulative\n      monotonic: true\n      value_type: int\n",
			problem:    "exactly one gauge or sum",
		},
		"multiple numeric types": {
			definition: "metrics:\n  fixture.metric:\n    description: Fixture.\n    gauge:\n      value_type: int or double\n",
			problem:    "unsupported value type",
		},
		"delta sum": {
			definition: "metrics:\n  fixture.metric:\n    description: Fixture.\n    sum:\n      aggregation_temporality: delta\n      monotonic: true\n      value_type: int\n",
			problem:    "unsupported sum temporality",
		},
		"non-monotonic sum": {
			definition: "metrics:\n  fixture.metric:\n    description: Fixture.\n    sum:\n      aggregation_temporality: cumulative\n      monotonic: false\n      value_type: int\n",
			problem:    "non-monotonic fixed sum",
		},
		"duplicate attribute": {
			definition: "metrics:\n  fixture.metric:\n    attributes: [fixture.attr, fixture.attr]\n    description: Fixture.\n    gauge:\n      value_type: int\n",
			problem:    "repeats attribute",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Generate([]byte(test.definition))
			require.ErrorContains(t, err, test.problem)
		})
	}
}
