// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEffectivePaginationResultLimit(t *testing.T) {
	limit, hard := EffectivePaginationResultLimit(25)
	assert.Equal(t, 25, limit)
	assert.False(t, hard)

	for _, configured := range []int{0, -1, HardMaxPaginationResults + 1} {
		limit, hard = EffectivePaginationResultLimit(configured)
		assert.Equal(t, HardMaxPaginationResults, limit)
		assert.True(t, hard)
	}
}

func TestPaginationLimitErrorIsTypedAndExplicit(t *testing.T) {
	err := NewPaginationLimitError("inventory", "page", 100, 42)
	var limitErr *PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.Equal(t, 42, limitErr.Results)
	assert.ErrorContains(t, err, "partial results")
}

func TestPaginationByteBudgetRejectsPageBeforeDecode(t *testing.T) {
	var budget PaginationByteBudget
	require.NoError(t, budget.Charge("inventory", HardMaxPaginationBytes-1, 4))
	err := budget.Charge("inventory", 2, 4)

	var limitErr *PaginationLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.Equal(t, "byte", limitErr.Kind)
	assert.Equal(t, HardMaxPaginationBytes, limitErr.Maximum)
	assert.Equal(t, 4, limitErr.Results)
}
