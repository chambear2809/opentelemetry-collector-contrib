// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRecentACIQueryOrdersNewestFirst(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.ACI.EventLookback = 2 * time.Hour
	now := time.Date(2026, time.July, 6, 12, 0, 0, 0, time.UTC)

	for _, className := range []string{"aaaModLR", "eventRecord"} {
		t.Run(className, func(t *testing.T) {
			query := recentACIQuery(cfg, now, className)
			assert.Equal(t, fmt.Sprintf(`gt(%s.created,"2026-07-06T10:00:00Z")`, className), query.Get("query-target-filter"))
			assert.Equal(t, className+".created|desc", query.Get("order-by"))
		})
	}
}
