// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package systemscraper

import (
	"reflect"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/systemscraper/internal/metadata"
)

// MetricNames returns the generated fixed metric-name catalog.
func MetricNames() []string {
	info := reflect.ValueOf(metadata.MetricsInfo)
	names := make([]string, 0, info.NumField())
	for i := 0; i < info.NumField(); i++ {
		name := info.Field(i).FieldByName("Name")
		if name.IsValid() && name.Kind() == reflect.String && name.String() != "" {
			names = append(names, name.String())
		}
	}
	return names
}
