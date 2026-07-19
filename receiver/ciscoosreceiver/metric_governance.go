// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

//go:generate go run ./internal/metricschemagen/cmd -metadata metadata.yaml -output generated_metric_schema.go

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"go.opentelemetry.io/collector/pdata/pmetric"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/interfacesscraper"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/scraper/systemscraper"
)

type fixedMetricInstrument uint8

const (
	fixedMetricInstrumentUnknown fixedMetricInstrument = iota
	fixedMetricInstrumentGauge
	fixedMetricInstrumentSum
)

type fixedMetricValueType uint8

const (
	fixedMetricValueTypeUnknown fixedMetricValueType = iota
	fixedMetricValueTypeInt
	fixedMetricValueTypeDouble
)

type fixedMetricTemporality uint8

const (
	fixedMetricTemporalityUnspecified fixedMetricTemporality = iota
	fixedMetricTemporalityCumulative
)

type fixedMetricDescriptor struct {
	description string
	unit        string
	instrument  fixedMetricInstrument
	valueType   fixedMetricValueType
	monotonic   bool
	temporality fixedMetricTemporality
	// Attribute lists mirror catalog declarations. Exact emitter-to-catalog
	// attribute governance is currently enforced only for the topology metric;
	// typed shared-gNMI mappings use governedMetricDescriptor below.
	requiredAttributes []string
	optionalAttributes []string
}

type governedMetricDescriptor struct {
	name               string
	description        string
	unit               string
	instrument         internalgnmi.MetricType
	valueType          internalgnmi.GaugeValueType
	monotonic          bool
	temporality        fixedMetricTemporality
	optionalAttributes []string
}

type governedMetricNamePattern struct {
	prefix             string
	contract           string
	nameSource         string
	nameEncoding       string
	collisionAttribute string
	variants           []governedDynamicMetricVariant
}

type governedDynamicMetricInstrument uint8

const (
	governedDynamicMetricInstrumentUnknown governedDynamicMetricInstrument = iota
	governedDynamicMetricInstrumentGauge
	governedDynamicMetricInstrumentCumulativeSum
)

type governedDynamicMetricValueType uint8

const (
	governedDynamicMetricValueTypeUnknown governedDynamicMetricValueType = iota
	governedDynamicMetricValueTypeInt
	governedDynamicMetricValueTypeDouble
)

type governedDynamicMetricVariant struct {
	marker      string
	instrument  governedDynamicMetricInstrument
	valueType   governedDynamicMetricValueType
	unit        string
	temporality fixedMetricTemporality
	monotonic   bool
}

const governedDynamicYANGNameEncoding = "__v1 reversible length-framed tuple encoding"

var governedYANGMetricVariants = []governedDynamicMetricVariant{
	{
		marker:     "n",
		instrument: governedDynamicMetricInstrumentGauge,
		valueType:  governedDynamicMetricValueTypeDouble,
	},
	{
		marker:      "n",
		instrument:  governedDynamicMetricInstrumentCumulativeSum,
		valueType:   governedDynamicMetricValueTypeInt,
		temporality: fixedMetricTemporalityCumulative,
		monotonic:   true,
	},
	{
		marker:     "i",
		instrument: governedDynamicMetricInstrumentGauge,
		valueType:  governedDynamicMetricValueTypeDouble,
	},
}

var governedDynamicMetricNamePatterns = [...]governedMetricNamePattern{
	{
		prefix:             "cisco.catalyst9800.yang.",
		contract:           "Catalyst 9800 model-defined YANG metrics",
		nameSource:         "raw module-presence/value plus ordered direct path or separately counted dial-out encoding/source tuples",
		nameEncoding:       governedDynamicYANGNameEncoding,
		collisionAttribute: "cisco.yang.source_path",
		variants:           governedYANGMetricVariants,
	},
	{
		prefix:             "cisco.iosxr.yang.",
		contract:           "IOS XR model-defined YANG metrics",
		nameSource:         "raw module-presence/value plus ordered direct path or separately counted dial-out encoding/source tuples",
		nameEncoding:       governedDynamicYANGNameEncoding,
		collisionAttribute: "cisco.yang.source_path",
		variants:           governedYANGMetricVariants,
	},
}

var governedFixedMetricNames = buildGovernedFixedMetricNames()

func buildGovernedFixedMetricNames() map[string]struct{} {
	names := make(map[string]struct{}, len(fixedMetricDescriptors))
	for name := range fixedMetricDescriptors {
		names[name] = struct{}{}
	}
	for _, name := range append(interfacesscraper.MetricNames(), systemscraper.MetricNames()...) {
		names[name] = struct{}{}
	}
	return names
}

func governedFixedMetricMetadata(
	name string,
	metricType pmetric.MetricType,
	valueType fixedMetricValueType,
	fallbackDescription,
	fallbackUnit string,
) (description, unit string) {
	descriptor, fixed := fixedMetricDescriptors[name]
	if !fixed {
		return fallbackDescription, fallbackUnit
	}
	expectedInstrument := fixedMetricInstrumentGauge
	if metricType == pmetric.MetricTypeSum {
		expectedInstrument = fixedMetricInstrumentSum
	}
	if descriptor.instrument != expectedInstrument || descriptor.valueType != valueType {
		panic(fmt.Sprintf(
			"fixed metric %q emitted with instrument=%s value_type=%s; catalog requires instrument=%s value_type=%s",
			name,
			pmetricTypeName(metricType),
			fixedMetricValueTypeName(valueType),
			fixedMetricInstrumentName(descriptor.instrument),
			fixedMetricValueTypeName(descriptor.valueType),
		))
	}
	if descriptor.instrument == fixedMetricInstrumentSum &&
		(!descriptor.monotonic || descriptor.temporality != fixedMetricTemporalityCumulative) {
		panic(fmt.Sprintf("fixed sum metric %q is not governed as cumulative and monotonic", name))
	}
	return descriptor.description, descriptor.unit
}

func pmetricTypeName(metricType pmetric.MetricType) string {
	if metricType == pmetric.MetricTypeSum {
		return "sum"
	}
	return "gauge"
}

func fixedMetricInstrumentName(instrument fixedMetricInstrument) string {
	if instrument == fixedMetricInstrumentSum {
		return "sum"
	}
	return "gauge"
}

func fixedMetricValueTypeName(valueType fixedMetricValueType) string {
	if valueType == fixedMetricValueTypeDouble {
		return "double"
	}
	return "int"
}

func governedMetricNameCollision(name string) (string, bool) {
	if _, fixed := governedFixedMetricNames[name]; fixed {
		return "a fixed Cisco OS receiver metric catalog", true
	}
	for _, pattern := range governedDynamicMetricNamePatterns {
		if err := validateGovernedDynamicMetricNamePattern(pattern); err != nil {
			panic(err)
		}
		if name == strings.TrimSuffix(pattern.prefix, ".") || strings.HasPrefix(name, pattern.prefix) {
			return pattern.contract, true
		}
	}
	return "", false
}

func validateGovernedDynamicMetricNamePattern(pattern governedMetricNamePattern) error {
	if pattern.prefix == "" || pattern.contract == "" || pattern.nameSource == "" || pattern.nameEncoding == "" || pattern.collisionAttribute == "" {
		return errors.New("dynamic metric pattern has an incomplete name or collision contract")
	}
	if len(pattern.variants) != 3 {
		return fmt.Errorf("dynamic metric pattern %q must define gauge, sum, and info variants", pattern.prefix)
	}
	if pattern.nameEncoding != governedDynamicYANGNameEncoding {
		return fmt.Errorf("dynamic metric pattern %q must declare the current __v1 generated-name encoding while reserving its broad namespace", pattern.prefix)
	}
	expected := map[governedDynamicMetricVariant]struct{}{
		governedYANGMetricVariants[0]: {},
		governedYANGMetricVariants[1]: {},
		governedYANGMetricVariants[2]: {},
	}
	seen := make(map[governedDynamicMetricVariant]struct{}, len(pattern.variants))
	for _, variant := range pattern.variants {
		if _, valid := expected[variant]; !valid {
			return fmt.Errorf("dynamic metric pattern %q has a variant outside the exact numeric-gauge, numeric-sum, and info-gauge contract", pattern.prefix)
		}
		if _, duplicate := seen[variant]; duplicate {
			return fmt.Errorf("dynamic metric pattern %q has a duplicate governed variant", pattern.prefix)
		}
		seen[variant] = struct{}{}
	}
	for variant := range expected {
		if _, present := seen[variant]; !present {
			return fmt.Errorf("dynamic metric pattern %q is missing a governed variant", pattern.prefix)
		}
	}
	return nil
}

func builtinGNMIMetricDescriptors() (map[string]governedMetricDescriptor, error) {
	descriptors := make(map[string]governedMetricDescriptor, len(builtinGNMIMetricMetadata))
	for _, catalog := range []map[string]builtinGNMIProfileDefinition{
		iosXEBuiltinGNMIProfileCatalog,
		iosXRBuiltinGNMIProfileCatalog,
		nxOSBuiltinGNMIProfileCatalog,
	} {
		for _, profile := range catalog {
			mappings := append([]builtinGNMIMapping(nil), profile.SyntheticMappings...)
			for _, path := range profile.Paths {
				mappings = append(mappings, path.Mappings...)
			}
			for mappingIndex := range mappings {
				builtin := &mappings[mappingIndex]
				mapping := &builtin.Mapping
				temporality := fixedMetricTemporalityUnspecified
				if mapping.MetricType == internalgnmi.MetricSum {
					temporality = fixedMetricTemporalityCumulative
				}
				descriptor := governedMetricDescriptor{
					name:        mapping.Metric.Name,
					description: mapping.Metric.Description,
					unit:        mapping.Metric.Unit,
					instrument:  mapping.MetricType,
					valueType:   mapping.GaugeType,
					monotonic:   mapping.Monotonic,
					temporality: temporality,
				}
				attributes := make(map[string]struct{}, len(mapping.KeyAttributes)+len(builtin.StaticAttributes))
				for _, attribute := range mapping.KeyAttributes {
					attributes[attribute.Attribute] = struct{}{}
				}
				for attribute := range builtin.StaticAttributes {
					attributes[attribute] = struct{}{}
				}
				for attribute := range attributes {
					descriptor.optionalAttributes = append(descriptor.optionalAttributes, attribute)
				}
				sort.Strings(descriptor.optionalAttributes)

				if existing, ok := descriptors[descriptor.name]; ok {
					if !governedMetricDescriptorsCompatible(existing, descriptor) {
						return nil, fmt.Errorf("builtin gNMI metric %q has incompatible typed mappings", descriptor.name)
					}
					descriptor.optionalAttributes = mergeSortedStrings(existing.optionalAttributes, descriptor.optionalAttributes)
				}
				descriptors[descriptor.name] = descriptor
			}
		}
	}
	for name := range builtinGNMIMetricMetadata {
		if _, ok := descriptors[name]; !ok {
			return nil, fmt.Errorf("builtin gNMI metric metadata %q has no typed mapping", name)
		}
	}
	return descriptors, nil
}

func governedMetricDescriptorsCompatible(left, right governedMetricDescriptor) bool {
	return left.name == right.name &&
		left.description == right.description &&
		left.unit == right.unit &&
		left.instrument == right.instrument &&
		left.valueType == right.valueType &&
		left.monotonic == right.monotonic &&
		left.temporality == right.temporality
}

func mergeSortedStrings(left, right []string) []string {
	values := make(map[string]struct{}, len(left)+len(right))
	for _, value := range append(append([]string(nil), left...), right...) {
		values[value] = struct{}{}
	}
	merged := make([]string, 0, len(values))
	for value := range values {
		merged = append(merged, value)
	}
	sort.Strings(merged)
	return merged
}
