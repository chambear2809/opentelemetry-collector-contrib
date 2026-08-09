// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"fmt"
	"slices"
	"strings"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

const (
	gnmiConservativeMinimumSampleInterval = time.Second
	gnmiConservativeMaximumSampleInterval = 604800 * time.Second
)

func gnmiProductApprovesEncoding(contract *gnmiProductContract, wanted gnmipb.Encoding) bool {
	return contract != nil && slices.Contains(contract.ApprovedEncodings, wanted)
}

func validateGNMIProductEncodingPreferences(prefix string, preferences []string, contract *gnmiProductContract) error {
	if contract == nil {
		return nil
	}
	for i, preference := range preferences {
		encoding, ok := encodingNameToGNMI(preference)
		if ok && !gnmiProductApprovesEncoding(contract, encoding) {
			return fmt.Errorf(
				"%s[%d] encoding %q is not approved for product %s",
				prefix, i, strings.ToLower(strings.TrimSpace(preference)), contract.Product,
			)
		}
	}
	return nil
}

func validateGNMIProductListPolicy(
	prefix string,
	contract *gnmiProductContract,
	updatesOnly, allowAggregation bool,
	qosMarking *uint32,
	extensions GNMIExtensionsConfig,
) error {
	if contract == nil || !contract.RequestPolicy.ConservativeSampleOnly {
		return nil
	}
	if updatesOnly {
		return fmt.Errorf("%s.updates_only must be false on product %s", prefix, contract.Product)
	}
	if allowAggregation {
		return fmt.Errorf("%s.allow_aggregation must be false on product %s", prefix, contract.Product)
	}
	if qosMarking != nil {
		return fmt.Errorf("%s.qos_marking is not qualified on product %s", prefix, contract.Product)
	}
	if extensions.Depth != nil {
		return fmt.Errorf("%s.gnmi_extensions.depth is not qualified on product %s", prefix, contract.Product)
	}
	return nil
}

func validateGNMIProductPathPolicy(prefix string, contract *gnmiProductContract, options GNMIPathOptionsConfig) error {
	if contract == nil || !contract.RequestPolicy.ConservativeSampleOnly {
		return nil
	}
	if options.StreamMode != "" && options.StreamMode != gnmiStreamModeSample {
		return fmt.Errorf("%s.stream_mode must be sample on product %s", prefix, contract.Product)
	}
	if options.HeartbeatInterval != nil || options.SuppressRedundant != nil {
		return fmt.Errorf("%s optional subscription flags are not qualified on product %s", prefix, contract.Product)
	}
	return nil
}

// validateGNMIProductSamplePlan enforces the conservative cadence used by
// contracts whose optional subscription behaviors have not been qualified.
// Every path in one subscription uses the same bounded SAMPLE interval.
func validateGNMIProductSamplePlan(
	prefix string,
	contract *gnmiProductContract,
	defaultInterval time.Duration,
	pathOptions []GNMIPathOptionsConfig,
) error {
	if contract == nil || !contract.RequestPolicy.ConservativeSampleOnly {
		return nil
	}
	if defaultInterval < gnmiConservativeMinimumSampleInterval || defaultInterval > gnmiConservativeMaximumSampleInterval {
		return fmt.Errorf("%s.sample_interval must be between 1s and 604800s on product %s", prefix, contract.Product)
	}
	var common time.Duration
	for index, options := range pathOptions {
		effective := defaultInterval
		if options.SampleInterval != nil {
			effective = *options.SampleInterval
		}
		if effective < gnmiConservativeMinimumSampleInterval || effective > gnmiConservativeMaximumSampleInterval {
			return fmt.Errorf("%s path %d effective sample_interval must be between 1s and 604800s on product %s", prefix, index, contract.Product)
		}
		if index == 0 {
			common = effective
			continue
		}
		if effective != common {
			return fmt.Errorf("%s paths must use one common sample_interval on product %s", prefix, contract.Product)
		}
	}
	return nil
}
