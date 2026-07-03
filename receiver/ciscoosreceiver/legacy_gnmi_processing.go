// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import "context"

const (
	legacyGNMIMaxConcurrentProcessing = 8
	legacyGNMIMaxRecvMsgSizeMiB       = 4
)

// legacyGNMIProcessingLimiter bounds decoder allocations and downstream calls
// across both deprecated dial-in implementations. One limiter is owned by each
// Cisco OS metrics receiver and shared by its IOS XR and Catalyst 9800 children.
type legacyGNMIProcessingLimiter struct {
	slots             chan struct{}
	responseAdmission *gnmiResponseAdmission
}

func newLegacyGNMIProcessingLimiter(admissions ...*gnmiResponseAdmission) *legacyGNMIProcessingLimiter {
	admission := newGNMIResponseAdmission()
	if len(admissions) > 0 && admissions[0] != nil {
		admission = admissions[0]
	}
	return &legacyGNMIProcessingLimiter{
		slots:             make(chan struct{}, legacyGNMIMaxConcurrentProcessing),
		responseAdmission: admission,
	}
}

func legacyGNMIResponseAdmission(limiter *legacyGNMIProcessingLimiter) *gnmiResponseAdmission {
	if limiter == nil {
		return nil
	}
	return limiter.responseAdmission
}

func (l *legacyGNMIProcessingLimiter) run(ctx context.Context, operation func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Direct unit-test receiver literals predate the shared limiter. Production
	// construction always supplies one, while a nil limiter retains compatibility
	// for those focused tests.
	if l == nil {
		return operation()
	}
	select {
	case l.slots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-l.slots
			return err
		}
		defer func() { <-l.slots }()
		return operation()
	case <-ctx.Done():
		return ctx.Err()
	}
}
