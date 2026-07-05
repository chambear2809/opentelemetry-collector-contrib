// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"errors"
	"fmt"
	"strings"

	"github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type sanitizedGNMIRPCStatus struct {
	status                *status.Status
	authenticationFailure bool
}

func (e *sanitizedGNMIRPCStatus) Error() string              { return e.status.Err().Error() }
func (e *sanitizedGNMIRPCStatus) GRPCStatus() *status.Status { return e.status }

// sanitizedGNMIRPCError preserves the status code used by reconnect and
// authentication policy without reflecting a remote gNMI status description
// into collector logs. A device controls that description and has already seen
// the request metadata, so it can otherwise echo credentials back to operators.
// Status details are deliberately discarded for the same reason.
func sanitizedGNMIRPCError(err error) error {
	if err == nil {
		return nil
	}
	var alreadySanitized *sanitizedGNMIRPCStatus
	if errors.As(err, &alreadySanitized) {
		return err
	}
	remoteStatus, ok := status.FromError(err)
	if !ok {
		return err
	}
	authenticationFailure := gnmiStatusIndicatesAuthenticationFailure(remoteStatus.Code(), remoteStatus.Message())
	sanitized := status.Newf(
		remoteStatus.Code(),
		"gNMI RPC failed: code=%s",
		remoteStatus.Code(),
	)
	return &sanitizedGNMIRPCStatus{status: sanitized, authenticationFailure: authenticationFailure}
}

func gnmiStatusIndicatesAuthenticationFailure(code codes.Code, message string) bool {
	switch code {
	case codes.Unauthenticated, codes.PermissionDenied:
		return true
	}
	message = strings.ToLower(message)
	return strings.Contains(message, "authentication") ||
		strings.Contains(message, "certificate") ||
		strings.Contains(message, "unknown authority")
}

// sanitizedGNMISubscribeError preserves stable diagnostic context without
// reflecting a device-controlled error message into collector logs.
func sanitizedGNMISubscribeError(protocolErr *gnmi.Error) error { //nolint:staticcheck // Handles deprecated in-band errors sent by legacy Cisco devices.
	if protocolErr == nil {
		return errors.New("subscribe response error")
	}
	return fmt.Errorf("subscribe response error: code=%d", protocolErr.GetCode())
}

// sanitizedGNMISubscribeStatusError retains the protocol status code used for
// retry and unsupported-path classification without reflecting device text.
func sanitizedGNMISubscribeStatusError(protocolErr *gnmi.Error) error { //nolint:staticcheck // Handles deprecated in-band errors sent by legacy Cisco devices.
	sanitized := sanitizedGNMISubscribeError(protocolErr)
	if protocolErr == nil {
		return sanitized
	}
	if code := codes.Code(protocolErr.GetCode()); code != codes.OK {
		return &sanitizedGNMIRPCStatus{
			status:                status.New(code, sanitized.Error()),
			authenticationFailure: gnmiStatusIndicatesAuthenticationFailure(code, protocolErr.GetMessage()),
		}
	}
	return sanitized
}
