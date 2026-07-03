// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// sanitizedGNMISubscribeError preserves stable diagnostic context without
// reflecting a device-controlled error message into collector logs.
func sanitizedGNMISubscribeError(protocolErr *gnmi.Error) error { //nolint:staticcheck // Handles deprecated in-band errors sent by legacy Cisco devices.
	if protocolErr == nil {
		return errors.New("subscribe response error")
	}
	message := []byte(protocolErr.GetMessage())
	fingerprint := sha256.Sum256(message)
	return fmt.Errorf("subscribe response error: code=%d message_length=%d message_sha256=%x", protocolErr.GetCode(), len(message), fingerprint)
}

// sanitizedGNMISubscribeStatusError retains the protocol status code used for
// retry and unsupported-path classification without reflecting device text.
func sanitizedGNMISubscribeStatusError(protocolErr *gnmi.Error) error { //nolint:staticcheck // Handles deprecated in-band errors sent by legacy Cisco devices.
	sanitized := sanitizedGNMISubscribeError(protocolErr)
	if protocolErr == nil {
		return sanitized
	}
	if code := codes.Code(protocolErr.GetCode()); code != codes.OK {
		return status.Error(code, sanitized.Error())
	}
	return sanitized
}
