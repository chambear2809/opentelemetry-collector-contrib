// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/openconfig/gnmi/proto/gnmi"
)

// sanitizedGNMISubscribeError preserves stable diagnostic context without
// reflecting a device-controlled error message into collector logs.
func sanitizedGNMISubscribeError(protocolErr *gnmi.Error) error { //nolint:staticcheck // Deprecated response errors remain required for older gNMI producers.
	if protocolErr == nil {
		return errors.New("subscribe response error")
	}
	message := []byte(protocolErr.GetMessage())
	fingerprint := sha256.Sum256(message)
	return fmt.Errorf("subscribe response error: code=%d message_length=%d message_sha256=%x", protocolErr.GetCode(), len(message), fingerprint)
}
