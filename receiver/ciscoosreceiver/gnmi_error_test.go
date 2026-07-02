// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"testing"

	"github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizedGNMISubscribeErrorDoesNotExposeDeviceMessage(t *testing.T) {
	err := sanitizedGNMISubscribeError(&gnmi.Error{Code: 7, Message: "device-controlled secret"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "code=7")
	assert.ErrorContains(t, err, "message_length=24")
	assert.ErrorContains(t, err, "message_sha256=")
	assert.NotContains(t, err.Error(), "device-controlled")
	assert.NotContains(t, err.Error(), "secret")
}
