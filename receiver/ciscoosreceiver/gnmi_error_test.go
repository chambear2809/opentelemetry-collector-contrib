// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"fmt"
	"testing"

	"github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSanitizedGNMIRPCErrorPreservesCodeWithoutRemoteMessage(t *testing.T) {
	const remoteStatusMessage = "device-echoed password=runtime-secret"
	err := sanitizedGNMIRPCError(fmt.Errorf("capabilities: %w", status.Error(codes.Unauthenticated, remoteStatusMessage)))
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.ErrorContains(t, err, "code=Unauthenticated")
	assert.NotContains(t, err.Error(), "sha256")
	assert.NotContains(t, err.Error(), "device-echoed")
	assert.NotContains(t, err.Error(), "runtime-secret")
	assert.Same(t, err, sanitizedGNMIRPCError(err), "sanitization must be idempotent across nested runtime boundaries")
}

func TestClassifySharedGNMIStreamErrorSanitizesUnsupportedStatus(t *testing.T) {
	const remoteStatusMessage = "device-echoed bearer token"
	err := classifySharedGNMIStreamError(status.Error(codes.InvalidArgument, remoteStatusMessage))
	require.Error(t, err)
	var unsupported *sharedGNMIUnsupportedError
	assert.ErrorAs(t, err, &unsupported)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.NotContains(t, err.Error(), "device-echoed")
	assert.NotContains(t, err.Error(), "bearer token")
}

func TestClassifySharedGNMIStreamErrorPreservesNoncanonicalAuthenticationClassification(t *testing.T) {
	const remoteStatusMessage = "device authentication failed with token=runtime-secret"
	err := classifySharedGNMIStreamError(status.Error(codes.Internal, remoteStatusMessage))
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.True(t, isSharedGNMIAuthenticationError(err))
	assert.NotContains(t, err.Error(), "device authentication")
	assert.NotContains(t, err.Error(), "runtime-secret")
}

func TestClassifySharedGNMIStreamErrorDoesNotTreatInvalidArgumentAuthenticationAsUnsupported(t *testing.T) {
	const remoteStatusMessage = "device authentication failed with token=runtime-secret"
	err := classifySharedGNMIStreamError(status.Error(codes.InvalidArgument, remoteStatusMessage))
	require.Error(t, err)
	var unsupported *sharedGNMIUnsupportedError
	assert.NotErrorAs(t, err, &unsupported)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.True(t, isSharedGNMIAuthenticationError(err))
	assert.NotContains(t, err.Error(), "device authentication")
	assert.NotContains(t, err.Error(), "runtime-secret")
}

func TestSanitizedGNMISubscribeErrorDoesNotExposeDeviceMessage(t *testing.T) {
	err := sanitizedGNMISubscribeError(&gnmi.Error{Code: 7, Message: "device-controlled secret"}) //nolint:staticcheck // Exercise legacy in-band gNMI error sanitization.
	require.Error(t, err)
	assert.ErrorContains(t, err, "code=7")
	assert.NotContains(t, err.Error(), "sha256")
	assert.NotContains(t, err.Error(), "device-controlled")
	assert.NotContains(t, err.Error(), "secret")
}

func TestSanitizedGNMISubscribeStatusErrorPreservesCodeWithoutDeviceMessage(t *testing.T) {
	err := sanitizedGNMISubscribeStatusError(&gnmi.Error{Code: uint32(codes.PermissionDenied), Message: "device-controlled secret"}) //nolint:staticcheck // Exercise legacy in-band gNMI error sanitization.
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.NotContains(t, err.Error(), "sha256")
	assert.NotContains(t, err.Error(), "device-controlled")
	assert.NotContains(t, err.Error(), "secret")
}
