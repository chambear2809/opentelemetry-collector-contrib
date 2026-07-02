// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

func TestSetLogValueRedactsSensitiveFieldsRecursivelyWithoutMutatingSource(t *testing.T) {
	source := map[string]any{
		"message": "authentication failed",
		"nested": map[string]any{
			"api_token": "nested-secret",
			"status":    "failed",
		},
		"events": []any{map[string]any{
			"Authorization": "Bearer secret",
			"eventID":       "event-1",
		}},
	}

	body := pcommon.NewMap()
	setLogValue(body, "payload", source)
	setLogValue(body, "clientPassword", "top-level-secret")

	payload, ok := body.Get("payload")
	require.True(t, ok)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(payload.Str()), &decoded))
	assert.Equal(t, redactedLogValue, decoded["nested"].(map[string]any)["api_token"])
	assert.Equal(t, redactedLogValue, decoded["events"].([]any)[0].(map[string]any)["Authorization"])
	assert.Equal(t, "event-1", decoded["events"].([]any)[0].(map[string]any)["eventID"])
	assert.Equal(t, "nested-secret", source["nested"].(map[string]any)["api_token"])

	topLevel, ok := body.Get("clientPassword")
	require.True(t, ok)
	assert.Equal(t, redactedLogValue, topLevel.Str())
}

func TestSensitiveLogKeyNormalizesVendorKeyStyles(t *testing.T) {
	for _, key := range []string{"password", "api_token", "Private-Key", "sessionID", "auth.cookie", "dbPwd"} {
		assert.True(t, isSensitiveLogKey(key), key)
	}
	for _, key := range []string{"eventID", "username", "sourceIP", "authenticationStatus"} {
		assert.False(t, isSensitiveLogKey(key), key)
	}
}
