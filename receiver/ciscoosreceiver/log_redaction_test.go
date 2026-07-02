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
	for _, key := range []string{"password", "api_token", "Private-Key", "sessionID", "auth.cookie", "dbPwd", "shared-key"} {
		assert.True(t, isSensitiveLogKey(key), key)
	}
	for _, key := range []string{"eventID", "username", "sourceIP", "authenticationStatus"} {
		assert.False(t, isSensitiveLogKey(key), key)
	}
}

func TestRedactLogValueHandlesNamedMapAndSliceTypes(t *testing.T) {
	type vendorObject map[string]any
	type vendorObjects []vendorObject
	redacted := redactLogValue(vendorObjects{{
		"name": "event",
		"nested": vendorObject{
			"clientSecret": "do-not-export",
		},
	}}).([]any)

	object := redacted[0].(map[string]any)
	assert.Equal(t, "event", object["name"])
	assert.Equal(t, redactedLogValue, object["nested"].(map[string]any)["clientSecret"])

	body := pcommon.NewMap()
	setLogValue(body, "vendor", vendorObjects{{"sharedKey": "do-not-export"}})
	encoded, ok := body.Get("vendor")
	require.True(t, ok)
	assert.NotContains(t, encoded.Str(), "do-not-export")
	assert.Contains(t, encoded.Str(), redactedLogValue)
}

func TestRedactLogValueBoundsRecursiveControllerValues(t *testing.T) {
	cyclic := map[string]any{}
	cyclic["self"] = cyclic

	redacted := redactLogValue(cyclic)
	encoded, err := json.Marshal(redacted)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), truncatedLogValue)

	var pointerCycle any
	pointerCycle = &pointerCycle
	assert.Equal(t, truncatedLogValue, redactLogValue(pointerCycle))
}
