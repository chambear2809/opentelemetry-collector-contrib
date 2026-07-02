// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeObjectsExtractsISESearchResultJSON(t *testing.T) {
	objects, total, err := decodeObjects([]byte(`{"SearchResult":{"total":2,"resources":[{"name":"nad-1"},{"name":"nad-2"}]}}`))
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	require.Len(t, objects, 2)
	assert.Equal(t, "nad-1", String(objects[0], "name"))
}

func TestDecodeObjectPreservesLargeGenericInteger(t *testing.T) {
	obj, err := decodeObject([]byte(`{"counter":9007199254740993}`))
	require.NoError(t, err)
	number, ok := obj["counter"].(json.Number)
	require.True(t, ok)
	assert.Equal(t, "9007199254740993", number.String())
}

func TestDecodeObjectsExtractsERSXMLResources(t *testing.T) {
	body := []byte(`<SearchResult total="2"><resources><resource><name>nad-1</name><id>1</id></resource><resource><name>nad-2</name><id>2</id></resource></resources></SearchResult>`)
	objects, _, err := decodeObjects(body)
	require.NoError(t, err)
	require.Len(t, objects, 2)
	assert.Equal(t, "nad-2", String(objects[1], "name"))
}

func TestDecodeObjectFlattensMNTXMLCount(t *testing.T) {
	obj, err := decodeObject([]byte(`<sessionCount><count>42</count></sessionCount>`))
	require.NoError(t, err)
	assert.Equal(t, "42", String(obj, "count"))
}

func TestDecodeObjectsExtractsMNTXMLSessionRows(t *testing.T) {
	body := []byte(`<activeSessionList noOfActiveSession="2"><activeSession><user_name>alice</user_name><calling_station_id>00:11:22:33:44:55</calling_station_id></activeSession><activeSession><user_name>bob</user_name><calling_station_id>66:77:88:99:AA:BB</calling_station_id></activeSession></activeSessionList>`)
	objects, total, err := decodeObjects(body)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	require.Len(t, objects, 2)
	assert.Equal(t, "bob", String(objects[1], "user_name"))
}

func TestDataConnectViewSafety(t *testing.T) {
	assert.True(t, ValidDataConnectViewName("RADIUS_AUTHENTICATIONS_WEEK"))
	assert.False(t, ValidDataConnectViewName("RADIUS_AUTHENTICATIONS_WEEK;DROP TABLE USERS"))
	assert.True(t, IsInternalDataConnectView("UPSPOLICYSET"))
	assert.False(t, IsInternalDataConnectView("NETWORK_DEVICES"))
}

func TestObjectHelpersHandleNormalizedNestedObjects(t *testing.T) {
	obj := Object{
		"link":      Object{"href": "https://ise.example.com/ers/config/networkdevice/nad-1"},
		"timestamp": int(1_700_000_000),
	}

	assert.Equal(t, "https://ise.example.com/ers/config/networkdevice/nad-1", String(obj, "link"))
	assert.Equal(t, "https://ise.example.com/ers/config/networkdevice/nad-1", StableID(obj))
	ts, ok := Time(obj, "timestamp")
	require.True(t, ok)
	assert.Equal(t, time.Unix(1_700_000_000, 0).UTC(), ts)
}

func TestStableIDDoesNotUseNonUniqueMessageCode(t *testing.T) {
	assert.Empty(t, StableID(Object{"message_code": "5200"}))
	assert.Empty(t, StableID(Object{"messageCode": "5200"}))
	assert.Equal(t, "event-123", StableID(Object{"message_code": "5200", "event_id": "event-123"}))
	assert.Equal(t, "event-123", StableID(Object{"link": "/events", "message_code": "5200", "event_id": "event-123"}))
	assert.Equal(t, "message-123", StableID(Object{"message_code": "5200", "message_id": "message-123"}))
}
