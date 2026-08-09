// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"encoding/json"
	"strings"
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

func TestDecodeObjectWrapsTopLevelJSONScalars(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
		want string
	}{
		{name: "number", body: `42`, want: "42"},
		{name: "string", body: `"enabled"`, want: "enabled"},
		{name: "boolean", body: `true`, want: "true"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			obj, err := decodeObject([]byte(tt.body))
			require.NoError(t, err)
			assert.Equal(t, tt.want, String(obj, "value"))
		})
	}
}

func TestDecodeObjectRejectsTopLevelJSONArray(t *testing.T) {
	_, err := decodeObject([]byte(`[{"id":"one"}]`))
	require.ErrorContains(t, err, "expected a JSON object or scalar")
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

func TestDecodeObjectsHandlesCurrentMNTActiveListAndEmptyList(t *testing.T) {
	objects, total, err := decodeObjects([]byte(`<activeList noOfActiveSession="1"><activeSession><user_name>alice</user_name></activeSession></activeList>`))
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, objects, 1)
	assert.Equal(t, "alice", String(objects[0], "user_name"))

	objects, total, err = decodeObjects([]byte(`<activeList noOfActiveSession="0"></activeList>`))
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, objects)
}

func TestDecodeXMLObjectRejectsUnsafeDepthBeforeMaterializing(t *testing.T) {
	body := []byte(strings.Repeat("<n>", hardMaxXMLDepth+1) + strings.Repeat("</n>", hardMaxXMLDepth+1))
	_, err := decodeXMLObject(body)
	require.ErrorContains(t, err, "XML response exceeds hard depth limit")
	var limitErr *xmlComplexityLimitError
	require.ErrorAs(t, err, &limitErr)
}

func TestValidateXMLComplexityBoundaries(t *testing.T) {
	base := xmlComplexityLimits{depth: 4, tokens: 20, elements: 4, attributes: 4}
	tests := []struct {
		name   string
		body   string
		limits xmlComplexityLimits
		err    string
	}{
		{name: "at depth boundary", body: `<a><b/></a>`, limits: xmlComplexityLimits{depth: 2, tokens: 4, elements: 2, attributes: 1}},
		{name: "over depth", body: `<a><b><c/></b></a>`, limits: xmlComplexityLimits{depth: 2, tokens: 10, elements: 4, attributes: 1}, err: "depth limit"},
		{name: "over tokens", body: `<a/>`, limits: xmlComplexityLimits{depth: 2, tokens: 1, elements: 2, attributes: 1}, err: "token limit"},
		{name: "over elements", body: `<a><b/></a>`, limits: xmlComplexityLimits{depth: 3, tokens: 10, elements: 1, attributes: 1}, err: "element limit"},
		{name: "over attributes", body: `<a x="1" y="2"/>`, limits: xmlComplexityLimits{depth: 2, tokens: 10, elements: 2, attributes: 1}, err: "attribute limit"},
		{name: "malformed", body: `<a>`, limits: base, err: "unexpected EOF"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateXMLComplexityWithLimits([]byte(tt.body), tt.limits)
			if tt.err == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.err)
		})
	}
}

func TestDecodeXMLObjectAcceptsDeclarationAndNamespace(t *testing.T) {
	obj, err := decodeXMLObject([]byte(`<?xml version="1.0"?><ise:SearchResult xmlns:ise="urn:cisco:ise" total="1"><ise:resource><ise:name>nad-1</ise:name></ise:resource></ise:SearchResult>`))
	require.NoError(t, err)
	root, ok := obj["SearchResult"].(Object)
	require.True(t, ok)
	assert.Equal(t, "1", String(root, "@total"))
	resource, ok := root["resource"].(Object)
	require.True(t, ok)
	assert.Equal(t, "nad-1", String(resource, "name"))
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
