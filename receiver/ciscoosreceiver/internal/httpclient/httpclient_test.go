// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadResponseBody(t *testing.T) {
	t.Run("at limit", func(t *testing.T) {
		body := bytes.Repeat([]byte{'a'}, int(MaxResponseBodySize))
		got, err := ReadResponseBody(bytes.NewReader(body))
		require.NoError(t, err)
		assert.Equal(t, body, got)
	})

	t.Run("over limit", func(t *testing.T) {
		body := bytes.Repeat([]byte{'a'}, int(MaxResponseBodySize)+1)
		got, err := ReadResponseBody(bytes.NewReader(body))
		require.ErrorIs(t, err, ErrResponseBodyTooLarge)
		assert.Nil(t, got)
	})

	t.Run("read error", func(t *testing.T) {
		wantErr := errors.New("read failed")
		got, err := ReadResponseBody(errorReader{err: wantErr})
		require.ErrorIs(t, err, wantErr)
		assert.Nil(t, got)
	})
}

func TestDecodeJSONPreservesGenericIntegersAndRejectsTrailingValues(t *testing.T) {
	var decoded map[string]any
	require.NoError(t, DecodeJSON([]byte(`{"counter":9007199254740993}`), &decoded))
	number, ok := decoded["counter"].(json.Number)
	require.True(t, ok)
	assert.Equal(t, "9007199254740993", number.String())

	assert.Error(t, DecodeJSON([]byte(`{"counter":1} {"counter":2}`), &decoded))
}

func TestDecodeJSONRejectsComplexityBeforeTargetDecode(t *testing.T) {
	t.Run("depth", func(t *testing.T) {
		input := strings.Repeat("[", HardMaxJSONDepth+1) + "0" + strings.Repeat("]", HardMaxJSONDepth+1)
		var target jsonDecodeProbe
		err := DecodeJSON([]byte(input), &target)
		var limitErr *JSONComplexityLimitError
		require.ErrorAs(t, err, &limitErr)
		assert.Equal(t, "depth", limitErr.Kind)
		assert.False(t, target.called)
	})

	t.Run("many empty objects", func(t *testing.T) {
		var input bytes.Buffer
		input.Grow(HardMaxJSONTokens*2 + 2)
		input.WriteByte('[')
		for i := 0; i < HardMaxJSONTokens/2+1; i++ {
			if i > 0 {
				input.WriteByte(',')
			}
			input.WriteString("{}")
		}
		input.WriteByte(']')

		var target jsonDecodeProbe
		err := DecodeJSON(input.Bytes(), &target)
		var limitErr *JSONComplexityLimitError
		require.ErrorAs(t, err, &limitErr)
		assert.Equal(t, "token", limitErr.Kind)
		assert.False(t, target.called)
	})

	t.Run("nodes", func(t *testing.T) {
		var input bytes.Buffer
		input.Grow(HardMaxJSONNodes*2 + 2)
		input.WriteByte('[')
		for i := 0; i < HardMaxJSONNodes; i++ {
			if i > 0 {
				input.WriteByte(',')
			}
			input.WriteByte('0')
		}
		input.WriteByte(']')

		var target jsonDecodeProbe
		err := DecodeJSON(input.Bytes(), &target)
		var limitErr *JSONComplexityLimitError
		require.ErrorAs(t, err, &limitErr)
		assert.Equal(t, "node", limitErr.Kind)
		assert.False(t, target.called)
	})
}

func TestRetryCountPreservesZeroAndRejectsUnsafeValues(t *testing.T) {
	retries, err := RetryCount(0)
	require.NoError(t, err)
	assert.Zero(t, retries)

	retries, err = RetryCount(HardMaxRequestRetries)
	require.NoError(t, err)
	assert.Equal(t, HardMaxRequestRetries, retries)

	_, err = RetryCount(-1)
	assert.Error(t, err)
	_, err = RetryCount(HardMaxRequestRetries + 1)
	assert.Error(t, err)
}

func TestSameOriginRedirectPolicy(t *testing.T) {
	origin, err := url.Parse("https://api.example.test/base")
	require.NoError(t, err)
	policy := SameOriginRedirectPolicy(origin)

	sameOrigin, err := http.NewRequest(http.MethodGet, "https://api.example.test/next", http.NoBody)
	require.NoError(t, err)
	require.NoError(t, policy(sameOrigin, []*http.Request{{}}))

	crossOrigin, err := http.NewRequest(http.MethodGet, "https://attacker.example/next", http.NoBody)
	require.NoError(t, err)
	assert.ErrorIs(t, policy(crossOrigin, []*http.Request{{}}), http.ErrUseLastResponse)

	downgrade, err := http.NewRequest(http.MethodGet, "http://api.example.test/next", http.NoBody)
	require.NoError(t, err)
	assert.ErrorIs(t, policy(downgrade, []*http.Request{{}}), http.ErrUseLastResponse)
}

func TestStatusErrorDoesNotExposeResponseBody(t *testing.T) {
	message := StatusError("controller", http.StatusUnauthorized)
	assert.Equal(t, "controller API returned HTTP 401", message)
	assert.NotContains(t, message, "password")
}

func TestNextLinkParsesRFC8288RelationsAndURICommas(t *testing.T) {
	header := `</items?filter=a,b&cursor=next>; title="quoted,value"; rel="prev next", </items?cursor=last>; rel="last"`
	assert.Equal(t, "/items?filter=a,b&cursor=next", NextLink(header))
	assert.Empty(t, NextLink(`</items?cursor=wrong>; rel="next-page"`))
	assert.Equal(t, "/items?cursor=bare", NextLink(`</items?cursor=bare>; rel=NEXT`))
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

type jsonDecodeProbe struct {
	called bool
}

func (p *jsonDecodeProbe) UnmarshalJSON([]byte) error {
	p.called = true
	return nil
}
