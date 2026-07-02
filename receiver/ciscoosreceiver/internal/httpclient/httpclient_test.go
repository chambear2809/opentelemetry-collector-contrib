// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"
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

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}
