// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

func TestDynamicYANGMetricNameIsFramedReversibleAndInjective(t *testing.T) {
	tests := []struct {
		name       string
		module     string
		path       []string
		variant    dynamicYANGMetricVariant
		expected   string
		collidesBy string
	}{
		{
			name:     "punctuation and case",
			module:   "Open-Config",
			path:     []string{"foo-bar", "foo_bar"},
			variant:  dynamicYANGMetricVariantNumber,
			expected: "cisco.iosxr.yang.__v1.m1.s11_Open_2DConfig.p2.s7_foo_2Dbar.s7_foo_5Fbar.n",
		},
		{
			name:     "module absent",
			path:     []string{"counters", "value"},
			variant:  dynamicYANGMetricVariantNumber,
			expected: "cisco.iosxr.yang.__v1.m0.p2.s8_counters.s5_value.n",
		},
		{
			name:     "module present",
			module:   "counters",
			path:     []string{"value"},
			variant:  dynamicYANGMetricVariantNumber,
			expected: "cisco.iosxr.yang.__v1.m1.s8_counters.p1.s5_value.n",
		},
		{
			name:     "info variant",
			module:   "test",
			path:     []string{"state_info"},
			variant:  dynamicYANGMetricVariantInfo,
			expected: "cisco.iosxr.yang.__v1.m1.s4_test.p1.s10_state_5Finfo.i",
		},
	}
	seen := map[string]string{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name, ok := dynamicYANGMetricName("cisco.iosxr.yang", test.module, test.path, test.variant, directGNMIHardMaxMetricNameBytes)
			require.True(t, ok)
			assert.Equal(t, test.expected, name)
			decodedModule, decodedPath, decodedVariant, ok := decodeDynamicYANGMetricNameForTest(name, "cisco.iosxr.yang")
			require.True(t, ok)
			assert.Equal(t, test.module, decodedModule)
			assert.Equal(t, test.path, decodedPath)
			assert.Equal(t, test.variant, decodedVariant)
			if prior, exists := seen[name]; exists {
				t.Fatalf("%s and %s encoded to the same name %q", prior, test.name, name)
			}
			seen[name] = test.name
		})
	}
}

func TestDynamicYANGMetricNameAcceptsExactFinalLimitAndRejectsOneByteLess(t *testing.T) {
	name, ok := dynamicYANGMetricName(
		"cisco.catalyst9800.yang",
		"wireless-rrm-oper",
		[]string{"content", "foo-bar"},
		dynamicYANGMetricVariantNumber,
		directGNMIHardMaxMetricNameBytes,
	)
	require.True(t, ok)
	require.Less(t, len(name), directGNMIHardMaxMetricNameBytes)

	exact, ok := dynamicYANGMetricName(
		"cisco.catalyst9800.yang",
		"wireless-rrm-oper",
		[]string{"content", "foo-bar"},
		dynamicYANGMetricVariantNumber,
		len(name),
	)
	require.True(t, ok)
	assert.Equal(t, name, exact)

	_, ok = dynamicYANGMetricName(
		"cisco.catalyst9800.yang",
		"wireless-rrm-oper",
		[]string{"content", "foo-bar"},
		dynamicYANGMetricVariantNumber,
		len(name)-1,
	)
	assert.False(t, ok)
}

func TestDynamicYANGDialOutMetricNameFramesTupleBoundaries(t *testing.T) {
	first, ok := dynamicYANGDialOutMetricName(
		"cisco.iosxr.yang", "test", []string{"a", "counters"}, []string{"content", "value"}, dynamicYANGMetricVariantNumber, directGNMIHardMaxMetricNameBytes,
	)
	require.True(t, ok)
	assert.Equal(t, "cisco.iosxr.yang.__v1.m1.s4_test.e1.e2.s1_a.s8_counters.p2.s7_content.s5_value.n", first)

	shifted, ok := dynamicYANGDialOutMetricName(
		"cisco.iosxr.yang", "test", []string{"a"}, []string{"counters", "content", "value"}, dynamicYANGMetricVariantNumber, directGNMIHardMaxMetricNameBytes,
	)
	require.True(t, ok)
	require.NotEqual(t, first, shifted)

	absent, ok := dynamicYANGDialOutMetricName(
		"cisco.iosxr.yang", "test", nil, []string{"content", "value"}, dynamicYANGMetricVariantNumber, directGNMIHardMaxMetricNameBytes,
	)
	require.True(t, ok)
	assert.Equal(t, "cisco.iosxr.yang.__v1.m1.s4_test.e0.p2.s7_content.s5_value.n", absent)
	require.NotEqual(t, absent, first)

	info := mustDialOutDynamicYANGName(
		t, "cisco.iosxr.yang", "test", "", "content/value", dynamicYANGMetricVariantInfo,
	)
	assert.Equal(t, "cisco.iosxr.yang.__v1.m1.s4_test.e0.p2.s7_content.s5_value.i", info)
}

func TestCanonicalDynamicYANGNumberIsDeterministicAndExact(t *testing.T) {
	tests := []struct {
		name       string
		metricType pmetric.MetricType
		input      metricNumber
		want       metricNumber
		ok         bool
	}{
		{name: "gauge int", metricType: pmetric.MetricTypeGauge, input: intMetricNumber(42), want: doubleMetricNumber(42), ok: true},
		{name: "gauge double", metricType: pmetric.MetricTypeGauge, input: doubleMetricNumber(1.5), want: doubleMetricNumber(1.5), ok: true},
		{name: "gauge large exact int", metricType: pmetric.MetricTypeGauge, input: intMetricNumber(1 << 60), want: doubleMetricNumber(1 << 60), ok: true},
		{name: "gauge minimum int", metricType: pmetric.MetricTypeGauge, input: intMetricNumber(math.MinInt64), want: doubleMetricNumber(math.MinInt64), ok: true},
		{name: "gauge adjacent inexact int", metricType: pmetric.MetricTypeGauge, input: intMetricNumber(1<<60 + 1)},
		{name: "gauge maximum int rounds out of range", metricType: pmetric.MetricTypeGauge, input: intMetricNumber(math.MaxInt64)},
		{name: "gauge NaN", metricType: pmetric.MetricTypeGauge, input: doubleMetricNumber(math.NaN())},
		{name: "gauge positive infinity", metricType: pmetric.MetricTypeGauge, input: doubleMetricNumber(math.Inf(1))},
		{name: "gauge negative infinity", metricType: pmetric.MetricTypeGauge, input: doubleMetricNumber(math.Inf(-1))},
		{name: "sum int", metricType: pmetric.MetricTypeSum, input: intMetricNumber(42), want: intMetricNumber(42), ok: true},
		{name: "sum exact double", metricType: pmetric.MetricTypeSum, input: doubleMetricNumber(42), want: intMetricNumber(42), ok: true},
		{name: "sum minimum int double", metricType: pmetric.MetricTypeSum, input: doubleMetricNumber(float64(math.MinInt64)), want: intMetricNumber(math.MinInt64), ok: true},
		{name: "sum largest positive float", metricType: pmetric.MetricTypeSum, input: doubleMetricNumber(math.Nextafter(math.Ldexp(1, 63), 0)), want: intMetricNumber(math.MaxInt64 - 1023), ok: true},
		{name: "sum fractional double", metricType: pmetric.MetricTypeSum, input: doubleMetricNumber(1.5)},
		{name: "sum NaN", metricType: pmetric.MetricTypeSum, input: doubleMetricNumber(math.NaN())},
		{name: "sum positive infinity", metricType: pmetric.MetricTypeSum, input: doubleMetricNumber(math.Inf(1))},
		{name: "sum negative infinity", metricType: pmetric.MetricTypeSum, input: doubleMetricNumber(math.Inf(-1))},
		{name: "sum positive two to sixty three", metricType: pmetric.MetricTypeSum, input: doubleMetricNumber(math.Ldexp(1, 63))},
		{name: "sum below minimum int", metricType: pmetric.MetricTypeSum, input: doubleMetricNumber(math.Nextafter(-math.Ldexp(1, 63), math.Inf(-1)))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := canonicalDynamicYANGNumber(test.metricType, test.input)
			assert.Equal(t, test.ok, ok)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestDialOutDynamicYANGPathRetainsEncodingAndContentContainers(t *testing.T) {
	metric := pmetric.NewMetric()
	metric.SetName("cisco.foo-bar")
	dp := metric.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetDoubleValue(1)
	dp.Attributes().PutStr("cisco.yang.source_path", "content/foo-bar")

	path, ok := dialOutDynamicYANGPathParts(metric, metric.Name(), "test-module:outer/counters", false)
	require.True(t, ok)
	assert.Equal(t, []string{"test-module:outer", "counters"}, path.encodingIdentity)
	assert.Equal(t, []string{"content", "foo-bar"}, path.sourceIdentity)
	assert.Equal(t, []string{"outer", "counters", "foo-bar"}, path.normalized)
	assert.Equal(t, []string{"foo-bar"}, path.aliases)

	qualified := pmetric.NewMetric()
	qualified.SetName("cisco.aug:counters.value")
	qualifiedDP := qualified.SetEmptyGauge().DataPoints().AppendEmpty()
	qualifiedDP.SetDoubleValue(1)
	qualifiedDP.Attributes().PutStr("cisco.yang.source_path", "content/aug:counters/value")
	qualifiedPath, ok := dialOutDynamicYANGPathParts(qualified, qualified.Name(), "test-module:root", false)
	require.True(t, ok)
	assert.Equal(t, []string{"test-module:root"}, qualifiedPath.encodingIdentity)
	assert.Equal(t, []string{"content", "aug:counters", "value"}, qualifiedPath.sourceIdentity)
	assert.Equal(t, []string{"root", "counters", "value"}, qualifiedPath.normalized)
	assert.Equal(t, []string{"counters", "value"}, qualifiedPath.aliases)
}

func TestDynamicYANGDialOutIdentityParsers(t *testing.T) {
	for _, test := range []struct {
		name  string
		raw   string
		want  []string
		valid bool
	}{
		{name: "JSON pointer escapes round trip", raw: "foo~0bar/baz~1qux", want: []string{"foo~bar", "baz/qux"}, valid: true},
		{name: "plain punctuation retained", raw: "content/$---", want: []string{"content", "$---"}, valid: true},
		{name: "lone escape", raw: "foo~"},
		{name: "invalid escape", raw: "foo~2bar"},
		{name: "internal empty segment", raw: "foo//bar"},
		{name: "leading empty segment", raw: "/foo"},
		{name: "trailing empty segment", raw: "foo/"},
		{name: "empty", raw: ""},
	} {
		t.Run("source_path/"+test.name, func(t *testing.T) {
			got, ok := decodeDynamicYANGSourcePath(test.raw)
			assert.Equal(t, test.valid, ok)
			assert.Equal(t, test.want, got)
		})
	}

	for _, test := range []struct {
		name           string
		raw            string
		wantIdentity   []string
		wantNormalized []string
		valid          bool
	}{
		{name: "qualified raw and local semantic", raw: "Aug-Module:Root/counters/$", wantIdentity: []string{"Aug-Module:Root", "counters", "$"}, wantNormalized: []string{"Root", "counters", "$"}, valid: true},
		{name: "canonical nonempty", raw: "foo", wantIdentity: []string{"foo"}, wantNormalized: []string{"foo"}, valid: true},
		{name: "absent", raw: "", valid: true},
		{name: "trimmed empty", raw: " / ", valid: true},
		{name: "surrounding whitespace", raw: " foo "},
		{name: "leading slash", raw: "/foo"},
		{name: "trailing slash", raw: "foo/"},
		{name: "surrounding slashes", raw: "/foo/"},
		{name: "internal empty segment", raw: "root//value"},
	} {
		t.Run("encoding_path/"+test.name, func(t *testing.T) {
			identity, normalized, ok := dynamicYANGEncodingPathParts(test.raw)
			assert.Equal(t, test.valid, ok)
			assert.Equal(t, test.wantIdentity, identity)
			assert.Equal(t, test.wantNormalized, normalized)
			if test.valid && len(test.wantIdentity) == 0 {
				name, encoded := dynamicYANGDialOutMetricName("cisco.iosxr.yang", "test", identity, []string{"value"}, dynamicYANGMetricVariantNumber, directGNMIHardMaxMetricNameBytes)
				require.True(t, encoded)
				assert.Contains(t, name, ".e0.p1.")
			}
		})
	}
}

func decodeDynamicYANGMetricNameForTest(name, prefix string) (string, []string, dynamicYANGMetricVariant, bool) {
	encoded, ok := strings.CutPrefix(name, prefix+".__v1.")
	if !ok {
		return "", nil, dynamicYANGMetricVariantUnknown, false
	}
	tokens := strings.Split(encoded, ".")
	index := 0
	module := ""
	if index >= len(tokens) {
		return "", nil, dynamicYANGMetricVariantUnknown, false
	}
	switch tokens[index] {
	case "m0":
		index++
	case "m1":
		index++
		var valid bool
		module, index, valid = decodeDynamicYANGSegmentForTest(tokens, index)
		if !valid {
			return "", nil, dynamicYANGMetricVariantUnknown, false
		}
	default:
		return "", nil, dynamicYANGMetricVariantUnknown, false
	}
	path := make([]string, 0)
	if index < len(tokens) && tokens[index] == "e0" {
		index++
	} else if index < len(tokens) && tokens[index] == "e1" {
		index++
		if index >= len(tokens) || !strings.HasPrefix(tokens[index], "e") {
			return "", nil, dynamicYANGMetricVariantUnknown, false
		}
		count, err := strconv.Atoi(strings.TrimPrefix(tokens[index], "e"))
		if err != nil || count <= 0 {
			return "", nil, dynamicYANGMetricVariantUnknown, false
		}
		index++
		for range count {
			segment, next, valid := decodeDynamicYANGSegmentForTest(tokens, index)
			if !valid {
				return "", nil, dynamicYANGMetricVariantUnknown, false
			}
			path = append(path, segment)
			index = next
		}
	}
	if index >= len(tokens) || !strings.HasPrefix(tokens[index], "p") {
		return "", nil, dynamicYANGMetricVariantUnknown, false
	}
	count, err := strconv.Atoi(strings.TrimPrefix(tokens[index], "p"))
	if err != nil || count <= 0 {
		return "", nil, dynamicYANGMetricVariantUnknown, false
	}
	index++
	for range count {
		segment, next, valid := decodeDynamicYANGSegmentForTest(tokens, index)
		if !valid {
			return "", nil, dynamicYANGMetricVariantUnknown, false
		}
		path = append(path, segment)
		index = next
	}
	if index != len(tokens)-1 {
		return "", nil, dynamicYANGMetricVariantUnknown, false
	}
	switch tokens[index] {
	case "n":
		return module, path, dynamicYANGMetricVariantNumber, true
	case "i":
		return module, path, dynamicYANGMetricVariantInfo, true
	default:
		return "", nil, dynamicYANGMetricVariantUnknown, false
	}
}

func decodeDynamicYANGSegmentForTest(tokens []string, index int) (string, int, bool) {
	if index >= len(tokens) || !strings.HasPrefix(tokens[index], "s") {
		return "", index, false
	}
	lengthText, escaped, found := strings.Cut(strings.TrimPrefix(tokens[index], "s"), "_")
	if !found {
		return "", index, false
	}
	wantLength, err := strconv.Atoi(lengthText)
	if err != nil || wantLength <= 0 {
		return "", index, false
	}
	decoded := make([]byte, 0, wantLength)
	for offset := 0; offset < len(escaped); offset++ {
		if escaped[offset] != '_' {
			decoded = append(decoded, escaped[offset])
			continue
		}
		if offset+2 >= len(escaped) {
			return "", index, false
		}
		value, err := strconv.ParseUint(escaped[offset+1:offset+3], 16, 8)
		if err != nil {
			return "", index, false
		}
		decoded = append(decoded, byte(value))
		offset += 2
	}
	if len(decoded) != wantLength {
		return "", index, false
	}
	return string(decoded), index + 1, true
}

func mustDialOutDynamicYANGName(t *testing.T, prefix, module, encodingPath, sourcePath string, variant dynamicYANGMetricVariant) string {
	t.Helper()
	encoding, _, ok := dynamicYANGEncodingPathParts(encodingPath)
	require.True(t, ok)
	source, ok := decodeDynamicYANGSourcePath(sourcePath)
	require.True(t, ok)
	name, ok := dynamicYANGDialOutMetricName(prefix, module, encoding, source, variant, directGNMIHardMaxMetricNameBytes)
	require.True(t, ok)
	return name
}
