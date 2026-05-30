// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestDashboardTokensAreWellFormed scans every Splunk Observability bundle
// dashboard shipped with the receiver and checks that each SignalFlow
// data('…') token resolves to a metric name the receiver could plausibly emit.
// It guards against serialization leaks like "state.json.mtu" or other tokens
// that contain characters which iosXRMetricName / metricNameCleaner would
// strip, since those tokens will silently render no data in Splunk O11y.
func TestDashboardTokensAreWellFormed(t *testing.T) {
	root := filepath.Join("dashboards", "splunk-o11y")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read dashboards dir: %v", err)
	}

	dataRE := regexp.MustCompile(`data\('([^']+)'`)
	// Allowed characters in any emitted metric name. Receivers route everything
	// through helpers that lower-case and squash non-alphanumerics, so any token
	// containing other characters cannot be produced by the receiver.
	tokenRE := regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)+$`)
	// Tokens with these substrings indicate a JSON/serialization leak.
	bannedSubstrings := []string{".json.", ".list.", ".jsonval.", ".string_val."}

	var bundles []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".bundle.json") {
			continue
		}
		bundles = append(bundles, filepath.Join(root, e.Name()))
	}
	sort.Strings(bundles)

	for _, path := range bundles {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			seen := map[string]struct{}{}
			for _, m := range dataRE.FindAllStringSubmatch(string(body), -1) {
				token := m[1]
				if _, ok := seen[token]; ok {
					continue
				}
				seen[token] = struct{}{}
				if !tokenRE.MatchString(token) {
					t.Errorf("token %q is not a well-formed metric name", token)
					continue
				}
				for _, banned := range bannedSubstrings {
					if strings.Contains(token, banned) {
						t.Errorf("token %q contains serialization-leak segment %q", token, banned)
					}
				}
			}
		})
	}
}
