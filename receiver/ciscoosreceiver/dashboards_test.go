// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestDashboardTokensAreWellFormed scans every Splunk Observability bundle
// dashboard shipped with the receiver and checks that each SignalFlow data('...')
// token is shaped like either a Cisco receiver metric name or an accepted
// Prometheus/OpenMetrics name used by adjacent Cisco AI POD integrations.
// It guards against serialization leaks like "state.json.mtu" that will
// silently render no data in Splunk O11y.
func TestDashboardTokensAreWellFormed(t *testing.T) {
	root := filepath.Join("dashboards", "splunk-o11y")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read dashboards dir: %v", err)
	}

	dataRE := regexp.MustCompile(`data\('([^']+)'`)
	// Allowed characters for Cisco receiver metric names and Prometheus metric
	// names used by storage integrations. Prometheus allows underscores, colons,
	// and mixed case; Cisco receiver names remain lower-case dotted tokens.
	tokenRE := regexp.MustCompile(`^[A-Za-z_:][A-Za-z0-9_:]*(\.[A-Za-z0-9_:]+)*$`)
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
			var bundle struct {
				Dashboards []struct {
					Name   string            `json:"name"`
					Charts []json.RawMessage `json:"charts"`
				} `json:"dashboards"`
			}
			if err := json.Unmarshal(body, &bundle); err != nil {
				t.Fatalf("decode %s as JSON: %v", path, err)
			}
			if len(bundle.Dashboards) == 0 {
				t.Fatalf("%s does not contain any dashboards", path)
			}
			for _, dashboard := range bundle.Dashboards {
				if strings.TrimSpace(dashboard.Name) == "" {
					t.Errorf("%s contains a dashboard without a name", path)
				}
				if len(dashboard.Charts) == 0 {
					t.Errorf("dashboard %q in %s does not contain any charts", dashboard.Name, path)
				}
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
