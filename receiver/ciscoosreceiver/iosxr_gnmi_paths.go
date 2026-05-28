// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"fmt"
	"strings"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
)

func parseGNMIPath(raw string) (*gnmi.Path, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, "/")
	if raw == "" {
		return nil, fmt.Errorf("path cannot be empty")
	}
	parts, err := splitGNMIPathElements(raw)
	if err != nil {
		return nil, err
	}
	out := &gnmi.Path{}
	for i, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("path %q contains an empty element", raw)
		}
		name := part
		if i == 0 {
			if idx := strings.Index(part, ":"); idx > 0 {
				out.Origin = part[:idx]
				name = part[idx+1:]
			}
		}
		elem, err := parseGNMIPathElem(name)
		if err != nil {
			return nil, fmt.Errorf("invalid path element %q in %q: %w", part, raw, err)
		}
		out.Elem = append(out.Elem, elem)
	}
	return out, nil
}

func splitGNMIPathElements(raw string) ([]string, error) {
	parts := []string{}
	depth := 0
	start := 0
	for i, r := range raw {
		switch r {
		case '[':
			depth++
		case ']':
			if depth == 0 {
				return nil, fmt.Errorf("path %q contains an unmatched closing bracket", raw)
			}
			depth--
		case '/':
			if depth == 0 {
				parts = append(parts, raw[start:i])
				start = i + 1
			}
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("path %q contains an unmatched opening bracket", raw)
	}
	parts = append(parts, raw[start:])
	return parts, nil
}

func parseGNMIPathElem(raw string) (*gnmi.PathElem, error) {
	name := raw
	keys := map[string]string{}
	if idx := strings.Index(raw, "["); idx >= 0 {
		name = raw[:idx]
		rest := raw[idx:]
		for rest != "" {
			if !strings.HasPrefix(rest, "[") {
				return nil, fmt.Errorf("unexpected key syntax")
			}
			end := strings.Index(rest, "]")
			if end < 0 {
				return nil, fmt.Errorf("missing closing bracket")
			}
			kv := rest[1:end]
			eq := strings.Index(kv, "=")
			if eq <= 0 {
				return nil, fmt.Errorf("key must be key=value")
			}
			key := strings.TrimSpace(kv[:eq])
			value := stripGNMIPathKeyQuotes(strings.TrimSpace(kv[eq+1:]))
			if key == "" {
				return nil, fmt.Errorf("key cannot be empty")
			}
			keys[key] = value
			rest = rest[end+1:]
		}
	}
	if name == "" {
		return nil, fmt.Errorf("element name cannot be empty")
	}
	if len(keys) == 0 {
		keys = nil
	}
	return &gnmi.PathElem{Name: name, Key: keys}, nil
}

func stripGNMIPathKeyQuotes(value string) string {
	if len(value) < 2 {
		return value
	}
	first := value[0]
	last := value[len(value)-1]
	if (first == '\'' && last == '\'') || (first == '"' && last == '"') {
		return value[1 : len(value)-1]
	}
	return value
}

func encodingNameToGNMI(value string) (gnmi.Encoding, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "json_ietf":
		return gnmi.Encoding_JSON_IETF, true
	case "json":
		return gnmi.Encoding_JSON, true
	case "proto":
		return gnmi.Encoding_PROTO, true
	default:
		return gnmi.Encoding_JSON, false
	}
}

func subscriptionListMode(value string) gnmi.SubscriptionList_Mode {
	switch value {
	case iosXRSubscribeModeOnce:
		return gnmi.SubscriptionList_ONCE
	case iosXRSubscribeModePoll:
		return gnmi.SubscriptionList_POLL
	default:
		return gnmi.SubscriptionList_STREAM
	}
}

func subscriptionStreamMode(value string) gnmi.SubscriptionMode {
	switch value {
	case iosXRStreamModeOnChange:
		return gnmi.SubscriptionMode_ON_CHANGE
	case iosXRStreamModeTargetDefined:
		return gnmi.SubscriptionMode_TARGET_DEFINED
	default:
		return gnmi.SubscriptionMode_SAMPLE
	}
}
