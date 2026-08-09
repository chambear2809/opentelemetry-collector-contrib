// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

const gnmiIOSXEJSONIETFMaximumKeyBytes = 4 * 1024

type iosXEJSONIETFQuotedKeyProfile struct {
	elements []string
	keys     map[string]struct{}
}

// iosXESwitchJSONIETFQuotedKeyProfiles is intentionally narrower than every
// RFC7951 path a custom subscription may request. A key is normalized only
// when the complete ancestry through its list element exactly matches an IOS
// XE switch identity probe or built-in path. A custom path with the same module,
// list, or key names therefore keeps standard gNMI PathElem string semantics.
var iosXESwitchJSONIETFQuotedKeyProfiles = []iosXEJSONIETFQuotedKeyProfile{
	{
		elements: []string{
			"Cisco-IOS-XE-device-hardware-oper:device-hardware-data",
			"device-hardware",
			"device-inventory",
		},
		keys: map[string]struct{}{"hw-type": {}, "hw-dev-index": {}},
	},
	{
		elements: []string{
			"Cisco-IOS-XE-install-oper:install-oper-data",
			"install-location-information",
		},
		keys: map[string]struct{}{"fru": {}, "slot": {}, "bay": {}, "chassis": {}},
	},
	{
		elements: []string{
			"Cisco-IOS-XE-install-oper:install-oper-data",
			"install-location-information",
			"install-version-info",
		},
		keys: map[string]struct{}{"version": {}, "version-extension": {}},
	},
	{
		elements: []string{
			"Cisco-IOS-XE-platform-software-oper:cisco-platform-software",
			"control-processes",
			"control-process",
		},
		keys: map[string]struct{}{"fru": {}, "slot": {}, "bay": {}, "chassis": {}},
	},
	{
		elements: []string{
			"Cisco-IOS-XE-transceiver-oper:transceiver-oper-data",
			"transceiver",
		},
		keys: map[string]struct{}{"name": {}},
	},
	{
		elements: []string{"openconfig-interfaces:interfaces", "interface"},
		keys:     map[string]struct{}{"name": {}},
	},
}

// canonicalizeIOSXERFC7951JSONIETFWireNotificationKeys runs before decoding.
// That ordering is essential: the decoder performs final-update-wins
// deduplication and reconciles list keys inside aggregated JSON objects.
// Canonicalizing afterward could make two retained paths collapse or reject a
// quoted PathElem key that refers to an unquoted JSON list-key leaf.
func canonicalizeIOSXERFC7951JSONIETFWireNotificationKeys(notification *gnmipb.Notification) error {
	if notification == nil {
		return nil
	}
	canonicalized := make(map[*gnmipb.PathElem]struct{})
	hasRelativePath := false
	for _, update := range notification.GetUpdate() {
		if update == nil {
			continue
		}
		hasRelativePath = true
		origin, compatible := iosXEJSONIETFEffectivePathOrigin(notification.GetPrefix(), update.GetPath())
		if compatible && origin == builtinGNMIOriginRFC7951 {
			if err := canonicalizeIOSXEJSONIETFProtoPathKeys(
				notification.GetPrefix(), update.GetPath(), canonicalized,
			); err != nil {
				return err
			}
		}
	}
	for _, deleted := range notification.GetDelete() {
		hasRelativePath = true
		origin, compatible := iosXEJSONIETFEffectivePathOrigin(notification.GetPrefix(), deleted)
		if compatible && origin == builtinGNMIOriginRFC7951 {
			if err := canonicalizeIOSXEJSONIETFProtoPathKeys(
				notification.GetPrefix(), deleted, canonicalized,
			); err != nil {
				return err
			}
		}
	}
	// A notification normally has updates or deletes whose complete effective
	// paths authorize canonicalization. Keep accepting a prefix-only
	// notification for the bounded pre-decode helper and its direct tests, but
	// do not use a prefix in isolation when the wire notification supplied
	// relative paths with conflicting origins.
	if !hasRelativePath && notification.GetPrefix().GetOrigin() == builtinGNMIOriginRFC7951 {
		if err := canonicalizeIOSXEJSONIETFProtoPathKeys(
			notification.GetPrefix(), nil, canonicalized,
		); err != nil {
			return err
		}
	}
	return nil
}

func iosXEJSONIETFEffectivePathOrigin(prefix, relative *gnmipb.Path) (string, bool) {
	prefixOrigin := prefix.GetOrigin()
	relativeOrigin := relative.GetOrigin()
	if prefixOrigin != "" && relativeOrigin != "" && prefixOrigin != relativeOrigin {
		return "", false
	}
	if relativeOrigin != "" {
		return relativeOrigin, true
	}
	return prefixOrigin, true
}

func canonicalizeIOSXEJSONIETFProtoPathKeys(
	prefix, relative *gnmipb.Path,
	canonicalized map[*gnmipb.PathElem]struct{},
) error {
	prefixElements := prefix.GetElem()
	relativeElements := relative.GetElem()
	elementCount := len(prefixElements) + len(relativeElements)
	elementAt := func(index int) *gnmipb.PathElem {
		if index < len(prefixElements) {
			return prefixElements[index]
		}
		return relativeElements[index-len(prefixElements)]
	}
	for _, profile := range iosXESwitchJSONIETFQuotedKeyProfiles {
		if elementCount < len(profile.elements) {
			continue
		}
		matches := true
		for index, expected := range profile.elements {
			element := elementAt(index)
			if element == nil || element.GetName() != expected {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		listElement := elementAt(len(profile.elements) - 1)
		if _, ok := canonicalized[listElement]; ok {
			continue
		}
		// JSON string decoding cannot be intrinsically idempotent for keys
		// whose legitimate value begins with a quote. Once "\"port\"" has
		// become the literal value "port", decoding that value again would
		// either collapse it to port or reject it. PathElem identity gives the
		// required notification-local exactly-once boundary while still using
		// each combined prefix and relative ancestry for authorization.
		canonicalized[listElement] = struct{}{}
		if err := canonicalizeIOSXEJSONIETFKeyMap(listElement.GetKey(), profile.keys); err != nil {
			return err
		}
	}
	return nil
}

func canonicalizeIOSXEJSONIETFKeyMap(keys map[string]string, allowed map[string]struct{}) error {
	for name, raw := range keys {
		if _, ok := allowed[name]; !ok {
			continue
		}
		value, changed, err := canonicalIOSXEJSONIETFKeyValue(raw)
		if err != nil {
			return err
		}
		if changed {
			keys[name] = value
		}
	}
	return nil
}

func canonicalIOSXEJSONIETFKeyValue(raw string) (string, bool, error) {
	if len(raw) > gnmiIOSXEJSONIETFMaximumKeyBytes {
		return "", false, errors.New("IOS XE JSON_IETF list key exceeds the bounded key size")
	}
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(trimmed, `"`) {
		return raw, false, nil
	}
	if err := validateIOSXEJSONIETFStringScalars(trimmed); err != nil {
		return "", false, err
	}
	var value string
	if err := json.Unmarshal([]byte(trimmed), &value); err != nil {
		return "", false, errors.New("IOS XE JSON_IETF list key is not one valid JSON string")
	}
	return value, true, nil
}

// encoding/json deliberately replaces malformed UTF-8 and unpaired UTF-16
// surrogate escapes with U+FFFD. That is appropriate for general-purpose JSON
// decoding, but not for a path key: replacement would make distinct wire keys
// collide before final-update-wins and delete reconciliation. Reject those
// representations before unquoting. json.Unmarshal remains the authority for
// all other JSON string grammar, including escaped solidus.
func validateIOSXEJSONIETFStringScalars(raw string) error {
	if !utf8.ValidString(raw) {
		return errors.New("IOS XE JSON_IETF list key is not one valid JSON string")
	}
	for index := 0; index < len(raw); index++ {
		if raw[index] != '\\' {
			continue
		}
		if index+1 >= len(raw) {
			return errors.New("IOS XE JSON_IETF list key is not one valid JSON string")
		}
		if raw[index+1] != 'u' {
			index++
			continue
		}

		codeUnit, ok := iosXEJSONIETFHexCodeUnit(raw, index+2)
		if !ok {
			return errors.New("IOS XE JSON_IETF list key is not one valid JSON string")
		}
		index += 5
		switch {
		case codeUnit >= 0xd800 && codeUnit <= 0xdbff:
			pairStart := index + 1
			if pairStart+5 >= len(raw) || raw[pairStart] != '\\' || raw[pairStart+1] != 'u' {
				return errors.New("IOS XE JSON_IETF list key is not one valid JSON string")
			}
			lowSurrogate, pairOK := iosXEJSONIETFHexCodeUnit(raw, pairStart+2)
			if !pairOK || lowSurrogate < 0xdc00 || lowSurrogate > 0xdfff {
				return errors.New("IOS XE JSON_IETF list key is not one valid JSON string")
			}
			index = pairStart + 5
		case codeUnit >= 0xdc00 && codeUnit <= 0xdfff:
			return errors.New("IOS XE JSON_IETF list key is not one valid JSON string")
		}
	}
	return nil
}

func iosXEJSONIETFHexCodeUnit(raw string, start int) (uint16, bool) {
	if start < 0 || start+4 > len(raw) {
		return 0, false
	}
	var value uint16
	for index := start; index < start+4; index++ {
		value <<= 4
		switch character := raw[index]; {
		case character >= '0' && character <= '9':
			value |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}
