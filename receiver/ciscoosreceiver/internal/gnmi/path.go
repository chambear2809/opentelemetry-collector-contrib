// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

const (
	maxPathDepth          = 128
	maxPathNameBytes      = 256
	maxPathKeysPerElement = 64
	maxPathKeyValueBytes  = 4 * 1024
	maxCanonicalPathBytes = 64 * 1024
)

// ParsePath parses path elements while taking target and origin as distinct
// arguments. A colon in an element name is retained (for example RFC7951
// module-qualified names) and is never interpreted as an origin separator.
func ParsePath(target, origin, raw string) (Path, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, "/")
	if raw == "" {
		return Path{}, errors.New("path cannot be empty")
	}
	parts, err := splitPath(raw)
	if err != nil {
		return Path{}, err
	}
	out := Path{Target: target, Origin: origin, Elements: make([]PathElem, 0, len(parts))}
	for _, part := range parts {
		elem, err := parsePathElem(part)
		if err != nil {
			return Path{}, fmt.Errorf("invalid path element %q: %w", part, err)
		}
		out.Elements = append(out.Elements, elem)
	}
	if _, err := validatePath(out); err != nil {
		return Path{}, err
	}
	return out, nil
}

// PathFromProto converts a protobuf path without merging target or origin into
// its element names. The deprecated Element representation remains supported.
//
//nolint:staticcheck // Element is deprecated but remains part of the supported gNMI wire format.
func PathFromProto(path *gnmipb.Path) Path {
	if path == nil {
		return Path{}
	}
	out := Path{PathTarget: path.GetTarget(), Origin: path.GetOrigin()}
	if len(path.GetElem()) > 0 {
		out.Elements = make([]PathElem, 0, len(path.GetElem()))
		for _, elem := range path.GetElem() {
			if elem == nil {
				continue
			}
			out.Elements = append(out.Elements, PathElem{Name: elem.GetName(), Keys: cloneStrings(elem.GetKey())})
		}
		return out
	}
	out.Elements = make([]PathElem, 0, len(path.GetElement()))
	for _, name := range path.GetElement() {
		out.Elements = append(out.Elements, PathElem{Name: name})
	}
	return out
}

// validatedPathFromProto rejects unsafe wire paths before cloning their maps
// or retaining any of their strings. PathFromProto remains available for
// trusted, already-bounded internal round trips.
func validatedPathFromProto(path *gnmipb.Path) (Path, int, error) {
	bytes, err := validateProtoPath(path)
	if err != nil {
		return Path{}, 0, err
	}
	return PathFromProto(path), bytes, nil
}

// validateProtoPath mirrors PathFromProto's Elem-over-Element precedence while
// operating directly on protobuf-owned data. This must run before map cloning.
//
//nolint:staticcheck // Element is deprecated but remains part of the supported gNMI wire format.
func validateProtoPath(path *gnmipb.Path) (int, error) {
	if path == nil {
		return canonicalPathFixedBytes("", "", ""), nil
	}
	bytes := canonicalPathFixedBytes("", path.GetTarget(), path.GetOrigin())
	if bytes > maxCanonicalPathBytes {
		return 0, fmt.Errorf("path exceeds %d canonical bytes", maxCanonicalPathBytes)
	}
	if len(path.GetElem()) > 0 {
		if len(path.GetElem()) > maxPathDepth {
			return 0, fmt.Errorf("path exceeds %d elements", maxPathDepth)
		}
		for _, elem := range path.GetElem() {
			if elem == nil {
				continue
			}
			var err error
			bytes, err = addValidatedPathElementBytes(bytes, elem.GetName(), elem.GetKey())
			if err != nil {
				return 0, err
			}
		}
		return bytes, nil
	}
	if len(path.GetElement()) > maxPathDepth {
		return 0, fmt.Errorf("path exceeds %d elements", maxPathDepth)
	}
	for _, name := range path.GetElement() {
		var err error
		bytes, err = addValidatedPathElementBytes(bytes, name, nil)
		if err != nil {
			return 0, err
		}
	}
	return bytes, nil
}

// validatePath returns the exact number of bytes Path.Key will allocate for a
// canonical path. It performs no cloning and never calls Path.Key itself.
func validatePath(path Path) (int, error) {
	if len(path.Elements) > maxPathDepth {
		return 0, fmt.Errorf("path exceeds %d elements", maxPathDepth)
	}
	bytes := canonicalPathFixedBytes(path.Target, path.PathTarget, path.Origin)
	if bytes > maxCanonicalPathBytes {
		return 0, fmt.Errorf("path exceeds %d canonical bytes", maxCanonicalPathBytes)
	}
	for _, elem := range path.Elements {
		var err error
		bytes, err = addValidatedPathElementBytes(bytes, elem.Name, elem.Keys)
		if err != nil {
			return 0, err
		}
	}
	return bytes, nil
}

// validateSeries applies the same limits without constructing Series.Path,
// which would otherwise clone every key map before validation.
func validateSeries(series Series) (int, error) {
	if len(series.Elements)+1 > maxPathDepth {
		return 0, fmt.Errorf("path exceeds %d elements", maxPathDepth)
	}
	bytes := canonicalPathFixedBytes(series.Target, series.PathTarget, series.Origin)
	if bytes > maxCanonicalPathBytes {
		return 0, fmt.Errorf("path exceeds %d canonical bytes", maxCanonicalPathBytes)
	}
	for _, elem := range series.Elements {
		var err error
		bytes, err = addValidatedPathElementBytes(bytes, elem.Name, elem.Keys)
		if err != nil {
			return 0, err
		}
	}
	return addValidatedPathElementBytes(bytes, series.Leaf, nil)
}

// ValidatePath verifies that an already-canonical path fits the same depth,
// element, key, and retained-key byte limits enforced during wire decoding.
func ValidatePath(path Path) error {
	_, err := validatePath(path)
	return err
}

// ValidateSeries verifies an already-canonical source series without cloning
// its element key maps.
func ValidateSeries(series Series) error {
	_, err := validateSeries(series)
	return err
}

func canonicalPathFixedBytes(target, pathTarget, origin string) int {
	return canonicalKeyPartBytes(target) + canonicalKeyPartBytes(pathTarget) + canonicalKeyPartBytes(origin)
}

func addValidatedPathElementBytes(current int, name string, keys map[string]string) (int, error) {
	if name == "" {
		return 0, errors.New("path element name cannot be empty")
	}
	if len(name) > maxPathNameBytes {
		return 0, fmt.Errorf("path element name exceeds %d bytes", maxPathNameBytes)
	}
	if len(keys) > maxPathKeysPerElement {
		return 0, fmt.Errorf("path element %q exceeds %d keys", name, maxPathKeysPerElement)
	}
	current += canonicalKeyPartBytes(name)
	for key, value := range keys {
		if key == "" {
			return 0, fmt.Errorf("path element %q contains an empty key name", name)
		}
		if len(key) > maxPathNameBytes {
			return 0, fmt.Errorf("path key name exceeds %d bytes", maxPathNameBytes)
		}
		if len(value) > maxPathKeyValueBytes {
			return 0, fmt.Errorf("path key %q value exceeds %d bytes", key, maxPathKeyValueBytes)
		}
		current += canonicalKeyPartBytes(key) + canonicalKeyPartBytes(value)
		if current > maxCanonicalPathBytes {
			return 0, fmt.Errorf("path exceeds %d canonical bytes", maxCanonicalPathBytes)
		}
	}
	// Path.Key writes an empty part after every element to delimit its key set.
	current += canonicalKeyPartBytes("")
	if current > maxCanonicalPathBytes {
		return 0, fmt.Errorf("path exceeds %d canonical bytes", maxCanonicalPathBytes)
	}
	return current, nil
}

func canonicalKeyPartBytes(value string) int {
	length := len(value)
	digits := 1
	for remaining := length; remaining >= 10; remaining /= 10 {
		digits++
	}
	return digits + 1 + length
}

// validateJoinedPath checks a combined canonical path without cloning either
// side's key maps.
func validateJoinedPath(prefix, relative Path) (int, error) {
	if prefix.Target != "" && relative.Target != "" && prefix.Target != relative.Target {
		return 0, fmt.Errorf("conflicting configured targets %q and %q", prefix.Target, relative.Target)
	}
	if prefix.PathTarget != "" && relative.PathTarget != "" && prefix.PathTarget != relative.PathTarget {
		return 0, fmt.Errorf("conflicting gNMI path targets %q and %q", prefix.PathTarget, relative.PathTarget)
	}
	if prefix.Origin != "" && relative.Origin != "" && prefix.Origin != relative.Origin {
		return 0, fmt.Errorf("conflicting path origins %q and %q", prefix.Origin, relative.Origin)
	}
	target := prefix.Target
	if relative.Target != "" {
		target = relative.Target
	}
	pathTarget := prefix.PathTarget
	if relative.PathTarget != "" {
		pathTarget = relative.PathTarget
	}
	origin := prefix.Origin
	if relative.Origin != "" {
		origin = relative.Origin
	}
	if len(prefix.Elements)+len(relative.Elements) > maxPathDepth {
		return 0, fmt.Errorf("path exceeds %d elements", maxPathDepth)
	}
	bytes := canonicalPathFixedBytes(target, pathTarget, origin)
	if bytes > maxCanonicalPathBytes {
		return 0, fmt.Errorf("path exceeds %d canonical bytes", maxCanonicalPathBytes)
	}
	for _, elements := range [][]PathElem{prefix.Elements, relative.Elements} {
		for _, elem := range elements {
			var err error
			bytes, err = addValidatedPathElementBytes(bytes, elem.Name, elem.Keys)
			if err != nil {
				return 0, err
			}
		}
	}
	return bytes, nil
}

func validateAppendedPathElement(path Path, name string, keys map[string]string) (int, error) {
	if len(path.Elements)+1 > maxPathDepth {
		return 0, fmt.Errorf("path exceeds %d elements", maxPathDepth)
	}
	bytes, err := validatePath(path)
	if err != nil {
		return 0, err
	}
	return addValidatedPathElementBytes(bytes, name, keys)
}

func validateReplacedLastPathElement(path Path, keys map[string]string) (int, error) {
	if len(path.Elements) == 0 {
		return 0, errors.New("path has no element to replace")
	}
	bytes := canonicalPathFixedBytes(path.Target, path.PathTarget, path.Origin)
	if bytes > maxCanonicalPathBytes {
		return 0, fmt.Errorf("path exceeds %d canonical bytes", maxCanonicalPathBytes)
	}
	for index, elem := range path.Elements {
		if index == len(path.Elements)-1 {
			elem.Keys = keys
		}
		var err error
		bytes, err = addValidatedPathElementBytes(bytes, elem.Name, elem.Keys)
		if err != nil {
			return 0, err
		}
	}
	return bytes, nil
}

// ToProto returns a deep protobuf representation of the canonical path.
func (p Path) ToProto() *gnmipb.Path {
	out := &gnmipb.Path{Target: p.PathTarget, Origin: p.Origin, Elem: make([]*gnmipb.PathElem, 0, len(p.Elements))}
	for _, elem := range p.Elements {
		out.Elem = append(out.Elem, &gnmipb.PathElem{Name: elem.Name, Key: cloneStrings(elem.Keys)})
	}
	return out
}

// JoinPaths combines a notification prefix and relative update path. Conflicting
// non-empty targets or origins are rejected instead of silently producing an
// ambiguous path.
func JoinPaths(prefix, relative Path) (Path, error) {
	if prefix.Target != "" && relative.Target != "" && prefix.Target != relative.Target {
		return Path{}, fmt.Errorf("conflicting configured targets %q and %q", prefix.Target, relative.Target)
	}
	if prefix.PathTarget != "" && relative.PathTarget != "" && prefix.PathTarget != relative.PathTarget {
		return Path{}, fmt.Errorf("conflicting gNMI path targets %q and %q", prefix.PathTarget, relative.PathTarget)
	}
	if prefix.Origin != "" && relative.Origin != "" && prefix.Origin != relative.Origin {
		return Path{}, fmt.Errorf("conflicting path origins %q and %q", prefix.Origin, relative.Origin)
	}
	target := prefix.Target
	if relative.Target != "" {
		target = relative.Target
	}
	pathTarget := prefix.PathTarget
	if relative.PathTarget != "" {
		pathTarget = relative.PathTarget
	}
	origin := prefix.Origin
	if relative.Origin != "" {
		origin = relative.Origin
	}
	out := Path{Target: target, PathTarget: pathTarget, Origin: origin, Elements: make([]PathElem, 0, len(prefix.Elements)+len(relative.Elements))}
	for _, elem := range prefix.Elements {
		out.Elements = append(out.Elements, PathElem{Name: elem.Name, Keys: cloneStrings(elem.Keys)})
	}
	for _, elem := range relative.Elements {
		out.Elements = append(out.Elements, PathElem{Name: elem.Name, Keys: cloneStrings(elem.Keys)})
	}
	return out, nil
}

// AppendElements returns a copy of p with the supplied unkeyed names appended.
func (p Path) AppendElements(names ...string) Path {
	out := p.Clone()
	for _, name := range names {
		out.Elements = append(out.Elements, PathElem{Name: name})
	}
	return out
}

// SplitLeaf converts a full path to a canonical source series.
func (p Path) SplitLeaf() (Series, error) {
	if len(p.Elements) == 0 {
		return Series{}, errors.New("path has no leaf")
	}
	leaf := p.Elements[len(p.Elements)-1]
	if leaf.Name == "" {
		return Series{}, errors.New("path leaf cannot be empty")
	}
	if len(leaf.Keys) > 0 {
		return Series{}, fmt.Errorf("path leaf %q cannot contain list keys", leaf.Name)
	}
	parents := make([]PathElem, len(p.Elements)-1)
	for i, elem := range p.Elements[:len(p.Elements)-1] {
		parents[i] = PathElem{Name: elem.Name, Keys: cloneStrings(elem.Keys)}
	}
	return Series{Target: p.Target, PathTarget: p.PathTarget, Origin: p.Origin, Elements: parents, Leaf: leaf.Name}, nil
}

// String renders only path elements. Target and origin are intentionally not
// folded into this representation.
func (p Path) String() string {
	parts := make([]string, 0, len(p.Elements))
	for _, elem := range p.Elements {
		var part strings.Builder
		part.WriteString(elem.Name)
		keys := make([]string, 0, len(elem.Keys))
		for key := range elem.Keys {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			part.WriteByte('[')
			part.WriteString(key)
			part.WriteByte('=')
			part.WriteString(quotePathValue(elem.Keys[key]))
			part.WriteByte(']')
		}
		parts = append(parts, part.String())
	}
	return strings.Join(parts, "/")
}

func splitPath(raw string) ([]string, error) {
	var parts []string
	start, depth := 0, 0
	var quote rune
	escaped := false
	for i, r := range raw {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		switch r {
		case '\'', '"':
			if depth > 0 {
				quote = r
			}
		case '[':
			depth++
		case ']':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("path %q contains an unmatched closing bracket", raw)
			}
		case '/':
			if depth == 0 {
				if i == start {
					return nil, fmt.Errorf("path %q contains an empty element", raw)
				}
				parts = append(parts, raw[start:i])
				start = i + 1
			}
		}
	}
	if quote != 0 || depth != 0 {
		return nil, fmt.Errorf("path %q contains an unterminated key", raw)
	}
	if start >= len(raw) {
		return nil, fmt.Errorf("path %q contains an empty element", raw)
	}
	return append(parts, raw[start:]), nil
}

func parsePathElem(raw string) (PathElem, error) {
	open := strings.IndexByte(raw, '[')
	if open < 0 {
		if raw == "" {
			return PathElem{}, errors.New("name cannot be empty")
		}
		return PathElem{Name: raw}, nil
	}
	if open == 0 {
		return PathElem{}, errors.New("name cannot be empty")
	}
	out := PathElem{Name: raw[:open], Keys: map[string]string{}}
	rest := raw[open:]
	for rest != "" {
		if rest[0] != '[' {
			return PathElem{}, errors.New("unexpected text after key")
		}
		end, err := findKeyEnd(rest)
		if err != nil {
			return PathElem{}, err
		}
		key, value, err := splitKeyValue(rest[1:end])
		if err != nil {
			return PathElem{}, err
		}
		if _, exists := out.Keys[key]; exists {
			return PathElem{}, fmt.Errorf("duplicate key %q", key)
		}
		out.Keys[key] = value
		rest = rest[end+1:]
	}
	return out, nil
}

func findKeyEnd(raw string) (int, error) {
	var quote byte
	escaped := false
	for i := 1; i < len(raw); i++ {
		ch := raw[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			continue
		}
		if ch == ']' {
			return i, nil
		}
	}
	return 0, errors.New("missing closing bracket")
}

func splitKeyValue(raw string) (string, string, error) {
	var quote byte
	escaped := false
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			continue
		}
		if ch == '=' {
			key := strings.TrimSpace(raw[:i])
			if key == "" {
				return "", "", errors.New("key cannot be empty")
			}
			value, err := unquotePathValue(strings.TrimSpace(raw[i+1:]))
			return key, value, err
		}
	}
	return "", "", errors.New("key must be key=value")
}

func quotePathValue(value string) string {
	if value != "" && !strings.ContainsAny(value, "/[]='\"\\ ") {
		return value
	}
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}

func unquotePathValue(value string) (string, error) {
	if len(value) < 2 || (value[0] != '\'' && value[0] != '"') {
		return value, nil
	}
	if value[len(value)-1] != value[0] {
		return "", errors.New("mismatched key quotes")
	}
	quote := value[0]
	value = value[1 : len(value)-1]
	var b strings.Builder
	escaped := false
	for i := 0; i < len(value); i++ {
		if escaped {
			b.WriteByte(value[i])
			escaped = false
			continue
		}
		if value[i] == '\\' {
			escaped = true
			continue
		}
		if value[i] == quote {
			return "", errors.New("unescaped quote in key value")
		}
		b.WriteByte(value[i])
	}
	if escaped {
		return "", errors.New("unterminated escape in key value")
	}
	return b.String(), nil
}
