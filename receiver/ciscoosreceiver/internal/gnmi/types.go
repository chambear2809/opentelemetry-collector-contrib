// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package gnmi provides the canonical, platform-neutral data model used by the
// Cisco OS receiver's gNMI transports. It deliberately contains no receiver
// lifecycle or fork-specific integration code.
package gnmi // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"sort"
	"strings"
	"time"
)

// PathElem is one canonical gNMI path element. Keys are retained separately
// from the element name so list identity is never encoded into a metric name.
type PathElem struct {
	Name string
	Keys map[string]string
}

// Path identifies a branch on one target. Origin is deliberately separate
// from Elements; callers must not encode an origin as an "origin:path" string.
type Path struct {
	Target   string
	Origin   string
	Elements []PathElem
}

// Clone returns a deep copy of the path.
func (p Path) Clone() Path {
	out := Path{Target: p.Target, Origin: p.Origin, Elements: make([]PathElem, len(p.Elements))}
	for i, elem := range p.Elements {
		out.Elements[i] = PathElem{Name: elem.Name, Keys: cloneStrings(elem.Keys)}
	}
	return out
}

// Key returns an unambiguous, stable identity for the path.
func (p Path) Key() string {
	var b strings.Builder
	appendKeyPart(&b, p.Target)
	appendKeyPart(&b, p.Origin)
	for _, elem := range p.Elements {
		appendKeyPart(&b, elem.Name)
		keys := make([]string, 0, len(elem.Keys))
		for key := range elem.Keys {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			appendKeyPart(&b, key)
			appendKeyPart(&b, elem.Keys[key])
		}
		appendKeyPart(&b, "")
	}
	return b.String()
}

// HasPrefix reports whether selector selects p. Selector keys are matched as a
// subset, allowing an unkeyed branch delete to select all keyed list entries.
func (p Path) HasPrefix(selector Path) bool {
	if selector.Target != "" && p.Target != selector.Target {
		return false
	}
	if selector.Origin != "" && p.Origin != selector.Origin {
		return false
	}
	if len(selector.Elements) > len(p.Elements) {
		return false
	}
	for i, want := range selector.Elements {
		got := p.Elements[i]
		if got.Name != want.Name {
			return false
		}
		for key, value := range want.Keys {
			if got.Keys[key] != value {
				return false
			}
		}
	}
	return true
}

// Series identifies one canonical leaf under a path.
type Series struct {
	Target   string
	Origin   string
	Elements []PathElem
	Leaf     string
}

// Path returns the full path, including the leaf as its final element.
func (s Series) Path() Path {
	elems := make([]PathElem, 0, len(s.Elements)+1)
	for _, elem := range s.Elements {
		elems = append(elems, PathElem{Name: elem.Name, Keys: cloneStrings(elem.Keys)})
	}
	elems = append(elems, PathElem{Name: s.Leaf})
	return Path{Target: s.Target, Origin: s.Origin, Elements: elems}
}

// Key returns an unambiguous, stable identity for the source series.
func (s Series) Key() string { return s.Path().Key() }

// ValueKind is the canonical wire value kind.
type ValueKind uint8

const (
	ValueInvalid ValueKind = iota
	ValueInt
	ValueUint
	ValueDouble
	ValueBool
	ValueString
)

// Value preserves scalar wire types until an explicit metric mapping applies
// scale and output type semantics.
type Value struct {
	Kind   ValueKind
	Int    int64
	Uint   uint64
	Double float64
	Bool   bool
	String string
}

func IntValue(value int64) Value      { return Value{Kind: ValueInt, Int: value} }
func UintValue(value uint64) Value    { return Value{Kind: ValueUint, Uint: value} }
func DoubleValue(value float64) Value { return Value{Kind: ValueDouble, Double: value} }
func BoolValue(value bool) Value      { return Value{Kind: ValueBool, Bool: value} }
func StringValue(value string) Value  { return Value{Kind: ValueString, String: value} }

// Equal reports exact canonical value equality. NaN is never equal.
func (v Value) Equal(other Value) bool {
	if v.Kind != other.Kind {
		return false
	}
	switch v.Kind {
	case ValueInt:
		return v.Int == other.Int
	case ValueUint:
		return v.Uint == other.Uint
	case ValueDouble:
		return !math.IsNaN(v.Double) && v.Double == other.Double
	case ValueBool:
		return v.Bool == other.Bool
	case ValueString:
		return v.String == other.String
	default:
		return false
	}
}

// Point is one decoded canonical leaf update.
type Point struct {
	Series    Series
	Value     Value
	Timestamp time.Time
}

// DecodedNotification is the platform-neutral result of decoding one gNMI
// Notification. Deletes select complete descendant branches.
type DecodedNotification struct {
	Prefix    Path
	Timestamp time.Time
	Atomic    bool
	// Touched retains every canonical wire update path, including values that
	// could not be decoded or did not match an explicit metric mapping. Cache
	// state uses it only to invalidate overlapping atomic baselines.
	Touched []Path
	Updates []Point
	Deletes []Path
}

// DecodeStats contains non-fatal wire-data diagnostics.
type DecodeStats struct {
	UnmappedValues    int
	InvalidTimestamps int
}

func cloneStrings(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	return maps.Clone(values)
}

func appendKeyPart(b *strings.Builder, value string) {
	fmt.Fprintf(b, "%d:", len(value))
	b.WriteString(value)
}

func stableAttributesKey(values map[string]string) string {
	encoded, _ := json.Marshal(values) // string maps are deterministically key-sorted.
	return string(encoded)
}
