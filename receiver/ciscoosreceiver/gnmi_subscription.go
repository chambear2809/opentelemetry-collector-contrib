// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

type sharedGNMIPath struct {
	Origin string
	Path   string
}

type sharedGNMIStream struct {
	Profile        string
	Required       bool
	Mode           string
	SampleInterval time.Duration
	PollInterval   time.Duration
	Paths          []sharedGNMIPath
	Mappings       []builtinGNMIMapping
	Optics         bool
	HealthOnly     bool
}

// buildSharedGNMIStreams converts enabled built-in profiles and custom
// subscriptions into compatible streams. IOS XE and IOS XR require one prefix
// origin per stream. NX-OS retains origin on each subscribed path so DME,
// device-YANG, and OpenConfig paths can coexist in one profile stream.
func buildSharedGNMIStreams(rawTarget GNMITargetConfig) ([]sharedGNMIStream, error) {
	target := rawTarget.withDefaults()
	var streams []sharedGNMIStream

	for _, profileName := range []string{
		builtinGNMIProfileIdentity,
		builtinGNMIProfileSystem,
		builtinGNMIProfileInterfaces,
		builtinGNMIProfileOptics,
		builtinGNMIProfileCatalyst9800Wireless,
	} {
		profileConfig := sharedGNMIProfileConfig(target.Profiles, profileName)
		if !boolValue(profileConfig.Enabled, false) {
			continue
		}
		definition, ok := builtinGNMIProfile(target.Platform, profileName)
		if !ok {
			return nil, fmt.Errorf("gNMI profile %q is not supported on platform %q", profileName, target.Platform)
		}
		profileStreams := buildBuiltinProfileStreams(target.Platform, definition, profileConfig)
		streams = append(streams, profileStreams...)
	}

	for _, subscription := range target.CustomSubscriptions {
		stream, err := buildCustomGNMIStream(subscription)
		if err != nil {
			return nil, fmt.Errorf("custom subscription %q: %w", subscription.Name, err)
		}
		streams = append(streams, stream)
	}

	if len(streams) > target.MaxStreams {
		return nil, fmt.Errorf("target %q requires %d compatible subscription streams, exceeding max_streams %d", target.Name, len(streams), target.MaxStreams)
	}
	return streams, nil
}

func buildBuiltinProfileStreams(platform string, definition builtinGNMIProfileDefinition, config GNMIProfileConfig) []sharedGNMIStream {
	base := sharedGNMIStream{
		Profile:        definition.Name,
		Required:       config.Required,
		Mode:           gnmiModeStream,
		SampleInterval: config.SampleInterval,
		Optics:         definition.Name == builtinGNMIProfileOptics,
		HealthOnly:     definition.Name == builtinGNMIProfileIdentity,
	}
	if platform == gnmiPlatformNXOS {
		stream := base
		stream.Mappings = append(stream.Mappings, definition.SyntheticMappings...)
		for _, path := range definition.Paths {
			appendSharedGNMIPath(&stream, sharedGNMIPath{Origin: path.Origin, Path: path.Path}, path.Mappings)
		}
		sortSharedGNMIPaths(stream.Paths)
		return []sharedGNMIStream{stream}
	}

	byOrigin := map[string]*sharedGNMIStream{}
	for _, path := range definition.Paths {
		stream := byOrigin[path.Origin]
		if stream == nil {
			streamCopy := base
			stream = &streamCopy
			byOrigin[path.Origin] = stream
		}
		appendSharedGNMIPath(stream, sharedGNMIPath{Origin: path.Origin, Path: path.Path}, path.Mappings)
	}
	origins := make([]string, 0, len(byOrigin))
	for origin := range byOrigin {
		origins = append(origins, origin)
	}
	sort.Strings(origins)
	streams := make([]sharedGNMIStream, 0, len(origins))
	for i, origin := range origins {
		stream := byOrigin[origin]
		if i == 0 {
			stream.Mappings = append(definition.SyntheticMappings, stream.Mappings...)
		}
		sortSharedGNMIPaths(stream.Paths)
		streams = append(streams, *stream)
	}
	return streams
}

func appendSharedGNMIPath(stream *sharedGNMIStream, path sharedGNMIPath, mappings []builtinGNMIMapping) {
	if slices.Contains(stream.Paths, path) {
		stream.Mappings = append(stream.Mappings, mappings...)
		return
	}
	stream.Paths = append(stream.Paths, path)
	stream.Mappings = append(stream.Mappings, mappings...)
}

func sortSharedGNMIPaths(paths []sharedGNMIPath) {
	sort.SliceStable(paths, func(i, j int) bool {
		if paths[i].Origin != paths[j].Origin {
			return paths[i].Origin < paths[j].Origin
		}
		return paths[i].Path < paths[j].Path
	})
}

func buildCustomGNMIStream(subscription GNMICustomSubscriptionConfig) (sharedGNMIStream, error) {
	stream := sharedGNMIStream{
		Profile:        subscription.Name,
		Required:       subscription.Required,
		Mode:           subscription.Mode,
		SampleInterval: subscription.SampleInterval,
		PollInterval:   subscription.PollInterval,
	}
	for i, configured := range subscription.Mappings {
		catalogMapping, path, err := convertCustomGNMIMapping(subscription.Origin, configured)
		if err != nil {
			return sharedGNMIStream{}, fmt.Errorf("mapping %d: %w", i, err)
		}
		appendSharedGNMIPath(&stream, path, []builtinGNMIMapping{catalogMapping})
	}
	sortSharedGNMIPaths(stream.Paths)
	return stream, nil
}

func convertCustomGNMIMapping(origin string, configured GNMIMetricMappingConfig) (builtinGNMIMapping, sharedGNMIPath, error) {
	parsed, err := internalgnmi.ParsePath("", origin, configured.Path)
	if err != nil {
		return builtinGNMIMapping{}, sharedGNMIPath{}, err
	}
	series, err := parsed.SplitLeaf()
	if err != nil {
		return builtinGNMIMapping{}, sharedGNMIPath{}, err
	}
	elements := make([]string, len(series.Elements))
	for i, element := range series.Elements {
		elements[i] = element.Name
	}
	keys := make([]internalgnmi.KeyAttribute, 0, len(configured.PathKeys))
	for _, selector := range sortedGNMIPathKeys(configured.PathKeys) {
		element, key, ok := strings.Cut(selector, ".")
		if !ok || element == "" || key == "" {
			return builtinGNMIMapping{}, sharedGNMIPath{}, fmt.Errorf("invalid path key selector %q", selector)
		}
		keys = append(keys, internalgnmi.KeyAttribute{Element: element, Key: key, Attribute: configured.PathKeys[selector]})
	}
	if configured.Scale == nil {
		return builtinGNMIMapping{}, sharedGNMIPath{}, errors.New("scale must be explicitly configured")
	}
	gauge := internalgnmi.GaugeValueType(configured.GaugeType)
	converted := builtinGNMIMapping{Mapping: internalgnmi.Mapping{
		Source: internalgnmi.SourcePath{
			Origin:   origin,
			Elements: elements,
			Leaf:     series.Leaf,
		},
		Metric: internalgnmi.MetricMetadata{
			Name:        configured.MetricName,
			Description: configured.Description,
			Unit:        configured.Unit,
		},
		Scale:         *configured.Scale,
		GaugeType:     gauge,
		KeyAttributes: keys,
	}}
	if _, err := internalgnmi.NewRegistry(converted.Mapping); err != nil {
		return builtinGNMIMapping{}, sharedGNMIPath{}, err
	}
	return converted, sharedGNMIPath{Origin: origin, Path: strings.Trim(configured.Path, "/")}, nil
}

func sharedGNMIProfileConfig(profiles GNMIProfilesConfig, name string) GNMIProfileConfig {
	switch name {
	case builtinGNMIProfileIdentity:
		return profiles.Identity
	case builtinGNMIProfileSystem:
		return profiles.System
	case builtinGNMIProfileInterfaces:
		return profiles.Interfaces
	case builtinGNMIProfileOptics:
		return profiles.Optics
	case builtinGNMIProfileCatalyst9800Wireless:
		return profiles.Catalyst9800Wireless
	default:
		return GNMIProfileConfig{}
	}
}

// buildSharedGNMISubscribeRequest places IOS XE and IOS XR origins on the
// SubscriptionList prefix. NX-OS keeps each origin on its individual path.
func buildSharedGNMISubscribeRequest(target GNMITargetConfig, stream sharedGNMIStream, encoding gnmipb.Encoding) (*gnmipb.SubscribeRequest, error) {
	if len(stream.Paths) == 0 {
		return nil, fmt.Errorf("stream %q has no subscription paths", stream.Profile)
	}
	listMode, err := sharedGNMIListMode(stream.Mode)
	if err != nil {
		return nil, err
	}
	list := &gnmipb.SubscriptionList{
		Mode:         listMode,
		Encoding:     encoding,
		Subscription: make([]*gnmipb.Subscription, 0, len(stream.Paths)),
	}
	if target.Platform != gnmiPlatformNXOS {
		origin := stream.Paths[0].Origin
		for _, path := range stream.Paths[1:] {
			if path.Origin != origin {
				return nil, fmt.Errorf("stream %q mixes prefix origins %q and %q", stream.Profile, origin, path.Origin)
			}
		}
		list.Prefix = &gnmipb.Path{Origin: origin}
	}
	for _, path := range stream.Paths {
		pathOrigin := ""
		if target.Platform == gnmiPlatformNXOS {
			pathOrigin = path.Origin
		}
		protoPath, err := sharedGNMIPathToProto(pathOrigin, path.Path)
		if err != nil {
			return nil, fmt.Errorf("path %q: %w", path.Path, err)
		}
		subscription := &gnmipb.Subscription{Path: protoPath, Mode: gnmipb.SubscriptionMode_SAMPLE}
		if stream.Mode == gnmiModeStream {
			subscription.SampleInterval = uint64(stream.SampleInterval.Nanoseconds())
		}
		list.Subscription = append(list.Subscription, subscription)
	}
	return &gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Subscribe{Subscribe: list}}, nil
}

func sharedGNMIPathToProto(origin, path string) (*gnmipb.Path, error) {
	if origin == builtinGNMIOriginDME {
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) == 0 || parts[0] == "" {
			return nil, errors.New("path cannot be empty")
		}
		out := &gnmipb.Path{Origin: origin, Elem: make([]*gnmipb.PathElem, 0, len(parts))}
		for _, part := range parts {
			if part == "" {
				return nil, errors.New("path contains an empty element")
			}
			out.Elem = append(out.Elem, &gnmipb.PathElem{Name: part})
		}
		return out, nil
	}
	parsed, err := internalgnmi.ParsePath("", origin, path)
	if err != nil {
		return nil, err
	}
	return parsed.ToProto(), nil
}

func sharedGNMIListMode(mode string) (gnmipb.SubscriptionList_Mode, error) {
	switch mode {
	case gnmiModeStream:
		return gnmipb.SubscriptionList_STREAM, nil
	case gnmiModeOnce:
		return gnmipb.SubscriptionList_ONCE, nil
	case gnmiModePoll:
		return gnmipb.SubscriptionList_POLL, nil
	default:
		return gnmipb.SubscriptionList_STREAM, fmt.Errorf("unsupported subscription mode %q", mode)
	}
}

// negotiateSharedGNMIEncoding uses one deterministic preference order. NX DME
// JSON payloads are not decodable from proto_bytes, so a DME stream cannot use
// a target that advertises only PROTO.
func negotiateSharedGNMIEncoding(target GNMITargetConfig, capabilities *gnmipb.CapabilityResponse, streams []sharedGNMIStream) (gnmipb.Encoding, error) {
	if capabilities == nil {
		return gnmipb.Encoding_JSON, errors.New("gNMI capabilities response is required")
	}
	supported := make(map[gnmipb.Encoding]struct{}, len(capabilities.GetSupportedEncodings()))
	for _, encoding := range capabilities.GetSupportedEncodings() {
		supported[encoding] = struct{}{}
	}
	preference := []gnmipb.Encoding{gnmipb.Encoding_JSON_IETF, gnmipb.Encoding_JSON}
	containsDME := target.Platform == gnmiPlatformNXOS && sharedGNMIStreamsContainOrigin(streams, builtinGNMIOriginDME)
	if containsDME {
		// NX DME's documented structured encoding is JSON, not RFC7951 JSON-IETF.
		preference = []gnmipb.Encoding{gnmipb.Encoding_JSON, gnmipb.Encoding_JSON_IETF}
	}
	for _, encoding := range preference {
		if _, ok := supported[encoding]; !ok {
			continue
		}
		return encoding, nil
	}
	return gnmipb.Encoding_JSON, errors.New("target advertises no supported JSON_IETF or JSON encoding; schema-neutral mappings cannot decode proto_bytes")
}

func sharedGNMIStreamsContainOrigin(streams []sharedGNMIStream, origin string) bool {
	for _, stream := range streams {
		for _, path := range stream.Paths {
			if path.Origin == origin {
				return true
			}
		}
	}
	return false
}
