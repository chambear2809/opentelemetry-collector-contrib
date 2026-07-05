// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	gnmiextpb "github.com/openconfig/gnmi/proto/gnmi_ext"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

type sharedGNMIPath struct {
	ID                string
	AliasIDs          []string
	PathTarget        string
	Origin            string
	Path              string
	StreamMode        string
	SampleInterval    *time.Duration
	HeartbeatInterval *time.Duration
	SuppressRedundant *bool
}

type sharedGNMIPrefix struct {
	PathTarget string
	Origin     string
}

type sharedGNMIStream struct {
	OwnerID            string
	Profile            string
	Required           bool
	Mode               string
	SampleInterval     time.Duration
	PollInterval       time.Duration
	EncodingPreference []string
	RequiredModels     []string
	UpdatesOnly        bool
	AllowAggregation   bool
	QoSMarking         *uint32
	GNMIExtensions     GNMIExtensionsConfig
	Paths              []sharedGNMIPath
	Mappings           []builtinGNMIMapping
	Optics             bool
	HealthOnly         bool
}

// buildSharedGNMIStreams converts enabled built-in profiles and custom
// subscriptions into product-contract-approved streams. Prefix-oriented
// contracts require one (path target, origin) pair per stream. Nexus contracts
// retain origins on individual paths so DME, device-YANG, and OpenConfig paths
// can coexist.
func buildSharedGNMIStreams(rawTarget GNMITargetConfig) ([]sharedGNMIStream, error) {
	target := rawTarget.withDefaults()
	contract, _, err := gnmiProductContractForTarget(target)
	if err != nil {
		return nil, err
	}
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
		definition, ok := builtinGNMIProfile(contract, profileName)
		if !ok {
			continue
		}
		if err := validateGNMIBuiltinPathOverrides("profiles."+profileName, definition, profileConfig, contract); err != nil {
			return nil, err
		}
		profileStreams := buildBuiltinProfileStreams(contract, definition, profileConfig)
		streams = append(streams, profileStreams...)
	}

	for i := range target.CustomSubscriptions {
		subscription := &target.CustomSubscriptions[i]
		if err := validateGNMICustomSubscriptionAddress("custom_subscriptions."+subscription.Name, *subscription); err != nil {
			return nil, fmt.Errorf("custom subscription %q: %w", subscription.Name, err)
		}
		if err := validateGNMICustomSubscriptionModels("custom_subscriptions."+subscription.Name, *subscription, contract); err != nil {
			return nil, fmt.Errorf("custom subscription %q: %w", subscription.Name, err)
		}
		if err := validateGNMICustomSubscriptionPaths("custom_subscriptions."+subscription.Name, *subscription, contract); err != nil {
			return nil, fmt.Errorf("custom subscription %q: %w", subscription.Name, err)
		}
		stream, err := buildCustomGNMIStream(*subscription)
		if err != nil {
			return nil, fmt.Errorf("custom subscription %q: %w", subscription.Name, err)
		}
		streams = append(streams, stream)
	}

	if len(streams) > target.MaxStreams {
		return nil, fmt.Errorf("target %q requires %d compatible subscription streams, exceeding max_streams %d", target.Name, len(streams), target.MaxStreams)
	}
	for i := range streams {
		normalizeSharedGNMIStreamPlan(target, &streams[i])
	}
	return streams, nil
}

func buildBuiltinProfileStreams(contract *gnmiProductContract, definition builtinGNMIProfileDefinition, config GNMIProfileConfig) []sharedGNMIStream {
	base := sharedGNMIStream{
		Profile:            definition.Name,
		Required:           config.Required,
		Mode:               gnmiModeStream,
		SampleInterval:     config.SampleInterval,
		EncodingPreference: append([]string(nil), config.EncodingPreference...),
		UpdatesOnly:        config.UpdatesOnly,
		AllowAggregation:   config.AllowAggregation,
		QoSMarking:         cloneGNMIUint32(config.QoSMarking),
		GNMIExtensions:     cloneGNMIExtensions(config.GNMIExtensions),
		Optics:             definition.Name == builtinGNMIProfileOptics,
		HealthOnly:         definition.Name == builtinGNMIProfileIdentity,
	}
	if contract != nil && !contract.RequestPolicy.UsePathPrefix {
		stream := base
		stream.Mappings = append(stream.Mappings, definition.SyntheticMappings...)
		for _, path := range definition.Paths {
			appendSharedGNMIPath(&stream, sharedGNMIPathFromBuiltin(path, config.PathOverrides[path.ID]), path.Mappings)
			appendSharedGNMIRequiredModel(&stream, path.Model)
		}
		sortSharedGNMIPaths(stream.Paths)
		return []sharedGNMIStream{stream}
	}

	byPrefix := map[sharedGNMIPrefix]*sharedGNMIStream{}
	for _, path := range definition.Paths {
		prefix := sharedGNMIPrefix{PathTarget: path.PathTarget, Origin: path.Origin}
		stream := byPrefix[prefix]
		if stream == nil {
			streamCopy := base
			stream = &streamCopy
			byPrefix[prefix] = stream
		}
		appendSharedGNMIPath(stream, sharedGNMIPathFromBuiltin(path, config.PathOverrides[path.ID]), path.Mappings)
		appendSharedGNMIRequiredModel(stream, path.Model)
	}
	prefixes := make([]sharedGNMIPrefix, 0, len(byPrefix))
	for prefix := range byPrefix {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].PathTarget != prefixes[j].PathTarget {
			return prefixes[i].PathTarget < prefixes[j].PathTarget
		}
		return prefixes[i].Origin < prefixes[j].Origin
	})
	streams := make([]sharedGNMIStream, 0, len(prefixes))
	for i, prefix := range prefixes {
		stream := byPrefix[prefix]
		if i == 0 {
			stream.Mappings = append(definition.SyntheticMappings, stream.Mappings...)
		}
		sortSharedGNMIPaths(stream.Paths)
		streams = append(streams, *stream)
	}
	return streams
}

func appendSharedGNMIPath(stream *sharedGNMIStream, path sharedGNMIPath, mappings []builtinGNMIMapping) {
	for i := range stream.Paths {
		existing := &stream.Paths[i]
		if existing.PathTarget != path.PathTarget || existing.Origin != path.Origin || existing.Path != path.Path {
			continue
		}
		if path.ID != "" && path.ID != existing.ID && !slices.Contains(existing.AliasIDs, path.ID) {
			existing.AliasIDs = append(existing.AliasIDs, path.ID)
			sort.Strings(existing.AliasIDs)
		}
		stream.Mappings = append(stream.Mappings, mappings...)
		return
	}
	stream.Paths = append(stream.Paths, path)
	stream.Mappings = append(stream.Mappings, mappings...)
}

func appendSharedGNMIRequiredModel(stream *sharedGNMIStream, model string) {
	if model == "" || slices.Contains(stream.RequiredModels, model) {
		return
	}
	stream.RequiredModels = append(stream.RequiredModels, model)
	sort.Strings(stream.RequiredModels)
}

func sharedGNMIPathFromBuiltin(path builtinGNMIPathDefinition, options GNMIPathOptionsConfig) sharedGNMIPath {
	return sharedGNMIPath{
		ID:                path.ID,
		PathTarget:        path.PathTarget,
		Origin:            path.Origin,
		Path:              path.Path,
		StreamMode:        options.StreamMode,
		SampleInterval:    cloneGNMIDuration(options.SampleInterval),
		HeartbeatInterval: cloneGNMIDuration(options.HeartbeatInterval),
		SuppressRedundant: cloneGNMIBool(options.SuppressRedundant),
	}
}

func sortSharedGNMIPaths(paths []sharedGNMIPath) {
	sort.SliceStable(paths, func(i, j int) bool {
		if paths[i].PathTarget != paths[j].PathTarget {
			return paths[i].PathTarget < paths[j].PathTarget
		}
		if paths[i].Origin != paths[j].Origin {
			return paths[i].Origin < paths[j].Origin
		}
		if paths[i].Path != paths[j].Path {
			return paths[i].Path < paths[j].Path
		}
		return paths[i].ID < paths[j].ID
	})
}

func buildCustomGNMIStream(subscription GNMICustomSubscriptionConfig) (sharedGNMIStream, error) {
	stream := sharedGNMIStream{
		Profile:            subscription.Name,
		Required:           subscription.Required,
		Mode:               subscription.Mode,
		SampleInterval:     subscription.SampleInterval,
		PollInterval:       subscription.PollInterval,
		EncodingPreference: append([]string(nil), subscription.EncodingPreference...),
		RequiredModels:     append([]string(nil), subscription.Models...),
		UpdatesOnly:        subscription.UpdatesOnly,
		AllowAggregation:   subscription.AllowAggregation,
		QoSMarking:         cloneGNMIUint32(subscription.QoSMarking),
		GNMIExtensions:     cloneGNMIExtensions(subscription.GNMIExtensions),
	}
	for _, selector := range subscription.Paths {
		path := strings.Trim(selector.Path, "/")
		appendSharedGNMIPath(&stream, sharedGNMIPath{
			PathTarget:        subscription.PathTarget,
			Origin:            subscription.Origin,
			Path:              path,
			StreamMode:        selector.StreamMode,
			SampleInterval:    cloneGNMIDuration(selector.SampleInterval),
			HeartbeatInterval: cloneGNMIDuration(selector.HeartbeatInterval),
			SuppressRedundant: cloneGNMIBool(selector.SuppressRedundant),
		}, nil)
	}
	for i, configured := range subscription.Mappings {
		catalogMapping, path, err := convertCustomGNMIMapping(subscription.PathTarget, subscription.Origin, configured)
		if err != nil {
			return sharedGNMIStream{}, fmt.Errorf("mapping %d: %w", i, err)
		}
		if len(subscription.Paths) == 0 {
			appendSharedGNMIPath(&stream, path, []builtinGNMIMapping{catalogMapping})
		} else {
			stream.Mappings = append(stream.Mappings, catalogMapping)
		}
	}
	sortSharedGNMIPaths(stream.Paths)
	return stream, nil
}

func normalizeSharedGNMIStreamPlan(target GNMITargetConfig, stream *sharedGNMIStream) {
	if stream == nil {
		return
	}
	dme := false
	for i := range stream.Paths {
		dme = dme || stream.Paths[i].Origin == builtinGNMIOriginDME
	}
	stream.EncodingPreference = effectiveGNMIEncodingPreferences(stream.EncodingPreference, target.EncodingPreference, dme)
	stream.OwnerID = sharedGNMIStreamOwnerID(target.Name, *stream)
}

func sharedGNMIStreamOwnerID(target string, stream sharedGNMIStream) string {
	digest := sha256.New()
	fmt.Fprintf(digest, "%d:%s%d:%s", len(target), target, len(stream.Profile), stream.Profile)
	for i := range stream.Paths {
		path := &stream.Paths[i]
		fmt.Fprintf(digest, "%d:%s%d:%s%d:%s", len(path.PathTarget), path.PathTarget, len(path.Origin), path.Origin, len(path.Path), path.Path)
	}
	return fmt.Sprintf("gnmi:%x", digest.Sum(nil))
}

func cloneGNMIDuration(value *time.Duration) *time.Duration {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneGNMIBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneGNMIUint32(value *uint32) *uint32 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneGNMIExtensions(extensions GNMIExtensionsConfig) GNMIExtensionsConfig {
	extensions.Depth = cloneGNMIUint32(extensions.Depth)
	return extensions
}

func convertCustomGNMIMapping(pathTarget, origin string, configured GNMIMetricMappingConfig) (builtinGNMIMapping, sharedGNMIPath, error) {
	parsed, err := internalgnmi.ParsePath("", origin, configured.Path)
	if err != nil {
		return builtinGNMIMapping{}, sharedGNMIPath{}, err
	}
	parsed.PathTarget = pathTarget
	if validationErr := internalgnmi.ValidatePath(parsed); validationErr != nil {
		return builtinGNMIMapping{}, sharedGNMIPath{}, validationErr
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
			PathTarget: pathTarget,
			Origin:     origin,
			Elements:   elements,
			Leaf:       series.Leaf,
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
	return converted, sharedGNMIPath{PathTarget: pathTarget, Origin: origin, Path: strings.Trim(configured.Path, "/")}, nil
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

// buildSharedGNMISubscribeRequest applies the product contract's origin and
// wildcard policy to an already normalized, independently encoded stream plan.
func buildSharedGNMISubscribeRequest(target GNMITargetConfig, stream sharedGNMIStream, encoding gnmipb.Encoding) (*gnmipb.SubscribeRequest, error) {
	contract, _, err := gnmiProductContractForTarget(target)
	if err != nil {
		return nil, err
	}
	if !gnmiProductApprovesEncoding(contract, encoding) {
		return nil, fmt.Errorf("encoding %q is not approved for product %s", sharedGNMIEncodingName(encoding), contract.Product)
	}
	if contract.RequestPolicy.StreamOnly && stream.Mode != gnmiModeStream {
		if contract.RequestPolicy.ConservativeSampleOnly {
			return nil, fmt.Errorf("stream %q supports only SAMPLE STREAM subscriptions on product %s", stream.Profile, contract.Product)
		}
		return nil, fmt.Errorf("stream %q mode must be stream on product %s", stream.Profile, contract.Product)
	}
	if len(stream.Paths) == 0 {
		return nil, fmt.Errorf("stream %q has no subscription paths", stream.Profile)
	}
	pathOptions := make([]GNMIPathOptionsConfig, 0, len(stream.Paths))
	for pathIndex := range stream.Paths {
		path := &stream.Paths[pathIndex]
		pathOptions = append(pathOptions, GNMIPathOptionsConfig{
			StreamMode:        path.StreamMode,
			SampleInterval:    path.SampleInterval,
			HeartbeatInterval: path.HeartbeatInterval,
			SuppressRedundant: path.SuppressRedundant,
		})
	}
	if samplePlanErr := validateGNMIProductSamplePlan("stream "+stream.Profile, contract, stream.SampleInterval, pathOptions); samplePlanErr != nil {
		return nil, samplePlanErr
	}
	listMode, err := sharedGNMIListMode(stream.Mode)
	if err != nil {
		return nil, err
	}
	if err := validateGNMIListOptions(
		"stream "+stream.Profile,
		stream.Mode,
		[]string{sharedGNMIEncodingName(encoding)},
		stream.UpdatesOnly,
		stream.AllowAggregation,
		stream.QoSMarking,
		stream.GNMIExtensions,
	); err != nil {
		return nil, err
	}
	if err := validateGNMIProductListPolicy(
		"stream "+stream.Profile, contract,
		stream.UpdatesOnly, stream.AllowAggregation,
		stream.QoSMarking, stream.GNMIExtensions,
	); err != nil {
		return nil, err
	}
	list := &gnmipb.SubscriptionList{
		Mode:             listMode,
		Encoding:         encoding,
		UpdatesOnly:      stream.UpdatesOnly,
		AllowAggregation: stream.AllowAggregation,
		Subscription:     make([]*gnmipb.Subscription, 0, len(stream.Paths)),
	}
	if stream.QoSMarking != nil {
		list.Qos = &gnmipb.QOSMarking{Marking: *stream.QoSMarking}
	}
	if contract.RequestPolicy.UsePathPrefix {
		prefix := sharedGNMIPrefix{PathTarget: stream.Paths[0].PathTarget, Origin: stream.Paths[0].Origin}
		for i := 1; i < len(stream.Paths); i++ {
			candidate := sharedGNMIPrefix{PathTarget: stream.Paths[i].PathTarget, Origin: stream.Paths[i].Origin}
			if candidate != prefix {
				return nil, fmt.Errorf(
					"stream %q mixes prefix (path_target, origin) pairs (%q, %q) and (%q, %q)",
					stream.Profile, prefix.PathTarget, prefix.Origin, candidate.PathTarget, candidate.Origin,
				)
			}
		}
		list.Prefix = &gnmipb.Path{Target: prefix.PathTarget, Origin: prefix.Origin}
	}
	for i := range stream.Paths {
		path := &stream.Paths[i]
		if !gnmiCustomPathNamespaceValid(path.Path, path.Origin) {
			return nil, fmt.Errorf("path %q does not use the namespace form required by origin %q", path.Path, path.Origin)
		}
		if err := validateGNMIProductPathPolicy("path "+path.Path, contract, GNMIPathOptionsConfig{
			StreamMode:        path.StreamMode,
			SampleInterval:    path.SampleInterval,
			HeartbeatInterval: path.HeartbeatInterval,
			SuppressRedundant: path.SuppressRedundant,
		}); err != nil {
			return nil, err
		}
		pathTarget, pathOrigin := "", ""
		if !contract.RequestPolicy.UsePathPrefix {
			pathTarget = path.PathTarget
			pathOrigin = path.Origin
		}
		if !contract.RequestPolicy.AllowWildcards && gnmiPathContainsWildcard(*path) {
			return nil, fmt.Errorf("path %q must be explicit and non-wildcard on product %q", path.Path, contract.Product)
		}
		protoPath, err := sharedGNMIPathToProto(pathTarget, pathOrigin, path.Path)
		if err != nil {
			return nil, fmt.Errorf("path %q: %w", path.Path, err)
		}
		subscription, err := buildSharedGNMIPathSubscription(stream, *path, protoPath)
		if err != nil {
			return nil, fmt.Errorf("path %q: %w", path.Path, err)
		}
		list.Subscription = append(list.Subscription, subscription)
	}
	request := &gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Subscribe{Subscribe: list}}
	if stream.GNMIExtensions.Depth != nil {
		request.Extension = []*gnmiextpb.Extension{{Ext: &gnmiextpb.Extension_Depth{
			Depth: &gnmiextpb.Depth{Level: *stream.GNMIExtensions.Depth},
		}}}
	}
	return request, nil
}

func buildSharedGNMIPathSubscription(stream sharedGNMIStream, path sharedGNMIPath, protoPath *gnmipb.Path) (*gnmipb.Subscription, error) {
	if err := validateGNMIPathOptions("subscription", stream.Mode, GNMIPathOptionsConfig{
		StreamMode:        path.StreamMode,
		SampleInterval:    path.SampleInterval,
		HeartbeatInterval: path.HeartbeatInterval,
		SuppressRedundant: path.SuppressRedundant,
	}); err != nil {
		return nil, err
	}
	subscription := &gnmipb.Subscription{Path: protoPath}
	if stream.Mode != gnmiModeStream {
		return subscription, nil
	}
	mode := path.StreamMode
	if mode == "" {
		mode = gnmiStreamModeSample
	}
	switch mode {
	case gnmiStreamModeSample:
		subscription.Mode = gnmipb.SubscriptionMode_SAMPLE
		interval := stream.SampleInterval
		if path.SampleInterval != nil {
			interval = *path.SampleInterval
		}
		if interval < 0 {
			return nil, errors.New("sample_interval must not be negative")
		}
		subscription.SampleInterval = uint64(interval.Nanoseconds())
		if path.HeartbeatInterval != nil {
			subscription.HeartbeatInterval = uint64(path.HeartbeatInterval.Nanoseconds())
		}
		subscription.SuppressRedundant = boolValue(path.SuppressRedundant, false)
	case gnmiStreamModeOnChange:
		subscription.Mode = gnmipb.SubscriptionMode_ON_CHANGE
		if path.HeartbeatInterval != nil {
			subscription.HeartbeatInterval = uint64(path.HeartbeatInterval.Nanoseconds())
		}
	case gnmiStreamModeTargetDefined:
		subscription.Mode = gnmipb.SubscriptionMode_TARGET_DEFINED
	default:
		return nil, fmt.Errorf("unsupported stream_mode %q", mode)
	}
	return subscription, nil
}

func sharedGNMIPathToProto(pathTarget, origin, path string) (*gnmipb.Path, error) {
	if origin == builtinGNMIOriginDME {
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) == 0 || parts[0] == "" {
			return nil, errors.New("path cannot be empty")
		}
		out := &gnmipb.Path{Target: pathTarget, Origin: origin, Elem: make([]*gnmipb.PathElem, 0, len(parts))}
		for _, part := range parts {
			if part == "" {
				return nil, errors.New("path contains an empty element")
			}
			out.Elem = append(out.Elem, &gnmipb.PathElem{Name: part})
		}
		if err := internalgnmi.ValidatePath(internalgnmi.PathFromProto(out)); err != nil {
			return nil, err
		}
		return out, nil
	}
	parsed, err := internalgnmi.ParsePath("", origin, path)
	if err != nil {
		return nil, err
	}
	parsed.PathTarget = pathTarget
	if err := internalgnmi.ValidatePath(parsed); err != nil {
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

// negotiateSharedGNMIStreamEncoding selects one encoding for one physical
// subscription stream from the target's single Capabilities response.
func negotiateSharedGNMIStreamEncoding(target GNMITargetConfig, capabilities *gnmipb.CapabilityResponse, stream sharedGNMIStream) (gnmipb.Encoding, error) {
	if capabilities == nil {
		return gnmipb.Encoding_JSON, errors.New("gNMI capabilities response is required")
	}
	if len(stream.EncodingPreference) == 0 {
		normalizeSharedGNMIStreamPlan(target, &stream)
	}
	contract, _, contractErr := gnmiProductContractForTarget(target)
	if contractErr != nil {
		return gnmipb.Encoding_JSON, contractErr
	}
	supported := make(map[gnmipb.Encoding]struct{}, len(capabilities.GetSupportedEncodings()))
	for _, encoding := range capabilities.GetSupportedEncodings() {
		supported[encoding] = struct{}{}
	}
	for _, preference := range stream.EncodingPreference {
		encoding, ok := encodingNameToGNMI(preference)
		if !ok || (stream.AllowAggregation && encoding == gnmipb.Encoding_PROTO) {
			continue
		}
		if !gnmiProductApprovesEncoding(contract, encoding) {
			continue
		}
		if _, ok := supported[encoding]; ok {
			return encoding, nil
		}
	}
	return gnmipb.Encoding_JSON, fmt.Errorf("target advertises no encoding requested by stream %q", stream.Profile)
}

// negotiateSharedGNMIEncoding is retained for the target-wide runtime during
// migration to per-stream negotiation. It chooses an encoding authorized by
// every stream; callers implementing parity should use the per-stream helper.
func negotiateSharedGNMIEncoding(target GNMITargetConfig, capabilities *gnmipb.CapabilityResponse, streams []sharedGNMIStream) (gnmipb.Encoding, error) {
	if capabilities == nil {
		return gnmipb.Encoding_JSON, errors.New("gNMI capabilities response is required")
	}
	contract, _, contractErr := gnmiProductContractForTarget(target)
	if contractErr != nil {
		return gnmipb.Encoding_JSON, contractErr
	}
	if len(streams) == 0 {
		stream := sharedGNMIStream{Profile: "target"}
		return negotiateSharedGNMIStreamEncoding(target, capabilities, stream)
	}
	normalized := append([]sharedGNMIStream(nil), streams...)
	for i := range normalized {
		if len(normalized[i].EncodingPreference) == 0 {
			normalizeSharedGNMIStreamPlan(target, &normalized[i])
		}
	}
	base := normalized[0]
	for i := range normalized {
		if sharedGNMIStreamContainsOrigin(normalized[i], builtinGNMIOriginDME) {
			base = normalized[i]
			break
		}
	}
	supported := make(map[gnmipb.Encoding]struct{}, len(capabilities.GetSupportedEncodings()))
	for _, encoding := range capabilities.GetSupportedEncodings() {
		supported[encoding] = struct{}{}
	}
	for _, preference := range base.EncodingPreference {
		encoding, ok := encodingNameToGNMI(preference)
		if !ok {
			continue
		}
		if !gnmiProductApprovesEncoding(contract, encoding) {
			continue
		}
		if _, ok := supported[encoding]; !ok {
			continue
		}
		authorized := true
		for i := range normalized {
			if (normalized[i].AllowAggregation && encoding == gnmipb.Encoding_PROTO) || !sharedGNMIStreamAllowsEncoding(normalized[i], encoding) {
				authorized = false
				break
			}
		}
		if !authorized {
			continue
		}
		return encoding, nil
	}
	return gnmipb.Encoding_JSON, errors.New("target advertises no encoding authorized by every configured stream")
}

func sharedGNMIStreamAllowsEncoding(stream sharedGNMIStream, wanted gnmipb.Encoding) bool {
	for _, preference := range stream.EncodingPreference {
		encoding, ok := encodingNameToGNMI(preference)
		if ok && encoding == wanted {
			return true
		}
	}
	return false
}

func sharedGNMIStreamContainsOrigin(stream sharedGNMIStream, origin string) bool {
	for i := range stream.Paths {
		if stream.Paths[i].Origin == origin {
			return true
		}
	}
	return false
}
