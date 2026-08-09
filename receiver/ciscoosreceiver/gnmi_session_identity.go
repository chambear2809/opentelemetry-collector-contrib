// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

const (
	sharedGNMIMaxIdentityNotifications = 64
	sharedGNMIMaxIdentityOperations    = 10_000
	sharedGNMIMaxIdentityRetainedBytes = 4 * 1024 * 1024
)

// sharedGNMIDeviceIdentity is populated only from an internal Subscribe ONCE
// transaction. Capabilities model names can narrow the probes attempted, but
// they never populate or prove any of these identity fields.
type sharedGNMIDeviceIdentity struct {
	OSFamily        string
	ProductFamily   string
	ModelIdentifier string
	SoftwareVersion string
	Manufacturer    string
	SerialNumber    string
	Hostname        string
	Role            string
	Platform        string
}

func (identity sharedGNMIDeviceIdentity) validForCatalogSelection() bool {
	return identity.OSFamily != "" && identity.ModelIdentifier != "" && identity.SoftwareVersion != ""
}

type sharedGNMIIdentityProbe struct {
	Name       string
	Platform   string
	Stream     sharedGNMIStream
	ListSchema []internalgnmi.JSONListKeySpec
}

// sharedGNMIIdentityProbes returns independent variants in preference order.
// A failed variant does not prove the product unsupported; the session planner
// exhausts the applicable variants before returning a compatibility failure.
func sharedGNMIIdentityProbes(platform string) []sharedGNMIIdentityProbe {
	base := func(name, platform string, paths ...sharedGNMIPath) sharedGNMIIdentityProbe {
		return sharedGNMIIdentityProbe{
			Name:     name,
			Platform: platform,
			Stream: sharedGNMIStream{
				Profile:    "_bootstrap_identity",
				Required:   true,
				Mode:       gnmiModeOnce,
				StreamMode: gnmiStreamModeTargetDefined,
				Encoding:   gnmiEncodingAuto,
				Paths:      paths,
			},
		}
	}

	switch platform {
	case gnmiPlatformIOSXE:
		probe := base("ios_xe_native", platform,
			sharedGNMIPath{Origin: builtinGNMIOriginRFC7951, Path: "Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware/device-inventory"},
			sharedGNMIPath{Origin: builtinGNMIOriginRFC7951, Path: "Cisco-IOS-XE-install-oper:install-oper-data/install-location-information/install-version-info"},
		)
		probe.ListSchema = []internalgnmi.JSONListKeySpec{
			{Origin: builtinGNMIOriginRFC7951, Elements: []string{"Cisco-IOS-XE-device-hardware-oper:device-hardware-data", "device-hardware", "device-inventory"}, Keys: []string{"hw-type", "hw-dev-index"}},
			{Origin: builtinGNMIOriginRFC7951, Elements: []string{"Cisco-IOS-XE-install-oper:install-oper-data", "install-location-information"}, Keys: []string{"fru", "slot", "bay", "chassis"}},
			{Origin: builtinGNMIOriginRFC7951, Elements: []string{"Cisco-IOS-XE-install-oper:install-oper-data", "install-location-information", "install-version-info"}, Keys: []string{"version", "version-extension"}},
		}
		return []sharedGNMIIdentityProbe{probe}
	case gnmiPlatformIOSXR:
		return []sharedGNMIIdentityProbe{base("ios_xr_install", platform,
			sharedGNMIPath{Origin: "Cisco-IOS-XR-install-oper", Path: "install/version"},
		)}
	case gnmiPlatformNXOS:
		probe := base("nx_os_openconfig_platform", platform,
			sharedGNMIPath{Origin: "openconfig-platform", Path: "components/component/state"},
		)
		probe.ListSchema = []internalgnmi.JSONListKeySpec{{
			Origin: "openconfig-platform", Elements: []string{"components", "component"}, Keys: []string{"name"},
		}}
		return []sharedGNMIIdentityProbe{probe}
	default:
		return nil
	}
}

// sharedGNMICapabilityFingerprint is stable across server ordering. It keys
// negative capability observations together with discovered PID and release.
func sharedGNMICapabilityFingerprint(capabilities *gnmipb.CapabilityResponse) string {
	if capabilities == nil {
		return ""
	}
	models := make([]string, 0, len(capabilities.GetSupportedModels()))
	for _, model := range capabilities.GetSupportedModels() {
		if model == nil {
			continue
		}
		models = append(models, model.GetName()+"\x00"+model.GetOrganization()+"\x00"+model.GetVersion())
	}
	sort.Strings(models)
	encodings := make([]int, 0, len(capabilities.GetSupportedEncodings()))
	for _, encoding := range capabilities.GetSupportedEncodings() {
		encodings = append(encodings, int(encoding))
	}
	sort.Ints(encodings)

	hash := sha256.New()
	hash.Write([]byte(capabilities.GetGNMIVersion()))
	hash.Write([]byte{0})
	for _, model := range models {
		hash.Write([]byte(model))
		hash.Write([]byte{0})
	}
	for _, encoding := range encodings {
		hash.Write([]byte(strconv.Itoa(encoding)))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// sharedGNMIEligiblePlatforms uses SupportedModels only to order/limit
// bootstrap attempts. The returned family is still verified from subscribed
// device identity before catalog selection.
func sharedGNMIEligiblePlatforms(expected string, capabilities *gnmipb.CapabilityResponse) ([]string, error) {
	if expected != "" && expected != gnmiPlatformIOSXE && expected != gnmiPlatformIOSXR && expected != gnmiPlatformNXOS {
		return nil, fmt.Errorf("unsupported expected gNMI platform %q", expected)
	}
	candidates := map[string]struct{}{}
	if capabilities != nil {
		for _, model := range capabilities.GetSupportedModels() {
			name := strings.ToLower(model.GetName())
			switch {
			case strings.Contains(name, "cisco-ios-xe"):
				candidates[gnmiPlatformIOSXE] = struct{}{}
			case strings.Contains(name, "cisco-ios-xr"):
				candidates[gnmiPlatformIOSXR] = struct{}{}
			case strings.Contains(name, "cisco-nx-os"):
				candidates[gnmiPlatformNXOS] = struct{}{}
			}
		}
	}
	if expected != "" {
		// A capability model name cannot prove the configured expectation
		// right or wrong. Probe the expectation first, then every differently
		// advertised family, and let subscribed identity plus exact catalog
		// matching make the assertion authoritative.
		observed := make([]string, 0, len(candidates)+1)
		observed = append(observed, expected)
		for candidate := range candidates {
			if candidate == expected {
				continue
			}
			observed = append(observed, candidate)
		}
		if len(observed) > 1 {
			sort.Strings(observed[1:])
		}
		return observed, nil
	}
	if len(candidates) > 0 {
		observed := make([]string, 0, len(candidates))
		for candidate := range candidates {
			observed = append(observed, candidate)
		}
		sort.Strings(observed)
		return observed, nil
	}
	// OpenConfig-only capability lists are common. Try all exact identity probes
	// in deterministic order and accept only a schema-valid identity result.
	return []string{gnmiPlatformIOSXE, gnmiPlatformIOSXR, gnmiPlatformNXOS}, nil
}

func discoverSharedGNMIDeviceIdentity(
	ctx context.Context,
	target GNMITargetConfig,
	client gnmipb.GNMIClient,
	capabilities *gnmipb.CapabilityResponse,
	admission *gnmiResponseAdmission,
) (sharedGNMIDeviceIdentity, error) {
	platforms, err := sharedGNMIEligiblePlatforms(target.Platform, capabilities)
	if err != nil {
		return sharedGNMIDeviceIdentity{}, err
	}
	encoding, err := sharedGNMIIdentityEncoding(target, capabilities)
	if err != nil {
		return sharedGNMIDeviceIdentity{}, err
	}
	var attempts []error
	for _, platform := range platforms {
		probes := sharedGNMIIdentityProbes(platform)
		for probeIndex := range probes {
			probe := probes[probeIndex]
			identity, probeErr := executeSharedGNMIIdentityProbe(ctx, target, client, probe, encoding, admission)
			if probeErr == nil {
				return identity, nil
			}
			attempts = append(attempts, probeErr)
			if ctx.Err() != nil {
				return sharedGNMIDeviceIdentity{}, ctx.Err()
			}
		}
	}
	if len(attempts) == 0 {
		return sharedGNMIDeviceIdentity{}, errors.New("no eligible Subscribe-ONCE identity probes")
	}
	return sharedGNMIDeviceIdentity{}, fmt.Errorf("all eligible Subscribe-ONCE identity probes failed: %w", errors.Join(attempts...))
}

func sharedGNMIIdentityEncoding(
	target GNMITargetConfig,
	capabilities *gnmipb.CapabilityResponse,
) (gnmipb.Encoding, error) {
	if capabilities == nil {
		return gnmipb.Encoding_JSON, errors.New("gNMI capabilities response is required for identity discovery")
	}
	for _, encoding := range sharedGNMIEncodingPreference(target) {
		if encoding != gnmipb.Encoding_JSON_IETF && encoding != gnmipb.Encoding_JSON {
			continue
		}
		if sharedGNMICapabilitiesSupportEncoding(capabilities, encoding) {
			return encoding, nil
		}
	}
	return gnmipb.Encoding_JSON, errors.New("identity probes require a target-advertised json_ietf or json encoding from encoding_preference")
}

func extractSharedGNMIDeviceIdentity(platform string, points []internalgnmi.Point) (sharedGNMIDeviceIdentity, error) {
	identity := sharedGNMIDeviceIdentity{OSFamily: platform, Manufacturer: "Cisco"}
	leafValues := make(map[string][]string)
	for pointIndex := range points {
		point := points[pointIndex]
		leaf := sharedGNMILocalName(point.Series.Leaf)
		value := sharedGNMIIdentityValue(point.Value)
		if value != "" {
			leafValues[leaf] = append(leafValues[leaf], value)
		}
	}
	unique := func(names ...string) []string {
		values := make([]string, 0)
		for _, name := range names {
			values = append(values, leafValues[name]...)
		}
		slices.Sort(values)
		return slices.Compact(values)
	}
	one := func(field string, names ...string) (string, error) {
		values := unique(names...)
		if len(values) == 0 {
			return "", fmt.Errorf("subscribed identity is missing %s", field)
		}
		if len(values) != 1 {
			return "", fmt.Errorf("subscribed identity has ambiguous %s", field)
		}
		return values[0], nil
	}

	var err error
	switch platform {
	case gnmiPlatformIOSXE:
		identity.ModelIdentifier, identity.SoftwareVersion, identity.SerialNumber, err = extractSharedGNMIIOSXEChassisAndVersion(points)
	case gnmiPlatformIOSXR:
		identity.ModelIdentifier, err = one("model identifier", "chassis-pid")
		if err == nil {
			identity.SoftwareVersion, err = one("software version", "label")
		}
	case gnmiPlatformNXOS:
		identity.ModelIdentifier, identity.SoftwareVersion, identity.SerialNumber, err = extractSharedGNMINXChassis(points)
	default:
		err = fmt.Errorf("unsupported identity platform %q", platform)
	}
	if err != nil {
		return sharedGNMIDeviceIdentity{}, err
	}
	if values := unique("serial-number", "serial-no", "serial"); identity.SerialNumber == "" && len(values) == 1 {
		identity.SerialNumber = values[0]
	}
	if values := unique("hostname", "host-name"); len(values) == 1 {
		identity.Hostname = values[0]
	}
	if values := unique("role"); len(values) == 1 {
		identity.Role = values[0]
	}
	if values := unique("platform"); len(values) == 1 {
		identity.Platform = values[0]
	}
	return identity, nil
}

func extractSharedGNMIIOSXEChassisAndVersion(points []internalgnmi.Point) (string, string, string, error) {
	type inventoryEntity struct {
		model, serial string
		chassis       bool
	}
	inventory := map[string]*inventoryEntity{}
	for pointIndex := range points {
		point := points[pointIndex]
		if point.Series.Origin != builtinGNMIOriginRFC7951 || !sharedGNMISeriesHasElementPath(point.Series, []string{
			"device-hardware-data", "device-hardware", "device-inventory",
		}) {
			continue
		}
		hardwareType := sharedGNMISeriesElementKey(point.Series, "device-inventory", "hw-type")
		hardwareIndex := sharedGNMISeriesElementKey(point.Series, "device-inventory", "hw-dev-index")
		if hardwareType == "" || hardwareIndex == "" {
			continue
		}
		entityKey := hardwareType + "\x00" + hardwareIndex
		entity := inventory[entityKey]
		if entity == nil {
			entity = &inventoryEntity{chassis: strings.EqualFold(sharedGNMILocalName(hardwareType), "hw-type-chassis")}
			inventory[entityKey] = entity
		}
		leaf := sharedGNMILocalName(point.Series.Leaf)
		value := sharedGNMIIdentityValue(point.Value)
		switch leaf {
		case "part-number", "chassis-pid":
			if entity.model != "" && entity.model != value {
				return "", "", "", fmt.Errorf("subscribed IOS XE chassis inventory %q has ambiguous model identifier", entityKey)
			}
			entity.model = value
		case "serial-number", "serial-no", "serial":
			if entity.serial != "" && entity.serial != value {
				return "", "", "", fmt.Errorf("subscribed IOS XE chassis inventory %q has ambiguous serial identity", entityKey)
			}
			entity.serial = value
		}
	}
	candidates := make([]inventoryEntity, 0, 1)
	for _, entity := range inventory {
		if entity.chassis && entity.model != "" {
			candidates = append(candidates, *entity)
		}
	}
	if len(candidates) != 1 {
		return "", "", "", errors.New("subscribed IOS XE identity must contain exactly one explicitly identified chassis inventory entry")
	}

	type versionEntity struct {
		values []string
		active bool
	}
	versions := map[string]*versionEntity{}
	for pointIndex := range points {
		point := points[pointIndex]
		if point.Series.Origin != builtinGNMIOriginRFC7951 || !sharedGNMISeriesHasElementPath(point.Series, []string{
			"install-oper-data", "install-location-information", "install-version-info",
		}) {
			continue
		}
		versionKey := sharedGNMISeriesElementKey(point.Series, "install-version-info", "version")
		versionExtension := sharedGNMISeriesElementKey(point.Series, "install-version-info", "version-extension")
		locationKey := sharedGNMISeriesCompositeKey(point.Series, "install-location-information", "fru", "slot", "bay", "chassis")
		if versionKey == "" || versionExtension == "" || locationKey == "" {
			continue
		}
		entityKey := locationKey + "\x00" + versionKey + "\x00" + versionExtension
		entity := versions[entityKey]
		if entity == nil {
			entity = &versionEntity{}
			versions[entityKey] = entity
		}
		entity.values = append(entity.values, versionKey)
		leaf := sharedGNMILocalName(point.Series.Leaf)
		value := sharedGNMIIdentityValue(point.Value)
		switch leaf {
		case "version", "version-number", "label":
			entity.values = append(entity.values, value)
		case "active", "is-active", "current", "running", "committed":
			entity.active = entity.active || sharedGNMIIdentityActiveValue(value)
		case "state", "status":
			entity.active = entity.active || sharedGNMIIdentityActiveValue(value)
		}
	}
	allVersions := make([]string, 0)
	activeVersions := make([]string, 0)
	for _, entity := range versions {
		values := uniqueSharedGNMIIdentityValues(entity.values)
		if len(values) > 1 {
			return "", "", "", errors.New("subscribed IOS XE install entry has ambiguous software version")
		}
		if len(values) == 0 {
			continue
		}
		allVersions = append(allVersions, values[0])
		if entity.active {
			activeVersions = append(activeVersions, values[0])
		}
	}
	allVersions = uniqueSharedGNMIIdentityValues(allVersions)
	activeVersions = uniqueSharedGNMIIdentityValues(activeVersions)
	var version string
	switch {
	case len(activeVersions) == 1:
		version = activeVersions[0]
	case len(activeVersions) > 1:
		return "", "", "", errors.New("subscribed IOS XE identity has multiple active software versions")
	case len(allVersions) == 1:
		version = allVersions[0]
	case len(allVersions) == 0:
		return "", "", "", errors.New("subscribed IOS XE identity is missing software version")
	default:
		return "", "", "", errors.New("subscribed IOS XE identity has ambiguous software version without an active marker")
	}
	return candidates[0].model, version, candidates[0].serial, nil
}

func sharedGNMISeriesHasElementPath(series internalgnmi.Series, expected []string) bool {
	if len(series.Elements) < len(expected) {
		return false
	}
	for start := 0; start <= len(series.Elements)-len(expected); start++ {
		matched := true
		for offset, name := range expected {
			if sharedGNMILocalName(series.Elements[start+offset].Name) != name {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func sharedGNMISeriesElementKey(series internalgnmi.Series, elementName, keyName string) string {
	for _, element := range series.Elements {
		if sharedGNMILocalName(element.Name) != elementName {
			continue
		}
		for key, value := range element.Keys {
			if sharedGNMILocalName(key) == keyName {
				return strings.TrimSpace(value)
			}
		}
	}
	return ""
}

func sharedGNMISeriesCompositeKey(series internalgnmi.Series, elementName string, keyNames ...string) string {
	values := make([]string, 0, len(keyNames))
	for _, keyName := range keyNames {
		value := sharedGNMISeriesElementKey(series, elementName, keyName)
		if value == "" {
			return ""
		}
		values = append(values, value)
	}
	return strings.Join(values, "\x00")
}

func sharedGNMIIdentityActiveValue(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "true", "1", "active", "activated", "current", "running", "committed", "selected":
		return true
	}
	return strings.HasSuffix(value, ":install-version-state-provisioned-committed") ||
		strings.HasSuffix(value, ":install-version-state-provisioned-uncommitted") ||
		value == "install-version-state-provisioned-committed" ||
		value == "install-version-state-provisioned-uncommitted"
}

func uniqueSharedGNMIIdentityValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func extractSharedGNMINXChassis(points []internalgnmi.Point) (string, string, string, error) {
	type component struct {
		typeName string
		model    string
		version  string
		serial   string
	}
	components := map[string]*component{}
	for pointIndex := range points {
		point := points[pointIndex]
		componentKey := ""
		for _, element := range point.Series.Elements {
			if sharedGNMILocalName(element.Name) != "component" {
				continue
			}
			componentKey = element.Keys["name"]
			if componentKey == "" {
				for key, value := range element.Keys {
					if sharedGNMILocalName(key) == "name" {
						componentKey = value
					}
				}
			}
		}
		if componentKey == "" {
			continue
		}
		item := components[componentKey]
		if item == nil {
			item = &component{}
			components[componentKey] = item
		}
		value := sharedGNMIIdentityValue(point.Value)
		switch sharedGNMILocalName(point.Series.Leaf) {
		case "type":
			item.typeName = value
		case "model-name":
			item.model = value
		case "software-version":
			item.version = value
		case "serial-no", "serial-number", "serial":
			item.serial = value
		}
	}
	models := make([]string, 0, 1)
	versions := make([]string, 0, 1)
	serials := make([]string, 0, 1)
	for _, component := range components {
		typeName := strings.ToUpper(sharedGNMILocalName(component.typeName))
		if typeName != "CHASSIS" || component.model == "" || component.version == "" {
			continue
		}
		models = append(models, component.model)
		versions = append(versions, component.version)
		serials = append(serials, component.serial)
	}
	if len(models) != 1 || len(versions) != 1 {
		return "", "", "", errors.New("subscribed OpenConfig platform identity must contain exactly one complete chassis component")
	}
	return models[0], versions[0], serials[0], nil
}

func sharedGNMILocalName(value string) string {
	if index := strings.LastIndexByte(value, ':'); index >= 0 {
		return value[index+1:]
	}
	return value
}

func sharedGNMIIdentityValue(value internalgnmi.Value) string {
	switch value.Kind {
	case internalgnmi.ValueString:
		return strings.TrimSpace(value.String)
	case internalgnmi.ValueInt:
		return strconv.FormatInt(value.Int, 10)
	case internalgnmi.ValueUint:
		return strconv.FormatUint(value.Uint, 10)
	case internalgnmi.ValueBool:
		return strconv.FormatBool(value.Bool)
	default:
		return ""
	}
}

// executeSharedGNMIIdentityProbe runs one internal identity transaction. It
// deliberately uses Subscribe ONCE and stages every decoded leaf until the
// server has sent sync_response=true and closed the stream. No partial
// identity is returned when decoding, synchronization, or extraction fails.
func executeSharedGNMIIdentityProbe(
	ctx context.Context,
	target GNMITargetConfig,
	client gnmipb.GNMIClient,
	probe sharedGNMIIdentityProbe,
	encoding gnmipb.Encoding,
	admission *gnmiResponseAdmission,
) (sharedGNMIDeviceIdentity, error) {
	if client == nil {
		return sharedGNMIDeviceIdentity{}, errors.New("gNMI identity client is required")
	}
	if probe.Name == "" {
		return sharedGNMIDeviceIdentity{}, errors.New("gNMI identity probe name is required")
	}
	if probe.Platform == "" {
		return sharedGNMIDeviceIdentity{}, fmt.Errorf("gNMI identity probe %q has no platform", probe.Name)
	}
	if probe.Stream.Mode != gnmiModeOnce {
		return sharedGNMIDeviceIdentity{}, fmt.Errorf("gNMI identity probe %q must use Subscribe ONCE", probe.Name)
	}
	if encoding != gnmipb.Encoding_JSON && encoding != gnmipb.Encoding_JSON_IETF {
		return sharedGNMIDeviceIdentity{}, fmt.Errorf("gNMI identity probe %q requires json or json_ietf encoding", probe.Name)
	}

	target = target.withDefaults()
	if target.SyncTimeout <= 0 || target.SyncTimeout > gnmiMaximumSyncTimeout {
		return sharedGNMIDeviceIdentity{}, fmt.Errorf("gNMI identity probe %q has invalid sync timeout %s", probe.Name, target.SyncTimeout)
	}
	schema, err := internalgnmi.NewJSONListKeySchema(probe.ListSchema...)
	if err != nil {
		return sharedGNMIDeviceIdentity{}, fmt.Errorf("gNMI identity probe %q JSON schema: %w", probe.Name, err)
	}
	requestTarget := target
	requestTarget.Platform = probe.Platform
	request, err := buildSharedGNMISubscribeRequest(requestTarget, probe.Stream, encoding)
	if err != nil {
		return sharedGNMIDeviceIdentity{}, fmt.Errorf("build gNMI identity probe %q: %w", probe.Name, err)
	}
	if request.GetSubscribe().GetMode() != gnmipb.SubscriptionList_ONCE {
		return sharedGNMIDeviceIdentity{}, fmt.Errorf("gNMI identity probe %q did not build a Subscribe ONCE request", probe.Name)
	}

	probeCtx, cancel := context.WithTimeout(ctx, target.SyncTimeout)
	defer cancel()
	subscribe, err := client.Subscribe(
		sharedGNMIOutgoingContext(probeCtx, target),
		gnmiResponsePreflightCallOption(target.MaxRecvMsgSizeMiB, admission, probeCtx.Done()),
	)
	if err != nil {
		return sharedGNMIDeviceIdentity{}, sharedGNMIIdentityProbeRPCError(probeCtx, probe.Name, err)
	}
	if sendErr := subscribe.Send(request); sendErr != nil {
		return sharedGNMIDeviceIdentity{}, sharedGNMIIdentityProbeRPCError(probeCtx, probe.Name, sendErr)
	}
	if closeErr := subscribe.CloseSend(); closeErr != nil {
		return sharedGNMIDeviceIdentity{}, sharedGNMIIdentityProbeRPCError(probeCtx, probe.Name, closeErr)
	}
	points, err := receiveSharedGNMIIdentity(target.Name, subscribe, admission, schema, probe.Stream.Paths)
	if err != nil {
		return sharedGNMIDeviceIdentity{}, sharedGNMIIdentityProbeRPCError(probeCtx, probe.Name, err)
	}
	identity, err := extractSharedGNMIDeviceIdentity(probe.Platform, points)
	if err != nil {
		return sharedGNMIDeviceIdentity{}, fmt.Errorf("extract gNMI identity probe %q: %w", probe.Name, err)
	}
	if !identity.validForCatalogSelection() {
		return sharedGNMIDeviceIdentity{}, fmt.Errorf("gNMI identity probe %q returned incomplete catalog identity", probe.Name)
	}
	return identity, nil
}

func sharedGNMIIdentityProbeRPCError(ctx context.Context, name string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("gNMI identity probe %q: %w", name, ctxErr)
	}
	return fmt.Errorf("gNMI identity probe %q: %w", name, classifySharedGNMIStreamError(err))
}

func receiveSharedGNMIIdentity(
	target string,
	stream grpc.ClientStream,
	admission *gnmiResponseAdmission,
	schema *internalgnmi.JSONListKeySchema,
	requested []sharedGNMIPath,
) ([]internalgnmi.Point, error) {
	scopes, err := sharedGNMIIdentityScopes(target, requested)
	if err != nil {
		return nil, err
	}
	points := make(map[string]internalgnmi.Point)
	tombstones := make([]sharedGNMIIdentityTombstone, 0)
	notifications := 0
	decodedOperations := 0
	retainedBytes := 0
	synced := false
	for {
		response, err := receiveGNMISubscribeResponse(stream, admission)
		if errors.Is(err, io.EOF) {
			if !synced {
				return nil, io.ErrUnexpectedEOF
			}
			out := make([]internalgnmi.Point, 0, len(points))
			for key := range points {
				out = append(out, points[key])
			}
			sort.Slice(out, func(i, j int) bool { return out[i].Series.Key() < out[j].Series.Key() })
			return out, nil
		}
		if err != nil {
			return nil, classifySharedGNMIStreamError(err)
		}
		if synced {
			admission.release(response)
			return nil, errors.New("gNMI identity Subscribe ONCE stream returned data after sync_response=true")
		}
		switch body := response.GetResponse().(type) {
		case *gnmipb.SubscribeResponse_Update:
			if body.Update == nil {
				admission.release(response)
				return nil, errors.New("empty gNMI identity notification")
			}
			notifications++
			if notifications > sharedGNMIMaxIdentityNotifications {
				admission.release(response)
				return nil, fmt.Errorf("identity subscription exceeds %d notifications", sharedGNMIMaxIdentityNotifications)
			}
			decoded, stats, decodeErr := internalgnmi.DecodeNotificationWithSchema(target, body.Update, time.Now(), schema)
			if decodeErr != nil {
				admission.release(response)
				return nil, fmt.Errorf("decode subscribed identity: %w", decodeErr)
			}
			if err := validateSharedGNMIIdentityNotificationScope(decoded, scopes); err != nil {
				admission.release(response)
				return nil, err
			}
			if stats.UnmappedValues != 0 {
				admission.release(response)
				return nil, fmt.Errorf("subscribed identity contains %d unsupported or non-scalar values", stats.UnmappedValues)
			}
			operations := len(decoded.Updates) + len(decoded.Touched) + len(decoded.Deletes)
			if operations > sharedGNMIMaxIdentityOperations-decodedOperations {
				admission.release(response)
				return nil, fmt.Errorf("identity subscription exceeds %d decoded operations", sharedGNMIMaxIdentityOperations)
			}
			notificationBytes := sharedGNMIIdentityNotificationRetainedBytes(decoded)
			if notificationBytes > sharedGNMIMaxIdentityRetainedBytes-retainedBytes {
				admission.release(response)
				return nil, fmt.Errorf("identity subscription exceeds %d retained bytes", sharedGNMIMaxIdentityRetainedBytes)
			}
			decodedOperations += operations
			retainedBytes += notificationBytes
			applySharedGNMIIdentityNotification(points, &tombstones, decoded)
		case *gnmipb.SubscribeResponse_SyncResponse:
			synced = synced || body.SyncResponse
		case *gnmipb.SubscribeResponse_Error:
			admission.release(response)
			//nolint:staticcheck // gNMI's deprecated response arm is still required for protocol compatibility.
			subscribeErr := body.Error
			if subscribeErr == nil {
				return nil, errors.New("empty gNMI identity Subscribe error")
			}
			return nil, classifySharedGNMIStreamError(sanitizedGNMISubscribeStatusError(subscribeErr))
		default:
			admission.release(response)
			return nil, errors.New("empty gNMI identity Subscribe response")
		}
		admission.release(response)
	}
}

type sharedGNMIIdentityTombstone struct {
	selector  internalgnmi.Path
	timestamp time.Time
}

func sharedGNMIIdentityScopes(target string, requested []sharedGNMIPath) ([]internalgnmi.Path, error) {
	if len(requested) == 0 {
		return nil, errors.New("gNMI identity probe has no requested paths")
	}
	scopes := make([]internalgnmi.Path, 0, len(requested))
	for _, requestedPath := range requested {
		scope, err := internalgnmi.ParsePath(target, requestedPath.Origin, requestedPath.Path)
		if err != nil {
			return nil, fmt.Errorf("parse gNMI identity probe path %s:%s: %w", requestedPath.Origin, requestedPath.Path, err)
		}
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

func validateSharedGNMIIdentityNotificationScope(
	decoded internalgnmi.DecodedNotification,
	scopes []internalgnmi.Path,
) error {
	withinScope := func(path internalgnmi.Path) bool {
		return slices.ContainsFunc(scopes, path.HasPrefix)
	}
	overlapsScope := func(path internalgnmi.Path) bool {
		return slices.ContainsFunc(scopes, func(scope internalgnmi.Path) bool {
			return path.HasPrefix(scope) || scope.HasPrefix(path)
		})
	}
	for pointIndex := range decoded.Updates {
		point := decoded.Updates[pointIndex]
		if !withinScope(point.Series.Path()) {
			return fmt.Errorf("subscribed identity update %q is outside every requested probe path", point.Series.Path().String())
		}
	}
	for _, touched := range decoded.Touched {
		if !withinScope(touched) {
			return fmt.Errorf("subscribed identity update %q is outside every requested probe path", touched.String())
		}
	}
	for _, deleted := range decoded.Deletes {
		if !withinScope(deleted) {
			return fmt.Errorf("subscribed identity delete %q is outside every requested probe path", deleted.String())
		}
	}
	if decoded.Atomic && !overlapsScope(decoded.Prefix) {
		return fmt.Errorf("subscribed identity atomic prefix %q is outside every requested probe path", decoded.Prefix.String())
	}
	return nil
}

func sharedGNMIIdentityNotificationRetainedBytes(decoded internalgnmi.DecodedNotification) int {
	retained := len(decoded.Prefix.Key())
	for _, touched := range decoded.Touched {
		retained += len(touched.Key())
	}
	for _, deleted := range decoded.Deletes {
		retained += len(deleted.Key())
	}
	for pointIndex := range decoded.Updates {
		point := decoded.Updates[pointIndex]
		retained += len(point.Series.Key()) + 64
		if point.Value.Kind == internalgnmi.ValueString {
			retained += len(point.Value.String)
		}
	}
	return retained
}

func applySharedGNMIIdentityNotification(
	points map[string]internalgnmi.Point,
	tombstones *[]sharedGNMIIdentityTombstone,
	decoded internalgnmi.DecodedNotification,
) {
	remove := func(selector internalgnmi.Path, timestamp time.Time) {
		for key := range points {
			point := points[key]
			if point.Series.Path().HasPrefix(selector) && !point.Timestamp.After(timestamp) {
				delete(points, key)
			}
		}
		*tombstones = compactSharedGNMIIdentityTombstones(
			*tombstones,
			sharedGNMIIdentityTombstone{selector: selector.Clone(), timestamp: timestamp},
		)
	}
	if decoded.Atomic {
		remove(decoded.Prefix, decoded.Timestamp)
	}
	for _, deleted := range decoded.Deletes {
		remove(deleted, decoded.Timestamp)
	}
	for pointIndex := range decoded.Updates {
		point := decoded.Updates[pointIndex]
		blocked := slices.ContainsFunc(*tombstones, func(tombstone sharedGNMIIdentityTombstone) bool {
			return point.Series.Path().HasPrefix(tombstone.selector) && tombstone.timestamp.After(point.Timestamp)
		})
		if blocked {
			continue
		}
		key := point.Series.Key()
		if previous, ok := points[key]; ok && previous.Timestamp.After(point.Timestamp) {
			continue
		}
		points[key] = point
	}
}

func compactSharedGNMIIdentityTombstones(
	existing []sharedGNMIIdentityTombstone,
	candidate sharedGNMIIdentityTombstone,
) []sharedGNMIIdentityTombstone {
	for _, tombstone := range existing {
		if candidate.selector.HasPrefix(tombstone.selector) && !candidate.timestamp.After(tombstone.timestamp) {
			return existing
		}
	}
	out := existing[:0]
	for _, tombstone := range existing {
		if tombstone.selector.HasPrefix(candidate.selector) && !tombstone.timestamp.After(candidate.timestamp) {
			continue
		}
		out = append(out, tombstone)
	}
	return append(out, candidate)
}
