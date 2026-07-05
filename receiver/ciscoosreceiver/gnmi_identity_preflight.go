// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
)

const (
	gnmiPreflightIdentityMissing      = "identity_missing"
	gnmiPreflightIdentityAmbiguous    = "identity_ambiguous"
	gnmiPreflightProductMismatch      = "product_mismatch"
	gnmiPreflightReleaseMismatch      = "release_mismatch"
	gnmiPreflightMissingModel         = "missing_model"
	gnmiPreflightUnsupportedEncoding  = "unsupported_encoding"
	gnmiPreflightMalformedIdentity    = "malformed_identity"
	gnmiMaximumIdentityNotifications  = 64
	gnmiMaximumIdentityDecodedUpdates = 10_000
)

// sharedGNMICompatibilityError is a deterministic product-contract failure.
// It is terminal for only the affected target and is deliberately separate
// from transport, authentication, and temporary RPC errors, which retain the
// receiver's reconnect behavior.
type sharedGNMICompatibilityError struct {
	reason string
	err    error
}

func (e *sharedGNMICompatibilityError) Error() string {
	if e == nil || e.err == nil {
		return "gNMI product compatibility preflight failed"
	}
	return e.err.Error()
}

func (e *sharedGNMICompatibilityError) Unwrap() error { return e.err }

func newSharedGNMICompatibilityError(reason string, err error) error {
	if !validGNMIPreflightFailureReason(reason) {
		reason = gnmiPreflightMalformedIdentity
	}
	if err == nil {
		err = errors.New("gNMI product compatibility preflight failed")
	}
	return &sharedGNMICompatibilityError{reason: reason, err: err}
}

func validGNMIPreflightFailureReason(reason string) bool {
	switch reason {
	case gnmiPreflightIdentityMissing,
		gnmiPreflightIdentityAmbiguous,
		gnmiPreflightProductMismatch,
		gnmiPreflightReleaseMismatch,
		gnmiPreflightMissingModel,
		gnmiPreflightUnsupportedEncoding,
		gnmiPreflightMalformedIdentity:
		return true
	default:
		return false
	}
}

type verifiedGNMIIdentity struct {
	Product         string
	OSFamily        string
	ModelIdentifier string
	SoftwareVersion string
}

func (identity verifiedGNMIIdentity) valid() bool {
	return identity.Product != "" && identity.OSFamily != "" &&
		identity.ModelIdentifier != "" && identity.SoftwareVersion != ""
}

func validateGNMIRequiredModels(
	contract *gnmiProductContract,
	streams []sharedGNMIStream,
	capabilities *gnmipb.CapabilityResponse,
) error {
	if contract == nil || capabilities == nil {
		return newSharedGNMICompatibilityError(
			gnmiPreflightMissingModel,
			errors.New("gNMI Capabilities did not provide the product contract model set"),
		)
	}
	advertised := make(map[string]struct{}, len(capabilities.GetSupportedModels()))
	for _, model := range capabilities.GetSupportedModels() {
		if model == nil {
			continue
		}
		name := strings.TrimSpace(model.GetName())
		if name != "" {
			advertised[name] = struct{}{}
		}
	}
	required := requiredGNMIModels(contract, streams)
	missing := make([]string, 0, len(required))
	for _, model := range required {
		if _, ok := advertised[model]; !ok {
			missing = append(missing, model)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return newSharedGNMICompatibilityError(
		gnmiPreflightMissingModel,
		fmt.Errorf("gNMI target does not advertise required models: %s", strings.Join(missing, ", ")),
	)
}

func runGNMIIdentityPreflight(
	ctx context.Context,
	conn grpc.ClientConnInterface,
	admission *gnmiResponseAdmission,
	target GNMITargetConfig,
	contract *gnmiProductContract,
	configuredVersion gnmiSoftwareVersion,
	encoding gnmipb.Encoding,
) (verifiedGNMIIdentity, error) {
	if contract == nil {
		return verifiedGNMIIdentity{}, newSharedGNMICompatibilityError(
			gnmiPreflightMalformedIdentity,
			errors.New("gNMI product contract is unavailable"),
		)
	}
	pointsByProbe := make(map[string][]internalgnmi.Point, len(contract.IdentityProbes))
	for i := range contract.IdentityProbes {
		probe := &contract.IdentityProbes[i]
		request, err := buildGNMIIdentityGetRequest(*probe, encoding)
		if err != nil {
			return verifiedGNMIIdentity{}, newSharedGNMICompatibilityError(gnmiPreflightMalformedIdentity, err)
		}
		probeCtx, cancel := context.WithTimeout(ctx, target.CapabilitiesTimeout)
		response, err := invokeGNMIGet(
			sharedGNMIOutgoingContext(probeCtx, target),
			conn,
			admission,
			target.MaxRecvMsgSizeMiB,
			request,
		)
		cancel()
		if err != nil {
			// Some servers incorrectly use deterministic-looking status codes for
			// credential failures. Preserve authentication as a retryable operational
			// failure instead of quarantining a compatible product.
			if isSharedGNMIAuthenticationError(err) {
				return verifiedGNMIIdentity{}, fmt.Errorf("identity Get %q: %w", probe.Name, err)
			}
			if deterministicGNMIIdentityRPCError(err) {
				return verifiedGNMIIdentity{}, newSharedGNMICompatibilityError(
					gnmiPreflightMalformedIdentity,
					fmt.Errorf("identity Get %q is incompatible with the product contract: %w", probe.Name, sanitizedGNMIRPCError(err)),
				)
			}
			return verifiedGNMIIdentity{}, fmt.Errorf("identity Get %q: %w", probe.Name, err)
		}
		points, decodeErr := decodeGNMIIdentityGetResponse(target.Name, response)
		admission.release(response)
		if decodeErr != nil {
			var responseStatus *gnmiIdentityResponseStatusError
			if errors.As(decodeErr, &responseStatus) {
				if isSharedGNMIAuthenticationError(responseStatus.err) || !deterministicGNMIIdentityRPCError(responseStatus.err) {
					return verifiedGNMIIdentity{}, fmt.Errorf("identity Get %q: %w", probe.Name, responseStatus.err)
				}
			}
			return verifiedGNMIIdentity{}, newSharedGNMICompatibilityError(
				gnmiPreflightMalformedIdentity,
				// Decode errors can contain device-controlled schema names. The
				// endpoint has already seen request metadata, so do not reflect
				// detailed peer data into the quarantine log.
				fmt.Errorf("identity Get %q returned malformed data", probe.Name),
			)
		}
		if validationErr := validateGNMIIdentityProbePoints(*probe, points); validationErr != nil {
			return verifiedGNMIIdentity{}, newSharedGNMICompatibilityError(
				gnmiPreflightMalformedIdentity,
				fmt.Errorf("identity Get %q returned data outside its requested STATE subtree: %w", probe.Name, validationErr),
			)
		}
		pointsByProbe[probe.Name] = points
	}

	model, observedRaw, err := extractGNMIProductIdentity(contract, pointsByProbe)
	if err != nil {
		return verifiedGNMIIdentity{}, err
	}
	if !contract.MatchesChassis(model) {
		return verifiedGNMIIdentity{}, newSharedGNMICompatibilityError(
			gnmiPreflightProductMismatch,
			errors.New("verified chassis identifier does not match the configured Cisco product"),
		)
	}
	observedVersion, err := contract.ParseSoftwareVersion(observedRaw)
	if err != nil {
		return verifiedGNMIIdentity{}, newSharedGNMICompatibilityError(
			gnmiPreflightMalformedIdentity,
			errors.New("verified software version has an unsupported syntax"),
		)
	}
	if observedVersion.Train != contract.ReleaseTrain || configuredVersion.Train != contract.ReleaseTrain ||
		observedVersion.Canonical != configuredVersion.Canonical {
		return verifiedGNMIIdentity{}, newSharedGNMICompatibilityError(
			gnmiPreflightReleaseMismatch,
			errors.New("verified software version does not exactly match the configured build and release train"),
		)
	}
	return verifiedGNMIIdentity{
		Product:         contract.Product,
		OSFamily:        contract.OSFamily,
		ModelIdentifier: model,
		SoftwareVersion: observedVersion.Canonical,
	}, nil
}

// buildGNMIIdentityGetRequest constructs one bounded read-only identity probe.
func buildGNMIIdentityGetRequest(probe gnmiIdentityProbe, encoding gnmipb.Encoding) (*gnmipb.GetRequest, error) {
	if len(probe.Paths) == 0 {
		return nil, fmt.Errorf("identity probe %q has no paths", probe.Name)
	}
	request := &gnmipb.GetRequest{Type: gnmipb.GetRequest_STATE, Encoding: encoding}
	if probe.PrefixTarget != "" || probe.PrefixOrigin != "" {
		request.Prefix = &gnmipb.Path{Target: probe.PrefixTarget, Origin: probe.PrefixOrigin}
	}
	for i := range probe.Paths {
		configured := &probe.Paths[i]
		pathTarget := configured.PathTarget
		if probe.PrefixTarget != "" {
			if pathTarget != "" && pathTarget != probe.PrefixTarget {
				return nil, fmt.Errorf("identity probe %q path target %q conflicts with prefix target %q", probe.Name, pathTarget, probe.PrefixTarget)
			}
			pathTarget = ""
		}
		origin := configured.Origin
		if probe.PrefixOrigin != "" {
			if origin != "" && origin != probe.PrefixOrigin {
				return nil, fmt.Errorf("identity probe %q path origin %q conflicts with prefix origin %q", probe.Name, origin, probe.PrefixOrigin)
			}
			origin = ""
		}
		path, err := sharedGNMIPathToProto(pathTarget, origin, configured.Path)
		if err != nil {
			return nil, fmt.Errorf("identity probe %q path %q: %w", probe.Name, configured.Path, err)
		}
		request.Path = append(request.Path, path)
	}
	return request, nil
}

func validateGNMIIdentityProbePoints(probe gnmiIdentityProbe, points []internalgnmi.Point) error {
	roots := make([]internalgnmi.Path, 0, len(probe.Paths))
	for i := range probe.Paths {
		configured := &probe.Paths[i]
		pathTarget := configured.PathTarget
		if probe.PrefixTarget != "" {
			pathTarget = probe.PrefixTarget
		}
		origin := configured.Origin
		if probe.PrefixOrigin != "" {
			origin = probe.PrefixOrigin
		}
		path, err := sharedGNMIPathToProto(pathTarget, origin, configured.Path)
		if err != nil {
			return fmt.Errorf("configured probe path %q is invalid: %w", configured.Path, err)
		}
		roots = append(roots, internalgnmi.PathFromProto(path))
	}
	for i := range points {
		point := &points[i]
		path := point.Series.Path()
		matched := slices.ContainsFunc(roots, func(root internalgnmi.Path) bool {
			return path.PathTarget == root.PathTarget && path.Origin == root.Origin && path.HasPrefix(root)
		})
		if !matched {
			// Do not include a peer-controlled path or key value in this error. It
			// is logged when the target is quarantined, and an endpoint could echo
			// credentials it observed in request metadata into an invalid path.
			return fmt.Errorf("decoded identity point %d does not match a configured probe path", i)
		}
		qualifiedNameValid := func(name string) bool {
			if !strings.Contains(name, ":") {
				return true
			}
			module, qualified := splitGNMIQualifiedName(name)
			return qualified && module == probe.Model
		}
		for _, element := range point.Series.Elements {
			if !qualifiedNameValid(element.Name) {
				return fmt.Errorf("decoded identity point %d contains a qualified name outside the required identity model", i)
			}
			for key := range element.Keys {
				if !qualifiedNameValid(key) {
					return fmt.Errorf("decoded identity point %d contains a qualified name outside the required identity model", i)
				}
			}
		}
		if !qualifiedNameValid(point.Series.Leaf) {
			return fmt.Errorf("decoded identity point %d contains a qualified name outside the required identity model", i)
		}
	}
	return nil
}

type gnmiIdentityResponseStatusError struct{ err error }

func (e *gnmiIdentityResponseStatusError) Error() string { return e.err.Error() }
func (e *gnmiIdentityResponseStatusError) Unwrap() error { return e.err }

//nolint:staticcheck // Deprecated in-band Error remains part of GetResponse.
func decodeGNMIIdentityGetResponse(target string, response *gnmipb.GetResponse) ([]internalgnmi.Point, error) {
	if response == nil {
		return nil, errors.New("empty Get response")
	}
	if response.GetError() != nil {
		return nil, &gnmiIdentityResponseStatusError{err: sanitizedGNMISubscribeStatusError(response.GetError())}
	}
	if len(response.GetNotification()) > gnmiMaximumIdentityNotifications {
		return nil, fmt.Errorf("Get response exceeds %d notifications", gnmiMaximumIdentityNotifications)
	}
	points := make([]internalgnmi.Point, 0)
	for _, notification := range response.GetNotification() {
		// Get returns a snapshot of existing state. A delete operation has no
		// useful identity meaning and accepting it would leave an unvalidated,
		// peer-controlled path outside the probe subtree.
		if len(notification.GetDelete()) != 0 {
			return nil, errors.New("Get response contains delete operations")
		}
		decoded, _, err := internalgnmi.DecodeNotification(target, notification, time.Now())
		if err != nil {
			return nil, err
		}
		if len(decoded.Updates) > gnmiMaximumIdentityDecodedUpdates-len(points) {
			return nil, fmt.Errorf("Get response exceeds %d decoded identity leaves", gnmiMaximumIdentityDecodedUpdates)
		}
		points = append(points, decoded.Updates...)
	}
	return points, nil
}

func deterministicGNMIIdentityRPCError(err error) bool {
	if err == nil {
		return false
	}
	// Errors marked by the local bounded response codec describe peer-controlled
	// wire shape, not a temporary transport condition. Never infer this from
	// text because a remote endpoint controls its gRPC status description.
	if localGNMIResponsePreflightRejected(err) {
		return true
	}
	switch status.Code(err) {
	case codes.InvalidArgument, codes.NotFound, codes.Unimplemented, codes.FailedPrecondition, codes.OutOfRange, codes.DataLoss:
		return true
	case codes.ResourceExhausted:
		return clientGNMIResponseTooLarge(err)
	default:
		return false
	}
}

func clientGNMIResponseTooLarge(err error) bool {
	if status.Code(err) != codes.ResourceExhausted {
		return false
	}
	message := status.Convert(err).Message()
	var received, maximum int64
	if count, scanErr := fmt.Sscanf(message, "grpc: received message larger than max (%d vs. %d)", &received, &maximum); scanErr == nil && count == 2 &&
		message == fmt.Sprintf("grpc: received message larger than max (%d vs. %d)", received, maximum) {
		return received > maximum && maximum > 0
	}
	if count, scanErr := fmt.Sscanf(message, "grpc: received message after decompression larger than max %d", &maximum); scanErr == nil && count == 1 &&
		message == fmt.Sprintf("grpc: received message after decompression larger than max %d", maximum) {
		return maximum > 0
	}
	return false
}

type gnmiIdentityGroup map[string][]internalgnmi.Value

func extractGNMIProductIdentity(
	contract *gnmiProductContract,
	pointsByProbe map[string][]internalgnmi.Point,
) (string, string, error) {
	switch contract.OSFamily {
	case gnmiPlatformIOSXE:
		return extractIOSXEGNMIIdentity(
			contract,
			pointsByProbe["ios_xe_hardware_inventory"],
			pointsByProbe["ios_xe_current_install_version"],
		)
	case gnmiPlatformIOSXR:
		return extractIOSXRGNMIIdentity(pointsByProbe["ios_xr_install_version"])
	case gnmiPlatformNXOS:
		return extractNXOSGNMIIdentity(pointsByProbe["nx_os_openconfig_platform"])
	default:
		return "", "", newSharedGNMICompatibilityError(
			gnmiPreflightMalformedIdentity,
			errors.New("product contract has an unsupported operating-system family"),
		)
	}
}

func extractIOSXEGNMIIdentity(
	contract *gnmiProductContract,
	hardwarePoints []internalgnmi.Point,
	versionPoints []internalgnmi.Point,
) (string, string, error) {
	inventory := groupGNMIIdentityPoints(hardwarePoints, "device-inventory", nil, []string{"hw-type", "hw-dev-index"})
	models := make([]string, 0, len(inventory))
	chassisGroups := 0
	for _, group := range inventory {
		isChassis, validationErr := validateIOSXEHardwareIdentityGroup(group)
		if validationErr != nil {
			return "", "", newSharedGNMICompatibilityError(gnmiPreflightMalformedIdentity, validationErr)
		}
		if !isChassis {
			continue
		}
		chassisGroups++
		partNumbers, validationErr := strictIdentityStrings(group["part-number"], false)
		if validationErr != nil {
			return "", "", newSharedGNMICompatibilityError(
				gnmiPreflightMalformedIdentity,
				errors.New("hardware inventory chassis has a malformed part-number"),
			)
		}
		models = append(models, partNumbers...)
	}
	if chassisGroups > 1 {
		return "", "", newSharedGNMICompatibilityError(gnmiPreflightIdentityAmbiguous, errors.New("hardware inventory contains multiple chassis entries"))
	}
	models = uniqueIdentityStrings(models)
	switch len(models) {
	case 0:
		return "", "", newSharedGNMICompatibilityError(gnmiPreflightIdentityMissing, errors.New("hardware inventory contains no chassis identifier"))
	case 1:
	default:
		return "", "", newSharedGNMICompatibilityError(gnmiPreflightIdentityAmbiguous, errors.New("hardware inventory contains multiple chassis identifiers"))
	}
	if !contract.MatchesChassis(models[0]) {
		return "", "", newSharedGNMICompatibilityError(gnmiPreflightProductMismatch, errors.New("hardware inventory chassis does not match the configured Cisco product"))
	}

	versions := make([]string, 0, 1)
	for _, group := range groupGNMIIdentityPoints(
		versionPoints,
		"install-version-info",
		nil,
		[]string{"fru", "slot", "bay", "chassis", "version", "version-extension"},
	) {
		isCurrent, validationErr := validateIOSXEInstallIdentityGroup(group)
		if validationErr != nil {
			return "", "", newSharedGNMICompatibilityError(gnmiPreflightMalformedIdentity, validationErr)
		}
		if !isCurrent {
			continue
		}
		// version-extension is the second list key used to distinguish install
		// records. Cisco documents it as a separate opaque discriminator;
		// it is not a suffix of the public IOS XE version. The version key itself
		// may use the internal major.minor.maintenance.0.build representation,
		// which the strict IOS XE parser canonicalizes to the public release.
		versionValues, validationErr := strictIdentityStrings(group["version"], false)
		if validationErr != nil {
			return "", "", newSharedGNMICompatibilityError(
				gnmiPreflightMalformedIdentity,
				errors.New("install inventory contains a malformed software version"),
			)
		}
		for _, version := range versionValues {
			parsed, parseErr := parseIOSXEInstallSoftwareVersion(version)
			if parseErr != nil {
				// Retain malformed current identities so a single bad value is
				// classified as malformed and mixed good/bad values remain
				// unambiguously fail-closed as multiple current identities.
				versions = append(versions, version)
				continue
			}
			versions = append(versions, parsed.Canonical)
		}
	}
	versions = uniqueIdentityStrings(versions)
	switch len(versions) {
	case 0:
		return "", "", newSharedGNMICompatibilityError(gnmiPreflightIdentityMissing, errors.New("install inventory contains no current software version"))
	case 1:
		return models[0], versions[0], nil
	default:
		return "", "", newSharedGNMICompatibilityError(gnmiPreflightIdentityAmbiguous, errors.New("install inventory contains multiple current software versions"))
	}
}

func extractIOSXRGNMIIdentity(points []internalgnmi.Point) (string, string, error) {
	models, modelErr := uniqueStrictIdentityPathLeafStrings(points, []string{"install", "version"}, "chassis-pid")
	versions, versionErr := uniqueStrictIdentityPathLeafStrings(points, []string{"install", "version"}, "label")
	if modelErr != nil || versionErr != nil {
		return "", "", newSharedGNMICompatibilityError(
			gnmiPreflightMalformedIdentity,
			errors.New("IOS XR install/version contains a malformed chassis PID or release label"),
		)
	}
	if len(models) == 0 || len(versions) == 0 {
		return "", "", newSharedGNMICompatibilityError(gnmiPreflightIdentityMissing, errors.New("IOS XR install/version is missing chassis PID or release label"))
	}
	if len(models) != 1 || len(versions) != 1 {
		return "", "", newSharedGNMICompatibilityError(gnmiPreflightIdentityAmbiguous, errors.New("IOS XR install/version contains ambiguous chassis PID or release label"))
	}
	return models[0], versions[0], nil
}

func extractNXOSGNMIIdentity(points []internalgnmi.Point) (string, string, error) {
	components := groupGNMIIdentityPoints(points, "component", []string{"state"}, nil)
	chassis := make([]gnmiIdentityGroup, 0, 1)
	for _, group := range components {
		if _, keyErr := requiredIdentityListKey(group, "component", "name"); keyErr != nil {
			return "", "", newSharedGNMICompatibilityError(
				gnmiPreflightMalformedIdentity,
				errors.New("OpenConfig platform component is missing its required name key"),
			)
		}
		componentTypes, typeErr := strictIdentityStrings(group["type"], false)
		if typeErr != nil {
			return "", "", newSharedGNMICompatibilityError(
				gnmiPreflightMalformedIdentity,
				errors.New("OpenConfig platform component has a malformed type"),
			)
		}
		localTypes := make([]string, 0, len(componentTypes))
		for _, componentType := range componentTypes {
			localTypes = append(localTypes, localGNMIIdentityValue(componentType))
		}
		localTypes = uniqueIdentityStrings(localTypes)
		if len(localTypes) > 1 {
			return "", "", newSharedGNMICompatibilityError(
				gnmiPreflightMalformedIdentity,
				errors.New("OpenConfig platform component contains conflicting types"),
			)
		}
		if len(localTypes) == 1 && localTypes[0] == "CHASSIS" {
			chassis = append(chassis, group)
		}
	}
	if len(chassis) == 0 {
		return "", "", newSharedGNMICompatibilityError(gnmiPreflightIdentityMissing, errors.New("OpenConfig platform state contains no chassis component"))
	}
	if len(chassis) != 1 {
		return "", "", newSharedGNMICompatibilityError(gnmiPreflightIdentityAmbiguous, errors.New("OpenConfig platform state contains multiple chassis components"))
	}
	models, modelErr := strictIdentityStrings(chassis[0]["model-name"], false)
	versions, versionErr := strictIdentityStrings(chassis[0]["software-version"], false)
	if modelErr != nil || versionErr != nil {
		return "", "", newSharedGNMICompatibilityError(
			gnmiPreflightMalformedIdentity,
			errors.New("OpenConfig chassis state contains a malformed model-name or software-version"),
		)
	}
	models = uniqueIdentityStrings(models)
	versions = uniqueIdentityStrings(versions)
	if len(models) == 0 || len(versions) == 0 {
		return "", "", newSharedGNMICompatibilityError(gnmiPreflightIdentityMissing, errors.New("OpenConfig chassis state is missing model-name or software-version"))
	}
	if len(models) != 1 || len(versions) != 1 {
		return "", "", newSharedGNMICompatibilityError(gnmiPreflightIdentityAmbiguous, errors.New("OpenConfig chassis state contains ambiguous model-name or software-version"))
	}
	return models[0], versions[0], nil
}

func groupGNMIIdentityPoints(
	points []internalgnmi.Point,
	listName string,
	leafParentSuffix []string,
	groupValueKeys []string,
) map[string]gnmiIdentityGroup {
	groups := map[string]gnmiIdentityGroup{}
	for pointIndex := range points {
		point := &points[pointIndex]
		listIndex := -1
		for i := range slices.Backward(point.Series.Elements) {
			if localGNMIIdentityName(point.Series.Elements[i].Name) == listName {
				listIndex = i
				break
			}
		}
		if listIndex < 0 {
			continue
		}
		if len(point.Series.Elements) != listIndex+1+len(leafParentSuffix) {
			continue
		}
		shapeMatches := true
		for index, expected := range leafParentSuffix {
			if localGNMIIdentityName(point.Series.Elements[listIndex+1+index].Name) != expected {
				shapeMatches = false
				break
			}
		}
		if !shapeMatches {
			continue
		}
		// Path.Key length-prefixes every component and key/value pair. Wire path
		// strings may legally contain NUL or '=' bytes, so delimiter concatenation
		// could otherwise collapse two chassis/version list entries into one group.
		groupKey := (internalgnmi.Path{
			Target:     point.Series.Target,
			PathTarget: point.Series.PathTarget,
			Origin:     point.Series.Origin,
			Elements:   point.Series.Elements[:listIndex+1],
		}).Key()
		group := groups[groupKey]
		if group == nil {
			group = gnmiIdentityGroup{}
			groups[groupKey] = group
		}
		for _, element := range point.Series.Elements[:listIndex+1] {
			for name, value := range element.Keys {
				local := localGNMIIdentityName(name)
				group[identityListKeyGroupName(localGNMIIdentityName(element.Name), local)] = append(
					group[identityListKeyGroupName(localGNMIIdentityName(element.Name), local)],
					internalgnmi.StringValue(value),
				)
				if slices.Contains(groupValueKeys, local) {
					group[local] = append(group[local], internalgnmi.StringValue(value))
				}
			}
		}
		leaf := localGNMIIdentityName(point.Series.Leaf)
		group[leaf] = append(group[leaf], point.Value)
	}
	return groups
}

const identityListKeyGroupPrefix = "\x00list-key:"

func identityListKeyGroupName(element, key string) string {
	return identityListKeyGroupPrefix + element + ":" + key
}

func requiredIdentityListKey(group gnmiIdentityGroup, element, key string) (string, error) {
	values, ok := group[identityListKeyGroupName(element, key)]
	if !ok || len(values) == 0 {
		return "", errors.New("required identity list key is missing")
	}
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value.Kind != internalgnmi.ValueString {
			return "", errors.New("required identity list key has an invalid type")
		}
		unique[value.String] = struct{}{}
	}
	if len(unique) != 1 {
		return "", errors.New("required identity list key is ambiguous")
	}
	for value := range unique {
		return value, nil
	}
	return "", errors.New("required identity list key is missing")
}

func strictIdentityStrings(values []internalgnmi.Value, allowEmpty bool) ([]string, error) {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value.Kind != internalgnmi.ValueString {
			return nil, errors.New("identity string has an invalid type")
		}
		if strings.TrimSpace(value.String) != value.String || (!allowEmpty && value.String == "") {
			return nil, errors.New("identity string is empty or contains surrounding whitespace")
		}
		out = append(out, value.String)
	}
	return out, nil
}

func validateStringIdentityListKey(group gnmiIdentityGroup, element, key string, allowEmpty bool) error {
	keyValue, err := requiredIdentityListKey(group, element, key)
	if err != nil {
		return err
	}
	values, err := strictIdentityStrings(group[key], allowEmpty)
	if err != nil || len(values) == 0 {
		return errors.New("identity list key leaf has an invalid type or is missing")
	}
	for _, value := range values {
		if value != keyValue {
			return errors.New("identity list key conflicts with its key leaf")
		}
	}
	return nil
}

func strictIdentityEnumCode(value internalgnmi.Value, names map[string]int64, minimum, maximum int64) (int64, error) {
	switch value.Kind {
	case internalgnmi.ValueString:
		if code, ok := names[value.String]; ok {
			return code, nil
		}
		code, err := strconv.ParseInt(value.String, 10, 64)
		if err != nil || code < minimum || code > maximum {
			return 0, errors.New("identity enum has an invalid string value")
		}
		return code, nil
	case internalgnmi.ValueInt:
		if value.Int < minimum || value.Int > maximum {
			return 0, errors.New("identity enum integer is out of range")
		}
		return value.Int, nil
	case internalgnmi.ValueUint:
		if value.Uint > uint64(maximum) {
			return 0, errors.New("identity enum integer is out of range")
		}
		return int64(value.Uint), nil
	default:
		return 0, errors.New("identity enum has an invalid type")
	}
}

func strictIdentityEnumValues(values []internalgnmi.Value, names map[string]int64, minimum, maximum int64) (int64, bool, error) {
	var code int64
	for index, value := range values {
		parsed, err := strictIdentityEnumCode(value, names, minimum, maximum)
		if err != nil {
			return 0, false, err
		}
		if index > 0 && parsed != code {
			return 0, false, errors.New("identity enum contains conflicting values")
		}
		code = parsed
	}
	return code, len(values) > 0, nil
}

var iosXEHardwareTypeCodes = map[string]int64{
	"hw-type-unknown": 0, "hw-type-chassis": 1, "hw-type-cpu": 2,
	"hw-type-dram": 3, "hw-type-flash": 4, "hw-type-emmc": 5,
	"hw-type-sdcard": 6, "hw-type-usb": 7, "hw-type-pim": 8,
	"hw-type-transceiver": 9, "hw-type-fantray": 10, "hw-type-pem": 11,
	"hw-type-ssd": 12,
}

var iosXEInstallVersionStateCodes = map[string]int64{
	"install-version-state-provisioned-committed":   0,
	"install-version-state-provisioned-uncommitted": 1,
	"install-version-state-in-progress":             2,
	"install-version-state-invalid":                 3,
	"install-version-state-present":                 4,
	"install-version-state-unknown":                 5,
	"install-version-state-installed":               6,
}

var iosXEFRUTypeCodes = map[string]int64{
	"fru-rp": 0, "fru-fp": 1, "fru-cc": 2, "fru-max": 3, "fru-fc": 4, "fru-bp": 5,
}

func validateIOSXEHardwareIdentityGroup(group gnmiIdentityGroup) (bool, error) {
	if err := validateStringIdentityListKey(group, "device-inventory", "hw-type", false); err != nil {
		// hw-type also has legacy numeric JSON interoperability, so validate it
		// by enum code below rather than requiring only a string leaf.
		if _, keyErr := requiredIdentityListKey(group, "device-inventory", "hw-type"); keyErr != nil {
			return false, errors.New("hardware inventory is missing required list keys")
		}
	}
	if _, err := requiredIdentityListKey(group, "device-inventory", "hw-dev-index"); err != nil {
		return false, errors.New("hardware inventory is missing required list keys")
	}
	hardwareType, present, err := strictIdentityEnumValues(group["hw-type"], iosXEHardwareTypeCodes, 0, 12)
	if err != nil || !present {
		return false, errors.New("hardware inventory contains a malformed hardware type")
	}
	if err := validateUnsignedIdentityListKey(group, "device-inventory", "hw-dev-index", 1<<32-1); err != nil {
		return false, errors.New("hardware inventory contains a malformed hardware index")
	}
	return hardwareType == 1, nil
}

func validateIOSXEInstallIdentityGroup(group gnmiIdentityGroup) (bool, error) {
	if err := validateEnumIdentityListKey(group, "install-location-information", "fru", iosXEFRUTypeCodes, 0, 5); err != nil {
		return false, errors.New("install inventory contains a malformed FRU key")
	}
	for _, key := range []string{"slot", "bay", "chassis"} {
		if err := validateSignedIdentityListKey(group, "install-location-information", key, -1<<15, 1<<15-1); err != nil {
			return false, errors.New("install inventory contains a malformed location key")
		}
	}
	if err := validateStringIdentityListKey(group, "install-version-info", "version", false); err != nil {
		return false, errors.New("install inventory contains a malformed version key")
	}
	if err := validateStringIdentityListKey(group, "install-version-info", "version-extension", true); err != nil {
		return false, errors.New("install inventory contains a malformed version-extension key")
	}
	state, present, err := strictIdentityEnumValues(group["current"], iosXEInstallVersionStateCodes, 0, 6)
	if err != nil {
		return false, errors.New("install inventory contains a malformed current state")
	}
	return present && (state == 0 || state == 1), nil
}

func validateEnumIdentityListKey(group gnmiIdentityGroup, element, key string, names map[string]int64, minimum, maximum int64) error {
	keyValue, err := requiredIdentityListKey(group, element, key)
	if err != nil {
		return err
	}
	keyCode, err := strictIdentityEnumCode(internalgnmi.StringValue(keyValue), names, minimum, maximum)
	if err != nil {
		return err
	}
	valueCode, present, err := strictIdentityEnumValues(group[key], names, minimum, maximum)
	if err != nil || !present || valueCode != keyCode {
		return errors.New("identity enum list key conflicts with its key leaf")
	}
	return nil
}

func identityInteger(value internalgnmi.Value, minimum, maximum int64) (int64, error) {
	var parsed int64
	switch value.Kind {
	case internalgnmi.ValueString:
		value, err := strconv.ParseInt(value.String, 10, 64)
		if err != nil {
			return 0, err
		}
		parsed = value
	case internalgnmi.ValueInt:
		parsed = value.Int
	case internalgnmi.ValueUint:
		if value.Uint > uint64(maximum) {
			return 0, errors.New("identity integer is out of range")
		}
		parsed = int64(value.Uint)
	default:
		return 0, errors.New("identity integer has an invalid type")
	}
	if parsed < minimum || parsed > maximum {
		return 0, errors.New("identity integer is out of range")
	}
	return parsed, nil
}

func validateSignedIdentityListKey(group gnmiIdentityGroup, element, key string, minimum, maximum int64) error {
	keyValue, err := requiredIdentityListKey(group, element, key)
	if err != nil {
		return err
	}
	keyNumber, err := identityInteger(internalgnmi.StringValue(keyValue), minimum, maximum)
	if err != nil {
		return err
	}
	for _, value := range group[key] {
		parsed, parseErr := identityInteger(value, minimum, maximum)
		if parseErr != nil || parsed != keyNumber {
			return errors.New("identity integer list key conflicts with its key leaf")
		}
	}
	return nil
}

func validateUnsignedIdentityListKey(group gnmiIdentityGroup, element, key string, maximum uint64) error {
	keyValue, err := requiredIdentityListKey(group, element, key)
	if err != nil {
		return err
	}
	keyNumber, err := strconv.ParseUint(keyValue, 10, 64)
	if err != nil || keyNumber > maximum {
		return errors.New("identity unsigned integer key is invalid")
	}
	for _, value := range group[key] {
		var parsed uint64
		switch value.Kind {
		case internalgnmi.ValueString:
			parsed, err = strconv.ParseUint(value.String, 10, 64)
		case internalgnmi.ValueInt:
			if value.Int < 0 {
				err = errors.New("negative unsigned identity integer")
			} else {
				parsed = uint64(value.Int)
			}
		case internalgnmi.ValueUint:
			parsed = value.Uint
		default:
			err = errors.New("identity unsigned integer has an invalid type")
		}
		if err != nil || parsed > maximum || parsed != keyNumber {
			return errors.New("identity unsigned integer list key conflicts with its key leaf")
		}
	}
	return nil
}

func uniqueStrictIdentityPathLeafStrings(points []internalgnmi.Point, parent []string, leaf string) ([]string, error) {
	values := make([]string, 0)
	for i := range points {
		point := &points[i]
		if localGNMIIdentityName(point.Series.Leaf) != leaf || len(point.Series.Elements) != len(parent) {
			continue
		}
		matched := true
		for index, expected := range parent {
			if localGNMIIdentityName(point.Series.Elements[index].Name) != expected {
				matched = false
				break
			}
		}
		if matched {
			strict, err := strictIdentityStrings([]internalgnmi.Value{point.Value}, false)
			if err != nil {
				return nil, err
			}
			values = append(values, strict...)
		}
	}
	return uniqueIdentityStrings(values), nil
}

func uniqueIdentityStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func localGNMIIdentityName(value string) string {
	if _, local, ok := strings.Cut(value, ":"); ok {
		return local
	}
	return value
}

func localGNMIIdentityValue(value string) string {
	value = strings.TrimSpace(value)
	if index := strings.LastIndexByte(value, ':'); index >= 0 {
		value = value[index+1:]
	}
	return strings.ToUpper(value)
}
