// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	gnmiDialOutIdentityLegacy   = "legacy"
	gnmiDialOutIdentityRequired = "required"

	maxGNMIDialOutIdentityBindings       = 256
	maxGNMIDialOutIdentitySourcesPerBind = 64
	maxGNMIDialOutIdentityNodeIDsPerBind = 64
	maxGNMIDialOutIdentitySources        = 4_096
	maxGNMIDialOutIdentityNodeIDs        = 4_096
	maxGNMIDialOutIdentityNodeIDBytes    = 256
	// Keep the identity-only scanner aligned with yanggrpcreceiver's eight
	// wire operations per 100,000-field semantic ceiling. It must not reject a
	// payload that the delegated hardened converter is explicitly able to scan.
	maxGNMIDialOutIdentityTelemetryFields = 100_000
	maxGNMIDialOutIdentityWireOperations  = maxGNMIDialOutIdentityTelemetryFields * 8

	gnmiDialOutArgsFullName  = protoreflect.FullName("mdt_dialout.MdtDialoutArgs")
	gnmiDialOutDataField     = protoreflect.FieldNumber(2)
	gnmiTelemetryNodeIDField = protowire.Number(1)
)

var errGNMIDialOutIdentityWireBudget = errors.New("dial-out telemetry identity wire-operation budget exceeded")

// GNMIDialOutIdentityBindingConfig binds one or more network sources to the
// node IDs those sources are permitted to claim in MDT telemetry payloads.
type GNMIDialOutIdentityBindingConfig struct {
	// DO NOT USE unkeyed struct initialization
	_ struct{} `mapstructure:"-"`

	Sources []string `mapstructure:"sources"`
	NodeIDs []string `mapstructure:"node_ids"`
}

type gnmiDialOutIdentityBinding struct {
	sources []netip.Prefix
	nodeIDs map[string]struct{}
}

type gnmiDialOutIdentityVerifier struct {
	bindings []gnmiDialOutIdentityBinding
}

func effectiveGNMIDialOutIdentityVerification(value string) string {
	if value == "" {
		return gnmiDialOutIdentityLegacy
	}
	return value
}

func gnmiDialOutEndpointRequiresIdentity(endpoint string) bool {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || strings.HasPrefix(endpoint, "unix://") {
		return false
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return false
	}
	parsedHost := net.ParseIP(host)
	return !strings.EqualFold(host, "localhost") && (parsedHost == nil || !parsedHost.IsLoopback())
}

func gnmiDialOutIdentitySupportsTransport(transport string) bool {
	switch transport {
	case "tcp", "tcp4", "tcp6":
		return true
	default:
		return false
	}
}

func compileGNMIDialOutIdentityVerifier(
	verification string,
	configured []GNMIDialOutIdentityBindingConfig,
) (*gnmiDialOutIdentityVerifier, error) {
	verification = effectiveGNMIDialOutIdentityVerification(verification)
	if verification != gnmiDialOutIdentityLegacy && verification != gnmiDialOutIdentityRequired {
		return nil, errors.New("identity_verification must be legacy or required")
	}
	if verification == gnmiDialOutIdentityLegacy {
		if len(configured) > 0 {
			return nil, errors.New("identity_bindings require identity_verification: required")
		}
		return nil, nil
	}

	var validationErr error
	if len(configured) == 0 {
		validationErr = errors.Join(validationErr, errors.New("identity_verification: required requires at least one identity_bindings entry"))
	}
	if len(configured) > maxGNMIDialOutIdentityBindings {
		return nil, fmt.Errorf("identity_bindings must contain at most %d entries", maxGNMIDialOutIdentityBindings)
	}
	totalSources := 0
	totalNodeIDs := 0
	hardLimitExceeded := false
	for bindingIndex, bindingConfig := range configured {
		if len(bindingConfig.Sources) > maxGNMIDialOutIdentitySourcesPerBind {
			hardLimitExceeded = true
			validationErr = errors.Join(validationErr, fmt.Errorf(
				"identity_bindings[%d].sources must contain at most %d entries",
				bindingIndex,
				maxGNMIDialOutIdentitySourcesPerBind,
			))
		}
		if len(bindingConfig.NodeIDs) > maxGNMIDialOutIdentityNodeIDsPerBind {
			hardLimitExceeded = true
			validationErr = errors.Join(validationErr, fmt.Errorf(
				"identity_bindings[%d].node_ids must contain at most %d entries",
				bindingIndex,
				maxGNMIDialOutIdentityNodeIDsPerBind,
			))
		}
		totalSources += len(bindingConfig.Sources)
		totalNodeIDs += len(bindingConfig.NodeIDs)
	}
	if totalSources > maxGNMIDialOutIdentitySources {
		hardLimitExceeded = true
		validationErr = errors.Join(validationErr, fmt.Errorf(
			"identity_bindings must contain at most %d source selectors in total",
			maxGNMIDialOutIdentitySources,
		))
	}
	if totalNodeIDs > maxGNMIDialOutIdentityNodeIDs {
		hardLimitExceeded = true
		validationErr = errors.Join(validationErr, fmt.Errorf(
			"identity_bindings must contain at most %d node IDs in total",
			maxGNMIDialOutIdentityNodeIDs,
		))
	}
	if hardLimitExceeded {
		return nil, validationErr
	}

	bindings := make([]gnmiDialOutIdentityBinding, 0, len(configured))
	seenSources := make(map[netip.Prefix]struct{})
	for bindingIndex, bindingConfig := range configured {
		if len(bindingConfig.Sources) == 0 {
			validationErr = errors.Join(validationErr, fmt.Errorf("identity_bindings[%d].sources must not be empty", bindingIndex))
		}
		if len(bindingConfig.NodeIDs) == 0 {
			validationErr = errors.Join(validationErr, fmt.Errorf("identity_bindings[%d].node_ids must not be empty", bindingIndex))
		}

		binding := gnmiDialOutIdentityBinding{
			sources: make([]netip.Prefix, 0, len(bindingConfig.Sources)),
			nodeIDs: make(map[string]struct{}, len(bindingConfig.NodeIDs)),
		}
		for sourceIndex, source := range bindingConfig.Sources {
			if source == "" {
				validationErr = errors.Join(validationErr, fmt.Errorf(
					"identity_bindings[%d].sources[%d] must not be empty",
					bindingIndex,
					sourceIndex,
				))
				continue
			}
			prefix, err := parseGNMIDialOutAllowedClient(source)
			if err != nil {
				validationErr = errors.Join(validationErr, fmt.Errorf(
					"identity_bindings[%d].sources[%d] %w",
					bindingIndex,
					sourceIndex,
					err,
				))
				continue
			}
			if _, duplicate := seenSources[prefix]; duplicate {
				validationErr = errors.Join(validationErr, fmt.Errorf(
					"identity_bindings[%d].sources[%d] duplicates source selector %q",
					bindingIndex,
					sourceIndex,
					prefix,
				))
				continue
			}
			seenSources[prefix] = struct{}{}
			binding.sources = append(binding.sources, prefix)
		}
		for nodeIndex, nodeID := range bindingConfig.NodeIDs {
			if err := validateGNMIDialOutNodeID(nodeID); err != nil {
				validationErr = errors.Join(validationErr, fmt.Errorf(
					"identity_bindings[%d].node_ids[%d] %w",
					bindingIndex,
					nodeIndex,
					err,
				))
				continue
			}
			if _, duplicate := binding.nodeIDs[nodeID]; duplicate {
				validationErr = errors.Join(validationErr, fmt.Errorf(
					"identity_bindings[%d].node_ids[%d] duplicates node ID within the binding",
					bindingIndex,
					nodeIndex,
				))
				continue
			}
			binding.nodeIDs[nodeID] = struct{}{}
		}
		bindings = append(bindings, binding)
	}
	if validationErr != nil {
		return nil, validationErr
	}
	return &gnmiDialOutIdentityVerifier{bindings: bindings}, nil
}

func validateGNMIDialOutNodeID(nodeID string) error {
	if nodeID == "" {
		return errors.New("must not be empty")
	}
	if len(nodeID) > maxGNMIDialOutIdentityNodeIDBytes {
		return fmt.Errorf("must not exceed %d bytes", maxGNMIDialOutIdentityNodeIDBytes)
	}
	if !utf8.ValidString(nodeID) {
		return errors.New("must be valid UTF-8")
	}
	if strings.TrimSpace(nodeID) != nodeID {
		return errors.New("must not have leading or trailing whitespace")
	}
	for _, character := range nodeID {
		if unicode.IsControl(character) {
			return errors.New("must not contain control characters")
		}
	}
	return nil
}

func (v *gnmiDialOutIdentityVerifier) nodeIDsForPeer(peerIP netip.Addr) (map[string]struct{}, bool) {
	if v == nil || !peerIP.IsValid() {
		return nil, false
	}
	peerIP = peerIP.Unmap()
	bestPrefixBits := -1
	var selected map[string]struct{}
	for _, binding := range v.bindings {
		for _, source := range binding.sources {
			if source.Bits() > bestPrefixBits && source.Contains(peerIP) {
				bestPrefixBits = source.Bits()
				selected = binding.nodeIDs
			}
		}
	}
	return selected, selected != nil
}

type gnmiDialOutIdentityServerStream struct {
	grpc.ServerStream
	allowedNodeIDs map[string]struct{}
	boundNodeID    string
	terminalErr    error
}

func (s *gnmiDialOutIdentityServerStream) RecvMsg(message any) error {
	if s.terminalErr != nil {
		return s.terminalErr
	}
	if err := s.ServerStream.RecvMsg(message); err != nil {
		return err
	}
	nodeID, err := gnmiDialOutNodeIDFromMessage(message)
	if err != nil {
		if errors.Is(err, errGNMIDialOutIdentityWireBudget) {
			s.terminalErr = status.Errorf(
				codes.ResourceExhausted,
				"dial-out telemetry identity exceeds %d wire operations",
				maxGNMIDialOutIdentityWireOperations,
			)
			return s.terminalErr
		}
		s.terminalErr = status.Error(codes.InvalidArgument, "invalid dial-out telemetry identity")
		return s.terminalErr
	}
	if _, allowed := s.allowedNodeIDs[nodeID]; !allowed {
		s.terminalErr = status.Error(codes.PermissionDenied, "dial-out telemetry node identity is not permitted for this client")
		return s.terminalErr
	}
	if s.boundNodeID == "" {
		s.boundNodeID = nodeID
		return nil
	}
	if s.boundNodeID != nodeID {
		s.terminalErr = status.Error(codes.PermissionDenied, "dial-out telemetry node identity changed during the stream")
		return s.terminalErr
	}
	return nil
}

func gnmiDialOutNodeIDFromMessage(message any) (string, error) {
	protoMessage, ok := message.(protoreflect.ProtoMessage)
	if !ok || protoMessage == nil {
		return "", errors.New("message is not a protobuf message")
	}
	value := reflect.ValueOf(protoMessage)
	if (value.Kind() == reflect.Ptr || value.Kind() == reflect.Interface) && value.IsNil() {
		return "", errors.New("message is nil")
	}
	reflected := protoMessage.ProtoReflect()
	if reflected == nil || !reflected.IsValid() || reflected.Descriptor().FullName() != gnmiDialOutArgsFullName {
		return "", errors.New("message is not mdt_dialout.MdtDialoutArgs")
	}
	dataField := reflected.Descriptor().Fields().ByNumber(gnmiDialOutDataField)
	if dataField == nil || dataField.Kind() != protoreflect.BytesKind || dataField.Cardinality() == protoreflect.Repeated {
		return "", errors.New("message has an invalid data field")
	}
	return gnmiDialOutNodeIDFromTelemetry(reflected.Get(dataField).Bytes())
}

func gnmiDialOutNodeIDFromTelemetry(payload []byte) (string, error) {
	var nodeID string
	foundNodeID := false
	wireOperations := 0
	for len(payload) > 0 {
		wireOperations++
		if wireOperations > maxGNMIDialOutIdentityWireOperations {
			return "", errGNMIDialOutIdentityWireBudget
		}
		fieldNumber, wireType, tagLength := protowire.ConsumeTag(payload)
		if tagLength < 0 {
			return "", protowire.ParseError(tagLength)
		}
		if !fieldNumber.IsValid() {
			return "", fmt.Errorf("invalid telemetry field number %d", fieldNumber)
		}
		if wireType == protowire.StartGroupType || wireType == protowire.EndGroupType {
			return "", errors.New("protobuf groups are not permitted in dial-out telemetry")
		}
		payload = payload[tagLength:]
		if fieldNumber == gnmiTelemetryNodeIDField {
			if wireType != protowire.BytesType || foundNodeID {
				return "", errors.New("telemetry contains an invalid or duplicate node_id_str field")
			}
			value, valueLength := protowire.ConsumeBytes(payload)
			if valueLength < 0 {
				return "", protowire.ParseError(valueLength)
			}
			if len(value) > maxGNMIDialOutIdentityNodeIDBytes {
				return "", fmt.Errorf("node ID must not exceed %d bytes", maxGNMIDialOutIdentityNodeIDBytes)
			}
			nodeID = string(value)
			foundNodeID = true
			payload = payload[valueLength:]
			continue
		}
		fieldLength := protowire.ConsumeFieldValue(fieldNumber, wireType, payload)
		if fieldLength < 0 {
			return "", protowire.ParseError(fieldLength)
		}
		payload = payload[fieldLength:]
	}
	if !foundNodeID {
		return "", errors.New("telemetry does not contain node_id_str")
	}
	if err := validateGNMIDialOutNodeID(nodeID); err != nil {
		return "", err
	}
	return nodeID, nil
}
