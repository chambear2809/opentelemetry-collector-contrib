// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"go.opentelemetry.io/collector/pdata/pcommon"
)

const finalDatapointHardMaxAttributeNodes = 2_000_000

// finalDatapointBudget is shared by the IOS XR and Catalyst 9800 dial-out
// normalizers. The upstream YANG converter bounds its own output, but these
// normalizers add per-datapoint YANG attributes and, for Catalyst 9800, derived
// aliases. Account that final shape before mutating pdata so a resource-scoped
// encoding path cannot be multiplied across an otherwise valid batch.
type finalDatapointBudgetLimits struct {
	maxDatapoints          int
	maxAttributes          int
	maxAttributeKeyBytes   int
	maxAttributeValueBytes int
	maxAttributeBytes      int
	maxAttributeDepth      int
	maxAttributeNodes      int
}

func (l finalDatapointBudgetLimits) withDefaults(configuredMaxDatapoints int) finalDatapointBudgetLimits {
	if configuredMaxDatapoints <= 0 {
		configuredMaxDatapoints = directGNMIDefaultMaxDatapoints
	}
	if configuredMaxDatapoints > directGNMIHardMaxDatapoints {
		configuredMaxDatapoints = directGNMIHardMaxDatapoints
	}
	if l.maxDatapoints <= 0 || l.maxDatapoints > configuredMaxDatapoints {
		l.maxDatapoints = configuredMaxDatapoints
	}
	if l.maxAttributes <= 0 || l.maxAttributes > directGNMIHardMaxAttributesPerPoint {
		l.maxAttributes = directGNMIHardMaxAttributesPerPoint
	}
	if l.maxAttributeKeyBytes <= 0 || l.maxAttributeKeyBytes > directGNMIHardMaxAttributeKeyBytes {
		l.maxAttributeKeyBytes = directGNMIHardMaxAttributeKeyBytes
	}
	if l.maxAttributeValueBytes <= 0 || l.maxAttributeValueBytes > directGNMIHardMaxAttributeValueBytes {
		l.maxAttributeValueBytes = directGNMIHardMaxAttributeValueBytes
	}
	if l.maxAttributeBytes <= 0 || l.maxAttributeBytes > directGNMIHardMaxAttributeBytes {
		l.maxAttributeBytes = directGNMIHardMaxAttributeBytes
	}
	if l.maxAttributeDepth <= 0 || l.maxAttributeDepth > directGNMIHardMaxDepth {
		l.maxAttributeDepth = directGNMIHardMaxDepth
	}
	if l.maxAttributeNodes <= 0 || l.maxAttributeNodes > finalDatapointHardMaxAttributeNodes {
		l.maxAttributeNodes = finalDatapointHardMaxAttributeNodes
	}
	return l
}

type finalDatapointBudget struct {
	limits         finalDatapointBudgetLimits
	datapoints     int
	attributeBytes int
	attributeNodes int
	dropped        int64
}

func newFinalDatapointBudget(limits finalDatapointBudgetLimits, configuredMaxDatapoints int) *finalDatapointBudget {
	return &finalDatapointBudget{limits: limits.withDefaults(configuredMaxDatapoints)}
}

// reservePcommonDatapoint accounts the final attribute set of an existing
// canonical datapoint. additions are applied only after this method succeeds.
func (b *finalDatapointBudget) reservePcommonDatapoint(attrs pcommon.Map, additions map[string]string) bool {
	remainingBytes, remainingNodes, ok := b.remainingAttributeCapacity()
	if !ok {
		return false
	}
	attributeBytes, attributeNodes, ok := finalPcommonAttributeUsage(
		attrs,
		additions,
		remainingBytes,
		remainingNodes,
		b.limits,
	)
	if !ok {
		b.dropped++
		return false
	}
	b.datapoints++
	b.attributeBytes += attributeBytes
	b.attributeNodes += attributeNodes
	return true
}

// reserveStringDatapoint accounts a datapoint that has not been created yet,
// such as a Catalyst 9800 alias.
func (b *finalDatapointBudget) reserveStringDatapoint(attrs map[string]string) bool {
	return b.reserveStringDatapointWithEmpty(attrs, "", "", false)
}

// reserveAliasStringDatapoint accounts attributes copied from canonical pdata.
// Every map entry represents an already-present canonical attribute, including
// an explicitly empty string, so alias emission must preserve and charge it.
func (b *finalDatapointBudget) reserveAliasStringDatapoint(attrs map[string]string, extraKey, extraValue string) bool {
	return b.reserveStringDatapointWithEmpty(attrs, extraKey, extraValue, true)
}

func (b *finalDatapointBudget) reserveStringDatapointWithEmpty(attrs map[string]string, extraKey, extraValue string, preserveEmpty bool) bool {
	remainingBytes, remainingNodes, ok := b.remainingAttributeCapacity()
	if !ok {
		return false
	}
	attributeBytes := 0
	attributeNodes := 0
	attributeCount := 0
	for key, value := range attrs {
		if (value == "" && !preserveEmpty && !isDirectGNMIIdentityAttribute(key)) || (extraKey != "" && key == extraKey) {
			continue
		}
		if !validFinalStringAttribute(key, value, b.limits) {
			b.dropped++
			return false
		}
		attributeCount++
		if attributeCount > b.limits.maxAttributes {
			b.dropped++
			return false
		}
		if !addFinalAttributeBytes(&attributeBytes, len(key)+len(value), remainingBytes) ||
			!addFinalAttributeNode(&attributeNodes, remainingNodes) {
			b.dropped++
			return false
		}
		// A non-empty host.ip is represented as a one-element OTLP slice. An
		// explicitly empty identity remains a string and consumes only its root.
		if key == "host.ip" && value != "" && !addFinalAttributeNode(&attributeNodes, remainingNodes) {
			b.dropped++
			return false
		}
	}
	if extraKey != "" {
		if !validFinalStringAttribute(extraKey, extraValue, b.limits) {
			b.dropped++
			return false
		}
		attributeCount++
		if attributeCount > b.limits.maxAttributes {
			b.dropped++
			return false
		}
		if !addFinalAttributeBytes(&attributeBytes, len(extraKey)+len(extraValue), remainingBytes) ||
			!addFinalAttributeNode(&attributeNodes, remainingNodes) {
			b.dropped++
			return false
		}
		if extraKey == "host.ip" && extraValue != "" && !addFinalAttributeNode(&attributeNodes, remainingNodes) {
			b.dropped++
			return false
		}
	}
	b.datapoints++
	b.attributeBytes += attributeBytes
	b.attributeNodes += attributeNodes
	return true
}

func validFinalStringAttribute(key, value string, limits finalDatapointBudgetLimits) bool {
	return key != "" && len(key) <= limits.maxAttributeKeyBytes && len(value) <= limits.maxAttributeValueBytes
}

func (b *finalDatapointBudget) remainingAttributeCapacity() (int, int, bool) {
	if b.datapoints >= b.limits.maxDatapoints {
		b.dropped++
		return 0, 0, false
	}
	if b.attributeBytes > b.limits.maxAttributeBytes {
		b.dropped++
		return 0, 0, false
	}
	if b.attributeNodes > b.limits.maxAttributeNodes {
		b.dropped++
		return 0, 0, false
	}
	return b.limits.maxAttributeBytes - b.attributeBytes, b.limits.maxAttributeNodes - b.attributeNodes, true
}

type finalPcommonValueFrame struct {
	value pcommon.Value
	depth int
	root  int
}

// finalPcommonAttributeUsage walks pdata iteratively. Every value or container
// consumes one node even when it has no serialized value bytes, so deeply
// nested or wide empty containers cannot bypass the aggregate complexity cap.
func finalPcommonAttributeUsage(attrs pcommon.Map, additions map[string]string, maximumBytes, maximumNodes int, limits finalDatapointBudgetLimits) (int, int, bool) {
	if maximumBytes < 0 || maximumNodes < 0 || limits.maxAttributeDepth <= 0 {
		return 0, 0, false
	}
	finalAttributeCount := attrs.Len()
	if finalAttributeCount > limits.maxAttributes || finalAttributeCount > maximumNodes {
		return 0, 0, false
	}
	for key, value := range additions {
		if value == "" {
			continue
		}
		if _, exists := attrs.Get(key); !exists {
			if finalAttributeCount >= limits.maxAttributes || finalAttributeCount >= maximumNodes {
				return 0, 0, false
			}
			finalAttributeCount++
		}
	}
	totalBytes := 0
	totalNodes := 0
	valid := true
	stackCapacity := min(attrs.Len(), 1_024)
	stack := make([]finalPcommonValueFrame, 0, stackCapacity)
	rootValueBytes := make([]int, 0, min(attrs.Len(), limits.maxAttributes))
	attrs.Range(func(key string, value pcommon.Value) bool {
		if key == "" || len(key) > limits.maxAttributeKeyBytes {
			valid = false
			return false
		}
		valueBytes, replaced := additions[key]
		replaced = replaced && valueBytes != ""
		if replaced {
			if len(valueBytes) > limits.maxAttributeValueBytes {
				valid = false
				return false
			}
			valid = addFinalAttributeBytes(&totalBytes, len(key)+len(valueBytes), maximumBytes) &&
				addFinalAttributeNode(&totalNodes, maximumNodes)
			return valid
		}
		valid = addFinalAttributeBytes(&totalBytes, len(key), maximumBytes) &&
			addFinalAttributeNode(&totalNodes, maximumNodes)
		if valid {
			root := len(rootValueBytes)
			rootValueBytes = append(rootValueBytes, 0)
			stack = append(stack, finalPcommonValueFrame{value: value, depth: 1, root: root})
		}
		return valid
	})
	if !valid {
		return 0, 0, false
	}
	for key, value := range additions {
		if value == "" {
			continue
		}
		if _, exists := attrs.Get(key); exists {
			continue
		}
		if !validFinalStringAttribute(key, value, limits) {
			return 0, 0, false
		}
		if !addFinalAttributeBytes(&totalBytes, len(key)+len(value), maximumBytes) ||
			!addFinalAttributeNode(&totalNodes, maximumNodes) {
			return 0, 0, false
		}
	}

	for len(stack) > 0 {
		frame := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if frame.depth > limits.maxAttributeDepth {
			return 0, 0, false
		}
		switch frame.value.Type() {
		case pcommon.ValueTypeEmpty:
		case pcommon.ValueTypeStr:
			if !addFinalPcommonValueBytes(&totalBytes, &rootValueBytes[frame.root], len(frame.value.Str()), maximumBytes, limits.maxAttributeValueBytes) {
				return 0, 0, false
			}
		case pcommon.ValueTypeInt, pcommon.ValueTypeDouble:
			if !addFinalPcommonValueBytes(&totalBytes, &rootValueBytes[frame.root], 8, maximumBytes, limits.maxAttributeValueBytes) {
				return 0, 0, false
			}
		case pcommon.ValueTypeBool:
			if !addFinalPcommonValueBytes(&totalBytes, &rootValueBytes[frame.root], 1, maximumBytes, limits.maxAttributeValueBytes) {
				return 0, 0, false
			}
		case pcommon.ValueTypeBytes:
			if !addFinalPcommonValueBytes(&totalBytes, &rootValueBytes[frame.root], frame.value.Bytes().Len(), maximumBytes, limits.maxAttributeValueBytes) {
				return 0, 0, false
			}
		case pcommon.ValueTypeSlice:
			values := frame.value.Slice()
			if values.Len() > 0 && frame.depth >= limits.maxAttributeDepth {
				return 0, 0, false
			}
			for i := 0; i < values.Len(); i++ {
				if !addFinalAttributeNode(&totalNodes, maximumNodes) {
					return 0, 0, false
				}
				stack = append(stack, finalPcommonValueFrame{value: values.At(i), depth: frame.depth + 1, root: frame.root})
			}
		case pcommon.ValueTypeMap:
			if frame.value.Map().Len() > 0 && frame.depth >= limits.maxAttributeDepth {
				return 0, 0, false
			}
			frame.value.Map().Range(func(key string, nested pcommon.Value) bool {
				if len(key) > limits.maxAttributeKeyBytes {
					valid = false
					return false
				}
				valid = addFinalPcommonValueBytes(&totalBytes, &rootValueBytes[frame.root], len(key), maximumBytes, limits.maxAttributeValueBytes) &&
					addFinalAttributeNode(&totalNodes, maximumNodes)
				if valid {
					stack = append(stack, finalPcommonValueFrame{value: nested, depth: frame.depth + 1, root: frame.root})
				}
				return valid
			})
			if !valid {
				return 0, 0, false
			}
		default:
			return 0, 0, false
		}
	}
	return totalBytes, totalNodes, true
}

func addFinalPcommonValueBytes(total, valueTotal *int, amount, maximumTotal, maximumValue int) bool {
	if !addFinalAttributeBytes(total, amount, maximumTotal) || !addFinalAttributeBytes(valueTotal, amount, maximumValue) {
		return false
	}
	return true
}

func addFinalAttributeBytes(total *int, amount, maximum int) bool {
	if amount < 0 || *total > maximum || amount > maximum-*total {
		return false
	}
	*total += amount
	return true
}

func addFinalAttributeNode(total *int, maximum int) bool {
	if *total < 0 || *total >= maximum {
		return false
	}
	*total++
	return true
}
