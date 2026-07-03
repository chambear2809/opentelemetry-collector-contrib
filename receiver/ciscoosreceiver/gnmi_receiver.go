// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	grpcmetadata "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

const (
	sharedGNMITransport             = "gnmi"
	sharedGNMIAuthenticationBackoff = 5 * time.Minute
	sharedGNMIInitialBackoff        = 5 * time.Second
	sharedGNMIMaximumBackoff        = time.Minute
	sharedGNMIBackoffResetAfter     = time.Minute
	sharedGNMIMaxBisectionProbes    = 64
	sharedGNMIMaxConcurrentDelivery = 8
	sharedGNMIMaxNXPlanningWork     = 25_000_000
	sharedGNMIMaxPathElements       = 128
	sharedGNMIMaxSeriesElements     = sharedGNMIMaxPathElements - 1
	// One mapped NX optical series can retain one sensor identity plus one
	// optical source, presence count, and attribute-map entry.
	sharedGNMIAuxiliaryEntriesPerCachedSeries = 4
	// sharedGNMIAuxiliaryRetainedBytes is independent from the 256 MiB cache
	// ceiling. It bounds receiver-owned NX sensor and optical-presence state.
	sharedGNMIAuxiliaryRetainedBytes int64 = 256 * 1024 * 1024

	// Auxiliary estimates intentionally charge complete sparse map allocations
	// to each retained entry. This overestimates shared buckets while preventing
	// one-entry maps and key-heavy paths from bypassing the byte ceiling.
	sharedGNMIAuxiliaryStringHeaderBytes  int64 = 16
	sharedGNMIAuxiliaryMapEntryBytes      int64 = 512
	sharedGNMIAuxiliaryStringMapBaseBytes int64 = 320
	sharedGNMIAuxiliaryStringMapEntry     int64 = 128
	sharedGNMIAuxiliaryPathBaseBytes      int64 = 128
	sharedGNMIAuxiliaryPathElementBytes   int64 = 128
	sharedGNMIAuxiliaryNXStateBytes       int64 = 256
)

type sharedGNMIReceiver struct {
	settings        receiver.Settings
	config          GNMIConfig
	consumer        consumer.Metrics
	obs             *receiverhelper.ObsReport
	telemetry       *gnmiTelemetry
	targets         []*sharedGNMITargetRuntime
	maxDatapoints   int
	maxCachedSeries int

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
	host   component.Host

	notificationSlots chan struct{}
	responseAdmission *gnmiResponseAdmission
}

type sharedGNMITargetRuntime struct {
	config     GNMITargetConfig
	streams    []sharedGNMIRuntimeStream
	cache      *internalgnmi.Cache
	deliveryMu sync.Mutex
	stateMu    sync.RWMutex
	isolate    map[string]struct{}
	stopped    map[string]struct{}
	rejects    map[string]int

	nxMu      sync.Mutex
	nxSensors map[string]nxSensorState
	nxBudget  *sharedGNMIAuxiliaryBudget
	sessionUp atomic.Bool

	presenceMu     sync.Mutex
	opticalSources map[string]string
	presenceCounts map[string]int
	presenceAttrs  map[string]map[string]string
}

type sharedGNMIRuntimeStream struct {
	sharedGNMIStream
	registry   *internalgnmi.Registry
	staticAttr map[string]map[string]string
}

type nxSensorState struct {
	description          string
	unit                 string
	path                 internalgnmi.Path
	descriptionTimestamp time.Time
	unitTimestamp        time.Time
}

type sharedGNMIAuxiliaryBudget struct {
	mu           sync.Mutex
	maximum      int
	maximumBytes int64
	used         int
	usedBytes    int64
}

func newSharedGNMIAuxiliaryBudget(maximum int) *sharedGNMIAuxiliaryBudget {
	return newSharedGNMIAuxiliaryBudgetWithLimits(maximum, sharedGNMIAuxiliaryRetainedBytes)
}

func newSharedGNMIAuxiliaryBudgetWithLimits(maximum int, maximumBytes int64) *sharedGNMIAuxiliaryBudget {
	return &sharedGNMIAuxiliaryBudget{maximum: maximum, maximumBytes: maximumBytes}
}

type sharedGNMIAuxiliaryUsage struct {
	count int
	bytes int64
}

type sharedGNMIAuxiliaryReservation struct {
	budget   *sharedGNMIAuxiliaryBudget
	delta    sharedGNMIAuxiliaryUsage
	reserved sharedGNMIAuxiliaryUsage
	prepared bool
	done     bool
}

// prepareChange reserves positive count and byte capacity while holding the
// per-target budget lock only for accounting. Negative changes publish their
// release at commit, so rollback never needs to restore capacity.
func (b *sharedGNMIAuxiliaryBudget) prepareChange(
	delta sharedGNMIAuxiliaryUsage,
) (current, requested, reserved sharedGNMIAuxiliaryUsage, started bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	current = sharedGNMIAuxiliaryUsage{count: b.used, bytes: b.usedBytes}
	requested.count, started = addSharedGNMIAuxiliaryCount(b.used, delta.count)
	if !started {
		return current, sharedGNMIAuxiliaryUsage{count: -1, bytes: b.usedBytes}, sharedGNMIAuxiliaryUsage{}, false
	}
	requested.bytes, started = addSharedGNMIAuxiliaryBytes(b.usedBytes, delta.bytes)
	if !started {
		return current, sharedGNMIAuxiliaryUsage{count: requested.count, bytes: -1}, sharedGNMIAuxiliaryUsage{}, false
	}
	if requested.count > b.maximum || requested.bytes > b.maximumBytes {
		return current, requested, sharedGNMIAuxiliaryUsage{}, false
	}
	if delta.count > 0 {
		b.used += delta.count
		reserved.count = delta.count
	}
	if delta.bytes > 0 {
		b.usedBytes += delta.bytes
		reserved.bytes = delta.bytes
	}
	return current, requested, reserved, true
}

func (b *sharedGNMIAuxiliaryBudget) finishChange(
	delta, reserved sharedGNMIAuxiliaryUsage,
	commit bool,
) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if commit {
		if delta.count < 0 {
			b.used += delta.count
		}
		if delta.bytes < 0 {
			b.usedBytes += delta.bytes
		}
		return
	}
	if reserved.count > 0 {
		b.used -= reserved.count
	}
	if reserved.bytes > 0 {
		b.usedBytes -= reserved.bytes
	}
}

func addSharedGNMIAuxiliaryCount(current, delta int) (int, bool) {
	maximum := int(^uint(0) >> 1)
	if delta > 0 && current > maximum-delta {
		return 0, false
	}
	if delta < 0 {
		requested := current + delta
		if requested < 0 {
			return 0, false
		}
		return requested, true
	}
	return current + delta, true
}

func addSharedGNMIAuxiliaryBytes(current, delta int64) (int64, bool) {
	const maximum = int64(^uint64(0) >> 1)
	if delta > 0 && current > maximum-delta {
		return 0, false
	}
	if delta < 0 {
		requested := current + delta
		if requested < 0 {
			return 0, false
		}
		return requested, true
	}
	return current + delta, true
}

func sharedGNMIAuxiliaryCapacityError(
	budget *sharedGNMIAuxiliaryBudget,
	current, requested sharedGNMIAuxiliaryUsage,
) error {
	if requested.count < 0 || requested.bytes < 0 {
		return errors.New("gNMI auxiliary-state accounting underflow")
	}
	return &internalgnmi.CapacityError{
		Limit:                  budget.maximum,
		Current:                current.count,
		Requested:              requested.count,
		RetainedByteLimit:      budget.maximumBytes,
		CurrentRetainedBytes:   current.bytes,
		RequestedRetainedBytes: requested.bytes,
	}
}

func sharedGNMIAuxiliaryUsageDelta(before, after sharedGNMIAuxiliaryUsage) sharedGNMIAuxiliaryUsage {
	delta := sharedGNMIAuxiliaryUsage{count: after.count - before.count}
	if after.bytes >= before.bytes {
		delta.bytes = after.bytes - before.bytes
	} else {
		delta.bytes = -(before.bytes - after.bytes)
	}
	return delta
}

func combineSharedGNMIAuxiliaryUsage(left, right sharedGNMIAuxiliaryUsage) (sharedGNMIAuxiliaryUsage, bool) {
	count, ok := addSharedGNMISignedCount(left.count, right.count)
	if !ok {
		return sharedGNMIAuxiliaryUsage{}, false
	}
	bytes, ok := addSharedGNMISignedBytes(left.bytes, right.bytes)
	if !ok {
		return sharedGNMIAuxiliaryUsage{}, false
	}
	return sharedGNMIAuxiliaryUsage{count: count, bytes: bytes}, true
}

func addSharedGNMISignedCount(left, right int) (int, bool) {
	maximum := int(^uint(0) >> 1)
	minimum := -maximum - 1
	if right > 0 && left > maximum-right {
		return 0, false
	}
	if right < 0 && left < minimum-right {
		return 0, false
	}
	return left + right, true
}

func addSharedGNMISignedBytes(left, right int64) (int64, bool) {
	const maximum = int64(^uint64(0) >> 1)
	const minimum = -maximum - 1
	if right > 0 && left > maximum-right {
		return 0, false
	}
	if right < 0 && left < minimum-right {
		return 0, false
	}
	return left + right, true
}

func prepareSharedGNMIAuxiliaryReservation(
	budget *sharedGNMIAuxiliaryBudget,
	delta sharedGNMIAuxiliaryUsage,
) (*sharedGNMIAuxiliaryReservation, error) {
	reservation := &sharedGNMIAuxiliaryReservation{budget: budget, delta: delta}
	if delta.count == 0 && delta.bytes == 0 {
		return reservation, nil
	}
	current, requested, reserved, started := budget.prepareChange(delta)
	if !started {
		return nil, sharedGNMIAuxiliaryCapacityError(budget, current, requested)
	}
	reservation.reserved = reserved
	reservation.prepared = true
	return reservation, nil
}

func (reservation *sharedGNMIAuxiliaryReservation) commit() {
	if reservation == nil || reservation.done {
		return
	}
	reservation.done = true
	if reservation.prepared {
		reservation.budget.finishChange(reservation.delta, reservation.reserved, true)
	}
}

func (reservation *sharedGNMIAuxiliaryReservation) rollback() {
	if reservation == nil || reservation.done {
		return
	}
	reservation.done = true
	if reservation.prepared {
		reservation.budget.finishChange(reservation.delta, reservation.reserved, false)
	}
}

func addSharedGNMIAuxiliaryEstimate(current, amount int64) int64 {
	const maximum = int64(^uint64(0) >> 1)
	if amount > 0 && current > maximum-amount {
		return maximum
	}
	return current + amount
}

func sharedGNMIAuxiliaryStringBytes(value string) int64 {
	return addSharedGNMIAuxiliaryEstimate(sharedGNMIAuxiliaryStringHeaderBytes, int64(len(value)))
}

func sharedGNMIAuxiliaryStringMapBytes(values map[string]string) int64 {
	if len(values) == 0 {
		return 0
	}
	bytes := sharedGNMIAuxiliaryStringMapBaseBytes
	for key, value := range values {
		bytes = addSharedGNMIAuxiliaryEstimate(bytes, sharedGNMIAuxiliaryStringMapEntry)
		bytes = addSharedGNMIAuxiliaryEstimate(bytes, sharedGNMIAuxiliaryStringBytes(key))
		bytes = addSharedGNMIAuxiliaryEstimate(bytes, sharedGNMIAuxiliaryStringBytes(value))
	}
	return bytes
}

func sharedGNMIAuxiliaryPathBytes(path internalgnmi.Path) int64 {
	bytes := sharedGNMIAuxiliaryPathBaseBytes
	bytes = addSharedGNMIAuxiliaryEstimate(bytes, sharedGNMIAuxiliaryStringBytes(path.Target))
	bytes = addSharedGNMIAuxiliaryEstimate(bytes, sharedGNMIAuxiliaryStringBytes(path.Origin))
	for _, element := range path.Elements {
		bytes = addSharedGNMIAuxiliaryEstimate(bytes, sharedGNMIAuxiliaryPathElementBytes)
		bytes = addSharedGNMIAuxiliaryEstimate(bytes, sharedGNMIAuxiliaryStringBytes(element.Name))
		bytes = addSharedGNMIAuxiliaryEstimate(bytes, sharedGNMIAuxiliaryStringMapBytes(element.Keys))
	}
	return bytes
}

func estimateSharedGNMINXSensorBytes(key string, state nxSensorState) int64 {
	bytes := sharedGNMIAuxiliaryMapEntryBytes + sharedGNMIAuxiliaryNXStateBytes
	bytes = addSharedGNMIAuxiliaryEstimate(bytes, sharedGNMIAuxiliaryStringBytes(key))
	bytes = addSharedGNMIAuxiliaryEstimate(bytes, sharedGNMIAuxiliaryStringBytes(state.description))
	bytes = addSharedGNMIAuxiliaryEstimate(bytes, sharedGNMIAuxiliaryStringBytes(state.unit))
	return addSharedGNMIAuxiliaryEstimate(bytes, sharedGNMIAuxiliaryPathBytes(state.path))
}

func estimateSharedGNMINXSensorUsage(states map[string]nxSensorState) sharedGNMIAuxiliaryUsage {
	usage := sharedGNMIAuxiliaryUsage{count: len(states)}
	for key := range states {
		usage.bytes = addSharedGNMIAuxiliaryEstimate(usage.bytes, estimateSharedGNMINXSensorBytes(key, states[key]))
	}
	return usage
}

func estimateSharedGNMIOpticalSourceBytes(sourceKey, presenceKey string) int64 {
	bytes := sharedGNMIAuxiliaryMapEntryBytes
	bytes = addSharedGNMIAuxiliaryEstimate(bytes, sharedGNMIAuxiliaryStringBytes(sourceKey))
	return addSharedGNMIAuxiliaryEstimate(bytes, sharedGNMIAuxiliaryStringBytes(presenceKey))
}

func estimateSharedGNMIOpticalCountBytes(presenceKey string) int64 {
	return addSharedGNMIAuxiliaryEstimate(sharedGNMIAuxiliaryMapEntryBytes, sharedGNMIAuxiliaryStringBytes(presenceKey))
}

func estimateSharedGNMIOpticalAttributesBytes(presenceKey string, attributes map[string]string) int64 {
	bytes := addSharedGNMIAuxiliaryEstimate(sharedGNMIAuxiliaryMapEntryBytes, sharedGNMIAuxiliaryStringBytes(presenceKey))
	return addSharedGNMIAuxiliaryEstimate(bytes, sharedGNMIAuxiliaryStringMapBytes(attributes))
}

type nxSensorChange struct {
	state  nxSensorState
	exists bool
}

type nxSensorTransaction struct {
	target      *sharedGNMITargetRuntime
	changes     map[string]nxSensorChange
	budgetDelta sharedGNMIAuxiliaryUsage
	done        bool
}

type opticalSourceChange struct {
	presenceKey string
	exists      bool
}

type opticalCountChange struct {
	count  int
	exists bool
}

type opticalAttributesChange struct {
	attributes map[string]string
	exists     bool
}

type opticalPresenceTransaction struct {
	target              *sharedGNMITargetRuntime
	sourceChanges       map[string]opticalSourceChange
	countChanges        map[string]opticalCountChange
	attributesChanges   map[string]opticalAttributesChange
	authoritativeAbsent map[string]struct{}
	points              []internalgnmi.MappedPoint
	budgetDelta         sharedGNMIAuxiliaryUsage
	done                bool
}

func (tx *nxSensorTransaction) commit() {
	if tx == nil || tx.done {
		return
	}
	tx.target.nxMu.Lock()
	// Copying each small transaction value keeps the map immutable while it is
	// published under nxMu.
	//nolint:gocritic // A map range cannot take a stable pointer to its value.
	for key, change := range tx.changes {
		if change.exists {
			if tx.target.nxSensors == nil {
				tx.target.nxSensors = map[string]nxSensorState{}
			}
			tx.target.nxSensors[key] = change.state
		} else {
			delete(tx.target.nxSensors, key)
		}
	}
	tx.done = true
	tx.target.nxMu.Unlock()
}

func (tx *nxSensorTransaction) rollback() {
	if tx == nil || tx.done {
		return
	}
	tx.done = true
}

type sharedGNMIStreamResult struct {
	stream   sharedGNMIRuntimeStream
	err      error
	terminal bool
}

type sharedGNMIUnsupportedError struct{ err error }

func (e *sharedGNMIUnsupportedError) Error() string { return e.err.Error() }
func (e *sharedGNMIUnsupportedError) Unwrap() error { return e.err }

type sharedGNMIProfileStopError struct{ err error }

func (e *sharedGNMIProfileStopError) Error() string { return e.err.Error() }
func (e *sharedGNMIProfileStopError) Unwrap() error { return e.err }

func newSharedGNMIReceiver(
	set receiver.Settings,
	cfg *Config,
	next consumer.Metrics,
	admissions ...*gnmiResponseAdmission,
) (receiver.Metrics, error) {
	defaults := defaultGNMIConfig()
	gnmiConfig := cfg.GNMI
	if gnmiConfig.MaxDatapointsPerChunk == 0 {
		gnmiConfig.MaxDatapointsPerChunk = defaults.MaxDatapointsPerChunk
	}
	if gnmiConfig.MaxCachedSeries == 0 {
		gnmiConfig.MaxCachedSeries = defaults.MaxCachedSeries
	}

	telemetryBuilder, err := componentmetadata.NewTelemetryBuilder(set.TelemetrySettings)
	if err != nil {
		return nil, fmt.Errorf("create gNMI telemetry: %w", err)
	}
	responseAdmission := newGNMIResponseAdmission()
	if len(admissions) > 0 && admissions[0] != nil {
		responseAdmission = admissions[0]
	}
	r := &sharedGNMIReceiver{
		settings:          set,
		config:            gnmiConfig,
		consumer:          next,
		obs:               newPlatformObsReport(set, sharedGNMITransport),
		telemetry:         &gnmiTelemetry{builder: telemetryBuilder},
		maxDatapoints:     gnmiConfig.MaxDatapointsPerChunk,
		maxCachedSeries:   gnmiConfig.MaxCachedSeries,
		done:              make(chan struct{}),
		notificationSlots: make(chan struct{}, sharedGNMIMaxConcurrentDelivery),
		responseAdmission: responseAdmission,
	}
	selector := newDeviceSelectionMatcher(cfg.DeviceSelection)
	selectedTargets := make([]GNMITargetConfig, 0, len(gnmiConfig.Targets))
	for targetIndex := range gnmiConfig.Targets {
		target := gnmiConfig.Targets[targetIndex].withDefaults()
		if selector.allows(sharedGNMITargetIdentity(target)) {
			selectedTargets = append(selectedTargets, target)
		}
	}
	cacheLimits, err := partitionSharedGNMICacheLimits(
		gnmiConfig.MaxCachedSeries,
		internalgnmi.DefaultMaxCacheRetainedBytes,
		len(selectedTargets),
	)
	if err != nil {
		telemetryBuilder.Shutdown()
		return nil, err
	}
	auxiliaryLimits, err := partitionSharedGNMIAuxiliaryLimits(
		gnmiConfig.MaxCachedSeries,
		len(selectedTargets),
	)
	if err != nil {
		telemetryBuilder.Shutdown()
		return nil, err
	}
	for targetIndex := range selectedTargets {
		target := selectedTargets[targetIndex]
		cache, cacheErr := internalgnmi.NewCacheWithLimits(
			cacheLimits[targetIndex].series,
			cacheLimits[targetIndex].retainedBytes,
		)
		if cacheErr != nil {
			telemetryBuilder.Shutdown()
			return nil, fmt.Errorf("build gNMI target %q cache: %w", target.Name, cacheErr)
		}
		auxiliaryBudget := newSharedGNMIAuxiliaryBudgetWithLimits(
			auxiliaryLimits[targetIndex].series,
			auxiliaryLimits[targetIndex].retainedBytes,
		)
		runtime, err := newSharedGNMITargetRuntimeWithBudget(target, cache, auxiliaryBudget)
		if err != nil {
			telemetryBuilder.Shutdown()
			return nil, fmt.Errorf("build gNMI target %q: %w", target.Name, err)
		}
		r.targets = append(r.targets, runtime)
	}
	return r, nil
}

type sharedGNMICacheLimit struct {
	series        int
	retainedBytes int64
}

// partitionSharedGNMICacheLimits deterministically gives earlier configured
// targets one unit of any remainder. Each target owns its partition, preventing
// one device from exhausting the receiver-wide count or byte budget and
// stopping unrelated targets.
func partitionSharedGNMICacheLimits(totalSeries int, totalRetainedBytes int64, targets int) ([]sharedGNMICacheLimit, error) {
	return partitionSharedGNMIStateLimits("cache", totalSeries, totalRetainedBytes, targets)
}

func partitionSharedGNMIAuxiliaryLimits(totalEntries, targets int) ([]sharedGNMICacheLimit, error) {
	if totalEntries < 0 {
		return nil, errors.New("gNMI auxiliary-state count limit cannot be negative")
	}
	maximum := int(^uint(0) >> 1)
	if totalEntries > maximum/sharedGNMIAuxiliaryEntriesPerCachedSeries {
		return nil, errors.New("gNMI auxiliary-state count limit overflows int")
	}
	return partitionSharedGNMIStateLimits(
		"auxiliary-state",
		totalEntries*sharedGNMIAuxiliaryEntriesPerCachedSeries,
		sharedGNMIAuxiliaryRetainedBytes,
		targets,
	)
}

func partitionSharedGNMIStateLimits(
	resource string,
	totalSeries int,
	totalRetainedBytes int64,
	targets int,
) ([]sharedGNMICacheLimit, error) {
	if targets == 0 {
		return nil, nil
	}
	if targets < 0 {
		return nil, errors.New("gNMI selected target count cannot be negative")
	}
	if totalSeries < targets {
		return nil, fmt.Errorf("gNMI %s count limit %d is smaller than selected target count %d", resource, totalSeries, targets)
	}
	if totalRetainedBytes < int64(targets) {
		return nil, fmt.Errorf("gNMI retained-byte %s limit %d is smaller than selected target count %d", resource, totalRetainedBytes, targets)
	}
	limits := make([]sharedGNMICacheLimit, targets)
	baseSeries, extraSeries := totalSeries/targets, totalSeries%targets
	baseBytes, extraBytes := totalRetainedBytes/int64(targets), totalRetainedBytes%int64(targets)
	for index := range limits {
		limits[index] = sharedGNMICacheLimit{series: baseSeries, retainedBytes: baseBytes}
		if index < extraSeries {
			limits[index].series++
		}
		if int64(index) < extraBytes {
			limits[index].retainedBytes++
		}
	}
	return limits, nil
}

func newSharedGNMITargetRuntime(target GNMITargetConfig, cache *internalgnmi.Cache) (*sharedGNMITargetRuntime, error) {
	if cache == nil {
		return nil, errors.New("shared gNMI cache cannot be nil")
	}
	return newSharedGNMITargetRuntimeWithBudget(target, cache, newSharedGNMIAuxiliaryBudget(cache.Capacity()))
}

func newSharedGNMITargetRuntimeWithBudget(
	target GNMITargetConfig,
	cache *internalgnmi.Cache,
	auxiliaryBudget *sharedGNMIAuxiliaryBudget,
) (*sharedGNMITargetRuntime, error) {
	streams, err := buildSharedGNMIStreams(target)
	if err != nil {
		return nil, err
	}
	if cache == nil {
		return nil, errors.New("shared gNMI cache cannot be nil")
	}
	if auxiliaryBudget == nil || auxiliaryBudget.maximum <= 0 || auxiliaryBudget.maximumBytes <= 0 {
		return nil, errors.New("shared gNMI auxiliary-state count and byte budgets must be positive")
	}
	runtime := &sharedGNMITargetRuntime{
		config:   target,
		cache:    cache,
		isolate:  map[string]struct{}{},
		stopped:  map[string]struct{}{},
		rejects:  map[string]int{},
		nxBudget: auxiliaryBudget,
	}
	for streamIndex := range streams {
		stream := streams[streamIndex]
		mappings := make([]internalgnmi.Mapping, 0, len(stream.Mappings))
		staticAttrs := make(map[string]map[string]string, len(stream.Mappings))
		for mappingIndex := range stream.Mappings {
			mapping := &stream.Mappings[mappingIndex]
			mappings = append(mappings, mapping.Mapping)
			if len(mapping.StaticAttributes) > 0 {
				staticAttrs[sharedGNMISourceKey(mapping.Mapping.Source)] = cloneGNMIAttributes(mapping.StaticAttributes)
			}
		}
		registry, err := internalgnmi.NewRegistry(mappings...)
		if err != nil {
			return nil, fmt.Errorf("profile %q mappings: %w", stream.Profile, err)
		}
		runtime.streams = append(runtime.streams, sharedGNMIRuntimeStream{
			sharedGNMIStream: stream,
			registry:         registry,
			staticAttr:       staticAttrs,
		})
	}
	return runtime, nil
}

func (r *sharedGNMIReceiver) Start(_ context.Context, host component.Host) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.host = host
	go r.run(ctx)
	return nil
}

func (r *sharedGNMIReceiver) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	cancel := r.cancel
	r.mu.Unlock()
	if cancel == nil {
		r.telemetry.shutdown()
		return nil
	}
	cancel()
	select {
	case <-r.done:
		r.telemetry.shutdown()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *sharedGNMIReceiver) run(ctx context.Context) {
	defer close(r.done)
	defer r.telemetry.shutdown()
	var wg sync.WaitGroup
	for _, target := range r.targets {
		wg.Go(func() {
			r.runTarget(ctx, target)
		})
	}
	wg.Wait()
}

func (r *sharedGNMIReceiver) runTarget(ctx context.Context, target *sharedGNMITargetRuntime) {
	attempt := 0
	for ctx.Err() == nil {
		terminal, resetBackoff, err := r.serveTarget(ctx, target)
		r.telemetry.connection(ctx, target.config.Name, false)
		if resetBackoff {
			attempt = 0
		}
		if terminal || ctx.Err() != nil {
			return
		}
		r.emitAvailability(ctx, target.config, false)
		delay := equalJitterGNMIBackoff(attempt)
		if isSharedGNMIAuthenticationError(err) {
			r.telemetry.authenticationFailure(ctx, target.config.Name)
			delay = sharedGNMIAuthenticationBackoff
		} else {
			attempt++
		}
		r.telemetry.reconnect(ctx, target.config.Name)
		r.settings.Logger.Warn("Cisco gNMI target disconnected",
			zap.String("target", target.config.Name),
			zap.String("endpoint", target.config.Endpoint),
			zap.Duration("retry_delay", delay),
			zap.Error(err))
		if !waitSharedGNMIBackoff(ctx, delay) {
			return
		}
	}
}

func (r *sharedGNMIReceiver) serveTarget(ctx context.Context, target *sharedGNMITargetRuntime) (bool, bool, error) {
	target.sessionUp.Store(false)
	if target.config.Platform == gnmiPlatformNXOS {
		// DME description/unit identity is scoped to a device session. Preserve
		// mapped cache and tombstones, but require fresh sensor identity before
		// values from a reconnected session can be mapped.
		target.clearNXSensorState()
		defer target.clearNXSensorState()
	}
	conn, err := r.dialTarget(ctx, target.config)
	if err != nil {
		return false, false, err
	}
	defer conn.Close()
	capCtx, cancel := context.WithTimeout(sharedGNMIOutgoingContext(ctx, target.config), target.config.CapabilitiesTimeout)
	capabilities, err := invokeGNMICapabilities(capCtx, conn, r.responseAdmission, target.config.MaxRecvMsgSizeMiB)
	cancel()
	if err != nil {
		return false, false, fmt.Errorf("capabilities: %w", err)
	}
	client := gnmipb.NewGNMIClient(conn)
	encoding, err := negotiateSharedGNMIEncoding(target.config, capabilities, runtimeSharedGNMIStreams(target.streams))
	r.responseAdmission.release(capabilities)
	if err != nil {
		return false, false, err
	}
	r.telemetry.connection(ctx, target.config.Name, true)
	connectedAt := time.Now()
	terminal, err := r.serveTargetStreams(ctx, target, client, encoding)
	resetBackoff := terminal || time.Since(connectedAt) >= sharedGNMIBackoffResetAfter
	if err == nil && !terminal {
		return false, resetBackoff, io.ErrUnexpectedEOF
	}
	return terminal, resetBackoff, err
}

func (r *sharedGNMIReceiver) dialTarget(ctx context.Context, target GNMITargetConfig) (*grpc.ClientConn, error) {
	clientConfig := configgrpc.NewDefaultClientConfig()
	clientConfig.Endpoint = target.Endpoint
	clientConfig.TLS = configtls.ClientConfig{
		Config: configtls.Config{
			CAFile:         target.TLS.CAFile,
			CertFile:       target.TLS.CertFile,
			KeyFile:        target.TLS.KeyFile,
			MinVersion:     target.TLS.MinVersion,
			ReloadInterval: target.TLS.ReloadInterval,
		},
		ServerName: target.TLS.ServerNameOverride,
	}
	clientConfig.Keepalive = configoptional.Some(configgrpc.KeepaliveClientConfig{
		Time:                target.Keepalive.Time,
		Timeout:             target.Keepalive.Timeout,
		PermitWithoutStream: boolValue(target.Keepalive.PermitWithoutStream, true),
	})
	dialCtx, cancel := context.WithTimeout(ctx, target.ConnectTimeout)
	defer cancel()
	conn, err := clientConfig.ToClientConn(
		dialCtx,
		r.host.GetExtensions(),
		r.settings.TelemetrySettings,
		configgrpc.WithGrpcDialOption(grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(target.MaxRecvMsgSizeMiB*1024*1024),
			gnmiResponsePreflightCallOption(target.MaxRecvMsgSizeMiB, r.responseAdmission, ctx.Done()),
		)),
	)
	if err != nil {
		return nil, err
	}
	conn.Connect()
	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			return conn, nil
		}
		if state == connectivity.Shutdown {
			_ = conn.Close()
			return nil, errors.New("gNMI connection shut down before becoming ready")
		}
		if !conn.WaitForStateChange(dialCtx, state) {
			_ = conn.Close()
			return nil, fmt.Errorf("gNMI connection did not become ready: %w", dialCtx.Err())
		}
	}
}

func (r *sharedGNMIReceiver) serveTargetStreams(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	client gnmipb.GNMIClient,
	encoding gnmipb.Encoding,
) (bool, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan sharedGNMIStreamResult, 32)
	semaphore := make(chan struct{}, target.config.MaxStreams)
	profileCancels := map[string][]context.CancelFunc{}
	var wg sync.WaitGroup
	active := 0
	launch := func(stream sharedGNMIRuntimeStream) {
		if target.profileStopped(stream.Profile) {
			return
		}
		stream.Paths = target.filterIsolated(stream.Paths)
		if len(stream.Paths) == 0 {
			return
		}
		subscriptionCtx, subscriptionCancel := context.WithCancel(streamCtx)
		profileCancels[stream.Profile] = append(profileCancels[stream.Profile], subscriptionCancel)
		active++
		wg.Go(func() {
			defer subscriptionCancel()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-subscriptionCtx.Done():
				results <- sharedGNMIStreamResult{stream: stream, err: subscriptionCtx.Err()}
				return
			}
			terminal, err := r.runSubscription(subscriptionCtx, target, client, stream, encoding)
			results <- sharedGNMIStreamResult{stream: stream, terminal: terminal, err: err}
		})
	}
	for streamIndex := range target.streams {
		launch(target.streams[streamIndex])
	}
	if active == 0 {
		return true, nil
	}
	for active > 0 {
		select {
		case <-ctx.Done():
			cancel()
			wg.Wait()
			return false, ctx.Err()
		case result := <-results:
			active--
			if target.profileStopped(result.stream.Profile) {
				continue
			}
			if result.err == nil && result.terminal {
				continue
			}
			var unsupported *sharedGNMIUnsupportedError
			if errors.As(result.err, &unsupported) {
				select {
				case semaphore <- struct{}{}:
				case <-streamCtx.Done():
					cancel()
					wg.Wait()
					return false, streamCtx.Err()
				}
				validGroups, resolutionErr := r.resolveUnsupportedGNMIPaths(streamCtx, target, client, result.stream, encoding)
				<-semaphore
				if resolutionErr != nil {
					var stopped *sharedGNMIProfileStopError
					if errors.As(resolutionErr, &stopped) {
						r.stopGNMIProfile(ctx, target, result.stream, "bisection_limit", stopped, profileCancels)
						continue
					}
					cancel()
					wg.Wait()
					return false, resolutionErr
				}
				if len(validGroups) > 1 {
					if active+len(validGroups) > target.config.MaxStreams {
						r.stopGNMIProfile(ctx, target, result.stream, "incompatible_path_group", fmt.Errorf(
							"the target accepts %d path groups separately, but they would require %d of %d allowed streams",
							len(validGroups), active+len(validGroups), target.config.MaxStreams,
						), profileCancels)
						continue
					}
				}
				for _, validPaths := range validGroups {
					validated := result.stream
					validated.Paths = validPaths
					launch(validated)
				}
				continue
			}
			var stopped *sharedGNMIProfileStopError
			if errors.As(result.err, &stopped) {
				r.stopGNMIProfile(ctx, target, result.stream, "cache_limit", stopped, profileCancels)
				continue
			}
			cancel()
			wg.Wait()
			return false, result.err
		}
	}
	wg.Wait()
	return true, nil
}

// resolveUnsupportedGNMIPaths probes rejected path groups serially while
// holding the failed stream's slot. A valid STREAM probe is stopped after its
// initial sync_response; POLL probes also complete one poll cycle, and ONCE
// probes require clean completion. Probe updates are intentionally discarded
// so only the final subscriptions mutate cache state or emit metrics. This
// avoids deadlocking when all configured stream slots are already occupied.
func (r *sharedGNMIReceiver) resolveUnsupportedGNMIPaths(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	client gnmipb.GNMIClient,
	stream sharedGNMIRuntimeStream,
	encoding gnmipb.Encoding,
) ([][]sharedGNMIPath, error) {
	rejectionKey := sharedGNMIRejectedPathSetKey(stream)
	if target.recordRejectedPathSet(rejectionKey) > 1 {
		return nil, &sharedGNMIProfileStopError{err: errors.New("subscription path set was rejected repeatedly after bisection")}
	}
	probes := 0
	var resolve func([]sharedGNMIPath) ([][]sharedGNMIPath, error)
	resolve = func(paths []sharedGNMIPath) ([][]sharedGNMIPath, error) {
		if len(paths) == 0 {
			return nil, nil
		}
		if len(paths) == 1 {
			target.isolatePath(paths[0])
			if stream.Required {
				r.telemetry.degraded(ctx, target.config.Name, stream.Profile, "unsupported_path", true)
			}
			r.settings.Logger.Warn("Cisco gNMI path isolated until receiver restart",
				zap.String("target", target.config.Name),
				zap.String("profile", stream.Profile),
				zap.String("origin", paths[0].Origin),
				zap.String("path", paths[0].Path))
			return nil, nil
		}

		midpoint := len(paths) / 2
		halves := [][]sharedGNMIPath{paths[:midpoint], paths[midpoint:]}
		validGroups := make([][]sharedGNMIPath, 0, 2)
		for _, half := range halves {
			probes++
			if probes > sharedGNMIMaxBisectionProbes {
				return nil, &sharedGNMIProfileStopError{err: fmt.Errorf("subscription bisection exceeded %d probes", sharedGNMIMaxBisectionProbes)}
			}
			probe := stream
			probe.Paths = append([]sharedGNMIPath(nil), half...)
			err := r.probeSubscriptionUntilSync(ctx, target, client, probe, encoding)
			if err == nil {
				validGroups = append(validGroups, append([]sharedGNMIPath(nil), half...))
				continue
			}
			var unsupported *sharedGNMIUnsupportedError
			if !errors.As(err, &unsupported) {
				return nil, err
			}
			resolved, err := resolve(half)
			if err != nil {
				return nil, err
			}
			validGroups = append(validGroups, resolved...)
		}
		if len(validGroups) <= 1 {
			return validGroups, nil
		}
		combined := make([]sharedGNMIPath, 0, len(paths))
		for _, group := range validGroups {
			combined = append(combined, group...)
		}
		probes++
		if probes > sharedGNMIMaxBisectionProbes {
			return nil, &sharedGNMIProfileStopError{err: fmt.Errorf("subscription bisection exceeded %d probes", sharedGNMIMaxBisectionProbes)}
		}
		probe := stream
		probe.Paths = combined
		err := r.probeSubscriptionUntilSync(ctx, target, client, probe, encoding)
		if err == nil {
			return [][]sharedGNMIPath{combined}, nil
		}
		var unsupported *sharedGNMIUnsupportedError
		if !errors.As(err, &unsupported) {
			return nil, err
		}
		return validGroups, nil
	}

	return resolve(stream.Paths)
}

func (r *sharedGNMIReceiver) probeSubscriptionUntilSync(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	client gnmipb.GNMIClient,
	stream sharedGNMIRuntimeStream,
	encoding gnmipb.Encoding,
) error {
	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	r.telemetry.subscription(probeCtx, target.config.Name, stream.Profile, true)
	defer r.telemetry.subscription(context.Background(), target.config.Name, stream.Profile, false)

	request, err := buildSharedGNMISubscribeRequest(target.config, stream.sharedGNMIStream, encoding)
	if err != nil {
		return err
	}
	subscribe, err := client.Subscribe(
		sharedGNMIOutgoingContext(probeCtx, target.config),
		gnmiResponsePreflightCallOption(target.config.MaxRecvMsgSizeMiB, r.responseAdmission, probeCtx.Done()),
	)
	if err != nil {
		return classifySharedGNMIStreamError(err)
	}
	if err := subscribe.Send(request); err != nil {
		return classifySharedGNMIStreamError(err)
	}
	if stream.Mode == gnmiModeOnce {
		if err := subscribe.CloseSend(); err != nil {
			return classifySharedGNMIStreamError(err)
		}
	}
	if stream.Mode == gnmiModeOnce {
		return receiveSharedGNMIProbeOnce(subscribe, r.responseAdmission)
	}
	if err := receiveSharedGNMIProbeUntilSync(subscribe, r.responseAdmission); err != nil {
		return err
	}
	if stream.Mode != gnmiModePoll {
		return nil
	}
	if err := subscribe.Send(&gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Poll{Poll: &gnmipb.Poll{}}}); err != nil {
		return classifySharedGNMIStreamError(err)
	}
	return receiveSharedGNMIProbeUntilSync(subscribe, r.responseAdmission)
}

//nolint:staticcheck // Deprecated in-band Error responses remain on the supported gNMI wire protocol.
func receiveSharedGNMIProbeUntilSync(
	subscribe grpc.BidiStreamingClient[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse],
	admission *gnmiResponseAdmission,
) error {
	for {
		response, err := receiveGNMISubscribeResponse(subscribe, admission)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return classifySharedGNMIStreamError(err)
		}
		var responseErr error
		synced := false
		switch body := response.GetResponse().(type) {
		case *gnmipb.SubscribeResponse_SyncResponse:
			synced = body.SyncResponse
		case *gnmipb.SubscribeResponse_Error:
			if body.Error == nil {
				responseErr = errors.New("empty gNMI subscribe error")
			} else {
				responseErr = classifySharedGNMIStreamError(sanitizedGNMISubscribeStatusError(body.Error))
			}
		}
		admission.release(response)
		if responseErr != nil {
			return responseErr
		}
		if synced {
			return nil
		}
	}
}

//nolint:staticcheck // Deprecated in-band Error responses remain on the supported gNMI wire protocol.
func receiveSharedGNMIProbeOnce(
	subscribe grpc.BidiStreamingClient[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse],
	admission *gnmiResponseAdmission,
) error {
	synced := false
	for {
		response, err := receiveGNMISubscribeResponse(subscribe, admission)
		if err != nil {
			if errors.Is(err, io.EOF) {
				if synced {
					return nil
				}
				return io.ErrUnexpectedEOF
			}
			return classifySharedGNMIStreamError(err)
		}
		var responseErr error
		switch body := response.GetResponse().(type) {
		case *gnmipb.SubscribeResponse_SyncResponse:
			synced = synced || body.SyncResponse
		case *gnmipb.SubscribeResponse_Error:
			if body.Error == nil {
				responseErr = errors.New("empty gNMI subscribe error")
			} else {
				responseErr = classifySharedGNMIStreamError(sanitizedGNMISubscribeStatusError(body.Error))
			}
		}
		admission.release(response)
		if responseErr != nil {
			return responseErr
		}
	}
}

func (r *sharedGNMIReceiver) stopGNMIProfile(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
	reason string,
	err error,
	profileCancels map[string][]context.CancelFunc,
) {
	target.stopProfile(stream.Profile)
	for _, profileCancel := range profileCancels[stream.Profile] {
		profileCancel()
	}
	if target.config.Platform == gnmiPlatformNXOS && stream.Optics {
		target.clearNXSensorState()
	}
	r.telemetry.degraded(ctx, target.config.Name, stream.Profile, reason, true)
	r.settings.Logger.Error("Cisco gNMI profile stopped until receiver restart",
		zap.String("target", target.config.Name),
		zap.String("profile", stream.Profile),
		zap.Bool("required", stream.Required),
		zap.String("reason", reason),
		zap.Error(err))
}

func (r *sharedGNMIReceiver) runSubscription(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	client gnmipb.GNMIClient,
	stream sharedGNMIRuntimeStream,
	encoding gnmipb.Encoding,
) (bool, error) {
	r.telemetry.subscription(ctx, target.config.Name, stream.Profile, true)
	defer r.telemetry.subscription(context.Background(), target.config.Name, stream.Profile, false)
	request, err := buildSharedGNMISubscribeRequest(target.config, stream.sharedGNMIStream, encoding)
	if err != nil {
		return false, err
	}
	subscribe, err := client.Subscribe(
		sharedGNMIOutgoingContext(ctx, target.config),
		gnmiResponsePreflightCallOption(target.config.MaxRecvMsgSizeMiB, r.responseAdmission, ctx.Done()),
	)
	if err != nil {
		return false, classifySharedGNMIStreamError(err)
	}
	if err := subscribe.Send(request); err != nil {
		return false, classifySharedGNMIStreamError(err)
	}
	switch stream.Mode {
	case gnmiModeOnce:
		if err := subscribe.CloseSend(); err != nil {
			return false, classifySharedGNMIStreamError(err)
		}
		if err := r.receiveOnceToCompletion(ctx, target, stream, subscribe); err != nil {
			return false, err
		}
		return true, nil
	case gnmiModePoll:
		if err := r.receiveUntilSync(ctx, target, stream, subscribe); err != nil {
			return false, err
		}
		for {
			if err := subscribe.Send(&gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Poll{Poll: &gnmipb.Poll{}}}); err != nil {
				return false, classifySharedGNMIStreamError(err)
			}
			if err := r.receiveUntilSync(ctx, target, stream, subscribe); err != nil {
				return false, err
			}
			timer := time.NewTimer(stream.PollInterval)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return false, ctx.Err()
			case <-timer.C:
			}
		}
	case gnmiModeStream:
		for {
			response, err := receiveGNMISubscribeResponse(subscribe, r.responseAdmission)
			if err != nil {
				if errors.Is(err, io.EOF) {
					return false, io.ErrUnexpectedEOF
				}
				return false, classifySharedGNMIStreamError(err)
			}
			_, handleErr := r.handleSubscribeResponse(ctx, target, stream, response)
			r.responseAdmission.release(response)
			if handleErr != nil {
				return false, handleErr
			}
		}
	default:
		return false, fmt.Errorf("unsupported gNMI subscription mode %q", stream.Mode)
	}
}

func (r *sharedGNMIReceiver) receiveOnceToCompletion(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
	subscribe grpc.BidiStreamingClient[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse],
) error {
	synced := false
	for {
		response, err := receiveGNMISubscribeResponse(subscribe, r.responseAdmission)
		if err != nil {
			if errors.Is(err, io.EOF) {
				if synced {
					return nil
				}
				return io.ErrUnexpectedEOF
			}
			return classifySharedGNMIStreamError(err)
		}
		responseSynced, handleErr := r.handleSubscribeResponse(ctx, target, stream, response)
		r.responseAdmission.release(response)
		if handleErr != nil {
			return handleErr
		}
		synced = synced || responseSynced
	}
}

func (r *sharedGNMIReceiver) receiveUntilSync(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
	subscribe grpc.BidiStreamingClient[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse],
) error {
	for {
		response, err := receiveGNMISubscribeResponse(subscribe, r.responseAdmission)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return classifySharedGNMIStreamError(err)
		}
		synced, handleErr := r.handleSubscribeResponse(ctx, target, stream, response)
		r.responseAdmission.release(response)
		if handleErr != nil {
			return handleErr
		}
		if synced {
			return nil
		}
	}
}

//nolint:staticcheck // Deprecated in-band Error responses remain on the supported gNMI wire protocol.
func (r *sharedGNMIReceiver) handleSubscribeResponse(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
	response *gnmipb.SubscribeResponse,
) (bool, error) {
	switch body := response.GetResponse().(type) {
	case *gnmipb.SubscribeResponse_Update:
		if body.Update == nil {
			return false, nil
		}
		if err := r.processNotification(ctx, target, stream, body.Update); err != nil {
			return false, err
		}
		r.emitTargetAvailable(ctx, target)
		return false, nil
	case *gnmipb.SubscribeResponse_SyncResponse:
		if body.SyncResponse {
			r.emitTargetAvailable(ctx, target)
		}
		return body.SyncResponse, nil
	case *gnmipb.SubscribeResponse_Error:
		if body.Error == nil {
			return false, errors.New("empty gNMI subscribe error")
		}
		return false, classifySharedGNMIStreamError(sanitizedGNMISubscribeStatusError(body.Error))
	default:
		return false, nil
	}
}

func (r *sharedGNMIReceiver) processNotification(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
	notification *gnmipb.Notification,
) error {
	target.deliveryMu.Lock()
	defer target.deliveryMu.Unlock()
	if target.profileStopped(stream.Profile) {
		return nil
	}
	if err := r.acquireNotificationSlot(ctx); err != nil {
		return err
	}
	defer r.releaseNotificationSlot()
	if target.profileStopped(stream.Profile) {
		return nil
	}
	receiptTime := time.Now()
	decoded, decodeStats, err := internalgnmi.DecodeNotification(target.config.Name, notification, receiptTime)
	if err != nil {
		r.telemetry.decodeErrors(ctx, target.config.Name, stream.Profile, 1)
		return nil
	}
	var nxTransaction *nxSensorTransaction
	if target.config.Platform == gnmiPlatformNXOS && stream.Optics {
		decoded, nxTransaction, err = target.prepareNXNotification(decoded)
		if err != nil {
			return &sharedGNMIProfileStopError{err: err}
		}
		defer func() {
			if nxTransaction != nil {
				nxTransaction.rollback()
			}
		}()
	}
	normalizeGNMIStateValues(&decoded)
	r.telemetry.updates(ctx, target.config.Name, stream.Profile, len(decoded.Updates))
	r.telemetry.invalidTimestamps(ctx, target.config.Name, stream.Profile, decodeStats.InvalidTimestamps)
	r.telemetry.deletes(ctx, target.config.Name, stream.Profile, len(decoded.Deletes))

	cacheNotification := internalgnmi.CacheNotification{
		Prefix: decoded.Prefix, Timestamp: decoded.Timestamp, Atomic: decoded.Atomic, Deletes: decoded.Deletes,
	}
	for _, touched := range decoded.Touched {
		cacheNotification.Touched = append(cacheNotification.Touched, touched.Clone())
	}
	unmapped := decodeStats.UnmappedValues
	for pointIndex := range decoded.Updates {
		point := &decoded.Updates[pointIndex]
		mapped, ok := stream.registry.Map(*point)
		if !ok {
			if !stream.HealthOnly {
				unmapped++
			}
			continue
		}
		maps.Copy(mapped.Attributes, stream.staticAttr[sharedGNMISeriesSourceKey(point.Series)])
		cacheNotification.Updates = append(cacheNotification.Updates, mapped)
	}
	r.telemetry.unmapped(ctx, target.config.Name, stream.Profile, unmapped)
	if stream.HealthOnly {
		r.telemetry.success(ctx, target.config.Name, stream.Profile, receiptTime)
		return nil
	}
	cacheTransaction, err := target.cache.Prepare(cacheNotification)
	if err != nil {
		var capacity *internalgnmi.CapacityError
		if errors.As(err, &capacity) {
			return &sharedGNMIProfileStopError{err: err}
		}
		return err
	}
	defer func() {
		if cacheTransaction != nil {
			cacheTransaction.Rollback()
		}
	}()
	result := cacheTransaction.Result()
	if target.profileStopped(stream.Profile) {
		return nil
	}
	if result.Rejected {
		cacheTransaction.Rollback()
		cacheTransaction = nil
		if nxTransaction != nil {
			nxTransaction.rollback()
			nxTransaction = nil
		}
		r.telemetry.duplicates(ctx, target.config.Name, stream.Profile, result.Duplicates)
		r.telemetry.cacheUtilization(ctx, target.cache.StateLen(), target.cache.Capacity())
		r.telemetry.success(ctx, target.config.Name, stream.Profile, receiptTime)
		return nil
	}
	points := append([]internalgnmi.MappedPoint(nil), result.Applied...)
	var presenceTransaction *opticalPresenceTransaction
	if stream.Optics {
		presenceTransaction = target.prepareOpticalPresence(result, decoded.Timestamp)
		defer func() {
			if presenceTransaction != nil {
				presenceTransaction.rollback()
			}
		}()
		points = append(points, presenceTransaction.points...)
	}
	auxiliaryDelta := sharedGNMIAuxiliaryUsage{}
	if nxTransaction != nil {
		auxiliaryDelta = nxTransaction.budgetDelta
	}
	if presenceTransaction != nil {
		var combined bool
		auxiliaryDelta, combined = combineSharedGNMIAuxiliaryUsage(auxiliaryDelta, presenceTransaction.budgetDelta)
		if !combined {
			return &sharedGNMIProfileStopError{err: errors.New("gNMI auxiliary-state accounting overflow")}
		}
	}
	var auxiliaryReservation *sharedGNMIAuxiliaryReservation
	if nxTransaction != nil || presenceTransaction != nil {
		auxiliaryReservation, err = prepareSharedGNMIAuxiliaryReservation(target.nxBudget, auxiliaryDelta)
		if err != nil {
			return &sharedGNMIProfileStopError{err: err}
		}
		defer func() {
			if auxiliaryReservation != nil {
				auxiliaryReservation.rollback()
			}
		}()
	}
	chunks, err := internalgnmi.BuildMetricChunks(points, r.maxDatapoints)
	if err != nil {
		return err
	}
	for chunkIndex, chunk := range chunks {
		decorateSharedGNMIResources(chunk, target.config)
		opCtx := startMetricsOp(ctx, r.obs)
		consumeErr := r.consumer.ConsumeMetrics(opCtx, chunk)
		endMetricsOp(opCtx, r.obs, chunk.DataPointCount(), consumeErr)
		if consumeErr != nil {
			r.telemetry.consumerRefusal(ctx, target.config.Name, stream.Profile)
			r.settings.Logger.Warn("Downstream consumer refused Cisco gNMI metric chunk; subscription will reconnect",
				zap.String("target", target.config.Name),
				zap.String("profile", stream.Profile),
				zap.Int("chunk", chunkIndex+1),
				zap.Int("chunks", len(chunks)),
				zap.Int("datapoints", chunk.DataPointCount()),
				zap.Error(consumeErr))
			return fmt.Errorf("consume Cisco gNMI metric chunk %d of %d: %w", chunkIndex+1, len(chunks), consumeErr)
		}
	}
	// stopGNMIProfile takes the write lock before clearing NX state. Keep the
	// profile active across the complete cache/NX/presence publication boundary
	// so a sibling stream cannot publish state after that cleanup boundary.
	target.stateMu.RLock()
	_, stopped := target.stopped[stream.Profile]
	if stopped {
		target.stateMu.RUnlock()
		return nil
	}
	cacheTransaction.Commit()
	cacheTransaction = nil
	if nxTransaction != nil {
		nxTransaction.commit()
		nxTransaction = nil
	}
	if presenceTransaction != nil {
		presenceTransaction.commit()
		presenceTransaction = nil
	}
	if auxiliaryReservation != nil {
		auxiliaryReservation.commit()
		auxiliaryReservation = nil
	}
	target.stateMu.RUnlock()
	r.telemetry.duplicates(ctx, target.config.Name, stream.Profile, result.Duplicates)
	r.telemetry.cacheUtilization(ctx, target.cache.StateLen(), target.cache.Capacity())
	r.telemetry.success(ctx, target.config.Name, stream.Profile, receiptTime)
	return nil
}

func (r *sharedGNMIReceiver) acquireNotificationSlot(ctx context.Context) error {
	if r.notificationSlots == nil {
		return errors.New("shared gNMI notification processing gate is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case r.notificationSlots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			r.releaseNotificationSlot()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *sharedGNMIReceiver) releaseNotificationSlot() {
	<-r.notificationSlots
}

func (target *sharedGNMITargetRuntime) clearNXSensorState() {
	target.deliveryMu.Lock()
	defer target.deliveryMu.Unlock()
	target.nxMu.Lock()
	usage := estimateSharedGNMINXSensorUsage(target.nxSensors)
	target.nxMu.Unlock()
	if usage.count == 0 {
		return
	}
	delta := sharedGNMIAuxiliaryUsage{count: -usage.count, bytes: -usage.bytes}
	_, _, reserved, started := target.nxBudget.prepareChange(delta)
	if !started {
		return
	}
	target.nxMu.Lock()
	target.nxSensors = nil
	target.nxMu.Unlock()
	target.nxBudget.finishChange(delta, reserved, true)
}

func (r *sharedGNMIReceiver) emitTargetAvailable(ctx context.Context, target *sharedGNMITargetRuntime) {
	if target.sessionUp.CompareAndSwap(false, true) {
		if !r.emitAvailability(ctx, target.config, true) {
			// A refused or canceled availability signal was not delivered. Let a
			// later notification retry it instead of pinning the local state to up.
			target.sessionUp.CompareAndSwap(true, false)
		}
	}
}

func (r *sharedGNMIReceiver) emitAvailability(ctx context.Context, target GNMITargetConfig, up bool) bool {
	if err := r.acquireNotificationSlot(ctx); err != nil {
		return false
	}
	defer r.releaseNotificationSlot()
	value := int64(0)
	if up {
		value = 1
	}
	point := internalgnmi.MappedPoint{
		Source: internalgnmi.Series{
			Target: target.Name, Origin: builtinGNMISyntheticReceiverOrigin,
			Elements: []internalgnmi.PathElem{{Name: "target"}, {Name: target.Platform}}, Leaf: "up",
		},
		Metric:     builtinGNMIMetricMetadata["cisco.device.up"],
		GaugeType:  internalgnmi.GaugeInt,
		MetricType: internalgnmi.MetricGauge,
		IntValue:   value,
		Timestamp:  time.Now(),
	}
	chunks, err := internalgnmi.BuildMetricChunks([]internalgnmi.MappedPoint{point}, 1)
	if err != nil || len(chunks) == 0 {
		return false
	}
	decorateSharedGNMIResources(chunks[0], target)
	opCtx := startMetricsOp(ctx, r.obs)
	consumeErr := r.consumer.ConsumeMetrics(opCtx, chunks[0])
	endMetricsOp(opCtx, r.obs, chunks[0].DataPointCount(), consumeErr)
	if consumeErr != nil {
		r.telemetry.consumerRefusal(ctx, target.Name, builtinGNMIProfileIdentity)
	}
	return consumeErr == nil
}

func decorateSharedGNMIResources(metrics pmetric.Metrics, target GNMITargetConfig) {
	osName := map[string]string{
		gnmiPlatformIOSXE: "Cisco IOS XE",
		gnmiPlatformIOSXR: "Cisco IOS XR",
		gnmiPlatformNXOS:  "Cisco NX-OS",
	}[target.Platform]
	host, _, splitErr := net.SplitHostPort(target.Endpoint)
	for i := 0; i < metrics.ResourceMetrics().Len(); i++ {
		attributes := metrics.ResourceMetrics().At(i).Resource().Attributes()
		attributes.PutStr("hw.type", "network")
		attributes.PutStr("cisco.os.name", target.Platform)
		attributes.PutStr("cisco.platform.family", target.Platform)
		attributes.PutStr("cisco.telemetry.transport", "gnmi_dial_in")
		if osName != "" {
			attributes.PutStr("os.name", osName)
		}
		if splitErr == nil {
			putIPAttr(attributes, "host.ip", host)
		}
	}
}

func (tx *opticalPresenceTransaction) commit() {
	if tx == nil || tx.done {
		return
	}
	tx.target.presenceMu.Lock()
	for sourceKey, trackedPresence := range tx.target.opticalSources {
		if _, absent := tx.authoritativeAbsent[trackedPresence]; absent {
			delete(tx.target.opticalSources, sourceKey)
		}
	}
	for presenceKey := range tx.authoritativeAbsent {
		delete(tx.target.presenceCounts, presenceKey)
		delete(tx.target.presenceAttrs, presenceKey)
	}
	for sourceKey, change := range tx.sourceChanges {
		if change.exists {
			if _, absent := tx.authoritativeAbsent[change.presenceKey]; !absent {
				if tx.target.opticalSources == nil {
					tx.target.opticalSources = map[string]string{}
				}
				tx.target.opticalSources[sourceKey] = change.presenceKey
			}
		} else {
			delete(tx.target.opticalSources, sourceKey)
		}
	}
	for presenceKey, change := range tx.countChanges {
		if _, absent := tx.authoritativeAbsent[presenceKey]; absent {
			continue
		}
		if change.exists {
			if tx.target.presenceCounts == nil {
				tx.target.presenceCounts = map[string]int{}
			}
			tx.target.presenceCounts[presenceKey] = change.count
		} else {
			delete(tx.target.presenceCounts, presenceKey)
		}
	}
	for presenceKey, change := range tx.attributesChanges {
		if _, absent := tx.authoritativeAbsent[presenceKey]; absent {
			continue
		}
		if change.exists {
			if tx.target.presenceAttrs == nil {
				tx.target.presenceAttrs = map[string]map[string]string{}
			}
			tx.target.presenceAttrs[presenceKey] = change.attributes
		} else {
			delete(tx.target.presenceAttrs, presenceKey)
		}
	}
	tx.target.presenceMu.Unlock()
	tx.done = true
}

func (tx *opticalPresenceTransaction) rollback() {
	if tx == nil || tx.done {
		return
	}
	tx.done = true
}

func (target *sharedGNMITargetRuntime) updateOpticalPresence(
	result internalgnmi.CacheResult,
	timestamp time.Time,
) ([]internalgnmi.MappedPoint, error) {
	target.deliveryMu.Lock()
	defer target.deliveryMu.Unlock()
	transaction := target.prepareOpticalPresence(result, timestamp)
	var err error
	reservation, err := prepareSharedGNMIAuxiliaryReservation(target.nxBudget, transaction.budgetDelta)
	if err != nil {
		transaction.rollback()
		return nil, err
	}
	transaction.commit()
	reservation.commit()
	return transaction.points, nil
}

func (target *sharedGNMITargetRuntime) prepareOpticalPresence(
	result internalgnmi.CacheResult,
	timestamp time.Time,
) *opticalPresenceTransaction {
	transaction := &opticalPresenceTransaction{
		target:              target,
		sourceChanges:       map[string]opticalSourceChange{},
		countChanges:        map[string]opticalCountChange{},
		attributesChanges:   map[string]opticalAttributesChange{},
		authoritativeAbsent: map[string]struct{}{},
	}
	target.presenceMu.Lock()
	getSource := func(sourceKey string) (string, bool) {
		if change, changed := transaction.sourceChanges[sourceKey]; changed {
			if !change.exists {
				return "", false
			}
			if _, absent := transaction.authoritativeAbsent[change.presenceKey]; absent {
				return "", false
			}
			return change.presenceKey, true
		}
		presenceKey, exists := target.opticalSources[sourceKey]
		if _, absent := transaction.authoritativeAbsent[presenceKey]; absent {
			return "", false
		}
		return presenceKey, exists
	}
	getCount := func(presenceKey string) (int, bool) {
		if _, absent := transaction.authoritativeAbsent[presenceKey]; absent {
			return 0, false
		}
		if change, changed := transaction.countChanges[presenceKey]; changed {
			return change.count, change.exists
		}
		count, exists := target.presenceCounts[presenceKey]
		return count, exists
	}
	getAttributes := func(presenceKey string) (map[string]string, bool) {
		if _, absent := transaction.authoritativeAbsent[presenceKey]; absent {
			return nil, false
		}
		if change, changed := transaction.attributesChanges[presenceKey]; changed {
			return change.attributes, change.exists
		}
		attributes, exists := target.presenceAttrs[presenceKey]
		return attributes, exists
	}

	emit := map[string]int64{}
	for pointIndex := range result.Applied {
		point := &result.Applied[pointIndex]
		if point.Metric.Name != "cisco.optics.present" || gnmiMappedPointIsPresent(*point) {
			continue
		}
		presenceKey, _ := opticalPresenceIdentity(point.Attributes)
		if presenceKey == "" {
			continue
		}
		transaction.authoritativeAbsent[presenceKey] = struct{}{}
	}
	// Apply removals against the committed source map before staging new points.
	// A cache replacement can remove and re-add the same source path with a new
	// optical identity; resolving the removal after the add would mistakenly
	// delete/decrement the newly staged identity.
	removeSource := func(point *internalgnmi.MappedPoint) {
		sourceKey := point.Source.Key()
		presenceKey, exists := getSource(sourceKey)
		if !exists {
			return
		}
		transaction.sourceChanges[sourceKey] = opticalSourceChange{}
		count, _ := getCount(presenceKey)
		count--
		if count <= 0 {
			transaction.countChanges[presenceKey] = opticalCountChange{}
			emit[presenceKey] = 0
			return
		}
		transaction.countChanges[presenceKey] = opticalCountChange{count: count, exists: true}
	}
	for pointIndex := range result.Removed {
		removeSource(&result.Removed[pointIndex])
	}
	for pointIndex := range result.Replaced {
		removeSource(&result.Replaced[pointIndex])
	}
	for pointIndex := range result.Applied {
		point := &result.Applied[pointIndex]
		if !strings.HasPrefix(point.Metric.Name, "cisco.optics.") {
			continue
		}
		sourceKey := point.Source.Key()
		presenceKey, attrs := opticalPresenceIdentity(point.Attributes)
		if presenceKey == "" {
			continue
		}
		if _, absent := transaction.authoritativeAbsent[presenceKey]; absent {
			continue
		}
		previous, exists := getSource(sourceKey)
		if exists && previous != presenceKey {
			count, _ := getCount(previous)
			count--
			if count <= 0 {
				transaction.countChanges[previous] = opticalCountChange{}
				emit[previous] = 0
			} else {
				transaction.countChanges[previous] = opticalCountChange{count: count, exists: true}
			}
		}
		if !exists || previous != presenceKey {
			transaction.sourceChanges[sourceKey] = opticalSourceChange{presenceKey: presenceKey, exists: true}
			count, _ := getCount(presenceKey)
			transaction.countChanges[presenceKey] = opticalCountChange{count: count + 1, exists: true}
		}
		transaction.attributesChanges[presenceKey] = opticalAttributesChange{attributes: attrs, exists: true}
		if point.Metric.Name != "cisco.optics.present" {
			emit[presenceKey] = 1
		} else {
			// The canonical applied presence point is authoritative. Suppress a
			// staged synthetic zero left by replacing the same identity.
			delete(emit, presenceKey)
		}
	}
	for presenceKey := range transaction.authoritativeAbsent {
		delete(emit, presenceKey)
	}
	points := make([]internalgnmi.MappedPoint, 0, len(emit))
	for presenceKey, value := range emit {
		attributes, _ := getAttributes(presenceKey)
		attrs := cloneGNMIAttributes(attributes)
		if value == 0 {
			transaction.attributesChanges[presenceKey] = opticalAttributesChange{}
		}
		points = append(points, internalgnmi.MappedPoint{
			Source: internalgnmi.Series{Target: target.config.Name, Origin: builtinGNMISyntheticReceiverOrigin, Elements: []internalgnmi.PathElem{{Name: "optics-presence", Keys: map[string]string{"id": presenceKey}}}, Leaf: "present"},
			Metric: builtinGNMIMetricMetadata["cisco.optics.present"], GaugeType: internalgnmi.GaugeInt,
			MetricType: internalgnmi.MetricGauge, IntValue: value, Attributes: attrs, Timestamp: timestamp,
		})
	}
	transaction.points = points

	beforeUsage := sharedGNMIAuxiliaryUsage{}
	afterUsage := sharedGNMIAuxiliaryUsage{}
	affectedSources := make(map[string]struct{}, len(transaction.sourceChanges))
	for sourceKey := range transaction.sourceChanges {
		affectedSources[sourceKey] = struct{}{}
	}
	if len(transaction.authoritativeAbsent) > 0 {
		for sourceKey, presenceKey := range target.opticalSources {
			if _, absent := transaction.authoritativeAbsent[presenceKey]; absent {
				affectedSources[sourceKey] = struct{}{}
			}
		}
	}
	for sourceKey := range affectedSources {
		if presenceKey, exists := target.opticalSources[sourceKey]; exists {
			beforeUsage.count++
			beforeUsage.bytes = addSharedGNMIAuxiliaryEstimate(
				beforeUsage.bytes,
				estimateSharedGNMIOpticalSourceBytes(sourceKey, presenceKey),
			)
		}
		presenceKey, exists := target.opticalSources[sourceKey]
		if change, changed := transaction.sourceChanges[sourceKey]; changed {
			presenceKey, exists = change.presenceKey, change.exists
		}
		if _, absent := transaction.authoritativeAbsent[presenceKey]; absent {
			exists = false
		}
		if exists {
			afterUsage.count++
			afterUsage.bytes = addSharedGNMIAuxiliaryEstimate(
				afterUsage.bytes,
				estimateSharedGNMIOpticalSourceBytes(sourceKey, presenceKey),
			)
		}
	}

	affectedPresence := make(map[string]struct{}, len(transaction.countChanges)+len(transaction.attributesChanges)+len(transaction.authoritativeAbsent))
	for presenceKey := range transaction.countChanges {
		affectedPresence[presenceKey] = struct{}{}
	}
	for presenceKey := range transaction.attributesChanges {
		affectedPresence[presenceKey] = struct{}{}
	}
	for presenceKey := range transaction.authoritativeAbsent {
		affectedPresence[presenceKey] = struct{}{}
	}
	for presenceKey := range affectedPresence {
		if _, exists := target.presenceCounts[presenceKey]; exists {
			beforeUsage.count++
			beforeUsage.bytes = addSharedGNMIAuxiliaryEstimate(
				beforeUsage.bytes,
				estimateSharedGNMIOpticalCountBytes(presenceKey),
			)
		}
		_, countExists := target.presenceCounts[presenceKey]
		if change, changed := transaction.countChanges[presenceKey]; changed {
			countExists = change.exists
		}
		if _, absent := transaction.authoritativeAbsent[presenceKey]; absent {
			countExists = false
		}
		if countExists {
			afterUsage.count++
			afterUsage.bytes = addSharedGNMIAuxiliaryEstimate(
				afterUsage.bytes,
				estimateSharedGNMIOpticalCountBytes(presenceKey),
			)
		}

		if attributes, exists := target.presenceAttrs[presenceKey]; exists {
			beforeUsage.count++
			beforeUsage.bytes = addSharedGNMIAuxiliaryEstimate(
				beforeUsage.bytes,
				estimateSharedGNMIOpticalAttributesBytes(presenceKey, attributes),
			)
		}
		attributes, attributesExist := target.presenceAttrs[presenceKey]
		if change, changed := transaction.attributesChanges[presenceKey]; changed {
			attributes, attributesExist = change.attributes, change.exists
		}
		if _, absent := transaction.authoritativeAbsent[presenceKey]; absent {
			attributesExist = false
		}
		if attributesExist {
			afterUsage.count++
			afterUsage.bytes = addSharedGNMIAuxiliaryEstimate(
				afterUsage.bytes,
				estimateSharedGNMIOpticalAttributesBytes(presenceKey, attributes),
			)
		}
	}
	target.presenceMu.Unlock()

	delta := sharedGNMIAuxiliaryUsageDelta(beforeUsage, afterUsage)
	transaction.budgetDelta = delta
	return transaction
}

func gnmiMappedPointIsPresent(point internalgnmi.MappedPoint) bool {
	if point.GaugeType == internalgnmi.GaugeDouble {
		return point.DoubleValue != 0
	}
	return point.IntValue != 0
}

func opticalPresenceIdentity(attributes map[string]string) (string, map[string]string) {
	name := attributes["network.interface.name"]
	if name == "" {
		return "", nil
	}
	attrs := map[string]string{"network.interface.name": name}
	for _, key := range []string{"cisco.optics.lane", "cisco.optics.profile", "cisco.optics.experimental"} {
		if value := attributes[key]; value != "" {
			attrs[key] = value
		}
	}
	return name + "\x00" + attrs["cisco.optics.lane"] + "\x00" + attrs["cisco.optics.profile"], attrs
}

func (target *sharedGNMITargetRuntime) normalizeNXNotification(notification internalgnmi.DecodedNotification) (internalgnmi.DecodedNotification, error) {
	target.deliveryMu.Lock()
	defer target.deliveryMu.Unlock()
	normalized, transaction, err := target.prepareNXNotification(notification)
	if err != nil {
		return notification, err
	}
	reservation, err := prepareSharedGNMIAuxiliaryReservation(target.nxBudget, transaction.budgetDelta)
	if err != nil {
		transaction.rollback()
		return notification, err
	}
	transaction.commit()
	reservation.commit()
	return normalized, nil
}

func (target *sharedGNMITargetRuntime) prepareNXNotification(
	notification internalgnmi.DecodedNotification,
) (internalgnmi.DecodedNotification, *nxSensorTransaction, error) {
	if err := preflightNXDMENormalization(notification); err != nil {
		return notification, nil, err
	}
	if err := normalizeAndValidateNXDMEPath("prefix", &notification.Prefix); err != nil {
		return notification, nil, err
	}
	for i := range notification.Deletes {
		if err := normalizeAndValidateNXDMEPath("delete", &notification.Deletes[i]); err != nil {
			return notification, nil, err
		}
	}
	for i := range notification.Updates {
		if err := normalizeAndValidateNXDMESeries(&notification.Updates[i].Series); err != nil {
			return notification, nil, err
		}
	}
	for i := range notification.Touched {
		if err := normalizeAndValidateNXDMEPath("touched path", &notification.Touched[i]); err != nil {
			return notification, nil, err
		}
	}
	staleMetadataUpdates := make([]bool, len(notification.Updates))
	staleQueryIndexes := make([]int, 0, len(notification.Updates))
	staleQueries := make([]internalgnmi.StaleQuery, 0, len(notification.Updates))
	for pointIndex := range notification.Updates {
		point := &notification.Updates[pointIndex]
		if point.Series.Origin != builtinGNMIOriginDME || point.Value.Kind != internalgnmi.ValueString {
			continue
		}
		switch normalizeGNMILeaf(point.Series.Leaf) {
		case "description", "descr", "sensor-description", "unit", "units", "sensor-unit":
			staleQueryIndexes = append(staleQueryIndexes, pointIndex)
			staleQueries = append(staleQueries, internalgnmi.StaleQuery{
				Path:      point.Series.Path(),
				Timestamp: point.Timestamp,
			})
		}
	}
	if len(staleQueries) > 0 {
		staleResults, err := target.cache.IsStaleBatch(staleQueries)
		if err != nil {
			return notification, nil, fmt.Errorf("check NX metadata cache state: %w", err)
		}
		for queryIndex, pointIndex := range staleQueryIndexes {
			staleMetadataUpdates[pointIndex] = staleResults[queryIndex]
		}
	}
	removeSelectors := make([]internalgnmi.Path, 0, len(notification.Deletes)+1)
	removeSelectorKeys := make(map[string]struct{}, len(notification.Deletes)+1)
	addRemoveSelector := func(selector internalgnmi.Path) {
		key := selector.Key()
		if _, exists := removeSelectorKeys[key]; exists {
			return
		}
		removeSelectorKeys[key] = struct{}{}
		removeSelectors = append(removeSelectors, selector)
	}
	// Match Cache.Prepare: the atomic bit represents snapshot replacement only
	// for an update/touched transaction (or an explicit empty snapshot), not a
	// delete-only notification. Otherwise NX auxiliary identity could erase
	// siblings that the mapped cache deliberately preserves.
	atomicSnapshot := notification.Atomic &&
		(len(notification.Updates) > 0 || len(notification.Touched) > 0 || len(notification.Deletes) == 0)
	if atomicSnapshot {
		addRemoveSelector(notification.Prefix)
	}
	for _, deleted := range notification.Deletes {
		addRemoveSelector(deleted)
	}

	target.nxMu.Lock()
	changes := map[string]nxSensorChange{}
	stagingExceeded := false
	getState := func(key string) (nxSensorState, bool) {
		if change, changed := changes[key]; changed {
			return change.state, change.exists
		}
		state, exists := target.nxSensors[key]
		return state, exists
	}
	maxInt := int(^uint(0) >> 1)
	stagingLimit := target.nxBudget.maximum
	if stagingLimit <= maxInt/2 {
		stagingLimit *= 2
	} else {
		stagingLimit = maxInt
	}
	if exceedsSharedGNMINXPlanningWork(target.nxSensors, stagingLimit, removeSelectors) {
		target.nxMu.Unlock()
		return notification, nil, fmt.Errorf(
			"NX auxiliary-state planning work exceeds %d comparisons",
			sharedGNMIMaxNXPlanningWork,
		)
	}
	setState := func(key string, state nxSensorState, exists bool) {
		if _, changed := changes[key]; !changed && len(changes) >= stagingLimit {
			stagingExceeded = true
			return
		}
		changes[key] = nxSensorChange{state: state, exists: exists}
	}
	removeStates := func(selector internalgnmi.Path, timestamp time.Time) {
		for key := range target.nxSensors {
			if stagingExceeded {
				return
			}
			state, exists := getState(key)
			if !exists {
				continue
			}
			if state.path.HasPrefix(selector) {
				if !state.descriptionTimestamp.After(timestamp) {
					state.description = ""
					state.descriptionTimestamp = timestamp
				}
				if !state.unitTimestamp.After(timestamp) {
					state.unit = ""
					state.unitTimestamp = timestamp
				}
				setState(key, state, state.description != "" || state.unit != "")
				continue
			}
			if !selector.HasPrefix(state.path) || len(selector.Elements) != len(state.path.Elements)+1 {
				continue
			}
			switch normalizeGNMILeaf(selector.Elements[len(selector.Elements)-1].Name) {
			case "description", "descr", "sensor-description":
				if !state.descriptionTimestamp.After(timestamp) {
					state.description = ""
					state.descriptionTimestamp = timestamp
				}
			case "unit", "units", "sensor-unit":
				if !state.unitTimestamp.After(timestamp) {
					state.unit = ""
					state.unitTimestamp = timestamp
				}
			default:
				continue
			}
			setState(key, state, state.description != "" || state.unit != "")
		}
	}
	for _, selector := range removeSelectors {
		if stagingExceeded {
			break
		}
		removeStates(selector, notification.Timestamp)
	}
	for pointIndex := range notification.Updates {
		point := &notification.Updates[pointIndex]
		if stagingExceeded {
			break
		}
		if point.Series.Origin != builtinGNMIOriginDME {
			continue
		}
		key := sharedGNMIParentSeriesKey(point.Series)
		state, exists := getState(key)
		if point.Value.Kind == internalgnmi.ValueString {
			changed := false
			switch normalizeGNMILeaf(point.Series.Leaf) {
			case "description", "descr", "sensor-description":
				if exists && point.Timestamp.Before(state.descriptionTimestamp) {
					continue
				}
				state.description = point.Value.String
				state.descriptionTimestamp = point.Timestamp
				changed = true
			case "unit", "units", "sensor-unit":
				if exists && point.Timestamp.Before(state.unitTimestamp) {
					continue
				}
				state.unit = point.Value.String
				state.unitTimestamp = point.Timestamp
				changed = true
			}
			if !changed {
				continue
			}
			if staleMetadataUpdates[pointIndex] {
				continue
			}
			state.path = (internalgnmi.Path{Target: point.Series.Target, Origin: point.Series.Origin, Elements: point.Series.Elements}).Clone()
			setState(key, state, true)
		}
	}
	if stagingExceeded {
		target.nxMu.Unlock()
		return notification, nil, &internalgnmi.CapacityError{Limit: stagingLimit, Current: len(changes), Requested: len(changes) + 1}
	}
	for i := range notification.Updates {
		point := &notification.Updates[i]
		if point.Series.Origin != builtinGNMIOriginDME {
			continue
		}
		leaf := normalizeGNMILeaf(point.Series.Leaf)
		if leaf != "value" && leaf != "current-value" && leaf != "reading" {
			continue
		}
		state, _ := getState(sharedGNMIParentSeriesKey(point.Series))
		if point.Timestamp.Before(state.descriptionTimestamp) || point.Timestamp.Before(state.unitTimestamp) {
			continue
		}
		definition, ok := normalizeNXOpticsSensor(state.description, state.unit)
		if !ok {
			continue
		}
		point.Series.Leaf = strings.TrimPrefix(definition.Metric.Name, "cisco.optics.")
		point.Series.Leaf = strings.ReplaceAll(point.Series.Leaf, "_", "-")
		point.Value = scaleGNMIValue(point.Value, definition.Scale)
	}
	beforeUsage := sharedGNMIAuxiliaryUsage{}
	afterUsage := sharedGNMIAuxiliaryUsage{}
	//nolint:gocritic // A map range cannot take a stable pointer to its value.
	for key, change := range changes {
		if existing, existed := target.nxSensors[key]; existed {
			beforeUsage.count++
			beforeUsage.bytes = addSharedGNMIAuxiliaryEstimate(
				beforeUsage.bytes,
				estimateSharedGNMINXSensorBytes(key, existing),
			)
		}
		if change.exists {
			afterUsage.count++
			afterUsage.bytes = addSharedGNMIAuxiliaryEstimate(
				afterUsage.bytes,
				estimateSharedGNMINXSensorBytes(key, change.state),
			)
		}
	}
	delta := sharedGNMIAuxiliaryUsageDelta(beforeUsage, afterUsage)
	transaction := &nxSensorTransaction{target: target, changes: changes, budgetDelta: delta}
	target.nxMu.Unlock()
	return notification, transaction, nil
}

// exceedsSharedGNMINXPlanningWork rejects selector/state cross-products before
// any retained-state scan. Each Path.HasPrefix pair is charged for every path
// element and key that both directional checks can visit. Delete planning can
// stage at most one change per retained sensor, so the worst-case retained
// work is charged twice even though staged delete keys are retained-key subsets
// and the current implementation does not traverse them separately.
func exceedsSharedGNMINXPlanningWork(
	states map[string]nxSensorState,
	stagingLimit int,
	selectors []internalgnmi.Path,
) bool {
	if len(states) == 0 || len(selectors) == 0 {
		return false
	}
	stateComplexity := 0
	for key := range states {
		additional := sharedGNMIPathMatchComplexity(states[key].path)
		if additional > sharedGNMIMaxNXPlanningWork-stateComplexity {
			return true
		}
		stateComplexity += additional
	}
	selectorComplexity := 0
	for index := range selectors {
		additional := sharedGNMIPathMatchComplexity(selectors[index])
		if additional > sharedGNMIMaxNXPlanningWork-selectorComplexity {
			return true
		}
		selectorComplexity += additional
	}
	work := 0
	addProduct := func(items, complexity int) bool {
		if items == 0 || complexity == 0 {
			return true
		}
		remaining := sharedGNMIMaxNXPlanningWork - work
		if complexity > remaining/items {
			return false
		}
		work += items * complexity
		return true
	}
	if !addProduct(len(states), selectorComplexity) || !addProduct(len(selectors), stateComplexity) {
		return true
	}
	if min(len(states), stagingLimit) == 0 {
		return false
	}
	return work > sharedGNMIMaxNXPlanningWork-work
}

func sharedGNMIPathMatchComplexity(path internalgnmi.Path) int {
	complexity := 2 // Target and origin checks.
	for index := range path.Elements {
		complexity += 1 + len(path.Elements[index].Keys)
	}
	return complexity
}

func scaleGNMIValue(value internalgnmi.Value, scale float64) internalgnmi.Value {
	if scale == 0 || scale == 1 {
		return value
	}
	switch value.Kind {
	case internalgnmi.ValueInt:
		return internalgnmi.DoubleValue(float64(value.Int) * scale)
	case internalgnmi.ValueUint:
		return internalgnmi.DoubleValue(float64(value.Uint) * scale)
	case internalgnmi.ValueDouble:
		return internalgnmi.DoubleValue(value.Double * scale)
	default:
		return value
	}
}

// preflightNXDMENormalization counts slash-packed DME expansions without
// allocating the expanded slices. It must run across the complete notification
// before any path is normalized so one bad path cannot leave partial work.
func preflightNXDMENormalization(notification internalgnmi.DecodedNotification) error {
	if notification.Prefix.Origin == builtinGNMIOriginDME {
		if err := validateNXDMEExpansion(notification.Prefix.Elements, sharedGNMIMaxPathElements); err != nil {
			return fmt.Errorf("normalize NX DME prefix: %w", err)
		}
	}
	for index := range notification.Deletes {
		if notification.Deletes[index].Origin != builtinGNMIOriginDME {
			continue
		}
		if err := validateNXDMEExpansion(notification.Deletes[index].Elements, sharedGNMIMaxPathElements); err != nil {
			return fmt.Errorf("normalize NX DME delete: %w", err)
		}
	}
	for index := range notification.Updates {
		if notification.Updates[index].Series.Origin != builtinGNMIOriginDME {
			continue
		}
		if err := validateNXDMEExpansion(notification.Updates[index].Series.Elements, sharedGNMIMaxSeriesElements); err != nil {
			return fmt.Errorf("normalize NX DME update: %w", err)
		}
	}
	for index := range notification.Touched {
		if notification.Touched[index].Origin != builtinGNMIOriginDME {
			continue
		}
		if err := validateNXDMEExpansion(notification.Touched[index].Elements, sharedGNMIMaxPathElements); err != nil {
			return fmt.Errorf("normalize NX DME touched path: %w", err)
		}
	}
	return nil
}

func validateNXDMEExpansion(elements []internalgnmi.PathElem, maximum int) error {
	expanded := 0
	for index := range elements {
		additional := countNormalizedNXDMEElement(elements[index].Name)
		if additional > maximum-expanded {
			return fmt.Errorf("path exceeds %d elements after slash-packed expansion", maximum)
		}
		expanded += additional
	}
	return nil
}

// countNormalizedNXDMEElement mirrors splitNXDMEElement's bracket-aware slash
// handling and lane/sensor expansion without constructing a parts slice.
func countNormalizedNXDMEElement(value string) int {
	if !strings.Contains(value, "/") {
		return normalizedNXDMEPartCount(value)
	}
	parts, start, depth := 0, 0, 0
	for index, char := range value {
		switch char {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case '/':
			if depth == 0 {
				if index > start {
					parts += normalizedNXDMEPartCount(value[start:index])
				}
				start = index + 1
			}
		}
	}
	if start < len(value) {
		parts += normalizedNXDMEPartCount(value[start:])
	}
	if parts == 0 {
		return normalizedNXDMEPartCount(value)
	}
	return parts
}

func normalizedNXDMEPartCount(value string) int {
	laneAndSensor, hasLane := strings.CutPrefix(value, "lane-")
	if !hasLane {
		return 1
	}
	lane, sensor, found := strings.Cut(laneAndSensor, "-sensor-")
	if found && lane != "" && sensor != "" {
		return 2
	}
	return 1
}

func normalizeAndValidateNXDMEPath(label string, path *internalgnmi.Path) error {
	if path.Origin != builtinGNMIOriginDME {
		return nil
	}
	path.Elements = normalizeNXDMEElements(path.Elements)
	if err := internalgnmi.ValidatePath(*path); err != nil {
		return fmt.Errorf("normalize NX DME %s: %w", label, err)
	}
	return nil
}

func normalizeAndValidateNXDMESeries(series *internalgnmi.Series) error {
	if series.Origin != builtinGNMIOriginDME {
		return nil
	}
	series.Elements = normalizeNXDMEElements(series.Elements)
	if err := internalgnmi.ValidateSeries(*series); err != nil {
		return fmt.Errorf("normalize NX DME update: %w", err)
	}
	return nil
}

func normalizeNXDMEElements(elements []internalgnmi.PathElem) []internalgnmi.PathElem {
	out := make([]internalgnmi.PathElem, 0, len(elements)+1)
	for _, element := range elements {
		parts := splitNXDMEElement(element.Name)
		for partIndex, name := range parts {
			if strings.HasPrefix(name, "phys-[") && strings.HasSuffix(name, "]") {
				out = append(out, internalgnmi.PathElem{Name: "phys", Keys: map[string]string{"id": strings.TrimSuffix(strings.TrimPrefix(name, "phys-["), "]")}})
				continue
			}
			if laneAndSensor, hasLane := strings.CutPrefix(name, "lane-"); hasLane {
				if lane, sensor, found := strings.Cut(laneAndSensor, "-sensor-"); found && lane != "" && sensor != "" {
					out = append(out,
						internalgnmi.PathElem{Name: "lane", Keys: map[string]string{"id": lane}},
						internalgnmi.PathElem{Name: "sensor", Keys: map[string]string{"id": sensor}},
					)
					continue
				}
			}
			keys := map[string]string(nil)
			if partIndex == len(parts)-1 {
				keys = element.Keys
			}
			out = append(out, internalgnmi.PathElem{Name: name, Keys: keys})
		}
	}
	return out
}

func splitNXDMEElement(value string) []string {
	if !strings.Contains(value, "/") {
		return []string{value}
	}
	parts := make([]string, 0, strings.Count(value, "/")+1)
	start, depth := 0, 0
	for index, char := range value {
		switch char {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case '/':
			if depth == 0 {
				if index > start {
					parts = append(parts, value[start:index])
				}
				start = index + 1
			}
		}
	}
	if start < len(value) {
		parts = append(parts, value[start:])
	}
	if len(parts) == 0 {
		return []string{value}
	}
	return parts
}

func normalizeGNMIStateValues(notification *internalgnmi.DecodedNotification) {
	for i := range notification.Updates {
		point := &notification.Updates[i]
		if point.Value.Kind != internalgnmi.ValueString {
			continue
		}
		switch normalizeGNMILeaf(point.Series.Leaf) {
		case "oper-status", "admin-status", "present", "is-joined":
			switch strings.ToLower(strings.TrimSpace(point.Value.String)) {
			case "up", "on", "true", "active", "enabled", "present", "joined", "ok":
				point.Value = internalgnmi.BoolValue(true)
			case "down", "off", "false", "inactive", "disabled", "absent", "not-present", "not joined", "failed":
				point.Value = internalgnmi.BoolValue(false)
			}
		}
	}
}

func normalizeGNMILeaf(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "_", "-"))
}

func classifySharedGNMIStreamError(err error) error {
	if err == nil {
		return nil
	}
	switch status.Code(err) {
	case codes.InvalidArgument, codes.Unimplemented:
		return &sharedGNMIUnsupportedError{err: err}
	default:
		return err
	}
}

func isSharedGNMIAuthenticationError(err error) bool {
	if err == nil {
		return false
	}
	switch status.Code(err) {
	case codes.Unauthenticated, codes.PermissionDenied:
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "authentication") || strings.Contains(message, "certificate") || strings.Contains(message, "unknown authority")
}

func sharedGNMIOutgoingContext(ctx context.Context, target GNMITargetConfig) context.Context {
	if target.Credentials.Mode != gnmiCredentialUsernamePassword && target.Credentials.Mode != gnmiCredentialMTLSUsernamePassword {
		return ctx
	}
	return grpcmetadata.AppendToOutgoingContext(ctx,
		"username", target.Credentials.Username,
		"password", string(target.Credentials.Password),
	)
}

func equalJitterGNMIBackoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	base := sharedGNMIInitialBackoff
	for range min(attempt, 8) {
		if base >= sharedGNMIMaximumBackoff/2 {
			base = sharedGNMIMaximumBackoff
			break
		}
		base *= 2
	}
	half := base / 2
	return half + time.Duration(rand.Int64N(int64(base-half)+1))
}

func waitSharedGNMIBackoff(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (target *sharedGNMITargetRuntime) isolatePath(path sharedGNMIPath) {
	target.stateMu.Lock()
	defer target.stateMu.Unlock()
	target.isolate[sharedGNMIPathKey(path)] = struct{}{}
}

func (target *sharedGNMITargetRuntime) stopProfile(profile string) {
	target.stateMu.Lock()
	defer target.stateMu.Unlock()
	target.stopped[profile] = struct{}{}
}

func (target *sharedGNMITargetRuntime) profileStopped(profile string) bool {
	target.stateMu.RLock()
	defer target.stateMu.RUnlock()
	_, stopped := target.stopped[profile]
	return stopped
}

func (target *sharedGNMITargetRuntime) pathIsolated(path sharedGNMIPath) bool {
	target.stateMu.RLock()
	defer target.stateMu.RUnlock()
	_, isolated := target.isolate[sharedGNMIPathKey(path)]
	return isolated
}

func (target *sharedGNMITargetRuntime) recordRejectedPathSet(key string) int {
	target.stateMu.Lock()
	defer target.stateMu.Unlock()
	target.rejects[key]++
	return target.rejects[key]
}

func (target *sharedGNMITargetRuntime) filterIsolated(paths []sharedGNMIPath) []sharedGNMIPath {
	target.stateMu.RLock()
	defer target.stateMu.RUnlock()
	out := make([]sharedGNMIPath, 0, len(paths))
	for _, path := range paths {
		if _, isolated := target.isolate[sharedGNMIPathKey(path)]; !isolated {
			out = append(out, path)
		}
	}
	return out
}

func sharedGNMIPathKey(path sharedGNMIPath) string { return path.Origin + "\x00" + path.Path }

func sharedGNMIRejectedPathSetKey(stream sharedGNMIRuntimeStream) string {
	var key strings.Builder
	key.WriteString(stream.Profile)
	key.WriteByte(0)
	key.WriteString(stream.Mode)
	for _, path := range stream.Paths {
		key.WriteByte(0)
		key.WriteString(sharedGNMIPathKey(path))
	}
	return key.String()
}

func runtimeSharedGNMIStreams(streams []sharedGNMIRuntimeStream) []sharedGNMIStream {
	out := make([]sharedGNMIStream, len(streams))
	for i := range streams {
		out[i] = streams[i].sharedGNMIStream
	}
	return out
}

func sharedGNMISourceKey(source internalgnmi.SourcePath) string {
	return source.Origin + "\x00" + strings.Join(source.Elements, "\x00") + "\x00" + source.Leaf
}

func sharedGNMISeriesSourceKey(series internalgnmi.Series) string {
	elements := make([]string, len(series.Elements))
	for i := range series.Elements {
		elements[i] = series.Elements[i].Name
	}
	return sharedGNMISourceKey(internalgnmi.SourcePath{Origin: series.Origin, Elements: elements, Leaf: series.Leaf})
}

func sharedGNMIParentSeriesKey(series internalgnmi.Series) string {
	return (internalgnmi.Path{Target: series.Target, Origin: series.Origin, Elements: series.Elements}).Key()
}

func cloneGNMIAttributes(attributes map[string]string) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	return maps.Clone(attributes)
}

func sharedGNMITargetIdentity(target GNMITargetConfig) deviceIdentity {
	host, _, err := net.SplitHostPort(target.Endpoint)
	if err != nil {
		host = target.Endpoint
	}
	return deviceIdentity{
		hostNames: []string{target.Name, host},
		hostIDs:   []string{target.Name, target.Endpoint, host},
		hostIPs:   []string{host},
		deviceIDs: []string{target.Name, target.Endpoint, host},
	}
}

var _ receiver.Metrics = (*sharedGNMIReceiver)(nil)
