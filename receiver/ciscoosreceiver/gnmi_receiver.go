// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"net"
	"slices"
	"strconv"
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
	"google.golang.org/protobuf/proto"

	internalgnmi "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmi"
	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

const (
	sharedGNMITransport              = "gnmi"
	sharedGNMIAuthenticationBackoff  = 5 * time.Minute
	sharedGNMIInitialBackoff         = 5 * time.Second
	sharedGNMIMaximumBackoff         = time.Minute
	sharedGNMIBackoffResetAfter      = time.Minute
	sharedGNMIDiagnosticProbeTimeout = 15 * time.Second
	sharedGNMIMaxBisectionProbes     = 64
	sharedGNMIMaxConcurrentDelivery  = 8
	sharedGNMIMaxNXPlanningWork      = 25_000_000
	sharedGNMIMaxPathElements        = 128
	sharedGNMIMaxSeriesElements      = sharedGNMIMaxPathElements - 1
	// One mapped NX optical series can retain one sensor identity plus one
	// optical source, presence count, and attribute-map entry.
	sharedGNMIAuxiliaryEntriesPerCachedSeries = 4
	// sharedGNMIAuxiliaryRetainedBytes is independent from the 1.5 GiB cache
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
	dialer            sharedGNMIDialer
}

// sharedGNMIClientConn is the small connection surface used by subscription
// execution. Keeping creation behind sharedGNMIDialer allows a future tunnel
// transport to provide its own net.Conn while leaving Capabilities and
// Subscribe lifecycle code unchanged.
type sharedGNMIClientConn interface {
	grpc.ClientConnInterface
	Close() error
}

type sharedGNMIDialer interface {
	DialTarget(
		context.Context,
		GNMITargetConfig,
		component.Host,
		receiver.Settings,
		*gnmiResponseAdmission,
		<-chan struct{},
	) (sharedGNMIClientConn, error)
}

type sharedGNMIDirectDialer struct{}

type sharedGNMITargetRuntime struct {
	config            GNMITargetConfig
	contract          *gnmiProductContract
	configuredVersion gnmiSoftwareVersion
	streams           []sharedGNMIRuntimeStream
	cache             *internalgnmi.Cache
	deliveryMu        sync.Mutex
	stateMu           sync.RWMutex
	isolate           map[string]struct{}
	stopped           map[string]struct{}
	rejects           map[string]int
	// updatesOnlyCacheOwners records physical cache scopes created by runtime
	// bisection until the next reconnect reset. Logical stream ownership remains
	// independent so one split group can still stop all of its siblings.
	updatesOnlyCacheOwners map[string]map[string]struct{}
	// cacheTopologies retains the last accepted physical owner grouping for each
	// logical stream across reconnects. deliveryMu serializes all mutations.
	cacheTopologies map[string]*sharedGNMICacheTopology

	identityMu            sync.RWMutex
	verifiedIdentity      verifiedGNMIIdentity
	qualificationMu       sync.Mutex
	pendingQualification  map[string]struct{}
	degradedQualification map[string]struct{}
	anyProgress           bool

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
	cacheOwnerID              string
	cacheTopologyOwners       []string
	registry                  *internalgnmi.Registry
	staticAttr                map[string]map[string]string
	responseSelectors         []internalgnmi.Path
	encoding                  gnmipb.Encoding
	baselineEncoding          gnmipb.Encoding
	baselineEncodingAvailable bool
}

type sharedGNMICacheTopology struct {
	current   []string
	candidate []string
	accepted  map[string]struct{}
	orphaned  map[string]struct{}
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

func (b *sharedGNMIAuxiliaryBudget) snapshot() (current, maximum sharedGNMIAuxiliaryUsage) {
	if b == nil {
		return sharedGNMIAuxiliaryUsage{}, sharedGNMIAuxiliaryUsage{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return sharedGNMIAuxiliaryUsage{count: b.used, bytes: b.usedBytes},
		sharedGNMIAuxiliaryUsage{count: b.maximum, bytes: b.maximumBytes}
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
	bytes = addSharedGNMIAuxiliaryEstimate(bytes, sharedGNMIAuxiliaryStringBytes(path.PathTarget))
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

var (
	errSharedGNMINotificationIgnored = errors.New("gNMI notification was ignored before qualification progress")
	errSharedGNMIStaleIgnored        = errors.New("out-of-order gNMI notification was ignored before qualification progress")
)

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
		dialer:            sharedGNMIDirectDialer{},
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
	contract, configuredVersion, err := gnmiProductContractForTarget(target)
	if err != nil {
		return nil, err
	}
	// Platform is decoder-only in public configuration. Populate the private
	// runtime copy exclusively from the verified product contract so legacy
	// OS-family selection can never influence behavior.
	target.Platform = contract.OSFamily
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
		config:                 target,
		contract:               contract,
		configuredVersion:      configuredVersion,
		cache:                  cache,
		isolate:                map[string]struct{}{},
		stopped:                map[string]struct{}{},
		rejects:                map[string]int{},
		updatesOnlyCacheOwners: map[string]map[string]struct{}{},
		cacheTopologies:        map[string]*sharedGNMICacheTopology{},
		nxBudget:               auxiliaryBudget,
		pendingQualification:   map[string]struct{}{},
		degradedQualification:  map[string]struct{}{},
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
		responseSelectors, err := sharedGNMIResponseSelectors(target.Name, stream.Paths)
		if err != nil {
			return nil, fmt.Errorf("profile %q response scope: %w", stream.Profile, err)
		}
		runtime.streams = append(runtime.streams, sharedGNMIRuntimeStream{
			sharedGNMIStream:  stream,
			cacheOwnerID:      stream.OwnerID,
			registry:          registry,
			staticAttr:        staticAttrs,
			responseSelectors: responseSelectors,
		})
		if stream.OwnerID != "" {
			if _, exists := runtime.cacheTopologies[stream.OwnerID]; !exists {
				runtime.cacheTopologies[stream.OwnerID] = &sharedGNMICacheTopology{current: []string{stream.OwnerID}}
			}
		}
	}
	runtime.resetSessionQualification()
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
		// Product verification is session-scoped. Clear the gauge as soon as the
		// session ends instead of leaving a stale 1 throughout reconnect backoff.
		r.telemetry.productVerified(ctx, target.config.Name, false)
		var compatibility *sharedGNMICompatibilityError
		if errors.As(err, &compatibility) {
			target.setVerifiedIdentity(verifiedGNMIIdentity{})
			r.telemetry.connection(ctx, target.config.Name, false)
			r.telemetry.productVerified(ctx, target.config.Name, false)
			r.telemetry.preflightFailure(ctx, target.config.Name, compatibility.reason)
			r.emitAvailability(ctx, target, false)
			r.settings.Logger.Error("Cisco gNMI target quarantined until receiver restart",
				zap.String("target", target.config.Name),
				zap.String("endpoint", target.config.Endpoint),
				zap.String("reason", compatibility.reason),
				zap.Error(compatibility))
			return
		}
		authenticationFailure := isSharedGNMIAuthenticationError(err)
		err = sanitizedGNMIRPCError(err)
		r.telemetry.connection(ctx, target.config.Name, false)
		if resetBackoff {
			attempt = 0
		}
		if terminal || ctx.Err() != nil {
			return
		}
		r.emitAvailability(ctx, target, false)
		delay := equalJitterGNMIBackoff(attempt)
		if authenticationFailure {
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
	target.resetSessionQualification()
	r.telemetry.productVerified(ctx, target.config.Name, false)
	if target.config.Platform == gnmiPlatformNXOS {
		// DME description/unit identity is scoped to a device session. Preserve
		// mapped cache and tombstones, but require fresh sensor identity before
		// values from a reconnected session can be mapped.
		r.clearTargetNXSensorState(ctx, target)
		defer r.clearTargetNXSensorState(ctx, target)
	}
	conn, err := r.dialTarget(ctx, target.config)
	if err != nil {
		return false, false, err
	}
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	capCtx, cancel := context.WithTimeout(sharedGNMIOutgoingContext(ctx, target.config), target.config.CapabilitiesTimeout)
	capabilities, err := invokeGNMICapabilities(capCtx, conn, r.responseAdmission, target.config.MaxRecvMsgSizeMiB)
	cancel()
	if err != nil {
		// Authentication failures are operational and must keep the target on the
		// bounded retry path even when a server reports them with a status code
		// (such as InvalidArgument) that otherwise denotes an incompatible RPC.
		// Check the preserved classification before applying deterministic
		// compatibility policy.
		if isSharedGNMIAuthenticationError(err) {
			return false, false, fmt.Errorf("capabilities: %w", err)
		}
		if deterministicGNMIIdentityRPCError(err) {
			compatibilityErr := sanitizedGNMIRPCError(err)
			if localGNMIResponsePreflightRejected(err) {
				compatibilityErr = errors.New("gNMI response preflight rejected the Capabilities response")
			}
			return false, false, newSharedGNMICompatibilityError(
				gnmiPreflightUnsupportedEncoding,
				fmt.Errorf("Capabilities cannot establish the product-approved encoding contract: %w", compatibilityErr),
			)
		}
		return false, false, fmt.Errorf("capabilities: %w", err)
	}
	if validationErr := validateGNMIProtocolVersion(target.contract, capabilities); validationErr != nil {
		r.responseAdmission.release(capabilities)
		return false, false, validationErr
	}
	identityEncoding, identityEncodingAvailable := sharedGNMIIdentityEncoding(target.contract, capabilities)
	if !identityEncodingAvailable {
		r.responseAdmission.release(capabilities)
		return false, false, newSharedGNMICompatibilityError(
			gnmiPreflightUnsupportedEncoding,
			fmt.Errorf("target advertises no encoding approved for product %q", target.contract.Product),
		)
	}
	if encodingErr := r.configureSharedGNMIStreamEncodings(target, capabilities); encodingErr != nil {
		r.responseAdmission.release(capabilities)
		return false, false, encodingErr
	}
	if validationErr := validateGNMIRequiredModels(target.contract, runtimeSharedGNMIStreams(target.streams), capabilities); validationErr != nil {
		r.responseAdmission.release(capabilities)
		return false, false, validationErr
	}
	r.responseAdmission.release(capabilities)
	verified, err := runGNMIIdentityPreflight(
		ctx,
		conn,
		r.responseAdmission,
		target.config,
		target.contract,
		target.configuredVersion,
		identityEncoding,
	)
	if err != nil {
		return false, false, err
	}
	target.setVerifiedIdentity(verified)
	if resetErr := r.resetUpdatesOnlyOwners(ctx, target); resetErr != nil {
		return false, false, resetErr
	}
	r.telemetry.productVerified(ctx, target.config.Name, true)
	r.telemetry.connection(ctx, target.config.Name, true)
	connectedAt := time.Now()
	terminal, err := r.serveTargetStreams(ctx, target, gnmipb.NewGNMIClient(conn))
	resetBackoff := terminal || time.Since(connectedAt) >= sharedGNMIBackoffResetAfter
	if err == nil && !terminal {
		return false, resetBackoff, io.ErrUnexpectedEOF
	}
	return terminal, resetBackoff, err
}

func sharedGNMIIdentityEncoding(
	contract *gnmiProductContract,
	capabilities *gnmipb.CapabilityResponse,
) (gnmipb.Encoding, bool) {
	if capabilities == nil {
		return gnmipb.Encoding_JSON, false
	}
	supported := make(map[gnmipb.Encoding]struct{}, len(capabilities.GetSupportedEncodings()))
	for _, encoding := range capabilities.GetSupportedEncodings() {
		supported[encoding] = struct{}{}
	}
	if contract == nil {
		return gnmipb.Encoding_JSON, false
	}
	for _, encoding := range contract.ApprovedEncodings {
		if _, ok := supported[encoding]; ok {
			return encoding, true
		}
	}
	return gnmipb.Encoding_JSON, false
}

func (*sharedGNMIReceiver) configureSharedGNMIStreamEncodings(
	target *sharedGNMITargetRuntime,
	capabilities *gnmipb.CapabilityResponse,
) error {
	target.stateMu.Lock()
	defer target.stateMu.Unlock()
	for i := range target.streams {
		stream := &target.streams[i]
		encoding, err := negotiateSharedGNMIStreamEncoding(target.config, capabilities, stream.sharedGNMIStream)
		if err != nil {
			return newSharedGNMICompatibilityError(
				gnmiPreflightUnsupportedEncoding,
				fmt.Errorf("stream %q has no product-approved advertised encoding: %w", stream.Profile, err),
			)
		}
		stream.encoding = encoding
		stream.baselineEncoding, stream.baselineEncodingAvailable = sharedGNMIBaselineEncoding(target.contract, capabilities)
	}
	return nil
}

func sharedGNMIBaselineEncoding(
	contract *gnmiProductContract,
	capabilities *gnmipb.CapabilityResponse,
) (gnmipb.Encoding, bool) {
	if contract == nil || capabilities == nil {
		return gnmipb.Encoding_JSON, false
	}
	supported := make(map[gnmipb.Encoding]struct{}, len(capabilities.GetSupportedEncodings()))
	for _, encoding := range capabilities.GetSupportedEncodings() {
		supported[encoding] = struct{}{}
	}
	for _, encoding := range contract.ApprovedEncodings {
		if _, ok := supported[encoding]; ok {
			return encoding, true
		}
	}
	return gnmipb.Encoding_JSON, false
}

func (r *sharedGNMIReceiver) resetUpdatesOnlyOwners(ctx context.Context, target *sharedGNMITargetRuntime) error {
	if target == nil || target.cache == nil {
		return errors.New("shared gNMI target cache is not initialized")
	}
	target.deliveryMu.Lock()
	defer target.deliveryMu.Unlock()
	seen := make(map[string]struct{}, len(target.streams))
	for i := range target.streams {
		stream := target.streams[i]
		if !stream.UpdatesOnly || target.streamStopped(stream) {
			continue
		}
		if _, duplicate := seen[stream.OwnerID]; duplicate {
			continue
		}
		seen[stream.OwnerID] = struct{}{}

		if err := r.resetCacheOwnersLocked(target, stream, target.cacheOwnerIDsForLogicalStream(stream.OwnerID)); err != nil {
			return fmt.Errorf("reset updates-only owner for stream %q: %w", stream.Profile, err)
		}
		target.clearPhysicalCacheOwners(stream.OwnerID)
		r.telemetry.cacheOwnerReset(ctx, target.config.Name, stream.Profile)
	}
	r.recordTargetStateUtilization(ctx, target)
	return nil
}

// resetCacheOwnersLocked silently removes complete cache-owner scopes. The
// caller holds deliveryMu so cache state, NX-derived metadata, and optical
// presence reconciliation cross one serialized publication boundary.
func (*sharedGNMIReceiver) resetCacheOwnersLocked(
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
	ownerIDs []string,
) error {
	for _, cacheOwnerID := range sharedGNMICanonicalCacheTopology(ownerIDs) {
		prepareReset := target.cache.PrepareResetOwner
		if stream.Optics {
			prepareReset = target.cache.PrepareResetOwnerForReconciliation
		}
		cacheReset, err := prepareReset(cacheOwnerID)
		if err != nil {
			return err
		}
		result := cacheReset.Result()
		var presence *opticalPresenceTransaction
		var reservation *sharedGNMIAuxiliaryReservation
		if stream.Optics && len(result.Removed) > 0 {
			presence = target.prepareOpticalPresence(internalgnmi.CacheResult{Removed: result.Removed}, time.Now())
			reservation, err = prepareSharedGNMIAuxiliaryReservation(target.nxBudget, presence.budgetDelta)
			if err != nil {
				presence.rollback()
				cacheReset.Rollback()
				return err
			}
		}
		cacheReset.Commit()
		if presence != nil {
			presence.commit()
			reservation.commit()
		}
	}
	return nil
}

func (r *sharedGNMIReceiver) dialTarget(ctx context.Context, target GNMITargetConfig) (sharedGNMIClientConn, error) {
	dialer := r.dialer
	if dialer == nil {
		dialer = sharedGNMIDirectDialer{}
	}
	return dialer.DialTarget(ctx, target, r.host, r.settings, r.responseAdmission, ctx.Done())
}

func (sharedGNMIDirectDialer) DialTarget(
	ctx context.Context,
	target GNMITargetConfig,
	host component.Host,
	settings receiver.Settings,
	responseAdmission *gnmiResponseAdmission,
	shutdown <-chan struct{},
) (sharedGNMIClientConn, error) {
	if host == nil {
		return nil, errors.New("shared gNMI host is not initialized")
	}
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
		InsecureSkipVerify: target.TLS.InsecureSkipVerify,
		ServerName:         target.TLS.ServerNameOverride,
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
		host.GetExtensions(),
		settings.TelemetrySettings,
		configgrpc.WithGrpcDialOption(grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(target.MaxRecvMsgSizeMiB*1024*1024),
			gnmiResponsePreflightCallOption(target.MaxRecvMsgSizeMiB, responseAdmission, shutdown),
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
			return nil, fmt.Errorf("gNMI connection shut down before becoming ready; %s", sharedGNMIConnectionHint(target))
		}
		if !conn.WaitForStateChange(dialCtx, state) {
			_ = conn.Close()
			return nil, fmt.Errorf("gNMI connection did not become ready before connect_timeout; %s: %w", sharedGNMIConnectionHint(target), dialCtx.Err())
		}
	}
}

func sharedGNMIConnectionHint(target GNMITargetConfig) string {
	if target.TLS.InsecureSkipVerify {
		return "verify endpoint reachability, gNMI service availability, and the configured TLS minimum version"
	}
	return "verify endpoint reachability and certificate trust via tls.ca_file and tls.server_name_override; for an isolated lab with a self-signed certificate, set tls.insecure_skip_verify: true"
}

func (r *sharedGNMIReceiver) serveTargetStreams(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	client gnmipb.GNMIClient,
) (bool, error) {
	target.beginCacheTopologySession()
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan sharedGNMIStreamResult, 32)
	semaphore := make(chan struct{}, target.config.MaxStreams)
	streamCancels := map[string][]context.CancelFunc{}
	var wg sync.WaitGroup
	active := 0
	launch := func(stream sharedGNMIRuntimeStream) {
		if target.streamStopped(stream) {
			return
		}
		stream.Paths = target.filterIsolated(stream.Paths)
		if len(stream.Paths) == 0 {
			return
		}
		target.registerPhysicalCacheOwner(stream)
		responseSelectors, selectorErr := sharedGNMIResponseSelectors(target.config.Name, stream.Paths)
		if selectorErr != nil {
			active++
			wg.Go(func() {
				results <- sharedGNMIStreamResult{
					stream: stream,
					err:    fmt.Errorf("build filtered response scope for stream %q: %w", stream.Profile, selectorErr),
				}
			})
			return
		}
		stream.responseSelectors = responseSelectors
		subscriptionCtx, subscriptionCancel := context.WithCancel(streamCtx)
		streamKey := sharedGNMIRuntimeStreamKey(stream)
		streamCancels[streamKey] = append(streamCancels[streamKey], subscriptionCancel)
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
			terminal, err := r.runSubscription(subscriptionCtx, target, client, stream, stream.encoding)
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
			if target.streamStopped(result.stream) {
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
				probeStream := result.stream
				probeEncoding := result.stream.encoding
				restoreOriginalOptions := false
				if sharedGNMIStreamHasNonBaselineRequest(result.stream.sharedGNMIStream, result.stream.encoding) {
					if !result.stream.baselineEncodingAvailable {
						<-semaphore
						r.stopGNMIProfile(ctx, target, result.stream, "unsupported_request_options", errors.New(
							"target rejected configured request options and advertises no JSON baseline encoding",
						), streamCancels)
						continue
					}
					probeStream = sharedGNMIBaselineRuntimeStream(result.stream)
					probeEncoding = result.stream.baselineEncoding
					probeErr := r.probeSubscriptionUntilSync(streamCtx, target, client, probeStream, probeEncoding)
					if probeErr == nil {
						<-semaphore
						r.stopGNMIProfile(ctx, target, result.stream, "unsupported_request_options", unsupported, streamCancels)
						continue
					}
					var baselineUnsupported *sharedGNMIUnsupportedError
					if !errors.As(probeErr, &baselineUnsupported) {
						<-semaphore
						cancel()
						wg.Wait()
						return false, probeErr
					}
					restoreOriginalOptions = true
				}
				validGroups, resolutionErr := r.resolveUnsupportedGNMIPaths(streamCtx, target, client, probeStream, probeEncoding)
				<-semaphore
				if resolutionErr != nil {
					var stopped *sharedGNMIProfileStopError
					if errors.As(resolutionErr, &stopped) {
						r.stopGNMIProfile(ctx, target, result.stream, "bisection_limit", stopped, streamCancels)
						continue
					}
					cancel()
					wg.Wait()
					return false, resolutionErr
				}
				if restoreOriginalOptions {
					validGroups = sharedGNMIRestoreOriginalPathGroups(result.stream.Paths, validGroups)
				}
				if len(validGroups) > 1 {
					if active+len(validGroups) > target.config.MaxStreams {
						r.stopGNMIProfile(ctx, target, result.stream, "incompatible_path_group", fmt.Errorf(
							"the target accepts %d path groups separately, but they would require %d of %d allowed streams",
							len(validGroups), active+len(validGroups), target.config.MaxStreams,
						), streamCancels)
						continue
					}
				}
				if len(validGroups) == 0 {
					continue
				}
				target.replacePendingQualificationStream(result.stream, validGroups)
				validatedStreams := sharedGNMIResolvedRuntimeStreams(result.stream, validGroups)
				for streamIndex := range validatedStreams {
					launch(validatedStreams[streamIndex])
				}
				continue
			}
			var stopped *sharedGNMIProfileStopError
			if errors.As(result.err, &stopped) {
				r.stopGNMIProfile(ctx, target, result.stream, "cache_limit", stopped, streamCancels)
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

func sharedGNMIStreamHasNonBaselineRequest(stream sharedGNMIStream, encoding gnmipb.Encoding) bool {
	if encoding == gnmipb.Encoding_PROTO || stream.UpdatesOnly || stream.AllowAggregation ||
		stream.QoSMarking != nil || stream.GNMIExtensions.Depth != nil {
		return true
	}
	if stream.Mode != gnmiModeStream {
		return false
	}
	for i := range stream.Paths {
		path := &stream.Paths[i]
		if path.StreamMode != "" && path.StreamMode != gnmiStreamModeSample {
			return true
		}
		if path.SampleInterval != nil || path.HeartbeatInterval != nil || path.SuppressRedundant != nil {
			return true
		}
	}
	return false
}

func sharedGNMIBaselineRuntimeStream(stream sharedGNMIRuntimeStream) sharedGNMIRuntimeStream {
	baseline := stream
	baseline.UpdatesOnly = false
	baseline.AllowAggregation = false
	baseline.QoSMarking = nil
	baseline.GNMIExtensions = GNMIExtensionsConfig{}
	baseline.Paths = append([]sharedGNMIPath(nil), stream.Paths...)
	for i := range baseline.Paths {
		baseline.Paths[i].StreamMode = ""
		baseline.Paths[i].SampleInterval = nil
		baseline.Paths[i].HeartbeatInterval = nil
		baseline.Paths[i].SuppressRedundant = nil
	}
	baseline.encoding = stream.baselineEncoding
	return baseline
}

func sharedGNMIRestoreOriginalPathGroups(
	original []sharedGNMIPath,
	groups [][]sharedGNMIPath,
) [][]sharedGNMIPath {
	byKey := make(map[string]sharedGNMIPath, len(original))
	for i := range original {
		byKey[sharedGNMIPathKey(original[i])] = original[i]
	}
	restored := make([][]sharedGNMIPath, 0, len(groups))
	for _, group := range groups {
		paths := make([]sharedGNMIPath, 0, len(group))
		for i := range group {
			if configured, ok := byKey[sharedGNMIPathKey(group[i])]; ok {
				paths = append(paths, configured)
			}
		}
		if len(paths) > 0 {
			restored = append(restored, paths)
		}
	}
	return restored
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
	rejectionKey, err := sharedGNMIRejectedRequestKey(target.config, stream, encoding)
	if err != nil {
		return nil, err
	}
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
			target.markQualificationDegraded(stream)
			r.emitTargetUnavailable(ctx, target)
			if !stream.Required {
				target.recordOptionalStreamStopped(stream)
			}
			r.telemetry.degraded(ctx, target.config.Name, stream.Profile, "unsupported_path", true)
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
	probeTimeout := target.config.CapabilitiesTimeout
	if probeTimeout <= 0 || probeTimeout > sharedGNMIDiagnosticProbeTimeout {
		probeTimeout = sharedGNMIDiagnosticProbeTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	r.telemetry.subscription(probeCtx, target.config.Name, stream.Profile, true)
	defer r.telemetry.subscription(context.Background(), target.config.Name, stream.Profile, false)
	request, err := buildSharedGNMISubscribeRequest(target.config, stream.sharedGNMIStream, encoding)
	if err != nil {
		return err
	}
	stream.responseSelectors, err = sharedGNMIResponseSelectors(target.config.Name, stream.Paths)
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
		return receiveSharedGNMIProbeOnce(subscribe, r.responseAdmission, target, stream)
	}
	if err := receiveSharedGNMIProbeUntilSync(subscribe, r.responseAdmission, target, stream); err != nil {
		return err
	}
	if stream.Mode != gnmiModePoll {
		return nil
	}
	if err := subscribe.Send(&gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Poll{Poll: &gnmipb.Poll{}}}); err != nil {
		return classifySharedGNMIStreamError(err)
	}
	return receiveSharedGNMIProbeUntilSync(subscribe, r.responseAdmission, target, stream)
}

//nolint:staticcheck // Deprecated in-band Error responses remain on the supported gNMI wire protocol.
func receiveSharedGNMIProbeUntilSync(
	subscribe grpc.BidiStreamingClient[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse],
	admission *gnmiResponseAdmission,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
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
		case *gnmipb.SubscribeResponse_Update:
			responseErr = validateSharedGNMIProbeUpdate(target, stream, body.Update)
		case *gnmipb.SubscribeResponse_SyncResponse:
			if !body.SyncResponse {
				responseErr = malformedSharedGNMIProbeResponse()
			} else {
				synced = true
			}
		case *gnmipb.SubscribeResponse_Error:
			if body.Error == nil {
				responseErr = malformedSharedGNMIProbeResponse()
			} else {
				responseErr = classifySharedGNMIStreamError(sanitizedGNMISubscribeStatusError(body.Error))
			}
		default:
			responseErr = malformedSharedGNMIProbeResponse()
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
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
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
		case *gnmipb.SubscribeResponse_Update:
			responseErr = validateSharedGNMIProbeUpdate(target, stream, body.Update)
		case *gnmipb.SubscribeResponse_SyncResponse:
			if !body.SyncResponse {
				responseErr = malformedSharedGNMIProbeResponse()
			} else {
				synced = true
			}
		case *gnmipb.SubscribeResponse_Error:
			if body.Error == nil {
				responseErr = malformedSharedGNMIProbeResponse()
			} else {
				responseErr = classifySharedGNMIStreamError(sanitizedGNMISubscribeStatusError(body.Error))
			}
		default:
			responseErr = malformedSharedGNMIProbeResponse()
		}
		admission.release(response)
		if responseErr != nil {
			return responseErr
		}
	}
}

func malformedSharedGNMIProbeResponse() error {
	return &sharedGNMIUnsupportedError{err: errors.New("gNMI diagnostic probe returned a malformed response")}
}

func validateSharedGNMIProbeUpdate(
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
	notification *gnmipb.Notification,
) error {
	if target == nil || notification == nil {
		return &sharedGNMIUnsupportedError{err: errors.New("gNMI diagnostic probe returned an empty update")}
	}
	var err error
	if target.contract != nil && target.contract.CanonicalizeJSONIETFPathKeys && stream.encoding == gnmipb.Encoding_JSON_IETF {
		err = canonicalizeIOSXERFC7951JSONIETFWireNotificationKeys(notification)
	}
	var decoded internalgnmi.DecodedNotification
	if err == nil {
		decoded, _, err = internalgnmi.DecodeNotificationWithRegistry(target.config.Name, notification, time.Now(), stream.registry)
	}
	if err == nil && target.config.Platform == gnmiPlatformNXOS && stream.Optics {
		err = normalizeNXNotificationPaths(&decoded)
	}
	if err == nil {
		err = validateSharedGNMIResponseScope(stream.responseSelectors, decoded)
	}
	if err != nil {
		return &sharedGNMIUnsupportedError{err: errors.New("gNMI diagnostic probe returned malformed or out-of-scope state")}
	}
	return nil
}

func (r *sharedGNMIReceiver) stopGNMIProfile(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
	reason string,
	err error,
	streamCancels map[string][]context.CancelFunc,
) {
	target.stopStream(stream)
	target.markQualificationDegraded(stream)
	r.emitTargetUnavailable(ctx, target)
	if !stream.Required {
		target.recordOptionalStreamStopped(stream)
	}
	for _, streamCancel := range streamCancels[sharedGNMIRuntimeStreamKey(stream)] {
		streamCancel()
	}
	if target.config.Platform == gnmiPlatformNXOS && stream.Optics {
		r.clearTargetNXSensorState(ctx, target)
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
			r.markSharedGNMIStreamMalformed(ctx, target, stream)
			return false, nil
		}
		if target.streamStopped(stream) {
			return false, nil
		}
		if err := r.processNotification(ctx, target, stream, body.Update); err != nil {
			if errors.Is(err, errSharedGNMINotificationIgnored) {
				r.markSharedGNMIStreamMalformed(ctx, target, stream)
				return false, nil
			}
			if errors.Is(err, errSharedGNMIStaleIgnored) {
				return false, nil
			}
			return false, err
		}
		if target.streamStopped(stream) {
			return false, nil
		}
		if err := r.reconcileCacheTopology(ctx, target, stream); err != nil {
			return false, err
		}
		target.recordStreamProgress(stream)
		r.emitTargetAvailable(ctx, target)
		return false, nil
	case *gnmipb.SubscribeResponse_SyncResponse:
		if !body.SyncResponse {
			r.markSharedGNMIStreamMalformed(ctx, target, stream)
			return false, nil
		}
		if err := r.reconcileCacheTopology(ctx, target, stream); err != nil {
			return false, err
		}
		target.recordStreamProgress(stream)
		r.emitTargetAvailable(ctx, target)
		return true, nil
	case *gnmipb.SubscribeResponse_Error:
		if body.Error == nil {
			r.markSharedGNMIStreamMalformed(ctx, target, stream)
			return false, nil
		}
		return false, classifySharedGNMIStreamError(sanitizedGNMISubscribeStatusError(body.Error))
	default:
		r.markSharedGNMIStreamMalformed(ctx, target, stream)
		return false, nil
	}
}

func (r *sharedGNMIReceiver) markSharedGNMIStreamMalformed(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
) {
	if target == nil {
		return
	}
	target.markQualificationDegraded(stream)
	r.emitTargetUnavailable(ctx, target)
	r.telemetry.degraded(ctx, target.config.Name, stream.Profile, "malformed_update", true)
}

func (r *sharedGNMIReceiver) processNotification(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
	notification *gnmipb.Notification,
) error {
	target.deliveryMu.Lock()
	defer target.deliveryMu.Unlock()
	if target.streamStopped(stream) {
		return nil
	}
	if err := r.acquireNotificationSlot(ctx); err != nil {
		return err
	}
	defer r.releaseNotificationSlot()
	if target.streamStopped(stream) {
		return nil
	}
	receiptTime := time.Now()
	if target.contract != nil && target.contract.CanonicalizeJSONIETFPathKeys && stream.encoding == gnmipb.Encoding_JSON_IETF {
		if err := canonicalizeIOSXERFC7951JSONIETFWireNotificationKeys(notification); err != nil {
			r.telemetry.decodeErrors(ctx, target.config.Name, stream.Profile, 1)
			return errSharedGNMINotificationIgnored
		}
	}
	decoded, decodeStats, err := internalgnmi.DecodeNotificationWithRegistry(target.config.Name, notification, receiptTime, stream.registry)
	if err != nil {
		r.telemetry.decodeErrors(ctx, target.config.Name, stream.Profile, 1)
		return errSharedGNMINotificationIgnored
	}
	r.telemetry.invalidTimestamps(ctx, target.config.Name, stream.Profile, decodeStats.InvalidTimestamps)
	if decodeStats.InvalidTimestamps > 0 {
		// Receipt-time fallback is useful to keep decoding bounded, but it must
		// never enter cache freshness ordering: a delayed malformed notification
		// could otherwise overwrite valid device-time state.
		r.telemetry.decodeErrors(ctx, target.config.Name, stream.Profile, 1)
		return errSharedGNMINotificationIgnored
	}
	var nxTransaction *nxSensorTransaction
	if target.config.Platform == gnmiPlatformNXOS && stream.Optics {
		decoded, nxTransaction, err = target.prepareNXNotificationForOwner(sharedGNMICacheOwnerID(stream), decoded)
		if err != nil {
			return &sharedGNMIProfileStopError{err: err}
		}
		defer func() {
			if nxTransaction != nil {
				nxTransaction.rollback()
			}
		}()
	}
	if scopeErr := validateSharedGNMIResponseScope(stream.responseSelectors, decoded); scopeErr != nil {
		r.telemetry.decodeErrors(ctx, target.config.Name, stream.Profile, 1)
		return errSharedGNMINotificationIgnored
	}
	invalidatedPaths, malformedStatePath := normalizeGNMIStateValuesChecked(&decoded)
	if malformedStatePath && !decoded.Atomic {
		r.telemetry.decodeErrors(ctx, target.config.Name, stream.Profile, 1)
		return errSharedGNMINotificationIgnored
	}
	r.telemetry.updates(ctx, target.config.Name, stream.Profile, len(decoded.Updates))
	for kind, count := range decodeStats.UnsupportedValueKinds {
		r.telemetry.unsupportedValueKind(ctx, target.config.Name, stream.Profile, string(kind), count)
	}
	r.telemetry.deletes(ctx, target.config.Name, stream.Profile, len(decoded.Deletes))

	cacheNotification := internalgnmi.CacheNotification{
		OwnerID: sharedGNMICacheOwnerID(stream),
		Prefix:  decoded.Prefix, Timestamp: decoded.Timestamp, Atomic: decoded.Atomic, Deletes: decoded.Deletes,
	}
	for _, invalidated := range invalidatedPaths {
		cacheNotification.Invalidates = append(cacheNotification.Invalidates, invalidated.Clone())
	}
	for _, touched := range decoded.Touched {
		cacheNotification.Touched = append(cacheNotification.Touched, touched.Clone())
	}
	unmapped := decodeStats.UnmappedValues
	semanticInvalidatedPaths := make(map[string]struct{}, len(invalidatedPaths))
	for _, invalidated := range invalidatedPaths {
		semanticInvalidatedPaths[invalidated.Key()] = struct{}{}
	}
	semanticInvalidValues := len(semanticInvalidatedPaths)
	if malformedStatePath {
		semanticInvalidValues++
	}
	for pathIndex := range decoded.Undecodable {
		undecodable := decoded.Undecodable[pathIndex]
		series, splitErr := undecodable.SplitLeaf()
		if splitErr != nil {
			continue
		}
		_, status := stream.registry.MapWithStatus(internalgnmi.Point{Series: series})
		switch status {
		case internalgnmi.MappingInvalidValue:
			if _, exists := semanticInvalidatedPaths[undecodable.Key()]; !exists {
				cacheNotification.Invalidates = append(cacheNotification.Invalidates, undecodable.Clone())
				semanticInvalidatedPaths[undecodable.Key()] = struct{}{}
				semanticInvalidValues++
			}
		case internalgnmi.MappingInvalidIdentity:
			semanticInvalidValues++
		}
	}
	for pointIndex := range decoded.Updates {
		point := &decoded.Updates[pointIndex]
		mapped, status := stream.registry.MapWithStatus(*point)
		if status != internalgnmi.MappingMapped {
			if !stream.HealthOnly {
				unmapped++
			}
			switch status {
			case internalgnmi.MappingInvalidValue:
				invalidated := point.Series.Path()
				if _, exists := semanticInvalidatedPaths[invalidated.Key()]; !exists {
					cacheNotification.Invalidates = append(cacheNotification.Invalidates, invalidated)
					semanticInvalidatedPaths[invalidated.Key()] = struct{}{}
					semanticInvalidValues++
				}
			case internalgnmi.MappingInvalidIdentity:
				semanticInvalidValues++
			}
			continue
		}
		maps.Copy(mapped.Attributes, stream.staticAttr[sharedGNMISeriesSourceKey(point.Series)])
		cacheNotification.Updates = append(cacheNotification.Updates, mapped)
	}
	r.telemetry.unmapped(ctx, target.config.Name, stream.Profile, unmapped)
	semanticRejected := semanticInvalidValues > 0
	if semanticRejected {
		r.telemetry.decodeErrors(ctx, target.config.Name, stream.Profile, semanticInvalidValues)
	}
	atomicSemanticInvalid := decoded.Atomic && semanticInvalidValues > 0
	if atomicSemanticInvalid {
		// An atomic notification is all-or-nothing. Withdraw the complete
		// owner-scoped snapshot and retain a same-timestamp-correctable semantic
		// watermark at its prefix; this blocks a delayed older atomic snapshot
		// from resurrecting state while admitting a corrected redelivery.
		cacheNotification = internalgnmi.CacheNotification{
			OwnerID:     sharedGNMICacheOwnerID(stream),
			Timestamp:   decoded.Timestamp,
			Invalidates: []internalgnmi.Path{decoded.Prefix.Clone()},
		}
		if nxTransaction != nil {
			nxTransaction.rollback()
			nxTransaction = nil
		}
	}
	if stream.HealthOnly {
		if semanticRejected {
			return errSharedGNMINotificationIgnored
		}
		r.telemetry.success(ctx, target.config.Name, stream.Profile, receiptTime)
		return nil
	}
	cacheTransaction, err := target.cache.Prepare(cacheNotification)
	if err != nil {
		var capacity *internalgnmi.CapacityError
		if errors.As(err, &capacity) {
			r.recordTargetCacheUtilization(ctx, target)
			r.recordTargetAuxiliaryStateUtilization(ctx, target)
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
	if target.streamStopped(stream) {
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
		r.telemetry.outOfOrder(ctx, target.config.Name, stream.Profile, result.OutOfOrder)
		r.recordTargetStateUtilization(ctx, target)
		if result.OutOfOrder > 0 {
			return errSharedGNMIStaleIgnored
		}
		if semanticRejected {
			return errSharedGNMINotificationIgnored
		}
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
			var capacity *internalgnmi.CapacityError
			if errors.As(err, &capacity) {
				// Prepare holds the cache write lock until commit or rollback. This
				// error path cannot publish state, so release it before collecting
				// read-locked utilization snapshots.
				cacheTransaction.Rollback()
				cacheTransaction = nil
				r.recordTargetCacheUtilization(ctx, target)
				r.telemetry.auxiliaryCapacityUtilization(ctx, target.config.Name, capacity)
			}
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
		decorateSharedGNMIResources(chunk, target.config, target.getVerifiedIdentity())
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
	_, stopped := target.stopped[sharedGNMIRuntimeStreamKey(stream)]
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
	r.telemetry.outOfOrder(ctx, target.config.Name, stream.Profile, result.OutOfOrder)
	r.recordTargetStateUtilization(ctx, target)
	if semanticRejected {
		return errSharedGNMINotificationIgnored
	}
	r.telemetry.success(ctx, target.config.Name, stream.Profile, receiptTime)
	return nil
}

func (r *sharedGNMIReceiver) recordTargetStateUtilization(ctx context.Context, target *sharedGNMITargetRuntime) {
	r.recordTargetCacheUtilization(ctx, target)
	r.recordTargetAuxiliaryStateUtilization(ctx, target)
}

func (r *sharedGNMIReceiver) recordTargetCacheUtilization(ctx context.Context, target *sharedGNMITargetRuntime) {
	if r == nil || target == nil || target.cache == nil {
		return
	}
	r.telemetry.cacheUtilization(
		ctx,
		target.config.Name,
		target.cache.StateLen(),
		target.cache.Capacity(),
		target.cache.RetainedBytes(),
		target.cache.RetainedByteCapacity(),
	)
}

func (r *sharedGNMIReceiver) recordTargetAuxiliaryStateUtilization(ctx context.Context, target *sharedGNMITargetRuntime) {
	if r == nil || target == nil || target.nxBudget == nil {
		return
	}
	current, maximum := target.nxBudget.snapshot()
	r.telemetry.auxiliaryStateUtilization(
		ctx,
		target.config.Name,
		current.count,
		maximum.count,
		current.bytes,
		maximum.bytes,
	)
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

func (r *sharedGNMIReceiver) clearTargetNXSensorState(ctx context.Context, target *sharedGNMITargetRuntime) {
	if r == nil || target == nil {
		return
	}
	target.clearNXSensorState()
	r.recordTargetAuxiliaryStateUtilization(ctx, target)
}

func (r *sharedGNMIReceiver) emitTargetAvailable(ctx context.Context, target *sharedGNMITargetRuntime) {
	if !target.sessionQualifiedForAvailability() {
		// A previously delivered up signal may still need its down transition
		// retried after a consumer refusal during late degradation.
		r.emitTargetUnavailable(ctx, target)
		return
	}
	if target.sessionUp.CompareAndSwap(false, true) {
		if !r.emitAvailability(ctx, target, true) {
			// A refused or canceled availability signal was not delivered. Let a
			// later notification retry it instead of pinning the local state to up.
			target.sessionUp.CompareAndSwap(true, false)
		}
	}
}

// emitTargetUnavailable withdraws a previously published up state when a
// curated or explicitly required stream becomes degraded while sibling
// streams remain connected. Qualification is monotonic-fail until restart, so
// one down transition is sufficient and duplicate degradation is suppressed.
func (r *sharedGNMIReceiver) emitTargetUnavailable(ctx context.Context, target *sharedGNMITargetRuntime) {
	if target != nil && target.sessionUp.CompareAndSwap(true, false) {
		if !r.emitAvailability(ctx, target, false) {
			// Preserve retry eligibility. Subsequent sibling progress or another
			// degradation event will attempt the down transition again.
			target.sessionUp.CompareAndSwap(false, true)
		}
	}
}

func (r *sharedGNMIReceiver) emitAvailability(ctx context.Context, target *sharedGNMITargetRuntime, up bool) bool {
	if target == nil {
		return false
	}
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
			Target: target.config.Name, Origin: builtinGNMISyntheticReceiverOrigin,
			Elements: []internalgnmi.PathElem{{Name: "target"}, {Name: target.config.Platform}}, Leaf: "up",
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
	decorateSharedGNMIResources(chunks[0], target.config, target.getVerifiedIdentity())
	opCtx := startMetricsOp(ctx, r.obs)
	consumeErr := r.consumer.ConsumeMetrics(opCtx, chunks[0])
	endMetricsOp(opCtx, r.obs, chunks[0].DataPointCount(), consumeErr)
	if consumeErr != nil {
		r.telemetry.consumerRefusal(ctx, target.config.Name, builtinGNMIProfileIdentity)
	}
	return consumeErr == nil
}

func decorateSharedGNMIResources(metrics pmetric.Metrics, target GNMITargetConfig, verified ...verifiedGNMIIdentity) {
	identity := verifiedGNMIIdentity{}
	if len(verified) > 0 {
		identity = verified[0]
	}
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
		if identity.valid() {
			attributes.PutStr("cisco.product.family", identity.Product)
			attributes.PutStr("device.manufacturer", "Cisco")
			attributes.PutStr("device.model.identifier", identity.ModelIdentifier)
			attributes.PutStr("os.version", identity.SoftwareVersion)
			if identity.BootMode != "" {
				attributes.PutStr("cisco.os.boot_mode", identity.BootMode)
			}
		}
		if osName != "" {
			attributes.PutStr("os.name", osName)
		}
		if splitErr == nil {
			putIPAttr(attributes, "host.ip", host)
		}
	}
}

func (target *sharedGNMITargetRuntime) setVerifiedIdentity(identity verifiedGNMIIdentity) {
	if target == nil {
		return
	}
	target.identityMu.Lock()
	target.verifiedIdentity = identity
	target.identityMu.Unlock()
}

func (target *sharedGNMITargetRuntime) getVerifiedIdentity() verifiedGNMIIdentity {
	if target == nil {
		return verifiedGNMIIdentity{}
	}
	target.identityMu.RLock()
	defer target.identityMu.RUnlock()
	return target.verifiedIdentity
}

func (target *sharedGNMITargetRuntime) resetSessionQualification() {
	if target == nil {
		return
	}
	target.qualificationMu.Lock()
	defer target.qualificationMu.Unlock()
	target.anyProgress = false
	target.pendingQualification = map[string]struct{}{}
	for i := range target.streams {
		stream := &target.streams[i]
		if isBuiltinGNMIProfileName(stream.Profile) || stream.Required {
			target.pendingQualification[sharedGNMIQualificationStreamKey(stream.sharedGNMIStream)] = struct{}{}
		}
	}
	if target.degradedQualification == nil {
		target.degradedQualification = map[string]struct{}{}
	}
}

func (target *sharedGNMITargetRuntime) recordStreamProgress(stream sharedGNMIRuntimeStream) {
	if target == nil {
		return
	}
	target.qualificationMu.Lock()
	target.anyProgress = true
	delete(target.pendingQualification, sharedGNMIQualificationStreamKey(stream.sharedGNMIStream))
	target.qualificationMu.Unlock()
}

func (target *sharedGNMITargetRuntime) recordOptionalStreamStopped(stream sharedGNMIRuntimeStream) {
	if target == nil || stream.Required {
		return
	}
	target.qualificationMu.Lock()
	delete(target.pendingQualification, sharedGNMIQualificationStreamKey(stream.sharedGNMIStream))
	target.qualificationMu.Unlock()
}

// replacePendingQualificationStream transfers one original qualification obligation
// to the valid path groups produced by runtime bisection. Split streams have
// path-derived keys and otherwise cannot clear the original pending key.
func (target *sharedGNMITargetRuntime) replacePendingQualificationStream(
	stream sharedGNMIRuntimeStream,
	validGroups [][]sharedGNMIPath,
) {
	if target == nil || (!isBuiltinGNMIProfileName(stream.Profile) && !stream.Required) || len(validGroups) == 0 {
		return
	}
	target.qualificationMu.Lock()
	defer target.qualificationMu.Unlock()
	originalKey := sharedGNMIQualificationStreamKey(stream.sharedGNMIStream)
	if _, pending := target.pendingQualification[originalKey]; !pending {
		return
	}
	delete(target.pendingQualification, originalKey)
	for _, paths := range validGroups {
		replacement := stream.sharedGNMIStream
		replacement.Paths = paths
		target.pendingQualification[sharedGNMIQualificationStreamKey(replacement)] = struct{}{}
	}
}

func (target *sharedGNMITargetRuntime) markQualificationDegraded(stream sharedGNMIRuntimeStream) {
	if target == nil || (!isBuiltinGNMIProfileName(stream.Profile) && !stream.Required) {
		return
	}
	target.qualificationMu.Lock()
	if target.degradedQualification == nil {
		target.degradedQualification = map[string]struct{}{}
	}
	target.degradedQualification[stream.Profile] = struct{}{}
	target.qualificationMu.Unlock()
}

func (target *sharedGNMITargetRuntime) sessionQualifiedForAvailability() bool {
	if target == nil {
		return false
	}
	target.qualificationMu.Lock()
	defer target.qualificationMu.Unlock()
	return target.anyProgress && len(target.pendingQualification) == 0 && len(target.degradedQualification) == 0
}

func sharedGNMIQualificationStreamKey(stream sharedGNMIStream) string {
	var key strings.Builder
	appendSharedGNMIKeyPart(&key, stream.Profile)
	for i := range stream.Paths {
		path := &stream.Paths[i]
		appendSharedGNMIKeyPart(&key, path.PathTarget)
		appendSharedGNMIKeyPart(&key, path.Origin)
		appendSharedGNMIKeyPart(&key, path.Path)
	}
	return key.String()
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
	var identity strings.Builder
	appendSharedGNMIKeyPart(&identity, name)
	appendSharedGNMIKeyPart(&identity, attrs["cisco.optics.lane"])
	appendSharedGNMIKeyPart(&identity, attrs["cisco.optics.profile"])
	return identity.String(), attrs
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
	return target.prepareNXNotificationForOwner("", notification)
}

func (target *sharedGNMITargetRuntime) prepareNXNotificationForOwner(
	ownerID string,
	notification internalgnmi.DecodedNotification,
) (internalgnmi.DecodedNotification, *nxSensorTransaction, error) {
	if err := normalizeNXNotificationPaths(&notification); err != nil {
		return notification, nil, err
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
		staleResults, err := target.cache.IsStaleBatchForOwner(ownerID, staleQueries)
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
			state.path = (internalgnmi.Path{Target: point.Series.Target, PathTarget: point.Series.PathTarget, Origin: point.Series.Origin, Elements: point.Series.Elements}).Clone()
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

func normalizeNXNotificationPaths(notification *internalgnmi.DecodedNotification) error {
	if notification == nil {
		return errors.New("NX notification cannot be nil")
	}
	if err := preflightNXDMENormalization(*notification); err != nil {
		return err
	}
	if err := normalizeAndValidateNXDMEPath("prefix", &notification.Prefix); err != nil {
		return err
	}
	for i := range notification.Deletes {
		if err := normalizeAndValidateNXDMEPath("delete", &notification.Deletes[i]); err != nil {
			return err
		}
	}
	for i := range notification.Updates {
		if err := normalizeAndValidateNXDMESeries(&notification.Updates[i].Series); err != nil {
			return err
		}
	}
	for i := range notification.Undecodable {
		if err := normalizeAndValidateNXDMEPath("undecodable value path", &notification.Undecodable[i]); err != nil {
			return err
		}
	}
	for i := range notification.Touched {
		if err := normalizeAndValidateNXDMEPath("touched path", &notification.Touched[i]); err != nil {
			return err
		}
	}
	return nil
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
	for index := range notification.Undecodable {
		if notification.Undecodable[index].Origin != builtinGNMIOriginDME {
			continue
		}
		if err := validateNXDMEExpansion(notification.Undecodable[index].Elements, sharedGNMIMaxPathElements); err != nil {
			return fmt.Errorf("normalize NX DME undecodable value path: %w", err)
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

var gnmiStateEnumTokenReplacer = strings.NewReplacer("-", "_", " ", "_")

func normalizeGNMIStateValues(notification *internalgnmi.DecodedNotification) []internalgnmi.Path {
	invalidated, _ := normalizeGNMIStateValuesChecked(notification)
	return invalidated
}

func normalizeGNMIStateValuesChecked(notification *internalgnmi.DecodedNotification) ([]internalgnmi.Path, bool) {
	var invalidated []internalgnmi.Path
	malformedStatePath := false
	for i := range notification.Updates {
		point := &notification.Updates[i]
		leaf := normalizeGNMILeaf(point.Series.Leaf)
		if leaf == "oper-status" || leaf == "admin-status" {
			selector, governed, addressable := governedGNMIInterfaceStateSelector(point.Series, leaf)
			if !governed {
				continue
			}
			if !addressable {
				// A missing canonical interface name cannot be converted into a
				// safe selector and must not flow through the registry as an
				// empty-cardinality status series. The caller ignores the whole
				// notification so sibling updates remain transactional.
				point.Value = internalgnmi.Value{}
				malformedStatePath = true
				continue
			}
			if point.Value.Kind == internalgnmi.ValueString {
				if value, ok := normalizedGNMIStateBoolean(leaf, point.Value.String); ok {
					point.Value = internalgnmi.BoolValue(value)
					continue
				}
			}
			// The governed interface status metrics are strictly binary. A
			// malformed or future wire representation must not emit an
			// arbitrary integer or leave a stale UP value in the cache.
			point.Value = internalgnmi.Value{}
			invalidated = append(invalidated, selector)
			continue
		}
		if point.Value.Kind != internalgnmi.ValueString {
			continue
		}
		if value, ok := normalizedGNMIStateBoolean(leaf, point.Value.String); ok {
			point.Value = internalgnmi.BoolValue(value)
		}
	}
	return invalidated, malformedStatePath
}

func governedGNMIInterfaceStateSelector(
	series internalgnmi.Series,
	leaf string,
) (internalgnmi.Path, bool, bool) {
	if len(series.Elements) != 3 ||
		series.Elements[1].Name != "interface" ||
		series.Elements[2].Name != "state" {
		return internalgnmi.Path{}, false, false
	}
	switch series.Origin {
	case builtinGNMIOriginRFC7951:
		if series.Elements[0].Name != "openconfig-interfaces:interfaces" {
			return internalgnmi.Path{}, false, false
		}
	case "openconfig-interfaces", builtinGNMIOriginOpenConfig:
		if series.Elements[0].Name != "interfaces" {
			return internalgnmi.Path{}, false, false
		}
	default:
		return internalgnmi.Path{}, false, false
	}
	name, addressable := series.Elements[1].Keys["name"]
	if !addressable || name == "" {
		return internalgnmi.Path{}, true, false
	}
	return internalgnmi.Path{
		Target:     series.Target,
		PathTarget: series.PathTarget,
		Origin:     series.Origin,
		Elements: []internalgnmi.PathElem{
			{Name: series.Elements[0].Name},
			{Name: series.Elements[1].Name, Keys: map[string]string{"name": name}},
			{Name: series.Elements[2].Name},
			{Name: leaf},
		},
	}, true, true
}

// normalizedGNMIStateBoolean applies leaf-specific enum contracts. In
// particular, OpenConfig interface operational status is binary at the OTLP
// boundary: UP is 1 and every other defined enum is 0. The caller rejects an
// unknown interface enum so a future value cannot silently acquire an
// incorrect meaning or leave a stale cached status.
func normalizedGNMIStateBoolean(leaf, raw string) (bool, bool) {
	value := strings.TrimSpace(raw)
	if separator := strings.LastIndexByte(value, ':'); separator >= 0 {
		if strings.IndexByte(value, ':') != separator {
			return false, false
		}
		qualifier := value[:separator]
		if (leaf == "oper-status" || leaf == "admin-status") && qualifier != "openconfig-interfaces" {
			return false, false
		}
		value = value[separator+1:]
	}
	value = strings.ToUpper(strings.TrimSpace(value))
	value = gnmiStateEnumTokenReplacer.Replace(value)

	switch leaf {
	case "oper-status":
		switch value {
		case "UP":
			return true, true
		case "DOWN", "TESTING", "UNKNOWN", "DORMANT", "NOT_PRESENT", "LOWER_LAYER_DOWN":
			return false, true
		}
	case "admin-status":
		switch value {
		case "UP":
			return true, true
		case "DOWN", "TESTING":
			return false, true
		}
	case "present":
		switch value {
		case "UP", "ON", "TRUE", "ACTIVE", "ENABLED", "PRESENT", "JOINED", "OK":
			return true, true
		case "DOWN", "OFF", "FALSE", "INACTIVE", "DISABLED", "ABSENT", "NOT_PRESENT", "NOT_JOINED", "FAILED":
			return false, true
		}
	case "is-joined":
		switch value {
		case "UP", "ON", "TRUE", "ACTIVE", "ENABLED", "PRESENT", "JOINED", "OK":
			return true, true
		case "DOWN", "OFF", "FALSE", "INACTIVE", "DISABLED", "ABSENT", "NOT_PRESENT", "NOT_JOINED", "FAILED":
			return false, true
		}
	}
	return false, false
}

func normalizeGNMILeaf(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "_", "-"))
}

func classifySharedGNMIStreamError(err error) error {
	if err == nil {
		return nil
	}
	code := status.Code(err)
	err = sanitizedGNMIRPCError(err)
	if isSharedGNMIAuthenticationError(err) {
		return err
	}
	switch code {
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
	var sanitized *sanitizedGNMIRPCStatus
	if errors.As(err, &sanitized) && sanitized.authenticationFailure {
		return true
	}
	return gnmiStatusIndicatesAuthenticationFailure(status.Code(err), err.Error())
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
	matched := false
	for i := range target.streams {
		stream := &target.streams[i]
		if stream.Profile != profile {
			continue
		}
		target.stopped[sharedGNMIRuntimeStreamKey(*stream)] = struct{}{}
		matched = true
	}
	if !matched {
		// Preserve the small legacy test/helper surface for targets constructed
		// without normalized runtime streams.
		target.stopped["profile\x00"+profile] = struct{}{}
	}
}

func (target *sharedGNMITargetRuntime) profileStopped(profile string) bool {
	target.stateMu.RLock()
	defer target.stateMu.RUnlock()
	if _, stopped := target.stopped["profile\x00"+profile]; stopped {
		return true
	}
	for i := range target.streams {
		stream := &target.streams[i]
		if stream.Profile == profile {
			if _, stopped := target.stopped[sharedGNMIRuntimeStreamKey(*stream)]; stopped {
				return true
			}
		}
	}
	return false
}

func (target *sharedGNMITargetRuntime) stopStream(stream sharedGNMIRuntimeStream) {
	target.stateMu.Lock()
	defer target.stateMu.Unlock()
	target.stopped[sharedGNMIRuntimeStreamKey(stream)] = struct{}{}
}

func (target *sharedGNMITargetRuntime) streamStopped(stream sharedGNMIRuntimeStream) bool {
	target.stateMu.RLock()
	defer target.stateMu.RUnlock()
	_, stopped := target.stopped[sharedGNMIRuntimeStreamKey(stream)]
	if stopped {
		return true
	}
	_, stopped = target.stopped["profile\x00"+stream.Profile]
	return stopped
}

func sharedGNMIRuntimeStreamKey(stream sharedGNMIRuntimeStream) string {
	if stream.OwnerID != "" {
		return "owner\x00" + stream.OwnerID
	}
	return "stream\x00" + sharedGNMIQualificationStreamKey(stream.sharedGNMIStream)
}

func sharedGNMICacheOwnerID(stream sharedGNMIRuntimeStream) string {
	if stream.cacheOwnerID != "" {
		return stream.cacheOwnerID
	}
	return stream.OwnerID
}

func sharedGNMIBisectedRuntimeStream(stream sharedGNMIRuntimeStream, paths []sharedGNMIPath) sharedGNMIRuntimeStream {
	return sharedGNMIBisectedRuntimeStreams(stream, [][]sharedGNMIPath{paths})[0]
}

func sharedGNMIResolvedRuntimeStreams(
	stream sharedGNMIRuntimeStream,
	groups [][]sharedGNMIPath,
) []sharedGNMIRuntimeStream {
	if len(groups) == 0 {
		return nil
	}
	if len(groups) == 1 && sharedGNMIPathSetsEqual(stream.Paths, groups[0]) {
		stream.Paths = groups[0]
		return []sharedGNMIRuntimeStream{stream}
	}
	return sharedGNMIBisectedRuntimeStreams(stream, groups)
}

func sharedGNMIBisectedRuntimeStreams(
	stream sharedGNMIRuntimeStream,
	groups [][]sharedGNMIPath,
) []sharedGNMIRuntimeStream {
	if len(groups) == 0 {
		return nil
	}
	replacedOwnerID := sharedGNMICacheOwnerID(stream)
	desiredOwners := sharedGNMICacheTopologyOwners(stream)
	for index := 0; index < len(desiredOwners); {
		if desiredOwners[index] == replacedOwnerID {
			desiredOwners = append(desiredOwners[:index], desiredOwners[index+1:]...)
			continue
		}
		index++
	}
	out := make([]sharedGNMIRuntimeStream, len(groups))
	for index, paths := range groups {
		out[index] = stream
		out[index].Paths = paths
		out[index].cacheOwnerID = sharedGNMIPhysicalCacheOwnerID(stream.OwnerID, paths)
		desiredOwners = append(desiredOwners, out[index].cacheOwnerID)
	}
	desiredOwners = sharedGNMICanonicalCacheTopology(desiredOwners)
	for index := range out {
		out[index].cacheTopologyOwners = append([]string(nil), desiredOwners...)
	}
	return out
}

func sharedGNMIPhysicalCacheOwnerID(logicalOwnerID string, paths []sharedGNMIPath) string {
	if logicalOwnerID == "" {
		return ""
	}
	digest := sha256.New()
	fmt.Fprintf(digest, "%d:%s", len(logicalOwnerID), logicalOwnerID)
	for _, pathKey := range sharedGNMICanonicalPathSet(paths) {
		fmt.Fprintf(digest, "%d:%s", len(pathKey), pathKey)
	}
	return fmt.Sprintf("gnmi-physical:%x", digest.Sum(nil))
}

func sharedGNMIPathSetsEqual(left, right []sharedGNMIPath) bool {
	return slices.Equal(sharedGNMICanonicalPathSet(left), sharedGNMICanonicalPathSet(right))
}

func sharedGNMICanonicalPathSet(paths []sharedGNMIPath) []string {
	keys := make([]string, len(paths))
	for index := range paths {
		keys[index] = sharedGNMIPathKey(paths[index])
	}
	slices.Sort(keys)
	return keys
}

func sharedGNMICacheTopologyOwners(stream sharedGNMIRuntimeStream) []string {
	if len(stream.cacheTopologyOwners) > 0 {
		owners := append([]string(nil), stream.cacheTopologyOwners...)
		return sharedGNMICanonicalCacheTopology(append(owners, sharedGNMICacheOwnerID(stream)))
	}
	return sharedGNMICanonicalCacheTopology([]string{sharedGNMICacheOwnerID(stream)})
}

func sharedGNMICanonicalCacheTopology(ownerIDs []string) []string {
	owners := make([]string, 0, len(ownerIDs))
	for _, ownerID := range ownerIDs {
		if ownerID != "" {
			owners = append(owners, ownerID)
		}
	}
	slices.Sort(owners)
	return slices.Compact(owners)
}

func sharedGNMICacheTopologyContains(topology []string, ownerID string) bool {
	_, found := slices.BinarySearch(topology, ownerID)
	return found
}

func (target *sharedGNMITargetRuntime) beginCacheTopologySession() {
	if target == nil {
		return
	}
	target.deliveryMu.Lock()
	defer target.deliveryMu.Unlock()
	for _, topology := range target.cacheTopologies {
		if topology == nil {
			continue
		}
		if topology.orphaned == nil {
			topology.orphaned = map[string]struct{}{}
		}
		for ownerID := range topology.accepted {
			if !sharedGNMICacheTopologyContains(topology.current, ownerID) {
				topology.orphaned[ownerID] = struct{}{}
			}
		}
		topology.candidate = nil
		topology.accepted = nil
	}
}

func (r *sharedGNMIReceiver) reconcileCacheTopology(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
) error {
	if target == nil || stream.OwnerID == "" {
		return nil
	}
	desired := sharedGNMICacheTopologyOwners(stream)
	member := sharedGNMICacheOwnerID(stream)
	if len(desired) == 0 || member == "" {
		return nil
	}

	target.deliveryMu.Lock()
	defer target.deliveryMu.Unlock()
	if target.streamStopped(stream) {
		return nil
	}
	if target.cacheTopologies == nil {
		target.cacheTopologies = map[string]*sharedGNMICacheTopology{}
	}
	topology := target.cacheTopologies[stream.OwnerID]
	if topology == nil {
		topology = &sharedGNMICacheTopology{current: []string{stream.OwnerID}}
		target.cacheTopologies[stream.OwnerID] = topology
	}
	if topology.orphaned == nil {
		topology.orphaned = map[string]struct{}{}
	}

	transition := !slices.Equal(topology.current, desired)
	if !transition && len(topology.candidate) > 0 {
		// A still-running sibling retains the topology attached when it was
		// launched. If another member is being split further, count this sibling
		// toward that candidate rather than abandoning the in-flight transition.
		if !sharedGNMICacheTopologyContains(topology.candidate, member) {
			return nil
		}
		desired = append([]string(nil), topology.candidate...)
		transition = true
	}
	if !transition {
		for ownerID := range topology.accepted {
			if !sharedGNMICacheTopologyContains(topology.current, ownerID) {
				topology.orphaned[ownerID] = struct{}{}
			}
		}
		obsolete := make([]string, 0, len(topology.orphaned))
		for ownerID := range topology.orphaned {
			if !sharedGNMICacheTopologyContains(topology.current, ownerID) {
				obsolete = append(obsolete, ownerID)
			}
		}
		if err := r.resetCacheOwnersLocked(target, stream, obsolete); err != nil {
			return &sharedGNMIProfileStopError{err: fmt.Errorf("reset abandoned gNMI cache topology: %w", err)}
		}
		topology.candidate = nil
		topology.accepted = nil
		topology.orphaned = nil
		target.removePhysicalCacheOwners(stream.OwnerID, obsolete)
		if len(obsolete) > 0 {
			r.recordTargetStateUtilization(ctx, target)
		}
		return nil
	}

	if !slices.Equal(topology.candidate, desired) {
		accepted := make(map[string]struct{}, len(desired))
		for _, ownerID := range topology.current {
			if sharedGNMICacheTopologyContains(desired, ownerID) {
				accepted[ownerID] = struct{}{}
			}
		}
		for ownerID := range topology.accepted {
			switch {
			case sharedGNMICacheTopologyContains(desired, ownerID):
				accepted[ownerID] = struct{}{}
			case !sharedGNMICacheTopologyContains(topology.current, ownerID):
				topology.orphaned[ownerID] = struct{}{}
			}
		}
		topology.candidate = append([]string(nil), desired...)
		topology.accepted = accepted
		for _, ownerID := range desired {
			delete(topology.orphaned, ownerID)
		}
	}
	if sharedGNMICacheTopologyContains(desired, member) {
		topology.accepted[member] = struct{}{}
	}
	if len(topology.accepted) < len(desired) {
		return nil
	}

	obsolete := make([]string, 0, len(topology.current)+len(topology.orphaned))
	for _, ownerID := range topology.current {
		if !sharedGNMICacheTopologyContains(desired, ownerID) {
			obsolete = append(obsolete, ownerID)
		}
	}
	for ownerID := range topology.orphaned {
		if !sharedGNMICacheTopologyContains(desired, ownerID) {
			obsolete = append(obsolete, ownerID)
		}
	}
	obsolete = sharedGNMICanonicalCacheTopology(obsolete)
	if err := r.resetCacheOwnersLocked(target, stream, obsolete); err != nil {
		return &sharedGNMIProfileStopError{err: fmt.Errorf("transition gNMI cache topology: %w", err)}
	}
	topology.current = append([]string(nil), desired...)
	topology.candidate = nil
	topology.accepted = nil
	topology.orphaned = nil
	target.removePhysicalCacheOwners(stream.OwnerID, obsolete)
	if len(obsolete) > 0 {
		r.recordTargetStateUtilization(ctx, target)
	}
	return nil
}

func (target *sharedGNMITargetRuntime) registerPhysicalCacheOwner(stream sharedGNMIRuntimeStream) {
	if target == nil || !stream.UpdatesOnly {
		return
	}
	logicalOwnerID := stream.OwnerID
	cacheOwnerID := sharedGNMICacheOwnerID(stream)
	if logicalOwnerID == "" || cacheOwnerID == "" || logicalOwnerID == cacheOwnerID {
		return
	}
	target.stateMu.Lock()
	defer target.stateMu.Unlock()
	if target.updatesOnlyCacheOwners == nil {
		target.updatesOnlyCacheOwners = map[string]map[string]struct{}{}
	}
	owners := target.updatesOnlyCacheOwners[logicalOwnerID]
	if owners == nil {
		owners = map[string]struct{}{}
		target.updatesOnlyCacheOwners[logicalOwnerID] = owners
	}
	owners[cacheOwnerID] = struct{}{}
}

func (target *sharedGNMITargetRuntime) cacheOwnerIDsForLogicalStream(logicalOwnerID string) []string {
	owners := []string{logicalOwnerID}
	if target == nil {
		return owners
	}
	target.stateMu.RLock()
	defer target.stateMu.RUnlock()
	for cacheOwnerID := range target.updatesOnlyCacheOwners[logicalOwnerID] {
		if cacheOwnerID != logicalOwnerID {
			owners = append(owners, cacheOwnerID)
		}
	}
	return owners
}

func (target *sharedGNMITargetRuntime) clearPhysicalCacheOwners(logicalOwnerID string) {
	if target == nil {
		return
	}
	target.stateMu.Lock()
	delete(target.updatesOnlyCacheOwners, logicalOwnerID)
	target.stateMu.Unlock()
}

func (target *sharedGNMITargetRuntime) removePhysicalCacheOwners(logicalOwnerID string, ownerIDs []string) {
	if target == nil || len(ownerIDs) == 0 {
		return
	}
	target.stateMu.Lock()
	defer target.stateMu.Unlock()
	owners := target.updatesOnlyCacheOwners[logicalOwnerID]
	for _, ownerID := range ownerIDs {
		delete(owners, ownerID)
	}
	if len(owners) == 0 {
		delete(target.updatesOnlyCacheOwners, logicalOwnerID)
	}
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
	for i := range paths {
		if _, isolated := target.isolate[sharedGNMIPathKey(paths[i])]; !isolated {
			out = append(out, paths[i])
		}
	}
	return out
}

func sharedGNMIPathKey(path sharedGNMIPath) string {
	var key strings.Builder
	appendSharedGNMIKeyPart(&key, path.PathTarget)
	appendSharedGNMIKeyPart(&key, path.Origin)
	appendSharedGNMIKeyPart(&key, path.Path)
	return key.String()
}

func sharedGNMIRejectedRequestKey(
	target GNMITargetConfig,
	stream sharedGNMIRuntimeStream,
	encoding gnmipb.Encoding,
) (string, error) {
	request, err := buildSharedGNMISubscribeRequest(target, stream.sharedGNMIStream, encoding)
	if err != nil {
		return "", err
	}
	wire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(request)
	if err != nil {
		return "", fmt.Errorf("marshal rejected gNMI request identity: %w", err)
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(stream.OwnerID))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(wire)
	return fmt.Sprintf("%x", digest.Sum(nil)), nil
}

func runtimeSharedGNMIStreams(streams []sharedGNMIRuntimeStream) []sharedGNMIStream {
	out := make([]sharedGNMIStream, len(streams))
	for i := range streams {
		out[i] = streams[i].sharedGNMIStream
	}
	return out
}

func sharedGNMISourceKey(source internalgnmi.SourcePath) string {
	return source.Key()
}

func appendSharedGNMIKeyPart(key *strings.Builder, value string) {
	key.WriteString(strconv.Itoa(len(value)))
	key.WriteByte(':')
	key.WriteString(value)
}

func sharedGNMISeriesSourceKey(series internalgnmi.Series) string {
	elements := make([]string, len(series.Elements))
	for i := range series.Elements {
		elements[i] = series.Elements[i].Name
	}
	return sharedGNMISourceKey(internalgnmi.SourcePath{PathTarget: series.PathTarget, Origin: series.Origin, Elements: elements, Leaf: series.Leaf})
}

func sharedGNMIParentSeriesKey(series internalgnmi.Series) string {
	return (internalgnmi.Path{Target: series.Target, PathTarget: series.PathTarget, Origin: series.Origin, Elements: series.Elements}).Key()
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
