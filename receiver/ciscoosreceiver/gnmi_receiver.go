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
	"sort"
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
	sharedGNMITransport             = "gnmi"
	sharedGNMIAuthenticationBackoff = 5 * time.Minute
	sharedGNMIInitialBackoff        = 5 * time.Second
	sharedGNMIMaximumBackoff        = time.Minute
	sharedGNMIBackoffResetAfter     = time.Minute
	sharedGNMIMaxBisectionProbes    = 64
	sharedGNMIMaxConcurrentDelivery = 8
	sharedGNMINegativeRetryMinimum  = time.Minute
	sharedGNMINegativeRetryMaximum  = 15 * time.Minute
	sharedGNMIMaxNXPlanningWork     = 25_000_000
	sharedGNMIMaxPathElements       = 128
	sharedGNMIMaxSeriesElements     = sharedGNMIMaxPathElements - 1
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
	configured   GNMITargetConfig
	config       GNMITargetConfig
	streams      []sharedGNMIRuntimeStream
	identity     sharedGNMIDeviceIdentity
	catalog      gnmiCatalogProductDefinition
	family       gnmiCatalogProductFamilyDefinition
	fingerprint  string
	sessionMu    sync.RWMutex
	cache        *internalgnmi.Cache
	deliveryMu   sync.Mutex
	stateMu      sync.RWMutex
	isolate      map[string]sharedGNMINegativeEntry
	stopped      map[string]sharedGNMINegativeEntry
	now          func() time.Time
	after        func(time.Duration) <-chan time.Time
	readinessMu  sync.Mutex
	readiness    *sharedGNMISessionReadiness
	entityLimits *sharedGNMIEntityLimitManager

	nxMu      sync.Mutex
	nxSensors map[string]nxSensorState
	nxBudget  *sharedGNMIAuxiliaryBudget
	sessionUp atomic.Bool

	presenceMu     sync.Mutex
	opticalSources map[string]string
	presenceCounts map[string]int
	presenceAttrs  map[string]map[string]string
}

type sharedGNMINegativeEntry struct {
	fingerprint string
	failures    int
	retryAt     time.Time
}

type sharedGNMINegativeRetryError struct{}

func (*sharedGNMINegativeRetryError) Error() string {
	return "gNMI negative-capability retry window elapsed"
}

type sharedGNMIRuntimeStream struct {
	sharedGNMIStream
	registry         *internalgnmi.Registry
	staticAttr       map[string]map[string]string
	wireEncoding     gnmipb.Encoding
	variantFallbacks []sharedGNMIRuntimeVariant
}

type sharedGNMIRuntimeVariant struct {
	pathSetID        string
	variantID        string
	variantOrder     int
	sourcePreference string
	stream           sharedGNMIRuntimeStream
	planningErr      error
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

type sharedGNMISessionReadiness struct {
	required    map[string]bool
	hasRequired bool
	anySynced   bool
}

type sharedGNMIUnsupportedError struct{ err error }

func (e *sharedGNMIUnsupportedError) Error() string { return e.err.Error() }
func (e *sharedGNMIUnsupportedError) Unwrap() error { return e.err }

type sharedGNMIProfileStopError struct {
	reason string
	err    error
}

var (
	errSharedGNMINotificationIgnored = errors.New("gNMI notification was ignored before qualification progress")
	errSharedGNMIStaleIgnored        = errors.New("out-of-order gNMI notification was ignored before qualification progress")
)

func (e *sharedGNMIProfileStopError) Error() string { return e.err.Error() }
func (e *sharedGNMIProfileStopError) Unwrap() error { return e.err }

type sharedGNMISyncTimeoutError struct {
	profile string
	timeout time.Duration
}

func (e *sharedGNMISyncTimeoutError) Error() string {
	return fmt.Sprintf("gNMI stream %q did not complete sync within %s", e.profile, e.timeout)
}

type sharedGNMISyncWatchdog struct {
	mu       sync.Mutex
	timer    *time.Timer
	cancel   context.CancelFunc
	finished bool
	timedOut bool
	profile  string
	timeout  time.Duration
}

func newSharedGNMISyncWatchdog(
	profile string,
	timeout time.Duration,
	cancel context.CancelFunc,
) (*sharedGNMISyncWatchdog, error) {
	if timeout <= 0 {
		return nil, errors.New("gNMI sync timeout must be positive")
	}
	if cancel == nil {
		return nil, errors.New("gNMI sync watchdog cancel function cannot be nil")
	}
	watchdog := &sharedGNMISyncWatchdog{cancel: cancel, profile: profile, timeout: timeout}
	watchdog.timer = time.AfterFunc(timeout, func() {
		watchdog.mu.Lock()
		if watchdog.finished {
			watchdog.mu.Unlock()
			return
		}
		watchdog.finished = true
		watchdog.timedOut = true
		watchdog.mu.Unlock()
		watchdog.cancel()
	})
	return watchdog, nil
}

func sharedGNMISyncTimeoutForStream(target *sharedGNMITargetRuntime, stream sharedGNMIRuntimeStream) time.Duration {
	if stream.SyncTimeout > 0 {
		return stream.SyncTimeout
	}
	return target.config.SyncTimeout
}

// finish stops the watchdog and reports whether its timeout won the race.
func (w *sharedGNMISyncWatchdog) finish() bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.finished {
		w.finished = true
		w.timer.Stop()
	}
	return w.timedOut
}

func (w *sharedGNMISyncWatchdog) timeoutError() error {
	if w == nil {
		return errors.New("gNMI sync timeout")
	}
	return &sharedGNMISyncTimeoutError{profile: w.profile, timeout: w.timeout}
}

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
	if cache == nil {
		return nil, errors.New("shared gNMI cache cannot be nil")
	}
	if auxiliaryBudget == nil || auxiliaryBudget.maximum <= 0 || auxiliaryBudget.maximumBytes <= 0 {
		return nil, errors.New("shared gNMI auxiliary-state count and byte budgets must be positive")
	}
	target = target.withDefaults()
	runtime := &sharedGNMITargetRuntime{
		configured: target,
		config:     target,
		cache:      cache,
		isolate:    map[string]sharedGNMINegativeEntry{},
		stopped:    map[string]sharedGNMINegativeEntry{},
		now:        time.Now,
		after:      time.After,
		nxBudget:   auxiliaryBudget,
	}
	// An empty platform is intentionally constructible. Its built-in profile
	// paths cannot be selected until Subscribe-discovered identity has matched
	// one exact catalog row. Explicit-platform construction remains eager for
	// fixture and transaction helpers; live sessions rebuild these streams.
	if target.Platform == "" {
		runtime.entityLimits, _ = newSharedGNMIEntityLimitManager(nil, nil)
		return runtime, nil
	}
	streams, err := buildSharedGNMIRuntimeStreams(target)
	if err != nil {
		return nil, err
	}
	runtime.streams = streams
	runtime.entityLimits, err = newSharedGNMIEntityLimitManager(streams, cache.Snapshot())
	if err != nil {
		return nil, fmt.Errorf("plan gNMI entity limits: %w", err)
	}
	runtime.resetSessionQualification()
	return runtime, nil
}

func buildSharedGNMIRuntimeStreams(target GNMITargetConfig) ([]sharedGNMIRuntimeStream, error) {
	streams, err := buildSharedGNMIStreams(target)
	if err != nil {
		return nil, err
	}
	runtimeStreams := make([]sharedGNMIRuntimeStream, 0, len(streams))
	for streamIndex := range streams {
		runtimeStream, err := buildSharedGNMIRuntimeStream(streams[streamIndex])
		if err != nil {
			return nil, err
		}
		runtimeStreams = append(runtimeStreams, runtimeStream)
	}
	return runtimeStreams, nil
}

func buildSharedGNMIRuntimeStream(stream sharedGNMIStream) (sharedGNMIRuntimeStream, error) {
	fallbacks := stream.VariantFallbacks
	stream.VariantFallbacks = nil
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
		return sharedGNMIRuntimeStream{}, fmt.Errorf("profile %q mappings: %w", stream.Profile, err)
	}
	runtimeStream := sharedGNMIRuntimeStream{
		sharedGNMIStream: stream,
		registry:         registry,
		staticAttr:       staticAttrs,
		variantFallbacks: make([]sharedGNMIRuntimeVariant, 0, len(fallbacks)),
	}
	for index := range fallbacks {
		fallback := fallbacks[index]
		candidate, candidateErr := buildSharedGNMIRuntimeStream(fallback.Stream)
		if candidateErr != nil {
			return sharedGNMIRuntimeStream{}, fmt.Errorf(
				"profile %q path set %q variant %q: %w",
				stream.Profile,
				fallback.PathSetID,
				fallback.VariantID,
				candidateErr,
			)
		}
		if pathSets := sharedGNMIAtomicPathSets(candidate.Paths); len(pathSets) != 1 {
			return sharedGNMIRuntimeStream{}, fmt.Errorf(
				"profile %q path set %q variant %q produced %d atomic path groups",
				stream.Profile,
				fallback.PathSetID,
				fallback.VariantID,
				len(pathSets),
			)
		}
		runtimeStream.variantFallbacks = append(runtimeStream.variantFallbacks, sharedGNMIRuntimeVariant{
			pathSetID:        fallback.PathSetID,
			variantID:        fallback.VariantID,
			variantOrder:     fallback.VariantOrder,
			sourcePreference: fallback.SourcePreference,
			stream:           candidate,
		})
	}
	return runtimeStream, nil
}

func (target *sharedGNMITargetRuntime) configuredTarget() GNMITargetConfig {
	target.sessionMu.RLock()
	defer target.sessionMu.RUnlock()
	return target.configured
}

func (target *sharedGNMITargetRuntime) beginDiscoverySession() {
	target.sessionMu.Lock()
	target.config = target.configured
	target.streams = nil
	target.identity = sharedGNMIDeviceIdentity{}
	target.catalog = gnmiCatalogProductDefinition{}
	target.family = gnmiCatalogProductFamilyDefinition{}
	target.entityLimits = nil
	target.sessionMu.Unlock()
}

func (target *sharedGNMITargetRuntime) configureDiscoveredSession(
	identity sharedGNMIDeviceIdentity,
	product gnmiCatalogProductDefinition,
	family gnmiCatalogProductFamilyDefinition,
	capabilities *gnmipb.CapabilityResponse,
) error {
	configured := target.configuredTarget()
	if family.ID == "" || family.Platform == "" || family.MaxStreams <= 0 {
		return errors.New("selected generated catalog row has an invalid product family")
	}
	if family.Platform != identity.OSFamily {
		return fmt.Errorf(
			"selected product family %q belongs to platform %q, not subscribed OS family %q",
			family.ID,
			family.Platform,
			identity.OSFamily,
		)
	}
	if configured.MaxStreams > family.MaxStreams {
		return fmt.Errorf(
			"configured max_streams %d exceeds selected catalog family %q ceiling %d",
			configured.MaxStreams,
			family.ID,
			family.MaxStreams,
		)
	}

	effective := configured
	effective.Platform = identity.OSFamily
	effective.ProductFamily = family.ID
	streams, err := buildSharedGNMIRuntimeStreams(effective)
	if err != nil {
		return err
	}
	for index := range streams {
		if encodingErr := negotiateSharedGNMIRuntimeStreamEncodings(effective, capabilities, &streams[index]); encodingErr != nil {
			return encodingErr
		}
	}
	identity.ProductFamily = family.ID
	fingerprint := strings.Join([]string{
		identity.OSFamily,
		identity.ModelIdentifier,
		identity.SoftwareVersion,
		identity.SerialNumber,
		identity.Hostname,
		product.ID,
		sharedGNMICapabilityFingerprint(capabilities),
	}, "\x00")

	// Session streams are fully joined before discovery starts, and every cache
	// or auxiliary-state mutation holds deliveryMu. Keep that publication
	// boundary here too so a changed device/release cannot observe or be
	// contaminated by retained state from the previous fingerprint.
	target.deliveryMu.Lock()
	defer target.deliveryMu.Unlock()
	target.sessionMu.RLock()
	previousFingerprint := target.fingerprint
	sessionCache := target.cache
	sessionBudget := target.nxBudget
	target.sessionMu.RUnlock()
	if sessionCache == nil {
		return errors.New("discovered gNMI session has no state cache")
	}
	if sessionBudget == nil {
		return errors.New("discovered gNMI session has no auxiliary-state budget")
	}
	changed := previousFingerprint != "" && previousFingerprint != fingerprint
	if changed {
		sessionCache, err = internalgnmi.NewCacheWithLimits(
			sessionCache.Capacity(),
			sessionCache.RetainedByteCapacity(),
		)
		if err != nil {
			return fmt.Errorf("replace changed-fingerprint gNMI cache: %w", err)
		}
		sessionBudget.mu.Lock()
		maximum, maximumBytes := sessionBudget.maximum, sessionBudget.maximumBytes
		sessionBudget.mu.Unlock()
		sessionBudget = newSharedGNMIAuxiliaryBudgetWithLimits(maximum, maximumBytes)
	}
	entityLimits, err := newSharedGNMIEntityLimitManager(streams, sessionCache.Snapshot())
	if err != nil {
		return fmt.Errorf("plan group entity limits: %w", err)
	}

	target.sessionMu.Lock()
	if changed {
		target.stateMu.Lock()
		target.nxMu.Lock()
		target.presenceMu.Lock()
	}
	target.config = effective
	target.streams = streams
	target.identity = identity
	target.catalog = product
	target.family = family
	target.fingerprint = fingerprint
	target.cache = sessionCache
	target.entityLimits = entityLimits
	if changed {
		// Negative observations and optional-profile stops are scoped to the
		// exact PID, release, and capability fingerprint that produced them.
		// Cache timestamps/tombstones and all optical/NX correlation state have
		// the same scope and must cross the fingerprint boundary together.
		target.isolate = map[string]sharedGNMINegativeEntry{}
		target.stopped = map[string]sharedGNMINegativeEntry{}
		target.nxSensors = nil
		target.opticalSources = nil
		target.presenceCounts = nil
		target.presenceAttrs = nil
		target.nxBudget = sessionBudget
		target.sessionUp.Store(false)
		target.presenceMu.Unlock()
		target.nxMu.Unlock()
		target.stateMu.Unlock()
	}
	target.sessionMu.Unlock()
	return nil
}

func (target *sharedGNMITargetRuntime) sessionResourceIdentity() (GNMITargetConfig, sharedGNMIDeviceIdentity) {
	target.sessionMu.RLock()
	defer target.sessionMu.RUnlock()
	return target.config, target.identity
}

func (target *sharedGNMITargetRuntime) sessionEntityLimits() *sharedGNMIEntityLimitManager {
	target.sessionMu.RLock()
	defer target.sessionMu.RUnlock()
	return target.entityLimits
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
		sessionConfig, _ := target.sessionResourceIdentity()
		r.telemetry.connection(ctx, sessionConfig.Name, false)
		wasUp := target.sessionUp.Swap(false)
		if resetBackoff {
			attempt = 0
		}
		if terminal {
			if wasUp && ctx.Err() == nil {
				r.emitAvailability(ctx, target, false)
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
		r.emitAvailability(ctx, target, false)
		var negativeRetry *sharedGNMINegativeRetryError
		if errors.As(err, &negativeRetry) {
			attempt = 0
			r.telemetry.reconnect(ctx, sessionConfig.Name)
			r.settings.Logger.Info("Cisco gNMI negative-capability retry window elapsed",
				zap.String("target", sessionConfig.Name),
				zap.String("endpoint", sessionConfig.Endpoint))
			continue
		}
		delay := equalJitterGNMIBackoff(attempt)
		if isSharedGNMIAuthenticationError(err) {
			r.telemetry.authenticationFailure(ctx, sessionConfig.Name)
			delay = sharedGNMIAuthenticationBackoff
		} else {
			attempt++
		}
		r.telemetry.reconnect(ctx, sessionConfig.Name)
		r.settings.Logger.Warn("Cisco gNMI target disconnected",
			zap.String("target", sessionConfig.Name),
			zap.String("endpoint", sessionConfig.Endpoint),
			zap.Duration("retry_delay", delay),
			zap.Error(err))
		if !waitSharedGNMIBackoff(ctx, delay) {
			return
		}
	}
}

func (r *sharedGNMIReceiver) serveTarget(ctx context.Context, target *sharedGNMITargetRuntime) (bool, bool, error) {
	target.sessionUp.Store(false)
	target.beginDiscoverySession()
	// DME description/unit identity is scoped to a device session. Clearing is
	// harmless for non-NX targets and also handles an automatically discovered
	// endpoint changing OS family between sessions.
	target.clearNXSensorState()
	defer target.clearNXSensorState()
	configured := target.configuredTarget()
	conn, err := r.dialTarget(ctx, configured)
	if err != nil {
		return false, false, err
	}
	defer conn.Close()
	capCtx, cancel := context.WithTimeout(sharedGNMIOutgoingContext(ctx, configured), configured.CapabilitiesTimeout)
	capabilities, err := invokeGNMICapabilities(capCtx, conn, r.responseAdmission, configured.MaxRecvMsgSizeMiB)
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
	if capabilities == nil {
		return false, false, errors.New("capabilities: target returned an empty response")
	}
	// Capability negotiation and identity Subscribe responses share one
	// admission gate. Retain an independent immutable copy and release the
	// unary response lease before starting any identity stream, otherwise a
	// one-slot gate can deadlock the bootstrap.
	sessionCapabilities := proto.Clone(capabilities).(*gnmipb.CapabilityResponse)
	r.responseAdmission.release(capabilities)
	client := gnmipb.NewGNMIClient(conn)
	identity, err := discoverSharedGNMIDeviceIdentity(ctx, configured, client, sessionCapabilities, r.responseAdmission)
	if err != nil {
		return false, false, fmt.Errorf("discover subscribed identity: %w", err)
	}
	product, family, err := selectSharedGNMICatalogProduct(identity, configured.Platform, configured.ProductFamily)
	if err != nil {
		return false, false, fmt.Errorf("select generated gNMI catalog row: %w", err)
	}
	if configureErr := target.configureDiscoveredSession(identity, product, family, sessionCapabilities); configureErr != nil {
		return false, false, fmt.Errorf("plan discovered gNMI session: %w", configureErr)
	}
	r.telemetry.connection(ctx, configured.Name, true)
	connectedAt := time.Now()
	terminal, err := r.serveTargetStreams(ctx, target, client)
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
	selectedStreams, err := r.selectSharedGNMIStreamVariants(streamCtx, target, client, target.streams)
	if err != nil {
		return false, err
	}
	if err := target.applySelectedRuntimeStreams(selectedStreams); err != nil {
		return false, err
	}
	if err := target.beginSessionReadiness(selectedStreams); err != nil {
		return false, err
	}
	defer target.endSessionReadiness()
	results := make(chan sharedGNMIStreamResult, 32)
	retryEvents := make(chan uint64, 1)
	semaphore := make(chan struct{}, target.config.MaxStreams)
	streamCancels := map[string][]context.CancelFunc{}
	var wg sync.WaitGroup
	active := 0
	var retryGeneration uint64
	retryScheduled := false
	scheduleNegativeRetry := func() {
		retryGeneration++
		generation := retryGeneration
		retryAt, ok := target.nextNegativeRetry()
		retryScheduled = ok
		if !ok {
			return
		}
		_, now := target.negativeContext()
		delay := max(time.Duration(0), retryAt.Sub(now))
		wait := target.afterDelay(delay)
		go func() {
			select {
			case <-wait:
				select {
				case retryEvents <- generation:
				case <-streamCtx.Done():
				}
			case <-streamCtx.Done():
			}
		}()
	}
	launch := func(stream sharedGNMIRuntimeStream) error {
		if len(stream.variantFallbacks) > 0 {
			if stream.Required {
				if _, retry := target.nextNegativeRetry(); retry {
					return nil
				}
				return fmt.Errorf("required gNMI profile %q has no usable path-set variant", stream.Profile)
			}
			return nil
		}
		if target.profileStopped(sharedGNMIStreamSuppressionKey(stream.sharedGNMIStream)) {
			if stream.Required {
				return fmt.Errorf("required gNMI profile %q is stopped", stream.Profile)
			}
			return nil
		}
		stoppedGroups := make([]string, 0, len(stream.Groups))
		for _, group := range stream.Groups {
			if target.profileStopped(sharedGNMIGroupSuppressionKey(stream.Profile, group)) {
				stoppedGroups = append(stoppedGroups, group)
			}
		}
		if len(stoppedGroups) > 0 {
			filtered, _, available, filterErr := filterSharedGNMIRuntimeGroups(stream, stoppedGroups...)
			if filterErr != nil {
				return fmt.Errorf("filter stopped gNMI groups for profile %q: %w", stream.Profile, filterErr)
			}
			if !available {
				if stream.Required {
					return fmt.Errorf("required gNMI profile %q has no active groups", stream.Profile)
				}
				return nil
			}
			stream = filtered
		}
		stream.Paths = target.filterIsolatedPathSets(stream.Paths)
		if len(stream.Paths) == 0 {
			if stream.Required {
				if _, retry := target.nextNegativeRetry(); retry {
					return nil
				}
				return fmt.Errorf("required gNMI profile %q has no available subscription paths", stream.Profile)
			}
			return nil
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
		suppressionKey := sharedGNMIStreamSuppressionKey(stream.sharedGNMIStream)
		profileCancels[suppressionKey] = append(profileCancels[suppressionKey], subscriptionCancel)
		for _, group := range stream.Groups {
			groupKey := sharedGNMIGroupSuppressionKey(stream.Profile, group)
			profileCancels[groupKey] = append(profileCancels[groupKey], subscriptionCancel)
		}
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
			terminal, err := r.runSubscription(subscriptionCtx, target, client, stream, stream.wireEncoding)
			results <- sharedGNMIStreamResult{stream: stream, terminal: terminal, err: err}
		})
		return nil
	}
	for streamIndex := range selectedStreams {
		if err := launch(selectedStreams[streamIndex]); err != nil {
			cancel()
			wg.Wait()
			return false, err
		}
	}
	scheduleNegativeRetry()
	if active == 0 && !retryScheduled {
		return true, nil
	}
	for active > 0 || retryScheduled {
		select {
		case <-ctx.Done():
			cancel()
			wg.Wait()
			return false, ctx.Err()
		case generation := <-retryEvents:
			if generation != retryGeneration {
				continue
			}
			cancel()
			wg.Wait()
			return false, &sharedGNMINegativeRetryError{}
		case result := <-results:
			active--
			if target.profileStopped(sharedGNMIStreamSuppressionKey(result.stream.sharedGNMIStream)) {
				continue
			}
			stoppedGroups := target.stoppedGroupsForStream(result.stream.sharedGNMIStream)
			if len(stoppedGroups) > 0 {
				filtered, _, available, filterErr := filterSharedGNMIRuntimeGroups(result.stream, stoppedGroups...)
				if filterErr != nil {
					cancel()
					wg.Wait()
					return false, fmt.Errorf("replan profile %q after sibling group suppression: %w", result.stream.Profile, filterErr)
				}
				if available {
					if launchErr := launch(filtered); launchErr != nil {
						cancel()
						wg.Wait()
						return false, launchErr
					}
				}
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
				validGroups, resolutionErr := r.resolveUnsupportedGNMIPaths(streamCtx, target, client, result.stream, result.stream.wireEncoding)
				<-semaphore
				if resolutionErr != nil {
					var stopped *sharedGNMIProfileStopError
					if errors.As(resolutionErr, &stopped) {
						if result.stream.Required {
							if stopped.reason == "unsupported_path" {
								scheduleNegativeRetry()
								if retryScheduled {
									// Keep the required readiness entry unsynchronized and
									// the target unavailable until this fingerprint's
									// negative-capability window expires.
									continue
								}
							}
							cancel()
							wg.Wait()
							return false, fmt.Errorf("required gNMI profile %q failed: %w", result.stream.Profile, stopped)
						}
						reason := stopped.reason
						if reason == "" {
							reason = "bisection_limit"
						}
						r.stopGNMIProfile(ctx, target, result.stream, reason, stopped, profileCancels)
						scheduleNegativeRetry()
						continue
					}
					var timeout *sharedGNMISyncTimeoutError
					if errors.As(resolutionErr, &timeout) && !result.stream.Required {
						r.stopGNMIProfile(ctx, target, result.stream, "sync_timeout", timeout, profileCancels)
						scheduleNegativeRetry()
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
						capacityErr := fmt.Errorf(
							"the target accepts %d path groups separately, but they would require %d of %d allowed streams",
							len(validGroups), active+len(validGroups), target.config.MaxStreams,
						)
						if result.stream.Required {
							cancel()
							wg.Wait()
							return false, fmt.Errorf("required gNMI profile %q failed: %w", result.stream.Profile, capacityErr)
						}
						r.stopGNMIProfile(ctx, target, result.stream, "incompatible_path_group", capacityErr, profileCancels)
						scheduleNegativeRetry()
						continue
					}
				}
				validatedStreams := make([]sharedGNMIRuntimeStream, 0, len(validGroups))
				for _, validPaths := range validGroups {
					validated := result.stream
					validated.Paths = validPaths
					validatedStreams = append(validatedStreams, validated)
				}
				if err := target.replaceRequiredRuntimeStream(result.stream, validatedStreams); err != nil {
					cancel()
					wg.Wait()
					return false, err
				}
				for validatedIndex := range validatedStreams {
					if launchErr := launch(validatedStreams[validatedIndex]); launchErr != nil {
						cancel()
						wg.Wait()
						return false, launchErr
					}
				}
				scheduleNegativeRetry()
				continue
			}
			var stopped *sharedGNMIProfileStopError
			if errors.As(result.err, &stopped) {
				if result.stream.Required {
					cancel()
					wg.Wait()
					return false, fmt.Errorf("required gNMI profile %q failed: %w", result.stream.Profile, stopped)
				}
				reason := stopped.reason
				if reason == "" {
					reason = "cache_limit"
				}
				var entityCapacity *sharedGNMIEntityCapacityError
				if errors.As(stopped, &entityCapacity) {
					filtered, removedGroups, available, filterErr := filterSharedGNMIRuntimeGroups(result.stream, entityCapacity.Group)
					if filterErr != nil {
						cancel()
						wg.Wait()
						return false, fmt.Errorf("replan profile %q after max_entities overflow: %w", result.stream.Profile, filterErr)
					}
					if len(removedGroups) == 0 {
						cancel()
						wg.Wait()
						return false, fmt.Errorf("max_entities overflow group %q is absent from profile %q stream", entityCapacity.Group, result.stream.Profile)
					}
					r.stopGNMIGroups(ctx, target, result.stream, removedGroups, reason, stopped, profileCancels)
					if available {
						if launchErr := launch(filtered); launchErr != nil {
							cancel()
							wg.Wait()
							return false, launchErr
						}
					}
					scheduleNegativeRetry()
					continue
				}
				r.stopGNMIProfile(ctx, target, result.stream, reason, stopped, profileCancels)
				scheduleNegativeRetry()
				continue
			}
			var timeout *sharedGNMISyncTimeoutError
			if errors.As(result.err, &timeout) && !result.stream.Required {
				r.stopGNMIProfile(ctx, target, result.stream, "sync_timeout", timeout, profileCancels)
				scheduleNegativeRetry()
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
	probes := 0
	var resolve func([][]sharedGNMIPath) ([][]sharedGNMIPath, error)
	resolve = func(pathSets [][]sharedGNMIPath) ([][]sharedGNMIPath, error) {
		if len(pathSets) == 0 {
			return nil, nil
		}
		if len(pathSets) == 1 {
			paths := pathSets[0]
			for _, path := range paths {
				target.isolatePath(path)
				r.telemetry.degraded(ctx, target.config.Name, stream.Profile, "unsupported_path")
				r.settings.Logger.Warn("Cisco gNMI path suppressed until its retry window expires",
					zap.String("target", target.config.Name),
					zap.String("profile", stream.Profile),
					zap.String("path_set", sharedGNMIAtomicPathSetLabel(paths)),
					zap.String("origin", path.Origin),
					zap.String("path", path.Path))
			}
			if stream.Required {
				return nil, &sharedGNMIProfileStopError{
					reason: "unsupported_path",
					err:    fmt.Errorf("required subscription path set %q is unsupported", sharedGNMIAtomicPathSetLabel(paths)),
				}
			}
			return nil, nil
		}

		midpoint := len(pathSets) / 2
		halves := [][][]sharedGNMIPath{pathSets[:midpoint], pathSets[midpoint:]}
		validGroups := make([][]sharedGNMIPath, 0, 2)
		for _, half := range halves {
			probes++
			if probes > sharedGNMIMaxBisectionProbes {
				return nil, &sharedGNMIProfileStopError{
					reason: "bisection_limit",
					err:    fmt.Errorf("subscription bisection exceeded %d probes", sharedGNMIMaxBisectionProbes),
				}
			}
			probe := stream
			probe.Paths = flattenSharedGNMIAtomicPathSets(half)
			err := r.probeSubscriptionUntilSync(ctx, target, client, probe, encoding)
			if err == nil {
				validGroups = append(validGroups, probe.Paths)
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
		combined := make([]sharedGNMIPath, 0)
		for _, group := range validGroups {
			combined = append(combined, group...)
		}
		probes++
		if probes > sharedGNMIMaxBisectionProbes {
			return nil, &sharedGNMIProfileStopError{
				reason: "bisection_limit",
				err:    fmt.Errorf("subscription bisection exceeded %d probes", sharedGNMIMaxBisectionProbes),
			}
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

	return resolve(sharedGNMIAtomicPathSets(stream.Paths))
}

func sharedGNMIAtomicPathSets(paths []sharedGNMIPath) [][]sharedGNMIPath {
	if len(paths) == 0 {
		return nil
	}
	parents := make([]int, len(paths))
	for index := range parents {
		parents[index] = index
	}
	var find func(int) int
	find = func(index int) int {
		if parents[index] != index {
			parents[index] = find(parents[index])
		}
		return parents[index]
	}
	union := func(left, right int) {
		leftRoot, rightRoot := find(left), find(right)
		if leftRoot != rightRoot {
			parents[rightRoot] = leftRoot
		}
	}
	firstByPathSet := map[string]int{}
	for index, path := range paths {
		for _, pathSetVariant := range sharedGNMIPathSetVariantKeys(path) {
			if first, ok := firstByPathSet[pathSetVariant]; ok {
				union(first, index)
			} else {
				firstByPathSet[pathSetVariant] = index
			}
		}
	}
	groups := make([][]sharedGNMIPath, 0, len(paths))
	groupByRoot := map[int]int{}
	for index, path := range paths {
		root := find(index)
		groupIndex, ok := groupByRoot[root]
		if !ok {
			groupIndex = len(groups)
			groupByRoot[root] = groupIndex
			groups = append(groups, nil)
		}
		groups[groupIndex] = append(groups[groupIndex], path)
	}
	return groups
}

func sharedGNMIPathSetVariantKeys(path sharedGNMIPath) []string {
	keys := make([]string, 0, len(path.PathSetVariants)+1)
	if path.PathSetID != "" {
		keys = append(keys, path.PathSetID+"\x00"+path.VariantID)
	}
	for _, variant := range path.PathSetVariants {
		key := variant.PathSetID + "\x00" + variant.VariantID
		if variant.PathSetID != "" && !slices.Contains(keys, key) {
			keys = append(keys, key)
		}
	}
	return keys
}

func flattenSharedGNMIAtomicPathSets(pathSets [][]sharedGNMIPath) []sharedGNMIPath {
	count := 0
	for _, pathSet := range pathSets {
		count += len(pathSet)
	}
	paths := make([]sharedGNMIPath, 0, count)
	for _, pathSet := range pathSets {
		paths = append(paths, pathSet...)
	}
	return paths
}

func sharedGNMIAtomicPathSetLabel(paths []sharedGNMIPath) string {
	ids := make([]string, 0)
	for _, path := range paths {
		for _, key := range sharedGNMIPathSetVariantKeys(path) {
			pathSetID, variantID, _ := strings.Cut(key, "\x00")
			id := pathSetID
			if variantID != "" {
				id += "@" + variantID
			}
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return sharedGNMIPathKey(paths[0])
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
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
	if sendErr := subscribe.Send(request); sendErr != nil {
		return classifySharedGNMIStreamError(sendErr)
	}
	if stream.Mode == gnmiModeOnce {
		if closeErr := subscribe.CloseSend(); closeErr != nil {
			return classifySharedGNMIStreamError(closeErr)
		}
	}
	if stream.Mode == gnmiModeOnce {
		watchdog, watchdogErr := newSharedGNMISyncWatchdog(stream.Profile, sharedGNMISyncTimeoutForStream(target, stream), cancel)
		if watchdogErr != nil {
			return watchdogErr
		}
		return receiveSharedGNMIProbeOnceWithWatchdog(subscribe, r.responseAdmission, watchdog)
	}
	watchdog, err := newSharedGNMISyncWatchdog(stream.Profile, sharedGNMISyncTimeoutForStream(target, stream), cancel)
	if err != nil {
		return err
	}
	if receiveErr := receiveSharedGNMIProbeUntilSyncWithWatchdog(subscribe, r.responseAdmission, watchdog); receiveErr != nil {
		return receiveErr
	}
	if stream.Mode != gnmiModePoll {
		return nil
	}
	if sendErr := subscribe.Send(&gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Poll{Poll: &gnmipb.Poll{}}}); sendErr != nil {
		return classifySharedGNMIStreamError(sendErr)
	}
	watchdog, err = newSharedGNMISyncWatchdog(stream.Profile, sharedGNMISyncTimeoutForStream(target, stream), cancel)
	if err != nil {
		return err
	}
	return receiveSharedGNMIProbeUntilSyncWithWatchdog(subscribe, r.responseAdmission, watchdog)
}

func receiveSharedGNMIProbeUntilSync(
	subscribe grpc.BidiStreamingClient[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse],
	admission *gnmiResponseAdmission,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
) error {
	return receiveSharedGNMIProbeUntilSyncWithWatchdog(subscribe, admission, nil)
}

//nolint:staticcheck // Deprecated in-band Error responses remain on the supported gNMI wire protocol.
func receiveSharedGNMIProbeUntilSyncWithWatchdog(
	subscribe grpc.BidiStreamingClient[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse],
	admission *gnmiResponseAdmission,
	watchdog *sharedGNMISyncWatchdog,
) error {
	defer watchdog.finish()
	for {
		response, err := receiveGNMISubscribeResponse(subscribe, admission)
		if err != nil {
			if watchdog.finish() {
				return watchdog.timeoutError()
			}
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
			if watchdog.finish() {
				return watchdog.timeoutError()
			}
			return nil
		}
	}
}

func receiveSharedGNMIProbeOnce(
	subscribe grpc.BidiStreamingClient[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse],
	admission *gnmiResponseAdmission,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
) error {
	return receiveSharedGNMIProbeOnceWithWatchdog(subscribe, admission, nil)
}

//nolint:staticcheck // Deprecated in-band Error responses remain on the supported gNMI wire protocol.
func receiveSharedGNMIProbeOnceWithWatchdog(
	subscribe grpc.BidiStreamingClient[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse],
	admission *gnmiResponseAdmission,
	watchdog *sharedGNMISyncWatchdog,
) error {
	defer watchdog.finish()
	synced := false
	for {
		response, err := receiveGNMISubscribeResponse(subscribe, admission)
		if err != nil {
			if watchdog.finish() {
				return watchdog.timeoutError()
			}
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
			if body.SyncResponse && !synced {
				// ONCE is complete only after the server closes the stream.
				// Keep the configured deadline armed through that EOF.
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
	suppressionKey := sharedGNMIStreamSuppressionKey(stream.sharedGNMIStream)
	target.stopProfile(suppressionKey)
	for _, profileCancel := range profileCancels[suppressionKey] {
		profileCancel()
	}
	if target.config.Platform == gnmiPlatformNXOS && stream.Optics {
		r.clearTargetNXSensorState(ctx, target)
	}
	r.telemetry.degraded(ctx, target.config.Name, stream.Profile, reason)
	r.settings.Logger.Error("Cisco gNMI profile suppressed until its retry window expires",
		zap.String("target", target.config.Name),
		zap.String("profile", stream.Profile),
		zap.Bool("required", stream.Required),
		zap.String("reason", reason),
		zap.Error(err))
}

func (r *sharedGNMIReceiver) stopGNMIGroups(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
	groups []string,
	reason string,
	err error,
	profileCancels map[string][]context.CancelFunc,
) {
	for _, group := range groups {
		groupKey := sharedGNMIGroupSuppressionKey(stream.Profile, group)
		target.stopProfile(groupKey)
		for _, profileCancel := range profileCancels[groupKey] {
			profileCancel()
		}
	}
	r.telemetry.degraded(ctx, target.config.Name, stream.Profile, reason)
	r.settings.Logger.Error("Cisco gNMI groups suppressed until their retry window expires",
		zap.String("target", target.config.Name),
		zap.String("profile", stream.Profile),
		zap.Strings("groups", groups),
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
	subscriptionCtx, subscriptionCancel := context.WithCancel(ctx)
	defer subscriptionCancel()
	request, err := buildSharedGNMISubscribeRequest(target.config, stream.sharedGNMIStream, encoding)
	if err != nil {
		return false, err
	}
	subscribe, err := client.Subscribe(
		sharedGNMIOutgoingContext(subscriptionCtx, target.config),
		gnmiResponsePreflightCallOption(target.config.MaxRecvMsgSizeMiB, r.responseAdmission, subscriptionCtx.Done()),
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
		if err := r.receiveOnceToCompletion(ctx, target, stream, subscribe, subscriptionCancel); err != nil {
			return false, err
		}
		return true, nil
	case gnmiModePoll:
		if err := r.receiveUntilSync(ctx, target, stream, subscribe, subscriptionCancel); err != nil {
			return false, err
		}
		for {
			if err := subscribe.Send(&gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Poll{Poll: &gnmipb.Poll{}}}); err != nil {
				return false, classifySharedGNMIStreamError(err)
			}
			if err := r.receiveUntilSync(ctx, target, stream, subscribe, subscriptionCancel); err != nil {
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
		if err := r.receiveUntilSync(ctx, target, stream, subscribe, subscriptionCancel); err != nil {
			return false, err
		}
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
	cancel context.CancelFunc,
) error {
	watchdog, err := newSharedGNMISyncWatchdog(stream.Profile, sharedGNMISyncTimeoutForStream(target, stream), cancel)
	if err != nil {
		return err
	}
	defer watchdog.finish()
	synced := false
	for {
		response, err := receiveGNMISubscribeResponse(subscribe, r.responseAdmission)
		if err != nil {
			if watchdog.finish() {
				return watchdog.timeoutError()
			}
			if errors.Is(err, io.EOF) {
				if synced {
					if syncErr := r.completeRuntimeStreamSync(ctx, target, stream); syncErr != nil {
						return syncErr
					}
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
		if responseSynced && !synced {
			// Unlike STREAM/POLL, ONCE is not ready until clean EOF follows
			// sync. Keep both the watchdog and required-readiness gate armed.
			synced = true
		}
	}
}

func (r *sharedGNMIReceiver) receiveUntilSync(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
	subscribe grpc.BidiStreamingClient[gnmipb.SubscribeRequest, gnmipb.SubscribeResponse],
	cancel context.CancelFunc,
) error {
	watchdog, err := newSharedGNMISyncWatchdog(stream.Profile, sharedGNMISyncTimeoutForStream(target, stream), cancel)
	if err != nil {
		return err
	}
	defer watchdog.finish()
	for {
		response, err := receiveGNMISubscribeResponse(subscribe, r.responseAdmission)
		if err != nil {
			if watchdog.finish() {
				return watchdog.timeoutError()
			}
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
			if watchdog.finish() {
				return watchdog.timeoutError()
			}
			if err := r.completeRuntimeStreamSync(ctx, target, stream); err != nil {
				return err
			}
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
		return false, nil
	case *gnmipb.SubscribeResponse_SyncResponse:
		return body.SyncResponse, nil
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
	if target.runtimeStreamStopped(stream.sharedGNMIStream) {
		return nil
	}
	if err := r.acquireNotificationSlot(ctx); err != nil {
		return err
	}
	defer r.releaseNotificationSlot()
	if target.runtimeStreamStopped(stream.sharedGNMIStream) {
		return nil
	}
	receiptTime := time.Now()
	decoded, decodeStats, err := internalgnmi.DecodeNotificationWithSchema(
		target.config.Name,
		notification,
		receiptTime,
		stream.JSONListKeys,
	)
	if err != nil {
		r.telemetry.decodeErrors(ctx, target.config.Name, stream.Profile, 1)
		return &sharedGNMIProfileStopError{reason: "decode_error", err: fmt.Errorf("decode gNMI notification: %w", err)}
	}
	var nxTransaction *nxSensorTransaction
	if target.config.Platform == gnmiPlatformNXOS && stream.Optics {
		decoded, nxTransaction, err = target.prepareNXNotificationForOwner(sharedGNMICacheOwnerID(stream), decoded)
		if err != nil {
			return &sharedGNMIProfileStopError{reason: "decode_error", err: err}
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
			return &sharedGNMIProfileStopError{reason: "cache_limit", err: err}
		}
		return err
	}
	defer func() {
		if cacheTransaction != nil {
			cacheTransaction.Rollback()
		}
	}()
	result := cacheTransaction.Result()
	if target.runtimeStreamStopped(stream.sharedGNMIStream) {
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
	entityLimitTransaction, err := target.sessionEntityLimits().prepare(result)
	if err != nil {
		var capacity *sharedGNMIEntityCapacityError
		if errors.As(err, &capacity) {
			return &sharedGNMIProfileStopError{reason: "entity_limit", err: err}
		}
		return &sharedGNMIProfileStopError{reason: "entity_accounting", err: err}
	}
	defer func() {
		if entityLimitTransaction != nil {
			entityLimitTransaction.rollback()
		}
	}()
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
			return &sharedGNMIProfileStopError{reason: "cache_limit", err: errors.New("gNMI auxiliary-state accounting overflow")}
		}
	}
	var auxiliaryReservation *sharedGNMIAuxiliaryReservation
	if nxTransaction != nil || presenceTransaction != nil {
		auxiliaryReservation, err = prepareSharedGNMIAuxiliaryReservation(target.nxBudget, auxiliaryDelta)
		if err != nil {
			return &sharedGNMIProfileStopError{reason: "cache_limit", err: err}
		}
		defer func() {
			if auxiliaryReservation != nil {
				auxiliaryReservation.rollback()
			}
		}()
	}
	chunks, err := internalgnmi.BuildMetricChunks(points, r.maxDatapoints)
	if err != nil {
		return &sharedGNMIProfileStopError{reason: "decode_error", err: err}
	}
	for chunkIndex, chunk := range chunks {
		config, identity := target.sessionResourceIdentity()
		decorateSharedGNMIResources(chunk, config, identity)
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
	_, stopped := target.stopped[sharedGNMIStreamSuppressionKey(stream.sharedGNMIStream)]
	if stopped {
		target.stateMu.RUnlock()
		return nil
	}
	cacheTransaction.Commit()
	cacheTransaction = nil
	if entityLimitTransaction != nil {
		entityLimitTransaction.commit()
		entityLimitTransaction = nil
	}
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

func (r *sharedGNMIReceiver) completeRuntimeStreamSync(
	ctx context.Context,
	target *sharedGNMITargetRuntime,
	stream sharedGNMIRuntimeStream,
) error {
	// A packed sibling can be canceled after another stream suppresses one of
	// its groups. Do not let a late sync_response from that sibling clear the
	// group's negative-capability entry or satisfy session readiness.
	if target.runtimeStreamStopped(stream.sharedGNMIStream) {
		return nil
	}
	target.clearNegativeForStream(stream)
	ready, err := target.markRuntimeStreamSynced(stream)
	if err != nil {
		return err
	}
	if ready && !r.emitTargetAvailable(ctx, target) {
		return errors.New("downstream consumer refused Cisco gNMI target availability")
	}
	return nil
}

func (r *sharedGNMIReceiver) emitTargetAvailable(ctx context.Context, target *sharedGNMITargetRuntime) bool {
	if target.sessionUp.CompareAndSwap(false, true) {
		if !r.emitAvailability(ctx, target, true) {
			// A refused or canceled availability signal was not delivered. Let a
			// later notification retry it instead of pinning the local state to up.
			target.sessionUp.CompareAndSwap(true, false)
			return false
		}
	}
	return target.sessionUp.Load()
}

func (r *sharedGNMIReceiver) emitAvailability(ctx context.Context, target *sharedGNMITargetRuntime, up bool) bool {
	if err := r.acquireNotificationSlot(ctx); err != nil {
		return false
	}
	defer r.releaseNotificationSlot()
	config, identity := target.sessionResourceIdentity()
	value := int64(0)
	if up {
		value = 1
	}
	point := internalgnmi.MappedPoint{
		Source: internalgnmi.Series{
			Target: config.Name, Origin: builtinGNMISyntheticReceiverOrigin,
			Elements: []internalgnmi.PathElem{{Name: "target"}, {Name: config.Platform}}, Leaf: "up",
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
	decorateSharedGNMIResources(chunks[0], config, identity)
	opCtx := startMetricsOp(ctx, r.obs)
	consumeErr := r.consumer.ConsumeMetrics(opCtx, chunks[0])
	endMetricsOp(opCtx, r.obs, chunks[0].DataPointCount(), consumeErr)
	if consumeErr != nil {
		r.telemetry.consumerRefusal(ctx, config.Name, builtinGNMIProfileIdentity)
	}
	return consumeErr == nil
}

func decorateSharedGNMIResources(
	metrics pmetric.Metrics,
	target GNMITargetConfig,
	identity sharedGNMIDeviceIdentity,
) {
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
		platformFamily := target.ProductFamily
		if platformFamily == "" {
			platformFamily = target.Platform
		}
		attributes.PutStr("cisco.platform.family", platformFamily)
		attributes.PutStr("cisco.telemetry.transport", "gnmi_dial_in")
		putStr(attributes, "device.manufacturer", identity.Manufacturer)
		putStr(attributes, "device.model.identifier", identity.ModelIdentifier)
		putStr(attributes, "os.version", identity.SoftwareVersion)
		putStr(attributes, "hw.serial_number", identity.SerialNumber)
		putStr(attributes, "host.id", identity.SerialNumber)
		hostName := identity.Hostname
		if hostName == "" {
			hostName = target.Name
		}
		putStr(attributes, "host.name", hostName)
		hostType := identity.Platform
		if hostType == "" {
			hostType = identity.ModelIdentifier
		}
		putStr(attributes, "host.type", hostType)
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

func (target *sharedGNMITargetRuntime) beginSessionReadiness(streams []sharedGNMIRuntimeStream) error {
	readiness := &sharedGNMISessionReadiness{required: map[string]bool{}}
	for index := range streams {
		if !streams[index].Required {
			continue
		}
		readiness.hasRequired = true
		key := sharedGNMIReadinessStreamKey(streams[index])
		if _, duplicate := readiness.required[key]; duplicate {
			return fmt.Errorf("duplicate required gNMI runtime stream %q", streams[index].Profile)
		}
		readiness.required[key] = false
	}
	target.readinessMu.Lock()
	target.readiness = readiness
	target.readinessMu.Unlock()
	return nil
}

func (target *sharedGNMITargetRuntime) endSessionReadiness() {
	target.readinessMu.Lock()
	target.readiness = nil
	target.readinessMu.Unlock()
}

func (target *sharedGNMITargetRuntime) replaceRequiredRuntimeStream(
	previous sharedGNMIRuntimeStream,
	replacements []sharedGNMIRuntimeStream,
) error {
	if !previous.Required {
		return nil
	}
	target.readinessMu.Lock()
	defer target.readinessMu.Unlock()
	if target.readiness == nil {
		return errors.New("gNMI session readiness is not initialized")
	}
	previousKey := sharedGNMIReadinessStreamKey(previous)
	if _, exists := target.readiness.required[previousKey]; !exists {
		return fmt.Errorf("required gNMI runtime stream %q is not registered", previous.Profile)
	}
	delete(target.readiness.required, previousKey)
	for index := range replacements {
		key := sharedGNMIReadinessStreamKey(replacements[index])
		if _, duplicate := target.readiness.required[key]; duplicate {
			return fmt.Errorf("duplicate replacement for required gNMI runtime stream %q", previous.Profile)
		}
		target.readiness.required[key] = false
	}
	if len(replacements) == 0 {
		return fmt.Errorf("required gNMI runtime stream %q has no supported replacement", previous.Profile)
	}
	return nil
}

func (target *sharedGNMITargetRuntime) markRuntimeStreamSynced(stream sharedGNMIRuntimeStream) (bool, error) {
	target.readinessMu.Lock()
	defer target.readinessMu.Unlock()
	if target.readiness == nil {
		return false, errors.New("gNMI session readiness is not initialized")
	}
	if !target.readiness.hasRequired {
		target.readiness.anySynced = true
		return true, nil
	}
	if !stream.Required {
		return false, nil
	}
	key := sharedGNMIReadinessStreamKey(stream)
	if _, exists := target.readiness.required[key]; !exists {
		return false, fmt.Errorf("required gNMI runtime stream %q is not registered", stream.Profile)
	}
	target.readiness.required[key] = true
	for _, synced := range target.readiness.required {
		if !synced {
			return false, nil
		}
	}
	return true, nil
}

func sharedGNMIReadinessStreamKey(stream sharedGNMIRuntimeStream) string {
	var key strings.Builder
	key.WriteString(sharedGNMIRejectedPathSetKey(stream))
	key.WriteByte(0)
	key.WriteString(stream.StreamMode)
	key.WriteByte(0)
	key.WriteString(stream.Encoding)
	fmt.Fprintf(&key, "\x00%d\x00%d\x00%d", stream.SampleInterval, stream.PollInterval, stream.SyncTimeout)
	return key.String()
}

func (target *sharedGNMITargetRuntime) isolatePath(path sharedGNMIPath) {
	fingerprint, now := target.negativeContext()
	target.stateMu.Lock()
	defer target.stateMu.Unlock()
	key := sharedGNMIPathKey(path)
	target.isolate[key] = nextSharedGNMINegativeEntry(target.isolate[key], fingerprint, now)
}

func (target *sharedGNMITargetRuntime) stopProfile(profile string) {
	fingerprint, now := target.negativeContext()
	target.stateMu.Lock()
	defer target.stateMu.Unlock()
	target.stopped[profile] = nextSharedGNMINegativeEntry(target.stopped[profile], fingerprint, now)
}

func (target *sharedGNMITargetRuntime) profileStopped(profile string) bool {
	fingerprint, now := target.negativeContext()
	target.stateMu.RLock()
	defer target.stateMu.RUnlock()
	entry, stopped := target.stopped[profile]
	return stopped && entry.fingerprint == fingerprint && now.Before(entry.retryAt)
}

func (target *sharedGNMITargetRuntime) stoppedGroupsForStream(stream sharedGNMIStream) []string {
	groups := make([]string, 0, len(stream.Groups))
	for _, group := range stream.Groups {
		if target.profileStopped(sharedGNMIGroupSuppressionKey(stream.Profile, group)) {
			groups = append(groups, group)
		}
	}
	return groups
}

func (target *sharedGNMITargetRuntime) runtimeStreamStopped(stream sharedGNMIStream) bool {
	return target.profileStopped(sharedGNMIStreamSuppressionKey(stream)) || len(target.stoppedGroupsForStream(stream)) > 0
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
	fingerprint, now := target.negativeContext()
	target.stateMu.RLock()
	defer target.stateMu.RUnlock()
	entry, isolated := target.isolate[sharedGNMIPathKey(path)]
	return isolated && entry.fingerprint == fingerprint && now.Before(entry.retryAt)
}

func (target *sharedGNMITargetRuntime) clearNegativeForStream(stream sharedGNMIRuntimeStream) {
	fingerprint, _ := target.negativeContext()
	target.stateMu.Lock()
	defer target.stateMu.Unlock()
	suppressionKey := sharedGNMIStreamSuppressionKey(stream.sharedGNMIStream)
	if entry, ok := target.stopped[suppressionKey]; ok && entry.fingerprint == fingerprint {
		delete(target.stopped, suppressionKey)
	}
	for _, group := range stream.Groups {
		key := sharedGNMIGroupSuppressionKey(stream.Profile, group)
		if entry, ok := target.stopped[key]; ok && entry.fingerprint == fingerprint {
			delete(target.stopped, key)
		}
	}
	for _, path := range stream.Paths {
		key := sharedGNMIPathKey(path)
		if entry, ok := target.isolate[key]; ok && entry.fingerprint == fingerprint {
			delete(target.isolate, key)
		}
	}
}

func (target *sharedGNMITargetRuntime) nextNegativeRetry() (time.Time, bool) {
	fingerprint, now := target.negativeContext()
	target.stateMu.RLock()
	defer target.stateMu.RUnlock()
	var earliest time.Time
	for _, entries := range []map[string]sharedGNMINegativeEntry{target.stopped, target.isolate} {
		for _, entry := range entries {
			if entry.fingerprint != fingerprint || !now.Before(entry.retryAt) {
				continue
			}
			if earliest.IsZero() || entry.retryAt.Before(earliest) {
				earliest = entry.retryAt
			}
		}
	}
	return earliest, !earliest.IsZero()
}

func (target *sharedGNMITargetRuntime) negativeContext() (string, time.Time) {
	target.sessionMu.RLock()
	fingerprint := target.fingerprint
	target.sessionMu.RUnlock()
	now := time.Now()
	if target.now != nil {
		now = target.now()
	}
	return fingerprint, now
}

func (target *sharedGNMITargetRuntime) afterDelay(delay time.Duration) <-chan time.Time {
	if target.after != nil {
		return target.after(delay)
	}
	return time.After(delay)
}

func nextSharedGNMINegativeEntry(
	previous sharedGNMINegativeEntry,
	fingerprint string,
	now time.Time,
) sharedGNMINegativeEntry {
	failures := 1
	if previous.fingerprint == fingerprint {
		failures = previous.failures + 1
	}
	return sharedGNMINegativeEntry{
		fingerprint: fingerprint,
		failures:    failures,
		retryAt:     now.Add(sharedGNMINegativeRetryDelay(failures)),
	}
}

func sharedGNMINegativeRetryDelay(failures int) time.Duration {
	if failures <= 1 {
		return sharedGNMINegativeRetryMinimum
	}
	delay := sharedGNMINegativeRetryMinimum
	for range failures - 1 {
		if delay >= sharedGNMINegativeRetryMaximum/2 {
			return sharedGNMINegativeRetryMaximum
		}
		delay *= 2
	}
	return min(delay, sharedGNMINegativeRetryMaximum)
}

func sharedGNMIPathKey(path sharedGNMIPath) string { return path.Origin + "\x00" + path.Path }

func sharedGNMIStreamSuppressionKey(stream sharedGNMIStream) string {
	if len(stream.Groups) == 0 {
		return stream.Profile
	}
	return stream.Profile + "\x00" + strings.Join(stream.Groups, "\x00")
}

func sharedGNMIRejectedPathSetKey(stream sharedGNMIRuntimeStream) string {
	var key strings.Builder
	appendSharedGNMIKeyPart(&key, path.PathTarget)
	appendSharedGNMIKeyPart(&key, path.Origin)
	appendSharedGNMIKeyPart(&key, path.Path)
	return key.String()
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
