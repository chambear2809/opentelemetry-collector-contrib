// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package ciscoosreceiver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	receiverhttpclient "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
	componentmetadata "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metadata"
)

const (
	gnmiProductE2EEndpointEnv       = "CISCOOS_E2E_GNMI_ENDPOINT"
	gnmiProductE2EUsernameEnv       = "CISCOOS_E2E_GNMI_USERNAME"
	gnmiProductE2EPasswordEnv       = "CISCOOS_E2E_GNMI_PASSWORD"
	gnmiProductE2ECAFileEnv         = "CISCOOS_E2E_GNMI_CA_FILE"
	gnmiProductE2EServerNameEnv     = "CISCOOS_E2E_GNMI_SERVER_NAME"
	gnmiProductE2EClientCertEnv     = "CISCOOS_E2E_GNMI_CLIENT_CERT_FILE"
	gnmiProductE2EClientKeyEnv      = "CISCOOS_E2E_GNMI_CLIENT_KEY_FILE"
	gnmiProductE2EProductEnv        = "CISCOOS_E2E_GNMI_PRODUCT"
	gnmiProductE2EVersionEnv        = "CISCOOS_E2E_GNMI_SOFTWARE_VERSION"
	gnmiProductE2EModelEnv          = "CISCOOS_E2E_GNMI_MODEL_IDENTIFIER"
	gnmiProductE2EMetricsEnv        = "CISCOOS_E2E_GNMI_REQUIRED_METRICS"
	gnmiProductE2EIntervalEnv       = "CISCOOS_E2E_GNMI_SAMPLE_INTERVAL"
	gnmiProductE2EWaitEnv           = "CISCOOS_E2E_GNMI_WAIT_TIMEOUT"
	gnmiProductE2EBackendURL        = "CISCOOS_E2E_GNMI_BACKEND_ASSERT_URL"
	gnmiProductE2EBackendToken      = "CISCOOS_E2E_GNMI_BACKEND_BEARER_TOKEN" //nolint:gosec // Environment variable name, not a credential.
	gnmiProductE2EMinimumIntervals  = 3
	gnmiProductE2EMaxAssertionBytes = 64 * 1024
	gnmiProductE2EMinimumInterval   = time.Second
	gnmiProductE2EMaximumInterval   = 5 * time.Minute
	gnmiProductE2EMaximumWait       = 30 * time.Minute
)

// TestE2EProductQualifiedGNMI is the release-qualification harness for the
// five shared gNMI product contracts. It deliberately requires an external,
// read-only backend assertion endpoint; a local consumer pass alone is not a
// retained backend-delivery qualification.
func TestE2EProductQualifiedGNMI(t *testing.T) {
	endpoint := requiredEnvOrSkip(t, gnmiProductE2EEndpointEnv)
	username := requiredEnvOrSkip(t, gnmiProductE2EUsernameEnv)
	password := requiredEnvOrSkip(t, gnmiProductE2EPasswordEnv)
	product := requiredEnvOrSkip(t, gnmiProductE2EProductEnv)
	softwareVersion := requiredEnvOrSkip(t, gnmiProductE2EVersionEnv)
	expectedModel := requiredEnvOrSkip(t, gnmiProductE2EModelEnv)
	backendURL := requiredEnvOrSkip(t, gnmiProductE2EBackendURL)
	contract, canonicalVersion, err := resolveGNMIProductContract(product, softwareVersion)
	require.NoError(t, err)
	requiredMetrics := csvEnv(gnmiProductE2EMetricsEnv)
	require.NotEmpty(t, requiredMetrics, "%s must name the metrics required for this exact-build qualification", gnmiProductE2EMetricsEnv)
	requiredMetrics = removeString(requiredMetrics, "cisco.device.up")
	if product == gnmiProductCatalyst9800 {
		requiredMetrics = appendUniqueStrings(requiredMetrics,
			"cisco.wlc.ap.join.status",
			"cisco.wlc.rf.channel.utilization",
			"cisco.wlc.ssid.client.count",
		)
	}
	require.NotEmpty(t, requiredMetrics, "%s must include at least one periodically collected profile metric", gnmiProductE2EMetricsEnv)
	runID := newGNMIProductE2ERunID(t)
	qualificationStarted := time.Now().UTC()

	interval := durationEnv(t, gnmiProductE2EIntervalEnv, 10*time.Second)
	waitTimeout := durationEnv(t, gnmiProductE2EWaitEnv, 3*time.Minute)
	require.NoError(t, validateGNMIProductE2EDurations(interval, waitTimeout))

	enabled, disabled := true, false
	_, systemProfileSupported := builtinGNMIProfile(contract, builtinGNMIProfileSystem)
	target := GNMITargetConfig{
		Name:            "product-qualified-live-" + runID,
		Endpoint:        endpoint,
		Product:         product,
		SoftwareVersion: softwareVersion,
		MaxStreams:      4,
		Credentials: GNMICredentialsConfig{
			Mode: gnmiCredentialUsernamePassword, Username: username, Password: configopaque.String(password),
		},
		TLS: GNMITLSConfig{
			CAFile:             os.Getenv(gnmiProductE2ECAFileEnv),
			ServerNameOverride: os.Getenv(gnmiProductE2EServerNameEnv),
			MinVersion:         "1.2",
		},
		Profiles: GNMIProfilesConfig{
			Identity:             gnmiProductE2EProfileConfig(enabled, interval),
			System:               gnmiProductE2EProfileConfig(systemProfileSupported, interval),
			Interfaces:           gnmiProductE2EProfileConfig(enabled, interval),
			Optics:               gnmiProductE2EProfileConfig(disabled, interval),
			Catalyst9800Wireless: gnmiProductE2EProfileConfig(product == gnmiProductCatalyst9800, interval),
		},
	}
	target.TLS.CertFile = os.Getenv(gnmiProductE2EClientCertEnv)
	target.TLS.KeyFile = os.Getenv(gnmiProductE2EClientKeyEnv)
	if target.TLS.CertFile != "" || target.TLS.KeyFile != "" {
		require.NotEmpty(t, target.TLS.CertFile)
		require.NotEmpty(t, target.TLS.KeyFile)
		target.Credentials.Mode = gnmiCredentialMTLSUsernamePassword
	}
	plannedStreams, err := buildSharedGNMIStreams(target)
	require.NoError(t, err)
	require.LessOrEqual(t, len(plannedStreams), target.MaxStreams, "baseline qualification must fit the pre-qualified stream limit")
	expectedSubscriptions := make(map[string]int64)
	for index := range plannedStreams {
		expectedSubscriptions[plannedStreams[index].Profile]++
	}

	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.GNMI = GNMIConfig{MaxDatapointsPerChunk: 10_000, MaxCachedSeries: 500_000, Targets: []GNMITargetConfig{target}}
	require.NoError(t, cfg.Validate())

	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { assert.NoError(t, provider.Shutdown(context.Background())) })
	settings := receivertest.NewNopSettings(componentmetadata.Type)
	settings.MeterProvider = provider
	sink := newGNMIProductQualificationSink(qualificationStarted, interval, requiredMetrics)
	receiver, err := NewFactory().CreateMetrics(t.Context(), settings, cfg, sink)
	require.NoError(t, err)
	require.NoError(t, receiver.Start(t.Context(), componenttest.NewNopHost()))
	t.Cleanup(func() { assert.NoError(t, receiver.Shutdown(context.Background())) })

	require.EventuallyWithT(t, func(tt *assert.CollectT) {
		summary := summarizeGNMIProductQualification(sink.AllMetrics(), requiredMetrics)
		assert.True(tt, summary.verifiedResource(product, expectedModel, canonicalVersion.Canonical), "verified resource identity was not delivered")
		assert.True(tt, summary.deviceUp, "cisco.device.up=1 was not delivered")
		if product == gnmiProductCatalyst9800 {
			assert.True(tt, summary.positiveValues["cisco.wlc.ap.join.status"], "no joined access point was observed")
			assert.True(tt, summary.positiveValues["cisco.wlc.ssid.client.count"], "no associated wireless client was observed")
		}
		assert.GreaterOrEqual(tt, time.Since(qualificationStarted), time.Duration(gnmiProductE2EMinimumIntervals)*interval,
			"qualification must observe three complete wall-clock collection intervals")
		for _, metricName := range requiredMetrics {
			assert.GreaterOrEqual(tt, sink.consecutiveRecentIntervalCount(metricName, time.Now()), gnmiProductE2EMinimumIntervals,
				"metric %s did not arrive for one series in three recent consecutive wall-clock intervals", metricName)
		}
	}, waitTimeout, time.Second)

	telemetry := collectGNMIProductE2ETelemetry(t, reader, target.Name)
	assert.Equal(t, int64(1), telemetry.productVerified)
	assert.Zero(t, telemetry.preflightFailures)
	assert.Zero(t, telemetry.degradedProfiles)
	assert.Equal(t, expectedSubscriptions, telemetry.activeSubscriptions,
		"every planned product/profile stream must remain active")

	remaining := time.Until(qualificationStarted.Add(waitTimeout))
	require.Positive(t, remaining, "local qualification exhausted the backend-delivery observation window")
	assertGNMIProductBackendDelivery(
		t,
		backendURL,
		product,
		canonicalVersion.Canonical,
		expectedModel,
		target.Name,
		runID,
		qualificationStarted,
		requiredMetrics,
		interval,
		remaining,
	)
	finalSummary := summarizeGNMIProductQualification(sink.AllMetrics(), requiredMetrics)
	assert.True(t, finalSummary.deviceUp, "the latest local availability value changed after qualification")
	finalTelemetry := collectGNMIProductE2ETelemetry(t, reader, target.Name)
	assert.Equal(t, int64(1), finalTelemetry.productVerified)
	assert.Zero(t, finalTelemetry.preflightFailures)
	assert.Zero(t, finalTelemetry.degradedProfiles)
	assert.Equal(t, expectedSubscriptions, finalTelemetry.activeSubscriptions)
	t.Logf("qualified run=%s product=%s model=%s version=%s metrics=%v intervals=%d",
		runID, product, expectedModel, canonicalVersion.Canonical, requiredMetrics, gnmiProductE2EMinimumIntervals)
}

func gnmiProductE2EProfileConfig(enabled bool, interval time.Duration) GNMIProfileConfig {
	configured := GNMIProfileConfig{Enabled: &enabled}
	if enabled {
		configured.Required = true
		configured.SampleInterval = interval
	}
	return configured
}

func newGNMIProductE2ERunID(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 16)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	return hex.EncodeToString(raw)
}

func validateGNMIProductE2EDurations(interval, waitTimeout time.Duration) error {
	if interval < gnmiProductE2EMinimumInterval || interval > gnmiProductE2EMaximumInterval {
		return fmt.Errorf("%s must be between %s and %s", gnmiProductE2EIntervalEnv, gnmiProductE2EMinimumInterval, gnmiProductE2EMaximumInterval)
	}
	minimumWait := time.Duration(gnmiProductE2EMinimumIntervals) * interval
	if waitTimeout < minimumWait || waitTimeout > gnmiProductE2EMaximumWait {
		return fmt.Errorf("%s must be between %s and %s", gnmiProductE2EWaitEnv, minimumWait, gnmiProductE2EMaximumWait)
	}
	return nil
}

type gnmiProductQualificationSink struct {
	sink     consumertest.MetricsSink
	started  time.Time
	interval time.Duration
	wanted   map[string]struct{}

	mu      sync.Mutex
	buckets map[string]map[string]map[int64]struct{}
}

func newGNMIProductQualificationSink(started time.Time, interval time.Duration, metrics []string) *gnmiProductQualificationSink {
	wanted := make(map[string]struct{}, len(metrics))
	buckets := make(map[string]map[string]map[int64]struct{}, len(metrics))
	for _, metricName := range metrics {
		wanted[metricName] = struct{}{}
		buckets[metricName] = map[string]map[int64]struct{}{}
	}
	return &gnmiProductQualificationSink{started: started, interval: interval, wanted: wanted, buckets: buckets}
}

func (*gnmiProductQualificationSink) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (s *gnmiProductQualificationSink) ConsumeMetrics(ctx context.Context, metrics pmetric.Metrics) error {
	s.recordAt(metrics, time.Now())
	return s.sink.ConsumeMetrics(ctx, metrics)
}

func (s *gnmiProductQualificationSink) recordAt(metrics pmetric.Metrics, received time.Time) {
	if s == nil || s.interval <= 0 {
		return
	}
	series := map[string]map[string]struct{}{}
	for i := 0; i < metrics.ResourceMetrics().Len(); i++ {
		scopes := metrics.ResourceMetrics().At(i).ScopeMetrics()
		for j := 0; j < scopes.Len(); j++ {
			items := scopes.At(j).Metrics()
			for k := 0; k < items.Len(); k++ {
				item := items.At(k)
				if _, wanted := s.wanted[item.Name()]; !wanted {
					continue
				}
				visitNumberDataPoints(item, func(point pmetric.NumberDataPoint) {
					attributes, err := json.Marshal(point.Attributes().AsRaw())
					if err != nil {
						return
					}
					if series[item.Name()] == nil {
						series[item.Name()] = map[string]struct{}{}
					}
					series[item.Name()][string(attributes)] = struct{}{}
				})
			}
		}
	}
	bucket := received.Sub(s.started) / s.interval
	if bucket < 0 {
		bucket = 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for metricName, identities := range series {
		for identity := range identities {
			if s.buckets[metricName][identity] == nil {
				s.buckets[metricName][identity] = map[int64]struct{}{}
			}
			s.buckets[metricName][identity][int64(bucket)] = struct{}{}
		}
	}
}

func (s *gnmiProductQualificationSink) intervalCount(metricName string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	maximum := 0
	for _, buckets := range s.buckets[metricName] {
		maximum = max(maximum, len(buckets))
	}
	return maximum
}

func (s *gnmiProductQualificationSink) consecutiveRecentIntervalCount(metricName string, observed time.Time) int {
	if s == nil || s.interval <= 0 {
		return 0
	}
	current := int64(observed.Sub(s.started) / s.interval)
	if current < 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	maximum := 0
	for _, buckets := range s.buckets[metricName] {
		for _, end := range []int64{current, current - 1} {
			count := 0
			for bucket := end; bucket >= 0; bucket-- {
				if _, present := buckets[bucket]; !present {
					break
				}
				count++
			}
			maximum = max(maximum, count)
		}
	}
	return maximum
}

func (s *gnmiProductQualificationSink) AllMetrics() []pmetric.Metrics {
	return s.sink.AllMetrics()
}

func TestGNMIProductE2EDurationBounds(t *testing.T) {
	for _, test := range []struct {
		name     string
		interval time.Duration
		wait     time.Duration
		wantErr  bool
	}{
		{name: "valid", interval: 10 * time.Second, wait: 3 * time.Minute},
		{name: "interval too short", interval: time.Millisecond, wait: time.Minute, wantErr: true},
		{name: "interval too long", interval: 6 * time.Minute, wait: 20 * time.Minute, wantErr: true},
		{name: "wait shorter than intervals", interval: time.Minute, wait: 2 * time.Minute, wantErr: true},
		{name: "wait too long", interval: time.Minute, wait: 31 * time.Minute, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateGNMIProductE2EDurations(test.interval, test.wait)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestGNMIProductE2EDisabledProfileHasNoConfiguration(t *testing.T) {
	profile := gnmiProductE2EProfileConfig(false, 10*time.Second)
	require.NotNil(t, profile.Enabled)
	assert.False(t, *profile.Enabled)
	assert.False(t, profile.Required)
	assert.Zero(t, profile.SampleInterval)
}

func TestGNMIProductQualificationSinkUsesWallClockBuckets(t *testing.T) {
	started := time.Unix(1_700_000_000, 0)
	interval := 10 * time.Second
	sink := newGNMIProductQualificationSink(started, interval, []string{"test.metric"})
	metrics := pmetric.NewMetrics()
	metricValue := metrics.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	metricValue.SetName("test.metric")
	metricValue.SetEmptyGauge().DataPoints().AppendEmpty().SetIntValue(1)

	for offset := range 3 {
		sink.recordAt(metrics, started.Add(time.Duration(offset)*time.Millisecond))
	}
	assert.Equal(t, 1, sink.intervalCount("test.metric"), "rapid initial-sync batches are one interval")
	sink.recordAt(metrics, started.Add(interval))
	sink.recordAt(metrics, started.Add(2*interval))
	assert.Equal(t, 3, sink.intervalCount("test.metric"))
	assert.Equal(t, 3, sink.consecutiveRecentIntervalCount("test.metric", started.Add(2*interval)))
	assert.Equal(t, 3, sink.consecutiveRecentIntervalCount("test.metric", started.Add(3*interval)))
	assert.Zero(t, sink.consecutiveRecentIntervalCount("test.metric", started.Add(4*interval)), "stale intervals cannot satisfy a current qualification")

	alternating := newGNMIProductQualificationSink(started, interval, []string{"test.metric"})
	point := metricValue.Gauge().DataPoints().At(0)
	for bucket, identity := range []string{"a", "b", "c"} {
		point.Attributes().PutStr("series", identity)
		alternating.recordAt(metrics, started.Add(time.Duration(bucket)*interval))
	}
	assert.Equal(t, 1, alternating.intervalCount("test.metric"), "different series cannot fabricate repeated intervals")
}

type gnmiProductQualificationSummary struct {
	resources      []map[string]string
	deviceUp       bool
	deviceUpSeen   bool
	deviceUpTime   uint64
	positiveValues map[string]bool
}

func summarizeGNMIProductQualification(all []pmetric.Metrics, required []string) gnmiProductQualificationSummary {
	summary := gnmiProductQualificationSummary{
		positiveValues: map[string]bool{},
	}
	wanted := make(map[string]struct{}, len(required))
	for _, name := range required {
		wanted[name] = struct{}{}
	}
	wanted["cisco.device.up"] = struct{}{}
	for _, metrics := range all {
		for i := 0; i < metrics.ResourceMetrics().Len(); i++ {
			resourceMetrics := metrics.ResourceMetrics().At(i)
			resource := map[string]string{}
			for _, key := range []string{"cisco.product.family", "device.manufacturer", "device.model.identifier", "os.version"} {
				if value, ok := resourceMetrics.Resource().Attributes().Get(key); ok {
					resource[key] = value.Str()
				}
			}
			summary.resources = append(summary.resources, resource)
			for j := 0; j < resourceMetrics.ScopeMetrics().Len(); j++ {
				metricsSlice := resourceMetrics.ScopeMetrics().At(j).Metrics()
				for k := 0; k < metricsSlice.Len(); k++ {
					metricValue := metricsSlice.At(k)
					if _, ok := wanted[metricValue.Name()]; !ok {
						continue
					}
					visitNumberDataPoints(metricValue, func(point pmetric.NumberDataPoint) {
						if metricValue.Name() == "cisco.device.up" {
							timestamp := uint64(point.Timestamp())
							if !summary.deviceUpSeen || timestamp >= summary.deviceUpTime {
								summary.deviceUpSeen = true
								summary.deviceUpTime = timestamp
								summary.deviceUp = point.IntValue() == 1
							}
							return
						}
						summary.positiveValues[metricValue.Name()] = summary.positiveValues[metricValue.Name()] || numberDataPointPositive(point)
					})
				}
			}
		}
	}
	return summary
}

func numberDataPointPositive(point pmetric.NumberDataPoint) bool {
	switch point.ValueType() {
	case pmetric.NumberDataPointValueTypeInt:
		return point.IntValue() > 0
	case pmetric.NumberDataPointValueTypeDouble:
		return point.DoubleValue() > 0
	default:
		return false
	}
}

func TestSummarizeGNMIProductQualificationUsesLatestAvailability(t *testing.T) {
	availability := func(timestamp time.Time, value int64) pmetric.Metrics {
		metrics := pmetric.NewMetrics()
		metricValue := metrics.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
		metricValue.SetName("cisco.device.up")
		point := metricValue.SetEmptyGauge().DataPoints().AppendEmpty()
		point.SetTimestamp(pcommon.NewTimestampFromTime(timestamp))
		point.SetIntValue(value)
		return metrics
	}
	started := time.Unix(1_700_000_000, 0)
	summary := summarizeGNMIProductQualification([]pmetric.Metrics{
		availability(started, 1), availability(started.Add(time.Second), 0),
	}, nil)
	assert.True(t, summary.deviceUpSeen)
	assert.False(t, summary.deviceUp, "historical up state cannot hide a later down transition")
}

func (summary gnmiProductQualificationSummary) verifiedResource(product, model, version string) bool {
	for _, resource := range summary.resources {
		if resource["cisco.product.family"] == product &&
			resource["device.manufacturer"] == "Cisco" &&
			resource["device.model.identifier"] == model &&
			resource["os.version"] == version {
			return true
		}
	}
	return false
}

type gnmiProductE2ETelemetry struct {
	productVerified     int64
	preflightFailures   int64
	degradedProfiles    int64
	activeSubscriptions map[string]int64
}

func collectGNMIProductE2ETelemetry(t *testing.T, reader *metric.ManualReader, target string) gnmiProductE2ETelemetry {
	t.Helper()
	var resourceMetrics metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &resourceMetrics))
	out := gnmiProductE2ETelemetry{activeSubscriptions: map[string]int64{}}
	for _, scope := range resourceMetrics.ScopeMetrics {
		for _, instrument := range scope.Metrics {
			switch data := instrument.Data.(type) {
			case metricdata.Gauge[int64]:
				for _, point := range data.DataPoints {
					targetValue, hasTarget := point.Attributes.Value(attribute.Key("cisco.gnmi.target"))
					if hasTarget && targetValue.AsString() != target {
						continue
					}
					switch instrument.Name {
					case "otelcol_ciscoosreceiver_gnmi_product_verified":
						out.productVerified = max(out.productVerified, point.Value)
					case "otelcol_ciscoosreceiver_gnmi_profile_degraded":
						out.degradedProfiles += point.Value
					case "otelcol_ciscoosreceiver_gnmi_subscriptions":
						profile, ok := point.Attributes.Value(attribute.Key("cisco.gnmi.profile"))
						if ok && point.Value > 0 {
							out.activeSubscriptions[profile.AsString()] = point.Value
						}
					}
				}
			case metricdata.Sum[int64]:
				if instrument.Name == "otelcol_ciscoosreceiver_gnmi_preflight_failures" {
					for _, point := range data.DataPoints {
						targetValue, ok := point.Attributes.Value(attribute.Key("cisco.gnmi.target"))
						if ok && targetValue.AsString() != target {
							continue
						}
						out.preflightFailures += point.Value
					}
				}
			}
		}
	}
	return out
}

func assertGNMIProductBackendDelivery(
	t *testing.T,
	rawURL, product, version, model, target, runID string,
	started time.Time,
	periodicMetrics []string,
	interval time.Duration,
	waitTimeout time.Duration,
) {
	t.Helper()
	parsed, err := validateGNMIProductBackendURL(rawURL)
	require.NoError(t, err)
	query := parsed.Query()
	query.Set("product", product)
	query.Set("software_version", version)
	query.Set("model_identifier", model)
	query.Set("target", target)
	query.Set("run_id", runID)
	query.Set("not_before_unix_nano", strconv.FormatInt(started.UnixNano(), 10))
	query.Set("minimum_intervals", fmt.Sprint(gnmiProductE2EMinimumIntervals))
	query.Set("interval_unix_nano", strconv.FormatInt(interval.Nanoseconds(), 10))
	for _, metricName := range periodicMetrics {
		query.Add("periodic_metric", metricName)
	}
	query.Add("latest_metric", "cisco.device.up")
	parsed.RawQuery = query.Encode()
	client := &http.Client{
		Timeout:       min(30*time.Second, waitTimeout),
		CheckRedirect: gnmiProductBackendRedirectPolicy(parsed),
	}
	pollInterval := min(time.Second, max(100*time.Millisecond, waitTimeout/20))
	require.EventuallyWithT(t, func(tt *assert.CollectT) {
		result, fetchErr := fetchGNMIProductBackendAssertion(t.Context(), client, parsed)
		if !assert.NoError(tt, fetchErr) {
			return
		}
		assert.NoError(tt, validateGNMIProductBackendAssertion(
			result, product, version, model, target, runID, started, periodicMetrics,
		))
	}, waitTimeout, pollInterval, "backend did not attest the current exact-build qualification before the observation window closed")
}

type gnmiProductBackendAssertion struct {
	Delivered                bool               `json:"delivered"`
	RunID                    string             `json:"run_id"`
	Target                   string             `json:"target"`
	Product                  string             `json:"product"`
	SoftwareVersion          string             `json:"software_version"`
	ModelIdentifier          string             `json:"model_identifier"`
	WindowStartUnixNano      int64              `json:"window_start_unix_nano"`
	FirstObservationUnixNano int64              `json:"first_observation_unix_nano"`
	LastObservationUnixNano  int64              `json:"last_observation_unix_nano"`
	MetricIntervals          map[string]int     `json:"metric_intervals"`
	LatestMetricValues       map[string]float64 `json:"latest_metric_values"`
}

func fetchGNMIProductBackendAssertion(
	ctx context.Context,
	client *http.Client,
	endpoint *url.URL,
) (gnmiProductBackendAssertion, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return gnmiProductBackendAssertion{}, err
	}
	if token := os.Getenv(gnmiProductE2EBackendToken); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		return gnmiProductBackendAssertion{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return gnmiProductBackendAssertion{}, fmt.Errorf("backend assertion returned HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, gnmiProductE2EMaxAssertionBytes+1))
	if err != nil {
		return gnmiProductBackendAssertion{}, err
	}
	if len(body) > gnmiProductE2EMaxAssertionBytes {
		return gnmiProductBackendAssertion{}, fmt.Errorf("backend assertion exceeds %d bytes", gnmiProductE2EMaxAssertionBytes)
	}
	var result gnmiProductBackendAssertion
	if err := json.Unmarshal(body, &result); err != nil {
		return gnmiProductBackendAssertion{}, fmt.Errorf("decode backend assertion: %w", err)
	}
	return result, nil
}

func validateGNMIProductBackendAssertion(
	result gnmiProductBackendAssertion,
	product, version, model, target, runID string,
	started time.Time,
	periodicMetrics []string,
) error {
	if !result.Delivered {
		return fmt.Errorf("backend has not delivered the qualification data")
	}
	if result.RunID != runID || result.Target != target {
		return fmt.Errorf("backend did not attest the unique current run and target")
	}
	if result.Product != product || result.SoftwareVersion != version || result.ModelIdentifier != model {
		return fmt.Errorf("backend did not attest the exact product, software version, and model")
	}
	if result.WindowStartUnixNano != started.UnixNano() || result.FirstObservationUnixNano < started.UnixNano() {
		return fmt.Errorf("backend observation window includes stale history")
	}
	if result.LastObservationUnixNano < result.FirstObservationUnixNano {
		return fmt.Errorf("backend observation timestamps are inconsistent")
	}
	for _, metricName := range periodicMetrics {
		if result.MetricIntervals[metricName] < gnmiProductE2EMinimumIntervals {
			return fmt.Errorf("backend metric %q has fewer than %d intervals", metricName, gnmiProductE2EMinimumIntervals)
		}
	}
	if result.LatestMetricValues["cisco.device.up"] != 1 {
		return fmt.Errorf("backend latest cisco.device.up value is not 1")
	}
	return nil
}

func TestValidateGNMIProductBackendAssertionRequiresExactCurrentEvidence(t *testing.T) {
	started := time.Unix(1_700_000_000, 0)
	valid := gnmiProductBackendAssertion{
		Delivered: true, RunID: "run", Target: "target", Product: gnmiProductASR9000,
		SoftwareVersion: "24.4.1", ModelIdentifier: "ASR-9904",
		WindowStartUnixNano: started.UnixNano(), FirstObservationUnixNano: started.UnixNano(),
		LastObservationUnixNano: started.Add(30 * time.Second).UnixNano(),
		MetricIntervals:         map[string]int{"system.cpu.utilization": 3},
		LatestMetricValues:      map[string]float64{"cisco.device.up": 1},
	}
	validate := func(result gnmiProductBackendAssertion) error {
		return validateGNMIProductBackendAssertion(
			result, gnmiProductASR9000, "24.4.1", "ASR-9904", "target", "run", started,
			[]string{"system.cpu.utilization"},
		)
	}
	require.NoError(t, validate(valid))

	mutations := []func(*gnmiProductBackendAssertion){
		func(result *gnmiProductBackendAssertion) { result.Delivered = false },
		func(result *gnmiProductBackendAssertion) { result.RunID = "stale-run" },
		func(result *gnmiProductBackendAssertion) { result.Product = gnmiProductNCS5500 },
		func(result *gnmiProductBackendAssertion) { result.SoftwareVersion = "24.4.2" },
		func(result *gnmiProductBackendAssertion) { result.ModelIdentifier = "NCS-5501-SE" },
		func(result *gnmiProductBackendAssertion) {
			result.FirstObservationUnixNano = started.Add(-time.Second).UnixNano()
		},
		func(result *gnmiProductBackendAssertion) {
			result.MetricIntervals = map[string]int{"system.cpu.utilization": 2}
		},
		func(result *gnmiProductBackendAssertion) {
			result.LatestMetricValues = map[string]float64{"cisco.device.up": 0}
		},
	}
	for index, mutate := range mutations {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			result := valid
			result.MetricIntervals = maps.Clone(valid.MetricIntervals)
			result.LatestMetricValues = maps.Clone(valid.LatestMetricValues)
			mutate(&result)
			require.Error(t, validate(result))
		})
	}
}

func validateGNMIProductBackendURL(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse backend assertion endpoint: %w", err)
	}
	if !parsed.IsAbs() || !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" {
		return nil, fmt.Errorf("backend assertion endpoint must be an absolute HTTPS URL with a hostname")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("backend assertion endpoint must not contain user information")
	}
	if parsed.Opaque != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("backend assertion endpoint must not contain an opaque path or fragment")
	}
	return parsed, nil
}

func gnmiProductBackendRedirectPolicy(origin *url.URL) func(*http.Request, []*http.Request) error {
	configuredOrigin := *origin
	return func(request *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 backend assertion redirects")
		}
		if request == nil || request.URL == nil ||
			!strings.EqualFold(request.URL.Scheme, "https") || request.URL.Hostname() == "" ||
			request.URL.User != nil || request.URL.Opaque != "" || request.URL.Fragment != "" ||
			!receiverhttpclient.SameOrigin(&configuredOrigin, request.URL) {
			return fmt.Errorf("backend assertion redirect must remain on the configured HTTPS origin")
		}
		return nil
	}
}

func TestGNMIProductBackendURLValidation(t *testing.T) {
	for _, test := range []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{name: "absolute HTTPS", rawURL: "https://backend.example.test/assert?tenant=lab"},
		{name: "HTTP", rawURL: "http://backend.example.test/assert", wantErr: true},
		{name: "relative", rawURL: "/assert", wantErr: true},
		{name: "no hostname", rawURL: "https:///assert", wantErr: true},
		{name: "user information", rawURL: "https://user:password@backend.example.test/assert", wantErr: true},
		{name: "fragment", rawURL: "https://backend.example.test/assert#token", wantErr: true},
		{name: "opaque", rawURL: "https:backend.example.test/assert", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateGNMIProductBackendURL(test.rawURL)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestGNMIProductBackendRedirectPolicy(t *testing.T) {
	origin, err := validateGNMIProductBackendURL("https://backend.example.test/assert")
	require.NoError(t, err)
	policy := gnmiProductBackendRedirectPolicy(origin)
	for _, test := range []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{name: "same origin", rawURL: "https://backend.example.test/next"},
		{name: "same effective port", rawURL: "https://backend.example.test:443/next"},
		{name: "downgrade", rawURL: "http://backend.example.test/next", wantErr: true},
		{name: "different host", rawURL: "https://other.example.test/next", wantErr: true},
		{name: "different port", rawURL: "https://backend.example.test:8443/next", wantErr: true},
		{name: "user information", rawURL: "https://user@backend.example.test/next", wantErr: true},
		{name: "fragment", rawURL: "https://backend.example.test/next#fragment", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			redirect, parseErr := url.Parse(test.rawURL)
			require.NoError(t, parseErr)
			err := policy(&http.Request{URL: redirect}, []*http.Request{{URL: origin}})
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}

	via := make([]*http.Request, 10)
	require.Error(t, policy(&http.Request{URL: origin}, via))
}

func appendUniqueStrings(values []string, additions ...string) []string {
	seen := make(map[string]struct{}, len(values)+len(additions))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, value := range additions {
		if _, ok := seen[value]; !ok {
			values = append(values, value)
			seen[value] = struct{}{}
		}
	}
	sort.Strings(values)
	return values
}

func removeString(values []string, removed string) []string {
	out := values[:0]
	for _, value := range values {
		if value != removed {
			out = append(out, value)
		}
	}
	return out
}
