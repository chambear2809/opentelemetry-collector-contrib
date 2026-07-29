// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package ciscoosreceiver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

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
	gnmiProductE2EEndpointEnv              = "CISCOOS_E2E_GNMI_ENDPOINT"
	gnmiProductE2EUsernameEnv              = "CISCOOS_E2E_GNMI_USERNAME"
	gnmiProductE2EPasswordEnv              = "CISCOOS_E2E_GNMI_PASSWORD"
	gnmiProductE2ECAFileEnv                = "CISCOOS_E2E_GNMI_CA_FILE"
	gnmiProductE2EServerNameEnv            = "CISCOOS_E2E_GNMI_SERVER_NAME"
	gnmiProductE2EClientCertEnv            = "CISCOOS_E2E_GNMI_CLIENT_CERT_FILE"
	gnmiProductE2EClientKeyEnv             = "CISCOOS_E2E_GNMI_CLIENT_KEY_FILE"
	gnmiProductE2EProductEnv               = "CISCOOS_E2E_GNMI_PRODUCT"
	gnmiProductE2EVersionEnv               = "CISCOOS_E2E_GNMI_SOFTWARE_VERSION"
	gnmiProductE2EModelEnv                 = "CISCOOS_E2E_GNMI_MODEL_IDENTIFIER"
	gnmiProductE2EImageEvidenceEnv         = "CISCOOS_E2E_GNMI_IMAGE_EVIDENCE_SHA256"
	gnmiProductE2EAuthorizationEvidenceEnv = "CISCOOS_E2E_GNMI_AUTHORIZATION_EVIDENCE_SHA256"
	gnmiProductE2ETopologyEnv              = "CISCOOS_E2E_GNMI_TOPOLOGY"
	gnmiProductE2EMetricsEnv               = "CISCOOS_E2E_GNMI_REQUIRED_METRICS"
	gnmiProductE2EIntervalEnv              = "CISCOOS_E2E_GNMI_SAMPLE_INTERVAL"
	gnmiProductE2EWaitEnv                  = "CISCOOS_E2E_GNMI_WAIT_TIMEOUT"
	gnmiProductE2EBackendURL               = "CISCOOS_E2E_GNMI_BACKEND_ASSERT_URL"
	gnmiProductE2EBackendToken             = "CISCOOS_E2E_GNMI_BACKEND_BEARER_TOKEN" //nolint:gosec // Environment variable name, not a credential.
	gnmiProductE2EMinimumIntervals         = 3
	gnmiProductE2EMaxAssertionBytes        = 64 * 1024
	gnmiProductE2EMinimumInterval          = time.Second
	gnmiProductE2EMaximumInterval          = 5 * time.Minute
	gnmiProductE2EMaximumWait              = 30 * time.Minute
	gnmiProductE2EMaximumClockSkew         = 5 * time.Second

	gnmiProductE2ETelemetryAuthenticationFailures = "otelcol_ciscoosreceiver_gnmi_authentication_failures"
	gnmiProductE2ETelemetryAuxiliaryUtilization   = "otelcol_ciscoosreceiver_gnmi_auxiliary_state_utilization"
	gnmiProductE2ETelemetryCacheOwnerResets       = "otelcol_ciscoosreceiver_gnmi_cache_owner_resets"
	gnmiProductE2ETelemetryCacheUtilization       = "otelcol_ciscoosreceiver_gnmi_cache_utilization"
	gnmiProductE2ETelemetryConnections            = "otelcol_ciscoosreceiver_gnmi_connections"
	gnmiProductE2ETelemetryConsumerRefusals       = "otelcol_ciscoosreceiver_gnmi_consumer_refusals"
	gnmiProductE2ETelemetryDecodeErrors           = "otelcol_ciscoosreceiver_gnmi_decode_errors"
	gnmiProductE2ETelemetryInvalidTimestamps      = "otelcol_ciscoosreceiver_gnmi_invalid_timestamps"
	gnmiProductE2ETelemetryOutOfOrderUpdates      = "otelcol_ciscoosreceiver_gnmi_out_of_order_updates"
	gnmiProductE2ETelemetryPreflightFailures      = "otelcol_ciscoosreceiver_gnmi_preflight_failures"
	gnmiProductE2ETelemetryProductVerified        = "otelcol_ciscoosreceiver_gnmi_product_verified"
	gnmiProductE2ETelemetryProfileDegraded        = "otelcol_ciscoosreceiver_gnmi_profile_degraded"
	gnmiProductE2ETelemetryReconnects             = "otelcol_ciscoosreceiver_gnmi_reconnects"
	gnmiProductE2ETelemetrySubscriptions          = "otelcol_ciscoosreceiver_gnmi_subscriptions"
	gnmiProductE2ETelemetryUnmappedValues         = "otelcol_ciscoosreceiver_gnmi_unmapped_values"
	gnmiProductE2ETelemetryUnsupportedValueKinds  = "otelcol_ciscoosreceiver_gnmi_unsupported_value_kinds"
	gnmiProductE2EMaximumExactJSONInteger         = float64(1<<53 - 1)
)

// TestE2EProductQualifiedGNMI is the release-qualification harness for the
// seven shared gNMI product contracts. It deliberately requires an external,
// read-only backend assertion endpoint; a local consumer pass alone is not a
// retained backend-delivery qualification. Catalyst switch Set/gNOI denial
// evidence is also produced externally; this harness never invokes those RPCs.
func TestE2EProductQualifiedGNMI(t *testing.T) {
	endpoint := requiredEnvOrSkip(t, gnmiProductE2EEndpointEnv)
	username := requiredEnvOrSkip(t, gnmiProductE2EUsernameEnv)
	password := requiredEnvOrSkip(t, gnmiProductE2EPasswordEnv)
	product := requiredEnvOrSkip(t, gnmiProductE2EProductEnv)
	softwareVersion := requiredEnvOrSkip(t, gnmiProductE2EVersionEnv)
	expectedModel := requiredEnvOrSkip(t, gnmiProductE2EModelEnv)
	imageEvidenceSHA256 := requiredEnvOrSkip(t, gnmiProductE2EImageEvidenceEnv)
	require.NoError(t, validateGNMIProductE2EImageEvidenceSHA256(imageEvidenceSHA256))
	contract, canonicalVersion, err := resolveGNMIProductContract(product, softwareVersion)
	require.NoError(t, err)
	authorizationEvidenceSHA256 := ""
	if gnmiProductE2ERequiresAuthorizationEvidence(product) {
		authorizationEvidenceSHA256 = os.Getenv(gnmiProductE2EAuthorizationEvidenceEnv)
		require.NoError(t, validateGNMIProductE2EAuthorizationEvidenceSHA256(product, authorizationEvidenceSHA256))
	}
	backendURL := requiredEnvOrSkip(t, gnmiProductE2EBackendURL)
	topology := os.Getenv(gnmiProductE2ETopologyEnv)
	require.NoError(t, validateGNMIProductE2ETopology(product, topology))
	requiredMetrics, err := gnmiProductE2EQualificationMetrics(product, csvEnv(gnmiProductE2EMetricsEnv))
	require.NoError(t, err)
	runID := newGNMIProductE2ERunID(t)
	qualificationStarted := time.Now().UTC()

	interval := durationEnv(t, gnmiProductE2EIntervalEnv, 10*time.Second)
	waitTimeout := durationEnv(t, gnmiProductE2EWaitEnv, 3*time.Minute)
	require.NoError(t, validateGNMIProductE2EDurations(interval, waitTimeout))

	enabled, disabled := true, false
	_, systemProfileSupported := builtinGNMIProfile(contract, builtinGNMIProfileSystem)
	target := GNMITargetConfig{
		Name:             "product-qualified-live-" + runID,
		Endpoint:         endpoint,
		Product:          product,
		SoftwareVersion:  softwareVersion,
		AllowUnqualified: contract.RequiresExplicitUnqualifiedOptIn,
		MaxStreams:       4,
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
	expectedIdentity := gnmiProductQualificationIdentity{
		Target: target.Name, Product: product, Model: expectedModel,
		Version: canonicalVersion.Canonical, BootMode: contract.RequiredIOSXEBootMode,
	}
	require.True(t, expectedIdentity.valid())

	preBackendReader := metric.NewManualReader()
	postBackendReader := metric.NewManualReader()
	provider := metric.NewMeterProvider(
		metric.WithReader(preBackendReader),
		metric.WithReader(postBackendReader),
	)
	t.Cleanup(func() { assert.NoError(t, provider.Shutdown(context.Background())) })
	settings := receivertest.NewNopSettings(componentmetadata.Type)
	settings.MeterProvider = provider
	sink := newGNMIProductQualificationSink(qualificationStarted, interval, requiredMetrics, expectedIdentity)
	receiver, err := NewFactory().CreateMetrics(t.Context(), settings, cfg, sink)
	require.NoError(t, err)
	require.NoError(t, receiver.Start(t.Context(), componenttest.NewNopHost()))
	t.Cleanup(func() { assert.NoError(t, receiver.Shutdown(context.Background())) })

	require.EventuallyWithT(t, func(tt *assert.CollectT) {
		summary := summarizeGNMIProductQualification(sink.AllMetrics(), requiredMetrics, expectedIdentity)
		assert.True(tt, summary.verifiedResource, "verified resource identity was not delivered")
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

	telemetry := collectGNMIProductE2ETelemetry(t, preBackendReader, target.Name)
	require.NoError(t, validateGNMIProductE2ETelemetry(telemetry, expectedSubscriptions),
		"current-run receiver self-telemetry disqualifies the local qualification")

	remaining := time.Until(qualificationStarted.Add(waitTimeout))
	require.Positive(t, remaining, "local qualification exhausted the backend-delivery observation window")
	backendEvidence := assertGNMIProductBackendDelivery(
		t,
		backendURL,
		product,
		topology,
		canonicalVersion.Canonical,
		expectedModel,
		imageEvidenceSHA256,
		authorizationEvidenceSHA256,
		contract.RequiredIOSXEBootMode,
		target.Name,
		runID,
		qualificationStarted,
		requiredMetrics,
		expectedSubscriptions,
		interval,
		remaining,
	)
	finalSummary := summarizeGNMIProductQualification(sink.AllMetrics(), requiredMetrics, expectedIdentity)
	require.True(t, finalSummary.deviceUp, "the latest local availability value changed after qualification")
	finalTelemetry := collectGNMIProductE2ETelemetry(t, postBackendReader, target.Name)
	require.NoError(t, validateGNMIProductE2ETelemetry(finalTelemetry, expectedSubscriptions),
		"current-run receiver self-telemetry changed to a disqualifying state during backend confirmation")
	localSelfTelemetry, err := json.Marshal(map[string]any{
		"values":               finalTelemetry.values,
		"active_subscriptions": finalTelemetry.activeSubscriptions,
	})
	require.NoError(t, err)
	backendSelfTelemetry, err := json.Marshal(map[string]any{
		"values":               backendEvidence.SelfTelemetryValues,
		"active_subscriptions": backendEvidence.ActiveSubscriptions,
	})
	require.NoError(t, err)
	backendAuthorization, err := json.Marshal(map[string]any{
		"authorization_evidence_sha256":                    backendEvidence.AuthorizationEvidenceSHA256,
		"server_read_only":                                 backendEvidence.ServerReadOnly,
		"gnoi_disabled":                                    backendEvidence.GNOIDisabled,
		"negative_set_permission_denied":                   backendEvidence.NegativeSetPermissionDenied,
		"negative_gnoi_permission_denied_or_unimplemented": backendEvidence.NegativeGNOIPermissionDeniedOrUnimplemented,
	})
	require.NoError(t, err)
	t.Logf("qualified run=%s product=%s model=%s version=%s image=%s authorization=%s boot_mode=%s topology=%s metrics=%v intervals=%d local_self_telemetry=%s backend_self_telemetry=%s backend_authorization=%s",
		runID, product, expectedModel, canonicalVersion.Canonical, imageEvidenceSHA256, authorizationEvidenceSHA256,
		contract.RequiredIOSXEBootMode, topology, requiredMetrics, gnmiProductE2EMinimumIntervals,
		localSelfTelemetry, backendSelfTelemetry, backendAuthorization)
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

func validateGNMIProductE2ETopology(product, topology string) error {
	var allowed []string
	switch product {
	case gnmiProductCatalyst9300:
		allowed = []string{"standalone", "stackwise"}
	case gnmiProductCatalyst9500:
		allowed = []string{"standalone", "stackwise_virtual"}
	default:
		if topology != "" {
			return fmt.Errorf("%s is defined only for Catalyst 9300 and 9500 qualification", gnmiProductE2ETopologyEnv)
		}
		return nil
	}
	for _, candidate := range allowed {
		if topology == candidate {
			return nil
		}
	}
	return fmt.Errorf("%s for product %s must be one of %s", gnmiProductE2ETopologyEnv, product, strings.Join(allowed, ", "))
}

func validateGNMIProductE2EImageEvidenceSHA256(identifier string) error {
	return validateGNMIProductE2EEvidenceSHA256(gnmiProductE2EImageEvidenceEnv, identifier)
}

func gnmiProductE2ERequiresAuthorizationEvidence(product string) bool {
	return product == gnmiProductCatalyst9300 || product == gnmiProductCatalyst9500
}

func validateGNMIProductE2EAuthorizationEvidenceSHA256(product, identifier string) error {
	if !gnmiProductE2ERequiresAuthorizationEvidence(product) {
		return nil
	}
	if identifier == "" {
		return fmt.Errorf("%s is required for Catalyst 9300 and 9500 qualification", gnmiProductE2EAuthorizationEvidenceEnv)
	}
	return validateGNMIProductE2EEvidenceSHA256(gnmiProductE2EAuthorizationEvidenceEnv, identifier)
}

func validateGNMIProductE2EEvidenceSHA256(environmentName, identifier string) error {
	const prefix = "sha256:"
	if !utf8.ValidString(identifier) || len(identifier) != len(prefix)+64 || !strings.HasPrefix(identifier, prefix) {
		return fmt.Errorf("%s must use sha256:<64 lowercase hex characters>", environmentName)
	}
	digest := strings.TrimPrefix(identifier, prefix)
	if strings.ToLower(digest) != digest {
		return fmt.Errorf("%s must use lowercase hexadecimal", environmentName)
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return fmt.Errorf("%s must use sha256:<64 lowercase hex characters>", environmentName)
	}
	return nil
}

func gnmiProductE2EQualificationMetrics(product string, additions []string) ([]string, error) {
	var baseline []string
	switch product {
	case gnmiProductCatalyst9300, gnmiProductCatalyst9500:
		baseline = []string{
			"system.cpu.utilization",
			"system.memory.utilization",
			"system.network.interface.status",
			"system.network.io",
			"cisco.interface.admin.status",
			"system.network.errors",
			"system.network.packet.count",
			"system.network.packet.dropped",
		}
	case gnmiProductCatalyst9800:
		baseline = []string{
			"system.cpu.utilization",
			"system.memory.utilization",
			"system.network.interface.status",
			"system.network.io",
			"cisco.interface.admin.status",
			"system.network.errors",
			"system.network.packet.count",
			"system.network.packet.dropped",
			"cisco.wlc.ap.join.status",
			"cisco.wlc.rf.channel.utilization",
			"cisco.wlc.ssid.client.count",
		}
	case gnmiProductASR9000, gnmiProductNCS5500:
		baseline = []string{
			"system.cpu.utilization",
			"system.network.interface.status",
			"system.network.io",
			"cisco.interface.admin.status",
			"system.network.errors",
			"system.network.packet.count",
			"system.network.packet.dropped",
		}
	case gnmiProductNexus9000, gnmiProductNexus3500:
		baseline = []string{
			"system.network.interface.status",
			"system.network.io",
			"cisco.interface.admin.status",
			"system.network.errors",
			"system.network.packet.count",
			"system.network.packet.dropped",
		}
	default:
		return nil, fmt.Errorf("product %q has no exact-build qualification metric contract", product)
	}
	seen := make(map[string]struct{}, len(baseline)+len(additions))
	metrics := make([]string, 0, len(baseline)+len(additions))
	appendMetric := func(metricName string) error {
		if metricName == "cisco.device.up" {
			return nil
		}
		if metricName == "" || strings.TrimSpace(metricName) != metricName || len(metricName) > 256 {
			return fmt.Errorf("%s contains an invalid metric name", gnmiProductE2EMetricsEnv)
		}
		for _, value := range metricName {
			if value < 0x21 || value == 0x7f {
				return fmt.Errorf("%s contains an invalid metric name", gnmiProductE2EMetricsEnv)
			}
		}
		if _, exists := seen[metricName]; exists {
			return nil
		}
		seen[metricName] = struct{}{}
		metrics = append(metrics, metricName)
		return nil
	}
	for _, metricName := range baseline {
		if err := appendMetric(metricName); err != nil {
			return nil, err
		}
	}
	for _, metricName := range additions {
		if err := appendMetric(metricName); err != nil {
			return nil, err
		}
	}
	sort.Strings(metrics)
	return metrics, nil
}

type gnmiProductQualificationIdentity struct {
	Target   string
	Product  string
	Model    string
	Version  string
	BootMode string
}

func (identity gnmiProductQualificationIdentity) valid() bool {
	return identity.Target != "" && identity.Product != "" && identity.Model != "" && identity.Version != ""
}

func resourceMatchesGNMIProductQualification(
	resource pcommon.Resource,
	expected gnmiProductQualificationIdentity,
) bool {
	if !expected.valid() {
		return false
	}
	attributes := resource.Attributes()
	required := map[string]string{
		"host.name":               expected.Target,
		"cisco.product.family":    expected.Product,
		"device.manufacturer":     "Cisco",
		"device.model.identifier": expected.Model,
		"os.version":              expected.Version,
	}
	if expected.BootMode != "" {
		required["cisco.os.boot_mode"] = expected.BootMode
	}
	for key, expectedValue := range required {
		value, present := attributes.Get(key)
		if !present || value.Type() != pcommon.ValueTypeStr || value.Str() != expectedValue {
			return false
		}
	}
	return true
}

type gnmiProductQualificationSink struct {
	sink     consumertest.MetricsSink
	started  time.Time
	interval time.Duration
	wanted   map[string]struct{}
	identity gnmiProductQualificationIdentity

	mu      sync.Mutex
	buckets map[string]map[string]map[int64]struct{}
}

func newGNMIProductQualificationSink(
	started time.Time,
	interval time.Duration,
	metrics []string,
	identity gnmiProductQualificationIdentity,
) *gnmiProductQualificationSink {
	wanted := make(map[string]struct{}, len(metrics))
	buckets := make(map[string]map[string]map[int64]struct{}, len(metrics))
	for _, metricName := range metrics {
		wanted[metricName] = struct{}{}
		buckets[metricName] = map[string]map[int64]struct{}{}
	}
	return &gnmiProductQualificationSink{
		started: started, interval: interval, wanted: wanted, identity: identity, buckets: buckets,
	}
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
		resourceMetrics := metrics.ResourceMetrics().At(i)
		if !resourceMatchesGNMIProductQualification(resourceMetrics.Resource(), s.identity) {
			continue
		}
		scopes := resourceMetrics.ScopeMetrics()
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

func TestGNMIProductE2ETopologyContract(t *testing.T) {
	for _, test := range []struct {
		name, product, topology string
		wantErr                 bool
	}{
		{name: "C9300 standalone", product: gnmiProductCatalyst9300, topology: "standalone"},
		{name: "C9300 StackWise", product: gnmiProductCatalyst9300, topology: "stackwise"},
		{name: "C9300 missing", product: gnmiProductCatalyst9300, wantErr: true},
		{name: "C9300 SVL", product: gnmiProductCatalyst9300, topology: "stackwise_virtual", wantErr: true},
		{name: "C9500 standalone", product: gnmiProductCatalyst9500, topology: "standalone"},
		{name: "C9500 SVL", product: gnmiProductCatalyst9500, topology: "stackwise_virtual"},
		{name: "C9500 StackWise", product: gnmiProductCatalyst9500, topology: "stackwise", wantErr: true},
		{name: "other product unset", product: gnmiProductASR9000},
		{name: "other product set", product: gnmiProductASR9000, topology: "standalone", wantErr: true},
		{name: "whitespace rejected", product: gnmiProductCatalyst9300, topology: " standalone ", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateGNMIProductE2ETopology(test.product, test.topology)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestGNMIProductE2EQualificationMetricsCannotOmitBaseline(t *testing.T) {
	expected := map[string][]string{
		gnmiProductCatalyst9300: {
			"system.cpu.utilization", "system.memory.utilization",
			"system.network.interface.status", "system.network.io",
			"cisco.interface.admin.status", "system.network.errors",
			"system.network.packet.count", "system.network.packet.dropped",
		},
		gnmiProductCatalyst9500: {
			"system.cpu.utilization", "system.memory.utilization",
			"system.network.interface.status", "system.network.io",
			"cisco.interface.admin.status", "system.network.errors",
			"system.network.packet.count", "system.network.packet.dropped",
		},
		gnmiProductCatalyst9800: {
			"system.cpu.utilization", "system.memory.utilization",
			"system.network.interface.status", "system.network.io",
			"cisco.interface.admin.status", "system.network.errors",
			"system.network.packet.count", "system.network.packet.dropped",
			"cisco.wlc.ap.join.status", "cisco.wlc.rf.channel.utilization",
			"cisco.wlc.ssid.client.count",
		},
		gnmiProductASR9000: {
			"system.cpu.utilization", "system.network.interface.status", "system.network.io",
			"cisco.interface.admin.status", "system.network.errors",
			"system.network.packet.count", "system.network.packet.dropped",
		},
		gnmiProductNCS5500: {
			"system.cpu.utilization", "system.network.interface.status", "system.network.io",
			"cisco.interface.admin.status", "system.network.errors",
			"system.network.packet.count", "system.network.packet.dropped",
		},
		gnmiProductNexus9000: {
			"system.network.interface.status", "system.network.io",
			"cisco.interface.admin.status", "system.network.errors",
			"system.network.packet.count", "system.network.packet.dropped",
		},
		gnmiProductNexus3500: {
			"system.network.interface.status", "system.network.io",
			"cisco.interface.admin.status", "system.network.errors",
			"system.network.packet.count", "system.network.packet.dropped",
		},
	}
	for product, baseline := range expected {
		t.Run(product, func(t *testing.T) {
			metrics, err := gnmiProductE2EQualificationMetrics(product, nil)
			require.NoError(t, err)
			assert.ElementsMatch(t, baseline, metrics)
			for _, omitted := range baseline {
				additions := removeString(append([]string(nil), baseline...), omitted)
				metrics, err = gnmiProductE2EQualificationMetrics(product, additions)
				require.NoError(t, err)
				assert.Contains(t, metrics, omitted,
					"the immutable baseline must restore an operator-omitted metric")
			}
			metrics, err = gnmiProductE2EQualificationMetrics(product, []string{"custom.metric", "cisco.device.up", "custom.metric"})
			require.NoError(t, err)
			assert.Contains(t, metrics, "custom.metric")
			assert.NotContains(t, metrics, "cisco.device.up")
		})
	}
	_, err := gnmiProductE2EQualificationMetrics("unknown", nil)
	require.Error(t, err)
}

func TestGNMIProductE2EImageEvidenceSHA256Validation(t *testing.T) {
	require.NoError(t, validateGNMIProductE2EImageEvidenceSHA256("sha256:"+strings.Repeat("a", 64)))
	for _, invalid := range []string{
		"", "17.18.3", "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("g", 64),
		"sha256:" + strings.Repeat("a", 63), " sha256:" + strings.Repeat("a", 64), string([]byte{0xff}),
	} {
		require.Error(t, validateGNMIProductE2EImageEvidenceSHA256(invalid))
	}
}

func TestGNMIProductE2EAuthorizationEvidenceSHA256Validation(t *testing.T) {
	valid := "sha256:" + strings.Repeat("a", 64)
	for _, product := range []string{gnmiProductCatalyst9300, gnmiProductCatalyst9500} {
		t.Run(product+" valid", func(t *testing.T) {
			require.NoError(t, validateGNMIProductE2EAuthorizationEvidenceSHA256(product, valid))
		})
		t.Run(product+" missing", func(t *testing.T) {
			require.ErrorContains(
				t,
				validateGNMIProductE2EAuthorizationEvidenceSHA256(product, ""),
				"is required",
			)
		})
		t.Run(product+" malformed", func(t *testing.T) {
			require.Error(t, validateGNMIProductE2EAuthorizationEvidenceSHA256(
				product, "sha256:"+strings.Repeat("A", 64),
			))
		})
	}

	require.NoError(t, validateGNMIProductE2EAuthorizationEvidenceSHA256(gnmiProductASR9000, ""))
	require.NoError(t, validateGNMIProductE2EAuthorizationEvidenceSHA256(
		gnmiProductASR9000, "not-switch-evidence",
	))
}

func TestGNMIProductE2EAuthorizationEvidenceQueryIsSwitchOnly(t *testing.T) {
	valid := "sha256:" + strings.Repeat("a", 64)
	query := make(url.Values)
	require.NoError(t, addGNMIProductE2EAuthorizationEvidenceQuery(query, gnmiProductCatalyst9300, valid))
	require.Equal(t, valid, query.Get("authorization_evidence_sha256"))

	query = make(url.Values)
	require.Error(t, addGNMIProductE2EAuthorizationEvidenceQuery(query, gnmiProductCatalyst9500, ""))
	require.Empty(t, query)

	query = make(url.Values)
	require.NoError(t, addGNMIProductE2EAuthorizationEvidenceQuery(query, gnmiProductASR9000, ""))
	require.Empty(t, query)
}

func TestGNMIProductQualificationResourceIdentityIsFailClosed(t *testing.T) {
	expected := testGNMIProductQualificationIdentity()
	makeResource := func() pcommon.Resource {
		resource := pcommon.NewResource()
		putGNMIProductQualificationResource(resource, expected)
		return resource
	}
	require.True(t, resourceMatchesGNMIProductQualification(makeResource(), expected))
	for _, key := range []string{
		"host.name", "cisco.product.family", "device.manufacturer",
		"device.model.identifier", "os.version", "cisco.os.boot_mode",
	} {
		t.Run("missing "+key, func(t *testing.T) {
			resource := makeResource()
			resource.Attributes().Remove(key)
			assert.False(t, resourceMatchesGNMIProductQualification(resource, expected))
		})
		t.Run("wrong "+key, func(t *testing.T) {
			resource := makeResource()
			resource.Attributes().PutStr(key, "wrong")
			assert.False(t, resourceMatchesGNMIProductQualification(resource, expected))
		})
	}
}

func TestGNMIProductQualificationSinkDoesNotCombineResourceIdentities(t *testing.T) {
	started := time.Unix(1_700_000_000, 0)
	identity := testGNMIProductQualificationIdentity()
	sink := newGNMIProductQualificationSink(started, time.Second, []string{"test.metric"}, identity)
	metricBatch := func(resourceIdentity gnmiProductQualificationIdentity) pmetric.Metrics {
		metrics := pmetric.NewMetrics()
		resourceMetrics := metrics.ResourceMetrics().AppendEmpty()
		putGNMIProductQualificationResource(resourceMetrics.Resource(), resourceIdentity)
		metricValue := resourceMetrics.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
		metricValue.SetName("test.metric")
		metricValue.SetEmptyGauge().DataPoints().AppendEmpty().SetIntValue(1)
		return metrics
	}
	wrong := identity
	wrong.Target = "other-target"
	for bucket := range 3 {
		sink.recordAt(metricBatch(wrong), started.Add(time.Duration(bucket)*time.Second))
	}
	assert.Zero(t, sink.intervalCount("test.metric"))
	sink.recordAt(metricBatch(identity), started)
	assert.Equal(t, 1, sink.intervalCount("test.metric"))
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
	identity := testGNMIProductQualificationIdentity()
	sink := newGNMIProductQualificationSink(started, interval, []string{"test.metric"}, identity)
	metrics := pmetric.NewMetrics()
	resourceMetrics := metrics.ResourceMetrics().AppendEmpty()
	putGNMIProductQualificationResource(resourceMetrics.Resource(), identity)
	metricValue := resourceMetrics.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
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

	alternating := newGNMIProductQualificationSink(started, interval, []string{"test.metric"}, identity)
	point := metricValue.Gauge().DataPoints().At(0)
	for bucket, identity := range []string{"a", "b", "c"} {
		point.Attributes().PutStr("series", identity)
		alternating.recordAt(metrics, started.Add(time.Duration(bucket)*interval))
	}
	assert.Equal(t, 1, alternating.intervalCount("test.metric"), "different series cannot fabricate repeated intervals")
}

type gnmiProductQualificationSummary struct {
	verifiedResource bool
	deviceUp         bool
	deviceUpSeen     bool
	deviceUpTime     uint64
	positiveValues   map[string]bool
}

func summarizeGNMIProductQualification(
	all []pmetric.Metrics,
	required []string,
	expected gnmiProductQualificationIdentity,
) gnmiProductQualificationSummary {
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
			if !resourceMatchesGNMIProductQualification(resourceMetrics.Resource(), expected) {
				continue
			}
			summary.verifiedResource = true
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
	identity := testGNMIProductQualificationIdentity()
	availability := func(timestamp time.Time, value int64) pmetric.Metrics {
		metrics := pmetric.NewMetrics()
		resourceMetrics := metrics.ResourceMetrics().AppendEmpty()
		putGNMIProductQualificationResource(resourceMetrics.Resource(), identity)
		metricValue := resourceMetrics.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
		metricValue.SetName("cisco.device.up")
		point := metricValue.SetEmptyGauge().DataPoints().AppendEmpty()
		point.SetTimestamp(pcommon.NewTimestampFromTime(timestamp))
		point.SetIntValue(value)
		return metrics
	}
	started := time.Unix(1_700_000_000, 0)
	summary := summarizeGNMIProductQualification([]pmetric.Metrics{
		availability(started, 1), availability(started.Add(time.Second), 0),
	}, nil, identity)
	assert.True(t, summary.verifiedResource)
	assert.True(t, summary.deviceUpSeen)
	assert.False(t, summary.deviceUp, "historical up state cannot hide a later down transition")
}

func testGNMIProductQualificationIdentity() gnmiProductQualificationIdentity {
	return gnmiProductQualificationIdentity{
		Target: "target", Product: gnmiProductCatalyst9300, Model: "C9300-48UXM",
		Version: "17.18.1", BootMode: gnmiIOSXEBootModeInstall,
	}
}

func putGNMIProductQualificationResource(
	resource pcommon.Resource,
	identity gnmiProductQualificationIdentity,
) {
	attributes := resource.Attributes()
	attributes.PutStr("host.name", identity.Target)
	attributes.PutStr("cisco.product.family", identity.Product)
	attributes.PutStr("device.manufacturer", "Cisco")
	attributes.PutStr("device.model.identifier", identity.Model)
	attributes.PutStr("os.version", identity.Version)
	if identity.BootMode != "" {
		attributes.PutStr("cisco.os.boot_mode", identity.BootMode)
	}
}

type gnmiProductE2ETelemetry struct {
	values              map[string]float64
	activeSubscriptions map[string]float64
}

func collectGNMIProductE2ETelemetry(t *testing.T, reader *metric.ManualReader, target string) gnmiProductE2ETelemetry {
	t.Helper()
	var resourceMetrics metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &resourceMetrics))
	out := gnmiProductE2ETelemetry{
		values:              map[string]float64{},
		activeSubscriptions: map[string]float64{},
	}
	// A fresh MeterProvider is created for each harness invocation. A monotonic
	// counter with no current-run Add call has the unambiguous value zero even
	// though the SDK omits that time series from a manual-reader collection.
	for _, metricName := range gnmiProductE2EZeroOnAbsenceTelemetryMetricNames() {
		out.values[metricName] = 0
	}
	for _, scope := range resourceMetrics.ScopeMetrics {
		for _, instrument := range scope.Metrics {
			switch data := instrument.Data.(type) {
			case metricdata.Gauge[int64]:
				for _, point := range data.DataPoints {
					if !gnmiProductE2ETelemetryTargetMatches(point.Attributes, target) {
						continue
					}
					switch instrument.Name {
					case gnmiProductE2ETelemetryProductVerified, gnmiProductE2ETelemetryConnections,
						gnmiProductE2ETelemetryProfileDegraded:
						out.values[instrument.Name] += float64(point.Value)
					case gnmiProductE2ETelemetrySubscriptions:
						profile, ok := point.Attributes.Value(attribute.Key("cisco.gnmi.profile"))
						if ok && profile.Type() == attribute.STRING && profile.AsString() != "" {
							out.activeSubscriptions[profile.AsString()] += float64(point.Value)
						}
					}
				}
			case metricdata.Gauge[float64]:
				switch instrument.Name {
				case gnmiProductE2ETelemetryCacheUtilization, gnmiProductE2ETelemetryAuxiliaryUtilization:
					for _, point := range data.DataPoints {
						if !gnmiProductE2ETelemetryTargetMatches(point.Attributes, target) {
							continue
						}
						current, present := out.values[instrument.Name]
						if !present || point.Value > current {
							out.values[instrument.Name] = point.Value
						}
					}
				}
			case metricdata.Sum[int64]:
				if !gnmiProductE2EIntegerTelemetryMetric(instrument.Name) {
					continue
				}
				for _, point := range data.DataPoints {
					if !gnmiProductE2ETelemetryTargetMatches(point.Attributes, target) {
						continue
					}
					out.values[instrument.Name] += float64(point.Value)
				}
			}
		}
	}
	return out
}

func gnmiProductE2ESelfTelemetryMetricNames() []string {
	return []string{
		gnmiProductE2ETelemetryAuthenticationFailures,
		gnmiProductE2ETelemetryAuxiliaryUtilization,
		gnmiProductE2ETelemetryCacheOwnerResets,
		gnmiProductE2ETelemetryCacheUtilization,
		gnmiProductE2ETelemetryConnections,
		gnmiProductE2ETelemetryConsumerRefusals,
		gnmiProductE2ETelemetryDecodeErrors,
		gnmiProductE2ETelemetryInvalidTimestamps,
		gnmiProductE2ETelemetryOutOfOrderUpdates,
		gnmiProductE2ETelemetryPreflightFailures,
		gnmiProductE2ETelemetryProductVerified,
		gnmiProductE2ETelemetryProfileDegraded,
		gnmiProductE2ETelemetryReconnects,
		gnmiProductE2ETelemetryUnmappedValues,
		gnmiProductE2ETelemetryUnsupportedValueKinds,
	}
}

func gnmiProductE2EZeroOnAbsenceTelemetryMetricNames() []string {
	return []string{
		gnmiProductE2ETelemetryAuthenticationFailures,
		gnmiProductE2ETelemetryCacheOwnerResets,
		gnmiProductE2ETelemetryConsumerRefusals,
		gnmiProductE2ETelemetryDecodeErrors,
		gnmiProductE2ETelemetryInvalidTimestamps,
		gnmiProductE2ETelemetryOutOfOrderUpdates,
		gnmiProductE2ETelemetryPreflightFailures,
		gnmiProductE2ETelemetryProfileDegraded,
		gnmiProductE2ETelemetryReconnects,
		gnmiProductE2ETelemetryUnmappedValues,
		gnmiProductE2ETelemetryUnsupportedValueKinds,
	}
}

func gnmiProductE2EIntegerTelemetryMetric(metricName string) bool {
	switch metricName {
	case gnmiProductE2ETelemetryAuthenticationFailures,
		gnmiProductE2ETelemetryCacheOwnerResets,
		gnmiProductE2ETelemetryConnections,
		gnmiProductE2ETelemetryConsumerRefusals,
		gnmiProductE2ETelemetryDecodeErrors,
		gnmiProductE2ETelemetryInvalidTimestamps,
		gnmiProductE2ETelemetryOutOfOrderUpdates,
		gnmiProductE2ETelemetryPreflightFailures,
		gnmiProductE2ETelemetryProductVerified,
		gnmiProductE2ETelemetryProfileDegraded,
		gnmiProductE2ETelemetryReconnects,
		gnmiProductE2ETelemetryUnmappedValues,
		gnmiProductE2ETelemetryUnsupportedValueKinds:
		return true
	default:
		return false
	}
}

func validateGNMIProductE2ETelemetry(
	telemetry gnmiProductE2ETelemetry,
	expectedSubscriptions map[string]int64,
) error {
	if len(expectedSubscriptions) == 0 {
		return errors.New("qualification has no expected active subscription profiles")
	}
	for profile, count := range expectedSubscriptions {
		if profile == "" || count <= 0 || float64(count) > gnmiProductE2EMaximumExactJSONInteger {
			return fmt.Errorf("expected subscription plan contains an invalid profile/count pair %q=%d", profile, count)
		}
	}
	for metricName, value := range telemetry.values {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return fmt.Errorf("current-run self-telemetry metric %q must be finite and nonnegative", metricName)
		}
	}
	for _, metricName := range gnmiProductE2ESelfTelemetryMetricNames() {
		value, present := telemetry.values[metricName]
		if !present {
			return fmt.Errorf("current-run self-telemetry metric %q is missing", metricName)
		}
		if gnmiProductE2EIntegerTelemetryMetric(metricName) &&
			(value != math.Trunc(value) || value > gnmiProductE2EMaximumExactJSONInteger) {
			return fmt.Errorf("current-run self-telemetry metric %q is not a bounded exact integer", metricName)
		}
		switch metricName {
		case gnmiProductE2ETelemetryProductVerified, gnmiProductE2ETelemetryConnections:
			if value != 1 {
				return fmt.Errorf("current-run self-telemetry metric %q must equal 1, got %v", metricName, value)
			}
		case gnmiProductE2ETelemetryCacheUtilization, gnmiProductE2ETelemetryAuxiliaryUtilization:
			if value >= 1 {
				return fmt.Errorf("current-run self-telemetry metric %q reached exhausted capacity", metricName)
			}
		case gnmiProductE2ETelemetryUnmappedValues:
			// Unmapped values remain explicit evidence. They are not a release
			// blocker when the bounded counter remains a valid exact integer.
		default:
			if value != 0 {
				return fmt.Errorf("current-run disqualifying self-telemetry metric %q is %v", metricName, value)
			}
		}
	}
	if len(telemetry.activeSubscriptions) != len(expectedSubscriptions) {
		return fmt.Errorf(
			"active subscription profiles do not exactly match the plan: got %v, want %v",
			telemetry.activeSubscriptions,
			expectedSubscriptions,
		)
	}
	for profile, value := range telemetry.activeSubscriptions {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 ||
			value != math.Trunc(value) || value > gnmiProductE2EMaximumExactJSONInteger {
			return fmt.Errorf("active subscription count for profile %q must be a bounded nonnegative integer", profile)
		}
		expected, present := expectedSubscriptions[profile]
		if !present || value != float64(expected) {
			return fmt.Errorf("active subscription count for profile %q is %v, want %d", profile, value, expected)
		}
	}
	return nil
}

func gnmiProductE2ETelemetryTargetMatches(attributes attribute.Set, target string) bool {
	value, present := attributes.Value(attribute.Key("cisco.gnmi.target"))
	return present && value.Type() == attribute.STRING && value.AsString() == target
}

func TestGNMIProductE2ETelemetryTargetMatchingIsFailClosed(t *testing.T) {
	assert.False(t, gnmiProductE2ETelemetryTargetMatches(attribute.NewSet(), "target"))
	assert.False(t, gnmiProductE2ETelemetryTargetMatches(
		attribute.NewSet(attribute.String("cisco.gnmi.target", "other")), "target",
	))
	assert.False(t, gnmiProductE2ETelemetryTargetMatches(
		attribute.NewSet(attribute.Int("cisco.gnmi.target", 1)), "target",
	))
	assert.True(t, gnmiProductE2ETelemetryTargetMatches(
		attribute.NewSet(attribute.String("cisco.gnmi.target", "target")), "target",
	))
}

func validGNMIProductE2ETelemetry(expectedSubscriptions map[string]int64) gnmiProductE2ETelemetry {
	values := make(map[string]float64, len(gnmiProductE2ESelfTelemetryMetricNames()))
	for _, metricName := range gnmiProductE2ESelfTelemetryMetricNames() {
		values[metricName] = 0
	}
	values[gnmiProductE2ETelemetryProductVerified] = 1
	values[gnmiProductE2ETelemetryConnections] = 1
	activeSubscriptions := make(map[string]float64, len(expectedSubscriptions))
	for profile, count := range expectedSubscriptions {
		activeSubscriptions[profile] = float64(count)
	}
	return gnmiProductE2ETelemetry{
		values:              values,
		activeSubscriptions: activeSubscriptions,
	}
}

func TestValidateGNMIProductE2ETelemetryFailsClosed(t *testing.T) {
	expectedSubscriptions := map[string]int64{
		builtinGNMIProfileIdentity:   1,
		builtinGNMIProfileInterfaces: 1,
	}
	require.NoError(t, validateGNMIProductE2ETelemetry(
		validGNMIProductE2ETelemetry(expectedSubscriptions),
		expectedSubscriptions,
	))

	t.Run("current-run decode error", func(t *testing.T) {
		telemetry := validGNMIProductE2ETelemetry(expectedSubscriptions)
		telemetry.values[gnmiProductE2ETelemetryDecodeErrors] = 1
		require.ErrorContains(t, validateGNMIProductE2ETelemetry(telemetry, expectedSubscriptions), "disqualifying")
	})
	t.Run("bounded unmapped evidence is retained", func(t *testing.T) {
		telemetry := validGNMIProductE2ETelemetry(expectedSubscriptions)
		telemetry.values[gnmiProductE2ETelemetryUnmappedValues] = 17
		require.NoError(t, validateGNMIProductE2ETelemetry(telemetry, expectedSubscriptions))
	})
	t.Run("missing evidence", func(t *testing.T) {
		telemetry := validGNMIProductE2ETelemetry(expectedSubscriptions)
		delete(telemetry.values, gnmiProductE2ETelemetryInvalidTimestamps)
		require.ErrorContains(t, validateGNMIProductE2ETelemetry(telemetry, expectedSubscriptions), "missing")
	})
	t.Run("non-finite evidence", func(t *testing.T) {
		telemetry := validGNMIProductE2ETelemetry(expectedSubscriptions)
		telemetry.values[gnmiProductE2ETelemetryCacheUtilization] = math.NaN()
		require.ErrorContains(t, validateGNMIProductE2ETelemetry(telemetry, expectedSubscriptions), "finite")
	})
	t.Run("capacity exhausted", func(t *testing.T) {
		telemetry := validGNMIProductE2ETelemetry(expectedSubscriptions)
		telemetry.values[gnmiProductE2ETelemetryAuxiliaryUtilization] = 1
		require.ErrorContains(t, validateGNMIProductE2ETelemetry(telemetry, expectedSubscriptions), "exhausted")
	})
	t.Run("profile stopped", func(t *testing.T) {
		telemetry := validGNMIProductE2ETelemetry(expectedSubscriptions)
		telemetry.activeSubscriptions[builtinGNMIProfileInterfaces] = 0
		require.ErrorContains(t, validateGNMIProductE2ETelemetry(telemetry, expectedSubscriptions), "active subscription")
	})
}

func TestGNMIProductE2ELocalQualificationRejectsRecordedErrorCounter(t *testing.T) {
	preBackendReader := metric.NewManualReader()
	postBackendReader := metric.NewManualReader()
	provider := metric.NewMeterProvider(
		metric.WithReader(preBackendReader),
		metric.WithReader(postBackendReader),
	)
	t.Cleanup(func() {
		require.NoError(t, provider.Shutdown(context.Background()))
	})
	settings := receivertest.NewNopSettings(componentmetadata.Type)
	settings.MeterProvider = provider
	builder, err := componentmetadata.NewTelemetryBuilder(settings.TelemetrySettings)
	require.NoError(t, err)
	t.Cleanup(builder.Shutdown)

	const target = "qualification-counter-injection"
	telemetry := &gnmiTelemetry{builder: builder}
	telemetry.productVerified(t.Context(), target, true)
	telemetry.connection(t.Context(), target, true)
	telemetry.cacheUtilization(t.Context(), target, 1, 10, 1, 10)
	telemetry.auxiliaryStateUtilization(t.Context(), target, 1, 10, 1, 10)
	telemetry.subscription(t.Context(), target, builtinGNMIProfileIdentity, true)
	telemetry.subscription(t.Context(), target, builtinGNMIProfileInterfaces, true)

	expectedSubscriptions := map[string]int64{
		builtinGNMIProfileIdentity:   1,
		builtinGNMIProfileInterfaces: 1,
	}
	beforeBackend := collectGNMIProductE2ETelemetry(t, preBackendReader, target)
	require.NoError(t, validateGNMIProductE2ETelemetry(beforeBackend, expectedSubscriptions))

	telemetry.decodeErrors(t.Context(), target, builtinGNMIProfileInterfaces, 1)
	afterBackend := collectGNMIProductE2ETelemetry(t, postBackendReader, target)
	require.Equal(t, float64(1), afterBackend.values[gnmiProductE2ETelemetryDecodeErrors])
	require.ErrorContains(t, validateGNMIProductE2ETelemetry(afterBackend, expectedSubscriptions), "disqualifying")
}

func addGNMIProductE2EAuthorizationEvidenceQuery(
	query url.Values,
	product, authorizationEvidenceSHA256 string,
) error {
	if !gnmiProductE2ERequiresAuthorizationEvidence(product) {
		return nil
	}
	if err := validateGNMIProductE2EAuthorizationEvidenceSHA256(product, authorizationEvidenceSHA256); err != nil {
		return err
	}
	query.Set("authorization_evidence_sha256", authorizationEvidenceSHA256)
	return nil
}

func assertGNMIProductBackendDelivery(
	t *testing.T,
	rawURL, product, topology, version, model, imageEvidenceSHA256, authorizationEvidenceSHA256, bootMode, target, runID string,
	started time.Time,
	periodicMetrics []string,
	expectedSubscriptions map[string]int64,
	interval time.Duration,
	waitTimeout time.Duration,
) gnmiProductBackendAssertion {
	t.Helper()
	parsed, err := validateGNMIProductBackendURL(rawURL)
	require.NoError(t, err)
	query := parsed.Query()
	query.Set("product", product)
	if topology != "" {
		query.Set("topology", topology)
	}
	query.Set("software_version", version)
	query.Set("model_identifier", model)
	query.Set("image_evidence_sha256", imageEvidenceSHA256)
	require.NoError(t, addGNMIProductE2EAuthorizationEvidenceQuery(
		query, product, authorizationEvidenceSHA256,
	))
	if bootMode != "" {
		query.Set("boot_mode", bootMode)
	}
	query.Set("target", target)
	query.Set("run_id", runID)
	query.Set("not_before_unix_nano", strconv.FormatInt(started.UnixNano(), 10))
	query.Set("minimum_intervals", fmt.Sprint(gnmiProductE2EMinimumIntervals))
	query.Set("interval_unix_nano", strconv.FormatInt(interval.Nanoseconds(), 10))
	for _, metricName := range periodicMetrics {
		query.Add("periodic_metric", metricName)
	}
	query.Add("latest_metric", "cisco.device.up")
	for _, metricName := range gnmiProductE2ESelfTelemetryMetricNames() {
		query.Add("self_telemetry_metric", metricName)
	}
	profiles := make([]string, 0, len(expectedSubscriptions))
	for profile := range expectedSubscriptions {
		profiles = append(profiles, profile)
	}
	sort.Strings(profiles)
	for _, profile := range profiles {
		query.Add("self_telemetry_profile", profile)
	}
	parsed.RawQuery = query.Encode()
	client := &http.Client{
		Timeout:       min(30*time.Second, waitTimeout),
		CheckRedirect: gnmiProductBackendRedirectPolicy(parsed),
	}
	pollInterval := min(time.Second, max(100*time.Millisecond, waitTimeout/20))
	var qualified gnmiProductBackendAssertion
	require.EventuallyWithT(t, func(tt *assert.CollectT) {
		result, fetchErr := fetchGNMIProductBackendAssertion(t.Context(), client, parsed)
		if !assert.NoError(tt, fetchErr) {
			return
		}
		observedBefore := time.Now().UTC()
		if !assert.NoError(tt, validateGNMIProductBackendAssertion(
			result, product, topology, version, model, imageEvidenceSHA256, authorizationEvidenceSHA256,
			bootMode, target, runID,
			started, observedBefore, periodicMetrics, expectedSubscriptions, interval,
		)) {
			return
		}
		qualified = result
	}, waitTimeout, pollInterval, "backend did not attest the current exact-build qualification before the observation window closed")
	return qualified
}

type gnmiProductBackendAssertion struct {
	Delivered                                   bool               `json:"delivered"`
	RunID                                       string             `json:"run_id"`
	Target                                      string             `json:"target"`
	Product                                     string             `json:"product"`
	Topology                                    string             `json:"topology"`
	SoftwareVersion                             string             `json:"software_version"`
	ModelIdentifier                             string             `json:"model_identifier"`
	ImageEvidenceSHA256                         string             `json:"image_evidence_sha256"`
	AuthorizationEvidenceSHA256                 string             `json:"authorization_evidence_sha256"`
	ServerReadOnly                              *bool              `json:"server_read_only"`
	GNOIDisabled                                *bool              `json:"gnoi_disabled"`
	NegativeSetPermissionDenied                 *bool              `json:"negative_set_permission_denied"`
	NegativeGNOIPermissionDeniedOrUnimplemented *bool              `json:"negative_gnoi_permission_denied_or_unimplemented"`
	BootMode                                    string             `json:"boot_mode"`
	WindowStartUnixNano                         int64              `json:"window_start_unix_nano"`
	FirstObservationUnixNano                    int64              `json:"first_observation_unix_nano"`
	LastObservationUnixNano                     int64              `json:"last_observation_unix_nano"`
	MinimumIntervals                            int                `json:"minimum_intervals"`
	IntervalUnixNano                            int64              `json:"interval_unix_nano"`
	MetricIntervalBuckets                       map[string][]int64 `json:"metric_interval_buckets"`
	LatestMetricValues                          map[string]float64 `json:"latest_metric_values"`
	LatestMetricTimestamps                      map[string]int64   `json:"latest_metric_timestamps_unix_nano"`
	SelfTelemetryValues                         map[string]float64 `json:"self_telemetry_values"`
	ActiveSubscriptions                         map[string]float64 `json:"active_subscriptions"`
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
	product, topology, version, model, imageEvidenceSHA256, authorizationEvidenceSHA256, bootMode, target, runID string,
	started, observedBefore time.Time,
	periodicMetrics []string,
	expectedSubscriptions map[string]int64,
	interval time.Duration,
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
	if result.ImageEvidenceSHA256 != imageEvidenceSHA256 || result.BootMode != bootMode {
		return fmt.Errorf("backend did not attest the content-addressed image evidence and required boot mode")
	}
	if err := validateGNMIProductE2EBackendAuthorizationEvidence(
		result, product, authorizationEvidenceSHA256,
	); err != nil {
		return err
	}
	if result.Topology != topology {
		return fmt.Errorf("backend did not attest the operator-verified topology")
	}
	if result.MinimumIntervals != gnmiProductE2EMinimumIntervals || result.IntervalUnixNano != interval.Nanoseconds() {
		return fmt.Errorf("backend did not attest the requested interval contract")
	}
	if result.WindowStartUnixNano != started.UnixNano() || result.FirstObservationUnixNano < started.UnixNano() {
		return fmt.Errorf("backend observation window includes stale history")
	}
	if result.LastObservationUnixNano < result.FirstObservationUnixNano {
		return fmt.Errorf("backend observation timestamps are inconsistent")
	}
	latestAllowed := observedBefore.Add(gnmiProductE2EMaximumClockSkew).UnixNano()
	if result.FirstObservationUnixNano > latestAllowed || result.LastObservationUnixNano > latestAllowed {
		return fmt.Errorf("backend observation window contains future timestamps")
	}
	minimumSpan := int64(gnmiProductE2EMinimumIntervals-1) * interval.Nanoseconds()
	if result.LastObservationUnixNano-result.FirstObservationUnixNano < minimumSpan {
		return fmt.Errorf("backend observation window does not span %d distinct requested intervals", gnmiProductE2EMinimumIntervals)
	}
	for _, metricName := range periodicMetrics {
		buckets := result.MetricIntervalBuckets[metricName]
		if err := validateGNMIProductMetricIntervalBuckets(
			buckets, started, observedBefore, interval,
		); err != nil {
			return fmt.Errorf("backend metric %q interval evidence: %w", metricName, err)
		}
	}
	availability, present := result.LatestMetricValues["cisco.device.up"]
	if !present {
		return fmt.Errorf("backend latest cisco.device.up value is missing")
	}
	if math.IsNaN(availability) || math.IsInf(availability, 0) || availability != 1 {
		return fmt.Errorf("backend latest cisco.device.up value is not 1")
	}
	availabilityTimestamp, present := result.LatestMetricTimestamps["cisco.device.up"]
	if !present {
		return fmt.Errorf("backend latest cisco.device.up timestamp is missing")
	}
	if availabilityTimestamp < started.UnixNano() || availabilityTimestamp > latestAllowed {
		return fmt.Errorf("backend latest cisco.device.up observation is outside the current run window")
	}
	if err := validateGNMIProductE2ETelemetry(gnmiProductE2ETelemetry{
		values:              result.SelfTelemetryValues,
		activeSubscriptions: result.ActiveSubscriptions,
	}, expectedSubscriptions); err != nil {
		return fmt.Errorf("backend current-run self-telemetry evidence: %w", err)
	}
	return nil
}

func validateGNMIProductE2EBackendAuthorizationEvidence(
	result gnmiProductBackendAssertion,
	product, authorizationEvidenceSHA256 string,
) error {
	if !gnmiProductE2ERequiresAuthorizationEvidence(product) {
		return nil
	}
	if err := validateGNMIProductE2EAuthorizationEvidenceSHA256(product, authorizationEvidenceSHA256); err != nil {
		return fmt.Errorf("backend switch authorization evidence contract: %w", err)
	}
	if result.AuthorizationEvidenceSHA256 != authorizationEvidenceSHA256 {
		return fmt.Errorf("backend did not attest the exact content-addressed switch authorization evidence")
	}
	for _, attestation := range []struct {
		name  string
		value *bool
	}{
		{name: "server_read_only", value: result.ServerReadOnly},
		{name: "gnoi_disabled", value: result.GNOIDisabled},
		{name: "negative_set_permission_denied", value: result.NegativeSetPermissionDenied},
		{name: "negative_gnoi_permission_denied_or_unimplemented", value: result.NegativeGNOIPermissionDeniedOrUnimplemented},
	} {
		if attestation.value == nil {
			return fmt.Errorf("backend omitted required switch authorization attestation %q", attestation.name)
		}
		if !*attestation.value {
			return fmt.Errorf("backend switch authorization attestation %q is false", attestation.name)
		}
	}
	return nil
}

func validateGNMIProductMetricIntervalBuckets(
	buckets []int64,
	started, observedBefore time.Time,
	interval time.Duration,
) error {
	if len(buckets) < gnmiProductE2EMinimumIntervals {
		return fmt.Errorf("has fewer than %d distinct cadence buckets", gnmiProductE2EMinimumIntervals)
	}
	if interval <= 0 || observedBefore.Before(started) {
		return errors.New("has an invalid qualification time window")
	}
	maximumBucket := observedBefore.Add(gnmiProductE2EMaximumClockSkew).Sub(started) / interval
	currentBucket := observedBefore.Sub(started) / interval
	consecutive := 0
	maximumConsecutive := 0
	qualifyingEnd := int64(-1)
	previous := int64(-2)
	for _, bucket := range buckets {
		if bucket < 0 || bucket > int64(maximumBucket) {
			return errors.New("contains an out-of-window cadence bucket")
		}
		if bucket <= previous {
			return errors.New("cadence buckets must be strictly increasing and unique")
		}
		if bucket == previous+1 {
			consecutive++
		} else {
			consecutive = 1
		}
		previous = bucket
		maximumConsecutive = max(maximumConsecutive, consecutive)
		if consecutive >= gnmiProductE2EMinimumIntervals {
			qualifyingEnd = bucket
		}
	}
	if maximumConsecutive < gnmiProductE2EMinimumIntervals {
		return fmt.Errorf("does not contain %d consecutive cadence buckets", gnmiProductE2EMinimumIntervals)
	}
	if qualifyingEnd < max(0, int64(currentBucket)-1) {
		return errors.New("contains only stale cadence buckets")
	}
	return nil
}

func TestValidateGNMIProductMetricIntervalBucketsRejectsStaleRun(t *testing.T) {
	started := time.Unix(1_700_000_000, 0)
	require.NoError(t, validateGNMIProductMetricIntervalBuckets(
		[]int64{15, 16, 17}, started, started.Add(3*time.Minute), 10*time.Second,
	))
	require.ErrorContains(t, validateGNMIProductMetricIntervalBuckets(
		[]int64{0, 1, 2}, started, started.Add(3*time.Minute), 10*time.Second,
	), "stale")
}

func TestValidateGNMIProductBackendAssertionRequiresExactCurrentEvidence(t *testing.T) {
	started := time.Unix(1_700_000_000, 0)
	observedBefore := started.Add(30 * time.Second)
	imageEvidence := "sha256:" + strings.Repeat("a", 64)
	expectedSubscriptions := map[string]int64{
		builtinGNMIProfileIdentity:   1,
		builtinGNMIProfileInterfaces: 1,
	}
	selfTelemetry := validGNMIProductE2ETelemetry(expectedSubscriptions)
	selfTelemetry.values[gnmiProductE2ETelemetryUnmappedValues] = 7
	valid := gnmiProductBackendAssertion{
		Delivered: true, RunID: "run", Target: "target", Product: gnmiProductASR9000,
		SoftwareVersion: "24.4.1", ModelIdentifier: "ASR-9904", ImageEvidenceSHA256: imageEvidence,
		WindowStartUnixNano: started.UnixNano(), FirstObservationUnixNano: started.UnixNano(),
		LastObservationUnixNano: started.Add(20 * time.Second).UnixNano(),
		MinimumIntervals:        3,
		IntervalUnixNano:        (10 * time.Second).Nanoseconds(),
		MetricIntervalBuckets:   map[string][]int64{"system.cpu.utilization": {0, 1, 2}},
		LatestMetricValues:      map[string]float64{"cisco.device.up": 1},
		LatestMetricTimestamps:  map[string]int64{"cisco.device.up": started.Add(time.Second).UnixNano()},
		SelfTelemetryValues:     selfTelemetry.values,
		ActiveSubscriptions:     selfTelemetry.activeSubscriptions,
	}
	validate := func(result gnmiProductBackendAssertion) error {
		return validateGNMIProductBackendAssertion(
			result, gnmiProductASR9000, "", "24.4.1", "ASR-9904", imageEvidence, "", "",
			"target", "run", started, observedBefore, []string{"system.cpu.utilization"},
			expectedSubscriptions, 10*time.Second,
		)
	}
	require.NoError(t, validate(valid))

	mutations := []func(*gnmiProductBackendAssertion){
		func(result *gnmiProductBackendAssertion) { result.Delivered = false },
		func(result *gnmiProductBackendAssertion) { result.RunID = "stale-run" },
		func(result *gnmiProductBackendAssertion) { result.Product = gnmiProductNCS5500 },
		func(result *gnmiProductBackendAssertion) { result.Topology = "standalone" },
		func(result *gnmiProductBackendAssertion) { result.SoftwareVersion = "24.4.2" },
		func(result *gnmiProductBackendAssertion) { result.ModelIdentifier = "NCS-5501-SE" },
		func(result *gnmiProductBackendAssertion) {
			result.ImageEvidenceSHA256 = "sha256:" + strings.Repeat("b", 64)
		},
		func(result *gnmiProductBackendAssertion) { result.BootMode = gnmiIOSXEBootModeInstall },
		func(result *gnmiProductBackendAssertion) { result.MinimumIntervals = 2 },
		func(result *gnmiProductBackendAssertion) { result.IntervalUnixNano = time.Second.Nanoseconds() },
		func(result *gnmiProductBackendAssertion) {
			result.FirstObservationUnixNano = started.Add(-time.Second).UnixNano()
		},
		func(result *gnmiProductBackendAssertion) {
			result.LastObservationUnixNano = started.Add(19 * time.Second).UnixNano()
		},
		func(result *gnmiProductBackendAssertion) {
			result.LastObservationUnixNano = observedBefore.Add(gnmiProductE2EMaximumClockSkew + time.Second).UnixNano()
		},
		func(result *gnmiProductBackendAssertion) {
			result.MetricIntervalBuckets = map[string][]int64{"system.cpu.utilization": {0, 1}}
		},
		func(result *gnmiProductBackendAssertion) {
			result.MetricIntervalBuckets = map[string][]int64{"system.cpu.utilization": {0, 2, 4}}
		},
		func(result *gnmiProductBackendAssertion) {
			result.MetricIntervalBuckets = map[string][]int64{"system.cpu.utilization": {0, 1, 1}}
		},
		func(result *gnmiProductBackendAssertion) {
			result.MetricIntervalBuckets = map[string][]int64{"system.cpu.utilization": {2, 3, 4}}
		},
		func(result *gnmiProductBackendAssertion) {
			result.LatestMetricTimestamps = map[string]int64{"cisco.device.up": started.Add(-time.Second).UnixNano()}
		},
		func(result *gnmiProductBackendAssertion) {
			result.LatestMetricTimestamps = map[string]int64{
				"cisco.device.up": observedBefore.Add(gnmiProductE2EMaximumClockSkew + time.Second).UnixNano(),
			}
		},
		func(result *gnmiProductBackendAssertion) {
			result.LatestMetricValues = map[string]float64{"cisco.device.up": 0}
		},
		func(result *gnmiProductBackendAssertion) {
			delete(result.LatestMetricValues, "cisco.device.up")
		},
		func(result *gnmiProductBackendAssertion) {
			delete(result.LatestMetricTimestamps, "cisco.device.up")
		},
		func(result *gnmiProductBackendAssertion) {
			delete(result.SelfTelemetryValues, gnmiProductE2ETelemetryDecodeErrors)
		},
		func(result *gnmiProductBackendAssertion) {
			result.SelfTelemetryValues[gnmiProductE2ETelemetryDecodeErrors] = 1
		},
		func(result *gnmiProductBackendAssertion) {
			result.SelfTelemetryValues[gnmiProductE2ETelemetryUnsupportedValueKinds] = -1
		},
		func(result *gnmiProductBackendAssertion) {
			result.SelfTelemetryValues[gnmiProductE2ETelemetryCacheUtilization] = 1
		},
		func(result *gnmiProductBackendAssertion) {
			delete(result.ActiveSubscriptions, builtinGNMIProfileIdentity)
		},
		func(result *gnmiProductBackendAssertion) {
			result.ActiveSubscriptions[builtinGNMIProfileInterfaces] = 0
		},
	}
	for index, mutate := range mutations {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			result := valid
			result.MetricIntervalBuckets = make(map[string][]int64, len(valid.MetricIntervalBuckets))
			for metricName, buckets := range valid.MetricIntervalBuckets {
				result.MetricIntervalBuckets[metricName] = append([]int64(nil), buckets...)
			}
			result.LatestMetricValues = maps.Clone(valid.LatestMetricValues)
			result.LatestMetricTimestamps = maps.Clone(valid.LatestMetricTimestamps)
			result.SelfTelemetryValues = maps.Clone(valid.SelfTelemetryValues)
			result.ActiveSubscriptions = maps.Clone(valid.ActiveSubscriptions)
			mutate(&result)
			require.Error(t, validate(result))
		})
	}
}

func TestValidateGNMIProductBackendAssertionRequiresSwitchAuthorizationEvidence(t *testing.T) {
	started := time.Unix(1_700_000_000, 0)
	observedBefore := started.Add(30 * time.Second)
	imageEvidence := "sha256:" + strings.Repeat("a", 64)
	authorizationEvidence := "sha256:" + strings.Repeat("b", 64)
	expectedSubscriptions := map[string]int64{
		builtinGNMIProfileIdentity:   1,
		builtinGNMIProfileInterfaces: 1,
	}
	selfTelemetry := validGNMIProductE2ETelemetry(expectedSubscriptions)
	trueAttestation := true
	falseAttestation := false
	valid := gnmiProductBackendAssertion{
		Delivered: true, RunID: "run", Target: "target", Product: gnmiProductCatalyst9300,
		Topology: "standalone", SoftwareVersion: "17.18.1", ModelIdentifier: "C9300-48UXM",
		ImageEvidenceSHA256: imageEvidence, AuthorizationEvidenceSHA256: authorizationEvidence,
		ServerReadOnly: &trueAttestation, GNOIDisabled: &trueAttestation,
		NegativeSetPermissionDenied: &trueAttestation, NegativeGNOIPermissionDeniedOrUnimplemented: &trueAttestation,
		BootMode: gnmiIOSXEBootModeInstall, WindowStartUnixNano: started.UnixNano(),
		FirstObservationUnixNano: started.UnixNano(),
		LastObservationUnixNano:  started.Add(20 * time.Second).UnixNano(),
		MinimumIntervals:         gnmiProductE2EMinimumIntervals,
		IntervalUnixNano:         (10 * time.Second).Nanoseconds(),
		MetricIntervalBuckets:    map[string][]int64{"system.cpu.utilization": {0, 1, 2}},
		LatestMetricValues:       map[string]float64{"cisco.device.up": 1},
		LatestMetricTimestamps:   map[string]int64{"cisco.device.up": started.Add(time.Second).UnixNano()},
		SelfTelemetryValues:      selfTelemetry.values,
		ActiveSubscriptions:      selfTelemetry.activeSubscriptions,
	}
	validate := func(result gnmiProductBackendAssertion, expectedAuthorizationEvidence string) error {
		return validateGNMIProductBackendAssertion(
			result, gnmiProductCatalyst9300, "standalone", "17.18.1", "C9300-48UXM",
			imageEvidence, expectedAuthorizationEvidence, gnmiIOSXEBootModeInstall,
			"target", "run", started, observedBefore, []string{"system.cpu.utilization"},
			expectedSubscriptions, 10*time.Second,
		)
	}
	require.NoError(t, validate(valid, authorizationEvidence))

	for _, test := range []struct {
		name                          string
		expectedAuthorizationEvidence string
		mutate                        func(*gnmiProductBackendAssertion)
	}{
		{
			name: "missing expected evidence",
		},
		{
			name:                          "missing backend evidence",
			expectedAuthorizationEvidence: authorizationEvidence,
			mutate: func(result *gnmiProductBackendAssertion) {
				result.AuthorizationEvidenceSHA256 = ""
			},
		},
		{
			name:                          "mismatched backend evidence",
			expectedAuthorizationEvidence: authorizationEvidence,
			mutate: func(result *gnmiProductBackendAssertion) {
				result.AuthorizationEvidenceSHA256 = "sha256:" + strings.Repeat("c", 64)
			},
		},
		{
			name:                          "missing server read-only",
			expectedAuthorizationEvidence: authorizationEvidence,
			mutate: func(result *gnmiProductBackendAssertion) {
				result.ServerReadOnly = nil
			},
		},
		{
			name:                          "false server read-only",
			expectedAuthorizationEvidence: authorizationEvidence,
			mutate: func(result *gnmiProductBackendAssertion) {
				result.ServerReadOnly = &falseAttestation
			},
		},
		{
			name:                          "missing gNOI disabled",
			expectedAuthorizationEvidence: authorizationEvidence,
			mutate: func(result *gnmiProductBackendAssertion) {
				result.GNOIDisabled = nil
			},
		},
		{
			name:                          "false gNOI disabled",
			expectedAuthorizationEvidence: authorizationEvidence,
			mutate: func(result *gnmiProductBackendAssertion) {
				result.GNOIDisabled = &falseAttestation
			},
		},
		{
			name:                          "missing negative Set denial",
			expectedAuthorizationEvidence: authorizationEvidence,
			mutate: func(result *gnmiProductBackendAssertion) {
				result.NegativeSetPermissionDenied = nil
			},
		},
		{
			name:                          "false negative Set denial",
			expectedAuthorizationEvidence: authorizationEvidence,
			mutate: func(result *gnmiProductBackendAssertion) {
				result.NegativeSetPermissionDenied = &falseAttestation
			},
		},
		{
			name:                          "missing negative gNOI denial",
			expectedAuthorizationEvidence: authorizationEvidence,
			mutate: func(result *gnmiProductBackendAssertion) {
				result.NegativeGNOIPermissionDeniedOrUnimplemented = nil
			},
		},
		{
			name:                          "false negative gNOI denial",
			expectedAuthorizationEvidence: authorizationEvidence,
			mutate: func(result *gnmiProductBackendAssertion) {
				result.NegativeGNOIPermissionDeniedOrUnimplemented = &falseAttestation
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := valid
			if test.mutate != nil {
				test.mutate(&result)
			}
			require.Error(t, validate(result, test.expectedAuthorizationEvidence))
		})
	}

	nonSwitch := valid
	nonSwitch.Product = gnmiProductASR9000
	nonSwitch.Topology = ""
	nonSwitch.SoftwareVersion = "24.4.1"
	nonSwitch.ModelIdentifier = "ASR-9904"
	nonSwitch.AuthorizationEvidenceSHA256 = ""
	nonSwitch.ServerReadOnly = nil
	nonSwitch.GNOIDisabled = nil
	nonSwitch.NegativeSetPermissionDenied = nil
	nonSwitch.NegativeGNOIPermissionDeniedOrUnimplemented = nil
	nonSwitch.BootMode = ""
	require.NoError(t, validateGNMIProductBackendAssertion(
		nonSwitch, gnmiProductASR9000, "", "24.4.1", "ASR-9904", imageEvidence, "", "",
		"target", "run", started, observedBefore, []string{"system.cpu.utilization"},
		expectedSubscriptions, 10*time.Second,
	))
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
