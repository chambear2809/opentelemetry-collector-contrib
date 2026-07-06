# Cisco Product Validation Matrix

This document separates implemented coverage, an available live-test harness, and evidence from an actual live run.
Those are different claims: a harness is not proof that a product or release passed. The `cisco_os` receiver is still
an alpha component, so a live result qualifies only the product version, enabled feature set, topology, and scale that
were exercised.

## Status Definitions

| Status | Meaning |
| --- | --- |
| `Qualified` | A post-fix live run passed its acceptance gates and a sanitized result was retained. |
| `Passed (limited scope)` | A post-fix live run passed, but production posture, scale, delivery, release, or feature coverage remains narrower than the integration. |
| `Run with findings` | A live run completed and produced actionable compatibility findings, but a post-fix result or durable sanitized evidence is still missing. |
| `Partial` | Only part of the product family, transport, or feature set has retained live evidence. |
| `Not run` | Automated coverage or a harness may exist, but no live result is recorded here. |

## Integration Inventory

| Integration | Configuration and transport | Signals | Automated coverage | Live harness | Validation status |
| --- | --- | --- | --- | --- | --- |
| Cisco IOS, IOS XE, and NX-OS | `devices`; SSH with password or key authentication | Metrics | Parser, scraper, connection, and factory tests | `TestE2ELiveSwitch` | `Partial` (NX-OS only) |
| Meraki Dashboard | `meraki`; Dashboard REST API with API key | Metrics | Client, receiver, filtering, pagination, and payload-variant tests | `TestE2ELiveMeraki` | `Qualified` for the tested organization and product set |
| Cisco Intersight | `intersight`; signed REST API requests | Metrics, logs | Client, receiver, signing, filtering, pagination, identity-collision, telemetry-row, all-event-family, and live-empty-domain contract tests | `TestE2ELiveIntersight` | `Passed (limited scope)` for the tested account: metrics qualified end to end; logs qualified locally and accepted by OTLP ingest, but full backend log readback remains unavailable |
| Cisco Catalyst Center | `catalyst_center`; HTTPS token flow | Metrics | Client, receiver, authentication, detail, and pagination tests | `TestE2ELiveCatalystCenter` | `Passed (limited scope)` for the tested DevNet sandbox and bounded collection groups |
| Cisco Catalyst 9800 WLC | `catalyst_9800`; gNMI dial-in and MDT gRPC dial-out | Metrics | Path catalog, decode, receiver, security, and runtime-contract tests | None dedicated | `Not run` |
| Cisco Catalyst SD-WAN Manager | `sdwan`; HTTPS REST API with JWT, session, bearer, or cookie auth | Metrics, logs | Client, auth/backoff, pagination, receiver, filtering, and all-group endpoint coverage tests | `TestE2ELiveSDWAN` | `Passed (limited scope)` for default groups; opt-in run has findings |
| Nexus Dashboard, NDFC, Insights, Orchestrator, and Data Broker | `nexus_dashboard`; HTTPS REST APIs | Metrics, logs | Client, receiver, endpoint-family, filtering, and pagination tests | `TestE2ENexusDashboardControllerAPI` | `Passed (limited scope)` for unified platform and targeted NDFC metrics; unified logs, optional applications, performance, and switch detail remain unqualified |
| Cisco ACI and APIC | `aci`; HTTPS APIC class APIs | Metrics, logs | Client, receiver, exact per-dimension filtering, pagination-limit visibility, statistics, event-ordering, TLS, and payload-variant tests | `TestE2EACIControllerAPI`, `TestE2EACIFullTelemetryInventory` | `Run with findings` for one APIC `6.1(3g)`: the retained pre-hardening metrics pilot passed locally and in Splunk, but endpoints, logs, verified TLS, a token-lifetime soak, and the current post-run patch remain unqualified |
| Cisco Secure Firewall Management Center | `fmc`; HTTPS REST plus optional TLS eStreamer | Metrics, logs | Client, receiver, eStreamer, and product-coverage tests | None | `Not run` |
| Cisco Identity Services Engine | `ise`; REST, OpenAPI, ERS, MnT, pxGrid, and Data Connect | Metrics, logs | Client, receiver, pxGrid, Data Connect, endpoint-family, semantic-value, CSRF, response-protocol, pagination, TLS, and live-harness tests | `TestE2ELiveISE` bounded REST harness, `TestE2ELiveISEPxGrid` bounded pxGrid metrics/stream harness, `TestE2ELiveISEPxGridLogs` bounded polling-log/dedup harness, `TestE2ELiveISEDataConnect` bounded database harness, and a four-interval local Collector/backend readback gate | `Passed (limited scope)` for ISE 3.4 REST/MnT scalar counts/details, read-only ERS inventories with enhanced CSRF, pxGrid activation/discovery/bounded queries, session/RADIUS polling logs and replay suppression, a continuous verified idle WebSocket/STOMP subscription, failure-reference metadata, licensing, all 19 default Data Connect views, and exact Splunk Observability metric-name-set readback with verified TLS; Data Connect was disabled after validation. pxGrid live message delivery/ACK, searchable backend log readback, broader OpenAPI groups, and production scale remain unqualified. |
| Cisco IOS XR | `ios_xr`; gNMI dial-in and MDT gRPC dial-out | Metrics | Path catalog, decode, receiver, security, and runtime-contract tests | `TestE2EIOSXRGNMIDialIn`, `TestE2EIOSXRMDTDialOut` | `Not run` |
| Product-qualified shared gNMI | `gnmi`; secure Capabilities, bounded identity Get, and Subscribe dial-in for five product contracts with zero Set calls | Metrics | Contract, model-set, identity, request-shape, fixture, mapping, admission, delivery, resource-limit, and scale tests | `TestE2EProductQualifiedGNMI` exact-build harness | See the two gNMI matrices below |
| VAST VMS and CSI (adjacent, not a `cisco_os` source) | Standard Prometheus receivers using the provided VMS and Kubernetes examples | Metrics | Example loading and dashboard validation | Manual checklist only | `Not run` |

The native configuration surfaces are defined in [`config.go`](../config.go), and the exact metrics/logs receiver
wiring is defined in [`factory.go`](../factory.go). VAST uses standard Collector components rather than the
`cisco_os` receiver; see the [VAST Storage guide](vast-storage.md).

## Shared gNMI Product/Train Implementation Status

This table records deterministic implementation coverage. `Implemented` means the product/train contract, strict
version and chassis matching, Capabilities/model validation, bounded identity Get preflight, permitted metric
Subscribe shape, zero Set calls, metrics, and verified resource attributes have automated coverage. It does not mean
that any physical device or exact build has passed live qualification.

| `product` | Derived OS | Accepted train | Chassis family | Implemented curated catalog | Implementation status |
| --- | --- | --- | --- | --- | --- |
| `catalyst_9800` | `ios_xe` | `17.18.x` | `C9800-` or `CAT9800-` | Identity; CPU; per-location memory; interface status/cumulative counters; optional wireless; experimental DOM optics | `Implemented` |
| `asr_9000` | `ios_xr` | `24.4.x` | `ASR-9` | Identity; per-node CPU; interface status/cumulative counters; experimental controller/lane DOM optics | `Implemented` |
| `ncs_5500` | `ios_xr` | `24.4.x` | `NCS-55` | Identity; per-node CPU; interface status/cumulative counters; experimental controller/lane DOM optics | `Implemented` |
| `nexus_9000` | `nx_os` | `10.6(x)` | `N9K-` | Identity; interface status/cumulative counters; experimental DME DOM/VDM optics; no system profile | `Implemented` |
| `nexus_3500` | `nx_os` | `10.5(x)` | `N3K-C35` | Identity; interface status/cumulative counters; experimental DME DOM/VDM optics; no system profile | `Implemented` |

NX-OS contracts intentionally use the conservative common Nexus subset: JSON,
explicit non-wildcard paths, SAMPLE subscriptions with one 1-to-604800-second cadence per request, and no path prefix
or optional subscription flags. OpenConfig Get and Subscribe paths use generic wire origin `openconfig`, while
Capabilities validation retains the individual `openconfig-platform`, `openconfig-system`, and
`openconfig-interfaces` model names. NX-OS 10.6 may omit that requested generic origin from identity Get responses;
the identity validator accepts the omission only for the built-in NX-OS OpenConfig platform probe and still rejects
every explicit mismatched origin.
Cisco SONiC is explicitly unsupported and has no product/train implementation or live-qualification row.

## Shared gNMI Exact-Build Live Qualification Status

A live result applies only to the recorded model, exact canonical build, topology/scale, authentication and TLS posture,
and enabled profiles. Qualification requires verified TLS, no preflight failures, no degraded enabled profile, active
subscriptions, `cisco.device.up=1`, correct `cisco.product.family`, `device.model.identifier`, and `os.version`, backend
delivery, and at least three successful collection intervals. Cisco contracts also require
`device.manufacturer=Cisco`.

| `product` | Exact model | Exact software build | Profiles and topology | Retained evidence | Status |
| --- | --- | --- | --- | --- | --- |
| `catalyst_9800` | Not recorded | Not recorded | Identity, CPU, memory, interfaces, and `catalyst_9800_wireless`; representative AP/client state required | None | `Not run` |
| `asr_9000` | Not recorded | Not recorded | Identity, per-node CPU, and interfaces | None | `Not run` |
| `ncs_5500` | Not recorded | Not recorded | Identity, per-node CPU, and interfaces | None | `Not run` |
| `nexus_9000` | `N9K-C9300v` | `10.6(1)` | Five reachable lab switches; one switch had OpenConfig enabled in running configuration only and was tested with required identity and interface profiles at 10-second cadence, but identity preflight stopped before Subscribe | Three staged 2026-07-05 lab preflights recorded below; latest sanitized evidence SHA-256 `8152f5208e3dd083f6646d2c5d7f21bc23b7dbfde1f100615744b16d52dbfd43` | `Run with findings` |
| `nexus_3500` | Not recorded | Not recorded | Identity and interfaces; no system profile | None | `Not run` |

Every optional optics profile requires separate physical qualification and does not become qualified when the baseline
product row passes: IOS XE DOM, IOS XR controller/lane DOM, and NX-OS DME DOM/VDM all remain experimental.

The opt-in live harness must be given the expected product, exact software version, model identifier, required metric
names, and backend-delivery assertion. Retained sanitized output must show zero preflight failures, no degraded enabled
profiles, active subscriptions, and the same required metric series delivered in at least three distinct wall-clock
collection intervals before a row changes from `Not run`.

Every harness invocation creates a random run ID and a unique `host.name`, and asks the backend to consider only
observations at or after the local run start. The assertion endpoint must echo `run_id`, `target`, and
`window_start_unix_nano`, and must return `first_observation_unix_nano` within that window; stale retained history is
not valid evidence for a new run. For IOS XE, the verified `os.version` is the exact public Cisco release label (for
example, `17.18.1a`) normalized from the internal install-version record. It does not attest SMUs or bit-for-bit image
identity.

### Reproducing exact-build shared-gNMI qualification

No completed shared-gNMI qualification is retained in this repository. The `nexus_9000` row records staged
TLS-bypass preflight findings and remains unqualified; the other four exact-build rows remain `Not run`. Run the
opt-in harness against one direct device at a time with a read-only account and verified TLS:

```shell
export CISCOOS_E2E_GNMI_ENDPOINT=nexus01.example.net:50051
export CISCOOS_E2E_GNMI_USERNAME=otel-telemetry
read -rs CISCOOS_E2E_GNMI_PASSWORD
export CISCOOS_E2E_GNMI_PASSWORD
export CISCOOS_E2E_GNMI_CA_FILE=/etc/otel/cisco-device-ca.pem
export CISCOOS_E2E_GNMI_SERVER_NAME=nexus01.example.net
export CISCOOS_E2E_GNMI_PRODUCT=nexus_9000
export CISCOOS_E2E_GNMI_SOFTWARE_VERSION='10.6(1)'
export CISCOOS_E2E_GNMI_MODEL_IDENTIFIER=N9K-C93180YC-FX3
export CISCOOS_E2E_GNMI_REQUIRED_METRICS='system.network.interface.status,system.network.io'
export CISCOOS_E2E_GNMI_BACKEND_ASSERT_URL=https://telemetry-evidence.example.net/assert

# Optional when the assertion service requires bearer authentication:
read -rs CISCOOS_E2E_GNMI_BACKEND_BEARER_TOKEN
export CISCOOS_E2E_GNMI_BACKEND_BEARER_TOKEN

(cd receiver/ciscoosreceiver && go test -tags=e2e -run '^TestE2EProductQualifiedGNMI$' -count=1 -timeout=10m .)
```

`CISCOOS_E2E_GNMI_CA_FILE` may be omitted when the device certificate chains to the system roots. Optional mutual TLS
uses both `CISCOOS_E2E_GNMI_CLIENT_CERT_FILE` and `CISCOOS_E2E_GNMI_CLIENT_KEY_FILE`. The harness has no insecure TLS
mode. `CISCOOS_E2E_GNMI_SAMPLE_INTERVAL` defaults to `10s` and accepts `1s` through `5m`;
`CISCOOS_E2E_GNMI_WAIT_TIMEOUT` defaults to `3m`, must cover at least three sample intervals, and cannot exceed `30m`.

Use metrics that the selected baseline actually emits. Catalyst 9800 can require
`system.cpu.utilization,system.memory.utilization,system.network.io`; the harness also requires its three wireless
metrics and positive representative AP/client state. ASR 9000 and NCS 5500 can require
`system.cpu.utilization,system.network.io`. Nexus can require
`system.network.interface.status,system.network.io`; it has no system profile. Do not include optics in a baseline row,
because the harness deliberately leaves the experimental optics profile disabled.

The backend assertion URL must be absolute HTTPS. The harness retries the assertion within the remaining qualification
window to allow for exporter latency. Each GET includes `product`, canonical `software_version`, `model_identifier`,
unique `target`, random `run_id`, `not_before_unix_nano`, `interval_unix_nano`, `minimum_intervals=3`, one repeated
`periodic_metric` parameter per required profile metric, and `latest_metric=cisco.device.up`. The service must filter
by the exact identity and current time window, count intervals independently for every periodic metric, and return
HTTP 200 with a JSON body like:

```json
{
  "delivered": true,
  "run_id": "<echo the request run_id>",
  "target": "<echo the request target>",
  "product": "nexus_9000",
  "software_version": "10.6(1)",
  "model_identifier": "N9K-C93180YC-FX3",
  "window_start_unix_nano": 1783180800000000000,
  "first_observation_unix_nano": 1783180801000000000,
  "last_observation_unix_nano": 1783180831000000000,
  "metric_intervals": {
    "system.network.interface.status": 3,
    "system.network.io": 3
  },
  "latest_metric_values": {
    "cisco.device.up": 1
  }
}
```

The identity fields and `window_start_unix_nano` must exactly echo the request, `first_observation_unix_nano` must be
at or after the requested window, every periodic metric must have at least three intervals, and the latest availability
value must be 1. `cisco.device.up` is presence/current-state evidence rather than a periodic metric, so it is not
incorrectly required in three intervals. This contract prevents retained historical telemetry or aggregate counts from
satisfying a new qualification run. Retain only a sanitized result containing the receiver revision, exact
product/model/build, enabled profiles, topology and scale, TLS/authentication posture, per-metric interval counts,
self-telemetry gates, and backend assertion outcome.

## Splunk Observability Dashboard Validation

The source tree currently contains 12 Splunk Observability Cloud bundles with 69 dashboards and 530 charts for Cisco
OS, Nexus switches, Meraki, Intersight, Catalyst Center, Catalyst 9800, SD-WAN, ISE, FMC, Nexus controllers/ACI,
IOS XR, and adjacent VAST storage correlation. The 2026-07-04 static validation passed all of these gates:

- every bundle parses as JSON and passes the repo-native schema, required-description, chart-type, variable, and
  12-column by 100-row layout checks;
- every bundle completes the all-bundle importer dry run;
- the importer payload tests cover current Splunk chart types, required dashboard-variable values, team-scoped
  writers, duplicate protection, safe retry behavior, rollback ordering, and layout limits;
- source-to-dashboard checks cover native metric families, high-risk dimensions, and all known cumulative metrics so
  cumulative counters are graphed as rates rather than raw running totals; and
- the FMC dashboard group has source-matched API trust, managed-firewall/interface health, VPN/HA, policy,
  deployment, audit, and change-evidence metrics.

The bundles use `TimeSeriesChart` because the chart endpoint has been observed to require that subtype even though a
published enum/example says `TimeSeries`; regression tests also reject stale publish-label options. No sanitized live
API transcript or result is retained in-tree, so the `us1` create, GET, and delete contract is not recorded as
qualified. A qualifying run must create and read back all requested groups, dashboards, and charts, verify exact
relationships, chart types, SignalFlow, filters, variables, and layouts, delete every temporary object, and retain a
sanitized result. Production rollout must additionally inspect rendering with representative telemetry and confirm
organization-specific team permissions, detector thresholds, and notification routing.

## Recorded Live Qualifications

The dashboard API compatibility observation above is intentionally absent from this table because no sanitized live
result is retained in-tree.

| Integration | Date | Environment and scope | Result and findings | Remaining qualification gate |
| --- | --- | --- | --- | --- |
| Cisco NX-OS over SSH | 2026-05-24 | One NX-OS target; system and interface scrapers; three collection intervals | Persistent SSH connected successfully. Each interval parsed 20 interfaces and exported 8 metric families with 245 data points; shutdown was clean. IOS and IOS XE were not exercised. | Run the current harness against representative IOS, IOS XE, and NX-OS releases with secure host-key verification and retain sanitized output. |
| Cisco Identity Services Engine REST/MnT core | 2026-07-05 | A two-node Cisco ISE `3.4.0.608` sandbox deployment; basic authentication with an administrative account; self-signed certificate and IP endpoint required explicit TLS verification bypass; bounded one-shot metrics and logs scrapes; bounded REST/MnT harness with ERS disabled, pxGrid not onboarded, and Data Connect forced off | The initial strict run reproduced obsolete MnT paths: `ActiveSessionsList` returned 405 and `AuthSessionsList` returned 404. After switching to the current `ActiveList` and `AuthList` routes and fixing current empty-list decoding, the combined `sessions,session_details` profile passed all 5 metric operations and both detail-log operations with HTTP 200, `ise.controller.up=1`, `ise.scrape.partial_success=0`, and a current `ise.scrape.last_success`; the empty sandbox emitted no session logs. The release-safe default now keeps only the three scalar count operations in `sessions`; row-level list polling and logs require opt-in `session_details`. The opt-in authentication-reference profile passed both MnT operations and emitted 837 bounded failure-reason reference points without misclassifying them as RADIUS failures. The opt-in licensing profile passed all 7 OpenAPI operations after correcting the tier-state list response mode. Separately, automated client tests cover redirect/HTML refusal, cookie-bound ERS enhanced-CSRF negotiation and one refresh after a token-protected 403, and authoritative ERS totals across server-clamped pages; ERS was not enabled during this initial run. | `Passed (limited scope)`. Repeat the REST/MnT run with a least-privilege account, non-empty representative sessions, backend delivery/readback, and production scale. ERS was subsequently enabled and qualified separately below with a dedicated account and verified TLS. Release-/feature-specific OpenAPI groups remain opt-in and require focused qualification. |
| Cisco Identity Services Engine ERS read-only | 2026-07-06 | Same ISE `3.4.0.608` deployment after ERS was enabled on both nodes with enhanced CSRF; dedicated ERS Operator account; each node certificate explicitly trusted as a PEM CA with SAN-matching SNI; exact-operation harness; forced one-result pages | The first live attempt exposed that ISE 3.4 rejects a multi-representation ERS `Accept` header with HTTP 400. After restricting ERS to `Accept: application/json`, the empty network-device inventory passed, then a strict nonempty primary-node run returned 2 nodes, 5 network-device groups, 19 endpoint groups, 8 identity groups, and 16 SGTs. All 50 decoded objects were collected through 48 successful protected paginated requests plus one successful protected node-list request; one CSRF fetch established the cookie-bound session. Every request returned HTTP 200, every ERS data request carried the negotiated token, TLS verification remained enabled, `ise.controller.up=1`, `ise.scrape.partial_success=0`, last-success advanced, and no request, endpoint, rate-limit, skipped-service, or unavailable-service error was emitted. The secondary node independently returned the same 5 network-device groups through its direct ERS port `9060` with identical health and CSRF assertions. Its port `443` still redirected to the admin UI, showing that ERS is enabled there but the secondary API Gateway is not. | `Passed (limited scope)`. Qualify the remaining enabled ERS families and detail hydration against representative nonempty data, enable and verify a secondary API Gateway for port-443 HA, deliver/read back telemetry from the production backend, and run longer-duration and production-scale gates. |
| Cisco Identity Services Engine pxGrid | 2026-07-06 | Same two-node ISE `3.4.0.608` deployment; pxGrid personas active on both nodes; TCP `8910`; manually approved ISE-issued certificate client; internal root CA trust; FQDN endpoints validated against each node's SAN | An administrative basic-auth probe was rejected with HTTP 401 as expected because pxGrid requires its own identity. The downloaded `ENCRYPTED PRIVATE KEY` exposed Cisco ISE's legacy PKCS#12 SHA-1/3DES PBE rather than PBES2, so bounded native compatibility was added and the original downloaded key then loaded successfully without writing plaintext key material. Activation and version passed, and all five selected services discovered 9 providers. All 8 receiver queries passed through 8 service lookups and 8 access-secret exchanges with HTTP 200 and no failed request; observed results included session, user-group, RADIUS-failure, system-health, system-performance, SGT, SGACL, and egress-policy data. The combined query profile passed three consecutive runs and one race-detector run with verified TLS, `ise.controller.up=1`, zero partial success, and a current last-success value. The initial stream error was traced to text WebSocket writes. Binary STOMP framing fixed that error, but a lifecycle-strict gate then exposed disconnects at the 30- and 60-second keepalive boundaries. Replacing raw STOMP newline heartbeats with bounded WebSocket Ping control frames and clearing each temporary write deadline fixed the x/net automatic-Pong failure. The final strict idle gate received STOMP `CONNECTED`, successfully wrote `SUBSCRIBE`, and held one continuous connection for a fresh full 70-second post-readiness window, crossing the 54-second Ping boundary. Its two service lookups and one access-secret exchange returned HTTP 200, with exactly one readiness event, no dependency growth, and no reconnect or failover. No event arrived, so broker acceptance, message delivery, and live ACK remain unqualified. The separate nonempty polling-log gate emitted one session and one RADIUS-failure record, observed both exact records again on its identical second request window, and suppressed both with zero replayed records. All log requests and dependencies returned HTTP 200 with verified TLS. The issued client CN duplicates the ISE node FQDN and should be replaced by a unique collector identity before production. | `Passed (limited scope)` for activation, discovery, bounded REST queries, session/RADIUS polling logs with non-vacuous replay suppression, and a continuous idle WebSocket/STOMP subscription across a keepalive interval. Generate representative events to qualify broker acceptance, live message delivery, and completed client ACK writes; reissue the client certificate with a unique collector CN/SAN; then qualify failover, backend delivery/readback, longer soak, and production scale. |
| Cisco Identity Services Engine Data Connect | 2026-07-05 | Same ISE `3.4.0.608` deployment; Data Connect temporarily enabled through its documented OpenAPI on the secondary Monitoring node; fixed read-only `dataconnect` database account; TCPS port `2484`; self-signed node certificate explicitly trusted as a PEM CA with SAN-matching DNS; 25-row cap and one-hour lookback; feature disabled again after the run | REST status and database Ping passed with verification enabled. All 19 default views passed individually, then the combined metrics-and-logs profile passed three consecutive runs and one race-detector run. Every query stayed within its cap; nonempty inventory included 2 nodes, 5 network-device groups, 1 policy set, 3 admin users, 8 user identity groups, and capped OpenAPI-operation, administrator-login, and profiling-policy results. The allowlisted log phase emitted 25 administrator-login records without printing bodies, and an identical second poll emitted zero duplicates. No query, REST, TLS, schema, permission, partial-success, or service-unavailable error was observed. | `Passed (limited scope)`. Repeat with production CA trust and secret management, representative nonempty RADIUS/TACACS/posture/security views, backend delivery/readback, longer soak, failover, and production scale. Qualify the explicitly opt-in full-history views separately. |
| Cisco Identity Services Engine local Collector and backend E2R | 2026-07-06 | Tested local `otelcontribcol` build from base HEAD `77bf4152c6d1c6e3b566d749b767793da0510ee1` plus run-time tracked/untracked patch SHA-256 `aef856a4a76329daa3f539681f086a98d56eec0fe98a96da7f2f094a72dfce05`; binary SHA-256 `0c56dfbbdb468fa3e7c82620cce5246ffbacbc8c1260d896c7744031137140b4`; dedicated ERS Operator account plus certificate-authenticated pxGrid; explicit REST and pxGrid CA trust with SAN-matching FQDNs; four 60-second polling intervals; pxGrid streaming and Data Connect disabled for this gate; unique run ID `ise20260706T052704Z93625516450d`; metrics exported to a local restrictive shadow and Splunk Observability Cloud, logs to a restrictive local shadow | Configuration validation passed. The local Collector emitted exactly 10 metric families and 366 points across four intervals spanning 188 seconds. All four `ise.controller.up` values were 1, all partial-success values were 0, last-success values were current and increasing, and no request, endpoint, rate-limit, skipped-service, or unavailable-service exception point appeared. Seventeen operations succeeded in all four intervals; the cookie-bound ERS CSRF negotiation correctly occurred once and was reused. The log pipeline emitted exactly one `pxgrid.session.get_sessions` and one `pxgrid.radius.get_failures` record across all four polls, with `event.domain=ise`, demonstrating production deduplication after the first batch. Backend metadata readback matched the exact 10-name local set across 102 complete MTS; every family had at least one MTS with four retained 60-second buckets, and the backend window returned no errors. The Collector exited cleanly with zero warnings or errors. Sanitized evidence SHA-256 is `5c4dc3bdba5cc13a936d6f8e2e9f41543d82393f6b73009e5e3e8f6bb218a198`. A subsequent streaming-only lifecycle hook made the message-required E2E gate wait for completed client ACK writes; focused unit, race, and E2E-tag checks passed, but that post-run delta is not represented by this streaming-disabled binary. | `Passed (limited scope)` for local-to-backend metrics and local logs/deduplication. A searchable logs API was not available, so exact backend log-body readback remains unqualified. Repeat with a unique production pxGrid client identity, secondary port-443 API Gateway, representative live pxGrid events, longer soak, failover, and production scale. |
| Cisco NX-OS over SSH follow-up | 2026-07-05 | One `N9K-C9300v` running NX-OS `10.6(1)`; username/password authentication; system and interface scrapers; strict pinning of a host key discovered through authenticated NDFC resource metadata, using TOFU rather than independent verification; 10-second stress and intended 30-second-cadence runs; Collector `0.155.0-dev`; live binary SHA-256 `26b0255118dec500fa7f77ba27b2b792df3d6697f3e63db7c1c642def8f0285f` | `TestE2ELiveSwitch` passed with 3 batches, 2,888 data points, 15 metric names, 69 interfaces, `cisco.device.up=1`, NX-OS identity, and clean shutdown. A 10-second Collector run produced three complete steady-state intervals after startup errors; each complete interval had 15 metric names, 966 data points, 69 interfaces, zero partial-success values, zero command errors, and zero reconnects. Repeated runs did not pass the clean gate: at the intended 30-second cadence only one of four pre-shutdown batches was complete, while the others reported `cisco.device.up=0` or partial success, command errors, SSH establishment/interface failures, and an observed `show system resources` timeout. The VPN had zero packet loss and sequential plus concurrent OpenSSH commands completed successfully, narrowing the finding to the receiver's persistent-session path. Sanitized steady-state and 30-second evidence SHA-256 values are `b33c4b192787561496a2fab58e599138d61dd7dbf3b0a83dcc1ea0ae71673bdb` and `3c19e3ac55d9c15fcb273bd56c901e9bc4c3ba66151f1a04f4a17f508b46b9a8`. | `Run with findings`. Diagnose and fix the persistent SSH session/command timeout behavior, then rerun the current rebuilt binary with an independently verified host key and retain at least three consecutive complete intervals with `cisco.device.up=1`, zero partial success, command errors, reconnects, or Collector warnings/errors, and destination delivery. IOS and IOS XE remain unqualified. |
| Meraki Dashboard | 2026-07-04 | Public Dashboard API with certificate verification enabled; five representative MS, MX, MR/CW, and Catalyst-managed devices plus the full 47-device organization | Post-fix live E2E passed under the race detector for both the selected devices and full organization. Both appliance and switch DOM operations succeeded, every selected serial emitted data, switch usage intervals were present, `cisco.scrape.partial_success=0`, and there were no API request errors. Run `meraki-live-clean-20260704T172741Z` produced 63 metrics/417 data points locally and 417 MTS in Splunk Observability Cloud. Live DOM endpoints returned no sensor values, so value conversion remains fixture-qualified. | Repeat after material API/receiver changes and add a representative cellular product if cellular telemetry is a release requirement. |
| Cisco Intersight post-fix metrics and logs | 2026-07-05 | Public Intersight SaaS API; signed API-key authentication; TLS certificate verification enabled; all configured metric groups and seven log families enabled; tested account emitted 2,176 metric resources per batch while the advisory, workflow, task, tech-support, HyperFlex, Kubernetes, and virtualization domains returned successful empty responses; five approximately 60-second intervals over 246 seconds; source base HEAD `8126f3630796ea86158a75b4b4945898c2abcb38` with the tested patch later committed as `0724fbc0f534429389af39ec22851746cb407e22`; Collector `0.155.0-dev` binary SHA-256 `0f2f0de37f1c7bffffb7353fd2d1dfa75e17ba206e4f66350428a3f879fd516f` | Metrics run `intersight-complete-20260705T230938Z-6e8f3bee6da3` emitted 62 metric families and 6,493 data points in each of five batches, with 6,493 unique streams and zero duplicate stream points per batch. All 83 operations—31 REST and 52 telemetry—succeeded, partial success remained zero, no API-error or rate-limit points were emitted, and the Collector shut down cleanly without warnings or errors. Splunk Observability Cloud matched the exact 62-name local set across 6,493 MTS, and every series retained five buckets. Logs run `intersight-events-complete-20260705T225855Z-1ff9427d3742` emitted 94 unique local records across audit and alarm families, reproduced all 94 exactly through the local shadow, emitted no duplicates on the second poll, and was accepted by the OTLP logs endpoint without exporter error. Exact public backend log-body readback was unavailable; a separate custom-event replay returned HTTP 200 but exposed only 71 of 94 records through search. Synthetic contracts passed for all seven log families. Sanitized metrics and logs evidence SHA-256 values are `3bc0ccb355c9b4b5c1b7629ddfbc88e36de303f284a29819ca4b988cceca827d` and `0506300a66ca09f06c9b00b3eb1c01231f132521e5ce744c81dc530bf1e20b22`. | `Passed (limited scope)`. Metrics are qualified for the tested account and observed data. Repeat against representative nonempty advisory, workflow/task, tech-support, HyperFlex, Kubernetes, and virtualization datasets, and obtain exact backend readback of all OTLP log bodies through Log Observer or a searchable log destination. Replace the exposed validation key before any reuse. |
| Catalyst Center | 2026-07-05 | Cisco DevNet Always-On sandbox; release summary installed build `3.723.75300`, system version `2.7.77`, and API envelope `2.0`; basic token authentication; TLS certificate verification bypass; inventory, interfaces, health, topology, and issues enabled with 25-result bounds; four scrapes at 60-second cadence; receiver revision `8126f36307` | Run `cc-20260705T165205Z-f0d7670fa6c5` completed four successful local OTLP batches over 192 seconds with 30 metric families and 6,089 data points. Every family appeared in all four intervals, all four `catalyst_center.scrape.partial_success` values were zero, and no API-error or rate-limit points were emitted. The Collector shut down cleanly with no warnings, exporter retries, drops, or errors. Splunk Observability Cloud readback matched the exact 30-name local set across 1,505 MTS, and each metric family had at least one MTS with four retained 60-second buckets; backend queries also found four distinct last-success values and no API-error or rate-limit points. | Repeat with certificate verification enabled against a production-trusted CA and representative production inventory and site scale. Targeted client detail remains unqualified. |
| Catalyst Center targeted device detail | 2026-07-05 | Same sandbox; one reachable managed device selected by UUID without retaining the identifier; TLS certificate verification bypass; four scrapes at 60-second cadence | Run `cc-detail-device-4x-20260705T171727Z-29e4fb4e7be3` completed four successful `device_detail` operations with HTTP 200 and emitted four points each for `catalyst_center.device.detail.health.score`, `catalyst_center.device.detail.communication.status`, `system.cpu.utilization`, and `system.memory.utilization` on the selected resource. All four partial-success values were zero, no API-error or rate-limit metrics were emitted, and the Collector shut down cleanly without exporter retries, drops, or errors. Splunk Observability Cloud readback matched all 34 local metric names across 1,510 MTS and retained four 60-second buckets for every targeted family and the detail-operation metric. | The sandbox exposed no client in the client list, client health, legacy issues, wired or wireless assurance events, or assurance-issues query, so client detail could not be qualified without fabricating a MAC. Repeat with an observed connected client, certificate verification enabled, and the other supported device identifiers or response variants when required. |
| Nexus Dashboard unified API profile | 2026-07-05 | Nexus Dashboard `4.1.1g`; one active primary `SE-VIRTUAL-DATA` OVA node; username/password authentication with one-time negotiation from the modern login route to cached `/login`; TLS certificate verification bypass; one discovered fabric with five switches; separate platform and one-switch targeted NDFC runs, each using four 60-second scrapes; source HEAD `0724fbc0f534429389af39ec22851746cb407e22` plus tracked-patch SHA-256 `52e62563230f3c671054aa3cc7004ad38cc3ee574b1f2ce8ce29921c89805438`; Collector binary SHA-256 `26b0255118dec500fa7f77ba27b2b792df3d6697f3e63db7c1c642def8f0285f` | Platform run `ndplatform20260705T235228Za8a9cc1a7157` completed four scrapes over 180 seconds with four successful unified infrastructure operations per scrape, 7 metric families/74 local points, four zero partial-success values, and four current, nondecreasing last-success values. It emitted no exception points. Splunk Observability Cloud matched all 7 names across 20 MTS and retained four 60-second buckets for every family. Targeted fabric run `ndfabric20260705T235228Z254cb7ed4ac9` completed four scrapes over 181 seconds with three successful unified Manage operations per scrape and 8 metric families/42 local points. It emitted only the selected `N9K-C9300v` running NX-OS `10.6(1)`, reported `cisco.device.up=1` in all four intervals, retained four current, nondecreasing last-success values, and emitted no exception points. Splunk matched all 8 names across 12 MTS and retained four buckets for every family. Both Collectors exited cleanly; each emitted only the expected lab TLS-bypass warning. Sanitized evidence SHA-256 is `b3b9664d96262581a59c6fae7a527b8828955b22a35ededda25debbecd3eccd3`. | Repeat with certificate verification enabled and representative physical Nexus models, releases, multi-fabric inventory, and production scale. Unified logs, Insights, Orchestrator, Data Broker, interface performance, and receiver-driven switch detail remain unqualified. A direct switch-detail API probe returned HTTP 200 but did not exercise receiver parsing, filtering, multi-interval emission, or backend delivery. Nested hardware/resource and switch-summary payload semantics remain resource-presence evidence rather than qualified numeric mappings. Qualify API-key and non-local-domain authentication only when required. |
| Nexus 9000 direct gNMI lab smoke | 2026-07-05 | Five `N9K-C9300v` switches running NX-OS `10.6(1)` were discovered through NDFC; every target was reachable over the VPN on SSH and gNMI port `50051`. One switch was tested with required identity and interface profiles at 10-second cadence using username/password authentication and encrypted TLS with verification explicitly disabled. The user-authorized `feature openconfig` change was made only on that switch and only in running configuration; startup configuration was not saved. | Initial run `nxgnmilab20260706T000752Za194d3339a20` authenticated successfully but found OpenConfig disabled and quarantined with `missing_model`. After OpenConfig was enabled, all required models were advertised; run `nxgnmilab20260706T001755Zfdd37c840a34` reached identity Get but found that NX-OS omitted the requested generic `openconfig` origin. A narrowly scoped compatibility fix admitted only that omission for the NX-OS platform identity probe. Post-fix run `nxgnmilab20260706T002633Zecf650307b9b` then reached semantic identity extraction but quarantined with `identity_missing` because platform state contained no recognizable chassis component. It kept `product_verified=0`, started zero subscriptions, emitted one batch containing only `cisco.device.up=0`, attempted no backend delivery, and shut down cleanly. The certificate was self-signed, valid for one day, and lacked a subject alternative name. Latest sanitized evidence SHA-256 is `8152f5208e3dd083f6646d2c5d7f21bc23b7dbfde1f100615744b16d52dbfd43`. | Restore a representative lab and capture a sanitized chassis discriminator plus model/version leaf shape, then rerun identity and interface subscriptions for at least three intervals. Full qualification also requires a SAN-bearing certificate with a trusted CA chain, a read-only account, and the HTTPS backend assertion service. Qualify optional NX-OS optics separately. |
| Cisco ACI/APIC metrics production pilot | 2026-07-05 | APIC `6.1(3g)`; one configured controller endpoint for a lab fabric with three APIC controllers, two leafs, and two spines; username/password authentication; TLS certificate verification bypass; one Collector replica; controller health, fabric, nodes, faults, audit, events, statistics, tenants, and topology enabled; endpoints and logs disabled; 60-second cadence, 45-second timeout, and one-hour event lookback; source HEAD `0724fbc0f534429389af39ec22851746cb407e22` plus tracked-patch SHA-256 `3d8f058aeb5038fbb49f4a02325780b92024b8016cad533c11d9f86d108afbe5`; Collector binary SHA-256 `f92c62f934ea9d643738018e04499630fed1395dc84fc15f8389dde13f6e445d` | Run `aci20260706T010752Zb2feaeb87626` completed four scrapes over 191 seconds with 23 metric families and 14,309 local data points. All 28 enabled non-login operations succeeded in every interval; all four `aci.controller.up` values were 1, all partial-success values were zero, last-success values were current and nondecreasing, and no API-error or rate-limit points were emitted. The Collector shut down cleanly with only the expected lab TLS-bypass warning. Splunk Observability Cloud readback matched the exact 23-name local set across 2,840 MTS, and every family had at least one MTS with four retained 60-second buckets. Sanitized evidence SHA-256 is `0d9e772ee5f47ffd0e4b57555c9a1899e42b813de7a8dfc6a540e2ecddc8d531`. The scoped metrics pilot passed, but the tested patch predates subsequent corrections for configured-cap truncation, newest-first event ordering, exact target-filter semantics, ACI CA/server-name configuration, and shared metric number kinds. | `Run with findings`. Rebuild and repeat the same four-interval local and backend gates on the current patch, then validate configured-cap and target-filter behavior live. Production qualification also requires certificate verification with a trusted SAN-bearing certificate, a dedicated read-only service account, a 48-hour soak crossing token lifetime, and representative scale/HA coverage. Endpoints remain unqualified; keep logs disabled until raw-body privacy and restart-safe deduplication are addressed. |
| Catalyst SD-WAN default groups | 2026-07-04 | Manager 20.18.2.1; JWT selected by auto auth; seven devices discovered; one reachable edge selected; self-signed lab TLS bypass | The initial run exposed singular `/dataservice/event` and string-valued `last_n_hours` requirements. After both fixes, run `sdwan-core-fixed-20260704T181702Z` reported `sdwan.manager.up=1`, `sdwan.scrape.partial_success=0`, a current last-success timestamp, 25 metric names/199 data points, and exact 25/25 metric-name delivery to Splunk. It captured 55 SD-WAN logs locally. | Validate production CA trust with verification enabled, deliver logs to the production backend, qualify the intended fleet size, and exercise non-JWT auth/release families only when they are deployment requirements. |
| Catalyst SD-WAN all opt-in sweep | 2026-07-04 | Same Manager and one-edge scope; all 16 opt-in groups deliberately enabled | Run `sdwan-all-fixed-20260704T181826Z` emitted 26 metric names/271 data points, produced 241 active Splunk MTS, delivered exact 26/26 names, and had no exporter failures. It correctly remained partial because 17 optional operations returned HTTP 403: `appqoe.status`, `appqoe.dre`, `branch.voice`, `cloud_onramp.gateways`, `hardware.environment`, `hardware.energy`, `lifecycle.reboot`, `management.sessions`, `nwpi.tasks`, `nwpi.events`, `policy_qos.qos`, `routing.routes`, `security.utd`, `security.zbfw`, `thousandeyes.agents`, `underlay.summary`, and `underlay.alarms`. | Treat each 403 as a role, release, feature, or license qualification failure—not delivery loss. Leave affected groups disabled unless focused validation passes after the deployment changes. |

No endpoint addresses, organization IDs, serial numbers, system IPs, usernames, tokens, passwords, session cookies, or
raw event bodies belong in retained validation evidence.

## SD-WAN Production Gate

The SD-WAN implementation has bounded response reads, pagination/result limits, request pacing, retry handling,
authentication backoff, same-origin redirect protection, per-operation health metrics, partial-success reporting,
target filters, log deduplication, and disabled-by-default high-cardinality feature groups. The live-run compatibility
fixes are regression-tested and the post-fix default path passed in the recorded one-edge lab scope. The integration is
not broadly production-qualified until the remaining gate below passes for the intended deployment.

1. Use HTTPS certificate verification with the production trust chain. `sdwan.insecure_skip_verify: true` is an
   isolated-lab setting and does not qualify a production deployment.
2. Start with the nine default groups. Enable opt-in groups only for installed/licensed features, use explicit target
   filters for per-device detail, and set `max_results` from measured cardinality and scrape duration.
3. Require `sdwan.manager.up=1`, `sdwan.scrape.partial_success=0`, a current `sdwan.scrape.last_success`, and no
   `sdwan.api.request.errors` or `sdwan.api.rate_limited` points during the qualification window.
4. Prove that inventory, control, BFD, app-route, interface, alarm, event, and audit operations complete within the
   configured timeout. Empty alarm/event/audit result sets are valid when the API operations themselves succeed.
5. Run for multiple collection intervals at the intended fleet size. Confirm stable memory, request volume, scrape
   duration, log deduplication, destination delivery, and clean shutdown/restart behavior.
6. Retain only a sanitized operation/metric/log inventory with the exact Manager release, enabled groups, topology
   scale, test date, receiver revision, and result.

## Reproducing SD-WAN Validation

The bounded live harness requires an explicit system-IP target so a validation run cannot fan out across an entire
fleet accidentally. Core groups are tested by default; opt-in groups are selected by name.

```shell
export CISCOOS_E2E_SDWAN_ENDPOINT=https://sdwan-manager.example.com
export CISCOOS_E2E_SDWAN_USERNAME=automation
read -rs CISCOOS_E2E_SDWAN_PASSWORD
export CISCOOS_E2E_SDWAN_PASSWORD
export CISCOOS_E2E_SDWAN_SYSTEM_IPS=10.0.0.1

# Lab only when the Manager certificate cannot be verified:
export CISCOOS_E2E_SDWAN_INSECURE_SKIP_VERIFY=true

# Optional: a comma-separated subset, or "all" for a bounded compatibility sweep.
export CISCOOS_E2E_SDWAN_OPT_IN_GROUPS=cloud_onramp,security

(cd receiver/ciscoosreceiver && go test -tags=e2e -run '^TestE2ELiveSDWAN$' -count=1 -timeout=10m .)
```

Optional bounds are `CISCOOS_E2E_SDWAN_TIMEOUT` (default `2m`, maximum `10m`),
`CISCOOS_E2E_SDWAN_MAX_RESULTS` (default `100`, maximum `1000`), and
`CISCOOS_E2E_SDWAN_EVENT_LOOKBACK` (default `1h`, maximum `24h`). The harness disables retries so a transient or
feature-specific endpoint failure cannot be hidden inside a passing qualification result.

Run the command from the repository root. Do not use the all-groups sweep as a production configuration template.
Feature-dependent 403/404 responses mean that group is not qualified for that Manager role, release, or license set;
leave it disabled unless the deployment is changed and the focused validation passes.

## Updating This Matrix

For every new live result, record the exact product release, topology/scale, enabled groups, authentication mode,
certificate-verification posture, date, receiver revision, acceptance gates, and sanitized outcome. A failed run is
useful evidence and should remain visible as `Run with findings` until a post-fix run closes it.
