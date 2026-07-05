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
| Cisco Catalyst Center | `catalyst_center`; HTTPS token flow | Metrics | Client, receiver, authentication, detail, and pagination tests | `TestE2ELiveCatalystCenter` | `Not run` |
| Cisco Catalyst 9800 WLC | `catalyst_9800`; gNMI dial-in and MDT gRPC dial-out | Metrics | Path catalog, decode, receiver, security, and runtime-contract tests | None dedicated | `Not run` |
| Cisco Catalyst SD-WAN Manager | `sdwan`; HTTPS REST API with JWT, session, bearer, or cookie auth | Metrics, logs | Client, auth/backoff, pagination, receiver, filtering, and all-group endpoint coverage tests | `TestE2ELiveSDWAN` | `Passed (limited scope)` for default groups; opt-in run has findings |
| Nexus Dashboard, NDFC, Insights, Orchestrator, and Data Broker | `nexus_dashboard`; HTTPS REST APIs | Metrics, logs | Client, receiver, endpoint-family, filtering, and pagination tests | `TestE2ENexusDashboardControllerAPI` | `Not run` |
| Cisco ACI and APIC | `aci`; HTTPS APIC class APIs | Metrics, logs | Client, receiver, filtering, statistics, and event tests | `TestE2EACIControllerAPI`, `TestE2EACIFullTelemetryInventory` | `Not run` |
| Cisco Secure Firewall Management Center | `fmc`; HTTPS REST plus optional TLS eStreamer | Metrics, logs | Client, receiver, eStreamer, and product-coverage tests | None | `Not run` |
| Cisco Identity Services Engine | `ise`; REST, OpenAPI, ERS, MnT, pxGrid, and Data Connect | Metrics, logs | Client, receiver, pxGrid, Data Connect, and endpoint-family tests | None | `Not run` |
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
`openconfig-interfaces` model names.
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
| `nexus_9000` | Not recorded | Not recorded | Identity and interfaces; no system profile | None | `Not run` |
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

No shared-gNMI hardware run is retained in this repository; all five exact-build rows above therefore remain
`Not run`. Run the opt-in harness against one direct device at a time with a read-only account and verified TLS:

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

go test -tags=e2e -run '^TestE2EProductQualifiedGNMI$' -count=1 -timeout=10m ./receiver/ciscoosreceiver
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
| Meraki Dashboard | 2026-07-04 | Public Dashboard API with certificate verification enabled; five representative MS, MX, MR/CW, and Catalyst-managed devices plus the full 47-device organization | Post-fix live E2E passed under the race detector for both the selected devices and full organization. Both appliance and switch DOM operations succeeded, every selected serial emitted data, switch usage intervals were present, `cisco.scrape.partial_success=0`, and there were no API request errors. Run `meraki-live-clean-20260704T172741Z` produced 63 metrics/417 data points locally and 417 MTS in Splunk Observability Cloud. Live DOM endpoints returned no sensor values, so value conversion remains fixture-qualified. | Repeat after material API/receiver changes and add a representative cellular product if cellular telemetry is a release requirement. |
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

go test -tags=e2e -run '^TestE2ELiveSDWAN$' -count=1 -timeout=10m ./receiver/ciscoosreceiver
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
