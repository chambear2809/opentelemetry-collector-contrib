# Cisco Product Validation Matrix

This document distinguishes current live qualification from implementation-only coverage and records the campaigns
that support each live claim. Automated coverage or an available harness is not proof that a product or release
passed. The `cisco_os` receiver is still an alpha component, so a live result qualifies only the product version,
enabled feature set, topology, and scale that were exercised.

## Status Definitions

| Status | Meaning |
| --- | --- |
| `Qualified` | A post-fix live run passed its acceptance gates and a sanitized result was retained. |
| `Passed (limited scope)` | A post-fix live run passed, but production posture, scale, delivery, release, or feature coverage remains narrower than the integration. |
| `Run with findings` | A live run completed and produced actionable compatibility findings, but a post-fix result or durable sanitized evidence is still missing. |
| `Partial` | Only part of the product family, transport, or feature set has retained live evidence. |
| `Not run` | Automated coverage or a harness may exist, but no live result is recorded here. |

## Current Qualification Status

This is the quick decision view. “Validated scope” states only what has retained live evidence; “Main remaining gate”
is the shortest path to broader production qualification. Details of individual commands and reruns are grouped into
campaigns in [Consolidated Validation Campaigns](#consolidated-validation-campaigns).

| Integration | Surface | Status | Validated scope | Main remaining gate |
| --- | --- | --- | --- | --- |
| Cisco IOS, IOS XE, and NX-OS | `devices`; SSH metrics | `Partial` (latest NX-OS run: `Run with findings`) | NX-OS parsing and collection passed a short live run; the later persistent-session campaign has findings. | Fix and rerun persistent-session timeouts, verify host keys independently, and qualify IOS/IOS XE. |
| Meraki Dashboard | `meraki`; HTTPS REST metrics | `Qualified` | Selected devices and the full tested organization passed local and Splunk delivery gates. | Rerun after material changes; add cellular only if required. |
| Cisco Intersight | `intersight`; signed HTTPS metrics/logs | `Passed (limited scope)` | Metrics passed five intervals and exact-name backend readback; logs passed local deduplication and OTLP ingest. | Exercise nonempty optional domains and obtain exact searchable backend log readback. |
| Cisco Catalyst Center | `catalyst_center`; HTTPS metrics | `Passed (limited scope)` | Core groups and one targeted device passed four-interval local and backend gates. | Use verified production TLS and exercise a connected client plus additional identifier variants. |
| Cisco Catalyst 9800 WLC | `catalyst_9800`; gNMI/MDT metrics | `Not run` | Automated contracts exist; no retained live qualification. | Run an exact-build campaign with representative AP/client state and backend delivery. |
| Cisco Catalyst SD-WAN Manager | `sdwan`; HTTPS metrics/logs | `Passed (limited scope)` | Default groups passed local and backend metric gates; the all-opt-in sweep produced scoped feature/role findings. | Use verified TLS, deliver logs to the backend, and qualify intended scale and installed features. |
| Nexus Dashboard, NDFC, Insights, Orchestrator, and Data Broker | `nexus_dashboard`; HTTPS metrics/logs | `Passed (limited scope)` | Platform and one targeted NDFC switch passed four-interval local and backend metric gates. | Use verified TLS and qualify physical scale, logs, Insights, Orchestrator, Data Broker, and performance. |
| Cisco ACI/APIC | `aci`; HTTPS metrics/logs | `Run with findings` | A pre-hardening metrics pilot passed locally and in Splunk. | Rebuild and rerun the current patch with verified TLS, least privilege, endpoints, and soak coverage; keep logs disabled until raw-body privacy and restart-safe deduplication are addressed. |
| Cisco Secure FMC | `fmc`; HTTPS/eStreamer metrics/logs | `Not run` | Automated coverage exists; no retained live qualification. | Run a bounded live campaign with verified TLS and destination delivery. |
| Cisco Identity Services Engine | `ise`; REST, OpenAPI, ERS, MnT, pxGrid, Data Connect | `Passed (limited scope)` | [ISE 3.4 campaign](#ise-3-4-campaign): REST/MnT/OpenAPI, ERS, pxGrid queries/polling logs/idle stream, all 19 default Data Connect views, and a bounded REST/ERS/pxGrid-polling metric profile delivered to Splunk; polling logs were validated locally. | Unique pxGrid identity, secondary port-443 API Gateway, live pxGrid events/ACKs, searchable backend logs, failover, soak, and scale. |
| Cisco IOS XR | `ios_xr`; gNMI/MDT metrics | `Not run` | Automated contracts exist; no retained live qualification. | Run exact supported builds with verified TLS and backend delivery. |
| Product-qualified shared gNMI | `gnmi`; secure Get/Subscribe metrics | `Run with findings` for Nexus 9000; otherwise `Not run` | The Nexus 9000 campaign reached semantic identity validation but did not start subscriptions. | Restore representative identity data, verified TLS, read-only auth, and backend assertion. |
| VAST VMS and CSI | Standard Prometheus receivers | `Not run` | Adjacent example/dashboard coverage only; not a `cisco_os` source. | Run the documented manual checklist if this adjacent integration is in scope. |

`Not run` does not mean unimplemented: automated coverage or a harness may exist without retained live evidence. The
native configuration surfaces are defined in [`config.go`](../config.go), and receiver wiring is defined in
[`factory.go`](../factory.go). VAST uses standard Collector components; see the
[VAST Storage guide](vast-storage.md).

## Consolidated Validation Campaigns

A campaign entry groups related validation milestones for one integration. Append or update a concise dated milestone
when the deployment and release remain comparable; create a new campaign when a materially different deployment,
release, topology, or validation period changes what the evidence can support. A campaign may cover several transports
or security postures when every difference is stated explicitly. This keeps compatibility findings visible without
adding one large row for every command.

The Splunk dashboard API observation is not listed because no sanitized live result was retained. No endpoint,
organization, device, or user identifiers—and no tokens, passwords, cookies, private keys, or raw event bodies—belong
in retained evidence.

<a id="ise-3-4-campaign"></a>

### Cisco ISE 3.4 combined qualification — 2026-07-05 to 2026-07-06

Overall status: `Passed (limited scope)` against a two-node Cisco ISE `3.4.0.608` sandbox.

| Area | What passed | Scope boundary |
| --- | --- | --- |
| REST/MnT and OpenAPI | Current session routes and empty-list decoding; 5 session metric operations and 2 detail-log operations; 837 bounded authentication-reference points; all 7 licensing operations. | The initial run used an administrative account and lab TLS bypass. Sessions were empty, and release-specific OpenAPI groups remain opt-in. |
| ERS | Dedicated ERS Operator, verified TLS, enhanced CSRF, forced pagination, and five qualified inventory families: 2 nodes, 5 network-device groups, 19 endpoint groups, 8 identity groups, and 16 SGTs (50 objects total) through 49 protected data requests. | Other ERS families and detail hydration remain unqualified. Secondary ERS passed on port `9060`; port `443` redirected to the admin UI because the secondary API Gateway was not enabled. |
| pxGrid | Certificate activation; 5 services and 9 providers; all 8 selected queries; session/RADIUS polling logs with non-vacuous replay suppression; one continuous 70-second idle WebSocket/STOMP subscription across the keepalive boundary. | No live event arrived, so broker acceptance, message delivery, and completed ACK writes remain unqualified. The client certificate needs a unique collector CN/SAN. |
| Data Connect | Verified TCPS using an explicitly trusted self-signed lab node certificate and a read-only validation account; database Ping; all 19 default views; three consecutive combined runs plus a race-detector run; and 25 administrator-login records with duplicate suppression. | Production CA trust and secret management, backend delivery, representative nonempty security views, and full-history views remain unqualified. Data Connect was disabled after validation. |
| Local Collector/backend E2R | Four 60-second intervals over 188 seconds; all 17 recurring operations succeeded in every interval; exactly 10 metric families and 366 local points; `ise.controller.up=1`, zero partial success, no exception points; exact 10-name backend match across 102 MTS, with at least one MTS per family retaining four buckets; exactly one session and one RADIUS log locally; clean exit. | pxGrid streaming and Data Connect were disabled. Metrics were read back from Splunk Observability Cloud; searchable backend log-body readback was unavailable. No AWS resources were used. |

Remaining production gates: rerun REST/MnT with verified TLS and least privilege; enable the secondary port-443 API
Gateway; reissue the pxGrid client certificate; generate representative pxGrid events; obtain backend log-body
readback; and complete longer soak, failover, representative-data, and production-scale testing.

Evidence: backend run `ise20260706T052704Z93625516450d`; source base
`77bf4152c6d1c6e3b566d749b767793da0510ee1`; run-time patch SHA-256
`aef856a4a76329daa3f539681f086a98d56eec0fe98a96da7f2f094a72dfce05`; binary SHA-256
`0c56dfbbdb468fa3e7c82620cce5246ffbacbc8c1260d896c7744031137140b4`; sanitized local evidence SHA-256
`5c4dc3bdba5cc13a936d6f8e2e9f41543d82393f6b73009e5e3e8f6bb218a198`. The evidence file is local and not
committed. The final implementation is commit `cd1e4dde26`; its post-run streaming ACK lifecycle delta was covered by
focused tests but was not present in the streaming-disabled backend binary.

### Cisco NX-OS over SSH — 2026-05-24 and 2026-07-05

- **What was combined:** The initial three-interval system/interface run and the later `N9K-C9300v` `10.6(1)`
  stress/cadence runs.
- **Result:** The initial run parsed 20 interfaces and emitted 8 metric families/245 points per interval. The later
  10-second steady-state window completed three clean intervals with 15 names, 966 points, and 69 interfaces, but the
  intended 30-second cadence reproduced persistent-session and command timeouts. Current status is `Run with findings`.
- **Evidence:** Latest sanitized SHA-256 values are
  `b33c4b192787561496a2fab58e599138d61dd7dbf3b0a83dcc1ea0ae71673bdb` and
  `3c19e3ac55d9c15fcb273bd56c901e9bc4c3ba66151f1a04f4a17f508b46b9a8`.

### Meraki Dashboard — 2026-07-04

- **What was done:** Race-enabled selected-device and full 47-device organization runs covering representative
  MS, MX, MR/CW, and Catalyst-managed products.
- **Result:** `Qualified` for the tested scope: 63 metric names/417 local points and 417 Splunk MTS, with zero partial
  success or API errors. Live DOM endpoints returned no sensor values, so conversion remains fixture-qualified.
- **Evidence:** Run `meraki-live-clean-20260704T172741Z`.

### Cisco Intersight — 2026-07-05

- **What was done:** Five metric intervals with all configured groups plus separate polling of all seven log families.
- **Result:** `Passed (limited scope)`: all 83 operations succeeded; 62 names and 6,493 unique streams matched in
  Splunk with five buckets. Local logging emitted 94 unique audit/alarm records with duplicate suppression and OTLP
  acceptance. Exact searchable backend log-body readback was unavailable.
- **Evidence:** Runs `intersight-complete-20260705T230938Z-6e8f3bee6da3` and
  `intersight-events-complete-20260705T225855Z-1ff9427d3742`; sanitized SHA-256 values
  `3bc0ccb355c9b4b5c1b7629ddfbc88e36de303f284a29819ca4b988cceca827d` and
  `0506300a66ca09f06c9b00b3eb1c01231f132521e5ce744c81dc530bf1e20b22`.

### Cisco Catalyst Center — 2026-07-05

- **What was combined:** Four core scrapes plus four targeted device-detail scrapes in the DevNet sandbox.
- **Result:** `Passed (limited scope)`: the core run emitted 30 names/6,089 points and matched 1,505 backend MTS; the
  targeted run matched all 34 local names across 1,510 MTS and retained four buckets for each targeted family. TLS
  verification was bypassed, and the sandbox exposed no connected client for client-detail qualification.
- **Evidence:** Runs `cc-20260705T165205Z-f0d7670fa6c5` and
  `cc-detail-device-4x-20260705T171727Z-29e4fb4e7be3`.

### Nexus Dashboard and NDFC — 2026-07-05

- **What was combined:** Four platform scrapes and four targeted one-switch NDFC scrapes against Nexus Dashboard
  `4.1.1g`.
- **Result:** `Passed (limited scope)`: platform metrics matched 7 names/20 MTS; targeted fabric metrics matched
  8 names/12 MTS, with four buckets per family and no exception points. TLS verification was bypassed.
- **Evidence:** Runs `ndplatform20260705T235228Za8a9cc1a7157` and
  `ndfabric20260705T235228Z254cb7ed4ac9`; sanitized SHA-256
  `b3b9664d96262581a59c6fae7a527b8828955b22a35ededda25debbecd3eccd3`.

### Nexus 9000 direct gNMI — 2026-07-05

- **What was combined:** Three staged preflights on one `N9K-C9300v` `10.6(1)`: OpenConfig disabled, then generic
  origin omission, then post-fix semantic identity validation.
- **Result:** `Run with findings`: the final attempt lacked a recognizable chassis identity, kept
  `product_verified=0`, started no subscriptions, and attempted no backend delivery. TLS verification was disabled;
  the short-lived certificate lacked a SAN.
- **Evidence:** Runs `nxgnmilab20260706T000752Za194d3339a20`,
  `nxgnmilab20260706T001755Zfdd37c840a34`, and
  `nxgnmilab20260706T002633Zecf650307b9b`; latest sanitized SHA-256
  `8152f5208e3dd083f6646d2c5d7f21bc23b7dbfde1f100615744b16d52dbfd43`.

### Cisco ACI/APIC — 2026-07-05

- **What was done:** Four 60-second metrics scrapes against APIC `6.1(3g)`, covering controller, fabric, nodes,
  faults, audit, events, statistics, tenants, and topology.
- **Result:** The pre-hardening pilot passed its scoped gates with all 28 operations, 23 metric families/14,309 local
  points, and 2,840 Splunk MTS, but it predates later correctness fixes and remains `Run with findings`.
- **Evidence:** Run `aci20260706T010752Zb2feaeb87626`; sanitized SHA-256
  `0d9e772ee5f47ffd0e4b57555c9a1899e42b813de7a8dfc6a540e2ecddc8d531`.

### Cisco Catalyst SD-WAN — 2026-07-04

- **What was combined:** The post-fix default-group run and the deliberate all-opt-in compatibility sweep against
  Manager `20.18.2.1`.
- **Result:** `Passed (limited scope)` for defaults: 25 names/199 points, exact 25/25 Splunk delivery, and 55 local
  logs. The opt-in sweep emitted 26 names/271 points and 241 active MTS; 17 optional operations returned feature,
  role, release, or license-related HTTP 403 findings and remain disabled by default.
- **Evidence:** Runs `sdwan-core-fixed-20260704T181702Z` and `sdwan-all-fixed-20260704T181826Z`.

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
| `nexus_9000` | `N9K-C9300v` | `10.6(1)` | Five reachable lab switches; one switch had OpenConfig enabled in running configuration only and was tested with required identity and interface profiles at 10-second cadence, but identity preflight stopped before Subscribe | Three staged 2026-07-05 lab preflights recorded in the consolidated campaign above; latest sanitized evidence SHA-256 `8152f5208e3dd083f6646d2c5d7f21bc23b7dbfde1f100615744b16d52dbfd43` | `Run with findings` |
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

For every new live result, update the current-status row only when the qualification claim changes. Append or update a
concise dated milestone in the existing product campaign when the deployment and release remain comparable; create a
new campaign when a materially different deployment, release, topology, or validation period changes what the
evidence can support. Record the exact product release, topology/scale, enabled groups, authentication mode,
certificate-verification posture, date, receiver revision, acceptance gates, and sanitized outcome. Preserve earlier
findings until a post-fix run explicitly closes them.
