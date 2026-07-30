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
| Cisco IOS, IOS XE, and NX-OS | `devices`; SSH metrics | `Partial` | One IOS XE Cat8000V and one NX-OS 9000v passed bounded local and Splunk backend gates; classic IOS remains unqualified. | Qualify classic IOS, verify host keys independently, and complete a longer representative soak/scale campaign. |
| Meraki Dashboard | `meraki`; HTTPS REST metrics | `Qualified` | Selected devices and the full tested organization passed local and Splunk delivery gates. | Rerun after material changes; add cellular only if required. |
| Cisco Intersight | `intersight`; signed HTTPS metrics/logs | `Passed (limited scope)` | Metrics passed five intervals and exact-name backend readback; logs passed local deduplication and OTLP ingest. | Exercise nonempty optional domains and obtain exact searchable backend log readback. |
| Cisco Catalyst Center | `catalyst_center`; HTTPS metrics | `Passed (limited scope)` | Core groups and one targeted device passed four-interval local and backend gates. | Use verified production TLS and exercise a connected client plus additional identifier variants. |
| Cisco Catalyst 9800 WLC | `catalyst_9800`; gNMI/MDT metrics | `Not run` | Automated contracts exist; no retained live qualification. | Run an exact-build campaign with representative AP/client state and backend delivery. |
| Cisco Catalyst SD-WAN Manager | `sdwan`; HTTPS metrics/logs | `Passed (limited scope)` | Default groups passed local and backend metric gates; the all-opt-in sweep produced scoped feature/role findings. | Use verified TLS, deliver logs to the backend, and qualify intended scale and installed features. |
| Nexus Dashboard, NDFC, Insights, Orchestrator, and Data Broker | `nexus_dashboard`; HTTPS metrics/logs | `Passed (limited scope)` | Platform and one targeted NDFC switch passed four-interval local and backend metric gates. | Use verified TLS and qualify physical scale, logs, Insights, Orchestrator, Data Broker, and performance. |
| Cisco ACI/APIC | `aci`; HTTPS metrics/logs | `Run with findings` | A pre-hardening metrics pilot passed locally and in Splunk. Complete exported logs are privacy-bounded and each log signal is opt-in, but neither has post-fix live evidence. | Rebuild and rerun with verified TLS, least privilege, endpoints, and soak coverage; qualify explicit log opt-ins, destination delivery, and restart-window replay before production log enablement. |
| Cisco Secure FMC | `fmc`; HTTPS/eStreamer metrics/logs | `Not run` | Automated coverage exists; no retained live qualification. | Run a bounded live campaign with verified TLS and destination delivery. |
| Cisco Identity Services Engine | `ise`; REST, OpenAPI, ERS, MnT, pxGrid, Data Connect | `Passed (limited scope)` | [ISE 3.4 campaign](#ise-3-4-campaign): REST/MnT/OpenAPI, ERS, pxGrid queries/polling logs/idle stream, all 19 default Data Connect views, and a bounded REST/ERS/pxGrid-polling metric profile delivered to Splunk; polling logs were validated locally. | Unique pxGrid identity, secondary port-443 API Gateway, live pxGrid events/ACKs, searchable backend logs, failover, soak, and scale. |
| Cisco IOS XR | `ios_xr`; gNMI/MDT metrics | `Passed (limited scope)` | [XRd 25.3.1 campaign](#ios-xr-xrd-25-3-1-campaign): verified-TLS eight-target dial-in, bounded soak and target-isolated recovery, path-compatibility inventory, and backend-confirmed hardened 30-second MDT dial-out. | Qualify shared `gnmi` on exact physical ASR 9000/NCS 5500 builds with least privilege, VDM/coherent/FEC optics, 5,000-port scale, and a production soak. |
| Product-contract shared gNMI | `gnmi`; secure Get/Subscribe metrics | `Run with findings` for Nexus 9000; otherwise `Not run` | Nexus 9000 reached semantic identity validation; XRd verified IOS XR model/identity failures quarantine before Subscribe. Catalyst 9300/9500 have implementation-only coverage. None is a success-path qualification. | Run exact physical product/build and topology success paths with verified TLS, least privilege, required profiles, and backend assertion. |

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

### Cisco NX-OS over SSH — 2026-05-24, 2026-07-05, and 2026-07-06

- **What was combined:** The initial three-interval system/interface run and the later `N9K-C9300v` `10.6(1)`
  stress/cadence runs.
- **Result:** The initial run parsed 20 interfaces and emitted 8 metric families/245 points per interval. The later
  10-second steady-state window completed three clean intervals with 15 names, 966 points, and 69 interfaces, but the
  intended 30-second cadence reproduced persistent-session and command timeouts. Current status is `Run with findings`.
- **2026-07-06 live recheck:** The built-in SSH e2e harness passed locally against one `N9K-C9300v` `10.6(1)` switch
  at a 10-second collection interval and emitted 15 metric names, 974 datapoints, and 70 interfaces in one collection
  batch. This improves confidence that the post-fix SSH path is currently healthy on the live lab image, but the run
  used a fresh `ssh-keyscan` pin and therefore retained TOFU host-key trust rather than an independently verified host
  key. It does not close the 30-second persistent-session or production host-key gates.
- **Evidence:** Latest sanitized SHA-256 values are
  `b33c4b192787561496a2fab58e599138d61dd7dbf3b0a83dcc1ea0ae71673bdb` and
  `3c19e3ac55d9c15fcb273bd56c901e9bc4c3ba66151f1a04f4a17f508b46b9a8`.

### Cisco IOS XE and NX-OS over SSH — 2026-07-07

- **What was done:** A production-like two-device SSH validation ran against one Cat8000V (`IOS XE 17.12.02`) and one
  Nexus 9000v (`NX-OS 9.3(5)`) using the receiver's `devices` surface, runtime-generated `known_hosts`, local file
  capture, and OTLP metric export with exact-name Splunk Observability Cloud readback.
- **Result:** `Partial` for the broader IOS/IOS XE/NX-OS family, but `Passed (limited scope)` for the tested lab
  targets. The run retained 10 host-scoped scrapes per device over 258 seconds, emitted 31 metric families and 13,765
  local datapoints, kept `cisco.device.up=1` and `cisco.scrape.partial_success=0` for both hosts, and confirmed both
  host dimensions in Splunk (`10.10.20.48`: 397 MTS, `10.10.20.40`: 2,358 MTS). Cat8000V-specific `cisco.qfp.*`
  dataplane metrics were present locally and in Splunk.
- **Scope boundary:** The run used fresh `ssh-keyscan` trust-on-first-use host keys, covered one IOS XE VM and one
  NX-OS VM only, and did not exercise classic IOS, IOS XR telemetry, production CA/host-key distribution, HA/failover,
  or a 24-hour soak.
- **Evidence:** Run `sshlab20260707T040201Z0614ed1776e3`; source base
  `9cd8989ef047b079f728a1423a0913d44c453696`; runtime patch SHA-256
  `ba80f6f0bbdbe839cfe5dff4b404b13b2c2e48d750d68014153e7fa221571780`; binary SHA-256
  `18ff57c1cba9495b03fe55c436d0ec07b8519df3dd87c8ca6608d484106ee60d`; sanitized evidence SHA-256
  `7a766fed70bd57c35765caf6fd15ee04ce067e7520072e33ddc424c4f40c3ec3`. The evidence file is local and not committed.

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

### Nexus Dashboard and NDFC — 2026-07-05 and 2026-07-06

- **What was combined:** Four platform scrapes and four targeted one-switch NDFC scrapes against Nexus Dashboard
  `4.1.1g`.
- **Result:** `Passed (limited scope)`: platform metrics matched 7 names/20 MTS; targeted fabric metrics matched
  8 names/12 MTS, with four buckets per family and no exception points. TLS verification was bypassed.
- **2026-07-06 local recheck:** The unified-API e2e harness passed in 5 seconds against the same one-fabric, five-switch
  sandbox using username/password authentication. This repeated only the local receiver assertion path and did not
  repeat backend readback, so the row remains `Passed (limited scope)`.
- **Evidence:** Runs `ndplatform20260705T235228Za8a9cc1a7157` and
  `ndfabric20260705T235228Z254cb7ed4ac9`; sanitized SHA-256
  `b3b9664d96262581a59c6fae7a527b8828955b22a35ededda25debbecd3eccd3`.

### Nexus 9000 direct gNMI — 2026-07-05 and 2026-07-06

- **What was combined:** Three staged preflights on one `N9K-C9300v` `10.6(1)`: OpenConfig disabled, then generic
  origin omission, then post-fix semantic identity validation.
- **Result:** `Run with findings`: the final attempt lacked a recognizable chassis identity, kept
  `product_verified=0`, started no subscriptions, and attempted no backend delivery. TLS verification was disabled;
  the short-lived certificate lacked a SAN.
- **2026-07-06 live follow-up:** On one switch, `feature openconfig` was disabled initially. Enabling it in running
  configuration caused `Capabilities` to advertise `openconfig-platform`, `openconfig-system`, and
  `openconfig-interfaces`, but the platform identity `Get` still returned only `LINECARD`, `CPU`, `FABRIC`, and `FRU`
  components. It exposed `N9K-X9364v` and `N9K-vSUP` component names and `10.6(1)` software versions, but no
  `CHASSIS` component and no `model-name` leaf. The receiver therefore continued to quarantine the target with
  `identity_missing` before `Subscribe`, emitting only `cisco.device.up`. Attempting `feature hardware-telemetry`
  returned `Invalid command` on the same 9000v image, so there was no additional obvious device-side knob to enrich
  OpenConfig platform identity. A second strict local receiver run against the same switch again quarantined immediately
  with `identity_missing` and emitted only `cisco.device.up=0`. A second `N9K-C9300v` switch still failed earlier with
  `missing_model` immediately after the same feature enable, so the current 9000v lab still does not prove a
  shared-gNMI success path.
- **Evidence:** Runs `nxgnmilab20260706T000752Za194d3339a20`,
  `nxgnmilab20260706T001755Zfdd37c840a34`, and
  `nxgnmilab20260706T002633Zecf650307b9b`; latest sanitized SHA-256
  `8152f5208e3dd083f6646d2c5d7f21bc23b7dbfde1f100615744b16d52dbfd43`. The 2026-07-06 follow-up was a local live
  recheck and no additional sanitized artifact was retained.

<a id="ios-xr-xrd-25-3-1-campaign"></a>

### Cisco IOS XR XRd gNMI and MDT — 2026-07-06

- **Dial-in compatibility and correctness:** The legacy `ios_xr` JSON_IETF surface passed verified TLS, authentication
  failures, untrusted-CA and name-mismatch failures, a non-vacuous exact-metric E2E gate, and all 45 curated paths against
  XRd Control Plane `25.3.1 LNT`. The path sweep found 25 data-producing paths, 12 valid empty paths, 7 models absent from
  Capabilities, and one schema-valid OpenConfig NTP path rejected by the provider. The initial one-target post-fix run
  retained four 60-second timestamps and complete Splunk readback at 114 names/565 MTS, including corrected counter
  semantics and interface attribution for `Null0` and an SR-TE virtual interface.
- **Eight-target extension:** All eight topology nodes used verified TLS 1.2+, explicit local AAA login/EXEC
  authorization, and one collector process. A broad compatibility sweep delivered 736,402 points to each exporter and
  reached Splunk at 991 names/120,506 MTS. A production-safe selection removed capability-absent paths and wire arrays
  whose list identity remained ambiguous. Recognizing IOS XR's unique scalar `entry` list key removed the remaining
  deterministic IS-IS loss while duplicate entries still fail closed. The post-fix run maintained eight active
  subscriptions for 20 minutes, delivered 1,037,979 points to each exporter with an empty queue, and ended with zero
  decode errors, dropped datapoints, unsupported paths, or compact-GPB payloads. Disabling one router's gRPC service
  reduced only that target and the aggregate active count, while the other seven continued; restoring the hardened
  stanza re-established verified TLS, resumed updates, and returned the active count to eight.
- **AAA finding:** The XRd read-only task group allowed operational CLI reads and denied configuration changes, but gNMI
  Subscribe returned `PermissionDenied`. Operator, sysadmin, and a constrained custom task group did not make the stream
  usable; `root-lr` did. The temporary elevated memberships were removed. This records a live XRd limitation and does not
  establish an acceptable least-privilege role for physical customer routers.
- **Shared `gnmi` preflight:** XRd is not an ASR 9000 or NCS 5500 and is outside the exact `24.4.x` product contracts.
  The shared surface correctly quarantined it before Subscribe: first for a missing required CPU model, then at the
  bounded IOS XR install-identity Get after the system profile was disabled. Each attempt emitted only
  `cisco.device.up=0`; this validates fail-closed behavior, not the shared success path.
- **MDT dial-out:** Live 30-second self-describing GPB exposed and then verified fixes for IOS XR's anonymous top-level
  `{keys, content}` row wrapper, cumulative counter semantics without optional external YANG files, and explicit virtual
  interface keys. The final hardened listener used verified TLS, a source allowlist, required source-to-node identity
  binding, receive/stream ceilings, an idle timeout, and rate limiting. Run
  `iosxr-xrd-dialout-final-20260706T201131Z` completed 23 router-confirmed collections over 681 seconds with zero deferred,
  send, drop, other, or collector errors. At the final checkpoint both exporters had accepted 5,106 points with an empty
  queue. Splunk readback contained all 222 MTS (37 names across 6 interfaces): 180 cumulative-counter and 42 gauge MTS.
  The representative byte counter retained all physical, management, `Null0`, and SR-TE identities and 6–8 backend
  buckets. The retained local file includes one final in-flight collection, for 24 intervals/5,328 points.
- **Splunk capacity finding:** The broad raw-YANG sweeps exceeded the POC organization's custom-MTS ceiling and Splunk's
  organization telemetry recorded 10,284 rejected custom-MTS creations even though ingest returned success. The limit
  was 93,073 and the rejection counter later returned to zero; final low-cardinality MDT series then became searchable.
  Full raw-YANG export is therefore not a production profile. Production validation must use a bounded normalized
  catalog, preflight expected MTS/DPM, and monitor Splunk limit/throttle metrics.
- **POC requirement decision:** The 5,000-port predictive-optics requirement remains `Not qualified`. XRd exposes no
  physical optics, its Capabilities omitted the tested optics models, and the current shared IOS XR optics catalog covers
  experimental controller/lane DOM only. It does not yet map the required IOS XR VDM, coherent DSP, or FEC sensor paths.
  No result in this campaign supports laser-EOL, Rx-fade, or coherent-degradation claims.
- **Scope boundary:** The campaign qualifies XRd `25.3.1` legacy dial-in and one hardened XRd MDT dial-out path only. It
  does not qualify the shared `gnmi` success path, physical ASR 9000/NCS/8201 hardware, IOS XR `24.4.x`, optical modules,
  least privilege, 5,000 ports, HA/failover, certificate rotation, a 24-hour soak, or production Splunk entitlements.
- **Evidence:** Historical runs remain `iosxr-fixed-canary-1783358542`, `iosxr-fixed-stream-1783358581`, and
  `iosxr-postfix-20260706T182746Z`. Extension runs are `iosxr-xrd8-20260706T185515Z`,
  `iosxr-xrd8-safe-postfix-20260706T192859Z`, and `iosxr-xrd-dialout-final-20260706T201131Z`. Current source base is
  `93506dc2e7ff171f3fdba4989777c70d5e0479b1`; the six-file runtime patch SHA-256 is
  `d0e232d14789f9bc5532790d0097e2b394ee4286ff230f6bc513fe7c96cef8f3`; the final Linux binary SHA-256 is
  `f7be5cb69ed168c2d20334cbaa530b990b9666d43008e7bc7bd3043aad0f6f09`. Dial-out metrics, collector log, complete
  backend MTS, representative MTS metadata, representative window, and Splunk limit evidence SHA-256 values are
  `86e56e67adcaccc343198ace87bd6ea1370721366e13ee7e54260f14c09e3a92`,
  `a7eb8badd0b42ec3002bcc3f4315160729d683f97ae76b8c37707269d2a05d6b`,
  `cd6346d60672b5d25c5cbc5e2f7fff560f8606fc8da0e2ca1f2191d1d3a8504b`,
  `4013fa476ec9a99c376d0cfc45141b4bc9b76a8142418cfa1eef3fa333b8eba3`,
  `2e78c1be1d7d84d986cec8e43f685f799d60e4d0b063a283d80075f4de62f7da`, and
  `df2aad8b4f0de1085c8d451bd5320e7ac28e1fb1e0abb62a86c4f5999cc1b490`. Sanitized artifacts remain local and are not
  committed.

### Cisco ACI/APIC — 2026-07-05

- **What was done:** Four 60-second metrics scrapes against APIC `6.1(3g)`, covering controller, fabric, nodes,
  faults, audit, events, statistics, tenants, and topology.
- **Result:** The pre-hardening pilot passed its scoped gates with all 28 operations, 23 metric families/14,309 local
  points, and 2,840 Splunk MTS, but it predates later correctness fixes and remains `Run with findings`.
- **Post-pilot release gate:** The current implementation leaves ACI metric defaults unchanged, disables each ACI log
  signal by default, and derives the complete exported log from fixed scalar `faultInst`, `aaaModLR`, and `eventRecord`
  allowlists plus controlled endpoint metadata. Dedup hashes that complete sanitized content, omits only replica-local
  audit identity copies, and remains controller-scoped. Deduplication is process-local without `storage` and
  storage-backed when configured. Configuration regressions require complete ACI target/auth settings for any log
  opt-in and reject top-level or per-signal null, string, list, and boolean shapes; YAML nulls are covered separately.
  This is automated hardening evidence rather than a new live result; explicit log opt-in, destination
  privacy/readback, cross-controller delivery, and live restart delivery and replay behavior remain unqualified.
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

This table records deterministic implementation coverage. `Implemented` means the product/train contract, canonical
software-release identifier and chassis matching, Capabilities/model validation, bounded identity Get preflight,
permitted metric Subscribe shape, zero Set calls, metrics, and verified resource attributes have automated coverage.
It does not mean that any physical device or exact build has passed live qualification.

| `product` | Derived OS | Accepted release/train | Chassis admission | Implemented curated catalog | Implementation status |
| --- | --- | --- | --- | --- | --- |
| `catalyst_9300` | `ios_xe` | `17.18.1` only; INSTALL boot mode | Explicit documented C9300/C9300L/C9300X base-PID allowlist; C9300LM excluded | Identity; CPU; per-location memory; interface status/cumulative counters; experimental DOM optics | `Implemented; explicit unqualified opt-in required` |
| `catalyst_9500` | `ios_xe` | `17.18.1` only; INSTALL boot mode | Explicit documented C9500/C9500X base-PID allowlist | Identity; CPU; per-location memory; interface status/cumulative counters; experimental DOM optics | `Implemented; explicit unqualified opt-in required` |
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

The Catalyst 9300 and Catalyst 9500 contracts deliberately use a conservative IOS XE 17.18.1 subset: advertised gNMI
version `0.4.0`, JSON_IETF, an RFC7951 subscription prefix, STREAM/SAMPLE, one 1-to-604800-second cadence per request,
no optional subscription flags, and no literal `*` selectors. Preflight requires exact reviewed
`ModelData(name, organization, version)` tuples for every required enabled module from a seven-entry closed direct
catalog. Custom origins, explicit model declarations, selectors, and mapped descendants cannot introduce another
module. Preflight also requires one consistent exact current-image identity across all current install locations and
INSTALL boot mode. Built-in
memory, interface, and experimental transceiver selectors use implicit list expansion,
which remains an exact-build live Subscribe gate. Explicit base-PID admission and synthetic test coverage establish an
implementation boundary only; they do not qualify every admitted SKU. Both contracts require
`allow_unqualified: true` while their physical-device rows are `Not run`; that acknowledgement does not change either
row's status. The `0.4.0` protocol pin comes from Cisco's 17.18 documentation; a public C9300 lab capture advertises
`0.7.0` but lacks the exact-build identity needed to qualify or admit that value. Retain the raw 17.18.1 Capabilities
response for each platform and update only the closed version allowlist after a separate compatibility review.

### Cat9000v non-qualification compatibility probe — 2026-07-29

This read-only probe exercised the contract-shaped gNMI requests against Cisco's shared
`devnetsandboxiosxec9k.cisco.com` Cat9000v sandbox. It validates transport interoperability and observed IOS XE
wire shapes only. The target is a virtual 17.15.1 C9KV rather than a physical C9300 or C9500 on 17.18.1, so this result
does not change either physical qualification row, remove `allow_unqualified: true`, or expand any closed contract
allowlist. Cisco's
[2026 sandbox material](https://www.ciscolive.com/c/dam/r/ciscolive/emea/docs/2026/pdf/DEVNET-2295.pdf)
identifies this target as a virtual Catalyst 9000 UADP eight-port switch running IOS XE 17.15.1 with gNMI access.

| Probe area | Observed result | C9300/C9500 17.18.1 contract disposition |
| --- | --- | --- |
| Reachability and authentication | TCP ports 22, 443, 830, and 9339 were reachable. Generated credentials authenticated to RESTCONF and gNMI; the SSH service rejected the same account, and NETCONF was not authenticated beyond TCP reachability. | Transport reachability alone is not qualification. |
| TLS | gNMI negotiated TLS 1.3. The peer certificate was self-signed, had no subject alternative name, and had SHA-256 fingerprint `FF:B7:89:9D:68:7A:87:E2:6B:B7:B3:B9:19:44:B6:84:1B:08:B9:5E:F5:21:39:45:EA:64:B5:00:B3:22:24:A1`. | The lab probe required explicit certificate-verification bypass. The verified-TLS qualification harness was not run. |
| Capabilities | Advertised gNMI `0.7.0` with JSON, JSON_IETF, and PROTO. | Fails first with `unsupported_gnmi_version`; the closed switch contract accepts `0.4.0` only. |
| Device and release identity | Hardware inventory reported virtual PID `C9KV-UADP-8P`. RESTCONF reported IOS XE `17.15`; Cisco's sandbox material identifies the exact release as 17.15.1. | Fails physical PID admission and the exact 17.18.1 release requirement. |
| Install identity | The contract-shaped Get returned `{}` for `install-version-info` and an empty `boot-mode`. | Cannot establish one current image or required INSTALL mode; identity remains unqualified. |
| Required ModelData | `device-hardware-oper` and `install-oper` advertised `2024-03-01`; `platform-software-oper` and `transceiver-oper` advertised `2023-11-01`. CPU advertised `2022-11-01`, OpenConfig interfaces `2.3.0`, and OpenConfig system `0.10.1`. | Four required Cisco tuples differ from the pinned 17.18.1 catalog and would fail with `unsupported_model_version`; the other three tuples match an accepted representation. |
| Identity profile | The RFC7951 STREAM/SAMPLE request for `openconfig-system:system/state` returned JSON_IETF state and a successful sync marker. | Request and aggregate-subtree wire shape observed; no physical identity qualification. |
| System profile | The combined 60-second STREAM/SAMPLE request returned the CPU `five-seconds` scalar and per-location memory `used-percent` with `fru`, `slot`, `bay`, and `chassis` keys. IOS XE emitted a valid sync marker for each requested path. | CPU and memory selectors and aggregate JSON_IETF shapes interoperated. Repeated true sync markers are tolerated by the STREAM receive loop. |
| Interfaces profile | The 60-second STREAM/SAMPLE request returned keyed OpenConfig interface-state aggregates containing administrative/operational state and cumulative counters, followed by sync. | Curated selector and decoder input shape interoperated; shared mutable sandbox scale is not qualification evidence. |
| Experimental optics | The 30-second STREAM/SAMPLE transceiver request was accepted and synchronized but returned no transceiver values. | Expected on a virtual switch; DOM remains unqualified and experimental. |
| Mutation and backend scope | Only Capabilities, Get, Subscribe, and RESTCONF GET operations were used. No Set, configuration RPC, mutating gNOI operation, AWS resource, or external backend assertion endpoint was invoked. | Provides client read-only behavior evidence only; it does not satisfy authorization or backend-delivery qualification gates. |

The bounded STREAM commands intentionally ended after receiving initial updates and sync; the client's final
`DeadlineExceeded` status was the local observation deadline, not a target rejection. No generated credentials,
passwords, or hardware serial numbers are retained in this repository. No immutable raw response artifact or backend
delivery result was captured, so the result is `Run with findings; not qualification`.

### Splunk Observability Cloud delivery acceptance — same run, 2026-07-29

The same validation window included a bounded Splunk Observability Cloud `us1` acceptance probe. The repository's
shared Cisco OS/gNMI dashboard bundle was created, round-trip verified, and deleted through the Splunk dashboard API:
one dashboard group, nine dashboards, and 109 charts. The exact gNMI device and receiver self-telemetry metric names
were then submitted to the Splunk SignalFlow datapoint ingest endpoint with a unique validation resource identity;
Splunk returned HTTP 200, and the metric-timeseries catalog returned active entries for each submitted metric. The
probe used no Cisco configuration or mutating RPC and retained no token, credential, or response body.

| Splunk acceptance check | Result | Qualification interpretation |
| --- | --- | --- |
| Dashboard API smoke test | Created, round-trip verified, and removed 1 group, 9 dashboards, and 109 charts. | Dashboard payloads, SignalFlow, filters, and chart relationships are accepted by the `us1` organization. |
| gNMI metric-name ingest | HTTP 200 for `cisco.device.up`, `system.cpu.utilization`, `system.memory.utilization`, `system.network.interface.status`, `otelcol_ciscoosreceiver_gnmi_product_verified`, and `otelcol_ciscoosreceiver_gnmi_updates`. | Splunk accepts the names and bounded dimensions used by the gNMI device/self-telemetry contract. |
| Metric catalog readback | Active metric-timeseries entries were returned for all six submitted names. | Backend catalog acceptance was observed; this was a controlled name/shape probe, not a live collector stream. |
| OTLP transport note | Direct JSON to `/v2/datapoint/otlp` returned HTTP 415 because that endpoint requires OTLP protobuf; the production `otlphttp` exporter sends protobuf. | Expected protocol behavior; do not use JSON for the OTLP endpoint. |

This proves Splunk organization access, dashboard compatibility, and backend acceptance of the gNMI metric contract, but
does not qualify C9300/C9500 hardware or prove a live Cisco-to-Collector-to-Splunk stream. The physical rows below
remain `Not run` until exact-build hardware, verified TLS, authorization evidence, three collection intervals, and a
backend assertion tied to that same run are retained.

This target also exposed a documentation/runtime discrepancy: Cisco's
[IOS XE 17.18 gNMI guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1718/b-1718-programmability-cg/gnmi.html)
documents and demonstrates gNMI `0.4.0`, while the 17.15.1 Cat9000v advertised `0.7.0`. The virtual result is not
evidence to admit `0.7.0` for either physical 17.18.1 product. Retain an exact physical C9300 and C9500 Capabilities
response and perform a separate compatibility review before changing the version allowlist.

## Shared gNMI Exact-Build Live Qualification Status

A live result applies only to the recorded model, exact canonical build, topology/scale, authentication and TLS posture,
and enabled profiles. Qualification requires verified TLS, no preflight, decode, unsupported-value, invalid-timestamp,
out-of-order, consumer-refusal, authentication, reconnect, or cache-owner-reset loss signal; no degraded or stopped
enabled profile; unexhausted cache and auxiliary-state capacity; `cisco.device.up=1`; correct
`cisco.product.family`, `device.model.identifier`, and `os.version`; backend delivery; and at least three successful
collection intervals. Cisco contracts also require `device.manufacturer=Cisco`. The bounded `unmapped_values` counter
is retained as explicit evidence but is not required to be zero. C9300/C9500 additionally require independently
produced, content-addressed authorization evidence that proves effective server read-only state, disabled gNOI, Set
`PERMISSION_DENIED`, and gNOI `PERMISSION_DENIED` or `UNIMPLEMENTED` for the exact collector identity. A zero receiver Set-call
count proves client behavior only and cannot satisfy this device-authorization gate.

| `product` | Exact model | Exact software build | Profiles and topology | Retained evidence | Status |
| --- | --- | --- | --- | --- | --- |
| `catalyst_9300` | Not recorded | Not recorded | Identity, CPU, memory, and interfaces; INSTALL boot mode; external inventory must identify standalone or StackWise topology | None | `Not run` |
| `catalyst_9500` | Not recorded | Not recorded | Identity, CPU, memory, and interfaces; INSTALL boot mode; external inventory must identify standalone or StackWise Virtual topology | None | `Not run` |
| `catalyst_9800` | Not recorded | Not recorded | Identity, CPU, memory, interfaces, and `catalyst_9800_wireless`; representative AP/client state required | None | `Not run` |
| `asr_9000` | Not recorded | Not recorded | Identity, per-node CPU, and interfaces | None | `Not run` |
| `ncs_5500` | Not recorded | Not recorded | Identity, per-node CPU, and interfaces | None | `Not run` |
| `nexus_9000` | `N9K-C9300v` | `10.6(1)` | Five reachable lab switches; one switch had OpenConfig enabled in running configuration only and was tested with required identity and interface profiles at 10-second cadence, but identity preflight stopped before Subscribe | Three staged 2026-07-05 lab preflights recorded in the consolidated campaign above; latest sanitized evidence SHA-256 `8152f5208e3dd083f6646d2c5d7f21bc23b7dbfde1f100615744b16d52dbfd43` | `Run with findings` |
| `nexus_3500` | Not recorded | Not recorded | Identity and interfaces; no system profile | None | `Not run` |

Every optional optics profile requires separate physical qualification and does not become qualified when the baseline
product row passes: IOS XE DOM, IOS XR controller/lane DOM, and NX-OS DME DOM/VDM all remain experimental.

For Catalyst 9300 and Catalyst 9500, one `hw-type-chassis` inventory group, one consistent exact current-image identity
across all current install locations, and INSTALL boot mode are necessary for unambiguous identity but do not prove
standalone topology. Retained qualification evidence must include an external physical inventory and scope results
separately to standalone, C9300 StackWise, or
C9500 StackWise Virtual. It must retain complete Capabilities tuples and independently captured
YANG-library/module-set/import/deviation closure; neither the seven-entry reviewed direct catalog nor the subset
enforced by one enabled plan attests the full CAT9K deviation set. A standalone result cannot qualify stack/SVL
member identity, scale, switchover, reconnect behavior, or
another admitted PID. The topology label scopes retained evidence and never relaxes the exactly-one
`hw-type-chassis` preflight: if a stack/SVL target reports multiple chassis groups, the current contract rejects it and
the topology remains unqualified pending capture-driven identity semantics.

`allow_unqualified: true` is currently contract-wide. A successful row for one exact PID/build/topology does not remove
that requirement or qualify the rest of the allowlist; removing it requires a granular qualification registry and
separate evidence for each admitted combination.

The opt-in live harness must be given the expected product, configured canonical software release identifier, model
identifier, and backend-delivery assertion. The harness always restores the selected product's immutable baseline
metric set; `CISCOOS_E2E_GNMI_REQUIRED_METRICS` can only add exact metric names. Retained sanitized output must show
every local and backend self-telemetry gate below, active subscriptions for the exact stream plan, and the same required
metric series delivered in at least three distinct wall-clock collection intervals before a row changes from `Not run`.

Every harness invocation creates a random run ID and a unique `host.name`, and asks the backend to consider only
observations at or after the local run start. The assertion endpoint must echo `run_id`, `target`, and
`window_start_unix_nano`, and must return `first_observation_unix_nano` within that window; stale retained history is
not valid evidence for a new run. For the switch contracts, configured `17.18.1`, `17.18.01`, and `017.018.001` all
canonicalize to the sole accepted verified `os.version` identity `17.18.1`; they do not admit another release. The
train-wide C9800 contract may use another canonical public Cisco label such as `17.18.1a`. The verified value excludes
the internal install build suffix, separate `version-extension`, and SMU state and therefore cannot populate the
table's exact-software-build column by itself. Retain the exact image filename, internal install version,
`version-extension`, installed SMUs, and schema evidence in an independently captured sanitized artifact. Digest that
artifact and bind the digest to the harness and backend result.

### Reproducing exact-build shared-gNMI qualification

No completed shared-gNMI qualification is retained in this repository. The `nexus_9000` row records staged
TLS-bypass preflight findings and remains unqualified; the other six exact-build rows remain `Not run`. Run the
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
export CISCOOS_E2E_GNMI_IMAGE_EVIDENCE_SHA256=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# Required for C9300/C9500 only, from the controlled external authorization test:
# export CISCOOS_E2E_GNMI_AUTHORIZATION_EVIDENCE_SHA256=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
export CISCOOS_E2E_GNMI_BACKEND_ASSERT_URL=https://telemetry-evidence.example.net/assert

# Optional exact metric additions; the immutable product baseline is always required:
# export CISCOOS_E2E_GNMI_REQUIRED_METRICS='site.custom.metric'

# Optional when the assertion service requires bearer authentication:
read -rs CISCOOS_E2E_GNMI_BACKEND_BEARER_TOKEN
export CISCOOS_E2E_GNMI_BACKEND_BEARER_TOKEN

(cd receiver/ciscoosreceiver && go test -tags=e2e -run '^TestE2EProductQualifiedGNMI$' -count=1 -timeout=10m .)
```

`CISCOOS_E2E_GNMI_CA_FILE` may be omitted when the device certificate chains to the system roots. Optional mutual TLS
uses both `CISCOOS_E2E_GNMI_CLIENT_CERT_FILE` and `CISCOOS_E2E_GNMI_CLIENT_KEY_FILE`. The harness has no insecure TLS
mode. Replace the sanitized digest example with `sha256:` plus the 64 lowercase hexadecimal characters produced by
hashing the independently captured device build/SMU/schema evidence artifact; an arbitrary operator string is not
evidence. `CISCOOS_E2E_GNMI_SAMPLE_INTERVAL` defaults to `10s` and accepts `1s` through `5m`;
`CISCOOS_E2E_GNMI_WAIT_TIMEOUT` defaults to `3m`, must cover at least three sample intervals, and cannot exceed `30m`.
For Catalyst 9300, `CISCOOS_E2E_GNMI_TOPOLOGY` is mandatory and must be exactly `standalone` or `stackwise`. For
Catalyst 9500 it is mandatory and must be exactly `standalone` or `stackwise_virtual`. Set it only after checking the
external physical inventory; the label is bound to the backend assertion but does not independently discover topology,
select a different identity contract, or bypass the single-chassis preflight.

Produce the C9300/C9500 authorization artifact outside the receiver on a disposable or fully isolated exact-build
switch with no production traffic, out-of-band access, a saved configuration, and rollback protection. Apply and verify
`gnxi read-only` plus `no gnxi enable-gnoi`; retain gNXI running configuration, `show gnxi state detail`/`stats`, and an
administrative read proving the effective `read-only=true` and `enable-gnoi=false` model leaves. With a separate tool
using the exact collector identity, require `PERMISSION_DENIED` from a syntactically valid same-value Set against a
reversible test-only leaf and independently confirm no configuration change. Call only a non-mutating gNOI read
operation and require `PERMISSION_DENIED` or `UNIMPLEMENTED`; transport timeout, generic `UNAVAILABLE`, and listener
failure are not proof. Never test a mutating gNOI operation. Sanitize but retain operation/path, status, timestamps,
identity fingerprint, effective state, and before/after configuration digest; hash the immutable artifact and set
`CISCOOS_E2E_GNMI_AUTHORIZATION_EVIDENCE_SHA256`. See the
[full controlled procedure](gnmi-dial-in.md#controlled-catalyst-authorization-test). The live harness only validates
that digest and backend attestations; it never calls Set or gNOI.

The immutable Catalyst 9300/9500 baseline is CPU, memory, interface status, interface administrative status, interface
I/O, errors, packet count, and dropped packets. Catalyst 9800 adds its three wireless metrics and requires positive
representative AP/client state. The ASR 9000/NCS 5500 baseline is CPU plus the complete interface family; the Nexus
9000/3500 baseline is the complete interface family and has no system profile. Here, the complete interface family is
`system.network.interface.status`, `cisco.interface.admin.status`, `system.network.io`, `system.network.errors`,
`system.network.packet.count`, and `system.network.packet.dropped`. The optional
`CISCOOS_E2E_GNMI_REQUIRED_METRICS` list adds to, but cannot remove from, those baselines. Do not include optics in a
baseline row because the harness deliberately leaves the experimental optics profile disabled. Catalyst 9300/9500
results must also retain the external topology evidence described above.

The backend assertion URL must be absolute HTTPS. The harness retries the assertion within the remaining qualification
window to allow for exporter latency. Each GET includes `product`, canonical `software_version`, `model_identifier`,
content-addressed `image_evidence_sha256`, optional required `boot_mode`, unique `target`, random `run_id`,
`not_before_unix_nano`, `interval_unix_nano`, `minimum_intervals=3`, one repeated `periodic_metric` parameter per
required baseline or added metric, `latest_metric=cisco.device.up`, one repeated `self_telemetry_metric` parameter for
each required receiver self-telemetry value, and one repeated `self_telemetry_profile` parameter for every planned
profile. Catalyst 9300/9500 requests also include INSTALL `boot_mode`, the operator-verified `topology`, and
`authorization_evidence_sha256`; the response must echo all three exactly. The assertion service must be able to query
both the exported device metrics and Collector internal telemetry for the unique current-run target, and independently
resolve the switch authorization artifact by its digest. It must filter by the exact identity and current time window,
return strictly increasing cadence bucket numbers for every periodic metric, and return HTTP 200 with a JSON body like:

```json
{
  "delivered": true,
  "run_id": "<echo the request run_id>",
  "target": "<echo the request target>",
  "product": "nexus_9000",
  "software_version": "10.6(1)",
  "model_identifier": "N9K-C93180YC-FX3",
  "image_evidence_sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "boot_mode": "",
  "window_start_unix_nano": 1783180800000000000,
  "first_observation_unix_nano": 1783180801000000000,
  "last_observation_unix_nano": 1783180831000000000,
  "minimum_intervals": 3,
  "interval_unix_nano": 10000000000,
  "metric_interval_buckets": {
    "system.network.interface.status": [0, 1, 2],
    "system.network.io": [0, 1, 2]
  },
  "latest_metric_values": {
    "cisco.device.up": 1
  },
  "latest_metric_timestamps_unix_nano": {
    "cisco.device.up": 1783180831000000000
  },
  "self_telemetry_values": {
    "otelcol_ciscoosreceiver_gnmi_authentication_failures": 0,
    "otelcol_ciscoosreceiver_gnmi_auxiliary_state_utilization": 0.001,
    "otelcol_ciscoosreceiver_gnmi_cache_owner_resets": 0,
    "otelcol_ciscoosreceiver_gnmi_cache_utilization": 0.004,
    "otelcol_ciscoosreceiver_gnmi_connections": 1,
    "otelcol_ciscoosreceiver_gnmi_consumer_refusals": 0,
    "otelcol_ciscoosreceiver_gnmi_decode_errors": 0,
    "otelcol_ciscoosreceiver_gnmi_invalid_timestamps": 0,
    "otelcol_ciscoosreceiver_gnmi_out_of_order_updates": 0,
    "otelcol_ciscoosreceiver_gnmi_preflight_failures": 0,
    "otelcol_ciscoosreceiver_gnmi_product_verified": 1,
    "otelcol_ciscoosreceiver_gnmi_profile_degraded": 0,
    "otelcol_ciscoosreceiver_gnmi_reconnects": 0,
    "otelcol_ciscoosreceiver_gnmi_unmapped_values": 12,
    "otelcol_ciscoosreceiver_gnmi_unsupported_value_kinds": 0
  },
  "active_subscriptions": {
    "identity": 1,
    "interfaces": 1
  }
}
```

For C9300/C9500 the same response must additionally contain:

```json
{
  "authorization_evidence_sha256": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "server_read_only": true,
  "gnoi_disabled": true,
  "negative_set_permission_denied": true,
  "negative_gnoi_permission_denied_or_unimplemented": true
}
```

The identity, image-evidence, switch authorization-evidence, boot-mode, interval-contract, and
`window_start_unix_nano` fields must exactly echo the request where applicable. Every switch authorization boolean must
be explicitly present and true; missing, `null`, or false values fail qualification. `first_observation_unix_nano` must
be at or after the requested window. Every periodic metric must contain at least three consecutive, unique cadence
buckets reaching the current or immediately preceding bucket; timestamps and buckets outside the bounded current-run
window are rejected. The latest availability value must be 1 and its timestamp must fall within the current run.
`cisco.device.up` is presence/current-state evidence rather than a periodic metric, so it is not incorrectly required
in three intervals.

The assertion service must return every requested self-telemetry map key explicitly, including zero-valued monotonic
counters that have no current-run sample. It aggregates counters across their bounded reason/profile/value-kind
dimensions, treats any `profile_degraded=1` series as degraded, returns current connection/product/capacity gauges, and
returns the active subscription count separately for every requested profile. All values must be finite and
nonnegative; integer counters and subscription counts must be exact JSON integers no larger than `2^53 - 1`.
`product_verified` and `connections` must equal 1, all disqualifying counters and `profile_degraded` must equal zero,
the active-subscription map must exactly match the planned streams, and both capacity-utilization gauges must remain
below 1. `unmapped_values` may be nonzero but must remain a bounded exact counter and is retained in the evidence.

This contract prevents retained historical telemetry, aggregate interval counts, missing map keys, or stale buckets
from satisfying a new qualification run. Retain only a sanitized result containing the receiver revision, exact
product/model/build artifact digest, separate switch authorization artifact digest and four attestations where
applicable, enabled profiles, boot mode, topology and scale, TLS/authentication posture, per-metric bucket evidence, the
complete local and backend self-telemetry maps, and the backend assertion outcome.

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
