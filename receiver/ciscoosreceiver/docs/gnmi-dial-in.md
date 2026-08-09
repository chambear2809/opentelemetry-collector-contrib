# Product-Contract gNMI Dial-In

The shared `cisco_os.gnmi` client collects normalized metrics from IOS XE, IOS XR, and NX-OS. Endpoint ownership is a
static inventory, while product identity and exact catalog-row selection are automatic. Each session uses Capabilities
followed by internal Subscribe-ONCE identity probes; it never uses Get or Set. SupportedModels can filter the identity
probes attempted, but model presence and a successful Capabilities response do not prove any operational path. SONiC,
dynamic endpoint discovery, configuration mutation, and dial-out metric semantics remain outside this feature's scope;
receiver-wide transport hardening also applies to the existing dial-out servers as described below.

The generated [product and domain coverage matrix](gnmi-coverage.md) is the source of truth for support claims. Only an
exact product/release/domain row marked **Live Qualified** is supported. `Cataloged`, `Implemented`, fixture-passed, and
`Findings` states are not support, and evidence from a sibling PID is not inherited. The generated
[metric catalog](gnmi-metrics.md) records metric definitions and catalog use; a metric appearing there does not promote
a product row to Live Qualified.

The fake-server and synthetic implementation gates can be completed without physical devices. Upstream submission still
requires human code-owner agreement on the configuration, security model, metric contract, and hardware plan. Exact-build
live hardware, physical-optics, and backend-delivery validation remain qualification gates; this document does not treat
their absence as qualification.

Existing `ios_xr.dial_out` and `catalyst_9800.dial_out` configurations remain available. Legacy dial-in targets keep
their legacy decoder and metric names for one fork release and emit a deprecation warning. Every endpoint has one owner
across the shared and both legacy dial-in lists; case/trailing-dot DNS variants and equivalent IP spellings are
canonicalized for this ownership check.

## Migration from OS-family targets

`gnmi.targets[].platform` is retained only so the decoder can return an actionable migration error. It never selects a
contract, including when the target contains only custom subscriptions. Replace it with both required fields:

```yaml
# Before (rejected)
platform: nx_os

# After
product: nexus_9000
software_version: "10.6(1)"
```

There is no OS-family compatibility fallback. Choose the product that matches the deployed chassis, configure its
expected software release identifier, and restart the receiver after correcting a terminal qualification failure.

## Secure configuration

```yaml
receivers:
  cisco_os:
    gnmi:
      max_datapoints_per_chunk: 10000
      max_cached_series: 500000
      targets:
        - name: nexus-shard-01
          endpoint: nexus01.example.net:50051
          # Optional expectations. Omit both for automatic identity discovery.
          platform: nx_os
          product_family: nx_os
          max_recv_msg_size_mib: 16
          max_streams: 4
          encoding_preference: [json, json_ietf]
          sync_timeout: 2m
          credentials:
            mode: username_password
            username: otel-telemetry
            password: ${env:CISCO_GNMI_PASSWORD}
          tls:
            ca_file: /etc/otel/cisco-ca.pem
            min_version: "1.2"
            server_name_override: access-switch-01.example.net
            reload_interval: 1h
          profiles:
            identity:
              enabled: true
            system:
              enabled: true
            interfaces:
              enabled: true
            optics:
              enabled: true
              required: true
              sample_interval: 30s
              stream_mode: sample
```

`platform` is an optional expected OS family (`ios_xe`, `ios_xr`, or `nx_os`), not the source of discovered identity.
`product_family` is an optional expected generated-catalog family (`ios_xr`, `ios_xe_routing`, `ios_xe_switching`,
`ios_xe_wireless`, or `nx_os`). If either assertion disagrees with Subscribe-ONCE identity, the target fails instead of
silently selecting a sibling row. The bootstrap stages identity leaves until a true sync response and clean ONCE-stream
completion, applies the target `sync_timeout`, and publishes no partial identity.

Profiles are `identity`, `system`, `interfaces`, `optics`, `catalyst_9800_wireless`, `inventory`, `environment`, `l2`,
`routing`, `mpls`, `overlay`, `qos`, `acl`, `topology`, `poe`, `time_sync`, `high_availability`, `asic`, and
`telemetry_self`. Identity defaults to five minutes, system and interfaces to 60 seconds, and optics to 30 seconds.
Identity, system, and interfaces preserve their existing enabled defaults. Optics, wireless, and every new normalized
profile are disabled by default.

The new profile names are a stable opt-in configuration surface for staged catalog expansion. Startup rejects an
enabled profile that has no implemented path definition for the expected platform; a product/domain row in the
coverage registry does not create a subscription by itself.

Credentials modes are `username_password`, `mtls`, and `mtls_username_password`. mTLS modes also require
`tls.cert_file` and `tls.key_file`. TLS is mandatory: plaintext `tls.insecure` and TLS versions below 1.2 are rejected.
Certificate verification is enabled by default. Prefer `tls.ca_file` plus `tls.server_name_override`; isolated labs with
self-signed device certificates may explicitly set `tls.insecure_skip_verify: true`. Arbitrary metadata headers are not
supported.

For an IOS XE password-authenticated production endpoint, the device-side qualification baseline is:

```text
gnxi
gnxi secure-trustpoint <device-server-trustpoint>
gnxi secure-password-auth
gnxi secure-port 9339
gnxi secure-server
no gnxi server
gnxi read-only
no gnxi enable-gnoi
```

Use `secure-client-auth` for mTLS and both authentication flags for combined mTLS plus username/password. Confirm the
effective flags, ports, and service state with `show gnxi state detail` and `show gnxi state stats`; do not infer them
from the presence of `secure-server`. The insecure and secure listeners can run simultaneously, which is why
`no gnxi server` is an explicit gate. The bare `gnxi` command starts the gNXI process; it is not a configuration
submode. `gnxi server` is the separate insecure-listener command and remains disabled above.

The pinned IOS XE 17.18.1
[`Cisco-IOS-XE-gnmi-cfg`](https://github.com/YangModels/yang/blob/63fa41359e1a5d14c844a3a87d8b7d9c000d1e44/vendor/cisco/xe/17181/Cisco-IOS-XE-gnmi-cfg.yang)
model defaults `enable-gnoi` to `true` and `read-only` to `false`. `gnxi read-only` makes gNMI Set return
`PERMISSION_DENIED` and disables all gNOI services; `no gnxi enable-gnoi` independently disables those services.
Both commands are mandatory defense in depth. Retain `show running-config` gNXI lines, `show gnxi state detail`, and
`show gnxi state stats`, and use a separate administrative read channel to verify the effective
`Cisco-IOS-XE-gnmi-cfg:gnmi-cfg-data/config/read-only=true` and `enable-gnoi=false` leaves. A configured line alone is
not effective-state evidence.

IOS XE's gNXI listener can expose gNOI certificate management, OS installation, and factory-reset operations. Current
Cisco documentation does not establish reliable gNMI path-level data authorization, so a dedicated collector account or
certificate must pass the controlled negative gNMI Set and gNOI tests below behind a management ACL/firewall. The
reviewed switch release `17.18.1` predates Cisco's `gnxi secure-vrf` feature, documented from 17.18.2. Use verified
management-plane ACL/firewall/control-plane isolation for 17.18.1; do not configure a later command or broaden the
product contract without a separate schema and device qualification.

`encoding_preference` is an ordered list of concrete `proto`, `json_ietf`, and `json` choices and defaults to
`[json_ietf, json]`. Selection happens only after intersecting the preference with the exact catalog path and target
capabilities. IOS XE scalar PROTO is eligible only on qualified product/release rows; opaque NX DME PROTO remains
ineligible without a schema decoder. `sync_timeout` defaults to two minutes, must be positive, and cannot exceed 30
minutes. A group may override it.

Targets normally use no more than four compatible subscription streams. `max_streams` accepts 1 through 16 and defaults
to 4. A value above 4 requires an explicit `product_family` and cannot exceed its generated catalog ceiling: the current
IOS catalog families remain capped at 4 and `nx_os` permits at most 16. These are configuration ceilings, not support claims; the exact row and
device configuration still require live qualification at that concurrency. Origins remain separate from paths: IOS XE
uses RFC7951 prefixing, IOS XR uses the module origin, and NX-OS assigns `DME`, device, or OpenConfig origin per path.

`max_recv_msg_size_mib` cannot exceed 16 MiB. Larger frames are rejected at transport level, and in-limit responses
receive a schema-aware raw-wire complexity scan before protobuf objects are materialized; narrow or split device
subscriptions instead of raising this ceiling.
At most 256 target definitions may be configured in total across `gnmi.targets`, `ios_xr.dial_in.targets`, and
`catalyst_9800.dial_in.targets`. Dial-in targets admitted by `device_selection` and both enabled dial-out servers share
a 512 MiB receiver-wide stream-by-frame capacity limit. Shared targets charge
`max_streams * max_recv_msg_size_mib`; each deprecated target charges one fixed 4 MiB stream; and each enabled dial-out
server charges `max_concurrent_streams * max_recv_msg_size_mib`. Excluded dial-in definitions count toward the target
ceiling but do not consume the runtime frame envelope.

NX-OS optical collection deliberately subscribes to the `DME` distinguished-name family under `sys/intf`; it does
not treat `Cisco-NX-OS-device:System/.../fcotdd-items` as an interchangeable representation. The current `sys/intf`
subscription is intentionally broad because NX-OS does not provide a portable recursive-wildcard form for this DN
family. Keep NX optics experimental until the deployed release and hardware have been qualified for returned object
volume, path shape, and sensor descriptions.

Each profile accepts `enabled`, `required`, `sample_interval`, `stream_mode`, and `groups`. Stream mode is `auto`,
`sample`, `on_change`, or `target_defined`; existing profiles retain SAMPLE defaults. A group can override `enabled`,
`required`, `sample_interval`, `stream_mode`, and `sync_timeout`, and can set `max_entities` plus `selectors`. Group names
and selector keys must be declared by the generated platform/profile catalog. Selector values are exact matches: empty values,
duplicates, and wildcard syntax are rejected. Enabling a catalog-marked high-cardinality group requires a positive
`max_entities`. Within an enabled profile, a catalog group is enabled unless its group override sets `enabled: false`;
sample interval and stream mode inherit the profile, sync timeout inherits the target, and `required` defaults to false.
For selectors, `max_entities` bounds the configured Cartesian request expansion before any stream starts.
It also bounds distinct catalog entity identities retained in committed cache state. An entity may own several metric
leaves while consuming one slot. Overflow rolls back the notification before OTLP delivery. An optional affected
packed group stream degrades independently; a required group keeps the target unavailable. Deletes and atomic
replacement release entity capacity transactionally.

Custom subscriptions are accepted only when each scalar numeric source path has an explicit mapping with a metric name,
description, UCUM unit, scale, gauge type, and path-key-to-attribute mappings. Their `encoding` is `auto`, `proto`,
`json_ietf`, or `json` and defaults to `auto`; a concrete choice remains subject to target capabilities and a declared
safe decoder. Unmapped paths, custom sums, arbitrary JSON-to-metric conversion, and dynamic `_info` metrics are rejected.

## Metric contract

The generated [metric catalog](gnmi-metrics.md) is the complete public mapping inventory for the dated catalog snapshot.
The summary below describes the existing baseline contracts; catalog presence is not a product support claim.

The identity, system, and interfaces profiles reuse the receiver's existing normalized metrics instead of creating
platform-specific duplicates:

Every product's interface profile emits `system.network.interface.status`, `cisco.interface.admin.status`, and the
cumulative sums `system.network.io`, `system.network.errors`, `system.network.packet.count`, and
`system.network.packet.dropped`. It does not emit `cisco.interface.speed`, `cisco.interface.io.rate`,
`cisco.interface.packet.rate`, or `cisco.interface.utilization`.

After verification, shared-gNMI resources include `cisco.product.family`, `device.manufacturer=Cisco`, the verified
`device.model.identifier`, canonical `os.version`, and, when required and verified by the product contract,
`cisco.os.boot_mode`. For IOS XE, `os.version` is the public release label and excludes the internal install build,
`version-extension`, and SMU state. Existing `cisco.os.name` and `os.name` remain available.
`cisco.platform.family` is retained as a legacy OS-family alias for compatibility; new grouping should use
`cisco.product.family`.

The receiver's internal telemetry exposes
`otelcol_ciscoosreceiver_gnmi_product_verified{cisco.gnmi.target}` and the cumulative
`otelcol_ciscoosreceiver_gnmi_preflight_failures{cisco.gnmi.target,cisco.gnmi.reason}`. Preflight reasons are bounded
to `identity_missing`, `identity_ambiguous`, `product_mismatch`, `release_mismatch`, `missing_model`,
`unsupported_model_version`, `unsupported_boot_mode`, `unsupported_gnmi_version`, `unsupported_encoding`, and
`malformed_identity`. Post-preflight stream degradation uses bounded `bisection_limit`, `cache_limit`,
`incompatible_path_group`, `unsupported_path`, and `unsupported_request_options` reasons. Self-telemetry separately
counts rejected invalid timestamps, ignored out-of-order updates, owner resets, and unsupported TypedValue kinds
without using device-controlled labels.

The optics profile emits explicit gauges. `network.interface.name`, `cisco.optics.lane`, an allowlisted
`cisco.optics.sensor`, `cisco.optics.profile`, and `cisco.optics.experimental` identify their source as applicable.

| Profile | Metric | Unit |
| --- | --- | --- |
| DOM | `cisco.optics.temperature` | `Cel` |
| DOM | `cisco.optics.voltage` | `V` |
| DOM | `cisco.optics.laser_bias_current` | `mA` |
| DOM | `cisco.optics.rx_power` | `dB{mW}` |
| DOM | `cisco.optics.tx_power` | `dB{mW}` |
| DOM | `cisco.optics.present` | `1` |
| VDM | `cisco.optics.esnr` | `dB` |
| VDM | `cisco.optics.tdecq` | `dB` |
| VDM | `cisco.optics.pre_fec_ber` | `1` |
| VDM | `cisco.optics.tec_current` | `mA` |
| VDM | `cisco.optics.tec_utilization` | `1` |

`dB{mW}` preserves the device's dBm scale using a valid UCUM annotation. UCUM braces are human-readable annotations,
so consumers must not treat this spelling as a machine-convertible 1 mW reference.

IOS XE and IOS XR currently map DOM metrics only. IOS XR uses controller and lane DOM leaves and has no coherent
profile. NX DME maps allowlisted DOM and VDM sensor descriptions. All of these optics paths are experimental.

`cisco.optics.tec_current` and `cisco.optics.tec_utilization` are mutually selected from the sensor's reported unit.
TDECQ is emitted only when an allowlisted description explicitly identifies TDECQ and the unit is dB. NX-OS's
"PAM4 level transition parameter" is not TDECQ and is never aliased to it. Unknown sensor IDs are counted as unmapped,
not exported as new metrics.

Every optical reading sets `cisco.optics.experimental=true` until its exact physical-hardware gate below passes. It
must not be described as production-ready before qualification.

## Removal, freshness, and bounds

Deletes evict the exact branch and its descendants. An atomic notification replaces cached state under its exact prefix;
omitted leaves are invalidated, and a later non-atomic update invalidates that atomic baseline. Out-of-order updates do
not roll state back.

Removed readings stop producing samples. When physical presence is semantically known, removal also emits
`cisco.optics.present=0`. Dashboards and models must require `present=1` and a fresh timestamp. Do not use the OTLP
"no recorded value" flag for staleness because the SignalFx datapoint translation path does not preserve that flag.

Notifications are split losslessly into consumer calls of at most `max_datapoints_per_chunk` datapoints. Data is never
trimmed. `max_cached_series` sets one receiver-wide count ceiling for active mapped series, atomic baselines,
authoritative delete tombstones, and semantic-invalidation watermarks. The independent auxiliary entry ceiling is four
times that value, accounting for one NX sensor identity and the optical source, presence-count, and attribute entries
associated with a cached optical series. Each count ceiling is deterministically partitioned across selected targets.
The cache and auxiliary state also have separate receiver-wide
retained-byte ceilings: 1.5 GiB for cache correctness state and 256 MiB for auxiliary state, yielding a 1.75 GiB combined
accounted ceiling. Their conservative byte
estimates include retained keys, paths, strings, attributes, and sparse-map overhead. The count multiplier provides
structural headroom while the auxiliary byte ceiling remains the primary defense against oversized metadata. Count and byte budgets are divided
as evenly as possible, with remainders assigned in configuration order, so one target cannot consume another target's
partition. Exceeding either partition stops the affected profile and marks it degraded; there is no receiver-side retry
queue. Each target serializes notification delivery and publishes cache, NX sensor identity, and optical-presence state
only after every chunk is accepted and the profile is still active. A downstream refusal aborts that staged state,
increments receiver telemetry, and ends the subscription so the target reconnects. Equal-timestamp redelivery is then
eligible because the refused attempt did not advance state. If an earlier chunk was accepted before a later chunk was
refused, reconnect redelivers the complete notification; those earlier chunks therefore have at-least-once semantics and
the downstream pipeline must tolerate duplicate datapoints.

A receiver-wide admission gate shared by normalized and deprecated gNMI dial-in permits at most eight decoded response
objects at once. The forced response codec acquires a keyed lease before fragmented-frame materialization and protobuf
unmarshal, honors the exact RPC or stream cancellation context, and releases it after capability negotiation or final
response handling. The shared engine additionally has an eight-slot notification-work gate acquired after per-target
delivery serialization and held through cache planning, downstream delivery, and commit. This prevents reordering;
each plan is independently limited to 32 MiB of staged payload accounting. The two deprecated dial-in implementations
also share a separate cancellation-aware eight-slot processing gate held from direct notification decoding through
downstream data and health delivery.

Device timestamps are normalized from seconds, milliseconds, microseconds, or nanoseconds. Device time must be
synchronized within five seconds. A future value no more than five seconds ahead is clamped to receipt time so it
cannot poison cache ordering. A zero value, a value before year 2000, or a value more than five seconds in the future
is dropped, counted as an invalid timestamp, and leaves the curated profile qualification-degraded until receiver
restart; receipt-time fallback is never committed to cache. Older out-of-order state is ignored and counted without
advancing stream progress or target availability.

## Security model and rotation

The production default is verified server TLS plus centralized AAA username/password. Cisco documents username/password
metadata for [IOS XE](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1718/b-1718-programmability-cg/gnmi.html),
[NX-OS](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/106x/programmability/cisco-nexus-9000-series-nx-os-programmability-guide-106x/m-grpc-agent.html),
and [IOS XR](https://www.cisco.com/c/en/us/td/docs/iosxr/ncs560/programmability/24xx/b-programmability-cg-24xx-ncs560/grpc-session.html).

- Give every device a unique server private key and certificate with its hostname or management IP in the SAN. Never
  reuse a device private key. Distribute only the enterprise CA chain to collector shards.
- Use one read-only AAA account per collector shard, rotate it centrally, and test Capabilities, only the bounded
  contract identity Get paths, and Subscribe while Set and other Get paths are denied. Keep a controlled local break-glass
  account.
- Optional mTLS uses one short-lived client identity per collector shard and a shared client-CA trust anchor on devices.
  Enable it only after the platform's certificate-to-user authorization mapping is validated.
- IOS XE supports PKI auto-enrollment and renewal, and IOS XR 24.x supports trustpoint renewal. NX-OS 10.6 documents
  manual PKCS#12 enrollment; automate secure transfer/import and expect its gRPC agent to restart during certificate
  changes.
- `reload_interval` reloads a collector client certificate and key for later TLS handshakes. A changed CA file is loaded
  on a new connection. An environment-sourced password is resolved when Collector configuration is loaded, so rotate it
  through a config reload or controlled shard rollout. Test device-side and collector-side rotations.
- Management-VRF isolation, ACLs, Kubernetes NetworkPolicies, and VM outbound firewalls are defense in depth, not a
  substitute for TLS and AAA. Unencrypted production gNMI is prohibited.

### Controlled Catalyst authorization test

C9300/C9500 authorization evidence must be produced outside the receiver and its live harness. Perform the following
only on a disposable or fully isolated exact-PID/exact-build lab switch with no production traffic:

1. Preserve the startup and running configuration, establish out-of-band console access and a rollback timer, and record
   the exact PID, topology, image filename, internal install version, `version-extension`, and SMUs.
2. Apply the secure baseline above through a separate administrative channel. Capture the sanitized gNXI running
   configuration, `show gnxi state detail`, `show gnxi state stats`, and an administrative read of the effective
   `read-only=true` and `enable-gnoi=false` YANG leaves.
3. With a separate one-off client using the exact collector account or certificate, issue a syntactically valid gNMI Set
   against a reversible test-only configuration leaf using its already-current value. Require gRPC
   `PERMISSION_DENIED`, then independently prove the configuration did not change. Stop and invalidate the run if the
   request succeeds or returns any other status.
4. With the same collector identity, call only a non-mutating gNOI read operation, such as certificate inventory. Require
   policy denial or service-level unavailability (`PERMISSION_DENIED` or `UNIMPLEMENTED`). A timeout, transport failure,
   generic `UNAVAILABLE`, or an unreachable listener is not proof that gNOI is disabled. Never invoke certificate
   install/rotate, OS install/activate, reboot, or factory reset during this test.
5. Sanitize credentials and private material, but retain the exact request operation/path, gRPC status and message,
   timestamp, collector-identity fingerprint, before/after configuration digest, and effective-state captures. Hash the
   immutable artifact as `sha256:<64 lowercase hex characters>` and make it independently retrievable by the backend
   assertion service.

For C9300/C9500, set that digest as `CISCOOS_E2E_GNMI_AUTHORIZATION_EVIDENCE_SHA256`. The read-only live harness never
issues Set or gNOI calls. It passes only the digest to the backend and requires the response to echo the exact digest and
attest `server_read_only=true`, `gnoi_disabled=true`, `negative_set_permission_denied=true`, and
`negative_gnoi_permission_denied_or_unimplemented=true`. Missing, mismatched, omitted, or false evidence fails qualification.

## Deployment

Kubernetes deployments use disjoint static target inventories, one single-replica Deployment per shard, mounted CA and
client-certificate secrets, externally managed password secrets, NetworkPolicies, and disruption budgets. A target has
exactly one active owner. See [kubernetes-gnmi-shard.yaml](../examples/kubernetes-gnmi-shard.yaml).

VM deployments use one systemd instance per shard, a root-owned `0600` environment file, root-owned certificate files,
an outbound firewall allowlist, and controlled restarts for secret or CA changes. See
[cisco-os-gnmi.service](../examples/cisco-os-gnmi.service).

Shard by estimated active series. Operate near 400,000 series per shard and retain 500,000 as the hard cap. Never scale
by assigning the same target to two active collectors.

## Alerts and runbook

Alert on target inactivity beyond two sample intervals, required profile or group degradation, authentication failures,
decode/unmapped growth, cache use above 80 percent, stream churn, consumer refusal, and device or collector certificate
expiry.

For an authentication alert, stop rapid retries, confirm the shard account is not locked, verify Capabilities and
the bounded identity Get and Subscribe permissions while Set remains denied, rotate the credential, then roll one shard.
For a certificate alert, verify SAN and chain first,
rotate one device or shard, force a new TLS handshake, and confirm last-success before continuing. For cache pressure,
identify the profile and series growth, then split the static inventory without overlapping ownership.

## Acceptance gates

Unit and fake-server coverage must include configuration validation, Capabilities followed by Subscribe-ONCE identity,
expected-family mismatches, origin/path construction, per-stream encodings and modes, sync timeouts, scaling and units,
atomic/delete behavior, timestamps and out-of-order updates, cache/batch bounds, POLL sequencing, reconnect and upgrade
reselection, shutdown rollback, TLS trust/SAN/mTLS cases, credentials on every RPC, denied credentials, and proof that
zero Set/Get calls occur.

Virtual labs can qualify common control-plane behavior only when Cisco documents that behavior across the exact family.
They do not qualify optics, PoE, environmental sensors, ASICs, supervisors, line cards, stacks, or attached wireless
hardware. A catalog row, successful fixture, model advertisement, or passing virtual test remains `Findings` or another
non-live disposition until the exact PID/release/domain row completes live validation. Consult the generated
[coverage matrix](gnmi-coverage.md); only its Live Qualified rows are supported.

Physical qualification is mandatory for hardware-dependent domains. Capture sanitized Capabilities and
SubscribeResponse fixtures tied to the selected model revision and path variant; record the exact PID, release, role,
hardware class, relevant firmware, origin, path, description, unit, and raw value. Compare representative emitted
metrics with simultaneous CLI or device-state readings within one documented source resolution. Exercise state
transitions and deletions, reconnect, AAA outage and recovery, certificate rotations, applicable supervisor or stack
failover, backend delivery, and a 24-hour soak. Record the tested scale envelope on the exact qualified row.

The scale gate is a synthetic TLS test with at least 100 targets, 5,000 optical ports, up to eight lanes, 500,000 active
mapped series, and about 16,700 datapoints/second. On 4 vCPU and 4 GiB, require CPU at or below 80 percent, RSS at or
below 3.2 GiB, p95 notification-to-consumer latency below five seconds, no receiver loss with an accepting consumer,
bounded cache, and reconnect recovery within 60 seconds.

Product-specific qualification adds a 64,000-client wireless scenario, the NX-OS documented 250,000 aggregate-MO
boundary, and bounded large RIB/FIB, MAC-table, ACL-rule, and QoS-class detail cases. Each run must record the enabled
features, selected path-set variants, selector and entity limits, retained-state peak, device control-plane impact, and
the exact PID/release envelope. Passing one scale case does not qualify a different product, hardware class, or domain.

An opt-in data-plane harness is included for the 100-target/500,000-series/16,700-point cache, mapping, and lossless
chunking portion:

```sh
CISCOOS_GNMI_RUN_SCALE_QUALIFICATION=1 GOMAXPROCS=4 go test ./internal/gnmi \
  -run '^TestInternalGNMIScaleQualification_100Targets5000Ports500KStateCapacity$' -count=1 -v
```

This opt-in harness uses an explicit 1.25 GiB retained-accounting limit for its deliberately high-overhead synthetic
series shape. Production retains the fixed 256 MiB cache ceiling described above; that byte ceiling is independent of
the 500,000-series count ceiling and stops this synthetic shape before all 500,000 series can be retained.

The local qualification run populated 500,000 series in 3.50 seconds and processed the interval in 150 ms, with a
1,100,820,000-byte conservative retained-state estimate, 1.32 GB RSS, 24.16 percent four-core burst CPU, and 3.63
percent four-core CPU at the modeled one-second cadence; chunks contained 10,000 and 6,700 datapoints with no loss.
That harness does not
exercise 100 TLS listeners, reconnect recovery, exporter queues, or hardware. Those portions of the scale gate remain
mandatory in the deployment environment.

Splunk Observability Cloud acceptance verifies metric names and dimensions, UCUM units (especially `dB{mW}`),
presence/freshness behavior, dashboards, and predictive-model inputs. Removal must stop new optical samples, and
detectors must exclude `present=0` and stale ports.
