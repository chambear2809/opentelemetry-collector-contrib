# Product-Qualified gNMI Dial-In

The shared `cisco_os.gnmi` client collects normalized metrics only from the product and release-train contracts below.
It is a static-inventory, read-only client: it uses Capabilities, bounded product-identity Gets, and Subscribe, and never uses Set.
Configuration alone does not establish support. A target must pass configuration validation, product-approved encoding
negotiation, required-model validation, and bounded identity Get probes in that order. Configured metric streams start
only after exact product, model, and software verification succeeds. Target discovery, configurable general-purpose gNMI Get/Set, and
dial-out metric semantics are outside this feature's implemented scope; receiver-wide transport hardening also applies
to the existing dial-out servers as described below.

See the [gNMI protocol roadmap](gnmi-protocol-roadmap.md) for proxy, tunnel, and configurable periodic Get designs that
are explicitly not implemented. Bounded product-identity Gets are part of the implemented preflight.

| `product` | Derived OS | Accepted train | Live identity source |
| --- | --- | --- | --- |
| `catalyst_9800` | `ios_xe` | [`17.18.x`](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1718/b-1718-programmability-cg/gnmi.html) | IOS XE hardware inventory plus current install-version entries |
| `asr_9000` | `ios_xr` | [`24.4.x`](https://www.cisco.com/c/en/us/td/docs/routers/asr9000/software/24xx/programmability/configuration/guide/b-programmability-cg-asr9000-24xx/use-grpc-protocol-to-define-network-operation-with-data-models.html) | `Cisco-IOS-XR-install-oper:install/version` chassis PID and release label |
| `ncs_5500` | `ios_xr` | [`24.4.x`](https://www.cisco.com/c/en/us/td/docs/iosxr/ncs5500/telemetry/24xx/configuration/guide/b-telemetry-cg-ncs5500-24xx/scale-up-your-network-monitoring-strategy-using-telemetry.html) | `Cisco-IOS-XR-install-oper:install/version` chassis PID and release label |
| `nexus_9000` | `nx_os` | [`10.6(x)`](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/106x/programmability/cisco-nexus-9000-series-nx-os-programmability-guide-106x/m-gnmi.html) | Generic `openconfig` origin, `openconfig-platform` model, and `components/component/state` path |
| `nexus_3500` | `nx_os` | [`10.5(x)`](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus3000/105x/programmability/cisco-nexus-3500-series-nx-os-programmability-guide_105x/m_n3600_gnmi_93x.html) | Generic `openconfig` origin, `openconfig-platform` model, and `components/component/state` path |

On NX-OS, `openconfig` is the generic wire origin for OpenConfig Get and Subscribe paths. It is not a Capabilities
model name. Preflight still validates the individual `openconfig-platform`, `openconfig-system`, and
`openconfig-interfaces` models required by the enabled identity and profile paths.

The contract registry accepts any syntactically valid build in the listed train. Each target's `software_version` is
the exact expected running build; its canonical configured and observed values must match exactly. Chassis identity is
matched against the anchored `C9800-`/`CAT9800-`, `ASR-9`, `NCS-55`, `N9K-`, or `N3K-C35` family for the selected
product. Cisco SONiC is explicitly unsupported. `platform`, including `platform: sonic`, remains a decoder-only
migration field that always fails validation; no OS-family field can select a contract.

For IOS XE, configure the exact public Cisco release label, such as `17.18.1` or `17.18.1a`. Preflight normalizes the
device's internal install-version form (for example, `17.18.01.0.1186`) to that public label; the separate opaque
`version-extension` list key is not appended. This verifies the running public release, not SMUs or bit-for-bit image
identity. NX-OS accepts documented builds such as `10.6(1)F` and `10.6(2n)F`.

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

There is no OS-family compatibility fallback. Choose the product that matches the deployed chassis, record its exact
running build, and restart the receiver after correcting a terminal qualification failure.

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
          product: nexus_9000
          software_version: "10.6(1)"
          max_recv_msg_size_mib: 16
          credentials:
            mode: username_password
            username: otel-telemetry
            password: ${env:CISCO_GNMI_PASSWORD}
          tls:
            ca_file: /etc/otel/cisco-ca.pem
            min_version: "1.2"
            server_name_override: nexus01.example.net
            reload_interval: 1h
          profiles:
            identity:
              enabled: true
            system:
              # Nexus contracts do not define a system profile.
              enabled: false
            interfaces:
              enabled: true
            optics:
              # Enable only after separate chassis/line-card/optic qualification.
              enabled: false
```

`product` must be one of the five canonical values in the contract table, and `software_version` must be the exact
expected running build in that product's accepted train. The OS family is derived from the product and is not
configurable. Profiles are product-specific rather than a universal list:

| Product family | Default normalized profiles | Optional profiles |
| --- | --- | --- |
| Catalyst 9800 | Identity, CPU, per-location memory utilization, interface state, and cumulative interface counters | `catalyst_9800_wireless`; experimental IOS XE DOM optics |
| ASR 9000 / NCS 5500 | Identity, per-node CPU, interface state, and cumulative interface counters | Experimental IOS XR controller/lane DOM optics |
| Nexus 9000 / Nexus 3500 | Identity, interface state, and cumulative interface counters; no system profile | Experimental NX DME DOM/VDM optics |

Identity defaults to five minutes, supported system and interface profiles to 60 seconds, and optics to 30 seconds.
Safe product-specific baseline profiles default on. `catalyst_9800_wireless` is valid only for `catalyst_9800`.
Every optics profile is opt-in and remains explicitly experimental until the exact product, release, line card, and
physical optics are separately qualified.

Credentials modes are `username_password`, `mtls`, and `mtls_username_password`. mTLS modes also require
`tls.cert_file` and `tls.key_file`. TLS is mandatory: plaintext `tls.insecure` and TLS versions below 1.2 are rejected.
Certificate verification is enabled by default. Prefer `tls.ca_file` plus `tls.server_name_override`; isolated labs with
self-signed device certificates may explicitly set `tls.insecure_skip_verify: true`. Arbitrary metadata headers are not
supported.

Targets normally use no more than four compatible subscription streams. A target may explicitly raise its maximum to
eight only after that product and release have been qualified. Origins remain separate from paths: IOS XE uses
RFC7951 prefixing, IOS XR uses the module origin, and NX-OS uses generic `openconfig` for OpenConfig paths and `DME`
for the distinguished-name optics family.
IOS XR baseline collection uses two streams; enabling its experimental optics profile raises the total to three.

The five Cisco product contracts require an origin for custom subscriptions and reject `path_target`. Both Nexus
contracts additionally require explicit non-wildcard paths; the IOS XE and IOS XR contracts retain their qualified
wildcard surface.

`custom_subscriptions[].models` explicitly separates Capabilities requirements from the wire origin. It is optional
for non-generic origins, but required and non-empty for `origin: openconfig`. Each custom subscription accepts at most
32 unique, whitespace-free valid YANG module identifiers, preserving exact case. Every explicit model is included in
Capabilities validation. Entries must identify concrete modules; the generic name `openconfig` is rejected. For
example:

```yaml
custom_subscriptions:
  - name: component_temperature
    origin: openconfig
    models: [openconfig-platform]
    mode: stream
    sample_interval: 1m
    encoding_preference: [json]
    paths:
      - path: components/component/state/temperature
        stream_mode: sample
    mappings:
      - path: components/component/state/temperature/instant
        metric_name: example.component.temperature
        description: Component temperature
        unit: Cel
        scale: 1
        gauge_type: double
        path_keys:
          component.name: hw.name
```

The request carries `openconfig` as its origin; it does not substitute `openconfig-platform` into the path prefix.

`path_target` is a decoder-only migration field: it remains in the schema solely to produce an actionable validation
error and is never placed on a qualified request. Each target accepts at most eight custom streams. A custom stream has
at most 256 effective request selectors (explicit `paths`, or derived mapping paths when `paths` is omitted), 1024
mappings, and 64 path-key attributes per mapping. Each profile accepts at most 64 path overrides. Receiver-wide limits
are 4096 custom request paths, 16384 mappings, 4096 profile path overrides, and 64 MiB of retained custom/profile plan
strings; validation enforces them before request or mapping construction.

## Subscribe request parity

The receiver plans each physical subscription stream independently from one Capabilities response. A target-wide
`encoding_preference` can contain only encodings approved by the selected product contract. Catalyst 9800, ASR 9000,
and NCS 5500 accept JSON_IETF or JSON; Nexus 9000 and Nexus 3500 accept JSON only. PROTO is rejected. When every
preference field is omitted, requests use STREAM/SAMPLE, the existing profile or custom sample interval, no list
options or extensions, and JSON_IETF before JSON for IOS XE/XR.

The two Nexus contracts deliberately narrow this generic request surface to the subset common to Nexus 9000 10.6 and
Nexus 3500 10.5: JSON encoding, STREAM/SAMPLE subscriptions, explicit non-wildcard paths, no subscription-list prefix,
and no optional subscription flags. All paths in one Nexus request must use one effective sample interval in the
documented 1-to-604800-second range. Nexus configurations that request JSON_IETF, PROTO, ON_CHANGE, TARGET_DEFINED,
ONCE, POLL, aggregation, updates-only, QoS, Depth, heartbeat, suppression, or mixed/out-of-range cadences fail
validation.

Profiles accept `encoding_preference`, `updates_only`, `allow_aggregation`, `qos_marking`,
`gnmi_extensions.depth`, and `path_overrides`. An override key is a stable path ID from the selected product's catalog,
such as `system.cpu` or `interfaces.openconfig`; an override changes request behavior only and cannot replace the
catalog path or metric mapping. Unknown path IDs are rejected. Custom subscriptions accept the same list-level and
extension fields plus `origin`, an origin-dependent `models` list, and an explicit `paths` list. Each path entry has
`path`, `stream_mode`, `sample_interval`, `heartbeat_interval`, and `suppress_redundant`.

`encoding_preference` order is resolved per stream. `updates_only` and `allow_aggregation` default to `false`.
`qos_marking` is absent by default and accepts `0` through `63`; `gnmi_extensions.depth` is absent by default and accepts
`1` through `128`. Depth is encoded as the typed extension on the top-level SubscribeRequest. QoS, aggregation, and
updates-only are encoded on SubscriptionList. Per-path mode, timing, heartbeat, and suppression are encoded on the
individual Subscription.

### Path validation

STREAM path options follow the gNMI protocol semantics:

- `sample`: an omitted `sample_interval` inherits the stream's existing interval; explicit `0s` asks for the target's
  fastest supported interval. `suppress_redundant` and a positive `heartbeat_interval` are permitted.
- `on_change`: a positive `heartbeat_interval` is permitted; `sample_interval` and `suppress_redundant` are rejected.
- `target_defined`: sample interval, heartbeat, and suppression are rejected so the target owns the behavior.

ONCE and POLL are available only to the ASR 9000 and NCS 5500 contracts. They leave all per-path mode and timing fields
at protobuf defaults. `path_overrides` and `updates_only` are rejected in those modes because they do not produce useful
mapped output; POLL continues to use the client-side `poll_interval`. Catalyst 9800 and both Nexus contracts are
STREAM-only.

When custom `paths` is omitted, the receiver derives one exact selector from every mapping, preserving existing custom
configurations. When it is present, every mapping must equal or descend from at least one selector. Keys on a selector
must be a subset of keys on the mapped path. Duplicate selectors and selectors that assign conflicting behavior are
rejected.

`allow_aggregation: true` requires a negotiated JSON or JSON_IETF encoding. All shared product contracts reject PROTO.
Actual support for modes,
heartbeat, suppression, QoS, aggregation, and Depth remains device- and release-dependent and must be recorded in the
validation matrix rather than encoded as a generic Cisco capability table.

### Decoding and reconnect state

The bounded primitive scalar PROTO decoder remains for deprecated receiver surfaces, but shared product contracts do
not negotiate PROTO. Aggregated JSON and JSON_IETF subtrees use the same bounded recursive decoder as non-aggregated
payloads, and only explicitly mapped descendant leaves become metrics.

`leaflist_val`, `bytes_val`, `any_val`, and experimental `proto_bytes` are recognized and bounded but do not become
metrics. They increment bounded self-telemetry by value kind. In particular, arbitrary binary protobuf data is never
guessed or promoted to a dynamically named metric.

Each stream owns its cache entries, atomic baselines, and tombstones. Before a new target session starts, the receiver
silently resets only owners belonging to streams configured with `updates_only: true`. The reset does not emit delete or
optical-presence signals. Streams without `updates_only` retain the existing cross-reconnect cache behavior.

### Rejected requests are not downgraded

If a non-baseline Subscribe request returns `InvalidArgument` or `Unimplemented`, the receiver makes one bounded
diagnostic probe using baseline SAMPLE/JSON semantics and discards all probe data. When the baseline succeeds, the
receiver classifies the failure as `unsupported_request_options`, stops only that configured stream until reload or
restart, and does not retry another encoding or remove options. When the baseline also fails, the existing bounded path
bisection runs with baseline requests; accepted path groups are relaunched with their original requested options.

Other streams remain connected. Any degraded enabled curated profile, whether required or optional, blocks live
qualification until receiver restart. An optional custom stream is isolated without making the whole target reconnect.
A custom stream marked `required` is also a qualification obligation; late degradation withdraws a previously emitted
up signal. Every discard-only diagnostic probe has a finite deadline no longer than 15 seconds.
Rejected-request identities include paths, every path and list option, encoding, and extensions so repeated failures
remain bounded without conflating different requests.

## Qualification preflight and quarantine

Every new session completes these steps in order:

1. Call Capabilities once on the target session and determine the product-approved encoding for every planned physical
   stream.
2. Derive the required model set from the contract's identity probes, every enabled curated-profile path, each
   non-generic custom origin, every explicit custom `models` entry, and every valid RFC7951 module qualifier in
   selectors and mapped descendants. The generic NX-OS `openconfig` origin is not treated as a model; its concrete
   model requirements come from the built-in contract or the custom stream's required `models` list. Preserve exact
   YANG module-name case and reject a target when any required model is missing.
3. Run only the bounded identity Get probes declared by the selected contract and validate one unambiguous chassis
   identity plus the exact configured software build.
4. Build the verified resource identity and launch metric Subscribe streams only after every preceding check passes.
   The verified session never invokes Set.

An identity that is missing, ambiguous, malformed, or oversized, a product or release mismatch, a missing required
model, an unsupported encoding, or a deterministic malformed/unimplemented Capabilities response is a terminal
compatibility failure. The receiver emits `cisco.device.up=0`, records one bounded preflight failure,
launches no configured metric stream, and quarantines only that target until receiver restart. The preflight may have
issued one or more bounded identity Gets; Set remains zero. A planned stream with no
product-approved advertised encoding is the terminal `unsupported_encoding` compatibility failure and
quarantines the target. The receiver does not try another preference after an actual request rejection. Transport
failures, authentication failures, and temporary RPC failures continue through the existing bounded backoff path.

Post-preflight device errors follow the no-downgrade diagnostic and path-bisection behavior above. A live qualification
cannot pass while any enabled curated profile is degraded, even when non-degraded profiles continue to produce data.

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

Custom subscriptions are accepted only when each scalar numeric source path has an explicit mapping with a metric name,
description, UCUM unit, scale, gauge type, and path-key-to-attribute mappings. Selectors may subscribe to a mapped
ancestor for aggregated JSON, but they never authorize arbitrary JSON-to-metric conversion. Unmapped paths, custom sums,
and dynamic `_info` metrics are rejected.

## Metric contract

The product-specific identity, system, and interface profiles reuse the receiver's existing normalized metrics instead
of creating platform-specific duplicates. Catalyst 9800 emits `cisco.device.up`, `system.cpu.utilization`, and
per-location `system.memory.utilization`. ASR 9000 and NCS 5500 emit `cisco.device.up` and per-node
`system.cpu.utilization`; they do not emit normalized memory or uptime. Nexus emits `cisco.device.up` and has no system
profile. No shared-gNMI product emits `system.uptime`.

Every product's interface profile emits `system.network.interface.status`, `cisco.interface.admin.status`, and the
cumulative sums `system.network.io`, `system.network.errors`, `system.network.packet.count`, and
`system.network.packet.dropped`. It does not emit `cisco.interface.speed`, `cisco.interface.io.rate`,
`cisco.interface.packet.rate`, or `cisco.interface.utilization`.

After verification, shared-gNMI resources include `cisco.product.family`, `device.manufacturer=Cisco`, the verified
`device.model.identifier`, and exact `os.version`. Existing `cisco.os.name` and `os.name` remain available.
`cisco.platform.family` is retained as a legacy OS-family alias for compatibility; new grouping should use
`cisco.product.family`.

The receiver's internal telemetry exposes
`otelcol_ciscoosreceiver_gnmi_product_verified{cisco.gnmi.target}` and the cumulative
`otelcol_ciscoosreceiver_gnmi_preflight_failures{cisco.gnmi.target,cisco.gnmi.reason}`. Preflight reasons are bounded
to `identity_missing`, `identity_ambiguous`, `product_mismatch`, `release_mismatch`, `missing_model`,
`unsupported_encoding`, and `malformed_identity`. Post-preflight stream degradation uses bounded `bisection_limit`,
`cache_limit`, `incompatible_path_group`, `unsupported_path`, and `unsupported_request_options` reasons, and
self-telemetry counts owner resets and unsupported TypedValue kinds without using device-controlled labels.

The optics profile emits explicit gauges. `network.interface.name`, `cisco.optics.lane`, an allowlisted
`cisco.optics.sensor`, `cisco.optics.profile`, and `cisco.optics.experimental` identify their source as applicable.

| Profile | Metric | Unit |
| --- | --- | --- |
| DOM | `cisco.optics.temperature` | `Cel` |
| DOM | `cisco.optics.voltage` | `V` |
| DOM | `cisco.optics.laser_bias_current` | `mA` |
| DOM | `cisco.optics.rx_power` | `dB[mW]` |
| DOM | `cisco.optics.tx_power` | `dB[mW]` |
| DOM | `cisco.optics.present` | `1` |
| VDM | `cisco.optics.esnr` | `dB` |
| VDM | `cisco.optics.tdecq` | `dB` |
| VDM | `cisco.optics.pre_fec_ber` | `1` |
| VDM | `cisco.optics.tec_current` | `mA` |
| VDM | `cisco.optics.tec_utilization` | `1` |

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
trimmed. `max_cached_series` sets one receiver-wide count ceiling for active mapped series, atomic baselines, and delete
tombstones. The independent auxiliary entry ceiling is four times that value, accounting for one NX sensor identity and
the optical source, presence-count, and attribute entries associated with a cached optical series. Each count ceiling is
deterministically partitioned across selected targets. The cache and auxiliary state also have separate receiver-wide
retained-byte ceilings: 1.25 GiB for cache correctness state and 256 MiB for auxiliary state, yielding a 1.5 GiB combined
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

Device timestamps are normalized from seconds, milliseconds, microseconds, or nanoseconds. Values outside year 2000
through receipt time plus 24 hours fall back to receipt time and increment the invalid-timestamp counter.

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

Alert on target inactivity beyond two sample intervals, required-profile degradation, authentication failures,
decode/unmapped growth, cache or auxiliary-state use above 80 percent, stream churn, consumer refusal, and device or
collector certificate expiry. Utilization is emitted per target and is the larger of that partition's entry-count and
retained-byte ratios, so byte pressure cannot remain hidden behind a low entry count.

Also alert when `otelcol_ciscoosreceiver_gnmi_product_verified` is zero or
`otelcol_ciscoosreceiver_gnmi_preflight_failures` increases. A compatibility failure requires correcting the configured
product/version, device image, model availability, or encoding contract and restarting the receiver; it is not a
transport outage to solve with more retries.

For an authentication alert, stop rapid retries, confirm the shard account is not locked, verify Capabilities and
the bounded identity Get and Subscribe permissions while Set remains denied, rotate the credential, then roll one shard.
For a certificate alert, verify SAN and chain first,
rotate one device or shard, force a new TLS handshake, and confirm last-success before continuing. For cache pressure,
identify the profile and series growth, then split the static inventory without overlapping ownership.

## Acceptance gates

Unit and fake-server coverage must include configuration validation, origin/path construction, all typed encodings,
scaling and units, atomic/delete behavior, timestamps and out-of-order updates, cache/batch bounds, POLL sequencing,
reconnect classification, shutdown rollback, TLS trust/SAN/mTLS cases, credentials on every RPC, denied credentials,
bounded Capabilities, identity Get, and Subscribe responses, required-model derivation, every terminal preflight and degradation reason,
option rejection versus bad-path bisection, and proof that Set remains zero. Each of the five contracts requires a
fake-server path through Capabilities, bounded identity Get, the permitted metric Subscribe shape,
verified resource attributes, and
decoded metrics. Negative cases must prove isolation without downgrade; transient network failures must continue
retrying.

Implementation coverage is recorded by product and train in the [validation matrix](validation-matrix.md). It does not
qualify a device. Live qualification is exact-build evidence and requires verified TLS, zero preflight failures, no
degraded enabled profile, active subscriptions, `cisco.device.up=1`, correct verified resource identity, backend
delivery, and at least three successful collection intervals. Catalyst 9800 qualification must additionally exercise
`catalyst_9800_wireless` against representative AP and client state.

Physical qualification is mandatory for every optional optics profile: IOS XE DOM, IOS XR controller/lane DOM, and
NX-OS DOM/VDM on the deployed chassis, line card, and optic. Capture sanitized Capabilities, identity GetResponse, and metric SubscribeResponse
fixtures, and record release,
SKU, optic PID, firmware, origin, path, description, unit, and raw value. Compare simultaneous gNMI and CLI/device
readings within one documented source resolution. Exercise insert/remove, link failure, reboot, AAA outage and recovery,
both certificate rotations, supervisor switchover, and a 24-hour soak at 30 seconds. A baseline product qualification
does not qualify an optional optics profile.

The scale gate is a synthetic TLS test with at least 100 targets, 5,000 optical ports, up to eight lanes, 500,000 active
mapped series, and about 16,700 datapoints/second. On 4 vCPU and 4 GiB, require CPU at or below 80 percent, RSS at or
below 3.2 GiB, p95 notification-to-consumer latency below five seconds, no receiver loss with an accepting consumer,
bounded cache, and reconnect recovery within 60 seconds.

An opt-in data-plane harness is included for the 100-target/500,000-series/16,700-point cache, mapping, and lossless
chunking portion:

```sh
CISCOOS_GNMI_RUN_SCALE_QUALIFICATION=1 GOMAXPROCS=4 go test ./internal/gnmi \
  -run '^TestInternalGNMIScaleQualification_100Targets5000Ports500KSeries$' -count=1 -v
```

The local qualification run populated 500,000 series in 3.20 seconds and processed the interval in 133 ms, with 1.30 GB
RSS, 25.04 percent four-core burst CPU, and 3.32 percent four-core CPU at the modeled one-second cadence. Its conservative
cache accounting retained 1,100,820,000 bytes under the 1.25 GiB production ceiling; chunks
contained 10,000 and 6,700 datapoints with no loss. That harness does not
exercise 100 TLS listeners, reconnect recovery, exporter queues, or hardware. Those portions of the scale gate remain
mandatory in the deployment environment.

Splunk Observability Cloud acceptance verifies metric names and dimensions, UCUM units (especially `dB[mW]`),
presence/freshness behavior, dashboards, and predictive-model inputs. Removal must stop new optical samples, and
detectors must exclude `present=0` and stale ports.
