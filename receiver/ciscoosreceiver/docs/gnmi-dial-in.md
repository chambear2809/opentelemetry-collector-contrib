# Production gNMI Dial-In

The shared `cisco_os.gnmi` client collects normalized metrics from IOS XE, IOS XR, and NX-OS. It is a static-inventory,
read-only client: it uses Capabilities and Subscribe, never Set, and does not require Get. SONiC, target discovery, gNMI
Set, and dial-out metric semantics are outside this feature's scope; receiver-wide transport hardening also applies to
the existing dial-out servers as described below.

The fake-server and synthetic implementation gates can be completed without physical devices. Upstream submission still
requires human code-owner agreement on the configuration, security model, metric contract, and hardware plan. CML,
physical-optics, and Splunk validation remain release gates; this document does not treat their absence as qualification.

Existing `ios_xr.dial_out` and `catalyst_9800.dial_out` configurations remain available. Legacy dial-in targets keep
their legacy decoder and metric names for one fork release and emit a deprecation warning. Do not configure the same
endpoint in both a legacy dial-in section and `gnmi.targets`.

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
          platform: nx_os
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
              enabled: true
            interfaces:
              enabled: true
            optics:
              enabled: true
              required: true
              sample_interval: 30s
```

`platform` is `ios_xe`, `ios_xr`, or `nx_os`. The available profiles are `identity`, `system`, `interfaces`, `optics`,
and the fork-only `catalyst_9800_wireless`. Identity defaults to five minutes, system and interfaces to 60 seconds, and
optics to 30 seconds. Safe baseline profiles default on. Optics is opt-in because lane telemetry is high-cardinality and
hardware-dependent.

Credentials modes are `username_password`, `mtls`, and `mtls_username_password`. mTLS modes also require
`tls.cert_file` and `tls.key_file`. Verified TLS is mandatory: `tls.insecure`, `tls.insecure_skip_verify`, and TLS
versions below 1.2 are rejected. Arbitrary metadata headers are not supported.

Targets normally use no more than four compatible subscription streams. A target may explicitly raise its maximum to
eight only after that device platform and release have been qualified. Origins remain separate from paths: IOS XE uses
RFC7951 prefixing, IOS XR uses the module origin, and NX-OS assigns `DME`, device, or OpenConfig origin per path.
IOS XR with the optics profile currently requires `max_streams: 6` because its native system and optical modules use
separate origins.

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
description, UCUM unit, scale, gauge type, and path-key-to-attribute mappings. Unmapped paths, custom sums, arbitrary
JSON-to-metric conversion, and dynamic `_info` metrics are rejected.

## Metric contract

The identity, system, and interfaces profiles reuse the receiver's existing normalized metrics instead of creating
platform-specific duplicates:

- `cisco.device.up`, `system.cpu.utilization`, `system.memory.utilization`, and `system.uptime`.
- `system.network.interface.status`, `system.network.io`, `system.network.errors`,
  `system.network.packet.count`, and `system.network.packet.dropped`.
- `cisco.interface.admin.status`, `cisco.interface.speed`, `cisco.interface.io.rate`,
  `cisco.interface.packet.rate`, and `cisco.interface.utilization`.

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
| Coherent | `cisco.optics.q_factor` | `dB` |
| Coherent | `cisco.optics.q_margin` | `dB` |
| Coherent | `cisco.optics.osnr` | `dB` |
| Coherent | `cisco.optics.dgd` | `ps` |
| Coherent | `cisco.optics.chromatic_dispersion` | `ps/nm` |

`cisco.optics.tec_current` and `cisco.optics.tec_utilization` are mutually selected from the sensor's reported unit.
TDECQ is emitted only when an allowlisted description explicitly identifies TDECQ and the unit is dB. NX-OS's
"PAM4 level transition parameter" is not TDECQ and is never aliased to it. Unknown sensor IDs are counted as unmapped,
not exported as new metrics.

NX-OS VDM and IOS XR coherent readings set `cisco.optics.experimental=true` until their physical-hardware gates below
pass. They must not be described as production-ready before qualification.

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
deterministically partitioned across selected targets. The cache and auxiliary state also have separate
256 MiB receiver-wide retained-byte ceilings, yielding a 512 MiB combined accounted ceiling; their conservative byte
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
- Use one read-only AAA account per collector shard, rotate it centrally, and test that Capabilities and Subscribe
  succeed while Set is denied. Keep a controlled local break-glass account.
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
decode/unmapped growth, cache use above 80 percent, stream churn, consumer refusal, and device or collector certificate
expiry.

For an authentication alert, stop rapid retries, confirm the shard account is not locked, verify Capabilities and
Subscribe permissions, rotate the credential, then roll one shard. For a certificate alert, verify SAN and chain first,
rotate one device or shard, force a new TLS handshake, and confirm last-success before continuing. For cache pressure,
identify the profile and series growth, then split the static inventory without overlapping ownership.

## Acceptance gates

Unit and fake-server coverage must include configuration validation, origin/path construction, all typed encodings,
scaling and units, atomic/delete behavior, timestamps and out-of-order updates, cache/batch bounds, POLL sequencing,
reconnect classification, shutdown rollback, TLS trust/SAN/mTLS cases, credentials on every RPC, denied credentials,
and proof that zero Set/Get calls occur.

CML qualification covers IOS XE 17.15+, IOS XR 24.3+, and NX-OS 10.5+ for secure transport, Capabilities, baseline
profiles, reconnects, and supported subscriptions. Treat the IOS XE management-VRF restriction as 17.18.2+, IOS XR
Subscribe as 24.2.1+, and NX advanced VDM as 10.6(1)+ on supported hardware. CML does not qualify optics.

Physical qualification is mandatory for NX-OS 10.6(1)+ on the deployed Nexus SKU with CMIS/VDM optics and IOS XR
24.3+ on 8201/NCS hardware with coherent optics. Capture sanitized Capabilities and SubscribeResponse fixtures and
record release, SKU, optic PID, firmware, origin, path, description, unit, and raw value. Compare simultaneous gNMI and
CLI/device readings within one documented source resolution. Exercise insert/remove, link failure, reboot, AAA outage
and recovery, both certificate rotations, supervisor switchover, and a 24-hour soak at 30 seconds.

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

The local qualification run populated 500,000 series in 2.12 seconds and processed the interval in 105 ms, with 1.41 GB
RSS, 25.03 percent four-core burst CPU, and 2.64 percent four-core CPU at the modeled one-second cadence; chunks
contained 10,000 and 6,700 datapoints with no loss. That harness does not
exercise 100 TLS listeners, reconnect recovery, exporter queues, or hardware. Those portions of the scale gate remain
mandatory in the deployment environment.

Splunk Observability Cloud acceptance verifies metric names and dimensions, UCUM units (especially `dB[mW]`),
presence/freshness behavior, dashboards, and predictive-model inputs. Removal must stop new optical samples, and
detectors must exclude `present=0` and stale ports.
