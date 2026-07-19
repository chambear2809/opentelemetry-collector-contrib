# Cisco OS Receiver Metrics

This guide lists the fixed metrics emitted by the Cisco OS receiver, documents its dynamic YANG metric patterns, and
explains in plain language why someone might monitor them. It is written for operators who may not know Cisco or
networking terms yet.

Fixed-name governance is exact for metric name, description, instrument, numeric type, unit, monotonicity, and
temporality across the receiver and both child scrapers. Attribute governance is deliberately narrower: required and
optional attributes are checked for `cisco.topology.neighbor.info`, and shared-gNMI builtin mappings have a typed
optional-attribute union. Other API, CLI, and direct-telemetry attributes remain source-conditional; the fixed catalog
does not claim an exhaustive attribute union for those emitters.

The fixed wire contracts use integer datapoints for IOS XR and Catalyst 9800 receiver health and for discrete WLC
status, count, counter, and byte aliases; continuous WLC measurements remain double gauges with cataloged units.
Compact-GPB diagnostics are a single per-message integer gauge and carry no receiver-health state. Direct
gNMI and GPB-KV dynamic datapoints retain an injective raw source identity in `cisco.yang.source_path`. Direct-gNMI
structured scalar paths are unchanged; JSON descendants use `rawGNMIPath#/escaped/key` framing, with the fragment
encoded as a JSON Pointer so the structured-to-JSON boundary and arbitrary object keys remain unambiguous. Complex-array
entries are emitted only when every entry has a recognized stable identity, including singleton arrays, so
an anonymous occupant cannot silently inherit a prior series identity. The normalized
`cisco.topology.*` attributes are additive: ACI continues to emit its legacy `network.peer.name`,
`network.peer.address`, and `network.protocol.name` attributes.

The broad `cisco.catalyst9800.yang.` and `cisco.iosxr.yang.` namespaces are reserved for pattern-governed model output
and are outside exact fixed-name completeness. Receiver-generated names use the current `__v1` encoding. After the
product prefix, the common grammar is `__v1.(m0|m1.<segment>)`: `m0` means no module and `m1` is followed by its raw
module value. Direct gNMI then uses `p<count>.<segment>...`; dial-out uses
`(e0|e1.e<count>.<segment>...).p<count>.<segment>...`, so canonical nonempty encoding-path containers and raw GPB-KV
source-path segments are separate tuples. `e0` represents the deliberate absent/empty encoding-path class. A nonempty
`encoding_path` is accepted only in slash-delimited canonical form, with no surrounding whitespace or slash and no
empty segment; noncanonical input is rejected rather than normalized. Only a valid `module:local-name` before any
predicate bracket changes the effective module. Colons in retained predicate values such as MAC or IPv6 identities
remain segment data. Numeric and info variants
end in `.n` and `.i`. A segment is `s<byte-count>_<bytes>`, where ASCII letters and digits remain readable and every
other byte is escaped as `_HH`. These length and count frames preserve case, punctuation, module qualifiers, segment
boundaries, the dial-out encoding/source boundary, and the transparent `content` segment. Target and list-key values
remain attributes rather than entering metric names.

For direct gNMI, differing nonempty prefix and relative-path origins are rejected and counted. Otherwise the one
nonempty effective origin is the module frame before any module-qualified path fallback. Dial-out accepts only raw
yang_grpc `cisco.*` metrics plus its exact compact-GPB diagnostic; apparent fixed, product, or alias prefixes from a
device are still framed, and non-`cisco.*` input is rejected. Every dynamic datapoint retains
`cisco.yang.source_path`. The active final-name budget applies to the completed encoded name and is capped at 1024
bytes; overflow is rejected without truncation.

Numeric `.n` streams have one deterministic contract per encoded leaf: gauges are finite double datapoints and known
counters are cumulative monotonic sums with int64 datapoints. Parser-less dial-out gauges are raw carriers and are
promoted to sums only when deterministic path classification identifies a counter. An incoming sum is never demoted
to a gauge, and a sum classified as a counter must already be cumulative and monotonic. Exact int-to-double and
integral double-to-int conversions are accepted, including exactly representable int64 values beyond 2^53; inexact
gauge integers, fractional or out-of-range counters, incompatible instruments, unset points, and nonnumeric dynamic instruments are
dropped and counted rather than rounded or silently coerced. Info `.i` streams are double gauges with the original
text, including a present empty string, on `value`. JSON null remains absent. This is a breaking replacement for the former sanitized dynamic names and mixed source numeric
representations. Fixed catalogs, stable `cisco.wlc.*` aliases, and normal shared-gNMI profiles are unchanged. Custom
shared-gNMI mappings remain a separate exact configuration-time contract and cannot claim any fixed name or any
current/future name in either broad YANG namespace.

The receiver has two SSH scrapers plus API polling and telemetry paths for Meraki, Intersight, Catalyst Center,
Catalyst 9800 WLCs, Catalyst SD-WAN Manager, Nexus Dashboard/NDFC, APIC, Secure Firewall Management Center, Cisco
Identity Services Engine, secure normalized gNMI dial-in, and IOS XR MDT:

- `system`: device availability, CPU, memory, protocol, control-plane, routing, forwarding, and router dataplane health.
- `interfaces`: physical and logical port traffic, errors, packet drops, link status, L2 topology, LACP, vPC, and transceiver sensors.
- `meraki`: organization-scoped Dashboard API polling for inventory, status, uplinks, switch ports, wireless, VPN, power modules, topology, and transceiver telemetry.
- `intersight`: signed Intersight API polling for UCS, HyperFlex, storage, Kubernetes, virtualization, alarms, advisories, HCL/compliance, workflows, audit records, and telemetry GroupBy performance.
- `catalyst_center`: Catalyst Center Assurance API polling for inventory, reachability, interface, network health, client health, site health, topology, issues, device-detail, and client-detail telemetry.
- `catalyst_9800`: Direct Catalyst 9800 WLC/AP gNMI dial-in and MDT gRPC dial-out telemetry for AP join state, CAPWAP, RF, SSID, client auth/roam, mobility, HA, RADIUS, and controller health.
- `sdwan`: Catalyst SD-WAN Manager polling for Manager API trust, inventory, control plane, BFD, app-route, interfaces, alarms, events, audit, and opt-in product modules such as tunnels, policy/QoS, security, AppQoE, Cloud OnRamp, NWPI, underlay, cellular, hardware/energy, routing services, branch services, lifecycle/compliance, ThousandEyes agent status, and management security.
- `nexus_dashboard`: API-first polling for Nexus Dashboard platform health, NDFC LAN/NX-OS fabrics, Insights/Analyze anomalies, Orchestrator/OneManage deployment state, Data Broker sessions, and interface performance.
- `aci`: APIC class-query polling for ACI controller health, fabric nodes, faults, audit/events, tenant objects, endpoint presence, topology, and bounded stats.
- `fmc`: Secure Firewall Management Center REST polling for FMC-managed FTD/ASA inventory, interfaces, health, VPN, HA/failover, policy, deployment, audit evidence, and optional eStreamer security-event logs.
- `ise`: Cisco Identity Services Engine REST/OpenAPI/ERS/MnT polling for deployment, network-device, endpoint, session,
  authentication, posture, profiler, policy, TrustSec, alarm, certificate, license, and webhook evidence, with opt-in
  pxGrid streaming and Data Connect queries.
- `gnmi`: Product-qualified secure gNMI dial-in for Catalyst 9800 17.18.x, ASR 9000/NCS 5500 24.4.x, Nexus 9000
  10.6(x), and Nexus 3500 10.5(x), with bounded preflight, cache, path-group, stream, and cardinality controls plus
  receiver self-telemetry for qualification, subscription health, and retained-state pressure.
- `ios_xr`: IOS XR gNMI dial-in and MDT gRPC dial-out telemetry for ASR 9000 and NCS routers, normalized from YANG paths into generic `cisco.iosxr.*` metrics.

Device-scoped SSH metrics include the following resource attributes. API account, controller, organization, network,
and aggregate resources include the attributes that exist at that scope; for example, they can omit `host.ip`,
`host.type`, or `os.version`. Shared gNMI adds `host.ip` only when the configured endpoint host is an IP literal.

| Attribute | Meaning |
| --- | --- |
| `host.id` | Stable device identity from the serial number when available, otherwise the configured device host. |
| `host.ip` | The IP address of the Cisco device. |
| `host.name` | Device hostname reported by `show version` when available. |
| `host.type` | Device model or platform reported by `show version` when available. |
| `hw.type` | Hardware type, set to `network`. |
| `os.name` | Device operating system, such as `IOS XE`, `IOS`, or `NX-OS`. |
| `os.version` | Device operating system version reported by `show version` when available. |

Shared gNMI emits device telemetry only after live identity verification. Its verified resource adds these values:

| Attribute | Meaning |
| --- | --- |
| `cisco.product.family` | Canonical configured and verified family: `catalyst_9800`, `asr_9000`, `ncs_5500`, `nexus_9000`, or `nexus_3500`. |
| `device.manufacturer` | `Cisco`. |
| `device.model.identifier` | Unambiguous chassis model returned by the product-specific identity probe. |
| `os.version` | Exact canonical running build, verified against required `software_version`. |
| `cisco.os.name` | Derived Cisco OS family. |
| `os.name` | Human-readable derived OS name. |
| `cisco.platform.family` | Legacy shared-gNMI OS-family alias retained for compatibility; use `cisco.product.family` for product grouping. |

Controller/API paths add these correlation attributes when available:

| Attribute | Meaning |
| --- | --- |
| `cisco.controller.type` | Controller source, such as `nexus_dashboard` or `apic`. |
| `cisco.controller.endpoint` | Controller endpoint used for the API poll. |
| `meraki.organization.id` | Meraki organization ID. |
| `meraki.network.id` | Meraki network ID. |
| `meraki.device.serial` | Meraki device serial. |
| `meraki.device.product_type` | Meraki appliance, switch, wireless, sensor, or other product family. |
| `intersight.endpoint` | Intersight API endpoint. |
| `intersight.moid` | Intersight managed-object ID. |
| `intersight.resource.type` | Intersight object family. |
| `intersight.serial` | Intersight-reported hardware serial. |
| `cisco.fabric.name` | Fabric name reported by NDFC, Insights, NDO, or APIC-derived context. |
| `cisco.site.name` | Site name reported by Nexus Dashboard services. |
| `cisco.switch.role` | Switch role, such as leaf, spine, border leaf, or controller. |
| `cisco.switch.serial` | Nexus switch serial used to correlate API, SSH, and MDT/YANG telemetry. |
| `catalyst_center.device.family` | Catalyst Center device family reported by inventory or topology APIs. |
| `catalyst_center.device.id` | Catalyst Center device ID. |
| `catalyst_center.device.serial` | Catalyst Center device serial. |
| `catalyst_center.device.role` | Catalyst Center device role reported by inventory or topology APIs. |
| `catalyst_center.health.state` | Bounded health-state label such as total or good for site population counts. |
| `catalyst_center.site.name` | Catalyst Center site name or hierarchy. |
| `catalyst_center.client.mac` | Targeted Catalyst Center client MAC address. |
| `sdwan.system_ip` | Catalyst SD-WAN system IP. |
| `sdwan.uuid` | Catalyst SD-WAN device UUID. |
| `sdwan.site.id` | Catalyst SD-WAN site ID. |
| `sdwan.personality` | Catalyst SD-WAN personality, such as Manager, Controller, Validator, WAN Edge, or SD-Routing role. |
| `sdwan.tloc.color` | Catalyst SD-WAN transport color. |
| `sdwan.application` | Bounded SD-WAN application name for app-route and AI/SaaS path views. |
| `sdwan.chassis_serial` / `sdwan.board_serial` | SD-WAN hardware identities. |
| `sdwan.device.type` / `sdwan.device.model` | SD-WAN device family and model. |
| `aci.node.id` | APIC node ID for ACI switches and controllers. |
| `aci.controller.name` | APIC controller name. |
| `aci.dn` / `aci.class` | ACI distinguished name and managed-object class. |
| `aci.resource.type` | Normalized ACI object family. |
| `aci.operation` | Bounded APIC endpoint family or evidence operation. |
| `fmc.controller.name` | FMC controller display name. |
| `fmc.domain.uuid` | FMC domain UUID used for `/api/fmc_config/v1/domain/{domainUUID}` requests. |
| `fmc.operation` | Bounded FMC endpoint family or evidence operation. |
| `fmc.resource.type` | Normalized FMC object type, such as device, interface, policy, deployment, HA, VPN, or audit record. |
| `fmc.object.id` / `fmc.group` | FMC managed-object ID and collection group. |
| `fmc.policy.id` / `fmc.policy.name` | FMC policy identity when applicable. |
| `cisco.device.serial` | Provider-reported Cisco device serial, including FMC-managed firewalls. |
| `ise.node.name` | ISE deployment node name. |
| `ise.network_device.name` | Network access device associated with authentication, session, or policy evidence. |
| `ise.endpoint.mac` | Endpoint MAC address used to correlate access, posture, and profiler evidence. |
| `ise.protocol` | Bounded access protocol such as RADIUS or TACACS. |
| `ise.endpoint` | Configured ISE API endpoint. |
| `cisco.os.name` | Direct telemetry OS name, such as `ios_xe` for Catalyst 9800 or `ios_xr` for IOS XR. |
| `cisco.platform.family` | Legacy shared-gNMI OS-family alias. Older direct Catalyst 9800 and IOS XR telemetry retains its existing platform-family values for compatibility. |
| `cisco.product.family` | Canonical product family for a live-verified shared-gNMI target. |
| `cisco.yang.path` | Original gNMI/MDT YANG path or encoding path. Direct gNMI decoding percent-encodes structural bytes such as `/`, `%`, `[`, `]`, and `=` inside individual path components so different wire paths remain distinct. |
| `cisco.yang.source_path` | Injective raw direct-gNMI or GPB-KV field path retained when a normalized metric name could otherwise conflate distinct YANG identifiers. Direct-gNMI JSON descendants use an unambiguous `rawGNMIPath#/JSON-pointer` boundary. Structured scalar paths retain their original form unless gNMI `Path.Target` is set; targeted paths use the injective `@target=<percent-encoded-target>@/rawGNMIPath` frame so identical paths from different targets remain distinct. |
| `cisco.yang.module` | Effective leaf YANG module encoded in the dynamic metric name, such as `wireless-access-point-oper`, `openconfig-interfaces`, or a Cisco native module. A module-qualified direct-JSON descendant updates this value from its parent module. |
| `cisco.telemetry.transport` | Direct telemetry direction, such as `gnmi_dial_in` or `mdt_grpc_dial_out`. |
| `cisco.wlc.ap.mac` | Catalyst 9800 AP radio/base MAC when present in the YANG key or JSON payload. |
| `cisco.wlc.ssid` | Catalyst 9800 SSID name when present. |
| `cisco.wlc.client.mac` | Catalyst 9800 client MAC when present. |
| `nexus_dashboard.operation` | Bounded Nexus Dashboard endpoint family or evidence operation. |
| `nexus_dashboard.product` / `nexus_dashboard.resource.type` | Nexus Dashboard application and object family. |
| `ndfc.switch.id` | NDFC switch database ID used by some NDFC interface/performance APIs. |
| `nd.service.name` | Nexus Dashboard service/app name. |

Unless a product-specific section says otherwise, controller state metrics use the shared numeric encoding: `1` for
healthy, online, reachable, or successful; `2` for informational, pending, or degraded; `3` for warning, minor, or
major; and `4` for critical, error, failed, or offline. Unknown source strings are retained as bounded attributes but
do not produce a numeric status datapoint.

For direct IOS XR and Catalyst 9800 JSON payloads, every multi-entry complex array is preflighted before child metrics
are emitted. Every entry must contribute a recognized identity, and those effective identities must be unique after the
receiver's key extraction rules. An ambiguous array is dropped as a unit rather than merging two device records into
one time series. Explicit empty identities remain distinct from missing identities.

## Quick Starting Set

For most users, start with these metrics before enabling the larger troubleshooting groups:

| Metric | Why start here |
| --- | --- |
| `cisco.device.up` | Confirms the receiver can reach the network device. |
| `system.uptime` | Shows whether the device recently rebooted. |
| `system.cpu.utilization` | Shows whether the device is overloaded. |
| `system.memory.utilization` | Shows whether the device is running out of memory. |
| `system.network.interface.status` | Shows whether important ports are up or down. |
| `system.network.io` | Shows how much traffic each port is carrying. |
| `cisco.interface.speed` | Gives a numeric line speed for capacity panels and utilization calculations. |
| `cisco.interface.utilization` | Shows how close each interface is to its reported line speed. |
| `system.network.errors` | Shows physical or link-layer problems on ports. |
| `system.network.packet.dropped` | Shows traffic the device could not forward. |
| `system.network.packet.count` | Shows packet volume by receive/transmit direction and, when available, packet type. |
| `cisco.interface.admin.status` | Shows whether a port is administratively enabled or intentionally disabled. |
| `cisco.scrape.partial_success` | Shows when the receiver reached a device but one or more command families failed. |
| `meraki.api.request.errors` | Shows Dashboard API request failures, including authorization, endpoint, or rate-limit issues. |
| `intersight.api.request.errors` | Shows Intersight API request failures, including signing, endpoint, permission, or rate-limit issues. |
| `intersight.alarm.count` | Shows active Intersight alarms grouped by severity, status, resource type, and acknowledgement state. |
| `intersight.task.status` | Shows failed or stalled Intersight workflow tasks that often explain recent operational changes. |
| `catalyst_center.api.request.errors` | Shows Catalyst Center API request failures, including authorization, endpoint, or rate-limit issues. |
| `catalyst_center.network.health.score` | Shows global Catalyst Center network health. |
| `catalyst_center.issue.active.count` | Shows active Catalyst Center Assurance issues grouped by severity, priority, status, category, and entity type. |
| `sdwan.api.request.errors` | Shows SD-WAN Manager API request failures, including authorization, endpoint, permission, or rate-limit issues. |
| `sdwan.control.connection.status` | Shows SD-WAN overlay control health. |
| `sdwan.bfd.session.status` | Shows SD-WAN tunnel/path session health. |
| `sdwan.app_route.latency` | Shows application-aware routing latency for SaaS, custom apps, and AI/model API paths. |
| `nexus_dashboard.resource.status` | Shows Nexus Dashboard, NDFC, Insights, Orchestrator, or Data Broker status with API context. |
| `nexus_dashboard.service.unavailable` | Shows an ND app/API endpoint that is unavailable, unauthorized, or not installed. |
| `aci.fault.count` | Shows active APIC faults grouped by severity, code, domain, and type. |
| `aci.tenant.status` | Shows tenant, VRF, bridge-domain, EPG, contract, and L3Out state from APIC. |
| `fmc.api.request.errors` | Shows FMC REST failures, including token, permission, endpoint, and rate-limit issues. |
| `fmc.deployment.status` | Shows deployment job, deployable-device, and pending-change state for managed firewalls. |
| `fmc.vpn.tunnel.status` | Shows site-to-site and remote-access VPN health where exposed by FMC. |
| `ise.api.request.errors` | Shows ISE REST/OpenAPI/ERS/MnT failures, including credential, permission, endpoint, and rate-limit issues. |
| `ise.radius.failure.count` | Shows RADIUS authentication failures by bounded protocol, outcome, failure, message, and policy context; user, endpoint, and network-device identities remain in logs. |
| `ise.session.active.count` | Shows the current active-session population reported by ISE. |
| `cisco.catalyst9800.receiver.decode_errors` | Shows Catalyst 9800 gNMI/gRPC decode failures. |
| `cisco.wlc.ap.join.status` | Shows whether APs are joined to the WLC. |
| `cisco.wlc.rf.channel.utilization` | Shows wireless channel utilization for RF congestion views. |
| `cisco.wlc.client.auth.failure.reason.info` | Shows client exclusion/auth failure reasons. |
| `cisco.iosxr.receiver.decode_errors` | Shows gNMI/MDT decode failures for IOS XR telemetry. |
| `cisco.iosxr.receiver.unsupported_paths` | Shows configured IOS XR paths pruned or rejected by capabilities. |
| `cisco.iosxr.receiver.reconnects` | Shows IOS XR gNMI reconnects. |

## Cost Controls For Splunk Observability Cloud

For the complete configuration workflow, examples, validation steps, and AI-agent checklist, see
[Controlling Metrics And Splunk Observability Cost](metric-control.md).

The receiver is intentionally configured by collection group first, then by metric name when a deployment needs a
smaller Splunk Observability footprint. Disable large endpoint families such as `sdwan.flows`,
`sdwan.policy_qos`, `intersight.telemetry`, `nexus_dashboard.performance`, or `aci.stats` unless those panels are
needed. Use each group's `max_results` and provider target filters to keep high-cardinality dimensions bounded.

For final per-metric control, set root-level `metrics.<metric_name-or-glob>.enabled: false`. Exact metric names
override matching globs, and the receiver removes matching metrics before they reach the downstream metrics pipeline:

```yaml
receivers:
  cisco_os:
    metrics:
      sdwan.app_route.loss:
        enabled: false
      system.network.errors:
        enabled: false
      cisco.wlc.client.*:
        enabled: false
      cisco.iosxr.yang.__v1.*:
        enabled: false
```

## Shared gNMI Normalized Profile Metrics

The product-qualified `gnmi.targets` catalog is deliberately narrower than the receiver's complete metric inventory:

| Products | Default normalized metrics |
| --- | --- |
| Catalyst 9800 | `cisco.device.up`, `system.cpu.utilization`, per-location `system.memory.utilization`, interface status, and cumulative interface counters |
| ASR 9000 and NCS 5500 | `cisco.device.up`, per-node `system.cpu.utilization`, interface status, and cumulative interface counters; no memory or uptime |
| Nexus 9000 and Nexus 3500 | `cisco.device.up`, interface status, and cumulative interface counters; no system profile |

Interface status is `system.network.interface.status` and `cisco.interface.admin.status`. Cumulative counters are
`system.network.io`, `system.network.errors`, `system.network.packet.count`, and
`system.network.packet.dropped`. Shared gNMI does not emit interface speed, rates, or utilization and does not emit
`system.uptime`.

## Shared gNMI Collector Self-Telemetry

The shared `gnmi.targets` path reports its own health through the Collector's internal telemetry endpoint. These are
not receiver-pipeline OTLP metrics: scrape or export Collector self-telemetry separately if they are needed in Splunk
Observability Cloud. Prometheus-style export exposes the `otelcol_`-prefixed names below.

| Metric | Type | Operational Use |
| --- | --- | --- |
| `otelcol_ciscoosreceiver_gnmi_connections` | Gauge | Current established gNMI connections by target. |
| `otelcol_ciscoosreceiver_gnmi_subscriptions` | Gauge | Active subscription streams by target and profile. |
| `otelcol_ciscoosreceiver_gnmi_updates` | Cumulative sum | Decoded leaf updates by target and profile. |
| `otelcol_ciscoosreceiver_gnmi_last_success_unixtime` | Gauge | Unix time of the most recent successfully decoded notification. |
| `otelcol_ciscoosreceiver_gnmi_preflight_failures` | Cumulative sum | Terminal qualification failures by target and bounded reason. |
| `otelcol_ciscoosreceiver_gnmi_product_verified` | Gauge | Whether the target passed product, model, release, and capability verification. |
| `otelcol_ciscoosreceiver_gnmi_reconnects` | Cumulative sum | Transport reconnect attempts by target. |
| `otelcol_ciscoosreceiver_gnmi_authentication_failures` | Cumulative sum | Authentication or authorization failures by target. |
| `otelcol_ciscoosreceiver_gnmi_decode_errors` | Cumulative sum | Decode failures by target and profile. |
| `otelcol_ciscoosreceiver_gnmi_consumer_refusals` | Cumulative sum | Downstream consumer refusals by target and profile. |
| `otelcol_ciscoosreceiver_gnmi_profile_degraded` | Gauge | Profile degradation state and bounded reason. |
| `otelcol_ciscoosreceiver_gnmi_unmapped_values` | Cumulative sum | Decoded values without an explicit stable metric mapping. |
| `otelcol_ciscoosreceiver_gnmi_deletes` | Cumulative sum | Delete paths applied to retained state. |
| `otelcol_ciscoosreceiver_gnmi_duplicate_updates` | Cumulative sum | Duplicate updates suppressed by retained state. |
| `otelcol_ciscoosreceiver_gnmi_invalid_timestamps` | Cumulative sum | Invalid device timestamps replaced with receipt time. |
| `otelcol_ciscoosreceiver_gnmi_cache_owner_resets` | Cumulative sum | Silent owner-scoped cache resets before an updates-only stream reconnects. |
| `otelcol_ciscoosreceiver_gnmi_unsupported_value_kinds` | Cumulative sum | Bounded opaque or aggregate typed values ignored by kind. |
| `otelcol_ciscoosreceiver_gnmi_cache_utilization` | Gauge | Maximum entry or byte utilization of the target's cache partition. |
| `otelcol_ciscoosreceiver_gnmi_auxiliary_state_utilization` | Gauge | Maximum entry or byte utilization of the target's auxiliary-state partition. |

Preflight-failure reasons are bounded to `identity_missing`, `identity_ambiguous`, `product_mismatch`,
`release_mismatch`, `missing_model`, `unsupported_encoding`, and `malformed_identity`. Compatibility failures
quarantine only the affected target until receiver restart; transport, authentication, and temporary RPC failures
remain retryable.

## Meraki API Metrics

Meraki support reuses existing Cisco metrics only when the Dashboard API has matching semantics, and emits
Meraki-specific gauges for cloud-only or windowed values.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `meraki.api.request.duration` | Gauge, double | `s` | Average duration of Dashboard API request attempts within the scrape for each matching request-attribute set. | Detect slow API responses or endpoint families that need tuning. |
| `meraki.api.request.errors` | Sum, int, cumulative | `{error}` | Dashboard API request failures. | Alert on broken credentials, endpoint failures, or repeated API errors. |
| `meraki.api.request.rate_limited` | Sum, int, cumulative | `{request}` | Requests that received HTTP 429. | Confirm the receiver is encountering Dashboard API rate limits. |
| `meraki.controller.up` | Gauge, int | `1` | Whether at least one Dashboard API request for the organization succeeded in the current scrape. | Distinguish an API outage from partial endpoint coverage. |
| `meraki.scrape.last_success` | Gauge, int | `s` | Unix timestamp of the most recent fully successful scrape for the organization. | Detect stale data without treating a partial scrape as fresh. |
| `meraki.device.status` | Gauge, int | `1` | Dashboard device status code with the original status as an attribute. | Distinguish online, alerting, dormant, and offline devices. |
| `meraki.uplink.status` | Gauge, int | `1` | WAN/uplink active state. | Alert on failed appliance uplinks. |
| `meraki.uplink.loss` | Gauge, double | `%` | Latest Dashboard uplink packet-loss sample. | Detect WAN degradation before a full outage. |
| `meraki.uplink.latency` | Gauge, double | `ms` | Latest Dashboard uplink latency sample. | Track WAN performance and ISP issues. |
| `meraki.switch.port.usage` | Gauge, double | `kBy` | Windowed switch port usage. | See recent port usage without treating it as a cumulative counter. |
| `meraki.switch.port.alert.active` | Gauge, int | `1` | Current port warning or error state by severity and reason. | Alert on persistent port faults without incrementing a synthetic counter on every poll. |
| `meraki.switch.port.poe.allocated` | Gauge, int | `1` | Whether Dashboard reports that PoE is allocated to the switch port. | Find access devices affected by missing port power. |
| `meraki.uplink.cellular.signal.rsrp` | Gauge, double | `dBm` | Cellular uplink reference-signal received power. | Detect weak LTE/5G backup coverage. |
| `meraki.uplink.cellular.signal.rsrq` | Gauge, double | `dB` | Cellular uplink reference-signal received quality. | Detect noisy or degraded cellular backup paths. |
| `meraki.wireless.client.count` | Gauge, int | `{client}` | Wireless client counts by status. | Monitor AP load and client connectivity. |
| `meraki.wireless.channel_utilization` | Gauge, double | `%` | Wi-Fi, non-Wi-Fi, and total channel utilization by band. | Find RF congestion. |
| `meraki.wireless.packet.count` | Gauge, int | `{packet}` | Windowed wireless packet count by direction. | Correlate client load with packet-volume changes. |
| `meraki.wireless.packet.loss` | Gauge, int | `{packet}` | Windowed wireless lost-packet count by direction. | Quantify RF or client-path loss. |
| `meraki.wireless.packet.loss_percentage` | Gauge, double | `%` | Wireless packet loss percentage by direction. | Detect poor wireless quality. |
| `meraki.wireless.ssid.status` | Gauge, int | `1` | Whether an SSID is enabled, advertised, and broadcasting on a BSS. | Catch unintended SSID outages. |
| `meraki.appliance.performance.score` | Gauge, double | `1` | Meraki appliance performance score. | Watch MX performance health. |
| `meraki.vpn.peer.status` | Gauge, int | `1` | Auto VPN or third-party VPN peer reachability. | Alert on VPN peer outages. |
| `meraki.vpn.peer.usage` | Gauge, int | `kBy` | Windowed VPN peer usage by direction. | Track VPN traffic volume. |
| `meraki.vpn.peer.latency` | Gauge, double | `ms` | Windowed VPN peer latency by sender and receiver uplink. | Detect slow tunnel paths. |
| `meraki.vpn.peer.loss` | Gauge, double | `%` | Windowed VPN peer loss by sender and receiver uplink. | Detect lossy tunnel paths. |
| `meraki.vpn.peer.jitter` | Gauge, double | `ms` | Windowed VPN peer jitter by sender and receiver uplink. | Detect unstable real-time application paths. |
| `meraki.vpn.peer.mos` | Gauge, double | `1` | Windowed VPN peer mean opinion score. | Track voice-quality degradation across VPN paths. |
| `meraki.power.module.status` | Gauge, int | `1` | Power module connection/powering status. | Detect PSU or power module failures. |

Meraki does not synthesize SSH-only parity gaps where the Dashboard API has no safe polling equivalent, including
`system.uptime`, `cisco.protocol.*`, control-plane process/CoPP/punt metrics, QFP dataplane drops, broad
route/FIB/adjacency counters, live routing-neighbor state, NX-OS NVE/EVPN fabric metrics, vPC, LACP counters, and
detailed QoS queue/policy counters.

## Intersight API Metrics And Logs

Intersight support is intentionally curated around troubleshooting domains instead of arbitrary poller definitions.
Metrics use bounded dimensions for health and counts. Detailed event evidence is emitted as logs so high-cardinality
fields such as descriptions, affected object names, failure reasons, and audit payloads do not become metric labels.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `intersight.api.request.duration` | Gauge, double | `s` | Average duration of Intersight API request attempts within the scrape for each matching request-attribute set. | Detect slow API responses, permission gaps, or endpoint families that need tuning. |
| `intersight.api.request.errors` | Sum, int, cumulative | `{error}` | Intersight API request failures. | Alert on broken credentials, signing failures, endpoint errors, or repeated API failures. |
| `intersight.api.rate_limited` | Sum, int, cumulative | `{request}` | Requests that received HTTP 429. | Confirm the receiver is hitting Intersight rate limits. |
| `intersight.scrape.partial_success` | Gauge, int | `1` | Whether one or more Intersight endpoint families failed during a scrape. | Keep dashboards honest when part of the API surface is unavailable. |
| `intersight.scrape.last_success` | Gauge, int | `s` | Unix timestamp of the most recent fully successful Intersight scrape. | Detect stale or persistently partial Intersight data. |
| `intersight.telemetry.query.rows` | Gauge, int | `{row}` | Per-query telemetry rows classified by the bounded `intersight.telemetry.outcome` attribute as emitted, capped, filtered, sparse, invalid, or malformed. | Prove GroupBy coverage and distinguish expected sparse data from selection, cap, or payload-shape loss. |
| `intersight.resource.info` | Gauge, int | `1` | Inventory metadata for an Intersight resource. | Build inventory and drilldown pages without making status labels too broad. |
| `intersight.resource.status` | Gauge, int | `1` | Encoded resource status, with the original status retained as an attribute. | Standardize online, healthy, degraded, failed, and unknown state across object families. |
| `intersight.resource.count` | Gauge, int | `1` | Resource count grouped by type, status, and severity. | Track fleet composition and health by domain. |
| `intersight.alarm.active` | Gauge, int | `1` | Active alarm instances. | Page or triage critical UCS, fabric, storage, or platform alarms. |
| `intersight.alarm.count` | Gauge, int | `1` | Active alarm counts by bounded attributes. | Create severity and acknowledgement rollups. |
| `intersight.advisory.active` | Gauge, int | `1` | Active advisory or security advisory exposure. | Identify assets exposed to known field notices or security advisories. |
| `intersight.hcl.status` | Gauge, int | `1` | Hardware compatibility/compliance status. | Catch unsupported combinations before maintenance or upgrades. |
| `intersight.hcl.status.count` | Gauge, int | `1` | HCL/compliance records grouped by bounded status and resource attributes. | Track compatibility coverage and drift. |
| `intersight.workflow.status` | Gauge, int | `1` | Workflow execution status. | Detect failed upgrades, deployments, or policy actions. |
| `intersight.workflow.count` | Gauge, int | `1` | Workflow records grouped by bounded status attributes. | Quantify workflow failures or backlogs. |
| `intersight.task.status` | Gauge, int | `1` | Workflow task execution status. | Find the specific failed step behind a workflow problem. |
| `intersight.task.count` | Gauge, int | `1` | Workflow task records grouped by bounded status attributes. | Quantify failed or stalled workflow steps. |
| `intersight.techsupport.status` | Gauge, int | `1` | Tech-support collection/upload status. | Track evidence bundle creation for support cases. |
| `intersight.techsupport.count` | Gauge, int | `1` | Tech-support jobs grouped by bounded status attributes. | Quantify support-bundle failures or backlog. |
| `intersight.audit.record.count` | Gauge, int | `1` | Recent audit/config-change records by user. | Correlate configuration changes with incidents. |
| `intersight.firmware.bundle.info` | Gauge, int | `1` | Firmware bundle identity with the version in `intersight.firmware.version`. | Find firmware drift without encoding arbitrary version strings as status codes. |
| `intersight.target.connection_status` | Gauge, int | `1` | Target connection state reported by Intersight. | Detect disconnected targets and device connector issues. |
| `intersight.compute.available_memory` | Gauge, int | `MBy` | Available server memory reported by Intersight. | Spot capacity constraints on managed compute. |
| `system.cpu.logical.count` | Gauge, int | `{cpu}` | CPU core count reported by Intersight. | Inventory logical compute capacity. |
| `intersight.compute.thread.count` | Gauge, int | `{thread}` | CPU thread count reported by Intersight. | Inventory compute capacity. |
| `intersight.fault.count` | Gauge, int | `{fault}` | Fault summary values from compute or HyperFlex objects. | Highlight objects carrying summarized faults. |
| `intersight.storage.media_error.count` | Gauge, int | `{error}` | Media errors reported by storage disks. | Detect disk degradation. |
| `intersight.storage.predictive_failure.count` | Gauge, int | `{failure}` | Predictive failure count for storage media. | Alert before disk failure causes impact. |
| `intersight.storage.life_left` | Gauge, int | `%` | Remaining storage media life. | Plan SSD replacement. |
| `intersight.storage.temperature` | Gauge, int | `Cel` | Storage device temperature. | Detect thermal issues in drive bays. |
| `intersight.storage.power_on.hours` | Gauge, int | `h` | Storage device power-on hours. | Track aged disks during replacement planning. |
| `intersight.storage.rebuild.rate` | Gauge, int | `%` | Storage controller rebuild progress/rate. | Follow rebuild activity during degraded storage events. |
| `intersight.storage.status` | Gauge, int | `1` | Encoded storage controller, disk, or virtual-drive state. | Find unhealthy storage resources quickly. |
| `intersight.hyperflex.status` | Gauge, int | `1` | Encoded HyperFlex cluster or node state. | Detect unhealthy HyperFlex clusters or nodes. |
| `intersight.kubernetes.cluster.connection_status` | Gauge, int | `1` | Encoded Kubernetes target connection state. | Detect disconnected IKS or Kubernetes targets. |
| `intersight.virtual_machine.count` | Gauge, int | `{vm}` | Virtual machine count on HyperFlex clusters. | Track workload concentration on clusters. |
| `intersight.virtual_machine.cpu.count` | Gauge, int | `{cpu}` | vCPU count for a VM. | Correlate VM sizing with host and cluster health. |
| `intersight.virtual_machine.memory` | Gauge, int | `MBy` | VM configured memory. | Correlate VM sizing with memory pressure. |
| `intersight.virtual_machine.power_state` | Gauge, int | `1` | Encoded VM power state. | Spot powered-off or unexpectedly running VMs. |
| `intersight.ucs.fan.speed` | Gauge, double | `rpm` | Mean fan speed from Intersight telemetry GroupBy. | Detect cooling issues and fan anomalies. |
| `intersight.ucs.fan.speed_ratio` | Gauge, double | `%` | Mean fan speed as a percentage of maximum. | Identify abnormal fan duty cycles. |
| `intersight.ucs.host.power` | Gauge, double | `W` | Mean host power from Intersight telemetry GroupBy. | Watch power draw and capacity. |
| `intersight.ucs.host.energy` | Gauge, double | `J` | Host energy consumption from Intersight telemetry. | Track energy use across managed hosts. |
| `intersight.ucs.host.power_state` | Gauge, double | `1` | Encoded host power state from telemetry. | Identify hosts that were on or off during the interval. |
| `intersight.ucs.temperature` | Gauge, double | `Cel` | Mean temperature from Intersight telemetry GroupBy. | Detect thermal problems. |
| `intersight.ucs.temperature.limit_high_critical` | Gauge, double | `Cel` | High critical temperature threshold. | Compare sensor values to hardware thresholds. |
| `intersight.ucs.temperature.limit_low_critical` | Gauge, double | `Cel` | Low critical temperature threshold. | Detect sensor readings outside supported ranges. |
| `intersight.ucs.voltage` | Gauge, double | `V` | Mean voltage from Intersight telemetry GroupBy. | Catch power-supply or sensor anomalies. |
| `intersight.ucs.current` | Gauge, double | `A` | Mean current from Intersight telemetry GroupBy. | Detect electrical or transceiver bias anomalies. |
| `intersight.ucs.cpu.system.utilization` | Gauge, double | `1` | System CPU utilization from Intersight telemetry. | Separate OS/kernel pressure from user workload pressure. |
| `intersight.ucs.cpu.idle.utilization` | Gauge, double | `1` | Idle CPU utilization from Intersight telemetry. | Confirm spare CPU headroom. |
| `intersight.ucs.memory.used` | Gauge, double | `By` | Used system memory from Intersight telemetry. | Correlate memory pressure with workload symptoms. |
| `intersight.ucs.memory.free` | Gauge, double | `By` | Free system memory from Intersight telemetry. | Confirm available memory headroom. |
| `intersight.ucs.memory.cached` | Gauge, double | `By` | Cached system memory from Intersight telemetry. | Understand host memory composition. |
| `intersight.ucs.memory.module.size` | Gauge, double | `By` | Memory module size from Intersight telemetry. | Inventory DIMM capacity by host. |
| `intersight.ucs.memory.ecc.correctable` | Gauge, double | `{error}` | Correctable memory ECC errors. | Catch DIMMs that are beginning to degrade. |
| `intersight.ucs.memory.ecc.uncorrectable` | Gauge, double | `{error}` | Uncorrectable memory ECC errors. | Alert on severe memory faults. |
| `intersight.ucs.network.receive` | Gauge, double | `By` | Network receive volume from Intersight telemetry. | Correlate host traffic with fabric and workload symptoms. |
| `intersight.ucs.network.transmit` | Gauge, double | `By` | Network transmit volume from Intersight telemetry. | Correlate host traffic with fabric and workload symptoms. |
| `intersight.ucs.network.receive.errors` | Gauge, double | `{error}` | Receive errors from Intersight telemetry. | Find NIC, fabric, or cable issues. |
| `intersight.ucs.network.transmit.errors` | Gauge, double | `{error}` | Transmit errors from Intersight telemetry. | Find NIC, fabric, or cable issues. |
| `intersight.ucs.network.receive.crc_errors` | Gauge, double | `{error}` | Receive CRC errors from Intersight telemetry. | Detect physical path, transceiver, or cabling faults. |
| `intersight.ucs.network.receive.discards` | Gauge, double | `{discard}` | Receive discards from Intersight telemetry. | Find drops before they become workload-visible packet loss. |
| `intersight.ucs.network.receive.no_buffer` | Gauge, double | `{error}` | Receive no-buffer errors from Intersight telemetry. | Detect buffer pressure near affected workloads. |
| `intersight.ucs.network.receive.drops` | Gauge, double | `{drop}` | Receive drops from Intersight telemetry. | Detect ingress drops near affected workloads. |
| `intersight.ucs.network.transmit.discards` | Gauge, double | `{discard}` | Transmit discards from Intersight telemetry. | Detect egress discard conditions. |
| `intersight.ucs.network.receive.packets` | Gauge, double | `{packet}` | Receive packet volume from Intersight telemetry. | Correlate packet rate with host and fabric symptoms. |
| `intersight.ucs.network.transmit.packets` | Gauge, double | `{packet}` | Transmit packet volume from Intersight telemetry. | Correlate packet rate with host and fabric symptoms. |
| `intersight.ucs.network.receive.pause_frames` | Gauge, double | `{frame}` | Receive pause frames from Intersight telemetry. | Diagnose congestion and flow-control symptoms. |
| `intersight.ucs.network.transmit.pause_frames` | Gauge, double | `{frame}` | Transmit pause frames from Intersight telemetry. | Diagnose congestion and flow-control symptoms. |
| `intersight.ucs.network.transmit.drops` | Gauge, double | `{drop}` | Transmit drops from Intersight telemetry. | Detect egress drops near affected workloads. |
| `intersight.ucs.network.utilization` | Gauge, double | `%` | Network bandwidth utilization. | Find saturated host or fabric interfaces. |
| `intersight.ucs.network.speed` | Gauge, double | `By/s` | Operational link speed. | Detect link speed mismatches. |
| `intersight.ucs.network.link.status` | Gauge, double | `1` | Network link status from Intersight telemetry. | Find links that went down during an incident window. |
| `intersight.ucs.network.link_failures` | Gauge, double | `{failure}` | Link failure counters from Intersight telemetry. | Detect unstable physical or fabric links. |
| `intersight.ucs.network.signal_losses` | Gauge, double | `{error}` | Signal-loss counters from Intersight telemetry. | Identify optical or physical-layer problems. |
| `intersight.ucs.network.interface_resets` | Gauge, double | `{reset}` | Interface reset counters from Intersight telemetry. | Correlate reset storms with workload impact. |
| `intersight.ucs.power_supply.output_power` | Gauge, double | `W` | PSU output power. | Detect power delivery imbalance or capacity issues. |
| `intersight.ucs.power_supply.utilization` | Gauge, double | `%` | PSU utilization. | Track PSU load against limits. |
| `intersight.ucs.power_supply.status` | Gauge, double | `1` | PSU operational status from Intersight telemetry. | Identify failed or unhealthy power supplies. |
| `intersight.ucs.fan.status` | Gauge, double | `1` | Fan operational status from Intersight telemetry. | Identify failed or unhealthy fans. |
| `intersight.ucs.memory.status` | Gauge, double | `1` | Memory module operational status from Intersight telemetry. | Identify unhealthy DIMMs. |
| `intersight.ucs.temperature.status` | Gauge, double | `1` | Temperature sensor operational status from Intersight telemetry. | Identify unhealthy thermal sensors. |
| `intersight.ucs.signal_power.receive` | Gauge, double | `dBm` | Transceiver receive optical power. | Detect weak or dirty optical paths. |
| `intersight.ucs.signal_power.transmit` | Gauge, double | `dBm` | Transceiver transmit optical power. | Detect transceiver or fiber degradation. |
| `intersight.hyperflex.read.iops` | Gauge, double | `{operation}/s` | HyperFlex read IOPS. | Detect storage load and imbalance. |
| `intersight.hyperflex.write.iops` | Gauge, double | `{operation}/s` | HyperFlex write IOPS. | Detect storage load and imbalance. |
| `intersight.hyperflex.read.latency` | Gauge, double | `ms` | HyperFlex read latency. | Alert on storage latency. |
| `intersight.hyperflex.write.latency` | Gauge, double | `ms` | HyperFlex write latency. | Alert on storage latency. |

Intersight logs are emitted for audit/config changes, alarms, advisories, workflow/task failures, and tech-support
status transitions. Every record includes `event.domain=intersight`, `event.name`, `intersight.operation`,
`intersight.status`, `intersight.severity`, and correlation attributes such as `host.id`, `intersight.moid`,
`intersight.affected_moid`, and `user.email` when present.

## Catalyst Center Metrics

Catalyst Center support polls read-only Assurance, inventory, topology, issue, device-detail, and client-detail APIs.
The broad collection groups keep metrics bounded around fleet health and counts. Device-detail and client-detail
metrics are intentionally target-scoped so investigations can add known affected devices or client MAC addresses
without turning every endpoint into a high-cardinality metric series.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `catalyst_center.api.request.duration` | Gauge, double | `s` | Average duration of Catalyst Center API request attempts within the scrape for each matching request-attribute set. | Detect slow Assurance APIs, auth problems, and endpoint failures. |
| `catalyst_center.api.request.errors` | Sum, int, cumulative | `{error}` | Catalyst Center API request failures. | Alert on broken credentials, permission gaps, rate limits, or repeated API failures. |
| `catalyst_center.api.rate_limited` | Sum, int, cumulative | `{request}` | Requests that received HTTP 429. | Confirm polling pressure against Catalyst Center. |
| `catalyst_center.scrape.partial_success` | Gauge, int | `1` | Whether one or more Catalyst Center endpoint families failed during a scrape. | Keep dashboards honest when only part of Assurance data was collected. |
| `catalyst_center.scrape.last_success` | Gauge, int | `s` | Unix timestamp of the most recent fully successful Catalyst Center scrape. | Detect stale or persistently partial Catalyst Center data. |
| `catalyst_center.inventory.device.count` | Gauge, int | `{device}` | Network-device inventory count. | Detect inventory scope, permission, or collection changes. |
| `catalyst_center.device.reachability.status` | Gauge, int | `1` | Encoded device reachability status with the original status retained as an attribute. | Find unreachable or partially reachable devices quickly. |
| `catalyst_center.device.collection.status` | Gauge, int | `1` | Encoded Catalyst Center collection status. | Separate device outages from managed/unmanaged or collection-state problems. |
| `catalyst_center.device.interface.count` | Gauge, int | `{interface}` | Interface count reported for a device. | Detect inventory churn, replacement, or collection gaps. |
| `catalyst_center.device.uptime` | Gauge, int | `s` | Device uptime reported by Catalyst Center. | Correlate site incidents with reloads or replacements. |
| `catalyst_center.interface.count` | Gauge, int | `{interface}` | Interface inventory count. | Track interface collection coverage. |
| `catalyst_center.network.health.score` | Gauge, int | `1` | Latest global Catalyst Center network health score. | Detect broad campus health degradation. |
| `catalyst_center.network.device.count` | Gauge, int | `{device}` | Network device count by health state. | Watch healthy, unhealthy, fair, unmonitored, or no-health populations. |
| `catalyst_center.network.health.entity.score` | Gauge, int | `1` | Network health score by Assurance entity. | Identify whether access, wireless, or another entity is driving health degradation. |
| `catalyst_center.network.health.entity.count` | Gauge, int | `{device}` | Entity count by health state. | See how many devices moved into good, fair, bad, or unknown states. |
| `catalyst_center.network.health.category.score` | Gauge, double | `1` | Network health score by device category. | Distinguish switching, routing, wireless, or other category impact. |
| `catalyst_center.client.health.score` | Gauge, double | `1` | Client health score by site and score category. | Detect wired or wireless client-experience degradation. |
| `catalyst_center.client.count` | Gauge, int | `{client}` | Client count by health category. | Measure client population affected by health changes. |
| `catalyst_center.client.unique.count` | Gauge, int | `{client}` | Unique client count by health category. | Separate broad endpoint impact from repeated sessions. |
| `catalyst_center.site.network_device.health.percentage` | Gauge, double | `%` | Percent of healthy network devices by site. | Find affected campuses, buildings, or floors. |
| `catalyst_center.site.client.health.percentage` | Gauge, double | `%` | Percent of healthy clients by site. | Identify client-facing site impact. |
| `catalyst_center.site.health.count` | Gauge, int | `{item}` | Site health counts for devices, clients, wireless, APs, WLCs, switches, routers, and issues. | Explain whether a site problem is device-heavy, client-heavy, wireless-heavy, or issue-heavy. |
| `catalyst_center.site.issue.count` | Gauge, int | `{issue}` | Site issue counts by priority. | Weight site health by P1/P2 impact instead of percentage alone. |
| `catalyst_center.site.client.count` | Gauge, int | `{client}` | Site client population by client type and health state. | Show how many users are represented by a degraded site score. |
| `catalyst_center.site.network_device.count` | Gauge, int | `{device}` | Site network-device population by role and health state. | Show which access, core, distribution, router, wireless, AP, WLC, or switch populations are affected. |
| `catalyst_center.topology.node.count` | Gauge, int | `{node}` | Physical topology node count globally and by node attributes. | Detect topology discovery, permission, or inventory shifts. |
| `catalyst_center.topology.link.count` | Gauge, int | `{link}` | Physical topology link count globally and by link status. | Detect missing, failed, or changed topology links. |
| `catalyst_center.issue.count` | Gauge, int | `{issue}` | Assurance issue count in the configured lookback window. | Track issue volume around incidents. |
| `catalyst_center.issue.active.count` | Gauge, int | `{item}` | Active Assurance issues grouped by severity, priority, status, category, entity type, and site. | Prioritize critical campus issues without putting issue text in metric labels. |
| `catalyst_center.device.detail.health.score` | Gauge, double | `1` | Targeted device-detail health score. | Correlate a known device with local health evidence. |
| `catalyst_center.device.detail.communication.status` | Gauge, int | `1` | Targeted device communication status. | Explain stale or missing detail data for an affected device. |
| `catalyst_center.client.detail.health.score` | Gauge, double | `1` | Targeted client-detail health score by client, health type, and reason. | Troubleshoot a known affected client MAC address. |
| `catalyst_center.client.issue.count` | Gauge, int | `{issue}` | Issue count for a targeted client detail lookup. | Confirm whether Catalyst Center has client-specific issue evidence. |
| `catalyst_center.client.wireless.rssi` | Gauge, double | `dBm` | RSSI for a targeted wireless client. | Diagnose weak RF or roaming symptoms. |
| `catalyst_center.client.wireless.snr` | Gauge, double | `dB` | SNR for a targeted wireless client. | Diagnose interference or poor wireless quality. |
| `catalyst_center.client.network.io` | Gauge, double | `By` | Client transmit and receive bytes. | Correlate client traffic silence or spikes with access symptoms. |

Catalyst Center also reuses common Cisco and OpenTelemetry metrics when the Assurance API has matching semantics,
including `cisco.device.up`, `system.network.interface.status`, `cisco.interface.admin.status`,
`cisco.interface.speed`, `system.cpu.utilization`, and `system.memory.utilization`.

## Catalyst SD-WAN Metrics And Logs

Catalyst SD-WAN support polls read-only SD-WAN Manager APIs. Default groups avoid the highest-cardinality feature
areas, but their per-device request volume must still be qualified against the selected fleet size and scrape timeout.
Realtime and high-cardinality feature areas are opt-in and report `sdwan.service.unavailable` or
`sdwan.service.skipped` when a feature, license, target filter, or endpoint is not available.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `sdwan.api.request.duration` | Gauge, double | `s` | Average duration of SD-WAN Manager API request attempts within the scrape for each matching request-attribute set. | Detect slow Manager APIs before trusting SD-WAN telemetry. |
| `sdwan.api.request.errors` | Sum, int, cumulative | `{error}` | API, auth, permission, timeout, or decode failures. | Alert on broken credentials, role gaps, endpoint failures, or rate limits. |
| `sdwan.api.rate_limited` | Sum, int, cumulative | `{request}` | Requests that received HTTP 429. | Confirm the receiver is hitting SD-WAN Manager rate limits. |
| `sdwan.scrape.partial_success` | Gauge, int | `1` | Whether one or more SD-WAN endpoint families failed or were skipped. | Keep dashboards honest when only part of SD-WAN data was collected. |
| `sdwan.scrape.last_success` | Gauge, int | `s` | Unix timestamp of the most recent fully successful SD-WAN scrape. | Detect stale or persistently partial SD-WAN data. |
| `sdwan.service.unavailable` | Gauge, int | `1` | Feature or endpoint was unavailable, unauthorized, unsupported, or missing. | Distinguish real network symptoms from API/product coverage gaps. |
| `sdwan.service.skipped` | Gauge, int | `1` | Feature or endpoint was skipped because target scope was missing. | Show when opt-in incident groups need filters or supported targets. |
| `sdwan.manager.up` | Gauge, int | `1` | Whether at least one SD-WAN Manager API operation succeeded in the scrape. | Separate Manager/API availability from partial endpoint failures. |
| `sdwan.manager.endpoint.status` | Gauge, int | `1` | Whether a Manager endpoint family returned data. | Find missing Manager API families before trusting dependent panels. |
| `sdwan.manager.health.score` | Gauge, double | `1` | Manager cluster or resource health value where exposed. | Detect Manager-side degradation. |
| `sdwan.manager.status` | Gauge, int | `1` | Encoded SD-WAN Manager status. | Detect Manager or cluster health degradation. |
| `sdwan.inventory.device.count` | Gauge, int | `{device}` | Device inventory count after target and shared selection. | Detect device scope, permission, or inventory changes. |
| `sdwan.resource.info` | Gauge, int | `1` | Stable SD-WAN resource identity. | Build inventory and drilldown pages. |
| `sdwan.resource.status` | Gauge, int | `1` | Encoded SD-WAN resource or opt-in object status. | Find unhealthy devices, tunnels, service objects, or feature resources. |
| `sdwan.device.reachability.status` | Gauge, int | `1` | Encoded SD-WAN device reachability. | Separate down WAN Edge devices from controller/API failures. |
| `sdwan.device.validity.status` | Gauge, int | `1` | Encoded device validity state. | Catch validity/certificate lifecycle issues before path failures. |
| `sdwan.device.certificate.status` | Gauge, int | `1` | Encoded certificate validity state. | Detect expired or invalid device certificates. |
| `sdwan.control.connection.status` | Gauge, int | `1` | Encoded control connection status. | Detect overlay control-plane failures. |
| `sdwan.control.connection.count` | Gauge, int | `{item}` | Control connection count grouped by status and path attributes. | Show expected versus degraded control-plane coverage. |
| `sdwan.control.expected_connections` | Gauge, int | `{connection}` | Expected control connections when exposed. | Compare desired overlay state with actual state. |
| `sdwan.control.actual_connections` | Gauge, int | `{connection}` | Actual control connections when exposed. | Detect missing vSmart/controller sessions. |
| `sdwan.bfd.session.status` | Gauge, int | `1` | Encoded BFD session status. | Find partial site or transport failure even when control plane is up. |
| `sdwan.bfd.session.count` | Gauge, int | `{item}` | BFD session count grouped by status and path attributes. | Spot site-wide or color-specific tunnel loss. |
| `sdwan.bfd.session.transitions` | Sum, int, cumulative | `{transition}` | BFD session transition count. | Detect flapping tunnels. |
| `sdwan.bfd.session.flap.count` | Sum, int, cumulative | `{flap}` | BFD flap count where exposed. | Correlate instability with incident windows. |
| `sdwan.app_route.latency` | Gauge, double | `ms` | Application-aware routing latency. | Troubleshoot SaaS, AI/model API, and custom app path quality. |
| `sdwan.app_route.jitter` | Gauge, double | `ms` | Application-aware routing jitter. | Find unstable paths for latency-sensitive applications. |
| `sdwan.app_route.loss` | Gauge, double | `%` | Application-aware routing loss. | Detect WAN path degradation. |
| `sdwan.app_route.sla.status` | Gauge, int | `1` | Encoded app-route SLA state. | Show whether an app path is inside policy. |
| `sdwan.transport.interface.status` | Gauge, int | `1` | SD-WAN transport or service interface state. | Find down WAN circuits or service interfaces. |
| `sdwan.collection.object.count` | Gauge, int | `{item}` | Object count from opt-in product feature groups. | Validate full product coverage without high-cardinality labels. |
| `sdwan.event.count` | Gauge, int | `{item}` | Alarm, event, and audit counts grouped by bounded attributes. | Correlate incidents with alarms, config changes, deployments, or security events. |

SD-WAN also reuses common Cisco and OpenTelemetry metrics where semantics match: `cisco.device.up`,
`system.cpu.utilization`, `system.memory.utilization`, `system.uptime`, `system.network.interface.status`,
`system.network.io`, `system.network.packet.count`, `system.network.errors`, `system.network.packet.dropped`,
`cisco.interface.admin.status`, and `cisco.interface.speed`.

SD-WAN logs are emitted for alarms, events, and audit records. The original API object is preserved in the log body,
while bounded attributes such as `event.domain=sdwan`, `event.name`, `sdwan.severity`, `sdwan.status`,
`sdwan.system_ip`, `sdwan.site.id`, `sdwan.uuid`, `sdwan.policy.name`, `user.name`, and `user.email` support incident
correlation without turning event text into metric dimensions.

## Nexus Dashboard, NDFC, Insights, Orchestrator, And Data Broker Metrics And Logs

Nexus Dashboard support is API-first and switch-centered. With `api_profile: legacy`, NDFC, Insights, Orchestrator,
and Data Broker objects are correlated back to Nexus switch identity with serial, switch ID, fabric, site, role,
interface, service, and controller endpoint attributes whenever the API response exposes them. Missing or disabled
legacy-profile apps do not fail the whole scrape: the receiver emits partial-success and unavailable-service metrics
so dashboards can distinguish fabric problems from management-plane coverage gaps. The `unified` profile currently
polls only the verified platform and Manage metric routes. Its nested hardware and summary payloads provide API health
and generic resource-presence evidence; their numeric values are not yet mapped into dedicated telemetry.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `nexus_dashboard.api.request.duration` | Gauge, double | `s` | Average duration of Nexus Dashboard API request attempts within the scrape for each matching request-attribute set. | Detect slow or failing controller APIs before trusting fabric data. |
| `nexus_dashboard.api.request.errors` | Sum, int, cumulative | `{error}` | Nexus Dashboard API request failures. | Alert on broken credentials, permission gaps, rate limits, or app/API failures. |
| `nexus_dashboard.api.endpoint.error` | Sum, int, cumulative | `{error}` | Endpoint-family scrape failures. | Identify the failed ND app or endpoint while preserving other results. |
| `nexus_dashboard.api.rate_limited` | Sum, int, cumulative | `{request}` | Requests that received HTTP 429. | Detect polling pressure against the controller. |
| `nexus_dashboard.scrape.partial_success` | Gauge, int | `1` | Whether one or more endpoint families failed or were skipped. | Keep dashboards honest when an ND service is absent or a target filter is missing. |
| `nexus_dashboard.scrape.last_success` | Gauge, int | `s` | Unix timestamp of the most recent fully successful Nexus Dashboard scrape. | Detect stale or persistently partial controller data. |
| `nexus_dashboard.service.unavailable` | Gauge, int | `1` | ND service endpoint unavailable, disabled, unauthorized, or not installed. | Explain why Insights, NDFC, NDO, or Data Broker charts are empty. |
| `nexus_dashboard.service.skipped` | Gauge, int | `1` | ND endpoint family skipped because target scope was not configured. | Distinguish an intentional scope gap from an app outage. |
| `nexus_dashboard.service.health` | Gauge, int | `1` | Encoded Nexus Dashboard service health. | Find degraded platform or application services. |
| `nexus_dashboard.resource.info` | Gauge, int | `1` | Bounded metadata for controller resources. | Build inventory and troubleshooting drilldowns. |
| `nexus_dashboard.resource.status` | Gauge, int | `1` | Encoded status with the original status string retained as an attribute. | Normalize healthy, degraded, failed, and unknown states across ND services. |
| `nexus_dashboard.resource.count` | Gauge, int | `1` | Controller resources grouped by bounded product, group, type, status, and severity. | Track object coverage and unexpected inventory changes. |
| `nexus_dashboard.audit.record.count` | Gauge, int | `1` | Recent Nexus Dashboard audit records by bounded product, operation, status, and severity attributes. | Correlate controller-side changes with fabric incidents without high-cardinality labels. |
| `nexus_dashboard.event.count` | Gauge, int | `1` | Recent events, anomalies, advisories, alerts, and root causes by bounded product, operation, status, and severity attributes. | Surface change and incident evidence as dashboard-friendly counts. |
| `nexus_dashboard.fabric.health` | Gauge, double | `1` | NDFC fabric, switch, or site health score when exposed by the API. | Find unhealthy fabrics before drilling into switches and interfaces. |
| `nexus_dashboard.config.compliance` | Gauge, double | `1` | NDFC configuration compliance score. | Detect drift between intended and deployed fabric configuration. |
| `nexus_dashboard.deployment.status` | Gauge, int | `1` | NDFC deployment, image, or change-control state. | Correlate incidents to pushes, failed deploys, or image activity. |
| `nexus_dashboard.endpoint.count` | Gauge, double | `{endpoint}` | Endpoint counts reported by NDFC. | Spot endpoint churn, disappearance, or unexpected growth. |
| `nexus_dashboard.insights.anomaly.active` | Gauge, int | `1` | Active Insights anomaly or advisory. | Bring root-cause and anomaly evidence into incident triage. |
| `nexus_dashboard.insights.anomaly.count` | Gauge, int | `1` | Insights anomaly/advisory count by severity and category. | Track fabric risk and anomaly volume without high-cardinality labels. |
| `nexus_dashboard.insights.score` | Gauge, double | `1` | Insights site, fabric, anomaly, advisory, or recommendation score. | Prioritize unhealthy sites/fabrics. |
| `nexus_dashboard.insights.confidence` | Gauge, double | `1` | Root-cause confidence where exposed by Insights. | Prefer high-confidence evidence during autopsy. |
| `nexus_dashboard.insights.status` | Gauge, int | `1` | Encoded Insights anomaly, advisory, or recommendation status. | Find active or unresolved Insights evidence. |
| `nexus_dashboard.orchestrator.deployment.status` | Gauge, int | `1` | NDO/OneManage deployment, schema, template, or site-sync status. | Detect multi-site policy drift or failed rollout state. |
| `nexus_dashboard.orchestrator.deployment.count` | Gauge, double | `{deployment}` | NDO/OneManage deployments grouped by bounded status attributes. | Quantify failed or pending multi-site changes. |
| `nexus_dashboard.orchestrator.policy_delta.count` | Gauge, double | `{delta}` | Policy delta count reported by NDO/OneManage. | Identify undeployed or divergent policy. |
| `nexus_dashboard.data_broker.status` | Gauge, int | `1` | Data Broker broker, TAP, SPAN, rule, filter, or session status. | Keep packet visibility paths observable during troubleshooting. |
| `nexus_dashboard.data_broker.rule.count` | Gauge, double | `{rule}` | Data Broker rule count. | Track visibility rule drift or unexpected rule removal. |
| `nexus_dashboard.data_broker.session.count` | Gauge, double | `{session}` | Data Broker session count. | Confirm visibility sessions exist when packet captures are expected. |
| `nexus_dashboard.storage.utilization` | Gauge, double | `1` | Nexus Dashboard storage utilization as a ratio. | Detect platform storage pressure before services degrade. |
| `nexus_dashboard.vpc.peer.count` | Gauge, double | `{peer}` | vPC peer count reported by NDFC. | Detect missing redundant peers from the controller view. |

With `api_profile: legacy`, Nexus Dashboard logs are emitted for NDFC audits/events, Insights
anomalies/advisories/root-cause evidence, NDO audit/deployment records, and Data Broker events. Every record includes
`event.domain=nexus_dashboard`, `event.name`, `nexus_dashboard.group`, `nexus_dashboard.status`,
`nexus_dashboard.severity`, and bounded correlation attributes such as `host.id`, `cisco.switch.serial`,
`ndfc.switch.id`, `cisco.fabric.name`, `cisco.site.name`, and `user.name` when present. The `unified` profile does not
register log endpoints until current audit/event routes are verified.

## Cisco ACI/APIC Metrics And Logs

ACI support polls APIC class endpoints directly. This provides controller-side troubleshooting even when SSH to every
ACI leaf/spine is not practical. Metrics stay bounded around health, state, counts, endpoint presence, interface
symptoms, and audit/event rollups; high-cardinality fault, audit, and event evidence can be emitted through explicit
signal-specific log opt-ins.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `aci.api.request.duration` | Gauge, double | `s` | Average duration of APIC API request attempts within the scrape for each matching request-attribute set. | Detect slow APICs, auth problems, and API endpoint failures. |
| `aci.api.request.errors` | Sum, int, cumulative | `{error}` | APIC API request failures. | Alert on broken credentials, permission gaps, or repeated APIC errors. |
| `aci.api.endpoint.error` | Sum, int, cumulative | `{error}` | APIC class or endpoint-family scrape failures. | Identify the failed class query while preserving other APIC results. |
| `aci.api.rate_limited` | Sum, int, cumulative | `{request}` | APIC requests that received HTTP 429. | Detect polling pressure and tune page size or interval. |
| `aci.controller.up` | Gauge, int | `1` | Whether an APIC controller API was reachable for the scrape. | Separate APIC reachability issues from fabric faults. |
| `aci.scrape.partial_success` | Gauge, int | `1` | Whether one or more APIC endpoint families failed during the scrape. | Keep dashboards honest when only part of APIC data was collected. |
| `aci.scrape.last_success` | Gauge, int | `s` | Unix timestamp of the most recent fully successful APIC scrape. | Detect stale or persistently partial ACI data. |
| `aci.resource.info` | Gauge, int | `1` | Bounded metadata for APIC managed objects. | Build inventory and object drilldowns. |
| `aci.resource.status` | Gauge, int | `1` | Encoded APIC object status with original state attributes. | Normalize state across fabric, tenant, endpoint, and topology classes. |
| `aci.resource.count` | Gauge, int | `1` | APIC resources grouped by bounded group, class, type, status, and severity. | Track class-query coverage and unexpected inventory changes. |
| `aci.audit.record.count` | Gauge, int | `1` | Recent APIC audit records by bounded operation, status, and severity attributes. | Correlate APIC-side changes with incidents without high-cardinality labels. |
| `aci.event.count` | Gauge, int | `1` | Recent APIC event records by bounded operation, status, and severity attributes. | Surface event evidence in dashboards while keeping allowlisted event detail in opt-in logs. |
| `aci.fabric.health` | Gauge, double | `1` | Fabric, pod, node, or tenant health score where exposed by APIC. | Detect unhealthy ACI domains quickly. |
| `aci.fault.active` | Gauge, int | `1` | Active APIC fault instance. | Drive fault triage by code, severity, domain, and type. |
| `aci.fault.count` | Gauge, int | `1` | Active APIC fault counts by bounded attributes. | Build severity and domain rollups. |
| `aci.endpoint.present` | Gauge, int | `1` | Endpoint MAC/IP presence. | Confirm whether a workload endpoint is still learned by the fabric. |
| `aci.endpoint.count` | Gauge, int | `1` | Endpoint count by bounded tenant/EPG context. | Detect endpoint churn or EPG-wide impact. |
| `aci.tenant.status` | Gauge, int | `1` | Tenant, VRF, bridge domain, EPG, app profile, contract, or L3Out status. | Correlate network incidents with tenant and policy state. |
| `aci.tenant.object.count` | Gauge, int | `1` | Tenant object counts by bounded tenant/VRF/BD/EPG attributes. | Track policy/object drift. |
| `system.network.interface.status` | Gauge, int | `1` | Interface state from APIC. | Alert on leaf/spine or workload-facing interface changes. |
| `cisco.interface.io.rate` | Gauge, double | `bit/s` | APIC interface traffic rate when exposed by stats classes. | Correlate ACI link pressure with fabric faults and endpoint impact. |
| `cisco.interface.packet.rate` | Gauge, double | `{packet}/s` | APIC interface packet rate when exposed by statistics classes. | Detect packet-rate pressure or traffic silence. |
| `cisco.interface.drop.rate` | Gauge, double | `{drop}/s` | APIC interface packet-drop rate when exposed by statistics classes. | Detect lossy leaf, spine, or workload-facing paths. |
| `system.cpu.utilization` | Gauge, double | `1` | APIC-reported CPU utilization. | Detect controller or node resource pressure. |
| `system.memory.utilization` | Gauge, double | `1` | APIC-reported memory utilization. | Detect controller or node memory pressure. |
| `cisco.topology.neighbor.info` | Gauge, int | `1` | LLDP, CDP, and fabric-link neighbor information. | Reconstruct physical and logical topology during incidents. |

ACI logs default to disabled independently from the enabled metric groups. `aci.logs.faults.enabled`,
`aci.logs.audit.enabled`, and `aci.logs.events.enabled` opt into the corresponding APIC record class. Bodies contain
only the signal-specific scalar allowlists in the
[ACI configuration guide](../README.md#cisco-aciapic-configuration). Resource attributes, event timestamp/severity,
`aci.status`, `aci.severity`, and `user.name` are derived only from that sanitized envelope plus fixed endpoint and
configured controller metadata. Raw APIC aliases, `changeSet`, session identifiers, unknown attributes, and nested
values are neither consulted nor forwarded. Deduplication hashes the complete sanitized semantic record, excludes
only replica-local audit `id`/`dn` copies when `txId` is present, and remains scoped to a configured controller.
Without `storage`, deduplication state is process-local and a restart can replay records inside the configured lookback.
When `storage` is configured, accepted ACI deduplication state is checkpointed across restarts subject to the bounded
unflushed and fail-open replay windows documented in the receiver's durable-checkpoint guidance. Live ACI restart
delivery and replay behavior remains unqualified.

## Cisco ISE Metrics And Logs

Cisco ISE support is identity, access, and policy evidence for the same incidents investigated with Catalyst,
wireless, SD-WAN, Nexus, ACI, and firewall telemetry. Only the three scalar MnT session counters default on;
row-level `session_details`, other REST groups, pxGrid, and Data Connect are opt-in.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `ise.api.request.duration` | Gauge, double | `s` | Average duration of ISE REST/OpenAPI/ERS/MnT and pxGrid REST request attempts within the scrape for each matching request-attribute set. | Detect slow or failing ISE APIs before trusting identity data. |
| `ise.api.request.errors` | Sum, int, cumulative | `{error}` | ISE API request failures. | Alert on broken credentials, disabled API services, permission gaps, and endpoint errors. |
| `ise.api.rate_limited` | Sum, int, cumulative | `{request}` | ISE API requests that were rate limited. | Tune collection interval, page size, and enabled groups. |
| `ise.api.endpoint.error` | Sum, int, cumulative | `{error}` | Endpoint-family scrape failures. | Show exactly which ISE service failed while preserving partial data. |
| `ise.scrape.partial_success` | Gauge, int | `1` | Whether one or more ISE endpoint families failed or were skipped. | Keep dashboards honest when only part of ISE data was collected. |
| `ise.scrape.last_success` | Gauge, int | `s` | Unix timestamp of the most recent fully successful ISE scrape. | Detect stale or persistently partial ISE data. |
| `ise.service.unavailable` | Gauge, int | `1` | ISE API, pxGrid, or Data Connect service unavailable, disabled, unauthorized, or not installed. | Explain empty posture, pxGrid, or historical panels. |
| `ise.service.skipped` | Gauge, int | `1` | ISE service or endpoint family skipped because required target scope was not configured. | Distinguish a scoped opt-in gap from an ISE outage. |
| `ise.controller.up` | Gauge, int | `1` | Whether any ISE REST, pxGrid, or Data Connect operation succeeded in the scrape. | Separate ISE/API availability from partial endpoint failures. |
| `ise.resource.info` | Gauge, int | `1` | Bounded metadata for ISE resources and evidence records. | Build inventory and drilldowns without making text fields metric dimensions. |
| `ise.resource.status` | Gauge, int | `1` | Encoded resource state with original status as an attribute. | Normalize healthy, pending, warning, and failed ISE states. |
| `ise.deployment.node.count` | Gauge, int | `{item}` | Deployment node/persona records by bounded status. | Detect missing or unhealthy PAN/MnT/PSN coverage. |
| `ise.deployment.node.status` | Gauge, int | `1` | Encoded deployment node/persona status. | Find unhealthy PAN, MnT, or PSN nodes. |
| `ise.network_device.count` | Gauge, int | `{item}` | Network access device inventory count. | Confirm Catalyst, WLC, SD-WAN, and firewall devices are represented in ISE. |
| `ise.network_device.status` | Gauge, int | `1` | Encoded network-access-device status. | Find network devices that are unavailable or misrepresented in ISE. |
| `ise.endpoint.count` | Gauge, int | `{item}` | Endpoint inventory and rejected endpoint counts. | Spot endpoint churn, rejection, or missing posture/profile data. |
| `ise.endpoint.status` | Gauge, int | `1` | Encoded endpoint inventory status. | Identify inactive, rejected, or otherwise unhealthy endpoint records. |
| `ise.session.active.count` | Gauge, double | `{session}` | Active session counters from MnT. | Detect authentication/session spikes or drops. |
| `ise.session.count` | Gauge, int | `{item}` | Session evidence records by bounded attributes. | Correlate user/device sessions with network incidents. |
| `ise.radius.failure.count` | Gauge, int | `{item}` | RADIUS authentication failure records. | Triage 802.1X/MAB/VPN/wireless access failures. |
| `ise.tacacs.failure.count` | Gauge, int | `{item}` | TACACS authentication/authorization/accounting failure records. | Triage network-admin login and command authorization failures. |
| `ise.auth.failure.reason.info` | Gauge, int | `1` | Bounded authentication-failure reason evidence. | Separate identity, policy, credential, and network-device causes without using raw event text as dimensions. |
| `ise.accounting.session.count` | Gauge, int | `{item}` | Accounting/session records from available APIs or Data Connect views. | Reconstruct access/session history. |
| `ise.endpoint.posture.status` | Gauge, int | `1` | Endpoint posture state encoded numerically. | Alert on noncompliant or unknown posture. |
| `ise.endpoint.posture.count` | Gauge, int | `{item}` | Endpoint posture records by bounded posture status. | Quantify compliant, noncompliant, and unknown populations. |
| `ise.endpoint.profile.count` | Gauge, int | `{item}` | Endpoint profiler records by bounded object type. | Detect profiler coverage or classification drift. |
| `ise.policy.object.count` | Gauge, int | `{item}` | Network-access, device-admin, TACACS, and policy object counts. | Detect policy coverage and drift. |
| `ise.policy.status` | Gauge, int | `1` | Encoded policy object status. | Find disabled, pending, or failed policy objects. |
| `ise.trustsec.resource.count` | Gauge, int | `{item}` | SGT, SGACL, and SG mapping records. | Correlate TrustSec policy state with segmentation incidents. |
| `ise.trustsec.resource.status` | Gauge, int | `1` | Encoded TrustSec resource status. | Find unhealthy SGT, SGACL, or mapping state. |
| `ise.profiler.policy.status` | Gauge, int | `1` | Encoded profiler-policy status. | Detect disabled or failed endpoint classification policy. |
| `ise.alarm.count` | Gauge, int | `{item}` | ISE alarm rules and active/recent alarm instances by bounded severity/status. | Surface ISE platform or policy incidents. |
| `ise.certificate.count` | Gauge, int | `{item}` | Certificate inventory count by bounded object type. | Detect missing certificate families or unexpected inventory changes. |
| `ise.certificate.expiration` | Gauge, int | `s` | Certificate expiration Unix timestamp. | Prevent API, EAP, pxGrid, or portal certificate outages. |
| `ise.license.count` | Gauge, int | `{item}` | License inventory count by bounded type and status. | Track license coverage and unexpected inventory changes. |
| `ise.license.status` | Gauge, int | `1` | ISE license status encoded numerically. | Detect licensing failures that can affect policy services. |
| `ise.webhook.delivery.count` | Gauge, int | `{item}` | Recent webhook delivery evidence count. | Verify webhook-based downstream evidence paths. |
| `ise.pxgrid.service.status` | Gauge, int | `1` | pxGrid service lookup and pxGrid Cloud/Direct status. | Confirm pxGrid service discovery works before relying on subscriptions. |
| `ise.pxgrid.subscription.status` | Gauge, int | `1` | Configured pxGrid subscription status by topic. | Show whether streaming topics are expected to be active. |
| `ise.pxgrid.message.count` | Gauge, int | `{item}` | pxGrid messages by bounded topic, object type, protocol, and outcome. | Confirm the feed is active and identify bursts of access evidence. |
| `ise.dataconnect.query.duration` | Gauge, double | `s` | Duration of each Data Connect query. | Detect slow or failing historical reporting views. |
| `ise.dataconnect.query.rows` | Gauge, int | `{row}` | Rows returned from each allowlisted Data Connect view. | Validate view coverage and row caps. |
| `ise.dataconnect.query.errors` | Sum, int, cumulative | `{error}` | Data Connect query failures. | Alert on wallet, TLS, credential, view, or database availability issues. |
| `ise.dataconnect.row.count` | Gauge, int | `{item}` | Data Connect evidence rows by bounded view and outcome attributes. | Correlate historical evidence volume with query coverage and row caps. |

ISE logs preserve raw REST/OpenAPI/ERS/MnT objects, pxGrid messages, and Data Connect rows. MnT `ActiveList` and
`AuthList` records require the opt-in `session_details` group. Each record includes
`event.domain=ise`, `event.name`, `ise.group`, `ise.object.type`, and bounded correlation attributes for node,
protocol, outcome, failure reason, message code, policy set/rule, authorization profile, network device, endpoint MAC,
user, and event/session/audit IDs when present.
Metric datapoint attributes intentionally omit high-cardinality usernames, endpoint MACs, network-device identifiers,
and event/session IDs. Event-like session, auth, accounting, pxGrid, and Data Connect metrics use the controller
resource, while those detailed fields remain available in logs and inventory-oriented resource evidence.

## Secure Firewall Management Center Metrics

FMC REST metrics are read-only management and control-plane signals for FMC-managed FTD/ASA firewalls. They cover
controller version/license state, device and chassis inventory, perimeter and segmentation state, interfaces, VNI/VTEP,
static routes, VPN, HA/failover, deployment readiness, policy objects/rules, security-intelligence lists/feeds, and API trust.
Detailed connection and threat events are emitted as logs through eStreamer because they are high-cardinality event
records, not bounded scrape metrics.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `fmc.api.request.duration` | Gauge, double | `s` | Average duration of FMC REST request attempts within the scrape for each matching request-attribute set. | Detect slow FMC APIs, endpoint failures, and auth/token pressure. |
| `fmc.api.request.errors` | Sum, int, cumulative | `{error}` | FMC REST request failures. | Alert on broken credentials, permission gaps, missing endpoint families, or repeated FMC errors. |
| `fmc.api.endpoint.error` | Sum, int, cumulative | `{error}` | FMC endpoint-family scrape failures. | Show exactly which REST family failed while preserving partial data from other groups. |
| `fmc.api.rate_limited` | Sum, int, cumulative | `{request}` | FMC REST requests that were rate limited. | Tune page size, collection interval, and enabled groups before data goes stale. |
| `fmc.manager.up` | Gauge, int | `1` | Whether the FMC REST API was reachable for the scrape. | Separate controller reachability issues from firewall health issues. |
| `fmc.scrape.partial_success` | Gauge, int | `1` | Whether one or more FMC endpoint families failed during the scrape. | Keep dashboards honest when only part of FMC data was collected. |
| `fmc.scrape.last_success` | Gauge, int | `s` | Unix timestamp of the most recent fully successful FMC scrape. | Detect stale or persistently partial controller telemetry. |
| `fmc.resource.info` | Gauge, int | `1` | Bounded metadata for FMC managed objects. | Build inventory, chassis, policy, VPN, HA, and deployment drilldowns. |
| `fmc.resource.status` | Gauge, int | `1` | Encoded FMC object status with original state attributes. | Normalize state across devices, chassis, interfaces, health metrics, policies, jobs, and HA/VPN objects. |
| `fmc.resource.count` | Gauge, int | `1` | FMC resources by group, operation, resource type, status, and severity. | Track object volume and spot missing endpoint families. |
| `fmc.health.status` | Gauge, int | `1` | FMC health alert, event, path-monitor, or aggregate CPU/memory/interface/disk/chassis metric status. | Surface device/controller health issues before they become outages. |
| `fmc.health.event.count` | Gauge, int | `1` | Recent health alerts/events by bounded status and severity. | Correlate firewall symptoms with controller health evidence. |
| `fmc.vpn.tunnel.status` | Gauge, int | `1` | VPN policy, tunnel, tunnel-detail, summary, or remote-access gateway status. | Detect perimeter or remote-access outages. |
| `fmc.ha.status` | Gauge, int | `1` | FMC HA, FTD HA-pair, monitored-interface, cluster, or failover state. | Verify failover readiness and catch degraded HA posture. |
| `fmc.policy.object.count` | Gauge, int | `1` | FMC policy, assignment, rule, object, security-zone, SGT, syslog, and security-intelligence resources by bounded attributes. | Track segmentation and perimeter-policy drift. |
| `fmc.deployment.status` | Gauge, int | `1` | Deployment job, deployable device, or pending-change status. | Identify undeployed or failed policy changes. |
| `fmc.deployment.pending.count` | Gauge, int | `1` | Deployment jobs, deployable devices, and pending changes by bounded status. | Quantify policy deployment backlog. |
| `fmc.audit.record.count` | Gauge, int | `1` | Audit and configuration-change records by bounded attributes. | Correlate network/security incidents with administrative changes. |

FMC REST logs are emitted for health alerts/events, deployment jobs, audit records, and config changes. eStreamer logs
use `event.domain=fmc.estreamer` and include `fmc.estreamer.event.type`, `source.address`, `destination.address`, and
the original fully-qualified event body when available. Accepted eStreamer aliases such as `malware` and
`security_intelligence` are normalized to the Cisco-supported fully-qualified file and connection event blocks.

## Catalyst 9800 Telemetry Metrics

Catalyst 9800 telemetry is emitted from gNMI dial-in subscriptions and MDT gRPC dial-out. Raw YANG-derived metrics keep
full model coverage while stable `cisco.wlc.*` aliases give dashboards product-oriented names across gNMI JSON and
gRPC KV-GPB inputs.

Generic YANG metrics and most stable aliases currently have an empty OTLP metric-unit descriptor; the physical units
shown below describe the source values and must not be used for automatic scaling. RF, SSID, and controller CPU
utilization aliases set unit `1`; `cisco.wlc.ssid.network.io`, `cisco.wlc.client.network.io`, and
`cisco.wlc.client.network.packets` set `By`, `By`, and `{packet}` respectively.

These generic YANG rows describe the pattern-governed contract above, not an enumerable catalog of exact metric names.

| Metric Pattern | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `cisco.catalyst9800.yang.__v1.<framed-schema-tuple>.n` | Gauge/double or cumulative monotonic sum/int | empty | Numeric YANG leaves from Cisco IOS XE wireless/controller models under the reversible contract above. | Keep full C9800 model coverage without conflating raw identifiers or changing a stream's descriptor. |
| `cisco.catalyst9800.yang.__v1.<framed-schema-tuple>.i` | Gauge, double | empty | String, enum, identity, and list leaves represented by value `1`, with the original value on the `value` attribute. | Preserve AP, client, HA, CAPWAP, and mobility states as bounded info metrics. |
| `cisco.wlc.ap.join.status` | Gauge, int | `1` | Whether an AP is joined. | Alert on APs that leave the controller. |
| `cisco.wlc.ap.join.failure.reason.info` | Gauge, double | `1` | Current AP join failure reason evidence. | Find certificate, discovery, authorization, or CAPWAP join issues. |
| `cisco.wlc.ap.disconnect` | Sum, int | `{disconnect}` | AP disconnect counter. | Detect unstable AP/WLC connectivity. |
| `cisco.wlc.ap.disconnect.reason.info` | Gauge, double | `1` | Current AP disconnect reason evidence. | Explain unstable AP/WLC connectivity. |
| `cisco.wlc.ap.capwap.state` | Gauge, int | `1` | CAPWAP/AP operational state with state text as an attribute. | Confirm AP control tunnels are operational. |
| `cisco.wlc.rf.channel.utilization` | Gauge, double | `1` | RF/channel utilization normalized to a ratio from 0 to 1. | Find congested or noisy channels. |
| `cisco.wlc.rf.noise_floor` | Gauge, double | `dBm` | RF noise floor. | Detect interference and RF health problems. |
| `cisco.wlc.rf.client.count` | Gauge, int | `{client}` | Client count per radio/RRM measurement. | Identify overloaded radios. |
| `cisco.wlc.rf.channel.change.count` | Sum, int | `{change}` | DCA/channel change counters. | Spot unstable RF environments. |
| `cisco.wlc.ssid.client.count` | Gauge, int | `{client}` | Associated clients per SSID/BSSID. | Track SSID load. |
| `cisco.wlc.ssid.channel.utilization` | Gauge, double | `1` | SSID/BSSID channel utilization normalized to a ratio from 0 to 1. | Compare SSID experience across APs and radios. |
| `cisco.wlc.ssid.network.io` | Sum, int | `By` | SSID traffic by direction. | Trend wireless traffic volume by WLAN. |
| `cisco.wlc.ssid.retry.count` | Sum, int | `{retry}` | SSID retry counters. | Detect poor airtime quality or client retries. |
| `cisco.wlc.client.connection.state` | Gauge, int | `1` | Client connection state. | Detect clients stuck before run/connected state. |
| `cisco.wlc.client.auth.failure.reason.info` | Gauge, double | `1` | Client auth/exclusion failure reason. | Troubleshoot RADIUS, policy, and exclusion problems. |
| `cisco.wlc.client.roam.count` | Sum, int | `{roam}` | Client or mobility roam counter. | Track roaming activity and unexpected churn. |
| `cisco.wlc.client.roam.type.info` | Gauge, double | `1` | Current client roam type evidence. | Explain roaming behavior without treating enum values as counters. |
| `cisco.wlc.client.roam.failure.count` | Sum, int | `{failure}` | Client roam failure counters. | Detect roaming issues across APs or mobility peers. |
| `cisco.wlc.client.wireless.rssi` | Gauge, double | `dBm` | Client RSSI. | Find weak-signal clients. |
| `cisco.wlc.client.wireless.snr` | Gauge, double | `dB` | Client SNR. | Diagnose poor client RF quality. |
| `cisco.wlc.mobility.peer.status` | Gauge, int | `1` | Mobility peer/link status. | Alert on broken mobility tunnels or peers. |
| `cisco.wlc.mobility.roam.count` | Sum, int | `{roam}` | L2/L3 mobility roam counters. | Track mobility handoff volume. |
| `cisco.wlc.mobility.handoff.count` | Sum, int | `{handoff}` | Successful handoff counters. | Confirm mobility handoffs are completing. |
| `cisco.wlc.mobility.handoff.failure.count` | Sum, int | `{failure}` | Failed handoff counters. | Detect mobility-domain problems. |
| `cisco.wlc.ha.state` | Gauge, int | `1` | Local or peer HA state. | Confirm active/standby WLC health. |
| `cisco.wlc.ha.enabled` | Gauge, int | `1` | Whether HA is enabled. | Detect missing redundancy. |
| `cisco.wlc.ha.switchover.count` | Sum, int | `{switchover}` | HA switchover counter. | Correlate client/AP events with controller failovers. |
| `cisco.wlc.ha.standby.failure.count` | Sum, int | `{failure}` | Standby failure counter. | Alert on degraded redundancy. |
| `cisco.wlc.auth.radius.*` | Counters: sum, int; delays: gauge, double | cataloged per metric | RADIUS accepts, rejects, timeouts, delays, responses, and bad authenticators. | Separate WLAN client failures from upstream AAA problems. |
| `cisco.wlc.controller.*` | Gauge or sum, typed per exact metric | cataloged per metric | Controller CPU uses double; memory and receiver health use int. | Detect WLC or collector-side telemetry health issues. |
| `cisco.catalyst9800.receiver.*` | Gauge or sum, int | empty | Receiver active subscriptions, updates, decode errors, unsupported paths, reconnects, dropped datapoints, compact GPB payloads, and last success timestamp. | Confirm the telemetry pipeline is live and bounded. |
| `cisco.catalyst9800.receiver.target.subscription.active` | Gauge, int | empty | Whether an individual configured target has an active subscription. | Isolate one failed WLC target from aggregate receiver state. |
| `cisco.catalyst9800.receiver.target.updates` | Sum, int, cumulative | empty | Updates received from an individual target. | Detect a target whose stream is connected but silent. |
| `cisco.catalyst9800.receiver.target.reconnects` | Sum, int, cumulative | empty | Reconnect attempts for an individual target. | Detect target-specific transport instability. |
| `cisco.catalyst9800.receiver.target.last_success_timestamp` | Gauge, int | empty | Unix timestamp of the individual target's last successful update. | Alert on target-specific stale telemetry. |
| `cisco.wlc.ap.capwap.encryption.enabled` | Gauge, int | empty | Whether CAPWAP link encryption is enabled. | Detect unexpected control/data tunnel encryption posture. |
| `cisco.wlc.rf.channel.recommended` | Gauge, int | empty | Controller-recommended RF channel. | Correlate DCA recommendations with channel changes. |
| `cisco.wlc.client.network.io` | Sum, int, cumulative | `By` | Client traffic volume by direction. | Detect client traffic silence or spikes. |
| `cisco.wlc.client.network.packets` | Sum, int, cumulative | `{packet}` | Client packet volume by direction. | Detect client packet-rate shifts. |

Catalyst 9800 state aliases retain the original enum on the `state` attribute. Use that attribute for detectors:
unrecognized non-empty states are emitted as informational value `1`, and a numeric `0` can represent an expected
standby role as well as an unhealthy state. Do not treat every `1` as healthy or every `0` as failed without an
enum- and role-specific condition.

Catalyst 9800 metrics include `host.*`, `hw.type=network`, `cisco.os.name=ios_xe`,
`cisco.platform.family=catalyst_9800`, `cisco.yang.path`, `cisco.yang.source_path`, `cisco.yang.module`, `cisco.telemetry.transport`, and WLC
correlation attributes such as `cisco.wlc.ap.mac`, `cisco.wlc.ap.name`, `cisco.wlc.radio.slot`,
`cisco.wlc.wlan.id`, `cisco.wlc.ssid`, `cisco.wlc.client.mac`, and `cisco.wlc.mobility.node_ip`.

## IOS XR Telemetry Metrics

IOS XR telemetry is emitted from gNMI dial-in subscriptions and MDT gRPC dial-out. Because IOS XR exposes many model
families, generic decoded YANG leaves use a predictable metric namespace rather than a fixed hand-authored list for
every leaf.

Generic IOS XR YANG metrics and direct receiver-health metrics currently have an empty OTLP metric-unit descriptor.
The source model still defines how operators should interpret each value; do not use the descriptor for automatic
scaling.

These generic YANG rows describe the pattern-governed contract above, not an enumerable catalog of exact metric names.

| Metric Pattern | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `cisco.iosxr.yang.__v1.<framed-schema-tuple>.n` | Gauge/double or cumulative monotonic sum/int | empty | Numeric YANG leaves from OpenConfig or Cisco IOS XR native models under the reversible contract above. | Build broad model coverage without conflating raw identifiers or changing a stream's descriptor. |
| `cisco.iosxr.yang.__v1.<framed-schema-tuple>.i` | Gauge, double | empty | String, enum, identity, and list leaves represented by value `1`, with the original value on the `value` attribute. | Preserve states such as admin/oper status, neighbor state, alarm text, and component identity as bounded info metrics. |
| `cisco.iosxr.receiver.active_subscriptions` | Gauge, int | empty | Active gNMI dial-in targets. | Detect target selection mistakes or subscriptions that never start. |
| `cisco.iosxr.receiver.updates` | Sum, int, cumulative | empty | gNMI updates and deletes received. | Confirm that subscriptions are producing telemetry. |
| `cisco.iosxr.receiver.decode_errors` | Sum, int, cumulative | empty | JSON/YANG decode failures. | Alert when a model or encoding change starts dropping data. |
| `cisco.iosxr.receiver.unsupported_paths` | Sum, int, cumulative | empty | Paths rejected or pruned by gNMI capabilities. | Catch path groups that are unavailable on a platform, line card, or IOS XR release. |
| `cisco.iosxr.receiver.reconnects` | Sum, int, cumulative | empty | gNMI reconnect attempts after subscription failures. | Detect unstable telemetry sessions or endpoint availability issues. |
| `cisco.iosxr.receiver.dropped_datapoints` | Sum, int, cumulative | empty | Datapoints dropped by the receiver cardinality guard. | Tune path groups, intervals, and caps before overwhelming downstream storage. |
| `cisco.iosxr.receiver.compact_gpb_payloads` | Gauge, int | empty | Compact GPB rows in the current MDT notification that were not generically decoded. | Make compact GPB visibility explicit without carrying one target's notification count into another target. |
| `cisco.iosxr.receiver.last_success_timestamp` | Gauge, int | empty | Unix timestamp of the last successful gNMI update. | Alert on stale IOS XR telemetry. |
| `cisco.iosxr.receiver.target.subscription.active` | Gauge, int | empty | Whether an individual configured target has an active subscription. | Isolate one failed router target from aggregate receiver state. |
| `cisco.iosxr.receiver.target.updates` | Sum, int, cumulative | empty | Updates received from an individual target. | Detect a target whose stream is connected but silent. |
| `cisco.iosxr.receiver.target.reconnects` | Sum, int, cumulative | empty | Reconnect attempts for an individual target. | Detect target-specific transport instability. |
| `cisco.iosxr.receiver.target.last_success_timestamp` | Gauge, int | empty | Unix timestamp of the individual target's last successful update. | Alert on target-specific stale telemetry. |

IOS XR metrics include `cisco.yang.path`, `cisco.yang.source_path`, `cisco.yang.module`, `cisco.telemetry.transport`, `cisco.platform.family`,
`host.*`, `hw.type=network`, and normalized datapoint keys such as `network.interface.name`, `network.vrf.name`, and
`network.peer.address` when those keys are present in the YANG path or JSON payload.

## Plain Language Terms

| Term | Meaning |
| --- | --- |
| Interface | A network port or virtual port on the device. |
| Packet | A small unit of network traffic. |
| Byte | A measure of traffic size. Large byte counts mean lots of data moved. |
| Error | The device saw something wrong while receiving or sending traffic. |
| Drop | The device discarded traffic instead of forwarding it. |
| Control plane | The part of the device that makes decisions, handles routing updates, and protects the device itself. |
| Forwarding plane | The part of the device that moves traffic from one port to another. |
| Routing table | The device's map for where traffic should go next. |
| ARP | A lookup table that maps IP addresses to hardware addresses on a local network. |
| FIB | A fast forwarding table built from routing information. |
| LACP | A protocol that combines multiple ports into one logical link. |
| Port channel | A logical link made from multiple physical ports. |
| STP | A protocol that prevents network loops. |
| vPC | A Cisco feature that lets two switches act like one logical switch for connected devices. |
| Transceiver | The plug-in optic or module that connects fiber or copper cabling to a switch port. |
| QoS | Quality of Service. It classifies traffic into queues or policies so important traffic can be prioritized. |
| PFC | Priority Flow Control. It pauses selected traffic classes on lossless Ethernet links. |
| ECN | Explicit Congestion Notification. It marks traffic instead of dropping it when congestion starts. |
| WRED | Weighted Random Early Detection. It drops or marks traffic before queues fill completely. |
| NVE | Network Virtualization Edge. In this receiver, it represents NX-OS VXLAN tunnel peer and VNI state. |
| EVPN | Ethernet VPN. A control-plane protocol often used with VXLAN fabrics. |
| QFP | Cisco's QuantumFlow Processor, a forwarding engine used by some IOS XE routers to move traffic. |
| Datapath | The traffic-moving path inside the device. If it is overloaded or dropping traffic, users can see network slowdowns or outages. |

## Core System Metrics

These metrics are collected by the `system` scraper without enabling optional troubleshooting groups.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `cisco.device.up` | Gauge, int | `1` | Whether the device is reachable by SSH and responding. `1` means up, `0` means down. | Use it for device availability alerts and to distinguish real device problems from missing metric data. |
| `system.uptime` | Gauge, int | `s` | How long the device has been running. | Use it to detect reloads, correlate outages to reboots, and annotate capacity dashboards. |
| `system.cpu.utilization` | Gauge, double | `1` | The fraction of total CPU in use, reported from `0` to `1`. | High CPU can cause slow command responses, delayed routing updates, dropped control traffic, or unstable device behavior. |
| `system.memory.utilization` | Gauge, double | `1` | The fraction of memory in use, reported from `0` to `1`. | High memory usage can lead to process failures, slow device response, or reload risk. |

## Receiver Health Metrics

These metrics are collected by both scrapers and help validate the receiver itself.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `cisco.scrape.command.duration` | Gauge, double | `s` | How long a bounded command family took to run. | Slow command families often point to overloaded devices, SSH issues, or commands that should stay opt-in. |
| `cisco.scrape.command.errors` | Sum, int, cumulative | `{error}` | Count of command execution failures by family and error type. | Use it to alert on broken credentials, unsupported command families, or device responsiveness problems. |
| `cisco.scrape.partial_success` | Gauge, int | `1` | Whether the scrape completed with at least one command-family failure. | Keeps dashboards honest when only part of a scrape succeeded. |
| `cisco.ssh.reconnects` | Sum, int, cumulative | `{reconnect}` | Successful SSH reconnects by the receiver. | Frequent reconnects can reveal network instability, device limits, or idle timeout behavior. |

## Core Interface Metrics

These metrics are collected by the `interfaces` scraper from normal interface command output.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `system.network.interface.status` | Gauge, int | `1` | Whether a port is operationally up. `1` means up, `0` means down. | Alert when important uplinks, server ports, or WAN links go down. |
| `system.network.io` | Sum, int, cumulative | `By` | Total bytes received and transmitted per interface. | Track traffic volume, capacity trends, and unexpected spikes or silence on important ports. |
| `system.network.packet.count` | Sum, int, cumulative | `{packet}` | Total packets by direction and, when available, packet type: unicast, multicast, or broadcast. | Detect unusual traffic patterns, broadcast storms, or large changes in packet volume. |
| `system.network.errors` | Sum, int, cumulative | `{error}` | Interface receive and transmit errors. | Find cabling, optics, duplex, hardware, or congestion problems before users report symptoms. |
| `system.network.packet.dropped` | Sum, int, cumulative | `{packet}` | Packets discarded by the interface. | Drops often mean congestion, buffering limits, faulty links, or device resource pressure. |
| `cisco.interface.admin.status` | Gauge, int | `1` | Whether an interface is administratively enabled. `1` means enabled/up, `0` means disabled/down. | Separate intentional shutdowns from operational failures when comparing against `system.network.interface.status`. |
| `cisco.interface.speed` | Gauge, int | `bit/s` | Explicit line speed parsed from interface output. | Drives Splunk O11y capacity and utilization dashboards without relying on string attributes. |
| `cisco.interface.utilization` | Gauge, double | `1` | Input or output rate divided by explicit line speed, reported from `0` to `1`. | Alert when links approach saturation. Unknown or auto speeds are skipped instead of guessed. |

Common interface attributes:

| Attribute | Meaning |
| --- | --- |
| `network.interface.name` | Interface name, such as `GigabitEthernet1` or `Ethernet1/1`. |
| `network.interface.description` | Interface description configured on the device. |
| `network.interface.mac` | Interface MAC address. |
| `network.interface.speed` | Configured or detected interface speed. |
| `network.io.direction` | `receive` or `transmit`. |
| `network.packet.type` | `unicast`, `multicast`, or `broadcast` for packet count metrics when the source exposes packet-type counters. |

## Optional Interface Rate Metrics

Enable with `scrapers.interfaces.rates.enabled: true`.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `cisco.interface.io.rate` | Gauge, double | `bit/s` | Device-reported traffic rate for an interface. | Use this for near-real-time bandwidth monitoring without calculating rates from byte counters. |
| `cisco.interface.packet.rate` | Gauge, double | `{packet}/s` | Device-reported packet rate for an interface. | Useful when packet volume matters more than data volume, such as small-packet floods. |

## Optional Detailed Interface Counter Metrics

Enable with `scrapers.interfaces.counters.enabled: true` or an individual `scrapers.interfaces.counters.commands.*` option.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `cisco.interface.counter` | Sum, int, cumulative | `{count}` | A detailed Cisco interface counter. The specific counter name is stored in `cisco.interface.counter.name`. | Use this when investigating interface-specific problems, QoS drops, pause frames, queue drops, WRED drops, ECN marks, or platform hardware queue behavior. |
| `cisco.interface.pause.frames` | Sum, int, cumulative | `{frame}` | Pause frames by interface, direction, pause type, and priority or class of service. | Useful for lossless Ethernet, storage, AI fabric, and congestion investigations. |
| `cisco.interface.qos.queue.packets` | Sum, int, cumulative | `{packet}` | Packets transmitted, enqueued, or dropped by queue or QoS group. | Shows which queues are congested or dropping. |
| `cisco.interface.qos.queue.bytes` | Sum, int, cumulative | `By` | Bytes transmitted, enqueued, or dropped by queue or QoS group. | Quantifies traffic volume affected by queue behavior. |
| `cisco.interface.qos.policy.packets` | Sum, int, cumulative | `{packet}` | Policy-map class packets by action, class, drop reason, direction, and source. | Helps explain policy drops, marks, and class matches. |
| `cisco.interface.qos.policy.bytes` | Sum, int, cumulative | `By` | Policy-map class bytes by action, class, drop reason, direction, and source. | Shows the byte volume affected by QoS policy behavior. |

Important note: `cisco.interface.counter` can create many time series because each counter name and interface combination is a separate series. Use `counters.include`, `counters.exclude`, `counters.max_per_interface`, and `counters.max_interfaces` to control volume.

The structured pause and QoS metrics are emitted from the same optional counter command groups and do not replace `cisco.interface.counter`.

## Optional Protocol Traffic Metrics

Enable with `scrapers.system.protocol_traffic.enabled: true`.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `cisco.protocol.packets` | Sum, int, cumulative | `{packet}` | Packets or protocol messages processed by a network protocol. | Detect unexpected growth in protocol traffic, such as routing, ICMP, or IP traffic changes. |
| `cisco.protocol.errors` | Sum, int, cumulative | `{error}` | Protocol-specific errors reported by the device. | Find malformed traffic, protocol instability, or network behavior that may affect routing and forwarding. |
| `cisco.protocol.dropped` | Sum, int, cumulative | `{packet}` | Protocol packets dropped by the device. | Identify traffic that the device is rejecting or failing to process. |

Common protocol attributes:

| Attribute | Meaning |
| --- | --- |
| `cisco.protocol.name` | Protocol name, such as IP, ICMP, TCP, UDP, or a routing protocol. |
| `cisco.protocol.message.type` | Message or packet type. |
| `cisco.protocol.error.type` | Error category. |
| `cisco.protocol.drop.reason` | Drop reason. |
| `network.io.direction` | `receive` or `transmit`. |

## Optional Control-Plane Metrics

Enable with `scrapers.system.control_plane.enabled: true` or an individual `scrapers.system.control_plane.commands.*` option.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `cisco.control_plane.cpu.process.utilization` | Gauge, double | `1` | CPU use for individual device processes. | Helps identify which process is making the device busy, such as a routing process or management process. |
| `cisco.control_plane.packets` | Sum, int, cumulative | `{packet}` | Control-plane packets processed by class, queue, source, and direction. | Shows whether the device is receiving unusual amounts of traffic that must be handled by the CPU. |
| `cisco.control_plane.dropped` | Sum, int, cumulative | `{packet}` | Control-plane packets dropped by policy class and reason. | Helps confirm whether protection policies are dropping traffic before it can overload the device. |
| `cisco.control_plane.punt.rate` | Gauge, int | `{packet}/s` | Device-reported packet rate for punt queues. | A high punt rate can mean too much traffic is being sent from hardware forwarding to the device CPU. |

Common control-plane attributes:

| Attribute | Meaning |
| --- | --- |
| `cisco.process.name` | Device process name. |
| `cisco.process.pid` | Device process ID. |
| `cisco.cpu.window` | CPU averaging window. |
| `cisco.control_plane.source` | Command output or subsystem that produced the value. |
| `cisco.control_plane.class` | Policy class or queue name. |
| `cisco.control_plane.drop.reason` | Reason packets were dropped. |
| `cisco.control_plane.punt.queue` | Punt queue name or identifier. |

## Optional Routing And Forwarding Metrics

Enable with `scrapers.system.routing_forwarding.enabled: true` or an individual `scrapers.system.routing_forwarding.commands.*` option.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `cisco.routing.routes` | Gauge, int | `{route}` | Number of routes in a routing table. | Sudden route growth or loss can indicate routing instability, outages, leaks, or configuration mistakes. |
| `cisco.arp.entries` | Gauge, int | `{entry}` | Number of ARP entries known by the device. | Unexpected changes can indicate endpoint churn, local network issues, or address-resolution problems. |
| `cisco.forwarding.fib.entries` | Gauge, int | `{entry}` | Number of entries in the forwarding information base. | Helps confirm that routing information is installed for fast packet forwarding. |
| `cisco.adjacency.entries` | Gauge, int | `{entry}` | Number of forwarding adjacencies by state. | Useful when checking whether the device can forward traffic to next-hop neighbors. |
| `cisco.forwarding.drops` | Sum, int, cumulative | `{packet}` | Forwarding-plane packet drops by reason. | Helps identify traffic the device could not forward, often due to policy, lookup, or hardware forwarding problems. |

Common routing and forwarding attributes:

| Attribute | Meaning |
| --- | --- |
| `cisco.routing.vrf` | Routing table or VRF name. Most environments use `default` unless they separate routing tables. |
| `cisco.route.source` | Source or category of routes. |
| `address.family` | IP version, such as IPv4 or IPv6. |
| `cisco.adjacency.state` | Forwarding adjacency state. |
| `cisco.forwarding.drop.reason` | Reason forwarding packets were dropped. |

## Optional Routing Neighbor Metrics

Enable with `scrapers.system.routing_neighbors.enabled: true` or an individual `scrapers.system.routing_neighbors.commands.*` option.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `cisco.routing.neighbor.state` | Gauge, int | `1` | Whether a BGP, OSPF, EIGRP, or ISIS neighbor is up or established. The raw state is preserved as an attribute. | Alert when routing adjacencies go down before traffic loss spreads across the network. |
| `cisco.routing.neighbor.prefixes` | Gauge, int | `{prefix}` | Prefixes associated with a routing neighbor when the platform reports them, such as BGP received prefixes. | Detect route leaks, missing routes, or unexpected neighbor changes. |

Common routing neighbor attributes:

| Attribute | Meaning |
| --- | --- |
| `cisco.routing.protocol` | Routing protocol, such as BGP, OSPF, EIGRP, or ISIS. |
| `cisco.routing.vrf` | VRF name. |
| `network.peer.address` | Neighbor address. |
| `cisco.routing.neighbor.state` | Raw neighbor state after normalization. |
| `address.family` | IP version, such as IPv4 or IPv6. |

## Optional Hardware Health Metrics

Enable with `scrapers.system.hardware_health.enabled: true` or an individual `scrapers.system.hardware_health.commands.*` option.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `cisco.hardware.status` | Gauge, int | `1` | Hardware status mapped to `-1` unknown, `0` critical/non-operational, `1` ok, or `2` warning. The raw state is preserved as an attribute. | Alert on failed fans, PSUs, modules, chassis components, and platform inventory health. |
| `cisco.hardware.temperature` | Gauge, double | `Cel` | Hardware temperature sensor reading. | Detect thermal issues before modules shut down or throttle. |

Common hardware attributes:

| Attribute | Meaning |
| --- | --- |
| `cisco.hardware.component` | Bounded component type, such as fan, power_supply, module, temperature, chassis, or environment. |
| `cisco.hardware.name` | Device-reported component name. |
| `cisco.hardware.slot` | Slot or numeric identifier when available. |
| `cisco.hardware.state` | Device-reported state after normalization. |

## Optional VXLAN/EVPN Fabric Metrics

Enable with `scrapers.system.fabric.enabled: true` or an individual `scrapers.system.fabric.commands.*` option. These metrics are intended for NX-OS fabrics.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `cisco.nve.peer.status` | Gauge, int | `1` | Whether an NVE peer is up. | Alert on VXLAN tunnel peer failures. |
| `cisco.nve.vni.status` | Gauge, int | `1` | Whether a VXLAN VNI is up. | Detect tenant or segment-level fabric outages. |
| `cisco.evpn.routes` | Gauge, int | `{route}` | EVPN route counts by route type. | Track control-plane route churn and missing route families. |

## Optional IOS XE Router Dataplane Metrics

Enable with `scrapers.system.router_dataplane.enabled: true` or an individual `scrapers.system.router_dataplane.commands.*` option. These metrics are mainly useful for IOS XE routers that expose QFP command output.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `cisco.qfp.datapath.io` | Gauge, int | `bit/s` | Device-reported traffic rate through the router datapath. | Shows whether the router's forwarding engine is carrying normal traffic, idle, or approaching capacity. |
| `cisco.qfp.datapath.packet.rate` | Gauge, int | `{packet}/s` | Device-reported packet rate through the router datapath. | High packet rates can stress a router even when byte volume looks moderate. |
| `cisco.qfp.datapath.utilization` | Gauge, double | `1` | QFP datapath load, reported from `0` to `1`. | Alerts when the traffic-moving engine is busy enough to risk latency or drops. |
| `cisco.qfp.drops` | Sum, int, cumulative | `{packet}` | Packets dropped by QFP drop source and reason. | Helps explain user-visible packet loss when interface counters alone do not show the full problem. |
| `cisco.qfp.drop.bytes` | Sum, int, cumulative | `By` | Bytes dropped by QFP drop source and reason. | Shows the traffic volume affected by QFP drops, not just packet count. |
| `cisco.qfp.interface.drops` | Sum, int, cumulative | `{packet}` | QFP packet drops by interface and direction. | Helps identify which interface is associated with datapath drops. |

Common IOS XE router dataplane attributes:

| Attribute | Meaning |
| --- | --- |
| `cisco.qfp.traffic.class` | QFP traffic class, such as priority or non-priority. |
| `cisco.qfp.load.type` | QFP load category, such as processing, crypto, receive, or transmit. |
| `cisco.qfp.drop.source` | Command family or feature source for QFP drops. |
| `cisco.forwarding.drop.reason` | Reason the datapath dropped traffic. |
| `cisco.cpu.window` | Averaging window for QFP rate or load values. |
| `network.interface.name` | Interface associated with interface-level QFP drops. |
| `network.io.direction` | `receive` or `transmit`. |

## Optional L2 Topology Metrics

Enable with `scrapers.interfaces.l2_topology.enabled: true` or an individual `scrapers.interfaces.l2_topology.commands.*` option.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `cisco.interface.errdisabled` | Gauge, int | `1` | Whether an interface is disabled by the device because it detected a problem. | Quickly find ports shut down by safety features, such as link flaps, loops, or policy violations. |
| `cisco.l2.stp.blocked_ports` | Gauge, int | `{port}` | STP-blocked ports by VLAN and interface. | Blocked ports can be normal, but unexpected changes may indicate topology or loop-prevention changes. |
| `cisco.l2.stp.instances` | Gauge, int | `{instance}` | Number of spanning-tree instances by state. | Helps detect broad L2 topology changes or unexpected STP state changes. |
| `cisco.l2.stp.topology_changes` | Sum, int, cumulative | `{change}` | Number of STP topology changes. | Frequent changes can cause brief network disruption and often point to unstable links. |
| `cisco.lacp.errors` | Sum, int, cumulative | `{error}` | LACP errors on bundled links. | Useful for diagnosing broken or misconfigured link bundles. |
| `cisco.lacp.packets` | Sum, int, cumulative | `{packet}` | LACP packets by interface, packet type, and direction. | Helps confirm that link bundle negotiation is active and healthy. |
| `cisco.port_channel.member.status` | Gauge, int | `1` | Whether each physical member of a port channel is bundled or up. | Alert when a link bundle loses one member but the overall logical link is still up. |
| `cisco.port_channel.status` | Gauge, int | `1` | Whether the port channel itself is up. | Alert when a bundled link goes down or becomes suspended. |
| `cisco.vpc.consistency.failures` | Gauge, int | `{failure}` | Number of vPC consistency failures by check. | Finds mismatches between paired switches before they cause outages. |
| `cisco.vpc.status` | Gauge, int | `1` | vPC peer or member status. | Monitors whether a paired-switch topology is healthy. |
| `cisco.topology.neighbor.info` | Gauge, int | `1` | LLDP, CDP, and fabric-link neighbor information. | Build topology maps and spot devices connected to the wrong ports. |

Common L2 topology attributes:

`cisco.topology.neighbor.info` has no required metric attributes. The following nine catalog attributes are optional because
LLDP, CDP, fabric-link, Meraki, and APIC sources do not all report every field:

| Attribute | Meaning |
| --- | --- |
| `cisco.topology.protocol` | Discovery protocol, `lldp` or `cdp`. |
| `network.interface.name` | Local interface on which the neighbor was observed. |
| `cisco.topology.neighbor.name` | Neighbor system name or device ID. |
| `cisco.topology.neighbor.interface` | Neighbor interface identifier. |
| `cisco.topology.neighbor.platform` | Neighbor platform when reported by the device. |
| `cisco.topology.neighbor.address` | Neighbor management address when reported by the device. |
| `network.peer.name` | Legacy peer name retained for compatible Meraki and APIC topology sources. |
| `network.peer.address` | Legacy peer address retained for compatible Meraki and APIC topology sources. |
| `network.protocol.name` | Legacy discovery protocol name retained for compatible topology sources. |

## Optional Transceiver Metrics

Enable with `scrapers.interfaces.transceiver.enabled: true`.

| Metric | Type | Unit | What It Tells You | Why Monitor It |
| --- | --- | --- | --- | --- |
| `cisco.transceiver.sensor` | Gauge, double | `1` | Digital optical monitoring sensor values, such as temperature, voltage, current, or optical receive/transmit power. The actual physical unit is in `cisco.transceiver.sensor.unit`. | Detect failing optics, dirty fiber, weak signal, overheating, or power levels drifting before a link fails. |

Common transceiver attributes:

| Attribute | Meaning |
| --- | --- |
| `network.interface.name` | Interface where the transceiver is installed. |
| `cisco.transceiver.sensor` | Sensor name, such as temperature or optical power. |
| `cisco.transceiver.lane` | Sensor lane identifier for multi-lane optics. |
| `cisco.transceiver.sensor.unit` | Sensor unit, such as `Cel`, `V`, `mA`, `dBm`, or `1`. |
| `meraki.transceiver.sfp_product_id` | Meraki-reported SFP product identifier; this is not an optical lane identifier. |

## Normalized gNMI Optics Metrics

Shared gNMI optical profiles emit stable metrics across supported IOS XE, IOS XR, and NX-OS paths. All optics profiles
remain experimental and are disabled by default. IOS XE and IOS XR expose DOM metrics; IOS XR is limited to controller
and lane DOM mappings and has no coherent profile. NX DME exposes allowlisted DOM and VDM sensor mappings. All metrics
are gauges and use `network.interface.name`, `cisco.optics.lane`, `cisco.optics.profile`, and
`cisco.optics.experimental`; sensor-bearing metrics also include the normalized allowlisted `cisco.optics.sensor`.

| Metric | Unit | Operational Use |
| --- | --- | --- |
| `cisco.optics.present` | `1` | Detect a missing module or lane before interpreting absent sensor data. |
| `cisco.optics.rx_power` | `dB[mW]` | Detect weak receive power, dirty fiber, or path loss. |
| `cisco.optics.tx_power` | `dB[mW]` | Detect transmitter or optical-launch degradation. |
| `cisco.optics.laser_bias_current` | `mA` | Detect transmitter aging or bias drift. |
| `cisco.optics.voltage` | `V` | Detect module supply instability. |
| `cisco.optics.temperature` | `Cel` | Detect thermal pressure at the optic. |
| `cisco.optics.esnr` | `dB` | Track effective SNR from an allowlisted, device-reported VDM sensor. |
| `cisco.optics.pre_fec_ber` | `1` | Detect rising bit errors before FEC can no longer recover the signal. |
| `cisco.optics.tdecq` | `dB` | Track PAM4 transmitter and dispersion eye closure when explicitly identified by the sensor. |
| `cisco.optics.tec_current` | `mA` | Track thermoelectric cooler current when the device reports milliamperes. |
| `cisco.optics.tec_utilization` | `1` | Track normalized thermoelectric cooler utilization and remaining thermal headroom. |

## Splunk O11y Dashboard Starting Points

These metric groups are intended to map cleanly to Splunk Observability Cloud charts and detectors:

| Dashboard Area | Metrics |
| --- | --- |
| Device inventory and health | `cisco.device.up`, `system.uptime`, `system.cpu.utilization`, `system.memory.utilization` grouped by `host.name`, `host.type`, `os.name`, and `os.version`. |
| Interface capacity | `cisco.interface.speed`, `cisco.interface.utilization`, `system.network.io`, `system.network.packet.count`, `system.network.errors`, and `system.network.packet.dropped` grouped by `host.name` and `network.interface.name`. |
| Interface state | `cisco.interface.admin.status` compared with `system.network.interface.status` grouped by `host.name` and `network.interface.name`. |
| Receiver reliability | `cisco.scrape.partial_success`, `cisco.scrape.command.duration`, `cisco.scrape.command.errors`, and `cisco.ssh.reconnects` grouped by `host.name` and `cisco.scrape.command.family`. |
| Hardware health | `cisco.hardware.status` and `cisco.hardware.temperature` grouped by `host.name`, `cisco.hardware.component`, `cisco.hardware.name`, and `cisco.hardware.slot`. |
| Routing health | `cisco.routing.neighbor.state`, `cisco.routing.neighbor.prefixes`, and `cisco.routing.routes` grouped by `host.name`, `cisco.routing.protocol`, `cisco.routing.vrf`, and `network.peer.address`. |
| VXLAN/EVPN fabric | `cisco.nve.peer.status`, `cisco.nve.vni.status`, and `cisco.evpn.routes` grouped by `host.name`, `network.peer.address`, `cisco.nve.vni`, and `cisco.evpn.route.type`. |
| AI fabric/QoS congestion | `cisco.interface.pause.frames`, `cisco.interface.qos.queue.packets`, `cisco.interface.qos.queue.bytes`, `cisco.interface.qos.policy.packets`, and `cisco.interface.qos.policy.bytes` grouped by interface, direction, queue, class, action, and drop reason. |
| L2 topology | `cisco.topology.neighbor.info`, `cisco.port_channel.status`, `cisco.port_channel.member.status`, `cisco.lacp.errors`, and `cisco.vpc.status` grouped by local interface, neighbor, protocol, and port-channel/vPC attributes. |
| Intersight UCS and AI pod health | `intersight.alarm.count`, `intersight.advisory.count`, `intersight.hcl.status`, `intersight.task.status`, `intersight.storage.*`, `intersight.hyperflex.*`, and `intersight.ucs.*` grouped by `host.name`, serial, resource type, cluster, and severity. |

For full dashboard and detector blueprints, see [Splunk O11y Dashboards And Troubleshooting](splunk-o11y.md).

## Metric Volume Guidance

The core metrics are intended to be low volume and safe for broad collection. Optional troubleshooting groups can add more time series, especially:

- `cisco.interface.counter`, because each interface and counter name creates a separate series.
- Structured QoS metrics, because queue, class, action, drop reason, and direction attributes add detail.
- L2 topology metrics on devices with many VLANs or interfaces.
- Routing, routing-neighbor, and forwarding metrics when collecting many VRFs or many neighbors.
- Hardware and fabric metrics on dense chassis or large VXLAN/EVPN fabrics.
- Router dataplane drop metrics when enabling many IOS XE dataplane command families.
- Transceiver metrics on dense switches with many optics.
- Intersight telemetry GroupBy metrics when collecting large UCS, HyperFlex, Kubernetes, or virtualization estates.

Use include, exclude, and maximum count settings when enabling optional groups in large environments.
