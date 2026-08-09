# Splunk Observability Cloud Dashboard Import

This directory contains importable Splunk Observability Cloud dashboard groups for the Cisco OS receiver. The bundles
cover Cisco OS SSH collection, Nexus switch SSH collection, Meraki, Intersight, Catalyst Center, Catalyst 9800 WLC,
Catalyst SD-WAN, Nexus Dashboard/NDFC/Insights/Orchestrator/Data Broker, ACI/APIC, FMC, ISE, IOS XR telemetry, and
VAST Storage telemetry for Cisco AI PODs.

The general Cisco OS bundle creates one dashboard group named `Cisco OS Receiver` with an overview dashboard plus focused pages:

| Dashboard | Value Provided |
| --- | --- |
| `00 Overview Troubleshooting Workflow` | Gives ITOps and NetOps a single landing page for telemetry trust, device health, interface symptoms, routing/fabric/redundancy state, AI/RDMA congestion, QoS, optics, and hardware evidence. |
| `01 Telemetry And Device Health` | Proves whether missing, stale, or suspicious data is caused by device reachability, receiver partial scrapes, slow commands, SSH churn, CPU/memory pressure, or reloads. |
| `02 Interfaces And Link Health` | Isolates link state, saturation, traffic silence, packet-rate pressure, errors, drops, speed downgrade, and err-disabled ports. |
| `03 Routing Fabric And Redundancy` | Correlates routing neighbors, route/FIB inventory, forwarding drops, VXLAN/EVPN state, port-channel/vPC health, LACP, STP, and topology neighbors. |
| `04 AI RDMA And QoS Congestion` | Focuses on switch-side RDMA/RoCEv2 and AI-fabric congestion evidence: ECN, PFC, PFC watchdog, queue drops, link pressure, optics, and path health. |
| `05 Hardware Optics And Physical Health` | Connects hardware component state, thermal pressure, optical power, transceiver temperature, voltage, and bias current to packet loss or device instability. |
| `06 Secure Networking` | Blends Cisco OS edge datapath, QFP drops, control-plane protection, protocol errors, and Meraki MX uplink/VPN/cellular/appliance signals. |
| `07 Campus Networking` | Blends Cisco OS switching/L2/optics with Meraki switching and wireless experience: ports, PoE, APs, SSIDs, clients, RF, topology, and power. |
| `08 Shared gNMI Operational Health` | Proves product qualification, connections, subscriptions, freshness, profile health, decode and delivery quality, and retained-state capacity for shared-gNMI targets. |

The Meraki-focused bundle creates a second dashboard group named `Cisco Meraki Receiver`:

| Dashboard | Value Provided |
| --- | --- |
| `00 Meraki Fleet And API Health` | Proves whether Dashboard API polling is healthy, whether rate limits or endpoint errors are distorting visibility, and which serials or product families are degraded. |
| `01 Meraki WAN VPN And Appliance` | Connects appliance health, WAN uplink state, loss, latency, cellular signal, VPN peer status, and tunnel quality into one branch-edge troubleshooting page. |
| `02 Meraki Wireless Experience` | Focuses on AP client load, RF channel utilization, packet loss, SSID broadcast state, and wireless quality symptoms from the Dashboard API. |
| `03 Meraki Switching And Physical` | Combines Meraki switch port state, speed, utilization, alerts, PoE, topology, power modules, and transceiver evidence for access-layer troubleshooting. |

The Intersight-focused bundle creates a third dashboard group named `Cisco Intersight Receiver`:

| Dashboard | Value Provided |
| --- | --- |
| `00 Intersight Fleet And API Health` | Proves whether native Intersight polling is healthy and which UCS, HyperFlex, storage, Kubernetes, virtualization, or firmware object families are degraded. |
| `01 Intersight Incident Evidence` | Summarizes active alarms, advisory exposure, HCL/compliance state, workflow/task failures, and tech-support status while preserving high-cardinality evidence in logs. |
| `02 AI Pod UCS HyperFlex Storage` | Correlates UCS/FI, HyperFlex, storage, VM, and telemetry GroupBy signals around affected host, serial, cluster, namespace, and workload investigations. |
| `03 UCS Network Counters And Utilization` | Focuses on link state, speed, utilization, byte and packet volume, CRC/discard/no-buffer errors, RX/TX drops, pause frames, link failures, signal losses, and interface resets. |
| `04 UCS Compute Power Thermal And Memory` | Connects CPU/memory utilization with power, energy, fan, thermal threshold, voltage/current, PSU, DIMM/ECC, and optical signal evidence. |
| `05 Storage HyperFlex And VM Impact` | Connects media errors, predictive failures, life left, drive age, rebuilds, HyperFlex IOPS/latency, faults, and VM footprint to workload impact. |

The Catalyst Center-focused bundle creates a fourth dashboard group named `Cisco Catalyst Center Receiver`:

| Dashboard | Value Provided |
| --- | --- |
| `00 Catalyst Center Fleet And API Health` | Proves whether Catalyst Center polling is healthy before operators trust inventory, health, topology, issue, or client-detail panels. |
| `01 Assurance Health Sites And Issues` | Connects Catalyst Center health scores and Assurance issue rollups to affected sites, device categories, and client populations. |
| `02 Inventory Interfaces And Topology` | Connects device inventory, reachability, interface state, line speed, and physical topology counts so operators can move from affected site to affected path. |
| `03 Client And Detail Impact` | Uses optional Catalyst Center device-detail and client-detail targets to connect affected devices and clients to health, signal, issue, CPU, memory, and traffic evidence. |

The Catalyst 9800 WLC-focused bundle creates a dashboard group named `Cisco Catalyst 9800 WLC Receiver`:

| Dashboard | Value Provided |
| --- | --- |
| `00 WLC Telemetry Trust And Controller Health` | Proves whether Catalyst 9800 subscriptions, update flow, decode health, path coverage, freshness, CPU, and memory are trustworthy before operators act on wireless symptoms. |
| `01 AP Join RF And CAPWAP Health` | Connects AP join state, CAPWAP state, join failures, disconnect reasons, RF utilization, noise floor, client load, and channel changes. |
| `02 Clients SSIDs And AAA Experience` | Correlates client connection state, RSSI, SNR, SSID traffic/retries, RADIUS outcomes, response delay, and client auth failures for user-impact triage. |
| `03 Mobility HA And Wireless Resiliency` | Shows mobility peer state, roaming, handoff failures, HA enablement, HA state, switchovers, and standby failures. |

The Catalyst SD-WAN-focused bundle creates a dashboard group named `Cisco SD-WAN Receiver`:

| Dashboard | Value Provided |
| --- | --- |
| `00 SD-WAN Fleet API And Manager Health` | Proves whether SD-WAN Manager polling is healthy before operators trust inventory, overlay, path, event, or feature-group panels. |
| `01 Control Plane Overlay And Validity` | Connects WAN Edge/controller validity, certificate state, control connections, and BFD session health into one overlay triage page. |
| `02 Site BFD TLOC Tunnel And Underlay Health` | Shows BFD session state, TLOC color context, tunnel/underlay feature coverage, and path instability evidence for affected sites. |
| `03 Application Experience SaaS And AI Paths` | Focuses on app-route loss, latency, jitter, SLA state, local/remote colors, and AI/model/SaaS application filters. |
| `04 Interfaces Circuits Cellular And Capacity` | Correlates WAN/service interface state, traffic, errors, drops, circuit pressure, and cellular/failover evidence around an incident window. |
| `05 Policy QoS Security And Service Edge` | Shows whether policy, QoS, and security/service-edge opt-in groups are producing evidence or exposing feature/license/API gaps. |
| `06 AppQoE Optimization And Flow Evidence` | Shows AppQoE and flow opt-in coverage so operators can correlate optimization behavior with app-route symptoms. |
| `07 Cloud OnRamp Multicloud Colocation And Gateways` | Shows Cloud OnRamp and cloud gateway evidence for SaaS, custom app, multicloud, colocation, and AI cloud path incidents. |
| `08 Routing Branch Services And SD-Routing` | Shows routing, WLAN, voice, NFV/service-hosting, and SD-Routing evidence that can explain branch or service-side incidents. |
| `09 Lifecycle Advisories Energy And Hardware` | Correlates device lifecycle, compliance, crash/reboot, certificate, advisory, EoX, hardware, power, and energy evidence with incidents. |
| `10 Alarms Events Audit And Change Evidence` | Shows active/recent alarms, events, audit records, user/session evidence, and hardening-relevant management-plane changes. |
| `11 Network-Wide Path Insight And Incident Readout` | Shows NWPI read-only result coverage and ThousandEyes agent correlation for deep SD-WAN path investigations. |
| `12 Service Desk End User Impact Triage` | Answers which users, sites, and applications are likely affected before exposing operators to SD-WAN implementation detail. |
| `13 Branch And Remote Site Experience` | Shows whether a branch or remote site is having a user experience problem caused by transport, circuit, failover, interface, or overlay instability. |
| `14 SaaS AI And Critical Application Experience` | Shows application experience by app, site, SLA class, color, Cloud OnRamp coverage, AppQoE coverage, and security/service-edge evidence. |
| `15 Incident Commander User Impact Summary` | Summarizes user-facing SD-WAN impact in language useful for incident commanders, service owners, and leadership updates. |

The Cisco ISE-focused bundle creates a dashboard group named `Cisco ISE Receiver`:

| Dashboard | Value Provided |
| --- | --- |
| `00 ISE API Trust And Deployment` | Proves whether ISE API polling, endpoint-family coverage, and deployment/node status are healthy before operators trust identity evidence. |
| `01 AAA Failures Sessions And Posture` | Connects bounded RADIUS/TACACS failure, active-session, posture, and profiler dimensions; correlated ISE logs retain user, endpoint, and network-device identity. |
| `02 Policy TrustSec Alarms And Certificates` | Correlates access behavior with policy objects, TrustSec state, platform alarms, certificate expiry, licensing, and webhook delivery. |
| `03 pxGrid And Data Connect Coverage` | Validates opt-in pxGrid service/subscription state and Data Connect query health for real-time and historical ISE evidence. |

The Secure Firewall-focused bundle creates a dashboard group named `Cisco Secure Firewall Management Center Receiver`:

| Dashboard | Value Provided |
| --- | --- |
| `00 FMC API Trust And Fleet` | Proves whether FMC collection is trustworthy and which managed firewalls are affected before operators act on downstream symptoms. |
| `01 Firewall Interface And Health` | Separates firewall availability, interface state, chassis/resource symptoms, and health evidence from FMC collection failures. |
| `02 VPN And HA Availability` | Correlates VPN tunnel/gateway state with FMC and managed-firewall HA, cluster, monitored-interface, and failover evidence. |
| `03 Policy Deployment And Change Evidence` | Connects policy/object inventory, pending or failed deployments, and bounded audit/config-change evidence to incident timing. |

The Nexus controller-focused bundle creates an API-first dashboard group named `Cisco Nexus Controller Receiver`:

| Dashboard | Value Provided |
| --- | --- |
| `00 Controller API Trust And Coverage` | Proves controller reachability, API latency, endpoint failures/skips, partial scrape state, last success timestamps, and object-family coverage before operators trust downstream fabric views. |
| `01 Nexus Dashboard Platform And NDFC Fabric` | Correlates ND platform service health, CPU/memory/storage pressure, NDFC fabric health, switch inventory, config compliance, deployment state, endpoint/vPC counts, and interface symptoms. |
| `02 Insights Root Cause And Advisories` | Turns Insights anomalies, advisories, scores, confidence, status, resource health, and active evidence into a root-cause queue for triage and autopsy. |
| `03 Orchestrator And Data Broker Operations` | Tracks NDO/OneManage deployments, policy deltas, resource status, site/schema impact, and Data Broker TAP/SPAN/rule/session health for change and packet-visibility workflows. |
| `04 ACI Fabric Tenant Endpoint Impact` | Correlates APIC controller health, ACI node availability/resource pressure, active faults, tenant/VRF/BD/EPG policy objects, endpoint presence, interface rates/utilization/counters, and topology neighbors. |

The SSH/NX-OS Nexus switch bundle creates a dashboard group named `Cisco Nexus Switch Receiver`:

| Dashboard | Value Provided |
| --- | --- |
| `00 Nexus Switch Telemetry And Device Health` | Proves SSH collection trust, device reachability, system pressure, uptime, and control-plane process CPU before deeper triage. |
| `01 Nexus Interfaces L2 And QoS Congestion` | Correlates utilization, packet mix, drops, errors, QoS queue/policy counters, LACP, and STP for slow or lossy service. |
| `02 Nexus VXLAN EVPN vPC And Redundancy` | Focuses on NVE peers, VNIs, EVPN routes, vPC consistency, port-channel state, and topology neighbors. |
| `03 Nexus Hardware Optics And Capacity` | Connects optics, hardware status, temperature, traffic, errors, and drops to physical switch symptoms. |

The IOS XR-focused bundle creates a dashboard group named `Cisco IOS XR Receiver`:

| Dashboard | Value Provided |
| --- | --- |
| `00 IOS XR Telemetry Trust And Coverage` | Proves whether IOS XR gNMI/MDT subscriptions are active, fresh, decodable, and producing model coverage before operators trust router evidence. |
| `01 IOS XR Interfaces Optics And Physical Path` | Uses common OpenConfig and native interface leaves to investigate state, traffic silence, errors, discards, packet counters, MTU, and optical power. |
| `02 IOS XR Routing MPLS SR And Time Sync` | Gives a model-aware landing page for BGP, ISIS, RIB/FIB, FlowSpec, BFD, MPLS-TE, segment routing, NTP, and PTP breadcrumbs when those path groups are enabled. |

The VAST Storage bundle creates a dashboard group named `VAST Storage For Cisco AI PODs`:

| Dashboard | Value Provided |
| --- | --- |
| `00 VAST Collection Trust` | Proves whether VMS and CSI Prometheus endpoints are reachable and producing samples before operators trust storage symptoms. |
| `01 VAST Cluster Health And Capacity` | Connects logical/physical capacity, quota pressure, node state, media state, and CNode scheduler utilization. |
| `02 VAST IOPS Bandwidth And Latency` | Correlates view, VIP, VIP pool, latency-event, bandwidth, IOPS, and QoS wait evidence. |
| `03 VAST Physical Devices And Media` | Shows VAST media, node, NIC, fan, temperature, memory, and RDMA link health. |
| `04 VAST CSI Provisioning And Mount Health` | Tracks CSI operations, mount outcomes, mount duration, and NFS transport backlog for Kubernetes workloads. |
| `05 Cisco AI POD Storage Fabric Correlation` | Correlates VAST and CSI symptoms with Cisco switch-side interface, PFC, ECN, queue-drop, error, and optics evidence. |

The overview dashboard is the first-response page when the failure domain is unknown. The focused pages are for operators who already know which area they are investigating, such as interfaces, routing, AI/RDMA, or optics. Each page includes a `Value Provided` text panel so the operational purpose is visible after import. Each chart description also uses this structure:

- `Value:` why the chart matters to an ITOps or NetOps troubleshooting workflow.
- `Interpretation:` how to read the visual and what pattern or exception to look for first.

State metrics are intentionally shown as list charts with sparklines instead of flat 1/0 line charts. This keeps the 0/1 encoding available while making the dashboard behave more like an exception finder: find the affected device, interface, neighbor, VNI, member link, or component first, then use the adjacent rate/utilization/churn charts to reconstruct when and why it happened. Rates, utilization, packet/byte volume, drops, ECN marks, PFC pause frames, temperatures, and inventory counts remain time-series charts because timing and slope are the useful troubleshooting evidence.

Some Cisco receiver metrics intentionally use standard OpenTelemetry names such as `system.cpu.utilization`, `system.memory.utilization`, `system.uptime`, and `system.network.*`. The dashboards filter those generic metrics with `hw.type=network` so host or EC2 agent telemetry with the same metric names does not appear in Cisco device panels.

Keep production imports paired with receiver-side cost controls: disable unused platform groups, scope `targets` and
`device_selection`, lower `max_results`, use `max_datapoints_per_batch` for direct telemetry receivers, and apply
root-level `metrics` exact-name or glob filters for families that should not be sent to Splunk Observability Cloud.

## Import

The Splunk UI imports dashboard JSON that was exported from the UI. Splunk documents that editing those exported JSON files is unsupported, so this package uses the supported Observability Cloud REST APIs for dashboard groups, dashboards, and charts.

Use an organization access token with the API permission or a session token. The principal must have the Splunk
Observability Cloud admin or power role for chart, dashboard, and dashboard-group writes:

```shell
export SPLUNK_REALM=us1
export SPLUNK_ACCESS_TOKEN=<api-token>
```

The default API endpoint is derived from `SPLUNK_REALM`. A private proxy can be selected with
`SPLUNK_O11Y_API_URL` or `--api-url`, but the URL must use HTTPS, must not contain credentials, a query, or a
fragment, and must be the final non-redirecting endpoint. The importer never follows redirects while carrying the
Splunk access token.

Validate the bundle without calling Splunk:

```shell
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --all --dry-run
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --dry-run
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-meraki-dashboard-group.bundle.json --dry-run
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-intersight-dashboard-group.bundle.json --dry-run
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-catalyst-center-dashboard-group.bundle.json --dry-run
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-catalyst-9800-dashboard-group.bundle.json --dry-run
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-sdwan-dashboard-group.bundle.json --dry-run
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-ise-dashboard-group.bundle.json --dry-run
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-fmc-dashboard-group.bundle.json --dry-run
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-nexus-controller-dashboard-group.bundle.json --dry-run
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-nexus-switch-dashboard-group.bundle.json --dry-run
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-ios-xr-dashboard-group.bundle.json --dry-run
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-vast-storage-dashboard-group.bundle.json --dry-run
```

Run a disposable live API qualification. The non-empty prefix is mandatory, and every created object is deleted after
read-back verification or after a failure:

```shell
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py \
  --all \
  --smoke-test \
  --prefix "Cisco OS validation 20260704T193536Z - "
```

Import the dashboard group:

```shell
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --all
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-meraki-dashboard-group.bundle.json
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-intersight-dashboard-group.bundle.json
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-catalyst-center-dashboard-group.bundle.json
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-catalyst-9800-dashboard-group.bundle.json
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-sdwan-dashboard-group.bundle.json
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-ise-dashboard-group.bundle.json
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-fmc-dashboard-group.bundle.json
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-nexus-controller-dashboard-group.bundle.json
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-nexus-switch-dashboard-group.bundle.json
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-ios-xr-dashboard-group.bundle.json
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-vast-storage-dashboard-group.bundle.json
```

Normal imports also read every created group, dashboard, and chart back from Splunk and verify names, relationships,
chart types, SignalFlow, filters, and layouts before returning success. A verification failure triggers the same
best-effort rollback as a create failure.

Use `--prefix "Lab - "` to create a separate copy for testing. When the Splunk write-permissions feature is enabled,
repeat `--team-id <TEAM_ID>` to link the group to those teams and make them the authorized writers for the group and
its dashboards. Without explicit permissions, Splunk makes custom dashboard groups and dashboards editable and
deletable by all users in the organization.

The importer validates every requested bundle and checks every requested group name before creating anything. It
fails on an exact duplicate group name unless `--allow-duplicate` is explicit. If a create fails, it makes a
best-effort rollback of the dashboards, charts, and groups whose IDs Splunk returned; an `--all` failure also rolls
back bundles completed earlier in that invocation. Review any `rollback warning` before retrying. GET and DELETE
requests retry throttles and transient server/transport failures. Non-idempotent POST requests retry explicit HTTP
429 throttles while honoring `Retry-After`, but do not retry ambiguous transport or 5xx failures that could otherwise
create an unknown duplicate. Successful API response bodies are limited to 16 MiB. Error bodies are read only through
a 64 KiB bound and are never included in terminal output, preventing a proxy or API from reflecting submitted content
or the access token into logs.

For a first production rollout, use `--smoke-test` with a temporary prefix. It creates every requested object, reads
it back to verify names, relationships, chart types, SignalFlow, filters, and layouts, and then deletes it in the same
process. The chart endpoint has been observed to require `TimeSeriesChart`; the published API enum/example says
`TimeSeries`, while its prose and the observed accepted subtype say `TimeSeriesChart`. The importer and its regression
tests preserve that compatibility behavior. No sanitized API transcript is retained in-tree, so this observation is
not recorded as a live qualification in the validation matrix.

## Bundle Format

`cisco-os-dashboard-group.bundle.json`, `cisco-nexus-switch-dashboard-group.bundle.json`,
`cisco-meraki-dashboard-group.bundle.json`, `cisco-intersight-dashboard-group.bundle.json`,
`cisco-catalyst-center-dashboard-group.bundle.json`, `cisco-catalyst-9800-dashboard-group.bundle.json`,
`cisco-sdwan-dashboard-group.bundle.json`, `cisco-ise-dashboard-group.bundle.json`,
`cisco-fmc-dashboard-group.bundle.json`,
`cisco-nexus-controller-dashboard-group.bundle.json`,
`cisco-ios-xr-dashboard-group.bundle.json`, and
`cisco-vast-storage-dashboard-group.bundle.json` are small
repo-native bundles. The importer converts them into Splunk Observability Cloud API payloads:

- `POST /v2/dashboardgroup` creates the dashboard group.
- `POST /v2/chart` creates each chart with SignalFlow.
- `POST /v2/dashboard` places charts into dashboards in the group.

The importer translates dashboard-wide bundle `filters.variables` into the current Splunk v2 API representation,
including the required empty `value` list when no default selection is configured. Review-only `description` and
`applyIfExists` fields are not sent. The bundles include variables for device, interface, fabric/site, and
product-specific identifiers such as the verified shared-gNMI product family and target/profile, Meraki serials, Intersight Moids, Catalyst device IDs, Catalyst 9800
AP/client/SSID attributes, SD-WAN system IPs/site IDs/applications, NDFC switch IDs, ACI node IDs, FMC policy and
domain identifiers, ISE node/protocol/policy dimensions, and IOS XR YANG module/transport dimensions. The repo-native
`TimeSeriesChart` type is preserved for compatibility with the observed chart-endpoint behavior. Dry-run mode validates the bundle schema,
chart types and layout bounds, dashboard and chart descriptions, SignalFlow presence, text-panel markdown, duplicate
names, and dashboard variables.

This keeps the source reviewable while still making the dashboards importable into a real Splunk Observability organization.

## Expected Data

The dashboards expect Cisco OS receiver metrics to be sent to Splunk Observability Cloud through OTLP/HTTP or an equivalent metrics exporter. Several pages use opt-in metric groups, so enable the relevant scraper options before expecting charts to populate:

- Hardware and optics: `hardware_health` and `transceiver`.
- Routing and overlay: `routing_neighbors`, `routing_forwarding`, and `fabric`.
- QoS and AI fabric congestion: interface `counters` command groups.
- AI and RDMA/RoCEv2 workload networks: `counters.commands.priority_flow_control`, `counters.commands.flowcontrol`, `counters.commands.queueing`, `counters.commands.pfc_watchdog`, `counters.commands.qos_policy`, `rates`, `transceiver`, `fabric`, and `l2_topology`.
- Layer 2 redundancy: `l2_topology`.
- IOS XE dataplane: `router_dataplane`.

For production Splunk Observability Cloud cost control, enable only the pages' supporting collection groups, set
provider target filters and group `max_results` caps, and use receiver root `metrics.<metric_name>.enabled: false` for
metrics that should not be forwarded. The full configuration workflow is in
[Controlling Metrics And Splunk Observability Cost](../../docs/metric-control.md).

For Nexus switch dashboards, configure at least one NX-OS device through the receiver SSH `devices` list. The compact
Nexus switch page is most useful when `fabric`, `l2_topology`, `transceiver`, `hardware_health`, and interface `rates`
or `counters` groups are enabled.

The Cisco OS receiver observes the switch side of RoCEv2. For full RDMA autopsy, pair these dashboards with host/NIC telemetry for CNP packets, retransmits, retry or timeout errors, RNR NAKs, QP errors, RDMA CM failures, MTU, and DSCP/PCP/traffic-class mapping.

For Meraki dashboards, configure the receiver with at least one `meraki.organizations` or `meraki.devices` target. The fleet/API page should populate for any Meraki target. WAN/VPN panels require appliance data, wireless panels require wireless devices, and switching/physical panels require switch, power module, topology, or transceiver endpoint data exposed by the Meraki organization. Switch DOM charts require Meraki beta enrollment plus `meraki.switch_transceivers.enabled: true`; appliance DOM remains enabled without that opt-in.

For Intersight dashboards, configure the receiver with `intersight.enabled: true` and Intersight API-key authentication.
The fleet/API page should populate for any reachable Intersight account. Incident evidence panels require active or
recent alarms, advisories, HCL statuses, workflows, tasks, or tech-support records. AI pod infrastructure panels require
UCS, HyperFlex, storage, virtualization, and telemetry GroupBy data exposed by the Intersight account.

For Catalyst Center dashboards, configure `catalyst_center.enabled: true` with a reachable Catalyst Center endpoint and
read-only Assurance API credentials. Fleet/API, inventory, health, topology, and issue panels populate from the broad
collection groups. Device-detail and client-detail panels require `catalyst_center.targets.device_details` or
`catalyst_center.targets.client_macs` because those APIs are intentionally scoped to known affected devices or clients.

For Catalyst 9800 dashboards, configure `catalyst_9800.enabled: true` with at least one gNMI dial-in target or MDT gRPC
dial-out stream. The WLC telemetry trust page should populate for any active target. AP, RF, SSID, mobility, HA, RADIUS,
controller-system, and client pages require their matching Catalyst 9800 path groups; high-volume client, CAPWAP packet,
and neighbor groups should stay scoped for incident use.

For SD-WAN dashboards, configure `sdwan.enabled: true` with a reachable SD-WAN Manager endpoint and read-only API
credentials. Fleet/API, inventory, control-plane, BFD, app-route, interface, alarm, event, and audit panels populate
from default collection groups. Advanced product feature panels require explicit opt-in groups such as
`cloud_onramp`, `security`, `appqoe`, `nwpi`, or `realtime_details`; realtime detail collection also requires target
filters because those APIs are intended for scoped incident use.

The SD-WAN bundle has two layers. Pages `00` through `11` are engineering and feature-domain views for NetOps and
ITOps. Pages `12` through `15` are end-user and stakeholder views for service desk, branch operations, application
owners, AI service owners, and incident commanders.

For ISE dashboards, configure `ise.enabled: true` with a reachable ISE endpoint and read-only API credentials. API
trust, deployment, network-device, endpoint, session, auth-failure, posture, profiler, TrustSec, alarm, certificate,
license, and webhook panels populate from REST-safe groups. pxGrid and Data Connect pages require
`ise.pxgrid.enabled` or `ise.data_connect.enabled` plus their dedicated credentials because those feeds are opt-in.

For FMC dashboards, configure `fmc.enabled: true` with at least one reachable FMC controller and read-only API
credentials. API trust and fleet panels populate from manager and inventory collection. Interface, health, VPN, HA,
policy, deployment, and audit panels require their matching FMC groups; eStreamer connection, intrusion, packet, and
file events remain high-cardinality logs and are intentionally not converted into dashboard metric dimensions.

For Nexus Dashboard/NDFC/Insights/NDO/Data Broker dashboards, configure `nexus_dashboard.enabled: true` with API-key
auth where possible. Broad controller trust and inventory panels populate with only the ND endpoint; interface and
policy-detail panels need exact target filters because several NDFC detail APIs are switch- or fabric-scoped:
`fabrics` expands fabric switch-overview and endpoint operations, `switch_serials` expands policy deployment, and
`switch_ids` expands interface statistics. With their groups enabled, an absent selector intentionally emits
`nexus_dashboard.service.skipped`, sets `nexus_dashboard.scrape.partial_success=1`, and prevents
`nexus_dashboard.scrape.last_success` from advancing. Missing apps are expected in some environments and are surfaced
through `nexus_dashboard.service.unavailable`. For clean platform-only collection, explicitly disable `ndfc`,
`insights`, `orchestrator`, `data_broker`, and `performance`; all collection groups otherwise default to enabled.

For ACI dashboards, configure `aci.enabled: true` with at least one APIC controller. Fabric and fault panels populate
from APIC class queries; tenant, endpoint, and topology pages become more useful when `aci.targets` is scoped to the
affected node IDs, tenants, EPGs, or interfaces during an investigation.

For IOS XR dashboards, configure `ios_xr.enabled: true` with at least one gNMI dial-in target or MDT gRPC dial-out
stream. The telemetry trust page should populate for any active target. Interface panels use common OpenConfig and native
IOS XR interface leaves; routing, MPLS, segment routing, BFD, optics, and time-sync panels populate when those path
groups are enabled and advertised by the target router release.

For VAST Storage dashboards, configure the Splunk Collector to scrape the VMS Prometheus endpoints and, when Kubernetes
volume evidence is required, the VAST CSI driver `/metrics` endpoints. See
[VAST Storage For Cisco AI PODs](../../docs/vast-storage.md). The VMS pages expect metrics such as
`vast_cluster_online`, `vast_cluster_logical_space`, `vast_cluster_physical_space`, `vast_view_metrics_ViewMetrics_*`,
`vast_vip_*`, `vast_quota_*`, `vast_vms_alarms`, `vast_ssd_*`, and `vast_cnode_*`. The CSI page expects
`csi_plugin_operations_total`, `csi_node_mount_operations_total`, `csi_node_mount_duration_seconds_*`, and
`csi_node_nfs_xprt_*`. The fabric correlation page also expects Cisco switch metrics from the Cisco OS receiver.
