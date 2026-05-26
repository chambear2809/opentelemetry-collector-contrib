# Splunk Observability Cloud Dashboard Import

This directory contains importable Splunk Observability Cloud dashboard groups for the Cisco OS receiver. The bundles
cover Cisco OS SSH collection, Nexus switch SSH collection, Meraki, Intersight, Catalyst Center, Nexus
Dashboard/NDFC/Insights/Orchestrator/Data Broker, and ACI/APIC telemetry.

The SSH-focused bundle creates one dashboard group named `Cisco OS Receiver` with an overview dashboard plus focused pages:

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

The Nexus controller-focused bundle creates an API-first dashboard group named `Cisco Nexus Controller Receiver`:

| Dashboard | Value Provided |
| --- | --- |
| `00 Controller API Trust And Coverage` | Proves controller reachability, API latency, endpoint failures/skips, partial scrape state, last success timestamps, and object-family coverage before operators trust downstream fabric views. |
| `01 Nexus Dashboard Platform And NDFC Fabric` | Correlates ND platform service health, CPU/memory/storage pressure, NDFC fabric health, switch inventory, config compliance, deployment state, endpoint/vPC counts, and interface symptoms. |
| `02 Insights Root Cause And Advisories` | Turns Insights anomalies, advisories, scores, confidence, status, resource health, and active evidence into a root-cause queue for triage and autopsy. |
| `03 Orchestrator And Data Broker Operations` | Tracks NDO/OneManage deployments, policy deltas, resource status, site/schema impact, and Data Broker TAP/SPAN/rule/session health for change and packet-visibility workflows. |
| `04 ACI Fabric Tenant Endpoint Impact` | Correlates APIC controller health, ACI node availability/resource pressure, active faults, tenant/VRF/BD/EPG policy objects, endpoint presence, interfaces, optional traffic/drop counters, and topology neighbors. |

The SSH/NX-OS Nexus switch bundle creates a dashboard group named `Cisco Nexus Switch Receiver`:

| Dashboard | Value Provided |
| --- | --- |
| `00 Nexus Switch Health And Fabric` | Focuses on Nexus switch telemetry collected over SSH: reachability, partial scrapes, interface pressure, VXLAN/EVPN, vPC/LACP, optics, and hardware health. |

The overview dashboard is the first-response page when the failure domain is unknown. The focused pages are for operators who already know which area they are investigating, such as interfaces, routing, AI/RDMA, or optics. Each page includes a `Value Provided` text panel so the operational purpose is visible after import. Each chart description also uses this structure:

- `Value:` why the chart matters to an ITOps or NetOps troubleshooting workflow.
- `Interpretation:` how to read the visual and what pattern or exception to look for first.

State metrics are intentionally shown as list charts with sparklines instead of flat 1/0 line charts. This keeps the 0/1 encoding available while making the dashboard behave more like an exception finder: find the affected device, interface, neighbor, VNI, member link, or component first, then use the adjacent rate/utilization/churn charts to reconstruct when and why it happened. Rates, utilization, packet/byte volume, drops, ECN marks, PFC pause frames, temperatures, and inventory counts remain time-series charts because timing and slope are the useful troubleshooting evidence.

Some Cisco receiver metrics intentionally use standard OpenTelemetry names such as `system.cpu.utilization`, `system.memory.utilization`, `system.uptime`, and `system.network.*`. The dashboards filter those generic metrics with `hw.type=network` so host or EC2 agent telemetry with the same metric names does not appear in Cisco device panels.

## Import

The Splunk UI imports dashboard JSON that was exported from the UI. Splunk documents that editing those exported JSON files is unsupported, so this package uses the supported Observability Cloud REST APIs for dashboard groups, dashboards, and charts.

Set a Splunk Observability Cloud API token with dashboard write access:

```shell
export SPLUNK_REALM=us1
export SPLUNK_ACCESS_TOKEN=<api-token>
```

Validate the bundle without calling Splunk:

```shell
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --all --dry-run
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --dry-run
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-meraki-dashboard-group.bundle.json --dry-run
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-intersight-dashboard-group.bundle.json --dry-run
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-catalyst-center-dashboard-group.bundle.json --dry-run
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-nexus-controller-dashboard-group.bundle.json --dry-run
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-nexus-switch-dashboard-group.bundle.json --dry-run
```

Import the dashboard group:

```shell
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --all
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-meraki-dashboard-group.bundle.json
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-intersight-dashboard-group.bundle.json
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-catalyst-center-dashboard-group.bundle.json
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-nexus-controller-dashboard-group.bundle.json
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-nexus-switch-dashboard-group.bundle.json
```

Use `--prefix "Lab - "` to create a separate copy for testing.

## Bundle Format

`cisco-os-dashboard-group.bundle.json`, `cisco-nexus-switch-dashboard-group.bundle.json`,
`cisco-meraki-dashboard-group.bundle.json`, `cisco-intersight-dashboard-group.bundle.json`,
`cisco-catalyst-center-dashboard-group.bundle.json`, and `cisco-nexus-controller-dashboard-group.bundle.json` are small
repo-native bundles. The importer converts them into Splunk Observability Cloud API payloads:

- `POST /v2/dashboardgroup` creates the dashboard group.
- `POST /v2/chart` creates each chart with SignalFlow.
- `POST /v2/dashboard` places charts into dashboards in the group.

The importer passes dashboard-wide `filters.variables` from each bundle into every dashboard payload. The bundles include variables for device, interface, fabric/site, and product-specific identifiers such as Meraki serials, Intersight Moids, Catalyst device IDs, NDFC switch IDs, and ACI node IDs. Dry-run mode validates bundle shape, dashboard and chart descriptions, SignalFlow presence, text-panel markdown, duplicate names, and dashboard variables.

This keeps the source reviewable while still making the dashboards importable into a real Splunk Observability organization.

## Expected Data

The dashboards expect Cisco OS receiver metrics to be sent to Splunk Observability Cloud through OTLP/HTTP or an equivalent metrics exporter. Several pages use opt-in metric groups, so enable the relevant scraper options before expecting charts to populate:

- Hardware and optics: `hardware_health` and `transceiver`.
- Routing and overlay: `routing_neighbors`, `routing_forwarding`, and `fabric`.
- QoS and AI fabric congestion: interface `counters` command groups.
- AI and RDMA/RoCEv2 workload networks: `counters.commands.priority_flow_control`, `counters.commands.flowcontrol`, `counters.commands.queueing`, `counters.commands.pfc_watchdog`, `counters.commands.qos_policy`, `rates`, `transceiver`, `fabric`, and `l2_topology`.
- Layer 2 redundancy: `l2_topology`.
- IOS XE dataplane: `router_dataplane`.

For Nexus switch dashboards, configure at least one NX-OS device through the receiver SSH `devices` list. The compact
Nexus switch page is most useful when `fabric`, `l2_topology`, `transceiver`, `hardware_health`, and interface `rates`
or `counters` groups are enabled.

The Cisco OS receiver observes the switch side of RoCEv2. For full RDMA autopsy, pair these dashboards with host/NIC telemetry for CNP packets, retransmits, retry or timeout errors, RNR NAKs, QP errors, RDMA CM failures, MTU, and DSCP/PCP/traffic-class mapping.

For Meraki dashboards, configure the receiver with at least one `meraki.organizations` or `meraki.devices` target. The fleet/API page should populate for any Meraki target. WAN/VPN panels require appliance data, wireless panels require wireless devices, and switching/physical panels require switch, power module, topology, or transceiver endpoint data exposed by the Meraki organization.

For Intersight dashboards, configure the receiver with `intersight.enabled: true` and Intersight API-key authentication.
The fleet/API page should populate for any reachable Intersight account. Incident evidence panels require active or
recent alarms, advisories, HCL statuses, workflows, tasks, or tech-support records. AI pod infrastructure panels require
UCS, HyperFlex, storage, virtualization, and telemetry GroupBy data exposed by the Intersight account.

For Catalyst Center dashboards, configure `catalyst_center.enabled: true` with a reachable Catalyst Center endpoint and
read-only Assurance API credentials. Fleet/API, inventory, health, topology, and issue panels populate from the broad
collection groups. Device-detail and client-detail panels require `catalyst_center.targets.device_details` or
`catalyst_center.targets.client_macs` because those APIs are intentionally scoped to known affected devices or clients.

For Nexus Dashboard/NDFC/Insights/NDO/Data Broker dashboards, configure `nexus_dashboard.enabled: true` with API-key
auth where possible. Broad controller trust and inventory panels populate with only the ND endpoint; interface and
policy-detail panels need target filters such as `switch_ids`, `switch_serials`, and `fabrics` because several NDFC
detail APIs are switch- or fabric-scoped. Missing apps are expected in some environments and are surfaced through
`nexus_dashboard.service.unavailable`, `nexus_dashboard.service.skipped`, and `nexus_dashboard.scrape.partial_success`.

For ACI dashboards, configure `aci.enabled: true` with at least one APIC controller. Fabric and fault panels populate
from APIC class queries; tenant, endpoint, and topology pages become more useful when `aci.targets` is scoped to the
affected node IDs, tenants, EPGs, or interfaces during an investigation.
