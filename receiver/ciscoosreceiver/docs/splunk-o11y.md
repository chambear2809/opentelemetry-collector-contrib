# Splunk O11y Dashboards And Troubleshooting

This guide gives Splunk Observability Cloud dashboard and detector blueprints for the Cisco OS receiver. It focuses on ITOps and NetOps workflows: live troubleshooting, post-incident autopsy, and capacity planning.

Importable dashboard group assets are available in [`dashboards/splunk-o11y`](../dashboards/splunk-o11y/README.md). The import bundles create high-density dashboards with visible "Value Provided" panels and workflow section headers so operators can see why each part of the dashboard exists inside Splunk Observability Cloud.

The import bundles also make chart descriptions operational: each chart description starts with `Value:` and `Interpretation:` so users can tell why the chart matters and how to read it during an incident. Binary state metrics are presented as list charts with sparklines rather than flat 1/0 line charts; rate, utilization, count, temperature, drop, mark, pause, and churn metrics remain time-series charts. Single-value charts are intentionally avoided because most Cisco receiver signals are multi-device or multi-interface and a single displayed value can hide which MTS is being shown.

Every importable bundle includes dashboard-wide `filters.variables` for device, interface, fabric/site, and product-specific identifiers. Use the dry-run importer before live import to validate that generated dashboard API payloads contain variables.

The Cisco OS receiver emits some standard OpenTelemetry metric names, including `system.cpu.utilization`, `system.memory.utilization`, `system.uptime`, and `system.network.*`. The importable dashboard filters those generic metrics with `hw.type=network` so host, EC2, or collector-agent telemetry with the same names does not leak into Cisco device charts.

Use receiver-side collection controls before importing every dashboard into a production Splunk Observability Cloud
organization. The dashboard bundles can reference optional metrics, but users can keep cost predictable by disabling
unused collection groups, lowering each group's `max_results`, scoping `device_selection` and provider `targets`, and
setting root-level `metrics.<metric_name-or-glob>.enabled: false` for metrics they do not want forwarded. See
[Controlling Metrics And Splunk Observability Cost](metric-control.md) for the full workflow.

## Recommended Dimensions

Use these dimensions as dashboard variables:

| Variable | Use |
| --- | --- |
| `host.name` | Device selector. |
| `host.id` | Stable device identity, normally the serial number. |
| `host.type` | Platform or model grouping. |
| `host.ip` | Reachability and inventory lookup. |
| `os.name` | IOS, IOS XE, or NX-OS grouping. |
| `network.interface.name` | Interface selector. |
| `network.io.direction` | Receive/transmit selector for link and queue symptoms. |
| `meraki.device.serial` | Meraki device serial selector. |
| `meraki.network.id` | Meraki network selector for Dashboard API metrics. |
| `intersight.serial` | Intersight device serial selector. |
| `intersight.moid` | Intersight managed object selector. |
| `cisco.routing.vrf` | VRF selector for routing views. |
| `cisco.routing.protocol` | BGP, OSPF, EIGRP, or ISIS selector. |
| `cisco.qos.group` | QoS group selector for AI/lossless queue investigation. |
| `cisco.qos.class` | Policy class selector for ECN/WRED and class-based congestion investigation. |
| `intersight.resource.type` | Intersight object family, such as compute, storage, HyperFlex, Kubernetes, or virtualization. |
| `intersight.severity` | Alarm, advisory, or status severity. |
| `intersight.status` | Original Intersight status string for state drilldowns. |
| `catalyst_center.site.name` | Catalyst Center site selector for Assurance health and issue views. |
| `catalyst_center.device.family` | Catalyst Center device family selector, such as switching, routing, wireless, or controller families. |
| `catalyst_center.device.role` | Catalyst Center device role selector, such as access, distribution, core, or border. |
| `catalyst_center.status` | Original Catalyst Center status string for reachability, collection, communication, and detail drilldowns. |
| `catalyst_center.client.mac` | Targeted Catalyst Center client selector for client-detail investigations. |
| `cisco.wlc.ap.name` | Catalyst 9800 AP selector for AP join, CAPWAP, RF, and client views. |
| `cisco.wlc.ssid` | Catalyst 9800 SSID selector for client, retry, and traffic views. |
| `cisco.wlc.client.mac` | Catalyst 9800 client selector for connection, RF quality, auth, and traffic investigations. |
| `sdwan.system_ip` | Catalyst SD-WAN system IP selector. |
| `sdwan.site.id` | Catalyst SD-WAN site selector. |
| `sdwan.uuid` | Catalyst SD-WAN device UUID selector. |
| `sdwan.personality` | Catalyst SD-WAN role selector for Manager, Controller, Validator, WAN Edge, or SD-Routing devices. |
| `sdwan.tloc.color` | Catalyst SD-WAN transport color selector. |
| `sdwan.application` | Application selector for app-route, SaaS, and AI/model path views. |
| `sdwan.sla_class` | SLA class selector for application-aware routing views. |
| `cisco.controller.type` | API source selector, such as SD-WAN Manager, Nexus Dashboard, or APIC. |
| `cisco.controller.endpoint` | Controller endpoint selector for API trust views. |
| `cisco.fabric.name` | Fabric selector for NDFC, Insights, NDO, and ACI workflows. |
| `cisco.site.name` | Nexus Dashboard site selector. |
| `cisco.switch.serial` | Nexus switch serial for cross-source API, SSH, and MDT correlation. |
| `aci.node.id` | ACI node selector. |
| `ndfc.switch.id` | NDFC switch ID selector for interface/performance drilldowns. |
| `nd.service.name` | Nexus Dashboard service/app selector. |
| `ise.node.name` | ISE node/persona selector. |
| `ise.network_device.name` | ISE network access device selector. |
| `ise.endpoint.mac` | ISE endpoint MAC selector for posture/session investigations. |
| `user.name` | User selector for ISE auth/session evidence and audit records. |
| `ise.protocol` | RADIUS/TACACS or authentication protocol selector. |
| `ise.policy.set` | ISE network-access or device-admin policy set selector. |
| `cisco.yang.module` | Direct telemetry YANG module selector for Catalyst 9800 and IOS XR model coverage. |
| `cisco.telemetry.transport` | Direct telemetry transport selector, such as gNMI dial-in or MDT gRPC dial-out. |
| `cisco.node.id` | IOS XR node, rack, slot, or location selector when exposed by telemetry. |
| `storage.vendor` | Storage vendor selector for adjacent Cisco AI POD storage integrations, such as VAST. |
| `ai.pod.component` | AI POD component selector, such as storage. |
| `vast.cluster` | VAST cluster selector added by the Collector resource processor. |
| `view_name` | VAST view selector for storage performance and capacity dashboards. |
| `tenant_name` | VAST tenant selector for scoped storage dashboards. |
| `vip` | VAST virtual IP selector for storage path analysis. |
| `vippool` | VAST VIP pool selector for load-balancing and path analysis. |
| `pvc_namespace` | Kubernetes namespace selector for VAST CSI mount and provisioning evidence. |

Avoid using high-cardinality fields such as process names, queue names, neighbor names, and drop reasons as global dashboard variables unless the dashboard is specifically for deep investigation.

## Dashboard: Cisco OS Receiver Troubleshooting

Audience: ITOps, NOC, NetOps, data center operators, AI infrastructure teams, and workload owners.

Purpose: Provide one Splunk Observability dashboard for live troubleshooting and post-incident autopsy. The dashboard is organized as a workflow: telemetry trust, interface/link symptoms, routing/fabric/redundancy health, then AI/RDMA/QoS/physical evidence.

Charts:

| Chart | Metric And Grouping | Useful Alert |
| --- | --- | --- |
| Device reachability | `cisco.device.up` by `host.name`, list with sparkline | Any critical device equals `0` for 2 collection intervals. |
| Receiver partial success | `cisco.scrape.partial_success` by `host.name`, list with sparkline | Value equals `1` for 3 consecutive scrapes. |
| Command latency | `cisco.scrape.command.duration` by `host.name`, `cisco.scrape.command.family`, time-series | A command family is slow or timing out. |
| SSH reconnects and command errors | Rates of `cisco.ssh.reconnects` and `cisco.scrape.command.errors`, time-series | Reconnects or command errors rise during missing telemetry. |
| CPU and memory pressure | `system.cpu.utilization`, `system.memory.utilization` by `host.name`, time-series | CPU or memory above 85 percent for 5 minutes. |
| Reboot timeline | `system.uptime` by `host.name`, time-series | Uptime drops sharply or is below expected minimum. |
| Admin vs oper state | `cisco.interface.admin.status` next to `system.network.interface.status`, list with sparkline | Admin is `1` and oper is `0`. |
| Interface utilization | `cisco.interface.utilization` by device, interface, direction, time-series | Sustained value above 80 percent on uplinks or AI fabric paths. |
| Interface traffic rate | Rate of `system.network.io` by interface and direction, time-series | Sudden silence or traffic spike. |
| Interface packet rate | `cisco.interface.packet.rate` by interface and direction, time-series | Packet-rate pressure or small-packet storms. |
| Errors and drops | Rates of `system.network.errors` and `system.network.packet.dropped`, time-series | Non-zero sustained rate on critical ports. |
| Interface speed | `cisco.interface.speed` by interface, list with sparkline | Unexpected speed downgrade or missing speed on known physical ports. |
| Routing neighbor state | `cisco.routing.neighbor.state` by protocol, VRF, peer, list with sparkline | Any required neighbor equals `0`. |
| Route, ARP, adjacency, and FIB counts | `cisco.routing.routes`, `cisco.arp.entries`, `cisco.adjacency.entries`, `cisco.forwarding.fib.entries`, time-series | Route/FIB divergence, route loss, route explosion, or ARP/adjacency collapse. |
| Forwarding and QFP drops | Rates of `cisco.forwarding.drops`, `cisco.qfp.drops`, `cisco.qfp.interface.drops`, time-series | Any new non-zero drop reason after a change. |
| VXLAN NVE and VNI status | `cisco.nve.peer.status`, `cisco.nve.vni.status`, list with sparkline | Required peer or VNI equals `0` or flaps. |
| EVPN route counts | `cisco.evpn.routes` by VRF and route type, time-series | Route count drops sharply or grows unexpectedly. |
| Redundant path health | `cisco.port_channel.*`, `cisco.vpc.*`, list with sparkline | Member loss, vPC peer down, or vPC consistency failures. |
| LACP errors and packets | `cisco.lacp.errors`, `cisco.lacp.packets`, time-series | Any sustained non-zero error rate. |
| STP topology changes | Rate of `cisco.l2.stp.topology_changes`, time-series | Repeated changes in a short interval. |
| RoCEv2 congestion control loop | ECN marks from `cisco.interface.qos.policy.packets`, PFC from `cisco.interface.pause.frames`, drops and watchdog from `cisco.interface.qos.queue.packets`, time-series | ECN marks do not precede PFC, or drops/watchdog appear. |
| PFC and flow-control pause pressure | Rate of `cisco.interface.pause.frames` by interface, direction, pause type, priority, time-series | Sustained pause-frame growth on GPU-facing or spine-facing ports. |
| ECN and WRED congestion feedback | Rate of `cisco.interface.qos.policy.packets` by class, action, drop reason, time-series | ECN marks spike or drops appear during workload slowdown. |
| Lossless queue drops and drains | Rate of `cisco.interface.qos.queue.packets` by queue, QoS group, action, reason, time-series | Queue drops on no-drop or high-priority classes. |
| Optical power drift | `cisco.transceiver.sensor` filtered to `rx_power` and `tx_power`, time-series | Low RX power or high TX power before errors. |
| Hardware temperature | `cisco.hardware.temperature` by component or slot, time-series | Temperature crosses platform threshold or anomaly baseline. |
| Hardware status | `cisco.hardware.status` by component, name, slot, state, list with sparkline | Status is critical or warning. |
| Intersight API health | `intersight.api.request.duration`, `intersight.api.request.errors`, and `intersight.api.rate_limited` by operation, time-series | API errors, signing failures, or 429s repeat. |
| Intersight active alarms | `intersight.alarm.count` by severity, status, resource type, and acknowledgement, stacked time-series | Critical active alarms are present or increasing. |
| Intersight advisory exposure | `intersight.advisory.count` by severity and resource type, stacked time-series | New critical security or field advisory exposure appears. |
| Intersight HCL/compliance | `intersight.hcl.status` by host and status, list with sparkline | Any required host is unsupported or degraded. |
| Intersight workflow/task failures | `intersight.workflow.status` and `intersight.task.status` by status and resource type, list with sparkline | A workflow or task is failed, stalled, or waiting on user action. |
| UCS power, thermal, and fan telemetry | `intersight.ucs.host.power`, `intersight.ucs.temperature`, `intersight.ucs.fan.speed`, and `intersight.ucs.voltage`, time-series | Thermal or power values move outside expected bands. |
| Storage and HyperFlex health | `intersight.storage.*`, `intersight.hyperflex.*`, and `intersight.fault.count` by cluster, host, and resource type | Disk life, predictive failures, media errors, IOPS, or latency degrade. |
| Catalyst Center API health | `catalyst_center.api.request.duration`, `catalyst_center.api.request.errors`, `catalyst_center.api.rate_limited`, and `catalyst_center.scrape.partial_success` by operation | Catalyst Center API errors, authorization failures, rate limits, or partial scrape repeat. |
| Catalyst Center device inventory | `cisco.device.up`, `catalyst_center.device.reachability.status`, `catalyst_center.device.collection.status`, and `catalyst_center.inventory.device.count` by device, family, role, and site | Catalyst Center sees devices as unreachable, unmanaged, or unexpectedly missing. |
| Catalyst Center Assurance health | `catalyst_center.network.health.score`, `catalyst_center.network.health.entity.score`, `catalyst_center.site.network_device.health.percentage`, `catalyst_center.site.client.health.percentage`, `catalyst_center.site.client.count`, and `catalyst_center.site.network_device.count` by entity and site | Campus or site health degrades and the operator can see how many clients or devices are represented by the score. |
| Catalyst Center issues and topology | `catalyst_center.issue.active.count`, `catalyst_center.site.issue.count`, `catalyst_center.topology.node.count`, and `catalyst_center.topology.link.count` by severity, priority, category, node type, and link status | Assurance issues or topology discovery changes explain campus symptoms. |
| Catalyst Center client detail | `catalyst_center.client.detail.health.score`, `catalyst_center.client.issue.count`, `catalyst_center.client.wireless.rssi`, `catalyst_center.client.wireless.snr`, and `catalyst_center.client.network.io` by targeted client MAC | Affected clients show poor health, RF degradation, issue counts, or traffic silence. |
| SD-WAN API and coverage | `sdwan.api.request.duration`, `sdwan.api.request.errors`, `sdwan.api.rate_limited`, `sdwan.scrape.partial_success`, `sdwan.scrape.last_success`, `sdwan.manager.up`, `sdwan.manager.status`, `sdwan.manager.endpoint.status`, `sdwan.inventory.device.count`, `sdwan.service.unavailable`, and `sdwan.service.skipped` by operation and group | SD-WAN Manager auth, permission, rate-limit, endpoint, feature/license, target-scope, manager, or stale-data gaps distort visibility. |
| SD-WAN overlay health | `sdwan.resource.status`, `cisco.device.up`, `sdwan.control.connection.status`, `sdwan.control.connection.count`, `sdwan.control.actual_connections`, `sdwan.control.expected_connections`, `sdwan.bfd.session.status`, and `sdwan.bfd.session.count` by system IP, site, personality, and color | WAN Edge, controller, TLOC, or BFD overlay health degrades. |
| SD-WAN app and AI path quality | `sdwan.app_route.latency`, `sdwan.app_route.jitter`, `sdwan.app_route.loss`, and `sdwan.app_route.sla.status` by site, application, SLA class, and local/remote color | SaaS, model/API, RAG, edge-to-cloud, or custom application paths violate SLA or shift transport. |
| SD-WAN interfaces and circuits | `system.network.interface.status`, `sdwan.transport.interface.status`, `system.network.io`, `system.network.errors`, `system.network.packet.dropped`, and `cisco.interface.speed` by site, device, interface, VPN, and color | WAN circuit, interface, cellular failover, or capacity pressure aligns with incident impact. |
| SD-WAN events and change evidence | `sdwan.event.count` plus SD-WAN logs by alarm/event/audit type, severity, user, policy, system IP, and site | Alarms, audit/config changes, policy deployments, or security events appear in the incident window. |
| SD-WAN end-user impact | `sdwan.app_route.*`, `sdwan.app_route.sla.status`, `sdwan.bfd.session.status`, `system.network.interface.status`, `system.network.errors`, `system.network.packet.dropped`, and `sdwan.event.count` by site, application, SLA class, color, interface, and event type | Service desk, app owners, and incident commanders can see which sites/apps/users are likely affected and what symptom class to escalate. |
| ISE identity and access evidence | `ise.api.request.errors`, `ise.scrape.partial_success`, `ise.radius.failure.count`, `ise.tacacs.failure.count`, `ise.session.active.count`, `ise.endpoint.posture.count`, `ise.policy.object.count`, `ise.trustsec.resource.count`, pxGrid metrics, Data Connect metrics, and ISE logs | Authentication, authorization, posture, TrustSec, or policy-change evidence aligns with network, wireless, SD-WAN, or firewall symptoms. |
| Catalyst 9800 WLC telemetry trust | `cisco.catalyst9800.receiver.*` and `cisco.wlc.controller.*` by controller and transport | Active subscriptions drop, decode errors rise, paths are unsupported, datapoints are dropped, or controller CPU/memory pressure appears. |
| Catalyst 9800 wireless user impact | `cisco.wlc.ap.*`, `cisco.wlc.rf.*`, `cisco.wlc.ssid.*`, `cisco.wlc.client.*`, `cisco.wlc.auth.radius.*`, `cisco.wlc.mobility.*`, and `cisco.wlc.ha.*` by AP, SSID, client, and controller | AP joins fail, RF utilization/noise rises, clients fail auth or roam, RADIUS rejects/timeouts appear, mobility peers fail, or HA changes. |
| IOS XR telemetry trust and model coverage | `cisco.iosxr.receiver.*` plus common `cisco.iosxr.yang.*` interface and model leaves by router, transport, YANG module, and path | Subscriptions stop, updates stall, decode/model errors rise, or common interface/routing/optics path groups stop producing data. |
| Nexus Dashboard API health | `nexus_dashboard.api.request.duration`, `nexus_dashboard.api.request.errors`, `nexus_dashboard.api.rate_limited`, and `nexus_dashboard.scrape.partial_success` by operation | Controller API errors, authorization failures, unavailable apps, or partial scrape repeat. |
| Nexus Dashboard service coverage | `nexus_dashboard.service.unavailable` and `nexus_dashboard.service.skipped` by product and group | NDFC, Insights, NDO, or Data Broker is unavailable, unauthorized, not installed, or missing target filters. |
| Nexus Dashboard change and event evidence | `nexus_dashboard.audit.record.count` and `nexus_dashboard.event.count` by product, operation, status, and severity | Controller-side changes, events, anomalies, advisories, alerts, or root causes appear near the incident window. |
| NDFC fabric and switch health | `nexus_dashboard.fabric.health`, `nexus_dashboard.resource.status`, and `cisco.device.up` by fabric, switch, role, and serial | Fabric or leaf/spine health degrades from the controller view. |
| NDFC config and deployment state | `nexus_dashboard.config.compliance`, `nexus_dashboard.deployment.status`, and NDFC logs | Config drift, failed policy deployment, image/change-control activity, or recent audit evidence appears. |
| Insights anomalies and root cause | `nexus_dashboard.insights.anomaly.count`, `nexus_dashboard.insights.score`, and `nexus_dashboard.insights.confidence` by site/fabric/severity | Insights points to a root-cause candidate or advisory during the incident window. |
| NDO/OneManage deployment drift | `nexus_dashboard.orchestrator.deployment.status` and `nexus_dashboard.orchestrator.policy_delta.count` by site/schema | Multi-site deployment or policy sync fails. |
| Data Broker visibility health | `nexus_dashboard.data_broker.status`, `nexus_dashboard.data_broker.rule.count`, and `nexus_dashboard.data_broker.session.count` | TAP/SPAN/rule/session state prevents packet visibility during troubleshooting. |
| APIC API health | `aci.api.request.duration`, `aci.api.request.errors`, `aci.controller.up`, and `aci.scrape.partial_success` by controller | APIC access or class-query coverage is degraded. |
| ACI active faults | `aci.fault.count` and `aci.fault.active` by severity, code, domain, type, node, and DN | Active ACI faults explain fabric, tenant, endpoint, or interface symptoms. |
| ACI change and event evidence | `aci.audit.record.count` and `aci.event.count` by operation, status, and severity | APIC audit or event activity appears near the fault window without high-cardinality event text in metric labels. |
| ACI tenant impact | `aci.tenant.status`, `aci.tenant.object.count`, and `aci.fabric.health` by tenant, VRF, BD, EPG, and L3Out | Tenant policy or health changed near affected workloads. |
| ACI endpoint presence | `aci.endpoint.present` and `aci.endpoint.count` by tenant, EPG, MAC, IP, and node | Workload endpoint disappeared, moved, or churned. |
| ACI topology and interface symptoms | `system.network.interface.status`, `cisco.interface.io.rate`, and `cisco.topology.neighbor.info` by node/interface/protocol | Leaf/spine interface or adjacency change precedes endpoint impact. |

Autopsy questions:

- Did telemetry stop because the device failed, the receiver failed, or only a command family failed?
- Was the interface administratively shut, operationally down, saturated, erroring, dropping, or speed-downgraded?
- Did routing adjacency loss, route/FIB divergence, VXLAN/EVPN state, LACP, STP, vPC, or port-channel member loss precede the impact?
- Did ECN marks appear before PFC and drops, or did the fabric jump straight to backpressure or loss?
- Did GPU job slowdown align with PFC pause frames, ECN marks, PFC watchdog activity, or queue drops?
- Did optics, hardware temperature, or hardware state change before errors or pause frames appeared?
- Did Intersight record an alarm, advisory, HCL change, workflow/task failure, or audit/config-change log before the impact?
- Did UCS, HyperFlex, storage, Kubernetes, or VM state degrade around the same host, serial, cluster, namespace, or workload?
- Did Catalyst Center show API partial success, site health degradation, active Assurance issues, topology changes, or poor targeted client health?
- Did Catalyst 9800 show stale telemetry, AP join/CAPWAP failures, RF noise or utilization, RADIUS rejects/timeouts, client roam failures, mobility peer loss, or HA events for the affected SSID or site?
- Did SD-WAN show Manager/API partial success, unreachable WAN Edge devices, control/BFD loss, TLOC color degradation, app-route SLA violations, Cloud OnRamp/vQoE issues, policy/security drops, cellular failover, or audit/config changes for the affected site or application?
- From the end-user perspective, which sites and applications are affected, what symptom is most visible to users (loss, latency, jitter, outage, drops, errors, or change), and which team should own the next action?
- Did Nexus Dashboard show NDFC config drift, deployment failure, fabric health degradation, Insights root-cause evidence, NDO policy deltas, or Data Broker visibility changes?
- Did APIC show active faults, tenant/EPG/contract/L3Out impact, endpoint disappearance, interface state changes, or topology churn for the affected workload?
- Did IOS XR telemetry show subscription loss, unsupported paths, interface state/counter changes, optics drift, routing neighbor loss, FIB drops, BFD changes, MPLS/SR state changes, or time-sync issues?

Switch-side coverage:

- The Cisco OS receiver can show ECN/WRED marks, PFC pause frames, PFC watchdog drains/drops, queue drops, link errors, link pressure, optics, port-channel/vPC state, and VXLAN/EVPN/routing health.
- The receiver does not observe endpoint-only RDMA symptoms such as CNP packets, retransmits, timeout or retry errors, RNR NAKs, QP errors, RDMA CM failures, GID selection, or pod/container RDMA device exposure.
- For full RoCEv2 autopsy, ingest host/NIC metrics alongside these switch dashboards and correlate by host, interface, DSCP/PCP/traffic class, MTU, and job or Kubernetes node labels.
- Intersight metrics and logs add the management-plane evidence for UCS, HyperFlex, storage, Kubernetes, and virtualization resources so AI pod dashboards can correlate fabric symptoms with affected host serials, clusters, namespaces, and workloads.
- SD-WAN app-route and Cloud OnRamp evidence add the WAN/application half of the AI story: whether model API, SaaS AI assistant, RAG data, or edge-to-cloud inference traffic saw path loss, latency, jitter, transport shift, service insertion, or policy/SLA drops.

## Detector Starting Set

Start with these detectors before adding organization-specific thresholds:

| Detector | Signal | Suggested Condition |
| --- | --- | --- |
| Device unreachable | `cisco.device.up` | Equals `0` for 2-3 scrapes. |
| Receiver partial scrape | `cisco.scrape.partial_success` | Equals `1` for 3 scrapes. |
| Enabled interface down | `cisco.interface.admin.status` and `system.network.interface.status` | Admin is `1` and oper is `0`. |
| Link saturation | `cisco.interface.utilization` | Above 80-90 percent for critical uplinks. |
| Interface errors | Rate of `system.network.errors` | Above baseline or non-zero on clean links. |
| Interface drops | Rate of `system.network.packet.dropped` | Sustained growth on critical paths. |
| Routing neighbor down | `cisco.routing.neighbor.state` | Equals `0` for required peers. |
| Hardware warning | `cisco.hardware.status` | Critical or warning state. |
| Optics degradation | `cisco.transceiver.sensor` | RX/TX power or temperature outside platform policy. |
| LACP member loss | `cisco.port_channel.member.status` | Member equals `0` while port-channel remains up. |
| STP churn | Rate of `cisco.l2.stp.topology_changes` | Repeated changes in a short interval. |
| RoCEv2 control-loop regression | ECN marks, PFC pause frames, queue drops, and PFC watchdog activity | Drops or watchdog activity appears, or PFC rises without prior ECN marking. |
| QoS congestion | Rate of QoS drop metrics or pause frames | Sustained growth during workload degradation. |
| QFP dataplane drops | Rate of `cisco.qfp.drops` or `cisco.qfp.interface.drops` | New or rising drop reasons. |
| Intersight critical alarm | `intersight.alarm.count` | Critical or fatal alarms greater than 0 for one or more scrapes. |
| Intersight workflow failure | `intersight.workflow.status` or `intersight.task.status` | Encoded status is failed/error for 1-2 scrapes. |
| Intersight API degraded | `intersight.api.request.errors` or `intersight.scrape.partial_success` | Errors or partial success repeat for 2-3 scrapes. |
| Intersight storage risk | `intersight.storage.predictive_failure.count` or `intersight.storage.life_left` | Predictive failures appear or SSD life falls below policy. |
| Catalyst Center API degraded | `catalyst_center.api.request.errors` or `catalyst_center.scrape.partial_success` | Errors or partial success repeat for 2-3 scrapes. |
| Catalyst Center site unhealthy | `catalyst_center.site.network_device.health.percentage` or `catalyst_center.site.client.health.percentage` | Site health falls below policy or drops sharply from baseline. |
| Catalyst Center active issues | `catalyst_center.issue.active.count` | P1/P2 or high-severity issue counts are greater than 0. |
| Catalyst 9800 telemetry degraded | `cisco.catalyst9800.receiver.decode_errors`, `cisco.catalyst9800.receiver.unsupported_paths`, or `cisco.catalyst9800.receiver.dropped_datapoints` | Decode, model coverage, or cardinality guardrail counters rise for 2-3 scrapes. |
| Catalyst 9800 AP or CAPWAP issue | `cisco.wlc.ap.join.status`, `cisco.wlc.ap.capwap.state`, `cisco.wlc.ap.join.failure.reason.info`, or `cisco.wlc.ap.disconnect` | Important APs are not joined, CAPWAP is unhealthy, or join/disconnect evidence rises. |
| Catalyst 9800 client or AAA issue | `cisco.wlc.client.connection.state`, `cisco.wlc.client.auth.failure.reason.info`, `cisco.wlc.auth.radius.access.reject.count`, or `cisco.wlc.auth.radius.timeout.count` | Clients fail to connect, auth failures rise, RADIUS rejects/timeouts increase, or response delay degrades. |
| SD-WAN API degraded | `sdwan.api.request.errors`, `sdwan.scrape.partial_success`, `sdwan.service.unavailable`, or `sdwan.service.skipped` | Errors, partial success, unavailable feature groups, or missing target scope repeat for 2-3 scrapes. |
| SD-WAN overlay degraded | `sdwan.control.connection.status`, `sdwan.control.actual_connections`, `sdwan.control.expected_connections`, or `sdwan.bfd.session.status` | Control connections or BFD sessions are down, partial, or below expected count. |
| SD-WAN app SLA violation | `sdwan.app_route.latency`, `sdwan.app_route.jitter`, `sdwan.app_route.loss`, or `sdwan.app_route.sla.status` | Critical app, SaaS, or AI/model path exceeds SLA thresholds or enters failed/degraded state. |
| SD-WAN WAN interface issue | `system.network.interface.status`, `sdwan.transport.interface.status`, `system.network.errors`, or `system.network.packet.dropped` | Admin-up WAN interfaces are down, erroring, dropping, or showing sudden traffic silence. |
| SD-WAN change evidence | `sdwan.event.count` and SD-WAN logs | Critical alarm, audit/config change, policy deployment, or security event appears in the incident window. |
| Nexus Dashboard API degraded | `nexus_dashboard.api.request.errors` or `nexus_dashboard.scrape.partial_success` | Errors, unavailable services, skipped endpoint families, or partial success repeat. |
| NDFC fabric unhealthy | `nexus_dashboard.fabric.health` or `nexus_dashboard.resource.status` | Fabric, site, or switch health score/status degrades. |
| Insights critical anomaly | `nexus_dashboard.insights.anomaly.count` | Critical anomalies or advisories greater than 0. |
| NDO deployment failure | `nexus_dashboard.orchestrator.deployment.status` | Deployment, schema, template, or site sync state is failed/degraded. |
| APIC fault present | `aci.fault.count` | Critical or major faults greater than 0. |
| ACI endpoint missing | `aci.endpoint.present` or `aci.endpoint.count` | Important endpoint is missing or endpoint count drops unexpectedly. |
| IOS XR telemetry stale | `cisco.iosxr.receiver.updates`, `cisco.iosxr.receiver.last_success_timestamp`, or `cisco.iosxr.receiver.reconnects` | Update rate stops, last success stops advancing, or reconnects rise. |
| IOS XR interface issue | Common `cisco.iosxr.yang.openconfig_interfaces.*` state, error, discard, and octet counters | Admin-up/oper-down, traffic silence, error/discard growth, or one-way traffic appears. |

## Incident Autopsy Workflow

Use this sequence when reconstructing an outage:

1. Confirm telemetry trust: check `cisco.device.up`, `cisco.scrape.partial_success`, command errors, command duration, and SSH reconnects.
2. Check reboot or reload evidence: inspect `system.uptime` around the incident window.
3. Find failed links: compare `cisco.interface.admin.status` with `system.network.interface.status`.
4. Look for link symptoms: inspect interface utilization, errors, drops, and packet rates before the first alert.
5. Check topology churn: review port-channel members, LACP errors, STP topology changes, err-disabled ports, vPC status, and topology neighbors.
6. Check routing and overlay: review routing neighbors, route counts, prefixes, NVE peers, VNIs, and EVPN route counts.
7. Check physical health: review hardware status, temperature, and transceiver sensors.
8. Check congestion: inspect PFC pause frames, QoS queue drops, policy drops, WRED/ECN signals, QFP drops, and forwarding drops.
9. Check wireless evidence: review Catalyst 9800 AP joins, CAPWAP state, RF utilization/noise, RADIUS outcomes, client state, roaming, mobility peers, and HA state for the same site, SSID, AP, or client.
10. Check controller evidence: review Intersight alarms/advisories/workflows, Catalyst Center Assurance health/issues/client detail, Nexus Dashboard/NDFC/Insights/NDO/Data Broker evidence, and APIC faults/audits/events for the same switch serial, site, fabric, tenant, endpoint, or workload.
11. Check IOS XR service evidence: review subscription freshness, interface counters, optics, routing/BFD/MPLS/SR state, FIB drops, and time-sync breadcrumbs for affected routers.
12. Correlate AI pod impact: align UCS/FI/HyperFlex health with Kubernetes namespace/workload, accelerator, Catalyst Center site/client context, ACI tenant/EPG, NDFC fabric, and switch telemetry.

For a fuller autopsy, pair these metrics with syslog or config-change events in Splunk. Metrics tell you what moved; logs and events often tell you who or what changed it.

## References

- [Splunk Observability Cloud OTLP/HTTP exporter](https://help.splunk.com/en/splunk-observability-cloud/manage-data/splunk-distribution-of-the-opentelemetry-collector/get-started-with-the-splunk-distribution-of-the-opentelemetry-collector/collector-components/exporters/otlphttp-exporter) for the `metrics_endpoint` and `X-SF-Token` configuration pattern.
- [Splunk Observability Cloud Chart Builder](https://help.splunk.com/en/splunk-observability-cloud/create-dashboards-and-charts/create-charts/plot-metrics-and-events-using-chart-builder) for chart signals, filters, dimensions, and analytics.
- [Splunk Observability Cloud detector best practices](https://help.splunk.com/en/splunk-observability-cloud/create-alerts-detectors-and-service-level-objectives/create-alerts-and-detectors/best-practices-for-creating-detectors) for threshold, duration, and population-style detector design.
- [Cisco Data Center Networking Blueprint for AI/ML Applications](https://www.cisco.com/c/en/us/td/docs/dcn/whitepapers/cisco-data-center-networking-blueprint-for-ai-ml-applications.html) for RoCEv2, PFC, ECN, and AI/ML data center fabric design context.
- [Cisco Nexus 9000 NX-OS Priority Flow Control configuration guide](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/102x/qos/configuration/guide/cisco-nexus-9000-nx-os-quality-of-service-configuration-guide-102x/m-configuring-priority-flow-control.html) for PFC and PFC watchdog behavior.
- [NVIDIA RoCE documentation](https://docs.nvidia.com/networking/display/Onyxv3104006/RDMA%2BOver%2BConverged%2BEthernet%2B%28RoCE%29) for RDMA, RoCE, ECN, CNP, and RoCE congestion management context.
- [NVIDIA flow control documentation](https://docs.nvidia.com/networking/display/FREEBSDv371/Flow%2BControl) for global pause, PFC, and ECN behavior relevant to RoCE fabrics.
