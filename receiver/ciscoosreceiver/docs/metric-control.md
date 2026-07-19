# Controlling Metrics And Splunk Observability Cost

This guide explains how to decide which Cisco OS receiver metrics are sent to a downstream destination such as Splunk Observability Cloud. It is written for operators and for AI agents editing Collector configs.

The short version:

1. Enable only the Cisco platforms you need.
2. Disable whole collection groups before disabling individual metrics.
3. Scope collection with `targets` and `device_selection`.
4. Cap returned objects with `max_results`.
5. Use root-level `metrics.<metric_name-or-glob>.enabled: false` for final drops.
6. Keep logs and metrics decisions separate.

## Mental Model

Splunk Observability Cloud cost and cardinality are affected by how many metric time series and datapoints are sent. A metric time series is usually the combination of:

- the metric name,
- the resource identity, such as `host.id` or a controller endpoint,
- datapoint attributes, such as interface, direction, site, application, severity, or status,
- collection frequency.

For example, one interface metric can become many time series when it is emitted for hundreds of devices, every interface, both directions, and several statuses. The receiver therefore gives users several layers of control.

## Control Order

Use the controls in this order. Earlier controls prevent work and reduce emitted telemetry more cleanly.

| Control | Best for | What it changes | What it does not change |
| --- | --- | --- | --- |
| Platform enablement | Turning off an entire source, such as SD-WAN, Intersight, or ACI | Stops that platform receiver from running | Other enabled platforms |
| Collection groups | Turning off a domain, such as SD-WAN interfaces or Intersight telemetry | Stops that endpoint family or command family from being collected and emitted | Metrics from other enabled groups |
| Provider `targets` | Scoping to sites, serials, applications, tenants, fabrics, or interfaces | Often reduces provider API query scope and emitted telemetry | Shared SSH device selection |
| `device_selection` | Applying one shared include/exclude selector across platforms | Filters emitted telemetry by host name, host ID, host IP, serial, or provider device ID | Provider API calls that are not target-aware |
| `max_results` | Bounding returned objects per collection group | Limits records processed per scrape | The number of datapoint attributes per returned object |
| Root `metrics` | Removing exact metric names or metric-name globs from the metrics pipeline | Drops matching metrics before forwarding to downstream components | API calls, SSH commands, logs, or other metrics |
| Downstream processors/exporters | Last-mile policy outside this receiver | Can enforce org-wide filtering | Receiver-side polling cost |

Prefer collection groups when you do not need a domain at all. Use root `metrics` when you want most of a group but need to suppress a few metric names.

## Root Metric Filter

Root-level `metrics` controls exact metric names and metric-name globs. Metrics are enabled unless explicitly disabled.
Exact metric names override matching globs, so a broad drop can keep a specific metric by setting the exact name to
`enabled: true`.

```yaml
receivers:
  cisco_os:
    metrics:
      sdwan.app_route.loss:
        enabled: false
      system.network.errors:
        enabled: false
```

Write exact metric names as emitted. Dots are part of the metric name, not nested YAML paths. Quoting is optional:

```yaml
receivers:
  cisco_os:
    metrics:
      "system.network.packet.dropped":
        enabled: false
```

Use globs for generated metric families, especially direct YANG telemetry:

```yaml
receivers:
  cisco_os:
    metrics:
      cisco.wlc.client.*:
        enabled: false
      cisco.iosxr.yang.__v1.m1.s29_Cisco_2DIOS_2DXR_2Dip_2Drib_2Dipv4_2Doper.*:
        enabled: false
      cisco.iosxr.yang.__v1.m1.s29_Cisco_2DIOS_2DXR_2Dip_2Drib_2Dipv4_2Doper.p6.s3_rib.s13_rib_2Dtable_2Dids.s12_rib_2Dtable_2Did.s14_summary_2Dprotos.s13_summary_2Dproto.s11_route_2Dcount.n:
        enabled: true
```

This filter applies to metrics from SSH scrapers and API platforms. It does not drop logs. To stop logs, remove the receiver from the logs pipeline or disable the platform groups that produce event logs.
For IOS XR, root metric filtering runs after YANG paths are encoded into `cisco.iosxr.yang.__v1.*` or
`cisco.iosxr.receiver.*` metric names. For Catalyst 9800, it runs after both `cisco.catalyst9800.yang.__v1.*` metrics and
`cisco.wlc.*` aliases are generated.

The framed strings are exact and case-sensitive. The first rule above disables the raw module
`Cisco-IOS-XR-ip-rib-ipv4-oper`; the second re-enables the direct-gNMI raw path tuple
`rib/rib-table-ids/rib-table-id/summary-protos/summary-proto/route-count`. Use
`cisco.iosxr.yang.__v1.*` when a broad all-dynamic selector is preferable.

## Collection Groups

Collection groups are the main control for cost and API load. A disabled group should not poll or emit that domain.

```yaml
receivers:
  cisco_os:
    sdwan:
      enabled: true
      endpoint: https://sdwan-manager.example.com
      auth:
        username: ${env:SDWAN_USERNAME}
        password: ${env:SDWAN_PASSWORD}
      interfaces:
        enabled: false
      flows:
        enabled: false
      policy_qos:
        enabled: false
      app_route:
        enabled: true
        max_results: 1000
```

If a dashboard panel depends on a disabled group, that panel will be empty. This is expected and is usually better than collecting high-volume data that nobody uses.

## Target Filters

Provider-native `targets` are the best way to keep large controller APIs focused. They also document operator intent clearly.

```yaml
receivers:
  cisco_os:
    sdwan:
      targets:
        site_ids: ["100", "200"]
        applications: ["openai-api", "crm"]
        colors: ["biz-internet"]
    nexus_dashboard:
      targets:
        fabrics: ["prod-fabric"]
        switch_serials: ["N9K-SERIAL-1"]
        interface_names: ["eth1/1", "eth1/2"]
    aci:
      targets:
        tenants: ["prod"]
        node_ids: ["101", "102"]
```

Use `device_selection` when the same receiver config covers multiple providers and the same devices must be included or excluded everywhere.

```yaml
receivers:
  cisco_os:
    device_selection:
      include:
        serials: ["FOC1234", "SDWAN-SERIAL-1", "N9K-SERIAL-1"]
      exclude:
        serials: ["LAB-DO-NOT-COLLECT"]
```

`exclude` always wins. Empty `include` fields mean "include all that pass provider targets."

For SSH targets, the receiver applies host-name and serial selection after `show version` discovers the device identity; a configured host IP can be rejected before the connection is created. Shared `gnmi.targets` expose their configured target name, endpoint, and endpoint host, but do not currently discover a serial or provider device ID for selection. Scope those targets with `host_names`, `host_ids`, or `host_ips`.

## Platform Guidance

Use this table when deciding what to enable.

| Platform or scraper | Lower-volume starting point | Higher-volume or specialized areas |
| --- | --- | --- |
| SSH `system` scraper | Device up, CPU, memory, uptime, scrape health | protocol traffic, control plane, routing/forwarding, router dataplane, hardware, routing neighbors, VXLAN/EVPN fabric |
| SSH `interfaces` scraper | Interface status, byte/packet/error/drop counters from normal interface output | rates, detailed counters, QoS, pause/PFC, L2 topology, transceiver sensors |
| Meraki | Organization and device status, uplinks, switch/wireless/VPN health | Broad organization coverage across many networks and product families |
| Intersight | Inventory, resource status, alarms, advisories, workflows, tasks | telemetry, equipment, storage, HyperFlex, Kubernetes, virtualization |
| Catalyst Center | Inventory, interfaces, health, topology, issues | targeted device-detail and client-detail lookups |
| SD-WAN | Manager, inventory, control plane, BFD, app-route, interfaces, alarms, events, audit | realtime details, tunnels, flows, policy/QoS, security, AppQoE, Cloud OnRamp, NWPI, underlay, cellular, hardware/energy, routing services, branch services, lifecycle/compliance, ThousandEyes, management security |
| Nexus Dashboard | Platform, NDFC, Insights, Orchestrator, Data Broker summaries | performance and broad interface/fabric detail |
| ACI | Controller health, fabric, nodes, faults, audit, events | stats, endpoints, tenants, topology across large fabrics |
| FMC | REST manager/version/license state, inventory, health, VPN, HA, deployments, audit, and bounded policy/object state | eStreamer security events, broad object/rule sweeps, per-device interface/routing/chassis detail, health aggregate metrics, and pending-change detail |
| Catalyst 9800 | Default AP/RF/SSID/mobility/HA/auth/controller groups, safe path minimum sample intervals, and `max_datapoints_per_batch` | client detail, CAPWAP packets, neighbors, broad custom YANG paths, and low sample intervals |
| IOS XR | A small set of enabled path groups with 60s+ sample intervals, such as interfaces, optics, and BGP, plus `max_datapoints_per_batch` | high-volume routing tables, FIB/CEF, QoS, ASIC, SR/SRv6, and broad native paths |
| ISE | Scalar MnT active, posture, and profiler session counts | Opt-in `session_details` row evidence; release-, feature-, and ERS-dependent REST groups; pxGrid; broad Data Connect historical views; and high-volume endpoint/session evidence |

## Common Recipes

### Minimal SD-WAN App Experience

Use this when the goal is to watch a few critical apps or sites without collecting every feature domain.

```yaml
receivers:
  cisco_os:
    collection_interval: 60s
    sdwan:
      enabled: true
      endpoint: https://sdwan-manager.example.com
      auth:
        username: ${env:SDWAN_USERNAME}
        password: ${env:SDWAN_PASSWORD}
      targets:
        site_ids: ["100"]
        applications: ["openai-api"]
        colors: ["biz-internet"]
      app_route:
        enabled: true
        max_results: 500
      interfaces:
        enabled: false
      flows:
        enabled: false
      policy_qos:
        enabled: false
      security:
        enabled: false
      cloud_onramp:
        enabled: false
```

### Keep Interface Health, Drop Expensive Metric Names

Use this when interface state and traffic are useful but a destination does not need specific error or loss metrics.

```yaml
receivers:
  cisco_os:
    metrics:
      system.network.errors:
        enabled: false
      system.network.packet.dropped:
        enabled: false
```

This does not stop interface polling. Disable the relevant collection group if you do not want the receiver to collect interface data at all.

### Focus ACI On Faults And Fabric Health

```yaml
receivers:
  cisco_os:
    aci:
      enabled: true
      controllers:
        - endpoint: https://apic1.example.com
      auth:
        username: ${env:ACI_USERNAME}
        password: ${env:ACI_PASSWORD}
      targets:
        tenants: ["prod"]
        node_ids: ["101", "102"]
      faults:
        enabled: true
        max_results: 500
      stats:
        enabled: false
      endpoints:
        enabled: false
      tenants:
        enabled: false
```

### Reduce SSH Optional Metrics

```yaml
receivers:
  cisco_os:
    scrapers:
      system:
        protocol_traffic:
          enabled: false
        router_dataplane:
          enabled: false
        routing_neighbors:
          enabled: false
      interfaces:
        rates:
          enabled: false
        counters:
          enabled: false
        transceiver:
          enabled: false
```

## Logs Are Separate

Root `metrics` entries do not affect logs. Several controller platforms emit logs for operational evidence, such as audit records, alarms, advisories, faults, events, workflow failures, and tech-support status.

To control logs:

- omit the receiver from the `logs` pipeline,
- disable collection groups that produce event logs, such as `sdwan.audit`, `aci.events`, `intersight.audit`, or `fmc.audit`; disable `fmc.estreamer.enabled` to stop eStreamer event ingestion,
- use a log processor downstream if an organization needs log-specific filtering.

## Validation Workflow

Use this workflow after changing metric controls:

1. Start with a small target scope, such as one site, one serial, one fabric, or one tenant.
2. Send data to a debug or file exporter in a non-production Collector.
3. Confirm expected metric names appear.
4. Confirm disabled metric names and glob families do not appear.
5. Confirm dashboards that depend on disabled groups are intentionally empty.
6. Increase target scope gradually.
7. Watch API request error, rate-limit, partial-success, and service-skipped metrics.

Useful receiver health metrics include:

- `cisco.scrape.partial_success`
- `cisco.scrape.command.errors`
- `meraki.api.request.errors`
- `intersight.api.request.errors`
- `catalyst_center.api.request.errors`
- `sdwan.api.request.errors`
- `sdwan.service.skipped`
- `nexus_dashboard.service.unavailable`
- `aci.api.request.errors`

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| A metric still appears in Splunk | The metric name is misspelled or another receiver emits the same metric | Copy the exact metric name from emitted telemetry and check other pipelines |
| A dashboard panel is empty | Its collection group or metric is disabled | Enable the supporting group or remove the metric filter |
| API request metrics still appear after a group is disabled | Another group still calls that API family | Check enabled groups and operation attributes |
| Splunk cost is still high | Target scope, attribute cardinality, or collection interval is still broad | Reduce targets, lower `max_results`, disable optional groups, or increase `collection_interval` |
| Logs are still arriving | Root `metrics` filters do not affect logs | Adjust the logs pipeline or log-producing groups |

## AI Agent Checklist

When an AI agent is asked to control metrics, follow this checklist:

1. Identify the destination and reason for control, such as Splunk Observability cost, API load, dashboard focus, or lab exclusion.
2. Locate the exact metrics in `receiver/ciscoosreceiver/docs/metrics.md` or in dashboard SignalFlow.
3. Prefer disabling collection groups when all metrics from a domain are unnecessary.
4. Add provider `targets` or shared `device_selection` before broadening collection.
5. Use `max_results` for any enabled group that can return many objects.
6. Use root `metrics` only for exact per-metric drops.
7. Do not enable opt-in or high-volume groups globally without a stated user need.
8. Update examples and tests when adding new platform metrics or control surfaces.
9. Explain the effect clearly: whether the change stops polling, reduces emitted telemetry, or only drops named metrics.

The most important distinction is this: group and target controls reduce what the receiver collects; root `metrics` controls what the receiver forwards.
