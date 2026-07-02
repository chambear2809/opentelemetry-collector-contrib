# Draft: Observability Cloud and Endpoint Observability

Working title: Collect What Matters: Cisco IT's Pilot Strategy for Cost-Aware Observability

Byline: Aaron [Last Name] with [team names]

Draft status: Working draft for Cisco-on-Cisco Marketing review. This is intentionally pilot-safe: it explains the collection strategy and avoids claiming production outcomes from the pilot.

## Collect What Matters: Cisco IT's Pilot Strategy for Cost-Aware Observability

In our recent Cisco-on-Cisco blog, we shared how Cisco IT is transforming observability from fragmented data into unified insights. That work is helping us bring together signals from across our environment so teams can move faster, reduce noise, and make better operational decisions.

As a follow-up, we want to share how we are approaching the next practical question: once you can observe more of the stack, how do you decide what telemetry is actually worth collecting?

That question matters because full-stack observability does not mean collecting every available metric from every source at every interval. The value of observability comes from the ability to connect the right signals to the right business and operational questions. The cost comes from the volume, frequency, and dimensionality of the telemetry we send and store.

Our current pilot with Splunk Observability Cloud and Endpoint Observability is focused on that balance. We are not yet using this post to report broad production outcomes from the metrics. Instead, this is about the strategy we are using to decide what to collect, what to defer, and how to keep the telemetry footprint aligned to business value.

## Why "collect everything" does not scale

Modern environments generate telemetry from many layers: endpoints, applications, infrastructure, wireless, WAN, campus networks, data center fabrics, identity systems, security platforms, and cloud services. Each layer has valuable signals, but each signal can multiply quickly.

For metrics, volume is driven by more than the metric name. A metric time series is shaped by the metric, the resource identity, the attributes or dimensions on the datapoint, and the collection frequency. One interface metric, for example, can become thousands of time series when it is collected across many devices, interfaces, directions, sites, statuses, and applications.

Endpoint Observability adds another important dimension because it helps connect technical health to user and device experience. But endpoints can be numerous, mobile, and context-rich. Without guardrails, the same context that makes endpoint data valuable can also create avoidable telemetry volume.

So our pilot strategy is simple: start with the questions that matter, collect the minimum useful signal to answer them, and expand only when there is a clear operational reason.

## Our multipoint collection strategy

We are using a layered control model to keep telemetry focused while still preserving visibility across the stack.

### 1. Start with the business and operational question

Before enabling a new telemetry group, we ask what decision it should support. Is the goal to understand whether a critical site is healthy? Whether an application path is degrading? Whether endpoint authentication failures are increasing? Whether a wireless controller, WAN edge, fabric switch, or identity system is contributing to a user-impacting incident?

That question determines the starting signal set. In many cases, we begin with lower-volume health and trust metrics: availability, scrape health, API errors, reachability, CPU, memory, interface state, traffic, errors, drops, site health, active issues, authentication failures, and application path quality.

This gives operators a useful baseline without turning on every detailed troubleshooting metric on day one.

### 2. Enable only the platforms and domains we need

The collection architecture is modular. We can enable Cisco telemetry from sources such as network devices, Meraki Dashboard, Intersight, Catalyst Center, Catalyst SD-WAN Manager, Nexus Dashboard, APIC, Cisco Secure Firewall Management Center, Cisco ISE, Catalyst 9800, and IOS XR telemetry.

Within those sources, we use collection groups to control whole domains of telemetry. If we do not need broad SD-WAN flow data, high-volume client detail, fabric stats, pxGrid streaming, or detailed YANG path groups for a pilot scenario, we leave those groups off. This is more efficient than collecting everything and dropping it later because it reduces polling, processing, and downstream ingest.

The principle is to keep broad health visible while making deep troubleshooting data intentional.

### 3. Scope collection to the relevant targets

The next control is target scope. We can focus collection by site, serial number, device ID, host name, interface, application, tenant, fabric, endpoint, policy, or controller object.

This matters for both cost and clarity. A pilot for a specific application path does not need every application in every site. A wireless investigation may need targeted SSIDs, APs, clients, or controller path groups. An identity workflow may need selected ISE endpoint, session, or authentication evidence rather than every available record.

Scoping also documents intent. When the configuration names the sites, applications, tenants, or endpoints we care about, reviewers can see why the data is being collected.

### 4. Bound high-cardinality data before it expands

Some telemetry is useful only when it is bounded. Detailed interface counters, queue and QoS data, routing neighbors, optical transceiver metrics, wireless client detail, endpoint/session evidence, and native telemetry paths can all expand quickly.

For those areas, we use controls such as maximum result counts, safe sample intervals, path groups, datapoint batch limits, and metric allow/deny switches. These controls help us prevent a pilot from becoming an unbounded ingest pattern.

This is especially important for Endpoint Observability, where the most valuable context is often attached to users, devices, sessions, posture, access policy, or location. We want that context when it explains business impact, but we do not want every high-cardinality field promoted into a metric dimension by default.

### 5. Keep metrics and evidence separate

Metrics are best for trends, alerting, thresholds, service health, and dashboards. Logs and events are better for detailed operational evidence: audit records, fault payloads, advisories, authentication details, deployment records, security events, and change context.

In the pilot strategy, we avoid turning every event field into a metric label. Instead, we keep metrics bounded and use logs for richer, high-cardinality evidence when incident context requires it.

This lets us preserve troubleshooting depth without forcing every unique user, endpoint, event body, or failure message into the metric time-series model.

### 6. Model the footprint before expanding

We also built a metric volume calculator to estimate active metric time series, datapoints per minute, datapoints per day, and datapoints per month before enabling broader collection. The model uses editable assumptions for devices, interfaces, sites, applications, endpoints, clients, queues, resources, and path groups.

The point is not to predict every number perfectly. Some Cisco command output, API response sizes, and endpoint populations are data-dependent. The point is to make the tradeoff visible before we scale.

When we enable a new group, we validate in a small scope first, confirm expected metric names and dimensions, confirm that disabled groups stay quiet, and then expand gradually.

## What this looks like in practice

For SD-WAN, a low-volume starting point may focus on manager/API trust, inventory, control-plane health, BFD sessions, application route latency, jitter, loss, and SLA status for selected sites and applications. More specialized areas such as realtime detail, flows, security, policy/QoS, AppQoE, Cloud OnRamp, and network-wide path insight can be enabled only when a workflow needs them.

For Catalyst Center, the pilot can start with inventory, reachability, site and network health, topology summaries, and active issues. Device-detail and client-detail lookups are intentionally scoped to known devices or clients instead of collected broadly.

For ISE and Endpoint Observability workflows, we can focus first on deployment health, network devices, endpoints, sessions, authentication failures, posture, TrustSec, certificates, licensing, and selected policy evidence. Higher-volume pxGrid and Data Connect views can be opt-in for scenarios that need real-time or historical depth.

For Catalyst 9800 and IOS XR telemetry, curated path groups, safe sample intervals, capabilities checks, and datapoint batch limits help us avoid wildcard subscriptions and unbounded native telemetry.

For Intersight, Nexus Dashboard, APIC, FMC, and related controller sources, we separate bounded metric rollups from detailed logs and event evidence. That gives teams operational context without making every audit or event field a metric dimension.

## How this supports the broader observability transformation

The original observability transformation focused on unifying fragmented data into actionable insight. This pilot extends that idea into the collection layer itself.

Unified insight requires enough data to understand the user experience, the endpoint, the application, the network path, and the infrastructure underneath. But sustainable observability also requires discipline about which telemetry becomes always-on, which telemetry is enabled for specific workflows, and which evidence belongs in logs rather than metrics.

That is the heart of our approach with Observability Cloud and Endpoint Observability: observe the full stack, but collect with intent.

As the pilot progresses, we expect the strategy to evolve. We will keep refining the starting metric sets, the target scopes, the dashboards, and the controls based on what operators actually use during real workflows. The goal is not the biggest telemetry footprint. The goal is the smallest useful footprint that helps teams see what matters, act faster, and connect technical signals to business impact.

## Suggested pull quote

"Full-stack observability does not mean collecting every signal. It means collecting the right signals, at the right granularity, with enough context to act."

## Suggested sidebar: The collection checklist

1. What operational or business question should this telemetry answer?
2. Which platform or endpoint domain is required?
3. Can we start with health, trust, and status metrics before detailed troubleshooting groups?
4. Can we scope by site, serial, application, tenant, fabric, interface, endpoint, or policy?
5. Which fields are safe metric dimensions, and which belong in logs?
6. What is the expected active MTS and datapoint rate?
7. How will we validate that the collected telemetry is being used?

## Source notes for reviewers

- Prior Cisco-on-Cisco blog: https://blogs.cisco.com/cisco-on-cisco/cisco-its-observability-transformation-from-fragmented-data-to-unified-insights
- Cisco Observability positioning: https://www.cisco.com/site/us/en/products/observability/index.html
- Repo evidence: `receiver/ciscoosreceiver/docs/metric-control.md`, `receiver/ciscoosreceiver/docs/metrics.md`, `receiver/ciscoosreceiver/README.md`, and `outputs/ciscoos_metric_volume_calculator/cisco_os_metric_volume_calculator.xlsx`
