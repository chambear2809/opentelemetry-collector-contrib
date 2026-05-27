# Catalyst SD-WAN Integration Research

Research date: 2026-05-26

This note describes how to incorporate Cisco Catalyst SD-WAN Manager, formerly vManage, into the Cisco OS receiver with the same operating model used for Meraki, Intersight, Catalyst Center, Nexus Dashboard, and ACI.

Implementation note: the final receiver implementation extends this initial research into full first-class `sdwan`
configuration, auth, client, metrics/log receivers, shared device selection, full opt-in product group coverage, and a
12-page Splunk Observability dashboard bundle. The dashboard coverage is broader than the first-pass eight-page sketch
below and includes dedicated pages for policy/security, AppQoE/flows, Cloud OnRamp/multicloud, routing/branch services,
lifecycle/hardware/energy, alarm/event/audit evidence, and Network-Wide Path Insight/ThousandEyes agent status.

## Goals

- Collect high-value SD-WAN telemetry for NetOps and ITOps incident response.
- Keep broad fleet signals safe by default and make expensive real-time or high-cardinality detail opt-in.
- Preserve the receiver's current conventions: bounded dimensions, controller-specific metrics, common Cisco/OTel metric reuse where semantics match, logs for high-cardinality evidence, and Splunk Observability dashboard bundles.
- Support networking for AI by exposing application path quality, SaaS/custom-app reachability, policy steering evidence, and WAN path degradation signals for model/API traffic and edge-to-cloud AI workflows.

## Source Notes

Primary references:

- Cisco Catalyst SD-WAN Manager API 20.18 Monitoring and Troubleshooting: https://developer.cisco.com/docs/sdwan/monitoring-and-troubleshooting-overview/
- Cisco Catalyst SD-WAN Manager API getting started and authentication: https://developer.cisco.com/docs/sdwan/getting-started/ and https://developer.cisco.com/docs/sdwan/authentication/
- Cisco SD-WAN Manager REST API examples and rate-limit guidance: https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/sdwan-xe-gs-book/appendix-vmanage-how-tos.html
- Cisco SD-WAN alarm, event, and audit queries: https://developer.cisco.com/docs/sdwan/alarm-and-event/
- Cisco SD-WAN query format for statistics database queries: https://developer.cisco.com/docs/sdwan/query-format/
- Cisco SD-WAN device and real-time API examples: https://developer.cisco.com/docs/sdwan/list-all-devices/, https://developer.cisco.com/docs/sdwan/create-bfd-sessions/, https://developer.cisco.com/docs/sdwan/create-app-route-statistics-list/, https://developer.cisco.com/docs/sdwan/get-device-interface/
- Cisco application-aware routing and enhanced application-aware routing: https://www.cisco.com/c/en/us/td/docs/routers/sdwan/26x-later/policies/policies-configuration-guide/application-aware-routing.html and https://www.cisco.com/c/en/us/td/docs/routers/sdwan/26x-later/policies/policies-configuration-guide/enhanced-application-aware-routing.html
- Cisco SD-WAN Analytics and Cloud OnRamp for SaaS: https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/vAnalytics/vAnalytics-book/vAnalytics.html and https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/cloudonramp/ios-xe-17/cloud-onramp-book-xe/cloud-onramp-saas.html

Important implementation implications:

- SD-WAN Manager API URLs are rooted at `/dataservice`.
- API users need API access permission. Release 20.18.1 adds JWT-based authentication; session-cookie authentication remains for backward compatibility.
- Cisco documents API rate limits of 100 requests per second and bulk API limits of 48 requests per minute from release 20.6.1.
- Cisco warns that real-time monitoring APIs are CPU intensive and should be used for troubleshooting rather than continuous broad monitoring. This should drive conservative defaults.
- Alarms, events, and audit logs support GET for short queries and POST for larger queries; POST should be the receiver default.
- The statistics query language supports simple queries, aggregation, field selection, sorting, and field discovery through `/fields` endpoints.

## Receiver Fit

Add SD-WAN as a top-level controller/API target:

```yaml
receivers:
  cisco_os:
    sdwan:
      enabled: true
      endpoint: ${env:SDWAN_MANAGER_ENDPOINT}
      auth:
        mode: auto
        username: ${env:SDWAN_MANAGER_USERNAME}
        password: ${env:SDWAN_MANAGER_PASSWORD}
      event_lookback: 24h
      statistics_lookback: 30m
      realtime_lookback: 5m
      targets:
        site_ids: []
        system_ips: []
        uuids: []
        serials: []
        device_types: []
        personalities: []
        colors: []
        interface_names: []
        vpn_ids: []
        applications: []
      inventory:
        enabled: true
      control_plane:
        enabled: true
      bfd:
        enabled: true
      app_route:
        enabled: true
      interfaces:
        enabled: true
      alarms:
        enabled: true
      events:
        enabled: true
      audit:
        enabled: true
      realtime_details:
        enabled: false
```

Implementation files should mirror existing platform receivers:

- `receiver/ciscoosreceiver/config.go`: add `SDWANConfig`, auth, targets, group config, defaults, validation.
- `receiver/ciscoosreceiver/factory.go`: create SD-WAN metrics and logs receivers when configured.
- `receiver/ciscoosreceiver/sdwan_receiver.go`: polling loop, partial success handling, builders, metrics/log emission.
- `receiver/ciscoosreceiver/internal/sdwan/client.go`: HTTPS client, auth, retry, rate limiting, request stats.
- `receiver/ciscoosreceiver/internal/sdwan/models.go`: typed models for stable endpoints plus generic object support for version-varied API payloads.
- `receiver/ciscoosreceiver/device_selection.go`: add SD-WAN identity extraction for system IP, host name, UUID, serial, site ID, and chassis serial.
- `receiver/ciscoosreceiver/docs/metrics.md`, `README.md`, `docs/splunk-o11y.md`: add SD-WAN coverage.
- `receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-sdwan-dashboard-group.bundle.json`: add importable dashboard group.

## Auth Strategy

Support these modes:

- `jwt`: use `POST /jwt/login` and send `Authorization: Bearer <token>` plus XSRF token for POST calls. Prefer for 20.18.1 and later.
- `session`: use `POST /j_security_check`, retrieve `/dataservice/client/token`, send cookie plus `X-XSRF-TOKEN`.
- `bearer`: accept an externally managed bearer token for environments that generate API tokens in SD-WAN Manager.
- `cookie`: accept externally supplied `JSESSIONID` and XSRF token for SSO-constrained environments, documented as less ideal for unattended collectors.
- `auto`: prefer bearer if provided, then JWT login, then session login.

Emit auth/API trust metrics for every mode so dashboards show whether missing SD-WAN data is caused by authorization, rate limits, endpoint failures, or collection errors.

## Collection Groups

Default enabled groups should be low-cardinality and operationally useful:

| Group | Default | Coverage |
| --- | --- | --- |
| `inventory` | Enabled | `/device`, device counters, reachability, certificate validity, host/model/version/site/personality. |
| `manager` | Enabled | SD-WAN Manager/API health, request duration, errors, rate limits, last success, partial success. |
| `control_plane` | Enabled | Control connection counts, expected vs actual vSmart connections, TLOC/control state, OMP summary where safe. |
| `bfd` | Enabled | BFD summary and site/device status summary; session details only when bounded. |
| `app_route` | Enabled | Application-aware routing loss, latency, jitter, SLA class, local/remote color, protocol. |
| `interfaces` | Enabled | WAN transport and service interfaces, admin/oper state, speed, bytes, packets, errors, drops, utilization. |
| `alarms` | Enabled | Active/recent alarms as metrics and logs. |
| `events` | Enabled | Recent events as logs plus bounded count metrics. |
| `audit` | Enabled | Audit/config-change records as logs plus bounded count metrics. |

Opt-in detail groups:

| Group | Why opt-in |
| --- | --- |
| `realtime_details` | Per-device real-time endpoints are CPU intensive on SD-WAN Manager. Use during incidents or with tight target filters. |
| `tunnels` | Per-tunnel packet, byte, drop, FEC, duplicate, GRE, and IPsec detail can be high volume. |
| `flows` | Cflowd/DPI/app-log flow records are high cardinality; logs or aggregated metrics only. |
| `policy` | ACL, data-policy, app-route policy, QoS, rewrite, policer, and zone-policy counters can have broad labels. |
| `security` | SIG, SSE, Umbrella, ZBFW, IPS, URL filtering, and UTD signals vary by deployment and license. |
| `appqoe` | AppQoE, DRE, TCP optimization, SSL proxy, and TCP proxy endpoints are feature-dependent. |
| `cloud_onramp` | SaaS/custom app vQoE, best path, DIA/gateway state, and endpoint monitoring are feature-dependent. |
| `cellular` | Useful for branch resilience, but only applies to cellular WAN Edge deployments. |
| `hardware` | Environment, alarms, inventory, SFP, power, and crash/reboot detail can be collected when SD-WAN Manager exposes it reliably. |

## Metric Names

Follow the existing receiver style:

- Reuse common metrics where semantics match: `cisco.device.up`, `system.cpu.utilization`, `system.memory.utilization`, `system.uptime`, `system.network.interface.status`, `system.network.io`, `system.network.errors`, `system.network.packet.dropped`, `system.network.packet.count`, `cisco.interface.admin.status`, `cisco.interface.speed`, `cisco.interface.io.rate`, `cisco.interface.utilization`.
- Use an `sdwan.*` namespace for SD-WAN-specific overlay, tunnel, app-route, policy, SaaS, and controller metrics.

Core API and scrape metrics:

| Metric | Unit | Purpose |
| --- | --- | --- |
| `sdwan.api.request.duration` | `s` | Duration by operation, method, outcome, path family, status code. |
| `sdwan.api.request.errors` | `{error}` | API/auth/permission/timeout/parse failures. |
| `sdwan.api.rate_limited` | `{request}` | HTTP 429 pressure. |
| `sdwan.scrape.partial_success` | `1` | One or more endpoint families failed or were skipped. |
| `sdwan.scrape.last_success` | `s` | Last completed scrape timestamp. |
| `sdwan.api.endpoint.error` | `{error}` | Endpoint-family error when a collection group fails. |

Inventory and lifecycle:

| Metric | Unit | Key attributes |
| --- | --- | --- |
| `sdwan.resource.info` | `1` | `sdwan.resource.type`, `sdwan.system_ip`, `sdwan.uuid`, `sdwan.site.id`, `sdwan.personality`, `sdwan.device.type` |
| `sdwan.resource.status` | `1` | Encoded `status`, `state`, `reachability`, certificate/validity state. |
| `sdwan.device.reachability.status` | `1` | `sdwan.reachability` |
| `sdwan.device.validity.status` | `1` | `sdwan.validity` |
| `sdwan.device.certificate.status` | `1` | `sdwan.certificate.validity` |
| `sdwan.device.reboot.count` | `{reboot}` | `sdwan.system_ip` |
| `sdwan.device.crash.count` | `{crash}` | `sdwan.system_ip` |

Control plane and overlay:

| Metric | Unit | Key attributes |
| --- | --- | --- |
| `sdwan.control.connection.count` | `{connection}` | `peer.type`, `sdwan.local.color`, `sdwan.remote.color`, `sdwan.tloc.status` |
| `sdwan.control.connection.status` | `1` | `state`, `local_status`, `remote_status`, `peer.type`, `preferred` |
| `sdwan.control.expected_connections` | `{connection}` | expected vSmart/control connections. |
| `sdwan.control.actual_connections` | `{connection}` | actual vSmart/control connections. |
| `sdwan.omp.peer.status` | `1` | `peer`, `vpn`, `state`; opt-in if endpoint cardinality is high. |
| `sdwan.omp.route.count` | `{route}` | `vpn`, address family, route type; opt-in. |

BFD, TLOC, and tunnel path:

| Metric | Unit | Key attributes |
| --- | --- | --- |
| `sdwan.bfd.session.count` | `{session}` | `state`, `site_id`, local/remote color. |
| `sdwan.bfd.session.status` | `1` | session `state`, local/remote color, protocol, remote system IP. |
| `sdwan.bfd.session.transitions` | `{transition}` | local/remote color, remote system IP. |
| `sdwan.bfd.session.flap.count` | `{flap}` | summary flap count. |
| `sdwan.bfd.session.max` | `{session}` | maximum sessions from BFD summary. |
| `sdwan.tloc.status` | `1` | color, interface, NAT type, public/private IP/port. |
| `sdwan.tunnel.packet.count` | `{packet}` | direction, protocol, local/remote color. |
| `sdwan.tunnel.drop.count` | `{drop}` | direction, reason, protocol. |
| `sdwan.tunnel.fec.packet.count` | `{packet}` | FEC recovered/lost where available. |

Application experience and AI/cloud path:

| Metric | Unit | Key attributes |
| --- | --- | --- |
| `sdwan.app_route.latency` | `ms` | local/remote color, remote system IP, SLA class, application/probe class. |
| `sdwan.app_route.jitter` | `ms` | local/remote color, remote system IP, SLA class, application/probe class. |
| `sdwan.app_route.loss` | `%` | local/remote color, remote system IP, SLA class, application/probe class. |
| `sdwan.app_route.packet.count` | `{packet}` | direction, protocol, local/remote color. |
| `sdwan.app_route.sla.status` | `1` | SLA class, strict/fallback state. |
| `sdwan.app_route.drop.count` | `{drop}` | app-route strict drops, matched-none drops, policy drops. |
| `sdwan.cloud_onramp.vqoe.score` | `1` | site, application, DIA/gateway, local/remote color. |
| `sdwan.cloud_onramp.path.status` | `1` | best path, selected interface, application, site. |
| `sdwan.application.usage` | `By` | bounded application/family/site dimensions from aggregated DPI/cflowd. |
| `sdwan.application.flow.count` | `{flow}` | aggregated flow counts by application/family/site/VPN. |

Interfaces, circuits, and capacity:

| Metric | Unit | Key attributes |
| --- | --- | --- |
| `sdwan.transport.interface.status` | `1` | `network.interface.name`, color, VPN, port type. |
| `sdwan.transport.interface.flap.count` | `{flap}` | interface, color, VPN. |
| `sdwan.circuit.availability` | `%` | site, circuit/color/provider where available. |
| `sdwan.circuit.utilization` | `1` | site, circuit/color/interface, direction. |

Policy, security, and service insertion:

| Metric | Unit | Key attributes |
| --- | --- | --- |
| `sdwan.policy.drop.count` | `{drop}` | policy family, direction, action, reason. |
| `sdwan.acl.drop.count` | `{drop}` | ACL family, direction, action, reason. |
| `sdwan.qos.queue.packet.count` | `{packet}` | interface, queue/class, action. |
| `sdwan.sig.tunnel.status` | `1` | SIG provider, site, tunnel. |
| `sdwan.sse.tunnel.status` | `1` | SSE tunnel/site. |
| `sdwan.umbrella.tunnel.status` | `1` | Umbrella tunnel/site. |
| `sdwan.zbfw.session.count` | `{session}` | zone pair, state, VPN. |
| `sdwan.ips.alert.count` | `{alert}` | severity, policy, site. |
| `sdwan.url_filtering.event.count` | `{event}` | action, category, site. |

Optimization and AppQoE:

| Metric | Unit | Key attributes |
| --- | --- | --- |
| `sdwan.appqoe.service.status` | `1` | service, cluster, site. |
| `sdwan.appqoe.flow.count` | `{flow}` | active/expired/closed, error class. |
| `sdwan.tcp_optimization.flow.count` | `{flow}` | active/expired, VPN, application family. |
| `sdwan.dre.peer.status` | `1` | peer, site. |
| `sdwan.dre.bypass.count` | `{bypass}` | reason, site. |

## Logs

Use logs for event evidence and high-cardinality payloads:

- `event.domain=sdwan`
- `event.name` set to endpoint family, for example `alarms`, `events`, `auditlog`, `reboot_history`, `crashlog`, `policy_deployment`, `admin_tech`, `appqoe_error`.
- Resource attributes should identify the SD-WAN Manager endpoint or affected device.
- Log attributes should include bounded fields such as `sdwan.severity`, `sdwan.status`, `sdwan.system_ip`, `sdwan.site.id`, `sdwan.uuid`, `sdwan.policy.name`, `user.name`, and `user.email` when present.
- Preserve the original API object in the log body map.

Emit logs for:

- Alarms, events, audit logs.
- Config/template attach, detach, deployment, and policy changes when endpoint coverage is stable.
- Device reboot history and crashlog summaries.
- Admin-tech collection state and troubleshooting task failures.
- Security/service-edge events from SIG, SSE, Umbrella, UTD, ZBFW, IPS, and URL filtering when available.
- AppQoE/TCP/DRE errors and closed-flow error summaries when enabled.

## Resource Attributes And Dimensions

Common resource attributes:

| Attribute | Meaning |
| --- | --- |
| `host.id` | Prefer chassis serial, UUID, or system IP in that order. |
| `host.name` | `host-name` from SD-WAN Manager. |
| `host.ip` | Management/system IP when applicable. |
| `host.type` | Device model/platform. |
| `hw.type` | Always `network`. |
| `os.name` | `IOS XE SD-WAN`, `vEdge`, `vManage`, `vSmart`, or best available source value. |
| `os.version` | SD-WAN software version. |
| `cisco.controller.type` | `sdwan_manager`. |
| `cisco.controller.endpoint` | SD-WAN Manager endpoint. |

SD-WAN dimensions:

- `sdwan.system_ip`
- `sdwan.uuid`
- `sdwan.chassis_serial`
- `sdwan.board_serial`
- `sdwan.site.id`
- `sdwan.personality`
- `sdwan.device.type`
- `sdwan.device.model`
- `sdwan.validity`
- `sdwan.certificate.validity`
- `sdwan.tloc.color`
- `sdwan.local.color`
- `sdwan.remote.color`
- `sdwan.remote.system_ip`
- `sdwan.vpn.id`
- `sdwan.application`
- `sdwan.application.family`
- `sdwan.sla_class`
- `sdwan.app_probe_class`
- `network.interface.name`
- `network.io.direction`

Cardinality rules:

- Do not use raw flow 5-tuples as metric attributes.
- Do not make application name a global dashboard variable unless the dashboard is specifically application-focused.
- Keep usernames, free-form alarm text, audit messages, policy payloads, and detailed descriptions in logs, not metric labels.
- Target-scoped detail collection should require explicit filters: system IPs, UUIDs, site IDs, interface names, colors, applications, or VPN IDs.

## AI Networking Support

The receiver already has strong data-center AI fabric support through Cisco OS switch-side QoS, PFC, ECN, queue, optics, VXLAN/EVPN, and Intersight UCS telemetry. SD-WAN adds the WAN and cloud/application half of the story:

- Application-aware routing exposes path loss, latency, jitter, SLA class, local/remote colors, and tunnel choice. This is the core signal for inference API calls, RAG data fetches, edge-to-cloud model traffic, SaaS AI assistants, and inter-site AI service traffic.
- Cloud OnRamp for SaaS supports user-defined probe endpoints in newer releases, so operators can define model/API endpoints as monitored applications and view best-path/vQoE state.
- DPI/cflowd/app-flow aggregates can show whether AI-related application traffic shifted site, circuit, VPN, or DIA path during an incident without pushing raw flow cardinality into metrics.
- QoS/policy/drop counters can expose DSCP/class handling and strict SLA/policy drops for latency-sensitive AI apps.
- SIG, SSE, Umbrella, and ZBFW signals help explain whether security service insertion, inspection, DNS handling, or cloud security tunnels caused an app path issue.

Dashboard questions for AI workflows:

- Did the affected app/model endpoint lose vQoE or violate loss, latency, or jitter thresholds?
- Did SD-WAN steer the app onto a different local/remote color or DIA/gateway path?
- Did strict SLA, data policy, SIG/SSE, DNS, or security inspection drop or detour the traffic?
- Did a site have BFD partial connectivity even though control plane stayed up?
- Did WAN circuit utilization, packet loss, cellular failover, or tunnel flaps line up with application errors?
- Did data-center fabric signals show congestion at the same time as SD-WAN path degradation?

## Dashboard Bundle

Create `Cisco SD-WAN Receiver` with the same import bundle structure as the existing platform dashboards.

Recommended pages:

| Dashboard | Value provided |
| --- | --- |
| `00 SD-WAN Fleet And API Health` | Proves SD-WAN Manager API reachability, auth, rate limits, partial scrape state, last success, inventory scope, and stale data risk. |
| `01 Control Plane And Overlay` | Shows control connections, expected vs actual vSmart/controller state, OMP state, TLOC status, device validity, certificate status, and reachability. |
| `02 Site BFD TLOC And Tunnel Health` | Shows BFD session count/up/total/flaps, per-site full/partial/down state, tunnel packets/drops, local/remote colors, IPsec/GRE state, and path transitions. |
| `03 Application Experience SaaS And AI Paths` | Shows app-route loss/latency/jitter, SLA status, app-route drops, Cloud OnRamp vQoE, best path, application usage, and AI endpoint/application filters. |
| `04 Interfaces Circuits And Capacity` | Shows WAN/service interface state, utilization, rates, errors, drops, circuit availability, cellular status, and capacity pressure. |
| `05 Policy Security And Service Edge` | Shows policy/ACL drops, QoS queue counters, SIG/SSE/Umbrella/ZBFW/UTD status, IPS alerts, URL filtering events, and service insertion health. |
| `06 AppQoE Optimization And Flow Evidence` | Shows AppQoE, DRE, TCP optimization, TCP proxy, SSL proxy, active/expired/error flow rollups, and optimization service state. |
| `07 Alarms Events Audit And Change Evidence` | Shows active alarm counts, event counts, audit/config-change logs, policy deployment failures, reboots, crash logs, and admin-tech status. |

Dashboard variables:

- `sdwan.system_ip`
- `sdwan.site.id`
- `host.name`
- `host.id`
- `sdwan.uuid`
- `sdwan.personality`
- `sdwan.device.type`
- `sdwan.tloc.color`
- `sdwan.local.color`
- `sdwan.remote.color`
- `network.interface.name`
- `sdwan.vpn.id`
- `sdwan.application`
- `sdwan.application.family`
- `sdwan.sla_class`
- `sdwan.app_probe_class`
- `cisco.controller.endpoint`

Detector starting set:

- SD-WAN Manager API errors or rate limits repeat for 2-3 scrapes.
- `sdwan.scrape.partial_success=1` for 3 scrapes.
- `cisco.device.up=0` for critical WAN Edge devices.
- Expected control connections exceed actual connections.
- Control connection status is down or TLOC status is red.
- BFD up sessions drop below total sessions for a critical site.
- BFD transition/flap count rises sharply.
- App-route loss/latency/jitter exceeds app/SLA policy thresholds.
- Cloud OnRamp vQoE is poor or unknown for monitored critical apps.
- WAN interface admin up and oper down.
- Interface utilization exceeds policy or drops/errors rise.
- Policy/security/service-edge drop counters start growing.
- Critical alarms, audit changes, reboot/crash events, or deployment failures appear in the incident window.

## Implementation Phases

1. Maintainer alignment if this is headed upstream.
   - The repo instructions say implementation direction for assigned issues should be agreed with maintainers first.
   - Do not post AI-generated issue or PR comments. The user should do any maintainer communication.

2. Client and config foundation.
   - Add `SDWANConfig`, defaults, schema, validation, and README config.
   - Build `internal/sdwan` client with JWT/session/bearer/cookie auth, retry, backoff, rate limiter, request stats, and JSON helpers.
   - Unit-test auth flows, retry behavior, XSRF handling, pagination/query helpers, and validation.

3. Core metrics and logs.
   - Implement inventory, API health, control-plane summary, BFD summary/status, interface, app-route, alarms, events, and audit.
   - Add logs receiver path for alarms/events/audit with original body payloads.
   - Add device selection identity support and tests.

4. Advanced coverage.
   - Add opt-in real-time details, tunnel statistics, policy/security, Cloud OnRamp, AppQoE, cellular, hardware, crash/reboot, and flow aggregates.
   - Add feature/endpoint discovery where API availability varies by release, role, license, or deployment.

5. Dashboards and docs.
   - Add SD-WAN dashboard bundle and dry-run importer tests.
   - Update metrics guide, Splunk O11y guide, README, and expected-data sections.
   - Add detector blueprints and incident workflow.

6. Live validation.
   - Add `e2e` smoke tests using `CISCOOS_E2E_SDWAN_*` environment variables.
   - Validate against a lab SD-WAN Manager with at least one WAN Edge, one controller, BFD sessions, app-route data, and recent alarm/event/audit records.

## Risks And Mitigations

| Risk | Mitigation |
| --- | --- |
| Real-time APIs can load SD-WAN Manager. | Use stats and summaries by default; require opt-in and target filters for detail. |
| API auth differs by release and SSO posture. | Support JWT, session, bearer, and externally supplied cookie/XSRF modes. |
| API payloads vary by release and feature license. | Use generic object decoding around stable fields; emit service unavailable/skipped metrics. |
| Role gaps can look like network outages. | Record operation/status-code/error metrics and dashboard API trust first. |
| Flow and event cardinality can explode. | Aggregate flow metrics; emit raw event/flow evidence as logs only when opt-in. |
| App-route data can be stale or averaged. | Preserve `lastupdated`, scrape timestamps, and poll interval attributes where useful. |
| Device identity differs across vEdge/cEdge/controllers. | Normalize around system IP, UUID, chassis/board serial, host name, and site ID. |

## Recommendation

Proceed with SD-WAN as a first-class `sdwan` API platform in `cisco_os`, not as a Catalyst Center subfeature. The first PR should cover client/config, API trust, inventory, control/BFD summaries, interfaces, app-route, alarms/events/audit logs, docs, and the first dashboard bundle. Advanced feature groups should follow behind explicit config gates so we can deliver full coverage without making default collection risky.
