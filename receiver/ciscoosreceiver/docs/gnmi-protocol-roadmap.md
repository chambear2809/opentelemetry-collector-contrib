# gNMI Protocol Roadmap

This document separates the normalized `cisco_os.gnmi` receiver's implemented read-only behavior from possible later
transport and snapshot work. A design below is not a configuration contract, support statement, or promise for a Cisco
release. Unless a feature is explicitly marked implemented in this document and appears in the generated configuration
schema, the receiver rejects its configuration.

## Implemented: product preflight and direct Subscribe collection

The implemented receiver uses a static inventory of direct TLS endpoints. One verified session calls Capabilities,
negotiates only product-approved encodings, validates the contract-required model set, and performs only the product
contract's bounded STATE identity Gets. After verifying one unambiguous product/model/exact-build identity, the receiver
launches configured metric Subscribe streams on that verified session. It never calls Set.
Compatibility failures are terminal for that target until receiver restart and launch zero configured metric streams,
although bounded identity Gets may already have run.

After qualification, the receiver supports independently planned subscription streams and, where the selected product
contract permits them, per-path SAMPLE, ON_CHANGE, and TARGET_DEFINED behavior, heartbeat and suppression requests,
updates-only state ownership, aggregation, QoS, and the typed Depth extension. JSON and JSON_IETF subtree values are
decoded only through explicit metric mappings. The bounded scalar PROTO decoder remains available only to deprecated
receiver surfaces; product-qualified contracts reject PROTO. Unsupported opaque value kinds remain bounded and
observable but do not become metrics.

The Nexus 9000 10.6 and Nexus 3500 10.5 contracts use only their conservative common subset: JSON,
STREAM/SAMPLE, explicit non-wildcard paths, no subscription-list prefix, and no optional subscription flags.

Rejected options are never silently removed. One bounded baseline probe distinguishes an unsupported request shape from
a bad path; its data is discarded. The affected stream stops until reload or restart when the baseline succeeds, while
a failed baseline enters bounded path bisection and accepted groups retain their original options.

Platform behavior still requires release-specific qualification. Cisco's documentation describes scalar PROTO on
[IOS XE](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1718/b-1718-programmability-cg/gnmi.html)
and broader subscription-mode support on
[NX-OS](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/106x/programmability/cisco-nexus-9000-series-nx-os-programmability-guide-106x/m-gnmi.html),
but those statements do not substitute for qualification of the configured product, image, paths, and options.

## Future wireframe: proxy targets

Proxy transport is not implemented. A future version may replace the direct-only endpoint with a discriminated
`transport` configuration while retaining the existing top-level `endpoint` as the backward-compatible direct form.
The proposed proxy form has an endpoint, exact `proxy_target`, optional `device_ip`, and explicit
`capabilities_mode`.

The intended identity rules are:

- Put `proxy_target` only on the request prefix, including a target-only NX prefix.
- Require every response prefix to reflect the exact requested target before canonicalizing it to the configured target
  name.
- Keep configured `name` as `host.id`, `host.name`, and cache identity. Never infer `host.ip` from a proxy endpoint; use
  only explicit `device_ip`.
- Permit a repeated proxy endpoint only when the `(endpoint, proxy_target)` pair is unique. Initial implementations would
  retain one gRPC connection per logical target.
- Require Capabilities by default. Because CapabilityRequest has no target field, permit an explicit skip only when one
  encoding is configured; never infer a skip from target behavior.

## Future wireframe: both gRPC tunnel roles

OpenConfig gRPC tunnel support is not implemented. A future version may support both an embedded tunnel server and a
client connected to an external tunnel server using the official
[`grpctunnel` protocol](https://github.com/openconfig/grpctunnel). Only its generated protobuf API would be used; the
receiver would own a bounded registration and session state machine.

Named embedded-server definitions would include the listen endpoint, outer TLS or mTLS policy, target-ID-to-certificate
identity bindings, and client, target, session, frame, and idle limits. Named external-client definitions would include
the upstream endpoint, outer TLS or mTLS policy, reconnect policy, and an allowlist of target IDs and types.

A target would select a named tunnel definition, exact `target_id`, `target_type` defaulting to `GNMI_GNOI`, explicit
`device_ip`, and mandatory inner gNMI TLS server name. Outer tunnel TLS would remain separate from inner gNMI TLS and
username/password metadata. Only statically configured IDs would be admitted; an unknown registration would be rejected,
and tunnel loss would cancel inner sessions until an authenticated re-registration signal arrives. Outer frames and inner
gNMI calls would both count against the receiver-wide in-flight budget.

Embedded and external roles require separate qualification. Cisco documents device dial-out on IOS XE and platform-
dependent tunnel constraints on
[IOS XR](https://www.cisco.com/c/en/us/td/docs/routers/asr9000/software/710x/telemetry/configuration/guide/b-telemetry-cg-asr9000-710x/enhancememts-to-telemetry.html);
neither statement establishes receiver support before this wireframe is implemented and tested.

## Future wireframe: configurable periodic Get

The receiver calls only fixed, bounded product-identity Gets and does not accept `get_requests`. A configurable bounded
periodic Get feature should be added only for a concrete, small-snapshot use case that cannot reasonably use ONCE or
POLL Subscribe.

The proposed request would have a name, origin, interval, timeout, data type, encoding preference, explicit paths and
mappings, required flag, and optional Depth. Implementation would limit path count, response bytes, unary concurrency,
and scheduling overlap; charge responses against the existing admission and in-flight budgets; apply wire preflight to
GetResponse; stage the entire response; and atomically reconcile owner state only after a successful RPC. ONCE and POLL
would remain preferred for large snapshots.

## Permanently out of scope: Set

Set is not a roadmap item. The receiver has no Set configuration, write credentials, transaction retry, or
commit/arbitration extension. Operators should authorize Capabilities, the fixed identity Get paths, and Subscribe, and
explicitly deny Set and any other Get path at the device or proxy.
