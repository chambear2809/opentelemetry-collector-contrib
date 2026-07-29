# Product-Contract gNMI Dial-In

The shared `cisco_os.gnmi` client collects normalized metrics only from the product and release-train contracts below.
It is a static-inventory, read-only client: it uses Capabilities, bounded product-identity Gets, and Subscribe, and never uses Set.
Configuration alone does not establish support. A target must pass configuration validation, any product-pinned gNMI
protocol version, product-approved encoding negotiation, required-model validation, and bounded identity Get probes in
that order. Configured metric streams start only after product, chassis-model, and canonical software-release
verification succeeds. Target discovery, configurable general-purpose gNMI Get/Set, and
dial-out metric semantics are outside this feature's implemented scope; receiver-wide transport hardening also applies
to the existing dial-out servers as described below.

See the [gNMI protocol roadmap](gnmi-protocol-roadmap.md) for proxy, tunnel, and configurable periodic Get designs that
are explicitly not implemented. Bounded product-identity Gets are part of the implemented preflight.

| `product` | Derived OS | Accepted release/train | Live identity source |
| --- | --- | --- | --- |
| `catalyst_9300` | `ios_xe` | [`17.18.1` only](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1718/b-1718-programmability-cg/gnmi.html) | IOS XE hardware inventory, current install-version entries, and INSTALL boot mode |
| `catalyst_9500` | `ios_xe` | [`17.18.1` only](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1718/b-1718-programmability-cg/gnmi.html) | IOS XE hardware inventory, current install-version entries, and INSTALL boot mode |
| `catalyst_9800` | `ios_xe` | [`17.18.x`](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1718/b-1718-programmability-cg/gnmi.html) | IOS XE hardware inventory plus current install-version entries |
| `asr_9000` | `ios_xr` | [`24.4.x`](https://www.cisco.com/c/en/us/td/docs/routers/asr9000/software/24xx/programmability/configuration/guide/b-programmability-cg-asr9000-24xx/use-grpc-protocol-to-define-network-operation-with-data-models.html) | `Cisco-IOS-XR-install-oper:install/version` chassis PID and release label |
| `ncs_5500` | `ios_xr` | [`24.4.x`](https://www.cisco.com/c/en/us/td/docs/iosxr/ncs5500/telemetry/24xx/configuration/guide/b-telemetry-cg-ncs5500-24xx/scale-up-your-network-monitoring-strategy-using-telemetry.html) | `Cisco-IOS-XR-install-oper:install/version` chassis PID and release label |
| `nexus_9000` | `nx_os` | [`10.6(x)`](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/106x/programmability/cisco-nexus-9000-series-nx-os-programmability-guide-106x/m-gnmi.html) | Generic `openconfig` origin, `openconfig-platform` model, and `components/component/state` path |
| `nexus_3500` | `nx_os` | [`10.5(x)`](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus3000/105x/programmability/cisco-nexus-3500-series-nx-os-programmability-guide_105x/m_n3600_gnmi_93x.html) | Generic `openconfig` origin, `openconfig-platform` model, and `components/component/state` path |

On NX-OS, `openconfig` is the generic wire origin for OpenConfig Get and Subscribe paths. It is not a Capabilities
model name. Preflight still validates the individual `openconfig-platform`, `openconfig-system`, and
`openconfig-interfaces` models required by the enabled identity and profile paths.

The Catalyst 9300/9500 contracts accept only the reviewed public release `17.18.1`; other contracts accept any
syntactically valid software release identifier in the listed train. Each target's `software_version` is the configured
expected release identifier; its canonical form must match the canonical form derived from the observed value.
Catalyst switch chassis identity uses the explicit base-PID allowlists below; the
remaining products use anchored `C9800-`/`CAT9800-`, `ASR-9`, `NCS-55`, `N9K-`, or `N3K-C35` family patterns. A
chassis match is an identity boundary, not live evidence for every admitted SKU. Cisco SONiC is explicitly unsupported.
`platform`, including `platform: sonic`, remains a decoder-only migration field that always fails validation; no
OS-family field can select a contract.

### Admitted Catalyst switch PIDs

The hardware inventory `part-number` must equal one of these documented base PIDs, case-insensitively. License,
Meraki-mode, module, arbitrary suffix, and invented family strings are rejected.

| Contract | Admitted base PIDs |
| --- | --- |
| C9300 | `C9300-24T`, `C9300-48T`, `C9300-24P`, `C9300-48P`, `C9300-24U`, `C9300-48U`, `C9300-24UX`, `C9300-48UXM`, `C9300-48UN`, `C9300-24UB`, `C9300-24UXB`, `C9300-48UB`, `C9300-24H`, `C9300-48H`, `C9300-24S`, `C9300-48S` |
| C9300L | `C9300L-24T-4G`, `C9300L-24T-4X`, `C9300L-48T-4G`, `C9300L-48T-4X`, `C9300L-24P-4G`, `C9300L-24P-4X`, `C9300L-48P-4G`, `C9300L-48P-4X`, `C9300L-48PF-4G`, `C9300L-48PF-4X`, `C9300L-24UXG-4X`, `C9300L-24UXG-2Q`, `C9300L-48UXG-4X`, `C9300L-48UXG-2Q` |
| C9300X | `C9300X-48HX`, `C9300X-48TX`, `C9300X-48HXN`, `C9300X-24HX`, `C9300X-12Y`, `C9300X-24Y` |
| C9500 | `C9500-12Q`, `C9500-24Q`, `C9500-40X`, `C9500-16X`, `C9500-32C`, `C9500-32QC`, `C9500-48Y4C`, `C9500-24Y4C` |
| C9500X | `C9500X-28C8D`, `C9500X-60L4D` |

C9300/C9300L/C9300X base PIDs were reviewed against Cisco's
[Catalyst 9300 Series data sheet](https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-06-cat9300-ser-data-sheet-cte-en.html),
revision dated 2026-06-22 and accessed 2026-07-29. C9500/C9500X base PIDs were reviewed against Cisco's
[Catalyst 9500 Series data sheet](https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9500-series-switches/nb-06-cat9500-ser-data-sheet-cte-en.html),
revision dated 2026-07-01 and accessed 2026-07-29. These are product-identity sources, not proof that each PID has passed
the receiver's live qualification. Cisco's official lifecycle notices identify `C9500-12Q`, `C9500-24Q`, and
`C9500-40X` as end-of-sale with IOS XE 17.18 EM as their last supported train and `17.18.1` as their last maintenance
release, and identify `C9500-16X` as end-of-sale with 17.18 EM as its last supported train
([12Q/24Q/40X notice](https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9500-series-switches/c9500-12q-c9500-24q-c9500-40x-eol.html);
[16X notice](https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9500-series-switches/c9500-16x-switch-nm-c9500-nm-8x-nm-2q-eol.html)).
Admitting those exact legacy chassis identities at the contract's sole reviewed release is not a statement of
orderability, current vendor support entitlement, or receiver qualification.

C9300LM is not admitted because no retained C9300LM gNMI evidence or platform-specific contract exists. Expanding
this list requires documented product evidence, contract tests, and the same live qualification gates as the existing
entries.

For C9300/C9500, the only accepted canonical release identity is `17.18.1`. The configured forms `17.18.1`,
`17.18.01`, and `017.018.001` all canonicalize to that identity; they do not admit another maintenance release.
Prefer the canonical `software_version: "17.18.1"` form shown in the examples. The train-wide C9800 contract may use
another canonical 17.18 public release label, such as `17.18.1a`. Preflight normalizes the device's internal
install-version form (for example, `17.18.01.0.1186`) to the public label and compares the canonical labels. The receiver
does not retain the internal install build suffix or separate opaque `version-extension` in `os.version`. Preflight therefore
does not attest the exact image build, installed SMUs, or bit-for-bit image identity; retain those details separately
as live-qualification evidence. Before decoding C9300/C9500 JSON_IETF responses, the switch contracts canonicalize
Cisco's documented JSON-string-in-string PathElem keys only for the identity probes and built-in switch profile
models/list keys. Deduplication, aggregated list-key reconciliation, identity comparison, scope validation, mapping,
and caching then see one key representation. Custom-model keys and legacy contracts keep standard gNMI PathElem string
semantics.

The exact gNMI `0.4.0` protocol pin is derived from Cisco's IOS XE 17.18 programming guide, not from a retained
17.18.1 C9300/C9500 Capabilities capture. A public
[C9300 lab capture](https://github.com/jeremycohoe/cisco-ios-xe-gnmi/blob/55b2f0b5dcce11de7614e6aee7c59e9d1db50882/image-6.png)
advertises `0.7.0`, but it does not retain the PID, software build, boot mode, topology, or raw response needed to
associate that value with this contract; its visible module dates also predate the 17.18.1 schema set. The receiver
therefore rejects `0.7.0` rather than treating pre-1.0 semantic versions as a compatible range. Live qualification must
retain the exact 17.18.1 value from both platforms; a different value requires an explicit wire-compatibility review
and closed allowlist update before admission.

### IOS XE 17.18.1 schema provenance

The reviewed schema baseline is the Cisco/YangModels IOS XE `17181` publication at immutable commit
[`63fa41359e1a5d14c844a3a87d8b7d9c000d1e44`](https://github.com/YangModels/yang/tree/63fa41359e1a5d14c844a3a87d8b7d9c000d1e44/vendor/cisco/xe/17181).
Raw-file SHA-256 values below were verified on 2026-07-29. C9300/C9500 Capabilities must advertise each exact
`ModelData` name and organization plus either the listed revision date or the corresponding semantic module version
for every module required by the enabled identity/profile plan. The table is the complete seven-entry reviewed direct
catalog and a closed required-module allowlist for these two contracts: configuration and runtime preflight reject a
custom origin, explicit `models` entry, selector, or mapped descendant that introduces another module. A disabled
profile does not make its module a runtime requirement. Accepting both documented representations does not admit a
different schema.

| Reviewed direct module | Organization | Accepted `ModelData.version` | Raw-file SHA-256 |
| --- | --- | --- | --- |
| [`Cisco-IOS-XE-device-hardware-oper`](https://github.com/YangModels/yang/blob/63fa41359e1a5d14c844a3a87d8b7d9c000d1e44/vendor/cisco/xe/17181/Cisco-IOS-XE-device-hardware-oper.yang) | `Cisco Systems, Inc.` | `2025-03-01` or `1.12.0` | `0086ba926fb8be8295f3362141ca83ae2fa4f9cf572accee9cbfd0989f089379` |
| [`Cisco-IOS-XE-install-oper`](https://github.com/YangModels/yang/blob/63fa41359e1a5d14c844a3a87d8b7d9c000d1e44/vendor/cisco/xe/17181/Cisco-IOS-XE-install-oper.yang) | `Cisco Systems, Inc.` | `2025-07-01` or `2.1.0` | `1305174ffd5c14796930b5eba231874a1341019da76a19da3e9678a0f6bf0276` |
| [`Cisco-IOS-XE-platform-software-oper`](https://github.com/YangModels/yang/blob/63fa41359e1a5d14c844a3a87d8b7d9c000d1e44/vendor/cisco/xe/17181/Cisco-IOS-XE-platform-software-oper.yang) | `Cisco Systems, Inc.` | `2025-07-01` or `3.7.1` | `130a7f48ea178646077705e1247de74a74d7d6527e97971e10aea1bdf9e932b5` |
| [`Cisco-IOS-XE-process-cpu-oper`](https://github.com/YangModels/yang/blob/63fa41359e1a5d14c844a3a87d8b7d9c000d1e44/vendor/cisco/xe/17181/Cisco-IOS-XE-process-cpu-oper.yang) | `Cisco Systems, Inc.` | `2022-11-01` or `1.3.0` | `9436769911329db0343d46b71b435ef222811e6222c4f902c6d677eb9885fad5` |
| [`Cisco-IOS-XE-transceiver-oper`](https://github.com/YangModels/yang/blob/63fa41359e1a5d14c844a3a87d8b7d9c000d1e44/vendor/cisco/xe/17181/Cisco-IOS-XE-transceiver-oper.yang) | `Cisco Systems, Inc.` | `2025-03-01` or `1.7.0` | `19da5aec067583ac531ba10f9ee8158bd8baa20f2dedfb932765a91283ac01a1` |
| [`openconfig-interfaces`](https://github.com/YangModels/yang/blob/63fa41359e1a5d14c844a3a87d8b7d9c000d1e44/vendor/cisco/xe/17181/openconfig-interfaces.yang) | `OpenConfig working group` | `2018-01-05` or `2.3.0` | `215d568b14e69b4e13549f912c823f3d8bb0f4cbb1e93bbc238d6458604596b7` |
| [`openconfig-system`](https://github.com/YangModels/yang/blob/63fa41359e1a5d14c844a3a87d8b7d9c000d1e44/vendor/cisco/xe/17181/openconfig-system.yang) | `OpenConfig working group` | `2021-06-16` or `0.10.1` | `34757fcf70272fcae80f603795543fd0131829630371453bb88105be7ad48269` |

The direct path contract derived from that baseline is:

| Purpose | Selector and keyed list boundary | Source unit / normalization |
| --- | --- | --- |
| Chassis identity | `device-hardware-data/device-hardware/device-inventory`; key `hw-type hw-dev-index`; read `part-number` | Identity only |
| Release and boot mode | `install-oper-data/install-location-information`; key `fru slot bay chassis`; current version key `version version-extension`; read `oper-state/boot-mode` | Identity only; boot mode must be `INSTALL` |
| Host identity | `openconfig-system:system/state` | Identity only |
| CPU | `cpu-usage/cpu-utilization/five-seconds` | percent constrained to `[0,100]`, scaled by `0.01` to unit `1` |
| Memory | `cisco-platform-software/control-processes/control-process/memory-stats`; implicit list key `fru slot bay chassis`; read `used-percent` | percent constrained to `[0,100]`, scaled by `0.01` to unit `1` |
| Interfaces | `openconfig-interfaces:interfaces/interface/state`; implicit list key `name` | enums plus cumulative octet/packet/error/discard counters |
| Experimental DOM optics | `transceiver-oper-data/transceiver`; implicit list key `name` | `Cel`, `V`, `mA`, and `dB{mW}`; disabled until separate physical qualification |

The direct tuple gate does not prove the complete platform module/deviation closure. The pinned
[`capability-cat9k.xml`](https://github.com/YangModels/yang/blob/63fa41359e1a5d14c844a3a87d8b7d9c000d1e44/vendor/cisco/xe/17181/capability-cat9k.xml)
has raw SHA-256 `8268bd5e85489f9a8685f1d2dd3f2d4e7c15040886b3d69075e4339e286ea448`, declares
`module-set-id=dac0317e8f6f38441e24acacc5e3de7a`, and associates multiple Cisco deviations with the OpenConfig interface and
system modules. A live qualification must independently retain and compare the device's full Capabilities tuples,
YANG-library/module-set identifier, imported modules, and applicable deviations. Until that closure and exact-device
evidence are retained, `allow_unqualified: true` remains mandatory and the physical rows remain `Not run`.

C9300/C9500 preflight requires exactly one reported `hw-type-chassis` inventory group, one consistent exact
current-image identity across every reported current install location, and an unambiguous INSTALL boot mode. Identical
`(version, version-extension)` records at multiple locations are accepted; a missing value or any disagreement within
or across locations fails closed. Preflight never selects the first of multiple values and rejects BUNDLE, UNKNOWN,
missing, or conflicting boot modes. One reported chassis does not prove the physical topology.
Standalone C9300/C9500, C9300 StackWise, and C9500 StackWise Virtual require separate retained live evidence; stack and
SVL deployment remain unqualified until their inventory shape, member identity, switchover, and reconnect behavior are
captured. The topology evidence label is not an admission override: a stack/SVL run must still pass the exactly-one
`hw-type-chassis` check. A device that exposes multiple chassis groups is rejected by the current contract and cannot
produce a qualifying result without a capture-driven, separately reviewed identity contract. NX-OS accepts documented
builds such as `10.6(1)F` and `10.6(2n)F`.

The C9300 and C9500 physical-device qualification rows remain `Not run`, so those targets must explicitly set
`allow_unqualified: true`. The field is a fail-loud acknowledgement required by those contracts, is rejected when a
selected contract does not require it, and does not turn synthetic evidence into device qualification.

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

There is no OS-family compatibility fallback. Choose the product that matches the deployed chassis, configure its
expected software release identifier, and restart the receiver after correcting a terminal qualification failure.

## Secure configuration

```yaml
receivers:
  cisco_os:
    gnmi:
      max_datapoints_per_chunk: 10000
      max_cached_series: 500000
      targets:
        - name: access-switch-01
          endpoint: access-switch-01.example.net:9339
          product: catalyst_9300
          software_version: "17.18.1"
          # Required while retained C9300 physical-device qualification is Not run.
          allow_unqualified: true
          max_recv_msg_size_mib: 16
          encoding_preference: [json_ietf]
          credentials:
            mode: username_password
            username: otel-telemetry
            password: ${env:CISCO_GNMI_PASSWORD}
          tls:
            ca_file: /etc/otel/cisco-ca.pem
            min_version: "1.2"
            server_name_override: access-switch-01.example.net
            reload_interval: 1h
          profiles:
            identity:
              enabled: true
            system:
              enabled: true
            interfaces:
              enabled: true
            optics:
              # Enable only after separate chassis/line-card/optic qualification.
              enabled: false
```

`product` must be one of the seven canonical values in the contract table, and `software_version` must be the expected
software release identifier in that product's accepted train. Preflight compares canonical configured and observed
forms; for IOS XE this is the public release label rather than the internal image build or SMU state. The OS family is
derived from the product and is not configurable. Profiles are product-specific rather than a universal list:

| Product family | Default normalized profiles | Optional profiles |
| --- | --- | --- |
| Catalyst 9300 / Catalyst 9500 | Identity, CPU, per-location memory utilization, interface state, and cumulative interface counters | Experimental IOS XE DOM optics |
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

For an IOS XE password-authenticated production endpoint, the device-side qualification baseline is:

```text
gnxi
gnxi secure-trustpoint <device-server-trustpoint>
gnxi secure-password-auth
gnxi secure-port 9339
gnxi secure-server
no gnxi server
gnxi read-only
no gnxi enable-gnoi
```

Use `secure-client-auth` for mTLS and both authentication flags for combined mTLS plus username/password. Confirm the
effective flags, ports, and service state with `show gnxi state detail` and `show gnxi state stats`; do not infer them
from the presence of `secure-server`. The insecure and secure listeners can run simultaneously, which is why
`no gnxi server` is an explicit gate. The bare `gnxi` command starts the gNXI process; it is not a configuration
submode. `gnxi server` is the separate insecure-listener command and remains disabled above.

The pinned IOS XE 17.18.1
[`Cisco-IOS-XE-gnmi-cfg`](https://github.com/YangModels/yang/blob/63fa41359e1a5d14c844a3a87d8b7d9c000d1e44/vendor/cisco/xe/17181/Cisco-IOS-XE-gnmi-cfg.yang)
model defaults `enable-gnoi` to `true` and `read-only` to `false`. `gnxi read-only` makes gNMI Set return
`PERMISSION_DENIED` and disables all gNOI services; `no gnxi enable-gnoi` independently disables those services.
Both commands are mandatory defense in depth. Retain `show running-config` gNXI lines, `show gnxi state detail`, and
`show gnxi state stats`, and use a separate administrative read channel to verify the effective
`Cisco-IOS-XE-gnmi-cfg:gnmi-cfg-data/config/read-only=true` and `enable-gnoi=false` leaves. A configured line alone is
not effective-state evidence.

IOS XE's gNXI listener can expose gNOI certificate management, OS installation, and factory-reset operations. Current
Cisco documentation does not establish reliable gNMI path-level data authorization, so a dedicated collector account or
certificate must pass the controlled negative gNMI Set and gNOI tests below behind a management ACL/firewall. The
reviewed switch release `17.18.1` predates Cisco's `gnxi secure-vrf` feature, documented from 17.18.2. Use verified
management-plane ACL/firewall/control-plane isolation for 17.18.1; do not configure a later command or broaden the
product contract without a separate schema and device qualification.

Targets normally use no more than four compatible subscription streams. A target may explicitly raise its maximum to
eight only after that product and release have been qualified. Origins remain separate from paths: IOS XE uses
RFC7951 prefixing, IOS XR uses the module origin, and NX-OS uses generic `openconfig` for OpenConfig paths and `DME`
for the distinguished-name optics family.
IOS XR baseline collection uses two streams; enabling its experimental optics profile raises the total to three.

The seven Cisco product contracts require an origin for custom subscriptions and reject `path_target`. Catalyst
9300/9500 and both Nexus contracts reject literal `*` selectors. Unkeyed built-in list ancestors are not literal
wildcards. Three switch selectors rely on implicit list expansion: memory omits
`control-process[fru,slot,bay,chassis]`, interfaces omit `interface[name]`, and experimental optics omit
`transceiver[name]`. Each requires live Subscribe qualification on the exact build; optics remains disabled until its
path shape, returned volume, and physical readings are separately qualified.

`custom_subscriptions[].models` explicitly separates Capabilities requirements from the wire origin. It is optional
for non-generic origins, but required and non-empty for `origin: openconfig`. Each custom subscription accepts at most
32 unique, whitespace-free valid YANG module identifiers, preserving exact case. Every explicit model is included in
Capabilities validation. Entries must identify concrete modules; the generic name `openconfig` is rejected. For
C9300/C9500, every model derived from the complete custom plan must also be present in the seven-entry reviewed
catalog; `allow_unqualified` does not permit an unreviewed custom module. For example:

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
error and is never placed on a contract-governed request. Each target accepts at most eight custom streams. A custom stream has
at most 256 effective request selectors (explicit `paths`, or derived mapping paths when `paths` is omitted), 1024
mappings, and 64 path-key attributes per mapping. Each profile accepts at most 64 path overrides. Receiver-wide limits
are 4096 custom request paths, 16384 mappings, 4096 profile path overrides, and 64 MiB of retained custom/profile plan
strings; validation enforces them before request or mapping construction.

## Subscribe request parity

The receiver plans each physical subscription stream independently from one Capabilities response. A target-wide
`encoding_preference` can contain only encodings approved by the selected product contract. Catalyst 9300 and Catalyst
9500 accept JSON_IETF only. Catalyst 9800, ASR 9000, and NCS 5500 accept JSON_IETF or JSON; Nexus 9000 and Nexus 3500
accept JSON only. PROTO is rejected. When every preference field is omitted, requests use STREAM/SAMPLE, the existing
profile or custom sample interval, no list options or extensions, and JSON_IETF before JSON where the product contract
allows both encodings.

The Catalyst 9300 and Catalyst 9500 contracts additionally require the target to advertise gNMI `0.4.0`, use an
RFC7951 subscription-list prefix, and narrow Subscribe to STREAM/SAMPLE with one effective 1-to-604800-second cadence
per request. Updates-only, aggregation, QoS, Depth, heartbeat, suppression, ON_CHANGE, TARGET_DEFINED, ONCE, POLL,
mixed cadences, and literal `*` selectors fail validation. The built-in memory, interface, and experimental transceiver
selectors intentionally leave their respective list keys unset; those implicit expansions remain exact-build live
qualification gates. The CPU subscription terminates at the `five-seconds` leaf rather than requesting the entire CPU
subtree.

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
mapped output; POLL continues to use the client-side `poll_interval`. All Catalyst and Nexus contracts are STREAM-only.

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

Each stream owns its cache entries, atomic baselines, authoritative delete tombstones, and semantic-invalidation
watermarks. Before a new target session starts, the receiver silently resets only owners belonging to streams configured
with `updates_only: true`. The reset does not emit delete or optical-presence signals. Streams without `updates_only`
retain the existing cross-reconnect cache behavior.

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

1. Call Capabilities once on the target session, validate any product-pinned gNMI protocol version, and determine the
   product-approved encoding for every planned physical stream. C9300/C9500 require gNMI `0.4.0` and JSON_IETF.
2. Derive the required model set from the contract's identity probes, every enabled curated-profile path, each
   non-generic custom origin, every explicit custom `models` entry, and every valid RFC7951 module qualifier in
   selectors and mapped descendants. The generic NX-OS `openconfig` origin is not treated as a model; its concrete
   model requirements come from the built-in contract or the custom stream's required `models` list. Preserve exact
   YANG module-name case and reject a target when any required model is missing. C9300/C9500 also require the exact
   reviewed organization and revision-date-or-semantic-version tuple for every required enabled module in the pinned
   seven-entry closed catalog, reject a plan that derives any other module, and reject conflicting same-name catalog
   entries.
3. Run only the bounded identity Get probes declared by the selected contract and validate one unambiguous chassis
   identity plus a canonical observed software release identifier matching the configured identifier. C9300/C9500
   additionally require one consistent exact current-image identity across all current install locations and INSTALL
   boot mode.
4. Build the verified resource identity and launch metric Subscribe streams only after every preceding check passes.
   The verified session never invokes Set.

An identity that is missing, ambiguous, malformed, or oversized, a product or release mismatch, a missing required
model, an unsupported pinned model tuple or boot mode, an unsupported product-pinned gNMI protocol version, an
unsupported encoding, or a deterministic
malformed/unimplemented Capabilities response is a terminal compatibility failure. The receiver emits
`cisco.device.up=0`, records one bounded preflight failure,
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
and dynamic `_info` metrics are rejected. Each custom name is therefore an exact configuration-time descriptor rather
than part of fixed catalog completeness. Validation rejects collisions with the union of receiver, system-scraper, and
interface-scraper fixed catalogs and reserves the pattern-governed `cisco.catalyst9800.yang.__v1.*` and
`cisco.iosxr.yang.__v1.*` generated namespaces (and their broader product YANG namespaces) for model-derived telemetry.

## Metric contract

The product-specific identity, system, and interface profiles reuse the receiver's existing normalized metrics instead
of creating platform-specific duplicates. Catalyst 9300, Catalyst 9500, and Catalyst 9800 emit `cisco.device.up`,
`system.cpu.utilization`, and per-location `system.memory.utilization`. ASR 9000 and NCS 5500 emit
`cisco.device.up` and per-node `system.cpu.utilization`; they do not emit normalized memory or uptime. Nexus emits
`cisco.device.up` and has no system profile. No shared-gNMI product emits `system.uptime`.

Every product's interface profile emits `system.network.interface.status`, `cisco.interface.admin.status`, and the
cumulative sums `system.network.io`, `system.network.errors`, `system.network.packet.count`, and
`system.network.packet.dropped`. It does not emit `cisco.interface.speed`, `cisco.interface.io.rate`,
`cisco.interface.packet.rate`, or `cisco.interface.utilization`.

After verification, shared-gNMI resources include `cisco.product.family`, `device.manufacturer=Cisco`, the verified
`device.model.identifier`, canonical `os.version`, and, when required and verified by the product contract,
`cisco.os.boot_mode`. For IOS XE, `os.version` is the public release label and excludes the internal install build,
`version-extension`, and SMU state. Existing `cisco.os.name` and `os.name` remain available.
`cisco.platform.family` is retained as a legacy OS-family alias for compatibility; new grouping should use
`cisco.product.family`.

The receiver's internal telemetry exposes
`otelcol_ciscoosreceiver_gnmi_product_verified{cisco.gnmi.target}` and the cumulative
`otelcol_ciscoosreceiver_gnmi_preflight_failures{cisco.gnmi.target,cisco.gnmi.reason}`. Preflight reasons are bounded
to `identity_missing`, `identity_ambiguous`, `product_mismatch`, `release_mismatch`, `missing_model`,
`unsupported_model_version`, `unsupported_boot_mode`, `unsupported_gnmi_version`, `unsupported_encoding`, and
`malformed_identity`. Post-preflight stream degradation uses bounded `bisection_limit`, `cache_limit`,
`incompatible_path_group`, `unsupported_path`, and `unsupported_request_options` reasons. Self-telemetry separately
counts rejected invalid timestamps, ignored out-of-order updates, owner resets, and unsupported TypedValue kinds
without using device-controlled labels.

The optics profile emits explicit gauges. `network.interface.name`, `cisco.optics.lane`, an allowlisted
`cisco.optics.sensor`, `cisco.optics.profile`, and `cisco.optics.experimental` identify their source as applicable.

| Profile | Metric | Unit |
| --- | --- | --- |
| DOM | `cisco.optics.temperature` | `Cel` |
| DOM | `cisco.optics.voltage` | `V` |
| DOM | `cisco.optics.laser_bias_current` | `mA` |
| DOM | `cisco.optics.rx_power` | `dB{mW}` |
| DOM | `cisco.optics.tx_power` | `dB{mW}` |
| DOM | `cisco.optics.present` | `1` |
| VDM | `cisco.optics.esnr` | `dB` |
| VDM | `cisco.optics.tdecq` | `dB` |
| VDM | `cisco.optics.pre_fec_ber` | `1` |
| VDM | `cisco.optics.tec_current` | `mA` |
| VDM | `cisco.optics.tec_utilization` | `1` |

`dB{mW}` preserves the device's dBm scale using a valid UCUM annotation. UCUM braces are human-readable annotations,
so consumers must not treat this spelling as a machine-convertible 1 mW reference.

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
trimmed. `max_cached_series` sets one receiver-wide count ceiling for active mapped series, atomic baselines,
authoritative delete tombstones, and semantic-invalidation watermarks. The independent auxiliary entry ceiling is four
times that value, accounting for one NX sensor identity and the optical source, presence-count, and attribute entries
associated with a cached optical series. Each count ceiling is deterministically partitioned across selected targets.
The cache and auxiliary state also have separate receiver-wide
retained-byte ceilings: 1.5 GiB for cache correctness state and 256 MiB for auxiliary state, yielding a 1.75 GiB combined
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

Device timestamps are normalized from seconds, milliseconds, microseconds, or nanoseconds. Device time must be
synchronized within five seconds. A future value no more than five seconds ahead is clamped to receipt time so it
cannot poison cache ordering. A zero value, a value before year 2000, or a value more than five seconds in the future
is dropped, counted as an invalid timestamp, and leaves the curated profile qualification-degraded until receiver
restart; receipt-time fallback is never committed to cache. Older out-of-order state is ignored and counted without
advancing stream progress or target availability.

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

### Controlled Catalyst authorization test

C9300/C9500 authorization evidence must be produced outside the receiver and its live harness. Perform the following
only on a disposable or fully isolated exact-PID/exact-build lab switch with no production traffic:

1. Preserve the startup and running configuration, establish out-of-band console access and a rollback timer, and record
   the exact PID, topology, image filename, internal install version, `version-extension`, and SMUs.
2. Apply the secure baseline above through a separate administrative channel. Capture the sanitized gNXI running
   configuration, `show gnxi state detail`, `show gnxi state stats`, and an administrative read of the effective
   `read-only=true` and `enable-gnoi=false` YANG leaves.
3. With a separate one-off client using the exact collector account or certificate, issue a syntactically valid gNMI Set
   against a reversible test-only configuration leaf using its already-current value. Require gRPC
   `PERMISSION_DENIED`, then independently prove the configuration did not change. Stop and invalidate the run if the
   request succeeds or returns any other status.
4. With the same collector identity, call only a non-mutating gNOI read operation, such as certificate inventory. Require
   policy denial or service-level unavailability (`PERMISSION_DENIED` or `UNIMPLEMENTED`). A timeout, transport failure,
   generic `UNAVAILABLE`, or an unreachable listener is not proof that gNOI is disabled. Never invoke certificate
   install/rotate, OS install/activate, reboot, or factory reset during this test.
5. Sanitize credentials and private material, but retain the exact request operation/path, gRPC status and message,
   timestamp, collector-identity fingerprint, before/after configuration digest, and effective-state captures. Hash the
   immutable artifact as `sha256:<64 lowercase hex characters>` and make it independently retrievable by the backend
   assertion service.

For C9300/C9500, set that digest as `CISCOOS_E2E_GNMI_AUTHORIZATION_EVIDENCE_SHA256`. The read-only live harness never
issues Set or gNOI calls. It passes only the digest to the backend and requires the response to echo the exact digest and
attest `server_read_only=true`, `gnoi_disabled=true`, `negative_set_permission_denied=true`, and
`negative_gnoi_permission_denied_or_unimplemented=true`. Missing, mismatched, omitted, or false evidence fails qualification.

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
option rejection versus bad-path bisection, and proof that Set remains zero. Each of the seven contracts requires a
fake-server path through Capabilities, bounded identity Get, the permitted metric Subscribe shape,
verified resource attributes, and
decoded metrics. Negative cases must prove isolation without downgrade; transient network failures must continue
retrying.

Implementation coverage is recorded by product and train in the [validation matrix](validation-matrix.md). It does not
qualify a device. Live qualification is exact-build evidence and requires verified TLS, zero preflight failures, no
degraded enabled profile, active subscriptions, `cisco.device.up=1`, correct verified resource identity, backend
delivery, and at least three successful collection intervals. C9300/C9500 additionally require the external
content-addressed authorization artifact and four positive backend attestations defined above; receiver-side proof that
Set was never called is not device authorization evidence. Catalyst 9800 qualification must additionally exercise
`catalyst_9800_wireless` against representative AP and client state.

Catalyst 9300 and Catalyst 9500 qualification also requires an external inventory record for the physical topology.
The current identity probe rejecting multiple reported chassis groups is fail-closed against ambiguous inventory, but
one reported chassis group does not prove standalone operation. Record standalone, C9300 StackWise, or C9500 StackWise
Virtual explicitly and qualify each topology separately; stack/SVL support cannot be inferred from a standalone run.
The live harness enforces that record with `CISCOOS_E2E_GNMI_TOPOLOGY`: C9300 accepts only `standalone` or `stackwise`,
and C9500 accepts only `standalone` or `stackwise_virtual`. The backend assertion must echo the same label. This label
scopes evidence only; it neither enables stack/SVL support nor bypasses the single-chassis identity check.

The switch image artifact must also record INSTALL boot mode, the exact image filename, internal install version,
`version-extension`, installed SMUs, and a digest of that independently captured evidence. Retain the complete gNMI
Capabilities `ModelData` tuples and independently capture the YANG-library module-set/import/deviation closure. Keep its
`CISCOOS_E2E_GNMI_IMAGE_EVIDENCE_SHA256` separate from the authorization artifact and
`CISCOOS_E2E_GNMI_AUTHORIZATION_EVIDENCE_SHA256`; neither digest can substitute for the other. The seven-entry reviewed
direct catalog—and the subset enforced by a given enabled plan—does not, by itself, attest the complete CAT9K deviation
set.

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

An opt-in data-plane harness is included for the 100-target/500,000-state-capacity/16,700-point cache, mapping, and
lossless chunking portion. It holds 450,000 active series and then fills the remaining capacity with 25,000 delete
tombstones and 25,000 semantic-invalidation watermarks:

```sh
CISCOOS_GNMI_RUN_SCALE_QUALIFICATION=1 GOMAXPROCS=4 go test ./internal/gnmi \
  -run '^TestInternalGNMIScaleQualification_100Targets5000Ports500KStateCapacity$' -count=1 -v
```

The 2026-07-29 audited synthetic run used Go 1.25.12 on Darwin arm64, an Apple M3 Pro, 18 GiB host memory, and
`GOMAXPROCS=4`. It populated 450,000 active series in 3.986 seconds, processed the 16,700-point interval in 152.168 ms,
and filled the remaining state headroom in 960.387 ms. RSS was 1,662,844,928 bytes; measured four-core burst CPU was
24.93 percent and projected four-core CPU at the modeled one-second cadence was 3.79 percent. Conservative cache
accounting retained 1,199,168,900 bytes for active state and 1,439,531,900 bytes after barriers, below the
1,610,612,736-byte (1.5 GiB) cache ceiling. Chunks contained 10,000 and 6,700 datapoints with no loss. This is
implementation evidence, not physical-device qualification. The harness does not exercise 100 TLS listeners,
reconnect recovery, exporter queues, a 4 GiB memory-constrained runtime, or hardware; those portions of the scale gate
remain mandatory in the deployment environment.

Splunk Observability Cloud acceptance verifies metric names and dimensions, UCUM units (especially `dB{mW}`),
presence/freshness behavior, dashboards, and predictive-model inputs. Removal must stop new optical samples, and
detectors must exclude `present=0` and stale ports.
