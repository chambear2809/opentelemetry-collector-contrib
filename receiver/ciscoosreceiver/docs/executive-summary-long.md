# ciscoosreceiver — Full Engineering & Business Summary

## Background

The **Cisco AI Pod** is a Cisco-validated design for on-premises AI/ML infrastructure: UCS blade and rack servers with NVIDIA GPUs connected over a Nexus 9000 or Catalyst 9000 spine-leaf fabric, typically running RoCEv2 for GPU-to-GPU RDMA traffic. As enterprises stand up these environments for LLM training and inference, a gap has emerged in observability: Splunk Observability Cloud has deep coverage of compute (GPU utilization, memory, NCCL throughput) and storage, but no native path to stream operational metrics from the Cisco network devices that carry the AI data plane.

The `ciscoosreceiver` fills that gap. It is a new OpenTelemetry Collector receiver that connects to Cisco IOS, IOS-XE, and NX-OS devices over SSH, runs structured CLI show commands, parses the output, and emits OpenTelemetry metrics into Splunk Observability Cloud — with no SNMP, no third-party NMS, and no additional licensing.

---

## What It Collects

### Core Interface Metrics (all deployments)

Every scrape cycle collects from `show interface` on all physical and logical interfaces:

- **Throughput** — bytes and packets in/out per interface, with unicast/multicast/broadcast breakdown
- **Errors** — input and output error counts (CRC, runts, giants, frame errors, collisions)
- **Drops** — input queue drops, output drops
- **Rate samples** — 5-second input/output bit rate and packet rate (when enabled)
- **Operational status** — interface up/down as a gauge (`cisco.interface.status`)

These metrics use OpenTelemetry semantic convention names (`system.network.io`, `system.network.errors`, `system.network.packet.dropped`, `system.network.packets`) with proper UCUM units (`By`, `{packet}`, `{error}`) so they join naturally with host-level network metrics from the OTel `hostmetricsreceiver` in the same Splunk O11y charts.

### Device Health

- **`cisco.device.up`** — emits `1` when the device is reachable and responding, `0` on connection failure or mid-session loss. This feeds device availability SLOs in Splunk O11y and drives alerting without requiring a separate ping monitor.

### System Resources

- **`system.cpu.utilization`** — overall device CPU utilization, parsed from `show process cpu` (IOS/IOS-XE) or `show system resources` (NX-OS)
- **`system.memory.utilization`** — processor pool memory utilization ratio

### Transceiver DOM Sensors (optional, for optics health)

Parsed from `show interfaces transceiver details`:

- Temperature, supply voltage, TX/RX optical power, and laser bias current per lane
- Unit is carried as a dimension attribute (`cisco.transceiver.sensor.unit`: `Cel`, `V`, `mA`, `dBm`) using UCUM-compliant values
- Configurable interface include/exclude filters and a `max_interfaces` cap prevent high-cardinality explosions on large chassis

For AI Pod deployments this is critical: a degrading DAC cable or QSFP transceiver running hot will show up here before it causes packet loss on the RDMA fabric.

### Layer 2 Topology Counters (optional)

- **STP** — instance counts by state, topology change counters per VLAN/interface, blocked port counts
- **Port-channel / LACP** — port-channel and member operational status, LACP packet and error counters
- **Err-disabled interfaces** — per-interface err-disabled reason
- **vPC** (NX-OS) — vPC peer-link status and consistency-check failure counts

LACP and port-channel visibility is particularly valuable in AI Pod environments where link aggregation provides redundant paths between UCS FIs and Nexus leaf switches. A degraded LACP bond that loses a member silently halves the available bandwidth for RDMA traffic.

### Control-Plane Telemetry (optional troubleshooting group)

- **Per-process CPU** — top-N processes by 5-second CPU window (IOS-XE: `show processes cpu sorted 5sec`)
- **CoPP / policy-map** — packets and drops per class from `show policy-map control-plane`
- **Punt rates** — per-interface punt rates from hardware forwarding ASICs
- **Routing table sizes** — route counts by VRF, address family, and source protocol
- **ARP / adjacency table sizes** — per-VRF ARP and CEF adjacency entry counts
- **FIB / CEF summary** — forwarding table prefix counts
- **Forwarding drops** — CEF and ASIC-level forwarding drop counters by reason

### Protocol Traffic Counters (optional)

IP-layer packet, error, and drop counters from `show ip traffic` — useful for detecting routing protocol storms or ICMP floods that consume control-plane bandwidth.

---

## Architecture

```
Cisco Device (SSH)
    │
    ▼
OTel Collector
  ┌─────────────────────────────┐
  │  ciscoosreceiver            │
  │  ┌──────────┐ ┌──────────┐  │
  │  │  system  │ │interfaces│  │
  │  │ scraper  │ │ scraper  │  │
  │  └──────────┘ └──────────┘  │
  └─────────────────────────────┘
    │
    ▼  (OTLP)
Splunk Observability Cloud
```

The receiver supports multiple devices in a single collector instance — one SSH connection per device, persistent across scrape cycles. Scrapers are independently configurable, so a high-frequency interface poll (every 30 seconds) can coexist with a lower-frequency control-plane poll (every 5 minutes).

---

## Correctness Improvements

The receiver underwent a systematic multi-pass correctness review. The issues found and fixed would have manifested as silent failures against real Cisco devices, corrupt metric values at scale, or security vulnerabilities in production deployments.

### SSH Execution (Critical)

**Problem:** The original implementation used `session.RequestPty()` with transposed dimensions (512 rows, 80 columns) combined with `session.CombinedOutput()`. Cisco IOS/IOS-XE SSH servers reject PTY allocation on exec sessions and return errors silently; `CombinedOutput` would have returned empty output for every command, making the receiver collect no metrics whatsoever against real devices.

**Fix:** Removed PTY entirely. Uses `session.Run()` with explicit stdout/stderr buffers. Cisco devices frequently return non-zero exit codes for valid commands (e.g., when output is empty); the new implementation treats `ExitError` with non-empty output as success, preserving that output for parsing.

**Problem:** CLI output pagination (`--More--` prompts) would truncate `show interface` output on large devices mid-interface, causing parsers to silently drop all interfaces after the first page.

**Fix:** A dedicated `DisablePaging()` method sends `terminal length 0` as a separate exec session immediately after connection, before any show commands. This is the correct approach for Cisco SSH exec sessions — shell semicolons (`;`) are not supported in exec mode.

**Problem:** Context cancellation during SSH dial left open TCP connections and goroutines blocked indefinitely.

**Fix:** `dialSSH` wraps `cryptossh.Dial` in a goroutine with a `select` on `ctx.Done()`. A cleanup goroutine closes any connection that arrives after the context expires. All SSH sessions now call `session.Close()` in the context-cancel branch.

### SSH Host Key Security (High)

**Problem:** The receiver used `InsecureIgnoreHostKey()` unconditionally — a hardcoded insecure policy with no option to verify server identity.

**Fix:** Config now requires either `auth.known_hosts_file` (production) or `auth.insecure_skip_verify: true` (lab only, emits a startup warning). `config.Validate()` rejects configurations with neither set, preventing silent MITM exposure.

### Counter Precision on 100GbE+ Links (Critical)

**Problem:** All interface counter fields (`InputBytes`, `OutputBytes`, `InputPackets`, `OutputPackets`, and all unicast/multicast/broadcast breakdowns) were stored as `float64`. IEEE 754 double precision loses integer exactness above 2^53 (~9 PB of bytes or ~9 quadrillion packets). On 100GbE links continuously at line rate, the byte counter wraps 2^53 in approximately 10 days, after which every reported metric value is silently corrupted by rounding.

**Fix:** All counter fields changed to `int64`. Added `str2int64()` which parses directly with `strconv.ParseInt`, handling both normal and 2^63-overflow cases correctly. All `int64(intf.X)` casts in the scraper removed as now redundant.

### Metric Unit Conventions (High)

**Problem:** Two metrics used non-standard plural unit strings (`{errors}`, `{packets}`) that violated OTel semantic conventions and would have caused Splunk O11y to treat them as incompatible with equivalent metrics from other receivers.

**Fix:** Units corrected to `{error}` and `{packet}` in `metadata.yaml` and all generated files. Transceiver temperature unit corrected from `"C"` to `"Cel"` (UCUM standard for Celsius).

### Connection Recovery (High)

**Problem:** Both scrapers checked `if rpcClient == nil` to decide whether to connect, but never cleared `rpcClient` after a broken connection. A device that went down mid-session would be retried forever against a dead SSH socket rather than attempting reconnection.

**Fix:** The interfaces scraper clears `rpcClient` and reconnects on next cycle when both primary and fallback interface commands fail. The system scraper detects mid-session connection loss when both CPU and memory collection fail simultaneously, clears the client, emits `cisco.device.up=0`, and reconnects on the next cycle.

**Problem:** `interfacesScraper.Start()` silently returned success when no device IP was configured, deferring the failure to the first `ScrapeMetrics()` call with a cryptic error.

**Fix:** `Start()` now returns an error immediately on empty IP, matching the system scraper's behaviour.

### Configuration Validation (Medium)

**Problem:** `config.Validate()` did not reject negative `Timeout` or zero/negative `CollectionInterval` values, which would cause runtime failures in the scraper controller.

**Fix:** Both are now validated at startup. `Timeout < 0` and `CollectionInterval <= 0` return descriptive errors.

### Control-Plane Config Symmetry (Medium)

**Problem:** `control_plane.commands.punt_rates` and `routing_forwarding.commands.forwarding_drops` were not enabled when their parent group (`control_plane.enabled: true` / `routing_forwarding.enabled: true`) was set, unlike every other command in the same groups.

**Fix:** Both `commandEnabled()` switch cases now correctly return `true` when the parent group is enabled.

### Default Timeout Alignment (Low)

**Problem:** `createDefaultConfig()` set `Timeout: 10 * time.Second` while the README and `testdata/config.yaml` documented 30 seconds.

**Fix:** Default aligned to `30 * time.Second`.

### Dead Code & Static Analysis

`staticcheck` surfaced an unused `packetCounterRegexp` variable and an unsafe bare array index `FindStringSubmatch(line)[1]` in `troubleshooting_parser.go` (would panic if the regex changed). Both fixed; `go vet` and `staticcheck` now pass clean.

---

## Splunk AI Pod Integration Scenarios

### 1. GPU Training Run Health Dashboard

Combine `ciscoosreceiver` interface metrics with GPU metrics from `dcgmreceiver` in a single Splunk O11y dashboard:

- GPU NVLink/NVSwitch utilization (already in O11y) alongside switch port utilization
- RDMA traffic rates on Nexus leaf-spine links during all-reduce operations
- Correlation between interface error spikes and NCCL timeout alerts

### 2. Fabric Congestion Detection

`cisco.interface.io.rate` (bits/s per interface) with direction and interface attributes enables real-time detection of congested uplinks. Alert when any leaf-spine uplink exceeds 80% utilization sustained for 60 seconds — before RDMA throughput degrades.

### 3. Optics Degradation Alerting

`cisco.transceiver.sensor` with `sensor=rx_power` and unit `dBm` enables:
- Threshold alerts on low received optical power (typically < -10 dBm indicates a problem)
- Early warning on DAC cables failing in high-density GPU rack cabling environments
- Trend analysis on transceiver temperature for thermal planning

### 4. Control-Plane Stability Monitoring

During large-scale AI Pod deployments or BGP convergence events:
- `cisco.routing.routes` tracks routing table growth
- `cisco.control_plane.cpu.process.utilization` identifies BGP/OSPF processes consuming excessive CPU
- `cisco.control_plane.packets` and dropped counts detect CoPP policy violations (e.g., ARP storms from newly provisioned GPU nodes)

### 5. Device Availability SLO

`cisco.device.up` per `host.ip` feeds a Splunk O11y service-level indicator for network device availability. Combined with the `os.name` resource attribute (`IOS XE`, `NX-OS`), this enables tiered alerting: spine switches at higher urgency than access-layer devices.

---

## Deployment

The receiver is configured as a standard OTel Collector component. A minimal AI Pod configuration for two Nexus 9000 leaf switches:

```yaml
receivers:
  cisco_os:
    collection_interval: 60s
    timeout: 30s
    devices:
      - name: leaf-01
        host: 10.0.0.1
        port: 22
        auth:
          username: otelcol
          known_hosts_file: /etc/otelcol/known_hosts
          password: ${env:CISCO_PASSWORD}
      - name: leaf-02
        host: 10.0.0.2
        port: 22
        auth:
          username: otelcol
          known_hosts_file: /etc/otelcol/known_hosts
          password: ${env:CISCO_PASSWORD}
    scrapers:
      system: {}
      interfaces:
        rates:
          enabled: true
        transceiver:
          enabled: true
        l2_topology:
          commands:
            lacp: true
            port_channel: true
```

---

## Status

- Stability: `alpha` metrics, matching the receiver metadata and factory registration
- Supported platforms: Cisco IOS-XE (Catalyst 9000), NX-OS (Nexus 9000)
- All tests passing; `go vet` and `staticcheck` clean
- Pending: end-to-end validation against physical AI Pod hardware
