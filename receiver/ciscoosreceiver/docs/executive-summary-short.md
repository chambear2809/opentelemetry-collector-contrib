# ciscoosreceiver — Executive Summary

## What This Delivers

The `ciscoosreceiver` is a new OpenTelemetry Collector receiver that streams real-time metrics from Cisco IOS, IOS-XE, and NX-OS devices over SSH into Splunk Observability Cloud. It is purpose-built for the **Cisco AI Pod** — the converged infrastructure stack (UCS compute, Nexus/Catalyst switching, ACI/NDFC fabric) that underpins Cisco-validated AI cluster deployments.

## Value for Splunk Observability Cloud + Cisco AI Pod

AI workloads are uniquely sensitive to network degradation. A single congested switch port or a flapping LACP bond can stall a GPU collective communication operation and cut training throughput by orders of magnitude. Today that signal is invisible in Splunk O11y unless the customer has already deployed a separate NMS.

This receiver closes that gap:

| Capability | What It Enables in Splunk O11y |
|---|---|
| Per-interface bytes, packets, errors, drops | Correlate network saturation with GPU utilization spikes in the same dashboard |
| Transceiver DOM sensors (power, temp, voltage) | Alert on failing optics before they cause packet loss in AI fabric links |
| LACP & port-channel health | Detect bond degradation that fragments RDMA bandwidth |
| Control-plane CPU & CoPP | Identify management-plane overload causing SSH/SNMP blackouts |
| Routing & forwarding table sizes, ARP/adjacency counts | Catch table exhaustion before it drops AI traffic |
| `cisco.device.up` gauge | Single pane-of-glass device health alongside compute and storage |
| STP topology changes, err-disabled ports | Surface L2 instability that disrupts RoCEv2/InfiniBand-over-Ethernet |

## Quality Improvements Shipped

A correctness review identified and fixed 20+ issues including: broken SSH session execution that would have silently failed against real Cisco devices, `float64` counter fields that lose precision on 100GbE+ links, a hardcoded insecure host-key policy, missing SSH host key verification, and metric unit strings that violated OTel semantic conventions. The receiver now ships in a production-ready state aligned with OpenTelemetry Collector contribution standards.

---
*Targets Cisco AI Pod deployments with IOS-XE on Catalyst 9000 and NX-OS on Nexus 9000 switching.*
