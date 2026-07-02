# VAST Storage For Cisco AI PODs

This guide shows how to collect VAST Storage metrics for Cisco AI POD environments with the Splunk Distribution of the OpenTelemetry Collector. It follows the same practical shape as Splunk's Pure Storage setup guidance for Cisco AI PODs: use Prometheus-compatible endpoints, add storage-specific resource attributes, keep high-cardinality families explicit, and import a Splunk Observability Cloud dashboard group.

VAST collection has two layers:

- VAST Management System (VMS) Prometheus endpoints for array, cluster, physical device, view, VIP, quota, alarm, and capacity telemetry.
- VAST CSI driver Prometheus endpoints for Kubernetes provisioning, controller, mount, and NFS transport health.

## Prerequisites

- Splunk Distribution of the OpenTelemetry Collector installed for the Cisco AI POD Kubernetes cluster.
- Network access from the Collector to the VAST Management System virtual IP (VMS VIP) over HTTPS, usually `https://<VMS_VIP>:443`.
- A VAST manager account with the built-in read-only role, or a bearer token/JWT that can call the VMS Prometheus exporter endpoints.
- A trusted CA file for the VMS certificate. Use `tls_config.insecure_skip_verify: true` only for isolated lab validation when the certificate cannot be verified.
- Optional: VAST CSI driver deployed in Kubernetes. CSI metrics are disabled by default and must be enabled in the VAST CSI Helm values.
- Optional: VAST vNFS Collector on Linux clients when workload-level NFS operation metrics are needed. Treat this as a later phase because it is privileged client-side collection and can emit high-cardinality workload dimensions.

## Version Matrix

| Capability | Version guidance | Notes |
| --- | --- | --- |
| VMS built-in Prometheus exporter | Modern supported VAST releases; VAST's public dashboard repo documents built-in exporters for VAST 4.7 and later. | Prefer the VMS exporter over the older external `vast-exporter` project. |
| Official VAST Grafana dashboards | VAST 5.1-sp40 and later in the current public dashboard repo. | Use these dashboards as a source of exact metric names and compatibility hints. |
| `/api/prometheusmetrics/basic_no_views` | VAST 5.4.3 and later. | Recommended for lightweight cluster coverage when available; remove this scrape job on older clusters. |
| `/api/prometheusmetrics/`, `/devices`, `/alarms`, `/views`, `/vips`, `/quotas` | Varies by VAST release and feature enablement. | These are the default endpoint families for this integration. |
| `/api/prometheusmetrics/users`, `/user_view`, `/host_view`, `/vip_view` | Version-gated and high-cardinality. | Enable only with explicit cost review and tight dashboard intent. |
| VAST CSI node/controller metrics | VAST CSI driver v2.6 docs describe metrics ports and ServiceMonitor support. | Node defaults to `9090`, controller to `9091`; block driver uses `9092` and `9093`. |

## VMS Authentication

Basic authentication is the simplest long-running scrape mode:

```yaml
basic_auth:
  username: ${env:VAST_VMS_USERNAME}
  password: ${env:VAST_VMS_PASSWORD}
```

Create a VAST manager user with read-only permissions for this purpose. Avoid using the full admin account in production.

Bearer/JWT authentication can also be used when your VMS access model requires it:

```yaml
authorization:
  type: Bearer
  credentials: ${env:VAST_VMS_JWT}
```

Prometheus scrape configuration does not refresh JWTs by itself. Use JWT mode only when token refresh and Collector config reload are handled by your deployment system, or when the token lifetime is operationally safe.

## TLS Guidance

Prefer a VMS certificate trusted by the Collector. In Prometheus scrape config, set:

```yaml
tls_config:
  ca_file: ${env:VAST_VMS_CA_FILE}
  insecure_skip_verify: false
```

For a lab-only smoke test with a self-signed certificate:

```yaml
tls_config:
  insecure_skip_verify: true
```

Do not leave `insecure_skip_verify: true` in production values.

## VMS Scrape Configuration

Use [`examples/vast-storage-splunk-otel.yaml`](../examples/vast-storage-splunk-otel.yaml) as the starting point. It defines a `prometheus/vast_vms` receiver with these endpoint families:

| Job | Metrics path | Default interval | Purpose |
| --- | --- | --- | --- |
| `vast_vms_basic_no_views` | `/api/prometheusmetrics/basic_no_views` | `1m` | Lightweight cluster/node/capacity/performance coverage on VAST 5.4.3+. |
| `vast_vms_cluster` | `/api/prometheusmetrics/` | `1m` | General cluster and CNode metrics not covered by narrower endpoints. |
| `vast_vms_devices` | `/api/prometheusmetrics/devices` | `1m` | SSD, NVRAM, DNode, CNode, NIC, fan, temperature, and state metrics. |
| `vast_vms_alarms` | `/api/prometheusmetrics/alarms` | `1m` | Active VAST cluster alarms. |
| `vast_vms_views` | `/api/prometheusmetrics/views` | `2m` | Per-view performance, capacity, latency, IOPS, bandwidth, and QoS metrics. |
| `vast_vms_vips` | `/api/prometheusmetrics/vips` | `2m` | VIP and VIP pool read/write IOPS, bandwidth, and latency. |
| `vast_vms_quotas` | `/api/prometheusmetrics/quotas` | `5m` | Quota, user quota, and group quota capacity metrics. |

Do not enable `/api/prometheusmetrics/all` by default. VAST warns that it exports every metric family and is not recommended for very large clusters. Use narrower endpoint families first.

## CSI Driver Metrics

Enable VAST CSI metrics in the CSI Helm values:

```yaml
node:
  metrics:
    enabled: true
    port: 9090
controller:
  metrics:
    enabled: true
    port: 9091
```

When running both NFS and block drivers, keep the default split ports so they do not conflict:

| Driver | Node port | Controller port |
| --- | --- | --- |
| `vastcsi` | `9090` | `9091` |
| `vastblock` | `9092` | `9093` |

Use [`examples/vast-storage-k8s-receiver-creator.yaml`](../examples/vast-storage-k8s-receiver-creator.yaml) when the Splunk Collector is using `k8s_observer` plus `receiver_creator/cisco-ai-pods`. The rules discover VAST CSI pods in the `vast-csi` namespace and scrape port endpoints on `9090`, `9091`, `9092`, and `9093`.

If you prefer direct Kubernetes service discovery in the Prometheus receiver, use endpoint discovery instead:

```yaml
receivers:
  prometheus/vast_csi:
    config:
      scrape_configs:
        - job_name: vast-csi-node-metrics
          metrics_path: /metrics
          kubernetes_sd_configs:
            - role: endpoints
              namespaces:
                names: [vast-csi]
          relabel_configs:
            - source_labels: [__meta_kubernetes_endpoint_port_name]
              regex: metrics
              action: keep
            - source_labels: [__meta_kubernetes_service_name]
              regex: .+-(vast|vastblock)-?node-metrics|.+-vast-node-metrics|.+-vastblock-node-metrics
              action: keep
        - job_name: vast-csi-controller-metrics
          metrics_path: /metrics
          kubernetes_sd_configs:
            - role: endpoints
              namespaces:
                names: [vast-csi]
          relabel_configs:
            - source_labels: [__meta_kubernetes_endpoint_port_name]
              regex: metrics
              action: keep
            - source_labels: [__meta_kubernetes_service_name]
              regex: .+-(vast|vastblock)-?controller-metrics|.+-vast-controller-metrics|.+-vastblock-controller-metrics
              action: keep
```

## Resource Attributes

Add these resource attributes before exporting to Splunk Observability Cloud:

```yaml
processors:
  resource/vast_storage:
    attributes:
      - key: storage.vendor
        value: vast
        action: upsert
      - key: ai.pod.component
        value: storage
        action: upsert
      - key: vast.cluster
        value: ${env:VAST_CLUSTER}
        action: upsert
      - key: k8s.cluster.name
        value: ${env:CLUSTER_NAME}
        action: upsert
      - key: deployment.environment
        value: ${env:ENVIRONMENT_NAME}
        action: upsert
      - key: environment
        value: ${env:ENVIRONMENT_NAME}
        action: upsert
```

The importable Splunk dashboard bundle uses these dimensions as filters where available: `vast.cluster`, `storage.vendor`, `ai.pod.component`, `k8s.cluster.name`, `environment`, `job`, `instance`, `view_name`, `tenant_name`, `vip`, `vippool`, `node_name`, `hostname`, `pvc_namespace`, and `network.interface.name`.

## Cardinality And Filtering

Start with the default VMS endpoint set. Add high-cardinality families only when the operational value is clear.

| Endpoint family | Cardinality risk | Recommendation |
| --- | --- | --- |
| `/users` | Per-user dimensions. | Enable for tenant/customer chargeback or noisy-user investigations only. |
| `/user_view` | User plus view dimensions. | Enable only for short incident windows or well-scoped environments. |
| `/host_view` | Client host plus view dimensions. | Enable only when host-to-view performance is required. |
| `/vip_view` | VIP plus view dimensions. | Enable only when VIP pool troubleshooting needs view-level context. |

If an endpoint must stay enabled but a destination should not receive expensive metric families, use the filter processor:

```yaml
processors:
  filter/vast_storage_cardinality:
    error_mode: ignore
    metric_conditions:
      - conditions:
          - IsMatch(metric.name, "^vast_user_.*")
          - IsMatch(metric.name, "^vast_user_view_.*")
          - IsMatch(metric.name, "^vast_host_view_.*")
          - IsMatch(metric.name, "^vast_vip_view_.*")
```

Put this processor before `batch` in the VAST metrics pipeline.

## Splunk Dashboard

Import the VAST dashboard group with:

```shell
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py \
  --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-vast-storage-dashboard-group.bundle.json \
  --dry-run
```

Remove `--dry-run` after validation. The dashboard group includes:

- `00 VAST Collection Trust`
- `01 VAST Cluster Health And Capacity`
- `02 VAST IOPS Bandwidth And Latency`
- `03 VAST Physical Devices And Media`
- `04 VAST CSI Provisioning And Mount Health`
- `05 Cisco AI POD Storage Fabric Correlation`

## Live Validation

Use `duo-sso` first when AWS/EKS access is required.

Validate Kubernetes access and CSI metrics:

```shell
kubectl get pods -n vast-csi
kubectl get services -n vast-csi
kubectl port-forward -n vast-csi pod/<vast-csi-node-pod> 9090:9090
curl -s http://localhost:9090/metrics | head
curl -s http://localhost:9090/health
```

Validate VMS endpoints:

```shell
curl -sku "$VAST_VMS_USERNAME:$VAST_VMS_PASSWORD" \
  "https://$VAST_VMS_VIP/api/prometheusmetrics/" | head

curl -sku "$VAST_VMS_USERNAME:$VAST_VMS_PASSWORD" \
  "https://$VAST_VMS_VIP/api/prometheusmetrics/devices" | head

curl -sku "$VAST_VMS_USERNAME:$VAST_VMS_PASSWORD" \
  "https://$VAST_VMS_VIP/api/prometheusmetrics/views" | head
```

Run the Collector locally or in-cluster with the debug exporter enabled, then verify these first:

- `up{job="vast_vms_cluster"}` or equivalent `up` series is `1`.
- `vast_cluster_online` is present.
- `vast_cluster_logical_space`, `vast_cluster_logical_space_in_use`, `vast_cluster_physical_space`, and `vast_cluster_physical_space_in_use` are present.
- `vast_view_metrics_ViewMetrics_read_iops_count` and write/read bandwidth and latency families are present when `/views` is enabled.
- `csi_plugin_operations_total` and `csi_node_mount_operations_total` are present when CSI metrics are enabled.

Finally, dry-run the dashboard importer:

```shell
python3 receiver/ciscoosreceiver/dashboards/splunk-o11y/import_splunk_o11y_dashboards.py \
  --bundle receiver/ciscoosreceiver/dashboards/splunk-o11y/cisco-vast-storage-dashboard-group.bundle.json \
  --dry-run
```
