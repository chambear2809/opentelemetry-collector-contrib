#!/usr/bin/env python3
"""Tests for Splunk O11y dashboard bundle payload generation."""

from __future__ import annotations

import importlib.util
import io
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
import unittest


SCRIPT = Path(__file__).with_name("import_splunk_o11y_dashboards.py")
BUNDLES = sorted(Path(__file__).parent.glob("*.bundle.json"))


def load_importer():
    spec = importlib.util.spec_from_file_location(
        "import_splunk_o11y_dashboards", SCRIPT
    )
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DashboardImporterTest(unittest.TestCase):
    def test_all_bundle_paths_discovers_every_bundle(self) -> None:
        importer = load_importer()
        args = SimpleNamespace(all=True, bundle=str(SCRIPT.parent))

        paths = importer.bundle_paths(args)

        self.assertEqual([path.name for path in BUNDLES], [path.name for path in paths])

    def test_dashboard_payloads_include_filter_variables(self) -> None:
        importer = load_importer()
        for bundle_path in BUNDLES:
            with self.subTest(bundle=bundle_path.name):
                bundle = importer.load_bundle(str(bundle_path))
                for dashboard in bundle["dashboards"]:
                    chart_ids = [
                        f"chart-{i}" for i, _ in enumerate(dashboard["charts"])
                    ]
                    filters = importer.dashboard_filters(bundle, dashboard)
                    variables = importer.dashboard_filter_variables(filters)
                    payload = importer.dashboard_payload(
                        dashboard,
                        "dashboard-group-id",
                        chart_ids,
                        "Test - ",
                        filters,
                        ["team-1"],
                    )
                    self.assertNotIn("tags", payload)
                    self.assertEqual(
                        {"teams": ["team-1"]}, payload["authorizedWriters"]
                    )
                    self.assertIn("filters", payload)
                    self.assertIn("variables", payload["filters"])
                    api_variables = payload["filters"]["variables"]
                    self.assertEqual(len(variables), len(api_variables))
                    self.assertGreater(len(api_variables), 0)
                    for bundle_variable, api_variable in zip(variables, api_variables):
                        self.assertEqual(
                            bundle_variable["property"], api_variable["property"]
                        )
                        self.assertEqual(
                            bundle_variable["alias"], api_variable["alias"]
                        )
                        self.assertEqual(
                            bundle_variable.get("value", []), api_variable["value"]
                        )
                        self.assertLessEqual(
                            set(api_variable), importer.API_FILTER_VARIABLE_FIELDS
                        )
                        self.assertNotIn("description", api_variable)
                        self.assertNotIn("applyIfExists", api_variable)

    def test_chart_payloads_use_splunk_api_types(self) -> None:
        importer = load_importer()
        expected_types = {
            "TimeSeriesChart": "TimeSeriesChart",
            "List": "List",
            "Text": "Text",
        }
        for bundle_path in BUNDLES:
            with self.subTest(bundle=bundle_path.name):
                bundle = importer.load_bundle(str(bundle_path))
                for dashboard in bundle["dashboards"]:
                    for chart in dashboard["charts"]:
                        payload = importer.chart_payload(
                            chart,
                            "Test - ",
                            bundle.get(
                                "default_time_range_ms", importer.DEFAULT_RANGE_MS
                            ),
                            bundle.get("default_tags", []),
                        )
                        bundle_type = chart.get("type", "TimeSeriesChart")
                        self.assertEqual(
                            expected_types[bundle_type], payload["options"]["type"]
                        )
                        if bundle_type == "Text":
                            self.assertNotIn("programText", payload)
                            self.assertIn("markdown", payload["options"])
                        else:
                            self.assertEqual(
                                chart["signalflow"], payload["programText"]
                            )

    def test_native_integration_bundles_have_matching_metrics(self) -> None:
        expected_prefixes = {
            "cisco-catalyst-9800-dashboard-group.bundle.json": ("cisco.wlc.",),
            "cisco-catalyst-center-dashboard-group.bundle.json": ("catalyst_center.",),
            "cisco-fmc-dashboard-group.bundle.json": ("fmc.",),
            "cisco-intersight-dashboard-group.bundle.json": ("intersight.",),
            "cisco-ios-xr-dashboard-group.bundle.json": ("cisco.iosxr.",),
            "cisco-ise-dashboard-group.bundle.json": ("ise.",),
            "cisco-meraki-dashboard-group.bundle.json": ("meraki.",),
            "cisco-nexus-controller-dashboard-group.bundle.json": (
                "nexus_dashboard.",
                "aci.",
            ),
            "cisco-nexus-switch-dashboard-group.bundle.json": ("cisco.",),
            "cisco-os-dashboard-group.bundle.json": ("cisco.",),
            "cisco-sdwan-dashboard-group.bundle.json": ("sdwan.",),
        }
        bundles_by_name = {path.name: path for path in BUNDLES}
        metric_re = re.compile(r"data\('([^']+)'")

        self.assertLessEqual(set(expected_prefixes), set(bundles_by_name))
        for name, prefixes in expected_prefixes.items():
            with self.subTest(bundle=name):
                metrics = set(metric_re.findall(bundles_by_name[name].read_text()))
                for prefix in prefixes:
                    self.assertTrue(
                        any(metric.startswith(prefix) for metric in metrics),
                        f"{name} does not contain a {prefix} metric",
                    )

    def test_shared_gnmi_dashboard_covers_operational_contract(self) -> None:
        importer = load_importer()
        bundle_path = SCRIPT.parent / "cisco-os-dashboard-group.bundle.json"
        bundle = importer.load_bundle(bundle_path)
        dashboard = next(
            dashboard
            for dashboard in bundle["dashboards"]
            if dashboard["name"] == "08 Shared gNMI Operational Health"
        )
        program_text = ";".join(
            chart.get("signalflow", "") for chart in dashboard["charts"]
        )
        metrics = set(re.findall(r"data\('([^']+)'", program_text))
        expected_metrics = {
            "otelcol_ciscoosreceiver_gnmi_authentication_failures",
            "otelcol_ciscoosreceiver_gnmi_auxiliary_state_utilization",
            "otelcol_ciscoosreceiver_gnmi_cache_owner_resets",
            "otelcol_ciscoosreceiver_gnmi_cache_utilization",
            "otelcol_ciscoosreceiver_gnmi_connections",
            "otelcol_ciscoosreceiver_gnmi_consumer_refusals",
            "otelcol_ciscoosreceiver_gnmi_decode_errors",
            "otelcol_ciscoosreceiver_gnmi_deletes",
            "otelcol_ciscoosreceiver_gnmi_duplicate_updates",
            "otelcol_ciscoosreceiver_gnmi_invalid_timestamps",
            "otelcol_ciscoosreceiver_gnmi_out_of_order_updates",
            "otelcol_ciscoosreceiver_gnmi_last_success_unixtime",
            "otelcol_ciscoosreceiver_gnmi_preflight_failures",
            "otelcol_ciscoosreceiver_gnmi_product_verified",
            "otelcol_ciscoosreceiver_gnmi_profile_degraded",
            "otelcol_ciscoosreceiver_gnmi_reconnects",
            "otelcol_ciscoosreceiver_gnmi_subscriptions",
            "otelcol_ciscoosreceiver_gnmi_unmapped_values",
            "otelcol_ciscoosreceiver_gnmi_unsupported_value_kinds",
            "otelcol_ciscoosreceiver_gnmi_updates",
        }
        self.assertEqual(expected_metrics, metrics)

        filters = importer.dashboard_filters(bundle, dashboard)
        filter_properties = {
            variable["property"]
            for variable in importer.dashboard_filter_variables(filters)
        }
        self.assertLessEqual(
            {
                "cisco.product.family",
                "cisco.gnmi.target",
                "cisco.gnmi.profile",
            },
            filter_properties,
        )
        for dimension in (
            "cisco.gnmi.target",
            "cisco.gnmi.profile",
            "cisco.gnmi.reason",
            "cisco.gnmi.value_kind",
        ):
            self.assertIn(f"'{dimension}'", program_text)

    def test_high_risk_dashboard_dimensions_match_emitted_contracts(self) -> None:
        common_resource_dimensions = {
            "host.id",
            "host.name",
            "hw.type",
            "os.name",
            "cisco.controller.endpoint",
            "cisco.controller.type",
        }
        contracts = {
            "cisco.control_plane.cpu.process.utilization": {
                "cisco.process.name",
                "cisco.process.pid",
                "cisco.cpu.window",
            },
            "cisco.nve.vni.status": {
                "cisco.nve.vni",
                "cisco.nve.vni.type",
                "cisco.nve.state",
            },
            "cisco.vpc.consistency.failures": {"cisco.vpc.check"},
            "cisco.port_channel.status": {
                "cisco.port_channel.name",
                "cisco.port_channel.state",
            },
            "cisco.port_channel.member.status": {
                "cisco.port_channel.name",
                "cisco.port_channel.state",
                "network.interface.name",
            },
            "cisco.hardware.temperature": {
                "cisco.hardware.name",
                "cisco.hardware.slot",
                "cisco.hardware.state",
            },
            "cisco.transceiver.sensor": {
                "network.interface.name",
                "cisco.transceiver.sensor",
                "cisco.transceiver.lane",
                "cisco.transceiver.sensor.unit",
                "meraki.transceiver.sfp_product_id",
            },
            "sdwan.manager.endpoint.status": {"sdwan.api.operation"},
            "sdwan.inventory.device.count": {"sdwan.personality", "sdwan.status"},
            "intersight.ucs.memory.module.size": set(),
            "ise.radius.failure.count": {
                "ise.protocol",
                "event.outcome",
                "ise.failure.reason",
                "ise.message.code",
                "ise.policy.set",
            },
            "ise.tacacs.failure.count": {
                "ise.protocol",
                "event.outcome",
                "ise.failure.reason",
                "ise.message.code",
                "ise.policy.set",
            },
            "ise.session.count": {
                "ise.protocol",
                "event.outcome",
                "ise.posture.status",
            },
            "ise.policy.object.count": {"ise.policy.set", "ise.object.type"},
            "ise.trustsec.resource.count": {"ise.object.type"},
            "ise.alarm.count": {"ise.severity", "ise.object.type"},
            "ise.pxgrid.service.status": {"ise.object.type", "ise.protocol"},
            "nexus_dashboard.insights.anomaly.count": {
                "nexus_dashboard.insights.severity",
                "nexus_dashboard.insights.category",
            },
            "cisco.wlc.ap.join.status": {
                "cisco.wlc.ap.name",
                "cisco.wlc.ap.mac",
            },
            "cisco.wlc.ap.capwap.state": {"cisco.wlc.ap.mac", "state"},
            "cisco.wlc.rf.channel.utilization": {
                "cisco.wlc.ap.mac",
                "cisco.wlc.radio.slot",
                "utilization.type",
            },
            "cisco.wlc.rf.noise_floor": {
                "cisco.wlc.ap.mac",
                "cisco.wlc.radio.slot",
            },
            "cisco.wlc.rf.client.count": {
                "cisco.wlc.ap.mac",
                "cisco.wlc.radio.slot",
            },
            "cisco.wlc.rf.channel.change.count": {
                "cisco.wlc.ap.mac",
                "cisco.wlc.radio.slot",
            },
            "cisco.wlc.rf.channel.recommended": {
                "cisco.wlc.ap.mac",
                "cisco.wlc.radio.slot",
            },
            "cisco.wlc.client.connection.state": {"cisco.wlc.client.mac", "state"},
            "cisco.wlc.client.wireless.rssi": {"cisco.wlc.client.mac"},
            "cisco.wlc.client.wireless.snr": {"cisco.wlc.client.mac"},
            "cisco.wlc.client.auth.failure.reason.info": {
                "cisco.wlc.client.mac",
                "failure.reason",
            },
            "cisco.wlc.client.network.io": {"cisco.wlc.client.mac", "direction"},
            "cisco.wlc.client.network.packets": {
                "cisco.wlc.client.mac",
                "direction",
            },
            "cisco.wlc.client.roam.count": {
                "cisco.wlc.mobility.node_ip",
                "roam.layer",
            },
            "cisco.wlc.client.roam.failure.count": {"cisco.wlc.ssid"},
            "cisco.wlc.mobility.handoff.failure.count": {"handoff.type"},
            "cisco.wlc.ha.state": {"ha.role", "state"},
            "cisco.wlc.ha.enabled": set(),
        }
        bundle_contracts = {
            (
                "cisco-nexus-switch-dashboard-group.bundle.json",
                "cisco.topology.neighbor.info",
            ): {
                "network.interface.name",
                "cisco.topology.protocol",
                "cisco.topology.neighbor.name",
                "cisco.topology.neighbor.interface",
                "cisco.topology.neighbor.platform",
                "cisco.topology.neighbor.address",
            }
        }
        metric_re = re.compile(r"data\('([^']+)'")
        by_re = re.compile(r"by=\[([^\]]*)\]")
        filter_re = re.compile(r"filter\('([^']+)'")

        for bundle_path in BUNDLES:
            bundle = load_importer().load_bundle(bundle_path)
            for dashboard in bundle["dashboards"]:
                for chart in dashboard["charts"]:
                    for expression in chart.get("signalflow", "").split(";"):
                        metric_match = metric_re.search(expression)
                        if metric_match is None:
                            continue
                        metric = metric_match.group(1)
                        allowed = bundle_contracts.get((bundle_path.name, metric))
                        if allowed is None:
                            allowed = contracts.get(metric)
                        if allowed is None:
                            continue
                        used = set(filter_re.findall(expression))
                        by_match = by_re.search(expression)
                        if by_match is not None:
                            used.update(re.findall(r"'([^']+)'", by_match.group(1)))
                        unexpected = used - allowed - common_resource_dimensions
                        self.assertFalse(
                            unexpected,
                            f"{bundle_path.name} / {dashboard['name']} / {chart['name']} "
                            f"uses unsupported {metric} dimensions: {sorted(unexpected)}",
                        )

    def test_layout_rejects_missing_chart_ids(self) -> None:
        importer = load_importer()
        with self.assertRaisesRegex(ValueError, "same length"):
            importer.layout_charts([{"name": "chart"}], [])

    def test_layout_rejects_more_than_100_rows(self) -> None:
        importer = load_importer()
        charts = [{"name": f"chart-{i}", "width": 12, "height": 2} for i in range(51)]
        chart_ids = [f"id-{i}" for i in range(51)]

        with self.assertRaisesRegex(ValueError, "100-row"):
            importer.layout_charts(charts, chart_ids)

    def test_retry_policy_avoids_ambiguous_post_retries(self) -> None:
        importer = load_importer()

        self.assertTrue(importer.response_is_retryable("POST", 429))
        self.assertFalse(importer.response_is_retryable("POST", 500))
        self.assertTrue(importer.response_is_retryable("GET", 500))
        self.assertFalse(importer.response_is_retryable("GET", 400))

    def test_api_base_rejects_unsafe_token_destinations(self) -> None:
        importer = load_importer()

        self.assertEqual(
            "https://api.us1.observability.splunkcloud.com/v2",
            importer.api_base(SimpleNamespace(api_url="", realm="us1")),
        )
        self.assertEqual(
            "https://proxy.example.test/splunk/v2",
            importer.api_base(
                SimpleNamespace(
                    api_url="https://proxy.example.test/splunk/v2/", realm=""
                )
            ),
        )
        for api_url in (
            "http://api.example.test/v2",
            "https://token@api.example.test/v2",
            "https://api.example.test/v2?token=value",
            "https://api.example.test/v2#fragment",
        ):
            with self.subTest(api_url=api_url), self.assertRaises(ValueError):
                importer.api_base(SimpleNamespace(api_url=api_url, realm=""))
        with self.assertRaises(ValueError):
            importer.api_base(SimpleNamespace(api_url="", realm="us1/redirect"))

    def test_redirect_handler_never_forwards_the_api_token(self) -> None:
        importer = load_importer()
        request = urllib.request.Request(
            "https://api.us1.observability.splunkcloud.com/v2/chart",
            headers={"X-SF-TOKEN": "secret"},
        )

        with self.assertRaisesRegex(
            urllib.error.HTTPError, "redirects are disabled"
        ) as raised:
            importer.RejectRedirectHandler().redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "https://attacker.example.test/collect",
            )
        raised.exception.close()

    def test_client_bounds_success_responses(self) -> None:
        importer = load_importer()
        importer.MAX_API_RESPONSE_BYTES = 8

        class OversizedResponseOpener:
            def open(self, _request, timeout):
                self.timeout = timeout
                return io.BytesIO(b'{"value":1}')

        opener = OversizedResponseOpener()
        client = importer.SplunkO11yClient(
            "https://api.example.test/v2", "secret", opener=opener
        )

        with self.assertRaisesRegex(RuntimeError, "response larger than 8 bytes"):
            client.get("/dashboardgroup")
        self.assertEqual(30, opener.timeout)

    def test_client_omits_and_bounds_http_error_bodies(self) -> None:
        importer = load_importer()
        importer.MAX_API_ERROR_BYTES = 8
        secret = "super-secret-token"
        response_body = io.BytesIO(("echoed " + secret).encode())

        class ErrorOpener:
            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                raise urllib.error.HTTPError(
                    request.full_url,
                    400,
                    "Bad Request",
                    {},
                    response_body,
                )

        opener = ErrorOpener()
        client = importer.SplunkO11yClient(
            "https://api.example.test/v2", secret, opener=opener
        )

        with self.assertRaises(RuntimeError) as raised:
            client.post("/chart", {"name": "example"})

        message = str(raised.exception)
        self.assertIn("HTTP 400", message)
        self.assertIn("response body exceeded 8 bytes and was omitted", message)
        self.assertNotIn(secret, message)
        self.assertEqual(secret, opener.request.get_header("X-sf-token"))
        self.assertEqual(30, opener.timeout)
        self.assertTrue(response_body.closed)

    def test_retry_after_is_not_shortened(self) -> None:
        importer = load_importer()
        error = SimpleNamespace(headers={"Retry-After": "120"})

        self.assertEqual(120.0, importer.retry_delay_seconds(error, 1))

    def test_cumulative_dashboard_metrics_are_converted_to_rates(self) -> None:
        cumulative_metrics = {
            "aci.api.request.errors",
            "aci.api.endpoint.error",
            "aci.api.rate_limited",
            "catalyst_center.api.rate_limited",
            "catalyst_center.api.request.errors",
            "cisco.interface.qos.policy.bytes",
            "cisco.interface.qos.queue.bytes",
            "cisco.l2.stp.topology_changes",
            "cisco.lacp.errors",
            "fmc.api.endpoint.error",
            "fmc.api.rate_limited",
            "fmc.api.request.errors",
            "intersight.api.request.errors",
            "intersight.api.rate_limited",
            "ise.api.request.errors",
            "ise.dataconnect.query.errors",
            "meraki.api.request.errors",
            "meraki.api.request.rate_limited",
            "nexus_dashboard.api.request.errors",
            "nexus_dashboard.api.endpoint.error",
            "nexus_dashboard.api.rate_limited",
            "sdwan.api.rate_limited",
            "sdwan.api.request.errors",
            "sdwan.bfd.session.flap.count",
            "sdwan.bfd.session.transitions",
            "otelcol_ciscoosreceiver_gnmi_authentication_failures",
            "otelcol_ciscoosreceiver_gnmi_cache_owner_resets",
            "otelcol_ciscoosreceiver_gnmi_consumer_refusals",
            "otelcol_ciscoosreceiver_gnmi_decode_errors",
            "otelcol_ciscoosreceiver_gnmi_deletes",
            "otelcol_ciscoosreceiver_gnmi_duplicate_updates",
            "otelcol_ciscoosreceiver_gnmi_invalid_timestamps",
            "otelcol_ciscoosreceiver_gnmi_out_of_order_updates",
            "otelcol_ciscoosreceiver_gnmi_preflight_failures",
            "otelcol_ciscoosreceiver_gnmi_reconnects",
            "otelcol_ciscoosreceiver_gnmi_unmapped_values",
            "otelcol_ciscoosreceiver_gnmi_unsupported_value_kinds",
            "otelcol_ciscoosreceiver_gnmi_updates",
            "system.network.errors",
            "system.network.io",
            "system.network.packet.count",
            "system.network.packet.dropped",
        }
        program_re = re.compile(r"data\('([^']+)'([^;]*?\.publish\([^;]*?\))")

        for bundle_path in BUNDLES:
            with self.subTest(bundle=bundle_path.name):
                for metric, expression in program_re.findall(bundle_path.read_text()):
                    if metric in cumulative_metrics:
                        self.assertIn(
                            ".rate()",
                            expression,
                            f"{bundle_path.name} graphs cumulative {metric} without rate()",
                        )

    def test_rollback_deletes_children_before_group(self) -> None:
        importer = load_importer()

        class FakeClient:
            def __init__(self) -> None:
                self.paths = []

            def delete(self, path: str) -> dict:
                self.paths.append(path)
                return {}

        client = FakeClient()
        failures = importer.rollback_created_objects(
            client,
            "group-1",
            ["dashboard-1", "dashboard-2"],
            ["chart-1", "chart-2"],
        )

        self.assertEqual([], failures)
        self.assertEqual(
            [
                "/dashboard/dashboard-2",
                "/dashboard/dashboard-1",
                "/chart/chart-2",
                "/chart/chart-1",
                "/dashboardgroup/group-1",
            ],
            client.paths,
        )

    def test_live_verification_checks_round_tripped_objects(self) -> None:
        importer = load_importer()
        bundle = {
            "group": {"name": "Group"},
            "default_filters": {
                "variables": [
                    {
                        "property": "host.name",
                        "alias": "Device",
                        "value": [],
                    }
                ]
            },
            "dashboards": [
                {
                    "name": "Dashboard",
                    "charts": [
                        {
                            "name": "Time series",
                            "signalflow": "data('metric').publish()",
                        },
                        {"name": "Runbook", "type": "Text"},
                    ],
                }
            ],
        }
        created = importer.CreatedObjects(
            "group-1", ["dashboard-1"], ["chart-1", "chart-2"]
        )

        class FakeClient:
            def get(self, path: str) -> dict:
                return {
                    "/dashboardgroup/group-1": {
                        "id": "group-1",
                        "name": "Test - Group",
                        "dashboards": ["dashboard-1"],
                    },
                    "/dashboard/dashboard-1": {
                        "id": "dashboard-1",
                        "name": "Test - Dashboard",
                        "groupId": "group-1",
                        "charts": [
                            {
                                "chartId": "chart-1",
                                "row": 0,
                                "column": 0,
                                "width": 6,
                                "height": 2,
                            },
                            {
                                "chartId": "chart-2",
                                "row": 2,
                                "column": 0,
                                "width": 12,
                                "height": 1,
                            },
                        ],
                        "filters": {
                            "variables": [
                                {
                                    "property": "host.name",
                                    "alias": "Device",
                                    "value": [],
                                }
                            ]
                        },
                    },
                    "/chart/chart-1": {
                        "id": "chart-1",
                        "name": "Test - Time series",
                        "options": {"type": "TimeSeriesChart"},
                        "programText": "data('metric').publish()",
                    },
                    "/chart/chart-2": {
                        "id": "chart-2",
                        "name": "Test - Runbook",
                        "options": {"type": "Text"},
                    },
                }[path]

        importer.verify_created_objects(FakeClient(), created, bundle, "Test - ")

    def test_exact_group_match_prevents_false_positive(self) -> None:
        importer = load_importer()

        class FakeClient:
            def get(self, path: str) -> dict:
                self.path = path
                return {"results": [{"name": "Cisco OS Receiver - old"}]}

        client = FakeClient()
        self.assertFalse(
            importer.exact_dashboard_group_exists(client, "Cisco OS Receiver")
        )
        self.assertIn("name=Cisco+OS+Receiver", client.path)


if __name__ == "__main__":
    unittest.main()
