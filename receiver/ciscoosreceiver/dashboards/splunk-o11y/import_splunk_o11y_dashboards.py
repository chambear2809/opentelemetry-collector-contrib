#!/usr/bin/env python3
"""Import Cisco OS receiver dashboards into Splunk Observability Cloud.

The input bundle is intentionally small and reviewable. This script converts it
to Splunk Observability Cloud chart, dashboard, and dashboard group API calls.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_BUNDLE = Path(__file__).with_name("cisco-os-dashboard-group.bundle.json")
ALL_BUNDLE_GLOB = "cisco-*-dashboard-group.bundle.json"
DEFAULT_RANGE_MS = 60 * 60 * 1000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create the Cisco OS Receiver Splunk O11y dashboard group."
    )
    parser.add_argument(
        "--bundle",
        default=str(DEFAULT_BUNDLE),
        help="Path to a Cisco OS receiver dashboard bundle JSON file.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Import or validate every Cisco OS receiver dashboard bundle in the bundle directory.",
    )
    parser.add_argument(
        "--realm",
        default=os.environ.get("SPLUNK_REALM", ""),
        help="Splunk Observability realm, for example us0, us1, eu0.",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("SPLUNK_ACCESS_TOKEN")
        or os.environ.get("SPLUNK_O11Y_TOKEN", ""),
        help="Splunk Observability API token with dashboard write access.",
    )
    parser.add_argument(
        "--api-url",
        default=os.environ.get("SPLUNK_O11Y_API_URL", ""),
        help="Override API base URL, for example https://api.us1.observability.splunkcloud.com/v2.",
    )
    parser.add_argument(
        "--prefix",
        default="",
        help="Optional name prefix for the imported group, dashboards, and charts.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and summarize the bundle without calling Splunk.",
    )
    return parser.parse_args()


def bundle_paths(args: argparse.Namespace) -> list[Path]:
    if not args.all:
        return [Path(args.bundle)]

    bundle_dir = Path(args.bundle)
    if bundle_dir.is_file():
        bundle_dir = bundle_dir.parent

    paths = sorted(bundle_dir.glob(ALL_BUNDLE_GLOB))
    if not paths:
        raise ValueError(f"no dashboard bundles found in {bundle_dir}")
    return paths


def load_bundle(path: str | Path) -> dict[str, Any]:
    bundle_path = Path(path)
    with open(bundle_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    if "group" not in bundle or "dashboards" not in bundle:
        raise ValueError("bundle must contain group and dashboards fields")
    if not bundle["dashboards"]:
        raise ValueError("bundle must contain at least one dashboard")
    validate_bundle(bundle, bundle_path)
    return bundle


def require_string(value: dict[str, Any], field: str, context: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item.strip():
        raise ValueError(f"{context} must contain a non-empty {field} field")
    return item


def validate_bundle(bundle: dict[str, Any], path: Path) -> None:
    context = str(path)
    group = bundle.get("group")
    if not isinstance(group, dict):
        raise ValueError(f"{context} group must be an object")
    require_string(group, "name", f"{context} group")
    require_string(group, "description", f"{context} group")

    dashboards = bundle.get("dashboards")
    if not isinstance(dashboards, list) or not dashboards:
        raise ValueError(f"{context} dashboards must be a non-empty list")

    dashboard_names: set[str] = set()
    for dashboard in dashboards:
        if not isinstance(dashboard, dict):
            raise ValueError(f"{context} dashboards entries must be objects")
        dashboard_name = require_string(dashboard, "name", f"{context} dashboard")
        require_string(dashboard, "description", f"{context} dashboard {dashboard_name}")
        require_string(dashboard, "value", f"{context} dashboard {dashboard_name}")
        if dashboard_name in dashboard_names:
            raise ValueError(f"{context} duplicate dashboard name: {dashboard_name}")
        dashboard_names.add(dashboard_name)

        charts = dashboard.get("charts")
        if not isinstance(charts, list) or not charts:
            raise ValueError(f"{context} dashboard {dashboard_name} must contain charts")
        chart_names: set[str] = set()
        for chart in charts:
            if not isinstance(chart, dict):
                raise ValueError(f"{context} chart entries must be objects")
            chart_name = require_string(chart, "name", f"{context} chart")
            description = require_string(
                chart, "description", f"{context} chart {chart_name}"
            )
            if chart_name in chart_names:
                raise ValueError(
                    f"{context} dashboard {dashboard_name} duplicate chart name: {chart_name}"
                )
            chart_names.add(chart_name)
            if not description.startswith("Value:") or "Interpretation:" not in description:
                raise ValueError(
                    f"{context} chart {chart_name} description must contain Value and Interpretation"
                )

            if chart.get("type") == "Text":
                require_string(chart, "markdown", f"{context} text chart {chart_name}")
            else:
                require_string(chart, "signalflow", f"{context} chart {chart_name}")


def api_base(args: argparse.Namespace) -> str:
    if args.api_url:
        return args.api_url.rstrip("/")
    if not args.realm:
        raise ValueError("SPLUNK_REALM or --realm is required")
    return f"https://api.{args.realm}.observability.splunkcloud.com/v2"


class SplunkO11yClient:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", path, payload)

    def get(self, path: str) -> dict[str, Any]:
        return self._request("GET", path)

    def delete(self, path: str) -> dict[str, Any]:
        return self._request("DELETE", path)

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body,
            method=method,
            headers={
                "Content-Type": "application/json",
                "Connection": "close",
                "X-SF-TOKEN": self.token,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                response_body = response.read().decode("utf-8")
                if not response_body:
                    return {}
                return json.loads(response_body)
        except urllib.error.HTTPError as err:
            error_body = err.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"{method} {path} failed with HTTP {err.code}: {error_body}"
            ) from err


def prefixed(prefix: str, name: str) -> str:
    return f"{prefix}{name}" if prefix else name


def chart_payload(
    chart: dict[str, Any],
    prefix: str,
    default_range_ms: int,
    default_tags: list[str],
) -> dict[str, Any]:
    chart_type = chart.get("type", "TimeSeriesChart")
    options: dict[str, Any] = {"type": chart_type}

    if chart_type == "Text":
        options["markdown"] = chart["markdown"]
    else:
        if chart_type == "TimeSeriesChart":
            options.update(
                {
                    "defaultPlotType": chart.get("plot_type", "LineChart"),
                    "includeZero": chart.get("include_zero", True),
                    "showEventLines": chart.get("show_event_lines", True),
                    "time": {
                        "type": "relative",
                        "range": chart.get("time_range_ms", default_range_ms),
                    },
                }
            )
        for bundle_key, api_key in {
            "color_by": "colorBy",
            "color_range": "colorRange",
            "color_scale": "colorScale",
            "maximum_precision": "maximumPrecision",
            "secondary_visualization": "secondaryVisualization",
            "sort_by": "sortBy",
            "sort_direction": "sortDirection",
            "unit_prefix": "unitPrefix",
        }.items():
            if bundle_key in chart:
                options[api_key] = chart[bundle_key]
        if chart_type == "TimeSeriesChart" and "legend_dimension" in chart:
            options["onChartLegendOptions"] = {
                "showLegend": True,
                "dimensionInLegend": chart["legend_dimension"],
            }
        if "publish_label_options" in chart:
            options["publishLabelOptions"] = chart["publish_label_options"]

    payload: dict[str, Any] = {
        "name": prefixed(prefix, chart["name"]),
        "description": chart["description"],
        "options": options,
        "tags": sorted(set(default_tags + chart.get("tags", []))),
    }
    if chart_type != "Text":
        payload["programText"] = chart["signalflow"]
    return payload


def dashboard_payload(
    dashboard: dict[str, Any],
    group_id: str,
    chart_ids: list[str],
    prefix: str,
    default_tags: list[str],
    filters: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = {
        "name": prefixed(prefix, dashboard["name"]),
        "description": dashboard["description"],
        "groupId": group_id,
        "chartDensity": dashboard.get("chart_density", "HIGH"),
        "charts": layout_charts(dashboard["charts"], chart_ids),
        "tags": sorted(set(default_tags + dashboard.get("tags", []))),
    }
    if filters:
        payload["filters"] = filters
    return payload


def dashboard_filters(bundle: dict[str, Any], dashboard: dict[str, Any]) -> dict[str, Any] | None:
    default_filters = copy.deepcopy(bundle.get("default_filters", {}))
    local_filters = copy.deepcopy(dashboard.get("filters", {}))
    if not default_filters and not local_filters:
        return None
    variables = default_filters.pop("variables", []) + local_filters.pop("variables", [])
    filters = default_filters
    filters.update(local_filters)
    if variables:
        filters["variables"] = variables
    return filters


def dashboard_filter_variables(filters: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not filters:
        return []
    variables = filters.get("variables", [])
    if not isinstance(variables, list):
        raise ValueError("dashboard filters.variables must be a list")
    for variable in variables:
        if not isinstance(variable, dict):
            raise ValueError("dashboard filters.variables entries must be objects")
        if not variable.get("property") or not variable.get("alias"):
            raise ValueError("dashboard filters.variables entries require property and alias")
    return variables


def layout_charts(
    chart_specs: list[dict[str, Any]],
    chart_ids: list[str],
) -> list[dict[str, Any]]:
    layout = []
    row = 0
    column = 0
    row_height = 0

    for chart, chart_id in zip(chart_specs, chart_ids):
        is_text = chart.get("type") == "Text"
        width = chart.get("width", 12 if is_text else 6)
        height = chart.get("height", 1 if is_text else 2)

        if is_text or column + width > 12:
            if row_height:
                row += row_height
            column = 0
            row_height = 0

        layout.append(
            {
                "chartId": chart_id,
                "column": column,
                "row": row,
                "width": width,
                "height": height,
            }
        )

        column += width
        row_height = max(row_height, height)
        if column >= 12:
            row += row_height
            column = 0
            row_height = 0

    return layout


def require_id(kind: str, response: dict[str, Any]) -> str:
    object_id = response.get("id")
    if not object_id:
        raise RuntimeError(f"Splunk {kind} create response did not include an id: {response}")
    return object_id


def delete_empty_group_dashboard(
    client: SplunkO11yClient,
    group_id: str,
    group_name: str,
) -> None:
    group = client.get(f"/dashboardgroup/{group_id}")
    for dashboard_id in group.get("dashboards", []):
        dashboard = client.get(f"/dashboard/{dashboard_id}")
        if dashboard.get("name") == group_name and not dashboard.get("charts"):
            client.delete(f"/dashboard/{dashboard_id}")
            print(f"Deleted empty placeholder dashboard ({dashboard_id})", flush=True)


def dry_run(bundle: dict[str, Any], prefix: str, path: Path) -> None:
    group = bundle["group"]
    dashboards = bundle["dashboards"]
    charts = sum(len(dashboard["charts"]) for dashboard in dashboards)
    variables = 0
    for dashboard in dashboards:
        variables += len(dashboard_filter_variables(dashboard_filters(bundle, dashboard)))
    print("Dry run OK")
    print(f"Bundle: {path}")
    print(f"Group: {prefixed(prefix, group['name'])}")
    print(f"Dashboards: {len(dashboards)}")
    print(f"Charts: {charts}")
    print(f"Dashboard variables: {variables}")
    for dashboard in dashboards:
        print(f"- {prefixed(prefix, dashboard['name'])}: {dashboard['value']}")


def import_bundle(args: argparse.Namespace, bundle: dict[str, Any]) -> None:
    if not args.token:
        raise ValueError("SPLUNK_ACCESS_TOKEN, SPLUNK_O11Y_TOKEN, or --token is required")

    client = SplunkO11yClient(api_base(args), args.token)
    default_tags = bundle.get("default_tags", [])
    default_range_ms = bundle.get("default_time_range_ms", DEFAULT_RANGE_MS)

    group_payload = {
        "name": prefixed(args.prefix, bundle["group"]["name"]),
        "description": bundle["group"]["description"],
        "dashboards": [],
    }
    group_id = require_id("dashboard group", client.post("/dashboardgroup", group_payload))
    print(f"Created dashboard group {group_payload['name']} ({group_id})", flush=True)
    delete_empty_group_dashboard(client, group_id, group_payload["name"])

    for dashboard in bundle["dashboards"]:
        chart_ids = []
        for chart in dashboard["charts"]:
            payload = chart_payload(chart, args.prefix, default_range_ms, default_tags)
            chart_id = require_id("chart", client.post("/chart", payload))
            chart_ids.append(chart_id)

        payload = dashboard_payload(
            dashboard,
            group_id,
            chart_ids,
            args.prefix,
            default_tags,
            dashboard_filters(bundle, dashboard),
        )
        dashboard_filter_variables(payload.get("filters"))
        dashboard_id = require_id("dashboard", client.post("/dashboard", payload))
        print(f"Created dashboard {payload['name']} ({dashboard_id})", flush=True)


def main() -> int:
    args = parse_args()
    try:
        for path in bundle_paths(args):
            bundle = load_bundle(path)
            if args.dry_run:
                dry_run(bundle, args.prefix, path)
            else:
                import_bundle(args, bundle)
        return 0
    except Exception as err:  # noqa: BLE001 - command-line tool should print concise failures.
        print(f"error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
