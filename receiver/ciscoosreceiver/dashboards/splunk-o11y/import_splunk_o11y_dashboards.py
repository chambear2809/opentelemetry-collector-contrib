#!/usr/bin/env python3
"""Import Cisco OS receiver dashboards into Splunk Observability Cloud.

The input bundle is intentionally small and reviewable. This script converts it
to Splunk Observability Cloud chart, dashboard, and dashboard group API calls.
"""

from __future__ import annotations

import argparse
import copy
import email.utils
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_BUNDLE = Path(__file__).with_name("cisco-os-dashboard-group.bundle.json")
ALL_BUNDLE_GLOB = "cisco-*-dashboard-group.bundle.json"
DEFAULT_RANGE_MS = 60 * 60 * 1000
BUNDLE_SCHEMA = (
    "com.cisco.opentelemetry.ciscoosreceiver.splunk-o11y.dashboard-bundle/v1"
)
BUNDLE_TO_API_CHART_TYPE = {
    "TimeSeriesChart": "TimeSeriesChart",
    "List": "List",
    "Text": "Text",
}
API_FILTER_VARIABLE_FIELDS = {
    "alias",
    "preferredSuggestions",
    "property",
    "required",
    "restricted",
    "value",
}
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
IDEMPOTENT_METHODS = {"GET", "DELETE"}
MAX_REQUEST_ATTEMPTS = 4
MAX_RETRY_DELAY_SECONDS = 30.0
MAX_API_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_API_ERROR_BYTES = 64 * 1024
REALM_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


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
        help="Splunk Observability organization token with API permission, or a session token, used by an admin or power-role principal.",
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
        "--allow-duplicate",
        action="store_true",
        help="Allow creation when an exact dashboard-group name already exists; by default the importer fails safely.",
    )
    parser.add_argument(
        "--team-id",
        action="append",
        default=[],
        help="Splunk team ID to link to the dashboard group and authorize as a writer; repeat for multiple teams (requires the write-permissions feature).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and summarize the bundle without calling Splunk.",
    )
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="Create, GET-verify, and delete every requested object; requires a non-empty unique --prefix.",
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
    if bundle.get("schema") != BUNDLE_SCHEMA:
        raise ValueError(f"{context} schema must be {BUNDLE_SCHEMA}")

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
        require_string(
            dashboard, "description", f"{context} dashboard {dashboard_name}"
        )
        require_string(dashboard, "value", f"{context} dashboard {dashboard_name}")
        if dashboard_name in dashboard_names:
            raise ValueError(f"{context} duplicate dashboard name: {dashboard_name}")
        dashboard_names.add(dashboard_name)

        charts = dashboard.get("charts")
        if not isinstance(charts, list) or not charts:
            raise ValueError(
                f"{context} dashboard {dashboard_name} must contain charts"
            )
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
            if (
                not description.startswith("Value:")
                or "Interpretation:" not in description
            ):
                raise ValueError(
                    f"{context} chart {chart_name} description must contain Value and Interpretation"
                )

            chart_type = chart.get("type", "TimeSeriesChart")
            if chart_type not in BUNDLE_TO_API_CHART_TYPE:
                raise ValueError(
                    f"{context} chart {chart_name} has unsupported type: {chart_type}"
                )
            width = chart.get("width", 12 if chart_type == "Text" else 6)
            height = chart.get("height", 1 if chart_type == "Text" else 2)
            if (
                not isinstance(width, int)
                or isinstance(width, bool)
                or not 1 <= width <= 12
            ):
                raise ValueError(
                    f"{context} chart {chart_name} width must be an integer from 1 through 12"
                )
            if (
                not isinstance(height, int)
                or isinstance(height, bool)
                or not 1 <= height <= 3
            ):
                raise ValueError(
                    f"{context} chart {chart_name} height must be an integer from 1 through 3"
                )

            if chart_type == "Text":
                require_string(chart, "markdown", f"{context} text chart {chart_name}")
            else:
                signalflow = require_string(
                    chart, "signalflow", f"{context} chart {chart_name}"
                )
                published_labels = set(
                    re.findall(r"\.publish\(label=['\"]([^'\"]+)['\"]", signalflow)
                )
                label_options = chart.get("publish_label_options", [])
                if not isinstance(label_options, list):
                    raise ValueError(
                        f"{context} chart {chart_name} publish_label_options must be a list"
                    )
                for option in label_options:
                    if not isinstance(option, dict):
                        raise ValueError(
                            f"{context} chart {chart_name} publish_label_options entries must be objects"
                        )
                    label = require_string(
                        option,
                        "label",
                        f"{context} chart {chart_name} publish label option",
                    )
                    if label not in published_labels:
                        raise ValueError(
                            f"{context} chart {chart_name} publish label option {label!r} is not published by SignalFlow"
                        )

        dashboard_filter_variables(dashboard_filters(bundle, dashboard))


def validated_api_base(raw_url: str) -> str:
    parsed = urllib.parse.urlsplit(raw_url)
    if parsed.scheme.lower() != "https":
        raise ValueError("Splunk Observability API URL must use https")
    if not parsed.hostname:
        raise ValueError("Splunk Observability API URL must contain a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(
            "Splunk Observability API URL must not contain user information"
        )
    if parsed.query or parsed.fragment:
        raise ValueError(
            "Splunk Observability API URL must not contain a query or fragment"
        )
    try:
        parsed.port
    except ValueError as err:
        raise ValueError(
            "Splunk Observability API URL contains an invalid port"
        ) from err
    return raw_url.rstrip("/")


def api_base(args: argparse.Namespace) -> str:
    if args.api_url:
        return validated_api_base(args.api_url)
    if not args.realm:
        raise ValueError("SPLUNK_REALM or --realm is required")
    if not REALM_PATTERN.fullmatch(args.realm):
        raise ValueError("SPLUNK_REALM or --realm contains invalid characters")
    return validated_api_base(
        f"https://api.{args.realm}.observability.splunkcloud.com/v2"
    )


class RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent an API redirect from forwarding the Splunk token elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            "Splunk Observability API redirects are disabled",
            headers,
            fp,
        )


def read_bounded_body(stream: Any, limit: int) -> tuple[bytes, bool]:
    """Read at most limit bytes plus one byte used only to detect overflow."""
    if limit < 1:
        raise ValueError("response body limit must be positive")
    body = stream.read(limit + 1)
    return body[:limit], len(body) > limit


class SplunkO11yClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        max_attempts: int = MAX_REQUEST_ATTEMPTS,
        opener: Any | None = None,
    ) -> None:
        self.base_url = validated_api_base(base_url)
        self.token = token
        self.max_attempts = max_attempts
        self.opener = opener or urllib.request.build_opener(RejectRedirectHandler())

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
        for attempt in range(1, self.max_attempts + 1):
            try:
                with self.opener.open(request, timeout=30) as response:
                    response_bytes, oversized = read_bounded_body(
                        response, MAX_API_RESPONSE_BYTES
                    )
                    if oversized:
                        raise RuntimeError(
                            f"{method} {path} returned a response larger than "
                            f"{MAX_API_RESPONSE_BYTES} bytes"
                        )
                    try:
                        response_body = response_bytes.decode("utf-8")
                    except UnicodeDecodeError as err:
                        raise RuntimeError(
                            f"{method} {path} returned a non-UTF-8 response"
                        ) from err
                    if not response_body:
                        return {}
                    try:
                        return json.loads(response_body)
                    except json.JSONDecodeError as err:
                        raise RuntimeError(
                            f"{method} {path} returned invalid JSON"
                        ) from err
            except urllib.error.HTTPError as err:
                try:
                    _, error_body_oversized = read_bounded_body(
                        err, MAX_API_ERROR_BYTES
                    )
                    should_retry = response_is_retryable(method, err.code) and (
                        attempt < self.max_attempts
                    )
                    delay = retry_delay_seconds(err, attempt) if should_retry else 0
                finally:
                    err.close()
                if not should_retry:
                    ambiguity = ""
                    if method not in IDEMPOTENT_METHODS and err.code >= 500:
                        ambiguity = (
                            " The server might have accepted this non-idempotent request; "
                            "automatic retry was suppressed to avoid creating a duplicate."
                        )
                    body_status = "response body omitted"
                    if error_body_oversized:
                        body_status = (
                            f"response body exceeded {MAX_API_ERROR_BYTES} bytes and "
                            "was omitted"
                        )
                    raise RuntimeError(
                        f"{method} {path} failed with HTTP {err.code}; "
                        f"{body_status}.{ambiguity}"
                    ) from err
                time.sleep(delay)
            except urllib.error.URLError as err:
                if method not in IDEMPOTENT_METHODS or attempt == self.max_attempts:
                    ambiguity = ""
                    if method not in IDEMPOTENT_METHODS:
                        ambiguity = (
                            " The request outcome is unknown; automatic retry was suppressed "
                            "to avoid creating a duplicate."
                        )
                    raise RuntimeError(
                        f"{method} {path} failed due to a transport error.{ambiguity}"
                    ) from err
                time.sleep(min(2 ** (attempt - 1), MAX_RETRY_DELAY_SECONDS))
        raise RuntimeError(f"{method} {path} failed after {self.max_attempts} attempts")


def response_is_retryable(method: str, status_code: int) -> bool:
    """Retry explicit throttles, plus transient failures for idempotent requests."""
    return status_code == 429 or (
        method in IDEMPOTENT_METHODS and status_code in RETRYABLE_STATUS_CODES
    )


def retry_delay_seconds(err: urllib.error.HTTPError, attempt: int) -> float:
    retry_after = err.headers.get("Retry-After") if err.headers else None
    if retry_after:
        try:
            return max(float(retry_after), 0.0)
        except ValueError:
            try:
                parsed = email.utils.parsedate_to_datetime(retry_after)
            except (TypeError, ValueError):
                parsed = None
            if parsed is not None:
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                delay = (parsed - datetime.now(timezone.utc)).total_seconds()
                return max(delay, 0.0)
    return min(2 ** (attempt - 1), MAX_RETRY_DELAY_SECONDS)


def prefixed(prefix: str, name: str) -> str:
    return f"{prefix}{name}" if prefix else name


def chart_payload(
    chart: dict[str, Any],
    prefix: str,
    default_range_ms: int,
    default_tags: list[str],
) -> dict[str, Any]:
    bundle_chart_type = chart.get("type", "TimeSeriesChart")
    chart_type = BUNDLE_TO_API_CHART_TYPE[bundle_chart_type]
    options: dict[str, Any] = {"type": chart_type}

    if bundle_chart_type == "Text":
        options["markdown"] = chart["markdown"]
    else:
        if bundle_chart_type == "TimeSeriesChart":
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
        if bundle_chart_type == "TimeSeriesChart" and "legend_dimension" in chart:
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
    if bundle_chart_type != "Text":
        payload["programText"] = chart["signalflow"]
    return payload


def dashboard_payload(
    dashboard: dict[str, Any],
    group_id: str,
    chart_ids: list[str],
    prefix: str,
    filters: dict[str, Any] | None,
    team_ids: list[str] | None = None,
) -> dict[str, Any]:
    payload = {
        "name": prefixed(prefix, dashboard["name"]),
        "description": dashboard["description"],
        "groupId": group_id,
        "chartDensity": dashboard.get("chart_density", "HIGH"),
        "charts": layout_charts(dashboard["charts"], chart_ids),
    }
    if filters:
        payload["filters"] = api_dashboard_filters(filters)
    if team_ids:
        payload["authorizedWriters"] = {"teams": team_ids}
    return payload


def dashboard_filters(
    bundle: dict[str, Any], dashboard: dict[str, Any]
) -> dict[str, Any] | None:
    default_filters = copy.deepcopy(bundle.get("default_filters", {}))
    local_filters = copy.deepcopy(dashboard.get("filters", {}))
    if not default_filters and not local_filters:
        return None
    variables = default_filters.pop("variables", []) + local_filters.pop(
        "variables", []
    )
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
            raise ValueError(
                "dashboard filters.variables entries require property and alias"
            )
        if "value" in variable and not isinstance(variable["value"], list):
            raise ValueError("dashboard filters.variables value must be a list")
    return variables


def api_dashboard_filters(filters: dict[str, Any]) -> dict[str, Any]:
    """Translate review-friendly bundle filters to the Splunk v2 dashboard API."""
    result = copy.deepcopy(filters)
    variables = dashboard_filter_variables(result)
    api_variables = []
    for variable in variables:
        api_variable = {
            "property": variable["property"],
            "alias": variable["alias"],
            # The v2 API requires value even when no default filter is selected.
            "value": copy.deepcopy(variable.get("value", [])),
        }
        for field in ("preferredSuggestions", "required", "restricted"):
            if field in variable:
                api_variable[field] = copy.deepcopy(variable[field])
        api_variables.append(api_variable)
    result["variables"] = api_variables
    return result


def layout_charts(
    chart_specs: list[dict[str, Any]],
    chart_ids: list[str],
) -> list[dict[str, Any]]:
    if len(chart_specs) != len(chart_ids):
        raise ValueError("chart specifications and chart IDs must have the same length")

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

        if row + height > 100:
            raise ValueError("dashboard chart layout exceeds the 100-row API limit")

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
        raise RuntimeError(
            f"Splunk {kind} create response did not include an id: {response}"
        )
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


def exact_dashboard_group_exists(client: SplunkO11yClient, name: str) -> bool:
    query = urllib.parse.urlencode({"name": name, "limit": 50})
    response = client.get(f"/dashboardgroup?{query}")
    return any(group.get("name") == name for group in response.get("results", []))


@dataclass
class CreatedObjects:
    group_id: str
    dashboard_ids: list[str]
    chart_ids: list[str]


def response_dashboard_chart_ids(response: dict[str, Any]) -> set[str]:
    chart_ids = set()
    for chart in response.get("charts", []):
        if isinstance(chart, str):
            chart_ids.add(chart)
        elif isinstance(chart, dict):
            chart_id = chart.get("chartId") or chart.get("id")
            if chart_id:
                chart_ids.add(chart_id)
    return chart_ids


def verify_dashboard_filters(
    bundle: dict[str, Any],
    dashboard: dict[str, Any],
    response: dict[str, Any],
) -> None:
    expected_filters = dashboard_filters(bundle, dashboard)
    expected_variables = []
    if expected_filters:
        expected_variables = api_dashboard_filters(expected_filters).get(
            "variables", []
        )
    actual_variables = dashboard_filter_variables(response.get("filters"))
    if len(actual_variables) != len(expected_variables):
        raise RuntimeError(
            f"dashboard {dashboard['name']!r} returned {len(actual_variables)} variables; "
            f"expected {len(expected_variables)}"
        )
    actual_by_key = {
        (variable["property"], variable["alias"]): variable
        for variable in actual_variables
    }
    for expected in expected_variables:
        key = (expected["property"], expected["alias"])
        actual = actual_by_key.get(key)
        if actual is None:
            raise RuntimeError(
                f"dashboard {dashboard['name']!r} is missing variable {key!r}"
            )
        for field, value in expected.items():
            if actual.get(field) != value:
                raise RuntimeError(
                    f"dashboard {dashboard['name']!r} variable {key!r} returned "
                    f"{field}={actual.get(field)!r}; expected {value!r}"
                )


def verify_created_objects(
    client: SplunkO11yClient,
    created: CreatedObjects,
    bundle: dict[str, Any],
    prefix: str,
) -> None:
    expected_group_name = prefixed(prefix, bundle["group"]["name"])
    group = client.get(f"/dashboardgroup/{created.group_id}")
    if group.get("id") != created.group_id or group.get("name") != expected_group_name:
        raise RuntimeError(
            f"dashboard group verification failed for {expected_group_name!r}: {group}"
        )
    missing_dashboards = set(created.dashboard_ids) - set(group.get("dashboards", []))
    if missing_dashboards:
        raise RuntimeError(
            f"dashboard group {expected_group_name!r} is missing dashboards: {sorted(missing_dashboards)}"
        )

    expected_charts = [
        chart for dashboard in bundle["dashboards"] for chart in dashboard["charts"]
    ]
    if len(expected_charts) != len(created.chart_ids):
        raise RuntimeError(
            f"chart verification count mismatch: expected {len(expected_charts)}, created {len(created.chart_ids)}"
        )

    chart_offset = 0
    for dashboard, dashboard_id in zip(
        bundle["dashboards"], created.dashboard_ids, strict=True
    ):
        response = client.get(f"/dashboard/{dashboard_id}")
        expected_name = prefixed(prefix, dashboard["name"])
        if response.get("id") != dashboard_id or response.get("name") != expected_name:
            raise RuntimeError(
                f"dashboard verification failed for {expected_name!r}: {response}"
            )
        if response.get("groupId") != created.group_id:
            raise RuntimeError(
                f"dashboard {expected_name!r} returned unexpected groupId: {response.get('groupId')!r}"
            )
        chart_count = len(dashboard["charts"])
        expected_ids = set(created.chart_ids[chart_offset : chart_offset + chart_count])
        missing_chart_ids = expected_ids - response_dashboard_chart_ids(response)
        if missing_chart_ids:
            raise RuntimeError(
                f"dashboard {expected_name!r} is missing charts: {sorted(missing_chart_ids)}"
            )
        actual_layout = {
            chart["chartId"]: chart
            for chart in response.get("charts", [])
            if isinstance(chart, dict) and chart.get("chartId")
        }
        expected_layout = layout_charts(
            dashboard["charts"],
            created.chart_ids[chart_offset : chart_offset + chart_count],
        )
        for expected in expected_layout:
            actual = actual_layout.get(expected["chartId"])
            if actual is None:
                raise RuntimeError(
                    f"dashboard {expected_name!r} did not return layout for chart {expected['chartId']}"
                )
            for field in ("row", "column", "width", "height"):
                if actual.get(field) != expected[field]:
                    raise RuntimeError(
                        f"dashboard {expected_name!r} chart {expected['chartId']} returned "
                        f"{field}={actual.get(field)!r}; expected {expected[field]!r}"
                    )
        verify_dashboard_filters(bundle, dashboard, response)
        chart_offset += chart_count

    for chart, chart_id in zip(expected_charts, created.chart_ids, strict=True):
        response = client.get(f"/chart/{chart_id}")
        expected_name = prefixed(prefix, chart["name"])
        if response.get("id") != chart_id or response.get("name") != expected_name:
            raise RuntimeError(
                f"chart verification failed for {expected_name!r}: {response}"
            )
        expected_type = BUNDLE_TO_API_CHART_TYPE[chart.get("type", "TimeSeriesChart")]
        actual_type = response.get("options", {}).get("type")
        if actual_type != expected_type:
            raise RuntimeError(
                f"chart {expected_name!r} returned type {actual_type!r}; expected {expected_type!r}"
            )
        if (
            chart.get("type", "TimeSeriesChart") != "Text"
            and response.get("programText") != chart["signalflow"]
        ):
            raise RuntimeError(
                f"chart {expected_name!r} did not round-trip its SignalFlow program"
            )


def rollback_created_objects(
    client: SplunkO11yClient,
    group_id: str | None,
    dashboard_ids: list[str],
    chart_ids: list[str],
) -> list[str]:
    failures = []
    for kind, object_ids, path in (
        ("dashboard", reversed(dashboard_ids), "/dashboard/{}"),
        ("chart", reversed(chart_ids), "/chart/{}"),
    ):
        for object_id in object_ids:
            try:
                client.delete(path.format(object_id))
            except Exception as err:  # noqa: BLE001 - preserve the original import failure.
                failures.append(f"{kind} {object_id}: {err}")
    if group_id:
        try:
            client.delete(f"/dashboardgroup/{group_id}")
        except Exception as err:  # noqa: BLE001 - preserve the original import failure.
            failures.append(f"dashboard group {group_id}: {err}")
    return failures


def rollback_imports(
    client: SplunkO11yClient, completed_imports: list[CreatedObjects]
) -> list[str]:
    failures = []
    for created in reversed(completed_imports):
        failures.extend(
            rollback_created_objects(
                client,
                created.group_id,
                created.dashboard_ids,
                created.chart_ids,
            )
        )
    return failures


def dry_run(bundle: dict[str, Any], prefix: str, path: Path) -> None:
    group = bundle["group"]
    dashboards = bundle["dashboards"]
    charts = sum(len(dashboard["charts"]) for dashboard in dashboards)
    variables = 0
    for dashboard in dashboards:
        variables += len(
            dashboard_filter_variables(dashboard_filters(bundle, dashboard))
        )
    print("Dry run OK")
    print(f"Bundle: {path}")
    print(f"Group: {prefixed(prefix, group['name'])}")
    print(f"Dashboards: {len(dashboards)}")
    print(f"Charts: {charts}")
    print(f"Dashboard variables: {variables}")
    for dashboard in dashboards:
        print(f"- {prefixed(prefix, dashboard['name'])}: {dashboard['value']}")


def import_bundle(
    args: argparse.Namespace,
    bundle: dict[str, Any],
    client: SplunkO11yClient | None = None,
    *,
    check_duplicate: bool = True,
) -> CreatedObjects:
    if not args.token:
        raise ValueError(
            "SPLUNK_ACCESS_TOKEN, SPLUNK_O11Y_TOKEN, or --token is required"
        )

    if client is None:
        client = SplunkO11yClient(api_base(args), args.token)
    default_tags = bundle.get("default_tags", [])
    default_range_ms = bundle.get("default_time_range_ms", DEFAULT_RANGE_MS)
    team_ids = sorted(set(getattr(args, "team_id", [])))

    group_name = prefixed(args.prefix, bundle["group"]["name"])
    if (
        check_duplicate
        and not getattr(args, "allow_duplicate", False)
        and exact_dashboard_group_exists(client, group_name)
    ):
        raise RuntimeError(
            f"dashboard group {group_name!r} already exists; use --prefix for a versioned import or --allow-duplicate explicitly"
        )

    group_payload = {
        "name": group_name,
        "description": bundle["group"]["description"],
        "dashboards": [],
    }
    if team_ids:
        group_payload["authorizedWriters"] = {"teams": team_ids}
        group_payload["teams"] = team_ids
    group_id = None
    created_chart_ids: list[str] = []
    created_dashboard_ids: list[str] = []
    try:
        group_id = require_id(
            "dashboard group", client.post("/dashboardgroup", group_payload)
        )
        print(
            f"Created dashboard group {group_payload['name']} ({group_id})", flush=True
        )
        delete_empty_group_dashboard(client, group_id, group_payload["name"])

        for dashboard in bundle["dashboards"]:
            dashboard_chart_ids = []
            for chart in dashboard["charts"]:
                payload = chart_payload(
                    chart, args.prefix, default_range_ms, default_tags
                )
                chart_id = require_id("chart", client.post("/chart", payload))
                dashboard_chart_ids.append(chart_id)
                created_chart_ids.append(chart_id)

            payload = dashboard_payload(
                dashboard,
                group_id,
                dashboard_chart_ids,
                args.prefix,
                dashboard_filters(bundle, dashboard),
                team_ids,
            )
            dashboard_filter_variables(payload.get("filters"))
            dashboard_id = require_id("dashboard", client.post("/dashboard", payload))
            created_dashboard_ids.append(dashboard_id)
            print(f"Created dashboard {payload['name']} ({dashboard_id})", flush=True)
        return CreatedObjects(group_id, created_dashboard_ids, created_chart_ids)
    except Exception:
        rollback_failures = rollback_created_objects(
            client,
            group_id,
            created_dashboard_ids,
            created_chart_ids,
        )
        for failure in rollback_failures:
            print(f"rollback warning: {failure}", file=sys.stderr)
        raise


def main() -> int:
    args = parse_args()
    client = None
    completed_imports: list[CreatedObjects] = []
    try:
        bundles = [(path, load_bundle(path)) for path in bundle_paths(args)]
        if args.smoke_test and args.dry_run:
            raise ValueError("--smoke-test and --dry-run cannot be used together")
        if args.smoke_test and not args.prefix.strip():
            raise ValueError("--smoke-test requires a non-empty unique --prefix")
        if args.dry_run:
            for path, bundle in bundles:
                dry_run(bundle, args.prefix, path)
            return 0

        if not args.token:
            raise ValueError(
                "SPLUNK_ACCESS_TOKEN, SPLUNK_O11Y_TOKEN, or --token is required"
            )
        client = SplunkO11yClient(api_base(args), args.token)
        if not args.allow_duplicate:
            duplicates = [
                prefixed(args.prefix, bundle["group"]["name"])
                for _, bundle in bundles
                if exact_dashboard_group_exists(
                    client, prefixed(args.prefix, bundle["group"]["name"])
                )
            ]
            if duplicates:
                joined = ", ".join(repr(name) for name in duplicates)
                raise RuntimeError(
                    f"dashboard groups already exist: {joined}; use --prefix for a versioned import or --allow-duplicate explicitly"
                )

        if args.smoke_test:
            cleanup_failures = []
            try:
                for _, bundle in bundles:
                    completed_imports.append(
                        import_bundle(args, bundle, client, check_duplicate=False)
                    )
                for (_, bundle), created in zip(
                    bundles, completed_imports, strict=True
                ):
                    verify_created_objects(client, created, bundle, args.prefix)
            finally:
                cleanup_failures = rollback_imports(client, completed_imports)
                completed_imports.clear()
                for failure in cleanup_failures:
                    print(f"cleanup warning: {failure}", file=sys.stderr)
            if cleanup_failures:
                raise RuntimeError(
                    f"live smoke test verified objects but cleanup had {len(cleanup_failures)} failure(s)"
                )
            dashboard_count = sum(len(bundle["dashboards"]) for _, bundle in bundles)
            chart_count = sum(
                len(dashboard["charts"])
                for _, bundle in bundles
                for dashboard in bundle["dashboards"]
            )
            print(
                f"Live smoke test OK: verified and deleted {len(bundles)} groups, "
                f"{dashboard_count} dashboards, and {chart_count} charts",
                flush=True,
            )
        else:
            for _, bundle in bundles:
                completed_imports.append(
                    import_bundle(args, bundle, client, check_duplicate=False)
                )
            for (_, bundle), created in zip(bundles, completed_imports, strict=True):
                verify_created_objects(client, created, bundle, args.prefix)
            print(
                f"Import verified: {len(bundles)} groups, "
                f"{sum(len(bundle['dashboards']) for _, bundle in bundles)} dashboards, and "
                f"{sum(len(dashboard['charts']) for _, bundle in bundles for dashboard in bundle['dashboards'])} charts",
                flush=True,
            )
        return 0
    except Exception as err:  # noqa: BLE001 - command-line tool should print concise failures.
        if client is not None and completed_imports:
            rollback_failures = rollback_imports(client, completed_imports)
            for failure in rollback_failures:
                print(f"rollback warning: {failure}", file=sys.stderr)
        print(f"error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
