#!/usr/bin/env python3
"""Tests for Splunk O11y dashboard bundle payload generation."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest


SCRIPT = Path(__file__).with_name("import_splunk_o11y_dashboards.py")
BUNDLES = sorted(Path(__file__).parent.glob("*.bundle.json"))


def load_importer():
    spec = importlib.util.spec_from_file_location("import_splunk_o11y_dashboards", SCRIPT)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
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
                    chart_ids = [f"chart-{i}" for i, _ in enumerate(dashboard["charts"])]
                    filters = importer.dashboard_filters(bundle, dashboard)
                    variables = importer.dashboard_filter_variables(filters)
                    payload = importer.dashboard_payload(
                        dashboard,
                        "dashboard-group-id",
                        chart_ids,
                        "Test - ",
                        bundle.get("default_tags", []),
                        filters,
                    )
                    self.assertIn("filters", payload)
                    self.assertIn("variables", payload["filters"])
                    self.assertEqual(variables, payload["filters"]["variables"])
                    self.assertGreater(len(payload["filters"]["variables"]), 0)


if __name__ == "__main__":
    unittest.main()
