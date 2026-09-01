from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest

from quant_hub.app import create_app
from tests.helpers import SettingsTestCase


def _load_gate_module():
    path = (
        Path(__file__).resolve().parents[1]
        / "tools"
        / "authenticated_route_performance_gate.py"
    )
    spec = importlib.util.spec_from_file_location("authenticated_route_gate_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GATE = _load_gate_module()
BASE_URL = "http://127.0.0.1:8765"


class AuthenticatedRoutePerformanceGateTests(unittest.TestCase):
    def test_only_management_topics_expand_to_management_detail(self) -> None:
        payload = {"topics": [{"topic_id": "top_example"}]}

        public_routes = GATE._json_routes(BASE_URL, "/api/v1/dashboard", payload)
        management_routes = GATE._json_routes(
            BASE_URL, "/api/v1/dashboard-topics", payload
        )

        detail = "/api/v1/dashboard-topics/top_example"
        self.assertNotIn(detail, public_routes)
        self.assertIn(detail, management_routes)

    def test_numeric_legacy_paper_ids_do_not_expand_to_paper_lab_routes(self) -> None:
        payload = {
            "components": [
                {"paper_id": "1"},
                {"paper_id": "labpaper_current"},
            ]
        }

        routes = GATE._json_routes(
            BASE_URL, "/api/v1/paper-lab/components", payload
        )

        self.assertNotIn("/paper-lab/papers/1", routes)
        self.assertNotIn("/api/v1/paper-lab/papers/1", routes)
        self.assertIn("/paper-lab/papers/labpaper_current", routes)
        self.assertIn("/api/v1/paper-lab/papers/labpaper_current", routes)

    def test_html_discovery_uses_response_url_and_get_form_actions(self) -> None:
        body = b"""
        <a href="../next/">next</a>
        <form method="get" action="search?q=alpha"></form>
        <form method="post" action="mutate"></form>
        """
        routes = GATE._html_routes(
            BASE_URL,
            BASE_URL + "/knowledge/research/doc/versions/ver/",
            body,
        )

        self.assertIn("/knowledge/research/doc/versions/next/", routes)
        self.assertIn(
            "/knowledge/research/doc/versions/ver/search?q=alpha", routes
        )
        self.assertNotIn("/knowledge/research/doc/versions/ver/mutate", routes)

    def test_json_discovery_accepts_any_same_origin_url_field(self) -> None:
        routes = GATE._json_routes(
            BASE_URL,
            "/api/example",
            {
                "citation_api_url": "/api/v1/evidence/citations/cit_example",
                "future_detail_url": "child",
                "external_url": "https://example.com/not-same-origin",
            },
            document_url=BASE_URL + "/api/example/",
        )

        self.assertIn("/api/v1/evidence/citations/cit_example", routes)
        self.assertIn("/api/example/child", routes)
        self.assertFalse(any("example.com" in route for route in routes))

    def test_deployment_identity_must_match_expected_release_and_manifest(self) -> None:
        manifest = "a" * 64
        payload = {
            "schema_version": "qrh-service-deployment-health/v1",
            "status": "ok",
            "release_id": "release-current",
            "manifest_sha256": manifest,
            "snapshot_id": "snapshot-current",
            "writer_authority": "exact-d-active",
            "pid": 101,
            "port": 8765,
        }
        identity = GATE._validate_deployment_identity(
            payload,
            expected_release_id="release-current",
            expected_manifest_sha256=manifest,
        )
        self.assertEqual("release-current", identity["release_id"])
        with self.assertRaises(GATE.GateError):
            GATE._validate_deployment_identity(
                payload,
                expected_release_id="release-other",
                expected_manifest_sha256=manifest,
            )


class AuthenticatedRoutePerformanceGateContractTests(SettingsTestCase):
    def test_flask_get_url_map_is_closed_by_gate_contract(self) -> None:
        app = create_app(self.settings, {"TESTING": True})
        actual = {
            rule.rule
            for rule in app.url_map.iter_rules()
            if "GET" in rule.methods
        }
        declared = set(GATE.GET_ROUTE_COVERAGE_CONTRACT).difference({"/deploymentz"})
        self.assertEqual(actual, declared)

    def test_generic_release_snapshot_expands_every_page_and_source(self) -> None:
        release_id = "release-test"
        snapshot_path = (
            self.root
            / "releases"
            / release_id
            / "content"
            / "deterministic_snapshot.json"
        )
        snapshot_path.parent.mkdir(parents=True)
        snapshot_path.write_text(
            json.dumps(
                {
                    "schema_version": "fixture/v1",
                    "snapshot": {
                        "snapshot_id": "snapshot-test",
                        "documents": {
                            "doc_example": {
                                "document_id": "doc_example",
                                "version_ids": ["ver_one", "ver_two"],
                            }
                        },
                    },
                }
            ),
            encoding="utf-8",
        )

        routes, evidence = GATE._generic_release_routes(self.root, release_id)

        self.assertEqual(1, evidence["document_count"])
        self.assertEqual(2, evidence["version_count"])
        self.assertEqual(5, evidence["route_count"])
        self.assertIn("/knowledge/research/doc_example/", routes)
        self.assertIn(
            "/knowledge/research/doc_example/versions/ver_two/source", routes
        )

    def test_evidence_output_cannot_escape_vm_root(self) -> None:
        inside = self.root / "audit" / "gate.json"
        GATE._atomic_write_json(inside, {"status": "PASS"}, vm_root=self.root)
        self.assertEqual(
            {"status": "PASS"}, json.loads(inside.read_text(encoding="utf-8"))
        )
        outside = self.root.parent / f"{self.root.name}-outside" / "gate.json"
        with self.assertRaises(GATE.GateError):
            GATE._atomic_write_json(outside, {}, vm_root=self.root)


if __name__ == "__main__":
    unittest.main()
