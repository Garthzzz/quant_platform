from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from quant_hub.ops.release_builder import seal_exact_release
from quant_hub.ops.vm_bootstrap_cli import (
    V39BootstrapError,
    activate_v39_pair_bridge,
    prepare_v39_candidate,
)


class V39BootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "app.py").write_bytes(b"print('v39')\n")
        self.archive = self.root / "payload.zip"
        with zipfile.ZipFile(self.archive, "w") as bundle:
            bundle.write(self.source / "app.py", "company_broadcast/app.py")
        archive_hash = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.release = {
            "schema_version": "qrh-release-manifest/v2",
            "release_id": "v39-test",
            "built_at": "2026-08-21T00:00:00Z",
            "application": {
                "build_tool_version": "tests/v1",
                "source_kind": "legacy_broadcast",
                "source_archive_sha256": archive_hash,
                "legacy_deployment_id": "legacy-v39-test",
                "provenance": {
                    "builder": "tests",
                    "labels": ["legacy-v39-baseline"],
                },
            },
            "content": {
                "snapshot_id": "snapshot-v39-test",
                "source_inventory_sha256": "2" * 64,
                "ir_sha256": "3" * 64,
                "knowledge_sha256": "4" * 64,
                "search_sha256": "5" * 64,
                "page_projection_sha256": None,
                "mcp_sha256": None,
                "active_membership_sha256": "6" * 64,
                "knowledge_enrichment": {"status": "not_applicable"},
                "presentation": {"language": "zh-CN"},
            },
            "resources": {},
            "state": {
                "compatibility": {
                    "comments": {"read": [1, 2], "write": [1, 2]},
                    "research_workspace": {
                        "read": [1, 2, 3],
                        "write": [1, 2, 3],
                    },
                    "rollback_policy": "expand_only_no_down_migration",
                }
            },
        }
        self.manifest_path = self.root / "release_manifest.json"
        sealed = seal_exact_release(
            candidate_root=self.source,
            manifest_without_inventory=self.release,
        )
        self.manifest_path.write_bytes((self.source / "release_manifest.json").read_bytes())
        self.release_hash = sealed.manifest_sha256
        (self.source / "release_manifest.json").unlink()

    def test_prepares_verified_partial_without_active_pointer(self) -> None:
        result = prepare_v39_candidate(
            vm_root=self.root,
            archive_path=self.archive,
            release_manifest_path=self.manifest_path,
            expected_release_id="v39-test",
            expected_release_manifest_sha256=self.release_hash,
            allow_test_root=True,
        )
        partial = self.root / "incoming" / "v39-test.partial"
        self.assertEqual("candidate_prepared_not_active", result["status"])
        self.assertTrue((partial / "release_manifest.json").is_file())
        self.assertFalse((self.root / "control" / "active_release.json").exists())
        self.assertFalse(any(path.name.startswith(".qrh-v39-") for path in (self.root / "incoming").iterdir()))

    def test_test_bootstrap_rejects_production_d_aliases_before_read_or_layout(self) -> None:
        aliases = (
            Path(r"D:\quant\quant_platform"),
            Path(r"D:\quant\quant_platform\."),
            Path(r"D:\quant\quant_platform\child\.."),
            Path(r"d:/QUANT/quant_PLATFORM"),
        )
        with patch(
            "quant_hub.ops.vm_bootstrap_cli.LocalDeploymentPersistence.for_test_only",
            side_effect=AssertionError("test persistence must not construct"),
        ), patch.object(
            Path,
            "read_text",
            side_effect=AssertionError("bootstrap input must not be read"),
        ):
            for alias in aliases:
                with self.subTest(alias=str(alias)), self.assertRaisesRegex(
                    V39BootstrapError, "cannot target production D root"
                ):
                    prepare_v39_candidate(
                        vm_root=alias,
                        archive_path=alias / "incoming" / "payload.zip",
                        release_manifest_path=(
                            alias / "incoming" / "release_manifest.json"
                        ),
                        expected_release_id="v39-test",
                        expected_release_manifest_sha256="a" * 64,
                        allow_test_root=True,
                    )

    def test_wrong_archive_or_extra_member_fails_without_partial(self) -> None:
        with zipfile.ZipFile(self.archive, "a") as bundle:
            bundle.writestr("outside.txt", b"bad")
        with self.assertRaises(V39BootstrapError):
            prepare_v39_candidate(
                vm_root=self.root,
                archive_path=self.archive,
                release_manifest_path=self.manifest_path,
                expected_release_id="v39-test",
                expected_release_manifest_sha256=self.release_hash,
                allow_test_root=True,
            )
        self.assertFalse((self.root / "incoming" / "v39-test.partial").exists())

    def test_exact_pair_bridge_orders_r0_before_distinct_r1(self) -> None:
        calls: list[tuple[str, str, str]] = []

        class Controller:
            existing = None

            def inspect_closed_bootstrap_baseline(
                self, *, release_id, expected_manifest_sha256
            ):
                calls.append(("inspect", release_id, expected_manifest_sha256))
                return self.existing

            def bootstrap_first_pair(
                self, *, release_id, expected_manifest_sha256, attempt_id
            ):
                calls.append(
                    ("bootstrap", release_id, expected_manifest_sha256)
                )
                return {
                    "status": "bootstrapped",
                    "release_id": release_id,
                    "release_manifest_sha256": expected_manifest_sha256,
                    "ingress_status": "closed",
                    "terminal_journal_sha256": "c" * 64,
                    "activation_receipt_id": f"activation-{attempt_id}",
                }

            def activate_successor(
                self, *, release_id, expected_manifest_sha256, attempt_id
            ):
                calls.append(
                    ("activate", release_id, expected_manifest_sha256)
                )
                return {
                    "status": "activated",
                    "release_id": release_id,
                    "release_manifest_sha256": expected_manifest_sha256,
                    "terminal_journal_sha256": "d" * 64,
                    "activation_receipt_id": f"activation-{attempt_id}",
                }

        with patch(
            "quant_hub.ops.vm_bootstrap_cli.ProductionExactDeploymentController.load_exact_d",
            return_value=Controller(),
        ):
            result = activate_v39_pair_bridge(
                baseline_release_id="release-v39-r0",
                baseline_manifest_sha256="a" * 64,
                successor_release_id="release-r1",
                successor_manifest_sha256="b" * 64,
                bootstrap_attempt_id="bootstrap-r0",
                activation_attempt_id="activate-r1",
            )
        self.assertEqual(
            [
                ("inspect", "release-v39-r0", "a" * 64),
                ("bootstrap", "release-v39-r0", "a" * 64),
                ("activate", "release-r1", "b" * 64),
            ],
            calls,
        )
        self.assertEqual("activated_pair", result["status"])
        self.assertEqual("release-r1", result["pair"]["active"]["release_id"])
        self.assertEqual(
            "release-v39-r0", result["pair"]["prior"]["release_id"]
        )
        self.assertFalse(result["bootstrap_reused"])

        calls.clear()
        resumed = Controller()
        resumed.existing = {
            "schema_version": "qrh-closed-bootstrap-baseline-proof/v1",
            "status": "closed_non_ingress",
            "release": {
                "release_id": "release-v39-r0",
                "manifest_sha256": "a" * 64,
            },
            "ingress_status": "closed",
            "terminal_journal_sha256": "c" * 64,
            "activation_receipt_id": "activation-old-bootstrap",
        }
        with patch(
            "quant_hub.ops.vm_bootstrap_cli.ProductionExactDeploymentController.load_exact_d",
            return_value=resumed,
        ):
            retried = activate_v39_pair_bridge(
                baseline_release_id="release-v39-r0",
                baseline_manifest_sha256="a" * 64,
                successor_release_id="release-r1",
                successor_manifest_sha256="b" * 64,
                bootstrap_attempt_id="new-bootstrap-id-must-not-run",
                activation_attempt_id="new-activate-r1",
            )
        self.assertEqual(
            [
                ("inspect", "release-v39-r0", "a" * 64),
                ("activate", "release-r1", "b" * 64),
            ],
            calls,
        )
        self.assertTrue(retried["bootstrap_reused"])
        with self.assertRaises(V39BootstrapError):
            activate_v39_pair_bridge(
                baseline_release_id="same",
                baseline_manifest_sha256="a" * 64,
                successor_release_id="same",
                successor_manifest_sha256="a" * 64,
                bootstrap_attempt_id="bootstrap-r0",
                activation_attempt_id="activate-r1",
            )


if __name__ == "__main__":
    unittest.main()
