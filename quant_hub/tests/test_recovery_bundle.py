from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import subprocess
import sys

from quant_hub.collaboration.checkpoint import create_sqlite_checkpoint
from quant_hub.ops.recovery_bundle import (
    RecoveryBundleError,
    build_recovery_bundle,
    finalize_recovery_receipt,
    restore_recovery_bundle,
    verify_recovery_bundle,
)
from quant_hub.ops.release_identity import canonical_manifest_bytes, manifest_sha256


def release_manifest() -> dict[str, object]:
    return {
        "schema_version": "qrh-release-manifest/v1",
        "release_id": "release-test-v1",
        "built_at": "2026-08-21T06:00:00+08:00",
        "application": {
            "commit_sha": "a" * 40,
            "tracked_tree_sha256": "1" * 64,
            "build_tool_version": "tests/v1",
        },
        "content": {
            "snapshot_id": "snapshot-test-v1",
            "source_inventory_sha256": "2" * 64,
            "ir_sha256": "3" * 64,
            "knowledge_sha256": "4" * 64,
            "search_sha256": "5" * 64,
            "knowledge_enrichment": {"status": "pending"},
        },
        "resources": {"inventory_sha256": "6" * 64},
        "state": {"compatibility": {"comments": {"read": [2], "write": [2]}}},
        "recovery": {
            "compatibility": {
                "checkpoint_manifest_schemas": ["qrh-checkpoint-manifest/v1"],
                "restore_protocol_versions": ["qrh-restore/v1"],
            }
        },
    }


class RecoveryBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.release = self.root / "candidate"
        self.release.mkdir()
        self.manifest = release_manifest()
        (self.release / "release_manifest.json").write_bytes(
            canonical_manifest_bytes(self.manifest)
        )
        (self.release / "app").mkdir()
        (self.release / "app" / "server.py").write_text("print('ok')\n", encoding="utf-8")
        (self.release / "resources").mkdir()
        (self.release / "resources" / "paper.bin").write_bytes(b"paper-bytes")

        state = self.root / "state"
        state.mkdir()
        comments = state / "comments.sqlite3"
        connection = sqlite3.connect(comments)
        try:
            connection.executescript("CREATE TABLE comment(id TEXT PRIMARY KEY); INSERT INTO comment VALUES('c1');")
            connection.commit()
        finally:
            connection.close()
        self.checkpoint = create_sqlite_checkpoint(
            sources={"comments": comments},
            checkpoint_root=self.root / "checkpoints",
            checkpoint_id="checkpoint-test-v1",
            state_authority_id="state-test",
            captured_under_release_id="release-test-v1",
            captured_under_manifest_sha256=manifest_sha256(self.manifest),
            captured_at=datetime(2026, 8, 21, 0, tzinfo=UTC),
        )
        self.recovery_root = self.root / "recovery"
        self.recovery_root.mkdir()
        self.restore_tool = self.root / "restore.py"
        self.restore_tool.write_text("# restore entrypoint\n", encoding="utf-8")
        self.runbook = self.root / "RUNBOOK.md"
        self.runbook.write_text("# 恢复\n\n机器验证后执行。\n", encoding="utf-8")

    def _build(self):
        return build_recovery_bundle(
            release_root=self.release,
            checkpoint_root=self.checkpoint.root,
            recovery_root=self.recovery_root,
            bundle_id="bundle-test-v1",
            created_at="2026-08-21T08:00:00+08:00",
            restore_tool=self.restore_tool,
            runbook=self.runbook,
            compatibility={"verdict": "compatible", "state_schema": 2},
        )

    def test_bundle_is_complete_verifiable_and_restores_empty_root(self) -> None:
        bundle = self._build()
        report = verify_recovery_bundle(bundle.root)
        self.assertTrue(report.valid, report.errors)
        self.assertEqual("release-test-v1", report.release_id)
        self.assertTrue((bundle.root / "SHA256SUMS").is_file())
        self.assertFalse(any(path.name == "viewer_secret.key" for path in bundle.root.rglob("*")))

        target = self.root / "empty" / "quant_platform"
        target.mkdir(parents=True)
        restored = restore_recovery_bundle(bundle_root=bundle.root, empty_target_root=target)
        self.assertEqual("release-test-v1", restored.release_id)
        self.assertFalse((target / "audit").exists())
        self.assertTrue((target / "state" / "comments.sqlite3").is_file())
        self.assertTrue((target / "control" / "active_release.json").is_file())
        connection = sqlite3.connect(target / "state" / "comments.sqlite3")
        try:
            self.assertEqual(1, connection.execute("select count(*) from comment").fetchone()[0])
        finally:
            connection.close()
        receipt = finalize_recovery_receipt(
            restored=restored,
            bundle_root=bundle.root,
            recovery_attempt_id="restore-test-v1",
            receipt_id="recovery-test-v1",
            recorded_at="2026-08-21T09:00:00+08:00",
            restore_verification={
                "closure": True,
                "state_restored": True,
                "service_started": True,
                "post_restore": True,
            },
        )
        self.assertTrue(receipt.is_file())

    def test_success_receipt_requires_post_restore_probes(self) -> None:
        bundle = self._build()
        target = self.root / "empty"
        target.mkdir()
        restored = restore_recovery_bundle(bundle_root=bundle.root, empty_target_root=target)
        with self.assertRaisesRegex(RecoveryBundleError, "all real probes"):
            finalize_recovery_receipt(
                restored=restored,
                bundle_root=bundle.root,
                recovery_attempt_id="restore-test-failed-probe",
                receipt_id="recovery-test-failed-probe",
                recorded_at="2026-08-21T09:00:00+08:00",
                restore_verification={
                    "closure": True,
                    "state_restored": True,
                    "service_started": False,
                    "post_restore": False,
                },
            )
        self.assertFalse((target / "audit").exists())

    def test_shipped_stdlib_tool_restores_without_quant_hub_import(self) -> None:
        project_root = Path(__file__).resolve().parents[2]
        restore_tool = project_root / "tools" / "release" / "restore_cold_bundle.py"
        bundle = build_recovery_bundle(
            release_root=self.release,
            checkpoint_root=self.checkpoint.root,
            recovery_root=self.recovery_root,
            bundle_id="bundle-stdlib-v1",
            created_at="2026-08-21T08:00:00+08:00",
            restore_tool=restore_tool,
            runbook=self.runbook,
            compatibility={"verdict": "compatible", "state_schema": 2},
        )
        target = self.root / "stdlib-empty"
        target.mkdir()
        copied_tool = bundle.root / "tools" / "restore" / restore_tool.name
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                str(copied_tool),
                "--bundle-root",
                str(bundle.root),
                "--empty-target-root",
                str(target),
            ],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual("materialized_pending_post_restore_verification", payload["status"])
        self.assertFalse((target / "audit").exists())

    def test_corruption_or_missing_object_fails_closed(self) -> None:
        bundle = self._build()
        (bundle.root / "release" / "resources" / "paper.bin").write_bytes(b"changed")
        self.assertFalse(verify_recovery_bundle(bundle.root).valid)
        target = self.root / "empty"
        target.mkdir()
        with self.assertRaisesRegex(RecoveryBundleError, "not restorable"):
            restore_recovery_bundle(bundle_root=bundle.root, empty_target_root=target)

    def test_bundle_id_is_immutable(self) -> None:
        first = self._build()
        before = hashlib.sha256((first.root / "recovery_manifest.json").read_bytes()).hexdigest()
        with self.assertRaisesRegex(RecoveryBundleError, "already exists"):
            self._build()
        self.assertEqual(
            before,
            hashlib.sha256((first.root / "recovery_manifest.json").read_bytes()).hexdigest(),
        )

    def test_secret_material_is_rejected_without_echoing_value(self) -> None:
        secret = "sk-" + "x" * 32
        (self.release / "app" / "settings.txt").write_text(
            "provider_key=" + secret + "\n", encoding="utf-8"
        )
        with self.assertRaises(RecoveryBundleError) as context:
            self._build()
        self.assertNotIn(secret, str(context.exception))
        self.assertFalse(any(self.recovery_root.iterdir()))

    def test_nonempty_restore_target_is_rejected(self) -> None:
        bundle = self._build()
        target = self.root / "not-empty"
        target.mkdir()
        (target / "keep.txt").write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(RecoveryBundleError, "real empty"):
            restore_recovery_bundle(bundle_root=bundle.root, empty_target_root=target)


if __name__ == "__main__":
    unittest.main()
