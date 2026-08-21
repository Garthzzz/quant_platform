from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from quant_hub.ops.release_builder import seal_release
from quant_hub.ops.vm_bootstrap_cli import V39BootstrapError, prepare_v39_candidate


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
            "schema_version": "qrh-release-manifest/v1",
            "release_id": "v39-test",
            "built_at": "2026-08-21T00:00:00Z",
            "application": {
                "commit_sha": "0" * 40,
                "tracked_tree_sha256": "1" * 64,
                "build_tool_version": "tests/v1",
                "source_kind": "legacy_broadcast",
                "source_archive_sha256": archive_hash,
                "legacy_deployment_id": "legacy-v39-test",
            },
            "content": {
                "snapshot_id": "snapshot-v39-test",
                "source_inventory_sha256": "2" * 64,
                "ir_sha256": "3" * 64,
                "knowledge_sha256": "4" * 64,
                "search_sha256": "5" * 64,
                "knowledge_enrichment": {"status": "not_applicable"},
            },
            "resources": {},
            "state": {"compatibility": {"comments": {"read": [1], "write": [1]}}},
            "recovery": {"compatibility": {"checkpoint_manifest_schemas": ["qrh-checkpoint-manifest/v1"], "restore_protocol_versions": ["qrh-restore/v1"]}},
        }
        self.manifest_path = self.root / "release_manifest.json"
        sealed = seal_release(
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
        )
        partial = self.root / "incoming" / "v39-test.partial"
        self.assertEqual("candidate_prepared_not_active", result["status"])
        self.assertTrue((partial / "release_manifest.json").is_file())
        self.assertFalse((self.root / "control" / "active_release.json").exists())
        self.assertFalse(any(path.name.startswith(".qrh-v39-") for path in (self.root / "incoming").iterdir()))

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
            )
        self.assertFalse((self.root / "incoming" / "v39-test.partial").exists())


if __name__ == "__main__":
    unittest.main()
