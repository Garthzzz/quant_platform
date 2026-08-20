from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "release" / "freeze_inventory.py"
SPEC = importlib.util.spec_from_file_location("qrh_freeze_inventory", MODULE_PATH)
assert SPEC and SPEC.loader
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class ReleaseInventoryTests(unittest.TestCase):
    def _zip(self, root: Path, *, database_hash: str | None = None) -> Path:
        database = b"sqlite-fixture"
        manifest = {
            "schema_version": "qrh-company-broadcast-package/v1",
            "deployment_id": "fixture-v1",
            "package_revision": "fixture",
            "source_delivery": "fixture-source",
            "databases": {
                "archive.sqlite3": {
                    "bytes": len(database),
                    "sha256": database_hash or hashlib.sha256(database).hexdigest(),
                }
            },
        }
        path = root / "release.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("company_broadcast/deployment_manifest.json", json.dumps(manifest))
            archive.writestr("company_broadcast/runtime/db/archive.sqlite3", database)
            archive.writestr("company_broadcast/runtime_contract/code/src/app.py", "pass\n")
        return path

    def test_inventory_is_deterministic_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._zip(root)
            first = inventory.freeze_zip(path)
            second = inventory.freeze_zip(path)
            self.assertEqual(first, second)
            frozen = root / "inventory.json"
            frozen.write_bytes(inventory.canonical_json(first))
            self.assertEqual(first, inventory.verify_inventory(path, frozen))
            self.assertEqual(3, first["summary"]["files"])
            self.assertEqual(1, first["summary"]["categories"]["readonly_database"]["files"])

    def test_declared_database_identity_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self._zip(Path(temporary), database_hash="0" * 64)
            with self.assertRaisesRegex(inventory.InventoryError, "identity mismatch"):
                inventory.freeze_zip(path)

    def test_windows_unsafe_and_case_colliding_members_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "unsafe.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("../escape", "bad")
            with self.assertRaisesRegex(inventory.InventoryError, "unsafe"):
                inventory.freeze_zip(path)

            path = Path(temporary) / "collision.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("root/deployment_manifest.json", "{}")
                archive.writestr("root/Name.txt", "one")
                archive.writestr("root/name.txt", "two")
            with self.assertRaisesRegex(inventory.InventoryError, "case-colliding"):
                inventory.freeze_zip(path)


if __name__ == "__main__":
    unittest.main()
