from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from quant_hub.ops.vm_boundary import (
    PRODUCTION_WRITE_AREAS,
    VMBoundaryError,
    build_vm_write_audit,
    capture_vm_write_snapshot,
    declared_production_vm_write_set,
    finalize_vm_write_audit,
    validate_production_vm_write_path,
    validate_vm_write_set,
)
from tools.release.restore_cold_bundle import (
    RestoreError,
    path_has_reparse,
    validate_production_restore_target,
)


ROOT = Path(__file__).resolve().parents[2]


class VMWriteBoundaryTests(unittest.TestCase):
    def test_all_approved_operational_paths_are_inside_exact_root(self) -> None:
        paths = validate_vm_write_set(
            [
                r"D:\quant\quant_platform\incoming\r1.partial",
                r"D:\quant\quant_platform\releases\r1",
                r"D:\quant\quant_platform\state\comments.sqlite3",
                r"D:\quant\quant_platform\backups\c1",
                r"D:\quant\quant_platform\audit\receipt.json",
                r"D:\quant\quant_platform\control\deploy.py",
                r"D:\quant\quant_platform\tmp\transfer.partial",
            ]
        )
        self.assertEqual(7, len(paths))

    def test_parent_sibling_c_drive_unc_and_ads_are_rejected(self) -> None:
        forbidden = [
            r"D:\candidate",
            r"D:\quant\candidate",
            r"D:\quant\quant_platform_other\candidate",
            r"D:\quant\quant_platform\..\outside",
            r"C:\quant_platform\new-file",
            r"C:\quant_platform_data\backup",
            r"\\server\share\quant_platform",
            r"D:\quant\quant_platform\state\db.sqlite3:stream",
            r"D:\quant\quant_platform\reference\must-remain-read-only.md",
            r"D:\quant\quant_platform\unreviewed-area\file.bin",
        ]
        for path in forbidden:
            with self.subTest(path=path), self.assertRaises(VMBoundaryError):
                validate_production_vm_write_path(path)

    def test_root_can_be_created_but_child_only_operations_can_forbid_it(self) -> None:
        self.assertEqual(
            r"D:\quant\quant_platform",
            str(validate_production_vm_write_path(r"D:\quant\quant_platform")),
        )
        with self.assertRaises(VMBoundaryError):
            validate_production_vm_write_path(
                r"D:\quant\quant_platform", allow_root=False
            )

    def test_checked_in_write_set_is_closed_and_matches_runtime(self) -> None:
        value = json.loads(
            (ROOT / "config" / "production_vm_write_set.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(r"D:\quant\quant_platform", value["root"])
        self.assertEqual(sorted(PRODUCTION_WRITE_AREAS), value["areas"])
        self.assertEqual(
            set(value["areas"]), set(declared_production_vm_write_set())
        )
        self.assertEqual(
            [
                r"C:\quant_platform_data\comments.sqlite3",
                r"C:\quant_platform_data\research_workspace.sqlite3",
            ],
            value["legacy_read_only_sources"],
        )
        self.assertEqual(
            {
                "type": "windows_scm_service_registration",
                "service_name": "QuantResearchHub",
                "image_path": "exact_hash_verified_D_root_candidate_only",
                "python_class": (
                    "quant_hub.ops.windows_service."
                    "QuantResearchHubWindowsService"
                ),
                "project_content_secret_temp_log_cache_on_C_forbidden": True,
            },
            value["contract"]["os_managed_non_file_state"],
        )

    def test_execution_delta_audit_maps_actual_writes_to_production_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            before = capture_vm_write_snapshot(root)
            for relative, body in (
                ("incoming/r1.partial/release_manifest.json", b"release"),
                ("state/locks/deployment.lock", b"owner"),
                ("logs/service.log", b"started"),
                ("tmp/deployment-cli/result.json", b"{}"),
                ("checkout/app.py", b"pass\n"),
                ("tooling/controller.py", b"pass\n"),
            ):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(body)
            after = capture_vm_write_snapshot(root)
            report = build_vm_write_audit(before, after, operation="candidate-r1")
            self.assertEqual("pass", report["verdict"])
            observed = report["observed_writes"]
            self.assertTrue(observed)
            self.assertTrue(
                all(
                    row["path"].casefold().startswith(
                        "d:\\quant\\quant_platform\\"
                    )
                    for row in observed
                )
            )
            self.assertIn(
                "incoming/r1.partial/release_manifest.json",
                {row["relative_path"] for row in observed},
            )

    def test_execution_delta_audit_rejects_unreviewed_actual_write_area(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            before = capture_vm_write_snapshot(root)
            target = root / "reference" / "forbidden.md"
            target.parent.mkdir()
            target.write_text("must fail", encoding="utf-8")
            after = capture_vm_write_snapshot(root)
            with self.assertRaises(VMBoundaryError):
                build_vm_write_audit(before, after, operation="forbidden-write")

    def test_post_execution_audit_is_append_only_and_accounts_for_itself(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            before = capture_vm_write_snapshot(root)
            target = root / "state" / "comments.sqlite3"
            target.parent.mkdir()
            target.write_bytes(b"sqlite-fixture")
            audit_path = finalize_vm_write_audit(
                root,
                before,
                operation="state-fixture",
                outcome="succeeded",
            )
            value = json.loads(audit_path.read_text(encoding="utf-8"))
            self.assertEqual("pass", value["verdict"])
            self.assertEqual("succeeded", value["outcome"])
            self.assertTrue(
                value["audit_record_path"].startswith(
                    "D:\\quant\\quant_platform\\audit\\events\\"
                )
            )
            self.assertIn(
                "state/comments.sqlite3",
                {row["relative_path"] for row in value["observed_writes"]},
            )
            with self.assertRaises(FileExistsError):
                # Evidence is append-only; a caller cannot overwrite it.
                from quant_hub.runtime_seal import write_atomic_new_json

                write_atomic_new_json(audit_path, value)

    def test_shipped_recovery_cli_target_is_exact_d_root_only(self) -> None:
        validate_production_restore_target(Path(r"D:\quant\quant_platform"))
        for target in (
            "D:\\",
            r"D:\quant",
            r"D:\quant\quant_platform_sibling",
            r"C:\quant_platform",
            r"\\server\share\quant_platform",
        ):
            with self.subTest(target=target), self.assertRaises(RestoreError):
                validate_production_restore_target(Path(target))

    def test_shipped_recovery_detects_reparse_in_parent_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "D" / "quant" / "quant_platform"
            target.mkdir(parents=True)
            simulated_parent = target.parent
            with patch(
                "tools.release.restore_cold_bundle.is_reparse",
                side_effect=lambda path: path == simulated_parent,
            ):
                self.assertTrue(path_has_reparse(target))


if __name__ == "__main__":
    unittest.main()
