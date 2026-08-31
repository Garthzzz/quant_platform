from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from quant_hub.ops.local_exact_runtime_tooling_scanner import (
    TestOnlyExactRuntimeToolingAdapter,
)


SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "update_vm_tooling.py"
SPEC = importlib.util.spec_from_file_location("update_vm_tooling", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class VMToolingUpdateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.release_id = "release-r1"
        self.candidate = self.root / "incoming" / f"{self.release_id}.partial"
        self.source = (
            self.candidate / "runtime_contract" / "code" / "src" / "quant_hub"
        )
        self.migration_source = (
            self.candidate
            / "runtime_contract"
            / "migrations"
            / "research_workspace"
        )
        self.code_migration_source = (
            self.candidate
            / "runtime_contract"
            / "code"
            / "migrations"
            / "research_workspace"
        )
        self.package = (
            self.root
            / "tooling"
            / "python"
            / "Lib"
            / "site-packages"
            / "quant_hub"
        )
        self.python = self.root / "tooling" / "python" / "python.exe"
        self.service_host = (
            self.root
            / "tooling"
            / "python"
            / "Lib"
            / "site-packages"
            / "win32"
            / "pythonservice.exe"
        )
        self.python.parent.mkdir(parents=True)
        self.python.write_bytes(b"python")
        self.service_host.parent.mkdir(parents=True)
        self.service_host.write_bytes(b"pythonservice")
        package_paths = {
            relative for _logical, relative in module._KEY_FILES
        } | {"ops/service_entry.py", "ops/vm_deploy_cli.py", "web/access_gate.py"}
        for relative in sorted(package_paths):
            old = self.package.joinpath(*relative.split("/"))
            new = self.source.joinpath(*relative.split("/"))
            old.parent.mkdir(parents=True, exist_ok=True)
            new.parent.mkdir(parents=True, exist_ok=True)
            old.write_bytes(f"old:{relative}\n".encode("utf-8"))
            new.write_bytes(f"new:{relative}\n".encode("utf-8"))
        self.migration_source.mkdir(parents=True)
        self.code_migration_source.mkdir(parents=True)
        for name in module._WORKSPACE_MIGRATION_FILES:
            raw = f"migration:{name}\n".encode("utf-8")
            (self.migration_source / name).write_bytes(raw)
            (self.code_migration_source / name).write_bytes(raw)
        updater = self.candidate / "runtime_contract" / "code" / "tools" / SCRIPT.name
        updater.parent.mkdir(parents=True)
        updater.write_bytes(SCRIPT.read_bytes())
        inventory_files = []
        for path in sorted(self.source.rglob("*")):
            if path.is_file():
                relative = path.relative_to(self.candidate).as_posix()
                inventory_files.append(
                    {
                        "path": relative,
                        "bytes": path.stat().st_size,
                        "sha256": _hash(path),
                    }
                )
        for path in sorted(self.migration_source.rglob("*")):
            if path.is_file():
                relative = path.relative_to(self.candidate).as_posix()
                inventory_files.append(
                    {
                        "path": relative,
                        "bytes": path.stat().st_size,
                        "sha256": _hash(path),
                    }
                )
        for path in sorted(self.code_migration_source.rglob("*")):
            if path.is_file():
                relative = path.relative_to(self.candidate).as_posix()
                inventory_files.append(
                    {
                        "path": relative,
                        "bytes": path.stat().st_size,
                        "sha256": _hash(path),
                    }
                )
        inventory_files.append(
            {
                "path": updater.relative_to(self.candidate).as_posix(),
                "bytes": updater.stat().st_size,
                "sha256": _hash(updater),
            }
        )
        manifest = {
            "schema_version": "qrh-release-manifest/v2",
            "release_id": self.release_id,
            "inventory": {"files": inventory_files},
        }
        self.manifest_raw = module._canonical(manifest)
        (self.candidate / "release_manifest.json").write_bytes(self.manifest_raw)
        self.manifest_hash = hashlib.sha256(self.manifest_raw).hexdigest()
        control = self.root / "control"
        control.mkdir()
        runtime = control / "deployment_runtime.json"
        runtime.write_bytes(b"runtime")
        old_records = module._regular_files(self.package)
        old_inventory_hash = module._package_inventory_sha256(old_records)
        install = {
            "schema_version": module.INSTALL_SCHEMA,
            "service_name": module.SERVICE_NAME,
            "python_class": "quant_hub.ops.windows_service.QuantResearchHubWindowsService",
            "service_executable": str(self.service_host),
            "service_executable_sha256": _hash(self.service_host),
            "service_python": str(self.python),
            "service_python_sha256": _hash(self.python),
            "service_host_module": str(self.package / "ops/windows_service.py"),
            "service_host_module_sha256": _hash(self.package / "ops/windows_service.py"),
            "service_entry_module": str(self.package / "ops/service_entry.py"),
            "service_entry_module_sha256": _hash(self.package / "ops/service_entry.py"),
            "deployment_cli_module": str(self.package / "ops/vm_deploy_cli.py"),
            "deployment_cli_module_sha256": _hash(self.package / "ops/vm_deploy_cli.py"),
            "access_gate_module": str(self.package / "web/access_gate.py"),
            "access_gate_module_sha256": _hash(self.package / "web/access_gate.py"),
            "deployment_runtime": str(runtime),
            "deployment_runtime_sha256": _hash(runtime),
            "quant_hub_package_root": str(self.package),
            "quant_hub_package_inventory_sha256": old_inventory_hash,
            "start_type": "automatic",
        }
        self.install_path = control / "service_install_candidate.json"
        self.install_path.write_bytes(module._canonical(install))
        self.tooling_path = control / "exact_runtime_tooling.json"
        self.tooling_path.write_bytes(
            module._canonical(
                module._build_tooling_claim(
                    self.root,
                    old_records,
                    package_inventory_sha256=old_inventory_hash,
                )
            )
        )
        self.old_package = {
            name: path.read_bytes()
            for name, path in (
                (item.relative_to(self.package).as_posix(), item)
                for item in self.package.rglob("*")
                if item.is_file()
            )
        }
        self.old_install = self.install_path.read_bytes()
        self.old_tooling = self.tooling_path.read_bytes()

    def expected_installed(self) -> dict[str, tuple[int, str]]:
        expected = module._regular_files(self.source)
        expected.update(
            {
                module._WORKSPACE_MIGRATION_PACKAGE_PREFIX + name: record
                for name, record in module._regular_files(
                    self.migration_source
                ).items()
            }
        )
        return expected

    def rewrite_manifest(self, inventory_files: list[dict[str, object]]) -> None:
        manifest = {
            "schema_version": "qrh-release-manifest/v2",
            "release_id": self.release_id,
            "inventory": {"files": inventory_files},
        }
        self.manifest_raw = module._canonical(manifest)
        (self.candidate / "release_manifest.json").write_bytes(self.manifest_raw)
        self.manifest_hash = hashlib.sha256(self.manifest_raw).hexdigest()

    def update(self, **changes):
        arguments = {
            "vm_root": self.root,
            "release_id": self.release_id,
            "release_manifest_sha256": self.manifest_hash,
            "attempt_id": "tooling-r1",
            "allow_test_root": True,
            "service_stopped_probe": lambda: True,
        }
        arguments.update(changes)
        return module.update_vm_tooling(**arguments)

    def test_script_is_stdlib_only_and_updates_all_bound_claims(self) -> None:
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            str(node.module).split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module != "__future__"
        }
        self.assertNotIn("quant_hub", imports)
        before = module._snapshot(self.root)
        result = self.update()
        expected = self.expected_installed()
        self.assertEqual(expected, module._regular_files(self.package))
        install = json.loads(self.install_path.read_text(encoding="utf-8"))
        self.assertEqual(
            module._package_inventory_sha256(expected),
            install["quant_hub_package_inventory_sha256"],
        )
        tooling = json.loads(self.tooling_path.read_text(encoding="utf-8"))
        scanner_inventory = [
            {"relative_path": name, "bytes": size, "sha256": digest}
            for name, (size, digest) in sorted(expected.items())
        ]
        self.assertEqual(
            hashlib.sha256(module._canonical(scanner_inventory)).hexdigest(),
            tooling["package"]["inventory_sha256"],
        )
        self.assertEqual(
            module._build_tooling_claim(self.root, expected), tooling
        )
        verified = TestOnlyExactRuntimeToolingAdapter.for_test_only(
            self.root
        ).verify_persisted()
        self.assertEqual(tooling, verified.as_dict())
        self.assertEqual(tooling["tooling_sha256"], result["exact_runtime_tooling_sha256"])
        self.assertFalse((self.root / "control" / "tooling_update_pending.json").exists())
        audit_path = module._finalize_audit(
            self.root, before, outcome="succeeded"
        )
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        self.assertEqual("qrh-production-vm-write-audit/v1", audit["schema_version"])
        self.assertEqual("update-vm-tooling", audit["operation"])
        self.assertTrue(
            any(
                item["relative_path"]
                == "control/exact_runtime_tooling.json"
                for item in audit["observed_writes"]
            )
        )

    def test_running_service_rejects_before_any_write(self) -> None:
        with self.assertRaisesRegex(module.ToolingUpdateError, "STOPPED"):
            self.update(service_stopped_probe=lambda: False)
        self.assertEqual(self.old_install, self.install_path.read_bytes())
        self.assertEqual(self.old_tooling, self.tooling_path.read_bytes())
        self.assertEqual(
            self.old_package,
            {
                item.relative_to(self.package).as_posix(): item.read_bytes()
                for item in self.package.rglob("*")
                if item.is_file()
            },
        )

    def test_missing_workspace_migration_record_fails_closed(self) -> None:
        manifest = json.loads(self.manifest_raw.decode("utf-8"))
        omitted = (
            module._WORKSPACE_MIGRATION_SOURCE_PREFIX
            + module._WORKSPACE_MIGRATION_FILES[0]
        )
        files = [
            item
            for item in manifest["inventory"]["files"]
            if item["path"] != omitted
        ]
        self.rewrite_manifest(files)
        with self.assertRaisesRegex(
            module.ToolingUpdateError, "workspace migration inventory"
        ):
            self.update()

    def test_extra_workspace_migration_fails_closed(self) -> None:
        extra = self.migration_source / "9999_extra.sql"
        extra.write_bytes(b"extra\n")
        manifest = json.loads(self.manifest_raw.decode("utf-8"))
        files = list(manifest["inventory"]["files"])
        files.append(
            {
                "path": extra.relative_to(self.candidate).as_posix(),
                "bytes": extra.stat().st_size,
                "sha256": _hash(extra),
            }
        )
        self.rewrite_manifest(files)
        with self.assertRaisesRegex(
            module.ToolingUpdateError, "workspace migration inventory"
        ):
            self.update()

    def test_changed_workspace_migration_bytes_fail_closed(self) -> None:
        target = self.migration_source / module._WORKSPACE_MIGRATION_FILES[0]
        target.write_bytes(b"changed-after-seal\n")
        with self.assertRaisesRegex(
            module.ToolingUpdateError, "workspace migration bytes"
        ):
            self.update()

    def test_changed_code_migration_mirror_fails_closed(self) -> None:
        target = self.code_migration_source / module._WORKSPACE_MIGRATION_FILES[0]
        target.write_bytes(b"changed-code-mirror-after-seal\n")
        with self.assertRaisesRegex(
            module.ToolingUpdateError, "code migration mirror bytes"
        ):
            self.update()

    def test_absent_optional_code_migration_mirror_is_accepted(self) -> None:
        manifest = json.loads(self.manifest_raw.decode("utf-8"))
        files = [
            item
            for item in manifest["inventory"]["files"]
            if not item["path"].startswith(
                module._WORKSPACE_CODE_MIGRATION_SOURCE_PREFIX
            )
        ]
        self.rewrite_manifest(files)
        for path in self.code_migration_source.iterdir():
            path.unlink()
        self.code_migration_source.rmdir()
        self.code_migration_source.parent.rmdir()
        self.update()
        self.assertEqual(self.expected_installed(), module._regular_files(self.package))

    def test_legacy_workspace_migration_layout_fails_closed(self) -> None:
        manifest = json.loads(self.manifest_raw.decode("utf-8"))
        files = list(manifest["inventory"]["files"])
        files.append(
            {
                "path": (
                    module._WORKSPACE_LEGACY_MIGRATION_PREFIX
                    + module._WORKSPACE_MIGRATION_FILES[0]
                ),
                "bytes": 1,
                "sha256": hashlib.sha256(b"x").hexdigest(),
            }
        )
        self.rewrite_manifest(files)
        with self.assertRaisesRegex(
            module.ToolingUpdateError, "workspace migration layout"
        ):
            self.update()

    def test_failure_after_package_swap_restores_package_and_both_claims(self) -> None:
        with self.assertRaisesRegex(module.ToolingUpdateError, "injected failure"):
            self.update(fail_after_package_swap=True)
        self.assertEqual(self.old_install, self.install_path.read_bytes())
        self.assertEqual(self.old_tooling, self.tooling_path.read_bytes())
        self.assertEqual(
            self.old_package,
            {
                item.relative_to(self.package).as_posix(): item.read_bytes()
                for item in self.package.rglob("*")
                if item.is_file()
            },
        )
        self.assertFalse((self.root / "control" / "tooling_update_pending.json").exists())
        self.assertFalse(any(self.package.parent.glob("quant_hub.update-*")))

    def test_failure_between_package_renames_restores_live_package(self) -> None:
        with self.assertRaisesRegex(module.ToolingUpdateError, "moved to prior"):
            self.update(fail_after_package_to_prior=True)
        self.assertEqual(
            self.old_package,
            {
                item.relative_to(self.package).as_posix(): item.read_bytes()
                for item in self.package.rglob("*")
                if item.is_file()
            },
        )
        self.assertEqual(self.old_install, self.install_path.read_bytes())
        self.assertEqual(self.old_tooling, self.tooling_path.read_bytes())
        self.assertFalse(any(self.package.parent.glob("quant_hub.update-*")))
        self.assertFalse((self.root / "control" / "tooling_update_pending.json").exists())

    def test_atomic_replace_failure_removes_partial_file(self) -> None:
        target = self.root / "control" / "atomic-test.json"
        with (
            patch.object(module.os, "replace", side_effect=OSError("replace failed")),
            self.assertRaisesRegex(OSError, "replace failed"),
        ):
            module._write_atomic(target, {"status": "test"}, suffix="fault")
        self.assertFalse(target.exists())
        self.assertFalse((target.parent / ".atomic-test.json.fault.partial").exists())

    def test_missing_old_claim_bootstraps_after_strict_live_verification(self) -> None:
        self.tooling_path.unlink()
        result = self.update()
        expected = self.expected_installed()
        tooling = json.loads(self.tooling_path.read_text(encoding="utf-8"))
        self.assertEqual(module._build_tooling_claim(self.root, expected), tooling)
        self.assertEqual(tooling["tooling_sha256"], result["exact_runtime_tooling_sha256"])
        self.assertFalse(any((self.root / "control").glob(".exact_runtime_tooling.*")))

    def test_missing_old_claim_rejects_tampered_binary_binding_without_write(self) -> None:
        self.tooling_path.unlink()
        install = json.loads(self.install_path.read_text(encoding="utf-8"))
        install["service_python_sha256"] = "0" * 64
        self.install_path.write_bytes(module._canonical(install))
        old_install = self.install_path.read_bytes()
        with self.assertRaisesRegex(module.ToolingUpdateError, "service_python"):
            self.update()
        self.assertFalse(self.tooling_path.exists())
        self.assertEqual(old_install, self.install_path.read_bytes())
        self.assertEqual(
            self.old_package,
            {
                item.relative_to(self.package).as_posix(): item.read_bytes()
                for item in self.package.rglob("*")
                if item.is_file()
            },
        )

    def test_bootstrap_failure_after_claim_creation_removes_new_claim(self) -> None:
        self.tooling_path.unlink()
        with self.assertRaisesRegex(
            module.ToolingUpdateError, "injected failure after claims swap"
        ):
            self.update(fail_after_claims_swap=True)
        self.assertFalse(self.tooling_path.exists())
        self.assertEqual(self.old_install, self.install_path.read_bytes())
        self.assertEqual(
            self.old_package,
            {
                item.relative_to(self.package).as_posix(): item.read_bytes()
                for item in self.package.rglob("*")
                if item.is_file()
            },
        )
        self.assertFalse((self.root / "control" / "tooling_update_pending.json").exists())
        self.assertFalse(any(self.package.parent.glob("quant_hub.update-*")))
        self.assertFalse(any((self.root / "control").glob(".exact_runtime_tooling.*")))


if __name__ == "__main__":
    unittest.main()
