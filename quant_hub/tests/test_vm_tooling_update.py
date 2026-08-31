from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
from pathlib import Path, PureWindowsPath
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
        self.python_runtime = self.root / "tooling" / "python" / "python313.dll"
        self.python_runtime.write_bytes(b"python313-runtime")
        self.legacy_pywin32_runtime = (
            self.root / "tooling" / "python" / "Lib" / "site-packages"
            / "pywin32_system32" / "pywintypes313.dll"
        )
        self.legacy_pywin32_runtime.parent.mkdir(parents=True)
        self.legacy_pywin32_runtime.write_bytes(b"pywintypes313-runtime")
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
            "schema_version": module.LEGACY_INSTALL_SCHEMA,
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
                module._build_legacy_tooling_claim(
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
        self.service_image_path = str(self.service_host)

    def service_rebind(self, expected: str, replacement: str) -> None:
        self.assertEqual(PureWindowsPath(expected), PureWindowsPath(self.service_image_path))
        self.service_image_path = replacement

    def migrate_fixture_to_v2(self) -> None:
        root_host = self.root / "tooling" / "python" / "pythonservice.exe"
        root_pywin32 = self.root / "tooling" / "python" / "pywintypes313.dll"
        root_host.write_bytes(self.service_host.read_bytes())
        root_pywin32.write_bytes(self.legacy_pywin32_runtime.read_bytes())
        install = json.loads(self.install_path.read_text(encoding="utf-8"))
        install["schema_version"] = module.INSTALL_SCHEMA
        for field, path in (
            ("service_executable", root_host),
            ("service_python_runtime", self.python_runtime),
            ("service_pywin32_runtime", root_pywin32),
        ):
            install[field] = str(path)
            install[f"{field}_sha256"] = _hash(path)
        self.install_path.write_bytes(module._canonical(install))
        old_records = module._regular_files(self.package)
        self.tooling_path.write_bytes(
            module._canonical(module._build_tooling_claim(self.root, old_records))
        )
        self.service_image_path = str(root_host)
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
            "service_image_path_probe": lambda: self.service_image_path,
            "service_binding_updater": self.service_rebind,
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
        self.assertEqual("qrh-tooling-update-result/v2", result["schema_version"])
        expected = self.expected_installed()
        self.assertEqual(expected, module._regular_files(self.package))
        install = json.loads(self.install_path.read_text(encoding="utf-8"))
        self.assertEqual(module.INSTALL_SCHEMA, install["schema_version"])
        self.assertEqual(
            str(self.root / "tooling" / "python" / "pythonservice.exe"),
            install["service_executable"],
        )
        self.assertEqual(
            str(self.root / "tooling" / "python" / "pythonservice.exe"),
            self.service_image_path,
        )
        self.assertEqual(
            self.service_host.read_bytes(),
            (self.root / "tooling" / "python" / "pythonservice.exe").read_bytes(),
        )
        self.assertEqual(
            self.legacy_pywin32_runtime.read_bytes(),
            (self.root / "tooling" / "python" / "pywintypes313.dll").read_bytes(),
        )
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
        self.assertEqual("derived_from_live_v1", result["root_bundle_provenance"])
        self.assertEqual("not_required", result["restart_recovery"])
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

    def test_v2_to_v2_update_preserves_bundle_without_scm_rebind(self) -> None:
        self.migrate_fixture_to_v2()
        bundle = {
            name: (self.root / "tooling" / "python" / name).read_bytes()
            for name in ("pythonservice.exe", "python313.dll", "pywintypes313.dll")
        }

        def forbidden_rebind(_expected: str, _replacement: str) -> None:
            self.fail("v2-to-v2 update must not rebind SCM")

        self.update(service_binding_updater=forbidden_rebind)
        self.assertEqual(
            bundle,
            {
                name: (self.root / "tooling" / "python" / name).read_bytes()
                for name in bundle
            },
        )
        self.assertEqual(
            module.INSTALL_SCHEMA,
            json.loads(self.install_path.read_text(encoding="utf-8"))["schema_version"],
        )

    def test_v2_failure_rollback_preserves_existing_bundle_and_binding(self) -> None:
        self.migrate_fixture_to_v2()
        bundle = {
            name: (self.root / "tooling" / "python" / name).read_bytes()
            for name in ("pythonservice.exe", "python313.dll", "pywintypes313.dll")
        }
        def forbidden_rebind(_expected: str, _replacement: str) -> None:
            self.fail("v2 rollback must not rebind unchanged SCM ImagePath")

        with self.assertRaisesRegex(module.ToolingUpdateError, "claims swap"):
            self.update(
                fail_after_claims_swap=True,
                service_binding_updater=forbidden_rebind,
            )
        self.assertEqual(self.old_install, self.install_path.read_bytes())
        self.assertEqual(self.old_tooling, self.tooling_path.read_bytes())
        self.assertEqual(
            bundle,
            {
                name: (self.root / "tooling" / "python" / name).read_bytes()
                for name in bundle
            },
        )
        self.assertEqual(
            str(self.root / "tooling" / "python" / "pythonservice.exe"),
            self.service_image_path,
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

    def test_transaction_lock_is_exclusive_for_full_update_owner(self) -> None:
        lock_path = self.root / "control" / "tooling_update.lock"
        with module._ToolingUpdateLock(lock_path):
            with self.assertRaisesRegex(module.ToolingUpdateError, "exclusive lock"):
                with module._ToolingUpdateLock(lock_path):
                    self.fail("contender unexpectedly acquired tooling update lock")

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
        self.assertEqual(str(self.service_host), self.service_image_path)
        self.assertFalse((self.root / "tooling" / "python" / "pythonservice.exe").exists())
        self.assertFalse((self.root / "tooling" / "python" / "pywintypes313.dll").exists())

    def test_failure_after_bundle_publish_restores_v1_files_claims_and_scm(self) -> None:
        with self.assertRaisesRegex(module.ToolingUpdateError, "bundle publish"):
            self.update(fail_after_host_bundle_publish=True)
        self.assertEqual(self.old_install, self.install_path.read_bytes())
        self.assertEqual(self.old_tooling, self.tooling_path.read_bytes())
        self.assertEqual(str(self.service_host), self.service_image_path)
        self.assertFalse((self.root / "tooling" / "python" / "pythonservice.exe").exists())
        self.assertFalse((self.root / "tooling" / "python" / "pywintypes313.dll").exists())

    def test_second_root_bundle_publish_failure_rolls_back_exact_v1(self) -> None:
        with self.assertRaisesRegex(module.ToolingUpdateError, "second root bundle"):
            self.update(fail_before_second_root_bundle_publish=True)
        self.assertEqual(self.old_install, self.install_path.read_bytes())
        self.assertEqual(self.old_tooling, self.tooling_path.read_bytes())
        self.assertEqual(str(self.service_host), self.service_image_path)
        self.assertFalse((self.root / "tooling" / "python" / "pythonservice.exe").exists())
        self.assertFalse((self.root / "tooling" / "python" / "pywintypes313.dll").exists())
        self.assertFalse((self.root / "control" / "tooling_update_pending.json").exists())

    def test_reverse_rebind_failure_preserves_recoverable_journal_and_priors(self) -> None:
        old_image = str(self.service_host)
        new_image = str(self.root / "tooling" / "python" / "pythonservice.exe")

        def fail_reverse(expected: str, replacement: str) -> None:
            if PureWindowsPath(expected) == PureWindowsPath(old_image):
                self.service_rebind(expected, replacement)
                return
            raise module.ToolingUpdateError("injected reverse rebind failure")

        with self.assertRaisesRegex(module.ToolingUpdateError, "journal remains"):
            self.update(
                service_binding_updater=fail_reverse,
                fail_after_service_rebind=True,
            )
        journal_path = self.root / "control" / "tooling_update_pending.json"
        self.assertTrue(journal_path.is_file())
        self.assertEqual(new_image, self.service_image_path)
        self.assertTrue(
            (self.root / "control" / ".service_install_candidate.tooling-r1.prior").is_file()
        )
        self.assertTrue(any(self.package.parent.glob("quant_hub.update-*.prior")))
        recovered = module._recover_pending_transaction(
            self.root,
            service_stopped_probe=lambda: True,
            service_image_path_probe=lambda: self.service_image_path,
            service_binding_updater=self.service_rebind,
        )
        self.assertEqual("rolled_back_exact_old", recovered)
        self.assertFalse(journal_path.exists())
        self.assertEqual(old_image, self.service_image_path)
        self.assertEqual(self.old_install, self.install_path.read_bytes())
        self.assertEqual(self.old_tooling, self.tooling_path.read_bytes())

    def test_recovery_never_rebinds_scm_to_drifted_legacy_source_bundle(self) -> None:
        old_image = str(self.service_host)
        new_image = str(self.root / "tooling" / "python" / "pythonservice.exe")

        def fail_reverse(expected: str, replacement: str) -> None:
            if PureWindowsPath(expected) == PureWindowsPath(old_image):
                self.service_rebind(expected, replacement)
                return
            raise module.ToolingUpdateError("injected reverse rebind failure")

        with self.assertRaisesRegex(module.ToolingUpdateError, "journal remains"):
            self.update(
                service_binding_updater=fail_reverse,
                fail_after_service_rebind=True,
            )
        self.legacy_pywin32_runtime.write_bytes(b"drifted-after-journal")
        with self.assertRaisesRegex(module.ToolingUpdateError, "source bundle differs"):
            module._recover_pending_transaction(
                self.root,
                service_stopped_probe=lambda: True,
                service_image_path_probe=lambda: self.service_image_path,
                service_binding_updater=self.service_rebind,
            )
        self.assertEqual(new_image, self.service_image_path)
        self.assertTrue(
            (self.root / "control" / "tooling_update_pending.json").is_file()
        )

    def test_process_restart_recovers_closed_journal_then_retries_update(self) -> None:
        with self.assertRaises(module._SimulatedProcessCrash):
            self.update(simulate_process_crash_after_claims_swap=True)
        journal_path = self.root / "control" / "tooling_update_pending.json"
        journal = module._read_journal(self.root, journal_path)
        self.assertEqual(module._JOURNAL_FIELDS, set(journal))
        self.assertEqual("claims_swapped", journal["phase"])
        self.assertEqual("derived_from_live_v1", journal["root_bundle_provenance"])
        self.assertEqual(str(self.service_host), journal["old_image_path"])
        self.assertEqual(
            str(self.root / "tooling" / "python" / "pythonservice.exe"),
            journal["new_image_path"],
        )
        self.assertEqual(
            hashlib.sha256(self.old_install).hexdigest(),
            journal["old_install_sha256"],
        )
        self.assertEqual(
            hashlib.sha256(self.old_tooling).hexdigest(),
            journal["old_tooling_sha256"],
        )
        self.assertEqual(
            ["pythonservice.exe", "python313.dll", "pywintypes313.dll"],
            [item["name"] for item in journal["root_bundle_members"]],
        )
        result = self.update()
        self.assertEqual("rolled_back_exact_old", result["restart_recovery"])
        self.assertFalse(journal_path.exists())
        self.assertEqual(
            str(self.root / "tooling" / "python" / "pythonservice.exe"),
            self.service_image_path,
        )

    def test_restart_after_verified_phase_completes_exact_new_only(self) -> None:
        original = module._recover_pending_transaction

        def crash_before_verified_cleanup(root, **arguments):
            journal_path = root / "control" / "tooling_update_pending.json"
            if journal_path.exists():
                journal = module._read_journal(root, journal_path)
                if journal["phase"] == "verified":
                    raise module._SimulatedProcessCrash()
            return original(root, **arguments)

        with (
            patch.object(
                module,
                "_recover_pending_transaction",
                side_effect=crash_before_verified_cleanup,
            ),
            self.assertRaises(module._SimulatedProcessCrash),
        ):
            self.update()
        journal_path = self.root / "control" / "tooling_update_pending.json"
        self.assertEqual(
            "verified", module._read_journal(self.root, journal_path)["phase"]
        )
        recovered = self.update()
        self.assertEqual("completed_exact_new", recovered["restart_recovery"])
        self.assertEqual("derived_from_live_v1", recovered["root_bundle_provenance"])
        self.assertFalse(journal_path.exists())
        self.assertEqual(
            module.INSTALL_SCHEMA,
            json.loads(self.install_path.read_text(encoding="utf-8"))["schema_version"],
        )

    def test_restart_rejects_non_closed_or_resigned_pending_journal(self) -> None:
        with self.assertRaises(module._SimulatedProcessCrash):
            self.update(simulate_process_crash_after_claims_swap=True)
        journal_path = self.root / "control" / "tooling_update_pending.json"
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        journal["unreviewed"] = True
        journal_path.write_bytes(module._canonical(journal))
        with self.assertRaisesRegex(module.ToolingUpdateError, "schema differs"):
            module._recover_pending_transaction(
                self.root,
                service_stopped_probe=lambda: True,
                service_image_path_probe=lambda: self.service_image_path,
                service_binding_updater=self.service_rebind,
            )
        self.assertTrue(journal_path.is_file())

    def test_service_becoming_running_preserves_journal_for_stopped_recovery(self) -> None:
        states = iter((True, False, False))

        def stopped() -> bool:
            return next(states, False)

        with self.assertRaisesRegex(module.ToolingUpdateError, "journal remains"):
            self.update(service_stopped_probe=stopped)
        journal_path = self.root / "control" / "tooling_update_pending.json"
        self.assertTrue(journal_path.is_file())
        self.assertEqual(self.old_package, {
            item.relative_to(self.package).as_posix(): item.read_bytes()
            for item in self.package.rglob("*") if item.is_file()
        })
        recovered = module._recover_pending_transaction(
            self.root,
            service_stopped_probe=lambda: True,
            service_image_path_probe=lambda: self.service_image_path,
            service_binding_updater=self.service_rebind,
        )
        self.assertEqual("rolled_back_exact_old", recovered)
        self.assertFalse(journal_path.exists())

    def test_service_stopped_is_rechecked_at_every_mutation_boundary(self) -> None:
        calls = 0

        def stopped() -> bool:
            nonlocal calls
            calls += 1
            return True

        self.update(service_stopped_probe=stopped)
        self.assertGreaterEqual(calls, 5)

    def test_failure_after_scm_rebind_restores_v1_files_claims_and_binding(self) -> None:
        calls = 0

        def rebind_then_fail(expected: str, replacement: str) -> None:
            nonlocal calls
            self.service_rebind(expected, replacement)
            calls += 1
            if calls == 1:
                raise module.ToolingUpdateError("injected rebind readback failure")

        with self.assertRaisesRegex(module.ToolingUpdateError, "rebind readback"):
            self.update(service_binding_updater=rebind_then_fail)
        self.assertEqual(self.old_install, self.install_path.read_bytes())
        self.assertEqual(self.old_tooling, self.tooling_path.read_bytes())
        self.assertEqual(str(self.service_host), self.service_image_path)
        self.assertFalse((self.root / "tooling" / "python" / "pythonservice.exe").exists())
        self.assertFalse((self.root / "tooling" / "python" / "pywintypes313.dll").exists())

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
