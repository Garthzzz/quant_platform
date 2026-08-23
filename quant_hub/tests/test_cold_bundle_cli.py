from __future__ import annotations

from datetime import UTC, datetime
import base64
import hashlib
import json
from pathlib import Path, PureWindowsPath
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from quant_hub.collaboration.checkpoint import create_sqlite_checkpoint
from quant_hub.ops.cold_bundle_cli import ColdBundleBuilder, ColdBundleCLIError
from quant_hub.ops.cold_restore_cli import ColdRestoreCLIError, OpenSSHColdRestore
from quant_hub.ops.publish_adapters import CommandResult, GitHubCIConfig, VMConfig
from quant_hub.ops.publish_recovery_cli import capture_legacy
from quant_hub.ops.publish_runtime import (
    RecoveryRuntimeConfig,
    RuntimePublishConfig,
)
from quant_hub.ops.release_identity import canonical_manifest_bytes, manifest_sha256
from quant_hub.ops.windows_service import quant_hub_package_inventory_sha256
from quant_hub.ops.recovery_bundle import RecoveryVerification


def _release_manifest() -> dict[str, object]:
    return {
        "schema_version": "qrh-release-manifest/v1",
        "release_id": "release-v39-cold-test",
        "built_at": "2026-08-21T08:00:00+08:00",
        "application": {
            "commit_sha": "a" * 40,
            "tracked_tree_sha256": "1" * 64,
            "build_tool_version": "test/v1",
        },
        "content": {
            "snapshot_id": "snapshot-v39-cold-test",
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


class ColdBundleBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        for target in (
            "quant_hub.ops.cold_bundle_cli.require_failure_domain_authority",
            "quant_hub.ops.cold_restore_cli.require_failure_domain_authority",
            "quant_hub.ops.publish_recovery_cli.require_failure_domain_authority",
            "quant_hub.ops.publish_runtime.require_failure_domain_authority",
        ):
            authority = patch(target, return_value=None)
            authority.start()
            self.addCleanup(authority.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.release = self.root / "release"
        self.release.mkdir()
        manifest = _release_manifest()
        self.release_hash = manifest_sha256(manifest)
        (self.release / "release_manifest.json").write_bytes(
            canonical_manifest_bytes(manifest)
        )
        (self.release / "app.py").write_bytes(b"print('v39')\n")

        self.legacy = self.root / "legacy-c-fixture"
        self.legacy.mkdir()
        sources = {}
        for name in ("comments", "research_workspace"):
            path = self.legacy / f"{name}.sqlite3"
            connection = sqlite3.connect(path)
            try:
                connection.execute("create table fixture(id integer primary key, value text)")
                connection.execute("insert into fixture(value) values (?)", (name,))
                connection.commit()
            finally:
                connection.close()
            sources[name] = path
        self.legacy_hashes = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sources.values()
        }
        self.remote_checkpoint = create_sqlite_checkpoint(
            sources=sources,
            checkpoint_root=self.root / "simulated-vm-d-checkpoints",
            checkpoint_id="checkpoint-v39-cold",
            state_authority_id="legacy-c-writer",
            captured_under_release_id="release-v39-cold-test",
            captured_under_manifest_sha256=self.release_hash,
            captured_at=datetime(2026, 8, 21, tzinfo=UTC),
        )

        self.operational = self.root / "operational"
        operational_files = {
            "tooling/python/Lib/site-packages/win32/pythonservice.exe": b"svc",
            "tooling/python/python.exe": b"python",
            "tooling/python/Lib/site-packages/quant_hub/ops/windows_service.py": b"host",
            "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py": b"entry",
            "tooling/python/Lib/site-packages/quant_hub/ops/vm_deploy_cli.py": b"deploy-cli",
            "tooling/python/Lib/site-packages/quant_hub/ops/publish_recovery_cli.py": b"recovery-cli",
            "tooling/python/Lib/site-packages/quant_hub/web/access_gate.py": b"gate",
            "control/deployment_runtime.json": canonical_manifest_bytes(
                {"schema_version": "qrh-vm-deploy-runtime/v1", "fixture": True}
            ),
        }
        for relative, payload in operational_files.items():
            path = self.operational.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        bindings = {
            "service_executable": "tooling/python/Lib/site-packages/win32/pythonservice.exe",
            "service_python": "tooling/python/python.exe",
            "service_host_module": "tooling/python/Lib/site-packages/quant_hub/ops/windows_service.py",
            "service_entry_module": "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
            "deployment_cli_module": "tooling/python/Lib/site-packages/quant_hub/ops/vm_deploy_cli.py",
            "publish_recovery_cli_module": "tooling/python/Lib/site-packages/quant_hub/ops/publish_recovery_cli.py",
            "access_gate_module": "tooling/python/Lib/site-packages/quant_hub/web/access_gate.py",
            "deployment_runtime": "control/deployment_runtime.json",
        }
        candidate = {
            "schema_version": "qrh-windows-service-install-candidate/v1",
            "service_name": "QuantResearchHub",
            "python_class": "quant_hub.ops.windows_service.QuantResearchHubWindowsService",
            "start_type": "automatic",
        }
        production = Path(r"D:\quant\quant_platform")
        for field, relative in bindings.items():
            source = self.operational.joinpath(*relative.split("/"))
            candidate[field] = str(production.joinpath(*relative.split("/")))
            candidate[f"{field}_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
        package = self.operational / "tooling/python/Lib/site-packages/quant_hub"
        candidate["quant_hub_package_root"] = str(
            production / "tooling/python/Lib/site-packages/quant_hub"
        )
        candidate["quant_hub_package_inventory_sha256"] = (
            quant_hub_package_inventory_sha256(package)
        )
        (self.operational / "control" / "service_install_candidate.json").write_bytes(
            canonical_manifest_bytes(candidate)
        )

        recovery_root = self.root / "off-host-recovery"
        recovery_root.mkdir()
        restore_tool = self.root / "restore.py"
        restore_tool.write_text("# restore\n", encoding="utf-8")
        runbook = self.root / "RUNBOOK.md"
        runbook.write_text("# recovery\n", encoding="utf-8")
        self.config = RuntimePublishConfig(
            project_root=self.root / "project",
            state_root=self.root / "state",
            candidate_root=self.root / "candidates",
            git_remote="origin",
            runtime_base=self.root / "runtime-base",
            runtime_base_manifest_sha256="9" * 64,
            reference_archive_root=self.root / "reference",
            code_source_relative_path="quant_hub",
            code_overlay_relative_path="runtime/code",
            launcher_relative_path="runtime/start.py",
            required_runtime_paths={},
            resource_overlays=(),
            github=GitHubCIConfig("Garthzzz", "quant_platform", 1, None, 1, 10),
            vm=VMConfig(
                "honghu-vm", "10.5.1.240", PureWindowsPath(r"D:\quant\quant_platform")
            ),
            recovery=RecoveryRuntimeConfig(
                recovery_root=recovery_root,
                attestation_path=self.root / "attestation.json",
                attestation_max_age_seconds=86400,
                state_authority_id="legacy-c-writer",
                restore_tool=restore_tool,
                runbook=runbook,
                operational_root=self.operational,
            ),
        )
        self.calls: list[tuple[str, ...]] = []

    def runner(self, arguments) -> CommandResult:
        call = tuple(arguments)
        self.calls.append(call)
        if call[0] == "ssh":
            script = base64.b64decode(call[-1]).decode("utf-16-le")
            self.assertIn("quant_hub.ops.publish_recovery_cli", script)
            self.assertIn(r"D:\quant\quant_platform\tooling\python\python.exe", script)
            self.assertIn("publish_recovery_cli_module_sha256", script)
            self.assertIn("package_inventory_hash_mismatch", script)
            self.assertIn("& $python @a", script)
            self.assertNotIn("& python", script)
            self.assertIn("SSH_CONNECTION", script)
            self.assertIn("10.5.1.240", script)
            self.assertIn("root_full_path_differs", script)
            self.assertIn("root_parent_reparse", script)
            self.assertIn("recovery_tmp_escaped_exact_root", script)
            self.assertNotIn("New-Item -ItemType Directory -Force -LiteralPath", script)
            self.assertLess(
                script.index("root_parent_reparse"),
                script.index("New-Item -ItemType Directory"),
            )
            self.assertIn(r"D:\quant\quant_platform\tmp\publish-recovery", script)
            if "cleanup-capture" in script:
                self.assertNotIn("capture-legacy", script)
                self.assertNotIn("C:\\", script)
                self.assertNotIn("active_release.json", script)
                return CommandResult(
                    0,
                    json.dumps(
                        {
                            "schema_version": "qrh-publish-checkpoint-cleanup/v1",
                            "checkpoint_id": "checkpoint-v39-cold",
                            "staging_removed": True,
                        }
                    ),
                )
            self.assertIn("capture-legacy", script)
            return CommandResult(
                0,
                json.dumps(
                    {
                        "schema_version": "qrh-publish-checkpoint-result/v1",
                        "checkpoint_id": "checkpoint-v39-cold",
                        "checkpoint_manifest_sha256": self.remote_checkpoint.manifest_sha256,
                        "checkpoint_root": r"D:\quant\quant_platform\tmp\publish-recovery\checkpoints\checkpoint-v39-cold",
                        "source_authority": "legacy_c_read_only",
                    }
                ),
            )
        if call[0] == "scp":
            self.assertIn("HostName=10.5.1.240", call)
            intake = Path(call[-1])
            shutil.copytree(self.remote_checkpoint.root, intake / self.remote_checkpoint.checkpoint_id)
            return CommandResult(0, "")
        return CommandResult(1, "")

    def test_fixed_legacy_capture_builds_verified_off_host_operational_bundle(self) -> None:
        release_bytes = (self.release / "release_manifest.json").read_bytes()
        result = ColdBundleBuilder(
            self.config,
            command_runner=self.runner,
            preflight=lambda: None,
            now=lambda: datetime(2026, 8, 21, 8, tzinfo=UTC),
        ).build(release_root=self.release, bundle_id="v39-cold", state_source="legacy_c")
        self.assertEqual("release-v39-cold-test", result.release_id)
        self.assertEqual(
            "qualification_only_requires_empty_d_attestation",
            result.protection_status,
        )
        self.assertTrue((result.bundle.root / "operational" / "control" / "operational_bootstrap.json").is_file())
        self.assertTrue((result.bundle.root / "operational" / "tooling" / "python" / "python.exe").is_file())
        self.assertEqual(release_bytes, (self.release / "release_manifest.json").read_bytes())
        self.assertEqual(
            self.legacy_hashes,
            {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in self.legacy.glob("*.sqlite3")
            },
        )
        self.assertEqual("ssh", self.calls[0][0])
        self.assertEqual("scp", self.calls[1][0])
        self.assertEqual("ssh", self.calls[2][0])
        cleanup_script = base64.b64decode(self.calls[2][-1]).decode("utf-16-le")
        self.assertIn("cleanup-capture", cleanup_script)
        self.assertNotIn("10.5.1.223", repr(self.calls))
        self.assertNotIn("10.5.1.235", repr(self.calls))

    def test_download_verification_failure_still_cleans_vm_staging(self) -> None:
        def runner(arguments):
            result = self.runner(arguments)
            if arguments[0] == "scp" and result.returncode == 0:
                destination = (
                    Path(arguments[-1])
                    / self.remote_checkpoint.checkpoint_id
                    / "checkpoint_manifest.json"
                )
                destination.write_bytes(b"{}\n")
            return result

        with self.assertRaisesRegex(
            ColdBundleCLIError, "downloaded checkpoint identity differs"
        ):
            ColdBundleBuilder(
                self.config,
                command_runner=runner,
                preflight=lambda: None,
            ).build(
                release_root=self.release,
                bundle_id="v39-cold",
                state_source="legacy_c",
            )
        self.assertEqual(["ssh", "scp", "ssh"], [call[0] for call in self.calls])
        self.assertIn(
            "cleanup-capture",
            base64.b64decode(self.calls[-1][-1]).decode("utf-16-le"),
        )

    def test_capture_command_failure_still_attempts_exact_cleanup(self) -> None:
        calls = []

        def runner(arguments):
            call = tuple(arguments)
            calls.append(call)
            self.assertEqual("ssh", call[0])
            script = base64.b64decode(call[-1]).decode("utf-16-le")
            if "cleanup-capture" in script:
                return CommandResult(
                    0,
                    json.dumps(
                        {
                            "schema_version": "qrh-publish-checkpoint-cleanup/v1",
                            "checkpoint_id": "checkpoint-v39-cold",
                            "staging_removed": False,
                        }
                    ),
                )
            return CommandResult(1, "capture failed after partial staging")

        with self.assertRaisesRegex(
            ColdBundleCLIError, "fixed .240 checkpoint command failed"
        ) as caught:
            ColdBundleBuilder(
                self.config,
                command_runner=runner,
                preflight=lambda: None,
            ).build(
                release_root=self.release,
                bundle_id="v39-cold",
                state_source="legacy_c",
            )
        self.assertEqual(2, len(calls))
        cleanup_script = base64.b64decode(calls[-1][-1]).decode("utf-16-le")
        self.assertIn("cleanup-capture", cleanup_script)
        self.assertNotIn("capture-legacy", cleanup_script)
        self.assertFalse(getattr(caught.exception, "__notes__", ()))

    def test_cleanup_failure_after_verified_download_is_explicit_failure(self) -> None:
        def runner(arguments):
            call = tuple(arguments)
            if call[0] == "ssh":
                script = base64.b64decode(call[-1]).decode("utf-16-le")
                if "cleanup-capture" in script:
                    self.calls.append(call)
                    return CommandResult(1, "cleanup failed")
            return self.runner(arguments)

        with self.assertRaisesRegex(
            ColdBundleCLIError, "VM checkpoint staging cleanup failed"
        ):
            ColdBundleBuilder(
                self.config,
                command_runner=runner,
                preflight=lambda: None,
            ).build(
                release_root=self.release,
                bundle_id="v39-cold",
                state_source="legacy_c",
            )
        self.assertEqual(["ssh", "scp", "ssh"], [call[0] for call in self.calls])
        self.assertFalse(
            (self.config.recovery.recovery_root / "cold-recovery-v39-cold").exists()
        )

    def test_verification_error_precedes_cleanup_error_and_records_both(self) -> None:
        def runner(arguments):
            call = tuple(arguments)
            if call[0] == "ssh":
                script = base64.b64decode(call[-1]).decode("utf-16-le")
                if "cleanup-capture" in script:
                    self.calls.append(call)
                    return CommandResult(1, "cleanup failed")
            result = self.runner(arguments)
            if call[0] == "scp" and result.returncode == 0:
                destination = (
                    Path(call[-1])
                    / self.remote_checkpoint.checkpoint_id
                    / "checkpoint_manifest.json"
                )
                destination.write_bytes(b"{}\n")
            return result

        with self.assertRaisesRegex(
            ColdBundleCLIError, "downloaded checkpoint identity differs"
        ) as caught:
            ColdBundleBuilder(
                self.config,
                command_runner=runner,
                preflight=lambda: None,
            ).build(
                release_root=self.release,
                bundle_id="v39-cold",
                state_source="legacy_c",
            )
        notes = getattr(caught.exception, "__notes__", ())
        self.assertTrue(
            any("VM checkpoint staging cleanup failed" in note for note in notes),
            notes,
        )
        self.assertEqual(["ssh", "scp", "ssh"], [call[0] for call in self.calls])

    def test_initial_legacy_qualification_bundle_does_not_require_future_attestation(self) -> None:
        self.assertFalse(self.config.recovery.attestation_path.exists())
        result = ColdBundleBuilder(
            self.config,
            command_runner=self.runner,
            now=lambda: datetime(2026, 8, 21, 8, tzinfo=UTC),
        ).build(
            release_root=self.release,
            bundle_id="v39-cold",
            state_source="legacy_c",
        )
        self.assertEqual("release-v39-cold-test", result.release_id)
        self.assertEqual(
            "qualification_only_requires_empty_d_attestation",
            result.protection_status,
        )
        self.assertFalse(self.config.recovery.attestation_path.exists())

    def test_d_active_bundle_still_requires_final_failure_domain_attestation(self) -> None:
        self.assertFalse(self.config.recovery.attestation_path.exists())
        with self.assertRaisesRegex(Exception, "attestation"):
            ColdBundleBuilder(
                self.config,
                command_runner=self.runner,
            ).build(
                release_root=self.release,
                bundle_id="d-active-must-be-protected",
                state_source="d_active",
            )
        self.assertEqual([], self.calls)

    def test_bundle_capture_root_parent_reparse_fails_before_first_write_or_scp(self) -> None:
        calls: list[tuple[str, ...]] = []

        def runner(arguments):
            call = tuple(arguments)
            calls.append(call)
            self.assertEqual("ssh", call[0])
            script = base64.b64decode(call[-1]).decode("utf-16-le")
            self.assertIn("root_parent_reparse", script)
            self.assertIn("recovery_tmp_escaped_exact_root", script)
            self.assertLess(
                script.index("root_parent_reparse"),
                script.index("New-Item -ItemType Directory"),
            )
            self.assertLess(
                script.index("recovery_tmp_escaped_exact_root"),
                script.index("New-Item -ItemType Directory"),
            )
            return CommandResult(1, "root_parent_reparse")

        with self.assertRaisesRegex(Exception, "checkpoint command"):
            ColdBundleBuilder(
                self.config,
                command_runner=runner,
                preflight=lambda: None,
            ).build(
                release_root=self.release,
                bundle_id="v39-cold",
                state_source="legacy_c",
            )
        # Capture failure is conservatively followed by one exact-id cleanup
        # attempt.  The same root guard fails before either command can write.
        self.assertEqual(["ssh", "ssh"], [call[0] for call in calls])
        self.assertIn(
            "cleanup-capture",
            base64.b64decode(calls[-1][-1]).decode("utf-16-le"),
        )

    def test_missing_operational_closure_cannot_produce_bundle(self) -> None:
        (self.operational / "tooling" / "python" / "python.exe").unlink()
        with self.assertRaises(Exception):
            ColdBundleBuilder(
                self.config, command_runner=self.runner, preflight=lambda: None
            ).build(
                release_root=self.release,
                bundle_id="v39-cold",
                state_source="legacy_c",
            )
        self.assertFalse(
            (self.config.recovery.recovery_root / "cold-recovery-v39-cold").exists()
        )

    def test_legacy_capture_source_set_is_fixed_and_all_output_is_d_root(self) -> None:
        observed = {}

        class Created:
            checkpoint_id = "checkpoint-fixed"
            manifest_sha256 = "f" * 64
            root = Path(r"D:\quant\quant_platform\tmp\publish-recovery\checkpoints\checkpoint-fixed")

        def fake_create(**kwargs):
            observed.update(kwargs)
            return Created()

        vm_root = Path(r"D:\quant\quant_platform")
        simulated_root = self.root / "simulated-vm-d" / "quant_platform"
        simulated_root.mkdir(parents=True)
        with patch(
            "quant_hub.ops.publish_recovery_cli._root", return_value=simulated_root
        ), patch(
            "quant_hub.ops.publish_recovery_cli._child", side_effect=lambda path: path
        ), patch(
            "quant_hub.ops.publish_recovery_cli.create_sqlite_checkpoint",
            side_effect=fake_create,
        ):
            capture_legacy(
                vm_root=vm_root,
                checkpoint_id="checkpoint-fixed",
                state_authority_id="legacy-c-writer",
                release_id="release-v39-cold-test",
                release_manifest_sha256="a" * 64,
            )
        self.assertEqual(
            {
                "comments": Path(r"C:\quant_platform_data\comments.sqlite3"),
                "research_workspace": Path(
                    r"C:\quant_platform_data\research_workspace.sqlite3"
                ),
            },
            observed["sources"],
        )
        self.assertEqual(
            simulated_root / "tmp" / "publish-recovery" / "checkpoints",
            observed["checkpoint_root"],
        )
        self.assertEqual(
            simulated_root / "tmp" / "publish-recovery" / "scratch",
            observed["scratch_root"],
        )

    def test_legacy_capture_is_forbidden_after_d_active_or_state_exists(self) -> None:
        vm_root = Path(r"D:\quant\quant_platform")
        for relative in (
            "control/active_release.json",
            "state/comments.sqlite3",
            "state/research_workspace.sqlite3",
        ):
            with self.subTest(relative=relative):
                simulated_root = self.root / ("simulated-" + relative.replace("/", "-"))
                target = simulated_root.joinpath(*relative.split("/"))
                target.parent.mkdir(parents=True)
                target.write_bytes(b"authority-present")
                with patch(
                    "quant_hub.ops.publish_recovery_cli._root",
                    return_value=simulated_root,
                ), patch(
                    "quant_hub.ops.publish_recovery_cli._child",
                    side_effect=lambda path: path,
                ), self.assertRaisesRegex(Exception, "forbidden after D"):
                    capture_legacy(
                        vm_root=vm_root,
                        checkpoint_id="checkpoint-must-not-exist",
                        state_authority_id="legacy-c-writer",
                        release_id="release-v39-cold-test",
                        release_manifest_sha256="a" * 64,
                    )
                self.assertFalse((simulated_root / "tmp").exists())

    def _restore_report(self) -> RecoveryVerification:
        return RecoveryVerification(
            valid=True,
            bundle_id="v39-cold",
            release_id="release-v39-cold-test",
            release_manifest_sha256=self.release_hash,
            checkpoint_id="checkpoint-v39-cold",
            checkpoint_manifest_sha256=self.remote_checkpoint.manifest_sha256,
            recovery_manifest_sha256="f" * 64,
            errors=(),
        )

    def _restore_bundle_fixture(self) -> Path:
        bundle = self.config.recovery.recovery_root / "cold-recovery-v39-cold"
        payloads = {
            "operational/tooling/python/python.exe": b"reviewed-bootstrap-python",
            "tools/restore/restore.py": b"# reviewed restore tool\n",
        }
        records = []
        sums = []
        for relative, payload in payloads.items():
            path = bundle.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            records.append(
                {"path": relative, "bytes": len(payload), "sha256": digest}
            )
            sums.append(f"{digest}  {relative}\n")
        (bundle / "closure_inventory.json").write_bytes(
            canonical_manifest_bytes(
                {
                    "schema_version": "qrh-recovery-closure-inventory/v1",
                    "bundle_id": "v39-cold",
                    "files": records,
                }
            )
        )
        (bundle / "SHA256SUMS").write_text("".join(sums), encoding="utf-8")
        return bundle

    def test_off_host_bundle_transfer_uses_only_exact_d_staging_and_cleans_it(self) -> None:
        bundle = self._restore_bundle_fixture()
        calls: list[tuple[str, ...]] = []

        def runner(arguments):
            call = tuple(arguments)
            calls.append(call)
            if call[0] == "scp":
                self.assertIn("HostName=10.5.1.240", call)
                # The runner account can expose one existing path as both
                # RUNNER~1 and runneradmin.  The transfer contract is physical
                # same-file identity, not a particular lexical spelling.
                self.assertTrue(Path(call[-2]).samefile(bundle))
                self.assertEqual(
                    "honghu-vm:D:/quant/quant_platform/tmp/recovery-import",
                    call[-1],
                )
                return CommandResult(0, "")
            script = base64.b64decode(call[-1]).decode("utf-16-le")
            self.assertNotIn("C:\\", script)
            self.assertNotIn("10.5.1.223", script)
            self.assertNotIn("10.5.1.235", script)
            self.assertIn("SSH_CONNECTION", script)
            self.assertIn("10.5.1.240", script)
            self.assertIn("ssh_target_address_differs", script)
            if "prepared_empty_root" in script:
                self.assertIn("exact_d_root_not_empty", script)
                self.assertIn("SSH_CONNECTION", script)
                self.assertIn("10.5.1.240", script)
                self.assertIn("root_full_path_differs", script)
                self.assertIn("root_parent_reparse", script)
                self.assertLess(
                    script.index("root_parent_reparse"),
                    script.index("New-Item -ItemType Directory"),
                )
                return CommandResult(
                    0,
                    json.dumps(
                        {"status": "prepared_empty_root", "empty_root_precondition": True}
                    ),
                )
            self.assertIn("--staged-under-target", script)
            parsed = subprocess.run(
                [
                    "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                    "[void][scriptblock]::Create([Console]::In.ReadToEnd())",
                ],
                input=script,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, parsed.returncode, parsed.stderr)
            self.assertIn("Assert-BootstrapFile", script)
            self.assertIn("Get-FileHash", script)
            self.assertIn("bootstrap_reparse_chain", script)
            self.assertLess(
                script.index("Assert-BootstrapFile 'D:"),
                script.index("$lines=&"),
            )
            for relative in (
                "operational\\tooling\\python\\python.exe",
                "tools\\restore\\restore.py",
            ):
                payload = bundle.joinpath(*relative.split("\\")).read_bytes()
                self.assertIn(hashlib.sha256(payload).hexdigest(), script)
                self.assertIn(f" {len(payload)} '", script)
            self.assertIn(
                r"D:\quant\quant_platform\tmp\recovery-import", script
            )
            self.assertIn(
                r"D:\quant\quant_platform\tmp\recovery-runtime", script
            )
            return CommandResult(
                0,
                json.dumps(
                    {
                        "schema_version": "qrh-recovery-materialization-event/v1",
                        "event_id": "cold-materialization-v39-cold",
                        "kind": "cold_recovery_materialized",
                        "authority": "evidence_only",
                        "fields": {
                            "bundle_id": "v39-cold",
                            "release_id": "release-v39-cold-test",
                            "manifest_sha256": self.release_hash,
                            "empty_root_precondition": True,
                            "import_cleaned": True,
                            "runtime_tmp_cleaned": True,
                        },
                    }
                ),
            )

        event = OpenSSHColdRestore(
            self.config,
            command_runner=runner,
            bundle_verifier=lambda _path: self._restore_report(),
        ).restore(
            bundle,
            evidence_output=(
                self.config.recovery.recovery_root / "evidence" /
                "cold-materialization" / "v39-cold.json"
            ),
        )
        self.assertEqual("cold_recovery_materialized", event["status"])
        self.assertEqual(["ssh", "scp", "ssh"], [call[0] for call in calls])

    def test_nonempty_remote_d_preflight_blocks_transfer(self) -> None:
        bundle = self._restore_bundle_fixture()
        calls: list[tuple[str, ...]] = []

        def runner(arguments):
            calls.append(tuple(arguments))
            return CommandResult(1, "")

        with self.assertRaisesRegex(ColdRestoreCLIError, "cold restore command"):
            OpenSSHColdRestore(
                self.config,
                command_runner=runner,
                bundle_verifier=lambda _path: self._restore_report(),
            ).restore(
                bundle,
                evidence_output=(
                    self.config.recovery.recovery_root / "evidence" /
                    "cold-materialization" / "nonempty.json"
                ),
            )
        self.assertEqual(["ssh"], [call[0] for call in calls])

    def test_remote_root_parent_reparse_fails_before_first_write_or_scp(self) -> None:
        bundle = self._restore_bundle_fixture()
        calls: list[tuple[str, ...]] = []

        def runner(arguments):
            call = tuple(arguments)
            calls.append(call)
            self.assertEqual("ssh", call[0])
            script = base64.b64decode(call[-1]).decode("utf-16-le")
            self.assertIn("root_parent_reparse", script)
            self.assertLess(
                script.index("root_parent_reparse"),
                script.index("New-Item -ItemType Directory"),
            )
            self.assertLess(
                script.index("root_full_path_differs"),
                script.index("New-Item -ItemType Directory"),
            )
            return CommandResult(1, "root_parent_reparse")

        with self.assertRaisesRegex(ColdRestoreCLIError, "cold restore command"):
            OpenSSHColdRestore(
                self.config,
                command_runner=runner,
                bundle_verifier=lambda _path: self._restore_report(),
            ).restore(
                bundle,
                evidence_output=(
                    self.config.recovery.recovery_root / "evidence" /
                    "cold-materialization" / "reparse.json"
                ),
            )
        self.assertEqual(["ssh"], [call[0] for call in calls])

    def test_local_bootstrap_tamper_blocks_before_ssh_or_scp(self) -> None:
        bundle = self._restore_bundle_fixture()
        (bundle / "operational" / "tooling" / "python" / "python.exe").write_bytes(
            b"tampered-after-verification"
        )
        calls: list[tuple[str, ...]] = []
        with self.assertRaisesRegex(ColdRestoreCLIError, "changed after"):
            OpenSSHColdRestore(
                self.config,
                command_runner=lambda arguments: (
                    calls.append(tuple(arguments)) or CommandResult(0, "{}")
                ),
                bundle_verifier=lambda _path: self._restore_report(),
            ).restore(
                bundle,
                evidence_output=(
                    self.config.recovery.recovery_root / "evidence" /
                    "cold-materialization" / "local-tamper.json"
                ),
            )
        self.assertEqual([], calls)

    def test_remote_bootstrap_mismatch_cannot_execute_or_emit_success_evidence(self) -> None:
        bundle = self._restore_bundle_fixture()
        calls: list[tuple[str, ...]] = []

        def runner(arguments):
            call = tuple(arguments)
            calls.append(call)
            if call[0] == "scp":
                return CommandResult(0, "")
            script = base64.b64decode(call[-1]).decode("utf-16-le")
            if "prepared_empty_root" in script:
                return CommandResult(
                    0,
                    json.dumps(
                        {"status": "prepared_empty_root", "empty_root_precondition": True}
                    ),
                )
            self.assertLess(script.index("Get-FileHash"), script.index("$lines=&"))
            self.assertNotIn("cold_recovery_materialized'", script[: script.index("$lines=&")])
            return CommandResult(1, "")

        with self.assertRaisesRegex(ColdRestoreCLIError, "cold restore command"):
            OpenSSHColdRestore(
                self.config,
                command_runner=runner,
                bundle_verifier=lambda _path: self._restore_report(),
            ).restore(
                bundle,
                evidence_output=(
                    self.config.recovery.recovery_root / "evidence" /
                    "cold-materialization" / "remote-tamper.json"
                ),
            )
        self.assertEqual(["ssh", "scp", "ssh"], [call[0] for call in calls])


if __name__ == "__main__":
    unittest.main()
