from __future__ import annotations

import json
from pathlib import Path, PureWindowsPath
import shutil
import subprocess
import sys
import tempfile
import unittest

from quant_hub.ops.operational_source_cli import (
    OperationalSourceError,
    OperationalSourceOrchestrator,
    _tree_records,
    inspect_portable_runtime,
    prepare_operational_control,
)
from quant_hub.ops.publish_adapters import CommandResult, GitHubCIConfig, VMConfig
from quant_hub.ops.publish_runtime import RecoveryRuntimeConfig, RuntimePublishConfig


class FakeCompatibility:
    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode
        self.calls = []

    def __call__(self, arguments, environment, cwd):
        self.calls.append((tuple(arguments), dict(environment), cwd))
        return subprocess.CompletedProcess(arguments, self.returncode, b"", b"")


def portable_runtime(root: Path) -> Path:
    python = root / "python"
    package = python / "Lib" / "site-packages" / "quant_hub"
    files = {
        "python.exe": b"portable-python",
        "Lib/site-packages/win32/pythonservice.exe": b"python-service",
        "Lib/site-packages/quant_hub/__init__.py": b"# package\n",
        "Lib/site-packages/quant_hub/ops/__init__.py": b"# ops\n",
        "Lib/site-packages/quant_hub/ops/windows_service.py": b"# host\n",
        "Lib/site-packages/quant_hub/ops/service_entry.py": b"# entry\n",
        "Lib/site-packages/quant_hub/ops/vm_deploy_cli.py": b"# deploy\n",
        "Lib/site-packages/quant_hub/ops/publish_recovery_cli.py": b"# recovery\n",
        "Lib/site-packages/quant_hub/ops/operational_source_cli.py": b"# prepare\n",
        "Lib/site-packages/quant_hub/web/__init__.py": b"# web\n",
        "Lib/site-packages/quant_hub/web/access_gate.py": b"# access\n",
    }
    for relative, payload in files.items():
        path = python.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    return python


def config(root: Path, operational_generation: str = "op-generation-1") -> RuntimePublishConfig:
    project = root / "project"
    project.mkdir(exist_ok=True)
    state = root / "protected-state"
    state.mkdir(exist_ok=True)
    recovery = root / "recovery"
    recovery.mkdir(exist_ok=True)
    return RuntimePublishConfig(
        project_root=project,
        state_root=state,
        candidate_root=root / "candidates",
        git_remote="origin",
        runtime_base=root / "runtime-base",
        runtime_base_manifest_sha256="a" * 64,
        reference_archive_root=root / "reference",
        code_source_relative_path="quant_hub",
        code_overlay_relative_path="runtime_contract/code",
        launcher_relative_path="tools/viewer/bootstrap.py",
        required_runtime_paths={},
        resource_overlays=(),
        github=GitHubCIConfig("Garthzzz", "quant_platform", 1, None, 1, 10),
        vm=VMConfig("honghu-vm", "10.5.1.240", PureWindowsPath(r"D:\quant\quant_platform")),
        recovery=RecoveryRuntimeConfig(
            recovery_root=recovery,
            attestation_path=root / "attestation.json",
            attestation_max_age_seconds=3600,
            state_authority_id="state-authority",
            restore_tool=root / "restore.py",
            runbook=root / "RUNBOOK.md",
            operational_root=root / "operational-sources" / operational_generation,
        ),
    )


class FakeBackend:
    def __init__(self) -> None:
        self.ssh_calls = []
        self.uploads = []

    def _ssh(self, script):
        self.ssh_calls.append(script)
        if len(self.ssh_calls) == 1:
            return '{"status":"absent"}'
        if len(self.ssh_calls) == 2:
            return '{"status":"tooling_adopted","generation":"op-generation-1"}'
        return '{"status":"operational_staging_removed"}'

    def ensure_directory(self, path):
        self.directory = path

    def upload(self, source, target):
        self.uploads.append((Path(source), PureWindowsPath(target)))


class OperationalSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_prepare_control_is_canonical_no_scm_and_uses_no_secret(self) -> None:
        vm = self.root / "vm"
        python = portable_runtime(vm / "tooling")
        (vm / "tmp").mkdir()
        runner = FakeCompatibility()
        result = prepare_operational_control(
            root=vm,
            environment={"TEMP": str(vm / "tmp"), "TMP": str(vm / "tmp")},
            compatibility_runner=runner,
            allow_test_root=True,
        )
        self.assertEqual("prepared_no_scm", result["status"])
        self.assertFalse(result["scm_changed"])
        self.assertFalse(result["active_changed"])
        self.assertFalse(result["secret_required"])
        self.assertEqual(2, len(runner.calls))
        self.assertTrue(all("-I" in call[0] and "-B" in call[0] for call in runner.calls))
        candidate_path = vm / "control" / "service_install_candidate.json"
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        self.assertEqual(
            r"D:\quant\quant_platform\tooling\python\python.exe",
            candidate["service_python"],
        )
        self.assertEqual(
            json.dumps(candidate, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            candidate_path.read_text(encoding="utf-8"),
        )
        self.assertFalse((vm / "control" / "active_release.json").exists())
        self.assertFalse((vm / "state" / "viewer_access_password.digest").exists())
        self.assertTrue(python.is_dir())

    def test_prepare_fails_before_control_on_compatibility_or_cache(self) -> None:
        vm = self.root / "vm"
        python = portable_runtime(vm / "tooling")
        (vm / "tmp").mkdir()
        with self.assertRaisesRegex(OperationalSourceError, "compatibility"):
            prepare_operational_control(
                root=vm,
                environment={"TEMP": str(vm / "tmp"), "TMP": str(vm / "tmp")},
                compatibility_runner=FakeCompatibility(1),
                allow_test_root=True,
            )
        self.assertFalse((vm / "control").exists())
        cache = python / "Lib/site-packages/quant_hub/__pycache__"
        cache.mkdir()
        with self.assertRaisesRegex(OperationalSourceError, "bytecode/cache"):
            prepare_operational_control(
                root=vm,
                environment={"TEMP": str(vm / "tmp"), "TMP": str(vm / "tmp")},
                compatibility_runner=FakeCompatibility(),
                allow_test_root=True,
            )

    def test_fixed_upload_uses_inventory_and_bootstrap_hashes(self) -> None:
        portable = portable_runtime(self.root / "portable")
        runtime = inspect_portable_runtime(portable, "op-generation-1")
        backend = FakeBackend()
        seen = []

        def runner(arguments):
            seen.append(tuple(arguments))
            return CommandResult(
                0,
                json.dumps(
                    {
                        "schema_version": "qrh-operational-prepare/v1",
                        "status": "prepared_no_scm",
                        "service_python_sha256": runtime.python_sha256,
                        "quant_hub_package_inventory_sha256": runtime.package_inventory_sha256,
                        "scm_changed": False,
                        "active_changed": False,
                        "secret_required": False,
                    }
                ),
            )

        orchestrator = OperationalSourceOrchestrator(
            config(self.root), command_runner=runner, backend=backend
        )
        result = orchestrator.prepare_remote(
            portable, generation="op-generation-1"
        )
        self.assertEqual("prepared_no_scm", result["status"])
        self.assertEqual(len(runtime.inventory["files"]) + 1, len(backend.uploads))
        adoption = backend.ssh_calls[1]
        self.assertIn("existing_tooling_requires_explicit_replace", adoption)
        self.assertIn("root_parent_reparse", adoption)
        self.assertLess(adoption.index("root_parent_reparse"), adoption.index("Move-Item"))
        script = base64_decode(seen[-1][-1])
        self.assertIn("SSH_CONNECTION", script)
        self.assertIn(runtime.python_sha256, script)
        self.assertIn(runtime.package_inventory_sha256, script)
        self.assertNotIn("sc.exe", script.casefold())
        self.assertEqual(3, len(backend.ssh_calls))
        cleanup = backend.ssh_calls[-1]
        self.assertIn("operational_staging_removed", cleanup)
        self.assertIn("root_parent_reparse", cleanup)
        self.assertLess(cleanup.index("root_parent_reparse"), cleanup.index("Remove-Item"))

    def test_portable_cache_or_secret_is_rejected(self) -> None:
        portable = portable_runtime(self.root / "portable")
        (portable / "Lib/site-packages/quant_hub/__pycache__").mkdir()
        with self.assertRaisesRegex(OperationalSourceError, "bytecode/cache"):
            inspect_portable_runtime(portable, "op-generation-1")
        shutil.rmtree(portable / "Lib/site-packages/quant_hub/__pycache__")
        (portable / "secret.bin").write_bytes(("sk-" + "X" * 32).encode())
        with self.assertRaisesRegex(OperationalSourceError, "no-secret"):
            inspect_portable_runtime(portable, "op-generation-1")

    def test_download_is_stable_verified_and_adopted_off_git(self) -> None:
        remote = self.root / "remote"
        portable_runtime(remote / "tooling")
        (remote / "tmp").mkdir()
        prepare_operational_control(
            root=remote,
            environment={"TEMP": str(remote / "tmp"), "TMP": str(remote / "tmp")},
            compatibility_runner=FakeCompatibility(),
            allow_test_root=True,
        )
        unrelated = remote / "tooling" / "source" / "old-diagnostic-source.txt"
        unrelated.parent.mkdir(parents=True)
        unrelated.write_text("must not enter operational authority", encoding="utf-8")
        remote_records = [
            row
            for row in _tree_records(remote)
            if str(row["path"]).startswith("tooling/python/")
            or str(row["path"])
            in {
                "control/deployment_runtime.json",
                "control/service_install_candidate.json",
            }
        ]
        inventory = {
            "schema_version": "qrh-remote-operational-tree/v1",
            "files": remote_records,
        }

        def runner(arguments):
            self.assertEqual("scp", arguments[0])
            self.assertIn("HostName=10.5.1.240", arguments)
            source = str(arguments[-2])
            destination = Path(arguments[-1])
            if source.endswith("/tooling/python"):
                shutil.copytree(remote / "tooling/python", destination / "python")
            elif source.endswith("deployment_runtime.json"):
                shutil.copy2(remote / "control/deployment_runtime.json", destination)
            elif source.endswith("service_install_candidate.json"):
                shutil.copy2(remote / "control/service_install_candidate.json", destination)
            return CommandResult(0, "")

        class Downloader(OperationalSourceOrchestrator):
            def _remote_inventory(self_inner):
                return inventory

        orchestrator = Downloader(config(self.root), command_runner=runner)
        receipt = orchestrator.download_and_seal(generation="op-generation-1")
        self.assertEqual("qrh-operational-source-receipt/v1", receipt["schema_version"])
        self.assertFalse(receipt["contains_secret"])
        self.assertTrue(orchestrator.config.recovery.operational_root.is_dir())
        self.assertFalse(
            (
                orchestrator.config.recovery.operational_root
                / "tooling/source/old-diagnostic-source.txt"
            ).exists()
        )
        self.assertTrue(
            (orchestrator.config.recovery.operational_root.parent / "receipts/op-generation-1.json").is_file()
        )

    def test_download_rejects_remote_mutation_and_leaves_no_generation(self) -> None:
        remote = self.root / "remote"
        portable_runtime(remote / "tooling")
        (remote / "tmp").mkdir()
        prepare_operational_control(
            root=remote,
            environment={"TEMP": str(remote / "tmp"), "TMP": str(remote / "tmp")},
            compatibility_runner=FakeCompatibility(),
            allow_test_root=True,
        )
        stable = {
            "schema_version": "qrh-remote-operational-tree/v1",
            "files": [
                row
                for row in _tree_records(remote)
                if str(row["path"]).startswith("tooling/python/")
                or str(row["path"])
                in {
                    "control/deployment_runtime.json",
                    "control/service_install_candidate.json",
                }
            ],
        }
        changed = json.loads(json.dumps(stable))
        changed["files"][0]["sha256"] = "f" * 64

        def runner(arguments):
            source = str(arguments[-2])
            destination = Path(arguments[-1])
            if source.endswith("/tooling/python"):
                shutil.copytree(remote / "tooling/python", destination / "python")
            elif source.endswith("deployment_runtime.json"):
                shutil.copy2(remote / "control/deployment_runtime.json", destination)
            else:
                shutil.copy2(remote / "control/service_install_candidate.json", destination)
            return CommandResult(0, "")

        class MutatingDownloader(OperationalSourceOrchestrator):
            probes = 0

            def _remote_inventory(self_inner):
                self_inner.probes += 1
                return stable if self_inner.probes == 1 else changed

        orchestrator = MutatingDownloader(config(self.root), command_runner=runner)
        with self.assertRaisesRegex(OperationalSourceError, "changed during download"):
            orchestrator.download_and_seal(generation="op-generation-1")
        self.assertFalse(orchestrator.config.recovery.operational_root.exists())

    def test_remote_inventory_is_exact_python_runtime_and_read_guarded(self) -> None:
        class InventoryBackend:
            def __init__(self):
                self.script = ""

            def _ssh(self, script):
                self.script = script
                return '{"schema_version":"qrh-remote-operational-tree/v1","files":[]}'

        backend = InventoryBackend()
        orchestrator = OperationalSourceOrchestrator(
            config(self.root), backend=backend
        )
        value = orchestrator._remote_inventory()
        self.assertEqual("qrh-remote-operational-tree/v1", value["schema_version"])
        self.assertIn(r"tooling\python", backend.script)
        self.assertIn("path='tooling/python/'", backend.script)
        self.assertNotIn("tooling/source", backend.script)
        self.assertIn("root_parent_reparse", backend.script)
        parsed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[void][scriptblock]::Create([Console]::In.ReadToEnd())",
            ],
            input=backend.script,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, parsed.returncode, parsed.stderr)


def base64_decode(value: str) -> str:
    import base64

    return base64.b64decode(value).decode("utf-16-le")


if __name__ == "__main__":
    unittest.main()
