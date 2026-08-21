from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import shutil
import subprocess
import tempfile
import unittest

from quant_hub.ops.cold_restore_cli import (
    ColdRestoreCLIError,
    OpenSSHColdRestore,
)
from quant_hub.ops.publish_adapters import CommandResult, GitHubCIConfig, VMConfig
from quant_hub.ops.publish_runtime import RecoveryRuntimeConfig, RuntimePublishConfig
from quant_hub.ops.recovery_bundle import RecoveryVerification


LEGACY_ID = "quant-hub-v39-company-broadcast-20260731-hotfix1"
INVENTORY_HASH = "b" * 64


def runtime_config(root: Path) -> RuntimePublishConfig:
    project = root / "project"
    project.mkdir()
    recovery = root / "offhost-recovery"
    recovery.mkdir()
    return RuntimePublishConfig(
        project_root=project,
        state_root=root / "state",
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
        vm=VMConfig(
            "honghu-vm", "10.5.1.240",
            PureWindowsPath(r"D:\quant\quant_platform"),
        ),
        recovery=RecoveryRuntimeConfig(
            recovery_root=recovery,
            attestation_path=root / "attestation.json",
            attestation_max_age_seconds=3600,
            state_authority_id="state-authority",
            restore_tool=root / "restore.py",
            runbook=root / "RUNBOOK.md",
            operational_root=root / "operational-source",
        ),
    )


def qualification_bundle(config: RuntimePublishConfig) -> tuple[Path, RecoveryVerification]:
    bundle = config.recovery.recovery_root / "cold-recovery-qualification-1"
    files = {
        "operational/tooling/python/python.exe": b"portable-python",
        "tools/restore/restore.py": b"# stdlib restore tool\n",
    }
    records = []
    sums = []
    for relative, payload in files.items():
        path = bundle.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        records.append({"path": relative, "bytes": len(payload), "sha256": digest})
        sums.append(f"{digest}  {relative}")
    (bundle / "closure_inventory.json").write_text(
        json.dumps({"files": records}), encoding="utf-8"
    )
    (bundle / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    report = RecoveryVerification(
        True, "qualification-1", "release-v39", "a" * 64,
        "checkpoint-1", "c" * 64, "d" * 64, (),
    )
    return bundle, report


def decode_ssh(arguments) -> str:
    return base64.b64decode(arguments[-1]).decode("utf-16-le")


class PrepareRunner:
    def __init__(self, *, fail_apply: bool = False) -> None:
        self.calls = []
        self.fail_apply = fail_apply

    def __call__(self, arguments):
        self.calls.append(tuple(arguments))
        script = decode_ssh(arguments)
        intent = re.search(r"\$intentHash='([0-9a-f]{64})';", script)
        assert intent is not None
        intent_hash = intent.group(1)
        if "Remove-Item -LiteralPath $child.FullName" in script:
            if self.fail_apply:
                return CommandResult(1, "")
            return CommandResult(
                0,
                json.dumps(
                    {
                        "schema_version": "qrh-prepare-empty-application/v1",
                        "status": "prepared_empty_root",
                        "intent_nonce_sha256": intent_hash,
                        "pre_delete_inventory_sha256": INVENTORY_HASH,
                        "deleted_child_count": 3,
                        "legacy_deployment_id": LEGACY_ID,
                        "root_exists": True,
                        "root_empty": True,
                        "old_c_v39_healthy": True,
                        "active_absent": True,
                        "writer_authority_absent": True,
                    }
                ),
            )
        return CommandResult(
            0,
            json.dumps(
                {
                    "schema_version": "qrh-prepare-empty-inspection/v1",
                    "status": "inspected_not_deleted",
                    "intent_nonce_sha256": intent_hash,
                    "inventory_sha256": INVENTORY_HASH,
                    "file_count": 10,
                    "directory_count": 5,
                    "total_bytes": 1234,
                    "top_level_count": 3,
                    "legacy_deployment_id": LEGACY_ID,
                    "active_absent": True,
                    "writer_authority_absent": True,
                    "old_c_v39_healthy": True,
                    "deleted": False,
                }
            ),
        )


class ColdRestorePrepareEmptyTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config = runtime_config(self.root)
        self.bundle, self.report = qualification_bundle(self.config)
        self.verifier = lambda _path: self.report

    def test_inspect_then_bound_apply_is_append_only_and_redacted(self) -> None:
        runner = PrepareRunner()
        operator = OpenSSHColdRestore(
            self.config, command_runner=runner, bundle_verifier=self.verifier
        )
        nonce = "intent-qualification-0001"
        inspected = operator.inspect_prepare_empty(
            self.bundle,
            intent_nonce=nonce,
            expected_legacy_deployment_id=LEGACY_ID,
        )
        self.assertEqual("inspected_not_deleted", inspected["status"])
        self.assertEqual(INVENTORY_HASH, inspected["pre_delete_inventory_sha256"])
        inspect_script = decode_ssh(runner.calls[0])
        self.assertNotIn("Remove-Item -LiteralPath $child.FullName", inspect_script)
        self.assertIn("unknown_top_level", inspect_script)
        self.assertIn("d_active_authority_exists", inspect_script)
        self.assertIn("d_pending_activation_exists", inspect_script)
        self.assertIn("d_state_writer_authority_exists", inspect_script)
        self.assertIn("Get-NetTCPConnection -LocalPort 8765", inspect_script)
        self.assertIn("C:\\quant_platform\\", inspect_script)
        self.assertIn(LEGACY_ID, inspect_script)
        self.assertIn("SSH_CONNECTION", inspect_script)
        self.assertLess(inspect_script.index("SSH_CONNECTION"), inspect_script.index("Get-ChildItem"))

        applied = operator.apply_prepare_empty(
            self.bundle,
            intent_nonce=nonce,
            expected_pre_delete_inventory_sha256=INVENTORY_HASH,
            expected_legacy_deployment_id=LEGACY_ID,
        )
        self.assertEqual("prepared_empty_root", applied["status"])
        apply_script = decode_ssh(runner.calls[1])
        self.assertIn("pre_delete_inventory_differs", apply_script)
        self.assertIn("pre_delete_inventory_changed", apply_script)
        self.assertIn("Remove-Item -LiteralPath $child.FullName", apply_script)
        self.assertLess(
            apply_script.index("pre_delete_inventory_changed"),
            apply_script.index("Remove-Item -LiteralPath $child.FullName"),
        )
        self.assertLess(
            apply_script.index("pre_delete_inventory_changed_after_child_preflight"),
            apply_script.index("Remove-Item -LiteralPath $child.FullName"),
        )
        self.assertLess(
            apply_script.index("d_active_authority_exists"),
            apply_script.index("Remove-Item -LiteralPath $child.FullName"),
        )
        self.assertNotIn("Remove-Item -LiteralPath $root", apply_script)
        self.assertNotIn("C:\\quant_platform' -Recurse", apply_script)
        self.assertGreaterEqual(apply_script.count("root_parent_reparse"), 2)
        evidence_root = self.config.recovery.recovery_root / "evidence" / "prepare-empty"
        self.assertEqual(3, len(list(evidence_root.glob("*.json"))))
        rendered = "\n".join(path.read_text(encoding="utf-8") for path in evidence_root.glob("*.json"))
        self.assertNotIn(nonce, rendered)
        self.assertNotIn("Authorization", rendered)
        calls_before_reuse = len(runner.calls)
        with self.assertRaisesRegex(ColdRestoreCLIError, "already inspected"):
            operator.inspect_prepare_empty(
                self.bundle,
                intent_nonce=nonce,
                expected_legacy_deployment_id=LEGACY_ID,
            )
        self.assertEqual(calls_before_reuse, len(runner.calls))

    def test_changed_hash_or_missing_inspection_performs_zero_remote_calls(self) -> None:
        runner = PrepareRunner()
        operator = OpenSSHColdRestore(
            self.config, command_runner=runner, bundle_verifier=self.verifier
        )
        with self.assertRaisesRegex(ColdRestoreCLIError, "inspection evidence"):
            operator.apply_prepare_empty(
                self.bundle,
                intent_nonce="never-inspected-0001",
                expected_pre_delete_inventory_sha256=INVENTORY_HASH,
                expected_legacy_deployment_id=LEGACY_ID,
            )
        self.assertEqual([], runner.calls)
        nonce = "hash-binding-inspect-0001"
        operator.inspect_prepare_empty(
            self.bundle,
            intent_nonce=nonce,
            expected_legacy_deployment_id=LEGACY_ID,
        )
        with self.assertRaisesRegex(ColdRestoreCLIError, "does not authorize"):
            operator.apply_prepare_empty(
                self.bundle,
                intent_nonce=nonce,
                expected_pre_delete_inventory_sha256="c" * 64,
                expected_legacy_deployment_id=LEGACY_ID,
            )
        self.assertEqual(1, len(runner.calls))

    def test_remote_apply_failure_has_intent_but_no_success_evidence(self) -> None:
        runner = PrepareRunner(fail_apply=True)
        operator = OpenSSHColdRestore(
            self.config, command_runner=runner, bundle_verifier=self.verifier
        )
        nonce = "intent-failing-apply-0001"
        operator.inspect_prepare_empty(
            self.bundle,
            intent_nonce=nonce,
            expected_legacy_deployment_id=LEGACY_ID,
        )
        with self.assertRaises(ColdRestoreCLIError):
            operator.apply_prepare_empty(
                self.bundle,
                intent_nonce=nonce,
                expected_pre_delete_inventory_sha256=INVENTORY_HASH,
                expected_legacy_deployment_id=LEGACY_ID,
            )
        evidence = self.config.recovery.recovery_root / "evidence" / "prepare-empty"
        self.assertEqual(1, len(list(evidence.glob("*.apply-intent.json"))))
        self.assertEqual(0, len(list(evidence.glob("*.applied.json"))))

    def test_prepare_scripts_parse_and_inspection_has_no_delete_ast(self) -> None:
        operator = OpenSSHColdRestore(self.config, bundle_verifier=self.verifier)
        scripts = (
            operator._prepare_empty_script(
                expected_legacy_deployment_id=LEGACY_ID,
                intent_nonce_sha256="d" * 64,
                apply=False,
                expected_inventory_sha256=None,
            ),
            operator._prepare_empty_script(
                expected_legacy_deployment_id=LEGACY_ID,
                intent_nonce_sha256="d" * 64,
                apply=True,
                expected_inventory_sha256=INVENTORY_HASH,
            ),
        )
        self.assertNotIn("Remove-Item", scripts[0])
        for script in scripts:
            encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
            completed = subprocess.run(
                [
                    "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                    f"[scriptblock]::Create([Text.Encoding]::Unicode.GetString("
                    f"[Convert]::FromBase64String('{encoded}'))) | Out-Null",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)

    def test_restore_writes_bound_local_event_only_after_remote_success(self) -> None:
        event = {
            "schema_version": "qrh-recovery-materialization-event/v1",
            "event_id": "cold-materialization-qualification-1",
            "kind": "cold_recovery_materialized",
            "authority": "evidence_only",
            "fields": {
                "bundle_id": "qualification-1",
                "release_id": "release-v39",
                "manifest_sha256": "a" * 64,
                "empty_root_precondition": True,
                "import_cleaned": True,
                "runtime_tmp_cleaned": True,
            },
        }
        calls = []

        def runner(arguments):
            calls.append(tuple(arguments))
            if arguments[0] == "scp":
                return CommandResult(0, "")
            script = decode_ssh(arguments)
            if "prepared_empty_root" in script:
                return CommandResult(0, '{"status":"prepared_empty_root","empty_root_precondition":true}')
            return CommandResult(0, json.dumps(event))

        operator = OpenSSHColdRestore(
            self.config, command_runner=runner, bundle_verifier=self.verifier
        )
        output = (
            self.config.recovery.recovery_root / "evidence" /
            "cold-materialization" / "qualification-1.json"
        )
        result = operator.restore(self.bundle, evidence_output=output)
        self.assertEqual(hashlib.sha256(operator._canonical_bytes(event)).hexdigest(), result["evidence_sha256"])
        self.assertEqual(event, json.loads(output.read_text(encoding="utf-8")))
        self.assertNotIn("fields", result)
        # Exact bytes are idempotent; another payload at the same authority is rejected.
        self.assertEqual(
            result["evidence_sha256"], operator._write_immutable_evidence(output, event)
        )
        with self.assertRaisesRegex(ColdRestoreCLIError, "differs"):
            operator._write_immutable_evidence(output, {**event, "kind": "different"})

    def test_restore_failure_does_not_publish_local_success_event(self) -> None:
        def runner(arguments):
            if arguments[0] == "scp":
                return CommandResult(0, "")
            script = decode_ssh(arguments)
            if "prepared_empty_root" in script:
                return CommandResult(0, '{"status":"prepared_empty_root","empty_root_precondition":true}')
            return CommandResult(1, "")

        output = (
            self.config.recovery.recovery_root / "evidence" /
            "cold-materialization" / "failed.json"
        )
        operator = OpenSSHColdRestore(
            self.config, command_runner=runner, bundle_verifier=self.verifier
        )
        with self.assertRaises(ColdRestoreCLIError):
            operator.restore(self.bundle, evidence_output=output)
        self.assertFalse(output.exists())

    def test_conflicting_local_materialization_evidence_blocks_before_remote(self) -> None:
        calls = []
        output = (
            self.config.recovery.recovery_root / "evidence" /
            "cold-materialization" / "conflict.json"
        )
        output.parent.mkdir(parents=True)
        output.write_text('{"different":true}', encoding="utf-8")
        operator = OpenSSHColdRestore(
            self.config,
            command_runner=lambda arguments: (
                calls.append(tuple(arguments)) or CommandResult(0, "{}")
            ),
            bundle_verifier=self.verifier,
        )
        with self.assertRaisesRegex(ColdRestoreCLIError, "already differs"):
            operator.restore(self.bundle, evidence_output=output)
        self.assertEqual([], calls)


if __name__ == "__main__":
    unittest.main()
