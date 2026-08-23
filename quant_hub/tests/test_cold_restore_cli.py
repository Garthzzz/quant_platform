from __future__ import annotations

import base64
import ctypes
from datetime import UTC, datetime
import gzip
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from quant_hub.ops.cold_restore_cli import (
    ColdRestoreCLIError,
    OpenSSHColdRestore,
    _CANONICAL_AUDIT_PROBE,
    _legacy_materialization_event_bytes,
    _qualification_candidate_residue_guard_script,
    _qualification_closure_guard_script,
    _qualification_legacy_guard_script,
    _qualification_native_probe_script,
    _qualification_no_d_execution_guard_script,
    _qualification_replay_guard_script,
)
from quant_hub.ops.failure_domain import (
    FACTS_SCHEMA,
    PROBE_SCHEMA,
    attest_failure_domain,
    canonical_bytes,
)
from quant_hub.ops.publish_adapters import CommandResult, GitHubCIConfig, VMConfig
from quant_hub.ops.publish_runtime import RecoveryRuntimeConfig, RuntimePublishConfig
from quant_hub.ops.recovery_bundle import RecoveryVerification


LEGACY_ID = "quant-hub-v39-company-broadcast-20260731-hotfix1"
INVENTORY_HASH = "b" * 64
TOP_LEVEL_CHILDREN = [
    {"name": name, "inventory_sha256": hashlib.sha256(name.encode()).hexdigest()}
    for name in (
        "audit", "backups", "control", "incoming", "releases", "state", "tmp",
        "tooling", "tools",
    )
]


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


def materialized_qualification_bundle(
    config: RuntimePublishConfig,
) -> tuple[Path, RecoveryVerification]:
    bundle, _report = qualification_bundle(config)
    release_payload = b"legacy release payload"
    legacy_server = b"# exact legacy V39 server fixture\n"
    release_file = bundle / "release" / "payload.bin"
    release_file.parent.mkdir(parents=True)
    release_file.write_bytes(release_payload)
    release_server = bundle / "release" / "tools" / "viewer" / "server.py"
    release_server.parent.mkdir(parents=True)
    release_server.write_bytes(legacy_server)
    release_manifest = {
        "schema_version": "qrh-release-manifest/v1",
        "release_id": "release-v39",
        "application": {
            "source_kind": "legacy_broadcast",
            "legacy_deployment_id": LEGACY_ID,
        },
        "inventory": {
            "files": [
                {
                    "path": "payload.bin",
                    "bytes": len(release_payload),
                    "sha256": hashlib.sha256(release_payload).hexdigest(),
                },
                {
                    "path": "tools/viewer/server.py",
                    "bytes": len(legacy_server),
                    "sha256": hashlib.sha256(legacy_server).hexdigest(),
                },
            ]
        },
    }
    release_manifest_bytes = json.dumps(
        release_manifest, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    (bundle / "release" / "release_manifest.json").write_bytes(
        release_manifest_bytes
    )
    state_records = []
    checkpoint_root = bundle / "checkpoints" / "checkpoint-1"
    for logical_name, byte in (("comments", b"c"), ("research_workspace", b"r")):
        payload = byte * 256
        path = checkpoint_root / "state" / f"{logical_name}.sqlite3"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        state_records.append(
            {
                "logical_name": logical_name,
                "relative_path": f"state/{logical_name}.sqlite3",
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    checkpoint = {
        "schema_version": "qrh-checkpoint-manifest/v1",
        "checkpoint_id": "checkpoint-1",
        "state": {"databases": state_records},
    }
    checkpoint_bytes = json.dumps(
        checkpoint, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    (checkpoint_root / "checkpoint_manifest.json").write_bytes(checkpoint_bytes)
    bootstrap = {
        "schema_version": "qrh-operational-bootstrap/v1",
        "authority_root": r"D:\quant\quant_platform",
        "files": [],
    }
    bootstrap_bytes = json.dumps(
        bootstrap, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    bootstrap_path = bundle / "operational" / "control" / "operational_bootstrap.json"
    bootstrap_path.parent.mkdir(parents=True)
    bootstrap_path.write_bytes(bootstrap_bytes)
    closure_path = bundle / "closure_inventory.json"
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    for relative, payload in (
        ("operational/control/operational_bootstrap.json", bootstrap_bytes),
        ("release/release_manifest.json", release_manifest_bytes),
    ):
        closure["files"].append(
            {
                "path": relative,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    closure_bytes = canonical_bytes(closure)
    closure_path.write_bytes(closure_bytes)
    recovery_manifest = {
        "schema_version": "qrh-recovery-manifest/v1",
        "bundle_id": "qualification-1",
        "release": {
            "release_id": "release-v39",
            "manifest_sha256": hashlib.sha256(release_manifest_bytes).hexdigest(),
        },
        "checkpoint": {
            "checkpoint_id": "checkpoint-1",
            "manifest_sha256": hashlib.sha256(checkpoint_bytes).hexdigest(),
        },
        "closure": {
            "inventory_sha256": hashlib.sha256(closure_bytes).hexdigest(),
        },
    }
    recovery_manifest_bytes = canonical_bytes(recovery_manifest)
    (bundle / "recovery_manifest.json").write_bytes(recovery_manifest_bytes)
    report = RecoveryVerification(
        True,
        "qualification-1",
        "release-v39",
        hashlib.sha256(release_manifest_bytes).hexdigest(),
        "checkpoint-1",
        hashlib.sha256(checkpoint_bytes).hexdigest(),
        hashlib.sha256(recovery_manifest_bytes).hexdigest(),
        (),
    )
    def host_facts(role: str, machine: str, volume: str, path: str):
        value = {
            "schema_version": FACTS_SCHEMA,
            "role": role,
            "host_name": machine,
            "machine_identity": machine,
            "canonical_path": path,
            "path_kind": "local",
            "reparse_or_symlink": False,
            "volume_identity": volume,
            "storage_backend": "local-ntfs:" + volume,
            "storage_authority": machine + "|" + volume,
            "tool_version": "tests/v1",
        }
        value["facts_sha256"] = hashlib.sha256(canonical_bytes(value)).hexdigest()
        return value

    event = {
        "schema_version": "qrh-recovery-materialization-event/v1",
        "event_id": "cold-materialization-qualification-1",
        "kind": "cold_recovery_materialized",
        "authority": "evidence_only",
        "fields": {
            "bundle_id": "qualification-1",
            "release_id": "release-v39",
            "manifest_sha256": report.release_manifest_sha256,
            "empty_root_precondition": True,
            "import_cleaned": True,
            "runtime_tmp_cleaned": True,
        },
    }
    probe = {
        "schema_version": PROBE_SCHEMA,
        "production_root_available": False,
        "recovery_bundle_readable": True,
        "closure_verified": True,
        "empty_root_precondition": True,
        "bundle_id": "qualification-1",
        "release_id": "release-v39",
        "release_manifest_sha256": report.release_manifest_sha256,
        "bundle_inventory_sha256": hashlib.sha256(closure_bytes).hexdigest(),
        "materialization_event_id": event["event_id"],
        "materialization_event_sha256": hashlib.sha256(
            canonical_bytes(event)
        ).hexdigest(),
        "probe_tool_sha256": "b" * 64,
    }
    observed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    attested = attest_failure_domain(
        production_facts=host_facts(
            "production", "vm-240", "volume-d", str(config.vm.root)
        ),
        recovery_facts=host_facts(
            "recovery", "developer", "volume-r",
            str(config.recovery.recovery_root.resolve()),
        ),
        independence_probe=probe,
        observed_at=observed_at,
    )
    attestation = {**attested.payload, "attestation_sha256": attested.sha256}
    config.recovery.attestation_path.write_bytes(canonical_bytes(attestation))
    event_path = (
        config.recovery.recovery_root / "evidence" / "cold-materialization"
        / "qualification-1.json"
    )
    event_path.parent.mkdir(parents=True)
    event_path.write_bytes(canonical_bytes(event))
    facts_path = (
        config.recovery.attestation_path.parent
        / "production-host-facts-qualification-1.json"
    )
    facts_path.write_bytes(
        (
            json.dumps(
                attestation["production"],
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    )
    return bundle, report


def decode_ssh(arguments) -> str:
    decoded = base64.b64decode(arguments[-1]).decode("utf-16-le")
    compressed = re.search(r"\$b=\[Convert\]::FromBase64String\('([^']+)'\)", decoded)
    if compressed is not None:
        return gzip.decompress(base64.b64decode(compressed.group(1))).decode("utf-8")
    return decoded


def run_powershell(script: str) -> subprocess.CompletedProcess[str]:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return subprocess.run(
        [
            "powershell.exe", "-NoProfile", "-NonInteractive",
            "-EncodedCommand", encoded,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


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


class QualificationResetRunner:
    def __init__(
        self, *, fail_first_apply_after_delete: bool = False,
        omit_service_gate: bool = False,
        partial_response_loss: bool = False,
    ) -> None:
        self.calls = []
        self.fail_first_apply_after_delete = fail_first_apply_after_delete
        self.omit_service_gate = omit_service_gate
        self.partial_response_loss = partial_response_loss
        self.root_empty = False
        self.remaining_children = list(TOP_LEVEL_CHILDREN)

    def __call__(self, arguments):
        self.calls.append(tuple(arguments))
        script = decode_ssh(arguments)
        intent = re.search(r"\$intentHash='([0-9a-f]{64})';", script)
        assert intent is not None
        result = {
            "intent_nonce_sha256": intent.group(1),
            "legacy_deployment_id": LEGACY_ID,
            "bundle_id": "qualification-1",
            "old_c_v39_healthy": True,
            "service_absent": not self.omit_service_gate,
            "d_execution_absent": True,
            "qualification_reset_materialized": True,
            "never_activated": True,
        }
        if "Remove-Item -LiteralPath $child.FullName" in script:
            was_empty = self.root_empty
            was_partial = len(self.remaining_children) < len(TOP_LEVEL_CHILDREN)
            if self.fail_first_apply_after_delete:
                self.fail_first_apply_after_delete = False
                if self.partial_response_loss:
                    self.remaining_children = self.remaining_children[3:]
                else:
                    self.root_empty = True
                    self.remaining_children = []
                return CommandResult(1, "")
            deleted = len(self.remaining_children)
            self.root_empty = True
            self.remaining_children = []
            return CommandResult(
                0,
                json.dumps(
                    {
                        **result,
                        "schema_version": (
                            "qrh-prepare-empty-qualification-reset-application/v1"
                        ),
                        "status": "prepared_empty_root",
                        "pre_delete_inventory_sha256": INVENTORY_HASH,
                        "remaining_pre_delete_inventory_sha256": (
                            hashlib.sha256(b"partial").hexdigest()
                            if was_partial else INVENTORY_HASH
                        ),
                        "deleted_child_count": 0 if was_empty else deleted,
                        "remaining_child_count": 0,
                        "root_exists": True,
                        "root_empty": True,
                        "response_recovered": was_empty or was_partial,
                    }
                ),
            )
        return CommandResult(
            0,
            json.dumps(
                {
                    **result,
                    "schema_version": (
                        "qrh-prepare-empty-qualification-reset-inspection/v1"
                    ),
                    "status": "inspected_not_deleted",
                    "inventory_sha256": INVENTORY_HASH,
                    "file_count": 1328,
                    "directory_count": 200,
                    "total_bytes": 1000000,
                    "top_level_count": len(TOP_LEVEL_CHILDREN),
                    "top_level_children": TOP_LEVEL_CHILDREN,
                    "deleted": False,
                }
            ),
        )


class InterruptedTransferRunner:
    """Model the remote states exercised by the generated fail-closed script."""

    def __init__(self, event: dict[str, object]) -> None:
        self.calls = []
        self.event = event
        self.partial_exists = False
        self.fail_first_scp = True

    def __call__(self, arguments):
        self.calls.append(tuple(arguments))
        if arguments[0] == "scp":
            if self.fail_first_scp:
                self.fail_first_scp = False
                self.partial_exists = True
                return CommandResult(1, "")
            self.partial_exists = False
            return CommandResult(0, "")
        script = decode_ssh(arguments)
        if "retry_unknown_root_child" in script:
            if self.partial_exists:
                # The real script permits only the exact recovery-import shape,
                # validates it, removes that exact child, and keeps its marker.
                for required in (
                    "Assert-LegacyV39",
                    "retry_d_authority_or_release_exists",
                    "retry_unknown_root_child",
                    "retry_unknown_tmp_child",
                    "retry_unknown_import_child",
                    "retry_partial_reparse",
                    "retry_partial_alternate_stream",
                    "retry_bundle_identity_mismatch",
                    "retry_delete_target_not_exact_child",
                ):
                    if required not in script:
                        return CommandResult(1, "")
            return CommandResult(
                0,
                '{"status":"prepared_empty_root","empty_root_precondition":true}',
            )
        return CommandResult(0, json.dumps(self.event))


class ColdRestorePrepareEmptyTests(unittest.TestCase):
    def setUp(self) -> None:
        authority = patch(
            "quant_hub.ops.cold_restore_cli.require_failure_domain_authority",
            return_value=None,
        )
        authority.start()
        self.addCleanup(authority.stop)
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
                    "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "-",
                ],
                input=(
                    f"[scriptblock]::Create([Text.Encoding]::Unicode.GetString("
                    f"[Convert]::FromBase64String('{encoded}'))) | Out-Null\n"
                ),
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
            self.assertNotIn("New-Item -ItemType Directory -Force -LiteralPath", script)
            if "prepared_empty_root" in script:
                return CommandResult(0, '{"status":"prepared_empty_root","empty_root_precondition":true}')
            self.assertIn("transfer_attempt_marker_differs", script)
            self.assertLess(
                script.index("materialization_identity_failed"),
                script.index("Remove-Item -LiteralPath $marker"),
            )
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

    def test_interrupted_scp_partial_is_safely_reset_then_retry_succeeds(self) -> None:
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
        runner = InterruptedTransferRunner(event)
        operator = OpenSSHColdRestore(
            self.config, command_runner=runner, bundle_verifier=self.verifier
        )
        output = (
            self.config.recovery.recovery_root / "evidence" /
            "cold-materialization" / "retry.json"
        )
        with self.assertRaisesRegex(ColdRestoreCLIError, "transfer"):
            operator.restore(self.bundle, evidence_output=output)
        self.assertTrue(runner.partial_exists)
        self.assertFalse(output.exists())

        result = operator.restore(self.bundle, evidence_output=output)
        self.assertEqual("cold_recovery_materialized", result["status"])
        self.assertFalse(runner.partial_exists)
        self.assertTrue(output.is_file())
        scp_calls = [call for call in runner.calls if call[0] == "scp"]
        self.assertEqual(2, len(scp_calls))
        prepare_scripts = [
            decode_ssh(call) for call in runner.calls
            if call[0] == "ssh" and "retry_unknown_root_child" in decode_ssh(call)
        ]
        self.assertEqual(2, len(prepare_scripts))
        retry_script = prepare_scripts[-1]
        self.assertIn(LEGACY_ID, retry_script)
        self.assertIn("$legacyPrefix=([char]67)+':\\quant_platform\\'", retry_script)
        self.assertIn("Remove-Item -LiteralPath $partial.FullName", retry_script)
        self.assertNotIn("Remove-Item -LiteralPath $root", retry_script)
        self.assertNotIn("Remove-Item -LiteralPath $top[0]", retry_script)

    def test_retry_unknown_reparse_and_identity_mismatch_fail_before_scp(self) -> None:
        for token in (
            "retry_unknown_root_child",
            "retry_partial_reparse",
            "retry_bundle_identity_mismatch",
        ):
            with self.subTest(token=token):
                calls = []

                def runner(arguments, expected=token):
                    calls.append(tuple(arguments))
                    self.assertEqual("ssh", arguments[0])
                    self.assertIn(expected, decode_ssh(arguments))
                    return CommandResult(1, "")

                operator = OpenSSHColdRestore(
                    self.config, command_runner=runner, bundle_verifier=self.verifier
                )
                output = (
                    self.config.recovery.recovery_root / "evidence" /
                    "cold-materialization" / f"{token}.json"
                )
                with self.assertRaises(ColdRestoreCLIError):
                    operator.restore(self.bundle, evidence_output=output)
                self.assertEqual(1, len(calls))
                self.assertFalse(output.exists())

    def test_retry_prepare_script_parses_and_delete_is_exact_child_only(self) -> None:
        operator = OpenSSHColdRestore(self.config, bundle_verifier=self.verifier)
        marker, files, directories, total_bytes = operator._transfer_attempt(
            self.bundle, self.report
        )
        import_parent = self.config.vm.root / "tmp" / "recovery-import"
        script = operator._restore_transfer_prepare_script(
            remote_bundle=import_parent / self.bundle.name,
            import_parent=import_parent,
            marker_bytes=marker,
            maximum_files=files,
            maximum_directories=directories,
            maximum_bytes=total_bytes,
        )
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

        self.assertGreaterEqual(script.count("root_parent_reparse"), 2)
        self.assertIn("retry_partial_exceeds_verified_bounds", script)
        self.assertIn("retry_partial_alternate_stream", script)
        self.assertIn("retry_marker_alternate_stream", script)
        self.assertIn("$relative -split '\\\\'", script)
        self.assertIn("if(-not $hasMarker){Assert-LegacyV39}", script)
        self.assertNotIn("else{Assert-LegacyV39", script)
        self.assertIn("if($item.PSIsContainer){if($streams.Count-ne 0)", script)
        self.assertIn("Remove-Item -LiteralPath $partial.FullName", script)
        self.assertNotIn("Remove-Item -LiteralPath $root", script)
        self.assertNotIn("D:\\quant' -Recurse", script)
        self.assertNotIn("C:\\quant_platform' -Recurse", script)

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


class ColdRestoreMaterializedQualificationResetTests(unittest.TestCase):
    def setUp(self) -> None:
        authority = patch(
            "quant_hub.ops.cold_restore_cli.require_failure_domain_authority",
            return_value=None,
        )
        authority.start()
        self.addCleanup(authority.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config = runtime_config(self.root)
        self.bundle, self.report = materialized_qualification_bundle(self.config)
        self.verifier = lambda _path: self.report

    def operator(self, runner=None) -> OpenSSHColdRestore:
        return OpenSSHColdRestore(
            self.config,
            command_runner=runner or QualificationResetRunner(),
            bundle_verifier=self.verifier,
        )

    def test_explicit_materialized_reset_inspects_then_deletes_exact_children(self) -> None:
        runner = QualificationResetRunner()
        operator = self.operator(runner)
        nonce = "materialized-reset-qualification-0001"
        inspected = operator.inspect_prepare_empty(
            self.bundle,
            intent_nonce=nonce,
            expected_legacy_deployment_id=LEGACY_ID,
            qualification_reset_materialized=True,
        )
        self.assertTrue(inspected["qualification_reset_materialized"])
        self.assertEqual(INVENTORY_HASH, inspected["pre_delete_inventory_sha256"])
        inspect_script = decode_ssh(runner.calls[0])
        self.assertLessEqual(
            len(
                "powershell.exe -NoProfile -NonInteractive -EncodedCommand "
                + runner.calls[0][-1]
            ),
            30000,
        )
        outer = base64.b64decode(runner.calls[0][-1]).decode("utf-16-le")
        self.assertIn("gz_l", outer)
        self.assertIn("gz_h", outer)
        self.assertNotIn("Remove-Item -LiteralPath $child.FullName", inspect_script)
        for gate in (
            "qualification_service_exists",
            "qualification_d_process_exists",
            "qualification_d_listener_exists",
            "qualification_inventory_reparse",
            "qualification_inventory_alternate_stream",
            "qualification_expected_file_differs",
            "materialization_event_bytes",
            "production_host_facts_relative_path",
            "production_host_facts_file_sha256",
            "qualification_candidate_audit_count",
            "qualification_candidate_audit_declared_set",
            "qualification_candidate_audit_write_shape",
            "qualification_candidate_audit_residue_unbound",
            "qualification_candidate_sidecar_wal_nonzero",
            "qualification_candidate_sidecar_shm_shape",
            "qualification_unknown_file",
            "qualification_unknown_directory",
            "control/active_release.json",
            "release_manifest.json",
            "operational_bootstrap.json",
        ):
            self.assertIn(gate, inspect_script)
        self.assertGreaterEqual(inspect_script.count("Assert-NoDExecution"), 3)
        self.assertGreaterEqual(inspect_script.count("Assert-LegacyV39"), 3)
        self.assertGreaterEqual(inspect_script.count("Assert-QualificationSnapshot"), 3)
        self.assertLess(
            inspect_script.index(
                "Assert-QrhClosedSnapshot $snapshot $expectedFiles $expectedDirectories"
            ),
            inspect_script.index(
                "$canonicalAudit=Invoke-QualificationAuditProbe $auditRelative"
            ),
        )

        applied = operator.apply_prepare_empty(
            self.bundle,
            intent_nonce=nonce,
            expected_pre_delete_inventory_sha256=INVENTORY_HASH,
            expected_legacy_deployment_id=LEGACY_ID,
            qualification_reset_materialized=True,
        )
        self.assertEqual("prepared_empty_root", applied["status"])
        self.assertFalse(applied["response_recovered"])
        apply_script = decode_ssh(runner.calls[1])
        self.assertIn("qualification_pre_delete_inventory_differs", apply_script)
        self.assertIn(
            "qualification_pre_delete_inventory_changed_after_child_preflight",
            apply_script,
        )
        self.assertIn("Remove-Item -LiteralPath $child.FullName", apply_script)
        self.assertNotIn("Remove-Item -LiteralPath $root", apply_script)
        self.assertNotIn("C:\\quant_platform' -Recurse", apply_script)
        self.assertNotIn("Invoke-QualificationAuditProbe", apply_script)
        self.assertNotIn("$probeSource", apply_script)
        self.assertLess(
            apply_script.index("qualification_pre_delete_inventory_changed"),
            apply_script.index("Remove-Item -LiteralPath $child.FullName"),
        )
        evidence = (
            self.config.recovery.recovery_root / "evidence"
            / "prepare-empty-qualification-reset"
        )
        self.assertEqual(3, len(list(evidence.glob("*.json"))))
        names = {path.name for path in evidence.glob("*.json")}
        self.assertTrue(any(name.endswith(".inspection.json") for name in names))
        self.assertTrue(any(name.endswith(".apply-intent.json") for name in names))
        self.assertTrue(any(name.endswith(".applied.json") for name in names))
        self.assertFalse(any("activation" in name or "recovery" in name for name in names))
        attestation_file_sha256 = hashlib.sha256(
            self.config.recovery.attestation_path.read_bytes()
        ).hexdigest()
        for path in evidence.glob("*.json"):
            with self.subTest(evidence=path.name):
                value = json.loads(path.read_bytes())
                self.assertEqual(
                    attestation_file_sha256,
                    value["failure_domain_attestation_file_sha256"],
                )
                self.assertEqual(105288, value["legacy_python_bytes"])
                self.assertEqual(
                    "187c79755d766743dd778487a796b354597c18a676888168fb75f09eba9539b0",
                    value["legacy_python_path_sha256"],
                )
                self.assertEqual(
                    "f3c05e11e9fc3fc0941fda221b1dfb0aac39d6ef298078054a5d949d620f3d6c",
                    value["legacy_python_sha256"],
                )

    def test_response_loss_reuses_exact_intent_and_recovers_empty_postcondition(self) -> None:
        runner = QualificationResetRunner(fail_first_apply_after_delete=True)
        operator = self.operator(runner)
        nonce = "materialized-reset-response-loss-0001"
        operator.inspect_prepare_empty(
            self.bundle,
            intent_nonce=nonce,
            expected_legacy_deployment_id=LEGACY_ID,
            qualification_reset_materialized=True,
        )
        with self.assertRaises(ColdRestoreCLIError):
            operator.apply_prepare_empty(
                self.bundle,
                intent_nonce=nonce,
                expected_pre_delete_inventory_sha256=INVENTORY_HASH,
                expected_legacy_deployment_id=LEGACY_ID,
                qualification_reset_materialized=True,
            )
        evidence = (
            self.config.recovery.recovery_root / "evidence"
            / "prepare-empty-qualification-reset"
        )
        intent = next(evidence.glob("*.apply-intent.json"))
        intent_hash = hashlib.sha256(intent.read_bytes()).hexdigest()
        self.assertEqual([], list(evidence.glob("*.applied.json")))
        recovered = operator.apply_prepare_empty(
            self.bundle,
            intent_nonce=nonce,
            expected_pre_delete_inventory_sha256=INVENTORY_HASH,
            expected_legacy_deployment_id=LEGACY_ID,
            qualification_reset_materialized=True,
        )
        self.assertTrue(recovered["response_recovered"])
        self.assertEqual(intent_hash, hashlib.sha256(intent.read_bytes()).hexdigest())
        self.assertEqual(1, len(list(evidence.glob("*.apply-intent.json"))))
        self.assertEqual(1, len(list(evidence.glob("*.applied.json"))))

    def test_response_loss_after_whole_child_deletes_replays_exact_remaining_subset(self) -> None:
        runner = QualificationResetRunner(
            fail_first_apply_after_delete=True,
            partial_response_loss=True,
        )
        operator = self.operator(runner)
        nonce = "materialized-reset-partial-response-loss-0001"
        operator.inspect_prepare_empty(
            self.bundle,
            intent_nonce=nonce,
            expected_legacy_deployment_id=LEGACY_ID,
            qualification_reset_materialized=True,
        )
        with self.assertRaises(ColdRestoreCLIError):
            operator.apply_prepare_empty(
                self.bundle,
                intent_nonce=nonce,
                expected_pre_delete_inventory_sha256=INVENTORY_HASH,
                expected_legacy_deployment_id=LEGACY_ID,
                qualification_reset_materialized=True,
            )
        result = operator.apply_prepare_empty(
            self.bundle,
            intent_nonce=nonce,
            expected_pre_delete_inventory_sha256=INVENTORY_HASH,
            expected_legacy_deployment_id=LEGACY_ID,
            qualification_reset_materialized=True,
        )
        self.assertTrue(result["response_recovered"])
        retry_script = decode_ssh(runner.calls[-1])
        for gate in (
            "Assert-ReplaySnapshot",
            "qualification_replay_unknown_top_level",
            "qualification_replay_partial_child_changed",
            "qualification_replay_not_partial",
            "remaining_pre_delete_inventory_sha256",
        ):
            self.assertIn(gate, retry_script)

    def test_tampered_inspection_blocks_apply_without_remote_call(self) -> None:
        runner = QualificationResetRunner()
        operator = self.operator(runner)
        nonce = "materialized-reset-tamper-0001"
        operator.inspect_prepare_empty(
            self.bundle,
            intent_nonce=nonce,
            expected_legacy_deployment_id=LEGACY_ID,
            qualification_reset_materialized=True,
        )
        evidence = (
            self.config.recovery.recovery_root / "evidence"
            / "prepare-empty-qualification-reset"
        )
        inspection = next(evidence.glob("*.inspection.json"))
        value = json.loads(inspection.read_text(encoding="utf-8"))
        value["remote_gates"]["never_activated"] = False
        inspection.write_bytes(operator._canonical_bytes(value))
        before = len(runner.calls)
        with self.assertRaisesRegex(ColdRestoreCLIError, "does not authorize"):
            operator.apply_prepare_empty(
                self.bundle,
                intent_nonce=nonce,
                expected_pre_delete_inventory_sha256=INVENTORY_HASH,
                expected_legacy_deployment_id=LEGACY_ID,
                qualification_reset_materialized=True,
            )
        self.assertEqual(before, len(runner.calls))

    def test_tampered_legacy_python_identity_blocks_apply_without_remote(self) -> None:
        mutations = {
            "legacy_python_path_sha256": "0" * 64,
            "legacy_python_bytes": 105289,
            "legacy_python_sha256": "1" * 64,
        }
        for index, (field, replacement) in enumerate(mutations.items()):
            with self.subTest(field=field):
                runner = QualificationResetRunner()
                operator = self.operator(runner)
                nonce = f"materialized-reset-python-id-{index:04d}"
                operator.inspect_prepare_empty(
                    self.bundle,
                    intent_nonce=nonce,
                    expected_legacy_deployment_id=LEGACY_ID,
                    qualification_reset_materialized=True,
                )
                evidence_root = (
                    self.config.recovery.recovery_root / "evidence"
                    / "prepare-empty-qualification-reset"
                )
                nonce_hash = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
                inspection = evidence_root / f"{nonce_hash}.inspection.json"
                value = json.loads(inspection.read_bytes())
                value[field] = replacement
                inspection.write_bytes(operator._canonical_bytes(value))
                before = len(runner.calls)
                with self.assertRaisesRegex(ColdRestoreCLIError, "does not authorize"):
                    operator.apply_prepare_empty(
                        self.bundle,
                        intent_nonce=nonce,
                        expected_pre_delete_inventory_sha256=INVENTORY_HASH,
                        expected_legacy_deployment_id=LEGACY_ID,
                        qualification_reset_materialized=True,
                    )
                self.assertEqual(before, len(runner.calls))

    def test_apply_rereads_attestation_file_and_rejects_equivalent_reformat(self) -> None:
        runner = QualificationResetRunner()
        operator = self.operator(runner)
        nonce = "materialized-reset-attestation-reread-0001"
        operator.inspect_prepare_empty(
            self.bundle,
            intent_nonce=nonce,
            expected_legacy_deployment_id=LEGACY_ID,
            qualification_reset_materialized=True,
        )
        original_contract = operator._qualification_reset_contract

        def contract_then_reformat(*args, **kwargs):
            contract = original_contract(*args, **kwargs)
            path = self.config.recovery.attestation_path
            value = json.loads(path.read_bytes())
            path.write_bytes(
                (
                    json.dumps(
                        dict(reversed(list(value.items()))),
                        ensure_ascii=False,
                        indent=1,
                        sort_keys=False,
                    )
                    + "\n"
                ).encode("utf-8")
            )
            return contract

        operator._qualification_reset_contract = contract_then_reformat  # type: ignore[method-assign]
        before = len(runner.calls)
        with self.assertRaisesRegex(ColdRestoreCLIError, "attestation file"):
            operator.apply_prepare_empty(
                self.bundle,
                intent_nonce=nonce,
                expected_pre_delete_inventory_sha256=INVENTORY_HASH,
                expected_legacy_deployment_id=LEGACY_ID,
                qualification_reset_materialized=True,
            )
        self.assertEqual(before, len(runner.calls))

    def test_remote_service_gate_cannot_be_omitted(self) -> None:
        runner = QualificationResetRunner(omit_service_gate=True)
        with self.assertRaisesRegex(ColdRestoreCLIError, "remote gates"):
            self.operator(runner).inspect_prepare_empty(
                self.bundle,
                intent_nonce="materialized-reset-service-0001",
                expected_legacy_deployment_id=LEGACY_ID,
                qualification_reset_materialized=True,
            )

    def test_materialized_reset_scripts_have_real_powershell_parse(self) -> None:
        operator = self.operator()
        bundle, report, restore_name, _python, _tool = operator._verified_bundle(
            self.bundle
        )
        contract = operator._qualification_reset_contract(
            bundle,
            report,
            restore_name,
            expected_legacy_deployment_id=LEGACY_ID,
        )
        scripts = (
            operator._qualification_reset_script(
                contract=contract,
                intent_nonce_sha256="e" * 64,
                apply=False,
                expected_inventory_sha256=None,
            ),
            operator._qualification_reset_script(
                contract={
                    **contract,
                    "inspected_top_level_children": TOP_LEVEL_CHILDREN,
                },
                intent_nonce_sha256="e" * 64,
                apply=True,
                expected_inventory_sha256=INVENTORY_HASH,
            ),
        )
        self.assertNotIn("Remove-Item", scripts[0])
        self.assertIn(
            "top_level_children=$topChildren.ToArray()",
            scripts[0],
        )
        self.assertIn(
            "'inbox,inbox/research,replay,replay/evidence'.Split(',')",
            scripts[0],
        )
        self.assertIn("$releaseBase+'/runtime/'+$r", scripts[0])
        for script in scripts:
            encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
            completed = subprocess.run(
                [
                    "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "-",
                ],
                input=(
                    f"[scriptblock]::Create([Text.Encoding]::Unicode.GetString("
                    f"[Convert]::FromBase64String('{encoded}'))) | Out-Null\n"
                ),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)

        # Windows PowerShell 5.1 has a binder bug for @($genericList) inside
        # a PSCustomObject literal.  Exercise the exact projection used by the
        # production inventory response so a parse-only test cannot regress
        # back to the runtime ArgumentException.
        projection = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "-"],
            input=(
                "$ErrorActionPreference='Stop';"
                "$items=New-Object 'System.Collections.Generic.List[object]';"
                "[void]$items.Add([pscustomobject]@{name='audit';"
                "inventory_sha256=('0'*64)});"
                "$result=[pscustomobject]@{top_level_children=$items.ToArray()};"
                "@{count=@($result.top_level_children).Count}|"
                "ConvertTo-Json -Compress\n"
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, projection.returncode, projection.stderr)
        self.assertEqual({"count": 1}, json.loads(projection.stdout))

        calls = []
        for script in scripts:
            transport = OpenSSHColdRestore(
                self.config,
                command_runner=lambda arguments: (
                    calls.append(tuple(arguments)) or CommandResult(0, "{}")
                ),
                bundle_verifier=self.verifier,
            )
            self.assertEqual(
                {},
                transport._ssh(
                    script,
                    compressed=True,
                    compact_qualification_wrapper=True,
                ),
            )
            full_command = (
                "powershell.exe -NoProfile -NonInteractive -EncodedCommand "
                + calls[-1][-1]
            )
            self.assertLessEqual(len(full_command), 30000)
            self.assertTrue(decode_ssh(calls[-1]).endswith(script))
        outer_script = base64.b64decode(calls[-1][-1]).decode("utf-16-le")
        encoded_outer = base64.b64encode(
            outer_script.encode("utf-16-le")
        ).decode("ascii")
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "-"],
            input=(
                f"[scriptblock]::Create([Text.Encoding]::Unicode.GetString("
                f"[Convert]::FromBase64String('{encoded_outer}'))) | Out-Null\n"
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)

        # Execute the production gzip length/hash/decompression path, replacing
        # only the final invocation with parse-only behavior so this test cannot
        # inspect or mutate the real D authority.
        parse_only = outer_script.replace(
            "&([scriptblock]::Create($s))",
            "[scriptblock]::Create($s)|Out-Null;"
            "@{status='decompressed_and_parsed'}|ConvertTo-Json -Compress",
        )
        self.assertNotEqual(outer_script, parse_only)
        executed = run_powershell(parse_only)
        self.assertEqual(0, executed.returncode, executed.stderr)
        self.assertEqual(
            {"status": "decompressed_and_parsed"}, json.loads(executed.stdout)
        )

        def local_powershell(arguments):
            environment = os.environ.copy()
            environment["SSH_CONNECTION"] = "127.0.0.1 1 10.5.1.240 22"
            completed = subprocess.run(
                [
                    "powershell.exe", "-NoProfile", "-NonInteractive",
                    "-EncodedCommand", arguments[-1],
                ],
                capture_output=True,
                text=True,
                check=False,
                env=environment,
            )
            return CommandResult(completed.returncode, completed.stdout)

        local_transport = OpenSSHColdRestore(
            self.config,
            command_runner=local_powershell,
            bundle_verifier=self.verifier,
        )
        self.assertEqual(
            {"status": "decompressed"},
            local_transport._ssh(
                "@{status='decompressed'}|ConvertTo-Json -Compress",
                compressed=True,
            ),
        )

    @unittest.skipUnless(os.name == "nt", "Win32 stream API requires Windows")
    def test_real_powershell_native_probe_rejects_root_directory_and_file_ads(self) -> None:
        def probe(root: Path) -> subprocess.CompletedProcess[str]:
            command = (
                "$ErrorActionPreference='Stop';$root="
                + OpenSSHColdRestore._literal(os.fspath(root))
                + ";"
                + _qualification_native_probe_script()
                + "$count=Assert-QrhNoAlternateStreams;"
                + "@{count=$count}|ConvertTo-Json -Compress"
            )
            return subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "-"],
                input=command + "\n",
                capture_output=True,
                text=True,
                check=False,
            )

        for target_kind in ("root", "directory", "file"):
            with self.subTest(target_kind=target_kind), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                child = root / "child"
                child.mkdir()
                file = root / "payload.bin"
                file.write_bytes(b"payload")
                self.assertEqual(0, probe(root).returncode)
                target = {"root": root, "directory": child, "file": file}[target_kind]
                create_file = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
                create_file.argtypes = [
                    ctypes.c_wchar_p,
                    ctypes.c_uint32,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                    ctypes.c_uint32,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                ]
                create_file.restype = ctypes.c_void_p
                handle = create_file(
                    os.fspath(target) + ":hidden",
                    0x40000000,
                    0x00000007,
                    None,
                    2,
                    0x80,
                    None,
                )
                self.assertNotEqual(ctypes.c_void_p(-1).value, handle)
                ctypes.WinDLL("kernel32").CloseHandle(ctypes.c_void_p(handle))
                rejected = probe(root)
                self.assertNotEqual(0, rejected.returncode)
                self.assertIn(
                    "qualification_inventory_alternate_stream",
                    rejected.stdout + rejected.stderr,
                )

        # Response-loss replay can begin after any whole top-level child was
        # removed.  The same off-script stream guard must remain executable
        # before tooling deletion, after tooling deletion, and at empty root.
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for name in ("audit", "control", "releases", "state", "tmp", "tooling", "tools"):
                child = root / name
                child.mkdir()
                (child / "identity.bin").write_bytes(name.encode("ascii"))
            self.assertEqual(0, probe(root).returncode)
            shutil.rmtree(root / "tooling")
            self.assertEqual(0, probe(root).returncode)
            for child in tuple(root.iterdir()):
                shutil.rmtree(child)
            empty = probe(root)
            self.assertEqual(0, empty.returncode, empty.stderr)
            self.assertEqual({"count": 1}, json.loads(empty.stdout))

    @unittest.skipUnless(os.name == "nt", "qualification native guard requires Windows")
    def test_real_powershell_process_identity_and_d_path_aliases(self) -> None:
        root = Path(__file__).resolve().parents[2]
        forward_root = os.fspath(root).replace("\\", "/")
        native = _qualification_native_probe_script()
        server = r"C:\quant_platform\tools\viewer\server.py"
        good = rf'"C:\quant_platform\python\python.exe" -I "{server}"'
        windows = rf'"C:\Windows\python.exe" -I "{server}"'
        substring = (
            rf'"C:\quant_platform\python\python.exe" -I '
            rf'"C:\elsewhere\server.py" "{server}"'
        )
        command = (
            "$ErrorActionPreference='Stop';$root="
            + OpenSSHColdRestore._literal(os.fspath(root))
            + ";"
            + native
            + "$server=" + OpenSSHColdRestore._literal(server) + ";"
            + "$good=" + OpenSSHColdRestore._literal(good) + ";"
            + "$windows=" + OpenSSHColdRestore._literal(windows) + ";"
            + "$substring=" + OpenSSHColdRestore._literal(substring) + ";"
            + "$short=[string]$qrhRootVariants[-1];"
            + "[ordered]@{good=(Test-QrhExactLegacyArgv $good "
            + "'C:\\quant_platform\\python\\python.exe' $server);"
            + "windows=(Test-QrhExactLegacyArgv $windows "
            + "'C:\\Windows\\python.exe' $server);"
            + "substring=(Test-QrhExactLegacyArgv $substring "
            + "'C:\\quant_platform\\python\\python.exe' $server);"
            + "forward=(Test-QrhContainsDRoot "
            + OpenSSHColdRestore._literal(f'python "{forward_root}/app.py"')
            + ");"
            + "extended=(Test-QrhContainsDRoot ('python \\\\?\\'+$root+'\\app.py'));"
            + "short=(Test-QrhContainsDRoot ('python '+$short+'\\app.py'));"
            + "sibling=(Test-QrhContainsDRoot "
            + OpenSSHColdRestore._literal(f'python "{forward_root}_evil/app.py"')
            + ");"
            + "prefix=(Test-QrhContainsDRoot "
            + OpenSSHColdRestore._literal(f'python "X{forward_root}/app.py"')
            + ");"
            + "short_path=$short}|ConvertTo-Json -Compress"
        )
        completed = run_powershell(command)
        self.assertEqual(0, completed.returncode, completed.stderr)
        value = json.loads(completed.stdout)
        self.assertTrue(value["good"])
        # This helper closes argv shape only; the full guard below binds the
        # opaque path hash and binary identity, so an arbitrary matching argv
        # cannot pass production qualification.
        self.assertTrue(value["windows"])
        self.assertFalse(value["substring"])
        self.assertTrue(value["forward"])
        self.assertTrue(value["extended"])
        self.assertTrue(value["short"])
        self.assertFalse(value["sibling"])
        self.assertFalse(value["prefix"])
        self.assertTrue(value["short_path"])

    @unittest.skipUnless(os.name == "nt", "qualification guard requires Windows")
    def test_real_powershell_full_no_d_execution_guard_normalizes_forward_slash(self) -> None:
        root = Path(__file__).resolve().parents[2]
        forward_root = os.fspath(root).replace("\\", "/")

        def invoke(command_line: str) -> dict:
            script = (
                "$ErrorActionPreference='Stop';$root="
                + OpenSSHColdRestore._literal(os.fspath(root))
                + ";"
                + _qualification_native_probe_script()
                + "$caseCommand=" + OpenSSHColdRestore._literal(command_line) + ";"
                + "function Get-Service{@()};"
                + "function Get-CimInstance{@([pscustomobject]@{ProcessId=42;"
                + "ExecutablePath='C:\\Windows\\python.exe';"
                + "CommandLine=$caseCommand})};"
                + "function Get-NetTCPConnection{@()};"
                + _qualification_no_d_execution_guard_script()
                + "try{Assert-NoDExecution;$result=@{passed=$true;error=$null}}"
                + "catch{$result=@{passed=$false;error=$_.Exception.Message}};"
                + "$result|ConvertTo-Json -Compress"
            )
            completed = run_powershell(script)
            self.assertEqual(0, completed.returncode, completed.stderr)
            return json.loads(completed.stdout)

        rejected = invoke(f'python "{forward_root}/tooling/task.py"')
        self.assertFalse(rejected["passed"])
        self.assertEqual("qualification_d_process_exists", rejected["error"])
        self.assertTrue(
            invoke(f'python "{forward_root}_sibling/tooling/task.py"')["passed"]
        )

    @unittest.skipUnless(os.name == "nt", "qualification guard requires Windows")
    def test_real_powershell_full_legacy_guard_rejects_c_windows_python(self) -> None:
        root = Path(__file__).resolve().parents[2]

        def invoke(
            executable: str,
            *,
            expected_executable: str,
            observed_python_sha256: str = "b" * 64,
        ) -> subprocess.CompletedProcess[str]:
            server = r"C:\quant_platform\tools\viewer\server.py"
            command_line = f'"{executable}" -I "{server}"'
            expected_path_sha256 = hashlib.sha256(
                expected_executable.lower().encode("utf-8")
            ).hexdigest()
            deployment = json.dumps(
                {
                    "schema_version": "qrh-company-broadcast-health/v1",
                    "status": "ok",
                    "deployment_id": LEGACY_ID,
                    "pid": 42,
                    "port": 8765,
                },
                separators=(",", ":"),
            )
            script = (
                "$ErrorActionPreference='Stop';$root="
                + OpenSSHColdRestore._literal(os.fspath(root))
                + ";"
                + _qualification_native_probe_script()
                + "$contract=[pscustomobject]@{legacy_server_bytes=32;"
                + "legacy_server_sha256='" + "a" * 64 + "';"
                + "python_id=@('" + expected_path_sha256 + "',100,'"
                + "b" * 64 + "');"
                + "legacy_deployment_id=" + OpenSSHColdRestore._literal(LEGACY_ID) + "};"
                + "$caseExecutable=" + OpenSSHColdRestore._literal(executable) + ";"
                + "$caseCommand=" + OpenSSHColdRestore._literal(command_line) + ";"
                + "function Get-NetTCPConnection{[pscustomobject]@{OwningProcess=42}};"
                + "function Get-CimInstance{[pscustomobject]@{ProcessId=42;"
                + "ExecutablePath=$caseExecutable;CommandLine=$caseCommand}};"
                + "function Get-Item{param($LiteralPath,[switch]$Force,$ErrorAction);"
                + "[pscustomobject]@{PSIsContainer=$false;Attributes=0;Length="
                + "$(if($LiteralPath-eq$caseExecutable){100}else{32})}};"
                + "function Get-FileHash{param($LiteralPath,$Algorithm);"
                + "[pscustomobject]@{Hash=$(if($LiteralPath-eq$caseExecutable){'"
                + observed_python_sha256 + "'}else{'" + "a" * 64 + "'})}};"
                + "function Invoke-WebRequest{[pscustomobject]@{StatusCode=200;Content="
                + OpenSSHColdRestore._literal(deployment)
                + "}};"
                + _qualification_legacy_guard_script()
                + "try{Assert-LegacyV39;$result=@{passed=$true;error=$null}}"
                + "catch{$result=@{passed=$false;error=$_.Exception.Message}};"
                + "$result|ConvertTo-Json -Compress"
            )
            return run_powershell(script)

        fixed = r"C:\opaque\fixed\python.exe"
        valid = invoke(fixed, expected_executable=fixed)
        self.assertEqual(0, valid.returncode, valid.stderr)
        self.assertTrue(json.loads(valid.stdout)["passed"])
        cases = (
            (r"C:\Windows\python.exe", "b" * 64),
            (r"D:\quant\quant_platform\tooling\python\python.exe", "b" * 64),
            (r"C:\opaque\sibling\python.exe", "b" * 64),
            (fixed, "c" * 64),
        )
        for executable, observed_hash in cases:
            with self.subTest(executable=executable, observed_hash=observed_hash[:1]):
                rejected = invoke(
                    executable,
                    expected_executable=fixed,
                    observed_python_sha256=observed_hash,
                )
                self.assertEqual(0, rejected.returncode, rejected.stderr)
                value = json.loads(rejected.stdout)
                self.assertFalse(value["passed"])
                self.assertEqual("listener_legacy_authority_differs", value["error"])

    @unittest.skipUnless(os.name == "nt", "qualification guard requires Windows")
    def test_real_powershell_replay_accepts_only_exact_remaining_top_children(self) -> None:
        contract_json = json.dumps(
            {"inspected_top_level_children": TOP_LEVEL_CHILDREN}, separators=(",", ":")
        )

        def check(children) -> dict:
            snapshot_json = json.dumps(
                {"top_level_children": children}, separators=(",", ":")
            )
            completed = run_powershell(
                "$ErrorActionPreference='Stop';$contract="
                + OpenSSHColdRestore._literal(contract_json)
                + "|ConvertFrom-Json;$snapshot="
                + OpenSSHColdRestore._literal(snapshot_json)
                + "|ConvertFrom-Json;"
                + _qualification_replay_guard_script()
                + "try{Assert-ReplaySnapshot $snapshot;"
                + "$result=@{passed=$true;error=$null}}"
                + "catch{$result=@{passed=$false;error=$_.Exception.Message}};"
                + "$result|ConvertTo-Json -Compress"
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            return json.loads(completed.stdout)

        cuts = (
            [item for item in TOP_LEVEL_CHILDREN if item["name"] != "tooling"],
            [item for item in TOP_LEVEL_CHILDREN if item["name"] == "tools"],
            [],
        )
        for children in cuts:
            with self.subTest(children=[item["name"] for item in children]):
                self.assertTrue(check(children)["passed"])
        changed = [dict(TOP_LEVEL_CHILDREN[0], inventory_sha256="0" * 64)]
        rejected = check(changed)
        self.assertFalse(rejected["passed"])
        self.assertEqual("qualification_replay_partial_child_changed", rejected["error"])

    @unittest.skipUnless(os.name == "nt", "qualification guard requires Windows")
    def test_dependency_tamper_is_rejected_before_tooling_python_executes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            python = root / "tooling" / "python" / "python.exe"
            python.parent.mkdir(parents=True)
            shutil.copy2(os.sys.executable, python)
            marker = root / "executed.marker"
            source = (
                "from pathlib import Path;Path("
                + repr(os.fspath(marker))
                + ").write_bytes(b'executed')"
            )
            script = (
                "$ErrorActionPreference='Stop';"
                + _qualification_closure_guard_script()
                + "$expectedFiles=New-Object 'System.Collections.Generic.HashSet[string]' "
                + "([StringComparer]::Ordinal);"
                + "[void]$expectedFiles.Add('tooling/python/python.exe');"
                + "$expectedDirectories=New-Object "
                + "'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal);"
                + "[void]$expectedDirectories.Add('tooling');"
                + "[void]$expectedDirectories.Add('tooling/python');"
                + "$snapshot=[pscustomobject]@{files=@{"
                + "'tooling/python/python.exe'=$null;"
                + "'tooling/python/tampered.dll'=$null};"
                + "directories=@('tooling','tooling/python')};$executed=$false;"
                + "try{Assert-QrhClosedSnapshot $snapshot $expectedFiles $expectedDirectories;"
                + "$executed=$true;&"
                + OpenSSHColdRestore._literal(os.fspath(python))
                + " -I -B -c "
                + OpenSSHColdRestore._literal(source)
                + "}catch{$failure=$_.Exception.Message};"
                + "@{executed=$executed;failure=$failure}|ConvertTo-Json -Compress"
            )
            completed = run_powershell(script)
            self.assertEqual(0, completed.returncode, completed.stderr)
            value = json.loads(completed.stdout)
            self.assertFalse(value["executed"])
            self.assertEqual("qualification_unknown_file", value["failure"])
            self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "nt", "qualification audit probe requires Windows")
    def test_real_powershell_audit_probe_rejects_singleton_array_scalar(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            audit = root / "audit.json"
            value = {
                "schema_version": "qrh-production-vm-write-audit/v1",
                "operation": ["deploy-candidate_only"],
                "authority_root": r"D:\quant\quant_platform",
                "verdict": "pass",
                "audit_id": "vm-write-audit-" + "a" * 32,
                "outcome": "failed",
                "audit_record_path": r"D:\quant\quant_platform\audit.json",
                "declared_write_set": {},
                "observed_writes": [],
            }
            audit.write_bytes(
                (
                    json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
                    + "\n"
                ).encode("utf-8")
            )
            script = (
                "$ErrorActionPreference='Continue';$probeSource="
                + OpenSSHColdRestore._literal(_CANONICAL_AUDIT_PROBE)
                + ";$probeEncoded=[Convert]::ToBase64String("
                + "[Text.Encoding]::UTF8.GetBytes($probeSource));"
                + "$bootstrap=\"import base64,sys;exec(compile(base64.b64decode("
                + "sys.argv.pop(1)),'<probe>','exec'))\";$raw=&"
                + OpenSSHColdRestore._literal(os.fspath(Path(os.sys.executable)))
                + " -I -B -c $bootstrap $probeEncoded "
                + OpenSSHColdRestore._literal(os.fspath(root))
                + " "
                + OpenSSHColdRestore._literal(os.fspath(audit))
                + " 2>&1;$exit=$LASTEXITCODE;"
                + "@{exit=$exit;output=[string]($raw-join ' ')}|ConvertTo-Json -Compress"
            )
            completed = run_powershell(script)
            self.assertEqual(0, completed.returncode, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertNotEqual(0, result["exit"])
            self.assertIn("qualification_candidate_audit_scalar_type", result["output"])

    def test_legacy_identity_mismatch_is_rejected_before_remote(self) -> None:
        calls = []
        operator = OpenSSHColdRestore(
            self.config,
            command_runner=lambda arguments: (
                calls.append(tuple(arguments)) or CommandResult(0, "{}")
            ),
            bundle_verifier=self.verifier,
        )
        with self.assertRaisesRegex(ColdRestoreCLIError, "exact legacy V39"):
            operator.inspect_prepare_empty(
                self.bundle,
                intent_nonce="materialized-reset-wrong-v39-0001",
                expected_legacy_deployment_id="wrong-v39",
                qualification_reset_materialized=True,
            )
        self.assertEqual([], calls)

    def test_contract_rejects_semantic_equivalent_or_identity_tamper(self) -> None:
        operator = self.operator()
        bundle, report, restore_name, _python, _tool = operator._verified_bundle(
            self.bundle
        )
        targets = {
            "closure": bundle / "closure_inventory.json",
            "recovery": bundle / "recovery_manifest.json",
            "event": (
                self.config.recovery.recovery_root / "evidence"
                / "cold-materialization" / "qualification-1.json"
            ),
            "facts": (
                self.config.recovery.attestation_path.parent
                / "production-host-facts-qualification-1.json"
            ),
            "attestation": self.config.recovery.attestation_path,
        }
        originals = {name: path.read_bytes() for name, path in targets.items()}
        mutations = {
            "closure": originals["closure"] + b" ",
            "recovery": originals["recovery"] + b" ",
            "event": (
                json.dumps(
                    json.loads(originals["event"]),
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8"),
            "facts": canonical_bytes(json.loads(originals["facts"])),
            "attestation": (
                json.dumps(
                    dict(reversed(list(json.loads(originals["attestation"]).items()))),
                    ensure_ascii=False,
                    indent=1,
                    sort_keys=False,
                )
                + "\n"
            ).encode("utf-8"),
        }
        for name, path in targets.items():
            with self.subTest(name=name):
                path.write_bytes(mutations[name])
                try:
                    with self.assertRaises(ColdRestoreCLIError):
                        operator._qualification_reset_contract(
                            bundle,
                            report,
                            restore_name,
                            expected_legacy_deployment_id=LEGACY_ID,
                        )
                finally:
                    path.write_bytes(originals[name])

    @unittest.skipUnless(os.name == "nt", "legacy event profile requires PS 5.1")
    def test_legacy_materialization_profile_matches_real_powershell_exact_bytes(self) -> None:
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
        expected = _legacy_materialization_event_bytes(event)
        script = (
            "$e=@{schema_version='qrh-recovery-materialization-event/v1';"
            "event_id='cold-materialization-qualification-1';"
            "kind='cold_recovery_materialized';authority='evidence_only';fields=@{"
            "bundle_id='qualification-1';release_id='release-v39';"
            "manifest_sha256='" + "a" * 64 + "';empty_root_precondition=$true;"
            "import_cleaned=$true;runtime_tmp_cleaned=$true}};"
            "$j=$e|ConvertTo-Json -Compress -Depth 4;"
            "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))"
        )
        completed = run_powershell(script)
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(expected, base64.b64decode(completed.stdout.strip()))
        self.assertNotEqual(canonical_bytes(event), expected)
        reordered = json.dumps(
            event, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        whitespace = json.dumps(event, ensure_ascii=False, indent=1).encode("utf-8")
        self.assertNotEqual(expected, reordered)
        self.assertNotEqual(expected, whitespace)

        operator = self.operator()
        bundle, report, restore_name, _python, _tool = operator._verified_bundle(
            self.bundle
        )
        contract = operator._qualification_reset_contract(
            bundle, report, restore_name,
            expected_legacy_deployment_id=LEGACY_ID,
        )
        self.assertEqual(
            "audit/evidence/production-host-facts-qualification-1.json",
            contract["production_host_facts_relative_path"],
        )
        self.assertEqual(
            hashlib.sha256(
                _legacy_materialization_event_bytes({
                    **event,
                    "fields": {
                        **event["fields"],
                        "manifest_sha256": report.release_manifest_sha256,
                    },
                })
            ).hexdigest(),
            contract["materialization_event_remote_sha256"],
        )
        self.assertEqual(
            "legacy_powershell_hashtable_v1",
            contract["materialization_event_remote_serialization"],
        )
        self.assertEqual(105288, contract["legacy_python_bytes"])
        self.assertEqual(
            "187c79755d766743dd778487a796b354597c18a676888168fb75f09eba9539b0",
            contract["legacy_python_path_sha256"],
        )
        self.assertEqual(
            "f3c05e11e9fc3fc0941fda221b1dfb0aac39d6ef298078054a5d949d620f3d6c",
            contract["legacy_python_sha256"],
        )

    @unittest.skipUnless(os.name == "nt", "candidate residue guard requires PS 5.1")
    def test_real_powershell_candidate_residue_guard_closes_real_shape(self) -> None:
        sidecars = {
            "state/comments.sqlite3-wal": {"bytes": 0, "sha256": "0" * 64},
            "state/comments.sqlite3-shm": {"bytes": 32768, "sha256": "1" * 64},
            "state/research_workspace.sqlite3-wal": {
                "bytes": 0, "sha256": "2" * 64,
            },
            "state/research_workspace.sqlite3-shm": {
                "bytes": 32768, "sha256": "3" * 64,
            },
        }
        directory_changes = {
            "audit": "modified", "audit/receipts": "created",
            "backups": "created", "incoming": "created", "state": "modified",
            "state/locks": "created", "tmp": "modified",
            "tmp/candidate-probes": "created",
        }
        writes = [
            {
                "bytes": 0, "change": change, "entry_type": "directory",
                "path": str(PureWindowsPath(r"D:\quant\quant_platform").joinpath(
                    *relative.split("/")
                )),
                "relative_path": relative, "sha256": None,
            }
            for relative, change in directory_changes.items()
        ] + [
            {
                "bytes": value["bytes"], "change": "created", "entry_type": "file",
                "path": str(PureWindowsPath(r"D:\quant\quant_platform").joinpath(
                    *relative.split("/")
                )),
                "relative_path": relative, "sha256": value["sha256"],
            }
            for relative, value in sidecars.items()
        ]
        directories = [*directory_changes, "tmp/deployment-cli"]

        def invoke(observed, dirs, files):
            data = json.dumps(
                {"observed_writes": observed}, separators=(",", ":")
            )
            file_data = json.dumps(files, separators=(",", ":"))
            dir_data = json.dumps(dirs, separators=(",", ":"))
            script = (
                "$ErrorActionPreference='Stop';$root='D:\\quant\\quant_platform';"
                + _qualification_candidate_residue_guard_script()
                + "$audit=" + OpenSSHColdRestore._literal(data) + "|ConvertFrom-Json;"
                + "$rawFiles=" + OpenSSHColdRestore._literal(file_data)
                + "|ConvertFrom-Json;$files=@{};foreach($p in $rawFiles.PSObject.Properties)"
                + "{$files[$p.Name]=$p.Value};$dirs=New-Object "
                + "'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal);"
                + "foreach($d in @((" + OpenSSHColdRestore._literal(dir_data)
                + "|ConvertFrom-Json))){[void]$dirs.Add([string]$d)};"
                + "$expected=New-Object 'System.Collections.Generic.HashSet[string]' "
                + "([StringComparer]::Ordinal);$snapshot=[pscustomobject]@{files=$files;"
                + "directories=$dirs};try{Assert-QrhCandidateResidueAudit $audit "
                + "$snapshot $expected;$result='pass'}catch{$result=$_.Exception.Message};"
                + "$result"
            )
            completed = run_powershell(script)
            self.assertEqual(0, completed.returncode, completed.stderr)
            return completed.stdout.strip()

        self.assertEqual("pass", invoke(writes, directories, sidecars))
        self.assertEqual(
            "qualification_candidate_audit_residue_unbound",
            invoke([item for item in writes if item["relative_path"] != "backups"],
                   directories, sidecars),
        )
        deployment_write = {
            "bytes": 0, "change": "created", "entry_type": "directory",
            "path": r"D:\quant\quant_platform\tmp\deployment-cli",
            "relative_path": "tmp/deployment-cli", "sha256": None,
        }
        self.assertEqual(
            "qualification_candidate_audit_write_shape",
            invoke([*writes, deployment_write], directories, sidecars),
        )
        self.assertEqual(
            "qualification_candidate_directory_not_empty",
            invoke(
                writes, directories,
                {**sidecars, "tmp/deployment-cli/foreign.bin": {
                    "bytes": 1, "sha256": "4" * 64,
                }},
            ),
        )

    def test_script_closes_exact_failed_audit_and_authority_absence(self) -> None:
        operator = self.operator()
        bundle, report, restore_name, _python, _tool = operator._verified_bundle(
            self.bundle
        )
        contract = operator._qualification_reset_contract(
            bundle,
            report,
            restore_name,
            expected_legacy_deployment_id=LEGACY_ID,
        )
        script = operator._qualification_reset_script(
            contract=contract,
            intent_nonce_sha256="f" * 64,
            apply=False,
            expected_inventory_sha256=None,
        )
        for closed_contract in (
            "$writeAudits.Count-ne 1",
            "audit_id,audit_record_path,authority_root,declared_write_set,",
            "bytes,change,entry_type,path,relative_path,sha256",
            "deploy-candidate_only",
            "$audit.outcome-ne'failed'",
            "vm-write-audit-[0-9a-f]{32}",
            "qualification_candidate_audit_residue_unbound",
            "audit/receipts",
            "backups='created'",
            "incoming='created'",
            "state/locks",
            "tmp/deployment-cli",
            "Assert-QrhClosedSnapshot",
        ):
            self.assertIn(closed_contract, script)


if __name__ == "__main__":
    unittest.main()
