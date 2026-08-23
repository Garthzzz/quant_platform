from __future__ import annotations

import base64
from contextlib import redirect_stdout
import hashlib
from io import StringIO
import json
from pathlib import Path, PureWindowsPath
import re
import tempfile
import unittest
from unittest.mock import Mock, patch

from quant_hub.ops.publish_adapters import CommandResult, VMConfig
from quant_hub.ops.release_identity import canonical_manifest_bytes, manifest_sha256
from quant_hub.ops.writer_handoff import (
    V39Baseline,
    WriterHandoffError,
    inspect_writer_handoff_status,
    seed_v39_access_identity,
)
from quant_hub.ops.writer_handoff_client import (
    WriterHandoffClient,
    WriterHandoffClientConfig,
    WriterHandoffClientError,
    WriterHandoffRunError,
    main as writer_handoff_client_main,
)


MANIFEST_HASH = "a" * 64
NONCE_BYTES = bytes.fromhex("12" * 24)
ATTEMPT = "handoff-20260821T040000-abcdef123456"

V39_SERVER_SOURCE = b'''import hashlib
import os
ACCESS_PASSWORD_SALT = bytes.fromhex("ae829f253a022e21e2b53ddd97c712b8")
ACCESS_PASSWORD_ITERATIONS = 600_000
DEFAULT_ACCESS_PASSWORD_DIGEST = bytes.fromhex(
    "6285c59738159eb58889d6402c1b654222cb39c6b01e5afaffa5f5a39624798d"
)
def _access_password_digest() -> bytes:
    configured = os.environ.get("VIEWER_ACCESS_PASSWORD")
    if configured is None:
        return DEFAULT_ACCESS_PASSWORD_DIGEST
    if not configured:
        raise RuntimeError("VIEWER_ACCESS_PASSWORD must not be empty")
    return hashlib.pbkdf2_hmac(
        "sha256",
        configured.encode("utf-8"),
        ACCESS_PASSWORD_SALT,
        ACCESS_PASSWORD_ITERATIONS,
    )
'''


def _seed_release(source: bytes) -> dict[str, object]:
    inventory = {
        "schema_version": "qrh-release-file-inventory/v1",
        "files": [
            {
                "path": "tools/viewer/server.py",
                "bytes": len(source),
                "sha256": hashlib.sha256(source).hexdigest(),
            }
        ],
    }
    return {
        "schema_version": "qrh-release-manifest/v1",
        "release_id": "v39-baseline-20260731-hotfix1",
        "built_at": "2026-07-31T10:04:18Z",
        "application": {
            "commit_sha": "0" * 40,
            "tracked_tree_sha256": "1" * 64,
            "build_tool_version": "writer-handoff-client-tests/v1",
            "source_kind": "legacy_broadcast",
            "legacy_deployment_id": "quant-hub-v39-company-broadcast-20260731-hotfix1",
            "source_archive_sha256": "2" * 64,
            "source_package_manifest_sha256": "3" * 64,
        },
        "content": {
            "snapshot_id": "v39-content-20260731-hotfix1",
            "source_inventory_sha256": "4" * 64,
            "ir_sha256": "5" * 64,
            "knowledge_sha256": "6" * 64,
            "search_sha256": "7" * 64,
            "knowledge_enrichment": {
                "status": "not_applicable",
                "reason": "legacy_v39_baseline",
            },
        },
        "resources": {"inventory_sha256": manifest_sha256(inventory)},
        "state": {
            "compatibility": {
                "comments": {"read": [1, 2], "write": [1, 2]},
                "research_workspace": {"read": [1, 2, 3], "write": [1, 2, 3]},
                "rollback_policy": "expand_only_no_down_migration",
            }
        },
        "recovery": {
            "compatibility": {
                "checkpoint_manifest_schemas": ["qrh-checkpoint-manifest/v1"],
                "restore_protocol_versions": ["qrh-restore/v1"],
            }
        },
        "inventory": inventory,
    }


def _inspection(baseline: V39Baseline) -> dict[str, object]:
    nonce = NONCE_BYTES.hex()
    return {
        "schema_version": "qrh-writer-handoff-inspection/v1",
        "inspection_id": f"writer-handoff-inspect-{nonce[:20]}",
        "inspected_at": "2026-08-21T04:00:00Z",
        "nonce": nonce,
        "authority": "evidence_only",
        "mutation_performed": False,
        "observation": {
            "target_address": "10.5.1.240",
            "port": 8765,
            "v39": {
                "release_id": baseline.release_id,
                "manifest_sha256": baseline.manifest_sha256,
                "snapshot_id": baseline.snapshot_id,
                "legacy_deployment_id": baseline.legacy_deployment_id,
            },
            "legacy_process": {"pid": 39},
            "legacy_state": {"authority": "C-legacy"},
            "d": {"qualified": True},
            "d_service": {"status": "stopped"},
        },
    }


def _success(
    baseline: V39Baseline, inspection_hash: str
) -> dict[str, object]:
    return {
        "schema_version": "qrh-writer-handoff-receipt/v1",
        "receipt_type": "writer_handoff",
        "receipt_id": f"writer-handoff-success-{ATTEMPT}",
        "attempt_id": ATTEMPT,
        "recorded_at": "2026-08-21T04:01:00Z",
        "authority": "evidence_only",
        "inspection_sha256": inspection_hash,
        "inspection_nonce_sha256": hashlib.sha256(NONCE_BYTES.hex().encode("ascii")).hexdigest(),
        "release_id": baseline.release_id,
        "release_manifest_sha256": baseline.manifest_sha256,
        "snapshot_id": baseline.snapshot_id,
        "final_checkpoint_id": f"handoff-final-{ATTEMPT}",
        "final_checkpoint_manifest_sha256": "b" * 64,
        "prehandoff_checkpoint_id": f"handoff-pre-d-{ATTEMPT}",
        "prehandoff_checkpoint_manifest_sha256": "c" * 64,
        "writer_transition": {
            "from": "C-legacy",
            "to": "D-active",
            "c_pid_stopped": True,
            "d_unique_listener": True,
            "c_permanently_fenced": True,
        },
        "verification": {
            "release_id": baseline.release_id,
            "manifest_sha256": baseline.manifest_sha256,
            "snapshot_id": baseline.snapshot_id,
            "writer_authority": "D-active",
            "unique_d_listener": True,
            "legacy_pid_stopped": True,
            "browser": True,
            "api": True,
            "resource": True,
            "legacy_restart_fenced": True,
            "session_key_ready": True,
        },
        "active_authority_changed": False,
    }


def _failure(
    baseline: V39Baseline, inspection_hash: str
) -> dict[str, object]:
    return {
        "schema_version": "qrh-writer-handoff-failure/v1",
        "receipt_type": "writer_handoff_failure",
        "receipt_id": f"writer-handoff-failure-{ATTEMPT}",
        "attempt_id": ATTEMPT,
        "recorded_at": "2026-08-21T04:01:00Z",
        "authority": "evidence_only",
        "inspection_sha256": inspection_hash,
        "inspection_nonce_sha256": hashlib.sha256(NONCE_BYTES.hex().encode("ascii")).hexdigest(),
        "release_id": baseline.release_id,
        "release_manifest_sha256": baseline.manifest_sha256,
        "failed_phase": "d_service_start",
        "error_code": "writer_handoff_failed",
        "final_checkpoint_id": f"handoff-final-{ATTEMPT}",
        "prehandoff_checkpoint_id": f"handoff-pre-d-{ATTEMPT}",
        "d_external_open": False,
        "legacy_rollback": {
            "attempted": True,
            "succeeded": True,
            "d_state_restored": True,
            "blocked": False,
        },
        "success_activation_recorded": False,
    }


class FakeBoundary:
    def __init__(
        self,
        baseline: V39Baseline,
        *,
        disconnect_apply: bool = False,
        fail_apply: bool = False,
    ):
        self.baseline = baseline
        self.inspection = _inspection(baseline)
        self.inspection_hash = manifest_sha256(self.inspection)
        self.fail_apply = fail_apply
        self.terminal = (
            _failure(baseline, self.inspection_hash)
            if fail_apply
            else _success(baseline, self.inspection_hash)
        )
        self.terminal_bytes = canonical_manifest_bytes(self.terminal)
        self.disconnect_apply = disconnect_apply
        self.calls: list[tuple[str, ...]] = []
        self.scripts: list[str] = []
        self.intent_adopted = False
        self.finalized = not disconnect_apply
        self.apply_count = 0

    @staticmethod
    def _script(arguments: tuple[str, ...]) -> str:
        return base64.b64decode(arguments[-1]).decode("utf-16le")

    def __call__(self, arguments):
        args = tuple(str(item) for item in arguments)
        self.calls.append(args)
        if args[0] == "scp":
            if ":D:/quant/quant_platform/control/writer-handoff-intents/" in args[-1]:
                return CommandResult(0, "")
            Path(args[-1]).write_bytes(self.terminal_bytes)
            return CommandResult(0, "")
        script = self._script(args)
        self.scripts.append(script)
        if "'seed-access-identity'" in script:
            return CommandResult(
                0,
                json.dumps(
                    {
                        "schema_version": "qrh-writer-handoff-access-identity/v1",
                        "status": "seeded",
                        "contract_version": "v39-default-access-identity-ast/v1",
                        "source_server_sha256": "d" * 64,
                        "protected_access_identity_present": True,
                        "override_evidence_absent": True,
                    }
                ),
            )
        if "'inspect'" in script:
            return CommandResult(
                0,
                json.dumps(
                    {
                        "schema_version": "qrh-writer-handoff-inspection-result/v1",
                        "status": "inspected_read_only",
                        "inspection_sha256": self.inspection_hash,
                        "receipt": self.inspection,
                    },
                    sort_keys=True,
                ),
            )
        if "'apply'" in script:
            self.apply_count += 1
            if self.disconnect_apply:
                return CommandResult(255, "")
            if self.fail_apply:
                return CommandResult(
                    2,
                    json.dumps(
                        {
                            "schema_version": "qrh-writer-handoff-apply-result/v1",
                            "status": "failed",
                            "evidence_type": "writer_handoff_failure",
                            "evidence_id": self.terminal["receipt_id"],
                            "legacy_rollback_attempted": True,
                            "legacy_rollback_succeeded": True,
                            "rollback_blocked": False,
                            "error_code": "writer_handoff_failed",
                        }
                    ),
                )
            if self.apply_count > 1:
                return CommandResult(
                    2,
                    json.dumps(
                        {
                            "schema_version": "qrh-writer-handoff-cli-error/v1",
                            "status": "error",
                            "error_type": "WriterHandoffError",
                        }
                    ),
                )
            return CommandResult(
                0,
                json.dumps(
                    {
                        "schema_version": "qrh-writer-handoff-apply-result/v1",
                        "status": "succeeded",
                        "evidence_type": "writer_handoff_receipt",
                        "evidence_id": self.terminal["receipt_id"],
                        "legacy_rollback_attempted": False,
                        "legacy_rollback_succeeded": False,
                        "rollback_blocked": False,
                        "error_code": None,
                    }
                ),
            )
        if "'finalize'" in script:
            self.finalized = True
            return CommandResult(
                0,
                json.dumps(
                    {
                        "schema_version": "qrh-writer-handoff-finalize-result/v1",
                        "status": "succeeded",
                        "evidence_type": "writer_handoff_receipt",
                        "evidence_id": self.terminal["receipt_id"],
                        "writer_authority_committed": True,
                    }
                ),
            )
        if "'status'" in script:
            if self.fail_apply:
                status = {
                    "schema_version": "qrh-writer-handoff-status/v1",
                    "status": "failed",
                    "attempt_id": ATTEMPT,
                    "phase": "legacy_restored_fenced",
                    "evidence_type": "writer_handoff_failure",
                    "evidence_id": self.terminal["receipt_id"],
                    "writer_authority_committed": False,
                }
            elif self.disconnect_apply and not self.finalized:
                status = {
                    "schema_version": "qrh-writer-handoff-status/v1",
                    "status": "finalize_required",
                    "attempt_id": ATTEMPT,
                    "phase": "handoff_committed_receipt_pending",
                    "evidence_type": "writer_handoff_coordination_journal",
                    "evidence_id": "writer_handoff_pending",
                    "writer_authority_committed": True,
                }
            else:
                status = {
                    "schema_version": "qrh-writer-handoff-status/v1",
                    "status": "succeeded",
                    "attempt_id": ATTEMPT,
                    "phase": "terminal_receipt",
                    "evidence_type": "writer_handoff_receipt",
                    "evidence_id": self.terminal["receipt_id"],
                    "writer_authority_committed": True,
                }
            return CommandResult(0, json.dumps(status))
        if "qrh-writer-handoff-download-probe/v1" in script:
            return CommandResult(
                0,
                json.dumps(
                    {
                        "schema_version": "qrh-writer-handoff-download-probe/v1",
                        "bytes": len(self.terminal_bytes),
                        "sha256": hashlib.sha256(self.terminal_bytes).hexdigest(),
                    }
                ),
            )
        if "intent_ready" in script:
            if self.intent_adopted:
                return CommandResult(0, '{"status":"intent_adopted"}')
            return CommandResult(0, '{"status":"intent_ready"}')
        if "intent_adopted" in script:
            self.intent_adopted = True
            return CommandResult(0, '{"status":"intent_adopted"}')
        raise AssertionError(f"unexpected boundary call: {script[-300:]}")


class WriterHandoffClientTests(unittest.TestCase):
    def setUp(self) -> None:
        authority = patch(
            "quant_hub.ops.writer_handoff_client.require_failure_domain_authority",
            return_value=None,
        )
        authority.start()
        self.addCleanup(authority.stop)
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.project = root / "project"
        self.recovery = root / "offhost-recovery"
        self.project.mkdir()
        self.recovery.mkdir()
        self.baseline = V39Baseline(MANIFEST_HASH)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _client(self, boundary: FakeBoundary) -> WriterHandoffClient:
        return WriterHandoffClient(
            WriterHandoffClientConfig(
                project_root=self.project,
                recovery_root=self.recovery,
                vm=VMConfig(
                    ssh_alias="honghu-vm",
                    target_address="10.5.1.240",
                    root=PureWindowsPath(r"D:\quant\quant_platform"),
                ),
            ),
            command_runner=boundary,
            nonce_factory=lambda size: NONCE_BYTES,
        )

    def test_single_command_preserves_intent_and_downloads_terminal_receipt(self) -> None:
        boundary = FakeBoundary(self.baseline)
        result = self._client(boundary).run(self.baseline)
        self.assertEqual(result.status, "succeeded")
        inspection = (
            self.recovery
            / "evidence"
            / "writer-handoff"
            / "inspections"
            / f"{boundary.inspection_hash}.json"
        )
        terminal = (
            self.recovery
            / "evidence"
            / "writer-handoff"
            / "terminal"
            / f"{boundary.terminal['receipt_id']}.json"
        )
        self.assertEqual(inspection.read_bytes(), canonical_manifest_bytes(boundary.inspection))
        self.assertEqual(terminal.read_bytes(), boundary.terminal_bytes)
        self.assertNotIn(NONCE_BYTES.hex(), json.dumps(result.public_document()))
        self.assertTrue(any(call[0] == "scp" and call[-1].endswith(".json.partial") for call in boundary.calls))
        self.assertTrue(any(call[0] == "scp" and call[-1].endswith(".download") for call in boundary.calls))

    def test_apply_disconnect_discovers_exact_attempt_then_finalizes(self) -> None:
        boundary = FakeBoundary(self.baseline, disconnect_apply=True)
        result = self._client(boundary).run(self.baseline)
        self.assertEqual(result.attempt_id, ATTEMPT)
        self.assertTrue(result.writer_authority_committed)
        self.assertTrue(boundary.finalized)
        self.assertEqual(
            sum("'finalize'" in script for script in boundary.scripts), 1
        )

    def test_failure_receipt_is_downloaded_without_false_success(self) -> None:
        boundary = FakeBoundary(self.baseline, fail_apply=True)
        result = self._client(boundary).run(self.baseline)
        self.assertEqual(result.status, "failed")
        self.assertFalse(result.writer_authority_committed)
        self.assertTrue(
            (
                self.recovery
                / "evidence"
                / "writer-handoff"
                / "terminal"
                / f"{boundary.terminal['receipt_id']}.json"
            ).is_file()
        )
        self.assertFalse(any("'finalize'" in script for script in boundary.scripts))

    def test_exact_repeat_reuses_immutable_offhost_and_remote_evidence(self) -> None:
        boundary = FakeBoundary(self.baseline)
        client = self._client(boundary)
        first = client.run(self.baseline)
        second = client.run(self.baseline)
        self.assertEqual(first, second)
        self.assertEqual(boundary.apply_count, 2)
        self.assertEqual(
            sum(call[0] == "scp" and ":D:/quant/" in call[-1] for call in boundary.calls),
            1,
        )

    def test_wrong_target_is_rejected_before_ssh_or_scp(self) -> None:
        boundary = FakeBoundary(self.baseline)
        with self.assertRaises(WriterHandoffClientError):
            WriterHandoffClient(
                WriterHandoffClientConfig(
                    project_root=self.project,
                    recovery_root=self.recovery,
                    vm=VMConfig(
                        ssh_alias="honghu-vm",
                        target_address="10.5.1.241",
                        root=PureWindowsPath(r"D:\quant\quant_platform"),
                    ),
                ),
                command_runner=boundary,
            )
        self.assertEqual(boundary.calls, [])

    def test_tampered_inspection_hash_stops_before_scp(self) -> None:
        boundary = FakeBoundary(self.baseline)
        boundary.inspection_hash = "f" * 64
        with self.assertRaises(WriterHandoffClientError):
            self._client(boundary).run(self.baseline)
        self.assertFalse(any(call[0] == "scp" for call in boundary.calls))

    def test_remote_adopt_hash_failure_stops_before_apply(self) -> None:
        boundary = FakeBoundary(self.baseline)
        original = boundary.__call__

        def failing(arguments):
            args = tuple(str(item) for item in arguments)
            if args[0] == "ssh":
                script = FakeBoundary._script(args)
                if "intent_adopted" in script and "intent_ready" not in script:
                    boundary.calls.append(args)
                    boundary.scripts.append(script)
                    return CommandResult(1, "")
            return original(arguments)

        client = WriterHandoffClient(
            self._client(boundary).config,
            command_runner=failing,
            nonce_factory=lambda size: NONCE_BYTES,
        )
        with self.assertRaises(WriterHandoffRunError) as caught:
            client.run(self.baseline)
        self.assertEqual(caught.exception.inspection_sha256, boundary.inspection_hash)
        self.assertFalse(any("'apply'" in script for script in boundary.scripts))

    def test_all_remote_paths_are_exact_d_root_and_scp_pins_dot240(self) -> None:
        boundary = FakeBoundary(self.baseline)
        self._client(boundary).run(self.baseline)
        for script in boundary.scripts:
            self.assertNotIn("C:\\", script)
            self.assertNotIn("D:\\quant\\writer", script)
            for path in re.findall(r"[Dd]:\\[^'\";]+", script):
                self.assertTrue(
                    path.casefold().startswith(r"d:\quant\quant_platform".casefold()),
                    path,
                )
        for call in boundary.calls:
            if call[0] == "scp":
                self.assertIn("HostName=10.5.1.240", call)


class AccessIdentitySeedTests(unittest.TestCase):
    def setUp(self) -> None:
        authority = patch(
            "quant_hub.ops.writer_handoff.require_failure_domain_authority",
            return_value=None,
        )
        authority.start()
        self.addCleanup(authority.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "D-root"
        self.root.mkdir()
        self.legacy_marker = Path(self.temporary.name) / "C-legacy-marker"
        self.legacy_marker.write_bytes(b"unchanged")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _fixture(self, source: bytes = V39_SERVER_SOURCE) -> V39Baseline:
        release = _seed_release(source)
        baseline = V39Baseline(manifest_sha256(release))
        release_root = self.root / "releases" / baseline.release_id
        server = release_root / "tools" / "viewer" / "server.py"
        server.parent.mkdir(parents=True)
        server.write_bytes(source)
        (release_root / "release_manifest.json").write_bytes(
            canonical_manifest_bytes(release)
        )
        control = self.root / "control"
        control.mkdir()
        (control / "active_release.json").write_bytes(
            canonical_manifest_bytes(
                {
                    "schema_version": "qrh-active-release/v1",
                    "release_id": baseline.release_id,
                    "release_path": str(release_root.resolve()),
                    "manifest_sha256": baseline.manifest_sha256,
                }
            )
        )
        (self.root / "state").mkdir()
        return baseline

    def test_seed_and_exact_retry_do_not_leak_identity_or_touch_legacy(self) -> None:
        baseline = self._fixture()
        seeded = seed_v39_access_identity(
            vm_root=self.root,
            baseline=baseline,
            allow_test_root=True,
            override_detector=lambda: False,
        )
        reused = seed_v39_access_identity(
            vm_root=self.root,
            baseline=baseline,
            allow_test_root=True,
            override_detector=lambda: False,
        )
        self.assertEqual(seeded["status"], "seeded")
        self.assertEqual(reused["status"], "reused")
        rendered = json.dumps([seeded, reused], sort_keys=True)
        self.assertNotIn(
            "6285c59738159eb58889d6402c1b654222cb39c6b01e5afaffa5f5a39624798d",
            rendered,
        )
        self.assertEqual(self.legacy_marker.read_bytes(), b"unchanged")
        self.assertEqual(
            len((self.root / "state" / "viewer_access_password.digest").read_bytes()),
            65,
        )

    def test_override_evidence_refuses_default_seed_without_value_leakage(self) -> None:
        baseline = self._fixture()
        with self.assertRaisesRegex(WriterHandoffError, "override evidence") as captured:
            seed_v39_access_identity(
                vm_root=self.root,
                baseline=baseline,
                allow_test_root=True,
                override_detector=lambda: True,
            )
        self.assertNotIn("password-value", str(captured.exception))
        self.assertFalse((self.root / "state" / "viewer_access_password.digest").exists())

    def test_source_tamper_against_manifest_is_rejected(self) -> None:
        baseline = self._fixture()
        server = self.root / "releases" / baseline.release_id / "tools" / "viewer" / "server.py"
        server.write_bytes(server.read_bytes() + b"# tamper\n")
        with self.assertRaisesRegex(WriterHandoffError, "release inventory"):
            seed_v39_access_identity(
                vm_root=self.root,
                baseline=baseline,
                allow_test_root=True,
                override_detector=lambda: False,
            )

    def test_manifest_or_active_identity_tamper_is_rejected(self) -> None:
        baseline = self._fixture()
        active_path = self.root / "control" / "active_release.json"
        active = json.loads(active_path.read_text(encoding="utf-8"))
        active["manifest_sha256"] = "f" * 64
        active_path.write_bytes(canonical_manifest_bytes(active))
        with self.assertRaisesRegex(WriterHandoffError, "active V39"):
            seed_v39_access_identity(
                vm_root=self.root,
                baseline=baseline,
                allow_test_root=True,
                override_detector=lambda: False,
            )

    def test_salt_or_constant_contract_tamper_is_rejected_even_when_manifest_resealed(self) -> None:
        variants = (
            V39_SERVER_SOURCE.replace(
                b"ae829f253a022e21e2b53ddd97c712b8",
                b"be829f253a022e21e2b53ddd97c712b8",
            ),
            V39_SERVER_SOURCE.replace(b"600_000", b"599_999"),
            V39_SERVER_SOURCE.replace(
                b"6285c59738159eb58889d6402c1b654222cb39c6b01e5afaffa5f5a39624798d",
                b"6285c59738159eb58889d6402c1b654222cb39c6b01e5afaffa5f5a3962479",
            ),
        )
        for index, bad_source in enumerate(variants):
            with self.subTest(index=index):
                if index:
                    self.tearDown()
                    self.setUp()
                baseline = self._fixture(bad_source)
                with self.assertRaisesRegex(WriterHandoffError, "default access identity contract"):
                    seed_v39_access_identity(
                        vm_root=self.root,
                        baseline=baseline,
                        allow_test_root=True,
                        override_detector=lambda: False,
                    )

    def test_existing_different_identity_is_never_overwritten(self) -> None:
        baseline = self._fixture()
        destination = self.root / "state" / "viewer_access_password.digest"
        destination.write_text("f" * 64 + "\n", encoding="ascii")
        with self.assertRaisesRegex(WriterHandoffError, "existing protected"):
            seed_v39_access_identity(
                vm_root=self.root,
                baseline=baseline,
                allow_test_root=True,
                override_detector=lambda: False,
            )
        self.assertEqual(destination.read_text(encoding="ascii"), "f" * 64 + "\n")


class WriterHandoffStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        authority = patch(
            "quant_hub.ops.writer_handoff.require_failure_domain_authority",
            return_value=None,
        )
        authority.start()
        self.addCleanup(authority.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "D-root"
        self.root.mkdir()
        self.baseline = V39Baseline(MANIFEST_HASH)
        self.inspection_hash = "e" * 64

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_terminal_status_resolves_exact_receipt_without_creating_directories(self) -> None:
        receipt = _success(self.baseline, self.inspection_hash)
        path = (
            self.root
            / "audit"
            / "writer-handoff"
            / "success"
            / f"{receipt['receipt_id']}.json"
        )
        path.parent.mkdir(parents=True)
        path.write_bytes(canonical_manifest_bytes(receipt))
        status = inspect_writer_handoff_status(
            vm_root=self.root,
            baseline=self.baseline,
            inspection_sha256=self.inspection_hash,
            nonce=NONCE_BYTES.hex(),
            allow_test_root=True,
        )
        self.assertEqual(status["status"], "succeeded")
        self.assertEqual(status["attempt_id"], ATTEMPT)
        self.assertFalse((self.root / "audit" / "writer-handoff" / "failure").exists())

    def test_pending_status_returns_only_exact_finalizable_attempt(self) -> None:
        journal = {
            "schema_version": "qrh-writer-handoff-pending/v2",
            "attempt_id": ATTEMPT,
            "nonce_sha256": hashlib.sha256(NONCE_BYTES.hex().encode("ascii")).hexdigest(),
            "inspection_sha256": self.inspection_hash,
            "success_receipt_id": f"writer-handoff-success-{ATTEMPT}",
            "release_id": self.baseline.release_id,
            "manifest_sha256": self.baseline.manifest_sha256,
            "phase": "handoff_committed_receipt_pending",
            "commit_evidence": {
                "recorded_at": "2026-08-21T04:01:00Z",
                "final_checkpoint_id": f"handoff-final-{ATTEMPT}",
                "final_checkpoint_manifest_sha256": "b" * 64,
                "prehandoff_checkpoint_id": f"handoff-pre-d-{ATTEMPT}",
                "prehandoff_checkpoint_manifest_sha256": "c" * 64,
            },
            "authority": "coordination_only",
        }
        path = self.root / "control" / "writer_handoff_pending.json"
        path.parent.mkdir()
        path.write_bytes(canonical_manifest_bytes(journal))
        status = inspect_writer_handoff_status(
            vm_root=self.root,
            baseline=self.baseline,
            inspection_sha256=self.inspection_hash,
            nonce=NONCE_BYTES.hex(),
            allow_test_root=True,
        )
        self.assertEqual(status["status"], "finalize_required")
        self.assertEqual(status["attempt_id"], ATTEMPT)
        self.assertTrue(status["writer_authority_committed"])

    def test_different_pending_intent_fails_closed(self) -> None:
        journal = {
            "schema_version": "qrh-writer-handoff-pending/v2",
            "attempt_id": ATTEMPT,
            "nonce_sha256": "f" * 64,
            "inspection_sha256": "d" * 64,
            "success_receipt_id": f"writer-handoff-success-{ATTEMPT}",
            "release_id": self.baseline.release_id,
            "manifest_sha256": self.baseline.manifest_sha256,
            "phase": "legacy_stop_pending",
            "commit_evidence": None,
            "authority": "coordination_only",
        }
        path = self.root / "control" / "writer_handoff_pending.json"
        path.parent.mkdir()
        path.write_bytes(canonical_manifest_bytes(journal))
        with self.assertRaisesRegex(WriterHandoffError, "different or invalid"):
            inspect_writer_handoff_status(
                vm_root=self.root,
                baseline=self.baseline,
                inspection_sha256=self.inspection_hash,
                nonce=NONCE_BYTES.hex(),
                allow_test_root=True,
            )


class WriterHandoffClientCLIContractTests(unittest.TestCase):
    def test_run_error_exposes_only_safe_exact_inspection_recovery_identity(self) -> None:
        client = Mock()
        client.run.side_effect = WriterHandoffRunError("b" * 64)
        output = StringIO()
        with patch(
            "quant_hub.ops.writer_handoff_client._client_from_runtime_config",
            return_value=client,
        ), patch(
            "quant_hub.ops.writer_handoff_client.require_failure_domain_authority",
            return_value=None,
        ), redirect_stdout(output):
            code = writer_handoff_client_main(
                [
                    "--config", r"D:\protected\runtime.json",
                    "--project-root", r"D:\quant\quant_platform",
                    "--release-manifest-sha256", MANIFEST_HASH,
                    "run",
                ]
            )
        self.assertEqual(code, 2)
        self.assertEqual(
            json.loads(output.getvalue()),
            {
                "schema_version": "qrh-writer-handoff-client-error/v2",
                "status": "error",
                "error_type": "WriterHandoffRunError",
                "inspection_sha256": "b" * 64,
            },
        )
        self.assertNotIn(NONCE_BYTES.hex(), output.getvalue())


if __name__ == "__main__":
    unittest.main()
