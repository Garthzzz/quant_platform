from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from quant_hub.collaboration.checkpoint import (
    CheckpointError,
    create_sqlite_checkpoint,
    verify_sqlite_checkpoint,
)
from quant_hub.ops.release_identity import canonical_manifest_bytes, manifest_sha256
from quant_hub.ops.vm_service_cli import production_runtime_document
from quant_hub.ops.windows_service import (
    WindowsServiceError,
    authorize_writer_handoff_service_start,
)
from quant_hub.ops.writer_handoff import (
    FAILURE_SCHEMA,
    LEGACY_SERVER,
    PORT,
    SUCCESS_SCHEMA,
    LegacyProcess,
    RuntimeObservation,
    V39Baseline,
    WriterHandoffError,
    apply_writer_handoff,
    finalize_writer_handoff,
    inspect_d_closure,
    inspect_writer_handoff,
)


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 21, 4, 0, tzinfo=UTC)
NONCE = "12" * 24
H = {str(index): str(index) * 64 for index in range(1, 10)}


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_manifest_bytes(value))


def _database(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE marker(value TEXT NOT NULL)")
        connection.execute("INSERT INTO marker(value) VALUES (?)", (value,))
        connection.commit()
    finally:
        connection.close()


def _value(path: Path) -> str:
    connection = sqlite3.connect(path)
    try:
        return str(connection.execute("SELECT value FROM marker").fetchone()[0])
    finally:
        connection.close()


def _release(baseline: V39Baseline | None = None) -> dict[str, object]:
    inventory = {"schema_version": "qrh-release-file-inventory/v1", "files": []}
    return {
        "schema_version": "qrh-release-manifest/v1",
        "release_id": "v39-baseline-20260731-hotfix1",
        "built_at": "2026-07-31T10:04:18Z",
        "application": {
            "commit_sha": "0" * 40,
            "tracked_tree_sha256": H["1"],
            "build_tool_version": "writer-handoff-tests/v1",
            "source_kind": "legacy_broadcast",
            "legacy_deployment_id": "quant-hub-v39-company-broadcast-20260731-hotfix1",
            "source_archive_sha256": H["8"],
            "source_package_manifest_sha256": H["9"],
        },
        "content": {
            "snapshot_id": "v39-content-20260731-hotfix1",
            "source_inventory_sha256": H["2"],
            "ir_sha256": H["3"],
            "knowledge_sha256": H["4"],
            "search_sha256": H["5"],
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


class Fixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.root = Path(self.temporary.name) / "D-root"
        self.root.mkdir()
        release = _release()
        self.baseline = V39Baseline(manifest_sha256(release))
        release_root = self.root / "releases" / self.baseline.release_id
        release_root.mkdir(parents=True)
        _write_json(release_root / "release_manifest.json", release)
        _write_json(
            self.root / "control" / "active_release.json",
            {
                "schema_version": "qrh-active-release/v1",
                "release_id": self.baseline.release_id,
                "release_path": str(release_root.resolve()),
                "manifest_sha256": self.baseline.manifest_sha256,
            },
        )
        _write_json(
            self.root / "control" / "deployment_runtime.json",
            production_runtime_document(),
        )
        _write_json(
            self.root / "control" / "service_install_candidate.json",
            {"schema_version": "test-service-binding/v1", "closed": True},
        )
        state = self.root / "state"
        state.mkdir()
        (state / "viewer_access_password.digest").write_text("a" * 64 + "\n", encoding="ascii")
        _database(state / "comments.sqlite3", "d-comments-old")
        _database(state / "research_workspace.sqlite3", "d-workspace-old")
        self.legacy = Path(self.temporary.name) / "C-state"
        _database(self.legacy / "comments.sqlite3", "c-comments-final")
        _database(self.legacy / "research_workspace.sqlite3", "c-workspace-final")
        self._recovery_evidence()

    def _recovery_evidence(self) -> None:
        _write_json(
            self.root / "audit" / "events" / "cold-materialization-v39.json",
            {
                "schema_version": "qrh-recovery-materialization-event/v1",
                "event_id": "cold-materialization-v39",
                "kind": "cold_recovery_materialized",
                "authority": "evidence_only",
                "fields": {
                    "bundle_id": "v39",
                    "release_id": self.baseline.release_id,
                    "manifest_sha256": self.baseline.manifest_sha256,
                    "empty_root_precondition": True,
                    "import_cleaned": True,
                    "runtime_tmp_cleaned": True,
                },
            },
        )
        _write_json(
            self.root / "audit" / "recovery-v39.json",
            {
                "schema_version": "qrh-recovery-receipt/v1",
                "receipt_type": "recovery",
                "receipt_id": "recovery-v39",
                "recovery_attempt_id": "restore-v39",
                "recorded_at": "2026-08-21T03:00:00Z",
                "authority": "evidence_only",
                "release_manifest_sha256": self.baseline.manifest_sha256,
                "recovery_manifest_sha256": H["6"],
                "checkpoint_manifest_sha256": H["7"],
                "verdict": "recovered",
                "restore_verification": {
                    "closure": True,
                    "state_restored": True,
                    "service_started": True,
                    "post_restore": True,
                },
            },
        )
        _write_json(
            self.root / "audit" / "receipts" / "protection-v39.json",
            {
                "schema_version": "qrh-recovery-protection-receipt/v1",
                "receipt_type": "recovery_protection",
                "receipt_id": "protection-v39",
                "deployment_attempt_id": "protect-v39",
                "recorded_at": "2026-08-21T03:10:00Z",
                "authority": "evidence_only",
                "release_manifest_sha256": self.baseline.manifest_sha256,
                "recovery_manifest_sha256": H["6"],
                "checkpoint_manifest_sha256": H["7"],
                "verdict": "protected",
                "pre_activation_verification": {
                    "closure": True,
                    "compatibility": True,
                    "failure_domain": True,
                    "no_secret": True,
                    "active_pointer_switched": False,
                },
            },
        )

    @property
    def legacy_sources(self) -> dict[str, Path]:
        return {
            "comments": self.legacy / "comments.sqlite3",
            "research_workspace": self.legacy / "research_workspace.sqlite3",
        }

    def closure(self, root: Path, baseline: V39Baseline) -> dict[str, object]:
        with mock.patch(
            "quant_hub.ops.writer_handoff.verify_installed_operational_bindings",
            return_value={"service_python": root / "tooling" / "python.exe"},
        ):
            return dict(inspect_d_closure(root, baseline))

    def close(self) -> None:
        self.temporary.cleanup()


class FakeRuntime:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.process = LegacyProcess(
            3901,
            r"C:\Miniconda3\envs\quant_hub\python.exe",
            (
                r"C:\Miniconda3\envs\quant_hub\python.exe",
                "-I",
                str(LEGACY_SERVER),
            ),
            "c" * 64,
            "d" * 64,
        )
        self.legacy_running = True
        self.d_status = "stopped"
        self.open = False
        self.toctou = False
        self.observe_calls = 0
        self.start_failure = ""
        self.probe_ok = True
        self.generate_session_key = True
        self.events: list[str] = []
        self.start_legacy_count = 0

    def observe(self, port: int) -> RuntimeObservation:
        self.observe_calls += 1
        process = self.process
        if self.toctou and self.observe_calls >= 2 and self.legacy_running:
            process = LegacyProcess(
                3902,
                process.executable,
                process.argv,
                process.executable_sha256,
                process.server_sha256,
            )
        if self.legacy_running:
            deployment = {
                "schema_version": "qrh-company-broadcast-health/v1",
                "status": "ok",
                "deployment_id": "quant-hub-v39-company-broadcast-20260731-hotfix1",
                "pid": process.pid,
                "port": port,
            }
            listeners = (process.pid,)
            legacy_process = process
        else:
            deployment = None
            legacy_process = None
            listeners = (8801,) if self.open else ()
        return RuntimeObservation(
            ("10.5.1.240",),
            listeners,
            deployment,
            legacy_process,
            {
                "service_name": "QuantResearchHub",
                "installed": True,
                "status": self.d_status,
                "binding_verified": True,
            },
        )

    def stop_legacy(self, expected: LegacyProcess) -> None:
        if expected != self.process or not self.legacy_running:
            raise RuntimeError("wrong legacy PID")
        self.events.append("stop-c")
        self.legacy_running = False

    def wait_port_free(self, port: int) -> bool:
        self.events.append("port-free")
        return not self.legacy_running and not self.open

    def start_d_service(self, service_name: str) -> None:
        self.events.append("start-d")
        if self.start_failure == "before_open":
            raise RuntimeError("D start failed")
        self.d_status = "running"
        if self.generate_session_key:
            (self.root / "state" / "viewer_secret.key").write_text(
                "b" * 64 + "\n", encoding="ascii"
            )
        self.open = True
        if self.start_failure == "after_open":
            raise RuntimeError("D opened then failed")

    def stop_d_service(self, service_name: str) -> None:
        self.events.append("stop-d")
        self.d_status = "stopped"
        self.open = False

    def d_external_open(self, port: int) -> bool:
        return self.open

    def probe_d(self, baseline: V39Baseline) -> dict[str, object]:
        self.events.append("probe-d")
        value = {
            "release_id": baseline.release_id,
            "manifest_sha256": baseline.manifest_sha256,
            "snapshot_id": baseline.snapshot_id,
            "writer_authority": "D-active",
            "unique_d_listener": True,
            "legacy_pid_stopped": not self.legacy_running,
            "browser": True,
            "api": True,
            "resource": True,
            "legacy_restart_fenced": True,
        }
        if not self.probe_ok:
            value["api"] = False
        return value

    def start_legacy(self, expected: LegacyProcess) -> None:
        self.events.append("start-c-exact-argv")
        self.start_legacy_count += 1
        self.legacy_running = True

    def verify_legacy_restored(
        self, expected: LegacyProcess, deployment_id: str, port: int
    ) -> bool:
        self.events.append("verify-c")
        return self.legacy_running and not self.open


class WriterHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()
        self.runtime = FakeRuntime(self.fixture.root)

    def tearDown(self) -> None:
        self.fixture.close()

    def inspect(self) -> dict[str, object]:
        return dict(
            inspect_writer_handoff(
                vm_root=self.fixture.root,
                baseline=self.fixture.baseline,
                runtime=self.runtime,
                nonce=NONCE,
                inspected_at=NOW,
                allow_test_root=True,
                closure_verifier=self.fixture.closure,
            )
        )

    def apply(self, receipt: dict[str, object], **changes):
        arguments = {
            "vm_root": self.fixture.root,
            "baseline": self.fixture.baseline,
            "runtime": self.runtime,
            "inspection_receipt": receipt,
            "expected_inspection_sha256": manifest_sha256(receipt),
            "nonce": NONCE,
            "now": lambda: NOW + timedelta(minutes=1),
            "id_factory": lambda: "a" * 32,
            "allow_test_root": True,
            "closure_verifier": self.fixture.closure,
            "legacy_sources": self.fixture.legacy_sources,
        }
        arguments.update(changes)
        return apply_writer_handoff(**arguments)

    def test_inspect_closes_v39_state_control_service_and_recovery_evidence(self) -> None:
        receipt = self.inspect()
        observation = receipt["observation"]
        self.assertEqual("evidence_only", receipt["authority"])
        self.assertFalse(receipt["mutation_performed"])
        self.assertEqual(3901, observation["legacy_process"]["pid"])
        self.assertEqual(self.fixture.baseline.manifest_sha256, observation["v39"]["manifest_sha256"])
        self.assertTrue(observation["d"]["recovery"]["failure_domain_accepted"])
        self.assertEqual(
            "pending_first_production_start",
            observation["d"]["protected_session_key_status"],
        )
        rendered = json.dumps(receipt, sort_keys=True)
        self.assertNotIn("a" * 64, rendered)  # protected access digest is not recorded
        self.assertFalse((self.fixture.root / "audit" / "writer-handoff").exists())

    def test_wrong_pid_or_server_path_is_rejected_read_only(self) -> None:
        process = self.runtime.process
        self.runtime.process = LegacyProcess(
            process.pid,
            process.executable,
            (process.executable, "-I", r"C:\tmp\server.py"),
            process.executable_sha256,
            process.server_sha256,
        )
        with self.assertRaises(WriterHandoffError):
            self.inspect()
        self.assertTrue(self.runtime.legacy_running)
        self.assertEqual([], self.runtime.events)

    def test_invalid_existing_session_key_is_rejected_before_handoff(self) -> None:
        (self.fixture.root / "state" / "viewer_secret.key").write_text(
            "not-a-valid-runtime-key\n", encoding="ascii"
        )
        with self.assertRaises(WriterHandoffError):
            self.inspect()
        self.assertTrue(self.runtime.legacy_running)
        self.assertEqual([], self.runtime.events)

    def test_recovery_and_failure_domain_receipts_must_bind_same_rm_checkpoint(self) -> None:
        path = self.fixture.root / "audit" / "receipts" / "protection-v39.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["checkpoint_manifest_sha256"] = H["8"]
        _write_json(path, value)
        with self.assertRaises(WriterHandoffError):
            self.inspect()
        self.assertTrue(self.runtime.legacy_running)

    def test_hash_nonce_and_toctou_are_fail_closed_before_pid_stop(self) -> None:
        receipt = self.inspect()
        with self.assertRaises(WriterHandoffError):
            self.apply(receipt, expected_inspection_sha256="f" * 64)
        self.assertTrue(self.runtime.legacy_running)
        self.runtime.toctou = True
        result = self.apply(receipt)
        self.assertFalse(result.succeeded)
        self.assertFalse(result.legacy_rollback_attempted)
        self.assertTrue(self.runtime.legacy_running)
        self.assertNotIn("stop-c", self.runtime.events)
        failure = json.loads(result.receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(FAILURE_SCHEMA, failure["schema_version"])
        self.assertFalse(failure["success_activation_recorded"])

    def test_final_checkpoint_failure_restores_exact_legacy_without_restart_script(self) -> None:
        receipt = self.inspect()

        def fail_legacy(**arguments):
            if arguments["state_authority_id"] == "legacy-c-final":
                raise CheckpointError("fixture final checkpoint failure")
            return create_sqlite_checkpoint(**arguments)

        result = self.apply(receipt, checkpoint_builder=fail_legacy)
        self.assertFalse(result.succeeded)
        self.assertTrue(result.legacy_rollback_attempted)
        self.assertTrue(result.legacy_rollback_succeeded)
        self.assertEqual(1, self.runtime.start_legacy_count)
        self.assertIn("start-c-exact-argv", self.runtime.events)
        self.assertNotIn("restart.py", " ".join(self.runtime.events))

    def test_d_start_failure_before_listener_restores_c_and_original_d_state(self) -> None:
        receipt = self.inspect()
        self.runtime.start_failure = "before_open"
        result = self.apply(receipt)
        self.assertFalse(result.succeeded)
        self.assertTrue(result.legacy_rollback_succeeded)
        self.assertFalse(result.rollback_blocked)
        self.assertEqual("d-comments-old", _value(self.fixture.root / "state" / "comments.sqlite3"))
        self.assertEqual("d-workspace-old", _value(self.fixture.root / "state" / "research_workspace.sqlite3"))
        self.assertLess(self.runtime.events.index("stop-c"), self.runtime.events.index("start-c-exact-argv"))
        journal = json.loads(
            (self.fixture.root / "control" / "writer_handoff_pending.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("legacy_restored_fenced", journal["phase"])
        with self.assertRaises(WindowsServiceError):
            authorize_writer_handoff_service_start(
                self.fixture.root,
                {
                    "release_id": self.fixture.baseline.release_id,
                    "manifest_sha256": self.fixture.baseline.manifest_sha256,
                },
            )

    def test_d_restore_failure_still_recovers_c_while_journal_fences_d(self) -> None:
        receipt = self.inspect()
        self.runtime.start_failure = "before_open"
        from quant_hub.ops import writer_handoff as module

        original = module._replace_d_state
        calls = 0

        def fail_restore(**arguments):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("fixture D restore failure")
            return original(**arguments)

        with mock.patch(
            "quant_hub.ops.writer_handoff._replace_d_state", side_effect=fail_restore
        ):
            result = self.apply(receipt)
        self.assertFalse(result.succeeded)
        self.assertTrue(result.legacy_rollback_succeeded)
        self.assertTrue(self.runtime.legacy_running)
        failure = json.loads(result.receipt_path.read_text(encoding="utf-8"))
        self.assertFalse(failure["legacy_rollback"]["d_state_restored"])
        journal = json.loads(
            (self.fixture.root / "control" / "writer_handoff_pending.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("legacy_restored_fenced", journal["phase"])

    def test_verified_c_rollback_journal_can_be_atomically_replaced_by_retry(self) -> None:
        first = self.inspect()
        self.runtime.start_failure = "before_open"
        failed = self.apply(first)
        self.assertTrue(failed.legacy_rollback_succeeded)
        self.runtime.start_failure = ""
        retry_nonce = "34" * 24
        retried = inspect_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            runtime=self.runtime,
            nonce=retry_nonce,
            inspected_at=NOW + timedelta(minutes=2),
            allow_test_root=True,
            closure_verifier=self.fixture.closure,
        )
        result = apply_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            runtime=self.runtime,
            inspection_receipt=retried,
            expected_inspection_sha256=manifest_sha256(retried),
            nonce=retry_nonce,
            now=lambda: NOW + timedelta(minutes=3),
            id_factory=lambda: "b" * 32,
            allow_test_root=True,
            closure_verifier=self.fixture.closure,
            legacy_sources=self.fixture.legacy_sources,
        )
        self.assertTrue(result.succeeded)
        self.assertFalse(
            (self.fixture.root / "control" / "writer_handoff_pending.json").exists()
        )

    def test_d_open_or_ambiguous_exposure_permanently_forbids_c_rollback(self) -> None:
        receipt = self.inspect()
        self.runtime.start_failure = "after_open"
        result = self.apply(receipt)
        self.assertFalse(result.succeeded)
        self.assertTrue(result.rollback_blocked)
        self.assertFalse(result.legacy_rollback_attempted)
        self.assertFalse(self.runtime.legacy_running)
        self.assertEqual(0, self.runtime.start_legacy_count)
        failure = json.loads(result.receipt_path.read_text(encoding="utf-8"))
        self.assertTrue(failure["d_external_open"])
        self.assertEqual("d_external_writer_open_rollback_forbidden", failure["error_code"])
        journal = json.loads(
            (self.fixture.root / "control" / "writer_handoff_pending.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("handoff_failed_fenced", journal["phase"])

    def test_absent_session_key_is_generated_and_success_is_secret_free(self) -> None:
        receipt = self.inspect()
        self.assertFalse((self.fixture.root / "state" / "viewer_secret.key").exists())
        result = self.apply(receipt)
        self.assertTrue(result.succeeded)
        self.assertEqual(SUCCESS_SCHEMA, json.loads(result.receipt_path.read_text(encoding="utf-8"))["schema_version"])
        self.assertEqual("c-comments-final", _value(self.fixture.root / "state" / "comments.sqlite3"))
        self.assertEqual("c-workspace-final", _value(self.fixture.root / "state" / "research_workspace.sqlite3"))
        for checkpoint_id in (result.final_checkpoint_id, result.prehandoff_checkpoint_id):
            report = verify_sqlite_checkpoint(self.fixture.root / "backups" / "checkpoints" / str(checkpoint_id))
            self.assertTrue(report.valid)
        self.assertFalse(self.runtime.legacy_running)
        self.assertTrue(self.runtime.open)
        self.assertEqual("running", self.runtime.d_status)
        self.assertEqual(["stop-c", "port-free", "start-d", "probe-d"], self.runtime.events)
        success = json.loads(result.receipt_path.read_text(encoding="utf-8"))
        self.assertTrue(success["writer_transition"]["c_permanently_fenced"])
        self.assertFalse(success["active_authority_changed"])
        key = (self.fixture.root / "state" / "viewer_secret.key").read_text(
            encoding="ascii"
        ).strip()
        self.assertEqual(64, len(key))
        self.assertNotIn(key, json.dumps(success, sort_keys=True))
        self.assertTrue(success["verification"]["session_key_ready"])
        self.assertFalse(
            (self.fixture.root / "control" / "writer_handoff_pending.json").exists()
        )
        self.assertFalse(list((self.fixture.root / "audit" / "writer-handoff" / "failure").glob("*.json")))

    def test_missing_session_key_after_d_start_fails_without_c_fallback(self) -> None:
        receipt = self.inspect()
        self.runtime.generate_session_key = False
        result = self.apply(receipt)
        self.assertFalse(result.succeeded)
        self.assertTrue(result.rollback_blocked)
        self.assertFalse(result.writer_authority_committed)
        self.assertFalse(self.runtime.legacy_running)
        self.assertFalse((self.fixture.root / "state" / "viewer_secret.key").exists())

    def test_probe_commit_cut_is_finalized_without_stopping_d(self) -> None:
        receipt = self.inspect()
        with mock.patch(
            "quant_hub.ops.writer_handoff._write_or_verify_success_receipt",
            side_effect=OSError("fixture crash after committed probe"),
        ):
            pending = self.apply(receipt)
        self.assertFalse(pending.succeeded)
        self.assertTrue(pending.writer_authority_committed)
        self.assertEqual("handoff_committed_receipt_pending", pending.error_code)
        self.assertTrue(self.runtime.open)
        self.assertNotIn("stop-d", self.runtime.events)
        journal = json.loads(pending.receipt_path.read_text(encoding="utf-8"))
        self.assertEqual("handoff_committed_receipt_pending", journal["phase"])
        attempt_id = str(journal["attempt_id"])
        success_path = (
            self.fixture.root
            / "audit"
            / "writer-handoff"
            / "success"
            / f"writer-handoff-success-{attempt_id}.json"
        )
        self.assertFalse(success_path.exists())

        completed = finalize_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            runtime=self.runtime,
            attempt_id=attempt_id,
            nonce=NONCE,
            now=lambda: NOW + timedelta(minutes=2),
            allow_test_root=True,
        )
        self.assertTrue(completed.succeeded)
        self.assertTrue(success_path.exists())
        self.assertFalse(pending.receipt_path.exists())
        self.assertTrue(self.runtime.open)

    def test_receipt_then_cleanup_cut_and_repeated_finalize_are_idempotent(self) -> None:
        receipt = self.inspect()
        with mock.patch(
            "quant_hub.ops.writer_handoff._remove_journal",
            side_effect=OSError("fixture crash after terminal receipt"),
        ):
            pending = self.apply(receipt)
        self.assertFalse(pending.succeeded)
        self.assertTrue(pending.writer_authority_committed)
        self.assertTrue(self.runtime.open)
        journal = json.loads(pending.receipt_path.read_text(encoding="utf-8"))
        self.assertEqual("handoff_committed_receipt_pending", journal["phase"])
        attempt_id = str(journal["attempt_id"])
        receipt_path = (
            self.fixture.root
            / "audit"
            / "writer-handoff"
            / "success"
            / f"writer-handoff-success-{attempt_id}.json"
        )
        before = receipt_path.read_bytes()
        first = finalize_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            runtime=self.runtime,
            attempt_id=attempt_id,
            nonce=NONCE,
            allow_test_root=True,
        )
        second = finalize_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            runtime=self.runtime,
            attempt_id=attempt_id,
            nonce=NONCE,
            allow_test_root=True,
        )
        self.assertTrue(first.succeeded)
        self.assertTrue(second.succeeded)
        self.assertEqual(before, receipt_path.read_bytes())
        self.assertTrue(self.runtime.open)
        self.assertNotIn("stop-d", self.runtime.events)

    def test_post_start_probe_failure_does_not_fall_back_to_c(self) -> None:
        receipt = self.inspect()
        self.runtime.probe_ok = False
        result = self.apply(receipt)
        self.assertFalse(result.succeeded)
        self.assertTrue(result.rollback_blocked)
        self.assertFalse(self.runtime.legacy_running)
        self.assertEqual(0, self.runtime.start_legacy_count)

    def test_service_start_allows_only_exact_post_state_install_journal_phase(self) -> None:
        path = self.fixture.root / "control" / "writer_handoff_pending.json"
        active = {
            "release_id": self.fixture.baseline.release_id,
            "manifest_sha256": self.fixture.baseline.manifest_sha256,
        }
        blocked = {
            "schema_version": "qrh-writer-handoff-pending/v2",
            "attempt_id": "handoff-fixture",
            "nonce_sha256": "e" * 64,
            "inspection_sha256": "f" * 64,
            "success_receipt_id": "writer-handoff-success-handoff-fixture",
            **active,
            "phase": "legacy_stop_pending",
            "commit_evidence": None,
            "authority": "coordination_only",
        }
        _write_json(path, blocked)
        with self.assertRaises(WindowsServiceError):
            authorize_writer_handoff_service_start(self.fixture.root, active)
        blocked["phase"] = "d_start_authorized"
        _write_json(path, blocked)
        authorize_writer_handoff_service_start(self.fixture.root, active)
        blocked["phase"] = "handoff_committed_receipt_pending"
        blocked["commit_evidence"] = {
            "recorded_at": "2026-08-21T04:01:00.000000Z",
            "final_checkpoint_id": "handoff-final-fixture",
            "final_checkpoint_manifest_sha256": "1" * 64,
            "prehandoff_checkpoint_id": "handoff-pre-d-fixture",
            "prehandoff_checkpoint_manifest_sha256": "2" * 64,
        }
        _write_json(path, blocked)
        authorize_writer_handoff_service_start(self.fixture.root, active)


if __name__ == "__main__":
    unittest.main()
