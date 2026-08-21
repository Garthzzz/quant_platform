from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from quant_hub.collaboration.checkpoint import create_sqlite_checkpoint
from quant_hub.ops.recovery_bundle import build_recovery_bundle
from quant_hub.ops.release_identity import canonical_manifest_bytes, manifest_sha256
from quant_hub.ops.state_only_backup import (
    ActiveBinding,
    StateOnlyBackupError,
    TASK_IDENTITY,
    apply_task_candidate,
    build_gc_roots_report,
    build_state_only_recovery_set,
    build_task_candidate,
    evaluate_state_only_status,
    run_state_only_backup,
    validate_task_candidate,
    verify_state_only_recovery_set,
)
from quant_hub.ops.publish_runtime import OpenSSHRecoveryActions
from quant_hub.ops.windows_service import quant_hub_package_inventory_sha256


def _release_manifest() -> dict[str, object]:
    return {
        "schema_version": "qrh-release-manifest/v1",
        "release_id": "release-state-only-v1",
        "built_at": "2026-08-21T08:00:00Z",
        "application": {
            "commit_sha": "a" * 40,
            "tracked_tree_sha256": "1" * 64,
            "build_tool_version": "state-only-tests/v1",
        },
        "content": {
            "snapshot_id": "snapshot-state-only-v1",
            "source_inventory_sha256": "2" * 64,
            "ir_sha256": "3" * 64,
            "knowledge_sha256": "4" * 64,
            "search_sha256": "5" * 64,
            "knowledge_enrichment": {"status": "pending"},
        },
        "resources": {"inventory_sha256": "6" * 64},
        "state": {
            "compatibility": {
                "comments": {"read": [2], "write": [2]},
                "research_workspace": {"read": [3], "write": [3]},
            }
        },
        "recovery": {
            "compatibility": {
                "checkpoint_manifest_schemas": ["qrh-checkpoint-manifest/v1"],
                "restore_protocol_versions": ["qrh-restore/v1"],
            }
        },
    }


class FakeVM:
    def __init__(self, fixture: "StateOnlyFixture") -> None:
        self.fixture = fixture
        self.cleaned: list[str] = []
        self.fail_cleanup = False
        self.fail_capture = False
        self.reads = 0
        self.drift_after_capture = False

    def read_active_identity(self):
        self.reads += 1
        digest = self.fixture.release_hash
        if self.drift_after_capture and self.reads > 1:
            digest = "f" * 64
        return {
            "release_id": self.fixture.manifest["release_id"],
            "release_manifest_sha256": digest,
        }

    def capture_state_only_checkpoint(
        self, *, release_id, release_manifest_sha256, checkpoint_id
    ):
        if self.fail_capture:
            raise RuntimeError("Authorization: Bearer must-never-enter-audit")
        intake = self.fixture.recovery_root / "checkpoint-intake"
        return create_sqlite_checkpoint(
            sources={"comments": self.fixture.live_state},
            checkpoint_root=intake,
            checkpoint_id=checkpoint_id,
            state_authority_id="state-d-authority",
            captured_under_release_id=release_id,
            captured_under_manifest_sha256=release_manifest_sha256,
            captured_at=self.fixture.now,
            scratch_root=self.fixture.recovery_root / "scratch",
        ).root

    def cleanup_state_only_capture(self, *, checkpoint_id):
        self.cleaned.append(checkpoint_id)
        if self.fail_cleanup:
            raise RuntimeError("SSH cleanup unavailable")


class FakeScheduler:
    def __init__(self) -> None:
        self.digest: str | None = None
        self.registrations = 0

    def inspect(self, candidate):
        return self.digest

    def register(self, candidate):
        self.registrations += 1
        self.digest = str(candidate["contract_sha256"])


class StateOnlyFixture(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.recovery_root = self.root / "recovery"
        self.recovery_root.mkdir()
        self.release = self.root / "release"
        self.release.mkdir()
        self.manifest = _release_manifest()
        self.release_hash = manifest_sha256(self.manifest)
        (self.release / "release_manifest.json").write_bytes(
            canonical_manifest_bytes(self.manifest)
        )
        (self.release / "app.py").write_text("print('ok')\n", encoding="utf-8")
        self.now = datetime(2026, 8, 21, 12, tzinfo=UTC)
        state = self.root / "state"
        state.mkdir()
        self.live_state = state / "comments.sqlite3"
        connection = sqlite3.connect(self.live_state)
        try:
            connection.execute("CREATE TABLE comment(id TEXT PRIMARY KEY, body TEXT)")
            connection.execute("INSERT INTO comment VALUES('c1','fixture')")
            connection.commit()
        finally:
            connection.close()
        base_checkpoint = create_sqlite_checkpoint(
            sources={"comments": self.live_state},
            checkpoint_root=self.root / "base-checkpoints",
            checkpoint_id="checkpoint-static-base",
            state_authority_id="state-d-authority",
            captured_under_release_id=str(self.manifest["release_id"]),
            captured_under_manifest_sha256=self.release_hash,
            captured_at=self.now - timedelta(hours=2),
            scratch_root=self.root / "scratch-base",
        )
        restore_tool = self.root / "restore.py"
        restore_tool.write_text("# fixed restore\n", encoding="utf-8")
        runbook = self.root / "RUNBOOK.md"
        runbook.write_text("# 恢复\n", encoding="utf-8")
        operational = self.root / "operational-source"
        files = {
            "tooling/python/Lib/site-packages/win32/pythonservice.exe": b"service",
            "tooling/python/python.exe": b"python",
            "tooling/python/Lib/site-packages/quant_hub/ops/windows_service.py": b"host",
            "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py": b"entry",
            "tooling/python/Lib/site-packages/quant_hub/ops/vm_deploy_cli.py": b"deploy",
            "tooling/python/Lib/site-packages/quant_hub/ops/publish_recovery_cli.py": b"recover",
            "tooling/python/Lib/site-packages/quant_hub/web/access_gate.py": b"gate",
            "control/deployment_runtime.json": canonical_manifest_bytes(
                {"schema_version": "qrh-vm-deploy-runtime/v1", "fixture": True}
            ),
        }
        for relative, payload in files.items():
            path = operational.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        production = Path(r"D:\quant\quant_platform")
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
        candidate: dict[str, object] = {
            "schema_version": "qrh-windows-service-install-candidate/v1",
            "service_name": "QuantResearchHub",
            "python_class": "quant_hub.ops.windows_service.QuantResearchHubWindowsService",
            "start_type": "automatic",
        }
        for field, relative in bindings.items():
            source = operational.joinpath(*relative.split("/"))
            candidate[field] = str(production.joinpath(*relative.split("/")))
            candidate[f"{field}_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
        package = operational / "tooling/python/Lib/site-packages/quant_hub"
        candidate["quant_hub_package_root"] = str(
            production / "tooling/python/Lib/site-packages/quant_hub"
        )
        candidate["quant_hub_package_inventory_sha256"] = (
            quant_hub_package_inventory_sha256(package)
        )
        (operational / "control" / "service_install_candidate.json").write_bytes(
            canonical_manifest_bytes(candidate)
        )
        base_bundle_scratch = self.root / "base-bundle-scratch"
        base_bundle_scratch.mkdir()
        self.base_bundle = build_recovery_bundle(
            release_root=self.release,
            checkpoint_root=base_checkpoint.root,
            recovery_root=self.recovery_root,
            bundle_id="static-state-only-base",
            created_at="2026-08-21T10:00:00Z",
            restore_tool=restore_tool,
            runbook=runbook,
            operational_root=operational,
            compatibility={"verdict": "compatible", "policy": "expand_only"},
            checkpoint_scratch_root=base_bundle_scratch,
        )
        self.active = ActiveBinding(str(self.manifest["release_id"]), self.release_hash)

    def _new_checkpoint(self, checkpoint_id: str, captured_at: datetime | None = None):
        return create_sqlite_checkpoint(
            sources={"comments": self.live_state},
            checkpoint_root=self.recovery_root / "checkpoint-intake",
            checkpoint_id=checkpoint_id,
            state_authority_id="state-d-authority",
            captured_under_release_id=self.active.release_id,
            captured_under_manifest_sha256=self.active.manifest_sha256,
            captured_at=captured_at or self.now,
            scratch_root=self.root / "checkpoint-scratch",
        )

    def _build_set(self, checkpoint_id: str, captured_at: datetime | None = None):
        checkpoint = self._new_checkpoint(checkpoint_id, captured_at)
        return build_state_only_recovery_set(
            recovery_root=self.recovery_root,
            base_bundle_root=self.base_bundle.root,
            checkpoint_root=checkpoint.root,
            active=self.active,
            attestation_sha256="a" * 64,
            recorded_at=captured_at or self.now,
        )


class StateOnlyBackupTests(StateOnlyFixture):
    def test_two_daily_sets_reuse_static_closure_and_keep_both_gc_roots(self) -> None:
        first = self._build_set("checkpoint-state-day1", self.now)
        second = self._build_set(
            "checkpoint-state-day2", self.now + timedelta(hours=20)
        )
        first_report = verify_state_only_recovery_set(
            first, recovery_root=self.recovery_root
        )
        second_report = verify_state_only_recovery_set(
            second, recovery_root=self.recovery_root
        )
        self.assertTrue(first_report.valid, first_report.errors)
        self.assertTrue(second_report.valid, second_report.errors)
        first_rm = json.loads((first / "recovery_manifest.json").read_text("utf-8"))
        second_rm = json.loads((second / "recovery_manifest.json").read_text("utf-8"))
        self.assertEqual(first_rm["release"], second_rm["release"])
        self.assertEqual(first_rm["closure"], second_rm["closure"])
        self.assertNotEqual(first_rm["checkpoint"], second_rm["checkpoint"])
        roots = build_gc_roots_report(
            recovery_root=self.recovery_root,
            active=self.active,
            report_id="gc-roots-two-days",
            recorded_at=self.now + timedelta(hours=20),
        )
        self.assertEqual(self.release_hash, roots["active_release_manifest_sha256"])
        self.assertGreaterEqual(len(roots["retained_checkpoint_roots"]), 3)
        self.assertGreaterEqual(len(roots["retained_recovery_manifest_roots"]), 3)
        self.assertFalse(roots["deletion_authorized"])

    def test_rpo_uses_captured_at_and_corrupt_closure_fails(self) -> None:
        recovery_set = self._build_set("checkpoint-rpo", self.now)
        protected = evaluate_state_only_status(
            recovery_root=self.recovery_root,
            now=self.now + timedelta(hours=23),
            latest_attempt_succeeded=True,
            failure_domain_attested=True,
        )
        self.assertEqual("protected", protected.status)
        degraded = evaluate_state_only_status(
            recovery_root=self.recovery_root,
            now=self.now + timedelta(hours=25),
            latest_attempt_succeeded=True,
            failure_domain_attested=True,
        )
        self.assertEqual("degraded", degraded.status)
        self.assertIn("checkpoint_rpo_exceeded", degraded.reason_codes)
        (recovery_set / "static_bundle_ref.json").write_bytes(b"corrupt")
        failed = evaluate_state_only_status(
            recovery_root=self.recovery_root,
            now=self.now + timedelta(hours=1),
            latest_attempt_succeeded=True,
            failure_domain_attested=True,
        )
        self.assertEqual("failed", failed.status)
        self.assertIn("recovery_closure_invalid", failed.reason_codes)

    def test_rpo_does_not_count_checkpoint_from_another_active_release(self) -> None:
        self._build_set("checkpoint-prior-release", self.now)
        another_active = ActiveBinding("release-new-v2", "f" * 64)
        status = evaluate_state_only_status(
            recovery_root=self.recovery_root,
            now=self.now + timedelta(hours=1),
            latest_attempt_succeeded=True,
            failure_domain_attested=True,
            current_active=another_active,
            active_identity_verified=True,
        )
        self.assertEqual("failed", status.status)
        self.assertIn("no_fully_verified_checkpoint", status.reason_codes)

    def test_unverifiable_current_active_is_failed_not_degraded(self) -> None:
        self._build_set("checkpoint-active-unknown", self.now)
        status = evaluate_state_only_status(
            recovery_root=self.recovery_root,
            now=self.now + timedelta(hours=1),
            latest_attempt_succeeded=False,
            failure_domain_attested=True,
            active_identity_verified=False,
        )
        self.assertEqual("failed", status.status)
        self.assertEqual(
            ("current_active_identity_unavailable",), status.reason_codes
        )

    def test_run_is_changed_state_only_and_cleans_vm_staging(self) -> None:
        # A dead predecessor may leave the lock audit file behind.  The OS
        # lock, rather than sentinel existence, controls ownership.
        lock = (
            self.recovery_root
            / "state-only"
            / "control"
            / "state-only-backup.lock"
        )
        lock.parent.mkdir(parents=True)
        lock.write_text("stale-process-token\n", encoding="ascii")
        vm = FakeVM(self)
        recovery = SimpleNamespace(
            recovery_root=self.recovery_root,
            state_authority_id="state-d-authority",
        )
        config = SimpleNamespace(recovery=recovery)
        identities = iter(("a" * 32, "b" * 32))
        with patch(
            "quant_hub.ops.state_only_backup.RecoveryProtectionCoordinator.preflight"
        ), patch(
            "quant_hub.ops.state_only_backup._attestation_sha", return_value="a" * 64
        ):
            result = run_state_only_backup(
                config=config,
                vm=vm,
                now=lambda: self.now,
                id_factory=lambda: next(identities),
            )
        self.assertTrue(result.succeeded)
        self.assertEqual("protected", result.status.status)
        self.assertEqual([result.checkpoint_id], vm.cleaned)
        self.assertFalse(
            (self.recovery_root / "checkpoint-intake" / str(result.checkpoint_id)).exists()
        )
        self.assertTrue(
            (
                self.recovery_root
                / "state-only"
                / "sets"
                / str(result.recovery_set_id)
            ).is_dir()
        )

    def test_success_after_rpo_gap_preserves_pre_run_degraded_alert(self) -> None:
        self._build_set(
            "checkpoint-before-scheduler-gap", self.now - timedelta(hours=25)
        )
        vm = FakeVM(self)
        config = SimpleNamespace(
            recovery=SimpleNamespace(
                recovery_root=self.recovery_root,
                state_authority_id="state-d-authority",
            )
        )
        identities = iter(("1" * 32, "2" * 32))
        with patch(
            "quant_hub.ops.state_only_backup.RecoveryProtectionCoordinator.preflight"
        ), patch(
            "quant_hub.ops.state_only_backup._attestation_sha", return_value="a" * 64
        ):
            result = run_state_only_backup(
                config=config,
                vm=vm,
                now=lambda: self.now,
                id_factory=lambda: next(identities),
            )
        self.assertTrue(result.succeeded)
        self.assertEqual("protected", result.status.status)
        observations = list(
            (
                self.recovery_root
                / "state-only"
                / "audit"
                / "status-observations"
            ).glob("*.json")
        )
        self.assertEqual(1, len(observations))
        observation = json.loads(observations[0].read_text(encoding="utf-8"))
        self.assertEqual("degraded", observation["status"])
        self.assertIn("checkpoint_rpo_exceeded", observation["reason_codes"])
        alerts = list(
            (self.recovery_root / "state-only" / "alerts").glob("*pre-run*.json")
        )
        self.assertEqual(1, len(alerts))

    def test_failure_is_redacted_and_degrades_without_false_receipt(self) -> None:
        # Establish one recent valid recovery point, then fail the next capture.
        self._build_set("checkpoint-prior-valid", self.now - timedelta(hours=1))
        vm = FakeVM(self)
        vm.fail_capture = True
        config = SimpleNamespace(
            recovery=SimpleNamespace(
                recovery_root=self.recovery_root,
                state_authority_id="state-d-authority",
            )
        )
        identities = iter(("c" * 32, "d" * 32))
        with patch(
            "quant_hub.ops.state_only_backup.RecoveryProtectionCoordinator.preflight"
        ), patch(
            "quant_hub.ops.state_only_backup._attestation_sha", return_value="a" * 64
        ):
            result = run_state_only_backup(
                config=config,
                vm=vm,
                now=lambda: self.now,
                id_factory=lambda: next(identities),
            )
        self.assertFalse(result.succeeded)
        self.assertEqual("degraded", result.status.status)
        self.assertIn("latest_checkpoint_attempt_failed", result.status.reason_codes)
        audit = self.recovery_root / "state-only" / "audit" / "attempts"
        body = next(audit.glob("*.json")).read_text(encoding="utf-8")
        logs = (
            self.recovery_root / "state-only" / "logs" / "state-only-backup.jsonl"
        ).read_text(encoding="utf-8")
        self.assertNotIn("Bearer", body + logs)
        self.assertNotIn("must-never-enter-audit", body + logs)
        self.assertEqual([result.checkpoint_id], vm.cleaned)

    def test_vm_cleanup_failure_marks_attempt_degraded(self) -> None:
        vm = FakeVM(self)
        vm.fail_cleanup = True
        config = SimpleNamespace(
            recovery=SimpleNamespace(
                recovery_root=self.recovery_root,
                state_authority_id="state-d-authority",
            )
        )
        identities = iter(("e" * 32, "f" * 32))
        with patch(
            "quant_hub.ops.state_only_backup.RecoveryProtectionCoordinator.preflight"
        ), patch(
            "quant_hub.ops.state_only_backup._attestation_sha", return_value="a" * 64
        ):
            result = run_state_only_backup(
                config=config,
                vm=vm,
                now=lambda: self.now,
                id_factory=lambda: next(identities),
            )
        self.assertFalse(result.succeeded)
        self.assertEqual("vm_staging_cleanup_failed", result.error_code)
        self.assertEqual("degraded", result.status.status)
        self.assertIsNotNone(result.recovery_set_id)

    def test_active_drift_during_capture_fails_current_protection(self) -> None:
        self._build_set("checkpoint-before-active-drift", self.now)
        vm = FakeVM(self)
        vm.drift_after_capture = True
        config = SimpleNamespace(
            recovery=SimpleNamespace(
                recovery_root=self.recovery_root,
                state_authority_id="state-d-authority",
            )
        )
        identities = iter(("7" * 32, "8" * 32))
        with patch(
            "quant_hub.ops.state_only_backup.RecoveryProtectionCoordinator.preflight"
        ), patch(
            "quant_hub.ops.state_only_backup._attestation_sha", return_value="a" * 64
        ):
            result = run_state_only_backup(
                config=config,
                vm=vm,
                now=lambda: self.now,
                id_factory=lambda: next(identities),
            )
        self.assertFalse(result.succeeded)
        self.assertEqual("failed", result.status.status)
        self.assertEqual(
            ("current_active_identity_unavailable",), result.status.reason_codes
        )

    def test_developer_task_candidate_is_single_idempotent_and_explicit(self) -> None:
        candidate = build_task_candidate(
            config_path=self.root / "protected" / "publish.json",
            project_root=self.root / "project",
            operational_python=self.root / "operational" / "python.exe",
        )
        validate_task_candidate(candidate)
        self.assertEqual(TASK_IDENTITY, candidate["task_identity"])
        self.assertEqual("developer_recovery_host", candidate["host_role"])
        self.assertFalse(candidate["vm_task_registration"])
        self.assertFalse(candidate["credential_material_embedded"])
        self.assertEqual(3, candidate["schedule"]["retry_count"])
        self.assertEqual(15, candidate["schedule"]["retry_interval_minutes"])
        scheduler = FakeScheduler()
        with self.assertRaises(StateOnlyBackupError):
            apply_task_candidate(
                candidate, adapter=scheduler, allow_os_registration=False
            )
        self.assertEqual(
            "applied",
            apply_task_candidate(
                candidate, adapter=scheduler, allow_os_registration=True
            ),
        )
        self.assertEqual(
            "unchanged",
            apply_task_candidate(
                candidate, adapter=scheduler, allow_os_registration=True
            ),
        )
        self.assertEqual(1, scheduler.registrations)
        tampered = json.loads(json.dumps(candidate))
        tampered["task_identity"] = r"\QuantResearchHub\SecondBackup"
        body = dict(tampered)
        body.pop("contract_sha256")
        tampered["contract_sha256"] = manifest_sha256(body)
        with self.assertRaises(StateOnlyBackupError):
            validate_task_candidate(tampered)

    def test_openssh_state_only_control_uses_only_fixed_recovery_cli(self) -> None:
        actions = object.__new__(OpenSSHRecoveryActions)
        actions.runtime = SimpleNamespace(
            vm=SimpleNamespace(root=Path(r"D:\quant\quant_platform"))
        )
        calls: list[tuple[str, ...]] = []

        def remote(arguments):
            calls.append(tuple(arguments))
            if "identify-active" in arguments:
                return {
                    "schema_version": "qrh-state-only-active-identity/v1",
                    "release_id": self.active.release_id,
                    "release_manifest_sha256": self.active.manifest_sha256,
                }
            return {
                "schema_version": "qrh-publish-checkpoint-cleanup/v1",
                "checkpoint_id": "checkpoint-fixed",
                "staging_removed": True,
            }

        actions._remote = remote
        self.assertEqual(
            self.release_hash,
            actions.read_active_identity()["release_manifest_sha256"],
        )
        actions.cleanup_state_only_capture(checkpoint_id="checkpoint-fixed")
        self.assertTrue(all("quant_hub.ops.publish_recovery_cli" in call for call in calls))
        self.assertIn("identify-active", calls[0])
        self.assertIn("cleanup-capture", calls[1])
        self.assertTrue(all(r"D:\quant\quant_platform" in call for call in calls))


class VMStagingCleanupTests(unittest.TestCase):
    def test_cleanup_removes_only_one_exact_checkpoint_and_scratch(self) -> None:
        from quant_hub.ops import publish_recovery_cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "tmp" / "publish-recovery"
            for relative in (
                "checkpoints/checkpoint-target/payload",
                "scratch/checkpoint-target/temp",
                "checkpoints/checkpoint-other/payload",
            ):
                path = target / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture", encoding="utf-8")
            with patch.object(publish_recovery_cli, "_root", return_value=root), patch.object(
                publish_recovery_cli, "_child", side_effect=lambda path: path
            ), patch.object(
                publish_recovery_cli,
                "verify_existing_vm_write_path",
                side_effect=lambda path, **_: path,
            ):
                result = publish_recovery_cli.cleanup_capture(
                    vm_root=root, checkpoint_id="checkpoint-target"
                )
            self.assertTrue(result["staging_removed"])
            self.assertFalse((target / "checkpoints/checkpoint-target").exists())
            self.assertFalse((target / "scratch/checkpoint-target").exists())
            self.assertTrue((target / "checkpoints/checkpoint-other/payload").is_file())


if __name__ == "__main__":
    unittest.main()
