from __future__ import annotations

from datetime import UTC, datetime, timedelta
from contextlib import contextmanager
import base64
import hashlib
import json
import multiprocessing
from pathlib import Path
import sqlite3
import subprocess
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from quant_hub.collaboration.checkpoint import create_sqlite_checkpoint
from quant_hub.ops.recovery_bundle import build_recovery_bundle
from quant_hub.ops.failure_domain import attest_failure_domain, canonical_bytes as failure_bytes, collect_host_facts
from quant_hub.ops.release_identity import canonical_manifest_bytes, manifest_sha256
from quant_hub.ops.stage_closure import DirectoryEvidenceResolver, artifact_ref, build_measured_prior_binding
from quant_hub.ops.state_only_backup import (
    ActiveBinding,
    PowerShellTaskSchedulerAdapter,
    StateOnlyBackupError,
    TASK_IDENTITY,
    TaskInspection,
    _job_lock,
    _normalize_windows_sid,
    apply_task_candidate,
    build_gc_roots_report,
    build_state_only_recovery_set,
    build_task_candidate,
    build_task_inspection_artifact,
    evaluate_state_only_status,
    run_state_only_backup,
    validate_task_candidate,
    verify_state_only_recovery_set,
)
from quant_hub.ops.publish_runtime import OpenSSHRecoveryActions, PublishRuntimeError
from quant_hub.ops.publish_adapters import PublishAdapterError
from quant_hub.ops.windows_service import quant_hub_package_inventory_sha256


TEST_TASK_SID = "S-1-5-21-1"
TEST_TASK_SID_SHA256 = hashlib.sha256(TEST_TASK_SID.encode("ascii")).hexdigest()


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


def _scheduler_xml(candidate: dict[str, object], *, extra_trigger: bool = False) -> bytes:
    action = candidate["action"]
    assert isinstance(action, dict)
    extra = "<TimeTrigger><StartBoundary>2026-08-22T04:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger>" if extra_trigger else ""
    return f'''<?xml version="1.0" encoding="UTF-8"?><Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Description>QRH_STATE_ONLY_CONTRACT:{candidate["contract_sha256"]}</Description><URI>\\QuantResearchHub\\StateOnlyBackup</URI></RegistrationInfo><Triggers><CalendarTrigger><StartBoundary>2026-08-22T03:00:00</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>{extra}</Triggers><Principals><Principal id="Author"><UserId>{TEST_TASK_SID}</UserId><LogonType>S4U</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT2H</ExecutionTimeLimit><Priority>7</Priority><RestartOnFailure><Interval>PT15M</Interval><Count>3</Count></RestartOnFailure></Settings><Actions Context="Author"><Exec><Command>{action["executable"]}</Command><Arguments>{subprocess.list2cmdline(action["arguments"])}</Arguments><WorkingDirectory>{action["working_directory"]}</WorkingDirectory></Exec></Actions></Task>'''.encode()


def _hold_lock(root: str, ready, release) -> None:
    with _job_lock(Path(root)) as acquired:
        ready.put(acquired)
        release.get(timeout=15)


def _probe_lock(root: str, result) -> None:
    with _job_lock(Path(root)) as acquired:
        result.put(acquired)


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
        if self.digest is None:
            return TaskInspection("missing", None, None, None, None)
        raw = _scheduler_xml(dict(candidate))
        return TaskInspection(
            "exact", self.digest, hashlib.sha256(raw).hexdigest(),
            TEST_TASK_SID_SHA256, base64.b64encode(raw).decode(),
        )

    def register(self, candidate):
        self.registrations += 1
        self.digest = str(candidate["contract_sha256"])


class StateOnlyFixture(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        token_patch = patch(
            "quant_hub.ops.state_only_backup._current_token_sid_sha256",
            return_value=TEST_TASK_SID_SHA256,
        )
        token_patch.start()
        self.addCleanup(token_patch.stop)
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
        self.operational = operational
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
        prior_manifest = json.loads(json.dumps(self.manifest))
        prior_manifest["release_id"] = "release-state-only-prior"
        prior_manifest["application"]["commit_sha"] = "b" * 40
        prior_manifest["content"]["snapshot_id"] = "snapshot-state-only-prior"
        prior_release = self.root / "prior-release"
        prior_release.mkdir()
        (prior_release / "release_manifest.json").write_bytes(
            canonical_manifest_bytes(prior_manifest)
        )
        (prior_release / "app.py").write_text("print('prior')\n", encoding="utf-8")
        self.prior = ActiveBinding(
            str(prior_manifest["release_id"]), manifest_sha256(prior_manifest)
        )
        prior_checkpoint = create_sqlite_checkpoint(
            sources={"comments": self.live_state},
            checkpoint_root=self.root / "prior-checkpoints",
            checkpoint_id="checkpoint-static-prior",
            state_authority_id="state-d-authority",
            captured_under_release_id=self.prior.release_id,
            captured_under_manifest_sha256=self.prior.manifest_sha256,
            captured_at=self.now - timedelta(days=1),
            scratch_root=self.root / "scratch-prior",
        )
        prior_scratch = self.root / "prior-bundle-scratch"
        prior_scratch.mkdir()
        self.prior_bundle = build_recovery_bundle(
            release_root=prior_release,
            checkpoint_root=prior_checkpoint.root,
            recovery_root=self.recovery_root,
            bundle_id="static-state-only-prior",
            created_at="2026-08-20T10:00:00Z",
            restore_tool=restore_tool,
            runbook=runbook,
            operational_root=operational,
            compatibility={"verdict": "compatible", "policy": "expand_only"},
            checkpoint_scratch_root=prior_scratch,
        )
        rollback = {
            "schema_version": "qrh-d-prior-rollback-receipt/v1",
            "receipt_id": "rollback-fixture",
            "observed_at": "2026-08-21T10:30:00Z",
            "authority": "evidence_only",
            "active_release": {
                "release_id": self.active.release_id,
                "manifest_sha256": self.active.manifest_sha256,
            },
            "prior_release": {
                "release_id": self.prior.release_id,
                "manifest_sha256": self.prior.manifest_sha256,
            },
            "verification": {
                "prior_activated": True,
                "health": True,
                "writer_fence": True,
                "active_restored": True,
            },
        }
        rollback["receipt_sha256"] = manifest_sha256(rollback)
        rollback_path = self.recovery_root / "stage5" / "d_prior" / "rollback_receipt.json"
        rollback_path.parent.mkdir(parents=True)
        rollback_raw = canonical_manifest_bytes(rollback)
        rollback_path.write_bytes(rollback_raw)
        measured = build_measured_prior_binding(
            observed_at="2026-08-21T11:00:00Z",
            rollback_receipt_ref=artifact_ref(
                kind="d_prior_rollback_receipt",
                locator="stage5/d_prior/rollback_receipt.json",
                raw_bytes=rollback_raw,
            ),
            resolver=DirectoryEvidenceResolver(self.recovery_root),
        )
        self.measured_prior_sha256 = str(measured["binding_sha256"])
        measured_path = (
            self.recovery_root
            / "state-only"
            / "control"
            / "measured_prior_release.json"
        )
        measured_path.parent.mkdir(parents=True, exist_ok=True)
        measured_path.write_bytes(canonical_manifest_bytes(measured))

        recovery_facts = collect_host_facts(
            self.recovery_root, role="recovery", tool_version="tests/v1"
        )
        production = dict(recovery_facts)
        production.update(
            {
                "role": "production",
                "host_name": "production-fixture",
                "machine_identity": "fixture-production-machine",
                "canonical_path": r"D:\quant\quant_platform",
                "volume_identity": "fixture-production-volume",
                "storage_backend": "fixture-production-storage",
                "storage_authority": "fixture-production-machine|fixture-production-volume|fixture-production-storage",
            }
        )
        production.pop("facts_sha256")
        production["facts_sha256"] = hashlib.sha256(
            failure_bytes(production)
        ).hexdigest()
        probe = {
            "schema_version": "qrh-recovery-independence-probe/v2",
            "production_root_available": False,
            "recovery_bundle_readable": True,
            "closure_verified": True,
            "empty_root_precondition": True,
            "bundle_id": "scheduler-fixture",
            "release_id": self.active.release_id,
            "release_manifest_sha256": self.active.manifest_sha256,
            "bundle_inventory_sha256": "8" * 64,
            "materialization_event_id": "cold-materialization-scheduler-fixture",
            "materialization_event_sha256": "9" * 64,
            "probe_tool_sha256": "a" * 64,
        }
        attestation = attest_failure_domain(
            production_facts=production,
            recovery_facts=recovery_facts,
            independence_probe=probe,
            observed_at="2026-08-21T11:30:00Z",
        ).payload
        self.attestation_path = self.recovery_root / "failure-domain.json"
        self.attestation_path.write_bytes(canonical_manifest_bytes(attestation))
        self.schedule_project = self.root / "schedule-project"
        self.schedule_project.mkdir()
        schedule_config_root = self.root / "schedule-config"
        schedule_config_root.mkdir()
        self.schedule_config = schedule_config_root / "publish.json"
        self.schedule_config.write_bytes(b"{}")
        self.schedule_python = operational / "tooling" / "python" / "python.exe"
        runtime_patch = patch(
            "quant_hub.ops.state_only_backup.RuntimePublishConfig.load",
            return_value=SimpleNamespace(
                project_root=self.schedule_project,
                github=SimpleNamespace(owner="owner", repository="quant-platform"),
                recovery=SimpleNamespace(
                    recovery_root=self.recovery_root,
                    operational_root=self.operational,
                    attestation_path=self.attestation_path,
                ),
            ),
        )
        runtime_patch.start()
        self.addCleanup(runtime_patch.stop)
        authority_material = {
            "schema_version": "qrh-state-only-scheduled-task-authority/v1",
            "authorized_at": "2026-08-21T11:45:00Z",
            "authority": "stage5_exact_identity",
            "repository": {
                "repository_id": "repository-state-only-tests",
                "full_name": "owner/quant-platform",
                "commit_sha": self.manifest["application"]["commit_sha"],
                "tracked_tree_sha256": self.manifest["application"]["tracked_tree_sha256"],
            },
            "release": {
                "release_id": self.active.release_id,
                "manifest_sha256": self.active.manifest_sha256,
                "snapshot_id": self.manifest["content"]["snapshot_id"],
            },
            "paths": {
                "project_root": str(self.schedule_project),
                "config_path": str(self.schedule_config),
                "operational_root": str(self.operational),
                "recovery_root": str(self.recovery_root),
                "operational_python": str(self.schedule_python),
                "failure_domain_attestation_path": str(self.attestation_path),
            },
            "bytes": {
                "config_sha256": hashlib.sha256(self.schedule_config.read_bytes()).hexdigest(),
                "operational_python_sha256": hashlib.sha256(self.schedule_python.read_bytes()).hexdigest(),
            },
            "failure_domain_attestation_sha256": hashlib.sha256(
                self.attestation_path.read_bytes()
            ).hexdigest(),
        }
        authority = dict(authority_material)
        authority["authorization_id"] = (
            "task-authority-" + manifest_sha256(authority_material)[:32]
        )
        authority["authority_sha256"] = manifest_sha256(authority)
        self.task_authority_path = (
            self.recovery_root / "state-only/control/scheduled_task_authority.json"
        )
        self.task_authority_path.parent.mkdir(parents=True, exist_ok=True)
        self.task_authority_path.write_bytes(canonical_manifest_bytes(authority))

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

    def _task_candidate(self):
        with patch(
            "quant_hub.ops.state_only_backup._current_token_sid_sha256",
            return_value=TEST_TASK_SID_SHA256,
        ):
            return build_task_candidate(
                config_path=self.schedule_config,
                project_root=self.schedule_project,
                operational_root=self.operational,
                operational_python=self.schedule_python,
                recovery_root=self.recovery_root,
                failure_domain_attestation_path=self.attestation_path,
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
            measured_prior=self.prior,
            measured_prior_binding_sha256=self.measured_prior_sha256,
            report_id="gc-roots-two-days",
            recorded_at=self.now + timedelta(hours=20),
        )
        self.assertEqual(self.release_hash, roots["active_release_manifest_sha256"])
        self.assertEqual(
            self.prior.manifest_sha256,
            roots["measured_prior_release_manifest_sha256"],
        )
        self.assertEqual(
            self.measured_prior_sha256, roots["measured_prior_binding_sha256"]
        )
        self.assertGreaterEqual(len(roots["retained_checkpoint_roots"]), 3)
        self.assertGreaterEqual(len(roots["retained_recovery_manifest_roots"]), 3)
        self.assertFalse(roots["deletion_authorized"])

    def test_gc_refuses_an_unretained_or_same_as_active_measured_prior(self) -> None:
        with self.assertRaises(StateOnlyBackupError):
            build_gc_roots_report(
                recovery_root=self.recovery_root,
                active=self.active,
                measured_prior=self.active,
                measured_prior_binding_sha256=self.measured_prior_sha256,
                report_id="gc-roots-same-prior",
                recorded_at=self.now,
            )
        with self.assertRaises(StateOnlyBackupError):
            build_gc_roots_report(
                recovery_root=self.recovery_root,
                active=self.active,
                measured_prior=ActiveBinding("release-not-retained", "8" * 64),
                measured_prior_binding_sha256=self.measured_prior_sha256,
                report_id="gc-roots-unretained-prior",
                recorded_at=self.now,
            )

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
        lock.parent.mkdir(parents=True, exist_ok=True)
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

    def test_missing_measured_prior_fails_before_capture_and_emits_no_gc(self) -> None:
        (
            self.recovery_root
            / "state-only"
            / "control"
            / "measured_prior_release.json"
        ).unlink()
        vm = FakeVM(self)
        config = SimpleNamespace(
            recovery=SimpleNamespace(
                recovery_root=self.recovery_root,
                state_authority_id="state-d-authority",
            )
        )
        with patch(
            "quant_hub.ops.state_only_backup.RecoveryProtectionCoordinator.preflight"
        ):
            result = run_state_only_backup(
                config=config,
                vm=vm,
                now=lambda: self.now,
                id_factory=lambda: "3" * 32,
            )
        self.assertFalse(result.succeeded)
        self.assertEqual("measured_prior_unavailable", result.error_code)
        self.assertIsNone(result.checkpoint_id)
        self.assertFalse(
            (self.recovery_root / "state-only" / "audit" / "gc-roots").exists()
        )

    def test_lock_conflict_is_a_failed_observation_and_does_not_touch_vm(self) -> None:
        @contextmanager
        def denied_lock(_root):
            yield False

        vm = FakeVM(self)
        config = SimpleNamespace(
            recovery=SimpleNamespace(
                recovery_root=self.recovery_root,
                state_authority_id="state-d-authority",
            )
        )
        with patch("quant_hub.ops.state_only_backup._job_lock", denied_lock):
            result = run_state_only_backup(
                config=config,
                vm=vm,
                now=lambda: self.now,
                id_factory=lambda: "4" * 32,
            )
        self.assertFalse(result.succeeded)
        self.assertEqual("state_only_backup_locked", result.error_code)
        self.assertEqual(("state_only_backup_locked",), result.status.reason_codes)
        self.assertEqual(0, vm.reads)
        conflicts = list(
            (
                self.recovery_root / "state-only" / "audit" / "lock-conflicts"
            ).glob("*.json")
        )
        self.assertEqual(1, len(conflicts))
        self.assertTrue(
            list((self.recovery_root / "state-only" / "alerts").glob("*lock-conflict*"))
        )

    def test_job_lock_rejects_a_real_second_process(self) -> None:
        context = multiprocessing.get_context("spawn")
        ready = context.Queue()
        release = context.Queue()
        result = context.Queue()
        lock_root = self.root / "two-process-lock"
        holder = context.Process(
            target=_hold_lock, args=(str(lock_root), ready, release)
        )
        contender = context.Process(
            target=_probe_lock, args=(str(lock_root), result)
        )
        holder.start()
        try:
            self.assertTrue(ready.get(timeout=15))
            contender.start()
            self.assertFalse(result.get(timeout=15))
            contender.join(timeout=15)
            self.assertEqual(0, contender.exitcode)
        finally:
            release.put(True)
            holder.join(timeout=15)
            if holder.is_alive():
                holder.terminate()
                holder.join(timeout=5)
        self.assertEqual(0, holder.exitcode)

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
        candidate = self._task_candidate()
        validate_task_candidate(candidate)
        self.assertEqual(
            "qrh-state-only-scheduled-task/v5-raw-xml-bound",
            candidate["schema_version"],
        )
        self.assertEqual(TASK_IDENTITY, candidate["task_identity"])
        self.assertEqual("attested_recovery_host", candidate["host_role"])
        self.assertFalse(candidate["vm_task_registration"])
        self.assertFalse(candidate["credential_material_embedded"])
        self.assertEqual(3, candidate["schedule"]["retry_count"])
        self.assertEqual(15, candidate["schedule"]["retry_interval_minutes"])
        self.assertEqual(
            "recovery_host_local_floating", candidate["schedule"]["timezone"]
        )
        self.assertTrue(candidate["schedule"]["enabled"])
        self.assertTrue(candidate["schedule"]["run_only_if_network_available"])
        self.assertEqual("PT2H", candidate["schedule"]["execution_time_limit"])
        self.assertEqual(
            {
                "disallow_start_if_on_batteries": True,
                "stop_if_going_on_batteries": True,
                "allow_hard_terminate": True,
                "allow_start_on_demand": True,
                "hidden": False,
                "run_only_if_idle": False,
                "wake_to_run": False,
                "idle_stop_on_end": True,
                "idle_restart": False,
                "priority": 7,
            },
            {
                name: candidate["schedule"][name]
                for name in (
                    "disallow_start_if_on_batteries",
                    "stop_if_going_on_batteries",
                    "allow_hard_terminate",
                    "allow_start_on_demand",
                    "hidden",
                    "run_only_if_idle",
                    "wake_to_run",
                    "idle_stop_on_end",
                    "idle_restart",
                    "priority",
                )
            },
        )
        self.assertEqual(
            TEST_TASK_SID_SHA256, candidate["principal"]["token_sid_sha256"]
        )
        self.assertEqual(
            "state-only/control/scheduled_task_authority.json",
            candidate["authority_ref"]["locator"],
        )
        self.assertEqual(self.active.release_id, candidate["release_binding"]["release_id"])
        self.assertEqual(
            hashlib.sha256(self.schedule_python.read_bytes()).hexdigest(),
            candidate["action"]["executable_sha256"],
        )
        scheduler = FakeScheduler()
        with self.assertRaises(StateOnlyBackupError):
            apply_task_candidate(
                candidate, adapter=scheduler, allow_os_registration=False
            )
        self.assertEqual(
            "applied",
            apply_task_candidate(
                candidate, adapter=scheduler, allow_os_registration=True
            ).status,
        )
        self.assertEqual(
            "unchanged",
            apply_task_candidate(
                candidate, adapter=scheduler, allow_os_registration=True
            ).status,
        )
        self.assertEqual(1, scheduler.registrations)
        tampered = json.loads(json.dumps(candidate))
        tampered["task_identity"] = r"\QuantResearchHub\SecondBackup"
        body = dict(tampered)
        body.pop("contract_sha256")
        tampered["contract_sha256"] = manifest_sha256(body)
        with self.assertRaises(StateOnlyBackupError):
            validate_task_candidate(tampered)

        disabled = json.loads(json.dumps(candidate))
        disabled["schedule"]["enabled"] = False
        disabled_body = dict(disabled)
        disabled_body.pop("contract_sha256")
        disabled["contract_sha256"] = manifest_sha256(disabled_body)
        with self.assertRaises(StateOnlyBackupError):
            validate_task_candidate(disabled)

        forged_sid = json.loads(json.dumps(candidate))
        forged_sid["principal"]["token_sid_sha256"] = "f" * 64
        forged_body = dict(forged_sid)
        forged_body.pop("contract_sha256")
        forged_sid["contract_sha256"] = manifest_sha256(forged_body)
        with self.assertRaises(StateOnlyBackupError):
            validate_task_candidate(forged_sid)

        executable_tamper = self.schedule_python.read_bytes()
        self.schedule_python.write_bytes(b"tampered")
        try:
            with self.assertRaises(StateOnlyBackupError):
                validate_task_candidate(candidate)
        finally:
            self.schedule_python.write_bytes(executable_tamper)

        unauthorized_project = self.root / "unauthorized-project"
        unauthorized_project.mkdir()
        with self.assertRaisesRegex(StateOnlyBackupError, "not pre-authorized"):
            build_task_candidate(
                config_path=self.schedule_config,
                project_root=unauthorized_project,
                operational_root=self.operational,
                operational_python=self.schedule_python,
                recovery_root=self.recovery_root,
                failure_domain_attestation_path=self.attestation_path,
            )

        for config_error in (
            PublishRuntimeError("invalid protected config"),
            PublishAdapterError("invalid protected transport config"),
        ):
            with self.subTest(config_error=type(config_error).__name__), patch(
                "quant_hub.ops.state_only_backup.RuntimePublishConfig.load",
                side_effect=config_error,
            ) as loader:
                with self.assertRaisesRegex(StateOnlyBackupError, "protected config failed"):
                    build_task_candidate(
                        config_path=self.schedule_config,
                        project_root=self.schedule_project,
                        operational_root=self.operational,
                        operational_python=self.schedule_python,
                        recovery_root=self.recovery_root,
                        failure_domain_attestation_path=self.attestation_path,
                    )
                loader.assert_called_once_with(
                    self.schedule_config, expected_project_root=self.schedule_project
                )

        forged_project = json.loads(json.dumps(candidate))
        forged_project["action"]["project_root"] = str(unauthorized_project)
        forged_project["action"]["arguments"][8] = str(unauthorized_project)
        forged_body = dict(forged_project)
        forged_body.pop("contract_sha256")
        forged_project["contract_sha256"] = manifest_sha256(forged_body)
        with self.assertRaisesRegex(StateOnlyBackupError, "pre-authorized"):
            validate_task_candidate(forged_project)

    def test_scheduler_inspection_binds_semantics_and_exported_xml(self) -> None:
        candidate = self._task_candidate()
        for subauthority_count in (14, 15):
            canonical_sid = "S-1-5-" + "-".join(
                str(index) for index in range(1, subauthority_count + 1)
            )
            padded_sid = " s-01-005-" + "-".join(
                f"{index:03d}" for index in range(1, subauthority_count + 1)
            ) + " "
            normalized = _normalize_windows_sid(padded_sid)
            with self.subTest(subauthority_count=subauthority_count):
                self.assertEqual(canonical_sid, normalized)
                self.assertEqual(
                    hashlib.sha256(canonical_sid.encode("ascii")).hexdigest(),
                    hashlib.sha256(normalized.encode("ascii")).hexdigest(),
                )
        too_many_subauthorities = "S-1-5-" + "-".join(
            str(index) for index in range(1, 17)
        )
        with self.assertRaisesRegex(StateOnlyBackupError, "Windows SID is invalid"):
            _normalize_windows_sid(too_many_subauthorities)
        raw = _scheduler_xml(dict(candidate))
        raw_sha = hashlib.sha256(raw).hexdigest()
        raw_b64 = base64.b64encode(raw).decode()
        scripts: list[str] = []

        def exact(script: str):
            scripts.append(script)
            return SimpleNamespace(
                returncode=0,
                stdout=f"xml|{raw_b64}\n",
            )

        adapter = PowerShellTaskSchedulerAdapter()
        with patch.object(adapter, "_run", side_effect=exact):
            inspection = adapter.inspect(candidate)
        self.assertEqual("exact", inspection.status)
        self.assertEqual(raw_sha, inspection.task_xml_sha256)
        script = scripts[0]
        for required in ("Get-ScheduledTask", "Export-ScheduledTask", "UTF8.GetBytes"):
            self.assertIn(required, script)
        for forbidden in (
            "$t.", "Description-match", "Principal.UserId", "Settings.Enabled",
            "StartBoundary", "sidHash", "xmlHash", "$ok=", "$v=",
        ):
            self.assertNotIn(forbidden, script)
        drift_raw = _scheduler_xml(dict(candidate), extra_trigger=True)
        with patch.object(
            adapter,
            "_run",
            return_value=SimpleNamespace(
                returncode=0,
                stdout=f"xml|{base64.b64encode(drift_raw).decode()}\n",
            ),
        ):
            self.assertEqual("drift", adapter.inspect(candidate).status)
        with patch(
            "quant_hub.ops.state_only_backup._current_token_sid_sha256",
            return_value="f" * 64,
        ), patch.object(adapter, "_run") as runner:
            with self.assertRaises(StateOnlyBackupError):
                adapter.register(candidate)
            runner.assert_not_called()
        registration_scripts: list[str] = []
        with patch.object(
            adapter,
            "_run",
            side_effect=lambda script: (
                registration_scripts.append(script)
                or SimpleNamespace(returncode=0, stdout="")
            ),
        ):
            adapter.register(candidate)
        self.assertIn("New-ScheduledTaskPrincipal -UserId $sid", registration_scripts[0])
        for forbidden in ("$account", "USERNAME", "USERDOMAIN"):
            self.assertNotIn(forbidden, registration_scripts[0])
        with patch.object(
            adapter,
            "_run",
            return_value=SimpleNamespace(
                returncode=0,
                stdout=f"exact|{candidate['contract_sha256']}|{raw_b64}\n",
            ),
        ), self.assertRaisesRegex(StateOnlyBackupError, "inspection is malformed"):
            adapter.inspect(candidate)

        artifact = build_task_inspection_artifact(
            inspection, observed_at="2026-08-21T12:00:00Z", candidate=candidate
        )
        self.assertEqual(
            "qrh-state-only-task-inspection/v2-raw-xml",
            artifact["schema_version"],
        )
        self.assertEqual(
            candidate["contract_sha256"],
            artifact["task_xml_projection"]["registration"]["contract_sha256"],
        )
        self.assertEqual(
            TEST_TASK_SID_SHA256,
            artifact["task_xml_projection"]["principal"]["principal_sid_sha256"],
        )
        forged = dict(artifact)
        forged["task_xml_base64"] = base64.b64encode(b"<Task/>").decode()
        body = dict(forged)
        body.pop("inspection_sha256")
        forged["inspection_sha256"] = manifest_sha256(body)
        from quant_hub.ops.state_only_backup import validate_task_inspection_artifact
        with self.assertRaises(StateOnlyBackupError):
            validate_task_inspection_artifact(forged, candidate=candidate)

        forged_projection = json.loads(json.dumps(artifact))
        forged_projection["task_xml_projection"]["settings"]["wake_to_run"] = True
        body = dict(forged_projection)
        body.pop("inspection_sha256")
        forged_projection["inspection_sha256"] = manifest_sha256(body)
        with self.assertRaisesRegex(StateOnlyBackupError, "projection differs"):
            validate_task_inspection_artifact(forged_projection, candidate=candidate)

        text = raw.decode()
        normalized_sid_raw = text.replace(
            f"<UserId>{TEST_TASK_SID}</UserId>",
            "<UserId> s-01-005-021-001 </UserId>",
            1,
        ).encode()
        normalized_sid_inspection = TaskInspection(
            "exact",
            candidate["contract_sha256"],
            hashlib.sha256(normalized_sid_raw).hexdigest(),
            TEST_TASK_SID_SHA256,
            base64.b64encode(normalized_sid_raw).decode(),
        )
        build_task_inspection_artifact(
            normalized_sid_inspection,
            observed_at="2026-08-21T12:00:00Z",
            candidate=candidate,
        )
        adversarial = {
            "trigger_disabled": text.replace(
                "<Enabled>true</Enabled>", "<Enabled>false</Enabled>", 1
            ).encode(),
            "trigger_time": text.replace("T03:00:00", "T04:00:00", 1).encode(),
            "trigger_days": text.replace(
                "<DaysInterval>1</DaysInterval>",
                "<DaysInterval>2</DaysInterval>",
                1,
            ).encode(),
            "repetition": text.replace(
                "<ScheduleByDay>",
                "<Repetition><Interval>PT1H</Interval></Repetition><ScheduleByDay>",
                1,
            ).encode(),
            "end_boundary": text.replace(
                "<Enabled>true</Enabled>",
                "<Enabled>true</Enabled><EndBoundary>2026-08-23T03:00:00</EndBoundary>",
                1,
            ).encode(),
            "extra_trigger": drift_raw,
            "random_delay": text.replace(
                "<ScheduleByDay>", "<RandomDelay>PT5M</RandomDelay><ScheduleByDay>", 1
            ).encode(),
            "namespace_drift": text.replace(
                "http://schemas.microsoft.com/windows/2004/02/mit/task",
                "urn:forged-task",
                1,
            ).encode(),
            "task_version_drift": text.replace(
                '<Task version="1.4"', '<Task version="1.3"', 1
            ).encode(),
            "description_drift": text.replace(
                "QRH_STATE_ONLY_CONTRACT:", "FORGED_CONTRACT:", 1
            ).encode(),
            "registration_extra": text.replace(
                "<Description>", "<Author>forged</Author><Description>", 1
            ).encode(),
            "uri_drift": text.replace(
                "<URI>\\QuantResearchHub\\StateOnlyBackup</URI>",
                "<URI>\\QuantResearchHub\\OtherTask</URI>",
                1,
            ).encode(),
            "principal_sid_drift": text.replace(TEST_TASK_SID, "S-1-5-21-2", 1).encode(),
            "principal_id_drift": text.replace(
                '<Principal id="Author">', '<Principal id="Other">', 1
            ).encode(),
            "principal_logon": text.replace(
                "<LogonType>S4U</LogonType>",
                "<LogonType>Password</LogonType>",
                1,
            ).encode(),
            "principal_run_level": text.replace(
                "<RunLevel>LeastPrivilege</RunLevel>",
                "<RunLevel>HighestAvailable</RunLevel>",
                1,
            ).encode(),
            "extra_principal": text.replace(
                "</Principals>",
                f'<Principal id="Other"><UserId>{TEST_TASK_SID}</UserId><LogonType>S4U</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>',
                1,
            ).encode(),
            "run_only_if_idle": text.replace(
                "<RunOnlyIfIdle>false</RunOnlyIfIdle>",
                "<RunOnlyIfIdle>true</RunOnlyIfIdle>",
                1,
            ).encode(),
            "battery_policy": text.replace(
                "<DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>",
                "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
                1,
            ).encode(),
            "stop_on_battery": text.replace(
                "<StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>",
                "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>",
                1,
            ).encode(),
            "hard_terminate": text.replace(
                "<AllowHardTerminate>true</AllowHardTerminate>",
                "<AllowHardTerminate>false</AllowHardTerminate>",
                1,
            ).encode(),
            "start_when_available": text.replace(
                "<StartWhenAvailable>true</StartWhenAvailable>",
                "<StartWhenAvailable>false</StartWhenAvailable>",
                1,
            ).encode(),
            "network_required": text.replace(
                "<RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>",
                "<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>",
                1,
            ).encode(),
            "multiple_instances": text.replace(
                "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>",
                "<MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>",
                1,
            ).encode(),
            "idle_stop": text.replace(
                "<StopOnIdleEnd>true</StopOnIdleEnd>",
                "<StopOnIdleEnd>false</StopOnIdleEnd>",
                1,
            ).encode(),
            "idle_restart": text.replace(
                "<RestartOnIdle>false</RestartOnIdle>",
                "<RestartOnIdle>true</RestartOnIdle>",
                1,
            ).encode(),
            "wake_to_run": text.replace(
                "<WakeToRun>false</WakeToRun>", "<WakeToRun>true</WakeToRun>", 1
            ).encode(),
            "allow_demand": text.replace(
                "<AllowStartOnDemand>true</AllowStartOnDemand>",
                "<AllowStartOnDemand>false</AllowStartOnDemand>",
                1,
            ).encode(),
            "task_disabled": text.replace(
                "<AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled>",
                "<AllowStartOnDemand>true</AllowStartOnDemand><Enabled>false</Enabled>",
                1,
            ).encode(),
            "hidden": text.replace(
                "<Hidden>false</Hidden>", "<Hidden>true</Hidden>", 1
            ).encode(),
            "execution_limit": text.replace(
                "<ExecutionTimeLimit>PT2H</ExecutionTimeLimit>",
                "<ExecutionTimeLimit>PT3H</ExecutionTimeLimit>",
                1,
            ).encode(),
            "priority": text.replace(
                "<Priority>7</Priority>", "<Priority>6</Priority>", 1
            ).encode(),
            "retry_interval": text.replace(
                "<Interval>PT15M</Interval>", "<Interval>PT20M</Interval>", 1
            ).encode(),
            "retry_count": text.replace(
                "<Count>3</Count>", "<Count>4</Count>", 1
            ).encode(),
            "idle_extra": text.replace(
                "</IdleSettings>", "<Duration>PT10M</Duration></IdleSettings>", 1
            ).encode(),
            "unknown_setting": text.replace(
                "</Settings>", "<MaintenanceSettings/></Settings>", 1
            ).encode(),
            "extra_action": text.replace(
                "</Actions>",
                f'<Exec><Command>{candidate["action"]["executable"]}</Command><Arguments>x</Arguments><WorkingDirectory>{candidate["action"]["working_directory"]}</WorkingDirectory></Exec></Actions>',
                1,
            ).encode(),
            "action_context": text.replace(
                '<Actions Context="Author">', '<Actions Context="Other">', 1
            ).encode(),
            "command_drift": text.replace(
                f"<Command>{candidate['action']['executable']}</Command>",
                "<Command>C:\\forged\\python.exe</Command>",
                1,
            ).encode(),
            "exec_extra_child": text.replace(
                "</Exec>", "<ComHandler>forbidden</ComHandler></Exec>", 1
            ).encode(),
        }
        for name, changed in adversarial.items():
            claimed_exact = TaskInspection(
                "exact",
                candidate["contract_sha256"],
                hashlib.sha256(changed).hexdigest(),
                TEST_TASK_SID_SHA256,
                base64.b64encode(changed).decode(),
            )
            with self.subTest(name=name), self.assertRaises(StateOnlyBackupError):
                build_task_inspection_artifact(
                    claimed_exact,
                    observed_at="2026-08-21T12:00:00Z",
                    candidate=candidate,
                )

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
