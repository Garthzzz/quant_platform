from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from quant_hub.ops.failure_domain import attest_failure_domain, canonical_bytes as fd_bytes, collect_host_facts
from quant_hub.ops.release_identity import canonical_manifest_bytes, manifest_sha256
from quant_hub.ops.stage_closure import (
    RECOVERY_FINALIZE_REQUIRED_EVIDENCE, STAGE5_REQUIRED_GATES,
    STAGE5_REQUIRED_RUNBOOKS, DirectoryEvidenceResolver, StageClosureError,
    artifact_ref, build_active_d_maintenance_plan, build_measured_prior_binding,
    build_recovery_finalize_plan, build_stage5_release_certificate,
    build_visibility_closure_receipt, reject_active_d_destructive_apply,
    reject_recovery_receipt_finalize, verify_measured_prior_binding,
    verify_stage5_release_certificate, verify_visibility_closure_receipt,
)
from quant_hub.ops.state_only_backup import TaskInspection, build_task_candidate, build_task_inspection_artifact


BASE = datetime(2026, 8, 22, 8, tzinfo=UTC)
TEST_TASK_SID = "S-1-5-21-1"
TEST_TASK_SID_SHA256 = hashlib.sha256(TEST_TASK_SID.encode("ascii")).hexdigest()


def at(minutes: int) -> str:
    return (BASE + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


def rehash(value: dict[str, object], field: str) -> None:
    material = dict(value); material.pop(field); value[field] = manifest_sha256(material)


def release_manifest() -> dict[str, object]:
    return {
        "schema_version": "qrh-release-manifest/v1", "release_id": "release-final", "built_at": at(0),
        "application": {"commit_sha": "c" * 40, "tracked_tree_sha256": "1" * 64, "build_tool_version": "tests/v1"},
        "content": {"snapshot_id": "snapshot-final", "source_inventory_sha256": "2" * 64, "ir_sha256": "3" * 64, "knowledge_sha256": "4" * 64, "search_sha256": "5" * 64, "knowledge_enrichment": {"status": "not_applicable"}},
        "resources": {"inventory_sha256": "6" * 64},
        "state": {"compatibility": {"comments": {"read": [1], "write": [1]}}},
        "recovery": {"compatibility": {"checkpoint_manifest_schemas": ["qrh-checkpoint-manifest/v1"], "restore_protocol_versions": ["qrh-restore/v1"]}},
    }


def task_xml(candidate: dict[str, object]) -> bytes:
    action = candidate["action"]; assert isinstance(action, dict)
    argv = subprocess.list2cmdline(action["arguments"])
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Description>QRH_STATE_ONLY_CONTRACT:{candidate["contract_sha256"]}</Description><URI>\\QuantResearchHub\\StateOnlyBackup</URI></RegistrationInfo><Triggers><CalendarTrigger><StartBoundary>2026-08-22T03:00:00</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger></Triggers><Principals><Principal id="Author"><UserId>{TEST_TASK_SID}</UserId><LogonType>S4U</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT2H</ExecutionTimeLimit><Priority>7</Priority><RestartOnFailure><Interval>PT15M</Interval><Count>3</Count></RestartOnFailure></Settings><Actions Context="Author"><Exec><Command>{action["executable"]}</Command><Arguments>{argv}</Arguments><WorkingDirectory>{action["working_directory"]}</WorkingDirectory></Exec></Actions></Task>'''.encode()


class StageClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        for target in (
            "quant_hub.ops.stage_closure.require_failure_domain_authority",
            "quant_hub.ops.state_only_backup.require_failure_domain_authority",
        ):
            authority = patch(target, return_value=None)
            authority.start()
            self.addCleanup(authority.stop)
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        token_patch = patch(
            "quant_hub.ops.state_only_backup._current_token_sid_sha256",
            return_value=TEST_TASK_SID_SHA256,
        )
        token_patch.start(); self.addCleanup(token_patch.stop)
        self.root = Path(temp.name).resolve(); self.evidence = self.root / "recovery"; self.evidence.mkdir()
        self.resolver = DirectoryEvidenceResolver(self.evidence)
        self.project = self.root / "project"; self.project.mkdir()
        self.operational = self.root / "operational"; python = self.operational / "tooling/python/python.exe"; python.parent.mkdir(parents=True); python.write_bytes(b"python")
        self.python = python
        protected = self.root / "protected"; protected.mkdir(); self.config = protected / "publish.json"; self.config.write_bytes(b"{}")

        release = release_manifest(); rh = manifest_sha256(release)
        self.active = {"release_id": "release-final", "manifest_sha256": rh, "snapshot_id": "snapshot-final"}
        self.prior = {"release_id": "release-prior", "manifest_sha256": "b" * 64}
        checkpoint = {"schema_version": "qrh-checkpoint-manifest/v1", "checkpoint_id": "checkpoint-final", "captured_at": at(10), "captured_under_active_release": {"release_id": "release-final", "manifest_sha256": rh}, "state": {"authority_id": "state-d", "inventory_sha256": "7" * 64, "database_count": 1}, "verification": {"integrity": True, "foreign_keys": True, "restorable": True}}
        ch = manifest_sha256(checkpoint)
        recovery = {"schema_version": "qrh-recovery-manifest/v1", "bundle_id": "bundle-final", "created_at": at(20), "release": {"release_id": "release-final", "manifest_sha256": rh}, "checkpoint": {"checkpoint_id": "checkpoint-final", "manifest_sha256": ch}, "closure": {"inventory_sha256": "8" * 64, "file_count": 2, "total_bytes": 10}, "compatibility": {"verdict": "compatible"}, "restore": {"protocol_version": "qrh-restore/v1", "tool_inventory_sha256": "9" * 64, "runbook_sha256": "a" * 64, "operational_bootstrap_sha256": "d" * 64}, "no_secret_attestation": {"verdict": "pass", "scanner_version": "tests/v1"}}
        rmh = manifest_sha256(recovery)
        recovery_receipt = {"schema_version": "qrh-recovery-receipt/v1", "receipt_type": "recovery", "receipt_id": "recovery-final", "recovery_attempt_id": "restore-final", "recorded_at": at(40), "authority": "evidence_only", "release_manifest_sha256": rh, "recovery_manifest_sha256": rmh, "checkpoint_manifest_sha256": ch, "verdict": "recovered", "restore_verification": {"closure": True, "state_restored": True, "service_started": True, "post_restore": True}}
        rollback = {"schema_version": "qrh-d-prior-rollback-receipt/v1", "receipt_id": "rollback-prior", "observed_at": at(25), "authority": "evidence_only", "active_release": {"release_id": "release-final", "manifest_sha256": rh}, "prior_release": self.prior, "verification": {"prior_activated": True, "health": True, "writer_fence": True, "active_restored": True}}
        rollback["receipt_sha256"] = manifest_sha256(rollback)
        rollback_ref = self.write_json("d_prior_rollback_receipt", "stage5/d_prior/rollback_receipt.json", rollback)
        measured = build_measured_prior_binding(observed_at=at(35), rollback_receipt_ref=rollback_ref, resolver=self.resolver)

        recovery_facts = collect_host_facts(self.evidence, role="recovery", tool_version="tests/v1")
        production = dict(recovery_facts); production.update({"role": "production", "host_name": "production", "machine_identity": "machine-production", "canonical_path": r"D:\quant\quant_platform", "volume_identity": "volume-production", "storage_backend": "storage-production", "storage_authority": "machine-production|volume-production|storage-production"}); production.pop("facts_sha256"); production["facts_sha256"] = hashlib.sha256(fd_bytes(production)).hexdigest()
        probe = {"schema_version": "qrh-recovery-independence-probe/v2", "production_root_available": False, "recovery_bundle_readable": True, "closure_verified": True, "empty_root_precondition": True, "bundle_id": "bundle-final", "release_id": "release-final", "release_manifest_sha256": rh, "bundle_inventory_sha256": "e" * 64, "materialization_event_id": "cold-materialization-bundle-final", "materialization_event_sha256": "f" * 64, "probe_tool_sha256": "1" * 64}
        attestation = attest_failure_domain(production_facts=production, recovery_facts=recovery_facts, independence_probe=probe, observed_at=at(30)).payload
        attestation_path = self.evidence / "stage5/final_recovery/failure_domain_attestation.json"; attestation_path.parent.mkdir(parents=True); attestation_path.write_bytes(canonical_manifest_bytes(attestation))
        self.attestation_path = attestation_path
        runtime_patch = patch(
            "quant_hub.ops.state_only_backup.RuntimePublishConfig.load",
            return_value=SimpleNamespace(
                project_root=self.project,
                github=SimpleNamespace(owner="owner", repository="quant-platform"),
                recovery=SimpleNamespace(
                    recovery_root=self.evidence,
                    operational_root=self.operational,
                    attestation_path=attestation_path,
                ),
            ),
        )
        runtime_patch.start(); self.addCleanup(runtime_patch.stop)
        authority_material = {
            "schema_version": "qrh-state-only-scheduled-task-authority/v1",
            "authorized_at": at(31),
            "authority": "stage5_exact_identity",
            "repository": {
                "repository_id": "repository-123", "full_name": "owner/quant-platform",
                "commit_sha": "c" * 40, "tracked_tree_sha256": "1" * 64,
            },
            "release": {
                "release_id": "release-final", "manifest_sha256": rh,
                "snapshot_id": "snapshot-final",
            },
            "paths": {
                "project_root": str(self.project), "config_path": str(self.config),
                "operational_root": str(self.operational), "recovery_root": str(self.evidence),
                "operational_python": str(python),
                "failure_domain_attestation_path": str(attestation_path),
            },
            "bytes": {
                "config_sha256": hashlib.sha256(self.config.read_bytes()).hexdigest(),
                "operational_python_sha256": hashlib.sha256(python.read_bytes()).hexdigest(),
            },
            "failure_domain_attestation_sha256": hashlib.sha256(attestation_path.read_bytes()).hexdigest(),
        }
        authority = dict(authority_material)
        authority["authorization_id"] = "task-authority-" + manifest_sha256(authority_material)[:32]
        authority["authority_sha256"] = manifest_sha256(authority)
        authority_path = self.evidence / "state-only/control/scheduled_task_authority.json"
        authority_path.parent.mkdir(parents=True, exist_ok=True)
        authority_path.write_bytes(canonical_manifest_bytes(authority))
        task = build_task_candidate(config_path=self.config, project_root=self.project, operational_root=self.operational, operational_python=python, recovery_root=self.evidence, failure_domain_attestation_path=attestation_path)
        xml = task_xml(dict(task))
        inspection = build_task_inspection_artifact(TaskInspection("exact", task["contract_sha256"], hashlib.sha256(xml).hexdigest(), TEST_TASK_SID_SHA256, base64.b64encode(xml).decode()), observed_at=at(50), candidate=task)
        repo = {"schema_version": "qrh-repository-public-observation/v1", "observation_id": "repo-public", "observed_at": at(45), "repository_id": "repository-123", "full_name": "owner/quant-platform", "visibility": "public", "head_sha": "c" * 40}; repo["evidence_sha256"] = manifest_sha256(repo)
        self.core = {
            "repository_observation": self.write_json("repository_observation", "stage5/repository_public_observation.json", repo),
            "release_manifest": self.write_json("release_manifest", "stage5/release_manifest.json", release),
            "measured_prior_binding": self.write_json("measured_prior_binding", "state-only/control/measured_prior_release.json", measured),
            "recovery_manifest": self.write_json("recovery_manifest", "stage5/final_recovery/recovery_manifest.json", recovery),
            "checkpoint_manifest": self.write_json("checkpoint_manifest", "stage5/final_recovery/checkpoint_manifest.json", checkpoint),
            "failure_domain_attestation": artifact_ref(kind="failure_domain_attestation", locator="stage5/final_recovery/failure_domain_attestation.json", raw_bytes=attestation_path.read_bytes()),
            "recovery_receipt": self.write_json("recovery_receipt", "stage5/final_recovery/recovery_receipt.json", recovery_receipt),
            "task_candidate": self.write_json("task_candidate", "state-only/control/scheduled_task_candidate.json", task),
            "task_inspection": self.write_json("task_inspection", "state-only/control/scheduled_task_inspection.json", inspection),
        }
        subject = {"repository_id": "repository-123", "commit_sha": "c" * 40, "release_id": "release-final", "release_manifest_sha256": rh, "snapshot_id": "snapshot-final"}
        self.gates = []
        for index, kind in enumerate(STAGE5_REQUIRED_GATES):
            bindings = {"report_sha256": f"{index % 8 + 1}" * 64}
            if kind == "stage5_6_6_final_cold_recovery": bindings = {"failure_domain_attestation_sha256": self.core["failure_domain_attestation"]["sha256"], "recovery_manifest_sha256": rmh, "checkpoint_manifest_sha256": ch, "recovery_receipt_sha256": self.core["recovery_receipt"]["sha256"]}
            elif kind == "stage5_6_7_gc_roots": bindings = {"measured_prior_binding_sha256": self.core["measured_prior_binding"]["sha256"], "gc_roots_report_sha256": "7" * 64}
            elif kind == "stage5_6_9_state_only_backup": bindings = {"task_candidate_sha256": self.core["task_candidate"]["sha256"], "task_inspection_sha256": self.core["task_inspection"]["sha256"]}
            gate = {"schema_version": "qrh-stage-gate-evidence/v1", "evidence_id": f"gate-{index}", "kind": kind, "observed_at": at(60 + index), "status": "pass", "subject": subject, "bindings": bindings}; gate["evidence_sha256"] = manifest_sha256(gate)
            self.gates.append(self.write_json(kind, f"stage5/gates/{kind}.json", gate))
        self.runbooks = []
        for kind in STAGE5_REQUIRED_RUNBOOKS:
            raw = f"# {kind}\n固定 runbook。\n".encode(); locator = f"runbooks/{kind}.md"; path = self.evidence / locator; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw); self.runbooks.append(artifact_ref(kind=kind, locator=locator, raw_bytes=raw))
        self.certificate = None

    def write_json(self, kind: str, name: str, value: object) -> dict[str, object]:
        raw = canonical_manifest_bytes(value); path = self.evidence / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        return dict(artifact_ref(kind=kind, locator=name, raw_bytes=raw))

    def test_certificate_fails_closed_without_concrete_gate_producers(self) -> None:
        with self.assertRaisesRegex(StageClosureError, "no registered canonical producer/verifier"):
            build_stage5_release_certificate(
                issued_at=at(90), artifact_refs=self.core, gate_evidence=self.gates,
                runbook_evidence=self.runbooks, resolver=self.resolver,
            )

    def test_raw_bytes_and_fixed_locator_are_fail_closed(self) -> None:
        path = self.evidence / "stage5/release_manifest.json"; path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaises(StageClosureError):
            build_stage5_release_certificate(
                issued_at=at(90), artifact_refs=self.core, gate_evidence=self.gates,
                runbook_evidence=self.runbooks, resolver=self.resolver,
            )

    def test_certificate_rejects_scheduler_authority_for_another_commit(self) -> None:
        authority_path = self.evidence / "state-only/control/scheduled_task_authority.json"
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
        authority.pop("authority_sha256")
        authority.pop("authorization_id")
        authority["repository"]["commit_sha"] = "f" * 40
        authority["authorization_id"] = (
            "task-authority-" + manifest_sha256(authority)[:32]
        )
        authority["authority_sha256"] = manifest_sha256(authority)
        authority_path.write_bytes(canonical_manifest_bytes(authority))
        task = build_task_candidate(
            config_path=self.config, project_root=self.project,
            operational_root=self.operational, operational_python=self.python,
            recovery_root=self.evidence,
            failure_domain_attestation_path=self.attestation_path,
        )
        xml = task_xml(dict(task))
        inspection = build_task_inspection_artifact(
            TaskInspection(
                "exact", task["contract_sha256"], hashlib.sha256(xml).hexdigest(),
                TEST_TASK_SID_SHA256, base64.b64encode(xml).decode(),
            ),
            observed_at=at(50), candidate=task,
        )
        self.core["task_candidate"] = self.write_json(
            "task_candidate", "state-only/control/scheduled_task_candidate.json", task
        )
        self.core["task_inspection"] = self.write_json(
            "task_inspection", "state-only/control/scheduled_task_inspection.json", inspection
        )
        with self.assertRaisesRegex(StageClosureError, "repository/commit binding differs"):
            build_stage5_release_certificate(
                issued_at=at(90), artifact_refs=self.core, gate_evidence=self.gates,
                runbook_evidence=self.runbooks, resolver=self.resolver,
            )

    def test_measured_prior_requires_real_receipt_distinct_ids_and_time(self) -> None:
        verify_measured_prior_binding(json.loads((self.evidence / "state-only/control/measured_prior_release.json").read_text()), resolver=self.resolver)
        rollback_path = self.evidence / "stage5/d_prior/rollback_receipt.json"; original = json.loads(rollback_path.read_text()); rollback = deepcopy(original); rollback["prior_release"]["release_id"] = rollback["active_release"]["release_id"]; rehash(rollback, "receipt_sha256")
        with self.assertRaises(StageClosureError): build_measured_prior_binding(observed_at=at(35), rollback_receipt_ref=self.write_json("d_prior_rollback_receipt", "stage5/d_prior/rollback_receipt.json", rollback), resolver=self.resolver)
        with self.assertRaises(StageClosureError): build_measured_prior_binding(observed_at=at(20), rollback_receipt_ref=self.write_json("d_prior_rollback_receipt", "stage5/d_prior/rollback_receipt.json", original), resolver=self.resolver)

    def test_visibility_cannot_bypass_missing_stage5_gate_producers(self) -> None:
        forged = {
            "schema_version": "qrh-stage5-release-certificate/v3",
            "certificate_id": "stage5-" + "1" * 32,
            "issued_at": at(90), "authority": "evidence_only",
        }
        cert_ref = self.write_json(
            "stage5_certificate", "stage5/stage5_release_certificate.json", forged
        )
        with self.assertRaises(StageClosureError):
            build_visibility_closure_receipt(
                recorded_at=at(120), stage5_certificate_ref=cert_ref,
                evidence_refs=[], resolver=self.resolver,
            )

    def test_evidence_resolver_rejects_hardlinks_and_read_identity_drift(self) -> None:
        outside = self.root / "outside.json"
        outside.write_bytes(b"{}")
        linked = self.evidence / "hardlink.json"
        os.link(outside, linked)
        self.assertGreaterEqual(outside.stat().st_nlink, 2)
        with self.assertRaisesRegex(StageClosureError, "single-link"):
            self.resolver.read_bytes("hardlink.json")

        stable = self.evidence / "stable.json"
        stable.write_bytes(b"{}")
        real_fstat = os.fstat
        calls = 0

        def drifting_fstat(fd):
            nonlocal calls
            observed = real_fstat(fd)
            calls += 1
            if calls == 2:
                return SimpleNamespace(
                    st_dev=observed.st_dev,
                    st_ino=observed.st_ino,
                    st_mode=observed.st_mode,
                    st_nlink=observed.st_nlink,
                    st_size=observed.st_size,
                    st_mtime_ns=observed.st_mtime_ns + 1,
                    st_ctime_ns=observed.st_ctime_ns,
                )
            return observed

        with patch("quant_hub.ops.stage_closure.os.fstat", side_effect=drifting_fstat):
            with self.assertRaisesRegex(StageClosureError, "changed while being read"):
                self.resolver.read_bytes("stable.json")

    def test_inspect_only_skeletons_have_no_mutating_producer(self) -> None:
        def evidence(kind: str, i: int) -> dict[str, object]: return {"kind": kind, "evidence_id": f"e-{i}", "sha256": f"{i % 8 + 1}" * 64, "observed_at": at(1), "verdict": "pass"}
        plan = build_active_d_maintenance_plan(plan_id="active-plan", created_at=at(1), active_release=self.active, prior_release=self.prior, cold_bundle={"bundle_id": "bundle-final", "recovery_manifest_sha256": "1" * 64, "closure_inventory_sha256": "2" * 64}, final_checkpoint={"checkpoint_id": "checkpoint-final", "checkpoint_manifest_sha256": "3" * 64, "captured_release_manifest_sha256": self.active["manifest_sha256"]}, prerequisite_evidence=[evidence(kind, i) for i, kind in enumerate(("maintenance_window", "traffic_fence", "writer_fence", "restore_path", "root_inventory", "independent_verifier"))])
        with self.assertRaises(StageClosureError): reject_active_d_destructive_apply(plan)
        final = build_recovery_finalize_plan(plan_id="finalize-plan", created_at=at(1), release=self.active, recovery_manifest_sha256="4" * 64, checkpoint_manifest_sha256="5" * 64, evidence=[evidence(kind, i) for i, kind in enumerate(RECOVERY_FINALIZE_REQUIRED_EVIDENCE)])
        with self.assertRaises(StageClosureError): reject_recovery_receipt_finalize(final)

    def test_public_json_schemas_are_closed_current_versions(self) -> None:
        config = Path(__file__).resolve().parents[2] / "config"
        for name, version in (("stage5_release_certificate.schema.json", "qrh-stage5-release-certificate/v3"), ("visibility_closure_receipt.schema.json", "qrh-visibility-closure-receipt/v3"), ("state_only_task_authority.schema.json", "qrh-state-only-scheduled-task-authority/v1")):
            schema = json.loads((config / name).read_text()); self.assertFalse(schema["additionalProperties"]); self.assertEqual(set(schema["required"]), set(schema["properties"])); self.assertEqual(version, schema["properties"]["schema_version"]["const"])
        certificate_schema = json.loads(
            (config / "stage5_release_certificate.schema.json").read_text()
        )
        state_only = certificate_schema["properties"]["state_only_task"]
        self.assertEqual(set(state_only["required"]), set(state_only["properties"]))
        self.assertTrue(
            {
                "authority_sha256", "project_root", "config_path", "config_sha256",
                "operational_root", "executable_sha256", "recovery_root",
                "failure_domain_attestation_path",
            }.issubset(state_only["required"])
        )


if __name__ == "__main__": unittest.main()
