from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from quant_hub.ops import release_closure as closure
from quant_hub.ops.local_release_identity import canonical_bytes


_SUBJECT = {
    "active_release": {
        "release_id": "release-r1",
        "manifest_sha256": "a" * 64,
        "snapshot_id": "ksnap-current",
    },
    "prior_release": {
        "release_id": "release-r0",
        "manifest_sha256": "b" * 64,
        "snapshot_id": "ksnap-prior",
    },
    "state_identity_sha256": "c" * 64,
}

_STAGE5_VALUES = {
    "full_replay_and_comment_lifecycle": {
        "browser_result": "pass",
        "sqlite_result": "pass",
        "source_bytes_unchanged": True,
        "wrong_comment_attachments": 0,
    },
    "failure_and_incremental_matrix": {
        "failure_matrix_result": "pass",
        "silent_failures": 0,
    },
    "web_search_mcp_snapshot_consistency": {
        "snapshot_consistency_result": "pass",
        "stale_current_returns": 0,
    },
    "independent_verification": {
        "independent_verdict": "pass",
        "executor_summary_only": False,
    },
    "shared_state_schema_compatibility": {
        "candidate_read_write": "pass",
        "prior_read_write": "pass",
        "state_replaced": False,
        "down_migration_performed": False,
    },
    "active_prior_active_drill": {
        "sequence_result": "pass",
        "state_identity_unchanged": True,
        "legacy_c_writer_restarted": False,
        "outside_exact_d_project_reads": 0,
    },
    "retention_closure": {
        "retention_result": "pass",
        "retained_release_count": 2,
        "active_count": 1,
        "prior_count": 1,
        "terminal_candidates": 0,
        "completed_incoming": 0,
    },
    "runbook_drills_and_quality_report": {
        "runbook_result": "pass",
        "drill_result": "pass",
        "quality_report_result": "pass",
    },
    "revocation_surface": {
        "revocation_surface_result": "pass",
        "periodic_state_copy_tasks": 0,
        "outside_d_project_storage": 0,
        "legacy_protection_exports": 0,
    },
    "identity_graph_negative_fixtures": {
        "schema_graph_hash_result": "pass",
        "negative_fixtures_rejected": True,
    },
}


def _utc(hour: int, minute: int = 0) -> str:
    return f"2026-08-31T{hour:02d}:{minute:02d}:00.000000Z"


def _write_canonical(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value))


class ReleaseClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)
        self.stage5_paths = self._make_stage5()

    def _gate(
        self,
        *,
        stage: str,
        role: str,
        assertions: dict[str, object],
        observed_at: str,
        subject: dict[str, object] | None = None,
    ) -> str:
        bound_subject = subject or _SUBJECT
        producer = {
            "name": (
                "independent-verifier"
                if role == "independent_verification"
                else "gate-runner"
            ),
            "version": "1.0.0",
            "independent": role == "independent_verification",
        }
        artifact_relative = f"artifacts/{stage}/{role}.json"
        artifact = {
            "schema_version": "qrh-test-run-result/v1",
            "gate_role": role,
            "subject": bound_subject,
            "verdict": "pass",
            "assertions": assertions,
            "observed_at": observed_at,
            "producer": producer,
        }
        artifact_raw = canonical_bytes(artifact)
        _write_canonical(self.root / artifact_relative, artifact)
        evidence_relative = f"gates/{stage}/{role}.json"
        evidence: dict[str, object] = {
            "schema_version": closure.GATE_EVIDENCE_SCHEMA,
            "evidence_id": f"evidence-{stage}-{role}",
            "gate_role": role,
            "subject": bound_subject,
            "verdict": "pass",
            "assertions": assertions,
            "observed_at": observed_at,
            "producer": producer,
            "artifacts": [
                {
                    "artifact_id": f"result-{stage}-{role}",
                    "relative_path": artifact_relative,
                    "artifact_kind": "canonical_json",
                    "schema_version": "qrh-test-run-result/v1",
                    "sha256": hashlib.sha256(artifact_raw).hexdigest(),
                    "size_bytes": len(artifact_raw),
                    "observed_at": observed_at,
                }
            ],
        }
        evidence["evidence_sha256"] = hashlib.sha256(
            canonical_bytes(evidence)
        ).hexdigest()
        _write_canonical(self.root / evidence_relative, evidence)
        return evidence_relative

    def _make_stage5(self) -> list[str]:
        return [
            self._gate(
                stage="stage5",
                role=role,
                assertions=dict(_STAGE5_VALUES[role]),
                observed_at=_utc(0),
            )
            for role in closure.STAGE5_GATE_ROLES
        ]

    def _write_stage5_certificate(self) -> dict[str, object]:
        (self.root / "certificates").mkdir()
        with patch.object(
            closure,
            "_utc_now",
            return_value=datetime(2026, 8, 31, 0, 30, tzinfo=timezone.utc),
        ):
            return dict(
                closure.write_stage5_release_certificate(
                    self.root,
                    self.stage5_paths,
                    output_path="certificates/stage5.json",
                )
            )

    def _stage6_values(self) -> dict[str, dict[str, object]]:
        return {
            "repository_private_observation": {
                "repository_visibility": "private",
                "visibility_changed_at": _utc(1),
            },
            "private_controls_revalidation": {
                "repository_visibility": "private",
                "actual_plan": "pass",
                "actions": "pass",
                "branch_protection": "pass",
                "environment_protection": "pass",
                "publish_minimum_permissions": "pass",
                "exact_sha_candidate_capability": "pass",
            },
            "private_exact_sha_ci": {
                "repository_visibility": "private",
                "commit_sha": "d" * 40,
                "ci_conclusion": "success",
            },
            "private_candidate_only": {
                "repository_visibility": "private",
                "mode": "candidate_only",
                "production_switch": "not_performed",
                "candidate_result": "pass",
                "commit_sha": "d" * 40,
                "candidate_release_id": "release-private-candidate",
                "candidate_manifest_sha256": "e" * 64,
            },
            "production_identity_unchanged": {
                "repository_visibility": "private",
                "active_pointer_before_sha256": "f" * 64,
                "active_pointer_after_sha256": "f" * 64,
                "binding_before_sha256": "1" * 64,
                "binding_after_sha256": "1" * 64,
                "state_before_sha256": "2" * 64,
                "state_after_sha256": "2" * 64,
            },
        }

    def _make_stage6(
        self, values: dict[str, dict[str, object]] | None = None, *, observed_at: str | None = None
    ) -> list[str]:
        material = values or self._stage6_values()
        return [
            self._gate(
                stage="stage6",
                role=role,
                assertions=dict(material[role]),
                observed_at=observed_at or _utc(1, 15),
            )
            for role in closure.STAGE6_GATE_ROLES
        ]

    def test_stage5_producer_verifier_bind_actual_files_and_scope(self) -> None:
        certificate = self._write_stage5_certificate()
        verified = closure.verify_stage5_release_certificate_file(
            self.root, "certificates/stage5.json"
        )
        self.assertEqual(certificate, verified)
        self.assertEqual(verified["result"], "pass")
        self.assertEqual(verified["scope"]["exact_project_root"], r"D:\quant\quant_platform")
        self.assertEqual(verified["scope"]["retained_release_count"], 2)
        self.assertEqual(
            verified["scope"]["state_contract"],
            "shared_current_d_state_no_restore_no_down_migration",
        )
        self.assertEqual(
            verified["scope"]["out_of_scope"],
            [
                "production_vm_total_loss",
                "exact_d_project_root_total_loss",
                "object_closure_total_loss",
                "shared_current_d_state_total_loss",
            ],
        )

    def test_stage5_verifier_rejects_artifact_tamper_and_schema_extension(self) -> None:
        certificate = self._write_stage5_certificate()
        first_artifact = self.root / "artifacts/stage5/full_replay_and_comment_lifecycle.json"
        changed = json.loads(first_artifact.read_text(encoding="utf-8"))
        changed["result"] = "fail"
        _write_canonical(first_artifact, changed)
        with self.assertRaisesRegex(closure.ReleaseClosureError, "artifact (size|hash)"):
            closure.verify_stage5_release_certificate_file(
                self.root, "certificates/stage5.json"
            )

        extended = dict(certificate)
        extended["unexpected"] = True
        with self.assertRaisesRegex(closure.ReleaseClosureError, "schema 不闭合"):
            closure.validate_stage5_release_certificate(extended, evidence_root=self.root)

    def test_stage5_rejects_missing_role_failed_assertion_and_subject_drift(self) -> None:
        with self.assertRaisesRegex(closure.ReleaseClosureError, "数量"):
            closure.produce_stage5_release_certificate(self.root, self.stage5_paths[:-1])

        role = "retention_closure"
        path = self.root / f"gates/stage5/{role}.json"
        evidence = json.loads(path.read_text(encoding="utf-8"))
        evidence["assertions"]["retained_release_count"] = 3
        evidence.pop("evidence_sha256")
        evidence["evidence_sha256"] = hashlib.sha256(canonical_bytes(evidence)).hexdigest()
        _write_canonical(path, evidence)
        with self.assertRaisesRegex(closure.ReleaseClosureError, "retained_release_count"):
            closure.produce_stage5_release_certificate(self.root, self.stage5_paths)

        self.stage5_paths = self._make_stage5()
        role = "failure_and_incremental_matrix"
        path = self.root / f"gates/stage5/{role}.json"
        evidence = json.loads(path.read_text(encoding="utf-8"))
        evidence["subject"]["state_identity_sha256"] = "9" * 64
        evidence.pop("evidence_sha256")
        evidence["evidence_sha256"] = hashlib.sha256(canonical_bytes(evidence)).hexdigest()
        _write_canonical(path, evidence)
        with self.assertRaisesRegex(closure.ReleaseClosureError, "identity"):
            closure.produce_stage5_release_certificate(self.root, self.stage5_paths)

    def test_visibility_closure_requires_private_exact_sha_and_no_switch(self) -> None:
        self._write_stage5_certificate()
        stage6_paths = self._make_stage6()
        (self.root / "receipts").mkdir()
        with patch.object(
            closure,
            "_utc_now",
            return_value=datetime(2026, 8, 31, 2, 0, tzinfo=timezone.utc),
        ):
            receipt = closure.write_visibility_closure_receipt(
                self.root,
                stage5_certificate_path="certificates/stage5.json",
                evidence_paths=stage6_paths,
                output_path="receipts/visibility.json",
            )
        verified = closure.verify_visibility_closure_receipt_file(
            self.root, "receipts/visibility.json"
        )
        self.assertEqual(receipt, verified)
        self.assertEqual(verified["repository_visibility"], "private")
        self.assertEqual(verified["private_commit_sha"], "d" * 40)
        self.assertEqual(verified["candidate_only"]["production_switch"], "not_performed")
        with self.assertRaisesRegex(closure.ReleaseClosureError, "不可覆盖"):
            with patch.object(
                closure,
                "_utc_now",
                return_value=datetime(2026, 8, 31, 2, 0, tzinfo=timezone.utc),
            ):
                closure.write_visibility_closure_receipt(
                    self.root,
                    stage5_certificate_path="certificates/stage5.json",
                    evidence_paths=stage6_paths,
                    output_path="receipts/visibility.json",
                )

    def test_visibility_closure_rejects_sha_mismatch_and_state_change(self) -> None:
        self._write_stage5_certificate()
        values = self._stage6_values()
        values["private_candidate_only"]["commit_sha"] = "3" * 40
        paths = self._make_stage6(values)
        with patch.object(
            closure,
            "_utc_now",
            return_value=datetime(2026, 8, 31, 2, 0, tzinfo=timezone.utc),
        ):
            with self.assertRaisesRegex(closure.ReleaseClosureError, "exact same SHA"):
                closure.produce_visibility_closure_receipt(
                    self.root,
                    stage5_certificate_path="certificates/stage5.json",
                    evidence_paths=paths,
                )

        values = self._stage6_values()
        values["production_identity_unchanged"]["state_after_sha256"] = "4" * 64
        paths = self._make_stage6(values)
        with patch.object(
            closure,
            "_utc_now",
            return_value=datetime(2026, 8, 31, 2, 0, tzinfo=timezone.utc),
        ):
            with self.assertRaisesRegex(closure.ReleaseClosureError, "生产 pointer/binding/state"):
                closure.produce_visibility_closure_receipt(
                    self.root,
                    stage5_certificate_path="certificates/stage5.json",
                    evidence_paths=paths,
                )

        paths = self._make_stage6(observed_at=_utc(0, 15))
        with patch.object(
            closure,
            "_utc_now",
            return_value=datetime(2026, 8, 31, 2, 0, tzinfo=timezone.utc),
        ):
            with self.assertRaisesRegex(closure.ReleaseClosureError, "必须晚于 Stage 5"):
                closure.produce_visibility_closure_receipt(
                    self.root,
                    stage5_certificate_path="certificates/stage5.json",
                    evidence_paths=paths,
                )

    def test_visibility_verifier_replays_stage5_and_rejects_noncanonical_evidence(self) -> None:
        self._write_stage5_certificate()
        paths = self._make_stage6()
        (self.root / "receipts").mkdir()
        with patch.object(
            closure,
            "_utc_now",
            return_value=datetime(2026, 8, 31, 2, 0, tzinfo=timezone.utc),
        ):
            closure.write_visibility_closure_receipt(
                self.root,
                stage5_certificate_path="certificates/stage5.json",
                evidence_paths=paths,
                output_path="receipts/visibility.json",
            )
        stage5_artifact = self.root / "artifacts/stage5/retention_closure.json"
        stage5_artifact.write_bytes(stage5_artifact.read_bytes() + b" ")
        with self.assertRaisesRegex(closure.ReleaseClosureError, "artifact (size|hash)"):
            closure.verify_visibility_closure_receipt_file(
                self.root, "receipts/visibility.json"
            )

        # Gate evidence 自身即使 JSON 语义相同，只要不是 exact canonical bytes 也拒绝。
        stage5_artifact.write_bytes(stage5_artifact.read_bytes()[:-1])
        gate = self.root / "gates/stage6/repository_private_observation.json"
        gate.write_bytes(gate.read_bytes() + b"\n")
        with patch.object(
            closure,
            "_utc_now",
            return_value=datetime(2026, 8, 31, 2, 0, tzinfo=timezone.utc),
        ):
            with self.assertRaisesRegex(closure.ReleaseClosureError, "非 canonical"):
                closure.produce_visibility_closure_receipt(
                    self.root,
                    stage5_certificate_path="certificates/stage5.json",
                    evidence_paths=paths,
                )


if __name__ == "__main__":
    unittest.main()
