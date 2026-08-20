from __future__ import annotations

from dataclasses import replace
import sqlite3

from quant_hub.ids import stable_sha256
from quant_hub.platform.db import connect_database
from quant_hub.platform.releases import (
    ReleaseAuthority,
    ReleaseAuthorityError,
    ReleaseCandidateSpec,
    ReleaseCertificateMismatch,
)
from tests.helpers import SettingsTestCase


class ReleaseAuthorityTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.authority = ReleaseAuthority(self.settings)
        self.spec = ReleaseCandidateSpec(
            domain="archive",
            subject_urn="qrh:archive-research:test-a",
            subject_version_urn="qrh:archive-release:test-a:sha256:" + "a" * 64,
            artifact_manifest_hash="a" * 64,
            source_snapshot_hash="b" * 64,
            projection_revision="projection-v1-" + "c" * 64,
            requirements_manifest_hash="d" * 64,
        )
        self.gate_hash = stable_sha256("release-test", "gate")
        self.review_hash = stable_sha256("release-test", "review")
        self.reconciliation_hash = stable_sha256("release-test", "reconcile")

    def _pass(self):
        candidate = self.authority.register_candidate(self.spec)
        decision = self.authority.record_decision(
            candidate.candidate_id,
            deterministic_gate_hash=self.gate_hash,
            review_set_hash=self.review_hash,
            reconciliation_hash=self.reconciliation_hash,
            verdict="pass",
        )
        certificate = self.authority.issue_snapshot(
            decision.decision_id,
            requirements_manifest_hash=self.spec.requirements_manifest_hash,
            issuance_key=stable_sha256("release-test", "initial-issuance"),
        )
        return candidate, decision, certificate

    def test_pass_certificate_is_idempotent_recomputable_and_reissuable(self) -> None:
        candidate, decision, certificate = self._pass()
        replay_candidate = self.authority.register_candidate(self.spec)
        replay_decision = self.authority.record_decision(
            candidate.candidate_id,
            deterministic_gate_hash=self.gate_hash,
            review_set_hash=self.review_hash,
            reconciliation_hash=self.reconciliation_hash,
            verdict="pass",
        )
        replay_certificate = self.authority.issue_snapshot(
            decision.decision_id,
            requirements_manifest_hash=self.spec.requirements_manifest_hash,
            issuance_key=stable_sha256("release-test", "initial-issuance"),
        )
        self.assertFalse(replay_candidate.created)
        self.assertFalse(replay_decision.created)
        self.assertFalse(replay_certificate.created)
        self.assertEqual(certificate.snapshot_urn, replay_certificate.snapshot_urn)
        verified = self.authority.verify_snapshot(
            certificate.snapshot_urn, certificate.decision_hash, self.spec
        )
        self.assertEqual(candidate.candidate_id, verified.candidate_id)

        rollback_certificate = self.authority.issue_snapshot(
            decision.decision_id,
            requirements_manifest_hash=self.spec.requirements_manifest_hash,
            issuance_key=stable_sha256("release-test", "rollback-issuance"),
        )
        self.assertNotEqual(certificate.snapshot_urn, rollback_certificate.snapshot_urn)
        connection = connect_database(self.settings.database_path)
        try:
            self.assertEqual(
                2,
                connection.execute("SELECT count(*) FROM release_snapshot").fetchone()[0],
            )
            self.assertEqual(
                2,
                connection.execute(
                    "SELECT count(*) FROM outbox_event WHERE event_type='PlatformReleaseSnapshotIssued'"
                ).fetchone()[0],
            )
        finally:
            connection.close()

    def test_forged_or_mismatched_certificates_fail_closed(self) -> None:
        _, _, certificate = self._pass()
        with self.assertRaisesRegex(ReleaseCertificateMismatch, "not registered"):
            self.authority.verify_snapshot(
                "qrh:release_snapshot:rsnp_" + "0" * 32,
                certificate.decision_hash,
                self.spec,
            )
        with self.assertRaisesRegex(ReleaseCertificateMismatch, "decision hash"):
            self.authority.verify_snapshot(
                certificate.snapshot_urn, "f" * 64, self.spec
            )
        wrong_domain = ReleaseCandidateSpec(
            domain="evidence",
            subject_urn=self.spec.subject_urn,
            subject_version_urn=self.spec.subject_version_urn,
            artifact_manifest_hash=self.spec.artifact_manifest_hash,
            source_snapshot_hash=self.spec.source_snapshot_hash,
            projection_revision=self.spec.projection_revision,
            requirements_manifest_hash=self.spec.requirements_manifest_hash,
        )
        with self.assertRaisesRegex(ReleaseCertificateMismatch, "candidate material"):
            self.authority.verify_snapshot(
                certificate.snapshot_urn, certificate.decision_hash, wrong_domain
            )
        wrong_requirements = ReleaseCandidateSpec(
            domain=self.spec.domain,
            subject_urn=self.spec.subject_urn,
            subject_version_urn=self.spec.subject_version_urn,
            artifact_manifest_hash=self.spec.artifact_manifest_hash,
            source_snapshot_hash=self.spec.source_snapshot_hash,
            projection_revision=self.spec.projection_revision,
            requirements_manifest_hash="e" * 64,
        )
        with self.assertRaisesRegex(ReleaseCertificateMismatch, "candidate material"):
            self.authority.verify_snapshot(
                certificate.snapshot_urn,
                certificate.decision_hash,
                wrong_requirements,
            )
        with self.assertRaisesRegex(ReleaseAuthorityError, "reviewed candidate"):
            self.authority.issue_snapshot(
                certificate.decision_id,
                requirements_manifest_hash=wrong_requirements.requirements_manifest_hash,
                issuance_key=stable_sha256("release-test", "wrong-requirements"),
            )

    def test_failed_decision_cannot_issue_and_material_is_immutable(self) -> None:
        rejected = ReleaseCandidateSpec(
            domain="archive",
            subject_urn="qrh:archive-research:test-rejected",
            subject_version_urn="qrh:archive-release:test-rejected:sha256:" + "e" * 64,
            artifact_manifest_hash="e" * 64,
            source_snapshot_hash="f" * 64,
            projection_revision="projection-rejected",
            requirements_manifest_hash="1" * 64,
        )
        candidate = self.authority.register_candidate(rejected)
        decision = self.authority.record_decision(
            candidate.candidate_id,
            deterministic_gate_hash=self.gate_hash,
            review_set_hash=self.review_hash,
            reconciliation_hash=self.reconciliation_hash,
            verdict="fail",
        )
        with self.assertRaisesRegex(ReleaseAuthorityError, "only a PASS"):
            self.authority.issue_snapshot(
                decision.decision_id,
                requirements_manifest_hash=rejected.requirements_manifest_hash,
                issuance_key=stable_sha256("release-test", "rejected"),
            )
        connection = connect_database(self.settings.database_path)
        self.addCleanup(connection.close)
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE release_candidate SET artifact_manifest_hash=? WHERE candidate_id=?",
                ("2" * 64, candidate.candidate_id),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE release_candidate SET requirements_manifest_hash=? WHERE candidate_id=?",
                ("3" * 64, candidate.candidate_id),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM release_decision WHERE decision_id=?", (decision.decision_id,)
            )

    def test_decision_collision_is_rejected(self) -> None:
        candidate = self.authority.register_candidate(self.spec)
        with self.assertRaisesRegex(ReleaseAuthorityError, "different release material"):
            self.authority.register_candidate(
                replace(self.spec, requirements_manifest_hash="e" * 64)
            )
        self.authority.record_decision(
            candidate.candidate_id,
            deterministic_gate_hash=self.gate_hash,
            review_set_hash=self.review_hash,
            reconciliation_hash=self.reconciliation_hash,
            verdict="pass",
        )
        with self.assertRaisesRegex(ReleaseAuthorityError, "different immutable decision"):
            self.authority.record_decision(
                candidate.candidate_id,
                deterministic_gate_hash=self.gate_hash,
                review_set_hash=stable_sha256("release-test", "different-review"),
                reconciliation_hash=self.reconciliation_hash,
                verdict="pass",
            )


if __name__ == "__main__":
    import unittest

    unittest.main()
