from __future__ import annotations

from dataclasses import replace

from quant_hub.evidence.database import evidence_connection
from quant_hub.evidence.releases import EvidenceReleaseService
from quant_hub.evidence.repository import EvidenceConflict, EvidenceRepository
from quant_hub.ids import stable_sha256
from quant_hub.platform.releases import ReleaseAuthority, ReleaseCertificateMismatch
from tests.helpers import SettingsTestCase


class EvidenceReleaseAuthorityTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.service = EvidenceReleaseService(self.settings)
        self.repository = EvidenceRepository(self.settings)

    def _approve(self, prepared, *, label: str, issuance: str = "initial"):
        authority = ReleaseAuthority(self.settings)
        candidate = authority.register_candidate(prepared.candidate_spec)
        decision = authority.record_decision(
            candidate.candidate_id,
            deterministic_gate_hash=stable_sha256("evidence-test-gate/v1", label),
            review_set_hash=stable_sha256("evidence-test-review/v1", label),
            reconciliation_hash=stable_sha256("evidence-test-reconciliation/v1", label),
            verdict="pass",
        )
        certificate = authority.issue_snapshot(
            decision.decision_id,
            requirements_manifest_hash=prepared.candidate_spec.requirements_manifest_hash,
            issuance_key=stable_sha256("evidence-test-issuance/v1", label, issuance),
        )
        return authority, candidate, decision, certificate

    def test_staging_candidate_is_not_active(self) -> None:
        prepared = self.service.prepare_candidate()
        with evidence_connection(self.settings) as connection:
            status = connection.execute(
                "SELECT candidate_status FROM evidence_release WHERE evidence_release_id=?",
                (prepared.evidence_release_id,),
            ).fetchone()[0]
            active_count = connection.execute(
                "SELECT count(*) FROM active_evidence_release"
            ).fetchone()[0]
            receipt_count = connection.execute(
                "SELECT count(*) FROM platform_certificate_receipt"
            ).fetchone()[0]
        self.assertEqual("staging", status)
        self.assertEqual(0, active_count)
        self.assertEqual(0, receipt_count)

    def test_only_exact_platform_pass_certificate_activates_atomically(self) -> None:
        prepared = self.service.prepare_candidate()
        _, candidate, decision, certificate = self._approve(prepared, label="publish")
        forged = replace(certificate, decision_hash="f" * 64)
        with self.assertRaises(ReleaseCertificateMismatch):
            self.service.publish(prepared, forged)
        with evidence_connection(self.settings) as connection:
            self.assertEqual(
                0,
                connection.execute("SELECT count(*) FROM active_evidence_release").fetchone()[0],
            )

        published = self.service.publish(prepared, certificate)
        replayed = self.service.publish(prepared, certificate)
        self.assertTrue(published.created)
        self.assertFalse(replayed.created)
        self.assertEqual(1, published.active_revision)
        with evidence_connection(self.settings) as connection:
            active = connection.execute(
                "SELECT * FROM active_evidence_release"
            ).fetchone()
            receipt = connection.execute(
                "SELECT * FROM platform_certificate_receipt"
            ).fetchone()
            release = connection.execute(
                "SELECT candidate_status FROM evidence_release WHERE evidence_release_id=?",
                (prepared.evidence_release_id,),
            ).fetchone()
        self.assertEqual(published.activation_id, active["activation_id"])
        self.assertEqual("released", release["candidate_status"])
        self.assertEqual(candidate.candidate_id, receipt["platform_candidate_id"])
        self.assertEqual(decision.decision_id, receipt["platform_decision_id"])
        self.assertEqual(certificate.snapshot_urn, receipt["release_snapshot_urn"])
        self.assertEqual(
            prepared.candidate_spec.requirements_manifest_hash,
            receipt["requirements_manifest_hash"],
        )

    def test_rollback_requires_new_snapshot_and_appends_activation(self) -> None:
        first = self.service.prepare_candidate()
        authority, _, first_decision, first_certificate = self._approve(
            first, label="first"
        )
        first_published = self.service.publish(first, first_certificate)

        self.repository.put_clue(
            source_candidate_id="P-ROLL-FORWARD",
            entity_kind="paper_or_scholarly_work",
            domain_category="ML",
            raw_claim={"title": "forward-only clue"},
            provenance_urn="qrh:test:forward",
            resolution_status="unresolved",
        )
        second = self.service.prepare_candidate()
        _, _, _, second_certificate = self._approve(second, label="second")
        second_published = self.service.publish(second, second_certificate)
        self.assertEqual(2, second_published.active_revision)

        with self.assertRaisesRegex(EvidenceConflict, "old Evidence certificate"):
            self.service.publish(first, first_certificate)

        rollback_certificate = authority.issue_snapshot(
            first_decision.decision_id,
            requirements_manifest_hash=first.candidate_spec.requirements_manifest_hash,
            issuance_key=stable_sha256(
                "evidence-test-issuance/v1", "first", "explicit-rollback"
            ),
        )
        self.assertNotEqual(first_certificate.snapshot_urn, rollback_certificate.snapshot_urn)
        rollback = self.service.publish(first, rollback_certificate)
        self.assertEqual(3, rollback.active_revision)
        self.assertEqual(first.evidence_release_id, rollback.evidence_release_id)
        with evidence_connection(self.settings) as connection:
            active = connection.execute(
                "SELECT * FROM active_evidence_release"
            ).fetchone()
            activation = connection.execute(
                "SELECT * FROM evidence_release_activation WHERE activation_id=?",
                (rollback.activation_id,),
            ).fetchone()
            self.assertEqual(
                second_published.activation_id,
                activation["supersedes_activation_id"],
            )
            self.assertEqual(rollback.activation_id, active["activation_id"])
            self.assertEqual(3, active["revision"])
            self.assertEqual(
                3,
                connection.execute(
                    "SELECT count(*) FROM platform_certificate_receipt"
                ).fetchone()[0],
            )
            self.assertEqual(
                3,
                connection.execute(
                    "SELECT count(*) FROM evidence_release_activation"
                ).fetchone()[0],
            )
        self.assertEqual(1, first_published.active_revision)


if __name__ == "__main__":
    import unittest

    unittest.main()
