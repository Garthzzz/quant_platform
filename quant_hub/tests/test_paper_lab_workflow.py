from __future__ import annotations

import os
import sqlite3
from unittest.mock import patch

from quant_hub.ids import stable_sha256
from quant_hub.paper_lab.database import paper_lab_connection
from quant_hub.paper_lab.service import PaperLabService
from quant_hub.paper_lab.reviewer import PaperLabReviewerAuthority, ReviewerAuthorityError
from quant_hub.platform.reviews import (
    ReviewAuthority,
    ReviewCertificateMismatch,
    ReviewCertificateSpec,
)
from tests.paper_lab_review_authority import (
    build_presigned_document,
    register_presigned_test_certificate,
    trusted_key_environment,
)
from tests.helpers import SettingsTestCase


class PaperLabWorkflowTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        trusted_environment = patch.dict(
            os.environ,
            {"QRH_PAPER_LAB_REVIEWER_RSA_KEYS": trusted_key_environment()},
        )
        trusted_environment.start()
        self.addCleanup(trusted_environment.stop)
        root = self.settings.paper_lab_drop_root
        root.mkdir(parents=True, exist_ok=True)
        (root / "1_workflow.pdf").write_bytes(b"%PDF-1.4\nworkflow\n%%EOF")
        self.service = PaperLabService(self.settings)
        self.registration = self.service.register_all()[0]
        with paper_lab_connection(self.settings) as connection:
            self.content_sha256 = connection.execute(
                "SELECT content_sha256 FROM lab_paper_version WHERE paper_version_id=?",
                (self.registration.paper_version_id,),
            ).fetchone()[0]

    def evidence(self, label: str) -> list[dict[str, object]]:
        return [{
            "paper_version_id": self.registration.paper_version_id,
            "content_sha256": self.content_sha256,
            "page": 1,
            "locator": "pdf-page:1",
            "excerpt": f"{label} evidence",
        }]

    def issue_review_certificate(
        self, run_id: str, *, artifact_hash: str | None = None, label: str = "valid",
    ) -> str:
        if artifact_hash is None:
            return register_presigned_test_certificate(
                self.settings, self.service, run_id
            ).certificate_urn
        material = self.service.review_material(run_id)
        certificate = ReviewAuthority(self.settings).issue_pass_certificate(
            ReviewCertificateSpec(
                gate_name=material.gate_name,
                gate_version=material.gate_version,
                subject_urn=material.subject_urn,
                subject_version_urn=material.subject_version_urn,
                artifact_manifest_hash=artifact_hash or material.run_artifact_hash,
                requirements_manifest_hash=material.requirements_manifest_hash,
                review_artifact_hash=stable_sha256(
                    "paper-lab-test-review-artifact/v1", run_id
                ),
                review_set_hash=stable_sha256(
                    "paper-lab-test-review-set/v1", material.run_artifact_hash
                ),
                reviewer_identity_hash=stable_sha256("producer-selected-reviewer/v1"),
            ),
            issuance_key=stable_sha256(
                "paper-lab-test-review-issuance/v1", run_id, label
            ),
        )
        return certificate.certificate_urn

    def test_four_phase_result_requires_review_before_publish(self) -> None:
        queued = self.service.queue_reading(self.registration.paper_id)
        self.assertEqual(queued.status, "queued")
        claimed = self.service.claim_run(queued.run_id)
        self.assertEqual(claimed.status, "running")
        phases = (
            ("problem", "problem"),
            ("method", "method"),
            ("experiment", "experiment"),
            ("synthesis", "synthesis"),
        )
        for phase, kind in phases:
            self.service.submit_phase(
                queued.run_id,
                phase,
                kind,  # type: ignore[arg-type]
                {"conclusion": phase},
                self.evidence(phase),
            )
        with paper_lab_connection(self.settings) as connection:
            status = connection.execute(
                "SELECT status FROM reading_run WHERE run_id=?", (queued.run_id,)
            ).fetchone()[0]
        self.assertEqual(status, "awaiting_review")
        with self.assertRaisesRegex(RuntimeError, "not releasable"):
            self.service.publish_run(queued.run_id)
        with self.assertRaisesRegex(ReviewCertificateMismatch, "requires a review certificate"):
            self.service.review_run(
                queued.run_id, verdict="pass", reason="missing certificate"
            )
        mismatched_urn = self.issue_review_certificate(
            queued.run_id, artifact_hash="f" * 64, label="mismatched"
        )
        with self.assertRaisesRegex(ReviewCertificateMismatch, "does not match"):
            self.service.review_run(
                queued.run_id,
                verdict="pass",
                reason="mismatched certificate",
                certificate_urn=mismatched_urn,
            )
        self_signed_urn = self.issue_review_certificate(
            queued.run_id,
            artifact_hash=self.service.review_material(queued.run_id).run_artifact_hash,
            label="producer-self-signed",
        )
        with self.assertRaisesRegex(ReviewCertificateMismatch, "independent reviewer"):
            self.service.review_run(
                queued.run_id,
                verdict="pass",
                reason="producer may not self-authorize",
                certificate_urn=self_signed_urn,
            )
        tampered = build_presigned_document(self.service, queued.run_id)
        tampered["authority_input"]["certificate_spec"]["review_set_hash"] = "f" * 64
        with patch.dict(
            os.environ,
            {"QRH_PAPER_LAB_REVIEWER_RSA_KEYS": trusted_key_environment()},
        ):
            with self.assertRaisesRegex(ReviewerAuthorityError, "signature"):
                PaperLabReviewerAuthority(self.settings).register_presigned_pass_certificate(
                    tampered
                )
        certificate_urn = self.issue_review_certificate(queued.run_id)
        self.assertEqual(
            self.service.review_run(
                queued.run_id,
                verdict="pass",
                reason="独立复核通过",
                certificate_urn=certificate_urn,
            ).status,
            "releasable",
        )
        self.assertEqual(self.service.publish_run(queued.run_id).status, "published")
        with paper_lab_connection(self.settings) as connection:
            receipt = connection.execute(
                "SELECT * FROM reading_review_receipt WHERE run_id=?", (queued.run_id,)
            ).fetchone()
            self.assertEqual(receipt["certificate_urn"], certificate_urn)
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "UPDATE reading_review_receipt SET review_set_hash=? WHERE run_id=?",
                    ("f" * 64, queued.run_id),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    """
                    UPDATE reading_review_authority_input
                    SET review_set_hash=? WHERE run_id=?
                    """,
                    ("f" * 64, queued.run_id),
                )

    def test_empty_evidence_is_rejected_without_result(self) -> None:
        run = self.service.queue_reading(self.registration.paper_id)
        self.service.claim_run(run.run_id)
        with self.assertRaisesRegex(ValueError, "evidence"):
            self.service.submit_phase(run.run_id, "problem", "problem", {"x": 1}, [])
        with paper_lab_connection(self.settings) as connection:
            count = connection.execute(
                "SELECT count(*) FROM reading_result WHERE run_id=?", (run.run_id,)
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_reading_result_is_immutable(self) -> None:
        run = self.service.queue_reading(self.registration.paper_id)
        self.service.claim_run(run.run_id)
        result_id = self.service.submit_phase(
            run.run_id, "problem", "problem", {"x": 1}, self.evidence("problem")
        )
        with paper_lab_connection(self.settings) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "UPDATE reading_result SET payload_json='{}' WHERE result_id=?", (result_id,)
                )

    def test_unbound_or_incomplete_evidence_is_rejected_without_result(self) -> None:
        run = self.service.queue_reading(self.registration.paper_id)
        self.service.claim_run(run.run_id)
        invalid = [
            [{"page": 1}],
            [{**self.evidence("wrong-version")[0], "paper_version_id": "labver_wrong"}],
            [{**self.evidence("wrong-hash")[0], "content_sha256": "f" * 64}],
            [{**self.evidence("wrong-locator")[0], "locator": "pdf-page:2"}],
            [{**self.evidence("blank-excerpt")[0], "excerpt": " "}],
        ]
        for locators in invalid:
            with self.subTest(locators=locators):
                with self.assertRaisesRegex(ValueError, "evidence"):
                    self.service.submit_phase(
                        run.run_id,
                        "problem",
                        "problem",
                        {"x": 1},
                        locators,
                    )
        with paper_lab_connection(self.settings) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM reading_result WHERE run_id=?", (run.run_id,)
                ).fetchone()[0],
                0,
            )
