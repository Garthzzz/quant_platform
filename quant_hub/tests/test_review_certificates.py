from __future__ import annotations

from dataclasses import replace
import sqlite3

from quant_hub.ids import stable_sha256
from quant_hub.platform.db import connect_database
from quant_hub.platform.reviews import (
    ReviewAuthority,
    ReviewCertificateMismatch,
    ReviewCertificateSpec,
)
from tests.helpers import SettingsTestCase


class ReviewCertificateTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.authority = ReviewAuthority(self.settings)
        self.spec = ReviewCertificateSpec(
            gate_name="archive_research_completion",
            gate_version="1",
            subject_urn="qrh:archive-research:reviewed-subject",
            subject_version_urn="qrh:archive-release:reviewed-subject:sha256:" + "a" * 64,
            artifact_manifest_hash="a" * 64,
            requirements_manifest_hash="b" * 64,
            review_artifact_hash="c" * 64,
            review_set_hash="d" * 64,
            reviewer_identity_hash="e" * 64,
        )

    def test_issue_verify_and_idempotent_replay_are_material_bound(self) -> None:
        key = stable_sha256("review-certificate-test/v1", "one")
        first = self.authority.issue_pass_certificate(self.spec, issuance_key=key)
        second = self.authority.issue_pass_certificate(self.spec, issuance_key=key)
        self.assertEqual(first, second)
        verified = self.authority.verify_certificate(
            first.certificate_urn,
            gate_name=self.spec.gate_name,
            gate_version=self.spec.gate_version,
            subject_urn=self.spec.subject_urn,
            subject_version_urn=self.spec.subject_version_urn,
            artifact_manifest_hash=self.spec.artifact_manifest_hash,
            requirements_manifest_hash=self.spec.requirements_manifest_hash,
        )
        self.assertEqual(first, verified)

        changed = replace(self.spec, artifact_manifest_hash="f" * 64)
        with self.assertRaisesRegex(ReviewCertificateMismatch, "different material"):
            self.authority.issue_pass_certificate(changed, issuance_key=key)
        with self.assertRaisesRegex(ReviewCertificateMismatch, "active subject"):
            self.authority.verify_certificate(
                first.certificate_urn,
                gate_name=self.spec.gate_name,
                gate_version=self.spec.gate_version,
                subject_urn="qrh:archive-research:other",
                subject_version_urn=self.spec.subject_version_urn,
                artifact_manifest_hash=self.spec.artifact_manifest_hash,
                requirements_manifest_hash=self.spec.requirements_manifest_hash,
            )

    def test_certificate_rows_are_append_only(self) -> None:
        certificate = self.authority.issue_pass_certificate(
            self.spec,
            issuance_key=stable_sha256("review-certificate-test/v1", "append-only"),
        )
        connection = connect_database(self.settings.database_path)
        self.addCleanup(connection.close)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            connection.execute(
                "UPDATE review_certificate SET gate_version='2' WHERE certificate_id=?",
                (certificate.certificate_id,),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            connection.execute(
                "DELETE FROM review_certificate WHERE certificate_id=?",
                (certificate.certificate_id,),
            )


if __name__ == "__main__":
    unittest.main()
