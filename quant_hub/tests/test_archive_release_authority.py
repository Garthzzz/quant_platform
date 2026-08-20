from __future__ import annotations

from quant_hub.archive.catalog import ArchiveCatalog, ArchiveMappingConflict
from quant_hub.archive.contracts import ArchiveDocumentInput, ArchiveReleaseInput
from quant_hub.archive.database import archive_connection
from quant_hub.ids import stable_sha256
from quant_hub.platform.releases import (
    CandidateRegistration,
    ReleaseAuthority,
    ReleaseCandidateSpec,
    ReleaseCertificate,
    ReleaseCertificateMismatch,
    ReleaseDecision,
)
from tests.helpers import SettingsTestCase


class ArchiveReleaseAuthorityIntegrationTests(SettingsTestCase):
    """Archive 只消费 platform authority 已登记且逐字段匹配的 PASS snapshot。"""

    def setUp(self) -> None:
        super().setUp()
        self.v1 = b"# Authority boundary\n\nimmutable source v1\n"
        self.v2 = b"# Authority boundary\n\nimmutable source v2\n"
        (self.archive / "authority-v1.md").write_bytes(self.v1)
        (self.archive / "authority-v2.md").write_bytes(self.v2)
        (self.archive / "authority-mutable.md").write_bytes(self.v1)
        self.catalog = ArchiveCatalog(self.settings)
        self.authority = ReleaseAuthority(self.settings)

    def _release(
        self,
        source_path: str,
        release_key: str,
        *,
        research_slug: str = "authority-boundary",
        display_title: str = "发布信任边界",
    ) -> ArchiveReleaseInput:
        return ArchiveReleaseInput(
            research_slug=research_slug,
            display_title=display_title,
            release_key=release_key,
            documents=(
                ArchiveDocumentInput(
                    document_slug="main",
                    document_role="primary",
                    source_path=source_path,
                    **self.approved_source_fields(source_path),
                    navigation_role="primary",
                    sort_key=10,
                    mapping_authority_urn="qrh:review:authority-boundary-mapping",
                    mapping_note="发布信任边界集成测试的显式 source→document 映射",
                ),
            ),
            activate=False,
        )

    def _approve(
        self, draft: ArchiveReleaseInput, *, label: str
    ) -> tuple[
        ReleaseCandidateSpec,
        CandidateRegistration,
        ReleaseDecision,
        ReleaseCertificate,
    ]:
        spec = self.catalog.prepare_release_candidate(draft)
        candidate = self.authority.register_candidate(spec)
        decision = self.authority.record_decision(
            candidate.candidate_id,
            deterministic_gate_hash=stable_sha256(
                "archive-authority-test/gate/v1", label, spec.artifact_manifest_hash
            ),
            review_set_hash=stable_sha256(
                "archive-authority-test/review/v1", label, spec.source_snapshot_hash
            ),
            reconciliation_hash=stable_sha256(
                "archive-authority-test/reconciliation/v1",
                label,
                spec.projection_revision,
            ),
            verdict="pass",
        )
        certificate = self.authority.issue_snapshot(
            decision.decision_id,
            requirements_manifest_hash=spec.requirements_manifest_hash,
            issuance_key=stable_sha256(
                "archive-authority-test/issuance/v1", label, "initial"
            ),
        )
        return spec, candidate, decision, certificate

    @staticmethod
    def _with_certificate(
        draft: ArchiveReleaseInput, certificate: ReleaseCertificate
    ) -> ArchiveReleaseInput:
        return draft.model_copy(
            update={
                "activate": True,
                "release_snapshot_urn": certificate.snapshot_urn,
                "activation_decision_hash": certificate.decision_hash,
            }
        )

    def _archive_counts(self) -> tuple[int, int, int, int, int]:
        with archive_connection(self.settings) as connection:
            return tuple(
                int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
                for table in (
                    "research",
                    "research_release",
                    "active_research_release",
                    "research_release_activation",
                    "research_release_authority_consumption",
                )
            )

    def test_forged_or_missing_snapshot_fails_before_archive_publication(self) -> None:
        draft = self._release("authority-v1.md", "v1")
        _, _, _, certificate = self._approve(draft, label="forged-caller")
        forged_existing = draft.model_copy(
            update={
                "activate": True,
                "release_snapshot_urn": certificate.snapshot_urn,
                "activation_decision_hash": "f" * 64,
            }
        )
        forged = draft.model_copy(
            update={
                "activate": True,
                "release_snapshot_urn": "qrh:release_snapshot:rsnp_" + "0" * 32,
                "activation_decision_hash": "0" * 64,
            }
        )

        with self.assertRaisesRegex(ReleaseCertificateMismatch, "decision hash"):
            self.catalog.publish_release(forged_existing)
        with self.assertRaisesRegex(ReleaseCertificateMismatch, "not registered"):
            self.catalog.publish_release(forged)

        self.assertEqual((0, 0, 0, 0, 0), self._archive_counts())
        self.assertEqual([], self.catalog.list_research())

    def test_certificate_cannot_authorize_mismatched_manifest_subject_or_version(self) -> None:
        base = self._release("authority-v1.md", "v1")
        base_spec, _, _, certificate = self._approve(base, label="mismatch-base")
        mismatches = {
            "manifest": self._release(
                "authority-v1.md", "v1", display_title="发布信任边界（篡改标题）"
            ),
            "subject": self._release(
                "authority-v1.md", "v1", research_slug="different-subject"
            ),
            "release-version": self._release("authority-v1.md", "v1-repacked"),
        }

        for label, draft in mismatches.items():
            with self.subTest(label=label):
                actual_spec = self.catalog.prepare_release_candidate(draft)
                self.assertNotEqual(base_spec, actual_spec)
                if label == "subject":
                    self.assertNotEqual(base_spec.subject_urn, actual_spec.subject_urn)
                else:
                    self.assertNotEqual(
                        base_spec.artifact_manifest_hash,
                        actual_spec.artifact_manifest_hash,
                    )
                    self.assertNotEqual(
                        base_spec.subject_version_urn,
                        actual_spec.subject_version_urn,
                    )
                with self.assertRaisesRegex(
                    ReleaseCertificateMismatch, "candidate material"
                ):
                    self.catalog.publish_release(
                        self._with_certificate(draft, certificate)
                    )

        self.assertEqual((0, 0, 0, 0, 0), self._archive_counts())
        self.assertEqual([], self.catalog.list_research())

    def test_old_candidate_and_certificate_cannot_authorize_changed_source_bytes(self) -> None:
        old = self._release("authority-mutable.md", "v1")
        old_spec, _, _, old_certificate = self._approve(old, label="mutable-v1")
        (self.archive / "authority-mutable.md").write_bytes(self.v2)
        changed = self._release("authority-mutable.md", "v1")
        changed_spec = self.catalog.prepare_release_candidate(changed)

        self.assertNotEqual(old_spec.source_snapshot_hash, changed_spec.source_snapshot_hash)
        self.assertNotEqual(
            old_spec.artifact_manifest_hash, changed_spec.artifact_manifest_hash
        )
        with self.assertRaisesRegex(ReleaseCertificateMismatch, "candidate material"):
            self.catalog.publish_release(
                self._with_certificate(changed, old_certificate)
            )

        self.assertEqual((0, 0, 0, 0, 0), self._archive_counts())
        self.assertEqual([], self.catalog.list_research())

    def test_rollback_requires_new_snapshot_issuance_for_same_approved_v1_candidate(
        self,
    ) -> None:
        v1 = self._release("authority-v1.md", "v1")
        v1_spec, v1_candidate, v1_decision, v1_certificate = self._approve(
            v1, label="rollback-v1"
        )
        published_v1 = self.catalog.publish_release(
            self._with_certificate(v1, v1_certificate)
        )
        v2 = self._release("authority-v2.md", "v2")
        _, _, _, v2_certificate = self._approve(v2, label="rollback-v2")
        published_v2 = self.catalog.publish_release(
            self._with_certificate(v2, v2_certificate)
        )

        # 已消费的 v1 snapshot 不能在 v2 生效后被复用为隐式降级凭据。
        with self.assertRaisesRegex(
            ArchiveMappingConflict, "old activation certificate"
        ):
            self.catalog.publish_release(
                self._with_certificate(v1, v1_certificate)
            )
        with archive_connection(self.settings) as connection:
            active_before = connection.execute(
                "SELECT * FROM active_research_release WHERE research_id=?",
                (published_v2.research_id,),
            ).fetchone()
            self.assertEqual(
                published_v2.research_release_id,
                active_before["research_release_id"],
            )
            self.assertEqual(2, active_before["revision"])
            self.assertEqual(
                2,
                connection.execute(
                    "SELECT count(*) FROM research_release_activation"
                ).fetchone()[0],
            )
            self.assertEqual(
                2,
                connection.execute(
                    "SELECT count(*) FROM research_release_authority_consumption"
                ).fetchone()[0],
            )

        rollback_certificate = self.authority.issue_snapshot(
            v1_decision.decision_id,
            requirements_manifest_hash=v1_spec.requirements_manifest_hash,
            issuance_key=stable_sha256(
                "archive-authority-test/issuance/v1", "rollback-v1", "explicit-rollback"
            ),
        )
        self.assertEqual(v1_candidate.candidate_id, rollback_certificate.candidate_id)
        self.assertNotEqual(v1_certificate.snapshot_urn, rollback_certificate.snapshot_urn)
        rolled_back = self.catalog.publish_release(
            self._with_certificate(v1, rollback_certificate)
        )

        self.assertFalse(rolled_back.created)
        self.assertEqual(published_v1.research_release_id, rolled_back.research_release_id)
        self.assertEqual(3, rolled_back.active_revision)
        with archive_connection(self.settings) as connection:
            active = connection.execute(
                "SELECT * FROM active_research_release WHERE research_id=?",
                (rolled_back.research_id,),
            ).fetchone()
            self.assertEqual(published_v1.research_release_id, active["research_release_id"])
            self.assertEqual(rollback_certificate.snapshot_urn, active["release_snapshot_urn"])
            self.assertEqual(3, active["revision"])
            activation = connection.execute(
                "SELECT * FROM research_release_activation WHERE activation_id=?",
                (rolled_back.activation_id,),
            ).fetchone()
            self.assertEqual(published_v2.activation_id, activation["supersedes_activation_id"])
            consumption = connection.execute(
                "SELECT * FROM research_release_authority_consumption WHERE activation_id=?",
                (rolled_back.activation_id,),
            ).fetchone()
            self.assertEqual(v1_candidate.candidate_id, consumption["platform_candidate_id"])
            self.assertEqual(
                rollback_certificate.snapshot_urn,
                consumption["release_snapshot_urn"],
            )
            self.assertEqual(rollback_certificate.decision_hash, consumption["decision_hash"])
            self.assertEqual(
                3,
                connection.execute(
                    "SELECT count(*) FROM research_release_activation"
                ).fetchone()[0],
            )
            self.assertEqual(
                3,
                connection.execute(
                    "SELECT count(*) FROM research_release_authority_consumption"
                ).fetchone()[0],
            )


if __name__ == "__main__":
    import unittest

    unittest.main()
