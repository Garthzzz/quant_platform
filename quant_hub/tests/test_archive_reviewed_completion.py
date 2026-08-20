from __future__ import annotations

from dataclasses import asdict

from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.archive.contracts import ArchiveDocumentInput, ArchiveReleaseInput, ActorInput, TopicInput
from quant_hub.archive.database import archive_connection
from quant_hub.collaboration.service import (
    ARCHIVE_COMPLETION_REVIEW_REQUIREMENTS_HASH,
    ArchiveCollaboration,
)
from quant_hub.ids import stable_sha256
from quant_hub.platform.db import immediate_transaction, utc_now
from quant_hub.platform.reviews import ReviewAuthority, ReviewCertificateSpec
from tests.helpers import SettingsTestCase


class ReviewedCompletionTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        (self.archive / "reviewed.md").write_text(
            "# 已审核研究\n\n来源明确给出完整结论。\n",
            encoding="utf-8",
            newline="\n",
        )
        fields = self.approved_source_fields("reviewed.md")
        self.release = ArchiveReleaseInput(
            research_slug="reviewed-completion",
            display_title="已审核完成研究",
            release_key="reviewed-v1",
            documents=(
                ArchiveDocumentInput(
                    document_slug="main",
                    document_role="primary",
                    source_path="reviewed.md",
                    **fields,
                    navigation_role="primary",
                    sort_key=10,
                    mapping_authority_urn="qrh:review:test-mapping",
                    mapping_note="测试中的显式 source→document 映射",
                ),
            ),
            summary="来源明确给出完整结论。",
            summary_provenance_urn=str(fields["approved_object_urn"]),
            activate=False,
        )
        self.catalog = ArchiveCatalog(self.settings)
        self.published = self.publish_with_test_certificate(
            self.catalog,
            self.release,
            label="reviewed-completion",
        )
        self.collaboration = ArchiveCollaboration(self.settings)

    def _certificate(self, *, artifact_hash: str | None = None):
        spec = self.published.candidate_spec
        return ReviewAuthority(self.settings).issue_pass_certificate(
            ReviewCertificateSpec(
                gate_name="archive_research_completion",
                gate_version="1",
                subject_urn=spec.subject_urn,
                subject_version_urn=spec.subject_version_urn,
                artifact_manifest_hash=artifact_hash or spec.artifact_manifest_hash,
                requirements_manifest_hash=ARCHIVE_COMPLETION_REVIEW_REQUIREMENTS_HASH,
                review_artifact_hash=stable_sha256("reviewed-completion/verdict/v1"),
                review_set_hash=stable_sha256("reviewed-completion/reviewer-set/v1"),
                reviewer_identity_hash=stable_sha256("reviewed-completion/reviewer/v1"),
            ),
            issuance_key=stable_sha256(
                "reviewed-completion/certificate/v1",
                artifact_hash or spec.artifact_manifest_hash,
            ),
        )

    @staticmethod
    def _require_ok(outcome):
        if not outcome.ok:
            raise AssertionError(asdict(outcome))
        return outcome.data or {}

    def test_bound_pass_certificate_completes_and_projects_dashboard(self) -> None:
        actor = ActorInput(actor_kind="zhang_zhengze")
        topic = self._require_ok(
            self.collaboration.create_topic(
                TopicInput(topic_key="reviewed-topic", title="已审核 Topic"),
                actor,
                idempotency_key="reviewed-topic-create",
            )
        )
        self._require_ok(
            self.collaboration.link_topic_research(
                str(topic["topic_id"]),
                self.published.research_id,
                actor,
                link_kind="primary",
                dashboard_primary=True,
                display_rank=10,
                provenance_urn="qrh:review:test-topic-link",
                idempotency_key="reviewed-topic-link",
            )
        )
        certificate = self._certificate()
        outcome = self.collaboration.complete_research(
            self.published.research_id,
            self.published.research_release_id,
            reason="独立审核确认该 release 的研究交付完整。",
            review_urn=certificate.certificate_urn,
            idempotency_key="reviewed-completion-command",
        )
        data = self._require_ok(outcome)
        self.assertEqual("reviewed_import", data["decision_kind"])
        dashboard = self.collaboration.dashboard()
        self.assertEqual("completed", dashboard[0]["state"])
        self.assertEqual("来源明确给出完整结论。", dashboard[0]["summary"])
        with archive_connection(self.settings) as connection:
            row = connection.execute(
                "SELECT * FROM research_completion_review_consumption"
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(certificate.certificate_urn, row["certificate_urn"])
            status = connection.execute(
                "SELECT work_status FROM research_status_projection WHERE research_id=?",
                (self.published.research_id,),
            ).fetchone()
            self.assertEqual("completed", status["work_status"])

    def test_bare_mismatched_or_unconsumed_review_cannot_project_completed(self) -> None:
        bare = self.collaboration.complete_research(
            self.published.research_id,
            self.published.research_release_id,
            reason="伪造审核。",
            review_urn="qrh:review-certificate:rvc_missing",
            idempotency_key="reviewed-completion-bare",
        )
        self.assertFalse(bare.ok)
        self.assertEqual("review_certificate_invalid", bare.error_code)

        with archive_connection(self.settings) as connection, immediate_transaction(connection):
            connection.execute(
                """
                INSERT INTO research_completion_decision(
                    decision_id,research_id,research_release_id,decision,decision_kind,
                    supersedes_decision_id,target_decision_id,actor_id,review_urn,reason,decided_at
                ) VALUES('forged-decision',?,?,'completed','reviewed_import',NULL,NULL,NULL,
                         'qrh:review-certificate:rvc_forged','直接 SQL 伪造',?)
                """,
                (self.published.research_id, self.published.research_release_id, utc_now()),
            )
            self.collaboration.recompute_after_release_activation(
                connection,
                self.published.research_id,
            )
            status = connection.execute(
                "SELECT work_status,completion_decision_id FROM research_status_projection WHERE research_id=?",
                (self.published.research_id,),
            ).fetchone()
            self.assertEqual(("planned", None), tuple(status))


if __name__ == "__main__":
    unittest.main()
