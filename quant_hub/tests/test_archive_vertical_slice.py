from __future__ import annotations

from dataclasses import replace
import json

from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.archive.contracts import (
    ActorInput,
    ArchiveDocumentInput,
    ArchiveReleaseInput,
    ArchiveVersionRelationInput,
    TopicInput,
)
from quant_hub.archive.database import archive_connection
from quant_hub.collaboration.service import ArchiveCollaboration, IdempotencyConflict
from quant_hub.ids import sha256_hex, stable_sha256
from quant_hub.platform.db import immediate_transaction
from tests.helpers import SettingsTestCase


class ArchiveVerticalSliceTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.catalog = ArchiveCatalog(self.settings)
        self.collaboration = ArchiveCollaboration(self.settings)
        self.actor = ActorInput(actor_kind="zhang_zhengze")
        self.v1 = b"# \xe7\xa0\x94\xe7\xa9\xb6 A\n\n\xe7\x8b\xac\xe7\x89\xb9\xe4\xb8\xad\xe6\x96\x87\xe6\x90\x9c\xe7\xb4\xa2\xe8\xaf\x8d\xe7\xbb\x84 alpha-signal\xe3\x80\x82\n\n|\xe5\x88\x97|\xe5\x80\xbc|\n|---|---:|\n|x|$r_t$|\n"
        self.v2 = b"# \xe7\xa0\x94\xe7\xa9\xb6 A\n\n\xe7\x8b\xac\xe7\x89\xb9\xe4\xb8\xad\xe6\x96\x87\xe6\x90\x9c\xe7\xb4\xa2\xe8\xaf\x8d\xe7\xbb\x84 alpha-signal\xe3\x80\x82\n\n## \xe6\x89\xa9\xe5\xb1\x95\n\n$$R=\x5csum_t r_t$$\n"
        (self.archive / "research-a-v1.md").write_bytes(self.v1)
        (self.archive / "research-a-v2.md").write_bytes(self.v2)

    def _document(self, source_path: str) -> ArchiveDocumentInput:
        return ArchiveDocumentInput(
            document_slug="main",
            document_role="primary",
            source_path=source_path,
            **self.approved_source_fields(source_path),
            navigation_role="primary",
            sort_key=10,
            mapping_authority_urn="qrh:review:test-mapping",
            mapping_note="测试夹具中的显式 document 映射",
        )

    def _release(
        self,
        source_path: str,
        key: str,
        summary: str,
        *,
        relation: bool = False,
    ) -> ArchiveReleaseInput:
        relations = ()
        if relation:
            relations = (
                ArchiveVersionRelationInput(
                    document_slug="main",
                    from_content_sha256=sha256_hex(self.v2),
                    to_content_sha256=sha256_hex(self.v1),
                    relation_kind="derived_from",
                    status="verified",
                    provenance_urn="qrh:source:test-v2-lineage",
                ),
            )
        return ArchiveReleaseInput(
            research_slug="research-a",
            display_title="研究 A",
            release_key=key,
            documents=(self._document(source_path),),
            version_relations=relations,
            summary=summary,
            summary_provenance_urn=(
                f"qrh:object:obj_sha256_{sha256_hex((self.archive / source_path).read_bytes())}"
            ),
            activate=False,
        )

    def test_versioned_release_completion_dashboard_and_search(self) -> None:
        source_before = {
            path.name: path.read_bytes()
            for path in self.archive.glob("*.md")
        }
        first = self.publish_with_test_certificate(
            self.catalog,
            self._release("research-a-v1.md", "v1", "第一版研究摘要。"),
            label="vertical-v1",
        )
        replay = self.publish_with_test_certificate(
            self.catalog,
            self._release("research-a-v1.md", "v1", "第一版研究摘要。"),
            label="vertical-v1",
        )
        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        self.assertEqual(first.research_release_id, replay.research_release_id)

        topic = self.collaboration.create_topic(
            TopicInput(topic_key="topic-a", title="Topic A", manual_order=10),
            self.actor,
            idempotency_key="topic-create-a-0001",
        )
        self.assertTrue(topic.ok)
        topic_id = str(topic.data["topic_id"])
        linked = self.collaboration.link_topic_research(
            topic_id,
            first.research_id,
            self.actor,
            link_kind="primary",
            dashboard_primary=True,
            display_rank=10,
            provenance_urn="qrh:review:test-topic-link",
            idempotency_key="topic-link-a-0001",
        )
        self.assertTrue(linked.ok)
        completed_v1 = self.collaboration.complete_research(
            first.research_id,
            first.research_release_id,
            reason="独立测试确认 v1 的定义范围已完成。",
            actor=self.actor,
            idempotency_key="research-complete-v1-0001",
        )
        self.assertTrue(completed_v1.ok)
        self.assertEqual("completed", self.collaboration.dashboard()[0]["state"])
        with archive_connection(self.settings) as connection:
            connection.execute(
                "UPDATE research_status_projection SET evidence_status='passed', evidence_source_urn='qrh:evidence_release:test-v1' WHERE research_id=?",
                (first.research_id,),
            )

        second = self.publish_with_test_certificate(
            self.catalog,
            self._release(
                "research-a-v2.md",
                "v2",
                "第二版研究摘要。",
                relation=True,
            ),
            label="vertical-v2",
        )
        # v1 的 completion decision 不得跨 active release 继承。
        self.assertEqual("planned", self.collaboration.dashboard()[0]["state"])
        completed_v2 = self.collaboration.complete_research(
            second.research_id,
            second.research_release_id,
            reason="独立测试确认 v2 的定义范围已完成。",
            actor=self.actor,
            idempotency_key="research-complete-v2-0001",
        )
        self.assertTrue(completed_v2.ok)
        duplicate_completion = self.collaboration.complete_research(
            second.research_id,
            second.research_release_id,
            reason="不应产生第二个并行有效决定。",
            actor=self.actor,
            idempotency_key="research-complete-v2-duplicate-0001",
        )
        self.assertFalse(duplicate_completion.ok)
        self.assertEqual("already_completed", duplicate_completion.error_code)
        dashboard = self.collaboration.dashboard()[0]
        self.assertEqual("completed", dashboard["state"])
        self.assertEqual("第二版研究摘要。", dashboard["summary"])
        self.assertEqual(f"/research/{second.research_id}", dashboard["page_url"])

        page = self.catalog.research_page(second.research_id)
        self.assertEqual(second.research_release_id, page["research_release_id"])
        self.assertEqual("completed", page["work_status"])
        self.assertIn('class="math math-display"', page["documents"][0]["rendered_html"])
        self.assertIn('data-math-rendered="mathml"', page["documents"][0]["rendered_html"])
        self.assertEqual(1, len(self.catalog.search("独特中文搜索词组")))
        self.assertEqual(1, len(self.catalog.search("alpha-signal")))
        revoked = self.collaboration.revoke_completion(
            second.research_id,
            str(completed_v2.data["decision_id"]),
            reason="验证撤销事件会重建 Dashboard。",
            actor=self.actor,
            idempotency_key="research-revoke-v2-0001",
        )
        self.assertTrue(revoked.ok)
        self.assertEqual("planned", self.collaboration.dashboard()[0]["state"])
        recompleted = self.collaboration.complete_research(
            second.research_id,
            second.research_release_id,
            reason="撤销测试完成后重新作出当前 release 的显式决定。",
            actor=self.actor,
            idempotency_key="research-recomplete-v2-0001",
        )
        self.assertTrue(recompleted.ok)
        self.assertEqual("completed", self.collaboration.dashboard()[0]["state"])
        with archive_connection(self.settings) as connection:
            versions = connection.execute("SELECT count(*) FROM research_document_version").fetchone()[0]
            relations = connection.execute("SELECT count(*) FROM document_version_relation WHERE status='verified'").fetchone()[0]
            axes = connection.execute("SELECT work_status,release_status,evidence_status FROM research_status_projection WHERE research_id=?", (second.research_id,)).fetchone()
        self.assertEqual(2, versions)
        self.assertEqual(1, relations)
        self.assertEqual(("completed", "published", "passed"), tuple(axes))
        self.assertEqual(source_before, {path.name: path.read_bytes() for path in self.archive.glob("*.md")})

    def test_projector_upgrade_atomically_replaces_single_derived_projection(self) -> None:
        published = self.publish_with_test_certificate(
            self.catalog,
            self._release("research-a-v1.md", "v1", "projector upgrade fixture"),
            label="projection-upgrade-v1",
        )
        prepared = self.catalog._prepare_document(self._document("research-a-v1.md"))
        next_projection = replace(
            prepared.projection,
            projector_version="qrh-markdown-projection/test-next",
        )
        next_prepared = replace(
            prepared,
            projection=next_projection,
            validation_manifest_hash=stable_sha256(
                "archive-document-projection/v1",
                next_projection.projector_version,
                next_projection.document_sha256,
                prepared.rendered_object_id,
                str(len(next_projection.headings)),
                str(len(next_projection.math_nodes)),
                sha256_hex(next_projection.plain_text.encode("utf-8")),
            ),
        )

        with archive_connection(self.settings) as connection:
            with immediate_transaction(connection):
                ArchiveCatalog._projection(
                    connection,
                    published.document_version_ids[0],
                    next_prepared,
                )
            projections = connection.execute(
                "SELECT projector_version FROM document_projection WHERE document_version_id=?",
                (published.document_version_ids[0],),
            ).fetchall()
            outline_count = connection.execute(
                "SELECT count(*) FROM outline_node WHERE document_version_id=?",
                (published.document_version_ids[0],),
            ).fetchone()[0]

        self.assertEqual([next_projection.projector_version], [row[0] for row in projections])
        self.assertEqual(len(next_projection.headings), outline_count)
        self.assertEqual(1, len(self.catalog.research_page(published.research_id)["documents"]))

    def test_comments_are_persistent_idempotent_and_revision_guarded(self) -> None:
        release = self.publish_with_test_certificate(
            self.catalog,
            self._release("research-a-v1.md", "v1", "评论测试摘要。"),
            label="vertical-comment-v1",
        )
        created = self.collaboration.create_comment(
            release.research_id,
            ActorInput(actor_kind="other", display_name="研究员甲"),
            "第一条评论 <script>不是 HTML</script>",
            idempotency_key="comment-create-0001",
        )
        replay = self.collaboration.create_comment(
            release.research_id,
            ActorInput(actor_kind="other", display_name="研究员甲"),
            "第一条评论 <script>不是 HTML</script>",
            idempotency_key="comment-create-0001",
        )
        self.assertTrue(created.ok)
        self.assertTrue(replay.replayed)
        self.assertEqual(created.data, replay.data)
        with self.assertRaises(IdempotencyConflict):
            self.collaboration.create_comment(
                release.research_id,
                self.actor,
                "同 key 不同 payload",
                idempotency_key="comment-create-0001",
            )
        comment_id = str(created.data["comment_id"])
        updated = self.collaboration.update_comment(
            comment_id,
            self.actor,
            "修订后的纯文本评论",
            expected_revision=1,
            idempotency_key="comment-update-0001",
        )
        self.assertTrue(updated.ok)
        stale = self.collaboration.update_comment(
            comment_id,
            self.actor,
            "过时更新",
            expected_revision=1,
            idempotency_key="comment-stale-0001",
        )
        stale_replay = self.collaboration.update_comment(
            comment_id,
            self.actor,
            "过时更新",
            expected_revision=1,
            idempotency_key="comment-stale-0001",
        )
        self.assertFalse(stale.ok)
        self.assertEqual("revision_conflict", stale.error_code)
        self.assertTrue(stale_replay.replayed)
        persisted = ArchiveCollaboration(self.settings).list_comments(release.research_id)
        self.assertEqual("修订后的纯文本评论", persisted[0]["content"])
        self.assertEqual(2, persisted[0]["revision"])
        with archive_connection(self.settings) as connection:
            self.assertEqual(2, connection.execute("SELECT count(*) FROM comment_event").fetchone()[0])
            self.assertEqual(3, connection.execute("SELECT count(*) FROM command_receipt WHERE command_name LIKE 'comment.%'").fetchone()[0])


if __name__ == "__main__":
    import unittest

    unittest.main()
