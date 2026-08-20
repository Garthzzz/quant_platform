from __future__ import annotations

from contextlib import closing
import hashlib
import json
import sqlite3
from pathlib import Path
from unittest.mock import Mock, patch

from pydantic import ValidationError

from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.archive.contracts import ActorInput, ArchiveDocumentInput, ArchiveReleaseInput
from quant_hub.archive.database import archive_connection
from quant_hub.collaboration.comment_anchors import (
    CommentAnchorSnapshot,
    CommentTargetInput,
    SnapshotBlock,
    SnapshotDocument,
    UnchangedBlockMapping,
    build_comment_anchor_projection,
    load_comment_anchor_projection,
    write_comment_anchor_projection,
)
from quant_hub.collaboration.comment_store import (
    comment_store_state,
    initialize_comment_store,
)
from quant_hub.collaboration.service import ArchiveCollaboration
from quant_hub.web.contracts import CommentCreate
from tests.helpers import SettingsTestCase


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _span(source: bytes, exact: bytes) -> tuple[int, int]:
    start = source.index(exact)
    return start, start + len(exact)


class StableCommentAnchorTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        presentation_patch = patch(
            "quant_hub.archive.catalog.ArchivePresentation.default",
            return_value=Mock(research={}),
        )
        chapter_patch = patch(
            "quant_hub.archive.catalog.ArchiveChapterManifests.default",
            return_value=Mock(),
        )
        link_index_patch = patch(
            "quant_hub.archive.catalog.ArchiveCatalog.archive_link_index",
            return_value={},
        )
        presentation_patch.start()
        chapter_patch.start()
        link_index_patch.start()
        self.addCleanup(presentation_patch.stop)
        self.addCleanup(chapter_patch.stop)
        self.addCleanup(link_index_patch.stop)

        self.source_v1 = (
            "# 因子稳定性\n\n"
            "## 方法\n\n"
            "保留的块：收益率必须滞后一日。\n\n"
            "## 限制\n\n"
            "将被修订的跨度：旧限制。\n"
        ).encode("utf-8")
        source_path = self.archive / "stable-comment-fixture.md"
        source_path.write_bytes(self.source_v1)
        catalog = ArchiveCatalog(self.settings)
        catalog.initialize()
        release = self.publish_with_test_certificate(
            catalog,
            ArchiveReleaseInput(
                research_slug="stable-comment-fixture",
                display_title="稳定评论锚点 fixture",
                release_key="v1",
                documents=(
                    ArchiveDocumentInput(
                        document_slug="main",
                        document_role="primary",
                        source_path=source_path.name,
                        **self.approved_source_fields(source_path.name),
                        navigation_role="primary",
                        sort_key=10,
                        mapping_authority_urn="qrh:test:stable-comment-mapping",
                        mapping_note="comment target integration fixture",
                    ),
                ),
                activate=False,
            ),
            label="stable-comment-v1",
        )
        self.research_id = release.research_id
        with archive_connection(self.settings) as connection:
            version = connection.execute(
                """
                SELECT document.document_id,version.document_version_id,
                       version.content_sha256
                FROM research_document AS document
                JOIN research_document_version AS version
                  ON version.document_id=document.document_id
                WHERE document.research_id=?
                """,
                (self.research_id,),
            ).fetchone()
        assert version is not None
        self.document_id = str(version["document_id"])
        self.version_v1 = str(version["document_version_id"])
        self.database_path = self.project / "state" / "comments.sqlite3"
        initialize_comment_store(
            self.database_path,
            legacy_archive_path=self.settings.archive_database_path,
        )

    @staticmethod
    def _context(heading: str) -> dict[str, object]:
        return {"heading_ancestry": ["因子稳定性", heading], "ordinal": 1}

    @staticmethod
    def _locator(label: str) -> dict[str, object]:
        return {"kind": "markdown-byte-span", "label": label}

    def _anchored_target(
        self,
        *,
        kind: str,
        exact: bytes,
        context: dict[str, object],
        label: str,
    ) -> CommentTargetInput:
        start, end = _span(self.source_v1, exact)
        return CommentTargetInput.anchored(
            target_kind=kind,  # type: ignore[arg-type]
            document_id=self.document_id,
            origin_document_version_id=self.version_v1,
            origin_source_sha256=_sha256(self.source_v1),
            origin_block_type="paragraph",
            origin_start_byte=start,
            origin_end_byte=end,
            origin_exact_bytes=exact,
            structural_context=context,
            locator=self._locator(label),
        )

    @staticmethod
    def _database_facts(path: Path) -> dict[str, list[tuple[object, ...]]]:
        with closing(sqlite3.connect(path)) as connection:
            return {
                "comments": connection.execute(
                    """
                    SELECT comment_id,research_id,actor_id,body,created_at,updated_at,
                           revision,deleted_at
                    FROM comment ORDER BY comment_id
                    """
                ).fetchall(),
                "events": connection.execute(
                    """
                    SELECT comment_event_id,comment_id,event_type,old_body_hash,
                           new_body_hash,actor_id,revision,occurred_at
                    FROM comment_event ORDER BY comment_event_id
                    """
                ).fetchall(),
                "actors": connection.execute(
                    "SELECT actor_id,actor_kind,display_name,created_at FROM actor ORDER BY actor_id"
                ).fetchall(),
            }

    def _snapshot(
        self,
        *,
        snapshot_id: str,
        version_id: str,
        source: bytes,
        blocks: tuple[SnapshotBlock, ...],
        view: str = "current",
    ) -> CommentAnchorSnapshot:
        return CommentAnchorSnapshot(
            snapshot_id=snapshot_id,
            manifest_sha256=_sha256(("manifest:" + snapshot_id).encode("utf-8")),
            view=view,  # type: ignore[arg-type]
            documents=(
                SnapshotDocument(
                    research_id=self.research_id,
                    document_id=self.document_id,
                    document_version_id=version_id,
                    source_sha256=_sha256(source),
                    source_bytes=source,
                    blocks=blocks,
                ),
            ),
        )

    def test_nonempty_cross_version_projection_is_exact_visible_and_fact_preserving(
        self,
    ) -> None:
        actor = ActorInput(actor_kind="zhang_zhengze")
        service = ArchiveCollaboration(
            self.settings, comment_database_path=self.database_path
        )
        retained = "保留的块：收益率必须滞后一日。".encode("utf-8")
        changed = "将被修订的跨度：旧限制。".encode("utf-8")
        created = (
            service.create_comment(
                self.research_id,
                actor,
                "文档级评论",
                idempotency_key="stable-document-comment",
                target=CommentTargetInput.document(self.document_id),
            ),
            service.create_comment(
                self.research_id,
                actor,
                "必须跟随未变方法块",
                idempotency_key="stable-block-comment",
                target=self._anchored_target(
                    kind="block",
                    exact=retained,
                    context=self._context("方法"),
                    label="retained-method",
                ),
            ),
            service.create_comment(
                self.research_id,
                ActorInput(actor_kind="song_dingkun"),
                "改写后必须 unresolved",
                idempotency_key="changed-span-comment",
                target=self._anchored_target(
                    kind="span",
                    exact=changed,
                    context=self._context("限制"),
                    label="changed-limit",
                ),
            ),
        )
        self.assertTrue(all(item.ok for item in created))
        comment_ids = [str(item.data["comment_id"]) for item in created if item.data]
        before = self._database_facts(self.database_path)

        # Simulate the next code release reopening the same release-external DB.
        initialize_comment_store(self.database_path)
        reopened = ArchiveCollaboration(
            self.settings, comment_database_path=self.database_path
        )
        self.assertEqual(3, len(reopened.list_comments(self.research_id)))

        # The document moved and was revised.  Path is intentionally absent
        # from the projection contract: identity is research_id/document_id.
        source_v2 = (
            "# 因子稳定性\n\n"
            "## 限制\n\n"
            "将被修订的跨度：新限制。\n\n"
            "## 方法\n\n"
            "保留的块：收益率必须滞后一日。\n"
        ).encode("utf-8")
        retained_v2 = _span(source_v2, retained)
        revised = "将被修订的跨度：新限制。".encode("utf-8")
        revised_v2 = _span(source_v2, revised)
        current_snapshot = self._snapshot(
            snapshot_id="snap_v2_moved",
            version_id="dver_v2_moved",
            source=source_v2,
            blocks=(
                SnapshotBlock(
                    "paragraph", revised_v2[0], revised_v2[1], self._context("限制")
                ),
                SnapshotBlock(
                    "paragraph", retained_v2[0], retained_v2[1], self._context("方法")
                ),
            ),
        )
        artifact_path = self.project / "projection" / "snap_v2_moved.json"
        written, digest = write_comment_anchor_projection(
            self.database_path, current_snapshot, artifact_path
        )
        self.assertEqual(artifact_path, written)
        self.assertEqual(_sha256(artifact_path.read_bytes()), digest)
        projection = load_comment_anchor_projection(
            artifact_path,
            expected_snapshot_id="snap_v2_moved",
            expected_manifest_sha256=current_snapshot.manifest_sha256,
        )
        by_id = {item["comment_id"]: item for item in projection["entries"]}
        self.assertEqual("resolved_current", by_id[comment_ids[0]]["resolution"]["status"])
        self.assertEqual("resolved_current", by_id[comment_ids[1]]["resolution"]["status"])
        self.assertEqual(retained_v2[0], by_id[comment_ids[1]]["resolution"]["start_byte"])
        self.assertEqual("unresolved", by_id[comment_ids[2]]["resolution"]["status"])
        self.assertNotIn("start_byte", by_id[comment_ids[2]]["resolution"])
        self.assertTrue(by_id[comment_ids[2]]["history"]["preserved"])

        # Historical source view remains explicitly visible.
        retained_v1 = _span(self.source_v1, retained)
        changed_v1 = _span(self.source_v1, changed)
        historical = build_comment_anchor_projection(
            self.database_path,
            self._snapshot(
                snapshot_id="snap_v1_history",
                version_id=self.version_v1,
                source=self.source_v1,
                view="history",
                blocks=(
                    SnapshotBlock(
                        "paragraph", retained_v1[0], retained_v1[1], self._context("方法")
                    ),
                    SnapshotBlock(
                        "paragraph", changed_v1[0], changed_v1[1], self._context("限制")
                    ),
                ),
            ),
        )
        self.assertEqual(
            {"resolved_history"},
            {item["resolution"]["status"] for item in historical["entries"]},
        )

        # A D-prior code rollback selects the prior snapshot, not an old state DB.
        prior = build_comment_anchor_projection(
            self.database_path,
            self._snapshot(
                snapshot_id="snap_v1_prior_active",
                version_id=self.version_v1,
                source=self.source_v1,
                blocks=(
                    SnapshotBlock(
                        "paragraph", retained_v1[0], retained_v1[1], self._context("方法")
                    ),
                    SnapshotBlock(
                        "paragraph", changed_v1[0], changed_v1[1], self._context("限制")
                    ),
                ),
            ),
        )
        self.assertEqual(
            {"resolved_current"},
            {item["resolution"]["status"] for item in prior["entries"]},
        )
        self.assertEqual(before, self._database_facts(self.database_path))

        # Write-once artifact semantics permit exact replay but reject mutation.
        self.assertEqual(
            (artifact_path, digest),
            write_comment_anchor_projection(
                self.database_path, current_snapshot, artifact_path
            ),
        )
        with self.assertRaises(FileExistsError):
            write_comment_anchor_projection(
                self.database_path,
                self._snapshot(
                    snapshot_id="different_snapshot",
                    version_id="dver_v2_moved",
                    source=source_v2,
                    blocks=current_snapshot.documents[0].blocks,
                ),
                artifact_path,
            )

    def test_duplicate_exact_candidates_are_ambiguous_never_fuzzy_attached(self) -> None:
        exact = "完全相同的限制。".encode("utf-8")
        target = self._anchored_target(
            kind="span",
            exact="将被修订的跨度：旧限制。".encode("utf-8"),
            context=self._context("限制"),
            label="origin-limit",
        )
        service = ArchiveCollaboration(
            self.settings, comment_database_path=self.database_path
        )
        created = service.create_comment(
            self.research_id,
            ActorInput(actor_kind="zhang_zhengze"),
            "不得猜测挂接",
            idempotency_key="ambiguous-comment",
            target=target,
        )
        self.assertTrue(created.ok)
        # Replace the origin bytes with two byte-identical candidates under the
        # same structural context.  The target exact bytes are used here.
        origin = bytes(target.normalized()["origin_exact_bytes"])
        source = b"prefix\n" + origin + b"\nmiddle\n" + origin + b"\nsuffix\n"
        first = _span(source, origin)
        second_start = source.index(origin, first[1])
        second = (second_start, second_start + len(origin))
        projection = build_comment_anchor_projection(
            self.database_path,
            self._snapshot(
                snapshot_id="snap_ambiguous",
                version_id="dver_ambiguous",
                source=source,
                blocks=(
                    SnapshotBlock(
                        "paragraph", first[0], first[1], self._context("限制")
                    ),
                    SnapshotBlock(
                        "paragraph", second[0], second[1], self._context("限制")
                    ),
                ),
            ),
        )
        resolution = projection["entries"][0]["resolution"]
        self.assertEqual("ambiguous", resolution["status"])
        self.assertEqual(2, resolution["candidate_count"])
        self.assertNotIn("start_byte", resolution)
        self.assertNotIn(exact.decode("utf-8"), str(projection))

    def test_verified_one_to_one_unchanged_block_mapping_is_fail_closed(self) -> None:
        exact = "保留的块：收益率必须滞后一日。".encode("utf-8")
        origin_context = self._context("方法")
        target_context = {
            "heading_ancestry": ["因子稳定性", "重排后的方法"],
            "ordinal": 3,
        }
        target = self._anchored_target(
            kind="block",
            exact=exact,
            context=origin_context,
            label="mapped-method",
        )
        service = ArchiveCollaboration(
            self.settings, comment_database_path=self.database_path
        )
        created = service.create_comment(
            self.research_id,
            ActorInput(actor_kind="zhang_zhengze"),
            "只接受编译器一对一证明",
            idempotency_key="mapped-block-comment",
            target=target,
        )
        self.assertTrue(created.ok)
        source = b"moved-prefix\n" + exact + b"\n"
        mapped_span = _span(source, exact)
        material = target.normalized()
        mapping = UnchangedBlockMapping(
            document_id=self.document_id,
            origin_document_version_id=self.version_v1,
            target_document_version_id="dver_mapped",
            origin_start_byte=int(material["origin_start_byte"]),
            origin_end_byte=int(material["origin_end_byte"]),
            target_start_byte=mapped_span[0],
            target_end_byte=mapped_span[1],
            exact_bytes_sha256=str(material["origin_exact_bytes_sha256"]),
            block_type="paragraph",
            origin_structural_context_sha256=str(
                material["origin_structural_context_sha256"]
            ),
            target_structural_context_sha256=_sha256(
                json.dumps(
                    target_context,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ),
        )
        snapshot = CommentAnchorSnapshot(
            snapshot_id="snap_mapped",
            manifest_sha256=_sha256(b"manifest:mapped"),
            view="current",
            documents=(
                SnapshotDocument(
                    research_id=self.research_id,
                    document_id=self.document_id,
                    document_version_id="dver_mapped",
                    source_sha256=_sha256(source),
                    source_bytes=source,
                    blocks=(
                        SnapshotBlock(
                            "paragraph", mapped_span[0], mapped_span[1], target_context
                        ),
                    ),
                ),
            ),
            unchanged_block_mappings=(mapping,),
        )
        resolved = build_comment_anchor_projection(self.database_path, snapshot)
        self.assertEqual(
            "verified_one_to_one_unchanged_block_mapping",
            resolved["entries"][0]["resolution"]["reason"],
        )
        self.assertEqual(
            "resolved_current", resolved["entries"][0]["resolution"]["status"]
        )

        # A second target for the same origin is no longer a one-to-one proof.
        second = UnchangedBlockMapping(
            document_id=mapping.document_id,
            origin_document_version_id=mapping.origin_document_version_id,
            target_document_version_id=mapping.target_document_version_id,
            origin_start_byte=mapping.origin_start_byte,
            origin_end_byte=mapping.origin_end_byte,
            target_start_byte=mapping.target_start_byte,
            target_end_byte=mapping.target_end_byte,
            exact_bytes_sha256=mapping.exact_bytes_sha256,
            block_type=mapping.block_type,
            origin_structural_context_sha256=mapping.origin_structural_context_sha256,
            target_structural_context_sha256=mapping.target_structural_context_sha256,
        )
        invalid_snapshot = CommentAnchorSnapshot(
            snapshot_id="snap_mapped_duplicate",
            manifest_sha256=_sha256(b"manifest:mapped-duplicate"),
            view="current",
            documents=snapshot.documents,
            unchanged_block_mappings=(mapping, second),
        )
        rejected = build_comment_anchor_projection(self.database_path, invalid_snapshot)
        self.assertEqual("unresolved", rejected["entries"][0]["resolution"]["status"])

    def test_v2_core_expands_to_target_v3_and_old_writer_remains_compatible(self) -> None:
        database = self.project / "state" / "legacy-v2.sqlite3"
        initialize_comment_store(database)
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("DROP TABLE comment_target")
            connection.execute("DROP TABLE comment_target_schema")
            connection.execute(
                "INSERT INTO actor VALUES(?,?,?,?)",
                ("act_v2", "zhang_zhengze", "张正泽", "2026-08-21T00:00:00Z"),
            )
            connection.execute(
                "INSERT INTO comment VALUES(?,?,?,?,?,?,?,NULL)",
                (
                    "cmt_00000000000000000000000000000001",
                    self.research_id,
                    "act_v2",
                    "v2 研究级评论",
                    "2026-08-21T00:00:00Z",
                    "2026-08-21T00:00:00Z",
                    1,
                ),
            )
            connection.execute(
                "INSERT INTO comment_event VALUES(?,?,?,?,?,?,?,?)",
                (
                    "cevt_v2",
                    "cmt_00000000000000000000000000000001",
                    "create",
                    None,
                    _sha256("v2 研究级评论".encode("utf-8")),
                    "act_v2",
                    1,
                    "2026-08-21T00:00:00Z",
                ),
            )
            connection.commit()
            versions = [row[0] for row in connection.execute(
                "SELECT version FROM comment_store_schema ORDER BY version"
            )]
            self.assertEqual([1, 2], versions)

        initialize_comment_store(database)
        state = comment_store_state(database)
        self.assertEqual(2, state["schema_version"])
        self.assertEqual(3, state["comment_target_schema_version"])
        self.assertEqual(1, state["comment_targets"])
        service = ArchiveCollaboration(self.settings, comment_database_path=database)
        comments = service.list_comments(self.research_id)
        self.assertEqual("v2 研究级评论", comments[0]["content"])

        # Simulate retained V39 writing after expansion.  Unknown v3 tables do
        # not impose a trigger/column requirement on the core v2 INSERT.
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO comment VALUES(?,?,?,?,?,?,?,NULL)",
                (
                    "cmt_00000000000000000000000000000002",
                    self.research_id,
                    "act_v2",
                    "prior release 新写评论",
                    "2026-08-21T01:00:00Z",
                    "2026-08-21T01:00:00Z",
                    1,
                ),
            )
            connection.execute(
                "INSERT INTO comment_event VALUES(?,?,?,?,?,?,?,?)",
                (
                    "cevt_v2_prior",
                    "cmt_00000000000000000000000000000002",
                    "create",
                    None,
                    _sha256("prior release 新写评论".encode("utf-8")),
                    "act_v2",
                    1,
                    "2026-08-21T01:00:00Z",
                ),
            )
            connection.commit()
        self.assertEqual(2, len(service.list_comments(self.research_id)))
        prior_projection = build_comment_anchor_projection(
            database,
            self._snapshot(
                snapshot_id="snap_prior_writer",
                version_id=self.version_v1,
                source=self.source_v1,
                blocks=(),
            ),
        )
        self.assertEqual(2, len(prior_projection["entries"]))
        self.assertEqual(
            {"resolved_current"},
            {item["resolution"]["status"] for item in prior_projection["entries"]},
        )
        initialize_comment_store(database)
        self.assertEqual(2, comment_store_state(database)["comment_targets"])

    def test_target_origin_is_immutable_and_invalid_span_is_rejected(self) -> None:
        service = ArchiveCollaboration(
            self.settings, comment_database_path=self.database_path
        )
        exact = "保留的块：收益率必须滞后一日。".encode("utf-8")
        valid = self._anchored_target(
            kind="block",
            exact=exact,
            context=self._context("方法"),
            label="immutable",
        )
        invalid = CommentTargetInput.anchored(
            target_kind="block",
            document_id=self.document_id,
            origin_document_version_id=self.version_v1,
            origin_source_sha256=_sha256(self.source_v1),
            origin_block_type="paragraph",
            origin_start_byte=0,
            origin_end_byte=len(exact),
            origin_exact_bytes=exact,
            structural_context=self._context("方法"),
            locator=self._locator("wrong-offset"),
        )
        rejected = service.create_comment(
            self.research_id,
            ActorInput(actor_kind="zhang_zhengze"),
            "invalid",
            idempotency_key="invalid-anchor",
            target=invalid,
        )
        self.assertFalse(rejected.ok)
        self.assertEqual("invalid_comment_target", rejected.error_code)
        applied = service.create_comment(
            self.research_id,
            ActorInput(actor_kind="zhang_zhengze"),
            "immutable",
            idempotency_key="immutable-anchor",
            target=valid,
        )
        self.assertTrue(applied.ok)
        with closing(sqlite3.connect(self.database_path)) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE comment_target SET document_id='wrong' WHERE comment_id=?",
                    (str(applied.data["comment_id"]),),
                )

    def test_http_contract_keeps_legacy_body_and_rejects_path_bound_locator(self) -> None:
        legacy = CommentCreate.model_validate(
            {
                "actor": {"actor_kind": "zhang_zhengze"},
                "content": "旧前端请求体保持有效",
            }
        )
        self.assertIsNone(legacy.target)
        document = CommentCreate.model_validate(
            {
                "actor": {"actor_kind": "zhang_zhengze"},
                "content": "文档级",
                "target": {
                    "target_kind": "document",
                    "document_id": self.document_id,
                },
            }
        )
        self.assertEqual("document", document.target.to_domain().target_kind)
        with self.assertRaises(ValidationError):
            CommentCreate.model_validate(
                {
                    "actor": {"actor_kind": "zhang_zhengze"},
                    "content": "禁止路径身份",
                    "target": {
                        "target_kind": "span",
                        "document_id": self.document_id,
                        "origin_document_version_id": self.version_v1,
                        "origin_source_sha256": _sha256(self.source_v1),
                        "origin_block_type": "paragraph",
                        "origin_start_byte": 0,
                        "origin_end_byte": 1,
                        "origin_exact_text": "x",
                        "structural_context": {"nested": {"source_path": "release/a.md"}},
                        "locator": {"kind": "markdown-byte-span"},
                    },
                }
            )
