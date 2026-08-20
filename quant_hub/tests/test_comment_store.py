from __future__ import annotations

from pathlib import Path
import hashlib
import sqlite3
from contextlib import closing
from unittest.mock import Mock, patch

from quant_hub.app import create_app
from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.archive.contracts import (
    ActorInput,
    ArchiveDocumentInput,
    ArchiveReleaseInput,
    ManualTopicCreateInput,
    ManualTopicUpdateInput,
)
from quant_hub.collaboration.comment_store import (
    backup_comment_store,
    comment_store_state,
    initialize_comment_store,
)
from quant_hub.collaboration.service import ArchiveCollaboration
from tests.helpers import SettingsTestCase


class DurableCommentStoreTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        # These tests exercise the external mutable state contract, not the
        # private, release-bound Archive presentation bundle.  Keep the public
        # source checkout self-contained by replacing those read-only content
        # projections with empty test doubles.
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
        source_path = self.archive / "durable-comment-research.md"
        source_path.write_text("# 持久评论研究\n", encoding="utf-8")
        catalog = ArchiveCatalog(self.settings)
        catalog.initialize()
        published = self.publish_with_test_certificate(
            catalog,
            ArchiveReleaseInput(
                research_slug="durable-comment-research",
                display_title="持久评论研究",
                release_key="v1",
                documents=(
                    ArchiveDocumentInput(
                        document_slug="main",
                        document_role="primary",
                        source_path=source_path.name,
                        **self.approved_source_fields(source_path.name),
                        navigation_role="primary",
                        sort_key=10,
                        mapping_authority_urn="qrh:test:durable-comment-mapping",
                        mapping_note="持久评论库集成测试。",
                    ),
                ),
                activate=False,
            ),
            label="durable-comment-v1",
        )
        self.research_id = published.research_id
        self.database_path = self.project / "persistent-data" / "comments.sqlite3"
        initialize_comment_store(
            self.database_path,
            legacy_archive_path=self.settings.archive_database_path,
        )

    def test_external_comment_store_is_reopenable_idempotent_and_backup_safe(self) -> None:
        service = ArchiveCollaboration(
            self.settings,
            comment_database_path=self.database_path,
        )
        actor = ActorInput(actor_kind="zhang_zhengze")
        created = service.create_comment(
            self.research_id,
            actor,
            "冻结发布包替换后仍需保留。",
            idempotency_key="durable-comment-create-0001",
        )
        self.assertTrue(created.ok)
        replay = service.create_comment(
            self.research_id,
            actor,
            "冻结发布包替换后仍需保留。",
            idempotency_key="durable-comment-create-0001",
        )
        self.assertTrue(replay.ok)
        self.assertTrue(replay.replayed)

        reopened = ArchiveCollaboration(
            self.settings,
            comment_database_path=self.database_path,
        )
        comments = reopened.list_comments(self.research_id)
        self.assertEqual(1, len(comments))
        self.assertEqual("冻结发布包替换后仍需保留。", comments[0]["content"])

        backup = backup_comment_store(
            self.database_path,
            self.project / "persistent-data" / "backups",
        )
        self.assertIsInstance(backup, Path)
        assert backup is not None
        self.assertTrue(backup.is_file())
        self.assertEqual(1, comment_store_state(backup)["active_comments"])

    def test_application_factory_initializes_an_external_comment_store(self) -> None:
        database_path = self.project / "app-data" / "comments.sqlite3"
        self.assertFalse(database_path.exists())

        app = create_app(
            self.settings,
            {
                "TESTING": True,
                "COMMENT_DATABASE_PATH": str(database_path),
            },
        )

        self.assertTrue(database_path.is_file())
        state = comment_store_state(database_path)
        self.assertEqual(2, state["schema_version"])
        self.assertEqual(
            database_path.resolve(),
            app.extensions["archive_collaboration"].comment_database_path,
        )
        # Reopening the same external store is the normal version-upgrade path.
        create_app(
            self.settings,
            {
                "TESTING": True,
                "COMMENT_DATABASE_PATH": str(database_path),
            },
        )
        self.assertEqual(2, comment_store_state(database_path)["schema_version"])

    def test_progress_topics_live_outside_the_frozen_archive_database(self) -> None:
        service = ArchiveCollaboration(
            self.settings,
            comment_database_path=self.database_path,
        )
        archive_before = hashlib.sha256(
            self.settings.archive_database_path.read_bytes()
        ).hexdigest()
        actor = ActorInput(actor_kind="zhang_zhengze")
        created = service.create_manual_topic(
            ManualTopicCreateInput(
                title="截面温度实证",
                state="planned",
                note="记录启动条件与当前进度。",
            ),
            actor,
            idempotency_key="external-progress-create-0001",
        )
        self.assertTrue(created.ok)
        assert created.data is not None
        topic_id = str(created.data["topic_id"])
        self.assertEqual("planned", created.data["manual_state"])
        self.assertIsNone(created.data["parent_topic_id"])

        updated = service.update_manual_topic(
            topic_id,
            ManualTopicUpdateInput(state="paused", note="等待样本补齐。"),
            ActorInput(actor_kind="song_dingkun"),
            expected_revision=1,
            idempotency_key="external-progress-update-0001",
        )
        self.assertTrue(updated.ok)
        assert updated.data is not None
        self.assertEqual("paused", updated.data["manual_state"])
        self.assertEqual(2, updated.data["revision"])
        self.assertEqual(
            archive_before,
            hashlib.sha256(self.settings.archive_database_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(1, comment_store_state(self.database_path)["active_progress_topics"])

    def test_legacy_workspace_reimport_deduplicates_same_reminder_after_status_change(self) -> None:
        service = ArchiveCollaboration(
            self.settings,
            comment_database_path=self.database_path,
        )
        created = service.create_manual_topic(
            ManualTopicCreateInput(
                title="因子质量检验更新",
                state="planned",
                note="傅里叶和小波方法等",
            ),
            ActorInput(actor_kind="zhang_zhengze"),
            idempotency_key="legacy-progress-dedupe-create-0001",
        )
        self.assertTrue(created.ok)

        workspace_path = self.project / "persistent-data" / "legacy-workspace.sqlite3"
        with closing(sqlite3.connect(workspace_path)) as connection:
            connection.executescript(
                """
                CREATE TABLE actor(actor_id TEXT PRIMARY KEY,actor_kind TEXT,display_name TEXT);
                CREATE TABLE research_workspace_node(
                    node_id TEXT PRIMARY KEY,title_override TEXT,default_title TEXT,
                    description_override TEXT,default_description TEXT,
                    lifecycle_status TEXT,sort_key INTEGER,created_at TEXT,updated_at TEXT
                );
                CREATE TABLE research_workspace_event(
                    event_id TEXT PRIMARY KEY,node_id TEXT,actor_id TEXT,occurred_at TEXT
                );
                """
            )
            connection.execute(
                "INSERT INTO actor VALUES('act_test','zhang_zhengze','张正泽')"
            )
            connection.execute(
                """
                INSERT INTO research_workspace_node VALUES(
                    'rnode_e2a54085f3cd423e8521dceb9d75b403',NULL,
                    'Q8｜因子质量检验更新',NULL,'傅里叶和小波方法等',
                    'archived',800,'2026-07-31T00:00:00Z','2026-08-11T00:00:00Z'
                )
                """
            )
            connection.execute(
                """
                INSERT INTO research_workspace_event VALUES(
                    'wevt_test','rnode_e2a54085f3cd423e8521dceb9d75b403',
                    'act_test','2026-08-11T00:00:00Z'
                )
                """
            )
            connection.commit()

        initialize_comment_store(
            self.database_path,
            legacy_workspace_path=workspace_path,
        )
        self.assertEqual(1, comment_store_state(self.database_path)["active_progress_topics"])
