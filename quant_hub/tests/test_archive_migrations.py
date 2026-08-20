from __future__ import annotations

from pathlib import Path
import sqlite3

from quant_hub.archive.contracts import ActorInput, TopicInput
from quant_hub.platform.db import connect_database
from quant_hub.platform.migrations import migrate_down, migrate_up, schema_hash
from quant_hub.collaboration.service import ArchiveCollaboration
from tests.helpers import SettingsTestCase


ARCHIVE_MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations" / "archive"
NOW = "2026-07-15T00:00:00.000000Z"
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


class ArchiveMigrationTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.connection = connect_database(self.var / "db" / "archive.sqlite3")
        self.addCleanup(self.connection.close)

    def _migrate(self) -> None:
        self.assertEqual([1, 2, 3, 4, 5], migrate_up(self.connection, ARCHIVE_MIGRATIONS))

    def _seed_research(self, suffix: str = "1", *, digest: str = HASH_A) -> tuple[str, str, str]:
        research_id = f"research-{suffix}"
        document_id = f"document-{suffix}"
        version_id = f"version-{suffix}"
        self.connection.execute(
            """
            INSERT INTO research(
                research_id,canonical_slug,display_title,lifecycle_status,created_at
            ) VALUES(?,?,?,?,?)
            """,
            (research_id, f"slug-{suffix}", f"研究 {suffix}", "active", NOW),
        )
        self.connection.execute(
            """
            INSERT INTO research_document(
                document_id,research_id,document_role,slug,created_at
            ) VALUES(?,?,?,?,?)
            """,
            (document_id, research_id, "primary", "main", NOW),
        )
        self.connection.execute(
            """
            INSERT INTO research_document_version(
                document_version_id,document_id,object_urn,content_sha256,bytes,encoding,
                source_observed_at,discovery_status,parser_status
                ,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (
                version_id,
                document_id,
                f"urn:qrh:object:sha256:{digest}",
                digest,
                123,
                "utf-8",
                NOW,
                "registered",
                "succeeded",
                NOW,
            ),
        )
        return research_id, document_id, version_id

    def _seed_actor(self) -> str:
        actor_id = "actor-zhang"
        self.connection.execute(
            "INSERT INTO actor(actor_id,actor_kind,display_name,created_at) VALUES(?,?,?,?)",
            (actor_id, "zhang_zhengze", "张正泽", NOW),
        )
        return actor_id

    def _seed_active_release(
        self,
        research_id: str,
        document_id: str,
        version_id: str,
        *,
        suffix: str = "1",
    ) -> tuple[str, str]:
        release_id = f"release-{suffix}"
        activation_id = f"activation-{suffix}"
        snapshot_urn = f"urn:qrh:release-snapshot:{suffix}"
        self.connection.execute(
            """
            INSERT INTO research_release(
                research_release_id,research_id,document_manifest_hash,candidate_status,created_at
            ) VALUES(?,?,?,?,?)
            """,
            (release_id, research_id, HASH_B, "staging", NOW),
        )
        self.connection.execute(
            """
            INSERT INTO research_release_item(
                research_release_id,document_id,document_version_id,navigation_role,sort_key
            ) VALUES(?,?,?,?,?)
            """,
            (release_id, document_id, version_id, "primary", 0),
        )
        for status in ("validated", "under_review", "releasable"):
            self.connection.execute(
                "UPDATE research_release SET candidate_status=? WHERE research_release_id=?",
                (status, release_id),
            )
        self.connection.execute(
            """
            INSERT INTO research_release_activation(
                activation_id,research_id,research_release_id,release_snapshot_urn,
                decision_hash,activated_at,supersedes_activation_id
            ) VALUES(?,?,?,?,?,?,NULL)
            """,
            (activation_id, research_id, release_id, snapshot_urn, HASH_C, NOW),
        )
        self.connection.execute(
            """
            INSERT INTO active_research_release(
                research_id,activation_id,research_release_id,release_snapshot_urn,revision
            ) VALUES(?,?,?,?,1)
            """,
            (research_id, activation_id, release_id, snapshot_urn),
        )
        return release_id, activation_id

    def test_up_is_repeatable_strict_and_down_is_reversible(self) -> None:
        self._migrate()
        first_hash = schema_hash(self.connection)
        self.assertEqual([], migrate_up(self.connection, ARCHIVE_MIGRATIONS))
        self.assertEqual(first_hash, schema_hash(self.connection))

        required_tables = {
            "research",
            "research_document",
            "research_document_origin",
            "research_document_version",
            "document_version_relation",
            "research_release",
            "research_release_item",
            "research_release_activation",
            "active_research_release",
            "research_release_candidate_identity",
            "research_release_authority_consumption",
            "research_completion_review_consumption",
            "outline_node",
            "document_projection",
            "derived_research_metadata",
            "document_search_projection",
            "research_relation",
            "knowledge_statement",
            "statement_selection",
            "actor",
            "comment",
            "comment_event",
            "topic",
            "topic_research_link",
            "topic_state_event",
            "topic_mutation_event",
            "research_work_state_event",
            "research_completion_decision",
            "research_status_projection",
            "topic_projection",
            "command_receipt",
            "outbox_event",
            "inbox_receipt",
        }
        table_rows = {
            row[1]: row
            for row in self.connection.execute("PRAGMA table_list")
            if row[1] in required_tables
        }
        self.assertEqual(required_tables, set(table_rows))
        self.assertTrue(all(row[5] == 1 for row in table_rows.values()))
        self.assertEqual(
            [],
            [
                row[1]
                for row in self.connection.execute("PRAGMA table_info(research_document_version)")
                if row[1].lower() in {"body", "content", "markdown", "source_text"}
            ],
        )
        self.assertEqual("ok", self.connection.execute("PRAGMA integrity_check").fetchone()[0])
        self.assertEqual([], self.connection.execute("PRAGMA foreign_key_check").fetchall())

        self._seed_research("rollback", digest=HASH_C)

        self.assertEqual(
            [5, 4, 3, 2, 1], migrate_down(self.connection, ARCHIVE_MIGRATIONS, steps=5)
        )
        remaining = {
            row[0]
            for row in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        self.assertEqual({"schema_migration"}, remaining)
        self.assertEqual([1, 2, 3, 4, 5], migrate_up(self.connection, ARCHIVE_MIGRATIONS))
        self.assertEqual(first_hash, schema_hash(self.connection))
        self.assertEqual(
            [1, 2, 3, 4, 5],
            [
                row[0]
                for row in self.connection.execute(
                    "SELECT version FROM schema_migration ORDER BY version"
                )
            ],
        )

    def test_foreign_keys_enums_json_and_actor_identity_are_enforced(self) -> None:
        self._migrate()
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO research_document(
                    document_id,research_id,document_role,slug,created_at
                ) VALUES('orphan','missing','primary','main',?)
                """,
                (NOW,),
            )
        research_id, document_id, version_id = self._seed_research()
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "UPDATE research_document SET document_role='completed' WHERE document_id=?",
                (document_id,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO document_projection(
                    projection_id,document_version_id,projector_version,input_sha256,toc_json,
                    section_index_json,rendered_object_urn,search_revision,
                    validation_manifest_hash,status,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "projection-invalid",
                    version_id,
                    "v1",
                    HASH_B,
                    "{}",
                    "{}",
                    None,
                    1,
                    None,
                    "ready",
                    NOW,
                ),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO research_document_origin(
                    origin_id,document_id,source_location_urn,origin_kind,mapping_status,
                    mapping_evidence_json,first_seen_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                ("origin-1", document_id, "urn:source:1", "archive_path", "verified", "not-json", NOW),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "INSERT INTO actor(actor_id,actor_kind,display_name,created_at) VALUES(?,?,?,?)",
                ("fake-zhang", "other", "张正泽", NOW),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "INSERT INTO actor(actor_id,actor_kind,display_name,created_at) VALUES(?,?,?,?)",
                ("wrong-preset", "zhang_zhengze", "张正泽（外部）", NOW),
            )
        self.assertEqual(research_id, "research-1")

    def test_versions_releases_decisions_and_events_are_tamper_resistant(self) -> None:
        self._migrate()
        actor_id = self._seed_actor()
        research_id, document_id, version_id = self._seed_research()
        _, other_document_id, other_version_id = self._seed_research("2", digest=HASH_B)

        with self.assertRaisesRegex(sqlite3.IntegrityError, "begin in staging"):
            self.connection.execute(
                """
                INSERT INTO research_release(
                    research_release_id,research_id,document_manifest_hash,
                    candidate_status,created_at
                ) VALUES('release-bypass',?,?,'releasable',?)
                """,
                (research_id, HASH_A, NOW),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "material fields are immutable"):
            self.connection.execute(
                "UPDATE research_document_version SET bytes=124 WHERE document_version_id=?",
                (version_id,),
            )
        self.connection.execute(
            """
            INSERT INTO research_release(
                research_release_id,research_id,document_manifest_hash,candidate_status,created_at
            ) VALUES('release-bad',?,?,?,?)
            """,
            (research_id, HASH_C, "staging", NOW),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "exactly one primary"):
            self.connection.execute(
                "UPDATE research_release SET candidate_status='validated' WHERE research_release_id='release-bad'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "same research"):
            self.connection.execute(
                """
                INSERT INTO research_release_item(
                    research_release_id,document_id,document_version_id,navigation_role,sort_key
                ) VALUES('release-bad',?,?,?,0)
                """,
                (other_document_id, other_version_id, "primary"),
            )

        release_id, activation_id = self._seed_active_release(
            research_id, document_id, version_id
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "activated research release"):
            self.connection.execute(
                "UPDATE research_release SET candidate_status='rejected' WHERE research_release_id=?",
                (release_id,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO research_completion_decision(
                    decision_id,research_id,research_release_id,decision,decision_kind,
                    supersedes_decision_id,target_decision_id,actor_id,review_urn,reason,decided_at
                ) VALUES(?,?,?,?,?,NULL,NULL,?,NULL,?,?)
                """,
                (
                    "decision-wrong-release",
                    research_id,
                    "release-bad",
                    "completed",
                    "human",
                    actor_id,
                    "not active",
                    NOW,
                ),
            )
        self.connection.execute(
            """
            INSERT INTO research_completion_decision(
                decision_id,research_id,research_release_id,decision,decision_kind,
                supersedes_decision_id,target_decision_id,actor_id,review_urn,reason,decided_at
            ) VALUES(?,?,?,?,?,NULL,NULL,?,NULL,?,?)
            """,
            (
                "decision-complete",
                research_id,
                release_id,
                "completed",
                "human",
                actor_id,
                "显式完成审核",
                NOW,
            ),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            self.connection.execute(
                "UPDATE research_completion_decision SET reason='tampered' WHERE decision_id='decision-complete'"
            )

        self.connection.execute(
            """
            INSERT INTO research_status_projection(
                research_id,work_status,release_status,evidence_status,work_source_event_id,
                completion_decision_id,release_activation_id,evidence_source_urn,
                projection_version,updated_at
            ) VALUES(?,?,?,?,NULL,?,?,?,?,?)
            """,
            (
                research_id,
                "completed",
                "published",
                "passed",
                "decision-complete",
                activation_id,
                "urn:qrh:evidence:release:1",
                "v1",
                NOW,
            ),
        )
        row = self.connection.execute(
            """
            SELECT work_status,release_status,evidence_status
            FROM research_status_projection WHERE research_id=?
            """,
            (research_id,),
        ).fetchone()
        self.assertEqual(("completed", "published", "passed"), tuple(row))
        self.assertEqual(
            [5, 4, 3, 2, 1], migrate_down(self.connection, ARCHIVE_MIGRATIONS, steps=5)
        )

    def test_fts_tracks_projection_insert_update_and_delete(self) -> None:
        self._migrate()
        research_id, _, version_id = self._seed_research()
        self.connection.execute(
            """
            INSERT INTO document_search_projection(
                research_id,document_version_id,title_text,search_text,
                projector_version,search_revision,updated_at
            ) VALUES(?,?,?,?,?,?,?)
            """,
            (
                research_id,
                version_id,
                "因子工厂",
                "alpha signal 与投资组合构建",
                "v1",
                1,
                NOW,
            ),
        )
        hit = self.connection.execute(
            """
            SELECT research_id,document_version_id
            FROM archive_document_fts WHERE archive_document_fts MATCH 'alpha'
            """
        ).fetchone()
        self.assertEqual((research_id, version_id), tuple(hit))

        self.connection.execute(
            """
            UPDATE document_search_projection
            SET search_text='beta portfolio',search_revision=2,updated_at=?
            WHERE document_version_id=?
            """,
            (NOW, version_id),
        )
        self.assertEqual(
            0,
            self.connection.execute(
                "SELECT count(*) FROM archive_document_fts WHERE archive_document_fts MATCH 'alpha'"
            ).fetchone()[0],
        )
        self.assertEqual(
            1,
            self.connection.execute(
                "SELECT count(*) FROM archive_document_fts WHERE archive_document_fts MATCH 'beta'"
            ).fetchone()[0],
        )
        self.connection.execute(
            "DELETE FROM document_search_projection WHERE document_version_id=?",
            (version_id,),
        )
        self.assertEqual(
            0,
            self.connection.execute(
                "SELECT count(*) FROM archive_document_fts WHERE archive_document_fts MATCH 'beta'"
            ).fetchone()[0],
        )

    def test_metadata_idempotency_and_append_only_transport_constraints(self) -> None:
        self._migrate()
        actor_id = self._seed_actor()
        research_id, _, version_id = self._seed_research()
        self.connection.execute(
            """
            INSERT INTO derived_research_metadata(
                metadata_id,document_version_id,research_release_id,derivation_type,
                derivation_version,payload_json,artifact_id,status,created_at
            ) VALUES(?,?,NULL,?,?,?,?,?,?)
            """,
            (
                "metadata-1",
                version_id,
                "summary",
                "v1",
                '{"summary":"derived"}',
                "artifact-1",
                "validated",
                NOW,
            ),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO derived_research_metadata(
                    metadata_id,document_version_id,research_release_id,derivation_type,
                    derivation_version,payload_json,artifact_id,status,created_at
                ) VALUES(?,NULL,NULL,?,?,?,?,?,?)
                """,
                ("metadata-invalid", "summary", "v1", "{}", "artifact-x", "proposed", NOW),
            )

        receipt = (
            "receipt-1",
            "idem-1",
            "comment.create",
            HASH_A,
            f"urn:qrh:archive:research:{research_id}",
            actor_id,
            "applied",
            '{"comment_id":"comment-1"}',
            HASH_B,
            201,
            NOW,
        )
        self.connection.execute(
            """
            INSERT INTO command_receipt(
                receipt_id,idempotency_key,command_name,payload_hash,aggregate_urn,actor_id,
                outcome,result_json,result_hash,http_status,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """,
            receipt,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO command_receipt(
                    receipt_id,idempotency_key,command_name,payload_hash,aggregate_urn,actor_id,
                    outcome,result_json,result_hash,http_status,created_at
                ) VALUES('receipt-2','idem-1','comment.create',?,?,?,'applied','{}',?,201,?)
                """,
                (HASH_C, f"urn:qrh:archive:research:{research_id}", actor_id, HASH_A, NOW),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.connection.execute(
                "UPDATE command_receipt SET http_status=200 WHERE receipt_id='receipt-1'"
            )

        self.connection.execute(
            """
            INSERT INTO outbox_event(
                event_id,event_type,event_version,aggregate_urn,payload_json,payload_hash,
                created_at,published_at,publish_attempt_count
            ) VALUES(?,?,?,?,?,?,?,NULL,0)
            """,
            (
                "event-1",
                "ArchiveDocumentVersionRegistered",
                "v1",
                f"urn:qrh:archive:research:{research_id}",
                '{"version_id":"version-1"}',
                HASH_C,
                NOW,
            ),
        )
        self.connection.execute(
            "UPDATE outbox_event SET publish_attempt_count=1,published_at=? WHERE event_id='event-1'",
            (NOW,),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.connection.execute(
                "UPDATE outbox_event SET payload_json='{}' WHERE event_id='event-1'"
            )
        self.connection.execute(
            """
            INSERT INTO inbox_receipt(
                consumer_name,source_domain,event_id,processed_at,result_hash
            ) VALUES('archive-import','research-evidence','event-external',?,?)
            """,
            (NOW, HASH_A),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO inbox_receipt(
                    consumer_name,source_domain,event_id,processed_at,result_hash
                ) VALUES('archive-import','research-evidence','event-external',?,?)
                """,
                (NOW, HASH_B),
            )

        self.connection.execute(
            "INSERT INTO topic(topic_id,topic_key,title,manual_order,created_at) VALUES(?,?,?,?,?)",
            ("topic-1", "topic-1", "待研究主题", 1, NOW),
        )
        self.connection.execute(
            """
            INSERT INTO topic_state_event(
                topic_state_event_id,topic_id,state,note,actor_id,occurred_at,supersedes_event_id
            ) VALUES('topic-event-1','topic-1','planned',NULL,?,?,NULL)
            """,
            (actor_id, NOW),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            self.connection.execute(
                "UPDATE topic_state_event SET note='tampered' WHERE topic_state_event_id='topic-event-1'"
            )

    def test_schema_executes_collaboration_command_handler_end_to_end(self) -> None:
        self._migrate()
        research_id, _, _ = self._seed_research()
        collaboration = ArchiveCollaboration(self.settings)
        actor = ActorInput(actor_kind="zhang_zhengze")

        created = collaboration.create_comment(
            research_id,
            actor,
            "对该研究的可持久化评论",
            idempotency_key="integration-comment-create",
        )
        self.assertTrue(created.ok)
        replay = collaboration.create_comment(
            research_id,
            actor,
            "对该研究的可持久化评论",
            idempotency_key="integration-comment-create",
        )
        self.assertTrue(replay.ok)
        self.assertTrue(replay.replayed)

        topic_result = collaboration.create_topic(
            TopicInput(topic_key="planned-topic", title="待完成研究", manual_order=10),
            actor,
            idempotency_key="integration-topic-create",
        )
        self.assertTrue(topic_result.ok)
        assert topic_result.data is not None
        topic_id = str(topic_result.data["topic_id"])
        linked = collaboration.link_topic_research(
            topic_id,
            research_id,
            actor,
            link_kind="primary",
            dashboard_primary=True,
            display_rank=0,
            provenance_urn="urn:qrh:review:integration",
            idempotency_key="integration-topic-link",
        )
        self.assertTrue(linked.ok)
        paused = collaboration.set_topic_state(
            topic_id,
            "paused",
            "等待外部证据",
            actor,
            idempotency_key="integration-topic-pause",
        )
        self.assertTrue(paused.ok)
        work = collaboration.set_work_state(
            research_id,
            "in_progress",
            "研究仍在进行",
            actor,
            idempotency_key="integration-work-state",
        )
        self.assertTrue(work.ok)
        dashboard = collaboration.dashboard()
        self.assertEqual("paused", dashboard[0]["state"])
        self.assertEqual("等待外部证据", dashboard[0]["state_note"])

        self.assertEqual(
            5,
            self.connection.execute("SELECT count(*) FROM command_receipt").fetchone()[0],
        )
        self.assertEqual(
            5,
            self.connection.execute("SELECT count(*) FROM outbox_event").fetchone()[0],
        )
