from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import sqlite3
import threading

from quant_hub.archive.contracts import (
    ActorInput,
    ManualTopicCreateInput,
    ManualTopicUpdateInput,
    TopicInput,
)
from quant_hub.archive.database import archive_connection
from quant_hub.collaboration.service import ArchiveCollaboration
from quant_hub.platform.migrations import migrate_down, migrate_up
from tests.helpers import SettingsTestCase


def _run_concurrently(count: int, action):
    barrier = threading.Barrier(count)

    def invoke(index: int):
        barrier.wait(timeout=20)
        return action(index)

    with ThreadPoolExecutor(max_workers=count) as executor:
        futures = [executor.submit(invoke, index) for index in range(count)]
        return [future.result(timeout=60) for future in futures]


class TopicManagementTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.collaboration = ArchiveCollaboration(self.settings)
        self.zhang = ActorInput(actor_kind="zhang_zhengze")
        self.song = ActorInput(actor_kind="song_dingkun")

    def _create(
        self,
        title: str,
        *,
        state: str = "planned",
        note: str | None = None,
        parent_topic_id: str | None = None,
        manual_order: int = 100,
        key: str,
    ):
        return self.collaboration.create_manual_topic(
            ManualTopicCreateInput(
                title=title,
                state=state,
                note=note,
                parent_topic_id=parent_topic_id,
                manual_order=manual_order,
            ),
            self.zhang,
            idempotency_key=key,
        )

    def test_manual_topic_lifecycle_hierarchy_and_audit(self) -> None:
        root = self._create(
            "低信噪比模型研究路线",
            note="统一维护后续研究议题。",
            manual_order=10,
            key="manual-topic-root-create-0001",
        )
        self.assertTrue(root.ok)
        assert root.data is not None
        root_id = str(root.data["topic_id"])
        self.assertRegex(str(root.data["topic_key"]), r"^manual-[0-9a-f]{32}$")
        self.assertEqual(1, root.data["revision"])
        self.assertEqual("manual", root.data["source_kind"])
        self.assertEqual("张正泽", root.data["created_by"]["display_name"])

        child = self._create(
            "跨种子表征一致性研究",
            state="paused",
            note="等待统一训练基线。",
            parent_topic_id=root_id,
            manual_order=20,
            key="manual-topic-child-create-0001",
        )
        self.assertTrue(child.ok)
        assert child.data is not None
        child_id = str(child.data["topic_id"])
        self.assertEqual(1, child.data["depth"])

        rejected_grandchild = self._create(
            "不允许的三级议题",
            parent_topic_id=child_id,
            key="manual-topic-grandchild-reject-0001",
        )
        self.assertFalse(rejected_grandchild.ok)
        self.assertEqual("invalid_topic_parent", rejected_grandchild.error_code)

        listed = self.collaboration.list_topics_for_management()
        self.assertEqual([root_id, child_id], [item["topic_id"] for item in listed])
        self.assertEqual([0, 1], [item["depth"] for item in listed])

        updated = self.collaboration.update_manual_topic(
            root_id,
            ManualTopicUpdateInput(
                title="低信噪比模型研究议程",
                state="paused",
                note="等待样本外验证协议冻结。",
                manual_order=5,
            ),
            self.song,
            expected_revision=1,
            idempotency_key="manual-topic-root-update-0001",
        )
        self.assertTrue(updated.ok)
        assert updated.data is not None
        self.assertEqual(2, updated.data["revision"])
        self.assertEqual("paused", updated.data["manual_state"])
        self.assertEqual("宋定坤", updated.data["last_modified_by"]["display_name"])

        replay = self.collaboration.update_manual_topic(
            root_id,
            ManualTopicUpdateInput(
                title="低信噪比模型研究议程",
                state="paused",
                note="等待样本外验证协议冻结。",
                manual_order=5,
            ),
            self.song,
            expected_revision=1,
            idempotency_key="manual-topic-root-update-0001",
        )
        self.assertTrue(replay.ok)
        self.assertTrue(replay.replayed)

        stale = self.collaboration.update_manual_topic(
            root_id,
            ManualTopicUpdateInput(title="陈旧修改"),
            self.zhang,
            expected_revision=1,
            idempotency_key="manual-topic-root-stale-0001",
        )
        self.assertFalse(stale.ok)
        self.assertEqual("revision_conflict", stale.error_code)

        parent_blocked = self.collaboration.retire_manual_topic(
            root_id,
            self.zhang,
            expected_revision=2,
            idempotency_key="manual-topic-root-retire-blocked-0001",
        )
        self.assertFalse(parent_blocked.ok)
        self.assertEqual("topic_has_active_children", parent_blocked.error_code)

        retired_child = self.collaboration.retire_manual_topic(
            child_id,
            self.zhang,
            expected_revision=1,
            idempotency_key="manual-topic-child-retire-0001",
        )
        self.assertTrue(retired_child.ok)
        self.assertEqual(2, retired_child.data["revision"])
        self.assertTrue(retired_child.data["retired"])

        retired_root = self.collaboration.retire_manual_topic(
            root_id,
            self.zhang,
            expected_revision=2,
            idempotency_key="manual-topic-root-retire-0001",
        )
        self.assertTrue(retired_root.ok)
        self.assertEqual(3, retired_root.data["revision"])
        self.assertEqual([], self.collaboration.list_topics_for_management())
        self.assertEqual(
            2,
            len(self.collaboration.list_topics_for_management(include_retired=True)),
        )

        with archive_connection(self.settings) as connection:
            self.assertEqual(
                5,
                connection.execute(
                    "SELECT count(*) FROM topic_mutation_event"
                ).fetchone()[0],
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute(
                    "UPDATE topic_mutation_event SET event_kind='state' "
                    "WHERE topic_id=? AND new_revision=1",
                    (root_id,),
                )

    def test_database_hierarchy_and_retirement_guards_are_fail_closed(self) -> None:
        root = self._create("根议题", key="manual-topic-db-root-0001")
        root_id = str(root.data["topic_id"])
        child = self._create(
            "子议题",
            parent_topic_id=root_id,
            key="manual-topic-db-child-0001",
        )
        child_id = str(child.data["topic_id"])

        with archive_connection(self.settings) as connection:
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(topic)")
            }
            self.assertTrue(
                {
                    "parent_topic_id",
                    "created_by_actor_id",
                    "revision",
                    "updated_at",
                }.issubset(columns)
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "one child level"):
                connection.execute(
                    "UPDATE topic SET parent_topic_id=? WHERE topic_id=?",
                    (child_id, root_id),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "active children"):
                connection.execute(
                    "UPDATE topic SET retired_at='2026-07-15T00:00:00Z' "
                    "WHERE topic_id=?",
                    (root_id,),
                )

    def test_topic_management_migration_down_preserves_legacy_topic_state(self) -> None:
        created = self._create(
            "迁移回退议题",
            note="回退后仍应保留既有 topic 与状态事件。",
            key="manual-topic-migration-down-0001",
        )
        topic_id = str(created.data["topic_id"])
        with archive_connection(self.settings) as connection:
            self.assertEqual(
                [5, 4],
                migrate_down(connection, self.settings.archive_migration_root, steps=2),
            )
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(topic)")
            }
            self.assertFalse(
                {
                    "parent_topic_id",
                    "created_by_actor_id",
                    "revision",
                    "updated_at",
                }
                & columns
            )
            self.assertEqual(
                ("迁移回退议题",),
                tuple(
                    connection.execute(
                        "SELECT title FROM topic WHERE topic_id=?", (topic_id,)
                    ).fetchone()
                ),
            )
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT count(*) FROM topic_state_event WHERE topic_id=?", (topic_id,)
                ).fetchone()[0],
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' "
                    "AND name='topic_mutation_event'"
                ).fetchone()
            )
            self.assertEqual(
                [4, 5], migrate_up(connection, self.settings.archive_migration_root)
            )

    def test_manual_topic_revision_competition_has_one_winner(self) -> None:
        created = self._create(
            "并发修改议题",
            key="manual-topic-concurrency-create-0001",
        )
        topic_id = str(created.data["topic_id"])

        outcomes = _run_concurrently(
            2,
            lambda index: ArchiveCollaboration(self.settings).update_manual_topic(
                topic_id,
                ManualTopicUpdateInput(title=f"并发候选标题 {index}"),
                self.zhang,
                expected_revision=1,
                idempotency_key=f"manual-topic-concurrency-update-{index:04d}",
            ),
        )
        winners = [item for item in outcomes if item.ok]
        rejected = [item for item in outcomes if not item.ok]
        self.assertEqual(1, len(winners))
        self.assertEqual(1, len(rejected))
        self.assertEqual(2, winners[0].data["revision"])
        self.assertEqual("revision_conflict", rejected[0].error_code)

        persisted = self.collaboration.get_topic_for_management(topic_id)
        assert persisted is not None
        self.assertEqual(winners[0].data["title"], persisted["title"])
        self.assertEqual(2, persisted["revision"])

    def test_legacy_topic_commands_keep_their_contract_and_gain_audit(self) -> None:
        created = self.collaboration.create_topic(
            TopicInput(topic_key="legacy-compatible-topic", title="兼容议题"),
            self.zhang,
            idempotency_key="legacy-topic-create-0001",
        )
        self.assertTrue(created.ok)
        topic_id = str(created.data["topic_id"])
        self.assertEqual(1, created.data["revision"])

        paused = self.collaboration.set_topic_state(
            topic_id,
            "paused",
            "兼容入口写入的状态。",
            self.zhang,
            idempotency_key="legacy-topic-state-0001",
        )
        self.assertTrue(paused.ok)
        self.assertEqual(2, paused.data["revision"])
        self.assertEqual("paused", self.collaboration.dashboard()[0]["state"])

        managed = self.collaboration.get_topic_for_management(topic_id)
        assert managed is not None
        self.assertFalse(managed["is_manual"])
        self.assertEqual("paused", managed["manual_state"])
        with archive_connection(self.settings) as connection:
            self.assertEqual(
                [("create", 1), ("state", 2)],
                [
                    tuple(row)
                    for row in connection.execute(
                        "SELECT event_kind,new_revision FROM topic_mutation_event "
                        "WHERE topic_id=? ORDER BY new_revision",
                        (topic_id,),
                    ).fetchall()
                ],
            )


if __name__ == "__main__":
    import unittest

    unittest.main()
