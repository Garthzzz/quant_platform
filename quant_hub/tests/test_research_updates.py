from __future__ import annotations

from contextlib import closing
import hashlib
import json
import re
from unittest import mock

from quant_hub.app import create_app
from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.archive.contracts import ArchiveDocumentInput, ArchiveReleaseInput
from quant_hub.archive.database import archive_connection
from quant_hub.collaboration.service import ArchiveCollaboration, IdempotencyConflict
from quant_hub.ids import sha256_hex, stable_sha256
from quant_hub.platform.db import connect_database
from quant_hub.platform.releases import ReleaseAuthority
from tests.helpers import SettingsTestCase


class ResearchUpdateTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.catalog = ArchiveCatalog(self.settings)
        self.collaboration = ArchiveCollaboration(self.settings)
        self.published = self._publish(1)
        self.app = create_app(
            self.settings,
            {
                "TESTING": True,
                "SECRET_KEY": "research-update-test",
                "TRUSTED_ORIGINS": ("http://localhost",),
            },
        )
        self.client = self.app.test_client()
        self.csrf = self.client.get("/api/v1/session").get_json()["data"]["csrf_token"]
        self.write_headers = {
            "Origin": "http://localhost",
            "X-CSRF-Token": self.csrf,
        }

    def _release(self, revision: int) -> ArchiveReleaseInput:
        relative = f"update-v{revision}.md"
        source = (
            f"# 更新流研究\n\n第 {revision} 版研究正文。\n"
        ).encode("utf-8")
        (self.archive / relative).write_bytes(source)
        return ArchiveReleaseInput(
            research_slug="update-history-research",
            display_title="更新流研究",
            release_key=f"v{revision}",
            documents=(
                ArchiveDocumentInput(
                    document_slug="main",
                    document_role="primary",
                    source_path=relative,
                    **self.approved_source_fields(relative),
                    navigation_role="primary",
                    sort_key=10,
                    mapping_authority_urn=f"qrh:review:update-v{revision}",
                    mapping_note="研究更新流的显式测试映射",
                ),
            ),
            summary=f"第 {revision} 版摘要。",
            summary_provenance_urn=f"qrh:object:obj_sha256_{sha256_hex(source)}",
            activate=False,
        )

    def _publish(self, revision: int):
        return self.publish_with_test_certificate(
            self.catalog,
            self._release(revision),
            label=f"research-update-v{revision}",
        )

    def test_release_update_is_exactly_once_and_rolls_back_with_activation(self) -> None:
        replay = self.publish_with_test_certificate(
            self.catalog,
            self._release(1),
            label="research-update-v1",
        )
        self.assertEqual(self.published.activation_id, replay.activation_id)
        with archive_connection(self.settings) as connection:
            update = connection.execute("SELECT * FROM research_update").fetchone()
            self.assertEqual(
                stable_sha256(
                    self.published.research_id,
                    self.published.document_manifest_hash,
                    "published",
                ),
                update["update_id"],
            )
            self.assertEqual(1, connection.execute("SELECT count(*) FROM research_update").fetchone()[0])
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT count(*) FROM outbox_event WHERE event_type='ArchiveResearchUpdateRecorded'"
                ).fetchone()[0],
            )

        release_v2 = self._release(2)
        original = ArchiveCollaboration.record_research_update_after_activation

        def fail_after_insert(connection, **kwargs):
            original(connection, **kwargs)
            raise RuntimeError("injected failure after research update insert")

        with mock.patch.object(
            ArchiveCollaboration,
            "record_research_update_after_activation",
            side_effect=fail_after_insert,
        ):
            with self.assertRaisesRegex(RuntimeError, "injected failure"):
                self.publish_with_test_certificate(
                    self.catalog,
                    release_v2,
                    label="research-update-v2",
                )
        with archive_connection(self.settings) as connection:
            active = connection.execute(
                "SELECT activation_id,revision FROM active_research_release WHERE research_id=?",
                (self.published.research_id,),
            ).fetchone()
            self.assertEqual(self.published.activation_id, active["activation_id"])
            self.assertEqual(1, active["revision"])
            self.assertEqual(1, connection.execute("SELECT count(*) FROM research_update").fetchone()[0])

        second = self.publish_with_test_certificate(
            self.catalog,
            release_v2,
            label="research-update-v2",
        )
        self.assertEqual(2, second.active_revision)
        with archive_connection(self.settings) as connection:
            self.assertEqual(2, connection.execute("SELECT count(*) FROM research_update").fetchone()[0])

    def test_annotation_reuses_actor_contract_and_http_write_guards(self) -> None:
        update = self.collaboration.list_research_updates(limit=1)[0]
        update_id = update["update_id"]
        endpoint = f"/api/v1/research-updates/{update_id}/annotations"
        body = {
            "actor": {"actor_kind": "other", "display_name": "研究员甲"},
            "note": None,
        }
        no_session = self.app.test_client().post(
            endpoint,
            json=body,
            headers={"Origin": "http://localhost", "Idempotency-Key": "update-no-session"},
        )
        self.assertEqual(403, no_session.status_code)
        missing_precondition = self.client.post(
            endpoint,
            json=body,
            headers={**self.write_headers, "Idempotency-Key": "update-missing-etag"},
        )
        self.assertEqual(428, missing_precondition.status_code)
        wrong_origin = self.client.post(
            endpoint,
            json=body,
            headers={
                "Origin": "http://attacker.invalid",
                "X-CSRF-Token": self.csrf,
                "Idempotency-Key": "update-wrong-origin",
                "If-Match": f'"research-update:{update_id}:r0"',
            },
        )
        self.assertEqual(403, wrong_origin.status_code)

        headers = {
            **self.write_headers,
            "Idempotency-Key": "update-annotation-1",
            "If-Match": f'"research-update:{update_id}:r0"',
        }
        created = self.client.post(endpoint, json=body, headers=headers)
        self.assertEqual(201, created.status_code)
        self.assertEqual("研究员甲", created.get_json()["data"]["actor"]["display_name"])
        self.assertIsNone(created.get_json()["data"]["note"])
        self.assertEqual(f'"research-update:{update_id}:r1"', created.headers["ETag"])
        replay = self.client.post(endpoint, json=body, headers=headers)
        self.assertEqual(201, replay.status_code)
        self.assertEqual("true", replay.headers["Idempotency-Replayed"])
        conflicting_key = self.client.post(
            endpoint,
            json={**body, "note": "不同载荷"},
            headers=headers,
        )
        self.assertEqual(409, conflicting_key.status_code)
        stale = self.client.post(
            endpoint,
            json={"actor": {"actor_kind": "song_dingkun"}, "note": "过时修订"},
            headers={
                **self.write_headers,
                "Idempotency-Key": "update-annotation-stale",
                "If-Match": f'"research-update:{update_id}:r0"',
            },
        )
        self.assertEqual(409, stale.status_code)
        too_long = self.client.post(
            endpoint,
            json={"actor": {"actor_kind": "song_dingkun"}, "note": "字" * 501},
            headers={
                **self.write_headers,
                "Idempotency-Key": "update-annotation-long",
                "If-Match": f'"research-update:{update_id}:r1"',
            },
        )
        self.assertEqual(422, too_long.status_code)
        invalid_other = self.client.post(
            endpoint,
            json={"actor": {"actor_kind": "other"}, "note": "无姓名"},
            headers={
                **self.write_headers,
                "Idempotency-Key": "update-annotation-other",
                "If-Match": f'"research-update:{update_id}:r1"',
            },
        )
        self.assertEqual(422, invalid_other.status_code)
        projected = self.client.get("/api/v1/research-updates").get_json()["data"][
            "updates"
        ][0]
        self.assertEqual("研究员甲", projected["annotation"]["actor"]["display_name"])
        self.assertEqual(1, projected["annotation_revision"])
        with archive_connection(self.settings) as connection:
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT count(*) FROM research_update_annotation_event"
                ).fetchone()[0],
            )

    def test_jsonl_export_retries_without_rolling_back_database_truth(self) -> None:
        with mock.patch.object(
            ArchiveCollaboration,
            "_atomic_write_research_update_history",
            side_effect=OSError("injected unwritable export"),
        ):
            second = self._publish(2)
        second_update_id = stable_sha256(
            second.research_id, second.document_manifest_hash, "published"
        )
        with archive_connection(self.settings) as connection:
            update_count = connection.execute("SELECT count(*) FROM research_update").fetchone()[0]
            event = connection.execute(
                """
                SELECT published_at,publish_attempt_count FROM outbox_event
                WHERE event_type='ArchiveResearchUpdateRecorded' AND aggregate_urn=?
                """,
                (f"qrh:research-update:{second_update_id}",),
            ).fetchone()
        self.assertEqual(2, update_count)
        self.assertIsNone(event["published_at"])
        self.assertEqual(1, event["publish_attempt_count"])

        recovered = self.collaboration.export_research_update_history()
        self.assertTrue(recovered["ok"])
        self.assertTrue(recovered["changed"])
        payload = self.collaboration.research_update_history_path.read_bytes()
        records = [json.loads(line) for line in payload.decode("utf-8").splitlines()]
        self.assertEqual(2, len(records))
        self.assertEqual(self.published.research_id, records[0]["research_id"])
        with archive_connection(self.settings) as connection:
            event = connection.execute(
                """
                SELECT published_at,publish_attempt_count FROM outbox_event
                WHERE event_type='ArchiveResearchUpdateRecorded' AND aggregate_urn=?
                """,
                (f"qrh:research-update:{second_update_id}",),
            ).fetchone()
            checkpoint = connection.execute(
                "SELECT * FROM research_update_export_checkpoint"
            ).fetchone()
        self.assertIsNotNone(event["published_at"])
        self.assertEqual(2, event["publish_attempt_count"])
        self.assertEqual(hashlib.sha256(payload).hexdigest(), checkpoint["history_sha256"])
        self.assertEqual(2, checkpoint["row_count"])
        self.assertEqual(
            [],
            list(
                self.collaboration.research_update_history_path.parent.glob(".*.tmp")
            ),
        )

    def test_history_gets_are_database_and_jsonl_read_only(self) -> None:
        self._publish(2)
        database_path = self.settings.archive_database_path
        history_path = self.collaboration.research_update_history_path
        before_database = (
            hashlib.sha256(database_path.read_bytes()).hexdigest(),
            database_path.stat().st_mtime_ns,
        )
        before_history = (
            hashlib.sha256(history_path.read_bytes()).hexdigest(),
            history_path.stat().st_mtime_ns,
        )

        self.assertEqual(200, self.client.get("/").status_code)
        self.assertEqual(200, self.client.get("/research-updates").status_code)
        self.assertEqual(200, self.client.get("/api/v1/research-updates").status_code)

        after_database = (
            hashlib.sha256(database_path.read_bytes()).hexdigest(),
            database_path.stat().st_mtime_ns,
        )
        after_history = (
            hashlib.sha256(history_path.read_bytes()).hexdigest(),
            history_path.stat().st_mtime_ns,
        )
        self.assertEqual(before_database, after_database)
        self.assertEqual(before_history, after_history)

    def test_python_backfill_is_deterministic_and_repeatable(self) -> None:
        expected_id = stable_sha256(
            self.published.research_id,
            self.published.document_manifest_hash,
            "published",
        )
        # Emulate a database whose activation predates 0005 while retaining the
        # exact production activation rows. The temporary test DB can remove the
        # new projection after disabling only its append-only deletion guards.
        with archive_connection(self.settings) as connection:
            connection.execute("DROP TRIGGER outbox_event_no_delete")
            connection.execute("DROP TRIGGER research_update_no_delete")
            connection.execute(
                "DELETE FROM outbox_event WHERE event_type='ArchiveResearchUpdateRecorded'"
            )
            connection.execute("DELETE FROM research_update")
        self.assertEqual(
            1,
            self.collaboration.backfill_research_updates(export=False),
        )
        self.assertEqual(
            0,
            self.collaboration.backfill_research_updates(export=False),
        )
        with archive_connection(self.settings) as connection:
            row = connection.execute("SELECT * FROM research_update").fetchone()
            self.assertEqual(expected_id, row["update_id"])
            self.assertEqual(self.published.activation_id, row["activation_id"])
            self.assertEqual(1, row["release_revision"])

    def test_backfill_rejects_a_corrupted_existing_update_projection(self) -> None:
        with archive_connection(self.settings) as connection:
            connection.execute("DROP TRIGGER research_update_no_update")
            connection.execute(
                "UPDATE research_update SET release_revision=99"
            )
        with self.assertRaisesRegex(
            RuntimeError,
            "differs from its first activation occurrence",
        ):
            self.collaboration.backfill_research_updates(export=False)

    def test_reactivating_old_content_keeps_the_first_activation_occurrence(self) -> None:
        self._publish(2)
        authority = ReleaseAuthority(self.settings)
        with closing(connect_database(self.settings.database_path)) as connection:
            approved_v1 = connection.execute(
                """
                SELECT decision.decision_id,candidate.requirements_manifest_hash
                FROM release_decision AS decision
                JOIN release_candidate AS candidate USING(candidate_id)
                ORDER BY candidate.created_at,candidate.candidate_id
                LIMIT 1
                """
            ).fetchone()
        rollback_certificate = authority.issue_snapshot(
            str(approved_v1["decision_id"]),
            requirements_manifest_hash=str(
                approved_v1["requirements_manifest_hash"]
            ),
            issuance_key=stable_sha256(
                "test-release-issuance/v1", "research-update-v1-return"
            ),
        )
        returned = self.catalog.publish_release(
            self._release(1).model_copy(
                update={
                    "activate": True,
                    "release_snapshot_urn": rollback_certificate.snapshot_urn,
                    "activation_decision_hash": rollback_certificate.decision_hash,
                }
            )
        )
        expected_id = stable_sha256(
            self.published.research_id,
            self.published.document_manifest_hash,
            "published",
        )
        with archive_connection(self.settings) as connection:
            self.assertEqual(
                3,
                connection.execute(
                    "SELECT count(*) FROM research_release_activation"
                ).fetchone()[0],
            )
            self.assertEqual(
                2,
                connection.execute("SELECT count(*) FROM research_update").fetchone()[0],
            )
            row = connection.execute(
                "SELECT * FROM research_update WHERE update_id=?",
                (expected_id,),
            ).fetchone()
            self.assertEqual(self.published.activation_id, row["activation_id"])
            self.assertEqual(1, row["release_revision"])
            active = connection.execute(
                "SELECT activation_id,revision FROM active_research_release"
            ).fetchone()
            self.assertEqual(returned.activation_id, active["activation_id"])
            self.assertEqual(3, active["revision"])

    def test_legacy_release_history_remains_exact_after_home_workspace_redesign(self) -> None:
        for revision in range(2, 5):
            self._publish(revision)
        expected = [item["update_id"] for item in self.collaboration.list_research_updates()]
        self.assertEqual(4, len(expected))

        home = self.client.get("/")
        history = self.client.get("/research-updates")
        api = self.client.get("/api/v1/research-updates")
        self.assertEqual(200, home.status_code)
        self.assertEqual(200, history.status_code)
        self.assertEqual(200, api.status_code)
        home_ids = re.findall(
            r'data-update-id="([0-9a-f]{64})"', home.get_data(as_text=True)
        )
        history_ids = re.findall(
            r'data-update-id="([0-9a-f]{64})"', history.get_data(as_text=True)
        )
        api_ids = [item["update_id"] for item in api.get_json()["data"]["updates"]]
        # The rectified home now projects file-backed workspace events.
        # Reviewed publication history remains available in its dedicated
        # history page/API but is deliberately no longer the home dashboard.
        self.assertEqual([], home_ids)
        self.assertEqual(expected, history_ids)
        self.assertEqual(expected, api_ids)
        self.assertIn("最近研究更新", home.get_data(as_text=True))

    def test_service_idempotency_key_conflict_remains_explicit(self) -> None:
        update_id = self.collaboration.list_research_updates(limit=1)[0]["update_id"]
        created = self.collaboration.annotate_research_update(
            update_id,
            self._actor("zhang_zhengze"),
            "初次说明",
            expected_revision=0,
            idempotency_key="direct-update-annotation",
        )
        self.assertTrue(created.ok)
        with self.assertRaises(IdempotencyConflict):
            self.collaboration.annotate_research_update(
                update_id,
                self._actor("song_dingkun"),
                "不同载荷",
                expected_revision=1,
                idempotency_key="direct-update-annotation",
            )

    @staticmethod
    def _actor(kind: str):
        from quant_hub.archive.contracts import ActorInput

        return ActorInput(actor_kind=kind)


if __name__ == "__main__":
    import unittest

    unittest.main()
