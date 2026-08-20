from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from contextlib import closing

from quant_hub.collaboration.checkpoint import (
    CHECKPOINT_MANIFEST_HASH_NAME,
    CHECKPOINT_MANIFEST_NAME,
    CheckpointConflictError,
    create_sqlite_checkpoint,
    evaluate_recovery_protection,
    verify_sqlite_checkpoint,
)
from quant_hub.ops.release_identity import (
    canonical_manifest_bytes,
    manifest_sha256,
    validate_checkpoint_manifest,
)


class SQLiteCheckpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.comments = self.root / "live" / "comments.sqlite3"
        self.workspace = self.root / "live" / "research_workspace.sqlite3"
        self.comments.parent.mkdir(parents=True)
        with closing(sqlite3.connect(self.comments)) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                PRAGMA user_version=2;
                CREATE TABLE actor(actor_id TEXT PRIMARY KEY,display_name TEXT NOT NULL);
                CREATE TABLE comment(
                    comment_id TEXT PRIMARY KEY,
                    actor_id TEXT NOT NULL REFERENCES actor(actor_id),
                    body TEXT NOT NULL
                );
                INSERT INTO actor VALUES('act_1','研究员');
                INSERT INTO comment VALUES('com_1','act_1','已提交评论');
                """
            )
            connection.commit()
        with closing(sqlite3.connect(self.workspace)) as connection:
            connection.executescript(
                """
                PRAGMA user_version=7;
                CREATE TABLE observation(observation_id TEXT PRIMARY KEY,note TEXT NOT NULL);
                INSERT INTO observation VALUES('obs_1','已提交观察');
                """
            )
            connection.commit()
        self.checkpoint_root = self.root / "checkpoints"
        self.release_hash = "a" * 64
        self.captured_at = datetime(2026, 8, 21, 1, 2, 3, tzinfo=UTC)

    def _create(self, checkpoint_id: str = "checkpoint-20260821-0001"):
        return create_sqlite_checkpoint(
            sources={
                "comments": self.comments,
                "research_workspace": self.workspace,
            },
            checkpoint_root=self.checkpoint_root,
            checkpoint_id=checkpoint_id,
            state_authority_id="quant-platform-d-state",
            captured_under_release_id="release-v39-test",
            captured_under_manifest_sha256=self.release_hash,
            captured_at=self.captured_at,
        )

    def test_online_backup_is_immutable_complete_and_restorable(self) -> None:
        # A WAL writer remains open with an uncommitted change.  Online backup
        # must remain usable and capture only committed source state.
        writer = sqlite3.connect(self.comments, timeout=5)
        self.addCleanup(writer.close)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("BEGIN IMMEDIATE")
        writer.execute(
            "INSERT INTO comment VALUES('com_uncommitted','act_1','尚未提交')"
        )

        created = self._create()
        report = verify_sqlite_checkpoint(created.root)
        self.assertTrue(report.valid, report.errors)
        self.assertEqual(self.captured_at, report.captured_at)
        self.assertEqual(2, report.database_count)

        manifest_bytes = created.manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
        validate_checkpoint_manifest(manifest)
        self.assertEqual(canonical_manifest_bytes(manifest), manifest_bytes)
        self.assertEqual(created.manifest_sha256, manifest_sha256(manifest))
        self.assertEqual(
            created.manifest_sha256,
            (created.root / CHECKPOINT_MANIFEST_HASH_NAME)
            .read_text(encoding="ascii")
            .strip(),
        )
        self.assertEqual(
            {
                "release_id": "release-v39-test",
                "manifest_sha256": self.release_hash,
            },
            manifest["captured_under_active_release"],
        )
        self.assertEqual(
            "sqlite_online_backup", manifest["state"]["backup_protocol"]["name"]
        )
        self.assertFalse(manifest["state"]["backup_protocol"]["wal_shm_copied"])
        records = {
            item["logical_name"]: item for item in manifest["state"]["databases"]
        }
        self.assertEqual(1, records["comments"]["logical_counts"]["comment"])
        self.assertEqual(2, records["comments"]["schema"]["user_version"])
        self.assertEqual(7, records["research_workspace"]["schema"]["user_version"])
        self.assertTrue(records["comments"]["restore_validation"]["schema_matches"])
        self.assertFalse(
            any(
                path.name.endswith(("-wal", "-shm"))
                for path in created.root.rglob("*")
            )
        )

        # The writer can still commit after capture; the checkpoint remains
        # an immutable earlier recovery point.
        writer.commit()
        self.assertEqual(1, records["comments"]["logical_counts"]["comment"])
        self.assertTrue(verify_sqlite_checkpoint(created.root).valid)

    def test_reusing_checkpoint_id_fails_without_changing_existing_bytes(self) -> None:
        created = self._create()
        before = {
            path.relative_to(created.root).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in created.root.rglob("*")
            if path.is_file()
        }
        with closing(sqlite3.connect(self.comments)) as connection:
            connection.execute(
                "INSERT INTO comment VALUES('com_2','act_1','后来写入')"
            )
            connection.commit()
        with self.assertRaises(CheckpointConflictError):
            self._create()
        after = {
            path.relative_to(created.root).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in created.root.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)

    def test_hash_or_restore_corruption_fails_closed(self) -> None:
        created = self._create()
        database_path = created.root / "state" / "comments.sqlite3"
        with database_path.open("ab") as stream:
            stream.write(b"corrupt-after-checkpoint")
        report = verify_sqlite_checkpoint(created.root)
        self.assertFalse(report.valid)
        self.assertEqual(("checkpoint_validation_failed",), report.errors)

        status = evaluate_recovery_protection(
            [created.root],
            now=self.captured_at + timedelta(hours=1),
        )
        self.assertEqual("failed", status.status)
        self.assertIn("no_fully_verified_checkpoint", status.reason_codes)

    def test_rpo_uses_latest_verified_captured_at_not_attempt_time(self) -> None:
        first = self._create("checkpoint-20260821-0001")
        protected = evaluate_recovery_protection(
            [first.root],
            now=self.captured_at + timedelta(hours=23, minutes=59),
        )
        self.assertEqual("protected", protected.status)
        self.assertEqual(23 * 3600 + 59 * 60, protected.checkpoint_age_seconds)

        degraded = evaluate_recovery_protection(
            [first.root],
            now=self.captured_at + timedelta(hours=24, seconds=1),
        )
        self.assertEqual("degraded", degraded.status)
        self.assertIn("checkpoint_rpo_exceeded", degraded.reason_codes)

        recent_failed_job = evaluate_recovery_protection(
            [first.root],
            now=self.captured_at + timedelta(hours=1),
            latest_attempt_succeeded=False,
        )
        self.assertEqual("degraded", recent_failed_job.status)
        self.assertIn("latest_checkpoint_attempt_failed", recent_failed_job.reason_codes)

        unattested = evaluate_recovery_protection(
            [first.root],
            now=self.captured_at + timedelta(hours=1),
            failure_domain_attested=False,
        )
        self.assertEqual("failed", unattested.status)
        self.assertIn("failure_domain_not_attested", unattested.reason_codes)

    def test_newer_valid_checkpoint_controls_rpo_without_release_change(self) -> None:
        first = self._create("checkpoint-20260821-0001")
        second_time = self.captured_at + timedelta(hours=20)
        second = create_sqlite_checkpoint(
            sources={"comments": self.comments},
            checkpoint_root=self.checkpoint_root,
            checkpoint_id="checkpoint-20260821-0002",
            state_authority_id="quant-platform-d-state",
            captured_under_release_id="release-v39-test",
            captured_under_manifest_sha256=self.release_hash,
            captured_at=second_time,
        )
        status = evaluate_recovery_protection(
            [first.root, second.root],
            now=self.captured_at + timedelta(hours=30),
        )
        self.assertEqual("protected", status.status)
        self.assertEqual(second.checkpoint_id, status.last_successful_checkpoint_id)
        self.assertEqual(10 * 3600, status.checkpoint_age_seconds)

        first_manifest = json.loads(
            (first.root / CHECKPOINT_MANIFEST_NAME).read_text(encoding="utf-8")
        )
        second_manifest = json.loads(
            (second.root / CHECKPOINT_MANIFEST_NAME).read_text(encoding="utf-8")
        )
        self.assertEqual(
            first_manifest["captured_under_active_release"],
            second_manifest["captured_under_active_release"],
        )

        # A newer object that no longer passes hash/restore validation is not a
        # successful checkpoint.  The older verified point remains usable, but
        # protection is explicitly degraded rather than silently reported fresh.
        with (second.root / "state" / "comments.sqlite3").open("ab") as stream:
            stream.write(b"invalid-newer-checkpoint")
        degraded = evaluate_recovery_protection(
            [first.root, second.root],
            now=self.captured_at + timedelta(hours=21),
        )
        self.assertEqual("degraded", degraded.status)
        self.assertEqual(first.checkpoint_id, degraded.last_successful_checkpoint_id)
        self.assertIn("latest_checkpoint_attempt_failed", degraded.reason_codes)


if __name__ == "__main__":
    unittest.main()
