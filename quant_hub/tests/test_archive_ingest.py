from __future__ import annotations

from dataclasses import replace
import multiprocessing
import os
from pathlib import Path
import sqlite3
import subprocess
from unittest import mock

from quant_hub.archive.service import ingest_archive_snapshot, initialize_platform
from quant_hub.platform.db import connect_database
from quant_hub.platform.objects import ObjectCorruptionError, ObjectStore, StoredObject
from quant_hub.archive.source_reader import ReadOnlyArchiveSource
from quant_hub.platform.workflow import register_archive_snapshot
from tests.helpers import SettingsTestCase


def _ingest_process_worker(settings, relative_path: str, queue) -> None:
    try:
        result = ingest_archive_snapshot(settings, relative_path)
        queue.put({"run_id": result.run_id, "run_created": result.run_created})
    except BaseException as error:
        queue.put({"error": f"{type(error).__name__}: {error}"})


def _initialize_process_worker(settings, queue) -> None:
    try:
        queue.put({"applied": initialize_platform(settings)})
    except BaseException as error:
        queue.put({"error": f"{type(error).__name__}: {error}"})


class ArchiveIngestTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.source = self.archive / "研究.md"
        self.source.write_text("# 研究\n\n原文保持不变。\n", encoding="utf-8")

    def _counts(self) -> dict[str, int]:
        connection = connect_database(self.settings.database_path)
        try:
            return {
                table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table in (
                    "object_blob",
                    "source_location",
                    "pipeline_run",
                    "step_execution",
                    "outbox_event",
                )
            }
        finally:
            connection.close()

    def test_end_to_end_registration_is_idempotent(self) -> None:
        before = self.source.read_bytes()
        first = ingest_archive_snapshot(self.settings, "研究.md")
        first_counts = self._counts()
        second = ingest_archive_snapshot(self.settings, "研究.md")
        self.assertTrue(first.run_created)
        self.assertFalse(second.run_created)
        self.assertEqual(first.object_id, second.object_id)
        self.assertEqual(first.source_location_id, second.source_location_id)
        self.assertEqual(first.run_id, second.run_id)
        self.assertEqual(
            {
                "object_blob": 1,
                "source_location": 1,
                "pipeline_run": 1,
                "step_execution": 1,
                "outbox_event": 1,
            },
            first_counts,
        )
        self.assertEqual(first_counts, self._counts())
        self.assertEqual(before, self.source.read_bytes())

    def test_idempotent_replay_rejects_incomplete_success_lifecycle(self) -> None:
        first = ingest_archive_snapshot(self.settings, "研究.md")
        connection = connect_database(self.settings.database_path)
        try:
            connection.execute(
                "UPDATE pipeline_run SET finished_at=NULL WHERE run_id=?",
                (first.run_id,),
            )
        finally:
            connection.close()
        with self.assertRaisesRegex(RuntimeError, "lifecycle"):
            ingest_archive_snapshot(self.settings, "研究.md")

        connection = connect_database(self.settings.database_path)
        try:
            connection.execute(
                "UPDATE pipeline_run SET finished_at=started_at WHERE run_id=?",
                (first.run_id,),
            )
            connection.execute(
                "UPDATE step_execution SET required_for_release=0 WHERE run_id=?",
                (first.run_id,),
            )
        finally:
            connection.close()
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            ingest_archive_snapshot(self.settings, "研究.md")

    def test_windows_case_alias_is_the_same_source_and_run(self) -> None:
        first = ingest_archive_snapshot(self.settings, "研究.md")
        second = ingest_archive_snapshot(self.settings, "研究.MD")
        self.assertEqual(first.source_location_id, second.source_location_id)
        self.assertEqual(first.run_id, second.run_id)
        self.assertFalse(second.run_created)
        self.assertEqual(
            {
                "object_blob": 1,
                "source_location": 1,
                "pipeline_run": 1,
                "step_execution": 1,
                "outbox_event": 1,
            },
            self._counts(),
        )

    def test_forged_object_identity_is_rejected_before_transaction(self) -> None:
        initialize_platform(self.settings)
        snapshot = ReadOnlyArchiveSource(self.archive).snapshot("研究.md")
        forged = StoredObject(
            object_id="obj_sha256_" + "0" * 64,
            sha256=snapshot.sha256,
            bytes=snapshot.bytes,
            relative_path=Path(snapshot.sha256[:2], snapshot.sha256[2:4], snapshot.sha256 + ".blob").as_posix(),
            created=False,
        )
        connection = connect_database(self.settings.database_path)
        try:
            with self.assertRaisesRegex(ValueError, "object ID"):
                register_archive_snapshot(connection, snapshot, forged, ObjectStore(self.settings.object_root))
        finally:
            connection.close()
        self.assertEqual(
            {
                "object_blob": 0,
                "source_location": 0,
                "pipeline_run": 0,
                "step_execution": 0,
                "outbox_event": 0,
            },
            self._counts(),
        )

    def test_mutually_consistent_forged_byte_counts_are_rejected(self) -> None:
        initialize_platform(self.settings)
        snapshot = ReadOnlyArchiveSource(self.archive).snapshot("研究.md")
        stored = ObjectStore(self.settings.object_root).put_bytes(snapshot.content)
        forged_snapshot = replace(snapshot, bytes=snapshot.bytes + 1)
        forged_stored = replace(stored, bytes=stored.bytes + 1)
        connection = connect_database(self.settings.database_path)
        try:
            with self.assertRaisesRegex(ValueError, "byte length"):
                register_archive_snapshot(
                    connection,
                    forged_snapshot,
                    forged_stored,
                    ObjectStore(self.settings.object_root),
                )
        finally:
            connection.close()
        self.assertEqual(
            {
                "object_blob": 0,
                "source_location": 0,
                "pipeline_run": 0,
                "step_execution": 0,
                "outbox_event": 0,
            },
            self._counts(),
        )

    def test_repository_reuses_the_full_archive_source_identity_contract(self) -> None:
        initialize_platform(self.settings)
        snapshot = ReadOnlyArchiveSource(self.archive).snapshot("研究.md")
        stored = ObjectStore(self.settings.object_root).put_bytes(snapshot.content)
        forged_snapshots = (
            replace(
                snapshot,
                relative_path="forged.txt",
                origin_uri="archive:///forged.txt",
            ),
            replace(
                snapshot,
                relative_path="bad /forged.md",
                origin_uri="archive:///bad%20/forged.md",
            ),
            replace(snapshot, observed_at="not-a-utc-timestamp"),
        )
        connection = connect_database(self.settings.database_path)
        try:
            for forged in forged_snapshots:
                with self.subTest(relative_path=forged.relative_path, observed_at=forged.observed_at):
                    with self.assertRaisesRegex(ValueError, "Archive identity contract|origin URI"):
                        register_archive_snapshot(
                            connection,
                            forged,
                            stored,
                            ObjectStore(self.settings.object_root),
                        )
        finally:
            connection.close()
        self.assertEqual(
            {
                "object_blob": 0,
                "source_location": 0,
                "pipeline_run": 0,
                "step_execution": 0,
                "outbox_event": 0,
            },
            self._counts(),
        )

    def test_missing_content_object_cannot_be_registered_as_success(self) -> None:
        initialize_platform(self.settings)
        snapshot = ReadOnlyArchiveSource(self.archive).snapshot("研究.md")
        stored = StoredObject(
            object_id="obj_sha256_" + snapshot.sha256,
            sha256=snapshot.sha256,
            bytes=snapshot.bytes,
            relative_path=ObjectStore.relative_path(snapshot.sha256).as_posix(),
            created=False,
        )
        connection = connect_database(self.settings.database_path)
        try:
            with self.assertRaisesRegex(ObjectCorruptionError, "missing"):
                register_archive_snapshot(
                    connection,
                    snapshot,
                    stored,
                    ObjectStore(self.settings.object_root),
                )
        finally:
            connection.close()
        self.assertEqual(
            {
                "object_blob": 0,
                "source_location": 0,
                "pipeline_run": 0,
                "step_execution": 0,
                "outbox_event": 0,
            },
            self._counts(),
        )

    def test_database_trigger_rejects_direct_object_identity_mismatch(self) -> None:
        initialize_platform(self.settings)
        connection = connect_database(self.settings.database_path)
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO object_blob(
                        object_id,sha256,bytes,media_type,relative_blob_path,created_at,verification_status
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        "obj_sha256_" + "0" * 64,
                        "1" * 64,
                        0,
                        "application/octet-stream",
                        "forged.blob",
                        "2026-01-01T00:00:00Z",
                        "verified",
                    ),
                )
            self.assertEqual(0, connection.execute("SELECT count(*) FROM object_blob").fetchone()[0])
        finally:
            connection.close()

    def test_database_trigger_rejects_noncanonical_digest_and_blob_path(self) -> None:
        initialize_platform(self.settings)
        connection = connect_database(self.settings.database_path)
        try:
            invalid_rows = (
                (
                    "obj_sha256_" + "g" * 64,
                    "g" * 64,
                    "gg/gg/" + "g" * 64 + ".blob",
                ),
                (
                    "obj_sha256_" + "a" * 64,
                    "a" * 64,
                    "wrong/location.blob",
                ),
            )
            for object_id, digest, relative_path in invalid_rows:
                with self.subTest(digest=digest, relative_path=relative_path):
                    with self.assertRaises(sqlite3.IntegrityError):
                        connection.execute(
                            """
                            INSERT INTO object_blob(
                                object_id,sha256,bytes,media_type,relative_blob_path,
                                created_at,verification_status
                            ) VALUES(?,?,?,?,?,?,?)
                            """,
                            (
                                object_id,
                                digest,
                                0,
                                "application/octet-stream",
                                relative_path,
                                "2026-01-01T00:00:00Z",
                                "verified",
                            ),
                        )
            self.assertEqual(0, connection.execute("SELECT count(*) FROM object_blob").fetchone()[0])
        finally:
            connection.close()

    def test_database_trigger_makes_object_material_fields_immutable(self) -> None:
        initialize_platform(self.settings)
        connection = connect_database(self.settings.database_path)
        try:
            first_digest = "1" * 64
            second_digest = "2" * 64
            connection.execute(
                """
                INSERT INTO object_blob(
                    object_id,sha256,bytes,media_type,relative_blob_path,
                    created_at,verification_status
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    "obj_sha256_" + first_digest,
                    first_digest,
                    0,
                    "application/octet-stream",
                    "11/11/" + first_digest + ".blob",
                    "2026-01-01T00:00:00Z",
                    "verified",
                ),
            )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    UPDATE object_blob
                    SET object_id=?,sha256=?,bytes=?,media_type=?,relative_blob_path=?,created_at=?
                    WHERE object_id=?
                    """,
                    (
                        "obj_sha256_" + second_digest,
                        second_digest,
                        999,
                        "text/plain",
                        "22/22/" + second_digest + ".blob",
                        "2099-01-01T00:00:00Z",
                        "obj_sha256_" + first_digest,
                    ),
                )
            row = connection.execute(
                "SELECT object_id,sha256,bytes,media_type,relative_blob_path,created_at FROM object_blob"
            ).fetchone()
            self.assertEqual(
                (
                    "obj_sha256_" + first_digest,
                    first_digest,
                    0,
                    "application/octet-stream",
                    "11/11/" + first_digest + ".blob",
                    "2026-01-01T00:00:00Z",
                ),
                tuple(row),
            )
            connection.execute(
                "UPDATE object_blob SET verification_status='quarantined' WHERE object_id=?",
                ("obj_sha256_" + first_digest,),
            )
            self.assertEqual(
                "quarantined",
                connection.execute("SELECT verification_status FROM object_blob").fetchone()[0],
            )
        finally:
            connection.close()

    def test_database_file_symlink_is_rejected_before_connect(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows runtime contract")
        self.settings.database_path.parent.mkdir(parents=True)
        external = self.project / "outside-runtime.sqlite3"
        sqlite3.connect(external).close()
        os.symlink(external, self.settings.database_path)
        try:
            with self.assertRaisesRegex(ValueError, "reparse"):
                self.settings.ensure_runtime_directories()
            with self.assertRaisesRegex(ValueError, "reparse"):
                connect_database(self.settings.database_path)
            connection = sqlite3.connect(external)
            try:
                self.assertEqual([], connection.execute("SELECT name FROM sqlite_master").fetchall())
            finally:
                connection.close()
        finally:
            if os.path.lexists(self.settings.database_path):
                self.settings.database_path.unlink()

    def test_database_hardlink_is_rejected_before_connect(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows runtime contract")
        self.settings.database_path.parent.mkdir(parents=True)
        external = self.project / "outside-hardlinked-runtime.sqlite3"
        sqlite3.connect(external).close()
        os.link(external, self.settings.database_path)
        try:
            with self.assertRaisesRegex(ValueError, "hard-linked"):
                self.settings.ensure_runtime_directories()
            with self.assertRaisesRegex(ValueError, "hard-linked"):
                connect_database(self.settings.database_path)
            connection = sqlite3.connect(external)
            try:
                self.assertEqual([], connection.execute("SELECT name FROM sqlite_master").fetchall())
            finally:
                connection.close()
        finally:
            if os.path.lexists(self.settings.database_path):
                self.settings.database_path.unlink()

    def test_replaced_runtime_root_is_rejected_before_directory_creation(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows runtime contract")
        external = self.project / "outside-runtime-root"
        external.mkdir()
        self.var.parent.mkdir(parents=True)
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(self.var), str(external)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr or completed.stdout)
        try:
            with self.assertRaisesRegex(ValueError, "reparse"):
                self.settings.ensure_runtime_directories()
            with self.assertRaisesRegex(ValueError, "reparse"):
                connect_database(self.settings.database_path)
            self.assertEqual([], list(external.iterdir()))
        finally:
            if os.path.lexists(self.var):
                os.rmdir(self.var)

    def test_disappearing_sqlite_sidecar_is_treated_as_transient(self) -> None:
        initialize_platform(self.settings)
        real_lstat = Path.lstat

        def lstat_with_transient_shm(path: Path, *args: object, **kwargs: object):
            if str(path).endswith("-shm"):
                raise FileNotFoundError(path)
            return real_lstat(path, *args, **kwargs)

        with mock.patch.object(Path, "lstat", new=lstat_with_transient_shm):
            connection = connect_database(self.settings.database_path)
            connection.close()

    def test_outbox_failure_rolls_back_all_database_success_state(self) -> None:
        initialize_platform(self.settings)
        connection = connect_database(self.settings.database_path)
        try:
            connection.execute(
                """
                CREATE TRIGGER reject_outbox BEFORE INSERT ON outbox_event
                BEGIN SELECT RAISE(ABORT, 'injected outbox failure'); END
                """
            )
        finally:
            connection.close()
        with self.assertRaises(sqlite3.DatabaseError):
            ingest_archive_snapshot(self.settings, "研究.md")
        self.assertEqual(
            {
                "object_blob": 0,
                "source_location": 0,
                "pipeline_run": 0,
                "step_execution": 0,
                "outbox_event": 0,
            },
            self._counts(),
        )

    def test_spawn_concurrent_replay_creates_one_run_and_event(self) -> None:
        initialize_platform(self.settings)
        context = multiprocessing.get_context("spawn")
        queue = context.Queue()
        processes = [
            context.Process(
                target=_ingest_process_worker,
                args=(self.settings, "研究.md", queue),
            )
            for _ in range(8)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(20)
            self.assertFalse(process.is_alive(), f"worker did not exit: {process.pid}")
            self.assertEqual(0, process.exitcode)
        results = [queue.get(timeout=2) for _ in processes]
        self.assertFalse([item for item in results if "error" in item], results)
        self.assertEqual(1, sum(bool(item["run_created"]) for item in results))
        self.assertEqual(1, len({item["run_id"] for item in results}))
        self.assertEqual(
            {
                "object_blob": 1,
                "source_location": 1,
                "pipeline_run": 1,
                "step_execution": 1,
                "outbox_event": 1,
            },
            self._counts(),
        )

    def test_spawn_concurrent_first_initialization_applies_migration_once(self) -> None:
        context = multiprocessing.get_context("spawn")
        queue = context.Queue()
        processes = [
            context.Process(target=_initialize_process_worker, args=(self.settings, queue))
            for _ in range(8)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(20)
            self.assertFalse(process.is_alive(), f"worker did not exit: {process.pid}")
            self.assertEqual(0, process.exitcode)
        results = [queue.get(timeout=2) for _ in processes]
        self.assertFalse([item for item in results if "error" in item], results)
        applied_versions = [version for item in results for version in item["applied"]]
        self.assertEqual([1, 2, 3, 4, 5, 6], sorted(applied_versions))
        self.assertTrue(
            all(
                item["applied"] == sorted(item["applied"])
                and set(item["applied"]).issubset({1, 2, 3, 4, 5, 6})
                for item in results
            )
        )
        connection = connect_database(self.settings.database_path)
        try:
            self.assertEqual(6, connection.execute("SELECT count(*) FROM schema_migration").fetchone()[0])
            self.assertEqual("ok", connection.execute("PRAGMA integrity_check").fetchone()[0])
        finally:
            connection.close()
