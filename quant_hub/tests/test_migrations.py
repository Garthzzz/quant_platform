from __future__ import annotations

from pathlib import Path
import shutil

from quant_hub.platform.db import connect_database
from quant_hub.platform.migrations import MigrationError, migrate_down, migrate_up, schema_hash
from tests.helpers import SettingsTestCase


class MigrationTests(SettingsTestCase):
    def test_up_is_repeatable_and_down_is_reversible(self) -> None:
        connection = connect_database(self.settings.database_path)
        self.addCleanup(connection.close)
        self.assertEqual([1, 2, 3, 4, 5, 6], migrate_up(connection, self.settings.migration_root))
        first_hash = schema_hash(connection)
        self.assertEqual([], migrate_up(connection, self.settings.migration_root))
        self.assertEqual(first_hash, schema_hash(connection))
        self.assertEqual([6, 5, 4, 3, 2, 1], migrate_down(connection, self.settings.migration_root, steps=6))
        names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        self.assertEqual({"schema_migration"}, names)
        self.assertEqual(
            [1, 2, 3, 4, 5, 6],
            migrate_up(connection, self.settings.migration_root),
        )
        self.assertEqual(first_hash, schema_hash(connection))
        self.assertEqual(
            [1, 2, 3, 4, 5, 6],
            [
                row[0]
                for row in connection.execute(
                    "SELECT version FROM schema_migration ORDER BY version"
                )
            ],
        )

    def test_failed_migration_rolls_back_its_ddl(self) -> None:
        bad_root = self.root / "bad-migrations"
        bad_root.mkdir()
        (bad_root / "0001_bad.up.sql").write_text(
            "CREATE TABLE partial(id INTEGER PRIMARY KEY) STRICT;\nTHIS IS NOT SQL;\n",
            encoding="utf-8",
        )
        (bad_root / "0001_bad.down.sql").write_text("DROP TABLE partial;\n", encoding="utf-8")
        connection = connect_database(self.settings.database_path)
        self.addCleanup(connection.close)
        with self.assertRaises(MigrationError):
            migrate_up(connection, bad_root)
        self.assertIsNone(
            connection.execute("SELECT name FROM sqlite_master WHERE name='partial'").fetchone()
        )
        self.assertEqual(0, connection.execute("SELECT count(*) FROM schema_migration").fetchone()[0])

    def test_failed_down_migration_rolls_back_ddl_and_registry_delete(self) -> None:
        bad_root = self.root / "bad-down-migrations"
        bad_root.mkdir()
        (bad_root / "0001_bad_down.up.sql").write_text(
            "CREATE TABLE retained(id INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT;\n",
            encoding="utf-8",
        )
        (bad_root / "0001_bad_down.down.sql").write_text(
            (
                "DROP TABLE retained;\n"
                "DELETE FROM schema_migration WHERE version=1;\n"
                "THIS IS NOT SQL;\n"
            ),
            encoding="utf-8",
        )
        connection = connect_database(self.settings.database_path)
        self.addCleanup(connection.close)
        self.assertEqual([1], migrate_up(connection, bad_root))
        connection.execute("INSERT INTO retained(id,value) VALUES(1,'preserved')")
        registry_before = tuple(
            connection.execute(
                """
                SELECT version,name,up_sha256,down_sha256,applied_at
                FROM schema_migration WHERE version=1
                """
            ).fetchone()
        )

        with self.assertRaisesRegex(MigrationError, "down migration 0001 failed"):
            migrate_down(connection, bad_root)

        self.assertEqual(
            (1, "preserved"),
            tuple(connection.execute("SELECT id,value FROM retained").fetchone()),
        )
        self.assertEqual(
            registry_before,
            tuple(
                connection.execute(
                    """
                    SELECT version,name,up_sha256,down_sha256,applied_at
                    FROM schema_migration WHERE version=1
                    """
                ).fetchone()
            ),
        )

    def test_applied_migration_hash_drift_is_rejected(self) -> None:
        copied = self.root / "migrations"
        shutil.copytree(self.settings.migration_root, copied)
        connection = connect_database(self.settings.database_path)
        self.addCleanup(connection.close)
        migrate_up(connection, copied)
        with (copied / "0001_kernel.up.sql").open("a", encoding="utf-8") as handle:
            handle.write("\n-- drift\n")
        with self.assertRaisesRegex(MigrationError, "drift"):
            migrate_up(connection, copied)

    def test_registry_constraint_migration_rejects_noncanonical_existing_rows(self) -> None:
        v1_root = self.root / "v1-migrations"
        v1_root.mkdir()
        for name in ("0001_kernel.up.sql", "0001_kernel.down.sql"):
            shutil.copy2(self.settings.migration_root / name, v1_root / name)
        connection = connect_database(self.settings.database_path)
        self.addCleanup(connection.close)
        self.assertEqual([1], migrate_up(connection, v1_root))
        digest = "g" * 64
        connection.execute(
            """
            INSERT INTO object_blob(
                object_id,sha256,bytes,media_type,relative_blob_path,created_at,verification_status
            ) VALUES(?,?,?,?,?,?,?)
            """,
            (
                "obj_sha256_" + digest,
                digest,
                0,
                "application/octet-stream",
                "forged.blob",
                "2026-01-01T00:00:00Z",
                "verified",
            ),
        )
        with self.assertRaisesRegex(MigrationError, "0003"):
            migrate_up(connection, self.settings.migration_root)
        self.assertEqual(
            [1, 2],
            [row[0] for row in connection.execute("SELECT version FROM schema_migration ORDER BY version")],
        )
        connection.execute("DELETE FROM object_blob")
        self.assertEqual([3, 4, 5, 6], migrate_up(connection, self.settings.migration_root))

    def test_outbox_material_is_append_only_but_delivery_marker_can_advance(self) -> None:
        connection = connect_database(self.settings.database_path)
        self.addCleanup(connection.close)
        migrate_up(connection, self.settings.migration_root)
        connection.execute(
            """
            INSERT INTO outbox_event(
                event_id,event_type,event_version,aggregate_urn,payload_json,
                payload_hash,created_at,published_at
            ) VALUES('evt_test','TestEvent','1','qrh:test:one','{}',?,? ,NULL)
            """,
            ("0" * 64, "2026-07-15T00:00:00Z"),
        )
        connection.execute(
            "UPDATE outbox_event SET published_at=? WHERE event_id='evt_test'",
            ("2026-07-15T00:01:00Z",),
        )
        with self.assertRaisesRegex(Exception, "immutable"):
            connection.execute(
                "UPDATE outbox_event SET payload_json='[]' WHERE event_id='evt_test'"
            )
        with self.assertRaisesRegex(Exception, "append-only"):
            connection.execute("DELETE FROM outbox_event WHERE event_id='evt_test'")

    def test_version_gap_is_rejected(self) -> None:
        gap_root = self.root / "gap-migrations"
        gap_root.mkdir()
        (gap_root / "0002_gap.up.sql").write_text(
            "CREATE TABLE gap(id INTEGER PRIMARY KEY) STRICT;\n", encoding="utf-8"
        )
        (gap_root / "0002_gap.down.sql").write_text("DROP TABLE gap;\n", encoding="utf-8")
        connection = connect_database(self.settings.database_path)
        self.addCleanup(connection.close)
        with self.assertRaisesRegex(MigrationError, "contiguous"):
            migrate_up(connection, gap_root)
