from __future__ import annotations

import sqlite3

from quant_hub.platform.db import connect_database
from quant_hub.platform.migrations import migrate_down, migrate_up
from tests.helpers import SettingsTestCase


class PaperLabMigrationTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.connection = connect_database(self.settings.paper_lab_database_path)
        self.addCleanup(self.connection.close)

    def test_schema_round_trip_and_strict_invariants(self) -> None:
        self.assertEqual(
            migrate_up(self.connection, self.settings.paper_lab_migration_root),
            [1, 2, 3, 4, 5, 6, 7, 8],
        )
        tables = {
            row[0]
            for row in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        self.assertTrue({
            "lab_paper",
            "lab_paper_version",
            "reading_phase",
            "reading_result",
            "lab_note",
            "tag_vocabulary",
            "concept_component",
            "architecture_blueprint",
            "legacy_record_map",
            "quarantine_record",
            "paper_lab_command_receipt",
            "reading_review_receipt",
            "paper_field_overlay",
            "reading_review_authority_input",
        }.issubset(tables))
        self.assertEqual(self.connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
        self.assertEqual(
            migrate_down(self.connection, self.settings.paper_lab_migration_root, steps=8),
            [8, 7, 6, 5, 4, 3, 2, 1],
        )
        self.assertEqual(
            migrate_up(self.connection, self.settings.paper_lab_migration_root),
            [1, 2, 3, 4, 5, 6, 7, 8],
        )

    def test_paper_version_and_event_are_immutable(self) -> None:
        migrate_up(self.connection, self.settings.paper_lab_migration_root)
        self.connection.execute(
            "INSERT INTO lab_paper VALUES('labpaper_00000000000000000000000000000000','1','T','discovered','manual','t','t')"
        )
        self.connection.execute(
            """
            INSERT INTO lab_paper_version VALUES(
              'labver_00000000000000000000000000000000',
              'labpaper_00000000000000000000000000000000',
              ?,5,'application/pdf','x.pdf','urn:x','aa/x.pdf','registered','t'
            )
            """,
            ("a" * 64,),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.connection.execute(
                "UPDATE lab_paper_version SET bytes=6 WHERE paper_version_id='labver_00000000000000000000000000000000'"
            )
        self.connection.execute(
            "INSERT INTO reading_workflow VALUES('test/v1','test','{}',1,'t')"
        )
        run_values = (
            "labrun_gate_test",
            "labver_00000000000000000000000000000000",
            "test/v1",
            "a" * 64,
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "consumed review certificate"):
            self.connection.execute(
                """
                INSERT INTO reading_run(
                    run_id,paper_version_id,workflow_version,status,attempt,
                    input_revision_sha256,created_at,updated_at
                ) VALUES(?,?,?,'releasable',1,?,'t','t')
                """,
                run_values,
            )
        self.connection.execute(
            """
            INSERT INTO reading_run(
                run_id,paper_version_id,workflow_version,status,attempt,
                input_revision_sha256,created_at,updated_at
            ) VALUES(?,?,?,'queued',1,?,'t','t')
            """,
            run_values,
        )
        self.connection.execute(
            "UPDATE reading_run SET status='awaiting_review' WHERE run_id='labrun_gate_test'"
        )
        self.connection.execute(
            """
            INSERT INTO paper_lab_event VALUES(
                'labevent_forged_review_test','reading_run','labrun_gate_test',
                'reading_reviewed','{"verdict":"pass"}','t'
            )
            """
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "independent review authority"):
            self.connection.execute(
                "UPDATE reading_run SET status='releasable' WHERE run_id='labrun_gate_test'"
            )
        self.connection.execute(
            "INSERT INTO paper_lab_event VALUES('labevent_00000000000000000000000000000000','x','y','z','{}','t')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            self.connection.execute(
                "DELETE FROM paper_lab_event WHERE event_id='labevent_00000000000000000000000000000000'"
            )
        self.connection.execute(
            "INSERT INTO paper_lab_command_receipt VALUES(?,?,?,?,?)",
            ("receipt-key-1", "test", "b" * 64, "{}", "t"),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            self.connection.execute(
                "UPDATE paper_lab_command_receipt SET response_json='[]' "
                "WHERE idempotency_key='receipt-key-1'"
            )
