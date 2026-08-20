from __future__ import annotations

import os
from pathlib import Path
import shutil
import tempfile
import unittest

from quant_hub.config import Settings
from quant_hub.paper_lab.database import paper_lab_connection
from quant_hub.paper_lab.importer import LegacyProj2Importer


class PaperLabImportIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name).resolve() / "project"
        (self.project / "reference" / "archive").mkdir(parents=True)
        formal_root = Path(__file__).resolve().parents[1]
        source = formal_root.parent / "reference" / "proj2"
        shutil.copytree(source, self.project / "reference" / "proj2")
        runtime = self.project / "quant_hub" / "var"
        self.settings = Settings(
            project_root=self.project,
            archive_root=self.project / "reference" / "archive",
            var_root=runtime,
            database_path=runtime / "db" / "platform.sqlite3",
            object_root=runtime / "objects",
            migration_root=formal_root / "migrations" / "platform",
        )
        self.settings.validate()

    def test_repeat_import_returns_error_and_quarantines_corrupt_or_linked_assets(self) -> None:
        first = LegacyProj2Importer(self.settings).import_all()
        self.assertEqual(first.status, "PASS")
        with paper_lab_connection(self.settings) as connection:
            pdf = connection.execute(
                """
                SELECT version.asset_relative_path
                FROM legacy_record_map AS map
                JOIN lab_paper_version AS version ON version.paper_version_id=map.target_id
                WHERE map.import_run_id=? AND map.legacy_kind='pdf'
                ORDER BY map.source_relative_path LIMIT 1
                """,
                (first.import_run_id,),
            ).fetchone()
            note = connection.execute(
                """
                SELECT lab_note.snapshot_relative_path
                FROM legacy_record_map AS map
                JOIN lab_note ON lab_note.note_id=map.target_id
                WHERE map.import_run_id=? AND map.legacy_kind='note'
                ORDER BY map.source_relative_path LIMIT 1
                """,
                (first.import_run_id,),
            ).fetchone()
        pdf_path = self.settings.paper_lab_asset_root / pdf["asset_relative_path"]
        hardlink_source = pdf_path.with_name(pdf_path.name + ".integrity-source")
        pdf_path.replace(hardlink_source)
        os.link(hardlink_source, pdf_path)
        note_path = (
            self.settings.paper_lab_asset_root.parent
            / "legacy_snapshot"
            / note["snapshot_relative_path"]
        )
        note_path.write_bytes(b"damaged managed note")

        repeated = LegacyProj2Importer(self.settings).import_all()
        self.assertEqual(repeated.status, "ERROR")
        self.assertGreaterEqual(
            repeated.quarantine_counts["managed_pdf_asset_integrity_error"], 1
        )
        self.assertGreaterEqual(
            repeated.quarantine_counts["managed_note_asset_integrity_error"], 1
        )
        with paper_lab_connection(self.settings) as connection:
            run = connection.execute(
                "SELECT status,summary_json FROM legacy_import_run WHERE import_run_id=?",
                (first.import_run_id,),
            ).fetchone()
            error_quarantines = connection.execute(
                """
                SELECT issue_code,evidence_json FROM quarantine_record
                WHERE import_run_id=? AND issue_code IN (
                    'managed_pdf_asset_integrity_error',
                    'managed_note_asset_integrity_error'
                )
                ORDER BY issue_code
                """,
                (first.import_run_id,),
            ).fetchall()
        self.assertEqual(run["status"], "failed")
        self.assertIn('"status":"ERROR"', run["summary_json"])
        self.assertEqual(
            {row["issue_code"] for row in error_quarantines},
            {
                "managed_pdf_asset_integrity_error",
                "managed_note_asset_integrity_error",
            },
        )
        self.assertTrue(any("hard_linked" in row["evidence_json"] for row in error_quarantines))
        self.assertTrue(any("content_mismatch" in row["evidence_json"] for row in error_quarantines))


if __name__ == "__main__":
    unittest.main()
