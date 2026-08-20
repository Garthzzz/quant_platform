from __future__ import annotations

import csv
import hashlib
from pathlib import Path
import unittest

from quant_hub.config import Settings
from quant_hub.paper_lab.database import paper_lab_connection
from quant_hub.paper_lab.importer import LegacyProj2Importer
from quant_hub.paper_lab.projection import ComponentProjector
from quant_hub.paper_lab.service import PaperLabService


class PaperLabRealReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.settings = Settings.default()
        cls.source = cls.settings.project_root / "reference" / "proj2"
        cls.sidecars_before = {
            path.name for path in (cls.source / "data").glob("papers.db-*")
        }
        cls.report = LegacyProj2Importer(cls.settings).import_all()

    def test_full_137_import_and_known_anomalies(self) -> None:
        self.assertEqual(self.report.status, "PASS")
        self.assertTrue(self.report.source_unchanged)
        self.assertEqual(self.report.source_counts, {"db_rows": 137, "pdf": 137, "json": 141, "notes": 161})
        self.assertEqual(self.report.imported_counts["papers"], 137)
        self.assertEqual(self.report.imported_counts["pdf_assets"], 137)
        self.assertEqual(self.report.imported_counts["json_assets"], 141)
        self.assertEqual(self.report.imported_counts["note_assets"], 161)
        self.assertEqual(self.report.quarantine_counts["legacy_json_missing_fields"], 53)
        self.assertEqual(self.report.quarantine_counts["legacy_json_parse_error"], 1)
        self.assertEqual(self.report.quarantine_counts["legacy_json_utf8_bom"], 1)
        self.assertEqual(self.report.unknown_tag_count, 29)
        self.assertEqual(self.report.local_pdf_routes_repaired, 51)

    def test_immutable_database_reader_created_no_source_sidecar(self) -> None:
        sidecars_after = {path.name for path in (self.source / "data").glob("papers.db-*")}
        self.assertEqual(self.sidecars_before, sidecars_after)

    def test_every_pdf_and_snapshot_is_byte_identical(self) -> None:
        with paper_lab_connection(self.settings) as connection:
            rows = connection.execute(
                """
                SELECT m.source_relative_path,m.source_sha256,v.asset_relative_path
                FROM legacy_record_map m
                JOIN lab_paper_version v ON v.paper_version_id=m.target_id
                WHERE m.import_run_id=? AND m.legacy_kind='pdf'
                """,
                (self.report.import_run_id,),
            ).fetchall()
        self.assertEqual(len(rows), 137)
        for row in rows:
            source = self.source / row["source_relative_path"]
            asset = self.settings.paper_lab_asset_root / row["asset_relative_path"]
            snapshot = Path(self.report.snapshot_root) / row["source_relative_path"]
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            self.assertEqual(digest, row["source_sha256"])
            self.assertEqual(asset.read_bytes(), source.read_bytes())
            self.assertEqual(snapshot.read_bytes(), source.read_bytes())

    def test_projection_covers_137_and_is_idempotent(self) -> None:
        first = ComponentProjector(self.settings).rebuild()
        second = ComponentProjector(self.settings).rebuild()
        self.assertEqual(first.status, "PASS")
        self.assertEqual(first.covered_paper_count, 137)
        self.assertEqual(second.created_component_count, 0)
        self.assertEqual(first.source_revision_sha256, second.source_revision_sha256)

    def test_year_filters_treat_undisclosed_years_as_unknown(self) -> None:
        rows = PaperLabService(self.settings).list_papers(after=2020, before=2026)
        self.assertTrue(rows)
        self.assertTrue(all(str(row.get("start_year", "")).isdigit() for row in rows))
        self.assertTrue(all(str(row.get("end_year", "")).isdigit() for row in rows))

    def test_executable_compatibility_matrix_has_no_unverified_row(self) -> None:
        path = self.settings.project_root / "quant_hub" / "fixtures" / "paper_lab" / "compatibility_matrix.tsv"
        with path.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle, delimiter="\t"))
        self.assertEqual(len(rows), 645)
        self.assertTrue(all(row["test_id"] and row["evidence_locator"] for row in rows))
        self.assertEqual({row["verdict"] for row in rows}, {"PASS"})
