from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from quant_hub.config import Settings
from quant_hub.evidence.bulk import (
    EvidenceBulkError,
    import_bulk_evidence,
    verify_normalized_resource_manifest,
)
from quant_hub.evidence.database import evidence_connection
from quant_hub.evidence.reading import PaperReadingService
from quant_hub.evidence.releases import EvidenceReleaseService
from quant_hub.evidence.resources import EvidenceResourceCorruption, EvidenceResourceStore
from quant_hub.evidence.service import EvidenceQueryService
from quant_hub.ids import stable_sha256
from quant_hub.platform.releases import ReleaseAuthority
from tests.helpers import materialize_reviewed_archive_with_historical_bootstraps


class EvidenceBulkImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.formal_root = Path(__file__).resolve().parents[1]
        self.workspace_root = self.formal_root.parent
        self.package = self.workspace_root / "project_state" / "workers" / "e_evidence_bulk_data"
        self.normalized = self.formal_root / "fixtures" / "evidence" / "normalized_resource_manifest.jsonl"
        self.temporary = tempfile.TemporaryDirectory(
            dir=self.formal_root, prefix=".evidence-bulk-test-"
        )
        self.addCleanup(self.temporary.cleanup)
        replay_archive = materialize_reviewed_archive_with_historical_bootstraps(
            workspace_root=self.workspace_root,
            destination=Path(self.temporary.name) / "archive",
            restore_occurrence_snapshot=True,
        )
        self.settings = Settings.default(
            project_root=self.workspace_root,
            archive_root=replay_archive,
            var_root=Path(self.temporary.name) / "var",
        )

    def test_full_bulk_import_release_queries_and_recovery_are_evidence_preserving(self) -> None:
        before_occurrences = (
            self.workspace_root
            / "project_state"
            / "workers"
            / "archive_paper_clues"
            / "occurrences.jsonl"
        ).read_bytes()
        first = import_bulk_evidence(
            self.settings,
            self.package,
            normalized_manifest_path=self.normalized,
        )
        second = import_bulk_evidence(
            self.settings,
            self.package,
            normalized_manifest_path=self.normalized,
        )
        self.assertTrue(first.created)
        self.assertFalse(second.created)
        self.assertEqual(first.source_snapshot_hash, second.source_snapshot_hash)
        self.assertEqual(first.inventory.content_sha256, second.inventory.content_sha256)
        self.assertEqual(
            first.candidate_inventory.content_sha256,
            second.candidate_inventory.content_sha256,
        )
        self.assertEqual(
            {
                "paper_clue": 245,
                "paper_candidate": 245,
                "external_identity_candidate": 474,
                "external_assertion": 8,
                "paper": 18,
                "paper_identifier_assertion": 18,
                "paper_category": 4,
                "paper_category_assignment": 23,
                "paper_category_assertion": 18,
                "paper_category_assignment_detail": 23,
                "paper_core_conclusion": 18,
                "paper_core_conclusion_evidence": 18,
                "paper_institution_resolution": 18,
                "organization": 0,
                "person_affiliation_assertion": 0,
                "paper_analysis": 36,
                "evidence_excerpt": 18,
                "paper_reading_task": 18,
                "paper_reading_run": 19,
                "paper_reading_conclusion_binding": 18,
                "citation_occurrence": 4630,
                "citation_ledger_entry": 5181,
                "citation_binding": 5181,
                "fetch_attempt": 221,
                "paper_resource": 18,
                "research_paper_relation": 367,
                "unlinked_ledger_entry": 35,
            },
            first.counts,
        )
        self.assertEqual(
            before_occurrences,
            (
                self.workspace_root
                / "project_state"
                / "workers"
                / "archive_paper_clues"
                / "occurrences.jsonl"
            ).read_bytes(),
        )

        inventory = (
            self.settings.research_papers_root / first.inventory.relative_path
        ).read_text(encoding="utf-8")
        self.assertNotIn("\r", inventory)
        self.assertIn(
            "# locator_counts=pdf_extracted_page_line:435->435;"
            "source_locator_claim:763->763;utf8_bytes:3983->3432",
            inventory,
        )
        self.assertIn("each_ledger_exactly_one_occurrence", inventory)

        candidate_inventory = (
            self.settings.research_papers_root
            / first.candidate_inventory.relative_path
        ).read_text(encoding="utf-8")
        candidate_lines = candidate_inventory.splitlines()
        self.assertEqual(248, len(candidate_lines))
        self.assertEqual(245, len({line.split("\t", 1)[0].strip('"') for line in candidate_lines[3:]}))
        self.assertIn("one_candidate_per_data_line;245_data_lines", candidate_lines[1])
        self.assertIn("source_locators", candidate_lines[2])
        self.assertIn("reading_status", candidate_lines[2])

        with evidence_connection(self.settings) as connection:
            self.assertEqual("ok", connection.execute("PRAGMA integrity_check").fetchone()[0])
            self.assertEqual([], connection.execute("PRAGMA foreign_key_check").fetchall())
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT count(*) FROM external_identity_candidate WHERE selection_status<>'not_selected'"
                ).fetchone()[0],
            )
            self.assertEqual(
                [("pdf_extracted_page_line", 435, 435),
                 ("source_locator_claim", 763, 763),
                 ("utf8_bytes", 3983, 3432)],
                [
                    tuple(row)
                    for row in connection.execute(
                        """
                        SELECT occurrence.locator_kind,count(*),count(DISTINCT citation_id)
                        FROM citation_ledger_entry AS ledger
                        JOIN citation_occurrence AS occurrence USING(citation_id)
                        GROUP BY occurrence.locator_kind ORDER BY occurrence.locator_kind
                        """
                    )
                ],
            )
            self.assertEqual(
                0,
                connection.execute(
                    """
                    SELECT count(*) FROM citation_ledger_entry AS ledger
                    LEFT JOIN citation_occurrence AS occurrence USING(citation_id)
                    WHERE occurrence.citation_id IS NULL
                    """
                ).fetchone()[0],
            )
            self.assertEqual(
                0,
                connection.execute(
                    """
                    SELECT count(*) FROM citation_occurrence AS occurrence
                    WHERE NOT EXISTS (
                        SELECT 1 FROM citation_ledger_entry AS ledger
                        WHERE ledger.citation_id=occurrence.citation_id
                    )
                    """
                ).fetchone()[0],
            )
            self.assertEqual(
                35,
                connection.execute(
                    """
                    SELECT count(*) FROM citation_ledger_entry AS ledger
                    JOIN citation_binding_projection AS projection USING(ledger_entry_id)
                    JOIN citation_binding AS binding USING(binding_id)
                    WHERE ledger.clue_id IS NULL AND binding.binding_status='unresolved'
                    """
                ).fetchone()[0],
            )
            receipt = json.loads(
                connection.execute(
                    "SELECT report_json FROM evidence_import_receipt"
                ).fetchone()[0]
            )
            self.assertEqual(
                "3432 + 763 + 435 = 4630 citation_occurrence",
                receipt["occurrence_contract"]["equations"][3],
            )
            self.assertEqual(
                0,
                connection.execute(
                    """
                    SELECT count(*) FROM citation_ledger_entry AS ledger
                    JOIN citation_occurrence AS occurrence USING(citation_id)
                    WHERE occurrence.locator_kind='utf8_bytes'
                      AND occurrence.line_start<>CAST(substr(ledger.locator_claim,6) AS INTEGER)
                    """
                ).fetchone()[0],
            )
            self.assertEqual(
                106,
                connection.execute(
                    """
                    SELECT count(*) FROM citation_ledger_entry AS ledger
                    JOIN citation_occurrence AS occurrence USING(citation_id)
                    WHERE occurrence.locator_kind='source_locator_claim'
                      AND occurrence.locator_status='unresolved'
                      AND json_extract(occurrence.locator_json,'$.match_status')=
                          'ambiguous_multiple_exact_on_claimed_line'
                    """
                ).fetchone()[0],
            )
            for ledger_id, claimed_line in (("O001851", 224), ("O000116", 506)):
                locator_row = connection.execute(
                    """
                    SELECT occurrence.locator_kind,occurrence.line_start,
                           occurrence.byte_start,occurrence.locator_json
                    FROM citation_ledger_entry AS ledger
                    JOIN citation_occurrence AS occurrence USING(citation_id)
                    WHERE ledger.ledger_entry_id=?
                    """,
                    (ledger_id,),
                ).fetchone()
                self.assertEqual("source_locator_claim", locator_row["locator_kind"])
                self.assertEqual(claimed_line, locator_row["line_start"])
                self.assertIsNone(locator_row["byte_start"])
                self.assertEqual(
                    "not_exact_on_claimed_line",
                    json.loads(locator_row["locator_json"])["match_status"],
                )
            self.assertEqual(
                (18, 18, 18, 18),
                tuple(
                    connection.execute(
                        """
                        SELECT
                          (SELECT count(DISTINCT paper_id) FROM paper_category_assignment),
                          (SELECT count(*) FROM paper_core_conclusion),
                          (SELECT count(*) FROM paper_institution_resolution),
                          (SELECT count(*) FROM paper_institution_resolution
                           WHERE resolution_status='unresolved'
                             AND reason_code='official_source_does_not_expose_affiliation_metadata')
                        """
                    ).fetchone()
                ),
            )
            self.assertEqual(
                0,
                connection.execute(
                    """
                    SELECT count(*) FROM paper_core_conclusion AS conclusion
                    JOIN paper_core_conclusion_evidence AS evidence USING(conclusion_id)
                    JOIN evidence_excerpt AS excerpt ON excerpt.excerpt_id=evidence.excerpt_id
                    WHERE conclusion.fact_status<>'source_claim'
                       OR conclusion.conclusion_text<>excerpt.excerpt_text
                       OR conclusion.provenance_urn<>excerpt.provenance_urn
                    """
                ).fetchone()[0],
            )
            resource_ids = [
                str(row[0])
                for row in connection.execute(
                    "SELECT resource_id FROM paper_resource ORDER BY resource_id"
                )
            ]
            resolved_citation = connection.execute(
                """
                SELECT ledger.citation_id,occurrence.document_sha256
                FROM citation_ledger_entry AS ledger
                JOIN citation_occurrence AS occurrence USING(citation_id)
                JOIN citation_binding_projection AS projection USING(ledger_entry_id)
                JOIN citation_binding AS binding USING(binding_id)
                WHERE binding.binding_status='resolved' LIMIT 1
                """
            ).fetchone()

        store = EvidenceResourceStore(self.settings)
        self.assertEqual(18, len(resource_ids))
        for resource_id in resource_ids:
            self.assertTrue(store.resource_response(resource_id).payload.startswith(b"%PDF-"))

        query = EvidenceQueryService(self.settings)
        paper = query.paper_detail(
            str(
                next(
                    item["paper_id"]
                    for item in query.list_papers(limit=18)["papers"]
                )
            )
        )
        self.assertTrue(paper["category_assignments"])
        self.assertTrue(paper["category_evidence"])
        self.assertEqual("unresolved", paper["institution_resolution"]["status"])
        self.assertEqual("source_claim", paper["core_conclusions"][0]["fact_status"])
        self.assertEqual(
            "official_abstract_verbatim",
            paper["core_conclusions"][0]["claim_scope"],
        )
        detail = query.citation_detail(str(resolved_citation["citation_id"]))
        summaries = [
            item["paper"]["paper_summary"]
            for item in detail["entries"]
            if item["paper"] is not None
        ]
        self.assertTrue(summaries)
        self.assertTrue(summaries[0]["evidence_excerpts"])
        self.assertTrue(summaries[0]["local_resources"])
        self.assertIn(
            query.citation_render_specs(str(resolved_citation["document_sha256"]))[0].resolution_state,
            {"valid", "source-only", "unresolved", "conflicted"},
        )

        reading = PaperReadingService(self.settings)
        self.assertEqual(0, len(reading.pending_tasks()))
        with evidence_connection(self.settings) as connection:
            recovery = connection.execute(
                """
                SELECT identifier.normalized_value,run.attempt_number,run.result_status,
                       json_extract(run.failure_json,'$.class') AS failure_class,
                       retry.attempt_number AS retry_attempt
                FROM paper_reading_run AS run
                JOIN paper_reading_task AS task USING(reading_task_id)
                JOIN paper_identifier_assertion AS identifier
                  ON identifier.paper_id=task.paper_id AND identifier.scheme='arxiv'
                JOIN paper_reading_run AS retry
                  ON retry.reading_task_id=run.reading_task_id
                 AND retry.result_status='succeeded'
                WHERE run.result_status='failed'
                """
            ).fetchone()
            self.assertEqual(
                ("2002.08709", 1, "failed", "controlled_recovery_probe", 2),
                tuple(recovery),
            )
            self.assertEqual(
                0,
                connection.execute(
                    """
                    SELECT count(*) FROM paper_reading_run AS run
                    JOIN paper_reading_task AS task USING(reading_task_id)
                    WHERE run.input_snapshot_hash<>task.input_snapshot_hash
                    """
                ).fetchone()[0],
            )
            self.assertEqual(
                18,
                connection.execute(
                    """
                    SELECT count(*) FROM paper_reading_conclusion_binding AS binding
                    JOIN paper_reading_run AS run USING(reading_run_id)
                    JOIN paper_reading_task AS task USING(reading_task_id)
                    JOIN paper_core_conclusion AS conclusion USING(conclusion_id)
                    WHERE run.result_status='succeeded'
                      AND conclusion.paper_id=task.paper_id
                    """
                ).fetchone()[0],
            )

        release_service = EvidenceReleaseService(self.settings)
        prepared = release_service.prepare_candidate()
        authority = ReleaseAuthority(self.settings)
        candidate = authority.register_candidate(prepared.candidate_spec)
        decision = authority.record_decision(
            candidate.candidate_id,
            deterministic_gate_hash=stable_sha256("bulk-evidence-gate/v1", first.source_snapshot_hash),
            review_set_hash=stable_sha256("bulk-evidence-review/v1", first.inventory.content_sha256),
            reconciliation_hash=stable_sha256("bulk-evidence-reconciliation/v1", "4630", "5181"),
            verdict="pass",
        )
        certificate = authority.issue_snapshot(
            decision.decision_id,
            requirements_manifest_hash=prepared.candidate_spec.requirements_manifest_hash,
            issuance_key=stable_sha256("bulk-evidence-issuance/v1", first.source_snapshot_hash),
        )
        published = release_service.publish(prepared, certificate)
        self.assertTrue(published.created)

        with evidence_connection(self.settings) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "UPDATE external_identity_candidate SET selection_status='rejected'"
                )

        manifest_copy = Path(self.temporary.name) / "normalized-tampered.jsonl"
        payload = self.normalized.read_bytes()
        manifest_copy.write_bytes(payload.replace(b'"bytes":', b'"bytes":9', 1))
        with self.assertRaises(EvidenceBulkError):
            verify_normalized_resource_manifest(self.package, manifest_copy)

        with evidence_connection(self.settings) as connection:
            resource = connection.execute(
                "SELECT relative_path FROM paper_resource ORDER BY resource_id LIMIT 1"
            ).fetchone()
        target = self.settings.research_papers_root.joinpath(*Path(resource[0]).parts)
        target.write_bytes(target.read_bytes() + b"tamper")
        with self.assertRaises(EvidenceResourceCorruption):
            store.resource_response(resource_ids[0])


if __name__ == "__main__":
    unittest.main()
