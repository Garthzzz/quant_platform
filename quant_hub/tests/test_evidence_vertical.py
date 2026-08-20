from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from quant_hub.config import Settings
from quant_hub.evidence.database import evidence_connection
from quant_hub.evidence.fixture import import_vertical_fixture
from quant_hub.evidence.resources import EvidenceResourceStore


class EvidenceVerticalSliceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.formal_root = Path(__file__).resolve().parents[1]
        self.workspace_root = self.formal_root.parent
        self.temporary = tempfile.TemporaryDirectory(
            dir=self.formal_root, prefix=".evidence-vertical-test-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.settings = Settings.default(
            project_root=self.workspace_root,
            var_root=Path(self.temporary.name) / "var",
        )
        self.manifest = self.formal_root / "fixtures" / "evidence" / "vertical_slice.json"
        fixture = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.source = self.settings.archive_root / fixture["canonical_source_path"]
        self.source_before = self.source.read_bytes()

    def test_real_five_class_replay_is_idempotent_and_preserves_fact_boundaries(self) -> None:
        first = import_vertical_fixture(self.settings, self.manifest)
        first_inventory = (
            self.settings.research_papers_root / first.inventory.relative_path
        ).read_bytes()
        second = import_vertical_fixture(self.settings, self.manifest)
        second_inventory = (
            self.settings.research_papers_root / second.inventory.relative_path
        ).read_bytes()

        self.assertEqual(5, first.case_count)
        self.assertEqual(
            {
                "paper_clue": 5,
                "paper_candidate": 5,
                "paper": 4,
                "citation_occurrence": 5,
                "citation_ledger_entry": 5,
                "citation_binding": 5,
                "fetch_attempt": 4,
                "paper_resource": 2,
                "research_paper_relation": 3,
                "evidence_method_origin_candidate_derivation": 0,
                "evidence_canonicalization_receipt": 0,
                "evidence_canonical_resource_attachment": 0,
                "evidence_associated_method_relation": 0,
                "evidence_fulltext_conclusion_support": 0,
                "evidence_canonicalization_event": 0,
                "evidence_canonicalization_state": 0,
            },
            first.counts,
        )
        self.assertEqual(first.counts, second.counts)
        self.assertEqual(first.citation_ids, second.citation_ids)
        self.assertEqual(first.inventory.content_sha256, second.inventory.content_sha256)
        self.assertEqual(first_inventory, second_inventory)
        self.assertNotIn(b"\r", first_inventory)
        self.assertTrue(
            first_inventory.startswith(
                b"# format_version=qrh-research-paper-inventory/v1\n"
            )
        )
        self.assertIn(
            b"# conservation=ledger_entries:5;citation_occurrences:5;",
            first_inventory,
        )
        self.assertEqual(
            "e2b79801433c9a178eae0b11d448c91e1e3048200cebb965c4d5b39ec3171e88",
            hashlib.sha256(first_inventory).hexdigest(),
        )

        with evidence_connection(self.settings) as connection:
            dispositions = {
                str(row["source_candidate_id"]): (
                    str(row["resolution_status"]),
                    row["paper_id"],
                )
                for row in connection.execute(
                    """
                    SELECT clue.source_candidate_id,binding.binding_status AS resolution_status,
                           binding.paper_id
                    FROM paper_clue AS clue
                    JOIN citation_ledger_entry AS ledger USING(clue_id)
                    JOIN citation_occurrence AS occurrence USING(citation_id)
                    JOIN citation_binding_projection AS current USING(ledger_entry_id)
                    JOIN citation_binding AS binding USING(binding_id)
                    """
                )
            }
            self.assertEqual("resolved", dispositions["P020"][0])
            self.assertEqual("resolved", dispositions["P001"][0])
            self.assertEqual(("conflicted", None), dispositions["P067"])
            self.assertEqual("resolved", dispositions["U009"][0])
            self.assertEqual(("rejected_non_paper", None), dispositions["P147"])

            u009_fetch = connection.execute(
                """
                SELECT fetch.result_status,fetch.rights_status
                FROM fetch_attempt AS fetch
                JOIN paper_candidate AS candidate USING(candidate_id)
                JOIN paper_clue_candidate AS link USING(candidate_id)
                JOIN paper_clue AS clue USING(clue_id)
                WHERE clue.source_candidate_id='U009'
                """
            ).fetchone()
            self.assertEqual(("license_blocked", "license_blocked"), tuple(u009_fetch))
            self.assertEqual(
                0,
                connection.execute(
                    """
                    SELECT count(*) FROM paper_resource AS resource
                    JOIN paper_candidate AS candidate
                    JOIN paper_clue_candidate AS link ON link.candidate_id=candidate.candidate_id
                    JOIN paper_clue AS clue ON clue.clue_id=link.clue_id
                    WHERE clue.source_candidate_id='U009'
                      AND resource.paper_id=(SELECT paper_id FROM fetch_attempt WHERE candidate_id=candidate.candidate_id LIMIT 1)
                    """
                ).fetchone()[0],
            )
            p001_marker, p001_links = connection.execute(
                """
                SELECT occurrence.raw_marker_text,
                       (SELECT count(*) FROM paper_external_link AS external
                        WHERE external.paper_id=binding.paper_id)
                FROM paper_clue AS clue
                JOIN citation_ledger_entry AS ledger USING(clue_id)
                JOIN citation_occurrence AS occurrence USING(citation_id)
                JOIN citation_binding_projection AS current USING(ledger_entry_id)
                JOIN citation_binding AS binding USING(binding_id)
                WHERE clue.source_candidate_id='P001'
                """
            ).fetchone()
            self.assertNotIn("academic.oup.com", p001_marker)
            self.assertGreaterEqual(p001_links, 3)
            resources = [
                str(row[0])
                for row in connection.execute(
                    "SELECT resource_id FROM paper_resource ORDER BY resource_id"
                )
            ]
        store = EvidenceResourceStore(self.settings)
        self.assertEqual(2, len(resources))
        for resource_id in resources:
            self.assertTrue(store.resource_response(resource_id).payload.startswith(b"%PDF-"))
        self.assertEqual(self.source_before, self.source.read_bytes())


if __name__ == "__main__":
    unittest.main()
