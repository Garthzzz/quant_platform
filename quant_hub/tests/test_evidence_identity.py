from __future__ import annotations

import hashlib

from quant_hub.evidence.contracts import CitationOccurrenceInput, StrongIdentifierInput
from quant_hub.evidence.ids import citation_id_for_marker, normalize_identifier
from quant_hub.evidence.repository import EvidenceConflict, EvidenceRepository
from tests.helpers import SettingsTestCase


class EvidenceIdentityTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.repository = EvidenceRepository(self.settings)
        self.repository.initialize()

    def test_citation_id_commits_to_raw_marker_and_exact_utf8_span(self) -> None:
        source = "标题\n引用 arXiv:2203.05556。\n".encode("utf-8")
        marker = "arXiv:2203.05556"
        start = source.index(marker.encode("utf-8"))
        end = start + len(marker.encode("utf-8"))
        digest = hashlib.sha256(source).hexdigest()
        occurrence = CitationOccurrenceInput(
            legacy_occurrence_id="O1",
            clue_id="clue-1",
            research_urn="qrh:research:test",
            archive_release_urn="qrh:release:test",
            document_version_urn="qrh:version:test",
            source_object_urn=f"qrh:object:obj_sha256_{digest}",
            document_sha256=digest,
            line_start=2,
            line_end=2,
            byte_start=start,
            byte_end=end,
            raw_marker_text=marker,
            context_text="引用 arXiv:2203.05556。",
            occurrence_kind="strong_identifier",
            resolution_status="unresolved",
            status_reason="fixture",
        )
        occurrence.verify_source_bytes(source)
        self.assertEqual(56, len(occurrence.citation_id))
        self.assertEqual(
            occurrence.citation_id,
            citation_id_for_marker(digest, start, end, marker.encode("utf-8")),
        )
        changed = occurrence.model_copy(update={"raw_marker_text": "arXiv:2203.05557"})
        self.assertNotEqual(occurrence.citation_id, changed.citation_id)
        with self.assertRaisesRegex(ValueError, "byte span"):
            changed.verify_source_bytes(source)

    def test_identifier_normalization_is_strict(self) -> None:
        self.assertEqual("10.1093/rfs/hhaa009", normalize_identifier("doi", "https://doi.org/10.1093/RFS/HHAA009"))
        self.assertEqual("2203.05556", normalize_identifier("arxiv", "arXiv:2203.05556v4"))
        self.assertEqual("pmc6689936", normalize_identifier("pmcid", "PMC6689936"))
        with self.assertRaises(ValueError):
            normalize_identifier("doi", "not-a-doi")

    def test_strong_identifier_unique_projection_and_explicit_reassignment(self) -> None:
        first = self.repository.create_paper(
            "doi:10.1234/example", provenance_urn="qrh:review:first"
        )
        second = self.repository.create_paper(
            "manual:second", provenance_urn="qrh:review:second"
        )
        identifier = StrongIdentifierInput(
            scheme="doi",
            raw_value="10.1234/example",
            assertion_status="verified",
            provenance_urn="https://doi.org/10.1234/example",
        )
        self.repository.assert_and_assign_identifier(first.paper_id, identifier)
        with self.assertRaisesRegex(EvidenceConflict, "already assigned"):
            self.repository.assert_and_assign_identifier(second.paper_id, identifier)
        self.repository.assert_and_assign_identifier(
            second.paper_id, identifier, allow_reassignment=True
        )
        from quant_hub.evidence.database import evidence_connection

        with evidence_connection(self.settings) as connection:
            assignment = connection.execute(
                "SELECT paper_id,revision FROM identifier_assignment_projection WHERE scheme='doi' AND normalized_value='10.1234/example'"
            ).fetchone()
            self.assertEqual((second.paper_id, 2), tuple(assignment))
            events = connection.execute(
                "SELECT event_kind FROM paper_identity_event ORDER BY occurred_at,identity_event_id"
            ).fetchall()
        self.assertIn(("identifier_reassigned",), [tuple(row) for row in events])


if __name__ == "__main__":
    import unittest

    unittest.main()
