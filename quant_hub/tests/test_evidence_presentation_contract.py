from __future__ import annotations

import hashlib
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from quant_hub.evidence.presentation_contract import (
    CROSSREF_GENERATED_FACT_BOUNDARY,
    ChineseOverlayContractError,
    GENERATED_FACT_BOUNDARY,
    build_chinese_overlay_contract,
    build_reviewed_arxiv_official_abstract_projection_contract,
    build_reviewed_crossref_official_abstract_projection_contract,
)
from quant_hub.runtime_seal import canonical_json


class ChineseOverlayContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "research_papers.sqlite3"
        self.overlay = self.root / "evidence_zh_overlays.json"
        self.text = "Official abstract source text."
        self.digest = hashlib.sha256(self.text.encode("utf-8")).hexdigest()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.executescript(
                """
                CREATE TABLE identifier_assignment_projection(
                    scheme TEXT NOT NULL,
                    normalized_value TEXT NOT NULL,
                    paper_id TEXT NOT NULL
                );
                CREATE TABLE paper_catalog_projection(
                    paper_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL
                );
                CREATE TABLE evidence_excerpt(
                    excerpt_id TEXT PRIMARY KEY,
                    paper_id TEXT NOT NULL,
                    excerpt_text TEXT NOT NULL,
                    excerpt_sha256 TEXT NOT NULL,
                    locator_json TEXT NOT NULL
                );
                CREATE TABLE evidence_canonicalization_receipt(
                    source_candidate_id TEXT NOT NULL,
                    paper_source_candidate_id TEXT NOT NULL,
                    paper_id TEXT NOT NULL
                );
                """
            )
            connection.execute(
                "INSERT INTO identifier_assignment_projection VALUES(?,?,?)",
                ("arxiv", "2401.00001", "paper-1"),
            )
            connection.execute(
                "INSERT INTO paper_catalog_projection VALUES(?,?)",
                ("paper-1", "Test Paper"),
            )
            connection.execute(
                "INSERT INTO evidence_excerpt VALUES(?,?,?,?,?)",
                (
                    "excerpt-1",
                    "paper-1",
                    self.text,
                    self.digest,
                    json.dumps(
                        {
                            "source_kind": "official_arxiv_atom_summary",
                            "normalized_identifier": "2401.00001",
                            "title": "Test Paper",
                            "normalized_excerpt_sha256": self.digest,
                            "normalized_excerpt_bytes": len(
                                self.text.encode("utf-8")
                            ),
                            "source_path": "project_state/evidence/official.xml",
                            "source_file_sha256": "a" * 64,
                            "source_file_bytes": 100,
                            "normalization_contract": "atom-summary/v1",
                        }
                    ),
                ),
            )
            connection.execute(
                "INSERT INTO evidence_canonicalization_receipt VALUES(?,?,?)",
                ("P001", "P001", "paper-1"),
            )
            connection.commit()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": "qrh-evidence-chinese-presentation/v1",
            "generated_at": "2026-07-16T00:00:00+00:00",
            "entries": [
                {
                    "identifier_scheme": "arxiv",
                    "normalized_identifier": "2401.00001",
                    "title": "Test Paper",
                    "source_excerpt_sha256": self.digest,
                    "source_excerpt_bytes": len(self.text.encode("utf-8")),
                    "source_path": "project_state/evidence/official.xml",
                    "abstract_translation_zh": "这是官方摘要的中文参考译文。",
                    "synthesis_zh": "这是一段不替代来源事实的中文综述。",
                    "translation_status": "generated_reference_translation",
                    "summary_status": "generated_research_aid_not_source_fact",
                    "fact_boundary": GENERATED_FACT_BOUNDARY,
                }
            ],
            "excluded": [],
        }

    def write_overlay(self, payload: dict[str, object]) -> None:
        self.overlay.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    def configure_crossref_projection(self) -> dict[str, object]:
        source_path = (
            "project_state/workers/crossref_identity_review/direct_doi_cache/"
            "P001_exact.body"
        )
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                "UPDATE identifier_assignment_projection "
                "SET scheme=?,normalized_value=? WHERE paper_id=?",
                ("doi", "10.1000/test", "paper-1"),
            )
            locator = json.loads(
                connection.execute(
                    "SELECT locator_json FROM evidence_excerpt"
                ).fetchone()[0]
            )
            locator.update(
                {
                    "source_kind": "official_crossref_deposit_abstract",
                    "field": "crossref.message.abstract",
                    "identifier_scheme": "doi",
                    "normalized_identifier": "10.1000/test",
                    "title": "Test Paper",
                    "source_path": source_path,
                    "fact_boundary": (
                        "publisher_deposited_source_claim_not_fulltext_review"
                    ),
                }
            )
            connection.execute(
                "UPDATE evidence_excerpt SET locator_json=?",
                (json.dumps(locator),),
            )
            connection.commit()
        return locator

    def test_exact_overlay_is_bound_to_database_inventory(self) -> None:
        self.write_overlay(self.payload())
        contract = build_chinese_overlay_contract(self.database, self.overlay)
        self.assertEqual(contract["entries"], 1)
        self.assertEqual(contract["database_official_abstracts"], 1)
        self.assertEqual(contract["excluded"], 0)

    def test_crossref_source_claim_uses_its_narrower_fact_boundary(self) -> None:
        source_path = (
            "project_state/workers/crossref_identity_review/direct_doi_cache/"
            "P001_exact.body"
        )
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                "UPDATE identifier_assignment_projection "
                "SET scheme=?,normalized_value=? WHERE paper_id=?",
                ("doi", "10.1000/test", "paper-1"),
            )
            locator = json.loads(
                connection.execute(
                    "SELECT locator_json FROM evidence_excerpt"
                ).fetchone()[0]
            )
            locator["source_path"] = source_path
            locator["field"] = "crossref.message.abstract"
            connection.execute(
                "UPDATE evidence_excerpt SET locator_json=?",
                (json.dumps(locator),),
            )
            connection.commit()

        payload = self.payload()
        entry = payload["entries"][0]
        entry["identifier_scheme"] = "doi"
        entry["normalized_identifier"] = "10.1000/test"
        entry["source_path"] = source_path
        entry["fact_boundary"] = CROSSREF_GENERATED_FACT_BOUNDARY
        self.write_overlay(payload)
        contract = build_chinese_overlay_contract(self.database, self.overlay)
        self.assertEqual(contract["entries"], 1)

        entry["fact_boundary"] = GENERATED_FACT_BOUNDARY
        self.write_overlay(payload)
        with self.assertRaisesRegex(ChineseOverlayContractError, "事实边界"):
            build_chinese_overlay_contract(self.database, self.overlay)

    def test_reviewed_arxiv_projection_is_rebuilt_from_candidate_database(self) -> None:
        projection = [
            {
                "source_candidate_id": "P001",
                "paper_source_candidate_id": "P001",
                "normalized_identifier": "2401.00001",
                "title": "Test Paper",
                "excerpt_sha256": self.digest,
                "excerpt_bytes": len(self.text.encode("utf-8")),
                "source_path": "project_state/evidence/official.xml",
                "source_file_sha256": "a" * 64,
                "source_file_bytes": 100,
            }
        ]
        expected_hash = hashlib.sha256(
            canonical_json(projection).encode("utf-8")
        ).hexdigest()
        contract = build_reviewed_arxiv_official_abstract_projection_contract(
            self.database
        )
        self.assertEqual(contract["rows"], 1)
        self.assertEqual(contract["projection_sha256"], expected_hash)

    def test_reviewed_arxiv_projection_locator_tampering_fails_closed(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection:
            locator = json.loads(
                connection.execute(
                    "SELECT locator_json FROM evidence_excerpt"
                ).fetchone()[0]
            )
            locator["source_file_sha256"] = "invalid"
            connection.execute(
                "UPDATE evidence_excerpt SET locator_json=?",
                (json.dumps(locator),),
            )
            connection.commit()
        with self.assertRaises(ChineseOverlayContractError):
            build_reviewed_arxiv_official_abstract_projection_contract(
                self.database
            )

    def test_reviewed_crossref_projection_is_rebuilt_from_candidate_database(
        self,
    ) -> None:
        locator = self.configure_crossref_projection()
        projection = [
            {
                "source_candidate_id": "P001",
                "paper_source_candidate_id": "P001",
                "normalized_identifier": "10.1000/test",
                "title": "Test Paper",
                "excerpt_sha256": self.digest,
                "excerpt_bytes": len(self.text.encode("utf-8")),
                "source_path": locator["source_path"],
                "source_file_sha256": "a" * 64,
                "source_file_bytes": 100,
            }
        ]
        expected_hash = hashlib.sha256(
            canonical_json(projection).encode("utf-8")
        ).hexdigest()
        contract = build_reviewed_crossref_official_abstract_projection_contract(
            self.database
        )
        self.assertEqual(contract["rows"], 1)
        self.assertEqual(contract["projection_sha256"], expected_hash)

    def test_reviewed_crossref_projection_locator_tampering_fails_closed(
        self,
    ) -> None:
        locator = self.configure_crossref_projection()
        locator["fact_boundary"] = "fulltext_reviewed"
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                "UPDATE evidence_excerpt SET locator_json=?",
                (json.dumps(locator),),
            )
            connection.commit()
        with self.assertRaises(ChineseOverlayContractError):
            build_reviewed_crossref_official_abstract_projection_contract(
                self.database
            )

    def test_missing_overlay_fails_closed(self) -> None:
        with self.assertRaisesRegex(ChineseOverlayContractError, "文件不存在"):
            build_chinese_overlay_contract(self.database, self.overlay)

    def test_hash_path_identity_and_coverage_tampering_fail_closed(self) -> None:
        for case in ("hash", "path", "identity", "duplicate", "missing"):
            with self.subTest(case=case):
                payload = self.payload()
                entry = payload["entries"][0]
                if case == "hash":
                    entry["source_excerpt_sha256"] = "0" * 64
                elif case == "path":
                    entry["source_path"] = "evidence/wrong.xml"
                elif case == "identity":
                    entry["normalized_identifier"] = "2401.99999"
                elif case == "duplicate":
                    payload["entries"].append(dict(entry))
                else:
                    payload["entries"] = []
                self.write_overlay(payload)
                with self.assertRaises(ChineseOverlayContractError):
                    build_chinese_overlay_contract(self.database, self.overlay)

    def test_excluded_items_and_unmarked_generated_text_fail_closed(self) -> None:
        for case in (
            "excluded",
            "translation_status",
            "summary_status",
            "fact_boundary",
        ):
            with self.subTest(case=case):
                payload = self.payload()
                if case == "excluded":
                    payload["excluded"] = ["excerpt-1"]
                elif case == "translation_status":
                    payload["entries"][0]["translation_status"] = "source_fact"
                elif case == "summary_status":
                    payload["entries"][0]["summary_status"] = "source_fact"
                else:
                    payload["entries"][0]["fact_boundary"] = (
                        "中文译文与综述已经成为来源事实。"
                    )
                self.write_overlay(payload)
                with self.assertRaises(ChineseOverlayContractError):
                    build_chinese_overlay_contract(self.database, self.overlay)


if __name__ == "__main__":
    unittest.main()
