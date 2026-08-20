from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from quant_hub.evidence.contracts import CitationOccurrenceInput
from quant_hub.evidence.database import evidence_connection
from quant_hub.evidence.repository import EvidenceRepository
from quant_hub.evidence.reviewed_material_importer import (
    ReviewedMaterialImportError,
    ReviewedMaterialImporter,
    ReviewedMaterialSources,
)
from quant_hub.evidence.service import EvidenceQueryService
from tests.helpers import SettingsTestCase, latest_activated_reviewed_delivery


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
CROSSREF_ROOT = WORKSPACE_ROOT / "project_state" / "workers" / "crossref_identity_review"
RIGHTS_MANIFEST = CROSSREF_ROOT / "rights_resource_offers.jsonl"
ARXIV_ROOT = WORKSPACE_ROOT / "project_state" / "workers" / "arxiv_expansion_materials"
IDENTITY_VERDICTS = (
    WORKSPACE_ROOT
    / "project_state"
    / "workers"
    / "independent_identity_verifier"
    / "item_verdicts.jsonl"
)
U055_FULLTEXT = (
    WORKSPACE_ROOT
    / "project_state"
    / "workers"
    / "u055_open_pdf_acquisition"
    / "manifest.json"
)
ARXIV_VERDICT_V1 = (
    WORKSPACE_ROOT
    / "project_state"
    / "workers"
    / "independent_arxiv_verifier"
    / "verdict.json"
)
ARXIV_VERDICT_V2 = ARXIV_VERDICT_V1.with_name("verdict_v2.json")
ARXIV_VERDICT_V4 = (
    WORKSPACE_ROOT
    / "project_state"
    / "workers"
    / "independent_arxiv_verifier_v2"
    / "verdict_v4.json"
)
OPEN_PDF_SUMMARY = (
    WORKSPACE_ROOT
    / "project_state"
    / "workers"
    / "evidence_open_pdf_review_20260716"
    / "summary.json"
)
HISTORICAL_V4_REPLAY_DATABASE = (
    WORKSPACE_ROOT
    / "quant_hub"
    / "var"
    / "delivery-final-reviewed-v5-20260716-v4"
    / "db"
    / "research_papers.sqlite3"
)


class ReviewedMaterialImporterIntegrationTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.repository = EvidenceRepository(self.settings)
        self.repository.initialize()
        self.sources = ReviewedMaterialSources(
            crossref_decisions=(CROSSREF_ROOT / "accepted_decisions.jsonl",),
            crossref_rights_manifest=CROSSREF_ROOT / "rights_resource_offers.jsonl",
            arxiv_materials_manifest=ARXIV_ROOT / "manifest.json",
            arxiv_reading_records=ARXIV_ROOT / "reading_records.json",
        )
        self.total_sources = ReviewedMaterialSources(
            crossref_decisions=(CROSSREF_ROOT / "accepted_decisions.jsonl",),
            crossref_rights_manifest=CROSSREF_ROOT / "rights_resource_offers.jsonl",
            arxiv_materials_manifest=ARXIV_ROOT / "manifest.json",
            arxiv_reading_records=ARXIV_ROOT / "reading_records.json",
            crossref_identity_verdicts=IDENTITY_VERDICTS,
            crossref_fulltext_manifest=U055_FULLTEXT,
            arxiv_total_delivery_manifest=ARXIV_ROOT / "total_delivery_manifest.json",
            arxiv_resolution_seed=ARXIV_ROOT / "total_resolution_seed.json",
            arxiv_method_origin_inputs=(
                ARXIV_ROOT / "identity_review" / "method_origin_candidate_inputs.json"
            ),
            arxiv_independent_verdict=ARXIV_VERDICT_V4,
        )

    def _source(self, source_id: str, *, method: bool = False) -> str:
        clue_id, _ = self.repository.put_clue(
            source_candidate_id=source_id,
            entity_kind=("method_or_resource_family" if method else "paper_or_scholarly_work"),
            domain_category="reviewed-import-fixture",
            raw_claim={"source_candidate_id": source_id},
            provenance_urn=f"qrh:test:reviewed-import:clue:{source_id}",
            resolution_status="rejected_non_paper" if method else "resolution_pending",
        )
        candidate_id, _ = self.repository.put_candidate(
            source_candidate_id=source_id,
            candidate_kind="non_paper_resource" if method else "paper",
            title_claim=f"Reviewed material source {source_id}",
            publication_year=2020,
            resolution_status="rejected_non_paper" if method else "proposed",
            provenance_urn=f"qrh:test:reviewed-import:candidate:{source_id}",
        )
        self.repository.link_clue_candidate(
            clue_id,
            candidate_id,
            link_kind="local_claim",
            evidence={"source_candidate_id": source_id},
        )
        marker = f"[{source_id}]"
        source_bytes = marker.encode("utf-8")
        digest = hashlib.sha256(source_bytes).hexdigest()
        occurrence = CitationOccurrenceInput(
            legacy_occurrence_id=f"reviewed-import-ledger-{source_id}",
            clue_id=clue_id,
            research_urn="qrh:archive:research:Q2_IMPORT_FIXTURE",
            archive_release_urn="qrh:archive-release:reviewed-import-fixture",
            document_version_urn=f"qrh:archive:document:{source_id}:sha256:{digest}",
            source_object_urn=f"qrh:archive:object:sha256:{digest}",
            document_sha256=digest,
            source_path=f"Q2/{source_id}.md",
            canonical_path=f"Q2/{source_id}.md",
            locator_claim="line:1",
            line_start=1,
            line_end=1,
            byte_start=0,
            byte_end=len(source_bytes),
            raw_marker_text=marker,
            context_text=marker,
            occurrence_kind="method_or_resource_name" if method else "formal_reference",
            resolution_status="rejected_non_paper" if method else "unresolved",
            status_reason="isolated reviewed-material integration fixture",
            raw_occurrence_type="fixture",
            candidate_link_method="fixture",
            evidence_strength="exact_fixture",
        )
        self.repository.add_citation(occurrence, source_bytes)
        self.repository.bind_citation(
            occurrence.legacy_occurrence_id,
            paper_id=None,
            binding_status="rejected_non_paper" if method else "unresolved",
            rationale="pending reviewed-material import",
            provenance_urn=f"qrh:test:reviewed-import:binding:{source_id}",
        )
        return candidate_id

    def _apply(
        self,
        include: frozenset[str],
        *,
        sources: ReviewedMaterialSources | None = None,
    ):
        return ReviewedMaterialImporter(self.settings).apply(
            sources or self.sources,
            review_id="reviewed-material-import-integration-v1",
            reviewed_by="Synthetic independent reviewer",
            reviewed_at="2026-07-15T00:00:00Z",
            provenance_urn="qrh:test:reviewed-material-import",
            include_source_candidates=include,
        )

    def test_plan_is_database_free_and_fail_closed_for_version_family(self) -> None:
        untouched_database = self.root / "plan-only.sqlite3"
        self.assertFalse(untouched_database.exists())
        plan = ReviewedMaterialImporter.static_plan(self.sources)
        self.assertFalse(plan["database_opened"])
        self.assertEqual(32, plan["crossref_reviewed"])
        self.assertEqual(31, plan["crossref_eligible"])
        self.assertIn("P095", plan["crossref_excluded"])
        self.assertEqual(["U055"], plan["crossref_rights_ready_without_pdf_bytes"])
        self.assertEqual(4, plan["arxiv_formal_citations"])
        self.assertEqual(7, plan["arxiv_associated_method_origins"])
        self.assertEqual(11, plan["arxiv_official_abstracts_verified"])
        self.assertEqual([], plan["arxiv_metadata_only"])
        self.assertEqual(["P137", "P143"], plan["arxiv_license_blocked"])
        self.assertEqual(9, len(plan["arxiv_storage_approved"]))
        self.assertFalse(untouched_database.exists())

    def test_total_delivery_plan_consumes_29_seed_and_independent_doi_overlay(self) -> None:
        plan = ReviewedMaterialImporter.static_plan(self.total_sources)
        self.assertEqual(31, plan["crossref_eligible"])
        self.assertIn("P095", plan["crossref_excluded"])
        self.assertEqual([], plan["crossref_rights_ready_without_pdf_bytes"])
        self.assertEqual(["U055"], plan["crossref_fulltext_failed_closed"])
        self.assertEqual(
            ["P107", "P126", "P183", "U038", "U054", "U055"],
            plan["crossref_tier_reconciled"],
        )
        self.assertEqual(["P033"], plan["crossref_official_metadata_conflicts"])
        self.assertEqual(6, plan["crossref_official_abstracts_verified"])
        self.assertEqual(6, len(plan["crossref_official_abstract_projection"]))
        self.assertEqual(
            {"P004", "P033", "P094", "P170", "P172", "P183"},
            {
                str(row["source_candidate_id"])
                for row in plan["crossref_official_abstract_projection"]
            },
        )
        self.assertTrue(
            all(
                str(row["source_path"]).startswith("project_state/")
                and str(row["source_path"]).endswith(".body")
                for row in plan["crossref_official_abstract_projection"]
            )
        )

    @unittest.skipUnless(
        HISTORICAL_V4_REPLAY_DATABASE.is_file(),
        "retired frozen V4 replay fixture is not retained in the compact workspace",
    )
    def test_reviewed_open_pdf_post_identity_import_is_idempotent_and_sealed(self) -> None:
        candidate = latest_activated_reviewed_delivery(WORKSPACE_ROOT)
        self.settings.research_papers_database_path.unlink()
        shutil.copy2(
            candidate / "db" / "research_papers.sqlite3",
            self.settings.research_papers_database_path,
        )
        shutil.rmtree(self.settings.research_papers_root, ignore_errors=True)
        shutil.copytree(candidate / "research_papers", self.settings.research_papers_root)
        sources = replace(
            self.total_sources, open_pdf_review_summary=OPEN_PDF_SUMMARY
        )
        plan = ReviewedMaterialImporter.static_plan(sources)
        importer = ReviewedMaterialImporter(self.settings)
        first = importer._import_reviewed_open_pdfs(
            sources=sources,
            plan=plan,
            provenance_urn="qrh:test:reviewed-open-pdf",
        )
        snapshot = EvidenceRepository(self.settings).snapshot_hash()
        second = importer._import_reviewed_open_pdfs(
            sources=sources,
            plan=plan,
            provenance_urn="qrh:test:reviewed-open-pdf",
        )
        self.assertEqual(first, second)
        self.assertEqual(snapshot, EvidenceRepository(self.settings).snapshot_hash())
        self.assertEqual(4, len(first))
        with evidence_connection(self.settings) as connection:
            self.assertEqual(
                48, connection.execute("SELECT count(*) FROM paper_resource").fetchone()[0]
            )
            self.assertEqual(
                4,
                connection.execute(
                    """
                    SELECT count(*) FROM paper_resource AS resource
                    JOIN fetch_attempt AS fetch USING(fetch_attempt_id)
                    WHERE fetch.source_request_id LIKE 'reviewed-open-pdf:%'
                      AND resource.verification_status='verified'
                      AND resource.rights_status='verified_open_license'
                    """
                ).fetchone()[0],
            )
        for imported in first:
            response = importer.resources.resource_response(imported.resource_id)
            self.assertTrue(response.payload.startswith(b"%PDF-"))
            self.assertEqual(
                imported.content_sha256,
                hashlib.sha256(response.payload).hexdigest(),
            )
        self.assertEqual(29, plan["arxiv_reviewed"])
        self.assertEqual(29, plan["arxiv_official_abstracts_verified"])
        self.assertEqual(29, len(plan["arxiv_official_abstract_projection"]))
        self.assertEqual(22, plan["arxiv_formal_citations"])
        self.assertEqual(7, plan["arxiv_associated_method_origins"])
        self.assertEqual(29, plan["arxiv_resolution_seed_rows"])
        self.assertEqual(135, plan["arxiv_hash_anchored_reading_locators"])
        self.assertEqual([], plan["arxiv_metadata_only"])
        self.assertEqual(
            ["P034", "P137", "P143"], plan["arxiv_license_blocked"]
        )
        self.assertEqual(26, len(plan["arxiv_storage_approved"]))
        self.assertEqual(
            ["P004", "P126", "P169", "P170"],
            plan["arxiv_version_family_holds"],
        )
        abstract_by_source = {
            str(row["source_candidate_id"]): row
            for row in plan["arxiv_official_abstract_projection"]
        }
        self.assertEqual(
            "062c384a940b00416e76c513973d595aeb1fbc6e0e09a433c18fddc5bdf529eb",
            abstract_by_source["P034"]["excerpt_sha256"],
        )
        self.assertEqual(
            "afce853e6a154f62365b8f98b2db9bc3220267581faa5775ea50ca0ed97877a3",
            abstract_by_source["P137"]["excerpt_sha256"],
        )
        self.assertEqual(
            "1f9578c369ea2c63c7850df671ffdba3cd985053cad46ec70ebabe6a501e5ed5",
            abstract_by_source["P143"]["excerpt_sha256"],
        )
        self.assertTrue(
            all(
                str(row["source_path"]).startswith("project_state/")
                and str(row["source_path"]).endswith(".xml")
                for row in abstract_by_source.values()
            )
        )

    def test_atom_summary_normalization_mismatch_fails_before_database_work(self) -> None:
        snapshot = self.repository.snapshot_hash()
        with patch(
            "quant_hub.evidence.reviewed_material_importer.normalize_arxiv_atom_summary",
            return_value="tampered normalized summary",
        ), self.assertRaisesRegex(
            ReviewedMaterialImportError, "official Atom abstract evidence is invalid"
        ):
            ReviewedMaterialImporter.static_plan(self.total_sources)
        self.assertEqual(snapshot, self.repository.snapshot_hash())

    def test_total_delivery_requires_exact_v4_verdict_and_rejects_v1_v2_v3(self) -> None:
        with self.assertRaisesRegex(
            ReviewedMaterialImportError, "requires the exact independent V4 verdict"
        ):
            ReviewedMaterialImporter.static_plan(
                replace(self.total_sources, arxiv_independent_verdict=None)
            )
        for path in (ARXIV_VERDICT_V1, ARXIV_VERDICT_V2):
            with self.subTest(path=path.name), self.assertRaisesRegex(
                ReviewedMaterialImportError, "frozen V4 verdict path"
            ):
                ReviewedMaterialImporter.static_plan(
                    replace(self.total_sources, arxiv_independent_verdict=path)
                )
        synthetic_v3 = self.root / "verdict_v3.json"
        synthetic_v3.write_text(
            json.dumps(
                {
                    "schema_version": "qrh-independent-arxiv-verdict/v3",
                    "overall_status": "PASS",
                    "release_authorized": True,
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            ReviewedMaterialImportError, "frozen V4 verdict path"
        ):
            ReviewedMaterialImporter.static_plan(
                replace(self.total_sources, arxiv_independent_verdict=synthetic_v3)
            )

    def test_invalid_v4_gate_fails_before_database_or_runtime_mutation(self) -> None:
        parent = (
            WORKSPACE_ROOT
            / "project_state"
            / "workers"
            / "evidence_canonicalization_bridge"
        )
        with tempfile.TemporaryDirectory(prefix="invalid-gate-", dir=parent) as value:
            runtime = Path(value)
            settings = self.settings.default(project_root=WORKSPACE_ROOT, var_root=runtime)
            importer = ReviewedMaterialImporter(settings)
            self.assertEqual([], list(runtime.iterdir()))
            with self.assertRaisesRegex(
                ReviewedMaterialImportError, "frozen V4 verdict path"
            ):
                importer.apply(
                    replace(
                        self.total_sources,
                        arxiv_independent_verdict=ARXIV_VERDICT_V1,
                    ),
                    review_id="invalid-gate-must-not-write",
                    reviewed_by="Synthetic negative gate",
                    reviewed_at="2026-07-15T00:00:00Z",
                    provenance_urn="qrh:test:invalid-gate-must-not-write",
                )
            self.assertFalse(settings.research_papers_database_path.exists())
            self.assertEqual([], list(runtime.iterdir()))

    def test_default_cli_consumes_exact_v4_gate_without_opening_a_database(self) -> None:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(WORKSPACE_ROOT / "quant_hub" / "src")
        completed = subprocess.run(
            [sys.executable, "tools/import_reviewed_evidence_materials.py"],
            cwd=WORKSPACE_ROOT / "quant_hub",
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        plan = json.loads(completed.stdout)
        self.assertFalse(plan["database_opened"])
        self.assertEqual(31, plan["crossref_eligible"])
        self.assertEqual(29, plan["arxiv_reviewed"])
        self.assertEqual(135, plan["arxiv_hash_anchored_reading_locators"])

    def test_crossref_verdict_recomputed_hash_is_bound_to_frozen_response(self) -> None:
        rows = [
            json.loads(line)
            for line in IDENTITY_VERDICTS.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        rows[0]["official_exact_doi_evidence"]["recomputed_sha256"] = "0" * 64
        altered = self.root / "altered-crossref-verdicts.jsonl"
        altered.write_text(
            "\n".join(
                json.dumps(row, ensure_ascii=False, sort_keys=True) for row in rows
            )
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            ReviewedMaterialImportError, "not bound to all exact evidence"
        ):
            ReviewedMaterialImporter.static_plan(
                replace(self.total_sources, crossref_identity_verdicts=altered)
            )

    def test_crossref_pass_requires_consistent_consumption_and_tier_verdicts(self) -> None:
        original = [
            json.loads(line)
            for line in IDENTITY_VERDICTS.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        mutations = {
            "consumption": lambda row: row.__setitem__(
                "consumption_verdict_as_produced", "FAIL"
            ),
            "tier": lambda row: row["tier_review"].__setitem__("verdict", "FAIL"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                rows = json.loads(json.dumps(original))
                self.assertEqual("P003", rows[0]["candidate_id"])
                mutate(rows[0])
                altered = self.root / f"contradictory-crossref-{label}.jsonl"
                altered.write_text(
                    "\n".join(
                        json.dumps(row, ensure_ascii=False, sort_keys=True)
                        for row in rows
                    )
                    + "\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    ReviewedMaterialImportError,
                    "identity/tier/consumption verdicts are contradictory",
                ):
                    ReviewedMaterialImporter.static_plan(
                        replace(
                            self.total_sources,
                            crossref_identity_verdicts=altered,
                        )
                    )

    def test_p095_denial_requires_failed_tier_and_version_reviews(self) -> None:
        rows = [
            json.loads(line)
            for line in IDENTITY_VERDICTS.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        p095 = next(row for row in rows if row["candidate_id"] == "P095")
        p095["tier_review"]["verdict"] = "PASS"
        altered = self.root / "p095-contradictory-tier.jsonl"
        altered.write_text(
            "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            ReviewedMaterialImportError, "P095 version-family denial changed"
        ):
            ReviewedMaterialImporter.static_plan(
                replace(self.total_sources, crossref_identity_verdicts=altered)
            )

    def test_crossref_rights_cannot_upgrade_metadata_only_identity(self) -> None:
        rows = [
            json.loads(line)
            for line in RIGHTS_MANIFEST.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        p003 = next(row for row in rows if row["candidate_id"] == "P003")
        offer = p003["official_fulltext_offers"][0]
        p003["best_acquisition_status"] = "available_verified_open_pdf"
        p003["verified_open_pdf_offer_count"] = 1
        offer["acquisition_status"] = "available_verified_open_pdf"
        offer["declared_content_type"] = "application/pdf"
        offer["mime_verified_pdf"] = True
        offer["mime_probe"] = {
            "request_method": "HEAD",
            "http_status": 200,
            "content_type": "application/pdf",
        }
        altered = self.root / "rights-upgrade.jsonl"
        altered.write_text(
            "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            ReviewedMaterialImportError, "contradicts the independent verdict"
        ):
            ReviewedMaterialImporter.static_plan(
                replace(self.total_sources, crossref_rights_manifest=altered)
            )

    def test_crossref_rights_rows_are_a_complete_unique_closed_set(self) -> None:
        original = [
            json.loads(line)
            for line in RIGHTS_MANIFEST.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        cases = {
            "missing": original[1:],
            "duplicate": [*original, json.loads(json.dumps(original[0]))],
            "unknown": [
                *original,
                {**json.loads(json.dumps(original[0])), "candidate_id": "UNKNOWN"},
            ],
        }
        for label, rows in cases.items():
            with self.subTest(label=label):
                altered = self.root / f"rights-{label}.jsonl"
                altered.write_text(
                    "\n".join(json.dumps(row, ensure_ascii=False) for row in rows)
                    + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(ReviewedMaterialImportError):
                    ReviewedMaterialImporter.static_plan(
                        replace(self.total_sources, crossref_rights_manifest=altered)
                    )

    def test_u055_post_get_failed_closed_item_is_mandatory(self) -> None:
        payload = json.loads(U055_FULLTEXT.read_text(encoding="utf-8"))
        payload["items"] = []
        altered = self.root / "u055-empty.json"
        altered.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            ReviewedMaterialImportError, "exactly U055 failed closed after GET"
        ):
            ReviewedMaterialImporter.static_plan(
                replace(self.total_sources, crossref_fulltext_manifest=altered)
            )

    def test_total_delivery_rejects_stale_import_sequence_receipt(self) -> None:
        payload = json.loads(
            (ARXIV_ROOT / "total_delivery_manifest.json").read_text(encoding="utf-8")
        )
        for entries in payload["files"].values():
            for entry in entries:
                entry["path"] = str(WORKSPACE_ROOT / entry["path"])
        for step in payload["import_sequence"]:
            step["input"]["path"] = str(WORKSPACE_ROOT / step["input"]["path"])
        payload["import_sequence"][1]["input"]["sha256"] = "0" * 64
        manifest = self.root / "stale-total-delivery.json"
        manifest.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            ReviewedMaterialImportError, "import sequence step 2 is stale"
        ):
            ReviewedMaterialImporter.static_plan(
                replace(self.total_sources, arxiv_total_delivery_manifest=manifest)
            )

    def test_reading_and_material_rights_decisions_must_match(self) -> None:
        payload = json.loads(
            (ARXIV_ROOT / "reading_records.json").read_text(encoding="utf-8")
        )
        payload["items"][0]["rights_boundary"]["serving_decision"] = (
            "metadata_and_official_external_link_only"
        )
        readings = self.root / "rights-mismatch-readings.json"
        readings.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            ReviewedMaterialImportError, "reading/material rights boundaries disagree"
        ):
            ReviewedMaterialImporter.static_plan(
                replace(self.sources, arxiv_reading_records=readings)
            )

    def test_arxiv_rights_evidence_is_persisted_for_block_and_cc_by(self) -> None:
        self._source("P143", method=True)
        self._source("P145", method=True)
        result = self._apply(frozenset({"P143", "P145"}))
        statuses = {
            item.source_candidate_id: item.resource_status
            for item in result.arxiv_identities
        }
        self.assertEqual(
            "license_blocked_no_local_resource", statuses["P143"]
        )
        self.assertEqual("verified_local_resource", statuses["P145"])
        with evidence_connection(self.settings) as connection:
            rows = connection.execute(
                """
                SELECT decision,rights_status,evidence_json
                FROM evidence_rights_assessment
                WHERE authority_kind='human_review'
                ORDER BY decision,rights_assessment_id
                """
            ).fetchall()
        self.assertEqual(2, len(rows))
        evidence_by_decision = {
            str(row["decision"]): json.loads(str(row["evidence_json"]))
            for row in rows
        }
        blocked = evidence_by_decision["blocked"]
        self.assertTrue(blocked["embedded_pdf_rights_notices"])
        self.assertEqual(
            "blocked_from_managed_storage", blocked["acquisition_decision"]
        )
        self.assertEqual(
            "metadata_and_official_external_link_only",
            blocked["serving_decision"],
        )
        approved = evidence_by_decision["approved_for_local_storage"]
        self.assertEqual("CC BY 4.0", approved["license_class"])
        self.assertTrue(approved["license_evidence"])
        self.assertTrue(approved["attribution_requirements"])
        self.assertEqual(
            "local_resource_permitted_with_cc_by_attribution",
            approved["serving_decision"],
        )
        with evidence_connection(self.settings) as connection:
            evidence_rows = list(
                connection.execute(
                    """
                    SELECT receipt.source_candidate_id,receipt.resource_mode,
                           excerpt.resource_id AS excerpt_resource_id,
                           count(DISTINCT attachment.resource_attachment_id) AS attachments,
                           count(DISTINCT task.reading_task_id) AS reading_tasks
                    FROM evidence_canonicalization_receipt AS receipt
                    JOIN evidence_excerpt AS excerpt ON excerpt.paper_id=receipt.paper_id
                    LEFT JOIN evidence_canonical_resource_attachment AS attachment
                      ON attachment.canonicalization_receipt_id=
                         receipt.canonicalization_receipt_id
                    LEFT JOIN paper_reading_task AS task
                      ON task.paper_id=receipt.paper_id
                    WHERE receipt.source_candidate_id IN ('P143','P145')
                    GROUP BY receipt.source_candidate_id,receipt.resource_mode,
                             excerpt.resource_id
                    ORDER BY receipt.source_candidate_id
                    """
                )
            )
        self.assertEqual(2, len(evidence_rows))
        by_source = {str(row["source_candidate_id"]): row for row in evidence_rows}
        self.assertIsNone(by_source["P143"]["excerpt_resource_id"])
        self.assertEqual("metadata_only", by_source["P143"]["resource_mode"])
        self.assertEqual(0, by_source["P143"]["attachments"])
        self.assertEqual(0, by_source["P143"]["reading_tasks"])
        self.assertIsNone(by_source["P145"]["excerpt_resource_id"])
        self.assertEqual("verified_local_resource", by_source["P145"]["resource_mode"])
        self.assertEqual(1, by_source["P145"]["attachments"])
        self.assertEqual(1, by_source["P145"]["reading_tasks"])
        papers = EvidenceQueryService(self.settings).list_papers(limit=10)["papers"]
        details = {
            str(paper["title"]): EvidenceQueryService(self.settings).paper_detail(
                str(paper["paper_id"])
            )
            for paper in papers
        }
        blocked_detail = details[
            "TS2Vec: Towards Universal Representation of Time Series"
        ]
        self.assertEqual(1, len(blocked_detail["core_conclusions"]))
        self.assertEqual(
            "official_abstract",
            blocked_detail["core_conclusions"][0]["evidence_scope"],
        )
        self.assertEqual(
            "official_abstract_source_claim_not_fulltext_review",
            blocked_detail["fact_boundary"]["core_conclusions"],
        )

    def test_doi_overlay_and_u055_post_get_rights_conflict_are_replayed(self) -> None:
        self._source("P033")
        self._source("U055")
        include = frozenset({"P033", "U055"})
        first = self._apply(include, sources=self.total_sources)
        self.assertEqual(2, first.crossref_canonical_papers)
        statuses = {
            item.source_candidate_id: item.resource_status
            for item in first.crossref_identities
        }
        self.assertEqual(
            "fulltext_verified_but_license_conflict_blocked", statuses["U055"]
        )
        papers = EvidenceQueryService(self.settings).list_papers(limit=10)["papers"]
        by_title = {
            str(paper["title"]): EvidenceQueryService(self.settings).paper_detail(
                str(paper["paper_id"])
            )
            for paper in papers
        }
        p033 = by_title["Long Short-Term Memory"]
        self.assertEqual("Neural Computation", p033["venue"]["value"])
        self.assertEqual("9", p033["venue"]["volume"])
        self.assertEqual("8", p033["venue"]["issue"])
        self.assertEqual("1735-1780", p033["venue"]["pages"])
        boundary = json.loads(p033["metadata_reviews"][0]["text"])
        self.assertIn(
            "volume 9, number 1",
            boundary["independent_identity_verifier"]["notes"][0],
        )
        self.assertEqual(
            "8", boundary["official_bibliographic_display"]["issue"]
        )
        self.assertEqual(1, len(p033["abstract_excerpts"]))
        self.assertIn(
            "Learning to store information over extended time intervals",
            p033["abstract_excerpts"][0]["text"],
        )
        self.assertEqual(
            "crossref.message.abstract",
            p033["abstract_excerpts"][0]["locator"]["field"],
        )
        self.assertEqual(1, len(p033["core_conclusions"]))
        self.assertEqual(
            "official_abstract", p033["core_conclusions"][0]["evidence_scope"]
        )
        self.assertEqual(
            "official_abstract_source_claim_not_fulltext_review",
            p033["fact_boundary"]["core_conclusions"],
        )
        u055 = by_title["Robust Large Margin Deep Neural Networks"]
        self.assertEqual([], u055["local_resources"])
        self.assertEqual([], u055["core_conclusions"])
        with evidence_connection(self.settings) as connection:
            self.assertEqual(
                ("blocked",),
                tuple(
                    connection.execute(
                        """
                        SELECT state.state FROM evidence_acquisition_state AS state
                        JOIN evidence_acquisition_case AS acquisition USING(acquisition_case_id)
                        JOIN evidence_resource_offer AS offer USING(resource_offer_id)
                        WHERE offer.provider='crossref'
                        """
                    ).fetchone()
                ),
            )
            self.assertEqual(
                ("license_blocked",),
                tuple(
                    connection.execute(
                        "SELECT result_status FROM fetch_attempt"
                    ).fetchone()
                ),
            )
            self.assertEqual(
                0, connection.execute("SELECT count(*) FROM paper_resource").fetchone()[0]
            )
        snapshot = self.repository.snapshot_hash()
        second = self._apply(include, sources=self.total_sources)
        self.assertEqual(first.as_dict(), second.as_dict())
        self.assertEqual(snapshot, self.repository.snapshot_hash())

    def test_real_crossref_and_formal_arxiv_materials_replay_end_to_end(self) -> None:
        self._source("U055")
        self._source("P012")
        include = frozenset({"U055", "P012"})
        first = self._apply(include)
        self.assertEqual(1, first.crossref_canonical_papers)
        self.assertEqual(1, first.arxiv_canonical_papers)
        self.assertEqual("rights_approved_fetch_not_performed", first.crossref_identities[0].resource_status)
        self.assertIsNone(first.crossref_identities[0].resource_id)
        self.assertEqual("verified_local_resource", first.arxiv_identities[0].resource_status)
        self.assertIsNotNone(first.arxiv_identities[0].resource_id)

        service = EvidenceQueryService(self.settings)
        papers = service.list_papers(limit=20)
        self.assertEqual(2, papers["total"])
        self.assertEqual(2, papers["coverage"]["resolved_citations"])
        self.assertEqual(1, papers["coverage"]["verified_local_resources"])
        by_title = {
            str(paper["title"]): service.paper_detail(str(paper["paper_id"]))
            for paper in papers["papers"]
        }
        u055 = by_title["Robust Large Margin Deep Neural Networks"]
        self.assertEqual([], u055["local_resources"])
        self.assertEqual([], u055["core_conclusions"])
        self.assertEqual("crossref", u055["category_evidence"]["source_system"])
        self.assertEqual("机器学习", u055["category_assignments"][0]["display_name"])
        p012 = by_title[
            "Sharpness-Aware Minimization for Efficiently Improving Generalization"
        ]
        self.assertEqual(1, len(p012["local_resources"]))
        self.assertTrue(p012["core_conclusions"])
        self.assertEqual("arxiv", p012["category_evidence"]["source_system"])
        self.assertEqual("cs.LG", p012["category_evidence"]["primary_source_category"])
        self.assertEqual("机器学习", p012["category_assignments"][0]["display_name"])

        with evidence_connection(self.settings) as connection:
            u055_state = connection.execute(
                """
                SELECT state.state
                FROM evidence_acquisition_state AS state
                JOIN evidence_acquisition_case AS acquisition USING(acquisition_case_id)
                JOIN evidence_resource_offer AS offer USING(resource_offer_id)
                WHERE offer.provider='crossref'
                """
            ).fetchone()
            self.assertEqual("ready", u055_state[0])
            self.assertEqual(
                0,
                connection.execute(
                    """
                    SELECT count(*) FROM paper_resource AS resource
                    JOIN fetch_attempt AS fetch USING(fetch_attempt_id)
                    WHERE fetch.candidate_id=(
                        SELECT candidate.candidate_id FROM paper_candidate AS candidate
                        JOIN paper_clue_candidate AS link USING(candidate_id)
                        JOIN paper_clue AS clue USING(clue_id)
                        WHERE clue.source_candidate_id='U055'
                    )
                    """
                ).fetchone()[0],
            )

        snapshot = self.repository.snapshot_hash()
        second = self._apply(include)
        self.assertEqual(snapshot, self.repository.snapshot_hash())
        self.assertEqual(first.as_dict(), second.as_dict())

    def test_real_method_origin_creates_distinct_paper_and_preserves_rejected_clue(self) -> None:
        self._source("P135", method=True)
        result = self._apply(frozenset({"P135"}))
        self.assertEqual(1, result.method_origin_derivations)
        self.assertEqual(1, result.arxiv_canonical_papers)
        coverage = EvidenceQueryService(self.settings).list_papers()["coverage"]
        self.assertEqual(0, coverage["resolved_citations"])
        self.assertEqual(1, coverage["associated_method_origins"])
        self.assertEqual(1, coverage["associated_method_origin_ledger_occurrences"])
        with evidence_connection(self.settings) as connection:
            original = connection.execute(
                """
                SELECT clue.resolution_status,candidate.resolution_status
                FROM paper_clue AS clue
                JOIN paper_clue_candidate AS link USING(clue_id)
                JOIN paper_candidate AS candidate USING(candidate_id)
                WHERE clue.source_candidate_id='P135'
                """
            ).fetchone()
            self.assertEqual(("rejected_non_paper", "rejected_non_paper"), tuple(original))
            derived = connection.execute(
                """
                SELECT original_source_candidate_id,derived_source_candidate_id
                FROM evidence_method_origin_candidate_derivation
                """
            ).fetchone()
            self.assertEqual("P135", derived[0])
            self.assertNotEqual(derived[0], derived[1])
            self.assertEqual(
                0, connection.execute("SELECT count(*) FROM research_paper_relation").fetchone()[0]
            )


if __name__ == "__main__":
    unittest.main()
