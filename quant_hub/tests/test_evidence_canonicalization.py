from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

from flask import Blueprint, Flask

from quant_hub.evidence.canonicalization import (
    CanonicalizationConflict,
    CanonicalizationEligibilityError,
    MethodOriginCandidateInput,
    ReviewedAuthor,
    ReviewedCategoryAssertion,
    ReviewedCanonicalizationItem,
    ReviewedCanonicalizationManifest,
    ReviewedConclusion,
    ReviewedEvidenceCanonicalizationService,
    ReviewedExternalLink,
    ReviewedExcerpt,
    ReviewedFulltextLocator,
    ReviewedInstitutionResolution,
    ReviewedMetadata,
    ReviewedReadingConclusion,
    ReviewedReadingResult,
    ReviewedResource,
    ReviewedSourceCategory,
)
from quant_hub.evidence.canonicalization_builders import (
    build_arxiv_reviewed_manifest,
    build_crossref_reviewed_manifest,
    method_origin_inputs_from_arxiv_readings,
)
from quant_hub.evidence.contracts import CitationOccurrenceInput, FetchAttemptInput
from quant_hub.evidence.database import evidence_connection
from quant_hub.evidence.expansion import EvidenceExpansionRepository, EvidenceExpansionService
from quant_hub.evidence.providers import (
    ArxivAdapter,
    ConservativeRightsPolicy,
    ProviderHttpResponse,
    ResolutionQuery,
    RightsAssessmentProposal,
    StrongIdentifierQuery,
    CrossrefAdapter,
)
from quant_hub.evidence.reading import PaperReadingService
from quant_hub.evidence.releases import EvidenceReleaseService
from quant_hub.evidence.repository import EvidenceRepository
from quant_hub.evidence.resources import EvidenceResourceStore
from quant_hub.evidence.service import EvidenceQueryService
from quant_hub.evidence.web import create_evidence_blueprint
from tests.helpers import SettingsTestCase


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "evidence" / "providers"


class ReviewedEvidenceCanonicalizationTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.repository = EvidenceRepository(self.settings)
        self.repository.initialize()
        self.expansion = EvidenceExpansionRepository(self.settings)
        self.expansion_service = EvidenceExpansionService(self.settings)
        self.canonicalization = ReviewedEvidenceCanonicalizationService(self.settings)

    def _source(
        self,
        source_id: str,
        *,
        method: bool = False,
        with_ledger: bool = True,
    ) -> tuple[str, str, str | None]:
        status = "rejected_non_paper" if method else "resolution_pending"
        candidate_status = "rejected_non_paper" if method else "proposed"
        clue_id, _ = self.repository.put_clue(
            source_candidate_id=source_id,
            entity_kind="method_or_resource_family" if method else "paper_or_scholarly_work",
            domain_category="ML",
            raw_claim={"label": source_id},
            provenance_urn=f"qrh:test:source:{source_id}",
            resolution_status=status,
        )
        candidate_id, _ = self.repository.put_candidate(
            source_candidate_id=source_id,
            candidate_kind="non_paper_resource" if method else "paper",
            title_claim=f"Synthetic {source_id}",
            publication_year=2020,
            resolution_status=candidate_status,
            provenance_urn=f"qrh:test:candidate:{source_id}",
        )
        self.repository.link_clue_candidate(
            clue_id,
            candidate_id,
            link_kind="local_claim",
            evidence={"source_candidate_id": source_id},
        )
        if not with_ledger:
            return clue_id, candidate_id, None
        marker = f"[{source_id}]"
        source_bytes = marker.encode("utf-8")
        digest = hashlib.sha256(source_bytes).hexdigest()
        occurrence = CitationOccurrenceInput(
            legacy_occurrence_id=f"ledger-{source_id}",
            clue_id=clue_id,
            research_urn="qrh:research:Q2",
            archive_release_urn="qrh:archive-release:test",
            document_version_urn=f"qrh:document:{source_id}:sha256:{digest}",
            source_object_urn=f"qrh:object:sha256:{digest}",
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
            status_reason="synthetic reviewed fixture",
            raw_occurrence_type="fixture",
            candidate_link_method="fixture",
            evidence_strength="exact_fixture",
        )
        self.repository.add_citation(occurrence, source_bytes)
        self.repository.bind_citation(
            occurrence.legacy_occurrence_id,
            paper_id=None,
            binding_status="rejected_non_paper" if method else "unresolved",
            rationale="synthetic pending disposition",
            provenance_urn=f"qrh:test:pending-binding:{source_id}",
        )
        return clue_id, candidate_id, occurrence.legacy_occurrence_id

    @staticmethod
    def _provider_response(request) -> ProviderHttpResponse:
        return ProviderHttpResponse(
            request_url=request.url,
            final_url=request.url,
            status_code=200,
            headers={"Content-Type": "application/atom+xml"},
            body=(FIXTURES / "arxiv_2010.01412_atom.xml").read_bytes(),
        )

    def _verified_identity(self, candidate_id: str, label: str) -> tuple[str, str, str]:
        query = ResolutionQuery(
            identifiers=(
                StrongIdentifierQuery(
                    scheme="arxiv",
                    raw_value="2010.01412",
                    source_provenance_urn=f"qrh:test:identifier:{label}",
                ),
            )
        )
        adapter = ArxivAdapter()
        opened, requests = self.expansion_service.enqueue_and_plan(
            candidate_id,
            query,
            (adapter,),
            provenance_urn=f"qrh:test:resolution:{label}",
            idempotency_key=f"open:{label}",
        )
        request = adapter.plan(query)[0]
        ingested = self.expansion.ingest_provider_response(
            requests[0].provider_request_id,
            self._provider_response(request),
            adapter,
            attempt_number=1,
            idempotency_key=f"provider:{label}",
            provenance_urn=f"qrh:test:provider:{label}",
        )
        reviewed, _ = self.expansion.finalize_provider_cycle(
            opened.resolution_case_id,
            expected_revision=opened.state.revision,
            idempotency_key=f"finalize:{label}",
        )
        decision = self.expansion.record_identity_decision(
            opened.resolution_case_id,
            expected_revision=reviewed.revision,
            decision_kind="accept_verified_identifier",
            provider_observation_id=ingested.observation_ids[0],
            identifier_scheme="arxiv",
            normalized_identifier="2010.01412",
            authority_kind="deterministic_strong_identifier_policy",
            rationale="Exact official arXiv identifier fixture was explicitly reviewed.",
            evidence_refs=list(ingested.observation_ids),
            idempotency_key=f"accept:{label}",
            provenance_urn=f"qrh:test:decision:{label}",
        )
        return opened.resolution_case_id, decision.identity_decision_id, ingested.resource_offer_ids[0]

    def _verified_crossref_identity(self, candidate_id: str, label: str) -> tuple[str, str]:
        query = ResolutionQuery(title="Deterministic Evidence Resolver Contract Fixture")
        adapter = CrossrefAdapter()
        opened, requests = self.expansion_service.enqueue_and_plan(
            candidate_id,
            query,
            (adapter,),
            provenance_urn=f"qrh:test:crossref-resolution:{label}",
            idempotency_key=f"crossref-open:{label}",
        )
        request = adapter.plan(query)[0]
        ingested = self.expansion.ingest_provider_response(
            requests[0].provider_request_id,
            ProviderHttpResponse(
                request_url=request.url,
                final_url=request.url,
                status_code=200,
                headers={"Content-Type": "application/json"},
                body=(FIXTURES / "crossref_title_search.json").read_bytes(),
            ),
            adapter,
            attempt_number=1,
            idempotency_key=f"crossref-provider:{label}",
            provenance_urn=f"qrh:test:crossref-provider:{label}",
        )
        reviewed, _ = self.expansion.finalize_provider_cycle(
            opened.resolution_case_id,
            expected_revision=opened.state.revision,
            idempotency_key=f"crossref-finalize:{label}",
        )
        decision = self.expansion.record_identity_decision(
            opened.resolution_case_id,
            expected_revision=reviewed.revision,
            decision_kind="accept_verified_identifier",
            provider_observation_id=ingested.observation_ids[0],
            identifier_scheme="doi",
            normalized_identifier="10.5555/qrh.fixture.1",
            authority_kind="human_review",
            rationale="Human review reconciled the synthetic title-search fixture.",
            evidence_refs=list(ingested.observation_ids),
            idempotency_key=f"crossref-accept:{label}",
            provenance_urn=f"qrh:test:crossref-decision:{label}",
        )
        return opened.resolution_case_id, decision.identity_decision_id

    def _acquire(self, candidate_id: str, case_id: str, offer_id: str, label: str) -> tuple[str, str]:
        automatic = self.expansion.assess_offer(
            offer_id,
            ConservativeRightsPolicy(),
            idempotency_key=f"rights-auto:{label}",
            provenance_urn=f"qrh:test:rights-auto:{label}",
        )
        reviewed = self.expansion.record_rights_assessment(
            offer_id,
            RightsAssessmentProposal(
                decision="approved_for_local_storage",
                rights_status="repository_distribution_only",
                authority_kind="human_review",
                policy_version="qrh-synthetic-rights/v1",
                legal_basis="Official repository distribution approved for isolated fixture storage.",
                evidence={"scope": "synthetic_test"},
            ),
            idempotency_key=f"rights-reviewed:{label}",
            provenance_urn=f"qrh:test:rights-reviewed:{label}",
            supersedes_assessment_id=automatic.rights_assessment_id,
        )
        acquisition = self.expansion.open_acquisition_case(
            offer_id,
            reviewed.rights_assessment_id,
            provenance_urn=f"qrh:test:acquisition:{label}",
        )
        fetching, _ = self.expansion.begin_acquisition(
            acquisition.acquisition_case_id,
            expected_revision=acquisition.state.revision,
            idempotency_key=f"fetch-start:{label}",
        )
        with evidence_connection(self.settings) as connection:
            url = str(
                connection.execute(
                    "SELECT url FROM evidence_resource_offer WHERE resource_offer_id=?",
                    (offer_id,),
                ).fetchone()[0]
            )
        payload = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF\n"
        digest = hashlib.sha256(payload).hexdigest()
        fetch = self.repository.record_fetch_attempt(
            FetchAttemptInput(
                requested_url=url,
                final_url=url,
                http_status=200,
                response_mime="application/pdf",
                response_bytes=len(payload),
                response_sha256=digest,
                request_identity_hash=hashlib.sha256(label.encode("utf-8")).hexdigest(),
                rights_status="repository_distribution_only",
                legal_basis="Reviewed synthetic repository-distribution decision.",
                result_status="succeeded",
            ),
            paper_id=None,
            candidate_id=candidate_id,
            attempt_key=f"fetch:{label}",
        )
        staged = EvidenceResourceStore(self.settings).put_pdf(payload)
        resource_id, _ = self.repository.register_resource(
            paper_id=None,
            candidate_id=candidate_id,
            fetch_attempt_id=fetch.fetch_attempt_id,
            content_sha256=staged.content_sha256,
            size=staged.bytes,
            relative_path=staged.relative_path,
            rights_status="repository_distribution_only",
        )
        self.expansion.complete_acquisition(
            acquisition.acquisition_case_id,
            expected_revision=fetching.revision,
            fetch_attempt_id=fetch.fetch_attempt_id,
            resource_id=resource_id,
            idempotency_key=f"fetch-complete:{label}",
        )
        return acquisition.acquisition_case_id, resource_id

    @staticmethod
    def _metadata(title: str = "Reviewed Synthetic Paper") -> ReviewedMetadata:
        return ReviewedMetadata(
            title=title,
            publication_date="2020-10-03",
            authors=(
                ReviewedAuthor(
                    name="Ada Researcher",
                    affiliations=(),
                    name_form="full",
                    fact_origin="official_external",
                ),
            ),
            author_resolution="verified_full_external",
            categories=("机器学习",),
            category_fact_origin="deterministic_mapping",
            category_assertion=ReviewedCategoryAssertion(
                source_system="reviewed",
                source_categories=(
                    ReviewedSourceCategory(
                        code="fixture:machine-learning",
                        display_name="Synthetic machine-learning source category",
                        is_primary=True,
                        fact_origin="human_reconciled",
                    ),
                ),
                primary_source_category="fixture:machine-learning",
                mapping_policy_version="qrh-test-broad-map/v1",
                primary_mapped_category="机器学习",
                assertion_status="human_reviewed",
                provenance_urn="qrh:test:reviewed-category:2010.01412",
            ),
            institutions=ReviewedInstitutionResolution(
                status="unresolved",
                institutions=(),
                reason_code="official_affiliation_absent",
                reason_text="Official fixture does not state an affiliation.",
                checked_source_fields=("atom.authors",),
            ),
            external_links=(
                ReviewedExternalLink(
                    kind="landing", url="https://arxiv.org/abs/2010.01412"
                ),
            ),
            source_kind="repository",
            review_tier="official_repository_full_material",
            assertion_boundaries={"official_metadata": "source_fact"},
            provenance_urn="qrh:test:reviewed-metadata:2010.01412",
        )

    def _manifest(
        self,
        item: ReviewedCanonicalizationItem,
        *,
        idempotency_key: str,
    ) -> ReviewedCanonicalizationManifest:
        return ReviewedCanonicalizationManifest(
            schema_version="qrh-reviewed-evidence-expansion/v1",
            review_id=f"review:{idempotency_key}",
            reviewed_by="Synthetic Independent Reviewer",
            reviewed_at="2026-07-15T00:00:00Z",
            idempotency_key=idempotency_key,
            provenance_urn=f"qrh:test:review:{idempotency_key}",
            items=(item,),
        )

    def _client(self):
        app = Flask(
            __name__,
            template_folder=str(
                Path(__file__).resolve().parents[1] / "src" / "quant_hub" / "web" / "templates"
            ),
        )
        app.config.update(TESTING=True)
        shell = Blueprint("web", __name__)

        @shell.get("/")
        def home_page() -> str:
            return "home"

        api_blueprint = Blueprint("api_v1", __name__)

        @api_blueprint.get("/api/v1/dashboard")
        def dashboard() -> dict[str, str]:
            return {"status": "ok"}

        app.register_blueprint(shell)
        app.register_blueprint(api_blueprint)
        app.register_blueprint(create_evidence_blueprint(self.settings))
        return app.test_client()

    def test_formal_resource_canonicalization_is_replayable_and_publicly_visible(self) -> None:
        _, candidate_id, ledger_id = self._source("P012")
        case_id, decision_id, offer_id = self._verified_identity(candidate_id, "formal")
        acquisition_id, resource_id = self._acquire(
            candidate_id, case_id, offer_id, "formal"
        )
        locator = ReviewedFulltextLocator(
            page_number=3,
            page_text_sha256="a" * 64,
            support_text_sha256="b" * 64,
            locator={"section": "3. Results", "paragraph": 2},
        )
        finding = "在审核过的合成证据页中，方法相对基线改善了目标指标。"
        item = ReviewedCanonicalizationItem(
            item_key="formal-P012",
            treatment="formal_citation",
            source_candidate_id="P012",
            paper_source_candidate_id="P012",
            resolution_case_id=case_id,
            identity_decision_id=decision_id,
            metadata=self._metadata(),
            official_abstract_excerpt=ReviewedExcerpt(
                text="Reviewed official abstract fixture.",
                page_sha256="c" * 64,
                locator={"field": "summary"},
                provenance_urn="qrh:test:official-abstract",
            ),
            resource=ReviewedResource(
                resource_id=resource_id,
                acquisition_case_id=acquisition_id,
                reading_result=ReviewedReadingResult(
                    worker_kind="human",
                    analysis="Reviewed full-text fixture analysis.",
                    core_conclusions=(
                        ReviewedReadingConclusion(text=finding, source_locator=locator),
                    ),
                    fact_boundary={"finding": "source_finding"},
                    provenance_urn="qrh:test:fulltext-reading",
                ),
            ),
            core_conclusions=(
                ReviewedConclusion(
                    text=finding,
                    evidence_scope="fulltext_reading",
                    source_locator=locator,
                    provenance_urn="qrh:test:fulltext-finding",
                ),
            ),
        )
        manifest = self._manifest(item, idempotency_key="formal-resource-v1")
        first = self.canonicalization.apply(manifest)
        snapshot = self.repository.snapshot_hash()
        second = self.canonicalization.apply(manifest)
        self.assertTrue(first.items[0].created)
        self.assertFalse(second.items[0].created)
        self.assertEqual(snapshot, self.repository.snapshot_hash())
        self.assertEqual(1, first.items[0].bound_citations)

        paper_id = first.items[0].paper_id
        detail = EvidenceQueryService(self.settings).paper_detail(paper_id)
        self.assertEqual(resource_id, detail["local_resources"][0]["resource_id"])
        self.assertEqual("fulltext_reading", detail["core_conclusions"][0]["evidence_scope"])
        self.assertEqual(3, detail["core_conclusions"][0]["source_locator"]["page_number"])
        self.assertEqual(
            "reviewed_fulltext_with_page_and_text_hash",
            detail["fact_boundary"]["core_conclusions"],
        )
        self.assertEqual("formal_reference", detail["archive_relations"][0]["relation_kind"])
        self.assertEqual("formal_or_direct", detail["archive_relations"][0]["relation_semantics"])
        coverage = EvidenceQueryService(self.settings).list_papers()["coverage"]
        self.assertEqual(1, coverage["canonicalized_candidates"])
        self.assertEqual(0, coverage["candidate_statuses"].get("proposed", 0))
        self.assertEqual(1, coverage["papers_with_local_resources"])
        self.assertEqual(1, coverage["resolved_citations"])
        self.assertEqual((), PaperReadingService(self.settings).pending_tasks())
        prepared = EvidenceReleaseService(self.settings).prepare_candidate(
            subject_urn="qrh:evidence:canonicalization-synthetic"
        )
        with evidence_connection(self.settings) as connection:
            release_urns = {
                str(row[0])
                for row in connection.execute(
                    "SELECT item_urn FROM evidence_release_item WHERE evidence_release_id=?",
                    (prepared.evidence_release_id,),
                )
            }
        for required_projection in (
            "reviewed-canonicalization",
            "canonicalization-events",
            "canonical-resource-attachments",
            "fulltext-conclusion-support",
        ):
            self.assertIn(
                f"qrh:evidence:projection:{required_projection}:v1", release_urns
            )

        with evidence_connection(self.settings) as connection:
            self.assertEqual(
                ("proposed", "resolution_pending"),
                tuple(
                    connection.execute(
                        """
                        SELECT candidate.resolution_status,clue.resolution_status
                        FROM paper_candidate AS candidate
                        JOIN paper_clue_candidate AS link USING(candidate_id)
                        JOIN paper_clue AS clue USING(clue_id)
                        WHERE clue.source_candidate_id='P012'
                        """
                    ).fetchone()
                ),
            )
            support = connection.execute(
                "SELECT page_number,page_text_sha256,support_text_sha256 FROM evidence_fulltext_conclusion_support"
            ).fetchone()
            self.assertEqual((3, "a" * 64, "b" * 64), tuple(support))
            binding = connection.execute(
                """
                SELECT binding.binding_status,binding.paper_id
                FROM citation_binding_projection AS projection
                JOIN citation_binding AS binding USING(binding_id)
                WHERE projection.ledger_entry_id=?
                """,
                (ledger_id,),
            ).fetchone()
            self.assertEqual(("resolved", paper_id), tuple(binding))

        client = self._client()
        api = client.get(f"/api/v1/evidence/papers/{paper_id}")
        self.assertEqual(200, api.status_code)
        api_data = api.get_json()["data"]
        self.assertEqual(
            f"/api/v1/evidence/resources/{resource_id}",
            api_data["local_resources"][0]["url"],
        )
        self.assertNotIn("resource_id", api_data["local_resources"][0])
        html = client.get(f"/evidence/papers/{paper_id}")
        self.assertEqual(200, html.status_code)
        html_body = html.get_data(as_text=True)
        self.assertIn(f"/api/v1/evidence/resources/{resource_id}", html_body)
        self.assertIn("打开本地 PDF", html_body)
        self.assertIn(finding, html_body)
        self.assertNotIn("全文证据定位", html_body)
        self.assertNotIn("支持文本哈希", html_body)
        pdf = client.get(f"/api/v1/evidence/resources/{resource_id}")
        self.assertEqual(200, pdf.status_code)
        self.assertTrue(pdf.data.startswith(b"%PDF-"))

    def test_associated_method_origin_uses_distinct_derived_paper_and_never_formal_binds(self) -> None:
        _, _, method_ledger = self._source("P135", method=True)
        derivation = self.canonicalization.prepare_method_origin_candidates(
            (
                MethodOriginCandidateInput(
                    original_source_candidate_id="P135",
                    derived_source_candidate_id="P135::origin:2010.01412",
                    identifier_scheme="arxiv",
                    identifier_value="2010.01412",
                    paper_title_claim="Reviewed Method-Origin Paper",
                    publication_year=2020,
                    rationale="The method-name clue is associated with, but is not itself, this paper.",
                    provenance_urn="qrh:test:method-origin-derivation:P135",
                ),
            )
        )[0]
        self.assertNotEqual(
            derivation.original_source_candidate_id,
            derivation.derived_source_candidate_id,
        )
        case_id, decision_id, _ = self._verified_identity(
            derivation.derived_candidate_id, "method-origin"
        )
        item = ReviewedCanonicalizationItem(
            item_key="associated-P135",
            treatment="associated_method_origin",
            source_candidate_id="P135",
            paper_source_candidate_id=derivation.derived_source_candidate_id,
            resolution_case_id=case_id,
            identity_decision_id=decision_id,
            metadata=self._metadata("Reviewed Method-Origin Paper"),
            resource=None,
            core_conclusions=(),
            association_rationale="Explicit method-family origin association; not a formal citation.",
        )
        result = self.canonicalization.apply(
            self._manifest(item, idempotency_key="associated-method-v1")
        )
        self.assertEqual(0, result.items[0].bound_citations)
        self.assertEqual(1, result.items[0].associated_relations)
        self.assertEqual(1, EvidenceQueryService(self.settings).list_papers()["total"])
        detail = EvidenceQueryService(self.settings).paper_detail(result.items[0].paper_id)
        self.assertEqual("associated_method_origin", detail["archive_relations"][0]["relation_kind"])
        self.assertEqual("associated_method_origin", detail["archive_relations"][0]["relation_semantics"])
        self.assertEqual([], detail["archive_core_relations"])
        self.assertEqual("none", detail["archive_relation_scope"])
        self.assertEqual(
            f"/api/v1/evidence/citations/{detail['archive_relations'][0]['citation_id']}",
            detail["archive_relations"][0]["citation_url"],
        )
        coverage = EvidenceQueryService(self.settings).list_papers()["coverage"]
        self.assertEqual(1, coverage["canonicalized_candidates"])
        self.assertEqual(1, coverage["candidate_statuses"]["rejected_non_paper"])
        self.assertEqual(0, coverage["resolved_citations"])
        self.assertEqual(1, coverage["associated_method_origins"])
        self.assertEqual(1, coverage["associated_method_origin_ledger_occurrences"])
        archive_index = {
            "Q2/P135.md": {
                "research_id": "res_method_origin_fixture",
                "research_title": "量化方法来源复核",
                "document_id": "doc_method_origin_fixture",
                "title": "方法谱系与适用边界",
                "sections": [
                    {
                        "anchor_id": "anc_sha256_" + "4" * 64,
                        "line_start": 1,
                        "title_text": "方法谱系与适用边界",
                    }
                ],
            }
        }
        with mock.patch.object(
            EvidenceQueryService, "_archive_link_index", return_value=archive_index
        ):
            linked_detail = EvidenceQueryService(self.settings).paper_detail(
                result.items[0].paper_id
            )
            self.assertEqual(1, len(linked_detail["archive_core_relations"]))
            self.assertEqual(
                "方法原始来源",
                linked_detail["archive_core_relations"][0]["relation_label"],
            )
            self.assertTrue(
                str(linked_detail["archive_core_relations"][0]["source_url"]).startswith(
                    "/research/res_method_origin_fixture/documents/"
                    "doc_method_origin_fixture#anc_sha256_"
                )
            )
            client = self._client()
            api = client.get(f"/api/v1/evidence/papers/{result.items[0].paper_id}")
            self.assertEqual(200, api.status_code)
            self.assertEqual(
                "方法原始来源",
                api.get_json()["data"]["archive_relations"][0]["relation_label"],
            )
            self.assertNotIn(
                "relation_semantics",
                api.get_json()["data"]["archive_relations"][0],
            )
            html = client.get(f"/evidence/papers/{result.items[0].paper_id}")
            self.assertEqual(200, html.status_code)
            html_body = html.get_data(as_text=True)
            self.assertIn("方法原始来源", html_body)
            self.assertIn("在量化研究中的具体用法", html_body)
            self.assertIn("查看研究正文 · 方法谱系与适用边界", html_body)
        list_html = client.get("/evidence/")
        self.assertEqual(200, list_html.status_code)
        self.assertIn("方法来源论文", list_html.get_data(as_text=True))
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
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT count(*) FROM research_paper_relation"
                ).fetchone()[0],
            )
            binding = connection.execute(
                """
                SELECT binding.binding_status,binding.paper_id
                FROM citation_binding_projection AS projection
                JOIN citation_binding AS binding USING(binding_id)
                WHERE projection.ledger_entry_id=?
                """,
                (method_ledger,),
            ).fetchone()
            self.assertEqual(("rejected_non_paper", None), tuple(binding))

    def test_metadata_only_has_explicit_empty_conclusions_and_no_local_file(self) -> None:
        _, candidate_id, _ = self._source("P-META")
        case_id, decision_id, _ = self._verified_identity(candidate_id, "metadata-only")
        item = ReviewedCanonicalizationItem(
            item_key="metadata-only",
            treatment="formal_citation",
            source_candidate_id="P-META",
            paper_source_candidate_id="P-META",
            resolution_case_id=case_id,
            identity_decision_id=decision_id,
            metadata=self._metadata("Metadata-only Reviewed Paper"),
            resource=None,
            core_conclusions=(),
        )
        result = self.canonicalization.apply(
            self._manifest(item, idempotency_key="metadata-only-v1")
        )
        detail = EvidenceQueryService(self.settings).paper_detail(result.items[0].paper_id)
        self.assertEqual([], detail["core_conclusions"])
        self.assertEqual([], detail["local_resources"])
        self.assertEqual([], detail["reading_tasks"])
        self.assertEqual("metadata_only", result.items[0].resource_mode)

    def test_official_abstract_is_source_evidence_without_local_pdf(self) -> None:
        _, candidate_id, _ = self._source("P-ATOM")
        case_id, decision_id, _ = self._verified_identity(candidate_id, "atom-only")
        excerpt_text = "Official repository abstract without a managed local PDF."
        excerpt_sha256 = hashlib.sha256(excerpt_text.encode("utf-8")).hexdigest()
        item = ReviewedCanonicalizationItem(
            item_key="atom-only",
            treatment="formal_citation",
            source_candidate_id="P-ATOM",
            paper_source_candidate_id="P-ATOM",
            resolution_case_id=case_id,
            identity_decision_id=decision_id,
            metadata=self._metadata("Atom-only Reviewed Paper"),
            official_abstract_excerpt=ReviewedExcerpt(
                text=excerpt_text,
                page_sha256="d" * 64,
                locator={
                    "source_kind": "official_arxiv_atom_summary",
                    "source_path": "project_state/workers/test/atom_fixture.xml",
                    "source_file_sha256": "e" * 64,
                    "source_file_bytes": 123,
                    "field": "atom.entry.summary",
                    "normalization_contract": "synthetic-test/v1",
                },
                provenance_urn="qrh:test:arxiv-atom:atom-only",
            ),
            resource=None,
            core_conclusions=(),
        )
        manifest = self._manifest(item, idempotency_key="atom-only-v1")
        first = self.canonicalization.apply(manifest)
        snapshot = self.repository.snapshot_hash()
        second = self.canonicalization.apply(manifest)
        self.assertTrue(first.items[0].created)
        self.assertFalse(second.items[0].created)
        self.assertEqual(snapshot, self.repository.snapshot_hash())
        self.assertEqual("metadata_only", first.items[0].resource_mode)

        paper_id = first.items[0].paper_id
        detail = EvidenceQueryService(self.settings).paper_detail(paper_id)
        self.assertEqual([], detail["local_resources"])
        self.assertEqual([], detail["reading_tasks"])
        self.assertEqual([], detail["core_conclusions"])
        self.assertEqual(1, len(detail["abstract_excerpts"]))
        self.assertEqual(excerpt_text, detail["abstract_excerpts"][0]["text"])
        self.assertEqual(excerpt_sha256, detail["abstract_excerpts"][0]["sha256"])

        with evidence_connection(self.settings) as connection:
            excerpt = connection.execute(
                "SELECT resource_id,excerpt_sha256 FROM evidence_excerpt WHERE paper_id=?",
                (paper_id,),
            ).fetchone()
            self.assertEqual((None, excerpt_sha256), tuple(excerpt))
            abstract_selection = connection.execute(
                """
                SELECT assertion.value_json
                FROM canonical_metadata_selection AS selection
                JOIN metadata_assertion AS assertion USING(assertion_id)
                WHERE selection.paper_id=? AND selection.field_name='abstract'
                """,
                (paper_id,),
            ).fetchone()
            self.assertEqual(excerpt_text, json.loads(abstract_selection[0]))
            events = {
                str(row["event_kind"]): json.loads(str(row["payload_json"]))
                for row in connection.execute(
                    """
                    SELECT event_kind,payload_json
                    FROM evidence_canonicalization_event
                    WHERE canonicalization_receipt_id=?
                    """,
                    (first.items[0].receipt_id,),
                )
            }
        for event_kind in ("metadata_selected", "application_committed"):
            self.assertEqual(
                detail["abstract_excerpts"][0]["excerpt_id"],
                events[event_kind]["official_abstract_excerpt_id"],
            )
            self.assertEqual(
                excerpt_sha256,
                events[event_kind]["official_abstract_sha256"],
            )

    def test_fulltext_conclusion_cannot_use_source_excerpt_without_resource(self) -> None:
        locator = ReviewedFulltextLocator(
            page_number=1,
            page_text_sha256="a" * 64,
            support_text_sha256="b" * 64,
        )
        with self.assertRaisesRegex(
            ValueError, "full-text conclusion requires a verified local resource"
        ):
            ReviewedCanonicalizationItem(
                item_key="invalid-source-only-fulltext",
                treatment="formal_citation",
                source_candidate_id="P-INVALID",
                paper_source_candidate_id="P-INVALID",
                resolution_case_id="resolution-invalid",
                identity_decision_id="decision-invalid",
                metadata=self._metadata("Invalid source-only fulltext"),
                official_abstract_excerpt=ReviewedExcerpt(
                    text="Official abstract.",
                    page_sha256="c" * 64,
                    provenance_urn="qrh:test:invalid-source-only",
                ),
                core_conclusions=(
                    ReviewedConclusion(
                        text="Unsupported fulltext claim.",
                        evidence_scope="fulltext_reading",
                        source_locator=locator,
                        provenance_urn="qrh:test:unsupported-fulltext",
                    ),
                ),
            )

    def test_manifest_is_atomic_and_idempotency_conflict_does_not_partially_write(self) -> None:
        _, first_candidate, _ = self._source("P-ATOMIC-1")
        _, second_candidate, _ = self._source("P-ATOMIC-2", with_ledger=False)
        first_case, first_decision, _ = self._verified_identity(first_candidate, "atomic-1")
        second_case, second_decision, _ = self._verified_identity(second_candidate, "atomic-2")
        items = (
            ReviewedCanonicalizationItem(
                item_key="atomic-1",
                treatment="formal_citation",
                source_candidate_id="P-ATOMIC-1",
                paper_source_candidate_id="P-ATOMIC-1",
                resolution_case_id=first_case,
                identity_decision_id=first_decision,
                metadata=self._metadata("Atomic Paper"),
            ),
            ReviewedCanonicalizationItem(
                item_key="atomic-2",
                treatment="formal_citation",
                source_candidate_id="P-ATOMIC-2",
                paper_source_candidate_id="P-ATOMIC-2",
                resolution_case_id=second_case,
                identity_decision_id=second_decision,
                metadata=self._metadata("Atomic Paper"),
            ),
        )
        manifest = ReviewedCanonicalizationManifest(
            schema_version="qrh-reviewed-evidence-expansion/v1",
            review_id="atomic-review",
            reviewed_by="Synthetic Reviewer",
            reviewed_at="2026-07-15T00:00:00Z",
            idempotency_key="atomic-v1",
            provenance_urn="qrh:test:atomic-review",
            items=items,
        )
        with self.assertRaisesRegex(CanonicalizationEligibilityError, "no Archive citation"):
            self.canonicalization.apply(manifest)
        with evidence_connection(self.settings) as connection:
            self.assertEqual(0, connection.execute("SELECT count(*) FROM paper").fetchone()[0])
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT count(*) FROM evidence_canonicalization_receipt"
                ).fetchone()[0],
            )

        valid = self._manifest(items[0], idempotency_key="conflict-v1")
        self.canonicalization.apply(valid)
        changed = valid.model_copy(
            update={
                "items": (
                    items[0].model_copy(update={"metadata": self._metadata("Changed title")}),
                )
            }
        )
        with self.assertRaises(CanonicalizationConflict):
            self.canonicalization.apply(changed)
        with evidence_connection(self.settings) as connection:
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT count(*) FROM evidence_canonicalization_receipt"
                ).fetchone()[0],
            )

    def test_reviewed_source_builders_preserve_crossref_tiers_and_arxiv_method_derivations(self) -> None:
        _, candidate_id, _ = self._source("P-CROSSREF")
        self._verified_crossref_identity(candidate_id, "builder")
        decision_path = self.root / "accepted_local_venue_unstated.jsonl"
        decision = {
            "candidate_id": "P-CROSSREF",
            "selected_doi": "10.5555/qrh.fixture.1",
            "identity_match_tier": "local_venue_unstated",
            "local_claim": {
                "title": "Deterministic Evidence Resolver Contract Fixture",
                "authors": "Doe",
                "year": "2024",
                "venue_or_publisher": "",
            },
            "strict_matches": [
                {
                    "doi": "10.5555/qrh.fixture.1",
                    "title": "Deterministic Evidence Resolver Contract Fixture",
                    "authors": [
                        {
                            "given": "Jane",
                            "family": "Doe",
                            "affiliations": [],
                        }
                    ],
                    "venues": ["Synthetic Registry Journal"],
                    "year_values": ["2024"],
                }
            ],
            "direct_doi_verification": {
                "endpoint": "https://api.crossref.org/works/10.5555%2Fqrh.fixture.1",
                "response_sha256": "d" * 64,
            },
            "assertion_boundaries": {
                "local_claim_unchanged": True,
                "official_venue_is_external_assertion": ["Synthetic Registry Journal"],
            },
        }
        decision_path.write_text(
            json.dumps(decision, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        crossref = build_crossref_reviewed_manifest(
            self.settings,
            (decision_path,),
            review_id="crossref-builder-review",
            reviewed_by="Synthetic Reviewer",
            reviewed_at="2026-07-15T00:00:00Z",
            idempotency_key="crossref-builder-v1",
            provenance_urn="qrh:test:crossref-builder",
        )
        crossref_item = crossref.items[0]
        self.assertEqual("metadata_only", self.canonicalization.static_plan(crossref)["items"][0]["resource_mode"])
        self.assertEqual("accepted_local_venue_unstated", crossref_item.metadata.review_tier)
        self.assertFalse(crossref_item.metadata.venue.local_venue_stated)
        self.assertEqual("official_external", crossref_item.metadata.authors[0].fact_origin)
        self.assertEqual([], list(crossref_item.core_conclusions))
        applied = self.canonicalization.apply(crossref)
        doi_detail = EvidenceQueryService(self.settings).paper_detail(applied.items[0].paper_id)
        self.assertEqual([], doi_detail["local_resources"])
        self.assertEqual([], doi_detail["core_conclusions"])
        self.assertEqual("crossref", doi_detail["category_evidence"]["source_system"])
        self.assertEqual(
            "deterministic_mapping",
            doi_detail["category_evidence"]["mapped_category_fact_origin"],
        )
        self.assertTrue(doi_detail["category_assignments"][0]["is_primary"])

        reading_path = (
            Path(__file__).resolve().parents[2]
            / "project_state"
            / "workers"
            / "arxiv_expansion_materials"
            / "reading_records.json"
        )
        derivations = method_origin_inputs_from_arxiv_readings(
            reading_path, provenance_urn="qrh:test:actual-arxiv-review"
        )
        self.assertEqual(7, len(derivations))
        self.assertEqual(
            {"P135", "P137", "P138", "P139", "P143", "P144", "P145"},
            {value.original_source_candidate_id for value in derivations},
        )
        self.assertTrue(
            all(
                value.original_source_candidate_id
                != value.resolved_derived_source_candidate_id
                for value in derivations
            )
        )


if __name__ == "__main__":
    unittest.main()
