from __future__ import annotations

import json
from pathlib import Path
import unittest

from pydantic import ValidationError

from quant_hub.evidence.providers import (
    ArxivAdapter,
    ConservativeRightsPolicy,
    CrossrefAdapter,
    ProviderContractError,
    ProviderHttpResponse,
    ProviderObservation,
    ProviderRequestSpec,
    ResolutionQuery,
    ResourceOfferObservation,
    RightsAssessmentProposal,
    StrongIdentifierQuery,
)


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "evidence" / "providers"
SEED_FIXTURE = FIXTURES.parent / "expansion_seed_arxiv_v1.json"


def _response(request, fixture: str, media_type: str) -> ProviderHttpResponse:
    return ProviderHttpResponse(
        request_url=request.url,
        final_url=request.url,
        status_code=200,
        headers={"Content-Type": media_type, "Set-Cookie": "must-not-be-persisted"},
        body=(FIXTURES / fixture).read_bytes(),
    )


class EvidenceProviderContractTests(unittest.TestCase):
    def test_exact_arxiv_seed_manifest_is_complete_unique_and_plannable(self) -> None:
        expected = {
            "P012": "2010.01412",
            "P005": "1806.07572",
            "P013": "1803.05407",
            "P054": "1612.01474",
            "P145": "2202.01575",
            "P143": "2106.10466",
            "P139": "2211.14730",
            "P135": "1909.04939",
            "P138": "1905.10437",
            "P137": "2012.08791",
            "P144": "2106.00750",
        }
        payload = json.loads(SEED_FIXTURE.read_text(encoding="utf-8"))
        observed = {
            item["source_candidate_id"]: item["arxiv_id"]
            for item in payload["items"]
        }
        self.assertEqual("qrh-evidence-resolution-seed/v1", payload["schema_version"])
        self.assertEqual(expected, observed)
        self.assertEqual(len(expected), len(payload["items"]))
        adapter = ArxivAdapter()
        for source_id, arxiv_id in observed.items():
            query = ResolutionQuery(
                identifiers=(
                    StrongIdentifierQuery(
                        scheme="arxiv",
                        raw_value=arxiv_id,
                        source_provenance_urn=f"qrh:test:seed:{source_id}",
                    ),
                )
            )
            request = adapter.plan(query)[0]
            self.assertIn(f"id_list={arxiv_id}", request.url)
            self.assertEqual("identifier_lookup", request.operation)

    def test_crossref_exact_doi_is_strong_evidence_but_not_canonicalization(self) -> None:
        query = ResolutionQuery(
            identifiers=(
                StrongIdentifierQuery(
                    scheme="doi",
                    raw_value="https://doi.org/10.5555/QRH.FIXTURE.1",
                    source_provenance_urn="qrh:test:source-doi",
                ),
            )
        )
        adapter = CrossrefAdapter()
        request = adapter.plan(query)[0]
        result = adapter.parse(
            request,
            _response(request, "crossref_doi_lookup.json", "application/json; charset=utf-8"),
        )
        self.assertEqual(1, len(result.observations))
        observation = result.observations[0]
        self.assertEqual("source_identifier_exact", observation.match_basis)
        self.assertEqual("strong_identifier_verified", observation.identity_effect)
        self.assertEqual("10.5555/qrh.fixture.1", observation.identifiers[0].normalized_value)
        self.assertEqual(999.0, observation.provider_score)
        self.assertNotIn("abstract", observation.record)
        self.assertEqual(
            "crossref_abstract_copyright_boundary",
            observation.record["abstract_omitted_by_policy"],
        )
        self.assertEqual("unknown", observation.resource_offers[0].rights_hint)
        rights = ConservativeRightsPolicy().assess(observation.resource_offers[0])
        self.assertEqual("review_required", rights.decision)

    def test_crossref_score_never_selects_title_search_result(self) -> None:
        query = ResolutionQuery(title="Deterministic Evidence Resolver Contract Fixture")
        adapter = CrossrefAdapter(max_results=5)
        request = adapter.plan(query)[0]
        result = adapter.parse(
            request,
            _response(request, "crossref_title_search.json", "application/json"),
        )
        self.assertEqual([999.0, 0.01], [item.provider_score for item in result.observations])
        self.assertEqual(
            {"metadata_candidate_only"},
            {item.match_basis for item in result.observations},
        )
        self.assertEqual(
            {"review_required"},
            {item.identity_effect for item in result.observations},
        )

    def test_crossref_duplicate_link_claims_form_one_auditable_offer(self) -> None:
        query = ResolutionQuery(
            identifiers=(
                StrongIdentifierQuery(
                    scheme="doi",
                    raw_value="10.5555/qrh.fixture.1",
                    source_provenance_urn="qrh:test:duplicate-crossref-links",
                ),
            )
        )
        adapter = CrossrefAdapter()
        request = adapter.plan(query)[0]
        payload = json.loads(
            (FIXTURES / "crossref_doi_lookup.json").read_text(encoding="utf-8")
        )
        original = payload["message"]["link"][0]
        payload["message"]["link"] = [
            {**original, "intended-application": "text-mining"},
            {**original, "intended-application": "syndication"},
        ]
        response = ProviderHttpResponse(
            request_url=request.url,
            final_url=request.url,
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(payload).encode("utf-8"),
        )
        offers = adapter.parse(request, response).observations[0].resource_offers
        self.assertEqual(1, len(offers))
        self.assertEqual(
            {"text-mining", "syndication"},
            {
                claim["intended_application"]
                for claim in offers[0].license_evidence["crossref_link_claims"]
            },
        )

    def test_arxiv_exact_identifier_is_normalized_and_resource_rights_stay_explicit(self) -> None:
        query = ResolutionQuery(
            identifiers=(
                StrongIdentifierQuery(
                    scheme="arxiv",
                    raw_value="arXiv:2010.01412v3",
                    source_provenance_urn="qrh:test:P012",
                ),
            )
        )
        adapter = ArxivAdapter()
        request = adapter.plan(query)[0]
        result = adapter.parse(
            request,
            _response(request, "arxiv_2010.01412_atom.xml", "application/atom+xml"),
        )
        observation = result.observations[0]
        self.assertEqual("2010.01412", observation.provider_record_id)
        self.assertEqual("source_identifier_exact", observation.match_basis)
        self.assertEqual("strong_identifier_verified", observation.identity_effect)
        self.assertEqual("https://arxiv.org/pdf/2010.01412v3", observation.resource_offers[0].url)
        self.assertEqual("unknown", observation.resource_offers[0].rights_hint)
        self.assertEqual(
            "review_required",
            ConservativeRightsPolicy().assess(observation.resource_offers[0]).decision,
        )

        title_request = adapter.plan(
            ResolutionQuery(title="Sharpness-Aware Minimization")
        )[0]
        title_result = adapter.parse(
            title_request,
            _response(title_request, "arxiv_2010.01412_atom.xml", "application/atom+xml"),
        )
        self.assertEqual("metadata_candidate_only", title_result.observations[0].match_basis)
        self.assertEqual("review_required", title_result.observations[0].identity_effect)

    def test_xml_entities_http_redirects_and_persisted_secrets_fail_closed(self) -> None:
        adapter = ArxivAdapter()
        request = adapter.plan(ResolutionQuery(title="fixture"))[0]
        malicious = ProviderHttpResponse(
            request_url=request.url,
            final_url=request.url,
            status_code=200,
            headers={"Content-Type": "application/atom+xml"},
            body=b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY y "z">]><feed />',
        )
        with self.assertRaisesRegex(ProviderContractError, "entity declaration"):
            adapter.parse(request, malicious)
        with self.assertRaises(ValidationError):
            ProviderHttpResponse(
                request_url=request.url,
                final_url=request.url,
                redirect_chain=("http://downgrade.invalid",),
                status_code=200,
                headers={"Content-Type": "application/atom+xml"},
                body=b"<feed />",
            )
        with self.assertRaises(ValidationError):
            ProviderRequestSpec(
                provider="crossref",
                operation="metadata_search",
                url="https://api.crossref.org/v1/works?rows=1",
                headers={"Authorization": "secret"},
            )

    def test_only_recognized_per_work_open_license_auto_approves(self) -> None:
        offer = ResourceOfferObservation(
            provider="arxiv",
            resource_kind="paper_pdf",
            source_kind="official_repository",
            url="https://arxiv.org/pdf/2401.00001",
            media_type="application/pdf",
            rights_hint="verified_open_license",
            license_evidence={
                "normalized_open_license_url": "https://creativecommons.org/licenses/by/4.0/"
            },
            provenance_urn="qrh:test:synthetic-open-license-contract",
        )
        assessment = ConservativeRightsPolicy().assess(offer)
        self.assertEqual("approved_for_local_storage", assessment.decision)
        self.assertEqual("verified_open_license", assessment.rights_status)

    def test_identity_effect_and_approved_rights_status_fail_closed(self) -> None:
        adapter = CrossrefAdapter()
        request = adapter.plan(
            ResolutionQuery(
                identifiers=(
                    StrongIdentifierQuery(
                        scheme="doi",
                        raw_value="10.5555/QRH.FIXTURE.1",
                        source_provenance_urn="qrh:test:contract-consistency",
                    ),
                )
            )
        )[0]
        observation = adapter.parse(
            request,
            _response(request, "crossref_doi_lookup.json", "application/json"),
        ).observations[0]
        invalid_observation = observation.model_dump(mode="python")
        invalid_observation["identity_effect"] = "review_required"
        with self.assertRaisesRegex(ValidationError, "source_identifier_exact"):
            ProviderObservation.model_validate(invalid_observation)
        with self.assertRaisesRegex(ValidationError, "storage-capable"):
            RightsAssessmentProposal(
                decision="approved_for_local_storage",
                rights_status="unknown",
                authority_kind="human_review",
                policy_version="qrh-test/v1",
                legal_basis="An explicit decision still cannot contradict its status.",
            )


if __name__ == "__main__":
    unittest.main()
