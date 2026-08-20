from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
import unittest

from quant_hub.evidence.contracts import FetchAttemptInput
from quant_hub.evidence.database import evidence_connection
from quant_hub.evidence.expansion import (
    EvidenceExpansionConflict,
    EvidenceExpansionRepository,
    EvidenceExpansionService,
)
from quant_hub.evidence.providers import (
    ArxivAdapter,
    ConservativeRightsPolicy,
    CrossrefAdapter,
    ProviderHttpResponse,
    ResolutionQuery,
    RightsAssessmentProposal,
    StrongIdentifierQuery,
)
from quant_hub.evidence.repository import EvidenceRepository
from quant_hub.evidence.resources import EvidenceResourceStore
from tests.helpers import SettingsTestCase


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "evidence" / "providers"


class EvidenceExpansionWorkflowTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.evidence = EvidenceRepository(self.settings)
        self.evidence.initialize()
        self.expansion = EvidenceExpansionRepository(self.settings)
        self.service = EvidenceExpansionService(self.settings)

    def _candidate(self, source_id: str = "P012") -> str:
        candidate_id, _ = self.evidence.put_candidate(
            source_candidate_id=source_id,
            candidate_kind="paper",
            title_claim=f"Candidate {source_id}",
            publication_year=2020,
            resolution_status="proposed",
            provenance_urn=f"qrh:test:candidate:{source_id}",
        )
        return candidate_id

    @staticmethod
    def _response(request, fixture: str, media_type: str) -> ProviderHttpResponse:
        return ProviderHttpResponse(
            request_url=request.url,
            final_url=request.url,
            status_code=200,
            headers={
                "Content-Type": media_type,
                "Set-Cookie": "secret-must-be-filtered",
            },
            body=(FIXTURES / fixture).read_bytes(),
        )

    def _exact_arxiv_cycle(self):
        candidate_id = self._candidate()
        query = ResolutionQuery(
            identifiers=(
                StrongIdentifierQuery(
                    scheme="arxiv",
                    raw_value="2010.01412",
                    source_provenance_urn="qrh:test:official-page:P012",
                ),
            )
        )
        adapter = ArxivAdapter()
        opened, request_records = self.service.enqueue_and_plan(
            candidate_id,
            query,
            (adapter,),
            provenance_urn="qrh:test:resolution:P012",
            idempotency_key="P012",
        )
        request = adapter.plan(query)[0]
        ingested = self.expansion.ingest_provider_response(
            request_records[0].provider_request_id,
            self._response(request, "arxiv_2010.01412_atom.xml", "application/atom+xml"),
            adapter,
            attempt_number=1,
            idempotency_key="arxiv-P012-attempt-1",
            provenance_urn="qrh:test:transport:P012:1",
        )
        state, _ = self.expansion.finalize_provider_cycle(
            opened.resolution_case_id,
            expected_revision=opened.state.revision,
            idempotency_key="finalize-P012-1",
        )
        return candidate_id, query, opened, ingested, state

    def test_exact_identifier_stops_for_explicit_decision_and_never_creates_paper(self) -> None:
        candidate_id, query, opened, ingested, state = self._exact_arxiv_cycle()
        self.assertEqual("awaiting_review", state.state)
        self.assertEqual(3, state.revision)
        with evidence_connection(self.settings) as connection:
            self.assertEqual(0, connection.execute("SELECT count(*) FROM paper").fetchone()[0])
            observation = connection.execute(
                "SELECT * FROM evidence_provider_observation"
            ).fetchone()
            self.assertEqual("source_identifier_exact", observation["match_basis"])
            self.assertEqual("not_canonicalized", observation["canonicalization_status"])
            headers = connection.execute(
                "SELECT response_headers_json FROM evidence_provider_attempt"
            ).fetchone()[0]
            self.assertNotIn("set-cookie", headers)

        decision = self.expansion.record_identity_decision(
            opened.resolution_case_id,
            expected_revision=state.revision,
            decision_kind="accept_verified_identifier",
            provider_observation_id=ingested.observation_ids[0],
            identifier_scheme="arxiv",
            normalized_identifier="2010.01412",
            authority_kind="deterministic_strong_identifier_policy",
            rationale="Official arXiv id_list response exactly matches the source identifier.",
            evidence_refs=list(ingested.observation_ids),
            idempotency_key="accept-P012-arxiv",
            provenance_urn="qrh:test:identity-decision:P012",
        )
        self.assertEqual("identifier_verified", decision.state.state)
        replay = self.expansion.record_identity_decision(
            opened.resolution_case_id,
            expected_revision=state.revision,
            decision_kind="accept_verified_identifier",
            provider_observation_id=ingested.observation_ids[0],
            identifier_scheme="arxiv",
            normalized_identifier="2010.01412",
            authority_kind="deterministic_strong_identifier_policy",
            rationale="Official arXiv id_list response exactly matches the source identifier.",
            evidence_refs=list(ingested.observation_ids),
            idempotency_key="accept-P012-arxiv",
            provenance_urn="qrh:test:identity-decision:P012",
        )
        self.assertFalse(replay.created)
        with evidence_connection(self.settings) as connection:
            self.assertEqual(0, connection.execute("SELECT count(*) FROM paper").fetchone()[0])
            self.assertEqual(
                "none",
                connection.execute(
                    "SELECT canonicalization_effect FROM evidence_identity_decision"
                ).fetchone()[0],
            )

        reopened, requests = self.service.enqueue_and_plan(
            candidate_id,
            query,
            (ArxivAdapter(),),
            provenance_urn="qrh:test:resolution:P012",
            idempotency_key="P012",
        )
        self.assertFalse(reopened.created)
        self.assertEqual("identifier_verified", reopened.state.state)
        self.assertEqual((), requests)

    def test_high_provider_score_cannot_pass_deterministic_identity_policy(self) -> None:
        candidate_id = self._candidate("P-SCORE")
        query = ResolutionQuery(title="Deterministic Evidence Resolver Contract Fixture")
        adapter = CrossrefAdapter()
        opened, request_records = self.service.enqueue_and_plan(
            candidate_id,
            query,
            (adapter,),
            provenance_urn="qrh:test:score-case",
            idempotency_key="score-case",
        )
        request = adapter.plan(query)[0]
        result = self.expansion.ingest_provider_response(
            request_records[0].provider_request_id,
            self._response(request, "crossref_title_search.json", "application/json"),
            adapter,
            attempt_number=1,
            idempotency_key="score-attempt-1",
            provenance_urn="qrh:test:score-transport",
        )
        state, _ = self.expansion.finalize_provider_cycle(
            opened.resolution_case_id,
            expected_revision=opened.state.revision,
            idempotency_key="score-finalize",
        )
        self.assertEqual("awaiting_review", state.state)
        with self.assertRaisesRegex(EvidenceExpansionConflict, "only accepts exact"):
            self.expansion.record_identity_decision(
                opened.resolution_case_id,
                expected_revision=state.revision,
                decision_kind="accept_verified_identifier",
                provider_observation_id=result.observation_ids[0],
                identifier_scheme="doi",
                normalized_identifier="10.5555/qrh.fixture.1",
                authority_kind="deterministic_strong_identifier_policy",
                rationale="A high score is deliberately insufficient.",
                evidence_refs=list(result.observation_ids),
                idempotency_key="score-illegal-accept",
                provenance_urn="qrh:test:score-illegal",
            )
        accepted = self.expansion.record_identity_decision(
            opened.resolution_case_id,
            expected_revision=state.revision,
            decision_kind="accept_verified_identifier",
            provider_observation_id=result.observation_ids[0],
            identifier_scheme="doi",
            normalized_identifier="10.5555/qrh.fixture.1",
            authority_kind="human_review",
            rationale="Human review explicitly reconciled title, author, date, and DOI evidence.",
            evidence_refs=list(result.observation_ids),
            idempotency_key="score-human-accept",
            provenance_urn="qrh:test:score-human-review",
        )
        self.assertEqual("identifier_verified", accepted.state.state)

    def test_transport_failure_is_append_only_and_retryable(self) -> None:
        candidate_id = self._candidate("P-RETRY")
        query = ResolutionQuery(title="Retryable provider query")
        adapter = CrossrefAdapter()
        opened, requests = self.service.enqueue_and_plan(
            candidate_id,
            query,
            (adapter,),
            provenance_urn="qrh:test:retry-case",
            idempotency_key="retry-case",
        )
        first = self.expansion.record_provider_failure(
            requests[0].provider_request_id,
            attempt_number=1,
            idempotency_key="retry-attempt-1",
            result_status="network_failed",
            error_class="TimeoutError",
            error_detail="fixture timeout",
            provenance_urn="qrh:test:retry-transport-1",
        )
        self.assertEqual("network_failed", first.result_status)
        failed, _ = self.expansion.finalize_provider_cycle(
            opened.resolution_case_id,
            expected_revision=opened.state.revision,
            idempotency_key="retry-finalize-1",
        )
        self.assertEqual("retryable_error", failed.state)
        resolving, _ = self.expansion.start_resolution(
            opened.resolution_case_id,
            expected_revision=failed.revision,
            idempotency_key="retry-start-2",
        )
        request = adapter.plan(query)[0]
        second = self.expansion.ingest_provider_response(
            requests[0].provider_request_id,
            self._response(request, "crossref_title_search.json", "application/json"),
            adapter,
            attempt_number=2,
            idempotency_key="retry-attempt-2",
            provenance_urn="qrh:test:retry-transport-2",
        )
        self.assertEqual("succeeded", second.result_status)
        reviewed, _ = self.expansion.finalize_provider_cycle(
            opened.resolution_case_id,
            expected_revision=resolving.revision,
            idempotency_key="retry-finalize-2",
        )
        self.assertEqual("awaiting_review", reviewed.state)
        with evidence_connection(self.settings) as connection:
            attempts = connection.execute(
                "SELECT attempt_number,result_status FROM evidence_provider_attempt ORDER BY attempt_number"
            ).fetchall()
        self.assertEqual(
            [(1, "network_failed"), (2, "succeeded")],
            [tuple(row) for row in attempts],
        )

    def test_rights_assessment_gates_fetch_and_failed_fetch_recovers(self) -> None:
        candidate_id, _, opened, ingested, _ = self._exact_arxiv_cycle()
        offer_id = ingested.resource_offer_ids[0]
        automatic = self.expansion.assess_offer(
            offer_id,
            ConservativeRightsPolicy(),
            idempotency_key="rights-auto-P012",
            provenance_urn="qrh:test:rights-auto:P012",
        )
        self.assertEqual("review_required", automatic.decision)
        held = self.expansion.open_acquisition_case(
            offer_id,
            automatic.rights_assessment_id,
            provenance_urn="qrh:test:acquisition-held:P012",
        )
        self.assertEqual("rights_review", held.state.state)
        with self.assertRaisesRegex(EvidenceExpansionConflict, "only start after rights approval"):
            self.expansion.begin_acquisition(
                held.acquisition_case_id,
                expected_revision=held.state.revision,
                idempotency_key="illegal-fetch-before-rights",
            )

        reviewed = self.expansion.record_rights_assessment(
            offer_id,
            RightsAssessmentProposal(
                decision="approved_for_local_storage",
                rights_status="repository_distribution_only",
                authority_kind="human_review",
                policy_version="qrh-test-human-rights/v1",
                legal_basis=(
                    "Fixture-only human decision: official repository distribution is "
                    "accepted for this isolated local test and grants no redistribution right."
                ),
                evidence={"fixture_scope": "isolated_test_only"},
            ),
            idempotency_key="rights-human-P012",
            provenance_urn="qrh:test:rights-human:P012",
            supersedes_assessment_id=automatic.rights_assessment_id,
        )
        acquisition = self.expansion.open_acquisition_case(
            offer_id,
            reviewed.rights_assessment_id,
            provenance_urn="qrh:test:acquisition-approved:P012",
        )
        self.assertEqual("ready", acquisition.state.state)
        fetching, _ = self.expansion.begin_acquisition(
            acquisition.acquisition_case_id,
            expected_revision=acquisition.state.revision,
            idempotency_key="fetch-P012-1",
        )
        with evidence_connection(self.settings) as connection:
            offer_url = str(
                connection.execute(
                    "SELECT url FROM evidence_resource_offer WHERE resource_offer_id=?",
                    (offer_id,),
                ).fetchone()[0]
            )
        failed_attempt = self.evidence.record_fetch_attempt(
            FetchAttemptInput(
                requested_url=offer_url,
                request_identity_hash="1" * 64,
                rights_status="repository_distribution_only",
                legal_basis="explicit reviewed fixture rights assessment",
                result_status="network_failed",
                error_class="TimeoutError",
                error_detail="fixture timeout",
            ),
            paper_id=None,
            candidate_id=candidate_id,
            attempt_key="P012-fetch-network-failure",
        )
        retryable, _ = self.expansion.fail_acquisition(
            acquisition.acquisition_case_id,
            expected_revision=fetching.revision,
            fetch_attempt_id=failed_attempt.fetch_attempt_id,
            idempotency_key="fetch-P012-failed-1",
        )
        self.assertEqual("retryable_error", retryable.state)
        retrying, _ = self.expansion.begin_acquisition(
            acquisition.acquisition_case_id,
            expected_revision=retryable.revision,
            idempotency_key="fetch-P012-2",
        )

        payload = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF\n"
        digest = hashlib.sha256(payload).hexdigest()
        success = self.evidence.record_fetch_attempt(
            FetchAttemptInput(
                requested_url=offer_url,
                final_url=offer_url,
                http_status=200,
                response_mime="application/pdf",
                response_bytes=len(payload),
                response_sha256=digest,
                request_identity_hash="2" * 64,
                rights_status="repository_distribution_only",
                legal_basis="explicit reviewed fixture rights assessment",
                result_status="succeeded",
            ),
            paper_id=None,
            candidate_id=candidate_id,
            attempt_key="P012-fetch-success",
        )
        staged = EvidenceResourceStore(self.settings).put_pdf(payload)
        resource_id, _ = self.evidence.register_resource(
            paper_id=None,
            candidate_id=candidate_id,
            fetch_attempt_id=success.fetch_attempt_id,
            content_sha256=staged.content_sha256,
            size=staged.bytes,
            relative_path=staged.relative_path,
            rights_status="repository_distribution_only",
        )
        acquired, _ = self.expansion.complete_acquisition(
            acquisition.acquisition_case_id,
            expected_revision=retrying.revision,
            fetch_attempt_id=success.fetch_attempt_id,
            resource_id=resource_id,
            idempotency_key="fetch-P012-complete",
        )
        self.assertEqual("acquired", acquired.state)
        self.assertEqual(5, acquired.revision)

    def test_case_count_is_data_driven_not_bound_to_legacy_eighteen(self) -> None:
        for index in range(23):
            candidate_id = self._candidate(f"P-DYNAMIC-{index:02d}")
            self.expansion.open_resolution_case(
                candidate_id,
                ResolutionQuery(
                    identifiers=(
                        StrongIdentifierQuery(
                            scheme="arxiv",
                            raw_value=f"2401.{index + 1:05d}",
                            source_provenance_urn=f"qrh:test:dynamic:{index}",
                        ),
                    )
                ),
                provenance_urn=f"qrh:test:dynamic-case:{index}",
            )
        queued = self.expansion.cases_by_state("queued")
        self.assertEqual(23, len(queued))
        self.assertNotEqual(18, len(queued))

    def test_database_rejects_invalid_case_transition_and_rights_approval(self) -> None:
        _, _, opened, ingested, state = self._exact_arxiv_cycle()
        with evidence_connection(self.settings) as connection:
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "invalid evidence resolution state transition"
            ):
                connection.execute(
                    """
                    INSERT INTO evidence_resolution_event(
                        resolution_event_id,resolution_case_id,idempotency_key,event_kind,
                        from_state,to_state,reason_code,reason_detail,evidence_refs_json,
                        occurred_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        "revent-invalid-direct-transition",
                        opened.resolution_case_id,
                        "invalid-direct-transition",
                        "retry_scheduled",
                        state.state,
                        "resolving",
                        "test_invalid_transition",
                        "awaiting_review cannot bypass its explicit identity decision",
                        "[]",
                        "2026-07-15T00:00:00Z",
                    ),
                )
        with evidence_connection(self.settings) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO evidence_rights_assessment(
                        rights_assessment_id,resource_offer_id,decision,rights_status,
                        authority_kind,policy_version,legal_basis,evidence_json,
                        supersedes_assessment_id,idempotency_key,provenance_urn,assessed_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        "rights-invalid-direct-approval",
                        ingested.resource_offer_ids[0],
                        "approved_for_local_storage",
                        "unknown",
                        "human_review",
                        "qrh-test/v1",
                        "An approval cannot contradict its persisted rights status.",
                        "{}",
                        None,
                        "invalid-direct-rights-approval",
                        "qrh:test:invalid-direct-rights-approval",
                        "2026-07-15T00:00:00Z",
                    ),
                )


if __name__ == "__main__":
    unittest.main()
