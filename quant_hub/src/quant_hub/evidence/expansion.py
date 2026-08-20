from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import sqlite3
from typing import Any, Literal

from quant_hub.config import Settings
from quant_hub.platform.db import immediate_transaction, utc_now
from quant_hub.platform.workflow import canonical_json

from .database import evidence_connection, initialize_evidence_database
from .ids import normalize_identifier, stable_evidence_id
from .providers import (
    ConservativeRightsPolicy,
    ProviderAdapter,
    ProviderContractError,
    ProviderHttpResponse,
    ProviderObservation,
    ProviderParseResult,
    ProviderRequestSpec,
    ResolutionQuery,
    ResourceOfferObservation,
    RightsAssessmentProposal,
)


ResolutionState = Literal[
    "queued",
    "resolving",
    "awaiting_review",
    "identifier_verified",
    "unresolved",
    "conflicted",
    "retryable_error",
    "blocked",
]
AcquisitionState = Literal[
    "rights_review",
    "ready",
    "fetching",
    "acquired",
    "retryable_error",
    "invalid_content",
    "blocked",
]


class EvidenceExpansionConflict(RuntimeError):
    pass


class EvidenceExpansionNotFound(KeyError):
    pass


@dataclass(frozen=True, slots=True)
class WorkflowState:
    case_id: str
    state: str
    revision: int


@dataclass(frozen=True, slots=True)
class ResolutionCaseRecord:
    resolution_case_id: str
    input_snapshot_hash: str
    state: WorkflowState
    created: bool


@dataclass(frozen=True, slots=True)
class ProviderRequestRecord:
    provider_request_id: str
    request_fingerprint: str
    created: bool


@dataclass(frozen=True, slots=True)
class ProviderIngestResult:
    provider_attempt_id: str
    result_status: str
    observation_ids: tuple[str, ...]
    resource_offer_ids: tuple[str, ...]
    created: bool
    parse_error: str | None = None


@dataclass(frozen=True, slots=True)
class IdentityDecisionRecord:
    identity_decision_id: str
    state: WorkflowState
    created: bool


@dataclass(frozen=True, slots=True)
class RightsAssessmentRecord:
    rights_assessment_id: str
    decision: str
    rights_status: str
    created: bool


@dataclass(frozen=True, slots=True)
class AcquisitionCaseRecord:
    acquisition_case_id: str
    state: WorkflowState
    created: bool


def _sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _row_material(row: sqlite3.Row, names: tuple[str, ...]) -> tuple[Any, ...]:
    return tuple(row[name] for name in names)


def _safe_response_headers(headers: dict[str, str]) -> dict[str, str]:
    allowed = {
        "cache-control",
        "content-length",
        "content-type",
        "date",
        "etag",
        "last-modified",
        "retry-after",
        "x-api-pool",
        "x-rate-limit-interval",
        "x-rate-limit-limit",
    }
    return {
        name.casefold(): value
        for name, value in headers.items()
        if name.casefold() in allowed
    }


class EvidenceExpansionRepository:
    """Incremental resolver/acquisition workflow; it never creates a canonical paper."""

    resolution_policy_version = "qrh-evidence-resolution-policy/v1"

    def __init__(self, settings: Settings):
        self.settings = settings

    def initialize(self) -> list[int]:
        return initialize_evidence_database(self.settings)

    @staticmethod
    def _resolution_state(
        connection: sqlite3.Connection, resolution_case_id: str
    ) -> WorkflowState:
        row = connection.execute(
            "SELECT state,revision FROM evidence_resolution_state WHERE resolution_case_id=?",
            (resolution_case_id,),
        ).fetchone()
        if row is None:
            raise EvidenceExpansionNotFound("resolution case does not exist")
        return WorkflowState(resolution_case_id, str(row["state"]), int(row["revision"]))

    @staticmethod
    def _acquisition_state(
        connection: sqlite3.Connection, acquisition_case_id: str
    ) -> WorkflowState:
        row = connection.execute(
            "SELECT state,revision FROM evidence_acquisition_state WHERE acquisition_case_id=?",
            (acquisition_case_id,),
        ).fetchone()
        if row is None:
            raise EvidenceExpansionNotFound("acquisition case does not exist")
        return WorkflowState(acquisition_case_id, str(row["state"]), int(row["revision"]))

    def open_resolution_case(
        self,
        candidate_id: str,
        query: ResolutionQuery,
        *,
        provenance_urn: str,
        policy_version: str | None = None,
    ) -> ResolutionCaseRecord:
        policy = policy_version or self.resolution_policy_version
        input_claim = query.snapshot_material()
        snapshot_hash = _sha256_json(
            {
                "schema_version": "qrh-evidence-resolution-input/v1",
                "candidate_id": candidate_id,
                "policy_version": policy,
                "query": input_claim,
            }
        )
        case_id = stable_evidence_id("rcase", candidate_id, snapshot_hash)
        event_id = stable_evidence_id("revent", case_id, "case-opened")
        expected = (
            candidate_id,
            snapshot_hash,
            canonical_json(input_claim),
            policy,
            provenance_urn,
        )
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            candidate = connection.execute(
                "SELECT candidate_kind FROM paper_candidate WHERE candidate_id=?",
                (candidate_id,),
            ).fetchone()
            if candidate is None:
                raise EvidenceExpansionNotFound("paper candidate does not exist")
            if candidate["candidate_kind"] != "paper":
                raise EvidenceExpansionConflict(
                    "non-paper resource clues cannot enter the paper resolver"
                )
            existing = connection.execute(
                "SELECT * FROM evidence_resolution_case WHERE resolution_case_id=?",
                (case_id,),
            ).fetchone()
            if existing is not None:
                fields = (
                    "candidate_id",
                    "input_snapshot_hash",
                    "input_claim_json",
                    "policy_version",
                    "provenance_urn",
                )
                if _row_material(existing, fields) != expected:
                    raise EvidenceExpansionConflict("stable resolution case conflicts")
                return ResolutionCaseRecord(
                    case_id,
                    snapshot_hash,
                    self._resolution_state(connection, case_id),
                    False,
                )
            now = utc_now()
            connection.execute(
                """
                INSERT INTO evidence_resolution_case(
                    resolution_case_id,candidate_id,input_snapshot_hash,input_claim_json,
                    policy_version,provenance_urn,created_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (case_id, *expected, now),
            )
            connection.execute(
                """
                INSERT INTO evidence_resolution_event(
                    resolution_event_id,resolution_case_id,idempotency_key,event_kind,
                    from_state,to_state,reason_code,reason_detail,evidence_refs_json,occurred_at
                ) VALUES(?,?,'case-opened','case_opened',NULL,'queued',
                         'candidate_enqueued',?,'[]',?)
                """,
                (
                    event_id,
                    case_id,
                    "Candidate query snapshot accepted; no identity claim has been upgraded.",
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO evidence_resolution_state(
                    resolution_case_id,state,revision,source_event_id,updated_at
                ) VALUES(?,'queued',1,?,?)
                """,
                (case_id, event_id, now),
            )
            return ResolutionCaseRecord(
                case_id, snapshot_hash, WorkflowState(case_id, "queued", 1), True
            )

    @staticmethod
    def _transition_resolution(
        connection: sqlite3.Connection,
        resolution_case_id: str,
        *,
        expected_revision: int,
        to_state: ResolutionState,
        event_kind: str,
        reason_code: str,
        reason_detail: str,
        evidence_refs: list[str],
        idempotency_key: str,
    ) -> tuple[WorkflowState, bool]:
        event_id = stable_evidence_id(
            "revent", resolution_case_id, idempotency_key
        )
        evidence_json = canonical_json(evidence_refs)
        existing = connection.execute(
            "SELECT * FROM evidence_resolution_event WHERE resolution_event_id=?",
            (event_id,),
        ).fetchone()
        if existing is not None:
            expected_existing = (
                resolution_case_id,
                idempotency_key,
                event_kind,
                to_state,
                reason_code,
                reason_detail,
                evidence_json,
            )
            fields = (
                "resolution_case_id",
                "idempotency_key",
                "event_kind",
                "to_state",
                "reason_code",
                "reason_detail",
                "evidence_refs_json",
            )
            if _row_material(existing, fields) != expected_existing:
                raise EvidenceExpansionConflict("resolution event idempotency key conflicts")
            return EvidenceExpansionRepository._resolution_state(
                connection, resolution_case_id
            ), False
        current = EvidenceExpansionRepository._resolution_state(
            connection, resolution_case_id
        )
        if current.revision != expected_revision:
            raise EvidenceExpansionConflict(
                f"stale resolution revision: expected {expected_revision}, current {current.revision}"
            )
        now = utc_now()
        connection.execute(
            """
            INSERT INTO evidence_resolution_event(
                resolution_event_id,resolution_case_id,idempotency_key,event_kind,
                from_state,to_state,reason_code,reason_detail,evidence_refs_json,occurred_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (
                event_id,
                resolution_case_id,
                idempotency_key,
                event_kind,
                current.state,
                to_state,
                reason_code,
                reason_detail,
                evidence_json,
                now,
            ),
        )
        connection.execute(
            """
            UPDATE evidence_resolution_state
            SET state=?,revision=revision+1,source_event_id=?,updated_at=?
            WHERE resolution_case_id=?
            """,
            (to_state, event_id, now, resolution_case_id),
        )
        return WorkflowState(
            resolution_case_id, to_state, current.revision + 1
        ), True

    def start_resolution(
        self,
        resolution_case_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> tuple[WorkflowState, bool]:
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            current = self._resolution_state(connection, resolution_case_id)
            if current.state not in {"queued", "retryable_error"}:
                raise EvidenceExpansionConflict(
                    "resolution can only start from queued or retryable_error"
                )
            event_kind = (
                "resolution_started" if current.state == "queued" else "retry_scheduled"
            )
            reason_code = (
                "provider_resolution_started"
                if current.state == "queued"
                else "provider_resolution_retried"
            )
            return self._transition_resolution(
                connection,
                resolution_case_id,
                expected_revision=expected_revision,
                to_state="resolving",
                event_kind=event_kind,
                reason_code=reason_code,
                reason_detail="Official provider requests may now be planned and audited.",
                evidence_refs=[],
                idempotency_key=idempotency_key,
            )

    def put_provider_request(
        self,
        resolution_case_id: str,
        request: ProviderRequestSpec,
        *,
        provenance_urn: str,
    ) -> ProviderRequestRecord:
        request_id = stable_evidence_id(
            "prequest", resolution_case_id, request.fingerprint
        )
        expected = (
            resolution_case_id,
            request.provider,
            request.operation,
            request.method,
            request.url,
            canonical_json(request.headers),
            canonical_json(request.query_context),
            request.fingerprint,
            provenance_urn,
        )
        fields = (
            "resolution_case_id",
            "provider",
            "operation",
            "request_method",
            "request_url",
            "request_headers_json",
            "query_context_json",
            "request_fingerprint",
            "provenance_urn",
        )
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            state = self._resolution_state(connection, resolution_case_id)
            if state.state != "resolving":
                raise EvidenceExpansionConflict(
                    "provider requests require a resolving case"
                )
            existing = connection.execute(
                "SELECT * FROM evidence_provider_request WHERE provider_request_id=?",
                (request_id,),
            ).fetchone()
            if existing is not None:
                if _row_material(existing, fields) != expected:
                    raise EvidenceExpansionConflict("stable provider request conflicts")
                return ProviderRequestRecord(request_id, request.fingerprint, False)
            connection.execute(
                """
                INSERT INTO evidence_provider_request(
                    provider_request_id,resolution_case_id,provider,operation,
                    request_method,request_url,request_headers_json,query_context_json,
                    request_fingerprint,provenance_urn,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (request_id, *expected, utc_now()),
            )
            return ProviderRequestRecord(request_id, request.fingerprint, True)

    @staticmethod
    def _request_spec(row: sqlite3.Row) -> ProviderRequestSpec:
        return ProviderRequestSpec(
            provider=str(row["provider"]),
            operation=str(row["operation"]),
            url=str(row["request_url"]),
            method=str(row["request_method"]),
            headers=json.loads(str(row["request_headers_json"])),
            query_context=json.loads(str(row["query_context_json"])),
        )

    @staticmethod
    def _persist_provider_attempt(
        connection: sqlite3.Connection,
        *,
        request_row: sqlite3.Row,
        attempt_number: int,
        idempotency_key: str,
        result_status: str,
        final_url: str | None,
        redirect_chain: tuple[str, ...],
        http_status: int | None,
        response_mime: str | None,
        response_bytes: int | None,
        response_sha256: str | None,
        response_headers: dict[str, str],
        error_class: str | None,
        error_detail: str | None,
        provenance_urn: str,
    ) -> tuple[str, bool]:
        request_id = str(request_row["provider_request_id"])
        attempt_id = stable_evidence_id(
            "pattempt", request_id, idempotency_key
        )
        request_identity_hash = _sha256_json(
            {
                "request_fingerprint": request_row["request_fingerprint"],
                "attempt_number": attempt_number,
            }
        )
        expected = (
            request_id,
            attempt_number,
            idempotency_key,
            result_status,
            final_url,
            canonical_json(list(redirect_chain)),
            http_status,
            response_mime,
            response_bytes,
            response_sha256,
            canonical_json(response_headers),
            request_identity_hash,
            error_class,
            error_detail,
            provenance_urn,
        )
        fields = (
            "provider_request_id",
            "attempt_number",
            "idempotency_key",
            "result_status",
            "final_url",
            "redirect_chain_json",
            "http_status",
            "response_mime",
            "response_bytes",
            "response_sha256",
            "response_headers_json",
            "request_identity_hash",
            "error_class",
            "error_detail",
            "provenance_urn",
        )
        existing = connection.execute(
            "SELECT * FROM evidence_provider_attempt WHERE provider_attempt_id=?",
            (attempt_id,),
        ).fetchone()
        if existing is not None:
            if _row_material(existing, fields) != expected:
                raise EvidenceExpansionConflict("provider attempt idempotency key conflicts")
            return attempt_id, False
        try:
            connection.execute(
                """
                INSERT INTO evidence_provider_attempt(
                    provider_attempt_id,provider_request_id,attempt_number,idempotency_key,
                    result_status,final_url,redirect_chain_json,http_status,response_mime,
                    response_bytes,response_sha256,response_headers_json,request_identity_hash,
                    error_class,error_detail,provenance_urn,completed_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (attempt_id, *expected, utc_now()),
            )
        except sqlite3.IntegrityError as error:
            raise EvidenceExpansionConflict(
                "provider attempt number or idempotency key conflicts"
            ) from error
        return attempt_id, True

    def ingest_provider_response(
        self,
        provider_request_id: str,
        response: ProviderHttpResponse,
        adapter: ProviderAdapter,
        *,
        attempt_number: int,
        idempotency_key: str,
        provenance_urn: str,
    ) -> ProviderIngestResult:
        with evidence_connection(self.settings) as connection:
            request_row = connection.execute(
                "SELECT * FROM evidence_provider_request WHERE provider_request_id=?",
                (provider_request_id,),
            ).fetchone()
        if request_row is None:
            raise EvidenceExpansionNotFound("provider request does not exist")
        request = self._request_spec(request_row)
        if adapter.name != request.provider:
            raise EvidenceExpansionConflict("provider adapter does not match request")
        parse_result: ProviderParseResult | None = None
        parse_error: str | None = None
        if not 200 <= response.status_code <= 299:
            result_status = "http_failed"
            parse_error = f"HTTP {response.status_code}"
        else:
            try:
                parse_result = adapter.parse(request, response)
            except ProviderContractError as error:
                result_status = "invalid_response"
                parse_error = str(error)
            else:
                if (
                    parse_result.request_fingerprint != request.fingerprint
                    or parse_result.response_sha256 != response.body_sha256
                ):
                    raise EvidenceExpansionConflict(
                        "provider parser result is not bound to request/response material"
                    )
                result_status = "succeeded"

        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            live_request = connection.execute(
                "SELECT * FROM evidence_provider_request WHERE provider_request_id=?",
                (provider_request_id,),
            ).fetchone()
            if live_request is None:
                raise EvidenceExpansionNotFound("provider request disappeared")
            state = self._resolution_state(
                connection, str(live_request["resolution_case_id"])
            )
            if state.state != "resolving":
                existing = connection.execute(
                    """
                    SELECT provider_attempt_id FROM evidence_provider_attempt
                    WHERE provider_request_id=? AND idempotency_key=?
                    """,
                    (provider_request_id, idempotency_key),
                ).fetchone()
                if existing is None:
                    raise EvidenceExpansionConflict(
                        "new provider attempts require a resolving case"
                    )
            attempt_id, created = self._persist_provider_attempt(
                connection,
                request_row=live_request,
                attempt_number=attempt_number,
                idempotency_key=idempotency_key,
                result_status=result_status,
                final_url=response.final_url,
                redirect_chain=response.redirect_chain,
                http_status=response.status_code,
                response_mime=response.media_type or None,
                response_bytes=len(response.body),
                response_sha256=response.body_sha256,
                response_headers=_safe_response_headers(response.headers),
                error_class="ProviderContractError" if result_status == "invalid_response" else None,
                error_detail=parse_error,
                provenance_urn=provenance_urn,
            )
            observation_ids: list[str] = []
            offer_ids: list[str] = []
            if parse_result is not None:
                for observation in parse_result.observations:
                    observation_id, offers = self._persist_observation(
                        connection,
                        attempt_id=attempt_id,
                        observation=observation,
                    )
                    observation_ids.append(observation_id)
                    offer_ids.extend(offers)
            return ProviderIngestResult(
                provider_attempt_id=attempt_id,
                result_status=result_status,
                observation_ids=tuple(observation_ids),
                resource_offer_ids=tuple(offer_ids),
                created=created,
                parse_error=parse_error,
            )

    @staticmethod
    def _persist_observation(
        connection: sqlite3.Connection,
        *,
        attempt_id: str,
        observation: ProviderObservation,
    ) -> tuple[str, tuple[str, ...]]:
        observation_id = stable_evidence_id(
            "pobs",
            attempt_id,
            observation.provider_record_id,
            str(observation.provider_rank),
            observation.record_sha256,
        )
        identifiers_json = canonical_json(
            [item.model_dump(mode="json") for item in observation.identifiers]
        )
        expected = (
            attempt_id,
            observation.provider,
            observation.provider_record_id,
            observation.provider_rank,
            observation.provider_score,
            canonical_json(observation.record),
            observation.record_sha256,
            canonical_json(observation.metadata),
            identifiers_json,
            observation.match_basis,
            observation.identity_effect,
            "not_canonicalized",
            observation.rationale,
            observation.provenance_urn,
        )
        fields = (
            "provider_attempt_id",
            "provider",
            "provider_record_id",
            "provider_rank",
            "provider_score",
            "record_json",
            "record_sha256",
            "metadata_json",
            "normalized_identifiers_json",
            "match_basis",
            "identity_effect",
            "canonicalization_status",
            "rationale",
            "provenance_urn",
        )
        existing = connection.execute(
            "SELECT * FROM evidence_provider_observation WHERE provider_observation_id=?",
            (observation_id,),
        ).fetchone()
        if existing is None:
            connection.execute(
                """
                INSERT INTO evidence_provider_observation(
                    provider_observation_id,provider_attempt_id,provider,
                    provider_record_id,provider_rank,provider_score,record_json,
                    record_sha256,metadata_json,normalized_identifiers_json,
                    match_basis,identity_effect,canonicalization_status,rationale,
                    provenance_urn,observed_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (observation_id, *expected, utc_now()),
            )
        elif _row_material(existing, fields) != expected:
            raise EvidenceExpansionConflict("stable provider observation conflicts")

        offer_ids: list[str] = []
        for offer in observation.resource_offers:
            offer_id = stable_evidence_id(
                "roff", observation_id, offer.resource_kind, offer.url
            )
            offer_expected = (
                observation_id,
                offer.provider,
                offer.resource_kind,
                offer.source_kind,
                offer.url,
                offer.media_type,
                offer.rights_hint,
                canonical_json(offer.license_evidence),
                "none",
                offer.provenance_urn,
            )
            offer_fields = (
                "provider_observation_id",
                "provider",
                "resource_kind",
                "source_kind",
                "url",
                "media_type",
                "rights_hint",
                "license_evidence_json",
                "canonicalization_effect",
                "provenance_urn",
            )
            existing_offer = connection.execute(
                "SELECT * FROM evidence_resource_offer WHERE resource_offer_id=?",
                (offer_id,),
            ).fetchone()
            if existing_offer is None:
                connection.execute(
                    """
                    INSERT INTO evidence_resource_offer(
                        resource_offer_id,provider_observation_id,provider,resource_kind,
                        source_kind,url,media_type,rights_hint,license_evidence_json,
                        canonicalization_effect,provenance_urn,observed_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (offer_id, *offer_expected, utc_now()),
                )
            elif _row_material(existing_offer, offer_fields) != offer_expected:
                raise EvidenceExpansionConflict("stable resource offer conflicts")
            offer_ids.append(offer_id)
        return observation_id, tuple(offer_ids)

    def record_provider_failure(
        self,
        provider_request_id: str,
        *,
        attempt_number: int,
        idempotency_key: str,
        result_status: Literal["network_failed", "not_attempted"],
        error_class: str,
        error_detail: str,
        provenance_urn: str,
    ) -> ProviderIngestResult:
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            request = connection.execute(
                "SELECT * FROM evidence_provider_request WHERE provider_request_id=?",
                (provider_request_id,),
            ).fetchone()
            if request is None:
                raise EvidenceExpansionNotFound("provider request does not exist")
            state = self._resolution_state(
                connection, str(request["resolution_case_id"])
            )
            if state.state != "resolving":
                existing = connection.execute(
                    """
                    SELECT provider_attempt_id FROM evidence_provider_attempt
                    WHERE provider_request_id=? AND idempotency_key=?
                    """,
                    (provider_request_id, idempotency_key),
                ).fetchone()
                if existing is None:
                    raise EvidenceExpansionConflict(
                        "new provider failures require a resolving case"
                    )
            attempt_id, created = self._persist_provider_attempt(
                connection,
                request_row=request,
                attempt_number=attempt_number,
                idempotency_key=idempotency_key,
                result_status=result_status,
                final_url=None,
                redirect_chain=(),
                http_status=None,
                response_mime=None,
                response_bytes=None,
                response_sha256=None,
                response_headers={},
                error_class=error_class,
                error_detail=error_detail,
                provenance_urn=provenance_urn,
            )
            return ProviderIngestResult(
                attempt_id, result_status, (), (), created, error_detail
            )

    def finalize_provider_cycle(
        self,
        resolution_case_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> tuple[WorkflowState, bool]:
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            attempts = connection.execute(
                """
                SELECT attempt.provider_attempt_id,attempt.result_status
                FROM evidence_provider_attempt AS attempt
                JOIN evidence_provider_request AS request USING(provider_request_id)
                WHERE request.resolution_case_id=?
                ORDER BY attempt.provider_attempt_id
                """,
                (resolution_case_id,),
            ).fetchall()
            if not attempts:
                raise EvidenceExpansionConflict(
                    "provider cycle cannot finish without an audited attempt"
                )
            observations = connection.execute(
                """
                SELECT observation.provider_observation_id,observation.identity_effect
                FROM evidence_provider_observation AS observation
                JOIN evidence_provider_attempt AS attempt USING(provider_attempt_id)
                JOIN evidence_provider_request AS request USING(provider_request_id)
                WHERE request.resolution_case_id=?
                ORDER BY observation.provider_observation_id
                """,
                (resolution_case_id,),
            ).fetchall()
            attempt_refs = [str(row["provider_attempt_id"]) for row in attempts]
            observation_refs = [
                str(row["provider_observation_id"]) for row in observations
            ]
            if any(row["identity_effect"] == "conflicted" for row in observations):
                to_state: ResolutionState = "conflicted"
                event_kind = "provider_cycle_completed"
                reason_code = "provider_identifier_conflict"
                detail = "At least one official identifier lookup contradicted its source claim."
            elif observations:
                # This is the core no-auto-canonicalize boundary. Even exact identifier
                # observations require a separate, explicit identity decision event.
                to_state = "awaiting_review"
                event_kind = "provider_cycle_completed"
                reason_code = "provider_observations_require_decision"
                detail = (
                    "Provider results were preserved as observations. Rank, score, title "
                    "similarity, and even exact registry evidence do not create a paper."
                )
            elif any(row["result_status"] == "succeeded" for row in attempts):
                to_state = "unresolved"
                event_kind = "provider_cycle_completed"
                reason_code = "provider_returned_no_records"
                detail = "Official provider requests succeeded but returned no candidate records."
            else:
                to_state = "retryable_error"
                event_kind = "provider_cycle_failed"
                reason_code = "provider_cycle_transport_failure"
                detail = "No provider request produced a parseable successful response."
            return self._transition_resolution(
                connection,
                resolution_case_id,
                expected_revision=expected_revision,
                to_state=to_state,
                event_kind=event_kind,
                reason_code=reason_code,
                reason_detail=detail,
                evidence_refs=[*attempt_refs, *observation_refs],
                idempotency_key=idempotency_key,
            )

    def record_identity_decision(
        self,
        resolution_case_id: str,
        *,
        expected_revision: int,
        decision_kind: Literal[
            "accept_verified_identifier", "mark_unresolved", "mark_conflicted", "block"
        ],
        provider_observation_id: str | None,
        identifier_scheme: str | None,
        normalized_identifier: str | None,
        authority_kind: Literal[
            "deterministic_strong_identifier_policy", "human_review"
        ],
        rationale: str,
        evidence_refs: list[str],
        idempotency_key: str,
        provenance_urn: str,
        policy_version: str | None = None,
    ) -> IdentityDecisionRecord:
        policy = policy_version or self.resolution_policy_version
        decision_id = stable_evidence_id(
            "idecision", resolution_case_id, idempotency_key
        )
        normalized: str | None = None
        if decision_kind == "accept_verified_identifier":
            if not provider_observation_id or not identifier_scheme or not normalized_identifier:
                raise EvidenceExpansionConflict(
                    "identifier acceptance requires an observation and normalized identifier"
                )
            normalized = normalize_identifier(identifier_scheme, normalized_identifier)
        elif identifier_scheme is not None or normalized_identifier is not None:
            raise EvidenceExpansionConflict(
                "non-acceptance decisions cannot claim an identifier"
            )
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            existing = connection.execute(
                "SELECT * FROM evidence_identity_decision WHERE identity_decision_id=?",
                (decision_id,),
            ).fetchone()
            expected = (
                resolution_case_id,
                provider_observation_id,
                decision_kind,
                identifier_scheme,
                normalized,
                authority_kind,
                policy,
                rationale,
                canonical_json(evidence_refs),
                "none",
                idempotency_key,
                provenance_urn,
            )
            fields = (
                "resolution_case_id",
                "provider_observation_id",
                "decision_kind",
                "identifier_scheme",
                "normalized_identifier",
                "authority_kind",
                "policy_version",
                "rationale",
                "evidence_refs_json",
                "canonicalization_effect",
                "idempotency_key",
                "provenance_urn",
            )
            if existing is not None:
                if _row_material(existing, fields) != expected:
                    raise EvidenceExpansionConflict(
                        "identity decision idempotency key conflicts"
                    )
                return IdentityDecisionRecord(
                    decision_id,
                    self._resolution_state(connection, resolution_case_id),
                    False,
                )
            if decision_kind == "accept_verified_identifier":
                observation = connection.execute(
                    """
                    SELECT observation.*
                    FROM evidence_provider_observation AS observation
                    JOIN evidence_provider_attempt AS attempt USING(provider_attempt_id)
                    JOIN evidence_provider_request AS request USING(provider_request_id)
                    WHERE observation.provider_observation_id=?
                      AND request.resolution_case_id=?
                    """,
                    (provider_observation_id, resolution_case_id),
                ).fetchone()
                if observation is None:
                    raise EvidenceExpansionConflict(
                        "identity decision observation belongs to another case"
                    )
                identifiers = json.loads(
                    str(observation["normalized_identifiers_json"])
                )
                selected = next(
                    (
                        value
                        for value in identifiers
                        if value.get("scheme") == identifier_scheme
                        and value.get("normalized_value") == normalized
                    ),
                    None,
                )
                if selected is None:
                    raise EvidenceExpansionConflict(
                        "accepted identifier is absent from the provider observation"
                    )
                if authority_kind == "deterministic_strong_identifier_policy" and (
                    observation["match_basis"] != "source_identifier_exact"
                    or observation["identity_effect"] != "strong_identifier_verified"
                    or selected.get("verification_status") != "provider_verified"
                ):
                    raise EvidenceExpansionConflict(
                        "deterministic identity policy only accepts exact provider-verified source identifiers"
                    )
            connection.execute(
                """
                INSERT INTO evidence_identity_decision(
                    identity_decision_id,resolution_case_id,provider_observation_id,
                    decision_kind,identifier_scheme,normalized_identifier,authority_kind,
                    policy_version,rationale,evidence_refs_json,canonicalization_effect,
                    idempotency_key,provenance_urn,decided_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (decision_id, *expected, utc_now()),
            )
            targets: dict[str, ResolutionState] = {
                "accept_verified_identifier": "identifier_verified",
                "mark_unresolved": "unresolved",
                "mark_conflicted": "conflicted",
                "block": "blocked",
            }
            state, _ = self._transition_resolution(
                connection,
                resolution_case_id,
                expected_revision=expected_revision,
                to_state=targets[decision_kind],
                event_kind="identity_decided",
                reason_code=f"identity_decision_{decision_kind}",
                reason_detail=rationale,
                evidence_refs=[decision_id, *evidence_refs],
                idempotency_key=f"decision-event:{idempotency_key}",
            )
            return IdentityDecisionRecord(decision_id, state, True)

    @staticmethod
    def _offer_from_row(row: sqlite3.Row) -> ResourceOfferObservation:
        return ResourceOfferObservation(
            provider=str(row["provider"]),
            resource_kind=str(row["resource_kind"]),
            source_kind=str(row["source_kind"]),
            url=str(row["url"]),
            media_type=str(row["media_type"]),
            rights_hint=str(row["rights_hint"]),
            license_evidence=json.loads(str(row["license_evidence_json"])),
            provenance_urn=str(row["provenance_urn"]),
        )

    def assess_offer(
        self,
        resource_offer_id: str,
        policy: ConservativeRightsPolicy,
        *,
        idempotency_key: str,
        provenance_urn: str,
    ) -> RightsAssessmentRecord:
        with evidence_connection(self.settings) as connection:
            offer_row = connection.execute(
                "SELECT * FROM evidence_resource_offer WHERE resource_offer_id=?",
                (resource_offer_id,),
            ).fetchone()
        if offer_row is None:
            raise EvidenceExpansionNotFound("resource offer does not exist")
        proposal = policy.assess(self._offer_from_row(offer_row))
        return self.record_rights_assessment(
            resource_offer_id,
            proposal,
            idempotency_key=idempotency_key,
            provenance_urn=provenance_urn,
        )

    def record_rights_assessment(
        self,
        resource_offer_id: str,
        proposal: RightsAssessmentProposal,
        *,
        idempotency_key: str,
        provenance_urn: str,
        supersedes_assessment_id: str | None = None,
    ) -> RightsAssessmentRecord:
        assessment_id = stable_evidence_id(
            "rights", resource_offer_id, idempotency_key
        )
        expected = (
            resource_offer_id,
            proposal.decision,
            proposal.rights_status,
            proposal.authority_kind,
            proposal.policy_version,
            proposal.legal_basis,
            canonical_json(proposal.evidence),
            supersedes_assessment_id,
            idempotency_key,
            provenance_urn,
        )
        fields = (
            "resource_offer_id",
            "decision",
            "rights_status",
            "authority_kind",
            "policy_version",
            "legal_basis",
            "evidence_json",
            "supersedes_assessment_id",
            "idempotency_key",
            "provenance_urn",
        )
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            offer = connection.execute(
                "SELECT * FROM evidence_resource_offer WHERE resource_offer_id=?",
                (resource_offer_id,),
            ).fetchone()
            if offer is None:
                raise EvidenceExpansionNotFound("resource offer does not exist")
            existing = connection.execute(
                "SELECT * FROM evidence_rights_assessment WHERE rights_assessment_id=?",
                (assessment_id,),
            ).fetchone()
            if existing is not None:
                if _row_material(existing, fields) != expected:
                    raise EvidenceExpansionConflict(
                        "rights assessment idempotency key conflicts"
                    )
                return RightsAssessmentRecord(
                    assessment_id,
                    proposal.decision,
                    proposal.rights_status,
                    False,
                )
            if supersedes_assessment_id is not None:
                superseded = connection.execute(
                    """
                    SELECT resource_offer_id FROM evidence_rights_assessment
                    WHERE rights_assessment_id=?
                    """,
                    (supersedes_assessment_id,),
                ).fetchone()
                if superseded is None or superseded["resource_offer_id"] != resource_offer_id:
                    raise EvidenceExpansionConflict(
                        "rights reassessment must supersede the same resource offer"
                    )
            if (
                proposal.authority_kind == "deterministic_rights_policy"
                and proposal.decision == "approved_for_local_storage"
                and (
                    offer["provider"] != "arxiv"
                    or offer["source_kind"] != "official_repository"
                    or offer["rights_hint"] != "verified_open_license"
                    or not proposal.evidence.get("license_url")
                )
            ):
                raise EvidenceExpansionConflict(
                    "deterministic rights policy cannot approve this resource offer"
                )
            connection.execute(
                """
                INSERT INTO evidence_rights_assessment(
                    rights_assessment_id,resource_offer_id,decision,rights_status,
                    authority_kind,policy_version,legal_basis,evidence_json,
                    supersedes_assessment_id,idempotency_key,provenance_urn,assessed_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (assessment_id, *expected, utc_now()),
            )
            return RightsAssessmentRecord(
                assessment_id,
                proposal.decision,
                proposal.rights_status,
                True,
            )

    def open_acquisition_case(
        self,
        resource_offer_id: str,
        rights_assessment_id: str,
        *,
        provenance_urn: str,
    ) -> AcquisitionCaseRecord:
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            rights = connection.execute(
                """
                SELECT * FROM evidence_rights_assessment
                WHERE rights_assessment_id=? AND resource_offer_id=?
                """,
                (rights_assessment_id, resource_offer_id),
            ).fetchone()
            if rights is None:
                raise EvidenceExpansionNotFound(
                    "rights assessment does not belong to this resource offer"
                )
            snapshot_hash = _sha256_json(
                {
                    "schema_version": "qrh-evidence-acquisition-input/v1",
                    "resource_offer_id": resource_offer_id,
                    "rights_assessment_id": rights_assessment_id,
                    "decision": rights["decision"],
                    "rights_status": rights["rights_status"],
                    "policy_version": rights["policy_version"],
                }
            )
            case_id = stable_evidence_id(
                "acase", resource_offer_id, snapshot_hash
            )
            expected = (
                resource_offer_id,
                rights_assessment_id,
                snapshot_hash,
                provenance_urn,
            )
            existing = connection.execute(
                "SELECT * FROM evidence_acquisition_case WHERE acquisition_case_id=?",
                (case_id,),
            ).fetchone()
            fields = (
                "resource_offer_id",
                "rights_assessment_id",
                "input_snapshot_hash",
                "provenance_urn",
            )
            if existing is not None:
                if _row_material(existing, fields) != expected:
                    raise EvidenceExpansionConflict("stable acquisition case conflicts")
                return AcquisitionCaseRecord(
                    case_id, self._acquisition_state(connection, case_id), False
                )
            initial: AcquisitionState = {
                "approved_for_local_storage": "ready",
                "review_required": "rights_review",
                "metadata_only": "blocked",
                "blocked": "blocked",
            }[str(rights["decision"])]  # type: ignore[assignment]
            now = utc_now()
            connection.execute(
                """
                INSERT INTO evidence_acquisition_case(
                    acquisition_case_id,resource_offer_id,rights_assessment_id,
                    input_snapshot_hash,provenance_urn,created_at
                ) VALUES(?,?,?,?,?,?)
                """,
                (case_id, *expected, now),
            )
            event_id = stable_evidence_id("aevent", case_id, "case-opened")
            connection.execute(
                """
                INSERT INTO evidence_acquisition_event(
                    acquisition_event_id,acquisition_case_id,idempotency_key,event_kind,
                    from_state,to_state,fetch_attempt_id,resource_id,reason_code,
                    reason_detail,evidence_refs_json,occurred_at
                ) VALUES(?,?,'case-opened','case_opened',NULL,?,NULL,NULL,
                         'rights_assessment_applied',?,?,?)
                """,
                (
                    event_id,
                    case_id,
                    initial,
                    (
                        "Resource acquisition state was derived from an explicit rights "
                        "assessment; no network fetch has been implied."
                    ),
                    canonical_json([rights_assessment_id]),
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO evidence_acquisition_state(
                    acquisition_case_id,state,revision,source_event_id,updated_at
                ) VALUES(?,?,1,?,?)
                """,
                (case_id, initial, event_id, now),
            )
            return AcquisitionCaseRecord(
                case_id, WorkflowState(case_id, initial, 1), True
            )

    @staticmethod
    def _transition_acquisition(
        connection: sqlite3.Connection,
        acquisition_case_id: str,
        *,
        expected_revision: int,
        to_state: AcquisitionState,
        event_kind: str,
        reason_code: str,
        reason_detail: str,
        evidence_refs: list[str],
        idempotency_key: str,
        fetch_attempt_id: str | None = None,
        resource_id: str | None = None,
    ) -> tuple[WorkflowState, bool]:
        event_id = stable_evidence_id(
            "aevent", acquisition_case_id, idempotency_key
        )
        refs_json = canonical_json(evidence_refs)
        existing = connection.execute(
            "SELECT * FROM evidence_acquisition_event WHERE acquisition_event_id=?",
            (event_id,),
        ).fetchone()
        expected = (
            acquisition_case_id,
            idempotency_key,
            event_kind,
            to_state,
            fetch_attempt_id,
            resource_id,
            reason_code,
            reason_detail,
            refs_json,
        )
        fields = (
            "acquisition_case_id",
            "idempotency_key",
            "event_kind",
            "to_state",
            "fetch_attempt_id",
            "resource_id",
            "reason_code",
            "reason_detail",
            "evidence_refs_json",
        )
        if existing is not None:
            if _row_material(existing, fields) != expected:
                raise EvidenceExpansionConflict(
                    "acquisition event idempotency key conflicts"
                )
            return EvidenceExpansionRepository._acquisition_state(
                connection, acquisition_case_id
            ), False
        current = EvidenceExpansionRepository._acquisition_state(
            connection, acquisition_case_id
        )
        if current.revision != expected_revision:
            raise EvidenceExpansionConflict(
                f"stale acquisition revision: expected {expected_revision}, current {current.revision}"
            )
        now = utc_now()
        connection.execute(
            """
            INSERT INTO evidence_acquisition_event(
                acquisition_event_id,acquisition_case_id,idempotency_key,event_kind,
                from_state,to_state,fetch_attempt_id,resource_id,reason_code,
                reason_detail,evidence_refs_json,occurred_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                event_id,
                acquisition_case_id,
                idempotency_key,
                event_kind,
                current.state,
                to_state,
                fetch_attempt_id,
                resource_id,
                reason_code,
                reason_detail,
                refs_json,
                now,
            ),
        )
        connection.execute(
            """
            UPDATE evidence_acquisition_state
            SET state=?,revision=revision+1,source_event_id=?,updated_at=?
            WHERE acquisition_case_id=?
            """,
            (to_state, event_id, now, acquisition_case_id),
        )
        return WorkflowState(
            acquisition_case_id, to_state, current.revision + 1
        ), True

    def begin_acquisition(
        self,
        acquisition_case_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> tuple[WorkflowState, bool]:
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            current = self._acquisition_state(connection, acquisition_case_id)
            if current.state not in {"ready", "retryable_error"}:
                raise EvidenceExpansionConflict(
                    "acquisition can only start after rights approval or a retryable failure"
                )
            event_kind = "fetch_started" if current.state == "ready" else "fetch_retried"
            return self._transition_acquisition(
                connection,
                acquisition_case_id,
                expected_revision=expected_revision,
                to_state="fetching",
                event_kind=event_kind,
                reason_code="audited_resource_fetch_started",
                reason_detail="Network retrieval began after an explicit approved rights assessment.",
                evidence_refs=[],
                idempotency_key=idempotency_key,
            )

    def complete_acquisition(
        self,
        acquisition_case_id: str,
        *,
        expected_revision: int,
        fetch_attempt_id: str,
        resource_id: str,
        idempotency_key: str,
    ) -> tuple[WorkflowState, bool]:
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            return self._transition_acquisition(
                connection,
                acquisition_case_id,
                expected_revision=expected_revision,
                to_state="acquired",
                event_kind="fetch_succeeded",
                reason_code="verified_resource_registered",
                reason_detail=(
                    "The successful fetch audit, PDF validation, content hash, and registered "
                    "resource agree."
                ),
                evidence_refs=[fetch_attempt_id, resource_id],
                idempotency_key=idempotency_key,
                fetch_attempt_id=fetch_attempt_id,
                resource_id=resource_id,
            )

    def fail_acquisition(
        self,
        acquisition_case_id: str,
        *,
        expected_revision: int,
        fetch_attempt_id: str,
        idempotency_key: str,
    ) -> tuple[WorkflowState, bool]:
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            fetch = connection.execute(
                "SELECT result_status,error_class,error_detail FROM fetch_attempt WHERE fetch_attempt_id=?",
                (fetch_attempt_id,),
            ).fetchone()
            if fetch is None:
                raise EvidenceExpansionNotFound("fetch attempt does not exist")
            status = str(fetch["result_status"])
            if status in {"http_failed", "network_failed"}:
                target: AcquisitionState = "retryable_error"
                event_kind = "fetch_failed_retryable"
            elif status == "invalid_content":
                target = "invalid_content"
                event_kind = "fetch_invalid_content"
            elif status in {"license_blocked", "not_attempted"}:
                target = "blocked"
                event_kind = "fetch_blocked"
            else:
                raise EvidenceExpansionConflict(
                    f"fetch status {status!r} is not a failure outcome"
                )
            return self._transition_acquisition(
                connection,
                acquisition_case_id,
                expected_revision=expected_revision,
                to_state=target,
                event_kind=event_kind,
                reason_code=f"audited_fetch_{status}",
                reason_detail=(
                    str(fetch["error_detail"])
                    or str(fetch["error_class"])
                    or f"Audited fetch outcome: {status}"
                ),
                evidence_refs=[fetch_attempt_id],
                idempotency_key=idempotency_key,
                fetch_attempt_id=fetch_attempt_id,
            )

    def cases_by_state(
        self, state: ResolutionState, *, limit: int = 1_000
    ) -> tuple[WorkflowState, ...]:
        if not 1 <= limit <= 10_000:
            raise ValueError("limit must be between 1 and 10000")
        with evidence_connection(self.settings) as connection:
            return tuple(
                WorkflowState(
                    str(row["resolution_case_id"]),
                    str(row["state"]),
                    int(row["revision"]),
                )
                for row in connection.execute(
                    """
                    SELECT resolution_case_id,state,revision
                    FROM evidence_resolution_state
                    WHERE state=? ORDER BY resolution_case_id LIMIT ?
                    """,
                    (state, limit),
                )
            )


class EvidenceExpansionService:
    """Pure orchestration over frozen provider adapters and the durable repository."""

    def __init__(self, settings: Settings):
        self.repository = EvidenceExpansionRepository(settings)

    def enqueue_and_plan(
        self,
        candidate_id: str,
        query: ResolutionQuery,
        adapters: tuple[ProviderAdapter, ...],
        *,
        provenance_urn: str,
        idempotency_key: str,
    ) -> tuple[ResolutionCaseRecord, tuple[ProviderRequestRecord, ...]]:
        opened = self.repository.open_resolution_case(
            candidate_id, query, provenance_urn=provenance_urn
        )
        if opened.state.state == "queued":
            state, _ = self.repository.start_resolution(
                opened.resolution_case_id,
                expected_revision=opened.state.revision,
                idempotency_key=f"start:{idempotency_key}",
            )
            opened = ResolutionCaseRecord(
                opened.resolution_case_id,
                opened.input_snapshot_hash,
                state,
                opened.created,
            )
        requests: list[ProviderRequestRecord] = []
        if opened.state.state == "resolving":
            for adapter in adapters:
                for request in adapter.plan(query):
                    requests.append(
                        self.repository.put_provider_request(
                            opened.resolution_case_id,
                            request,
                            provenance_urn=(
                                f"{provenance_urn}:provider:{request.provider}:"
                                f"request-sha256:{request.fingerprint}"
                            ),
                        )
                    )
        # A replay after review/finalization is a no-op. A new source snapshot opens
        # a new case instead of mutating or silently reopening the historical one.
        return opened, tuple(requests)
